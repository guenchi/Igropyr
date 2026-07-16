#!chezscheme
;;; (igropyr ws-client) -- outbound WebSocket client.
;;;
;;; Connects, performs the RFC 6455 upgrade handshake, and returns a ws
;;; session in client role (outbound frames are masked, inbound frames
;;; must be unmasked). The session is the same object the server side
;;; uses, so ws-recv / ws-send-text! / ws-send-binary! / ws-close! all
;;; work unchanged.
;;;
;;;   (define w (ws-connect "ws://127.0.0.1:8080/chat/42"))
;;;   (ws-send-text! w "hello")
;;;   (ws-recv w)            ; -> #(text s) | #(binary bv) | #(close)
;;;   (ws-close! w)
;;;
;;; Runs in the caller's green process; connect/handshake failures raise
;;; #(ws-client-error msg).

(library (igropyr ws-client)
  (export ws-connect
          ;; Re-exported session operations from (igropyr websocket):
          ;; ws-connect returns a session that is only usable through
          ;; these, so a client-only program imports this library alone.
          ws-recv ws-send-text! ws-send-binary! ws-close!
          ;; Re-exported app-facing (igropyr actor) surface, for the same
          ;; reason as (igropyr client): a client-only program still needs
          ;; the scheduler and process primitives. Same original bindings
          ;; as those re-exported by (igropyr http) -- importing both
          ;; never conflicts.
          start-scheduler spawn send receive self
          sleep-ms kill register whereis process-id)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr websocket)
          (only (igropyr crypto) base64-encode))

  (define connect-timeout-ms 10000)
  (define default-port 80)

  (define (fail msg) (raise (vector 'ws-client-error msg)))

  ;; ---- bytevector helpers ---------------------------------------------

  (define empty-bv (make-bytevector 0))

  (define (bv-append a b)
    (let* ((la (bytevector-length a)) (lb (bytevector-length b))
           (r (make-bytevector (+ la lb))))
      (bytevector-copy! a 0 r 0 la)
      (bytevector-copy! b 0 r la lb)
      r))

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  (define (find-header-end bv)
    (let ((n (bytevector-length bv)))
      (let loop ((i 0))
        (cond
          ((> (+ i 3) (- n 1)) #f)
          ((and (fx= (bytevector-u8-ref bv i) 13)
                (fx= (bytevector-u8-ref bv (fx+ i 1)) 10)
                (fx= (bytevector-u8-ref bv (fx+ i 2)) 13)
                (fx= (bytevector-u8-ref bv (fx+ i 3)) 10))
           i)
          (else (loop (fx+ i 1)))))))

  ;; ---- URL parsing (ws://host[:port][/path]) --------------------------

  (define (string-index s ch from)
    (let ((n (string-length s)))
      (let loop ((i from))
        (cond ((= i n) #f)
              ((char=? (string-ref s i) ch) i)
              (else (loop (+ i 1)))))))

  (define (parse-ws-url url)
    (let ((rest (cond
                  ((and (>= (string-length url) 5)
                        (string-ci=? (substring url 0 5) "ws://"))
                   (substring url 5 (string-length url)))
                  ((and (>= (string-length url) 6)
                        (string-ci=? (substring url 0 6) "wss://"))
                   (fail "wss not supported; put TLS behind a proxy"))
                  (else (fail "url must start with ws://")))))
      (let* ((slash (string-index rest #\/ 0))
             (authority (if slash (substring rest 0 slash) rest))
             (path (if slash (substring rest slash (string-length rest)) "/"))
             (colon (string-index authority #\: 0)))
        (if colon
            (values (substring authority 0 colon)
                    (or (string->number (substring authority (+ colon 1)
                                          (string-length authority)))
                        default-port)
                    path)
            (values authority default-port path)))))

  ;; ---- handshake -------------------------------------------------------

  ;; 16 random bytes, base64 -> Sec-WebSocket-Key
  (define (make-ws-key)
    (base64-encode
      (call-with-port (open-file-input-port "/dev/urandom")
        (lambda (p) (get-bytevector-n p 16)))))

  (define (handshake-request host path key extra-headers)
    (string->utf8
      (string-append
        "GET " path " HTTP/1.1\r\n"
        "Host: " host "\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: " key "\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        (apply string-append
               (map (lambda (h)
                      (string-append (car h) ": " (cdr h) "\r\n"))
                    extra-headers))
        "\r\n")))

  ;; verify the 101 response: status 101 and a correct Accept header
  (define (verify-response buf hend key)
    (let* ((text (utf8->string (bv-sub buf 0 hend)))
           (lower (string-downcase text))
           (expected (string-downcase (ws-accept-key key))))
      (and (let ((sp (string-index text #\space 0)))
             (and sp (>= (string-length text) (+ sp 4))
                  (string=? (substring text (+ sp 1) (+ sp 4)) "101")))
           (let ((needle (string-append "sec-websocket-accept: " expected)))
             (let search ((i 0))
               (cond
                 ((> (+ i (string-length needle)) (string-length lower)) #f)
                 ((string=? (substring lower i (+ i (string-length needle)))
                            needle) #t)
                 (else (search (+ i 1)))))))))

  (define max-handshake-header 16384)   ; cap on the 101 response headers

  ;; read until the response headers are complete, then verify
  (define (await-handshake c key buf)
    (let ((hend (find-header-end buf)))
      (cond
        (hend
         (if (verify-response buf (+ hend 2) key)
             ;; leftover bytes after \r\n\r\n belong to the ws stream
             (make-ws-client c (bv-sub buf (+ hend 4) (bytevector-length buf)))
             (begin (tcp-close! c) (fail "handshake rejected"))))
        ((> (bytevector-length buf) max-handshake-header)
         (tcp-close! c) (fail "handshake header too large"))
        (else
         (receive (after connect-timeout-ms
                     (tcp-close! c) (fail "handshake timeout"))
           (`#(tcp-data ,bv) (await-handshake c key (bv-append buf bv)))
           (`#(tcp-eof) (tcp-close! c) (fail "connection closed during handshake"))
           (`#(tcp-error ,e) (tcp-close! c) (fail "connection error")))))))

  ;; ---- public API ------------------------------------------------------

  ;; Connect to a ws:// URL and complete the handshake; returns a ws
  ;; session. Runs in the caller's process. Optional rest argument: an
  ;; alist of extra handshake headers, e.g. the credential for a
  ;; guarded route ((igropyr auth)):
  ;;   (ws-connect url `(("Authorization" . ,(string-append "Bearer " tok))))
  (define (ws-connect url . rest)
    (let ((extra-headers (if (pair? rest) (car rest) '())))
      (let-values (((host port path) (parse-ws-url url)))
        (dns-resolve! host self)
        (receive (after connect-timeout-ms (fail "dns timeout"))
          (`#(dns-resolved ,ip)
            (tcp-connect! ip port self)
            (receive (after connect-timeout-ms (fail "connect timeout"))
              (`#(tcp-connected ,c)
                (tcp-read-start! c)
                (let ((key (make-ws-key)))
                  (tcp-write! c (handshake-request host path key extra-headers) #f)
                  (await-handshake c key empty-bv)))
              (`#(tcp-connect-failed ,e) (fail (uv-strerror e)))))
          (`#(dns-failed ,e) (fail "dns resolution failed"))))))
)
