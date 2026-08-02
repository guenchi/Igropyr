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
  (import (chezscheme) (igropyr buffer)
          (igropyr actor) (igropyr libuv) (igropyr websocket)
          (only (igropyr crypto) base64-encode))

  (define connect-timeout-ms 10000)
  (define default-port 80)

  (define (fail msg) (raise (vector 'ws-client-error msg)))

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

  (define (string-crlf-index s from)
    (let ((n (string-length s)))
      (let loop ((i from))
        (cond ((>= (+ i 1) n) #f)
              ((and (char=? (string-ref s i) #\return)
                    (char=? (string-ref s (+ i 1)) #\newline)) i)
              (else (loop (+ i 1)))))))

  (define (trim-ows s)
    (let ((n (string-length s)))
      (let left ((start 0))
        (if (and (< start n) (memv (string-ref s start) '(#\space #\tab)))
            (left (+ start 1))
            (let right ((end n))
              (if (and (> end start)
                       (memv (string-ref s (- end 1)) '(#\space #\tab)))
                  (right (- end 1))
                  (substring s start end)))))))

  (define (valid-101-status-line? line)
    (let ((sp1 (string-index line #\space 0)))
      (and sp1
           (string=? (substring line 0 sp1) "HTTP/1.1")
           (let* ((start (+ sp1 1))
                  (sp2 (string-index line #\space start))
                  (end (or sp2 (string-length line))))
             (string=? (substring line start end) "101")))))

  ;; Parse the already bounded handshake header block into lowercase names.
  ;; A malformed line invalidates the response instead of being skipped.
  (define (parse-response-headers text start)
    (let ((n (string-length text)))
      (let loop ((pos start) (acc '()))
        (cond
          ((= pos n) (reverse acc))
          (else
           (let ((eol (string-crlf-index text pos)))
             (and eol
                  (let* ((line (substring text pos eol))
                         (colon (string-index line #\: 0)))
                    (and colon (> colon 0)
                         (loop (+ eol 2)
                           (cons (cons (string-downcase (substring line 0 colon))
                                       (trim-ows
                                         (substring line (+ colon 1)
                                                    (string-length line))))
                                 acc)))))))))))

  (define (response-header-values headers name)
    (let loop ((hs headers) (acc '()))
      (cond ((null? hs) (reverse acc))
            ((string=? (caar hs) name)
             (loop (cdr hs) (cons (cdar hs) acc)))
            (else (loop (cdr hs) acc)))))

  (define (value-has-token? value wanted)
    (let ((n (string-length value)))
      (let loop ((start 0) (i 0))
        (cond
          ((= i n)
           (string-ci=? (trim-ows (substring value start i)) wanted))
          ((char=? (string-ref value i) #\,)
           (or (string-ci=? (trim-ows (substring value start i)) wanted)
               (loop (+ i 1) (+ i 1))))
          (else (loop start (+ i 1)))))))

  (define (header-has-token? headers name wanted)
    (exists (lambda (value) (value-has-token? value wanted))
            (response-header-values headers name)))

  ;; RFC 6455 4.1: the response must be an HTTP/1.1 101 upgrade, nominate
  ;; websocket/Upgrade in its token fields, and carry exactly one Accept
  ;; field whose complete value proves possession of this request's key.
  (define (verify-response head-bv key)
    (guard (e (#t #f))
      (let* ((text (utf8->string head-bv))
             (status-end (string-crlf-index text 0)))
        (and status-end
             (valid-101-status-line? (substring text 0 status-end))
             (let ((headers (parse-response-headers text (+ status-end 2))))
               (and headers
                    (header-has-token? headers "upgrade" "websocket")
                    (header-has-token? headers "connection" "upgrade")
                    (let ((accepts
                           (response-header-values
                             headers "sec-websocket-accept")))
                      (and (= (length accepts) 1)
                           (string=? (car accepts) (ws-accept-key key))))))))))

  (define max-handshake-header 16384)   ; cap on the 101 response headers

  ;; read until the response headers are complete (resumable scan --
  ;; no rescans-from-zero as segments arrive), then verify
  (define (await-handshake c key buf)
    (let ((hend (inbuf-find-header-end buf)))
      (cond
        (hend
         (if (verify-response (inbuf-sub buf 0 (fx+ hend 2)) key)
             ;; leftover bytes after \r\n\r\n belong to the ws stream
             (make-ws-client c (inbuf-sub buf (fx+ hend 4) (inbuf-length buf)))
             (begin (tcp-close! c) (fail "handshake rejected"))))
        ((> (inbuf-length buf) max-handshake-header)
         (tcp-close! c) (fail "handshake header too large"))
        (else
         (receive (after connect-timeout-ms
                     (tcp-close! c) (fail "handshake timeout"))
           (`#(tcp-data ,bv)
             (inbuf-append! buf bv)
             (await-handshake c key buf))
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
                  (await-handshake c key (make-inbuf))))
              (`#(tcp-connect-failed ,e) (fail (uv-strerror e)))))
          (`#(dns-failed ,e) (fail "dns resolution failed"))))))
)
