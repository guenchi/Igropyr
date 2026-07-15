#!chezscheme
;;; (igropyr client) -- non-blocking outbound HTTP/1.1 client.
;;;
;;; Same actor model as the database clients: each request runs in its
;;; own green process that connects, sends, and reads the reply, while
;;; the caller parks in receive -- the OS thread keeps serving other
;;; work. One connection per request (Connection: close); no pooling.
;;;
;;;   (http-get "http://127.0.0.1:8080/json")
;;;     ;; -> a response; response-status / -headers / -body / -header
;;;   (http-post "http://host/api" "{\"x\":1}"
;;;              '((headers . (("Content-Type" . "application/json")))))
;;;   (http-request 'PUT url '((body . ,bv) (timeout . 5000)))
;;;
;;; Body arrives as a bytevector (utf8->string it if text). A transport
;;; failure or timeout raises #(http-client-error ,message).
;;;
;;; https:// works when the OPTIONAL (igropyr tls) library has been
;;; enabled -- (import (igropyr tls)) then (tls-enable!) once at startup.
;;; This library itself stays dependency-free: TLS plugs in through
;;; set-https-connector! as a pure byte codec (encrypt out, decrypt in),
;;; so the socket, timeout, and parsing paths here are identical for
;;; both schemes. Without it, https:// fails with a clear message.

(library (igropyr client)
  (export http-request http-get http-post
          response? response-status response-headers response-body
          response-header
          set-https-connector!     ; internal: registered by (igropyr tls)
          ;; Re-exported app-facing (igropyr actor) surface: this library
          ;; can be the sole entry point of a client-only program (a
          ;; crawler, an API caller), which still needs the scheduler and
          ;; process primitives. Same original bindings as those
          ;; re-exported by (igropyr http) -- importing both never
          ;; conflicts.
          start-scheduler spawn send receive self
          sleep-ms kill register whereis process-id)
  (import (chezscheme) (igropyr actor) (igropyr libuv))

  (define default-timeout-ms 30000)
  (define default-port 80)
  (define default-tls-port 443)
  (define max-response 33554432)      ; 32 MiB response cap (DoS guard)

  ;; ---- TLS hook ---------------------------------------------------------
  ;;
  ;; (igropyr tls) registers a connector: (lambda (conn host timeout) codec)
  ;; called inside the connection process right after tcp-read-start!, so
  ;; it can drive the handshake with receive on the socket's messages.
  ;; codec = #(encrypt decrypt close):
  ;;   encrypt: plaintext bv -> ciphertext bv to write
  ;;   decrypt: ciphertext bv -> plaintext bv (may be empty: pure TLS records)
  ;;   close:   () -> free the session (no I/O)
  ;; On failure the connector raises #(http-client-error ,message).
  (define https-connector #f)
  (define (set-https-connector! f) (set! https-connector f))

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

  (define (find-crlf bv start)
    (let ((n (bytevector-length bv)))
      (let loop ((i start))
        (cond
          ((>= (+ i 1) n) #f)
          ((and (fx= (bytevector-u8-ref bv i) 13)
                (fx= (bytevector-u8-ref bv (+ i 1)) 10))
           i)
          (else (loop (+ i 1)))))))

  (define (fail msg) (raise (vector 'http-client-error msg)))

  ;; ---- URL parsing ----------------------------------------------------

  (define (string-index s ch from)
    (let ((n (string-length s)))
      (let loop ((i from))
        (cond ((= i n) #f)
              ((char=? (string-ref s i) ch) i)
              (else (loop (+ i 1)))))))

  ;; "http[s]://host[:port][/path]" -> (values host port path-with-query tls?)
  (define (parse-url url)
    (let-values (((rest tls?)
                  (cond
                    ((and (>= (string-length url) 7)
                          (string-ci=? (substring url 0 7) "http://"))
                     (values (substring url 7 (string-length url)) #f))
                    ((and (>= (string-length url) 8)
                          (string-ci=? (substring url 0 8) "https://"))
                     (values (substring url 8 (string-length url)) #t))
                    (else (fail "url must start with http:// or https://")))))
      (let* ((slash (string-index rest #\/ 0))
             (authority (if slash (substring rest 0 slash) rest))
             (path (if slash (substring rest slash (string-length rest)) "/"))
             (colon (string-index authority #\: 0))
             (dport (if tls? default-tls-port default-port)))
        (if colon
            (values (substring authority 0 colon)
                    (or (string->number (substring authority (+ colon 1)
                                                   (string-length authority)))
                        dport)
                    path tls?)
            (values authority dport path tls?)))))

  ;; ---- request encoding ------------------------------------------------

  (define crlf (string->utf8 "\r\n"))

  (define (build-request method host path headers body)
    (let ((body-bv (cond ((not body) empty-bv)
                         ((string? body) (string->utf8 body))
                         (else body))))
      (let-values (((p get) (open-bytevector-output-port)))
        (define (line s) (put-bytevector p (string->utf8 s)) (put-bytevector p crlf))
        (line (string-append (symbol->string method) " " path " HTTP/1.1"))
        (line (string-append "Host: " host))
        (line "Connection: close")
        (for-each
          (lambda (h) (line (string-append (car h) ": " (cdr h))))
          headers)
        (when (> (bytevector-length body-bv) 0)
          (line (string-append "Content-Length: "
                               (number->string (bytevector-length body-bv)))))
        (put-bytevector p crlf)                    ; end of headers
        (put-bytevector p body-bv)
        (get))))

  ;; ---- response record + parsing --------------------------------------

  (define-record-type (response make-response response?)
    (fields
      (immutable status response-status)     ; integer
      (immutable headers response-headers)   ; alist, lowercase symbol keys
      (immutable body response-body)))        ; bytevector

  (define (response-header r name)
    (let ((p (assq name (response-headers r))))
      (and p (cdr p))))

  (define (parse-status-line bv end)
    ;; "HTTP/1.1 200 OK"
    (let* ((s (utf8->string (bv-sub bv 0 end)))
           (sp1 (string-index s #\space 0)))
      (and sp1
           (let ((sp2 (string-index s #\space (+ sp1 1))))
             (string->number
               (if sp2 (substring s (+ sp1 1) sp2)
                   (substring s (+ sp1 1) (string-length s))))))))

  (define (parse-headers bv start end)
    ;; header lines between start and end (the \r\n\r\n index)
    (let loop ((pos start) (acc '()))
      (let ((eol (find-crlf bv pos)))
        (if (or (not eol) (>= pos end))
            (reverse acc)
            (let ((line (utf8->string (bv-sub bv pos eol))))
              (let ((colon (string-index line #\: 0)))
                (if colon
                    (let ((k (string->symbol
                               (string-downcase (substring line 0 colon))))
                          (v (let trim ((j (+ colon 1)))
                               (if (and (< j (string-length line))
                                        (char=? (string-ref line j) #\space))
                                   (trim (+ j 1))
                                   (substring line j (string-length line))))))
                      (loop (+ eol 2) (cons (cons k v) acc)))
                    (loop (+ eol 2) acc))))))))

  ;; decode a chunked body starting at `start`; -> body-bv | 'more | 'bad
  (define (decode-chunked bv start)
    (let-values (((p get) (open-bytevector-output-port)))
      (let loop ((pos start))
        (let ((eol (find-crlf bv pos)))
          (if (not eol)
              'more
              (let ((size (string->number
                            (let ((line (utf8->string (bv-sub bv pos eol))))
                              (let ((semi (string-index line #\; 0)))
                                (if semi (substring line 0 semi) line)))
                            16)))
                (cond
                  ((not size) 'bad)
                  ((= size 0) (get))                ; final chunk
                  ((< (bytevector-length bv) (+ eol 2 size 2)) 'more)
                  (else
                   (put-bytevector p (bv-sub bv (+ eol 2) (+ eol 2 size)))
                   (loop (+ eol 2 size 2))))))))))

  ;; Try to parse a complete response from buf. Returns one of:
  ;;   #(done response)
  ;;   #(more)
  ;;   #(need-eof status headers body-start)   ; body runs until close
  (define (parse-response buf)
    (let ((hend (find-header-end buf)))
      (if (not hend)
          (vector 'more)
          (let* ((sl-end (or (find-crlf buf 0) hend))
                 (status (parse-status-line buf sl-end))
                 (headers (parse-headers buf (+ sl-end 2) hend))
                 (body-start (+ hend 4)))
            (cond
              ((not status) (vector 'more))
              ((assq 'content-length headers)
               (let ((len (or (string->number
                                (cdr (assq 'content-length headers))) 0)))
                 (if (>= (- (bytevector-length buf) body-start) len)
                     (vector 'done
                       (make-response status headers
                         (bv-sub buf body-start (+ body-start len))))
                     (vector 'more))))
              ((let ((te (assq 'transfer-encoding headers)))
                 (and te (string-ci=? (cdr te) "chunked")))
               (let ((r (decode-chunked buf body-start)))
                 (cond
                   ((eq? r 'more) (vector 'more))
                   ((eq? r 'bad) (fail "bad chunked response"))
                   (else (vector 'done (make-response status headers r))))))
              (else
               (vector 'need-eof status headers body-start)))))))

  ;; ---- connection process ----------------------------------------------

  ;; ref tags each reply so a late reply (after the caller timed out)
  ;; cannot be mis-read by a later request from the same caller.
  ;; eof-mode is #f while parsing, or (status headers body-start) once the
  ;; headers are in and the body runs until the server closes.
  (define (client-loop c caller ref buf eof-mode timeout codec)
    (define (done!) (when codec ((vector-ref codec 2))) (tcp-close! c))
    (define (reply! r) (send caller (vector 'http-reply ref r)) (done!))
    (define (err! msg) (send caller (vector 'http-error ref msg)) (done!))
    (receive (after timeout (err! "response timeout"))
      (`#(tcp-data ,raw)
        (let ((bv (if codec ((vector-ref codec 1) raw) raw)))
          (if (zero? (bytevector-length bv))   ; pure TLS records, no app data
              (client-loop c caller ref buf eof-mode timeout codec)
              (let ((buf (bv-append buf bv)))
                (cond
                  ((> (bytevector-length buf) max-response) (err! "response too large"))
                  (eof-mode
                    (client-loop c caller ref buf eof-mode timeout codec))
                  (else
                    (let ((res (parse-response buf)))
                      (case (vector-ref res 0)
                        ((done) (reply! (vector-ref res 1)))
                        ((need-eof)
                         (client-loop c caller ref buf
                           (list (vector-ref res 1) (vector-ref res 2) (vector-ref res 3))
                           timeout codec))
                        (else (client-loop c caller ref buf #f timeout codec))))))))))
      (`#(tcp-eof)
        (if eof-mode
            (reply! (make-response (car eof-mode) (cadr eof-mode)
                      (bv-sub buf (caddr eof-mode) (bytevector-length buf))))
            (err! "connection closed early")))
      (`#(tcp-error ,e) (err! "connection error"))))

  ;; ---- public API ------------------------------------------------------

  (define ref-counter 0)

  ;; (http-request method url opts) where opts is an alist:
  ;;   (headers . ((name . value) ...))   extra request headers
  ;;   (body    . string-or-bytevector)   request body
  ;;   (timeout . milliseconds)           default 30000
  (define (http-request method url . rest)
    (let* ((opts (if (pair? rest) (car rest) '()))
           (headers (let ((p (assq 'headers opts))) (if p (cdr p) '())))
           (body (let ((p (assq 'body opts))) (and p (cdr p))))
           (timeout (let ((p (assq 'timeout opts))) (if p (cdr p) default-timeout-ms)))
           (caller self)
           (ref (gensym)))
      (let-values (((host port path tls?) (parse-url url)))
        ;; fail fast, before any connection is attempted
        (when (and tls? (not https-connector))
          (fail "https not supported; import (igropyr tls) and call (tls-enable!)"))
        (spawn
          (lambda ()
            (guard (e (#t (send caller
                            (vector 'http-error ref
                              ;; surface codec/parse errors (e.g. a TLS
                              ;; certificate failure) instead of a blur
                              (if (and (vector? e)
                                       (eq? (vector-ref e 0) 'http-client-error)
                                       (string? (vector-ref e 1)))
                                  (vector-ref e 1)
                                  "request failed")))))
              ;; resolve the host (a dotted IP resolves to itself), then
              ;; connect to the IP
              (dns-resolve! host self)
              (receive (after timeout
                          (send caller (vector 'http-error ref "dns timeout")))
                (`#(dns-resolved ,ip)
                  (tcp-connect! ip port self)
                  (receive (after timeout
                              (send caller (vector 'http-error ref "connect timeout"))
                              ;; the connect is still in flight; if it
                              ;; lands after we gave up, close it so the
                              ;; conn/fd is not leaked
                              (receive (after 5000 'done)
                                (`#(tcp-connected ,c) (tcp-close! c))
                                (`#(tcp-connect-failed ,e) 'done)))
                    (`#(tcp-connected ,c)
                      (tcp-read-start! c)
                      ;; if TLS setup or a later codec step raises, free
                      ;; the session and the socket before propagating
                      (let ((codec #f))
                        (guard (e (#t (when codec ((vector-ref codec 2)))
                                      (tcp-close! c)
                                      (raise e)))
                          (when tls?
                            (set! codec (https-connector c host timeout)))
                          (let ((req (build-request method host path headers body)))
                            (tcp-write! c (if codec ((vector-ref codec 0) req) req) #f))
                          (client-loop c caller ref empty-bv #f timeout codec))))
                    (`#(tcp-connect-failed ,e)
                      (send caller (vector 'http-error ref (uv-strerror e))))))
                (`#(dns-failed ,e)
                  (send caller (vector 'http-error ref "dns resolution failed")))))))
        (receive (after (+ timeout 2000)
                    (raise (vector 'http-client-error "request timeout")))
          (`#(http-reply ,@ref ,resp) resp)
          (`#(http-error ,@ref ,msg) (raise (vector 'http-client-error msg)))))))

  (define (http-get url . rest)
    (apply http-request 'GET url rest))

  (define (http-post url body . rest)
    (let ((opts (if (pair? rest) (car rest) '())))
      (http-request 'POST url (cons (cons 'body body) opts))))
)
