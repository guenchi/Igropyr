#!chezscheme
;;; (igropyr http) -- HTTP/1.1 core, in the spirit of Node's `http` module.
;;;
;;; The core knows the protocol, not the framework: it parses requests,
;;; owns the connection lifecycle, runs every request through the fault-
;;; tolerant worker pool, and encodes responses. It exposes exactly one
;;; entry point:
;;;
;;;   (http-listen port (lambda (req res) ...))          ; 8 workers
;;;   (http-listen port (lambda (req res) ...) workers)
;;;
;;; There is no router, no middleware, no MIME table here -- those are
;;; framework concerns; see (igropyr express) for one such layer, or
;;; build your own: anything that produces a (lambda (req res)) handler
;;; sits on the same footing as express.
;;;
;;; Response primitives (the res.end level): set-status!, set-header!,
;;; res-send!. Convenience encoders (JSON, files, ...) belong to layers.
;;;
;;; Connection lifecycle:
;;;   accept -> one reader process per connection (a half-sent request
;;;   parks only its own reader and is reaped by a 30s timeout)
;;;   reader parses request line/headers/body incrementally, then sends
;;;   #(submit-task #(task ,id ,conn ,request)) to the supervisor;
;;;   a pool worker runs the handler and writes the response; the
;;;   write-completion callback tells the reader to parse the next
;;;   request (keep-alive) or closes the connection.

(library (igropyr http)
  (export http-listen http-swap! http-set-ws!
          req-method req-path req-query req-headers req-header req-body
          req-keep-alive? req-params req-params-set!
          set-status! set-header! res-send!
          res-conn res-status res-headers res-keep-alive?
          send-response!)
  (import (chezscheme) (igropyr actor) (igropyr uv) (igropyr otp)
          (igropyr ws))

  (define header-limit 8192)
  (define body-limit 1048576)
  (define read-timeout-ms 30000)   ; slow/half requests reaped after this
  (define await-timeout-ms 60000)  ; reader waits this long for a response

  ;; ---- bytevector helpers ------------------------------------------------

  (define empty-bv (make-bytevector 0))

  (define (bv-append a b)
    (let* ((la (bytevector-length a))
           (lb (bytevector-length b))
           (r (make-bytevector (+ la lb))))
      (bytevector-copy! a 0 r 0 la)
      (bytevector-copy! b 0 r la lb)
      r))

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  ;; index of the \r\n\r\n terminating the header block, or #f
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

  ;; ---- request record ------------------------------------------------------

  (define-record-type (request make-request request?)
    (fields
      (immutable method req-method)      ; symbol: GET POST ...
      (immutable path req-path)          ; decoded path string
      (immutable query req-query)        ; alist of (string . string)
      ;; free slot owned by framework layers (e.g. router path params)
      (mutable params req-params req-params-set!)
      (immutable headers req-headers)    ; alist of (symbol . string)
      (immutable body req-body)          ; bytevector
      (immutable keep-alive? req-keep-alive?)))

  (define (req-header req name)
    (let ((p (assq name (req-headers req))))
      (and p (cdr p))))

  ;; ---- parsing --------------------------------------------------------------

  (define (string-split s ch)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n) (reverse (cons (substring s start n) acc)))
          ((char=? (string-ref s i) ch)
           (loop (+ i 1) (+ i 1) (cons (substring s start i) acc)))
          (else (loop (+ i 1) start acc))))))

  (define (string-index s ch)
    (let ((n (string-length s)))
      (let scan ((i 0))
        (cond
          ((= i n) #f)
          ((char=? (string-ref s i) ch) i)
          (else (scan (+ i 1)))))))

  ;; %XX escapes are octets of a UTF-8 sequence: collect bytes first,
  ;; decode as UTF-8 once at the end (decoding each %XX to a character
  ;; directly would mangle multi-byte sequences like %E4%B8%AD).
  (define (percent-decode s)
    (let ((n (string-length s)))
      (let-values (((p get) (open-bytevector-output-port)))
        (let loop ((i 0))
          (when (< i n)
            (let ((ch (string-ref s i)))
              (cond
                ((and (char=? ch #\%) (< (+ i 2) n))
                 (let ((v (string->number (substring s (+ i 1) (+ i 3)) 16)))
                   (if v
                       (begin (put-u8 p v) (loop (+ i 3)))
                       (begin (put-bytevector p (string->utf8 (string ch)))
                              (loop (+ i 1))))))
                ((char=? ch #\+) (put-u8 p 32) (loop (+ i 1)))
                (else
                 (put-bytevector p (string->utf8 (string ch)))
                 (loop (+ i 1)))))))
        (utf8->string (get)))))

  (define (parse-query s)
    (if (string=? s "")
        '()
        (map (lambda (kv)
               (let ((parts (string-split kv #\=)))
                 (if (>= (length parts) 2)
                     (cons (percent-decode (car parts))
                           (percent-decode (cadr parts)))
                     (cons (percent-decode (car parts)) ""))))
             (string-split s #\&))))

  (define (strip-cr l)
    (let ((n (string-length l)))
      (if (and (> n 0) (char=? (string-ref l (- n 1)) #\return))
          (substring l 0 (- n 1))
          l)))

  ;; "Content-Length: 42" -> (content-length . "42"), or #f
  (define (parse-header-line l)
    (let ((colon (string-index l #\:)))
      (and colon
           (let ((k (string->symbol (string-downcase (substring l 0 colon))))
                 (v (let trim ((j (+ colon 1)))
                      (if (and (< j (string-length l))
                               (char=? (string-ref l j) #\space))
                          (trim (+ j 1))
                          (substring l j (string-length l))))))
             (cons k v)))))

  (define (parse-header-lines lines)
    (fold-right
      (lambda (l acc)
        (let ((kv (and (not (string=? l "")) (parse-header-line l))))
          (if kv (cons kv acc) acc)))
      '() lines))

  ;; Parse request line + headers from the header block.
  ;; Returns #(method path query version headers) or #f on malformed input.
  (define (parse-head bv hend)
    (guard (e (#t #f))
      (let* ((text (utf8->string (bv-sub bv 0 hend)))
             (lines (map strip-cr (string-split text #\newline)))
             (rl (string-split (car lines) #\space)))
        (and (= (length rl) 3)
             (let* ((method (string->symbol (car rl)))
                    (target (cadr rl))
                    (version (caddr rl))
                    (qpos (string-index target #\?))
                    (path (percent-decode
                            (if qpos (substring target 0 qpos) target)))
                    (query (if qpos
                               (parse-query
                                 (substring target (+ qpos 1)
                                            (string-length target)))
                               '()))
                    (headers (parse-header-lines (cdr lines))))
               (vector method path query version headers))))))

  (define (content-length headers)
    (let ((p (assq 'content-length headers)))
      (if p (or (string->number (cdr p)) 0) 0)))

  (define (chunked-body? headers)
    (let ((p (assq 'transfer-encoding headers)))
      (and p (string-ci=? (cdr p) "chunked"))))

  ;; websocket upgrade request? returns the Sec-WebSocket-Key or #f
  (define (websocket-key headers)
    (let ((u (assq 'upgrade headers))
          (k (assq 'sec-websocket-key headers)))
      (and u k (string-ci=? (cdr u) "websocket") (cdr k))))

  (define (keep-alive? version headers)
    (let* ((p (assq 'connection headers))
           (cn (and p (string-downcase (cdr p)))))
      (if (string=? version "HTTP/1.1")
          (not (equal? cn "close"))
          (equal? cn "keep-alive"))))

  ;; ---- responses -------------------------------------------------------------

  (define (status-text s)
    (case s
      ((200) "OK") ((201) "Created") ((204) "No Content")
      ((301) "Moved Permanently") ((302) "Found") ((304) "Not Modified")
      ((400) "Bad Request") ((403) "Forbidden") ((404) "Not Found")
      ((408) "Request Timeout") ((413) "Payload Too Large")
      ((431) "Request Header Fields Too Large")
      ((500) "Internal Server Error") ((503) "Service Unavailable")
      (else "Unknown")))

  ;; Write a full response. The completion callback (libuv context: no
  ;; yielding) tells the reader to continue (keep-alive) or closes the
  ;; connection and lets the reader finish. Guarded by conn-responded?
  ;; so a supervisor fallback 500 can never double-write.
  (define (send-response! c status headers body ka)
    (unless (conn-responded? c)
      (conn-set-responded! c #t)
      (let* ((head
              (string-append
                "HTTP/1.1 " (number->string status) " " (status-text status)
                "\r\n"
                (apply string-append
                       (map (lambda (h)
                              (string-append (car h) ": " (cdr h) "\r\n"))
                            headers))
                "Content-Length: " (number->string (bytevector-length body))
                "\r\nConnection: " (if ka "keep-alive" "close")
                "\r\n\r\n"))
             (full (bv-append (string->utf8 head) body))
             (owner (conn-owner c)))
        (tcp-write! c full
          (lambda (st)
            (if (and ka (>= st 0))
                (send owner (vector 'next-request))
                (begin
                  (tcp-close! c)
                  (send owner (vector 'conn-closed)))))))))

  ;; minimal error response; always closes
  (define (quick-response! c status text)
    (send-response! c status '(("Content-Type" . "text/plain"))
                    (string->utf8 text) #f))

  ;; ---- res record + primitives (the res.end level) ----------------------------

  (define-record-type (res make-res res?)
    (fields
      (immutable conn res-conn)
      (mutable status res-status res-status-set!)
      (mutable headers res-headers res-headers-set!)
      (immutable keep-alive? res-keep-alive?)))

  (define (set-status! r s) (res-status-set! r s))

  (define (set-header! r k v)
    (res-headers-set! r (cons (cons k v) (res-headers r))))

  ;; Send the response: current status + accumulated headers + body
  ;; bytevector. One shot per request; later calls are ignored.
  (define (res-send! r body)
    (send-response! (res-conn r) (res-status r) (res-headers r)
                    body (res-keep-alive? r)))

  ;; ---- task execution (inside a pool worker) -----------------------------------

  ;; A crash here kills the worker (Let It Crash): the supervisor retries
  ;; the task up to 3 times, then answers 500 via fail-task below.
  (define (run-task handler task)
    (let* ((c (vector-ref task 2))
           (req (vector-ref task 3))
           (r (make-res c 200 '() (req-keep-alive? req))))
      (handler req r)
      ;; handler finished without responding: don't leave the client hanging
      (unless (conn-responded? c)
        (set-status! r 404)
        (set-header! r "Content-Type" "text/plain; charset=utf-8")
        (res-send! r (string->utf8 "Not Found")))))

  ;; supervisor gave up on the task (crash retries exhausted, or stuck
  ;; worker killed): last-resort 500 unless a response already went out
  (define (fail-task task)
    (let ((c (vector-ref task 2)))
      (quick-response! c 500 "Internal Server Error")))

  ;; ---- chunked transfer-encoding (request side) ----------------------------------

  (define (find-crlf bv start)
    (let ((n (bytevector-length bv)))
      (let loop ((i start))
        (cond
          ((>= (+ i 1) n) #f)
          ((and (fx= (bytevector-u8-ref bv i) 13)
                (fx= (bytevector-u8-ref bv (+ i 1)) 10))
           i)
          (else (loop (+ i 1)))))))

  ;; hex chunk size, stopping at ';' (chunk extensions); #f if malformed
  (define (parse-chunk-size bv start end)
    (let loop ((i start) (v 0) (any #f))
      (if (= i end)
          (and any v)
          (let ((b (bytevector-u8-ref bv i)))
            (cond
              ((= b 59) (and any v))                                 ; ';'
              ((and (>= b 48) (<= b 57)) (loop (+ i 1) (+ (* v 16) (- b 48)) #t))
              ((and (>= b 97) (<= b 102)) (loop (+ i 1) (+ (* v 16) (- b 87)) #t))
              ((and (>= b 65) (<= b 70)) (loop (+ i 1) (+ (* v 16) (- b 55)) #t))
              (else #f))))))

  (define (bv-concat lst total)
    (let ((out (make-bytevector total)))
      (let loop ((l lst) (off 0))
        (if (null? l)
            out
            (let ((x (car l)))
              (bytevector-copy! x 0 out off (bytevector-length x))
              (loop (cdr l) (+ off (bytevector-length x))))))))

  ;; Try to parse a complete chunked body starting at `start`.
  ;; -> (values 'done body end-index) | (values 'more #f #f)
  ;;  | (values 'too-large #f #f) | (values 'bad #f #f)
  (define (parse-chunked-body bv start)
    (let loop ((pos start) (chunks '()) (len 0))
      (let ((eol (find-crlf bv pos)))
        (if (not eol)
            (if (> (- (bytevector-length bv) start) (+ body-limit 1024))
                (values 'too-large #f #f)
                (values 'more #f #f))
            (let ((size (parse-chunk-size bv pos eol)))
              (cond
                ((not size) (values 'bad #f #f))
                ((> (+ len size) body-limit) (values 'too-large #f #f))
                ((= size 0)
                 ;; skip optional trailers; a blank line ends the body
                 (let scan ((p (+ eol 2)))
                   (let ((e2 (find-crlf bv p)))
                     (cond
                       ((not e2) (values 'more #f #f))
                       ((= e2 p)
                        (values 'done (bv-concat (reverse chunks) len) (+ p 2)))
                       (else (scan (+ e2 2)))))))
                (else
                 (let ((dstart (+ eol 2)))
                   (if (< (bytevector-length bv) (+ dstart size 2))
                       (values 'more #f #f)
                       (loop (+ dstart size 2)   ; data + trailing CRLF
                             (cons (bv-sub bv dstart (+ dstart size)) chunks)
                             (+ len size)))))))))))

  ;; ---- reader process ----------------------------------------------------------

  (define task-counter 0)
  (define (next-task-id!)
    (set! task-counter (+ task-counter 1))
    task-counter)

  (define (make-reader c srv)
    (lambda () (reader-loop c srv empty-bv)))

  (define (reader-loop c srv acc)
    (conn-set-responded! c #f)
    (let ((hend (find-header-end acc)))
      (cond
        (hend (have-header c srv acc hend))
        ((> (bytevector-length acc) header-limit)
         (quick-response! c 431 "Header Too Large"))
        (else
         (receive (after read-timeout-ms
                     (if (> (bytevector-length acc) 0)
                         (quick-response! c 408 "Request Timeout")
                         (tcp-close! c)))   ; idle connection: just close
           (`#(tcp-data ,bv) (reader-loop c srv (bv-append acc bv)))
           (`#(tcp-eof) (tcp-close! c))
           (`#(tcp-error ,e) (tcp-close! c)))))))

  (define (have-header c srv acc hend)
    (let ((parsed (parse-head acc hend)))
      (if (not parsed)
          (quick-response! c 400 "Bad Request")
          (let* ((headers (vector-ref parsed 4))
                 (wskey (websocket-key headers))
                 (resolver (unbox (http-server-wsbox srv))))
            (cond
              ;; websocket upgrade: resolve a session, shake hands, and
              ;; run the session in this reader process
              ((and wskey resolver)
               (let* ((req (make-request (vector-ref parsed 0)
                                         (vector-ref parsed 1)
                                         (vector-ref parsed 2)
                                         '() headers empty-bv #f))
                      (session (resolver req)))
                 (if session
                     (run-ws-session c acc hend wskey req session)
                     (quick-response! c 404 "Not Found"))))
              ((chunked-body? headers)
               (collect-chunked c srv acc parsed (+ hend 4)))
              (else
               (let ((clen (content-length headers)))
                 (if (> clen body-limit)
                     (quick-response! c 413 "Payload Too Large")
                     (collect-body c srv acc parsed (+ hend 4 clen))))))))))

  ;; hand the parsed request to the worker pool, then await the response
  (define (dispatch-request! c srv parsed body leftover)
    (let* ((headers (vector-ref parsed 4))
           (req (make-request (vector-ref parsed 0)
                              (vector-ref parsed 1)
                              (vector-ref parsed 2)
                              '()
                              headers
                              body
                              (keep-alive? (vector-ref parsed 3) headers)))
           (id (next-task-id!)))
      (send (http-server-sup srv) (vector 'submit-task (vector 'task id c req)))
      (await-response c srv leftover #f)))

  (define (collect-body c srv acc parsed total)
    (if (>= (bytevector-length acc) total)
        (let ((body-start (- total (content-length (vector-ref parsed 4)))))
          (dispatch-request! c srv parsed
            (bv-sub acc body-start total)
            (bv-sub acc total (bytevector-length acc))))
        (receive (after read-timeout-ms (quick-response! c 408 "Request Timeout"))
          (`#(tcp-data ,bv) (collect-body c srv (bv-append acc bv) parsed total))
          (`#(tcp-eof) (tcp-close! c))
          (`#(tcp-error ,e) (tcp-close! c)))))

  (define (collect-chunked c srv acc parsed body-start)
    (let-values (((st body end) (parse-chunked-body acc body-start)))
      (case st
        ((done)
         (dispatch-request! c srv parsed body
           (bv-sub acc end (bytevector-length acc))))
        ((more)
         (receive (after read-timeout-ms (quick-response! c 408 "Request Timeout"))
           (`#(tcp-data ,bv) (collect-chunked c srv (bv-append acc bv) parsed body-start))
           (`#(tcp-eof) (tcp-close! c))
           (`#(tcp-error ,e) (tcp-close! c))))
        ((too-large) (quick-response! c 413 "Payload Too Large"))
        (else (quick-response! c 400 "Bad Request")))))

  ;; Wait for the worker's response to complete. Data arriving meanwhile
  ;; (pipelining) is buffered; EOF is remembered so we stop after replying.
  (define (await-response c srv leftover eof?)
    (receive (after await-timeout-ms (tcp-close! c))
      (`#(next-request)
        (if eof? (tcp-close! c) (reader-loop c srv leftover)))
      (`#(conn-closed) 'done)
      (`#(tcp-data ,bv) (await-response c srv (bv-append leftover bv) eof?))
      (`#(tcp-eof) (await-response c srv leftover #t))
      (`#(tcp-error ,e) (await-response c srv leftover #t))))

  ;; ---- websocket session ---------------------------------------------------------

  ;; 101 handshake, then hand the connection to the session procedure,
  ;; still inside this reader process (one process per ws connection).
  ;; A crashing session just closes its own connection.
  (define (run-ws-session c acc hend key req session)
    (conn-set-responded! c #t)
    (tcp-write! c
      (string->utf8
        (string-append
          "HTTP/1.1 101 Switching Protocols\r\n"
          "Upgrade: websocket\r\nConnection: Upgrade\r\n"
          "Sec-WebSocket-Accept: " (ws-accept-key key)
          "\r\n\r\n"))
      #f)
    (let ((w (make-ws c (bv-sub acc (+ hend 4) (bytevector-length acc)))))
      (guard (e (#t (void)))
        (session w req))
      (ws-close! w)))

  ;; ---- listen ------------------------------------------------------------------

  ;; The running server: worker-pool supervisor plus two swappable slots.
  ;; hbox holds the (lambda (req res)) handler -- replacing it with
  ;; http-swap! upgrades the code with zero downtime (in-flight requests
  ;; finish on the old handler; new requests get the new one).
  ;; wsbox holds the websocket resolver: (lambda (req) session-or-#f).
  (define-record-type (http-server make-http-server http-server?)
    (fields
      (immutable sup http-server-sup)
      (immutable hbox http-server-hbox)
      (immutable wsbox http-server-wsbox)))

  (define (http-swap! srv handler)
    (set-box! (http-server-hbox srv) handler))

  (define (http-set-ws! srv resolver)
    (set-box! (http-server-wsbox srv) resolver))

  ;; Start the worker pool and the TCP listener; handler is
  ;; (lambda (req res) ...), run inside a pool worker for every request.
  ;; Must run inside the scheduler (call from the start-scheduler boot
  ;; thunk). Returns an http-server usable with http-swap!/http-set-ws!.
  ;;
  ;; The optional third argument configures the pool: either a plain
  ;; integer (worker count) or an alist:
  ;;   (http-listen 8080 handler
  ;;     '((workers . 16)        ; pool size            (default 8)
  ;;       (max-retries . 3)     ; crash retries        (default 3)
  ;;       (stuck-ms . 30000)    ; stuck-kill threshold (default 30000)
  ;;       (check-ms . 5000)))   ; ticker interval      (default 5000)
  (define (http-listen port handler . rest)
    (define opts
      (cond
        ((null? rest) '())
        ((integer? (car rest)) (list (cons 'workers (car rest))))
        ((or (null? (car rest)) (pair? (car rest))) (car rest))
        (else (assertion-violation 'http-listen "bad options" (car rest)))))
    (define (opt key default)
      (let ((p (assq key opts)))
        (if p (cdr p) default)))
    (let* ((hbox (box handler))
           (wsbox (box #f))
           (sup (start-worker-pool (opt 'workers 8)
                  (lambda (task) (run-task (unbox hbox) task))
                  fail-task
                  (opt 'max-retries 3)
                  (opt 'stuck-ms 30000)
                  (opt 'check-ms 5000)))
           (srv (make-http-server sup hbox wsbox)))
      (tcp-listen! "0.0.0.0" port 511
        (lambda (c)
          ;; libuv callback context: spawn + register only, no yielding
          (let ((pid (spawn (make-reader c srv))))
            (conn-set-owner! c pid)
            (tcp-read-start! c))))
      (display (string-append "igropyr listening on http://0.0.0.0:"
                              (number->string port) "\n"))
      srv))
)
