#!chezscheme
;;; (igropyr http) -- HTTP/1.1 server with an Express-style API.
;;;
;;; Connection lifecycle:
;;;   accept -> one reader process per connection (a half-sent request
;;;   parks only its own reader and is reaped by a 30s timeout)
;;;   reader parses request line/headers/body incrementally, then sends
;;;   #(submit-task #(task ,id ,conn ,request)) to the supervisor;
;;;   a pool worker runs middleware + route handler and writes the
;;;   response; the write-completion callback tells the reader to parse
;;;   the next request (keep-alive) or closes the connection.
;;;
;;; API: create-app, app-get/post/put/delete (with :param segments),
;;; app-use (middleware), app-static, app-listen; request accessors;
;;; set-status!, send-text!/send-html!/send-json!/send-file!.

(library (igropyr http)
  (export create-app app-get app-post app-put app-delete
          app-use app-static app-listen
          req-method req-path req-query req-params req-headers
          req-header req-body req-param
          set-status! set-header! send-text! send-html! send-json! send-file!
          res-conn)
  (import (chezscheme) (igropyr actor) (igropyr uv) (igropyr otp))

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
      (mutable params req-params req-params-set!) ; alist, set by router
      (immutable headers req-headers)    ; alist of (symbol . string)
      (immutable body req-body)          ; bytevector
      (immutable keep-alive? req-keep-alive?)))

  (define (req-header req name)
    (let ((p (assq name (req-headers req))))
      (and p (cdr p))))

  (define (req-param req name)
    (let ((p (assoc name (req-params req))))
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

  (define (percent-decode s)
    (let ((n (string-length s)))
      (call-with-string-output-port
        (lambda (p)
          (let loop ((i 0))
            (when (< i n)
              (let ((ch (string-ref s i)))
                (cond
                  ((and (char=? ch #\%) (< (+ i 2) (+ n 0)))
                   (let ((v (string->number (substring s (+ i 1) (+ i 3)) 16)))
                     (if v
                         (begin (write-char (integer->char v) p) (loop (+ i 3)))
                         (begin (write-char ch p) (loop (+ i 1))))))
                  ((char=? ch #\+) (write-char #\space p) (loop (+ i 1)))
                  (else (write-char ch p) (loop (+ i 1)))))))))))

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

  (define (string-index s ch)
    (let ((n (string-length s)))
      (let scan ((i 0))
        (cond
          ((= i n) #f)
          ((char=? (string-ref s i) ch) i)
          (else (scan (+ i 1)))))))

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

  ;; ---- res record + Express-style helpers --------------------------------------

  (define-record-type (res make-res res?)
    (fields
      (immutable conn res-conn)
      (mutable status res-status res-status-set!)
      (mutable headers res-headers res-headers-set!)
      (immutable keep-alive? res-keep-alive?)))

  (define (set-status! r s) (res-status-set! r s))
  (define (set-header! r k v)
    (res-headers-set! r (cons (cons k v) (res-headers r))))

  (define (finish! r ctype body)
    (send-response! (res-conn r) (res-status r)
                    (cons (cons "Content-Type" ctype) (res-headers r))
                    body (res-keep-alive? r)))

  (define (send-text! r s) (finish! r "text/plain; charset=utf-8" (string->utf8 s)))
  (define (send-html! r s) (finish! r "text/html; charset=utf-8" (string->utf8 s)))
  (define (send-json! r obj) (finish! r "application/json" (string->utf8 (json->string obj))))

  ;; ---- tiny JSON writer: alist -> object, list -> array ------------------------

  (define (json-escape s)
    (call-with-string-output-port
      (lambda (p)
        (string-for-each
          (lambda (ch)
            (case ch
              ((#\") (display "\\\"" p))
              ((#\\) (display "\\\\" p))
              ((#\newline) (display "\\n" p))
              ((#\return) (display "\\r" p))
              ((#\tab) (display "\\t" p))
              (else (write-char ch p))))
          s))))

  (define (json->string x)
    (cond
      ((eq? x #t) "true")
      ((eq? x #f) "false")
      ((eq? x 'null) "null")
      ((number? x)
       (if (exact? x) (number->string x) (number->string (exact->inexact x))))
      ((string? x) (string-append "\"" (json-escape x) "\""))
      ((symbol? x) (string-append "\"" (json-escape (symbol->string x)) "\""))
      ((and (list? x) (pair? x) (pair? (car x)))   ; alist -> object
       (string-append
         "{"
         (fold-right
           (lambda (kv acc)
             (let ((entry (string-append
                            "\"" (json-escape
                                   (if (symbol? (car kv))
                                       (symbol->string (car kv))
                                       (car kv)))
                            "\":" (json->string (cdr kv)))))
               (if (string=? acc "") entry (string-append entry "," acc))))
           "" x)
         "}"))
      ((list? x)                                    ; list -> array
       (string-append
         "["
         (fold-right
           (lambda (v acc)
             (if (string=? acc "")
                 (json->string v)
                 (string-append (json->string v) "," acc)))
           "" x)
         "]"))
      (else "null")))

  ;; ---- static files ---------------------------------------------------------------

  (define (mime-type path)
    (let* ((dot (let scan ((i (- (string-length path) 1)))
                  (cond ((< i 0) #f)
                        ((char=? (string-ref path i) #\.) i)
                        (else (scan (- i 1))))))
           (ext (and dot (string-downcase
                           (substring path (+ dot 1) (string-length path))))))
      (cond
        ((equal? ext "html") "text/html; charset=utf-8")
        ((equal? ext "css") "text/css")
        ((equal? ext "js") "application/javascript")
        ((equal? ext "json") "application/json")
        ((equal? ext "txt") "text/plain; charset=utf-8")
        ((equal? ext "png") "image/png")
        ((equal? ext "jpg") "image/jpeg")
        ((equal? ext "jpeg") "image/jpeg")
        ((equal? ext "gif") "image/gif")
        ((equal? ext "svg") "image/svg+xml")
        ((equal? ext "ico") "image/x-icon")
        (else "application/octet-stream"))))

  (define (read-file-bv path)
    (guard (e (#t #f))
      (and (file-exists? path)
           (call-with-port (open-file-input-port path)
             (lambda (p)
               (let ((bv (get-bytevector-all p)))
                 (if (eof-object? bv) empty-bv bv)))))))

  (define (path-has-dotdot? s)
    (let ((parts (string-split s #\/)))
      (exists (lambda (p) (string=? p "..")) parts)))

  (define (send-file! r path)
    (if (path-has-dotdot? path)
        (begin (set-status! r 403) (send-text! r "Forbidden"))
        (let ((bv (read-file-bv path)))
          (if bv
              (finish! r (mime-type path) bv)
              (begin (set-status! r 404) (send-text! r "Not Found"))))))

  ;; ---- router ---------------------------------------------------------------------

  ;; "/users/:id" -> ("users" ":id"); "/" -> ()
  (define (split-segments path)
    (filter (lambda (s) (not (string=? s ""))) (string-split path #\/)))

  ;; match pattern segments against path segments; alist of params or #f
  (define (match-segments psegs segs)
    (let loop ((ps psegs) (ss segs) (params '()))
      (cond
        ((and (null? ps) (null? ss)) params)
        ((or (null? ps) (null? ss)) #f)
        ((and (> (string-length (car ps)) 0)
              (char=? (string-ref (car ps) 0) #\:))
         (loop (cdr ps) (cdr ss)
               (cons (cons (substring (car ps) 1 (string-length (car ps)))
                           (car ss))
                     params)))
        ((string=? (car ps) (car ss))
         (loop (cdr ps) (cdr ss) params))
        (else #f))))

  ;; ---- app ------------------------------------------------------------------------

  (define-record-type (app make-app-record app?)
    (fields
      (mutable routes app-routes app-routes-set!)       ; list of #(method segs handler)
      (mutable middlewares app-middlewares app-middlewares-set!)
      (mutable statics app-statics app-statics-set!)))  ; list of (prefix . root)

  (define (create-app) (make-app-record '() '() '()))

  (define (add-route! a method pattern handler)
    (app-routes-set! a
      (append (app-routes a)
              (list (vector method (split-segments pattern) handler)))))

  (define (app-get a pattern handler) (add-route! a 'GET pattern handler))
  (define (app-post a pattern handler) (add-route! a 'POST pattern handler))
  (define (app-put a pattern handler) (add-route! a 'PUT pattern handler))
  (define (app-delete a pattern handler) (add-route! a 'DELETE pattern handler))

  ;; middleware: (lambda (req res next) ...); call (next) to continue
  (define (app-use a mw)
    (app-middlewares-set! a (append (app-middlewares a) (list mw))))

  (define (app-static a prefix root)
    (app-statics-set! a (append (app-statics a) (list (cons prefix root)))))

  (define (string-prefix? p s)
    (and (>= (string-length s) (string-length p))
         (string=? p (substring s 0 (string-length p)))))

  (define (try-static a req r)
    (and (eq? (req-method req) 'GET)
         (exists
           (lambda (entry)
             (let ((prefix (car entry)) (root (cdr entry)))
               (and (string-prefix? prefix (req-path req))
                    (begin
                      (send-file! r
                        (string-append root
                          (substring (req-path req)
                                     (string-length prefix)
                                     (string-length (req-path req)))))
                      #t))))
           (app-statics a))))

  (define (route-dispatch a req r)
    (let ((segs (split-segments (req-path req))))
      (let loop ((routes (app-routes a)))
        (cond
          ((null? routes)
           (or (try-static a req r)
               (begin (set-status! r 404) (send-text! r "Not Found"))))
          (else
           (let ((route (car routes)))
             (let ((params (and (eq? (vector-ref route 0) (req-method req))
                                (match-segments (vector-ref route 1) segs))))
               (if params
                   (begin
                     (req-params-set! req params)
                     ((vector-ref route 2) req r))
                   (loop (cdr routes))))))))))

  ;; Executed inside a pool worker; a crash here kills the worker (Let It
  ;; Crash) and the supervisor takes over.
  (define (run-app-task a task)
    (let* ((c (vector-ref task 2))
           (req (vector-ref task 3))
           (r (make-res c 200 '() (req-keep-alive? req)))
           (endpoint (lambda () (route-dispatch a req r))))
      ((fold-right
         (lambda (mw next) (lambda () (mw req r next)))
         endpoint
         (app-middlewares a)))
      ;; handler finished without responding: don't leave the client hanging
      (unless (conn-responded? c)
        (set-status! r 404)
        (send-text! r "Not Found"))))

  ;; supervisor gave up on the task (crash retries exhausted, or stuck
  ;; worker killed): last-resort 500 unless a response already went out
  (define (fail-app-task task)
    (let ((c (vector-ref task 2)))
      (quick-response! c 500 "Internal Server Error")))

  ;; ---- reader process ----------------------------------------------------------------

  (define task-counter 0)
  (define (next-task-id!)
    (set! task-counter (+ task-counter 1))
    task-counter)

  (define (make-reader c sup)
    (lambda () (reader-loop c sup empty-bv)))

  (define (reader-loop c sup acc)
    (conn-set-responded! c #f)
    (let ((hend (find-header-end acc)))
      (cond
        (hend (have-header c sup acc hend))
        ((> (bytevector-length acc) header-limit)
         (quick-response! c 431 "Header Too Large"))
        (else
         (receive (after read-timeout-ms
                     (if (> (bytevector-length acc) 0)
                         (quick-response! c 408 "Request Timeout")
                         (tcp-close! c)))   ; idle connection: just close
           (`#(tcp-data ,bv) (reader-loop c sup (bv-append acc bv)))
           (`#(tcp-eof) (tcp-close! c))
           (`#(tcp-error ,e) (tcp-close! c)))))))

  (define (have-header c sup acc hend)
    (let ((parsed (parse-head acc hend)))
      (if (not parsed)
          (quick-response! c 400 "Bad Request")
          (let ((clen (content-length (vector-ref parsed 4))))
            (if (> clen body-limit)
                (quick-response! c 413 "Payload Too Large")
                (collect-body c sup acc parsed (+ hend 4 clen)))))))

  (define (collect-body c sup acc parsed total)
    (if (>= (bytevector-length acc) total)
        (let* ((headers (vector-ref parsed 4))
               (body-start (- total (content-length headers)))
               (body (bv-sub acc body-start total))
               (leftover (bv-sub acc total (bytevector-length acc)))
               (req (make-request (vector-ref parsed 0)
                                  (vector-ref parsed 1)
                                  (vector-ref parsed 2)
                                  '()
                                  headers
                                  body
                                  (keep-alive? (vector-ref parsed 3) headers)))
               (id (next-task-id!)))
          (send sup (vector 'submit-task (vector 'task id c req)))
          (await-response c sup leftover #f))
        (receive (after read-timeout-ms (quick-response! c 408 "Request Timeout"))
          (`#(tcp-data ,bv) (collect-body c sup (bv-append acc bv) parsed total))
          (`#(tcp-eof) (tcp-close! c))
          (`#(tcp-error ,e) (tcp-close! c)))))

  ;; Wait for the worker's response to complete. Data arriving meanwhile
  ;; (pipelining) is buffered; EOF is remembered so we stop after replying.
  (define (await-response c sup leftover eof?)
    (receive (after await-timeout-ms (tcp-close! c))
      (`#(next-request)
        (if eof? (tcp-close! c) (reader-loop c sup leftover)))
      (`#(conn-closed) 'done)
      (`#(tcp-data ,bv) (await-response c sup (bv-append leftover bv) eof?))
      (`#(tcp-eof) (await-response c sup leftover #t))
      (`#(tcp-error ,e) (await-response c sup leftover #t))))

  ;; ---- listen ------------------------------------------------------------------------

  ;; Start the worker pool and the TCP listener. Must run inside the
  ;; scheduler (call from the start-scheduler boot thunk).
  (define (app-listen a port . opts)
    (let* ((nworkers (if (pair? opts) (car opts) 8))
           (sup (start-worker-pool nworkers
                  (lambda (task) (run-app-task a task))
                  fail-app-task)))
      (tcp-listen! "0.0.0.0" port 511
        (lambda (c)
          ;; libuv callback context: spawn + register only, no yielding
          (let ((pid (spawn (make-reader c sup))))
            (conn-set-owner! c pid)
            (tcp-read-start! c))))
      (display (string-append "igropyr listening on http://0.0.0.0:"
                              (number->string port) "\n"))
      sup))
)
