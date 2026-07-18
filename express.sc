#!chezscheme
;;; (igropyr express) -- an Express-style framework on the Igropyr core.
;;;
;;; This is a framework layer, not part of the engine: it turns an app
;;; description (routes, middleware, static mounts) into the single
;;; (lambda (req res) ...) handler that (igropyr http)'s http-listen
;;; expects. Alternative frameworks can be built the same way against
;;; the same core.
;;;
;;;   (define app (create-app))
;;;   (app-get app "/users/:id" (lambda (req res) ...))
;;;   (app-use app (lambda (req res next) ...))
;;;   (app-static app "/assets" "./public")
;;;   (start-scheduler (lambda () (app-listen app 8080)))
;;;
;;; Convenience response encoders live here too (the res.json level):
;;; send-text!, send-html!, send-json!, send-file!.

(library (igropyr express)
  (export create-app app-get app-post app-put app-delete
          app-use app-static app-ws app-listen app->handler
          req-param req-json req-form req-cookie set-cookie!
          req-sexpr send-sexpr! app-rpc
          ws-send-sexpr! ws-recv-sexpr sse-send-sexpr!
          send-text! send-html! send-json! send-file!
          sse-start! sse-send! make-fault-handler)
  (import (chezscheme) (igropyr checked)
          (igropyr actor) (igropyr libuv) (igropyr http)
          (igropyr json) (igropyr gzip) (igropyr sexpr)
          (only (igropyr websocket) ws-recv ws-send-text! ws?))

  ;; ---- string helpers -----------------------------------------------------

  (define (string-split s ch)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n) (reverse (cons (substring s start n) acc)))
          ((char=? (string-ref s i) ch)
           (loop (+ i 1) (+ i 1) (cons (substring s start i) acc)))
          (else (loop (+ i 1) start acc))))))

  ;; char-wise: no substring allocation on this per-request check
  (define (string-prefix? p s)
    (let ((pl (string-length p)))
      (and (fx>= (string-length s) pl)
           (let loop ((i 0))
             (or (fx= i pl)
                 (and (char=? (string-ref s i) (string-ref p i))
                      (loop (fx+ i 1))))))))

  ;; ---- response encoders (the res.json level) --------------------------------

  ;; compress bodies over this size when the client accepts gzip and the
  ;; content type is worth compressing (already-compressed formats like
  ;; images are skipped)
  (define gzip-min-size 1024)

  (define compressible-prefixes
    '("text/" "application/json" "application/javascript"
      "application/xml" "image/svg+xml"))

  (define (compressible-type? ctype)
    (exists (lambda (p) (string-prefix? p ctype)) compressible-prefixes))

  (define (finish! r ctype body)
    (set-header! r "Content-Type" ctype)
    (let ((ae (req-header (res-req r) 'accept-encoding)))
      (if (and (> (bytevector-length body) gzip-min-size)
               (compressible-type? ctype)
               (gzip-acceptable? ae))
          (let ((gz (gzip-compress body 6)))
            (if gz
                (begin
                  (set-header! r "Content-Encoding" "gzip")
                  (set-header! r "Vary" "Accept-Encoding")
                  (res-send! r gz))
                (res-send! r body)))          ; compression failed: send raw
          (res-send! r body))))

  ;; Every encoder also accepts a bytevector, taken as the body already
  ;; encoded. The fast pattern for constant responses is to do the
  ;; encoding ONCE at startup with define, so the handler just hands the
  ;; framework a pointer:
  ;;   (define home (string->utf8 "<h1>hi</h1>"))
  ;;   (app-get app "/" (lambda (req res) (send-html! res home)))
  (define (as-utf8 s) (if (string? s) (string->utf8 s) s))

  ;; body data accepted by every encoder: a string, or a bytevector
  ;; taken as the body already encoded
  (define (body-data? x) (or (string? x) (bytevector? x)))

  (define-checked (send-text! (r res?) (s body-data?))
    (finish! r "text/plain; charset=utf-8" (as-utf8 s)))
  (define-checked (send-html! (r res?) (s body-data?))
    (finish! r "text/html; charset=utf-8" (as-utf8 s)))
  ;; serialization comes from (igropyr json): alist -> object,
  ;; vector or list -> array, 'null -> null. A bytevector is passed
  ;; through as pre-serialized JSON (define it once at startup).
  (define-checked (send-json! (r res?) obj)
    (finish! r "application/json; charset=utf-8"
             (if (bytevector? obj)
                 obj
                 (string->utf8 (json->string obj)))))

  ;; parse a JSON request body; #f when the body is not valid JSON
  (define-checked (req-json (req request?))
    (guard (e (#t #f))
      (string->json (utf8->string (req-body req)))))

  ;; ---- s-expression bodies: Scheme-to-Scheme RPC ---------------------------
  ;; (igropyr sexpr) is the safe parser -- whitelisted data, depth
  ;; limited, never the host reader. Payloads are DATA: dispatch on a
  ;; tag, never evaluate.

  ;; parse an s-expression body; #f when invalid (or over 1 MiB)
  (define-checked (req-sexpr (req request?))
    (guard (e (#t #f))
      (let ((body (req-body req)))
        (and (<= (bytevector-length body) (* 1024 1024))
             (string->sexpr-extended (utf8->string body))))))

  ;; a bytevector is passed through as a pre-serialized datum
  (define-checked (send-sexpr! (r res?) x)
    (finish! r "application/sexpr; charset=utf-8"
             (if (bytevector? x)
                 x
                 (string->utf8 (sexpr->string-extended x)))))

  ;; ---- cookies --------------------------------------------------------------

  (define (string-trim s)
    (let ((n (string-length s)))
      (let ((a (let lp ((i 0)) (if (and (< i n) (char=? (string-ref s i) #\space))
                                   (lp (+ i 1)) i)))
            (b (let lp ((i n)) (if (and (> i 0) (char=? (string-ref s (- i 1)) #\space))
                                   (lp (- i 1)) i))))
        (if (< a b) (substring s a b) ""))))

  (define (string-index s ch)
    (let ((n (string-length s)))
      (let lp ((i 0))
        (cond ((= i n) #f)
              ((char=? (string-ref s i) ch) i)
              (else (lp (+ i 1)))))))

  ;; value of a cookie sent by the client, or #f
  (define-checked (req-cookie (req request?) (name string?))
    (let ((h (req-header req 'cookie)))
      (and h
           (let lp ((parts (string-split h #\;)))
             (cond
               ((null? parts) #f)
               (else
                (let* ((kv (string-trim (car parts)))
                       (eqp (string-index kv #\=)))
                  (if (and eqp (string=? (substring kv 0 eqp) name))
                      (substring kv (+ eqp 1) (string-length kv))
                      (lp (cdr parts))))))))))

  ;; add a Set-Cookie header; extra attribute strings are appended:
  ;;   (set-cookie! res "sid" "abc" "Path=/" "HttpOnly" "Max-Age=3600")
  (define (set-cookie! res name value . attrs)
    (set-header! res "Set-Cookie"
      (apply string-append name "=" value
             (map (lambda (a) (string-append "; " a)) attrs))))

  ;; ---- form bodies (urlencoded + multipart/form-data) ---------------------------

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  ;; first occurrence of needle in bv at or after `from`
  (define (bv-search bv needle from)
    (let ((n (bytevector-length bv))
          (m (bytevector-length needle)))
      (let outer ((i from))
        (cond
          ((> (+ i m) n) #f)
          ((let inner ((j 0))
             (cond ((= j m) #t)
                   ((fx= (bytevector-u8-ref bv (+ i j))
                         (bytevector-u8-ref needle j))
                    (inner (+ j 1)))
                   (else #f)))
           i)
          (else (outer (+ i 1)))))))

  ;; boundary=... from a Content-Type header (possibly quoted)
  (define (multipart-boundary ct)
    (let ((key "boundary="))
      (let lp ((i 0))
        (cond
          ((> (+ i (string-length key)) (string-length ct)) #f)
          ((string=? (substring ct i (+ i (string-length key))) key)
           (let* ((start (+ i (string-length key)))
                  (raw (let scan ((j start))
                         (if (or (= j (string-length ct))
                                 (memv (string-ref ct j) '(#\; #\space)))
                             (substring ct start j)
                             (scan (+ j 1))))))
             (if (and (> (string-length raw) 1)
                      (char=? (string-ref raw 0) #\"))
                 (substring raw 1 (- (string-length raw) 1))
                 raw)))
          (else (lp (+ i 1)))))))

  ;; "form-data; name=\"a\"; filename=\"b\"" -> value of one attribute
  (define (disposition-attr line attr)
    (let ((key (string-append attr "=\"")))
      (let lp ((i 0))
        (cond
          ((> (+ i (string-length key)) (string-length line)) #f)
          ((string=? (substring line i (+ i (string-length key))) key)
           (let ((start (+ i (string-length key))))
             (let scan ((j start))
               (cond ((= j (string-length line)) #f)
                     ((char=? (string-ref line j) #\") (substring line start j))
                     (else (scan (+ j 1)))))))
          (else (lp (+ i 1)))))))

  (define crlf2-bv (string->utf8 "\r\n\r\n"))

  ;; parse one multipart part: header block + payload
  ;; -> (name . string-value) or (name . #(file filename content-type bytes))
  (define (parse-part bv start end)
    (let ((hend (bv-search bv crlf2-bv start)))
      (and hend (<= (+ hend 4) end)
           (let* ((head (utf8->string (bv-sub bv start hend)))
                  (data (bv-sub bv (+ hend 4) end))
                  (disp (let lp ((lines (string-split head #\newline)))
                          (cond
                            ((null? lines) "")
                            ((let ((l (car lines)))
                               (and (>= (string-length l) 20)
                                    (string-ci=? (substring l 0 20)
                                                 "content-disposition:")))
                             (car lines))
                            (else (lp (cdr lines))))))
                  (name (disposition-attr disp "name"))
                  (filename (disposition-attr disp "filename"))
                  (ctype (let lp ((lines (string-split head #\newline)))
                           (cond
                             ((null? lines) "application/octet-stream")
                             ((let ((l (car lines)))
                                (and (>= (string-length l) 13)
                                     (string-ci=? (substring l 0 13)
                                                  "content-type:")))
                              (string-trim
                                (let ((l (car lines)))
                                  (let ((s (substring l 13 (string-length l))))
                                    (if (and (> (string-length s) 0)
                                             (char=? (string-ref s (- (string-length s) 1))
                                                     #\return))
                                        (substring s 0 (- (string-length s) 1))
                                        s)))))
                             (else (lp (cdr lines)))))))
             (and name
                  (cons name
                        (if filename
                            (vector 'file filename ctype data)
                            (utf8->string data))))))))

  (define (parse-multipart bv boundary)
    (let ((delim (string->utf8 (string-append "--" boundary))))
      (let lp ((pos (or (bv-search bv delim 0) (bytevector-length bv)))
               (acc '()))
        (let ((part-start (+ pos (bytevector-length delim) 2))) ; skip \r\n
          (if (or (> part-start (bytevector-length bv))
                  ;; "--" right after the delimiter: final boundary
                  (and (<= (+ pos (bytevector-length delim) 2) (bytevector-length bv))
                       (fx= (bytevector-u8-ref bv (+ pos (bytevector-length delim))) 45)
                       (fx= (bytevector-u8-ref bv (+ pos (bytevector-length delim) 1)) 45)))
              (reverse acc)
              (let ((next (bv-search bv delim part-start)))
                (if (not next)
                    (reverse acc)
                    (let ((part (parse-part bv part-start (- next 2)))) ; strip \r\n
                      (lp next (if part (cons part acc) acc))))))))))

  ;; Parse a form body. urlencoded -> alist of strings; multipart ->
  ;; alist where text fields are strings and uploads are
  ;; #(file ,filename ,content-type ,bytevector). '() otherwise.
  (define-checked (req-form (req request?))
    (let ((ct (or (req-header req 'content-type) "")))
      (cond
        ((and (>= (string-length ct) 33)
              (string-ci=? (substring ct 0 33)
                           "application/x-www-form-urlencoded"))
         (parse-query (utf8->string (req-body req))))
        ((and (>= (string-length ct) 19)
              (string-ci=? (substring ct 0 19) "multipart/form-data"))
         (let ((b (multipart-boundary ct)))
           (if b (parse-multipart (req-body req) b) '())))
        (else '()))))

  ;; ---- Server-Sent Events -------------------------------------------------
  ;; Detach long streams from the pool worker:
  ;;   (sse-start! res)
  ;;   (spawn (lambda () ... (sse-send! res data) ... (res-end! res)))

  (define-checked (sse-start! (res res?))
    (set-header! res "Content-Type" "text/event-stream")
    (set-header! res "Cache-Control" "no-cache")
    (res-begin! res))

  ;; returns #f when the client is gone -- stop the producer loop then
  (define-checked (sse-send! (res res?) (data string?))
    (res-write! res (string-append "data: " data "\n\n")))

  ;; ---- pool failure hook template -----------------------------------------------
  ;; Ready-made on-failure handler for app-listen's pool options. When the
  ;; pool gives up on a request (crash retries exhausted, or a stuck
  ;; worker killed -- killed first, so no execution is in flight), it
  ;; replies a small JSON envelope instead of the plain 500:
  ;;   {"fault":"crash"|"stuck", "attempts":n, "elapsed-ms":t, "retryable":true}
  ;; The connection stays open (keep-alive), so the client can resubmit
  ;; -- changed parameters, carried state -- on the same connection and
  ;; get a fresh retry round. Optional argument overrides the HTTP status
  ;; (default 503). For custom envelopes write your own
  ;; (lambda (req res info) ...) instead.
  ;;   (app-listen app 8080 `((stuck-ms . 3000) (check-ms . 1000)
  ;;                          (on-failure . ,(make-fault-handler))))
  (define (make-fault-handler . rest)
    (let ((status (if (pair? rest) (car rest) 503)))
      (lambda (req res info)
        (define (ref k d)
          (let ((p (assq k info))) (if p (cdr p) d)))
        (set-status! res status)
        (send-json! res
          (list (cons 'fault (symbol->string (ref 'kind 'crash)))
                (cons 'attempts (ref 'attempts 1))
                (cons 'elapsed-ms (ref 'elapsed-ms 0))
                (cons 'retryable #t))))))

  ;; ---- static files -----------------------------------------------------------

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

  (define (path-has-dotdot? s)
    (exists (lambda (p) (string=? p "..")) (string-split s #\/)))

  ;; a NUL byte can truncate a path in a lower-level file API, slipping
  ;; past an extension/suffix check (e.g. "safe.txt\x0;.jpg")
  (define (path-has-nul? s)
    (let loop ((i 0))
      (and (< i (string-length s))
           (or (fx= (char->integer (string-ref s i)) 0)
               (loop (+ i 1))))))

  ;; ---- static file cache -----------------------------------------------------
  ;;
  ;; Files are read once and kept in memory keyed by path; a request
  ;; re-reads only when the file's mtime has changed. This turns the
  ;; common case (serving an unchanged index.html / css / js) from a
  ;; blocking disk read + fresh allocation into a hashtable lookup, and
  ;; supplies a weak ETag for conditional requests (304 Not Modified).
  ;; Files larger than max-cache-file are served but not cached.

  (define max-cache-file (* 1024 1024))   ; 1 MiB per-file cache cap
  ;; A cached file's mtime is re-checked at most once per this many ms
  ;; (nginx open_file_cache_valid works the same way, default 60s there).
  ;; Within the window a hit costs a hashtable lookup and NO syscalls --
  ;; the stat pair (exists? + mtime) dominated cached static serving.
  (define stat-window-ms 1000)
  ;; path -> #(mtime size etag content-type body gzip-box last-stat-ms)
  (define static-cache (make-hashtable string-hash string=?))

  (define (file-mtime path)
    (guard (e (#t #f))
      (and (file-exists? path)
           (time-second (file-modification-time path)))))

  (define (etag-of size mtime)
    (string-append "W/\"" (number->string size 16) "-"
                   (number->string mtime 16) "\""))

  (define (bv-concat lst total)
    (let ((out (make-bytevector total)))
      (let loop ((l lst) (off 0))
        (if (null? l)
            out
            (let ((x (car l)))
              (bytevector-copy! x 0 out off (bytevector-length x))
              (loop (cdr l) (+ off (bytevector-length x))))))))

  ;; pull a whole (small) stream into one bytevector; #f on error/short
  (define (stream-read-all st size)
    (let loop ((chunks '()) (got 0))
      (file-stream-read! st)
      (receive (after 30000 (begin (file-stream-close! st) #f))
        (`#(file-chunk ,bv) (loop (cons bv chunks) (+ got (bytevector-length bv))))
        (`#(file-eof) (and (= got size) (bv-concat (reverse chunks) got)))
        (`#(file-error ,e) #f))))

  ;; return the cache entry for path (reading/refreshing as needed), or #f.
  ;; Within stat-window-ms of the last check the entry is trusted as-is;
  ;; past it the mtime is re-checked (and the window restamped), and the
  ;; file re-read only when the mtime actually changed.
  ;;
  ;; A cache miss opens the file as a stream so the size is known (from
  ;; fstat) BEFORE any bytes are read. A small file is pulled whole,
  ;; cached, and served from memory as before. A large one is cached as
  ;; METADATA only (body slot = 'large): within the stat window a
  ;; conditional request answers 304 with zero file operations, and a
  ;; download opens a fresh stream on demand -- the miss itself returns
  ;; a live one-shot #(stream handle size etag ctype) descriptor, which
  ;; the caller must either pump (stream-file!) or close.
  (define (stream-entry? e) (eq? (vector-ref e 0) 'stream))
  (define (large-entry? e) (eq? (vector-ref e 4) 'large))

  (define (static-entry path)
    (let ((cached (hashtable-ref static-cache path #f))
          (now (now-ms)))
      (if (and cached (< (- now (vector-ref cached 6)) stat-window-ms))
          cached
          (let ((mt (file-mtime path)))
            (and mt
                 (if (and cached (= (vector-ref cached 0) mt))
                     (begin (vector-set! cached 6 now) cached)
                     (open-entry path mt now)))))))

  ;; open with a timeout that can never leak the fd: the handle comes
  ;; back synchronously, so a timed-out open is closed via its handle
  ;; (the abort flag also suppresses any late ready message).
  ;; -> (values stream size) | (values #f #f)
  (define (open-stream path)
    (let ((st (file-stream-open! path self)))
      (receive (after 30000 (begin (file-stream-close! st) (values #f #f)))
        (`#(file-stream ,@st ,size) (values st size))
        (`#(file-error ,e) (values #f #f)))))

  (define (open-entry path mt now)
    (let-values (((st size) (open-stream path)))
      (and st
           (if (<= size max-cache-file)
               (let ((body (stream-read-all st size)))
                 (and body
                      ;; gzip-box holds the lazily-built gzip body
                      (let ((e (vector mt size (etag-of size mt)
                                       (mime-type path) body (box #f) now)))
                        (hashtable-set! static-cache path e)
                        e)))
               (let ((etag (etag-of size mt)) (ctype (mime-type path)))
                 (hashtable-set! static-cache path
                   (vector mt size etag ctype 'large #f now))
                 (vector 'stream st size etag ctype))))))

  ;; Pump a large file through a fixed-length response from a detached
  ;; process: the pool worker is released immediately, and each chunk
  ;; is read only after the previous one drained to the client
  ;; (res-write-chunk! waits) -- constant memory however slow the peer.
  ;; The stream runs raw: chunks go C buffer -> socket without touching
  ;; the Scheme heap, so a gigabyte download causes no GC traffic.
  (define (stream-file! r st size ctype)
    (set-header! r "Content-Type" ctype)
    (res-begin-file! r size)
    (spawn
      (lambda ()
        (file-stream-own! st self)
        (file-stream-raw! st)
        (let loop ()
          (file-stream-read! st)
          (receive (after 30000 (res-abort-file! r))
            (`#(file-chunk ,len)
              (case (res-write-chunk! r st len)
                ((more) (loop))
                ((done) (void))
                (else (res-abort-file! r))))
            ;; eof before the promised length: file shrank underneath us
            (`#(file-eof) (res-abort-file! r))
            (`#(file-error ,e) (res-abort-file! r))))
        (file-stream-close! st))))

  ;; window-hit download of a large (metadata-cached) file: open a
  ;; fresh stream on demand. Content-Length comes from the live fstat;
  ;; etag/ctype from the metadata (<= 1s stale, like every window hit).
  (define (serve-large! r ctype path)
    (let-values (((st size) (open-stream path)))
      (if st
          (stream-file! r st size ctype)
          (begin (set-status! r 404) (send-text! r "Not Found")))))

  ;; Public helper: send a file (cached read; no conditional request
  ;; since there is no req here). Path traversal is rejected. Files
  ;; over the cache cap are streamed with backpressure, not buffered.
  (define-checked (send-file! (r res?) (path string?))
    (if (path-has-dotdot? path)
        (begin (set-status! r 403) (send-text! r "Forbidden"))
        (let ((e (static-entry path)))
          (cond
            ((not e) (set-status! r 404) (send-text! r "Not Found"))
            ((stream-entry? e)
             (stream-file! r (vector-ref e 1) (vector-ref e 2) (vector-ref e 4)))
            ((large-entry? e) (serve-large! r (vector-ref e 3) path))
            (else (finish! r (vector-ref e 3) (vector-ref e 4)))))))

  ;; Serve a static file with caching + conditional request. abs-path is
  ;; already inside the mount root; caller has done the boundary check.
  ;; gzip ETag differs from the plain one so a client cannot confuse the
  ;; two representations: W/"..." -> W/"...-gz"
  (define (gzip-etag etag)
    (string-append (substring etag 0 (- (string-length etag) 1)) "-gz\""))

  (define (serve-static! r req abs-path)
    (if (path-has-dotdot? abs-path)
        (begin (set-status! r 403) (send-text! r "Forbidden"))
        (let ((e (static-entry abs-path)))
          (cond
            ((not e)
             (set-status! r 404) (send-text! r "Not Found"))
            ((stream-entry? e)
             ;; large file, first request (cache miss): the stream is
             ;; already open. Conditional requests answer from the etag;
             ;; otherwise pump it (no gzip -- the body is never held in
             ;; memory to compress).
             (let ((st (vector-ref e 1)) (size (vector-ref e 2))
                   (etag (vector-ref e 3)) (ctype (vector-ref e 4)))
               (set-header! r "ETag" etag)
               (set-header! r "Cache-Control" "public, max-age=3600")
               (if (equal? (req-header req 'if-none-match) etag)
                   (begin
                     (file-stream-close! st)
                     (set-status! r 304)
                     (res-send! r (make-bytevector 0)))
                   (stream-file! r st size ctype))))
            ((large-entry? e)
             ;; large file, window hit: everything needed for a 304 is
             ;; in the metadata -- a revalidation costs NO file
             ;; operations at all; only a download opens the file
             (let ((etag (vector-ref e 2)) (ctype (vector-ref e 3)))
               (set-header! r "ETag" etag)
               (set-header! r "Cache-Control" "public, max-age=3600")
               (if (equal? (req-header req 'if-none-match) etag)
                   (begin
                     (set-status! r 304)
                     (res-send! r (make-bytevector 0)))
                   (serve-large! r ctype abs-path))))
            (else
             (let* ((size (vector-ref e 1))
                     (etag (vector-ref e 2))
                     (ctype (vector-ref e 3))
                     (body (vector-ref e 4))
                     (gzbox (vector-ref e 5))
                     ;; use gzip when the client accepts it and it's worth it
                     (gz (and (> size gzip-min-size)
                              (compressible-type? ctype)
                              (gzip-acceptable? (req-header req 'accept-encoding))
                              (or (unbox gzbox)
                                  (let ((g (gzip-compress body 6)))
                                    (when g (set-box! gzbox g))
                                    g))))
                     (tag (if gz (gzip-etag etag) etag)))
                (set-header! r "ETag" tag)
                (set-header! r "Cache-Control" "public, max-age=3600")
                (when gz (set-header! r "Vary" "Accept-Encoding"))
                (cond
                  ((equal? (req-header req 'if-none-match) tag)
                   (set-status! r 304) (res-send! r (make-bytevector 0)))
                  (gz
                   (set-header! r "Content-Encoding" "gzip")
                   (set-header! r "Content-Type" ctype)
                   (res-send! r gz))
                  (else
                   (set-header! r "Content-Type" ctype)
                   (res-send! r body)))))))))

  ;; ---- router -------------------------------------------------------------------

  ;; "/users/:id" -> ("users" ":id"); "/" -> (). One pass, empty
  ;; segments skipped during the split rather than filtered after.
  (define (split-segments path)
    (let ((n (string-length path)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((fx= i n)
           (reverse (if (fx> i start) (cons (substring path start i) acc) acc)))
          ((char=? (string-ref path i) #\/)
           (loop (fx+ i 1) (fx+ i 1)
                 (if (fx> i start) (cons (substring path start i) acc) acc)))
          (else (loop (fx+ i 1) start acc))))))

  ;; match pattern segments against path segments; alist of params or #f
  ;; ":name" captures one segment; a trailing "*" (Express splat) captures all
  ;; remaining segments joined with "/" under the param name "0". A
  ;; non-trailing "*" never reaches here: registration rejects it
  ;; (check-splat!), so the swallow-everything arm is safe.
  ;; index of the first #\: in s, or #f
  (define (seg-colon-index s)
    (let ((n (string-length s)))
      (let lp ((i 0)) (cond ((fx= i n) #f) ((char=? (string-ref s i) #\:) i) (else (lp (fx+ i 1)))))))

  (define (match-segments psegs segs)
    (let loop ((ps psegs) (ss segs) (params '()))
      (cond
        ((and (null? ps) (null? ss)) params)
        ((and (pair? ps) (string=? (car ps) "*"))
         (cons (cons "0"
                     (let join ((l ss) (acc ""))
                       (cond ((null? l) acc)
                             ((string=? acc "") (join (cdr l) (car l)))
                             (else (join (cdr l) (string-append acc "/" (car l)))))))
               params))
        ((or (null? ps) (null? ss)) #f)
        ((and (> (string-length (car ps)) 0)
              (char=? (string-ref (car ps) 0) #\:))
         (loop (cdr ps) (cdr ss)
               (cons (cons (substring (car ps) 1 (string-length (car ps)))
                           (car ss))
                     params)))
        ;; literal-prefix param (express syntax, e.g. "@:username"): the URL
        ;; segment must start with the literal prefix, the rest is the param.
        ((let ((ci (seg-colon-index (car ps)))) (and ci (fx> ci 0)))
         (let* ((p (car ps)) (ci (seg-colon-index p))
                (prefix (substring p 0 ci)) (name (substring p (fx+ ci 1) (string-length p)))
                (seg (car ss)) (pl (string-length prefix)))
           (if (and (fx> (string-length seg) pl) (string=? (substring seg 0 pl) prefix))
               (loop (cdr ps) (cdr ss) (cons (cons name (substring seg pl (string-length seg))) params))
               #f)))
        ((string=? (car ps) (car ss))
         (loop (cdr ps) (cdr ss) params))
        (else #f))))

  ;; router params are stored in the core request's layer-owned slot
  (define-checked (req-param (req request?) (name string?))
    (let ((p (assoc name (req-params req))))
      (and p (cdr p))))

  ;; ---- app ------------------------------------------------------------------------

  ;; routes: list of #(method segs handler); mw-chain: the middleware
  ;; list composed into one callable, rebuilt by app-use -- so a request
  ;; pays no fold/list walk; statics: list of (prefix . root);
  ;; ws-routes: list of #(segs session guard-or-#f)
  (define-checked-record app
    (mutable routes list?)
    (mutable middlewares list?)
    (mutable mw-chain procedure?)
    (mutable statics list?)
    (mutable ws-routes list?))

  ;; chain shape: (lambda (req r tail) ...); tail runs the router
  (define empty-chain (lambda (req r tail) (tail)))

  (define (compose-chain mws)
    (fold-right
      (lambda (mw rest)
        (lambda (req r tail) (mw req r (lambda () (rest req r tail)))))
      empty-chain
      mws))

  (define-checked (create-app) (make-app '() '() empty-chain '() '()))

  ;; Registering a route that already exists (same method + pattern)
  ;; REPLACES it -- this is what makes hot reloading work: re-evaluating
  ;; a routes file against a live app swaps the handlers in place.
  ;; A splat '*' is only meaningful as the LAST pattern segment --
  ;; anywhere else it swallows the rest of the path and the segments
  ;; after it silently never match. That is a route-table typo, so it
  ;; fails HERE, at registration, not as a mystery 200 in production.
  (define (check-splat! who pattern segs)
    (let loop ((ss segs))
      (when (pair? ss)
        (when (and (string=? (car ss) "*") (pair? (cdr ss)))
          (assertion-violation who
            "splat '*' must be the last pattern segment" pattern))
        (loop (cdr ss)))))

  (define (add-route! a method pattern handler)
    (let ((segs (split-segments pattern)))
      (check-splat! 'add-route! pattern segs)
      (app-routes-set! a
        (append
          (filter (lambda (r)
                    (not (and (eq? (vector-ref r 0) method)
                              (equal? (vector-ref r 1) segs))))
                  (app-routes a))
          (list (vector method segs handler))))))

  (define-checked (app-get (a app?) (pattern string?) (handler procedure?))
    (add-route! a 'GET pattern handler))
  (define-checked (app-post (a app?) (pattern string?) (handler procedure?))
    (add-route! a 'POST pattern handler))
  (define-checked (app-put (a app?) (pattern string?) (handler procedure?))
    (add-route! a 'PUT pattern handler))
  (define-checked (app-delete (a app?) (pattern string?) (handler procedure?))
    (add-route! a 'DELETE pattern handler))

  ;; RPC endpoint sugar: requests are (tag arg ...); the tag picks a
  ;; handler from the alist, which receives the argument list and
  ;; returns the reply datum. Unknown tags and bad payloads answer
  ;; (error ...) data, never a crash.
  ;;   (app-rpc app "/rpc"
  ;;     `((get-user . ,(lambda (args) ...))
  ;;       (add      . ,(lambda (args) (apply + args)))))
  ;;
  ;; Optional 4th argument: an auth guard (lambda (req) claims-or-#f),
  ;; the same request-guard protocol app-ws takes ((igropyr auth)'s
  ;; token-guard works for both). A refusal answers 401 with the sexpr
  ;; datum (error unauthorized) -- this is a sexpr channel, not JSON.
  ;; Claims land on the request's layer-owned slot (req-claims). A
  ;; handler that can take TWO arguments is called with (args req), so
  ;; it can read claims/params for per-tag authorization; one-argument
  ;; handlers work as before. Rest args, so plain define.
  ;;   (app-rpc app "/rpc"
  ;;     `((whoami . ,(lambda (args req) (json-ref (req-claims req) "sub"))))
  ;;     (token-guard (jwt-verifier key)))
  (define (app-rpc app path handlers . rest)
    (let ((auth-guard (and (pair? rest) (car rest))))
      (when auth-guard
        (unless (procedure? auth-guard)
          (assertion-violation 'app-rpc "guard must be a procedure" auth-guard)))
      (app-post app path
        (lambda (req res)
          (let ((claims (if auth-guard (auth-guard req) #t)))
            (cond
              ((not claims)
               (set-status! res 401)
               (send-sexpr! res '(error unauthorized)))
              (else
               (when auth-guard (req-set-local! req 'claims claims))
               (let ((msg (req-sexpr req)))
                 (if (and (pair? msg) (symbol? (car msg)))
                     (let ((h (assq (car msg) handlers)))
                       (if h
                           (send-sexpr! res
                             (guard (e (#t (list 'error 'handler-failed)))
                               (let ((proc (cdr h)))
                                 (list 'ok
                                   (if (logbit? 2 (procedure-arity-mask proc))
                                       (proc (cdr msg) req)
                                       (proc (cdr msg)))))))
                           (send-sexpr! res (list 'error 'unknown-tag (car msg)))))
                     (send-sexpr! res (list 'error 'bad-payload)))))))))))

  ;; ---- s-expressions over WebSocket and SSE ---------------------------------
  ;; a message is one datum: write to send, safe-parse on receive --
  ;; the natural framing for pushed data.

  (define-checked (ws-send-sexpr! (ws ws?) x)
    (ws-send-text! ws (sexpr->string-extended x)))

  ;; -> datum | 'close (connection over) | #f (binary or bad datum)
  (define-checked (ws-recv-sexpr (ws ws?))
    (let ((m (ws-recv ws)))
      (cond
        ((and (vector? m) (eq? (vector-ref m 0) 'text))
         (guard (e (#t #f)) (string->sexpr-extended (vector-ref m 1))))
        ((and (vector? m) (eq? (vector-ref m 0) 'close)) 'close)
        (else #f))))

  ;; one event, data = one datum. A literal newline inside a string
  ;; datum splits into multiple data: lines; EventSource rejoins them
  ;; with \n on the client, so the datum survives intact.
  (define-checked (sse-send-sexpr! (res res?) x)
    (let* ((text (sexpr->string-extended x))
           (lines (string-split text #\newline)))
      (res-write! res
        (string-append
          (apply string-append
                 (map (lambda (l) (string-append "data: " l "\n")) lines))
          "\n"))))

  ;; middleware: (lambda (req res next) ...); call (next) to continue.
  ;; The composed chain is rebuilt here, at registration time, so
  ;; mutation stays live while requests just call the prebuilt chain.
  (define-checked (app-use (a app?) (mw procedure?))
    (app-middlewares-set! a (append (app-middlewares a) (list mw)))
    (app-mw-chain-set! a (compose-chain (app-middlewares a))))

  ;; prefix/root get always-on semantic validation below (they shape
  ;; what the filesystem is asked for) -- that is business code, not a
  ;; dev-only contract, so only the app argument is contracted here
  (define-checked (app-static (a app?) prefix root)
    (unless (and (string? prefix) (> (string-length prefix) 0)
                 (char=? (string-ref prefix 0) #\/))
      (assertion-violation 'app-static
        "mount prefix must be an absolute URL path" prefix))
    (unless (and (string? root) (> (string-length root) 0)
                 (not (path-has-nul? root)))
      (assertion-violation 'app-static
        "static root must be a non-empty path without NUL" root))
    ;; store one canonical spelling: drop a trailing slash so "/assets/"
    ;; and "/assets" have identical segment-boundary behaviour (root "/"
    ;; itself is left as-is)
    (let ((p (if (and (> (string-length prefix) 1)
                      (char=? (string-ref prefix (- (string-length prefix) 1)) #\/))
                 (substring prefix 0 (- (string-length prefix) 1))
                 prefix)))
      (app-statics-set! a (append (app-statics a) (list (cons p root))))))

  ;; websocket route: session is (lambda (ws req) ...), run in the
  ;; connection's own process; :param segments work as in app-get.
  ;; Optional 4th argument: an auth guard (lambda (req) claims-or-#f),
  ;; run by the resolver BEFORE the 101 handshake -- truthy claims are
  ;; stashed on the request (read via (igropyr auth)'s req-claims) and
  ;; the upgrade proceeds; #f answers 401 with no handshake. Rest arg,
  ;; so plain define ((igropyr checked) is fixed-arity only).
  (define (app-ws a pattern session . rest)
    (let ((segs (split-segments pattern))
          (guard (and (pair? rest) (car rest))))
      (check-splat! 'app-ws pattern segs)
      (when guard
        (unless (procedure? guard)
          (assertion-violation 'app-ws "guard must be a procedure" guard)))
      (app-ws-routes-set! a
        (append
          (filter (lambda (r) (not (equal? (vector-ref r 0) segs)))
                  (app-ws-routes a))
          (list (vector segs session guard))))))

  ;; resolver handed to the core: request -> session procedure,
  ;; #f (no route: 404), or #(ws-reject status text) (guard refused:
  ;; answered before any handshake)
  (define (ws-resolver a)
    (lambda (req)
      (let ((segs (split-segments (req-path req))))
        (let loop ((rs (app-ws-routes a)))
          (cond
            ((null? rs) #f)
            (else
             (let* ((r (car rs))
                    (params (match-segments (vector-ref r 0) segs)))
               (if params
                   (begin
                     (req-params-set! req params)
                     (let ((guard (vector-ref r 2)))
                       (if guard
                           (let ((claims (guard req)))
                             (if claims
                                 (begin (req-set-local! req 'claims claims)
                                        (vector-ref r 1))
                                 '#(ws-reject 401 "Unauthorized")))
                           (vector-ref r 1))))
                   (loop (cdr rs))))))))))

  ;; The request path relative to a mount prefix, or #f if it does not
  ;; belong to this mount. The prefix must align on a path boundary:
  ;; "/assets" matches "/assets" and "/assets/x", but NOT "/assets-x",
  ;; so a sibling directory cannot be reached by prefix confusion.
  (define (static-relative prefix path)
    (let ((pl (string-length prefix)) (nl (string-length path)))
      (cond
        ((string=? prefix "/")                     ; root mount
         (and (> nl 0) (char=? (string-ref path 0) #\/)
              (substring path 1 nl)))
        ((not (string-prefix? prefix path)) #f)
        ((= nl pl) "")                             ; exactly the mount root
        ((char=? (string-ref path pl) #\/)          ; prefix + "/..."
         (substring path (+ pl 1) nl))
        (else #f))))                                ; e.g. "/assets-private"

  ;; Resolve a URL-relative name under root without letting it escape.
  ;; Chez has no portable realpath, so reject any symbolic link in the
  ;; untrusted part of the path (stricter than following the link and
  ;; comparing platform-specific canonical spellings) -- this blocks
  ;; symlink-based escapes as well as ".." and NUL. Returns the safe
  ;; absolute path or #f.
  (define (safe-static-path root rel)
    (and (not (path-has-dotdot? rel))
         (not (path-has-nul? rel))
         (let loop ((base root) (parts (string-split rel #\/)))
           (cond
             ((null? parts) base)
             ((or (string=? (car parts) "") (string=? (car parts) "."))
              (loop base (cdr parts)))
             (else
              (let ((next (string-append base "/" (car parts))))
                (and (not (guard (e (#t #t)) (file-symbolic-link? next)))
                     (loop next (cdr parts)))))))))

  (define (try-static a req r)
    (and (eq? (req-method req) 'GET)
         (exists
           (lambda (entry)
             (let* ((prefix (car entry)) (root (cdr entry))
                    (rel (static-relative prefix (req-path req)))
                    (path (and rel (safe-static-path root rel))))
               (and rel
                    (begin
                      ;; safe-static-path rejects "..", NUL, and symlink
                      ;; escapes; serve-static! then caches + answers 304
                      (if path
                          (serve-static! r req path)
                          (begin (set-status! r 403) (send-text! r "Forbidden")))
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

  ;; Fold the app into the single (lambda (req res)) handler the core
  ;; expects: middlewares wrap the router, first-registered outermost.
  ;; The chain was composed when the middleware was registered; a request
  ;; only reads the chain slot (so app-use stays live) and runs it.
  (define-checked (app->handler (a app?))
    (lambda (req r)
      ((app-mw-chain a) req r (lambda () (route-dispatch a req r)))))

  ;; Returns the http-server, so callers can http-swap! the whole
  ;; handler later. Route/middleware mutations on the app are live
  ;; anyway (app->handler reads the app on every request).
  ;; Rest args, so plain define ((igropyr checked) is fixed-arity only).
  ;; The contracts line is the mixed-build canary: it reports the level
  ;; baked into THIS module at compile time (see checked.sc).
  (define (app-listen a port . opts)
    (printf "igropyr contracts: ~a\n" (contract-level))
    (let ((srv (apply http-listen port (app->handler a) opts)))
      (http-set-ws! srv (ws-resolver a))
      srv))
)
