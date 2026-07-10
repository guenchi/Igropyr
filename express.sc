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
          app-get-fast app-post-fast app-put-fast app-delete-fast
          app-use app-static app-ws app-listen app->handler
          req-param req-json req-form req-cookie set-cookie!
          send-text! send-html! send-json! send-file!
          sse-start! sse-send!)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
          (igropyr json) (igropyr gzip))

  ;; ---- string helpers -----------------------------------------------------

  (define (string-split s ch)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n) (reverse (cons (substring s start n) acc)))
          ((char=? (string-ref s i) ch)
           (loop (+ i 1) (+ i 1) (cons (substring s start i) acc)))
          (else (loop (+ i 1) start acc))))))

  (define (string-prefix? p s)
    (and (>= (string-length s) (string-length p))
         (string=? p (substring s 0 (string-length p)))))

  ;; ---- response encoders (the res.json level) --------------------------------

  ;; compress bodies over this size when the client accepts gzip and the
  ;; content type is worth compressing (already-compressed formats like
  ;; images are skipped)
  (define gzip-min-size 1024)

  (define (compressible-type? ctype)
    (let ((prefixes '("text/" "application/json" "application/javascript"
                      "application/xml" "image/svg+xml")))
      (exists (lambda (p)
                (and (>= (string-length ctype) (string-length p))
                     (string=? (substring ctype 0 (string-length p)) p)))
              prefixes)))

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

  (define (send-text! r s) (finish! r "text/plain; charset=utf-8" (string->utf8 s)))
  (define (send-html! r s) (finish! r "text/html; charset=utf-8" (string->utf8 s)))
  ;; serialization comes from (igropyr json): alist -> object,
  ;; vector or list -> array, 'null -> null
  (define (send-json! r obj)
    (finish! r "application/json; charset=utf-8"
             (string->utf8 (json->string obj))))

  ;; parse a JSON request body; #f when the body is not valid JSON
  (define (req-json req)
    (guard (e (#t #f))
      (string->json (utf8->string (req-body req)))))

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
  (define (req-cookie req name)
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

  ;; parse one multipart part: header block + payload
  ;; -> (name . string-value) or (name . #(file filename content-type bytes))
  (define (parse-part bv start end)
    (let ((hend (bv-search bv (string->utf8 "\r\n\r\n") start)))
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
  (define (req-form req)
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

  (define (sse-start! res)
    (set-header! res "Content-Type" "text/event-stream")
    (set-header! res "Cache-Control" "no-cache")
    (res-begin! res))

  ;; returns #f when the client is gone -- stop the producer loop then
  (define (sse-send! res data)
    (res-write! res (string-append "data: " data "\n\n")))

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
  ;; path -> #(mtime size etag content-type body)
  (define static-cache (make-hashtable string-hash string=?))

  (define (file-mtime path)
    (guard (e (#t #f))
      (and (file-exists? path)
           (time-second (file-modification-time path)))))

  (define (etag-of size mtime)
    (string-append "W/\"" (number->string size 16) "-"
                   (number->string mtime 16) "\""))

  ;; read a file on libuv's thread pool; the caller (a pool worker or
  ;; reader process) parks until the read finishes, so a large or slow
  ;; read never blocks the scheduler. Returns the bytevector or #f.
  (define (read-file-async path)
    (file-read-async! path self)
    (receive (after 30000 #f)
      (`#(file-read ,bv) bv)
      (`#(file-error ,e) #f)))

  ;; return the cache entry for path (reading/refreshing as needed), or #f
  (define (static-entry path)
    (let ((mt (file-mtime path)))
      (and mt
           (let ((cached (hashtable-ref static-cache path #f)))
             (if (and cached (= (vector-ref cached 0) mt))
                 cached
                 (let ((body (read-file-async path)))
                   (and body
                        (let* ((size (bytevector-length body))
                               ;; entry: #(mtime size etag ctype body gzip-box)
                               ;; gzip-box holds the lazily-built gzip body
                               (e (vector mt size (etag-of size mt)
                                          (mime-type path) body (box #f))))
                          (when (<= size max-cache-file)
                            (hashtable-set! static-cache path e))
                          e))))))))

  ;; Public helper: send a file (cached read; no conditional request
  ;; since there is no req here). Path traversal is rejected.
  (define (send-file! r path)
    (if (path-has-dotdot? path)
        (begin (set-status! r 403) (send-text! r "Forbidden"))
        (let ((e (static-entry path)))
          (if e
              (finish! r (vector-ref e 3) (vector-ref e 4))
              (begin (set-status! r 404) (send-text! r "Not Found"))))))

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
          (if (not e)
              (begin (set-status! r 404) (send-text! r "Not Found"))
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
                   (res-send! r body))))))))

  ;; ---- router -------------------------------------------------------------------

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

  ;; router params are stored in the core request's layer-owned slot
  (define (req-param req name)
    (let ((p (assoc name (req-params req))))
      (and p (cdr p))))

  ;; ---- app ------------------------------------------------------------------------

  (define-record-type (app make-app-record app?)
    (fields
      (mutable routes app-routes app-routes-set!)       ; list of #(method segs handler)
      (mutable middlewares app-middlewares app-middlewares-set!)
      (mutable statics app-statics app-statics-set!)    ; list of (prefix . root)
      (mutable ws-routes app-ws-routes app-ws-routes-set!) ; list of (segs . session)
      (mutable fast app-fast app-fast-set!)))           ; list of (method . segs)

  (define (create-app) (make-app-record '() '() '() '() '()))

  ;; Registering a route that already exists (same method + pattern)
  ;; REPLACES it -- this is what makes hot reloading work: re-evaluating
  ;; a routes file against a live app swaps the handlers in place.
  ;; fast? marks the route for inline execution (bypassing the worker
  ;; pool); see app-get-fast and the README for the trade-offs.
  (define (add-route! a method pattern handler fast?)
    (let ((segs (split-segments pattern)))
      (app-routes-set! a
        (append
          (filter (lambda (r)
                    (not (and (eq? (vector-ref r 0) method)
                              (equal? (vector-ref r 1) segs))))
                  (app-routes a))
          (list (vector method segs handler))))
      ;; keep the fast set in sync: drop any old entry, re-add if fast?
      (app-fast-set! a
        (filter (lambda (k)
                  (not (and (eq? (car k) method) (equal? (cdr k) segs))))
                (app-fast a)))
      (when fast?
        (app-fast-set! a (cons (cons method segs) (app-fast a))))))

  (define (app-get a pattern handler) (add-route! a 'GET pattern handler #f))
  (define (app-post a pattern handler) (add-route! a 'POST pattern handler #f))
  (define (app-put a pattern handler) (add-route! a 'PUT pattern handler #f))
  (define (app-delete a pattern handler) (add-route! a 'DELETE pattern handler #f))

  ;; Fast variants: the handler runs inline in the reader process,
  ;; skipping the worker-pool round trip. Use only for pure, prompt
  ;; handlers -- they lose crash retry and stuck-kill (a crash answers
  ;; 500 for that one connection; a block/loop freezes that connection).
  (define (app-get-fast a pattern handler) (add-route! a 'GET pattern handler #t))
  (define (app-post-fast a pattern handler) (add-route! a 'POST pattern handler #t))
  (define (app-put-fast a pattern handler) (add-route! a 'PUT pattern handler #t))
  (define (app-delete-fast a pattern handler) (add-route! a 'DELETE pattern handler #t))

  ;; predicate handed to the core: does this request hit a fast route?
  (define (app-fast-predicate a)
    (lambda (req)
      (let ((m (req-method req)) (segs (split-segments (req-path req))))
        (let loop ((fs (app-fast a)))
          (cond
            ((null? fs) #f)
            ((and (eq? (caar fs) m) (match-segments (cdar fs) segs)) #t)
            (else (loop (cdr fs))))))))

  ;; middleware: (lambda (req res next) ...); call (next) to continue
  (define (app-use a mw)
    (app-middlewares-set! a (append (app-middlewares a) (list mw))))

  (define (app-static a prefix root)
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
  ;; connection's own process; :param segments work as in app-get
  (define (app-ws a pattern session)
    (let ((segs (split-segments pattern)))
      (app-ws-routes-set! a
        (append
          (filter (lambda (r) (not (equal? (car r) segs)))
                  (app-ws-routes a))
          (list (cons segs session))))))

  ;; resolver handed to the core: request -> session procedure or #f
  (define (ws-resolver a)
    (lambda (req)
      (let ((segs (split-segments (req-path req))))
        (let loop ((rs (app-ws-routes a)))
          (cond
            ((null? rs) #f)
            (else
             (let ((params (match-segments (caar rs) segs)))
               (if params
                   (begin (req-params-set! req params) (cdar rs))
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
  (define (app->handler a)
    (lambda (req r)
      ((fold-right
         (lambda (mw next) (lambda () (mw req r next)))
         (lambda () (route-dispatch a req r))
         (app-middlewares a)))))

  ;; Returns the http-server, so callers can http-swap! the whole
  ;; handler later. Route/middleware mutations on the app are live
  ;; anyway (app->handler reads the app on every request).
  (define (app-listen a port . opts)
    (let ((srv (apply http-listen port (app->handler a) opts)))
      (http-set-ws! srv (ws-resolver a))
      (http-set-fast! srv (app-fast-predicate a))
      srv))
)
