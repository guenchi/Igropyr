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
          req-param
          send-text! send-html! send-json! send-file!)
  (import (chezscheme) (igropyr actor) (igropyr http))

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

  (define (finish! r ctype body)
    (set-header! r "Content-Type" ctype)
    (res-send! r body))

  (define (send-text! r s) (finish! r "text/plain; charset=utf-8" (string->utf8 s)))
  (define (send-html! r s) (finish! r "text/html; charset=utf-8" (string->utf8 s)))
  (define (send-json! r obj)
    (finish! r "application/json; charset=utf-8"
             (string->utf8 (json->string obj))))

  ;; tiny JSON writer: alist -> object, list -> array
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

  (define (read-file-bv path)
    (guard (e (#t #f))
      (and (file-exists? path)
           (call-with-port (open-file-input-port path)
             (lambda (p)
               (let ((bv (get-bytevector-all p)))
                 (if (eof-object? bv) (make-bytevector 0) bv)))))))

  (define (path-has-dotdot? s)
    (exists (lambda (p) (string=? p "..")) (string-split s #\/)))

  ;; Whole-file read on the worker (blocking; fine for small local
  ;; files, not a streaming file server).
  (define (send-file! r path)
    (if (path-has-dotdot? path)
        (begin (set-status! r 403) (send-text! r "Forbidden"))
        (let ((bv (read-file-bv path)))
          (if bv
              (finish! r (mime-type path) bv)
              (begin (set-status! r 404) (send-text! r "Not Found"))))))

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
      (mutable ws-routes app-ws-routes app-ws-routes-set!))) ; list of (segs . session)

  (define (create-app) (make-app-record '() '() '() '()))

  ;; Registering a route that already exists (same method + pattern)
  ;; REPLACES it -- this is what makes hot reloading work: re-evaluating
  ;; a routes file against a live app swaps the handlers in place.
  (define (add-route! a method pattern handler)
    (let ((segs (split-segments pattern)))
      (app-routes-set! a
        (append
          (filter (lambda (r)
                    (not (and (eq? (vector-ref r 0) method)
                              (equal? (vector-ref r 1) segs))))
                  (app-routes a))
          (list (vector method segs handler))))))

  (define (app-get a pattern handler) (add-route! a 'GET pattern handler))
  (define (app-post a pattern handler) (add-route! a 'POST pattern handler))
  (define (app-put a pattern handler) (add-route! a 'PUT pattern handler))
  (define (app-delete a pattern handler) (add-route! a 'DELETE pattern handler))

  ;; middleware: (lambda (req res next) ...); call (next) to continue
  (define (app-use a mw)
    (app-middlewares-set! a (append (app-middlewares a) (list mw))))

  (define (app-static a prefix root)
    (app-statics-set! a (append (app-statics a) (list (cons prefix root)))))

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
      srv))
)
