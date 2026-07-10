#!chezscheme
;;; (igropyr middleware) -- common Express-style middleware.
;;;
;;;   (app-use app (cors))                       ; permissive CORS
;;;   (app-use app (cors '((origin . "https://app.example.com")
;;;                        (methods . "GET,POST")
;;;                        (credentials . #t))))
;;;   (app-use app (security-headers))           ; sensible defaults
;;;   (app-use app (logger))                     ; access log to stdout
;;;
;;; Each returns a middleware: (lambda (req res next) ...).

(library (igropyr middleware)
  (export cors security-headers logger)
  (import (chezscheme) (igropyr actor) (igropyr libuv)
          (igropyr http) (igropyr express))

  (define (opt alist key default)
    (let ((p (assq key alist))) (if p (cdr p) default)))

  ;; ---- CORS ------------------------------------------------------------
  ;; Adds Access-Control-* headers; answers OPTIONS preflight with 204.
  (define (cors . rest)
    (let* ((o (if (pair? rest) (car rest) '()))
           (origin (opt o 'origin "*"))
           (methods (opt o 'methods "GET,POST,PUT,DELETE,OPTIONS"))
           (headers (opt o 'headers "Content-Type,Authorization"))
           (credentials (opt o 'credentials #f))
           (max-age (opt o 'max-age "86400")))
      (lambda (req res next)
        (set-header! res "Access-Control-Allow-Origin" origin)
        (unless (string=? origin "*")
          (set-header! res "Vary" "Origin"))
        (when credentials
          (set-header! res "Access-Control-Allow-Credentials" "true"))
        (if (eq? (req-method req) 'OPTIONS)
            ;; preflight: answer here, don't run the rest of the chain
            (begin
              (set-header! res "Access-Control-Allow-Methods" methods)
              (set-header! res "Access-Control-Allow-Headers" headers)
              (set-header! res "Access-Control-Max-Age" max-age)
              (set-status! res 204)
              (res-send! res (make-bytevector 0)))
            (next)))))

  ;; ---- security headers ------------------------------------------------
  ;; Conservative defaults; override any via the options alist, or pass
  ;; 'hsts #t to add Strict-Transport-Security (only behind TLS).
  (define (security-headers . rest)
    (let* ((o (if (pair? rest) (car rest) '()))
           (frame (opt o 'frame-options "DENY"))
           (referrer (opt o 'referrer-policy "no-referrer"))
           (hsts (opt o 'hsts #f))
           (csp (opt o 'content-security-policy #f)))
      (lambda (req res next)
        (set-header! res "X-Content-Type-Options" "nosniff")
        (set-header! res "X-Frame-Options" frame)
        (set-header! res "Referrer-Policy" referrer)
        (when hsts
          (set-header! res "Strict-Transport-Security"
                       "max-age=31536000; includeSubDomains"))
        (when csp
          (set-header! res "Content-Security-Policy" csp))
        (next))))

  ;; ---- access logger ---------------------------------------------------
  ;; Logs "METHOD path -> status (Nms)" after the handler runs. Since the
  ;; response is written asynchronously, the status is read from the res
  ;; at that point (accurate for handlers that set-status! before send).
  (define (logger . rest)
    (let* ((o (if (pair? rest) (car rest) '()))
           (port (opt o 'port (current-output-port))))
      (lambda (req res next)
        (let ((t0 (now-ms)))
          (next)
          (fprintf port "~a ~a -> ~a (~ams)\n"
                   (req-method req) (req-path req)
                   (res-status res) (- (now-ms) t0))
          (flush-output-port port)))))
)
