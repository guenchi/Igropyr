#!chezscheme
;;; (igropyr middleware) -- common Express-style middleware.
;;;
;;;   (app-use app (cors))                       ; permissive CORS
;;;   (app-use app (cors '((origin . "https://app.example.com")
;;;                        (methods . "GET,POST")
;;;                        (credentials . #t))))
;;;   (app-use app (security-headers))           ; sensible defaults
;;;   (app-use app (logger))                     ; access log to stdout
;;;   (app-use app (auth (jwt-verifier key)))    ; bearer-token auth
;;;
;;; Each returns a middleware: (lambda (req res next) ...).

(library (igropyr middleware)
  (export cors security-headers logger rate-limit error-handler
          auth req-claims)
  (import (chezscheme) (igropyr checked)
          (igropyr actor) (igropyr libuv) (igropyr gen-server)
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

  ;; ---- rate limiting ---------------------------------------------------
  ;; Fixed-window counter per key in a gen-server store. Over the limit
  ;; within the window -> 429. Default key is the X-Forwarded-For header
  ;; (the client IP behind a proxy); pass 'key (lambda (req) string) to
  ;; key on something else. Options: 'max (default 100), 'window ms
  ;; (default 60000), 'key.
  (define (make-rate-store)
    (let ((store
           (gen-server-start
             (lambda () (make-hashtable string-hash string=?))
             ;; call #(check key max window) -> 'ok | 'limited
             (lambda (msg from tbl)
               (let ((key (vector-ref msg 1))
                     (limit (vector-ref msg 2))
                     (window (vector-ref msg 3))
                     (now (now-ms)))
                 (let ((entry (hashtable-ref tbl key #f)))
                   (cond
                     ((or (not entry) (> now (cdr entry)))   ; new window
                      (hashtable-set! tbl key (cons 1 (+ now window)))
                      (values 'ok tbl))
                     ((< (car entry) limit)
                      (set-car! entry (+ 1 (car entry)))
                      (values 'ok tbl))
                     (else (values 'limited tbl))))))
             ;; cast 'prune: drop keys whose window has elapsed, so a
             ;; long-lived limiter does not accumulate stale IPs
             (lambda (msg tbl)
               (when (eq? (vector-ref msg 0) 'prune)
                 (let ((now (now-ms)))
                   (let-values (((ks vs) (hashtable-entries tbl)))
                     (vector-for-each
                       (lambda (k v) (when (< (cdr v) now) (hashtable-delete! tbl k)))
                       ks vs))))
               tbl))))
      ;; prune once a minute
      (spawn (lambda ()
               (let loop ()
                 (sleep-ms 60000)
                 (gen-server-cast store (vector 'prune))
                 (loop))))
      store))

  (define (default-rate-key req)
    (or (req-header req 'x-forwarded-for) "global"))

  (define (rate-limit . rest)
    (let* ((o (if (pair? rest) (car rest) '()))
           (max-req (opt o 'max 100))
           (window-ms (opt o 'window 60000))
           (key-fn (opt o 'key default-rate-key))
           (store (make-rate-store)))
      (lambda (req res next)
        (if (eq? 'ok (gen-server-call store
                       (vector 'check (key-fn req) max-req window-ms)))
            (next)
            (begin
              (set-status! res 429)
              (set-header! res "Retry-After" (number->string (div window-ms 1000)))
              (send-json! res (list (cons 'error "rate limit exceeded"))))))))

  ;; ---- global error handler --------------------------------------------
  ;; Wraps the rest of the chain in a guard: an exception from any inner
  ;; middleware or the handler is caught here instead of crashing the
  ;; worker. Register it OUTERMOST (first app-use). Note this opts out of
  ;; Let It Crash for the wrapped handlers -- a caught error answers a
  ;; structured 500 (or your 'handler), with no supervisor retry. If the
  ;; handler already responded, the fallback is dropped (token guard).
  (define (default-error-response e req res)
    (set-status! res 500)
    (send-json! res (list (cons 'error "internal server error"))))

  (define (error-handler . rest)
    (let ((handle (opt (if (pair? rest) (car rest) '())
                       'handler default-error-response)))
      (lambda (req res next)
        (guard (e (#t (handle e req res)))
          (next)))))

  ;; ---- bearer-token auth --------------------------------------------------
  ;; Credential-format neutral: verify is any (lambda (token) ...) that
  ;; returns a claims value for a good token and #f for a bad one --
  ;; (jwt-verifier key) from (igropyr jwt) today, an s-expression token
  ;; verifier tomorrow, the middleware doesn't care. Claims land on the
  ;; request's layer-owned slot, read with (req-claims req).
  ;;
  ;;   (app-use app (auth (jwt-verifier key)))
  ;;   (app-use app (auth (jwt-verifier key '((leeway . 30)))
  ;;                      '((optional . #t))))
  ;;
  ;; Options: (optional . #t) lets a request WITHOUT a token through
  ;; (req-claims stays #f); a present-but-invalid token still answers
  ;; 401. (on-fail . (lambda (req res) ...)) overrides the refusal --
  ;; the default answers 401 + WWW-Authenticate: Bearer with a small
  ;; JSON body; an s-expression endpoint may prefer a sexpr body.

  (define (bearer-token req)
    (let ((h (req-header req 'authorization)))
      (and (string? h)
           (fx>= (string-length h) 7)
           (string-ci=? (substring h 0 7) "Bearer ")
           (let ((t (substring h 7 (string-length h))))
             (and (fx> (string-length t) 0) t)))))

  (define (default-auth-fail req res)
    (set-status! res 401)
    (set-header! res "WWW-Authenticate" "Bearer")
    (send-json! res '((error . "unauthorized"))))

  (define (auth verify . rest)
    (unless (procedure? verify)             ; boot-time config error, be loud
      (assertion-violation 'auth "verify must be a procedure" verify))
    (let* ((o (if (pair? rest) (car rest) '()))
           (optional (opt o 'optional #f))
           (on-fail (opt o 'on-fail default-auth-fail)))
      (lambda (req res next)
        (let* ((tok (bearer-token req))
               (claims (and tok (verify tok))))
          (cond
            (claims
             (req-set-local! req 'claims claims)
             (next))
            ((and optional (not tok))
             (next))
            (else (on-fail req res)))))))

  ;; claims left by (auth ...), or #f
  (define-checked (req-claims (req request?))
    (req-local req 'claims))
)
