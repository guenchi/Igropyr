#!chezscheme
;;; (igropyr dashboard): the serving layer over metrics. Mounting onto an
;;; app (built-in page / custom HTML / data-only), the turnkey
;;; admin-listen (loopback bind + optional auth), and the single-quote
;;; injection guard. The signal itself is pinned in test/metrics.sc.

(import (chezscheme) (igropyr util) (igropyr http) (igropyr express)
        (igropyr http-client) (igropyr metrics) (igropyr dashboard)
        (igropyr json) (igropyr sexpr) (igropyr auth))

(define main-port 18110)
(define admin-port 18111)
(define auth-port 18112)
(define authv-port 18113)

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (GET url . opts)
  (apply http-get url opts))
(define (url port path) (string-append "http://127.0.0.1:" (number->string port) path))

;; an (app-use)-shaped guard: no token -> 401, short-circuit
(define admin-guard
  (lambda (req res next)
    (if (equal? (req-header req 'x-admin-token) "s3cret")
        (next)
        (begin (set-status! res 401) (send-text! res "unauthorized")))))

(define m (make-metrics))
(define app (create-app))
(app-use app (metrics-middleware m))
(app-get app "/ok" (lambda (req res) (send-text! res "ok")))

(start-scheduler
  (lambda ()
    (let ((srv (app-listen app main-port '((workers . 2)))))
      (sleep-ms 80)
      ;; some traffic so the snapshot is non-trivial
      (GET (url main-port "/ok"))
      (GET (url main-port "/ok"))

      ;; ---- mount onto an existing app: built-in page + data routes ----
      (mount-dashboard! app m srv)              ; default prefix /dash
      (let* ((r (GET (url main-port "/dash")))
             (page (utf8->string (response-body r))))
        (check "page-200" (= (response-status r) 200))
        (check "page-html" (string-contains? page "<!doctype html>"))
        (check "page-data-path" (string-contains? page "const DATA='/dash/data'")))
      (let* ((r (GET (url main-port "/dash/data")))
             (d (string->json (utf8->string (response-body r)))))
        (check "data-json-200" (= (response-status r) 200))
        (check "data-json-uptime" (number? (json-ref d "uptime_ms"))))
      (let ((r (GET (url main-port "/dash/data.sexpr"))))
        (check "data-sexpr-200" (= (response-status r) 200))
        (check "data-sexpr-shape"
          (number? (cdr (assoc "uptime_ms"
                          (string->sexpr-extended (utf8->string (response-body r))))))))

      ;; ---- data-only mount: (html . #f) suppresses the page ----
      (mount-dashboard! app m srv '((prefix . "/nopage") (html . #f)))
      (check "nopage-no-page" (= 404 (response-status (GET (url main-port "/nopage")))))
      (check "nopage-data-ok" (= 200 (response-status (GET (url main-port "/nopage/data")))))

      ;; ---- bring-your-own page: an inline HTML string ----
      (mount-dashboard! app m srv '((prefix . "/custom") (html . "<h1>MINE</h1>")))
      (let ((page (utf8->string (response-body (GET (url main-port "/custom"))))))
        (check "custom-html" (string-contains? page "<h1>MINE</h1>"))
        (check "custom-not-builtin" (not (string-contains? page "<!doctype html>"))))

      ;; ---- turnkey admin listener, loopback bind, page at "/" ----
      (admin-listen m srv `((host . "127.0.0.1") (port . ,admin-port)))
      (sleep-ms 80)
      (let* ((r (GET (url admin-port "/")))
             (page (utf8->string (response-body r))))
        (check "admin-page-200" (= (response-status r) 200))
        (check "admin-page-html" (string-contains? page "<!doctype html>"))
        (check "admin-page-data-path" (string-contains? page "const DATA='/data'")))
      (check "admin-data-200" (= 200 (response-status (GET (url admin-port "/data")))))
      ;; admin metrics ride the MAIN server's stats, and the admin port's
      ;; own polling is NOT recorded (no middleware on the admin app)
      (let ((d (string->json (utf8->string (response-body (GET (url admin-port "/data")))))))
        (check "admin-shows-main-requests"
          (let ((n (json-ref d "requests" "200"))) (and (number? n) (>= n 2)))))

      ;; ---- admin listener with an auth guard ----
      (admin-listen m srv `((host . "127.0.0.1") (port . ,auth-port)
                            (auth . ,admin-guard)))
      (sleep-ms 80)
      (check "auth-blocks"
        (= 401 (response-status (GET (url auth-port "/data")))))
      (check "auth-allows"
        (= 200 (response-status
                 (GET (url auth-port "/data")
                      '((headers . (("X-Admin-Token" . "s3cret"))))))))
      (check "auth-blocks-page"
        (= 401 (response-status (GET (url auth-port "/")))))

      ;; ---- the composition the usage example teaches: (auth verify) ----
      ;; This file's own header example once passed (token-guard verify)
      ;; into the auth slot -- a one-argument request guard, where the
      ;; slot takes app-use middleware. admin-listen installs whatever
      ;; procedure it is given, so boot accepted it and the first admin
      ;; request died on arity, answering 500: an admin surface closed by
      ;; accident, not by design. This case runs the composition the
      ;; example teaches NOW -- `auth' lifting a token verifier into
      ;; middleware -- end to end, so the documented shape has a cell
      ;; that goes red if it stops fitting the slot.
      (admin-listen m srv
        `((host . "127.0.0.1") (port . ,authv-port)
          (auth . ,(auth (lambda (tok)
                           (and (equal? tok "tk") '(("sub" . "ops"))))))))
      (sleep-ms 80)
      (check "verifier-composed auth refuses a tokenless request with 401"
        (= 401 (response-status (GET (url authv-port "/data")))))
      ;; the refusal must be AUTH'S OWN -- its 401 with its JSON body.
      ;; A bare not-500 here discriminates nothing: any middleware
      ;; failure is a 500 and any non-500 passes, so only the refusal's
      ;; identity separates "refused by auth" from "died on the way".
      (check "...and the refusal is auth's own JSON, not a wreck"
        (let ((r (GET (url authv-port "/data"))))
          (and (= 401 (response-status r))
               (let* ((body (utf8->string (response-body r)))
                      (needle "unauthorized") (m (string-length needle))
                      (n (string-length body)))
                 (let loop ((k 0))
                   (cond ((> (+ k m) n) #f)
                         ((string=? (substring body k (+ k m)) needle) #t)
                         (else (loop (+ k 1)))))))))
      (check "verifier-composed auth admits a bearer token"
        (= 200 (response-status
                 (GET (url authv-port "/data")
                      '((headers . (("Authorization" . "Bearer tk"))))))))

      ;; ---- the example itself, read out of dashboard.sc ----------------
      ;; The three cells above run a COPY of the composition, and a copy
      ;; guards nothing: roll the header example back to (token-guard
      ;; verify) and the copy stays green. So the example's auth
      ;; expression is extracted from the source file and evaluated, and
      ;; the value it builds must have app-use middleware arity (mask 8,
      ;; three arguments) -- (token-guard verify) builds a one-argument
      ;; guard (mask 2) and goes red here. The anchor must match exactly
      ;; once: zero means the example moved (fail loudly, do not skip),
      ;; two means the anchor stopped being an anchor.
      (check "the header example builds middleware, measured from the file"
        (let* ((src (call-with-input-file "dashboard.sc"
                      (lambda (p) (get-string-all p))))
               (pat "(auth . ,")
               (m (string-length pat))
               (n (string-length src))
               (hits (let loop ((k 0) (acc '()))
                       (cond ((> (+ k m) n) (reverse acc))
                             ((string=? (substring src k (+ k m)) pat)
                              (loop (+ k 1) (cons k acc)))
                             (else (loop (+ k 1) acc))))))
          (and (= 1 (length hits))
               (let* ((expr (read (open-input-string
                                    (substring src (+ (car hits) m) n))))
                      (built (eval `(let ((verify (lambda (t) #f))) ,expr)
                                   (environment '(chezscheme)
                                                '(igropyr auth)))))
                 (and (procedure? built)
                      (= 8 (procedure-arity-mask built)))))))

      ;; ---- injection guard: a quote in the data path is rejected ----
      (check "quote-in-path-rejected"
        (guard (e ((assertion-violation? e) #t) (#t #f))
          (dashboard-html "/x'y")
          #f))

      (if (zero? failures)
          (begin (display "dashboard: all tests passed") (newline) (exit 0))
          (begin (display failures) (display " failures") (newline) (exit 1))))))
