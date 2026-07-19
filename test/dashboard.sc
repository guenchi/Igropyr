#!chezscheme
;;; (igropyr dashboard): the serving layer over metrics. Mounting onto an
;;; app (built-in page / custom HTML / data-only), the turnkey
;;; admin-listen (loopback bind + optional auth), and the single-quote
;;; injection guard. The signal itself is pinned in test/metrics.sc.

(import (chezscheme) (igropyr util) (igropyr http) (igropyr express)
        (igropyr http-client) (igropyr metrics) (igropyr dashboard)
        (igropyr json) (igropyr sexpr))

(define main-port 18110)
(define admin-port 18111)
(define auth-port 18112)

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

      ;; ---- injection guard: a quote in the data path is rejected ----
      (check "quote-in-path-rejected"
        (guard (e ((assertion-violation? e) #t) (#t #f))
          (dashboard-html "/x'y")
          #f))

      (if (zero? failures)
          (begin (display "dashboard: all tests passed") (newline) (exit 0))
          (begin (display failures) (display " failures") (newline) (exit 1))))))
