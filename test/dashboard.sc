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
(define hdr-port 18114)

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
      ;; the refusal must be AUTH'S OWN -- its 401 with its JSON body,
      ;; parsed and matched structurally. A bare not-500 discriminates
      ;; nothing (any wreck is a 500, any non-500 passed it), and a
      ;; substring match would accept a hand-rolled text refusal that
      ;; stopped being auth's.
      (check "...and the refusal is auth's own JSON, not a wreck"
        (let ((r (GET (url authv-port "/data"))))
          (and (= 401 (response-status r))
               (let ((ct (response-header r 'content-type)))
                 (and (string? ct)
                      (>= (string-length ct) 16)
                      (string=? (substring ct 0 16) "application/json")))
               (equal? "unauthorized"
                       (let ((d (string->json
                                  (utf8->string (response-body r)))))
                         (and (pair? d) (cdr (assoc "error" d))))))))
      (check "verifier-composed auth admits a bearer token"
        (= 200 (response-status
                 (GET (url authv-port "/data")
                      '((headers . (("Authorization" . "Bearer tk"))))))))

      ;; ---- the example itself, read out of dashboard.sc ----------------
      ;; The three cells above run a COPY of the composition, and a copy
      ;; guards nothing: roll the header example back to (token-guard
      ;; verify) and the copy stays green. And a SHAPE check on the
      ;; extracted expression is a proxy: every three-argument procedure
      ;; has app-use arity, including (lambda (req res next) (next)) --
      ;; an unconditional pass. So the example's auth expression is not
      ;; measured, it is MOUNTED: a fourth admin listener runs whatever
      ;; the example builds, and the requests judge it as auth --
      ;; refused without a token, admitted with one. The anchor must
      ;; match exactly once (zero = the example moved: fail loudly, do
      ;; not skip; two = the anchor stopped being an anchor) and must
      ;; sit in the header commentary, so a stray copy elsewhere cannot
      ;; be what gets extracted.
      (check "the header example, mounted, refuses and admits like auth"
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
               ;; the one hit lies on a ";;;" header-comment line
               (let ((ls (let loop ((k (car hits)))
                           (if (or (= k 0)
                                   (char=? (string-ref src (- k 1)) #\newline))
                               k (loop (- k 1))))))
                 (and (>= n (+ ls 3))
                      (string=? (substring src ls (+ ls 3)) ";;;")))
               (let* ((expr (read (open-input-string
                                    (substring src (+ (car hits) m) n))))
                      (built (eval `(let ((verify (lambda (t)
                                                    (and (equal? t "tk2")
                                                         '(("sub" . "hdr"))))))
                                      ,expr)
                                   (environment '(chezscheme)
                                                '(igropyr auth)))))
                 (and (procedure? built)
                      (begin
                        (admin-listen m srv
                          `((host . "127.0.0.1") (port . ,hdr-port)
                            (auth . ,built)))
                        (sleep-ms 80)
                        (and (= 401 (response-status
                                      (GET (url hdr-port "/data"))))
                             (= 200 (response-status
                                      (GET (url hdr-port "/data")
                                           '((headers . (("Authorization"
                                                          . "Bearer tk2"))))))))))))))

      ;; ---- injection guard: a quote in the data path is rejected ----
      (check "quote-in-path-rejected"
        (guard (e ((assertion-violation? e) #t) (#t #f))
          (dashboard-html "/x'y")
          #f))

      (if (zero? failures)
          (begin (display "dashboard: all tests passed") (newline) (exit 0))
          (begin (display failures) (display " failures") (newline) (exit 1))))))
