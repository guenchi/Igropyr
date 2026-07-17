#!chezscheme
;;; (igropyr metrics) end to end: the middleware's status/duration
;;; families, business counters via metrics-count! (labelled, +n, and
;;; label-value escaping), all scraped through a real /metrics endpoint.

(import (chezscheme) (igropyr util) (igropyr http) (igropyr express)
        (igropyr client) (igropyr metrics) (igropyr gen-server)
        (igropyr json))

(define port 18096)

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define m (make-metrics))
(define app (create-app))
(app-use app (metrics-middleware m))
(app-get app "/ok" (lambda (req res) (send-text! res "ok")))

(start-scheduler
  (lambda ()
    (let ((srv (app-listen app port '((workers . 2)))))
      (app-get app "/metrics" (metrics-endpoint m srv))
      (sleep-ms 100)

      (http-get (string-append "http://127.0.0.1:" (number->string port) "/ok"))
      (http-get (string-append "http://127.0.0.1:" (number->string port) "/ok"))

      (metrics-count! m "iter_lookup_outcome_total" '(("outcome" . "hit")))
      (metrics-count! m "iter_lookup_outcome_total" '(("outcome" . "hit")))
      (metrics-count! m "iter_lookup_outcome_total" '(("outcome" . "miss")))
      (metrics-count! m "jobs_done_total" '() 5)
      (metrics-count! m "odd_labels_total" '(("q" . "say \"hi\"\\x")))
      ;; the same label SET in two alist orders must be one series
      (metrics-count! m "order_total" '(("a" . "1") ("b" . "2")))
      (metrics-count! m "order_total" '(("b" . "2") ("a" . "1")))
      (sleep-ms 100)                     ; casts are async; let them land

      ;; malformed input fails the CALLER; the collector stays alive
      ;; (the scrape checks below double as its liveness probe)
      (let ((rejects? (lambda (thunk) (guard (e (#t #t)) (thunk) #f))))
        (check "bad-n-rejected"
          (rejects? (lambda () (metrics-count! m "x_total" '() "5"))))
        (check "bad-name-rejected"
          (rejects? (lambda () (metrics-count! m "bad-name" '()))))
        (check "reserved-name-rejected"
          (rejects? (lambda () (metrics-count! m "igropyr_requests_total" '()))))
        (check "bad-label-rejected"
          (rejects? (lambda () (metrics-count! m "y_total" '(("ok" . "1") ("bad-key" . "2"))))))
        (check "dup-label-rejected"
          (rejects? (lambda () (metrics-count! m "z_total" '(("a" . "1") ("a" . "2")))))))

      (let* ((r (http-get (string-append "http://127.0.0.1:" (number->string port)
                                         "/metrics")))
             (body (utf8->string (response-body r))))
        (check "scrape-200" (= (response-status r) 200))
        (check "requests-family" (string-contains? body "igropyr_requests_total{status=\"200\"} 2"))
        (check "duration-count" (string-contains? body "igropyr_request_duration_ms_count 2"))
        (check "custom-type-line" (string-contains? body "# TYPE iter_lookup_outcome_total counter"))
        (check "custom-labelled-hit" (string-contains? body "iter_lookup_outcome_total{outcome=\"hit\"} 2"))
        (check "custom-labelled-miss" (string-contains? body "iter_lookup_outcome_total{outcome=\"miss\"} 1"))
        (check "custom-unlabelled-n" (string-contains? body "jobs_done_total 5"))
        (check "label-escaping" (string-contains? body "odd_labels_total{q=\"say \\\"hi\\\"\\\\x\"} 1"))
        (check "label-order-one-series" (string-contains? body "order_total{a=\"1\",b=\"2\"} 2"))
        (check "label-order-no-dup" (not (string-contains? body "order_total{b="))))

      ;; browser dashboard: the page and its JSON snapshot ride the
      ;; same collector as the Prometheus endpoint
      (app-get app "/dash/data" (metrics-json m srv))
      (app-get app "/dash" (metrics-dashboard "/dash/data"))

      (let* ((r (http-get (string-append "http://127.0.0.1:" (number->string port)
                                         "/dash")))
             (page (utf8->string (response-body r))))
        (check "dash-200" (= (response-status r) 200))
        (check "dash-html" (string-contains? page "<!doctype html>"))
        (check "dash-data-path" (string-contains? page "const DATA='/dash/data'")))

      (let* ((r (http-get (string-append "http://127.0.0.1:" (number->string port)
                                         "/dash/data")))
             (d (string->json (utf8->string (response-body r)))))
        (check "data-200" (= (response-status r) 200))
        (check "data-uptime" (number? (json-ref d "uptime_ms")))
        (check "data-requests-200"
          (let ((n (json-ref d "requests" "200"))) (and (number? n) (>= n 2))))
        (check "data-duration" (>= (json-ref d "duration_count") 2))
        (check "data-pool" (number? (json-ref d "pool" "idle")))
        (check "data-custom-jobs"
          (let loop ((l (vector->list (json-ref d "custom"))))
            (cond ((null? l) #f)
                  ((equal? (json-ref (car l) "name") "jobs_done_total")
                   (equal? 5 (json-ref (car l) "series" 0 "value")))
                  (else (loop (cdr l)))))))

      ;; a quote in the data path would break out of the JS string
      (check "dash-bad-path-rejected"
        (guard (e ((assertion-violation? e) #t) (#t #f))
          (metrics-dashboard "/x'y")
          #f))

      (if (zero? failures)
          (begin (display "metrics: all tests passed") (newline) (exit 0))
          (begin (display failures) (display " failures") (newline) (exit 1))))))
