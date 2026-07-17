#!chezscheme
;;; (igropyr metrics) end to end: the middleware's status/duration
;;; families, business counters via metrics-count! (labelled, +n, and
;;; label-value escaping), all scraped through a real /metrics endpoint.

(import (chezscheme) (igropyr http) (igropyr express) (igropyr client)
        (igropyr metrics) (igropyr gen-server))

(define port 18096)

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (contains? hay needle)
  (let ((hn (string-length hay)) (nn (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i nn) hn) #f)
            ((string=? (substring hay i (+ i nn)) needle) #t)
            (else (loop (+ i 1)))))))

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
      (sleep-ms 100)                     ; casts are async; let them land

      (let* ((r (http-get (string-append "http://127.0.0.1:" (number->string port)
                                         "/metrics")))
             (body (utf8->string (response-body r))))
        (check "scrape-200" (= (response-status r) 200))
        (check "requests-family" (contains? body "igropyr_requests_total{status=\"200\"} 2"))
        (check "duration-count" (contains? body "igropyr_request_duration_ms_count 2"))
        (check "custom-type-line" (contains? body "# TYPE iter_lookup_outcome_total counter"))
        (check "custom-labelled-hit" (contains? body "iter_lookup_outcome_total{outcome=\"hit\"} 2"))
        (check "custom-labelled-miss" (contains? body "iter_lookup_outcome_total{outcome=\"miss\"} 1"))
        (check "custom-unlabelled-n" (contains? body "jobs_done_total 5"))
        (check "label-escaping" (contains? body "odd_labels_total{q=\"say \\\"hi\\\"\\\\x\"} 1")))

      (if (zero? failures)
          (begin (display "metrics: all tests passed") (newline) (exit 0))
          (begin (display failures) (display " failures") (newline) (exit 1))))))
