#!chezscheme
;;; (igropyr metrics) end to end: the middleware's status/duration
;;; families, business counters via metrics-count! (labelled, +n, and
;;; label-value escaping), all scraped through a real /metrics endpoint.

(import (chezscheme) (igropyr util) (igropyr http) (igropyr express)
        (igropyr client) (igropyr metrics) (igropyr gen-server)
        (igropyr json) (igropyr sexpr) (igropyr node))

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

      ;; the snapshot signal, two encodings off the same collector: the
      ;; JSON the dashboard polls, and the sexpr a Scheme/Goeteia reader
      ;; would take. The page + its serving live in (igropyr dashboard),
      ;; exercised in test/dashboard.sc -- here we pin the signal.
      (app-get app "/stats.json" (metrics-json m srv))
      (app-get app "/stats.sexpr" (metrics-sexpr m srv))

      (let* ((r (http-get (string-append "http://127.0.0.1:" (number->string port)
                                         "/stats.json")))
             (d (string->json (utf8->string (response-body r)))))
        (check "json-200" (= (response-status r) 200))
        (check "json-uptime" (number? (json-ref d "uptime_ms")))
        (check "json-requests-200"
          (let ((n (json-ref d "requests" "200"))) (and (number? n) (>= n 2))))
        (check "json-duration" (>= (json-ref d "duration_count") 2))
        (check "json-pool" (number? (json-ref d "pool" "idle")))
        (check "json-custom-jobs"
          (let loop ((l (vector->list (json-ref d "custom"))))
            (cond ((null? l) #f)
                  ((equal? (json-ref (car l) "name") "jobs_done_total")
                   (equal? 5 (json-ref (car l) "series" 0 "value")))
                  (else (loop (cdr l))))))
        ;; not a node yet: the cluster member is null
        (check "json-cluster-null" (eq? (json-ref d "cluster") 'null)))

      ;; the sexpr encoding mirrors the JSON shape (string keys), so the
      ;; same fields resolve -- one snapshot, two serializers, no drift
      (let* ((r (http-get (string-append "http://127.0.0.1:" (number->string port)
                                         "/stats.sexpr")))
             (ct (response-header r 'content-type))
             (d (string->sexpr-extended (utf8->string (response-body r)))))
        (check "sexpr-200" (= (response-status r) 200))
        (check "sexpr-content-type"
          (and ct (string-contains? ct "application/sexpr")))
        (check "sexpr-uptime" (number? (cdr (assoc "uptime_ms" d))))
        (check "sexpr-requests-200"
          (let ((n (cdr (assoc "200" (cdr (assoc "requests" d))))))
            (and (number? n) (>= n 2)))))

      ;; cluster view: become a (single-node) mesh member, announce,
      ;; and the snapshot grows a cluster member with the self row
      (node-start! 'm1 "metrics-secret" 18097 "127.0.0.1")
      (metrics-announce! m srv)
      (let* ((r (http-get (string-append "http://127.0.0.1:" (number->string port)
                                         "/stats.json")))
             (d (string->json (utf8->string (response-body r))))
             (cl (json-ref d "cluster")))
        (check "cluster-self" (equal? (json-ref cl "self") "m1"))
        (let ((n0 (json-ref cl "nodes" 0)))
          (check "cluster-node-name" (equal? (json-ref n0 "name") "m1"))
          (check "cluster-node-self" (eq? (json-ref n0 "self") #t))
          (check "cluster-node-uptime" (number? (json-ref n0 "uptime_ms")))
          (check "cluster-node-requests"
            (let ((n (json-ref n0 "requests"))) (and (number? n) (>= n 2))))
          (check "cluster-node-5xx" (equal? 0 (json-ref n0 "err_5xx")))))

      ;; the announced summary answers rcall under the well-known name
      ;; (own-node rcall = the same path a peer's dashboard would take)
      (check "announce-rcall"
        (let ((s (rcall 'm1 'igropyr-metrics 'summary)))
          (and (pair? (assq 'requests s))
               (number? (cdr (assq 'requests s))))))

      ;; in-process callers can read the snapshot directly
      (check "snapshot-value"
        (number? (cdr (assoc "uptime_ms" (metrics-snapshot m srv)))))

      (if (zero? failures)
          (begin (display "metrics: all tests passed") (newline) (exit 0))
          (begin (display failures) (display " failures") (newline) (exit 1))))))
