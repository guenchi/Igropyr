#!chezscheme
;;; (igropyr metrics) -- Prometheus metrics.
;;;
;;; A gen-server accumulates per-status request counts and request
;;; duration; a middleware records each request; an endpoint renders
;;; everything (plus http-stats connection/pool gauges) in Prometheus
;;; text format.
;;;
;;;   (define m (make-metrics))                    ; at boot
;;;   (app-use app (metrics-middleware m))         ; record every request
;;;   ;; after app-listen returns the server:
;;;   (app-get app "/metrics" (metrics-endpoint m srv))

(library (igropyr metrics)
  (export make-metrics metrics-middleware metrics-endpoint)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr gen-server)
          (igropyr http) (igropyr express))

  ;; state: #(status-count-ht duration-sum-box duration-count-box)
  (define (metrics-init)
    (vector (make-eqv-hashtable) (box 0) (box 0)))

  (define (metrics-cast msg st)
    (when (eq? (vector-ref msg 0) 'record)
      (let ((status (vector-ref msg 1)) (dur (vector-ref msg 2)))
        (hashtable-update! (vector-ref st 0) status (lambda (n) (+ n 1)) 0)
        (set-box! (vector-ref st 1) (+ (unbox (vector-ref st 1)) dur))
        (set-box! (vector-ref st 2) (+ (unbox (vector-ref st 2)) 1))))
    st)

  ;; call 'dump -> #(status-alist duration-sum duration-count)
  (define (metrics-call msg from st)
    (let-values (((ks vs) (hashtable-entries (vector-ref st 0))))
      (values
        (vector
          (let loop ((i 0) (acc '()))
            (if (= i (vector-length ks))
                acc
                (loop (+ i 1)
                      (cons (cons (vector-ref ks i) (vector-ref vs i)) acc))))
          (unbox (vector-ref st 1))
          (unbox (vector-ref st 2)))
        st)))

  ;; a metrics collector is just the gen-server pid
  (define (make-metrics)
    (gen-server-start metrics-init metrics-call metrics-cast))

  ;; record each request's final status and wall-clock duration
  (define (metrics-middleware m)
    (lambda (req res next)
      (let ((t0 (now-ms)))
        (next)
        (gen-server-cast m (vector 'record (res-status res) (- (now-ms) t0))))))

  ;; ---- Prometheus text rendering ---------------------------------------

  (define (line . parts) (apply string-append (append parts (list "\n"))))

  (define (render dump stats)
    (let ((counts (vector-ref dump 0))
          (sum (vector-ref dump 1))
          (count (vector-ref dump 2)))
      (define (stat key) (number->string (cdr (assq key stats))))
      (string-append
        (line "# HELP igropyr_requests_total HTTP requests by status")
        (line "# TYPE igropyr_requests_total counter")
        (apply string-append
          (map (lambda (kv)
                 (line "igropyr_requests_total{status=\""
                       (number->string (car kv)) "\"} "
                       (number->string (cdr kv))))
               counts))
        (line "# HELP igropyr_request_duration_ms Request duration summary")
        (line "# TYPE igropyr_request_duration_ms summary")
        (line "igropyr_request_duration_ms_sum " (number->string sum))
        (line "igropyr_request_duration_ms_count " (number->string count))
        (line "# TYPE igropyr_connections gauge")
        (line "igropyr_connections " (stat 'connections))
        (line "# TYPE igropyr_uptime_ms gauge")
        (line "igropyr_uptime_ms " (stat 'uptime-ms))
        (line "# TYPE igropyr_pool_workers gauge")
        (line "igropyr_pool_busy " (stat 'busy))
        (line "igropyr_pool_idle " (stat 'idle))
        (line "igropyr_pool_pending " (stat 'pending)))))

  ;; endpoint handler; srv is the http-server from app-listen
  (define (metrics-endpoint m srv)
    (lambda (req res)
      (let ((dump (gen-server-call m (vector 'dump)))
            (stats (http-stats srv)))
        (set-header! res "Content-Type" "text/plain; version=0.0.4")
        (res-send! res (string->utf8 (render dump stats))))))
)
