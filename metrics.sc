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
;;;
;;; Business counters ride the same collector -- register nothing,
;;; just count; each name renders as its own TYPE counter family:
;;;
;;;   (metrics-count! m "iter_lookup_outcome_total" '(("outcome" . "hit")))
;;;   (metrics-count! m "jobs_done_total" '() 5)    ; labels optional, +n form
;;;   ;; -> iter_lookup_outcome_total{outcome="hit"} 1

(library (igropyr metrics)
  (export make-metrics metrics-middleware metrics-endpoint metrics-count!)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr gen-server)
          (igropyr http) (igropyr express))

  ;; state: #(status-count-ht duration-sum-box duration-count-box
  ;;          custom-ht)  where custom-ht: name -> (label-string -> count)
  (define (metrics-init)
    (vector (make-eqv-hashtable) (box 0) (box 0)
            (make-hashtable string-hash string=?)))

  (define (metrics-cast msg st)
    (case (vector-ref msg 0)
      ((record)
       (let ((status (vector-ref msg 1)) (dur (vector-ref msg 2)))
         (hashtable-update! (vector-ref st 0) status (lambda (n) (+ n 1)) 0)
         (set-box! (vector-ref st 1) (+ (unbox (vector-ref st 1)) dur))
         (set-box! (vector-ref st 2) (+ (unbox (vector-ref st 2)) 1))))
      ((count)
       (let* ((name (vector-ref msg 1))
              (labels (vector-ref msg 2))
              (n (vector-ref msg 3))
              (custom (vector-ref st 3))
              (inner (or (hashtable-ref custom name #f)
                         (let ((h (make-hashtable string-hash string=?)))
                           (hashtable-set! custom name h)
                           h))))
         (hashtable-update! inner labels (lambda (v) (+ v n)) 0))))
    st)

  (define (hashtable->alist ht)
    (let-values (((ks vs) (hashtable-entries ht)))
      (let loop ((i 0) (acc '()))
        (if (= i (vector-length ks))
            acc
            (loop (+ i 1) (cons (cons (vector-ref ks i) (vector-ref vs i)) acc))))))

  ;; call 'dump -> #(status-alist duration-sum duration-count custom-alist)
  ;; custom-alist: ((name . ((label-string . count) ...)) ...)
  (define (metrics-call msg from st)
    (values
      (vector
        (hashtable->alist (vector-ref st 0))
        (unbox (vector-ref st 1))
        (unbox (vector-ref st 2))
        (map (lambda (kv) (cons (car kv) (hashtable->alist (cdr kv))))
             (hashtable->alist (vector-ref st 3))))
      st))

  ;; a metrics collector is just the gen-server pid
  (define (make-metrics)
    (gen-server-start metrics-init metrics-call metrics-cast))

  ;; Prometheus label escaping: backslash, double-quote, newline
  (define (escape-label-value v)
    (let-values (((p get) (open-string-output-port)))
      (do ((i 0 (+ i 1))) ((= i (string-length v)) (get))
        (let ((c (string-ref v i)))
          (case c
            ((#\\) (put-string p "\\\\"))
            ((#\") (put-string p "\\\""))
            ((#\newline) (put-string p "\\n"))
            (else (put-char p c)))))))

  ;; labels alist -> "{k=\"v\",...}" or "" -- built once, off the collector
  (define (label-string labels)
    (if (null? labels)
        ""
        (let-values (((p get) (open-string-output-port)))
          (put-char p #\{)
          (let loop ((l labels) (first #t))
            (unless (null? l)
              (unless first (put-char p #\,))
              (put-string p (caar l))
              (put-string p "=\"")
              (put-string p (escape-label-value (cdar l)))
              (put-string p "\"")
              (loop (cdr l) #f)))
          (put-char p #\})
          (get))))

  ;; count a business event: name is the Prometheus family, labels an
  ;; alist of (name . value) strings, n the increment (default 1)
  (define metrics-count!
    (case-lambda
      ((m name labels) (metrics-count! m name labels 1))
      ((m name labels n)
       (gen-server-cast m (vector 'count name (label-string labels) n)))))

  ;; record each request's final status and wall-clock duration
  (define (metrics-middleware m)
    (lambda (req res next)
      (let ((t0 (now-ms)))
        (next)
        (gen-server-cast m (vector 'record (res-status res) (- (now-ms) t0))))))

  ;; ---- Prometheus text rendering ---------------------------------------

  (define (line . parts) (apply string-append (append parts (list "\n"))))

  (define (render-custom custom)
    (apply string-append
      (map (lambda (family)
             (string-append
               (line "# TYPE " (car family) " counter")
               (apply string-append
                 (map (lambda (lv)
                        (line (car family) (car lv) " "
                              (number->string (cdr lv))))
                      (cdr family)))))
           custom)))

  (define (render dump stats)
    (let ((counts (vector-ref dump 0))
          (sum (vector-ref dump 1))
          (count (vector-ref dump 2))
          (custom (vector-ref dump 3)))
      (define (stat key) (number->string (cdr (assq key stats))))
      (string-append
        (render-custom custom)
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
