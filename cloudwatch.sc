#!chezscheme
;;; (igropyr cloudwatch) -- CloudWatch PutMetricData: publish one custom metric
;;; data point (a namespace + metric name + value, optionally a unit and
;;; dimensions). Build the metric as a counter or a gauge and alarm on it in
;;; CloudWatch; this signs the call and returns #t (PutMetricData answers a 2xx
;;; with an empty body -- there is no id to read back).
;;;
;;;   (define cw (make-cloudwatch '((region . "us-east-1")
;;;                                 (access-key . "...") (secret . "..."))))
;;;   (cloudwatch-put-metric cw "myapp" "requests" 1)            ; unit "Count"
;;;   (cloudwatch-put-metric cw "myapp" "latency_ms" 42 "Milliseconds"
;;;                          '(("route" . "/checkout")))          ; + a dimension
;;;
;;; unit defaults to "Count"; dims is an alist of (name . value). Raises
;;; #(cloudwatch-error status message) on a non-2xx response.

(library (igropyr cloudwatch)
  (export make-cloudwatch cloudwatch-put-metric)
  (import (chezscheme) (igropyr aws)
          (only (igropyr http-client) response-status response-body))

  (define-record-type (cloudwatch make-cloudwatch-raw cloudwatch?)
    (fields endpoint region access-key secret timeout))

  ;; opts: region access-key secret [endpoint] [timeout]
  (define (make-cloudwatch opts)
    (define (opt k d) (let ((p (assq k opts))) (if p (cdr p) d)))
    (let ((region (opt 'region "us-east-1")))
      (make-cloudwatch-raw
        (opt 'endpoint (string-append "https://monitoring." region ".amazonaws.com"))
        region (opt 'access-key "") (opt 'secret "") (opt 'timeout 30000))))

  ;; ((name . value) ...) -> the query params for MetricData.member.1's
  ;; Dimensions.member.1..N (a metric carries up to 30 dimensions).
  (define (dim-params dims)
    (let loop ((l dims) (i 1) (acc '()))
      (if (null? l)
          (reverse acc)
          (let ((base (string-append "MetricData.member.1.Dimensions.member."
                                     (number->string i) ".")))
            (loop (cdr l) (+ i 1)
                  (cons (cons (string-append base "Value") (cdar l))
                        (cons (cons (string-append base "Name") (caar l))
                              acc)))))))

  ;; namespace: metric namespace; name: metric name; value: a number;
  ;; optional unit (default "Count") and dims (alist). -> #t on success.
  (define (cloudwatch-put-metric s namespace name value . rest)
    (let* ((unit (if (pair? rest) (car rest) "Count"))
           (dims (if (and (pair? rest) (pair? (cdr rest))) (cadr rest) '()))
           (body (string->utf8
                   (form-encode
                     (append
                       `(("Action" . "PutMetricData")
                         ("Version" . "2010-08-01")
                         ("Namespace" . ,namespace)
                         ("MetricData.member.1.MetricName" . ,name)
                         ;; AWS wants a decimal double; an exact non-integer
                         ;; (e.g. from (/ a b)) would render as "1/3" and be
                         ;; rejected -- coerce those to inexact. Integers and
                         ;; flonums pass through unchanged.
                         ("MetricData.member.1.Value"
                          . ,(number->string
                               (if (and (exact? value) (not (integer? value)))
                                   (exact->inexact value) value)))
                         ("MetricData.member.1.Unit" . ,unit))
                       (dim-params dims)))))
           (r (aws-signed-post (cloudwatch-endpoint s) "monitoring"
                (cloudwatch-region s) (cloudwatch-access-key s)
                (cloudwatch-secret s) "/"
                '(("content-type" . "application/x-www-form-urlencoded"))
                body (cloudwatch-timeout s)))
           (status (response-status r)))
      (if (and (>= status 200) (< status 300))
          #t                                    ; empty 2xx body -> nothing to read
          (let ((xml (utf8->string (response-body r))))
            (raise (vector 'cloudwatch-error status
                     (or (xml-first xml "Message")
                         (if (> (string-length xml) 200)
                             (string-append (substring xml 0 200) "...")
                             xml))))))))
)
