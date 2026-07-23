#!chezscheme
;;; (igropyr s3-control) against a hermetic in-process fake S3 Control endpoint.
;;; Pins that CreateJob PUTs to /v20180820/jobs and parses JobId, DescribeJob
;;; GETs /v20180820/jobs/{id} and parses Status + ProgressSummary, and that
;;; both carry the (signed) x-amz-account-id header. Signature correctness is
;;; pinned by test/sigv4.sc; this pins request/response construction.

(import (chezscheme) (igropyr http) (igropyr express) (igropyr s3-control))

(define port 18097)
(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1)) (display "FAIL  ") (display label) (newline))))

(define last-account (box #f))
(define last-method (box #f))

(define app (create-app))
(app-put app "/v20180820/jobs"
  (lambda (req res)
    (set-box! last-account (req-header req 'x-amz-account-id))
    (set-box! last-method "PUT")
    (set-status! res 200)
    (send-text! res "<CreateJobResult xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\"><JobId>job-abc-123</JobId></CreateJobResult>")))
(app-get app "/v20180820/jobs/:id"
  (lambda (req res)
    (set-box! last-account (req-header req 'x-amz-account-id))
    (set-box! last-method "GET")
    (if (equal? (req-param req "id") "bad-job")
        (begin (set-status! res 400)
               (send-text! res "<ErrorResponse><Error><Message>no such job</Message></Error></ErrorResponse>"))
    (begin
    (set-status! res 200)
    (send-text! res (string-append
      "<DescribeJobResult><Job><JobId>" (req-param req "id") "</JobId><Status>Active</Status>"
      "<ProgressSummary><TotalNumberOfTasks>1000</TotalNumberOfTasks>"
      "<NumberOfTasksSucceeded>600</NumberOfTasksSucceeded>"
      "<NumberOfTasksFailed>5</NumberOfTasksFailed></ProgressSummary></Job></DescribeJobResult>"))))))

(start-scheduler
  (lambda ()
    (define c (make-s3-control `((account-id . "acct-123") (region . "us-east-1")
                                 (access-key . "AKIAEXAMPLE") (secret . "secretexample")
                                 (endpoint . ,(string-append "http://127.0.0.1:" (number->string port))))))
    (app-listen app port '((workers . 2)))
    (sleep-ms 120)

    ;; CreateJob
    (let ((job-id (s3-control-create-job c "<CreateJobRequest><Priority>10</Priority></CreateJobRequest>")))
      (check "create-jobid" (equal? job-id "job-abc-123"))
      (check "create-put"   (equal? (unbox last-method) "PUT"))
      (check "create-account-header" (equal? (unbox last-account) "acct-123")))

    ;; DescribeJob
    (let ((d (s3-control-describe-job c "job-abc-123")))
      (check "describe-get"       (equal? (unbox last-method) "GET"))
      (check "describe-status"    (equal? (cdr (assq 'status d)) "Active"))
      (check "describe-total"     (= (cdr (assq 'total d)) 1000))
      (check "describe-succeeded" (= (cdr (assq 'succeeded d)) 600))
      (check "describe-failed"    (= (cdr (assq 'failed d)) 5))
      (check "describe-account-header" (equal? (unbox last-account) "acct-123")))

    ;; error mapping: a non-2xx raises #(s3-control-error status message)
    (check "error-raise"
      (guard (e ((s3-control-error? e) (equal? (vector-ref e 2) "no such job")) (#t #f))
        (s3-control-describe-job c "bad-job") #f))

    (if (zero? failures)
        (begin (display "s3-control: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
