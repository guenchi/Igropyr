#!chezscheme
;;; (igropyr s3-control) -- the AWS S3 Control API: create and describe S3 Batch
;;; Operations jobs. The endpoint is per-account
;;; ({account-id}.s3-control.{region}.amazonaws.com); requests carry the
;;; x-amz-account-id header (signed) and are SigV4-signed under the "s3"
;;; service, so x-amz-content-sha256 is added like any S3 request.
;;;
;;;   (define c (make-s3-control `((account-id . "123456789012") (region . "us-east-1")
;;;                                (access-key . ...) (secret . ...))))
;;;   (s3-control-create-job c create-job-xml)   ; PUT /v20180820/jobs -> JobId string
;;;   (s3-control-describe-job c job-id)          ; GET .../jobs/{id}
;;;     ; -> ((status . "Active") (total . N) (succeeded . N) (failed . N))
;;;
;;; The CreateJob body is an opaque XML string (the caller builds the
;;; operation/manifest/report spec), so this stays a thin, service-generic
;;; client. A non-2xx raises #(s3-control-error status message).

(library (igropyr s3-control)
  (export make-s3-control s3-control-create-job s3-control-describe-job s3-control-error?)
  (import (chezscheme)
          (only (igropyr sigv4) sigv4-sign-headers sha256-hex)
          (only (igropyr aws) endpoint->host xml-first)
          (only (igropyr http-client) http-request response-status response-body))

  (define-record-type (s3-control make-s3-control-raw s3-control?)
    (fields endpoint host account-id region access-key secret timeout))

  (define (make-s3-control opts)
    (define (opt k d) (let ((p (assq k opts))) (if p (cdr p) d)))
    (let* ((account-id (opt 'account-id ""))
           (region (opt 'region "us-east-1"))
           (endpoint (opt 'endpoint
                       (string-append "https://" account-id ".s3-control." region ".amazonaws.com"))))
      (make-s3-control-raw endpoint (endpoint->host endpoint) account-id region
                           (opt 'access-key "") (opt 'secret "") (opt 'timeout 30000))))

  (define (s3-control-error? e) (and (vector? e) (eq? (vector-ref e 0) 's3-control-error)))
  (define empty-bv (make-bytevector 0))

  ;; sign (SigV4, service "s3", x-amz-account-id) and send. body #f -> no body.
  (define (signed-request c method path body)
    (let* ((payload (or body empty-bv))
           (payload-hash (sha256-hex payload))
           (headers (cons `("x-amz-account-id" . ,(s3-control-account-id c))
                          (if body '(("content-type" . "application/xml")) '())))
           (signed (sigv4-sign-headers method path '() headers payload-hash
                     `((host . ,(s3-control-host c))
                       (access-key . ,(s3-control-access-key c)) (secret . ,(s3-control-secret c))
                       (region . ,(s3-control-region c)) (service . "s3")))))
      (http-request method (string-append (s3-control-endpoint c) path)
        (append `((headers . ,signed) (timeout . ,(s3-control-timeout c)))
                (if body `((body . ,body)) '())))))

  ;; CreateJob: the caller supplies the <CreateJobRequest> XML. -> JobId string
  (define (s3-control-create-job c xml-body)
    (let* ((r (signed-request c 'PUT "/v20180820/jobs" (string->utf8 xml-body)))
           (status (response-status r))
           (xml (utf8->string (response-body r))))
      (if (and (>= status 200) (< status 300))
          (or (xml-first xml "JobId")
              (raise (vector 's3-control-error status "CreateJob response has no JobId")))
          (raise (vector 's3-control-error status
                   (or (xml-first xml "Message")
                       (if (> (string-length xml) 200) (substring xml 0 200) xml)))))))

  (define (num s) (or (and s (string->number s)) 0))

  ;; DescribeJob: GET /v20180820/jobs/{id}. -> the status + progress alist.
  (define (s3-control-describe-job c job-id)
    (let* ((r (signed-request c 'GET (string-append "/v20180820/jobs/" job-id) #f))
           (status (response-status r))
           (xml (utf8->string (response-body r))))
      (if (and (>= status 200) (< status 300))
          `((status . ,(xml-first xml "Status"))
            (total . ,(num (xml-first xml "TotalNumberOfTasks")))
            (succeeded . ,(num (xml-first xml "NumberOfTasksSucceeded")))
            (failed . ,(num (xml-first xml "NumberOfTasksFailed"))))
          (raise (vector 's3-control-error status
                   (or (xml-first xml "Message")
                       (if (> (string-length xml) 200) (substring xml 0 200) xml)))))))
)
