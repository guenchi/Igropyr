#!chezscheme
;;; (igropyr sts) -- STS GetFederationToken: vend scoped, temporary AWS
;;; credentials (e.g. narrow S3 access) to a client. The session policy
;;; that narrows the grant is built by the caller; this signs the call and
;;; returns the credentials.
;;;
;;;   (define sts (make-sts '((region . "us-east-1")
;;;                           (access-key . "...") (secret . "..."))))
;;;   (sts-get-federation-token sts "u-abc" policy-json 3600)
;;;     ;; -> ((access-key-id . "...") (secret-access-key . "...")
;;;     ;;     (session-token . "...") (expiration . "2026-..T..Z"))
;;;
;;; Raises #(sts-error status message) on a non-2xx response.

(library (igropyr sts)
  (export make-sts sts-get-federation-token)
  (import (chezscheme) (igropyr aws)
          (only (igropyr http-client) response-status response-body))

  (define-record-type (sts make-sts-raw sts?)
    (fields endpoint region access-key secret timeout))

  ;; opts: region access-key secret [endpoint] [timeout]
  (define (make-sts opts)
    (define (opt k d) (let ((p (assq k opts))) (if p (cdr p) d)))
    (let ((region (opt 'region "us-east-1")))
      (make-sts-raw
        (opt 'endpoint (string-append "https://sts." region ".amazonaws.com"))
        region (opt 'access-key "") (opt 'secret "") (opt 'timeout 30000))))

  ;; name: 2-32 chars of [A-Za-z0-9_=,.@-]; policy: an IAM policy JSON
  ;; string; duration: seconds (900-129600). GetFederationToken's final
  ;; grant is the caller's IAM policy INTERSECT this session policy.
  (define (sts-get-federation-token s name policy duration)
    (let* ((body (string->utf8
                   (form-encode
                     `(("Action" . "GetFederationToken")
                       ("Version" . "2011-06-15")
                       ("Name" . ,name)
                       ("Policy" . ,policy)
                       ("DurationSeconds" . ,(number->string duration))))))
           (r (aws-signed-post (sts-endpoint s) "sts" (sts-region s)
                (sts-access-key s) (sts-secret s) "/"
                '(("content-type" . "application/x-www-form-urlencoded"))
                body (sts-timeout s)))
           (status (response-status r))
           (xml (utf8->string (response-body r))))
      (if (and (>= status 200) (< status 300))
          (let ((ak (xml-first xml "AccessKeyId"))
                (sk (xml-first xml "SecretAccessKey"))
                (tok (xml-first xml "SessionToken"))
                (exp (xml-first xml "Expiration")))
            (if (and ak sk tok)
                `((access-key-id . ,ak) (secret-access-key . ,sk)
                  (session-token . ,tok) (expiration . ,exp))
                (raise (vector 'sts-error status
                         "malformed GetFederationToken response"))))
          ;; clip an unrecognized error body (5xx/HTML page, no <Message>) so
          ;; it cannot flood a log wholesale if it escapes up to a panic handler
          (raise (vector 'sts-error status
                   (or (xml-first xml "Message")
                       (if (> (string-length xml) 200)
                           (string-append (substring xml 0 200) "...")
                           xml)))))))
)
