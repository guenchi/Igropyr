#!chezscheme
;;; (igropyr sns) -- Amazon SNS Publish: push one message to a topic (fan-out
;;; to that topic's subscribers -- email, SMS, SQS, Lambda, HTTP). The topic
;;; and its subscriptions are provisioned out of band; this signs the call and
;;; returns the MessageId.
;;;
;;;   (define sns (make-sns '((region . "us-east-1")
;;;                           (access-key . "...") (secret . "..."))))
;;;   (sns-publish sns "arn:aws:sns:us-east-1:123:alerts" "subject" "body")
;;;     ;; -> the MessageId string
;;;
;;; Subject is optional (it only shows up in email delivery): pass #f or ""
;;; to omit it. Raises #(sns-error status message) on a non-2xx response.

(library (igropyr sns)
  (export make-sns sns-publish)
  (import (chezscheme) (igropyr aws)
          (only (igropyr http-client) response-status response-body))

  (define-record-type (sns make-sns-raw sns?)
    (fields endpoint region access-key secret timeout))

  ;; opts: region access-key secret [endpoint] [timeout]
  (define (make-sns opts)
    (define (opt k d) (let ((p (assq k opts))) (if p (cdr p) d)))
    (let ((region (opt 'region "us-east-1")))
      (make-sns-raw
        (opt 'endpoint (string-append "https://sns." region ".amazonaws.com"))
        region (opt 'access-key "") (opt 'secret "") (opt 'timeout 30000))))

  ;; topic-arn: the target topic; subject: optional (#f/"" omits it);
  ;; message: the message body. -> MessageId string.
  (define (sns-publish s topic-arn subject message)
    (let* ((body (string->utf8
                   (form-encode
                     (append
                       `(("Action" . "Publish")
                         ("Version" . "2010-03-31")
                         ("TopicArn" . ,topic-arn))
                       (if (and (string? subject) (> (string-length subject) 0))
                           `(("Subject" . ,subject)) '())
                       `(("Message" . ,message))))))
           (r (aws-signed-post (sns-endpoint s) "sns" (sns-region s)
                (sns-access-key s) (sns-secret s) "/"
                '(("content-type" . "application/x-www-form-urlencoded"))
                body (sns-timeout s)))
           (status (response-status r))
           (xml (utf8->string (response-body r))))
      (if (and (>= status 200) (< status 300))
          (or (xml-first xml "MessageId")
              (raise (vector 'sns-error status "malformed Publish response")))
          ;; clip an unrecognized error body (5xx/HTML, no <Message>) so it
          ;; cannot flood a log wholesale if it escapes up to a panic handler
          (raise (vector 'sns-error status
                   (or (xml-first xml "Message")
                       (if (> (string-length xml) 200)
                           (string-append (substring xml 0 200) "...")
                           xml)))))))
)
