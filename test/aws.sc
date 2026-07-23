#!chezscheme
;;; (igropyr sts / ses / sns / cloudwatch) against a hermetic in-process fake
;;; AWS: it pins the wire each call puts on the socket (STS/SNS/CloudWatch
;;; query-protocol form bodies + SigV4 service scope; SES v2 JSON shape + RFC
;;; 2047 From) and that each parses its canned response. Signature CORRECTNESS
;;; is pinned by the AWS vectors in igropyr/test/sigv4.sc; this pins the
;;; request/response construction. A live AWS round-trip needs real credentials.

(import (chezscheme) (igropyr http) (igropyr express)
        (only (igropyr json) string->json json-ref)
        (only (igropyr aws) endpoint->host)
        (igropyr sts) (igropyr ses) (igropyr sns) (igropyr cloudwatch))

(define port 18096)

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1)) (display "FAIL  ") (display label) (newline))))

(define server-fails (box '()))
(define (sfail! x) (set-box! server-fails (cons x (unbox server-fails))))

(define (str-has? hay needle)
  (let ((hn (string-length hay)) (nn (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i nn) hn) #f)
            ((string=? (substring hay i (+ i nn)) needle) #t)
            (else (loop (+ i 1)))))))

(define (count-sub hay needle)
  (let ((hn (string-length hay)) (nn (string-length needle)))
    (let loop ((i 0) (c 0))
      (cond ((> (+ i nn) hn) c)
            ((string=? (substring hay i (+ i nn)) needle) (loop (+ i nn) (+ c 1)))
            (else (loop (+ i 1) c))))))

;; the fake SES server records the last request's From/To here so the client
;; can assert the display-name / recipient encoding black-box
(define last-from (box #f))
(define last-to (box #f))

;; endpoint->host drops an explicit default port (443/80) so the signed host
;; equals the Host header (igropyr http-client) writes on the wire; any other
;; port is kept. Pure, so it runs before the scheduler.
(check "host-drop-443" (equal? (endpoint->host "https://sts.us-east-1.amazonaws.com:443") "sts.us-east-1.amazonaws.com"))
(check "host-drop-80"  (equal? (endpoint->host "http://mail.example.com:80") "mail.example.com"))
(check "host-keep-nondefault" (equal? (endpoint->host "https://mail.example.com:8080") "mail.example.com:8080"))
(check "host-no-port"  (equal? (endpoint->host "https://sts.us-east-1.amazonaws.com") "sts.us-east-1.amazonaws.com"))
(check "host-keep-testport" (equal? (endpoint->host "http://127.0.0.1:18096") "127.0.0.1:18096"))

(define app (create-app))

;; ---- fake query-protocol services: STS / SNS / CloudWatch all POST "/",
;;      so dispatch on the Action in the form body --------------------------
(app-post app "/"
  (lambda (req res)
    (let ((body (utf8->string (req-body req)))
          (auth (req-header req 'authorization)))
      (cond
        ;; STS GetFederationToken -> XML credentials
        ((str-has? body "Action=GetFederationToken")
         (unless (str-has? body "Version=2011-06-15") (sfail! 'sts-version))
         (unless (str-has? body "DurationSeconds=3600") (sfail! 'sts-duration))
         (unless (str-has? body "Name=u-test") (sfail! 'sts-name))
         (unless (and auth (str-has? auth "/sts/aws4_request")) (sfail! 'sts-auth-scope))
         (send-text! res
           (string-append
             "<GetFederationTokenResponse><GetFederationTokenResult><Credentials>"
             "<AccessKeyId>AKIATEST</AccessKeyId>"
             "<SecretAccessKey>secret123</SecretAccessKey>"
             "<SessionToken>token456==</SessionToken>"
             "<Expiration>2026-07-19T18:00:00Z</Expiration>"
             "</Credentials></GetFederationTokenResult></GetFederationTokenResponse>")))
        ;; SNS Publish -> XML MessageId
        ((str-has? body "Action=Publish")
         (unless (str-has? body "Version=2010-03-31") (sfail! 'sns-version))
         (unless (str-has? body "TopicArn=")   (sfail! 'sns-topic))   ; ARN is %-encoded
         (unless (str-has? body "Subject=subj1") (sfail! 'sns-subject))
         (unless (str-has? body "Message=hi")  (sfail! 'sns-message))
         (unless (and auth (str-has? auth "/sns/aws4_request")) (sfail! 'sns-auth-scope))
         (send-text! res
           "<PublishResponse><PublishResult><MessageId>sns-msg-1</MessageId></PublishResult></PublishResponse>"))
        ;; CloudWatch PutMetricData -> empty 2xx body
        ((str-has? body "Action=PutMetricData")
         (unless (str-has? body "Version=2010-08-01") (sfail! 'cw-version))
         (unless (and auth (str-has? auth "/monitoring/aws4_request")) (sfail! 'cw-auth-scope))
         (cond
           ((str-has? body "Namespace=cwmin")       ; the defaults call (no unit/dims)
            (unless (str-has? body "MetricData.member.1.MetricName=hits2") (sfail! 'cw2-name))
            (unless (str-has? body "MetricData.member.1.Value=1") (sfail! 'cw2-value))
            (unless (str-has? body "MetricData.member.1.Unit=Count") (sfail! 'cw2-default-unit))
            (when   (str-has? body "Dimensions.member") (sfail! 'cw2-unexpected-dims)))
           ((str-has? body "Namespace=cwratio")     ; an exact rational value -> decimal
            (unless (str-has? body "MetricData.member.1.Value=0.25") (sfail! 'cw-rational)))
           ((str-has? body "Namespace=cwfull")      ; the full call (unit + one dim)
            (unless (str-has? body "MetricData.member.1.MetricName=hits") (sfail! 'cw-name))
            (unless (str-has? body "MetricData.member.1.Value=5") (sfail! 'cw-value))
            (unless (str-has? body "MetricData.member.1.Unit=Milliseconds") (sfail! 'cw-unit))
            (unless (str-has? body "MetricData.member.1.Dimensions.member.1.Name=kind") (sfail! 'cw-dim-name))
            (unless (str-has? body "MetricData.member.1.Dimensions.member.1.Value=alert") (sfail! 'cw-dim-value)))
           (else (sfail! 'cw-namespace)))
         (send-text! res ""))                        ; PutMetricData: 2xx, empty body
        (else (sfail! 'unknown-action) (send-text! res ""))))))

;; ---- fake SES v2 (JSON) ----------------------------------------------------
(app-post app "/v2/email/outbound-emails"
  (lambda (req res)
    (let* ((body (utf8->string (req-body req)))
           (j (guard (e (#t #f)) (string->json body)))
           (subj (and j (json-ref j "Content" "Simple" "Subject" "Data"))))
      (when j
        (set-box! last-from (json-ref j "FromEmailAddress"))
        (set-box! last-to (json-ref j "Destination" "ToAddresses")))
      ;; the primary "云图" send pins the full nested JSON shape (array To,
      ;; nested Subject/Body) + RFC 2047 From -- what pins (igropyr json) building
      (when (equal? subj "Verify your email")
        (unless (and j
                     (equal? (json-ref j "Destination" "ToAddresses" 0) "user@x.com")
                     (equal? (json-ref j "Content" "Simple" "Body" "Html" "Data") "<p>hi</p>"))
          (sfail! 'ses-json-shape))
        (unless (str-has? body "=?UTF-8?B?") (sfail! 'ses-mime))
        (unless (str-has? body "noreply@ynthu.com") (sfail! 'ses-addr)))
      (let ((auth (req-header req 'authorization)))
        (unless (and auth (str-has? auth "/ses/aws4_request")) (sfail! 'ses-auth-scope)))
      ;; "trigger-empty-200" returns a 2xx with an empty body to exercise the
      ;; client's json-guard; every other send gets the canned MessageId
      (if (equal? subj "trigger-empty-200")
          (send-text! res "")
          (send-json! res '(("MessageId" . "msg-789")))))))

;; ---- tests -----------------------------------------------------------------
(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (sleep-ms 100)
    (let ((ep (string-append "http://127.0.0.1:" (number->string port))))

      ;; STS: form body signed to service sts, credentials parsed from XML
      (let* ((sts (make-sts `((region . "us-east-1") (access-key . "AKIA")
                              (secret . "SEKRIT") (endpoint . ,ep))))
             (c (sts-get-federation-token sts "u-test"
                  "{\"Version\":\"2012-10-17\",\"Statement\":[]}" 3600)))
        (check "sts-access-key-id"  (equal? (cdr (assq 'access-key-id c)) "AKIATEST"))
        (check "sts-secret-key"     (equal? (cdr (assq 'secret-access-key c)) "secret123"))
        (check "sts-session-token"  (equal? (cdr (assq 'session-token c)) "token456=="))
        (check "sts-expiration"     (equal? (cdr (assq 'expiration c)) "2026-07-19T18:00:00Z")))

      ;; SES: JSON body signed to service ses, MessageId parsed back
      (let* ((ses (make-ses `((region . "eu-west-3") (access-key . "AKIA")
                              (secret . "SEKRIT") (endpoint . ,ep))))
             (mid (ses-send-email ses "noreply@ynthu.com" "云图" "user@x.com"
                                  "Verify your email" "<p>hi</p>")))
        (check "ses-message-id" (equal? mid "msg-789"))
        ;; a long non-ASCII name splits into multiple <=75-char encoded-words
        (ses-send-email ses "noreply@ynthu.com" "云图科技股份有限公司北京总部研发中心"
                        "user@x.com" "long-name" "<p>x</p>")
        (check "ses-longname-split" (>= (count-sub (or (unbox last-from) "") "=?UTF-8?B?") 2))
        ;; an ASCII name with a comma becomes a quoted-string, not a bare phrase
        (ses-send-email ses "noreply@ynthu.com" "Foo, Bar" "user@x.com" "comma" "<p>x</p>")
        (check "ses-quoted-name" (equal? (unbox last-from) "\"Foo, Bar\" <noreply@ynthu.com>"))
        ;; an empty display name falls through to address-only
        (ses-send-email ses "noreply@ynthu.com" "" "user@x.com" "empty" "<p>x</p>")
        (check "ses-empty-name" (equal? (unbox last-from) "noreply@ynthu.com"))
        ;; a list of recipients becomes a JSON array of N addresses
        (ses-send-email ses "noreply@ynthu.com" #f (list "a@x.com" "b@y.com")
                        "tolist" "<p>x</p>")
        (check "ses-to-list" (let ((t (unbox last-to)))
                               (and (vector? t) (= 2 (vector-length t))
                                    (equal? (vector-ref t 0) "a@x.com")
                                    (equal? (vector-ref t 1) "b@y.com"))))
        ;; a 2xx with an empty body returns #t, never raises json-error past
        ;; the ses-error-only contract
        (check "ses-empty-2xx-ok"
          (eq? #t (ses-send-email ses "noreply@ynthu.com" #f "user@x.com"
                                  "trigger-empty-200" "<p>x</p>"))))

      ;; SNS: query body signed to service sns, MessageId parsed from XML
      (let ((sns (make-sns `((region . "us-east-1") (access-key . "AKIA")
                             (secret . "SEKRIT") (endpoint . ,ep)))))
        (check "sns-message-id"
          (equal? (sns-publish sns "arn:aws:sns:us-east-1:123:alerts" "subj1" "hi")
                  "sns-msg-1")))

      ;; CloudWatch: query body signed to service monitoring, empty 2xx -> #t;
      ;; both the full (unit + dim) and the defaults (unit "Count", no dims) path
      (let ((cw (make-cloudwatch `((region . "us-east-1") (access-key . "AKIA")
                                   (secret . "SEKRIT") (endpoint . ,ep)))))
        (check "cw-put-full"
          (eq? #t (cloudwatch-put-metric cw "cwfull" "hits" 5 "Milliseconds"
                                         '(("kind" . "alert")))))
        (check "cw-put-defaults"
          (eq? #t (cloudwatch-put-metric cw "cwmin" "hits2" 1)))
        ;; an exact rational value renders as a decimal ("0.25"), not "1/4"
        (check "cw-put-rational"
          (eq? #t (cloudwatch-put-metric cw "cwratio" "ratio" (/ 1 4))))))

    (check "server-side" (null? (unbox server-fails)))
    (unless (null? (unbox server-fails))
      (display "  server-side failures: ") (write (unbox server-fails)) (newline))

    (if (zero? failures)
        (begin (display "aws (sts/ses/sns/cloudwatch): all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
