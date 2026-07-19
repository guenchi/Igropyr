#!chezscheme
;;; (igropyr sts) / (igropyr ses) against a hermetic in-process fake AWS: it
;;; pins the wire the two calls put on the socket (STS query-protocol form
;;; body + SigV4 service scope; SES v2 JSON shape + RFC 2047 From) and that
;;; each parses its canned response. Signature CORRECTNESS is pinned by the
;;; AWS vectors in igropyr/test/sigv4.sc; this pins the request/response
;;; construction. A live AWS round-trip needs real credentials.

(import (chezscheme) (igropyr http) (igropyr express)
        (only (igropyr json) string->json json-ref)
        (igropyr sts) (igropyr ses))

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

(define app (create-app))

;; ---- fake STS (query protocol, XML response) -------------------------------
(app-post app "/"
  (lambda (req res)
    (let ((body (utf8->string (req-body req))))
      (unless (str-has? body "Action=GetFederationToken") (sfail! 'sts-action))
      (unless (str-has? body "Version=2011-06-15") (sfail! 'sts-version))
      (unless (str-has? body "DurationSeconds=3600") (sfail! 'sts-duration))
      (unless (str-has? body "Name=u-test") (sfail! 'sts-name))
      (let ((auth (req-header req 'authorization)))
        (unless (and auth (str-has? auth "/sts/aws4_request")) (sfail! 'sts-auth-scope))))
    (send-text! res
      (string-append
        "<GetFederationTokenResponse><GetFederationTokenResult><Credentials>"
        "<AccessKeyId>AKIATEST</AccessKeyId>"
        "<SecretAccessKey>secret123</SecretAccessKey>"
        "<SessionToken>token456==</SessionToken>"
        "<Expiration>2026-07-19T18:00:00Z</Expiration>"
        "</Credentials></GetFederationTokenResult></GetFederationTokenResponse>"))))

;; ---- fake SES v2 (JSON) ----------------------------------------------------
(app-post app "/v2/email/outbound-emails"
  (lambda (req res)
    (let ((body (utf8->string (req-body req))))
      ;; the JSON must round-trip to the expected nested shape (array To,
      ;; nested Subject/Body) -- this is what pins (igropyr json) building
      (let ((j (guard (e (#t #f)) (string->json body))))
        (unless (and j
                     (equal? (json-ref j "Destination" "ToAddresses" 0) "user@x.com")
                     (equal? (json-ref j "Content" "Simple" "Subject" "Data") "Verify your email")
                     (equal? (json-ref j "Content" "Simple" "Body" "Html" "Data") "<p>hi</p>"))
          (sfail! 'ses-json-shape)))
      ;; the Chinese display name must be RFC 2047 mime-word encoded
      (unless (str-has? body "=?UTF-8?B?") (sfail! 'ses-mime))
      (unless (str-has? body "noreply@ynthu.com") (sfail! 'ses-addr))
      (let ((auth (req-header req 'authorization)))
        (unless (and auth (str-has? auth "/ses/aws4_request")) (sfail! 'ses-auth-scope))))
    (send-json! res '(("MessageId" . "msg-789")))))

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
        (check "ses-message-id" (equal? mid "msg-789"))))

    (check "server-side" (null? (unbox server-fails)))
    (unless (null? (unbox server-fails))
      (display "  server-side failures: ") (write (unbox server-fails)) (newline))

    (if (zero? failures)
        (begin (display "aws (sts/ses): all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
