#!chezscheme
;;; (igropyr ses) -- Amazon SES v2 SendEmail (the JSON API). The message
;;; (subject + HTML) is the caller's; this sends one already-rendered
;;; message. A non-ASCII From display name is RFC 2047 mime-word encoded,
;;; or clients (Gmail) show only the address local-part.
;;;
;;;   (define ses (make-ses '((region . "eu-west-3")
;;;                           (access-key . "...") (secret . "..."))))
;;;   (ses-send-email ses "noreply@ynthu.com" "云图" "u@x.com" subject html)
;;;     ;; -> the MessageId string; raises #(ses-error status body) otherwise

(library (igropyr ses)
  (export make-ses ses-send-email)
  (import (chezscheme) (igropyr aws)
          (only (igropyr json) json->string json-ref string->json)
          (only (igropyr http-client) response-status response-body)
          (only (igropyr crypto) base64-encode))

  (define-record-type (ses make-ses-raw ses?)
    (fields endpoint region access-key secret timeout))

  ;; opts: region access-key secret [endpoint] [timeout]
  (define (make-ses opts)
    (define (opt k d) (let ((p (assq k opts))) (if p (cdr p) d)))
    (let ((region (opt 'region "us-east-1")))
      (make-ses-raw
        (opt 'endpoint (string-append "https://email." region ".amazonaws.com"))
        region (opt 'access-key "") (opt 'secret "") (opt 'timeout 30000))))

  (define (ascii? s)
    (let loop ((i 0))
      (cond ((= i (string-length s)) #t)
            ((< (char->integer (string-ref s i)) 128) (loop (+ i 1)))
            (else #f))))

  ;; RFC 2047: =?UTF-8?B?base64?= for a non-ASCII display name
  (define (encode-mime-word s)
    (if (ascii? s)
        s
        (string-append "=?UTF-8?B?" (base64-encode (string->utf8 s)) "?=")))

  ;; from-name may be #f (address only). to/subject/html are strings.
  ;; -> MessageId string; raises #(ses-error status body).
  (define (ses-send-email s from-addr from-name to subject html)
    (let* ((from (if from-name
                     (string-append (encode-mime-word from-name) " <" from-addr ">")
                     from-addr))
           ;; ToAddresses is a vector so (igropyr json) writes it as a JSON
           ;; array unambiguously; every object is an alist.
           (body (string->utf8
                   (json->string
                     `(("FromEmailAddress" . ,from)
                       ("Destination" . (("ToAddresses" . ,(vector to))))
                       ("Content" .
                        (("Simple" .
                          (("Subject" . (("Data" . ,subject) ("Charset" . "UTF-8")))
                           ("Body" . (("Html" . (("Data" . ,html)
                                                 ("Charset" . "UTF-8")))))))))))))
           (r (aws-signed-post (ses-endpoint s) "ses" (ses-region s)
                (ses-access-key s) (ses-secret s) "/v2/email/outbound-emails"
                '(("content-type" . "application/json"))
                body (ses-timeout s)))
           (status (response-status r))
           (txt (utf8->string (response-body r))))
      (if (and (>= status 200) (< status 300))
          (or (json-ref (string->json txt) "MessageId") #t)
          (raise (vector 'ses-error status txt)))))
)
