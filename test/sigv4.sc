#!chezscheme
;;; (igropyr sigv4) tests: the AWS documented known-answer vectors --
;;; the SigV4 suite's IAM ListUsers example (canonical request hash,
;;; signing key, final signature) and the S3 GET Object example -- plus
;;; the encoding/normalization helpers. Pure, no sockets.

(import (chezscheme) (igropyr sigv4) (igropyr crypto))

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define empty-hash (sha256-hex (make-bytevector 0)))

;; ---- helpers ---------------------------------------------------------------

(check "empty-payload-hash"
  (equal? empty-hash "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

(check "uri-encode-space" (equal? (sigv4-uri-encode "a b" #f) "a%20b"))
(check "uri-encode-keep-slash" (equal? (sigv4-uri-encode "a b/c.txt" #t) "a%20b/c.txt"))
(check "uri-encode-slash" (equal? (sigv4-uri-encode "a/b" #f) "a%2Fb"))
(check "uri-encode-unreserved" (equal? (sigv4-uri-encode "AZaz09-._~" #f) "AZaz09-._~"))
(check "uri-encode-utf8" (equal? (sigv4-uri-encode "文" #f) "%E6%96%87"))
(check "uri-encode-plus-equals" (equal? (sigv4-uri-encode "a+b=c" #f) "a%2Bb%3Dc"))

(check "canonical-query-sorted"
  (equal? (sigv4-canonical-query '(("Version" . "2010-05-08") ("Action" . "ListUsers")))
          "Action=ListUsers&Version=2010-05-08"))
(check "canonical-query-empty" (equal? (sigv4-canonical-query '()) ""))
(check "canonical-query-value-encoded"
  (equal? (sigv4-canonical-query '(("prefix" . "a b/c")))
          "prefix=a%20b%2Fc"))

;; ---- AWS SigV4 suite: IAM ListUsers (docs "complete signing workflow") ----

(define iam-secret "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
(define iam-datetime "20150830T123600Z")

(let-values (((canonical signed)
              (sigv4-canonical-request "GET" "/"
                (sigv4-canonical-query '(("Action" . "ListUsers")
                                         ("Version" . "2010-05-08")))
                `(("host" . "iam.amazonaws.com")
                  ("content-type" . "application/x-www-form-urlencoded; charset=utf-8")
                  ("x-amz-date" . ,iam-datetime))
                empty-hash)))
  (check "iam-signed-headers" (equal? signed "content-type;host;x-amz-date"))
  (check "iam-canonical-hash"
    (equal? (sha256-hex (string->utf8 canonical))
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"))
  (let ((sts (sigv4-string-to-sign iam-datetime
                                   "20150830/us-east-1/iam/aws4_request"
                                   canonical)))
    (check "iam-signing-key"
      (equal? (bytevector->hex (sigv4-signing-key iam-secret "20150830" "us-east-1" "iam"))
              "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"))
    (check "iam-signature"
      (equal? (bytevector->hex
                (hmac-sha256 (sigv4-signing-key iam-secret "20150830" "us-east-1" "iam")
                             (string->utf8 sts)))
              "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"))))

;; the one-call entry reproduces the same signature end to end
(let* ((headers (sigv4-sign-headers 'GET "/"
                  '(("Action" . "ListUsers") ("Version" . "2010-05-08"))
                  '(("content-type" . "application/x-www-form-urlencoded; charset=utf-8"))
                  empty-hash
                  `((host . "iam.amazonaws.com")
                    (access-key . "AKIDEXAMPLE") (secret . ,iam-secret)
                    (region . "us-east-1") (service . "iam")
                    (datetime . ,iam-datetime)
                    (content-sha256 . #f))))       ; the IAM example signs no body hash header
       (auth (cdr (assoc "authorization" headers))))
  (check "iam-authorization"
    (equal? auth
      (string-append
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request"
        ", SignedHeaders=content-type;host;x-amz-date"
        ", Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")))
  (check "iam-x-amz-date-added" (equal? (cdr (assoc "x-amz-date" headers)) iam-datetime))
  (check "iam-host-not-sent" (not (assoc "host" headers))))

;; ---- AWS S3 docs: GET Object with Range (examplebucket, 20130524) ---------

(define s3-secret "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
(define s3-datetime "20130524T000000Z")

(let-values (((canonical signed)
              (sigv4-canonical-request "GET" "/test.txt" ""
                `(("host" . "examplebucket.s3.amazonaws.com")
                  ("range" . "bytes=0-9")
                  ("x-amz-content-sha256" . ,empty-hash)
                  ("x-amz-date" . ,s3-datetime))
                empty-hash)))
  (check "s3-signed-headers" (equal? signed "host;range;x-amz-content-sha256;x-amz-date"))
  (check "s3-canonical-hash"
    (equal? (sha256-hex (string->utf8 canonical))
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"))
  (let ((sts (sigv4-string-to-sign s3-datetime "20130524/us-east-1/s3/aws4_request" canonical)))
    (check "s3-signature"
      (equal? (bytevector->hex
                (hmac-sha256 (sigv4-signing-key s3-secret "20130524" "us-east-1" "s3")
                             (string->utf8 sts)))
              "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))))

;; sign-headers with content-sha256 on (the S3 default) matches too
(let* ((headers (sigv4-sign-headers 'GET "/test.txt" '()
                  '(("range" . "bytes=0-9"))
                  empty-hash
                  `((host . "examplebucket.s3.amazonaws.com")
                    (access-key . "AKIAIOSFODNN7EXAMPLE") (secret . ,s3-secret)
                    (region . "us-east-1") (service . "s3")
                    (datetime . ,s3-datetime))))
       (auth (cdr (assoc "authorization" headers))))
  (check "s3-authorization-signature"
    (let ((tail "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))
      (equal? (substring auth (- (string-length auth) (string-length tail))
                         (string-length auth))
              tail)))
  (check "s3-content-sha-added"
    (equal? (cdr (assoc "x-amz-content-sha256" headers)) empty-hash)))

;; header value normalization: trim + collapse inner runs
(let-values (((canonical signed)
              (sigv4-canonical-request "GET" "/" ""
                '(("host" . "h") ("x-test" . "  a   b  ")) empty-hash)))
  (check "header-trim-collapse"
    (let loop ((i 0))
      (cond ((> (+ i 12) (string-length canonical)) #f)
            ((string=? (substring canonical i (+ i 12)) "x-test:a b\n\n") #t)
            (else (loop (+ i 1)))))))

(if (zero? failures)
    (begin (display "sigv4: all tests passed") (newline) (exit 0))
    (begin (display failures) (display " failures") (newline) (exit 1)))
