#!chezscheme
;;; (igropyr s3) end to end against a hermetic in-process fake S3: the
;;; wire shape (signed headers, payload hash, copy-source, explicit
;;; zero content-length on bodyless PUT), the soft error contracts
;;; (404 -> #f / idempotent delete), and ListObjectsV2 pagination with
;;; XML entity unescaping. Signature CORRECTNESS is pinned by the AWS
;;; vectors in test/sigv4.sc; this file pins the HTTP integration.

(import (chezscheme) (igropyr http) (igropyr express) (igropyr client)
        (igropyr crypto) (igropyr s3))

(define port 18095)
(define empty-bv (make-bytevector 0))

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

;; server-side assertions: recorded here, asserted at the end
(define server-fails (box '()))
(define (sfail! label) (set-box! server-fails (cons label (unbox server-fails))))

(define (s3-error-status thunk)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 's3-error))
             (vector-ref e 1)))
    (thunk)
    'no-error))

;; ---- the fake S3 -----------------------------------------------------------

(define app (create-app))

(define put-body-sha (box #f))

(app-put app "/iter/audio/L1_en.wav"
  (lambda (req res)
    (let ((auth (req-header req 'authorization))
          (sha (req-header req 'x-amz-content-sha256))
          (body (req-body req)))
      (unless (and auth
                   (let ((p "AWS4-HMAC-SHA256 Credential=AKtest/"))
                     (and (> (string-length auth) (string-length p))
                          (string=? (substring auth 0 (string-length p)) p))))
        (sfail! 'put-authorization))
      ;; the signed payload hash must match the bytes that actually arrived
      (unless (and sha (equal? sha (bytevector->hex (sha256 body))))
        (sfail! 'put-payload-hash))
      (unless (equal? (req-header req 'content-type) "audio/wav")
        (sfail! 'put-content-type))
      ;; non-default port: Host must carry it (it is signed, so client
      ;; and sigv4 must agree byte for byte)
      (unless (equal? (req-header req 'host)
                      (string-append "127.0.0.1:" (number->string port)))
        (sfail! 'put-host-port))
      (set-box! put-body-sha sha)
      (set-header! res "ETag" "\"etag-123\"")
      (res-send! res empty-bv))))

(app-get app "/iter/audio/L1_en.wav"
  (lambda (req res) (send-text! res "hello-wav")))

(app-get app "/iter/missing.wav"
  (lambda (req res) (set-status! res 404) (send-text! res "no")))

(app-delete app "/iter/audio/L1_en.wav"
  (lambda (req res) (set-status! res 204) (res-send! res empty-bv)))

(app-delete app "/iter/ghost.wav"
  (lambda (req res) (set-status! res 404) (send-text! res "no")))

(app-put app "/iter/items/x/L1_en.wav"
  (lambda (req res)
    (unless (equal? (req-header req 'x-amz-copy-source) "/iter/sandbox/s1/L1_en.wav")
      (sfail! 'copy-source-header))
    ;; bodyless PUT must carry an explicit (signed) zero content-length
    (unless (equal? (req-header req 'content-length) "0")
      (sfail! 'copy-content-length))
    (send-text! res "<CopyObjectResult/>")))

(define list-calls (box 0))

(app-get app "/iter"
  (lambda (req res)
    (let ((q (req-query req)))
      (unless (equal? (cdr (assoc "list-type" q)) "2") (sfail! 'list-type))
      (unless (equal? (cdr (assoc "prefix" q)) "sandbox/s1/") (sfail! 'list-prefix))
      (set-box! list-calls (+ 1 (unbox list-calls)))
      (set-header! res "Content-Type" "application/xml")
      (if (assoc "continuation-token" q)
          (begin
            (unless (equal? (cdr (assoc "continuation-token" q)) "tok-1")
              (sfail! 'list-token))
            (send-text! res
              (string-append
                "<?xml version=\"1.0\"?><ListBucketResult>"
                "<IsTruncated>false</IsTruncated>"
                "<Contents><Key>sandbox/s1/L3_en.wav</Key></Contents>"
                "</ListBucketResult>")))
          (send-text! res
            (string-append
              "<?xml version=\"1.0\"?><ListBucketResult>"
              "<IsTruncated>true</IsTruncated>"
              "<Contents><Key>sandbox/s1/L1_en.wav</Key></Contents>"
              "<Contents><Key>sandbox/s1/a&amp;b.wav</Key></Contents>"
              "<NextContinuationToken>tok-1</NextContinuationToken>"
              "</ListBucketResult>"))))))

;; ---- tests -----------------------------------------------------------------

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (sleep-ms 100)

    (let ((s (make-s3 `((endpoint . ,(string-append "http://127.0.0.1:"
                                                    (number->string port)))
                        (bucket . "iter")
                        (access-key . "AKtest")
                        (secret . "SecretTest")))))

      ;; put: etag round-trips, server saw matching payload hash
      (let ((etag (s3-put! s "audio/L1_en.wav" (string->utf8 "wav-bytes") "audio/wav")))
        (check "put-etag" (equal? etag "etag-123"))
        (check "put-sha-recorded"
          (equal? (unbox put-body-sha)
                  (bytevector->hex (sha256 (string->utf8 "wav-bytes"))))))

      ;; get: body back; 404 -> #f
      (check "get-body" (equal? (utf8->string (s3-get s "audio/L1_en.wav")) "hello-wav"))
      (check "get-404-is-false" (eq? (s3-get s "missing.wav") #f))

      ;; copy: server checks x-amz-copy-source + explicit zero length
      (check "copy-ok" (eq? (s3-copy! s "sandbox/s1/L1_en.wav" "items/x/L1_en.wav") #t))

      ;; delete: 204 and 404 both succeed (idempotent GC)
      (check "delete-ok" (eq? (s3-delete! s "audio/L1_en.wav") #t))
      (check "delete-404-ok" (eq? (s3-delete! s "ghost.wav") #t))

      ;; list: paginates through the continuation token, unescapes entities
      (let ((keys (s3-list s "sandbox/s1/")))
        (check "list-keys"
          (equal? keys '("sandbox/s1/L1_en.wav" "sandbox/s1/a&b.wav" "sandbox/s1/L3_en.wav")))
        (check "list-two-pages" (= (unbox list-calls) 2)))

      ;; a path in the endpoint would silently break signing: rejected
      (check "endpoint-path-rejected"
        (guard (e ((assertion-violation? e) #t) (#t #f))
          (make-s3 '((endpoint . "http://127.0.0.1:9000/minio") (bucket . "b")
                     (access-key . "a") (secret . "s")))
          #f))

      ;; unknown bucket path -> typed s3-error with the status
      (check "error-typed"
        (= 404 (s3-error-status (lambda () (s3-put! s "nope/void.bin" (string->utf8 "x")
                                                    "application/octet-stream")))))

      (check "server-side" (null? (unbox server-fails)))
      (unless (null? (unbox server-fails))
        (display "server-side failures: ") (write (unbox server-fails)) (newline)))

    (if (zero? failures)
        (begin (display "s3: all tests passed") (newline) (exit 0))
        (begin (display failures) (display " failures") (newline) (exit 1)))))
