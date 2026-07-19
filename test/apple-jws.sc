#!chezscheme
;;; (igropyr apple-jws) against a hermetic fixture: a real ES256 JWS whose
;;; x5c is a self-made EC chain (leaf -> intermediate -> root), generated
;;; once with openssl + node's crypto (dsaEncoding ieee-p1363, the raw
;;; R||S JOSE form). Pins the happy path plus the four ways a token must be
;;; rejected: untrusted/unpinned root, tampered signature, tampered
;;; payload, and a non-JWS string.

(import (chezscheme) (igropyr apple-jws) (only (igropyr crypto) base64-decode))

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1)) (display "FAIL  ") (display label) (newline))))

;; run thunk, return the apple-jws-error CODE it raises (or 'no-error)
(define (err-code thunk)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'apple-jws-error))
             (vector-ref e 1)))
    (thunk)
    'no-error))

;; ---- fixture (see the file header) ----
(define JWS
  "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCampDQ0FUT2dBd0lCQWdJVVExYTJvODJSVlpqVkIydXJhT2hIb3dkNFJ4Y3dDZ1lJS29aSXpqMEVBd0l3RnpFVk1CTUdBMVVFQXd3TVZHVnpkQ0JYVjBSU0lFTkJNQjRYRFRJMk1EY3hPVEV6TWpFMU5Gb1hEVEk0TVRBeU1URXpNakUxTkZvd0ZERVNNQkFHQTFVRUF3d0pWR1Z6ZENCTVpXRm1NRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVEcXI3Mk5qajVEVU1UZDk1NVIxV0dzSUJHaDBkRVcxREVuQTVTR1d6TURNaTh2OWhnYzRBNTBQNFBBa0c1S1JMc29TczdBTFY2RVZqZHlVZVhkUXBkS05nTUY0d0RBWURWUjBUQVFIL0JBSXdBREFPQmdOVkhROEJBZjhFQkFNQ0I0QXdIUVlEVlIwT0JCWUVGQm1JaXlrUUtURFprMDR5cEErY3ZGcnJpTm10TUI4R0ExVWRJd1FZTUJhQUZPOVo2S1BpbnBkM3JSNXh0Y256d2MvWWdrS3NNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUURvb0VNQzJtbmZDRmhUdW9Fb2tqdHJzdGh2NXlXUWNqRElyNGROck11TGZBSWhBS2tzUk5tR05JeHVXVUZIYU01eEFIMnpVYUhObnNDTHJXRkh0Z0dMSVdLRyIsIk1JSUJrekNDQVRtZ0F3SUJBZ0lVRWRmbzBXWWdITnhuYUhuRkl6R1p3M0QvRHFnd0NnWUlLb1pJemowRUF3SXdGekVWTUJNR0ExVUVBd3dNVkdWemRDQlNiMjkwSUVjek1CNFhEVEkyTURjeE9URXpNakUxTkZvWERUTXhNRGN4T0RFek1qRTFORm93RnpFVk1CTUdBMVVFQXd3TVZHVnpkQ0JYVjBSU0lFTkJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUUwaWlQOFBIMFNiMzByRk4vWTZMZzhCQzA1cDRHbi9ISmJmcXJJVFNiV1A2RFRkU3VqbXZIVzhGR0hUYnM5NUowZHJHbFY2QzUrRUN2N1pvV3ZaWGMxNk5qTUdFd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBT0JnTlZIUThCQWY4RUJBTUNBUVl3SFFZRFZSME9CQllFRk85WjZLUGlucGQzclI1eHRjbnp3Yy9ZZ2tLc01COEdBMVVkSXdRWU1CYUFGQ3hLTHJtb1VUQnJYKzE4VEhiY01OL2tFc2lyTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSUh2SWNEL2ZDbENnWHByWnJOMENudEhsUHByRjEwZ0JxdE9UYnhQT2hoV1JBaUVBOU9HN21NU09NaUYxUUc1bW9lRGNkOUE2b013SzFsUmNlSy9UalNzcG5RND0iLCJNSUlCa3pDQ0FUbWdBd0lCQWdJVUZObVBoY2hhUjNFenRsMjBHYmpZQkpGREVhQXdDZ1lJS29aSXpqMEVBd0l3RnpFVk1CTUdBMVVFQXd3TVZHVnpkQ0JTYjI5MElFY3pNQjRYRFRJMk1EY3hPVEV6TWpFMU5Gb1hEVE0yTURjeE5qRXpNakUxTkZvd0Z6RVZNQk1HQTFVRUF3d01WR1Z6ZENCU2IyOTBJRWN6TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFblpYYm0wUWt4cDlBdDdvbXVseTIrSFNyWmV3Mzd0bzN4bjRSdnlTRFRDRGVrbGYzUWdVK3FwMEFxcThVSTNRdGl0cXU2NEZDTlFGQjdKVGwxRlNnUjZOak1HRXdIUVlEVlIwT0JCWUVGQ3hLTHJtb1VUQnJYKzE4VEhiY01OL2tFc2lyTUI4R0ExVWRJd1FZTUJhQUZDeEtMcm1vVVRCclgrMThUSGJjTU4va0VzaXJNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lEY21qeS83U2oxazQwMW4rWW5qMHNpWHYwSmNmajlpTjNrRVA4aW5SUjZQQWlFQXBXL29FaGhxOWRJMTlla052NTVaZjJTT3o0TktudHJKVjZ1QkthWVNVU2M9Il19.eyJub3RpZmljYXRpb25UeXBlIjoiVEVTVCIsImRhdGEiOnsieCI6MX19.xEpTknwx6Ya5EVszvyc9Uw7Gu5fkEETfcfkb_3c_8SsW9MwCNgWpUP9lzNfw3x6ffN5XTVW7Gxm-Pb7pQTN1Jw")
(define ROOTB64
  "MIIBkzCCATmgAwIBAgIUFNmPhchaR3Eztl20GbjYBJFDEaAwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMVGVzdCBSb290IEczMB4XDTI2MDcxOTEzMjE1NFoXDTM2MDcxNjEzMjE1NFowFzEVMBMGA1UEAwwMVGVzdCBSb290IEczMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnZXbm0Qkxp9At7omuly2+HSrZew37to3xn4RvySDTCDeklf3QgU+qp0Aqq8UI3Qtitqu64FCNQFB7JTl1FSgR6NjMGEwHQYDVR0OBBYEFCxKLrmoUTBrX+18THbcMN/kEsirMB8GA1UdIwQYMBaAFCxKLrmoUTBrX+18THbcMN/kEsirMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIDcmjy/7Sj1k401n+Ynj0siXv0Jcfj9iN3kEP8inRR6PAiEApW/oEhhq9dI19ekNv55Zf2SOz4NKntrJV6uBKaYSUSc=")
(define PAYLOAD "{\"notificationType\":\"TEST\",\"data\":{\"x\":1}}")
(define test-root-der (base64-decode ROOTB64))

;; happy path: trusting the chain's own root returns the exact payload bytes
(check "verify-ok"
  (equal? PAYLOAD (utf8->string (verify-jws-x5c JWS (list test-root-der)))))

;; the pinned root must actually gate: Apple G3 is not this chain's root
(check "wrong-root-rejected"
  (eq? 'invalid-root (err-code (lambda () (verify-jws-x5c JWS (list apple-root-ca-g3-der))))))
(check "apple-pin-rejects-foreign-chain"
  (eq? 'invalid-root (err-code (lambda () (verify-apple-jws JWS)))))

;; helpers to corrupt one base64url char (A<->B keeps it valid base64url)
(define (flip s i)
  (let ((c (string-ref s i)))
    (string-append (substring s 0 i)
                   (string (if (char=? c #\A) #\B #\A))
                   (substring s (+ i 1) (string-length s)))))
(define (dot1 s) (let loop ((i 0)) (if (char=? (string-ref s i) #\.) i (loop (+ i 1)))))

;; a flipped signature byte -> ES256 verify fails
(check "tampered-signature-rejected"
  (eq? 'sig-failed (err-code (lambda () (verify-jws-x5c (flip JWS (- (string-length JWS) 1))
                                                        (list test-root-der))))))
;; a flipped payload byte changes the signing input -> ES256 verify fails
(check "tampered-payload-rejected"
  (eq? 'sig-failed (err-code (lambda () (verify-jws-x5c (flip JWS (+ (dot1 JWS) 1))
                                                        (list test-root-der))))))
;; not a compact JWS at all
(check "not-a-jws-rejected"
  (eq? 'not-jws (err-code (lambda () (verify-jws-x5c "not-a-jws" (list test-root-der))))))

(if (zero? failures)
    (begin (display "apple-jws: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
