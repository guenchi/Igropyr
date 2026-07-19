#!chezscheme
;;; (igropyr apple-jws) against hermetic fixtures: real ES256 JWSs whose
;;; x5c is a self-made EC chain (leaf -> intermediate -> root), generated
;;; with openssl + node's crypto (dsaEncoding ieee-p1363, the raw R||S JOSE
;;; form). JWS carries Apple's marker OIDs on the leaf/intermediate; the
;;; separate JWS-NO-OID chain omits them. Pins the happy path plus every way
;;; a token must be rejected: unpinned root, missing leaf OID, wrong alg,
;;; tampered signature, tampered payload, non-base64url, and non-JWS.

(import (chezscheme) (igropyr apple-jws)
        (only (igropyr crypto) base64-decode base64-encode))

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

;; ---- fixtures --------------------------------------------------------------
;; JWS: leaf carries 1.2.840.113635.100.6.11.1, intermediate 1.2.840.113635.100.6.2.1
(define JWS
  "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCbnpDQ0FVV2dBd0lCQWdJVWFEUWtZQ1RubkdaTGtwYmJMV21UWFBKSEpOTXdDZ1lJS29aSXpqMEVBd0l3RnpFVk1CTUdBMVVFQXd3TVZHVnpkQ0JYVjBSU0lFTkJNQjRYRFRJMk1EY3hPVEUxTVRVeU4xb1hEVEk0TVRBeU1URTFNVFV5TjFvd0ZERVNNQkFHQTFVRUF3d0pWR1Z6ZENCTVpXRm1NRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVjdnBaTjR0UjUzcFRnNWtEQzdmL3Z3NmliRXR2cU9vMUhCZjdsT1B2aWM2YS9CVkRFQ1E1ZU1GTHBQSllLMWpPSHpvQ3ZjZkNObDJGck1rV0xHN3czNk55TUhBd0RBWURWUjBUQVFIL0JBSXdBREFPQmdOVkhROEJBZjhFQkFNQ0I0QXdFQVlLS29aSWh2ZGpaQVlMQVFRQ0JRQXdIUVlEVlIwT0JCWUVGSEI0YncrV2hqN0svRUJVUzQzZHRyQ001azdRTUI4R0ExVWRJd1FZTUJhQUZBSFl1V05EaXkzRXVyN29vdXJEQU5BbjBUM2RNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUURVZ2NOS25JeVpJUXcwVy9qenV5MVk0RXpMZ1pKdkMwbWt4VHZ6VEtjUVVnSWdYYTh2SVIzdkMveHdMdDlyU3JkYzkzWDNOZ25KUThmMnF6MUl1eklmUUtRPSIsIk1JSUJwVENDQVV1Z0F3SUJBZ0lVVUU1N0QyZVRXbmxndmp0V2JxMlpKSjNYNm1rd0NnWUlLb1pJemowRUF3SXdGekVWTUJNR0ExVUVBd3dNVkdWemRDQlNiMjkwSUVjek1CNFhEVEkyTURjeE9URTFNVFV5TjFvWERUTXhNRGN4T0RFMU1UVXlOMW93RnpFVk1CTUdBMVVFQXd3TVZHVnpkQ0JYVjBSU0lFTkJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUU5ZzVRbnFPKzlZcG02SU1aak1jV3Z6dFptakUzYXVuVGRrQkxiTERtL0xBWDNyZWczTWJ2Zk04RDRzTFlaczV5cmNNZDh3S3c4MWFlcGtZTVl2TS9jNk4xTUhNd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBT0JnTlZIUThCQWY4RUJBTUNBUVl3RUFZS0tvWklodmRqWkFZQ0FRUUNCUUF3SFFZRFZSME9CQllFRkFIWXVXTkRpeTNFdXI3b291ckRBTkFuMFQzZE1COEdBMVVkSXdRWU1CYUFGTUhyeE1xMmdTNEVMSHdrd2JKcFI3c0xzSk1ITUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFDRERMNmRXakUxa2dvbU8vRGI5YUNUMmc4L2lYMHVFbDhNdDVtSlh3Z3l5UUlnYTB3TVpEdHRjcHdJcm5Yc1Yyb0FQZGFwbXgvUGxYQ1c3QWk1MTNNNHhoRT0iLCJNSUlCa2pDQ0FUbWdBd0lCQWdJVVZueTdLY0xucnVVdnl2Qk40V3hhS1Y0bzdiWXdDZ1lJS29aSXpqMEVBd0l3RnpFVk1CTUdBMVVFQXd3TVZHVnpkQ0JTYjI5MElFY3pNQjRYRFRJMk1EY3hPVEUxTVRVeU4xb1hEVE0yTURjeE5qRTFNVFV5TjFvd0Z6RVZNQk1HQTFVRUF3d01WR1Z6ZENCU2IyOTBJRWN6TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFbjlqd1J6V1hIY1lwN1NVYmU4cWJSQVkrYU8zMFJLOEFvMExucmFlZk94TzB2NkZ0eHFmbzhlV0VHZUdheGpBbVlBN1o2bDk2cVpJWllLZmc3aXNlS0tOak1HRXdIUVlEVlIwT0JCWUVGTUhyeE1xMmdTNEVMSHdrd2JKcFI3c0xzSk1ITUI4R0ExVWRJd1FZTUJhQUZNSHJ4TXEyZ1M0RUxId2t3YkpwUjdzTHNKTUhNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTUNBMGNBTUVRQ0lGVHF1QUhncEU5TVVJY1Nmb0VEdlJxZ3ZoUXp3YU83bHI5WkFjRE42VzRmQWlCUG90Z0pRQ3h2bisvb29wY1pzeXFad1pKd1lTMjJXZDYwS1FQOHRhT2ZYQT09Il19.eyJub3RpZmljYXRpb25UeXBlIjoiVEVTVCIsImRhdGEiOnsieCI6MX19.DWNeVClZi9Z3_ICXO9APzJAR2Y7Lyccv9Y8nEMlqcdZCnN8-iRX-YHKskJ6DcUx-YJL0UAd19ZfPwkoqLnuVkA")
(define ROOTB64
  "MIIBkjCCATmgAwIBAgIUVny7KcLnruUvyvBN4WxaKV4o7bYwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMVGVzdCBSb290IEczMB4XDTI2MDcxOTE1MTUyN1oXDTM2MDcxNjE1MTUyN1owFzEVMBMGA1UEAwwMVGVzdCBSb290IEczMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn9jwRzWXHcYp7SUbe8qbRAY+aO30RK8Ao0LnraefOxO0v6Ftxqfo8eWEGeGaxjAmYA7Z6l96qZIZYKfg7iseKKNjMGEwHQYDVR0OBBYEFMHrxMq2gS4ELHwkwbJpR7sLsJMHMB8GA1UdIwQYMBaAFMHrxMq2gS4ELHwkwbJpR7sLsJMHMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0cAMEQCIFTquAHgpE9MUIcSfoEDvRqgvhQzwaO7lr9ZAcDN6W4fAiBPotgJQCxvn+/oopcZsyqZwZJwYS22Wd60KQP8taOfXA==")
;; JWS-NO-OID: a valid chain to ROOTB64-NO-OID, but the leaf/intermediate omit
;; Apple's marker OIDs -- it must pass root+chain+signature yet be rejected.
(define JWS-NO-OID
  "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCampDQ0FUT2dBd0lCQWdJVVExYTJvODJSVlpqVkIydXJhT2hIb3dkNFJ4Y3dDZ1lJS29aSXpqMEVBd0l3RnpFVk1CTUdBMVVFQXd3TVZHVnpkQ0JYVjBSU0lFTkJNQjRYRFRJMk1EY3hPVEV6TWpFMU5Gb1hEVEk0TVRBeU1URXpNakUxTkZvd0ZERVNNQkFHQTFVRUF3d0pWR1Z6ZENCTVpXRm1NRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVEcXI3Mk5qajVEVU1UZDk1NVIxV0dzSUJHaDBkRVcxREVuQTVTR1d6TURNaTh2OWhnYzRBNTBQNFBBa0c1S1JMc29TczdBTFY2RVZqZHlVZVhkUXBkS05nTUY0d0RBWURWUjBUQVFIL0JBSXdBREFPQmdOVkhROEJBZjhFQkFNQ0I0QXdIUVlEVlIwT0JCWUVGQm1JaXlrUUtURFprMDR5cEErY3ZGcnJpTm10TUI4R0ExVWRJd1FZTUJhQUZPOVo2S1BpbnBkM3JSNXh0Y256d2MvWWdrS3NNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUURvb0VNQzJtbmZDRmhUdW9Fb2tqdHJzdGh2NXlXUWNqRElyNGROck11TGZBSWhBS2tzUk5tR05JeHVXVUZIYU01eEFIMnpVYUhObnNDTHJXRkh0Z0dMSVdLRyIsIk1JSUJrekNDQVRtZ0F3SUJBZ0lVRWRmbzBXWWdITnhuYUhuRkl6R1p3M0QvRHFnd0NnWUlLb1pJemowRUF3SXdGekVWTUJNR0ExVUVBd3dNVkdWemRDQlNiMjkwSUVjek1CNFhEVEkyTURjeE9URXpNakUxTkZvWERUTXhNRGN4T0RFek1qRTFORm93RnpFVk1CTUdBMVVFQXd3TVZHVnpkQ0JYVjBSU0lFTkJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUUwaWlQOFBIMFNiMzByRk4vWTZMZzhCQzA1cDRHbi9ISmJmcXJJVFNiV1A2RFRkU3VqbXZIVzhGR0hUYnM5NUowZHJHbFY2QzUrRUN2N1pvV3ZaWGMxNk5qTUdFd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBT0JnTlZIUThCQWY4RUJBTUNBUVl3SFFZRFZSME9CQllFRk85WjZLUGlucGQzclI1eHRjbnp3Yy9ZZ2tLc01COEdBMVVkSXdRWU1CYUFGQ3hLTHJtb1VUQnJYKzE4VEhiY01OL2tFc2lyTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSUh2SWNEL2ZDbENnWHByWnJOMENudEhsUHByRjEwZ0JxdE9UYnhQT2hoV1JBaUVBOU9HN21NU09NaUYxUUc1bW9lRGNkOUE2b013SzFsUmNlSy9UalNzcG5RND0iLCJNSUlCa3pDQ0FUbWdBd0lCQWdJVUZObVBoY2hhUjNFenRsMjBHYmpZQkpGREVhQXdDZ1lJS29aSXpqMEVBd0l3RnpFVk1CTUdBMVVFQXd3TVZHVnpkQ0JTYjI5MElFY3pNQjRYRFRJMk1EY3hPVEV6TWpFMU5Gb1hEVE0yTURjeE5qRXpNakUxTkZvd0Z6RVZNQk1HQTFVRUF3d01WR1Z6ZENCU2IyOTBJRWN6TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFblpYYm0wUWt4cDlBdDdvbXVseTIrSFNyWmV3Mzd0bzN4bjRSdnlTRFRDRGVrbGYzUWdVK3FwMEFxcThVSTNRdGl0cXU2NEZDTlFGQjdKVGwxRlNnUjZOak1HRXdIUVlEVlIwT0JCWUVGQ3hLTHJtb1VUQnJYKzE4VEhiY01OL2tFc2lyTUI4R0ExVWRJd1FZTUJhQUZDeEtMcm1vVVRCclgrMThUSGJjTU4va0VzaXJNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lEY21qeS83U2oxazQwMW4rWW5qMHNpWHYwSmNmajlpTjNrRVA4aW5SUjZQQWlFQXBXL29FaGhxOWRJMTlla052NTVaZjJTT3o0TktudHJKVjZ1QkthWVNVU2M9Il19.eyJub3RpZmljYXRpb25UeXBlIjoiVEVTVCIsImRhdGEiOnsieCI6MX19.xEpTknwx6Ya5EVszvyc9Uw7Gu5fkEETfcfkb_3c_8SsW9MwCNgWpUP9lzNfw3x6ffN5XTVW7Gxm-Pb7pQTN1Jw")
(define ROOTB64-NO-OID
  "MIIBkzCCATmgAwIBAgIUFNmPhchaR3Eztl20GbjYBJFDEaAwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMVGVzdCBSb290IEczMB4XDTI2MDcxOTEzMjE1NFoXDTM2MDcxNjEzMjE1NFowFzEVMBMGA1UEAwwMVGVzdCBSb290IEczMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnZXbm0Qkxp9At7omuly2+HSrZew37to3xn4RvySDTCDeklf3QgU+qp0Aqq8UI3Qtitqu64FCNQFB7JTl1FSgR6NjMGEwHQYDVR0OBBYEFCxKLrmoUTBrX+18THbcMN/kEsirMB8GA1UdIwQYMBaAFCxKLrmoUTBrX+18THbcMN/kEsirMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIDcmjy/7Sj1k401n+Ynj0siXv0Jcfj9iN3kEP8inRR6PAiEApW/oEhhq9dI19ekNv55Zf2SOz4NKntrJV6uBKaYSUSc=")
(define PAYLOAD "{\"notificationType\":\"TEST\",\"data\":{\"x\":1}}")
(define test-root-der (base64-decode ROOTB64))
(define root-no-oid-der (base64-decode ROOTB64-NO-OID))

;; happy path: trusting the chain's own root returns the exact payload bytes
(check "verify-ok"
  (equal? PAYLOAD (utf8->string (verify-jws-x5c JWS (list test-root-der)))))

;; the pinned root must actually gate: Apple G3 is not this chain's root
(check "wrong-root-rejected"
  (eq? 'invalid-root (err-code (lambda () (verify-jws-x5c JWS (list apple-root-ca-g3-der))))))
(check "apple-pin-rejects-foreign-chain"
  (eq? 'invalid-root (err-code (lambda () (verify-apple-jws JWS)))))

;; a chain that is valid + correctly rooted but whose leaf lacks Apple's
;; App Store Server signing OID must still be rejected (defense in depth:
;; "chains to the root" is not "is the notification signer")
(check "leaf-oid-required"
  (eq? 'chain-failed (err-code (lambda () (verify-jws-x5c JWS-NO-OID (list root-no-oid-der))))))

;; the alg is never trusted to select the algorithm: a header claiming
;; anything but ES256 is refused before any crypto
(define (b64url-of str)
  (let* ((std (base64-encode (string->utf8 str))) (n (string-length std)))
    (let loop ((i 0) (acc '()))
      (if (= i n)
          (list->string (reverse acc))
          (let ((c (string-ref std i)))
            (loop (+ i 1)
                  (cond ((char=? c #\+) (cons #\- acc))
                        ((char=? c #\/) (cons #\_ acc))
                        ((char=? c #\=) acc)
                        (else (cons c acc)))))))))
(check "alg-none-rejected"
  (eq? 'bad-alg
    (err-code (lambda ()
      (verify-jws-x5c (string-append (b64url-of "{\"alg\":\"none\"}") ".e30.AA")
                      (list test-root-der))))))

;; helpers to corrupt one base64url char (A<->B keeps it valid base64url)
(define (flip s i)
  (let ((c (string-ref s i)))
    (string-append (substring s 0 i)
                   (string (if (char=? c #\A) #\B #\A))
                   (substring s (+ i 1) (string-length s)))))
(define (dot1 s) (let loop ((i 0)) (if (char=? (string-ref s i) #\.) i (loop (+ i 1)))))

;; a flipped signature byte -> ES256 verify fails. Flip a full-6-bit char
;; well inside the signature, not the final char (which only carries 2
;; significant bits, so A<->B would decode to the same bytes).
(check "tampered-signature-rejected"
  (eq? 'sig-failed (err-code (lambda () (verify-jws-x5c (flip JWS (- (string-length JWS) 10))
                                                        (list test-root-der))))))
;; a flipped payload byte changes the signing input -> ES256 verify fails
(check "tampered-payload-rejected"
  (eq? 'sig-failed (err-code (lambda () (verify-jws-x5c (flip JWS (+ (dot1 JWS) 1))
                                                        (list test-root-der))))))
;; a non-base64url character is refused, not silently normalised away
(check "non-base64url-rejected"
  (eq? 'not-jws (err-code (lambda () (verify-jws-x5c (string-append "!" JWS)
                                                     (list test-root-der))))))
;; not a compact JWS at all
(check "not-a-jws-rejected"
  (eq? 'not-jws (err-code (lambda () (verify-jws-x5c "not-a-jws" (list test-root-der))))))

(if (zero? failures)
    (begin (display "apple-jws: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
