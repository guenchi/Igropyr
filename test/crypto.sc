#!chezscheme
;;; (igropyr crypto) PBKDF2-HMAC-SHA256 against the published test vectors
;;; (RFC 6070's PBKDF2 inputs, with the SHA-256 outputs used across Go's
;;; x/crypto, Python, etc). Pins iteration folding, multi-block output and
;;; truncation to a non-block-multiple length.

(import (chezscheme) (igropyr crypto))

(define failures 0)
(define (check label got want)
  (if (string=? got want)
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline)
             (display "    got  ") (display got) (newline)
             (display "    want ") (display want) (newline))))

(define (pb pw salt c dklen)
  (bytevector->hex
    (pbkdf2-hmac-sha256 (string->utf8 pw) (string->utf8 salt) c dklen)))

(check "c=1" (pb "password" "salt" 1 32)
  "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
(check "c=2" (pb "password" "salt" 2 32)
  "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
(check "c=4096" (pb "password" "salt" 4096 32)
  "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
;; two output blocks truncated to 40 bytes (dk-len not a multiple of 32)
(check "long-dk40"
  (pb "passwordPASSWORDpassword" "saltSALTsaltSALTsaltSALTsaltSALTsalt" 4096 40)
  "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")

;; iterations <= 0 (a config default or off-by-one) must fail loudly rather
;; than silently fold to a single-round key; dk-len must be nonnegative.
(define (rejects? thunk)
  (guard (e ((assertion-violation? e) #t) (#t #f)) (thunk) #f))
(define (check-reject label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))
(check-reject "iters=0-rejected"
  (rejects? (lambda () (pbkdf2-hmac-sha256 (string->utf8 "pw") (string->utf8 "salt") 0 32))))
(check-reject "iters=-1-rejected"
  (rejects? (lambda () (pbkdf2-hmac-sha256 (string->utf8 "pw") (string->utf8 "salt") -1 32))))
(check-reject "neg-dklen-rejected"
  (rejects? (lambda () (pbkdf2-hmac-sha256 (string->utf8 "pw") (string->utf8 "salt") 1 -1))))

;; ---- base64url (RFC 4648 section 5) -------------------------------------
;; The JOSE alphabet, shared by jwt and the JWKS/RS256 paths. What matters
;; beyond round-tripping is the STRICTNESS: base64-decode skips characters
;; outside the alphabet, so a lax base64url would let a token segment carry
;; whitespace or padding and still verify.

;; RFC 4648 section 10 vectors, url alphabet with padding removed
(check "b64url-empty"  (base64url-encode (string->utf8 "")) "")
(check "b64url-f"      (base64url-encode (string->utf8 "f")) "Zg")
(check "b64url-fo"     (base64url-encode (string->utf8 "fo")) "Zm8")
(check "b64url-foo"    (base64url-encode (string->utf8 "foo")) "Zm9v")
(check "b64url-foobar" (base64url-encode (string->utf8 "foobar")) "Zm9vYmFy")

;; the two substituted characters: 0xFB 0xFF encodes to "+/" in standard
;; base64, so this is what separates the alphabets
(check "b64url-alphabet"
  (base64url-encode (bytevector #xfb #xff)) "-_8")
(check "b64url-roundtrip-alphabet"
  (utf8->string (base64url-decode "Zm9vYmFy")) "foobar")
(check "b64url-decode-substituted"
  (bytevector->hex (base64url-decode "-_8")) "fbff")

;; every byte value survives a round trip
(check "b64url-roundtrip-all-bytes"
  (bytevector->hex
    (base64url-decode
      (base64url-encode (let ((bv (make-bytevector 256)))
                          (do ((i 0 (+ i 1))) ((= i 256) bv)
                            (bytevector-u8-set! bv i i))))))
  (bytevector->hex (let ((bv (make-bytevector 256)))
                     (do ((i 0 (+ i 1))) ((= i 256) bv)
                       (bytevector-u8-set! bv i i)))))

;; strictness: each of these decodes FINE under a lax decoder that merely
;; skips what it does not recognise, which is exactly the bug being pinned
(check-reject "b64url-rejects-padding"
  (rejects? (lambda () (base64url-decode "Zm9v="))))
(check-reject "b64url-rejects-standard-alphabet"
  (rejects? (lambda () (base64url-decode "-/8"))))
(check-reject "b64url-rejects-whitespace"
  (rejects? (lambda () (base64url-decode "Zm 9v"))))
(check-reject "b64url-rejects-newline"
  (rejects? (lambda () (base64url-decode "Zm9v\n"))))
;; one base64url character leaves an impossible dangling six-bit group
(check-reject "b64url-rejects-length-1"
  (rejects? (lambda () (base64url-decode "A"))))
(check-reject "b64url-rejects-length-5"
  (rejects? (lambda () (base64url-decode "AAAAA"))))
;; non-canonical tail: "Zh" has unused bits set in the final character
(check-reject "b64url-rejects-non-canonical-tail"
  (rejects? (lambda () (base64url-decode "Zh"))))

(if (zero? failures)
    (begin (display "crypto: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
