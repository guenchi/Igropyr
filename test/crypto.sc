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

(define (rep byte n)
  (let ((bv (make-bytevector n)))
    (do ((i 0 (+ i 1))) ((= i n) bv) (bytevector-u8-set! bv i byte))))

;; ---- RFC 4231: the exported HMAC-SHA256 primitive ------------------------
;;
;; THE PBKDF2 VECTORS DO NOT ANCHOR THIS. pbkdf2-hmac-sha256 builds its own
;; ipad/opad and inlines the PRF -- deliberately, so the key schedule is not
;; rebuilt on every one of hundreds of thousands of iterations -- so it never
;; calls the procedure below. Measured before these cases existed: changing
;; hmac-sha256's block size from 64 to 128, which breaks it completely, left
;; the whole suite green. "PBKDF2 is HMAC-SHA256 underneath" is a statement
;; about the algorithm, not about this code path, and a transitive anchor
;; that does not pass through the code is not an anchor.
;;
;; The exported one is what webhook signature checks and other callers use,
;; so it gets its own known answers. Constants transcribed from RFC 4231 and
;; cross-checked against an independent implementation before being written
;; down, so a typo here cannot quietly become the expected value.
(define (hm key msg) (bytevector->hex (hmac-sha256 key msg)))

(check "rfc4231-1 short key" (hm (rep #x0b 20) (string->utf8 "Hi There"))
  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
(check "rfc4231-2 key shorter than block"
  (hm (string->utf8 "Jefe") (string->utf8 "what do ya want for nothing?"))
  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
(check "rfc4231-3 50-byte message" (hm (rep #xaa 20) (rep #xdd 50))
  "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
(check "rfc4231-4 non-repeating key"
  (hm (let ((k (make-bytevector 25)))
        (do ((i 0 (+ i 1))) ((= i 25) k) (bytevector-u8-set! k i (+ i 1))))
      (rep #xcd 50))
  "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
;; 131 bytes: LONGER THAN THE BLOCK, so the key must be hashed first -- the
;; branch a wrong block size gets wrong, and the one PBKDF2 never exercises
;; because its key schedule is built once from a password it never rehashes
(check "rfc4231-6 key longer than block"
  (hm (rep #xaa 131)
      (string->utf8 "Test Using Larger Than Block-Size Key - Hash Key First"))
  "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
(check "rfc4231-7 long key and long message"
  (hm (rep #xaa 131)
      (string->utf8 (string-append
        "This is a test using a larger than block-size key and a larger "
        "than block-size data. The key needs to be hashed before being "
        "used by the HMAC algorithm.")))
  "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")

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
