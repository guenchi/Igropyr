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

(if (zero? failures)
    (begin (display "crypto: all pbkdf2 tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
