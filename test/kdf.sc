#!chezscheme
;;; (igropyr kdf): the libcrypto-backed KDFs against official vectors
;;; (PBKDF2-HMAC-SHA256; scrypt RFC 7914) and the self-describing
;;; password-hash / password-verify (roundtrip, wrong / tamper / malformed,
;;; cross-algorithm dispatch), plus a perf probe at the production scrypt
;;; cost so the choice is measured, not guessed.

(import (chezscheme) (igropyr kdf) (only (igropyr crypto) bytevector->hex))

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1)) (display "FAIL  ") (display label) (newline))))

(define (u s) (string->utf8 s))

;; ---- PBKDF2-HMAC-SHA256 (RFC 6070 inputs, SHA-256 outputs) ----
(check "pbkdf2-c1"
  (string=? (bytevector->hex (kdf-pbkdf2-sha256 (u "password") (u "salt") 1 32))
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"))
(check "pbkdf2-c4096"
  (string=? (bytevector->hex (kdf-pbkdf2-sha256 (u "password") (u "salt") 4096 32))
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"))

;; ---- scrypt (RFC 7914) ----
(define (scrypt-hex pw salt N r p) (bytevector->hex (kdf-scrypt (u pw) (u salt) N r p 64)))
(check "scrypt-rfc-1"      ; N=16 r=1 p=1, empty password + salt
  (string=? (scrypt-hex "" "" 16 1 1)
    "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"))
(check "scrypt-rfc-2"      ; N=1024 r=8 p=16
  (string=? (scrypt-hex "password" "NaCl" 1024 8 16)
    "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"))
(check "scrypt-rfc-3"      ; N=16384 r=8 p=1
  (string=? (scrypt-hex "pleaseletmein" "SodiumChloride" 16384 8 1)
    "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"))

;; ---- argon2id (vector from `openssl kdf ... ARGON2ID`, i.e. this libcrypto) ----
(check "argon2id-vector"    ; t=2 m=64 p=1
  (string=? (bytevector->hex (kdf-argon2id (u "password") (u "0123456789abcdef") 2 64 1 32))
            "fb83b5711fd91df630b63677dee62ccd13ee6f0c4897d856b49542b9b1e9975b"))

;; ---- self-describing password hashes ----
;; scrypt roundtrip (small N for test speed; the format is cost-agnostic)
(let ((s (password-hash "hunter2" 'scrypt '((N . 1024)))))
  (check "scrypt-format"     (string=? (substring s 0 7) "scrypt$"))
  (check "scrypt-roundtrip"  (password-verify "hunter2" s))
  (check "scrypt-wrong"      (not (password-verify "wrong" s)))
  (check "scrypt-tampered"   (not (password-verify "hunter2" (string-append s "x")))))
;; pbkdf2 roundtrip
(let ((s (password-hash "hunter2" 'pbkdf2 '((iterations . 4096)))))
  (check "pbkdf2-format"     (string=? (substring s 0 14) "pbkdf2-sha256$"))
  (check "pbkdf2-roundtrip"  (password-verify "hunter2" s))
  (check "pbkdf2-wrong"      (not (password-verify "wrong" s))))
;; argon2id roundtrip (small m for test speed)
(let ((s (password-hash "hunter2" 'argon2id '((t . 1) (m . 8) (p . 1)))))
  (check "argon2id-format"    (string=? (substring s 0 9) "argon2id$"))
  (check "argon2id-roundtrip" (password-verify "hunter2" s))
  (check "argon2id-wrong"     (not (password-verify "wrong" s)))
  (check "argon2id-tampered"  (not (password-verify "hunter2" (string-append s "x")))))
;; ONE verify dispatches on the prefix -> an app can migrate algorithms
(check "cross-dispatch"
  (and (password-verify "a" (password-hash "a" 'scrypt '((N . 1024))))
       (password-verify "b" (password-hash "b" 'pbkdf2 '((iterations . 4096))))
       (password-verify "c" (password-hash "c" 'argon2id '((t . 1) (m . 8) (p . 1))))))
;; malformed / crafted -> #f, never a crash and never "matches anything"
(check "malformed-empty-dk-scrypt" (not (password-verify "x" "scrypt$1024$8$1$@@@$@@@")))
(check "malformed-empty-dk-pbkdf2" (not (password-verify "x" "pbkdf2-sha256$4096$@@@$@@@")))
(check "malformed-empty-dk-argon2" (not (password-verify "x" "argon2id$2$8$1$@@@$@@@")))
(check "malformed-unknown-algo"    (not (password-verify "x" "md5$abc$def")))
(check "malformed-junk"            (not (password-verify "x" "not-a-hash")))

;; ---- perf probe: scrypt at the production default (N=32768) ----
(let* ((t0 (real-time)) (_ (password-hash "measure" 'scrypt '())) (ms (- (real-time) t0)))
  (display "  [perf] scrypt N=32768 = ") (display ms)
  (display " ms/hash (vs ~790 ms pure-Scheme pbkdf2)\n"))
(let* ((t0 (real-time)) (_ (password-hash "measure" 'argon2id '())) (ms (- (real-time) t0)))
  (display "  [perf] argon2id m=19456,t=2 = ") (display ms) (display " ms/hash\n"))

(if (zero? failures)
    (begin (display "kdf: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
