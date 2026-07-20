#!chezscheme
;;; (igropyr kdf) -- password-hashing KDFs over the already-loaded libcrypto
;;; (the same OpenSSL that (igropyr tls) / (igropyr apple-jws) use), offered
;;; as infrastructure so an app can CHOOSE its algorithm -- and migrate
;;; between them without a flag day. Two layers:
;;;
;;;   raw derivations (bytevector -> bytevector; you pick the cost params):
;;;     (kdf-pbkdf2-sha256 pw salt iterations dk-len)   ; PKCS5_PBKDF2_HMAC
;;;     (kdf-scrypt        pw salt N r p dk-len)        ; EVP_PBE_scrypt
;;;
;;;   self-describing password hashes -- the algorithm + params live in the
;;;   string, so verify dispatches and an app can rehash-on-login to a
;;;   stronger algorithm transparently:
;;;     (password-hash "pw" 'scrypt '())    ; -> "scrypt$32768$8$1$<salt>$<dk>"
;;;     (password-hash "pw" 'pbkdf2 '())    ; -> "pbkdf2-sha256$600000$<salt>$<dk>"
;;;     (password-verify "pw" stored)       ; -> #t | #f (constant time)
;;;
;;; This is the FAST path; (igropyr crypto) keeps a pure-Scheme
;;; pbkdf2-hmac-sha256 for environments without libcrypto. scrypt is
;;; memory-hard -- meaningfully harder to crack on GPU/ASIC than PBKDF2 --
;;; which is why it is the sensible default; argon2id joins this module next.

(library (igropyr kdf)
  (export kdf-pbkdf2-sha256 kdf-scrypt kdf-argon2id
          password-hash password-verify)
  (import (chezscheme) (igropyr platform)
          (only (igropyr crypto) base64-encode base64-decode))

  ;; ---- libcrypto (loaded explicitly, like (igropyr tls)) ---------------
  (define brew-arm "/opt/homebrew/opt/openssl@3/lib/")
  (define brew-x86 "/usr/local/opt/openssl@3/lib/")
  (define (candidates base)
    (case platform-os
      ((macos) (list (string-append brew-arm base ".3.dylib")
                     (string-append brew-x86 base ".3.dylib")
                     (string-append base ".3.dylib")
                     (string-append base ".dylib")))
      (else    (list (string-append base ".so.3")
                     (string-append base ".so.1.1")
                     (string-append base ".so")))))
  (define _libcrypto
    (load-first-shared-object! 'igropyr-kdf (candidates "libcrypto")))

  ;; ---- FFI -------------------------------------------------------------
  (define _EVP_sha256 (foreign-procedure "EVP_sha256" () void*))
  (define _PKCS5_PBKDF2_HMAC
    (foreign-procedure "PKCS5_PBKDF2_HMAC" (u8* int u8* int int void* int u8*) int))
  (define _EVP_PBE_scrypt
    (foreign-procedure "EVP_PBE_scrypt"
      (u8* size_t u8* size_t unsigned-64 unsigned-64 unsigned-64 unsigned-64 u8* size_t)
      int))
  ;; argon2id has no single-shot function -- it goes through the generic
  ;; EVP_KDF interface with an OSSL_PARAM array (built in C memory below).
  (define _EVP_KDF_fetch    (foreign-procedure "EVP_KDF_fetch" (void* string void*) void*))
  (define _EVP_KDF_CTX_new  (foreign-procedure "EVP_KDF_CTX_new" (void*) void*))
  (define _EVP_KDF_CTX_free (foreign-procedure "EVP_KDF_CTX_free" (void*) void))
  (define _EVP_KDF_free     (foreign-procedure "EVP_KDF_free" (void*) void))
  (define _EVP_KDF_derive
    (foreign-procedure "EVP_KDF_derive" (void* u8* size_t void*) int))

  ;; memory ceiling for scrypt: caps a chosen (or crafted) N so a huge one
  ;; is rejected by libcrypto (return 0) rather than attempting the alloc.
  ;; The sane default (N=32768, r=8 -> 32 MiB working set) fits comfortably.
  (define scrypt-maxmem (* 256 1024 1024))

  ;; ---- raw derivations -------------------------------------------------
  (define (kdf-pbkdf2-sha256 password salt iterations dk-len)
    (unless (and (fixnum? iterations) (fx>= iterations 1))
      (assertion-violation 'kdf-pbkdf2-sha256 "iterations must be >= 1" iterations))
    (let ((out (make-bytevector dk-len)))
      (if (fx= 1 (_PKCS5_PBKDF2_HMAC password (bytevector-length password)
                                     salt (bytevector-length salt)
                                     iterations (_EVP_sha256) dk-len out))
          out
          (error 'kdf-pbkdf2-sha256 "PKCS5_PBKDF2_HMAC failed"))))

  ;; N must be a power of two > 1; r, p >= 1. 128*N*r bytes is the working
  ;; set (bounded by scrypt-maxmem).
  (define (kdf-scrypt password salt N r p dk-len)
    (let ((out (make-bytevector dk-len)))
      (if (fx= 1 (_EVP_PBE_scrypt password (bytevector-length password)
                                  salt (bytevector-length salt)
                                  N r p scrypt-maxmem out dk-len))
          out
          (error 'kdf-scrypt "EVP_PBE_scrypt failed (bad N/r/p or over memory cap)"))))

  ;; ---- argon2id via EVP_KDF --------------------------------------------
  ;; The OSSL_PARAM array is assembled in foreign (C) memory: the key
  ;; strings, the pass/salt copies and the uint cells all live outside the
  ;; Scheme heap, so nothing the array points at can move between building
  ;; it and EVP_KDF_derive.
  (define param-size 40)     ; sizeof(OSSL_PARAM) on LP64
  (define type-uint 2)       ; OSSL_PARAM_UNSIGNED_INTEGER
  (define type-octet 5)      ; OSSL_PARAM_OCTET_STRING

  (define (cstr s)           ; persistent NUL-terminated C string (module-lifetime)
    (let* ((bv (string->utf8 s)) (n (bytevector-length bv)) (p (foreign-alloc (+ n 1))))
      (do ((i 0 (+ i 1))) ((= i n)) (foreign-set! 'unsigned-8 p i (bytevector-u8-ref bv i)))
      (foreign-set! 'unsigned-8 p n 0)
      p))
  (define k-pass (cstr "pass"))
  (define k-salt (cstr "salt"))
  (define k-iter (cstr "iter"))
  (define k-memcost (cstr "memcost"))
  (define k-lanes (cstr "lanes"))

  (define (c-bytes bv)       ; copy bv into fresh C memory -> address
    (let* ((n (bytevector-length bv)) (p (foreign-alloc (max 1 n))))
      (do ((i 0 (+ i 1))) ((= i n)) (foreign-set! 'unsigned-8 p i (bytevector-u8-ref bv i)))
      p))
  (define (c-uint v) (let ((p (foreign-alloc 4))) (foreign-set! 'unsigned-32 p 0 v) p))

  (define (set-param! arr idx key type data data-size)
    (let ((o (* idx param-size)))
      (foreign-set! 'void* arr (+ o 0) key)
      (foreign-set! 'unsigned-32 arr (+ o 8) type)
      (foreign-set! 'void* arr (+ o 16) data)
      (foreign-set! 'unsigned-64 arr (+ o 24) data-size)
      (foreign-set! 'unsigned-64 arr (+ o 32) 0)))

  ;; t = time cost (passes), m = memory in KiB, p = lanes (parallelism)
  (define (kdf-argon2id password salt t m p dk-len)
    (let ((kdf (_EVP_KDF_fetch 0 "ARGON2ID" 0)))
      (when (zero? kdf) (error 'kdf-argon2id "ARGON2ID unavailable (need OpenSSL 3.2+)"))
      (let ((ctx (_EVP_KDF_CTX_new kdf)))
        (_EVP_KDF_free kdf)
        (when (zero? ctx) (error 'kdf-argon2id "EVP_KDF_CTX_new failed"))
        (let ((pass-p (c-bytes password)) (salt-p (c-bytes salt))
              (iter-c (c-uint t)) (mem-c (c-uint m)) (lanes-c (c-uint p))
              (params (foreign-alloc (* 6 param-size)))
              (out (make-bytevector dk-len)))
          (do ((i 0 (+ i 1))) ((= i (* 6 param-size))) (foreign-set! 'unsigned-8 params i 0))
          (set-param! params 0 k-pass    type-octet pass-p (bytevector-length password))
          (set-param! params 1 k-salt    type-octet salt-p (bytevector-length salt))
          (set-param! params 2 k-iter    type-uint  iter-c 4)
          (set-param! params 3 k-memcost type-uint  mem-c  4)
          (set-param! params 4 k-lanes   type-uint  lanes-c 4)
          ;; entry 5 stays zeroed == OSSL_PARAM_END
          (let ((rc (_EVP_KDF_derive ctx out dk-len params)))
            (foreign-free pass-p) (foreign-free salt-p)
            (foreign-free iter-c) (foreign-free mem-c) (foreign-free lanes-c)
            (foreign-free params)
            (_EVP_KDF_CTX_free ctx)
            (if (fx= rc 1)
                out
                (error 'kdf-argon2id "EVP_KDF_derive failed (bad params or over memory)")))))))

  ;; ---- self-describing password hashing --------------------------------
  (define salt-len 16)
  (define dk-len 32)

  (define (random-bytes n)
    (call-with-port (open-file-input-port "/dev/urandom")
      (lambda (p)
        (let ((bv (get-bytevector-n p n)))
          (if (and (bytevector? bv) (= (bytevector-length bv) n))
              bv
              (error 'random-bytes "short read from /dev/urandom"))))))

  ;; constant-time equality (fixed-width DKs); no early exit
  (define (ct=? a b)
    (and (= (bytevector-length a) (bytevector-length b))
         (let loop ((i 0) (diff 0))
           (if (= i (bytevector-length a))
               (fx= diff 0)
               (loop (+ i 1)
                     (fxior diff (fxxor (bytevector-u8-ref a i)
                                        (bytevector-u8-ref b i))))))))

  (define (split-dollar s)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n) (reverse (cons (substring s start i) acc)))
          ((char=? (string-ref s i) #\$)
           (loop (+ i 1) (+ i 1) (cons (substring s start i) acc)))
          (else (loop (+ i 1) start acc))))))

  (define (b64 s) (guard (e (#t #f)) (base64-decode s)))
  (define (opt alist key default)
    (let ((p (and (pair? alist) (assq key alist)))) (if p (cdr p) default)))

  ;; algo: 'scrypt | 'pbkdf2 ; params: ((N . _)(r . _)(p . _)) for scrypt or
  ;; ((iterations . _)) for pbkdf2 -- sane defaults otherwise.
  (define (password-hash password algo params)
    (let ((salt (random-bytes salt-len))
          (pw (string->utf8 password)))
      (case algo
        ((scrypt)
         (let ((N (opt params 'N 32768)) (r (opt params 'r 8)) (p (opt params 'p 1)))
           (string-append "scrypt$" (number->string N) "$" (number->string r)
                          "$" (number->string p) "$" (base64-encode salt) "$"
                          (base64-encode (kdf-scrypt pw salt N r p dk-len)))))
        ((pbkdf2)
         (let ((iters (opt params 'iterations 600000)))
           (string-append "pbkdf2-sha256$" (number->string iters) "$"
                          (base64-encode salt) "$"
                          (base64-encode (kdf-pbkdf2-sha256 pw salt iters dk-len)))))
        ((argon2id)
         ;; defaults follow OWASP's minimum: m=19 MiB, t=2, p=1
         (let ((t (opt params 't 2)) (m (opt params 'm 19456)) (p (opt params 'p 1)))
           (string-append "argon2id$" (number->string t) "$" (number->string m)
                          "$" (number->string p) "$" (base64-encode salt) "$"
                          (base64-encode (kdf-argon2id pw salt t m p dk-len)))))
        (else (assertion-violation 'password-hash "unknown algo" algo)))))

  ;; verify dispatches on the algorithm prefix. A full-width DK is required
  ;; (base64-decode is lenient about invalid characters, so a crafted
  ;; "$@@@$@@@" would otherwise decode to an empty DK and match any
  ;; password), and cost params are sanity-capped so a crafted hash cannot
  ;; turn verify into a CPU/memory bomb.
  (define (password-verify password stored)
    (let ((parts (and (string? stored) (split-dollar stored))))
      (and (pair? parts)
           (let ((pw (string->utf8 password)))
             (cond
               ((and (string=? (car parts) "scrypt") (= (length parts) 6))
                (let ((N (string->number (list-ref parts 1)))
                      (r (string->number (list-ref parts 2)))
                      (p (string->number (list-ref parts 3)))
                      (salt (b64 (list-ref parts 4)))
                      (dk (b64 (list-ref parts 5))))
                  (and N r p (integer? N) (integer? r) (integer? p)
                       salt (fx> (bytevector-length salt) 0)
                       dk (fx= (bytevector-length dk) dk-len)
                       (guard (e (#t #f))                     ; huge/bad N -> #f
                         (ct=? dk (kdf-scrypt pw salt N r p dk-len))))))
               ((and (string=? (car parts) "pbkdf2-sha256") (= (length parts) 4))
                (let ((iters (string->number (list-ref parts 1)))
                      (salt (b64 (list-ref parts 2)))
                      (dk (b64 (list-ref parts 3))))
                  (and iters (integer? iters) (> iters 0) (<= iters 10000000)
                       salt (fx> (bytevector-length salt) 0)
                       dk (fx= (bytevector-length dk) dk-len)
                       (guard (e (#t #f))
                         (ct=? dk (kdf-pbkdf2-sha256 pw salt iters dk-len))))))
               ((and (string=? (car parts) "argon2id") (= (length parts) 6))
                (let ((t (string->number (list-ref parts 1)))
                      (m (string->number (list-ref parts 2)))
                      (p (string->number (list-ref parts 3)))
                      (salt (b64 (list-ref parts 4)))
                      (dk (b64 (list-ref parts 5))))
                  (and t m p (integer? t) (integer? m) (integer? p)
                       (> t 0) (<= t 1000) (<= m 262144) (> p 0) (<= p 64)
                       salt (fx> (bytevector-length salt) 0)
                       dk (fx= (bytevector-length dk) dk-len)
                       (guard (e (#t #f))
                         (ct=? dk (kdf-argon2id pw salt t m p dk-len))))))
               (else #f))))))
)
