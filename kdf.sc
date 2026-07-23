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
  (define _RAND_bytes (foreign-procedure "RAND_bytes" (u8* int) int))

  ;; memory ceiling for scrypt: caps a chosen (or crafted) N so a huge one
  ;; is rejected by libcrypto (return 0) rather than attempting the alloc.
  ;; The sane default (N=32768, r=8 -> 32 MiB working set) fits comfortably.
  (define scrypt-maxmem (* 256 1024 1024))

  ;; Verify-time resource ceiling: no single password-verify may exceed ~one
  ;; 256-MiB fill of KDF work (~0.1-0.2 s). A blocking KDF freezes igropyr's
  ;; single-threaded scheduler, so a crafted stored hash must not be able to
  ;; turn a login into a multi-second stall. Anchored to scrypt-maxmem; covers
  ;; every OWASP server config with headroom. (The raw kdf-* exports are NOT
  ;; capped -- they are primitives; this ceiling lives at the untrusted-input
  ;; boundary, password-verify.)
  (define kdf-max-passes-kib 262144)     ; argon2 t*m ceiling (= 256 MiB-passes)
  (define pbkdf2-max-iters   2000000)    ; ~one fill of time; >3x OWASP's 600k
  ;; scrypt TIME ceiling. scrypt-maxmem bounds MEMORY (~128*r*(N+p)) but NOT
  ;; time, which is ~N*r*p -- so a crafted balanced-N,p hash (memory fits, time
  ;; = N*p) would freeze the scheduler for hours. Bound the work N*r*p to one
  ;; 256 MiB pass (256MiB/128), the same budget scrypt-maxmem uses for memory.
  (define scrypt-max-work    2097152)    ; N*r*p ceiling (= 256 MiB / 128)
  ;; cap the untrusted password length: the KDF hashes it once (O(len)), so a
  ;; multi-MB password is a cheap DoS. 1024 UTF-8 bytes fits any real passphrase.
  (define max-password-bytes 1024)

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
    (unless (and (fixnum? N) (fx> N 1) (fixnum? r) (fx> r 0)
                 (fixnum? p) (fx> p 0) (fixnum? dk-len) (fx> dk-len 0))
      (assertion-violation 'kdf-scrypt "N>1 and r/p/dk-len>0, all fixnums" (list N r p dk-len)))
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
  (define k-threads (cstr "threads"))

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
  ;; t/m/p cross the OSSL_PARAM as uint32, so each must be a positive fixnum
  ;; below 2^32 (a bignum/flonum would raise, a negative would wrap); validate
  ;; BEFORE any allocation so a bad arg can neither crash nor leak. Cleanup is
  ;; a dynamic-wind, so an OOM/raise mid-build still frees ctx and every buffer.
  (define (kdf-argon2id password salt t m p dk-len)
    (define u32-max #x100000000)
    (unless (and (fixnum? t) (fx> t 0) (fx< t u32-max)
                 (fixnum? m) (fx> m 0) (fx< m u32-max)
                 (fixnum? p) (fx> p 0) (fx< p u32-max)
                 (fixnum? dk-len) (fx> dk-len 0))
      (assertion-violation 'kdf-argon2id
        "t/m/p positive fixnums < 2^32 and dk-len > 0" (list t m p dk-len)))
    (let ((out (make-bytevector dk-len))          ; Scheme heap first: an OOM
          (kdf (_EVP_KDF_fetch 0 "ARGON2ID" 0)))  ; here frees nothing native
      (when (zero? kdf) (error 'kdf-argon2id "ARGON2ID unavailable (need OpenSSL 3.2+)"))
      (let ((ctx (_EVP_KDF_CTX_new kdf)))
        (_EVP_KDF_free kdf)
        (when (zero? ctx) (error 'kdf-argon2id "EVP_KDF_CTX_new failed"))
        (let ((pass-p 0) (salt-p 0) (iter-c 0) (mem-c 0) (lanes-c 0) (threads-c 0) (params 0))
          (dynamic-wind
            (lambda () (void))
            (lambda ()
              (set! pass-p (c-bytes password)) (set! salt-p (c-bytes salt))
              (set! iter-c (c-uint t)) (set! mem-c (c-uint m)) (set! lanes-c (c-uint p))
              ;; threads=1: compute single-threaded regardless of lanes -- never
              ;; spawn OS threads (igropyr is one OS thread). The output depends
              ;; on lanes(=p), not on how many threads compute it, so this does
              ;; not change the hash.
              (set! threads-c (c-uint 1))
              (set! params (foreign-alloc (* 7 param-size)))
              (do ((i 0 (+ i 1))) ((= i (* 7 param-size))) (foreign-set! 'unsigned-8 params i 0))
              (set-param! params 0 k-pass    type-octet pass-p (bytevector-length password))
              (set-param! params 1 k-salt    type-octet salt-p (bytevector-length salt))
              (set-param! params 2 k-iter    type-uint  iter-c 4)
              (set-param! params 3 k-memcost type-uint  mem-c  4)
              (set-param! params 4 k-lanes   type-uint  lanes-c 4)
              (set-param! params 5 k-threads type-uint  threads-c 4)
              ;; entry 6 stays zeroed == OSSL_PARAM_END
              (if (fx= 1 (_EVP_KDF_derive ctx out dk-len params))
                  out
                  (error 'kdf-argon2id "EVP_KDF_derive failed (bad params or over memory)")))
            (lambda ()
              (unless (zero? pass-p)   (foreign-free pass-p))
              (unless (zero? salt-p)   (foreign-free salt-p))
              (unless (zero? iter-c)   (foreign-free iter-c))
              (unless (zero? mem-c)    (foreign-free mem-c))
              (unless (zero? lanes-c)  (foreign-free lanes-c))
              (unless (zero? threads-c)(foreign-free threads-c))
              (unless (zero? params)   (foreign-free params))
              (_EVP_KDF_CTX_free ctx)))))))

  ;; ---- self-describing password hashing --------------------------------
  (define salt-len 16)
  (define dk-len 32)

  ;; libcrypto's CSPRNG (already loaded, OS-seeded, fork-safe) -- no per-hash
  ;; /dev/urandom open/read/close.
  (define (random-bytes n)
    (let ((bv (make-bytevector n)))
      (if (fx= 1 (_RAND_bytes bv n))
          bv
          (error 'random-bytes "RAND_bytes failed"))))

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
      (when (fx> (bytevector-length pw) max-password-bytes)
        (assertion-violation 'password-hash "password too long (bytes)"
                             (bytevector-length pw)))
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
  ;; a positive fixnum from an untrusted numeric field -- rejects #f, flonums
  ;; (1e9), ratios and bignums, so the TYPE/RANGE check is the gate, not an
  ;; incidental FFI raise downstream.
  (define (pos-fx? x) (and (fixnum? x) (fx> x 0)))

  (define (password-verify password stored)
    (and (string? password) (string? stored)
         (let ((parts (split-dollar stored)))
           (and (pair? parts)
                (let ((pw (string->utf8 password)))
                  (and (fx<= (bytevector-length pw) max-password-bytes)
                   (cond
                    ((and (string=? (car parts) "scrypt") (= (length parts) 6))
                     (let ((N (string->number (list-ref parts 1)))
                           (r (string->number (list-ref parts 2)))
                           (p (string->number (list-ref parts 3)))
                           (salt (b64 (list-ref parts 4)))
                           (dk (b64 (list-ref parts 5))))
                       ;; work ~ N*r*p bounds TIME; scrypt-maxmem only bounds
                       ;; MEMORY (~N+p), so without this a balanced-N,p hash
                       ;; (memory fits, time = N*p) would freeze verify for
                       ;; hours. Generic * so a huge product -> bignum -> #f.
                       (and (pos-fx? N) (fx> N 1) (pos-fx? r) (pos-fx? p)
                            (<= (* N r p) scrypt-max-work)
                            salt (fx> (bytevector-length salt) 0)
                            dk (fx= (bytevector-length dk) dk-len)
                            (guard (e (#t #f))
                              (ct=? dk (kdf-scrypt pw salt N r p dk-len))))))
                    ((and (string=? (car parts) "pbkdf2-sha256") (= (length parts) 4))
                     (let ((iters (string->number (list-ref parts 1)))
                           (salt (b64 (list-ref parts 2)))
                           (dk (b64 (list-ref parts 3))))
                       (and (pos-fx? iters) (fx<= iters pbkdf2-max-iters)
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
                       ;; m<=256MiB AND t*m<=one fill bound BOTH memory and the
                       ;; time-cost t (which no memory ceiling can bound); use
                       ;; generic * so a huge t*m becomes a bignum -> #f, not a
                       ;; fixnum-overflow raise.
                       (and (pos-fx? t) (pos-fx? m) (pos-fx? p) (fx<= p 64)
                            (fx<= m kdf-max-passes-kib)
                            (<= (* t m) kdf-max-passes-kib)
                            salt (fx> (bytevector-length salt) 0)
                            dk (fx= (bytevector-length dk) dk-len)
                            (guard (e (#t #f))
                              (ct=? dk (kdf-argon2id pw salt t m p dk-len))))))
                    (else #f))))))))
)
