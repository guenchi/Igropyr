#!chezscheme
;;; (igropyr rsa) -- RSA keys and RSA-SHA256 (PKCS#1 v1.5) over ARBITRARY
;;; bytes. This is the general layer: it knows about keys, byte strings and
;;; signatures, and nothing about JWT, JOSE, claims or key-set documents.
;;; (igropyr jwks) is a JWT-shaped wrapper written on top of it; a caller
;;; signing a receipt, a manifest, a webhook body or a firmware image talks
;;; to this library directly.
;;;
;;;   (import (igropyr rsa))
;;;   (define k (rsa-load-private-key "/etc/keys/signing.pem"))
;;;   (define sig (rsa-sign-sha256 k (string->utf8 "any bytes at all")))
;;;
;;;   (define pub (rsa-load-public-key "/etc/keys/signing.pub"))   ; or a cert
;;;   (rsa-verify-sha256 pub (string->utf8 "any bytes at all") sig)  ; -> #t
;;;
;;; Loading:
;;;   rsa-private-key-from-pem   PEM text/bytes -> key (can sign and verify)
;;;   rsa-public-key-from-pem    PEM text/bytes -> key (verify only); accepts
;;;                              SubjectPublicKeyInfo ("BEGIN PUBLIC KEY"),
;;;                              an X.509 certificate ("BEGIN CERTIFICATE")
;;;                              and PKCS#1 ("BEGIN RSA PUBLIC KEY")
;;;   rsa-public-key-from-modulus  n-bytes e-bytes -> key (verify only), for
;;;                              key formats that publish the raw big-endian
;;;                              magnitudes rather than a PEM
;;;   rsa-load-private-key / rsa-load-public-key   the same, from a file path
;;;
;;; Inspection: rsa-key? rsa-key-private? rsa-key-bits rsa-key-modulus
;;; rsa-key-exponent rsa-key-consistency-checked. The two byte accessors
;;; hand back fresh copies, so a caller cannot reach into a live key.
;;; The last one answers what load time actually established about a
;;; private key's self-consistency -- 'checked, or one of two ways the
;;; question went unanswered -- because a key that loaded is not
;;; necessarily a key that was checked.
;;;
;;; WHAT COUNTS AS A KEY. A key is accepted only if it is a plain RSA key
;;; (an RSA-PSS key is refused, see below) whose parameters pass every one
;;; of these, checked in one place for every loading path:
;;;   modulus    odd, 2048 <= bits <= 16384
;;;   exponent   odd, 3 <= e < n, at most 64 bits
;;; The exponent floor is the important one. With e = 1 the public operation
;;; is the identity, so anyone can present a PKCS#1 v1.5 encoded block AS the
;;; signature and have it verify with no private key anywhere; an even
;;; exponent or an even modulus is not an RSA key at all. The 2048-bit floor
;;; refuses key sizes that are already factorable, and the two ceilings keep
;;; a caller-supplied modulus or exponent from turning one verification into
;;; a multi-second modular exponentiation -- which, in a single-threaded
;;; runtime, is a multi-second stop of every green process (see SCHEDULING).
;;;
;;; Signing and verification are SHA-256 with PKCS#1 v1.5 padding -- the
;;; scheme JOSE calls RS256 and `openssl dgst -sha256 -sign` produces, so
;;; signatures cross-check against the CLI in both directions. PSS is not
;;; offered: one padding, named in the procedure, cannot be confused for
;;; another by a caller reading a parameter out of untrusted input. An
;;; RSA-PSS key (algorithm id-RSASSA-PSS, which EVP_PKEY_get1_RSA happily
;;; unwraps) would silently make EVP_DigestSign produce PSS instead, so such
;;; a key is refused at load; the padding is ALSO pinned on the operation
;;; context, two independent mechanisms for one rule.
;;;
;;; rsa-verify-sha256 answers #t or #f and never raises on a bad signature:
;;; a signature is attacker-supplied, so "no" is an answer, not an error.
;;; It does raise when the machine could not perform the verification at
;;; all -- a failed digest init or update, or a final that reports an error
;;; rather than a mismatch -- because "this signature is forged" and "this
;;; host cannot check signatures" must not arrive as the same value.
;;; Everything else -- a malformed PEM, a non-RSA key, a wrong argument
;;; type, an exhausted allocator -- raises #(rsa-error MESSAGE) or an
;;; assertion, at the earliest point it can be detected. Type errors report
;;; the TYPE and never the value: the value here is a key, a plaintext or a
;;; PEM, and irritants are printed by every logger that renders a condition.
;;;
;;; A key holds a native EVP_PKEY that nothing in Scheme collects. A key
;;; loaded at boot and held for the life of the process needs no release --
;;; that is ownership, not a leak. Rotation is the case that needs
;;; rsa-key-free!, which is idempotent and leaves a freed key refusing
;;; cleanly rather than handing a NULL to OpenSSL. Sign and verify take
;;; their OWN reference for the duration of the operation, so a rotation
;;; that frees the key between the two does not hand OpenSSL a dangling
;;; pointer; it just makes the in-flight operation the last user.
;;;
;;; SCHEDULING AND OWNERSHIP. Every native object here (BIO, BIGNUM, RSA,
;;; EVP_PKEY, EVP_MD_CTX) is released by a dynamic-wind or a guard, and the
;;; runtime's kill DISCARDS both. So each operation runs inside
;;; with-openssl-scope, which turns preemption off for the whole
;;; acquire/use/release interval: a process cannot be killed where it cannot
;;; be preempted, and the release therefore always runs. That is affordable
;;; because the inputs are bounded -- a PEM is at most 64 KiB, a modulus at
;;; most 16384 bits -- with ONE exception, the message handed to
;;; rsa-sign-sha256 / rsa-verify-sha256, whose digest is O(input) and is
;;; already a single non-preemptible FFI call today. Bounding THAT is the
;;; caller's job: hand these procedures a message, not a file.
;;;
;;; The same scope brackets OpenSSL's error queue with ERR_set_mark /
;;; ERR_pop_to_mark. The queue is per OS THREAD, and every green process
;;; shares one, so a bare ERR_clear_error would delete errors belonging to
;;; whoever was preempted last (an in-flight TLS session, say) and a missing
;;; one would leave ours for them to misreport. Popping to a mark removes
;;; exactly the entries this operation added and nothing else.
;;;
;;; The deprecated-but-exported RSA_get0_key / RSA_set0_key /
;;; EVP_PKEY_set1_RSA path is used because it is present in OpenSSL 1.1 and
;;; 3.x alike, unlike the 3.x-only EVP_PKEY_fromdata.

(library (igropyr rsa)
  (export rsa-key? rsa-key-private? rsa-key-bits
          rsa-key-consistency-checked
          rsa-key-modulus rsa-key-exponent rsa-key-free!
          rsa-private-key-from-pem rsa-public-key-from-pem
          rsa-public-key-from-modulus
          rsa-load-private-key rsa-load-public-key
          rsa-sign-sha256 rsa-verify-sha256)
  (import (chezscheme) (igropyr platform))

  (define (rsa-fail msg) (raise (vector 'rsa-error msg)))

  ;; Type errors name the type, never the value. A caller who gets one of
  ;; these wrong has passed a private key, a plaintext or a passphrase.
  (define (type-name x)
    (cond ((bytevector? x) 'bytevector)
          ((string? x) 'string)
          ((symbol? x) 'symbol)
          ((number? x) 'number)
          ((char? x) 'char)
          ((boolean? x) 'boolean)
          ((null? x) 'null)
          ((pair? x) 'pair)
          ((vector? x) 'vector)
          ((procedure? x) 'procedure)
          ((port? x) 'port)
          (else 'other)))

  ;; ---- policy ------------------------------------------------------------

  (define rsa-min-modulus-bits 2048)
  (define rsa-max-modulus-bits 16384)
  (define rsa-max-exponent-bits 64)
  ;; A 4096-bit private key in PKCS#8 PEM is about 3.2 KiB; 64 KiB is room
  ;; for any real key file and a bound on how long the parse can hold the
  ;; scheduler. The same number caps a key FILE, so the read is bounded too.
  (define rsa-max-pem-bytes 65536)

  ;; Opening a key file safely on the one OS thread this runtime has.
  ;; open() on a FIFO with no writer would block the whole scheduler, so
  ;; open O_NONBLOCK -- then reject anything that is not seekable: a
  ;; regular file (and a block/char device) answers lseek(SEEK_CUR),
  ;; while a FIFO, pipe or socket returns ESPIPE. lseek, fcntl and their
  ;; constants are identical across the Unix targets, so this needs no
  ;; per-arch struct layout; only O_NONBLOCK's value differs (0x0004 on
  ;; macOS/FreeBSD, 0x0800 on Linux). The fd is made close-on-exec so a
  ;; concurrent fork+exec cannot inherit an open key file, and it is
  ;; closed on every path until the port takes ownership. A device that
  ;; is seekable but not a real key is bounded by the read limit below
  ;; and then fails to parse -- it cannot hang or read without end.
  (define _libc
    (load-first-shared-object! 'libc
      (case platform-os
        ((macos) '("libSystem.B.dylib" "libSystem.dylib"))
        ((freebsd) '("libc.so.7" "libc.so.6" "libc.so"))
        (else '("libc.so.6" "libc.so")))))
  (define O-RDONLY 0)
  ;; O_NONBLOCK and O_CLOEXEC are the two flags whose value differs per OS.
  ;; Setting O_CLOEXEC in the open() flags is atomic -- there is no
  ;; open-then-fcntl window in which a concurrent fork+exec could inherit
  ;; the key fd, and no fcntl return value to check.
  (define O-NONBLOCK (case platform-os ((linux) #x800) (else 4)))
  (define O-CLOEXEC
    (case platform-os
      ((linux) #x80000) ((freebsd) #x100000) ((macos) #x1000000) (else 0)))
  (define SEEK-CUR 1)                 ; POSIX, same everywhere
  (define c-open  (foreign-procedure "open" (string int) int))
  (define c-lseek (foreign-procedure "lseek" (int integer-64 int) integer-64))
  (define c-close (foreign-procedure "close" (int) int))
  ;; raw big-endian magnitudes handed to rsa-public-key-from-modulus: the
  ;; bit limits above are enforced after BN_bin2bn, but the byte arrays are
  ;; refused first so a gigabyte of leading zeros never reaches libcrypto
  (define rsa-max-magnitude-bytes 4096)

  ;; ---- libcrypto ---------------------------------------------------------

  (define _libcrypto
    (load-first-shared-object! 'igropyr-rsa
      (shared-object-candidates "libcrypto")))

  ;; The PEM text is copied into memory C owns before the BIO is built.
  ;; BIO_new_mem_buf does NOT copy: it keeps the pointer it was handed until
  ;; BIO_free, and the Chez collector MOVES bytevectors, so a GC anywhere
  ;; between the BIO and the PEM reader would leave the BIO pointing at
  ;; whatever now occupies that address. (Locking the object would stop the
  ;; move but not another process mutating a shared bytevector mid-parse;
  ;; the copy stops both.)
  (define BIO_new_mem_buf (foreign-procedure "BIO_new_mem_buf" (void* int) void*))
  (define BIO_free        (foreign-procedure "BIO_free" (void*) int))
  (define memcpy-to-c     (foreign-procedure "memcpy" (void* u8* size_t) void*))

  ;; PASSPHRASES ARE REFUSED, NOT GUESSED. The last two arguments of every
  ;; PEM reader are a pem_password_cb and its userdata, and the three ways
  ;; to fill them are not "prompt / do not prompt":
  ;;   cb NULL, userdata NULL      OpenSSL installs PEM_def_callback, which
  ;;                               PROMPTS ON THE TERMINAL and blocks.
  ;;   cb NULL, userdata non-NULL  userdata IS the passphrase. An empty C
  ;;                               string therefore means "try the EMPTY
  ;;                               PASSWORD", which is a real password: a
  ;;                               PKCS#8 key encrypted under it LOADS, and
  ;;                               every encrypted PEM first runs the KDF
  ;;                               named in its own header -- attacker-chosen
  ;;                               PBKDF2 iteration counts run to completion
  ;;                               inside one unpreemptible FFI call, which
  ;;                               stops the whole runtime for as long as the
  ;;                               attacker asked for.
  ;;   cb non-NULL                 the callback decides, and a -1 return
  ;;                               aborts the read BEFORE any key derivation.
  ;; So a real callback is installed, and it refuses everything. The reader
  ;; then fails the way an unreadable PEM fails, which is the documented
  ;; answer: this library takes UNENCRYPTED PEM only.
  (define refuse-passphrase-code
    (foreign-callable
      (lambda (buf size rwflag userdata) -1)
      (void* int int void*)
      int))
  (define locked-callbacks
    (begin (lock-object refuse-passphrase-code) refuse-passphrase-code))
  (define refuse-passphrase
    (foreign-callable-entry-point refuse-passphrase-code))

  (define PEM_read_bio_PrivateKey
    (foreign-procedure "PEM_read_bio_PrivateKey" (void* void* void* void*) void*))
  (define PEM_read_bio_PUBKEY
    (foreign-procedure "PEM_read_bio_PUBKEY" (void* void* void* void*) void*))
  (define PEM_read_bio_X509
    (foreign-procedure "PEM_read_bio_X509" (void* void* void* void*) void*))
  (define PEM_read_bio_RSAPublicKey
    (foreign-procedure "PEM_read_bio_RSAPublicKey" (void* void* void* void*) void*))
  (define X509_get_pubkey (foreign-procedure "X509_get_pubkey" (void*) void*))
  (define X509_free       (foreign-procedure "X509_free" (void*) void))
  (define EVP_PKEY_new    (foreign-procedure "EVP_PKEY_new" () void*))
  (define EVP_PKEY_free   (foreign-procedure "EVP_PKEY_free" (void*) void))
  (define EVP_PKEY_up_ref (foreign-procedure "EVP_PKEY_up_ref" (void*) int))
  ;; OpenSSL 3 renamed it and left the old spelling a macro, so the old
  ;; name is not an exported symbol there; 1.1 has only the old name.
  (define EVP_PKEY_id
    (foreign-procedure
      (if (foreign-entry? "EVP_PKEY_get_id") "EVP_PKEY_get_id" "EVP_PKEY_id")
      (void*) int))
  (define EVP_PKEY_CTX_new  (foreign-procedure "EVP_PKEY_CTX_new" (void* void*) void*))
  (define EVP_PKEY_CTX_free (foreign-procedure "EVP_PKEY_CTX_free" (void*) void))
  ;; consistency of a private key's own parameters (d*e = 1 mod lcm, p*q = n):
  ;; PEM decoding does not perform it, so a structurally valid but
  ;; mathematically inconsistent private key would otherwise be accepted
  ;; and only fail later at signing time. New in OpenSSL 1.1.1, so bind it
  ;; optionally: on an older libcrypto the check is skipped rather than
  ;; failing to load the library.
  (define EVP_PKEY_check
    (and (foreign-entry? "EVP_PKEY_check")
         (foreign-procedure "EVP_PKEY_check" (void*) int)))
  (define EVP_PKEY_get1_RSA (foreign-procedure "EVP_PKEY_get1_RSA" (void*) void*))
  (define EVP_PKEY_set1_RSA (foreign-procedure "EVP_PKEY_set1_RSA" (void* void*) int))
  (define RSA_new         (foreign-procedure "RSA_new" () void*))
  (define RSA_free        (foreign-procedure "RSA_free" (void*) void))
  ;; out-params: BIGNUM** written into 8-byte buffers (LP64 on every target)
  (define RSA_get0_key    (foreign-procedure "RSA_get0_key" (void* u8* u8* u8*) void))
  (define RSA_set0_key    (foreign-procedure "RSA_set0_key" (void* void* void* void*) int))
  (define BN_free         (foreign-procedure "BN_free" (void*) void))
  (define BN_bin2bn       (foreign-procedure "BN_bin2bn" (u8* int void*) void*))
  (define BN_num_bits     (foreign-procedure "BN_num_bits" (void*) int))
  (define BN_bn2bin       (foreign-procedure "BN_bn2bin" (void* u8*) int))
  (define EVP_sha256      (foreign-procedure "EVP_sha256" () void*))
  (define EVP_MD_CTX_new  (foreign-procedure "EVP_MD_CTX_new" () void*))
  (define EVP_MD_CTX_free (foreign-procedure "EVP_MD_CTX_free" (void*) void))
  ;; the second argument is an EVP_PKEY_CTX** out-param: the operation
  ;; context, borrowed (the EVP_MD_CTX owns it), used to pin the padding
  (define EVP_DigestSignInit
    (foreign-procedure "EVP_DigestSignInit" (void* u8* void* void* void*) int))
  (define EVP_DigestUpdate
    (foreign-procedure "EVP_DigestUpdate" (void* u8* size_t) int))
  ;; declared twice: the probe call passes NULL to learn the length
  (define EVP_DigestSignFinal-len
    (foreign-procedure "EVP_DigestSignFinal" (void* void* u8*) int))
  (define EVP_DigestSignFinal
    (foreign-procedure "EVP_DigestSignFinal" (void* u8* u8*) int))
  (define EVP_DigestVerifyInit
    (foreign-procedure "EVP_DigestVerifyInit" (void* u8* void* void* void*) int))
  (define EVP_DigestVerifyFinal
    (foreign-procedure "EVP_DigestVerifyFinal" (void* u8* size_t) int))

  ;; EVP_PKEY_CTX_set_rsa_padding is a real symbol in 3.x and a macro over
  ;; RSA_pkey_ctx_ctrl in 1.1; neither is guaranteed, so both are probed and
  ;; the pin is skipped (not faked) when the build offers no way to do it.
  (define EVP_PKEY_ALG_CTRL #x1000)
  (define EVP_PKEY_CTRL_RSA_PADDING (fx+ EVP_PKEY_ALG_CTRL 1))
  (define RSA_PKCS1_PADDING 1)
  (define set-rsa-padding!
    (cond
      ((foreign-entry? "EVP_PKEY_CTX_set_rsa_padding")
       (let ((f (foreign-procedure "EVP_PKEY_CTX_set_rsa_padding" (void* int) int)))
         (lambda (pctx) (f pctx RSA_PKCS1_PADDING))))
      ((foreign-entry? "RSA_pkey_ctx_ctrl")
       (let ((f (foreign-procedure "RSA_pkey_ctx_ctrl" (void* int int int void*) int)))
         (lambda (pctx) (f pctx -1 EVP_PKEY_CTRL_RSA_PADDING RSA_PKCS1_PADDING 0))))
      (else #f)))

  ;; Error-queue scoping. ERR_set_mark records the current top of the
  ;; per-thread queue; ERR_pop_to_mark drops everything pushed above it.
  (define ERR_set_mark    (foreign-procedure "ERR_set_mark" () int))
  (define ERR_pop_to_mark (foreign-procedure "ERR_pop_to_mark" () int))

  ;; One region per public operation. Preemption off for its whole extent,
  ;; so a kill cannot land between an acquire and its release (the runtime
  ;; discards winders, and a process that cannot be preempted cannot be
  ;; killed); the error queue bracketed so this operation's failures are
  ;; removed and nobody else's are.
  (define-syntax with-openssl-scope
    (syntax-rules ()
      ((_ body ...)
       (with-interrupts-disabled
         (dynamic-wind
           (lambda () (ERR_set_mark))
           (lambda () body ...)
           (lambda () (ERR_pop_to_mark)))))))

  (define (ptr-ref bv) (bytevector-u64-native-ref bv 0))

  (define (bn->bytes bn)
    (let* ((len (fxdiv (fx+ (BN_num_bits bn) 7) 8))
           (buf (make-bytevector len 0)))
      (unless (fx= len (BN_bn2bin bn buf)) (rsa-fail "BN_bn2bin length"))
      buf))

  ;; ---- the key record ----------------------------------------------------

  ;; pkey is mutable so rsa-key-free! can clear it; n/e/bits are read once at
  ;; load and never change, so inspection needs no native call.
  ;; consistency-checked: what load time established about this key --
  ;; 'checked / 'unavailable / 'not-implemented for a private key (see
  ;; check-private-consistency!), 'not-applicable for a public one, whose
  ;; parameters there is nothing to cross-check. A caller that must not
  ;; run on an unverified key asks for 'checked; one that only wants a key
  ;; ignores it, as before.
  (define-record-type (rsa-key mk-rsa-key rsa-key?)
    (fields (mutable pkey) private? n-bytes e-bytes bits
            consistency-checked))

  (define (need-key who k)
    (unless (rsa-key? k)
      (assertion-violation who "not an RSA key" (type-name k)))
    k)

  (define (need-bv who what x)
    (unless (bytevector? x)
      (assertion-violation who (string-append what " must be a bytevector")
                           (type-name x)))
    x)

  (define (rsa-key-modulus k)
    (bytevector-copy (rsa-key-n-bytes (need-key 'rsa-key-modulus k))))

  (define (rsa-key-exponent k)
    (bytevector-copy (rsa-key-e-bytes (need-key 'rsa-key-exponent k))))

  ;; The read, the clear and the free are ONE step. Split across a safe point
  ;; they are not idempotent at all: two processes both read the same non-zero
  ;; pointer and both free it, which corrupts the allocator -- the exact
  ;; failure the idempotence exists to prevent. The mirror window is as bad:
  ;; cleared, then killed before the free, and the key leaks with no way left
  ;; to reach it. EVP_PKEY_free is called INSIDE the region deliberately: it
  ;; is a short native call and cannot yield.
  ;;
  ;; This drops the record's reference. An operation already running holds
  ;; its own (with-pkey-ref), so freeing a key another process is signing
  ;; with is no longer a use-after-free -- the last reference to go wins, and
  ;; the in-flight signature completes on a key nothing can reach any more.
  (define (rsa-key-free! k)
    (need-key 'rsa-key-free! k)
    (with-interrupts-disabled
      (let ((pk (rsa-key-pkey k)))
        (unless (zero? pk)
          (rsa-key-pkey-set! k 0)
          (EVP_PKEY_free pk))))
    (void))

  (define (live-pkey who k)
    (let ((pk (rsa-key-pkey (need-key who k))))
      (when (zero? pk) (rsa-fail (string-append (symbol->string who)
                                                ": key already freed")))
      pk))

  ;; Read the live pointer and take a reference in one step -- callers run
  ;; inside with-openssl-scope, so no rotation can slip between them -- and
  ;; drop it when the operation is over.
  (define (with-pkey-ref who k proc)
    (let ((pk (live-pkey who k)))
      (unless (fx= 1 (EVP_PKEY_up_ref pk))
        (rsa-fail (string-append (symbol->string who) ": EVP_PKEY_up_ref failed")))
      (dynamic-wind
        (lambda () (void))
        (lambda () (proc pk))
        (lambda () (EVP_PKEY_free pk)))))

  (define (with-md-ctx proc)
    (let ((ctx (EVP_MD_CTX_new)))
      (when (zero? ctx) (rsa-fail "EVP_MD_CTX_new failed"))
      (dynamic-wind
        (lambda () (void))
        (lambda () (proc ctx))
        (lambda () (EVP_MD_CTX_free ctx)))))

  ;; ---- what a key has to be ----------------------------------------------
  ;;
  ;; ONE place, reached by every loading path: PEM private, PEM public,
  ;; certificate, PKCS#1 and raw modulus all end in pkey->rsa-key. Adding a
  ;; sixth way to name a key adds no sixth copy of the policy.
  ;;
  ;; The arguments are the minimal big-endian magnitudes BN_bn2bin produces,
  ;; so they carry no leading zero byte and their length is the value's byte
  ;; length. EVP_PKEY_public_check is deliberately NOT used in their place:
  ;; what it enforces for RSA depends on the provider (under SP800-56B rules
  ;; it rejects e = 3, a legal exponent this library interoperates with),
  ;; so the set of keys accepted would vary by host and by FIPS mode. The
  ;; rules below are the same everywhere and cost microseconds.

  (define (magnitude-odd? bv)
    (let ((n (bytevector-length bv)))
      (and (fx> n 0) (fxodd? (bytevector-u8-ref bv (fx- n 1))))))

  ;; a < b, both minimal big-endian magnitudes
  (define (magnitude<? a b)
    (let ((la (bytevector-length a)) (lb (bytevector-length b)))
      (cond ((fx< la lb) #t)
            ((fx> la lb) #f)
            (else
              (let loop ((i 0))
                (cond ((fx= i la) #f)
                      ((fx< (bytevector-u8-ref a i) (bytevector-u8-ref b i)) #t)
                      ((fx> (bytevector-u8-ref a i) (bytevector-u8-ref b i)) #f)
                      (else (loop (fx+ i 1)))))))))

  ;; value of a magnitude that is known to be small (<= 8 bytes)
  (define (magnitude->integer bv)
    (let loop ((i 0) (acc 0))
      (if (fx= i (bytevector-length bv))
          acc
          (loop (fx+ i 1) (+ (* acc 256) (bytevector-u8-ref bv i))))))

  (define (check-rsa-parts! n-bytes e-bytes n-bits)
    (when (fx< n-bits rsa-min-modulus-bits)
      (rsa-fail (string-append "RSA modulus is only " (number->string n-bits)
                               " bits; this library requires at least "
                               (number->string rsa-min-modulus-bits))))
    (when (fx> n-bits rsa-max-modulus-bits)
      (rsa-fail (string-append "RSA modulus is " (number->string n-bits)
                               " bits; this library allows at most "
                               (number->string rsa-max-modulus-bits))))
    (unless (magnitude-odd? n-bytes)
      (rsa-fail "RSA modulus is even"))
    (let ((e-bits (fx* 8 (bytevector-length e-bytes))))
      (when (fx> e-bits rsa-max-exponent-bits)
        (rsa-fail (string-append "RSA public exponent is wider than "
                                 (number->string rsa-max-exponent-bits)
                                 " bits"))))
    (unless (magnitude-odd? e-bytes)
      (rsa-fail "RSA public exponent is even"))
    (when (< (magnitude->integer e-bytes) 3)
      ;; e = 1 makes the public operation the identity: any PKCS#1 v1.5
      ;; block presented as a signature would "verify" with no private key
      (rsa-fail "RSA public exponent is less than 3"))
    (unless (magnitude<? e-bytes n-bytes)
      (rsa-fail "RSA public exponent is not smaller than the modulus")))

  ;; ---- PEM plumbing ------------------------------------------------------

  ;; Postel: PEM is text, and a caller has it either as a string it built or
  ;; as the bytes it read off a file or a socket. Take both.
  (define (pem-bytes who x)
    (let ((bv (cond ((bytevector? x) x)
                    ((string? x) (string->utf8 x))
                    (else (assertion-violation who
                            "PEM must be a string or a bytevector"
                            (type-name x))))))
      (when (fx> (bytevector-length bv) rsa-max-pem-bytes)
        (rsa-fail (string-append (symbol->string who) ": PEM is larger than "
                                 (number->string rsa-max-pem-bytes) " bytes")))
      bv))

  ;; Every parse attempt gets its own copy, its own BIO, and both are freed
  ;; on every path including a raise out of proc. The copy is what makes the
  ;; BIO safe: see BIO_new_mem_buf above.
  ;; Each native resource is allocated inside the before-thunk of the wind
  ;; that frees it, so the free is registered before the resource exists to
  ;; be leaked -- no out-of-memory window between allocation and winder.
  (define (with-bio pem proc)
    (let ((n (bytevector-length pem))
          (buf #f))
      (dynamic-wind
        (lambda () (set! buf (foreign-alloc (fx+ n 1))))  ; +1: never a zero-size alloc
        (lambda ()
          (when (fx> n 0) (memcpy-to-c buf pem n))
          (let ((bio #f))
            (dynamic-wind
              (lambda ()
                (set! bio (BIO_new_mem_buf buf n))
                (when (zero? bio) (rsa-fail "BIO_new_mem_buf failed")))
              (lambda () (proc bio))
              (lambda () (when (and bio (not (zero? bio))) (BIO_free bio))))))
        (lambda () (when buf (foreign-free buf))))))

  ;; EVP_PKEY -> rsa-key. Owns pk from here: every exit either hands it to
  ;; the record or frees it, the record construction included -- an
  ;; allocation failure at the very last step must not strand a private key.
  (define EVP_PKEY_RSA 6)          ; NID_rsaEncryption
  (define EVP_PKEY_RSA_PSS 912)    ; NID_rsassaPss

  ;; A private key must be self-consistent, not merely well-encoded: a
  ;; PEM whose d/p/q do not match n/e decodes fine but cannot sign
  ;; verifiably. Reject it at load time rather than at first signature.
  ;;
  ;; -> what this load actually established, which is NOT always "the key
  ;; was judged sound":
  ;;   'checked         the check ran and passed
  ;;   'unavailable     no EVP_PKEY_check in this libcrypto (before 1.1.1,
  ;;                    and LibreSSL): nothing was judged
  ;;   'not-implemented the provider declined to judge (-2): nothing was
  ;;                    judged
  ;; and it raises, rather than returning, when the key IS judged bad.
  ;;
  ;; SO A KEY THAT LOADED IS NOT A KEY THAT WAS CHECKED. Both non-checked
  ;; answers are deliberate -- refusing to load on an older libcrypto
  ;; would be a larger change than this check is worth, and a provider
  ;; that cannot judge must not thereby reject every key -- but they were
  ;; previously indistinguishable from a pass, and a caller that needs the
  ;; guarantee had no way to ask. rsa-key-consistency-checked reports this
  ;; per key.
  ;;
  ;; The reject path is fail-closed: 0 and every other negative are
  ;; refused, so an internal error cannot read as a pass. That is a
  ;; property of the branch below, not of key loading as a whole.
  (define (check-private-consistency! pk)
    (if (not EVP_PKEY_check)
        'unavailable
      (let ((ctx #f))
        ;; allocate inside the before-thunk so the free is registered
        ;; before the ctx exists to be leaked
        (dynamic-wind
          (lambda ()
            (set! ctx (EVP_PKEY_CTX_new pk 0))
            (when (zero? ctx) (rsa-fail "EVP_PKEY_CTX_new failed")))
          (lambda ()
            ;; 1 = valid; -2 = provider does not implement the check, which
            ;; is reported rather than treated as a pass; 0 and any other
            ;; negative = invalid or the check itself failed -> reject. A
            ;; FIPS provider failing a mathematically sound key on policy
            ;; also returns 0 and is refused here -- the return value
            ;; cannot tell the two apart; such a key must be loaded through
            ;; the raw-modulus API instead.
            (let ((r (EVP_PKEY_check ctx)))
              (cond ((fx= r 1) 'checked)
                    ((fx= r -2) 'not-implemented)
                    (else
                      (rsa-fail (string-append
                                  "inconsistent RSA private key "
                                  "(parameters do not agree)"))))))
          (lambda () (when (and ctx (not (zero? ctx))) (EVP_PKEY_CTX_free ctx)))))))

  (define (pkey->rsa-key pk private?)
    (guard (e (#t (EVP_PKEY_free pk) (raise e)))
      (let ((id (EVP_PKEY_id pk)))
        (unless (fx= id EVP_PKEY_RSA)
          (rsa-fail
            (if (fx= id EVP_PKEY_RSA_PSS)
                "RSA-PSS key: this library signs and verifies PKCS#1 v1.5 only"
                "not an RSA key"))))
      (let ((rsa (EVP_PKEY_get1_RSA pk)))
        (when (zero? rsa) (rsa-fail "not an RSA key"))
        ;; extract first, free the RSA handle exactly once afterwards
        (let ((parts
                (guard (e (#t (RSA_free rsa) (raise e)))
                  (let ((np (make-bytevector 8 0))
                        (ep (make-bytevector 8 0))
                        (dp (make-bytevector 8 0)))
                    (RSA_get0_key rsa np ep dp)
                    (let ((n (ptr-ref np)) (e (ptr-ref ep)))
                      (when (or (zero? n) (zero? e))
                        (rsa-fail "RSA key carries no modulus/exponent"))
                      (list (bn->bytes n) (bn->bytes e) (BN_num_bits n)))))))
          (RSA_free rsa)
          (check-rsa-parts! (car parts) (cadr parts) (caddr parts))
          (let ((checked (if private?
                             (check-private-consistency! pk)
                             'not-applicable)))
            (mk-rsa-key pk private? (car parts) (cadr parts) (caddr parts)
                        checked))))))

  (define (rsa-private-key-from-pem pem)
    (let ((bv (pem-bytes 'rsa-private-key-from-pem pem)))
      (with-openssl-scope
        (let ((pk (with-bio bv
                    (lambda (bio)
                      (PEM_read_bio_PrivateKey bio 0 refuse-passphrase 0)))))
          (when (zero? pk)
            (rsa-fail "PEM_read_bio_PrivateKey failed (unencrypted PKCS#8/PKCS#1 PEM expected)"))
          (pkey->rsa-key pk #t)))))

  ;; SubjectPublicKeyInfo: "-----BEGIN PUBLIC KEY-----"
  (define (try-pem-pubkey bv)
    (let ((pk (with-bio bv
                (lambda (bio) (PEM_read_bio_PUBKEY bio 0 refuse-passphrase 0)))))
      (if (zero? pk) #f pk)))

  ;; X.509 certificate: "-----BEGIN CERTIFICATE-----". The certificate itself
  ;; is a wrapper around the key; nothing here validates a chain or a validity
  ;; window, which is (igropyr apple-jws)'s job for the chains it pins. Taking
  ;; a key out of a certificate is not trusting the certificate.
  (define (try-pem-cert bv)
    (let ((x (with-bio bv
               (lambda (bio) (PEM_read_bio_X509 bio 0 refuse-passphrase 0)))))
      (if (zero? x)
          #f
          (let ((pk (X509_get_pubkey x)))
            (X509_free x)
            (if (zero? pk) #f pk)))))

  ;; PKCS#1: "-----BEGIN RSA PUBLIC KEY-----" (an RSAPublicKey, no algorithm
  ;; identifier around it). Older tooling still emits this.
  (define (try-pem-pkcs1 bv)
    (let ((rsa (with-bio bv
                 (lambda (bio)
                   (PEM_read_bio_RSAPublicKey bio 0 refuse-passphrase 0)))))
      (if (zero? rsa)
          #f
          (let ((pk (EVP_PKEY_new)))
            (cond
              ((zero? pk) (RSA_free rsa) #f)
              ((not (fx= 1 (EVP_PKEY_set1_RSA pk rsa)))
               (EVP_PKEY_free pk) (RSA_free rsa) #f)
              (else (RSA_free rsa) pk))))))   ; pkey holds its own reference

  ;; Postel again: three encodings all mean "here is a public key", so try
  ;; each rather than making the caller sniff the label and pick a procedure.
  ;; The output is narrow either way -- one key record, or a raise.
  (define (rsa-public-key-from-pem pem)
    (let ((bv (pem-bytes 'rsa-public-key-from-pem pem)))
      (with-openssl-scope
        (let ((pk (or (try-pem-pubkey bv) (try-pem-cert bv) (try-pem-pkcs1 bv))))
          (unless pk
            (rsa-fail "not a PEM public key (expected BEGIN PUBLIC KEY, BEGIN CERTIFICATE or BEGIN RSA PUBLIC KEY)"))
          (pkey->rsa-key pk #f)))))

  ;; n-bytes / e-bytes: big-endian magnitudes, the form JWK, DNSKEY and SSH
  ;; wire encodings publish.
  (define (rsa-public-key-from-modulus n-bytes e-bytes)
    (let ((nb (need-bv 'rsa-public-key-from-modulus "modulus" n-bytes))
          (eb (need-bv 'rsa-public-key-from-modulus "exponent" e-bytes)))
      (when (or (fx= 0 (bytevector-length nb)) (fx= 0 (bytevector-length eb)))
        (assertion-violation 'rsa-public-key-from-modulus
          "modulus and exponent must be non-empty"
          (list (bytevector-length nb) (bytevector-length eb))))
      ;; refuse absurd magnitudes before libcrypto allocates for them; the
      ;; real bit limits are enforced by check-rsa-parts! after conversion
      (when (or (fx> (bytevector-length nb) rsa-max-magnitude-bytes)
                (fx> (bytevector-length eb) rsa-max-magnitude-bytes))
        (rsa-fail (string-append "modulus and exponent must each be at most "
                                 (number->string rsa-max-magnitude-bytes)
                                 " bytes")))
      (with-openssl-scope
        (let* ((n (BN_bin2bn nb (bytevector-length nb) 0))
               (e (BN_bin2bn eb (bytevector-length eb) 0)))
          (when (or (zero? n) (zero? e))
            (unless (zero? n) (BN_free n))
            (unless (zero? e) (BN_free e))
            (rsa-fail "BN_bin2bn failed"))
          (when (or (fx< (BN_num_bits n) 1) (fx< (BN_num_bits e) 1))
            (BN_free n) (BN_free e)
            (rsa-fail "modulus and exponent must be non-zero"))
          (let ((rsa (RSA_new)))
            (when (zero? rsa)
              (BN_free n) (BN_free e) (rsa-fail "RSA_new failed"))
            (unless (fx= 1 (RSA_set0_key rsa n e 0))
              (RSA_free rsa) (BN_free n) (BN_free e)
              (rsa-fail "RSA_set0_key failed"))
            ;; n and e belong to rsa from here; freeing rsa frees them
            (let ((pk (EVP_PKEY_new)))
              (when (zero? pk)
                (RSA_free rsa) (rsa-fail "EVP_PKEY_new failed"))
              (unless (fx= 1 (EVP_PKEY_set1_RSA pk rsa))
                (EVP_PKEY_free pk) (RSA_free rsa)
                (rsa-fail "EVP_PKEY_set1_RSA failed"))
              (RSA_free rsa)                  ; pkey holds its own reference
              (pkey->rsa-key pk #f)))))))

  ;; A path is not just a name for bytes. open() on a FIFO with no writer
  ;; blocks forever, /dev/zero never reaches EOF, and either one -- executed
  ;; on the one OS thread this runtime has -- stops every green process,
  ;; every timer and all supervision, with no actor timeout able to
  ;; interrupt it. So open with O_NONBLOCK (a FIFO returns a fd instead of
  ;; parking), fstat THAT fd, accept only a regular file, and read at most
  ;; one PEM's worth. Because the fstat and the read act on the opened
  ;; inode, not on the path, the classic stat-then-open swap (regular file
  ;; replaced by a FIFO in between) cannot reach the read. A caller who
  ;; must not block AT ALL should read the bytes itself, asynchronously,
  ;; and use rsa-*-key-from-pem -- the interface these wrappers build on.
  (define (read-file-bytes who path)
    (unless (string? path)
      (assertion-violation who "path must be a string" (type-name path)))
    (let ((fd (c-open path (fxior O-RDONLY O-NONBLOCK O-CLOEXEC))))
      (when (fx< fd 0)
        (rsa-fail (string-append (symbol->string who) ": cannot open: " path)))
      ;; own the raw fd until it is either rejected (closed here) or handed
      ;; to a port (closed with the port). A failure anywhere in this
      ;; stretch -- an allocation that throws, a non-seekable verdict --
      ;; must not strand it. close-on-exec was set atomically in the open
      ;; flags, so no fork+exec can inherit it.
      (let ((port #f))
        (dynamic-wind
          (lambda () (void))
          (lambda ()
            ;; a FIFO/pipe/socket cannot seek (ESPIPE) -- reject it before
            ;; a read could block; the verdict is on this fd, so no
            ;; path-swap window
            (when (< (c-lseek fd 0 SEEK-CUR) 0)
              (rsa-fail (string-append (symbol->string who)
                                       ": not a seekable file: " path)))
            (set! port (open-fd-input-port fd (buffer-mode block)))
            (let ((bv (get-bytevector-n port (fx+ rsa-max-pem-bytes 1))))
              (cond
                ;; an empty file reads as EOF; hand the parser bytes, not an
                ;; eof object, so the answer is "malformed PEM" and not "PEM
                ;; must be a string or a bytevector"
                ((eof-object? bv) (make-bytevector 0))
                ((fx> (bytevector-length bv) rsa-max-pem-bytes)
                 (rsa-fail (string-append (symbol->string who) ": " path
                                          " is larger than "
                                          (number->string rsa-max-pem-bytes)
                                          " bytes")))
                (else bv))))
          (lambda ()
            ;; the port, once created, owns the fd; before that we do
            (if port (close-port port) (c-close fd)))))))

  (define (rsa-load-private-key path)
    (rsa-private-key-from-pem (read-file-bytes 'rsa-load-private-key path)))

  (define (rsa-load-public-key path)
    (rsa-public-key-from-pem (read-file-bytes 'rsa-load-public-key path)))

  ;; ---- signing -----------------------------------------------------------

  ;; The operation context handed back by DigestSignInit/DigestVerifyInit is
  ;; borrowed from the EVP_MD_CTX -- not freed here. Pinning PKCS#1 v1.5 on
  ;; it is the second of the two mechanisms that keep this library from ever
  ;; producing or accepting PSS; the first is refusing RSA-PSS keys at load.
  (define (pin-pkcs1-padding! who pctx)
    (when (and set-rsa-padding! (not (zero? pctx)))
      (unless (fx= 1 (set-rsa-padding! pctx))
        (rsa-fail (string-append (symbol->string who)
                                 ": could not select PKCS#1 v1.5 padding")))))

  ;; A public-only key cannot sign. libcrypto would refuse too, but it refuses
  ;; several sentences later and blames EVP_DigestSignInit; say it here.
  (define (rsa-sign-sha256 k input)
    (need-key 'rsa-sign-sha256 k)
    (need-bv 'rsa-sign-sha256 "input" input)
    (unless (rsa-key-private? k)
      (rsa-fail "rsa-sign-sha256: key is public only"))
    (with-openssl-scope
      (with-pkey-ref 'rsa-sign-sha256 k
        (lambda (pk)
          (with-md-ctx
            (lambda (ctx)
              (let ((pctx (make-bytevector 8 0)))
                (unless (fx= 1 (EVP_DigestSignInit ctx pctx (EVP_sha256) 0 pk))
                  (rsa-fail "EVP_DigestSignInit failed"))
                (pin-pkcs1-padding! 'rsa-sign-sha256 (ptr-ref pctx)))
              (unless (fx= 1 (EVP_DigestUpdate ctx input (bytevector-length input)))
                (rsa-fail "EVP_DigestUpdate failed"))
              (let ((lenbuf (make-bytevector 8 0)))
                (unless (fx= 1 (EVP_DigestSignFinal-len ctx 0 lenbuf))
                  (rsa-fail "EVP_DigestSignFinal(len) failed"))
                (let* ((cap (bytevector-u64-native-ref lenbuf 0))
                       (sig (make-bytevector cap 0)))
                  (unless (fx= 1 (EVP_DigestSignFinal ctx sig lenbuf))
                    (rsa-fail "EVP_DigestSignFinal failed"))
                  ;; the RETURN value of bytevector-truncate!: it shrinks in
                  ;; place except at zero, where it hands back a fresh empty
                  ;; bytevector -- and the signature is the buffer itself,
                  ;; not a copy of it
                  (let ((n (bytevector-u64-native-ref lenbuf 0)))
                    (if (fx= n cap) sig (bytevector-truncate! sig n)))))))))))

  ;; ---- verification ------------------------------------------------------

  ;; #t or #f for the SIGNATURE, and a raise for everything else. Only
  ;; EVP_DigestVerifyFinal answers about the signature, and only its 1/0 are
  ;; answers: 1 is "this is the signature", 0 is "it is not". Any other
  ;; result, and any failure of the init or the update, means the check did
  ;; not happen -- a key restricted to another digest, a provider or policy
  ;; refusal, an allocation failure -- and reporting that as #f would tell
  ;; the caller a forgery was attempted when the truth is that this host
  ;; cannot answer. The queue entries such a failure leaves are removed with
  ;; the rest of the scope, so a rejected signature cannot make an unrelated
  ;; later libcrypto call report the wrong reason.
  (define (rsa-verify-sha256 k input sig)
    (need-key 'rsa-verify-sha256 k)
    (need-bv 'rsa-verify-sha256 "input" input)
    (need-bv 'rsa-verify-sha256 "signature" sig)
    (with-openssl-scope
      (with-pkey-ref 'rsa-verify-sha256 k
        (lambda (pk)
          (with-md-ctx
            (lambda (ctx)
              (let ((pctx (make-bytevector 8 0)))
                (unless (fx= 1 (EVP_DigestVerifyInit ctx pctx (EVP_sha256) 0 pk))
                  (rsa-fail "EVP_DigestVerifyInit failed"))
                (pin-pkcs1-padding! 'rsa-verify-sha256 (ptr-ref pctx)))
              (unless (fx= 1 (EVP_DigestUpdate ctx input (bytevector-length input)))
                (rsa-fail "EVP_DigestUpdate failed"))
              (let ((r (EVP_DigestVerifyFinal ctx sig (bytevector-length sig))))
                (cond
                  ((fx= r 1) #t)
                  ((fx= r 0) #f)
                  (else (rsa-fail "EVP_DigestVerifyFinal failed"))))))))))
)
