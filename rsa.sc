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
;;; rsa-key-exponent. The two byte accessors hand back fresh copies, so a
;;; caller cannot reach into a live key.
;;;
;;; Signing and verification are SHA-256 with PKCS#1 v1.5 padding -- the
;;; scheme JOSE calls RS256 and `openssl dgst -sha256 -sign` produces, so
;;; signatures cross-check against the CLI in both directions. PSS is not
;;; offered: one padding, named in the procedure, cannot be confused for
;;; another by a caller reading a parameter out of untrusted input.
;;;
;;; rsa-verify-sha256 answers #t or #f and never raises on a bad signature:
;;; a signature is attacker-supplied, so "no" is an answer, not an error.
;;; Everything else -- a malformed PEM, a non-RSA key, a wrong argument
;;; type, an exhausted allocator -- raises #(rsa-error MESSAGE) or an
;;; assertion, at the earliest point it can be detected.
;;;
;;; A key holds a native EVP_PKEY that nothing in Scheme collects. A key
;;; loaded at boot and held for the life of the process needs no release --
;;; that is ownership, not a leak. Rotation is the case that needs
;;; rsa-key-free!, which is idempotent and leaves a freed key refusing
;;; cleanly rather than handing a NULL to OpenSSL.
;;;
;;; The deprecated-but-exported RSA_get0_key / RSA_set0_key /
;;; EVP_PKEY_set1_RSA path is used because it is present in OpenSSL 1.1 and
;;; 3.x alike, unlike the 3.x-only EVP_PKEY_fromdata.

(library (igropyr rsa)
  (export rsa-key? rsa-key-private? rsa-key-bits
          rsa-key-modulus rsa-key-exponent rsa-key-free!
          rsa-private-key-from-pem rsa-public-key-from-pem
          rsa-public-key-from-modulus
          rsa-load-private-key rsa-load-public-key
          rsa-sign-sha256 rsa-verify-sha256)
  (import (chezscheme) (igropyr platform))

  (define (rsa-fail msg) (raise (vector 'rsa-error msg)))

  ;; ---- libcrypto ---------------------------------------------------------

  (define _libcrypto
    (load-first-shared-object! 'igropyr-rsa
      (shared-object-candidates "libcrypto")))

  (define BIO_new_mem_buf (foreign-procedure "BIO_new_mem_buf" (u8* int) void*))
  (define BIO_free        (foreign-procedure "BIO_free" (void*) int))
  ;; The last argument of every PEM reader is the passphrase callback's
  ;; userdata, and passing NULL for BOTH the callback and the userdata is
  ;; what makes OpenSSL install PEM_def_callback and PROMPT ON THE TERMINAL.
  ;; Any PEM carrying Proc-Type/DEK-Info headers reaches that prompt --
  ;; including one labelled BEGIN PUBLIC KEY, so caller-supplied input gets
  ;; there too -- and the read blocks the process. A non-NULL userdata is
  ;; taken as the passphrase itself and returned immediately, so an empty C
  ;; string means "no passphrase, do not ask": the header fails to decrypt
  ;; and the reader fails, which is the documented answer.
  (define no-passphrase (make-bytevector 1 0))
  (define PEM_read_bio_PrivateKey
    (foreign-procedure "PEM_read_bio_PrivateKey" (void* void* void* u8*) void*))
  (define PEM_read_bio_PUBKEY
    (foreign-procedure "PEM_read_bio_PUBKEY" (void* void* void* u8*) void*))
  (define PEM_read_bio_X509
    (foreign-procedure "PEM_read_bio_X509" (void* void* void* u8*) void*))
  (define PEM_read_bio_RSAPublicKey
    (foreign-procedure "PEM_read_bio_RSAPublicKey" (void* void* void* u8*) void*))
  (define X509_get_pubkey (foreign-procedure "X509_get_pubkey" (void*) void*))
  (define X509_free       (foreign-procedure "X509_free" (void*) void))
  (define EVP_PKEY_new    (foreign-procedure "EVP_PKEY_new" () void*))
  (define EVP_PKEY_free   (foreign-procedure "EVP_PKEY_free" (void*) void))
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
  (define EVP_DigestSignInit
    (foreign-procedure "EVP_DigestSignInit" (void* void* void* void* void*) int))
  (define EVP_DigestUpdate
    (foreign-procedure "EVP_DigestUpdate" (void* u8* size_t) int))
  ;; declared twice: the probe call passes NULL to learn the length
  (define EVP_DigestSignFinal-len
    (foreign-procedure "EVP_DigestSignFinal" (void* void* u8*) int))
  (define EVP_DigestSignFinal
    (foreign-procedure "EVP_DigestSignFinal" (void* u8* u8*) int))
  (define EVP_DigestVerifyInit
    (foreign-procedure "EVP_DigestVerifyInit" (void* void* void* void* void*) int))
  (define EVP_DigestVerifyFinal
    (foreign-procedure "EVP_DigestVerifyFinal" (void* u8* size_t) int))
  ;; A parse attempt that misses leaves entries on OpenSSL's per-thread error
  ;; queue. rsa-public-key-from-pem tries three parsers in turn, so without
  ;; this the queue would carry two stale failures into whatever the caller
  ;; does next -- the classic way an unrelated later call reports the wrong
  ;; reason for its own failure.
  (define ERR_clear_error (foreign-procedure "ERR_clear_error" () void))

  (define (ptr-ref bv) (bytevector-u64-native-ref bv 0))

  (define (bn->bytes bn)
    (let* ((len (fxdiv (fx+ (BN_num_bits bn) 7) 8))
           (buf (make-bytevector len 0)))
      (unless (fx= len (BN_bn2bin bn buf)) (rsa-fail "BN_bn2bin length"))
      buf))

  ;; ---- the key record ----------------------------------------------------

  ;; pkey is mutable so rsa-key-free! can clear it; n/e/bits are read once at
  ;; load and never change, so inspection needs no native call.
  (define-record-type (rsa-key mk-rsa-key rsa-key?)
    (fields (mutable pkey) private? n-bytes e-bytes bits))

  (define (need-key who k)
    (unless (rsa-key? k)
      (assertion-violation who "not an RSA key" k))
    k)

  (define (need-bv who what x)
    (unless (bytevector? x)
      (assertion-violation who (string-append what " must be a bytevector") x))
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
  ;; The caller must be finished with the key. OpenSSL will not tell us that,
  ;; so this is the C ownership contract, unchanged: freeing a key another
  ;; process is signing with is a use-after-free. Retire the key from wherever
  ;; verifiers reach it first, then free it.
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

  ;; ---- PEM plumbing ------------------------------------------------------

  ;; Postel: PEM is text, and a caller has it either as a string it built or
  ;; as the bytes it read off a file or a socket. Take both.
  (define (pem-bytes who x)
    (cond ((bytevector? x) x)
          ((string? x) (string->utf8 x))
          (else (assertion-violation who
                  "PEM must be a string or a bytevector" x))))

  ;; Every parse attempt gets its own BIO, and the BIO is freed on every path
  ;; including a raise out of proc.
  (define (with-bio pem proc)
    (let ((bio (BIO_new_mem_buf pem (bytevector-length pem))))
      (when (zero? bio) (rsa-fail "BIO_new_mem_buf failed"))
      (dynamic-wind
        (lambda () (void))
        (lambda () (proc bio))
        (lambda () (BIO_free bio)))))

  ;; EVP_PKEY -> rsa-key, or free the pkey and fail. Owns pk from here.
  (define (pkey->rsa-key pk private?)
    (let ((rsa (EVP_PKEY_get1_RSA pk)))
      (when (zero? rsa)
        (ERR_clear_error)
        (EVP_PKEY_free pk)
        (rsa-fail "not an RSA key"))
      ;; extract first, free the RSA handle exactly once afterwards: freeing
      ;; inside the guarded region would let a raise from the tail free it
      ;; twice
      (let ((parts
              (guard (e (#t (RSA_free rsa) (EVP_PKEY_free pk) (raise e)))
                (let ((np (make-bytevector 8 0))
                      (ep (make-bytevector 8 0))
                      (dp (make-bytevector 8 0)))
                  (RSA_get0_key rsa np ep dp)
                  (let ((n (ptr-ref np)) (e (ptr-ref ep)))
                    (when (or (zero? n) (zero? e))
                      (rsa-fail "RSA key carries no modulus/exponent"))
                    (let ((bits (BN_num_bits n)))
                      (when (fx< bits 1)
                        (rsa-fail "RSA key has a zero modulus"))
                      (list (bn->bytes n) (bn->bytes e) bits)))))))
        (RSA_free rsa)
        (mk-rsa-key pk private? (car parts) (cadr parts) (caddr parts)))))

  (define (rsa-private-key-from-pem pem)
    (let* ((bv (pem-bytes 'rsa-private-key-from-pem pem))
           (pk (with-bio bv (lambda (bio) (PEM_read_bio_PrivateKey bio 0 0 no-passphrase)))))
      (when (zero? pk)
        (ERR_clear_error)
        (rsa-fail "PEM_read_bio_PrivateKey failed (unencrypted PKCS#8/PKCS#1 PEM expected)"))
      (pkey->rsa-key pk #t)))

  ;; SubjectPublicKeyInfo: "-----BEGIN PUBLIC KEY-----"
  (define (try-pem-pubkey bv)
    (let ((pk (with-bio bv (lambda (bio) (PEM_read_bio_PUBKEY bio 0 0 no-passphrase)))))
      (if (zero? pk) (begin (ERR_clear_error) #f) pk)))

  ;; X.509 certificate: "-----BEGIN CERTIFICATE-----". The certificate itself
  ;; is a wrapper around the key; nothing here validates a chain or a validity
  ;; window, which is (igropyr apple-jws)'s job for the chains it pins. Taking
  ;; a key out of a certificate is not trusting the certificate.
  (define (try-pem-cert bv)
    (let ((x (with-bio bv (lambda (bio) (PEM_read_bio_X509 bio 0 0 no-passphrase)))))
      (if (zero? x)
          (begin (ERR_clear_error) #f)
          (let ((pk (X509_get_pubkey x)))
            (X509_free x)
            (if (zero? pk) (begin (ERR_clear_error) #f) pk)))))

  ;; PKCS#1: "-----BEGIN RSA PUBLIC KEY-----" (an RSAPublicKey, no algorithm
  ;; identifier around it). Older tooling still emits this.
  (define (try-pem-pkcs1 bv)
    (let ((rsa (with-bio bv (lambda (bio) (PEM_read_bio_RSAPublicKey bio 0 0 no-passphrase)))))
      (if (zero? rsa)
          (begin (ERR_clear_error) #f)
          (let ((pk (EVP_PKEY_new)))
            (cond
              ((zero? pk) (RSA_free rsa) (ERR_clear_error) #f)
              ((not (fx= 1 (EVP_PKEY_set1_RSA pk rsa)))
               (EVP_PKEY_free pk) (RSA_free rsa) (ERR_clear_error) #f)
              (else (RSA_free rsa) pk))))))   ; pkey holds its own reference

  ;; Postel again: three encodings all mean "here is a public key", so try
  ;; each rather than making the caller sniff the label and pick a procedure.
  ;; The output is narrow either way -- one key record, or a raise.
  (define (rsa-public-key-from-pem pem)
    (let* ((bv (pem-bytes 'rsa-public-key-from-pem pem))
           (pk (or (try-pem-pubkey bv) (try-pem-cert bv) (try-pem-pkcs1 bv))))
      (unless pk
        (rsa-fail "not a PEM public key (expected BEGIN PUBLIC KEY, BEGIN CERTIFICATE or BEGIN RSA PUBLIC KEY)"))
      (pkey->rsa-key pk #f)))

  ;; n-bytes / e-bytes: big-endian magnitudes, the form JWK, DNSKEY and SSH
  ;; wire encodings publish.
  (define (rsa-public-key-from-modulus n-bytes e-bytes)
    (let ((nb (need-bv 'rsa-public-key-from-modulus "modulus" n-bytes))
          (eb (need-bv 'rsa-public-key-from-modulus "exponent" e-bytes)))
      (when (or (fx= 0 (bytevector-length nb)) (fx= 0 (bytevector-length eb)))
        (assertion-violation 'rsa-public-key-from-modulus
          "modulus and exponent must be non-empty"
          (list (bytevector-length nb) (bytevector-length eb))))
      (let ((n (BN_bin2bn nb (bytevector-length nb) 0))
            (e (BN_bin2bn eb (bytevector-length eb) 0)))
        (when (or (zero? n) (zero? e))
          (unless (zero? n) (BN_free n))
          (unless (zero? e) (BN_free e))
          (ERR_clear_error)
          (rsa-fail "BN_bin2bn failed"))
        (when (or (fx< (BN_num_bits n) 1) (fx< (BN_num_bits e) 1))
          (BN_free n) (BN_free e)
          (rsa-fail "modulus and exponent must be non-zero"))
        (let ((rsa (RSA_new)))
          (when (zero? rsa)
            (BN_free n) (BN_free e) (rsa-fail "RSA_new failed"))
          (unless (fx= 1 (RSA_set0_key rsa n e 0))
            (RSA_free rsa) (BN_free n) (BN_free e)
            (ERR_clear_error)
            (rsa-fail "RSA_set0_key failed"))
          ;; n and e belong to rsa from here; freeing rsa frees them
          (let ((pk (EVP_PKEY_new)))
            (when (zero? pk)
              (RSA_free rsa) (rsa-fail "EVP_PKEY_new failed"))
            (unless (fx= 1 (EVP_PKEY_set1_RSA pk rsa))
              (EVP_PKEY_free pk) (RSA_free rsa)
              (ERR_clear_error)
              (rsa-fail "EVP_PKEY_set1_RSA failed"))
            (RSA_free rsa)                    ; pkey holds its own reference
            (pkey->rsa-key pk #f))))))

  (define (read-file-bytes who path)
    (unless (string? path)
      (assertion-violation who "path must be a string" path))
    (call-with-port (open-file-input-port path)
      (lambda (p) (get-bytevector-all p))))

  (define (rsa-load-private-key path)
    (rsa-private-key-from-pem (read-file-bytes 'rsa-load-private-key path)))

  (define (rsa-load-public-key path)
    (rsa-public-key-from-pem (read-file-bytes 'rsa-load-public-key path)))

  ;; ---- signing -----------------------------------------------------------

  ;; A public-only key cannot sign. libcrypto would refuse too, but it refuses
  ;; several sentences later and blames EVP_DigestSignInit; say it here.
  (define (rsa-sign-sha256 k input)
    (need-key 'rsa-sign-sha256 k)
    (need-bv 'rsa-sign-sha256 "input" input)
    (unless (rsa-key-private? k)
      (rsa-fail "rsa-sign-sha256: key is public only"))
    (let ((pk (live-pkey 'rsa-sign-sha256 k))
          (ctx (EVP_MD_CTX_new)))
      (when (zero? ctx) (rsa-fail "EVP_MD_CTX_new failed"))
      (guard (e (#t (EVP_MD_CTX_free ctx) (ERR_clear_error) (raise e)))
        (unless (fx= 1 (EVP_DigestSignInit ctx 0 (EVP_sha256) 0 pk))
          (rsa-fail "EVP_DigestSignInit failed"))
        (unless (fx= 1 (EVP_DigestUpdate ctx input (bytevector-length input)))
          (rsa-fail "EVP_DigestUpdate failed"))
        (let ((lenbuf (make-bytevector 8 0)))
          (unless (fx= 1 (EVP_DigestSignFinal-len ctx 0 lenbuf))
            (rsa-fail "EVP_DigestSignFinal(len) failed"))
          (let* ((cap (bytevector-u64-native-ref lenbuf 0))
                 (sig (make-bytevector cap 0)))
            (unless (fx= 1 (EVP_DigestSignFinal ctx sig lenbuf))
              (rsa-fail "EVP_DigestSignFinal failed"))
            ;; the shrink happens BEFORE the free, and the free is the last
            ;; thing in the guarded region: allocating after it would leave
            ;; a window where a failed allocation re-entered the handler and
            ;; freed the same context a second time
            (let* ((n (bytevector-u64-native-ref lenbuf 0))
                   (out (if (fx= n cap)
                            sig
                            (let ((o (make-bytevector n)))
                              (bytevector-copy! sig 0 o 0 n)
                              o))))
              (EVP_MD_CTX_free ctx)
              out))))))

  ;; ---- verification ------------------------------------------------------

  ;; #t or #f, never a raise for a bad signature -- the signature is
  ;; attacker-supplied and "no" is the answer. The error queue is cleared on
  ;; the way out of a failure so a rejected signature cannot make an
  ;; unrelated later libcrypto call report the wrong reason.
  (define (rsa-verify-sha256 k input sig)
    (need-key 'rsa-verify-sha256 k)
    (need-bv 'rsa-verify-sha256 "input" input)
    (need-bv 'rsa-verify-sha256 "signature" sig)
    (let ((pk (live-pkey 'rsa-verify-sha256 k))
          (ctx (EVP_MD_CTX_new)))
      (when (zero? ctx) (rsa-fail "EVP_MD_CTX_new failed"))
      (let ((ok (guard (e (#t (EVP_MD_CTX_free ctx) (ERR_clear_error) (raise e)))
                  (and (fx= 1 (EVP_DigestVerifyInit ctx 0 (EVP_sha256) 0 pk))
                       (fx= 1 (EVP_DigestUpdate ctx input
                                (bytevector-length input)))
                       (fx= 1 (EVP_DigestVerifyFinal ctx sig
                                (bytevector-length sig)))))))
        (EVP_MD_CTX_free ctx)
        (unless ok (ERR_clear_error))
        ok)))
)
