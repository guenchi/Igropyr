#!chezscheme
;;; (igropyr aead) -- AES-256-GCM: authenticated encryption with associated
;;; data, over arbitrary bytes.
;;;
;;; GCM gives confidentiality for the plaintext AND integrity for both the
;;; plaintext and the associated data. The associated data travels in the
;;; clear but is bound to the ciphertext: bind the context an attacker must
;;; not be able to swap (a record id, a purpose string, a version) into it
;;; and a ciphertext lifted from one context stops decrypting in another.
;;;
;;;   (import (igropyr aead))
;;;   (define key (aead-random-bytes aes-256-gcm-key-bytes))   ; 32, kept safe
;;;   (define iv  (aead-random-bytes aes-256-gcm-iv-bytes))    ; 12, FRESH
;;;
;;;   (define sealed (aes-256-gcm-seal key iv plaintext aad))  ; ct || tag
;;;   (aes-256-gcm-open key iv sealed aad)                     ; -> pt | #f
;;;
;;; seal/open is the pair to reach for: the tag travels with the ciphertext,
;;; so it cannot be dropped or forgotten, and open answers #f rather than
;;; plaintext for anything that fails to authenticate. When a wire format
;;; puts the tag in its own field, encrypt/decrypt expose it:
;;;
;;;   (aes-256-gcm-encrypt key iv plaintext aad)   ; -> #(ciphertext tag)
;;;   (aes-256-gcm-decrypt key iv ciphertext aad tag)  ; -> plaintext | #f
;;;
;;; aad may be #f or an empty bytevector, which mean the same thing to GCM.
;;;
;;; THE IV MUST NEVER REPEAT UNDER ONE KEY. Two messages encrypted with the
;;; same key and IV leak the XOR of their plaintexts and, worse, hand an
;;; attacker enough to forge tags for that key. This library will not
;;; generate the IV for you, because the only safe generator depends on how
;;; you store messages: a fresh random 12 bytes per message (what
;;; aead-random-bytes is for) is right when you have nowhere to keep a
;;; counter, and a counter is right when you do.
;;;
;;; What raises and what answers #f is a deliberate split. A wrong key or IV
;;; SIZE is the caller's own configuration and raises immediately. A tag or
;;; a ciphertext that fails to authenticate -- including a tag of the wrong
;;; length, which can never authenticate -- is attacker-supplied input, and
;;; the answer is #f. Decryption never returns partial or unauthenticated
;;; plaintext: the buffer is handed back only after the tag check passes.
;;;
;;; libcrypto FFI, the same OpenSSL (igropyr tls) and (igropyr kdf) load.
;;; Only AES-256 is offered; a 128-bit variant would be a second name to
;;; confuse for this one, at no gain.

(library (igropyr aead)
  (export aes-256-gcm-encrypt aes-256-gcm-decrypt
          aes-256-gcm-seal aes-256-gcm-open
          aes-256-gcm-key-bytes aes-256-gcm-iv-bytes aes-256-gcm-tag-bytes
          aead-random-bytes)
  (import (chezscheme) (igropyr platform))

  (define (aead-fail msg) (raise (vector 'aead-error msg)))

  ;; ---- libcrypto ---------------------------------------------------------

  (define _libcrypto
    (load-first-shared-object! 'igropyr-aead
      (shared-object-candidates "libcrypto")))

  (define EVP_CIPHER_CTX_new  (foreign-procedure "EVP_CIPHER_CTX_new" () void*))
  (define EVP_CIPHER_CTX_free (foreign-procedure "EVP_CIPHER_CTX_free" (void*) void))
  (define EVP_aes_256_gcm     (foreign-procedure "EVP_aes_256_gcm" () void*))
  ;; Init_ex is called twice with different NULLs, so it is declared twice:
  ;; once to install the cipher (key and iv NULL) and once to install the key
  ;; and iv (cipher NULL), which is the order GCM requires when the IV length
  ;; is set between them.
  (define EVP_EncryptInit_ex/cipher
    (foreign-procedure "EVP_EncryptInit_ex" (void* void* void* void* void*) int))
  (define EVP_EncryptInit_ex/key
    (foreign-procedure "EVP_EncryptInit_ex" (void* void* void* u8* u8*) int))
  (define EVP_DecryptInit_ex/cipher
    (foreign-procedure "EVP_DecryptInit_ex" (void* void* void* void* void*) int))
  (define EVP_DecryptInit_ex/key
    (foreign-procedure "EVP_DecryptInit_ex" (void* void* void* u8* u8*) int))
  ;; a NULL output buffer is how associated data is fed in
  (define EVP_EncryptUpdate/aad
    (foreign-procedure "EVP_EncryptUpdate" (void* void* u8* u8* int) int))
  (define EVP_EncryptUpdate
    (foreign-procedure "EVP_EncryptUpdate" (void* u8* u8* u8* int) int))
  (define EVP_DecryptUpdate/aad
    (foreign-procedure "EVP_DecryptUpdate" (void* void* u8* u8* int) int))
  (define EVP_DecryptUpdate
    (foreign-procedure "EVP_DecryptUpdate" (void* u8* u8* u8* int) int))
  (define EVP_EncryptFinal_ex
    (foreign-procedure "EVP_EncryptFinal_ex" (void* u8* u8*) int))
  (define EVP_DecryptFinal_ex
    (foreign-procedure "EVP_DecryptFinal_ex" (void* u8* u8*) int))
  (define EVP_CIPHER_CTX_ctrl
    (foreign-procedure "EVP_CIPHER_CTX_ctrl" (void* int int u8*) int))
  (define EVP_CIPHER_CTX_ctrl/null
    (foreign-procedure "EVP_CIPHER_CTX_ctrl" (void* int int void*) int))
  (define RAND_bytes (foreign-procedure "RAND_bytes" (u8* int) int))
  (define ERR_clear_error (foreign-procedure "ERR_clear_error" () void))

  ;; EVP_CTRL_AEAD_* -- stable across OpenSSL 1.1 and 3.x
  (define EVP_CTRL_GCM_SET_IVLEN #x9)
  (define EVP_CTRL_GCM_GET_TAG   #x10)
  (define EVP_CTRL_GCM_SET_TAG   #x11)

  (define aes-256-gcm-key-bytes 32)
  (define aes-256-gcm-iv-bytes  12)     ; the 96-bit IV GCM is specified for
  (define aes-256-gcm-tag-bytes 16)     ; full-length tag; nothing truncated

  ;; libcrypto's CSPRNG (already loaded, OS-seeded, fork-safe).
  (define (aead-random-bytes n)
    (unless (and (fixnum? n) (fx> n 0))
      (assertion-violation 'aead-random-bytes "n must be a positive fixnum" n))
    (let ((bv (make-bytevector n)))
      (if (fx= 1 (RAND_bytes bv n))
          bv
          (aead-fail "RAND_bytes failed"))))

  ;; ---- argument shapes ---------------------------------------------------

  (define (need-bv who what x)
    (unless (bytevector? x)
      (assertion-violation who (string-append what " must be a bytevector") x))
    x)

  (define (check-key who key)
    (need-bv who "key" key)
    (unless (fx= aes-256-gcm-key-bytes (bytevector-length key))
      (assertion-violation who "key must be exactly 32 bytes (AES-256)"
                           (bytevector-length key)))
    key)

  ;; A 96-bit IV is what GCM is specified for and what everything
  ;; interoperable uses; other lengths are legal (GCM derives the counter
  ;; block by hashing them) and are accepted, because a caller reading a
  ;; foreign format does not get to choose. Empty is not legal anywhere.
  (define (check-iv who iv)
    (need-bv who "iv" iv)
    (when (fx= 0 (bytevector-length iv))
      (assertion-violation who "iv must not be empty" iv))
    iv)

  (define empty-bytes (make-bytevector 0))

  (define (check-aad who aad)
    (cond ((not aad) empty-bytes)
          ((bytevector? aad) aad)
          (else (assertion-violation who
                  "aad must be a bytevector or #f" aad))))

  (define (with-cipher-ctx proc)
    (let ((ctx (EVP_CIPHER_CTX_new)))
      (when (zero? ctx) (aead-fail "EVP_CIPHER_CTX_new failed"))
      (dynamic-wind
        (lambda () (void))
        (lambda () (proc ctx))
        (lambda () (EVP_CIPHER_CTX_free ctx)))))

  ;; int* out-parameter
  (define (make-outl) (make-bytevector 4 0))
  (define (outl-ref b) (bytevector-s32-native-ref b 0))

  ;; EVP_*Update with inl = 0 and a non-NULL in is the documented way to
  ;; signal "the AAD is finished", not "here is nothing" -- so an empty AAD
  ;; or an empty plaintext skips the call entirely rather than making it.
  (define (feed-aad! who ctx update/aad outl ad)
    (let ((n (bytevector-length ad)))
      (unless (fx= 0 n)
        (unless (fx= 1 (update/aad ctx 0 outl ad n))
          (aead-fail (string-append (symbol->string who) ": AAD rejected"))))))

  ;; ---- encryption --------------------------------------------------------

  ;; -> #(ciphertext tag). The ciphertext is exactly as long as the
  ;; plaintext (GCM is a counter mode); the tag is always 16 bytes.
  (define (aes-256-gcm-encrypt key iv plaintext aad)
    (let ((who 'aes-256-gcm-encrypt))
      (check-key who key)
      (check-iv who iv)
      (need-bv who "plaintext" plaintext)
      (let ((ad (check-aad who aad))
            (ptlen (bytevector-length plaintext)))
        (with-cipher-ctx
          (lambda (ctx)
            (let ((outl (make-outl))
                  ;; +16: a block's slack, so a mode that is not
                  ;; length-preserving cannot write past the end. GCM never
                  ;; uses it, and the length check below says so out loud.
                  (buf (make-bytevector (fx+ ptlen 16) 0))
                  (tag (make-bytevector aes-256-gcm-tag-bytes 0)))
              (unless (fx= 1 (EVP_EncryptInit_ex/cipher ctx (EVP_aes_256_gcm) 0 0 0))
                (aead-fail "EVP_EncryptInit_ex(cipher) failed"))
              (unless (fx= 1 (EVP_CIPHER_CTX_ctrl/null ctx EVP_CTRL_GCM_SET_IVLEN
                                                       (bytevector-length iv) 0))
                (aead-fail "EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed"))
              (unless (fx= 1 (EVP_EncryptInit_ex/key ctx 0 0 key iv))
                (aead-fail "EVP_EncryptInit_ex(key) failed"))
              (feed-aad! who ctx EVP_EncryptUpdate/aad outl ad)
              (let ((n (if (fx= 0 ptlen)
                           0
                           (begin
                             (unless (fx= 1 (EVP_EncryptUpdate ctx buf outl
                                                               plaintext ptlen))
                               (aead-fail "EVP_EncryptUpdate failed"))
                             (outl-ref outl)))))
                (let ((fin (make-bytevector 16 0)))
                  (unless (fx= 1 (EVP_EncryptFinal_ex ctx fin outl))
                    (aead-fail "EVP_EncryptFinal_ex failed"))
                  (let* ((m (outl-ref outl)) (total (fx+ n m)))
                    (when (fx> m 0) (bytevector-copy! fin 0 buf n m))
                    (unless (fx= total ptlen)
                      (aead-fail "ciphertext length does not match plaintext"))
                    (unless (fx= 1 (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_GCM_GET_TAG
                                                        aes-256-gcm-tag-bytes tag))
                      (aead-fail "EVP_CIPHER_CTX_ctrl(GET_TAG) failed"))
                    (let ((ct (make-bytevector total)))
                      (bytevector-copy! buf 0 ct 0 total)
                      (vector ct tag)))))))))))

  ;; ---- decryption --------------------------------------------------------

  ;; -> plaintext bytevector, or #f if anything fails to authenticate.
  ;; Nothing is returned before EVP_DecryptFinal_ex has checked the tag.
  (define (aes-256-gcm-decrypt key iv ciphertext aad tag)
    (let ((who 'aes-256-gcm-decrypt))
      (check-key who key)
      (check-iv who iv)
      (need-bv who "ciphertext" ciphertext)
      (need-bv who "tag" tag)
      (let ((ad (check-aad who aad))
            (ctlen (bytevector-length ciphertext)))
        ;; a truncated tag can never authenticate -- refusing it here is the
        ;; same answer, reached without touching the cipher
        (and (fx= aes-256-gcm-tag-bytes (bytevector-length tag))
             (with-cipher-ctx
               (lambda (ctx)
                 (let ((outl (make-outl))
                       (buf (make-bytevector (fx+ ctlen 16) 0)))
                   (unless (fx= 1 (EVP_DecryptInit_ex/cipher ctx (EVP_aes_256_gcm) 0 0 0))
                     (aead-fail "EVP_DecryptInit_ex(cipher) failed"))
                   (unless (fx= 1 (EVP_CIPHER_CTX_ctrl/null ctx EVP_CTRL_GCM_SET_IVLEN
                                                            (bytevector-length iv) 0))
                     (aead-fail "EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed"))
                   (unless (fx= 1 (EVP_DecryptInit_ex/key ctx 0 0 key iv))
                     (aead-fail "EVP_DecryptInit_ex(key) failed"))
                   (feed-aad! who ctx EVP_DecryptUpdate/aad outl ad)
                   (let ((n (if (fx= 0 ctlen)
                                0
                                (begin
                                  (unless (fx= 1 (EVP_DecryptUpdate ctx buf outl
                                                                    ciphertext ctlen))
                                    (aead-fail "EVP_DecryptUpdate failed"))
                                  (outl-ref outl)))))
                     (unless (fx= 1 (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_GCM_SET_TAG
                                                         aes-256-gcm-tag-bytes tag))
                       (aead-fail "EVP_CIPHER_CTX_ctrl(SET_TAG) failed"))
                     (let ((fin (make-bytevector 16 0)))
                       (if (fx= 1 (EVP_DecryptFinal_ex ctx fin outl))
                           (let* ((m (outl-ref outl)) (total (fx+ n m)))
                             (when (fx> m 0) (bytevector-copy! fin 0 buf n m))
                             (let ((pt (make-bytevector total)))
                               (bytevector-copy! buf 0 pt 0 total)
                               pt))
                           ;; authentication failed: no plaintext leaves here,
                           ;; and the failure does not stay on the error queue
                           (begin (ERR_clear_error) #f)))))))))))

  ;; ---- ciphertext with the tag attached ----------------------------------

  (define (aes-256-gcm-seal key iv plaintext aad)
    (let* ((r (aes-256-gcm-encrypt key iv plaintext aad))
           (ct (vector-ref r 0))
           (tag (vector-ref r 1))
           (n (bytevector-length ct))
           (out (make-bytevector (fx+ n aes-256-gcm-tag-bytes))))
      (bytevector-copy! ct 0 out 0 n)
      (bytevector-copy! tag 0 out n aes-256-gcm-tag-bytes)
      out))

  (define (aes-256-gcm-open key iv sealed aad)
    (let ((who 'aes-256-gcm-open))
      (check-key who key)
      (check-iv who iv)
      (need-bv who "sealed" sealed)
      ;; too short to hold a tag: attacker-supplied, so #f, not a raise
      (let ((len (bytevector-length sealed)))
        (and (fx>= len aes-256-gcm-tag-bytes)
             (let* ((n (fx- len aes-256-gcm-tag-bytes))
                    (ct (make-bytevector n))
                    (tag (make-bytevector aes-256-gcm-tag-bytes)))
               (bytevector-copy! sealed 0 ct 0 n)
               (bytevector-copy! sealed n tag 0 aes-256-gcm-tag-bytes)
               (aes-256-gcm-decrypt key iv ct aad tag))))))
)
