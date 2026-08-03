#!chezscheme
;;; (igropyr jwks) -- RSA keys, RS256 signing/verification, and JWKS.
;;;
;;; The asymmetric half of (igropyr jwt). HS256 authenticates with a shared
;;; secret, so every party that can verify can also mint; RS256 splits that,
;;; which is what lets one service issue tokens a different service (or a
;;; different operator) can check without being able to forge them. The
;;; public half travels as a JWKS document.
;;;
;;;   jwks-load-key      PEM path -> key record (private, can sign)
;;;   jwks-key-id        key -> kid string
;;;   jwks-document      key -> the JWKS JSON body to serve
;;;   jwks-sign          (key claims) -> compact JWT string
;;;   jwks-verify        (token jwks-url opts) -> claims alist | #f
;;;   jwks-fetch!        url -> jwks (forced refetch; verify uses the cache)
;;;   jwks-cache-clear!  drop cached documents (tests, key rotation drills)
;;;
;;; jwks-verify mirrors jwt-verify: fail-closed, and every failure -- bad
;;; format, wrong alg, unknown kid, bad signature, expired, wrong iss/aud --
;;; is the same #f. A caller needing to tell them apart (to log, or to answer
;;; a specific status) should classify before calling rather than have this
;;; leak which check failed to whoever supplied the token.
;;;
;;; RSA is libcrypto FFI. The deprecated-but-exported RSA_get0_key /
;;; RSA_set0_key / EVP_PKEY_set1_RSA path is used because it is present in
;;; OpenSSL 1.1 and 3.x alike, unlike the 3.x-only EVP_PKEY_fromdata.
;;;
;;; Not implemented: ES256/EdDSA, encrypted PEM keys, JWKS x5c chains.

(library (igropyr jwks)
  (export jwks-load-key jwks-key-id jwks-document
          jwks-sign jwks-verify
          jwks-fetch! jwks-cache-clear!)
  (import (chezscheme) (igropyr checked) (igropyr util)
          (igropyr platform) (igropyr crypto) (igropyr json)
          (igropyr http-client))

  (define (jwks-fail msg) (raise (vector 'jwks-error msg)))

  ;; ---- libcrypto ---------------------------------------------------------

  (define _libcrypto
    (load-first-shared-object! 'igropyr-jwks
      (shared-object-candidates "libcrypto")))

  (define BIO_new_mem_buf (foreign-procedure "BIO_new_mem_buf" (u8* int) void*))
  (define BIO_free        (foreign-procedure "BIO_free" (void*) int))
  (define PEM_read_bio_PrivateKey
    (foreign-procedure "PEM_read_bio_PrivateKey" (void* void* void* void*) void*))
  (define EVP_PKEY_new    (foreign-procedure "EVP_PKEY_new" () void*))
  (define EVP_PKEY_free   (foreign-procedure "EVP_PKEY_free" (void*) void))
  (define EVP_PKEY_get1_RSA (foreign-procedure "EVP_PKEY_get1_RSA" (void*) void*))
  (define EVP_PKEY_set1_RSA (foreign-procedure "EVP_PKEY_set1_RSA" (void* void*) int))
  (define RSA_new         (foreign-procedure "RSA_new" () void*))
  (define RSA_free        (foreign-procedure "RSA_free" (void*) void))
  ;; out-params: BIGNUM** written into 8-byte buffers (LP64 on every target)
  (define RSA_get0_key    (foreign-procedure "RSA_get0_key" (void* u8* u8* u8*) void))
  (define RSA_set0_key    (foreign-procedure "RSA_set0_key" (void* void* void* void*) int))
  (define BN_new          (foreign-procedure "BN_new" () void*))
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

  (define (ptr-ref bv) (bytevector-u64-native-ref bv 0))

  (define (bn->bytes bn)
    (let* ((len (fxdiv (fx+ (BN_num_bits bn) 7) 8))
           (buf (make-bytevector len 0)))
      (unless (fx= len (BN_bn2bin bn buf)) (jwks-fail "BN_bn2bin length"))
      buf))

  ;; ---- key loading -------------------------------------------------------

  (define-record-type (jwks-key mk-jwks-key jwks-key?)
    (fields pkey n-b64 e-b64 kid))

  ;; kid = the first 16 hex characters of sha256(modulus). Deriving it from
  ;; the key rather than assigning one keeps it stable across restarts and
  ;; across every process that loads the same PEM, and makes it change if and
  ;; only if the key does -- which is precisely what a verifier needs a kid to
  ;; tell it, and what a hand-assigned name gets wrong during rotation.
  (define-checked (jwks-load-key (path string?))
    (let* ((pem (call-with-port (open-file-input-port path)
                  (lambda (p) (get-bytevector-all p))))
           (bio (BIO_new_mem_buf pem (bytevector-length pem))))
      (when (zero? bio) (jwks-fail "BIO_new_mem_buf failed"))
      (let ((pk (PEM_read_bio_PrivateKey bio 0 0 0)))
        (BIO_free bio)
        (when (zero? pk)
          (jwks-fail "PEM_read_bio_PrivateKey failed (unencrypted PKCS#8/PKCS#1 PEM expected)"))
        (let ((rsa (EVP_PKEY_get1_RSA pk)))
          (when (zero? rsa)
            (EVP_PKEY_free pk) (jwks-fail "not an RSA key"))
          (let ((np (make-bytevector 8 0)) (ep (make-bytevector 8 0))
                (dp (make-bytevector 8 0)))
            (RSA_get0_key rsa np ep dp)
            (let* ((n-bytes (bn->bytes (ptr-ref np)))
                   (e-bytes (bn->bytes (ptr-ref ep)))
                   (kid (substring (bytevector->hex (sha256 n-bytes)) 0 16)))
              (RSA_free rsa)
              (mk-jwks-key pk (base64url-encode n-bytes)
                           (base64url-encode e-bytes) kid)))))))

  (define-checked (jwks-key-id (k jwks-key?)) (jwks-key-kid k))

  ;; The document to serve at /.well-known/jwks.json. Compute once and cache
  ;; it in the application: it only changes when the key does.
  (define-checked (jwks-document (k jwks-key?))
    (json->string
      `(("keys" . ,(vector
                     `(("kty" . "RSA") ("alg" . "RS256") ("use" . "sig")
                       ("kid" . ,(jwks-key-kid k))
                       ("n" . ,(jwks-key-n-b64 k))
                       ("e" . ,(jwks-key-e-b64 k))))))))

  ;; ---- signing -----------------------------------------------------------

  (define (rs256-sign k input)          ; bytevector -> signature bytevector
    (let ((ctx (EVP_MD_CTX_new)))
      (when (zero? ctx) (jwks-fail "EVP_MD_CTX_new failed"))
      (guard (e (#t (EVP_MD_CTX_free ctx) (raise e)))
        (unless (fx= 1 (EVP_DigestSignInit ctx 0 (EVP_sha256) 0 (jwks-key-pkey k)))
          (jwks-fail "EVP_DigestSignInit failed"))
        (unless (fx= 1 (EVP_DigestUpdate ctx input (bytevector-length input)))
          (jwks-fail "EVP_DigestUpdate failed"))
        (let ((lenbuf (make-bytevector 8 0)))
          (unless (fx= 1 (EVP_DigestSignFinal-len ctx 0 lenbuf))
            (jwks-fail "EVP_DigestSignFinal(len) failed"))
          (let* ((cap (bytevector-u64-native-ref lenbuf 0))
                 (sig (make-bytevector cap 0)))
            (unless (fx= 1 (EVP_DigestSignFinal ctx sig lenbuf))
              (jwks-fail "EVP_DigestSignFinal failed"))
            (let ((n (bytevector-u64-native-ref lenbuf 0)))
              (EVP_MD_CTX_free ctx)
              (if (fx= n cap)
                  sig
                  (let ((out (make-bytevector n)))
                    (bytevector-copy! sig 0 out 0 n)
                    out))))))))

  (define (now-sec) (time-second (current-time)))

  ;; claims: an alist with symbol or string keys, matching jwt-sign. With
  ;; '((expires-in . N)) it stamps iat = now and exp = now + N unless the
  ;; caller already supplied them; registered claims are otherwise the
  ;; caller's business -- this signs what it is given.
  ;; not define-checked: it does not take a rest argument, and the options
  ;; alist is optional here the same way it is on jwt-sign
  (define (jwks-sign k claims . rest)
    (unless (jwks-key? k)
      (assertion-violation 'jwks-sign "not a jwks key" k))
    (unless (list? claims)
      (assertion-violation 'jwks-sign "claims must be an alist" claims))
    (let* ((o (if (pair? rest) (car rest) '()))
           (expires-in (opt o 'expires-in #f))
           (now (now-sec))
           (has? (lambda (name)
                   (or (assq (string->symbol name) claims)
                       (assoc name claims))))
           (full (append
                   (if (and expires-in (not (has? "iat"))) `((iat . ,now)) '())
                   (if (and expires-in (not (has? "exp")))
                       `((exp . ,(+ now expires-in)))
                       '())
                   claims))
           (header (json->string
                     `(("alg" . "RS256") ("typ" . "JWT")
                       ("kid" . ,(jwks-key-kid k)))))
           (h64 (base64url-encode (string->utf8 header)))
           (p64 (base64url-encode (string->utf8 (json->string full))))
           (input (string->utf8 (string-append h64 "." p64)))
           (s64 (base64url-encode (rs256-sign k input))))
      (string-append h64 "." p64 "." s64)))

  ;; ---- verification ------------------------------------------------------

  ;; n-bytes / e-bytes: big-endian magnitudes straight from the JWK.
  (define (rs256-verify n-bytes e-bytes signing-input sig)
    (let ((n (BN_bin2bn n-bytes (bytevector-length n-bytes) 0))
          (e (BN_bin2bn e-bytes (bytevector-length e-bytes) 0)))
      (when (or (zero? n) (zero? e))
        (unless (zero? n) (BN_free n))
        (unless (zero? e) (BN_free e))
        (jwks-fail "BN_bin2bn failed"))
      (let ((rsa (RSA_new)))
        (when (zero? rsa)
          (BN_free n) (BN_free e) (jwks-fail "RSA_new failed"))
        (unless (fx= 1 (RSA_set0_key rsa n e 0))
          (RSA_free rsa) (BN_free n) (BN_free e)
          (jwks-fail "RSA_set0_key failed"))
        ;; n and e belong to rsa from here; freeing rsa frees them
        (let ((pk (EVP_PKEY_new)))
          (when (zero? pk)
            (RSA_free rsa) (jwks-fail "EVP_PKEY_new failed"))
          (unless (fx= 1 (EVP_PKEY_set1_RSA pk rsa))
            (EVP_PKEY_free pk) (RSA_free rsa)
            (jwks-fail "EVP_PKEY_set1_RSA failed"))
          (RSA_free rsa)                      ; pkey holds its own reference
          (let ((ctx (EVP_MD_CTX_new)))
            (when (zero? ctx)
              (EVP_PKEY_free pk) (jwks-fail "EVP_MD_CTX_new failed"))
            (let ((ok (guard (e (#t (EVP_MD_CTX_free ctx) (EVP_PKEY_free pk)
                                    (raise e)))
                        (and (fx= 1 (EVP_DigestVerifyInit ctx 0 (EVP_sha256) 0 pk))
                             (fx= 1 (EVP_DigestUpdate ctx signing-input
                                      (bytevector-length signing-input)))
                             (fx= 1 (EVP_DigestVerifyFinal ctx sig
                                      (bytevector-length sig)))))))
              (EVP_MD_CTX_free ctx)
              (EVP_PKEY_free pk)
              ok))))))

  ;; ---- JWKS fetch + cache ------------------------------------------------

  (define jwks-cache (make-hashtable string-hash string=?))  ; url -> (jwks . at)
  ;; Actor processes are preemptive, and Chez hashtable operations are not a
  ;; safe interruption boundary while a table is being resized. Keep every
  ;; access in one short interrupt-free section. The generation also gives
  ;; cache-clear! a linearization point: a fetch that began before the clear
  ;; may still return its document to its caller, but cannot repopulate the
  ;; shared cache after the clear has completed.
  (define jwks-cache-generation 0)

  (define (cache-generation)
    (with-interrupts-disabled jwks-cache-generation))

  (define (cache-ref url)
    (with-interrupts-disabled
      (hashtable-ref jwks-cache url #f)))

  (define (cache-store-if-current! url entry generation)
    (with-interrupts-disabled
      (when (= generation jwks-cache-generation)
        (hashtable-set! jwks-cache url entry))))

  (define (cache-clear!)
    (with-interrupts-disabled
      (set! jwks-cache-generation (+ jwks-cache-generation 1))
      (hashtable-clear! jwks-cache)))

  (define jwks-ttl-s 21600)                                  ; 6h
  (define jwks-fetch-timeout-ms 10000)
  ;; A JWKS is a handful of keys; anything larger is not one, and the reply
  ;; is parsed into memory before anything about it is trusted.
  (define jwks-max-bytes 262144)

  ;; A kid miss may mean that the issuer rotated since the cached document
  ;; was fetched, so verification is allowed to force a refresh. The kid is
  ;; still attacker-controlled at that point, however: without a cooldown,
  ;; every distinct unknown kid drives another outbound HTTP request and can
  ;; exhaust both this service and the issuer. Keep the gate separate from
  ;; the document cache so this policy does not extend the cache's six-hour
  ;; lifetime. The alist mutation is tiny but shared by preemptive actors, so
  ;; it must be one interrupt-free operation.
  (define jwks-kid-refresh-cooldown-s 5)
  (define jwks-kid-refresh-at '())               ; url -> last attempt time

  (define (kid-refresh-slot-take! url)
    (with-interrupts-disabled
      (let* ((now (now-sec))
             (p (assoc url jwks-kid-refresh-at))
             (recent? (and p (>= now (cdr p))
                           (< (- now (cdr p)) jwks-kid-refresh-cooldown-s))))
        (if recent?
            #f
            (begin
              (if p
                  (set-cdr! p now)
                  (set! jwks-kid-refresh-at
                        (cons (cons url now) jwks-kid-refresh-at)))
              #t)))))

  (define-checked (jwks-fetch! (url string?))
    (let* ((generation (cache-generation))
           (r (guard (e (#t (jwks-fail "jwks fetch failed")))
               (http-request 'GET url
                 `((timeout . ,jwks-fetch-timeout-ms)
                   (max-response . ,jwks-max-bytes))))))
      (unless (= 200 (response-status r))
        (jwks-fail "jwks fetch non-200"))
      (let ((jwks (guard (e (#t (jwks-fail "jwks parse failed")))
                    (string->json (utf8->string (response-body r))))))
        (cache-store-if-current! url (cons jwks (now-sec)) generation)
        jwks)))

  (define (cached-jwks url)
    (let ((hit (cache-ref url)))
      (if (and hit (< (- (now-sec) (cdr hit)) jwks-ttl-s))
          (car hit)
          (jwks-fetch! url))))

  (define (jwks-cache-clear!) (cache-clear!))

  ;; JWKS document -> the key entry whose kid matches, or #f
  (define (jwks-key-for jwks kid)
    (let ((keys (json-ref jwks "keys")))
      (and (vector? keys)
           (let loop ((i 0))
             (and (fx< i (vector-length keys))
                  (let ((k (vector-ref keys i)))
                    (if (equal? (json-ref k "kid") kid)
                        k
                        (loop (fx+ i 1)))))))))

  (define (str-index s ch start)
    (let ((n (string-length s)))
      (let loop ((i start))
        (cond ((fx>= i n) #f)
              ((char=? (string-ref s i) ch) i)
              (else (loop (fx+ i 1)))))))

  (define (split-3 token)
    (let* ((d1 (str-index token #\. 0))
           (d2 (and d1 (str-index token #\. (fx+ d1 1)))))
      (and d1 d2
           (not (str-index token #\. (fx+ d2 1)))   ; exactly two dots
           (list (substring token 0 d1)
                 (substring token (fx+ d1 1) d2)
                 (substring token (fx+ d2 1) (string-length token))))))

  (define (aud-match? a expected)
    (cond
      ((equal? a expected) #t)
      ((vector? a) (let lp ((i 0))
                     (and (fx< i (vector-length a))
                          (or (equal? (vector-ref a i) expected)
                              (lp (fx+ i 1))))))
      ((list? a) (and (member expected a) #t))
      (else #f)))

  (define (time-claim-ok? claims name pred)
    (let ((p (or (assoc name claims) (assq (string->symbol name) claims))))
      (or (not p)
          (and (real? (cdr p)) (pred (cdr p))))))

  ;; Tokens are attacker-supplied; a length bound keeps a hostile one from
  ;; being decoded and parsed before anything about it is known.
  (define jwks-max-token 8192)

  ;; -> claims alist (possibly '(), still true) | #f. Same fail-closed
  ;; contract as jwt-verify: every failure is the same #f.
  ;; rest: one options alist -- (leeway . secs) (iss . str) (aud . str)
  (define (jwks-verify token url . rest)
    (guard (e (#t #f))                  ; malformed anything, or fetch failure
      (let* ((o (if (pair? rest) (car rest) '()))
             (leeway (opt o 'leeway 0))
             (iss (opt o 'iss #f))
             (aud (opt o 'aud #f))
             (parts (and (string? token)
                         (fx< (string-length token) jwks-max-token)
                         (split-3 token))))
        (and parts
             (let* ((h64 (car parts)) (p64 (cadr parts)) (s64 (caddr parts))
                    (header (string->json (utf8->string (base64url-decode h64)))))
               (and (list? header)
                    ;; The alg check is the SECOND lock, not the only one:
                    ;; this verifier never consults the header to choose an
                    ;; algorithm, it always runs RS256, so alg=none and the
                    ;; HS256 confusion attack already die at the signature.
                    ;; Deleting this line therefore breaks no test -- which is
                    ;; exactly why the line has to stay and say so. It refuses
                    ;; a token whose header claims something this code did not
                    ;; do, rather than leaving that to hold by accident of the
                    ;; call order below.
                    (equal? (json-ref header "alg") "RS256")
                    (let ((typ (json-ref header "typ")))
                      (or (not typ) (and (string? typ) (string-ci=? typ "JWT"))))
                    (let ((kid (json-ref header "kid")))
                      (and (string? kid)
                           ;; A kid miss may be a rotation. Force one refresh
                           ;; when this URL's cooldown grants the slot; misses
                           ;; during the cooldown fail closed without I/O.
                           (let ((jwk (or (jwks-key-for (cached-jwks url) kid)
                                          (and (kid-refresh-slot-take! url)
                                               (jwks-key-for
                                                 (jwks-fetch! url) kid)))))
                             (and jwk
                                  (let ((n (json-ref jwk "n"))
                                        (ev (json-ref jwk "e")))
                                    (and (string? n) (string? ev)
                                         (rs256-verify
                                           (base64url-decode n)
                                           (base64url-decode ev)
                                           (string->utf8
                                             (string-append h64 "." p64))
                                           (base64url-decode s64))))))))
                    ;; the signature holds: now, and only now, judge claims
                    (let ((claims (string->json (utf8->string (base64url-decode p64))))
                          (now (now-sec)))
                      (and (list? claims)
                           (time-claim-ok? claims "exp" (lambda (v) (< now (+ v leeway))))
                           (time-claim-ok? claims "nbf" (lambda (v) (>= now (- v leeway))))
                           (or (not iss) (equal? (json-ref claims "iss") iss))
                           (or (not aud) (aud-match? (json-ref claims "aud") aud))
                           claims)))))))))
