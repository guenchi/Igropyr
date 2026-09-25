#!chezscheme
;;; Copyright 2018 - 2026 guenchi.
;;;
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;;
;;; http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

;;; (igropyr apple-jws) -- verify Apple App Store Server (v2) JWS.
;;;
;;; App Store Server Notifications V2 and the App Store Server API deliver
;;; signed data as a compact JWS whose protected header carries the x5c
;;; certificate chain (leaf -> Apple WWDR intermediate -> Apple Root CA).
;;; This verifies one such token end to end and hands back the payload:
;;;
;;;   (import (igropyr apple-jws) (igropyr json))
;;;   (let ((payload (verify-apple-jws signed-payload)))     ; bytevector
;;;     (string->json (utf8->string payload)))               ; -> the claims
;;;
;;; On any failure it raises #(apple-jws-error CODE MESSAGE); CODE is a
;;; symbol so the caller can map it to an HTTP status (bad signature /
;;; chain / root / expiry are attacker-facing 401s; parse/internal are
;;; retryable 5xx):
;;;   not-jws bad-alg crit no-x5c cert-parse-failed invalid-root
;;;   chain-failed cert-expired sig-failed internal
;;;
;;; Verification (mirrors Apple's own app-store-server-library):
;;;   1. the header alg is ES256 (never trusted to pick the algorithm), and
;;;      the header has no crit member (no extension is understood here)
;;;   2. the x5c root's DER bytes equal a pinned trusted root (verify-apple-jws
;;;      pins Apple Root CA G3; verify-jws-x5c takes explicit roots)
;;;   3. OpenSSL validates the certificate path from the leaf to that root,
;;;      and the path it validated is exactly the presented chain
;;;   4. the leaf carries Apple's App Store Server signing OID
;;;      (1.2.840.113635.100.6.11.1) and the intermediate the WWDR OID
;;;      (1.2.840.113635.100.6.2.1) -- so a cert that merely chains to the
;;;      pinned root but is not the notification signer is rejected
;;;   5. the JWS signature, 64 bytes of R||S, verifies over SHA-256 under
;;;      the leaf's public key. The key's algorithm and curve are NOT checked,
;;;      so this is weaker than ES256, which requires ECDSA on P-256.
;;;
;;; WHAT STEP 3 PROMISES, AND WHAT IT DOES NOT. It is OpenSSL's path
;;; validation to a pinned anchor, under the default profile, with policy
;;; processing on and an initial policy set of anyPolicy, at the current
;;; time. The strict-profile rules (X509_V_FLAG_X509_STRICT) are NOT
;;; applied: whether Apple's real chain passes them has not been measured,
;;; and turning them on blind could refuse every genuine notification. That
;;; is a compatibility allowance, written here so it is not read as an
;;; oversight. There is no revocation checking -- no CRL, no OCSP.
;;;
;;; It is VERIFY-ONLY: no signing, so no App Store Server API JWT is
;;; produced here. The heavy lifting -- X.509 parsing, path validation,
;;; ECDSA -- is libcrypto via FFI, the same library (igropyr tls) loads.

(library (igropyr apple-jws)
  (export verify-apple-jws verify-jws-x5c apple-root-ca-g3-der)
  (import (chezscheme) (igropyr platform)
          (only (igropyr crypto) base64-decode base64url-decode)
          (only (igropyr json) string->json json-ref)
          (only (igropyr jose) jose-crit-present?))

  ;; ---- libcrypto (loaded explicitly, like (igropyr tls)) ----------------

  (define _libcrypto
    (load-first-shared-object! 'igropyr-apple-jws (shared-object-candidates "libcrypto")))

  ;; ---- FFI (pointers are machine integers; 0 is NULL) -------------------

  (define BIO_s_mem   (foreign-procedure "BIO_s_mem" () void*))
  (define BIO_new     (foreign-procedure "BIO_new" (void*) void*))
  (define BIO_free    (foreign-procedure "BIO_free" (void*) int))
  (define BIO_write   (foreign-procedure "BIO_write" (void* u8* int) int))
  (define d2i_X509_bio (foreign-procedure "d2i_X509_bio" (void* void*) void*))
  (define X509_free   (foreign-procedure "X509_free" (void*) void))
  (define X509_get_pubkey (foreign-procedure "X509_get_pubkey" (void*) void*))
  (define X509_cmp (foreign-procedure "X509_cmp" (void* void*) int))
  ;; the path validator: a store holding the anchor, a stack of the
  ;; untrusted intermediates, and a context that ties them to the leaf
  (define X509_STORE_new (foreign-procedure "X509_STORE_new" () void*))
  (define X509_STORE_free (foreign-procedure "X509_STORE_free" (void*) void))
  (define X509_STORE_add_cert
    (foreign-procedure "X509_STORE_add_cert" (void* void*) int))
  (define X509_STORE_CTX_new (foreign-procedure "X509_STORE_CTX_new" () void*))
  (define X509_STORE_CTX_free (foreign-procedure "X509_STORE_CTX_free" (void*) void))
  (define X509_STORE_CTX_init
    (foreign-procedure "X509_STORE_CTX_init" (void* void* void* void*) int))
  (define X509_STORE_CTX_get0_param
    (foreign-procedure "X509_STORE_CTX_get0_param" (void*) void*))
  (define X509_VERIFY_PARAM_set_flags
    (foreign-procedure "X509_VERIFY_PARAM_set_flags" (void* unsigned-long) int))
  (define X509_VERIFY_PARAM_add0_policy
    (foreign-procedure "X509_VERIFY_PARAM_add0_policy" (void* void*) int))
  (define X509_verify_cert (foreign-procedure "X509_verify_cert" (void*) int))
  (define X509_STORE_CTX_get_error
    (foreign-procedure "X509_STORE_CTX_get_error" (void*) int))
  (define X509_verify_cert_error_string
    (foreign-procedure "X509_verify_cert_error_string" (long) string))
  (define X509_STORE_CTX_get0_chain
    (foreign-procedure "X509_STORE_CTX_get0_chain" (void*) void*))
  ;; OpenSSL 3's sk_X509_* are macros over these
  (define OPENSSL_sk_new_null (foreign-procedure "OPENSSL_sk_new_null" () void*))
  (define OPENSSL_sk_push (foreign-procedure "OPENSSL_sk_push" (void* void*) int))
  (define OPENSSL_sk_free (foreign-procedure "OPENSSL_sk_free" (void*) void))
  (define OPENSSL_sk_num (foreign-procedure "OPENSSL_sk_num" (void*) int))
  (define OPENSSL_sk_value (foreign-procedure "OPENSSL_sk_value" (void* int) void*))
  ;; from x509_vfy.h
  (define X509_V_ERR_CERT_NOT_YET_VALID 9)
  (define X509_V_ERR_CERT_HAS_EXPIRED 10)
  (define X509_V_FLAG_POLICY_CHECK #x80)
  (define EVP_PKEY_free (foreign-procedure "EVP_PKEY_free" (void*) void))
  (define EVP_sha256  (foreign-procedure "EVP_sha256" () void*))
  (define EVP_MD_CTX_new (foreign-procedure "EVP_MD_CTX_new" () void*))
  (define EVP_MD_CTX_free (foreign-procedure "EVP_MD_CTX_free" (void*) void))
  (define EVP_DigestVerifyInit
    (foreign-procedure "EVP_DigestVerifyInit" (void* void* void* void* void*) int))
  (define EVP_DigestUpdate
    (foreign-procedure "EVP_DigestUpdate" (void* u8* size_t) int))
  (define EVP_DigestVerifyFinal
    (foreign-procedure "EVP_DigestVerifyFinal" (void* u8* size_t) int))
  (define OBJ_txt2obj (foreign-procedure "OBJ_txt2obj" (string int) void*))
  (define ASN1_OBJECT_free (foreign-procedure "ASN1_OBJECT_free" (void*) void))
  (define X509_get_ext_by_OBJ
    (foreign-procedure "X509_get_ext_by_OBJ" (void* void* int) int))

  ;; ---- errors ----------------------------------------------------------

  (define (ajws-fail code msg) (raise (vector 'apple-jws-error code msg)))

  ;; ---- byte helpers ----------------------------------------------------

  (define (bv-append a b)
    (let* ((la (bytevector-length a)) (lb (bytevector-length b))
           (r (make-bytevector (+ la lb))))
      (bytevector-copy! a 0 r 0 la)
      (bytevector-copy! b 0 r la lb)
      r))
  (define (bv-sub bv s e)
    (let ((r (make-bytevector (- e s))))
      (bytevector-copy! bv s r 0 (- e s))
      r))

  ;; Decode every JWS part with the shared strict base64url primitive. Its
  ;; assertions describe attacker-controlled input here, so re-tag them with
  ;; the public apple-jws error contract instead of leaking an assertion.
  (define (b64url->bytes s)
    (guard (e (#t (ajws-fail 'not-jws "malformed base64url in token")))
      (base64url-decode s)))

  ;; ---- X.509 from DER --------------------------------------------------

  (define (der->x509 der)
    (let ((bio (BIO_new (BIO_s_mem))))
      (if (zero? bio)
          #f
          (begin
            (BIO_write bio der (bytevector-length der))
            (let ((x (d2i_X509_bio bio 0)))
              (BIO_free bio)
              (if (zero? x) #f x))))))

  ;; ---- ES256 JOSE signature (raw R||S, 64 bytes) -> DER ECDSA-Sig-Value -

  ;; one 32-byte big-endian magnitude -> a DER INTEGER TLV (minimal, and
  ;; 0x00-prefixed when the high bit would make it look negative)
  (define (der-uint mag)
    (let* ((n (bytevector-length mag))
           (start (let loop ((i 0))
                    (if (and (< i (- n 1)) (fx= 0 (bytevector-u8-ref mag i)))
                        (loop (+ i 1))
                        i)))
           (m (bv-sub mag start n))
           (m (if (fx>= (bytevector-u8-ref m 0) #x80)
                  (bv-append (bytevector 0) m)
                  m)))
      (bv-append (bytevector 2 (bytevector-length m)) m)))   ; INTEGER (all lens < 128)

  (define (es256-raw->der raw)
    (and (fx= (bytevector-length raw) 64)
         (let ((body (bv-append (der-uint (bv-sub raw 0 32))
                                (der-uint (bv-sub raw 32 64)))))
           (bv-append (bytevector #x30 (bytevector-length body)) body)))) ; SEQUENCE

  ;; ---- ES256 verify (leaf pubkey over the signing input) ---------------

  (define (es256-verify cert signing-input der-sig)
    (let ((pk (X509_get_pubkey cert)))
      (when (zero? pk) (ajws-fail 'sig-failed "leaf certificate has no public key"))
      (let ((ctx (EVP_MD_CTX_new)))
        (when (zero? ctx) (EVP_PKEY_free pk) (ajws-fail 'internal "EVP_MD_CTX_new failed"))
        (let ((ok (guard (e (#t (EVP_MD_CTX_free ctx) (EVP_PKEY_free pk) (raise e)))
                    (and (fx= 1 (EVP_DigestVerifyInit ctx 0 (EVP_sha256) 0 pk))
                         (fx= 1 (EVP_DigestUpdate ctx signing-input
                                  (bytevector-length signing-input)))
                         ;; Final: 1 verified, 0 mismatch, <0 error
                         (fx= 1 (EVP_DigestVerifyFinal ctx der-sig
                                  (bytevector-length der-sig)))))))
          (EVP_MD_CTX_free ctx)
          (EVP_PKEY_free pk)
          ok))))

  ;; ---- compact JWS split (exactly two dots) ----------------------------

  (define (str-index s ch start)
    (let ((n (string-length s)))
      (let loop ((i start))
        (cond ((fx>= i n) #f)
              ((char=? (string-ref s i) ch) i)
              (else (loop (fx+ i 1)))))))

  (define (jws-parts token)
    (let ((d1 (str-index token #\. 0)))
      (and d1
           (let ((d2 (str-index token #\. (fx+ d1 1))))
             (and d2
                  (not (str-index token #\. (fx+ d2 1)))
                  (list (substring token 0 d1)
                        (substring token (fx+ d1 1) d2)
                        (substring token (fx+ d2 1) (string-length token))))))))

  ;; does the certificate carry an extension with this dotted OID? Apple's
  ;; marker OIDs -- presence is what its own library checks, not the value.
  (define (cert-has-oid? cert oid-text)
    (let ((obj (OBJ_txt2obj oid-text 1)))
      (and (not (zero? obj))
           (let ((idx (X509_get_ext_by_OBJ cert obj -1)))
             (ASN1_OBJECT_free obj)
             (>= idx 0)))))

  ;; ---- core verification -----------------------------------------------

  ;; trusted-root-ders: a list of DER bytevectors; the x5c root must match
  ;; one of them byte for byte. Returns the decoded payload bytevector.
  (define (verify-jws-x5c token trusted-root-ders)
    (unless (string? token) (ajws-fail 'not-jws "token is not a string"))
    (let ((parts (jws-parts token)))
      (unless parts (ajws-fail 'not-jws "not a compact JWS (need exactly two dots)"))
      (let* ((h-b64 (car parts)) (p-b64 (cadr parts)) (s-b64 (caddr parts))
             ;; Bound the ENCODED header before touching it. The x5c limits
             ;; below are checked after base64 decode, UTF-8 conversion and a
             ;; full JSON parse -- so they bounded the OpenSSL work and left
             ;; the parsing that precedes it open, paid on the one OS thread
             ;; from a header nothing has authenticated yet. 64 KiB is
             ;; generous for the eight certificates the limits below allow
             ;; (Apple sends three) and three orders under a default body.
             (_ (when (fx> (string-length h-b64) 65536)
                  (ajws-fail 'not-jws "JWS header segment is too large")))
             (header (guard (e (#t (ajws-fail 'not-jws "header is not valid JSON")))
                       (string->json (utf8->string (b64url->bytes h-b64)))))
             (alg (and (pair? header) (json-ref header "alg")))
             (x5c (and (pair? header) (json-ref header "x5c"))))
        ;; never let the header pick the algorithm: Apple signs ES256, so
        ;; anything else (including "none") is refused fail-closed
        (unless (equal? alg "ES256")
          (ajws-fail 'bad-alg "unexpected JWS alg (want ES256)"))
        ;; CRIT IS REFUSED HERE, BEFORE THE CHAIN OR THE SIGNATURE IS
        ;; TOUCHED. The position is a choice, and it buys two things: no
        ;; certificate parsing or OpenSSL work is spent on a token that is
        ;; refused whatever the chain says, and the refusal is reported as
        ;; 'crit rather than as whichever later check it would have tripped
        ;; first. The header is known to be an object by now: the alg test
        ;; above passes only on a pair. Why any crit member refuses, whatever
        ;; it lists, is written once in (igropyr jose).
        (when (jose-crit-present? header)
          (ajws-fail 'crit "JWS header marks an extension critical; none is understood"))
        (unless (and (vector? x5c) (fx>= (vector-length x5c) 3))
          (ajws-fail 'no-x5c "x5c header missing or shorter than 3 certificates"))
        ;; And an UPPER bound, checked before any DER is decoded or handed to
        ;; OpenSSL. The chain below is parsed entry by entry and only then
        ;; compared against the pinned root, so an oversized x5c buys a lot of
        ;; synchronous X.509 parsing and native allocation from an unverified
        ;; header -- on the one OS thread, where a green process cannot
        ;; isolate the delay. Apple presents three; a handful is generous.
        (when (fx> (vector-length x5c) 8)
          (ajws-fail 'no-x5c "x5c chain is longer than 8 certificates"))
        ;; Likewise the encoded size: one entry can be arbitrarily long, and
        ;; base64-decode plus der->x509 both scale with it.
        (do ((i 0 (fx+ i 1))) ((fx= i (vector-length x5c)))
          (let ((e (vector-ref x5c i)))
            (unless (and (string? e) (fx<= (string-length e) 8192))
              (ajws-fail 'cert-parse-failed "x5c entry is missing or too large"))))
        (let ((certs '()) (store 0) (untrusted 0) (ctx 0))
          (dynamic-wind
            (lambda () (void))
            (lambda ()
              ;; parse each x5c DER cert (STANDARD base64), collecting for cleanup
              (do ((i 0 (fx+ i 1))) ((fx= i (vector-length x5c)))
                (let* ((der (guard (e (#t (ajws-fail 'cert-parse-failed "x5c entry is not base64")))
                              (base64-decode (vector-ref x5c i))))
                       (x (der->x509 der)))
                  (unless x (ajws-fail 'cert-parse-failed "x5c entry is not a DER certificate"))
                  (set! certs (cons x certs))))
              (set! certs (reverse certs))
              ;; 1) pinned root: presented root's DER must equal a trusted root
              (let ((presented-root
                      (base64-decode (vector-ref x5c (fx- (vector-length x5c) 1)))))
                (unless (exists (lambda (d)
                                  (and (bytevector? d) (bytevector=? d presented-root)))
                                trusted-root-ders)
                  (ajws-fail 'invalid-root "root certificate is not a pinned trusted root")))
              ;; 2) THE PATH IS OPENSSL'S. X509_verify_cert checks signatures,
              ;; CA status and path length, unknown critical extensions, name
              ;; and policy constraints and validity at the current time. The
              ;; loop this replaced checked adjacent pairs, and constraints that
              ;; span the chain -- pathLenConstraint, critical extensions,
              ;; policy constraints -- were never evaluated: re-implementing RFC
              ;; 5280 a clause at a time leaves every clause not yet written as
              ;; a silent accept.
              ;;
              ;; THE ONLY ANCHOR IS THE PRESENTED ROOT, which step 1 has just
              ;; proved byte-equal to a pin, and which is already parsed. The
              ;; pins themselves are not parsed here: a pin that is not a valid
              ;; certificate would then fail verification of tokens it has
              ;; nothing to do with. The untrusted stack holds the presented
              ;; intermediates and nothing else; the leaf is the target.
              (let ((n (length certs)))
                (set! store (X509_STORE_new))
                (when (zero? store) (ajws-fail 'internal "X509_STORE_new failed"))
                (unless (fx= 1 (X509_STORE_add_cert store (list-ref certs (fx- n 1))))
                  (ajws-fail 'internal "X509_STORE_add_cert failed"))
                (set! untrusted (OPENSSL_sk_new_null))
                (when (zero? untrusted) (ajws-fail 'internal "OPENSSL_sk_new_null failed"))
                ;; push answers the new count, not 1, so success is > 0
                (do ((i 1 (fx+ i 1))) ((fx= i (fx- n 1)))
                  (unless (fx> (OPENSSL_sk_push untrusted (list-ref certs i)) 0)
                    (ajws-fail 'internal "OPENSSL_sk_push failed")))
                (set! ctx (X509_STORE_CTX_new))
                (when (zero? ctx) (ajws-fail 'internal "X509_STORE_CTX_new failed"))
                (unless (fx= 1 (X509_STORE_CTX_init ctx store (car certs) untrusted))
                  (ajws-fail 'internal "X509_STORE_CTX_init failed"))
                ;; POLICY PROCESSING ON, AND THE INITIAL SET IS anyPolicy.
                ;; Without the flag, a critical policyConstraints is recognised
                ;; -- so the unknown-critical-extension rule does not catch it
                ;; -- and then never enforced. Without the initial set, a path
                ;; on which requireExplicitPolicy takes effect -- carried below
                ;; the anchor, whose own policy constraints are not processed,
                ;; with its skip count reached -- fails whatever policies its
                ;; certificates assert, so the day Apple's chain carried such a
                ;; constraint every notification would fail. Adding the policy
                ;; does not turn the flag on; both are needed. The parameter
                ;; belongs to the context and must not be freed here; once add0
                ;; succeeds the policy object belongs to the parameter, and
                ;; until then it is ours.
                (let ((param (X509_STORE_CTX_get0_param ctx)))
                  (when (zero? param) (ajws-fail 'internal "X509_STORE_CTX_get0_param failed"))
                  (unless (fx= 1 (X509_VERIFY_PARAM_set_flags param X509_V_FLAG_POLICY_CHECK))
                    (ajws-fail 'internal "X509_VERIFY_PARAM_set_flags failed"))
                  (let ((any-policy (OBJ_txt2obj "2.5.29.32.0" 1)))
                    (when (zero? any-policy)
                      (ajws-fail 'internal "OBJ_txt2obj failed for anyPolicy"))
                    (unless (fx= 1 (X509_VERIFY_PARAM_add0_policy param any-policy))
                      (ASN1_OBJECT_free any-policy)
                      (ajws-fail 'internal "X509_VERIFY_PARAM_add0_policy failed"))))
                ;; 1 verified, 0 refused, negative for an internal error. Of
                ;; the refusals only the two validity-window errors are
                ;; cert-expired; the set of codes this file raises is
                ;; unchanged.
                (let ((r (X509_verify_cert ctx)))
                  (cond
                    ((fx< r 0) (ajws-fail 'internal "X509_verify_cert failed internally"))
                    ((fx= r 0)
                     (let ((err (X509_STORE_CTX_get_error ctx)))
                       (if (or (fx= err X509_V_ERR_CERT_HAS_EXPIRED)
                               (fx= err X509_V_ERR_CERT_NOT_YET_VALID))
                           (ajws-fail 'cert-expired
                             (string-append "certificate is outside its validity window: "
                                            (X509_verify_cert_error_string err)))
                           (ajws-fail 'chain-failed
                             (string-append "certificate path does not verify: "
                                            (X509_verify_cert_error_string err))))))))
                ;; THE VERIFIED PATH MUST BE THE PRESENTED CHAIN, position by
                ;; position. OpenSSL builds its own path from the leaf, the
                ;; untrusted stack and the store; if some other path verified --
                ;; one skipping an intermediate, or taking the presented ones in
                ;; another order -- the marker checks below, which look at
                ;; the presented positions, would be judging a certificate
                ;; the verification did not use, or one it used at another
                ;; place in the path. A length comparison alone accepts a
                ;; reordering, so every position is compared.
                (let ((chain (X509_STORE_CTX_get0_chain ctx)))
                  (unless (and (not (zero? chain))
                               (fx= (OPENSSL_sk_num chain) n)
                               (let loop ((i 0) (cs certs))
                                 (or (null? cs)
                                     (and (fx= 0 (X509_cmp (OPENSSL_sk_value chain i) (car cs)))
                                          (loop (fx+ i 1) (cdr cs))))))
                    (ajws-fail 'chain-failed "the verified path is not the presented chain"))))
              ;; 3) Apple marker OIDs: the leaf must be the App Store Server
              ;; signing cert and the intermediate the WWDR CA -- exactly what
              ;; Apple's own app-store-server-library pins, so a certificate
              ;; that merely chains to the pinned root but is not the
              ;; notification signer is rejected.
              (unless (cert-has-oid? (car certs) "1.2.840.113635.100.6.11.1")
                (ajws-fail 'chain-failed "leaf is not an App Store Server signing certificate"))
              (unless (cert-has-oid? (cadr certs) "1.2.840.113635.100.6.2.1")
                (ajws-fail 'chain-failed "intermediate is not the Apple WWDR CA"))
              ;; 4) ES256 over "header.payload" under the leaf's public key
              (let ((der-sig (es256-raw->der (b64url->bytes s-b64))))
                (unless der-sig (ajws-fail 'sig-failed "signature is not a 64-byte ES256 value"))
                (unless (es256-verify (car certs)
                          (string->utf8 (string-append h-b64 "." p-b64)) der-sig)
                  (ajws-fail 'sig-failed "JWS signature does not verify")))
              ;; success -> the decoded payload bytes
              (b64url->bytes p-b64))
            ;; the context (which frees its parameter and the anyPolicy object
            ;; it owns), the stack container only -- the certificates in it
            ;; are the ones in certs -- the store (which drops its own
            ;; reference to the anchor), then every certificate parsed above,
            ;; once
            (lambda ()
              (unless (zero? ctx) (X509_STORE_CTX_free ctx))
              (unless (zero? untrusted) (OPENSSL_sk_free untrusted))
              (unless (zero? store) (X509_STORE_free store))
              (for-each X509_free certs)))))))

  ;; ---- Apple Root CA G3 (pinned) ---------------------------------------
  ;; https://www.apple.com/certificateauthority/AppleRootCA-G3.cer ; notAfter 2039.

  (define apple-root-g3-pem
    (string-append
      "-----BEGIN CERTIFICATE-----\n"
      "MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS\n"
      "QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u\n"
      "IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN\n"
      "MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS\n"
      "b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y\n"
      "aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49\n"
      "AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf\n"
      "TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517\n"
      "IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr\n"
      "MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA\n"
      "MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4\n"
      "at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM\n"
      "6BgD56KyKA==\n"
      "-----END CERTIFICATE-----\n"))

  (define (split-lines s)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond ((fx= i n) (reverse (cons (substring s start i) acc)))
              ((char=? (string-ref s i) #\newline)
               (loop (fx+ i 1) (fx+ i 1) (cons (substring s start i) acc)))
              (else (loop (fx+ i 1) start acc))))))

  ;; PEM body (drop the dashed delimiter lines) is exactly base64 of the DER
  (define (pem->der pem)
    (base64-decode
      (apply string-append
        (filter (lambda (l) (and (fx> (string-length l) 0)
                                 (not (char=? (string-ref l 0) #\-))))
                (split-lines pem)))))

  (define apple-root-ca-g3-der (pem->der apple-root-g3-pem))

  ;; Verify against the pinned Apple Root CA G3.
  (define (verify-apple-jws token)
    (verify-jws-x5c token (list apple-root-ca-g3-der)))
)
