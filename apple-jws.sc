#!chezscheme
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
;;;   not-jws no-x5c cert-parse-failed invalid-root chain-failed
;;;   cert-expired sig-failed internal
;;;
;;; Verification (mirrors Apple's documented steps):
;;;   1. the x5c root's DER bytes must equal a pinned trusted root
;;;      (verify-apple-jws pins Apple Root CA G3; verify-jws-x5c takes an
;;;      explicit list of trusted root DERs for tests / future roots)
;;;   2. each cert is issued by the next, whose CA bit is set, and its
;;;      signature verifies under the issuer's public key
;;;   3. every cert is inside its validity window
;;;   4. the JWS signature (ES256) verifies under the leaf's public key
;;;
;;; It is VERIFY-ONLY: no signing, so no App Store Server API JWT is
;;; produced here (ynthu talks to the legacy verifyReceipt endpoint for
;;; receipts). The heavy lifting -- X.509 parsing, ECDSA -- is libcrypto
;;; via FFI, the same library (igropyr tls) loads; only the pinned-root
;;; byte compare and the JOSE raw-R||S -> DER signature reshaping are here.

(library (igropyr apple-jws)
  (export verify-apple-jws verify-jws-x5c apple-root-ca-g3-der)
  (import (chezscheme) (igropyr platform)
          (only (igropyr crypto) base64-decode)
          (only (igropyr json) string->json json-ref))

  ;; ---- libcrypto (loaded explicitly, like (igropyr tls)) ----------------

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
    (load-first-shared-object! 'igropyr-apple-jws (candidates "libcrypto")))

  ;; ---- FFI (pointers are machine integers; 0 is NULL) -------------------

  (define BIO_s_mem   (foreign-procedure "BIO_s_mem" () void*))
  (define BIO_new     (foreign-procedure "BIO_new" (void*) void*))
  (define BIO_free    (foreign-procedure "BIO_free" (void*) int))
  (define BIO_write   (foreign-procedure "BIO_write" (void* u8* int) int))
  (define d2i_X509_bio (foreign-procedure "d2i_X509_bio" (void* void*) void*))
  (define X509_free   (foreign-procedure "X509_free" (void*) void))
  (define X509_check_issued (foreign-procedure "X509_check_issued" (void* void*) int))
  (define X509_check_ca (foreign-procedure "X509_check_ca" (void*) int))
  (define X509_verify (foreign-procedure "X509_verify" (void* void*) int))
  (define X509_get_pubkey (foreign-procedure "X509_get_pubkey" (void*) void*))
  (define X509_get0_notBefore (foreign-procedure "X509_get0_notBefore" (void*) void*))
  (define X509_get0_notAfter  (foreign-procedure "X509_get0_notAfter" (void*) void*))
  (define X509_cmp_current_time (foreign-procedure "X509_cmp_current_time" (void*) int))
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

  ;; base64url (the JWS parts) -> bytes, via (igropyr crypto) base64-decode
  ;; which wants the standard alphabet and tolerates '=' padding.
  (define (b64url->bytes s)
    (let* ((n (string-length s)) (t (make-string n)))
      (do ((i 0 (+ i 1))) ((= i n))
        (let ((c (string-ref s i)))
          (string-set! t i (cond ((char=? c #\-) #\+)
                                 ((char=? c #\_) #\/)
                                 (else c)))))
      (base64-decode
        (string-append t (make-string (mod (- 4 (mod n 4)) 4) #\=)))))

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

  ;; ---- core verification -----------------------------------------------

  ;; trusted-root-ders: a list of DER bytevectors; the x5c root must match
  ;; one of them byte for byte. Returns the decoded payload bytevector.
  (define (verify-jws-x5c token trusted-root-ders)
    (unless (string? token) (ajws-fail 'not-jws "token is not a string"))
    (let ((parts (jws-parts token)))
      (unless parts (ajws-fail 'not-jws "not a compact JWS (need exactly two dots)"))
      (let* ((h-b64 (car parts)) (p-b64 (cadr parts)) (s-b64 (caddr parts))
             (header (guard (e (#t (ajws-fail 'not-jws "header is not valid JSON")))
                       (string->json (utf8->string (b64url->bytes h-b64)))))
             (x5c (and (pair? header) (json-ref header "x5c"))))
        (unless (and (vector? x5c) (fx>= (vector-length x5c) 3))
          (ajws-fail 'no-x5c "x5c header missing or shorter than 3 certificates"))
        (let ((certs '()))
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
              ;; 2) chain: cert[i] issued by cert[i+1], which is a CA, sig valid
              (let loop ((cs certs))
                (when (pair? (cdr cs))
                  (let ((cert (car cs)) (issuer (cadr cs)))
                    (when (fx<= (X509_check_ca issuer) 0)
                      (ajws-fail 'chain-failed "issuer is not a CA"))
                    (unless (fx= 0 (X509_check_issued issuer cert))
                      (ajws-fail 'chain-failed "issuer does not match subject"))
                    (let ((pk (X509_get_pubkey issuer)))
                      (when (zero? pk) (ajws-fail 'chain-failed "issuer has no public key"))
                      (let ((ok (fx= 1 (X509_verify cert pk))))
                        (EVP_PKEY_free pk)
                        (unless ok (ajws-fail 'chain-failed "certificate signature is invalid")))))
                  (loop (cdr cs))))
              ;; 3) validity window (notBefore < now < notAfter) for every cert
              (for-each
                (lambda (c)
                  (unless (and (fx< (X509_cmp_current_time (X509_get0_notBefore c)) 0)
                               (fx> (X509_cmp_current_time (X509_get0_notAfter c)) 0))
                    (ajws-fail 'cert-expired "certificate is outside its validity window")))
                certs)
              ;; 4) ES256 over "header.payload" under the leaf's public key
              (let ((der-sig (es256-raw->der (b64url->bytes s-b64))))
                (unless der-sig (ajws-fail 'sig-failed "signature is not a 64-byte ES256 value"))
                (unless (es256-verify (car certs)
                          (string->utf8 (string-append h-b64 "." p-b64)) der-sig)
                  (ajws-fail 'sig-failed "JWS signature does not verify")))
              ;; success -> the decoded payload bytes
              (b64url->bytes p-b64))
            (lambda () (for-each X509_free certs)))))))

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
