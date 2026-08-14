#!chezscheme
;;; (igropyr rsa) RSA-SHA256, PKCS#1 v1.5.
;;;
;;; Signing and verifying with the same code proves nothing: a wrong padding
;;; verifies its own wrong padding. Everything asserted here is anchored
;;; outside this library.
;;;
;;;  1. A PUBLISHED signature. RFC 7515 appendix A.2 gives an RS256 example
;;;     in full -- the RSA public key, the exact bytes signed, and the exact
;;;     signature. The modulus goes in through rsa-public-key-from-modulus
;;;     and the published signature must verify, so both the PKCS#1 v1.5
;;;     encoding and the SHA-256 digest identifier are pinned to bytes this
;;;     repository did not produce. This part needs nothing but libcrypto and
;;;     always runs.
;;;
;;;  2. The openssl CLI, in BOTH directions and byte for byte. PKCS#1 v1.5 is
;;;     deterministic, so a signature we make over a file must equal
;;;     `openssl dgst -sha256 -sign` over the same file exactly -- a stronger
;;;     statement than "each accepts the other". Then each verifies the
;;;     other's signature, across 2048- and 3072-bit keys and a key with
;;;     e = 3, over an empty file, a file containing NUL bytes, and a
;;;     megabyte. The CLI also mints every PEM shape the loader claims to
;;;     accept. Gated on `openssl` being on PATH, and says so if it is not.
;;;
;;; Then the failure modes: a modified message, a modified signature, a
;;; signature from another key, and every malformed PEM shape must be
;;; refused, cleanly and without prompting the operator for a passphrase.

(import (chezscheme) (igropyr rsa)
        (only (igropyr crypto) bytevector->hex sha256))

(define failures 0)
(define (fail label)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label) (newline))
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (fail label)))
(define (check= label got want)
  (if (equal? got want)
      (begin (display "  ok  ") (display label) (newline))
      (begin (fail label)
             (display "    got  ") (write got) (newline)
             (display "    want ") (write want) (newline))))
(define (raises? thunk) (guard (e (#t #t)) (thunk) #f))
(define (rejects label thunk) (check label (raises? thunk)))
;; the library's own error shape, as documented: #(rsa-error MESSAGE)
(define (rsa-error? thunk)
  (guard (e (#t (and (vector? e) (= 2 (vector-length e))
                     (eq? 'rsa-error (vector-ref e 0)))))
    (thunk) #f))

(define dir "/tmp/igropyr-rsa-test")
(system (string-append "rm -rf " dir " && mkdir -p " dir))
(define (p name) (string-append dir "/" name))

;; ---- helpers -----------------------------------------------------------

(define (u s) (string->utf8 s))
(define (hex bv) (bytevector->hex bv))

(define (hex->bv s)
  (let* ((n (div (string-length s) 2))
         (bv (make-bytevector n)))
    (do ((i 0 (+ i 1))) ((= i n) bv)
      (bytevector-u8-set! bv i
        (string->number (substring s (* 2 i) (+ 2 (* 2 i))) 16)))))

(define (flip bv i)
  (let ((c (bytevector-copy bv)))
    (bytevector-u8-set! c i (fxxor 1 (bytevector-u8-ref bv i)))
    c))

(define (read-bytes path)
  (call-with-port (open-file-input-port path)
    (lambda (in) (let ((b (get-bytevector-all in)))
                   (if (eof-object? b) (make-bytevector 0) b)))))

(define (write-bytes path bv)
  (when (file-exists? path) (delete-file path))
  (call-with-port (open-file-output-port path) (lambda (o) (put-bytevector o bv))))

;; "" for an empty file, not the eof object: several callers hand the result
;; straight to string-length, and a child that was killed before it could
;; print anything must be reported as "said nothing", not as a crash in the
;; harness.
(define (read-text path)
  (let ((s (call-with-port (open-input-file path) get-string-all)))
    (if (eof-object? s) "" s)))

(define capture-file (p "capture.txt"))
(define (cap cmd)
  (system (string-append "( " cmd " ) > " capture-file " 2>&1"))
  (read-text capture-file))

(define (contains? hay needle)
  (let ((hn (string-length hay)) (nn (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i nn) hn) #f)
            ((string=? needle (substring hay i (+ i nn))) #t)
            (else (loop (+ i 1)))))))

(define (bv-find hay needle)
  (let ((hn (bytevector-length hay)) (nn (bytevector-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i nn) hn) #f)
            ((let inner ((j 0))
               (cond ((= j nn) #t)
                     ((= (bytevector-u8-ref hay (+ i j))
                         (bytevector-u8-ref needle j))
                      (inner (+ j 1)))
                     (else #f)))
             i)
            (else (loop (+ i 1)))))))

;; The PKCS#1 v1.5 signature block for a SHA-256 digest, built from the
;; encoding in RFC 8017 section 9.2 rather than from anything this library
;; does: 0x00 0x01, 0xff padding, 0x00, then the DER DigestInfo. It is the
;; value an RSA public operation is supposed to RECOVER from a signature --
;; which is why, with e = 1, presenting it AS the signature is a forgery.
(define sha256-digestinfo-prefix
  (hex->bv "3031300d060960864801650304020105000420"))

(define (emsa-pkcs1-v15-sha256 msg k)
  (let* ((t (let* ((h (sha256 msg))
                   (b (make-bytevector (+ (bytevector-length sha256-digestinfo-prefix) 32))))
              (bytevector-copy! sha256-digestinfo-prefix 0 b 0
                                (bytevector-length sha256-digestinfo-prefix))
              (bytevector-copy! h 0 b (bytevector-length sha256-digestinfo-prefix) 32)
              b))
         (tl (bytevector-length t))
         (out (make-bytevector k #xff)))
    (bytevector-u8-set! out 0 #x00)
    (bytevector-u8-set! out 1 #x01)
    (bytevector-u8-set! out (- k tl 1) #x00)
    (bytevector-copy! t 0 out (- k tl) tl)
    out))

;; ---- 1. RFC 7515 A.2: a published RS256 signature ----------------------
;;
;; The key, the signing input and the signature are the RFC's own; they are
;; written here in hex rather than base64url so that nothing in this
;; repository (including its base64 decoder) sits between the RFC and the
;; assertion.

(define rfc7515-n (hex->bv (string-append
  "a1f8160ae2e3c9b465ce8d2d656263362b927dbe29e1f02477fc1625cc90a136"
  "e38bd93497c5b6ea63dd7711e67c7429f956b0fb8a8f089adc4b69893cc1333f"
  "53edd019b87784252fec914fe4857769594bea4280d32c0f55bf62944f130396"
  "bc6e9bdf6ebdd2bda3678eeca0c668f701b38dbffb38c8342ce2fe6d27fade4a"
  "5a4874979dd4b9cf9adec4c75b05852c2c0f5ef8a5c1750392f944e8ed64c110"
  "c6b647609aa4783aeb9c6c9ad755313050638b83665c6f6f7a82a396702a1f64"
  "1b82d3ebf2392219491fb686872c5716f50af8358d9a8b9d17c340728f7f87d8"
  "9a18d8fcab67ad84590c2ecf759339363c07034d6f606f9e21e05456cae5e9a1")))
(define rfc7515-e (hex->bv "010001"))
;; the JWS Signing Input of A.2: ASCII, and it contains CR LF inside the
;; payload, which is why it is spelled out rather than reconstructed
(define rfc7515-input
  (u (string-append
       "eyJhbGciOiJSUzI1NiJ9."
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")))
(define rfc7515-sig (hex->bv (string-append
  "702e218943e88fd11eb5d82dbf7845f34106ae1b81fff7731116add1717d8365"
  "6d420afd3c96eedd73a2663e5166687b000b87226e0187ed1073f945e582adfc"
  "ef16d85a798ee8c66ddb3db8975b17d09402beedd5d9d97007108db28160d5f8"
  "040ca7445762b81fbe7ff9d92e0ae76f24f25b33bbe6f44ae61eb1040acb2004"
  "4d3ef9128ed40130795bd4bd3b41eecad066ab651981fde48df77f372dc38b9f"
  "afdd3befb18b5da3cc3c2eb02f9e3a41d612caad15911273a05f23b9e838faaf"
  "849d698429ef5a1e88798236c3d40e604522a544c8f27a7a2db80663d16cf7ca"
  "ea56de405cb2215a45b2c25566b55ac1a748a070dfc8a32a469543d019eefb47")))

(define rfc-key (rsa-public-key-from-modulus rfc7515-n rfc7515-e))

(check "rfc7515-verifies" (rsa-verify-sha256 rfc-key rfc7515-input rfc7515-sig))
(check "rfc7515-bits-2048" (= 2048 (rsa-key-bits rfc-key)))
(check "rfc7515-not-private" (not (rsa-key-private? rfc-key)))
(check "rfc7515-is-key" (rsa-key? rfc-key))
(check= "rfc7515-modulus-round-trip" (hex (rsa-key-modulus rfc-key)) (hex rfc7515-n))
(check= "rfc7515-exponent-round-trip" (hex (rsa-key-exponent rfc-key)) "010001")
;; one bit anywhere in the signature and it is no longer that signature
(check "rfc7515-sig-bit-flipped-rejected"
  (not (rsa-verify-sha256 rfc-key rfc7515-input (flip rfc7515-sig 0))))
(check "rfc7515-sig-last-bit-flipped-rejected"
  (not (rsa-verify-sha256 rfc-key rfc7515-input (flip rfc7515-sig 255))))
(check "rfc7515-message-bit-flipped-rejected"
  (not (rsa-verify-sha256 rfc-key (flip rfc7515-input 5) rfc7515-sig)))
;; a truncated message with the same prefix must not slide through
(check "rfc7515-message-truncated-rejected"
  (let ((short (make-bytevector 20)))
    (bytevector-copy! rfc7515-input 0 short 0 20)
    (not (rsa-verify-sha256 rfc-key short rfc7515-sig))))
;; a verify-only key must refuse to sign, and say so as an rsa-error rather
;; than letting libcrypto blame EVP_DigestSignInit
(check "rfc7515-public-cannot-sign"
  (rsa-error? (lambda () (rsa-sign-sha256 rfc-key rfc7515-input))))
;; leading zero bytes in the modulus are not part of the number
(check "modulus-leading-zeros-ignored"
  (let* ((padded (make-bytevector (+ 3 (bytevector-length rfc7515-n)) 0)))
    (bytevector-copy! rfc7515-n 0 padded 3 (bytevector-length rfc7515-n))
    (let ((k2 (rsa-public-key-from-modulus padded rfc7515-e)))
      (and (rsa-verify-sha256 k2 rfc7515-input rfc7515-sig)
           (= 2048 (rsa-key-bits k2))
           (equal? (rsa-key-modulus k2) rfc7515-n)))))
;; the accessors hand back copies: writing to one must not reach the key
(check "modulus-accessor-returns-a-copy"
  (let ((m (rsa-key-modulus rfc-key)))
    (bytevector-u8-set! m 0 0)
    (and (equal? (rsa-key-modulus rfc-key) rfc7515-n)
         (rsa-verify-sha256 rfc-key rfc7515-input rfc7515-sig))))
(check "exponent-accessor-returns-a-copy"
  (let ((e (rsa-key-exponent rfc-key)))
    (bytevector-u8-set! e 0 0)
    (equal? (rsa-key-exponent rfc-key) rfc7515-e)))

;; signature lengths other than the modulus length are answers, not errors
(check "empty-signature-rejected"
  (not (rsa-verify-sha256 rfc-key rfc7515-input (make-bytevector 0))))
(check "short-signature-rejected"
  (let ((s (make-bytevector 255))) (bytevector-copy! rfc7515-sig 0 s 0 255)
    (not (rsa-verify-sha256 rfc-key rfc7515-input s))))
(check "long-signature-rejected"
  (let ((s (make-bytevector 257 0))) (bytevector-copy! rfc7515-sig 0 s 0 256)
    (not (rsa-verify-sha256 rfc-key rfc7515-input s))))
(check "zero-signature-rejected"
  (not (rsa-verify-sha256 rfc-key rfc7515-input (make-bytevector 256 0))))
(check "ff-signature-rejected"
  (not (rsa-verify-sha256 rfc-key rfc7515-input (make-bytevector 256 255))))

;; ---- argument shapes (no keys needed) ----------------------------------

(rejects "verify-non-key"        (lambda () (rsa-verify-sha256 'nope (u "x") (u "y"))))
(rejects "verify-non-bv-input"   (lambda () (rsa-verify-sha256 rfc-key "x" rfc7515-sig)))
(rejects "verify-non-bv-sig"     (lambda () (rsa-verify-sha256 rfc-key rfc7515-input "sig")))
(rejects "sign-non-key"          (lambda () (rsa-sign-sha256 "key" (u "x"))))
(rejects "key-bits-non-key"      (lambda () (rsa-key-bits 42)))
(rejects "modulus-non-key"       (lambda () (rsa-key-modulus 42)))
(rejects "exponent-non-key"      (lambda () (rsa-key-exponent 42)))
(rejects "free-non-key"          (lambda () (rsa-key-free! 42)))
(check "rsa-key?-says-no" (not (rsa-key? "not a key")))

(rejects "from-modulus-empty-n"  (lambda () (rsa-public-key-from-modulus (make-bytevector 0) rfc7515-e)))
(rejects "from-modulus-empty-e"  (lambda () (rsa-public-key-from-modulus rfc7515-n (make-bytevector 0))))
(rejects "from-modulus-zero-n"   (lambda () (rsa-public-key-from-modulus (make-bytevector 4 0) rfc7515-e)))
(rejects "from-modulus-zero-e"   (lambda () (rsa-public-key-from-modulus rfc7515-n (make-bytevector 4 0))))
(rejects "from-modulus-non-bv-n" (lambda () (rsa-public-key-from-modulus "n" rfc7515-e)))
(rejects "from-modulus-non-bv-e" (lambda () (rsa-public-key-from-modulus rfc7515-n 65537)))
(rejects "from-pem-non-text"     (lambda () (rsa-public-key-from-pem 42)))
(rejects "private-from-pem-non-text" (lambda () (rsa-private-key-from-pem 42)))

;; A structurally valid PKCS#1 private key whose d was tampered (d+2) so it
;; no longer agrees with n/e. PEM decoding accepts it -- `openssl rsa -check`
;; reports "d e not congruent to 1" on this exact blob -- so loading it must
;; be refused here, not deferred to a mysterious failure at signing time.
;; Frozen vector (generated once via pyca unsafe_skip_rsa_key_validation),
;; so the test needs no key-generation tool at run time.
(define inconsistent-private-pem
  (string-append
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAtBvqND3Ux3kCcRwPdY1MU11U/60OiRHsRMb3w8MnbEdvF0ZY\n"
    "lq9L8fQIBuD8dzqjlJdt/4yxT/iLD9eNHcZis/wpbRUnjJ+QkQwb/qlBS46ZFOTa\n"
    "CWm2i9sAm9Kr4JpyWU7c2DUMXH0UeZ+hAlZbGBSLt1ex0KU1/caeNA9+yy/P0F0B\n"
    "9C+D1xUcbKOyBfDkKrpaZVu3hCD9dVkkGQ/MQ/MhbzQSTx0/A1lbzkUSdPG3pMcl\n"
    "eYrYAdq7HeZIyfyPtIhdAmE3sJHz6muo5xMB6AsEVMcGzIkIlyzReE+GDI6GMSDg\n"
    "ZzKYmkKVvLzESFf+xrfHIir5ZXx+zN8DMiJxyQIDAQABAoIBADzIMujAeR98OhO7\n"
    "+YedUMXNeJL0bzRY5Rhs4U6ifJpxHQ+IwPrRW9rilRblNK50DqJl3ExiybAIW73T\n"
    "657BxauiDMTwX7F4ZAxfPs9ZhVyfWhAQD3kfwOg/11u+5BxfYvm6wJMCjBJmb9N/\n"
    "yJGGXSWqQWB1at/T8X2cWuWM2ShugE1/Pvl3G+1oucNVI/zM61dUe3IcBT4h1fax\n"
    "PwVOsbDZXnMZuqcBI9CMhOV37j338DpFt6m0q84yfYkBt4s/0fIeELGcNKKEkEks\n"
    "TKjQxL/L9uJi1RXSGuyOU/nSFetWTKn6UNdGON0dlF2laExkqwpHBrJGwaUpOUVv\n"
    "9k5bRxcCgYEA2TFyufGNK9QtTIzLbt5c+eJAAi9EbOqRb6EKx2TeBtrQa/1hOVws\n"
    "Tx1/9BhmOFZ+0mjWRRWOCnkLKQxeKHLpaTt96nkNpwQ0e3JrnlgSgpCj9ztYAdTS\n"
    "p5vIwXy1B82YpO+EwpB11DIXohtKyzqquZWJKWLmNtJDKFoY9oLBN1MCgYEA1Eo3\n"
    "SHQW5cYJobCzosxD5ZqgWOYgd1WvaCK5Fc1B1kTWF3datC3NLEx9ooijX1icMSyM\n"
    "DJQK0GUZX+i6Rgon77aPj1OkxWlMY3C8aV3TxA3zvyOTlCngG+VZehZdHW3qu703\n"
    "qTFSMkVkVYEtYZZ62GyeMph83TK2+iqUMDFhmvMCgYEAy6D0syio9qKjJdYLFRMd\n"
    "kJpy8JloScVSPZp7BJ6pGzwjlFumv6SPVk2OHUiS7dcKaDMqUPL4jREXSZDy5nF2\n"
    "LNc+IosEJcZnfiW0iGyCTi9VywG0bWMfbU09V0qYX4x+xIRbsB7Imf2s8qsr4IZM\n"
    "clqkkkzLEjLoC/kM1nGYvUkCgYAcmJKx09Fxyidp/F92QoWy3A1VbEpbSNOD94lv\n"
    "AmMn9cXRC2bQdor4uKUDy9wV7926UgHbf+WlBLlSTgspfBy9EZ5s9Btx7Ck6C+mV\n"
    "V+o6spZu3N/4SVvC5jYTWAfa+v9voqFozRgBZY+KZQgz6Q1LMfZtYlUPhtFXCX1E\n"
    "sKIxOQKBgBFnGl20BiDvX0ZZbbZjecUs+3SldW6rUixUrdZwClPE43I1AM0FGYNb\n"
    "nnUnY+NmR2sJ78HQZaDU8MoVW3TQmtsSoPqGkohfLUSfHZpkaCIocDVUUQoE/kTt\n"
    "BHhsWo14945YjMbprrzEekuk52fqpKh8x0VkVKCz+MKSZIwDYzeS\n"
    "-----END RSA PRIVATE KEY-----\n"))
(check "inconsistent-private-key-refused"
  (rsa-error? (lambda () (rsa-private-key-from-pem inconsistent-private-pem))))
(rejects "load-path-not-a-string" (lambda () (rsa-load-public-key 42)))
(rejects "load-missing-file"     (lambda () (rsa-load-public-key (p "does-not-exist.pem"))))

;; garbage that never looked like a PEM
(check "garbage-pem-raises-rsa-error"
  (rsa-error? (lambda () (rsa-public-key-from-pem "this is not a PEM at all"))))
(check "empty-string-pem-raises"
  (raises? (lambda () (rsa-public-key-from-pem ""))))
(check "private-from-garbage-raises-rsa-error"
  (rsa-error? (lambda () (rsa-private-key-from-pem "this is not a PEM at all"))))
;; a header with no body, and a header whose body is not base64
(check "header-only-pem-raises"
  (raises? (lambda () (rsa-public-key-from-pem
    "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"))))
(check "non-base64-body-raises"
  (raises? (lambda () (rsa-public-key-from-pem
    "-----BEGIN PUBLIC KEY-----\n!!!! not base64 !!!!\n-----END PUBLIC KEY-----\n"))))
;; base64 that decodes to something that is not a SubjectPublicKeyInfo
(check "wrong-der-body-raises"
  (raises? (lambda () (rsa-public-key-from-pem
    "-----BEGIN PUBLIC KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PUBLIC KEY-----\n"))))
;; a PEM with embedded NUL bytes must not be treated as a C string
(check "pem-with-nul-bytes-raises"
  (raises? (lambda ()
    (let ((bv (u "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")))
      (bytevector-u8-set! bv 5 0)
      (rsa-public-key-from-pem bv)))))

;; ---- what a key is allowed to be ---------------------------------------
;;
;; These need no private key and no CLI: every one of them is a public key
;; an attacker publishes, and the question is whether the loader takes it.

;; e = 1. The public operation becomes the identity, so the PKCS#1 v1.5
;; block a verifier expects to RECOVER can simply be handed in as the
;; signature. The first check is that the key is refused; the second is the
;; forgery itself, spelled out, so that a loader which ever starts accepting
;; e = 1 again fails on the consequence and not only on the policy.
(define e1-message (u "a message nobody holding a private key ever signed"))
(check "exponent-1-key-refused"
  (rsa-error? (lambda () (rsa-public-key-from-modulus rfc7515-n (bytevector 1)))))
(check "exponent-1-forgery-does-not-verify"
  (let ((k (guard (e (#t #f))
             (rsa-public-key-from-modulus rfc7515-n (bytevector 1)))))
    (or (not k)
        (not (rsa-verify-sha256 k e1-message
               (emsa-pkcs1-v15-sha256 e1-message 256))))))
;; and the forged block really is the block a verifier looks for: with the
;; RFC's own key it is exactly what the RFC's own signature recovers, so the
;; check above would have passed for the wrong reason if this were wrong
(check "forged-block-is-256-bytes-and-well-formed"
  (let ((b (emsa-pkcs1-v15-sha256 e1-message 256)))
    (and (= 256 (bytevector-length b))
         (= 0 (bytevector-u8-ref b 0))
         (= 1 (bytevector-u8-ref b 1))
         (= 255 (bytevector-u8-ref b 2))
         (= 0 (bytevector-u8-ref b (- 256 51 1))))))

;; even exponents and even moduli are not RSA at all
(check "even-exponent-refused"
  (rsa-error? (lambda () (rsa-public-key-from-modulus rfc7515-n (bytevector 2)))))
(check "even-modulus-refused"
  (let ((n (bytevector-copy rfc7515-n)))
    (bytevector-u8-set! n 255 (fxand #xfe (bytevector-u8-ref n 255)))
    (rsa-error? (lambda () (rsa-public-key-from-modulus n rfc7515-e)))))

;; a 1024-bit modulus is factorable today; the floor is 2048
(check "1024-bit-modulus-refused"
  (let ((n (make-bytevector 128 #xff)))
    (rsa-error? (lambda () (rsa-public-key-from-modulus n rfc7515-e)))))
(check "2048-bit-modulus-accepted"
  (rsa-key? (rsa-public-key-from-modulus rfc7515-n rfc7515-e)))

;; and the ceilings, which exist so that one verification cannot become a
;; multi-second modular exponentiation with the whole runtime stopped behind
;; it: 16384 bits of modulus, 64 bits of exponent
(check "oversized-modulus-refused"
  (let ((n (make-bytevector 2049 #xff)))
    (rsa-error? (lambda () (rsa-public-key-from-modulus n rfc7515-e)))))
(check "16384-bit-modulus-accepted"
  (let ((n (make-bytevector 2048 #xff)))
    (rsa-key? (rsa-public-key-from-modulus n rfc7515-e))))
(check "oversized-exponent-refused"
  (let ((e (make-bytevector 9 #xff)))
    (rsa-error? (lambda () (rsa-public-key-from-modulus rfc7515-n e)))))
(check "64-bit-exponent-accepted"
  (let ((e (make-bytevector 8 #xff)))
    (rsa-key? (rsa-public-key-from-modulus rfc7515-n e))))
;; leading zeros are not part of the number, so they must not count against
;; either ceiling
(check "leading-zeros-do-not-count-against-the-exponent-ceiling"
  (let ((e (make-bytevector 16 0)))
    (bytevector-u8-set! e 13 1)
    (bytevector-u8-set! e 15 1)
    (rsa-key? (rsa-public-key-from-modulus rfc7515-n e))))
;; a magnitude too big to be any key is refused before libcrypto is asked
;; to allocate for it
(check "absurd-magnitude-refused"
  (rsa-error? (lambda () (rsa-public-key-from-modulus
                           (make-bytevector 5000 #xff) rfc7515-e))))

;; ---- 2. everything that needs a key: the openssl CLI --------------------

(define have-openssl? (zero? (system "command -v openssl >/dev/null 2>&1")))

(unless have-openssl?
  (display "  SKIP every check that needs a key: the `openssl` CLI is not on\n")
  (display "       PATH. This suite mints its own throwaway RSA keys with\n")
  (display "       `openssl genpkey` at run time (nothing is stored in the\n")
  (display "       repository), so without the CLI there is no private key to\n")
  (display "       sign with and no second implementation to cross-check\n")
  (display "       against. Install openssl (base system on FreeBSD; apt\n")
  (display "       install openssl on Debian/Ubuntu; brew install openssl on\n")
  (display "       macOS) and this section runs. The RFC 7515 published\n")
  (display "       vector and the argument/PEM refusals above ran regardless.\n"))

(define (openssl-version)
  (let ((s (cap "openssl version"))) (substring s 0 (max 0 (- (string-length s) 1)))))

(when have-openssl?
  (display "  [cli] ") (display (openssl-version)) (newline)
  (system (string-append
    "cd " dir " && "
    "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out a.pem 2>/dev/null && "
    "openssl rsa -in a.pem -pubout -out a.pub 2>/dev/null && "
    "openssl rsa -in a.pem -RSAPublicKey_out -out a.pkcs1.pub 2>/dev/null && "
    "{ openssl rsa -in a.pem -traditional -out a.trad.pem 2>/dev/null || "
    "  openssl rsa -in a.pem -out a.trad.pem 2>/dev/null; } && "
    "openssl req -x509 -key a.pem -subj /CN=igropyr-rsa-test -days 1 -out a.cert.pem 2>/dev/null && "
    "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out b.pem 2>/dev/null && "
    "openssl rsa -in b.pem -pubout -out b.pub 2>/dev/null && "
    "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out c.pem 2>/dev/null && "
    "openssl rsa -in c.pem -pubout -out c.pub 2>/dev/null && "
    "openssl pkcs8 -topk8 -in a.pem -out a.enc.pem -passout pass:igropyr -v2 aes-256-cbc 2>/dev/null && "
    "openssl ecparam -name prime256v1 -genkey -noout -out ec.pem 2>/dev/null && "
    "openssl ec -in ec.pem -pubout -out ec.pub 2>/dev/null")))

;; openssl on PATH but no key on disk is not a reason to skip: the CLI is
;; here, so the section is expected to run, and a generation that failed is
;; an environment defect to fix rather than a check to drop. It is reported
;; as a failure, loudly and by name, and the checks that need a key are then
;; held back so the run ends on that message instead of an unhandled raise.
(define have-keys?
  (and have-openssl?
       (or (and (file-exists? (p "a.pem")) (file-exists? (p "a.pub"))
                (file-exists? (p "c.pub")) (file-exists? (p "ec.pub")))
           (begin
             (fail "openssl-generated-the-test-keys")
             (display "    `openssl genpkey`/`openssl req` did not produce the\n")
             (display "    throwaway keys in " ) (display dir) (display ".\n")
             (display "    Check that the directory is writable and that this\n")
             (display "    openssl build allows RSA key generation and X.509\n")
             (display "    self-signing; every check needing a private key was\n")
             (display "    held back.\n")
             #f))))

;; e = 3: a legal public exponent that is not 65537, so the exponent really
;; is read from the key rather than assumed. Some builds refuse to generate
;; it; that is a property of the CLI, not of this library, so it self-skips.
(define e3?
  (and have-keys?
       (begin
         (system (string-append "cd " dir " && openssl genpkey -algorithm RSA "
                                "-pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3 "
                                "-out e3.pem 2>/dev/null && openssl rsa -in e3.pem "
                                "-pubout -out e3.pub 2>/dev/null"))
         (file-exists? (p "e3.pub")))))
(when (and have-keys? (not e3?))
  (display "  SKIP e=3 key checks: this openssl build would not generate an\n")
  (display "       RSA key with rsa_keygen_pubexp:3 (some distributions\n")
  (display "       disable non-65537 exponents). Every other key check ran.\n"))

;; the messages, written from here so their bytes are known exactly
(when have-keys?
  (write-bytes (p "m-empty.bin") (make-bytevector 0))
  (write-bytes (p "m-hello.bin") (u "hello"))
  (write-bytes (p "m-bin.bin")
    (let ((bv (make-bytevector 256)))
      (do ((i 0 (+ i 1))) ((= i 256) bv) (bytevector-u8-set! bv i i))))
  (write-bytes (p "m-big.bin")
    (let ((bv (make-bytevector 1048576)))
      (do ((i 0 (+ i 1))) ((= i 1048576) bv)
        (bytevector-u8-set! bv i (mod (* i 31) 256))))))

(define (cli-sign key-file msg-file out-file)
  (system (string-append "openssl dgst -sha256 -sign " (p key-file)
                         " -out " (p out-file) " " (p msg-file) " 2>/dev/null")))

(define (cli-verify pub-file msg-file sig-file)
  (contains? (cap (string-append "openssl dgst -sha256 -verify " (p pub-file)
                                 " -signature " (p sig-file) " " (p msg-file)))
             "Verified OK"))

;; both directions over one (key, message) pair, with the exact-bytes
;; comparison in the middle: PKCS#1 v1.5 is deterministic, so agreement is
;; not a matter of each side accepting the other's output
(define (cross label priv-file pub-file msg-file)
  (let* ((k (rsa-load-private-key (p priv-file)))
         (pub (rsa-load-public-key (p pub-file)))
         (msg (read-bytes (p msg-file)))
         (ours (rsa-sign-sha256 k msg)))
    (write-bytes (p "ours.sig") ours)
    (cli-sign priv-file msg-file "theirs.sig")
    (let ((theirs (read-bytes (p "theirs.sig"))))
      (check= (string-append label "-bytes-identical-to-cli") (hex ours) (hex theirs))
      (check (string-append label "-cli-verifies-ours") (cli-verify pub-file msg-file "ours.sig"))
      (check (string-append label "-we-verify-cli") (rsa-verify-sha256 pub msg theirs))
      (check (string-append label "-we-verify-ours") (rsa-verify-sha256 pub msg ours))
      ;; and the private key verifies too -- it carries the public half
      (check (string-append label "-private-key-verifies") (rsa-verify-sha256 k msg ours)))))

(when have-keys?
  (cross "a2048-hello" "a.pem" "a.pub" "m-hello.bin")
  (cross "a2048-empty" "a.pem" "a.pub" "m-empty.bin")
  (cross "a2048-binary" "a.pem" "a.pub" "m-bin.bin")
  (cross "a2048-1mib"  "a.pem" "a.pub" "m-big.bin")
  (cross "c3072-hello" "c.pem" "c.pub" "m-hello.bin")
  (cross "b2048-hello" "b.pem" "b.pub" "m-hello.bin"))

(when e3? (cross "e3-hello" "e3.pem" "e3.pub" "m-hello.bin"))

(when e3?
  (check= "e3-exponent-is-3" (hex (rsa-key-exponent (rsa-load-public-key (p "e3.pub")))) "03"))

(when have-keys?
  (let ((a (rsa-load-private-key (p "a.pem")))
        (c (rsa-load-private-key (p "c.pem"))))
    (check "a-bits-2048" (= 2048 (rsa-key-bits a)))
    (check "c-bits-3072" (= 3072 (rsa-key-bits c)))
    (check "a-is-private" (rsa-key-private? a))
    (check "a-signature-is-modulus-sized"
      (= 256 (bytevector-length (rsa-sign-sha256 a (u "x")))))
    (check "c-signature-is-modulus-sized"
      (= 384 (bytevector-length (rsa-sign-sha256 c (u "x")))))
    (check "a-signature-is-deterministic"
      (equal? (rsa-sign-sha256 a (u "same input")) (rsa-sign-sha256 a (u "same input"))))
    (check "different-input-different-signature"
      (not (equal? (rsa-sign-sha256 a (u "one")) (rsa-sign-sha256 a (u "two")))))))

;; ---- every PEM shape the loader claims to accept -----------------------

(when have-keys?
  (let* ((priv (rsa-load-private-key (p "a.pem")))
         (msg (u "one message, five ways to publish the verifying key"))
         (sig (rsa-sign-sha256 priv msg))
         (n (rsa-key-modulus priv))
         (e (rsa-key-exponent priv)))
    (define (accepts label loader)
      (let ((k (guard (ex (#t #f)) (loader))))
        (if (not k)
            (fail (string-append label "-loads"))
            (begin
              (check (string-append label "-loads") #t)
              (check= (string-append label "-same-modulus") (hex (rsa-key-modulus k)) (hex n))
              (check (string-append label "-verifies") (rsa-verify-sha256 k msg sig))
              (check (string-append label "-rejects-tampered")
                (not (rsa-verify-sha256 k (flip msg 0) sig)))))))
    (accepts "spki-pub"   (lambda () (rsa-load-public-key (p "a.pub"))))
    (accepts "certificate" (lambda () (rsa-load-public-key (p "a.cert.pem"))))
    (accepts "pkcs1-pub"  (lambda () (rsa-load-public-key (p "a.pkcs1.pub"))))
    (accepts "from-modulus" (lambda () (rsa-public-key-from-modulus n e)))
    (accepts "pkcs8-priv"  (lambda () (rsa-load-private-key (p "a.pem"))))
    (accepts "traditional-priv" (lambda () (rsa-load-private-key (p "a.trad.pem"))))
    ;; PEM handed over as text and as bytes must reach the same key
    (accepts "pub-pem-as-string" (lambda () (rsa-public-key-from-pem (read-text (p "a.pub")))))
    (accepts "pub-pem-as-bytes"  (lambda () (rsa-public-key-from-pem (read-bytes (p "a.pub")))))
    (accepts "priv-pem-as-string" (lambda () (rsa-private-key-from-pem (read-text (p "a.pem")))))
    ;; and the private half loaded from a traditional PEM must still sign
    ;; identically -- same key, different container
    (check= "traditional-priv-signs-identically"
            (hex (rsa-sign-sha256 (rsa-load-private-key (p "a.trad.pem")) msg))
            (hex sig))
    ;; the certificate path must not be confused for chain validation: a
    ;; self-signed certificate is accepted for its key alone, which is what
    ;; the header says it does
    (check "certificate-key-equals-its-own-key"
      (equal? (rsa-key-modulus (rsa-load-public-key (p "a.cert.pem"))) n))))

;; ---- wrong key, wrong digest, wrong direction --------------------------

(when have-keys?
  (let* ((a (rsa-load-private-key (p "a.pem")))
         (b (rsa-load-private-key (p "b.pem")))
         (a-pub (rsa-load-public-key (p "a.pub")))
         (b-pub (rsa-load-public-key (p "b.pub")))
         (msg (u "signed by exactly one of these keys"))
         (sig-a (rsa-sign-sha256 a msg)))
    (check "other-key-rejects-signature" (not (rsa-verify-sha256 b-pub msg sig-a)))
    (check "own-key-accepts-signature" (rsa-verify-sha256 a-pub msg sig-a))
    (check "signature-swapped-between-keys"
      (not (rsa-verify-sha256 a-pub msg (rsa-sign-sha256 b msg))))
    (check "cli-rejects-wrong-key"
      (begin (write-bytes (p "m-swap.bin") msg)
             (write-bytes (p "ours.sig") sig-a)
             (not (cli-verify "b.pub" "m-swap.bin" "ours.sig"))))
    ;; a 3072-bit key's signature is not even the right length for a
    ;; 2048-bit modulus, and must be refused as an answer, not a raise
    (check "wrong-size-signature-rejected"
      (not (rsa-verify-sha256 a-pub msg
             (rsa-sign-sha256 (rsa-load-private-key (p "c.pem")) msg))))
    ;; PKCS#1 v1.5 carries the digest's OID: a SHA-1 signature over the same
    ;; bytes must NOT verify as SHA-256, or the algorithm is not really bound
    (check "sha1-signature-not-accepted-as-sha256"
      (begin
        (system (string-append "openssl dgst -sha1 -sign " (p "a.pem") " -out "
                               (p "sha1.sig") " " (p "m-swap.bin") " 2>/dev/null"))
        (not (rsa-verify-sha256 a-pub msg (read-bytes (p "sha1.sig"))))))
    ;; every single-byte corruption of a valid signature must be caught
    (check "every-byte-corruption-rejected"
      (let loop ((i 0))
        (cond ((= i (bytevector-length sig-a)) #t)
              ((rsa-verify-sha256 a-pub msg (flip sig-a i)) #f)
              (else (loop (+ i 1))))))
    ;; a public key where a private one is required
    (check "public-key-cannot-sign"
      (rsa-error? (lambda () (rsa-sign-sha256 a-pub msg))))
    (check "certificate-key-cannot-sign"
      (rsa-error? (lambda () (rsa-sign-sha256 (rsa-load-public-key (p "a.cert.pem")) msg))))
    ;; a public PEM is not a private key and vice versa
    (check "public-pem-to-private-loader-raises"
      (rsa-error? (lambda () (rsa-load-private-key (p "a.pub")))))
    (check "private-pem-to-public-loader-raises"
      (rsa-error? (lambda () (rsa-load-public-key (p "a.pem")))))
    (check "certificate-to-private-loader-raises"
      (rsa-error? (lambda () (rsa-load-private-key (p "a.cert.pem")))))))

;; ---- PEMs that are not RSA keys, or not keys at all --------------------

(when have-keys?
  (check "ec-public-pem-raises-rsa-error"
    (rsa-error? (lambda () (rsa-load-public-key (p "ec.pub")))))
  (check "ec-private-pem-raises-rsa-error"
    (rsa-error? (lambda () (rsa-load-private-key (p "ec.pem")))))
  ;; an empty file, and a file of only whitespace
  (system (string-append "> " (p "empty.pem") "; printf '\\n\\n\\n' > " (p "blank.pem")))
  (check "empty-file-raises" (raises? (lambda () (rsa-load-public-key (p "empty.pem")))))
  (check "empty-file-raises-private" (raises? (lambda () (rsa-load-private-key (p "empty.pem")))))
  (check "blank-file-raises" (raises? (lambda () (rsa-load-public-key (p "blank.pem")))))
  ;; truncated PEMs: cut in the middle of the body, and with the END line
  ;; removed entirely
  (let* ((text (read-text (p "a.pub")))
         (half (substring text 0 (div (string-length text) 2))))
    (write-bytes (p "half.pub") (u half))
    (check "truncated-pem-raises" (rsa-error? (lambda () (rsa-load-public-key (p "half.pub")))))
    (check "truncated-pem-string-raises" (rsa-error? (lambda () (rsa-public-key-from-pem half)))))
  (let* ((text (read-text (p "a.pem")))
         (half (substring text 0 (div (string-length text) 2))))
    (write-bytes (p "half.pem") (u half))
    (check "truncated-private-pem-raises"
      (rsa-error? (lambda () (rsa-load-private-key (p "half.pem"))))))
  ;; one flipped character inside a well-formed body
  (let* ((text (read-text (p "a.pub")))
         (i (div (string-length text) 2))
         (corrupt (string-append (substring text 0 i)
                                 (if (char=? #\A (string-ref text i)) "B" "A")
                                 (substring text (+ i 1) (string-length text)))))
    (check "corrupted-pem-body-refused-or-different"
      ;; either it fails to parse, or it parses to a DIFFERENT key -- what it
      ;; must never do is silently answer the original key
      (let ((k (guard (e (#t #f)) (rsa-public-key-from-pem corrupt))))
        (or (not k)
            (not (equal? (rsa-key-modulus k)
                         (rsa-key-modulus (rsa-load-public-key (p "a.pub"))))))))))

;; ---- an encrypted PEM must fail, not ask the operator a question -------
;;
;; With a NULL passphrase callback AND NULL userdata, OpenSSL installs
;; PEM_def_callback, which PROMPTS on the terminal -- and any PEM carrying
;; Proc-Type/DEK-Info headers reaches it, including one labelled BEGIN
;; PUBLIC KEY, so caller-supplied input gets there too. In a single-threaded
;; runtime that read stops everything.
;;
;; The check has to run in a CHILD process for two reasons: the prompt is
;; written by OpenSSL to the terminal rather than to anything this process
;; can capture, and a regression here would HANG rather than fail, which is
;; the one outcome a test must not inflict on the suite that runs it.

;; Run one loader in a child and report what it said. The child is killed
;; by a shell watchdog after `kill-after` seconds, because every regression
;; guarded here HANGS rather than fails -- a terminal prompt waiting on
;; stdin, a key derivation the attacker sized, a FIFO with no writer -- and
;; a suite must not be hangable by the thing it is testing. `timeout(1)` is
;; not used: it is not in the base system everywhere this runs.
(define (child-run script kill-after)
  (cap (string-append
         "bin=\"${SCHEME_BIN:-}\"; "
         "[ -n \"$bin\" ] || { if command -v chez >/dev/null 2>&1; "
         "then bin=chez; else bin=scheme; fi; }; "
         "\"$bin\" --script " script " < /dev/null & cpid=$!; "
         "( sleep " (number->string kill-after)
         "; kill -9 $cpid >/dev/null 2>&1 ) & wpid=$!; "
         "wait $cpid >/dev/null 2>&1; "
         "kill $wpid >/dev/null 2>&1; wait $wpid >/dev/null 2>&1; true")))

(define (write-child-script loader-form path)
  (let ((script (p "child.sc")))
    (write-bytes script
      (u (string-append
           "(import (chezscheme) (igropyr rsa))\n"
           "(display \"CHILD \")\n"
           "(display (guard (e (#t (if (and (vector? e) (eq? 'rsa-error (vector-ref e 0)))\n"
           "                          'rsa-error 'other-raise)))\n"
           "  (" loader-form " \"" path "\") 'loaded))\n"
           "(newline)\n")))
    script))

(define (child-loads label loader-form path expected)
  (let ((out (child-run (write-child-script loader-form path) 60)))
    (cond
      ((not (contains? out "CHILD "))
       (fail (string-append label "-child-ran"))
       (display "    child output: ") (write out) (newline))
      (else
        (check (string-append label "-raises-cleanly")
               (contains? out (string-append "CHILD " expected)))
        ;; the actual regression: OpenSSL asking for a passphrase
        (check (string-append label "-does-not-prompt")
               (not (contains? out "pass phrase")))))))

;; Same, but the assertion is about the CLOCK: the loader must come back
;; with an answer inside `limit-ms`, so that "it refused" is distinguished
;; from "it is still working on it". The watchdog is set well beyond the
;; limit, so a regression is reported as a slow child rather than as a
;; missing one.
(define (child-loads-promptly label loader-form path expected limit-ms)
  (let* ((script (write-child-script loader-form path))
         (t0 (real-time))
         (out (child-run script (div (* 3 limit-ms) 1000)))
         (elapsed (- (real-time) t0)))
    (check (string-append label "-answers")
           (contains? out (string-append "CHILD " expected)))
    (unless (contains? out (string-append "CHILD " expected))
      (display "    child output: ") (write out) (newline))
    (check (string-append label "-within-" (number->string limit-ms) "ms")
           (< elapsed limit-ms))
    (display "    [clock] ") (display label) (display ": ")
    (display elapsed) (display " ms\n")))

(when have-keys?
  (child-loads "encrypted-private-pem" "rsa-load-private-key" (p "a.enc.pem") "rsa-error")
  ;; a PEM an attacker can hand in: public-key label, encryption headers
  (write-bytes (p "hostile.pub")
    (u (string-append
         "-----BEGIN PUBLIC KEY-----\n"
         "Proc-Type: 4,ENCRYPTED\n"
         "DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n\n"
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
         "-----END PUBLIC KEY-----\n")))
  (child-loads "hostile-public-pem" "rsa-load-public-key" (p "hostile.pub") "rsa-error")
  ;; the same headers on a private-key label
  (write-bytes (p "hostile.pem")
    (u (string-append
         "-----BEGIN RSA PRIVATE KEY-----\n"
         "Proc-Type: 4,ENCRYPTED\n"
         "DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n"
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
         "-----END RSA PRIVATE KEY-----\n")))
  (child-loads "hostile-private-pem" "rsa-load-private-key" (p "hostile.pem") "rsa-error"))

;; An ENCRYPTED PKCS#8 key whose password is the EMPTY STRING. This is the
;; one that says whether the passphrase handling refuses or guesses: with a
;; NULL callback and a non-NULL userdata OpenSSL treats the userdata AS the
;; passphrase, so an empty C string is not "do not ask", it is "try the
;; empty password" -- and this key is encrypted under exactly that password,
;; so it decrypts and loads. The library's contract says unencrypted PEM
;; only, whatever the password happens to be.
(when have-keys?
  (system (string-append "cd " dir " && openssl pkcs8 -topk8 -in a.pem "
                         "-out empty.enc.pem -passout pass: -v2 aes-256-cbc "
                         "2>/dev/null"))
  (if (not (file-exists? (p "empty.enc.pem")))
      (begin
        (fail "openssl-generated-the-empty-passphrase-key")
        (display "    `openssl pkcs8 -passout pass:` did not produce a key\n")
        (display "    encrypted under the empty password, so the check that\n")
        (display "    an empty passphrase is REFUSED rather than TRIED could\n")
        (display "    not run.\n"))
      (check "pem-encrypted-under-the-empty-passphrase-refused"
        (rsa-error? (lambda () (rsa-load-private-key (p "empty.enc.pem")))))))

;; And the reason refusing matters beyond the contract: an encrypted PEM
;; names its own key-derivation parameters, so an attacker who can hand one
;; in picks the iteration count. The derivation runs inside a single
;; unpreemptible FFI call, so on a one-thread runtime it stops every green
;; process, every timer and all supervision for as long as it was asked to.
;; The PEM below carries a PBKDF2 iteration count of 2147483647 -- minutes
;; of work -- reached by generating one at 8388608 (under a second) and
;; patching the count in place, since both encode in four DER bytes and
;; nothing else in the structure moves. A loader that refuses the passphrase
;; request never starts the derivation, so it must answer in well under a
;; second; the assertion is on the clock, in a child, because the regression
;; is a hang.
(define kdf-bomb?
  (and have-keys?
       (begin
         (system (string-append "cd " dir " && openssl pkcs8 -topk8 -in a.pem "
                                "-outform DER -out kdf.der -passout pass: "
                                "-v2 aes-256-cbc -iter 8388608 2>/dev/null"))
         (and (file-exists? (p "kdf.der"))
              (let* ((der (read-bytes (p "kdf.der")))
                     ;; DER INTEGER 8388608, four content bytes
                     (at (bv-find der (bytevector #x02 #x04 #x00 #x80 #x00 #x00))))
                (and at
                     (begin
                       (bytevector-copy! (bytevector #x02 #x04 #x7f #xff #xff #xff)
                                         0 der at 6)
                       (write-bytes (p "kdf.patched.der") der)
                       (system (string-append
                                 "cd " dir " && { echo '-----BEGIN ENCRYPTED PRIVATE KEY-----'; "
                                 "openssl base64 -in kdf.patched.der; "
                                 "echo '-----END ENCRYPTED PRIVATE KEY-----'; } > kdfbomb.pem"))
                       (file-exists? (p "kdfbomb.pem")))))))))

(when (and have-keys? (not kdf-bomb?))
  (display "  SKIP key-derivation-bomb check: this openssl build would not\n")
  (display "       produce a PBES2/PBKDF2 key at -iter 8388608, or encoded\n")
  (display "       the iteration count differently, so the count could not be\n")
  (display "       patched up to 2147483647. The empty-passphrase refusal\n")
  (display "       above covers the same code path without the clock.\n"))

(when kdf-bomb?
  (child-loads-promptly "kdf-bomb-pem" "rsa-load-private-key"
                        (p "kdfbomb.pem") "rsa-error" 5000))

;; ---- RSA-PSS is a different algorithm wearing the same parameters ------
;;
;; EVP_PKEY_get1_RSA unwraps an id-RSASSA-PSS key perfectly happily, and the
;; EVP_PKEY that reaches EVP_DigestSign still carries the PSS type -- so a
;; key loaded this way would make rsa-sign-sha256 emit randomised PSS
;; signatures under a procedure whose name, and whose whole file, promise
;; PKCS#1 v1.5. It has to be refused at load.

(define pss?
  (and have-keys?
       (begin
         (system (string-append "cd " dir " && openssl genpkey -algorithm RSA-PSS "
                                "-pkeyopt rsa_keygen_bits:2048 -out pss.pem 2>/dev/null "
                                "&& openssl pkey -in pss.pem -pubout -out pss.pub 2>/dev/null"))
         (and (file-exists? (p "pss.pem")) (file-exists? (p "pss.pub"))))))

(when (and have-keys? (not pss?))
  (display "  SKIP RSA-PSS refusal checks: this openssl build would not\n")
  (display "       generate an RSA-PSS key (`openssl genpkey -algorithm\n")
  (display "       RSA-PSS`). Every other key check ran.\n"))

(when pss?
  (check "rsa-pss-private-pem-refused"
    (rsa-error? (lambda () (rsa-load-private-key (p "pss.pem")))))
  (check "rsa-pss-public-pem-refused"
    (rsa-error? (lambda () (rsa-load-public-key (p "pss.pub")))))
  ;; and the same key handed over as text, not as a path
  (check "rsa-pss-public-pem-as-string-refused"
    (rsa-error? (lambda () (rsa-public-key-from-pem (read-text (p "pss.pub")))))))

;; ---- a key too small to be worth verifying with -------------------------

(define k1024?
  (and have-keys?
       (begin
         (system (string-append "cd " dir " && openssl genpkey -algorithm RSA "
                                "-pkeyopt rsa_keygen_bits:1024 -out k1024.pem 2>/dev/null "
                                "&& openssl rsa -in k1024.pem -pubout -out k1024.pub 2>/dev/null"))
         (and (file-exists? (p "k1024.pem")) (file-exists? (p "k1024.pub"))))))

(when (and have-keys? (not k1024?))
  (display "  SKIP 1024-bit refusal checks on a real key: this openssl build\n")
  (display "       would not generate a 1024-bit RSA key (several now refuse\n")
  (display "       below 2048 by policy). The synthetic 1024-bit modulus\n")
  (display "       check above covers the same rule.\n"))

(when k1024?
  (check "real-1024-bit-private-key-refused"
    (rsa-error? (lambda () (rsa-load-private-key (p "k1024.pem")))))
  (check "real-1024-bit-public-key-refused"
    (rsa-error? (lambda () (rsa-load-public-key (p "k1024.pub"))))))

;; ---- how big a PEM is allowed to be -------------------------------------
;;
;; PEM readers skip whatever precedes the BEGIN line, so "a valid key with a
;; lot of text in front of it" is a PEM as far as OpenSSL is concerned. The
;; bound has to be applied to the input, not inferred from its shape.

(when have-keys?
  (let ((padded (string-append (make-string 70000 #\newline)
                               (read-text (p "a.pub")))))
    (check "valid-key-behind-70KB-of-padding-refused"
      (rsa-error? (lambda () (rsa-public-key-from-pem padded))))
    ;; the same key without the padding still loads, so the refusal above is
    ;; about the size and not about the leading blank lines
    (check "same-key-with-a-little-padding-still-loads"
      (rsa-key? (rsa-public-key-from-pem
                  (string-append (make-string 100 #\newline)
                                 (read-text (p "a.pub"))))))))

;; ---- a path is not just a name for bytes --------------------------------
;;
;; open() on a FIFO with no writer blocks forever and /dev/zero never
;; reaches EOF; on one OS thread either one stops every green process, and
;; no actor timeout can interrupt it, because the thread that would run the
;; timeout is the thread that is blocked. The loader opens O_NONBLOCK and
;; rejects a fd that cannot seek (a FIFO/pipe/socket answers lseek with
;; ESPIPE), so a FIFO returns instead of parking; the verdict is on the
;; opened fd, so there is no stat-then-open swap window, and /dev/zero is
;; bounded by the read limit rather than read without end. Child processes
;; with a clock, because the regression is a hang.

(when have-keys?
  (system (string-append "rm -f " (p "fifo.pem") " && mkfifo " (p "fifo.pem")
                         " 2>/dev/null"))
  (if (not (file-exists? (p "fifo.pem")))
      (begin
        (display "  SKIP FIFO refusal check: `mkfifo` is not available here,\n")
        (display "       so there is no way to present a path that blocks on\n")
        (display "       open. The character-device check below covers the\n")
        (display "       same rule.\n"))
      (child-loads-promptly "fifo-key-path" "rsa-load-private-key"
                            (p "fifo.pem") "rsa-error" 5000))
  (if (not (file-exists? "/dev/zero"))
      (begin
        (display "  SKIP character-device refusal check: this host has no\n")
        (display "       /dev/zero, so there is nothing that reads forever\n")
        (display "       without reaching EOF.\n"))
      (child-loads-promptly "char-device-key-path" "rsa-load-public-key"
                            "/dev/zero" "rsa-error" 5000)))

;; An empty file is a malformed key, and must be reported as one -- not as
;; "PEM must be a string or a bytevector", which is what a port EOF object
;; handed straight to the parser produces.
(when have-keys?
  (check "empty-file-raises-rsa-error"
    (rsa-error? (lambda () (rsa-load-public-key (p "empty.pem")))))
  (check "empty-file-raises-rsa-error-private"
    (rsa-error? (lambda () (rsa-load-private-key (p "empty.pem"))))))

;; ---- rsa-key-free! ------------------------------------------------------

(when have-keys?
  (let ((k (rsa-load-private-key (p "a.pem")))
        (msg (u "before the key is retired")))
    (let ((sig (rsa-sign-sha256 k msg)))
      (rsa-key-free! k)
      ;; idempotent: a second free must not hand a stale pointer to OpenSSL
      (rsa-key-free! k)
      (rsa-key-free! k)
      (check "free-is-idempotent" #t)
      (check "sign-after-free-raises-rsa-error"
        (rsa-error? (lambda () (rsa-sign-sha256 k msg))))
      (check "verify-after-free-raises-rsa-error"
        (rsa-error? (lambda () (rsa-verify-sha256 k msg sig))))
      ;; the cached inspection data survives: it was copied out at load
      (check "modulus-readable-after-free" (= 256 (bytevector-length (rsa-key-modulus k))))
      (check "bits-readable-after-free" (= 2048 (rsa-key-bits k)))
      (check "still-a-key-after-free" (rsa-key? k))
      (check "still-marked-private-after-free" (rsa-key-private? k))
      ;; and a freed key does not poison the ones still loaded
      (check "other-keys-unaffected-by-free"
        (rsa-verify-sha256 (rsa-load-public-key (p "a.pub")) msg sig)))))

;; ---- the OpenSSL error queue belongs to the OS thread ------------------
;;
;; One OS thread runs every green process, so all of them share one error
;; queue. A library that calls ERR_clear_error on its failure path deletes
;; whatever else was on it -- a TLS session preempted between SSL_read and
;; SSL_get_error, say -- and one that clears nothing leaves its own failures
;; to be reported as somebody else's reason. The answer is a scope: mark on
;; entry, pop to the mark on exit, so exactly what this operation pushed
;; goes away and nothing else does. Checked from outside the library,
;; against the same libcrypto it loaded.

(define ERR_clear_error #f)
(define ERR_peek_error #f)
(define push-openssl-error! #f)

(let ()
  (import (igropyr platform))
  (load-first-shared-object! 'rsa-test (shared-object-candidates "libcrypto"))
  (set! ERR_clear_error (foreign-procedure "ERR_clear_error" () void))
  (set! ERR_peek_error (foreign-procedure "ERR_peek_error" () unsigned-long))
  (let ((BIO_new_mem_buf (foreign-procedure "BIO_new_mem_buf" (void* int) void*))
        (BIO_free (foreign-procedure "BIO_free" (void*) int))
        (PEM_read_bio_PUBKEY
          (foreign-procedure "PEM_read_bio_PUBKEY" (void* void* void* void*) void*))
        (memcpy-to-c (foreign-procedure "memcpy" (void* u8* size_t) void*))
        ;; no Proc-Type/DEK-Info, so a NULL callback cannot reach a
        ;; passphrase prompt; it just fails and leaves entries on the queue
        (garbage (u "-----BEGIN PUBLIC KEY-----\nAAAAAAAAAAAAAAAA\n-----END PUBLIC KEY-----\n")))
    (set! push-openssl-error!
      (lambda ()
        (let* ((len (bytevector-length garbage))
               (buf (foreign-alloc len)))
          (memcpy-to-c buf garbage len)
          (let ((bio (BIO_new_mem_buf buf len)))
            (PEM_read_bio_PUBKEY bio 0 0 0)
            (BIO_free bio))
          (foreign-free buf))))))

(let ((bad-sig (flip rfc7515-sig 100)))
  ;; each check plants its own entry, so one failing cannot make the next
  ;; fail for a reason that is not its own
  (define (with-planted-error thunk)
    (ERR_clear_error)
    (push-openssl-error!)
    (let ((planted (ERR_peek_error)))
      (guard (e (#t #t)) (thunk))
      (and (not (zero? planted)) (= planted (ERR_peek_error)))))
  (define (leaves-nothing thunk)
    (ERR_clear_error)
    (guard (e (#t #t)) (thunk))
    (zero? (ERR_peek_error)))
  (ERR_clear_error)
  (push-openssl-error!)
  (if (zero? (ERR_peek_error))
      (begin
        (ERR_clear_error)
        (display "  SKIP error-queue scoping checks: a deliberately malformed\n")
        (display "       PEM left nothing on this build's error queue, so there\n")
        (display "       is no planted entry to see preserved and the checks\n")
        (display "       would pass vacuously.\n"))
      (begin
        (ERR_clear_error)
        (check "rejected-signature-preserves-an-unrelated-error"
          (with-planted-error
            (lambda () (rsa-verify-sha256 rfc-key rfc7515-input bad-sig))))
        (check "accepted-signature-preserves-an-unrelated-error"
          (with-planted-error
            (lambda () (rsa-verify-sha256 rfc-key rfc7515-input rfc7515-sig))))
        (check "failed-pem-parse-preserves-an-unrelated-error"
          (with-planted-error
            (lambda () (rsa-public-key-from-pem "not a PEM at all"))))
        (check "key-from-modulus-preserves-an-unrelated-error"
          (with-planted-error
            (lambda () (rsa-public-key-from-modulus rfc7515-n rfc7515-e))))
        ;; and in the other direction: nothing of its own is left behind.
        ;; The public-key loader is the sharpest case -- it tries three
        ;; parsers, so two of them always fail even on a key it accepts.
        (check "rejected-signature-leaves-nothing-behind"
          (leaves-nothing
            (lambda () (rsa-verify-sha256 rfc-key rfc7515-input bad-sig))))
        (check "failed-pem-parse-leaves-nothing-behind"
          (leaves-nothing
            (lambda () (rsa-public-key-from-pem "not a PEM at all"))))
        (when have-keys?
          (check "successful-pem-parse-leaves-nothing-behind"
            (leaves-nothing (lambda () (rsa-load-public-key (p "a.pub")))))
          (check "successful-private-pem-parse-leaves-nothing-behind"
            (leaves-nothing (lambda () (rsa-load-private-key (p "a.pem"))))))
        (ERR_clear_error))))

;; NOT TESTED, and said out loud rather than covered by an assertion that
;; could not fail:
;;
;;  - That the PEM is copied into memory C owns before BIO_new_mem_buf sees
;;    it. The bug it prevents needs a collection to land between the BIO
;;    construction and the PEM reader, and Scheme cannot ask for a
;;    collection at a point inside a procedure it is calling. Verifiable
;;    only by reading with-bio.
;;
;;  - That sign and verify hold their own EVP_PKEY reference, so a rotation
;;    that frees the key while an operation is in flight cannot hand
;;    OpenSSL a dangling pointer. Reaching the window needs two processes
;;    interleaved inside one operation, and the operation now runs with
;;    preemption off precisely so that cannot happen -- the property and
;;    the means of provoking it exclude each other. Verifiable only by
;;    reading with-pkey-ref.
;;
;;  - That a verification which could not be PERFORMED raises instead of
;;    answering #f. The reachable trigger the review named was an RSA-PSS
;;    key restricted to another digest, and refusing PSS keys at load (see
;;    above) removes it; what is left -- a provider or policy refusal, an
;;    allocation failure inside EVP_DigestVerifyInit -- cannot be
;;    provoked from Scheme. What IS pinned, by the signature checks
;;    throughout this file, is the other half of that boundary: a
;;    malformed, truncated, over-long, all-zero or all-ones signature must
;;    still answer #f and must NOT raise, which is what would break first
;;    if the classification were widened too far.

;; ---- FFI discipline: contexts and BIOs freed on the failing paths ------
;;
;; Every verify allocates an EVP_MD_CTX and every PEM attempt a BIO (three
;; per public-key parse, two of which always fail). None of those failures
;; happens often enough anywhere else in the suite for a missing free to
;; show up, so it is provoked here and measured.

(define rss-file (p "rss.txt"))
(define (rss-kb)
  (system (string-append "ps -o rss= -p " (number->string (get-process-id))
                         " > " rss-file " 2>/dev/null"))
  (let ((s (read-text rss-file)))
    (or (string->number
          (let loop ((i 0))
            (cond ((= i (string-length s)) "0")
                  ((char-whitespace? (string-ref s i)) (loop (+ i 1)))
                  (else (let loop2 ((j i))
                          (if (or (= j (string-length s))
                                  (char-whitespace? (string-ref s j)))
                              (substring s i j)
                              (loop2 (+ j 1))))))))
        0)))

(let ((bad-sig (flip rfc7515-sig 100))
      (garbage "-----BEGIN PUBLIC KEY-----\nAAAAAAAAAAAAAAAA\n-----END PUBLIC KEY-----\n")
      (n 4000))
  (do ((i 0 (+ i 1))) ((= i 200))
    (rsa-verify-sha256 rfc-key rfc7515-input bad-sig)
    (guard (e (#t #t)) (rsa-public-key-from-pem garbage)))
  (collect (collect-maximum-generation))
  (let ((before (rss-kb)))
    (if (zero? before)
        ;; a zero reading is no reading: comparing 0 to 0 would pass however
        ;; badly the library leaked, which is worse than not measuring
        (begin
          (display "  SKIP resident-set check: `ps -o rss= -p PID` printed no\n")
          (display "       number on this host, so there is nothing to compare\n")
          (display "       and the check would pass vacuously. Every other\n")
          (display "       check in this suite ran; to cover the FFI free paths\n")
          (display "       as well, run where ps reports RSS in kilobytes.\n"))
        (begin
          (do ((i 0 (+ i 1))) ((= i n))
            ;; a rejected signature: the MD context must be freed on the #f path
            (rsa-verify-sha256 rfc-key rfc7515-input bad-sig)
            ;; three failed PEM parses and their BIOs, ending in a raise
            (guard (e (#t #t)) (rsa-public-key-from-pem garbage))
            ;; a key built and dropped: its EVP_PKEY is the caller's to release,
            ;; and this loop is what makes the accounting visible
            (rsa-key-free! (rsa-public-key-from-modulus rfc7515-n rfc7515-e)))
          (collect (collect-maximum-generation))
          (let* ((after (rss-kb)) (grew (- after before)))
            (display "  [rss] ") (display n)
            (display " rejected verifies + failed PEM parses + key churn: ")
            (display before) (display " -> ") (display after) (display " KB\n")
            (check "no-rss-growth-on-failure-paths" (< grew 32768)))))))

;; nothing minted here may outlive the run: these are private keys
(system (string-append "rm -rf " dir))
(check "key-material-removed" (not (file-exists? (p "a.pem"))))

(if (zero? failures)
    (begin (display "rsa: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
