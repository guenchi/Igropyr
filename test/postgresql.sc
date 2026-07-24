#!chezscheme
;;; SCRAM-SHA-256 for (igropyr postgresql), checked against the published
;;; RFC 7677 section 3 exchange (username "user", password "pencil",
;;; i=4096). This recomputes the ClientProof and ServerSignature with the
;;; same formula the connection's auth path composes -- SaltedPassword =
;;; PBKDF2(pw, salt, i); ClientKey = HMAC(SaltedPassword,"Client Key");
;;; StoredKey = H(ClientKey); ClientSignature = HMAC(StoredKey, AuthMessage);
;;; ClientProof = ClientKey XOR ClientSignature; ServerKey =
;;; HMAC(SaltedPassword,"Server Key"); ServerSignature = HMAC(ServerKey,
;;; AuthMessage) -- and pins them to the RFC's base64 outputs. A live server
;;; is needed for the wire/framing path; this pins the cryptography.

(import (chezscheme)
        (only (igropyr crypto)
              sha256 hmac-sha256 pbkdf2-hmac-sha256 base64-encode base64-decode))

(define failures 0)
(define (check label got want)
  (if (string=? got want)
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline)
             (display "    got  ") (display got) (newline)
             (display "    want ") (display want) (newline))))

(define (bv-xor a b)
  (let* ((n (bytevector-length a)) (out (make-bytevector n)))
    (do ((i 0 (+ i 1))) ((= i n) out)
      (bytevector-u8-set! out i
        (fxxor (bytevector-u8-ref a i) (bytevector-u8-ref b i))))))

;; ---- RFC 7677 section 3 exchange ---------------------------------------
(define password "pencil")
(define client-first-bare "n=user,r=rOprNGfwEbeRWgbNEkqO")
(define server-first
  "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
(define client-final-noproof
  "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0")
(define salt (base64-decode "W22ZaJ0SNY7soEsUEjb6gQ=="))
(define iters 4096)

(define auth-msg
  (string-append client-first-bare "," server-first "," client-final-noproof))

(define salted (pbkdf2-hmac-sha256 (string->utf8 password) salt iters 32))
(define client-key (hmac-sha256 salted (string->utf8 "Client Key")))
(define stored-key (sha256 client-key))
(define client-sig (hmac-sha256 stored-key (string->utf8 auth-msg)))
(define client-proof (bv-xor client-key client-sig))
(define server-key (hmac-sha256 salted (string->utf8 "Server Key")))
(define server-sig (hmac-sha256 server-key (string->utf8 auth-msg)))

(check "client-proof" (base64-encode client-proof)
  "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
(check "server-signature" (base64-encode server-sig)
  "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")

(if (zero? failures)
    (begin (display "postgresql: SCRAM-SHA-256 RFC 7677 vectors passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
