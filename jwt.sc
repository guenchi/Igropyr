#!chezscheme
;;; (igropyr jwt) -- JSON Web Tokens: HS256 JWS compact serialization.
;;;
;;;   (jwt-sign '(("sub" . "42") ("role" . "admin")) key
;;;             '((expires-in . 3600)))            ; -> token string
;;;   (jwt-verify token key)                       ; -> claims alist | #f
;;;   (jwt-verify token key '((leeway . 30) (iss . "api.example.com")))
;;;   (app-use app (auth (jwt-verifier key)))      ; (igropyr middleware)
;;;   (req-claims req)                             ; claims in a handler
;;;
;;; This library is the CREDENTIAL FORMAT only (the J is JSON). The
;;; HTTP-side middleware lives in (igropyr middleware) under the
;;; format-neutral name auth -- it guards s-expression RPC endpoints
;;; just as well, taking any (lambda (token) claims-or-#f) verifier.
;;; jwt-verifier packages a key (+ options) into that shape.
;;;
;;; A token is EXTERNAL INPUT, so everything here is always-on business
;;; code -- none of it is behind IGROPYR_CONTRACTS (contracts on the
;;; exported procedures only guard our own callers' argument types).
;;;
;;; Security decisions, deliberate and non-configurable:
;;;   - the algorithm is pinned: a token verifies as HS256 or not at
;;;     all. The header's alg field must literally be "HS256"; "none"
;;;     and everything else is rejected, so algorithm-confusion
;;;     downgrades are unrepresentable.
;;;   - signatures compare in constant time (no early exit), so a
;;;     byte-at-a-time timing oracle cannot forge one.
;;;   - base64url decoding is strict: any character outside the url
;;;     alphabet rejects the token (fail closed, no silent skipping).
;;;   - exp/nbf must be numbers when present; a malformed time claim
;;;     rejects the token rather than skipping the check.
;;;   - every verification failure returns the same #f -- no reason
;;;     oracle for an attacker to probe.
;;;
;;; The key is a string (taken as UTF-8) or a bytevector. Use at least
;;; 32 random bytes; the sid generator's /dev/urandom pattern in
;;; (igropyr session) is a good source. Claims alists returned by
;;; jwt-verify have STRING keys ((igropyr json) object convention) --
;;; read them with json-ref, which accepts symbols too.
;;;
;;; jwt-sign accepts claims with symbol or string keys. With
;;; '((expires-in . N)) it stamps iat = now and exp = now + N unless
;;; the caller already provided them. Registered claims are otherwise
;;; the caller's responsibility.
;;;
;;; jwt-decode parses WITHOUT verifying -- logging and debugging only,
;;; never authorization.
;;;
;;; Not implemented (yet): RS256/ES256 (no RSA/EC in (igropyr crypto)),
;;; HS384/HS512 (no SHA-384/512), JWE, multi-signature JWS JSON
;;; serialization. Adding an algorithm means extending sign+verify in
;;; lockstep; the verifier must stay pinned to an explicit list.

(library (igropyr jwt)
  (export jwt-sign jwt-verify jwt-verifier jwt-decode)
  (import (chezscheme) (igropyr checked) (igropyr util)
          (igropyr crypto) (igropyr json))

  (define (jwt-fail msg)
    (raise (vector 'jwt-error msg)))

  ;; ---- base64url ---------------------------------------------------------
  ;;
  ;; The pair lives in (igropyr crypto); it is shared with the JWKS/RS256
  ;; paths, which must decode token segments exactly the same way. Only the
  ;; error tagging is local: crypto raises &assertion for a stray character
  ;; or a non-canonical tail, and a malformed TOKEN has to surface as a jwt
  ;; error, since it is untrusted input rather than a caller bug.
  (define (b64url-decode s)
    (guard (e (#t (jwt-fail "malformed base64url")))
      (base64url-decode s)))

  ;; ---- helpers -----------------------------------------------------------

  ;; constant time over the shared length; HS256 tags are fixed 32 bytes,
  ;; so the length itself is public
  (define (bv-ct=? a b)
    (let ((n (bytevector-length a)))
      (and (fx= n (bytevector-length b))
           (let loop ((i 0) (diff 0))
             (if (fx= i n)
                 (fxzero? diff)
                 (loop (fx+ i 1)
                       (fxior diff (fxxor (bytevector-u8-ref a i)
                                          (bytevector-u8-ref b i)))))))))

  (define (key->bv key)
    (cond ((bytevector? key) key)
          ((string? key) (string->utf8 key))
          (else (assertion-violation 'jwt
                  "key must be a string or bytevector" key))))

  ;; "h.p.s" with non-empty parts and exactly two dots, or #f
  (define (split-3 s)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (parts '()))
        (cond
          ((fx= i n)
           (and (fx> i start) (fx= (length parts) 2)
                (reverse (cons (substring s start i) parts))))
          ((char=? (string-ref s i) #\.)
           (and (fx> i start)
                (loop (fx+ i 1) (fx+ i 1) (cons (substring s start i) parts))))
          (else (loop (fx+ i 1) start parts))))))

  (define (now-sec) (time-second (current-time)))

  ;; claim lookup tolerating symbol or string keys on the sign side
  (define (claim-present? claims name)
    (exists (lambda (kv)
              (and (pair? kv)
                   (let ((k (car kv)))
                     (equal? name (if (symbol? k) (symbol->string k) k)))))
            claims))

  ;; ---- sign ----------------------------------------------------------------

  ;; the header is constant: the algorithm is pinned, so it is built once
  (define header-b64
    (base64url-encode (string->utf8 "{\"alg\":\"HS256\",\"typ\":\"JWT\"}")))

  ;; rest: one options alist; (expires-in . secs) stamps iat/exp
  (define (jwt-sign claims key . rest)
    (let* ((o (if (pair? rest) (car rest) '()))
           (expires-in (opt o 'expires-in #f))
           (claims
             (if expires-in
                 (let ((now (now-sec)))
                   (append claims
                     (if (claim-present? claims "iat")
                         '()
                         (list (cons "iat" now)))
                     (if (claim-present? claims "exp")
                         '()
                         (list (cons "exp" (+ now expires-in))))))
                 claims))
           (signing-input
             (string-append header-b64 "."
               (base64url-encode (string->utf8 (json->string claims))))))
      (string-append signing-input "."
        (base64url-encode
          (hmac-sha256 (key->bv key) (string->utf8 signing-input))))))

  ;; ---- verify ----------------------------------------------------------------

  ;; absent -> pass; present -> must be a number and satisfy pred
  ;; FINITE, not merely real. +inf.0 is a real, so a correctly signed token
  ;; carrying exp=1e999 used to satisfy (real? v) and then (< now v) -- a
  ;; token that never expires. (igropyr json) now refuses non-finite numbers
  ;; at the parse, but this check does not depend on that: claims can reach
  ;; here from any decoder, and an expiry is the last place to take a value
  ;; on trust.
  (define (time-claim-ok? claims name pred)
    (let ((p (assoc name claims)))
      (or (not p)
          (let ((v (cdr p)))
            (and (real? v) (not (nan? v)) (not (infinite? v)) (pred v))))))

  ;; aud claim: a string, or an array of strings (list or vector)
  (define (aud-match? a expected)
    (cond
      ((equal? a expected) #t)
      ((vector? a) (let lp ((i 0))
                     (and (fx< i (vector-length a))
                          (or (equal? (vector-ref a i) expected)
                              (lp (fx+ i 1))))))
      ((list? a) (and (member expected a) #t))
      (else #f)))

  ;; -> claims alist (possibly '(), still true) | #f. Every failure --
  ;; format, algorithm, signature, time, iss/aud -- is the same #f.
  ;; rest: one options alist: (leeway . secs) (iss . str) (aud . str)
  (define (jwt-verify token key . rest)
    ;; the key is OUR caller's argument, not attacker input: a bad key
    ;; type crashes loudly here, outside the fail-closed guard below
    (let ((kbv (key->bv key)))
     (guard (e (#t #f))                ; malformed anything = invalid
      (let* ((o (if (pair? rest) (car rest) '()))
             (leeway (opt o 'leeway 0))
             (iss (opt o 'iss #f))
             (aud (opt o 'aud #f))
             (parts (and (string? token) (split-3 token))))
        (and parts
             (let* ((h64 (car parts)) (p64 (cadr parts)) (s64 (caddr parts))
                    (header (string->json (utf8->string (b64url-decode h64)))))
               (and (list? header)
                    (equal? (json-ref header "alg") "HS256")
                    (let ((typ (json-ref header "typ")))
                      (or (not typ) (and (string? typ) (string-ci=? typ "JWT"))))
                    (bv-ct=?
                      (hmac-sha256 kbv
                        (string->utf8 (string-append h64 "." p64)))
                      (b64url-decode s64))
                    ;; signature holds: now, and only now, judge claims
                    (let ((claims (string->json (utf8->string (b64url-decode p64))))
                          (now (now-sec)))
                      (and (list? claims)
                           (time-claim-ok? claims "exp" (lambda (v) (< now (+ v leeway))))
                           (time-claim-ok? claims "nbf" (lambda (v) (>= now (- v leeway))))
                           (or (not iss) (equal? (json-ref claims "iss") iss))
                           (or (not aud) (aud-match? (json-ref claims "aud") aud))
                           claims)))))))))

  ;; ---- decode without verification (logging/debugging ONLY) ---------------

  ;; -> (header . claims) | #f. Never use the result for authorization.
  (define-checked (jwt-decode (token string?))
    (guard (e (#t #f))
      (let ((parts (split-3 token)))
        (and parts
             (cons (string->json (utf8->string (b64url-decode (car parts))))
                   (string->json (utf8->string (b64url-decode (cadr parts)))))))))

  ;; ---- verifier factory ------------------------------------------------------

  ;; Package a key (+ verification options: leeway/iss/aud) into the
  ;; (lambda (token) claims-or-#f) shape that (igropyr middleware)'s
  ;; auth takes. The key is checked here, at boot, not per request.
  (define (jwt-verifier key . rest)
    (let ((kbv (key->bv key))
          (o (if (pair? rest) (car rest) '())))
      (lambda (token) (jwt-verify token kbv o))))
)
