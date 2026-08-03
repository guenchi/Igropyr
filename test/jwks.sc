#!chezscheme
;;; (igropyr jwks) RS256 + JWKS, as a closed loop: generate a key, sign with
;;; the private half, and verify through a JWKS document served over real
;;; HTTP -- the same path an application takes. Nothing is asserted against a
;;; recorded fixture, so a change that corrupted BOTH sides consistently
;;; would go unnoticed; the second key exists for exactly that reason, since
;;; a token signed by one must fail against the other's published modulus.
;;;
;;; Requires the openssl CLI to mint the test keys (ephemeral, in /tmp).

(import (chezscheme) (igropyr actor) (igropyr jwks) (igropyr json)
        (igropyr crypto) (igropyr express) (igropyr http))

(define dir "/tmp/igropyr-jwks-test")
(define port 18771)

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(system (string-append "rm -rf " dir " && mkdir -p " dir))
(system (string-append "openssl genpkey -algorithm RSA -pkeyopt "
                       "rsa_keygen_bits:2048 -out " dir "/a.pem 2>/dev/null"))
(system (string-append "openssl genpkey -algorithm RSA -pkeyopt "
                       "rsa_keygen_bits:2048 -out " dir "/b.pem 2>/dev/null"))

(define key-a (jwks-load-key (string-append dir "/a.pem")))
(define key-b (jwks-load-key (string-append dir "/b.pem")))

(define url (string-append "http://127.0.0.1:" (number->string port)
                           "/.well-known/jwks.json"))
(define url-b (string-append "http://127.0.0.1:" (number->string port)
                             "/b/jwks.json"))
(define delayed-url (string-append "http://127.0.0.1:" (number->string port)
                                    "/delayed/jwks.json"))

;; how many times each document has actually been fetched -- the cache and
;; the kid-miss refetch are claims about NETWORK behaviour, so counting is
;; the only way to assert them
(define fetches-a 0)
(define fetches-b 0)
(define delayed-fetches 0)
(define test-owner #f)

(define app (create-app))
(app-get app "/.well-known/jwks.json"
  (lambda (req res)
    (set! fetches-a (+ fetches-a 1))
    (set-header! res "Content-Type" "application/json")
    (send-text! res (jwks-document key-a))))
(app-get app "/b/jwks.json"
  (lambda (req res)
    (set! fetches-b (+ fetches-b 1))
    (set-header! res "Content-Type" "application/json")
    (send-text! res (jwks-document key-b))))
(app-get app "/delayed/jwks.json"
  (lambda (req res)
    (set! delayed-fetches (+ delayed-fetches 1))
    ;; Hold the first reply until the test clears the cache. Later requests
    ;; answer immediately, so a post-clear refetch is directly observable.
    (when (= delayed-fetches 1)
      (send test-owner (vector 'delayed-fetch-started self))
      (receive (after 5000 (void))
        (`#(release-delayed-fetch) (void))))
    (set-header! res "Content-Type" "application/json")
    (send-text! res (jwks-document key-a))))

(start-scheduler
  (lambda ()
    (set! test-owner self)
    (app-listen app port '((workers . 2)))
    (sleep-ms 200)

    ;; ---- key identity ---------------------------------------------------
    (check "kid is 16 hex chars"
      (and (string? (jwks-key-id key-a))
           (= 16 (string-length (jwks-key-id key-a)))))
    ;; kid is derived from the modulus, so two keys cannot collide and the
    ;; same PEM always yields the same kid (this is what makes rotation work)
    (check "distinct keys get distinct kids"
      (not (string=? (jwks-key-id key-a) (jwks-key-id key-b))))
    (check "kid is stable across loads"
      (string=? (jwks-key-id key-a)
                (jwks-key-id (jwks-load-key (string-append dir "/a.pem")))))

    ;; ---- the document ---------------------------------------------------
    (let* ((doc (string->json (jwks-document key-a)))
           (keys (json-ref doc "keys"))
           (k0 (and (vector? keys) (= 1 (vector-length keys))
                    (vector-ref keys 0))))
      (check "document has one key" (and k0 #t))
      (check "document announces RSA/RS256/sig"
        (and (equal? (json-ref k0 "kty") "RSA")
             (equal? (json-ref k0 "alg") "RS256")
             (equal? (json-ref k0 "use") "sig")))
      (check "document kid matches the key"
        (equal? (json-ref k0 "kid") (jwks-key-id key-a)))
      ;; the modulus must be published unpadded base64url, not standard
      ;; base64 -- a '+' or '/' here is a document every other library
      ;; rejects, and nothing else in this test would notice
      (check "modulus is base64url with no padding"
        (let ((n (json-ref k0 "n")))
          (and (string? n)
               (not (memv #\+ (string->list n)))
               (not (memv #\/ (string->list n)))
               (not (memv #\= (string->list n))))))
      ;; RSA-2048 => 256-byte modulus
      (check "modulus is 2048 bits"
        (= 256 (bytevector-length (base64url-decode (json-ref k0 "n"))))))

    ;; ---- sign / verify round trip ---------------------------------------
    (let ((tok (jwks-sign key-a '(("iss" . "https://a.example")
                                  ("sub" . "u-1")
                                  ("aud" . "svc"))
                          '((expires-in . 300)))))
      (check "token has three segments"
        (= 2 (let loop ((i 0) (n 0))
               (cond ((= i (string-length tok)) n)
                     ((char=? (string-ref tok i) #\.) (loop (+ i 1) (+ n 1)))
                     (else (loop (+ i 1) n))))))
      (let ((claims (jwks-verify tok url)))
        (check "round trip verifies" (and claims #t))
        (check "claims survive" (equal? (cdr (assoc "sub" claims)) "u-1"))
        ;; expires-in stamps both, so a verifier elsewhere can bound the token
        (check "expires-in stamped iat and exp"
          (and (assoc "iat" claims) (assoc "exp" claims)
               (= 300 (- (cdr (assoc "exp" claims))
                         (cdr (assoc "iat" claims)))))))

      ;; ---- claim gates --------------------------------------------------
      (check "matching iss accepted"
        (and (jwks-verify tok url '((iss . "https://a.example"))) #t))
      (check "wrong iss refused"
        (not (jwks-verify tok url '((iss . "https://evil.example")))))
      (check "matching aud accepted"
        (and (jwks-verify tok url '((aud . "svc"))) #t))
      (check "wrong aud refused"
        (not (jwks-verify tok url '((aud . "other")))))

      ;; ---- the signature actually matters -------------------------------
      ;; verifying key-a's token against key-b's published modulus must fail.
      ;; Without this, a verify that ignored the signature entirely would
      ;; pass every other assertion in this file.
      (check "token refused against a different key's JWKS"
        (not (jwks-verify tok url-b)))

      ;; THE load-bearing signature case: a token whose kid resolves, whose
      ;; three segments all decode, and whose ONLY defect is that the
      ;; signature was made by the wrong key. Every other rejection here can
      ;; also be produced by a malformed segment or a kid miss, so without
      ;; this one a verifier that skipped the signature entirely still passes
      ;; the whole file -- verified by short-circuiting rs256-verify to #t.
      (let* ((b-tok (jwks-sign key-b '(("iss" . "https://a.example")
                                       ("sub" . "u-1"))))
             (d1 (let loop ((i 0))
                   (if (char=? (string-ref b-tok i) #\.) i (loop (+ i 1)))))
             ;; re-label it with key-a's kid: the JWKS lookup now succeeds and
             ;; hands back key-a's modulus, against which the signature fails
             (relabelled
               (string-append
                 (base64url-encode
                   (string->utf8
                     (string-append "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\""
                                    (jwks-key-id key-a) "\"}")))
                 (substring b-tok d1 (string-length b-tok)))))
        (check "valid-shaped token with a foreign signature refused"
          (not (jwks-verify relabelled url))))

      ;; a flipped byte in the payload invalidates the signature; the claims
      ;; must never be read, let alone returned
      (let* ((last-dot (let loop ((i (- (string-length tok) 1)))
                         (if (char=? (string-ref tok i) #\.) i (loop (- i 1)))))
             (tampered (string-append
                         (substring tok 0 3)
                         (if (char=? (string-ref tok 3) #\A) "B" "A")
                         (substring tok 4 (string-length tok)))))
        (check "tampered token refused" (not (jwks-verify tampered url))))

      ;; ---- alg pinning ----------------------------------------------------
      ;; the alg=none downgrade: re-encode the header as {"alg":"none"} and
      ;; drop the signature. A verifier that trusted the header would accept.
      (let* ((d1 (let loop ((i 0))
                   (if (char=? (string-ref tok i) #\.) i (loop (+ i 1)))))
             (d2 (let loop ((i (+ d1 1)))
                   (if (char=? (string-ref tok i) #\.) i (loop (+ i 1)))))
             (p64 (substring tok (+ d1 1) d2))
             ;; the kid MUST be the real one: a header without it is rejected
             ;; for the missing kid, which would make these pass no matter
             ;; what the alg check does -- the bug this pair exists to catch
             (kid (jwks-key-id key-a))
             (none-h (base64url-encode
                       (string->utf8
                         (string-append "{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\""
                                        kid "\"}")))))
        (check "alg=none refused"
          (not (jwks-verify (string-append none-h "." p64 ".") url)))
        ;; HS256 with the modulus as the key is the classic confusion attack
        (let ((hs-h (base64url-encode
                      (string->utf8
                        (string-append "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\""
                                       kid "\"}")))))
          (check "alg=HS256 refused"
            (not (jwks-verify (string-append hs-h "." p64 ".sig") url))))
        ;; and a header carrying the right kid but no alg at all
        (let ((no-alg (base64url-encode
                        (string->utf8
                          (string-append "{\"typ\":\"JWT\",\"kid\":\"" kid "\"}")))))
          (check "missing alg refused"
            (not (jwks-verify (string-append no-alg "." p64 ".") url)))))

      ;; ---- malformed input is #f, never a raise --------------------------
      (check "empty token refused" (not (jwks-verify "" url)))
      (check "non-JWT refused" (not (jwks-verify "not-a-token" url)))
      (check "two segments refused"
        (not (jwks-verify "aaa.bbb" url)))
      (check "four segments refused"
        (not (jwks-verify (string-append tok ".extra") url)))
      (check "non-string token refused" (not (jwks-verify 42 url)))
      ;; an unreachable JWKS is a #f, not an exception escaping into the
      ;; caller's request handler
      (check "unreachable jwks url refused"
        (not (jwks-verify tok "http://127.0.0.1:1/nope.json")))

      ;; ---- expiry ---------------------------------------------------------
      (let ((expired (jwks-sign key-a
                       `(("iss" . "https://a.example")
                         ("exp" . ,(- (time-second (current-time)) 60))))))
        (check "expired token refused" (not (jwks-verify expired url)))
        ;; leeway is what lets a fleet with imperfect clocks interoperate
        (check "expired token accepted within leeway"
          (and (jwks-verify expired url '((leeway . 120))) #t)))
      (let ((future (jwks-sign key-a
                      `(("iss" . "https://a.example")
                        ("nbf" . ,(+ (time-second (current-time)) 60))))))
        (check "not-yet-valid token refused" (not (jwks-verify future url))))

      ;; ---- caching and the kid-miss refetch -------------------------------
      ;; every verify above went through one document; the cache means the
      ;; count must be far below the number of calls
      (check "jwks document is cached across verifies"
        (< fetches-a 5))
      (let ((before fetches-a))
        (jwks-verify tok url)
        (check "a cached verify performs no fetch" (= before fetches-a)))
      ;; an unknown kid forces exactly one refetch (issuer rotation), and no
      ;; more -- otherwise unknown kids become a way to drive traffic at the
      ;; issuer on demand
      (let* ((before fetches-a)
             (odd-h (base64url-encode
                      (string->utf8
                        "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"deadbeefdeadbeef\"}")))
             (odd-h-2 (base64url-encode
                        (string->utf8
                          "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"feedfacefeedface\"}")))
             (d1 (let loop ((i 0))
                   (if (char=? (string-ref tok i) #\.) i (loop (+ i 1)))))
             (d2 (let loop ((i (+ d1 1)))
                   (if (char=? (string-ref tok i) #\.) i (loop (+ i 1)))))
             (rest (substring tok d1 (string-length tok))))
        (check "unknown kid refused"
          (not (jwks-verify (string-append odd-h rest) url)))
        (check "unknown kid refetches exactly once"
          (= (+ before 1) fetches-a))
        ;; The header is untrusted and changing the kid is free. A second
        ;; miss inside the cooldown must fail without another network fetch.
        (let ((after-first fetches-a))
          (check "second unknown kid refused"
            (not (jwks-verify (string-append odd-h-2 rest) url)))
          (check "unknown kid refresh is rate-limited"
            (= after-first fetches-a))))
      (check "cache clear forces a refetch"
        (let ((before fetches-a))
          (jwks-cache-clear!)
          (jwks-verify tok url)
          (= (+ before 1) fetches-a)))

      ;; A clear that races an older in-flight fetch must win. Otherwise the
      ;; old completion silently repopulates the cache after clear! returns.
      (jwks-cache-clear!)
      (spawn
        (lambda ()
          (let ((ok (guard (e (#t #f)) (jwks-fetch! delayed-url) #t)))
            (send test-owner (vector 'delayed-fetch-done ok)))))
      (let ((server
              (receive (after 5000 #f)
                (`#(delayed-fetch-started ,pid) pid))))
        (check "delayed fetch reached the server" (and server #t))
        (when server
          (jwks-cache-clear!)
          (send server (vector 'release-delayed-fetch))
          (check "in-flight fetch still returns to its caller"
            (receive (after 5000 #f)
              (`#(delayed-fetch-done ,ok) ok)))
          (let ((before delayed-fetches))
            (check "cache clear rejects an older fetch completion"
              (and (jwks-verify tok delayed-url)
                   (= (+ before 1) delayed-fetches)))))))

    ;; ---- releasing a key ------------------------------------------------
    ;; The EVP_PKEY behind a loaded key is a native allocation the record
    ;; owns, and nothing in Scheme collects it. That is fine for a key held
    ;; for the life of the process; it was not fine for ROTATION, where every
    ;; reload added an RSA private key to the native heap permanently.
    ;;
    ;; A leak cannot be asserted from inside the process, so what is pinned
    ;; here is the CONTRACT that makes releasing safe: the call is idempotent,
    ;; and a freed key is refused rather than passing a NULL to OpenSSL -- a
    ;; double free of an EVP_PKEY corrupts the allocator, which would be a
    ;; worse bug than the leak.
    (let ((rotated (jwks-load-key (string-append dir "/b.pem"))))
      (check "a freed key still signs before it is freed"
        (string? (jwks-sign rotated '(("sub" . "u")))))
      (jwks-key-free! rotated)
      (check "freeing twice is not a double free"
        (guard (e (#t #f)) (jwks-key-free! rotated) #t))
      (check "signing with a freed key is refused, not a NULL deref"
        (guard (e (#t #t)) (jwks-sign rotated '(("sub" . "u"))) #f))
      ;; and freeing one key does not disturb another
      (check "an unrelated key still signs"
        (string? (jwks-sign key-a '(("sub" . "u"))))))

    (system (string-append "rm -rf " dir))
    (if (zero? failures)
        (begin (display "jwks: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
