#!chezscheme
;;; (igropyr jwt) tests: sign/verify round trips, the RFC 7515 A.1
;;; known-answer vector, algorithm pinning, time claims, fail-closed
;;; parsing, and the express middleware end to end over real HTTP.

(import (chezscheme) (igropyr http) (igropyr express) (igropyr jwt)
        (igropyr json) (igropyr crypto) (igropyr libuv))

(define port 18086)
(define empty-bv (make-bytevector 0))

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))
(define (fail label detail)
  (display "FAIL ") (display label) (display ": ") (write detail) (newline)
  (exit 1))

(define key "0123456789abcdef0123456789abcdef")

;; local base64url encoder for crafting hostile tokens
(define (b64url bv)
  (let* ((s (base64-encode bv))
         (end (let lp ((i (string-length s)))
                (if (and (> i 0) (char=? (string-ref s (- i 1)) #\=)) (lp (- i 1)) i))))
    (list->string
      (map (lambda (c) (case c ((#\+) #\-) ((#\/) #\_) (else c)))
           (string->list (substring s 0 end))))))

(define (craft header-json claims-json sign-key)
  (let* ((si (string-append (b64url (string->utf8 header-json)) "."
                            (b64url (string->utf8 claims-json)))))
    (string-append si "." (b64url (hmac-sha256
                                    (if (string? sign-key) (string->utf8 sign-key) sign-key)
                                    (string->utf8 si))))))

(define (now) (time-second (current-time)))

;; ---- round trips -----------------------------------------------------

(define tok (jwt-sign '(("sub" . "42") (role . "admin")) key))
(define claims (jwt-verify tok key))
(check "round-trip" (and claims
                         (equal? (json-ref claims "sub") "42")
                         (equal? (json-ref claims "role") "admin")))
(check "empty-claims-round-trip" (equal? (jwt-verify (jwt-sign '() key) key) '()))
(check "bytevector-key"
  (let ((k (string->utf8 key)))
    (and (jwt-verify (jwt-sign '(("a" . 1)) k) k) #t)))
(check "unicode-claims"
  (let ((c (jwt-verify (jwt-sign '(("名" . "值")) key) key)))
    (equal? (json-ref c "名") "值")))

;; expires-in stamps iat/exp; caller-provided exp is kept
(let ((c (jwt-verify (jwt-sign '(("sub" . "x")) key '((expires-in . 3600))) key)))
  (check "expires-in-stamps" (and (json-ref c "iat") (json-ref c "exp")
                                  (= (- (json-ref c "exp") (json-ref c "iat")) 3600))))
(let* ((e (+ (now) 77))
       (c (jwt-verify (jwt-sign `(("exp" . ,e)) key '((expires-in . 3600))) key)))
  (check "expires-in-keeps-callers-exp" (equal? (json-ref c "exp") e)))

;; ---- rejection: keys and tampering ------------------------------------

(check "wrong-key" (not (jwt-verify tok "another-key-entirely-0123456789a")))
(check "tampered-payload"
  (not (jwt-verify (craft "{\"alg\":\"HS256\"}" "{\"sub\":\"43\"}" "other") key)))
(check "truncated-sig"
  (not (jwt-verify (substring tok 0 (- (string-length tok) 2)) key)))

;; a wrong-type key is OUR bug: it must crash loudly, not return #f
(check "bad-key-type-crashes"
  (guard (c ((assertion-violation? c) #t) (#t #f))
    (jwt-verify tok 'not-a-key)
    #f))

;; ---- algorithm pinning ---------------------------------------------------

(check "alg-none-rejected"
  (not (jwt-verify (string-append (b64url (string->utf8 "{\"alg\":\"none\"}")) "."
                                  (b64url (string->utf8 "{\"sub\":\"1\"}")) ".x")
                   key)))
(check "alg-none-empty-sig-rejected"
  (not (jwt-verify (string-append (b64url (string->utf8 "{\"alg\":\"none\"}")) "."
                                  (b64url (string->utf8 "{\"sub\":\"1\"}")) ".")
                   key)))
;; correctly HMAC-SHA256-signed but the header claims another alg: pinned out
(check "alg-hs384-header-rejected"
  (not (jwt-verify (craft "{\"alg\":\"HS384\"}" "{\"sub\":\"1\"}" key) key)))
(check "typ-wrong-rejected"
  (not (jwt-verify (craft "{\"alg\":\"HS256\",\"typ\":\"JWS\"}" "{\"sub\":\"1\"}" key) key)))
(check "typ-absent-ok"
  (and (jwt-verify (craft "{\"alg\":\"HS256\"}" "{\"sub\":\"1\"}" key) key) #t))
(check "typ-case-insensitive"
  (and (jwt-verify (craft "{\"alg\":\"HS256\",\"typ\":\"jwt\"}" "{\"sub\":\"1\"}" key) key) #t))

;; ---- time claims -------------------------------------------------------------

(check "expired" (not (jwt-verify (jwt-sign `(("exp" . ,(- (now) 10))) key) key)))
(check "expired-leeway-ok"
  (and (jwt-verify (jwt-sign `(("exp" . ,(- (now) 10))) key) key '((leeway . 60))) #t))
(check "nbf-future" (not (jwt-verify (jwt-sign `(("nbf" . ,(+ (now) 60))) key) key)))
(check "nbf-future-leeway-ok"
  (and (jwt-verify (jwt-sign `(("nbf" . ,(+ (now) 30))) key) key '((leeway . 60))) #t))
(check "nbf-past-ok"
  (and (jwt-verify (jwt-sign `(("nbf" . ,(- (now) 10))) key) key) #t))
;; malformed time claims fail closed
(check "string-exp-rejected"
  (not (jwt-verify (craft "{\"alg\":\"HS256\"}" "{\"exp\":\"later\"}" key) key)))

;; ---- iss / aud ------------------------------------------------------------------

(define itok (jwt-sign '(("iss" . "api") ("aud" . "web")) key))
(check "iss-match" (and (jwt-verify itok key '((iss . "api"))) #t))
(check "iss-mismatch" (not (jwt-verify itok key '((iss . "other")))))
(check "aud-match" (and (jwt-verify itok key '((aud . "web"))) #t))
(check "aud-mismatch" (not (jwt-verify itok key '((aud . "mobile")))))
;; aud as a JSON array (parses to a vector)
(check "aud-array-match"
  (and (jwt-verify (craft "{\"alg\":\"HS256\"}" "{\"aud\":[\"web\",\"mobile\"]}" key)
                   key '((aud . "mobile"))) #t))
(check "aud-array-mismatch"
  (not (jwt-verify (craft "{\"alg\":\"HS256\"}" "{\"aud\":[\"web\"]}" key)
                   key '((aud . "tv")))))
;; requiring iss when the token has none
(check "iss-required-absent" (not (jwt-verify tok key '((iss . "api")))))

;; ---- malformed tokens all answer the same #f -----------------------------------

(for-each
  (lambda (bad)
    (check (string-append "malformed:" (if (string? bad) bad "non-string"))
      (not (jwt-verify bad key))))
  (list "a.b" "a.b.c.d" ".." "a..c" "!!!.b.c"
        (string-append (b64url (string->utf8 "not json")) "."
                       (b64url (string->utf8 "{}")) ".sig")
        42 'sym))

;; ---- RFC 7515 A.1 known-answer ---------------------------------------------------

(define rfc-token
  (string-append
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
(define rfc-key
  (base64-decode
    (list->string
      (map (lambda (c) (case c ((#\-) #\+) ((#\_) #\/) (else c)))
           (string->list
             "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")))))
(let ((c (jwt-verify rfc-token rfc-key '((leeway . 99999999999)))))
  (check "rfc7515-A1" (and c (equal? (json-ref c "iss") "joe")
                           (equal? (json-ref c "http://example.com/is_root") #t))))
(check "rfc7515-A1-expired" (not (jwt-verify rfc-token rfc-key)))

;; ---- jwt-decode (unverified) ---------------------------------------------------------

(let ((d (jwt-decode tok)))
  (check "decode" (and d (equal? (json-ref (car d) "alg") "HS256")
                       (equal? (json-ref (cdr d) "sub") "42"))))
(check "decode-garbage" (not (jwt-decode "not-a-token")))

;; ---- middleware, end to end over real HTTP -----------------------------------------

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

;; one request on a fresh connection; returns the full response text
(define (http-req p text)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" p self)
        (receive (after 3000 (send caller (vector 'r-err ref 'connect)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c (string->utf8 text) #f)
            (let loop ((buf empty-bv))
              (receive (after 5000
                          (tcp-close! c)
                          (send caller (vector 'r-ok ref (utf8->string buf))))
                (`#(tcp-data ,bv) (loop (bv-append buf bv)))
                (`#(tcp-eof) (send caller (vector 'r-ok ref (utf8->string buf))))
                (`#(tcp-error ,e) (send caller (vector 'r-ok ref (utf8->string buf)))))))
          (`#(tcp-connect-failed ,e)
            (send caller (vector 'r-err ref e))))))
    (receive (after 10000 (fail "http-req" 'timeout))
      (`#(r-ok ,@ref ,s) s)
      (`#(r-err ,@ref ,e) (fail "http-req" e)))))

(define (get-on p path headers)
  (http-req p (string-append
                "GET " path " HTTP/1.1\r\nHost: x\r\n"
                (apply string-append
                       (map (lambda (h) (string-append h "\r\n")) headers))
                "Connection: close\r\n\r\n")))
(define (get path . headers) (get-on port path headers))

(define (status-of resp)
  (and (> (string-length resp) 12)
       (substring resp 9 12)))
(define (body-of resp)
  (let ((n (string-length resp)))
    (let loop ((i 0))
      (cond ((> (+ i 4) n) "")
            ((string=? (substring resp i (+ i 4)) "\r\n\r\n")
             (substring resp (+ i 4) n))
            (else (loop (+ i 1)))))))
(define (header-present? resp name)
  (let ((n (string-length resp)) (m (string-length name)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string-ci=? (substring resp i (+ i m)) name) #t)
            (else (loop (+ i 1)))))))

;; the middleware is app-wide, so optional mode gets its own app + port
(define app (create-app))
(app-use app (jwt-middleware key))
(app-get app "/me"
  (lambda (req res)
    (send-json! res (list (cons 'sub (json-ref (req-jwt req) "sub"))))))

(define port2 18087)
(define app2 (create-app))
(app-use app2 (jwt-middleware key '((optional . #t))))
(app-get app2 "/who"
  (lambda (req res)
    (let ((c (req-jwt req)))
      (send-json! res (list (cons 'sub (if c (json-ref c "sub") "anon")))))))

(define (get2 path . headers) (get-on port2 path headers))

(define good-tok (jwt-sign '(("sub" . "42")) key '((expires-in . 300))))

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (app-listen app2 port2 '((workers . 2)))
    (sleep-ms 100)

    (let ((r (get "/me")))
      (check "mw-no-token-401" (equal? (status-of r) "401"))
      (check "mw-www-authenticate" (header-present? r "WWW-Authenticate: Bearer")))
    (let ((r (get "/me" "Authorization: Bearer garbage.token.here")))
      (check "mw-bad-token-401" (equal? (status-of r) "401")))
    (let ((r (get "/me" (string-append "Authorization: Bearer " good-tok))))
      (check "mw-valid-200" (equal? (status-of r) "200"))
      (check "mw-claims-visible"
        (equal? (json-ref (string->json (body-of r)) "sub") "42")))
    (let ((r (get "/me" (string-append "Authorization: bearer " good-tok))))
      (check "mw-bearer-case-insensitive" (equal? (status-of r) "200")))
    (let ((r (get "/me" (string-append "Authorization: Bearer "
                          (jwt-sign `(("exp" . ,(- (now) 10))) key)))))
      (check "mw-expired-401" (equal? (status-of r) "401")))

    ;; optional mode: no token passes through, invalid still refused
    (let ((r (get2 "/who")))
      (check "mw-optional-anon-200" (equal? (status-of r) "200"))
      (check "mw-optional-anon-body"
        (equal? (json-ref (string->json (body-of r)) "sub") "anon")))
    (let ((r (get2 "/who" (string-append "Authorization: Bearer " good-tok))))
      (check "mw-optional-claims"
        (equal? (json-ref (string->json (body-of r)) "sub") "42")))
    (let ((r (get2 "/who" "Authorization: Bearer bad.bad.bad")))
      (check "mw-optional-invalid-401" (equal? (status-of r) "401")))

    (if (zero? failures)
        (begin (display "jwt: all tests passed") (newline) (exit 0))
        (begin (display failures) (display " failures") (newline) (exit 1)))))
