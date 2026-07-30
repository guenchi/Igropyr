#!chezscheme
;;; (igropyr auth) tests: WebSocket upgrade guards end to end -- the
;;; token form (jwt-verifier via Authorization header and ?token=
;;; query) and the session form (sid cookie against a live store).
;;; Refusals happen BEFORE the 101 handshake (401 over plain HTTP).
;;; The HTTP-side auth middleware is covered end to end in jwt.sc.

(import (chezscheme) (igropyr http) (igropyr express) (igropyr session)
        (igropyr auth) (igropyr jwt) (igropyr ws-client)
        (only (igropyr websocket) ws-conn ws-send-text! ws-close!)
        (igropyr json) (igropyr sexpr) (igropyr libuv))

(define port 18088)
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

;; ---- raw HTTP client (for asserting pre-handshake refusals) -----------

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

(define (http-req text)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'r-err ref 'connect)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c (string->utf8 text) #f)
            (let loop ((buf empty-bv))
              (receive (after 3000
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

;; a websocket upgrade request expected to be refused pre-handshake
(define (upgrade-req path . headers)
  (http-req (string-append
              "GET " path " HTTP/1.1\r\nHost: x\r\n"
              "Upgrade: websocket\r\nConnection: Upgrade\r\n"
              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
              "Sec-WebSocket-Version: 13\r\n"
              (apply string-append
                     (map (lambda (h) (string-append h "\r\n")) headers))
              "\r\n")))

(define (status-of resp)
  (and (> (string-length resp) 12) (substring resp 9 12)))

(define (find-substr hay needle)
  (let ((n (string-length hay)) (m (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring hay i (+ i m)) needle) i)
            (else (loop (+ i 1)))))))

;; "Set-Cookie: sid=HEX; ..." -> "HEX"
(define (extract-sid resp)
  (let ((at (find-substr resp "sid=")))
    (and at
         (let scan ((j (+ at 4)))
           (if (or (= j (string-length resp))
                   (memv (string-ref resp j) '(#\; #\return #\newline)))
               (substring resp (+ at 4) j)
               (scan (+ j 1)))))))

;; One more frame than (igropyr websocket)'s max-fragments accepts. That
;; constant is library-internal, so the number here has to track it by
;; hand: if it grows, these frames quietly stop reaching the cap and the
;; check goes back to passing without exercising anything.
(define fragment-cap 16384)

(define (zero-fragment-attack)
  ;; ... and then ONE final continuation. Without it a server that does not
  ;; cap simply waits for a frame that never comes while the test waits for
  ;; a message that never arrives: a regression hangs the suite instead of
  ;; failing it, which in CI is a burned job timeout with no diagnostic.
  (let* ((frames (+ 1 fragment-cap))
         (out (make-bytevector (* (+ frames 1) 6) 0)))
    (do ((i 0 (+ i 1))) ((= i frames))
      ;; First frame: non-final text; the rest: non-final continuations.
      (bytevector-u8-set! out (* i 6) (if (= i 0) #x01 #x00))
      (bytevector-u8-set! out (+ (* i 6) 1) #x80))
    (bytevector-u8-set! out (* frames 6) #x80)          ; FIN + continuation
    (bytevector-u8-set! out (+ (* frames 6) 1) #x80)    ; masked, length 0
    out))

;; read one text message from a ws session, then close
(define (recv-text-and-close w)
  (let ((m (ws-recv w)))
    (ws-close! w)
    (if (and (vector? m) (eq? (vector-ref m 0) 'text))
        (vector-ref m 1)
        (list 'unexpected m))))

;; ---- the app --------------------------------------------------------------

(define store (make-session-store))
(define app (create-app))
(app-use app (session-middleware store))

;; Establish anonymous state, then rotate the identifier at login.
(app-get app "/seed"
  (lambda (req res)
    (session-set! (req-session req) 'preauth "kept")
    (send-text! res "ok")))

(app-get app "/login"
  (lambda (req res)
    (session-regenerate! (req-session req))
    (session-set! (req-session req) 'user "ada")
    (send-text! res "ok")))

;; the ordering mistake: answer, then rotate. The replacement cookie can no
;; longer reach the client, so rotating anyway would drop the live id and
;; silently log the user out.
(define late-outcome 'unrun)
(app-get app "/late-rotate"
  (lambda (req res)
    (send-text! res "answered")
    (set! late-outcome
      (guard (e (#t 'raised))
        (session-regenerate! (req-session req))
        'returned))))

;; reports what the handler above saw; the client of /late-rotate cannot,
;; because its response was already on the wire before the raise
(app-get app "/late-outcome"
  (lambda (req res) (send-text! res (symbol->string late-outcome))))

;; Rotating twice in one request is idempotent: the first call marks the
;; session new, so the second returns that same id rather than minting a
;; competing one. Two layers can each insist on rotating without knowing
;; about each other.
(define twice-same? 'unrun)
(app-get app "/rotate-twice"
  (lambda (req res)
    (let* ((s (req-session req))
           (a (session-regenerate! s))
           (b (session-regenerate! s)))
      (set! twice-same? (string=? a b))
      (send-text! res "done"))))

;; A session handed to a process that outlives the handler must not be
;; able to rotate against that request's finished response. Nothing
;; answers here, so the refusal rests on the framework answering for an
;; unanswered request -- if that ever stops being true, the response token
;; stays unclaimed, res-answered? stays #f, and the drop goes through with
;; a cookie no one will ever receive. This pins that dependency.
(define escaped-outcome 'unrun)
(app-get app "/escape-rotate"
  (lambda (req res)
    (let ((s (req-session req)))
      (spawn (lambda ()
               (sleep-ms 300)
               (set! escaped-outcome
                 (guard (e (#t 'raised))
                   (session-regenerate! s)
                   'returned)))))))

(app-get app "/escape-outcome"
  (lambda (req res) (send-text! res (symbol->string escaped-outcome))))

;; unguarded ws route (regression: guards are opt-in)
(app-ws app "/open"
  (lambda (ws req)
    (ws-send-text! ws "open")
    (ws-recv ws)))

;; Answers only if a message actually got assembled and delivered. A bare
;; close cannot say why it happened -- the cap closing the session and this
;; handler simply returning look identical from the client, and ws-recv
;; surfaces no status code -- so the delivery itself has to be what is
;; observable.
(app-ws app "/sink"
  (lambda (ws req)
    (let ((m (ws-recv ws)))
      (unless (and (vector? m) (eq? (vector-ref m 0) 'close))
        (ws-send-text! ws "delivered")))))

;; token-guarded: claims are the verified JWT claims (string keys)
(app-ws app "/chat"
  (lambda (ws req)
    (ws-send-text! ws (json-ref (req-claims req) "sub"))
    (ws-recv ws))
  (token-guard (jwt-verifier key)))

;; session-guarded: claims are the session's data alist (symbol keys)
(app-ws app "/feed"
  (lambda (ws req)
    (ws-send-text! ws (cdr (assq 'user (req-claims req))))
    (ws-recv ws))
  (session-guard store))

;; Same credential, with an origin allow-list. The cookie is attached by
;; the browser whatever page opened the socket, and the same-origin policy
;; does not apply to WebSockets, so this is the only thing standing between
;; a hostile page and an authenticated session.
(app-ws app "/feed-origin"
  (lambda (ws req)
    (ws-send-text! ws "ok")
    (ws-recv ws))
  (session-guard store '((origins . ("https://app.example")))))

;; A foreign Origin must be rejected before session-peek. This deliberately
;; unusable store makes an accidental lookup raise instead of letting the
;; status check pass without exercising the ordering.
(app-ws app "/feed-origin-first"
  (lambda (ws req) (ws-recv ws))
  (session-guard (vector 'missing-session-store 0)
    '((origins . ("https://app.example")))))

;; token-guarded sexpr RPC: refusal is sexpr data; two-argument
;; handlers see the request (claims), one-argument ones work as before
(app-rpc app "/rpc"
  `((whoami . ,(lambda (args req) (json-ref (req-claims req) "sub")))
    (add    . ,(lambda (args) (apply + args))))
  (token-guard (jwt-verifier key)))

(define good-tok (jwt-sign '(("sub" . "42")) key '((expires-in . 300))))

;; sexpr RPC over raw HTTP; returns (status . reply-datum)
(define (rpc-post datum . headers)
  (let* ((body (sexpr->string datum))
         (resp (http-req
                 (string-append
                   "POST /rpc HTTP/1.1\r\nHost: x\r\nContent-Length: "
                   (number->string (string-length body))
                   "\r\n"
                   (apply string-append
                          (map (lambda (h) (string-append h "\r\n")) headers))
                   "Connection: close\r\n\r\n" body)))
         (bend (find-substr resp "\r\n\r\n")))
    (unless bend (fail "rpc-post" resp))
    (cons (status-of resp)
          (string->sexpr (substring resp (+ bend 4) (string-length resp))))))

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (sleep-ms 100)

    ;; unguarded route still upgrades with no credential
    (check "ws-open"
      (equal? (recv-text-and-close
                (ws-connect "ws://127.0.0.1:18088/open"))
              "open"))
    ;; Zero-length fragments consume a list cell and a bytevector each even
    ;; though the message stays at zero bytes, so the byte cap never fires.
    ;; The server must cap their COUNT: a close here means it did, because
    ;; the handler only answers when a message was actually delivered.
    (let ((w (ws-connect "ws://127.0.0.1:18088/sink")))
      (tcp-write! (ws-conn w) (zero-fragment-attack) #f)
      (check "ws-zero-fragment-limit"
        (let ((m (ws-recv w)))
          (and (vector? m) (eq? (vector-ref m 0) 'close))))
      ;; the session outlives the check when the cap is missing; leaving it
      ;; open takes the rest of the suite down with it, so a failure here
      ;; stays one failure instead of aborting every check after it
      (ws-close! w))

    ;; The HTTP upgrade path validates every RFC 6455 handshake invariant
    ;; before transferring ownership to a WebSocket session.
    (check "ws-handshake-method"
      (equal? (status-of (http-req
        "POST /open HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"))
              "400"))
    (check "ws-handshake-http-version"
      (equal? (status-of (http-req
        "GET /open HTTP/1.0\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"))
              "400"))
    (check "ws-handshake-connection-token"
      (equal? (status-of (http-req
        "GET /open HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"))
              "400"))
    (check "ws-handshake-version-13"
      (equal? (status-of (http-req
        "GET /open HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 12\r\n\r\n"))
              "400"))
    (check "ws-handshake-key-length"
      (equal? (status-of (http-req
        "GET /open HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: YQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"))
              "400"))

    ;; token guard: header credential
    (check "ws-token-header"
      (equal? (recv-text-and-close
                (ws-connect "ws://127.0.0.1:18088/chat"
                  `(("Authorization" . ,(string-append "Bearer " good-tok)))))
              "42"))
    ;; token guard: query-parameter fallback (browser clients)
    (check "ws-token-query"
      (equal? (recv-text-and-close
                (ws-connect (string-append "ws://127.0.0.1:18088/chat?token="
                                           good-tok)))
              "42"))
    ;; refusals answer plain HTTP 401 before any handshake
    (check "ws-token-missing-401"
      (equal? (status-of (upgrade-req "/chat")) "401"))
    (check "ws-token-bad-401"
      (equal? (status-of (upgrade-req "/chat"
                           "Authorization: Bearer bad.bad.bad"))
              "401"))
    (check "ws-token-expired-401"
      (equal? (status-of (upgrade-req (string-append "/chat?token="
                           (jwt-sign `(("exp" . ,(- (time-second (current-time)) 10)))
                                     key))))
              "401"))
    ;; unknown ws route stays 404 (reject is 401, not-found is not)
    (check "ws-unknown-404"
      (equal? (status-of (upgrade-req "/nope")) "404"))

    ;; An established anonymous id is invalidated and replaced at the
    ;; authentication boundary; its data is carried to the new id.
    (let* ((seed (http-req
                   "GET /seed HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
           (old (extract-sid seed))
           (login (and old (http-req
                     (string-append
                       "GET /login HTTP/1.1\r\nHost: x\r\nCookie: sid=" old
                       "\r\nConnection: close\r\n\r\n"))))
           (fresh (and login (extract-sid login))))
      (check "session-login-rotates-id"
        (and old fresh (not (string=? old fresh))))
      (sleep-ms 100)
      (check "session-login-drops-old-id"
        (and old (not (session-peek store old))))
      (check "session-login-keeps-state"
        (let ((data (and fresh (session-peek store fresh))))
          (and data (equal? (cdr (assq 'preauth data)) "kept")
               (equal? (cdr (assq 'user data)) "ada")))))

    ;; Rotating after the response is out must fail loudly rather than
    ;; half-apply: the cookie cannot be delivered, so the id must not be
    ;; dropped either. The handler raise surfaces as a 500.
    (let* ((seed (http-req
                   "GET /seed HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
           (sid (extract-sid seed))
           (late (and sid (http-req
                    (string-append
                      "GET /late-rotate HTTP/1.1\r\nHost: x\r\nCookie: sid=" sid
                      "\r\nConnection: close\r\n\r\n")))))
      (sleep-ms 150)
      ;; the client legitimately still sees its 200: the response was
      ;; complete before the mistake was made
      (check "late-rotate-answers-normally" (equal? "200" (status-of late)))
      (check "late-rotate-raises"
        (equal? "raised"
                (let ((r (http-req
                           "GET /late-outcome HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
                  (let ((b (find-substr r "\r\n\r\n")))
                    (and b (substring r (+ b 4) (string-length r)))))))
      (check "late-rotate-keeps-the-live-id"
        (let ((data (and sid (session-peek store sid))))
          (and data (equal? (cdr (assq 'preauth data)) "kept")))))

    ;; one identity per request, however many layers ask for it
    (let* ((seed (http-req
                   "GET /seed HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
           (sid (extract-sid seed))
           (resp (and sid (http-req
                    (string-append
                      "GET /rotate-twice HTTP/1.1\r\nHost: x\r\nCookie: sid=" sid
                      "\r\nConnection: close\r\n\r\n")))))
      (check "rotate-twice-is-idempotent" (eq? #t twice-same?))
      (check "rotate-twice-issues-one-cookie"
        (= 1 (let loop ((i 0) (n 0))
               (let ((at (find-substr (substring resp i (string-length resp))
                                      "Set-Cookie")))
                 (if at (loop (+ i at 10) (+ n 1)) n))))))

    ;; a session that outlives its handler cannot rotate against the
    ;; finished response
    (let* ((seed (http-req
                   "GET /seed HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
           (sid (extract-sid seed)))
      (when sid
        (http-req (string-append
                    "GET /escape-rotate HTTP/1.1\r\nHost: x\r\nCookie: sid=" sid
                    "\r\nConnection: close\r\n\r\n")))
      (sleep-ms 700)
      (check "escaped-session-rotate-raises"
        (equal? "raised"
                (let ((r (http-req
                           "GET /escape-outcome HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
                  (let ((b (find-substr r "\r\n\r\n")))
                    (and b (substring r (+ b 4) (string-length r)))))))
      (check "escaped-session-rotate-keeps-the-live-id"
        (let ((data (and sid (session-peek store sid))))
          (and data (equal? (cdr (assq 'preauth data)) "kept")))))

    ;; Cross-site WebSocket hijacking: a page on another origin can open
    ;; this socket and the browser attaches the session cookie regardless.
    ;; With an allow-list the foreign origin must be refused BEFORE the
    ;; handshake, and the configured one must still get through.
    (let* ((login (http-req "GET /login HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
           (sid (extract-sid login))
           (upgrade
             (lambda (path origin)
               (status-of
                 (http-req
                   (string-append
                     "GET " path " HTTP/1.1\r\nHost: x\r\n"
                     "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     (if origin (string-append "Origin: " origin "\r\n") "")
                     "Cookie: sid=" sid "\r\n\r\n"))))))
      (unless sid (fail "origin-login" login))
      (check "ws-origin-allowed"
        (equal? "101" (upgrade "/feed-origin" "https://app.example")))
      (check "ws-origin-foreign-refused"
        (equal? "401" (upgrade "/feed-origin" "http://evil.example")))
      ;; Omitting the option is fail-closed for browsers, rather than
      ;; silently preserving the cross-site session-hijacking exposure.
      (check "ws-origin-default-refused"
        (equal? "401" (upgrade "/feed" "https://app.example")))
      ;; Prove the Origin decision happens before the synchronous lookup:
      ;; this route's store cannot answer a session-peek call.
      (check "ws-origin-foreign-skips-store"
        (equal? "401"
          (upgrade "/feed-origin-first" "http://evil.example")))
      ;; no Origin at all is a non-browser client, which cannot be carrying
      ;; somebody else's cookie -- refusing it would lock out every ordinary
      ;; WebSocket library without closing anything
      (check "ws-origin-absent-allowed"
        (equal? "101" (upgrade "/feed-origin" #f))))

    ;; session guard: log in over HTTP, ride the cookie into the upgrade
    (let* ((login (http-req "GET /login HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
           (sid (extract-sid login)))
      (unless sid (fail "login" login))
      (check "ws-session-cookie"
        (equal? (recv-text-and-close
                  (ws-connect "ws://127.0.0.1:18088/feed"
                    `(("Cookie" . ,(string-append "sid=" sid)))))
                "ada"))
      (check "ws-session-bogus-401"
        (equal? (status-of (upgrade-req "/feed" "Cookie: sid=deadbeef"))
                "401"))
      (check "ws-session-missing-401"
        (equal? (status-of (upgrade-req "/feed")) "401")))

    ;; guarded sexpr RPC: refusal is 401 + sexpr data, not JSON
    (check "rpc-no-token"
      (equal? (rpc-post '(add 1 2)) '("401" . (error unauthorized))))
    (check "rpc-bad-token"
      (equal? (rpc-post '(add 1 2) "Authorization: Bearer bad.bad.bad")
              '("401" . (error unauthorized))))
    (let ((auth-h (string-append "Authorization: Bearer " good-tok)))
      ;; one-argument handler unchanged under a guard
      (check "rpc-one-arg-handler"
        (equal? (rpc-post '(add 1 2 39) auth-h) '("200" . (ok 42))))
      ;; two-argument handler reads the claims off the request
      (check "rpc-claims-in-handler"
        (equal? (rpc-post '(whoami) auth-h) '("200" . (ok "42")))))

    (if (zero? failures)
        (begin (display "auth: all tests passed") (newline) (exit 0))
        (begin (display failures) (display " failures") (newline) (exit 1)))))
