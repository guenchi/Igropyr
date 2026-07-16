#!chezscheme
;;; (igropyr auth) tests: WebSocket upgrade guards end to end -- the
;;; token form (jwt-verifier via Authorization header and ?token=
;;; query) and the session form (sid cookie against a live store).
;;; Refusals happen BEFORE the 101 handshake (401 over plain HTTP).
;;; The HTTP-side auth middleware is covered end to end in jwt.sc.

(import (chezscheme) (igropyr http) (igropyr express) (igropyr session)
        (igropyr auth) (igropyr jwt) (igropyr ws-client)
        (igropyr json) (igropyr libuv))

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

;; HTTP login: writes the user into the session, cookie comes back
(app-get app "/login"
  (lambda (req res)
    (session-set! (req-session req) 'user "ada")
    (send-text! res "ok")))

;; unguarded ws route (regression: guards are opt-in)
(app-ws app "/open"
  (lambda (ws req)
    (ws-send-text! ws "open")
    (ws-recv ws)))

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

(define good-tok (jwt-sign '(("sub" . "42")) key '((expires-in . 300))))

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (sleep-ms 100)

    ;; unguarded route still upgrades with no credential
    (check "ws-open"
      (equal? (recv-text-and-close
                (ws-connect "ws://127.0.0.1:18088/open"))
              "open"))

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

    (if (zero? failures)
        (begin (display "auth: all tests passed") (newline) (exit 0))
        (begin (display failures) (display " failures") (newline) (exit 1)))))
