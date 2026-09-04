#!chezscheme
;;; Logging out must retire the identifier, not just empty it.
;;;
;;; THE JUDGE IS AN ATTACKER'S COPY. A sid taken before logout is
;;; presented after the next login: if clearing a session left the id
;;; alive, that copy names whatever the next login writes, and the
;;; stolen cookie becomes an authenticated session without the attacker
;;; doing anything else. So the case does not ask "was the data
;;; cleared?" -- data clearing was never in doubt, and asserting it
;;; passes on the broken version too. It asks whether the old id still
;;; buys anything.
;;;
;;; The re-login here deliberately does NOT rotate. Every correct
;;; application rotates at its authentication boundary, and this file
;;; would go green on the old behaviour if it did -- the framework's
;;; guarantee is what is under test, not the application's discipline
;;; on top of it. (The suite that pins the rotation-at-login path is
;;; session-rotation-race.sc; this one deliberately removes it.)
;;;
;;; A cookie-less request is a separate case and not an edge to skip:
;;; its id has never reached anyone, so there is nothing to retire, and
;;; retiring it anyway would put two Set-Cookie fields in one response.

(import (chezscheme) (igropyr actor) (igropyr express) (igropyr session)
        (igropyr http) (igropyr libuv) (igropyr tcp))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))

(define port 18102)
(define empty-bv (make-bytevector 0))
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
                (`#(tcp-error ,e)
                  (send caller (vector 'r-ok ref (utf8->string buf)))))))
          (`#(tcp-connect-failed ,e)
            (send caller (vector 'r-err ref e))))))
    (receive (after 10000 (fail "http-req" 'timeout) "")
      (`#(r-ok ,@ref ,s) s)
      (`#(r-err ,@ref ,e) (fail "http-req" e) ""))))

(define (get path . cookie)
  (http-req (string-append
              "GET " path " HTTP/1.1\r\nHost: x\r\n"
              (if (and (pair? cookie) (car cookie))
                  (string-append "Cookie: sid=" (car cookie) "\r\n")
                  "")
              "Connection: close\r\n\r\n")))

;; ---- probes -------------------------------------------------------------
;; Needle lengths are COMPUTED, never written as a number: the first
;; version of sid-of searched 16 characters for a 17-character needle,
;; so it matched nothing and every sid came back #f -- and the case that
;; matters ("the stolen sid buys nothing") went GREEN on that, because a
;; request carrying no cookie is of course anonymous. A probe that finds
;; nothing and a subject that has nothing are the same answer.
(define (find-at s needle from)
  (let ((n (string-length s)) (m (string-length needle)))
    (let loop ((k from))
      (cond ((> (+ k m) n) #f)
            ((string=? (substring s k (+ k m)) needle) k)
            (else (loop (+ k 1)))))))

(define (lower s) (list->string (map char-downcase (string->list s))))

;; the sid a response hands out, or #f
(define (sid-of resp)
  (let* ((needle "\nset-cookie: sid=")
         (i (find-at (lower resp) needle 0)))
    (and i
         (let* ((start (+ i (string-length needle)))
                (end (let loop ((k start))
                       (if (or (>= k (string-length resp))
                               (char=? (string-ref resp k) #\;)
                               (char=? (string-ref resp k) #\return)
                               (char=? (string-ref resp k) #\newline))
                           k (loop (+ k 1))))))
           (substring resp start end)))))

(define (body-of resp)
  (let loop ((k 0))
    (cond ((> (+ k 4) (string-length resp)) "")
          ((string=? (substring resp k (+ k 4)) "\r\n\r\n")
           (substring resp (+ k 4) (string-length resp)))
          (else (loop (+ k 1))))))

(define (count-set-cookie resp)
  (let ((l (lower resp)))
    (let loop ((k 0) (n 0))
      (let ((i (find-at l "\nset-cookie:" k)))
        (if i (loop (+ i 1) (+ n 1)) n)))))

(define store (make-session-store))
(define app (create-app))
(app-use app (session-middleware store '((secure . #f))))

;; login WITHOUT rotating: the framework's own guarantee is what is
;; being measured, not the application's discipline on top of it
(app-get app "/login"
  (lambda (req res)
    (session-set! (req-session req) 'user "ada")
    (send-text! res "in")))

(app-get app "/logout"
  (lambda (req res)
    (session-clear! (req-session req))
    (send-text! res "out")))

(app-get app "/who"
  (lambda (req res)
    (let ((u (session-get (req-session req) 'user)))
      (send-text! res (if u u "anon")))))

;; writes AFTER the clear, in the same request
(app-get app "/logout-then-write"
  (lambda (req res)
    (session-clear! (req-session req))
    (session-set! (req-session req) 'flash "bye")
    (send-text! res "out")))

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 1)))
    (sleep-ms 200)

    ;; ---- the attacker's copy ------------------------------------------
    (let* ((r1 (get "/login"))
           (stolen (sid-of r1)))
      (check "login issues a sid" (and stolen (> (string-length stolen) 8))
             stolen)
      (check "the session is live under it"
             (equal? "ada" (body-of (get "/who" stolen))))
      (let* ((r2 (get "/logout" stolen))
             (after-logout (sid-of r2)))
        ;; the guarantee: logging out retires the identifier
        (check "logout answers with a DIFFERENT sid"
               (and after-logout (not (equal? after-logout stolen)))
               stolen after-logout)
        ;; RE-LOGIN AS A BROWSER WOULD: it keeps the cookie it has unless
        ;; it is given a new one, so the id presented here is the new one
        ;; if logout issued it and the OLD one if logout issued nothing.
        ;; Passing `after-logout` directly instead was this file's third
        ;; probe bug and the worst of them: against the un-rotating
        ;; version that value is #f, the re-login then carried no cookie
        ;; at all, a fresh session was made, and the headline case below
        ;; went green while testing nothing.
        (let* ((browser-sid (or after-logout stolen))
               (r3 (get "/login" browser-sid))
               (current (or (sid-of r3) browser-sid)))
          (check "the re-login session is live"
                 (equal? "ada" (body-of (get "/who" current))))
          ;; THE CASE: the copy taken before logout must buy nothing
          (check "the stolen sid is NOT an authenticated session"
                 (equal? "anon" (body-of (get "/who" stolen)))
                 (body-of (get "/who" stolen)))
          ;; ...and it did not silently become the live one either
          (check "the stolen sid is not the live identity"
                 (not (equal? stolen current))))))

    ;; ---- a cookie-less request: nothing to retire ----------------------
    ;; its id has never reached anyone, so clearing must not rotate --
    ;; two Set-Cookie fields in one response is the failure to catch here
    (let ((r (get "/logout")))
      (check "clearing a brand-new session sends exactly one cookie"
             (= 1 (count-set-cookie r)) (count-set-cookie r))
      (check "...and the response is normal"
             (equal? "out" (body-of r))))

    ;; ---- writes after a clear land under the NEW identity --------------
    (let* ((r1 (get "/login"))
           (sid1 (sid-of r1))
           (r2 (get "/logout-then-write" sid1))
           (sid2 (sid-of r2)))
      (check "clear-then-write rotates" (and sid2 (not (equal? sid1 sid2))))
      (check "the write landed under the new sid"
             (equal? "anon" (body-of (get "/who" sid2))))
      (check "and the old sid carries nothing"
             (equal? "anon" (body-of (get "/who" sid1)))))

    (if (= failures 0)
        (begin (display "session-fixation: all tests passed\n") (exit 0))
        (begin (display (number->string failures))
               (display " failures\n") (exit 1)))))
