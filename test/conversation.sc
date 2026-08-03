#!chezscheme
;;; (igropyr conversation) protocol tests: a two-step transfer flow.
;;;
;;;   - full dialogue: start -> confirm -> committed
;;;   - cancel path: start -> cancel -> hold rolled back
;;;   - gone: resume after the conversation ended / with a bad id -> 410
;;;   - expiry: abandoning the dialogue rolls the hold back (guard ran)
;;;   - crash inside a step -> resume answers gone, hold rolled back

(import (chezscheme) (igropyr util) (igropyr http) (igropyr express)
        (igropyr json) (igropyr conversation) (igropyr libuv))

(define port 18084)
(define empty-bv (make-bytevector 0))

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

(define (fail label detail)
  (display "FAIL: ") (display label) (display " ") (write detail) (newline)
  (exit 1))

;; one request on a fresh connection; returns the full response text
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

(define (post path body)
  (http-req (string-append
              "POST " path " HTTP/1.1\r\nHost: x\r\nContent-Length: "
              (number->string (string-length body))
              "\r\nConnection: close\r\n\r\n" body)))

(define (get path)
  (http-req (string-append
              "GET " path " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))

(define (body-of response)
  (let ((n (string-length response)))
    (let scan ((i 0))
      (cond ((> (+ i 3) (- n 1)) response)
            ((and (char=? (string-ref response i) #\return)
                  (char=? (string-ref response (+ i 1)) #\linefeed)
                  (char=? (string-ref response (+ i 2)) #\return)
                  (char=? (string-ref response (+ i 3)) #\linefeed))
             (substring response (+ i 4) n))
            (else (scan (+ i 1)))))))

(define (json-of response) (string->json (body-of response)))

(define (expect label got want)
  (if (equal? got want)
      (begin (display label) (display " ok\n"))
      (fail label (list 'got got 'want want))))

;; ---- the app under test -------------------------------------------------------

(define account (box 1000))

(define (transfer-flow amt crash-on-confirm?)
  (lambda (req suspend!)
    (set-box! account (- (unbox account) amt))       ; provisional hold
    (guard (e (#t (set-box! account (+ (unbox account) amt))
                  (raise e)))                        ; roll the hold back
      (let ((req2 (suspend! (list (cons 'step "confirm")
                                  (cons 'amount amt)))))
        (when crash-on-confirm? (raise 'step-crashed))
        (if (equal? (utf8->string (req-body req2)) "confirm")
            (list (cons 'done #t) (cons 'balance (unbox account)))
            (begin (set-box! account (+ (unbox account) amt))
                   (list (cons 'done #f))))))))

(define app (create-app))

(app-post app "/t"
  (lambda (req res)
    (let* ((q (req-query req))
           (amt (or (string->number (utf8->string (req-body req))) 0))
           (ttl (let ((p (assoc "ttl" q))) (if p (string->number (cdr p)) 300000)))
           (crash? (assoc "crash" q)))
      (let-values (((id reply)
                    (conversation-start! (transfer-flow amt (and crash? #t))
                                         req ttl)))
        (send-json! res (cons (cons 'conv id) reply))))))

(app-post app "/t/:id"
  (lambda (req res)
    (let ((r (conversation-resume! (req-param req "id") req)))
      (if (conversation-gone? r)
          (begin (set-status! res 410)
                 (send-json! res (list (cons 'fault "gone"))))
          (send-json! res r)))))

(app-get app "/balance"
  (lambda (req res)
    (send-json! res (list (cons 'balance (unbox account))))))

;; ---- the dialogue -------------------------------------------------------------

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 4)))
    (sleep-ms 100)

    ;; full dialogue: hold, confirm, committed
    (let* ((r1 (json-of (post "/t" "100")))
           (id (json-ref r1 "conv")))
      (expect "start holds" (json-ref (json-of (get "/balance")) "balance") 900)
      (let ((r2 (json-of (post (string-append "/t/" id) "confirm"))))
        (expect "confirm commits" (json-ref r2 "done") #t))
      (expect "balance after commit"
        (json-ref (json-of (get "/balance")) "balance") 900)
      ;; the conversation is over: a further resume is gone
      (let ((r3 (post (string-append "/t/" id) "confirm")))
        (unless (string-contains? r3 "HTTP/1.1 410 ") (fail "resume after end" r3))
        (display "resume after end ok\n")))

    ;; cancel path rolls the hold back
    (let* ((r1 (json-of (post "/t" "100")))
           (id (json-ref r1 "conv")))
      (post (string-append "/t/" id) "cancel")
      (expect "cancel rolls back"
        (json-ref (json-of (get "/balance")) "balance") 900))

    ;; unknown id
    (let ((r (post "/t/deadbeef" "confirm")))
      (unless (string-contains? r "HTTP/1.1 410 ") (fail "unknown id" r))
      (display "unknown id ok\n"))

    ;; expiry: abandon the dialogue; the guard restores the hold
    (let* ((r1 (json-of (post "/t?ttl=400" "100")))
           (id (json-ref r1 "conv")))
      (expect "expiry holds first" (json-ref (json-of (get "/balance")) "balance") 800)
      (sleep-ms 900)
      (expect "expiry rolls back"
        (json-ref (json-of (get "/balance")) "balance") 900)
      (let ((r (post (string-append "/t/" id) "confirm")))
        (unless (string-contains? r "HTTP/1.1 410 ") (fail "resume after expiry" r))
        (display "resume after expiry ok\n")))

    ;; crash inside a step: resume answers gone, hold rolled back
    (let* ((r1 (json-of (post "/t?crash=1" "100")))
           (id (json-ref r1 "conv")))
      (let ((r (post (string-append "/t/" id) "confirm")))
        (unless (string-contains? r "HTTP/1.1 410 ") (fail "crash in step" r))
        (display "crash in step ok\n"))
      (expect "crash rolls back"
        (json-ref (json-of (get "/balance")) "balance") 900))

    ;; Two concurrent resumes must not become two consecutive steps. A double
;; click, a client retry or two front ends all produce this: both requests
;; land in the mailbox, the first wakes the current suspend!, and the second
;; used to be picked up by the NEXT one -- advancing the flow with a request
;; whose caller never saw the reply in between. That is a confirmation step
;; skipped, or one stage's payload applied to the next.
(let-values (((id first)
              (conversation-start!
                (lambda (req suspend!)
                  ;; Three stages, so the conversation is still ALIVE and
                  ;; parked when the second resume arrives -- otherwise it
                  ;; answers 'gone (the flow finished) and the test proves
                  ;; nothing about concurrency.
                  (let ((a (suspend! (vector 'after-first req))))
                    (sleep-ms 200)          ; both resumes land during this
                    (let ((b (suspend! (vector 'after-second a))))
                      (vector 'final a b))))
                'go)))
  (let ((me self))
    (spawn (lambda () (send me (vector 'r1 (conversation-resume! id 'A)))))
    (sleep-ms 20)
    (spawn (lambda () (send me (vector 'r2 (conversation-resume! id 'B)))))
    (let loop ((got '()) (n 0))
      (if (= n 2)
          (let ((busy (filter (lambda (x) (eq? (cdr x) 'busy)) got)))
            (unless (= 1 (length busy))
              (fail "concurrent-resume: expected exactly one busy" got))
            (display "concurrent resume -> one busy ok\n"))
          (receive (after 4000 (fail "concurrent-resume timeout" got))
            (`#(r1 ,v) (loop (cons (cons 'r1 v) got) (+ n 1)))
            (`#(r2 ,v) (loop (cons (cons 'r2 v) got) (+ n 1))))))))

;; The TTL must bound a RUNNING step, not only time parked in suspend!.
;; A step that runs long -- slow I/O, a wait that never returns, a CPU loop
;; -- leaves that receive entirely, and nothing else was counting: the
;; conversation could hold its transaction or reservation indefinitely. The
;; pool's stuck-killer does not cover it; that reaps the worker waiting for
;; the reply, while the conversation is its own process.
(let-values (((id first)
              (conversation-start!
                (lambda (req suspend!)
                  (let ((a (suspend! (vector 'parked req))))
                    (sleep-ms 3000)          ; far past the TTL below
                    (vector 'should-not-get-here a)))
                'go
                300)))                       ; TTL 300 ms
  (let ((me self))
    (spawn (lambda () (send me (vector 'slow (conversation-resume! id 'X)))))
    ;; the step overruns, so the watchdog must end the conversation rather
    ;; than let it run to completion
    (receive (after 6000 (fail "runaway-step" 'no-answer))
      (`#(slow ,v)
        (when (and (vector? v) (eq? (vector-ref v 0) 'should-not-get-here))
          (fail "runaway step ran to completion despite the TTL" v))
        (display "runaway step bounded by TTL ok\n")))))

;; ...and the allowance must be the TTL, not whatever is left of a sampling
;; cycle. The watchdog used to sample on a fixed period and decide from "has
;; the step counter moved since my last look", which hands a step anything
;; between almost nothing and almost twice the TTL depending on where it
;; starts in that cycle.
;;
;; It takes TWO steps to construct. On the first sample the opening suspend!
;; has just moved the counter, so that sample always sees progress; and a
;; conversation parked longer than its TTL is reaped by suspend! itself, so
;; the resume cannot simply be delayed. The second step parks before a
;; sample (moving the counter again) and the third resumes just after one --
;; and is then killed at the next, having run a fraction of its allowance.
(let-values (((id2 first2)
              (conversation-start!
                (lambda (req suspend!)
                  (let ((a (suspend! (vector 'parked req))))
                    (sleep-ms 100)
                    (let ((b (suspend! (vector 'parked2 a))))
                      (sleep-ms 600)          ; well inside the 1000 ms TTL
                      (vector 'finished b))))
                'go
                1000)))
  (let ((me self))
    (sleep-ms 800)                            ; still parked, still alive
    (conversation-resume! id2 'X)             ; step 2 runs 100 ms, parks again
    (sleep-ms 900)                            ; just past a sampling point
    (spawn (lambda () (send me (vector 'phase (conversation-resume! id2 'Y)))))
    (receive (after 8000 (fail "phase-step" 'no-answer))
      (`#(phase ,v)
        (if (and (vector? v) (eq? (vector-ref v 0) 'finished))
            (display "a step gets its whole TTL whatever the sampling phase ok\n")
            (fail "a step well inside the TTL was cut short by sampling phase" v))))))

(display "ALL CONVERSATION TESTS PASSED\n")
    (exit 0)))
