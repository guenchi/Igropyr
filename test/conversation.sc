#!chezscheme
;;; (igropyr conversation) protocol tests: a two-step transfer flow.
;;;
;;;   - full dialogue: start -> confirm -> committed
;;;   - cancel path: start -> cancel -> hold rolled back
;;;   - gone: resume after the conversation ended / with a bad id -> 410
;;;   - expiry: abandoning the dialogue rolls the hold back (guard ran)
;;;   - crash inside a step -> resume answers gone, hold rolled back
;;;   - commit!: a raise after a commit the library witnessed -> 'unknown,
;;;     never 'gone; a commit! whose thunk raised is still 'gone

(import (chezscheme) (igropyr util) (igropyr http) (igropyr express)
        (igropyr json) (igropyr conversation) (igropyr libuv)
        ;; process-count: the hook cases below assert that a wedged hook
        ;; leaves no process behind, which is the observation the counters
        ;; cannot make
        (only (igropyr actor) process-count))

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

(define (stat name s) (cond ((assq name s) => cdr) (else #f)))

(define (expect label got want)
  (if (equal? got want)
      (begin (display label) (display " ok\n"))
      (fail label (list 'got got 'want want))))

;; ---- the app under test -------------------------------------------------------

(define account (box 1000))

(define (transfer-flow amt crash-on-confirm?)
  (lambda (req suspend! commit!)
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
      (let-values (((id token reply)
                    (conversation-start! (transfer-flow amt (and crash? #t))
                                         req ttl
                                         ;; over HTTP two retries are two
                                         ;; different request records, so
                                         ;; what identifies the call is its
                                         ;; body -- and the body is all that
                                         ;; gets retained
                                         req-body)))
        (send-json! res (cons (cons 'conv id)
                              (cons (cons 'token token) reply)))))))

(app-post app "/t/:id"
  (lambda (req res)
    (let ((token (cond ((assoc "token" (req-query req)) => cdr) (else ""))))
      ;; the STATUS decides, never the reply -- a flow may legitimately
      ;; return the symbol 'gone as an ordinary answer
      (let-values (((r status) (conversation-resume! (req-param req "id") token req)))
        (cond
          ((conversation-gone? status)
           (set-status! res 410)
           (send-json! res (list (cons 'fault "gone"))))
          ;; NOT 410. 410 says the transaction rolled back, and this
          ;; answer cannot support that: the conversation is not here and
          ;; this node no longer has a record either way. The one thing a
          ;; client must not do with it is resubmit.
          ((conversation-unknown? status)
           (set-status! res 409)
           (send-json! res (list (cons 'fault "unknown"))))
          ((conversation-stale? status)
           (set-status! res 409)
           (send-json! res (list (cons 'fault "stale"))))
          ((conversation-done? status) (send-json! res r))
          (else (send-json! res (cons (cons 'token status) r))))))))

(app-get app "/balance"
  (lambda (req res)
    (send-json! res (list (cons 'balance (unbox account))))))

;; the URL a client builds from what the previous reply handed it
(define (step-url id token)
  (string-append "/t/" id "?token=" token))

;; ---- the dialogue -------------------------------------------------------------

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 4)))
    (sleep-ms 100)

    ;; full dialogue: hold, confirm, committed
    (let* ((r1 (json-of (post "/t" "100")))
           (id (json-ref r1 "conv"))
           (tok (json-ref r1 "token")))
      (expect "start holds" (json-ref (json-of (get "/balance")) "balance") 900)
      (let ((r2 (json-of (post (step-url id tok) "confirm"))))
        (expect "confirm commits" (json-ref r2 "done") #t))
      (expect "balance after commit"
        (json-ref (json-of (get "/balance")) "balance") 900)
      ;; The conversation is over, and repeating the request that ended it
      ;; REPLAYS its answer rather than reporting 'gone.
      ;;
      ;; This is the case that matters most with money in it. Exiting at
      ;; once meant a client whose final reply was lost retried, met a
      ;; process that no longer existed, and was told 'gone -- which this
      ;; library documents as "the transaction rolled back". For a flow
      ;; that had just committed that is false, and a client acting on it
      ;; performs the whole transfer again.
      (let ((r3 (json-of (post (step-url id tok) "confirm"))))
        (expect "a repeated final request replays its answer"
          (json-ref r3 "done") #t))
      ;; ...and it replayed rather than re-running: the balance moved once
      (expect "the replay moved no money"
        (json-ref (json-of (get "/balance")) "balance") 900)
      ;; a token that never belonged to this conversation is still refused
      (let ((r4 (post (step-url id (string-append tok "aa")) "confirm")))
        (unless (string-contains? r4 "HTTP/1.1 409 ")
          (fail "an invented token after the end was accepted" r4))
        (display "replay after the end, invented token still refused ok\n")))

    ;; cancel path rolls the hold back
    (let* ((r1 (json-of (post "/t" "100")))
           (id (json-ref r1 "conv"))
           (tok (json-ref r1 "token")))
      (post (step-url id tok) "cancel")
      (expect "cancel rolls back"
        (json-ref (json-of (get "/balance")) "balance") 900))

    ;; An id this node never issued is NOT the same as one it knows rolled
    ;; back. It cannot tell a fabricated id from a real one whose record it
    ;; has since forgotten, so it says so: 409 unknown, not 410 gone.
    ;; Claiming a rollback here is how a committed transfer gets performed
    ;; twice by a client that trusted the claim.
    (let ((r (post "/t/deadbeef?token=1" "confirm")))
      (unless (string-contains? r "HTTP/1.1 409 ") (fail "unknown id" r))
      (unless (string-contains? r "unknown") (fail "unknown id fault" r))
      (display "an id this node cannot speak for -> unknown, not gone ok\n"))

    ;; expiry: abandon the dialogue; the guard restores the hold
    (let* ((r1 (json-of (post "/t?ttl=400" "100")))
           (id (json-ref r1 "conv")))
      (expect "expiry holds first" (json-ref (json-of (get "/balance")) "balance") 800)
      (sleep-ms 900)
      (expect "expiry rolls back"
        (json-ref (json-of (get "/balance")) "balance") 900)
      (let ((r (post (step-url id (json-ref r1 "token")) "confirm")))
        (unless (string-contains? r "HTTP/1.1 410 ") (fail "resume after expiry" r))
        (display "resume after expiry ok\n")))

    ;; crash inside a step: resume answers gone, hold rolled back
    (let* ((r1 (json-of (post "/t?crash=1" "100")))
           (id (json-ref r1 "conv")))
      (let ((r (post (step-url id (json-ref r1 "token")) "confirm")))
        (unless (string-contains? r "HTTP/1.1 410 ") (fail "crash in step" r))
        (display "crash in step ok\n"))
      (expect "crash rolls back"
        (json-ref (json-of (get "/balance")) "balance") 900))

    ;; A REPEATED confirm -- the same request sent twice, which is what a
    ;; double click or a client retry is -- is ANSWERED, with the answer the
    ;; first one produced, and must not move the money a second time.
    ;;
    ;; Both halves matter. Refusing would also protect the money, but it
    ;; leaves a client whose reply was lost unable to learn the outcome;
    ;; replaying gives it the reply it lost. What must never happen is the
    ;; step running twice.
    ;;
    ;; Placed last, because a committed transfer changes the running balance
    ;; every later assertion is written against.
    (let* ((r1 (json-of (post "/t" "100")))
           (id (json-ref r1 "conv"))
           (tok (json-ref r1 "token")))
      (let ((first (json-of (post (step-url id tok) "confirm"))))
        (expect "the first confirm commits" (json-ref first "done") #t))
      (let ((again (json-of (post (step-url id tok) "confirm"))))
        (expect "a repeated confirm replays the same answer"
          (json-ref again "done") #t))
      ;; 900 was the balance before this transfer; one commit of 100 leaves
      ;; 800, and a second would have left 700
      (expect "and the balance moved once"
        (json-ref (json-of (get "/balance")) "balance") 800))

    ;; a resume with no token at all, or a made-up one, is refused
    (let* ((r1 (json-of (post "/t" "100")))
           (id (json-ref r1 "conv"))
           (tok (json-ref r1 "token")))
      (let ((no-token (post (string-append "/t/" id) "confirm")))
        (unless (string-contains? no-token "HTTP/1.1 409 ")
          (fail "a resume with no token was accepted" no-token)))
      (let ((wrong (post (step-url id (string-append tok "ff")) "confirm")))
        (unless (string-contains? wrong "HTTP/1.1 409 ")
          (fail "a resume with a made-up token was accepted" wrong)))
      (display "a missing or invented token is refused ok\n")
      ;; the conversation is untouched and still finishes properly
      (let ((r2 (json-of (post (step-url id tok) "cancel"))))
        (expect "the real token still works" (json-ref r2 "done") #f))
      (expect "and the cancel restored the hold"
        (json-ref (json-of (get "/balance")) "balance") 800))

    ;; Two concurrent resumes must not become two consecutive steps. A double
;; click, a client retry or two front ends all produce this: both requests
;; land in the mailbox, the first wakes the current suspend!, and the second
;; used to be picked up by the NEXT one -- advancing the flow with a request
;; whose caller never saw the reply in between. That is a confirmation step
;; skipped, or one stage's payload applied to the next.
(let-values (((id token first)
              (conversation-start!
                (lambda (req suspend! commit!)
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
    ;; Two callers holding the SAME token but asking DIFFERENT things. One
    ;; wins; the other must be told 'stale, not handed the winner's answer.
    ;;
    ;; Replaying by token alone did exactly that: the caller who asked 'B
    ;; received the result of 'A. In the transfer flow above, that is a
    ;; caller who asked to cancel being told the transfer was confirmed.
    (spawn (lambda ()
             (let-values (((r st) (conversation-resume! id token 'A)))
               (send me (vector 'r1 (cons r st))))))
    (sleep-ms 20)
    (spawn (lambda ()
             (let-values (((r st) (conversation-resume! id token 'B)))
               (send me (vector 'r2 (cons r st))))))
    (let loop ((got '()) (n 0))
      (if (= n 2)
          (let* ((vs (map cdr got))
                 (stales (filter (lambda (x) (eq? (cdr x) 'stale)) vs))
                 (answered (filter (lambda (x) (not (eq? (cdr x) 'stale))) vs)))
            (unless (= 1 (length stales))
              (fail "concurrent-resume: expected exactly one stale" got))
            (unless (= 1 (length answered))
              (fail "concurrent-resume: expected exactly one answer" got))
            ;; and the one that was answered got ITS OWN question's result
            (unless (equal? (car (car answered)) (vector 'after-second 'A))
              (fail "concurrent-resume: wrong answer delivered" got))
            (display "two different questions, one token -> one wins, one stale ok\n"))
          (receive (after 4000 (fail "concurrent-resume timeout" got))
            (`#(r1 ,v) (loop (cons (cons 'r1 v) got) (+ n 1)))
            (`#(r2 ,v) (loop (cons (cons 'r2 v) got) (+ n 1))))))))

;; ...and the SAME question repeated is replayed rather than refused --
;; that is the lost-response case, and it is the whole reason replay
;; exists.
(let-values (((rid rtok rfirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'after-first req))))
                    (sleep-ms 150)
                    (let ((b (suspend! (vector 'after-second a))))
                      (vector 'final a b))))
                'go)))
  (let ((me self))
    (spawn (lambda ()
             (let-values (((r st) (conversation-resume! rid rtok 'SAME)))
               (send me (vector 'q1 (cons r st))))))
    (sleep-ms 20)
    (spawn (lambda ()
             (let-values (((r st) (conversation-resume! rid rtok 'SAME)))
               (send me (vector 'q2 (cons r st))))))
    (let loop ((got '()) (n 0))
      (if (= n 2)
          (let ((vs (map cdr got)))
            (when (memq 'stale (map cdr vs))
              (fail "same question refused rather than replayed" got))
            (unless (equal? (car (car vs)) (car (cadr vs)))
              (fail "same question got two different answers" got))
            (display "the same question twice -> one step, answer replayed ok\n"))
          (receive (after 4000 (fail "replay timeout" got))
            (`#(q1 ,v) (loop (cons (cons 'q1 v) got) (+ n 1)))
            (`#(q2 ,v) (loop (cons (cons 'q2 v) got) (+ n 1))))))))

;; ...but a request the application CANNOT key is never a replay of
;; another one it also cannot key. Failure has to be one value that
;; equals nothing, itself included: if two unkeyable requests compare
;; equal, a caller asking to cancel is handed the confirm's answer --
;; the exact case request keys were added to prevent. Refusing to key
;; something is the application saying "I cannot tell these apart", and
;; the safe reading of that is 'stale.
(let-values (((uid utok ufirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (vector 'confirmed a)))
                'go
                4000
                (lambda (r) (raise 'cannot-key)))))   ; keys nothing, ever
  ;; the first resume advances -- advancing needs the token, not the key
  (let-values (((r st) (conversation-resume! uid utok 'CONFIRM)))
    (unless (conversation-done? st) (fail "unkeyable-setup" st))
    (unless (equal? r (vector 'confirmed 'CONFIRM))
      (fail "unkeyable-setup answer" r)))
  ;; a DIFFERENT question on the spent token, equally unkeyable
  (let-values (((r st) (conversation-resume! uid utok 'CANCEL)))
    (unless (conversation-stale? st)
      (fail "an unkeyable request replayed another unkeyable one" (cons r st)))
    (display "two requests the app cannot key do not replay each other ok\n")))

;; ---- what a KILLED step leaves behind -----------------------------------
;;
;; TTL expiry has two paths and only one of them raises. A conversation
;; that sat PARKED too long is raised at, so the flow's guard runs. A STEP
;; that overruns is KILLED -- which is what the watchdog is for, since a
;; step stuck in a loop cannot be raised at -- and @kill discards
;; dynamic-wind winders, so that guard does NOT run.
;;
;; A pooled database connection survives that: the pool rebuilds a
;; connection whose borrower died, which drops the transaction. Anything
;; held IN PROCESS does not. Here that is a hold on a balance, restored in
;; a guard the kill skips: without the hook the money stays deducted for
;; the life of the VM.
;; The releaser is IDEMPOTENT and shared by both paths. The guard and the
;; hook are normally exclusive, but a flow that raises just as the watchdog
;; decides to kill it reaches both, and giving the hold back twice is a
;; worse bug than never giving it back.
(let* ((held (box 0))
       (released (box #f))
       (hook-arg (box 'unset))
       (release! (lambda ()
                   (unless (unbox released)
                     (set-box! released #t)
                     (set-box! held (- (unbox held) 100))))))
  (let-values (((kid ktok kfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (set-box! held (+ (unbox held) 100))       ; the hold
                    (guard (e (#t (release!) (raise e)))       ; never runs
                      (let ((a (suspend! (vector 'held req))))
                        (sleep-ms 5000)                        ; overruns
                        (vector 'unreachable a))))
                  'go
                  300                                          ; TTL 300 ms
                  values                                       ; request-key
                  ;; runs AFTER the kill, in the watchdog's process, on
                  ;; what the flow was holding -- reached through the box
                  ;; it closed over, not through the dead stack. This flow
                  ;; never committed, and the hook is told so.
                  (lambda (committed?)
                    (set-box! hook-arg committed?)
                    (release!)))))
    (let ((me self))
      (spawn (lambda ()
               (let-values (((r st) (conversation-resume! kid ktok 'go)))
                 (send me (vector 'k r)))))
      (receive (after 6000 (fail "killed-step" 'no-answer)) (`#(k ,v) 'ok))))
  (sleep-ms 400)
  (unless (= 0 (unbox held))
    (fail "a killed step leaked its in-process hold" (unbox held)))
  (unless (eq? #f (unbox hook-arg))
    (fail "an uncommitted kill did not tell its hook so" (unbox hook-arg)))
  (display "an on-killed hook releases what a killed step held ok\n"))


;; ---- a cleanup that blocks is still on the clock -------------------------
;;
;; The park TTL expires by RAISING into the flow, and what that raise
;; reaches is application code: the guard that gives back whatever the flow
;; was holding. While the phase still said "parked" the watchdog skipped
;; the process for as long as that cleanup ran, so a rollback that blocked
;; -- a resource manager that never answers, a lock nobody releases -- left
;; a conversation alive, registered, and never coming back. A caller waits
;; for a reply or for a DOWN and would have had neither, forever.
(let ((released (box #f)))
  (let-values (((bid btok bfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (guard (e (#t (receive (after 60000 'never))))   ; wedges
                      (suspend! (vector 'parked req))))
                  'go
                  300)))                            ; TTL 300 ms
    (let ((me self))
      ;; nobody resumes: the park expires and the wedged guard runs
      (sleep-ms 500)
      (spawn (lambda ()
               (let-values (((r st) (conversation-resume! bid btok 'anything)))
                 (send me (vector 'answered st)))))
      ;; ...AND IS TOLD 'unknown, EXACTLY. This used to accept any of
      ;; gone/settled/stale, and what it actually got was 'gone -- which
      ;; this library documents as "the transaction rolled back". The
      ;; watchdog cannot know that: it sees a step that overran, and
      ;; cannot tell a cleanup from a first step that had already
      ;; committed. 'gone is now reserved for a flow that RAISED, whose
      ;; winders ran; a step stopped in flight says so, and the caller
      ;; reconciles instead of redoing the work.
      (receive (after 4000 (fail "a caller waited forever on a wedged cleanup" bid))
        (`#(answered ,st)
          (if (eq? st 'unknown)
              (display "a wedged cleanup is killed and the caller is told 'unknown ok\n")
              (fail "a killed step was reported as something other than unknown"
                    st)))))))

;; ---- a settled record that was pruned is still not 'killed --------------
;;
;; First-write-wins is decided by what is in the table, and the table
;; forgets. A conversation that settled, whose record was then evicted by
;; the count limit while it was still lingering, and which is then killed
;; for a hung key, would have its certain answer overwritten with an
;; uncertain one -- although the flag saying it settled is still right
;; there to be read.
(let ((limit-restored #f))
  (conversation-set-limits! 1 #f)          ; one tombstone at a time
  (let ((released (box 0)))
    (let-values (((pid ptok pfirst)
                  (conversation-start!
                    (lambda (req suspend! commit!)
                      (let ((a (suspend! (vector 'parked req))))
                        (vector 'committed a)))
                    'go
                    150
                    (lambda (r)                  ; hangs, only on replay
                      (if (eq? r 'HANG) (sleep-ms 60000) (void))
                      r)
                    (lambda (committed?)
                      (set-box! released (+ 1 (unbox released)))))))
      (let-values (((r st) (conversation-resume! pid ptok 'confirm)))
        (unless (conversation-done? st) (fail "pruned-settled setup" st)))
      ;; a second conversation completes and evicts the first one's record
      (let-values (((qid qtok qfirst)
                    (conversation-start!
                      (lambda (req suspend! commit!) (vector 'done req))
                      'go
                      150)))
        (void))
      ;; ...and now the first one is killed while it still knows it settled
      (let ((me self))
        (spawn (lambda ()
                 (let-values (((r2 st2)
                               (guard (e (#t (values 'raised 'raised)))
                                 (conversation-resume! pid ptok 'HANG))))
                   (send me (vector 'pruned st2)))))
        (receive (after 8000 (fail "the pruned-settled replay never answered"
                                   'no-answer))
          (`#(pruned ,st)
            (conversation-set-limits! 4096 #f)
            (set! limit-restored #t)
            (unless (eq? st 'settled)
              (fail "a settled conversation whose record was pruned was answered"
                    st))
            (display "a pruned settled record is not overwritten by a kill ok\n"))))))
  (unless limit-restored (conversation-set-limits! 4096 #f)))

;; ---- an initial step that committed is not a retryable failure ----------
;;
;; The same hazard one step earlier. A flow that reaches its COMMIT before
;; its first suspend! and is then stopped never gives conversation-start!
;; a reply, so the starter sees only a DOWN -- and the worker pool re-runs
;; an unanswered task by design. Raising the ordinary retryable failure
;; there is how that commit happens a second time.
(let* ((ttl 100)
       (committed (box 0)))
  (let ((outcome
         (guard (e (#t e))
           (conversation-start!
             (lambda (req suspend! commit!)
               (set-box! committed (+ 1 (unbox committed)))   ; the COMMIT
               (sleep-ms (* 6 ttl))                           ; ...then late
               (suspend! (vector 'never-reached req)))
             'go
             ttl))))
    (unless (= 1 (unbox committed))
      (fail "the initial flow never reached its commit" (unbox committed)))
    (unless (vector? outcome)
      (fail "a killed initial step did not raise" outcome))
    (when (eq? (vector-ref outcome 0) 'conversation-failed)
      (fail "a committed initial step was raised as a retryable failure"
            outcome))
    (unless (eq? (vector-ref outcome 0) 'conversation-uncertain)
      (fail "a killed initial step raised the wrong thing" outcome))
    ;; the id has to come with it, or the caller cannot reconcile what it
    ;; started -- and reconciling is the only thing left to do
    (unless (and (> (vector-length outcome) 2)
                 (eq? (vector-ref outcome 2) 'unknown))
      (fail "the uncertain raise did not carry an outcome" outcome))
    (let-values (((st tok reply) (conversation-peek (vector-ref outcome 1))))
      (unless (eq? st 'unknown)
        (fail "the id from an uncertain raise does not reconcile" st)))
    (display "a committed initial step is not raised as retryable ok\n")))

;; ---- an effect that landed is never reported rolled back ----------------
;;
;; The window this is about: the flow's COMMIT has returned -- the money
;; has moved -- and the flow is on its way back to publish. Nothing in the
;; system records "on its way back", so the watchdog can stop it there.
;; The compensation runs against work that already succeeded (unavoidable,
;; and why compensation must be idempotent), but what must NOT happen is
;; telling the caller the transaction rolled back: it would do the whole
;; thing again. 'gone says exactly that, and before the tombstone learned
;; to distinguish a kill from a settle, that is what this caller got.
(let* ((ttl 100)
       (committed (box 0)))
  (let-values (((eid etok efirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (set-box! committed (+ 1 (unbox committed)))  ; the COMMIT
                      (sleep-ms (* 6 ttl))          ; ...and then it is late
                      (vector 'committed a)))
                  'go
                  ttl)))
    (let ((me self))
      (spawn (lambda ()
               (let-values (((r st)
                             (guard (e (#t (values 'raised 'raised)))
                               (conversation-resume! eid etok 'go))))
                 (send me (vector 'eff r st)))))
      (receive (after 6000 (fail "the committed-then-late flow never answered"
                                 'no-answer))
        (`#(eff ,r ,st)
          ;; the effect really did land -- without this the case could pass
          ;; on a flow that was killed before doing anything
          (unless (= 1 (unbox committed))
            (fail "the flow never reached its commit" (unbox committed)))
          (when (eq? st 'gone)
            (fail "an effect that landed was reported rolled back" st))
          (unless (eq? st 'unknown)
            (fail "a flow killed after its commit got the wrong status" st))
          (display "an effect that landed is never reported rolled back ok\n"))))))

;; ---- a spent token against a flow that re-parks is stale ----------------
;;
;; What this actually pins: a flow whose guard swallows 'conversation-expired
;; and parks again is answerable, and the token from before that expiry is
;; refused rather than applied. The conversation has already expired and
;; re-parked by the time the resume arrives, so the token is simply spent.
;;
;; It does NOT cover the reply the deadline re-check now sends before
;; expiring. Reaching that needs the step to arrive after the deadline but
;; before the conversation is next scheduled -- the same race the re-check
;; itself is documented as untestable for. The reply is defence on that
;; path: without it the sender waits in a receive with no deadline at all.
(let ((rounds (box 0)))
  (let-values (((sid stok sfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let loop ((r req))
                      (set-box! rounds (+ 1 (unbox rounds)))
                      (loop (guard (e (#t 'swallowed))   ; eats the expiry
                              (suspend! (vector 'ask r))))))
                  'go
                  300)))
    (let ((me self))
      (sleep-ms 500)                       ; the park window has closed
      (spawn (lambda ()
               (let-values (((r st) (conversation-resume! sid stok 'LATE)))
                 (send me (vector 'answered st)))))
      (receive (after 4000 (fail "a late step was dropped without an answer" sid))
        (`#(answered ,st)
          (unless (conversation-stale? st)
            (fail "a late step was not answered stale" st))
          (display "a spent token against a re-parking flow is stale ok\n"))))))

;; ---- a completed conversation is not a step that overran ----------------
;;
;; Computing a request key marks the phase running, and it does that during
;; the LINGER too. A slow key function on a replay could therefore bring the
;; watchdog down on a conversation that had committed and finished: its own
;; guard had already run, so the on-killed hook released a second time. Only
;; the flow's own idempotence was hiding that.
(let ((releases (box 0)))
  (let-values (((cid ctok cfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (vector 'committed a)))
                  'go
                  400
                  (lambda (r)                       ; slow key, only on replay
                    (if (eq? r 'REPLAY) (sleep-ms 900) (void))
                    r)
                  (lambda (committed?)
                    (set-box! releases (+ 1 (unbox releases)))))))
    (let-values (((r st) (conversation-resume! cid ctok 'confirm)))
      (unless (conversation-done? st) (fail "completed-setup" st)))
    ;; a replay whose key is slow enough to look like an overrunning step
    (let-values (((r2 st2) (conversation-resume! cid ctok 'REPLAY)))
      (void))
    (sleep-ms 300)
    (unless (= 0 (unbox releases))
      (fail "a finished conversation ran its on-killed hook" (unbox releases)))
    ;; The kill is gated on the same flag, not just the hook -- but that
    ;; cannot be asserted here and no test can assert it: the linger window
    ;; IS the ttl, so a key slow enough to look like an overrunning step is
    ;; also slow enough to outlast the linger. The conversation ends either
    ;; way, and the two reasons are indistinguishable from outside. What is
    ;; observable, and what this pins, is that a finished flow's hook does
    ;; not run a second time.
    (display "a slow key during the linger does not re-release ok\n")))

;; ---- a flow that returned inside its TTL is never reported gone ----------
;;
;; Between a flow returning and its completion being published there were
;; four separate writes, and the deadline can fall inside them: the watchdog
;; then found a step still marked running and past its allowance, killed a
;; conversation that had ALREADY COMMITTED, and left no tombstone -- so the
;; caller was told 'gone, which this library documents as a rollback
;; guarantee. Committing and then being told it did not happen is the one
;; outcome nothing else here is worth anything without.
;;
;; The flow returns with almost none of its allowance left, so the
;; publication and the deadline land on top of each other.
(let ((committed (box #f)))
  (let-values (((wid wtok wfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (sleep-ms 380)            ; inside a 400ms TTL, just
                      (set-box! committed #t)   ; "commit"
                      (vector 'committed a)))
                  'go
                  400)))
    (let-values (((r st) (conversation-resume! wid wtok 'confirm)))
      (unless (unbox committed)
        (fail "the flow did not reach its commit" st))
      (when (conversation-gone? st)
        (fail "a flow that committed inside its TTL was reported rolled back" st))
      (unless (or (conversation-done? st) (conversation-settled? st))
        (fail "a committed flow was neither done nor settled" st)))
    ;; ...and it must still say so afterwards
    (let-values (((state token reply) (conversation-peek wid)))
      (when (conversation-gone? state)
        (fail "a committed conversation later reported rolled back" state)))
    (display "a flow that returns inside its TTL is never gone ok\n")))

;; ---- a small TTL is still a TTL ------------------------------------------
;;
;; What this pins: a step far past a TTL below the watchdog's poll floor is
;; still killed.
;;
;; It does NOT pin the floor change itself. Separating the two needs a step
;; that lands inside the gap between the TTL and the old 50ms floor -- a
;; five millisecond window with a 40ms TTL -- and an assertion with five
;; milliseconds of margin is a coin toss reported as a result. The floor now
;; never outlasts the thing it watches, which is free and correct; it is not
;; claimed as tested.
(let-values (((tid ttok tfirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (sleep-ms 300)              ; far past a 40ms TTL
                    (vector 'should-not-get-here a)))
                'go
                40)))
  (let ((me self))
    (spawn (lambda ()
             (let-values (((r st) (conversation-resume! tid ttok 'X)))
               (send me (vector 'tiny r)))))
    (receive (after 5000 (fail "tiny-ttl" 'no-answer))
      (`#(tiny ,v)
        (when (and (vector? v) (eq? (vector-ref v 0) 'should-not-get-here))
          (fail "a step outran a TTL below the watchdog's floor" v))
        (display "a TTL below the poll floor is still enforced ok\n")))))

;; ---- a satisfied caller is not answered twice ---------------------------
;;
;; The reply destination used to persist after it had been answered, so a
;; flow whose guard swallows 'conversation-expired and parks again sent its
;; next reply to the caller that finished rounds ago. Nothing reads those,
;; and in a reused pool worker's mailbox they accumulate one per round --
;; each one scanned past by every later selective receive.
(let ((me self))
  (let-values (((oid otok ofirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let loop ((r req))
                      (loop (guard (e (#t 'swallowed))
                              (suspend! (vector 'ask r))))))
                  'go
                  200)))
    ;; ofirst was this process's answer; the flow now expires and re-parks
    ;; several times on its own
    (sleep-ms 900)
    ;; nothing more may have arrived for the exchange already settled
    (let ((extra (let drain ((n 0))
                   (receive (after 0 n)
                     (`#(conv-reply ,r ,reply ,status) (drain (+ n 1)))))))
      (unless (= 0 extra)
        (fail "a settled caller received further replies" extra))
      (display "a caller that was already answered is not answered again ok\n"))))

;; ---- a key that hangs during the linger is still bounded ----------------
;;
;; safe-key marks the phase running precisely so that a key function
;; which never returns is the watchdog's problem. That only held while
;; the conversation was unsettled: the kill also asked for NOT settled,
;; and the linger -- when replays actually arrive -- is settled by
;; definition. A hung key there took the conversation, its caller, and
;; every later request to that id with it, for the life of the VM.
;;
;; Killing a settled conversation costs nothing: its value is published
;; and its tombstone written, so the caller falls back to the record and
;; is told 'settled. What must NOT happen is the compensation running --
;; the flow committed.
(let ((released (box 0))
      (entered-key (box #f)))
  (let-values (((hid htok hfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (vector 'committed a)))
                  'go
                  120
                  (lambda (r)                     ; hangs, only on replay
                    (when (eq? r 'HANG) (set-box! entered-key #t))
                    (if (eq? r 'HANG) (sleep-ms 60000) (void))
                    r)
                  (lambda (committed?)
                    (set-box! released (+ 1 (unbox released)))))))
    (let-values (((r st) (conversation-resume! hid htok 'confirm)))
      (unless (conversation-done? st) (fail "hung-key setup" st)))
    ;; ...and now a replay whose key never comes back, WITH A SECOND
    ;; REQUEST QUEUED BEHIND IT. The conversation serves one at a time, so
    ;; a key that never returns holds not just its own caller but every
    ;; later arrival at that id; bounding only the first would leave the
    ;; queue exactly as stuck as before. The second is sent while the key
    ;; is still hanging -- sending it afterwards would only prove that a
    ;; dead conversation answers from its tombstone, which is a different
    ;; and much weaker statement.
    (let ((me self))
      (spawn (lambda ()
               (let* ((t0 (now-ms)))
                 (let-values (((r2 st2)
                               (guard (e (#t (values 'raised 'raised)))
                                 (conversation-resume! hid htok 'HANG))))
                   (send me (vector 'hung (- (now-ms) t0) st2))))))
      (sleep-ms 30)                          ; well inside the 120ms TTL
      (spawn (lambda ()
               (let* ((t0 (now-ms)))
                 (let-values (((r3 st3)
                               (guard (e (#t (values 'raised 'raised)))
                                 (conversation-resume! hid htok 'BEHIND))))
                   (send me (vector 'behind (- (now-ms) t0) st3))))))
      (let wait ((hung #f) (behind #f))
        (if (and hung behind)
            (begin
              ;; the key really did run and really did hang -- an
              ;; implementation that only compares tokens and never calls
              ;; the key at all would otherwise pass this whole case
              (unless (unbox entered-key)
                (fail "the request key was never called" (unbox entered-key)))
              (when (> (car hung) 4000)
                (fail "a hung key was bounded only by its own sleep" (car hung)))
              ;; exactly 'settled: the flow committed and its tombstone
              ;; says so. 'raised would mean the guard swallowed something
              ;; and 'done would mean it was never killed at all -- the
              ;; disjunction that used to be here accepted both.
              (unless (eq? (cdr hung) 'settled)
                (fail "a replay past a hung key got the wrong answer" (cdr hung)))
              (when (> (car behind) 4000)
                (fail "a request behind a hung key waited out the hang"
                      (car behind)))
              (sleep-ms 200)
              (unless (= 0 (unbox released))
                (fail "a committed flow was compensated for a hung key"
                      (unbox released)))
              (display (string-append "a key that hangs after settling is bounded ("
                                      (number->string (car hung)) "ms, the one behind it "
                                      (number->string (car behind)) "ms) ok\n")))
            (receive (after 8000
                       (fail "a hung key during the linger was never bounded"
                             (list 'hung hung 'behind behind)))
              (`#(hung ,t ,st) (wait (cons t st) behind))
              (`#(behind ,t ,st) (wait hung (cons t st)))))))))

;; ---- the kill happens ON TIME, not eventually ---------------------------
;;
;; Every other watchdog case here asserts only that the sentinel value did
;; not come back -- which cannot tell "killed at the TTL" from "killed at
;; twice the TTL". Reverting the whole event-driven wake-up left all of
;; them green. What pins it is the LATENCY: a step that runs far past its
;; allowance must be stopped within a small multiple of it, and the
;; parked poll floor is 50ms, so a TTL well under that separates "told"
;; from "noticed on the next poll".
;;
;; MEASURED FROM THE STEP, and only when there was one.
;;
;; Timing from the caller's side measures two things it should not. A
;; resume that arrives after the park deadline is refused outright, and
;; the 2000ms step never starts -- an all-but-instant answer that would
;; have become the best sample and proved nothing. And the watchdog's
;; poll is already part-elapsed when a step begins, so what a caller
;; sees on the polling path is the REMAINDER of a 50ms wait, which can
;; be almost nothing. Both are removed by starting the clock in the step
;; itself: from there the notification path costs about the TTL, and the
;; poll path cannot cost less than the floor minus the park window the
;; step had to start inside.
;;
;; Best of several, because now-ms is a wall clock and a collection
;; lands in the measurement; a lost notification costs EVERY trial, so
;; one good sample is enough to show it arrived and no slow one can
;; condemn it.
;; SEEDED WITH NOTHING. There was a fourth trial ahead of these that
;; timed from the caller and seeded this, and it carried the very defect
;; the paragraph above says was removed: when its resume arrived after
;; the park deadline it was refused, returned in under a millisecond,
;; and seeded a value already under the bar -- so the assertion passed
;; whatever the three real samples said. Reproduced by delaying that
;; trial 40ms with the notification also removed: green at "0ms after it
;; started". The gate was applied to the new trials and left off the one
;; feeding them.
;; A MAJORITY, NOT THE LUCKIEST. Taking the fastest of several resists a
;; collection landing in one measurement, but it also lets one lucky
;; trial carry the assertion -- and there is a way to be lucky without
;; the notification: the watchdog may still be asleep on a PREVIOUS
;; step's deadline, which expires first, and it re-reads the clock on
;; waking and kills the new step on time having been told nothing.
;; Requiring two of three to clear the bar survives one slow trial and
;; one lucky one, and both together are what it would take to hide a
;; lost notification.
(let ((under 0)
      (best 999999)
      (samples 0)
      (trials 3))
  (do ((i 0 (+ i 1))) ((= i trials))
    (let ((ttl 20)
          (started (box #f)))
      (let-values (((kid ktok kfirst)
                    (conversation-start!
                      (lambda (req suspend! commit!)
                        (let ((a (suspend! (vector 'parked req))))
                          (set-box! started (now-ms))
                          (sleep-ms 2000)
                          (vector 'should-not-get-here a)))
                      'go
                      ttl)))
        (let ((me self))
          (spawn (lambda ()
                   (let-values (((r st) (conversation-resume! kid ktok 'X)))
                     (send me (vector 'latency (now-ms) r)))))
          ;; A TRIAL THAT NEVER ANSWERS IS NOT A TRIAL THAT DID NOT COUNT.
          ;; Swallowing the timeout here meant two ordinary trials and one
          ;; caller left with neither a reply nor a DOWN still passed the
          ;; whole case -- the one outcome that would matter most.
          (receive (after 6000 (fail "a latency trial was never answered" i))
            (`#(latency ,at ,v)
              (when (and (vector? v) (eq? (vector-ref v 0) 'should-not-get-here))
                (fail "a runaway step ran to completion" v))
              ;; no step, no sample: the resume was refused and the thing
              ;; being timed never happened
              (when (unbox started)
                (set! samples (+ samples 1))
                (let ((took (- at (unbox started))))
                  (when (< took best) (set! best took))
                  (when (< took 30) (set! under (+ under 1)))))))))))
  (when (= samples 0)
    (fail "no trial started a step: nothing was timed" samples))
  ;; told: ttl plus the grace. Noticed on the poll: the floor is 50 and
  ;; the step had to begin inside a 20ms park window, so 30 is the least
  ;; it can cost measured from the step.
  (unless (>= under 2)
    (fail "the kill waited for a poll instead of being told"
          (list 'under under 'of samples 'best best)))
  (display (string-append "a runaway step is stopped "
                          (number->string best)
                          "ms after it started ("
                          (number->string under) "/"
                          (number->string samples)
                          " under the bar) ok\n")))

;; ---- a step that lands inside the grace tick is NOT killed --------------
;;
;; The grace tick exists so that a flow which has already returned is not
;; killed on its way back and reported rolled back. The sweep below pins
;; that declining to kill leaves the watchdog watching -- but it is
;; satisfied just as well by a watchdog that never declines at all, so
;; deleting the re-check inside the grace window left it green. This is
;; the other side: a step finishing one or two milliseconds past its
;; allowance must COMPLETE, which it can only do if the grace period is
;; there and the decision is taken again at the end of it.
;; WHAT TO COUNT IS NOT HOW MANY SURVIVED. Whether a step overrunning by
;; four milliseconds is killed or not is a coin toss on the sampling
;; phase, and asserting a rate would be asserting the coin. What must
;; never happen is BOTH: a flow whose value came back and whose
;; compensation ran anyway -- a committed transaction told it was rolled
;; back. Deleting the re-check produced exactly that, 13 times in 20.
(let* ((ttl 20)
       (d (+ ttl 4))
       (n 20)
       (both 0)
       (killed 0))
  (do ((i 0 (+ i 1))) ((= i n))
    (let ((released (box #f)))
      (let ((r (guard (e (#t 'raised))
                 (let-values (((gid gtok gfirst)
                               (conversation-start!
                                 (lambda (req suspend! commit!)
                                   (sleep-ms d)
                                   (vector 'landed d))
                                 'go
                                 ttl
                                 (lambda (x) x)
                                 (lambda (committed?) (set-box! released #t)))))
                   gfirst))))
        (sleep-ms 60)                       ; let a late kill land
        (when (unbox released) (set! killed (+ killed 1)))
        (when (and (vector? r) (eq? (vector-ref r 0) 'landed) (unbox released))
          (set! both (+ both 1))))))
  (unless (= both 0)
    (fail "a flow that returned its value also had its compensation run"
          (list both n)))
  (display (string-append "a committed flow is never also released ("
                          (number->string killed) "/"
                          (number->string n) " killed) ok\n")))

;; ...AND THE GRACE PERIOD IS WHAT BUYS THAT, measured where the answer is
;; not a coin toss. Two milliseconds past the allowance, a step that is
;; still running when the watchdog first looks has almost always finished
;; by the time it looks again: 0 of 25 killed here, against 25 of 25 with
;; the millisecond removed. Four milliseconds past, both numbers climb and
;; the gap closes -- which is why the case above uses that value for the
;; exclusivity property and this one does not: an assertion on a rate has
;; to sit somewhere the rate is flat, or a host that oversleeps by one
;; millisecond fails it on correct code.
;; THE STEP PARKS rather than finishing outright, because that is the
;; case the re-check still protects: a flow that suspended has not
;; settled, so killing it DOES run its compensation -- work released for
;; a conversation that was healthy and waiting. A flow that finished is
;; covered by the exclusivity property above and by nothing here.
(let* ((ttl 20)
       (d (+ ttl 2))
       (n 20)
       (killed 0))
  (do ((i 0 (+ i 1))) ((= i n))
    (let ((released (box #f)))
      (guard (e (#t (void)))
        (let-values (((gid gtok gfirst)
                      (conversation-start!
                        (lambda (req suspend! commit!)
                          (sleep-ms d)
                          (let ((a (suspend! (vector 'parked 'x))))
                            (vector 'done a)))
                        'go
                        ttl
                        (lambda (x) x)
                        (lambda (committed?) (set-box! released #t)))))
          ;; finish it at once, so the park deadline is not what ends it
          (guard (e (#t (void)))
            (let-values (((r st) (conversation-resume! gid gtok 'go)))
              (void)))))
      (sleep-ms 40)
      (when (unbox released) (set! killed (+ killed 1)))))
  ;; WHAT THIS SEPARATES AND WHAT IT DOES NOT. Removing the grace
  ;; entirely kills all 40 of 40 here against 0 of 40 with it, which is
  ;; the assertion below. Removing only the re-check INSIDE the grace is
  ;; separated much less: 3 of 40 against 0, rising to 40 against 18 two
  ;; milliseconds further out, where a host that oversleeps by one
  ;; millisecond would fail the tighter bound on correct code. Every
  ;; point on that curve moves together under a host shift, so no rate
  ;; threshold pins it. It is left uncovered rather than covered by
  ;; something that would fire on a slower machine.
  (unless (< killed (div n 2))
    (fail "a step that parked during the grace tick was killed anyway"
          killed))
  (display (string-append "the grace tick spares a step that parks in it ("
                          (number->string killed) "/"
                          (number->string n) " killed) ok\n")))

;; ---- the watchdog outlives a step it decided NOT to kill ----------------
;;
;; The grace tick re-checks before killing, so it can find the step
;; already finished -- and a watchdog that treats "nothing to kill" as
;; "nothing left to do" leaves every LATER step of that conversation
;; unbounded. The window is one millisecond wide, so this sweeps the
;; first step's duration across the deadline and settles for hitting it
;; some of the time: a single run to completion is the failure.
(let* ((ttl 20)
       (hits 0)
       (survived 0))
  (do ((d ttl (+ d 1))) ((> d (+ ttl 5)))
    (do ((trial 0 (+ trial 1))) ((= trial 5))
      ;; the first step may or may not have been killed -- when it was,
      ;; the start itself raises, and that trial simply did not land in
      ;; the window. What must hold is that when it PARKED, the second
      ;; step is still bounded.
      (guard (e (#t (void)))
       (let-values (((gid gtok gfirst)
                    (conversation-start!
                      (lambda (req suspend! commit!)
                        (sleep-ms d)          ; ends right around the deadline
                        (let ((a (suspend! (vector 'parked req))))
                          (sleep-ms (* 20 ttl))
                          (vector 'ran-to-completion a)))
                      'go
                      ttl)))
        (set! survived (+ survived 1))
        (let ((me self))
          (spawn (lambda ()
                   ;; a first step that WAS killed makes the resume raise;
                   ;; that is the healthy outcome, not the one under test
                   (guard (e (#t (send me (vector 'g 'raised))))
                     (let-values (((r st) (conversation-resume! gid gtok 'X)))
                       (send me (vector 'g r))))))
          (receive (after (* 30 ttl) (void))
            (`#(g ,v)
              (when (and (vector? v) (eq? (vector-ref v 0) 'ran-to-completion))
                (set! hits (+ hits 1))))))))))
  (unless (= hits 0)
    (fail "a later step ran unbounded after the watchdog declined to kill"
          hits))
  ;; ...AND SOME TRIAL HAS TO HAVE HAD A SECOND STEP. This is weaker than
  ;; it looks and is labelled for what it is: a trial that survived its
  ;; first step did not necessarily go through the decline branch, so this
  ;; rules out only the emptiest way for `hits = 0` to mean nothing. What
  ;; the branch was actually entered by, measured with instrumentation, is
  ;; roughly a third of the trials at the middle of the sweep and none at
  ;; either end -- which no assertion here can see.
  (when (= survived 0)
    (fail "no trial got past its first step: nothing had a second step"
          survived))
  (display "the watchdog keeps watching after declining to kill ok\n"))

;; ---- a resume long after the park deadline does not advance -------------
;;
;; What this pins is the ordinary case: the window closed, the flow was
;; raised into, and the conversation is gone -- nothing can revive it.
;;
;; It does NOT cover the boundary the deadline re-check in serve-steps!
;; exists for: a resume that arrives microseconds after the deadline while
;; the conversation is still queued to run, where a receive would answer
;; the message in its mailbox before consulting its timer. Constructing
;; that means winning a race against the scheduler on purpose; the guard
;; is cheap and correct, and is not claimed as tested.
(let ((advanced (box #f)))
  (let-values (((lid ltok lfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (set-box! advanced #t)
                      (vector 'advanced a)))
                  'go
                  300)))
    ;; sent well after the park deadline
    (sleep-ms 700)
    (let-values (((r st) (conversation-resume! lid ltok 'LATE)))
      (if (unbox advanced)
          (fail "a resume after the park deadline was applied" st)
          (display "a resume after the park deadline is not applied ok\n")))))

;; ---- after the linger, 'gone must still not lie -------------------------
;;
;; 'gone is documented as the rollback guarantee, and for a conversation
;; that DIED it is one. For one that COMPLETED it is false: the flow
;; committed and then exited, and a caller told "rolled back" performs the
;; whole thing again. The linger covers the window right after completion,
;; but it holds a process; a tombstone is an id and an outcome, so it can
;; outlast it cheaply.
(let-values (((sid stok sfirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (vector 'committed a)))
                'go
                300)))                          ; short TTL -> short linger
  (let-values (((r st) (conversation-resume! sid stok 'confirm)))
    (unless (conversation-done? st) (fail "settled-setup" st)))
  ;; wait out the linger
  (sleep-ms 700)
  (let-values (((state token reply) (conversation-peek sid)))
    (unless (conversation-settled? state)
      (fail "a completed conversation was reported as gone" state)))
  (let-values (((r st) (conversation-resume! sid stok 'confirm)))
    (unless (conversation-settled? st)
      (fail "a resume after the linger was reported as gone" st)))
  (display "after the linger a completed conversation is settled, not gone ok\n"))

;; ...and one that DIED is still 'gone -- the guarantee that matters
(let-values (((did dtok dfirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (raise 'flow-crashed)))
                'go
                300)))
  (let-values (((r st) (conversation-resume! did dtok 'confirm)))
    (unless (conversation-gone? st) (fail "crashed-flow-status" st)))
  (sleep-ms 500)
  (let-values (((state token reply) (conversation-peek did)))
    (unless (conversation-gone? state)
      (fail "a crashed conversation was reported as settled" state)))
  (display "a conversation that died is still gone ok\n"))

;; ---- 'gone comes only from evidence: the death-mode matrix --------------
;;
;; 'gone is the rollback guarantee -- the one answer a caller is told it
;; may retry on -- so it has to be read off a record that SAYS the flow
;; rolled back, never off the absence of one. The absence reading is
;; wrong for every way of dying that writes nothing: a kill from outside,
;; a link cascade, an after-thunk raising while the flow was already
;; returning from its COMMIT. Those cannot be enumerated, so what is
;; pinned here is the rule and not the list -- a death that left through
;; the flow's winders answers 'gone, and a death nothing witnessed
;; answers 'unknown.
;;
;; EXACT ANSWERS, in both directions. Accepting either of gone/unknown
;; anywhere below would pass with the entire distinction deleted, which
;; is the shape of the defect these cases exist for.

;; 1. A RAISE MID-STEP, before anything committed. The flow's own guard
;; ran on the way out, so something witnessed the rollback and 'gone can
;; be stated rather than guessed.
(let ((rolled (box #f)))
  (let-values (((aid atok afirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (guard (e (#t (set-box! rolled #t) (raise e)))
                      (let ((a (suspend! (vector 'parked req))))
                        (raise 'flow-raised))))
                  'go
                  300)))
    (let-values (((r st) (conversation-resume! aid atok 'confirm)))
      (unless (eq? st 'gone)
        (fail "a flow that raised was not reported rolled back" st)))
    ;; without this the case would pass on a flow that never got there
    (unless (unbox rolled)
      (fail "the raise never reached the flow's rollback" (unbox rolled)))
    ;; ...and the record outlives the process, so a caller reconciling
    ;; later is told the same thing
    (sleep-ms 200)
    (let-values (((state tok reply) (conversation-peek aid)))
      (unless (eq? state 'gone)
        (fail "a rolled-back conversation stopped saying so" state)))
    (display "a flow that raised mid-step -> gone, on its own record ok\n")))

;; 2. A PARK DEADLINE THAT PASSED. This one is 'gone for the same reason
;; and by the same path: the park expiry RAISES 'conversation-expired
;; into the flow rather than killing it, so an application that does not
;; swallow the raise leaves through its winders exactly as above. That is
;; a fact about the code and not a choice made here -- were the park
;; deadline ever changed to a kill, the winders would not run, nothing
;; would witness a rollback, and this assertion would be wrong and would
;; say so.
(let ((rolled (box #f)))
  (let-values (((bid btok bfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (guard (e (#t (set-box! rolled #t) (raise e)))
                      (let ((a (suspend! (vector 'parked req))))
                        (vector 'never a))))
                  'go
                  200)))
    (sleep-ms 500)                     ; nobody answers; the window closes
    (unless (unbox rolled)
      (fail "the park deadline did not raise into the flow" (unbox rolled)))
    (let-values (((state tok reply) (conversation-peek bid)))
      (unless (eq? state 'gone)
        (fail "an expired park was not reported rolled back" state)))
    (display "a park deadline that expired -> gone, its winders ran ok\n")))

;; 3. A KILL FROM OUTSIDE, mid-step. Nothing in this library caused it,
;; the flow's guard did NOT run -- @kill discards winders -- and the step
;; may have committed a moment earlier. The old rule answered 'gone here
;; purely because the id was young and the table was empty, which is a
;; rollback guarantee derived from having no evidence at all.
;;
;; The conversation's process is reached the way the outside world
;; reaches it, through the registry, so nothing about this shape depends
;; on the library cooperating.
(let-values (((cid ctok cfirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (guard (e (#t (raise e)))     ; would witness a rollback...
                    (let ((a (suspend! (vector 'parked req))))
                      (sleep-ms 3000)           ; ...but is killed in here
                      (vector 'never a))))
                'go
                400)))
  (let ((me self))
    (spawn (lambda ()
             (let-values (((r st)
                           (guard (e (#t (values 'raised 'raised)))
                             (conversation-resume! cid ctok 'go))))
               (send me (vector 'ext st)))))
    (sleep-ms 100)                              ; the step is running now
    (let ((p (whereis (string->symbol (string-append "igropyr-conv-" cid)))))
      (unless p (fail "the conversation process could not be reached" cid))
      (kill p 'killed-by-someone-else))
    (receive (after 4000 (fail "an externally killed conversation never answered" cid))
      (`#(ext ,st)
        (when (eq? st 'gone)
          (fail "a kill from outside was reported as a rollback" st))
        (unless (eq? st 'unknown)
          (fail "a kill from outside got the wrong status" st))))
    ;; ...and it must still be 'unknown once the watchdog has had its say.
    ;; The watchdog outlives the process it watches, so it is the only
    ;; thing left that can record a death the conversation never got to
    ;; describe -- and what it records is a kill, which reads as 'unknown,
    ;; the same as the silence it replaces. What must not happen is the
    ;; answer drifting to 'gone once the process is properly gone.
    (sleep-ms 700)
    (let-values (((state tok reply) (conversation-peek cid)))
      (when (eq? state 'gone)
        (fail "a kill from outside later became a rollback" state))
      (unless (eq? state 'unknown)
        (fail "a kill from outside did not reconcile as unknown" state)))
    (display "a kill from outside -> unknown, never gone ok\n")))

;; 4. ...and the same rule one step EARLIER. A flow that raises before its
;; first suspend! never answers conversation-start!, which sees only a
;; DOWN and has to decide whether the caller may retry. It may -- the
;; raise left through the winders and the record says so -- and that is
;; the documented retryable failure. Nothing else here pins it: the
;; neighbouring case pins only that a KILLED initial step is NOT
;; retryable, and both of them would pass with the retryable raise
;; deleted altogether.
(let ((outcome
       (guard (e (#t e))
         (conversation-start!
           (lambda (req suspend! commit!) (raise 'before-anything))
           'go
           4000))))
  (unless (vector? outcome)
    (fail "an initial raise did not reach the caller" outcome))
  (unless (eq? (vector-ref outcome 0) 'conversation-failed)
    (fail "an initial raise was not raised as the retryable failure" outcome))
  (display "a flow that raised before its first suspend! is retryable ok\n"))

;; An id from BEFORE this incarnation is outside what this process can
;; speak for. A restart erases the completion records but not the ids the
;; clients are holding, and answering 'gone for those is the same lie the
;; expiry case makes: the transaction may well have committed just before
;; the restart.
;;
;; HOW MUCH THIS STILL PINS, stated plainly because it used to pin more.
;; Since 'gone became a positive record and every absence became 'unknown,
;; this and the two cases below hold for a reason that has nothing to do
;; with the id's shape: there is no record, so there is no 'gone to be
;; had. They no longer discriminate the incarnation check or the horizon
;; comparison, and would stay green with both deleted. They are kept as
;; statements about the ANSWER -- an old id, whatever its shape, is never
;; a rollback guarantee -- and not as coverage of the machinery that used
;; to produce it.
(let ((ancient "1-00112233445566778899aabbccddeeff"))   ; no node prefix: this test runs single-node
  (let-values (((state token reply) (conversation-peek ancient)))
    (unless (conversation-unknown? state)
      (fail "an id older than this process was not reported unknown" state)))
  (display "an id in the pre-incarnation format -> unknown ok\n"))

;; Same incarnation as this run, and a timestamp older than anything this
;; process would still have a record of. This used to be the one case that
;; reached the horizon comparison at all; see the note above for why it no
;; longer reaches it, and what it does still say.
(let* ((real (let-values (((hid htok hfirst)
                           (conversation-start!
                             (lambda (req suspend! commit!) 'done) 'go 300)))
               hid))
       (len (string-length real))
       (dot (let loop ((i 0))
              (cond ((= i len) #f)
                    ((char=? (string-ref real i) #\.) i)
                    (else (loop (+ i 1))))))
       (dash (and dot (let loop ((i (+ dot 1)))
                        (cond ((= i len) #f)
                              ((char=? (string-ref real i) #\-) i)
                              (else (loop (+ i 1)))))))
       ;; "1" ms into this machine's uptime: this run's incarnation, a
       ;; timestamp far below its horizon
       (ancient (and dot dash
                     (string-append (substring real 0 (+ dot 1))
                                    "1"
                                    (substring real dash len)))))
  (unless ancient (fail "could not build a same-incarnation ancient id" real))
  (let-values (((state token reply) (conversation-peek ancient)))
    (when (conversation-gone? state)
      (fail "an id older than the horizon was reported as rolled back" state))
    (unless (conversation-unknown? state)
      (fail "an id older than the horizon was not reported unknown" state)))
  (display "a same-incarnation id older than the horizon -> unknown ok\n"))

;; Tokens from different steps can never be equal, and that is a property
;; of the token rather than of a list this conversation keeps. Nothing else
;; in this file looks at a token's SHAPE, so without this the step number
;; could be dropped and every test would stay green -- uniqueness would
;; quietly go back to being a 64-bit coincidence.
(let ((seen '()))
  (let-values (((tid ttok tfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let loop ((i 0) (r req))
                      (if (>= i 4)
                          'done
                          (loop (+ i 1) (suspend! (vector 'round i))))))
                  'go
                  4000)))
    (let step ((tok ttok) (i 0))
      (when (and tok (string? tok) (< i 4))
        (when (member tok seen)
          (fail "a token repeated an earlier one" tok))
        (set! seen (cons tok seen))
        (let-values (((r st) (conversation-resume! tid tok 'next)))
          (step (and (string? st) st) (+ i 1)))))
    ;; The PREFIXES must differ, not merely the whole tokens. Whole-token
    ;; distinctness is satisfied by the random half alone, so an assertion
    ;; that only checks that would pass with the step number replaced by a
    ;; constant -- which is exactly the property being claimed.
    (let ((prefixes
           (map (lambda (tok)
                  (let ((dash (let loop ((j 0))
                                (cond ((= j (string-length tok)) #f)
                                      ((char=? (string-ref tok j) #\-) j)
                                      (else (loop (+ j 1)))))))
                    (unless (and dash (> dash 0))
                      (fail "a token does not name its step" tok))
                    (substring tok 0 dash)))
                seen)))
      (let dup ((rest prefixes))
        (unless (null? rest)
          (when (member (car rest) (cdr rest))
            (fail "two steps issued tokens with the same step number"
                  (car rest)))
          (dup (cdr rest)))))
    (unless (= 4 (length seen))
      (fail "expected four tokens" (length seen)))
    (display "tokens name their step, and no two steps share one ok\n")))

;; ...and an id from ANOTHER incarnation is unknown however NEW it looks.
;;
;; now-ms is uv_hrtime: monotonic, with an origin nobody promises anything
;; about. Across a host reboot it starts over near zero, so an id minted
;; before the reboot carries a LARGER number than the fresh horizon and
;; would read as "newer than anything I have forgotten" -- 'gone, for a
;; conversation that may well have committed. Requiring a record to say
;; rolled back removes that reading whatever the timestamp says; see the
;; note two cases up for what this still discriminates, which is less.
(let ((from-another-run "deadbeef.zzzzzzzzzz-00112233445566778899aabbccddeeff"))
  (let-values (((state token reply) (conversation-peek from-another-run)))
    (when (conversation-gone? state)
      (fail "an id from another incarnation was reported as rolled back" state))
    (unless (conversation-unknown? state)
      (fail "an id from another incarnation was not reported unknown" state)))
  (display "an id from another incarnation -> unknown, however new it looks ok\n"))

;; A timestamp field nobody would ever mint is not parsed at all. Exact
;; integers in Chez do not overflow, they GROW: a few million base36 digits
;; would be multiplied one at a time into an ever larger bignum, and a
;; single lookup would occupy a worker for as long as that takes.
;; Built from a REAL id, so it carries this run's own incarnation and gets
;; past that check -- otherwise the incarnation mismatch refuses it first
;; and the length bound is never reached.
;; MEASURES NOTHING WHILE NOTHING PARSES THE TIMESTAMP. The lookup path
;; stopped consulting an id's mint time when 'gone became a record rather
;; than an inference, so this is fast because it does no work at all, not
;; because the length bound refused it. Kept as a bound on the PUBLIC
;; call -- a caller-supplied id may not cost a worker whatever the lookup
;; does with it -- and it will discriminate again the moment anything
;; parses the field.
(let* ((absurd-id-from
        (lambda (real)
          (let* ((len (string-length real))
                 (dot (let loop ((i 0))
                        (cond ((= i len) #f)
                              ((char=? (string-ref real i) #\.) i)
                              (else (loop (+ i 1))))))
                 (dash (and dot (let loop ((i (+ dot 1)))
                                  (cond ((= i len) #f)
                                        ((char=? (string-ref real i) #\-) i)
                                        (else (loop (+ i 1))))))))
            (and dot dash
                 (string-append (substring real 0 (+ dot 1))
                                (make-string 200000 #\z)
                                (substring real dash len))))))
       (probe (let-values (((pid ptok pfirst)
                            (conversation-start!
                              (lambda (req suspend! commit!) 'done) 'go 300)))
                pid))
       (absurd (or (absurd-id-from probe)
                   (fail "could not build an absurd id from" probe))))
  (let* ((t0 (now-ms))
         (r (guard (e (#t 'raised))
              (let-values (((state token reply) (conversation-peek absurd)))
                state)))
         (took (- (now-ms) t0)))
    (unless (or (eq? r 'unknown) (eq? r 'raised))
      (fail "an absurd id was not refused" r))
    (when (> took 500)
      (fail "an absurd id was parsed rather than refused" took))
    (display (string-append "a 200k-digit timestamp is refused in "
                            (number->string took) "ms ok\n"))))

;; A predicate that answers with no value, or with several, is not a raise
;; -- so a guard wrapped only around the call let the wrong-number-of-values
;; condition escape into the caller and take the whole public call down,
;; instead of leaving 'unknown standing.
(let ((forgotten "1-00112233445566778899aabbccddeeff"))
  (for-each
    (lambda (bad)
      (let ((r (guard (e (#t 'escaped))
                 (let-values (((state token reply)
                               (conversation-peek forgotten bad)))
                   state))))
        (unless (eq? r 'unknown)
          (fail "a predicate with the wrong value count escaped" r))))
    (list (lambda (id) (values))
          (lambda (id) (values #t #f))
          (lambda (id) (values 1 2 3))))
  (display "a predicate answering with no value or several leaves unknown ok\n"))

;; The record is bounded, and past its age this node stops being able to
;; speak for the conversation at all. It used to answer 'gone there --
;; which this library documents as "the transaction rolled back" -- for a
;; conversation that had COMMITTED and whose only evidence it had just
;; discarded. The honest answer is 'unknown: not here, and no longer
;; knowable from here.
(let-values (((eid etok efirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (vector 'committed a)))
                'go
                200)))
  (conversation-set-limits! #f 300)             ; forget after 300 ms
  (let-values (((r st) (conversation-resume! eid etok 'confirm)))
    (unless (conversation-done? st) (fail "expiry-setup" st)))
  (sleep-ms 900)
  (let-values (((state token reply) (conversation-peek eid)))
    (when (conversation-gone? state)
      (fail "a forgotten conversation was reported as rolled back" state))
    (unless (conversation-unknown? state)
      (fail "a forgotten conversation was not reported unknown" state)))
  (conversation-set-limits! #f 3600000)         ; put it back
  (display "the completion record expires, and says unknown -- not gone ok\n"))

;; ---- a parked conversation cannot be kept alive by poking it -----------
;;
;; The park used to arm `after ttl` afresh on every message, so a caller
;; repeating a spent or invented token slightly more often than the TTL
;; kept the conversation parked forever -- holding whatever it holds, an
;; open transaction included. The watchdog cannot help: it deliberately
;; ignores a parked conversation, because idling between rounds is not
;; what it bounds.
(let-values (((kid ktok kfirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (vector 'final a)))
                'go
                600)))                          ; TTL 600 ms
  ;; poke it with an invented token every 200 ms for well over one TTL
  (let poke ((i 0))
    (when (< i 6)
      (conversation-resume! kid "00000000deadbeef" 'noise)
      (sleep-ms 200)
      (poke (+ i 1))))
  ;; the park has run out: the conversation is gone, not still holding
  (let-values (((state token reply) (conversation-peek kid)))
    (unless (eq? state 'gone)
      (fail "a parked conversation was kept alive by repeated pokes" state)))
  (display "repeated stale requests do not extend the park ok\n"))

;; ---- peek: settling the question after 'unreachable ---------------------
;;
;; 'unreachable is not a rollback guarantee and never can be -- a broken
;; link says nothing about the process behind it. A caller left holding
;; that answer had no way to settle the question, and the one thing it must
;; not do is resubmit, which is how a flow's effects get applied twice.
;;
;; peek answers without advancing anything: what is it waiting for, and
;; what did it last say.
(let-values (((pid ptok pfirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (vector 'final a)))
                'go
                5000)))
  ;; parked: peek reports the token that continues it, and the reply it is
  ;; waiting to have answered
  (let-values (((state token reply) (conversation-peek pid)))
    (unless (eq? state 'parked) (fail "peek-parked-state" state))
    (unless (equal? token ptok) (fail "peek-parked-token" token))
    (unless (equal? reply (vector 'parked 'go)) (fail "peek-parked-reply" reply)))
  ;; ...and it did NOT advance: the token still works
  (let-values (((r st) (conversation-resume! pid ptok 'X)))
    (unless (equal? r (vector 'final 'X)) (fail "peek-advanced-the-flow" r))
    (unless (conversation-done? st) (fail "peek-final-status" st)))
  ;; completed: peek reports the final answer, still inside the linger
  (let-values (((state token reply) (conversation-peek pid)))
    (unless (eq? state 'completed) (fail "peek-completed-state" state))
    (unless (eq? token #f) (fail "peek-completed-token" token))
    (unless (equal? reply (vector 'final 'X)) (fail "peek-completed-reply" reply)))
  (display "peek reports parked / completed without advancing ok\n"))

;; An id nobody knows is an ANSWER, not an error -- and the answer is
;; 'unknown. This node cannot tell a fabricated id from a real one whose
;; record it has forgotten, and 'gone would claim it could.
(let-values (((state token reply) (conversation-peek "deadbeef")))
  (unless (eq? state 'unknown) (fail "peek-unknown-id" state)))
(display "peek on an id this node cannot speak for -> unknown ok\n")

;; ---- an application that kept its own record answers for itself --------
;;
;; 'unknown is honest and useless on its own. The construction that does
;; better is the one payment systems already use: write the conversation id
;; in the SAME transaction as the effect, so the truth is durable and
;; atomic with the thing it describes. The optional predicate is where the
;; library asks. A predicate that fails must leave 'unknown standing --
;; turning "I cannot say" into a confident wrong answer is the failure this
;; whole change exists to remove.
(let ((forgotten "1-00112233445566778899aabbccddeeff"))
  (let-values (((state token reply)
                (conversation-peek forgotten (lambda (id) #t))))
    (unless (conversation-settled? state)
      (fail "a durable record of completion was not believed" state)))
  (let-values (((state token reply)
                (conversation-peek forgotten (lambda (id) #f))))
    (unless (conversation-gone? state)
      (fail "a durable record of NON-completion was not believed" state)))
  (let-values (((state token reply)
                (conversation-peek forgotten (lambda (id) (raise 'db-down)))))
    (unless (conversation-unknown? state)
      (fail "a failing predicate did not leave unknown standing" state)))
  (let-values (((state token reply)
                (conversation-peek forgotten (lambda (id) 'no-idea))))
    (unless (conversation-unknown? state)
      (fail "an inconclusive predicate did not leave unknown standing" state)))
  (display "a durable completion record answers what the node cannot ok\n"))

;; and it is consulted ONLY for 'unknown: a status the node can stand
;; behind is never second-guessed by application code
(let ((asked (box 0)))
  (let-values (((gid gtok gfirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (suspend! (vector 'parked req))
                    (raise 'boom))
                  'go
                  300)))
    (let-values (((r st) (conversation-resume! gid gtok 'confirm
                                               (lambda (id)
                                                 (set-box! asked (+ 1 (unbox asked)))
                                                 #t))))
      (unless (conversation-gone? st) (fail "died-not-gone-with-predicate" st))
      (unless (= 0 (unbox asked))
        (fail "the predicate was consulted for a status the node knows"
              (unbox asked))))
    (display "the predicate is asked only where the node cannot say ok\n")))

;; ...but 'gone must NOT collapse into 'unknown. A conversation whose id
;; this node minted, in this incarnation, inside the retention window, and
;; which left no completion record, really did not complete: the record
;; would still be here if it had. That is the case 'gone exists for, and
;; the change above must not have swallowed it.
(let-values (((gid gtok gfirst)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (suspend! (vector 'parked req))
                  (raise 'boom))                   ; dies without completing
                'go
                300)))
  (let-values (((r st) (conversation-resume! gid gtok 'confirm)))
    (when (conversation-unknown? st)
      (fail "a conversation this node can speak for was reported unknown" st))
    (unless (conversation-gone? st) (fail "died-not-gone" st)))
  (display "an id minted here, inside the window, still says gone ok\n"))



;; The TTL must bound a RUNNING step, not only time parked in suspend!.
;; A step that runs long -- slow I/O, a wait that never returns, a CPU loop
;; -- leaves that receive entirely, and nothing else was counting: the
;; conversation could hold its transaction or reservation indefinitely. The
;; pool's stuck-killer does not cover it; that reaps the worker waiting for
;; the reply, while the conversation is its own process.
(let-values (((id tok first)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (sleep-ms 3000)          ; far past the TTL below
                    (vector 'should-not-get-here a)))
                'go
                300)))                       ; TTL 300 ms
  (let ((me self))
    (spawn (lambda ()
             (let-values (((r st) (conversation-resume! id tok 'X)))
               (send me (vector 'slow r)))))
    ;; the step overruns, so the watchdog must end the conversation rather
    ;; than let it run to completion
    (receive (after 6000 (fail "runaway-step" 'no-answer))
      (`#(slow ,v)
        (when (and (vector? v) (eq? (vector-ref v 0) 'should-not-get-here))
          (fail "runaway step ran to completion despite the TTL" v))
        (display "runaway step bounded by TTL ok\n")))))

;; ...and the key function is part of the step it belongs to. The key is
;; application code -- it can be slow, it can hang -- and it runs after
;; the step is already marked running. Restarting the clock when it
;; finishes would hand the step a second full TTL, which is how a bound
;; stops being a bound: any flow could double its allowance by keying its
;; requests slowly. Here neither half exceeds the TTL on its own and the
;; two together do, so only a step measured end to end is stopped.
(let-values (((id tok first)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (sleep-ms 300)              ; under the TTL by itself
                    (vector 'should-not-get-here a)))
                'go
                400                             ; TTL 400 ms
                (lambda (r) (sleep-ms 300) r)))) ; also under it by itself
  (let ((me self))
    (spawn (lambda ()
             (let-values (((r st) (conversation-resume! id tok 'X)))
               (send me (vector 'slowkey r)))))
    (receive (after 6000 (fail "slow-key-step" 'no-answer))
      (`#(slowkey ,v)
        (when (and (vector? v) (eq? (vector-ref v 0) 'should-not-get-here))
          (fail "the key function's time was refunded to the step" v))
        (display "a slow request key does not buy the step a second TTL ok\n")))))

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
(let-values (((id2 tok2 first2)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (sleep-ms 100)
                    (let ((b (suspend! (vector 'parked2 a))))
                      (sleep-ms 600)          ; well inside the 1000 ms TTL
                      (vector 'finished b))))
                'go
                1000)))
  (let ((me self))
    (sleep-ms 800)                            ; still parked, still alive
    ;; each resume answers the reply it was handed, so the token comes from
    ;; the previous round rather than being guessed
    (let-values (((r2 tok3) (conversation-resume! id2 tok2 'X)))
      (sleep-ms 900)                          ; just past a sampling point
      (spawn (lambda ()
               (let-values (((r st) (conversation-resume! id2 tok3 'Y)))
                 (send me (vector 'phase r))))))
    (receive (after 8000 (fail "phase-step" 'no-answer))
      (`#(phase ,v)
        (if (and (vector? v) (eq? (vector-ref v 0) 'finished))
            (display "a step gets its whole TTL whatever the sampling phase ok\n")
            (fail "a step well inside the TTL was cut short by sampling phase" v))))))

;; ---- a commit the library WITNESSED is never reported rolled back -------
;;
;; The one shape dynamic-wind cannot let the library distinguish from
;; outside: the body has run its COMMIT and is returning, and the
;; after-thunk raises on the way out. That raise leaves the flow exactly
;; like a rollback does, and the guard used to record it as 'rolled-back --
;; so the caller was told 'gone, the one answer documented as "safe to
;; retry", and retried a committed transaction. commit! exists so the
;; library can witness the commit itself: the thunk returned, so the
;; record says the transaction may have landed and the answer is 'unknown.
(let ((committed (box 0)))
  (let-values (((id tok first)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (dynamic-wind
                        (lambda () (void))
                        (lambda ()
                          (commit! (lambda ()
                                     (set-box! committed
                                               (+ 1 (unbox committed)))))
                          (vector 'committed a))
                        (lambda () (raise 'cleanup-raised)))))
                  'go
                  3000)))
    (let ((me self))
      (spawn (lambda ()
               (let-values (((r st)
                             (guard (e (#t (values 'raised 'raised)))
                               (conversation-resume! id tok 'go))))
                 (send me (vector 'cw r st)))))
      (receive (after 6000 (fail "commit-then-raise never answered" 'no-answer))
        (`#(cw ,r ,st)
          (unless (= 1 (unbox committed))
            (fail "the commit! thunk never ran" (unbox committed)))
          (when (eq? st 'gone)
            (fail "a commit the library witnessed was reported rolled back" st))
          (unless (eq? st 'unknown)
            (fail "commit-then-raise got the wrong status" st))
          (display "a raise after commit! answers 'unknown, not 'gone ok\n"))))
    ;; ...and the classification is DURABLE: a reconciler asking later --
    ;; off the tombstone, not off a parked resume -- gets the same answer,
    ;; not a rollback record that was merely overridden once.
    (let-values (((st tok2 reply) (conversation-peek id)))
      (unless (eq? st 'unknown)
        (fail "the witnessed commit did not survive into the record" st))
      (display "a witnessed commit survives into the tombstone ok\n"))))

;; ...and the witness OUTRANKS the reconciliation predicate. A
;; caller-supplied settled? may turn 'unknown into 'gone off durable
;; absence -- built for records this node knows nothing about (killed,
;; aged out, never written). A committed-then-failed record is not
;; nothing: this node watched the commit! thunk return. A predicate
;; answering #f against that -- a lagging replica, a mismatched key -- is
;; contradicted evidence, and the answer stays 'unknown; #t still
;; upgrades to 'settled, and junk still leaves 'unknown standing.
(let-values (((id tok first)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (dynamic-wind
                      (lambda () (void))
                      (lambda ()
                        (commit! (lambda () 'tx))
                        (vector 'done a))
                      (lambda () (raise 'cleanup-raised)))))
                'go
                3000)))
  (let ((me self))
    (spawn (lambda ()
             (let-values (((r st)
                           (guard (e (#t (values 'raised 'raised)))
                             (conversation-resume! id tok 'go))))
               (send me (vector 'pw st)))))
    (receive (after 6000 (fail "the predicate-witness setup never answered"
                               'no-answer))
      (`#(pw ,st)
        (unless (eq? st 'unknown)
          (fail "the predicate-witness setup got the wrong status" st)))))
  ;; the flow is dead behind a committed-then-failed record; ask again
  ;; with a predicate of each shape
  (let-values (((r st) (conversation-resume! id tok 'again (lambda (i) #f))))
    (when (eq? st 'gone)
      (fail "a #f predicate overrode the local commit witness" st))
    (unless (eq? st 'unknown)
      (fail "witness-vs-#f got the wrong status" st)))
  (let-values (((r st) (conversation-resume! id tok 'again (lambda (i) #t))))
    (unless (eq? st 'settled)
      (fail "a #t predicate did not upgrade a witnessed commit" st)))
  (let-values (((r st) (conversation-resume! id tok 'again (lambda (i) 'maybe))))
    (unless (eq? st 'unknown)
      (fail "a non-boolean predicate disturbed a witnessed commit" st)))
  (display "the commit witness outranks a #f reconciliation predicate ok\n"))

;; ...and a commit! whose thunk RAISES marked nothing. The transaction
;; never happened -- the raise left the thunk before commit! could witness
;; a return -- so the flow's death through its winders is an ordinary
;; rollback, and 'gone (retry) is exactly right.
(let ((entered (box 0)))
  (let-values (((id tok first)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (commit! (lambda ()
                                 (set-box! entered (+ 1 (unbox entered)))
                                 (raise 'commit-refused)))
                      (vector 'unreachable a)))
                  'go
                  3000)))
    (let ((me self))
      (spawn (lambda ()
               (let-values (((r st)
                             (guard (e (#t (values 'raised 'raised)))
                               (conversation-resume! id tok 'go))))
                 (send me (vector 'cr st)))))
      (receive (after 6000 (fail "refused-commit never answered" 'no-answer))
        (`#(cr ,st)
          (unless (= 1 (unbox entered))
            (fail "the refused commit! thunk never ran" (unbox entered)))
          (unless (eq? st 'gone)
            (fail "a commit that never happened was not reported rolled back" st))
          (display "a commit! whose thunk raises still answers 'gone ok\n"))))))

;; ...and the witness is STICKY. A flow that committed in one round and
;; parked again is a conversation whose one logical transaction is already
;; permanent -- that is the contract: one conversation, one transaction,
;; nothing new opened after commit!. A raise in ANY later round leaves a
;; conversation that committed, and 'gone there would invite a retry that
;; performs the committed transaction again. Once the mark is set, every
;; later death answers 'unknown.
(let-values (((id tok first)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'round1 req))))
                    (commit! (lambda () 'first-tx))
                    (let ((b (suspend! (vector 'round2 a))))
                      (raise 'later-round-raise))))
                'go
                3000)))
  (let-values (((r2 tok2) (conversation-resume! id tok 'go)))
    (unless (and (vector? r2) (eq? (vector-ref r2 0) 'round2))
      (fail "the committed round did not park again" r2))
    (let ((me self))
      (spawn (lambda ()
               (let-values (((r st)
                             (guard (e (#t (values 'raised 'raised)))
                               (conversation-resume! id tok2 'go))))
                 (send me (vector 'rr st)))))
      (receive (after 6000 (fail "the later-round raise never answered" 'no-answer))
        (`#(rr ,st)
          (when (eq? st 'gone)
            (fail "a committed conversation's later raise was reported rolled back"
                  st))
          (unless (eq? st 'unknown)
            (fail "a raise after a committed round got the wrong status" st))
          (display "a raise in any round after a commit answers 'unknown ok\n"))))))

;; ...and commit! is transparent on the success path: it returns the
;; thunk's value, the flow returns its reply, and the record says settled.
(let-values (((id tok first)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (let ((a (suspend! (vector 'parked req))))
                    (vector 'done (commit! (lambda () 'tx-value)))))
                'go
                3000)))
  (let-values (((r st) (conversation-resume! id tok 'go)))
    (unless (and (vector? r) (eq? (vector-ref r 0) 'done)
                 (eq? (vector-ref r 1) 'tx-value))
      (fail "commit! did not return its thunk's value" r))
    (unless (conversation-done? st)
      (fail "a committed clean return did not settle" st))
    (display "commit! returns the thunk's value and the flow settles ok\n")))

;; ...and a flow that committed and then sat PARKED past its TTL is not
;; 'gone either. The expiry raise runs the flow's winders like any
;; rollback, but the transaction this conversation carried already
;; committed and the mark never clears, so the answer is 'unknown:
;; reconcile, do not redo.
(let ((committed (box 0)))
  (let-values (((id tok first)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'round1 req))))
                      (commit! (lambda ()
                                 (set-box! committed (+ 1 (unbox committed)))))
                      (let ((b (suspend! (vector 'round2 a))))
                        (vector 'unreachable b))))
                  'go
                  300)))
    (let-values (((r2 tok2) (conversation-resume! id tok 'go)))
      (unless (= 1 (unbox committed))
        (fail "the expiring flow never reached its commit" (unbox committed)))
      (unless (and (vector? r2) (eq? (vector-ref r2 0) 'round2))
        (fail "the committed flow did not park again" r2))
      (sleep-ms 700)                     ; the round-2 park expires; flow dies
      (let-values (((r st) (conversation-resume! id tok2 'go)))
        (when (eq? st 'gone)
          (fail "a committed conversation that expired was reported rolled back"
                st))
        (unless (eq? st 'unknown)
          (fail "commit-then-expiry got the wrong status" st))
        (display "a committed flow abandoned at a park answers 'unknown ok\n")))))

;; ---- the witness works on the INITIAL round too --------------------------
;;
;; Before the first suspend! nothing has been answered, so the starter's
;; classification is what decides between "retry" and "reconcile". A flow
;; whose commit! returned and whose after-thunk then raised must surface
;; as conversation-uncertain -- the retryable conversation-failed there is
;; how a worker pool re-runs a committed transaction.
(let ((committed (box 0)))
  (let ((outcome
         (guard (e (#t e))
           (conversation-start!
             (lambda (req suspend! commit!)
               (dynamic-wind
                 (lambda () (void))
                 (lambda ()
                   (commit! (lambda ()
                              (set-box! committed (+ 1 (unbox committed)))))
                   (vector 'never-published req))
                 (lambda () (raise 'initial-cleanup-raised))))
             'go
             3000))))
    (unless (= 1 (unbox committed))
      (fail "the initial commit! thunk never ran" (unbox committed)))
    (unless (and (vector? outcome)
                 (eq? (vector-ref outcome 0) 'conversation-uncertain))
      (fail "an initial commit-then-raise was raised as retryable" outcome))
    (unless (and (> (vector-length outcome) 2)
                 (eq? (vector-ref outcome 2) 'unknown))
      (fail "the initial uncertain raise carried the wrong outcome" outcome))
    (display "an initial commit-then-raise is uncertain, not retryable ok\n")))

;; ...and an initial round that commits and returns cleanly needs no
;; suspension for commit! to work.
(let-values (((id st reply)
              (conversation-start!
                (lambda (req suspend! commit!)
                  (vector 'done (commit! (lambda () 'initial-tx))))
                'go
                3000)))
  (unless (conversation-done? st)
    (fail "an initial clean commit did not settle" st))
  (unless (and (vector? reply) (eq? (vector-ref reply 1) 'initial-tx))
    (fail "the initial commit! lost its thunk's value" reply))
  (display "an initial-round commit! settles without a suspension ok\n"))

;; ---- one conversation's witness is not another's -------------------------
;;
;; Two conversations in flight: A commits and parks again; B never
;; commits and is abandoned. B's expiry must read B's mark, not A's --
;; a witness kept anywhere but per-conversation state answers 'unknown
;; for B, and 'unknown where 'gone was earned surrenders the retry.
(let ((a-committed (box 0)))
  (let-values (((aid atok afirst)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'a-round1 req))))
                      (commit! (lambda ()
                                 (set-box! a-committed
                                           (+ 1 (unbox a-committed)))))
                      (let ((b (suspend! (vector 'a-round2 a))))
                        (vector 'unreachable b))))
                  'go
                  600)))
    (let-values (((bid btok bfirst)
                  (conversation-start!
                    (lambda (req suspend! commit!)
                      (let ((a (suspend! (vector 'b-round1 req))))
                        (vector 'unreachable a)))
                    'go
                    400)))
      ;; A commits while B is parked, then both are abandoned
      (let-values (((ar atok2) (conversation-resume! aid atok 'go)))
        (unless (= 1 (unbox a-committed))
          (fail "conversation A never reached its commit" (unbox a-committed)))
        (sleep-ms 1300)                  ; both parks expire; both flows die
        (let-values (((br bst) (conversation-resume! bid btok 'go)))
          (unless (eq? bst 'gone)
            (fail "an uncommitted conversation borrowed another's witness" bst)))
        (let-values (((ar2 ast) (conversation-resume! aid atok2 'go)))
          (unless (eq? ast 'unknown)
            (fail "a committed conversation lost its witness to another" ast)))
        (display "the commit witness is per conversation ok\n")))))

;; ...and a message that does not ADVANCE the flow does not touch the
;; witness either. Nothing clears the mark, and a stale token in
;; particular must not: it answers 'stale without waking the flow, and a
;; replayed request must never talk a committed conversation back into
;; 'gone.
(let ((committed (box 0)))
  (let-values (((id tok first)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'round1 req))))
                      (commit! (lambda ()
                                 (set-box! committed (+ 1 (unbox committed)))))
                      (let ((b (suspend! (vector 'round2 a))))
                        (vector 'unreachable b))))
                  'go
                  400)))
    (let-values (((r2 tok2) (conversation-resume! id tok 'go)))
      (unless (= 1 (unbox committed))
        (fail "the stale-probe flow never reached its commit" (unbox committed)))
      ;; a token this conversation never issued: answered 'stale, no round
      ;; starts, the witness must survive it
      (let-values (((sr sst) (conversation-resume! id (gensym "bogus") 'poke)))
        (unless (conversation-stale? sst)
          (fail "a bogus token was not answered stale" sst)))
      (sleep-ms 900)                     ; the round-2 park expires; flow dies
      (let-values (((r st) (conversation-resume! id tok2 'go)))
        (unless (eq? st 'unknown)
          (fail "a stale probe erased the commit witness" st))
        (display "a stale token does not touch the commit witness ok\n")))))

;; ---- the on-killed hook is told whether the flow had committed -----------
;;
;; on-killed does two jobs: it releases what the dead flow held in
;; process (a handle, a reservation), and it compensates the flow's
;; effect. After commit! has returned those jobs part ways -- the handle
;; must still be given back, but compensating would undo a transaction
;; that is permanent. The library cannot run half a hook, so it passes
;; the witness in and the application branches: release unconditionally,
;; compensate only when nothing committed.
(let ((held (box 100))
      (seen (box 'unset))
      (compensated (box #f)))
  (let-values (((id tok first)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (dynamic-wind
                        (lambda () (void))
                        (lambda ()
                          (commit! (lambda () 'tx))
                          (vector 'done a))
                        ;; wedges AFTER the commit: the watchdog is what
                        ;; ends this flow, with the mark already set
                        (lambda () (receive (after 60000 'never))))))
                  'go
                  300
                  values
                  (lambda (committed?)
                    (set-box! seen committed?)
                    (set-box! held 0)                 ; the handle: always
                    (unless committed?
                      (set-box! compensated #t))))))  ; the effect: only if not
    (let ((me self))
      (spawn (lambda ()
               (let-values (((r st)
                             (guard (e (#t (values 'raised 'raised)))
                               (conversation-resume! id tok 'go))))
                 (send me (vector 'ck st)))))
      (receive (after 6000 (fail "the committed-kill flow never answered"
                                 'no-answer))
        (`#(ck ,st)
          (unless (eq? st 'unknown)
            (fail "a flow killed after its commit got the wrong status" st)))))
    (sleep-ms 400)
    (unless (eq? #t (unbox seen))
      (fail "the hook was not told the flow had committed" (unbox seen)))
    (unless (= 0 (unbox held))
      (fail "a committed kill still leaked its in-process hold" (unbox held)))
    (when (unbox compensated)
      (fail "a committed effect was compensated away" (unbox compensated)))
    (display "on-killed is told about a witnessed commit ok\n")))

;; ...and a hook that cannot receive the witness is refused where it is
;; written. The watchdog swallows whatever on-killed raises -- it has to
;; survive a bad hook -- so a zero-argument hook would not blow up there:
;; it would silently never run. No release, no compensation, and no
;; message saying why. The arity is checked at conversation-start!
;; instead, in the caller that wrote the hook, like the ttl is.
(let ((outcome (guard (e (#t
                          ;; the RIGHT refusal, not just any raise: an
                          ;; assertion-violation attributed to
                          ;; conversation-start!, where the hook was written
                          (if (and (assertion-violation? e)
                                   (who-condition? e)
                                   (eq? (condition-who e)
                                        'conversation-start!))
                              'refused
                              (list 'wrong-raise e))))
                 (conversation-start!
                   (lambda (req suspend! commit!) (vector 'done req))
                   'go
                   300
                   values
                   (lambda () 'legacy-zero-arg))
                 'accepted)))
  (unless (eq? outcome 'refused)
    (fail "a zero-argument on-killed hook was not refused at start" outcome))
  (display "a zero-argument on-killed hook is refused at start ok\n"))

;; ---- a hook that fails does not fail silently ---------------------------
;;
;; on-killed is the last chance to give back what a killed flow held, and
;; it is application code called from the watchdog. Its two failures used
;; to leave nothing behind: a raise was swallowed by the guard that keeps
;; a bad hook from taking the watchdog with it, and a hook that blocked
;; kept the watchdog inside it forever -- never reaching its loop, never
;; finishing, one green process leaked per occurrence.
;; A HOOK THAT RAISES THE SAME REASON A RETURN PRODUCES. The runtime uses
;; whatever was raised as the exit reason, so a hook raising 'normal dies
;; with exactly the reason a clean return gives -- and an implementation
;; reading DOWN without tagging first records it as a success. This is the
;; case that looks like it works.
(let ((base (conversation-hook-stats)))
  (let-values (((id tok first)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (sleep-ms 5000)                 ; overruns, gets killed
                      (vector 'unreachable a)))
                  'go
                  200
                  values
                  (lambda (committed?) (raise 'normal)))))
    (let ((me self))
      (spawn (lambda ()
               (let-values (((r st)
                             (guard (e (#t (values 'raised 'raised)))
                               (conversation-resume! id tok 'go))))
                 (send me (vector 'hk st)))))
      (receive (after 6000 (fail "raising-hook-no-answer" 'timeout))
        (`#(hk ,st) 'ok)))
    (sleep-ms 500)
    (let ((now (conversation-hook-stats)))
      (unless (= (+ 1 (stat 'attempted base)) (stat 'attempted now))
        (fail "the hook was not attempted" now))
      (unless (= (+ 1 (stat 'raised base)) (stat 'raised now))
        (fail "a hook that raised was not counted as raised" now))
      (unless (= (stat 'succeeded base) (stat 'succeeded now))
        (fail "a hook that raised was counted as a success" now))
      (let ((f (stat 'last-failure now)))
        (unless (and (vector? f) (eq? (vector-ref f 0) 'conversation-hook-failure))
          (fail "no failure record was kept" f))
        (unless (equal? (vector-ref f 1) id)
          (fail "the failure record does not name the conversation" f))
        (unless (eq? (vector-ref f 2) 'raised)
          (fail "the failure was not classified as a raise" f)))
      (display "a hook raising the reason a return produces is still a failure ok\n"))))

;; ...AND A HOOK THAT BLOCKS DOES NOT KEEP THE WATCHDOG. The observation
;; that matters is not the counter -- it is that the processes go away.
;; Before this, the watchdog sat inside the hook forever; the count of
;; live green processes never came back down.
(let ((base (conversation-hook-stats))
      (procs-before (process-count)))
  (let-values (((id tok first)
                (conversation-start!
                  (lambda (req suspend! commit!)
                    (let ((a (suspend! (vector 'parked req))))
                      (sleep-ms 5000)
                      (vector 'unreachable a)))
                  'go
                  200
                  values
                  (lambda (committed?) (sleep-ms 600000)))))   ; never returns
    (let ((me self))
      (spawn (lambda ()
               (let-values (((r st)
                             (guard (e (#t (values 'raised 'raised)))
                               (conversation-resume! id tok 'go))))
                 (send me (vector 'hk st)))))
      (receive (after 6000 (fail "blocking-hook-no-answer" 'timeout))
        (`#(hk ,st) 'ok)))
    ;; the hook's allowance is the conversation's own ttl, so this is well
    ;; past it
    (sleep-ms 1500)
    (let ((now (conversation-hook-stats)))
      (unless (= (+ 1 (stat 'timed-out base)) (stat 'timed-out now))
        (fail "a hook that blocked was not counted as timed out" now))
      (unless (= 0 (stat 'running now))
        (fail "a timed-out hook is still counted as running" now)))
    (let settle ((tries 0))
      (cond ((<= (process-count) procs-before)
             (display "  [info] processes: ") (display procs-before)
             (display " -> ") (display (process-count)) (newline)
             (display "a hook that blocks is bounded and leaks no process ok\n"))
            ((> tries 20)
             (fail "a blocked hook left processes behind"
                   (list 'before procs-before 'after (process-count))))
            (else (sleep-ms 200) (settle (+ tries 1)))))))

(display "ALL CONVERSATION TESTS PASSED\n")
    (exit 0)))
