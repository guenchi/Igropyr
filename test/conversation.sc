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
                (lambda (req suspend!)
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
                (lambda (req suspend!)
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
       (release! (lambda ()
                   (unless (unbox released)
                     (set-box! released #t)
                     (set-box! held (- (unbox held) 100))))))
  (let-values (((kid ktok kfirst)
                (conversation-start!
                  (lambda (req suspend!)
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
                  ;; it closed over, not through the dead stack
                  release!)))
    (let ((me self))
      (spawn (lambda ()
               (let-values (((r st) (conversation-resume! kid ktok 'go)))
                 (send me (vector 'k r)))))
      (receive (after 6000 (fail "killed-step" 'no-answer)) (`#(k ,v) 'ok))))
  (sleep-ms 400)
  (unless (= 0 (unbox held))
    (fail "a killed step leaked its in-process hold" (unbox held)))
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
                  (lambda (req suspend!)
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
      (receive (after 4000 (fail "a caller waited forever on a wedged cleanup" bid))
        (`#(answered ,st)
          (if (or (conversation-gone? st) (conversation-settled? st)
                  (conversation-stale? st))
              (display "a wedged cleanup is killed and the caller is answered ok\n")
              (fail "a wedged cleanup left the caller with a live conversation" st)))))))

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
                  (lambda (req suspend!)
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
                (lambda (req suspend!)
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
                (lambda (req suspend!)
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

;; MUST RUN BEFORE ANY RECORD IS PRUNED. What it pins is the horizon's
;; STARTING value -- process start -- and the moment a prune discards
;; anything the horizon moves up to that entry's age, which would answer
;; this case for the wrong reason.
;; An id from BEFORE this incarnation is outside what this process can
;; speak for. A restart erases the completion records but not the ids the
;; clients are holding, and answering 'gone for those is the same lie the
;; expiry case makes: the transaction may well have committed just before
;; the restart. The horizon starts at process start, so this is free --
;; the id below is well-formed and simply older than this process.
(let ((ancient "1-00112233445566778899aabbccddeeff"))   ; no node prefix: this test runs single-node
  (let-values (((state token reply) (conversation-peek ancient)))
    (unless (conversation-unknown? state)
      (fail "an id older than this process was not reported unknown" state)))
  (display "an id older than this incarnation -> unknown ok\n"))

;; The record is bounded, and past its age this node stops being able to
;; speak for the conversation at all. It used to answer 'gone there --
;; which this library documents as "the transaction rolled back" -- for a
;; conversation that had COMMITTED and whose only evidence it had just
;; discarded. The honest answer is 'unknown: not here, and no longer
;; knowable from here.
(let-values (((eid etok efirst)
              (conversation-start!
                (lambda (req suspend!)
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
                (lambda (req suspend!)
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
                (lambda (req suspend!)
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
                  (lambda (req suspend!)
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
                (lambda (req suspend!)
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
                (lambda (req suspend!)
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
                (lambda (req suspend!)
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

(display "ALL CONVERSATION TESTS PASSED\n")
    (exit 0)))
