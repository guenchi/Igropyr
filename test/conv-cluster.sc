#!chezscheme
;;; (igropyr conversation) cluster test: two real OS processes.
;;;
;;; The conversation is created on node b (the owner). Node a receives
;;; only its id and drives every resume -- so each resume must be
;;; forwarded to b over the mesh, run against the live continuation
;;; there, and the reply carried back. Verifies:
;;;   - forwarded resume round-trips (ack sums accumulate correctly)
;;;   - the final reply crosses back
;;;   - a completed conversation still answers across the link: its final
;;;     reply replays, an invented token is 'stale. (Nothing here expects
;;;     'gone, and nothing here can produce it: 'gone is a record saying
;;;     the flow rolled back, and every flow in this file completes.)
;;;   - resuming an id whose owner node is unknown returns 'unreachable

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation)
        (only (igropyr libuv) now-ms))

(define port 18093)
(define secret "conv-mesh-secret")

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

(define (spawn-child!)
  (system (string-append
            "scheme --script igropyr/test/conv-cluster-child.sc b "
            (number->string port) " " secret " &")))

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (register 'main self)
    (monitor-node 'b)

    ;; An id whose owner node we never heard of answers 'unreachable, not
    ;; 'gone. We have no evidence about a node we cannot contact, and 'gone
    ;; is a GUARANTEE that the transaction rolled back -- claiming it here
    ;; would invite a retry that duplicates a flow still running elsewhere.
    (let-values (((r st) (conversation-resume! "nowhere~deadbeef" "deadbeef" 1)))
      (unless (eq? 'unreachable st)
        (fail! "unknown-owner-should-be-unreachable" st)))
    (display "resume to unknown owner -> unreachable ok\n")

    (spawn-child!)
    (receive (after 10000 (fail! "node-up-timeout")) (`#(node-up b) 'ok))
    (display "handshake ok\n")

    (let* ((got (receive (after 10000 (fail! "conv-id-timeout"))
                  (`#(conv-id ,id ,tk ,fr) (list id tk fr))))
           (id (car got))
           (tok0 (cadr got))
           (fr (caddr got)))
      (unless (equal? fr (vector 'ack 0)) (fail! "first-reply" fr))
      ;; the id must actually carry b as its owner, else this proves nothing
      (unless (eq? 'b (string->symbol
                        (let ((s id))
                          (substring s 0 (let loop ((i 0))
                                           (if (char=? (string-ref s i) #\~) i (loop (+ i 1))))))))
        (fail! "id-not-owned-by-b" id))
      (display "forwarded conversation created, owner=b ok\n")

      ;; peek crosses the link too, with the same failure semantics: an
      ;; owner we cannot reach is 'unreachable, never 'gone. This is the
      ;; call a caller makes AFTER an 'unreachable resume, once the link is
      ;; back, instead of resubmitting.
      (let-values (((st tk rp) (conversation-peek id)))
        (unless (eq? st 'parked) (fail! "cross-node-peek-state" st))
        (unless (equal? tk tok0) (fail! "cross-node-peek-token" tk))
        (unless (equal? rp (vector 'ack 0)) (fail! "cross-node-peek-reply" rp)))
      (display "peek across the link reports the parked step ok\n")

      ;; an owner node we never heard of is unreachable, not gone
      (let-values (((st tk rp) (conversation-peek "nowhere~deadbeef")))
        (unless (eq? st 'unreachable) (fail! "peek-unknown-owner" st)))
      (display "peek to an unknown owner -> unreachable ok\n")

      ;; each round answers the reply it was handed, and the next token
      ;; comes back over the link with it
      (let-values (((r t1) (conversation-resume! id tok0 5)))
        (unless (equal? r (vector 'ack 5)) (fail! "resume-1" r))
        (let-values (((r2 t2) (conversation-resume! id t1 10)))
          (unless (equal? r2 (vector 'ack 15)) (fail! "resume-2" r2))
          (display "cross-node resume round-trips ok\n")

          ;; A token already spent REPLAYS across the link too -- and this
          ;; is where a duplicate is most likely, because the network
          ;; carrying the forward is exactly what delays it. The answer
          ;; must be the one that token produced, not a second run: here
          ;; that means (ack 15) again rather than (ack 25).
          (let-values (((rs ts) (conversation-resume! id t1 10)))
            (unless (equal? rs (vector 'ack 15)) (fail! "cross-node-replay" rs))
            (unless (equal? ts t2) (fail! "cross-node-replay-token" ts)))
          (display "a spent token replays across the link ok\n")

          ;; an invented one is still refused
          (let-values (((rw tw) (conversation-resume! id "00000000deadbeef" 10)))
            (unless (eq? tw 'stale) (fail! "cross-node-invented" tw)))
          (display "an invented token is refused across the link ok\n")

          (let-values (((r3 t3) (conversation-resume! id t2 'done)))
            (unless (equal? r3 (vector 'final 15)) (fail! "resume-final" r3))
            (display "cross-node final reply ok\n")

            ;; the conversation LINGERS after completing, so within that
            ;; window it can still tell an invented token apart from a
            ;; repeat -- which is the whole point of lingering: a client
            ;; whose final reply was lost gets it back rather than 'gone
            (let-values (((r4 t4) (conversation-resume! id "00000000deadbeef" 99)))
              (unless (eq? t4 'stale) (fail! "resume-after-done" t4)))
            (display "an invented token after completion -> stale ok\n")

            (let-values (((r5 t5) (conversation-resume! id t2 'done)))
              (unless (equal? r5 (vector 'final 15))
                (fail! "final-replay-across-link" r5)))
            (display "the final reply replays across the link ok\n")))))

    ;; ---- the commit witness crosses the link -----------------------------
    ;;
    ;; The owner (b) holds a record saying committed-then-failed: its flow
    ;; committed through commit! and then raised. This node's settled?
    ;; predicate answers #f -- a lagging replica, a mismatched key. Locally
    ;; that #f cannot demote a witnessed commit to 'gone; before the
    ;; witness crossed the link, the SAME call forwarded to b answered
    ;; 'gone, and a retry of a committed transaction is what 'gone invites.
    (let ((wid (receive (after 10000 (fail! "witness-id-timeout"))
                 (`#(conv-witness ,id) id)
                 (`#(conv-witness-setup-failed ,r)
                   (fail! "witness-setup-on-owner" r)))))
      (let-values (((r st) (conversation-resume! wid "bogus" 'x
                                                 (lambda (i) #f))))
        (unless (eq? st 'unknown)
          (fail! "a #f predicate overrode the owner's commit witness" st)))
      ;; peek rides the same frames and takes the same protection
      (let-values (((st tok reply) (conversation-peek wid (lambda (i) #f))))
        (unless (eq? st 'unknown)
          (fail! "peek let the predicate override the owner's witness" st))))
    (display "a #f predicate cannot override the owner's commit witness ok\n")

    ;; ...and where the owner has NO record, the predicate's demotion is
    ;; legitimate and must keep working: an id shaped for b that b never
    ;; issued forwards, finds nothing, and the #f answer is the only
    ;; evidence there is.
    (let-values (((r st) (conversation-resume! "b~deadbeef" "bogus" 'x
                                               (lambda (i) #f))))
      (unless (eq? st 'gone)
        (fail! "an absent record no longer demotes across the link" st)))
    (display "no record on the owner still demotes to 'gone ok\n")

    ;; ...and an UNCERTAIN commit crosses differently from a confirmed
    ;; one, which is the whole reason the box has three states. Without a
    ;; predicate the answer is 'unknown -- possibly effective, never
    ;; 'gone. WITH an authoritative #f the demotion is legitimate: the
    ;; owner's evidence is "maybe", the predicate's is "no", and maybe
    ;; does not outrank no. (A single sticky box would have answered
    ;; 'unknown here too, silently disabling negative reconciliation.)
    (let ((uid (receive (after 10000 (fail! "uncertain-id-timeout"))
                 (`#(conv-uncertain ,id) id)
                 (`#(conv-uncertain-setup-failed ,r)
                   (fail! "uncertain-setup-on-owner" r)))))
      (let-values (((r st) (conversation-resume! uid "bogus" 'x)))
        (unless (eq? st 'unknown)
          (fail! "an uncertain commit did not answer unknown across the link" st)))
      (let-values (((r st) (conversation-resume! uid "bogus" 'x
                                                 (lambda (i) #f))))
        (unless (eq? st 'gone)
          (fail! "an authoritative #f could not resolve an uncertain commit" st))))
    (display "an uncertain commit answers unknown, and yields to an authoritative no ok\n")

    ;; ---- killing an asker mid-wait reclaims what it armed ---------------
    ;;
    ;; A forwarded peek registers a reply name and arms a remote monitor,
    ;; and puts its teardown in a dynamic-wind after-thunk -- which a kill
    ;; discards. The registered name survives that (kill reclaims a dead
    ;; process's aliases itself), but the monitor is the library's own
    ;; problem: watching a NODE left the dead process in a global list that
    ;; is only ever swept when that node next changes state, which on a
    ;; mesh that stays up is never. Watching the ROUTER instead gives the
    ;; monitor an owner agent that reclaims on DOWN -- the one teardown
    ;; that outlives a kill.
    ;;
    ;; This is the case that needs two real nodes: the asker parks in a
    ;; forwarded peek at a conversation that is BUSY, and is killed there.
    (let ((slow (receive (after 10000 (fail! "slow-conv-timeout"))
                  (`#(conv-slow ,id ,tk) (cons id tk)))))
      ;; drive it into its long step FROM ANOTHER PROCESS: this resume does
      ;; not return until that step ends, and waiting for it here would
      ;; mean peeking at a conversation that has already finished
      (spawn (lambda () (conversation-resume! (car slow) (cdr slow) 1)))
      (sleep-ms 500)
      (let ((base (cond ((assq 'rmonitors (node-monitor-stats)) => cdr) (else 0))))
        (let ((asker (spawn (lambda () (conversation-peek (car slow))))))
          (sleep-ms 400)                ; it is now parked in the forward
          (let ((armed (cond ((assq 'rmonitors (node-monitor-stats)) => cdr) (else 0))))
            ;; it really did arm one -- without this the reclaim below
            ;; would also "pass" if nothing had ever been armed
            (unless (> armed base)
              (fail! "the forwarded peek armed no monitor -- nothing was tested"
                     (list 'base base 'armed armed)))
            (kill asker 'asker-died)
            (let settle ((n 0))
              (let ((now (cond ((assq 'rmonitors (node-monitor-stats)) => cdr)
                               (else 0))))
                (cond ((<= now base)
                       (display "  [info] rmonitors ") (display base)
                       (display " -> ") (display armed) (display " -> ")
                       (display now) (newline))
                      ((> n 30)
                       (fail! "a killed asker left its remote monitor behind"
                              (list 'base base 'armed armed 'now now)))
                      (else (sleep-ms 100) (settle (+ n 1))))))))))
    (display "killing an asker parked in a forwarded peek reclaims its monitor ok\n")

    ;; ---- a link that really drops still ends the wait at once -----------
    ;;
    ;; What ends a forwarded wait is whether the link is up -- not what a
    ;; remote-down said, since a reason is somebody else's exit reason or a
    ;; stale broadcast. The other half of that rule has to hold too: when
    ;; the link is genuinely gone, the caller must not sit until the
    ;; forwarding TTL (five minutes) expires.
    (let ((slow-id (car (receive (after 10000 (fail! "slow2-timeout"))
                          (`#(conv-slow2 ,id ,tk) (cons id tk))))))
      (rsend 'b 'ctrl (vector 'quit))
      (receive (after 10000 (fail! "owner-never-went-down")) (`#(node-down b) 'ok))
      (let ((t0 (now-ms)))
        (let-values (((st tk rp) (conversation-peek slow-id)))
          (let ((elapsed (- (now-ms) t0)))
            (unless (eq? st 'unreachable)
              (fail! "a peek across a dropped link did not answer unreachable" st))
            ;; the point is the SPEED: waiting out conv-forward-ttl-ms would
            ;; also produce 'unreachable, and would be the bug
            (when (> elapsed 5000)
              (fail! "the caller waited out the forwarding TTL instead of
                      noticing the link" elapsed))
            (display "  [info] peek across a dropped link answered in ")
            (display elapsed) (display "ms\n")))))
    (display "a dropped link ends a forwarded wait at once ok\n")

    (sleep-ms 200)
    (display "ALL CONV-CLUSTER TESTS PASSED\n")
    (exit 0)))
