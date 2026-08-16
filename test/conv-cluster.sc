#!chezscheme
;;; (igropyr conversation) cluster test: two real OS processes.
;;;
;;; The conversation is created on node b (the owner). Node a receives
;;; only its id, so an ask from a must be forwarded to b over the mesh,
;;; run against the live continuation there, and the reply carried back.
;;; Most cases here drive the conversation from a, which forwards; the
;;; three that measure monitor tables have b drive its own, so that on a
;;; the only thing arming a monitor is the ask under test. Verifies:
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

;; A forwarded peek arms a monitor on the owner for as long as it waits,
;; so these counts are how a test tells "has got as far as arming" from
;; "has not run", and "reclaimed" from "leaked". They do not locate the
;; caller inside the call: arming happens before the request is even
;; sent, so a rise is a lower bound on progress, never a proof of where
;; it is waiting.
(define (mstat k) (cond ((assq k (node-monitor-stats)) => cdr) (else 0)))
(define (rmon) (mstat 'rmonitors))
(define (owner-agents) (mstat 'owner-agents))

;; The same counts on the OWNER. A monitor armed on b's router is hosted
;; by b, so this is where "the watcher's frame really crossed the link"
;; and "the hosted side was released too" can be read; node a's tables
;; say nothing about either.
;; The ref is an integer, not a gensym: an uninterned symbol does not
;; survive the codec as itself, so the reply would never match and the
;; wait would look like an owner that went quiet.
(define stats-ref 0)
(define (next-ref!) (set! stats-ref (+ stats-ref 1)) stats-ref)
(define (b-stat k)
  (let ((ref (next-ref!)))
    (register 'stats-probe self)
    (unless (rsend 'b 'ctrl (vector 'stats 'stats-probe ref))
      (fail! "could not ask the owner for its monitor stats"))
    (receive (after 5000 (fail! "the owner never reported its monitor stats"))
      (`#(stats ,@ref ,alist)
        (cond ((assq k alist) => cdr) (else 0))))))

;; Wait for a count to rise above a baseline. This answers "has it got
;; as far as arming", and it can only be read as "which of them armed"
;; because the cases that use it leave exactly one candidate: the busy
;; step is driven by the owner itself, which arms nothing here. With two
;; candidates no ordering of samples would recover the attribution -- a
;; count is a number, not a name.
(define (await-rise! what get base)
  (let loop ((n 0))
    (cond ((> (get) base) 'rose)
          ((> n 200)
           (fail! (string-append "nothing armed a monitor for: " what)
                  (list 'base base 'now (get))))
          (else (sleep-ms 25) (loop (+ n 1))))))

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
    ;; This is the case that needs two real nodes: the asker is killed
    ;; during a forwarded peek at a conversation that is BUSY -- busy
    ;; because the owner says so from inside the step, and forwarded
    ;; because the owner is hosting the monitor the peek armed.
    (let ((slow (receive (after 10000 (fail! "slow-conv-timeout"))
                  (`#(conv-slow ,id ,tk) (cons id tk)))))
      ;; The owner drives its own conversation into the step and says so
      ;; from inside it, so this is a fact reported by the code under
      ;; observation rather than one inferred here. It also leaves the
      ;; asker as the ONLY thing that can arm a monitor on this node --
      ;; a forwarded resume would arm one too, and no amount of ordering
      ;; around a shared counter can then say which of them moved it.
      ;; ask for the step NOW, so the announcement below is about the
      ;; present. Left to start at the owner's convenience it would be
      ;; a message about a step that could already have run out by the
      ;; time this case read it -- and a case reading it late would be
      ;; testing a conversation that had gone idle again. (The request
      ;; itself arms nothing here: rsend is not a monitor.)
      (unless (rsend 'b 'drive-slow (vector 'drive))
        (fail! "could not ask the owner to start its busy step"))
      (receive (after 10000 (fail! "the owner never entered its busy step"))
        (`#(busy slow) 'ok))
      (let ((base (rmon)) (obase (owner-agents)) (cbase (b-stat 'callee-agents)))
        (let ((asker (spawn (lambda () (conversation-peek (car slow))))))
          ;; armed here, and hosted THERE: the second is what says the
          ;; asker's own frame crossed the link, and it is what makes the
          ;; reclaim below a statement about both ends rather than one.
          (await-rise! "the forwarded peek" rmon base)
          (await-rise! "the owner hosting the peek's monitor"
                       (lambda () (b-stat 'callee-agents)) cbase)
          (let ((armed (rmon)))
            ;; ...and its monitor is STILL armed -- which is mid-call,
            ;; not necessarily still waiting: a reply already matched but
            ;; not yet cleaned up looks the same. That is the strongest
            ;; statement these counts support, and it is the one this
            ;; case depends on, rather than a proxy for it.
            ;; "The process is alive" is very nearly the same statement
            ;; and is not it: a peek that has just been answered drops
            ;; its monitor on the way out and stays alive for a few more
            ;; instructions. If that one were used, the fall back to
            ;; baseline below could be the peek's own doing rather than
            ;; the kill's, and a reclaim that tested nothing would read
            ;; as green.
            (unless (> (rmon) base)
              (fail! "the peek answered on its own -- nothing was killed mid-wait"
                     (list 'base base 'now (rmon))))
            ;; Watch it, so that the kill is known to be what ended it.
            ;; A kill aimed at a process that had already gone is a
            ;; no-op, and its counts would fall back all the same.
            (let ((m (monitor asker)))
              (kill asker 'asker-died)
              (receive (after 5000 (fail! "the killed asker never reported DOWN"))
                (`#(DOWN ,@asker ,why)
                  (unless (eq? why 'asker-died)
                    (fail! "the asker ended for its own reasons, not the kill"
                           why)))))
            (let settle ((n 0))
              (let ((now (rmon)) (onow (owner-agents)))
                ;; EXACTLY back, not merely no higher: <= would also pass
                ;; if this asker's entry leaked while an unrelated monitor
                ;; happened to go at the same time. The agent that clears
                ;; the entry is checked with it -- an entry released by an
                ;; agent that stayed behind is the same leak one table
                ;; over. Neither check rules out an exactly-cancelling
                ;; pair of changes; what rules it out here is that nothing
                ;; else in this case is due to end while it settles.
                (cond ((and (= now base) (= onow obase))
                       ;; ...and the hosted half, which node a cannot see:
                       ;; the owner has to drop the monitor it was holding
                       ;; for the dead asker too, or the reclaim only
                       ;; happened on one side of the link.
                       (let host ((m 0))
                         (let ((cnow (b-stat 'callee-agents)))
                           (cond ((= cnow cbase) 'released-there-too)
                                 ((> m 30)
                                  (fail! "the owner still hosts the dead asker's monitor"
                                         (list 'callee-base cbase 'callee-now cnow)))
                                 (else (sleep-ms 100) (host (+ m 1))))))
                       (display "  [info] rmonitors ") (display base)
                       (display " -> ") (display armed) (display " -> ")
                       (display now)
                       (display " (owner-agents ") (display onow)
                       (display ", owner's callee-agents ") (display cbase)
                       (display ")\n"))
                      ((< now base)
                       ;; the opposite of the leak, and it must not be
                       ;; reported as one: something that was armed before
                       ;; this case started went away while we settled
                       (fail! "an unrelated monitor was released while settling"
                              (list 'base base 'armed armed 'now now)))
                      ((> n 50)
                       (fail! "a killed asker left its remote monitor behind"
                              (list 'base base 'armed armed 'now now
                                    'owner-base obase 'owner-now onow)))
                      (else (sleep-ms 100) (settle (+ n 1))))))))))
    (display "killing an asker mid-forwarded-peek reclaims its monitor ok\n")

    ;; ---- a stale remote-down does not decide anything -------------------
    ;;
    ;; A remote-down carries the exit reason of somebody else's process, or
    ;; is left over from an earlier call -- it has no ref, so nothing ties
    ;; it to this one. Ending the wait on it produced 'unreachable for an
    ;; owner that was answering: a router killed with 'noconnection, a
    ;; monitor armed while the link happened to be down, a leftover from
    ;; the previous forward. The rule is now about the link itself, so a
    ;; message like this can prompt a look and nothing more.
    ;;
    ;; Injected by hand here: forward-peek runs IN the asking process, and
    ;; the real one is sent to the pid that armed the monitor -- the same
    ;; process, matched by the same receive clause. What the injection
    ;; does NOT reproduce is the state change that precedes a real
    ;; delivery: fire-remote-down! removes the rmonitor and stops the
    ;; owner agent first, so this arrives with the monitor still armed.
    ;; That is the shape a LEFTOVER has, which is the shape under test.
    (let ((slow (receive (after 10000 (fail! "slow3-timeout"))
                  (`#(conv-slow3 ,id ,tk) (cons id tk)))))
      ;; ask for the step NOW, so the announcement below is about the
      ;; present. Left to start at the owner's convenience it would be
      ;; a message about a step that could already have run out by the
      ;; time this case read it -- and a case reading it late would be
      ;; testing a conversation that had gone idle again. (The request
      ;; itself arms nothing here: rsend is not a monitor.)
      (unless (rsend 'b 'drive-slow3 (vector 'drive))
        (fail! "could not ask the owner to start its busy step"))
      (receive (after 10000 (fail! "the owner never entered its busy step"))
        (`#(busy slow3) 'ok))
      (let* ((me self)
             (base (rmon))
             (cbase (b-stat 'callee-agents))
             (asker (spawn (lambda ()
                             (let-values (((st tk rp) (conversation-peek (car slow))))
                               (send me (vector 'asked st)))))))
        ;; The asker armed its monitor and the owner is hosting it, so
        ;; its frame crossed. That is as far as this can be established
        ;; from outside: nothing marks the moment a caller enters the
        ;; receive, so this rules out injecting into a process that never
        ;; ran -- which a fixed sleep does not -- without proving where
        ;; inside the call it now is.
        (await-rise! "the forwarded peek" rmon base)
        (await-rise! "the owner hosting the peek's monitor"
                     (lambda () (b-stat 'callee-agents)) cbase)
        ;; the shape the node layer would deliver, with a reason that says
        ;; nothing about this call
        (send asker (vector 'remote-down 'b 'igropyr-conv-router 'overload))
        (let ((answer (receive (after 20000 'wedged)
                        (`#(asked ,st) st))))
          ;; The wait must end with a REAL answer. Accepting the timeout
          ;; sentinel here would encode the failure as a pass: a wedged
          ;; asker -- the exact thing a wrong rule produces at the other
          ;; extreme -- would report green.
          (when (eq? answer 'wedged)
            (fail! "the peek never answered at all after a stale remote-down"))
          (when (eq? answer 'unreachable)
            (fail! "a stale remote-down ended a wait on a healthy link" answer))
          ;; conversation-peek's documented set, minus the two rejected
          ;; above. Naming it rather than accepting anything keeps a
          ;; garbage answer from reading as "not unreachable, so fine".
          (unless (memq answer '(parked completed settled gone unknown))
            (fail! "the peek answered outside its documented set" answer))
          (display "  [info] after a stale remote-down the peek answered: ")
          (display answer) (newline))))
    (display "a stale remote-down does not end a wait on a live link ok\n")

    ;; ---- a link that really drops ends a PARKED wait --------------------
    ;;
    ;; The rule has two halves -- a live link keeps the wait going, a dead
    ;; one ends it -- and only the first was covered. This is the second,
    ;; and reaching it takes more than dropping a link: the caller has to
    ;; be parked in the forwarded receive ALREADY, because that is the
    ;; only place the peer list is consulted.
    ;;
    ;; Cutting the link first does not get there, which is what the
    ;; earlier version of this case did. remove-peer! deletes the peer
    ;; before it announces node-down, so a caller that waits for the
    ;; announcement finds rsend's precheck already failing, and
    ;; forward-peek returns 'unreachable from its else branch without
    ;; entering the receive at all. That path is worth keeping -- it is
    ;; below -- but it predates this rule and cannot speak for it.
    ;;
    ;; What this pins is that a genuine drop ends a parked wait promptly.
    ;; It does NOT separate this rule from the reason-based one it
    ;; replaced: the synthesized remote-down carries 'noconnection, so
    ;; both answer 'unreachable here. The case that tells them apart is
    ;; the stale one above, where the reason lies and the link does not.
    (let ((slow2 (receive (after 10000 (fail! "slow2-timeout"))
                   (`#(conv-slow2 ,id ,tk) (cons id tk)))))
      ;; FIRST, send the owner's hung-child net away. It exits the owner
      ;; process, and an owner process that exits drops the link -- the
      ;; event this whole case is waiting for. While it is armed, a run
      ;; slow enough to reach its deadline would hand this case its
      ;; expected ending for the wrong reason and print ok. Sending quit
      ;; and checking that rsend succeeded does not close that: rsend
      ;; reports what it handed to a link that looked live, not what was
      ;; delivered, so the net could still fire on either side of it.
      (let ((ref (next-ref!)))
        (register 'stats-probe self)
        (unless (rsend 'b 'net (vector 'stand-down 'stats-probe ref))
          (fail! "could not ask the owner's safety net to stand down"))
        (receive (after 5000 (fail! "the owner's safety net never stood down"))
          (`#(net-down ,@ref) 'ok)))
      ;; ask for the step NOW, so the announcement below is about the
      ;; present. Left to start at the owner's convenience it would be
      ;; a message about a step that could already have run out by the
      ;; time this case read it -- and a case reading it late would be
      ;; testing a conversation that had gone idle again. (The request
      ;; itself arms nothing here: rsend is not a monitor.)
      (unless (rsend 'b 'drive-slow2 (vector 'drive))
        (fail! "could not ask the owner to start its busy step"))
      (receive (after 10000 (fail! "the owner never entered its busy step"))
        (`#(busy slow2) 'ok))
      (let* ((me self)
             (base (rmon))
             (cbase (b-stat 'callee-agents))
             (asker (spawn (lambda ()
                             (let-values (((st tk rp)
                                           (conversation-peek (car slow2))))
                               (send me (vector 'dropped st)))))))
        ;; How far the asker has got, established rather than assumed.
        ;; Its monitor is armed HERE...
        (await-rise! "the forwarded peek" rmon base)
        ;; ...and hosted THERE, which only happens once its own frame has
        ;; crossed a link that was still up. What remains unobservable is
        ;; the step between that frame and the request that follows it:
        ;; nothing outside the library marks the moment the caller enters
        ;; the receive. So this establishes that the asker ran and reached
        ;; the owner, not that the drop is guaranteed to find it waiting.
        ;; A schedule that preempted it in between would quietly demote
        ;; this to the precheck case below -- which answers 'unreachable
        ;; too. What shows the tested schedules do reach the clause is the
        ;; mutation: disabling it leaves this case hanging.
        (await-rise! "the owner hosting the peek's monitor"
                     (lambda () (b-stat 'callee-agents)) cbase)
        (let ((t0 (now-ms)))
          ;; and it has to be THIS that drops the link. What makes that
          ;; true is the stood-down net above, not this check: rsend
          ;; answers for what it handed to a link that looked live, never
          ;; for what arrived. It still catches the plain case of an
          ;; owner that has already gone.
          (unless (rsend 'b 'ctrl (vector 'quit))
            (fail! "the owner was already gone -- the drop is not this case's doing"))
          (receive (after 20000
                     (fail! "a parked peek never answered after the link dropped"))
            (`#(dropped ,st)
              (let ((elapsed (- (now-ms) t0)))
                (unless (eq? st 'unreachable)
                  (fail! "a parked peek did not end when its link dropped" st))
                ;; the point is the SPEED: sitting out conv-forward-ttl-ms
                ;; would also produce 'unreachable, and would be the bug
                (when (> elapsed 5000)
                  (fail! "the parked caller waited out the forwarding TTL"
                         elapsed))
                (display "  [info] a parked peek ended ") (display elapsed)
                (display "ms after the link dropped\n"))))))
      ;; ...and the other path, named for what it is: with the peer
      ;; already gone, rsend's precheck fails and the answer comes back
      ;; without any waiting at all. This predates the peer-list rule.
      (receive (after 10000 (fail! "owner-never-went-down")) (`#(node-down b) 'ok))
      (let ((t0 (now-ms)))
        (let-values (((st tk rp) (conversation-peek (car slow2))))
          (let ((elapsed (- (now-ms) t0)))
            (unless (eq? st 'unreachable)
              (fail! "a peek with no link did not answer unreachable" st))
            (when (> elapsed 5000)
              (fail! "the precheck did not fail fast" elapsed))
            (display "  [info] peek with no link answered in ")
            (display elapsed) (display "ms (rsend precheck)\n")))))
    (display "a dropped link ends a parked forwarded wait ok\n")

    (sleep-ms 200)
    (display "ALL CONV-CLUSTER TESTS PASSED\n")
    (exit 0)))
