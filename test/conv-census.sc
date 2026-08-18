#!chezscheme
;;; Census and quiesce: the node can say what it is holding, and can stop
;;; taking new work without stranding the work it has.
;;;
;;; THE KILLER CASE IS THE ONE THAT LOOKS BACKWARDS. Quiesce gates ONE
;;; thing -- starting -- and the suite spends most of its assertions on
;;; what must KEEP WORKING under it: local resume and peek, a resume
;;; forwarded from another node, prepare!, abandon!, a linger replay, and
;;; a neighbour node's own starts. A quiesce that refuses any of those
;;; strands exactly the dialogues the drain is waiting for, so the node
;;; would never finish leaving.
;;;
;;; Census assertions are EXACT ALISTS, never single keys: a census that
;;; bumps everything on every event, or never counts a bucket, passes any
;;; one-key check. The running bucket gets its own case (both parked
;;; conversations were observed only after start! returned, so without it
;;; running=0-forever would pass). Drain is asserted in both halves:
;;; NOT-drained while a lingerer holds its name, drained only after.
;;;
;;; What a green run here does NOT prove, said plainly:
;;;   - that census PRUNES its table (an implementation that keeps stale
;;;     entries forever but skips them at read time answers identically;
;;;     deletion is not observable through this API);
;;;   - the two atomicity windows (quiesce-read vs claim, register vs
;;;     census-add) -- single-scheduler preemption cannot be aimed from a
;;;     test; those are held by the with-interrupts-disabled regions in
;;;     the source and checked by reading them.

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation))

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))

(define (fail label . info)
  (display "FAIL: ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))
(define (ok label) (display "  ok  ") (display label) (newline))

(define port 19791)
(define secret "census-secret")

(define repo (string-append (current-directory) "/igropyr"))
(define child (string-append repo "/test/conv-census-child.sc"))

(start-scheduler
  (lambda ()

    (define (ask cmd) (rsend 'b 'ctrl cmd))
    (define tag-counter 0)
    (define (fresh-tag)
      (set! tag-counter (+ tag-counter 1))
      tag-counter)
    (define (await tag timeout label)
      (receive (after timeout (fail label 'timeout tag))
        (`#(res ,@tag ,payload) payload)))
    (define (ask/wait cmd-of-tag timeout label)
      (let ((tag (fresh-tag)))
        (ask (cmd-of-tag tag))
        (await tag timeout label)))
    (define (census-is what label)
      (let ((c (conversation-census)))
        (unless (equal? c what) (fail label c 'wanted what))))
    (define (poll-census want label)
      (let poll ((k 0))
        (cond ((equal? (conversation-census) want) 'ok)
              ((> k 300) (fail label (conversation-census) 'wanted want))
              (else (sleep-ms 20) (poll (+ k 1))))))
    (define (census-of r p l)
      (list (cons 'running r) (cons 'parked p) (cons 'lingering l)
            (cons 'total (+ r p l))))
    (define (expect-quiescing-raise thunk label)
      (guard (e (#t (unless (and (vector? e)
                                 (= 2 (vector-length e))
                                 (eq? (vector-ref e 0) 'conversation-quiescing)
                                 (eq? (vector-ref e 1) 'a))
                      (fail label 'wrong-raise e))))
        (thunk)
        (fail label 'accepted)))

    ;; flows: gated (parks 'ready; 'block waits for #(go); 'done settles),
    ;; and a settle-flow whose whole life fits a short ttl so its linger
    ;; window is watchable inside a test run
    (define (gated-flow name)
      (lambda (req suspend! commit!)
        (register name self)
        (let loop ((r (suspend! 'ready)))
          (case r
            ((block) (receive (`#(go) 'ok))
                     (loop (suspend! 'unblocked)))
            ((done) (commit! (lambda () 'ok)) 'finished)
            (else (loop (suspend! (vector 'echo r))))))))
    (define (settle-flow req suspend! commit!)
      (let ((r (suspend! 'ready)))
        (commit! (lambda () 'ok))
        (vector 'final r)))

    ;; ---- an empty node: exact zeros, and quiesce defaults off ----------
    (node-start! 'a secret port)
    (register 'census-suite self)
    (census-is (census-of 0 0 0) "a fresh node's census is not exact zeros")
    (when (conversation-quiescing?)
      (fail "a fresh node claims to be quiescing"))
    (guard (e (#t 'ok))
      (conversation-quiesce! 'yes)
      (fail "a non-boolean quiesce argument was accepted"))
    ;; set, not toggle: repeating a value must not flip it
    (conversation-quiesce! #t)
    (conversation-quiesce! #t)
    (unless (conversation-quiescing?) (fail "double-set #t flipped the switch"))
    (conversation-quiesce! #f)
    (conversation-quiesce! #f)
    (when (conversation-quiescing?) (fail "double-set #f flipped the switch"))
    (ok "fresh census exact zeros; quiesce validates, defaults off, sets not toggles")

    ;; ---- child asker ----------------------------------------------------
    (system (string-append
              "cd " (current-directory) " && "
              "CHEZSCHEMELIBDIRS=. "
              "CHEZSCHEMELIBEXTS=\"" (or (getenv "CHEZSCHEMELIBEXTS") "") "\" "
              scheme-bin " --script " child " "
              (number->string port) " " secret
              " > /tmp/conv-census-child.log 2>&1 &"))
    (monitor-node 'b)
    (receive (after 15000 (fail "asker node never came up"))
      (`#(node-up b) 'ok))

    (let*-values (((id1 t1 r1) (conversation-start! (gated-flow 'g1) 'hi 120000))
                  ((id2 t2 r2) (conversation-start! (gated-flow 'g2) 'hi 120000)))
      (unless (and (eq? r1 'ready) (eq? r2 'ready))
        (fail "the gated flows did not park" r1 r2))
      (census-is (census-of 0 2 0) "two parked conversations miscounted")
      (ok "two parked conversations: exact (0 running, 2 parked)")

      ;; ---- the running bucket, on its own -------------------------------
      (let ((tagB (fresh-tag)))
        (ask (vector 'resume-async tagB id1 t1 'block 60000))
        (poll-census (census-of 1 1 0)
                     "a flow blocked mid-step never counted as running")
        (ok "a flow held mid-step counts as running, exactly one")
        (send (whereis 'g1) (vector 'go))
        (let ((rb (await tagB 15000 "the blocked resume never returned")))
          (unless (eq? (car rb) 'unblocked)
            (fail "the released block did not complete" rb))
          (set! t1 (cadr rb)))
        (census-is (census-of 0 2 0) "the released flow did not re-park"))

      ;; ---- quiesce on: the gate refuses, everything else keeps working --
      (let ((h-before (conversation-prepare! settle-flow 'hi 30000)))
        (conversation-quiesce! #t)
        (expect-quiescing-raise
          (lambda () (conversation-start! settle-flow 'hi 30000))
          "start! under quiesce")
        (expect-quiescing-raise
          (lambda () (conversation-run! h-before))
          "run! of a pre-quiesce handle")
        (census-is (census-of 0 2 0) "the refused starts left tracks in the census")
        ;; prepare has nothing to withhold; abandon must still work too
        (let ((h-during (conversation-prepare! settle-flow 'hi 30000)))
          (conversation-abandon! h-during))
        (ok "start! and run! refuse with the named vector; prepare/abandon still work")

        ;; the paths that must keep working, each with an exact answer.
        ;; Guarded so a gate grown too wide reds HERE, as the refusal it
        ;; is, instead of escaping as a crash three frames up
        (guard (e (#t (fail "a local resume RAISED under quiesce" e)))
          (let-values (((reply status) (conversation-resume! id1 t1 'poke)))
            (unless (equal? reply (vector 'echo 'poke))
              (fail "a local resume was disturbed by quiesce" reply status))
            (set! t1 status)))
        (let-values (((st tok last) (conversation-peek id1)))
          (unless (eq? st 'parked)
            (fail "a local peek was disturbed by quiesce" st)))
        (let-values (((st tok last) (conversation-peek/timeout id2 1000)))
          (unless (eq? st 'parked)
            (fail "a bounded local peek was disturbed by quiesce" st)))
        (let ((r (ask/wait (lambda (tag) (vector 'resume tag id2 t2 'poke 10000))
                           15000 "remote resume under quiesce")))
          (unless (equal? (car r) (vector 'echo 'poke))
            (fail "a forwarded resume was refused by a quiescing owner" r))
          (set! t2 (cadr r)))
        (let ((r (ask/wait (lambda (tag) (vector 'peek tag id2 10000))
                           15000 "remote peek under quiesce")))
          (unless (eq? (car r) 'parked)
            (fail "a forwarded peek was refused by a quiescing owner" r)))
        (ok "local and forwarded resume/peek all keep working under quiesce")

        ;; a quiescing owner past its cap still says 'overloaded -- the
        ;; two words stay apart, and admission is judged before quiesce
        ;; could ever matter
        (conv-set-forward-limit! 1)
        (let ((tagB (fresh-tag)))
          (ask (vector 'resume-async tagB id1 t1 'block 60000))
          (poll-census (census-of 1 1 0) "the occupying forward never landed")
          (let ((r (ask/wait (lambda (tag) (vector 'resume tag id2 t2 'poke 10000))
                             15000 "over-cap resume at a quiescing owner")))
            (unless (and (eq? (car r) #f) (eq? (cadr r) 'overloaded))
              (fail "a quiescing owner past cap answered something else" r)))
          (send (whereis 'g1) (vector 'go))
          (let ((rb (await tagB 15000 "the occupying forward never returned")))
            (set! t1 (cadr rb))))
        (conv-set-forward-limit! 256)
        (ok "a quiescing owner past its cap still answers 'overloaded")

        ;; the neighbour is its own node: quiescing a must not touch b
        (let ((r (ask/wait (lambda (tag) (vector 'start-own tag))
                           15000 "the neighbour's own start")))
          (unless (and (eq? (car r) 'ok) (equal? (cadr r) (vector 'own-final 7)))
            (fail "quiescing this node disturbed the neighbour's starts" r)))
        (census-is (census-of 0 2 0)
                   "the neighbour's conversation leaked into this census")
        (ok "a quiesced node's neighbour starts freely; censuses stay apart")

        ;; ---- reversible: off means on-duty again -------------------------
        (conversation-quiesce! #f)
        (let-values (((token reply) (conversation-run! h-before)))
          (unless (eq? reply 'ready)
            (fail "the pre-quiesce handle did not run after unquiesce" reply))
          ;; the SAME handle is consumed now: a second run must refuse as
          ;; already-claimed, proving the refusal never half-claimed it
          (guard (e (#t 'ok))
            (conversation-run! h-before)
            (fail "a consumed handle ran twice"))
          (census-is (census-of 0 3 0) "the revived handle's flow miscounted")
          (ok "quiesce off: the refused handle runs exactly once")

          ;; finish it and watch the linger window from both sides
          (let ((id3 (conversation-ref-id h-before)))
            (let-values (((reply2 status2) (conversation-resume! id3 token 5)))
              (unless (equal? reply2 (vector 'final 5))
                (fail "the settle flow's final reply is wrong" reply2))
              (census-is (census-of 0 2 1)
                         "a just-settled conversation is not lingering")
              ;; replay DURING the linger, with quiesce back on: the very
              ;; window that exists for retries must not be gated
              (conversation-quiesce! #t)
              (let-values (((reply3 status3) (conversation-resume! id3 token 5)))
                (unless (equal? reply3 (vector 'final 5))
                  (fail "the linger replay under quiesce broke" reply3 status3)))
              (ok "settled conversation lingers, and replays under quiesce")
              ;; not drained while it lingers -- this is the half a
              ;; too-eager drain check would skip
              (unless (and (conversation-quiescing?)
                           (> (cdr (assq 'total (conversation-census))) 2))
                (fail "the lingerer vanished from the drain's view"))
              ;; its ttl is 30s -- too long to watch here, so take the
              ;; operator's path: a lingerer holds only a replay window,
              ;; and killing it is the documented way to finish a drain
              ;; without waiting one out
              (kill (whereis (string->symbol
                               (string-append "igropyr-conv-" id3)))
                    'census-drain)
              (poll-census (census-of 0 2 0)
                           "a killed lingerer stayed in the census")
              ;; and past the window (here: past the process) the record
              ;; remains: settled, and never counted
              (let-values (((st tok last) (conversation-peek id3)))
                (unless (eq? st 'settled)
                  (fail "the settled record did not survive its process" st)))
              (census-is (census-of 0 2 0) "a tombstone was counted as live")
              (ok "drain sees the lingerer until it goes; the record outlives it")))))

      ;; ---- the drain, end to end ----------------------------------------
      ;; still quiescing; two parked conversations remain. Kill one (the
      ;; census must self-heal around the scheduler's own unregister) and
      ;; settle the other through a resume -- both roads must end at zero.
      (kill (whereis 'g2) 'census-drain)
      (poll-census (census-of 0 1 0) "the killed conversation was still counted")
      (ok "census self-heals around a kill it never saw")
      (let-values (((reply status) (conversation-resume! id1 t1 'done)))
        (unless (eq? reply 'finished)
          (fail "the last conversation did not settle" reply status)))
      ;; it lingers now (120s ttl): drain is NOT done...
      (unless (equal? (conversation-census) (census-of 0 0 1))
        (fail "the settling conversation did not linger"
              (conversation-census)))
      ;; ...until the operator ends the replay window
      (kill (whereis (string->symbol (string-append "igropyr-conv-" id1)))
            'census-drain)
      (poll-census (census-of 0 0 0) "the drain never reached zero")
      (unless (conversation-quiescing?)
        (fail "the switch drifted during the drain"))
      (ok "drained: quiescing with an exactly-zero census"))

    ;; ---- admitted means counted, before the process ever runs ----------
    ;; spawn only queues. A probe woken BEFORE run! spawns the conversation
    ;; sits ahead of it in the run queue, so it executes in the window
    ;; between admission and the conversation's first instruction -- the
    ;; exact instant where a census that counts late reports "quiescing
    ;; and zero" while an accepted conversation is about to start. The
    ;; drained node above is the known-zero baseline, so the probe must
    ;; read exactly one.
    (conversation-quiesce! #f)
    (let* ((me self)
           (probe (spawn
                    (lambda ()
                      (receive
                        (`#(go)
                          (conversation-quiesce! #t)
                          (send me (vector 'probe
                                           (conversation-census)
                                           (conversation-quiescing?)))))))))
      (sleep-ms 50)                       ; let the probe park first
      (send probe (vector 'go))           ; runnable, ahead of the spawn
      (let-values (((idp tp rp) (conversation-start! settle-flow 'hi 30000)))
        (receive (after 5000 (fail "the probe never reported"))
          (`#(probe ,c ,qs)
            (unless qs (fail "the probe's quiesce did not take"))
            (unless (= 1 (cdr (assq 'total c)))
              (fail "an admitted conversation was invisible to the census"
                    c))))
        (ok "an admitted conversation is counted before it first runs")
        ;; leave the node as drained as we found it
        (kill (whereis (string->symbol (string-append "igropyr-conv-" idp)))
              'census-drain)
        (poll-census (census-of 0 0 0) "the probe's conversation lingered")))

    (ask (vector 'quit))
    (display "ALL CONV-CENSUS TESTS PASSED\n")
    (exit 0)))
