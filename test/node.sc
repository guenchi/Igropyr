#!chezscheme
;;; (igropyr node) integration test: two real OS processes.
;;;   - handshake + node-up
;;;   - rsend round-trip with extended-whitelist payload fidelity
;;;     (vector, bytevector, flonum, ratio through the wire and back)
;;;   - node-down when the peer exits
;;;   - a peer with the WRONG secret never becomes a node
;;;   - rsend to a disconnected node returns #f; to self delivers locally

(import (chezscheme) (igropyr actor) (igropyr libuv)
        (igropyr node) (igropyr pubsub))

;; The run may be using `chez` or $SCHEME_BIN rather than `scheme`, and a
;; child started with the wrong name simply never appears -- which this
;; suite would report as whatever it was waiting for timing out, not as a
;; missing interpreter. run-all.sh exports the name it chose.
(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))


(define port 18091)
(define secret "test-mesh-secret")

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

(define (spawn-child! name secret)
  (system (string-append
            scheme-bin " --script igropyr/test/node-child.sc "
            name " " (number->string port) " " secret " &")))

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (node-set-limits! 64 2)
    (start-pubsub!)
    (register 'main self)
    (monitor-node 'b)

    ;; The pre-auth handshake has one absolute deadline. Dripping a byte
    ;; before each idle timeout must not hold an unauthenticated fd forever.
    (tcp-connect! "127.0.0.1" port self)
    (let ((slow
            (receive (after 2000 (fail! "slow-handshake-connect"))
              (`#(tcp-connected ,c) c)
              (`#(tcp-connect-failed ,e) (fail! "slow-handshake-connect" e)))))
      (tcp-read-start! slow)
      (tcp-write! slow (string->utf8 "10\n(") #f)
      ;; Drip a byte every second rather than once. A single drip has to
      ;; land inside the server's own window to prove anything: if the
      ;; scheduler drifts past it, the server closes on its own schedule
      ;; and the check passes against the very code it exists to reject --
      ;; moving one sleep from 4000 to 5200 was enough to make this report
      ;; ok against a per-receive timeout. Dripping continuously removes
      ;; the dependency: a refreshing window outlives the whole loop no
      ;; matter where individual bytes land, and an absolute deadline is
      ;; moved by none of them.
      (let ((t0 (now-ms)))
        (let loop ((k 0))
          (if (= k 8)
              (begin (tcp-close! slow) (fail! "slow-handshake-deadline"))
              (receive (after 1000
                          (tcp-write! slow (string->utf8 "x") #f)
                          (loop (+ k 1)))
                (`#(tcp-eof) 'ok)
                (`#(tcp-error ,_) 'ok))))
        ;; reaching k = 8 already fails; this keeps the check honest if the
        ;; deadline is ever made longer than the loop
        (let ((elapsed (- (now-ms) t0)))
          (when (>= elapsed 7000)
            (fail! "slow-handshake-deadline-not-absolute" elapsed))))
      (display "absolute pre-auth handshake deadline ok\n"))

    ;; Each pre-auth connection is bounded in bytes and in time, but a
    ;; stranger must not be able to hold an unbounded NUMBER of them --
    ;; every one is an fd and a process, and the fd budget belongs to the
    ;; whole OS process, not just the mesh. Over the ceiling the node must
    ;; close without answering and without spawning. Runs before any child
    ;; node exists, so nothing else is competing for a slot.
    (node-set-limits! #f #f 4)
    (let ((me self) (ref (gensym)))
      ;; one prober process per connection: tcp-data carries no connection,
      ;; so a shared mailbox could not tell which socket was answered
      (do ((i 0 (+ i 1))) ((= i 8))
        (spawn
          (lambda ()
            (tcp-connect! "127.0.0.1" port self)
            (receive (after 3000 (send me (vector ref 'no-connect)))
              (`#(tcp-connected ,c)
                (tcp-read-start! c)
                (receive (after 3000 (send me (vector ref 'silent)))
                  (`#(tcp-data ,_)
                    ;; report, then HOLD. Closing here would free the slot
                    ;; and let the next prober take it, so the eight
                    ;; connections would never be in flight at once and the
                    ;; ceiling would never be reached.
                    (send me (vector ref 'challenged))
                    (receive (after 6000 (tcp-close! c))
                      (`#(tcp-eof) 'ok)
                      (`#(tcp-error ,_) 'ok)))
                  (`#(tcp-eof) (send me (vector ref 'refused)))
                  (`#(tcp-error ,_) (send me (vector ref 'refused)))))
              (`#(tcp-connect-failed ,e) (send me (vector ref 'refused)))))))
      (let loop ((k 0) (challenged 0) (refused 0))
        (if (= k 8)
            (begin
              (unless (= challenged 4)
                (fail! "preauth-cap-challenged" challenged))
              (unless (= refused 4)
                (fail! "preauth-cap-refused" refused)))
            (receive (after 8000 (fail! "preauth-cap-timeout" k))
              (`#(,@ref ,tag)
                (case tag
                  ((challenged) (loop (+ k 1) (+ challenged 1) refused))
                  ((refused) (loop (+ k 1) challenged (+ refused 1)))
                  (else (fail! "preauth-cap-unexpected" tag))))))))
    ;; back to a ceiling that cannot interfere with the real handshakes below
    (node-set-limits! #f #f 256)
    (display "pre-auth connection ceiling ok\n")

    ;; rsend to an unknown node: #f, no crash
    (unless (eq? #f (rsend 'nowhere 'svc 'x))
      (fail! "rsend-unknown"))
    (display "rsend to unknown node ok\n")

    ;; rsend to self is a local send
    (rsend 'a 'main (vector 'loopback 1))
    (receive (after 1000 (fail! "self-rsend"))
      (`#(loopback 1) 'ok))
    (display "rsend to self ok\n")

    ;; A missing local name completes through the self-monitor agent's
    ;; immediate path. Exercise a burst so agent publication and cleanup
    ;; can be preempted at every point without losing or duplicating DOWN.
    (do ((i 0 (+ i 1))) ((= i 64))
      (monitor-remote 'a 'missing-local-service))
    (let loop ((left 64))
      (unless (zero? left)
        (receive (after 2000 (fail! "self-monitor-noproc-timeout" left))
          (`#(remote-down a missing-local-service ,reason)
            (unless (eq? reason 'noproc)
              (fail! "self-monitor-noproc-reason" reason))
            (loop (- left 1))))))
    (receive (after 50 'ok)
      (`#(remote-down a missing-local-service ,reason)
        (fail! "self-monitor-duplicate-down" reason)))
    ;; Delivery was never the broken part -- retention was. The immediate
    ;; noproc path returned without removing its own caller-agents entry,
    ;; so 64 dead agent pids stayed rooted with nothing to ever sweep them.
    ;; Nothing above can see that; the table sizes can.
    (let ((stats (node-monitor-stats)))
      (for-each
        (lambda (k)
          (let ((n (cdr (assq k stats))))
            (unless (zero? n)
              (fail! "self-monitor-retained" k n))))
        '(rmonitors caller-agents owner-agents)))
    (display "missing self monitors clean up exactly once ok\n")

    ;; The arming step itself: the rmonitors entry and the owner agent
    ;; must appear in ONE atomic region. The entry roots the caller's pcb,
    ;; and when that caller dies the agent is the only thing that clears
    ;; it (the other paths that delete an entry -- a target-side down, a
    ;; link drop, an explicit demonitor -- all require the monitor to
    ;; still be running somewhere). So a kill landing between two separate
    ;; regions leaves an entry with nothing left to release it -- on a
    ;; mesh that stays up, forever.
    ;;
    ;; Aiming a kill at the gap between two adjacent statements does not
    ;; work, but the reason it does not is also the way in: a kill only
    ;; lands where the victim yields, so a yield inside the gap is a
    ;; yield another runnable process can SEE. This watches for that
    ;; state rather than aiming at it -- rmonitors above owner-agents,
    ;; read from ONE snapshot. Two calls would read the second count
    ;; before an arming and the first count after it, manufacturing the
    ;; very imbalance under test. The watcher spins rather than sleeps:
    ;; sleeping makes it unrunnable, and an imbalance nobody is scheduled
    ;; to observe passes unseen. set-timer walks the victim's preemption
    ;; point across the call -- a tick budget that expires inside an
    ;; atomic region is delivered when the outermost one exits, which in
    ;; a split arming is exactly the gap.
    ;;
    ;; Two things keep the reading unambiguous. The victim PARKS instead
    ;; of returning, for longer than a round is allowed to last, so its
    ;; own teardown cannot be in flight while it is watched: teardown
    ;; shows the same imbalance for a benign reason, since the owner
    ;; agent deletes its own table entry first and the rmonitors entry
    ;; second. And every round starts from a measured baseline, so the
    ;; previous round's teardown cannot be read as this round's arming.
    ;; With both, an imbalance can only be the split -- and killing the
    ;; victim there and finding the entry still present is the leak
    ;; itself rather than an inference about it.
    ;;
    ;; Each round must prove it ran the arming at all: it ends on a
    ;; caught gap or on an observed entry, never on a clock. k is swept
    ;; because a tick budget expires at compiler-inserted trap points,
    ;; whose spacing is a property of the build; the range is empirical
    ;; -- a tree with the two regions split apart is caught here at k=5,
    ;; deterministically -- and is not a claim that 60 rounds cover every
    ;; point on every build.
    (let* ((tables '(rmonitors caller-agents owner-agents))
           (at-baseline?
             (lambda ()
               (let ((s (node-monitor-stats)))
                 (for-all (lambda (k) (zero? (cdr (assq k s)))) tables))))
           (await-baseline!
             (lambda (label k)
               (let loop ((n 0))
                 (cond ((at-baseline?) 'ok)
                       ((= n 200) (fail! label k (node-monitor-stats)))
                       (else (sleep-ms 10) (loop (+ n 1))))))))
      (do ((k 1 (+ k 1))) ((> k 60))
        (await-baseline! "arming-window-baseline" k)
        (let* ((me self)
               (v (spawn (lambda ()
                           (send me (vector 'gap-ready))
                           (receive (`#(gap-go) 'ok))
                           (set-timer k)
                           (monitor-remote 'a 'main)
                           ;; park past the round's own bound: a victim
                           ;; that returned would tear the monitor down
                           ;; and produce the benign imbalance
                           (receive (after 10000 'done))))))
          ;; the victim has RUN before its budget is set -- a round that
          ;; killed a process still sitting in the run queue would test
          ;; nothing while looking exactly like a round that passed
          (receive (after 2000 (fail! "arming-window-victim-never-ran" k))
            (`#(gap-ready) 'ok))
          (send v (vector 'gap-go))
          (let ((deadline (+ (now-ms) 3000)))
            (let poll ()
              (let* ((s (node-monitor-stats))
                     (r (cdr (assq 'rmonitors s)))
                     (o (cdr (assq 'owner-agents s))))
                (cond
                  ((> r o)
                   (kill v 'caught-in-gap)
                   (sleep-ms 200)
                   (let ((s2 (node-monitor-stats)))
                     (if (> (cdr (assq 'rmonitors s2)) 0)
                         (fail! "arming-window-leaked" k s s2)
                         ;; the state itself should not exist on a merged
                         ;; region; seeing it and then losing the race to
                         ;; the kill is still a finding, not a pass
                         (fail! "arming-window-imbalance-without-leak"
                                k s s2))))
                  ((> r 0) 'this-round-armed)
                  ((> (now-ms) deadline)
                   (fail! "arming-window-round-never-armed" k s))
                  (else (poll))))))
          (kill v 'round-over)))
      (await-baseline! "arming-window-residue" 'end))
    (display "arming window: entry and agent inseparable under kill ok\n")

    ;; wrong secret: must never come up
    (spawn-child! "evil" "wrong-secret")
    (monitor-node 'evil)
    (receive (after 2500 'ok)
      (`#(node-up evil) (fail! "bad-secret-accepted")))
    (when (memq 'evil (node-peers)) (fail! "bad-secret-in-peers"))
    (display "wrong secret rejected ok\n")

    ;; the real peer comes up
    (spawn-child! "b" secret)
    (receive (after 10000 (fail! "node-up-timeout"))
      (`#(node-up b) 'ok))
    (unless (memq 'b (node-peers)) (fail! "peers-missing-b"))
    (display "handshake + node-up ok\n")

    ;; round-trip: extended payload must cross bit-intact both ways
    (let ((payload (vector 'blob (bytevector 0 127 255) 3.25 1/3 '(a . b))))
      (unless (rsend 'b 'svc (vector 'add1 41 payload))
        (fail! "rsend-b"))
      (receive (after 5000 (fail! "roundtrip-timeout"))
        (`#(ans ,n ,p)
          (unless (= n 42) (fail! "roundtrip-value" n))
          (unless (equal? p payload) (fail! "payload-fidelity" p)))))
    (display "rsend round-trip + payload fidelity ok\n")

    ;; ordering: a burst arrives in send order
    (do ((i 0 (+ i 1))) ((= i 100))
      (rsend 'b 'svc (vector 'add1 i (vector))))
    (let loop ((expect 1))
      (unless (= expect 101)
        (receive (after 5000 (fail! "ordering-timeout" expect))
          (`#(ans ,n ,p)
            (unless (= n expect) (fail! "ordering" expect n))
            (loop (+ expect 1))))))
    (display "in-order burst ok\n")

    ;; rcall: synchronous cross-node call to a gen-server on b
    (unless (= 49 (rcall 'b 'calc (vector 'square 7)))
      (fail! "rcall-value"))
    (display "rcall round-trip ok\n")

    ;; rcall to a gen-server that raises -> rcall-error, not a hang
    (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'rcall-error))
                          (vector-ref e 1)))
                 (rcall 'b 'calc (vector 'boom))
                 'no-raise)))
      (unless (memq got '(unavailable server-died call-failed))
        (fail! "rcall-error-kind" got)))
    (display "rcall remote failure -> rcall-error ok\n")

    ;; rcall to a missing server -> rcall-error (no hang)
    (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'rcall-error)) #t))
                 (rcall 'b 'nonesuch (vector 'x) 2000)
                 #f)))
      (unless got (fail! "rcall-missing")))
    (display "rcall missing server -> rcall-error ok\n")

    ;; distributed pubsub: a publish on node a must reach a subscriber
    ;; on node b (b relays it back as #(heard ...))
    (sleep-ms 300)                       ; let b's subscribe settle
    (publish 'room "cross-node-hello")
    (receive (after 5000 (fail! "dist-pubsub-timeout"))
      (`#(heard ,m)
        (unless (equal? m "cross-node-hello") (fail! "dist-pubsub-payload" m))))
    (display "distributed pubsub fan-out ok\n")

    ;; Remote monitor state is owned by its caller. Short-lived callers
    ;; must release target-side slots instead of leaving permanent watches.
    (do ((i 0 (+ i 1))) ((= i 2))
      (spawn (lambda () (monitor-remote 'b 'svc))))
    (sleep-ms 600)
    (let ((m (monitor-remote 'b 'svc)))
      (receive (after 400 'ok)
        (`#(remote-down b svc overload)
          (fail! "dead-monitor-callers-leaked-slots")))
      (demonitor-remote m))
    (display "dead monitor callers release remote slots ok\n")

    ;; monitor-remote: watch b's 'watched process, kill it, observe the
    ;; real exit reason cross the wire
    (monitor-remote 'b 'watched)
    (rsend 'b 'svc (vector 'kill-watched 'crash-reason))
    (receive (after 5000 (fail! "remote-down-timeout"))
      (`#(remote-down b watched ,reason)
        (unless (eq? reason 'crash-reason) (fail! "remote-down-reason" reason))))
    (display "monitor-remote -> remote-down with reason ok\n")

    ;; watching a name that isn't registered -> immediate noproc
    (monitor-remote 'b 'watched)                 ; now dead
    (receive (after 5000 (fail! "noproc-timeout"))
      (`#(remote-down b watched ,r) (unless (eq? r 'noproc) (fail! "noproc" r))))
    (display "monitor-remote missing name -> noproc ok\n")

    ;; demonitor: a demonitored watch must NOT fire when b dies
    (let ((m (monitor-remote 'b 'svc)))
      (demonitor-remote m))
    (receive (after 400 'ok)
      (`#(remote-down b svc ,_) (fail! "demonitor-still-fired")))
    (display "demonitor-remote silences the watch ok\n")

    ;; a live watch fires noconnection when the node's link drops
    (monitor-remote 'b 'svc)

    ;; peer exits -> node-down, remote-down(noconnection), rsend turns #f
    (rsend 'b 'svc (vector 'quit))
    (let wait ((down? #f) (noconn? #f))
      (unless (and down? noconn?)
        (receive (after 10000 (fail! "node-down-timeout" down? noconn?))
          (`#(node-down b) (wait #t noconn?))
          (`#(remote-down b svc ,r)
            (unless (eq? r 'noconnection) (fail! "noconnection" r))
            (wait down? #t)))))
    (when (memq 'b (node-peers)) (fail! "peers-still-b"))
    (unless (eq? #f (rsend 'b 'svc 'x)) (fail! "rsend-after-down"))
    (display "node-down + remote-down(noconnection) + rsend #f ok\n")

    ;; The wire whitelist holds on THIS node too. rsend used to skip the
    ;; check for its own node name, so a payload no peer would accept -- a
    ;; procedure, a port -- was delivered locally and refused everywhere
    ;; else: the same task succeeded or failed depending on which node a
    ;; round robin happened to pick, and the local case is exactly where
    ;; such a payload gets written and never noticed.
    (register 'wire-probe self)
    (let ((delivered (box #f)))
      (spawn (lambda ()
               (receive (after 1000 'done)
                 (`#(got ,x) (set-box! delivered #t)))))
      (unless (guard (e (#t #t)) (rsend (node-self) 'wire-probe (vector 'got car)) #f)
        (fail! "local rsend accepted a procedure payload"))
      ;; ...and an ordinary payload still goes through
      (unless (rsend (node-self) 'wire-probe (vector 'got "text"))
        (fail! "local rsend refused a wire-safe payload"))
      (receive (after 500 'done) (`#(got ,x) 'ok)))
    (display "local rsend enforces the wire whitelist ok\n")

    (display "ALL NODE TESTS PASSED\n")
    (exit 0)))
