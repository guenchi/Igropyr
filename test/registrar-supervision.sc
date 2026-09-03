#!chezscheme
;;; THE REGISTRAR IS SUPERVISED, AND WHAT IT WAS ASKED TO DO SURVIVES ITS DEATH.
;;;
;;; The registrar is the only process that authorises dials. Before this
;;; change it was spawned bare: an unexpected raise inside it ended it with
;;; nothing restarting it, and from then on every node-connect! sent into a
;;; dead mailbox -- dropped by contract -- and authorised-connect! returned
;;; #f after its 5 s timeout. No error, no DOWN, no counter: the node simply
;;; could never dial again.
;;;
;;; Now it is a warden child, and commands live in a shared queue that the
;;; registrar executes serially and dequeues only after finishing, so a
;;; death loses no command; each handler's steps are ordered so that every
;;; prefix is a consistent state and a re-run is harmless (design v6-v11).
;;;
;;; The seams $registrar-pid / $registrar-queue-length / $registrar-seed-gen!
;;; exist only with IGROPYR_INJECT=on and RAISE otherwise, so a run that
;;; forgot the variable cannot seed nothing and pass. Injection points named
;;; here exist in the correct code and are no-ops unless armed; a raise
;;; armed at one of them ends the registrar the way any unexpected raise
;;; would, which is the event under test.
;;;
;;; Deferred to child-process cells (they need a captured stderr and, for
;;; two of them, a node fail-stop): R6-3' (set-endpoint under a kill after
;;; the take), R6-7 (give-up prints the consequence), R6-8' (exhaustion
;;; inside the registrar names it in the death line).
(import (chezscheme) (igropyr actor) (igropyr node)
        (igropyr inject-control) (igropyr inject))
(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))
(define port 18796)
(define secret "test-registrar-secret")
(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "registrar-supervision suite requires IGROPYR_INJECT=on\n") (exit 1))
(unless (> ($inject-ticket) 0)
  (display "registrar-supervision suite process was not expanded with injection on (stale .so?)\n") (exit 1))
(define failures 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define peer-port (+ port 1))
;; a LISTENING peer: node 'a must be the dialer for the registrar to be exercised
(define (spawn-listener! name)
  (system (string-append scheme-bin " --script igropyr/test/node-listener-child.sc "
                         name " " (number->string peer-port) " " secret " 120000 &")))
;; The registrar is started by the warden, asynchronously: node-start! does
;; not wait for it (design C6), so right after node-start! the seam may say
;; #f. That is the real state, not an error; a cell that reads it has to
;; wait, bounded, for the first pid -- and for the successor after a kill.
(define (wait-pid ms)
  (let loop ((left ms))
    (let ((q ($registrar-pid)))
      (cond ((and q (process-alive? q)) q)
            ((<= left 0) #f)
            (else (sleep-ms 10) (loop (- left 10)))))))
;; wait until the registrar's pid differs from p (the warden restarted it), bounded
(define (wait-restart p ms)
  (let loop ((left ms))
    (let ((q ($registrar-pid)))
      (cond ((and q (not (eq? q p)) (process-alive? q)) q)
            ((<= left 0) #f)
            (else (sleep-ms 20) (loop (- left 20)))))))
(define (now-ms) (let ((t (current-time))) (+ (* 1000 (time-second t)) (div (time-nanosecond t) 1000000))))
;; wall clock of the first registrar death in this run: the warden gives up at
;; child-restart-min-count (5) deaths inside child-restart-window-ms (60 s), and
;; the cells above R6-9 kill it four times, so R6-9's death must fall outside
;; that window or the node fail-stops -- which is the warden being right.
(define first-death-ms #f)
(define (drain-node-events!) (receive (after 300 'ok) (`#(node-up ,x) (drain-node-events!)) (`#(node-down ,x) (drain-node-events!))))

(start-scheduler
  (lambda ()
    (spawn (lambda () (sleep-ms 120000) (display "FAIL watchdog\n") (exit 1)))
    (node-start! 'a secret port)
    (register 'main self)
    (monitor-node 'b)
    ;; ---- R6-1 kill the registrar; a later node-connect! still establishes
    (let ((p0 (wait-pid 5000)))
      (check "registrar is alive (started asynchronously by the warden)" (and p0 (process-alive? p0)) p0)
      (set! first-death-ms (now-ms))
      (kill p0 'test-kill)
      (let ((p1 (wait-restart p0 5000)))
        (check "the warden restarted the registrar (new pid)" (and p1 (not (eq? p1 p0))) p0 p1)
        (begin (spawn-listener! "b") (sleep-ms 400))
        (node-connect! 'b "127.0.0.1" peer-port)
        (receive (after 15000 (check "node-connect! after a registrar death still establishes" #f))
          (`#(node-up b) (check "node-connect! after a registrar death still establishes" #t)))))
    ;; ---- R6-5 / R6-6 a command enqueued while the registrar is dead is executed after restart
    (let ((p ($registrar-pid)))
      (kill p 'test-kill)
      ;; enqueue immediately: no yield between the kill and the enqueue
      (node-disconnect! 'b)
      (check "the disconnect sat in the queue while the registrar was dead"
             (>= ($registrar-queue-length) 1) ($registrar-queue-length))
      (let ((q (wait-restart p 5000)))
        (check "registrar restarted" (and q #t))
        (receive (after 15000 (check "a disconnect queued during the death was executed after restart" #f))
          (`#(node-down b) (check "a disconnect queued during the death was executed after restart" #t)))
        (check "the queue is drained after the command ran" (= ($registrar-queue-length) 0) ($registrar-queue-length))))
    (drain-node-events!)
    ;; ---- R6-2 a raise after the take, before the stop, in disconnect: the re-run finishes it
    (node-connect! 'b "127.0.0.1" peer-port)
    (receive (after 15000 (check "reconnect for R6-2" #f)) (`#(node-up b) 'ok))
    (let ((p ($registrar-pid)))
      (inject-arm-fault! 'registrar-disconnect-after-take 1)   ; the registrar dies right after reading the row
      (node-disconnect! 'b)
      (let ((q (wait-restart p 5000)))
        ;; TWO hits, not one: the first raised (the registrar died there), and
        ;; the successor RE-RAN the same command and passed through the same
        ;; point with the fault spent. That second pass is the evidence that the
        ;; command survived the death -- a count of 1 would mean it was lost.
        (check "R6-2: the registrar died at the point, was restarted, and re-ran the command (2 hits)"
               (and q (eqv? (inject-hits 'registrar-disconnect-after-take) 2)) (inject-hits 'registrar-disconnect-after-take))
        (inject-disarm!)
        (receive (after 15000 (check "R6-2: the re-run completed the disconnect (node-down arrived)" #f))
          (`#(node-down b) (check "R6-2: the re-run completed the disconnect (node-down arrived)" #t)))
        ;; The half that sees an ORPHANED connector: node-down alone does not,
        ;; because disconnect also stops the link. A connector the re-run
        ;; failed to stop (its pid was only on the dead registrar's stack)
        ;; keeps dialling and, with the listener still up, reconnects -- so
        ;; an unexpected node-up here is the orphan announcing itself.
        ;; 8 s, not 3: an orphan's first re-dial comes after reconnect-base-ms
        ;; (3000) plus dispersion, so a shorter window would pass the mutant.
        (receive (after 8000 (check "R6-2: no orphaned connector re-dialled after the completed disconnect" #t))
          (`#(node-up b) (check "R6-2: no orphaned connector re-dialled after the completed disconnect" #f 'orphan-reconnected)))
        ;; and the peer can be dialled again under a fresh authorisation
        (node-connect! 'b "127.0.0.1" peer-port)
        (receive (after 15000 (check "R6-2: the peer is dialable again after the completed disconnect" #f))
          (`#(node-up b) (check "R6-2: the peer is dialable again after the completed disconnect" #t)))))
    (drain-node-events!)
    ;; ---- R6-4 a raise between the attempt's region and its send: the re-run resends go promptly
    (node-disconnect! 'b)
    (receive (after 15000 (check "disconnect for R6-4" #f)) (`#(node-down b) 'ok))
    (drain-node-events!)
    (let ((p ($registrar-pid)) (t0 (now-ms)))
      (inject-arm-fault! 'registrar-attempt-after-region 1)
      (node-connect! 'b "127.0.0.1" peer-port)
      (let ((q (wait-restart p 5000)))
        (check "R6-4: the registrar died after publishing the row and re-ran the attempt (2 hits)"
               (and q (eqv? (inject-hits 'registrar-attempt-after-region) 2)) (inject-hits 'registrar-attempt-after-region))
        (inject-disarm!)
        (receive (after 15000 (check "R6-4: the connection was established" #f))
          (`#(node-up b)
            (let ((dt (- (now-ms) t0)))
              ;; with the resend the child gets `go` on the re-run; without it the child
              ;; waits out its 5 s timeout and starts a new attempt -- so the bound is 5 s
              (check "R6-4: established via the re-run's resend, not via the child's 5 s timeout" (< dt 5000) 'ms dt))))))
    ;; ---- R6-9 R-e's window is survivable: a death in set-endpoint's phase (a)
    ;; (after the pre-placement and the spawn, before the region) restarts the
    ;; registrar, the command is re-run from the queue head, and the link comes
    ;; up exactly once -- no fail-stop, no orphan connector from the first spawn.
    ;; What this cell does NOT pin: peer-gen's 0 guard. The stored 0 is written
    ;; here but never read -- the command that wrote it holds the queue head
    ;; until it completes (advancing 0->1) or the node fail-stops, and
    ;; peer-gen's only caller (attempt-register) is behind it in the FIFO. So
    ;; the "generation is 1" line below is a state check the peer-gen mutant
    ;; also passes; the discriminator is the orphan check (a compensation
    ;; guard that fails to kill the first spawn lets it dial too).
    (node-disconnect! 'b)
    (receive (after 15000 (check "disconnect for R6-9" #f)) (`#(node-down b) 'ok))
    ;; let the restart window of the four earlier deaths expire (see first-death-ms)
    (let ((rem (- (+ first-death-ms 61000) (now-ms))))
      (when (> rem 0) (sleep-ms rem)))
    (drain-node-events!)
    (let ((p ($registrar-pid)))
      ;; seed 0: identical to the state the pre-placement leaves (the pre-placement
      ;; finds the key present and does nothing), so the injected death below
      ;; leaves exactly "a 0 with no advance behind it"
      ($registrar-seed-gen! 'b 0)
      (inject-arm-fault! 'registrar-endpoint-after-spawn 1)
      (node-connect! 'b "127.0.0.1" peer-port)
      (let ((q (wait-restart p 5000)))
        (check "R6-9: the registrar died in phase (a), after the spawn, and was restarted"
               (and q (eqv? (inject-hits 'registrar-endpoint-after-spawn) 2)) (inject-hits 'registrar-endpoint-after-spawn))
        (inject-disarm!)
        ;; the re-run of the queued set-endpoint completes and the connector dials
        (receive (after 15000 (check "R6-9: the queued set-endpoint completed after the restart" #f))
          (`#(node-up b) 'ok))
        ;; the first spawn was killed by the compensation guard: no second link,
        ;; no flap, for longer than reconnect-base-ms (3000)
        (let ((extra (receive (after 8000 #f)
                       (`#(node-up b) 'second-node-up)
                       (`#(node-down b) 'node-down))))
          (check "R6-9: exactly one link came up after the re-run (no orphan connector)" (not extra) extra))
        (check "R6-9: the pre-placed 0 was advanced by the re-run (state check, not a discriminator)"
               (eqv? ($registrar-peer-gen 'b) 1) ($registrar-peer-gen 'b))
        ;; THE DISCRIMINATOR. An orphan from the first spawn is invisible
        ;; while the published link is up: the connector loop takes the
        ;; live-entry branch and idles, one wake per reconnect-delay. It
        ;; shows itself the moment the link goes down -- it is the one
        ;; connector nobody's row names, so a disconnect does not kill it,
        ;; and it re-dials within reconnect-delay (base 3 s). Same shape as
        ;; R6-2's orphan check.
        (node-disconnect! 'b)
        (receive (after 15000 (check "R6-9: disconnect after the survived death" #f)) (`#(node-down b) 'ok))
        (let ((orphan (receive (after 8000 #f) (`#(node-up b) 'orphan-redialled))))
          (check "R6-9: no orphan connector from the killed first spawn re-dialled after the disconnect"
                 (not orphan) orphan))))
    ;; reconnect so the quit reaches the child over a live link
    (node-connect! 'b "127.0.0.1" peer-port)
    (receive (after 15000 (check "reconnect before quit" #f)) (`#(node-up b) 'ok))
    (rsend 'b 'svc (vector 'quit))
    (sleep-ms 300)
    (if (zero? failures) (begin (display "ALL REGISTRAR-SUPERVISION TESTS PASSED\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
