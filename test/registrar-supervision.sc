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
    ;; ---- R6-9 a pre-touched 0 becomes generation 1 on the next authorisation
    ;; What this pins: the seam sees the stored 0 (it does not launder), and
    ;; the connect that follows issues 1. What it does NOT yet pin: peer-gen's
    ;; own "0 is absent" guard. That guard is reachable only if a death or a
    ;; raise lands between the pre-placement and the advance -- set-endpoint's
    ;; phase (a) spawns (allocates, and is a scheduling point) between the two
    ;; -- which is R-e's window. No injection point exists there today, so no
    ;; cell covers it: reachable and untested, not unreachable. A mutant that
    ;; hands a stored 0 back stays green here for that reason. Queued: an
    ;; injection point 'registrar-endpoint-after-spawn and a cell that arms it.
    ;; The registrar's tails pre-touch dial-gens with 0 before their region so
    ;; the advance inside it replaces in place; peer-gen must therefore treat
    ;; a stored 0 as absent (mint 1) -- generation 0 is never issued. The seam
    ;; reads the raw table, not through peer-gen, so a 0 is visible to it.
    (node-disconnect! 'b)
    (receive (after 15000 (check "disconnect for R6-9" #f)) (`#(node-down b) 'ok))
    (drain-node-events!)
    (check "R6-9 precondition: the seam sees a stored value, not a minted one" (integer? ($registrar-peer-gen 'b)) ($registrar-peer-gen 'b))
    ($registrar-seed-gen! 'b 0)
    (check "R6-9: the seeded 0 is visible as 0 (the seam does not launder it)" (eqv? ($registrar-peer-gen 'b) 0) ($registrar-peer-gen 'b))
    (node-connect! 'b "127.0.0.1" peer-port)
    (receive (after 15000 (check "R6-9: reconnect after seeding 0" #f)) (`#(node-up b) 'ok))
    (check "R6-9: a stored 0 was treated as absent -- the issued generation is 1, never 0"
           (eqv? ($registrar-peer-gen 'b) 1) ($registrar-peer-gen 'b))
    (rsend 'b 'svc (vector 'quit))
    (sleep-ms 300)
    (if (zero? failures) (begin (display "ALL REGISTRAR-SUPERVISION TESTS PASSED\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
