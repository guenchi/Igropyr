#!chezscheme
;;; A poison event -- one whose delivery raises every time -- must not take
;;; the node down. Before this change the dispatcher died on it, the warden
;;; restarted the dispatcher, the event was still at the head of its queue,
;;; and the loop ran until the warden gave up: one bad delivery ended every
;;; service on the node. Now the dispatcher retries the delivery three times
;;; under its own guard, then moves the event to a dead-letter ring, tells
;;; the node observer, and goes on with the next event. Dead letters can be
;;; read back and re-delivered. See poison-event-design-v3..v5.
;;;
;;; Runs only with IGROPYR_INJECT=on, from source, like test/inject.sc: the
;;; failure is injected at notify-list!'s entry ('notify-deliver). The
;;; events under test are the node's own topology events (node-down /
;;; node-up for the child), so the fixture is the same two-process one.
;;;
;;; A WATCHDOG ENDS THE RUN. On the tree before the change this script
;;; would sit in the dispatcher's death loop until the warden gave up and
;;; the node stopped, which from outside is a hang; a hang has no voice of
;;; its own, so a watchdog turns it into an exit with a name.
(import (chezscheme) (igropyr actor) (igropyr node)
        (igropyr inject-control) (igropyr inject))

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))
(define port 18095)
(define secret "test-poison-secret")
(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "poison suite requires IGROPYR_INJECT=on\n") (exit 1))
(unless (> ($inject-ticket) 0)
  (display "poison suite process was not expanded with injection on (stale .so?)\n") (exit 1))

(define (fail label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline) (exit 1))
(define (spawn-child! name)
  (system (string-append scheme-bin " --script igropyr/test/node-child.sc "
                         name " " (number->string port) " " secret " 120000 &")))
(define (dispatcher-pid) (whereis 'igropyr-node-dispatcher))
(define (stat key alist) (let ((p (assq key alist))) (and p (cdr p))))

(start-scheduler
  (lambda ()
    ;; the watchdog: a hang becomes "FAIL watchdog", not silence
    (spawn (lambda () (sleep-ms 90000) (display "FAIL watchdog: poison suite did not finish in 90 s\n") (exit 1)))
    (node-start! 'a secret port)
    (register 'main self)
    (register 'igropyr-node-observer self)   ; quarantine notices come here
    (monitor-node 'b)                          ; the watcher whose delivery will be poisoned
    (spawn-child! "b")
    (receive (after 15000 (fail "child-never-came-up")) (`#(node-up b) 'ok))
    (let ((d0 (dispatcher-pid)))
      (unless d0 (fail "no-dispatcher"))
      ;; ---- poison the next delivery: the child's node-down --------------
      (inject-arm-fault! 'notify-deliver)     ; every hit raises until disarmed
      (rsend 'b 'svc (vector 'quit))          ; the child exits: one node-down event
      ;; the quarantine notice is the first thing that must arrive
      ;; on failure say whether the dispatcher is still the same process,
      ;; not what its record looks like: writing a pcb prints its fields,
      ;; and one of them can read like a panic that never happened
      (let ((notice (receive (after 20000 (fail "no-quarantine-notice"
                                                'hits (inject-hits 'notify-deliver)
                                                'dispatcher (cond ((not (dispatcher-pid)) 'gone)
                                                                  ((eq? (dispatcher-pid) d0) 'same-pid)
                                                                  (else 'replaced))))
                      (`#(event-quarantined ,name ,kind ,seq ,reason ,failures ,reason-kind)
                        (list name kind seq reason failures)))))
        (unless (eq? (car notice) 'b) (fail "quarantined-wrong-name" notice))
        (unless (eq? (cadr notice) 'node-down) (fail "quarantined-wrong-kind" notice))
        (unless (eqv? (list-ref notice 4) 3) (fail "quarantined-wrong-failure-count" notice))
        (unless (eqv? (inject-hits 'notify-deliver) 3) (fail "hits" (inject-hits 'notify-deliver)))
        (inject-disarm!)
        ;; the dispatcher survived: same pid, and it kept the node running
        (unless (eq? (dispatcher-pid) d0) (fail "dispatcher-was-replaced" d0 (dispatcher-pid)))
        ;; the dead letter is readable
        (let ((dl (node-dead-letters)) (st (node-dead-letter-stats)))
          (unless (and (pair? dl) (eq? (vector-ref (car dl) 0) 'b) (eq? (vector-ref (car dl) 1) 'node-down)
                       (eqv? (vector-ref (car dl) 4) 3))
            (fail "dead-letter-missing-or-wrong" dl))
          (unless (and (eqv? (stat 'stored st) 1) (eqv? (stat 'lifetime st) 1) (eqv? (stat 'dropped st) 0))
            (fail "dead-letter-stats" st))
          ;; the poisoned notice itself never reached the watcher
          (receive (after 300 'ok) (`#(node-down b) (fail "poisoned-event-was-also-delivered")))
          ;; the dispatcher goes on: the child comes back, node-up arrives normally
          (spawn-child! "b")
          (receive (after 15000 (fail "node-up-after-quarantine-not-delivered")) (`#(node-up b) 'ok))
          ;; and the dead letter can be re-delivered: the original node-down, same seq
          (let ((seq (vector-ref (car dl) 2)))
            (unless (node-redeliver-dead-letter! seq) (fail "redeliver-refused" seq))
            (receive (after 5000 (fail "redelivered-event-not-received")) (`#(node-down b) 'ok))
            (let ((st2 (node-dead-letter-stats)))
              (unless (eqv? (stat 'stored st2) 0) (fail "dead-letter-not-cleared-after-redeliver" st2)))
            (when (node-redeliver-dead-letter! seq) (fail "redeliver-twice-succeeded")))))
      (display "poison event: three failed deliveries quarantine it, the node lives, the letter is read back and re-delivered ok\n"))
    (rsend 'b 'svc (vector 'quit))
    (sleep-ms 300)
    (display "ALL POISON TESTS PASSED\n")
    (exit 0)))
