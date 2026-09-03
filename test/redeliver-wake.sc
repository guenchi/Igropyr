#!chezscheme
;;; REDELIVERY REPORTS WHAT WAS COMMITTED, NOT WHETHER THE WAKE WENT OUT.
;;;
;;; node-redeliver-dead-letter! does its whole state change inside one
;;; region -- the letter leaves the ring and joins its queue -- and only
;;; then wakes the dispatcher. The wake allocates a message, and an
;;; allocation can raise. Before this change that raise reached the
;;; caller: an exception for a redelivery that had already happened, and
;;; nothing to undo it with. Now the wake is best effort and the call
;;; returns #t for what it committed; a lost wake costs latency, not the
;;; event, because the dispatcher's receive is timed at 1000 ms and a
;;; restarted one runs a round before its first receive.
;;;
;;; Two cells, and the second is the one that keeps the first honest:
;;; "returned #t without raising" is also what a call that did nothing
;;; would do, so the event must then actually arrive, on the timed-receive
;;; path, with no wake at all.
;;;
;;; Same fixture as poison.sc: a real dead letter is made by poisoning the
;;; child's node-down three times. Needs IGROPYR_INJECT=on, from source.
(import (chezscheme) (igropyr actor) (igropyr node)
        (igropyr inject-control) (igropyr inject))

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))
(define port 18773)
(define secret "test-redeliver-wake-secret")
(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "redeliver-wake suite requires IGROPYR_INJECT=on\n") (exit 1))
(unless (> ($inject-ticket) 0)
  (display "redeliver-wake suite process was not expanded with injection on (stale .so?)\n") (exit 1))

(define (fail label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline) (exit 1))
(define (spawn-child! name)
  (system (string-append scheme-bin " --script igropyr/test/node-child.sc "
                         name " " (number->string port) " " secret " 120000 &")))
(define (stat key alist) (let ((p (assq key alist))) (and p (cdr p))))

(start-scheduler
  (lambda ()
    (spawn (lambda () (sleep-ms 90000) (display "FAIL watchdog: redeliver-wake did not finish in 90 s\n") (exit 1)))
    (node-start! 'a secret port)
    (register 'main self)
    (register 'igropyr-node-observer self)
    (monitor-node 'b)
    (spawn-child! "b")
    (receive (after 15000 (fail "child-never-came-up")) (`#(node-up b) 'ok))
    ;; make one dead letter, exactly as poison.sc does
    (inject-arm-fault! 'notify-deliver)
    (rsend 'b 'svc (vector 'quit))
    (receive (after 20000 (fail "no-quarantine-notice" 'hits (inject-hits 'notify-deliver)))
      (`#(event-quarantined ,name ,kind ,seq ,reason ,failures ,reason-kind) 'ok))
    (inject-disarm!)
    (receive (after 300 'ok) (`#(node-down b) (fail "poisoned-event-was-also-delivered")))
    (spawn-child! "b")
    (receive (after 15000 (fail "node-up-after-quarantine-not-delivered")) (`#(node-up b) 'ok))
    (let* ((dl (node-dead-letters))
           (seq (begin (unless (pair? dl) (fail "no-dead-letter")) (vector-ref (car dl) 2))))
      ;; ---- R9-1: the wake raises; the call still returns #t and raises nothing
      (inject-arm-fault! 'dead-letter-wake 1)
      (let ((outcome (guard (e (#t (list 'raised e)))
                       (list 'returned (node-redeliver-dead-letter! seq)))))
        (unless (eqv? (inject-hits 'dead-letter-wake) 1)
          (fail "wake-injection-not-hit" (inject-hits 'dead-letter-wake)))
        (inject-disarm!)
        (unless (eq? (car outcome) 'returned)
          (fail "redeliver-raised-after-commit" (cadr outcome)))
        (unless (eq? (cadr outcome) #t)
          (fail "redeliver-returned-not-true" (cadr outcome)))
        ;; the state change was committed: the letter has left the ring
        (unless (eqv? (stat 'stored (node-dead-letter-stats)) 0)
          (fail "letter-still-in-ring-after-committed-redeliver" (node-dead-letter-stats)))
        (display "  ok  a raise from the wake is not the caller's: #t, nothing thrown, letter out of the ring\n"))
      ;; ---- R9-2: with NO wake, the event still arrives on the timed-receive path
      (receive (after 1500 (fail "redelivered-event-not-received-without-wake"))
        (`#(node-down b) 'ok))
      (display "  ok  the dispatcher's timed receive delivered it with no wake at all\n"))
    (rsend 'b 'svc (vector 'quit))
    (sleep-ms 300)
    (display "ALL REDELIVER-WAKE TESTS PASSED\n")
    (exit 0)))
