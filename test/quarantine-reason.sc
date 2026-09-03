#!chezscheme
;;; THE REASON A LETTER WAS SET ASIDE IS A RECORD, NOT WHATEVER WAS RAISED.
;;;
;;; Before this change dl-reason held the raised object itself on the
;;; poison path and a bare symbol on the lost-outcome path, so an
;;; application that raised that symbol was indistinguishable from a
;;; dispatcher killed mid-attempt -- and the observer message's `why` was
;;; the only field that told those apart. Now both paths store a private
;;; sealed record #[quarantine-reason kind payload]; the constructor is
;;; not exported, so nothing outside can produce one; and the observer
;;; message carries the kind in a seventh slot, `why` keeping its old
;;; meaning for readers that index the first six.
;;;
;;; Same fixture as poison.sc. Needs IGROPYR_INJECT=on, from source.
(import (chezscheme) (igropyr actor) (igropyr node)
        (igropyr inject-control) (igropyr inject))
(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))
(define port 18777)
(define secret "test-qreason-secret")
(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "quarantine-reason suite requires IGROPYR_INJECT=on\n") (exit 1))
(unless (> ($inject-ticket) 0)
  (display "quarantine-reason suite process was not expanded with injection on (stale .so?)\n") (exit 1))
(define failures 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (spawn-child! name)
  (system (string-append scheme-bin " --script igropyr/test/node-child.sc "
                         name " " (number->string port) " " secret " 120000 &")))
(start-scheduler
  (lambda ()
    (spawn (lambda () (sleep-ms 90000) (display "FAIL watchdog\n") (exit 1)))
    (node-start! 'a secret port)
    (register 'main self)
    (register 'igropyr-node-observer self)
    (monitor-node 'b)
    (spawn-child! "b")
    (receive (after 15000 (display "FAIL child-never-came-up\n") (exit 1)) (`#(node-up b) 'ok))
    (inject-arm-fault! 'notify-deliver)
    (rsend 'b 'svc (vector 'quit))
    ;; Two clauses: the seven-slot shape this change introduces, and the
    ;; old six-slot one, so a regression to six is reported as such
    ;; rather than as a hang.
    (let ((msg (receive (after 20000 (display "FAIL no-quarantine-notice\n") (exit 1))
                 (`#(event-quarantined ,name ,kind ,seq ,why ,failures ,rkind)
                   (list 'event-quarantined name kind seq why failures rkind))
                 (`#(event-quarantined ,name ,kind ,seq ,why ,failures)
                   (list 'event-quarantined name kind seq why failures)))))
      (inject-disarm!)
      ;; ---- R8-1 the observer message has a seventh slot naming the kind
      (check "observer message carries seven slots" (= (length msg) 7) (length msg))
      (check "the seventh slot is the reason kind, 'raised on the poison path"
             (and (= (length msg) 7) (eq? (list-ref msg 6) 'raised)) msg)
      ;; `why` keeps its old meaning: the object that was raised
      (check "`why` (slot 5) is still the raised object, not a record"
             (and (>= (length msg) 6) (not (quarantine-reason? (list-ref msg 4)))) (list-ref msg 4))
      ;; ---- R8-2 the dead letter's reason position is the private record
      (let* ((dl (node-dead-letters)) (r (and (pair? dl) (vector-ref (car dl) 3))))
        (check "node-dead-letters reason position is a quarantine-reason record" (quarantine-reason? r) r)
        (check "its kind is 'raised" (and (quarantine-reason? r) (eq? (quarantine-reason-kind r) 'raised)))
        (check "its payload is the raised object (a condition)"
               (and (quarantine-reason? r) (condition? (quarantine-reason-payload r))))
        ;; ---- R8-3 unforgeable: the constructor is not exported
        (check "make-quarantine-reason is not reachable from outside"
               (guard (e (#t #t)) (eval 'make-quarantine-reason (environment '(igropyr node))) #f))))
    (rsend 'b 'svc (vector 'quit))
    (sleep-ms 300)
    (if (zero? failures) (begin (display "ALL QUARANTINE-REASON TESTS PASSED\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
