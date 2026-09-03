#!chezscheme
;;; monitor and demonitor each write BOTH sides, and both writes matter.
;;;
;;; A monitor is one record filed in two places: the watcher's list and
;;; the watched process's. The DOWN is sent by walking the WATCHED
;;; process's list when it exits, so a record that reached only the
;;; watcher's side is a watch that will never fire while its owner goes on
;;; believing it is watching. demonitor has the same shape in reverse: a
;;; removal that reaches only one side leaves a record that either fires
;;; after it was cancelled or is never collected.
;;;
;;; Each function makes two writes with an allocation between them, so
;;; either half can be the one that does not happen. Nothing in the
;;; library compares the two sides -- the counts are per process and are
;;; free to differ -- so there is no invariant to assert, only this: for
;;; THIS pair of processes, arming moves both counts up and disarming
;;; moves both back.
;;;
;;; FOUR ASSERTIONS, IN TWO OPPOSED PAIRS. Two say a count rose, two
;;; say it returned. A count that never moved would satisfy the returning
;;; pair on its own, so the rising pair is what makes them mean anything;
;;; and a count that rose and stayed would satisfy the rising pair, so the
;;; returning pair is what makes THOSE mean anything.
;;;
;;; WHAT THIS DOES NOT COVER. The failure this shape produces in
;;; practice is an allocation that fails between the two writes, which
;;; nothing here can ask for; these assertions catch an edit that drops a
;;; write, not a machine that runs out of memory. link/spawn&link have the
;;; same two-sided shape and are NOT covered at all: there is no exported
;;; count on that side to read.

(import (chezscheme) (igropyr actor))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "  FAIL  ") (display label) (newline))))

(start-scheduler
  (lambda ()
    (let ((target (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void)))))))
      (let ((self-base (process-monitor-count self))
            (targ-base (process-monitor-count target)))
        (let ((m (monitor target)))
          (check "arming files the record on the watcher's side"
            (= (process-monitor-count self) (+ self-base 1)))
          (check "arming files the record on the watched side"
            (= (process-monitor-count target) (+ targ-base 1)))
          (demonitor m)
          (check "disarming removes it from the watcher's side"
            (= (process-monitor-count self) self-base))
          (check "disarming removes it from the watched side"
            (= (process-monitor-count target) targ-base)))
        (kill target 'done)))
    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "monitor-symmetry: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
