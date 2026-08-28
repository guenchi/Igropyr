#!chezscheme
;;; A critical component's death must take the whole process down.
;;;
;;; critical! marks a process the image depends on -- the worker pool's
;;; supervisor, a listener. The sentinel (process #1) already watches
;;; boot with almost this rule; critical! generalises the watch from one
;;; process to a set. The difference from boot: a critical component that
;;; exits for ANY reason, 'normal included, panics the process. A pool
;;; supervisor or a listener never returns in normal operation, so a
;;; return is not a deliberate stop -- it is a regression that ran a
;;; loop off its end, and tolerating it would leave the process passing
;;; health checks with nothing serving, the half-dead state this library
;;; refuses. To stop a critical component on purpose, clear the mark
;;; first with uncritical!; "not critical any more" is a state change
;;; made explicitly, not inferred from how the process happened to end.
;;;
;;; This runs as its own OS process because the assertion IS a process
;;; exit: the runner checks status 70 and a panic naming the component.
;;;
;;; Two things in sequence. First uncritical! REMOVES the guard: a marked
;;; component that is un-marked and then stops must NOT panic -- the
;;; process stays alive to reach the second half. Second, a still-marked
;;; component that exits 'normal MUST panic, named. If the panic fired in
;;; the first half instead it would name 'stoppable, and the runner --
;;; which asserts the panic names 'test-critical -- would catch it.
(import (chezscheme) (igropyr actor))

(start-scheduler
  (lambda ()
    ;; uncritical! clears the mark: a normal exit after it is not fatal
    (let ((stoppable (spawn (lambda () (receive (`#(stop) 'ok))))))
      (critical! stoppable 'stoppable)
      (uncritical! stoppable)
      (send stoppable (vector 'stop))          ; exits 'normal, un-marked
      (sleep-ms 200))                          ; must outlive it
    ;; a still-marked component that returns 'normal is a fatal regression
    (let ((vital (spawn (lambda () 'done))))    ; exits 'normal, still marked
      (critical! vital 'test-critical)
      (sleep-ms 2000)
      (display "STILL ALIVE\n")                 ; must be unreachable
      (exit 1))))
