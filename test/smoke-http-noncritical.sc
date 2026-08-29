#!chezscheme
;;; The 'critical option is WIRED, in the direction smoke-http-critical
;;; cannot see: a listener that opted out loses its pool and the image
;;; SURVIVES. That suite owns the default (pool death is fatal); this one
;;; owns the opt-out line -- ignore the option and this process exits 70
;;; exactly like the default case, which the runner reads as the failure
;;; it is. Port 18098, so the two fixtures can never collide.
;;;
;;; What survival means here is stated by the option's own comment: the
;;; port stays open and stops working. This fixture only asserts the
;;; choice was honored -- the process outlives its pool -- not that the
;;; outcome is pleasant.
(import (chezscheme) (igropyr http))

(start-scheduler
  (lambda ()
    (let ((srv (http-listen 18098
                 (lambda (req res) (send-response! res 200 "ok"))
                 '((workers . 2) (host . "127.0.0.1") (critical . #f)))))
      (sleep-ms 200)
      (kill (http-server-sup srv) 'simulated-crash)
      (sleep-ms 500)
      ;; THE POOL'S DEATH IS PINNED BEFORE SURVIVAL MEANS ANYTHING: exit
      ;; 0 alone is also satisfied by a kill that never landed or a pid
      ;; taken from the wrong place -- the image survives trivially when
      ;; nothing died. pool-alive?'s false answer is conclusive by its
      ;; own contract, so requiring it first makes the green uniquely
      ;; attributable to the opt-out, not to an unexecuted fixture.
      (when (http-server-pool-alive? srv)
        (display "POOL NEVER DIED\n")
        (exit 1))
      (sleep-ms 1500)
      ;; reaching here IS the assertion: the sentinel did not end us
      (display "SURVIVED WITHOUT THE POOL\n")
      (exit 0))))
