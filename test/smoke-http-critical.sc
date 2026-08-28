#!chezscheme
;;; The HTTP pool supervisor is marked critical, and the mark is WIRED.
;;;
;;; test/pool-config.sc owns what critical! does; test/smoke-critical-
;;; failure.sc owns the sentinel's rule. Neither owns the one line in
;;; http.sc that connects them, and a cell that owns a part does not own
;;; the wiring: delete (critical! sup ...) from http-listen and both of
;;; those suites stay green while a lost pool silently stops being fatal.
;;; This suite exists for that line and nothing else.
;;;
;;; It runs as its own OS process because the assertion IS a process exit:
;;; the runner checks status 70 and a panic naming the pool.
;;;
;;; The pid comes from http-server-sup, which is exported as a CONTROL
;;; capability -- holding it is authority, not a reading. This suite is the
;;; use that argues for it: killing the real supervisor is the only way to
;;; test that the marking is wired, and simulating it would test the
;;; simulation. An earlier version of this comment called the accessor
;;; introspection and argued that http-stats already read the value; both
;;; halves were wrong, and an internal dependency is not public access.
(import (chezscheme) (igropyr http))

(start-scheduler
  (lambda ()
    (let ((srv (http-listen 18099
                 (lambda (req res) (send-response! res 200 "ok"))
                 '((workers . 2) (host . "127.0.0.1")))))
      (sleep-ms 200)
      ;; the supervisor dies the way a crash would leave it: not normally,
      ;; and with nobody to replace it
      (kill (http-server-sup srv) 'simulated-crash)
      (sleep-ms 2000)
      (display "STILL ALIVE\n")            ; must be unreachable
      (exit 1))))
