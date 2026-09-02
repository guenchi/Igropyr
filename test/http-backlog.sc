#!chezscheme
;;; http-listen's backlog is an option with a default, and both the value
;;; asked for and the value the kernel actually granted can be read back.
;;;
;;; Why this exists: the backlog was a literal (511, a habit inherited from
;;; nginx and Redis: 512 minus one for kernels that once rounded up), and
;;; the kernel truncates a listen backlog to kern.ipc.soacceptqueue at
;;; listen() time without saying so. Measured across two hosts: 400
;;; simultaneous connections passed under 511, 1500 were reset, and the
;;; only visible trace was a kernel counter. So the option is explicit, the
;;; default is 8192, and the effective value is read back where the
;;; platform can tell (FreeBSD: SO_LISTENQLIMIT; elsewhere #f -- reported,
;;; not guessed).
;;;
;;; Cells: default is 8192; a given value reads back as given; a bad value
;;; is refused at http-listen, not at some later accept; the effective
;;; value is either #f (platform cannot say) or a positive fixnum no
;;; larger than the request. On FreeBSD with soacceptqueue below the
;;; request the last cell reads the truncated number -- that run is done
;;; on the servers and recorded in the ledger, not here.
(import (chezscheme) (igropyr actor) (igropyr http))   ; process-count and http-shutdown! are both exported

(define (fail label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline) (exit 1))
;; The process count is read when it is STABLE, not after a guessed sleep:
;; worker pools spawn asynchronously, and a fixed wait either under-waits
;; on a slow machine (a false red) or over-waits on a fast one. Stability
;; -- two consecutive equal readings -- is the criterion, the rounds it
;; took are printed so a slowdown shows up as a number, and a count that
;; never settles is reported as broken, not as a pass or a red.
(define (stable-process-count! label)
  (let poll ((prev (process-count)) (rounds 0))
    (sleep-ms 50)
    (let ((now (process-count)))
      (cond ((= now prev)
             (display "  process count stable at ") (display now)
             (display " after ") (display (+ rounds 1)) (display " rounds\n")
             now)
            ((>= rounds 100)
             (display "💥 BROKEN ") (display label)
             (display ": process count never settled (") (display prev) (display " -> ")
             (display now) (display ")\n") (exit 1))
            (else (poll now (+ rounds 1)))))))
(define (handler req res) (res-send! res (string->utf8 "ok")))
(define base-port 18110)                ; two listeners succeed; the third port only ever sees refused calls

(start-scheduler
  (lambda ()
    ;; ---- default -------------------------------------------------------
    (let ((srv (http-listen base-port handler '((host . "127.0.0.1") (workers . 1)))))
      (unless (eqv? (http-server-backlog srv) 8192)
        (fail "default-backlog" (http-server-backlog srv) 'want 8192))
      (let ((eff (http-server-backlog-effective srv)))
        (unless (or (not eff) (and (fixnum? eff) (fx> eff 0) (fx<= eff 8192)))
          (fail "effective-shape" eff))
        (display "backlog default 8192, effective ") (display eff) (display " ok\n")))
    ;; ---- given value reads back as given ---------------------------------
    (let ((srv (http-listen (+ base-port 1) handler
                 '((host . "127.0.0.1") (workers . 1) (backlog . 64)))))
      (unless (eqv? (http-server-backlog srv) 64)
        (fail "given-backlog-not-read-back" (http-server-backlog srv) 'want 64))
      (let ((eff (http-server-backlog-effective srv)))
        (unless (or (not eff) (and (fixnum? eff) (fx> eff 0) (fx<= eff 64)))
          (fail "effective-exceeds-request" eff)))
      (display "backlog option 64 reads back 64 ok\n"))
    ;; ---- a bad value is refused where it was written, and leaves nothing --
    ;; The refusal has to come before anything is created: a check placed
    ;; after the worker pool starts would refuse and leave the pool running.
    ;; The process count before and after is the reading for that. Values
    ;; above a C int are bad too: they pass fixnum? and arrive in listen()
    ;; wrapped negative.
    (for-each
      (lambda (bad)
        (let* ((procs0 (stable-process-count! "baseline"))
               (refused (guard (e (#t #t))
                          (http-listen (+ base-port 2) handler
                            (list (cons 'host "127.0.0.1") (cons 'workers 1) (cons 'backlog bad)))
                          #f)))
          (unless refused (fail "bad-backlog-accepted" bad))
          (let ((procs1 (stable-process-count! "after-refusal")))
            (unless (= procs1 procs0)
              (fail "refusal-left-processes-behind" bad 'procs procs1 'before procs0)))))
      (list 0 -1 "many" 1.5 2147483648 4294967296))
    (display "bad backlog values refused at http-listen, nothing left behind ok\n")
    ;; ---- after shutdown the effective value is #f, not a read of a freed handle
    ;; The listener handle is freed by its close callback; a read after
    ;; shutdown must see the field cleared, never the stale pointer.
    (let ((srv (http-listen (+ base-port 3) handler '((host . "127.0.0.1") (workers . 1)))))
      (http-shutdown! srv)
      (sleep-ms 200)
      (let ((eff (http-server-backlog-effective srv)))
        (unless (not eff) (fail "effective-after-shutdown" eff)))
      (unless (eqv? (http-server-backlog srv) 8192)
        (fail "requested-after-shutdown" (http-server-backlog srv))))
    (display "effective backlog after shutdown is #f ok\n")
    (display "ALL HTTP BACKLOG TESTS PASSED\n")
    (exit 0)))
