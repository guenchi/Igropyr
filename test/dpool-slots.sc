#!chezscheme
;;; (igropyr dpool) worker slot accounting: a task's slot must be reclaimed
;;; even when the task never reports back.
;;;
;;; run! only sends #(slot-free) at the end of its body, and its guard
;;; catches a raise -- not a kill, and not a handler that never returns. A
;;; worker that trusted that message alone leaked the slot permanently, and
;;; after `max-concurrency` such tasks the node kept ACCEPTING work while
;;; executing none of it, with nothing on either side reporting a fault.
;;; The worker now monitors each task (a DOWN reclaims the slot) and can be
;;; given a per-task timeout (which kills the task, producing that DOWN).
;;;
;;; Single node: tasks are dispatched to the worker directly and results
;;; come back through rsend to this node, which delivers locally.

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr dpool))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(start-scheduler
  (lambda ()
    (node-start! 'solo "slots-secret" 18094)
    (let ((main self))
      ;; collector: every task result lands here
      (register 'collector
        (spawn (lambda ()
                 (let loop () (receive (m (send main m) (loop)))))))

      ;; ---- 1. a task KILLED mid-run must still free its slot ------------
      ;; cap 1, so the second task can only run if the first one's slot came
      ;; back. The handler parks forever and reports its own pid first.
      (dpool-worker-start 'w-kill
        (lambda (payload)
          (if (eq? payload 'park)
              (begin (send (whereis 'collector) (vector 'parked self))
                     (receive (`#(never) 'unreachable)))   ; never returns
              (begin (send (whereis 'collector) (vector 'ran payload))
                     payload)))
        1)
      (let ((w (whereis 'w-kill)))
        (send w (vector 'dtask 1 'solo 'collector 'park 't1))
        (let ((victim (receive (after 5000 #f) (`#(parked ,p) p))))
          (check "task started and holds the only slot" (and victim #t))
          ;; queue a second task: it must NOT run while the slot is held
          (send w (vector 'dtask 2 'solo 'collector 'second 't2))
          (check "queued task does not run while the slot is held"
            (not (receive (after 700 #f) (`#(ran ,x) x))))
          ;; kill the parked task: no #(slot-free) is ever sent
          (kill victim 'test-kill)
          (check "slot reclaimed on DOWN -> queued task runs"
            (eq? 'second (receive (after 5000 #f) (`#(ran ,x) x))))))

      ;; ---- 2. a per-task timeout reaps a handler that never returns -----
      (dpool-worker-start 'w-timeout
        (lambda (payload)
          (if (eq? payload 'park)
              (receive (`#(never) 'unreachable))
              (begin (send (whereis 'collector) (vector 'ran payload))
                     payload)))
        1 1200)                                  ; task-timeout-ms
      (let ((w (whereis 'w-timeout)))
        (send w (vector 'dtask 3 'solo 'collector 'park 't3))
        (sleep-ms 200)
        (send w (vector 'dtask 4 'solo 'collector 'after-timeout 't4))
        (check "stuck task is reaped and its slot freed"
          (eq? 'after-timeout (receive (after 8000 #f) (`#(ran ,x) x)))))

      ;; ---- 3. the normal path still frees exactly one slot --------------
      ;; (a double release would let cap+1 tasks run at once)
      (dpool-worker-start 'w-normal
        (lambda (payload)
          (send (whereis 'collector) (vector 'ran payload))
          payload)
        1)
      (let ((w (whereis 'w-normal)))
        (do ((i 0 (+ i 1))) ((= i 5))
          (send w (vector 'dtask (+ 10 i) 'solo 'collector (+ 100 i) 'tok)))
        (let count ((n 0))
          (let ((r (receive (after 4000 #f) (`#(ran ,x) x))))
            (if r (count (+ n 1))
                (check "all queued tasks drained through one slot" (= n 5))))))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "dpool-slots: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
