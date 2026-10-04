#!chezscheme
;;; test/dpool-timeout.sc -- a task the worker kills for outstaying its
;;; timeout still ends in ONE terminal result for its caller.
;;;
;;; The worker reaps a task that runs past task-timeout-ms by killing its
;;; process; the DOWN that produces frees the slot. But a kill skips the
;;; paths that report a result, so the coordinator never heard that the
;;; task ended: the caller's dpool-await ran out its own clock and raised
;;; await-timeout, and the task stayed on the books as in flight. Two
;;; timeouts for one event, and the honest one -- "your task was killed" --
;;; was the one never sent.
;;;
;;; The rows ask for: a terminal error that is NOT await-timeout, well
;;; inside the await window; the task gone from inflight; the slot free, so
;;; the next task runs; and exactly one answer, so a result that raced the
;;; kill is not answered twice.
;;;
;;; The kind is `task-killed`: the await raises #(dpool-error task-killed id)
;;; and the rows ask for that kind, not merely "something other than
;;; await-timeout".
;;;
;;; Not asked here: a second await of an id whose result was already taken
;;; waits for its whole window, as it always has for an id the coordinator
;;; does not know -- that is the await contract, not this defect.
;;;
;;; The report does not depend on the DOWN's reason: a handler can end its
;;; own process with (kill self 'normal) before answering, and a worker
;;; that took `normal` for "the result was already shipped" would leave
;;; that caller to await-timeout as before. What says the task answered is
;;; its entry being gone from the worker's live table (the task frees its
;;; slot only after shipping its result), not the reason. The last rows
;;; read exactly that case. In dpool-stats, `live` counts live NODES, not
;;; tasks; this single node is always 1.
;;;
;;; Single node, as dpool-slots.sc: the coordinator and the worker are
;;; both here, dispatch and results travel through this node.

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr dpool))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define (stat s key) (let ((p (assq key s))) (and p (cdr p))))

;; -> (ok . value) | (error . kind) | (raised . e), with the elapsed ms
(define (awaited pool id ms)
  (let* ((t0 (real-time))
         (r (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'dpool-error))
                       (cons 'error (vector-ref e 1)))
                      (#t (cons 'raised e)))
              (cons 'ok (dpool-await pool id ms)))))
    (values r (- (real-time) t0))))

(start-scheduler
  (lambda ()
    (node-start! 'solo "timeout-secret" 18097)
    (let ((main self))
      ;; the handler: 'park never returns; 'quick answers; 'raise raises
      (dpool-worker-start 'w-slow
        (lambda (payload)
          (cond ((eq? payload 'park) (receive (`#(never) 'unreachable)))
                ((eq? payload 'raise) (raise 'handler-raised))
                ((eq? payload 'quit-normal) (kill self 'normal))
                (else (list 'done payload))))
        1 400)
      (let ((pool (dpool-start '(solo) 'w-slow)))
        (sleep-ms 100)

        ;; ---- twin: a quick task answers normally ------------------------------
        (let-values (((r ms) (awaited pool (dpool-submit pool 'quick) 5000)))
          (check "twin: a task that returns is awaited as its value" (equal? r '(ok . (done quick))) r))
        ;; ---- twin: a handler that raises answers task-error (the existing path) --
        (let-values (((r ms) (awaited pool (dpool-submit pool 'raise) 5000)))
          (check "twin: a handler that raises is awaited as task-error" (equal? r '(error . task-error)) r))

        ;; ---- the task that outstays its timeout --------------------------------
        ;; task-timeout 400 ms, reaped on a 1000 ms tick: killed by ~1.4 s. The
        ;; await window is 6 s, so an answer before 4 s came from the kill, not
        ;; from this clock running out.
        (let* ((id (dpool-submit pool 'park)))
          (let-values (((r ms) (awaited pool id 6000)))
            (check "a reaped task is awaited as dpool-error task-killed"
                   (equal? r '(error . task-killed)) r)
            (check "  and that error arrives from the kill, well inside the await window"
                   (< ms 4000) ms)
            (display "  [info] terminal error ") (write r) (display " after ") (display ms) (display " ms\n"))
          (sleep-ms 200)
          (let ((s (dpool-stats pool)))
            (check "after it, the task is no longer in flight" (eqv? (stat s 'inflight) 0) s))
          ;; the slot is free: the next task runs at once
          (let-values (((r ms) (awaited pool (dpool-submit pool 'after) 5000)))
            (check "the slot the kill freed runs the next task" (equal? r '(ok . (done after))) r)
            (check "  promptly (not after another reap tick)" (< ms 900) ms)))

        ;; ---- exactly one answer when a result races the kill ---------------------
        ;; The reaper runs on a tick of max(1000, timeout/2) ms, and kills
        ;; every task older than the timeout at that moment. With a 300 ms
        ;; timeout the first tick, about one second after the worker started,
        ;; reaps everything still running -- so tasks finishing just around
        ;; that second race their own kill. Every await must return exactly
        ;; once, as a value or as task-killed, never await-timeout; some of
        ;; each must occur (else the race was not run); the books must be
        ;; clean afterwards.
        (dpool-worker-start 'w-edge
          (lambda (payload) (sleep-ms payload) (list 'done payload))
          8 300)
        (let ((edge (dpool-start '(solo) 'w-edge)))
          (sleep-ms 100)
          (let* ((ids (map (lambda (ms) (dpool-submit edge ms)) '(700 820 860 890 920 950 1000 1300)))
                 (answers (map (lambda (id)
                                 (let-values (((r ms) (awaited edge id 6000))) r))
                               ids)))
            (check "every racing task is answered, as a value or task-killed, never await-timeout"
                   (for-all (lambda (r) (or (eq? (car r) 'ok) (equal? r '(error . task-killed)))) answers)
                   answers)
            (check "  and the race was run: at least one finished (700 ms) and at least one was killed (1300 ms)"
                   (and (exists (lambda (r) (eq? (car r) 'ok)) answers)
                        (exists (lambda (r) (equal? r '(error . task-killed))) answers))
                   answers)
            (display "  [info] answers ") (write answers) (newline)
            (sleep-ms 1500)
            (let ((s (dpool-stats edge)))
              (check "and the books are clean: nothing in flight (live = this one node)"
                     (and (eqv? (stat s 'inflight) 0) (eqv? (stat s 'live) 1)) s))))

        ;; ---- a handler that ends its own process with reason `normal` --------------
        ;; No result was shipped, so the caller must still get task-killed --
        ;; promptly, from the DOWN, not from a reaper tick or its own clock.
        (let-values (((r ms) (awaited pool (dpool-submit pool 'quit-normal) 6000)))
          (check "a handler that kills its own process with reason normal is awaited as task-killed"
                 (equal? r '(error . task-killed)) r)
          (check "  promptly, from the DOWN (not the reaper tick, not the await clock)" (< ms 900) ms))
        (let-values (((r ms) (awaited pool (dpool-submit pool 'after-quit) 5000)))
          (check "  and its slot is free for the next task" (equal? r '(ok . (done after-quit))) r))

        (if (zero? failures)
            (begin (display "dpool-timeout: all tests passed\n") (exit 0))
            (begin (display "dpool-timeout: ") (display failures) (display " failed\n") (exit 1)))))))
