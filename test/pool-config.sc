#!chezscheme
;;; Pool capacity/timing settings are refused at startup, not absorbed.
;;;
;;; Each of these fails SILENTLY when it is out of range, which is the
;;; reason to check rather than trust: workers=0 starts a listener that
;;; accepts requests and queues them forever; a negative check-ms kills the
;;; ticker immediately, so stuck-worker detection disappears while the pool
;;; still looks healthy; a negative or fractional pool size never satisfies
;;; the (= i n) that ends the connect loop, so it spawns connection workers
;;; without end. None announces itself -- each surfaces much later as "the
;;; service stopped responding", with nothing pointing at the cause.

(import (chezscheme) (igropyr actor) (igropyr otp) (igropyr connpool)
        (igropyr mysql) (igropyr postgresql))
(define fails 0)
(define (rejects? label thunk)
  (let ((ok (guard (e ((assertion-violation? e) #t) (#t #f)) (thunk) #f)))
    (if ok (begin (display "  ok  ") (display label) (newline))
        (begin (set! fails (+ fails 1))
               (display "FAIL  ") (display label) (newline)))))
(define cfg (make-connpool-cfg (lambda (r) #f) 'l 'c 'q 'k "BEGIN"))
(start-scheduler
  (lambda ()
    (rejects? "workers=0"    (lambda () (start-worker-pool 0 (lambda (t) t) (lambda (t i) t))))
    (rejects? "workers=-1"   (lambda () (start-worker-pool -1 (lambda (t) t) (lambda (t i) t))))
    (rejects? "workers=2.5"  (lambda () (start-worker-pool 2.5 (lambda (t) t) (lambda (t i) t))))
    (rejects? "max-retries=-1" (lambda () (start-worker-pool 2 (lambda (t) t) (lambda (t i) t) -1)))
    (rejects? "stuck-ms=0"   (lambda () (start-worker-pool 2 (lambda (t) t) (lambda (t i) t) 3 0)))
    (rejects? "check-ms=-5"  (lambda () (start-worker-pool 2 (lambda (t) t) (lambda (t i) t) 3 30000 -5)))
    (rejects? "sql pool n=0"  (lambda () (connpool-loop 0 (lambda (a b c) #f) cfg)))
    (rejects? "sql pool n=-3" (lambda () (connpool-loop -3 (lambda (a b c) #f) cfg)))
    (rejects? "sql pool n=1.5"(lambda () (connpool-loop 1.5 (lambda (a b c) #f) cfg)))
    ;; The three above call connpool-loop DIRECTLY, so the check runs in this
    ;; process and raises here. That is not how an application creates a
    ;; pool: mysql-pool and postgresql-pool spawn the loop and hand back a
    ;; pid, so the same check ran inside a process the caller cannot see --
    ;; a bad size returned a pid that died a moment later, and the mistake
    ;; surfaced as a pool that answered nothing rather than as an error where
    ;; it was written. These go through the public constructors.
    (rejects? "mysql-pool n=0"
      (lambda () (mysql-pool 0 "127.0.0.1" 3306 "u" "p")))
    (rejects? "mysql-pool n=-1"
      (lambda () (mysql-pool -1 "127.0.0.1" 3306 "u" "p")))
    (rejects? "mysql-pool n=2.5"
      (lambda () (mysql-pool 2.5 "127.0.0.1" 3306 "u" "p")))
    (rejects? "postgresql-pool n=0"
      (lambda () (postgresql-pool 0 "127.0.0.1" 5432 "u" "p")))
    (rejects? "postgresql-pool n=-1"
      (lambda () (postgresql-pool -1 "127.0.0.1" 5432 "u" "p")))
    (rejects? "postgresql-pool n=2.5"
      (lambda () (postgresql-pool 2.5 "127.0.0.1" 5432 "u" "p")))
    ;; retryable? is APPLICATION code called from the supervisor's own DOWN
    ;; path, so a non-procedure there is a crash at the worst moment
    (rejects? "retryable? not a procedure"
      (lambda () (start-worker-pool 2 (lambda (t) t) (lambda (t i) t)
                                    3 30000 5000 'not-a-procedure)))

    ;; critical! must reject a non-symbol name at the CALL, not absorb it.
    ;; #f is the worst case: the sentinel stores pid->name and reads the
    ;; table with (hashtable-ref crit p #f), so a #f name is indexed and
    ;; then read back as "absent" -- the DOWN of a critical component is
    ;; silently ignored, the exact failure this mechanism exists to catch.
    ;; A synchronous check at the call is fail-fast where the mistake is
    ;; written; the table also separates presence from value as depth.
    (rejects? "critical! rejects #f name"
      (lambda () (critical! (spawn (lambda () (receive (`#(x) 'ok)))) #f)))
    (rejects? "critical! rejects string name"
      (lambda () (critical! (spawn (lambda () (receive (`#(x) 'ok)))) "pool")))

    ;; ...and one that RAISES must not take the supervisor with it. The
    ;; supervisor is the one process whose death orphans every worker and
    ;; the ticker, so a raise is read as "not retryable" -- the task has
    ;; already crashed once, and a predicate that cannot answer is not a
    ;; reason to run it again.
    (let* ((failed (box #f))
           (sup (start-worker-pool 1
                  (lambda (t) (raise 'task-boom))
                  (lambda (t info) (set-box! failed info))
                  3 30000 5000
                  (lambda (t) (raise 'retry-policy-boom)))))
      (send sup (vector 'submit-task (vector 'task 1 #f #f)))
      (sleep-ms 600)
      (if (and (process-alive? sup) (unbox failed))
          (display "  ok  a raising retryable? does not kill the supervisor\n")
          (begin (set! fails (+ fails 1))
                 (display "FAIL  a raising retryable? does not kill the supervisor")
                 (display " (alive=") (display (process-alive? sup))
                 (display " failed=") (display (and (unbox failed) #t))
                 (display ")\n")))
      ;; and it still serves afterwards
      (let ((ran (box #f)))
        (let ((sup2 (start-worker-pool 1
                      (lambda (t) (set-box! ran #t))
                      (lambda (t info) (void)))))
          (send sup2 (vector 'submit-task (vector 'task 2 #f #f)))
          (sleep-ms 300)
          (if (unbox ran)
              (display "  ok  a fresh pool still runs tasks\n")
              (begin (set! fails (+ fails 1))
                     (display "FAIL  a fresh pool still runs tasks\n"))))))

    ;; ---- a pool's parts follow their supervisor down (C2) --------------
    ;; The supervision ran one way only: the sup monitored workers, nothing
    ;; watched the sup. Kill it and the workers and ticker kept running --
    ;; refill and stuck-detection silently gone while the process stayed
    ;; green. Now each part monitors the sup and exits when it dies.

    ;; workers die with the sup. Three BLOCKING tasks pin all three
    ;; workers so each reports its own pid; release them BEFORE the kill,
    ;; because a worker parked inside run-task cannot see a DOWN (that is
    ;; the documented residual, not the behaviour under test).
    (let* ((me self)
           (sup (start-worker-pool 3
                  (lambda (t) (send me (vector 'wp self))
                              (receive (`#(go) 'ok)))
                  (lambda (t i) (void)))))
      ;; run-task only runs when a task is dispatched, so without these
      ;; the three #(wp pid) are never sent and collect times out BEFORE
      ;; the orphan check -- red in the right direction but at the wrong
      ;; point. Submit one per worker to pin all three, then collect.
      (do ((i 0 (+ i 1))) ((= i 3))
        (send sup (vector 'submit-task (vector 'task i #f #f))))
      (let collect ((pids '()))
        (if (= (length pids) 3)
            (begin
              (for-each (lambda (w) (send w (vector 'go))) pids)
              (sleep-ms 200)
              (kill sup 'boom)
              (let wait ((left pids) (n 0))
                (cond ((null? left)
                       (display "  ok  workers follow their supervisor\n"))
                      ((= n 60)
                       (set! fails (+ fails 1))
                       (display "FAIL  workers orphaned after sup death ")
                       (write (map process-alive? pids)) (newline))
                      ((process-alive? (car left)) (sleep-ms 50) (wait left (+ n 1)))
                      (else (wait (cdr left) n)))))
            (receive (after 3000
                       (set! fails (+ fails 1))
                       (display "FAIL  worker pid collect timeout\n"))
              (`#(wp ,w) (collect (cons w pids)))))))

    ;; the whole unit nets to zero: sup + ticker + n workers all gone.
    ;; This is the ONLY cell that can see the ticker -- its pid is never
    ;; exposed, so only the process count can account for it.
    (let ((p0 (process-count)))
      (let ((sup (start-worker-pool 2 (lambda (t) t) (lambda (t i) (void)))))
        (sleep-ms 100)
        (if (= (process-count) (+ p0 4))       ; sup + ticker + 2 workers
            (begin
              (kill sup 'boom)
              (let wait ((n 0))
                (cond ((= (process-count) p0)
                       (display "  ok  pool unit nets to zero after sup death\n"))
                      ((= n 60)
                       (set! fails (+ fails 1))
                       (display "FAIL  ticker or worker survives sup (count ")
                       (display (- (process-count) p0)) (display " over base)\n"))
                      (else (sleep-ms 50) (wait (+ n 1))))))
            (begin (set! fails (+ fails 1))
                   (display "FAIL  pool process accounting: expected +4, got +")
                   (display (- (process-count) p0)) (newline)))))

    ;; ---- a worker takes no NEW work once its supervisor is gone --------
    ;; The mailbox is FIFO and the DOWN clause must win over a queued
    ;; process-task: with the sup dead, nothing will receive task-completed,
    ;; retry a crash, or answer 500, so a queued task is orphan work whose
    ;; only trace is an untracked side effect. Deliver a task and the sup's
    ;; death into one worker's mailbox with no yield between, so both are
    ;; present when it next runs; the worker must consume the DOWN and exit,
    ;; not run the task. (A task already inside run-task cannot be pulled
    ;; back -- that is the residual; this is about work not yet begun.)
    (let* ((me self)
           (wbox (box #f))
           (sup (start-worker-pool 1
                  (lambda (t)
                    (set-box! wbox self)
                    (send me (vector 'ran (vector-ref t 1))))
                  (lambda (t i) (void)))))
      (send sup (vector 'submit-task (vector 'task 1 #f #f)))   ; primes the worker
      (receive (after 2000 (set! fails (+ fails 1))
                           (display "FAIL  queued-after-death: worker never ran\n"))
        (`#(ran 1) 'ok))
      (sleep-ms 100)                          ; let the worker park in receive
      (let ((w (unbox wbox)))
        ;; both messages land before the worker is scheduled again: the
        ;; direct process-task, then the DOWN kill produces synchronously
        (send w (vector 'process-task (vector 'task 2 #f #f)))
        (kill sup 'boom)
        (receive (after 700 'ok)              ; silence is the pass here
          (`#(ran 2)
            (set! fails (+ fails 1))
            (display "FAIL  queued-after-death: worker ran a task after sup died\n")))))
    (display "  ok  a worker takes no new work once its supervisor is gone\n")

    ;; ---- the DOWN clause must be the supervisor's, not any DOWN --------
    ;; run-task is application code: it can monitor other processes, and a
    ;; DOWN is an ordinary vector an application could even send by hand.
    ;; A #(DOWN _ _) pattern would let any of those retire the worker. The
    ;; clause must match the supervisor's pid specifically.
    (let* ((me self)
           (wbox (box #f))
           (sup (start-worker-pool 1
                  (lambda (t)
                    (set-box! wbox self)
                    (send me (vector 'ran (vector-ref t 1))))
                  (lambda (t i) (void)))))
      (send sup (vector 'submit-task (vector 'task 1 #f #f)))
      (receive (after 2000 (set! fails (+ fails 1))
                           (display "FAIL  down-pid: worker never ran\n"))
        (`#(ran 1) 'ok))
      (sleep-ms 100)
      (let ((w (unbox wbox)) (impostor (spawn (lambda () 'gone))))
        (send w (vector 'DOWN impostor 'forged))    ; not the sup's pid
        (sleep-ms 100)
        (if (process-alive? w)
            (begin
              ;; and it still serves: a real task still runs
              (send sup (vector 'submit-task (vector 'task 3 #f #f)))
              (receive (after 1000 (set! fails (+ fails 1))
                                   (display "FAIL  down-pid: worker wedged after forged DOWN\n"))
                (`#(ran 3) (display "  ok  a forged DOWN does not retire the worker\n"))))
            (begin (set! fails (+ fails 1))
                   (display "FAIL  down-pid: forged DOWN retired the worker\n")))))

    ;; ---- re-marking must not leak a monitor ---------------------------
    ;; A monitor leak has no behaviour: the extra watch just accumulates on
    ;; the marked process's pcb, and a DOWN it would produce is ignored once
    ;; the pid is gone from the sentinel's table. Counting is the only
    ;; witness. critical!/uncritical! act asynchronously, so let the
    ;; sentinel run between steps. p is watched by nothing but the sentinel.
    (let ((p (spawn (lambda () (receive (`#(x) 'ok))))))
      (sleep-ms 50)
      (let ((base (process-monitor-count p)))
        (critical! p 'a) (sleep-ms 50)
        (let ((one (process-monitor-count p)))
          (critical! p 'b) (sleep-ms 50)          ; re-mark: must not stack
          (let ((two (process-monitor-count p)))
            (uncritical! p) (sleep-ms 50)
            (let ((gone (process-monitor-count p)))
              (cond
                ((not (= one (+ base 1)))
                 (set! fails (+ fails 1))
                 (display "FAIL  monitor-count: critical! did not add exactly one\n"))
                ((not (= two (+ base 1)))
                 (set! fails (+ fails 1))
                 (display "FAIL  monitor-count: re-marking leaked a monitor\n"))
                ((not (= gone base))
                 (set! fails (+ fails 1))
                 (display "FAIL  monitor-count: uncritical! left a monitor behind\n"))
                (else
                 (display "  ok  re-marking does not leak a monitor\n"))))))))

    (if (zero? fails)
        (begin (display "pool config validation: all tests passed\n") (exit 0))
        (begin (display fails) (display " failures\n") (exit 1)))))
