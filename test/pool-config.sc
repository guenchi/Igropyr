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
    (if (zero? fails)
        (begin (display "pool config validation: all tests passed\n") (exit 0))
        (begin (display fails) (display " failures\n") (exit 1)))))
