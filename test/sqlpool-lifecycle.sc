#!chezscheme
;;; (igropyr sqlpool) waiter lifecycle, against FAKE connection workers.
;;;
;;; sql-pool-loop takes spawn-conn! as an argument, so the whole pool can be
;;; driven with stand-in processes that speak the db-* protocol and never
;;; touch a database. That is what makes these cases runnable everywhere --
;;; they are about the pool's bookkeeping, not about SQL.
;;;
;;; What is pinned here is the queued-waiter window. A caller that dies or
;;; times out WHILE QUEUED was invisible to the pool: nothing monitored it
;;; until it was handed a connection.

(import (chezscheme) (igropyr actor) (igropyr sqlpool))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define cfg
  (make-sql-cfg
    (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'fake-error)))
    (vector 'fake-error "lost")
    (vector 'fake-error "closed")
    (vector 'fake-error "query timeout")
    (vector 'fake-error "checkout timeout")
    "BEGIN"))

;; How many connection workers the pool has spawned over its lifetime. A
;; rebuild spawns another, so this counts destroy+rebuild cycles.
(define spawned 0)
(define (bump!) (set! spawned (+ spawned 1)))

;; A stand-in connection: reports up, waits to be adopted, then answers
;; queries instantly and pings idle, exactly like a driver worker.
(define (fake-spawn-conn! notify report-to ref)
  (bump!)
  (spawn
    (lambda ()
      (send report-to (vector 'db-up ref self 'ok))
      (receive (`#(db-adopt) 'ok))
      (let loop ()
        (receive
          (`#(db-query ,sql ,r ,from)
            (send from (vector 'db-reply r (vector 'fake-rows sql)))
            (send notify (vector 'db-idle self))
            (loop))
          (`#(db-quit) 'done))))))

(start-scheduler
  (lambda ()
    ;; ---- a caller that dies while queued must not cost a connection ------
    ;;
    ;; One connection, held by a transaction lease, so a second checkout has
    ;; to queue. Kill the queued caller; then release the lease. The pool now
    ;; hands the freed connection to a dead pid -- and monitor on a dead
    ;; process delivers DOWN at once (actor.sc), which the pool reads as "a
    ;; borrower died holding this, it may carry a half-open transaction" and
    ;; destroys a connection the dead caller never touched.
    (set! spawned 0)
    (let* ((pool (spawn (lambda () (sql-pool-loop 1 fake-spawn-conn! cfg))))
           (me self))
      (sleep-ms 200)
      (check "pool spawned one connection" (= spawned 1))

      ;; holder takes the only connection as a lease
      (let ((holder (spawn (lambda ()
                             (let ((r (gensym)))
                               (send pool (vector 'db-checkout r self))
                               (receive
                                 (`#(db-checkout-reply ,@r ,c)
                                   (send me (vector 'held c))
                                   ;; hold until told to release
                                   (receive (`#(release) (void)))
                                   (send pool (vector 'db-checkin self c))
                                   (send me (vector 'released)))))))))
        (let ((conn (receive (after 2000 #f) (`#(held ,c) c))))
          (check "holder leased the only connection" (and conn #t))

          ;; a second caller queues behind it, then dies while queued
          (let ((victim (spawn (lambda ()
                                 (let ((r (gensym)))
                                   (send pool (vector 'db-checkout r self))
                                   (send me (vector 'queued))
                                   (receive (`#(never) (void))))))))
            (receive (after 2000 (void)) (`#(queued) 'ok))
            (sleep-ms 100)
            (monitor victim)
            (kill victim 'died-while-queued)
            (receive (after 2000 (void)) (`#(DOWN ,@victim ,_) 'ok))
            (sleep-ms 100)

            (let ((before spawned))
              ;; release the lease -- the pool now looks for someone to give
              ;; the connection to, and the only waiter is the dead one
              (send holder (vector 'release))
              (receive (after 2000 (void)) (`#(released) 'ok))
              (sleep-ms 300)
              (check "a waiter that died while queued costs no connection"
                (= spawned before))))

          ;; and the pool must still work afterwards
          (let ((r (gensym)))
            (send pool (vector 'db-query "SELECT 1" r self))
            (check "pool still serves queries"
              (receive (after 2000 #f)
                (`#(db-reply ,@r ,v) (and (vector? v)
                                          (eq? (vector-ref v 0) 'fake-rows))))))))
      (send pool (vector 'db-close)))

    ;; ---- a timed-out query must not execute later --------------------
    ;;
    ;; The pool has one connection and it is leased away, so the query can
    ;; only queue. sql-query's own timeout is 60 s, far too long for a test,
    ;; so the timeout is simulated exactly as sql-query performs it: send the
    ;; request, then send db-query-cancel. What is asserted is what the
    ;; caller's timeout is FOR -- that the statement never reaches a
    ;; connection afterwards. Before the cancel existed it ran as soon as the
    ;; pool recovered, applying a write the application had been told failed.
    (set! spawned 0)
    (let* ((executed (box '()))
           (spawn-recording
             (lambda (notify report-to ref)
               (bump!)
               (spawn
                 (lambda ()
                   (send report-to (vector 'db-up ref self 'ok))
                   (receive (`#(db-adopt) 'ok))
                   (let loop ()
                     (receive
                       (`#(db-query ,sql ,r ,from)
                         (set-box! executed (cons sql (unbox executed)))
                         (send from (vector 'db-reply r (vector 'fake-rows sql)))
                         (send notify (vector 'db-idle self))
                         (loop))
                       (`#(db-quit) 'done)))))))
           (pool (spawn (lambda () (sql-pool-loop 1 spawn-recording cfg))))
           (me self))
      (sleep-ms 200)
      (let ((holder (spawn (lambda ()
                             (let ((r (gensym)))
                               (send pool (vector 'db-checkout r self))
                               (receive
                                 (`#(db-checkout-reply ,@r ,c)
                                   (send me (vector 'held c))
                                   (receive (`#(release) (void)))
                                   (send pool (vector 'db-checkin self c))
                                   (send me (vector 'released)))))))))
        (receive (after 2000 (void)) (`#(held ,c) 'ok))

        (let ((r (gensym)))
          (send pool (vector 'db-query "INSERT INTO t VALUES (1)" r self))
          (sleep-ms 100)
          ;; the caller gives up, exactly as sql-query does on timeout
          (send pool (vector 'db-query-cancel r self)))

        ;; release the connection: the pool now looks for queued work
        (send holder (vector 'release))
        (receive (after 2000 (void)) (`#(released) 'ok))
        (sleep-ms 300)
        (check "a cancelled query never reaches a connection"
          (null? (unbox executed)))

        ;; and a fresh query still runs, so the cancel did not wedge the pool
        (let ((r2 (gensym)))
          (send pool (vector 'db-query "SELECT 2" r2 self))
          (check "pool still runs later queries"
            (receive (after 2000 #f) (`#(db-reply ,@r2 ,v) #t)))))
      (send pool (vector 'db-close)))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "sqlpool-lifecycle: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
