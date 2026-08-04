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

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr sqlpool))

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

;; A stand-in that reports up, is adopted, and dies at once -- what a peer
;; that accepts and then drops the connection looks like from in here.
(define stillborn-spawns 0)
(define (stillborn-spawn-conn! notify report-to ref)
  (set! stillborn-spawns (+ stillborn-spawns 1))
  (spawn
    (lambda ()
      (send report-to (vector 'db-up ref self 'ok))
      (receive (`#(db-adopt) 'ok))
      'gone)))

;; A stand-in that comes up and then never answers anything: what is left
;; when only a deadline can end the call.
(define (mute-spawn-conn! notify report-to ref)
  (spawn
    (lambda ()
      (send report-to (vector 'db-up ref self 'ok))
      (receive (`#(db-adopt) 'ok))
      (let loop ()
        (receive
          (`#(db-quit) 'done)
          (`#(db-query ,sql ,r ,from) (loop))     ; swallowed on purpose
          (`#(db-query-cancel ,r ,from) (loop)))))))

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
      (send pool (vector (quote db-quit))))

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
      (send pool (vector (quote db-quit))))

    ;; ---- a queued QUERY whose caller dies --------------------------------
    ;;
    ;; The checkout path monitored its waiters; the plain query path did not,
    ;; so the caller-death cleanup below -- which does filter pending jobs by
    ;; caller -- never received the DOWN that would run it. A caller killed
    ;; by its supervisor also never runs its own timeout cancel, so the
    ;; statement stayed queued and executed whenever a connection freed up:
    ;; an INSERT applied on behalf of a process long dead.
    (let ((executed (box '())) (me self))
      (let ((pool (spawn (lambda ()
                           (sql-pool-loop 1
                             (lambda (notify report-to ref)
                               (bump!)
                               (spawn
                                 (lambda ()
                                   (send report-to (vector 'db-up ref self 'ok))
                                   (receive (`#(db-adopt) 'ok))
                                   (let loop ()
                                     (receive
                                       (`#(db-query ,sql ,r ,from)
                                         (set-box! executed
                                                   (cons sql (unbox executed)))
                                         (send from (vector 'db-reply r 'ok))
                                         (send notify (vector 'db-idle self))
                                         (loop))
                                       (`#(db-stats ,r ,from)
                                         (send from (vector 'db-stats-reply r #f))
                                         (loop))
                                       (`#(db-quit) 'done))))))
                             cfg)))))
        (sleep-ms 300)
        ;; occupy the only connection with a lease so the next query queues
        (let ((holder (spawn (lambda ()
                               (sql-call-with-connection pool
                                 (lambda (c)
                                   (send me (vector 'held))
                                   (receive (`#(release) 'ok)))
                                 cfg)))))
          (receive (after 2000 (void)) (`#(held) 'ok))
          ;; a caller queues an effectful statement, then is killed
          (let ((victim (spawn (lambda ()
                                 (guard (e (#t (void)))
                                   (sql-query pool "INSERT DEAD" cfg))))))
            (sleep-ms 150)
            (monitor victim)
            (kill victim 'reaped)
            (receive (after 2000 (void)) (`#(DOWN ,@victim ,_) 'ok)))
          (sleep-ms 150)
          (send holder (vector 'release)))
        (sleep-ms 400)
        (check "a dead caller's queued statement is never executed"
          (null? (unbox executed)))
        ;; and the pool still works
        (check "the pool still serves live callers"
          (eq? 'ok (sql-query pool "SELECT 1" cfg)))
        (send pool (vector 'db-quit))))

    ;; ---- a checkout for a caller that is ALREADY dead ---------------------
    ;;
    ;; monitor answers #f for a dead pid and delivers the DOWN at once. The
    ;; pool leased a connection to it anyway, and that immediate DOWN then
    ;; read as "a borrower died holding a transaction" -- destroying and
    ;; rebuilding a connection nobody had ever touched.
    (let ((spawned-before spawned))
      (let ((pool (spawn (lambda () (sql-pool-loop 1 fake-spawn-conn! cfg)))))
        (sleep-ms 300)
        (let ((base (- spawned spawned-before)))
          ;; a pid that is dead before the request reaches the pool
          (let ((corpse (spawn (lambda () 'done))))
            (sleep-ms 100)
            (send pool (vector 'db-checkout (gensym) corpse))
            (sleep-ms 400)
            (check "a checkout from a dead caller destroys no connection"
              (= base (- spawned spawned-before)))))
        ;; the connection is still there and usable
        (check "and the connection is still usable"
          (vector? (sql-query pool "SELECT 1" cfg)))
        (send pool (vector 'db-quit))))

    ;; ---- a connection handed back twice ----------------------------------
    ;;
    ;; A leased connection replies to its lessee, then is preempted before
    ;; sending db-idle. The lessee checks in first, so the checkin frees the
    ;; connection -- and the late db-idle then finds it neither leased nor
    ;; dying and frees it AGAIN. It was in `idle` twice, two checkouts got
    ;; the same connection, and the second lease overwrote the first lease
    ;; record: that borrower's monitor was never released, its checkin could
    ;; no longer find its lease, and its death no longer reclaimed a
    ;; connection that may have held its open transaction.
    ;;
    ;; The order is forced by sending db-idle by hand AFTER the checkin,
    ;; which is exactly what that preemption produces.
    (let ((pool (spawn (lambda () (sql-pool-loop 1 fake-spawn-conn! cfg))))
          (me self))
      (sleep-ms 300)
      (let ((conn (box #f)))
        (let ((holder (spawn (lambda ()
                               (sql-call-with-connection pool
                                 (lambda (c)
                                   (set-box! conn c)
                                   (send me (vector 'held))
                                   (receive (`#(release) 'ok)))
                                 cfg)))))
          (receive (after 2000 (void)) (`#(held) 'ok))
          (send holder (vector 'release))
          (sleep-ms 200)
          ;; the late db-idle, arriving after the checkin already freed it
          (send pool (vector 'db-idle (unbox conn)))
          (sleep-ms 200)
          ;; If it is in idle twice, two checkouts get the SAME connection.
          (let ((a (box #f)) (b (box #f)))
            (spawn (lambda ()
                     (sql-call-with-connection pool
                       (lambda (c) (set-box! a c) (send me (vector 'got 'a))
                                   (sleep-ms 400))
                       cfg)))
            (sleep-ms 100)
            (spawn (lambda ()
                     (sql-call-with-connection pool
                       (lambda (c) (set-box! b c) (send me (vector 'got 'b))
                                   (sleep-ms 50))
                       cfg)))
            (receive (after 2000 (void)) (`#(got ,x) x))
            (sleep-ms 250)
            (display "  [info] two concurrent checkouts got ")
            (display (if (and (unbox a) (unbox b) (eq? (unbox a) (unbox b)))
                         "the SAME connection" "different or one connection"))
            (newline)
            (check "one connection is never leased to two borrowers at once"
              (not (and (unbox a) (unbox b) (eq? (unbox a) (unbox b))))))))
      (send pool (vector 'db-quit)))

    ;; ---- a connection that dies at once is a FAILED CONNECT ---------------
    ;;
    ;; The peer accepted and then dropped it: a database refusing on
    ;; max_connections, one that requires TLS, a proxy draining, a worker
    ;; that is listening but useless. Rebuilding those with no delay is not
    ;; a rebuild, it is a spin -- measured at 38k connect/close cycles in
    ;; three seconds against a socket that accepted and closed, on the one
    ;; OS thread, churning a file descriptor each time.
    ;;
    ;; The bound here is deliberately loose. What it has to separate is
    ;; "backed off" from "as fast as the machine will go", and those differ
    ;; by four orders of magnitude.
    (set! stillborn-spawns 0)
    (let ((pool (spawn (lambda () (sql-pool-loop 1 stillborn-spawn-conn! cfg)))))
      (sleep-ms 1500)
      (check "a connection that dies at once is retried with backoff"
             (< stillborn-spawns 12))
      (display (string-append "  [info] rebuilds in 1.5s against a peer that "
                              "accepts and closes: "
                              (number->string stillborn-spawns) "\n"))
      (send pool (vector 'db-quit)))

    ;; ---- the deadlines belong to the CONFIG -------------------------------
    ;;
    ;; They used to be two constants in the library, so every pool in a
    ;; process waited a minute -- the right order of magnitude for a
    ;; database and the wrong one for anything whose work is measured in
    ;; milliseconds. What is pinned here is that a config's own deadlines
    ;; are the ones that fire, measured rather than assumed: against the
    ;; module constants these two calls would return after a MINUTE, and
    ;; the assertions below would never be reached inside the suite.
    (let ((short (make-sql-cfg
                   (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'fake-error)))
                   (vector 'fake-error "lost")
                   (vector 'fake-error "closed")
                   (vector 'fake-error "query timeout")
                   (vector 'fake-error "checkout timeout")
                   "BEGIN"
                   300      ; query
                   200)))   ; checkout
      (let ((pool (spawn (lambda () (sql-pool-loop 1 mute-spawn-conn! short)))))
        (sleep-ms 200)
        ;; a connection that never answers: only the deadline can end this
        (let* ((t0 (now-ms))
               (r (guard (e (#t e)) (sql-query pool 'anything short)))
               (took (- (now-ms) t0)))
          (check "a query gives up on the config's deadline, not the library's"
                 (and (vector? r) (equal? (vector-ref r 1) "query timeout")
                      (< took 3000)))
          (display (string-append "  [info] query timeout fired after "
                                  (number->string took) "ms (configured 300)\n")))
        ;; the one connection is now busy forever, so a checkout must queue
        ;; and then give up on ITS configured deadline
        (let* ((t0 (now-ms))
               (r (guard (e (#t e))
                    (sql-call-with-connection pool (lambda (c) 'unreachable) short)))
               (took (- (now-ms) t0)))
          (check "a checkout gives up on the config's deadline too"
                 (and (vector? r) (equal? (vector-ref r 1) "checkout timeout")
                      (< took 3000)))
          (display (string-append "  [info] checkout timeout fired after "
                                  (number->string took) "ms (configured 200)\n")))
        (send pool (vector 'db-quit))))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "sqlpool-lifecycle: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
