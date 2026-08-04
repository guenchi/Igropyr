#!chezscheme
;;; (igropyr connpool) waiter lifecycle, against FAKE connection workers.
;;;
;;; connpool-loop takes spawn-conn! as an argument, so the whole pool can be
;;; driven with stand-in processes that speak the db-* protocol and never
;;; touch a database. That is what makes these cases runnable everywhere --
;;; they are about the pool's bookkeeping, not about SQL.
;;;
;;; What is pinned here is the queued-waiter window. A caller that dies or
;;; times out WHILE QUEUED was invisible to the pool: nothing monitored it
;;; until it was handed a connection.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr connpool))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define cfg
  (make-connpool-cfg
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
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-request ,sql ,r ,from)
            (send from (vector 'pool-reply r (vector 'fake-rows sql)))
            (send notify (vector 'pool-idle self))
            (loop))
          (`#(pool-quit) 'done))))))

;; A stand-in that can be told to report itself dead to the pool WITHOUT
;; exiting -- which is the state a driver connection is in for the moment
;; between telling the pool its transport failed and actually closing.
(define (reporting-spawn-conn! notify report-to ref)
  (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-request ,sql ,r ,from)
            (send from (vector 'pool-reply r (vector 'fake-rows sql)))
            (send notify (vector 'pool-idle self))
            (loop))
          (`#(report-dead) (send notify (vector 'pool-conn-dead self)) (loop))
          (`#(pool-stats ,r ,from)
            (send from (vector 'pool-stats-reply r #f))
            (loop))
          (`#(pool-quit) 'done))))))

;; Reports up, is adopted, and on pool-quit answers the way every real
;; driver does -- as a TRANSPORT failure -- before exiting. That is what
;; makes the pool's own teardown come back to it labelled 'transport.
(define teardown-spawns 0)
(define (quit-as-transport-spawn-conn! notify report-to ref)
  (set! teardown-spawns (+ teardown-spawns 1))
  (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-quit)
            (send notify (vector 'pool-conn-dead self))   ; as a driver does
            'gone)
          (`#(pool-request ,sql ,r ,from)
            (send from (vector 'pool-reply r (vector 'fake-rows sql)))
            (send notify (vector 'pool-idle self))
            (loop))
          (`#(pool-stats ,r ,from)
            (send from (vector 'pool-stats-reply r #f))
            (loop)))))))

;; Reports up, is adopted, and then reports a TRANSPORT failure before
;; exiting -- which is what a driver does when its socket dies on the
;; first request. The pool marks it dying on that message, and reading any
;; dying mark as "the pool decided this" exempted it from the backoff.
(define transport-dead-spawns 0)
(define transport-dead-at '())
(define (transport-dead-spawn-conn! notify report-to ref)
  (set! transport-dead-spawns (+ transport-dead-spawns 1))
  (set! transport-dead-at (cons (now-ms) transport-dead-at))
  (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (send notify (vector 'pool-conn-dead self))
      'gone)))

;; Comes up and serves, but EXITS instead of answering -- what a connection
;; that dies while leased looks like to the borrower holding it.
(define (vanishing-spawn-conn! notify report-to ref)
  (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-request ,sql ,r ,from) 'gone)      ; no reply, just exit
          (`#(pool-quit) 'done)
          (`#(pool-stats ,r ,from)
            (send from (vector 'pool-stats-reply r #f))
            (loop)))))))

;; A stand-in that reports up, is adopted, and dies at once -- what a peer
;; that accepts and then drops the connection looks like from in here.
(define stillborn-spawns 0)
(define (stillborn-spawn-conn! notify report-to ref)
  (set! stillborn-spawns (+ stillborn-spawns 1))
  (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      'gone)))

;; A stand-in that comes up and then never answers anything: what is left
;; when only a deadline can end the call.
(define (mute-spawn-conn! notify report-to ref)
  (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-quit) 'done)
          (`#(pool-request ,sql ,r ,from) (loop))     ; swallowed on purpose
          (`#(pool-request-cancel ,r ,from) (loop)))))))

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
    (let* ((pool (spawn (lambda () (connpool-loop 1 fake-spawn-conn! cfg))))
           (me self))
      (sleep-ms 200)
      (check "pool spawned one connection" (= spawned 1))

      ;; holder takes the only connection as a lease
      (let ((holder (spawn (lambda ()
                             (let ((r (gensym)))
                               (send pool (vector 'pool-checkout r self))
                               (receive
                                 (`#(pool-checkout-reply ,@r ,c)
                                   (send me (vector 'held c))
                                   ;; hold until told to release
                                   (receive (`#(release) (void)))
                                   (send pool (vector 'pool-checkin self c))
                                   (send me (vector 'released)))))))))
        (let ((conn (receive (after 2000 #f) (`#(held ,c) c))))
          (check "holder leased the only connection" (and conn #t))

          ;; a second caller queues behind it, then dies while queued
          (let ((victim (spawn (lambda ()
                                 (let ((r (gensym)))
                                   (send pool (vector 'pool-checkout r self))
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
            (send pool (vector 'pool-request "SELECT 1" r self))
            (check "pool still serves queries"
              (receive (after 2000 #f)
                (`#(pool-reply ,@r ,v) (and (vector? v)
                                          (eq? (vector-ref v 0) 'fake-rows))))))))
      (send pool (vector (quote pool-quit))))

    ;; ---- a timed-out query must not execute later --------------------
    ;;
    ;; The pool has one connection and it is leased away, so the query can
    ;; only queue. connpool-call's own timeout is 60 s, far too long for a test,
    ;; so the timeout is simulated exactly as connpool-call performs it: send the
    ;; request, then send pool-request-cancel. What is asserted is what the
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
                   (send report-to (vector 'pool-up ref self 'ok))
                   (receive (`#(pool-adopt) 'ok))
                   (let loop ()
                     (receive
                       (`#(pool-request ,sql ,r ,from)
                         (set-box! executed (cons sql (unbox executed)))
                         (send from (vector 'pool-reply r (vector 'fake-rows sql)))
                         (send notify (vector 'pool-idle self))
                         (loop))
                       (`#(pool-quit) 'done)))))))
           (pool (spawn (lambda () (connpool-loop 1 spawn-recording cfg))))
           (me self))
      (sleep-ms 200)
      (let ((holder (spawn (lambda ()
                             (let ((r (gensym)))
                               (send pool (vector 'pool-checkout r self))
                               (receive
                                 (`#(pool-checkout-reply ,@r ,c)
                                   (send me (vector 'held c))
                                   (receive (`#(release) (void)))
                                   (send pool (vector 'pool-checkin self c))
                                   (send me (vector 'released)))))))))
        (receive (after 2000 (void)) (`#(held ,c) 'ok))

        (let ((r (gensym)))
          (send pool (vector 'pool-request "INSERT INTO t VALUES (1)" r self))
          (sleep-ms 100)
          ;; the caller gives up, exactly as connpool-call does on timeout
          (send pool (vector 'pool-request-cancel r self)))

        ;; release the connection: the pool now looks for queued work
        (send holder (vector 'release))
        (receive (after 2000 (void)) (`#(released) 'ok))
        (sleep-ms 300)
        (check "a cancelled query never reaches a connection"
          (null? (unbox executed)))

        ;; and a fresh query still runs, so the cancel did not wedge the pool
        (let ((r2 (gensym)))
          (send pool (vector 'pool-request "SELECT 2" r2 self))
          (check "pool still runs later queries"
            (receive (after 2000 #f) (`#(pool-reply ,@r2 ,v) #t)))))
      (send pool (vector (quote pool-quit))))

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
                           (connpool-loop 1
                             (lambda (notify report-to ref)
                               (bump!)
                               (spawn
                                 (lambda ()
                                   (send report-to (vector 'pool-up ref self 'ok))
                                   (receive (`#(pool-adopt) 'ok))
                                   (let loop ()
                                     (receive
                                       (`#(pool-request ,sql ,r ,from)
                                         (set-box! executed
                                                   (cons sql (unbox executed)))
                                         (send from (vector 'pool-reply r 'ok))
                                         (send notify (vector 'pool-idle self))
                                         (loop))
                                       (`#(pool-stats ,r ,from)
                                         (send from (vector 'pool-stats-reply r #f))
                                         (loop))
                                       (`#(pool-quit) 'done))))))
                             cfg)))))
        (sleep-ms 300)
        ;; occupy the only connection with a lease so the next query queues
        (let ((holder (spawn (lambda ()
                               (connpool-lease pool
                                 (lambda (c)
                                   (send me (vector 'held))
                                   (receive (`#(release) 'ok)))
                                 cfg)))))
          (receive (after 2000 (void)) (`#(held) 'ok))
          ;; a caller queues an effectful statement, then is killed
          (let ((victim (spawn (lambda ()
                                 (guard (e (#t (void)))
                                   (connpool-call pool "INSERT DEAD" cfg))))))
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
          (eq? 'ok (connpool-call pool "SELECT 1" cfg)))
        (send pool (vector 'pool-quit))))

    ;; ---- a checkout for a caller that is ALREADY dead ---------------------
    ;;
    ;; monitor answers #f for a dead pid and delivers the DOWN at once. The
    ;; pool leased a connection to it anyway, and that immediate DOWN then
    ;; read as "a borrower died holding a transaction" -- destroying and
    ;; rebuilding a connection nobody had ever touched.
    (let ((spawned-before spawned))
      (let ((pool (spawn (lambda () (connpool-loop 1 fake-spawn-conn! cfg)))))
        (sleep-ms 300)
        (let ((base (- spawned spawned-before)))
          ;; a pid that is dead before the request reaches the pool
          (let ((corpse (spawn (lambda () 'done))))
            (sleep-ms 100)
            (send pool (vector 'pool-checkout (gensym) corpse))
            (sleep-ms 400)
            (check "a checkout from a dead caller destroys no connection"
              (= base (- spawned spawned-before)))))
        ;; the connection is still there and usable
        (check "and the connection is still usable"
          (vector? (connpool-call pool "SELECT 1" cfg)))
        (send pool (vector 'pool-quit))))

    ;; ---- a connection handed back twice ----------------------------------
    ;;
    ;; A leased connection replies to its lessee, then is preempted before
    ;; sending pool-idle. The lessee checks in first, so the checkin frees the
    ;; connection -- and the late pool-idle then finds it neither leased nor
    ;; dying and frees it AGAIN. It was in `idle` twice, two checkouts got
    ;; the same connection, and the second lease overwrote the first lease
    ;; record: that borrower's monitor was never released, its checkin could
    ;; no longer find its lease, and its death no longer reclaimed a
    ;; connection that may have held its open transaction.
    ;;
    ;; The order is forced by sending pool-idle by hand AFTER the checkin,
    ;; which is exactly what that preemption produces.
    (let ((pool (spawn (lambda () (connpool-loop 1 fake-spawn-conn! cfg))))
          (me self))
      (sleep-ms 300)
      (let ((conn (box #f)))
        (let ((holder (spawn (lambda ()
                               (connpool-lease pool
                                 (lambda (c)
                                   (set-box! conn c)
                                   (send me (vector 'held))
                                   (receive (`#(release) 'ok)))
                                 cfg)))))
          (receive (after 2000 (void)) (`#(held) 'ok))
          (send holder (vector 'release))
          (sleep-ms 200)
          ;; the late pool-idle, arriving after the checkin already freed it
          (send pool (vector 'pool-idle (unbox conn)))
          (sleep-ms 200)
          ;; If it is in idle twice, two checkouts get the SAME connection.
          (let ((a (box #f)) (b (box #f)))
            (spawn (lambda ()
                     (connpool-lease pool
                       (lambda (c) (set-box! a c) (send me (vector 'got 'a))
                                   (sleep-ms 400))
                       cfg)))
            (sleep-ms 100)
            (spawn (lambda ()
                     (connpool-lease pool
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
      (send pool (vector 'pool-quit)))

    ;; ---- a check-in must not put a DYING connection back in rotation ------
    ;;
    ;; A connection that hits a transport error tells its caller and tells
    ;; the pool, and the caller's check-in can arrive in between. The pool
    ;; then made a connection it already knew was going available again and
    ;; leased it to the next borrower, who got a pid that was about to
    ;; exit: its statement went nowhere and it waited out its whole query
    ;; timeout for a reply nobody would send. The connection's own DOWN
    ;; tidied up afterwards, far too late to matter.
    (let* ((pool (spawn (lambda () (connpool-loop 1 reporting-spawn-conn! cfg))))
           (me self))
      (sleep-ms 200)
      (let ((borrower
             (spawn (lambda ()
                      (let ((r (gensym)))
                        (send pool (vector 'pool-checkout r self))
                        (receive (after 2000 (send me (vector 'no-lease)))
                          (`#(pool-checkout-reply ,@r ,c)
                            (send me (vector 'leased c))
                            (receive (`#(release) (void)))
                            (send pool (vector 'pool-checkin self c))
                            (send me (vector 'checked-in)))))))))
        (let ((conn (receive (after 3000 #f) (`#(leased ,c) c))))
          (check "the borrower has the only connection" (and conn #t))
          ;; the transport failed: the connection says so and stays alive,
          ;; exactly as a driver does between its two sends
          (send conn (vector 'report-dead))
          (sleep-ms 100)
          (send borrower (vector 'release))
          (receive (after 3000 (void)) (`#(checked-in) 'ok))
          ;; a fresh borrower must NOT be handed that connection
          (let ((r (gensym)))
            (send pool (vector 'pool-checkout r self))
            (let ((got (receive (after 700 'none)
                         (`#(pool-checkout-reply ,@r ,c2) c2))))
              (check "a checked-in connection the pool knows is dying is not re-lent"
                     (not (eq? got conn)))
              (when (eq? got conn)
                (display "  [info] the pool handed back the dying connection\n"))))))
      (send pool (vector 'pool-quit)))

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
    (let ((pool (spawn (lambda () (connpool-loop 1 stillborn-spawn-conn! cfg)))))
      (sleep-ms 1500)
      (check "a connection that dies at once is retried with backoff"
             (< stillborn-spawns 12))
      (display (string-append "  [info] rebuilds in 1.5s against a peer that "
                              "accepts and closes: "
                              (number->string stillborn-spawns) "\n"))
      (send pool (vector 'pool-quit)))

    ;; ---- a TRANSPORT failure is not the pool's own decision ---------------
    ;;
    ;; The connection tells the pool it is dead before it replies, which
    ;; marks it dying; the DOWN handler then read any dying mark as "the
    ;; pool tore this down on purpose" and rebuilt it with no delay. So a
    ;; peer that accepts and fails on its first request was back in the hot
    ;; reconnect loop the backoff exists to stop -- through a mark the
    ;; connection itself had set.
    (set! transport-dead-spawns 0)
    (set! transport-dead-at '())
    (let ((pool (spawn (lambda () (connpool-loop 1 transport-dead-spawn-conn! cfg)))))
      (sleep-ms 7000)   ; long enough for 1s, 2s, 4s to be distinguishable
      (check "a connection that reports a transport failure at once is backed off"
             (< transport-dead-spawns 8))
      ;; ...and the interval GROWS. Clearing the penalty the moment a
      ;; connection reported up meant each failure erased the history of
      ;; the one before it, so the backoff never left its first step.
      (let ((ts (reverse transport-dead-at)))
        (if (< (length ts) 3)
            (display "  [info] too few rebuilds to compare intervals\n")
            (let ((first-gap (- (cadr ts) (car ts)))
                  (last-gap (- (list-ref ts (- (length ts) 1))
                               (list-ref ts (- (length ts) 2)))))
              (display (string-append "  [info] rebuild gaps: first "
                                      (number->string first-gap) "ms, last "
                                      (number->string last-gap) "ms over "
                                      (number->string (length ts)) " attempts\n"))
              (check "and the backoff escalates rather than repeating its first step"
                     (> last-gap (* 3/2 first-gap))))))
      (send pool (vector 'pool-quit)))

    ;; ---- the pool's own teardown stays the pool's own decision ------------
    ;;
    ;; The pool tears a connection down by sending pool-quit. Every driver
    ;; answers pool-quit while mid-request as a TRANSPORT failure, so the
    ;; connection then reports pool-conn-dead -- and an unconditional write
    ;; let that overwrite the pool's own mark. A healthy connection the pool
    ;; asked to go then looked stillborn, and the backoff that follows is
    ;; POOL-WIDE and doubles: a supervisor reaping stuck borrowers walks an
    ;; entirely healthy pool up toward the ceiling.
    (set! teardown-spawns 0)
    (let ((pool (spawn (lambda () (connpool-loop 1 quit-as-transport-spawn-conn! cfg))))
          (me self))
      (sleep-ms 300)
      ;; a borrower takes the lease and is killed, which is what makes the
      ;; pool send pool-quit
      (let ((victim (spawn (lambda ()
                             (let ((r (gensym)))
                               (send pool (vector 'pool-checkout r self))
                               (receive (after 2000 'none)
                                 (`#(pool-checkout-reply ,@r ,c)
                                   (send me (vector 'leased))
                                   (receive (`#(never) 'no)))))))))
        (receive (after 3000 (void)) (`#(leased) 'ok))
        (kill victim 'reaped)
        ;; the replacement must be built AT ONCE -- this was the pool's own
        ;; decision, not a peer problem
        (sleep-ms 700)
        (check "a connection the pool tore down is rebuilt without backoff"
               (>= teardown-spawns 2))
        (display (string-append "  [info] rebuilds 700ms after a reaped borrower: "
                                (number->string teardown-spawns) "\n")))
      (send pool (vector 'pool-quit)))

    ;; ---- a leased connection that dies answers its borrower ---------------
    ;;
    ;; A pooled call is answered when its connection dies: the pool holds
    ;; the caller and the ref and sends the lost error. A call on a LEASED
    ;; connection is in no such table -- the pool has nothing to answer
    ;; with -- so the borrower waited out its entire query timeout for a
    ;; reply from a process that had already exited.
    (let ((short (make-connpool-cfg
                   (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'fake-error)))
                   (vector 'fake-error "lost")
                   (vector 'fake-error "closed")
                   (vector 'fake-error "query timeout")
                   (vector 'fake-error "checkout timeout")
                   "BEGIN"
                   5000       ; the query deadline this must NOT wait out
                   1000)))
      (let ((pool (spawn (lambda () (connpool-loop 1 vanishing-spawn-conn! short)))))
        (sleep-ms 300)
        (let* ((t0 (now-ms))
               (r (guard (e (#t e))
                    (connpool-lease pool
                      (lambda (conn) (connpool-call conn 'anything short))
                      short)))
               (took (- (now-ms) t0)))
          (check "a borrower learns at once that its connection died"
                 (and (vector? r) (< took 2000)))
          (display (string-append "  [info] leased connection death reported after "
                                  (number->string took) "ms (the query deadline is 5000)\n")))
        (send pool (vector 'pool-quit))))

    ;; ---- the deadlines belong to the CONFIG -------------------------------
    ;;
    ;; They used to be two constants in the library, so every pool in a
    ;; process waited a minute -- the right order of magnitude for a
    ;; database and the wrong one for anything whose work is measured in
    ;; milliseconds. What is pinned here is that a config's own deadlines
    ;; are the ones that fire, measured rather than assumed: against the
    ;; module constants these two calls would return after a MINUTE, and
    ;; the assertions below would never be reached inside the suite.
    (let ((short (make-connpool-cfg
                   (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'fake-error)))
                   (vector 'fake-error "lost")
                   (vector 'fake-error "closed")
                   (vector 'fake-error "query timeout")
                   (vector 'fake-error "checkout timeout")
                   "BEGIN"
                   300      ; query
                   200)))   ; checkout
      (let ((pool (spawn (lambda () (connpool-loop 1 mute-spawn-conn! short)))))
        (sleep-ms 200)
        ;; a connection that never answers: only the deadline can end this
        (let* ((t0 (now-ms))
               (r (guard (e (#t e)) (connpool-call pool 'anything short)))
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
                    (connpool-lease pool (lambda (c) 'unreachable) short)))
               (took (- (now-ms) t0)))
          (check "a checkout gives up on the config's deadline too"
                 (and (vector? r) (equal? (vector-ref r 1) "checkout timeout")
                      (< took 3000)))
          (display (string-append "  [info] checkout timeout fired after "
                                  (number->string took) "ms (configured 200)\n")))
        (send pool (vector 'pool-quit))))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "connpool-lifecycle: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
