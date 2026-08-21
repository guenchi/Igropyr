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

;; ...and WHICH ones, for the case that has to say "a different process"
;; rather than "one more process". A count cannot tell a replacement from
;; a straggler still coming up, and it is recorded before the spawn it
;; counts, so it is not even an ordering. These are the pids themselves,
;; recorded after they exist.
(define born '())
(define (born! pid) (set! born (cons pid born)) pid)

;; A stand-in connection: reports up, waits to be adopted, then answers
;; queries instantly and pings idle, exactly like a driver worker.
(define (fake-spawn-conn! notify report-to ref)
  (bump!)
  (born!
    (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-request ,sql ,r ,from)
            (send from (vector 'pool-reply r (vector 'fake-rows sql)))
            (send notify (vector 'pool-idle self r))
            (loop))
          (`#(pool-quit) 'done)))))))

;; A stand-in that answers its caller itself and then reports the death,
;; which is the order a driver uses when its transport fails under a query.
(define (dying-mid-query-conn! notify report-to ref)
  (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-request ,sql ,r ,from)
            (send notify (vector 'pool-conn-dead self))
            (send from (vector 'pool-reply r (vector 'fake-error "transport")))
            'gone)                      ; ...and exits, so a DOWN follows
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
            (send notify (vector 'pool-idle self r))
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
            (send notify (vector 'pool-idle self r))
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

;; Answers slowly, so a dispatched request stays on the pool's books long
;; enough to send something at it.
(define slow-conn (box #f))
(define (slow-spawn-conn! notify report-to ref)
  (spawn
    (lambda ()
      (set-box! slow-conn self)
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-request ,sql ,r ,from)
            (sleep-ms 800)
            (send from (vector 'pool-reply r (vector 'fake-rows sql)))
            (send notify (vector 'pool-idle self r))
            (loop))
          (`#(pool-quit) 'done)
          (`#(pool-stats ,r ,from)
            (send from (vector 'pool-stats-reply r #f))
            (loop)))))))

;; Reports a TRANSPORT failure to the pool and then keeps running, so the
;; borrower's own broken check-in can arrive AFTER that report. This is the
;; mirror of the teardown case: here the peer failed first and the pool's
;; quit is a consequence, so the transport verdict must stand.
(define transport-first-spawns 0)
(define transport-first-at '())
(define transport-died-at '())
(define (transport-then-linger-spawn-conn! notify report-to ref)
  (set! transport-first-spawns (+ transport-first-spawns 1))
  (set! transport-first-at (cons (now-ms) transport-first-at))
  (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-request ,sql ,r ,from)
            ;; stamped where the DEATH is, so the gap below measures
            ;; death -> replacement. Stamping at spawn folded the test's own
            ;; settle time into it, which left the assertion only about
            ;; 400ms of real discrimination on a 700ms threshold.
            (set! transport-died-at (cons (now-ms) transport-died-at))
            (send notify (vector 'pool-conn-dead self))   ; transport, FIRST
            (send from (vector 'pool-reply r (vector 'fake-error "lost")))
            (sleep-ms 250)                                ; ...then linger
            'gone)
          (`#(pool-quit) 'done)
          (`#(pool-stats ,r ,from)
            (send from (vector 'pool-stats-reply r #f))
            (loop)))))))

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
                         (send notify (vector 'pool-idle self r))
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
                                         (send notify (vector 'pool-idle self r))
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
          ;; The late pool-idle, arriving after the check-in already freed
          ;; it. It names a request this connection is not running -- which
          ;; is the whole point: a stale idle is now ignored outright, a
          ;; stronger guarantee than the idempotent re-add this case
          ;; originally pinned. Either way it must not end up in idle twice.
          (send pool (vector 'pool-idle (unbox conn) (gensym)))
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

    ;; ---- ...and neither must one that was ALREADY back in rotation -------
    ;;
    ;; The mirror of the case above, and the one the gate in
    ;; make-available! cannot cover: here the check-in lands FIRST, so the
    ;; connection is sitting in the idle set when its death is reported and
    ;; never has to pass that gate again. Clearing only its busy entry left
    ;; it idle and marked dying at the same time, and the next checkout was
    ;; handed it.
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
                            (send pool (vector 'pool-checkin self c))
                            (send me (vector 'checked-in)))))))))
        (let ((conn (receive (after 3000 #f) (`#(leased ,c) c))))
          (check "the borrower has the only connection (idle-then-dead)"
                 (and conn #t))
          (receive (after 3000 (void)) (`#(checked-in) 'ok))
          (sleep-ms 100)                       ; the pool has filed it as idle
          (send conn (vector 'report-dead))    ; ...and only now does it die
          (sleep-ms 150)
          (let ((st (connpool-stats pool)))
            (check "a connection reported dead while idle leaves the idle set"
                   (= (cond ((assq 'idle st) => cdr) (else -1)) 0))
            (when (> (cond ((assq 'idle st) => cdr) (else -1)) 0)
              (display "  [info] idle/dying at once: ")
              (write (list (assq 'idle st) (assq 'dying st))) (newline)))
          (let ((r (gensym)))
            (send pool (vector 'pool-checkout r self))
            (let ((got (receive (after 700 'none)
                         (`#(pool-checkout-reply ,@r ,c2) c2))))
              (check "an idle connection reported dead is not lent out"
                     (not (eq? got conn)))))))
      (send pool (vector 'pool-quit)))

    ;; ---- a caller is answered ONCE when its connection fails mid-query ---
    ;;
    ;; A driver that hits a transport error answers its caller itself and
    ;; then tells the pool. If the pool keeps the busy entry, the DOWN that
    ;; follows answers the same caller a second time with the pool's own
    ;; lost-error -- a caller that has already moved on gets a stray reply
    ;; in its mailbox, and whatever it selectively receives next may match
    ;; it. Clearing the entry when the death is reported is what makes the
    ;; reply one shot.
    (let* ((pool (spawn (lambda () (connpool-loop 1 dying-mid-query-conn! cfg))))
           (me self))
      (sleep-ms 200)
      (let ((caller
             (spawn (lambda ()
                      (let ((n (box 0)))
                        (send me (vector 'asked
                                         (guard (e (#t 'raised))
                                           (connpool-call pool "SELECT 1" cfg))))
                        ;; anything else that arrives is a SECOND answer
                        (receive (after 1200 (send me (vector 'extra 0)))
                          (`#(pool-reply ,r ,v) (send me (vector 'extra (list 1 v))))))))))
        (receive (after 3000 (void))
(`#(asked ,v) 'ok))
        (let ((extra (receive (after 3000 'lost) (`#(extra ,k) k))))
          (check "a caller answered by its failing connection is not answered again"
                 (eqv? extra 0))
          (when (not (eqv? extra 0))
            (display "  [info] duplicate replies: ") (write extra) (newline))))
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
        ;; too few samples is a FAILED measurement, not a silent pass: the
        ;; assertion below simply disappears, and a slower machine reaches
        ;; that state without anything saying the case stopped testing.
        (if (< (length ts) 3)
            (check "enough rebuilds to compare backoff intervals" #f)
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

    ;; ---- ...and a transport failure keeps its verdict -----------------
    ;;
    ;; The mirror sequence. The connection fails on its own and reports it;
    ;; the borrower then raises and, because the render path returns a
    ;; connection BROKEN when the call escapes, the pool hears a check-in
    ;; -broken for the same connection. Letting that overwrite the earlier
    ;; verdict made the death look like the pool's own decision and rebuilt
    ;; with no backoff at all -- the spin the backoff exists to stop.
    (set! transport-first-spawns 0)
    (set! transport-first-at '())
    (set! transport-died-at '())
    (let ((pool (spawn (lambda () (connpool-loop 1 transport-then-linger-spawn-conn! cfg)))))
      (sleep-ms 300)
      ;; a lease whose body raises: the after-thunk sends check-in-broken
      (guard (e (#t 'expected))
        (connpool-lease pool
          (lambda (conn) (connpool-call conn 'anything cfg))
          cfg
          #t))                                  ; broken-on-escape
      (sleep-ms 2200)
      ;; ONE death, so counting rebuilds proves nothing -- nobody asks for a
      ;; second lease, so no second failure follows however it was
      ;; classified. What separates the two verdicts is the DELAY before the
      ;; replacement appears: a peer problem is backed off ~1s, the pool's
      ;; own decision is rebuilt at once.
      (let ((ts (reverse transport-first-at))
            (died (reverse transport-died-at)))
        (if (or (< (length ts) 2) (null? died))
            (check "a replacement connection was built at all" #f)
            (let ((gap (- (cadr ts) (car died))))
              (check "a transport failure is not reclassified by a later broken check-in"
                     (> gap 700))
              (display (string-append "  [info] replacement after a transport failure: "
                                      (number->string gap) "ms\n")))))
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

    ;; ---- a late idle must not free somebody else's request -----------------
    ;;
    ;; A connection sends its reply and then pool-idle, and can be preempted
    ;; between the two. If the pool dispatches the next queued request in
    ;; that gap, the LATE idle arrives against a busy entry belonging to a
    ;; DIFFERENT request -- clearing it, crediting the wrong request with
    ;; the duration, and putting the connection back in rotation while the
    ;; request it was just given is still in its mailbox. Two callers, one
    ;; connection.
    ;;
    ;; Constructed directly: a request slow enough to still be dispatched,
    ;; and an idle naming something this connection never ran. The books
    ;; must still show it busy.
    (let ((pool (spawn (lambda () (connpool-loop 1 slow-spawn-conn! cfg))))
          (me self))
      (sleep-ms 300)
      (spawn (lambda ()
               (guard (e (#t 'ok)) (connpool-call pool 'slow cfg))
               (send me (vector 'slow-done))))
      (sleep-ms 200)                       ; dispatched, still running
      ;; an idle for this very connection, naming a request it never ran
      (send pool (vector 'pool-idle (unbox slow-conn) (gensym)))
      (sleep-ms 50)
      (let ((st (connpool-stats pool)))
        (define (g k) (cond ((assq k st) => cdr) (else -1)))
        (check "a request in flight is still on the books"
               (and (= 1 (g 'busy)) (= 0 (g 'idle)))))
      (receive (after 3000 (void)) (`#(slow-done) 'ok))
      (send pool (vector 'pool-quit)))

    ;; ---- a dead pool is not a busy one -------------------------------------
    ;;
    ;; A checkout waits for a reply that a dead pool can never send, so the
    ;; caller sat out the whole checkout deadline -- a minute for the SQL
    ;; drivers -- and was then told the pool was SATURATED. That is a
    ;; different fault with a different remedy: one says "run more
    ;; connections", the other says "your pool is gone".
    (let ((slow (make-connpool-cfg
                  (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'fake-error)))
                  (vector 'fake-error "lost")
                  (vector 'fake-error "closed")
                  (vector 'fake-error "query timeout")
                  (vector 'fake-error "checkout timeout")
                  "BEGIN"
                  5000
                  5000)))            ; the checkout deadline this must NOT wait out
      (let ((pool (spawn (lambda () (connpool-loop 1 fake-spawn-conn! slow)))))
        (sleep-ms 200)
        (kill pool 'reaped)
        (sleep-ms 100)
        (let* ((t0 (now-ms))
               (r (guard (e (#t e))
                    (connpool-lease pool (lambda (c) 'unreachable) slow)))
               (took (- (now-ms) t0)))
          (check "a checkout against a dead pool fails at once"
                 (and (vector? r) (< took 2000)))
          (check "...and says the connection was lost, not that the pool is full"
                 (and (vector? r) (equal? (vector-ref r 1) "lost")))
          (display (string-append "  [info] dead pool reported after "
                                  (number->string took)
                                  "ms (the checkout deadline is 5000)\n")))))

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


    ;; ---- a lease is ONE connection, or it fails ---------------------------
    ;;
    ;; A borrower holds a connection so that a sequence of statements runs
    ;; on one server session: that is the whole reason leases exist, and a
    ;; transaction is only atomic because nothing else and nothing later
    ;; runs somewhere else. The pool never substitutes: a connection that
    ;; dies takes its lease down with it and is replaced by a DIFFERENT
    ;; process, so a handle cannot quietly acquire a new session.
    ;;
    ;; That holds today because a connection worker never re-dials itself
    ;; -- every rebuild is a fresh spawn from the pool -- but it holds as
    ;; an accident of how the code is arranged, and a later "reconnect
    ;; transparently, the caller need not care" would take it away with
    ;; nothing to object. Consumers reason about transaction scope with
    ;; it, so it is pinned here.
    ;;
    ;; AIMED AT THE BOUNDARY, not at the ordinary path: the pool is given
    ;; TWO connections, so a healthy sibling exists to be substituted at
    ;; the moment the leased one dies. With a single connection there is
    ;; nothing to put in its place and any implementation passes.
    (set! spawned 0)
    (set! born '())
    (let ((pool (spawn (lambda () (connpool-loop 2 fake-spawn-conn! cfg)))))
      ;; WAIT FOR BOTH INITIAL CONNECTIONS, and wait for them by asking.
      ;; A fixed sleep here does not merely risk being short: if the
      ;; second one is still coming up when the baseline is taken, its
      ;; arrival satisfies both the wait for a replacement and the
      ;; assertion that one appeared -- while the sibling this case needs
      ;; at the moment of death was never there. The boundary would be
      ;; gone and the case would still pass.
      (let settle ((i 0))
        (cond ((= (length born) 2) 'up)
              ((> i 200) (check "the pool brought up both connections" #f))
              (else (sleep-ms 50) (settle (+ i 1)))))
      (let* ((before spawned)
             (born-before born)
             (outcome
               (guard (e (#t (list 'lease-raised e)))
                 (connpool-lease pool
                   (lambda (conn)
                     (let ((first (connpool-call conn "SELECT 1" cfg)))
                       ;; the session goes: the socket drops, the peer
                       ;; restarts, the process dies whatever the reason
                       (kill conn 'peer-went-away)
                       (sleep-ms 300)
                       (list 'ran first
                             (guard (e (#t (list 'raised e)))
                               (list 'returned
                                     (connpool-call conn "SELECT 2" cfg))))))
                   cfg))))
        ;; WAIT FOR THE REBUILD, NOT FOR A DURATION. It is backed off as a
        ;; peer problem, so reading the count at once would find nothing
        ;; and report that the pool had reused the connection; picking a
        ;; number larger than the backoff only moves that failure onto
        ;; whichever machine is slower than the number.
        (let await ((i 0))
          (cond ((> (length born) (length born-before)) 'rebuilt)
                ((> i 200) 'gave-up)          ; the check below reports it
                (else (sleep-ms 50) (await (+ i 1)))))
        ;; the two shapes are told apart by a tag rather than by length:
        ;; a lease that raised as a whole is also a two-element list, and
        ;; reading it as the other one reports the first statement going
        ;; unanswered -- true-ish, and pointing the wrong way
        (let* ((ran (and (pair? outcome) (eq? (car outcome) 'ran)))
               (first (and ran (cadr outcome)))
               (second (and ran (caddr outcome))))
          (unless ran
            (check "the lease itself completed" #f)
            (display "  [info] the lease raised: ") (write outcome) (newline))
          (check "a statement on a live leased connection is answered"
                 (and (vector? first) (eq? (vector-ref first 0) 'fake-rows)))
          ;; the point: NOT answered by the sibling
          (check "a statement on a dead leased connection fails the lease"
                 (and (pair? second) (eq? (car second) 'raised)
                      (let ((r (cadr second)))
                        (and (vector? r) (equal? (vector-ref r 1) "lost")))))
          ;; a DIFFERENT process, said as identity rather than as arithmetic:
          ;; one more pid could be a straggler, and the counter is bumped
          ;; before the spawn it counts
          (let ((added (filter (lambda (p) (not (memq p born-before))) born)))
            (check "the replacement is a new connection, not the same one"
                   (and (= (length added) 1)
                        (not (memq (car added) born-before))))
            (display "  [info] replacement pids added ")
            (display (length added)) (newline))
          (display "  [info] lease outcome ") (write second)
          (display ", connections spawned ") (display (- spawned before))
          (newline))))


    ;; ---- what the observer sees, and where it runs -----------------------
    ;;
    ;; A consumer wrapping its own query entry point sees its DML and
    ;; nothing else: BEGIN and COMMIT are issued by sql-transaction and
    ;; ROLLBACK by the check-in path, so "these three statements ran in one
    ;; transaction" cannot be decided from outside. The dangerous shape is
    ;; not a missing log line -- an extra commit in the middle ends the
    ;; atomicity while every assertion about the DML stays green.
    ;;
    ;; THE POOL IS STARTED WITH THE PLAIN cfg AND ONLY THE CALLS CARRY THE
    ;; OBSERVED ONE. That is what makes these cases say WHERE the observer
    ;; runs rather than only THAT it ran: an implementation that hooked the
    ;; pool loop, or the point where a queued job is forwarded to a
    ;; connection, would see every one of these statements and pass a test
    ;; that used the observed cfg on both sides.
    (let ()
      (define obs-log '())      ; (borrower conn sql), newest first
      (define worker-log '())   ; what a connection was actually asked
      (define (reset-logs!) (set! obs-log '()) (set! worker-log '()))
      (define (obs-sql) (reverse (map caddr obs-log)))
      (define (recording-conn! notify report-to ref)
        (bump!)
        (born!
          (spawn
            (lambda ()
              (send report-to (vector 'pool-up ref self 'ok))
              (receive (`#(pool-adopt) 'ok))
              (let loop ()
                (receive
                  (`#(pool-request ,sql ,r ,from)
                    (set! worker-log (cons sql worker-log))
                    (send from (vector 'pool-reply r (vector 'fake-rows sql)))
                    (send notify (vector 'pool-idle self r))
                    (loop))
                  (`#(pool-quit) 'done)))))))
      ;; the setter answers with nothing, as a set!-shaped procedure
      ;; should, so the cfg is what this hands back
      (define (watch! proc)
        (let ((c (copy-cfg))) (connpool-cfg-set-observer! c proc) c))
      ;; a cfg of this file's own shape, so an observed one and a plain one
      ;; are different objects and cannot be confused for each other
      (define (copy-cfg)
        (make-connpool-cfg
          (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'fake-error)))
          (vector 'fake-error "lost") (vector 'fake-error "closed")
          (vector 'fake-error "query timeout")
          (vector 'fake-error "checkout timeout")
          "BEGIN"))
      (define (up! n spawner c)
        (set! born '())
        (let ((pool (spawn (lambda () (connpool-loop n spawner c)))))
          (let settle ((i 0))
            (cond ((= (length born) n) pool)
                  ((> i 200) (check "the pool came up" #f) pool)
                  (else (sleep-ms 50) (settle (+ i 1)))))))

      ;; ---- a committed transaction, end to end -------------------------
      (reset-logs!)
      (let* ((me self)
             (ocfg (watch! (lambda (conn sql)
                             (set! obs-log
                               (cons (list self conn sql) obs-log)))))
             (pool (up! 1 recording-conn! cfg))     ; plain cfg starts it
             (lease-conn #f))
        (sql-transaction pool
          (lambda (conn)
             (set! lease-conn conn)
             (connpool-call conn "INSERT 1" ocfg))
          ocfg)
        (check "BEGIN, the statement and COMMIT are seen, in that order"
               (equal? (obs-sql) (list "BEGIN" "INSERT 1" "COMMIT")))
        ;; ...and the connection was actually asked for them: an observer
        ;; that synthesised its events without a request behind them would
        ;; satisfy the line above on its own
        (check "the connection was asked for exactly those statements"
               (equal? (reverse worker-log)
                       (list "BEGIN" "INSERT 1" "COMMIT")))
        (check "every event names the leased connection"
               (and lease-conn
                    (for-all (lambda (e) (eq? (cadr e) lease-conn)) obs-log)))
        (check "every event ran in the borrowing process"
               (for-all (lambda (e) (eq? (car e) me)) obs-log))
        (display "  [info] observed: ") (write (obs-sql)) (newline)

        ;; ---- ...and one that rolls back ---------------------------------
        ;;
        ;; ROLLBACK does not go through connpool-call: the check-in path
        ;; sends it straight to the connection. An observer wired only into
        ;; connpool-call would show every statement EXCEPT the one saying
        ;; the transaction did not happen -- and would show it in green.
        (reset-logs!)
        (let ((escaped
                (guard (e (#t e))
                  (sql-transaction pool
                    (lambda (conn)
                      (connpool-call conn "INSERT 2" ocfg)
                      (raise 'nope))
                    ocfg))))
          (check "a rollback shows as begin, statement, rollback"
                 (equal? (obs-sql) (list "BEGIN" "INSERT 2" "ROLLBACK")))
          (check "and the connection was asked to roll back"
                 (equal? (reverse worker-log)
                         (list "BEGIN" "INSERT 2" "ROLLBACK")))
          (check "the transaction's own exception is what escaped"
                 (eq? escaped 'nope)))
        (send pool (vector 'pool-quit)))

      ;; ---- an observer that raises cannot reach the caller ---------------
      (reset-logs!)
      (let* ((attempts 0)
             (before (connpool-observer-failures))
             (ocfg (watch! (lambda (conn sql)
                             (set! attempts (+ attempts 1))
                             (raise 'observer-broke))))
             (pool (up! 1 recording-conn! cfg)))
        (let ((r (guard (e (#t (list 'raised e)))
                   (connpool-call pool "SELECT 1" ocfg))))
          (check "a raising observer does not reach the caller"
                 (equal? r (vector 'fake-rows "SELECT 1")))
          (check "it was called once and counted once"
                 (and (= attempts 1)
                      (= (connpool-observer-failures) (+ before 1))))
          (check "and the statement still reached the connection"
                 (equal? (reverse worker-log) (list "SELECT 1"))))
        (send pool (vector 'pool-quit)))

      ;; ---- ...including on the rollback path ----------------------------
      ;;
      ;; That path calls the observer from inside an after-thunk, usually
      ;; while an exception is already unwinding. An implementation that
      ;; guarded the call in connpool-call and made a bare one here would
      ;; pass every case above and lose the caller's exception here.
      (reset-logs!)
      (let* ((before (connpool-observer-failures))
             (ocfg (watch! (lambda (conn sql)
                             (when (string=? sql "ROLLBACK")
                               (raise 'observer-broke-on-rollback)))))
             (pool (up! 1 recording-conn! cfg)))
        (let ((escaped
                (guard (e (#t e))
                  (sql-transaction pool
                    (lambda (conn)
                      (connpool-call conn "INSERT 3" ocfg)
                      (raise 'nope))
                    ocfg))))
          (check "an observer raising on rollback keeps the exception"
                 (eq? escaped 'nope))
          (check "that failure is counted too"
                 (= (connpool-observer-failures) (+ before 1)))
          (check "and the rollback still reached the connection"
                 (equal? (reverse worker-log)
                         (list "BEGIN" "INSERT 3" "ROLLBACK"))))
        (send pool (vector 'pool-quit)))

      ;; ---- two observers do not share a stream --------------------------
      ;;
      ;; The observer belongs to the cfg it was installed on. Kept in one
      ;; module-level place instead, the last installation would answer for
      ;; every caller, and every case above would still pass.
      (reset-logs!)
      (let* ((a-log '()) (b-log '())
             (a (watch! (lambda (c sql) (set! a-log (cons sql a-log)))))
             (b (watch! (lambda (c sql) (set! b-log (cons sql b-log)))))
             (pool (up! 1 recording-conn! cfg)))
        (connpool-call pool "FOR A" a)
        (connpool-call pool "FOR B" b)
        (connpool-call pool "FOR A AGAIN" a)
        (check "an observer sees only calls made through its own cfg"
               (and (equal? (reverse a-log) (list "FOR A" "FOR A AGAIN"))
                    (equal? (reverse b-log) (list "FOR B"))))
        (send pool (vector 'pool-quit)))

      ;; ---- a cfg with no observer behaves as it always did ---------------
      (reset-logs!)
      (let* ((before (connpool-observer-failures))
             (pool (up! 1 recording-conn! cfg)))
        (let ((r (connpool-call pool "PLAIN" cfg)))
          (check "an unobserved call is answered normally"
                 (equal? r (vector 'fake-rows "PLAIN")))
          (check "it reached the connection exactly once"
                 (equal? (reverse worker-log) (list "PLAIN")))
          (check "and nothing was counted as an observer failure"
                 (= (connpool-observer-failures) before)))
        (send pool (vector 'pool-quit)))

      ;; ---- a killed borrower issues no rollback, and none is invented ----
      ;;
      ;; @kill discards winders, so the after-thunk that would roll back
      ;; never runs. What keeps the next borrower away from a half-open
      ;; transaction is the pool reclaiming on DOWN -- not a rollback. A
      ;; trace with no ROLLBACK in it therefore says nothing about whether
      ;; one happened, and this case exists so that reading is written down
      ;; somewhere that fails if the code ever starts inventing the event.
      (reset-logs!)
      (let* ((me self)
             (ocfg (watch! (lambda (conn sql)
                             (set! obs-log
                               (cons (list self conn sql) obs-log)))))
             (pool (up! 1 recording-conn! cfg))
             (victim (spawn (lambda ()
                              (sql-transaction pool
                                (lambda (conn)
                                  (connpool-call conn "INSERT 4" ocfg)
                                  (send me (vector 'in-transaction))
                                  (receive (after 10000 'done)))
                                ocfg)))))
        (receive (after 5000 (check "the victim reached its transaction" #f))
          (`#(in-transaction) 'ok))
        (kill victim 'killed-mid-transaction)
        (sleep-ms 400)
        (check "a killed borrower leaves begin and statement, no ending"
               (equal? (obs-sql) (list "BEGIN" "INSERT 4")))
        (check "and no ending was sent to the connection either"
               (equal? (reverse worker-log) (list "BEGIN" "INSERT 4")))
        (display "  [info] after a killed borrower: ")
        (write (obs-sql)) (newline)
        (send pool (vector 'pool-quit))))

    ;; ---- the stats timeout raises a structured error, not a bare symbol
    ;; A pool that never answers #(pool-stats ...) leaves connpool-stats
    ;; on its 5s deadline. What that deadline raises is part of the
    ;; library's error surface: a bare symbol cannot be told apart from
    ;; any other symbol in a guard, so the raise must carry the library
    ;; tag and the reason. This cell waits the full deadline -- the cost
    ;; of pinning the shape of a timeout is one timeout.
    (let ((deaf (spawn (lambda () (receive (`#(never-sent) 'ok))))))
      (let ((caught (guard (e (#t e))
                      (connpool-stats deaf)
                      'no-raise)))
        (check "the stats deadline raises the library's error shape"
               (and (vector? caught)
                    (= (vector-length caught) 3)
                    (eq? (vector-ref caught 0) 'connpool-error)
                    (eq? (vector-ref caught 1) 'stats-timeout)))
        ;; THE CONTEXT SLOT IS A PRINTABLE SCALAR, AND BOTH HALVES ARE
        ;; ASSERTED. The first version of this error carried the pool
        ;; itself -- a pcb record whose fields include the continuation
        ;; and the inbox -- and `write` on the vector walked into a
        ;; cycle and took the runtime down, printing the mailbox's
        ;; in-flight statements on the way. The type check names the
        ;; rule; the write below exercises the path that detonated, so
        ;; an object in the slot goes loudly red here rather than in an
        ;; operator's log.
        ;;
        ;; IF THIS SUITE DIES WITHOUT PRINTING ITS SUMMARY, LOOK HERE
        ;; FIRST. A PANIC from that write kills the process before the
        ;; report line, so in CI this cell's red does not look like an
        ;; assertion failure -- it looks like an infrastructure fault
        ;; (no output, nonzero exit). That is what it looked like when
        ;; the object was in the slot: one FAIL line from the type
        ;; check, then the runtime went down mid-suite.
        (check "the context slot is a scalar id, not the pool object"
               (and (vector? caught)
                    (= (vector-length caught) 3)
                    (let ((slot (vector-ref caught 2)))
                      (or (fixnum? slot) (string? slot)))))
        (check "the raised error survives being written"
               (and (vector? caught)
                    (string? (call-with-string-output-port
                              (lambda (p) (write caught p))))))
        (when (symbol? caught)
          (display "  [info] raised a bare symbol: ")
          (write caught) (newline))
        (kill deaf 'cleanup)))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "connpool-lifecycle: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
