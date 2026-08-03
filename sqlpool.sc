#!chezscheme
;;; (igropyr sqlpool) -- shared connection-pool engine for the SQL drivers.
;;;
;;; (igropyr mysql) and (igropyr postgresql) share one architecture: a
;;; green process per connection serving queries from its mailbox, a
;;; fixed pool behind a dispatcher, whole-connection leases for
;;; transactions, and monitors for crash reclaim. The machinery is
;;; subtle -- checkout-cancel races, reclaim of a borrower killed
;;; mid-transaction (dynamic-wind winders are discarded by @kill, so
;;; only the pool's monitor runs), adoption of workers that finish
;;; connecting after their pool or caller is gone -- and a fix landing
;;; in one duplicated copy but not the other would be a silent
;;; correctness bug. This library is the single copy.
;;;
;;; The engine is protocol-blind: the wire protocol, authentication and
;;; result parsing stay in each driver. The message contract a driver's
;;; connection process must speak:
;;;
;;;   #(db-query ,sql ,ref ,from)   run sql, then #(db-reply ,ref ,r) to from
;;;   #(db-adopt) / #(db-quit)      adoption handshake / shutdown
;;;   #(db-idle ,self)              to its pool after each finished query
;;;   #(db-conn-dead ,self)         to its pool when it replied a transport
;;;                                 error and is about to exit
;;;   #(db-up ,ref ,self ,status)   reported by a connecting worker
;;;   #(db-stats ,ref ,from)        -> #(db-stats-reply ,ref #f); a single
;;;                                 connection keeps no pool bookkeeping,
;;;                                 and answering is what stops the request
;;;                                 sitting in its mailbox forever
;;;
;;; Drivers keep their public error shapes: the engine takes the error
;;; VALUES it must produce and a predicate for recognizing an error
;;; reply, bundled in a config record built once per driver.

(library (igropyr sqlpool)
  (export make-sql-cfg
          sql-pool-loop sql-query sql-drain-stale! sql-check-pool-size!
          sql-transaction sql-call-with-connection sql-close!
          sql-pool-stats)
  (import (chezscheme) (igropyr actor) (igropyr libuv))

  (define query-timeout-ms 60000)
  (define checkout-timeout-ms 60000)   ; how long a caller parks for a free lease

  ;; error?: (r) -> is this reply the driver's error vector;
  ;; lost-err/closed-err/query-timeout-err/checkout-timeout-err: the
  ;; driver's error values for those events; begin-sql: the statement
  ;; that opens a transaction ("BEGIN" / "START TRANSACTION").
  (define-record-type (sql-cfg make-sql-cfg sql-cfg?)
    (fields error? lost-err closed-err
            query-timeout-err checkout-timeout-err begin-sql))

  ;; A negative or non-integer pool size never satisfies (= i n), so the
  ;; startup loop spawns connection workers without end; nothing downstream
  ;; would name it a configuration mistake, it presents as the database
  ;; melting.
  ;;
  ;; Exported because checking it INSIDE the pool process is too late for the
  ;; caller: mysql-pool and postgresql-pool spawn and hand back a pid, so a
  ;; bad size did not raise where it was written -- it returned a pid that
  ;; died a moment later, and the mistake surfaced as a pool that answered
  ;; nothing. The drivers call this before they spawn.
  (define (sql-check-pool-size! who n)
    (unless (and (integer? n) (exact? n) (> n 0))
      (assertion-violation who "pool size must be a positive exact integer" n)))

  ;; ---- pool ---------------------------------------------------------------

  ;; Fixed pool of n connections behind this dispatcher process. Queries go
  ;; to an idle connection or wait in a FIFO; replies flow directly from the
  ;; connection to the caller. Dead connections are replaced automatically
  ;; (1s backoff on failed connects); a caller whose connection dies
  ;; mid-query gets cfg's lost-err exactly once.
  ;;
  ;; spawn-conn!: (notify report-to ref) -> connection worker pid; the
  ;; worker must report #(db-up ,ref ,self ,status) and then wait for
  ;; #(db-adopt) before serving.
  (define (sql-pool-loop n spawn-conn! cfg)
    (define me self)
    (define idle '())
    (define busy (make-eq-hashtable))   ; conn pid -> (caller-pid . ref)
    ;; transaction leases: a whole connection handed to one borrower for the
    ;; extent of a transaction, kept out of query rotation until checked back
    ;; in (or its borrower dies). Each lease is its own record -- keyed by
    ;; connection, carrying the borrower, its monitor and the checkout ref --
    ;; so one borrower holding several leases (nested checkouts) never
    ;; clobbers its own bookkeeping.
    (define leased (make-eq-hashtable))       ; conn pid -> #(borrower mon ref)
    (define dying (make-eq-hashtable))        ; conn pid -> #t (being torn down)
    (define pending-front '())
    (define pending-back '())
    (define (pending?) (or (pair? pending-front) (pair? pending-back)))
    (define (pop-pending!)
      (when (null? pending-front)
        (set! pending-front (reverse pending-back))
        (set! pending-back '()))
      (let ((x (car pending-front)))
        (set! pending-front (cdr pending-front))
        x))
    ;; checkout requests waiting for a free connection; each is (ref . from)
    (define co-front '())
    (define co-back '())
    (define (co-pending?) (or (pair? co-front) (pair? co-back)))
    (define (pop-co!)
      (when (null? co-front)
        (set! co-front (reverse co-back))
        (set! co-back '()))
      (let ((x (car co-front)))
        (set! co-front (cdr co-front))
        x))
    ;; Workers that have been spawned but have not yet reported #(db-up ...).
    ;; They are in NO other table, so without this set a worker that dies
    ;; before reporting -- a crash in the driver, a connect error killing the
    ;; actor, a supervisor kill -- matched none of the DOWN branches below and
    ;; the pool silently lost that slot FOREVER. Enough of those and the pool
    ;; is empty while every caller queues behind connections that no longer
    ;; exist and will never be rebuilt.
    ;;
    ;; A worker that reports failure and then exits is removed here at db-up
    ;; time, because it has already scheduled its own backed-off retry; only
    ;; the ones that never reported are rebuilt from DOWN.
    (define connecting (make-eq-hashtable))
    (define (connect!)
      (let ((pid (spawn-conn! me me (gensym))))
        (hashtable-set! connecting pid #t)
        (monitor pid)))
    ;; a job is #(sql ref from queued-at mon)
    ;;
    ;; The MONITOR is why the last slot exists. A queued single query was not
    ;; monitored at all, so the caller-death cleanup below -- which does
    ;; filter pending jobs by caller -- never received the DOWN that would
    ;; run it. A caller killed by its supervisor also never runs its own
    ;; timeout cancel, so the statement stayed queued and executed whenever
    ;; a connection freed up: an INSERT applied for a process that had been
    ;; dead for however long the pool was saturated.
    ;; A busy entry is #(caller ref started-ms). It used to be (caller . ref);
    ;; the dispatch time is what makes query DURATION observable, measured
    ;; from here to the connection's db-idle -- the pool never sees the reply
    ;; itself, which goes straight from the connection to the caller.
    (define (assign! c job)
      (let ((waited (- (now-ms) (vector-ref job 3))))
        (set! stat-queue-wait-total (+ stat-queue-wait-total waited))
        (when (> waited stat-queue-wait-max) (set! stat-queue-wait-max waited)))
      (set! stat-queries (+ stat-queries 1))
      ;; it is dispatched: the pool no longer owes this caller anything it
      ;; could act on, and a monitor left behind would make its later death
      ;; look like a borrower dying with a lease
      (when (vector-ref job 4) (demonitor (vector-ref job 4)))
      (hashtable-set! busy c (vector (vector-ref job 2) (vector-ref job 1)
                                     (now-ms)))
      (send c (vector 'db-query (vector-ref job 0)
                      (vector-ref job 1) (vector-ref job 2))))
    ;; A waiter is #(ref from mon). The monitor is taken WHEN THE REQUEST
    ;; ARRIVES, not when a connection is handed over, because the window in
    ;; between is real: a caller can die queued, and monitoring only at
    ;; handover means the pool learns of it by monitoring a pid that is
    ;; already dead -- which delivers DOWN immediately (see actor.sc), lands
    ;; in the borrower-died case, and destroys a healthy connection that the
    ;; dead caller never received, let alone opened a transaction on.
    ;;
    ;; It is also what reclaims a lease afterwards: the supervisor killing a
    ;; stuck worker discards its dynamic-wind winders (actor @kill), so the
    ;; checkin never runs and this monitor is the only path back.
    ;; #f when the caller is already dead: monitor answers #f for a dead pid
    ;; (and delivers the DOWN at once). Leasing to it anyway handed a healthy
    ;; connection to a corpse, and the immediate DOWN then read as "a
    ;; borrower died holding a transaction" -- destroying and rebuilding a
    ;; connection nobody had ever touched.
    (define (make-waiter ref from)
      (let ((m (monitor from)))
        (and m (vector ref from m (now-ms)))))
    (define (waiter-ref w) (vector-ref w 0))
    (define (waiter-from w) (vector-ref w 1))
    (define (waiter-mon w) (vector-ref w 2))
    (define (waiter-queued-at w) (vector-ref w 3))
    ;; hand connection c to waiter w, carrying its existing monitor into the
    ;; lease record rather than taking a second one
    (define (lease! c w)
      (let ((waited (- (now-ms) (waiter-queued-at w))))
        (set! stat-checkout-wait-total (+ stat-checkout-wait-total waited))
        (when (> waited stat-checkout-wait-max)
          (set! stat-checkout-wait-max waited)))
      (set! stat-checkouts (+ stat-checkouts 1))
      (hashtable-set! leased c (vector (waiter-from w) (waiter-mon w)
                                       (waiter-ref w)))
      (send (waiter-from w) (vector 'db-checkout-reply (waiter-ref w) c)))
    (define (drop-lease! c entry)
      (demonitor (vector-ref entry 1))
      (hashtable-delete! leased c))
    ;; all (conn . entry) leases held by borrower pid
    (define (leases-of pid)
      (let ((ks (hashtable-keys leased)) (acc '()))
        (do ((i 0 (+ i 1))) ((= i (vector-length ks)) acc)
          (let* ((c (vector-ref ks i)) (e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) pid))
              (set! acc (cons (cons c e) acc)))))))
    ;; the lease created for checkout ref by borrower from, or #f
    (define (lease-by-ref ref from)
      (let ((ks (hashtable-keys leased)))
        (let loop ((i 0))
          (if (= i (vector-length ks))
              #f
              (let* ((c (vector-ref ks i)) (e (hashtable-ref leased c #f)))
                (if (and e (eq? (vector-ref e 0) from) (eq? (vector-ref e 2) ref))
                    (cons c e)
                    (loop (+ i 1))))))))
    ;; alternate between the single-query queue and checkout waiters when
    ;; both are non-empty, so a sustained stream of one kind cannot starve
    ;; the other past its timeout
    (define co-turn #f)
    ;; ---- statistics ------------------------------------------------------
    ;;
    ;; A saturated pool and a slow database look identical from outside: both
    ;; present as slow requests. What tells them apart is where the time goes
    ;; -- waiting for a connection, or running the statement -- and nothing
    ;; here made that observable. Callers could not size a pool, could not
    ;; tell a leak (in-use never returns to zero) from load, and saw timeouts
    ;; only as individual raises with no rate behind them.
    ;;
    ;; Latencies are kept as total + max + count rather than a histogram: the
    ;; mean falls out of total/count, the max is the tail that actually hurts,
    ;; and both are one fixnum add on the hot path.
    ;;
    ;; QUERY DURATION is measured from dispatch to the connection's db-idle,
    ;; because the pool never sees the reply -- that goes straight from the
    ;; connection to the caller. It therefore excludes queue wait, which is
    ;; reported separately and is the number that matters when sizing.
    (define stat-queries 0)              ; statements dispatched
    (define stat-query-timeouts 0)       ; callers that gave up (db-query-cancel)
    (define stat-checkouts 0)            ; leases granted
    (define stat-checkout-timeouts 0)    ; callers that gave up waiting
    (define stat-connects 0)             ; workers that came up
    (define stat-connect-failures 0)
    (define stat-connections-lost 0)     ; live connections that died
    (define stat-queue-wait-total 0)     ; ms a statement spent queued
    (define stat-queue-wait-max 0)
    (define stat-checkout-wait-total 0)  ; ms a borrower spent waiting
    (define stat-checkout-wait-max 0)
    (define stat-query-total 0)          ; ms dispatch -> db-idle
    (define stat-query-max 0)
    (define stat-completed 0)            ; the count behind stat-query-total
    (define started-at (now-ms))

    ;; grows 1s -> 2 -> 4 ... to a ceiling; reset by any successful connect
    (define backoff-ms 0)
    (define max-backoff-ms 30000)
    (define (next-backoff!)
      (let ((base (if (= backoff-ms 0) 1000 (min (* 2 backoff-ms) max-backoff-ms))))
        (set! backoff-ms base)
        ;; +/- 20%, so slots that failed together stop retrying in lockstep
        (let ((j (fxdiv base 5)))
          (max 100 (+ (- base j) (random (max 1 (* 2 j))))))))
    (define (make-available! c)
      (hashtable-delete! busy c)
      (cond
        ((and (pending?) (co-pending?))
         (if co-turn
             (begin (set! co-turn #f) (lease! c (pop-co!)))
             (begin (set! co-turn #t) (assign! c (pop-pending!)))))
        ((pending?) (assign! c (pop-pending!)))
        ((co-pending?) (lease! c (pop-co!)))
        (else (set! idle (cons c idle)))))
    (sql-check-pool-size! 'sql-pool n)
    (do ((i 0 (+ i 1))) ((= i n)) (connect!))
    (let loop ()
      (receive
        (`#(db-query ,sql ,ref ,from)
          (if (pair? idle)
              ;; dispatched at once: nothing to watch, the connection
              ;; answers the caller directly
              (let ((c (car idle)))
                (set! idle (cdr idle))
                (assign! c (vector sql ref from (now-ms) #f)))
              ;; queued: watch the caller for as long as it is waiting.
              ;; monitor returns #f for a pid that is ALREADY dead (and
              ;; delivers the DOWN immediately), so that request is simply
              ;; not queued -- there is nobody to answer.
              (let ((m (monitor from)))
                (when m
                  (set! pending-back
                        (cons (vector sql ref from (now-ms) m) pending-back)))))
          (loop))
        (`#(db-idle ,c)
          ;; This is where a dispatched statement finishes, as far as the
          ;; pool can see it: the reply itself went straight to the caller.
          (let ((e (hashtable-ref busy c #f)))
            (when e
              (let ((took (- (now-ms) (vector-ref e 2))))
                (set! stat-completed (+ stat-completed 1))
                (set! stat-query-total (+ stat-query-total took))
                (when (> took stat-query-max) (set! stat-query-max took)))))
          ;; a leased connection pings idle after each of its transaction
          ;; queries -- ignore those, it stays with its lessee; likewise skip
          ;; a connection we are tearing down.
          (unless (or (hashtable-ref leased c #f) (hashtable-ref dying c #f))
            (make-available! c))
          (loop))
        (`#(db-conn-dead ,c)
          ;; the connection already sent the transport-error reply to its
          ;; caller and is about to exit: clear the busy entry so the DOWN
          ;; below does not send a duplicate reply, and mark it dying so
          ;; the DOWN still rebuilds it.
          (hashtable-delete! busy c)
          (hashtable-set! dying c #t)
          (loop))
        (`#(db-checkout ,ref ,from)
          (let ((w (make-waiter ref from)))
            (when w
              (if (pair? idle)
                  (let ((c (car idle)))
                    (set! idle (cdr idle))
                    (lease! c w))
                  (set! co-back (cons w co-back)))))
          (loop))
        (`#(db-checkin ,from ,c)
          ;; only when c really is leased to `from` -- guards a stale or double
          ;; checkin (e.g. after the connection already died and was rebuilt).
          (let ((e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) from))
              (drop-lease! c e)
              (make-available! c)))
          (loop))
        (`#(db-checkin-broken ,from ,c)
          ;; the lessee could not clean the connection (e.g. ROLLBACK failed):
          ;; drop the lease and destroy+rebuild it rather than ever lending a
          ;; possibly-open transaction to the next caller. Atomic here (single
          ;; loop), so the connection is never made available in between.
          (let ((e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) from))
              (drop-lease! c e)
              (hashtable-set! dying c #t)
              (send c (vector 'db-quit))))       ; -> DOWN -> rebuild (case 2)
          (loop))
        (`#(db-query-cancel ,ref ,from)
          ;; A query timed out. If it is STILL QUEUED it has not been sent
          ;; anywhere, so dropping it is exact: the caller has already been
          ;; told the call failed, and executing it later would apply a write
          ;; the application believes never happened. (Once assigned to a
          ;; connection the statement is in flight and its outcome is
          ;; genuinely unknown -- that is documented on sql-query and is not
          ;; something a cancel can undo.)
          (set! stat-query-timeouts (+ stat-query-timeouts 1))
          ;; Record what this caller WAITED before giving up. Timing only the
          ;; requests that eventually got a connection left the wait metrics
          ;; blind to precisely the situation they exist for: a pool so
          ;; saturated that everything times out reported a maximum wait of
          ;; zero, because nothing ever waited successfully.
          (let ((mine? (lambda (job)
                         (if (and (eq? (vector-ref job 1) ref)
                                  (eq? (vector-ref job 2) from))
                             (let ((waited (- (now-ms) (vector-ref job 3))))
                               (when (vector-ref job 4)
                                 (demonitor (vector-ref job 4)))
                               (set! stat-queue-wait-total
                                     (+ stat-queue-wait-total waited))
                               (when (> waited stat-queue-wait-max)
                                 (set! stat-queue-wait-max waited))
                               #f)
                             #t))))
            (set! pending-front (filter mine? pending-front))
            (set! pending-back  (filter mine? pending-back)))
          (loop))
        (`#(db-checkout-cancel ,ref ,from)
          ;; a checkout timed out: drop its still-queued request so a freed
          ;; connection is never leased to a borrower that has moved on. If the
          ;; pool already leased one to it (raced the timeout), reclaim exactly
          ;; that lease -- matched by ref, so other leases the same borrower
          ;; holds are untouched.
          ;; drop the queued request AND release its monitor: without the
          ;; demonitor the pool keeps watching a caller it no longer owes
          ;; anything, and that caller's eventual death lands in the
          ;; borrower-died case with no lease to find
          (set! stat-checkout-timeouts (+ stat-checkout-timeouts 1))
          (let ((drop! (lambda (w)
                         (when (eq? (waiter-ref w) ref)
                           ;; same as the query side: the wait that ended in
                           ;; a timeout is the one worth knowing about
                           (let ((waited (- (now-ms) (waiter-queued-at w))))
                             (set! stat-checkout-wait-total
                                   (+ stat-checkout-wait-total waited))
                             (when (> waited stat-checkout-wait-max)
                               (set! stat-checkout-wait-max waited)))
                           (demonitor (waiter-mon w)))
                         (not (eq? (waiter-ref w) ref)))))
            (set! co-front (filter drop! co-front))
            (set! co-back  (filter drop! co-back)))
          (let ((hit (lease-by-ref ref from)))
            (when hit
              (drop-lease! (car hit) (cdr hit))
              (make-available! (car hit))))
          (loop))
        (`#(db-up ,ref ,pid ,status)
          (hashtable-delete! connecting pid)
          (if (eq? status 'ok)
              (begin
                (send pid (vector 'db-adopt))
                (set! stat-connects (+ stat-connects 1))
                (set! backoff-ms 0)          ; a success clears the penalty
                (make-available! pid))
              ;; Failed connect: retry with EXPONENTIAL BACKOFF. A fixed one
              ;; second is right for a database that is restarting and wrong
              ;; for one that will never accept us -- a bad password, a
              ;; missing database, an expired certificate, an unsupported
              ;; auth plugin. Those retried once per second per slot forever,
              ;; and for PostgreSQL each attempt runs a pure-Scheme PBKDF2,
              ;; so a large pool against a wrong password is a CPU load on
              ;; the one OS thread rather than a background annoyance.
              ;;
              ;; Jittered, so a pool whose slots failed together does not
              ;; reconnect in lockstep forever after.
              (begin
                (set! stat-connect-failures (+ stat-connect-failures 1))
                (let ((wait (next-backoff!)))
                  (spawn (lambda ()
                           (sleep-ms wait)
                           (send me (vector 'pool-reconnect)))))))
          (loop))
        (`#(pool-reconnect)
          (connect!)
          (loop))
        (`#(db-stats ,ref ,from)
          (send from
            (vector 'db-stats-reply ref
              (list
                ;; gauges: what the pool looks like right now
                (cons 'size n)
                (cons 'idle (length idle))
                (cons 'busy (hashtable-size busy))
                (cons 'leased (hashtable-size leased))
                ;; what a caller means by "in use": running a statement or
                ;; held for a transaction. A pool whose in-use never falls
                ;; back to zero under no load is leaking leases, and that is
                ;; not visible from either number alone.
                (cons 'in-use (+ (hashtable-size busy) (hashtable-size leased)))
                (cons 'connecting (hashtable-size connecting))
                (cons 'dying (hashtable-size dying))
                (cons 'pending (+ (length pending-front) (length pending-back)))
                (cons 'checkout-pending (+ (length co-front) (length co-back)))
                ;; counters since the pool started
                (cons 'queries stat-queries)
                (cons 'queries-completed stat-completed)
                (cons 'query-timeouts stat-query-timeouts)
                (cons 'checkouts stat-checkouts)
                (cons 'checkout-timeouts stat-checkout-timeouts)
                (cons 'connects stat-connects)
                (cons 'connect-failures stat-connect-failures)
                (cons 'connections-lost stat-connections-lost)
                ;; latency: total + max, with the count above them, so the
                ;; mean is total/count and the tail is not averaged away
                (cons 'queue-wait-ms-total stat-queue-wait-total)
                (cons 'queue-wait-ms-max stat-queue-wait-max)
                (cons 'checkout-wait-ms-total stat-checkout-wait-total)
                (cons 'checkout-wait-ms-max stat-checkout-wait-max)
                (cons 'query-ms-total stat-query-total)
                (cons 'query-ms-max stat-query-max)
                (cons 'uptime-ms (- (now-ms) started-at)))))
          (loop))
        (`#(DOWN ,pid ,reason)
          ;; First: a caller that died while still QUEUED holds nothing. Drop
          ;; its requests before the cases below, so it is never mistaken for
          ;; a borrower whose connection might carry an open transaction --
          ;; that mistake destroys and rebuilds a healthy connection the dead
          ;; caller never received. Its monitor died with it, so no demonitor.
          (let ((mine? (lambda (w) (not (eq? (waiter-from w) pid)))))
            (set! co-front (filter mine? co-front))
            (set! co-back  (filter mine? co-back)))
          (let ((mine? (lambda (job) (not (eq? (vector-ref job 2) pid)))))
            (set! pending-front (filter mine? pending-front))
            (set! pending-back  (filter mine? pending-back)))
          (cond
            ;; (1) a transaction borrower died (a crash, or the supervisor
            ;; killing a stuck worker -- winders discarded, so no checkin ran).
            ;; Its connections may hold half-open transactions: destroy every
            ;; one it held and let each connection's own DOWN below rebuild a
            ;; clean replacement, rather than ever returning an open
            ;; transaction to the pool.
            ((let ((hits (leases-of pid))) (and (pair? hits) hits))
             => (lambda (hits)
                  (for-each
                    (lambda (hit)
                      (drop-lease! (car hit) (cdr hit))
                      (hashtable-set! dying (car hit) #t)
                      (send (car hit) (vector 'db-quit)))
                    hits)))
            ;; (2) a connection died (idle, mid single-query, leased, or one we
            ;; are already tearing down). Fail any waiting single-query caller,
            ;; drop a lease if it held one, and rebuild. Failed connect workers
            ;; already scheduled their own retry, so they fall through here.
            ((or (memq pid idle) (hashtable-contains? busy pid)
                 (hashtable-ref leased pid #f) (hashtable-ref dying pid #f))
             (set! idle (remq pid idle))
             (hashtable-delete! dying pid)
             (set! stat-connections-lost (+ stat-connections-lost 1))
             (let ((entry (hashtable-ref busy pid #f)))
               (hashtable-delete! busy pid)
               (when entry
                 (send (vector-ref entry 0)
                       (vector 'db-reply (vector-ref entry 1)
                               (sql-cfg-lost-err cfg)))))
             (let ((e (hashtable-ref leased pid #f)))
               (when e (drop-lease! pid e)))
             (connect!))
            ;; (3) a worker that died while still connecting, without ever
            ;; reporting. Nothing scheduled a retry for it, so this slot is
            ;; rebuilt here -- backed off, because dying during connect is a
            ;; connect failure and retrying it flat out is the storm that
            ;; next-backoff! exists to prevent.
            ((hashtable-contains? connecting pid)
             (hashtable-delete! connecting pid)
             ;; A worker that dies in the handshake failed to connect just
             ;; as surely as one that reported failure. Counting only the
             ;; latter meant a driver crashing on every greeting showed
             ;; connect-failures 0 while the pool never filled -- the one
             ;; number an operator would look at, reading healthy.
             (set! stat-connect-failures (+ stat-connect-failures 1))
             (let ((wait (next-backoff!)))
               (spawn (lambda ()
                        (sleep-ms wait)
                        (send me (vector 'pool-reconnect)))))))
          (loop))
        (`#(db-quit)
          (for-each (lambda (c) (send c (vector 'db-quit))) idle)
          (vector-for-each
            (lambda (c) (send c (vector 'db-quit)))
            (hashtable-keys busy))
          (vector-for-each
            (lambda (c) (send c (vector 'db-quit)))
            (hashtable-keys leased))
          ;; connections still authenticating self-terminate: nobody adopts
          ;; them once this process is gone. Queued callers get an error now
          ;; instead of parking until their timeouts.
          (let ((closed (sql-cfg-closed-err cfg)))
            (for-each
              (lambda (job)
                (send (vector-ref job 2)
                      (vector 'db-reply (vector-ref job 1) closed)))
              (append pending-front (reverse pending-back)))
            (for-each
              (lambda (req)
                (send (waiter-from req)
                      (vector 'db-checkout-failed (waiter-ref req) closed)))
              (append co-front (reverse co-back))))
          'done))))

  ;; ---- caller-side operations ---------------------------------------------

  ;; These operations are strictly synchronous within one green process,
  ;; so any db-reply / db-checkout-reply / db-checkout-failed sitting in
  ;; the mailbox at ENTRY is by construction stale -- the late answer to
  ;; an earlier call that timed out (its gensym ref can never be matched
  ;; again, and a stale checkout's lease was already reclaimed by the
  ;; cancel). Drain them here, or a long-lived process that suffers
  ;; timeouts accumulates immortal messages that slow every later
  ;; selective-receive scan.
  ;; Exported because the DRIVERS need it too: a single-connection connect
  ;; that times out leaves its worker's late up-report in the caller's
  ;; mailbox, and a long-lived process that reconnects in a loop -- a
  ;; supervisor, a reconnect manager -- never calls sql-query, so nothing
  ;; ever cleared them. They are immortal (the per-attempt ref can never
  ;; match again) and every later selective receive scans past all of them.
  (define sql-drain-stale! (lambda () (drain-stale!)))

  (define (drain-stale!)
    (let loop ()
      (receive (after 0 'done)
        (`#(db-reply ,r ,v) (loop))
        (`#(db-checkout-reply ,r ,conn) (loop))
        (`#(db-checkout-failed ,r ,e) (loop))
        ;; a lone driver connect that timed out leaves the worker's late
        ;; up-report behind (its per-attempt ref never matches again)
        (`#(db-up ,r ,p ,s) (loop))
        (`#(db-stats-reply ,r ,st) (loop)))))

  ;; A snapshot of the pool: an alist of gauges, counters and latency
  ;; totals. See the db-stats clause in the loop for what each key means.
  ;;
  ;; POOL ONLY. A lone connection answers #(db-stats-reply ,ref #f), which
  ;; raises here -- it is not a degenerate pool, it has none of this
  ;; bookkeeping, and reporting zeros would be worse than refusing: an
  ;; operator reading `in-use 0` would conclude the connection was free.
  ;; The reply exists so the request cannot sit in a connection's mailbox
  ;; forever, which is the failure mode a bare timeout would have left.
  (define (sql-pool-stats pool)
    (drain-stale!)
    (let ((ref (gensym)))
      (send pool (vector 'db-stats ref self))
      (receive (after 5000 (raise 'sql-pool-stats-timeout))
        (`#(db-stats-reply ,@ref ,st)
          (or st
              (assertion-violation 'sql-pool-stats
                "not a pool -- a single connection keeps no pool statistics"
                pool))))))

  ;; Run one SQL statement on a connection or a pool; blocks only the
  ;; calling green process. The per-call ref (a fresh gensym) is echoed in
  ;; the reply, so a late reply after a timeout will not be matched by the
  ;; caller's next query. A timed-out statement's outcome is UNKNOWN -- it
  ;; may still execute on the server.
  (define (sql-query h sql cfg)
    (drain-stale!)
    (let ((ref (gensym)))
      (send h (vector 'db-query sql ref self))
      (receive (after query-timeout-ms
                  ;; symmetric with sql-checkout: tell the pool to drop the
                  ;; request if it is still queued. A statement left behind
                  ;; runs whenever the pool recovers -- long after the caller
                  ;; was told it failed -- so a write the application gave up
                  ;; on still lands. Harmless against a lone connection, which
                  ;; ignores the message.
                  (send h (vector 'db-query-cancel ref self))
                  (raise (sql-cfg-query-timeout-err cfg)))
        (`#(db-reply ,@ref ,r)
          (if ((sql-cfg-error? cfg) r) (raise r) r)))))

  ;; Ask the pool for a dedicated connection and park until one is free (or
  ;; raise cfg's checkout-timeout-err -- the pool is saturated, nothing is
  ;; broken). Internal: callers use the with-connection / transaction
  ;; wrappers, which guarantee checkin.
  (define (sql-checkout pool cfg)
    (drain-stale!)
    (let ((ref (gensym)))
      (send pool (vector 'db-checkout ref self))
      (receive (after checkout-timeout-ms
                  ;; tell the pool to drop (or reclaim) this request --
                  ;; otherwise a connection freed after the timeout is leased
                  ;; to us and never checked in, bleeding the pool.
                  (send pool (vector 'db-checkout-cancel ref self))
                  (raise (sql-cfg-checkout-timeout-err cfg)))
        (`#(db-checkout-reply ,@ref ,conn) conn)
        (`#(db-checkout-failed ,@ref ,err) (raise err)))))

  ;; ROLLBACK on a borrowed connection without parking a full query timeout
  ;; when the connection is already dead: monitor it, so a dead process
  ;; answers with an immediate DOWN instead of 60 seconds of silence.
  ;; -> #t when the connection cannot be returned clean.
  (define (sql-rollback! conn cfg)
    (let ((m (monitor conn)) (ref (gensym)))
      (let ((broken
             (guard (e (#t #t))
               (send conn (vector 'db-query "ROLLBACK" ref self))
               (receive (after query-timeout-ms #t)
                 (`#(db-reply ,@ref ,r) ((sql-cfg-error? cfg) r))
                 (`#(DOWN ,@conn ,reason) #t)))))
        (when m
          (demonitor m)
          ;; a DOWN already queued between the reply and the demonitor
          ;; would sit unmatched forever -- drain it
          (receive (after 0 'ok) (`#(DOWN ,@conn ,reason) 'ok)))
        broken)))

  ;; Borrow one whole connection from a POOL for the extent of proc, then
  ;; return it -- even if proc raises or exits non-locally. proc receives the
  ;; connection process; queries on it cannot interleave with other callers.
  ;; Don't send queries (or a second checkout) to the pool itself while
  ;; holding a connection: an exhausted pool deadlocks the former and delays
  ;; the latter.
  (define (sql-call-with-connection pool proc cfg)
    (let ((conn (sql-checkout pool cfg)))
      (dynamic-wind
        (lambda () (void))
        (lambda () (proc conn))
        (lambda () (send pool (vector 'db-checkin self conn))))))

  ;; Run proc inside a transaction on a borrowed pool connection: cfg's
  ;; begin-sql first, then COMMIT if proc returns normally, or ROLLBACK if
  ;; it escapes. Returns proc's value. Self-manages the lease (rather than
  ;; sql-call-with-connection) so the single return message can be checkin
  ;; OR checkin-broken -- no second checkin racing the discard. Kill-safety:
  ;; if the borrower is killed the winders are discarded, no message is
  ;; sent, and the pool's monitor reclaims + rebuilds the connection, so a
  ;; half-open transaction is never handed to the next caller.
  (define (sql-transaction pool proc cfg)
    (let ((conn (sql-checkout pool cfg)))
      (let ((committed #f) (broken #f))
        (dynamic-wind
          (lambda () (void))
          (lambda ()
            ;; inside the wind: if the BEGIN itself fails, the after-clause
            ;; still runs, so the lease is always returned.
            (sql-query conn (sql-cfg-begin-sql cfg) cfg)
            (let ((r (proc conn)))
              (sql-query conn "COMMIT" cfg)
              (set! committed #t)
              r))
          (lambda ()
            (unless committed
              ;; roll back; if ROLLBACK fails (or the connection is dead)
              ;; the transaction may still be open, so flag the connection
              ;; for discard instead of returning it dirty.
              (set! broken (sql-rollback! conn cfg)))
            (send pool (vector (if broken 'db-checkin-broken 'db-checkin)
                               self conn)))))))

  ;; Close a pool (or a lone connection). Leased connections are quit
  ;; immediately: a transaction still in flight on one will time out on
  ;; its next statement -- close the pool only after its borrowers are
  ;; done.
  (define (sql-close! h)
    (send h (vector 'db-quit)))
)
