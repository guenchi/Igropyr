#!chezscheme
;;; (igropyr connpool) -- a pool of connections to something that is not us.
;;;
;;; Every driver here has the same architecture: a green process per
;;; connection serving requests from its mailbox, a fixed pool behind a
;;; dispatcher, whole-connection leases, and monitors for crash reclaim.
;;; The machinery is subtle -- checkout-cancel races, reclaim of a
;;; borrower killed mid-lease (dynamic-wind winders are discarded by
;;; @kill, so only the pool's monitor runs), adoption of workers that
;;; finish connecting after their pool or caller is gone, refusing to
;;; re-lend a connection already on its way out -- and a fix landing in
;;; one duplicated copy but not the other would be a silent correctness
;;; bug. This library is the single copy.
;;;
;;; It was written for (igropyr mysql) and (igropyr postgresql) and was
;;; called sqlpool. What it actually models is narrower than SQL and
;;; wider: a scarce EXCLUSIVE resource whose work happens on the far side
;;; of a socket, borrowed for the length of one request. (igropyr qjspool)
;;; -- QuickJS renders in worker processes -- is the third driver, and
;;; fitting it generalized this engine three times: the request became
;;; opaque (it had been SQL-shaped, down to the message names); the
;;; deadlines moved from module constants into the config, because a
;;; minute is right for a database and wrong for a render; and
;;; connpool-lease grew broken-on-escape?. (NOT because a timed-out
;;; render may still be running while a query may not -- a timed-out
;;; statement may still execute on the server too, as connpool-call
;;; says below. The question the flag answers is narrower: after the
;;; borrower leaves non-locally, is this connection safe to LEND AGAIN?
;;; For a SQL connection the worker serialises what is left and the
;;; answer is yes; for a render worker a cancelled job and a new one
;;; can race, and the answer is no.)
;;; A fourth driver should expect to find a fourth.
;;;
;;; The engine is PROTOCOL-BLIND: the wire protocol, authentication and
;;; result parsing stay in each driver. The message contract a driver's
;;; connection process must speak:
;;;
;;;   #(pool-request ,req ,ref ,from)  do req, then #(pool-reply ,ref ,r) to from
;;;   #(pool-adopt) / #(pool-quit)     adoption handshake / shutdown
;;;   #(pool-idle ,self ,ref)         to its pool after each finished request,
;;;                                    naming the one it just finished -- a late
;;;                                    idle must not free a connection that has
;;;                                    since been given something else
;;;   #(pool-conn-dead ,self)          to its pool BEFORE it replies a transport
;;;                                    error, so the mark arrives before the
;;;                                    check-in that reply sets off
;;;   #(pool-up ,ref ,self ,status)    reported by a connecting worker
;;;   #(pool-stats ,ref ,from)         -> #(pool-stats-reply ,ref #f); a single
;;;                                    connection keeps no pool bookkeeping,
;;;                                    and answering is what stops the request
;;;                                    sitting in its mailbox forever
;;;
;;; A connection must also answer pool-quit and pool-request-cancel WHILE
;;; IT IS WAITING for the far side. A receive that matches only the socket
;;; strands both: the pool cannot reclaim it and the caller cannot
;;; abandon it, and the connection sits marked-dying and un-rebuilt for as
;;; long as its own deadline allows.
;;;
;;; Drivers keep their public error shapes: the engine takes the error
;;; VALUES it must produce and a predicate for recognizing an error
;;; reply, bundled in a config record built once per driver.
;;;
;;; sql-transaction is the one SQL-shaped thing left here, and it stays
;;; because the alternative is worse: it is built on checkout + request +
;;; check-in-or-check-in-broken, and that kill-safety is exactly the
;;; reasoning this file exists to keep in one copy. Everything below it
;;; is blind to what the connections are.

(library (igropyr connpool)
  (export make-connpool-cfg
          connpool-loop connpool-call connpool-drain-stale! connpool-check-size!
          sql-transaction connpool-lease connpool-close!
          connpool-stats
          connpool-cfg-set-observer! connpool-observer-failures)
  (import (chezscheme) (igropyr actor) (igropyr libuv))

  (define default-query-ms 60000)
  (define default-checkout-ms 60000)   ; how long a caller parks for a free lease

  ;; error?: (r) -> is this reply the driver's error vector;
  ;; lost-err/closed-err/query-timeout-err/checkout-timeout-err: the
  ;; driver's error values for those events; begin-sql: the statement
  ;; that opens a transaction ("BEGIN" / "START TRANSACTION");
  ;; query-ms/checkout-ms: how long a caller waits for a reply, and for a
  ;; free connection, before giving up.
  (define-record-type (connpool-cfg make-cfg connpool-cfg?)
    (fields error? lost-err closed-err
            query-timeout-err checkout-timeout-err begin-sql
            query-ms checkout-ms (mutable observer)))

  ;; The deadlines are OPTIONAL and default to a minute. A minute is the
  ;; right order of magnitude for a database and the wrong one for a
  ;; resource whose work is measured in milliseconds -- and this engine is
  ;; no longer only for databases. A driver that needs its own passes them;
  ;; the SQL drivers do not, so their calls are unchanged.
  ;;
  ;; They belong to the config rather than to the library because a deadline
  ;; is a property of the resource, not of the pooling: two pools of
  ;; different things in one process need different ones, and a module-level
  ;; constant can only give them the same.
  (define (make-connpool-cfg error? lost-err closed-err
                        query-timeout-err checkout-timeout-err begin-sql
                        . rest)
    (define (arg i default)
      (let loop ((r rest) (i i))
        (cond ((null? r) default)
              ((> i 0) (loop (cdr r) (- i 1)))
              (else (car r)))))
    (let ((q (arg 0 default-query-ms)) (c (arg 1 default-checkout-ms)))
      (unless (and (integer? q) (exact? q) (> q 0))
        (assertion-violation 'make-connpool-cfg
          "query timeout must be a positive exact integer (ms)" q))
      (unless (and (integer? c) (exact? c) (> c 0))
        (assertion-violation 'make-connpool-cfg
          "checkout timeout must be a positive exact integer (ms)" c))
      (make-cfg error? lost-err closed-err
                query-timeout-err checkout-timeout-err begin-sql q c #f)))

  ;; ---- request observation -----------------------------------------------
  ;;
  ;; Every statement this engine dispatches, handed to `proc` as
  ;; (proc conn sql) at the moment it is sent. Off by default; when no
  ;; observer is installed the dispatch path pays one #f test.
  ;;
  ;; WHY HERE AND NOT AROUND A TRANSACTION. A caller that wraps its own
  ;; query function sees its own statements and nothing else -- the BEGIN,
  ;; the COMMIT and the ROLLBACK are issued inside this engine, so a trace
  ;; built that way can show three statements in a row and still not
  ;; distinguish one transaction from three. It cannot even tell that no
  ;; COMMIT slipped in between, which is the one thing such a trace is
  ;; usually built to establish. Observing dispatch puts all of them in
  ;; one stream, already in order, with nothing to interleave.
  ;;
  ;; "Transaction" is also not this engine's vocabulary -- it pools a
  ;; scarce exclusive resource and a database is one instance -- so the
  ;; hook is about REQUESTS, and a transaction boundary is simply a
  ;; request whose text says so.
  ;;
  ;; SCOPE IS ONE DRIVER MODULE, NOT ONE POOL. The cfg holding the
  ;; observer is built once per driver and shared by every pool that
  ;; driver serves, so two pools opened through the same driver in one
  ;; process report to the SAME observer, with no field distinguishing
  ;; them beyond the connection. That is a consequence of where the
  ;; observer lives, not an oversight; a caller that needs them apart
  ;; must tell them apart by connection. Install before there is traffic:
  ;; the field is mutable and nothing here orders an install against a
  ;; dispatch already under way.
  ;;
  ;; IT RUNS IN THE BORROWER'S PROCESS, which is the reason this is safe
  ;; to expose: a slow or wedged observer delays only the caller that
  ;; provoked it and cannot stall the pool. It must not, however, break
  ;; what it observes, so every call is guarded and a raise is counted
  ;; rather than propagated -- see connpool-observer-failures, which
  ;; exists because this library has no logging and a silently failing
  ;; observer would otherwise look exactly like an idle one.
  ;;
  ;; AND IT IS CALLED ON THE EXCEPTION PATH TOO. The ROLLBACK below is
  ;; issued from sql-transaction's after-thunk, so an observer will find
  ;; itself running during an unwind, usually with an exception already in
  ;; flight. Anything it does that assumes a normal return -- raising, in
  ;; particular -- is wrong there.
  ;;
  ;; TWO THINGS IT DOES NOT ESTABLISH, both of which a reader will
  ;; otherwise assume:
  ;;
  ;;   - A KILLED BORROWER EMITS NO ROLLBACK. sql-transaction rolls back
  ;;     from a dynamic-wind after-thunk and @kill discards winders, so
  ;;     that path produces NO event at all. The absence of a rollback
  ;;     event therefore says neither "the transaction is still open" nor
  ;;     "it committed" -- what actually protects the next borrower is the
  ;;     pool's monitor reclaiming and rebuilding the connection on DOWN,
  ;;     and what the observer sees of that is nothing. Expect no event
  ;;     and a rebuilt connection.
  ;;   - AN EVENT IS EVIDENCE, NOT AUTHORITY. It reports what was
  ;;     dispatched. It confers nothing: an observer is not a participant
  ;;     in the transaction it is watching, and "I saw X, so I may do Y"
  ;;     does not follow from anything here.
  (define observer-failures 0)
  (define (connpool-observer-failures) observer-failures)

  (define (connpool-cfg-set-observer! cfg proc)
    (unless (or (not proc) (procedure? proc))
      (assertion-violation 'connpool-cfg-set-observer!
        "observer must be a procedure of two arguments, or #f" proc))
    (connpool-cfg-observer-set! cfg proc)
    (void))

  ;; Guarded at every call site: an observer that raises is counted and
  ;; the statement proceeds. It gets the connection and the request; the
  ;; outcome is the caller's own return value and is deliberately not
  ;; repeated here, so this cannot drift into being a second result path.
  (define (observe! cfg conn sql)
    (let ((proc (connpool-cfg-observer cfg)))
      (when proc
        (guard (e (#t (set! observer-failures (+ observer-failures 1))))
          (proc conn sql)))))

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
  (define (connpool-check-size! who n)
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
  ;; worker must report #(pool-up ,ref ,self ,status) and then wait for
  ;; #(pool-adopt) before serving.
  (define (connpool-loop n spawn-conn! cfg)
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
    (define dying (make-eq-hashtable))        ; conn pid -> 'teardown | 'transport

    ;; FIRST WRITER WINS -- whoever noticed first says what this is.
    ;;
    ;; The two marks are written from different places and the last writer
    ;; used to win, so each of them could erase the other:
    ;;
    ;;   the pool tears a connection down (pool-quit) while it is mid
    ;;   request; every driver answers pool-quit as a TRANSPORT failure, so
    ;;   the connection then reports pool-conn-dead and the pool's own
    ;;   decision became 'transport -- a healthy connection the pool asked
    ;;   to go now looks stillborn, and the backoff it triggers is
    ;;   pool-wide and doubles. A supervisor reaping stuck borrowers walked
    ;;   an entirely healthy pool up toward the ceiling;
    ;;
    ;;   and the other way, a check-in-broken arriving after a transport
    ;;   failure turned it into "the pool asked for this" and rebuilt with
    ;;   NO backoff -- the spin the backoff exists to stop.
    ;;
    ;; Neither "last wins" nor "teardown wins" is right, because the two
    ;; sequences are mirror images and each rule breaks the other one:
    ;; in the first the pool acted on a HEALTHY connection and the transport
    ;; report is an artifact of its own pool-quit; in the second the peer
    ;; failed first and the pool's quit is a CONSEQUENCE. What tells them
    ;; apart is which came first, and that is exactly what first-write-wins
    ;; records. It is also order-independent in the sense that matters: the
    ;; order it depends on is causal, not the order two messages happen to
    ;; be drained in.
    (define (mark-dying! c why)
      (unless (hashtable-ref dying c #f)
        (hashtable-set! dying c why)))
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
    ;; Workers that have been spawned but have not yet reported #(pool-up ...).
    ;; They are in NO other table, so without this set a worker that dies
    ;; before reporting -- a crash in the driver, a connect error killing the
    ;; actor, a supervisor kill -- matched none of the DOWN branches below and
    ;; the pool silently lost that slot FOREVER. Enough of those and the pool
    ;; is empty while every caller queues behind connections that no longer
    ;; exist and will never be rebuilt.
    ;;
    ;; A worker that reports failure and then exits is removed here at pool-up
    ;; time, because it has already scheduled its own backed-off retry; only
    ;; the ones that never reported are rebuilt from DOWN.
    (define connecting (make-eq-hashtable))
    ;; conn pid -> when it reported up. A connection that dies almost at
    ;; once did not really connect: the peer accepted and then dropped it --
    ;; a database refusing on max_connections, one that requires TLS, a
    ;; proxy draining, a worker that is listening but useless. Case (2)
    ;; below rebuilt those with no delay at all, so a pool aimed at such a
    ;; peer span its rebuild loop at full speed: measured at 38k
    ;; connect/close cycles in three seconds, on the one OS thread, churning
    ;; a file descriptor each time. That is not a rebuild, it is a spin.
    (define up-at (make-eq-hashtable))
    (define min-lifetime-ms 1000)
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
    ;; from here to the connection's pool-idle -- the pool never sees the reply
    ;; itself, which goes straight from the connection to the caller.
    ;; -> #t if the job was dispatched.
    ;;
    ;; The caller is checked HERE, not only when the job was queued. The
    ;; mailbox can hold a pool-idle that arrived while the caller was alive
    ;; and a DOWN behind it: processing them in order dispatches a statement
    ;; for a process already known to be gone. This cannot make "alive" a
    ;; durable property -- the caller may die immediately after the check --
    ;; but it stops the pool acting on information it already has.
    (define (assign! c job)
      (if (not (process-alive? (vector-ref job 2)))
          (begin
            (when (vector-ref job 4) (demonitor (vector-ref job 4)))
            #f)
          (assign!* c job)))

    (define (assign!* c job)
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
      (send c (vector 'pool-request (vector-ref job 0)
                      (vector-ref job 1) (vector-ref job 2)))
      #t)
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
    ;; -> #t if the connection was leased. Same reasoning as assign!: a
    ;; borrower that died after its request was queued must not be handed a
    ;; connection, because the DOWN already on its way would then read as
    ;; "died holding a transaction" and destroy a connection it never saw.
    (define (lease! c w)
      (if (not (process-alive? (waiter-from w)))
          (begin (demonitor (waiter-mon w)) #f)
          (lease!* c w)))

    (define (lease!* c w)
      (let ((waited (- (now-ms) (waiter-queued-at w))))
        (set! stat-checkout-wait-total (+ stat-checkout-wait-total waited))
        (when (> waited stat-checkout-wait-max)
          (set! stat-checkout-wait-max waited)))
      (set! stat-checkouts (+ stat-checkouts 1))
      (hashtable-set! leased c (vector (waiter-from w) (waiter-mon w)
                                       (waiter-ref w)))
      (send (waiter-from w) (vector 'pool-checkout-reply (waiter-ref w) c))
      #t)
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
    ;; QUERY DURATION is measured from dispatch to the connection's pool-idle,
    ;; because the pool never sees the reply -- that goes straight from the
    ;; connection to the caller. It therefore excludes queue wait, which is
    ;; reported separately and is the number that matters when sizing.
    (define stat-queries 0)              ; statements dispatched
    (define stat-query-timeouts 0)       ; callers that gave up (pool-request-cancel)
    (define stat-checkouts 0)            ; leases granted
    (define stat-checkout-timeouts 0)    ; callers that gave up waiting
    (define stat-connects 0)             ; workers that came up
    (define stat-connect-failures 0)
    ;; THREE WAYS A LIVE CONNECTION ENDS, counted apart because the number
    ;; an operator reads to decide whether a peer is flaky must not have
    ;; the other two mixed into it. Lost is the peer's doing; retired is
    ;; the connection standing down on schedule; discarded is this pool
    ;; deciding to drop one -- a lease that escaped broken, or a borrower
    ;; that died holding it. The same three names drive the backoff a few
    ;; hundred lines down, and are read from the same place.
    (define stat-connections-lost 0)
    (define stat-connections-retired 0)
    (define stat-connections-discarded 0)
    (define stat-queue-wait-total 0)     ; ms a statement spent queued
    (define stat-queue-wait-max 0)
    (define stat-checkout-wait-total 0)  ; ms a borrower spent waiting
    (define stat-checkout-wait-max 0)
    (define stat-query-total 0)          ; ms dispatch -> pool-idle
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
    ;; IDEMPOTENT. A connection can be handed back twice: it replies to its
    ;; lessee, is preempted before sending pool-idle, the lessee checks in
    ;; first -- so the checkin frees it, and the late pool-idle then finds it
    ;; neither leased nor dying and frees it again. It landed in `idle`
    ;; TWICE, two checkouts popped the same connection, and the second
    ;; lease! overwrote the first lease record: that borrower's monitor was
    ;; never released, its checkin could no longer find its lease, and its
    ;; death no longer reclaimed a connection that may have held its open
    ;; transaction.
    ;; THE ONE GATE BACK INTO ROTATION.
    ;;
    ;; "a connection already on its way out is never lent again" is one
    ;; rule, and it used to be written three times -- once at each caller,
    ;; a round apiece as each route was noticed separately, with a fourth
    ;; route left unguarded because it happened not to need it. A rule kept
    ;; at its callers is a rule the next caller silently opts out of. It
    ;; lives here now, so every route in is covered by construction.
    (define (conn-dead! c why)
      (hashtable-delete! busy c)
      (when (memq c idle) (set! idle (remq c idle)))
      (mark-dying! c why))

    (define (make-available! c)
      (unless (hashtable-ref dying c #f)
        (make-available!* c)))

    (define (make-available!* c)
      (hashtable-delete! busy c)
      (when (memq c idle) (set! idle (remq c idle)))
      ;; A dead requester at the head of a queue must not swallow the
      ;; connection: assign!/lease! answer #f for one, and this keeps
      ;; looking. Otherwise one reaped caller idles a connection while
      ;; everyone behind it waits.
      (let next ()
        (cond
          ((and (pending?) (co-pending?))
           (if co-turn
               (begin (set! co-turn #f)
                      (or (lease! c (pop-co!)) (next)))
               (begin (set! co-turn #t)
                      (or (assign! c (pop-pending!)) (next)))))
          ((pending?) (or (assign! c (pop-pending!)) (next)))
          ((co-pending?) (or (lease! c (pop-co!)) (next)))
          (else (set! idle (cons c idle))))))
    (connpool-check-size! 'sql-pool n)
    (do ((i 0 (+ i 1))) ((= i n)) (connect!))
    (let loop ()
      (receive
        (`#(pool-request ,sql ,ref ,from)
          (if (pair? idle)
              ;; dispatched at once: nothing to watch, the connection
              ;; answers the caller directly. assign! still checks the
              ;; caller -- it may have died between sending this and the
              ;; pool reaching it -- and puts the connection back if so.
              (let ((c (car idle)))
                (set! idle (cdr idle))
                (unless (assign! c (vector sql ref from (now-ms) #f))
                  (set! idle (cons c idle))))
              ;; queued: watch the caller for as long as it is waiting.
              ;; monitor returns #f for a pid that is ALREADY dead (and
              ;; delivers the DOWN immediately), so that request is simply
              ;; not queued -- there is nobody to answer.
              (let ((m (monitor from)))
                (when m
                  (set! pending-back
                        (cons (vector sql ref from (now-ms) m) pending-back)))))
          (loop))
        (`#(pool-idle ,c ,done-ref)
          ;; a finished request is the first evidence that this endpoint
          ;; works, and the only evidence worth clearing the penalty for
          (set! backoff-ms 0)
          ;; IT MUST NAME THE REQUEST IT FINISHED.
          ;;
          ;; A connection sends its reply and then this message, and can be
          ;; preempted between the two. A borrower that checks in during
          ;; that gap frees the connection, the pool dispatches the next
          ;; queued request to it, and the LATE idle then arrived against
          ;; somebody else's busy entry -- clearing it, crediting the wrong
          ;; request with the duration, and handing the connection out a
          ;; second time while the request it was just given is still in
          ;; its mailbox. Two callers, one connection.
          ;;
          ;; A ref that does not match the current dispatch is stale and is
          ;; ignored. No entry at all means the connection is leased (its
          ;; lessee's check-in is what frees it) or already accounted for.
          (let ((e (hashtable-ref busy c #f)))
            (when (and e (eq? (vector-ref e 1) done-ref))
              (let ((took (- (now-ms) (vector-ref e 2))))
                (set! stat-completed (+ stat-completed 1))
                (set! stat-query-total (+ stat-query-total took))
                (when (> took stat-query-max) (set! stat-query-max took)))
              ;; a leased connection reports idle after each of its
              ;; lessee's own queries; that is not the connection becoming
              ;; free, the lessee's check-in is. A dying one is refused by
              ;; make-available! itself.
              (unless (hashtable-ref leased c #f)
                (make-available! c))))
          (loop))
        ;; WHY, when the connection knows. A connection that is standing
        ;; down on schedule -- because it has answered as many requests as
        ;; its protocol lets it number, or as many as its owner allows --
        ;; is not reporting a peer problem, and classifying it as one made
        ;; every planned recycle pay the backoff meant for a peer that
        ;; accepts and then fails. The two-field form is the older one and
        ;; still means 'transport'.
        (`#(pool-conn-dead ,c ,why)
          (conn-dead! c (if (memq why '(transport retired)) why 'transport))
          (loop))
        (`#(pool-conn-dead ,c)
          ;; the connection already sent the transport-error reply to its
          ;; caller and is about to exit: clear the busy entry so the DOWN
          ;; below does not send a duplicate reply, and mark it dying so
          ;; the DOWN still rebuilds it.
          ;; conn-dead! also takes it out of the idle set, which is a
          ;; separate place it can be sitting: a connection whose caller
          ;; checked in before this message arrived is idle, not busy, and
          ;; clearing only the busy entry left it in rotation while marked
          ;; dying -- the one state the guard in make-available! cannot
          ;; help with, because the connection never passes that gate again.
          ;; WHY it is dying, not merely that it is. A connection that
          ;; reported a transport failure is not one this pool decided to
          ;; discard, and treating the two the same let a peer that accepts
          ;; and then fails on its first request bypass the stillborn
          ;; backoff entirely -- the very hot loop that backoff exists to
          ;; stop, reintroduced by marking the connection dying before the
          ;; DOWN that classifies it.
          ;; ...but never DOWNGRADE a mark the pool made itself. See mark-dying!.
          (conn-dead! c 'transport)
          (loop))
        (`#(pool-checkout ,ref ,from)
          (let ((w (make-waiter ref from)))
            (when w
              (if (pair? idle)
                  (let ((c (car idle)))
                    (set! idle (cdr idle))
                    (unless (lease! c w) (set! idle (cons c idle))))
                  (set! co-back (cons w co-back)))))
          (loop))
        (`#(pool-checkin ,from ,c)
          ;; only when c really is leased to `from` -- guards a stale or double
          ;; checkin (e.g. after the connection already died and was rebuilt).
          (let ((e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) from))
              (drop-lease! c e)
              (make-available! c)))
          (loop))
        (`#(pool-checkin-broken ,from ,c)
          ;; the lessee could not clean the connection (e.g. ROLLBACK failed):
          ;; drop the lease and destroy+rebuild it rather than ever lending a
          ;; possibly-open transaction to the next caller. Atomic here (single
          ;; loop), so the connection is never made available in between.
          (let ((e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) from))
              (drop-lease! c e)
              (mark-dying! c 'teardown)            ; the pool's decision
              (send c (vector 'pool-quit))))       ; -> DOWN -> rebuild (case 2)
          (loop))
        (`#(pool-request-cancel ,ref ,from)
          ;; A query timed out. If it is STILL QUEUED it has not been sent
          ;; anywhere, so dropping it is exact: the caller has already been
          ;; told the call failed, and executing it later would apply a write
          ;; the application believes never happened. (Once assigned to a
          ;; connection the statement is in flight and its outcome is
          ;; genuinely unknown -- that is documented on connpool-call and is not
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
        (`#(pool-checkout-cancel ,ref ,from)
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
        (`#(pool-up ,ref ,pid ,status)
          (hashtable-delete! connecting pid)
          (if (eq? status 'ok)
              (begin
                (send pid (vector 'pool-adopt))
                (set! stat-connects (+ stat-connects 1))
                ;; NOT here. Coming up is provisional -- a peer that accepts
                ;; and then drops gets this far every time, and clearing the
                ;; penalty here meant each stillborn connection erased the
                ;; history of the one before it: the backoff never left its
                ;; first step, however many times the cycle repeated. What
                ;; clears it is a connection that has actually SERVED
                ;; something (see pool-idle).
                (hashtable-set! up-at pid (now-ms))
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
        (`#(pool-stats ,ref ,from)
          (send from
            (vector 'pool-stats-reply ref
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
                (cons 'connections-retired stat-connections-retired)
                (cons 'connections-discarded stat-connections-discarded)
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
          ;; These waits ended too, and for the worst reason. Recording only
          ;; the ones that ended in a reply or a timeout left the metrics
          ;; blind to a pool so saturated that its callers are being reaped
          ;; before they ever time out -- @kill runs no cancel, so nothing
          ;; else would ever record them.
          (let ((mine? (lambda (w)
                         (if (eq? (waiter-from w) pid)
                             (let ((waited (- (now-ms) (waiter-queued-at w))))
                               (set! stat-checkout-wait-total
                                     (+ stat-checkout-wait-total waited))
                               (when (> waited stat-checkout-wait-max)
                                 (set! stat-checkout-wait-max waited))
                               #f)
                             #t))))
            (set! co-front (filter mine? co-front))
            (set! co-back  (filter mine? co-back)))
          (let ((mine? (lambda (job)
                         (if (eq? (vector-ref job 2) pid)
                             (let ((waited (- (now-ms) (vector-ref job 3))))
                               (set! stat-queue-wait-total
                                     (+ stat-queue-wait-total waited))
                               (when (> waited stat-queue-wait-max)
                                 (set! stat-queue-wait-max waited))
                               #f)
                             #t))))
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
                      (mark-dying! (car hit) 'teardown)
                      (send (car hit) (vector 'pool-quit)))
                    hits)))
            ;; (2) a connection died (idle, mid single-query, leased, or one we
            ;; are already tearing down). Fail any waiting single-query caller,
            ;; drop a lease if it held one, and rebuild. Failed connect workers
            ;; already scheduled their own retry, so they fall through here.
            ((or (memq pid idle) (hashtable-contains? busy pid)
                 (hashtable-ref leased pid #f) (hashtable-ref dying pid #f))
             ;; read before the deletes below: a connection WE tore down on
             ;; purpose (a broken checkin) is not a peer problem and is
             ;; rebuilt at once however short its life was
             ;; only the POOL's own decision counts as deliberate. A
             ;; connection that reported a transport failure died of a peer
             ;; problem, and if it did so within its first second it never
             ;; really connected -- the backoff is for exactly that.
             ;; a RETIREMENT is deliberate too: the connection stood down
             ;; on schedule, so its short life is not evidence of a peer
             ;; that cannot hold one up, and making it wait out the
             ;; stillborn backoff would charge every planned recycle for a
             ;; failure that did not happen.
             ;; READ BEFORE THE DELETES BELOW: the dying mark is cleared a
             ;; few lines down, so anything that wants to know why has to
             ;; ask here.
             (let* ((why (hashtable-ref dying pid #f))
                    ;; deliberate = not the peer's doing, so no backoff
                    (deliberate (memq why '(teardown retired)))
                    (born (hashtable-ref up-at pid #f))
                    (stillborn (and (not deliberate) born
                                    (< (- (now-ms) born) min-lifetime-ms))))
               (hashtable-delete! up-at pid)
               (set! idle (remq pid idle))
               (hashtable-delete! dying pid)
               (case why
                 ((retired)
                  (set! stat-connections-retired (+ stat-connections-retired 1)))
                 ((teardown)
                  (set! stat-connections-discarded (+ stat-connections-discarded 1)))
                 (else
                  (set! stat-connections-lost (+ stat-connections-lost 1))))
               (let ((entry (hashtable-ref busy pid #f)))
                 (hashtable-delete! busy pid)
                 (when entry
                   (send (vector-ref entry 0)
                         (vector 'pool-reply (vector-ref entry 1)
                                 (connpool-cfg-lost-err cfg)))))
               (let ((e (hashtable-ref leased pid #f)))
                 (when e (drop-lease! pid e)))
               (if stillborn
                   ;; the same jittered backoff a failed connect gets: this
                   ;; IS a failed connect, it just failed after the accept
                   (let ((wait (next-backoff!)))
                     (spawn (lambda ()
                              (sleep-ms wait)
                              (send me (vector 'pool-reconnect)))))
                   (connect!))))
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
        (`#(pool-quit)
          (for-each (lambda (c) (send c (vector 'pool-quit))) idle)
          (vector-for-each
            (lambda (c) (send c (vector 'pool-quit)))
            (hashtable-keys busy))
          (vector-for-each
            (lambda (c) (send c (vector 'pool-quit)))
            (hashtable-keys leased))
          ;; connections still authenticating self-terminate: nobody adopts
          ;; them once this process is gone. Queued callers get an error now
          ;; instead of parking until their timeouts.
          (let ((closed (connpool-cfg-closed-err cfg)))
            (for-each
              (lambda (job)
                (send (vector-ref job 2)
                      (vector 'pool-reply (vector-ref job 1) closed)))
              (append pending-front (reverse pending-back)))
            (for-each
              (lambda (req)
                (send (waiter-from req)
                      (vector 'pool-checkout-failed (waiter-ref req) closed)))
              (append co-front (reverse co-back))))
          'done))))

  ;; ---- caller-side operations ---------------------------------------------

  ;; These operations are strictly synchronous within one green process,
  ;; so any pool-reply / pool-checkout-reply / pool-checkout-failed sitting in
  ;; the mailbox at ENTRY is by construction stale -- the late answer to
  ;; an earlier call that timed out (its gensym ref can never be matched
  ;; again, and a stale checkout's lease was already reclaimed by the
  ;; cancel). Drain them here, or a long-lived process that suffers
  ;; timeouts accumulates immortal messages that slow every later
  ;; selective-receive scan.
  ;; Exported because the DRIVERS need it too: a single-connection connect
  ;; that times out leaves its worker's late up-report in the caller's
  ;; mailbox, and a long-lived process that reconnects in a loop -- a
  ;; supervisor, a reconnect manager -- never calls connpool-call, so nothing
  ;; ever cleared them. They are immortal (the per-attempt ref can never
  ;; match again) and every later selective receive scans past all of them.
  (define connpool-drain-stale! (lambda () (drain-stale!)))

  ;; consume a DOWN that raced the reply, so it cannot rot in the mailbox
  ;; of a caller that gets reused (a pool worker, a supervisor)
  (define (flush-down! p)
    (receive (after 0 'ok) (`#(DOWN ,@p ,r) 'ok)))

  (define (drain-stale!)
    (let loop ()
      (receive (after 0 'done)
        (`#(pool-reply ,r ,v) (loop))
        (`#(pool-checkout-reply ,r ,conn) (loop))
        (`#(pool-checkout-failed ,r ,e) (loop))
        ;; a lone driver connect that timed out leaves the worker's late
        ;; up-report behind (its per-attempt ref never matches again)
        (`#(pool-up ,r ,p ,s) (loop))
        (`#(pool-stats-reply ,r ,st) (loop)))))

  ;; A snapshot of the pool: an alist of gauges, counters and latency
  ;; totals. See the pool-stats clause in the loop for what each key means.
  ;;
  ;; POOL ONLY. A lone connection answers #(pool-stats-reply ,ref #f), which
  ;; raises here -- it is not a degenerate pool, it has none of this
  ;; bookkeeping, and reporting zeros would be worse than refusing: an
  ;; operator reading `in-use 0` would conclude the connection was free.
  ;; The reply exists so the request cannot sit in a connection's mailbox
  ;; forever, which is the failure mode a bare timeout would have left.
  (define (connpool-stats pool)
    (drain-stale!)
    (let ((ref (gensym)))
      (send pool (vector 'pool-stats ref self))
      ;; STRUCTURED, NOT A BARE SYMBOL. Not because a symbol is hard to
      ;; catch -- eq? picks one out exactly -- but because this raise has
      ;; two things to say and a symbol is one value: WHICH failure it
      ;; was, and WHICH pool it was. Slots 1 and 2 carry them, the way
      ;; #(durable-error op path) and #(dpool-error reason id) do.
      ;;
      ;; Two things it does NOT do, both of which have been claimed here
      ;; before and are wrong. It says nothing about who raised it: those
      ;; tag symbols are as public as any others and a caller can build
      ;; the same vector. And it is not this procedure's whole error
      ;; surface -- the `not a pool' case below raises a condition.
      ;;
      ;; THE ID, NOT THE POOL. A context slot holds a printable
      ;; scalar. Not a style rule: `write` is unbounded by default, a
      ;; process is a pcb record whose fields include its continuation,
      ;; its links and its inbox, and so writing a vector that holds one
      ;; walks into a cycle and takes the runtime down -- printing the
      ;; mailbox on the way, which for a pool holds the statements in
      ;; flight. The operator reading the error is the one who triggers
      ;; it. (Bounding the printer first, print-level 1, is safe; the
      ;; rule is here because nothing makes a handler do that.)
      ;;
      ;; Conditions are exempt and may carry the process itself, as the
      ;; `not a pool' report below does: `write` on a condition gives
      ;; #<compound condition> and never reaches the irritants, and
      ;; display-condition bounds what it descends into.
      ;;
      ;; #(durable-error op path) and #(dpool-error reason id) follow the
      ;; rule. Known violator: gen-server-call, which puts the caller's
      ;; own message in this position -- and a message carrying a process
      ;; is how a request names its replier, this procedure included.
      ;; It is in the ledger; it is not evidence the rule is optional.
      (receive (after 5000
                 (raise (vector 'connpool-error 'stats-timeout
                                (process-id pool))))
        (`#(pool-stats-reply ,@ref ,st)
          (or st
              (assertion-violation 'connpool-stats
                "not a pool -- a single connection keeps no pool statistics"
                pool))))))

  ;; Run one SQL statement on a connection or a pool; blocks only the
  ;; calling green process. The per-call ref (a fresh gensym) is echoed in
  ;; the reply, so a late reply after a timeout will not be matched by the
  ;; caller's next query. A timed-out statement's outcome is UNKNOWN -- it
  ;; may still execute on the server.
  (define (connpool-call h sql cfg)
    (drain-stale!)
    (let ((ref (gensym))
          ;; WATCH THE HANDLE. A pooled call is answered when its
          ;; connection dies -- the pool holds the caller and the ref in
          ;; `busy` and sends lost-err. A call on a LEASED connection is in
          ;; no such table: the pool has nothing to answer with, and this
          ;; caller had no way to learn the connection was gone. It waited
          ;; out the whole query deadline for a reply from a dead process.
          ;;
          ;; monitor answers #f for a pid that is already dead and delivers
          ;; the DOWN at once, so this also covers a connection that died
          ;; between the checkout and here.
          (m (monitor h)))
      (observe! cfg h sql)
      (send h (vector 'pool-request sql ref self))
      (receive (after (connpool-cfg-query-ms cfg)
                  ;; symmetric with connpool-checkout: tell the pool to drop the
                  ;; request if it is still queued. A statement left behind
                  ;; runs whenever the pool recovers -- long after the caller
                  ;; was told it failed -- so a write the application gave up
                  ;; on still lands. Harmless against a lone connection, which
                  ;; ignores the message.
                  (send h (vector 'pool-request-cancel ref self))
                  (when m (demonitor m) (flush-down! h))
                  (raise (connpool-cfg-query-timeout-err cfg)))
        (`#(pool-reply ,@ref ,r)
          (when m (demonitor m) (flush-down! h))
          (if ((connpool-cfg-error? cfg) r) (raise r) r))
        ;; the handle is gone: for a leased connection that is the whole
        ;; answer, and for a pool it is one too
        (`#(DOWN ,@h ,reason)
          (raise (connpool-cfg-lost-err cfg))))))

  ;; Ask the pool for a dedicated connection and park until one is free (or
  ;; raise cfg's checkout-timeout-err -- the pool is saturated, nothing is
  ;; broken). Internal: callers use the with-connection / transaction
  ;; wrappers, which guarantee checkin.
  (define (connpool-checkout pool cfg)
    (drain-stale!)
    (let ((ref (gensym))
          ;; WATCH THE POOL. Without this a dead pool is indistinguishable
          ;; from a busy one: no reply can come, so the caller waits out the
          ;; whole checkout deadline -- a minute for the SQL drivers -- and
          ;; is then told the pool is SATURATED, which is a different fault
          ;; with a different remedy. connpool-call already watches its
          ;; handle; this is the other half of the lease path.
          (m (monitor pool)))
      (send pool (vector 'pool-checkout ref self))
      (receive (after (connpool-cfg-checkout-ms cfg)
                  ;; tell the pool to drop (or reclaim) this request --
                  ;; otherwise a connection freed after the timeout is leased
                  ;; to us and never checked in, bleeding the pool.
                  (send pool (vector 'pool-checkout-cancel ref self))
                  (when m (demonitor m) (flush-down! pool))
                  (raise (connpool-cfg-checkout-timeout-err cfg)))
        (`#(pool-checkout-reply ,@ref ,conn)
          (when m (demonitor m) (flush-down! pool))
          conn)
        (`#(pool-checkout-failed ,@ref ,err)
          (when m (demonitor m) (flush-down! pool))
          (raise err))
        (`#(DOWN ,@pool ,reason) (raise (connpool-cfg-lost-err cfg))))))

  ;; ROLLBACK on a borrowed connection without parking a full query timeout
  ;; when the connection is already dead: monitor it, so a dead process
  ;; answers with an immediate DOWN instead of 60 seconds of silence.
  ;; -> #t when the connection cannot be returned clean.
  (define (connpool-rollback! conn cfg)
    (let ((m (monitor conn)) (ref (gensym)))
      (let ((broken
             (guard (e (#t #t))
               ;; observed HERE and not via connpool-call, which this
               ;; path deliberately bypasses: without this line the one
               ;; statement a caller most wants to see is the only one
               ;; missing, and the stream would look complete
               (observe! cfg conn "ROLLBACK")
               (send conn (vector 'pool-request "ROLLBACK" ref self))
               (receive (after (connpool-cfg-query-ms cfg) #t)
                 (`#(pool-reply ,@ref ,r) ((connpool-cfg-error? cfg) r))
                 (`#(DOWN ,@conn ,reason) #t)))))
        (when m
          (demonitor m)
          ;; a DOWN already queued between the reply and the demonitor
          ;; would sit unmatched forever -- drain it
          (receive (after 0 'ok) (`#(DOWN ,@conn ,reason) 'ok)))
        broken)))

  ;; Borrow one whole connection from a POOL for the extent of proc, then
  ;; return it -- even if proc raises or exits non-locally. proc receives the
  ;; connection process; queries on it cannot interleave with other
  ;; callers -- provided the handle does not leave proc (see the lease
  ;; contract below: it is a capability, and the pool cannot police
  ;; where it travels).
  ;; Don't send queries (or a second checkout) to the pool itself while
  ;; holding a connection: an exhausted pool deadlocks the former and delays
  ;; the latter.
  ;; broken-on-escape?: when proc leaves NON-LOCALLY, hand the connection
  ;; back as broken rather than clean. That matters wherever an escape
  ;; means the request may still be running on the far side -- a call that
  ;; gave up on its deadline is exactly that. A plain check-in there races
  ;; the connection's own reaction to the cancel: the pool can free and
  ;; re-lend a connection that is still serving the caller who left, and
  ;; the next borrower's request goes to a process about to exit.
  ;;
  ;; Off by default, because for SQL an escape is usually just a statement
  ;; error and the connection is perfectly good.
  ;;
  ;; ---- ONE LEASE IS ONE CONNECTION -------------------------------------
  ;;
  ;; WHAT THE POOL PROMISES, all of it about the pool and none of it about
  ;; the far side:
  ;;
  ;;   1. It never re-points a handle. For the extent of proc, the handle
  ;;      denotes the same connection process; the pool will not swap in a
  ;;      sibling, even an idle one, and not while the leased connection
  ;;      is dying.
  ;;   2. Once that process is gone, THE NEXT connpool-call ON THE OLD
  ;;      HANDLE raises cfg's lost-err. Note the shape: nothing here
  ;;      watches the connection on proc's behalf, so a proc that simply
  ;;      stops calling returns normally. The failure is delivered to the
  ;;      next call, not announced to the borrower.
  ;;   3. It does not alter a handle it has already handed out, and it
  ;;      never gives a dead worker's handle to that worker's
  ;;      replacement. (Connections themselves ARE reused -- across
  ;;      leases, by later borrowers. What is not reused is the identity
  ;;      of one that died.)
  ;;
  ;; ONE PEER SESSION FOR THE WHOLE LEASE -- which is what a caller
  ;; actually wants -- FOLLOWS FROM (1) ONLY IF the driver's worker does
  ;; not re-dial inside itself. That is a condition on the driver, not a
  ;; promise made here, and the pool can neither see nor report a breach
  ;; of it: the pid is unchanged, so nothing is different from where the
  ;; pool stands. State it as a condition when citing this.
  ;;
  ;; PRECONDITION ON spawn-conn!: it must return a pid it has never
  ;; returned before. The bundled drivers do, since each call is a fresh
  ;; actor spawn -- but spawn-conn! is injected, the protocol above does
  ;; not demand this, and the pool does not check. A spawn-conn! that
  ;; recycled identities would break (3) without the pool noticing.
  ;;
  ;; THE MECHANISM, so this can be checked and not merely believed. Every
  ;; rebuild goes through connect!, which calls the injected spawn-conn!,
  ;; and all three of its call sites run in the pool process. A worker
  ;; announces that it needs replacing in one of two ways, and both are
  ;; worth following if you are checking the claim: by DYING, which the
  ;; pool's monitor turns into a rebuild, or -- for a transport error it
  ;; is still able to report -- by sending pool-conn-dead first, which
  ;; marks it so that the DOWN behind it still rebuilds. Where the failure
  ;; deserves a backoff, the pool spawns a timer process; that timer is
  ;; what later sends pool-reconnect TO the pool, and the pool then runs
  ;; connect!. No worker re-dials itself, and no worker's handle is
  ;; carried across a rebuild.
  ;;
  ;; NOT PROMISED. Each of these is a way (1)-(3) can hold exactly as
  ;; written and still not give a caller what it was after:
  ;;
  ;;   - NOTHING ABOUT WHAT A DRIVER DOES INSIDE ITS WORKER -- see the
  ;;     condition above. This is the one that silently removes the
  ;;     property most callers are really relying on.
  ;;   - NOTHING ABOUT THE PEER'S OWN CONTINUITY. A server that holds the
  ;;     socket open while resetting what the session contains is outside
  ;;     this model.
  ;;   - A LIVE HANDLE IS NOT AN OPEN TRANSACTION. If the borrower is
  ;;     killed its winders are discarded and no check-in is sent; what
  ;;     keeps a half-open transaction away from the next borrower is the
  ;;     pool's monitor reclaiming and rebuilding on DOWN, not the lease.
  ;;     See sql-transaction, which says the same for its own path.
  ;;   - THE HANDLE IS A CAPABILITY, AND COPYING IT IS NOT DETECTABLE.
  ;;     Exclusivity is the pool declining to lend the connection to
  ;;     anyone else; it is not a restriction on who may send to that
  ;;     worker. A handle that proc passes to another process, or retains
  ;;     past the lease, lets those calls land in the same session --
  ;;     interleaved with proc's own, or after the connection has been
  ;;     lent to somebody else. Whoever holds the handle has the ability;
  ;;     the pool does not police how it travels.
  ;;
  ;; Comparing handles with eq? does not establish any of this. The case
  ;; it cannot see is exactly the one that matters: a worker that
  ;; re-dialled its own socket is eq? to itself, while the session behind
  ;; it changed -- so the comparison answers "same process", which was
  ;; never in doubt, and stays silent about the thing being asked. It also
  ;; has to be sampled at some moment of the caller's choosing, and the
  ;; guarantee above has no such window.
  (define (connpool-lease pool proc cfg . rest)
    (let ((conn (connpool-checkout pool cfg))
          (broken-on-escape? (and (pair? rest) (car rest)))
          (clean #f))
      (dynamic-wind
        (lambda () (void))
        (lambda () (let ((r (proc conn))) (set! clean #t) r))
        (lambda ()
          (send pool (vector (if (or clean (not broken-on-escape?))
                                 'pool-checkin
                                 'pool-checkin-broken)
                             self conn))))))

  ;; Run proc inside a transaction on a borrowed pool connection: cfg's
  ;; begin-sql first, then COMMIT if proc returns normally, or ROLLBACK if
  ;; it escapes. Returns proc's value. Self-manages the lease (rather than
  ;; connpool-lease) so the single return message can be checkin
  ;; OR checkin-broken -- no second checkin racing the discard. Kill-safety:
  ;; if the borrower is killed the winders are discarded, no message is
  ;; sent, and the pool's monitor reclaims + rebuilds the connection, so a
  ;; half-open transaction is never handed to the next caller.
  (define (sql-transaction pool proc cfg)
    (let ((conn (connpool-checkout pool cfg)))
      (let ((committed #f) (broken #f))
        (dynamic-wind
          (lambda () (void))
          (lambda ()
            ;; inside the wind: if the BEGIN itself fails, the after-clause
            ;; still runs, so the lease is always returned.
            (connpool-call conn (connpool-cfg-begin-sql cfg) cfg)
            (let ((r (proc conn)))
              (connpool-call conn "COMMIT" cfg)
              (set! committed #t)
              r))
          (lambda ()
            (unless committed
              ;; roll back; if ROLLBACK fails (or the connection is dead)
              ;; the transaction may still be open, so flag the connection
              ;; for discard instead of returning it dirty.
              (set! broken (connpool-rollback! conn cfg)))
            (send pool (vector (if broken 'pool-checkin-broken 'pool-checkin)
                               self conn)))))))

  ;; Close a pool (or a lone connection). Leased connections are quit
  ;; immediately: a transaction still in flight on one will time out on
  ;; its next statement -- close the pool only after its borrowers are
  ;; done.
  (define (connpool-close! h)
    (send h (vector 'pool-quit)))
)
