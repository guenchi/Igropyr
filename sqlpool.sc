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
;;;
;;; Drivers keep their public error shapes: the engine takes the error
;;; VALUES it must produce and a predicate for recognizing an error
;;; reply, bundled in a config record built once per driver.

(library (igropyr sqlpool)
  (export make-sql-cfg
          sql-pool-loop sql-query
          sql-transaction sql-call-with-connection sql-close!)
  (import (chezscheme) (igropyr actor))

  (define query-timeout-ms 60000)
  (define checkout-timeout-ms 60000)   ; how long a caller parks for a free lease

  ;; error?: (r) -> is this reply the driver's error vector;
  ;; lost-err/closed-err/query-timeout-err/checkout-timeout-err: the
  ;; driver's error values for those events; begin-sql: the statement
  ;; that opens a transaction ("BEGIN" / "START TRANSACTION").
  (define-record-type (sql-cfg make-sql-cfg sql-cfg?)
    (fields error? lost-err closed-err
            query-timeout-err checkout-timeout-err begin-sql))

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
    (define (connect!)
      (monitor (spawn-conn! me me (gensym))))
    ;; a job is #(sql ref from)
    (define (assign! c job)
      (hashtable-set! busy c (cons (vector-ref job 2) (vector-ref job 1)))
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
    (define (make-waiter ref from) (vector ref from (monitor from)))
    (define (waiter-ref w) (vector-ref w 0))
    (define (waiter-from w) (vector-ref w 1))
    (define (waiter-mon w) (vector-ref w 2))
    ;; hand connection c to waiter w, carrying its existing monitor into the
    ;; lease record rather than taking a second one
    (define (lease! c w)
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
    ;; Checked here, before the loop that consumes it: a negative or
    ;; non-integer n never satisfies (= i n), so this spawns connection
    ;; workers without end. Nothing downstream would name it a
    ;; configuration mistake -- it presents as the database melting.
    (unless (and (integer? n) (exact? n) (> n 0))
      (assertion-violation 'sql-pool
        "pool size must be a positive exact integer" n))
    (do ((i 0 (+ i 1))) ((= i n)) (connect!))
    (let loop ()
      (receive
        (`#(db-query ,sql ,ref ,from)
          (let ((job (vector sql ref from)))
            (if (pair? idle)
                (let ((c (car idle)))
                  (set! idle (cdr idle))
                  (assign! c job))
                (set! pending-back (cons job pending-back))))
          (loop))
        (`#(db-idle ,c)
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
            (if (pair? idle)
                (let ((c (car idle)))
                  (set! idle (cdr idle))
                  (lease! c w))
                (set! co-back (cons w co-back))))
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
          (let ((mine? (lambda (job) (not (and (eq? (vector-ref job 1) ref)
                                               (eq? (vector-ref job 2) from))))))
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
          (let ((drop! (lambda (w)
                         (when (eq? (waiter-ref w) ref)
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
          (if (eq? status 'ok)
              (begin
                (send pid (vector 'db-adopt))
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
              (let ((wait (next-backoff!)))
                (spawn (lambda ()
                         (sleep-ms wait)
                         (send me (vector 'pool-reconnect))))))
          (loop))
        (`#(pool-reconnect)
          (connect!)
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
             (let ((entry (hashtable-ref busy pid #f)))
               (hashtable-delete! busy pid)
               (when entry
                 (send (car entry)
                       (vector 'db-reply (cdr entry) (sql-cfg-lost-err cfg)))))
             (let ((e (hashtable-ref leased pid #f)))
               (when e (drop-lease! pid e)))
             (connect!)))
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
  (define (drain-stale!)
    (let loop ()
      (receive (after 0 'done)
        (`#(db-reply ,r ,v) (loop))
        (`#(db-checkout-reply ,r ,conn) (loop))
        (`#(db-checkout-failed ,r ,e) (loop))
        ;; a lone driver connect that timed out leaves the worker's late
        ;; up-report behind (its per-attempt ref never matches again)
        (`#(db-up ,r ,p ,s) (loop)))))

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
