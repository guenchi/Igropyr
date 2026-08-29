#!chezscheme
;;; (igropyr dpool) -- a distributed task pool over node links.
;;;
;;; Spreads tasks across member nodes and runs them concurrently. Built
;;; on (igropyr node): the same Let-It-Crash story as the local otp
;;; pool, lifted from process level to NODE level.
;;;
;;;   ;; on every member node (a, b, c):
;;;   (node-start! 'a secret 4100) ...
;;;   (dpool-worker-start 'render (lambda (job) (render job)))
;;;
;;;   ;; on the submitting node:
;;;   (define pool (dpool-start '(a b c) 'render))   ; at-least-once
;;;   (define t (dpool-submit pool #(resize "x.png" 800)))
;;;   (dpool-await pool t)          ; -> the handler's return value
;;;
;;; Failure semantics -- chosen PER POOL, overridable PER TASK, because
;;; only the caller knows whether a task may safely run twice:
;;;
;;;   at-least-once (default): if the node running a task dies before its
;;;     result comes back, the task is re-dispatched to another live
;;;     node. The task WILL complete (while any node lives) but MAY run
;;;     twice -- the node might have finished and died with the reply in
;;;     flight. Use only for idempotent tasks (unique-key upserts, dedup
;;;     ids). This is the default because a silently DROPPED task is
;;;     harder to notice than a duplicated one.
;;;
;;;   at-most-once: a node death fails the task (dpool-await raises
;;;     #(dpool-error node-down id)); it is never re-run. Use for tasks
;;;     with side effects that can't be made idempotent ("charge once").
;;;     The caller decides whether to resubmit, with its own context.
;;;
;;;   A CONNECTION REPLACEMENT COUNTS AS A NODE DEATH, and it is worth
;;;   knowing where that bites. (igropyr node) treats a link that is
;;;   replaced -- two nodes dialing each other at once resolve to one
;;;   connection, and the other is replaced -- as the peer going down and
;;;   coming back up. This pool sees the node-down and acts on it:
;;;     - at-least-once tasks in flight on that node are RE-RUN. The
;;;       contract already allows that; what changes is how often it
;;;       happens.
;;;     - at-most-once tasks in flight on that node FAIL with
;;;       #(dpool-error node-down id). The caller already has to handle
;;;       that error; what changes is that a reconnection can now cause
;;;       it, not only a node that really went away.
;;;   HOW OFTEN THIS HAPPENS IS A DEPLOYMENT QUESTION, not a property of
;;;   the mesh. A configuration where both ends of a pair call
;;;   node-connect! produces a replacement whenever they dial at once --
;;;   typically at startup, when there is usually nothing in flight. A
;;;   configuration where only one end dials each pair (by node-name
;;;   order, say) produces none at all. Replacements can also arrive
;;;   later, from a configuration change or a connection that took its
;;;   time, so "startup only" is not a safe assumption either.
;;;
;;;   Exactly-once is not on offer: no message-passing system can give
;;;   both "never dropped" and "never duplicated" across a crash -- that
;;;   needs downstream cooperation (idempotency keys, a transactional
;;;   inbox). dpool gives the two honest extremes.
;;;
;;; A task whose HANDLER crashes (on a live node) is different from a
;;; node death: the node replies with the error, dpool-await raises
;;; #(dpool-error task-error id), and the task is NOT re-dispatched --
;;; a deterministic crash would only re-crash elsewhere.
;;;
;;; Wire safety: a task payload and its result must be extended-wire-safe
;;; (see (igropyr sexpr)) -- they cross node links.

(library (igropyr dpool)
  (export dpool-start dpool-submit dpool-await dpool-worker-start
          dpool-stats)
  (import (chezscheme) (igropyr util) (igropyr actor) (igropyr node))

  (define default-await-ms 30000)

  (define ref-counter 0)
  ;; Guarded like random-token! below: scheduling is preemptive at Chez
  ;; safe points, so an unguarded read-modify-write on a shared counter can
  ;; lose an update and REWIND it -- reissuing refs that a stale reply
  ;; still matches.
  (define (next-ref!)
    (with-interrupts-disabled
      (set! ref-counter (+ ref-counter 1))
      ref-counter))

  (define coord-counter 0)
  (define (next-coord-name!)
    (with-interrupts-disabled
      (set! coord-counter (+ coord-counter 1))
      (string->symbol
        (string-append "dpool-coord-" (number->string coord-counter)))))

  ;; Per-dispatch unforgeable attempt token. A result is only accepted
  ;; if it echoes the token the coordinator sent with the task, which
  ;; (a) stops any other authenticated node from forging a result for a
  ;; task it wasn't given -- coord names are guessable, the token is not
  ;; -- and (b) makes a stale reply from an at-least-once FIRST attempt
  ;; harmless once the task has been re-dispatched with a fresh token.
  ;; 64 bits from /dev/urandom; the read is guarded against preemption
  ;; because several coordinators share this one port.
  (define urandom-port #f)
  (define (random-token!)
    (with-interrupts-disabled
      (unless urandom-port
        (set! urandom-port (open-file-input-port "/dev/urandom")))
      (let ((bv (get-bytevector-n urandom-port 8)))
        (unless (and (bytevector? bv) (fx= (bytevector-length bv) 8))
          (raise 'entropy))
        (bytevector-uint-ref bv 0 (endianness big) 8))))

  ;; a wire-safe reason symbol out of whatever was raised
  (define (reason-of e)
    (cond
      ((symbol? e) e)
      ((and (vector? e) (fx> (vector-length e) 0) (symbol? (vector-ref e 0)))
       (vector-ref e 0))
      (else 'crashed)))

  ;; ---- worker side (runs on each member node) ----------------------------

  ;; concurrent tasks a single worker will run before it starts queuing;
  ;; bounds the number of processes one node spawns under a task burst.
  (define default-worker-concurrency 64)

  ;; Register a task runner under name. Each task runs in its own process
  ;; (Let It Crash: a crashing task is isolated and reported, never takes
  ;; the worker down), so one node serves many tasks concurrently -- up
  ;; to `max-concurrency` (optional, default 64) at once; the rest wait
  ;; in FIFO order and start as slots free.
  ;; rest: [max-concurrency [task-timeout-ms]]. task-timeout-ms > 0 kills a
  ;; task that has run that long (its slot is then reclaimed by the monitor
  ;; below and the caller sees a task-error); 0 -- the default -- means a
  ;; task may run indefinitely, so a handler that can block forever should
  ;; either carry its own timeout or be given one here.
  (define (dpool-worker-start name handler . rest)
    (let ((cap (if (pair? rest) (car rest) default-worker-concurrency))
          (task-timeout (if (and (pair? rest) (pair? (cdr rest))) (cadr rest) 0)))
      (unless (and (integer? cap) (exact? cap) (> cap 0))
        (assertion-violation 'dpool-worker-start
          "max-concurrency must be a positive integer" cap))
      (unless (and (integer? task-timeout) (exact? task-timeout)
                   (>= task-timeout 0))
        (assertion-violation 'dpool-worker-start
          "task-timeout-ms must be a nonnegative integer" task-timeout))
      (register name
        (spawn
          (lambda ()
            (let ((worker self)          ; tasks send #(slot-free ,self) back
                  (running 0)
                  ;; task pid -> #(monitor-ref started-ms); a task occupies a
                  ;; slot exactly as long as it has an entry here
                  (live (make-eq-hashtable))
                  (pf '()) (pb '()))     ; two-list FIFO of tasks over the cap
              (define (penq! x) (set! pb (cons x pb)))
              (define (pdeq!)            ; oldest queued task, or #f
                (when (null? pf) (set! pf (reverse pb)) (set! pb '()))
                (and (pair? pf) (let ((x (car pf))) (set! pf (cdr pf)) x)))
              ;; Run one task in its own process, ship the result tagged
              ;; with the SAME token the coordinator dispatched, then free
              ;; the slot. The guard covers a handler crash and a
              ;; non-serializable reply -- but NOT a task that is killed or
              ;; never returns, which is why the worker also monitors it.
              (define (run! id rnode rname payload token)
                (let ((p (spawn
                           (lambda ()
                             (let ((me self))
                               (let ((result
                                      (guard (e (#t (vector 'task-error (reason-of e))))
                                        (vector 'ok (handler payload)))))
                                 (guard (e (#t (rsend rnode rname
                                                 (vector 'dresult id token
                                                   (vector 'task-error 'not-serializable)))))
                                   (rsend rnode rname (vector 'dresult id token result))))
                               (send worker (vector 'slot-free me)))))))
                  (hashtable-set! live p (vector (monitor p) (real-time)))
                  p))
              ;; Release the slot p holds, if it still holds one. Idempotent:
              ;; a task normally reports #(slot-free) and THEN dies, so its
              ;; DOWN arrives afterwards and must not free a second slot.
              (define (release! p)
                (let ((e (hashtable-ref live p #f)))
                  (and e
                       (begin
                         (demonitor (vector-ref e 0))
                         (hashtable-delete! live p)
                         (set! running (- running 1))
                         (let ((t (pdeq!)))
                           (when t
                             (set! running (+ running 1))
                             (run! (vector-ref t 0) (vector-ref t 1)
                                   (vector-ref t 2) (vector-ref t 3)
                                   (vector-ref t 4))))
                         #t))))
              ;; kill tasks that have outstayed task-timeout; the DOWN each
              ;; one produces is what actually reclaims its slot
              (define (reap-stuck!)
                (let ((now (real-time)) (ks (hashtable-keys live)))
                  (do ((i 0 (+ i 1))) ((= i (vector-length ks)))
                    (let* ((p (vector-ref ks i)) (e (hashtable-ref live p #f)))
                      (when (and e (> (- now (vector-ref e 1)) task-timeout))
                        (kill p 'dpool-task-timeout))))))
              (when (> task-timeout 0)
                (let ((w worker) (period (max 1000 (div task-timeout 2))))
                  (spawn (lambda ()
                           (let tick ()
                             (sleep-ms period)
                             (send w (vector 'check-stuck-tasks))
                             (tick))))))
              (let loop ()
                (receive
                  (`#(dtask ,id ,rnode ,rname ,payload ,token)
                    (if (< running cap)
                        (begin (set! running (+ running 1))
                               (run! id rnode rname payload token))
                        (penq! (vector id rnode rname payload token)))
                    (loop))
                  (`#(slot-free ,p)
                    (release! p)
                    (loop))
                  ;; A task died without reporting -- killed as stuck, killed
                  ;; by a supervisor (dynamic-wind winders are discarded, so
                  ;; no message is ever sent), or crashed outside the guard.
                  ;; Without this the slot would be occupied forever, and
                  ;; after `cap` such tasks the node would keep ACCEPTING
                  ;; work while executing none of it.
                  (`#(DOWN ,p ,reason)
                    (release! p)
                    (loop))
                  (`#(check-stuck-tasks)
                    (reap-stuck!)
                    (loop))
                  (other (loop))))))))))            ; ignore stray messages

  ;; ---- coordinator (on the submitting node) ------------------------------

  (define-record-type (dpool make-dpool dpool?)
    (fields (immutable pid dpool-pid)
            (immutable default-mode dpool-default-mode)))

  (define (dpool-start members worker-name . rest)
    (let ((self-node (node-self)))
      (unless self-node
        (assertion-violation 'dpool-start "call node-start! first" members))
      (unless (and (list? members) (pair? members) (for-all symbol? members))
        (assertion-violation 'dpool-start "members must be a list of node names" members))
      (let* ((opts (if (pair? rest) (car rest) '()))
             (default-mode (opt opts 'mode 'at-least-once))
             (queue-cap (opt opts 'max-queued 10000))
             (coord-name (next-coord-name!)))
        (unless (memq default-mode '(at-least-once at-most-once))
          (assertion-violation 'dpool-start "bad mode" default-mode))
        (unless (and (integer? queue-cap) (exact? queue-cap) (> queue-cap 0))
          (assertion-violation 'dpool-start
            "max-queued must be a positive exact integer" queue-cap))
        (let ((pid (spawn (lambda ()
                            (coordinator self-node coord-name members worker-name queue-cap)))))
          ;; register so remote workers can rsend results back by name
          (register coord-name pid)
          (make-dpool pid default-mode)))))

  (define (coordinator self-node coord-name members worker-name queue-cap)
    ;; --- state ---
    (define live
      (filter (lambda (m) (or (eq? m self-node) (memq m (node-peers)))) members))
    (define rr '())                            ; rotating cursor over live
    (define inflight (make-eqv-hashtable))     ; id -> #(payload node mode)
    (define awaiters (make-eqv-hashtable))     ; id -> list of #(from ref)
    (define results (make-eqv-hashtable))      ; id -> result (awaited later)
    ;; FIFO of stashed result ids, so a result nobody ever awaits cannot
    ;; grow the table without bound (O(1) amortized eviction)
    (define stash-front '())
    (define stash-back '())
    (define stash-n 0)
    (define max-stashed 10000)
    ;; tasks with no live node to run on, newest-first; reversed to FIFO
    ;; on drain. A plain list appended per enqueue was O(n^2) under a
    ;; large backlog.
    (define queue-rev '())                     ; #(id payload mode)
    (define queued-n 0)
    ;; With every node offline nothing drains, and each queued entry holds a
    ;; whole payload -- so an application that keeps submitting turns an
    ;; outage into memory exhaustion, on the coordinator, which is the one
    ;; process that has to survive to recover. Results are already bounded
    ;; (max-stashed); the queue was the half that was not. Refusing is the
    ;; honest answer: the submitter learns now, rather than holding an id
    ;; for work nobody will ever run.
    ;; Configurable (dpool-start's 'max-queued) so the refusal can be
    ;; exercised at all: a hard-coded ten thousand is not a limit any test
    ;; can reach, which is how it went unverified.
    (define max-queued queue-cap)
    (define next-id 0)

    (define (stash-result! id result)
      (hashtable-set! results id result)
      (set! stash-back (cons id stash-back))
      (set! stash-n (+ stash-n 1))
      (when (> stash-n max-stashed)
        (when (null? stash-front)
          (set! stash-front (reverse stash-back))
          (set! stash-back '()))
        (unless (null? stash-front)
          (hashtable-delete! results (car stash-front))   ; no-op if already taken
          (set! stash-front (cdr stash-front))
          (set! stash-n (- stash-n 1)))))

    (define (pick-node!)
      (let loop ((tries (length live)))
        (cond
          ((null? live) #f)
          ((fx<= tries 0) #f)
          (else
           (when (null? rr) (set! rr live))
           (let ((n (car rr)))
             (set! rr (cdr rr))
             (if (memq n live) n (loop (fx- tries 1))))))))

    ;; Requeueing is NOT bounded, and that is deliberate.
    ;;
    ;; A task reaching here from node-gone! or the offline drain was already
    ;; accepted: the submitter holds an id and an at-least-once promise, and
    ;; there is no longer any way to tell it otherwise. Dropping it to
    ;; respect a queue bound would break the one guarantee this pool makes.
    ;; What the bound governs instead is NEW work -- the submit clause
    ;; refuses that while the backlog stands -- so the queue is bounded by
    ;; what was in flight when the nodes went away, which is itself bounded
    ;; by the slot accounting.
    (define (dispatch! id payload mode)
      (let ((node (pick-node!)))
        (if (not node)
            (begin
              (set! queue-rev (cons (vector id payload mode) queue-rev))
              (set! queued-n (+ queued-n 1)))
            (let ((token (random-token!)))
              (hashtable-set! inflight id (vector payload node mode token))
              ;; rsend can RAISE, not merely answer #f: serialising the
              ;; payload fails on a procedure, a port, or anything else
              ;; outside the extended wire format. Unguarded that killed the
              ;; coordinator -- after the submitter had already been handed a
              ;; task id -- and every later submit then waited forever on a
              ;; process that no longer existed. One bad payload took down
              ;; the whole pool, which is a far larger blast radius than the
              ;; one task deserved.
              (let ((sent (guard (e (#t 'unsendable))
                            (rsend node worker-name
                                   (vector 'dtask id self-node coord-name
                                           payload token)))))
                (cond
                  ((eq? sent 'unsendable)
                   ;; not the node's fault and not retryable: reassigning it
                   ;; elsewhere would fail identically. Fail this task only,
                   ;; through the same path a worker-side failure takes, so
                   ;; awaiters are answered and the outcome is stashed.
                   (complete! id (vector 'task-error 'not-serializable)))
                  ((not sent)
                   ;; the link died between pick and send: drop the node and
                   ;; treat this task as hit by a node-down
                   (hashtable-delete! inflight id)
                   (set! live (remq node live))
                   (lost! id payload mode))
                  (else (void))))))))

    ;; a task's node vanished: reassign (at-least-once) or fail it
    (define (lost! id payload mode)
      (if (eq? mode 'at-least-once)
          (dispatch! id payload mode)
          (complete! id (vector 'node-down))))

    (define (complete! id result)
      (hashtable-delete! inflight id)
      (let ((aws (hashtable-ref awaiters id '())))
        (for-each
          (lambda (a) (send (vector-ref a 0)
                            (vector 'dpool-result (vector-ref a 1) result)))
          aws)
        (hashtable-delete! awaiters id)
        ;; Stash it EVEN when awaiters were notified. A caller whose
        ;; timeout fired microseconds earlier is already gone; without a
        ;; stash the outcome of an at-most-once task would be permanently
        ;; unknowable, because a re-await registers against an id no
        ;; longer in flight and just times out again.
        (stash-result! id result)))

    (define (drain-queue!)
      (let ((q (reverse queue-rev)))
        (set! queue-rev '())
        (set! queued-n 0)
        (for-each (lambda (t) (dispatch! (vector-ref t 0) (vector-ref t 1)
                                         (vector-ref t 2)))
                  q)))

    (define (node-gone! node)
      (set! live (remq node live))
      ;; reassign / fail every task that was running on the dead node
      (let-values (((ids entries) (hashtable-entries inflight)))
        (vector-for-each
          (lambda (id e)
            (when (eq? (vector-ref e 1) node)
              (hashtable-delete! inflight id)
              (lost! id (vector-ref e 0) (vector-ref e 2))))
          ids entries)))

    ;; watch every remote member for up/down, then serve forever
    (for-each (lambda (m) (unless (eq? m self-node) (monitor-node m))) members)
    (let loop ()
      (receive
        (`#(submit ,payload ,mode ,from ,ref)
          ;; Checked BEFORE an id is handed out: a submitter that receives an
          ;; id reasonably believes the task is accepted, and there would be
          ;; no way to tell it otherwise afterwards.
          ;; The backlog counts whether or not a node happens to be live.
          ;; Requiring both meant a coordinator sitting on a large queue --
          ;; the tasks a node failure handed back, which cannot be dropped
          ;; without breaking the at-least-once promise already made about
          ;; them -- went on accepting NEW work as soon as any node
          ;; returned, on top of a backlog already over budget. With a live
          ;; node a submission does not queue at all, so this only bites
          ;; when there is a real backlog, which is when it should.
          (if (>= queued-n max-queued)
              (send from (vector 'dpool-rejected ref 'overloaded))
              (let ((id next-id))
                (set! next-id (+ next-id 1))
                (send from (vector 'dpool-submitted ref id))
                (dispatch! id payload mode))))
        (`#(await ,id ,from ,ref)
          (let ((r (hashtable-ref results id #f)))
            (if r
                (begin
                  (hashtable-delete! results id)
                  (send from (vector 'dpool-result ref r)))
                (hashtable-set! awaiters id
                  (cons (vector from ref) (hashtable-ref awaiters id '()))))))
        (`#(await-cancel ,id ,from ,ref)
          ;; the awaiting caller timed out: drop its slot so a never-
          ;; completing id (or a repeatedly re-awaited one) cannot pile
          ;; up awaiter entries forever
          (let ((rest (filter (lambda (a)
                                (not (and (eq? (vector-ref a 0) from)
                                          (eqv? (vector-ref a 1) ref))))
                              (hashtable-ref awaiters id '()))))
            (if (null? rest)
                (hashtable-delete! awaiters id)
                (hashtable-set! awaiters id rest))))
        (`#(dresult ,id ,token ,result)
          ;; a live node finished (ok or task-error): terminal, no retry.
          ;; Accept only if the token matches THIS attempt -- rejects a
          ;; forged result and a stale reply from a superseded attempt.
          (let ((e (hashtable-ref inflight id #f)))
            (when (and e (eqv? (vector-ref e 3) token))
              (complete! id result))))
        (`#(node-up ,node)
          (unless (memq node live) (set! live (cons node live)))
          (drain-queue!))
        (`#(node-down ,node)
          (node-gone! node))
        (`#(stats ,from ,ref)
          (send from
            (vector 'dpool-stats ref
              (list (cons 'live (length live))
                    (cons 'inflight (hashtable-size inflight))
                    (cons 'queued (length queue-rev))))))
        (other (void)))                        ; ignore stray messages
      (loop)))

  ;; ---- public submit / await -------------------------------------------------

  ;; Dispatch a task; returns its id immediately (async).
  (define (dpool-submit pool payload . rest)
    (let ((mode (opt (if (pair? rest) (car rest) '()) 'mode (dpool-default-mode pool)))
          (ref (next-ref!)))
      (unless (memq mode '(at-least-once at-most-once))
        (assertion-violation 'dpool-submit "bad mode" mode))
      (send (dpool-pid pool) (vector 'submit payload mode self ref))
      (receive
        (`#(dpool-submitted ,@ref ,id) id)
        (`#(dpool-rejected ,@ref ,why)
          (raise (vector 'dpool-error 'overloaded why))))))

  ;; Block for a task's result: the handler's return value, or a raised
  ;; #(dpool-error ,reason ,id) where reason is task-error | node-down |
  ;; await-timeout.
  ;; Drain the late answer to a previously timed-out await. Its ref can
  ;; never match again (refs are monotonic), so selective receive would
  ;; keep it in this mailbox forever, rescanned by every later receive.
  ;; Safe because an await is synchronous within one green process: any
  ;; dpool-result present at ENTRY is by construction stale.
  (define (drain-stale-results!)
    (let loop ()
      (receive (after 0 'done)
        (`#(dpool-result ,r ,v) (loop)))))

  (define (dpool-await pool id . rest)
    (drain-stale-results!)
    (let ((timeout (if (pair? rest) (car rest) default-await-ms))
          (ref (next-ref!)))
      (send (dpool-pid pool) (vector 'await id self ref))
      (receive (after timeout
                  (send (dpool-pid pool) (vector 'await-cancel id self ref))
                  (raise (vector 'dpool-error 'await-timeout id)))
        (`#(dpool-result ,@ref ,result)
          (if (eq? (vector-ref result 0) 'ok)
              (vector-ref result 1)
              (raise (vector 'dpool-error (vector-ref result 0) id)))))))

  ;; snapshot: live node count, in-flight tasks, queued tasks
  (define (dpool-stats pool)
    (let ((ref (next-ref!)))
      (send (dpool-pid pool) (vector 'stats self ref))
      (receive (after 5000 (raise 'dpool-stats-timeout))
        (`#(dpool-stats ,@ref ,s) s))))
)
