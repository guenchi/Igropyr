#!chezscheme
;;; (igropyr actor) -- Erlang-style green processes for Chez Scheme.
;;;
;;; Continuation-based context switching (call/1cc), a FIFO run queue,
;;; an indexed min-heap sleep queue, mailboxes with a receive macro whose
;;; (after timeout ...) clause is only recognized in FIRST position,
;;; link/monitor with EXIT/DOWN notification, and preemptive scheduling
;;; via Chez's timer interrupt so a CPU-spinning process can still be
;;; killed by the supervisor.
;;;
;;; Interrupt discipline: every scheduler-state mutation happens with
;;; interrupts disabled; a process always enters @yield with the disable
;;; count it expects to resume at (saved in pcb-sic). The
;;; event-loop process runs with interrupts permanently disabled so the
;;; timer interrupt can never fire inside uv_run or a libuv callback
;;; frame (yielding across a C frame would corrupt the system).

(library (igropyr actor)
  (export spawn spawn&link send receive self
          link monitor demonitor process-trap-exit kill
          register unregister whereis
          sleep-ms process-alive? process-id process-count
          process-monitor-count
          critical! uncritical! start-scheduler)
  ;; ⭐ (igropyr inject) IS A COMPILE-TIME ONLY DEPENDENCY WHEN OFF -- the
  ;; off expansion of every primitive refers to no runtime name of it, so
  ;; this unit's invoke-requirements stay (), which is what
  ;; test/inject-isolation.ss measures for every unit in library-units.
  (import (chezscheme) (igropyr libuv) (igropyr inject))

  (define process-default-ticks 100000)

  ;; ---- intrusive doubly-linked queues --------------------------------

  (define-record-type (q make-q q?)
    (fields
      (mutable prev q-prev q-prev-set!)
      (mutable next q-next q-next-set!)))

  (define (make-queue)
    (let ((x (make-q #f #f)))
      (q-prev-set! x x)
      (q-next-set! x x)
      x))

  (define (queue-empty? x) (eq? (q-next x) x))
  (define (enqueued? node) (and (q-next node) #t))

  (define (insert-before! node next)
    (let ((prev (q-prev next)))
      (q-prev-set! node prev)
      (q-next-set! node next)
      (q-next-set! prev node)
      (q-prev-set! next node)))

  (define (remove-q! node)
    (let ((prev (q-prev node)) (next (q-next node)))
      (q-next-set! prev next)
      (q-prev-set! next prev)
      (q-prev-set! node #f)
      (q-next-set! node #f))
    node)

  ;; Remove a message but keep its next pointer so an in-progress inbox
  ;; scan can step over it.
  (define (remove-msg! m)
    (let ((prev (q-prev m)))
      (when prev
        (let ((next (q-next m)))
          (q-next-set! prev next)
          (q-prev-set! next prev)
          (q-prev-set! m #f)))))

  (define-record-type (msg make-msg-record msg?)
    (parent q)
    (fields (immutable contents msg-contents)))

  (define (make-msg contents) (make-msg-record #f #f contents))

  ;; ---- process control block -----------------------------------------

  (define-record-type (pcb make-pcb-record pcb?)
    (parent q)
    (fields
      (immutable id pcb-id)
      (mutable cont pcb-cont pcb-cont-set!)
      (mutable winders pcb-winders pcb-winders-set!)
      (mutable exception-state pcb-exception-state pcb-exception-state-set!)
      (mutable inbox pcb-inbox pcb-inbox-set!)   ; queue sentinel; #f = dead
      (mutable waketime pcb-waketime pcb-waketime-set!)
      (mutable sleeping? pcb-sleeping? pcb-sleeping?-set!)
      (mutable trap-exit pcb-trap-exit pcb-trap-exit-set!)
      (mutable sic pcb-sic pcb-sic-set!)         ; saved interrupt count
      (mutable links pcb-links pcb-links-set!)
      (mutable monitors pcb-monitors pcb-monitors-set!)
      (mutable exit-reason pcb-exit-reason pcb-exit-reason-set!)
      ;; slot in the sleep heap; meaningful only while sleeping? is #t
      (mutable heap-index pcb-heap-index pcb-heap-index-set!)))

  (define-record-type (mon make-mon mon?)
    (fields (immutable origin mon-origin) (immutable target mon-target)))

  (define (alive? p) (and (pcb-inbox p) #t))
  (define process-alive? alive?)
  (define (process-id p) (pcb-id p))

  ;; HOW MANY ENTRIES ARE IN THIS PROCESS'S MONITOR LIST -- entries, not
  ;; relationships, and the difference is observable. A watch puts the SAME
  ;; record into the watcher's list and the watched process's list, so it
  ;; contributes one entry here whichever end this process is. When both
  ;; ends are this process, (monitor self), it contributes TWO: measured,
  ;; the count went from 2 to 4 for one such call.
  ;;
  ;; SO THE NUMBER IS FOR COMPARING WITH ITSELF, not for reading absolutely.
  ;; A value of 5 does not say five watches, or in which direction. Take a
  ;; baseline, perform the operation, compare -- which is what it is for:
  ;;
  ;; A LEAKED MONITOR IS NEARLY INVISIBLE. It occupies memory, adds to the
  ;; work done when either process dies, and can produce a DOWN that some
  ;; handler then ignores -- none of which any assertion is watching. So a
  ;; test that removes the demonitor from a mark-and-replace path stays
  ;; green, which is how the leak this exists to catch was written. Counting
  ;; is what makes that visible; it is not the only trace, only the one a
  ;; cell can hold on to.
  ;;
  ;; It is a length, so it walks the list. Fine for introspection, not for a
  ;; hot path.
  (define (process-monitor-count p)
    (unless (pcb? p)
      (assertion-violation 'process-monitor-count "not a process" p))
    (length (pcb-monitors p)))

  ;; ---- global scheduler state ------------------------------------------

  ;; Virtual register allocation (Chez provides 16; see
  ;; virtual-register-count). igropyr claims register 0 process-wide for
  ;; the current pcb. Registers 1..15 are RESERVED, not free scratch:
  ;; a register lives in the thread context, so its real value is being
  ;; PER-OS-THREAD state, and it should be spent only on that. The one
  ;; obvious future claimant is an SMP multi-scheduler (N OS threads,
  ;; one run/sleep queue + uv loop each); those per-thread roots are
  ;; what registers 1..3 are held for. Do NOT move an ordinary global
  ;; (run-queue, uv-loop, a counter) into a register for "speed": at
  ;; optimize-level 2 a library-variable reference already compiles to
  ;; one load, exactly like a register, so there is no single-threaded
  ;; win to be had -- only the finite register file to waste. (*self*
  ;; earned register 0 for three reasons at once, not speed alone: it
  ;; was a box, so two dependent loads; it is read/written on every
  ;; send/receive/switch, and a box write also takes a GC write barrier
  ;; that a register write does not; and the exported `self` needs a
  ;; cross-library reference that R6RS forbids for an assigned variable.
  ;; No other global meets that bar.)
  (define-syntax *self*
    (identifier-syntax
      (id (virtual-register 0))
      ((set! id v) (set-virtual-register! 0 v))))
  (define-syntax self (identifier-syntax *self*))
  (define run-queue (make-queue))
  ;; Roots every live pcb: a process parked in receive with no timeout
  ;; sits in no queue and would otherwise be collectable.
  (define process-table (make-eqv-hashtable))

  ;; How many green processes are alive right now.
  ;;
  ;; A leaked process is invisible by nature: it is parked in a receive, so
  ;; it burns nothing and shows up in no counter -- it only accumulates.
  ;; Several of the leaks found in this system were of exactly that shape,
  ;; and none of them could be asserted on from outside without this.
  (define (process-count) (hashtable-size process-table))
  (define pid-counter 0)
  (define event-loop-pid #f)

  ;; process registry: names survive restarts, pids don't. A dead
  ;; process is unregistered automatically (see @kill).
  (define name->pid (make-eq-hashtable))
  ;; A name has one owner, but a process may intentionally expose several
  ;; names (conversation routing does this), so the reverse side is a list.
  (define pid->names (make-eq-hashtable))

  (define (remove-pid-name! pid name)
    (let ((remaining (remq name (hashtable-ref pid->names pid '()))))
      (if (null? remaining)
          (hashtable-delete! pid->names pid)
          (hashtable-set! pid->names pid remaining))))

  (define (register name pid)
    (with-interrupts-disabled
      ;; Rebinding a NAME must also detach it from the displaced process.
      ;; Otherwise that process's later @kill follows a stale reverse entry
      ;; and deletes the replacement registration.
      (let ((old-pid (hashtable-ref name->pid name #f)))
        (when (and old-pid (not (eq? old-pid pid)))
          (remove-pid-name! old-pid name)))
      (hashtable-set! name->pid name pid)
      (let ((names (hashtable-ref pid->names pid '())))
        (unless (memq name names)
          (hashtable-set! pid->names pid (cons name names)))))
    pid)

  (define (unregister name)
    (with-interrupts-disabled
      (let ((p (hashtable-ref name->pid name #f)))
        (hashtable-delete! name->pid name)
        (when p (remove-pid-name! p name)))))

  ;; guarded like register/unregister: hashtable-ref is preemptible, and
  ;; a concurrent register that grows the table can relink the chain
  ;; under a half-finished lookup, yielding a spurious #f for a name
  ;; that is registered the whole time.
  (define (whereis name)
    (with-interrupts-disabled (hashtable-ref name->pid name #f)))

  ;; INTERRUPT REGIONS HERE ARE EXIT-SAFE, and that is not free.
  ;;
  ;; There used to be a faster macro that skipped the re-enable when its
  ;; body escaped, on the rule that every body was short enough and
  ;; pre-validated enough that it could not raise. The rule was written
  ;; down and it was not kept: twelve sites shared it, and a rule spread
  ;; over twelve sites is a rule somebody eventually reads as advice.
  ;;
  ;; What it cost when broken was out of all proportion to what it
  ;; bought. A raise that escapes such a region AND IS CAUGHT inside the
  ;; same still-alive process leaves that process's saved interrupt
  ;; count one too high, and that process is never preempted again --
  ;; for the rest of the run, with no error and nothing to see. (An
  ;; UNCAUGHT one is harmless: the process dies and the context switch
  ;; discards its count. So the damage needs a guard between the raise
  ;; and the top, which is exactly what careful code has.)
  ;;
  ;; Measured price of exit-safety, ping-pong with no work between
  ;; messages -- the worst case for it, since the whole loop is send and
  ;; receive. 200k round-trips, three runs each, on one machine: 245-251
  ;; ns per round-trip before, 261-263 after. About 5%, and every bit of
  ;; that 5% is on the two hottest calls in the system. Anything with
  ;; real work between messages dilutes it. What it buys is the removal
  ;; of a silent, permanent, whole-process failure, which is not a trade
  ;; that needed thinking about.
  ;;
  ;; The argument type checks stay OUTSIDE these regions anyway (see
  ;; send and link): failing early is still better than unwinding.
  ;;
  ;; ⭐ WHEN TO USE THIS FORM, AND WHEN A BARE disable-interrupts IS
  ;; RIGHT. Some of this file does not use the form at all: it disables
  ;; and enables by hand, sometimes across a yield, sometimes in a place
  ;; that never enables again. That is not sloppiness left to tidy up
  ;; later, and the rule for telling the two apart is short:
  ;;
  ;;   ⭐ A NEW hand-written disable-interrupts belongs in this form
  ;;   UNLESS no path out of it ever returns. If there is a path that
  ;;   comes back, write it lexically.
  ;;
  ;; All ten of the hand-paired sites here have been judged one at a
  ;; time against that rule and none of them qualifies: three sit in
  ;; front of a yield the process never comes back from, two implement
  ;; the interrupt save/restore that this form relies on, one spans a
  ;; park and a rescan loop with two exits at different depths, one is
  ;; the whole life of the event loop, and one is not a region at all --
  ;; its disable is an argument, producing a count rather than a scope.
  ;; The reasoning per site is in the segment archive; what belongs here
  ;; is the rule, because the person who adds an eleventh will be
  ;; editing this file and not reading that one.
  ;;
  ;; PAYING IT UNIFORMLY IS THE POINT, and the next reader will want to
  ;; stop. Some of these twelve bodies genuinely cannot raise, and it is
  ;; easy to argue that those ones could keep the fast form and save
  ;; their share of the 5%. That argument is not new -- it is the rule
  ;; that used to be written here, and following it site by site is what
  ;; produced the defect. Twelve places sharing one written rule is one
  ;; rule read as advice twelve times.
  ;;
  ;; So: going back to per-site judgement is allowed, but it starts by
  ;; explaining why it will not end the same way. "This one obviously
  ;; cannot raise" is the sentence that was already there.

  (define (panic what reason)
    (with-interrupts-disabled
      (display "PANIC: ") (display what) (display " ")
      (if (condition? reason)
          (display-condition reason (current-output-port))
          (write reason))
      (newline)
      (exit 70)))

  ;; ---- run queue ------------------------------------------------------

  ;; Make p runnable: append to the run-queue tail (the run queue is
  ;; FIFO; there are no priorities among runnable processes).
  ;; Precondition: p is not queue-linked. A running, parked, fresh, or
  ;; just-woken process never is, and @send guards its already-runnable
  ;; case with enqueued?, so there is no removal check here.
  (define (@run! p)
    (insert-before! p run-queue))

  ;; ---- sleep heap -----------------------------------------------------

  ;; Sleeping processes live in an indexed binary min-heap keyed by
  ;; pcb-waketime (always a fixnum: receive-after clamps it), with
  ;; pcb-heap-index tracking each sleeper's slot so a message arrival
  ;; or kill removes an arbitrary sleeper without a scan. Why not a
  ;; sorted list: with mixed timeout durations (5s gen-server calls
  ;; among 60s keep-alives) a sorted insert of a short deadline walks
  ;; past every longer one -- O(n) per timed receive, at exactly the
  ;; connection counts where it hurts. Heap costs for the common cases:
  ;; inserting the latest deadline ("now + constant" while older timers
  ;; drain) is one compare; cancelling a young timer when its message
  ;; arrives (the dominant @send path) re-settles near the bottom, ~one
  ;; compare; expiry pops are O(log n) and happen at most once per
  ;; timeout. Equal waketimes wake in unspecified relative order, as in
  ;; Erlang.
  (define sleep-heap (make-vector 64 #f))
  (define sleep-count 0)

  (define (@heap-place! i p)
    (vector-set! sleep-heap i p)
    (pcb-heap-index-set! p i))

  ;; slot i is conceptually empty: settle p at i or above it
  (define (@heap-up! i p)
    (if (fx= i 0)
        (@heap-place! 0 p)
        (let* ((pi (fxsrl (fx- i 1) 1))
               (parent (vector-ref sleep-heap pi)))
          (if (fx< (pcb-waketime p) (pcb-waketime parent))
              (begin (@heap-place! i parent) (@heap-up! pi p))
              (@heap-place! i p)))))

  ;; slot i is conceptually empty: settle p at i or below it
  (define (@heap-down! i p)
    (let ((l (fx+ (fxsll i 1) 1)))
      (if (fx>= l sleep-count)
          (@heap-place! i p)
          (let* ((r (fx+ l 1))
                 (c (if (and (fx< r sleep-count)
                             (fx< (pcb-waketime (vector-ref sleep-heap r))
                                  (pcb-waketime (vector-ref sleep-heap l))))
                        r
                        l))
                 (cp (vector-ref sleep-heap c)))
            (if (fx< (pcb-waketime cp) (pcb-waketime p))
                (begin (@heap-place! i cp) (@heap-down! c p))
                (@heap-place! i p))))))

  ;; p is running (in no structure); put it to sleep until waketime
  (define (@sleep! p waketime)
    (pcb-waketime-set! p waketime)
    (pcb-sleeping?-set! p #t)
    (let ((n (vector-length sleep-heap)))
      (when (fx= sleep-count n)
        (let ((v (make-vector (fx* n 2) #f)))
          (do ((i 0 (fx+ i 1)))
              ((fx= i n))
            (vector-set! v i (vector-ref sleep-heap i)))
          (set! sleep-heap v))))
    (let ((i sleep-count))
      (set! sleep-count (fx+ i 1))
      (@heap-up! i p)))

  ;; Remove a sleeper (waketime reached, message arrived, or killed):
  ;; the vacated last element is re-settled from p's old slot -- up if
  ;; it beats the parent there, down otherwise. The caller clears
  ;; pcb-sleeping?.
  (define (@sleep-remove! p)
    (let ((i (pcb-heap-index p))
          (last (fx- sleep-count 1)))
      (set! sleep-count last)
      (let ((moved (vector-ref sleep-heap last)))
        (vector-set! sleep-heap last #f)
        (unless (eq? moved p)
          (if (and (fx> i 0)
                   (fx< (pcb-waketime moved)
                        (pcb-waketime
                          (vector-ref sleep-heap (fxsrl (fx- i 1) 1)))))
              (@heap-up! i moved)
              (@heap-down! i moved))))))

  ;; Wake sleeping processes whose time has come. Called only from the
  ;; event loop, never from @yield: reading the clock costs an FFI call,
  ;; and paying it per context switch buys nothing -- a woken process
  ;; joins the TAIL of the run queue either way, and the event-loop
  ;; process runs once per scheduling round (with uv-poll!'s timeout
  ;; aimed at the earliest deadline when idle), so waking from here adds
  ;; at most a fraction of the round the process was already going to
  ;; wait out.
  (define (@event-check)
    (unless (fx= sleep-count 0)
      (let ((rt (now-ms)))
        (let wake ()
          (unless (fx= sleep-count 0)
            (let ((p (vector-ref sleep-heap 0)))
              (when (fx<= (pcb-waketime p) rt)
                (@sleep-remove! p)
                (pcb-sleeping?-set! p #f)
                (@run! p)
                (wake))))))))

  ;; ---- context switch -----------------------------------------------------

  (define (yield where waketime)
    (@yield where waketime (disable-interrupts)))

  (define (@yield-preserving-interrupts where waketime)
    (disable-interrupts)
    (@yield where waketime (enable-interrupts))
    (disable-interrupts))

  ;; Called with interrupts disabled; disable-count is the current
  ;; count. where is 'run (stay runnable), 'sleep (until waketime), or
  ;; #f (park: blocked in receive, or dead). The running process is
  ;; never queue-linked -- it was dequeued when it was scheduled -- so
  ;; the #f case has nothing to remove.
  ;; The winder list is SAVED AND RESTORED per process, never run. That is
  ;; the right call for dynamic-wind -- an after-thunk must not fire merely
  ;; because its process yielded -- but it is why (make-parameter) gives no
  ;; per-process isolation: Chez implements parameterize by swapping a
  ;; GLOBAL cell and registering a winder to swap it back, so with the hooks
  ;; unrun the cell belongs to whichever process wrote it last. A process
  ;; then cannot even read back its own binding across a yield. Documented in
  ;; the README under "Dynamic state and parameterize"; there is no clean fix
  ;; (running the winders would break dynamic-wind, and saving the values
  ;; instead would need to enumerate every live parameter, which Chez does
  ;; not expose). Applications wanting request-scoped state use req-local.
  (define (@yield where waketime disable-count)
    (when (alive? *self*)
      (pcb-winders-set! *self* (#%$current-winders))
      (pcb-exception-state-set! *self* (current-exception-state)))
    (#%$current-winders '())
    ;; snap the continuation
    (call/1cc
      (lambda (k)
        (when (alive? *self*)
          (pcb-cont-set! *self* k)
          (cond
            ((eq? where 'run) (@run! *self*))
            ((eq? where 'sleep) (@sleep! *self* waketime))))
        ;; context switch
        (when (alive? *self*)
          (pcb-sic-set! *self* disable-count))
        (let ((p (q-next run-queue)))
          (when (eq? p run-queue)
            (panic 'scheduler "run queue empty"))
          (set! *self* (remove-q! p)))
        ;; adjust the interrupt disable count for the new process
        (let loop ((next-sic (pcb-sic *self*)))
          (unless (fx= next-sic disable-count)
            (cond
              ((fx> next-sic disable-count)
               (disable-interrupts)
               (loop (fx- next-sic 1)))
              (else
               (enable-interrupts)
               (loop (fx+ next-sic 1))))))
        ;; restart the new process
        ((pcb-cont *self*) (void))))
    ;; restart point
    (#%$current-winders (pcb-winders *self*))
    (current-exception-state (pcb-exception-state *self*))
    (pcb-cont-set! *self* #f)             ; drop refs to avoid leaks
    (pcb-winders-set! *self* '())
    (pcb-exception-state-set! *self* #f)
    (set-timer process-default-ticks)
    (enable-interrupts))

  ;; Turn a thunk into a resumable continuation on a fresh stack
  ;; Any uncaught raise lands in the exception
  ;; state's base handler `done` and becomes the exit reason.
  (define @thunk->cont
    (let ((return #f))
      (lambda (thunk)
        (let ((winders (#%$current-winders)))
          (#%$current-winders '())
          (let ((k (call/1cc
                     (lambda (k1)
                       ;; don't close over k1, or the new process would
                       ;; keep the creating continuation alive
                       (set! return k1)
                       (#%$current-stack-link #%$null-continuation)
                       (let ((reason
                              (call/cc
                                (lambda (done)
                                  (call/1cc return)
                                  ;; first activation starts here
                                  (current-exception-state
                                    (create-exception-state done))
                                  (pcb-cont-set! *self* #f)
                                  (set-timer process-default-ticks)
                                  (enable-interrupts)
                                  (thunk)
                                  'normal))))
                         ;; process finished or crashed
                         (disable-interrupts)
                         (@kill *self* reason)
                         (yield #f 0))))))
            (set! return #f)
            (#%$current-winders winders)
            k)))))

  ;; ---- spawn / kill / link / monitor -------------------------------------

  (define (@make-process cont)
    (set! pid-counter (+ pid-counter 1))
    (let ((p (make-pcb-record #f #f pid-counter cont '() #f (make-queue)
                              0 #f #f 1 '() '() #f 0)))
      (hashtable-set! process-table pid-counter p)
      p))

  (define (spawn thunk)
    (with-interrupts-disabled
      (let ((p (@make-process (@thunk->cont thunk))))
        (@run! p)
        p)))

  (define (spawn&link thunk)
    (with-interrupts-disabled
      (let ((p (@make-process (@thunk->cont thunk))))
        (@link p *self*)
        (@run! p)
        p)))

  (define (@link p1 p2)
    (unless (memq p2 (pcb-links p1))
      ;; ⛔ BOTH CELLS ARE ALLOCATED BEFORE EITHER IS PUBLISHED. A link is
      ;; one fact about two processes, and it was written as two steps
      ;; with an allocation between them: the second cons could fail with
      ;; p1 already listing p2 and p2 not listing p1. Nothing repairs
      ;; that -- the raise leaves link's caller, and the half that landed
      ;; is a live link as far as every reader is concerned, so p1's exit
      ;; acts on it while p2 never hears. Measured: the proxy received
      ;; #(EXIT <pcb> for-the-cell) from a link it does not have.
      ;;
      ;; With both conses first, the only steps after the first publish
      ;; are two pointer writes, which is what the R0 rule for this
      ;; region asks for and is why no guard is needed or wanted here.
      (let ((l1 (cons p2 (pcb-links p1))))
        ;; INJECTION POINT 'link-second-half -- OWNING GUARD: none. This
        ;; body runs inside with-interrupts-disabled at every caller, and
        ;; a disabled-interrupt region is not a guard: it does not catch,
        ;; so the raise leaves the region and reaches link's caller.
        ;;
        ;; ⚠ THE POINT IS ANCHORED TO THE SECOND ALLOCATION, NOT TO A
        ;; POSITION BETWEEN THE TWO WRITES. It models the second cons
        ;; failing, which is the only step here that can fail, and it
        ;; follows that cons wherever the cons goes. Between the two
        ;; pcb-links-set! calls below there is now nothing that can fail
        ;; at all: a point placed there would inject an impossible
        ;; failure, the cell could never go green, and a correct fix
        ;; would read as ineffective.
        (inject-fault! 'link-second-half)
        (let ((l2 (cons p1 (pcb-links p2))))
          (pcb-links-set! p1 l1)
          (pcb-links-set! p2 l2)))))

  (define (link p)
    ;; Validated OUTSIDE the interrupt region, as send already does. An accessor
    ;; raising INSIDE the region skips its enable-interrupts, so the process
    ;; carries a permanently disabled preemption timer: it cannot be
    ;; preempted again, and one CPU loop then freezes the whole scheduler.
    ;; An application that guards the error and continues -- (link (whereis
    ;; 'missing)) is the obvious way in -- gets exactly that.
    (unless (pcb? p)
      (assertion-violation 'link "not a process" p))
    (unless (eq? p *self*)
      (with-interrupts-disabled
        (if (alive? p)
            (@link p *self*)
            ;; linking to a dead process: behave as if it just died
            (if (pcb-trap-exit *self*)
                (@send *self* (vector 'EXIT p (pcb-exit-reason p)))
                (unless (eq? (pcb-exit-reason p) 'normal)
                  (kill *self* (pcb-exit-reason p))))))))

  ;; Unidirectional watch: when p dies the caller gets #(DOWN ,p ,reason).
  ;; Returns the monitor reference for demonitor, or #f if p was already
  ;; dead (the DOWN message is delivered immediately in that case).
  (define (monitor p)
    (unless (pcb? p)
      (assertion-violation 'monitor "not a process" p))
    (with-interrupts-disabled
      (if (alive? p)
          ;; Both cells before either publish, for the reason spelled out
          ;; at @link. Measured before the change: the watcher's own pcb
          ;; carried the monitor and the target's did not, so demonitor
          ;; had something to remove and the target's death had nobody to
          ;; tell.
          (let* ((m (make-mon *self* p))
                 (a (cons m (pcb-monitors *self*))))
            ;; INJECTION POINT 'monitor-second-half -- OWNING GUARD: none,
            ;; for the reason given at @link's point, and anchored the same
            ;; way: to the second cons, which this call sits before in
            ;; either version of the code.
            (inject-fault! 'monitor-second-half)
            ;; ⛔ (monitor self) IS LEGAL AND ALIASES THE TWO LISTS.
            ;; Unlike link, which refuses a self-target, monitor accepts
            ;; one, and the header of this file records the measured
            ;; consequence: such a call adds TWO entries, because the
            ;; old code's second cons read the list the first write had
            ;; already updated. Building both cells from the same
            ;; snapshot loses that -- the second write would overwrite
            ;; the first and the call would add ONE. Chaining b onto a
            ;; keeps the published result identical to the old code's
            ;; while still allocating everything before either write.
            (let ((b (if (eq? p *self*)
                         (cons m a)
                         (cons m (pcb-monitors p)))))
              (pcb-monitors-set! *self* a)
              (pcb-monitors-set! p b)
              m))
          (begin
            (@send *self* (vector 'DOWN p (pcb-exit-reason p)))
            #f))))

  (define (demonitor m)
    (when (mon? m)
      (with-interrupts-disabled
        (pcb-monitors-set! (mon-origin m)
          (remq m (pcb-monitors (mon-origin m))))
        (pcb-monitors-set! (mon-target m)
          (remq m (pcb-monitors (mon-target m)))))))

  (define (process-trap-exit b)
    (pcb-trap-exit-set! *self* b))

  ;; Terminate a process unconditionally (used by the supervisor to kill
  ;; stuck workers). Killing self never returns.
  (define (kill p reason)
    (unless (pcb? p)                       ; see link: never raise inside
      (assertion-violation 'kill "not a process" p))
    (if (eq? p *self*)
        (begin
          (disable-interrupts)
          (@kill p reason)
          (yield #f 0))
        (begin
          (with-interrupts-disabled (@kill p reason))
          ;; @kill cascades along links, and one of those links can be
          ;; US: a non-trapping process that kills a peer it is linked
          ;; to dies in the cascade. Without this check it would return
          ;; here and keep running with a dead pcb (inbox #f) -- sending
          ;; messages and doing I/O after its monitors already fired,
          ;; then crashing confusingly at its next receive.
          (unless (alive? *self*)
            (disable-interrupts)
            (yield #f 0)))))

  ;; interrupts disabled
  (define (@kill p reason)
    (when (alive? p)
      (when (eq? p event-loop-pid)
        (panic 'event-loop-terminated reason))
      (cond
        ((pcb-sleeping? p) (@sleep-remove! p))
        ((enqueued? p) (remove-q! p)))
      (pcb-cont-set! p #f)
      ;; The victim's dynamic-wind after-thunks are DISCARDED, not run:
      ;; they belong on the victim's stack, and a killer must not execute
      ;; arbitrary user cleanup in its own context (a stuck worker being
      ;; killed is exactly the case where that code must not run again).
      ;; Normal return and an uncaught raise DO run them. So dynamic-wind
      ;; is not a reliable release mechanism for a process that can be
      ;; killed -- have the resource's owner monitor the holder and
      ;; reclaim on DOWN (see (igropyr connpool)'s leases), which is the
      ;; only teardown that survives a kill.
      (pcb-winders-set! p '())
      (pcb-exception-state-set! p #f)
      (pcb-inbox-set! p #f)
      (pcb-sleeping?-set! p #f)
      (pcb-exit-reason-set! p reason)
      (hashtable-delete! process-table (pcb-id p))
      ;; release I/O resources the dead process can no longer close
      ;; itself (its winders do not run -- see the note above)
      (uv-owner-died! p)
      ;; drop every registered alias still owned by this process
      (let ((names (hashtable-ref pid->names p '())))
        (for-each
          (lambda (name)
            ;; A stale reverse entry must never erase a newer binding.
            (when (eq? (hashtable-ref name->pid name #f) p)
              (hashtable-delete! name->pid name)))
          names)
        (hashtable-delete! pid->names p))
      ;; notify/cascade links
      (let ((links (pcb-links p)))
        (pcb-links-set! p '())
        (for-each
          (lambda (l) (pcb-links-set! l (remq p (pcb-links l))))
          links)
        (for-each
          (lambda (l)
            (when (alive? l)
              (if (pcb-trap-exit l)
                  (@send l (vector 'EXIT p reason))
                  (unless (eq? reason 'normal)
                    (@kill l reason)))))
          links))
      ;; notify monitors
      (let ((mons (pcb-monitors p)))
        (pcb-monitors-set! p '())
        (for-each
          (lambda (m)
            (let ((origin (mon-origin m)) (target (mon-target m)))
              (if (eq? origin p)
                  ;; p was watching target
                  (pcb-monitors-set! target (remq m (pcb-monitors target)))
                  ;; p was watched: tell the watcher
                  (begin
                    (pcb-monitors-set! origin (remq m (pcb-monitors origin)))
                    (@send origin (vector 'DOWN p reason))))))
          mons))))

  ;; ---- send / receive ---------------------------------------------------

  ;; the pcb check is deliberately OUTSIDE the interrupt region: raising inside
  ;; that guard would skip its enable-interrupts (see the macro's note).
  ;; A whereis miss handing #f here is the common way to reach it.
  (define (send p m)
    (unless (pcb? p)
      (assertion-violation 'send "not a process" p))
    (with-interrupts-disabled (@send p m)))

  ;; interrupts disabled
  (define (@send p m)
    (let ((inbox (pcb-inbox p)))
      (when inbox
        (insert-before! (make-msg m) inbox)
        (cond
          ((pcb-sleeping? p)            ; timed receive: cancel the timer
           (@sleep-remove! p)
           (pcb-sleeping?-set! p #f)
           (@run! p))
          ((eq? p *self*) (void))       ; running; will see it on next scan
          ((enqueued? p) (void))        ; already runnable
          (else (@run! p))))))          ; parked in receive: wake

  ;; Core mailbox scan: scan the inbox against the
  ;; matcher; park (or sleep until waketime) when it runs dry; rescan on
  ;; wake; run the timeout handler once waketime has passed.
  (define ($receive matcher waketime timeout-handler)
    (disable-interrupts)
    ;; The inbox sentinel is stable across the parks below (a killed
    ;; process never resumes), so it is read once instead of per
    ;; scanned message.
    (let ((inbox (pcb-inbox *self*)))
      (let find-prev ((prev inbox))
        (let ((m (q-next prev)))
          (cond
            ((eq? inbox m)
             ;; inbox exhausted
             (cond
               ((not waketime)
                (@yield-preserving-interrupts #f 0)
                (find-prev prev))
               ((fx< (now-ms) waketime)
                (@yield-preserving-interrupts 'sleep waketime)
                (find-prev prev))
               (else
                (enable-interrupts)
                (timeout-handler))))
            ((not (q-prev m)) (find-prev m))   ; removed meanwhile; step over
            (else
             (enable-interrupts)
             (let ((run (matcher (msg-contents m))))
               (if run
                   (begin
                     (with-interrupts-disabled (remove-msg! m))
                     (run))
                   (begin
                     (disable-interrupts)
                     (find-prev m))))))))))

  (define (receive-after matcher timeout timeout-handler)
    (cond
      ((and (integer? timeout) (exact? timeout) (>= timeout 0))
       ;; clamp so waketime is always a fixnum (the queues compare
       ;; precedences with fx ops); greatest-fixnum ms is ~73M years
       ($receive matcher (min (+ (now-ms) timeout) (greatest-fixnum))
                 timeout-handler))
      ((eq? timeout 'infinity)
       ($receive matcher #f #f))
      (else (assertion-violation 'receive "bad after timeout" timeout))))

  ;; ---- pattern matcher for receive ---------------------------------------
  ;; Supports: bare variable (binds anything), literals, quasiquoted
  ;; patterns with ,var binders over vectors / pairs / literals -- enough
  ;; for every protocol message, e.g. `#(submit-task ,task).

  (define-syntax match-qp-vector
    (syntax-rules ()
      ((_ () i x sk) sk)
      ((_ (p p* ...) i x sk)
       (let ((e (vector-ref x i)))
         (match-qp p e (match-qp-vector (p* ...) (fx+ i 1) x sk))))))

  (define-syntax match-qp
    (lambda (stx)
      (syntax-case stx (unquote unquote-splicing)
        ((_ (unquote v) x sk)
         (identifier? #'v)
         #'(let ((v x)) sk))
        ;; ,@v matches only a value equal to the EXISTING binding v --
        ;; selective receive by value (e.g. reply tags): `#(reply ,@ref ,v)
        ((_ (unquote-splicing v) x sk)
         (identifier? #'v)
         #'(if (equal? v x) sk #f))
        ((_ #(p ...) x sk)
         (with-syntax ((n (length #'(p ...))))
           #'(if (and (vector? x) (fx= (vector-length x) n))
                 (match-qp-vector (p ...) 0 x sk)
                 #f)))
        ((_ (p1 . p2) x sk)
         #'(if (pair? x)
               (let ((h (car x)) (t (cdr x)))
                 (match-qp p1 h (match-qp p2 t sk)))
               #f))
        ((_ lit x sk)
         #'(if (equal? x 'lit) sk #f)))))

  (define-syntax match-clause
    (lambda (stx)
      (syntax-case stx (quasiquote)
        ((_ x (quasiquote qp) thunk)
         #'(match-qp qp x thunk))
        ((_ x var thunk)
         (identifier? #'var)
         #'(let ((var x)) thunk))
        ((_ x lit thunk)
         #'(if (equal? x 'lit) thunk #f)))))

  (define-syntax match-msg
    (syntax-rules ()
      ((_ m ((pattern b1 b2 ...) ...))
       (let ((x m))
         (or (match-clause x pattern (lambda () b1 b2 ...)) ...)))))

  ;; The (after timeout ...) clause is only recognized in FIRST position
  ;; an after clause anywhere else is a syntax error.
  (define-syntax receive
    (lambda (stx)
      (syntax-case stx ()
        ((_ (after timeout t1 t2 ...) (pattern b1 b2 ...) ...)
         ;; THE SAME GUARD AS THE PLAIN CASE, and it was missing here.
         ;; Without the memq, (receive (after 1 'a) (after 2 'b)) expands
         ;; silently: the first form is taken as the timeout and the
         ;; SECOND one goes through as an ordinary pattern, where a bare
         ;; identifier is a binding catch-all -- so a second after clause
         ;; quietly becomes a clause that matches every message. A
         ;; duplicated or mistyped timeout has to be a syntax error, not a
         ;; wildcard. The check looks for a BARE `after, so a quasiquoted
         ;; pattern matching the literal symbol -- `after inside `#(...) --
         ;; is unaffected and stays legal, exactly as in the plain case.
         (and (identifier? #'after) (eq? (syntax->datum #'after) 'after)
              (not (memq 'after (syntax->datum #'(pattern ...)))))
         #'(receive-after
             (lambda (m) (match-msg m ((pattern b1 b2 ...) ...)))
             timeout
             (lambda () t1 t2 ...)))
        ((_ (pattern b1 b2 ...) ...)
         (not (memq 'after (syntax->datum #'(pattern ...))))
         #'($receive
             (lambda (m) (match-msg m ((pattern b1 b2 ...) ...)))
             #f #f)))))

  (define (sleep-ms n)
    (receive (after n 'ok)))

  ;; ---- event loop process & scheduler startup -----------------------------

  (define (system-sleep-time)
    (cond
      ((not (queue-empty? run-queue)) 0)
      ((fx= sleep-count 0) 60000)          ; safety cap; I/O wakes uv_run
      (else
       (fxmin 60000
              (fxmax 0 (fx- (pcb-waketime (vector-ref sleep-heap 0))
                            (now-ms)))))))

  ;; Runs with interrupts permanently disabled (baseline disable count 1)
  ;; so the preemption timer can never fire inside uv_run or a libuv
  ;; callback frame.
  (define (event-loop)
    (disable-interrupts)
    (let loop ()
      (uv-poll! (system-sleep-time))
      (with-interrupts-disabled (@event-check))
      (yield 'run 0)
      (loop)))

  ;; Boot the world: the calling (OS-level) continuation becomes process
  ;; #1 and parks forever; libuv and the preemption timer are set up; the
  ;; event-loop process and the boot process are spawned. Never returns.
  ;; ---- critical components -----------------------------------------------
  ;;
  ;; THE SENTINEL IS ALREADY DOING THIS FOR ONE PROCESS. Process #1 watches
  ;; boot and panics unless it exits 'normal, so a boot failure cannot leave
  ;; a healthy event loop running with no application. A component the image
  ;; depends on afterwards -- the worker pool's supervisor is the first --
  ;; needs the same treatment, and this generalises the watch from that one
  ;; process to a set -- with a different rule, not the same one: see below,
  ;; boot may finish normally and a marked component may not. It is not a
  ;; supervision tree: nothing is restarted in
  ;; place. The image exits 70 and whatever started it decides what happens
  ;; next; whether that is a restart is that supervisor's configuration, not
  ;; something this code can promise.
  ;;
  ;; ANY EXIT PANICS, INCLUDING 'normal, and that is the difference from
  ;; boot. Boot returning normally is what success looks like. A pool
  ;; supervisor returning normally is not a stop, it is a component that was
  ;; supposed to run forever and fell off the end of its loop -- a missing
  ;; recursion, an unexpected branch -- and 'normal cannot tell that apart
  ;; from a deliberate one. Treating them alike would leave the image
  ;; running without the component, answering liveness checks and serving
  ;; nothing, which is the exact state critical! exists to prevent.
  ;;
  ;; SO A DELIBERATE STOP SAYS SO, with uncritical!, before stopping. That
  ;; makes the intent a call rather than an exit reason: the two are then
  ;; distinguishable, and the ambiguous case defaults to fatal.
  (define sentinel-pid #f)

  ;; Both validate in the CALLER. A bad argument discovered later would be
  ;; raised inside process #1 -- the process responsible for propagating
  ;; fatal failure -- which is the worst place in the image to put an
  ;; unexpected exception. The name is required to be a symbol because it is
  ;; the part of the panic that says WHICH component (the exit reason is
  ;; printed beside it), and because a #f name once made an earlier version
  ;; of the sentinel treat the entry as absent.
  ;; The shared half is only what both callers actually share. The name is
  ;; checked in critical! itself: uncritical! has no name, and folding that
  ;; difference into the helper with a "when there is a name" made #f a
  ;; legal name for the caller that has to refuse it.
  (define (critical-check who p)
    (unless sentinel-pid
      (assertion-violation who "call inside start-scheduler" p))
    (unless (pcb? p)
      (assertion-violation who "not a process" p)))

  (define (critical! p name)
    (critical-check 'critical! p)
    (unless (symbol? name)
      (assertion-violation 'critical! "name must be a symbol" name))
    (send sentinel-pid (vector 'critical p name))
    (void))

  ;; Registration and removal are asynchronous -- both return once the
  ;; request is queued, not once the sentinel has acted -- and THAT IS
  ;; ENOUGH, because the queue is where the order is decided. Enqueueing is
  ;; the linearisation point: a stop issued after uncritical! cannot put a
  ;; DOWN ahead of the removal already sitting in the sentinel's mailbox.
  ;; So this is safe, with no yield in between:
  ;;
  ;;   (uncritical! p) (kill p 'whatever)      ;; and (uncritical! self)
  ;;                                           ;; immediately before returning
  ;;
  ;; Measured, with a control: the first sequence does not panic, while the
  ;; same kill without the uncritical! does. Do not add a warning here
  ;; telling callers to yield first -- there is no hazard to warn about, and
  ;; a warning about one would make a correct sequence look dangerous.
  ;;
  ;; A death that was ALREADY queued still wins, which is the right way
  ;; round: unmarking cannot retroactively excuse a component that has
  ;; already gone.
  (define (uncritical! p)
    (critical-check 'uncritical! p)
    (send sentinel-pid (vector 'uncritical p))
    (void))

  (define (start-scheduler boot-thunk)
    (uv-init!)
    (uv-set-deliver! send)
    (set! *self* (@make-process #f))
    (timer-interrupt-handler
      (lambda () (yield 'run 0)))
    (set-timer process-default-ticks)
    (set! event-loop-pid (spawn event-loop))
    (let ((boot-pid (spawn boot-thunk)))
      ;; A boot failure (bind error, bad configuration, missing resource)
      ;; must not leave a healthy event loop running with no application.
      ;; Normal boot completion is expected after setup and is ignored.
      (monitor boot-pid)
      (set! sentinel-pid self)
      ;; The DOWN pattern is general now and the pid is dispatched on in the
      ;; body: boot keeps its own reading -- normal completion is success
      ;; there -- while a marked component panics on ANY reason, under the
      ;; symbol its critical! call supplied, which is a diagnostic label and
      ;; not a lookup in the process registry. A DOWN from anything else --
      ;; a monitor this process took for some other purpose -- is ignored
      ;; rather than read as a critical failure.
      ;; pid -> (name . monitor). The monitor is kept so uncritical! can
      ;; take the watch back off; the pair also keeps presence and value
      ;; apart, since hashtable-contains? decides membership and the stored
      ;; value is only read once membership is known.
      (let ((crit (make-eq-hashtable)))
        (let forever ()
          (receive (after 3600000 (forever))
            ;; A REPEATED MARK REPLACES, it does not accumulate. Marking
            ;; the same pid twice used to install a second monitor and
            ;; overwrite the only reference to the first, so uncritical!
            ;; could remove only the newer one and the older stayed in both
            ;; processes' monitor lists until one of them died. Mark and
            ;; unmark a long-lived process in a loop and that list grows
            ;; without bound.
            (`#(critical ,p ,name)
              (when (hashtable-contains? crit p)
                (demonitor (cdr (hashtable-ref crit p #f))))
              (hashtable-set! crit p (cons name (monitor p)))
              (forever))
            (`#(uncritical ,p)
              (let ((e (and (hashtable-contains? crit p)
                            (hashtable-ref crit p #f))))
                (when e (demonitor (cdr e)) (hashtable-delete! crit p)))
              (forever))
            ;; The DOWN pattern is general and the pid is dispatched on
            ;; here: boot keeps its own reading, a marked component panics
            ;; on ANY reason, and a DOWN from anything else -- a monitor
            ;; this process took for some other purpose -- is ignored
            ;; rather than read as a critical failure.
            (`#(DOWN ,p ,reason)
              (cond
                ((eq? p boot-pid)
                 (if (eq? reason 'normal) (forever) (panic 'boot reason)))
                ((hashtable-contains? crit p)
                 (panic (car (hashtable-ref crit p #f)) reason))
                (else (forever)))))))))
)
