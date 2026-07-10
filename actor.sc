#!chezscheme
;;; (igropyr actor) -- Erlang-style green processes for Chez Scheme.
;;;
;;; Continuation-based context switching (call/1cc), a precedence-ordered
;;; run queue and sleep queue, mailboxes with a receive macro whose
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
          sleep-ms process-alive? process-id
          start-scheduler)
  (import (chezscheme) (igropyr libuv))

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
      (mutable precedence pcb-precedence pcb-precedence-set!)
      (mutable sleeping? pcb-sleeping? pcb-sleeping?-set!)
      (mutable trap-exit pcb-trap-exit pcb-trap-exit-set!)
      (mutable sic pcb-sic pcb-sic-set!)         ; saved interrupt count
      (mutable links pcb-links pcb-links-set!)
      (mutable monitors pcb-monitors pcb-monitors-set!)
      (mutable exit-reason pcb-exit-reason pcb-exit-reason-set!)))

  (define-record-type (mon make-mon mon?)
    (fields (immutable origin mon-origin) (immutable target mon-target)))

  (define (alive? p) (and (pcb-inbox p) #t))
  (define process-alive? alive?)
  (define (process-id p) (pcb-id p))

  ;; ---- global scheduler state ------------------------------------------

  ;; The current pcb lives in a box so the exported `self` macro can read
  ;; it from other libraries (R6RS forbids referencing an assigned library
  ;; variable across library boundaries).
  (define self-cell (box #f))
  (define-syntax *self*
    (identifier-syntax
      (id (unbox self-cell))
      ((set! id v) (set-box! self-cell v))))
  (define-syntax self (identifier-syntax *self*))
  (define run-queue (make-queue))
  (define sleep-queue (make-queue))
  ;; Roots every live pcb: a process parked in receive with no timeout
  ;; sits in no queue and would otherwise be collectable.
  (define process-table (make-eqv-hashtable))
  (define pid-counter 0)
  (define event-loop-pid #f)

  ;; process registry: names survive restarts, pids don't. A dead
  ;; process is unregistered automatically (see @kill).
  (define name->pid (make-eq-hashtable))
  (define pid->name (make-eq-hashtable))

  (define (register name pid)
    (no-interrupts
      (hashtable-set! name->pid name pid)
      (hashtable-set! pid->name pid name))
    pid)

  (define (unregister name)
    (no-interrupts
      (let ((p (hashtable-ref name->pid name #f)))
        (hashtable-delete! name->pid name)
        (when p (hashtable-delete! pid->name p)))))

  (define (whereis name)
    (hashtable-ref name->pid name #f))

  (define-syntax no-interrupts
    (syntax-rules ()
      ((_ body ...)
       (let ((x (begin (disable-interrupts) body ...)))
         (enable-interrupts)
         x))))

  (define (panic what reason)
    (with-interrupts-disabled
      (display "PANIC: ") (display what) (display " ")
      (if (condition? reason)
          (display-condition reason (current-output-port))
          (write reason))
      (newline)
      (exit 70)))

  ;; ---- queues with precedence -------------------------------------------

  (define (@enqueue p queue precedence)
    (when (enqueued? p) (remove-q! p))
    (pcb-precedence-set! p precedence)
    (let find ((next queue))
      (let ((prev (q-prev next)))
        (if (or (eq? prev queue) (<= (pcb-precedence prev) precedence))
            (insert-before! p next)
            (find prev)))))

  ;; wake sleeping processes whose time has come
  (define (@event-check)
    (unless (queue-empty? sleep-queue)
      (let ((rt (now-ms)))
        (let wake ((p (q-next sleep-queue)))
          (when (and (not (eq? sleep-queue p)) (<= (pcb-precedence p) rt))
            (let ((next (q-next p)))
              (pcb-sleeping?-set! p #f)
              (@enqueue p run-queue 0)
              (wake next)))))))

  ;; ---- context switch -----------------------------------------------------

  (define (yield queue precedence)
    (@yield queue precedence (disable-interrupts)))

  (define (@yield-preserving-interrupts queue precedence)
    (disable-interrupts)
    (@yield queue precedence (enable-interrupts))
    (disable-interrupts))

  ;; called with interrupts disabled; disable-count is the current count
  (define (@yield queue precedence disable-count)
    (@event-check)
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
            (queue (@enqueue *self* queue precedence))
            ((enqueued? *self*) (remove-q! *self*))))
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
                              0 #f #f 1 '() '() #f)))
      (hashtable-set! process-table pid-counter p)
      p))

  (define (spawn thunk)
    (no-interrupts
      (let ((p (@make-process (@thunk->cont thunk))))
        (@enqueue p run-queue 0)
        p)))

  (define (spawn&link thunk)
    (no-interrupts
      (let ((p (@make-process (@thunk->cont thunk))))
        (@link p *self*)
        (@enqueue p run-queue 0)
        p)))

  (define (@link p1 p2)
    (unless (memq p2 (pcb-links p1))
      (pcb-links-set! p1 (cons p2 (pcb-links p1)))
      (pcb-links-set! p2 (cons p1 (pcb-links p2)))))

  (define (link p)
    (unless (eq? p *self*)
      (no-interrupts
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
    (no-interrupts
      (if (alive? p)
          (let ((m (make-mon *self* p)))
            (pcb-monitors-set! *self* (cons m (pcb-monitors *self*)))
            (pcb-monitors-set! p (cons m (pcb-monitors p)))
            m)
          (begin
            (@send *self* (vector 'DOWN p (pcb-exit-reason p)))
            #f))))

  (define (demonitor m)
    (when (mon? m)
      (no-interrupts
        (pcb-monitors-set! (mon-origin m)
          (remq m (pcb-monitors (mon-origin m))))
        (pcb-monitors-set! (mon-target m)
          (remq m (pcb-monitors (mon-target m)))))))

  (define (process-trap-exit b)
    (pcb-trap-exit-set! *self* b))

  ;; Terminate a process unconditionally (used by the supervisor to kill
  ;; stuck workers). Killing self never returns.
  (define (kill p reason)
    (if (eq? p *self*)
        (begin
          (disable-interrupts)
          (@kill p reason)
          (yield #f 0))
        (no-interrupts (@kill p reason))))

  ;; interrupts disabled
  (define (@kill p reason)
    (when (alive? p)
      (when (eq? p event-loop-pid)
        (panic 'event-loop-terminated reason))
      (when (enqueued? p) (remove-q! p))
      (pcb-cont-set! p #f)
      (pcb-winders-set! p '())
      (pcb-exception-state-set! p #f)
      (pcb-inbox-set! p #f)
      (pcb-sleeping?-set! p #f)
      (pcb-exit-reason-set! p reason)
      (hashtable-delete! process-table (pcb-id p))
      ;; drop the registered name, if any
      (let ((nm (hashtable-ref pid->name p #f)))
        (when nm
          (hashtable-delete! name->pid nm)
          (hashtable-delete! pid->name p)))
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

  (define (send p m)
    (no-interrupts (@send p m)))

  ;; interrupts disabled
  (define (@send p m)
    (let ((inbox (pcb-inbox p)))
      (when inbox
        (insert-before! (make-msg m) inbox)
        (cond
          ((pcb-sleeping? p)
           (pcb-sleeping?-set! p #f)
           (@enqueue p run-queue 0))
          ((eq? p *self*) (void))       ; running; will see it on next scan
          ((enqueued? p) (void))        ; already runnable
          (else (@enqueue p run-queue 0)))))) ; parked in receive: wake

  ;; Core mailbox scan: scan the inbox against the
  ;; matcher; park (or sleep until waketime) when it runs dry; rescan on
  ;; wake; run the timeout handler once waketime has passed.
  (define ($receive matcher waketime timeout-handler)
    (define (find-prev prev)
      (let ((m (q-next prev)))
        (cond
          ((eq? (pcb-inbox *self*) m)
           ;; inbox exhausted
           (cond
             ((not waketime)
              (@yield-preserving-interrupts #f 0)
              (find-prev prev))
             ((< (now-ms) waketime)
              (pcb-sleeping?-set! *self* #t)
              (@yield-preserving-interrupts sleep-queue waketime)
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
                   (no-interrupts (remove-msg! m))
                   (run))
                 (begin
                   (disable-interrupts)
                   (find-prev m))))))))
    (disable-interrupts)
    (find-prev (pcb-inbox *self*)))

  (define (receive-after matcher timeout timeout-handler)
    (cond
      ((and (integer? timeout) (exact? timeout) (>= timeout 0))
       ($receive matcher (+ (now-ms) timeout) timeout-handler))
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
         (and (identifier? #'after) (eq? (syntax->datum #'after) 'after))
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
      ((queue-empty? sleep-queue) 60000)   ; safety cap; I/O wakes uv_run
      (else
       (min 60000
            (max 0 (- (pcb-precedence (q-next sleep-queue)) (now-ms)))))))

  ;; Runs with interrupts permanently disabled (baseline disable count 1)
  ;; so the preemption timer can never fire inside uv_run or a libuv
  ;; callback frame.
  (define (event-loop)
    (disable-interrupts)
    (let loop ()
      (uv-poll! (system-sleep-time))
      (no-interrupts (@event-check))
      (yield run-queue 0)
      (loop)))

  ;; Boot the world: the calling (OS-level) continuation becomes process
  ;; #1 and parks forever; libuv and the preemption timer are set up; the
  ;; event-loop process and the boot process are spawned. Never returns.
  (define (start-scheduler boot-thunk)
    (uv-init!)
    (uv-set-deliver! send)
    (set! *self* (@make-process #f))
    (timer-interrupt-handler
      (lambda () (yield run-queue 0)))
    (set-timer process-default-ticks)
    (set! event-loop-pid (spawn event-loop))
    (let ((boot-pid (spawn boot-thunk)))
      ;; A boot failure (bind error, bad configuration, missing resource)
      ;; must not leave a healthy event loop running with no application.
      ;; Normal boot completion is expected after setup and is ignored.
      (monitor boot-pid)
      (let forever ()
        (receive (after 3600000 (forever))
          (`#(DOWN ,@boot-pid ,reason)
            (if (eq? reason 'normal)
                (forever)
                (panic 'boot reason)))))))
)
