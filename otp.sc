#!chezscheme
;;; (igropyr otp) -- worker pool with Let-It-Crash fault tolerance.
;;;
;;; A fixed pool of worker processes executes tasks handed in by reader
;;; processes. The supervisor monitors every worker:
;;;   - crash: replacement worker is spawned; the task is retried at most
;;;     max-retries times (default 3, so 4 executions total), then
;;;     fail-task runs (HTTP 500) and the task is dropped;
;;;   - stuck > stuck-ms (default 30s, detected by a check-ms ticker,
;;;     default 5s): the worker is killed and replaced; the task is NOT
;;;     retried (retrying an infinite loop would re-stick the pool) and
;;;     fail-task runs.
;;;
;;; All coordination is message passing; the supervisor's bookkeeping
;;; tables are private to its process. Protocol (from 需求.md):
;;;   reader -> supervisor: #(submit-task ,task)
;;;   supervisor -> worker: #(process-task ,task)
;;;   worker -> supervisor: #(task-completed ,task-id ,self)
;;;   ticker -> supervisor: #(check-stuck-workers)   (every 5s)
;;;   crashes arrive as #(DOWN ,pid ,reason) via monitor
;;; Task shape (built by the http layer): #(task ,task-id ,conn ,request)
;;;
;;; ---- Design model ----------------------------------------------------
;;;
;;; Four commitments shape the concurrency and distribution layers. They
;;; are deliberate: a review comparing this library to Erlang/OTP or Swish
;;; will find several OTP mechanisms missing -- a supervision tree above
;;; all -- and each absence traces to one of these. Two of them are this
;;; file's own, and are given in full; the other two live in (igropyr node)
;;; and are summarised here.
;;;
;;; 1. CRASH-ONLY, WITH THE REAL SUPERVISOR OUTSIDE THE PROCESS. Inside the
;;;    process: let-it-crash workers, resource reclamation through owner
;;;    monitors, task-level retry that knows its side effects -- all three
;;;    are above. At the process level: die loudly and let the service
;;;    manager (rc.d, daemon -r, systemd) restart the whole image. Recovery
;;;    means rebuilding from durable state, not surgically restarting a
;;;    subtree in place -- so there is no in-process supervision tree, and
;;;    its absence is a decision, not a gap.
;;;
;;; 2. A SINGLE SCHEDULER MEANS AN IN-PROCESS SUPERVISION TREE COULD NOT
;;;    HELP WITH THE HARDEST FAILURES ANYWAY. A supervisor process shares
;;;    the scheduler with everything it supervises: when the scheduler
;;;    itself stalls -- a foreign call that never returns -- the tree
;;;    stalls with it. The only supervisor that survives that failure class
;;;    lives outside the process, and it is already there. Note what this
;;;    does NOT say: the pool supervisor above is worth having, because the
;;;    failures it handles are worker crashes and stuck tasks, which do not
;;;    stop the scheduler. The claim is about what a TREE would add.
;;;
;;; 3 and 4, in one line each: the node mesh is a control plane -- names
;;; not pids, small messages, fail-closed on confusion, slow-is-dead rather
;;; than paused; and that mesh is small and fully trusted by design, a
;;; cluster administered as one unit and upgraded in lockstep. See
;;; (igropyr node) for both in full.

(library (igropyr otp)
  (export start-worker-pool pool-stats)
  (import (chezscheme) (igropyr actor) (igropyr libuv))

  (define default-max-retries 3)
  (define default-stuck-ms 30000)
  (define default-check-ms 5000)

  (define (task-id-of task) (vector-ref task 1))

  ;; run-task: (lambda (task) ...) executed inside a worker; may crash.
  ;; fail-task: (lambda (task info) ...) executed by the supervisor when
  ;; a task is given up on; must not block (writing a response or
  ;; requeueing an urgent task is fine). info is an alist:
  ;;   ((kind . crash|stuck) (reason . <exit reason>)
  ;;    (attempts . <executions>) (elapsed-ms . <last run's duration>))
  ;; Optional trailing args: max-retries stuck-ms check-ms retryable?.
  ;;
  ;; retryable? -- (task) -> boolean, default: everything is retryable.
  ;; A crashed task is re-run only if this says so. Retrying assumes the
  ;; task left no effect the world can already see; when it did, re-running
  ;; repeats that effect. This pool cannot judge it -- what counts as a
  ;; visible effect belongs to whoever defined the task -- so the question
  ;; is asked rather than guessed. The HTTP layer answers it by checking
  ;; whether the response token has been claimed.
  ;; Returns the supervisor pid; send it #(submit-task ,task).
  ;; Every one of these fails SILENTLY when it is out of range, which is
  ;; why they are checked at startup rather than trusted. n = 0 starts a
  ;; listener that accepts requests and queues them forever; a negative
  ;; check-ms kills the ticker at once, so stuck-worker detection simply
  ;; disappears while the pool goes on looking healthy; check-ms = 0 spins.
  ;; None of them announces itself, so a misconfiguration surfaces much
  ;; later as "the service stopped responding" with nothing to point at.
  (define (check-pos who what v)
    (unless (and (integer? v) (exact? v) (> v 0))
      (assertion-violation who
        (string-append what " must be a positive exact integer") v)))
  (define (check-nonneg who what v)
    (unless (and (integer? v) (exact? v) (>= v 0))
      (assertion-violation who
        (string-append what " must be a nonnegative exact integer") v)))

  (define (start-worker-pool n run-task fail-task . opts)
    (let* ((max-retries (if (>= (length opts) 1) (car opts) default-max-retries))
           (stuck-ms (if (>= (length opts) 2) (cadr opts) default-stuck-ms))
           (check-ms (if (>= (length opts) 3) (caddr opts) default-check-ms))
           (retryable? (if (>= (length opts) 4) (list-ref opts 3) (lambda (t) #t))))
      (check-pos 'start-worker-pool "workers" n)
      ;; 0 retries is meaningful (run once, never retry); negative is not
      (check-nonneg 'start-worker-pool "max-retries" max-retries)
      (check-pos 'start-worker-pool "stuck-ms" stuck-ms)
      (check-pos 'start-worker-pool "check-ms" check-ms)
      (unless (procedure? retryable?)
        (assertion-violation 'start-worker-pool
          "retryable? must be a procedure of one argument" retryable?))
      (let ((sup (spawn (lambda ()
                          (supervisor n run-task fail-task
                                      max-retries stuck-ms retryable?)))))
        (spawn (lambda () (ticker sup check-ms)))
        sup)))

  (define (ticker sup interval-ms)
    (sleep-ms interval-ms)
    (send sup (vector 'check-stuck-workers))
    (ticker sup interval-ms))

  (define (worker sup run-task)
    (lambda ()
      (let loop ()
        (receive
          (`#(process-task ,task)
            (run-task task)
            (send sup (vector 'task-completed (task-id-of task) self))
            (loop))))))

  (define (supervisor n run-task fail-task max-retries stuck-ms retryable?)
    (define idle '())
    (define busy (make-eq-hashtable))      ; worker pid -> (task . start-ms)
    (define stuck (make-eq-hashtable))     ; worker pid -> #t (kill in flight)
    (define attempts (make-eqv-hashtable)) ; task-id -> crash count
    ;; simple FIFO with O(1) amortized push/pop; retries jump the queue
    (define pending-front '())
    (define pending-back '())

    (define (pending?) (or (pair? pending-front) (pair? pending-back)))
    (define (push-pending! t) (set! pending-back (cons t pending-back)))
    (define (push-front! t) (set! pending-front (cons t pending-front)))
    (define (pop-pending!)
      (when (null? pending-front)
        (set! pending-front (reverse pending-back))
        (set! pending-back '()))
      (let ((t (car pending-front)))
        (set! pending-front (cdr pending-front))
        t))

    (define (spawn-worker!)
      (let ((w (spawn (worker self run-task))))
        (monitor w)
        (set! idle (cons w idle))))

    (define (dispatch! task)
      (if (null? idle)
          (push-pending! task)
          (let ((w (car idle)))
            (set! idle (cdr idle))
            (hashtable-set! busy w (cons task (now-ms)))
            (send w (vector 'process-task task)))))

    (define (drain!)
      (let loop ()
        (when (and (pair? idle) (pending?))
          (dispatch! (pop-pending!))
          (loop))))

    (define (give-up! task info)
      (hashtable-delete! attempts (task-id-of task))
      ;; never let a bad fail-task take the supervisor down
      (guard (e (#t (void)))
        (fail-task task info)))

    (define (fail-info kind reason id elapsed)
      (list (cons 'kind kind)
            (cons 'reason reason)
            (cons 'id id)
            (cons 'attempts (+ 1 (hashtable-ref attempts id 0)))
            (cons 'elapsed-ms elapsed)))

    (define (handle-down w reason)
      (set! idle (remq w idle))
      (let ((entry (hashtable-ref busy w #f))
            (was-stuck? (hashtable-ref stuck w #f)))
        (hashtable-delete! busy w)
        (hashtable-delete! stuck w)
        (spawn-worker!)                    ; keep the pool at n workers
        (when entry
          (let* ((task (car entry))
                 (id (task-id-of task))
                 (elapsed (- (now-ms) (cdr entry))))
            (if was-stuck?
                ;; no retry for stuck tasks; the worker is already dead,
                ;; so the failure report describes a settled state
                (give-up! task (fail-info 'stuck reason id elapsed))
                ;; A task that already produced a visible effect is NOT
                ;; re-run, however many attempts remain: the crash happened
                ;; after the effect, so retrying repeats it rather than
                ;; retrying it. Report the failure instead, which is what
                ;; the caller of a settled task can still act on.
                ;; The predicate is APPLICATION code, called from the
                ;; supervisor's own DOWN path. An exception from it used to
                ;; take the supervisor down with it -- and the supervisor is
                ;; the one process whose death orphans every worker and the
                ;; ticker. A raise is read as "not retryable": the task has
                ;; already crashed once, and a predicate that cannot answer
                ;; is not a reason to run it again.
                (if (not (guard (e (#t #f)) (and (retryable? task) #t)))
                    (give-up! task (fail-info 'crash reason id elapsed))
                    (let ((a (+ 1 (hashtable-ref attempts id 0))))
                      (if (> a max-retries)
                          (give-up! task (fail-info 'crash reason id elapsed))
                          (begin
                            (hashtable-set! attempts id a)
                            (if (null? idle)
                                (push-front! task)
                                (dispatch! task)))))))))))

    (define (check-stuck!)
      (let ((now (now-ms)))
        (let-values (((ws entries) (hashtable-entries busy)))
          (vector-for-each
            (lambda (w entry)
              (when (and (> (- now (cdr entry)) stuck-ms)
                         (not (hashtable-ref stuck w #f)))
                (hashtable-set! stuck w #t)
                (kill w 'stuck-killed)))   ; DOWN follows; handled above
            ws entries))))

    ;; init: fill the pool, then serve messages forever
    (do ((i 0 (+ i 1))) ((= i n)) (spawn-worker!))
    (let loop ()
      (receive
        (`#(submit-task ,task) (dispatch! task))
        ;; latency-sensitive tasks (e.g. failure notifications) jump the
        ;; queue instead of waiting behind the regular backlog
        (`#(submit-urgent ,task)
          (if (null? idle)
              (push-front! task)
              (dispatch! task)))
        (`#(task-completed ,task-id ,w)
          (when (hashtable-ref busy w #f)
            (hashtable-delete! busy w)
            (hashtable-delete! attempts task-id)
            ;; A worker can finish just as check-stuck! kills it, so this
            ;; completion may arrive from an already-dead worker (its
            ;; DOWN is still queued behind us). Returning it to the idle
            ;; list would dispatch the next task into a dead mailbox --
            ;; silently lost, and then failed as 'stuck when the DOWN
            ;; lands, blaming a task that never ran.
            (unless (hashtable-ref stuck w #f)
              (set! idle (cons w idle))))
          (drain!))
        (`#(check-stuck-workers) (check-stuck!))
        (`#(get-stats ,from ,ref)
          (send from
            (vector 'pool-stats ref
              (list (cons 'idle (length idle))
                    (cons 'busy (hashtable-size busy))
                    (cons 'pending (+ (length pending-front)
                                      (length pending-back)))))))
        (`#(DOWN ,w ,reason)
          (handle-down w reason)
          (drain!)))
      (loop)))

  ;; synchronous stats snapshot from the supervisor
  (define stats-ref 0)
  (define (pool-stats sup)
    ;; drain the late answer to any previously timed-out call: its ref
    ;; can never match again, so it would sit in this mailbox forever
    (let drain ()
      (receive (after 0 'done) (`#(pool-stats ,r ,s) (drain))))
    (let ((ref (with-interrupts-disabled      ; shared counter, see gen-server
                 (set! stats-ref (+ stats-ref 1))
                 stats-ref)))
      (send sup (vector 'get-stats self ref))
      (receive (after 5000 (raise 'pool-stats-timeout))
        (`#(pool-stats ,@ref ,s) s))))
)
