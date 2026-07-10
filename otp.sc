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

(library (igropyr otp)
  (export start-worker-pool pool-stats)
  (import (chezscheme) (igropyr actor) (igropyr uv))

  (define default-max-retries 3)
  (define default-stuck-ms 30000)
  (define default-check-ms 5000)

  (define (task-id-of task) (vector-ref task 1))

  ;; run-task: (lambda (task) ...) executed inside a worker; may crash.
  ;; fail-task: (lambda (task) ...) executed by the supervisor when a
  ;; task is given up on; must not block (writing a 500 is fine).
  ;; Optional trailing args: max-retries stuck-ms check-ms.
  ;; Returns the supervisor pid; send it #(submit-task ,task).
  (define (start-worker-pool n run-task fail-task . opts)
    (when (> (length opts) 3)
      (assertion-violation 'start-worker-pool
        "expected at most max-retries, stuck-ms and check-ms" opts))
    (let* ((max-retries (if (>= (length opts) 1) (car opts) default-max-retries))
           (stuck-ms (if (>= (length opts) 2) (cadr opts) default-stuck-ms))
           (check-ms (if (>= (length opts) 3) (caddr opts) default-check-ms)))
      (unless (and (integer? n) (exact? n) (> n 0))
        (assertion-violation 'start-worker-pool
          "worker count must be a positive exact integer" n))
      (unless (procedure? run-task)
        (assertion-violation 'start-worker-pool
          "run-task must be a procedure" run-task))
      (unless (procedure? fail-task)
        (assertion-violation 'start-worker-pool
          "fail-task must be a procedure" fail-task))
      (unless (and (integer? max-retries) (exact? max-retries)
                   (>= max-retries 0))
        (assertion-violation 'start-worker-pool
          "max-retries must be a non-negative exact integer" max-retries))
      (unless (and (integer? stuck-ms) (exact? stuck-ms) (> stuck-ms 0))
        (assertion-violation 'start-worker-pool
          "stuck-ms must be a positive exact integer" stuck-ms))
      (unless (and (integer? check-ms) (exact? check-ms) (> check-ms 0))
        (assertion-violation 'start-worker-pool
          "check-ms must be a positive exact integer" check-ms))
      (let ((sup (spawn (lambda ()
                          (supervisor n run-task fail-task
                                      max-retries stuck-ms)))))
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

  (define (supervisor n run-task fail-task max-retries stuck-ms)
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

    (define (give-up! task)
      (hashtable-delete! attempts (task-id-of task))
      ;; never let a bad fail-task take the supervisor down
      (guard (e (#t (void)))
        (fail-task task)))

    (define (handle-down w reason)
      (set! idle (remq w idle))
      (let ((entry (hashtable-ref busy w #f))
            (was-stuck? (hashtable-ref stuck w #f)))
        (hashtable-delete! busy w)
        (hashtable-delete! stuck w)
        (spawn-worker!)                    ; keep the pool at n workers
        (when entry
          (let* ((task (car entry))
                 (id (task-id-of task)))
            (if was-stuck?
                (give-up! task)            ; no retry for stuck tasks
                (let ((a (+ 1 (hashtable-ref attempts id 0))))
                  (if (> a max-retries)
                      (give-up! task)
                      (begin
                        (hashtable-set! attempts id a)
                        (if (null? idle)
                            (push-front! task)
                            (dispatch! task))))))))))

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
        (`#(task-completed ,task-id ,w)
          (when (hashtable-ref busy w #f)
            (hashtable-delete! busy w)
            (hashtable-delete! attempts task-id)
            (set! idle (cons w idle)))
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
    (set! stats-ref (+ stats-ref 1))
    (let ((ref stats-ref))
      (send sup (vector 'get-stats self ref))
      (receive (after 5000 (raise 'pool-stats-timeout))
        (`#(pool-stats ,@ref ,s) s))))
)
