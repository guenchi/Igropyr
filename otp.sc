#!chezscheme
;;; (igropyr otp) -- worker pool with Let-It-Crash fault tolerance.
;;;
;;; A fixed pool of worker processes executes tasks handed in by reader
;;; processes. The supervisor monitors every worker:
;;;   - crash: replacement worker is spawned; the task is retried at most
;;;     3 times (4 executions total), then fail-task runs (HTTP 500) and
;;;     the task is dropped;
;;;   - stuck > 30s (detected by a 5s ticker): the worker is killed and
;;;     replaced; the task is NOT retried (retrying an infinite loop
;;;     would re-stick the pool) and fail-task runs.
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
  (export start-worker-pool)
  (import (chezscheme) (igropyr actor) (igropyr uv))

  (define stuck-threshold-ms 30000)
  (define check-interval-ms 5000)
  (define max-retries 3)

  (define (task-id-of task) (vector-ref task 1))

  ;; run-task: (lambda (task) ...) executed inside a worker; may crash.
  ;; fail-task: (lambda (task) ...) executed by the supervisor when a
  ;; task is given up on; must not block (writing a 500 is fine).
  ;; Returns the supervisor pid; send it #(submit-task ,task).
  (define (start-worker-pool n run-task fail-task)
    (let ((sup (spawn (lambda () (supervisor n run-task fail-task)))))
      (spawn (lambda () (ticker sup)))
      sup))

  (define (ticker sup)
    (sleep-ms check-interval-ms)
    (send sup (vector 'check-stuck-workers))
    (ticker sup))

  (define (worker sup run-task)
    (lambda ()
      (let loop ()
        (receive
          (`#(process-task ,task)
            (run-task task)
            (send sup (vector 'task-completed (task-id-of task) self))
            (loop))))))

  (define (supervisor n run-task fail-task)
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
              (when (and (> (- now (cdr entry)) stuck-threshold-ms)
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
        (`#(DOWN ,w ,reason)
          (handle-down w reason)
          (drain!)))
      (loop)))
)
