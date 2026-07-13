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
  (import (chezscheme) (igropyr actor) (igropyr node))

  (define default-await-ms 30000)

  (define ref-counter 0)
  (define (next-ref!)
    (set! ref-counter (+ ref-counter 1))
    ref-counter)

  (define coord-counter 0)
  (define (next-coord-name!)
    (set! coord-counter (+ coord-counter 1))
    (string->symbol (string-append "dpool-coord-" (number->string coord-counter))))

  (define (opt alist key default)
    (let ((p (assq key alist))) (if p (cdr p) default)))

  ;; a wire-safe reason symbol out of whatever was raised
  (define (reason-of e)
    (cond
      ((symbol? e) e)
      ((and (vector? e) (fx> (vector-length e) 0) (symbol? (vector-ref e 0)))
       (vector-ref e 0))
      (else 'crashed)))

  ;; ---- worker side (runs on each member node) ----------------------------

  ;; Register a task runner under name. Each task runs in its own process
  ;; (Let It Crash: a crashing task is isolated and reported, never takes
  ;; the worker down), so one node serves many tasks concurrently.
  (define (dpool-worker-start name handler)
    (register name
      (spawn
        (lambda ()
          (let loop ()
            (receive
              (`#(dtask ,id ,rnode ,rname ,payload)
                (spawn
                  (lambda ()
                    (let ((result
                           (guard (e (#t (vector 'task-error (reason-of e))))
                             (vector 'ok (handler payload)))))
                      ;; reply to the coordinator; if it or the link is
                      ;; gone the result is simply dropped. A result that
                      ;; won't serialize would crash rsend and strand the
                      ;; task -- turn it into a task-error instead.
                      (guard (e (#t (rsend rnode rname
                                      (vector 'dresult id
                                        (vector 'task-error 'not-serializable)))))
                        (rsend rnode rname (vector 'dresult id result))))))
                (loop))))))))

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
             (coord-name (next-coord-name!)))
        (unless (memq default-mode '(at-least-once at-most-once))
          (assertion-violation 'dpool-start "bad mode" default-mode))
        (let ((pid (spawn (lambda ()
                            (coordinator self-node coord-name members worker-name)))))
          ;; register so remote workers can rsend results back by name
          (register coord-name pid)
          (make-dpool pid default-mode)))))

  (define (coordinator self-node coord-name members worker-name)
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
    (define queue '())                         ; #(id payload mode), no live node
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

    (define (dispatch! id payload mode)
      (let ((node (pick-node!)))
        (if (not node)
            (set! queue (append queue (list (vector id payload mode))))
            (begin
              (hashtable-set! inflight id (vector payload node mode))
              (unless (rsend node worker-name
                             (vector 'dtask id self-node coord-name payload))
                ;; the link died between pick and send: drop the node and
                ;; treat this task as hit by a node-down
                (hashtable-delete! inflight id)
                (set! live (remq node live))
                (lost! id payload mode))))))

    ;; a task's node vanished: reassign (at-least-once) or fail it
    (define (lost! id payload mode)
      (if (eq? mode 'at-least-once)
          (dispatch! id payload mode)
          (complete! id (vector 'node-down))))

    (define (complete! id result)
      (hashtable-delete! inflight id)
      (let ((aws (hashtable-ref awaiters id '())))
        (if (pair? aws)
            (begin
              (for-each
                (lambda (a) (send (vector-ref a 0)
                                  (vector 'dpool-result (vector-ref a 1) result)))
                aws)
              (hashtable-delete! awaiters id))
            (stash-result! id result))))

    (define (drain-queue!)
      (let ((q queue))
        (set! queue '())
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
          (let ((id next-id))
            (set! next-id (+ next-id 1))
            (send from (vector 'dpool-submitted ref id))
            (dispatch! id payload mode)))
        (`#(await ,id ,from ,ref)
          (let ((r (hashtable-ref results id #f)))
            (if r
                (begin
                  (hashtable-delete! results id)
                  (send from (vector 'dpool-result ref r)))
                (hashtable-set! awaiters id
                  (cons (vector from ref) (hashtable-ref awaiters id '()))))))
        (`#(dresult ,id ,result)
          ;; a live node finished (ok or task-error): terminal, no retry
          (when (hashtable-ref inflight id #f)
            (complete! id result)))
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
                    (cons 'queued (length queue))))))
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
      (receive (`#(dpool-submitted ,@ref ,id) id))))

  ;; Block for a task's result: the handler's return value, or a raised
  ;; #(dpool-error ,reason ,id) where reason is task-error | node-down |
  ;; await-timeout.
  (define (dpool-await pool id . rest)
    (let ((timeout (if (pair? rest) (car rest) default-await-ms))
          (ref (next-ref!)))
      (send (dpool-pid pool) (vector 'await id self ref))
      (receive (after timeout (raise (vector 'dpool-error 'await-timeout id)))
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
