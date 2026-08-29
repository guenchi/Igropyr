#!chezscheme
;;; (igropyr dpool) integration test: coordinator on node a, workers on
;;; two child OS processes (nodes b and c).
;;;   - fan-out: a burst of tasks spreads across both member nodes
;;;   - correctness: every result is the handler's value
;;;   - at-least-once: a node killed mid-task -> the task reruns elsewhere
;;;     and still completes
;;;   - at-most-once: a node killed mid-task -> dpool-await raises node-down
;;;   - task-error: a crashing handler raises task-error, never retried

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr dpool))

;; The run may be using `chez` or $SCHEME_BIN rather than `scheme`, and a
;; child started with the wrong name simply never appears -- which this
;; suite would report as whatever it was waiting for timing out, not as a
;; missing interpreter. run-all.sh exports the name it chose.
(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))



(define port 18092)
(define secret "dpool-secret")

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

(define (spawn-child! name)
  (system (string-append
            scheme-bin " --script igropyr/test/dpool-child.sc "
            name " " (number->string port) " " secret " &")))

(define (await-node-up! who)
  (monitor-node who)
  (unless (memq who (node-peers))
    (receive (after 10000 (fail! "node-up-timeout" who))
      (`#(node-up ,@who) 'ok))))

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)

    (spawn-child! "b")
    (spawn-child! "c")
    (await-node-up! 'b)
    (await-node-up! 'c)
    (display "two worker nodes up\n")

    (let ((pool (dpool-start '(b c) 'render)))    ; at-least-once default

      ;; fan-out: 40 tasks, results correct, and BOTH nodes get work
      (let* ((ids (map (lambda (i) (cons i (dpool-submit pool (vector 'square i))))
                       (iota 40)))
             (seen (make-eq-hashtable)))
        (for-each
          (lambda (p)
            (let ((r (dpool-await pool (cdr p) 10000)))
              ;; r is #(from <node> <value>)
              (unless (and (vector? r) (eq? (vector-ref r 0) 'from)
                           (= (vector-ref r 2) (* (car p) (car p))))
                (fail! "fanout-value" (car p) r))
              (hashtable-set! seen (vector-ref r 1) #t)))
          ids)
        (unless (and (hashtable-ref seen 'b #f) (hashtable-ref seen 'c #f))
          (fail! "fanout-spread" (vector->list (hashtable-keys seen)))))
      (display "fan-out across both nodes + correctness ok\n")

      ;; at-least-once: start a slow task, kill the node running it, the
      ;; task must reappear on the surviving node and still return
      (let ((t (dpool-submit pool (vector 'slow 777 4000))))
        (sleep-ms 500)                    ; let it land on some node
        ;; kill whichever node is busy by asking both to die if slow --
        ;; simplest: kill b; if the task was on c it finishes anyway, if
        ;; on b it must reassign to c
        (rsend 'b 'render                 ; deliver #(die) straight to worker
          (vector 'dtask -1 'a 'ignore (vector 'die) 0))   ; 0 = dummy token
        (let ((r (dpool-await pool t 15000)))
          (unless (and (vector? r) (= (vector-ref r 2) 777))
            (fail! "at-least-once-value" r))
          ;; it must have completed on a LIVE node (c, since b died)
          (unless (eq? (vector-ref r 1) 'c)
            (fail! "at-least-once-node" r))))
      (display "at-least-once reassign on node-down ok\n")

      ;; bring b back for the next checks
      (spawn-child! "b")
      (await-node-up! 'b)

      ;; task-error: a crashing handler -> dpool-error task-error, no retry
      (let ((t (dpool-submit pool (vector 'boom))))
        (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'dpool-error))
                              (vector-ref e 1)))
                     (dpool-await pool t 10000)
                     'no-raise)))
          (unless (eq? got 'task-error) (fail! "task-error" got))))
      (display "handler crash -> task-error (no retry) ok\n")

      ;; A payload the wire refuses must FAIL the task, not strand it.
      ;; The coordinator's dispatch wraps its send in a guard whose
      ;; 'unsendable arm answers the awaiter through the task-error
      ;; path; this cell pins that arm alive. The red shapes it owns:
      ;; a coordinator that dies on the raise (every later await hangs
      ;; on a dead process), and an arm that never fires (this await
      ;; burns its whole timeout against a task nobody will answer).
      ;; The prompt bound is the assertion: an ANSWER within the window,
      ;; not a timeout spent.
      (let ((t (dpool-submit pool (vector 'x car))))
        (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'dpool-error))
                              (vector-ref e 1)))
                     (dpool-await pool t 5000)
                     'no-raise)))
          (unless (eq? got 'task-error) (fail! "unsendable-payload" got))))
      ;; ...and the refusal cost one task, not the pool: the next
      ;; ordinary submit still completes
      (let ((t (dpool-submit pool (vector 'square 6))))
        (let ((r (dpool-await pool t 10000)))
          (unless (and (vector? r) (= (vector-ref r 2) 36))
            (fail! "pool-dead-after-unsendable" r))))
      (display "unsendable payload fails one task, pool survives ok\n")

      ;; a non-serializable result must not strand the task: the worker
      ;; turns it into a task-error instead of crashing on the reply
      (let ((t (dpool-submit pool (vector 'unserializable))))
        (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'dpool-error))
                              (vector-ref e 1)))
                     (dpool-await pool t 10000)
                     'no-raise)))
          (unless (eq? got 'task-error) (fail! "unserializable-result" got))))
      (display "non-serializable result -> task-error (not stranded) ok\n")

      ;; at-most-once: kill the node mid-task -> node-down, never re-run
      (let ((t (dpool-submit pool (vector 'slow 999 4000)
                             '((mode . at-most-once)))))
        (sleep-ms 500)
        (rsend 'b 'render (vector 'dtask -1 'a 'ignore (vector 'die) 0))
        (rsend 'c 'render (vector 'dtask -1 'a 'ignore (vector 'die) 0))
        (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'dpool-error))
                              (vector-ref e 1)))
                     (dpool-await pool t 15000)
                     'no-raise)))
          (unless (eq? got 'node-down) (fail! "at-most-once" got))))
      (display "at-most-once fail on node-down ok\n"))

    (display "ALL DPOOL TESTS PASSED\n")
    (exit 0)))
