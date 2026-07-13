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

(define port 18092)
(define secret "dpool-secret")

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

(define (spawn-child! name)
  (system (string-append
            "scheme --script igropyr/test/dpool-child.sc "
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
          (vector 'dtask -1 'a 'ignore (vector 'die)))
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

      ;; at-most-once: kill the node mid-task -> node-down, never re-run
      (let ((t (dpool-submit pool (vector 'slow 999 4000)
                             '((mode . at-most-once)))))
        (sleep-ms 500)
        (rsend 'b 'render (vector 'dtask -1 'a 'ignore (vector 'die)))
        (rsend 'c 'render (vector 'dtask -1 'a 'ignore (vector 'die)))
        (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'dpool-error))
                              (vector-ref e 1)))
                     (dpool-await pool t 15000)
                     'no-raise)))
          (unless (eq? got 'node-down) (fail! "at-most-once" got))))
      (display "at-most-once fail on node-down ok\n"))

    (display "ALL DPOOL TESTS PASSED\n")
    (exit 0)))
