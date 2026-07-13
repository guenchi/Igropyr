#!chezscheme
;;; Helper for test/dpool.sc: a member node running a dpool worker.
;;; Usage: scheme --script dpool-child.sc <name> <port> <secret>
;;; The 'render worker:
;;;   #(square ,n)        -> n*n
;;;   #(slow ,n ,ms)      -> sleep ms, then n (so the parent can kill the
;;;                          node mid-task to test reassignment)
;;;   #(die)              -> the whole node exits (drops the link)
;;;   #(boom)             -> the task handler crashes (task-error, no retry)
;;; The node also tags results with its own name so the test can see WHERE
;;; a task ran: a successful reply is #(from <node> <value>).

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr dpool))

(define args (cdr (command-line)))
(define name (string->symbol (car args)))
(define port (string->number (cadr args)))
(define secret (caddr args))

(start-scheduler
  (lambda ()
    (node-start! name secret)
    (node-connect! 'a "127.0.0.1" port)
    (spawn (lambda () (sleep-ms 30000) (exit 1)))   ; safety net
    (dpool-worker-start 'render
      (lambda (job)
        (case (vector-ref job 0)
          ((square) (vector 'from name (* (vector-ref job 1) (vector-ref job 1))))
          ((slow)
           (sleep-ms (vector-ref job 2))
           (vector 'from name (vector-ref job 1)))
          ((die) (exit 0))
          ((boom) (raise 'handler-blew-up))
          (else (vector 'from name 'unknown)))))
    ;; park forever serving the worker
    (let loop () (receive (,_ (loop))))))
