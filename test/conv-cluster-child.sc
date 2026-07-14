#!chezscheme
;;; Helper for test/conv-cluster.sc: the OWNER node <name> (b).
;;; Usage: scheme --script conv-cluster-child.sc <name> <port> <secret>
;;;
;;; Dials node 'a, waits for the link, then starts a conversation HERE
;;; (so this node owns its continuation) and ships the id + first reply
;;; back to node a. The flow accumulates each resumed number and answers
;;; #(ack sum); #(done) ends it with #(final sum). Node a resumes over
;;; the mesh, exercising the owner-forwarding path.

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation))

(define args (cdr (command-line)))
(define name (string->symbol (car args)))
(define port (string->number (cadr args)))
(define secret (caddr args))

(start-scheduler
  (lambda ()
    (node-start! name secret)
    (node-connect! 'a "127.0.0.1" port)
    (register 'ctrl self)
    (spawn (lambda () (sleep-ms 30000) (exit 1)))   ; safety net

    (monitor-node 'a)
    (receive (after 10000 (exit 2)) (`#(node-up a) 'ok))

    ;; start the conversation in its own process; report id + first reply
    (spawn
      (lambda ()
        (call-with-values
          (lambda ()
            (conversation-start!
              (lambda (req suspend!)
                (let loop ((sum 0) (r req))
                  (if (eq? r 'done)
                      (vector 'final sum)
                      (loop (+ sum r) (suspend! (vector 'ack (+ sum r)))))))
              0))
          (lambda (id first-reply)
            (rsend 'a 'main (vector 'conv-id id first-reply))))))

    (let loop ()
      (receive
        (`#(quit) (exit 0))
        (,_ (loop))))))
