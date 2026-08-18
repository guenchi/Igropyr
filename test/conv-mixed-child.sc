#!chezscheme
;;; Helper for test/conv-mixed.sc: node b, run against an OLD checkout of
;;; this library (the parent of the wide-reply release) while node a runs
;;; the current one. This file lives in the CURRENT tree and is executed
;;; with CHEZSCHEMELIBDIRS pointing at the old one, so it may use only
;;; API that existed there: node-start!/connect!, conversation-start!/
;;; resume!, rsend, monitor-node.
;;;
;;; Two roles, one per mixed direction:
;;;   1. it OWNS a conversation and reports the id -- node a (new asker)
;;;      resumes and peeks it over the mesh, exercising new-asker ->
;;;      old-owner: the old router echoes the negative ref it cannot
;;;      interpret and answers the narrow shape;
;;;   2. it ASKS: node a sends #(ask <id> <n>), this node resumes a's own
;;;      conversation with n, exercising old-asker -> new-owner: a
;;;      positive ref reaches the new router, which must answer narrow.
;;; Usage: scheme --script conv-mixed-child.sc <port> <secret>

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation))

(define args (cdr (command-line)))
(define port (string->number (car args)))
(define secret (cadr args))

(start-scheduler
  (lambda ()
    (node-start! 'b secret)
    (node-connect! 'a "127.0.0.1" port)
    (register 'ctrl self)
    ;; hung-child net: sized for the run node a performs; firing it is
    ;; never good news
    (spawn (lambda () (receive (after 60000 (exit 1)))))
    (monitor-node 'a)
    (receive (after 10000 (exit 2)) (`#(node-up a) 'ok))

    ;; role 1: own a summing conversation, report id + token home
    (spawn
      (lambda ()
        (call-with-values
          (lambda ()
            (conversation-start!
              (lambda (req suspend! commit!)
                (let loop ((sum 0) (r req))
                  (if (eq? r 'done)
                      (begin (commit! (lambda () 'ok)) (vector 'final sum))
                      (loop (+ sum r)
                            (suspend! (vector 'ack (+ sum r)))))))
              5))
          (lambda (id token reply)
            (rsend 'a 'mixed (vector 'owned id token reply))))))

    ;; role 2: resume whatever id node a hands over, report the outcome
    (let loop ()
      (receive
        (`#(ask ,id ,token ,n)
          (let ((r (guard (e (#t (vector 'asked 'raised)))
                     (call-with-values
                       (lambda () (conversation-resume! id token n))
                       (lambda (reply status)
                         (vector 'asked reply status))))))
            (rsend 'a 'mixed r))
          (loop))
        (`#(quit) (exit 0))
        (`#(node-down a) (exit 0))))))
