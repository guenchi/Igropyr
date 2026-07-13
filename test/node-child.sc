#!chezscheme
;;; Helper for test/node.sc: a second OS process acting as node <name>.
;;; Usage: scheme --script node-child.sc <name> <port> <secret>
;;; Dials node 'a on 127.0.0.1:<port>, registers 'svc, and serves:
;;;   #(add1 ,x ,payload)  -> (rsend 'a 'main #(ans ,(+ x 1) ,payload))
;;;   #(quit)              -> exits (dropping the link -> node-down on a)
;;; Exits by itself after 30s as a safety net.

(import (chezscheme) (igropyr actor) (igropyr node))

(define args (cdr (command-line)))
(define name (string->symbol (car args)))
(define port (string->number (cadr args)))
(define secret (caddr args))

(start-scheduler
  (lambda ()
    (node-start! name secret)
    (node-connect! 'a "127.0.0.1" port)
    (register 'svc self)
    (spawn (lambda () (sleep-ms 30000) (exit 1)))   ; safety net
    (let loop ()
      (receive
        (`#(add1 ,x ,payload)
          (rsend 'a 'main (vector 'ans (+ x 1) payload))
          (loop))
        (`#(quit) (exit 0))))))
