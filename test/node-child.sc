#!chezscheme
;;; Helper for test/node.sc: a second OS process acting as node <name>.
;;; Usage: scheme --script node-child.sc <name> <port> <secret>
;;; Dials node 'a on 127.0.0.1:<port>, then:
;;;   - registers 'svc: #(add1 ,x ,p) -> (rsend 'a 'main #(ans ,(+ x 1) ,p))
;;;     and #(quit) -> exit (drops the link -> node-down on a)
;;;   - registers a gen-server 'calc for rcall: #(square ,n) -> n*n,
;;;     #(boom) -> raises (so the caller sees an rcall-error)
;;;   - starts pubsub, subscribes to 'room, relays #(pub room ,m) to
;;;     node a's 'main as #(heard ,m)
;;; Exits by itself after 30s as a safety net.

(import (chezscheme) (igropyr actor) (igropyr node)
        (igropyr gen-server) (igropyr pubsub))

(define args (cdr (command-line)))
(define name (string->symbol (car args)))
(define port (string->number (cadr args)))
(define secret (caddr args))

(start-scheduler
  (lambda ()
    (node-start! name secret)
    (node-connect! 'a "127.0.0.1" port)
    (start-pubsub!)
    (register 'svc self)

    ;; a gen-server target for rcall
    (gen-server-start-named 'calc
      (lambda () 0)
      (lambda (msg from state)
        (case (vector-ref msg 0)
          ((square) (let ((n (vector-ref msg 1))) (values (* n n) state)))
          ((boom) (raise 'kaboom))
          (else (values 'bad state))))
      (lambda (msg state) state))

    ;; relay room traffic back to node a so the test can observe fan-out
    (spawn (lambda ()
             (subscribe 'room)
             (let loop ()
               (receive (`#(pub room ,m)
                          (rsend 'a 'main (vector 'heard m)) (loop))))))

    (spawn (lambda () (sleep-ms 30000) (exit 1)))   ; safety net
    (let loop ()
      (receive
        (`#(add1 ,x ,payload)
          (rsend 'a 'main (vector 'ans (+ x 1) payload))
          (loop))
        (`#(quit) (exit 0))))))
