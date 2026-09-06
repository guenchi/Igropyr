#!chezscheme
;;; tls-node-child.sc -- a TLS node in its own process, for test/tls-mesh-pair.sc.
;;; usage: NAME PORT SECRET CERT KEY [LIFETIME-MS]
;;; It listens with TLS, never dials, registers 'ping, answers #(ping from)
;;; with #(pong NAME) to the sender's node, and exits after LIFETIME-MS.
(import (chezscheme) (igropyr actor) (igropyr node))
(define args (cdr (command-line)))
(define name (string->symbol (list-ref args 0)))
(define port (string->number (list-ref args 1)))
(define secret (list-ref args 2))
(define cert (list-ref args 3))
(define key (list-ref args 4))
(define lifetime-ms (if (> (length args) 5) (string->number (list-ref args 5)) 60000))
(start-scheduler
  (lambda ()
    (node-start! name secret port "127.0.0.1" (list (cons 'tls-cert cert) (cons 'tls-key key)))
    (node-set-limits! 64 2)
    (register 'ping
      (spawn (lambda ()
               (let loop ()
                 (receive
                   (`#(ping ,from) (rsend from 'main (vector 'pong name)) (loop))
                   (`#(peers? ,from) (rsend from 'main (vector 'peers name (node-peers))) (loop)))))))
    (sleep-ms lifetime-ms)
    (exit 0)))
