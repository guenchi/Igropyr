#!chezscheme
;;; Helper for test/cluster.sc: a node that joins the mesh via a
;;; discovery strategy -- it never calls node-connect! itself.
;;; Usage: scheme --script cluster-child.sc <name> <my-port> <secret> <strategy> <a-port>
;;;   strategy = static  -> discover node a by a fixed list
;;;            = redis   -> discover peers via Redis (needs a server)
;;;            = gossip  -> node a is the ONLY seed; every other member
;;;                         must be learned transitively through gossip
;;; Registers 'ping so the parent can confirm the link both ways and
;;; query this node's own peer list (the transitive-mesh assertion).

(import (chezscheme) (igropyr actor) (igropyr node)
        (igropyr redis) (igropyr cluster))

(define args (cdr (command-line)))
(define name (string->symbol (list-ref args 0)))
(define my-port (string->number (list-ref args 1)))
(define secret (list-ref args 2))
(define strategy (list-ref args 3))
(define a-port (string->number (list-ref args 4)))

(start-scheduler
  (lambda ()
    (node-start! name secret my-port "127.0.0.1")
    (cluster-start
      (cond
        ((string=? strategy "redis")
         `((name . "test-cluster")
           (interval-ms . 1000)
           (ttl-ms . 5000)
           (discover . (redis ,(redis-connect "127.0.0.1" 6379)
                              "127.0.0.1" ,my-port))))
        ((string=? strategy "gossip")
         `((name . "gossip-cluster")
           (interval-ms . 400)
           (ttl-ms . 2000)
           (discover . (gossip (advertise "127.0.0.1" ,my-port)
                               (seeds (a "127.0.0.1" ,a-port))))))
        (else
         `((interval-ms . 1000)
           (discover . (static (a "127.0.0.1" ,a-port)))))))
    (register 'ping
      (spawn (lambda ()
               (let loop ()
                 (receive
                   (`#(ping ,from)
                     (rsend from 'main (vector 'pong name)) (loop))
                   (`#(peers? ,from)
                     (rsend from 'main (vector 'peers name (node-peers)))
                     (loop)))))))
    (let loop () (receive (`#(quit) (exit 0)) (,_ (loop))))))
