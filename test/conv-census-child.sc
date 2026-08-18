#!chezscheme
;;; Helper for test/conv-census.sc: node b. Two jobs the parent cannot do
;;; from inside node a: originate FORWARDED work (a resume or peek that
;;; crosses the mesh exercises the paths quiesce must NOT gate), and
;;; prove locality (a quiesced a must not stop b starting conversations
;;; of its own).
;;;
;;; Deliberately dumb: commands in, raw observations out, every assertion
;;; lives in the parent.
;;; Usage: scheme --script conv-census-child.sc <port> <secret>

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation)
        (only (igropyr libuv) now-ms))

(define args (cdr (command-line)))
(define port (string->number (car args)))
(define secret (cadr args))

(start-scheduler
  (lambda ()
    (define (report tag payload)
      (rsend 'a 'census-suite (vector 'res tag payload)))

    (define (observe-resume id token req ttl)
      (let ((t0 (now-ms)))
        (let-values (((reply status) (conversation-resume! id token req ttl)))
          (list reply status (- (now-ms) t0)))))

    (node-start! 'b secret)
    (node-connect! 'a "127.0.0.1" port)
    (register 'ctrl self)
    (spawn (lambda () (receive (after 120000 (exit 1)))))
    (monitor-node 'a)
    (receive (after 10000 (exit 2)) (`#(node-up a) 'ok))

    (let loop ()
      (receive
        (`#(resume ,tag ,id ,token ,req ,ttl)
          (report tag (observe-resume id token req ttl))
          (loop))
        (`#(resume-async ,tag ,id ,token ,req ,ttl)
          (spawn (lambda () (report tag (observe-resume id token req ttl))))
          (loop))
        (`#(peek ,tag ,id ,ttl)
          (let-values (((state token reply) (conversation-peek id ttl)))
            (report tag (list state reply)))
          (loop))
        ;; a conversation of b's OWN: a quiesced neighbour must not stop it
        (`#(start-own ,tag)
          (let ((r (guard (e (#t (list 'raised e)))
                     (let-values (((id token reply)
                                   (conversation-start!
                                     (lambda (req suspend! commit!)
                                       (commit! (lambda () 'ok))
                                       (vector 'own-final req))
                                     7)))
                       (list 'ok reply)))))
            (report tag r))
          (loop))
        (`#(quit) (exit 0))
        (`#(node-down a) (exit 0))))))
