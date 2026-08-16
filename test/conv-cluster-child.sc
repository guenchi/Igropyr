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
              (lambda (req suspend! commit!)
                (let loop ((sum 0) (r req))
                  (if (eq? r 'done)
                      (vector 'final sum)
                      (loop (+ sum r) (suspend! (vector 'ack (+ sum r)))))))
              0))
          ;; the token crosses the link with the id: a resume from another
          ;; node has to name the reply it is answering, exactly as a local
          ;; one does
          (lambda (id token first-reply)
            (rsend 'a 'main (vector 'conv-id id token first-reply))))))

    ;; A conversation whose commit THIS node witnessed, and which then
    ;; failed: the record here says committed-then-failed, and the whole
    ;; point of carrying the witness across the link is that node a's
    ;; lagging predicate cannot turn that into a retry.
    (let ((r (guard (e (#t e))
               (conversation-start!
                 (lambda (req suspend! commit!)
                   (commit! (lambda () 'tx))
                   (raise 'post-commit-cleanup-failure))
                 0))))
      ;; #(conversation-uncertain id outcome reason)
      (unless (and (vector? r) (eq? (vector-ref r 0) 'conversation-uncertain))
        (rsend 'a 'main (vector 'conv-witness-setup-failed r))
        (exit 3))
      (rsend 'a 'main (vector 'conv-witness (vector-ref r 1))))

    ;; ...and one whose commit is UNCERTAIN: the thunk signalled
    ;; commit-uncertain -- it did something that may already have taken
    ;; effect -- and the flow then died of it. The record here says
    ;; commit-uncertain-then-failed, which answers 'unknown but, unlike a
    ;; confirmed commit, does not outrank an authoritative #f.
    (let ((r (guard (e (#t e))
               (conversation-start!
                 (lambda (req suspend! commit!)
                   (commit! (lambda ()
                              (raise (vector 'commit-uncertain 'timed-out)))))
                 0))))
      (unless (and (vector? r) (eq? (vector-ref r 0) 'conversation-uncertain))
        (rsend 'a 'main (vector 'conv-uncertain-setup-failed r))
        (exit 4))
      (rsend 'a 'main (vector 'conv-uncertain (vector-ref r 1))))

    (let loop ()
      (receive
        (`#(quit) (exit 0))
        (,_ (loop))))))
