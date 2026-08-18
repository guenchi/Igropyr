#!chezscheme
;;; Helper for test/conv-mixed-overload.sc: an OLD asker, run against a
;;; checkout from before the refusal frame existed, while node a (the
;;; owner) runs the current tree. Executed with CHEZSCHEMELIBDIRS pointing
;;; at the old tree, so it may use only API that existed there --
;;; node-start!/connect!, conversation-resume! (call-level ttl included:
;;; the pinned revision already has it), rsend, monitor-node.
;;;
;;; Two commands, one per role in the overload story:
;;;   #(hold ,id ,token)    resume in a spawned process; the flow blocks
;;;                         on the owner, so this forward OCCUPIES the
;;;                         owner's one slot until the owner releases it.
;;;                         Reports #(held ,reply ,status) when it returns.
;;;   #(try ,id ,token ,ttl) resume synchronously with that ttl and report
;;;                         #(tried ,reply ,status ,elapsed).
;;; Usage: scheme --script conv-mixed-overload-child.sc <port> <secret>

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation)
        (only (igropyr libuv) now-ms))

(define args (cdr (command-line)))
(define port (string->number (car args)))
(define secret (cadr args))

(start-scheduler
  (lambda ()
    (node-start! 'b secret)
    (node-connect! 'a "127.0.0.1" port)
    (register 'ctrl self)
    ;; hung-child net: sized for the parent's run; firing it is never
    ;; good news
    (spawn (lambda () (receive (after 60000 (exit 1)))))
    (monitor-node 'a)
    (receive (after 10000 (exit 2)) (`#(node-up a) 'ok))

    (let loop ()
      (receive
        (`#(hold ,id ,token)
          (spawn
            (lambda ()
              (let-values (((reply status)
                            (conversation-resume! id token 'block 30000)))
                (rsend 'a 'mixed (vector 'held reply status)))))
          (loop))
        (`#(try ,id ,token ,ttl)
          (let ((t0 (now-ms)))
            (let-values (((reply status)
                          (conversation-resume! id token 5 ttl)))
              (rsend 'a 'mixed
                     (vector 'tried reply status (- (now-ms) t0)))))
          (loop))
        (`#(quit) (exit 0))
        (`#(node-down a) (exit 0))))))
