#!chezscheme
;;; Helper for test/conv-admission.sc: the ASKER node. Every forwarded
;;; resume and peek in that suite originates here, because admission is
;;; an owner-side judgement about FORWARDED work -- a local caller never
;;; takes a slot, and a suite that resumed locally would be measuring the
;;; wrong path while its labels claimed otherwise.
;;;
;;; This node is deliberately dumb: it executes commands and reports raw
;;; observations (reply, status, elapsed ms, its own forward-stats
;;; snapshot). Every assertion lives in the parent, so each rule is
;;; written in exactly one place.
;;; Usage: scheme --script conv-admission-child.sc <port> <secret>

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation)
        (only (igropyr libuv) now-ms))

(define args (cdr (command-line)))
(define port (string->number (car args)))
(define secret (cadr args))

(start-scheduler
  (lambda ()
    (define (report tag payload)
      (rsend 'a 'adm (vector 'res tag payload)))

    ;; a resume observed from the outside: what came back, and how long
    ;; it took to come back. ttl is passed through so the parent decides
    ;; per call how long a silence is allowed to run.
    (define (observe-resume id token req ttl)
      (let ((t0 (now-ms)))
        (let-values (((reply status) (conversation-resume! id token req ttl)))
          (list reply status (- (now-ms) t0)))))

    (node-start! 'b secret)
    (node-connect! 'a "127.0.0.1" port)
    (register 'ctrl self)
    ;; hung-child net: sized for the parent's run; firing it is never
    ;; good news
    (spawn (lambda () (receive (after 120000 (exit 1)))))
    (monitor-node 'a)
    (receive (after 10000 (exit 2)) (`#(node-up a) 'ok))

    (let loop ()
      (receive
        (`#(resume ,tag ,id ,token ,req ,ttl)
          (report tag (observe-resume id token req ttl))
          (loop))
        ;; async: the call parks this side, so it runs in its own
        ;; process and reports whenever it returns -- this is how the
        ;; parent holds owner-side slots open while doing other things
        (`#(resume-async ,tag ,id ,token ,req ,ttl)
          (spawn (lambda () (report tag (observe-resume id token req ttl))))
          (loop))
        (`#(peek ,tag ,id ,ttl)
          (let ((t0 (now-ms)))
            (let-values (((state token reply)
                          (conversation-peek id ttl)))
              (report tag (list state (- (now-ms) t0)))))
          (loop))
        (`#(stats ,tag)
          (report tag (conversation-forward-stats))
          (loop))
        (`#(quit) (exit 0))
        (`#(node-down a) (exit 0))))))
