;;; Smoke test: process-per-connection echo server on the actor layer.
;;; Each accepted connection gets its own reader process; slow or idle
;;; connections only park their own process.
;;; Run: scheme --script test/smoke-echo-actor.sc

(import (chezscheme) (igropyr actor) (igropyr uv))

(define (reader c)
  (lambda ()
    (let loop ()
      (receive (after 10000 (tcp-close! c))
        (`#(tcp-data ,bv)
          (tcp-write! c bv #f)
          (loop))
        (`#(tcp-eof) (tcp-close! c))
        (`#(tcp-error ,e) (tcp-close! c))))))

(start-scheduler
  (lambda ()
    (tcp-listen! "0.0.0.0" 5556 128
      (lambda (c)
        ;; runs in libuv callback context: spawn + register only, no yield
        (let ((pid (spawn (reader c))))
          (conn-set-owner! c pid)
          (tcp-read-start! c))))
    (display "actor echo server on 127.0.0.1:5556\n")))
