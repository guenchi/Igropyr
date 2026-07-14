#!chezscheme
;;; (igropyr conversation) cluster test: two real OS processes.
;;;
;;; The conversation is created on node b (the owner). Node a receives
;;; only its id and drives every resume -- so each resume must be
;;; forwarded to b over the mesh, run against the live continuation
;;; there, and the reply carried back. Verifies:
;;;   - forwarded resume round-trips (ack sums accumulate correctly)
;;;   - the final reply crosses back
;;;   - resuming a completed conversation returns 'gone
;;;   - resuming an id whose owner node is unknown returns 'gone at once

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation))

(define port 18093)
(define secret "conv-mesh-secret")

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

(define (spawn-child!)
  (system (string-append
            "scheme --script igropyr/test/conv-cluster-child.sc b "
            (number->string port) " " secret " &")))

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (register 'main self)
    (monitor-node 'b)

    ;; an id whose owner node we never heard of -> 'gone immediately
    (unless (eq? 'gone (conversation-resume! "nowhere~deadbeef" 1))
      (fail! "unknown-owner-not-gone"))
    (display "resume to unknown owner -> gone ok\n")

    (spawn-child!)
    (receive (after 10000 (fail! "node-up-timeout")) (`#(node-up b) 'ok))
    (display "handshake ok\n")

    (let* ((got (receive (after 10000 (fail! "conv-id-timeout"))
                  (`#(conv-id ,id ,fr) (cons id fr))))
           (id (car got))
           (fr (cdr got)))
      (unless (equal? fr (vector 'ack 0)) (fail! "first-reply" fr))
      ;; the id must actually carry b as its owner, else this proves nothing
      (unless (eq? 'b (string->symbol
                        (let ((s id))
                          (substring s 0 (let loop ((i 0))
                                           (if (char=? (string-ref s i) #\~) i (loop (+ i 1))))))))
        (fail! "id-not-owned-by-b" id))
      (display "forwarded conversation created, owner=b ok\n")

      (let ((r (conversation-resume! id 5)))
        (unless (equal? r (vector 'ack 5)) (fail! "resume-1" r)))
      (let ((r (conversation-resume! id 10)))
        (unless (equal? r (vector 'ack 15)) (fail! "resume-2" r)))
      (display "cross-node resume round-trips ok\n")

      (let ((r (conversation-resume! id 'done)))
        (unless (equal? r (vector 'final 15)) (fail! "resume-final" r)))
      (display "cross-node final reply ok\n")

      (let ((r (conversation-resume! id 99)))
        (unless (eq? r 'gone) (fail! "resume-after-done" r)))
      (display "resume after completion -> gone ok\n"))

    (rsend 'b 'ctrl (vector 'quit))     ; let the owner exit promptly
    (sleep-ms 200)
    (display "ALL CONV-CLUSTER TESTS PASSED\n")
    (exit 0)))
