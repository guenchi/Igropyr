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
;;;   - resuming an id whose owner node is unknown returns 'unreachable

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

    ;; An id whose owner node we never heard of answers 'unreachable, not
    ;; 'gone. We have no evidence about a node we cannot contact, and 'gone
    ;; is a GUARANTEE that the transaction rolled back -- claiming it here
    ;; would invite a retry that duplicates a flow still running elsewhere.
    (let-values (((r n) (conversation-resume! "nowhere~deadbeef" 1 1)))
      (unless (eq? 'unreachable r)
        (fail! "unknown-owner-should-be-unreachable" r)))
    (display "resume to unknown owner -> unreachable ok\n")

    (spawn-child!)
    (receive (after 10000 (fail! "node-up-timeout")) (`#(node-up b) 'ok))
    (display "handshake ok\n")

    (let* ((got (receive (after 10000 (fail! "conv-id-timeout"))
                  (`#(conv-id ,id ,tk ,fr) (list id tk fr))))
           (id (car got))
           (tok0 (cadr got))
           (fr (caddr got)))
      (unless (equal? fr (vector 'ack 0)) (fail! "first-reply" fr))
      ;; the id must actually carry b as its owner, else this proves nothing
      (unless (eq? 'b (string->symbol
                        (let ((s id))
                          (substring s 0 (let loop ((i 0))
                                           (if (char=? (string-ref s i) #\~) i (loop (+ i 1))))))))
        (fail! "id-not-owned-by-b" id))
      (display "forwarded conversation created, owner=b ok\n")

      ;; each round answers the reply it was handed, and the next token
      ;; comes back over the link with it
      (let-values (((r t1) (conversation-resume! id tok0 5)))
        (unless (equal? r (vector 'ack 5)) (fail! "resume-1" r))
        (let-values (((r2 t2) (conversation-resume! id t1 10)))
          (unless (equal? r2 (vector 'ack 15)) (fail! "resume-2" r2))
          (display "cross-node resume round-trips ok\n")

          ;; a token already spent is refused ACROSS the link too -- this is
          ;; where a duplicate is most likely, since a forwarded resume can
          ;; be delayed by the network that carries it
          (let-values (((rs ts) (conversation-resume! id t1 10)))
            (unless (eq? rs 'stale) (fail! "cross-node-stale" rs)))
          (display "a spent token is refused across the link ok\n")

          (let-values (((r3 t3) (conversation-resume! id t2 'done)))
            (unless (equal? r3 (vector 'final 15)) (fail! "resume-final" r3))
            (display "cross-node final reply ok\n")

            (let-values (((r4 t4) (conversation-resume! id 99 99)))
              (unless (eq? r4 'gone) (fail! "resume-after-done" r4)))
            (display "resume after completion -> gone ok\n")))))

    (rsend 'b 'ctrl (vector 'quit))     ; let the owner exit promptly
    (sleep-ms 200)
    (display "ALL CONV-CLUSTER TESTS PASSED\n")
    (exit 0)))
