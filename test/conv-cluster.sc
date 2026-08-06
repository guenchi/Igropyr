#!chezscheme
;;; (igropyr conversation) cluster test: two real OS processes.
;;;
;;; The conversation is created on node b (the owner). Node a receives
;;; only its id and drives every resume -- so each resume must be
;;; forwarded to b over the mesh, run against the live continuation
;;; there, and the reply carried back. Verifies:
;;;   - forwarded resume round-trips (ack sums accumulate correctly)
;;;   - the final reply crosses back
;;;   - a completed conversation still answers across the link: its final
;;;     reply replays, an invented token is 'stale. (Nothing here expects
;;;     'gone, and nothing here can produce it: 'gone is a record saying
;;;     the flow rolled back, and every flow in this file completes.)
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
    (let-values (((r st) (conversation-resume! "nowhere~deadbeef" "deadbeef" 1)))
      (unless (eq? 'unreachable st)
        (fail! "unknown-owner-should-be-unreachable" st)))
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

      ;; peek crosses the link too, with the same failure semantics: an
      ;; owner we cannot reach is 'unreachable, never 'gone. This is the
      ;; call a caller makes AFTER an 'unreachable resume, once the link is
      ;; back, instead of resubmitting.
      (let-values (((st tk rp) (conversation-peek id)))
        (unless (eq? st 'parked) (fail! "cross-node-peek-state" st))
        (unless (equal? tk tok0) (fail! "cross-node-peek-token" tk))
        (unless (equal? rp (vector 'ack 0)) (fail! "cross-node-peek-reply" rp)))
      (display "peek across the link reports the parked step ok\n")

      ;; an owner node we never heard of is unreachable, not gone
      (let-values (((st tk rp) (conversation-peek "nowhere~deadbeef")))
        (unless (eq? st 'unreachable) (fail! "peek-unknown-owner" st)))
      (display "peek to an unknown owner -> unreachable ok\n")

      ;; each round answers the reply it was handed, and the next token
      ;; comes back over the link with it
      (let-values (((r t1) (conversation-resume! id tok0 5)))
        (unless (equal? r (vector 'ack 5)) (fail! "resume-1" r))
        (let-values (((r2 t2) (conversation-resume! id t1 10)))
          (unless (equal? r2 (vector 'ack 15)) (fail! "resume-2" r2))
          (display "cross-node resume round-trips ok\n")

          ;; A token already spent REPLAYS across the link too -- and this
          ;; is where a duplicate is most likely, because the network
          ;; carrying the forward is exactly what delays it. The answer
          ;; must be the one that token produced, not a second run: here
          ;; that means (ack 15) again rather than (ack 25).
          (let-values (((rs ts) (conversation-resume! id t1 10)))
            (unless (equal? rs (vector 'ack 15)) (fail! "cross-node-replay" rs))
            (unless (equal? ts t2) (fail! "cross-node-replay-token" ts)))
          (display "a spent token replays across the link ok\n")

          ;; an invented one is still refused
          (let-values (((rw tw) (conversation-resume! id "00000000deadbeef" 10)))
            (unless (eq? tw 'stale) (fail! "cross-node-invented" tw)))
          (display "an invented token is refused across the link ok\n")

          (let-values (((r3 t3) (conversation-resume! id t2 'done)))
            (unless (equal? r3 (vector 'final 15)) (fail! "resume-final" r3))
            (display "cross-node final reply ok\n")

            ;; the conversation LINGERS after completing, so within that
            ;; window it can still tell an invented token apart from a
            ;; repeat -- which is the whole point of lingering: a client
            ;; whose final reply was lost gets it back rather than 'gone
            (let-values (((r4 t4) (conversation-resume! id "00000000deadbeef" 99)))
              (unless (eq? t4 'stale) (fail! "resume-after-done" t4)))
            (display "an invented token after completion -> stale ok\n")

            (let-values (((r5 t5) (conversation-resume! id t2 'done)))
              (unless (equal? r5 (vector 'final 15))
                (fail! "final-replay-across-link" r5)))
            (display "the final reply replays across the link ok\n")))))

    (rsend 'b 'ctrl (vector 'quit))     ; let the owner exit promptly
    (sleep-ms 200)
    (display "ALL CONV-CLUSTER TESTS PASSED\n")
    (exit 0)))
