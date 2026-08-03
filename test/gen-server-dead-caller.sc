#!chezscheme
;;; A gen-server must not run a call whose caller is already dead.
;;;
;;; A busy server queues work in its mailbox, and a caller can be killed
;;; while it waits there -- a stuck worker reaped by its supervisor is
;;; exactly that. Running the handler then applies effects nobody will ever
;;; observe, and the application's retry applies them again: one charge
;;; becomes two.
;;;
;;; Only the DEAD case is pinned. A caller that merely timed out is still
;;; running and looks identical to one still waiting, so the server cannot
;;; act on that -- gen-server-call documents the consequence instead.

(import (chezscheme) (igropyr actor) (igropyr gen-server))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define effects (box 0))

(start-scheduler
  (lambda ()
    (let* ((me self)
           (srv (gen-server-start
                  (lambda () 'state)
                  (lambda (msg from state)
                    (case msg
                      ;; blocks the server so the next call has to queue
                      ((block) (sleep-ms 700) (values 'unblocked state))
                      ((effect)
                       (set-box! effects (+ 1 (unbox effects)))
                       (values 'did-it state))
                      (else (values 'ok state))))
                  (lambda (msg state) state))))

      ;; occupy the server
      (spawn (lambda () (gen-server-call srv 'block 5000)))
      (sleep-ms 100)

      ;; a caller queues an effectful call behind it, then is killed
      (let ((victim (spawn (lambda ()
                             (guard (e (#t (void)))
                               (gen-server-call srv 'effect 5000))))))
        (sleep-ms 100)
        (monitor victim)
        (kill victim 'reaped-while-waiting)
        (receive (after 2000 (void)) (`#(DOWN ,@victim ,_) 'ok)))

      ;; let the server work through its mailbox
      (sleep-ms 1500)
      (check "a dead caller's call is not executed" (= 0 (unbox effects)))

      ;; and the server is still healthy for a live caller
      (check "server still serves live callers"
        (eq? 'did-it (gen-server-call srv 'effect 2000)))
      (check "that one did run" (= 1 (unbox effects))))

    (if (zero? failures)
        (begin (display "gen-server-dead-caller: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
