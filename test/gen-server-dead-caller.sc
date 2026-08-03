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

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr gen-server))

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
                      ;; a handler calling its own server: the request would
                      ;; land in this very mailbox, and the loop that would
                      ;; answer it is the one running this handler
                      ((self-call)
                       (let ((t0 (now-ms)))
                         (let ((outcome
                                 (guard (e ((and (vector? e)
                                                 (eq? (vector-ref e 0) 'gen-server-error))
                                            (vector-ref e 1))
                                           (#t 'other))
                                   (gen-server-call self 'effect 'infinity)
                                   'returned)))
                           (values (cons outcome (- (now-ms) t0)) state))))
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
      (check "that one did run" (= 1 (unbox effects)))

      ;; ---- calling yourself -------------------------------------------
      ;; The deadlock is total: the request sits in the server's own mailbox
      ;; while the server waits inside the handler. What made it hard to
      ;; diagnose is how it FAILED -- the default timeout turned it into a
      ;; 'timeout five seconds later, usually killing the server, and this
      ;; case asks for 'infinity, under which the server never came back at
      ;; all. The answer must be immediate and must name the mistake.
      (let ((r (gen-server-call srv 'self-call 2000)))
        (check "a self-call is refused, not parked"
          (and (pair? r) (eq? (car r) 'calling-self)))
        (display "  [info] self-call answered in ")
        (display (and (pair? r) (cdr r)))
        (display " ms (was: never, with 'infinity)\n")
        (check "and it was refused at once"
          (and (pair? r) (< (cdr r) 200))))
      ;; the server survived its handler's mistake
      (check "the server still serves after a refused self-call"
        (eq? 'did-it (gen-server-call srv 'effect 2000)))
      (check "and that call ran" (= 2 (unbox effects))))

    (if (zero? failures)
        (begin (display "gen-server-dead-caller: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
