#!chezscheme
;;; (igropyr sqlpool): a connection worker that dies BEFORE reporting.
;;;
;;; The pool tracks its workers in idle / busy / leased / dying. A worker
;;; that has been spawned but has not yet sent #(db-up ...) is in none of
;;; them, so its DOWN matched no branch and was silently dropped -- the slot
;;; was gone for the life of the process. Nothing surfaced it: the pool
;;; answered, just with fewer connections each time a connect crashed, until
;;; it had none and every caller queued forever.
;;;
;;; That window is not exotic. It is where a driver crashes on a malformed
;;; greeting, where a TLS handshake raises, where a connect error kills the
;;; actor, and where a supervisor kills a worker stuck on a black-hole
;;; address.

(import (chezscheme) (igropyr actor) (igropyr sqlpool))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define cfg
  (make-sql-cfg
    (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'fake-error)))
    (vector 'fake-error "lost")
    (vector 'fake-error "closed")
    (vector 'fake-error "query timeout")
    (vector 'fake-error "checkout timeout")
    "BEGIN"))

;; The first `die-first` workers exit during connect without reporting
;; anything; every one after that behaves.
(define die-first 2)
(define spawned 0)

(define (fake-spawn-conn! notify report-to ref)
  (set! spawned (+ spawned 1))
  (let ((doomed? (<= spawned die-first)))
    (spawn
      (lambda ()
        (if doomed?
            ;; dies mid-connect: no db-up, no retry scheduled by anyone
            (raise 'connect-crashed)
            (begin
              (send report-to (vector 'db-up ref self 'ok))
              (receive (`#(db-adopt) 'ok))
              (let loop ()
                (receive
                  (`#(db-query ,sql ,r ,from)
                    (send from (vector 'db-reply r (vector 'fake-rows sql)))
                    (send notify (vector 'db-idle self))
                    (loop))
                  (`#(db-quit) 'done)))))))))

(start-scheduler
  (lambda ()
    (let ((pool (spawn (lambda () (sql-pool-loop 1 fake-spawn-conn! cfg)))))
      ;; Both initial attempts crash before reporting. The pool must notice
      ;; and rebuild; the first backoff is ~1s, so allow for two rounds.
      (let ((r (gensym)))
        (send pool (vector 'db-query "SELECT 1" r self))
        (check "the pool rebuilds a worker that died while connecting"
          (receive (after 8000 #f) (`#(db-reply ,@r ,v) #t))))

      (check "and it did so by spawning replacements" (> spawned die-first))

      ;; The slot is a real slot afterwards, not a one-shot: a second query
      ;; must run on it too.
      (let ((r2 (gensym)))
        (send pool (vector 'db-query "SELECT 2" r2 self))
        (check "the rebuilt connection serves later queries"
          (receive (after 3000 #f) (`#(db-reply ,@r2 ,v) #t))))

      (send pool (vector 'db-close)))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "sqlpool-connect-death: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
