#!chezscheme
;;; Pool capacity/timing settings are refused at startup, not absorbed.
;;;
;;; Each of these fails SILENTLY when it is out of range, which is the
;;; reason to check rather than trust: workers=0 starts a listener that
;;; accepts requests and queues them forever; a negative check-ms kills the
;;; ticker immediately, so stuck-worker detection disappears while the pool
;;; still looks healthy; a negative or fractional pool size never satisfies
;;; the (= i n) that ends the connect loop, so it spawns connection workers
;;; without end. None announces itself -- each surfaces much later as "the
;;; service stopped responding", with nothing pointing at the cause.

(import (chezscheme) (igropyr actor) (igropyr otp) (igropyr sqlpool))
(define fails 0)
(define (rejects? label thunk)
  (let ((ok (guard (e ((assertion-violation? e) #t) (#t #f)) (thunk) #f)))
    (if ok (begin (display "  ok  ") (display label) (newline))
        (begin (set! fails (+ fails 1))
               (display "FAIL  ") (display label) (newline)))))
(define cfg (make-sql-cfg (lambda (r) #f) 'l 'c 'q 'k "BEGIN"))
(start-scheduler
  (lambda ()
    (rejects? "workers=0"    (lambda () (start-worker-pool 0 (lambda (t) t) (lambda (t i) t))))
    (rejects? "workers=-1"   (lambda () (start-worker-pool -1 (lambda (t) t) (lambda (t i) t))))
    (rejects? "workers=2.5"  (lambda () (start-worker-pool 2.5 (lambda (t) t) (lambda (t i) t))))
    (rejects? "max-retries=-1" (lambda () (start-worker-pool 2 (lambda (t) t) (lambda (t i) t) -1)))
    (rejects? "stuck-ms=0"   (lambda () (start-worker-pool 2 (lambda (t) t) (lambda (t i) t) 3 0)))
    (rejects? "check-ms=-5"  (lambda () (start-worker-pool 2 (lambda (t) t) (lambda (t i) t) 3 30000 -5)))
    (rejects? "sql pool n=0"  (lambda () (sql-pool-loop 0 (lambda (a b c) #f) cfg)))
    (rejects? "sql pool n=-3" (lambda () (sql-pool-loop -3 (lambda (a b c) #f) cfg)))
    (rejects? "sql pool n=1.5"(lambda () (sql-pool-loop 1.5 (lambda (a b c) #f) cfg)))
    (if (zero? fails)
        (begin (display "pool config validation: all tests passed\n") (exit 0))
        (begin (display fails) (display " failures\n") (exit 1)))))
