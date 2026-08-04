#!chezscheme
;;; (igropyr connpool) statistics, against FAKE connection workers.
;;;
;;; A saturated pool and a slow database look identical from outside: both
;;; present as slow requests. What separates them is where the time went --
;;; waiting for a connection, or running the statement -- and none of it was
;;; observable. A pool could not be sized, a lease leak (in-use never falls
;;; back to zero) could not be told from load, and timeouts were individual
;;; raises with no rate behind them.
;;;
;;; Every number here is checked against a situation this test CONSTRUCTS,
;;; not merely read back: the pool is saturated on purpose so `pending` has
;;; something in it, a query is made to take a known time so its duration
;;; can be bounded, a checkout is made to wait behind a lease, and both
;;; timeout paths are driven for real. A stats call that only asserted "the
;;; keys are present" would pass against a pool that reported zeros.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr connpool))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define cfg
  (make-connpool-cfg
    (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'fake-error)))
    (vector 'fake-error "lost")
    (vector 'fake-error "closed")
    (vector 'fake-error "query timeout")
    (vector 'fake-error "checkout timeout")
    "BEGIN"))

(define (stat st k)
  (cond ((assq k st) => cdr) (else 'missing)))

;; A stand-in connection. "SLOW" in the SQL text makes it take 300 ms, so a
;; query duration can be bounded from both sides.
(define (fake-spawn-conn! notify report-to ref)
  (spawn
    (lambda ()
      (send report-to (vector 'pool-up ref self 'ok))
      (receive (`#(pool-adopt) 'ok))
      (let loop ()
        (receive
          (`#(pool-request ,sql ,r ,from)
            (when (and (string? sql) (>= (string-length sql) 4)
                       (string=? (substring sql 0 4) "SLOW"))
              (sleep-ms 300))
            (send from (vector 'pool-reply r (vector 'fake-rows sql)))
            (send notify (vector 'pool-idle self r))
            (loop))
          ;; part of the driver contract: a lone connection answers #f, so
          ;; the request cannot sit here forever
          (`#(pool-stats ,r ,from)
            (send from (vector 'pool-stats-reply r #f))
            (loop))
          (`#(pool-quit) 'done))))))

(start-scheduler
  (lambda ()
    (let ((pool (spawn (lambda () (connpool-loop 1 fake-spawn-conn! cfg)))))
      (sleep-ms 300)

      ;; ---- an idle pool ---------------------------------------------------
      (let ((st (connpool-stats pool)))
        (check "size is the configured size" (= 1 (stat st 'size)))
        (check "an idle pool has its connection idle" (= 1 (stat st 'idle)))
        (check "nothing in use" (= 0 (stat st 'in-use)))
        (check "nothing pending" (= 0 (stat st 'pending)))
        (check "the connection came up" (= 1 (stat st 'connects)))
        (check "no queries yet" (= 0 (stat st 'queries))))

      ;; ---- a query, timed -------------------------------------------------
      (connpool-call pool "SLOW SELECT 1" cfg)
      (let ((st (connpool-stats pool)))
        (check "the query was counted" (= 1 (stat st 'queries)))
        (check "and completed" (= 1 (stat st 'queries-completed)))
        ;; the worker slept 300 ms: the measurement must bracket that, which
        ;; a zero or a wall-clock-since-boot would not
        (check "its duration is measured, not guessed"
          (<= 250 (stat st 'query-ms-max) 900))
        (display "  [info] query-ms-max ") (display (stat st 'query-ms-max))
        (display " for a 300 ms statement\n")
        ;; it went straight to an idle connection, so it never queued
        (check "a query that never queued reports no queue wait"
          (< (stat st 'queue-wait-ms-max) 100))
        (check "the connection is idle again" (= 0 (stat st 'in-use))))

      ;; ---- saturation: pending and queue wait -----------------------------
      ;; The single connection is occupied for 300 ms; two more queries must
      ;; queue behind it, and the pool must say so WHILE they are queued.
      (let ((me self))
        (spawn (lambda () (connpool-call pool "SLOW A" cfg) (send me (vector 'q 'a))))
        (sleep-ms 60)
        (spawn (lambda () (connpool-call pool "SLOW B" cfg) (send me (vector 'q 'b))))
        (spawn (lambda () (connpool-call pool "SLOW C" cfg) (send me (vector 'q 'c))))
        (sleep-ms 60)
        (let ((st (connpool-stats pool)))
          (check "the running query shows as in use" (= 1 (stat st 'in-use)))
          (check "the queued ones show as pending" (= 2 (stat st 'pending)))
          (display "  [info] in-use ") (display (stat st 'in-use))
          (display ", pending ") (display (stat st 'pending)) (newline))
        ;; let them drain
        (let drain ((i 0)) (when (< i 3) (receive (after 5000 'lost) (`#(q ,x) x))
                                         (drain (+ i 1))))
        (let ((st (connpool-stats pool)))
          (check "queue wait was measured for the ones that waited"
            (> (stat st 'queue-wait-ms-max) 200))
          (display "  [info] queue-wait-ms-max ")
          (display (stat st 'queue-wait-ms-max)) (newline)
          (check "the pool drained back to nothing in use"
            (= 0 (stat st 'in-use)))))

      ;; ---- leases: in-use, checkout wait ----------------------------------
      (let ((me self))
        (let ((holder (spawn (lambda ()
                               (connpool-lease pool
                                 (lambda (c)
                                   (send me (vector 'held))
                                   (receive (`#(release) 'ok)))
                                 cfg)))))
          (receive (after 3000 'lost) (`#(held) 'ok))
          (let ((st (connpool-stats pool)))
            (check "a lease shows as leased" (= 1 (stat st 'leased)))
            (check "and counts as in use" (= 1 (stat st 'in-use)))
            (check "the lease was counted" (= 1 (stat st 'checkouts))))

          ;; a second borrower must wait behind it
          (spawn (lambda ()
                   (connpool-lease pool
                     (lambda (c) (send me (vector 'second))) cfg)))
          (sleep-ms 250)
          (let ((st (connpool-stats pool)))
            (check "a waiting borrower shows as checkout-pending"
              (= 1 (stat st 'checkout-pending))))

          (send holder (vector 'release))
          (receive (after 3000 'lost) (`#(second) 'ok))
          (sleep-ms 100)
          (let ((st (connpool-stats pool)))
            (check "its wait was measured"
              (> (stat st 'checkout-wait-ms-max) 150))
            (display "  [info] checkout-wait-ms-max ")
            (display (stat st 'checkout-wait-ms-max)) (newline)
            (check "both leases counted" (= 2 (stat st 'checkouts)))
            (check "nothing left in use" (= 0 (stat st 'in-use))))))

      ;; ---- timeouts -------------------------------------------------------
      ;; Both timeout paths tell the pool (pool-request-cancel / pool-checkout-cancel)
      ;; so it can drop the request; those are exactly the events to count.
      (let ((before (stat (connpool-stats pool) 'query-timeouts)))
        (send pool (vector 'pool-request-cancel (gensym) self))
        (sleep-ms 100)
        (check "a query timeout is counted"
          (= (+ before 1) (stat (connpool-stats pool) 'query-timeouts))))
      (let ((before (stat (connpool-stats pool) 'checkout-timeouts)))
        (send pool (vector 'pool-checkout-cancel (gensym) self))
        (sleep-ms 100)
        (check "a checkout timeout is counted"
          (= (+ before 1) (stat (connpool-stats pool) 'checkout-timeouts))))

      ;; ---- waits that ended in a TIMEOUT ---------------------------------
      ;; Recording only the requests that eventually got a connection left
      ;; these metrics blind to exactly the situation they exist for: a pool
      ;; saturated enough that everything times out reported a maximum wait
      ;; of zero, because nothing ever waited successfully.
      ;;
      ;; The waits are driven for real -- a request is queued behind a lease,
      ;; left there, then cancelled the way connpool-call and connpool-checkout cancel
      ;; on timeout.
      (let ((me self))
        (let ((holder (spawn (lambda ()
                               (connpool-lease pool
                                 (lambda (c)
                                   (send me (vector 'held))
                                   (receive (`#(release) 'ok)))
                                 cfg)))))
          (receive (after 3000 'lost) (`#(held) 'ok))
          ;; the TOTALS, not the maxima: a max cannot show a 400 ms wait
          ;; when an earlier successful wait was longer, and asserting on
          ;; one is a test that depends on the order of the cases above
          (let ((qref (gensym)) (cref (gensym))
                (q0 (stat (connpool-stats pool) 'queue-wait-ms-total))
                (c0 (stat (connpool-stats pool) 'checkout-wait-ms-total)))
            (send pool (vector 'pool-request "SELECT waited" qref self))
            (send pool (vector 'pool-checkout cref self))
            (sleep-ms 400)
            ;; exactly what the client side sends when its timeout fires
            (send pool (vector 'pool-request-cancel qref self))
            (send pool (vector 'pool-checkout-cancel cref self))
            (sleep-ms 150)
            (let ((st (connpool-stats pool)))
              (display "  [info] ~400 ms of waiting that timed out added ")
              (display (- (stat st 'queue-wait-ms-total) q0))
              (display " ms to queue-wait-total and ")
              (display (- (stat st 'checkout-wait-ms-total) c0))
              (display " ms to checkout-wait-total\n")
              (check "a query that timed out still records its wait"
                (>= (- (stat st 'queue-wait-ms-total) q0) 300))
              (check "a checkout that timed out still records its wait"
                (>= (- (stat st 'checkout-wait-ms-total) c0) 300))))
          (send holder (vector 'release))
          (sleep-ms 200)))

      (send pool (vector (quote pool-quit))))

    ;; ---- a lone connection is not a pool ----------------------------------
    ;; Asking one for pool statistics must be an error, not zeros: an
    ;; operator reading `in-use 0` off a busy connection would draw exactly
    ;; the wrong conclusion. It must also not leave the request sitting in
    ;; that connection's mailbox forever, which is why there is a reply at
    ;; all rather than a bare timeout here.
    (let ((conn (fake-spawn-conn! self self (gensym))))
      (send conn (vector 'pool-adopt))
      (check "a lone connection refuses pool statistics"
        (guard (e ((assertion-violation? e) #t) (#t #f))
          (connpool-stats conn)
          #f))
      (send conn (vector 'pool-quit)))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "connpool-stats: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
