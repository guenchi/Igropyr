#!chezscheme
;;; (igropyr blas): the scoring contract pinned against an independent
;;; double-accumulation reference. Whichever lane is active (native
;;; sgemv where a BLAS loads, the pure loop otherwise) must agree with
;;; the reference within f32-accumulation tolerance; bounds violations
;;; must fail as Scheme errors, never reach the native call.

(import (chezscheme) (igropyr blas))

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

;; deterministic values in [-1, 1) -- a tiny LCG, no external deps
(define seed 123456789)
(define (next!)
  (set! seed (mod (+ (* seed 1103515245) 12345) 2147483648))
  (- (* 2.0 (/ seed 2147483648.0)) 1.0))

(define n 300)
(define dim 64)
(define base (make-bytevector (* n dim 4)))
(define query (make-bytevector (* dim 4)))
(define scores (make-bytevector (* n 4)))

(do ((i 0 (+ i 1))) ((= i (* n dim)))
  (bytevector-ieee-single-native-set! base (* i 4) (next!)))
(do ((j 0 (+ j 1))) ((= j dim))
  (bytevector-ieee-single-native-set! query (* j 4) (next!)))

;; independent reference: read the same f32 buffers, accumulate double
(define (ref-score i)
  (let loop ((j 0) (acc 0.0))
    (if (= j dim)
        acc
        (loop (+ j 1)
              (+ acc (* (bytevector-ieee-single-native-ref
                          base (* (+ (* i dim) j) 4))
                        (bytevector-ieee-single-native-ref
                          query (* j 4))))))))

(display (if (blas-available?)
             "blas: native lane active\n"
             "blas: pure lane active (no BLAS on this host)\n"))

(blas-scores! base n dim query scores)
(check "scores-match-reference"
  (let loop ((i 0))
    (or (= i n)
        (and (<= (abs (- (bytevector-ieee-single-native-ref scores (* i 4))
                         (ref-score i)))
                 1e-4)
             (loop (+ i 1))))))

;; n = 0 is a no-op, not an error
(blas-scores! base 0 dim query scores)
(check "zero-rows-ok" #t)

;; a short buffer must be a Scheme error, never a native overrun
(define (rejects? thunk)
  (guard (e ((assertion-violation? e) #t) (#t #f)) (thunk) #f))
(check "short-base-rejected"
  (rejects? (lambda () (blas-scores! (make-bytevector 8) n dim query scores))))
(check "short-query-rejected"
  (rejects? (lambda () (blas-scores! base n dim (make-bytevector 8) scores))))
(check "short-scores-rejected"
  (rejects? (lambda () (blas-scores! base n dim query (make-bytevector 8)))))
(check "bad-dim-rejected"
  (rejects? (lambda () (blas-scores! base n 0 query scores))))

(if (zero? failures)
    (begin (display "blas: all tests passed") (newline) (exit 0))
    (begin (display failures) (display " failures") (newline) (exit 1)))
