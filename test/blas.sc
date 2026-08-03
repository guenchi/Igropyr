#!chezscheme
;;; (igropyr blas): the scoring contract pinned against an independent
;;; double-accumulation reference. Whichever lane is active (native
;;; sgemv where a BLAS loads, the pure loop otherwise) must agree with
;;; the reference within f32-accumulation tolerance; bounds violations
;;; must fail as Scheme errors, never reach the native call.

;;; The pure lane is checked here EVEN WHERE A BLAS LOADS. Left to
;;; blas-scores! alone it would run on no developer machine that has one
;;; (macOS always does, via Accelerate), so the fallback everything
;;; depends on for correctness would be exercised nowhere -- and it now
;;; has two expand-time variants of its query buffer, doubling the
;;; surface that would go unrun.

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

;; the pure lane, forced: on a BLAS host the line above never reached it
(define pure-scores (make-bytevector (* n 4)))
(blas-scores-pure! base n dim query pure-scores)
(check "pure-lane-matches-reference"
  (let loop ((i 0))
    (or (= i n)
        (and (<= (abs (- (bytevector-ieee-single-native-ref pure-scores (* i 4))
                         (ref-score i)))
                 1e-4)
             (loop (+ i 1))))))

;; and the two lanes must agree with each other, not merely each with the
;; reference: a shared bias in both would slip past a one-sided check
(check "lanes-agree"
  (let loop ((i 0))
    (or (= i n)
        (and (<= (abs (- (bytevector-ieee-single-native-ref scores (* i 4))
                         (bytevector-ieee-single-native-ref pure-scores (* i 4))))
                 1e-4)
             (loop (+ i 1))))))

;; n = 0 is a no-op, not an error
(blas-scores! base 0 dim query scores)
(blas-scores-pure! base 0 dim query scores)
(check "zero-rows-ok" #t)

;; a short buffer must be a Scheme error, never a native overrun
(define (rejects? thunk)
  (guard (e ((assertion-violation? e) #t) (#t #f)) (thunk) #f))
;; run the whole set against BOTH entry points: the pure lane is public
;; too, so it must not be the lax door into the same buffers
(for-each
  (lambda (entry)
    (let ((f (car entry)) (tag (cdr entry)))
      (check (string-append "short-base-rejected " tag)
        (rejects? (lambda () (f (make-bytevector 8) n dim query scores))))
      (check (string-append "short-query-rejected " tag)
        (rejects? (lambda () (f base n dim (make-bytevector 8) scores))))
      (check (string-append "short-scores-rejected " tag)
        (rejects? (lambda () (f base n dim query (make-bytevector 8)))))
      (check (string-append "bad-dim-rejected " tag)
        (rejects? (lambda () (f base n 0 query scores))))
      ;; n or dim above int32-max is silently truncated crossing the FFI as
      ;; C int, so the native call would read a different shape than the
      ;; buffer checks validated -- reject before the call rather than
      ;; trust the truncated value
      (check (string-append "n-over-int32-rejected " tag)
        (rejects? (lambda () (f base #x80000000 dim query scores))))
      (check (string-append "dim-over-int32-rejected " tag)
        (rejects? (lambda () (f base n #x80000000 query scores))))
      ;; The output buffer must not be one of the inputs. CBLAS sgemv gives
      ;; no guarantee about overlap between Y and X or A, so the native lane
      ;; may overwrite bytes it has yet to read. Both lanes reject, because
      ;; the pure one copying the query first would otherwise make the two
      ;; lanes DISAGREE on the same call -- and a difference between lanes is
      ;; the one thing this module must not have.
      (let ((sq (make-bytevector (* (max n dim) 4) 0)))
        (check (string-append "scores-aliasing-query-rejected " tag)
          (rejects? (lambda () (f base n dim sq sq))))
        (check (string-append "scores-aliasing-base-rejected " tag)
          (rejects? (lambda () (f base n dim query base)))))))
  (list (cons blas-scores! "(blas-scores!)")
        (cons blas-scores-pure! "(blas-scores-pure!)")))

(if (zero? failures)
    (begin (display "blas: all tests passed") (newline) (exit 0))
    (begin (display failures) (display " failures") (newline) (exit 1)))
