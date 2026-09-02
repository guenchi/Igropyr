#!chezscheme
;;; soak-load.sc -- external HTTP pressure for a soak node, from another
;;; machine. N processes each loop GET on URL for SECONDS, counting
;;; statuses, transport failures and latency. A companion to
;;; soak-mesh.sc's SOAK_HTTP_PORT: the point is to load the same
;;; scheduler that is hosting watches and surviving a crash-looping peer,
;;; and to see whether either side degrades the other -- rcall timeouts
;;; on the mesh driver, or stalls and failures here.
;;;
;;; usage: chez --script test/soak-load.sc URL SECONDS CONCURRENCY
;;; Prints a line every 10 s and a summary at the end (exit 0). It has no
;;; pass/fail of its own: the readings are for the ledger.
(import (chezscheme) (igropyr actor) (igropyr http-client))

(define args (cdr (command-line)))
(unless (= (length args) 3)
  (display "usage: soak-load.sc URL SECONDS CONCURRENCY\n") (exit 64))
(define url (car args))
(define seconds (string->number (cadr args)))
(define conc (string->number (caddr args)))

(define (now) (let ((t (current-time))) (+ (* 1000 (time-second t)) (quotient (time-nanosecond t) 1000000))))
(define t0 (now))
(define (elapsed) (- (now) t0))

(define ok 0) (define bad-status 0) (define failed 0)
(define lat '())                       ; ms, most recent first
(define (record! ms) (set! lat (cons ms lat)))
(define (percentile p)
  (if (null? lat) 0
      (let* ((v (list->vector lat)) (n (vector-length v)))
        (vector-sort! < v)
        (vector-ref v (min (- n 1) (exact (floor (* p n))))))))

(start-scheduler
  (lambda ()
    (let ((main self))
      (do ((i 0 (+ i 1))) ((= i conc))
        (spawn (lambda ()
                 (let loop ()
                   (when (< (elapsed) (* 1000 seconds))
                     (let ((t1 (now)))
                       (guard (e (#t (send main (vector 'failed))))
                         (let ((r (http-get url '((timeout . 5000)))))
                           (send main (vector (if (= (response-status r) 200) 'ok 'bad-status)
                                              (- (now) t1)))))
                       (loop)))))))
      (let loop ((last-report 0))
        (receive (after 1000 (void))
          (`#(ok ,ms) (set! ok (+ ok 1)) (record! ms))
          (`#(bad-status ,ms) (set! bad-status (+ bad-status 1)) (record! ms))
          (`#(failed) (set! failed (+ failed 1))))
        (let ((lr (if (> (- (elapsed) last-report) 10000)
                      (begin
                        (display (elapsed)) (display "ms ok ") (display ok)
                        (display " bad-status ") (display bad-status)
                        (display " failed ") (display failed)
                        (display " p50 ") (display (percentile 0.5))
                        (display " p99 ") (display (percentile 0.99)) (newline)
                        (elapsed))
                      last-report)))
          (if (< (elapsed) (* 1000 (+ seconds 6)))
              (loop lr)
              (begin
                (display "LOAD DONE ok ") (display ok)
                (display " bad-status ") (display bad-status)
                (display " failed ") (display failed)
                (display " p50 ") (display (percentile 0.5))
                (display " p99 ") (display (percentile 0.99))
                (display " max ") (display (percentile 1.0))
                (display " req/s ") (display (quotient (* 1000 (+ ok bad-status)) (max 1 (elapsed))))
                (newline)
                (exit 0))))))))
