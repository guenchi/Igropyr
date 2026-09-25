#!chezscheme
;;; (igropyr redis): a reply larger than the socket buffer must be parsed
;;; as it arrives, not restarted from byte zero on every segment.
;;;
;;; The defect this guards is COST, not correctness. A parser that reparses
;;; the accumulated buffer each time still returns the right value, just
;;; after work quadratic in the reply size -- so the value proves nothing
;;; and the elapsed time is the assertion that matters.
;;;
;;; Fragmentation needs no help, and cannot be faked by writing small
;;; pieces: the loopback coalesces, and 64000 one-byte writes were measured
;;; arriving as FOUR segments of ~16 KB. What produces segments is a reply
;;; bigger than the socket buffer. Size is the knob.
;;;
;;; The companion check on a fragmented LINE lived here until max-resp-line
;;; was introduced: under the default limits a line long enough to show
;;; quadratic rescanning is refused outright, so the input cannot be built. redis-limits.sc asserts
;;; that ceiling instead.
;;;
;;; THE ASSERTION IS A RATIO, NOT A BUDGET IN MILLISECONDS (2026-09-25). It
;;; was a 250 ms budget, chosen on one machine where resumable parsing took
;;; ~65 ms and reparsing ~610 ms. On a slower FreeBSD host resumable parsing
;;; alone took 234-236 ms in five runs and 264 ms inside the whole-suite run,
;;; so the budget failed a correct parser. Now the same reply shape is timed at
;;; two sizes, N and 2N, in the same process: resumable parsing is linear, so
;;; the larger takes about twice as long; reparsing from zero is quadratic, so
;;; about four times. The line is at three. The sizes are timed alternately,
;;; small, large, small, large, and the faster of each pair kept, which makes
;;; it less likely -- not impossible -- that a collection or a busy moment
;;; lands on one size only.
;;;
;;; WHAT THIS DOES NOT CATCH. It is a regression check for restarting from
;;; zero, not a general complexity test. A cheaper quadratic term hidden in
;;; the resumption (review, 2026-09-25: recounting the items gathered so far
;;; on every resume, measured in an isolated harness) stays under the line at
;;; these sizes, ratios 2.4-2.8. The second listener is one more fixed port,
;;; as every suite here uses.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp)
        (igropyr redis))

(define port-small 18813)
(define port-large 18819)
;; ~1.6 MB and ~3.2 MB of reply
(define n-small 400000)
(define n-large 800000)
(define ratio-limit 3)
(define failures 0)

(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (array-reply n)
  (let-values (((p get) (open-string-output-port)))
    (display "*" p) (display n p) (display "\r\n" p)
    (do ((i 0 (+ i 1))) ((= i n)) (display ":1\r\n" p))
    (get)))

;; the reply is encoded once, before any timing, so the timed interval is
;; the transfer and the client's parse, not the server building a string
(define (start-server! port reply)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid
              (spawn
                (lambda ()
                  (receive
                    (`#(tcp-data ,_)
                      (tcp-write! c reply #f)
                      (sleep-ms 100)
                      (tcp-close! c))
                    (`#(tcp-eof) (tcp-close! c))
                    (`#(tcp-error ,_) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

;; one PING against a server that answers with an n-element array:
;; milliseconds, and whether the value came back whole
(define (timed-ping port n)
  (let* ((r (redis-connect "127.0.0.1" port))
         (t0 (real-time))
         (v (redis r "PING"))
         (ms (- (real-time) t0)))
    (redis-close! r)
    (values ms (and (list? v) (= (length v) n) (for-all (lambda (x) (= x 1)) v)))))


(start-scheduler
  (lambda ()
    (start-server! port-small (string->utf8 (array-reply n-small)))
    (start-server! port-large (string->utf8 (array-reply n-large)))
    (sleep-ms 100)
    (let*-values (((s1 ok-s1) (timed-ping port-small n-small))
                  ((l1 ok-l1) (timed-ping port-large n-large))
                  ((s2 ok-s2) (timed-ping port-small n-small))
                  ((l2 ok-l2) (timed-ping port-large n-large)))
      (define small (min s1 s2))
      (define large (min l1 l2))
      (check "fragmented array parses correctly" (and ok-s1 ok-l1 ok-s2 ok-l2))
      ;; the assertion that separates a resumable parser from one that
      ;; starts over at byte zero on every segment
      (let ((ratio (/ (max large 1) (max small 1))))
        (check "fragmented array parses in linear time" (< ratio ratio-limit))
        (display "  [timing] ") (display small) (display " ms at ") (display n-small)
        (display ", ") (display large) (display " ms at ") (display n-large)
        (display ", ratio ") (display (exact->inexact ratio))
        (display " (limit ") (display ratio-limit) (display ")\n")))
    (if (zero? failures)
        (begin (display "redis-incremental: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
