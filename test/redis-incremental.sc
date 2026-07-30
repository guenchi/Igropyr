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

(import (chezscheme) (igropyr actor) (igropyr libuv)
        (igropyr redis))

(define port 18813)
;; ~3 MB of reply. Measured: ~610 ms reparsing from zero, ~65 ms resumable,
;; both stable within a few percent, so 250 ms sits clear of either.
(define elements 800000)
(define budget-ms 250)
(define line-length (* 8 1024 1024))
(define line-budget-ms 750)
(define failures 0)
(define connection-number 0)

(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (array-reply n)
  (let-values (((p get) (open-string-output-port)))
    (display "*" p) (display n p) (display "\r\n" p)
    (do ((i 0 (+ i 1))) ((= i n)) (display ":1\r\n" p))
    (get)))

(define line-reply
  (let ((bv (make-bytevector (+ line-length 3) (char->integer #\x))))
    (bytevector-u8-set! bv 0 (char->integer #\+))
    (bytevector-u8-set! bv (+ line-length 1) 13)
    (bytevector-u8-set! bv (+ line-length 2) 10)
    bv))

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((reply-number connection-number))
        (set! connection-number (+ connection-number 1))
        (let ((pid
              (spawn
                (lambda ()
                  (receive
                    (`#(tcp-data ,_)
                      (tcp-write! c
                        (if (zero? reply-number)
                            (string->utf8 (array-reply elements))
                            line-reply)
                        #f)
                      (sleep-ms 100)
                      (tcp-close! c))
                    (`#(tcp-eof) (tcp-close! c))
                    (`#(tcp-error ,_) (tcp-close! c)))))))
          (conn-set-owner! c pid)
          (tcp-read-start! c))))
    0))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 100)
    (let ((r (redis-connect "127.0.0.1" port)))
      (let* ((t0 (real-time))
             (v (redis r "PING"))
             (ms (- (real-time) t0)))
        (check "fragmented array parses correctly"
          (and (list? v) (= (length v) elements)
               (for-all (lambda (x) (= x 1)) v)))
        ;; the assertion that separates a resumable parser from one that
        ;; starts over at byte zero on every segment
        (check "fragmented array parses in linear time" (< ms budget-ms))
        (display "  [timing] ") (display ms) (display " ms of ")
        (display budget-ms) (display " ms budget\n"))
      (redis-close! r))
    (collect)
    (let ((r (redis-connect "127.0.0.1" port)))
      (let* ((t0 (real-time))
             (v (redis r "PING"))
             (ms (- (real-time) t0)))
        (check "fragmented line parses correctly"
          (and (string? v)
               (= (string-length v) line-length)
               (char=? (string-ref v 0) #\x)
               (char=? (string-ref v (- line-length 1)) #\x)))
        ;; A saved CRLF cursor makes the total scan linear in the reply.
        (check "fragmented line parses in linear time" (< ms line-budget-ms))
        (display "  [line timing] ") (display ms) (display " ms of ")
        (display line-budget-ms) (display " ms budget\n"))
      (redis-close! r))
    (if (zero? failures)
        (begin (display "redis-incremental: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
