#!chezscheme
;;; RESP replies stay resumable across hostile one-byte-at-a-time delivery.

(import (chezscheme) (igropyr actor) (igropyr libuv)
        (igropyr redis))

(define port 18813)
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

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid
              (spawn
                (lambda ()
                  (receive
                    (`#(tcp-data ,_)
                      (let* ((bv (string->utf8 (array-reply 2000)))
                             (n (bytevector-length bv)))
                        (do ((i 0 (+ i 1))) ((= i n))
                          (let ((part (make-bytevector 1)))
                            (bytevector-u8-set! part 0 (bytevector-u8-ref bv i))
                            (tcp-write! c part #f))))
                      (sleep-ms 100)
                      (tcp-close! c))
                    (`#(tcp-eof) (tcp-close! c))
                    (`#(tcp-error ,_) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 100)
    (let ((r (redis-connect "127.0.0.1" port)))
      (let ((v (redis r "PING")))
        (check "fragmented array parses incrementally"
          (and (list? v) (= (length v) 2000)
               (for-all (lambda (x) (= x 1)) v))))
      (redis-close! r))
    (if (zero? failures)
        (begin (display "redis-incremental: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
