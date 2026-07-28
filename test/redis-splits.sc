#!chezscheme
;;; (igropyr redis) RESP parsing: the same value at every split offset.
;;;
;;; A resumable parser is only as good as its worst cut, and the cuts that
;;; break one land mid-structure -- between the elements of a nested array,
;;; inside a bulk payload, before a terminator. Rather than guess at them,
;;; send one reply exercising every RESP type (status, integer, bulk,
;;; nested array, nil, error, empty array, and a bulk string that is NOT
;;; valid UTF-8, so the binary-safe path is live) and deliver it split at
;;; EVERY byte offset, one offset per command. Any offset that parses
;;; differently is a resumption bug.
;;;
;;; No server needed: the fake below speaks the wire format directly.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr redis))

(define port 18815)
(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

;; a bulk string with a lone 0xFF byte: invalid UTF-8, must come back raw
(define binary-bulk
  (let ((bv (make-bytevector 3)))
    (bytevector-u8-set! bv 0 1)
    (bytevector-u8-set! bv 1 255)
    (bytevector-u8-set! bv 2 2)
    bv))

(define reply-bv
  (let ((head (string->utf8
                (string-append
                  "*8\r\n"
                  "+OK\r\n"
                  ":42\r\n"
                  "$5\r\nhello\r\n"
                  "*2\r\n:1\r\n$3\r\nabc\r\n"
                  "$-1\r\n"
                  "-ERR bad thing\r\n"
                  "*0\r\n"
                  "$3\r\n")))
        (tail (string->utf8 "\r\n")))
    (let* ((n (+ (bytevector-length head) 3 (bytevector-length tail)))
           (out (make-bytevector n)))
      (bytevector-copy! head 0 out 0 (bytevector-length head))
      (bytevector-copy! binary-bulk 0 out (bytevector-length head) 3)
      (bytevector-copy! tail 0 out (+ (bytevector-length head) 3)
                        (bytevector-length tail))
      out)))

(define (expected? v)
  (and (list? v) (= (length v) 8)
       (equal? (list-ref v 0) "OK")
       (eqv? (list-ref v 1) 42)
       (equal? (list-ref v 2) "hello")
       (let ((inner (list-ref v 3)))
         (and (list? inner) (= (length inner) 2)
              (eqv? (car inner) 1) (equal? (cadr inner) "abc")))
       (eq? (list-ref v 4) #f)
       (let ((e (list-ref v 5)))
         (and (vector? e) (eq? (vector-ref e 0) 'redis-error)
              (equal? (vector-ref e 1) "ERR bad thing")))
       (null? (list-ref v 6))
       ;; the binary bulk: invalid UTF-8, so it must come back as raw bytes
       ;; rather than a string with substituted U+FFFD
       (equal? (list-ref v 7) binary-bulk)))

(define (bv-sub bv a b)
  (let ((r (make-bytevector (- b a))))
    (bytevector-copy! bv a r 0 (- b a))
    r))

(define split-at 0)

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid (spawn
                   (lambda ()
                     (let serve ()
                       (receive
                         (`#(tcp-data ,_)
                           (let ((k split-at)
                                 (n (bytevector-length reply-bv)))
                             (if (or (<= k 0) (>= k n))
                                 (tcp-write! c reply-bv #f)
                                 (begin
                                   (tcp-write! c (bv-sub reply-bv 0 k) #f)
                                   (sleep-ms 1)
                                   (tcp-write! c (bv-sub reply-bv k n) #f))))
                           (serve))
                         (`#(tcp-eof) (tcp-close! c))
                         (`#(tcp-error ,_) (tcp-close! c))))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 100)
    (let ((r (redis-connect "127.0.0.1" port))
          (n (bytevector-length reply-bv)))
      (display "reply is ") (display n) (display " bytes; ")
      (display "testing every split offset\n")
      (do ((k 0 (+ k 1))) ((> k n))
        (set! split-at k)
        (let ((v (redis r "PING")))
          (unless (expected? v)
            (check (string-append "split at " (number->string k)) #f)
            (when (< failures 4) (display "    got: ") (write v) (newline)))))
      (redis-close! r))
    (if (zero? failures)
        (begin (display "redis-splits: every split offset parses identically\n")
               (exit 0))
        (begin (display failures) (display " failing offsets\n") (exit 1)))))
