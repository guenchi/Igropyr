#!chezscheme
;;; RESP byte, item, depth and line ceilings against a hostile server.
;;;
;;; Each case lowers the ceiling it is about to something it can reach,
;;; instead of building a reply large enough to hit the shipped default.
;;; The defaults sit where no legitimate Redis reply arrives -- LRANGE and
;;; SMEMBERS return hundreds of thousands of elements, and one value may be
;;; 512 MiB -- so testing them at face value would mean sending half a
;;; gigabyte to prove a constant.
;;;
;;; Each case asserts the ceiling is enforced AND that the failure is a
;;; protocol error rather than a hang or a wrong value: a malformed reply
;;; desynchronises the stream, so the only correct outcome is to tell every
;;; waiter and drop the connection.

(import (chezscheme) (igropyr actor) (igropyr libuv)
        (igropyr redis) (igropyr util))

(define port 18815)
(define failures 0)
(define responses '())

(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (deep-reply n)
  (let-values (((p get) (open-string-output-port)))
    (do ((i 0 (+ i 1))) ((= i n)) (display "*1\r\n" p))
    (display "+x\r\n" p)
    (get)))

(define (array-reply n item)
  (let-values (((p get) (open-string-output-port)))
    (display "*" p) (display n p) (display "\r\n" p)
    (do ((i 0 (+ i 1))) ((= i n)) (display item p))
    (get)))

(define (next-response!)
  (with-interrupts-disabled
    (let ((x (car responses)))
      (set! responses (cdr responses))
      x)))

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((reply (next-response!)))
        (let ((pid
                (spawn
                  (lambda ()
                    (receive
                      (`#(tcp-data ,_)
                        (tcp-write! c (string->utf8 reply) #f)
                        (sleep-ms 100)
                        (tcp-close! c))
                      (`#(tcp-eof) (tcp-close! c))
                      (`#(tcp-error ,_) (tcp-close! c)))))))
          (conn-set-owner! c pid)
          (tcp-read-start! c))))
    0))

(define (redis-error-message thunk)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'redis-error))
             (vector-ref e 1)))
    (thunk)
    'no-error))

(define (one-call)
  (let ((r (redis-connect "127.0.0.1" port)))
    (let ((v (guard (e (#t (redis-close! r) (raise e)))
               (redis r "PING"))))
      (redis-close! r)
      v)))

;; (label tighten reply expected-fragment)
(define cases
  (list
    (list "oversized bulk declaration"
          (lambda () (redis-set-limits! 1024 #f #f #f #f))
          "$1025\r\n"
          "bulk reply too large")
    (list "oversized array declaration"
          (lambda () (redis-set-limits! #f 8 #f #f #f))
          "*9\r\n"
          "array reply too large")
    (list "excessive reply nesting"
          (lambda () (redis-set-limits! #f #f #f 4 #f))
          (deep-reply 5)
          "reply nesting too deep")
    (list "unterminated reply line"
          (lambda () (redis-set-limits! #f #f #f #f 64))
          (string-append "+" (make-string 100 #\a))
          "reply line too long")
    (list "aggregate reply item cap"
          ;; every element is legal on its own and the array is well inside
          ;; its own ceiling: only the running total refuses this one
          (lambda () (redis-set-limits! #f 1000 4 #f #f))
          (array-reply 8 "*0\r\n")
          "reply has too many items")))

(start-scheduler
  (lambda ()
    (set! responses (map caddr cases))
    (start-server!)
    (sleep-ms 100)
    (for-each
      (lambda (c)
        ;; back to generous first, then tighten only the ceiling under
        ;; test: no case may pass because an earlier one left one low
        (redis-set-limits! (* 512 1024 1024) 4000000 8000000 64 1024)
        ((cadr c))
        (let ((msg (redis-error-message one-call)))
          (check (car c)
            (and (string? msg) (string-contains? msg (cadddr c))))))
      cases)
    (if (zero? failures)
        (begin (display "redis-limits: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
