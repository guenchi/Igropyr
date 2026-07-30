#!chezscheme
;;; RESP byte, item, depth, and line ceilings against a hostile server.

(import (chezscheme) (igropyr actor) (igropyr libuv)
        (igropyr redis) (igropyr util))

(define port 18813)
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

(start-scheduler
  (lambda ()
    (set! responses
      (list "$16777217\r\n"
            "*65537\r\n"
            (deep-reply 65)
            (string-append "+" (make-string 1025 #\a))
            (array-reply 65536 "*0\r\n")))
    (start-server!)
    (sleep-ms 100)
    (for-each
      (lambda (case)
        (let ((msg (redis-error-message one-call)))
          (check (car case)
            (and (string? msg) (string-contains? msg (cdr case))))))
      '(("oversized bulk declaration" . "bulk reply too large")
        ("oversized array declaration" . "array reply too large")
        ("excessive reply nesting" . "reply nesting too deep")
        ("unterminated reply line" . "reply line too long")
        ("aggregate reply item cap" . "reply has too many items")))
    (if (zero? failures)
        (begin (display "redis-limits: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
