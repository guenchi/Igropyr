#!chezscheme
;;; (igropyr mysql) option validation -- no server needed, always runs.
;;;
;;; The one thing pinned here: a 'tls option (the postgresql client's
;;; idiom) must be REJECTED, not silently ignored -- ignoring it would
;;; hand the caller a plaintext connection while they believe the
;;; traffic is encrypted, a silent security downgrade. Both entry
;;; points raise before any socket is opened, so this needs no MySQL.

(import (chezscheme) (igropyr actor) (igropyr mysql))

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define (rejects-tls? thunk)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'mysql-error)
                  (string? (vector-ref e 2))) #t)
            (#t #f))
    (thunk)
    #f))

(start-scheduler
  (lambda ()
    (check "connect-rejects-tls-opt"
      (rejects-tls?
        (lambda ()
          (mysql-connect "127.0.0.1" 3306 "u" "p" #f
                         (list (cons 'tls (lambda args 'never)))))))
    (check "pool-rejects-tls-opt"
      (rejects-tls?
        (lambda ()
          (mysql-pool 1 "127.0.0.1" 3306 "u" "p" #f
                      (list (cons 'tls (lambda args 'never)))))))
    (if (zero? failures)
        (begin (display "mysql-opts: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
