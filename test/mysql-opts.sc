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
    ;; ---- the installer writes the cfg the queries read -----------------
    ;;
    ;; mysql-observe! sets an observer on this module's cfg, and
    ;; mysql-query closes over that same cfg. Those are two bindings, and
    ;; nothing makes them one except that they are written that way today:
    ;; give the driver a cfg per pool, or hand the installer a copy, and
    ;; the observer is installed on something no statement reads. It
    ;; would not raise, it would not warn -- it would see nothing, which
    ;; is exactly what an unused observer looks like. That is the shape
    ;; this whole feature was built to remove, so it is pinned in the
    ;; place it can still occur.
    ;;
    ;; NO SERVER IS NEEDED for that: connpool is blind to what a
    ;; connection speaks, so a process that answers pool-request is a
    ;; connection as far as mysql-query is concerned -- while the cfg it
    ;; consults is this module's real one, which is the thing under test.
    (let ((seen '()))
      (mysql-observe! (lambda (conn sql) (set! seen (cons sql seen))))
      (let ((worker (spawn (lambda ()
                             (let loop ()
                               (receive
                                 (`#(pool-request ,sql ,r ,from)
                                   (send from
                                     (vector 'pool-reply r
                                             (vector 'rows sql)))
                                   (loop))))))))
        (let ((r (mysql-query worker "SELECT 1")))
          (check "a statement through the driver's own entry is answered"
                 (equal? r (vector 'rows "SELECT 1")))
          (check "and the observer installed on the driver saw exactly it"
                 (equal? (reverse seen) (list "SELECT 1")))))
      (mysql-observe! #f))

    (if (zero? failures)
        (begin (display "mysql-opts: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
