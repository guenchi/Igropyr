#!chezscheme
;;; mysql-observe! and mysql-query share one cfg object -- and that is
;;; the whole test.
;;;
;;; WHY THIS EXISTS AS ITS OWN FILE. test/mysql.sc needs a live server
;;; and gates on IGROPYR_MYSQL_TEST, so on most machines it never runs;
;;; this property must not hide behind that gate, because it needs no
;;; server at all. The engine side -- where the observer runs, that a
;;; raising observer cannot reach the caller, the failure counter -- is
;;; covered in test/connpool-lifecycle.sc against fake cfgs. What none
;;; of that can see is the one thing that once went wrong in design:
;;; an install that wrote the observer into a COPY of the driver cfg
;;; while dispatch read the original. Both compile, every engine test
;;; stays green, and the observer is silently never called. The two
;;; bindings live in one module and nothing outside it can compare
;;; them, so the only way to check is to drive one against the other.
;;;
;;; NO DATABASE. connpool-call runs the observer BEFORE it sends the
;;; statement to the handle, and the handle is whatever the caller
;;; passed -- so a plain actor that answers the pool protocol is a
;;; complete stand-in: mysql-query dispatches through the REAL driver
;;; cfg (the observer, the error predicate, the timeouts), and only
;;; the connection at the far end is fake.

(import (chezscheme) (igropyr actor) (igropyr mysql))

(define failures 0)
(define (fail label detail)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label) (display " ") (write detail) (newline))
(define (check label ok . detail)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (apply fail label detail)))

(start-scheduler
  (lambda ()
    ;; a connection that answers every request with an innocuous row --
    ;; the protocol is connpool's, the cfg the call runs under is mysql's
    (define (spawn-fake!)
      (spawn
        (lambda ()
          (let loop ()
            (receive
              (`#(pool-request ,sql ,ref ,from)
                (send from (vector 'pool-reply ref '(("ok" . 1))))
                (loop))
              (`#(pool-request-cancel ,ref ,from) (loop)))))))

    ;; ---- the installed observer is the dispatched observer ---------------
    (let ((seen (box '()))
          (fake (spawn-fake!)))
      (mysql-observe!
        (lambda (conn sql) (set-box! seen (cons (cons conn sql)
                                                (unbox seen)))))
      (let ((r (guard (e (#t (cons 'raised e)))
                 (mysql-query fake "SELECT 1"))))
        (check "the query itself went through the fake connection"
               (equal? r '(("ok" . 1))) r))
      (let ((hits (reverse (unbox seen))))
        (check "the observer installed by mysql-observe! saw the dispatch"
               (= (length hits) 1) hits)
        ;; the pair carries evidence, not authority: the handle it was
        ;; ABOUT and the statement text, exactly as dispatched
        (check "...with the handle and the statement, as dispatched"
               (and (pair? hits)
                    (eq? (car (car hits)) fake)
                    (equal? (cdr (car hits)) "SELECT 1"))
               hits))

      ;; ---- and uninstalling really uninstalls -----------------------------
      ;; the same one-object property from the other side: a #f written
      ;; through mysql-observe! must be the #f dispatch reads, or an
      ;; application that turns tracing off keeps paying for it
      (mysql-observe! #f)
      (set-box! seen '())
      (let ((r (guard (e (#t (cons 'raised e)))
                 (mysql-query fake "SELECT 2"))))
        (check "a query still answers after the observer is removed"
               (equal? r '(("ok" . 1))) r))
      (check "...and the removed observer saw nothing"
             (null? (unbox seen)) (unbox seen))
      (kill fake 'done))

    (if (= failures 0)
        (begin (display "mysql-observe: all tests passed\n") (exit 0))
        (begin (display (number->string failures))
               (display " failures\n")
               (exit 1)))))
