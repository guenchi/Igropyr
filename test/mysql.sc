#!chezscheme
;;; (igropyr mysql) transaction leases against a REAL MySQL server.
;;;
;;; This test needs a live MySQL, so it is opt-in: it runs only when
;;; IGROPYR_MYSQL_TEST is set, and skips (exit 0) otherwise, which keeps
;;; run-all.sh deterministic on machines without a database. Point it at a
;;; scratch database whose user may CREATE/DROP a table:
;;;
;;;   IGROPYR_MYSQL_TEST=1 MYSQL_HOST=127.0.0.1 MYSQL_PORT=3306 \
;;;   MYSQL_USER=... MYSQL_PASSWORD=... MYSQL_DB=igropyr_test \
;;;   chez --script igropyr/test/mysql.sc
;;;
;;; What it pins is exactly the property ynthu's money paths depend on:
;;; that mysql-transaction gives a private connection for the whole
;;; BEGIN..COMMIT, so SELECT..FOR UPDATE actually serialises concurrent
;;; writers (no lost updates), rolls back on escape, never leaks a
;;; connection across many transactions, and -- the reason the pool
;;; monitors its borrowers -- reclaims and rebuilds a connection whose
;;; borrower is killed mid-transaction (dynamic-wind does NOT run then).

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr mysql))

(define (env k d) (or (getenv k) d))

;; ---- opt-in gate: skip cleanly when no database is configured -------------
(unless (getenv "IGROPYR_MYSQL_TEST")
  (display "mysql: SKIP (set IGROPYR_MYSQL_TEST + MYSQL_* to run)\n")
  (exit 0))

(define host (env "MYSQL_HOST" "127.0.0.1"))
(define port (string->number (env "MYSQL_PORT" "3306")))
(define user (env "MYSQL_USER" "root"))
(define pass (env "MYSQL_PASSWORD" ""))
(define db   (env "MYSQL_DB" "igropyr_test"))
;; localhost only: permit caching_sha2 full auth over the plaintext dev socket
(define opts '((allow-insecure-auth . #t)))

(define table "_igropyr_tx_test")

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))
(define (fail msg) (display "FAIL: ") (display msg) (newline) (exit 1))

;; SELECT that returns a single scalar cell as a string (or #f)
(define (scalar r)
  (and (vector? r) (eq? (vector-ref r 0) 'rows)
       (pair? (vector-ref r 2))
       (car (car (vector-ref r 2)))))
(define (scalar-num r) (let ((s (scalar r))) (and s (string->number s))))

(start-scheduler
  (lambda ()
    (define main self)

    ;; ---- connect (skip if the server is unreachable) ------------------------
    (define pool
      (guard (e (#t
                 (display "mysql: SKIP (cannot connect: ")
                 (write e) (display ")\n")
                 (exit 0)))
        ;; a lone connect proves reachability + auth before we build the pool
        (mysql-close! (mysql-connect host port user pass db opts))
        (mysql-pool 4 host port user pass db opts)))

    ;; ---- fresh table --------------------------------------------------------
    (mysql-query pool (string-append "DROP TABLE IF EXISTS " table))
    (mysql-query pool
      (string-append "CREATE TABLE " table
        " (id INT PRIMARY KEY, val INT NOT NULL) ENGINE=InnoDB"))
    (mysql-query pool (string-append "INSERT INTO " table " (id,val) VALUES (1,0)"))

    ;; ---- 1. commit persists -------------------------------------------------
    (mysql-transaction pool
      (lambda (c)
        (mysql-query c (string-append "UPDATE " table " SET val=7 WHERE id=1"))))
    (check "commit-persists"
      (= 7 (scalar-num (mysql-query pool
             (string-append "SELECT val FROM " table " WHERE id=1")))))

    ;; ---- 2. escape rolls back, and the connection comes back to the pool -----
    (check "rollback-raises"
      (guard (e (#t #t))
        (mysql-transaction pool
          (lambda (c)
            (mysql-query c (string-append "UPDATE " table " SET val=999 WHERE id=1"))
            (raise 'boom)))
        #f))                                   ; should not reach here
    (check "rollback-reverted"
      (= 7 (scalar-num (mysql-query pool
             (string-append "SELECT val FROM " table " WHERE id=1")))))
    ;; the connection that ran the rolled-back txn must be reusable
    (check "pool-alive-after-rollback"
      (= 1 (scalar-num (mysql-query pool "SELECT 1"))))

    ;; ---- 3. FOR UPDATE serialises concurrent writers (no lost updates) -------
    ;;    N transactions each do  SELECT val FOR UPDATE; UPDATE val = val+1.
    ;;    On a pool smaller than N this also exercises checkout queueing.
    (mysql-query pool (string-append "UPDATE " table " SET val=0 WHERE id=1"))
    (let ((n 20) (p3 (mysql-pool 3 host port user pass db opts)))
      (do ((i 0 (+ i 1))) ((= i n))
        (spawn (lambda ()
          (mysql-transaction p3
            (lambda (c)
              (let ((v (scalar-num
                         (mysql-query c
                           (string-append "SELECT val FROM " table
                                          " WHERE id=1 FOR UPDATE")))))
                (mysql-query c
                  (string-append "UPDATE " table " SET val="
                    (number->string (+ v 1)) " WHERE id=1")))))
          (send main (vector 'done)))))
      (let loop ((k 0))
        (when (< k n)
          (receive (after 20000 (fail "concurrency: workers did not finish"))
            (`#(done) (loop (+ k 1))))))
      (mysql-close! p3)
      (check "for-update-no-lost-updates"
        (= n (scalar-num (mysql-query pool
               (string-append "SELECT val FROM " table " WHERE id=1"))))))

    ;; ---- 4. no connection leak: far more transactions than pool size --------
    (let ((m 40))
      (let loop ((i 0))
        (when (< i m)
          (mysql-transaction pool (lambda (c) (mysql-query c "SELECT 1")))
          (loop (+ i 1))))
      (check "no-leak-sequential"
        (= 1 (scalar-num (mysql-query pool "SELECT 1")))))

    ;; ---- 5. a borrower killed mid-transaction is reclaimed + rebuilt --------
    ;;    Pool of 1: the victim holds the ONLY connection with an open
    ;;    transaction, then is killed (its dynamic-wind checkin never runs).
    ;;    The pool must monitor -> destroy -> rebuild, so the next
    ;;    transaction still succeeds instead of parking forever.
    (let ((p1 (mysql-pool 1 host port user pass db opts)))
      (let ((victim
             (spawn (lambda ()
               (mysql-transaction p1
                 (lambda (c)
                   (mysql-query c "SELECT 1")      ; open txn, hold the conn
                   (send main (vector 'holding))
                   (receive (`#(never) 'unreached))))))))  ; park forever
        (receive (after 5000 (fail "reclaim: victim never acquired the connection"))
          (`#(holding) 'ok))
        (kill victim 'test-kill)
        (check "reclaim-after-kill"
          (equal? 42
            (guard (e (#t #f))
              (mysql-transaction p1
                (lambda (c) (scalar-num (mysql-query c "SELECT 42"))))))))
      (mysql-close! p1))

    ;; ---- done ---------------------------------------------------------------
    (mysql-query pool (string-append "DROP TABLE IF EXISTS " table))
    (mysql-close! pool)
    (sleep-ms 50)
    (if (zero? failures)
        (begin (display "mysql: all transaction tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
