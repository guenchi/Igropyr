#!chezscheme
;;; (igropyr postgresql) end-to-end against a REAL PostgreSQL server.
;;;
;;; Needs a live PostgreSQL, so it is opt-in: it runs only when
;;; IGROPYR_PG_TEST is set, and skips (exit 0) otherwise, keeping
;;; run-all.sh deterministic on machines without a database. Point it at a
;;; scratch database whose user may CREATE/DROP a table:
;;;
;;;   IGROPYR_PG_TEST=1 PG_HOST=127.0.0.1 PG_PORT=5432 \
;;;   PG_USER=... PG_PASSWORD=... PG_DB=igropyr_test \
;;;   chez --script igropyr/test/postgresql-e2e.sc
;;;
;;; It exercises the whole wire path -- SCRAM-SHA-256 auth, the simple
;;; query protocol (RowDescription/DataRow/CommandComplete/ErrorResponse),
;;; and the pool + transaction leases: that a transaction gives a private
;;; connection for the whole BEGIN..COMMIT so SELECT..FOR UPDATE serialises
;;; concurrent writers (no lost updates), rolls back on escape, never leaks
;;; a connection, and reclaims + rebuilds a connection whose borrower is
;;; killed mid-transaction (dynamic-wind does NOT run then).

;; NOTE: importing (igropyr tls) below loads OpenSSL at import time, so
;; running THIS file needs OpenSSL installed even when the PG_TLS section
;; is skipped (run-all.sh already requires OpenSSL via test/tls.sc).
(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr postgresql)
        (only (igropyr tls) tls-establish!))

(define (env k d) (or (getenv k) d))

(unless (getenv "IGROPYR_PG_TEST")
  (display "postgresql-e2e: SKIP (set IGROPYR_PG_TEST + PG_* to run)\n")
  (exit 0))

(define host (env "PG_HOST" "127.0.0.1"))
(define port (string->number (env "PG_PORT" "5432")))
(define user (env "PG_USER" "postgres"))
(define pass (env "PG_PASSWORD" ""))
(define db   (env "PG_DB" "igropyr_test"))

(define table "_igropyr_tx_test")

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))
(define (fail msg) (display "FAIL: ") (display msg) (newline) (exit 1))

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
                 (display "postgresql-e2e: SKIP (cannot connect: ")
                 (write e) (display ")\n")
                 (exit 0)))
        ;; a lone connect proves reachability + SCRAM auth before the pool
        (postgreconnpool-close! (postgresql-connect host port user pass db))
        (postgresql-pool 4 host port user pass db)))

    ;; ---- basic query shapes -------------------------------------------------
    (check "select-scalar" (= 1 (scalar-num (postgreconnpool-call pool "SELECT 1"))))
    (let ((r (postgreconnpool-call pool "SELECT 1 AS a, 'x' AS b")))
      (check "rows-shape"
        (and (vector? r) (eq? (vector-ref r 0) 'rows)
             (equal? (vector-ref r 1) '("a" "b"))
             (equal? (vector-ref r 2) '(("1" "x"))))))
    (check "null-is-#f"
      (let ((r (postgreconnpool-call pool "SELECT NULL")))
        (and (eq? (vector-ref r 0) 'rows)
             (equal? (vector-ref r 2) '((#f))))))
    ;; a server SQL error carries its SQLSTATE and leaves the pool usable
    (check "sql-error-sqlstate"
      (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'postgresql-error))
                 (string? (vector-ref e 1))))       ; 5-char SQLSTATE, not 'transport
        (postgreconnpool-call pool "SELECT * FROM no_such_table_xyz") #f))
    (check "pool-alive-after-sql-error"
      (= 1 (scalar-num (postgreconnpool-call pool "SELECT 1"))))

    ;; ---- fresh table + affected-row counts ----------------------------------
    (postgreconnpool-call pool (string-append "DROP TABLE IF EXISTS " table))
    (postgreconnpool-call pool
      (string-append "CREATE TABLE " table " (id INT PRIMARY KEY, val INT NOT NULL)"))
    (let ((r (postgreconnpool-call pool
               (string-append "INSERT INTO " table " (id,val) VALUES (1,0)"))))
      (check "insert-affected" (equal? r (vector 'ok 1))))

    ;; ---- 1. commit persists -------------------------------------------------
    (postgresql-transaction pool
      (lambda (c)
        (postgreconnpool-call c (string-append "UPDATE " table " SET val=7 WHERE id=1"))))
    (check "commit-persists"
      (= 7 (scalar-num (postgreconnpool-call pool
             (string-append "SELECT val FROM " table " WHERE id=1")))))

    ;; ---- 2. escape rolls back, connection returns to the pool ---------------
    (check "rollback-raises"
      (guard (e (#t #t))
        (postgresql-transaction pool
          (lambda (c)
            (postgreconnpool-call c (string-append "UPDATE " table " SET val=999 WHERE id=1"))
            (raise 'boom)))
        #f))
    (check "rollback-reverted"
      (= 7 (scalar-num (postgreconnpool-call pool
             (string-append "SELECT val FROM " table " WHERE id=1")))))
    (check "pool-alive-after-rollback"
      (= 1 (scalar-num (postgreconnpool-call pool "SELECT 1"))))

    ;; ---- 3. FOR UPDATE serialises concurrent writers (no lost updates) ------
    (postgreconnpool-call pool (string-append "UPDATE " table " SET val=0 WHERE id=1"))
    (let ((n 20) (p3 (postgresql-pool 3 host port user pass db)))
      (do ((i 0 (+ i 1))) ((= i n))
        (spawn (lambda ()
          (postgresql-transaction p3
            (lambda (c)
              (let ((v (scalar-num
                         (postgreconnpool-call c
                           (string-append "SELECT val FROM " table
                                          " WHERE id=1 FOR UPDATE")))))
                (postgreconnpool-call c
                  (string-append "UPDATE " table " SET val="
                    (number->string (+ v 1)) " WHERE id=1")))))
          (send main (vector 'done)))))
      (let loop ((k 0))
        (when (< k n)
          (receive (after 20000 (fail "concurrency: workers did not finish"))
            (`#(done) (loop (+ k 1))))))
      (postgreconnpool-close! p3)
      (check "for-update-no-lost-updates"
        (= n (scalar-num (postgreconnpool-call pool
               (string-append "SELECT val FROM " table " WHERE id=1"))))))

    ;; ---- 4. no connection leak: far more transactions than pool size --------
    (let ((m 40))
      (let loop ((i 0))
        (when (< i m)
          (postgresql-transaction pool (lambda (c) (postgreconnpool-call c "SELECT 1")))
          (loop (+ i 1))))
      (check "no-leak-sequential"
        (= 1 (scalar-num (postgreconnpool-call pool "SELECT 1")))))

    ;; ---- 5. a borrower killed mid-transaction is reclaimed + rebuilt --------
    (let ((p1 (postgresql-pool 1 host port user pass db)))
      (let ((victim
             (spawn (lambda ()
               (postgresql-transaction p1
                 (lambda (c)
                   (postgreconnpool-call c "SELECT 1")
                   (send main (vector 'holding))
                   (receive (`#(never) 'unreached))))))))
        (receive (after 5000 (fail "reclaim: victim never acquired the connection"))
          (`#(holding) 'ok))
        (kill victim 'test-kill)
        (check "reclaim-after-kill"
          (equal? 42
            (guard (e (#t #f))
              (postgresql-transaction p1
                (lambda (c) (scalar-num (postgreconnpool-call c "SELECT 42"))))))))
      (postgreconnpool-close! p1))

    ;; ---- 6. extended query protocol: postgresql-execute ---------------------
    (let ((evil "Robert'); DROP TABLE students;--"))
      ;; values travel out-of-band: quoting characters are data, not SQL
      (postgreconnpool-call pool
        (string-append "DROP TABLE IF EXISTS " table "_ex"))
      (postgreconnpool-call pool
        (string-append "CREATE TABLE " table
                       "_ex (id INT PRIMARY KEY, name TEXT, score REAL)"))
      (check "execute-insert-params"
        (equal? (vector 'ok 1)
                (postgresql-execute pool
                  (string-append "INSERT INTO " table
                                 "_ex (id, name, score) VALUES ($1, $2, $3)")
                  1 evil 2.5)))
      (check "execute-select-param"
        (let ((r (postgresql-execute pool
                   (string-append "SELECT name FROM " table "_ex WHERE id = $1")
                   1)))
          (equal? (vector-ref r 2) (list (list evil)))))   ; injection stayed data
      (check "execute-null-param"
        (equal? (vector 'ok 1)
                (postgresql-execute pool
                  (string-append "INSERT INTO " table
                                 "_ex (id, name) VALUES ($1, $2)")
                  2 #f)))
      (check "execute-null-roundtrip"
        (let ((r (postgresql-execute pool
                   (string-append "SELECT name FROM " table "_ex WHERE id = $1")
                   2)))
          (equal? (vector-ref r 2) '((#f)))))
      ;; non-finite floats round-trip: PostgreSQL spells them Infinity/NaN
      (check "execute-infinity-roundtrip"
        (equal? '(("Infinity" "NaN"))
                (vector-ref (postgresql-execute pool
                              "SELECT $1::float8::text, $2::float8::text"
                              +inf.0 +nan.0)
                            2)))
      ;; >65535 parameters is a caller error caught CALLER-side: the pool
      ;; connection must stay healthy
      (check "execute-too-many-params-asserts"
        (guard (e ((not (and (vector? e)
                             (eq? (vector-ref e 0) 'postgresql-error)))
                   #t))
          (apply postgresql-execute pool "SELECT 1"
                 (vector->list (make-vector 65536 1)))
          #f))
      (check "pool-alive-after-param-overflow"
        (= 1 (scalar-num (postgreconnpool-call pool "SELECT 1"))))
      ;; a server error over the extended flow keeps the connection framed
      (check "execute-error-sqlstate"
        (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'postgresql-error))
                   (string? (vector-ref e 1))))
          (postgresql-execute pool "SELECT * FROM no_such_table_xyz WHERE a = $1" 1)
          #f))
      (check "pool-alive-after-execute-error"
        (= 1 (scalar-num (postgreconnpool-call pool "SELECT 1"))))
      (postgreconnpool-call pool (string-append "DROP TABLE IF EXISTS " table "_ex")))

    ;; ---- 7. TLS (extra opt-in: server needs ssl=on and SSL_CERT_FILE must
    ;;         point at its certificate, self-signed being its own CA) -------
    (when (getenv "PG_TLS")
      (let ((topts (list (cons 'tls tls-establish!))))
        (let ((conn (postgresql-connect host port user pass db topts)))
          (check "tls-scram-connect"
            (= 1 (scalar-num (postgreconnpool-call conn "SELECT 1"))))
          ;; the backend itself must see this session as SSL
          (check "tls-backend-sees-ssl"
            (equal? "true"
                    (scalar (postgreconnpool-call conn
                      "SELECT ssl::text FROM pg_stat_ssl WHERE pid = pg_backend_pid()"))))
          (check "tls-execute-params"
            (let ((r (postgresql-execute conn "SELECT $1 || $2" "en" "crypted")))
              (equal? (vector-ref r 2) '(("encrypted")))))
          (postgreconnpool-close! conn))
        ;; pool over TLS: rebuild machinery composes with the codec
        (let ((p2 (postgresql-pool 2 host port user pass db topts)))
          (check "tls-pool-query"
            (= 7 (scalar-num (postgreconnpool-call p2 "SELECT 7"))))
          (postgreconnpool-close! p2))))

    ;; ---- done ---------------------------------------------------------------
    (postgreconnpool-call pool (string-append "DROP TABLE IF EXISTS " table))
    (postgreconnpool-close! pool)
    (sleep-ms 50)
    (if (zero? failures)
        (begin (display "postgresql-e2e: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
