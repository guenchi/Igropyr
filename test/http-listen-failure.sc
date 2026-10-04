#!chezscheme
;;; test/http-listen-failure.sc -- an http-listen that fails to start leaves
;;; nothing behind.
;;;
;;; http-listen starts the worker pool (its supervisor, its workers, its
;;; ticker) before it has checked the host, built the TLS context or bound
;;; the port. When one of those failed, http-listen raised -- and the pool it
;;; had already started stayed alive, with no server record returned that
;;; anyone could shut down. Three failed starts with two workers each took the
;;; process count from 3 to 15 in the review that found it.
;;;
;;; THE READING IS THE PROCESS COUNT, before and after. Each failure path is
;;; tried several times; the count must come back to what it was before THAT
;;; attempt, every time (asynchronous teardown is waited for, not assumed),
;;; so one attempt's leak cannot hide behind another's. Afterwards a correct
;;; start on the same port must still work.
;;;
;;; The twin shows the counter measures the pool at all: a correct start
;;; raises it, and http-shutdown! brings it back. The second half of that
;;; is a reading of its own -- before this change http-shutdown! stopped the
;;; listener and drained the pool but left the pool's processes alive -- and
;;; the mechanism that releases a pool on a failed start is the one that
;;; releases it on shutdown.
;;;
;;; The three failure paths: an empty host; a TLS certificate that cannot be
;;; read; a port that is already bound. Each raises as it always did -- what
;;; changes is what is left when it has.
;;;
;;; And shutdown still DRAINS before it stops the pool: a request whose
;;; handler is mid-flight when http-shutdown! is called completes with its
;;; response. A shutdown that stopped the pool at once would pass the count
;;; rows and fail that one. After the stop, a request arriving on a
;;; keep-alive connection that was established before (those stay open) is
;;; answered 503 and the connection closed -- not submitted to a pool that
;;; is gone and left to the client's timeout; a HEAD gets the 503 with no
;;; body, read on a raw socket so the bytes after the header terminator
;;; are seen (the client would discard them). Not measured: that the 503
;;; is written out in full before the close -- only back-pressure on the
;;; write could show a difference, and nothing here produces it.
;;;
;;; Not measured here: the ORDER of checks and acquisitions (a pool started
;;; and then released on a bad host reads the same as one never started;
;;; the count is the contract, the order a preference); a TLS context
;;; acquired and then released on a later failure (no counter exposes
;;; contexts); that the supervisor is registered critical only after the
;;; bind (deleting the registration passes here; its effect is pinned by
;;; test/http-ready.sc's second server, which opts out of it).

(import (chezscheme) (igropyr actor) (igropyr tcp) (igropyr http) (igropyr http-client)
        (only (igropyr libuv) now-ms))

(define port 18854)
(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define (handler req res) (void))
(define (slow-handler req res) (sleep-ms 400) (res-send! res (string->utf8 "late")))
(define (ok-handler req res) (res-send! res (string->utf8 "ok")))

;; -> 'raised or (started . server)
(define (try-listen opts)
  (guard (e (#t 'raised))
    (cons 'started (http-listen port handler opts))))

(define (settles-to? n)
  (let loop ((t 0))
    (cond ((= (process-count) n) #t)
          ((>= t 4000) #f)
          (else (sleep-ms 50) (loop (+ t 50))))))

(define (url path) (string-append "http://127.0.0.1:" (number->string port) path))

;; raw socket helpers: a kept connection the test can write to after shutdown
(define (index-of text sub from)
  (let ((n (string-length text)) (m (string-length sub)))
    (let loop ((i from))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring text i (+ i m))) i)
            (else (loop (+ i 1)))))))
(define (raw-connect!)
  (tcp-connect! "127.0.0.1" port self)
  (receive (after 3000 #f)
    (`#(tcp-connected ,c) (tcp-read-start! c) c)
    (`#(tcp-connect-failed ,e) #f)))
;; read until `until` has been seen (#f: until EOF), or the deadline; -> text
(define (raw-read-response ms until)
  (let ((deadline (+ (now-ms) ms)))
    (let loop ((acc ""))
      (if (and until (index-of acc until 0))
          acc
          (receive (after (max 1 (- deadline (now-ms))) acc)
            (`#(tcp-data ,bv) (loop (string-append acc (utf8->string bv))))
            (`#(tcp-eof) acc)
            (`#(tcp-error ,_) acc))))))

(start-scheduler
  (lambda ()
    (sleep-ms 50)
    ;; WARM-UP, before the baseline is read: the HTTP client keeps one
    ;; registry process for the life of the image, born on its first use.
    ;; The in-flight row below is this file's first use of the client, so
    ;; without this the count would sit one above every baseline taken
    ;; earlier and read as a leak that is not one.
    (let ((srv (http-listen port handler (list (cons 'host "127.0.0.1") (cons 'workers 1)))))
      (sleep-ms 100)
      (guard (e (#t (void)))
        (http-request 'GET (url "/warm-up") '((timeout . 3000) (reuse . #f))))
      (http-shutdown! srv)
      (sleep-ms 500))
    (let ((baseline (process-count)))
      (display "  [info] baseline processes: ") (display baseline) (newline)

      ;; ---- twin: a correct start and its shutdown are both visible ------------
      (let ((r (try-listen (list (cons 'host "127.0.0.1") (cons 'workers 2)))))
        (check "twin: a correct listen starts" (and (pair? r) (eq? (car r) 'started)) r)
        (sleep-ms 100)
        (check "twin: a running pool of 2 workers raises the process count above baseline"
               (> (process-count) baseline) (process-count) baseline)
        (when (pair? r) (http-shutdown! (cdr r)))
        (check "twin: shutting it down returns the count to baseline"
               (settles-to? baseline) (process-count) baseline))

      ;; ---- the three failures, each three times ----------------------------------
      (for-each
        (lambda (label opts)
          (do ((i 1 (+ i 1))) ((> i 3))
            (let* ((before (process-count))
                   (r (try-listen opts)))
              (check (string-append label ", attempt " (number->string i) ": raises")
                     (eq? r 'raised) r)
              (check (string-append label ", attempt " (number->string i)
                                    ": the process count returns to what it was")
                     (settles-to? before) (process-count) before))))
        '("an empty host" "an unreadable TLS certificate")
        (list (list (cons 'host "") (cons 'workers 2))
              (list (cons 'host "127.0.0.1") (cons 'workers 2)
                    (cons 'tls-cert "/nonexistent/igropyr-no-such.pem")
                    (cons 'tls-key "/nonexistent/igropyr-no-such.key"))))
      ;; a port already bound: hold it with a plain listener for the attempts
      (let ((holder (tcp-listen! "127.0.0.1" port 4 (lambda (c) (tcp-close! c)) 0)))
        (sleep-ms 50)
        (do ((i 1 (+ i 1))) ((> i 3))
          (let* ((before (process-count))
                 (r (try-listen (list (cons 'host "127.0.0.1") (cons 'workers 2)))))
            (check (string-append "a port already bound, attempt " (number->string i) ": raises")
                   (eq? r 'raised) r)
            (check (string-append "a port already bound, attempt " (number->string i)
                                  ": the process count returns to what it was")
                   (settles-to? before) (process-count) before)))
        (tcp-stop-listen! holder)
        (sleep-ms 100))

      ;; ---- shutdown drains the request in flight, then stops the pool -----------------
      (let* ((before (process-count))
             (srv (http-listen port slow-handler (list (cons 'host "127.0.0.1") (cons 'workers 2))))
             (me self))
        (sleep-ms 100)
        (spawn (lambda ()
                 (send me (vector 'reply
                                  (guard (e (#t (cons 'raised e)))
                                    (let ((r (http-request 'GET (url "/slow") '((timeout . 5000) (reuse . #f)))))
                                      (cons (response-status r) (utf8->string (response-body r)))))))))
        (sleep-ms 100)
        (http-shutdown! srv)
        (let ((reply (receive (after 6000 'no-reply) (`#(reply ,r) r))))
          (check "a request in flight when http-shutdown! is called still completes (drained before the stop)"
                 (equal? reply '(200 . "late")) reply))
        (check "  and the pool is gone afterwards" (settles-to? before) (process-count) before))

      ;; ---- after shutdown, a kept connection gets 503, not silence ---------------------
      (let* ((before (process-count))
             (srv (http-listen port ok-handler (list (cons 'host "127.0.0.1") (cons 'workers 2)))))
        (sleep-ms 100)
        (let ((r (guard (e (#t (cons 'raised e)))
                   (let ((r (http-request 'GET (url "/keep") '((timeout . 3000)))))
                     (cons (response-status r) (utf8->string (response-body r)))))))
          (check "setup: a request over a kept (reusable) connection" (equal? r '(200 . "ok")) r))
        (http-shutdown! srv)
        (sleep-ms 200)
        (let* ((t0 (now-ms))
               (r (guard (e (#t (cons 'raised (if (condition? e) (condition-message e) e))))
                    (let ((r (http-request 'GET (url "/after-shutdown") '((timeout . 4000)))))
                      (cons (response-status r) (utf8->string (response-body r))))))
               (ms (- (now-ms) t0)))
          (check "a request on the kept connection after shutdown is answered 503, not left to time out"
                 (and (pair? r) (eqv? (car r) 503) (< ms 3000)) r ms))
        (check "  and the count is back" (settles-to? before) (process-count) before))

      ;; ---- HEAD on a kept connection after shutdown: 503 with no body -------------------
      (let* ((before (process-count))
             (srv (http-listen port ok-handler (list (cons 'host "127.0.0.1") (cons 'workers 2))))
             (c (begin (sleep-ms 100) (raw-connect!))))
        (check "setup: a raw connection to the server" (and c #t))
        (when c
          (tcp-write! c (string->utf8 "GET /keep HTTP/1.1\r\nHost: x\r\n\r\n") #f)
          (let ((r (raw-read-response 3000 "\r\n\r\nok")))
            (check "setup: a GET over it is answered 200 and the connection kept"
                   (and (index-of r "HTTP/1.1 200" 0) (index-of r "\r\n\r\nok" 0)) r))
          (http-shutdown! srv)
          (sleep-ms 200)
          (tcp-write! c (string->utf8 "HEAD /after HTTP/1.1\r\nHost: x\r\n\r\n") #f)
          (let* ((r (raw-read-response 3000 #f))
                 (hend (index-of r "\r\n\r\n" 0)))
            (check "a HEAD on the kept connection after shutdown is answered 503"
                   (index-of r "HTTP/1.1 503" 0) r)
            (check "  with no body after the header terminator"
                   (and hend (= (+ hend 4) (string-length r))) r))
          (tcp-close! c))
        (check "  and the count is back" (settles-to? before) (process-count) before))

      ;; ---- and the same process can still serve afterwards -------------------------
      (let* ((before (process-count))
             (r (try-listen (list (cons 'host "127.0.0.1") (cons 'workers 2)))))
        (check "after the failures, a correct listen on the same port still starts"
               (and (pair? r) (eq? (car r) 'started)) r)
        (when (pair? r) (http-shutdown! (cdr r)))
        (check "and its shutdown returns the count to what it was" (settles-to? before) (process-count) before)
        (check "all of it together: the count is back at the first baseline" (settles-to? baseline) (process-count) baseline))

      (if (zero? failures)
          (begin (display "http-listen-failure: all tests passed\n") (exit 0))
          (begin (display "http-listen-failure: ") (display failures) (display " failed\n") (exit 1))))))
