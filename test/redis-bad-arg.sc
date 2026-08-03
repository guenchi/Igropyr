#!chezscheme
;;; A bad command argument must cost the caller, not the connection.
;;;
;;; arg->bv accepts strings, symbols, numbers and bytevectors and raises on
;;; anything else -- a list, a record, an #f from a lookup that missed. That
;;; encoding used to happen inside the connection actor, unguarded, so the
;;; raise killed the actor. The waiters were that actor's local state and
;;; died with it, so nothing answered them: every caller already in flight
;;; sat until its own 30 s reply timeout, and later callers sent to a dead
;;; pid and waited 30 s as well.
;;;
;;; One process's type error therefore took down a Redis connection shared
;;; by the whole application, and did it in the slowest possible way -- no
;;; error, no close, just everything touching Redis stalling for half a
;;; minute at a time.
;;;
;;; What is asserted is both halves: the caller is told at once, and the
;;; connection is still serving afterwards. A test that only checked "an
;;; error is raised" would have passed against the old code too, because the
;;; dying actor did raise -- in the wrong process.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr redis))

(define port 18817)
(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

;; A fake Redis that answers every command with +OK.
(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid (spawn
                   (lambda ()
                     (let loop ()
                       (receive
                         (`#(tcp-data ,_)
                           (tcp-write! c (string->utf8 "+OK\r\n") #f)
                           (loop))
                         (`#(tcp-eof) (tcp-close! c))
                         (`#(tcp-error ,_) (tcp-close! c))))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 200)
    (let ((r (redis-connect "127.0.0.1" port)))
      (check "the connection works to begin with"
        (equal? "OK" (redis r "SET" "k" "v")))

      ;; a list is not an encodable argument
      (let* ((t0 (now-ms))
             (outcome (guard (e (#t 'raised)) (redis r "SET" "k" '(1 2 3)) 'returned))
             (ms (- (now-ms) t0)))
        (check "a bad argument raises in the caller" (eq? outcome 'raised))
        (display "  [info] raised in ") (display ms)
        (display " ms (was: 30000, after killing the connection)\n")
        ;; the discriminating assertion: the old code raised too, but only
        ;; after the caller's own reply timeout expired
        (check "and raises immediately, not after the reply timeout"
          (< ms 500)))

      ;; the whole point: the shared connection is untouched
      (check "the connection still serves the same caller"
        (equal? "OK" (redis r "GET" "k")))

      ;; and other processes on that connection were never disturbed
      (let ((me self))
        (spawn (lambda () (send me (vector 'other (guard (e (#t 'failed))
                                                    (redis r "PING"))))))
        (check "and still serves other processes"
          (receive (after 3000 #f) (`#(other ,v) (equal? "OK" v)))))

      ;; every non-encodable shape, not just the one that was noticed
      (for-each
        (lambda (bad)
          (check "refused without harming the connection"
            (and (guard (e (#t #t)) (redis r "SET" "k" bad) #f)
                 (equal? "OK" (redis r "PING")))))
        (list '(1 2) #f #t (vector 1 2) car))

      ;; ---- a late reply must not become a permanent mailbox resident ----
      ;; A reply that arrives just as the caller gives up is still delivered;
      ;; its ref keeps a later call from mis-reading it, but nothing removed
      ;; it. In a long-lived process each timeout left one behind forever --
      ;; possibly a large bulk value -- for every later selective receive to
      ;; walk past.
      ;;
      ;; Timing this proves nothing at test scale, so the leftover is
      ;; PLANTED in exactly the shape a real one has, and its absence after
      ;; the next call is the drain, directly observed.
      (let ((planted (gensym)))
        (send self (vector 'redis-reply planted "a late one"))
        (redis r "PING")
        (check "a call drains an earlier call's late reply"
          (eq? 'gone (receive (after 0 'gone)
                       (`#(redis-reply ,@planted ,v) 'still-there)))))

      (redis-close! r))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "redis-bad-arg: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
