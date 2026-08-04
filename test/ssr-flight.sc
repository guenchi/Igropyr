#!chezscheme
;;; (igropyr ssr) single-flight, against a fake render worker.
;;;
;;; These sequences were not constructible before renders left the
;;; process. An in-process render never yields, so a leader and a follower
;;; could not exist at the same instant and nothing could happen "during"
;;; a render. A render on the far side of a socket parks the caller like
;;; any other I/O, so a leader can be caught mid-render, invalidated
;;; under, killed, or outlasted -- which is exactly where single-flight's
;;; remaining defects were.
;;;
;;; The worker here speaks the qjspool frame protocol and answers after a
;;; delay it is told; it needs no libquickjs, so this runs everywhere.
;;;
;;; Covered:
;;;   * an invalidation ends the rounds in progress -- a request that
;;;     arrives after it must not be handed the render that was already
;;;     running when it was made;
;;;   * a follower that stops waiting looks in the cache before rendering;
;;;   * a round whose leader has died is not one to join, and a waiter
;;;     that was KILLED does not pin the key in follower-forever mode.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr buffer)
        (igropyr qjspool)
        (only (igropyr ssr) make-ssr ssr-render ssr-invalidate! ssr-stats))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c) (if c (ok label) (fail label)))

;; ---- a fake render worker ------------------------------------------------

(define (put-u32! bv i n) (bytevector-u32-set! bv i n (endianness big)))
(define (get-u32 bv i) (bytevector-u32-ref bv i (endianness big)))
(define (get-u16 bv i) (bytevector-u16-ref bv i (endianness big)))
(define (sub bv from n)
  (let ((out (make-bytevector n))) (bytevector-copy! bv from out 0 n) out))

(define (frame id status body)
  (let* ((n (+ 4 1 (bytevector-length body))) (bv (make-bytevector (+ 4 n))))
    (put-u32! bv 0 n)
    (put-u32! bv 4 id)
    (bytevector-u8-set! bv 8 status)
    (bytevector-copy! body 0 bv 9 (bytevector-length body))
    bv))

(define (take-request! buf)
  (and (>= (inbuf-length buf) 4)
       (let ((n (get-u32 (inbuf-sub buf 0 4) 0)))
         (and (>= (inbuf-length buf) (+ 4 n))
              (let ((body (inbuf-sub buf 4 (+ 4 n))))
                (inbuf-consume! buf (+ 4 n))
                (let ((id (get-u32 body 0)) (fl (get-u16 body 4)))
                  (list id
                        (utf8->string (sub body 6 fl))
                        (utf8->string (sub body (+ 6 fl) (- n 6 fl))))))))))

;; how long the worker takes, and how many renders it has served: the
;; counter is the only witness of what actually reached an engine
(define delay-ms (box 0))
(define served (box 0))
(define port 19761)

(define (start-worker!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid (spawn
                   (lambda ()
                     (let ((buf (make-inbuf)))
                       (let loop ()
                         (receive
                           (`#(tcp-data ,bv)
                             (inbuf-append! buf bv)
                             (let ((req (take-request! buf)))
                               (when req
                                 (when (> (unbox delay-ms) 0)
                                   (sleep-ms (unbox delay-ms)))
                                 (set-box! served (+ 1 (unbox served)))
                                 (tcp-write! c
                                   (frame (car req) 0
                                          (string->utf8
                                            (string-append "<" (caddr req) ">")))
                                   #f))
                               (loop)))
                           (`#(tcp-eof) (tcp-close! c))
                           (`#(tcp-error ,e) (tcp-close! c)))))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))))

(start-scheduler
  (lambda ()
    (start-worker!)
    (sleep-ms 200)
    ;; two workers' worth of connections, so a leader and a follower can
    ;; genuinely render at the same time when they are wrong to
    (let* ((pool (qjspool (list (cons "127.0.0.1" port) (cons "127.0.0.1" port))
                          '((render-timeout-ms . 4000)
                            (checkout-timeout-ms . 3000))))
           (me self))

      ;; ---- an invalidation ends the rounds in progress ------------------
      ;;
      ;; The epoch already keeps a render that started before the
      ;; invalidation out of the cache. It does not keep it away from a
      ;; caller: a request arriving AFTER the invalidation joined the round
      ;; already running and was handed its pre-invalidation HTML. Both are
      ;; the same statement -- content from before this call must not be
      ;; served after it.
      (let ((r (make-ssr "" (list (cons 'engine pool) (cons 'ttl-ms 60000)))))
        (set-box! delay-ms 1200)
        (spawn (lambda ()
                 (send me (vector 'leader
                                  (ssr-render r "v" "OLD" '((key . "/k")))))))
        (sleep-ms 250)                    ; the leader is inside its render
        (ssr-invalidate! r "/k")          ; ...and the content changes
        (sleep-ms 50)
        (set-box! delay-ms 0)             ; the next render is quick
        (let ((after (ssr-render r "v" "NEW" '((key . "/k")))))
          (check "a request after an invalidation is not served the round it interrupted"
                 (string=? after "<NEW>")))
        (receive (after 6000 (fail "the leader never finished"))
          (`#(leader ,v) 'ok)))

      ;; ---- a retired follower is WOKEN, not left to time out ------------
      ;;
      ;; A follower whose round has just been invalidated has a fresh
      ;; render to do and no reason to wait for one that no longer counts.
      ;; Leaving it to its timeout would make every invalidation during a
      ;; render cost its followers the whole wait -- eight seconds at these
      ;; settings, for an answer that was already known to be unusable.
      (let ((r (make-ssr "" (list (cons 'engine pool) (cons 'ttl-ms 60000)))))
        (set-box! delay-ms 2500)
        (spawn (lambda ()
                 (guard (e (#t 'ok))
                   (ssr-render r "v" "OLD" '((key . "/w"))))))
        (sleep-ms 200)
        (let ((t0 (now-ms)))
          (spawn (lambda ()
                   (send me (vector 'follower
                                    (guard (e (#t 'raised))
                                      (ssr-render r "v" "OLD" '((key . "/w")))))))) 
          (sleep-ms 200)
          (set-box! delay-ms 0)
          (ssr-invalidate! r "/w")        ; retires the round under both
          (receive (after 8000 (fail "the retired follower never came back"))
            (`#(follower ,v)
              (let ((took (- (now-ms) t0)))
                (check "a retired follower comes back at once, not on its timeout"
                       (< took 3000))
                (display (string-append "  [info] retired follower answered in "
                                        (number->string took)
                                        "ms (its wait was 9000)\n")))))))

      ;; ---- a killed waiter does not wedge the key ------------------------
      ;;
      ;; @kill discards the follower's context, so it never unclaims: while
      ;; it was still counted the entry could not empty and could not be
      ;; dropped, and every later request joined a round whose leader was
      ;; long gone -- waiting out the full timeout before rendering, for as
      ;; long as the key stayed cold.
      (let ((r (make-ssr "" (list (cons 'engine pool) (cons 'ttl-ms 60000)))))
        (set-box! delay-ms 2500)
        (let ((leader (spawn (lambda ()
                               (guard (e (#t 'ok))
                                 (ssr-render r "v" "X" '((key . "/z")))))))
              (waiter #f))
          (sleep-ms 200)
          (set! waiter (spawn (lambda ()
                                (guard (e (#t 'ok))
                                  (ssr-render r "v" "X" '((key . "/z")))))))
          (sleep-ms 200)
          (kill waiter 'reaped)           ; never unclaims
          (kill leader 'reaped)           ; and the round has no leader left
          (sleep-ms 100)
          (set-box! delay-ms 0)
          ;; a fresh request must LEAD, not join the corpse of that round
          ;; let* and not let: the binding order of `let` is unspecified, so
          ;; t0 could be sampled AFTER the render it is supposed to time --
          ;; which reads as 0ms and passes whatever the code does.
          (let* ((t0 (now-ms))
                 (v (ssr-render r "v" "FRESH" '((key . "/z"))))
                 (took (- (now-ms) t0)))
            (begin
              (check "a request after a dead round leads instead of waiting it out"
                     (and (string=? v "<FRESH>") (< took 1500)))
              (display (string-append "  [info] request after a dead round answered in "
                                      (number->string took) "ms\n"))))))

      (qjspool-close! pool))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "ssr-flight: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
