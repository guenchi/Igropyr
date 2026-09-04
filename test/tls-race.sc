#!chezscheme
;;; Race cells on the TLS write gate, driven by inject-barrier!: a writer is
;;; parked at a named boundary inside tcp.sc and the controller runs the
;;; competing operation while it is parked. Plan: archive
;;; race-cells-on-barrier v1..v5 (codex r1-r5). Every hook that sits inside a
;;; region is SKIPPED in correct code and parks only in the split mutant; the
;;; cell then runs the mutant's choreography and fails by name, so the red
;;; names the split. Hooks outside any region park in correct code (AGG, Z6a).
;;;
;;; THE HOLD POINT. P (a spawned writer, never the connection's owner) is
;;; parked at 'agg-chunk-boundary; a barrier row at another point may coexist
;;; (check-arm! refuses only a second barrier at the SAME point). While P is
;;; parked nothing else can release the gate or retire the session, so the
;;; row under test is armed only after P is parked -- no theft by P's path.
;;;
;;; Requires IGROPYR_INJECT=on and the openssl CLI (test/tls-certs.sh). Own
;;; listener, own ports; every barrier row is released individually before
;;; inject-disarm! (bulk disarm refuses a live row).

(import (chezscheme)
        (igropyr actor) (igropyr libuv) (igropyr tcp) (igropyr http) (igropyr tls)
        (igropyr inject-control) (igropyr inject)
        (only (igropyr tls-core) tls-live-session-count)
        (only (igropyr tcp) tcp-writev-raw! tls-conn-charge tls-conn-totals tls-shutdown-ms-set! tls-raw-blocks tls-live-watcher-count)
        (test tls-raw-client))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))
(define (fail label . info) (apply check label #f info))
(define (now-ms) (let ((t (current-time))) (+ (* 1000 (time-second t)) (div (time-nanosecond t) 1000000))))
(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "tls-race suite requires IGROPYR_INJECT=on\n") (exit 1))

(define dir "/tmp/igropyr-tls-race-test")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))
(define (in-dir f) (string-append dir "/" f))
(define port 18484)

(define (snap)
  (list (cons 'sessions (tls-live-session-count))
        (cons 'watchers (tls-live-watcher-count))
        (cons 'live-timers (tls-live-timer-count))
        (cons 'active-timers (tls-active-timer-count))
        (cons 'handles (uv-live-handle-count))))
(define (settled-to? base ms)
  (let ((deadline (+ (now-ms) ms)))
    (let loop ()
      (cond ((equal? (snap) base) #t)
            ((> (now-ms) deadline) #f)
            (else (sleep-ms 50) (loop))))))
(define (within? bound-ms thunk)
  (let loop ((waited 0))
    (cond ((thunk) #t)
          ((>= waited bound-ms) #f)
          (else (sleep-ms 20) (loop (+ waited 20))))))
(define (dead-within? p ms) (within? ms (lambda () (not (process-alive? p)))))
;; never WRITE a pid (a pcb prints its fields and contains cycles); describe it
(define (desc x)
  (cond ((pair? x) (if (or (symbol? (car x)) (number? (car x))) (list (car x) (desc (cdr x))) 'parked))
        ((or (symbol? x) (number? x) (string? x) (boolean? x) (null? x)) x)
        (else 'pid)))

(define (bv . xs) (string->utf8 (apply string-append xs)))
(define GET-KA (bv "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
(define GET-CLOSE (bv "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
(define big (make-bytevector (* 4 1024 1024) 65))          ; P: 4 MB of A
;; P's payload for the rows that close the connection while P writes: three
;; chunks, small enough that the whole aggregate leaves through the synchronous
;; write path before the clean close. A hard close (tcp-close-raw! = uv_close)
;; CANCELS queued output, close_notify included; with 4 MB pending the peer saw
;; 802816 bytes and a truncated record. That is a separate finding (recorded
;; in the ledger), not what these rows measure.
(define mid (make-bytevector (* 48 1024) 65))
(define small-q (make-bytevector (* 64 1024) 81))          ; Q: 64 KB of Q
(define small-r (make-bytevector (* 64 1024) 82))          ; Q': 64 KB of R
(define sentinel (bv "Q2LEAKQ2LEAKQ2LEAKQ2LEAKQ2LEAKQ2LEAK"))
(define huge (make-bytevector (* 32 1024 1024) 66))         ; 32 MB of B, to out-size loopback buffers

;; Does a raw byte stream consist of complete TLS records only? -> residue length
;; (0 = clean). Header: type in {20,21,22,23}, version 0x03xx, length <= 2^14+256.
(define (tls-record-residue raw)
  (let ((n (bytevector-length raw)))
    (let loop ((i 0))
      (cond ((= i n) 0)
            ((> (+ i 5) n) (- n i))
            (else
              (let ((type (bytevector-u8-ref raw i))
                    (vmaj (bytevector-u8-ref raw (+ i 1)))
                    (len (+ (* 256 (bytevector-u8-ref raw (+ i 3))) (bytevector-u8-ref raw (+ i 4)))))
                (if (and (memv type '(20 21 22 23)) (= vmaj 3) (<= len (+ 16384 256)) (<= (+ i 5 len) n))
                    (loop (+ i 5 len))
                    (- n i))))))))

;; the aggregate-id runs of the submitted raw blocks, in block-id order
(define (aggregate-runs c)
  (let* ((blocks (with-interrupts-disabled (car (tls-raw-blocks c))))
         (sorted (list-sort (lambda (a b) (< (car a) (car b))) blocks)))
    (let loop ((bs sorted) (runs '()))
      (cond ((null? bs) (reverse runs))
            ((and (pair? runs) (eqv? (car runs) (cadr (car bs)))) (loop (cdr bs) runs))
            (else (loop (cdr bs) (cons (cadr (car bs)) runs)))))))

;; ---- fixture: the handler hands the connection to the test and waits ------
(define main-pid #f)
(define handler-count 0)
(define (holding-handler req res)
  (send main-pid (vector 'conn (res-conn res) self))
  (receive (`#(release) 'ok)))
(define (counting-handler req res)
  (set! handler-count (+ handler-count 1))
  (res-send! res (string->utf8 "ok-over-tls")))

;; a writer process: one application write on c, outcome reported to main
(define (spawn-writer! c tag payload)
  (spawn (lambda ()
           (tcp-writev! c (list payload)
                        (lambda (st) (send main-pid (vector 'done tag st)))))))
(define (writer-outcome tag ms)
  (receive (after ms 'no-outcome) (`#(done ,@tag ,st) st)))

;; a client process reading everything the server writes until it closes
(define (spawn-client! mode)
  (spawn (lambda ()
           (case mode
             ((collect)
              (let-values (((plain raw cause) (raw-tls-collect "127.0.0.1" port "localhost" GET-KA 60000)))
                (send main-pid (vector 'client-done self (bytevector-length plain) cause plain raw))))
             ((stall)
              (let-values (((plain raw cause) (raw-tls-stall-then-collect "127.0.0.1" port "localhost" GET-KA 150000)))
                (send main-pid (vector 'client-done self (bytevector-length plain) cause plain raw))))
             ((slow)
              (let-values (((plain raw cause) (raw-tls-slow-collect "127.0.0.1" port "localhost" GET-KA 150000 50)))
                (send main-pid (vector 'client-done self (bytevector-length plain) cause plain raw))))
             (else
              (let-values (((plain writes eof? fail) (raw-tls-exchange "127.0.0.1" port "localhost" GET-KA #f 60000)))
                (send main-pid (vector 'client-done self (bytevector-length plain) eof? plain fail))))))))
(define (client-result ms)
  ;; matched by the CURRENT client's pid: a late result from an earlier cell's
  ;; client must not be taken for this one's
  (let ((cli client-pid))
    (receive (after ms #f) (`#(client-done ,@cli ,n ,eof? ,plain ,extra) (list n eof? plain extra)))))

;; open a connection through the holding handler; -> (conn . handler-pid)
(define client-pid #f)
(define (open-held-conn! mode)
  (set! client-pid (spawn-client! mode))
  (receive (after 10000 #f) (`#(conn ,c ,h) (cons c h))))
;; the server-side raw queue of a connection (bytes charged, not yet refunded)
(define (raw-queued c) (let ((ch (tls-conn-charge c))) (and ch (cdr ch))))
(define (retire-reason) (tls-last-retire-reason))
(define (raw-completions c) (let ((b (tls-raw-blocks c))) (if (pair? b) (length (cdr b)) 0)))

(start-scheduler
  (lambda ()
    (set! main-pid self)
    (spawn (lambda () (sleep-ms 240000) (display "FAIL watchdog: tls-race suite did not finish in 240 s\n") (exit 1)))
    (inject-disarm!)
    (let ((srv (http-listen port holding-handler
                 (list (cons 'host "127.0.0.1") (cons 'workers 2)
                       (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))))
      (sleep-ms 200)
      (let ((base (snap)))
        (display (list 'baseline base)) (newline)

        ;; ---- W0: the fixture itself: a held connection, one big write, the client reads it all
        (let* ((ch (open-held-conn! 'plain)) (c (and ch (car ch))))
          (check "W0: the handler handed over a live TLS connection" c)
          (when c
            (spawn-writer! c 'p big)
            (check "W0: P's write completed" (eqv? (writer-outcome 'p 20000) 0))
            (tcp-close! c)
            (let ((r (client-result 20000)))
              (check "W0: the client read the whole 4 MB and saw the close" (and r (eqv? (car r) (bytevector-length big)) (cadr r)) (and r (car r)) (and r (cadr r))))
            (send (cdr ch) (vector 'release))
            (check "W0: resources back to baseline" (settled-to? base 4000) (snap) base)))

        ;; ---- AGG(a): the chunk boundary is an enabled gap: correct code PARKS there
        (let* ((ch (open-held-conn! 'plain)) (c (car ch))
               (t (inject-arm-barrier! 'agg-chunk-boundary 1 30000))
               (p (spawn-writer! c 'p big))
               (w (inject-barrier-wait t 'agg-chunk-boundary 5000)))
          (check "AGG(a): P parked at the first chunk boundary (polarity: an aggregate-wide region would skip)" (and (pair? w) (eq? (cdr w) p)) (desc w) (inject-barrier-state t))
          (when (pair? w) (inject-barrier-drain! (cdr w) t 5000))
          (unless (pair? w) (inject-barrier-cleanup! t 'agg-chunk-boundary 31000))
          (check "AGG(a): P's write completed after the resume" (eqv? (writer-outcome 'p 20000) 0))
          (tcp-close! c)
          (let ((r (client-result 20000)))
            (check "AGG(a): the client decrypted every record (4 MB, contiguous)" (and r (eqv? (car r) (bytevector-length big))) (and r (car r))))
          (when (pair? w) (inject-release! t))
          (send (cdr ch) (vector 'release))
          (check "AGG(a): resources back to baseline" (settled-to? base 4000) (snap) base))

        ;; ---- AGG(b): two writers, contiguity and acquisition order under a forced interleave point
        (let* ((ch (open-held-conn! 'plain)) (c (car ch))
               (t1 (inject-arm-barrier! 'agg-chunk-boundary 1 30000))
               (t2 (inject-arm-barrier! 'agg-chunk-boundary-2 2 30000))
               (p (spawn-writer! c 'p big))
               (w1 (inject-barrier-wait t1 'agg-chunk-boundary 5000)))
          (check "AGG(b): P parked at boundary 1" (and (pair? w1) (eq? (cdr w1) p)) (desc w1))
          (cond
            ((pair? w1)
             (let ((q (spawn-writer! c 'q small-q)))
               (check "AGG(b): Q joined the waiter list while P was parked" (within? 2000 (lambda () (eqv? (tls-gate-waiters-length c) 1))) (tls-gate-waiters-length c))
               (inject-barrier-drain! p t1 5000)
               (inject-release! t1)
               (let ((w2 (inject-barrier-wait t2 'agg-chunk-boundary-2 5000)))
                 (check "AGG(b): a writer parked at boundary 2" (pair? w2) (desc w2) (inject-barrier-state t2))
                 (when (pair? w2)
                   (let ((holder (tls-conn-holder c)))
                     (cond
                       ((eq? holder p)
                        (check "AGG(b): P still holds the gate at boundary 2 (no release inside the loop)" #t)
                        (check "AGG(b): and the parked writer is P" (eq? (cdr w2) p) (desc (cdr w2)))
                        (inject-barrier-drain! (cdr w2) t2 5000))
                       (else
                        ;; the mutant's shape: the loop released the gate after chunk 1
                        (fail "AGG(b): the gate was released inside the chunk loop (holder is not P at boundary 2)" (desc holder) (desc p) (desc (cdr w2)))
                        (within? 2000 (lambda () (> (length (aggregate-runs c)) 1)))
                        (inject-barrier-drain! (cdr w2) t2 5000)))))
                 (unless (pair? w2) (inject-barrier-cleanup! t2 'agg-chunk-boundary-2 31000)))
               (check "AGG(b): P completed" (eqv? (writer-outcome 'p 20000) 0))
               (check "AGG(b): Q completed" (eqv? (writer-outcome 'q 20000) 0))
               (let ((runs (aggregate-runs c)))
                 (check "AGG(b): the raw blocks form exactly two runs: all of P's, then all of Q's" (= (length runs) 2) runs))
               (tcp-close! c)
               (let ((r (client-result 20000)))
                 (check "AGG(b): the client received P's bytes then Q's, contiguous" 
                        (and r (eqv? (car r) (+ (bytevector-length big) (bytevector-length small-q)))
                             (eqv? (bytevector-u8-ref (caddr r) (- (bytevector-length big) 1)) 65)
                             (eqv? (bytevector-u8-ref (caddr r) (bytevector-length big)) 81))
                        (and r (car r))))
               (inject-release! t2)))
            (else (inject-barrier-cleanup! t1 'agg-chunk-boundary 31000) (inject-release! t2) (tcp-close! c) (client-result 20000)))
          (send (cdr ch) (vector 'release))
          (check "AGG(b): resources back to baseline" (settled-to? base 4000) (snap) base))

        ;; ---- GATE(c): the closing tests and the append are one step
        (let* ((ch (open-held-conn! 'plain)) (c (car ch))
               (th (inject-arm-barrier! 'agg-chunk-boundary 1 30000))
               (p (spawn-writer! c 'p mid))
               (wh (inject-barrier-wait th 'agg-chunk-boundary 5000)))
          (check "GATE(c): P parked (hold point)" (and (pair? wh) (eq? (cdr wh) p)) (desc wh))
          (cond
            ((pair? wh)
             (let* ((t (inject-arm-barrier! 'gate-holder-append 1 30000))
                    (q (spawn-writer! c 'q small-q))
                    (w (inject-barrier-wait t 'gate-holder-append 1500)))
               (cond
                 ((eq? w 'skipped)
                  (check "GATE(c): the append point inside the region was skipped, not parked" #t)
                  (check "GATE(c): Q is on the waiter list" (within? 2000 (lambda () (eqv? (tls-gate-waiters-length c) 1))) (tls-gate-waiters-length c)))
                 ((pair? w)
                  ;; the mutant's shape: Q parked between the tests and the append
                  (fail "GATE(c): Q PARKED between the closing tests and the append: they are two steps" (desc w))
                  (inject-barrier-drain! (cdr w) t 5000)
                  (check "GATE(c): (mutant) Q appended after its resume" (within? 2000 (lambda () (eqv? (tls-gate-waiters-length c) 1))) (tls-gate-waiters-length c)))
                 (else (fail "GATE(c): neither skipped nor parked" (desc w) (inject-barrier-state t))))
               ;; close requested while P still holds: Q (already listed) is refused now,
               ;; and a writer arriving AFTER the request must be refused promptly
               (tcp-close! c)
               (check "GATE(c): Q (listed before the close) was refused" (eqv? (writer-outcome 'q 3000) -1))
               (spawn-writer! c 'q3 small-r)
               (check "GATE(c): a writer arriving after the close request is refused promptly (kills a dropped closing? test)" (eqv? (writer-outcome 'q3 2000) -1))
               (inject-barrier-drain! p th 5000)
               (check "GATE(c): P completed its aggregate" (eqv? (writer-outcome 'p 20000) 0))
               (inject-release! t)
               (inject-release! th)))
            (else (inject-barrier-cleanup! th 'agg-chunk-boundary 31000) (tcp-close! c)))
          (client-result 20000)
          (send (cdr ch) (vector 'release))
          (check "GATE(c): resources back to baseline" (settled-to? base 4000) (snap) base))

        ;; ---- GATE-FIFO: two waiters are granted in acquisition order (no close)
        (let* ((ch (open-held-conn! 'plain)) (c (car ch))
               (th (inject-arm-barrier! 'agg-chunk-boundary 1 30000))
               (p (spawn-writer! c 'p big))
               (wh (inject-barrier-wait th 'agg-chunk-boundary 5000)))
          (check "GATE-FIFO: P parked (hold point)" (and (pair? wh) (eq? (cdr wh) p)) (desc wh))
          (cond
            ((pair? wh)
             (spawn-writer! c 'q small-q)
             (check "GATE-FIFO: Q listed" (within? 2000 (lambda () (eqv? (tls-gate-waiters-length c) 1))))
             (spawn-writer! c 'q2 small-r)
             (check "GATE-FIFO: Q' listed behind Q" (within? 2000 (lambda () (eqv? (tls-gate-waiters-length c) 2))))
             (inject-barrier-drain! p th 5000)
             (check "GATE-FIFO: P completed" (eqv? (writer-outcome 'p 20000) 0))
             (check "GATE-FIFO: Q completed" (eqv? (writer-outcome 'q 20000) 0))
             (check "GATE-FIFO: Q' completed" (eqv? (writer-outcome 'q2 20000) 0))
             (tcp-close! c)
             (let ((r (client-result 20000)) (nb (bytevector-length big)) (nq (bytevector-length small-q)))
               (check "GATE-FIFO: the client saw P, then Q, then Q' (acquisition order)"
                      (and r (eqv? (car r) (+ nb nq nq))
                           (eqv? (bytevector-u8-ref (caddr r) nb) 81)
                           (eqv? (bytevector-u8-ref (caddr r) (+ nb nq)) 82))
                      (and r (car r))))
             (inject-release! th))
            (else (inject-barrier-cleanup! th 'agg-chunk-boundary 31000) (tcp-close! c) (client-result 20000)))
          (send (cdr ch) (vector 'release))
          (check "GATE-FIFO: resources back to baseline" (settled-to? base 4000) (snap) base))

        ;; ---- RET': the gate (conn-set-tls! #f) and the closed mark are one step
        (let* ((s0 (tls-live-session-count))
               (ch (open-held-conn! 'collect)) (c (car ch))
               (th (inject-arm-barrier! 'agg-chunk-boundary 1 30000))
               (p (spawn-writer! c 'p mid))
               (wh (inject-barrier-wait th 'agg-chunk-boundary 5000)))
          (check "RET': P parked (hold point)" (and (pair? wh) (eq? (cdr wh) p)) (desc wh))
          (cond
            ((pair? wh)
             (tcp-close! c)                      ; closing; P still holds, retire happens on P's release
             (let ((t (inject-arm-barrier! 'ret-gate-closed 1 30000)))
               (inject-barrier-drain! p th 5000)
               (inject-release! th)
               (let ((w (inject-barrier-wait t 'ret-gate-closed 5000)))
                 (cond
                   ((eq? w 'skipped)
                    (check "RET': the gate->closed point inside the region was skipped, not parked" #t)
                    (check "RET': the retirement was P's clean close" (equal? (tls-last-retire-reason) '(clean-close . tls-closed)) (tls-last-retire-reason))
                    (check "RET': the point was hit exactly once (no other retirement stole the occurrence)" (eqv? (inject-hits 'ret-gate-closed) 1) (inject-hits 'ret-gate-closed))
                    (spawn-writer! c 'q2 sentinel)
                    (check "RET': a write after the gate is refused (raw path rejected by the state)" (eqv? (writer-outcome 'q2 3000) -1)))
                   ((pair? w)
                    ;; the mutant's shape: P parked after the gate, before the closed mark
                    (fail "RET': P PARKED between the gate and the closed mark: they are two steps" (desc w))
                    (spawn-writer! c 'q2 sentinel)
                    (let ((st (writer-outcome 'q2 3000)))
                      (check "RET': (mutant) the leaked write must not succeed" (not (eqv? st 0)) st))
                    (inject-barrier-drain! (cdr w) t 5000))
                   (else (fail "RET': neither skipped nor parked" (desc w) (inject-barrier-state t))))
                 (check "RET': P's aggregate ended exactly once" (number? (writer-outcome 'p 20000)))
                 (check "RET': live sessions back to the pre-connection count" (within? 4000 (lambda () (eqv? (tls-live-session-count) s0))) (tls-live-session-count) s0)
                 (let ((r (client-result 20000)))
                   (check "RET': the client received P's whole aggregate" (and r (eqv? (car r) (bytevector-length mid))) (and r (car r)))
                   (check "RET': every byte on the wire parsed as a TLS record (no plaintext after the gate)"
                          (and r (bytevector? (cadddr r)) (eqv? (tls-record-residue (cadddr r)) 0))
                          (and r (bytevector? (cadddr r)) (tls-record-residue (cadddr r)))))
                 (inject-release! t))))
            (else (inject-barrier-cleanup! th 'agg-chunk-boundary 31000) (tcp-close! c) (client-result 20000)))
          (send (cdr ch) (vector 'release))
          (check "RET': resources back to baseline" (settled-to? base 4000) (snap) base))

        ;; ---- Z6a: the holder is killed after acquiring, before its first chunk
        (let* ((ch (open-held-conn! 'plain)) (c (car ch))
               (t (inject-arm-barrier! 'tls-after-held 1 30000))
               (p (spawn-writer! c 'p big))
               (w (inject-barrier-wait t 'tls-after-held 5000)))
          (check "Z6a: P parked after acquiring the gate, before its first chunk" (and (pair? w) (eq? (cdr w) p)) (desc w) (inject-barrier-state t))
          (cond
            ((pair? w)
             (spawn-writer! c 'q small-q)
             (check "Z6a: Q is waiting behind P" (within? 2000 (lambda () (eqv? (tls-gate-waiters-length c) 1))) (tls-gate-waiters-length c))
             (kill p 'z6a-kill)
             (check "Z6a: P is dead" (dead-within? p 3000))
             (check "Z6a: Q was refused within bound (the holder monitor's DOWN retired the connection)" (eqv? (writer-outcome 'q 5000) -1))
             (check "Z6a: the retirement carries the holder's death reason" (let ((r (tls-last-retire-reason))) (and (pair? r) (eq? (cdr r) 'z6a-kill))) (tls-last-retire-reason))
             (check "Z6a: release of the parked-and-dead row succeeds" (vector? (inject-release! t))))
            (else (inject-barrier-cleanup! t 'tls-after-held 31000) (tcp-close! c)))
          (client-result 20000)
          (send (cdr ch) (vector 'release))
          (check "Z6a: resources back to baseline" (settled-to? base 4000) (snap) base))


        ;; ======== E9: a clean close drains before the handle closes ========
        ;; tcp-close! while the holder still has queued ciphertext: the queue
        ;; and the close_notify must reach the peer; only the idle bound may
        ;; cut a peer that stops reading. The client stalls (stops reading) so
        ;; the server's output queues; raw-queued > 0 on the server witnesses it.

        ;; ---- CLOSE-DRAIN: 4 MB queued, close, everything arrives, then close_notify
        (let* ((s0 (tls-live-session-count))
               (ch (open-held-conn! 'stall)) (c (car ch)) (cli client-pid)
               (p (spawn-writer! c 'p big)))
          (check "CLOSE-DRAIN: the server queued output behind the stalled client" (within? 5000 (lambda () (let ((q (raw-queued c))) (and q (> q 0))))) (raw-queued c))
          (let ((q-at-close (raw-queued c)))
            (tcp-close! c)
            (check "CLOSE-DRAIN: premise -- raw-queued > 0 at the moment of the close" (and q-at-close (> q-at-close 0)) q-at-close))
          (check "CLOSE-DRAIN: P's aggregate ended (no hang)" (number? (writer-outcome 'p 20000)))
          (send cli (vector 'resume))
          (let ((r (client-result 30000)))
            (check "CLOSE-DRAIN: the client received the whole 4 MB after resuming" (and r (eqv? (car r) (bytevector-length big))) (and r (car r)))
            (check "CLOSE-DRAIN: and then close_notify (not a bare transport EOF)" (and r (eq? (cadr r) 'close-notify)) (and r (cadr r)))
            (check "CLOSE-DRAIN: every byte on the wire parsed as a TLS record" (and r (bytevector? (cadddr r)) (eqv? (tls-record-residue (cadddr r)) 0)) (and r (bytevector? (cadddr r)) (tls-record-residue (cadddr r)))))
          (check "CLOSE-DRAIN: the retirement is the clean close" (equal? (retire-reason) '(clean-close . tls-closed)) (retire-reason))
          (check "CLOSE-DRAIN: live sessions back to the pre-connection count" (within? 4000 (lambda () (eqv? (tls-live-session-count) s0))) (tls-live-session-count) s0)
          (send (cdr ch) (vector 'release))
          (check "CLOSE-DRAIN: resources back to baseline" (settled-to? base 6000) (snap) base))

        ;; ---- CLOSE-DRAIN-REPEAT: the owner exits normally while the alert is queued
        (let* ((ch (open-held-conn! 'stall)) (c (car ch)) (cli client-pid)
               (owner (conn-owner c))
               (p (spawn-writer! c 'p big)))
          (check "CLOSE-DRAIN-REPEAT: queued output" (within? 5000 (lambda () (let ((q (raw-queued c))) (and q (> q 0))))) (raw-queued c))
          (tcp-close! c)
          (check "CLOSE-DRAIN-REPEAT: P ended" (number? (writer-outcome 'p 20000)))
          ;; the alert is now queued behind the stalled data; the owner dies NORMALLY
          ;; (no link cascade): uv-owner-died!'s tcp-close! and the watcher's owner
          ;; DOWN must not cut the drain
          (check "CLOSE-DRAIN-REPEAT: premise -- the connection is still draining when the owner dies" (let ((q (raw-queued c))) (and q (> q 0))) (raw-queued c))
          (when owner (kill owner 'normal))
          (send cli (vector 'resume))
          (let ((r (client-result 30000)))
            (check "CLOSE-DRAIN-REPEAT: the client still received the whole 4 MB" (and r (eqv? (car r) (bytevector-length big))) (and r (car r)))
            (check "CLOSE-DRAIN-REPEAT: and close_notify" (and r (eq? (cadr r) 'close-notify)) (and r (cadr r))))
          (check "CLOSE-DRAIN-REPEAT: clean close recorded" (equal? (retire-reason) '(clean-close . tls-closed)) (retire-reason))
          (send (cdr ch) (vector 'release))
          (check "CLOSE-DRAIN-REPEAT: resources back to baseline" (settled-to? base 6000) (snap) base))

        ;; ---- CLOSE-DRAIN-OWNER-KILLED: the owner dies abnormally mid-drain
        (let* ((ch (open-held-conn! 'stall)) (c (car ch)) (cli client-pid)
               (owner (conn-owner c))
               (p (spawn-writer! c 'p big)))
          (check "CLOSE-DRAIN-OWNER-KILLED: queued output" (within? 5000 (lambda () (let ((q (raw-queued c))) (and q (> q 0))))) (raw-queued c))
          (tcp-close! c)
          (check "CLOSE-DRAIN-OWNER-KILLED: P ended" (number? (writer-outcome 'p 20000)))
          (when owner (kill owner 'owner-killed-mid-drain))
          (send cli (vector 'resume))
          (let ((r (client-result 30000)))
            (check "CLOSE-DRAIN-OWNER-KILLED: the drain was not cut by the owner's abnormal death (4 MB + close_notify)" (and r (eqv? (car r) (bytevector-length big)) (eq? (cadr r) 'close-notify)) (and r (car r)) (and r (cadr r))))
          (send (cdr ch) (vector 'release))
          (check "CLOSE-DRAIN-OWNER-KILLED: resources incl. the watcher count back to baseline" (settled-to? base 6000) (snap) base))

        ;; ---- CLOSE-DRAIN-DRAINS: a stalled client is resumed and receives the
        ;; whole 32 MB and close_notify -- the drain is not truncated even for a
        ;; large body. (The idle-bound-vs-total-deadline distinction is NOT cell-
        ;; testable on loopback: a fast reader drains 32 MB in ~40 ms, below any
        ;; usable bound, and a slow reader's scheduling gaps exceed a small bound
        ;; so correct code would be cut too -- the window closes on both sides.
        ;; The rearm/idle path is covered deterministically by CLOSE-DRAIN-REARM-
        ;; FAIL below, which is barrier-driven rather than timing-driven.)
        (let* ((ch (open-held-conn! 'stall)) (c (car ch)) (cli client-pid)
               (p (spawn-writer! c 'p huge)))
          (check "CLOSE-DRAIN-DRAINS: output queued behind the stalled client" (within? 8000 (lambda () (let ((q (raw-queued c))) (and q (> q 0))))) (raw-queued c))
          (tcp-close! c)
          (send cli (vector 'resume))
          (check "CLOSE-DRAIN-DRAINS: P ended" (number? (writer-outcome 'p 60000)))
          (let ((r (client-result 90000)))
            (check "CLOSE-DRAIN-DRAINS: the client received the whole 32 MB and close_notify" (and r (eqv? (car r) (bytevector-length huge)) (eq? (cadr r) 'close-notify)) (and r (car r)) (and r (cadr r))))
          (check "CLOSE-DRAIN-DRAINS: clean close recorded" (equal? (retire-reason) '(clean-close . tls-closed)) (retire-reason))
          (send (cdr ch) (vector 'release))
          (check "CLOSE-DRAIN-DRAINS: resources back to baseline" (settled-to? base 8000) (snap) base))

        ;; ---- CLOSE-DRAIN-SEAL: nothing can be submitted after the alert
        ;; P is held at a chunk boundary so that the close is requested while P
        ;; still holds the gate: then P's own release runs finish-shutdown and P
        ;; is the process that parks at 'tls-after-alert (a controller cannot park).
        (let* ((ch (open-held-conn! 'stall)) (c (car ch)) (cli client-pid)
               (th (inject-arm-barrier! 'agg-chunk-boundary 1 30000))
               (p (spawn-writer! c 'p big))
               (wh (inject-barrier-wait th 'agg-chunk-boundary 5000))
               (t (inject-arm-barrier! 'tls-after-alert 1 30000)))
          (check "CLOSE-DRAIN-SEAL: P held at a chunk boundary" (and (pair? wh) (eq? (cdr wh) p)) (desc wh))
          (tcp-close! c)
          (when (pair? wh) (inject-barrier-drain! p th 5000))
          (inject-release! th)
          (check "CLOSE-DRAIN-SEAL: queued output" (within? 5000 (lambda () (let ((q (raw-queued c))) (and q (> q 0))))) (raw-queued c))
          (let ((w (inject-barrier-wait t 'tls-after-alert 10000)))
            (check "CLOSE-DRAIN-SEAL: the finishing process parked right after the alert was queued" (pair? w) (desc w) (inject-barrier-state t))
            (cond
              ((pair? w)
               (check "CLOSE-DRAIN-SEAL: premise -- still open and attached while parked" (let ((q (raw-queued c))) (and q (> q 0))) (raw-queued c))
               (let ((st 'no-callback))
                 (let ((accepted (tcp-writev-raw! c (list sentinel) (lambda (s) (set! st s)))))
                   (check "CLOSE-DRAIN-SEAL: a raw submission after the alert is refused synchronously" (and (not accepted) (eqv? st -1)) accepted st)))
               (inject-barrier-drain! (cdr w) t 5000)
               (inject-release! t))
              (else (inject-barrier-cleanup! t 'tls-after-alert 31000))))
          (writer-outcome 'p 20000)
          (send cli (vector 'resume))
          (let ((r (client-result 30000)))
            (check "CLOSE-DRAIN-SEAL: the client received 4 MB, close_notify, and no sentinel bytes (residue 0)" (and r (eqv? (car r) (bytevector-length big)) (eq? (cadr r) 'close-notify) (bytevector? (cadddr r)) (eqv? (tls-record-residue (cadddr r)) 0)) (and r (car r)) (and r (cadr r)) (and r (bytevector? (cadddr r)) (tls-record-residue (cadddr r)))))
          (send (cdr ch) (vector 'release))
          (check "CLOSE-DRAIN-SEAL: resources back to baseline" (settled-to? base 6000) (snap) base))

        ;; ---- CLOSE-DRAIN-REARM-FAIL: a failed PROGRESS rearm retires at once
        (let* ((ch (open-held-conn! 'slow)) (c (car ch)) (cli client-pid)
               (th (inject-arm-barrier! 'agg-chunk-boundary 1 30000))
               (p (spawn-writer! c 'p big))
               (wh (inject-barrier-wait th 'agg-chunk-boundary 5000))
               (t (inject-arm-barrier! 'tls-after-alert 1 30000)))
          (check "CLOSE-DRAIN-REARM-FAIL: P held at a chunk boundary" (and (pair? wh) (eq? (cdr wh) p)) (desc wh))
          (tcp-close! c)
          (when (pair? wh) (inject-barrier-drain! p th 5000))
          (inject-release! th)
          (check "CLOSE-DRAIN-REARM-FAIL: queued output" (within? 5000 (lambda () (let ((q (raw-queued c))) (and q (> q 0))))) (raw-queued c))
          (let ((w (inject-barrier-wait t 'tls-after-alert 10000)))
            (check "CLOSE-DRAIN-REARM-FAIL: parked after the alert (initial arm succeeded)" (pair? w) (desc w))
            (when (pair? w)
              ;; the NEXT successful application completion's progress rearm fails
              (inject-arm-return! 'tls-timer-rearm-fail -1 1)
              (inject-barrier-drain! (cdr w) t 5000))
            (inject-release! t))
          (send cli (vector 'resume))         ; progress begins: the first completion's rearm fails
          (writer-outcome 'p 30000)
          (check "CLOSE-DRAIN-REARM-FAIL: retired promptly with the timer-failed reason" (within? 5000 (lambda () (equal? (retire-reason) '(clean-close . tls-shutdown-timer-failed)))) (retire-reason))
          (client-result 30000)
          (inject-disarm!)
          (send (cdr ch) (vector 'release))
          (check "CLOSE-DRAIN-REARM-FAIL: resources back to baseline" (settled-to? base 8000) (snap) base))

        ;; ---- Z14: the empty check and the gate opening are one step
        ;; A is coalesced with Finished and delivered by the watcher's first
        ;; drain; the drain's EMPTY round reaches the hook. The client sends B as
        ;; soon as A's response arrives -- while the watcher is parked in the
        ;; mutant. B is read by a real callback and, with the gate still closed,
        ;; queued; the mutant then opens the gate and never drains it.
        (http-swap! srv counting-handler)
        ;; the size of one full response (headers included), measured, so the
        ;; client sends B only after A's whole response and stops after B's
        (let ((resp-len
               (let-values (((plain writes eof? fail) (raw-tls-exchange "127.0.0.1" port "localhost" GET-KA #t 2000)))
                 (bytevector-length plain))))
        (check "Z14: premise -- one response measured" (> resp-len 0) resp-len)
        (set! handler-count 0)
        (let* ((t (inject-arm-barrier! 'z14-empty-open 1 30000))
               (expect resp-len)
               (client (let ((cp (spawn (lambda ()
                                (let-values (((plain writes eof? fail)
                                              (raw-tls-exchange "127.0.0.1" port "localhost" GET-KA #t 8000 'second GET-KA resp-len)))
                                  (send main-pid (vector 'client-done self (bytevector-length plain) eof? plain fail)))))))
                         (set! client-pid cp) cp))
               (w (inject-barrier-wait t 'z14-empty-open 1500)))
          (cond
            ((eq? w 'skipped)
             (check "Z14: the empty-then-open point inside the region was skipped, not parked" #t)
             (let ((r (client-result 15000)))
               (check "Z14: both requests were answered (A then B, each once)" (and r (eqv? handler-count 2) (>= (car r) (* 2 expect))) handler-count (and r (car r))))
             (inject-release! t))
            ((pair? w)
             ;; the mutant's shape: the watcher parked between the empty check and the open
             (fail "Z14: the watcher PARKED between the empty check and the gate opening: two regions" (desc w))
             (let ((reads0 (car (tls-server-raw-reads))))
               (check "Z14: (mutant) B reached the server's read callback while the watcher was parked" (within? 5000 (lambda () (> (car (tls-server-raw-reads)) reads0))) (tls-server-raw-reads) reads0)
               (check "Z14: (mutant) B has not reached the handler yet (queued behind the closed gate)" (eqv? handler-count 1) handler-count)
               (inject-barrier-drain! (cdr w) t 5000)
               (let ((r (client-result 15000)))
                 (check "Z14: (mutant) B must still be delivered once the gate opens" (eqv? handler-count 2) handler-count))
               (inject-release! t)))
            (else (fail "Z14: neither skipped nor parked" (desc w) (inject-barrier-state t))
                  (inject-barrier-cleanup! t 'z14-empty-open 31000)))
          (check "Z14: resources back to baseline" (settled-to? base 6000) (snap) base)))

        (inject-disarm!)
        (if (zero? failures)
            (begin (display "ALL TLS-RACE TESTS PASSED\n") (exit 0))
            (begin (display failures) (display " failures\n") (exit 1)))))))
