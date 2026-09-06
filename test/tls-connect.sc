#!chezscheme
;;; tls-connect.sc -- the connection layer's TLS CLIENT role (tcp-connect-tls!).
;;;
;;; The other end is the controllable TLS server of test/tls-raw-server.sc, so
;;; every observation is made from the wire side or from the dialer's own
;;; mailbox: what a dialer receives (#(tcp-connected c) only after TLS is
;;; established; #(tcp-connect-failed why) exactly once before that), what it
;;; can read and write through the codec afterwards, and what is left behind
;;; when it dies mid-handshake. Requires IGROPYR_INJECT=on for the counters.
(import (chezscheme) (igropyr actor)
        (only (igropyr libuv) now-ms)
        (only (igropyr tcp) tcp-connect-tls! tcp-write! tcp-close! tcp-read-start!
              tls-conn-peer-cb-hash tls-live-watcher-count tls-conn-charge)
        (only (igropyr tls-core) tls-mesh-client-context! tls-context-retire!
              tls-live-session-count tls-live-context-count)
        (igropyr tls-watch)
        (test tls-raw-server))

(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define dir "/tmp/igropyr-tls-connect-test")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(define (in-dir f) (string-append dir "/" f))
(define port 18500)
(define (snap) (list (cons 'sessions (tls-live-session-count)) (cons 'watchers (tls-live-watcher-count))))

;; a dialer process: connects with TLS, reports what it receives, then runs a script
(define (dial! ctx script)
  (let ((main self))
    (spawn (lambda ()
             (tcp-connect-tls! "127.0.0.1" port self ctx "localhost")
             (let loop ((events '()))
               (receive (after 6000 (send main (vector 'dialer-done self (reverse events))))
                 (`#(tcp-connected ,c)
                   (send main (vector 'dialer-connected self c))
                   (script c)
                   (loop (cons 'connected events)))
                 (`#(tcp-connect-failed ,why)
                   (send main (vector 'dialer-failed self why))
                   (loop (cons (list 'failed why) events)))
                 (`#(dialer-stop) (send main (vector 'dialer-done self (reverse events))))))))))

(start-scheduler
  (lambda ()
    (tls-watch-install!)
    ;; let, not define: definitions cannot follow an expression in this body
    (let* ((ctx (tls-mesh-client-context! #f))      ; mode B: no CA, verify none
           (base (snap))
           (main self))

    ;; ---- C1: connected is delivered only after establishment; data flows both ways
    (let ((srv (raw-tls-server-start "127.0.0.1" port (in-dir "good.pem") (in-dir "good.key"))))
      (sleep-ms 100)
      (let* ((script (lambda (c) (tcp-read-start! c)
                                 (tcp-write! c (string->utf8 "hello-from-dialer") #f)
                                 (receive (after 3000 (send main (vector 'dialer-read 'timeout)))
                                   (`#(tcp-data ,bv) (send main (vector 'dialer-read (utf8->string bv)))))))
             (d (dial! ctx script))
             (ss (raw-tls-server-accept srv 5000)))
        (check "C1: the server established a session" (not (or (pair? ss) (symbol? ss))) ss)
        (unless (or (pair? ss) (symbol? ss))
          (let ((got (receive (after 5000 'none) (`#(dialer-connected ,@d ,c) c))))
            (check "C1: the dialer received tcp-connected after establishment" (not (eq? got 'none)))
            (let ((r (raw-tls-session-recv! ss 3000)))
              (check "C1: the server read the dialer's plaintext through the codec" (and (bytevector? r) (equal? (utf8->string r) "hello-from-dialer")) r))
            (raw-tls-session-send! ss (string->utf8 "hello-from-server"))
            (receive (after 3000 (check "C1: dialer read" #f 'timeout))
              (`#(dialer-read ,x) (check "C1: the dialer read the server's plaintext through the codec" (equal? x "hello-from-server") x)))
            (when (not (eq? got 'none))
              (let ((h (tls-conn-peer-cb-hash got)))
                (check "C1: the dialer can read the peer certificate hash (32 bytes for the SHA-256 test cert)" (and (bytevector? h) (= (bytevector-length h) 32)) h)))
            (raw-tls-session-close! ss)
            (send d (vector 'dialer-stop))
            (receive (after 3000 (check "C1: dialer done" #f 'timeout))
              (`#(dialer-done ,@d ,evs) (check "C1: the dialer saw exactly one connected and no failure" (equal? evs '(connected)) evs))))))
      (raw-tls-server-stop! srv))

    ;; ---- C2 (M3b): while the server withholds its first flight, no tcp-connected;
    ;; after release exactly one
    (let ((srv (raw-tls-server-start "127.0.0.1" port (in-dir "good.pem") (in-dir "good.key") '((hold-flight . #t)))))
      (sleep-ms 100)
      (let ((d (dial! ctx (lambda (c) (void)))))
        (receive (after 1500 (check "C2: no tcp-connected while the handshake is held" #t))
          (`#(dialer-connected ,@d ,c) (check "C2: no tcp-connected while the handshake is held" #f 'connected-early))
          (`#(dialer-failed ,@d ,why) (check "C2: no failure while the handshake is held" #f why)))
        (raw-tls-server-release! srv)
        (let ((ss (raw-tls-server-accept srv 5000)))
          (receive (after 5000 (check "C2: connected after release" #f 'timeout))
            (`#(dialer-connected ,@d ,c) (check "C2: exactly one tcp-connected after release" #t)))
          (unless (or (pair? ss) (symbol? ss)) (raw-tls-session-close! ss)))
        (send d (vector 'dialer-stop))
        (receive (after 3000 (void)) (`#(dialer-done ,@d ,evs) (check "C2: event list is exactly (connected)" (equal? evs '(connected)) evs))))
      (raw-tls-server-stop! srv))

    ;; ---- C3: the server closes during the handshake: exactly one tcp-connect-failed,
    ;; never a tcp-connected
    (let ((srv (raw-tls-server-start "127.0.0.1" port (in-dir "good.pem") (in-dir "good.key") '((hold-flight . #t)))))
      (sleep-ms 100)
      (let ((d (dial! ctx (lambda (c) (void)))))
        (sleep-ms 300)
        ;; the held driver closes its socket WITHOUT sending its flight: a handshake
        ;; broken by the peer (stopping the listener would not do it -- an accepted
        ;; socket outlives its listener, and a released flight completes the handshake)
        (raw-tls-server-abort! srv)
        (receive (after 6000 (check "C3: a failure was delivered" #f 'timeout))
          ;; the reason is (retire-path . reason) or a bare symbol; both name the cause
          (`#(dialer-failed ,@d ,why) (check "C3: tcp-connect-failed delivered with a reason" (or (symbol? why) (and (pair? why) (symbol? (car why)) (symbol? (cdr why)))) why))
          (`#(dialer-connected ,@d ,c) (check "C3: no tcp-connected on a broken handshake" #f)))
        (send d (vector 'dialer-stop))
        (receive (after 3000 (void))
          (`#(dialer-done ,@d ,evs) (check "C3: exactly one failure, no connected" (and (= (length evs) 1) (pair? (car evs))) evs))))
      (raw-tls-server-stop! srv))

    ;; ---- C4: the dialer dies mid-handshake: nothing leaks
    (let ((srv (raw-tls-server-start "127.0.0.1" port (in-dir "good.pem") (in-dir "good.key") '((hold-flight . #t)))))
      (sleep-ms 100)
      (let ((d (dial! ctx (lambda (c) (void)))))
        (sleep-ms 300)
        (kill d 'c4-dialer-killed-mid-handshake)
        (raw-tls-server-release! srv)
        (let ((ss (raw-tls-server-accept srv 3000))) (unless (or (pair? ss) (symbol? ss)) (raw-tls-session-close! ss)))
        (check "C4: sessions and watchers back to baseline after a dialer died mid-handshake" (within? 6000 (lambda () (equal? (snap) base))) (snap) base))
      (raw-tls-server-stop! srv))

    ;; ---- C5 (mode A): a CA the server's cert is not signed by -> failure before any data
    ;; self.pem is a self-signed cert that did NOT sign good.pem: a wrong trust anchor
    (let ((ctx-a (tls-mesh-client-context! (in-dir "self.pem"))))
      (let ((srv (raw-tls-server-start "127.0.0.1" port (in-dir "good.pem") (in-dir "good.key"))))
        (sleep-ms 100)
        (let ((d (dial! ctx-a (lambda (c) (void)))))
          (receive (after 6000 (check "C5: verification failure delivered" #f 'timeout))
            (`#(dialer-failed ,@d ,why) (check "C5: wrong CA -> tcp-connect-failed" #t why))
            (`#(dialer-connected ,@d ,c) (check "C5: wrong CA must not connect" #f)))
          (send d (vector 'dialer-stop)) (receive (after 3000 (void)) (`#(dialer-done ,@d ,evs) 'ok)))
        (raw-tls-server-stop! srv))
      (tls-context-retire! ctx-a))

    (tls-context-retire! ctx)
    (check "resources back to baseline at the end" (within? 6000 (lambda () (equal? (snap) base))) (snap) base)
    (if (zero? fails)
        (begin (display "ALL TLS-CONNECT TESTS PASSED\n") (exit 0))
        (begin (display "TLS-CONNECT VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1))))))
