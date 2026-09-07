#!chezscheme
;; C cells: the connector monitors its attempt child.
;;
;; Node a dials peer p, served by the raw TLS server fixture speaking the v5
;; mesh handshake (as in tls-mesh-dial). After the welcome, the attempt child
;; IS the link process, so $node-link-pid gives its pid. A child that dies by
;; kill sends no result; before C the connector waited for that result for
;; ever and never dialled again.
;;
;;   M19   the child is killed before it reports -> the connector dials again
;;   M19f  the child dies before the parent's monitor call (parent parked at
;;         'attempt-before-monitor) -> DOWN is immediate, attempt! returns #f,
;;         the connector dials again
;;   M19b  result already in the mailbox AND the child's DOWN queued behind it
;;         (parent parked at 'attempt-before-result-receive) -> settle! leaves
;;         no straggler ('attempt-settled-clean is reached, -straggler is not)
;;   M19c  the child parks after sending its result until the parent settled;
;;         it then exits with the monitor already removed -> no DOWN; the
;;         connector dials again
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr libuv) now-ms)
        (igropyr inject-control)
        (only (igropyr tls-core) tls-live-session-count)
        (test tls-raw-server) (test mesh-proof))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define dir "/tmp/igropyr-tls-mesh-attempt")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))
(define (in-dir f) (string-append dir "/" f))
(define node-port 18620)
(define srv-port 18621)
(define secret "tls-mesh-attempt-secret-0123456789abcdef")
(define srv-boot "abcdefabcdefabcd")
(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))
(define (read-frame s ms)
  (let loop ((acc ""))
    (let* ((n (string-length acc))
           (nl (let scan ((k 0)) (cond ((= k n) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1))))))
           (len (and nl (string->number (substring acc 0 nl)))))
      (if (and len (>= n (+ nl 1 len)))
          (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len))))
          (let ((r (raw-tls-session-recv! s ms))) (if (bytevector? r) (loop (string-append acc (utf8->string r))) r))))))
;; accept one dial from a, complete the v5 handshake as p -> session or (no-session ...)
(define (serve-one! srv ms)
  (let ((ss (raw-tls-server-accept srv ms)))
    (if (or (pair? ss) (symbol? ss))
        (list 'no-session ss)
        (let ((nonce-a "0123456789abcdef0123456789abcdef") (cb (raw-tls-server-cb-hash srv)))
          (raw-tls-session-send! ss (frame-bytes (list 'challenge nonce-a 5 srv-boot)))
          (let ((h (read-frame ss 5000)))
            (if (not (and (pair? h) (eq? (car h) 'hello) (= (length h) 7)))
                (begin (raw-tls-session-close! ss) (list 'no-hello h))
                (let ((nonce-b (cadddr h)))
                  (raw-tls-session-send! ss (frame-bytes (list 'welcome "p" (v5-proof-a secret nonce-b "p" srv-boot cb))))
                  ss)))))))

(start-scheduler
  (lambda ()
    (define (expect-up! label ms)
      (receive (after ms (check label #f 'no-node-up)) (`#(node-up p) (check label #t))))
    (define (expect-down! label ms)
      (receive (after ms (check label #f 'no-node-down)) (`#(node-down p) (check label #t))))
    (define (session? x) (not (pair? x)))
    ;; never write a pcb (cyclic): show a barrier wait result by process id
    (define (show w) (if (and (pair? w) (not (symbol? (cdr w)))) (list (car w) (process-id (cdr w))) w))
    ;; after node-disconnect!: swallow late dials from the previous cell until 1.5 s of quiet
    (define (drain-dials! srv)
      (let loop ()
        (let ((x (raw-tls-server-accept srv 1500)))
          (unless (or (pair? x) (symbol? x)) (raw-tls-session-close! x) (loop)))))
    (register 'main self)
    (node-start! 'a secret node-port "127.0.0.1"
                 (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))
    (monitor-node 'p)
    (let ((srv (raw-tls-server-start "127.0.0.1" srv-port (in-dir "good.pem") (in-dir "good.key")))
          (base (tls-live-session-count)))

      ;; ---- M19: the attempt child is killed before it reports --------------
      (node-connect! 'p "127.0.0.1" srv-port)
      (let ((s1 (serve-one! srv 8000)))
        (check "M19: a dialled and was welcomed" (session? s1) s1)
        (expect-up! "M19: node-up p" 3000)
        (let ((link ($node-link-pid 'p)))
          (check "M19: the attempt child is the link process" (and link (process-alive? link)) (and link (process-id link)))
          (when link
            (kill link 'm19-killed-before-report)
            (expect-down! "M19: node-down p (the reaper reclaimed the entry)" 5000)
            (let ((t0 (now-ms)) (s2 (serve-one! srv 20000)))
              (check "M19: the connector dialled again after the kill" (session? s2) s2)
              (display "  [M19] re-dial after ms ") (display (- (now-ms) t0)) (newline)
              (expect-up! "M19: node-up p again" 3000)
              (when (session? s1) (raw-tls-session-close! s1))
              (when (session? s2)
                ;; hand the new link a clean end so the next cell starts from nothing
                (raw-tls-session-close! s2)
                (expect-down! "M19: node-down after the clean close" 5000))))))
      (node-disconnect! 'p)
      (drain-dials! srv)

      ;; ---- M19f: the child dies before the parent's monitor call -----------
      (let ((t-mon (inject-arm-barrier! 'attempt-before-monitor 1 30000)))
        (node-connect! 'p "127.0.0.1" srv-port)
        (let ((w (inject-barrier-wait t-mon 'attempt-before-monitor 5000)))
          (check "M19f: the connector parked between spawn and monitor" (pair? w) (show w))
          (let ((s1 (serve-one! srv 8000)))
            (check "M19f: the child dialled and was welcomed while the parent is parked" (session? s1) s1)
            (expect-up! "M19f: node-up p" 3000)
            (let ((link ($node-link-pid 'p)))
              (check "M19f: the child is the link process" (and link (process-alive? link)) (and link (process-id link)))
              (when link (kill link 'm19f-killed-before-monitor))
              (check "M19f: the child is dead before the parent monitors it" (within? 2000 (lambda () (not (process-alive? link)))))
              (when (pair? w) (send (cdr w) (vector 'inject-resume t-mon)))
              (expect-down! "M19f: node-down p" 5000)
              (let ((s2 (serve-one! srv 20000)))
                (check "M19f: the connector dialled again (monitor on a dead child -> immediate DOWN -> failed attempt)" (session? s2) s2)
                (expect-up! "M19f: node-up p again" 3000)
                (when (session? s1) (raw-tls-session-close! s1))
                (when (session? s2) (raw-tls-session-close! s2) (expect-down! "M19f: node-down after the clean close" 5000))))))
        (guard (e (#t (void))) (inject-barrier-cleanup! t-mon 'attempt-before-monitor 2000)))
      (node-disconnect! 'p)
      (drain-dials! srv)

      ;; ---- M19b: result in the mailbox with the DOWN queued behind it ------
      (let ((t-recv (inject-arm-barrier! 'attempt-before-result-receive 1 30000)))
        (node-connect! 'p "127.0.0.1" srv-port)
        (let ((w (inject-barrier-wait t-recv 'attempt-before-result-receive 5000)))
          (check "M19b: the connector parked before its result receive" (pair? w) (show w))
          (let ((s1 (serve-one! srv 8000)))
            (check "M19b: welcomed" (session? s1) s1)
            (expect-up! "M19b: node-up p" 3000)
            (let ((link ($node-link-pid 'p)))
              ;; the peer closes cleanly: the link ends, the child sends its result and exits
              (when (session? s1) (raw-tls-session-close! s1))
              (check "M19b: the child exited after reporting" (and link (within? 5000 (lambda () (not (process-alive? link))))))
              (expect-down! "M19b: node-down p" 5000)
              (let ((t-clean (inject-arm-barrier! 'attempt-settled-clean 1 30000))
                    (t-strag (inject-arm-barrier! 'attempt-settled-straggler 1 30000)))
                (when (pair? w) (send (cdr w) (vector 'inject-resume t-recv)))
                (let ((c (inject-barrier-wait t-clean 'attempt-settled-clean 5000)))
                  (check "M19b: settle! left no straggler (the clean point was reached)" (pair? c) (show c))
                  (check "M19b: the straggler point was not reached" (eq? (inject-barrier-wait t-strag 'attempt-settled-straggler 300) 'timeout))
                  (when (pair? c) (send (cdr c) (vector 'inject-resume t-clean))))
                ;; liveness: the connector goes on to dial again -- serve it BEFORE any
                ;; cleanup wait, the dialer's handshake timer is running
                (let ((s2 (serve-one! srv 20000)))
                  (check "M19b: the connector dialled again" (session? s2) s2)
                  (expect-up! "M19b: node-up p again" 3000)
                  (when (session? s2) (raw-tls-session-close! s2) (expect-down! "M19b: node-down after the clean close" 5000)))
                (guard (e (#t (void))) (inject-release! t-strag))
                (guard (e (#t (void))) (inject-barrier-cleanup! t-clean 'attempt-settled-clean 2000))))))
        (guard (e (#t (void))) (inject-barrier-cleanup! t-recv 'attempt-before-result-receive 2000)))
      (node-disconnect! 'p)
      (drain-dials! srv)

      ;; ---- M19c: the child reports and then stays alive across the parent's
      ;; settle!; settle! must have DROPPED the child monitor (demonitor), so the
      ;; connector's monitor count returns to its pre-monitor baseline even while
      ;; the child is still alive. Without demonitor the count stays one higher.
      (let ((t-mon (inject-arm-barrier! 'attempt-before-monitor 1 30000))
            (t-child (inject-arm-barrier! 'attempt-child-after-result 1 30000))
            (t-clean (inject-arm-barrier! 'attempt-settled-clean 1 30000)))
        (node-connect! 'p "127.0.0.1" srv-port)
        (let* ((mw (inject-barrier-wait t-mon 'attempt-before-monitor 5000))
               (conn-pid (and (pair? mw) (cdr mw)))
               (base-mons (and conn-pid (process-monitor-count conn-pid))))
          (check "M19c: the connector parked before monitoring its child" (and conn-pid #t) (show mw))
          (when (pair? mw) (send (cdr mw) (vector 'inject-resume t-mon)))
          (let ((s1 (serve-one! srv 8000)))
            (check "M19c: welcomed" (session? s1) s1)
            (expect-up! "M19c: node-up p" 3000)
            (let ((link ($node-link-pid 'p)))
              (when (session? s1) (raw-tls-session-close! s1))    ; the link ends -> the child reports 'up
              (let ((cw (inject-barrier-wait t-child 'attempt-child-after-result 5000)))
                (check "M19c: the child parked after sending its result" (and (pair? cw) (eq? (cdr cw) link)) (show cw))
                (let ((c (inject-barrier-wait t-clean 'attempt-settled-clean 5000)))
                  (check "M19c: the parent settled while the child is still alive" (and (pair? c) (eq? (cdr c) conn-pid)) (show c))
                  (check "M19c: premise -- the child is still alive at settle time" (and link (process-alive? link)))
                  (check "M19c: settle! dropped the child monitor (count back to the pre-monitor baseline)"
                         (and base-mons conn-pid (= (process-monitor-count conn-pid) base-mons))
                         (list 'base base-mons 'after (and conn-pid (process-monitor-count conn-pid))))
                  (when (pair? cw) (send (cdr cw) (vector 'inject-resume t-child)))
                  (check "M19c: the child exited" (and link (within? 3000 (lambda () (not (process-alive? link))))))
                  (when (pair? c) (send (cdr c) (vector 'inject-resume t-clean)))))
              (expect-down! "M19c: node-down p" 5000)
              (let ((s2 (serve-one! srv 20000)))
                (check "M19c: the connector dialled again after a demonitored child's death" (session? s2) s2)
                (expect-up! "M19c: node-up p again" 3000)
                (when (session? s2) (raw-tls-session-close! s2) (expect-down! "M19c: node-down after the clean close" 5000))))))
        (guard (e (#t (void))) (inject-barrier-cleanup! t-mon 'attempt-before-monitor 2000))
        (guard (e (#t (void))) (inject-barrier-cleanup! t-child 'attempt-child-after-result 2000))
        (guard (e (#t (void))) (inject-barrier-cleanup! t-clean 'attempt-settled-clean 2000)))
      (node-disconnect! 'p)

      (check "baseline: TLS sessions back to baseline" (within? 8000 (lambda () (= (tls-live-session-count) base))) (tls-live-session-count) base)
      (raw-tls-server-stop! srv))
    (if (zero? fails)
        (begin (display "ALL TLS-MESH-ATTEMPT TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-ATTEMPT VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
