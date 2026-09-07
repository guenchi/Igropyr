#!chezscheme
;; B' cleanup records -- recovery and accounting cells (design v4 §6).
;;   N7a a pending record that fits in one round survives a reaper outage:
;;       the replacement reaper's STARTUP rescan finishes it while the periodic
;;       scan is 60 s away.
;;   N7b a record larger than one round: the startup rescan makes one round of
;;       progress, the periodic scan (500 ms) finishes it -- run in a second node
;;       process? No: the scan interval is read at reaper (re)start, so N7b uses
;;       a reaper restart with the interval set to 500 ms before that restart.
;;   N8  hosted accounting: many hosted monitors from b, removal, each agent
;;       stopped once, callee agents back to base after the agent reaper's DOWNs.
;;   N9  boundedness: 300 monitors + 300 calls on b; a killed link is reclaimed
;;       in bounded rounds while another peer's dead link is reclaimed within a
;;       period plus a scan; everything is delivered eventually (no single-period
;;       claim).
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr libuv) now-ms)
        (igropyr inject-control)
        (test plain-peer))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define port 18730)
(define secret "cleanup-record-reaper-secret-0123456789abcdef")
(define BOOT-X "feedfacefeedface")
(define (stat key) (let ((p (assq key (node-monitor-stats)))) (and p (cdr p))))
(define (arm! point occ) (inject-arm-barrier! point occ 60000))
(define (wait! t point ms) (inject-barrier-wait t point ms))
(define (resume! t w) (when (pair? w) (send (cdr w) (vector 'inject-resume t))))
(define (cleanup! t point) (guard (e (#t (void))) (inject-release! t)) (guard (e (#t (void))) (inject-barrier-cleanup! t point 2000)))
(define (show w) (if (and (pair? w) (not (symbol? (cdr w)))) (list (car w) (process-id (cdr w))) w))
(define (open-peer name boot gen) (plain-peer-open "127.0.0.1" port name boot gen secret 6000))
(define (expect-down! label who ms) (receive (after ms (check label #f 'no-node-down)) (`#(node-down ,@who) (check label #t))))
(define (expect-up! label who ms) (receive (after ms (check label #f 'no-node-up)) (`#(node-up ,@who) (check label #t))))
(define (noconnection? r) (and (vector? r) (eq? (vector-ref r 0) 'rcall-error) (eq? (vector-ref r 1) 'noconnection)))
(define (spawn-callers! n main) (let loop ((i 0)) (when (< i n) (spawn (lambda () (send main (vector 'call-outcome i (guard (e (#t e)) (rcall 'b 'svc (list 'q i) 60000)))))) (loop (+ i 1)))))
(define (collect-calls n ms)
  (let ((deadline (+ (now-ms) ms)))
    (let loop ((acc '()))
      (if (or (= (length acc) n) (> (now-ms) deadline)) acc
          (receive (after (max 1 (- deadline (now-ms))) acc) (`#(call-outcome ,i ,r) (loop (cons (cons i r) acc))))))))
(define (arm-monitors! n) (let loop ((i 0) (acc '())) (if (= i n) (reverse acc) (loop (+ i 1) (cons (monitor-remote 'b (string->symbol (string-append "m" (number->string i)))) acc)))))
(define (collect-downs n ms)
  (let ((deadline (+ (now-ms) ms)))
    (let loop ((acc '()))
      (if (or (= (length acc) n) (> (now-ms) deadline)) acc
          (receive (after (max 1 (- deadline (now-ms))) acc) (`#(remote-down b ,name ,reason) (loop (cons (cons name reason) acc))))))))
(define (all-noconnection? outs n) (and (= (length outs) n) (for-all (lambda (p) (noconnection? (cdr p))) outs)))
(define (all-down-once? downs n) (and (= (length downs) n) (for-all (lambda (p) (eq? (cdr p) 'noconnection)) downs)
                                      (= n (length (let dedup ((l (map car downs)) (seen '())) (cond ((null? l) seen) ((memq (car l) seen) (dedup (cdr l) seen)) (else (dedup (cdr l) (cons (car l) seen)))))))))
(define (reaper) (whereis 'igropyr-node-link-reaper))
(define (records-finished? ms) (within? ms (lambda () (eqv? (stat 'cleanup-records) 0))))

(start-scheduler
  (lambda ()
    (define main self)
    (register 'main self)
    (register 'svc (spawn (lambda () (let loop () (receive (x (loop)))))))
    (set-link-reaper-scan-ms! 60000)                        ; read by the reaper at (re)start: N7a's premise
    (node-start! 'a secret port "127.0.0.1")
    (monitor-node 'b) (monitor-node 'c)
    (let ((rbase (stat 'rmonitors)) (obase (stat 'owner-agents)) (cbase (stat 'callee-agents)))

      ;; ---- N7a: reaper outage, record fits in one round -----------------------
      (let ((b1 (open-peer "b" BOOT-X 1)))
        (check "N7a: b installed" (not (pair? b1)) b1)
        (expect-up! "N7a: node-up b" 'b 3000)
        (let ((mrefs (arm-monitors! 3)))
          (spawn-callers! 2 main)
          (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 3000)
          ;; hold the ORIGINAL reaper first (it would act on the publish hint at once)
          (let* ((tr (arm! 'link-reaper-loop-entry 1))
                 (wr (wait! tr 'link-reaper-loop-entry 5000))
                 (t (arm! 'cleanup-before-round 1)) (link ($node-link-pid 'b)))
            (check "N7a: the original reaper is held" (pair? wr) (show wr))
            (plain-peer-close! b1)                         ; primary = the link's guard
            (let ((w (wait! t 'cleanup-before-round 8000)))
              (check "N7a: the primary parked with the record published" (and (pair? w) (eq? (cdr w) link) (eqv? (stat 'cleanup-records) 1)) (list (show w) (stat 'cleanup-records)))
              (expect-down! "N7a: node-down b" 'b 6000)
              (when (pair? w) (kill (cdr w) 'n7a-primary-killed) (guard (e (#t (void))) (inject-release! t)))
              (cleanup! t 'cleanup-before-round)
              (sleep-ms 800)
              (check "N7a: premise -- the record is still pending (reaper held, periodic scan 60 s away)" (eqv? (stat 'cleanup-records) 1) (stat 'cleanup-records))
              ;; kill the (parked) reaper; hold its warden replacement before it registers; still pending
              (let ((tk (arm! 'warden-child-before-register 1)) (r0 (reaper)))
                (kill r0 'n7a-reaper-killed)
                (guard (e (#t (void))) (inject-release! tr)) (cleanup! tr 'link-reaper-loop-entry)
                (let ((k (wait! tk 'warden-child-before-register 5000)))
                  (check "N7a: the replacement reaper parked before registering" (pair? k) (show k))
                  (check "N7a: premise -- still pending during the outage" (eqv? (stat 'cleanup-records) 1) (stat 'cleanup-records))
                  (let ((t0 (now-ms)))
                    (resume! tk k)
                    (let ((outs (collect-calls 2 6000)) (downs (collect-downs 3 6000)))
                      (check "N7a: the startup rescan finished the record: calls failed once" (all-noconnection? outs 2) outs)
                      (check "N7a: ...monitors fired once" (all-down-once? downs 3) downs)
                      (display "  [N7a] finished by the startup rescan after ms ") (display (- (now-ms) t0)) (newline))
                    (check "N7a: the record is gone within 2 s (startup rescan, not the 60 s periodic scan)" (records-finished? 2000) (stat 'cleanup-records))))
                (cleanup! tk 'warden-child-before-register))))))

      ;; ---- N7b: a record larger than one round (K = 64) ----------------------
      ;; the reaper is restarted with a 500 ms interval so the periodic scan can finish it
      (set-link-reaper-scan-ms! 500)
      (let ((r0 (reaper))) (kill r0 'n7b-restart-with-short-interval)
        (check "N7b: reaper restarted" (within? 5000 (lambda () (let ((r (reaper))) (and r (process-alive? r) (not (eq? r r0))))))))
      (let ((b1 (open-peer "b" BOOT-X 1)))
        (check "N7b: b installed" (not (pair? b1)) b1)
        (expect-up! "N7b: node-up b" 'b 3000)
        (let ((mrefs (arm-monitors! 70)))
          (let ((t (arm! 'cleanup-before-round 1)) (link ($node-link-pid 'b)))
            (plain-peer-close! b1)
            (let ((w (wait! t 'cleanup-before-round 8000)))
              (check "N7b: the primary parked with 70 obligations published" (and (pair? w) (eq? (cdr w) link)) (show w))
              (expect-down! "N7b: node-down b" 'b 6000)
              (when (pair? w) (kill (cdr w) 'n7b-primary-killed) (guard (e (#t (void))) (inject-release! t)))
              (cleanup! t 'cleanup-before-round)
              (let ((t0 (now-ms)) (downs (collect-downs 70 15000)))
                (check "N7b: all 70 monitors fired exactly once across several rounds" (all-down-once? downs 70) (length downs))
                (display "  [N7b] 70 obligations finished after ms ") (display (- (now-ms) t0)) (newline))
              (check "N7b: the record finished" (records-finished? 8000) (stat 'cleanup-records))))))

      ;; ---- N8: hosted accounting -------------------------------------------------
      (let ((b1 (open-peer "b" BOOT-X 1)))
        (check "N8: b installed" (not (pair? b1)) b1)
        (expect-up! "N8: node-up b" 'b 3000)
        ;; the PEER monitors 'svc on a 30 times: a hosts 30 agents
        (let loop ((i 0)) (when (< i 30) (plain-peer-send! b1 (list 'mon 'svc (+ 5000 i))) (loop (+ i 1))))
        (check "N8: a hosts 30 monitors for b" (within? 5000 (lambda () (eqv? (stat 'callee-agents) (+ cbase 30)))) (stat 'callee-agents) cbase)
        (plain-peer-close! b1)                           ; removal by the link's guard
        (expect-down! "N8: node-down b" 'b 6000)
        (check "N8: every hosted agent was stopped once and retired by the agent reaper (callee agents back to base)"
               (within? 8000 (lambda () (eqv? (stat 'callee-agents) cbase))) (stat 'callee-agents) cbase)
        (check "N8: the record finished" (records-finished? 8000) (stat 'cleanup-records)))

      ;; ---- N9: boundedness with a second peer reclaimed meanwhile ----------------
      (let ((b1 (open-peer "b" BOOT-X 1)) (c1 (open-peer "c" "c0c0c0c0c0c0c0c0" 1)))
        (check "N9: b and c installed" (and (not (pair? b1)) (not (pair? c1))) (list b1 c1))
        (expect-up! "N9: node-up b" 'b 3000) (expect-up! "N9: node-up c" 'c 3000)
        (let ((mrefs (arm-monitors! 300)))
          (spawn-callers! 300 main)
          (check "N9: the peer saw calls" (and (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 5000) #t))
          (let ((t0 (now-ms)))
            (kill ($node-link-pid 'b) 'n9-kill-b)          ; reclaimed by the reaper, one round per rescan
            (sleep-ms 200)
            (kill ($node-link-pid 'c) 'n9-kill-c)          ; must not wait for b's 600 obligations
            (expect-down! "N9: node-down c within a period plus a scan (bounded rounds keep the mailbox served)" 'c 4000)
            (expect-down! "N9: node-down b" 'b 6000)
            (let ((outs (collect-calls 300 30000)) (downs (collect-downs 300 30000)))
              (check "N9: all 300 calls failed exactly once" (all-noconnection? outs 300) (length outs))
              (check "N9: all 300 monitors fired exactly once" (all-down-once? downs 300) (length downs))
              (display "  [N9] 600 obligations delivered after ms ") (display (- (now-ms) t0)) (newline))
            (check "N9: records finished" (records-finished? 10000) (stat 'cleanup-records))))
        (plain-peer-close! b1) (plain-peer-close! c1))

      (check "baseline: rmonitors" (eqv? (stat 'rmonitors) rbase) (stat 'rmonitors) rbase)
      (check "baseline: owner agents" (within? 5000 (lambda () (eqv? (stat 'owner-agents) obase))) (stat 'owner-agents) obase)
      (check "baseline: callee agents" (within? 8000 (lambda () (eqv? (stat 'callee-agents) cbase))) (stat 'callee-agents) cbase))
    (if (zero? fails)
        (begin (display "ALL CLEANUP-RECORD-REAPER TESTS PASSED\n") (exit 0))
        (begin (display "CLEANUP-RECORD-REAPER VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
