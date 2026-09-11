#!chezscheme
;; B' cleanup records -- recovery and accounting cells (design v4 §6).
;;   N7a a pending record that fits in one round survives a reaper outage:
;;       the replacement reaper's STARTUP rescan finishes it while the periodic
;;       scan is 60 s away.
;;   N7b a reaper outage with a record larger than one round (70 > K = 64):
;;       the replacement's startup rescan makes exactly one round and enters its
;;       loop with six owed; its periodic scan (500 ms, read at its start)
;;       finishes them.
;;   N8  hosted accounting: many hosted monitors from b, removal, each agent
;;       stopped once, callee agents and the permit count back to base.
;;   N9  boundedness: 300 monitors + 300 calls outstanding on b; a killed link
;;       is reclaimed in bounded rounds -- another peer's dead link is reclaimed
;;       while b's record is still owed; everything is delivered eventually (no
;;       single-period claim).
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
;; callers report once and then stay alive forwarding strays (see cleanup-record-exec.sc)
(define live-callers '())
(define (spawn-callers! n main)
  (let loop ((i 0))
    (when (< i n)
      (set! live-callers
            (cons (spawn (lambda ()
                           (send main (vector 'call-outcome i (guard (e (#t e)) (rcall 'b 'svc (list 'q i) 60000))))
                           (let fwd () (receive (m (send main (vector 'stray i m)) (fwd))))))
                  live-callers))
      (loop (+ i 1)))))
(define live-callers-ended '())
(define (end-callers!) (for-each (lambda (p) (kill p 'cell-done)) live-callers) (set! live-callers-ended (append live-callers live-callers-ended)) (set! live-callers '()))
(define (no-strays! label ms)
  (receive (after ms (check label #t))
    (`#(remote-down b ,name ,reason) (check label #f (list 'remote-down name reason)))
    (`#(stray ,tag ,m) (check label #f (list 'stray tag m)))))
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
;; node-start! returns before the warden has spawned all its children: the
;; baseline is the count once it has stopped changing for half a second
(define (settled-process-count)
  (let loop ((n (process-count)) (stable 0))
    (if (>= stable 500) n
        (begin (sleep-ms 100)
               (let ((m (process-count))) (if (= m n) (loop n (+ stable 100)) (loop m 0)))))))
(define (records-finished? ms) (within? ms (lambda () (eqv? (stat 'cleanup-records) 0))))

(start-scheduler
  (lambda ()
    (define main self)
    (register 'main self)
    (register 'svc (spawn (lambda () (let loop () (receive (x (loop)))))))
    (set-link-reaper-scan-ms! 60000)                        ; read by the reaper at (re)start: N7a's premise
    (node-start! 'a secret port "127.0.0.1")
    (monitor-node 'b) (monitor-node 'c)
    (let ((rbase (stat 'rmonitors)) (obase (stat 'owner-agents)) (cbase (stat 'callee-agents)) (abase (stat 'accounted)) (pbase (settled-process-count)))
      (define (cell-done! label)
        (end-callers!)
        (check (string-append label ": every process the cell created is gone (agents stopped, not only unrowed)")
               (within? 8000 (lambda () (eqv? (process-count) pbase))) (process-count) pbase))

      ;; ---- N7a: reaper outage, record fits in one round -----------------------
      (let ((b1 (open-peer "b" BOOT-X 1)))
        (check "N7a: b installed" (not (pair? b1)) b1)
        (expect-up! "N7a: node-up b" 'b 3000)
        (let ((mrefs (arm-monitors! 3)))
          (spawn-callers! 2 main)
          (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 3000)
          ;; hold the ORIGINAL reaper first (it would act on the publish hint at once)
          (let* ((tr (arm! 'link-reaper-loop-entry 1))
                 ;; with a 60 s scan the reaper sits in its receive: nudge it with a harmless
                 ;; hint so it re-enters the loop and parks at loop-entry
                 (wr (begin (send (reaper) (vector 'cleanup-published)) (wait! tr 'link-reaper-loop-entry 5000)))
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
                    (check "N7a: the record is gone right after the notifications (startup rescan; the periodic scan is 60 s away)" (records-finished? 2000) (stat 'cleanup-records))))
                (cleanup! tk 'warden-child-before-register)))))
        (no-strays! "N7a: no duplicates" 800)
        (cell-done! "N7a"))

      ;; ---- N7b: reaper outage, record larger than one round (70 > K = 64) ------
      (let ((b1 (open-peer "b" BOOT-X 1)))
        (check "N7b: b installed" (not (pair? b1)) b1)
        (expect-up! "N7b: node-up b" 'b 3000)
        (let ((mrefs (arm-monitors! 70)))
          (check "N7b: the peer saw the last mon frame" (and (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'mon) (eq? (cadr d) 'm69))) 5000) #t))
          (let* ((tr (arm! 'link-reaper-loop-entry 1))
                 (wr (begin (send (reaper) (vector 'cleanup-published)) (wait! tr 'link-reaper-loop-entry 5000)))
                 (t (arm! 'cleanup-before-round 1)) (link ($node-link-pid 'b)))
            (check "N7b: the original reaper is held" (pair? wr) (show wr))
            (plain-peer-close! b1)                         ; primary = the link's guard
            (let ((w (wait! t 'cleanup-before-round 8000)))
              (check "N7b: the primary parked with 70 obligations published" (and (pair? w) (eq? (cdr w) link) (eqv? (stat 'cleanup-records) 1)) (list (show w) (stat 'cleanup-records)))
              (expect-down! "N7b: node-down b" 'b 6000)
              (when (pair? w) (kill (cdr w) 'n7b-primary-killed) (guard (e (#t (void))) (inject-release! t)))
              (cleanup! t 'cleanup-before-round)
              (set-link-reaper-scan-ms! 500)               ; read by the REPLACEMENT at its start
              (let ((tk (arm! 'warden-child-before-register 1)) (r0 (reaper)))
                (kill r0 'n7b-reaper-killed)
                (guard (e (#t (void))) (inject-release! tr)) (cleanup! tr 'link-reaper-loop-entry)
                (let ((k (wait! tk 'warden-child-before-register 5000)))
                  (check "N7b: the replacement reaper parked before registering" (pair? k) (show k))
                  (check "N7b: premise -- 70 obligations still owed during the outage" (and (eqv? (stat 'cleanup-records) 1) (eqv? (stat 'cleanup-obligations) 70)) (list (stat 'cleanup-records) (stat 'cleanup-obligations)))
                  ;; hold the replacement at its FIRST loop entry: after its startup rescan, before any periodic scan
                  (let ((tl (arm! 'link-reaper-loop-entry 1)))
                    (resume! tk k) (cleanup! tk 'warden-child-before-register)
                    (let ((wl (wait! tl 'link-reaper-loop-entry 8000)))
                      (check "N7b: the replacement reached its loop entry after the startup rescan" (and (pair? wl) (eq? (cdr wl) (reaper))) (show wl))
                      (let ((d1 (collect-downs 64 8000)))
                        (check "N7b: the startup rescan made exactly one round: 64 monitors fired once" (all-down-once? d1 64) (length d1))
                        (no-strays! "N7b: ...and no more while the replacement is held at its loop entry" 800)
                        (check "N7b: six obligations remain owed on the still-pending record" (and (eqv? (stat 'cleanup-records) 1) (eqv? (stat 'cleanup-obligations) 6)) (list (stat 'cleanup-records) (stat 'cleanup-obligations)))
                        (let ((t0 (now-ms)))
                          (resume! tl wl) (cleanup! tl 'link-reaper-loop-entry)
                          (let ((d2 (collect-downs 6 8000)))
                            (check "N7b: the periodic scan finished the remaining six, once each" (all-down-once? d2 6) d2)
                            (check "N7b: 70 distinct monitors, each once, across the two visits" (all-down-once? (append d1 d2) 70) (length (append d1 d2)))
                            (display "  [N7b] the rest finished after ms ") (display (- (now-ms) t0)) (newline))))
                      (no-strays! "N7b: no duplicates" 800)
                      (check "N7b: the record finished" (records-finished? 8000) (stat 'cleanup-records)))))))))
        (cell-done! "N7b"))

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
        (check "N8: the permit count is back to base (each hosted monitor released exactly once)"
               (within? 8000 (lambda () (eqv? (stat 'accounted) abase))) (stat 'accounted) abase)
        (check "N8: the record finished" (records-finished? 8000) (stat 'cleanup-records))
        (cell-done! "N8"))

      ;; ---- N9: boundedness with a second peer reclaimed meanwhile ----------------
      (let ((b1 (open-peer "b" BOOT-X 1)) (c1 (open-peer "c" "c0c0c0c0c0c0c0c0" 1)))
        (check "N9: b and c installed" (and (not (pair? b1)) (not (pair? c1))) (list b1 c1))
        (expect-up! "N9: node-up b" 'b 3000) (expect-up! "N9: node-up c" 'c 3000)
        (let ((mrefs (arm-monitors! 300)))
          (define (calls) (plain-peer-count b1 (lambda (d) (and (pair? d) (eq? (car d) 'call)))))
          (define (mons) (plain-peer-count b1 (lambda (d) (and (pair? d) (eq? (car d) 'mon)))))
          (spawn-callers! 300 main)
          (check "N9: premise -- all 300 calls and 300 monitors reached the peer and are outstanding at the kill"
                 (within? 10000 (lambda () (and (>= (calls) 300) (>= (mons) 300)))) (list (calls) (mons)))
          (let ((t0 (now-ms)))
            (kill ($node-link-pid 'b) 'n9-kill-b)          ; reclaimed by the reaper, one round per rescan
            (sleep-ms 200)
            (kill ($node-link-pid 'c) 'n9-kill-c)          ; must not wait for b's 600 obligations
            (expect-down! "N9: node-down c arrives while b's record is still being paid (bounded rounds keep the mailbox served)" 'c 4000)
            (check "N9: ...and b's record was indeed still owed at that moment (not drained in one invocation)"
                   (and (>= (stat 'cleanup-records) 1) (> (stat 'cleanup-obligations) 0)) (list (stat 'cleanup-records) (stat 'cleanup-obligations)))
            (expect-down! "N9: node-down b" 'b 6000)
            (let ((outs (collect-calls 300 30000)) (downs (collect-downs 300 30000)))
              (check "N9: all 300 calls failed exactly once" (all-noconnection? outs 300) (length outs))
              (check "N9: all 300 monitors fired exactly once" (all-down-once? downs 300) (length downs))
              (display "  [N9] 600 obligations delivered after ms ") (display (- (now-ms) t0)) (newline))
            (no-strays! "N9: no duplicates" 800)
            (check "N9: records finished" (records-finished? 10000) (stat 'cleanup-records))))
        (plain-peer-close! b1) (plain-peer-close! c1)
        (check "N9: both peer fixtures exited after close" (within? 4000 (lambda () (and (not (plain-peer-alive? b1)) (not (plain-peer-alive? c1))))) (list (plain-peer-alive? b1) (plain-peer-alive? c1)))
        (check "N9: the callers were all ended" (within? 4000 (lambda () (begin (end-callers!) (not (exists process-alive? live-callers-ended))))))
        (cell-done! "N9"))

      (check "baseline: rmonitors" (eqv? (stat 'rmonitors) rbase) (stat 'rmonitors) rbase)
      (check "baseline: owner agents" (within? 5000 (lambda () (eqv? (stat 'owner-agents) obase))) (stat 'owner-agents) obase)
      (check "baseline: callee agents" (within? 8000 (lambda () (eqv? (stat 'callee-agents) cbase))) (stat 'callee-agents) cbase))
    (if (zero? fails)
        (begin (display "ALL CLEANUP-RECORD-REAPER TESTS PASSED\n") (exit 0))
        (begin (display "CLEANUP-RECORD-REAPER VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
