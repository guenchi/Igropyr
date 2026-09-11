#!chezscheme
;; B' cleanup records -- execution cells (design v4 §6): executor death,
;; send-allocation failure, competing executors, competing ordinary completion,
;; hint loss. Plaintext node a, plain peer b (test/plain-peer.sc).
;;
;; Who executes a record: after a KILL the link reaper's DOWN handler runs
;; remove-peer! (one bounded round; the rest by its rescan); after a clean
;; peer close the LINK's own guard runs it (unbounded). The cells choose the
;; executor by choosing kill vs close.
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
(define port 18720)
(define secret "cleanup-record-exec-secret-0123456789abcdef")
(define BOOT-X "feedfacefeedface")
(define (stat key) (let ((p (assq key (node-monitor-stats)))) (and p (cdr p))))
(define (arm! point occ) (inject-arm-barrier! point occ 60000))
(define (wait! t point ms) (inject-barrier-wait t point ms))
(define (resume! t w) (when (pair? w) (send (cdr w) (vector 'inject-resume t))))
(define (cleanup! t point) (guard (e (#t (void))) (inject-release! t)) (guard (e (#t (void))) (inject-barrier-cleanup! t point 2000)))
(define (show w) (if (and (pair? w) (not (symbol? (cdr w)))) (list (car w) (process-id (cdr w))) w))
(define (open-b boot gen) (plain-peer-open "127.0.0.1" port "b" boot gen secret 6000))
(define (expect-up! label ms) (receive (after ms (check label #f 'no-node-up)) (`#(node-up b) (check label #t))))
(define (expect-down! label ms) (receive (after ms (check label #f 'no-node-down)) (`#(node-down b) (check label #t))))
(define (noconnection? r) (and (vector? r) (eq? (vector-ref r 0) 'rcall-error) (eq? (vector-ref r 1) 'noconnection)))
(define (timeout-error? r) (and (vector? r) (eq? (vector-ref r 0) 'rcall-error) (eq? (vector-ref r 1) 'timeout)))
;; a caller reports #(call-outcome tag r) once and then STAYS ALIVE, forwarding
;; anything else it receives as #(stray tag m): a second reply to the same call
;; would otherwise vanish with a caller that had already exited. end-callers!
;; kills them when the cell is done.
(define live-callers '())
(define (spawn-call! tag main msg tmo)
  (let ((p (spawn (lambda ()
                    (send main (vector 'call-outcome tag (guard (e (#t e)) (rcall 'b 'svc msg tmo))))
                    (let fwd () (receive (m (send main (vector 'stray tag m)) (fwd))))))))
    (set! live-callers (cons p live-callers))
    p))
(define (end-callers!) (for-each (lambda (p) (kill p 'cell-done)) live-callers) (set! live-callers '()))
;; n callers whose calls stay pending (the peer does not answer)
(define (spawn-callers! n main tmo)
  (let loop ((i 0)) (when (< i n) (spawn-call! i main (list 'q i) tmo) (loop (+ i 1)))))
;; nothing more arrives: no second remote-down, no message to a caller that already returned
(define (no-strays! label ms)
  (receive (after ms (check label #t))
    (`#(remote-down b ,name ,reason) (check label #f (list 'remote-down name reason)))
    (`#(stray ,tag ,m) (check label #f (list 'stray tag m)))))
;; collect outcomes for n callers within ms -> alist i -> r (each i at most once by construction)
(define (collect-calls n ms)
  (let ((deadline (+ (now-ms) ms)))
    (let loop ((acc '()))
      (if (or (= (length acc) n) (> (now-ms) deadline)) acc
          (receive (after (max 1 (- deadline (now-ms))) acc)
            (`#(call-outcome ,i ,r) (loop (cons (cons i r) acc))))))))
;; n remote monitors b/m0..m(n-1) -> mrefs; collect their remote-downs
(define (arm-monitors! n) (let loop ((i 0) (acc '())) (if (= i n) (reverse acc) (loop (+ i 1) (cons (monitor-remote 'b (string->symbol (string-append "m" (number->string i)))) acc)))))
(define (collect-downs n ms)
  (let ((deadline (+ (now-ms) ms)))
    (let loop ((acc '()))
      (if (or (= (length acc) n) (> (now-ms) deadline)) acc
          (receive (after (max 1 (- deadline (now-ms))) acc)
            (`#(remote-down b ,name ,reason) (loop (cons (cons name reason) acc))))))))
(define (all-noconnection? outcomes n) (and (= (length outcomes) n) (for-all (lambda (p) (noconnection? (cdr p))) outcomes)))
(define (all-down-once? downs n) (and (= (length downs) n) (for-all (lambda (p) (eq? (cdr p) 'noconnection)) downs)
                                      (let ((names (map car downs))) (= (length names) (length (let dedup ((l names) (seen '())) (cond ((null? l) seen) ((memq (car l) seen) (dedup (cdr l) seen)) (else (dedup (cdr l) (cons (car l) seen))))))))))
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
    (register 'svc (spawn (lambda () (let loop () (receive (x (loop)))))))   ; a hosted-monitor target on a
    (node-start! 'a secret port "127.0.0.1")
    (monitor-node 'b)
    (let ((rbase (stat 'rmonitors)) (obase (stat 'owner-agents)) (cbase (stat 'callee-agents)) (pbase (settled-process-count)))
      ;; every cell ends with its callers killed and the process count back here:
      ;; agents stopped (not just their rows deleted), peers closed, links gone
      (define (cell-done! label)
        (end-callers!)
        (check (string-append label ": every process the cell created is gone (agents stopped, not only unrowed)")
               (within? 8000 (lambda () (eqv? (process-count) pbase))) (process-count) pbase))

      ;; ---- N3: the executor (the reaper, after a kill) dies inside cleanup ----
      ;; spec: (point occurrence label remote-monitors hosted-monitors). N3d puts
      ;; the death at the start of the SECOND round with hosted obligations
      ;; still owed (3 + 5 + 56 of 70 hosted fill the first).
      (for-each
        (lambda (spec)
          (let ((point (car spec)) (occ (cadr spec)) (label (caddr spec)) (nhosted (car (cddddr spec))))
            (let ((b1 (open-b BOOT-X 1)))
              (check (string-append label ": b installed") (not (pair? b1)) b1)
              (expect-up! (string-append label ": node-up b") 3000)
              (let* ((nmon (cadddr spec)) (mrefs (arm-monitors! nmon)))
                (spawn-callers! 3 main 30000)
                (let loop ((i 0)) (when (< i nhosted) (plain-peer-send! b1 (list 'mon 'svc (+ 7000 i))) (loop (+ i 1))))
                (check (string-append label ": a hosts the peer's monitors") (within? 5000 (lambda () (eqv? (stat 'callee-agents) (+ cbase nhosted)))) (stat 'callee-agents) cbase)
                (check (string-append label ": the peer saw the frames") (and (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 3000) #t))
                (let ((t (arm! point occ)) (r0 (reaper)))
                  (kill ($node-link-pid 'b) 'n3-kill)
                  (let ((w (wait! t point 8000)))
                    (check (string-append label ": the executor parked at " (symbol->string point)) (and (pair? w) (eq? (cdr w) r0)) (show w))
                    (when (pair? w)
                      (check (string-append label ": premise -- the record is pending") (eqv? (stat 'cleanup-records) 1) (stat 'cleanup-records))
                      (kill (cdr w) 'n3-executor-killed)
                      (guard (e (#t (void))) (inject-release! t))))
                  (cleanup! t point))
                ;; the warden restarts the reaper; its startup rescan finishes the record
                (check (string-append label ": a reaper is back") (within? 5000 (lambda () (let ((r (reaper))) (and r (process-alive? r))))))
                (expect-down! (string-append label ": node-down b") 8000)
                (let ((outs (collect-calls 3 10000)) (downs (collect-downs nmon 15000)))
                  (check (string-append label ": every pending call failed exactly once") (all-noconnection? outs 3) outs)
                  (check (string-append label ": every monitor fired DOWN exactly once") (all-down-once? downs nmon) (length downs)))
                (no-strays! (string-append label ": no duplicate remote-down") 800)
                (check (string-append label ": the peer's socket was closed (close obligation done)") (within? 5000 (lambda () (plain-peer-closed? b1))))
                (check (string-append label ": the record finished") (records-finished? 8000) (stat 'cleanup-records))
                (check (string-append label ": owner agents back to base") (within? 5000 (lambda () (eqv? (stat 'owner-agents) obase))) (stat 'owner-agents) obase)
                (check (string-append label ": hosted agents back to base (each stopped once, by the recovery)") (within? 8000 (lambda () (eqv? (stat 'callee-agents) cbase))) (stat 'callee-agents) cbase)
                (check (string-append label ": rmonitors back to base") (eqv? (stat 'rmonitors) rbase) (stat 'rmonitors) rbase))
              (plain-peer-close! b1)
              (cell-done! label)
              (sleep-ms 300))))
        '((cleanup-after-publish 1 "N3a" 5 0) (cleanup-before-round 2 "N3b" 70 0) (cleanup-before-control 1 "N3c" 5 0)
          (cleanup-before-round 2 "N3d" 5 70)))

      ;; ---- N3e: the executor of a REPLACEMENT record (the new link) dies -------
      ;; A same-incarnation replacement (I8a) publishes a record carrying the old
      ;; connection's pending calls and both control obligations (close, stop);
      ;; the hosted agents are NOT on it (they belong to the peer, and survive a
      ;; same-incarnation replacement by design). The new link executes the record
      ;; BEFORE it sends the welcome, so the peer's open is driven from a helper
      ;; and only completes as a failure once the killed link's connection is
      ;; closed. The reaper is held meanwhile, else its rescan would finish the
      ;; record while the executor is parked (N4).
      (let ((b1 (open-b BOOT-X 1)))
        (check "N3e: b installed (C1)" (not (pair? b1)) b1)
        (expect-up! "N3e: node-up b" 3000)
        (let ((mrefs (arm-monitors! 3)) (link1 ($node-link-pid 'b)))
          (spawn-callers! 2 main 30000)
          (let loop ((i 0)) (when (< i 20) (plain-peer-send! b1 (list 'mon 'svc (+ 7000 i))) (loop (+ i 1))))
          (check "N3e: a hosts 20 monitors for b over C1" (within? 5000 (lambda () (eqv? (stat 'callee-agents) (+ cbase 20)))) (stat 'callee-agents) cbase)
          (check "N3e: the peer saw the calls" (and (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 3000) #t))
          (let* ((tr (arm! 'link-reaper-loop-entry 1))
                 (wr (wait! tr 'link-reaper-loop-entry 5000))
                 (t (arm! 'cleanup-before-control 1)))
            (check "N3e: the reaper is held" (pair? wr) (show wr))
            ;; the opener reports #(opened r) when the handshake ends either way
            (spawn (lambda () (send main (vector 'opened (open-b BOOT-X 2)))))   ; I8a: replaces the open C1
            (let ((w (wait! t 'cleanup-before-control 8000)))
              (check "N3e: the replacement's executor (the new link) parked at its close attempt" (and (pair? w) (eq? (cdr w) ($node-link-pid 'b))) (show w))
              (expect-down! "N3e: node-down (C1)" 6000) (expect-up! "N3e: node-up (C2)" 6000)
              (let ((outs (collect-calls 2 6000)))
                (check "N3e: the old connection's calls failed once before the park (collections first)" (all-noconnection? outs 2) outs))
              (check "N3e: the hosted agents survive a same-incarnation replacement (not on the record)" (eqv? (stat 'callee-agents) (+ cbase 20)) (stat 'callee-agents) cbase)
              (check "N3e: premise -- the record is pending with its control obligations (reaper held)" (eqv? (stat 'cleanup-records) 1) (stat 'cleanup-records))
              (when (pair? w) (kill (cdr w) 'n3e-executor-killed) (guard (e (#t (void))) (inject-release! t)))
              (cleanup! t 'cleanup-before-control)
              (sleep-ms 500)
              (check "N3e: premise -- still pending after the executor's death, until the reaper is released" (eqv? (stat 'cleanup-records) 1) (stat 'cleanup-records))
              (resume! tr wr) (cleanup! tr 'link-reaper-loop-entry))
            (expect-down! "N3e: node-down (C2, its link killed)" 8000)
            (receive (after 8000 (check "N3e: the peer's open ended" #f 'no-open-result))
              (`#(opened ,r) (check "N3e: the peer's handshake ended with C2 closed (never welcomed)" (and (pair? r) (pair? (cdr r)) (eq? (cadr r) 'closed-during-handshake)) r)))
            (let ((downs (collect-downs 3 10000)))
              (check "N3e: the inherited monitors fired once, at C2's removal" (all-down-once? downs 3) downs))
            (check "N3e: both records finished (stop retired; C1's close was done in the transaction, its redo is not observable here)" (records-finished? 8000) (stat 'cleanup-records))
            (check "N3e: the hosted agents went with C2's removal" (within? 8000 (lambda () (eqv? (stat 'callee-agents) cbase))) (stat 'callee-agents) cbase)
            (check "N3e: the old link is gone" (within? 5000 (lambda () (not (process-alive? link1)))))
            (no-strays! "N3e: no duplicates" 800))
          (plain-peer-close! b1)
          (check "N3e: owner agents back to base" (within? 5000 (lambda () (eqv? (stat 'owner-agents) obase))) (stat 'owner-agents) obase)
          (cell-done! "N3e")))

      ;; ---- N4: competing executors (link guard vs the reaper's rescan) --------
      (let ((b1 (open-b BOOT-X 1)))
        (check "N4: b installed" (not (pair? b1)) b1)
        (expect-up! "N4: node-up b" 3000)
        (let ((mrefs (arm-monitors! 6)))
          (spawn-callers! 3 main 30000)
          (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 3000)
          (let ((t (arm! 'cleanup-before-round 1)) (link ($node-link-pid 'b)))
            (plain-peer-close! b1)                         ; clean close: the LINK's guard is the primary
            (let ((w (wait! t 'cleanup-before-round 8000)))
              (check "N4: the primary (the link) parked before its first round" (and (pair? w) (eq? (cdr w) link)) (show w))
              (expect-down! "N4: node-down b (enqueued in the transaction)" 6000)
              ;; the reaper's periodic rescan runs the record to completion meanwhile
              (let ((outs (collect-calls 3 10000)) (downs (collect-downs 6 10000)))
                (check "N4: the reaper's rescan delivered every call failure once" (all-noconnection? outs 3) outs)
                (check "N4: ...and every monitor DOWN once" (all-down-once? downs 6) downs))
              (check "N4: the record finished by the rescan while the primary is parked" (records-finished? 8000) (stat 'cleanup-records))
              (resume! t w)
              (no-strays! "N4: the resumed primary found nothing left (no duplicates)" 1000)
              (cleanup! t 'cleanup-before-round))))
        (cell-done! "N4"))

      ;; ---- N11a: competing ordinary completion during cleanup -----------------
      (let ((b1 (open-b BOOT-X 1)))
        (check "N11a: b installed" (not (pair? b1)) b1)
        (expect-up! "N11a: node-up b" 3000)
        (let* ((m-reply-ref #f)
               (mref-mdown (monitor-remote 'b 'mdown))
               (mref-demon (monitor-remote 'b 'demon))
               (victim (spawn (lambda () (let ((m (monitor-remote 'b 'victim))) (receive (x x))))))   ; its owner agent DOWN path
               (short (spawn-call! 'short main '(short) 2500))
               (late  (spawn-call! 'late main '(late) 30000)))
          (let ((fcall (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call) (equal? (cadddr d) '(late)))) 3000)))
            (check "N11a: the peer saw the late call" (and fcall #t))
            (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'mon) (eq? (cadr d) 'victim))) 3000)
            ;; the reaper acts on the publish hint at once, so hold it first: the record
            ;; must stay pending while the competing completions run
            (let* ((tr (arm! 'link-reaper-loop-entry 1))
                   (wr (wait! tr 'link-reaper-loop-entry 5000))
                   (t (arm! 'cleanup-before-round 1)))
              (check "N11a: the reaper is held" (pair? wr) (show wr))
              (plain-peer-close! b1)                        ; primary = link guard; record published
              (let ((w (wait! t 'cleanup-before-round 8000)))
                (check "N11a: the primary parked with the record pending" (and (pair? w) (eqv? (stat 'cleanup-records) 1)) (list (show w) (stat 'cleanup-records)))
                (check "N11a: premise -- the record holds all five slots (three monitors, both calls: the short one has not timed out yet)" (eqv? (stat 'cleanup-obligations) 5) (stat 'cleanup-obligations))
                (expect-down! "N11a: node-down b" 6000)
                ;; reinstall b with the SAME boot id so the peer's frames are admitted (5888)
                (let ((b2 (open-b BOOT-X 1)))
                  (check "N11a: b reinstalled (same boot id)" (not (pair? b2)) b2)
                  (expect-up! "N11a: node-up b (reinstalled)" 6000)
                  ;; (1) a late reply for the old pending ref, through the reinstalled peer
                  (when fcall (plain-peer-send! b2 (list 'reply (caddr fcall) (list 'ok 'late-value))))
                  ;; (2) a peer mdown for an old monitor
                  (plain-peer-send! b2 (list 'mdown mref-mdown 'peer-says-down))
                  ;; (3) the short call times out on its own
                  ;; (4) a demonitor of an old monitor
                  (demonitor-remote mref-demon)
                  ;; (5) the victim caller dies: its owner agent's DOWN path removes that watch
                  (kill victim 'n11-victim)
                  ;; all three watches are retired by their ORDINARY paths while both
                  ;; executors are still held -- so the cleanup cannot be what removed them
                  (check "N11a: the three watches retired by their ordinary paths while both executors are held" (within? 4000 (lambda () (eqv? (stat 'rmonitors) rbase))) (stat 'rmonitors) rbase)
                  (check "N11a: ...with the record still pending" (eqv? (stat 'cleanup-records) 1) (stat 'cleanup-records))
                  ;; (3) the short call times out ON ITS OWN, retiring its slot, while both
                  ;; executors are still held -- so the cleanup must find nothing for it
                  (receive (after 4000 (check "N11a: the short call timed out on its own while both executors are held" #f 'no-outcome))
                    (`#(call-outcome short ,r) (check "N11a: the short call timed out on its own while both executors are held" (timeout-error? r) r)))
                  ;; resume the parked primary: everything it finds is stale or already done
                  (resume! t w)
                  (let ((outs (collect-calls 1 8000)))
                    (check "N11a: the late call got the peer's value once, not noconnection" (equal? (cdr (or (assq 'late outs) '(late . none))) 'late-value) outs))
                  (let ((downs (collect-downs 1 4000)))
                    (check "N11a: the mdown monitor was delivered once with the peer's reason" (equal? downs '((mdown . peer-says-down))) downs))
                  (no-strays! "N11a: no noconnection for the demonitored or the victim's watch, no duplicates" 1200)
                  (check "N11a: the record finished with its stale nodes retired" (records-finished? 8000) (stat 'cleanup-records))
                  (check "N11a: owner agents back to base (each stopped exactly once)" (within? 5000 (lambda () (eqv? (stat 'owner-agents) obase))) (stat 'owner-agents) obase)
                  (cleanup! t 'cleanup-before-round)
                  (resume! tr wr) (cleanup! tr 'link-reaper-loop-entry)
                  (plain-peer-close! b2)
                  (expect-down! "N11a: node-down (reinstalled b closed)" 6000))))))
        (cell-done! "N11a"))

      ;; ---- N11b: a stale chain node left by a seam is retired silently ---------
      (let ((b1 (open-b BOOT-X 1)))
        (check "N11b: b installed" (not (pair? b1)) b1)
        (expect-up! "N11b: node-up b" 3000)
        (let ((mrefs (arm-monitors! 2))
              (stale-caller (spawn (lambda () (send main (vector 'call-outcome 'stale (guard (e (#t e)) (rcall 'b 'svc '(stale) 3000))))))))
          (check "N11b: the peer saw the call whose slot will be taken" (and (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 3000) #t))
          (check "N11b: the seam took the pending slot, leaving its chain node stale" ($node-stale-chain-node! 'b))
          (let ((t (arm! 'cleanup-stale-retired 1)))
            (kill ($node-link-pid 'b) 'n11b-kill)
            (let ((ws (wait! t 'cleanup-stale-retired 8000)))
              (check "N11b: the stale node was retired silently (counted once)" (pair? ws) (show ws))
              (resume! t ws)
              (cleanup! t 'cleanup-stale-retired))
            (expect-down! "N11b: node-down b" 8000)
            (let ((downs (collect-downs 2 8000)))
              (check "N11b: the live monitors still fired exactly once" (all-down-once? downs 2) downs))
            (no-strays! "N11b: nothing for the stale node" 800)
            (let ((outs (collect-calls 1 6000)))
              (check "N11b: the caller whose slot was taken gets only its own timeout (no noconnection)" (and (pair? outs) (timeout-error? (cdar outs))) outs))
            (check "N11b: the record finished" (records-finished? 8000) (stat 'cleanup-records))))
        (plain-peer-close! b1)
        (cell-done! "N11b"))

      ;; ---- N12: the hint is lost, the reaper stays alive ----------------------
      (let ((b1 (open-b BOOT-X 1)))
        (check "N12: b installed" (not (pair? b1)) b1)
        (expect-up! "N12: node-up b" 3000)
        (let ((mrefs (arm-monitors! 3)))
          (spawn-callers! 2 main 30000)
          (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 3000)
          (let ((t (arm! 'cleanup-before-hint 1)) (link ($node-link-pid 'b)) (r0 (reaper)))
            (plain-peer-close! b1)                         ; primary = link guard
            (let ((w (wait! t 'cleanup-before-hint 8000)))
              (check "N12: the primary parked between publishing and the hint" (and (pair? w) (eq? (cdr w) link)) (show w))
              (when (pair? w) (kill (cdr w) 'n12-primary-killed) (guard (e (#t (void))) (inject-release! t)))
              (cleanup! t 'cleanup-before-hint)
              (expect-down! "N12: node-down b" 6000)
              (let ((t0 (now-ms)) (outs (collect-calls 2 10000)) (downs (collect-downs 3 10000)))
                (check "N12: the reaper finished the record without the hint (calls)" (all-noconnection? outs 2) outs)
                (check "N12: ...(monitors)" (all-down-once? downs 3) downs)
                (display "  [N12] recovered without the hint after ms ") (display (- (now-ms) t0)) (newline))
              (check "N12: the record finished" (records-finished? 8000) (stat 'cleanup-records))
              (check "N12: the same reaper did it (alive, not restarted)" (and (eq? (reaper) r0) (process-alive? r0)))))
          (plain-peer-close! b1)
          (cell-done! "N12")))

      ;; ---- N3': a send raises (allocation failure injected) ------------------
      ;; The executor (the reaper, after a kill) must CATCH the raise, RETURN from
      ;; the invocation with the obligation still owed, and finish it on a later
      ;; visit. Two raises in a row, with the loop entry observed between them,
      ;; show the retry is a later visit by the same executor, not a retry in
      ;; place and not a restarted executor.
      (for-each
        (lambda (spec)
          (let ((fault (car spec)) (label (cadr spec)))
            (let ((b1 (open-b BOOT-X 1)))
              (check (string-append label ": b installed") (not (pair? b1)) b1)
              (expect-up! (string-append label ": node-up b") 3000)
              (let ((mrefs (arm-monitors! 4)) (r0 (reaper)))
                (spawn-callers! 2 main 30000)
                (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 3000)
                (inject-arm-fault! fault 1)                 ; the first such send raises once
                (let ((tr (arm! 'cleanup-obligation-raised 1)))
                  (kill ($node-link-pid 'b) 'n3p-kill)
                  (let ((w (wait! tr 'cleanup-obligation-raised 8000)))
                    (check (string-append label ": the executor caught the raise (parked at cleanup-obligation-raised)") (and (pair? w) (eq? (cdr w) r0)) (show w))
                    (expect-down! (string-append label ": node-down b") 8000)
                    (check (string-append label ": premise -- the record is still owed") (eqv? (stat 'cleanup-records) 1) (stat 'cleanup-records))
                    ;; the invocation returns: the reaper reaches its loop entry with the record still owed
                    (let ((tl (arm! 'link-reaper-loop-entry 1)))
                      (resume! tr w) (cleanup! tr 'cleanup-obligation-raised)
                      (let ((wl (wait! tl 'link-reaper-loop-entry 8000)))
                        (check (string-append label ": the invocation returned (the reaper is back at its loop entry) with the record still owed")
                               (and (pair? wl) (eq? (cdr wl) r0) (eqv? (stat 'cleanup-records) 1)) (list (show wl) (stat 'cleanup-records)))
                        ;; a second raise on the next visit: caught again, by the same executor
                        (inject-arm-fault! fault 1)
                        (let ((tr2 (arm! 'cleanup-obligation-raised 1)))
                          (resume! tl wl) (cleanup! tl 'link-reaper-loop-entry)
                          (let ((w2 (wait! tr2 'cleanup-obligation-raised 8000)))
                            (check (string-append label ": the second raise, on a later visit, was caught by the same executor") (and (pair? w2) (eq? (cdr w2) r0)) (show w2))
                            (resume! tr2 w2) (cleanup! tr2 'cleanup-obligation-raised)))))))
                (let ((outs (collect-calls 2 12000)) (downs (collect-downs 4 12000)))
                  (check (string-append label ": every pending call failed exactly once despite the raises") (all-noconnection? outs 2) outs)
                  (check (string-append label ": every monitor fired DOWN exactly once despite the raises") (all-down-once? downs 4) downs))
                (no-strays! (string-append label ": no duplicate remote-down or reply (no replay)") 800)
                (check (string-append label ": the record finished") (records-finished? 8000) (stat 'cleanup-records))
                (check (string-append label ": the reaper survived both raises (same process)") (and (eq? (reaper) r0) (process-alive? r0)))
                (check (string-append label ": owner agents back to base (owner-stop not replayed, not lost)") (within? 5000 (lambda () (eqv? (stat 'owner-agents) obase))) (stat 'owner-agents) obase))
              (plain-peer-close! b1)
              (cell-done! label)
              (sleep-ms 300))))
        '((cleanup-send-remote-down "N3'a") (cleanup-send-owner-stop "N3'b") (cleanup-send-reply "N3'c")))

      ;; ---- N3'd: the same raise, but the executor is the 'unbounded primary --------
      ;; A clean peer close makes the LINK's guard the executor, with rounds =
      ;; 'unbounded. A raise must still END THE INVOCATION: the link returns from
      ;; execute-cleanup! with the monitors owed and exits; nothing more is
      ;; delivered while the reaper is held. An executor that retried in place
      ;; under 'unbounded would deliver the rest at once (the fault is spent).
      (let ((b1 (open-b BOOT-X 1)))
        (check "N3'd: b installed" (not (pair? b1)) b1)
        (expect-up! "N3'd: node-up b" 3000)
        (let ((mrefs (arm-monitors! 4)) (link ($node-link-pid 'b)))
          (spawn-callers! 2 main 30000)
          (plain-peer-wait-frame b1 (lambda (d) (and (pair? d) (eq? (car d) 'call))) 3000)
          (let* ((tr (arm! 'link-reaper-loop-entry 1))
                 (wr (wait! tr 'link-reaper-loop-entry 5000)))
            (check "N3'd: the reaper is held" (pair? wr) (show wr))
            (inject-arm-fault! 'cleanup-send-remote-down 1)
            (let ((t (arm! 'cleanup-obligation-raised 1)))
              (plain-peer-close! b1)                       ; primary = the link's guard, 'unbounded
              (let ((w (wait! t 'cleanup-obligation-raised 8000)))
                (check "N3'd: the primary (the link) caught the raise" (and (pair? w) (eq? (cdr w) link)) (show w))
                (expect-down! "N3'd: node-down b" 6000)
                (let ((outs (collect-calls 2 4000)))
                  (check "N3'd: the calls were answered before the raise (pends first)" (all-noconnection? outs 2) outs))
                (resume! t w) (cleanup! t 'cleanup-obligation-raised)
                (check "N3'd: the invocation ended: the link exited with the monitors still owed" (within? 4000 (lambda () (not (process-alive? link)))))
                (check "N3'd: ...the record is still pending, four obligations owed" (and (eqv? (stat 'cleanup-records) 1) (eqv? (stat 'cleanup-obligations) 4)) (list (stat 'cleanup-records) (stat 'cleanup-obligations)))
                (no-strays! "N3'd: nothing delivered while the reaper is held (no retry in place)" 1500)
                (resume! tr wr) (cleanup! tr 'link-reaper-loop-entry)
                (let ((downs (collect-downs 4 8000)))
                  (check "N3'd: the reaper's next visit delivered every monitor DOWN once" (all-down-once? downs 4) downs))
                (no-strays! "N3'd: no duplicates" 800)
                (check "N3'd: the record finished" (records-finished? 8000) (stat 'cleanup-records))
                (check "N3'd: owner agents back to base" (within? 5000 (lambda () (eqv? (stat 'owner-agents) obase))) (stat 'owner-agents) obase)))))
        (plain-peer-close! b1)
        (cell-done! "N3'd"))

      (check "baseline: rmonitors" (eqv? (stat 'rmonitors) rbase) (stat 'rmonitors) rbase)
      (check "baseline: owner agents" (within? 5000 (lambda () (eqv? (stat 'owner-agents) obase))) (stat 'owner-agents) obase)
      (check "baseline: no cleanup records" (records-finished? 5000) (stat 'cleanup-records)))
    (if (zero? fails)
        (begin (display "ALL CLEANUP-RECORD-EXEC TESTS PASSED\n") (exit 0))
        (begin (display "CLEANUP-RECORD-EXEC VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
