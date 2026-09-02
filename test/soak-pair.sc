#!chezscheme
;;; soak-pair.sc -- two REAL nodes on two machines, churning a real link.
;;;
;;; This is a discovery tool, not a cell: it runs monitor/demonitor, rcall,
;;; rsend and reconnect churn across a real WAN for a set time, and keeps
;;; asserting the node's own accounting invariants. It cannot produce a
;;; rerunnable red for a KNOWN defect -- the loopback cells do that -- but
;;; it can surface an UNKNOWN one under timing the loopback suite never
;;; sees. When an invariant breaks it dumps the full stats and exits 2;
;;; the dump is the thing to bring back to a cell.
;;;
;;; usage:
;;;   chez --script test/soak-pair.sc ROLE SELF PORT HOST PEER PEER-HOST PEER-PORT SECRET SECONDS
;;;   ROLE = a (driver: watches, calls, sends, reconnects)  |  b (targets, killer, server)
;;; Run b first on one machine, then a on the other. Both bind HOST (the
;;; tunnel address), never the public interface.
(import (chezscheme) (igropyr actor) (igropyr node) (igropyr gen-server))

(define args (cdr (command-line)))
(unless (= (length args) 9)
  (display "usage: soak-pair.sc ROLE SELF PORT HOST PEER PEER-HOST PEER-PORT SECRET SECONDS\n")
  (exit 64))
(define role      (string->symbol (list-ref args 0)))
(define self-name (string->symbol (list-ref args 1)))
(define port      (string->number (list-ref args 2)))
(define host      (list-ref args 3))
(define peer      (string->symbol (list-ref args 4)))
(define peer-host (list-ref args 5))
(define peer-port (string->number (list-ref args 6)))
(define secret    (list-ref args 7))
(define seconds   (string->number (list-ref args 8)))

(define (now) (let ((t (current-time))) (+ (* 1000 (time-second t)) (quotient (time-nanosecond t) 1000000))))
(define t0 (now))
(define (elapsed) (- (now) t0))
(define (log . xs)
  (display (elapsed)) (display "ms ") (display role) (display ": ")
  (for-each (lambda (x) (display x) (display " ")) xs) (newline))
(define (stat k) (let ((e (assq k (node-monitor-stats)))) (and e (cdr e))))
(define (anomaly! label . xs)
  (log "ANOMALY" label xs)
  (display (node-monitor-stats)) (newline)
  (display (node-outbound-stats)) (newline)
  (display (list 'orphans (node-orphan-count) 'peers (node-peers))) (newline)
  (exit 2))

;; ALWAYS-true invariants (hold at every scheduler-visible boundary, per the
;; accounting design): accounted == |global chain|; per-peer chains never
;; exceed the global chain; a remote watch always has its owner agent.
(define (always-check! label)
  (let ((g (stat 'mon-chain)) (p (stat 'mon-peer-chains)) (a (stat 'accounted))
        (rm (stat 'rmonitors)) (oa (stat 'owner-agents)))
    (unless (= a g) (anomaly! label 'accounted/=global a g))
    (unless (<= p g) (anomaly! label 'peer-chains>global p g))
    (unless (>= rm oa) (anomaly! label 'owner-agents>rmonitors rm oa))))
;; AT-REST invariants (only when the driver has paused its churn): the
;; three monitor readings agree, no orphan queue heads, watches and their
;; owner agents match exactly.
(define (rest-check! label)
  (always-check! label)
  (let ((g (stat 'mon-chain)) (p (stat 'mon-peer-chains)) (a (stat 'accounted))
        (rm (stat 'rmonitors)) (oa (stat 'owner-agents)))
    (unless (= g p a) (anomaly! label 'chains-disagree-at-rest g p a))
    (unless (= rm oa) (anomaly! label 'rmonitors/=owner-agents-at-rest rm oa))
    (unless (zero? (node-orphan-count)) (anomaly! label 'orphans (node-orphan-count)))))

(define (rand n) (random n))
(define target-names (map (lambda (i) (string->symbol (string-append "t" (number->string i)))) '(0 1 2 3 4 5 6 7)))

(start-scheduler
  (lambda ()
    (node-start! self-name secret port host)
    (node-set-limits! 256 4096)
    (node-connect! peer peer-host peer-port)
    (monitor-node peer)
    (log "started; peer" peer peer-host peer-port)
    (case role
      ;; ---------------------------------------------------------------- b
      ((b)
       ;; targets that respawn when killed, a killer, an rcall server, a sink
       (for-each
         (lambda (nm)
           (spawn (lambda ()
                    (let keep ()
                      (let ((p (spawn (lambda () (receive (`#(stop) (void)))))))
                        (register nm p)
                        (let ((m (monitor p)))
                          (receive (`#(DOWN ,@p ,_) (void))))
                        (sleep-ms (+ 50 (rand 150)))
                        (keep))))))
         target-names)
       (spawn (lambda ()
                (let loop ()
                  (sleep-ms (+ 400 (rand 1200)))
                  (let ((p (whereis (list-ref target-names (rand 8)))))
                    (when p (kill p 'soak-kill)))
                  (loop))))
       ;; handle-call returns (values reply state); handle-cast returns state
       ;; -- the protocol node-child.sc's servers use
       (gen-server-start-named 'svc
         (lambda () 0)
         (lambda (msg from st)
           (if (and (pair? msg) (eq? (car msg) 'echo))
               (values (cadr msg) (+ st 1))
               (values 'bad st)))
         (lambda (msg st) st))
       (register 'sink (spawn (lambda () (let loop () (receive (_ (loop)))))))
       ;; a's driver asks us to check at rest by rsend'ing #(quiesce k)
       (register 'ctl (spawn (lambda ()
                               (let loop ()
                                 (receive
                                   (`#(quiesce ,k) (sleep-ms 700) (rest-check! (list 'b-rest k)) (log "rest ok" k) (loop))
                                   (_ (loop)))))))
       (let watch ()
         (sleep-ms 1500)
         (always-check! 'b-always)
         (receive (after 0 (void))
           (`#(node-down ,@peer) (log "peer down"))
           (`#(node-up ,@peer) (log "peer up")))
         (when (< (elapsed) (* 1000 (+ seconds 15))) (watch)))
       (log "b done")
       (exit 0))
      ;; ---------------------------------------------------------------- a
      ((a)
       (let loop ((held '()) (downs 0) (calls 0) (ok 0) (round 0) (last-rest 0) (last-reconn 0))
         (cond
           ((> (elapsed) (* 1000 seconds))
            (for-each demonitor-remote held)
            (sleep-ms 3000)
            (rest-check! 'a-final)
            (rsend peer 'ctl (vector 'quiesce 'final))
            (sleep-ms 2500)
            (log "DONE rounds" round "rcalls" calls "ok" ok "remote-downs" downs "held" (length held))
            (exit 0))
           (else
            (let* ((op (rand 10))
                   (held
                     (cond
                       ;; arm a watch, but keep the driver's own book bounded:
                       ;; a fired watch is gone from rmonitors and its mref is
                       ;; dead, and remote-down does not carry the mref, so
                       ;; the book cannot shed it precisely -- shed the oldest
                       ;; instead once it is long. Below the peer's hosting
                       ;; cap most of the time, so overload is exercised but
                       ;; is not the only thing exercised.
                       ((and (< op 4) (< (length held) 200))
                        (cons (monitor-remote peer (list-ref target-names (rand 8))) held))
                       ((and (< op 6) (pair? held))    ; cancel one
                        (demonitor-remote (car held)) (cdr held))
                       ((> (length held) 150)          ; shed the oldest few
                        (for-each demonitor-remote (list-tail held 100))
                        (let take ((h held) (n 100) (acc '()))
                          (if (or (null? h) (zero? n)) (reverse acc)
                              (take (cdr h) (- n 1) (cons (car h) acc)))))
                       (else held)))
                   (calls (if (= op 6) (+ calls 1) calls))
                   (ok (if (= op 6)
                           ;; a failed rcall is logged WITH its reason and
                           ;; time, so the handful that fail can be laid
                           ;; against the reconnect windows afterwards --
                           ;; a swallowed reason is a reading nobody can
                           ;; attribute (first run: 3 of 470, cause unknown)
                           (guard (e (#t (log "rcall failed" (if (vector? e) (vector->list e) e)) ok))
                             (if (equal? (rcall peer 'svc (list 'echo round) 4000) round) (+ ok 1) ok))
                           ok)))
              (when (= op 7) (rsend peer 'sink (vector 'blob round (make-string 2000 #\x))))
              ;; drain notices without blocking. RETURNS the new down count:
              ;; the first version tail-called the loop from the `after 0`
              ;; branch, so nothing below this point ever ran -- no rest
              ;; checks on this side, no reconnect churn, no pacing -- and
              ;; the driver spun 6000 rounds a second. A drain must come
              ;; back to its caller.
              (let ((downs
                      (let drain ((downs downs))
                        (receive (after 0 downs)
                          (`#(remote-down ,@peer ,_ ,_) (drain (+ downs 1)))
                          (`#(node-down ,@peer) (log "peer down; watches will report noconnection") (drain downs))
                          (`#(node-up ,@peer) (log "peer up") (drain downs))
                          (_ (drain downs)))))
                    (last-rest
                      ;; every ~3s pause and check at rest, asking b to check too
                      (if (> (- (elapsed) last-rest) 3000)
                          (begin (sleep-ms 800)
                                 (rest-check! (list 'a-rest round))
                                 (log "rest ok" round)   ; silent success is unreadable afterwards
                                 (rsend peer 'ctl (vector 'quiesce round))
                                 (elapsed))
                          last-rest))
                    (last-reconn
                      ;; every ~20s drop the link and come back (generation churn)
                      (if (> (- (elapsed) last-reconn) 20000)
                          (begin (log "reconnect churn")
                                 (node-disconnect! peer)
                                 (sleep-ms 1200)
                                 (node-connect! peer peer-host peer-port)
                                 (sleep-ms 2500)
                                 (elapsed))
                          last-reconn)))
                (sleep-ms (rand 40))
                (loop held downs calls ok (+ round 1) last-rest last-reconn)))))))
      (else (display "ROLE must be a or b\n") (exit 64)))))
