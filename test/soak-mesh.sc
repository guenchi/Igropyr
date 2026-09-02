#!chezscheme
;;; soak-mesh.sc -- three real nodes, one of them dying and coming back.
;;;
;;; Extends soak-pair.sc with a third role. What a mesh of three exercises
;;; that a pair cannot: pubsub forwarding one hop to two peers, a
;;; third party's node-up/down, the simultaneous-dial tie-break, and --
;;; the reason this exists -- a node being REPLACED BY A NEW INCARNATION
;;; while another node still watches it and a third still hosts watches
;;; for it. That is the territory of the watch-ownership rules (I6, the
;;; hosted-monitor sweep, stale-live refusal, mref reuse after restart)
;;; and loopback cannot reach it: the crash has to be real.
;;;
;;; Roles:
;;;   a  driver: arms/cancels watches on b AND c, calls b, drops and
;;;      re-dials, quiesces both peers for at-rest checks.
;;;   b  host: respawning targets, a killer, an rcall server, a sink;
;;;      hosts watches from a AND c.
;;;   c  the crashy one: hosts targets (so a can watch it) and arms
;;;      watches on b (so b hosts for two peers). It is meant to be run
;;;      under a supervisor that SIGKILLs it at random and restarts it --
;;;      every restart is a new boot id, a new incarnation.
;;; A laptop as c adds the other crash: lid closed, no packets at all,
;;; peers learn only from dead-ms. Suspend is NOT a restart (same boot id,
;;; same run: a same-incarnation reconnect); only a killed process is.
;;;
;;; usage:
;;;   soak-mesh.sc ROLE SELF PORT HOST SECRET SECONDS P1 H1 PORT1 [P2 H2 PORT2]
;;; Every node binds HOST (the tunnel address) and dials the listed peers.
;;; ⛔ P1/P2 ARE THE PEERS' SELF NAMES -- what each of them passes as SELF --
;;; not role letters. node-connect! authenticates the far end against the
;;; name it was given; a mismatch is a silent handshake refusal, and the
;;; first mesh run formed no links at all for exactly that reason.
(import (chezscheme) (igropyr actor) (igropyr node) (igropyr gen-server) (igropyr http))

(define args (cdr (command-line)))
(unless (>= (length args) 9)
  (display "usage: soak-mesh.sc ROLE SELF PORT HOST SECRET SECONDS P1 H1 PORT1 [P2 H2 PORT2]\n")
  (exit 64))
(define role      (string->symbol (list-ref args 0)))
(define self-name (string->symbol (list-ref args 1)))
(define port      (string->number (list-ref args 2)))
(define host      (list-ref args 3))
(define secret    (list-ref args 4))
(define seconds   (string->number (list-ref args 5)))
(define peers                            ; ((name host port) ...)
  (let loop ((l (list-tail args 6)) (acc '()))
    (if (< (length l) 3) (reverse acc)
        (loop (list-tail l 3)
              (cons (list (string->symbol (car l)) (cadr l) (string->number (caddr l))) acc)))))
(define (peer-name p) (car p))
(define peer-names (map peer-name peers))

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
(define (always-check! label)
  (let ((g (stat 'mon-chain)) (p (stat 'mon-peer-chains)) (a (stat 'accounted))
        (rm (stat 'rmonitors)) (oa (stat 'owner-agents)))
    (unless (= a g) (anomaly! label 'accounted/=global a g))
    (unless (<= p g) (anomaly! label 'peer-chains>global p g))
    (unless (>= rm oa) (anomaly! label 'owner-agents>rmonitors rm oa))))
(define (rest-check! label)
  (always-check! label)
  (let ((g (stat 'mon-chain)) (p (stat 'mon-peer-chains)) (a (stat 'accounted))
        (rm (stat 'rmonitors)) (oa (stat 'owner-agents)))
    (unless (= g p a) (anomaly! label 'chains-disagree-at-rest g p a))
    (unless (= rm oa) (anomaly! label 'rmonitors/=owner-agents-at-rest rm oa))
    (unless (zero? (node-orphan-count)) (anomaly! label 'orphans (node-orphan-count)))))

(define (rand n) (random n))
(define target-names (map (lambda (i) (string->symbol (string-append "t" (number->string i)))) '(0 1 2 3 4 5 6 7)))
(define (pick l) (list-ref l (rand (length l))))

;; ---- shared pieces ------------------------------------------------------
(define (host-targets!)                  ; respawning targets + a killer
  (for-each
    (lambda (nm)
      (spawn (lambda ()
               (let keep ()
                 (let ((p (spawn (lambda () (receive (`#(stop) (void)))))))
                   (register nm p)
                   (let ((m (monitor p))) (receive (`#(DOWN ,@p ,_) (void))))
                   (sleep-ms (+ 50 (rand 150)))
                   (keep))))))
    target-names)
  (spawn (lambda ()
           (let loop ()
             (sleep-ms (+ 400 (rand 1200)))
             (let ((p (whereis (pick target-names)))) (when p (kill p 'soak-kill)))
             (loop)))))
(define (serve!)                          ; rcall server + sink + quiesce control
  (gen-server-start-named 'svc
    (lambda () 0)
    (lambda (msg from st)
      (if (and (pair? msg) (eq? (car msg) 'echo)) (values (cadr msg) (+ st 1)) (values 'bad st)))
    (lambda (msg st) st))
  (register 'sink (spawn (lambda () (let loop () (receive (_ (loop)))))))
  (register 'ctl (spawn (lambda ()
                          (let loop ()
                            (receive
                              (`#(quiesce ,k) (sleep-ms 700) (rest-check! (list role 'rest k)) (log "rest ok" k) (loop))
                              (_ (loop))))))))
(define (drain-notices! downs)           ; -> new down count; logs topology
  (let drain ((downs downs))
    (receive (after 0 downs)
      (`#(remote-down ,_ ,_ ,_) (drain (+ downs 1)))
      (`#(node-down ,n) (log "peer down" n) (drain downs))
      (`#(node-up ,n) (log "peer up" n) (drain downs))
      (_ (drain downs)))))

;; A driver loop: arm/cancel watches on `watch-peers`, call `call-peer`,
;; quiesce every ~3s (self + peers), and -- if `churn?` -- drop and re-dial
;; the first peer every ~20s.
(define (drive! watch-peers call-peer churn?)
  (let loop ((held '()) (downs 0) (calls 0) (ok 0) (round 0) (last-rest 0) (last-reconn 0))
    (cond
      ((> (elapsed) (* 1000 seconds))
       (for-each demonitor-remote held)
       (sleep-ms 3000)
       (rest-check! (list role 'final))
       (for-each (lambda (p) (rsend p 'ctl (vector 'quiesce 'final))) peer-names)
       (sleep-ms 2500)
       (log "DONE rounds" round "rcalls" calls "ok" ok "remote-downs" downs "held" (length held))
       (exit 0))
      (else
       (let* ((op (rand 10))
              (held
                (cond
                  ((and (< op 4) (< (length held) 200))
                   (cons (monitor-remote (pick watch-peers) (pick target-names)) held))
                  ((and (< op 6) (pair? held)) (demonitor-remote (car held)) (cdr held))
                  ((> (length held) 150)
                   (for-each demonitor-remote (list-tail held 100))
                   (let take ((h held) (n 100) (acc '()))
                     (if (or (null? h) (zero? n)) (reverse acc) (take (cdr h) (- n 1) (cons (car h) acc)))))
                  (else held)))
              (calls (if (= op 6) (+ calls 1) calls))
              (ok (if (= op 6)
                      (guard (e (#t (log "rcall failed" (if (vector? e) (vector->list e) e)) ok))
                        (if (equal? (rcall call-peer 'svc (list 'echo round) 4000) round) (+ ok 1) ok))
                      ok)))
         (when (= op 7) (rsend (pick watch-peers) 'sink (vector 'blob round (make-string 2000 #\x))))
         (let ((downs (drain-notices! downs))
               (last-rest
                 (if (> (- (elapsed) last-rest) 3000)
                     (begin (sleep-ms 800)
                            (rest-check! (list role 'rest round))
                            (log "rest ok" round)
                            (for-each (lambda (p) (rsend p 'ctl (vector 'quiesce round))) peer-names)
                            (elapsed))
                     last-rest))
               (last-reconn
                 (if (and churn? (> (- (elapsed) last-reconn) 20000))
                     (let ((p (car peers)))
                       (log "reconnect churn" (peer-name p))
                       (node-disconnect! (peer-name p))
                       (sleep-ms 1200)
                       (node-connect! (peer-name p) (cadr p) (caddr p))
                       (sleep-ms 2500)
                       (elapsed))
                     last-reconn)))
           (sleep-ms (rand 40))
           (loop held downs calls ok (+ round 1) last-rest last-reconn)))))))

(start-scheduler
  (lambda ()
    (node-start! self-name secret port host)
    (node-set-limits! 256 4096)
    (for-each (lambda (p) (node-connect! (peer-name p) (cadr p) (caddr p)) (monitor-node (peer-name p))) peers)
    (log "started; peers" peer-names "boot" (node-self))
    ;; With SOAK_HTTP_PORT set, ANY role also answers HTTP on the tunnel
    ;; address: an external load generator on another machine (ab, or
    ;; test/soak-load.sc) then shares this node's single scheduler with the
    ;; link churn and the crash-looping peer -- the mix neither loopback nor
    ;; the mesh alone produces. Two hosts serving and loading each other
    ;; makes the pressure mutual.
    (let ((hp (getenv "SOAK_HTTP_PORT")))
      (when hp
        (http-listen (string->number hp)
          (lambda (req res) (res-send! res (string->utf8 "pong")))
          (list (cons 'host host) (cons 'workers 4)))
        (log "http listening on" host hp)))
    (case role
      ((b)
       (host-targets!) (serve!)
       (let watch ()
         (sleep-ms 1500)
         (always-check! 'b-always)
         (drain-notices! 0)
         (when (< (elapsed) (* 1000 (+ seconds 15))) (watch)))
       (log "b done") (exit 0))
      ((c)
       ;; hosts targets for a, arms watches on b, never churns the link
       ;; itself -- its supervisor supplies the crashes
       (host-targets!) (serve!)
       (drive! (list (peer-name (car peers))) (peer-name (car peers)) #f))
      ((a)
       (serve!)                           ; so c's quiesce requests land
       (drive! peer-names (peer-name (car peers)) #t))
      (else (display "ROLE must be a, b or c\n") (exit 64)))))
