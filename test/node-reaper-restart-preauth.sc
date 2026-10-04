#!chezscheme
;;; test/node-reaper-restart-preauth.sc -- a reaper that restarts while a
;;; pre-auth lease is alive finishes its rescan and goes on to serve.
;;;
;;; The replacement reaper rebuilds its watch index by walking the agent
;;; chain and the lease chain. A pid found on the lease chain was indexed
;;; with the value #f ("leases only, no agent key"), and membership on the
;;; next pass was asked with (hashtable-ref watched pid #f) -- which reads
;;; #f as "absent". So a live pre-auth holder was fresh on every pass: the
;;; rescan called monitor on it again and again and never returned. The
;;; reaper was alive and registered and processed no DOWN: agent credit
;;; never came back, dead holders' leases were never retired. The rest of
;;; the image kept running (the scheduler preempts a spinner), which is why
;;; this reads as a bounded poll that runs out, not as a hang.
;;;
;;; READINGS. accounted (node-monitor-stats) is the hosted-monitor credit;
;;; it returns to 0 only when the reaper processes the agent's DOWN -- that
;;; is the row the defect turns red. process-monitor-count on the
;;; replacement reaper counts the monitors it is party to, read once the
;;; credit is back (the agent has exited by then): the warden's monitor on
;;; it makes 1; one inherited pre-auth holder makes 2. A reaper spinning in
;;; its rescan runs that number up without bound (5,312,460 in one round on
;;; the unfixed tree); one that skipped the lease walk altogether stays at
;;; 1 (measured: a mutant without the lease walk is red on that row). So
;;; that reading is both the defect and the fix.
;;;
;;; TIMING THAT MATTERS. A pre-auth lease lives at most handshake-timeout-ms
;;; (5 s): a silent connection is freed by the acceptor itself after that,
;;; and an unfixed reaper's rescan then terminates on its own. Every round
;;; therefore prepares its peer and victim BEFORE opening the silent
;;; connection, and reads preauth-slots = 1 again at the moment the credit
;;; came back -- a credit that returned after the lease expired is not the
;;; fix. The warden stops the node at the fifth reaper death spread over
;;; 5 s; this file kills the reaper four times.
;;;
;;; Not covered, stated: a holder that died without freeing its lease (the
;;; rescan's "monitor a dead pid delivers its DOWN at once" path and the
;;; DOWN handler's lease sweep) -- the holder pid is private to node.sc;
;;; a chain that is unlinked under the rescan between its chunks (more than
;;; one chunk of holders, one of them released mid-walk), which is a
;;; separate defect of the walk, queued;
;;; the upgrade of a lease-only index entry to an agent key (no admission
;;; path makes the acceptor's pid an agent); the per-pass memory growth.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp) (igropyr node)
        (only (igropyr crypto) hmac-sha256 bytevector->hex))

(define port 18099)
(define secret "test-mesh-secret")
(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))
(define (fail! label . info)
  (apply check label #f info)
  (display "node-reaper-restart-preauth: aborted\n") (exit 1))

(define (stat key) (let ((p (assq key (node-monitor-stats)))) (and p (cdr p))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define reaper-name 'igropyr-node-reaper)

;; ---- the wire, copied from test/node.sc ---------------------------------------------------
(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))
(define (read-frame-or-closed label)
  (let loop ((acc ""))
    (let* ((n (string-length acc))
           (nl (let scan ((k 0))
                 (cond ((= k n) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1))))))
           (len (and nl (string->number (substring acc 0 nl)))))
      (if (and len (>= n (+ nl 1 len)))
          (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len))))
          (receive (after 4000 (fail! label 'frame-timeout acc))
            (`#(tcp-data ,bv) (loop (string-append acc (utf8->string bv))))
            (`#(tcp-eof) (if (zero? (string-length acc)) 'closed 'closed-with-bytes))
            (`#(tcp-error ,_) (if (zero? (string-length acc)) 'closed 'closed-with-bytes)))))))
(define wire-name-of-this-node "a")
(define probe-boot-id "feedfacefeedface")
(define (v4-hmac msg) (bytevector->hex (hmac-sha256 (string->utf8 secret) (string->utf8 msg))))
(define (v4-proof-d nonce-a name-d bootid-d dialgen name-a bootid-a)
  (v4-hmac (string-append nonce-a ":" name-d ":5:" bootid-d ":" dialgen ":" name-a ":" bootid-a ":")))
;; complete the handshake on an OPEN connection whose challenge has not been read
(define (handshake-on! c name label)
  (let ((d (read-frame-or-closed label)))
    (unless (and (pair? d) (= (length d) 4) (eq? (car d) 'challenge))
      (fail! label 'challenge-shape d))
    (let ((nonce-a (cadr d)) (bootid-a (cadddr d)))
      (tcp-write! c (frame-bytes (list 'hello name
                                       (v4-proof-d nonce-a name probe-boot-id "1" wire-name-of-this-node bootid-a)
                                       "feedfeedfeedfeedfeedfeedfeedfeed" 5 probe-boot-id 1))
                  #f)
      (let ((w (read-frame-or-closed label)))
        (and (pair? w) (eq? (car w) 'welcome))))))
(define (connect! label)
  (tcp-connect! "127.0.0.1" port self)
  (receive (after 3000 (fail! label 'no-connect))
    (`#(tcp-connected ,c) (tcp-read-start! c) c)
    (`#(tcp-connect-failed ,e) (fail! label 'no-connect e))))
;; a peer connection, authenticated, owned by this process
(define (peer! name label)
  (let ((c (connect! label)))
    (unless (handshake-on! c name label) (fail! label 'no-welcome))
    c))
;; A connection owned by its OWN process, so its frames never land in the
;; main mailbox beside the peer's (the peer connection delivers mdown
;; notices there; a handshake read from the main mailbox could take one of
;; those for its challenge). Returns the owner pid; it answers
;; #(handshake name from) with #(handshake-result ok?) and #(close).
(define (open-conn! label)
  (let ((me self))
    (spawn
      (lambda ()
        (let ((c (connect! label)))
          (send me (vector 'opened self))
          (let loop ()
            (receive
              (`#(handshake ,name ,from)
                (send from (vector 'handshake-result (handshake-on! c name label)))
                (loop))
              ;; frames stay in the mailbox for the handshake's own reads
              (`#(close) (tcp-close! c)))))))
    (receive (after 3000 (fail! label 'no-open)) (`#(opened ,p) p))))
(define (conn-handshake! owner name)
  (send owner (vector 'handshake name self))
  (receive (after 6000 #f) (`#(handshake-result ,ok) ok)))
(define (conn-close! owner) (send owner (vector 'close)))

;; ---- one restart with an armed monitor: kill, replacement, credit back ------------------
;; `silent` is the pre-auth connection to hold open through the restart, or #f
(define (restart-round! label peer victim-name key silent)
  (let ((victim (spawn (lambda () (receive (after 60000 (void)) (`#(stop) (void)))))))
    (register victim-name victim)
    (tcp-write! peer (frame-bytes (list 'mon victim-name key)) #f)
    (check (string-append label ": the hosted monitor is accounted")
           (within? 1500 (lambda () (eqv? (stat 'accounted) 1))) (node-monitor-stats))
    (let ((r0 (whereis reaper-name)) (t0 (now-ms)))
      (unless r0 (fail! label 'no-reaper))
      (kill r0 'cell-kill)
      (check (string-append label ": the warden brings up a replacement (a different, live pid)")
             (within? 2500 (lambda () (let ((r (whereis reaper-name)))
                                        (and r (not (eq? r r0)) (process-alive? r)))))
             (whereis reaper-name))
      (when silent
        (check (string-append label ": the pre-auth lease is still held at the restart")
               (eqv? (stat 'preauth-slots) 1) (node-monitor-stats)))
      ;; the replacement must get past its rescan: kill the victim, the
      ;; credit must come back -- and come back while the lease is still held
      (kill victim 'cell-kill)
      (let ((back (within? 2000 (lambda () (eqv? (stat 'accounted) 0)))))
        (check (string-append label ": the replacement processes the agent's DOWN -- credit back within 2 s")
               back (node-monitor-stats))
        (when silent
          (check (string-append label ": ...while the lease was still held (not after it expired)")
                 (and back (eqv? (stat 'preauth-slots) 1) (< (- (now-ms) t0) 4500))
                 (node-monitor-stats) (- (now-ms) t0))))
      (let ((r (whereis reaper-name)))
        (when r
          (sleep-ms 200)
          (let ((n (process-monitor-count r)))
            (check (string-append label ": the replacement is party to exactly "
                                  (if silent "2 monitors (the warden's on it, its own on the inherited holder)"
                                      "1 monitor (the warden's on it; the agent has exited)"))
                   (eqv? n (if silent 2 1)) n)))))))

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (sleep-ms 200)
    (register 'main self)
    (let ((peer (peer! "preauthpeer" "setup")))
      (sleep-ms 100)
      (check "setup: no pre-auth lease, no credit out" (and (eqv? (stat 'preauth-slots) 0) (eqv? (stat 'accounted) 0))
             (node-monitor-stats))

      ;; ---- twin: a restart with NO pre-auth lease (green before and after) ------------------
      (restart-round! "twin, no lease" peer 'victim-0 7000 #f)

      ;; ---- two rounds with a live pre-auth lease at the restart -----------------------------
      (do ((i 1 (+ i 1))) ((> i 2))
        (let* ((label (string-append "round " (number->string i)))
               (silent (open-conn! label)))
          (check (string-append label ": a silent connection holds a pre-auth lease")
                 (within? 1000 (lambda () (eqv? (stat 'preauth-slots) 1))) (node-monitor-stats))
          (restart-round! label peer (string->symbol (string-append "victim-" (number->string i))) (+ 7000 i) silent)
          (conn-close! silent)
          (check (string-append label ": closing it frees the lease (the acceptor's own release)")
                 (within? 1500 (lambda () (eqv? (stat 'preauth-slots) 0))) (node-monitor-stats))))

      ;; ---- authentication across a restart, on the same connection -------------------------
      (let ((c (open-conn! "auth")))
        (check "auth: the connection holds a pre-auth lease"
               (within? 1000 (lambda () (eqv? (stat 'preauth-slots) 1))) (node-monitor-stats))
        (let ((r0 (whereis reaper-name)))
          (kill r0 'cell-kill)
          (check "auth: a replacement reaper is up"
                 (within? 2500 (lambda () (let ((r (whereis reaper-name))) (and r (not (eq? r r0)) (process-alive? r)))))
                 (whereis reaper-name)))
        (check "auth: the handshake completes on that connection after the restart"
               (conn-handshake! c "latepeer"))
        (check "auth: completing it frees the pre-auth lease"
               (within? 1500 (lambda () (eqv? (stat 'preauth-slots) 0))) (node-monitor-stats))
        (conn-close! c))

      ;; ---- final ---------------------------------------------------------------------------
      (sleep-ms 300)
      (check "final: no credit out, no lease held, the reaper registered and alive"
             (and (eqv? (stat 'accounted) 0) (eqv? (stat 'preauth-slots) 0)
                  (let ((r (whereis reaper-name))) (and r (process-alive? r))))
             (node-monitor-stats))
      (tcp-close! peer))
    (if (zero? failures)
        (begin (display "node-reaper-restart-preauth: all tests passed\n") (exit 0))
        (begin (display "node-reaper-restart-preauth: ") (display failures) (display " failed\n") (exit 1)))))
