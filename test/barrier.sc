#!chezscheme
;;; Barrier cells: a victim is parked at a named point between two
;;; expressions, and the controller acts while it is parked. Four subjects
;;; (B1-B4) and three cells on the instrument itself (W1-W3). Design:
;;; archive E7-tranche3-barrier-design v3, v5, v8, v9, v10 (higher wins).
;;;
;;; Runs only with IGROPYR_INJECT=on, from source, in ITS OWN PROCESS: B4
;;; kills the node dispatcher on purpose, which test/poison.sc asserts never
;;; happens, so the two suites cannot share a node.
;;;
;;; WHICH POINTS PARK. In the fixed tree two of the four points sit inside
;;; a region and are skipped by construction; only the mutant parks there.
;;;   'tcp-stop-listen-before-close  region  -> skipped (B1: mutant parks)
;;;   'fs-open-before-region         none    -> parks   (B2, W1-W3)
;;;   'fs-open-after-publish         region  -> skipped (B3: mutant parks)
;;;   'poison-attempt-start          none    -> parks   (B4)
;;; A cell that expects `skipped` and gets (parked . pid) is looking at the
;;; mutant; it then runs the choreography the design wrote for that shape,
;;; so the red names the defect instead of a bare mismatch.
;;;
;;; resumed / skipped / timed-out say the RESERVATION was consumed. Every
;;; cell that needs the victim's work to have happened waits for a witness
;;; the victim sends.
;;;
;;; A WATCHDOG ENDS THE RUN: a parked victim nobody resumes is a hang, and a
;;; hang has no voice of its own.
(import (chezscheme) (igropyr actor) (igropyr node) (igropyr libuv) (igropyr tcp)
        (only (igropyr tcp) fs-req-block-count)
        (igropyr inject-control) (igropyr inject))

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))
(define node-port 18194)
(define listen-port 18200)
(define secret "test-barrier-secret")
(define victim-file "igropyr/test/barrier.sc")
(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "barrier suite requires IGROPYR_INJECT=on\n") (exit 1))
(unless (> ($inject-ticket) 0)
  (display "barrier suite process was not expanded with injection on (stale .so?)\n") (exit 1))

(define failures 0)
(define (fail label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline) (set! failures (+ failures 1)))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label pass? . info)
  (if pass? (ok label) (apply fail label info)))

;; handles-stable!: local on purpose (this suite must not load test/inject.sc);
;; semantics as there: 50 ms polls, two equal readings in a row, 100 tries.
(define (handles-stable! label)
  (let poll ((prev (uv-live-handle-count)) (n 0))
    (sleep-ms 50)
    (let ((now (uv-live-handle-count)))
      (cond ((= now prev) now)
            ((>= n 100) (fail label 'handles-never-settled prev now) now)
            (else (poll now (+ n 1)))))))

;; bounded poll: thunk true within bound-ms -> #t
(define (within? bound-ms thunk)
  (let loop ((waited 0))
    (cond ((thunk) #t)
          ((>= waited bound-ms) #f)
          (else (sleep-ms 20) (loop (+ waited 20))))))

(define (dead-within? p bound-ms) (within? bound-ms (lambda () (not (process-alive? p)))))

;; the refusal every live-row release must raise, checked by who AND message
(define (release-refused? thunk)
  (guard (e ((and (assertion-violation? e) (who-condition? e)
                  (eq? (condition-who e) '$inject-release!)
                  (message-condition? e)
                  (string=? (condition-message e) "barrier still live"))
             #t)
            (#t (list 'other-condition (and (who-condition? e) (condition-who e))
                      (and (message-condition? e) (condition-message e)))))
    (thunk) #f))

;; a victim that reads a whole file and reports how it ended
(define (spawn-reader! main tag)
  (spawn (lambda ()
           (file-read-async! victim-file self)
           (receive (after 20000 (send main (vector tag 'no-file-message)))
             (`#(file-read ,bv) (send main (vector tag 'read (bytevector-length bv))))
             (`#(file-error ,errno) (send main (vector tag 'error errno)))))))

(define (spawn-child! name)
  (system (string-append scheme-bin " --script igropyr/test/node-child.sc "
                         name " " (number->string node-port) " " secret " 120000 &")))
(define (dispatcher-pid) (whereis 'igropyr-node-dispatcher))

(start-scheduler
  (lambda ()
    (spawn (lambda () (sleep-ms 120000) (display "FAIL watchdog: barrier suite did not finish in 120 s\n") (exit 1)))
    (register 'main self)
    (inject-disarm!)
    (let ((main self) (h-base (handles-stable! "baseline")))

      ;; ---- W1: the release shape when nothing ever arrived ----------------
      (let ((t (inject-arm-barrier! 'fs-open-before-region 1 30000)))
        (check "W1: a wait with no victim returns timeout" (eq? (inject-barrier-wait t 'fs-open-before-region 100) 'timeout))
        (check "W1: the row is still armed" (eq? (inject-barrier-state t) 'armed) (inject-barrier-state t))
        (let ((v (inject-release! t)))
          (check "W1: release of an armed row returns the row with zero hits" (and (vector? v) (eqv? (vector-ref v 4) 0)) v)
          (check "W1: after release the ticket reads #f" (eq? (inject-barrier-state t) #f) (inject-barrier-state t)))
        (let ((t2 (inject-arm-barrier! 'fs-open-before-region 1 30000)))
          (check "W1: the same point can be armed again after release" (and t2 (not (eqv? t2 t))) t2)
          (inject-release! t2)))

      ;; ---- W2: reserved but not yet reported ------------------------------
      ;; before-report holds the parker 300 ms between the reservation and
      ;; the report: the only way to observe 'reserved from outside.
      (let ((t (inject-arm-barrier! 'fs-open-before-region 1 30000 300)))
        (spawn-reader! main 'w2)
        (check "W2: the first wait (100 ms) times out before the report" (eq? (inject-barrier-wait t 'fs-open-before-region 100) 'timeout))
        (check "W2: the row is reserved" (eq? (inject-barrier-state t) 'reserved) (inject-barrier-state t))
        (let ((r (release-refused? (lambda () (inject-release! t)))))
          (check "W2: release of a reserved row raises $inject-release! \"barrier still live\"" (eq? r #t) r))
        (check "W2: the row survived the refused release" (eq? (inject-barrier-state t) 'reserved) (inject-barrier-state t))
        (let ((second (inject-barrier-wait t 'fs-open-before-region 2000)))
          (check "W2: the second wait sees the victim parked" (pair? second) second)
          (when (pair? second)
            (let ((st (inject-barrier-drain! (cdr second) t 2000)))
              (check "W2: resumed after the drain" (eq? st 'resumed) st))))
        (let ((w (receive (after 5000 'no-witness) (`#(w2 ,how ,n) (list how n)))))
          (check "W2: the victim finished its read (witness)" (and (pair? w) (eq? (car w) 'read) (> (cadr w) 0)) w))
        (let ((v (inject-release! t)))
          (check "W2: release after the terminal state returns the row" (vector? v) v)
          (check "W2: no timeouts were counted" (and (vector? v) (eqv? (vector-ref v 9) 0)) (and (vector? v) (vector-ref v 9)))))

      ;; ---- W3: disarm refuses while a row is live, and clears nothing ------
      (let ((t (inject-arm-barrier! 'fs-open-before-region 1 30000 300)))
        (spawn-reader! main 'w3)
        (check "W3: first wait times out" (eq? (inject-barrier-wait t 'fs-open-before-region 100) 'timeout))
        (check "W3: reserved" (eq? (inject-barrier-state t) 'reserved) (inject-barrier-state t))
        (let ((r (guard (e ((and (assertion-violation? e) (who-condition? e)) (condition-who e))
                           (#t 'other-condition))
                   (inject-disarm!) 'no-raise)))
          (check "W3: inject-disarm! raises from $inject-disarm! while the row is live" (eq? r '$inject-disarm!) r))
        (check "W3: the armed point is still there (no partial clear)" (memq 'fs-open-before-region (inject-armed-points)) (inject-armed-points))
        (let ((second (inject-barrier-wait t 'fs-open-before-region 2000)))
          (check "W3: the victim parks" (pair? second) second)
          (when (pair? second)
            (check "W3: drained to resumed" (eq? (inject-barrier-drain! (cdr second) t 2000) 'resumed))))
        (let ((w (receive (after 5000 'no-witness) (`#(w3 ,how ,n) (list how n)))))
          (check "W3: witness" (and (pair? w) (eq? (car w) 'read)) w))
        (let ((v (inject-release! t)))
          (check "W3: release ok, timeouts 0" (and (vector? v) (eqv? (vector-ref v 9) 0)) v))
        (inject-disarm!)
        (check "W3: disarm succeeds once the row is gone" (null? (inject-armed-points)) (inject-armed-points)))

      ;; ---- B2: killed between the Scheme allocation and the region ---------
      ;; The fs request block is allocated INSIDE the region (fs-req-alloc!,
      ;; count and foreign-alloc together). A victim killed at this point has
      ;; allocated nothing foreign: the count is back at the captured
      ;; baseline. The mutant (alloc moved before the region) leaks one block
      ;; and the count says so.
      (let* ((b0 (fs-req-block-count)) (f0 (fs-count))
             (t (inject-arm-barrier! 'fs-open-before-region 1 30000))
             (p (spawn-reader! main 'b2))
             (w (inject-barrier-wait t 'fs-open-before-region 5000)))
        (check "B2: the reader parks before the region" (and (pair? w) (eq? (cdr w) p)) w (inject-barrier-state t))
        (cond
          ((pair? w)
           (kill p 'b2-kill-at-barrier)
           (check "B2: the victim is dead" (dead-within? p 3000))
           (check "B2: no fs request block outlived the kill (count back at baseline)" (eqv? (fs-req-block-count) b0) (fs-req-block-count) b0)
           (check "B2: nothing was published (fs-count unchanged)" (eqv? (fs-count) f0) (fs-count) f0)
           (let ((v (inject-release! t)))
             (check "B2: release of the parked-and-dead row succeeds" (vector? v) v)))
          (else (inject-barrier-cleanup! t 'fs-open-before-region 31000))))

      ;; ---- B3: publish -> submit is one step --------------------------------
      ;; Fixed tree: the point is inside the region, the victim skips and
      ;; finishes; fs-count returns to baseline by itself. Mutant (region ends
      ;; after publish): the victim parks; killing it there leaves a published
      ;; op with no submitter, and fs-count stays one above baseline.
      (let* ((f0 (fs-count)) (b0 (fs-req-block-count))
             (t (inject-arm-barrier! 'fs-open-after-publish 1 30000))
             (p (spawn-reader! main 'b3))
             (w (inject-barrier-wait t 'fs-open-after-publish 5000)))
        (cond
          ((eq? w 'skipped)
           (check "B3: the point inside the region is skipped, not parked" #t)
           (let ((wit (receive (after 5000 'no-witness) (`#(b3 ,how ,n) (list how n)))))
             (check "B3: the reader finished (witness)" (and (pair? wit) (eq? (car wit) 'read)) wit))
           (check "B3: skipped counted once" (eqv? (inject-barrier-skipped t) 1) (inject-barrier-skipped t))
           (check "B3: fs-count back at baseline after completion" (within? 2000 (lambda () (eqv? (fs-count) f0))) (fs-count) f0)
           ;; the account moves both ways: a whole read allocates one request
           ;; block and frees it. This is what proves B2's "still at baseline"
           ;; is a reading and not a counter that never moves.
           (check "B3: the fs request block count is back at baseline after a whole read" (within? 2000 (lambda () (eqv? (fs-req-block-count) b0))) (fs-req-block-count) b0)
           (inject-release! t))
          ((pair? w)
           ;; the mutant's shape: kill the parked publisher and look for the orphan
           (kill (cdr w) 'b3-kill-after-publish)
           (dead-within? (cdr w) 3000)
           (check "B3: (mutant) fs-count returns to baseline after the owner's death" (within? 2000 (lambda () (eqv? (fs-count) f0))) (fs-count) f0)
           (fail "B3: the victim PARKED after publish: the region ends before submit" w)
           (inject-release! t))
          (else (fail "B3: neither skipped nor parked" w (inject-barrier-state t))
                (inject-barrier-cleanup! t 'fs-open-after-publish 31000))))

      ;; ---- B1: token check -> stop! is one step --------------------------------
      ;; Fixed tree: the point is inside the region, skipped. Mutant: the caller
      ;; parks after the token check; meanwhile the listener is stopped by
      ;; someone else and a NEW listener is allocated at the same address; the
      ;; resumed caller's stop! re-tests membership only and closes the new one.
      (let* ((t (inject-arm-barrier! 'tcp-stop-listen-before-close 1 30000))
             (a (spawn (lambda ()
                         (let* ((l (tcp-listen! "127.0.0.1" listen-port 16 (lambda (c) (void))))
                                (tok (listener-token l)))
                           (send main (vector 'b1-listening l tok))
                           (receive (`#(go) 'ok))
                           (tcp-stop-listen! l tok)
                           (send main (vector 'b1-stopped))))))
             (lt (receive (after 5000 #f) (`#(b1-listening ,l ,tok) (cons l tok)))))
        (check "B1: the victim listens" (pair? lt) lt)
        (when (pair? lt)
          (send a (vector 'go))
          (let ((w (inject-barrier-wait t 'tcp-stop-listen-before-close 5000)))
            (cond
              ((eq? w 'skipped)
               (check "B1: the point inside the region is skipped, not parked" #t)
               (check "B1: the victim stopped its listener (witness)" (receive (after 5000 #f) (`#(b1-stopped) #t)))
               (check "B1: the listener is closed for its token" (not (listener-open? (car lt) (cdr lt))))
               (check "B1: skipped counted once" (eqv? (inject-barrier-skipped t) 1) (inject-barrier-skipped t))
               (inject-release! t))
              ((pair? w)
               ;; the mutant's choreography, as designed: stop the listener
               ;; from here, wait for its close callback to FREE the handle
               ;; (the table entry goes at stop!, the memory at the callback),
               ;; then allocate listeners until one lands at the old address.
               (let ((h-before (uv-live-handle-count)))
                 (tcp-stop-listen! (car lt) (cdr lt))
                 (check "B1: (mutant) the old handle was freed before the reuse attempt" (within? 3000 (lambda () (< (uv-live-handle-count) h-before)))))
               (let loop ((extra '()) (n 0))
                 (if (>= n 64)
                     (begin (fail "B1: cannot-force-handle-reuse" n)
                            ;; the victim is still parked: resume it before release
                            (inject-barrier-drain! (cdr w) t 5000)
                            (receive (after 5000 #f) (`#(b1-stopped) #t))
                            (for-each (lambda (e) (tcp-stop-listen! (car e) (cdr e))) extra))
                     (let* ((l2 (tcp-listen! "127.0.0.1" (+ listen-port 1 n) 16 (lambda (c) (void))))
                            (tok2 (listener-token l2)))
                       (if (eqv? l2 (car lt))
                           (begin
                             (inject-barrier-drain! (cdr w) t 5000)
                             (receive (after 5000 #f) (`#(b1-stopped) #t))
                             (check "B1: (mutant) the resumed stop! must not close the new listener at the reused address"
                                    (listener-open? l2 tok2) l2 tok2)
                             (fail "B1: the victim PARKED after the token check: the test and the close are not one step" w)
                             (tcp-stop-listen! l2 tok2)
                             (for-each (lambda (e) (tcp-stop-listen! (car e) (cdr e))) extra))
                           (loop (cons (cons l2 tok2) extra) (+ n 1))))))
               (inject-release! t))
              (else (fail "B1: neither skipped nor parked" w (inject-barrier-state t))
                    (inject-barrier-cleanup! t 'tcp-stop-listen-before-close 31000)))))
        (check "B1: handles back at baseline" (eqv? (handles-stable! "b1-after") h-base) (uv-live-handle-count) h-base))

      ;; ---- B4: the dispatcher killed between storing the attempt count and the delivery
      ;; Two failed deliveries (hits 2), the third attempt stores k=3 and parks;
      ;; kill; the successor sees the stored count already at the limit and
      ;; quarantines with 'lost-outcome-after-kill without a third delivery.
      ;; Mutant (count stored after the failure): the successor sees 2, delivers
      ;; once more (hits 3), fails, and quarantines on the injected condition.
      (node-start! 'a secret node-port)
      (register 'igropyr-node-observer self)
      (monitor-node 'b)
      (spawn-child! "b")
      (let ((up (receive (after 15000 #f) (`#(node-up b) #t))))
        (check "B4: the child came up" up)
        (when up
          (let ((d0 (dispatcher-pid))
                (t (inject-arm-barrier! 'poison-attempt-start 3 30000)))
            (check "B4: a dispatcher exists" d0)
            (inject-arm-fault! 'notify-deliver)
            (rsend 'b 'svc (vector 'quit))
            (let ((w (inject-barrier-wait t 'poison-attempt-start 20000)))
              (check "B4: the dispatcher parks at the start of the third attempt" (and (pair? w) (eq? (cdr w) d0)) w d0 (inject-barrier-state t))
              (cond
                ((pair? w)
                 (check "B4: two deliveries had been attempted when it parked" (eqv? (inject-hits 'notify-deliver) 2) (inject-hits 'notify-deliver))
                 (kill (cdr w) 'b4-kill-between-count-and-delivery)
                 (check "B4: the dispatcher is dead" (dead-within? (cdr w) 3000))
                 (let ((notice (receive (after 20000 'no-notice)
                                 (`#(event-quarantined ,name ,kind ,seq ,reason ,fails ,reason-kind)
                                   (list name kind seq reason fails reason-kind)))))
                   (check "B4: the successor quarantined the event" (pair? notice) notice)
                   (when (pair? notice)
                     (check "B4: for the right event" (and (eq? (car notice) 'b) (eq? (cadr notice) 'node-down)) notice)
                     ;; the notice vector carries two `kind`s: index 2 is the
                     ;; EVENT's kind (node-down), index 6 the REASON's kind, and
                     ;; `why` (index 4) is the reason's kind for every kind but
                     ;; 'raised, where it is the payload. ON THIS PATH why AND
                     ;; index 6 HOLD THE SAME SYMBOL, so asserting index 6 here
                     ;; would be the same assertion twice; the slot carries
                     ;; weight only on a 'raised reason (test/quarantine-reason.sc).
                     (check "B4: with reason lost-outcome-after-kill (no third delivery was started)" (eq? (list-ref notice 3) 'lost-outcome-after-kill) (list-ref notice 3))
                     (check "B4: the delivery count stayed at 2" (eqv? (inject-hits 'notify-deliver) 2) (inject-hits 'notify-deliver))
                     ;; the notice carries `why` (a symbol); the dead letter
                     ;; keeps the quarantine-reason record. Kind 'raised
                     ;; would mean a third delivery ran and failed: the
                     ;; mutant's shape.
                     (let* ((dl (node-dead-letters)) (r (and (pair? dl) (vector-ref (car dl) 3))))
                       (check "B4: the dead letter's reason record has kind lost-outcome-after-kill, not raised"
                              (and (quarantine-reason? r) (eq? (quarantine-reason-kind r) 'lost-outcome-after-kill)) r))))
                 (check "B4: a successor dispatcher is running" (let ((d1 (dispatcher-pid))) (and d1 (not (eq? d1 d0)))) (dispatcher-pid) d0)
                 (let ((v (inject-release! t)))
                   (check "B4: release of the parked-and-dead row succeeds" (vector? v) v)))
                (else (inject-barrier-cleanup! t 'poison-attempt-start 31000))))
            (inject-disarm!))))
      (rsend 'b 'svc (vector 'quit))
      (sleep-ms 300)

      (if (zero? failures)
          (begin (display "ALL BARRIER TESTS PASSED\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
