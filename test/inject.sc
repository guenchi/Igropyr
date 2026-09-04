#!chezscheme
;;; The fault-injection shadow suite (E7). Runs ONLY with IGROPYR_INJECT=on
;;; and only from source: the hooks in libuv.sc expand to nothing in the
;;; normal build, so arming here would be a silent no-op and every cell
;;; would pass for the wrong reason. That is why the first thing this file
;;; does is refuse to run without the flag.
;;;
;;; What these cells are for: E1 (a submission failure on a LIVE link must
;;; be reported, not swallowed) had no red cell, ever -- its two failure
;;; shapes, uv_write refusing with a negative errno and an allocation
;;; failing during submission, cannot be produced from outside the
;;; process. The hooks give the test a hand inside it. See
;;; archive/igropyr-C-design/E7-design-v4-converged.md.
;;;
;;; The two shapes have DIFFERENT contracts and the cells pin each one:
;;;   C1 negative errno -> the failure slot is exactly 'submission-refused
;;;   C3 allocation raise -> the failure slot is the injected condition
;;; Loosened to "some submission failure was raised", a fix that handled
;;; only one shape would pass both. Payloads are > 65536 bytes so the
;;; frame takes the queued path through the raw uv_write / the block
;;; allocation; smaller frames complete through uv_try_write and never
;;; reach either hook (libuv.sc's tcp-writev!).
;;;
;;; EVERY CELL RUNS, WHATEVER THE ONES BEFORE IT DID. This file is run as
;;; the same bytes against several old versions (the per-commit matrix),
;;; and a fixture that exits on its first red answers only one question
;;; per tree: the first matrix run reported C3 as "unobserved" on three
;;; trees because C1 had already exited. So a cell failure is recorded,
;;; the arming is cleared, and the next cell runs; the verdict is the
;;; list at the end. Setup failures (the child never came up) still abort,
;;; since no cell means anything without the link.
(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp) (igropyr node)
        (igropyr inject-control) (igropyr inject))

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))
(define port 18092)                     ; not node.sc's 18091: never collide
(define secret "test-mesh-secret")

(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "inject suite requires IGROPYR_INJECT=on (hooks expand to nothing otherwise)\n")
  (exit 1))
;; AND THE EXPANSION HAS TO AGREE. The variable being set says what
;; this process asked for; whether the libraries it loaded were expanded
;; that way is a separate fact -- a stale .so compiled with injection off
;; answers every arm with a silent success and every hit count with #f,
;; which reads exactly like "armed but never reached". The ticket counter
;; is 0 in the off expansion and monotone from 1 in the on one, and it
;; keeps that shape when the barrier primitive becomes real.
;; takes ticket #1: no cell may assert an absolute ticket value
(unless (> ($inject-ticket) 0)
  (display "inject suite process was not expanded with injection on (stale .so?)\n")
  (exit 1))

;; A CELL FAILURE IS RECORDED BEFORE IT IS RAISED, and the raise is only
;; transport. The library under test has two dozen catch-all guards
;; (guard (e (#t ...))) on callbacks, agents and the critical write path;
;; a fail! evaluated under one of them would be swallowed, the code after
;; it would run on, and the cell would finish looking GREEN -- the worst
;; outcome a fixture can have. Today every fail! here sits on the main
;; process's own stack inside run-cell's dynamic extent, so nothing eats
;; it; but nothing pinned that, and the next cell written inside a spawn
;; or an on-done would change it silently. So fail! writes its verdict
;; down first: run-cell then knows three endings, not two --
;;   the thunk returned and nothing was recorded  -> green
;;   a cell-failure came out through the guard    -> red
;;   the thunk returned but a failure WAS recorded -> the raise was
;;      swallowed on the way up: reported as broken (💥), never as green.
(define-record-type cell-failure (fields label info))
(define recorded #f)                     ; the failure this cell wrote down
(define (fail! label . info)
  (set! recorded (make-cell-failure label info))
  (raise recorded))
;; a setup failure: nothing further can be measured
(define (die! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

(define failures '())
(define (report-failure! name f)
  (display "FAIL ") (display (cell-failure-label f))
  (for-each (lambda (x) (display " ") (write x)) (cell-failure-info f))
  (newline)
  (set! failures (cons name failures)))
;; INJECT_SKIP=name,name -- leave those cells out, everything else in the
;; same order. A bisection aid: "does cell X's arm cause what cell Y sees"
;; is answered by two runs whose only difference is this variable. A
;; skipped cell prints SKIP so it cannot be mistaken for one that ran.
(define skipped
  (let ((v (getenv "INJECT_SKIP")))
    (if (not v) '()
        (let loop ((cs (string->list v)) (cur '()) (acc '()))
          (cond ((null? cs) (reverse (if (null? cur) acc (cons (list->string (reverse cur)) acc))))
                ((char=? (car cs) #\,) (loop (cdr cs) '() (if (null? cur) acc (cons (list->string (reverse cur)) acc))))
                (else (loop (cdr cs) (cons (car cs) cur) acc)))))))
(define (run-cell name thunk)
  (if (member name skipped)
      (begin (display "SKIP ") (display name) (newline))
      (run-cell* name thunk)))
(define (run-cell* name thunk)
  (set! recorded #f)
  (let ((came-out
          (guard (e ((cell-failure? e) (report-failure! name e) 'red)
                    (#t (display "FAIL ") (display name) (display " raised ")
                        ;; a bare #<compound condition> names nothing: print
                        ;; what a reader needs to find the raise site
                        (if (condition? e) (display-condition e) (write e))
                        (newline)
                        (set! failures (cons name failures)) 'red))
            (thunk)
            'returned)))
    (when (and (eq? came-out 'returned) recorded)
      ;; the verdict was written but never arrived: something between the
      ;; fail! and this frame caught it. Not a pass.
      (display "💥 BROKEN ") (display name)
      (display ": fail! was recorded but its raise was swallowed en route -- ")
      (write (cell-failure-label recorded)) (newline)
      (set! failures (cons name failures))))
  ;; a stale arm must not poison the next cell, whatever happened; after
  ;; the verdict is written, so a red still carries its hit counts
  (inject-disarm!))

;; POSITIVE CONTROL FOR THE THIRD ENDING. A detector that has never fired
;; is only present, not measuring: this puts a fail! under a spawn -- the
;; scheduler's process wrapper eats the raise, the thunk runs on and
;; returns -- and requires run-cell to call that BROKEN. It prints one
;; expected "💥 BROKEN probe:..." line; the probe's own mark is then taken
;; back out of the verdict. If run-cell stays quiet here, the fixture's
;; green column cannot be trusted and nothing else is worth running.
(define (probe-swallow-detection!)
  (let ((before failures))
    (run-cell "probe:fail-under-spawn"
      (lambda () (spawn (lambda () (fail! "probe-swallowed"))) (sleep-ms 100)))
    (if (eq? failures before)
        (die! "probe:run-cell-did-not-report-a-swallowed-fail!")
        (begin (set! failures before)
               (display "PROBE a fail! swallowed under spawn is reported as broken, not green ok\n")))))

(define (spawn-child! name secret)
  (system (string-append
            scheme-bin " --script igropyr/test/node-child.sc "
            name " " (number->string port) " " secret " 180000 &")))

(define (bytes-now) (cdr (assq 'bytes (node-outbound-stats))))
;; Two equal consecutive readings of the live handle count, 50 ms apart;
;; 100 rounds without one is a failure of the reading, not of the cell.
(define (handles-stable! label)
  (let poll ((prev (uv-live-handle-count)) (n 0))
    (sleep-ms 50)
    (let ((now (uv-live-handle-count)))
      (cond ((= now prev) now)
            ((>= n 100) (fail! label 'handles-never-settled prev now))
            (else (poll now (+ n 1)))))))

(define (submit-gap-cell! name point thunk)
  (run-cell name
    (lambda ()
      (let ((fds0 (length (directory-list "/dev/fd")))
            (idx0 (uv-owner-index-count)))
        (inject-arm-fault! point 1)
        (let ((raised (guard (e (#t #t)) (thunk) #f)))
          (unless raised (fail! (string-append name "-no-raise")))
          (unless (eqv? (inject-hits point) 1)
            (fail! (string-append name "-hits") (inject-hits point)))
          (unless (zero? (fs-count)) (fail! (string-append name "-fs-table-row-left") (fs-count)))
          (unless (= (uv-owner-index-count) idx0)
            (fail! (string-append name "-owner-index-left") (uv-owner-index-count) idx0))
          (let ((fds1 (length (directory-list "/dev/fd"))))
            (unless (= fds1 fds0) (fail! (string-append name "-fd-leaked") 'now fds1 'before fds0)))))
      (display name)
      (display " a raise after publication and before submission leaves nothing behind ok\n"))))
;; THE CONTRACT IS A SHAPE, AND IT IS SPELLED OUT HERE ON PURPOSE. node.sc
;; exports submission-failure? for it, but that predicate is part of the
;; fix under test: on the trees the per-commit matrix runs against it does
;; not exist, and a fixture that names it does not go red there -- it
;; fails to load (rc 70, PANIC unbound variable). A version-tolerant
;; fixture would be worse: the branch that asserts the old shape passes
;; by asserting the defect. So the fixture asserts the shape itself, the
;; same bytes on every tree, red on the old ones for the right reason.
(define (submission-failed? e)
  (and (vector? e) (fx>= (vector-length e) 4)
       (eq? (vector-ref e 0) 'rsend-error)
       (eq? (vector-ref e 1) 'submission-failed)))
(define big (make-string 70000 #\x))    ; > 65536: takes the queued path

;; rsend that returns the raised object, or 'no-raise. The fixed tree
;; raises a submission-failure; the trees before the fix return #t or #f
;; silently -- which is exactly the red these cells exist to show.
(define (rsend-catch node reg msg)
  (call/cc (lambda (k)
    (with-exception-handler
      (lambda (e) (k e))
      (lambda () (rsend node reg msg) 'no-raise)))))

;; the child echoes #(add1 x payload) as #(ans x+1 payload): a uniquely
;; tagged round trip is the proof the link still carries traffic
(define (echo! tag label)
  (rsend 'b 'svc (vector 'add1 tag (string-append "tag-" label)))
  (receive (after 8000 (fail! label 'echo-timeout tag))
    (`#(ans ,y ,p)
      (unless (and (eqv? y (+ tag 1)) (equal? p (string-append "tag-" label)))
        (fail! label 'echo-mismatch y p)))))

(define (no-node-down! label)
  (receive (after 700 'ok)
    (`#(node-down b) (fail! label 'link-dropped-on-refusal))))

;; ---- tranche 2 helpers (top level: a body may not define after an expression)
(define (counts-back! label h0 idx0)
  (let poll ((n 0))
    (unless (and (= (uv-live-handle-count) h0) (= (uv-owner-index-count) idx0))
      (if (= n 40)
          (fail! label (list 'handles (uv-live-handle-count) h0
                             'index (uv-owner-index-count) idx0))
          (begin (sleep-ms 50) (poll (+ n 1)))))))
(define (local-callee-agents) (cdr (assq 'callee-agents (node-monitor-stats))))
(define (wait-local-callee! label want)
  (let poll ((n 0))
    (unless (= (local-callee-agents) want)
      (if (= n 100)
          (fail! label (list 'callee-agents (local-callee-agents) 'want want))
          (begin (sleep-ms 50) (poll (+ n 1)))))))
;; the peer's reading, over whatever link is live: it can only be asked
;; while there is one
(define (peer-callee-agents! label)
  (rsend 'b 'svc (vector 'stats))
  (receive (after 5000 (fail! label 'stats-timeout))
    (`#(stats ,alist) (cdr (assq 'callee-agents alist)))))
(define (wait-peer-callee! label want)
  (let poll ((n 0))
    (let ((got (peer-callee-agents! label)))
      (unless (= got want)
        (if (= n 60)
            (fail! label (list 'peer-callee-agents got 'want want))
            (begin (sleep-ms 100) (poll (+ n 1))))))))
(define drops 0)                         ; link drops this fixture has caused
(define (expect-node-down! label)
  (receive (after 10000 (fail! label 'no-node-down-slack-elapsed))
    (`#(node-down b) (set! drops (+ drops 1)) 'ok)))
;; THE BUDGET IS DERIVED, NOT GUESSED. The child redials after
;; reconnect-delay, which doubles per attempt (node.sc: base 3000, cap
;; 60000, +-25% jitter) and whose jitter is a hash of (self peer attempt)
;; -- the same number in every process -- so this process can compute
;; the child's own wait. The attempt counter only resets when a link has
;; OUTLIVED the previous delay (node.sc's connector, `(if (and up (>= up
;; waited)) 0 (+ attempt 1))`), which the links these cells drop never do,
;; so it ratchets: attempt <= drops always, and the delay is monotone in
;; attempt, so (reconnect-delay 'b 'a drops) is a provable upper bound on
;; the wait. The +3000 is redundancy, not load-bearing. A fixed 15 s was
;; here first and sat exactly on the attempt-2 window (9-15 s).
;; attempt itself is UNOBSERVABLE BY CONSTRUCTION -- it is the connector's
;; loop variable (node.sc run-connector), in no table, entry or exported
;; reading -- so the budget takes drops as its bound; attempt <= drops
;; because each drop advances it by at most one and may reset it. That is
;; the correct reading, not a stand-in: a precise value would be a new
;; connector reading, a separate change, never a narrower cell.
;; AND THE MEASUREMENT IS JUDGED, NOT ONLY PRINTED: an upper bound this
;; wide would let a reconnect that has slowed pass unnoticed, so a wait
;; beyond the two-drop bound (15000) is flagged on its own line. The flag
;; is the substitute for the reading this process cannot take; remove it
;; and the cell is blind to a ratchet that has run ahead.
;; EVERY NODE CELL STARTS FROM ATTEMPT 0, BY CONSTRUCTION. The child's
;; connector resets its attempt counter only when the link that just
;; ended outlived the delay it last waited (node.sc run-connector: `(if
;; (and up (>= up waited)) 0 (+ attempt 1))`). Left alone, the link a
;; cell drops has lived exactly as long as the cells before it took --
;; the first version of these cells measured a first link of 3323 ms
;; against a first delay of 3513 ms, and whether it reset was decided by
;; whether an unrelated earlier cell had run to completion. So before a
;; cell drops the link it lets it live past the longest delay the counter
;; could be holding: the SAME bound the budget below uses -- attempt <=
;; drops, reconnect-delay monotone -- plus a second. A first version keyed
;; this to attempt 1, which holds only while every earlier settle succeeded:
;; one miss puts the counter at 2, whose delay that settle never reaches,
;; and the ratchet is then stuck for good, silently, since the budget
;; grows with drops too. Keyed to drops it waits longer only when the
;; counter can actually be higher. Measured, the reconnects land at the
;; attempt-0 delay every time, and the flag below fires only when
;; something has actually slowed.
(define (settle-link!)
  (sleep-ms (+ (reconnect-delay 'b 'a drops) 1000)))
(define (expect-node-up! label)
  (let* ((budget (+ (reconnect-delay 'b 'a drops) 3000))
         (t0 (let ((t (current-time))) (+ (* 1000 (time-second t)) (quotient (time-nanosecond t) 1000000)))))
    (receive (after budget (fail! label 'no-node-up 'budget budget 'drops drops))
      (`#(node-up b)
        (let* ((t (current-time))
               (ms (- (+ (* 1000 (time-second t)) (quotient (time-nanosecond t) 1000000)) t0)))
          (display "  node-up after ") (display ms) (display " ms (budget ")
          (display budget) (display ", drops ") (display drops) (display ")")
          (when (> ms 15000) (display "  SLOWER THAN THE TWO-DROP BOUND"))
          (newline))))))
(define (accounted-ok! label)
  (let ((s (node-monitor-stats)))
    (unless (= (cdr (assq 'accounted s)) (cdr (assq 'mon-chain s)))
      (fail! label 'accounted/=mon-chain s))))
(define (drained-has? l name reason)
  (and (pair? l)
       (or (let ((n (car l)))
             (and (vector? n) (= (vector-length n) 4)
                  (eq? (vector-ref n 2) name) (eq? (vector-ref n 3) reason)))
           (drained-has? (cdr l) name reason))))
(define (drain! label)
  (rsend 'b 'svc (vector 'drain))
  (receive (after 5000 (fail! label 'no-drain-reply))
    (`#(drained ,l) l)))


(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (node-set-limits! 64 8)
    (register 'main self)
    (monitor-node 'b)
    (spawn-child! "b" secret)
    (receive (after 15000 (die! "inject-child-never-came-up"))
      (`#(node-up b) 'ok))
    (sleep-ms 300)
    (run-cell "warmup" (lambda () (echo! 0 "warmup")))
    (probe-swallow-detection!)

    ;; ---- C4: the harness injects at all -----------------------------
    ;; try-write-eagain alone: uv_try_write reports nothing written, the
    ;; frame goes down the queued path and the REAL uv_write delivers it.
    ;; Observable: the hook was hit exactly once and the message arrived.
    (run-cell "C4"
      (lambda ()
        (inject-arm-return! 'try-write-eagain 0 1)
        (echo! 10 "c4")
        (unless (eqv? (inject-hits 'try-write-eagain) 1)
          (fail! "c4-positive-control" 'hits (inject-hits 'try-write-eagain)))
        (display "C4 harness injects (try-write-eagain -> queued path, delivered) ok\n")))

    ;; ---- C1: negative errno on a live link -> 'submission-refused -----
    (run-cell "C1"
      (lambda ()
        (let ((b0 (bytes-now)))
          (inject-arm-return! 'uv-write-neg -32 1)          ; EPIPE, once
          (let ((e (rsend-catch 'b 'svc (vector 'add1 100 big))))
            (unless (submission-failed? e)
              (fail! "c1-neg-errno-not-reported" e))
            (unless (eq? (vector-ref e 2) 'b)
              (fail! "c1-wrong-peer" (vector-ref e 2)))
            ;; THE CONTRACT: a refusal on an OPEN connection is named as
            ;; such, not conflated with a dead link
            (unless (eq? (vector-ref e 3) 'submission-refused)
              (fail! "c1-wrong-failure-shape" (vector-ref e 3)))
            (unless (eqv? (inject-hits 'uv-write-neg) 1)
              (fail! "c1-hits" (inject-hits 'uv-write-neg)))
            ;; the connection is still current and was not torn down
            (unless (memq 'b (node-peers)) (fail! "c1-peer-gone"))
            (no-node-down! "c1")
            ;; the charge came back (libuv's negative-status path ran
            ;; on-done); snapshot compare, the stat is aggregate
            (sleep-ms 200)
            (unless (= (bytes-now) b0)
              (fail! "c1-charge-not-discharged" (bytes-now) b0))
            ;; and the same link still carries traffic
            (echo! 101 "c1-after")))
        (display "C1 negative errno on a live link is reported as submission-refused ok\n")))

    ;; ---- C3: allocation raise during submission -> the raise itself ---
    (run-cell "C3"
      (lambda ()
        (let ((b0 (bytes-now)))
          (inject-arm-fault! 'writev-oom 1)
          (let ((e (rsend-catch 'b 'svc (vector 'add1 200 big))))
            (unless (submission-failed? e)
              (fail! "c3-oom-not-reported" e))
            (unless (eq? (vector-ref e 2) 'b)
              (fail! "c3-wrong-peer" (vector-ref e 2)))
            ;; THE CONTRACT: the second value carries the ORIGINAL raised
            ;; object, and it is the injected one -- who and irritant both
            (let ((inner (vector-ref e 3)))
              (unless (and (condition? inner)
                           (who-condition? inner)
                           (eq? (condition-who inner) 'inject-fault!)
                           (irritants-condition? inner)
                           (memq 'writev-oom (condition-irritants inner)))
                (fail! "c3-payload-is-not-the-injected-condition" inner)))
            (unless (eqv? (inject-hits 'writev-oom) 1)
              (fail! "c3-hits" (inject-hits 'writev-oom)))
            (unless (memq 'b (node-peers)) (fail! "c3-peer-gone"))
            (no-node-down! "c3")
            ;; here the discharge is write-body!'s own guard: nothing was
            ;; handed to libuv, so no on-done could refund it
            (sleep-ms 200)
            (unless (= (bytes-now) b0)
              (fail! "c3-charge-not-discharged" (bytes-now) b0))
            (echo! 201 "c3-after")))
        (display "C3 allocation failure during submission is reported with the raised object ok\n")))

    ;; ==== tranche 2: the three cells that are red before their repair ====
    ;; See archive/igropyr-C-design/E7-tranche2-design-v4.md §二 rows 2, 5, 6.
    ;; Each arms a fault point that sits after the first of two steps and
    ;; before the second, and asserts that NOTHING of the first step
    ;; survives the failure. On the tree before the repair the first step
    ;; has already happened: the cell is red for that reason, and the
    ;; repair is what turns it green.

    ;; ---- T2-2: an allocation failure in fs-start-fd! must close the fd ----
    ;; file-stream-open-under! opens the raw fd first and only then hands it
    ;; to fs-start-fd!, which now does all of its work -- the record, the
    ;; index cell, the foreign request block, the two publications --
    ;; inside one interrupt-disabled region under one guard whose handler
    ;; closes the fd. The point sits just before the foreign allocation, so
    ;; what it stands in for is that allocation failing; a Scheme
    ;; allocation failing earlier in the region lands in the same handler.
    ;; A raise anywhere in there that did not close the fd would leave a
    ;; descriptor nobody knows about. The reading is the process's own
    ;; descriptor table: /dev/fd lists it, and the listing's own transient
    ;; fd is present in both samples alike.
    (run-cell "T2-2"
      (lambda ()
        (let ((fds0 (length (directory-list "/dev/fd"))))
          (inject-arm-fault! 'fs-oom-fd 1)
          (let ((raised (guard (e (#t #t))
                          (file-stream-open-under! "igropyr/test" "node-child.sc" self)
                          #f)))
            (unless raised (fail! "t2-2-no-raise"))
            (unless (eqv? (inject-hits 'fs-oom-fd) 1)
              (fail! "t2-2-hits" (inject-hits 'fs-oom-fd)))
            (let ((fds1 (length (directory-list "/dev/fd"))))
              (unless (= fds1 fds0) (fail! "t2-2-fd-leaked" 'now fds1 'before fds0))
              ;; and nothing was published either
              (unless (zero? (fs-count)) (fail! "t2-2-published" (fs-count)))
              ;; the baseline is printed on success too: "equal" on a shifted
              ;; baseline is not the same reading as "equal" on the old one
              (display "T2-2 an allocation failure after open-under closes the fd ok (fds ")
              (display fds1) (display "/") (display fds0) (display ")\n"))))))

    ;; ---- T2-5: a failed monitor leaves no half registration --------------
    ;; monitor writes the record on the watcher's pcb, then on the target's,
    ;; with an allocation between the two. Half a registration is worse
    ;; than none: the target's exit does not see it, so no DOWN, while
    ;; the watcher's count stays elevated until the watcher itself dies.
    (run-cell "T2-5"
      (lambda ()
        (let* ((p (spawn (lambda () (receive (`#(stop) (void))))))
               (m0 (process-monitor-count self))
               (p0 (process-monitor-count p)))
          (inject-arm-fault! 'monitor-second-half 1)
          (let ((raised (guard (e (#t #t)) (monitor p) #f)))
            (unless raised (fail! "t2-5-no-raise"))
            (unless (eqv? (inject-hits 'monitor-second-half) 1)
              (fail! "t2-5-hits" (inject-hits 'monitor-second-half)))
            ;; NEITHER side may hold half of it
            (unless (and (= (process-monitor-count self) m0)
                         (= (process-monitor-count p) p0))
              (fail! "t2-5-half-registered"
                     (list 'watcher (process-monitor-count self) m0
                           'target (process-monitor-count p) p0)))
            (kill p 'for-the-cell)
            (receive (after 300 'ok)
              (`#(DOWN ,@p ,_) (fail! "t2-5-down-from-a-failed-monitor")))))
        (display "T2-5 a failed monitor leaves no half registration ok\n")))

    ;; ---- T2-6: a failed link leaves no half link ---------------------------
    ;; @link writes the caller into the TARGET's list first. Half a link is
    ;; not silent like half a monitor: when the target exits it acts on
    ;; that entry and sends EXIT to (or kills) a process that never became
    ;; linked. The proxy forwards WHATEVER reaches it, so a notice of any
    ;; shape is red -- a cell that named one shape would go green on the
    ;; others. The arm happens before the proxy exists, so the hit cannot
    ;; be raced.
    (run-cell "T2-6"
      (lambda ()
        (let* ((me self)
               (t (spawn (lambda () (receive (`#(stop) (void)))))))
          (inject-arm-fault! 'link-second-half 1)
          (let ((proxy (spawn (lambda ()
                                (process-trap-exit #t)
                                (let ((raised (guard (e (#t #t)) (link t) #f)))
                                  (send me (vector 'linked raised)))
                                (receive (after 1500 (send me (vector 'proxy-quiet)))
                                  (x (send me (vector 'proxy-got x))))))))
            (receive (after 3000 (fail! "t2-6-proxy-silent"))
              (`#(linked ,raised) (unless raised (fail! "t2-6-no-raise"))))
            (unless (eqv? (inject-hits 'link-second-half) 1)
              (fail! "t2-6-hits" (inject-hits 'link-second-half)))
            (kill t 'for-the-cell)
            (receive (after 3000 (fail! "t2-6-verdict-timeout"))
              (`#(proxy-got ,x) (fail! "t2-6-half-link-acted-on" x))
              (`#(proxy-quiet) 'ok))
            (kill proxy 'done)))
        (display "T2-6 a failed link leaves no half link ok\n")))

    ;; ==== tranche 2: cells that are green today and owe their red to a mutation
    ;; (design v4 §二 rows 1, 3, 4). Each pins a cleanup path that the
    ;; ordinary suite never drives because its trigger is a refusal from
    ;; inside libuv.

    ;; ---- T2-1: a refused getaddrinfo retires its request on the spot ----
    ;; uv_getaddrinfo can decline synchronously; the request was already
    ;; indexed under its owner and filed in the table before the call.
    (run-cell "T2-1"
      (lambda ()
        (let ((idx0 (uv-owner-index-count)) (dns0 (dns-count)))
          (inject-arm-return! 'getaddrinfo-refused -3 1)   ; EAI_AGAIN-ish, once
          (dns-resolve! "127.0.0.1" self)
          (receive (after 3000 (fail! "t2-1-no-failure-delivered"))
            (`#(dns-failed ,e) (unless (eqv? e -3) (fail! "t2-1-wrong-errno" e)))
            (`#(dns-resolved ,ip) (fail! "t2-1-resolved-despite-refusal" ip)))
          (unless (eqv? (inject-hits 'getaddrinfo-refused) 1)
            (fail! "t2-1-hits" (inject-hits 'getaddrinfo-refused)))
          (unless (= (uv-owner-index-count) idx0)
            (fail! "t2-1-owner-index-not-retired" (uv-owner-index-count) idx0))
          (unless (= (dns-count) dns0)
            (fail! "t2-1-table-row-not-retired" (dns-count) dns0))
          ;; the resolver still works afterwards: nothing stale blocks it
          (inject-disarm!)
          (dns-resolve! "127.0.0.1" self)
          (receive (after 5000 (fail! "t2-1-next-resolution-silent"))
            (`#(dns-resolved ,ip) 'ok)
            (`#(dns-failed ,e) (fail! "t2-1-next-resolution-failed" e))))
        (display "T2-1 a refused getaddrinfo retires its request ok\n")))

    ;; ---- T2-3: a refused uv_tcp_connect releases everything it took -----
    ;; By the time the raw connect is called, the handle is initialised,
    ;; the request allocated, filed, and indexed under the owner. The
    ;; refusal must undo all of it; the close is asynchronous, so the
    ;; handle count is read after the loop has run.
    (run-cell "T2-3"
      (lambda ()
        (sleep-ms 200)                    ; let earlier closes settle first
        (let ((h0 (uv-live-handle-count)) (idx0 (uv-owner-index-count)))
          (inject-arm-return! 'tcp-connect-refused -61 1)   ; ECONNREFUSED, once
          (let ((raised (guard (e (#t #t)) (tcp-connect! "127.0.0.1" port self) #f)))
            (unless raised (fail! "t2-3-no-raise")))
          (unless (eqv? (inject-hits 'tcp-connect-refused) 1)
            (fail! "t2-3-hits" (inject-hits 'tcp-connect-refused)))
          (counts-back! "t2-3-not-released" h0 idx0)
          ;; and no stray connected/failed notice arrives for it
          (receive (after 300 'ok)
            (`#(tcp-connected ,c) (fail! "t2-3-connected-despite-refusal"))
            (`#(tcp-connect-failed ,e) (fail! "t2-3-async-failure-for-a-sync-refusal" e))))
        (display "T2-3 a refused connect releases handle, request and index ok\n")))

    ;; ---- T2-4: an allocation failure mid-connect releases the handle ----
    ;; The request allocation comes after the handle is initialised: the
    ;; guard around it must close the handle, and only the handle.
    (run-cell "T2-4"
      (lambda ()
        (sleep-ms 200)
        (let ((h0 (uv-live-handle-count)) (idx0 (uv-owner-index-count)))
          (inject-arm-fault! 'connect-oom 1)
          (let ((raised (guard (e (#t #t)) (tcp-connect! "127.0.0.1" port self) #f)))
            (unless raised (fail! "t2-4-no-raise")))
          (unless (eqv? (inject-hits 'connect-oom) 1)
            (fail! "t2-4-hits" (inject-hits 'connect-oom)))
          (counts-back! "t2-4-not-released" h0 idx0))
        (display "T2-4 an allocation failure mid-connect releases the handle ok\n")))

    ;; ---- T2-10: a foreign write that cannot go out at once still arrives -
    ;; tcp-write-foreign!'s own uv_try_write is the second raw try-write in
    ;; libuv.sc; tranche 1 left it unwrapped for want of a cell. With the
    ;; try-write told "nothing written", the bytes must take the queued
    ;; path -- copied out of the foreign buffer, which is free for reuse
    ;; the moment the call returns -- and reach the peer intact.
    (run-cell "T2-10"
      (lambda ()
        (let* ((me self) (lport 18093)
               (payload (string->utf8 "foreign-bytes")))
          (tcp-listen! "127.0.0.1" lport 16
            (lambda (c)
              (conn-set-owner! c
                (spawn (lambda ()
                         (tcp-read-start! c)
                         (receive (after 5000 (send me (vector 'server-silent)))
                           (`#(tcp-data ,bv) (send me (vector 'server-got bv)))
                           (`#(tcp-eof) (send me (vector 'server-eof)))
                           (`#(tcp-error ,e) (send me (vector 'server-error e))))
                         (tcp-close! c))))))
          (tcp-connect! "127.0.0.1" lport self)
          (let ((c (receive (after 5000 (fail! "t2-10-no-connect"))
                     (`#(tcp-connected ,c) c)
                     (`#(tcp-connect-failed ,e) (fail! "t2-10-connect-failed" e)))))
            (inject-arm-return! 'try-write-foreign-eagain 0 1)
            (let ((ptr (foreign-alloc (bytevector-length payload))))
              (do ((i 0 (+ i 1))) ((= i (bytevector-length payload)))
                (foreign-set! 'unsigned-8 ptr i (bytevector-u8-ref payload i)))
              (tcp-write-foreign! c ptr (bytevector-length payload)
                (lambda (status) (send me (vector 'written status))))
              ;; the source buffer may be released as soon as the call returned
              (foreign-free ptr))
            (unless (eqv? (inject-hits 'try-write-foreign-eagain) 1)
              (fail! "t2-10-hits" (inject-hits 'try-write-foreign-eagain)))
            (receive (after 5000 (fail! "t2-10-no-completion"))
              (`#(written ,status) (unless (eqv? status 0) (fail! "t2-10-write-status" status))))
            (receive (after 5000 (fail! "t2-10-verdict-timeout"))
              (`#(server-got ,bv) (unless (equal? bv payload) (fail! "t2-10-bytes-differ" bv)))
              (`#(server-silent) (fail! "t2-10-never-arrived"))
              (`#(server-eof) (fail! "t2-10-eof-before-data"))
              (`#(server-error ,e) (fail! "t2-10-server-error" e)))
            (tcp-close! c)))
        (display "T2-10 a foreign write pushed to the queued path still arrives ok\n")))

    ;; ==== tranche 2: the node cells (design v4 §二 rows 7, 8, 9) ==========
    ;; All three arm 'critical-submit, the point inside link-write/critical's
    ;; own guard, and each asserts the failure branch's IMMEDIATE stop-link!:
    ;; node-down arrives, the hosted agent is reclaimed, accounting stays
    ;; consistent, and the peer comes back on its own. The wait is slack,
    ;; not a bound: if this ever waits for dead-ms the cell is red, and that
    ;; is the finding.
    ;; The child is the watcher for 7 and 8 (the hosting side is THIS
    ;; process, where the arm lives: injection state is per process) and
    ;; the host for 9.
    ;; ---- T2-7: a DOWN that cannot be submitted costs the link ------------
    (run-cell "T2-7"
      (lambda ()
        ;; a link drop that happened BEFORE this cell would have left its
        ;; notices waiting here; say so, because the reconnect ratchet
        ;; would then already be one step ahead
        (let probe ((n 0))
          (receive (after 0 (when (> n 0) (display "  stray link notices before T2-7: ") (display n) (newline)))
            (`#(node-down b) (display "  stray node-down before T2-7\n") (probe (+ n 1)))
            (`#(node-up b) (display "  stray node-up before T2-7\n") (probe (+ n 1)))))
        (let* ((base (local-callee-agents))
               (t (spawn (lambda () (receive (`#(stop) (void)))))))
          (register 't7 t)
          (rsend 'b 'svc (vector 'watch 't7))
          (receive (after 5000 (fail! "t2-7-no-watched")) (`#(watched ,m) 'ok))
          (wait-local-callee! "t2-7-not-hosted" (+ base 1))
          (settle-link!)
          (inject-arm-fault! 'critical-submit 1)
          (kill t 'for-the-cell)
          (expect-node-down! "t2-7")
          (unless (eqv? (inject-hits 'critical-submit) 1)
            (fail! "t2-7-hits" (inject-hits 'critical-submit)))
          (inject-disarm!)
          (wait-local-callee! "t2-7-agent-not-reclaimed" base)
          (accounted-ok! "t2-7")
          (expect-node-up! "t2-7")
          (sleep-ms 300)
          ;; the watcher was told, by the link's death, that its watch is gone
          (let ((l (drain! "t2-7")))
            (unless (drained-has? l 't7 'noconnection)
              (fail! "t2-7-watcher-not-told" l))))
        (display "T2-7 a DOWN that cannot be submitted costs the link ok\n")))

    ;; ---- T2-8: the same, on the immediate noproc branch -----------------
    ;; No pause exists between the mon's arrival and the noproc submission,
    ;; so the arm comes BEFORE the child is told to watch. The child's
    ;; #(watched ...) reply may itself be lost to the drop: it is not waited
    ;; for.
    (run-cell "T2-8"
      (lambda ()
        (let ((base (local-callee-agents)))
          (settle-link!)
          (inject-arm-fault! 'critical-submit 1)
          (rsend 'b 'svc (vector 'watch 'no-such-name-t8))
          (expect-node-down! "t2-8")
          (unless (eqv? (inject-hits 'critical-submit) 1)
            (fail! "t2-8-hits" (inject-hits 'critical-submit)))
          (inject-disarm!)
          (wait-local-callee! "t2-8-agent-not-reclaimed" base)
          (accounted-ok! "t2-8")
          (expect-node-up! "t2-8")
          (sleep-ms 300)
          (let ((l (drain! "t2-8")))
            (unless (drained-has? l 'no-such-name-t8 'noconnection)
              (fail! "t2-8-watcher-not-told" l))))
        (display "T2-8 a noproc DOWN that cannot be submitted costs the link ok\n")))

    ;; ---- T2-9: a demon that cannot be submitted costs the link ----------
    ;; This process is the watcher; the peer hosts. The local rmonitors
    ;; entry is gone before the demon is even built, so the local invariant
    ;; is blind to a hosted agent nobody reclaims: the peer's own count,
    ;; read over the NEW link, is the assertion.
    (run-cell "T2-9"
      (lambda ()
        (let ((pbase (peer-callee-agents! "t2-9")))
          (let ((mref (monitor-remote 'b 'svc)))
            (wait-peer-callee! "t2-9-not-hosted" (+ pbase 1))
            (settle-link!)
            (inject-arm-fault! 'critical-submit 1)
            (demonitor-remote mref)
            (expect-node-down! "t2-9")
            (unless (eqv? (inject-hits 'critical-submit) 1)
              (fail! "t2-9-hits" (inject-hits 'critical-submit)))
            (inject-disarm!)
            (expect-node-up! "t2-9")
            (sleep-ms 300)
            (wait-peer-callee! "t2-9-peer-agent-not-reclaimed" pbase)
            (accounted-ok! "t2-9")))
        (display "T2-9 a demon that cannot be submitted costs the link ok\n")))

    ;; ==== batch A ==========================================================
    ;; A1: publication of a file stream is two writes (fs-table, then the
    ;; owner index) and the second can fail. Half a publication is worse
    ;; than none: uv-owner-died! starts from the owner index, so a row that
    ;; is only in fs-table is unreachable, and the fd and request it pins
    ;; are never returned. See batch-A-design-v2.
    (run-cell "A1"
      (lambda ()
        (let ((fds0 (length (directory-list "/dev/fd")))
              (idx0 (uv-owner-index-count)))
          (inject-arm-fault! 'fs-publish-second-half 1)
          (let ((raised (guard (e (#t #t))
                          (file-stream-open-under! "igropyr/test" "node-child.sc" self)
                          #f)))
            (unless raised (fail! "a1-no-raise"))
            (unless (eqv? (inject-hits 'fs-publish-second-half) 1)
              (fail! "a1-hits" (inject-hits 'fs-publish-second-half)))
            ;; nothing half-published: no fs-table row, index back, fd back
            (unless (zero? (fs-count)) (fail! "a1-fs-table-row-left" (fs-count)))
            (unless (= (uv-owner-index-count) idx0)
              (fail! "a1-owner-index-left" (uv-owner-index-count) idx0))
            (let ((fds1 (length (directory-list "/dev/fd"))))
              (unless (= fds1 fds0) (fail! "a1-fd-leaked" 'now fds1 'before fds0)))))
        (display "A1 a failed second publication write leaves no half-published stream ok\n")))

    ;; A1b: the same failure on the open-by-path route (fs-start!), whose
    ;; request is published before libuv has opened anything, so the only
    ;; things that can be left behind are the fs-table row and the index
    ;; entry; the fd baseline is kept to say so, not because one is expected.
    (run-cell "A1b"
      (lambda ()
        (let ((fds0 (length (directory-list "/dev/fd")))
              (idx0 (uv-owner-index-count)))
          (inject-arm-fault! 'fs-publish-second-half-open 1)
          (let ((raised (guard (e (#t #t))
                          (file-stream-open! "igropyr/test/node-child.sc" self)
                          #f)))
            (unless raised (fail! "a1b-no-raise"))
            (unless (eqv? (inject-hits 'fs-publish-second-half-open) 1)
              (fail! "a1b-hits" (inject-hits 'fs-publish-second-half-open)))
            (unless (zero? (fs-count)) (fail! "a1b-fs-table-row-left" (fs-count)))
            (unless (= (uv-owner-index-count) idx0)
              (fail! "a1b-owner-index-left" (uv-owner-index-count) idx0))
            (let ((fds1 (length (directory-list "/dev/fd"))))
              (unless (= fds1 fds0) (fail! "a1b-fd-leaked" 'now fds1 'before fds0)))))
        (display "A1b a failed second publication write on the path route leaves nothing behind ok\n")))

    ;; A1c / A1d: a raise between the two publications and the submission.
    ;; Once the request is in both tables and not yet handed to libuv, no
    ;; callback will ever come for it; if the region and its guard end
    ;; before the submission, a raise there leaves a row that
    ;; uv-owner-died! later reaches through file-stream-close! -- which
    ;; only cleans an op in phase 'idle -- and so never releases. The
    ;; point stands for any raise in that gap; today nothing there raises,
    ;; and the cell pins that the guard reaches as far as the submission.
    (submit-gap-cell! "A1c" 'fs-submit-gap-open
      (lambda () (file-stream-open! "igropyr/test/node-child.sc" self)))
    (submit-gap-cell! "A1d" 'fs-submit-gap-fd
      (lambda () (file-stream-open-under! "igropyr/test" "node-child.sc" self)))

    ;; A2: a refused accept is counted, closes what it initialised, and
    ;; leaves the listener serving. uv_accept's negative return used to be
    ;; swallowed: no log line, no counter, the listener silently one
    ;; connection short.
    (run-cell "A2"
      (lambda ()
        (let* ((me self) (lport 18094)
               (accepted 0))
          ;; THE ACCEPT CALLBACK CLOSES WHAT IT ACCEPTS, AT ONCE. The injected
          ;; refusal is an override: uv_accept really runs, the callback
          ;; then takes the refusal branch and closes the client handle it
          ;; initialised, and the peer sees a close. Recording an accepted
          ;; connection and closing it later would leave a handle alive at
          ;; the next baseline; counting and closing here keeps every
          ;; baseline deterministic, and the count is the proof that the
          ;; listener still serves.
          (tcp-listen! "127.0.0.1" lport 16
            (lambda (c) (set! accepted (+ accepted 1)) (tcp-close! c)))
          (let* ((h0 (handles-stable! "a2-baseline"))   ; listener up, nothing else
                 (c0 (uv-accept-failure-counts))
                 (refused0 (cdr (assq 'refused c0)))
                 (error0 (cdr (assq 'error c0))))
            (inject-arm-return! 'accept-refused -53 1)   ; ECONNABORTED, once
            (tcp-connect! "127.0.0.1" lport self)
            (let ((c1 (receive (after 5000 (fail! "a2-first-connect-silent"))
                        (`#(tcp-connected ,c) c)
                        (`#(tcp-connect-failed ,e) 'failed))))
              ;; tcp-connected IS THE CLIENT'S EVENT, NOT THE LISTENER'S.
              ;; The connect completion and the accept readiness reach the
              ;; loop as two separate kqueue/epoll events and nothing orders
              ;; them: the client's message can be delivered a poll
              ;; iteration before the accept callback has run, and hits then
              ;; reads 0 for a refusal that is still on its way. Seen once,
              ;; on a loaded machine, as "a2-hits 0". So the witness is the
              ;; point itself, polled with a bound -- the peer's event is
              ;; evidence that a connection exists, not that it was handled.
              (let poll ((n 0))
                (cond ((eqv? (inject-hits 'accept-refused) 1) 'hit)
                      ((= n 200) (fail! "a2-hits" (inject-hits 'accept-refused)))
                      (else (sleep-ms 10) (poll (+ n 1)))))
              ;; hits says the point consumed its arm; delivered says the
              ;; point took the substitute branch for it. A wrapped call
              ;; that raises consumes the arm without delivering, and the
              ;; state assertions below would then be saved by the raise,
              ;; not by the override -- this line is what tells those apart.
              (unless (eqv? (inject-delivered 'accept-refused) 1)
                (fail! "a2-delivered" (inject-delivered 'accept-refused)))
              (let ((c1n (uv-accept-failure-counts)))
                (unless (= (cdr (assq 'refused c1n)) (+ refused0 1))
                  (fail! "a2-refused-not-counted" (cdr (assq 'refused c1n)) refused0))
                (unless (= (cdr (assq 'error c1n)) error0)
                  (fail! "a2-error-counter-moved" (cdr (assq 'error c1n)) error0)))
              (when (conn? c1) (tcp-close! c1))
              (inject-disarm!)
              ;; ROUND TWO, for the counter's reset. delivered lives with the
              ;; arm and starts from zero at every arming; a count that
              ;; survived re-arming would let one old delivery satisfy the
              ;; assertion above for a later override that never delivers.
              ;; So: arm again, read zero BEFORE anything can hit the point,
              ;; then refuse once more and read one.
              (inject-arm-return! 'accept-refused -53 1)
              ;; delivered answers 0 both for "no arming" and for "armed,
              ;; not delivered"; hits answers #f for the first and 0 for
              ;; the second. Read hits first so the zero below is known to
              ;; come from a fresh arming, not from the absence of one.
              (unless (eqv? (inject-hits 'accept-refused) 0)
                (fail! "a2-delivered-read-without-arming" (inject-hits 'accept-refused)))
              (unless (eqv? (inject-delivered 'accept-refused) 0)
                (fail! "a2-delivered-not-reset-by-arm" (inject-delivered 'accept-refused)))
              (tcp-connect! "127.0.0.1" lport self)
              (let ((c1b (receive (after 5000 (fail! "a2-second-refusal-silent"))
                           (`#(tcp-connected ,c) c)
                           (`#(tcp-connect-failed ,e) 'failed))))
                ;; same witness rule as round one: the client's event does
                ;; not order the listener's callback, so poll the point.
                (let poll ((n 0))
                  (cond ((eqv? (inject-delivered 'accept-refused) 1) 'delivered)
                        ((= n 200) (fail! "a2-delivered-round-two" (inject-delivered 'accept-refused)))
                        (else (sleep-ms 10) (poll (+ n 1)))))
                (let ((c2n (uv-accept-failure-counts)))
                  (unless (= (cdr (assq 'refused c2n)) (+ refused0 2))
                    (fail! "a2-second-refusal-not-counted" (cdr (assq 'refused c2n)) refused0)))
                (when (conn? c1b) (tcp-close! c1b))
                (inject-disarm!))
              ;; the listener still serves: a further connection is accepted
              (tcp-connect! "127.0.0.1" lport self)
              (let ((c2 (receive (after 5000 (fail! "a2-listener-dead-after-refusal"))
                          (`#(tcp-connected ,c) c)
                          (`#(tcp-connect-failed ,e) (fail! "a2-second-connect-failed" e)))))
                ;; and once more for the accept callback itself: a fixed
                ;; sleep is a guess, a bounded poll on the count is a witness
                (let poll ((n 0))
                  (cond ((>= accepted 1) 'accepted)
                        ((= n 200) (fail! "a2-second-connection-not-accepted" accepted))
                        (else (sleep-ms 10) (poll (+ n 1)))))
                (tcp-close! c2)
                ;; every handle the refusal or the second connection made is gone
                (let ((h1 (handles-stable! "a2-final")))
                  (unless (= h1 h0) (fail! "a2-handles-leaked" h1 h0)))))))
        (display "A2 a refused accept is counted and the listener keeps serving ok\n")))

    ;; INJECT_EXPECT_UNHIT=point -- the positive control for a skip run:
    ;; skipping a cell proves the print branch ran, not that nobody else
    ;; armed its point. If the point was hit anyway, the skip run's
    ;; conclusion (either of them) is void, and that is reported as broken.
    (let ((pt (getenv "INJECT_EXPECT_UNHIT")))
      (when pt
        (let* ((sym (string->symbol pt)) (h (inject-hits sym)))
          (if (or (not h) (eqv? h 0))
              (begin (display "UNHIT ") (display pt) (display " ok (never armed or hit)\n"))
              (begin (display "💥 BROKEN skip-run: ") (display pt) (display " was hit ")
                     (display h) (display " times despite the skipped cell\n")
                     (set! failures (cons "skip-run" failures)))))))
    (rsend 'b 'svc (vector 'quit))
    (sleep-ms 400)
    (cond
      ((null? failures) (display "ALL INJECT TESTS PASSED\n") (exit 0))
      (else (display "INJECT VERDICT: failed cells ") (write (reverse failures)) (newline)
            (exit 1)))))
