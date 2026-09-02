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
(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr node)
        (igropyr inject-control))

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))
(define port 18092)                     ; not node.sc's 18091: never collide
(define secret "test-mesh-secret")

(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "inject suite requires IGROPYR_INJECT=on (hooks expand to nothing otherwise)\n")
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
(define (run-cell name thunk)
  (set! recorded #f)
  (let ((came-out
          (guard (e ((cell-failure? e) (report-failure! name e) 'red)
                    (#t (display "FAIL ") (display name) (display " raised ") (write e) (newline)
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
            name " " (number->string port) " " secret " &")))

(define (bytes-now) (cdr (assq 'bytes (node-outbound-stats))))

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

    (rsend 'b 'svc (vector 'quit))
    (sleep-ms 400)
    (cond
      ((null? failures) (display "ALL INJECT TESTS PASSED\n") (exit 0))
      (else (display "INJECT VERDICT: failed cells ") (write (reverse failures)) (newline)
            (exit 1)))))
