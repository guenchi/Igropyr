#!chezscheme
;;; THREE FILE OPERATIONS THAT DO NOT STOP THE SCHEDULER: stat, unlink, scandir.
;;;
;;; Before this change a consumer wanting any of them had only Chez's
;;; synchronous primitives, which hold the single scheduler thread for the
;;; whole syscall. These run on libuv's thread pool like file-read-async!
;;; and deliver one message to the owner.
;;;
;;; The cell that matters most is R12-3: it does not ask whether the call
;;; returns the right answer (R12-1 does) but whether OTHER processes keep
;;; running while it is in flight -- a ticker counts its own ticks during a
;;; scandir of a directory with twenty thousand entries. Its positive
;;; control is the synchronous directory-list, which must stall the same
;;; ticker; without that control a ticker that would have kept ticking
;;; regardless (a directory too small to matter) passes the async call for
;;; the wrong reason.
;;;
;;; Needs IGROPYR_INJECT=on, from source (R12-5 injects a fault).
(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp)
        (igropyr inject-control) (igropyr inject))
(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "fs-async-ops suite requires IGROPYR_INJECT=on\n") (exit 1))
(unless (> ($inject-ticket) 0)
  (display "fs-async-ops suite process was not expanded with injection on (stale .so?)\n") (exit 1))
(define failures 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (field k al) (let ((p (assq k al))) (and p (cdr p))))
;; the file's size by the plainest route there is, so stat has something independent to agree with
(define (byte-count path) (let* ((ip (open-file-input-port path)) (bv (get-bytevector-all ip))) (close-port ip) (if (eof-object? bv) 0 (bytevector-length bv))))
(define big-dir "test/.scandir-20k")
(define big-n 20000)
(define n-par 10)   ; concurrent scandirs in R12-3
(define (make-big-dir!)
  (unless (file-directory? big-dir) (mkdir big-dir))
  (let loop ((i 0))
    (when (< i big-n)
      (let ((p (string-append big-dir "/e" (number->string i))))
        (unless (file-exists? p) (call-with-output-file p (lambda (o) (put-char o #\x)))))
      (loop (+ i 1)))))
(define (remove-big-dir!)
  (when (file-directory? big-dir)
    (for-each (lambda (n) (delete-file (string-append big-dir "/" n))) (directory-list big-dir))
    (delete-directory big-dir)))
;; A process that ticks every 10 ms; returns (ticks . elapsed-ms) measured
;; over the CALL ONLY, not over a padded window -- a synchronous call cannot
;; yield, so its tick count is 0 whatever the directory size, and that is
;; the positive control. The async call must run long enough (>= 20 ms) for
;; ">= 2 ticks" to mean anything; a directory too small to reach that is
;; reported as a failure, not passed over.
(define (ticks-during thunk)
  (let ((box (box 0)))
    (let ((t (spawn (lambda () (let loop () (sleep-ms 10) (set-box! box (+ 1 (unbox box))) (loop))))))
      (sleep-ms 0)
      (let ((t0 (now-ms)))
        (thunk)
        (let ((el (- (now-ms) t0)))
          (kill t 'done)
          (cons (unbox box) el))))))

(start-scheduler
  (lambda ()
    (spawn (lambda () (sleep-ms 120000) (display "FAIL watchdog\n") (remove-big-dir!) (exit 1)))
    ;; ---- R12-1 each call answers, and the answers are right
    (file-stat-async! "test/node-child.sc" self)
    (receive (after 5000 (check "stat answered" #f))
      (`#(file-stat ,al)
        (check "stat: size matches file-size" (= (field 'size al) (byte-count "test/node-child.sc")) (field 'size al))
        (check "stat: mtime-sec is a plausible recent epoch second"
               (and (integer? (field 'mtime-sec al)) (> (field 'mtime-sec al) 1700000000)) (field 'mtime-sec al))
        (check "stat: mode, dev, ino, nlink, uid, gid, ctime present as integers"
               (for-all (lambda (k) (integer? (field k al))) '(mode dev ino nlink uid gid ctime-sec ctime-nsec))))
      (`#(file-error ,e) (check "stat answered without error" #f e)))
    (let ((victim "test/.unlink-me"))
      (call-with-output-file victim (lambda (o) (put-char o #\x)))
      (file-unlink-async! victim self)
      (receive (after 5000 (check "unlink answered" #f))
        (`#(file-unlinked) (check "unlink: the file is gone" (not (file-exists? victim))))
        (`#(file-error ,e) (check "unlink answered without error" #f e))))
    (file-scandir-async! "test" self)
    (receive (after 5000 (check "scandir answered" #f))
      (`#(file-entries ,names)
        (check "scandir: lists a known file" (member "node-child.sc" names))
        (check "scandir: neither . nor .." (not (or (member "." names) (member ".." names))))
        (check "scandir: every entry is a string" (for-all string? names)))
      (`#(file-error ,e) (check "scandir answered without error" #f e)))
    ;; ---- R12-2 a missing path reports ENOENT, for each of the three
    (for-each
      (lambda (start label)
        (start "test/.does-not-exist" self)
        (receive (after 5000 (check (string-append label ": ENOENT answered") #f))
          (`#(file-error ,e) (check (string-append label ": ENOENT is an error, not a hang") (integer? e) e))
          (,x (check (string-append label ": ENOENT must not succeed") #f x))))
      (list file-stat-async! file-unlink-async! file-scandir-async!)
      (list "stat" "unlink" "scandir"))
    ;; ---- R12-3 the scheduler keeps running while big scandirs are in flight
    ;; One 20k-entry scandir finishes in ~13 ms on a warm cache -- too short
    ;; to see a 10 ms ticker. Ten submitted back to back serialise on the
    ;; four-thread pool, so the loop is free for tens of milliseconds
    ;; between completions; the synchronous control does the same ten
    ;; listings in a row and cannot yield once.
    (make-big-dir!)
    (let* ((main self)
           (a (ticks-during
                (lambda ()
                  (let sub ((i 0)) (when (< i n-par) (file-scandir-async! big-dir main) (sub (+ i 1))))
                  (let recv ((i 0))
                    (when (< i n-par)
                      (receive (after 20000 (check "big scandirs answered" #f))
                        (`#(file-entries ,names)
                          (unless (= (length names) big-n) (check "big scandir: all twenty thousand entries" #f (length names)))
                          (recv (+ i 1)))
                        (`#(file-error ,e) (check "big scandir answered without error" #f e))))))))
           (s (ticks-during (lambda () (let l ((i 0)) (when (< i n-par) (directory-list big-dir) (l (+ i 1))))))))
      (check "ten async scandirs: all answered with twenty thousand entries" #t)
      (check "async scandirs took long enough to measure (>= 20 ms elapsed)" (>= (cdr a) 20) 'elapsed-ms (cdr a))
      (check "async scandirs: the ticker ticked during the calls (>= 2)" (>= (car a) 2) 'ticks (car a) 'elapsed-ms (cdr a))
      (check "positive control: ten synchronous directory-lists yield no tick" (= (car s) 0) 'ticks (car s) 'elapsed-ms (cdr s)))
    ;; ---- R12-4 owner dies before completion: nothing leaks, nothing is delivered
    ;; The obvious construction -- an owner that submits and then exits --
    ;; proves nothing: any yield after the submit is enough for a scandir to
    ;; complete and be reclaimed the ORDINARY way, and "fs-count 0 before, 0
    ;; after" is two zeros compared. So: this process submits, the OWNER is
    ;; another process, and it is killed in the same scheduling turn with no
    ;; yield between. fs-count = 1 right after the kill is the positive
    ;; control that the request was in flight when its owner died.
    (let ((idx0 (uv-owner-index-count))
          (p (spawn (lambda () (receive (after 20000 'x) (,m m))))))
      (sleep-ms 0)                          ; let p reach its receive
      (file-scandir-async! big-dir p)       ; submitted here, owned by p
      (kill p 'bye)                         ; same turn: no yield since the submit
      (check "positive control: the request was in flight when its owner died"
             (and (= (fs-count) 1) (not (process-alive? p))) (fs-count) (process-alive? p))
      (sleep-ms 1500)
      (check "owner died before completion: fs table row reclaimed" (zero? (fs-count)) (fs-count))
      (check "owner died before completion: owner index back to baseline" (= (uv-owner-index-count) idx0) (uv-owner-index-count) idx0)
      (receive (after 200 'ok) (`#(file-entries ,x) (check "a dead owner's result must not reach anyone else" #f))))
    ;; ---- R12-5 a raise between publish and submit leaves nothing behind
    (let ((idx0 (uv-owner-index-count)))
      (inject-arm-fault! 'fs-simple-submit-gap 1)
      (let ((raised (guard (e (#t #t)) (file-stat-async! "test/node-child.sc" self) #f)))
        (check "submit-gap: the injected raise reached the caller" raised)
        (check "submit-gap: hit once" (eqv? (inject-hits 'fs-simple-submit-gap) 1) (inject-hits 'fs-simple-submit-gap))
        (inject-disarm!)
        (check "submit-gap: no fs table row left" (zero? (fs-count)) (fs-count))
        (check "submit-gap: owner index unchanged" (= (uv-owner-index-count) idx0) (uv-owner-index-count) idx0)))
    (remove-big-dir!)
    (if (zero? failures) (begin (display "ALL FS-ASYNC-OPS TESTS PASSED\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
