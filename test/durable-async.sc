#!chezscheme
;;; (igropyr durable-async): the same crash-safe sequence, and the world
;;; keeps running while it happens.
;;;
;;; THE JUDGE IS A CONTRAST PAIR with a real disk sync behind it. The
;;; synchronous version was measured stopping the scheduler for the whole
;;; write (ticks 0 over 255ms of 192 MiB); here a competitor MUST tick
;;; while the same sequence runs on the pool. This is the probe the
;;; yielding-writer cases could never be: the stimulus is an actual
;;; fsync, not a sleep that cooperates.
;;;
;;; The second measured promise: AT MOST ONE FS JOB IN FLIGHT per call.
;;; Await-before-submit is what makes the trace mean anything -- an eager
;;; implementation could submit every step upfront, receive them in
;;; planned order, and emit a perfect-looking trace of a sequence the
;;; disk never saw. A competitor samples fs-job-count throughout; its
;;; maximum is the discriminator (the eager mutant shows >= 2 for the
;;; whole write duration).
;;;
;;; Error identity with the sync version is OP AND SHAPE, not path: the
;;; two libraries keep independent temp counters, so the same failure
;;; names each library's own candidate. Asserting path equality here was
;;; tried and was wrong; the honest form is "target-adjacent, .tmp
;;; suffixed, correct op".
;;;
;;; Deliberately NOT covered, said plainly: short-write resubmission
;;; (real files on local filesystems do not short-write; the loop is
;;; held by code review), and a mid-fsync kill's exact residue timing
;;; (kills cannot be aimed between two awaits from outside; the residue
;;; POLICY is asserted after the fact instead).

(import (chezscheme) (igropyr actor)
        (only (igropyr libuv) now-ms fs-o-wronly fs-o-creat) (only (igropyr tcp) fs-job-count fs-fd-count fs-open-async!)
        (igropyr durable-async)
        (only (igropyr durable)
              durable-write-file! durable-error? durable-error-op
              durable-error-path fs-trace-hook-set! with-fs-trace))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))

(define root
  (format "~a/igropyr-dasync-test-~a-~a"
          (or (getenv "IGROPYR_DURABLE_TEST_ROOT") "/tmp")
          (get-process-id) (real-time)))
(system (string-append "rm -rf " root "; mkdir -p " root))

(define (suffix? s suf)
  (let ((n (string-length s)) (m (string-length suf)))
    (and (>= n m) (string=? (substring s (- n m) n) suf))))

(start-scheduler
  (lambda ()

    (define (temp-n path)
      ;; "<target>.<pid>.<n>.tmp" -> n
      (let* ((no-tmp (substring path 0 (- (string-length path) 4)))
             (dot (let loop ((i (- (string-length no-tmp) 1)))
                    (if (char=? (string-ref no-tmp i) #\.) i (loop (- i 1))))))
        (string->number (substring no-tmp (+ dot 1) (string-length no-tmp)))))
    (define (fail-parent!)
      (guard (e ((durable-error? e) e))
        (durable-write-file-async! (string-append root "/no/x.bin")
                                   (string->utf8 "x"))
        (fail "a missing parent did not raise") #f))
    ;; ---- the contrast pair, with the in-flight ceiling sampled ---------
    (let ((payload (make-bytevector (* 32 1024 1024) 7))
          (ticks (box 0)) (maxjobs (box 0)) (stop (box #f)))
      (spawn (lambda ()
               (let loop ()
                 (unless (unbox stop)
                   (set-box! ticks (+ 1 (unbox ticks)))
                   (let ((j (fs-job-count)))
                     (when (> j (unbox maxjobs)) (set-box! maxjobs j)))
                   (sleep-ms 2)
                   (loop)))))
      ;; the synchronous half of the pair: same payload, zero ticks
      (set-box! ticks 0)
      (durable-write-file! (string-append root "/sync.bin") payload)
      (let ((sync-ticks (unbox ticks)))
        ;; the asynchronous half: the world runs, one job at a time
        (set-box! ticks 0)
        (let ((r (durable-write-file-async! (string-append root "/async.bin")
                                            payload)))
          (set-box! stop #t)
          (check "the async write returns its path"
                 (equal? r (string-append root "/async.bin")))
          (printf "  [info] ticks: sync ~a, async ~a; max in-flight ~a\n"
                  sync-ticks (unbox ticks) (unbox maxjobs))
          (check "the synchronous write stopped the world (the old truth)"
                 (= sync-ticks 0) sync-ticks)
          (check "a competitor ran while the async sequence held the disk"
                 (>= (unbox ticks) 10) (unbox ticks))
          (check "at most one fs job in flight for the whole sequence"
                 (<= (unbox maxjobs) 1) (unbox maxjobs))))
      ;; and the bytes are really there
      (check "the async payload reads back whole"
             (equal? payload
                     (call-with-port
                       (open-file-input-port (string-append root "/async.bin"))
                       get-bytevector-all))))

    ;; ---- the eight steps, in order, through the shared hook ------------
    (let ((ops '()))
      (with-fs-trace
        (lambda (op path detail) (set! ops (cons op ops)))
        (lambda ()
          (durable-write-file-async! (string-append root "/traced.bin")
                                     (string->utf8 "traced"))))
      (check "the eight steps arrive in exact order through the SHARED hook"
             (equal? (reverse ops)
                     '(open write fsync close rename
                       dir-open dir-fsync dir-close))
             (reverse ops)))

    ;; ---- the same eight steps for an EMPTY payload ----------------------
    ;; the write loop's first version tested the remaining count before
    ;; submitting, so a zero-length payload skipped 'write entirely --
    ;; same assertion, different input, different answer. An empty file
    ;; is a real use (a marker, a truncation), not an edge to skip
    (let ((ops '()))
      (with-fs-trace
        (lambda (op path detail) (set! ops (cons op ops)))
        (lambda ()
          (durable-write-file-async! (string-append root "/empty.bin")
                                     (make-bytevector 0))))
      (check "an empty payload still walks all eight steps"
             (equal? (reverse ops)
                     '(open write fsync close rename
                       dir-open dir-fsync dir-close))
             (reverse ops))
      ;; an empty file reads back as EOF, not as a zero-length bytevector
      (check "...and produces an empty file"
             (and (file-exists? (string-append root "/empty.bin"))
                  (eof-object?
                    (call-with-port
                      (open-file-input-port (string-append root "/empty.bin"))
                      get-bytevector-all)))))

    ;; ---- both variants produce the same file mode ----------------------
    ;; the async library once hardcoded #o600 where the sync one lets
    ;; umask govern 0666 -- switching variants silently changed who could
    ;; read the product, because rename makes the temp's mode the
    ;; target's mode
    (let ((mode-of (lambda (path)
                     (let ((p (process (string-append "ls -l " path))))
                       (substring (get-line (car p)) 0 10)))))
      (check "sync and async products carry the same permissions"
             (equal? (mode-of (string-append root "/sync.bin"))
                     (mode-of (string-append root "/async.bin")))
             (mode-of (string-append root "/sync.bin"))
             (mode-of (string-append root "/async.bin"))))

    ;; ---- killed callers: the OS's fd count, not the library's ----------
    ;; fs-fd-count counts the REGISTRY, and the leak class this guards
    ;; against lives exactly on the paths that never register -- an open
    ;; completing after its owner died, a close deferred past a kill. The
    ;; witness has to be /dev/fd: the kernel's own ledger.
    ;; IN-PROCESS directory-list, not a subprocess ls: these fds carry
    ;; O_CLOEXEC, so a child's /dev/fd never shows them -- a subprocess
    ;; witness is blind to exactly the leak class it is here to catch
    (let ((os-fds (lambda () (length (directory-list "/dev/fd")))))
      (let ((baseline (os-fds)))
        (do ((i 0 (+ i 1))) ((= i 12))
          (let ((victim (spawn
                          (lambda ()
                            (durable-write-file-async!
                              (format "~a/victim-~a.bin" root i)
                              (make-bytevector (* 2 1024 1024) 3))))))
            ;; let it get into the middle of its sequence, then kill it
            (sleep-ms 3)
            (kill victim 'fd-accounting)))
        ;; deferred closes complete as their jobs drain
        (let poll ((k 0))
          (cond ((= 0 (fs-job-count)) 'ok)
                ((> k 400) (fail "killed callers' jobs never drained"
                                 (fs-job-count)))
                (else (sleep-ms 20) (poll (+ k 1)))))
        (sleep-ms 100)
        (let ((after (os-fds)))
          (check "twelve mid-sequence kills leak no fd the KERNEL can see"
                 (<= after baseline) baseline after))
        ;; the deterministic orphan: submit an open and RETURN, so the
        ;; owner is dead before the completion arrives, every time --
        ;; a kill aimed from outside almost never lands in that window
        ;; (measured: a 3ms-late kill misses it in twelve of twelve)
        (do ((i 0 (+ i 1))) ((= i 30))
          (spawn (lambda ()
                   (fs-open-async!
                     (format "~a/orphan-~a.bin" root i)
                     (bitwise-ior fs-o-wronly fs-o-creat) #o644 self)
                   'die)))
        (let poll ((k 0))
          (cond ((= 0 (fs-job-count)) 'ok)
                ((> k 400) (fail "orphan opens never drained" (fs-job-count)))
                (else (sleep-ms 20) (poll (+ k 1)))))
        (sleep-ms 50)
        (let ((after (os-fds)))
          (check "thirty opens completing after their owners died leak nothing"
                 (<= after baseline) baseline after))))

    ;; ---- fail fast: no job is ever submitted for a bad argument --------
    (let ((jobs-before (fs-job-count)))
      (guard (e (#t 'ok))
        (durable-write-file-async! (string-append root "/nul\x0;.bin")
                                   (string->utf8 "x"))
        (fail "a NUL path was accepted"))
      (guard (e (#t 'ok))
        (durable-write-file-async! (string-append root "/notbytes.bin") "str")
        (fail "a string payload was accepted"))
      (check "rejected arguments submitted zero jobs"
             (= (fs-job-count) jobs-before)))

    ;; ---- error mapping, three phases, sync-identical op ----------------
    ;; parent missing: the temp open fails -> 'write, and the path is the
    ;; library's own first candidate (target-adjacent, .tmp), NOT the
    ;; sync library's counter value
    ;; the temp counter is module-global and monotonic, so "failed on the
    ;; FIRST candidate" is asserted as a DELTA: two identical failures in
    ;; a row mint exactly one candidate each. A retry-on-anything
    ;; implementation burns 1024 per failure and the delta says so.
    (let* ((e1 (fail-parent!))
           (e2 (fail-parent!)))
      (check "missing parent classifies as 'write, like the sync version"
             (and e1 (eq? (durable-error-op e1) 'write)))
      (check "ENOENT fails without retrying: one candidate per failure"
             (and e1 e2 (= 1 (- (temp-n (durable-error-path e2))
                                (temp-n (durable-error-path e1)))))
             (and e1 (durable-error-path e1))
             (and e2 (durable-error-path e2))))
    ;; rename onto a directory: rename fails -> 'rename with the TARGET
    ;; path, and the temp survives with its bytes
    (let* ((tdir (string-append root "/take-this"))
           (_ (system (string-append "mkdir -p " tdir "/sub")))
           (e (guard (e ((durable-error? e) e))
                (durable-write-file-async! tdir (string->utf8 "doomed"))
                (fail "renaming onto a non-empty directory succeeded") #f)))
      (check "rename failure classifies as 'rename with the target path"
             (and e (eq? (durable-error-op e) 'rename)
                  (equal? (durable-error-path e) tdir)))
      ;; the completed body survives the failed rename, same as sync
      (let ((tmps (let ((p (process (string-append "ls " root))))
                    (let loop ((acc '()))
                      (let ((l (get-line (car p))))
                        (if (eof-object? l) acc
                            (loop (if (suffix? l ".tmp") (cons l acc) acc))))))))
        (check "the temp survives a failed rename, as in the sync library"
               (pair? tmps) tmps)))

    ;; ---- exclusive temp: a squatter is preserved, the write goes on ----
    ;; The plant must be the EXACT next candidate or the case is vacuous
    ;; (a first version planted ".0.tmp" against the monotonic counter and
    ;; tested nothing). A traced probe reveals the current counter; the
    ;; squat call's first candidate is the successor.
    (let* ((target (string-append root "/squat.bin"))
           (probe-tmp (box #f)))
      (with-fs-trace
        (lambda (op path detail)
          (when (and (eq? op 'open) (not (unbox probe-tmp)))
            (set-box! probe-tmp path)))
        (lambda ()
          (durable-write-file-async! (string-append root "/probe.bin")
                                     (string->utf8 "p"))))
      (let ((squat (format "~a.~a.~a.tmp" target (get-process-id)
                           (+ 1 (temp-n (unbox probe-tmp)))))
            (opens (box 0)))
        (call-with-output-file squat (lambda (p) (display "SENTINEL" p)))
        (let ((r (with-fs-trace
                   (lambda (op path detail)
                     (when (eq? op 'open)
                       (set-box! opens (+ 1 (unbox opens)))))
                   (lambda ()
                     (durable-write-file-async! target
                                                (string->utf8 "real"))))))
          (check "the write succeeds past a squatting temp" (equal? r target))
          (check "...via exactly one extra open attempt"
                 (= 2 (unbox opens)) (unbox opens))
          (check "...and the squatter's bytes are untouched"
                 (equal? "SENTINEL"
                         (call-with-input-file squat get-string-all)))
          (check "...and the target holds the real payload"
                 (equal? (string->utf8 "real")
                         (call-with-port (open-file-input-port target)
                                         get-bytevector-all))))))

    ;; ---- a stale fs-done in the mailbox is not this call's answer -----
    ;; each await pins its own job id; a composite that consumes any
    ;; fs-done would swallow this forged frame and desync every step
    (send self (vector 'fs-done 999999 0))
    ;; guarded: a library that consumes any fs-done takes the forged
    ;; frame as its open's answer and derails into a raise -- that must
    ;; red HERE as the mismatch it is, not crash the suite
    (let ((r (guard (e (#t (fail "the sequence was derailed by a stale frame"
                                 e)
                           #f))
               (durable-write-file-async! (string-append root "/pinned.bin")
                                          (string->utf8 "pinned")))))
      (check "a forged stale completion does not derail the sequence"
             (equal? r (string-append root "/pinned.bin")))
      (receive (after 0 (fail "the stale frame was consumed by the library"))
        (`#(fs-done 999999 ,rc) (ok "the stale frame is still ours"))))

    ;; ---- dir-ensure: three shapes, flush jobs only for OWN creation ----
    (let ((fresh (string-append root "/mkme")))
      (let ((ops '()))
        (with-fs-trace
          (lambda (op path detail) (set! ops (cons op ops)))
          (lambda () (durable-dir-ensure-async! fresh)))
        (check "a fresh directory is created and its parent flushed"
               (and (file-directory? fresh)
                    (memq 'dir-fsync ops)
                    (memq 'mkdir ops))
               (reverse ops)))
      ;; pre-existing: vouches only for its own creation -- ZERO flush
      ;; jobs, expressed as job absence rather than prose
      (let ((ops '()))
        (with-fs-trace
          (lambda (op path detail) (set! ops (cons op ops)))
          (lambda () (durable-dir-ensure-async! fresh)))
        (check "an existing directory triggers no flush at all"
               (not (memq 'dir-fsync ops)) (reverse ops)))
      ;; a regular file where the directory should be
      (let ((f (string-append root "/imafile")))
        (call-with-output-file f (lambda (p) (display "x" p)))
        (let ((e (guard (e ((durable-error? e) e))
                   (durable-dir-ensure-async! f)
                   (fail "dir-ensure accepted a regular file") #f)))
          (check "a regular file classifies as a mkdir failure"
                 (and e (eq? (durable-error-op e) 'mkdir)
                      (equal? (durable-error-path e) f))))))

    ;; ---- the directory flush, on its own -------------------------------
    ;; The consumer that asked for this export needs it during recovery,
    ;; where the same directory is flushed again and again. So the case
    ;; that matters is not "does it flush" but "does it flush EVERY TIME":
    ;; a cached or skip-if-already-done implementation would satisfy a
    ;; single-call test and quietly do nothing on the second, which is
    ;; exactly the path recovery runs on.
    (let ((dir (string-append root "/flushme")))
      (durable-dir-ensure-async! dir)
      (let ((first '()) (second '()))
        (with-fs-trace
          (lambda (op path detail) (set! first (cons op first)))
          (lambda () (durable-fsync-dir-async! dir)))
        (with-fs-trace
          (lambda (op path detail) (set! second (cons op second)))
          (lambda () (durable-fsync-dir-async! dir)))
        (check "a directory flush is exactly open, fsync, close"
               (equal? (reverse first) '(dir-open dir-fsync dir-close))
               (reverse first))
        (check "...and the second call does the whole thing again"
               (equal? (reverse second) '(dir-open dir-fsync dir-close))
               (reverse second)))
      (check "it answers with the path it was given"
             (equal? (durable-fsync-dir-async! dir) dir)))
    ;; a missing directory names the step that failed, on the path given
    (let ((e (guard (e ((durable-error? e) e))
               (durable-fsync-dir-async! (string-append root "/no-such-dir"))
               (fail "flushing a missing directory did not raise") #f)))
      (check "a missing directory fails at dir-open with that path"
             (and e (eq? (durable-error-op e) 'dir-open)
                  (equal? (durable-error-path e)
                          (string-append root "/no-such-dir")))
             (and e (list (durable-error-op e) (durable-error-path e)))))
    ;; A REGULAR FILE MUST BE REFUSED. O_RDONLY opens one happily and
    ;; fsync succeeds on it, so without O_DIRECTORY this call would
    ;; silently flush that file's CONTENTS -- the one thing the function
    ;; documents as not its guarantee. The boundary has to be in the
    ;; implementation, not only in the prose.
    (let* ((f (string-append root "/not-a-dir"))
           (_ (call-with-output-file f (lambda (p) (display "x" p))))
           (e (guard (e ((durable-error? e) e))
                (durable-fsync-dir-async! f)
                (fail "flushing a regular file silently succeeded") #f)))
      (check "a regular file is refused at dir-open"
             (and e (eq? (durable-error-op e) 'dir-open)
                  (equal? (durable-error-path e) f))))
    (guard (e (#t 'ok))
      (durable-fsync-dir-async! (string-append root "/nul\x0;dir"))
      (fail "a NUL path was accepted by the directory flush"))
    (ok "the directory flush validates its path at the entry")

    ;; ---- nothing leaks ------------------------------------------------
    (check "no fs job outstanding" (= 0 (fs-job-count)) (fs-job-count))
    (check "no fs fd held" (= 0 (fs-fd-count)) (fs-fd-count))

    (system (string-append "rm -rf " root))
    (if (= failures 0)
        (begin (display "durable-async: all tests passed\n") (exit 0))
        (begin (display (number->string failures))
               (display " failures\n") (exit 1)))))
