#!chezscheme
;;; The async fs write bindings: the scheduler keeps running, the codes
;;; come back to their owners, and a dead owner's descriptors are closed.
;;;
;;; THE POINT COMES FIRST. These bindings exist so that a file-system
;;; write does not stop the runtime: the synchronous story is measured
;;; (a 20ms tick stretched to 641ms by one blocking syscall), and the
;;; asynchronous claim is judged the opposite way -- while an 8 MiB
;;; write sits on a pool thread, a competing green process MUST be
;;; running. A binding that wraps a synchronous call in an async-shaped
;;; API scores exactly zero on that count; the judge is the count being
;;; nonzero, not the write succeeding.
;;;
;;; Everything else is bookkeeping the protocol promises: completion
;;; messages carry the job id they answer (without it, two jobs from one
;;; process are indistinguishable in the mailbox and the ordering case
;;; would pass while testing nothing), libuv's normalized error codes
;;; come through (-2 is UV_ENOENT on every platform), and the outstanding
;;; counts drain to zero.

(import (chezscheme) (igropyr actor)
        (only (igropyr libuv) fs-o-rdonly fs-o-wronly fs-o-creat fs-o-trunc) (only (igropyr tcp) fs-open-async! fs-write-async! fs-fsync-async! fs-rename-async! fs-close-async! fs-job-count fs-fd-count))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (apply fail label info)))

(define root
  (format "~a/igropyr-fsw-test-~a-~a"
          (or (getenv "IGROPYR_LIBUV_FS_TEST_ROOT") "/tmp")
          (get-process-id) (real-time)))
(system (string-append "rm -rf " root "; mkdir -p " root))

(define wcflags (bitwise-ior fs-o-wronly fs-o-creat fs-o-trunc))

;; a failed prerequisite (an fd that never arrived) must stop the run,
;; not flow onward as #f into a foreign call -- the failure the label
;; describes, not a crash three lines later
(define (need v label)
  (unless v
    (display "  !! prerequisite failed, aborting: ") (display label) (newline)
    (exit 1))
  v)

(start-scheduler
  (lambda ()
    (define (await id label)
      (receive (after 15000 (fail label 'timeout) #f)
        (`#(fs-done ,jid ,rc)
          (if (= jid id)
              rc
              (begin (fail label 'wrong-job jid id) #f)))))

    ;; ---- the scheduler keeps running through a large write --------------
    (let ((ticks (box 0)) (stop (box #f)))
      (spawn (lambda ()
               (let loop ()
                 (unless (unbox stop)
                   (set-box! ticks (+ 1 (unbox ticks)))
                   (sleep-ms 0)
                   (loop)))))
      (let* ((path (string-append root "/big.bin"))
             (fd (need (let ((id (fs-open-async! path wcflags #o644 self)))
                         (await id "open for the big write"))
                       "big-write fd")))
        (check "the open answered a descriptor" (and fd (>= fd 0)) fd)
        (set-box! ticks 0)
        (let* ((id (fs-write-async! fd (make-bytevector (* 8 1024 1024) 120)
                                    0 self))
               (rc (await id "the big write"))
               (ran (unbox ticks)))
          (set-box! stop #t)
          (check "the write completed in full"
                 (equal? rc (* 8 1024 1024)) rc)
          ;; the judge: a synchronous call wearing this API scores zero.
          ;; Ten is far above scheduler noise and far below the measured
          ;; tens of thousands; the discrimination is zero versus not.
          (printf "  [info] competitor ran ~a times during the 8MiB write\n"
                  ran)
          (check "a green process ran while the write sat on the pool"
                 (>= ran 10) ran))
        (let ((id (fs-close-async! fd self)))
          (check "the close answered" (equal? (await id "close big") 0)))))

    ;; ---- the promised sequence, step by step, contents read back --------
    (let* ((tmp (string-append root "/seq.tmp"))
           (final (string-append root "/seq.bin"))
           (payload (string->utf8 "async sequence payload")))
      (let* ((fd (need (await (fs-open-async! tmp wcflags #o644 self) "seq open")
                       "seq fd")))
        (check "seq open ok" (and fd (>= fd 0)) fd)
        (check "seq write ok"
               (equal? (await (fs-write-async! fd payload 0 self) "seq write")
                       (bytevector-length payload)))
        (check "seq fsync ok"
               (equal? (await (fs-fsync-async! fd self) "seq fsync") 0))
        (check "seq close ok"
               (equal? (await (fs-close-async! fd self) "seq close") 0))
        (check "seq rename ok"
               (equal? (await (fs-rename-async! tmp final self) "seq rename")
                       0))
        (check "the bytes read back through the rename"
               (equal? payload
                       (call-with-port (open-file-input-port final)
                                       get-bytevector-all)))))

    ;; ---- a libuv-normalized error code, not a hang ----------------------
    (let ((rc (await (fs-open-async!
                       (string-append root "/no-such-dir/x.bin")
                       wcflags #o644 self)
                     "ENOENT open")))
      (check "an open into a missing directory answers UV_ENOENT"
             (equal? rc -2) rc))

    ;; ---- two jobs in flight: each completion names its own job ----------
    ;; a large and a small write race on the pool; whichever finishes
    ;; first, each fs-done carries the id of the job it answers, so both
    ;; waits resolve correctly. Arrival order is genuinely undetermined
    ;; and printed, not asserted.
    (let* ((pa (string-append root "/race-a.bin"))
           (pb (string-append root "/race-b.bin"))
           (fda (need (await (fs-open-async! pa wcflags #o644 self) "race open a")
                      "race fd a"))
           (fdb (need (await (fs-open-async! pb wcflags #o644 self) "race open b")
                      "race fd b"))
           (ida (fs-write-async! fda (make-bytevector (* 4 1024 1024) 97)
                                 0 self))
           (idb (fs-write-async! fdb (string->utf8 "b") 0 self)))
      (check "the two jobs have distinct ids" (not (= ida idb)) ida idb)
      (let ((first (receive (after 15000 (fail "race first" 'timeout) #f)
                     (`#(fs-done ,jid ,rc) (cons jid rc))))
            (second (receive (after 15000 (fail "race second" 'timeout) #f)
                      (`#(fs-done ,jid ,rc) (cons jid rc)))))
        (printf "  [info] completion order: ~a then ~a\n"
                (car first) (car second))
        (let ((by-id (lambda (id)
                       (cond ((and first (= (car first) id)) (cdr first))
                             ((and second (= (car second) id)) (cdr second))
                             (else #f)))))
          (check "the big write's completion names the big job"
                 (equal? (by-id ida) (* 4 1024 1024)) (by-id ida))
          (check "the small write's completion names the small job"
                 (equal? (by-id idb) 1) (by-id idb))))
      (await (fs-close-async! fda self) "race close a")
      (await (fs-close-async! fdb self) "race close b"))

    ;; ---- a dead owner's descriptor is closed for it ---------------------
    ;; the victim opens a file and dies holding the fd. The fd table is
    ;; the footprint: it must return to its baseline once the DOWN is
    ;; processed. Closing is the ONLY cleanup -- a half-written file is
    ;; the caller's protocol to reconcile, and that boundary is the
    ;; binding's documented semantics, not this suite's business.
    (let ((baseline (fs-fd-count))
          (me self))
      (let ((victim (spawn
                      (lambda ()
                        (let ((fd (let ((id (fs-open-async!
                                              (string-append root "/orphan.bin")
                                              wcflags #o644 self)))
                                    (receive
                                      (`#(fs-done ,jid ,rc) rc)))))
                          (send me (vector 'opened fd))
                          (receive))))))  ; hold the fd, wait forever
        (receive (after 15000 (fail "victim never opened" 'timeout))
          (`#(opened ,fd)
            (check "the victim's fd is tracked"
                   (= (fs-fd-count) (+ baseline 1))
                   (fs-fd-count) baseline)
            (kill victim 'orphan-test)
            ;; the DOWN is processed by the event loop; give it a beat
            (let poll ((k 0))
              (cond ((= (fs-fd-count) baseline)
                     (check "a dead owner's fd was closed for it" #t))
                    ((> k 100)
                     (fail "the orphaned fd was never reclaimed"
                           (fs-fd-count) baseline))
                    (else (sleep-ms 20) (poll (+ k 1)))))))))

    ;; ---- everything drained ---------------------------------------------
    (check "no job left outstanding" (= 0 (fs-job-count)) (fs-job-count))

    (system (string-append "rm -rf " root))
    (if (= failures 0)
        (begin (display "libuv-fs-write: all tests passed\n") (exit 0))
        (begin (display (number->string failures))
               (display " failures\n")
               (exit 1)))))
