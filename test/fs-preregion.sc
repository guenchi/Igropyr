#!chezscheme
;;; fs-start-fd! OWNS THE DESCRIPTOR FROM ITS FIRST INSTRUCTION, WITHOUT A
;;; REGION AROUND THE CALL.
;;;
;;; It used to allocate its state vector before entering its own region,
;;; while already holding the fd its caller had just opened -- so a raise
;;; there leaked the fd, and the only thing preventing that was the caller
;;; wrapping the openat and the call in a region of its own. A part whose
;;; correctness depended on its caller's context. Now the caller builds the
;;; vector before openat, and the function's first form is the region.
;;;
;;; The injection point 'fs-preregion-fd is the FIRST form inside the
;;; function's own guard: a raise there is the earliest possible raise
;;; after ownership transfers, and the fd must still be closed.
;;; Needs IGROPYR_INJECT=on, from source. Shape of test/inject.sc T2-2.
(import (chezscheme) (igropyr actor) (igropyr libuv)
        (igropyr inject-control) (igropyr inject))
(unless (equal? (getenv "IGROPYR_INJECT") "on")
  (display "fs-preregion suite requires IGROPYR_INJECT=on\n") (exit 1))
(unless (> ($inject-ticket) 0)
  (display "fs-preregion suite process was not expanded with injection on (stale .so?)\n") (exit 1))
(define failures 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(start-scheduler
  (lambda ()
    (let ((fds0 (length (directory-list "/dev/fd")))
          (idx0 (uv-owner-index-count)))
      (inject-arm-fault! 'fs-preregion-fd 1)
      (let ((raised (guard (e (#t #t))
                      (file-stream-open-under! "igropyr/test" "node-child.sc" self)
                      #f)))
        (check "the injected raise reached the caller" raised)
        (check "the point was hit exactly once" (eqv? (inject-hits 'fs-preregion-fd) 1) (inject-hits 'fs-preregion-fd))
        (inject-disarm!)
        (sleep-ms 50)
        (let ((fds1 (length (directory-list "/dev/fd"))))
          (check "the descriptor was closed: fd count unchanged" (= fds1 fds0) 'now fds1 'before fds0))
        (check "nothing was published to the fs table" (zero? (fs-count)) (fs-count))
        (check "the owner index is unchanged" (= (uv-owner-index-count) idx0) (uv-owner-index-count) idx0)))
    ;; control: without the fault the same call succeeds and the stream is closable
    (let ((s (file-stream-open-under! "igropyr/test" "node-child.sc" self)))
      (receive (after 5000 (check "control open did not complete" #f))
        (`#(file-stream ,st ,size) (check "control: the same call opens when nothing raises" (> size 0) size)
                                    (file-stream-close! st))
        (`#(file-error ,e) (check "control open failed" #f e))))
    (sleep-ms 100)
    (if (zero? failures) (begin (display "ALL FS-PREREGION TESTS PASSED\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
