#!chezscheme
;;; A file stream that changes owner must still be reclaimed.
;;;
;;; file-stream-own! moved the owner FIELD but not the owner INDEX, and the
;;; index is what uv-owner-died! consults. So a pump spawned to drive a
;;; download -- which is exactly the shape express.sc uses, and the reason
;;; the transfer exists -- left its fd, its uv_fs_t and its 256 KiB foreign
;;; buffer rooted by fs-table for the life of the VM when it was killed.
;;;
;;; A killed process runs no dynamic-wind exit handlers, so nothing else
;;; was ever going to close them.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define path "/tmp/igropyr-fs-owner-test.bin")

(start-scheduler
  (lambda ()
    (system (string-append "dd if=/dev/zero of=" path " bs=1024 count=512 2>/dev/null"))
    (sleep-ms 100)
    (let ((base (fs-count)) (me self))
      ;; open in THIS process, then hand the stream to a pump, exactly as a
      ;; streaming file response does
      (let ((st (file-stream-open! path self)))
        (check "the stream opened" (and st #t))
        (let ((pump (spawn (lambda ()
                             (file-stream-own! st self)
                             (file-stream-raw! st)
                             (send me (vector 'owned))
                             ;; take one chunk, then wait to be killed
                             (file-stream-read! st)
                             (receive (after 30000 'done)
                               (`#(file-chunk ,len)
                                 (receive (after 30000 'done))))))))
          (receive (after 3000 'lost) (`#(owned) 'ok))
          (sleep-ms 200)
          (check "the stream is open while the pump holds it"
            (> (fs-count) base))
          (monitor pump)
          (kill pump 'reaped)
          (receive (after 3000 (void)) (`#(DOWN ,@pump ,_) 'ok))
          (sleep-ms 500)
          (display "  [info] open file streams ") (display base)
          (display " -> ") (display (fs-count)) (display " after the owner died\n")
          (check "killing the new owner reclaims the stream"
            (= (fs-count) base)))))
    (system (string-append "rm -f " path))
    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "fs-owner-transfer: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
