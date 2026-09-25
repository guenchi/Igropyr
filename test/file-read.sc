#!chezscheme
(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp))

(define prefix (string-append "/tmp/igropyr-file-read-"
                              (number->string (get-process-id))))
(define empty-path (string-append prefix "-empty"))
(define large-path (string-append prefix "-large"))
(define append-path (string-append prefix "-append"))
(define missing-path (string-append prefix "-missing"))

(define (write-bytes path bv)
  (call-with-port
    (open-file-output-port path (file-options no-fail) (buffer-mode block) #f)
    (lambda (p) (put-bytevector p bv))))

;; no-truncate IS WHAT MAKES THIS AN APPEND. Without it Chez truncates an
;; existing file on open even with `append`, so this helper emptied the file
;; and wrote the extra bytes from offset 0 -- while the read was running.
;; The cell below then read a file that shrank under it: measured on FreeBSD,
;; one run in about forty returned 6750208 bytes of an 8388608-byte file
;; (the read met end-of-file early, as it should), and the size check failed.
(define (append-bytes path bv)
  (call-with-port
    (open-file-output-port path (file-options no-create no-fail no-truncate append)
                           (buffer-mode block) #f)
    (lambda (p) (put-bytevector p bv))))

(define (cleanup)
  (for-each (lambda (p) (when (file-exists? p) (delete-file p)))
            (list empty-path large-path append-path missing-path)))

(define (bytevector-copy-part bv from to)
  (let ((r (make-bytevector (- to from))))
    (bytevector-copy! bv from r 0 (- to from))
    r))

(define (pattern-bytes n seed)
  (let ((bv (make-bytevector n)))
    (do ((i 0 (+ i 1))) ((= i (bytevector-length bv)) bv)
      (bytevector-u8-set! bv i (mod (+ (* i 31) seed) 256)))))

(define large (pattern-bytes 131123 7))
(define append-base (pattern-bytes (* 8 1024 1024) 13))
(define append-extra (pattern-bytes 65536 29))

(cleanup)
(write-bytes empty-path (make-bytevector 0))
(write-bytes large-path large)
(write-bytes append-path append-base)

(define (fail msg)
  (display "FAIL: ") (display msg) (newline)
  (cleanup)
  (exit 1))

(define (read-one path)
  (file-read-async! path self)
  (receive (after 5000 (fail (string-append "timeout reading " path)))
    (`#(file-read ,bv) bv)
    (`#(file-error ,e) (fail (string-append "unexpected read error " path)))))

(define (expect-file-error path label)
  (file-read-async! path self)
  (receive (after 5000 (fail (string-append label " timeout")))
    (`#(file-error ,e) e)
    (`#(file-read ,bv) (fail (string-append label " unexpectedly succeeded")))))

(start-scheduler
  (lambda ()
    (unless (= 0 (bytevector-length (read-one empty-path)))
      (fail "empty file was not empty"))
    (unless (equal? large (read-one large-path))
      (fail "large file content mismatch"))
    (expect-file-error missing-path "missing-file")
    (expect-file-error "/dev/zero" "non-regular file")
    ;; A file that GROWS while it is being read must still yield a
    ;; consistent snapshot: the read is sized by one fstat, so it returns
    ;; the size seen then, which may be the original size, the full size, or
    ;; anything between -- the append is 64 KiB through a buffered port and
    ;; need not reach the file in one write -- but never less than the
    ;; original, never more than was written, and always a prefix of the
    ;; original bytes followed by the appended ones.
    ;;
    ;; Which of the two sizes comes back is a race with libuv's thread
    ;; pool, so it is NOT asserted: an earlier version slept 10 ms and
    ;; demanded the smaller size, which held on an idle machine and failed
    ;; on FreeBSD under the full suite's load, where the fstat had not run
    ;; yet. What matters, and what is checked, is that the bytes are a
    ;; prefix of what the file legitimately held.
    (file-read-async! append-path self)
    (sleep-ms 10)
    (append-bytes append-path append-extra)
    (receive (after 5000 (fail "append-during-read timeout"))
      (`#(file-read ,bv)
        (let ((n (bytevector-length bv))
              (base-n (bytevector-length append-base))
              (full-n (+ (bytevector-length append-base)
                         (bytevector-length append-extra))))
          (unless (and (>= n base-n) (<= n full-n))
            (fail (string-append "append-during-read size "
                                 (number->string n) " is outside ["
                                 (number->string base-n) ", "
                                 (number->string full-n) "]")))
          (unless (equal? (bytevector-copy-part bv 0 base-n) append-base)
            (fail "append-during-read content changed"))
          (unless (equal? (bytevector-copy-part bv base-n n)
                          (bytevector-copy-part append-extra 0 (- n base-n)))
            (fail "append-during-read tail is not a prefix of the appended bytes"))))
      (`#(file-error ,e)
        (fail "append-during-read unexpectedly failed")))
    (cleanup)
    (display "ALL FILE READ TESTS PASSED\n")
    (exit 0)))
