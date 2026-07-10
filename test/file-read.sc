#!chezscheme
(import (chezscheme) (igropyr actor) (igropyr libuv))

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

(define (append-bytes path bv)
  (call-with-port
    (open-file-output-port path (file-options no-create no-fail append)
                           (buffer-mode block) #f)
    (lambda (p) (put-bytevector p bv))))

(define (cleanup)
  (for-each (lambda (p) (when (file-exists? p) (delete-file p)))
            (list empty-path large-path append-path missing-path)))

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
    (file-read-async! append-path self)
    (sleep-ms 10)
    (append-bytes append-path append-extra)
    (receive (after 5000 (fail "append-during-read timeout"))
      (`#(file-read ,bv)
        (unless (= (bytevector-length bv) (bytevector-length append-base))
          (fail "append-during-read length changed"))
        (unless (equal? bv append-base)
          (fail "append-during-read content changed")))
      (`#(file-error ,e)
        (fail "append-during-read unexpectedly failed")))
    (cleanup)
    (display "ALL FILE READ TESTS PASSED\n")
    (exit 0)))
