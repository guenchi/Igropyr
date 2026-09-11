#!chezscheme
;; A PANIC is the framework's last word and it went on the current output
;; port: an application keeping stdout for a protocol had "PANIC: ..." injected
;; into that stream as it died. It goes on the console error port, flushed,
;; exit status 70 unchanged. The stimulus is the tree's own boot-failure smoke
;; script; stdout and stderr are captured separately.
(import (chezscheme))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define scheme-bin (or (getenv "SCHEME_BIN") "chez"))
(define dir "/tmp/igropyr-panic-stderr")
(system (string-append "rm -rf " dir " && mkdir -p " dir))
(define tree (let ((d (getenv "IGROPYR_TREE"))) (or d ".")))
(define (slurp f)
  (if (file-exists? f)
      (let ((s (call-with-input-file f get-string-all))) (if (eof-object? s) "" s))
      "MISSING-CAPTURE"))
(define (exit-code r) (if (and (integer? r) (>= r 256)) (quotient r 256) r))
(define out (string-append dir "/out.txt"))
(define err (string-append dir "/err.txt"))
(define (contains? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0)) (and (<= (+ i m) n) (or (string=? (substring s i (+ i m)) sub) (loop (+ i 1)))))))
(define (starts? s pre) (and (>= (string-length s) (string-length pre)) (string=? (substring s 0 (string-length pre)) pre)))

(let ((r (exit-code (system (string-append "cd " tree " && IGROPYR_CONTRACTS=full CHEZSCHEMELIBDIRS=. CHEZSCHEMELIBEXTS='.sc::.no-obj' timeout 30 "
                                           scheme-bin " --script test/smoke-boot-failure.sc > " out " 2> " err)))))
  (check "the boot failure still exits 70" (eqv? r 70) r (slurp err))
  (check "stdout is empty: the PANIC line is not in the application's output stream" (equal? (slurp out) "") (slurp out))
  (check "stderr starts with the PANIC line" (starts? (slurp err) "PANIC: boot ") (slurp err))
  (check "the reason is still printed with it" (contains? (slurp err) "deliberate boot failure") (slurp err))
  (check "and it was flushed before exit (the capture is not empty after a hard exit)" (> (string-length (slurp err)) 0) (slurp err)))

;; the port itself may be broken: a panic whose console port raises must still
;; exit 70 instead of turning the death into an ordinary exception that leaves
;; the process alive
(let ((f (string-append dir "/bad-port.sc")))
  (call-with-output-file f
    (lambda (o) (display "(import (chezscheme) (igropyr actor))\n(let ((p (open-output-string))) (close-port p) (console-error-port p))\n(start-scheduler (lambda () (error 'boot-test \"deliberate boot failure\")))\n" o)) 'truncate)
  (let ((r (exit-code (system (string-append "cd " tree " && IGROPYR_CONTRACTS=full CHEZSCHEMELIBDIRS=. CHEZSCHEMELIBEXTS='.sc::.no-obj' timeout 30 "
                                             scheme-bin " --script " f " > " out " 2> " err)))))
    (check "a console port that raises on write: the panic still exits 70" (eqv? r 70) r (slurp err))
    (check "...and stdout stays empty" (equal? (slurp out) "") (slurp out))))

(if (zero? fails)
    (begin (display "ALL PANIC-STDERR TESTS PASSED\n") (exit 0))
    (begin (display "PANIC-STDERR VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
