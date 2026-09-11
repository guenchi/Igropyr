#!chezscheme
;; The framework does not own the application's stdout. app-listen printed a
;; contracts line and http-listen its "listening on" line with plain display,
;; i.e. on the current output port: an application that keeps stdout for a
;; protocol or a pipe got two framework lines injected into it at start-up.
;; Both go through the http-notice hook, which defaults to the console error
;; port and which an application can replace. A child chez listens on a free
;; port and exits; its stdout and stderr are captured separately.
(import (chezscheme) (only (igropyr libuv) now-ms))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define scheme-bin (or (getenv "SCHEME_BIN") "chez"))
(define dir "/tmp/igropyr-listen-stdout")
(system (string-append "rm -rf " dir " && mkdir -p " dir))
(define tree (let ((d (getenv "IGROPYR_TREE"))) (or d ".")))
(define (slurp f) (guard (e (#t "")) (let ((s (call-with-input-file f get-string-all))) (if (eof-object? s) "" s))))
(define (exit-code r) (if (and (integer? r) (>= r 256)) (quotient r 256) r))
;; the child: listen on port 0 (kernel-assigned), then leave the scheduler
(define (run-child! prelude)
  (let ((f (string-append dir "/child.sc")))
    (call-with-output-file f
      (lambda (o)
        (display (string-append
                  "(import (chezscheme) (igropyr node) (igropyr express) (igropyr http))\n"
                  prelude "\n"
                  "(define app (create-app))\n"
                  "(start-scheduler (lambda () (app-listen app 0) (exit 0)))\n") o))
      'truncate)
    (exit-code (system (string-append "cd " tree " && IGROPYR_CONTRACTS=full CHEZSCHEMELIBDIRS=. CHEZSCHEMELIBEXTS='.sc::.no-obj' timeout 20 "
                                      scheme-bin " --script " f " > " dir "/out.txt 2> " dir "/err.txt")))))
(define (contains? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0)) (and (<= (+ i m) n) (or (string=? (substring s i (+ i m)) sub) (loop (+ i 1)))))))

(let ((r (run-child! "")))
  (check "the child listened and exited on its own" (eqv? r 0) r (slurp (string-append dir "/err.txt")))
  (check "stdout is empty: the framework wrote nothing on the application's output port" (equal? (slurp (string-append dir "/out.txt")) "") (slurp (string-append dir "/out.txt")))
  (check "stderr carries the listening line" (contains? (slurp (string-append dir "/err.txt")) "igropyr listening on") (slurp (string-append dir "/err.txt")))
  (check "the contracts line is gone (it reported the framework's own compile mode, a constant)" (not (contains? (slurp (string-append dir "/err.txt")) "igropyr contracts")) (slurp (string-append dir "/err.txt"))))
;; twin: the hook replaced by the application -> silence on both ports
(let ((r (run-child! "(http-notice (lambda (s) #f))")))
  (check "twin: with the hook replaced the child still listens and exits" (eqv? r 0) r (slurp (string-append dir "/err.txt")))
  (check "twin: stdout empty" (equal? (slurp (string-append dir "/out.txt")) "") (slurp (string-append dir "/out.txt")))
  (check "twin: stderr empty too (the line went to the hook)" (equal? (slurp (string-append dir "/err.txt")) "") (slurp (string-append dir "/err.txt"))))
;; twin: the hook receives the line as a string, once
(let ((r (run-child! "(define seen 0) (http-notice (lambda (s) (set! seen (+ seen 1)) (display (string-append \"[app] \" s) (current-output-port))))")))
  (check "twin: the application's own hook may put the line wherever it likes, stdout included" (contains? (slurp (string-append dir "/out.txt")) "[app] igropyr listening on") (slurp (string-append dir "/out.txt")))
  (check "twin: nothing on stderr then" (equal? (slurp (string-append dir "/err.txt")) "") (slurp (string-append dir "/err.txt"))))

(if (zero? fails)
    (begin (display "ALL LISTEN-STDOUT TESTS PASSED\n") (exit 0))
    (begin (display "LISTEN-STDOUT VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
