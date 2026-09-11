#!chezscheme
;; The framework does not own the application's stdout. app-listen printed a
;; contracts line and http-listen its "listening on" line with plain display,
;; i.e. on the current output port: an application that keeps stdout for a
;; protocol or a pipe got two framework lines injected into it at start-up.
;; The listening line goes through the notice hook (set once with http-notice!;
;; a plain setter, not a parameter: the scheduler shares parameter values
;; across green processes, so parameterize could not promise isolation),
;; which defaults to the console error port (flushed) and which an application
;; can replace; the contracts line is removed. Announcing is not part of
;; listening: a hook that raises does not lose the listener. A child chez listens on a free port and exits;
;; its stdout and stderr are captured separately. The child copies its own
;; stderr capture while it is still alive (before exit could flush anything),
;; so the flush is observed and not assumed.
(import (chezscheme))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define scheme-bin (or (getenv "SCHEME_BIN") "chez"))
(define dir "/tmp/igropyr-listen-stdout")
(system (string-append "rm -rf " dir " && mkdir -p " dir))
(define tree (let ((d (getenv "IGROPYR_TREE"))) (or d ".")))
;; a missing capture is a failure of the fixture, never silence
(define (slurp f)
  (if (file-exists? f)
      (let ((s (call-with-input-file f get-string-all))) (if (eof-object? s) "" s))
      "MISSING-CAPTURE"))
(define (exit-code r) (if (and (integer? r) (>= r 256)) (quotient r 256) r))
(define out (string-append dir "/out.txt"))
(define err (string-append dir "/err.txt"))
(define live (string-append dir "/err-live.txt"))
;; the child: prelude, then `body` runs inside the scheduler with `app` bound,
;; then it copies its stderr capture (still alive) and exits 0
(define (run-child! prelude body)
  (let ((f (string-append dir "/child.sc")))
    (call-with-output-file f
      (lambda (o)
        (display (string-append
                  "(import (chezscheme) (igropyr node) (igropyr express) (igropyr http))\n"
                  prelude "\n"
                  "(define app (create-app))\n"
                  "(start-scheduler (lambda () " body
                  " (system \"cp " err " " live "\") (exit 0)))\n") o))
      'truncate)
    (system (string-append "rm -f " out " " err " " live))
    (exit-code (system (string-append "cd " tree " && IGROPYR_CONTRACTS=full CHEZSCHEMELIBDIRS=. CHEZSCHEMELIBEXTS='.sc::.no-obj' timeout 20 "
                                      scheme-bin " --script " f " > " out " 2> " err)))))
(define (contains? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0)) (and (<= (+ i m) n) (or (string=? (substring s i (+ i m)) sub) (loop (+ i 1)))))))
;; the whole line, pinned: only the effective backlog varies by kernel
(define (listening-line? s)
  (let ((pre "igropyr listening on http://0.0.0.0:0 backlog 8192 (effective "))
    (and (> (string-length s) (string-length pre))
         (string=? (substring s 0 (string-length pre)) pre)
         (let* ((rest (substring s (string-length pre) (string-length s)))
                (n (string-length rest)))
           (and (>= n 2)
                (string=? (substring rest (- n 2) n) ")\n")
                (let ((mid (substring rest 0 (- n 2))))
                  (or (string=? mid "unavailable")
                      (and (> (string-length mid) 0)
                           (let lp ((i 0)) (or (= i (string-length mid)) (and (char<=? #\0 (string-ref mid i) #\9) (lp (+ i 1)))))))))))))

;; ---- the default hook -----------------------------------------------------------
(let ((r (run-child! "" "(app-listen app 0)")))
  (check "the child listened and exited on its own" (eqv? r 0) r (slurp err))
  (check "stdout is empty: the framework wrote nothing on the application's output port" (equal? (slurp out) "") (slurp out))
  (check "stderr is exactly the listening line, content unchanged, once" (listening-line? (slurp err)) (slurp err))
  (check "the line was flushed: the child saw it in its stderr capture while still alive" (listening-line? (slurp live)) (slurp live))
  (check "the contracts line is gone from both ports (it reported a constant)"
         (and (not (contains? (slurp out) "igropyr contracts")) (not (contains? (slurp err) "igropyr contracts"))) (slurp out) (slurp err)))
;; the default writes on the CONSOLE error port, not on whatever the current
;; error port is at call time: with current-error-port rebound to a string
;; port, that port stays empty and process stderr still gets the line
(let ((r (run-child! "(define sp (open-output-string))"
                     "(parameterize ((current-error-port sp)) (app-listen app 0)) (when (> (string-length (get-output-string sp)) 0) (display \"LEAKED-TO-CURRENT-ERROR-PORT\" (console-error-port)))")))
  (check "console error port: the child listened" (eqv? r 0) r (slurp err))
  (check "console error port: the line is on process stderr and the rebound current-error-port stayed empty" (listening-line? (slurp err)) (slurp err)))
;; ---- twin: the hook replaced -> silence on both ports ------------------------------
(let ((r (run-child! "(http-notice! (lambda (s) #f))" "(app-listen app 0)")))
  (check "twin: with the hook replaced the child still listens and exits" (eqv? r 0) r (slurp err))
  (check "twin: stdout empty" (equal? (slurp out) "") (slurp out))
  (check "twin: stderr empty too (the line went to the hook)" (equal? (slurp err) "") (slurp err)))
;; ---- twin: the application's hook decides, and is called once with the line ---------
(let ((r (run-child! "(define seen 0) (http-notice! (lambda (s) (set! seen (+ seen 1)) (display (string-append \"[app] \" s) (current-output-port))))"
                     "(app-listen app 0) (display (string-append \"seen=\" (number->string seen) \"\\n\") (current-output-port))")))
  (check "twin: the child listened and exited" (eqv? r 0) r (slurp err))
  (check "twin: the hook put the unchanged line on stdout and was called exactly once"
         (let ((o (slurp out)))
           (and (> (string-length o) 6) (string=? (substring o 0 6) "[app] ")
                (let* ((rest (substring o 6 (string-length o)))
                       (k (let lp ((i 0)) (cond ((= i (string-length rest)) #f) ((char=? (string-ref rest i) #\newline) i) (else (lp (+ i 1)))))))
                  (and k (listening-line? (substring rest 0 (+ k 1)))
                       (string=? (substring rest (+ k 1) (string-length rest)) "seen=1\n")))))
         (slurp out))
  (check "twin: nothing on stderr then" (equal? (slurp err) "") (slurp err)))
;; ---- the setter: last one wins, a non-procedure is refused, a raising hook
;; does not lose the listener ------------------------------------------------------
(let ((r (run-child! "(http-notice! (lambda (s) (display \"first\" (console-error-port)))) (http-notice! (lambda (s) (display \"second\" (console-error-port))))"
                     "(app-listen app 0)")))
  (check "setter: the last hook set is the one called" (equal? (slurp err) "second") r (slurp err)))
;; the refusal must be the setter's own (who = http-notice!), and the setter
;; must still accept a procedure afterwards: an unbound name would also raise
(let ((r (run-child! "(define refused (guard (e (#t (if (and (assertion-violation? e) (who-condition? e) (eq? (condition-who e) 'http-notice!)) \"refused\" \"other\"))) (http-notice! 42) \"accepted\")) (http-notice! (lambda (s) #f)) (display refused (console-error-port))"
                     "(app-listen app 0)")))
  (check "setter: a non-procedure is refused by the setter itself, a procedure is then accepted" (and (eqv? r 0) (equal? (slurp err) "refused")) r (slurp err)))
(let ((r (run-child! "(http-notice! (lambda (s) (error 'hook \"the application's hook raised\")))"
                     "(let ((srv (app-listen app 0))) (display (if (http-server? srv) \"server-returned\n\" \"no-server\n\") (console-error-port)))")))
  (check "a hook that raises: app-listen still returns the server (announcing is not part of listening)" (equal? (slurp err) "server-returned\n") r (slurp err))
  (check "a hook that raises: nothing on stdout either" (equal? (slurp out) "") (slurp out)))
;; ---- a terminal: nothing kept back for the TTY case ---------------------------------
;; `script` gives the child a pty on both platforms (macOS: script -q file cmd;
;; FreeBSD: same). A line printed only when stdout is a terminal would hide from
;; every redirected run above and show here
(let* ((f (string-append dir "/child.sc"))
       (ty (string-append dir "/tty.txt")))
  (call-with-output-file f
    (lambda (o) (display "(import (chezscheme) (igropyr node) (igropyr express) (igropyr http))\n(define app (create-app))\n(start-scheduler (lambda () (app-listen app 0) (exit 0)))\n" o)) 'truncate)
  (let ((r (exit-code (system (string-append "cd " tree " && IGROPYR_CONTRACTS=full CHEZSCHEMELIBDIRS=. CHEZSCHEMELIBEXTS='.sc::.no-obj' timeout 20 script -q " ty " " scheme-bin " --script " f " < /dev/null > /dev/null 2>&1")))))
    (if (and (eqv? r 0) (file-exists? ty))
        (check "tty: no contracts line even when stdout is a terminal" (not (contains? (slurp ty) "igropyr contracts")) (slurp ty))
        (begin (display "  skip  tty case: `script -q <file> <cmd>` did not run here (rc ") (display r) (display "); install/adjust script(1) to run it\n")))))

(if (zero? fails)
    (begin (display "ALL LISTEN-STDOUT TESTS PASSED\n") (exit 0))
    (begin (display "LISTEN-STDOUT VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
