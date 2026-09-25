#!chezscheme
;;; test/signal-watch.sc -- OS signals delivered to a process as messages.
;;;
;;; Design: archive/igropyr-signal-watch-design.md (revision 4).
;;;
;;; THIS PROCESS MUST SURVIVE EVERY ROW. The default action of SIGHUP, SIGTERM,
;;; SIGUSR1 and SIGUSR2 is to terminate, and libuv puts a signal back to its
;;; default when the LAST watch of it closes. So a keeper process watches
;;; SIGUSR1 and SIGUSR2 for the whole file, and HUP and TERM are sent to this
;;; process only while a row's own watch of them is open. What happens after
;;; the last watch closes is measured in a CHILD (row 8).
;;;
;;; Messages come back through forwarders: each watching process sends
;;; #(got TAG SIG) to the main process, TAG a literal symbol per forwarder, so
;;; the main process can wait for one forwarder by pattern.
;;;
;;; Cleanup is asynchronous (libuv frees a handle in its close callback), so
;;; counts are compared by WAITING UNTIL they reach the expected value, with a
;;; deadline, not after a fixed sleep.
;;;
;;; WHAT THESE ROWS DO NOT SHOW, stated so a green is not read as more:
;;; - row 1 shows a signal reaching a parked owner promptly; it cannot tell a
;;;   loop woken by the signal from one polling every few milliseconds;
;;; - construction races (the owner killed between two construction steps)
;;;   and the guards inside the signal and close callbacks have no row; they
;;;   rest on the design review and the code review;
;;; - that a child started with uv_spawn does not inherit a watch is libuv's
;;;   behaviour (read in its source), not tested here.
;;;
;;; Rows 7c need the injection seams and run under IGROPYR_INJECT=on, as
;;; test/run-all.sh runs this file; without it they print SKIP and why.

(import (chezscheme)
        (igropyr actor) (igropyr tcp)
        (only (igropyr libuv) uv-live-handle-count)
        (only (igropyr platform) platform-os)
        (igropyr inject-control))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define inject-on? (equal? (getenv "IGROPYR_INJECT") "on"))
(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))

;; one directory per run, so two runs cannot read each other's children
(define dir
  (let ((t (current-time)))
    (string-append "/tmp/igropyr-signal-watch-"
                   (number->string (time-second t)) "-" (number->string (time-nanosecond t)))))
(define (sh-quote s) (string-append "'" s "'"))
(system (string-append "rm -rf " (sh-quote dir) " && mkdir -p " (sh-quote dir)))
(define (in-dir f) (string-append dir "/" f))

;; this process's pid, from the shell `system` starts: its parent is us
(define my-pid
  (begin
    (system (string-append "echo $PPID > " (sh-quote (in-dir "pid"))))
    (call-with-input-file (in-dir "pid") read)))
(define (kill-self! name)
  (system (string-append "kill -" name " " (number->string my-pid))))

;; name for kill(1), symbol in messages, this platform's number
(define accepted
  (let ((linux? (eq? platform-os 'linux)))
    (list (list "HUP" 'SIGHUP 1)
          (list "TERM" 'SIGTERM 15)
          (list "USR1" 'SIGUSR1 (if linux? 10 30))
          (list "USR2" 'SIGUSR2 (if linux? 12 31))
          (list "WINCH" 'SIGWINCH 28))))
(define usr1-number (caddr (assoc "USR1" accepted)))

(define (condition-text c)
  (call-with-string-output-port
    (lambda (p)
      (when (message-condition? c) (display (condition-message c) p))
      (when (irritants-condition? c) (write (condition-irritants c) p)))))
(define (contains? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (and (<= (+ i m) n) (or (string=? (substring s i (+ i m)) sub) (loop (+ i 1)))))))
(define (raised thunk) (guard (e (#t e)) (thunk) 'no-raise))
(define (show x) (call-with-string-output-port (lambda (p) (write x p))))

(define (read-file-or f default)
  (if (file-exists? f) (call-with-input-file f read) default))

(define (counts)
  (list (uv-owner-index-count) (uv-live-handle-count)
        (car (signal-watch-counts)) (cdr (signal-watch-counts))))
(define (rows) (car (signal-watch-counts)))

;; poll a predicate every 10 ms until it holds or the deadline passes
(define (wait-until pred ms)
  (let loop ((t 0))
    (cond ((pred) #t)
          ((>= t ms) #f)
          (else (sleep-ms 10) (loop (+ t 10))))))
(define (settles-to? expected) (wait-until (lambda () (equal? (counts) expected)) 3000))

;; rows 8 and 9 run in children. The child's pid and exit status are written
;; to a temporary name and renamed, so a reader never sees a half-written
;; file; the child's own output goes to a log that a failure prints.
(define (run-child name source)
  (let* ((src (in-dir (string-append name ".ss")))
         (pidf (in-dir (string-append name ".pid")))
         (status (in-dir (string-append name ".status")))
         (log (in-dir (string-append name ".log")))
         (pid-tmp (string-append pidf ".tmp"))
         (status-tmp (string-append status ".tmp")))
    (call-with-output-file src (lambda (p) (display source p)) 'replace)
    (system (string-append
              "( " (sh-quote scheme-bin) " --script " (sh-quote src) " > " (sh-quote log) " 2>&1 & "
              "echo $! > " (sh-quote pid-tmp) " && mv " (sh-quote pid-tmp) " " (sh-quote pidf) "; "
              "wait $!; echo $? > " (sh-quote status-tmp) " && mv " (sh-quote status-tmp) " " (sh-quote status)
              " ) >/dev/null 2>&1 &"))
    (values pidf status log)))
(define (wait-for-file f ms) (wait-until (lambda () (file-exists? f)) ms))
(define (kill-child! pidf)
  (when (file-exists? pidf)
    (system (string-append "kill -9 $(cat " (sh-quote pidf) ") 2>/dev/null"))))
(define (print-log log)
  (when (file-exists? log)
    (display "  [child log]\n")
    (system (string-append "tail -20 " (sh-quote log)))))
;; the child writes its own markers through a temporary name too
(define child-write
  (string-append
    "(define (write-file f v)\n"
    "  (call-with-output-file (string-append f \".tmp\") (lambda (p) (write v p)) 'replace)\n"
    "  (rename-file (string-append f \".tmp\") f))\n"))

(start-scheduler
  (lambda ()
    (define main self)

    ;; a process that forwards every signal message as #(got tag sig)
    (define (forwarder tag)
      (spawn (lambda ()
               (let loop ()
                 (receive
                   (`#(signal ,s) (send main (vector 'got tag s)) (loop))
                   (`#(stop) (void)))))))

    (define baseline0 (counts))
    ;; THE KEEPER: holds SIGUSR1 and SIGUSR2 open for the whole file
    (define keeper (spawn (lambda () (let loop () (receive (_ (loop)))))))
    (define keeper-usr1 (signal-watch! 'SIGUSR1 keeper))
    (define keeper-usr2 (signal-watch! 'SIGUSR2 keeper))

    (check "setup: the keeper's two watches exist" (and keeper-usr1 keeper-usr2 #t))
    (sleep-ms 50)
    (let ((baseline (counts)))

    ;; ---- 1. a signal reaches a parked owner -------------------------------------
    ;; An external shell sends USR1 300 ms from now; the owner is a forwarder
    ;; parked in receive. let* so the clock is read AFTER the receive returns.
    (let* ((a (forwarder 'a))
           (w (signal-watch! 'SIGUSR1 a))
           (t0 (real-time)))
      (system (string-append "(sleep 0.3; kill -USR1 " (number->string my-pid)
                             ") >/dev/null 2>&1 &"))
      (let* ((got (receive (after 5000 'timeout) (`#(got a ,s) s)))
             (ms (- (real-time) t0)))
        (check "1 a watched USR1 arrives as #(signal SIGUSR1)" (eq? got 'SIGUSR1) got)
        (check "1 it arrived after the kill (>= 250 ms), not before" (>= ms 250) ms)
        (check "1 and well before the 5 s deadline" (< ms 2000) ms)
        (display "  [info] kill scheduled at +300 ms, message after ") (display ms) (display " ms\n"))
      (signal-unwatch! w)
      (send a '#(stop)))
    (check "1 counts settle back to baseline" (settles-to? baseline) (counts) baseline)

    ;; ---- 2. every accepted signal, by symbol and by number --------------------------
    ;; HUP and TERM terminate by default, so each is sent only while this row's
    ;; own watch of it is open.
    (for-each
      (lambda (entry)
        (let ((name (car entry)) (sym (cadr entry)) (num (caddr entry)))
          (for-each
            (lambda (given)
              (let* ((x (forwarder 'x))
                     (w (signal-watch! given x)))
                (kill-self! name)
                (let ((got (receive (after 3000 'timeout) (`#(got x ,s) s))))
                  (check (string-append "2 " name " watched as "
                                        (if (symbol? given) "symbol" "number")
                                        ": the message carries '" (symbol->string sym))
                         (eq? got sym) got))
                (signal-unwatch! w)
                (send x '#(stop))
                (settles-to? baseline)))
            (list sym num))))
      accepted)
    (check "2 counts settle back to baseline" (settles-to? baseline) (counts) baseline)

    ;; ---- 3. two owners -------------------------------------------------------------
    (let* ((c (forwarder 'c)) (d (forwarder 'd))
           (wc (signal-watch! 'SIGUSR1 c)) (wd (signal-watch! 'SIGUSR1 d)))
      (kill-self! "USR1")
      (let* ((gc (receive (after 3000 'timeout) (`#(got c ,s) s)))
             (gd (receive (after 3000 'timeout) (`#(got d ,s) s))))
        (check "3 two owners watching USR1 both receive it" (and (eq? gc 'SIGUSR1) (eq? gd 'SIGUSR1)) gc gd))

      ;; ---- 4. one of them unwatches -----------------------------------------------
      (let ((rows-before (rows)))
        (check "4 unwatch answers #t the first time" (eq? (signal-unwatch! wc) #t))
        ;; THE ROW STAYS UNTIL THE CLOSE CALLBACK: nothing has yielded since
        ;; the unwatch, so a row removed here was removed synchronously
        (check "4 right after unwatch the row is still there (only the close callback removes it)"
               (eqv? (rows) rows-before) (rows) rows-before)
        (check "4 and #f the second time" (eq? (signal-unwatch! wc) #f))
        ;; sent while c's watch is closing, before any cleanup has run
        (kill-self! "USR1")
        (let* ((gd (receive (after 3000 'timeout) (`#(got d ,s) s)))
               (gc (receive (after 500 'none) (`#(got c ,s) s))))
          (check "4 the remaining watch still receives" (eq? gd 'SIGUSR1) gd)
          (check "4 the closing watch delivers nothing" (eq? gc 'none) gc)
          (check "4 and its forwarder is alive, so that silence is a reading" (process-alive? c))))
      (signal-unwatch! wd)
      (send c '#(stop)) (send d '#(stop)))

    ;; ---- 3, one owner with two watches ----------------------------------------------
    (let* ((m (forwarder 'm))
           (w1 (signal-watch! 'SIGUSR1 m))
           (w2 (signal-watch! 'SIGUSR1 m)))
      (kill-self! "USR1")
      (let* ((g1 (receive (after 3000 'timeout) (`#(got m ,s) s)))
             (g2 (receive (after 3000 'timeout) (`#(got m ,s) s))))
        (check "3 one owner with two watches of USR1 gets a message from each"
               (and (eq? g1 'SIGUSR1) (eq? g2 'SIGUSR1)) g1 g2))
      (signal-unwatch! w1) (signal-unwatch! w2)
      (send m '#(stop)))
    (check "3/4 counts settle back to baseline" (settles-to? baseline) (counts) baseline)

    ;; ---- 5. owner death closes the watch; other watches keep delivering -----------
    (let* ((e2 (forwarder 'e2))
           (w2 (signal-watch! 'SIGUSR1 e2)))
      (sleep-ms 20)
      (let* ((before (counts))
             (e (forwarder 'e))
             (w (signal-watch! 'SIGUSR1 e)))
        (check "5 one row more while the owner lives" (eqv? (rows) (+ 1 (list-ref before 2))) (rows))
        (kill e 'test)
        (check "5 after the owner is killed, counts settle to what they were before it watched"
               (settles-to? before) (counts) before)
        (check "5 the dead owner's watch is closed: unwatch answers #f" (eq? (signal-unwatch! w) #f))
        (kill-self! "USR1")
        (let ((g (receive (after 3000 'timeout) (`#(got e2 ,s) s))))
          (check "5 the surviving watch still delivers" (eq? g 'SIGUSR1) g)))
      (signal-unwatch! w2)
      (send e2 '#(stop)))
    (check "5 counts settle back to baseline" (settles-to? baseline) (counts) baseline)

    ;; ---- 6. refusals ------------------------------------------------------------------
    ;; Refused before anything is allocated: the counts are compared at once,
    ;; with nothing waited for. A refused signal's error names what is accepted.
    (let ((f (forwarder 'f))
          (dead (spawn (lambda () (void)))))
      (sleep-ms 50)
      (for-each
        (lambda (sig)
          (let* ((before (counts))
                 (c (raised (lambda () (signal-watch! sig f)))))
            (check (string-append "6 refused: " (show sig))
                   (and (condition? c) (who-condition? c) (eq? (condition-who c) 'signal-watch!)
                        (contains? (condition-text c) "SIGHUP"))
                   c)
            (check (string-append "6 nothing allocated for " (show sig))
                   (equal? (counts) before) (counts) before)))
        (list 'SIGINT 'SIGQUIT 'SIGPIPE 'SIGKILL 'SIGSTOP 'SIGSEGV 'SIGBUS 'SIGFPE 'SIGILL
              'SIGCHLD 'SIGALRM 2 3 13 9 0 -1 99 "SIGTERM" 'sigterm 1.5 #f))
      (for-each
        (lambda (owner label)
          (let ((c (raised (lambda () (signal-watch! 'SIGUSR1 owner)))))
            (check (string-append "6 refused: an owner that " label)
                   (and (condition? c) (who-condition? c) (eq? (condition-who c) 'signal-watch!)) c)))
        (list 'nobody dead) (list "is not a process" "has exited"))
      (check "6 after every refusal, counts are at baseline" (equal? (counts) baseline) (counts) baseline)
      (send f '#(stop)))

    ;; ---- 7b. repeated watch/unwatch by a LIVE owner, each cycle checked -----------
    ;; Owner death drops the owner's whole index entry before any arm runs, so
    ;; only a live owner can show a watch that closes without unindexing.
    (let ((g (forwarder 'g)))
      (do ((i 0 (+ i 1))) ((= i 5))
        (let ((w (signal-watch! 'SIGUSR2 g)))
          (check (string-append "7b cycle " (number->string i) ": the watch adds a row and storage")
                 (and (eqv? (rows) (+ 1 (list-ref baseline 2)))
                      (eqv? (cdr (signal-watch-counts)) (+ 1 (list-ref baseline 3))))
                 (counts))
          (signal-unwatch! w)
          (check (string-append "7b cycle " (number->string i) ": after unwatch, counts settle to baseline")
                 (settles-to? baseline) (counts) baseline)))
      (send g '#(stop)))

    ;; ---- 7c. every rollback state, each reached for certain ------------------------
    ;; The four rows share one baseline, so a mutant that leaks at one state can
    ;; also redden the rows after it; the first red row is the one that names it.
    (if (not inject-on?)
        (display "  SKIP 7c rollback rows: need the injection seams; run under IGROPYR_INJECT=on (test/run-all.sh does)\n")
        (let ((h (forwarder 'h)))
          (for-each
            (lambda (spec)
              (let ((point (car spec)) (kind (cadr spec)) (label (symbol->string (car spec))))
                (inject-disarm!)
                (if (eq? kind 'fault)
                    (inject-arm-fault! point)
                    (inject-arm-return! point -22))
                ;; hits and delivered belong to the CURRENT arming and are
                ;; gone once it is disarmed, so they are read before that
                (let* ((c (raised (lambda () (signal-watch! 'SIGUSR1 h))))
                       (hits (inject-hits point))
                       (delivered (inject-delivered point)))
                  (inject-disarm!)
                  (check (string-append "7c " label ": the call raised") (not (eq? c 'no-raise)))
                  (check (string-append "7c " label ": its seam fired exactly once") (eqv? hits 1) hits)
                  (if (eq? kind 'fault)
                      (check (string-append "7c " label ": the raise is the injected fault")
                             (and (condition? c) (who-condition? c) (eq? (condition-who c) 'inject-fault!)
                                  (irritants-condition? c) (memq point (condition-irritants c)) #t)
                             c)
                      (begin
                        (check (string-append "7c " label ": the injected value was returned exactly once")
                               (eqv? delivered 1) delivered)
                        (check (string-append "7c " label ": the raise is signal-watch!'s own, for that failure")
                               (and (condition? c) (who-condition? c) (eq? (condition-who c) 'signal-watch!))
                               c)))
                  (check (string-append "7c " label ": index, handles, rows and storage settle to baseline")
                         (settles-to? baseline) (counts) baseline))))
            '((signal-init-neg return) (signal-row fault) (signal-publish fault) (signal-start-neg return)))
          (send h '#(stop))))

    ;; ---- 7d. a stale token against a reused address --------------------------------
    (let* ((i (forwarder 'i))
           (w1 (signal-watch! 'SIGUSR1 i))
           (h1 (signal-watch-handle w1)))
      (signal-unwatch! w1)
      (settles-to? baseline)
      (let loop ((k 0))
        (let ((w (signal-watch! 'SIGUSR1 i)))
          (cond
            ((eqv? (signal-watch-handle w) h1)
             (check "7d setup: a new watch reused the old watch's address" #t)
             (check "7d the stale token answers #f" (eq? (signal-unwatch! w1) #f))
             (kill-self! "USR1")
             (let ((got (receive (after 3000 'timeout) (`#(got i ,s) s))))
               (check "7d the new watch at that address still delivers" (eq? got 'SIGUSR1) got))
             (signal-unwatch! w))
            ((< k 20)
             (signal-unwatch! w) (settles-to? baseline) (loop (+ k 1)))
            (else
             (signal-unwatch! w)
             (check "7d PRECONDITION NOT REACHED: no address reuse in 20 tries; the row cannot run" #f)))))
      (send i '#(stop)))
    (check "7d counts settle back to baseline" (settles-to? baseline) (counts) baseline)

    ;; ---- 7f. a message already in the mailbox survives the unwatch -----------------
    (let* ((holder (spawn (lambda ()
                            (receive (`#(report) (void)))
                            (send main (vector 'held (receive (after 500 'none) (`#(signal ,s) s)))))))
           (w (signal-watch! 'SIGUSR1 holder)))
      (kill-self! "USR1")
      (sleep-ms 300)
      (signal-unwatch! w)
      (settles-to? baseline)
      (send holder '#(report))
      (let ((held (receive (after 3000 'timeout) (`#(held ,s) s))))
        (check "7f a signal message delivered before unwatch is still in the owner's mailbox after it"
               (eq? held 'SIGUSR1) held)))

    ;; ---- 8. after the last watch closes, the signal has its DEFAULT action ----------
    ;; Measured in a child that first gave USR1 a known non-default handler, so
    ;; "reset to default" and "restore what was there" read differently.
    (let-values (((pidf status log)
                  (run-child "c8"
                    (string-append
                      "(import (chezscheme) (igropyr actor) (igropyr tcp))\n"
                      child-write
                      "(define flag #f)\n"
                      "(register-signal-handler " (number->string usr1-number) " (lambda (n) (set! flag #t)))\n"
                      "(start-scheduler (lambda ()\n"
                      "  (system \"kill -USR1 $PPID\")\n"
                      "  (let loop ((i 0)) (unless (or flag (> i 100)) (sleep-ms 10) (loop (+ i 1))))\n"
                      "  (write-file \"" (in-dir "c8.handled") "\" flag)\n"
                      "  (let ((w (signal-watch! 'SIGUSR1))) (sleep-ms 50) (signal-unwatch! w) (sleep-ms 200))\n"
                      "  (write-file \"" (in-dir "c8.ready") "\" 1)\n"
                      "  (sleep-ms 10000)\n"
                      "  (exit 0)))\n"))))
      (let ((ready (wait-for-file (in-dir "c8.ready") 20000)))
        (check "8 setup: the child is ready" ready)
        (check "8 setup: the child's own USR1 handler ran and it survived"
               (eq? (read-file-or (in-dir "c8.handled") 'missing) #t) (read-file-or (in-dir "c8.handled") 'missing))
        (when ready (system (string-append "kill -USR1 $(cat " (sh-quote pidf) ")")))
        (let ((done (wait-for-file status 15000)))
          (check "8 setup: the child's exit status was recorded" done)
          (unless done (kill-child! pidf))
          (let ((st (read-file-or status 'missing)))
            (check "8 after the last unwatch, USR1 terminates the child (status 128+USR1)"
                   (eqv? st (+ 128 usr1-number)) st)
            (unless (eqv? st (+ 128 usr1-number)) (print-log log))))))

    ;; ---- 9. TERM end to end: the child handles TERM as a message and exits 0 --------
    (let-values (((pidf status log)
                  (run-child "c9"
                    (string-append
                      "(import (chezscheme) (igropyr actor) (igropyr tcp))\n"
                      child-write
                      "(start-scheduler (lambda ()\n"
                      "  (signal-watch! 'SIGTERM)\n"
                      "  (write-file \"" (in-dir "c9.ready") "\" 1)\n"
                      "  (receive\n"
                      "    (after 20000 (exit 3))\n"
                      "    (`#(signal SIGTERM)\n"
                      "      (write-file \"" (in-dir "c9.marker") "\" 'term)\n"
                      "      (exit 0)))))\n"))))
      (let ((ready (wait-for-file (in-dir "c9.ready") 20000)))
        (check "9 setup: the child's watch is installed" ready)
        (when ready (system (string-append "kill -TERM $(cat " (sh-quote pidf) ")")))
        (let ((done (wait-for-file status 25000)))
          (check "9 setup: the child's exit status was recorded" done)
          (unless done (kill-child! pidf))
          (check "9 the child exited 0, not by the signal" (eqv? (read-file-or status 'missing) 0)
                 (read-file-or status 'missing))
          (check "9 and it wrote its marker from the message handler"
                 (eq? (read-file-or (in-dir "c9.marker") 'missing) 'term))
          (unless (eqv? (read-file-or status 'missing) 0) (print-log log)))))

    ;; ---- 10. SIGPIPE is still ignored in this process ---------------------------------
    ;; The refusal in row 6 exists to protect this. A write to a pipe whose
    ;; reader has closed returns -1 with errno EPIPE when SIGPIPE is ignored;
    ;; with the default action this process would die here instead. (A blocked
    ;; SIGPIPE or a handler that returns would read the same; what is protected
    ;; is that the process survives.)
    (load-shared-object
      (case platform-os
        ((macos) "/usr/lib/libSystem.B.dylib")
        ((freebsd) "libc.so.7")
        (else "libc.so.6")))
    (let ((c-pipe (foreign-procedure "pipe" (u8*) int))
          (c-close (foreign-procedure "close" (int) int))
          (c-write (foreign-procedure "write" (int u8* size_t) ssize_t))
          (c-errno (foreign-procedure (if (eq? platform-os 'linux) "__errno_location" "__error") () void*))
          (fds (make-bytevector 8 0)))
      (check "10 setup: pipe() succeeded" (eqv? (c-pipe fds) 0))
      (let ((rd (bytevector-s32-native-ref fds 0)) (wr (bytevector-s32-native-ref fds 4)))
        (c-close rd)
        (let* ((r (c-write wr (make-bytevector 1 65) 1))
               (errno (foreign-ref 'int (c-errno) 0)))
          (c-close wr)
          (check "10 a write with no reader returned -1 with EPIPE, and this process is still here"
                 (and (eqv? r -1) (eqv? errno 32)) r errno))))

    ;; ---- 12. before the scheduler runs, nothing could receive: refused --------------
    ;; A child initialises the loop but never starts the scheduler. With no
    ;; actor layer there is no process to deliver to and no owner death to
    ;; close the watch, and an accepted SIGTERM watch would stop TERM from
    ;; terminating the process. Both forms are refused and nothing is kept.
    (let-values (((pidf status log)
                  (run-child "c12"
                    (string-append
                      "(import (chezscheme) (igropyr libuv) (igropyr tcp))\n"
                      child-write
                      "(define (try thunk)\n"
                      "  (guard (e (#t (if (and (condition? e) (who-condition? e) (eq? (condition-who e) 'signal-watch!))\n"
                      "                    'refused\n"
                      "                    (list 'raised-elsewhere (and (condition? e) (who-condition? e) (condition-who e))))))\n"
                      "    (thunk) 'accepted))\n"
                      "(uv-init!)\n"
                      "(write-file \"" (in-dir "c12.result") "\"\n"
                      "  (list (try (lambda () (signal-watch! 'SIGTERM 'nobody)))\n"
                      "        (try (lambda () (signal-watch! 'SIGTERM)))\n"
                      "        (signal-watch-counts)))\n"
                      "(exit 0)\n"))))
      (let ((done (wait-for-file status 20000)))
        (check "12 setup: the child ran to the end" (and done (eqv? (read-file-or status 'missing) 0))
               (read-file-or status 'missing))
        (unless done (kill-child! pidf))
        (let ((r (read-file-or (in-dir "c12.result") 'missing)))
          (check "12 before the scheduler starts, signal-watch! with an owner is refused"
                 (and (pair? r) (eq? (car r) 'refused)) r)
          (check "12 and without one"
                 (and (pair? r) (eq? (cadr r) 'refused)) r)
          (check "12 and no row or storage was kept"
                 (and (pair? r) (equal? (caddr r) '(0 . 0))) r)
          (unless (and (pair? r) (eq? (car r) 'refused) (eq? (cadr r) 'refused)) (print-log log)))))

    ;; ---- 11. the keeper's watches close too ----------------------------------------
    (signal-unwatch! keeper-usr1)
    (signal-unwatch! keeper-usr2)
    (check "11 with the keeper's watches closed, counts settle to what they were before any watch"
           (settles-to? baseline0) (counts) baseline0)

    (if (zero? failures)
        (begin (display "signal-watch: all tests passed\n") (exit 0))
        (begin (display "signal-watch: ") (display failures) (display " failed\n") (exit 1))))))
