#!chezscheme
;; Child processes -- lifecycle cells (proc-spawn design v3 §5, v4-v8 deltas;
;; codex coverage pre-review 01a08dfe folded).
;;   P4a  SIGTERM on sleep -> exit (0 . 15)
;;   P4b  a child that ignores TERM after exec: TERM does nothing, KILL -> signal 9
;;   P5   spawn failure (ENOENT): synchronous (failed . ...), every count back
;;   P8   stdout/stderr tagged separately; 'inherit (our stdout redirected to a file
;;        around the spawn, the file is the oracle) and 'ignore
;;   P9   100 children admitted at once (gated on stdin) under max-procs 128; P9b the limit
;;   P10  coexistence with Chez `system`: libc's wait does not reap our child, and system's
;;        own child still has our stdout (file oracle)
;;   P11  env and cwd exact
;;   P13  stdout EOF while the child is held on stdin, then stderr data, then the exit
;;   P14  proc-close! before and after exit is idempotent and leaves kill eligible
;;   P16  a dead explicit owner is refused before anything is allocated
;;   P17  (this whole file runs without TLS: the liveness hook comes from actor)
;;   P22  socket-conn-count sampled during pipe churn with two real sockets open:
;;        never below 2, never above conn-count; the spawner outlives the baseline check
;;   P23  pipe conns cannot change owner or replace their close hook
;; Every cell ends with the five counts back to their cell-start values while
;; the owner (this process) is alive.
(import (chezscheme) (igropyr actor) (igropyr tcp)
        (only (igropyr libuv) now-ms uv-live-handle-count uv-strerror)
        (igropyr inject-control))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define (spawn-sh cmd . opts) (apply proc-spawn! "/bin/sh" (list "sh" "-c" cmd) opts))
(define (failed? r) (and (pair? r) (eq? (car r) 'failed)))
(define (wait-exit p ms) (receive (after ms 'timeout) (`#(proc-exit ,@p ,code ,signal) (cons code signal))))
(define (cat bvs)
  (let* ((n (apply + (map bytevector-length bvs))) (out (make-bytevector n)))
    (let loop ((bvs bvs) (o 0))
      (unless (null? bvs)
        (bytevector-copy! (car bvs) 0 out o (bytevector-length (car bvs)))
        (loop (cdr bvs) (+ o (bytevector-length (car bvs))))))
    out))
;; one stream to EOF -> bytevector, or (partial . bytevector) on timeout
(define (collect p stream ms)
  (let ((deadline (+ (now-ms) ms)))
    (let loop ((acc '()))
      (receive (after (max 1 (- deadline (now-ms))) (cons 'partial (cat (reverse acc))))
        (`#(proc-data ,@p ,@stream ,bv) (loop (cons bv acc)))
        (`#(proc-eof ,@p ,@stream) (cat (reverse acc)))))))
(define (text p stream ms) (let ((r (collect p stream ms))) (if (bytevector? r) (utf8->string r) r)))
;; a stream until the accumulated text holds a newline -> the line; reads may split lines
(define (read-line-of p stream ms)
  (let ((deadline (+ (now-ms) ms)))
    (let loop ((acc ""))
      (let ((i (let scan ((k 0)) (cond ((= k (string-length acc)) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1)))))))
        (if i (substring acc 0 i)
            (receive (after (max 1 (- deadline (now-ms))) (cons 'timeout acc))
              (`#(proc-data ,@p ,@stream ,bv) (loop (string-append acc (utf8->string bv))))))))))
(define (base) (list (uv-live-handle-count) (conn-count) (pipe-conn-count) (proc-count) (uv-owner-index-count)))
(define (back-to-base! label b ms) (check label (within? ms (lambda () (equal? (base) b))) (base) b))
(define (quiet! label ms)
  (receive (after ms (check label #t))
    (`#(proc-data ,p ,s ,bv) (check label #f (list 'data s (bytevector-length bv))))
    (`#(proc-eof ,p ,s) (check label #f (list 'eof s)))
    (`#(proc-error ,p ,s ,n) (check label #f (list 'error s n)))
    (`#(proc-exit ,p ,c ,sg) (check label #f (list 'exit c sg)))))
;; our own stdout redirected to a file around a thunk: the file is what an
;; inherited descriptor 1 wrote to (dup/dup2 through libc; O_WRONLY|O_CREAT|O_TRUNC)
(define c-dup (foreign-procedure "dup" (int) int))
(define c-dup2 (foreign-procedure "dup2" (int int) int))
(define c-close (foreign-procedure "close" (int) int))
;; open(2) is variadic, so the mode cannot be passed through a fixed-arity foreign
;; procedure; the file is created by Chez first and opened here without a mode
;; (O_WRONLY|O_TRUNC = #x401)
(define c-open2 (foreign-procedure "open" (string int) int))
(define (with-stdout-to-file f thunk)
  (flush-output-port (current-output-port))
  (call-with-port (open-file-output-port f (file-options no-fail)) (lambda (o) (void)))
  (let* ((saved (c-dup 1)) (fd (c-open2 f #x401)))
    (c-dup2 fd 1) (c-close fd)
    (let ((r (thunk)))
      (flush-output-port (current-output-port))
      (c-dup2 saved 1) (c-close saved)
      r)))
;; get-string-all answers the eof object for an empty file: that is ""
(define (file-text f) (guard (e (#t (list 'unreadable f))) (let ((t (call-with-input-file f get-string-all))) (if (eof-object? t) "" t))))
(define port 18800)

(start-scheduler
  (lambda ()
    (define main self)
    (register 'main self)
    (let ((b0 (base)))

      ;; ---- P4a: SIGTERM ----------------------------------------------------------
      (let ((p (spawn-sh "exec sleep 100")))
        (check "P4a: spawned" (proc? p) p)
        (check "P4a: running" (eq? (proc-state p) 'running) (proc-state p))
        (check "P4a: pid known" (and (proc-pid p) (> (proc-pid p) 0)) (proc-pid p))
        (check "P4a: proc-kill! 15 -> #t" (proc-kill! p 15))
        (check "P4a: exit (0 . 15)" (equal? (wait-exit p 5000) '(0 . 15)))
        (check "P4a: stdout EOF" (equal? (collect p 'stdout 3000) (make-bytevector 0)))
        (check "P4a: stderr EOF" (equal? (collect p 'stderr 3000) (make-bytevector 0)))
        (check "P4a: pid cleared, state not running" (and (not (proc-pid p)) (not (eq? (proc-state p) 'running))) (list (proc-pid p) (proc-state p)))
        (check "P4a: proc-kill! after exit -> #f" (not (proc-kill! p 15)))
        (check "P4a: closed once every pipe reached EOF (stdin closed by the exit)" (within? 3000 (lambda () (eq? (proc-state p) 'closed))) (proc-state p))
        (back-to-base! "P4a: counts back to base" b0 3000))

      ;; ---- P4b: TERM ignored after exec, KILL works --------------------------------
      (let ((p (spawn-sh "trap \"\" TERM; echo ready; exec sleep 100")))
        (check "P4b: spawned" (proc? p) p)
        (check "P4b: the child reported ready" (equal? (read-line-of p 'stdout 3000) "ready"))
        (check "P4b: TERM accepted for sending" (proc-kill! p 15))
        (check "P4b: ...but the child is still running 500 ms later" (and (eq? (wait-exit p 500) 'timeout) (eq? (proc-state p) 'running)) (proc-state p))
        (check "P4b: KILL -> #t" (proc-kill! p 9))
        (check "P4b: exit (0 . 9)" (equal? (wait-exit p 5000) '(0 . 9)))
        (collect p 'stdout 3000) (collect p 'stderr 3000)
        (back-to-base! "P4b: counts back to base" b0 3000))

      ;; ---- P5: ENOENT --------------------------------------------------------------
      (let ((r (proc-spawn! "/nonexistent/igropyr-no-such-binary" '("x"))))
        (check "P5: synchronous failure" (failed? r) r)
        (quiet! "P5: nothing arrives" 300)
        (back-to-base! "P5: counts back after the close callbacks" b0 3000))

      ;; ---- P8: tagged streams, inherit, ignore ---------------------------------------
      (let ((p (spawn-sh "echo out; echo err 1>&2; exit 0")))
        (check "P8: stdout tagged" (equal? (text p 'stdout 3000) "out\n"))
        (check "P8: stderr tagged" (equal? (text p 'stderr 3000) "err\n"))
        (check "P8: exit 0" (equal? (wait-exit p 3000) '(0 . 0)))
        (back-to-base! "P8: counts back" b0 3000))
      (let* ((f "/tmp/igropyr-p8-inherit.txt")
             (p (with-stdout-to-file f
                  (lambda ()
                    (let ((p (spawn-sh "echo inherited-marker" '(stdout . inherit))))
                      (when (proc? p) (wait-exit p 3000))
                      p)))))
        (check "P8 inherit: spawned" (proc? p) p)
        (check "P8 inherit: no stdout conn" (and (proc? p) (not (proc-stdout p))))
        (check "P8 inherit: the child wrote through OUR descriptor 1 (the redirected file holds the marker)" (equal? (file-text f) "inherited-marker\n") (file-text f))
        (when (proc? p) (collect p 'stderr 2000))
        (receive (after 300 (check "P8 inherit: nothing tagged for stdout arrives" #t))
          (`#(proc-data ,q stdout ,bv) (check "P8 inherit: nothing tagged for stdout arrives" #f (bytevector-length bv)))
          (`#(proc-eof ,q stdout) (check "P8 inherit: nothing tagged for stdout arrives" #f 'eof)))
        (back-to-base! "P8 inherit: counts back" b0 3000))
      (let* ((f "/tmp/igropyr-p8-ignore.txt")
             (p (with-stdout-to-file f
                  (lambda ()
                    (let ((p (spawn-sh "echo dropped; exit 4" '(stdout . ignore))))
                      (when (proc? p) (wait-exit p 3000))
                      p)))))
        (check "P8 ignore: no stdout conn" (and (proc? p) (not (proc-stdout p))))
        (check "P8 ignore: the ignored output reached neither a pipe nor our descriptor 1" (equal? (file-text f) "") (file-text f))
        (check "P8 ignore: stderr EOF" (equal? (collect p 'stderr 3000) (make-bytevector 0)))
        (quiet! "P8 ignore: nothing from stdout" 300)
        (receive (after 0 (void)) (`#(proc-exit ,q ,c ,s) (void)))
        (back-to-base! "P8 ignore: counts back" b0 3000))

      ;; ---- P9: 100 concurrent children; P9b: the limit ---------------------------------
      (set-max-procs! 128)
      (let ((ps (let loop ((i 0) (acc '())) (if (= i 100) acc (loop (+ i 1) (cons (spawn-sh "read x; exit 7") acc))))))
        (check "P9: 100 spawned" (for-all proc? ps) (length (filter (lambda (p) (not (proc? p))) ps)))
        (check "P9: proc-count = 100 above base while all are held on stdin" (eqv? (proc-count) (+ (list-ref b0 3) 100)) (proc-count))
        (check "P9: pipe-conn-count = 300 above base" (eqv? (pipe-conn-count) (+ (list-ref b0 2) 300)) (pipe-conn-count))
        (for-each (lambda (p) (proc-write! p (string->utf8 "go\n"))) ps)
        (let ((exits (let loop ((n 0) (seen '()))
                       (if (= n 100) seen
                           (receive (after 10000 seen)
                             (`#(proc-exit ,p ,c ,s) (loop (+ n 1) (cons (list p c s) seen))))))))
          (check "P9: 100 exits with code 7" (and (= (length exits) 100) (for-all (lambda (e) (equal? (cdr e) '(7 0))) exits)) (length exits))
          (check "P9: one exit per proc, each a spawned one" (and (= 100 (length (let dedup ((l (map car exits)) (seen '())) (cond ((null? l) seen) ((memq (car l) seen) (dedup (cdr l) seen)) (else (dedup (cdr l) (cons (car l) seen)))))))
                                                                  (for-all (lambda (e) (memq (car e) ps)) exits))))
        (let drain () (receive (after 500 (void)) (`#(proc-eof ,p ,s) (drain)) (`#(proc-data ,p ,s ,bv) (drain))))
        (back-to-base! "P9: every count and the owner index back while the owner is alive (pipes self-closed at EOF)" b0 8000))
      (set-max-procs! 2)
      (let ((a (spawn-sh "exec sleep 100")) (b (spawn-sh "exec sleep 100")))
        (check "P9b: two admitted" (and (proc? a) (proc? b)))
        (let* ((before (base)) (c (spawn-sh "exec sleep 100")))
          (check "P9b: the third is refused with proc-limit" (equal? c '(failed . proc-limit)) c)
          (check "P9b: nothing allocated for the refused one (all five counts as before the call)" (equal? (base) before) (base) before))
        (proc-kill! a 9) (proc-kill! b 9)
        (wait-exit a 3000) (wait-exit b 3000)
        (collect a 'stdout 2000) (collect a 'stderr 2000) (collect b 'stdout 2000) (collect b 'stderr 2000)
        (back-to-base! "P9b: counts back" b0 3000))
      (set-max-procs! 64)

      ;; ---- P10: coexistence with `system` -------------------------------------------
      (let ((p (spawn-sh "sleep 0.1; exit 5")))
        (let* ((t0 (now-ms)) (r (system "sleep 0.3")) (t1 (now-ms)))
          (check "P10: system blocked for its 0.3 s and returned 0 (libc did not reap our child)" (and (eqv? r 0) (>= (- t1 t0) 250)) r (- t1 t0))
          (let* ((e (wait-exit p 3000)) (t2 (now-ms)))
            (check "P10: the uv child's exit (5) arrived once polling resumed" (and (equal? e '(5 . 0)) (< (- t2 t1) 1000)) e (- t2 t1))))
        (collect p 'stdout 2000) (collect p 'stderr 2000)
        (back-to-base! "P10: counts back" b0 3000))
      ;; descriptor 1 must survive a spawn: redirect FIRST, spawn a child (the suspect
      ;; operation), then let system's child write through the same descriptor before
      ;; it is restored -- dup2 would otherwise clear a wrongly set close-on-exec flag
      (let ((f "/tmp/igropyr-p10-system.txt"))
        (with-stdout-to-file f
          (lambda ()
            (let ((q (spawn-sh "true")))
              (when (proc? q) (wait-exit q 3000) (collect q 'stdout 2000) (collect q 'stderr 2000)))
            (system "echo from-system")))
        (check "P10: system's child wrote through our descriptor 1 after a spawn (not marked close-on-exec)" (equal? (file-text f) "from-system\n") (file-text f))
        (back-to-base! "P10 fd: counts back" b0 3000))

      ;; ---- P11: env and cwd --------------------------------------------------------
      (let ((p (spawn-sh "pwd; echo $IGROPYR_P11; echo $HOME" '(cwd . "/usr") '(env . ("IGROPYR_P11=exact-value" "PATH=/usr/bin:/bin")))))
        (check "P11: cwd and env exact, unlisted variables absent" (equal? (text p 'stdout 3000) "/usr\nexact-value\n\n"))
        (wait-exit p 3000) (collect p 'stderr 2000)
        (back-to-base! "P11: counts back" b0 3000))

      ;; ---- P13: stdout EOF while running --------------------------------------------
      (let ((p (spawn-sh "exec 1>&-; read x; echo err 1>&2; exit 2")))
        (receive (after 3000 (check "P13: first message is stdout EOF" #f 'timeout))
          (`#(proc-eof ,@p stdout) (check "P13: stdout EOF arrives while the child is held on stdin (running)" (eq? (proc-state p) 'running) (proc-state p)))
          (`#(proc-data ,@p ,s ,bv) (check "P13: first message is stdout EOF" #f (list 'data s)))
          (`#(proc-exit ,@p ,c ,s) (check "P13: first message is stdout EOF" #f (list 'exit c s))))
        (check "P13: proc-stdout cleared once its close ran, child still running" (within? 2000 (lambda () (and (not (proc-stdout p)) (eq? (proc-state p) 'running)))))
        (proc-write! p (string->utf8 "go\n"))
        (check "P13: stderr data after the stdout EOF" (equal? (text p 'stderr 3000) "err\n"))
        (check "P13: exit 2" (equal? (wait-exit p 3000) '(2 . 0)))
        (back-to-base! "P13: counts back" b0 3000))

      ;; ---- P14: close vs lifetime ------------------------------------------------------
      (let ((p (spawn-sh "exec sleep 100")))
        (proc-close! p) (proc-close! p)
        (check "P14: pipes gone after close, child still running" (within? 2000 (lambda () (and (not (proc-stdin p)) (not (proc-stdout p)) (not (proc-stderr p)) (eq? (proc-state p) 'running)))) (proc-state p))
        (check "P14: kill after close -> #t" (proc-kill! p 15))
        (check "P14: exit arrives" (equal? (wait-exit p 3000) '(0 . 15)))
        (proc-close! p)
        (check "P14: closed" (within? 2000 (lambda () (eq? (proc-state p) 'closed))) (proc-state p))
        (back-to-base! "P14: counts back" b0 3000))

      ;; ---- P16: dead explicit owner ---------------------------------------------------
      (let ((dead (spawn (lambda () (void)))))
        (check "P16: premise -- the owner is dead" (within? 1000 (lambda () (not (process-alive? dead)))))
        (let ((r (spawn-sh "true" (cons 'owner dead))))
          (check "P16: refused with owner-dead" (equal? r '(failed . owner-dead)) r)
          (check "P16: nothing allocated" (equal? (base) b0) (base) b0)))

      ;; ---- P22: counts sampled during pipe churn ---------------------------------------
      (let* ((srv #f) (i1 #f)
             (l (tcp-listen! "127.0.0.1" port 16 (lambda (c) (set! srv c))))
             (sock (begin (tcp-connect! "127.0.0.1" port main)
                          (receive (after 3000 #f) (`#(tcp-connected ,c) c)))))
        ;; the accepted side appears a few ms after the client's tcp-connected
        (check "P22: premise -- a real socket pair is open (both rows)" (and sock (within? 3000 (lambda () (and srv (>= (- (conn-count) (list-ref b0 1)) 2))))) (conn-count))
        (set! i1 (uv-owner-index-count))
        (let ((spawner (spawn (lambda ()
                                (let loop ((i 0) (ps '()))
                                  (if (< i 50)
                                      (loop (+ i 1) (cons (spawn-sh "true") ps))
                                      (begin
                                        (for-each (lambda (p) (when (proc? p) (wait-exit p 5000) (collect p 'stdout 2000) (collect p 'stderr 2000))) ps)
                                        (send main (vector 'churn-done (length (filter proc? ps))))
                                        (let hold () (receive (m (hold))))))))))
              (samples 0) (bad 0) (max-pipes 0) (done #f))
          (let sample ()
            (unless done
              (let ((s (socket-conn-count)) (c (conn-count)) (pc (pipe-conn-count)))
                (set! samples (+ samples 1))
                (when (> pc max-pipes) (set! max-pipes pc))
                (when (or (not (= s 2)) (> s c)) (set! bad (+ bad 1))))
              (receive (after 0 (sample))
                (`#(churn-done ,n) (set! done n)))))
          (check "P22: the churn finished (50 children)" (eqv? done 50) done)
          (check "P22: every sample counted exactly the two sockets (pipes never counted as sockets)" (and (>= samples 100) (= bad 0)) samples bad)
          (check "P22: the sampler overlapped the churn (pipes were open during sampling)" (> max-pipes (list-ref b0 2)) max-pipes)
          (check "P22: counts back while the spawner (the owner) is still alive" (within? 8000 (lambda () (equal? (list-ref (base) 2) (list-ref b0 2)) )) (base))
          (check "P22: procs and owner index back (to the socket-pair level) with the owner alive" (within? 8000 (lambda () (and (eqv? (proc-count) (list-ref b0 3)) (eqv? (uv-owner-index-count) i1)))) (base) b0 i1)
          (kill spawner 'done)
          (tcp-close! sock) (when srv (tcp-close! srv)) (tcp-stop-listen! l)
          (back-to-base! "P22: counts back" b0 5000)))

      ;; ---- P23: pipe conns refuse owner transfer and hook replacement --------------------
      (let ((p (spawn-sh "exec sleep 100")))
        (check "P23: conn-set-owner! on a pipe conn is an assertion violation"
               (guard (e (#t (assertion-violation? e))) (conn-set-owner! (proc-stdout p) main) #f))
        (check "P23: conn-on-close! on a pipe conn is an assertion violation"
               (guard (e (#t (assertion-violation? e))) (conn-on-close! (proc-stdout p) (lambda () (void))) #f))
        (proc-kill! p 9) (wait-exit p 3000) (collect p 'stdout 2000) (collect p 'stderr 2000)
        (back-to-base! "P23: counts back" b0 3000))

      (check "baseline: counts" (equal? (base) b0) (base) b0))
    (if (zero? fails)
        (begin (display "ALL PROC-SPAWN TESTS PASSED\n") (exit 0))
        (begin (display "PROC-SPAWN VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
