#!chezscheme
;; Child processes -- lifecycle cells (proc-spawn design v3 §5, v4-v8 deltas).
;;   P4a  SIGTERM on sleep -> exit (0 . 15)
;;   P4b  a child that ignores TERM after exec: TERM does nothing, KILL -> signal 9
;;   P5   spawn failure (ENOENT): synchronous (failed . ...), every count back
;;   P8   stdout/stderr tagged separately; 'inherit and 'ignore modes
;;   P9   100 concurrent children under max-procs 128; P9b the limit refuses a third
;;   P10  coexistence with Chez `system` (libc wait does not reap our children)
;;   P11  env and cwd exact
;;   P13  stdout EOF while the child still runs, then stderr data, then the exit
;;   P14  proc-close! before and after exit is idempotent and leaves kill eligible
;;   P16  a dead explicit owner is refused before anything is allocated
;;   P17  (this whole file runs without TLS: the liveness hook comes from actor)
;;   P22  socket-conn-count sampled during pipe churn: never negative, never above conn-count
;;   P23  pipe conns cannot change owner or replace their close hook
;; Every cell ends with the five counts back to their cell-start values while
;; the owner (this process) is alive.
(import (chezscheme) (igropyr actor) (igropyr tcp)
        (only (igropyr libuv) now-ms uv-live-handle-count)
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
(define (base) (list (uv-live-handle-count) (conn-count) (pipe-conn-count) (proc-count) (uv-owner-index-count)))
(define (back-to-base! label b ms) (check label (within? ms (lambda () (equal? (base) b))) (base) b))
(define (quiet! label ms)
  (receive (after ms (check label #t))
    (`#(proc-data ,p ,s ,bv) (check label #f (list 'data s (bytevector-length bv))))
    (`#(proc-eof ,p ,s) (check label #f (list 'eof s)))
    (`#(proc-error ,p ,s ,n) (check label #f (list 'error s n)))
    (`#(proc-exit ,p ,c ,sg) (check label #f (list 'exit c sg)))))
(define (stat p key) (let ((a (assq key (proc-stats)))) (and a (cdr a))))
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
        (check "P4a: closed once every pipe reached EOF" (within? 3000 (lambda () (eq? (proc-state p) 'closed))) (proc-state p))
        (back-to-base! "P4a: counts back to base" b0 3000))

      ;; ---- P4b: TERM ignored after exec, KILL works --------------------------------
      (let ((p (spawn-sh "trap \"\" TERM; echo ready; exec sleep 100")))
        (check "P4b: spawned" (proc? p) p)
        (receive (after 3000 (check "P4b: the child reported ready" #f 'timeout))
          (`#(proc-data ,@p stdout ,bv) (check "P4b: the child reported ready" (equal? (utf8->string bv) "ready\n") bv)))
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
      (let ((p (spawn-sh "echo P8-inherit-marker-on-our-stdout; echo P8-inherit-marker-on-our-stderr 1>&2"
                         '(stdout . inherit) '(stderr . inherit))))
        (check "P8 inherit: spawned" (proc? p) p)
        (check "P8 inherit: no stdout/stderr conns" (and (proc? p) (not (proc-stdout p)) (not (proc-stderr p))))
        (check "P8 inherit: exit 0" (equal? (wait-exit p 3000) '(0 . 0)))
        (quiet! "P8 inherit: nothing tagged arrives (the markers went to our own descriptors, see the log)" 300)
        (check "P8 inherit: only stdin was a pipe" (eqv? (- (list-ref (base) 2) (list-ref b0 2)) (if (proc-stdin p) 1 0)))
        (proc-close! p)
        (back-to-base! "P8 inherit: counts back" b0 3000))
      (let ((p (spawn-sh "echo dropped; exit 4" '(stdout . ignore))))
        (check "P8 ignore: no stdout conn" (and (proc? p) (not (proc-stdout p))))
        (check "P8 ignore: exit 4" (equal? (wait-exit p 3000) '(0 . 4)))
        (check "P8 ignore: stderr EOF" (equal? (collect p 'stderr 3000) (make-bytevector 0)))
        (quiet! "P8 ignore: nothing from stdout" 300)
        (back-to-base! "P8 ignore: counts back" b0 3000))

      ;; ---- P9: 100 concurrent children; P9b: the limit ---------------------------------
      (set-max-procs! 128)
      (let ((ps (let loop ((i 0) (acc '())) (if (= i 100) acc (loop (+ i 1) (cons (spawn-sh "sleep 0.1; exit 7") acc))))))
        (check "P9: 100 spawned" (for-all proc? ps) (length (filter (lambda (p) (not (proc? p))) ps)))
        (check "P9: proc-count = 100 above base" (eqv? (proc-count) (+ (list-ref b0 3) 100)) (proc-count))
        (let ((exits (let loop ((n 0) (seen '()))
                       (if (= n 100) seen
                           (receive (after 10000 seen)
                             (`#(proc-exit ,p ,c ,s) (loop (+ n 1) (cons (list p c s) seen))))))))
          (check "P9: 100 exits with code 7" (and (= (length exits) 100) (for-all (lambda (e) (equal? (cdr e) '(7 0))) exits)) (length exits))
          (check "P9: one exit per proc" (= 100 (length (let dedup ((l (map car exits)) (seen '())) (cond ((null? l) seen) ((memq (car l) seen) (dedup (cdr l) seen)) (else (dedup (cdr l) (cons (car l) seen)))))))))
        ;; drain the EOFs (the pipes close themselves at EOF)
        (let drain () (receive (after 500 (void)) (`#(proc-eof ,p ,s) (drain)) (`#(proc-data ,p ,s ,bv) (drain))))
        (back-to-base! "P9: every count and the owner index back while the owner is alive" b0 8000))
      (set-max-procs! 2)
      (let ((a (spawn-sh "exec sleep 100")) (b (spawn-sh "exec sleep 100")))
        (check "P9b: two admitted" (and (proc? a) (proc? b)))
        (let ((c (spawn-sh "exec sleep 100")))
          (check "P9b: the third is refused with proc-limit" (equal? c '(failed . proc-limit)) c)
          (check "P9b: nothing allocated for the refused one" (eqv? (proc-count) (+ (list-ref b0 3) 2)) (proc-count)))
        (proc-kill! a 9) (proc-kill! b 9)
        (wait-exit a 3000) (wait-exit b 3000)
        (collect a 'stdout 2000) (collect a 'stderr 2000) (collect b 'stdout 2000) (collect b 'stderr 2000)
        (back-to-base! "P9b: counts back" b0 3000))
      (set-max-procs! 64)

      ;; ---- P10: coexistence with `system` -------------------------------------------
      (let ((p (spawn-sh "sleep 0.1; exit 5")))
        (let ((r (system "sleep 0.3")))
          (check "P10: system returned 0 (libc did not reap our child; ECHILD would have shown)" (eqv? r 0) r))
        (check "P10: the uv child reports 5 after polling resumed" (equal? (wait-exit p 3000) '(5 . 0)))
        (collect p 'stdout 2000) (collect p 'stderr 2000)
        (let ((f "/tmp/igropyr-p10-system.txt"))
          (system (string-append "rm -f " f))
          (system (string-append "echo from-system >> " f))
          (check "P10: system's own child still has its stdio (wrote the file)"
                 (guard (e (#t #f)) (equal? (call-with-input-file f get-line) "from-system"))))
        (back-to-base! "P10: counts back" b0 3000))

      ;; ---- P11: env and cwd --------------------------------------------------------
      (let ((p (spawn-sh "pwd; echo $IGROPYR_P11; echo $HOME" '(cwd . "/usr") '(env . ("IGROPYR_P11=exact-value" "PATH=/usr/bin:/bin")))))
        (check "P11: cwd and env exact, unlisted variables absent" (equal? (text p 'stdout 3000) "/usr\nexact-value\n\n"))
        (wait-exit p 3000) (collect p 'stderr 2000)
        (back-to-base! "P11: counts back" b0 3000))

      ;; ---- P13: stdout EOF while running --------------------------------------------
      (let ((p (spawn-sh "exec 1>&-; sleep 0.5; echo err 1>&2; exit 2")))
        (receive (after 3000 (check "P13: first message is stdout EOF" #f 'timeout))
          (`#(proc-eof ,@p stdout) (check "P13: first message is stdout EOF, while the child still runs" (eq? (proc-state p) 'running) (proc-state p)))
          (`#(proc-data ,@p ,s ,bv) (check "P13: first message is stdout EOF" #f (list 'data s)))
          (`#(proc-exit ,@p ,c ,s) (check "P13: first message is stdout EOF" #f (list 'exit c s))))
        (check "P13: proc-stdout cleared once its close ran" (within? 2000 (lambda () (not (proc-stdout p)))))
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
      (let ((spawner (spawn (lambda ()
                              (let loop ((i 0) (ps '()))
                                (if (< i 50)
                                    (loop (+ i 1) (cons (spawn-sh "true") ps))
                                    (begin
                                      (for-each (lambda (p) (when (proc? p) (wait-exit p 5000) (collect p 'stdout 2000) (collect p 'stderr 2000))) ps)
                                      (send main (vector 'churn-done (length (filter proc? ps)))))))))))
        (let sample ((n 0) (bad 0))
          (if (< n 1000)
              (let ((s (socket-conn-count)) (c (conn-count)))
                (sample (+ n 1) (if (or (< s 0) (> s c)) (+ bad 1) bad)))
              (check "P22: 1000 samples, none negative, none above conn-count" (= bad 0) bad)))
        (receive (after 15000 (check "P22: the churn finished" #f 'timeout))
          (`#(churn-done ,n) (check "P22: the churn finished (50 children)" (= n 50) n)))
        (check "P22: spawner exited" (within? 3000 (lambda () (not (process-alive? spawner)))))
        (back-to-base! "P22: counts back (the spawner's procs closed with it)" b0 8000))

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
