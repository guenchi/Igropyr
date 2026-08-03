;;; Smoke test for (igropyr actor): ping-pong, after timeout, monitor,
;;; preemption of a CPU-spinning process, link/EXIT.
;;; Run: scheme --script test/smoke-actor.sc (from the project root)

(import (chezscheme) (igropyr actor) (igropyr libuv))

(define (fail msg)
  (display "FAIL: ") (display msg) (newline)
  (exit 1))

(start-scheduler
  (lambda ()
    ;; 1. ping-pong between two processes
    (let ((me self))
      (let ((pong (spawn
                    (lambda ()
                      (receive
                        (`#(ping ,from) (send from (vector 'pong))))))))
        (send pong (vector 'ping me))
        (receive (after 1000 (fail "ping-pong timeout"))
          (`#(pong) 'ok))))
    (display "ping-pong ok\n")

    ;; 2. after timeout fires and takes roughly the right time
    (let ((t0 (now-ms)))
      (receive (after 200 'ok))
      (unless (>= (- (now-ms) t0) 190)
        (fail "after fired too early")))
    (display "after-timeout ok\n")

    ;; 3. monitor delivers DOWN when the target crashes
    (let ((p (spawn (lambda () (raise 'boom)))))
      (monitor p)
      (receive (after 1000 (fail "no DOWN from crashed process"))
        (`#(DOWN ,pid ,reason)
          (display "down reason: ") (write reason) (newline))))

    ;; 4. preemption: a spinning process cannot starve us, and kill works
    (let ((spinner (spawn (lambda () (let loop ((n 0)) (loop (+ n 1)))))))
      (monitor spinner)
      (sleep-ms 100)     ; only returns if the spinner gets preempted
      (kill spinner 'kill)
      (receive (after 1000 (fail "no DOWN from killed spinner"))
        (`#(DOWN ,pid ,reason) 'ok)))
    (display "preemption+kill ok\n")

    ;; Established sockets are owned resources. Killing their actor must
    ;; remove the conn-table root and close the fd without actor cooperation.
    (let* ((caller self)
           (before (conn-count))
           (owner (spawn (lambda () (receive (`#(stop) (void))))))
           (listener
             (tcp-listen! "127.0.0.1" 18919 4
               (lambda (c)
                 (conn-set-owner! c owner)
                 (tcp-read-start! c)
                 (send caller (vector 'accepted c)))
               0)))
      (tcp-connect! "127.0.0.1" 18919 self)
      (let ((client
              (receive (after 1000 (fail "owner-cleanup connect timeout"))
                (`#(tcp-connected ,c) c)
                (`#(tcp-connect-failed ,e)
                  (fail "owner-cleanup connect failed")))))
        (receive (after 1000 (fail "owner-cleanup accept timeout"))
          (`#(accepted ,c) 'ok))
        (monitor owner)
        (kill owner 'owner-cleanup-test)
        (receive (after 1000 (fail "owner-cleanup no DOWN"))
          (`#(DOWN ,@owner ,_) 'ok))
        (sleep-ms 100)
        (unless (<= (conn-count) (+ before 1))
          (fail "dead owner retained its socket"))
        (tcp-close! client)
        (tcp-stop-listen! listener)
        (sleep-ms 100)
        (unless (<= (conn-count) before)
          (fail "owner-cleanup leaked a connection"))))
    (display "owner resource cleanup ok\n")

    ;; A connect that completes after its owner died is the worse half of
    ;; the same leak: on-connect would root a conn in conn-table under a
    ;; dead pid, and no later uv-owner-died! can reach it -- that pid's
    ;; teardown has already run. Nothing but the VM exit frees it.
    ;;
    ;; tcp-connect! takes the owner as an argument, so the request can be
    ;; put in flight and the owner killed within one scheduler turn: spawn,
    ;; tcp-connect! and kill do not yield, so the loop cannot have polled
    ;; and the connect is guaranteed still outstanding. Do not rewrite this
    ;; to have the victim call tcp-connect! on itself -- the handshake then
    ;; races the kill and the test silently degrades into the established-
    ;; socket case above.
    (let* ((caller self)
           (before (conn-count))
           (listener
             (tcp-listen! "127.0.0.1" 18920 4
               (lambda (c) (send caller (vector 'served c)))
               0))
           (victim (spawn (lambda () (receive (`#(never) (void)))))))
      (monitor victim)
      (tcp-connect! "127.0.0.1" 18920 victim)
      (kill victim 'died-mid-connect)
      (receive (after 1000 (fail "mid-connect no DOWN"))
        (`#(DOWN ,@victim ,_) 'ok))
      (let ((served (receive (after 1000 (fail "mid-connect never accepted"))
                      (`#(served ,c) c))))
        (sleep-ms 200)
        (tcp-close! served)
        (tcp-stop-listen! listener)
        (sleep-ms 100)
        (unless (<= (conn-count) before)
          (fail "connect completed for a dead owner and was registered"))))
    (display "mid-connect owner death ok\n")

    ;; Cleanup owned by the resource, not the code path: a thunk attached
    ;; with conn-on-close! must run when the conn closes -- including when
    ;; the close came from the owner-death sweep, where no user code (no
    ;; winders, no guards) gets to run. This is what lets a TLS session be
    ;; freed even when its process is killed mid-request.
    (let* ((caller self)
           (ran (box 0))
           (listener
             (tcp-listen! "127.0.0.1" 18921 4
               (lambda (c) (tcp-read-start! c)) 0)))
      ;; normal close path
      (tcp-connect! "127.0.0.1" 18921 self)
      (let ((c (receive (after 1000 (fail "on-close connect timeout"))
                 (`#(tcp-connected ,c) c))))
        (conn-on-close! c (lambda () (set-box! ran (+ 1 (unbox ran)))))
        (tcp-close! c)
        (sleep-ms 100)
        (unless (= (unbox ran) 1) (fail "on-close hook missed tcp-close!"))
        ;; registering on an already-closed conn runs immediately
        (conn-on-close! c (lambda () (set-box! ran (+ 1 (unbox ran)))))
        (unless (= (unbox ran) 2) (fail "on-close hook missed late registration")))
      ;; owner-death path: the kill must trigger it via uv-owner-died!
      (let ((victim (spawn (lambda ()
                             (tcp-connect! "127.0.0.1" 18921 self)
                             (receive
                               (`#(tcp-connected ,c)
                                 (conn-on-close! c
                                   (lambda () (set-box! ran (+ 1 (unbox ran)))))
                                 (send caller (vector 'armed))
                                 (receive (`#(never) (void)))))))))
        (receive (after 1000 (fail "on-close arm timeout")) (`#(armed) 'ok))
        (monitor victim)
        (kill victim 'on-close-test)
        (receive (after 1000 (fail "on-close no DOWN")) (`#(DOWN ,@victim ,_) 'ok))
        (sleep-ms 100)
        (unless (= (unbox ran) 3) (fail "on-close hook missed owner death")))
      (tcp-stop-listen! listener))
    (display "conn on-close cleanup ok\n")

    ;; A name has one owner while a pid may have multiple aliases. Rebinding
    ;; a name must remove the displaced reverse entry: otherwise the replaced
    ;; process can die later and unregister its replacement. Killing a pid
    ;; must remove all of its aliases.
    (let ((old (spawn (lambda () (receive (`#(never) (void))))))
          (new (spawn (lambda () (receive (`#(never) (void)))))))
      (register 'registry-rebind old)
      (register 'registry-rebind new)
      (kill old 'replaced)
      (unless (eq? (whereis 'registry-rebind) new)
        (fail "old process death removed replacement registration"))
      (register 'registry-alias new)
      (unless (and (eq? (whereis 'registry-rebind) new)
                   (eq? (whereis 'registry-alias) new))
        (fail "one process could not retain multiple registered aliases"))
      (kill new 'done)
      (when (or (whereis 'registry-rebind) (whereis 'registry-alias))
        (fail "dead process retained a registered alias")))
    (display "registry rebinding ok\n")

    ;; parameterize gives NO per-process isolation, and this pins that as a
    ;; known limitation rather than leaving it to be rediscovered. Chez
    ;; implements it by swapping a global cell and registering a winder to
    ;; swap it back; @yield saves and restores winder lists without running
    ;; them (right for dynamic-wind, whose after-thunk must not fire on a
    ;; yield), so the cell belongs to whoever wrote it last.
    ;;
    ;; Asserted as the OBSERVED behaviour, not the desirable one: if a future
    ;; scheduler change makes parameters process-local this test fails and
    ;; should be replaced by its opposite -- and if someone "fixes" it by
    ;; running the winders on every switch, the dynamic-wind case below
    ;; catches that instead.
    (let ((param (make-parameter 'nobody))
          (me self))
      (spawn (lambda ()
               (parameterize ((param 'first))
                 (sleep-ms 20)
                 (send me (vector 'param-saw 'inside-own-body (param))))))
      (spawn (lambda ()
               (sleep-ms 10)
               (parameterize ((param 'second))
                 (sleep-ms 30)
                 (send me (vector 'param-done)))))
      (let loop ((seen #f) (done #f))
        (unless (and seen done)
          (receive (after 3000 (fail "parameterize probe timed out"))
            (`#(param-saw ,_ ,val)
              ;; its own binding is NOT what it reads back
              (when (eq? val 'first)
                (fail "parameters became process-local -- update this test"))
              (loop #t done))
            (`#(param-done) (loop seen #t))))))
    ;; ...while dynamic-wind keeps its contract across the same yields: the
    ;; after-thunk runs on normal exit, and NOT merely because we yielded.
    (let ((log '()))
      (dynamic-wind
        (lambda () (set! log (cons 'in log)))
        (lambda () (sleep-ms 20))
        (lambda () (set! log (cons 'out log))))
      (unless (equal? (reverse log) '(in out))
        (fail "dynamic-wind did not run exactly once around a yielding body")))
    (display "parameterize limitation + dynamic-wind contract ok\n")

    ;; A bad pid must be refused BEFORE interrupts are disabled. Raising
    ;; inside that region skips its enable-interrupts, so the process keeps
    ;; a disabled preemption timer forever -- and one CPU loop in it then
    ;; freezes the entire scheduler, since there is a single OS thread.
    ;; An application that guards the error and carries on is the way in:
    ;; (link (whereis 'missing)) hands link a #f.
    (let ((me self))
      (let ((victim (spawn (lambda ()
                             ;; guard and continue, exactly as an application
                             ;; that treats a missing name as recoverable would
                             (guard (e (#t (void))) (link #f))
                             (guard (e (#t (void))) (kill #f 'nope))
                             (send me (vector 'survived))
                             ;; now spin: if preemption was lost, nothing else
                             ;; in this scheduler will ever run again
                             (let loop ((n 0)) (loop (+ n 1)))))))
        (receive (after 2000 (fail "bad-pid guard did not survive"))
          (`#(survived) 'ok))
        ;; the spinner is running; this only completes if it can be preempted
        (sleep-ms 150)
        (kill victim 'done)
        (display "bad pid refused without losing preemption ok\n")))

    ;; 5. spawn&link + trap-exit turns a crash into an EXIT message
    (process-trap-exit #t)
    (spawn&link (lambda () (raise 'linked-crash)))
    (receive (after 1000 (fail "no EXIT from linked process"))
      (`#(EXIT ,pid ,reason) 'ok))
    (display "link/EXIT ok\n")

    (display "ALL ACTOR TESTS PASSED\n")
    (exit 0)))
