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

    ;; 5. spawn&link + trap-exit turns a crash into an EXIT message
    (process-trap-exit #t)
    (spawn&link (lambda () (raise 'linked-crash)))
    (receive (after 1000 (fail "no EXIT from linked process"))
      (`#(EXIT ,pid ,reason) 'ok))
    (display "link/EXIT ok\n")

    (display "ALL ACTOR TESTS PASSED\n")
    (exit 0)))
