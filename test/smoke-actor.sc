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

    ;; 5. spawn&link + trap-exit turns a crash into an EXIT message
    (process-trap-exit #t)
    (spawn&link (lambda () (raise 'linked-crash)))
    (receive (after 1000 (fail "no EXIT from linked process"))
      (`#(EXIT ,pid ,reason) 'ok))
    (display "link/EXIT ok\n")

    (display "ALL ACTOR TESTS PASSED\n")
    (exit 0)))
