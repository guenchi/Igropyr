#!chezscheme
;;; (igropyr node) integration test: two real OS processes.
;;;   - handshake + node-up
;;;   - rsend round-trip with extended-whitelist payload fidelity
;;;     (vector, bytevector, flonum, ratio through the wire and back)
;;;   - node-down when the peer exits
;;;   - a peer with the WRONG secret never becomes a node
;;;   - rsend to a disconnected node returns #f; to self delivers locally

(import (chezscheme) (igropyr actor) (igropyr libuv)
        (igropyr node) (igropyr pubsub))

(define port 18091)
(define secret "test-mesh-secret")

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

(define (spawn-child! name secret)
  (system (string-append
            "scheme --script igropyr/test/node-child.sc "
            name " " (number->string port) " " secret " &")))

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (node-set-limits! 64 2)
    (start-pubsub!)
    (register 'main self)
    (monitor-node 'b)

    ;; The pre-auth handshake has one absolute deadline. Dripping a byte
    ;; before each idle timeout must not hold an unauthenticated fd forever.
    (tcp-connect! "127.0.0.1" port self)
    (let ((slow
            (receive (after 2000 (fail! "slow-handshake-connect"))
              (`#(tcp-connected ,c) c)
              (`#(tcp-connect-failed ,e) (fail! "slow-handshake-connect" e)))))
      (tcp-read-start! slow)
      (tcp-write! slow (string->utf8 "10\n(") #f)
      ;; Drip a byte every second rather than once. A single drip has to
      ;; land inside the server's own window to prove anything: if the
      ;; scheduler drifts past it, the server closes on its own schedule
      ;; and the check passes against the very code it exists to reject --
      ;; moving one sleep from 4000 to 5200 was enough to make this report
      ;; ok against a per-receive timeout. Dripping continuously removes
      ;; the dependency: a refreshing window outlives the whole loop no
      ;; matter where individual bytes land, and an absolute deadline is
      ;; moved by none of them.
      (let ((t0 (now-ms)))
        (let loop ((k 0))
          (if (= k 8)
              (begin (tcp-close! slow) (fail! "slow-handshake-deadline"))
              (receive (after 1000
                          (tcp-write! slow (string->utf8 "x") #f)
                          (loop (+ k 1)))
                (`#(tcp-eof) 'ok)
                (`#(tcp-error ,_) 'ok))))
        ;; reaching k = 8 already fails; this keeps the check honest if the
        ;; deadline is ever made longer than the loop
        (let ((elapsed (- (now-ms) t0)))
          (when (>= elapsed 7000)
            (fail! "slow-handshake-deadline-not-absolute" elapsed))))
      (display "absolute pre-auth handshake deadline ok\n"))

    ;; rsend to an unknown node: #f, no crash
    (unless (eq? #f (rsend 'nowhere 'svc 'x))
      (fail! "rsend-unknown"))
    (display "rsend to unknown node ok\n")

    ;; rsend to self is a local send
    (rsend 'a 'main (vector 'loopback 1))
    (receive (after 1000 (fail! "self-rsend"))
      (`#(loopback 1) 'ok))
    (display "rsend to self ok\n")

    ;; wrong secret: must never come up
    (spawn-child! "evil" "wrong-secret")
    (monitor-node 'evil)
    (receive (after 2500 'ok)
      (`#(node-up evil) (fail! "bad-secret-accepted")))
    (when (memq 'evil (node-peers)) (fail! "bad-secret-in-peers"))
    (display "wrong secret rejected ok\n")

    ;; the real peer comes up
    (spawn-child! "b" secret)
    (receive (after 10000 (fail! "node-up-timeout"))
      (`#(node-up b) 'ok))
    (unless (memq 'b (node-peers)) (fail! "peers-missing-b"))
    (display "handshake + node-up ok\n")

    ;; round-trip: extended payload must cross bit-intact both ways
    (let ((payload (vector 'blob (bytevector 0 127 255) 3.25 1/3 '(a . b))))
      (unless (rsend 'b 'svc (vector 'add1 41 payload))
        (fail! "rsend-b"))
      (receive (after 5000 (fail! "roundtrip-timeout"))
        (`#(ans ,n ,p)
          (unless (= n 42) (fail! "roundtrip-value" n))
          (unless (equal? p payload) (fail! "payload-fidelity" p)))))
    (display "rsend round-trip + payload fidelity ok\n")

    ;; ordering: a burst arrives in send order
    (do ((i 0 (+ i 1))) ((= i 100))
      (rsend 'b 'svc (vector 'add1 i (vector))))
    (let loop ((expect 1))
      (unless (= expect 101)
        (receive (after 5000 (fail! "ordering-timeout" expect))
          (`#(ans ,n ,p)
            (unless (= n expect) (fail! "ordering" expect n))
            (loop (+ expect 1))))))
    (display "in-order burst ok\n")

    ;; rcall: synchronous cross-node call to a gen-server on b
    (unless (= 49 (rcall 'b 'calc (vector 'square 7)))
      (fail! "rcall-value"))
    (display "rcall round-trip ok\n")

    ;; rcall to a gen-server that raises -> rcall-error, not a hang
    (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'rcall-error))
                          (vector-ref e 1)))
                 (rcall 'b 'calc (vector 'boom))
                 'no-raise)))
      (unless (memq got '(unavailable server-died call-failed))
        (fail! "rcall-error-kind" got)))
    (display "rcall remote failure -> rcall-error ok\n")

    ;; rcall to a missing server -> rcall-error (no hang)
    (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'rcall-error)) #t))
                 (rcall 'b 'nonesuch (vector 'x) 2000)
                 #f)))
      (unless got (fail! "rcall-missing")))
    (display "rcall missing server -> rcall-error ok\n")

    ;; distributed pubsub: a publish on node a must reach a subscriber
    ;; on node b (b relays it back as #(heard ...))
    (sleep-ms 300)                       ; let b's subscribe settle
    (publish 'room "cross-node-hello")
    (receive (after 5000 (fail! "dist-pubsub-timeout"))
      (`#(heard ,m)
        (unless (equal? m "cross-node-hello") (fail! "dist-pubsub-payload" m))))
    (display "distributed pubsub fan-out ok\n")

    ;; Remote monitor state is owned by its caller. Short-lived callers
    ;; must release target-side slots instead of leaving permanent watches.
    (do ((i 0 (+ i 1))) ((= i 2))
      (spawn (lambda () (monitor-remote 'b 'svc))))
    (sleep-ms 600)
    (let ((m (monitor-remote 'b 'svc)))
      (receive (after 400 'ok)
        (`#(remote-down b svc overload)
          (fail! "dead-monitor-callers-leaked-slots")))
      (demonitor-remote m))
    (display "dead monitor callers release remote slots ok\n")

    ;; monitor-remote: watch b's 'watched process, kill it, observe the
    ;; real exit reason cross the wire
    (monitor-remote 'b 'watched)
    (rsend 'b 'svc (vector 'kill-watched 'crash-reason))
    (receive (after 5000 (fail! "remote-down-timeout"))
      (`#(remote-down b watched ,reason)
        (unless (eq? reason 'crash-reason) (fail! "remote-down-reason" reason))))
    (display "monitor-remote -> remote-down with reason ok\n")

    ;; watching a name that isn't registered -> immediate noproc
    (monitor-remote 'b 'watched)                 ; now dead
    (receive (after 5000 (fail! "noproc-timeout"))
      (`#(remote-down b watched ,r) (unless (eq? r 'noproc) (fail! "noproc" r))))
    (display "monitor-remote missing name -> noproc ok\n")

    ;; demonitor: a demonitored watch must NOT fire when b dies
    (let ((m (monitor-remote 'b 'svc)))
      (demonitor-remote m))
    (receive (after 400 'ok)
      (`#(remote-down b svc ,_) (fail! "demonitor-still-fired")))
    (display "demonitor-remote silences the watch ok\n")

    ;; a live watch fires noconnection when the node's link drops
    (monitor-remote 'b 'svc)

    ;; peer exits -> node-down, remote-down(noconnection), rsend turns #f
    (rsend 'b 'svc (vector 'quit))
    (let wait ((down? #f) (noconn? #f))
      (unless (and down? noconn?)
        (receive (after 10000 (fail! "node-down-timeout" down? noconn?))
          (`#(node-down b) (wait #t noconn?))
          (`#(remote-down b svc ,r)
            (unless (eq? r 'noconnection) (fail! "noconnection" r))
            (wait down? #t)))))
    (when (memq 'b (node-peers)) (fail! "peers-still-b"))
    (unless (eq? #f (rsend 'b 'svc 'x)) (fail! "rsend-after-down"))
    (display "node-down + remote-down(noconnection) + rsend #f ok\n")

    (display "ALL NODE TESTS PASSED\n")
    (exit 0)))
