#!chezscheme
;;; (igropyr node) integration test: two real OS processes.
;;;   - handshake + node-up
;;;   - rsend round-trip with extended-whitelist payload fidelity
;;;     (vector, bytevector, flonum, ratio through the wire and back)
;;;   - node-down when the peer exits
;;;   - a peer with the WRONG secret never becomes a node
;;;   - rsend to a disconnected node returns #f; to self delivers locally

(import (chezscheme) (igropyr actor) (igropyr node))

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
    (register 'main self)
    (monitor-node 'b)

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

    ;; peer exits -> node-down, and rsend turns #f
    (rsend 'b 'svc (vector 'quit))
    (receive (after 10000 (fail! "node-down-timeout"))
      (`#(node-down b) 'ok))
    (when (memq 'b (node-peers)) (fail! "peers-still-b"))
    (unless (eq? #f (rsend 'b 'svc 'x)) (fail! "rsend-after-down"))
    (display "node-down + rsend #f ok\n")

    (display "ALL NODE TESTS PASSED\n")
    (exit 0)))
