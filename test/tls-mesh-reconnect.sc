#!chezscheme
;; Two processes: node A dials a tls-node-child b. A's LOCAL link for b is
;; killed. A's connector must redial and reconnect -> node-up again. This is
;; real node recovery after a local link death (across process boundaries),
;; which the isolated single-process kill cells do not cover: an in-process raw
;; client reopened after an in-process kill hits a same-process loopback
;; artifact (see the ledger), so that path is exercised only here, honestly.
(import (chezscheme) (igropyr actor) (igropyr node) (only (igropyr libuv) now-ms))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define dir "/tmp/igropyr-tls-mesh-reconnect")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(define (in-dir f) (string-append dir "/" f))
(define scheme-bin (let ((s (getenv "IGROPYR_SCHEME"))) (or s "chez")))
(define a-port 18660)
(define b-port 40030)
(define secret "tls-mesh-reconnect-secret-0123456789abcdef")
(define pidf "/tmp/igropyr-tls-mesh-reconnect-b.pid")
(define (spawn-child!)
  (system (string-append scheme-bin " --script igropyr/test/tls-node-child.sc b "
                         (number->string b-port) " " secret " " (in-dir "good.pem") " " (in-dir "good.key")
                         " 40000 > /tmp/igropyr-tls-mesh-reconnect-b.log 2>&1 & echo $! > " pidf)))
(define (kill-child!) (system (string-append "kill -9 $(cat " pidf " 2>/dev/null) 2>/dev/null; rm -f " pidf)))

(start-scheduler
  (lambda ()
    (register 'main self)
    (node-start! 'a secret a-port "127.0.0.1"
                 (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))
    (monitor-node 'b)
    (spawn-child!)
    (sleep-ms 1500)
    (node-connect! 'b "127.0.0.1" b-port)
    (receive (after 10000 (check "reconnect: node-up b (first connection)" #f 'timeout))
      (`#(node-up b) (check "reconnect: node-up b (first connection)" #t)))
    (let ((link1 ($node-link-pid 'b)))
      (check "reconnect: A holds a local link for b" (and link1 (process-alive? link1)) (and link1 (process-id link1)))
      (kill link1 'reconnect-killed)
      (receive (after 8000 (check "reconnect: node-down b after the local link died" #f 'timeout))
        (`#(node-down b) (check "reconnect: node-down b after the local link died" #t)))
      (let ((t0 (now-ms)))
        (receive (after 20000 (check "reconnect: A reconnected (node-up again) after a local link kill" #f 'timeout))
          (`#(node-up b)
            (check "reconnect: A reconnected (node-up again) after a local link kill" #t)
            (display "  [reconnect] came back after ms ") (display (- (now-ms) t0)) (newline)))
        (let ((link2 ($node-link-pid 'b)))
          (check "reconnect: the new link is a fresh live process, not the killed one"
                 (and link2 (not (eq? link2 link1)) (process-alive? link2))
                 (list (and link1 (process-id link1)) (and link2 (process-id link2)))))))
    (kill-child!)
    (if (zero? fails)
        (begin (display "ALL TLS-MESH-RECONNECT TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-RECONNECT VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
