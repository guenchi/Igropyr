#!chezscheme
;;; tls-mesh-pair.sc -- two TLS nodes in two processes, linked through a
;;; recording relay (design M3). This node 'a dials the child 'b through a
;;; relay that copies bytes both ways and keeps the first bytes of each
;;; direction: both must begin with a TLS record header (0x16 0x03 ..), never
;;; with a plaintext frame ("<len>\n("). The link is confirmed both ways by a
;;; ping to the child's 'ping process and its pong back. Needs the openssl CLI.
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr libuv) now-ms)
        (only (igropyr tcp) tcp-listen! tcp-stop-listen! tcp-connect! tcp-read-start! tcp-write! tcp-close! conn-set-owner!))

(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define scheme-bin (let ((s (getenv "IGROPYR_SCHEME"))) (or s "chez")))
(define dir "/tmp/igropyr-tls-mesh-pair")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(define (in-dir f) (string-append dir "/" f))
(define secret "tls-mesh-pair-secret-0123456789abcdef")
(define a-port 18590)
(define b-port 18591)
(define relay-port 18592)
(define pid-file "/tmp/igropyr-tls-mesh-pair-b.pid")
(define (spawn-child!)
  (system (string-append scheme-bin " --script igropyr/test/tls-node-child.sc b "
                         (number->string b-port) " " secret " " (in-dir "good.pem") " " (in-dir "good.key")
                         " 40000 > /tmp/igropyr-tls-mesh-pair-b.log 2>&1 & echo $! > " pid-file)))
(define (kill-child!)
  (system (string-append "kill -9 $(cat " pid-file " 2>/dev/null) 2>/dev/null; rm -f " pid-file)))
(define (tls-record-head? bv)
  (and (>= (bytevector-length bv) 3) (= (bytevector-u8-ref bv 0) #x16) (= (bytevector-u8-ref bv 1) #x03)))

;; first bytes seen in each direction through the relay
(define a->b-first (box #f))
(define b->a-first (box #f))
;; NOTE: #(tcp-data bv) carries no connection, so a single process cannot own both
;; ends. Each end gets its own owner process instead (see relay-pair! below).
(define (relay-pair! down)
  ;; owner of `down` forwards to `up`; a second process owns `up` and forwards back
  (tcp-connect! "127.0.0.1" b-port self)
  (receive (after 5000 (tcp-close! down))
    (`#(tcp-connect-failed ,e) (tcp-close! down))
    (`#(tcp-connected ,up)
      (let* ((me self)
             (back (spawn (lambda ()
                            (tcp-read-start! up)
                            (let loop ()
                              (receive
                                (`#(tcp-data ,bv)
                                  (unless (unbox b->a-first) (set-box! b->a-first bv))
                                  (tcp-write! down bv #f) (loop))
                                (`#(tcp-eof) (tcp-close! down))
                                (`#(tcp-error ,e) (tcp-close! down))))))))
        (conn-set-owner! up back)
        (tcp-read-start! down)
        (let loop ()
          (receive
            (`#(tcp-data ,bv)
              (unless (unbox a->b-first) (set-box! a->b-first bv))
              (tcp-write! up bv #f) (loop))
            (`#(tcp-eof) (tcp-close! up))
            (`#(tcp-error ,e) (tcp-close! up))))))))

(start-scheduler
  (lambda ()
    (define relay (tcp-listen! "127.0.0.1" relay-port 16
                    (lambda (down)
                      (let ((pid (spawn (lambda () (relay-pair! down)))))
                        (conn-set-owner! down pid)))))
    (node-start! 'a secret a-port "127.0.0.1" (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))
    (register 'main self)
    (monitor-node 'b)
    (spawn-child!)
    (sleep-ms 1500)                                   ; the child's listener comes up
    (node-connect! 'b "127.0.0.1" relay-port)         ; through the relay
    (check "M3: node-up for the child over TLS through the relay" (receive (after 15000 #f) (`#(node-up b) #t)))
    ;; two-way: ping the child's 'ping, await its pong
    (let wait ((tries 0))
      (cond ((> tries 40) (check "M3: pong from the child (two-way link)" #f 'timeout))
            ((memq 'b (node-peers))
             (rsend 'b 'ping (vector 'ping 'a))
             (receive (after 500 (wait (+ tries 1)))
               (`#(pong b) (check "M3: pong from the child (two-way link)" #t))))
            (else (sleep-ms 250) (wait (+ tries 1)))))
    (check "M3: a->b first bytes on the wire are a TLS record header" (and (unbox a->b-first) (tls-record-head? (unbox a->b-first))) (unbox a->b-first))
    (check "M3: b->a first bytes on the wire are a TLS record header" (and (unbox b->a-first) (tls-record-head? (unbox b->a-first))) (unbox b->a-first))
    (kill-child!)
    (check "M3: node-down when the child is killed" (receive (after 15000 #f) (`#(node-down b) #t)))
    (tcp-stop-listen! relay)
    (sleep-ms 300)
    (if (zero? fails)
        (begin (display "ALL TLS-MESH-PAIR TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-PAIR VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
