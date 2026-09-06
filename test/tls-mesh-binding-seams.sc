#!chezscheme
;;; tls-mesh-binding-seams.sc -- an UNAVAILABLE channel binding must refuse, never
;;; degrade to the empty binding (design 2.1c, M2d). Both sides are forced to
;;; #f through injection override points: the acceptor's own-certificate hash
;;; ('acceptor-binding-hash) and the dialer's peer-certificate hash
;;; ('dialer-binding-hash). A correct, bound handshake must then be refused on
;;; that side. Requires IGROPYR_INJECT=on and the openssl CLI.
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr libuv) now-ms)
        (igropyr inject-control)
        (only (igropyr tls-core) tls-live-session-count)
        (test tls-raw-client) (test tls-raw-server) (test mesh-proof))

(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define dir "/tmp/igropyr-tls-mesh-binding-seams")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))
(define (in-dir f) (string-append dir "/" f))
(define node-port 18600)
(define srv-port 18601)
(define secret "tls-mesh-binding-seams-0123456789abcdef")
(define probe-boot-id "feedfacefeedface")
(define srv-boot "beefbeefbeefbeef")
(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))
(define (read-frame-with recv ms)
  (let loop ((acc ""))
    (let* ((n (string-length acc))
           (nl (let scan ((k 0)) (cond ((= k n) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1))))))
           (len (and nl (string->number (substring acc 0 nl)))))
      (if (and len (>= n (+ nl 1 len)))
          (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len))))
          (let ((r (recv ms))) (if (bytevector? r) (loop (string-append acc (utf8->string r))) r))))))

(start-scheduler
  (lambda ()
    (register 'main self)
    (node-start! 'a secret node-port "127.0.0.1"
                 (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))
    (monitor-node 'b) (monitor-node 'p)

    ;; ---- M2d(a): acceptor's own hash forced #f -> a correct bound hello is refused
    (inject-arm-return! 'acceptor-binding-hash #f 1)
    (let ((s (raw-tls-open "127.0.0.1" node-port "localhost" 5000)))
      (if (pair? s) (check "M2d(a): open" #f (cdr s))
          (let ((d (read-frame-with (lambda (ms) (raw-tls-recv! s ms)) 4000)))
            (check "M2d(a): challenge received" (and (pair? d) (eq? (car d) 'challenge)) d)
            (when (and (pair? d) (eq? (car d) 'challenge))
              (let* ((nonce-a (cadr d)) (bootid-a (cadddr d)) (cb (raw-tls-peer-cb-hash s))
                     (proof (v5-proof-d secret nonce-a "b" probe-boot-id 1 "a" bootid-a cb)))
                (raw-tls-send! s (frame-bytes (list 'hello "b" proof "feedfeedfeedfeedfeedfeedfeedfeed" 5 probe-boot-id 1)))
                (let ((w (read-frame-with (lambda (ms) (raw-tls-recv! s ms)) 4000)))
                  (check "M2d(a): with its own binding unavailable the acceptor refuses even a correct bound hello (closed)" (eq? w 'closed) w))))
            (raw-tls-close! s))))
    (check "M2d(a): the override fired once" (eqv? (inject-hits 'acceptor-binding-hash) 1) (inject-hits 'acceptor-binding-hash))

    ;; ---- M2d(b): dialer's peer hash forced #f -> no hello is ever sent
    (inject-arm-return! 'dialer-binding-hash #f 1)
    (let ((srv (raw-tls-server-start "127.0.0.1" srv-port (in-dir "good.pem") (in-dir "good.key"))))
      (sleep-ms 100)
      (node-connect! 'p "127.0.0.1" srv-port)
      (let ((ss (raw-tls-server-accept srv 8000)))
        (if (or (pair? ss) (symbol? ss))
            (check "M2d(b): the TLS session was established (the refusal is about the binding, not TLS)" #f ss)
            (begin
              (raw-tls-session-send! ss (frame-bytes (list 'challenge "0123456789abcdef0123456789abcdef" 5 srv-boot)))
              (let ((h (read-frame-with (lambda (ms) (raw-tls-session-recv! ss ms)) 5000)))
                (check "M2d(b): with the peer hash unavailable the dialer sends no hello and closes" (eq? h 'closed) h))
              (raw-tls-session-close! ss))))
      (check "M2d(b): the override fired once" (eqv? (inject-hits 'dialer-binding-hash) 1) (inject-hits 'dialer-binding-hash))
      (node-disconnect! 'p)
      (raw-tls-server-stop! srv) (sleep-ms 300))
    (if (zero? fails)
        (begin (display "ALL TLS-MESH-BINDING-SEAMS TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-BINDING-SEAMS VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
