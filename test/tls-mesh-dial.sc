#!chezscheme
;;; tls-mesh-dial.sc -- the node's DIALER side over TLS, against the controllable
;;; TLS server of test/tls-raw-server.sc playing the acceptor by hand.
;;;
;;; M2c: the dialer verifies the welcome's proof-a against the channel binding
;;; it saw -- a welcome carrying a proof made with a wrong binding, or with the
;;; empty (plaintext) binding, must be refused (no node-up, the link closes),
;;; and one carrying the correct bound proof must be accepted (node-up).
;;; M6 (mode A): with tls-ca given, a server whose certificate is not signed by
;;; that CA, or is signed by it but names another host, fails before the mesh
;;; handshake (the server never sees a hello); the properly signed one connects.
;;; Requires IGROPYR_INJECT=on and the openssl CLI.
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr libuv) now-ms)
        (only (igropyr crypto) bytevector->hex)
        (only (igropyr tls-core) tls-live-session-count)
        (test tls-raw-server) (test mesh-proof))

(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define dir "/tmp/igropyr-tls-mesh-dial")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(define (in-dir f) (string-append dir "/" f))
(define node-port 18570)
(define srv-port 18571)
(define secret "tls-mesh-dial-secret-0123456789abcdef")
(define srv-boot "beefbeefbeefbeef")
(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))
(define (read-frame s ms)
  (let loop ((acc ""))
    (let* ((n (string-length acc))
           (nl (let scan ((k 0)) (cond ((= k n) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1))))))
           (len (and nl (string->number (substring acc 0 nl)))))
      (if (and len (>= n (+ nl 1 len)))
          (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len))))
          (let ((r (raw-tls-session-recv! s ms))) (if (bytevector? r) (loop (string-append acc (utf8->string r))) r))))))

;; Play the acceptor "p" for one dial: challenge, read hello, answer welcome with
;; a proof-a built by `make-proof-a` (given nonce-b, the binding). -> (list hello welcome-sent)
(define (serve-one! srv make-proof-a)
  (let ((ss (raw-tls-server-accept srv 8000)))
    (if (or (pair? ss) (symbol? ss))
        (list 'no-session ss)
        (let ((nonce-a "0123456789abcdef0123456789abcdef") (cb (raw-tls-server-cb-hash srv)))
          (raw-tls-session-send! ss (frame-bytes (list 'challenge nonce-a 5 srv-boot)))
          (let ((h (read-frame ss 5000)))
            (if (not (and (pair? h) (eq? (car h) 'hello) (= (length h) 7)))
                (begin (raw-tls-session-close! ss) (list 'no-hello h))
                (let* ((nonce-b (cadddr h))
                       (proof (make-proof-a nonce-b cb)))
                  (raw-tls-session-send! ss (frame-bytes (list 'welcome "p" proof)))
                  (let ((after (raw-tls-session-recv! ss 3000)))   ; 'closed if the dialer refused
                    (list 'welcomed h (if (eq? after 'closed) 'peer-closed 'peer-kept) ss)))))))))

(start-scheduler
  (lambda ()
    ;; definitions first: a define may not follow an expression in this body
    (define (expect-up? ms) (receive (after ms #f) (`#(node-up p) #t)))
    (define (drain-down!) (receive (after 3000 (void)) (`#(node-down p) (void))))
    (register 'main self)
    (node-start! 'a secret node-port "127.0.0.1"
                 (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))
    (monitor-node 'p)

    ;; ---- M2c(a): correct bound proof-a -> node-up
    (let ((srv (raw-tls-server-start "127.0.0.1" srv-port (in-dir "good.pem") (in-dir "good.key"))))
      (sleep-ms 100)
      (node-connect! 'p "127.0.0.1" srv-port)
      (let ((r (serve-one! srv (lambda (nonce-b cb) (v5-proof-a secret nonce-b "p" srv-boot cb)))))
        (check "M2c(a): the dialer sent a hello and the correct bound welcome was accepted (node-up)" (and (eq? (car r) 'welcomed) (expect-up? 5000)) (car r) (and (pair? (cdr r)) (cadr r)))
        (when (and (eq? (car r) 'welcomed) (not (symbol? (cadddr r)))) (raw-tls-session-close! (cadddr r))))
      (node-disconnect! 'p) (drain-down!)
      (raw-tls-server-stop! srv) (sleep-ms 300))

    ;; ---- M2c(b): proof-a with a WRONG binding -> refused
    (let ((srv (raw-tls-server-start "127.0.0.1" srv-port (in-dir "good.pem") (in-dir "good.key"))))
      (sleep-ms 100)
      (node-connect! 'p "127.0.0.1" srv-port)
      (let ((r (serve-one! srv (lambda (nonce-b cb)
                                 (let ((wrong (bytevector-copy cb))) (bytevector-u8-set! wrong 0 (bitwise-xor 1 (bytevector-u8-ref wrong 0)))
                                   (v5-proof-a secret nonce-b "p" srv-boot wrong))))))
        (check "M2c(b): a welcome with a wrong-binding proof-a is refused (dialer closed, no node-up)" (and (eq? (car r) 'welcomed) (eq? (caddr r) 'peer-closed) (not (expect-up? 2500))) r)
        (when (and (eq? (car r) 'welcomed) (not (symbol? (cadddr r)))) (raw-tls-session-close! (cadddr r))))   ; the fixture's own session
      (node-disconnect! 'p)
      (raw-tls-server-stop! srv) (sleep-ms 300))

    ;; ---- M2c(c): proof-a with the EMPTY binding -> refused
    (let ((srv (raw-tls-server-start "127.0.0.1" srv-port (in-dir "good.pem") (in-dir "good.key"))))
      (sleep-ms 100)
      (node-connect! 'p "127.0.0.1" srv-port)
      (let ((r (serve-one! srv (lambda (nonce-b cb) (v5-proof-a secret nonce-b "p" srv-boot #f)))))
        (check "M2c(c): a welcome with an empty-binding proof-a is refused on a TLS link" (and (eq? (car r) 'welcomed) (eq? (caddr r) 'peer-closed) (not (expect-up? 2500))) r)
        (when (and (eq? (car r) 'welcomed) (not (symbol? (cadddr r)))) (raw-tls-session-close! (cadddr r))))
      (node-disconnect! 'p)
      (raw-tls-server-stop! srv) (sleep-ms 300))

    ;; ---- M6 (mode A) needs a node with tls-ca: a second node cannot start in this
    ;; process, so M6 runs in test/tls-mesh-dial-ca.sc (same fixture, tls-ca given).
    (check "sessions back to zero" (within? 6000 (lambda () (= (tls-live-session-count) 0))) (tls-live-session-count))
    (if (zero? fails)
        (begin (display "ALL TLS-MESH-DIAL TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-DIAL VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
