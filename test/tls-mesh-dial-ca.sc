#!chezscheme
;;; tls-mesh-dial-ca.sc -- mode A on the dialer: tls-ca given (design M6).
;;;
;;; The node dials the controllable TLS server three times: (i) the server's
;;; certificate is signed by the CA the node trusts and names 127.0.0.1 --
;;; the mesh handshake runs and the link comes up; (ii) the certificate is
;;; self-signed by nobody the node trusts -- the TLS handshake fails, the
;;; server never sees a hello, no node-up; (iii) the certificate is signed by
;;; the CA but names another host -- identity mismatch, same outcome. The
;;; server's view ("did a hello arrive?") is what tells a skipped verification
;;; from a failed one: a dialer that skipped verification would send its
;;; hello to (ii) and (iii). Requires IGROPYR_INJECT=on and the openssl CLI.
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr libuv) now-ms)
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
(define dir "/tmp/igropyr-tls-mesh-dial-ca")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(define (in-dir f) (string-append dir "/" f))
(define node-port 18580)
(define srv-port 18581)
(define secret "tls-mesh-dial-ca-secret-0123456789abcdef")
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
;; -> 'up (hello arrived, welcome sent, node-up seen) | 'no-session (TLS never established) | 'no-hello
(define (dial-and-serve! srv expect-up-ms)
  (let ((ss (raw-tls-server-accept srv 8000)))
    (if (or (pair? ss) (symbol? ss))
        (list 'no-session ss)
        (let ((nonce-a "0123456789abcdef0123456789abcdef") (cb (raw-tls-server-cb-hash srv)))
          (raw-tls-session-send! ss (frame-bytes (list 'challenge nonce-a 5 srv-boot)))
          (let ((h (read-frame ss 5000)))
            (if (not (and (pair? h) (eq? (car h) 'hello) (= (length h) 7)))
                (begin (raw-tls-session-close! ss) (list 'no-hello h))
                (begin
                  (raw-tls-session-send! ss (frame-bytes (list 'welcome "p" (v5-proof-a secret (cadddr h) "p" srv-boot cb))))
                  (let ((up (receive (after expect-up-ms #f) (`#(node-up p) #t))))
                    (list (if up 'up 'welcomed-no-up) ss)))))))))

(start-scheduler
  (lambda ()
    (define (round! label cert key expect)
      (let ((srv (raw-tls-server-start "127.0.0.1" srv-port (in-dir cert) (in-dir key))))
        (sleep-ms 100)
        (node-connect! 'p "127.0.0.1" srv-port)
        (let ((r (dial-and-serve! srv 5000)))
          (check label (eq? (car r) expect) r)
          (when (and (pair? (cdr r)) (not (symbol? (cadr r))) (not (pair? (cadr r)))) (raw-tls-session-close! (cadr r))))
        (node-disconnect! 'p)
        (receive (after 3000 (void)) (`#(node-down p) (void)))
        (raw-tls-server-stop! srv)
        (sleep-ms 400)))
    (register 'main self)
    (node-start! 'a secret node-port "127.0.0.1"
                 (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))
                       (cons 'tls-ca (in-dir "ca.pem"))))            ; mode A: verify peers against ca.pem
    (monitor-node 'p)
    (round! "M6(i): a CA-signed certificate naming 127.0.0.1 -> handshake runs, node-up" "good.pem" "good.key" 'up)
    (round! "M6(ii): a certificate not signed by the CA -> TLS fails, the server never sees a hello" "self.pem" "self.key" 'no-session)
    (round! "M6(iii): a CA-signed certificate naming another host -> identity fails before any hello" "wrong.pem" "wrong.key" 'no-session)
    (check "sessions back to zero" (within? 6000 (lambda () (= (tls-live-session-count) 0))) (tls-live-session-count))
    (if (zero? fails)
        (begin (display "ALL TLS-MESH-DIAL-CA TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-DIAL-CA VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
