#!chezscheme
;;; tls-mesh-mixed.sc -- a TLS node and a plaintext peer, both directions (M4, M5).
;;;
;;; Neither direction has a transport-mismatch classifier (design 4.5): what
;;; the code promises is that both fail CLOSED and bounded, that the TLS side
;;; never falls back to plaintext, and that the dialer's failure category is
;;; reported. M4: this TLS node dials a plaintext listener (a fixture that
;;; sends a plaintext challenge on accept) -- the listener must only ever see
;;; TLS bytes, the attempt must fail with a reported category, and a later
;;; retry must still be TLS. M5: a plaintext client connects to this TLS node
;;; -- both sides wait, the client gets no challenge, and the node's session
;;; is gone within its handshake bound. Needs IGROPYR_INJECT=on and openssl.
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr libuv) now-ms)
        (only (igropyr tcp) tcp-listen! tcp-stop-listen! tcp-connect! tcp-read-start! tcp-write! tcp-close! conn-set-owner!
              tls-live-watcher-count)
        (only (igropyr tls-core) tls-live-session-count))

(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define (has-substr? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0)) (cond ((> (+ i m) n) #f) ((string=? (substring s i (+ i m)) sub) #t) (else (loop (+ i 1)))))))
(define dir "/tmp/igropyr-tls-mesh-mixed")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(define (in-dir f) (string-append dir "/" f))
(define node-port 18540)
(define plain-port 18541)
(define secret "tls-mesh-mixed-secret-0123456789abcdef")
(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))

(start-scheduler
  (lambda ()
    (register 'main self)
    (node-start! 'a secret node-port "127.0.0.1"
                 (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))
    (monitor-node 'p)
    (let ((base (list (tls-live-session-count) (tls-live-watcher-count))) (main self))

      ;; ---- M4: TLS dialer -> plaintext listener
      (let* ((seen (box '()))                      ; first bytes of every accepted connection
             (l (tcp-listen! "127.0.0.1" plain-port 16
                  (lambda (c)
                    (let ((pid (spawn (lambda ()
                                        (tcp-read-start! c)
                                        ;; a plaintext acceptor sends its challenge at once
                                        (tcp-write! c (frame-bytes (list 'challenge (make-string 32 #\a) 5 "feedfacefeedface")) #f)
                                        (receive (after 8000 (void))
                                          (`#(tcp-data ,bv) (set-box! seen (cons bv (unbox seen))) (send main (vector 'plain-saw bv)))
                                          (`#(tcp-eof) (send main (vector 'plain-eof)))
                                          (`#(tcp-error ,e) (send main (vector 'plain-eof))))
                                        (tcp-close! c)))))
                      (conn-set-owner! c pid)))))
             (errbuf (open-output-string)) (old-err (console-error-port)))
        ;; the node reports dial failures on the CONSOLE error port
        (console-error-port errbuf)
        (node-connect! 'p "127.0.0.1" plain-port)
        ;; first attempt: the listener must see TLS bytes, never a plaintext hello
        (receive (after 8000 (check "M4: the plaintext listener received something from the TLS dialer" #f 'nothing))
          (`#(plain-saw ,bv)
            (check "M4: what the TLS dialer sent is a TLS record (0x16 0x03), not a plaintext frame" (and (>= (bytevector-length bv) 2) (= (bytevector-u8-ref bv 0) #x16) (= (bytevector-u8-ref bv 1) #x03)) (bytevector-u8-ref bv 0)))
          (`#(plain-eof) (check "M4: the dialer closed before sending anything (expected a ClientHello first)" #f)))
        (receive (after 3000 (void)) (`#(node-up p) (check "M4: no node-up across a transport mismatch" #f)))
        (check "M4: the failure category was reported once on the error port" (within? 8000 (lambda () (has-substr? (get-output-string errbuf) "TLS"))) (get-output-string errbuf))
        ;; a later retry (backoff >= 3 s) is STILL TLS: no plaintext fallback
        (let ((first-count (length (unbox seen))))
          (check "M4: a retry arrived and was again a TLS record (no plaintext fallback)"
                 (within? 12000 (lambda () (and (> (length (unbox seen)) first-count)
                                                (let ((bv (car (unbox seen)))) (and (>= (bytevector-length bv) 2) (= (bytevector-u8-ref bv 0) #x16))))))
                 (length (unbox seen))))
        (console-error-port old-err)
        (node-disconnect! 'p)
        (tcp-stop-listen! l)
        (sleep-ms 500))

      ;; ---- M5: plaintext dialer -> this TLS node
      (let ((me self))
        (tcp-connect! "127.0.0.1" node-port self)
        (receive (after 3000 (check "M5: connect" #f 'timeout))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            ;; a plaintext dialer waits for a challenge; the TLS node waits for a ClientHello
            (receive (after 3000 (check "M5: no plaintext challenge arrives from a TLS node (both wait)" #t))
              (`#(tcp-data ,bv) (check "M5: no plaintext challenge arrives from a TLS node" #f (bytevector-length bv)))
              (`#(tcp-eof) (check "M5: the TLS node did not close within 3 s on its own (it waits for the handshake)" #t)))
            (check "M5: no node-up for a plaintext peer" (not (receive (after 500 #f) (`#(node-up ,x) x))))
            (tcp-close! c)
            (check "M5: the node's session for the plaintext peer is gone within the handshake bound" (within? 12000 (lambda () (= (tls-live-session-count) (car base)))) (tls-live-session-count) base))
          (`#(tcp-connect-failed ,e) (check "M5: connect" #f e))))

      (check "resources back to baseline" (within? 8000 (lambda () (and (= (tls-live-session-count) (car base)) (= (tls-live-watcher-count) (cadr base))))) (list (tls-live-session-count) (tls-live-watcher-count)) base))
    (if (zero? fails)
        (begin (display "ALL TLS-MESH-MIXED TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-MIXED VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
