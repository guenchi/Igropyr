#!chezscheme
;;; tls-ws.sc -- a WebSocket upgrade on an HTTPS listener (wss).
;;;
;;; WebSocket frames are written with tcp-write! on the same connection the
;;; upgrade arrived on, and read through the same read callback, so on a TLS
;;; listener they ride the connection's TLS codec with nothing WebSocket-
;;; specific in the TLS path. That is an argument from construction; this
;;; suite is what makes it a result. The client is the raw TLS driver
;;; (test/tls-raw-client.sc): it performs the TLS handshake itself, sends
;;; the upgrade request as ciphertext, and only after the 101 has come back
;;; sends a masked text frame. Everything it reports is what it DECRYPTED, so
;;; a server that wrote a frame in plaintext would not parse as a record and
;;; the exchange would end in a TLS failure, not in an echo.
;;;
;;; Needs the openssl CLI (test/tls-certs.sh mints the certificates).
(import (chezscheme) (igropyr actor) (igropyr http) (igropyr express)
        (igropyr websocket) (test tls-raw-client))

(define fails 0)
(define (fail! label . info)
  (set! fails (+ fails 1))
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok! label) (display "  ok ") (display label) (newline))

(define dir "/tmp/igropyr-tls-ws-test")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))
(define (in-dir f) (string-append dir "/" f))
(define port 18490)

(define (bv-index-of hay needle)
  ;; -> first index of needle in hay, or #f
  (let ((n (bytevector-length hay)) (m (bytevector-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((let cmp ((j 0))
               (or (= j m)
                   (and (= (bytevector-u8-ref hay (+ i j)) (bytevector-u8-ref needle j))
                        (cmp (+ j 1)))))
             i)
            (else (loop (+ i 1)))))))

;; A client text frame: FIN+text, masked, payload < 126 bytes.
(define (masked-text-frame s mask)
  (let* ((p (string->utf8 s)) (n (bytevector-length p))
         (f (make-bytevector (+ 6 n))))
    (bytevector-u8-set! f 0 #x81)
    (bytevector-u8-set! f 1 (bitwise-ior #x80 n))
    (do ((i 0 (+ i 1))) ((= i 4)) (bytevector-u8-set! f (+ 2 i) (bytevector-u8-ref mask i)))
    (do ((i 0 (+ i 1))) ((= i n))
      (bytevector-u8-set! f (+ 6 i)
        (bitwise-xor (bytevector-u8-ref p i) (bytevector-u8-ref mask (mod i 4)))))
    f))

;; The server's echo: FIN+text, unmasked, so the wire form is 0x81, len, bytes.
(define (server-text-frame s)
  (let* ((p (string->utf8 s)) (n (bytevector-length p)) (f (make-bytevector (+ 2 n))))
    (bytevector-u8-set! f 0 #x81)
    (bytevector-u8-set! f 1 n)
    (bytevector-copy! p 0 f 2 n)
    f))

(define app (create-app))
(define seen '())                              ; what the handler received
(app-ws app "/echo"
  (lambda (ws req)
    (let ((m (ws-recv ws)))
      (set! seen (cons m seen))
      (when (and (vector? m) (eq? (vector-ref m 0) 'text))
        (ws-send-text! ws (string-append "echo:" (vector-ref m 1))))
      (ws-close! ws))))

(define upgrade
  (string->utf8
    (string-append
      "GET /echo HTTP/1.1\r\nHost: localhost\r\n"
      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Sec-WebSocket-Version: 13\r\n\r\n")))
(define message "hello over wss")

(start-scheduler
  (lambda ()
    (define srv (app-listen app port
                  (list (cons 'host "127.0.0.1") (cons 'workers 1)
                        (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key")))))
    (sleep-ms 200)
    ;; The raw driver sends the frame once it has received `expect` bytes of
    ;; plaintext: the 101 status line alone is longer than 20 bytes, and
    ;; nothing else can arrive before it, so the frame goes out after the
    ;; handshake response and never before.
    (let-values (((plain writes failure)
                  (raw-tls-two-requests "127.0.0.1" port "localhost"
                                        upgrade (masked-text-frame message (bytevector 1 2 3 4))
                                        20 8000)))
      (let ((status (bv-index-of plain (string->utf8 "HTTP/1.1 101 Switching Protocols")))
            (echo (bv-index-of plain (server-text-frame (string-append "echo:" message))))
            (close-frame (bv-index-of plain (bytevector #x88))))
        (if failure (fail! "wss: the exchange failed" failure) (ok! "wss: the TLS exchange completed without a failure"))
        (if (eqv? status 0) (ok! "wss: the 101 arrived first, decrypted") (fail! "wss: no 101 at the start of the plaintext" status (bytevector-length plain)))
        (if echo (ok! "wss: the server's text frame came back through the codec") (fail! "wss: echoed frame missing from the decrypted stream" (bytevector-length plain)))
        (if (and echo status (> echo status)) (ok! "wss: the echo follows the 101") (fail! "wss: echo did not follow the 101" status echo))
        (if close-frame (ok! "wss: the server's close frame arrived before the connection ended") (fail! "wss: no close frame" (bytevector-length plain)))
        (if (and (pair? seen) (equal? (car seen) (vector 'text message)))
            (ok! "wss: the handler read the client's masked frame as text")
            (fail! "wss: handler saw" seen))))
    (http-shutdown! srv)
    (sleep-ms 200)
    (if (zero? fails)
        (begin (display "ALL TLS-WS TESTS PASSED\n") (exit 0))
        (begin (display "TLS-WS VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
