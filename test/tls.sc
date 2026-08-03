#!chezscheme
;;; (igropyr tls) test: real TLS against local openssl s_server instances.
;;;   - https:// without (tls-enable!) fails with a clear message
;;;   - verified GET over TLS 1.2+ (trusted CA, SAN IP:127.0.0.1) succeeds
;;;     and the body arrives intact (need-eof framing: s_server -www is
;;;     HTTP/1.0 close-delimited, so this also exercises eof-mode + codec)
;;;   - an untrusted (self-signed) server is REJECTED
;;;   - a certificate for the wrong name is REJECTED even though its
;;;     chain is trusted
;;;   - plain http:// keeps working with the TLS connector registered
;;;
;;; Requires the openssl CLI. Certs are ephemeral (test/tls-certs.sh).

(import (chezscheme) (igropyr http-client) (igropyr tls) (igropyr http)
        (igropyr actor) (igropyr libuv))

(define dir "/tmp/igropyr-tls-test")
(define port-good 18441)
(define port-self 18442)
(define port-wrong 18443)
(define port-plain 18444)

(define (cleanup!)
  (system "pkill -f 's_server -accept 1844' 2>/dev/null"))

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (cleanup!)
  (exit 1))

;; stdout/stderr to /dev/null so a piped test runner sees eof when this
;; scheme process exits; a 30s watchdog reaps the server even if the
;; final pkill cannot deliver signals (sandboxed runs)
(define (s-server! port cert key)
  (system (string-append
            "( openssl s_server -accept " (number->string port)
            " -key " dir "/" key " -cert " dir "/" cert
            " -www -quiet >/dev/null 2>&1 & pid=$!;"
            " sleep 30; kill $pid 2>/dev/null ) &")))

;; the client must only trust the test CA
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))

(system "sh igropyr/test/tls-certs.sh /tmp/igropyr-tls-test")
(cleanup!)

(define (get-error url)
  ;; -> the http-client-error message, or #f if the request succeeded
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'http-client-error))
             (vector-ref e 1)))
    (http-get url '((timeout . 8000)))
    #f))

(start-scheduler
  (lambda ()
    ;; before tls-enable!: https must fail with the pointer message
    (let ((msg (get-error "https://127.0.0.1:18441/")))
      (unless (and msg (string=? msg "https not supported; import (igropyr tls) and call (tls-enable!)"))
        (fail! "https-disabled-message" msg)))
    (display "https without tls-enable! -> clear error ok\n")

    (tls-enable!)
    (s-server! port-good "good.pem" "good.key")
    (s-server! port-self "self.pem" "self.key")
    (s-server! port-wrong "wrong.pem" "wrong.key")
    (sleep-ms 800)                       ; let the servers come up

    ;; verified GET (IP-literal SAN path), close-delimited body
    (let ((r (http-get "https://127.0.0.1:18441/" '((timeout . 8000)))))
      (unless (= (response-status r) 200) (fail! "tls-get-status" (response-status r)))
      (when (zero? (bytevector-length (response-body r))) (fail! "tls-get-empty-body")))
    (display "verified https GET ok\n")

    ;; a second request on a fresh session (session reuse must not break)
    (let ((r (http-get "https://127.0.0.1:18441/" '((timeout . 8000)))))
      (unless (= (response-status r) 200) (fail! "tls-get-2" (response-status r))))
    (display "second https GET ok\n")

    ;; untrusted chain -> refused
    (let ((msg (get-error "https://127.0.0.1:18442/")))
      (unless msg (fail! "self-signed-accepted")))
    (display "self-signed certificate rejected ok\n")

    ;; trusted chain, wrong name -> refused
    (let ((msg (get-error "https://127.0.0.1:18443/")))
      (unless msg (fail! "wrong-host-accepted")))
    (display "wrong-hostname certificate rejected ok\n")

    ;; ---- a DNS hostname, not an IP ------------------------------------
    ;; Every case above connects to 127.0.0.1, which exercises the IP SAN
    ;; path and nothing else: no name is resolved, and the SNI extension
    ;; carries an address rather than a host. The good certificate also
    ;; carries DNS:localhost, so the name path can be walked for real.
    (let ((r (http-get "https://localhost:18441/" '((timeout . 8000)))))
      (unless (= (response-status r) 200)
        (fail! "dns-name-tls" (response-status r))))
    (display "TLS to a DNS name (SNI + DNS SAN) ok\n")

    ;; ...and the name must be CHECKED, not merely sent. The wrong-name
    ;; certificate is for wrong.example, so localhost must be refused --
    ;; the IP case above cannot show this, since an IP mismatch and a name
    ;; mismatch are different comparisons.
    (let ((msg (get-error "https://localhost:18443/")))
      (unless msg (fail! "dns-name-mismatch-accepted")))
    (display "a DNS name that the certificate does not cover is rejected ok\n")

    ;; ---- a handshake that never finishes ------------------------------
    ;; A peer that accepts the TCP connection and then says nothing used to
    ;; be bounded only per segment, so it could hold the caller for as long
    ;; as it kept dribbling. What is asserted is WHEN the call returns.
    (let ((silent-port 18449))
      (tcp-listen! "127.0.0.1" silent-port 4
        (lambda (c)
          ;; accept and stay silent; a process owns it so nothing else
          ;; consumes its messages
          (let ((pid (spawn (lambda ()
                              (receive (after 20000 (tcp-close! c))
                                (`#(tcp-eof) (tcp-close! c))
                                (`#(tcp-error ,e) (tcp-close! c)))))))
            (conn-set-owner! c pid)
            (tcp-read-start! c)))
        0)
      (sleep-ms 100)
      (let* ((t0 (now-ms))
             (msg (get-error (string-append "https://127.0.0.1:"
                                            (number->string silent-port) "/")))
             (ms (- (now-ms) t0)))
        (unless msg (fail! "silent-tls-peer-accepted"))
        (display "  [info] a silent TLS peer gave up after ")
        (display ms) (display " ms\n")
        (when (> ms 20000) (fail! "silent-tls-peer-unbounded" ms))))
    (display "a TLS handshake that never completes is bounded ok\n")

    ;; plain http still works with the connector registered
    (http-listen port-plain
      (lambda (req res) (res-send! res (string->utf8 "plain-ok")))
      2)
    (sleep-ms 50)
    (let ((r (http-get (string-append "http://127.0.0.1:" (number->string port-plain) "/"))))
      (unless (= (response-status r) 200) (fail! "plain-http" (response-status r)))
      (unless (string=? (utf8->string (response-body r)) "plain-ok")
        (fail! "plain-http-body")))
    (display "plain http unaffected ok\n")

    (cleanup!)
    (display "ALL TLS TESTS PASSED\n")
    (exit 0)))
