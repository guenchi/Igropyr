#!chezscheme
;;; tls-mesh-isolation.sc -- the mesh client context must not change how the
;;; HTTPS client verifies (design M13). A mesh context built with no CA turns
;;; verification OFF for the mesh; the https client's context is a different
;;; object with the system trust store and SSL_VERIFY_PEER. If the two were
;;; shared, an untrusted server certificate would suddenly be accepted by
;;; http-get after a mesh context exists. Both construction orders are
;;; exercised: mesh context first, then https; and https first, then mesh.
;;; Needs the openssl CLI (test/tls-certs.sh).
(import (chezscheme) (igropyr actor) (igropyr http) (igropyr http-client) (igropyr tls)
        (only (igropyr tls-core) tls-mesh-client-context! tls-context-retire!))

(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define dir "/tmp/igropyr-tls-mesh-isolation")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))   ; the https client trusts ONLY ca.pem
(define (in-dir f) (string-append dir "/" f))
(define trusted-port 18520)
(define untrusted-port 18521)
(define (handler req res) (res-send! res (string->utf8 "ok")))
(define (https-get port)
  ;; -> 'ok | (cons 'error text)
  (guard (e (#t (cons 'error (if (condition? e) (condition-message e) e))))
    (let ((r (http-get (string-append "https://localhost:" (number->string port) "/") '((timeout . 4000)))))
      (if (eqv? (response-status r) 200) 'ok (cons 'error (response-status r))))))

(start-scheduler
  (lambda ()
    (define trusted (http-listen trusted-port handler (list (cons 'host "127.0.0.1") (cons 'workers 1)
                                                            (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key")))))
    (define untrusted (http-listen untrusted-port handler (list (cons 'host "127.0.0.1") (cons 'workers 1)
                                                                (cons 'tls-cert (in-dir "self.pem")) (cons 'tls-key (in-dir "self.key")))))
    (sleep-ms 200)
    ;; order 1: mesh context (verify none) exists BEFORE the https client is enabled
    (let ((mesh (tls-mesh-client-context! #f)))
      (tls-enable!)
      (check "order 1: https to the trusted server succeeds" (eq? (https-get trusted-port) 'ok) (https-get trusted-port))
      (let ((r (https-get untrusted-port)))
        (check "order 1: https to the untrusted (self-signed) server is REFUSED although a verify-none mesh context exists" (pair? r) r))
      (tls-context-retire! mesh))
    ;; order 2: https client already enabled, then a mesh context with a CA file
    (let ((mesh (tls-mesh-client-context! (in-dir "self.pem"))))
      (check "order 2: https to the trusted server still succeeds" (eq? (https-get trusted-port) 'ok))
      (let ((r (https-get untrusted-port)))
        (check "order 2: https to the untrusted server still refused (the mesh CA is not the https trust store)" (pair? r) r))
      (tls-context-retire! mesh))
    (http-shutdown! trusted) (http-shutdown! untrusted)
    (sleep-ms 200)
    (if (zero? fails)
        (begin (display "ALL TLS-MESH-ISOLATION TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-ISOLATION VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
