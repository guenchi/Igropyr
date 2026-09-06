#!chezscheme
;;; node-plain-no-ssl.sc -- a plaintext node never opens OpenSSL (design M11).
;;;
;;; Run in its own process: start a node without TLS options, complete a
;;; plaintext mesh handshake by hand, then ask the foreign-symbol table whether
;;; an OpenSSL entry point exists. A #f alone proves nothing (the symbol table
;;; could be empty for other reasons), so the same process then builds a TLS
;;; context on purpose and asks again: the positive control must flip to #t.
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr tcp) tcp-connect! tcp-read-start! tcp-write! tcp-close!)
        (only (igropyr tls-core) tls-mesh-client-context! tls-context-retire!)
        (test mesh-proof))

(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define port 18530)
(define secret "plain-node-test-secret-0123456789abcdef")
(define probe-boot-id "feedfacefeedface")
(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))
(define (read-frame ms)
  (let loop ((acc ""))
    (let* ((n (string-length acc))
           (nl (let scan ((k 0)) (cond ((= k n) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1))))))
           (len (and nl (string->number (substring acc 0 nl)))))
      (if (and len (>= n (+ nl 1 len)))
          (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len))))
          (receive (after ms 'timeout)
            (`#(tcp-data ,bv) (loop (string-append acc (utf8->string bv))))
            (`#(tcp-eof) 'closed) (`#(tcp-error ,e) 'closed))))))
(define (ssl-loaded?) (foreign-entry? "SSL_new"))

(start-scheduler
  (lambda ()
    (register 'main self)
    (node-start! 'a secret port)                    ; no TLS options: a plaintext node
    (monitor-node 'b)
    (check "M11: before any handshake OpenSSL is not loaded" (not (ssl-loaded?)))
    ;; a plaintext handshake by hand (version 5, empty binding)
    (tcp-connect! "127.0.0.1" port self)
    (receive (after 3000 (check "M11: connect" #f 'timeout))
      (`#(tcp-connected ,c)
        (tcp-read-start! c)
        (let ((d (read-frame 4000)))
          (check "M11: challenge received" (and (pair? d) (eq? (car d) 'challenge)) d)
          (when (and (pair? d) (eq? (car d) 'challenge))
            (let ((nonce-a (cadr d)) (version (caddr d)) (bootid-a (cadddr d)))
              (tcp-write! c (frame-bytes (list 'hello "b" (v5-proof-d secret nonce-a "b" probe-boot-id 1 "a" bootid-a #f)
                                              "feedfeedfeedfeedfeedfeedfeedfeed" version probe-boot-id 1)) #f)
              (let ((w (read-frame 4000)))
                (check "M11: plaintext welcome with the empty binding" (and (pair? w) (eq? (car w) 'welcome)) w)
                (when (and (pair? w) (eq? (car w) 'welcome))
                  (check "M11: welcome proof-a is the v5 proof with the empty binding (independent)"
                         (equal? (caddr w) (v5-proof-a secret "feedfeedfeedfeedfeedfeedfeedfeed" "a" bootid-a #f)) (caddr w)))))))
        (receive (after 3000 (void)) (`#(node-up b) 'ok))
        (check "M11: after a plaintext handshake OpenSSL is STILL not loaded" (not (ssl-loaded?)))
        (tcp-close! c))
      (`#(tcp-connect-failed ,e) (check "M11: connect" #f e)))
    ;; positive control: the same process now opens OpenSSL on purpose
    (let ((ctx (tls-mesh-client-context! #f)))
      (check "M11 control: building a TLS context loads OpenSSL (the probe can flip)" (ssl-loaded?))
      (tls-context-retire! ctx))
    (if (zero? fails)
        (begin (display "ALL NODE-PLAIN-NO-SSL TESTS PASSED\n") (exit 0))
        (begin (display "NODE-PLAIN-NO-SSL VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
