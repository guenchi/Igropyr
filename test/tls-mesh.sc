#!chezscheme
;;; tls-mesh.sc -- the node distribution link over TLS, acceptor side.
;;;
;;; A TLS node is started with tls-cert/tls-key; the peer is the interactive
;;; raw TLS client (test/tls-raw-client.sc), which completes the TLS handshake
;;; itself, reads the certificate the node presented, and then drives the
;;; mesh handshake by hand -- challenge -> hello -> welcome -- with proofs from
;;; an INDEPENDENT protocol-5 implementation (test/mesh-proof.sc). So every
;;; assertion about channel binding is made against a value the test computed
;;; from what it saw on the wire, never against the node's own helper.
;;;
;;; Requires IGROPYR_INJECT=on (counters) and the openssl CLI (test/tls-certs.sh).
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr libuv) now-ms)
        (only (igropyr crypto) bytevector->hex hmac-sha256)
        (only (igropyr tls-core) tls-live-context-count tls-live-session-count)
        (only (igropyr tcp) tls-live-watcher-count tls-last-retire-reason)
        (test tls-raw-client) (test mesh-proof))

(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define dir "/tmp/igropyr-tls-mesh-test")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))
(define (in-dir f) (string-append dir "/" f))
(define port 18510)
(define secret "tls-mesh-test-secret-0123456789abcdef")   ; 40 chars: no length warning
(define probe-boot-id "feedfacefeedface")
(define node-name "a")
(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))
;; read one length-prefixed frame from the TLS session; -> datum | 'closed | 'timeout
(define (read-frame s ms)
  (let loop ((acc ""))
    (let* ((n (string-length acc))
           (nl (let scan ((k 0)) (cond ((= k n) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1))))))
           (len (and nl (string->number (substring acc 0 nl)))))
      (if (and len (>= n (+ nl 1 len)))
          (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len))))
          (let ((r (raw-tls-recv! s ms)))
            (cond ((bytevector? r) (loop (string-append acc (utf8->string r))))
                  (else r)))))))                     ; 'closed or 'timeout

;; Drive the mesh handshake over an open TLS session as peer `name` with the
;; given proof-d builder (receives the challenge fields and the peer hash).
;; -> (list outcome welcome-datum) where outcome is 'welcomed | 'refused | 'no-challenge
(define (handshake! s name make-proof-d)
  (let ((d (read-frame s 4000)))
    (if (not (and (pair? d) (eq? (car d) 'challenge) (= (length d) 4)))
        (list 'no-challenge d)
        (let* ((nonce-a (cadr d)) (version (caddr d)) (bootid-a (cadddr d))
               (cb (raw-tls-peer-cb-hash s))
               (proof (make-proof-d nonce-a name bootid-a cb)))
          (raw-tls-send! s (frame-bytes (list 'hello name proof "feedfeedfeedfeedfeedfeedfeedfeed"
                                              version probe-boot-id 1)))
          (let ((w (read-frame s 4000)))
            (if (and (pair? w) (eq? (car w) 'welcome)) (list 'welcomed w cb version bootid-a) (list 'refused w cb version bootid-a)))))))

(define (report-after label)
  ;; a refused handshake must leave nothing behind on the node: its session is
  ;; retired promptly (the count here is process-wide, so the raw client's own
  ;; session must be released by the caller BEFORE this check -- see the
  ;; released?/closed? note in test/tls-raw-client.sc)
  (check (string-append label ": the refused connection's TLS session is retired promptly")
         (within? 3000 (lambda () (= (tls-live-session-count) 0)))
         (tls-live-session-count) (tls-last-retire-reason)))
(define (correct-proof-d nonce-a name bootid-a cb)
  (v5-proof-d secret nonce-a name probe-boot-id 1 node-name bootid-a cb))

(start-scheduler
  (lambda ()
    (register 'main self)
    (let ((base (list (tls-live-context-count) (tls-live-session-count) (tls-live-watcher-count))))
      ;; ---- M12 first: startup failures publish nothing
      (define (start-fails? opts)
        (guard (e (#t #t)) (node-start! 'a secret port "127.0.0.1" opts) #f))
      (check "M12: tls-cert without tls-key is refused" (start-fails? (list (cons 'tls-cert (in-dir "good.pem")))))
      (check "M12: tls-ca without cert/key is refused" (start-fails? (list (cons 'tls-ca (in-dir "ca.pem")))))
      (check "M12: an unreadable certificate file is refused" (start-fails? (list (cons 'tls-cert (in-dir "missing.pem")) (cons 'tls-key (in-dir "good.key")))))
      (check "M12: a mismatched key is refused" (start-fails? (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "self.key")))))
      (check "M12: after the refusals no warden is registered" (not (whereis 'igropyr-node-warden)))
      (check "M12: after the refusals the context count is unchanged" (= (tls-live-context-count) (car base)) (tls-live-context-count) (car base))

      ;; ---- the TLS node
      (node-start! 'a secret port "127.0.0.1"
                   (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))
      (check "M12: a valid start after the refusals works (warden registered)" (within? 3000 (lambda () (whereis 'igropyr-node-warden))))
      (node-set-limits! 64 2)
      (monitor-node 'b)

      ;; ---- M1: correct secret + correct channel binding -> welcome + node-up
      (let ((s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
        (check "M1: the raw client established TLS with the node" (not (pair? s)) s)
        (unless (pair? s)
          (let ((r (handshake! s "b" correct-proof-d)))
            (check "M1: the node answered the challenge with protocol version 5" (eqv? (list-ref r 3) 5) (list-ref r 3))
            (check "M1: the peer certificate hash is available (32 bytes)" (and (bytevector? (list-ref r 2)) (= 32 (bytevector-length (list-ref r 2)))))
            (check "M1: the bound proof-d was welcomed" (eq? (car r) 'welcomed) r)
            (when (eq? (car r) 'welcomed)
              ;; the welcome's proof-a is checked INDEPENDENTLY: over the nonce this
              ;; test sent in hello, the acceptor's name and boot id, and the binding
              (let* ((w (cadr r)) (cb (list-ref r 2)) (bootid-a (list-ref r 4))
                     (expected (v5-proof-a secret "feedfeedfeedfeedfeedfeedfeedfeed" node-name bootid-a cb)))
                (check "M1: welcome names the acceptor" (and (= (length w) 3) (equal? (cadr w) node-name)) w)
                (check "M1: the welcome's proof-a is the channel-bound v5 proof (independent computation)" (equal? (caddr w) expected) (caddr w) expected)))
            (receive (after 3000 (check "M1: node-up for the raw peer" #f 'timeout))
              (`#(node-up b) (check "M1: node-up for the raw peer" #t)))
            (raw-tls-close! s)
            (receive (after 5000 (check "M1: node-down when the raw peer closes" #f 'timeout))
              (`#(node-down b) (check "M1: node-down when the raw peer closes" #t))))))

      ;; ---- M2a: a wrong (nonempty, right-sized) binding is refused
      (let ((s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
        (when (pair? s) (check "open failed" #f (cdr s) (tls-live-session-count)))
        (unless (pair? s)
          (let ((r (handshake! s "b" (lambda (nonce-a name bootid-a cb)
                                       (let ((wrong (bytevector-copy cb)))
                                         (bytevector-u8-set! wrong 0 (bitwise-xor 1 (bytevector-u8-ref wrong 0)))
                                         (v5-proof-d secret nonce-a name probe-boot-id 1 node-name bootid-a wrong))))))
            (check "M2a: a proof-d bound to a different certificate hash is refused (closed, no welcome)" (and (eq? (car r) 'refused) (eq? (cadr r) 'closed)) r))
          (raw-tls-close! s)
          (report-after "M2a")))
      ;; ---- M2b: proofs computed WITHOUT the binding (both spellings) are refused
      (let ((s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
        (when (pair? s) (check "open failed" #f (cdr s) (tls-live-session-count)))
        (unless (pair? s)
          (let ((r (handshake! s "b" (lambda (nonce-a name bootid-a cb)
                                       (v5-proof-d secret nonce-a name probe-boot-id 1 node-name bootid-a #f)))))   ; separator + empty
            (check "M2b: a proof-d with the empty (plaintext) binding is refused on a TLS link" (and (eq? (car r) 'refused) (eq? (cadr r) 'closed)) r))
          (raw-tls-close! s)
          (report-after "M2b-empty")))
      (let ((s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
        (when (pair? s) (check "open failed" #f (cdr s) (tls-live-session-count)))
        (unless (pair? s)
          (let ((r (handshake! s "b" (lambda (nonce-a name bootid-a cb)
                                       ;; no suffix at all: the v4-shaped preimage under version 5
                                       (let ((pre (string-append nonce-a ":" name ":5:" probe-boot-id ":1:" node-name ":" bootid-a)))
                                         (bytevector->hex (hmac-sha256 (string->utf8 secret) (string->utf8 pre))))))))
            (check "M2b: a proof-d with no binding suffix is refused" (and (eq? (car r) 'refused) (eq? (cadr r) 'closed)) r))
          (raw-tls-close! s)
          (report-after "M2b-nosuffix")))

      ;; ---- M9: a hello claiming version 4 is refused by a version-5 node BY THE
      ;; VERSION CHECK: the proof is the CORRECT v5 channel-bound proof, so a node
      ;; that ignored the version field would welcome it (that is the mutant this
      ;; cell is for); a garbage proof would be refused by the proof check and
      ;; prove nothing about the version check.
      (let ((s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
        (when (pair? s) (check "open failed" #f (cdr s)))
        (unless (pair? s)
          (let ((d (read-frame s 4000)))
            (when (and (pair? d) (eq? (car d) 'challenge))
              (let* ((nonce-a (cadr d)) (bootid-a (cadddr d)) (cb (raw-tls-peer-cb-hash s))
                     (proof (correct-proof-d nonce-a "b" bootid-a cb)))
                (raw-tls-send! s (frame-bytes (list 'hello "b" proof "feedfeedfeedfeedfeedfeedfeedfeed" 4 probe-boot-id 1)))
                (let ((w (read-frame s 4000)))
                  (check "M9: a version-4 hello with a correct v5 proof is refused (version checked before the proof)" (eq? w 'closed) w)))))
          (raw-tls-close! s)
          (report-after "M9")))

      ;; ---- resources
      (check "resources back to baseline (sessions, watchers)" (within? 6000 (lambda () (and (= (tls-live-session-count) (cadr base)) (= (tls-live-watcher-count) (caddr base))))) (list (tls-live-session-count) (tls-live-watcher-count)) base)
      (if (zero? fails)
          (begin (display "ALL TLS-MESH TESTS PASSED\n") (exit 0))
          (begin (display "TLS-MESH VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1))))))
