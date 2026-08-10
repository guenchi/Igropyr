#!chezscheme
;;; (igropyr tls) test: real TLS against local openssl s_server instances.
;;;   - https:// without (tls-enable!) fails with a clear message
;;;   - verified GET over TLS 1.2+ (trusted CA, SAN IP:127.0.0.1) succeeds
;;;     and the body arrives intact (need-eof framing: s_server -www is
;;;     HTTP/1.0 close-delimited, so this also exercises eof-mode + codec)
;;;   - an untrusted (self-signed) server is REJECTED
;;;   - a certificate for the wrong name is REJECTED even though its
;;;     chain is trusted
;;;   - a rejection says WHY, in OpenSSL's own words
;;;   - a handshake survives another green process poisoning the shared
;;;     OpenSSL error queue underneath it
;;;   - plain http:// keeps working with the TLS connector registered
;;;
;;; Requires the openssl CLI. Certs are ephemeral (test/tls-certs.sh).

(import (chezscheme) (igropyr http-client) (igropyr tls) (igropyr http)
        (igropyr actor) (igropyr libuv) (igropyr platform))

;; The shared error queue cases below need OpenSSL directly, both to plant
;; a foreign entry and to make the unprotected pairing they are about.
(define _libcrypto
  (load-first-shared-object! 'igropyr-tls-test (shared-object-candidates "libcrypto")))
(define _libssl
  (load-first-shared-object! 'igropyr-tls-test (shared-object-candidates "libssl")))
(define TLS_client_method (foreign-procedure "TLS_client_method" () void*))
(define SSL_CTX_new       (foreign-procedure "SSL_CTX_new" (void*) void*))
(define SSL_CTX_free      (foreign-procedure "SSL_CTX_free" (void*) void))
(define SSL_new           (foreign-procedure "SSL_new" (void*) void*))
(define SSL_free          (foreign-procedure "SSL_free" (void*) void))
(define SSL_set_bio       (foreign-procedure "SSL_set_bio" (void* void* void*) void))
(define SSL_set_connect_state (foreign-procedure "SSL_set_connect_state" (void*) void))
(define SSL_do_handshake  (foreign-procedure "SSL_do_handshake" (void*) int))
(define SSL_get_error     (foreign-procedure "SSL_get_error" (void* int) int))
(define BIO_s_mem         (foreign-procedure "BIO_s_mem" () void*))
(define BIO_new           (foreign-procedure "BIO_new" (void*) void*))
(define ERR_get_error     (foreign-procedure "ERR_get_error" () unsigned-long))
(define ERR_peek_error    (foreign-procedure "ERR_peek_error" () unsigned-long))
(define SSL_ERROR_SSL 1)
(define SSL_ERROR_WANT_READ 2)

;; Push one entry onto the per-thread queue: a NULL method is refused with
;; SSL_R_NULL_SSL_METHOD_PASSED and allocates nothing.
(define (plant-openssl-error!) (SSL_CTX_new 0))
(define (drain-openssl-errors!)
  (let loop ((n 0)) (if (zero? (ERR_get_error)) n (loop (+ n 1)))))

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

(define (prefix? p s)
  (and (>= (string-length s) (string-length p))
       (string=? p (substring s 0 (string-length p)))))

;; A rejection must carry OpenSSL's own reason for it, not the generic
;; fallback text. tls.sc reads that reason out of the shared error queue,
;; and reads only the part of the queue its own call produced: a reader
;; that decides wrongly which entries are its own falls back, and this
;; becomes the bare "tls handshake failed".
(define (reject! label url)
  (let ((msg (get-error url)))
    (unless msg (fail! label 'accepted))
    (unless (prefix? "tls: error:" msg) (fail! label 'no-openssl-reason msg))
    (display "  [info] ") (display label) (display ": ") (display msg) (newline)
    msg))

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
    (reject! "self-signed" "https://127.0.0.1:18442/")
    (display "self-signed certificate rejected ok\n")

    ;; trusted chain, wrong name -> refused
    (reject! "wrong-host" "https://127.0.0.1:18443/")
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
    (reject! "dns-name-mismatch" "https://localhost:18443/")
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

    ;; ---- the OpenSSL error queue is shared by every green process ------
    ;;
    ;; SSL_get_error is not a function of (ssl, ret). It peeks the
    ;; per-OS-THREAD error queue first and answers SSL_ERROR_SSL /
    ;; SSL_ERROR_SYSCALL for whatever it finds there, before it ever
    ;; consults the SSL object's own rwstate. One OS thread here means one
    ;; queue for every green process, so an entry pushed by an unrelated
    ;; process between an SSL_* call and its SSL_get_error rewrites that
    ;; call's verdict -- and the client treats everything but WANT_READ as
    ;; fatal, so a healthy connection dies.
    ;;
    ;; Two halves, because neither says much alone.

    ;; The control: the mechanism, on this OpenSSL, with the same two
    ;; calls the library makes and nothing protecting them. A first
    ;; handshake step against empty memory BIOs honestly wants a read;
    ;; one foreign entry planted in the gap turns that into SSL_ERROR_SSL.
    ;; If this ever passes on its own -- want-read reported through a
    ;; dirty queue -- then OpenSSL changed and the non-preemptible step in
    ;; tls.sc became hygiene rather than correctness. Read it before
    ;; deleting anything.
    (let* ((ctx (SSL_CTX_new (TLS_client_method)))
           (ssl (SSL_new ctx)))
      (SSL_set_bio ssl (BIO_new (BIO_s_mem)) (BIO_new (BIO_s_mem)))
      (SSL_set_connect_state ssl)
      (drain-openssl-errors!)
      (let ((r (SSL_do_handshake ssl)))
        (when (> r 0) (fail! "queue-control-handshake-succeeded" r))
        ;; clean queue: the honest answer
        (let ((clean (SSL_get_error ssl r)))
          (unless (= clean SSL_ERROR_WANT_READ)
            (fail! "queue-control-not-want-read" clean))
          ;; same call, same return value, one foreign entry in the gap
          (plant-openssl-error!)
          (let ((dirty (SSL_get_error ssl r)))
            (unless (= dirty SSL_ERROR_SSL)
              (fail! "queue-control-not-poisoned" 'clean clean 'dirty dirty)))))
      (drain-openssl-errors!)
      (SSL_free ssl)
      (SSL_CTX_free ctx))
    (display "a foreign error-queue entry does flip WANT_READ to fatal ok\n")

    ;; The other direction, the one the sibling crypto suites also pin:
    ;; nothing of this library's own is left on the shared queue for the
    ;; next process to read as its reason. A failing handshake is the
    ;; sharp case -- it is the path that pushes.
    ;;
    ;; Weaker than it looks, and worth saying: measured on this OpenSSL, a
    ;; rejected chain, a peer that answers with HTTP, and a peer that
    ;; answers with garbage each push exactly ONE entry, and reading the
    ;; reason consumes it -- so removing tls.sc's ERR_pop_to_mark does not
    ;; turn this red. It pins the invariant, not that one line. The pop is
    ;; there for the failures that push more than one and for the OpenSSL
    ;; versions that do not clear the queue on entry to SSL_*.
    (let ()
      (define (leaves-nothing label thunk)
        (drain-openssl-errors!)
        (guard (e (#t #t)) (thunk))
        (let ((left (ERR_peek_error)))
          (unless (zero? left) (fail! label 'queue-not-empty left))))
      (leaves-nothing "failed-handshake-leaves-nothing"
        (lambda () (http-get "https://127.0.0.1:18442/" '((timeout . 8000)))))
      (leaves-nothing "successful-handshake-leaves-nothing"
        (lambda () (http-get "https://127.0.0.1:18441/" '((timeout . 8000))))))
    (display "a handshake leaves nothing of its own on the shared queue ok\n")

    ;; The converse -- "an unrelated entry planted BEFORE the handshake is
    ;; still there afterwards", which rsa/aead do assert -- is NOT asserted
    ;; here, and cannot be: SSL_do_handshake, SSL_read and SSL_write each
    ;; call ERR_clear_error on entry in OpenSSL 3 (measured on 3.6.3: a
    ;; planted entry is gone the moment any of the three is called, and the
    ;; ERR_set_mark taken just before it is destroyed with it). That is
    ;; inside OpenSSL, so no scoping on this side can preserve the entry.
    ;; An assertion saying otherwise would only be pinning the version.

    ;; The sweep: the library is immune to it. A green process is switched
    ;; in with a fresh tick budget, so the preemption cannot be aimed by
    ;; waiting for it; but the budget can be REPLACED with set-timer
    ;; immediately before the call, which puts the expiry at a chosen
    ;; distance into the handshake prologue. Walking that distance across
    ;; the prologue, with a second process spinning on OpenSSL errors so
    ;; that whatever runs during the yield poisons the queue, reaches the
    ;; gap. Against the version that flushed the wbio between the step and
    ;; its SSL_get_error this killed the handshakes at ticks 19..23 of
    ;; 1..160, each reporting the poisoner's own "null ssl method passed"
    ;; as a TLS failure; the identical sweep with the poisoner idle was
    ;; clean, so the timer walk by itself is not what breaks it.
    ;;
    ;; What this sweep does NOT show: which half of the fix carries it.
    ;; Measured with the reordering alone and the non-preemptible step
    ;; removed, all 160 offsets still pass -- the remaining gap is two
    ;; adjacent foreign calls with no allocation and no Scheme call
    ;; between them, and this compiler puts no trap check there for the
    ;; expiry to land on. That is a property of code generation, not a
    ;; contract, and the SSL_read pairing has no reordering available to
    ;; it at all, so tls.sc closes the gap explicitly rather than
    ;; inheriting it. No red case here distinguishes the two.
    (let ()
      (define poisoning #f)
      (define (handshake-at-tick k)
        ;; -> #f when the handshake succeeded, else the failure message
        (tcp-connect! "127.0.0.1" port-good self)
        (let ((c (receive (after 8000 #f)
                   (`#(tcp-connected ,c) c)
                   (`#(tcp-connect-failed ,e) #f))))
          (if (not c)
              "connect failed"
              (begin
                (conn-set-owner! c self)
                (tcp-read-start! c)
                (let ((r (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'tls-error))
                                    (vector-ref e 1)))
                           (set-timer k)         ; expiry k ticks from here
                           (tls-establish! c "127.0.0.1" 8000)
                           #f)))
                  (tcp-close! c)
                  ;; this process owns the conn: clear its late messages
                  (let flush () (receive (after 0 'done) (,_ (flush))))
                  r)))))
      (define (sweep lo hi)
        (let loop ((k lo) (bad '()))
          (if (> k hi)
              (reverse bad)
              (loop (+ k 1)
                    (let ((r (handshake-at-tick k)))
                      (if r (cons (cons k r) bad) bad))))))
      (let ((quiet (sweep 1 160)))
        (unless (null? quiet) (fail! "tls-tick-sweep-unpoisoned" quiet)))
      (set! poisoning #t)
      (spawn (lambda ()
               ;; deliberately never parks: it has to be RUNNABLE at the
               ;; instant the handshake yields, or nothing poisons anything
               (let spin () (when poisoning (plant-openssl-error!) (spin)))))
      (let ((poisoned (sweep 1 160)))
        (set! poisoning #f)
        (unless (null? poisoned) (fail! "tls-tick-sweep-poisoned" poisoned))))
    (display "a handshake survives another process poisoning the error queue ok\n")

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
