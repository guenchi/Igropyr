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
;; for the premise probe below: whether a mark survives an SSL_* call
(define ERR_set_mark      (foreign-procedure "ERR_set_mark" () int))
(define ERR_pop_to_mark   (foreign-procedure "ERR_pop_to_mark" () int))
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
(define port-reneg 18445)

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

;; The renegotiation case needs a server it can TALK to: s_server's
;; interactive mode reads commands from its stdin, and "r" on a line of
;; its own makes it renegotiate. -www is not usable for that (its HTTP
;; modes never read stdin), and neither is -quiet: measured, a -quiet
;; server sends the "r" to the client as data instead of acting on it,
;; which produces a run that looks like a result and tested nothing.
;; The log is kept because it is the only place the SECOND handshake is
;; visible from outside the client.
(define reneg-fifo "/tmp/igropyr-tls-test/reneg-fifo")
(define reneg-log "/tmp/igropyr-tls-test/reneg-log")

(define (s-server-interactive! port cert key)
  (system (string-append "rm -f " reneg-fifo " " reneg-log
                         "; mkfifo " reneg-fifo))
  ;; a writer that outlives the server keeps the fifo from seeing eof
  (system (string-append "( sleep 60 > " reneg-fifo " ) &"))
  (system (string-append
            "( openssl s_server -accept " (number->string port)
            " -key " dir "/" key " -cert " dir "/" cert
            " -tls1_2 < " reneg-fifo " > " reneg-log " 2>&1 & pid=$!;"
            " sleep 30; kill $pid 2>/dev/null ) &")))

(define (s-server-say! line)
  (system (string-append "printf '" line "\\n' > " reneg-fifo)))

;; How many RENEGOTIATIONS the server has completed. s_server logs
;; "SSL_do_handshake -> 1" only when it drives a second handshake on an
;; established connection -- the initial one goes through SSL_accept and
;; prints the cipher block instead, so this line counts exactly the thing
;; being tested and nothing else.
(define (server-renegotiation-count)
  (let ((out (string-append reneg-log ".count")))
    (system (string-append "grep -c 'SSL_do_handshake -> 1' "
                           reneg-log " > " out " 2>/dev/null || echo 0 > " out))
    (guard (e (#t 0))
      (let ((n (call-with-input-file out read)))
        (if (number? n) n 0)))))

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

(define (contains? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring s i (+ i m)) sub) #t)
            (else (loop (+ i 1)))))))

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

    ;; ...AND THAT IS WHY THE LIBRARY CLEARS BEFORE EACH SSL_* CALL rather
    ;; than bracketing one with a mark.
    ;;
    ;; THIS IS NOT REGRESSION COVERAGE. It calls OpenSSL directly and
    ;; passes with the library before and after the change; nothing here
    ;; can fail because clear-before-call was removed. What it pins is the
    ;; PREMISE that decision rests on: where SSL_* clears the queue on
    ;; entry, a mark taken just before it is destroyed by the call, and the
    ;; ERR_pop_to_mark that follows finds no mark and empties the whole
    ;; queue -- entries that were there first, belonging to whoever queued
    ;; them, included. The bracket therefore protected nothing on this path
    ;; while reading as though it did, so clearing deliberately gives up
    ;; nothing that was not already being given up.
    ;;
    ;; If this fails, the premise moved rather than the library breaking. A
    ;; surviving mark would restore the bracket's ability to preserve older
    ;; entries -- it would NOT make a dirty queue safe for SSL_get_error,
    ;; which reads the queue and not the mark, and which the control case
    ;; above pins independently. What to revisit then is the cross-process
    ;; ownership cost of clearing and the versions this has to hold for,
    ;; not the classification step itself.
    ;;
    ;; The SSL object is built BEFORE the queue is prepared, so that
    ;; SSL_do_handshake is the first OpenSSL call after the mark and the
    ;; three observations can only be attributed to it.
    (let* ((ctx (SSL_CTX_new (TLS_client_method)))
           (ssl (SSL_new ctx)))
      (SSL_set_bio ssl (BIO_new (BIO_s_mem)) (BIO_new (BIO_s_mem)))
      (SSL_set_connect_state ssl)
      (drain-openssl-errors!)
      (plant-openssl-error!)                       ; somebody else's entry
      (when (zero? (ERR_peek_error))
        (fail! "premise-probe-could-not-plant-an-entry"))
      (let ((marked (ERR_set_mark)))
        (when (zero? marked)
          (fail! "premise-probe-set-mark-refused-a-non-empty-queue" marked))
        (SSL_do_handshake ssl)
        ;; the planted entry is gone, taken by the call's own clear
        (unless (zero? (ERR_peek_error))
          (fail! "premise-probe-foreign-entry-survived-the-call" 'premise-moved))
        ;; ...and with it the mark, so the pop cannot stop where it was told
        (let ((popped (ERR_pop_to_mark)))
          (unless (zero? popped)
            (fail! "premise-probe-mark-survived-the-call" 'premise-moved popped))))
      (drain-openssl-errors!)
      (SSL_free ssl)
      (SSL_CTX_free ctx))
    (display "  [CHARACTERIZATION] an SSL_* call clears the queue and destroys the mark taken before it\n")

    ;; ---- a setter that failed is not a setter that ran ------------------
    ;;
    ;; The SNI extension carries at most 255 bytes of name, and
    ;; SSL_ctrl(SET_TLSEXT_HOSTNAME) refuses a longer one by returning 0 --
    ;; measured here: 255 is accepted, 256 is refused, while SSL_set1_host
    ;; accepts both, so verification is still armed either way. That return
    ;; used to be discarded, and the handshake went out with NO SNI: a
    ;; virtual host would answer with its default certificate, and the only
    ;; thing standing between that and a wrong-certificate connection is a
    ;; check that was never the one meant to carry it.
    ;;
    ;; The one branch among this round's new return checks that stock
    ;; OpenSSL can actually be made to take: the others (the minimum
    ;; protocol version, BIO transfers, the trust store) fail only on
    ;; allocation failure or an OpenSSL built differently, and no honest
    ;; black-box test provokes them.
    (let ()
      (tcp-connect! "127.0.0.1" port-good self)
      (let ((c (receive (after 8000 #f)
                 (`#(tcp-connected ,c) c)
                 (`#(tcp-connect-failed ,e) #f))))
        (unless c (fail! "sni-length-connect-failed"))
        (conn-set-owner! c self)
        (tcp-read-start! c)
        (let ((r (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'tls-error))
                            (vector-ref e 1)))
                   (tls-establish! c (make-string 256 #\a) 8000)
                   #f)))
          (tcp-close! c)
          (let flush () (receive (after 0 'done) (,_ (flush))))
          (when (not r)
            (fail! "a hostname too long for SNI was accepted silently"))
          (display "  [info] over-long SNI name: ") (display r) (newline)
          ;; ...AND IT MUST SAY SO. "It failed" is not the assertion: with
          ;; the return discarded, this same call still fails -- the
          ;; handshake goes out without SNI, SSL_set1_host has armed
          ;; verification against the 256-byte name, and the certificate
          ;; does not match it, so the answer is a verification failure.
          ;; Same verdict, different reason, and asserting only the verdict
          ;; would pass on both sides of the fix while pinning nothing.
          (unless (contains? r "SNI")
            (fail! "an over-long SNI name failed for some other reason" r)))))
    (display "a hostname too long for the SNI extension is refused, not ignored ok\n")


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

    ;; ---- a server-initiated renegotiation is carried by the read path ---
    ;;
    ;; TLS 1.2 lets a server ask for a second handshake mid-connection.
    ;; Nothing in tls.sc looks like it handles that, and yet it works:
    ;; SSL_read processes the HelloRequest and queues a ClientHello in the
    ;; wbio, decrypt's closing flush-out! puts it on the socket, and the
    ;; answering records come back through decrypt as ordinary ciphertext.
    ;; The capability is accidental, which is exactly why it is pinned
    ;; here -- it would otherwise be removed by anyone tightening the
    ;; context's options, and nothing would report it. (Turning on
    ;; SSL_OP_NO_RENEGOTIATION was tried and reverted for this reason.)
    ;;
    ;; TWO OBSERVATIONS, because the obvious one alone proves nothing. The
    ;; client receiving data after the renegotiation is NOT evidence on its
    ;; own: if the server never treated "r" as a command it would send that
    ;; line as data and the rest of the exchange would look identical.
    ;; Measured once, that is exactly what a -quiet server does. So the
    ;; server's own log has to show a SECOND completed handshake, and the
    ;; literal "r" must not arrive as application data.
    (let ()
      (s-server-interactive! port-reneg "good.pem" "good.key")
      (sleep-ms 700)
      (tcp-connect! "127.0.0.1" port-reneg self)
      (let ((c (receive (after 8000 #f)
                 (`#(tcp-connected ,c) c)
                 (`#(tcp-connect-failed ,e) #f))))
        (unless c (fail! "reneg-connect-failed"))
        (conn-set-owner! c self)
        (tcp-read-start! c)
        (let* ((codec (guard (e (#t (fail! "reneg-handshake" e)))
                        (tls-establish! c "127.0.0.1" 8000)))
               (encrypt (vector-ref codec 0))
               (decrypt (vector-ref codec 1)))
          ;; application data before the renegotiation, so the server has
          ;; a live connection to renegotiate ON
          (tcp-write! c (encrypt (string->utf8 "before\n")) #f)
          (sleep-ms 300)
          (let ((renegs-before (server-renegotiation-count)))
            ;; DRIVEN BY OBSERVATION, NOT BY SLEEPING. s_server only looks
            ;; at its stdin between reads, so a command sent while it is
            ;; still busy is simply not seen -- measured: with a fixed
            ;; pause this passed on an idle machine and silently tested
            ;; nothing right after the 320-handshake sweep above. So the
            ;; command is repeated until the server's own log shows the
            ;; second handshake, and the client keeps decrypting
            ;; throughout, because the renegotiation cannot complete
            ;; without it.
            (s-server-say! "r")
            (let loop ((deadline (+ (now-ms) 12000))
                       (seen "")
                       (renegotiated #f)
                       (asked 1)
                       (payload-sent #f))
              (cond
                ((and payload-sent (contains? seen "after-reneg"))
                 (system (string-append "pkill -f 's_server -accept "
                                        (number->string port-reneg) "' 2>/dev/null"))
                 ;; the command must not have been delivered as data --
                 ;; the other way this case can look like it worked
                 (when (contains? seen "r\n")
                   (fail! "the renegotiate command arrived as application data" seen))
                 (display "  [info] server renegotiations: ")
                 (display renegs-before) (display " -> ")
                 (display (server-renegotiation-count)) (newline))
                ((>= (now-ms) deadline)
                 (system (string-append "pkill -f 's_server -accept "
                                        (number->string port-reneg) "' 2>/dev/null"))
                 (if (not renegotiated)
                     (fail! "the server never renegotiated -- the case tested nothing"
                            (list 'before renegs-before
                                  'after (server-renegotiation-count) 'asked asked))
                     (fail! "no application data survived the renegotiation" seen)))
                ((and (not renegotiated)
                      (> (server-renegotiation-count) renegs-before))
                 ;; the second handshake is done: now ask for data across it
                 (s-server-say! "after-reneg")
                 (loop deadline seen #t asked #t))
                (else
                 (receive (after 300
                            ;; still no second handshake: the server was
                            ;; busy when it was asked, so ask again
                            (if (or renegotiated (>= asked 8))
                                (loop deadline seen renegotiated asked payload-sent)
                                (begin (s-server-say! "r")
                                       (loop deadline seen renegotiated
                                             (+ asked 1) payload-sent))))
                   (`#(tcp-data ,bv)
                     (let ((plain (guard (e (#t (fail! "a renegotiation killed the connection" e)))
                                    (decrypt bv))))
                       (loop deadline (string-append seen (utf8->string plain))
                             renegotiated asked payload-sent)))
                   (`#(tcp-eof)
                     (loop 0 seen renegotiated asked payload-sent))
                   (`#(tcp-error ,e)
                     (loop 0 seen renegotiated asked payload-sent))))))))))
    (display "a server-initiated renegotiation is carried by the read path ok\n")

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
