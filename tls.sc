#!chezscheme
;;; (igropyr tls) -- OPTIONAL outbound TLS for (igropyr http-client).
;;;
;;; The core framework stays dependency-free: this library is the only
;;; place that touches OpenSSL/LibreSSL, and nothing loads it unless a
;;; program imports it and calls (tls-enable!) once at startup:
;;;
;;;   (import (igropyr http-client) (igropyr tls))
;;;   (tls-enable!)
;;;   (http-get "https://example.com/")
;;;
;;; Design: TLS as a pure byte codec, not an I/O owner. The socket, the
;;; event loop, timeouts, and the actor scheduling all stay in libuv /
;;; (igropyr http-client); OpenSSL runs in memory-BIO mode and only ever
;;; transforms bytes:
;;;
;;;   socket ciphertext --BIO_write--> rbio --SSL_read-->  plaintext up
;;;   plaintext down    --SSL_write--> wbio --BIO_read-->  socket out
;;;
;;; The connector registered with set-https-connector! runs inside the
;;; request's own green process right after tcp-read-start!, so it can
;;; drive the handshake with plain receive on #(tcp-data ...) messages
;;; -- no threads, no callbacks, no blocking of other processes.
;;;
;;; Security posture (all non-negotiable for a TLS client):
;;;   - SSL_VERIFY_PEER: handshake fails on an unverifiable chain
;;;   - SSL_set1_host / X509_VERIFY_PARAM_set1_ip_asc: hostname (or IP)
;;;     must match the certificate's SANs
;;;   - TLS >= 1.2 only
;;;   - trust roots from the system store (SSL_CTX_set_default_verify_paths;
;;;     the standard SSL_CERT_FILE / SSL_CERT_DIR overrides apply)
;;; Failures raise the neutral #(tls-error "tls: ...") -- this library
;;; serves any protocol, not just https. The https connector registered
;;; by tls-enable! re-tags them as #(http-client-error "tls: ...") so
;;; the http-client error contract for REQUESTS is unchanged; note that
;;; tls-enable! itself (e.g. a missing system trust store at startup)
;;; raises tls-error directly.
;;;
;;; A CODEC IS ONE-SHOT ONCE IT BREAKS. After close!, or after any failure
;;; that had already touched TLS state, the codec is permanently unusable:
;;; every later encrypt/decrypt fails with a stable message naming the
;;; failure that retired it, without reaching the SSL or BIO objects (the
;;; error-queue bookkeeping around them still runs; what never happens is a
;;; call on a session that has been freed). So an operator
;;; reads one incident and a misuse, not two independent TLS faults. A
;;; failure decided BEFORE OpenSSL is entered -- a segment longer than a C
;;; int -- is the caller's, not the session's, and leaves the codec usable;
;;; split the buffer and carry on.
;;;
;;; One flag, not one per direction. A record-layer failure ends both: the
;;; session may have failed at the protocol level, the inbound stream may
;;; have a hole, and a write-side WANT_READ is deliberately fatal here (see
;;; the renegotiation note below). Keeping the read side "open" would
;;; invite an application to go on writing to a connection both consumers
;;; must discard.
;;;
;;; WHERE THAT FLAG IS TESTED matters as much as that it exists. Safety
;;; comes from reading it INSIDE each non-preemptible region, immediately
;;; before the pointers are used -- never from the check at the entry to
;;; encrypt/decrypt, which exists only so that a retired codec gives the
;;; same answer to every bytevector it is handed, empty ones included. An entry check
;;; answers about a moment that has passed: another process (the
;;; connection's close hook) can free the session between the check and the
;;; SSL_write, or between a completed SSL_write and the drain of the wbio
;;; that follows it. Since freeing also happens in a region, and regions on
;;; one thread cannot interleave, a test inside the region holds for the
;;; whole region -- and only there.
;;;
;;; RETIRING HAPPENS IN THAT SAME REGION wherever a LIVE CODEC could be
;;; used concurrently -- the three record-layer failures -- for the
;;; mirror-image reason: a failure detected inside and recorded after
;;; leaves a gap where the state is already broken and the flag still says
;;; otherwise, and it makes the stored message depend on who got there
;;; first rather than on whose failure came first. Two paths retire
;;; outside their region instead, and may: a setup call that fails, and a
;;; fatal SSL_do_handshake -- no codec exists yet, so this code is the
;;; session's only user, and the handshake needs its alert flushed before
;;; the free. (Buffering ciphertext during the handshake still retires
;;; in-region; it shares that code with the established codec.)
;;;
;;; Sessions are closed by freeing (no close_notify): the client speaks
;;; Connection: close and hard-closes the socket right after, and both
;;; framings it accepts (content-length, chunked) detect truncation by
;;; construction.
;;;
;;; One hazard is specific to running OpenSSL under green processes, and
;;; shapes the code below: the error queue is per OS THREAD, this runtime
;;; has one thread, so EVERY green process shares a single queue.
;;;
;;;   - SSL_get_error is not a function of (ssl, ret) alone. It peeks the
;;;     queue FIRST and answers SSL_ERROR_SSL / SSL_ERROR_SYSCALL for
;;;     whatever it finds there, before it ever consults the SSL object's
;;;     own rwstate. So an entry pushed by an unrelated process between an
;;;     SSL_* call and its SSL_get_error turns that call's verdict into a
;;;     fatal one. Measured on 3.6.3: a handshake step and a read that are
;;;     both genuinely SSL_ERROR_WANT_READ (2) report SSL_ERROR_SSL (1)
;;;     when one foreign entry is planted in the gap. Neither call site
;;;     has a way back from a fatal verdict -- the handshake fails and the
;;;     read retires the codec -- so this closes a live connection rather
;;;     than merely mislabelling one. Each SSL_* call,
;;;     the test of its result, its SSL_get_error and the reading of its
;;;     reason therefore run as one non-preemptible step (ssl-step).
;;;     ONLY that: this library parks in receive and writes to a socket,
;;;     and neither may ever happen with interrupts disabled.
;;;
;;;   - So the queue must be EMPTY when an SSL_* call is made, and this
;;;     library empties it: ERR_clear_error immediately before the call,
;;;     inside the same non-preemptible step. That is the obligation
;;;     OpenSSL documents for anyone who calls SSL_get_error, and it is
;;;     not one brackets can discharge. Measured on 3.6.3: ERR_set_mark
;;;     succeeds, SSL_do_handshake then clears the queue itself -- which
;;;     destroys the mark -- and the closing ERR_pop_to_mark reports "no
;;;     mark" and takes the whole stack. This file used to be bracketed
;;;     that way and say it never deleted another process's entries; on
;;;     OpenSSL 3 it deleted them on every SSL_* call, by way of OpenSSL's
;;;     own clear. Clearing on purpose therefore costs nothing new there,
;;;     and on a libcrypto that does NOT self-clear (1.1, LibreSSL) it
;;;     removes the misverdict described above instead of leaving it to
;;;     chance. Every supported version now behaves identically.
;;;
;;;     A process that leaves errors queued across a yield and expects to
;;;     read them later is already outside SSL_get_error's contract; this
;;;     library does not, and reads its own reasons before releasing the
;;;     step.
;;;
;;;     "SSL_*" above means the three TLS I/O calls and only those:
;;;     SSL_do_handshake, SSL_read, SSL_write. They are what clears the
;;;     queue, and what SSL_get_error is asked about.
;;;
;;;   - Everything else -- SSL_CTX_new, SSL_new, the verification
;;;     parameters, buffering ciphertext into a memory BIO, the
;;;     certificate hashing -- keeps the ERR_set_mark / ERR_pop_to_mark
;;;     brackets, where a mark is real because nothing in those paths
;;;     clears. Those regions do not call SSL_get_error, so a foreign
;;;     entry cannot change their verdict, and their reason extraction
;;;     only PEEKS (see tls-reason), so it can never consume one either.
;;;     (BIO_new itself is called unbracketed; its failure is reported by
;;;     a fixed string, not from the queue.)

(library (igropyr tls)
  (export tls-enable! tls-establish!)
  (import (chezscheme) (igropyr actor) (igropyr platform)
          (only (igropyr libuv) tcp-write! conn-on-close! now-ms)
          (only (igropyr http-client) set-https-connector!))

  ;; ---- shared objects ---------------------------------------------------
  ;; libcrypto first and explicitly: BIO_* / ERR_* / X509_* live there,
  ;; and loading it ourselves guarantees its symbols are visible to
  ;; foreign-procedure regardless of how the platform scopes transitive
  ;; dependencies.


  (define _libcrypto (load-first-shared-object! 'igropyr-tls (shared-object-candidates "libcrypto")))
  (define _libssl    (load-first-shared-object! 'igropyr-tls (shared-object-candidates "libssl")))

  ;; ---- FFI ---------------------------------------------------------------

  (define TLS_client_method (foreign-procedure "TLS_client_method" () void*))
  (define SSL_CTX_new       (foreign-procedure "SSL_CTX_new" (void*) void*))
  (define SSL_CTX_ctrl      (foreign-procedure "SSL_CTX_ctrl" (void* int long void*) long))
  (define SSL_CTX_set_verify (foreign-procedure "SSL_CTX_set_verify" (void* int void*) void))
  (define SSL_CTX_set_default_verify_paths
    (foreign-procedure "SSL_CTX_set_default_verify_paths" (void*) int))

  (define SSL_new           (foreign-procedure "SSL_new" (void*) void*))
  (define SSL_free          (foreign-procedure "SSL_free" (void*) void))
  (define SSL_set_bio       (foreign-procedure "SSL_set_bio" (void* void* void*) void))
  (define SSL_set_connect_state (foreign-procedure "SSL_set_connect_state" (void*) void))
  (define SSL_ctrl/string   (foreign-procedure "SSL_ctrl" (void* int long string) long))
  (define SSL_set1_host     (foreign-procedure "SSL_set1_host" (void* string) int))
  (define SSL_get0_param    (foreign-procedure "SSL_get0_param" (void*) void*))
  (define X509_VERIFY_PARAM_set1_ip_asc
    (foreign-procedure "X509_VERIFY_PARAM_set1_ip_asc" (void* string) int))
  (define SSL_do_handshake  (foreign-procedure "SSL_do_handshake" (void*) int))
  (define SSL_get_error     (foreign-procedure "SSL_get_error" (void* int) int))
  (define SSL_read          (foreign-procedure "SSL_read" (void* u8* int) int))
  (define SSL_write         (foreign-procedure "SSL_write" (void* u8* int) int))

  (define BIO_s_mem         (foreign-procedure "BIO_s_mem" () void*))
  (define BIO_new           (foreign-procedure "BIO_new" (void*) void*))
  (define BIO_read          (foreign-procedure "BIO_read" (void* u8* int) int))
  (define BIO_write         (foreign-procedure "BIO_write" (void* u8* int) int))
  (define BIO_ctrl_pending  (foreign-procedure "BIO_ctrl_pending" (void*) size_t))

  (define ERR_get_error     (foreign-procedure "ERR_get_error" () unsigned-long))
  (define ERR_peek_error    (foreign-procedure "ERR_peek_error" () unsigned-long))
  ;; the LATEST entry, and it does not modify the queue -- the only
  ;; reader a mark/pop region may use; see tls-reason
  (define ERR_peek_last_error
    (foreign-procedure "ERR_peek_last_error" () unsigned-long))
  (define ERR_clear_error   (foreign-procedure "ERR_clear_error" () void))
  (define ERR_error_string_n
    (foreign-procedure "ERR_error_string_n" (unsigned-long u8* size_t) void))
  ;; Error-queue scoping. ERR_set_mark records the current top of the
  ;; per-thread queue; ERR_pop_to_mark drops everything pushed above it,
  ;; and returns 0 having dropped EVERYTHING if the mark is gone -- which
  ;; is what a clear inside OpenSSL does to it. That case used to be
  ;; excused here as "then the queue holds only this region's entries
  ;; anyway"; it is true only if the clear and the region began together,
  ;; and it was being relied on where they did not. The SSL_* path no
  ;; longer uses these at all (see with-ssl-call); the paths that do keep
  ;; them contain nothing that clears.
  (define ERR_set_mark      (foreign-procedure "ERR_set_mark" () int))
  (define ERR_pop_to_mark   (foreign-procedure "ERR_pop_to_mark" () int))
  (define SSL_CTX_free      (foreign-procedure "SSL_CTX_free" (void*) void))
  (define BIO_free          (foreign-procedure "BIO_free" (void*) int))

  ;; peer certificate hash for RFC 5929 tls-server-end-point channel
  ;; binding (OpenSSL 3 renamed the accessor; 1.1 has only the old name)
  (define SSL_get-peer-cert
    (foreign-procedure
      (if (foreign-entry? "SSL_get1_peer_certificate")
          "SSL_get1_peer_certificate"
          "SSL_get_peer_certificate")
      (void*) void*))
  (define X509_free (foreign-procedure "X509_free" (void*) void))
  (define X509_get_signature_nid
    (foreign-procedure "X509_get_signature_nid" (void*) int))
  (define OBJ_find_sigid_algs
    (foreign-procedure "OBJ_find_sigid_algs" (int u8* u8*) int))
  ;; EVP_get_digestbynid is a macro in OpenSSL 3, not an exported symbol:
  ;; go nid -> short name -> digest by name instead
  (define OBJ_nid2sn (foreign-procedure "OBJ_nid2sn" (int) string))
  (define EVP_get_digestbyname
    (foreign-procedure "EVP_get_digestbyname" (string) void*))
  (define EVP_sha256 (foreign-procedure "EVP_sha256" () void*))
  (define X509_digest
    (foreign-procedure "X509_digest" (void* void* u8* u8*) int))

  ;; OpenSSL constants (stable public ABI values)
  (define SSL_VERIFY_PEER 1)
  (define SSL_CTRL_SET_MIN_PROTO_VERSION 123)
  (define TLS1_2_VERSION #x0303)
  (define SSL_CTRL_SET_TLSEXT_HOSTNAME 55)     ; SSL_set_tlsext_host_name
  (define SSL_ERROR_NONE 0)
  (define SSL_ERROR_WANT_READ 2)
  (define SSL_ERROR_ZERO_RETURN 6)

  ;; The length arguments of BIO_write / SSL_write / BIO_read are C int.
  ;; A bytevector longer than that would be truncated by the conversion --
  ;; silently, and into ciphertext, where a lost tail is not a short write
  ;; but a corrupt stream. Anything past this is refused before the FFI.
  (define max-c-int (- (expt 2 31) 1))

  ;; ---- error reporting ---------------------------------------------------

  ;; Does the queue hold an entry pushed since the enclosing scope's mark?
  ;; ERR_count_to_mark answers exactly; it is PROBED rather than assumed,
  ;; because it is not in every libcrypto this library builds against, and
  ;; without it the question degrades to "is the queue non-empty", which
  ;; can attribute a foreign entry to us -- a wrong message, never a
  ;; deletion, since the reader that follows only peeks. (ERR_count_to_mark
  ;; arrived in OpenSSL 3.2, so 3.0 and 3.1 take the degraded path too;
  ;; probing rather than version-testing is what makes that automatic.)
  ;; Used only by the mark/pop regions: the TLS I/O path clears first and
  ;; therefore owns everything it can see (see with-ssl-call).
  (define err-own-entry?
    (if (foreign-entry? "ERR_count_to_mark")
        (let ((f (foreign-procedure "ERR_count_to_mark" () int)))
          (lambda () (fx> (f) 0)))
        (lambda () (not (zero? (ERR_peek_error))))))

  ;; One region per operation: preemption off for its whole extent, and
  ;; the error queue bracketed so the region's own failures are removed
  ;; and nobody else's are. NOTHING inside a scope may park, write to a
  ;; socket, or otherwise block -- it would stop the entire runtime, and
  ;; a process that cannot be preempted cannot be killed. Keep the bodies
  ;; to the OpenSSL calls themselves and act on the result outside.
  ;;
  ;; NOT NESTABLE. On 1.1 and LibreSSL a mark is a flag on the top entry,
  ;; not a counter of marks: two scopes entered around the same top entry
  ;; set the same flag, and the inner ERR_pop_to_mark clears it -- so the
  ;; outer pop finds no mark and takes the whole queue, including entries
  ;; that were there before either scope began. Nothing here nests today;
  ;; keep it that way rather than reasoning about which version forgives it.
  ;;
  ;; It also does NOT cover a call that then asks SSL_get_error what
  ;; happened: see with-ssl-call, which is the form for those.
  (define-syntax with-openssl-scope
    (syntax-rules ()
      ((_ body ...)
       (with-interrupts-disabled
         (dynamic-wind
           (lambda () (ERR_set_mark))
           (lambda () body ...)
           (lambda () (ERR_pop_to_mark)))))))

  ;; THE SSL_* FORM: clear the queue, then call, and own what you find.
  ;;
  ;; SSL_get_error is only meaningful on a queue that held nothing before
  ;; the call -- that is the documented obligation on the CALLER, and this
  ;; library could not meet it with brackets. Measured on 3.6.3: entering
  ;; a region with ERR_set_mark and then calling SSL_do_handshake finds
  ;; the mark GONE afterwards, because SSL_* clears the whole queue on
  ;; entry and a clear destroys marks; ERR_pop_to_mark then returns 0 and
  ;; takes the entire stack. So the brackets that used to be here removed
  ;; other processes' entries anyway, while reading as though they could
  ;; not -- protection in name, a drain in fact.
  ;;
  ;; Clearing explicitly costs nothing that was not already being paid on
  ;; that platform, and buys the two things brackets never delivered: on
  ;; libcryptos that do NOT self-clear (1.1, LibreSSL) a stale entry can
  ;; no longer turn a healthy WANT_READ into a fatal verdict, and every
  ;; version now behaves the same way, which is the only version of this
  ;; that can be described honestly at the top of the file.
  ;;
  ;; Deliberately no ERR_set_mark after the clear: the queue is empty, a
  ;; mark on nothing is not a boundary, and interrupts are off for the
  ;; whole extent -- so everything the queue holds when the body looks was
  ;; put there by this call. Same rules as above about parking and sockets.
  (define-syntax with-ssl-call
    (syntax-rules ()
      ((_ body ...)
       (with-interrupts-disabled
         (ERR_clear_error)
         body ...))))

  (define (bv-prefix->string bv)
    (let ((n (bytevector-length bv)))
      (let loop ((i 0))
        (if (or (= i n) (zero? (bytevector-u8-ref bv i)))
            (utf8->string
              (let ((r (make-bytevector i)))
                (bytevector-copy! bv 0 r 0 i)
                r))
            (loop (+ i 1))))))

  (define (err-entry->string e)
    (let ((buf (make-bytevector 256 0)))
      (ERR_error_string_n e buf 256)
      (bv-prefix->string buf)))

  ;; This region's most recent queued OpenSSL error as text, or default.
  ;; Only valid inside with-openssl-scope: entries below the mark belong to
  ;; another green process, and neither reporting one as ours nor
  ;; consuming it would be right.
  ;;
  ;; PEEK THE LATEST, NEVER GET THE EARLIEST. ERR_get_error is documented
  ;; to return the EARLIEST entry in the thread's queue and to remove it,
  ;; and a mark does not bound it -- so reading a reason with it did the
  ;; two things this region exists to avoid: it reported another process's
  ;; oldest error as this region's failure, and it deleted that error from
  ;; under the process that was going to read it. (Worse where the deleted
  ;; entry was the marked one: the mark went with it, and the closing
  ;; ERR_pop_to_mark then found no mark and took the rest of the queue.)
  ;; ERR_peek_last_error returns the LATEST and modifies nothing, and the
  ;; latest is this region's whenever err-own-entry? is true -- because
  ;; anything pushed after the mark is on top. Nothing is consumed here at
  ;; all; the region's own entries go with the scope's ERR_pop_to_mark.
  ;;
  ;; Where ERR_count_to_mark is missing (before OpenSSL 3.2) the guard
  ;; degrades to "the queue is non-empty", so a foreign entry can still be
  ;; reported as ours -- a wrong message. It cannot be deleted, which is
  ;; the property worth keeping.
  (define (tls-reason default)
    (if (not (err-own-entry?))
        default
        (let ((e (ERR_peek_last_error)))
          (if (zero? e)
              default
              (string-append "tls: " (err-entry->string e))))))

  ;; The whole chain this call left, oldest first. Only valid inside
  ;; with-ssl-call, where the queue was empty on entry: everything in it
  ;; is this call's, so draining takes nothing from anyone.
  ;;
  ;; ONE FAILURE IS USUALLY SEVERAL ENTRIES, and the interesting one is
  ;; not always at either end -- a rejected certificate chain pushes the
  ;; verification failure first and the handshake-level alert on top of
  ;; it, so reporting only the newest names the symptom and only the
  ;; oldest can name something too low to act on. Oldest first, joined,
  ;; is the order OpenSSL's own error printing uses.
  ;;
  ;; Bounded because an error message is a thing that gets logged, not
  ;; because the queue could be huge (OpenSSL caps it at a small fixed
  ;; number of entries): past the cap the rest is still DRAINED -- leaving
  ;; it would hand this call's entries to whoever looks next -- but not
  ;; rendered.
  (define ssl-reason-max 4)

  (define (ssl-drain-reason default)
    (let loop ((n 0) (acc '()))
      (let ((e (ERR_get_error)))
        (cond ((zero? e)
               (if (null? acc)
                   default
                   (let join ((rest (cdr acc)) (out (car acc)))
                     (if (null? rest)
                         (string-append "tls: " out)
                         (join (cdr rest)
                               (string-append (car rest) "; " out))))))
              ((fx>= n ssl-reason-max) (loop n acc))
              (else (loop (fx+ n 1) (cons (err-entry->string e) acc)))))))

  ;; One SSL_* call and its whole classification as a single step with no
  ;; preemption point inside: SSL_get_error must see the error queue
  ;; exactly as the call left it, and a fatal reason must be read from the
  ;; same region. The body raises nothing, parks nowhere and touches no
  ;; socket -- the caller acts on the values after the scope has ended.
  ;; The reason is #f whenever nothing was retired: a positive return, a
  ;; want-read the caller retries, or a clean close_notify.
  ;;
  ;; That set of "not a failure" codes is a property of THIS configuration
  ;; -- a memory BIO, no async engine, no client-certificate callback.
  ;; WANT_WRITE needs a BIO that can push back, and the others need modes
  ;; or callbacks nothing here installs. Adding any of those means
  ;; revisiting this classification.
  ;; -> (values gone rc code reason). `gone` is #f, or the stored message
  ;; of a codec that is already unusable -- in which case the call was NOT
  ;; made and the other three values mean nothing.
  ;;
  ;; THE LIVENESS TEST IS INSIDE THE REGION, and that placement is the
  ;; whole point. Asking before entering would answer about a moment that
  ;; has passed: another process can free the session between the answer
  ;; and the dereference, and this one would then hand a dangling pointer
  ;; to OpenSSL. Inside, the test and the call cannot be separated -- and
  ;; whatever frees does so from a region of its own, so the two can never
  ;; interleave.
  ;; A verdict that BREAKS THE SESSION retires it here, before the region
  ;; ends: a TLS session does not resynchronise past one, and leaving the
  ;; flag for the caller to set after it returns is a window in which the
  ;; state is already finished and the codec still says it is fine.
  ;;
  ;; ZERO_RETURN IS NOT ONE OF THOSE. A close_notify is the peer ending the
  ;; stream cleanly -- an ending, not a fault -- and the caller turns it
  ;; into an ordinary EOF. Retiring on it would file a normal shutdown as
  ;; "a previous failure" and hand that sentence to whoever asked next.
  (define-syntax ssl-step
    (syntax-rules ()
      ((_ dead-expr poison-expr ssl-expr default call)
       (let ((d dead-expr) (p poison-expr) (s ssl-expr))
         (with-ssl-call
           (let ((gone (unbox d)))
             (if gone
                 (values gone 0 SSL_ERROR_NONE #f)
                 (let* ((rc call)
                        (code (if (fx> rc 0) SSL_ERROR_NONE (SSL_get_error s rc))))
                   (cond
                     ((or (fx> rc 0)
                          (fx= code SSL_ERROR_WANT_READ)
                          (fx= code SSL_ERROR_ZERO_RETURN))
                      (values #f rc code #f))
                     (else
                       (let ((reason (ssl-drain-reason default)))
                         (p reason)
                         (values #f rc code reason))))))))))))

  (define (die msg) (raise (vector 'tls-error msg)))

  ;; ---- context (one per program) ------------------------------------------

  (define ctx 0)

  ;; EVERY POSTURE CALL IS CHECKED, because each one of them is a claim
  ;; this file makes at the top and a client cannot verify afterwards.
  ;; SSL_CTX_ctrl returning 0 for the minimum version is the sharp one: it
  ;; leaves a context that negotiates whatever the peer offers, including
  ;; TLS 1.0, under a library that advertises "TLS >= 1.2, non-negotiable".
  ;; A downgrade nobody is told about is worse than a connection refused.
  ;;
  ;; THE REASON IS READ BEFORE THE CLEANUP. SSL_CTX_free is OpenSSL work
  ;; and can push entries of its own; reading the queue after it meant the
  ;; message describing a missing trust store could be one the free left.
  ;; Capture, then free, then raise -- and raise OUTSIDE the scope, which
  ;; is this file's rule everywhere else.
  (define (ensure-ctx!)
    (let ((err
            (with-openssl-scope
              (if (not (zero? ctx))
                  #f
                  (let ((c (SSL_CTX_new (TLS_client_method))))
                    (if (zero? c)
                        (tls-reason "tls: SSL_CTX_new failed")
                        (let ((bad
                                (cond
                                  ((zero? (SSL_CTX_ctrl
                                            c SSL_CTRL_SET_MIN_PROTO_VERSION
                                            TLS1_2_VERSION 0))
                                   (tls-reason "tls: could not require TLS >= 1.2"))
                                  (else
                                    (SSL_CTX_set_verify c SSL_VERIFY_PEER 0)
                                    (and (zero? (SSL_CTX_set_default_verify_paths c))
                                         (tls-reason "tls: no system trust store"))))))
                          (cond
                            (bad
                              ;; free before raising: a caller in a reconnect
                              ;; loop (e.g. a database pool retrying every
                              ;; second) would otherwise leak one SSL_CTX per
                              ;; attempt for the life of the misconfiguration
                              (SSL_CTX_free c)
                              bad)
                            (else (set! ctx c) #f)))))))))
      (when err (die err))))

  ;; ---- helpers -------------------------------------------------------------

  ;; a dotted-quad or colon-hex literal? (then verify as IP, and no SNI)
  (define (ip-literal? host)
    (let ((n (string-length host)))
      (let loop ((i 0) (digits-and-dots #t))
        (if (= i n)
            digits-and-dots
            (let ((ch (string-ref host i)))
              (cond ((char=? ch #\:) #t)     ; any colon: IPv6 literal
                    ((or (char-numeric? ch) (char=? ch #\.))
                     (loop (+ i 1) digits-and-dots))
                    (else (loop (+ i 1) #f))))))))

  ;; everything the wbio holds, as a fresh bytevector (or #f when empty)
  ;;
  ;; BIO_READ'S RETURN VALUE DECIDES THE LENGTH, not BIO_ctrl_pending.
  ;; Sizing the buffer from pending and then keeping all of it assumed the
  ;; read filled it exactly; when it does not, the tail of the bytevector
  ;; is uninitialised memory that goes out on the socket as ciphertext, and
  ;; the bytes actually still in the BIO are dropped. Reading in a loop
  ;; keeps the property that matters: every byte reported is a byte the
  ;; BIO actually handed over, and nothing is invented. The per-read size
  ;; is capped at C int range, which the loop then walks.
  ;;
  ;; TWO CONDITIONS END IT EARLY, and neither loses data -- a memory BIO
  ;; is FIFO, so later output queues behind whatever is left and the next
  ;; drain still emits in order:
  ;;   - a read that delivers nothing while bytes are still pending. This
  ;;     should not happen for a memory BIO, but the loop has to terminate
  ;;     on it rather than spin.
  ;;   - more than C int range accumulated in one call, which bounds the
  ;;     bytevector returned.
  ;; So a caller must not assume one call empties the BIO. Every drain
  ;; site here is reached again -- each handshake step, each decrypt, each
  ;; encrypt -- and what is left goes out on the next one.
  (define (drain-wbio wbio)
    (let loop ((chunks '()) (total 0))
      (let ((n (BIO_ctrl_pending wbio)))
        (if (or (= n 0) (> total max-c-int))
            (and (pair? chunks) (join-chunks (reverse chunks) total))
            (let* ((k (if (> n max-c-int) max-c-int n))
                   (bv (make-bytevector k))
                   (rc (BIO_read wbio bv k)))
              (cond
                ((fx= rc k) (loop (cons bv chunks) (+ total k)))
                ((fx> rc 0)
                 (let ((part (make-bytevector rc)))
                   (bytevector-copy! bv 0 part 0 rc)
                   (loop (cons part chunks) (+ total rc))))
                (else (and (pair? chunks) (join-chunks (reverse chunks) total)))))))))

  (define (join-chunks chunks total)
    (if (null? (cdr chunks))
        (car chunks)
        (let ((out (make-bytevector total)))
          (let loop ((cs chunks) (off 0))
            (if (null? cs)
                out
                (let ((n (bytevector-length (car cs))))
                  (bytevector-copy! (car cs) 0 out off n)
                  (loop (cdr cs) (+ off n))))))))

  ;; Ciphertext INTO a memory BIO: all of it or none of it.
  ;;
  ;; A memory BIO grows to take what it is given, so a short write is not
  ;; backpressure -- it is an allocation failure, and the bytes that did
  ;; not fit are gone from a stream that cannot tolerate a hole. The
  ;; return value used to be discarded at both call sites, so such a
  ;; connection carried on and failed later as a decryption error with no
  ;; trace of where the gap came from.
  ;; -> #f on success, or (kind . message). The caller raises the message;
  ;;   the retiring, where it is due, has already happened in here.
  ;;      'dead  the codec was already unusable; message is the stored one
  ;;      'arg   the CALLER's input was impossible, before OpenSSL was
  ;;             touched -- nothing is broken and a smaller segment works
  ;;      'state the BIO took part of it; the record stream now has a hole,
  ;;             and the codec has been retired inside the region that saw it
  (define (bio-write! dead poison! bio bv)
    (let ((n (bytevector-length bv)))
      (cond
        ((unbox dead) => (lambda (d) (cons 'dead d)))
        ((fx= n 0) #f)
        ((> n max-c-int)
         (cons 'arg "tls: ciphertext segment too large for this platform"))
        (else
          (with-openssl-scope
            (let ((d (unbox dead)))
              (if d
                  (cons 'dead d)
                  (let ((rc (BIO_write bio bv n)))
                    (and (not (fx= rc n))
                         (let ((m (tls-reason
                                    "tls: could not buffer ciphertext")))
                           ;; retired HERE, still inside the region that
                           ;; saw the hole appear
                           (poison! m)
                           (cons 'state m)))))))))))

  ;; The OpenSSL half is scoped; the socket write is not, and must not be.
  ;; Best-effort by design: a dead codec has nothing to flush, and no
  ;; caller of this needs a flush to have happened to be correct.
  (define (flush-out! dead c wbio)
    (let ((out (with-openssl-scope
                 (and (not (unbox dead)) (drain-wbio wbio)))))
      (when out (tcp-write! c out #f))))

  (define empty-bv (make-bytevector 0))

  ;; RFC 5929 tls-server-end-point channel-binding data: the peer
  ;; certificate hashed with its signature hash algorithm, MD5/SHA-1
  ;; upgraded to SHA-256 -- the exact computation PostgreSQL performs
  ;; server-side, so a SCRAM-SHA-256-PLUS client using this value
  ;; interoperates. #f when the hash cannot be determined (no peer
  ;; certificate, or a signature scheme with no retrievable digest).
  (define NID-md5 4)
  (define NID-sha1 64)
  ;; Scoped: several of these push on failure (no peer certificate, an
  ;; unknown signature OID), and this runs once at the end of a handshake
  ;; whose entries nobody is going to read.
  (define (peer-cb-hash dead ssl)
   (with-openssl-scope
    (let ((x (if (unbox dead) 0 (SSL_get-peer-cert ssl))))
      (if (zero? x)
          #f
          (let ((dignid-bv (make-bytevector 4 0))
                (pknid-bv (make-bytevector 4 0)))
            (if (zero? (OBJ_find_sigid_algs (X509_get_signature_nid x)
                                            dignid-bv pknid-bv))
                (begin (X509_free x) #f)
                (let* ((dignid (bytevector-s32-native-ref dignid-bv 0))
                       (md (if (or (= dignid NID-md5) (= dignid NID-sha1))
                               (EVP_sha256)
                               (let ((sn (OBJ_nid2sn dignid)))
                                 (if sn (EVP_get_digestbyname sn) 0)))))
                  (if (zero? md)
                      (begin (X509_free x) #f)
                      (let ((buf (make-bytevector 64 0))
                            (lenbv (make-bytevector 4 0)))
                        (let ((r (X509_digest x md buf lenbv)))
                          (X509_free x)
                          (and (= r 1)
                               (let* ((n (bytevector-u32-native-ref lenbv 0))
                                      (out (make-bytevector n)))
                                 (bytevector-copy! buf 0 out 0 n)
                                 out))))))))))))

  ;; ---- the connector --------------------------------------------------------
  ;;
  ;; Runs inside the request's green process; the socket is read-started,
  ;; so ciphertext arrives here as #(tcp-data ...) messages. Returns the
  ;; codec #(encrypt decrypt close! cb-hash); raises the neutral
  ;; #(tls-error ...) after retiring the session on any failure. (The https
  ;; connector registered by tls-enable! is what re-tags those as
  ;; #(http-client-error ...) and drops the fourth slot; this is the shared
  ;; entry point, and tls-establish! hands the four back unchanged.)

  (define (establish! c host timeout)
    (ensure-ctx!)
    (let ((rbio (BIO_new (BIO_s_mem)))
          (wbio (BIO_new (BIO_s_mem))))
      (when (or (zero? rbio) (zero? wbio))
        ;; free whichever succeeded; ownership passes to the SSL only at
        ;; SSL_set_bio below
        (unless (zero? rbio) (BIO_free rbio))
        (unless (zero? wbio) (BIO_free wbio))
        (die "tls: BIO_new failed"))
      ;; SSL_new and the reading of its failure reason are one scope: the
      ;; reason has to come from this call, not from whatever another
      ;; process happened to leave queued, and must not be eaten from it.
      (let* ((born (with-openssl-scope
                     (let ((s (SSL_new ctx)))
                       (cons s (and (zero? s)
                                    (tls-reason "tls: SSL_new failed"))))))
             (ssl (car born))
             ;; ONE CELL FOR TWO FACTS: #f while the session is usable,
             ;; otherwise the message every later call raises. It is the
             ;; liveness flag the regions above test, and the reason they
             ;; report, deliberately in one place -- a codec that is dead
             ;; and a codec that has something to say about why are the
             ;; same codec.
             (dead (box #f)))
        ;; THE TRANSITION IS INDIVISIBLE, and it frees exactly once.
        ;; Setting a flag and then freeing was two acts: a process killed
        ;; between them left a session that the close hook would skip
        ;; (the flag said "done") and that nothing else would ever free.
        ;; Whoever gets here first inside the region does both or neither.
        (define (retire! msg)
          (with-interrupts-disabled
            (unless (unbox dead)
              (set-box! dead msg)
              (SSL_free ssl))))         ; frees both BIOs too (SSL owns them)
        (define (close!) (retire! "tls: codec is closed"))
        ;; A failure that touched TLS state: the session is finished, and
        ;; the FIRST caller still gets its own message. What is stored is
        ;; the sentence later callers get, and it says plainly that this is
        ;; a second use of a broken codec rather than a second TLS fault --
        ;; the difference between one incident and two in an operator's log.
        ;;
        ;; CALLED WHERE THE FAILURE IS SEEN, inside the same region. Doing
        ;; it after leaving the region left a gap with the state already
        ;; broken and the flag not yet set: another process could enter and
        ;; be told the codec was fine. It also decided the stored message
        ;; by who reached this first rather than by whose failure happened
        ;; first, which are not the same ordering once anyone is preempted.
        (define (poison! msg)
          (retire! (string-append
                     "tls: codec is unusable after previous failure: " msg)))
        (define (fail! msg) (close!) (die msg))
        (when (zero? ssl)
          (BIO_free rbio) (BIO_free wbio)
          (die (cdr born)))
        (SSL_set_bio ssl rbio wbio)
        ;; From here the SSL exists and this process can be killed while
        ;; parked in the handshake receive below -- winders and guards do
        ;; not run then, so freeing cannot be owned by this code path.
        ;; Tie it to the connection instead: the owner-death sweep closes
        ;; the conn, and the close completion runs close! (idempotent, so
        ;; the normal-path free through the codec stays correct).
        (conn-on-close! c close!)
        ;; ...AND IT CAN HAVE RUN ALREADY. conn-on-close! runs the thunk
        ;; immediately when the connection is closed by the time it is
        ;; registered, so close! -- and the SSL_free inside it -- can
        ;; happen on the line above, before anything below has configured
        ;; the session. That is not a race to lose; it is a straight line.
        ;; Everything from here on therefore asks whether the session is
        ;; still there, in the same region where it uses it.
        ;;
        ;; Verification parameters: scoped, so the entries a rejected host
        ;; or IP literal leaves behind cannot outlive this call. The
        ;; messages are fixed strings, so nothing is read from the queue;
        ;; raising happens after the scope, never inside one.
        (let ((setup-err
                (with-openssl-scope
                  (cond
                    ((unbox dead))      ; the stored message, as-is
                    ((ip-literal? host)
                     (and (zero? (X509_VERIFY_PARAM_set1_ip_asc
                                   (SSL_get0_param ssl) host))
                          "tls: bad ip literal"))
                    (else
                      ;; SNI is checked too. It can fail (an allocation,
                      ;; a host name the extension cannot carry), and the
                      ;; result used to be dropped -- so the handshake went
                      ;; ahead WITHOUT the extension, and a virtual host
                      ;; answered with whatever certificate it serves by
                      ;; default. That either fails verification later with
                      ;; a message pointing at the wrong thing, or succeeds
                      ;; against a name nobody asked for.
                      (cond
                        ((zero? (SSL_ctrl/string
                                  ssl SSL_CTRL_SET_TLSEXT_HOSTNAME 0 host))
                         "tls: could not set SNI host name")
                        ((zero? (SSL_set1_host ssl host))
                         "tls: SSL_set1_host failed")
                        (else #f)))))))
          (when setup-err (fail! setup-err)))
        ;; the last configuration call, and the only one that used to sit
        ;; outside a region entirely
        (let ((gone (with-interrupts-disabled
                      (let ((d (unbox dead)))
                        (unless d (SSL_set_connect_state ssl))
                        d))))
          (when gone (die gone)))

        ;; drive the handshake: flush whatever each step produced, wait
        ;; for more ciphertext when OpenSSL wants it
        ;; ABSOLUTE deadline, not a per-segment budget: this receive re-arms
        ;; on every record, so a peer that dribbles one just inside the
        ;; window holds the process, the connection and this SSL session
        ;; open indefinitely at no cost to itself.
        (let ((deadline (+ (now-ms) timeout)))
        (let handshake ()
          ;; Classify BEFORE flushing. The flush used to sit between the
          ;; step and its SSL_get_error, which is the widest form of the
          ;; gap described at the top of this file: draining the wbio is
          ;; itself OpenSSL work, and tcp-write! is a preemption point, so
          ;; any process scheduled there decided whether this handshake
          ;; lived. Nothing needs the flush first: SSL_get_error reads the
          ;; SSL object's rwstate and the error queue, never the wbio's
          ;; contents. It does read the BIOs' retry FLAGS, and reading a
          ;; memory BIO down to empty is what sets those -- so if it has
          ;; to be on one side, this is the correct side.
          ;; THE HANDSHAKE DOES NOT RETIRE IN-REGION, and passes a hook
          ;; that does nothing. Retiring frees the SSL, and the SSL owns
          ;; the wbio -- so poisoning here would throw away the alert that
          ;; the flush below exists to send, and the peer would be left to
          ;; infer the failure from a dropped connection. Nothing is racing
          ;; for this session either: no codec has been handed out, so the
          ;; only user is this code, and fail! retires it a few lines down
          ;; once the alert is gone.
          (let-values (((gone r code reason)
                        (ssl-step dead (lambda (m) (void)) ssl
                                  "tls handshake failed"
                                  (SSL_do_handshake ssl))))
            ;; the connection's close hook can retire this session while
            ;; the handshake is parked below; then there is nothing left
            ;; to hand back and the stored message is the whole answer
            (when gone (die gone))
            ;; Still before anything that blocks, and on the failing path
            ;; too: whatever OpenSSL just produced -- the ClientHello, or
            ;; the alert that explains the failure below -- goes out.
            (flush-out! dead c wbio)
            (cond
              ((= r 1) 'established)
              ((= code SSL_ERROR_WANT_READ)
               (receive (after (max 1 (- deadline (now-ms)))
                           (fail! "tls handshake timeout"))
                 (`#(tcp-data ,bv)
                   ;; every kind is fatal to a HANDSHAKE -- there is no
                   ;; codec yet to keep usable -- so they share fail!
                   (let ((werr (bio-write! dead poison! rbio bv)))
                     (when werr (fail! (cdr werr))))
                   (handshake))
                 (`#(tcp-eof) (fail! "connection closed during tls handshake"))
                 (`#(tcp-error ,e) (fail! "connection error during tls handshake"))))
              ;; ssl-step withholds a reason for a positive return, a
              ;; want-read, and a clean close_notify. The first two are
              ;; handled above; a close_notify DURING a handshake reaches
              ;; here, and the fallback string is what it gets -- an
              ;; unfinished handshake is a failed connection whatever ended
              ;; it, and a clean shutdown leaves no OpenSSL reason to quote
              (else (fail! (or reason "tls handshake failed")))))))

        ;; ---- established: hand back the codec --------------------------
        ;;
        ;; RENEGOTIATION, which this codec half supports -- and the half it
        ;; supports is the one that matters. TLS 1.3 has no renegotiation;
        ;; TLS 1.2 does, and a server can ask for one mid-connection.
        ;;
        ;; THE READ PATH HANDLES IT, and this is measured rather than
        ;; intended: against `openssl s_server -tls1_2` driven to
        ;; renegotiate on command, a client built from this file completes
        ;; the second handshake and goes on to receive the application data
        ;; sent after it. The mechanism is entirely accidental and worth
        ;; writing down because nothing here looks like it does this:
        ;; SSL_read processes the HelloRequest and queues a ClientHello in
        ;; the wbio, decrypt's closing flush-out! puts it on the socket,
        ;; the answering handshake records arrive as ordinary ciphertext
        ;; and go through decrypt again. SSL_write is never involved.
        ;;
        ;; THE WRITE PATH IS THE BOUNDARY. A renegotiation that a SSL_write
        ;; runs into makes it answer WANT_READ, and encrypt treats anything
        ;; short of a full write as fatal, so that connection closes.
        ;;
        ;; Neither half is fixed here, for different reasons.
        ;;
        ;; The write path is not fixed because handling WANT_READ correctly
        ;; means re-issuing the SAME write once the handshake finishes --
        ;; OpenSSL wants the identical pointer, contents and length -- and
        ;; holding the caller's plaintext for later is a state a codec
        ;; whose contract is "bytes in, bytes out" cannot express: a
        ;; successful return from encrypt would have to mean "your data is
        ;; still with me". A HALF FIX IS WORSE THAN NONE: classifying the
        ;; WANT_READ without retrying makes encrypt return empty ciphertext
        ;; for plaintext that was never sent and never will be, which is
        ;; silent data loss. A closed connection is at least visible.
        ;;
        ;; And renegotiation is NOT disabled at the context
        ;; (SSL_OP_NO_RENEGOTIATION), which was tried and reverted: it does
        ;; not narrow the write case, it removes the read case as well. The
        ;; shape of these clients decides which one that costs -- a short
        ;; request and then a long read is what both HTTP and the
        ;; PostgreSQL protocol do, so a server's HelloRequest lands while
        ;; the client is READING, most of the time. Turning the option on
        ;; trades the path that works for the path that does not.
        (let ((scratch (make-bytevector 16384)))
          (define (encrypt bv)
            (let ((n (bytevector-length bv)))
              (cond
                ;; A RETIRED CODEC ANSWERS THE SAME TO EVERY BYTEVECTOR,
                ;; and that is what this first test is for -- not safety,
                ;; which the regions below provide, but a consistent
                ;; answer. Without it an empty buffer would still return
                ;; successfully from a dead codec, and an over-long one
                ;; would report a length complaint about a session that no
                ;; longer exists. (A non-bytevector argument still fails as
                ;; the type error it is, before any of this.)
                ((unbox dead) => die)
                ((zero? n) empty-bv)
                ;; the length argument is a C int; a longer plaintext would
                ;; be truncated by the conversion and the tail silently
                ;; never encrypted.
                ;; THIS ONE DOES NOT RETIRE THE CODEC: it is decided before
                ;; OpenSSL is entered, so no state was touched and the same
                ;; caller can split the buffer and carry on.
                ((> n max-c-int) (die "tls: plaintext segment too large"))
                (else
                  ;; the write and the reading of its reason in one step,
                  ;; for the same reason the handshake needs one; the
                  ;; raise happens after the step
                  (let-values (((gone err)
                                (with-ssl-call
                                  (let ((d (unbox dead)))
                                    (if d
                                        (values d #f)
                                        (values #f
                                                (let ((bad (not (= n (SSL_write ssl bv n)))))
                                                  (and bad
                                                       (let ((m (ssl-drain-reason
                                                                  "tls write failed")))
                                                         ;; retired here, not
                                                         ;; after the region
                                                         (poison! m)
                                                         m)))))))))
                    (when gone (die gone))
                    ;; already retired inside the region that saw it
                    (when err (die err))
                    ;; the drain dereferences the wbio, so it needs the
                    ;; same guard: the session can be retired between the
                    ;; write above and this region
                    (let-values (((gone2 out)
                                  (with-openssl-scope
                                    (let ((d (unbox dead)))
                                      (if d
                                          (values d #f)
                                          (values #f (drain-wbio wbio)))))))
                      (when gone2 (die gone2))
                      (or out empty-bv)))))))
          (define (decrypt raw)
            (cond ((unbox dead) => die))
            ;; only 'state retires the codec: 'arg was decided before
            ;; OpenSSL was entered and leaves the session intact, 'dead
            ;; is the stored message of a session already retired
            (let ((werr (bio-write! dead poison! rbio raw)))
              ;; every kind is raised the same way here; they differ in
              ;; whether the codec was retired, which bio-write! decided
              (when werr (die (cdr werr))))
            (let-values (((p get) (open-bytevector-output-port)))
              (let loop ()
                ;; SSL_read and its SSL_get_error are one step: with a gap
                ;; between them a plain "no more whole records buffered"
                ;; (WANT_READ) reads as SSL_ERROR_SSL and kills a healthy
                ;; connection. Growing the output port is done outside.
                (let-values (((gone n code reason)
                              (ssl-step dead poison! ssl "tls read failed"
                                        (SSL_read ssl scratch 16384))))
                  (cond
                    (gone (die gone))
                    ((> n 0) (put-bytevector p scratch 0 n) (loop))
                    ((= code SSL_ERROR_WANT_READ) 'drained)
                    ((= code SSL_ERROR_ZERO_RETURN)
                     ;; close_notify: the TLS stream is over NOW.
                     ;; A close-wait peer (e.g. openssl s_server)
                     ;; may hold the TCP socket open waiting for
                     ;; our close_notify, so a close-delimited
                     ;; response must not depend on a TCP FIN --
                     ;; synthesize the eof for the client loop.
                     (send self (vector 'tcp-eof)))
                    ;; a fatal read means the inbound record stream is
                    ;; finished -- there is no resynchronising a TLS
                    ;; session past one -- so this retires the codec
                    (else (die (or reason "tls read failed"))))))
              ;; post-handshake protocol output (ticket acks, key updates)
              (flush-out! dead c wbio)
              (get)))
          ;; 4th slot: the tls-server-end-point hash for SCRAM channel
          ;; binding (or #f); https ignores it, the postgresql client
          ;; feeds it into SCRAM-SHA-256-PLUS.
          ;; THE LAST LOOK, and it comes after everything that touches the
          ;; session -- peer-cb-hash included, which silently answers #f
          ;; on a retired one and would otherwise let a codec through on
          ;; the strength of a check made before it.
          ;;
          ;; It is an OBSERVATION, not a promise. The connection can close
          ;; between this line and the vector below, or one instruction
          ;; after establish! returns, and no check anywhere covers that --
          ;; what it does cover is the window that mattered: every point up
          ;; to here that still touches the session. A codec retired
          ;; afterwards is not a hazard, because every call on it raises the
          ;; stored message instead of reaching a freed pointer.
          (let ((cb (peer-cb-hash dead ssl)))
            (cond ((unbox dead) => die))
            (vector encrypt decrypt close! cb))))))

  ;; ---- public entry ---------------------------------------------------------

  (define enabled #f)

  ;; Idempotent; call once at startup, before the first https request.
  ;; The registered connector adapts the neutral #(tls-error ...) raises
  ;; to http-client's own error tag -- for the handshake AND for the
  ;; returned codec's encrypt/decrypt (a post-handshake failure must
  ;; surface its "tls: ..." text, not http-client's generic fallback) --
  ;; preserving http-client's documented contract exactly.
  (define (retag f)
    (lambda (bv)
      (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'tls-error))
                 (raise (vector 'http-client-error (vector-ref e 1)))))
        (f bv))))

  (define (tls-enable!)
    (ensure-ctx!)
    (with-interrupts-disabled
      (unless enabled
        (set-https-connector!
          (lambda (c host timeout)
            (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'tls-error))
                       (raise (vector 'http-client-error (vector-ref e 1)))))
              (let ((codec (establish! c host timeout)))
                (vector (retag (vector-ref codec 0))
                        (retag (vector-ref codec 1))
                        (vector-ref codec 2))))))
        (set! enabled #t)))
    'ok)

  ;; The generic byte-codec connector, for protocols other than https
  ;; that upgrade an established TCP connection to TLS (e.g. the
  ;; PostgreSQL client after SSLRequest). Must run inside the green
  ;; process that owns the read-started connection c; drives the
  ;; handshake on #(tcp-data ...) messages and returns the codec
  ;; #(encrypt decrypt close! cb-hash) -- the first three as described
  ;; above, cb-hash the RFC 5929 tls-server-end-point value for SCRAM
  ;; channel binding (or #f when unavailable). Verification posture is
  ;; identical to https: peer certificate + hostname (or IP) against the
  ;; system trust store, TLS >= 1.2. Raises #(tls-error "tls: ...")
  ;; on failure, after freeing the session.
  (define (tls-establish! c host timeout)
    (establish! c host timeout))
)
