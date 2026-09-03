#!chezscheme
;;; (igropyr tls-core) -- OpenSSL/LibreSSL primitives, shared by the client
;;; codec in (igropyr tls) and by the server-side connection codec.
;;;
;;; ⭐ THIS LIBRARY EXISTS TO BREAK A DEPENDENCY CYCLE, and that is its whole
;;; reason for being. (igropyr tls) drives a socket, so it imports
;;; (igropyr libuv); the server-side codec lives inside libuv and has to
;;; drive SSL, so it needs these primitives. Had they stayed in (igropyr tls)
;;; the two libraries would have had to import each other. Everything here is
;;; therefore free of any transport: it imports (chezscheme) and
;;; (igropyr platform) and nothing else, and it must stay that way -- an
;;; import of (igropyr libuv) added to this file recreates the cycle.
;;;
;;; What lives here: the FFI bindings and their constants; the error-queue
;;; discipline (with-openssl-scope / with-ssl-call and the reason readers);
;;; one handshake step (tls-step!); the single free (tls-session-retire!) and the
;;; live-session counter behind it; and context construction for both roles
;;; -- ensure-ctx! for the client, tls-listen-context! for a listener.
;;;
;;; What does NOT live here: anything that reads or writes a socket. The
;;; byte plumbing that only moves BIO contents around (drain-wbio,
;;; bio-write!) is still in (igropyr tls); it has no transport dependency
;;; either and can move here when the server codec needs it.
;;;
;;; The posture claims this file makes -- TLS >= 1.2, peer verification for
;;; the client, renegotiation refused for a listener -- are documented at
;;; ensure-ctx! and tls-listen-context! respectively.

(library (igropyr tls-core)
  (export
          ;; ⭐ NO OpenSSL ENTRY POINT IS EXPORTED. Everything a caller can do
          ;; to a live session it does through the operations below, which take
          ;; the session object; the SSL*, the BIOs and the raw bindings stay
          ;; inside this library. (Still API curation, not a sandbox -- see the
          ;; note at the session record.)
          ;;
          ;; session lifetime and operations
          tls-session? tls-session-new! tls-session-retire! tls-session-poison!
          tls-session-dead
          tls-session-configure-client! tls-session-configure-server!
          tls-session-handshake-step! tls-session-drain! tls-session-feed!
          tls-session-encrypt! tls-session-decrypt! tls-session-peer-cb-hash
          ;; errors
          die tls-reason
          ;; seams
          tls-live-session-count tls-error-attribution
          client-ctx ensure-ctx! tls-listen-context! tls-context-retire!
          tls-context? tls-live-context-count
          tls-context-renegotiation-refused?
          )
  ;; ⭐ (igropyr inject) IS A COMPILE-TIME ONLY DEPENDENCY WHEN OFF -- the same
  ;; arrangement libuv.sc documents. Its macros expand to the guarded
  ;; expression or to nothing unless IGROPYR_INJECT was on when this file was
  ;; compiled, so an ordinary build refers to none of its runtime part.
  ;;
  ;; ⚠ (igropyr libuv) MUST NOT APPEAR HERE. That is the whole reason this
  ;; library exists; adding it recreates the cycle it was split out to break.
  (import (chezscheme) (igropyr platform) (igropyr inject))

  ;; ---- OpenSSL entry points, bound on first use -------------------------
  ;;
  ;; ⭐ THESE ARE MUTABLE AND START #f, AND BOTH HALVES OF THAT MATTER.
  ;;
  ;; MUTABLE, because Chez resolves a foreign-procedure at BIND time, not at
  ;; call time: an unresolvable symbol raises where the define is evaluated.
  ;; Binding them at library-invoke time would therefore make libcrypto and
  ;; libssl a hard requirement of every program that reaches this library --
  ;; and libuv imports it, so that is every program. TLS is documented as
  ;; optional, so a plain-HTTP program on a machine with no OpenSSL has to
  ;; start normally. Nothing here touches a shared object until
  ;; ensure-loaded! runs, which is on the first call of ANY of these
  ;; wrappers -- context and session construction are the usual first
  ;; callers, but an exported wrapper called directly loads just as well.
  ;;
  ;; #f, so that a path which somehow reaches one of these before
  ;; ensure-loaded! fails immediately and locally rather than calling into
  ;; whatever the symbol would have been.
  ;;
  ;; ⚠ Being assigned also means they CANNOT be exported (R6RS forbids
  ;; exporting an assigned variable), which is the property that keeps the
  ;; raw FFI inside this library -- the same rule that keeps ctx and
  ;; live-sessions in. Callers get the session and context operations below.


  (define ffi-bound? #f)

  ;; ⭐ THE EXPORTED NAME IS A PROCEDURE, AND IT IS NEVER ASSIGNED. Chez
  ;; resolves a foreign-procedure at BIND time, so binding these at
  ;; library-invoke time would make libcrypto/libssl a hard requirement of
  ;; every program that reaches this library -- and libuv imports it, so
  ;; that is every program, while TLS is documented as optional. Each name
  ;; is therefore a closure that resolves its entry point on first call.
  ;;
  ;; The assignment is to the INNER f, not to the exported name: R6RS
  ;; forbids exporting an assigned variable, and making these mutable
  ;; top-level variables (the obvious way to write this) is rejected by the
  ;; expander with "attempt to export assigned variable". Measured, not
  ;; guessed -- that error is what sent this through a closure.
  ;;
  ;; Cost is one boolean test and one indirect call per FFI call, against
  ;; the cost of a crypto operation.
  (define-syntax define-ffi
    (syntax-rules ()
      ((_ name fp)
       (define name
         (let ((f #f))
           (lambda args
             (unless f (ensure-loaded!) (set! f fp))
             (apply f args)))))))

  ;; Idempotent, and the single place a shared object is loaded. A failure
  ;; here is reported with its reason and leaves ffi-bound? #f, so a later
  ;; call tries again rather than running against half-bound entry points.
  (define (ensure-loaded!)
    (unless ffi-bound?
      (load-first-shared-object! 'igropyr-tls (shared-object-candidates "libcrypto"))
      (load-first-shared-object! 'igropyr-tls (shared-object-candidates "libssl"))
      (set! ffi-bound? #t)))


  ;; ---- shared objects ---------------------------------------------------
  ;; libcrypto first and explicitly: BIO_* / ERR_* / X509_* live there,
  ;; and loading it ourselves guarantees its symbols are visible to
  ;; foreign-procedure regardless of how the platform scopes transitive
  ;; dependencies.



  ;; ---- FFI ---------------------------------------------------------------

  (define-ffi TLS_client_method (foreign-procedure "TLS_client_method" () void*))
  (define-ffi SSL_CTX_new       (foreign-procedure "SSL_CTX_new" (void*) void*))
  (define-ffi SSL_CTX_ctrl      (foreign-procedure "SSL_CTX_ctrl" (void* int long void*) long))
  (define-ffi SSL_CTX_set_verify (foreign-procedure "SSL_CTX_set_verify" (void* int void*) void))
  (define-ffi SSL_CTX_set_default_verify_paths
    (foreign-procedure "SSL_CTX_set_default_verify_paths" (void*) int))

  (define-ffi SSL_new           (foreign-procedure "SSL_new" (void*) void*))
  (define-ffi SSL_free          (foreign-procedure "SSL_free" (void*) void))
  (define-ffi SSL_set_bio       (foreign-procedure "SSL_set_bio" (void* void* void*) void))
  (define-ffi SSL_set_connect_state (foreign-procedure "SSL_set_connect_state" (void*) void))
  (define-ffi SSL_ctrl/string   (foreign-procedure "SSL_ctrl" (void* int long string) long))
  (define-ffi SSL_set1_host     (foreign-procedure "SSL_set1_host" (void* string) int))
  (define-ffi SSL_get0_param    (foreign-procedure "SSL_get0_param" (void*) void*))
  (define-ffi X509_VERIFY_PARAM_set1_ip_asc
    (foreign-procedure "X509_VERIFY_PARAM_set1_ip_asc" (void* string) int))
  (define-ffi SSL_do_handshake  (foreign-procedure "SSL_do_handshake" (void*) int))
  (define-ffi SSL_get_error     (foreign-procedure "SSL_get_error" (void* int) int))
  (define-ffi SSL_read          (foreign-procedure "SSL_read" (void* u8* int) int))
  (define-ffi SSL_write         (foreign-procedure "SSL_write" (void* u8* int) int))
  (define-ffi SSL_shutdown      (foreign-procedure "SSL_shutdown" (void*) int))
  ;; Both OpenSSL and LibreSSL export this as a real function (verified
  ;; here: crypto.h:181 declares it, libcrypto exports it, and it returns
  ;; 0x30600030 on the 3.6.3 this is developed against).
  (define-ffi OpenSSL_version_num
    (foreign-procedure "OpenSSL_version_num" () unsigned-long))

  ;; ---- server side ------------------------------------------------------
  ;; Bound here, unused by the client half. A context built by
  ;; tls-listen-context! is a SERVER context: it presents a certificate
  ;; and does not verify a peer, which is the exact opposite posture from
  ;; ensure-ctx! above -- the two must never be interchanged.
  (define-ffi TLS_server_method (foreign-procedure "TLS_server_method" () void*))
  (define-ffi SSL_set_accept_state
    (foreign-procedure "SSL_set_accept_state" (void*) void))
  (define-ffi SSL_CTX_use_certificate_chain_file
    (foreign-procedure "SSL_CTX_use_certificate_chain_file" (void* string) int))
  (define-ffi SSL_CTX_use_PrivateKey_file
    (foreign-procedure "SSL_CTX_use_PrivateKey_file" (void* string int) int))
  (define-ffi SSL_CTX_check_private_key
    (foreign-procedure "SSL_CTX_check_private_key" (void*) int))
  ;; ⚠ THE WIDTH IS uint64_t ON OpenSSL 3 AND unsigned long ON 1.1.1 AND
  ;; LibreSSL. Those are the same 64-bit word on every LP64 platform this
  ;; library builds on, which is what makes one binding serve all three;
  ;; on an ILP32 target it would not, and this binding would need a
  ;; per-version split. Anchored to OpenSSL 3.6.3 ssl.h:630.
  (define-ffi SSL_CTX_set_options
    (foreign-procedure "SSL_CTX_set_options" (void* unsigned-long) unsigned-long))

  (define-ffi BIO_s_mem         (foreign-procedure "BIO_s_mem" () void*))
  (define-ffi BIO_new           (foreign-procedure "BIO_new" (void*) void*))
  (define-ffi BIO_read          (foreign-procedure "BIO_read" (void* u8* int) int))
  (define-ffi BIO_write         (foreign-procedure "BIO_write" (void* u8* int) int))
  (define-ffi BIO_ctrl_pending  (foreign-procedure "BIO_ctrl_pending" (void*) size_t))

  (define-ffi ERR_get_error     (foreign-procedure "ERR_get_error" () unsigned-long))
  (define-ffi ERR_peek_error    (foreign-procedure "ERR_peek_error" () unsigned-long))
  ;; the LATEST entry, and it does not modify the queue -- the only
  ;; reader a mark/pop region may use; see tls-reason
  (define-ffi ERR_peek_last_error
    (foreign-procedure "ERR_peek_last_error" () unsigned-long))
  (define-ffi ERR_clear_error   (foreign-procedure "ERR_clear_error" () void))
  (define-ffi ERR_error_string_n
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
  (define-ffi ERR_set_mark      (foreign-procedure "ERR_set_mark" () int))
  (define-ffi ERR_pop_to_mark   (foreign-procedure "ERR_pop_to_mark" () int))
  (define-ffi SSL_CTX_free      (foreign-procedure "SSL_CTX_free" (void*) void))
  (define-ffi BIO_free          (foreign-procedure "BIO_free" (void*) int))

  ;; peer certificate hash for RFC 5929 tls-server-end-point channel
  ;; binding (OpenSSL 3 renamed the accessor; 1.1 has only the old name)
  (define-ffi SSL_get-peer-cert
    (foreign-procedure
      (if (foreign-entry? "SSL_get1_peer_certificate")
          "SSL_get1_peer_certificate"
          "SSL_get_peer_certificate")
      (void*) void*))
  (define-ffi X509_free (foreign-procedure "X509_free" (void*) void))
  (define-ffi X509_get_signature_nid
    (foreign-procedure "X509_get_signature_nid" (void*) int))
  (define-ffi OBJ_find_sigid_algs
    (foreign-procedure "OBJ_find_sigid_algs" (int u8* u8*) int))
  ;; EVP_get_digestbynid is a macro in OpenSSL 3, not an exported symbol:
  ;; go nid -> short name -> digest by name instead
  (define-ffi OBJ_nid2sn (foreign-procedure "OBJ_nid2sn" (int) string))
  (define-ffi EVP_get_digestbyname
    (foreign-procedure "EVP_get_digestbyname" (string) void*))
  (define-ffi EVP_sha256 (foreign-procedure "EVP_sha256" () void*))
  (define-ffi X509_digest
    (foreign-procedure "X509_digest" (void* void* u8* u8*) int))

  ;; OpenSSL constants (stable public ABI values)
  (define SSL_VERIFY_PEER 1)
  (define SSL_CTRL_SET_MIN_PROTO_VERSION 123)
  (define TLS1_2_VERSION #x0303)
  (define SSL_CTRL_SET_TLSEXT_HOSTNAME 55)     ; SSL_set_tlsext_host_name
  (define SSL_ERROR_NONE 0)
  (define SSL_ERROR_WANT_READ 2)
  (define SSL_ERROR_ZERO_RETURN 6)
  (define SSL_ERROR_WANT_WRITE 3)
  (define SSL_FILETYPE_PEM 1)            ; x509.h: X509_FILETYPE_PEM
  ;; ssl.h:436 SSL_OP_BIT(30); ssl.h:350 SSL_OP_BIT(n) = (uint64_t)1 << n
  (define SSL_OP_NO_RENEGOTIATION (bitwise-arithmetic-shift-left 1 30))

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
  ;; ⛔ THE PROBE MUST NOT RUN AT LIBRARY-INVOKE TIME. It once did, and it
  ;; was correct then only because this file used to load libcrypto eagerly
  ;; two forms above: foreign-entry? was asked its question with the library
  ;; already in the process. Once loading became lazy, the same expression
  ;; ran against a process that had never opened libcrypto, always answered
  ;; #f, and PERMANENTLY selected the degraded branch -- on every platform,
  ;; including the OpenSSL 3.6 this is developed against, and silently:
  ;; error attribution just gets weaker, nothing fails. Loading OpenSSL
  ;; afterwards never reconsidered the choice.
  ;;
  ;; So the selection is deferred exactly like the entry points are: decided
  ;; once, on first use, after ensure-loaded! has run.
  ;; ⭐ THE CHOICE IS RECORDED, NOT RE-DERIVABLE. A cell has to be able to
  ;; see WHICH implementation this actually selected; a seam that answered
  ;; by probing foreign-entry? a second time would be asking its own
  ;; question at its own moment, and would answer 'mark-count even in a
  ;; build whose selection was made too early -- the mutation this exists
  ;; to catch would be invisible to it. What is published below is this
  ;; variable, set exactly where the decision is taken.
  (define err-attribution #f)          ; 'mark-count | 'queue-nonempty

  (define err-own-entry?
    (let ((impl #f))
      (lambda ()
        (unless impl
          (ensure-loaded!)
          (if (foreign-entry? "ERR_count_to_mark")
              (let ((f (foreign-procedure "ERR_count_to_mark" () int)))
                (set! err-attribution 'mark-count)
                (set! impl (lambda () (fx> (f) 0))))
              (begin
                (set! err-attribution 'queue-nonempty)
                (set! impl (lambda () (not (zero? (ERR_peek_error))))))))
        (impl))))

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

  ;; ONE HANDSHAKE STEP, CLASSIFIED -- the core the client driver below and
  ;; the server's read-callback driver both run. Two values: a verdict and
  ;; its payload, where the verdict is one of
  ;;
  ;;   done | want-read | want-write | error | gone
  ;;
  ;; `gone` is the session having been retired under us (the payload is the
  ;; stored message); it is separated from `error` because the two call for
  ;; opposite actions -- there is nothing left to close, and nothing to say
  ;; about OpenSSL's queue.
  ;;
  ;; ⚠ want-write IS UNREACHABLE TODAY and is still a verdict of its own.
  ;; The write BIO is an unbounded memory BIO, so OpenSSL never has to stop
  ;; for room. It is named rather than folded into `error` so that a driver
  ;; which one day writes into a bounded sink fails loudly at a case it does
  ;; not handle, instead of finding that a silently-impossible branch has
  ;; quietly become possible.
  ;;
  ;; THE CALLER FLUSHES, NOT THIS. Classification has to happen before the
  ;; write BIO is drained (see the handshake loop for why that ordering is
  ;; load-bearing), so draining cannot be folded in here.
  (define (tls-step! dead poison! ssl default)
    (let-values (((gone r code reason)
                  (ssl-step dead poison! ssl default (SSL_do_handshake ssl))))
      (cond
        (gone                            (values 'gone gone))
        ((fx> r 0)                       (values 'done #f))
        ((fx= code SSL_ERROR_WANT_READ)  (values 'want-read #f))
        ((fx= code SSL_ERROR_WANT_WRITE) (values 'want-write reason))
        (else                            (values 'error reason)))))

  (define (die msg) (raise (vector 'tls-error msg)))

  ;; ---- session lifetime ---------------------------------------------------
  ;;
  ;; Incremented once per SSL that exists, decremented in tls-session-retire! and
  ;; nowhere else, so that a session freed by a path which forgot to go
  ;; through the single free shows up as a count that never comes back down.
  (define live-sessions 0)

  ;; -> a new SSL for this context, or 0. THE COUNT IS TAKEN HERE because the
  ;; decrement is in tls-session-retire! just below: keeping the two ends of the
  ;; counter in one file is what makes a leak visible as a count that never
  ;; comes back down. A caller that reached for SSL_new directly would open a
  ;; session this counter never saw.
  ;; ⭐ THE SSL POINTER DOES NOT LEAVE THIS LIBRARY AS A BARE VALUE. SSL_new
  ;; and SSL_free are not exported, so creation and retirement are the two
  ;; procedures below and a cooperating caller has no third way in.
  ;;
  ;; ⚠ THIS IS API CURATION, NOT A SECURITY BOUNDARY, and the difference
  ;; matters enough to write down. Any caller may import this library and
  ;; bind SSL_free itself with foreign-procedure, or call the exported
  ;; SSL_CTX_set_verify on the client context and turn verification off for
  ;; every later connection. Against hostile code in the same process no
  ;; export list can be a sandbox. What this prevents is accidental misuse
  ;; by cooperating modules, which is the whole of the claim.
  ;; The ssl field is mutable because retirement detaches it before the free
  ;; -- v3's "clear the pointer, then free" -- so a retired session reads as
  ;; #f rather than as a dangling pointer.
  ;;
  ;; dead is the liveness cell: #f while the session is usable, otherwise the
  ;; message every later call raises. It is a box because the client codec's
  ;; regions already read and write it directly.
  ;; rbio/wbio are held for access only: SSL_set_bio hands OWNERSHIP to the
  ;; SSL, so SSL_free frees them and nothing here ever frees them again.
  ;; After retirement the ssl field is #f and these two are dangling, which
  ;; is why every operation below tests the session before dereferencing.
  ;;
  ;; scratch is per session rather than shared: the read loop fills it inside
  ;; a region, and one buffer shared between sessions would be a second
  ;; session's plaintext in the first one's port if the two ever interleaved.
  (define-record-type tls-session
    (fields (mutable ssl) dead rbio wbio scratch)
    (nongenerative)
    (sealed #t))

  ;; -> a session, or #f when OpenSSL could not make one (the caller reads
  ;; the reason in its own scope).
  ;;
  ;; ⭐ THE ORDER IS SSL_new -> COUNT -> RECORD, AND IT IS NOT ARBITRARY.
  ;; make-tls-session allocates, so a kill can land between the count and
  ;; the record. The SSL is then genuinely orphaned -- nothing holds it and
  ;; nothing can ever retire it -- and this order has already counted it.
  ;; The reverse order (record first, then count) loses that same leak from
  ;; the count. What this counter measures is live native SSL allocations,
  ;; not reachable session records -- so counting that orphan is not an
  ;; over-count, it is the accurate reading, and the reverse order is a
  ;; genuine under-count. A leak that is not counted is a leak no cell can
  ;; see.
  ;;
  ;; There is no window on the other side: SSL_new is a foreign call, a kill
  ;; cannot land inside it, and the increment follows it without allocating.
  ;;
  ;; ⚠ DO NOT TIDY THESE TWO LINES INTO THE OTHER ORDER. They look
  ;; interchangeable and are not: the difference is invisible in every
  ;; ordinary run, and shows up only as a leak the instrument stops seeing.
  (define (tls-session-new! c)
    (ensure-loaded!)
    (let ((p (and (tls-context? c) (tls-context-ptr c))))
      (unless p (die "tls: context has been retired"))
      ;; allocated OUTSIDE the region: 16 KiB inside a scope would be the one
      ;; allocation in it that is not an OpenSSL call.
      (let* ((scratch (make-bytevector 16384))
             (r (with-openssl-scope
                  (let ((rbio (BIO_new (BIO_s_mem)))
                        (wbio (BIO_new (BIO_s_mem))))
                    (if (or (zero? rbio) (zero? wbio))
                        (begin
                          ;; free whichever succeeded: ownership passes to the
                          ;; SSL only at SSL_set_bio below
                          (unless (zero? rbio) (BIO_free rbio))
                          (unless (zero? wbio) (BIO_free wbio))
                          (cons "tls: BIO_new failed" #f))
                        (let ((s (SSL_new p)))
                          (if (zero? s)
                              ;; the reason must come from THIS call, read in
                              ;; the same scope, and not be eaten by the frees
                              (let ((why (tls-reason "tls: SSL_new failed")))
                                (BIO_free rbio) (BIO_free wbio)
                                (cons why #f))
                              (begin
                                (set! live-sessions (fx+ live-sessions 1))
                                (SSL_set_bio s rbio wbio)
                                (cons #f (make-tls-session
                                           s (box #f) rbio wbio scratch))))))))))
        (when (car r) (die (car r)))
        (cdr r))))

  ;; A failure that touched TLS state: the session is finished, and the FIRST
  ;; caller still gets its own message. What is stored is the sentence later
  ;; callers get, and it says plainly that this is a second use of a broken
  ;; codec rather than a second TLS fault.
  (define (tls-session-poison! sess msg)
    (tls-session-retire!
      sess (string-append "tls: codec is unusable after previous failure: " msg)))

  ;; ⛔ THE GUARD IS THE SSL FIELD, NOT THE MESSAGE. An earlier version
  ;; tested (unbox dead), which conflates "has something to say" with "has
  ;; been retired" -- two different facts that happen to travel together on
  ;; the client's paths because it always passes a string. Retiring with
  ;; msg = #f freed the SSL and decremented the counter while leaving dead
  ;; #f, so the NEXT retire passed the guard too: counter to -1, a second
  ;; free attempted, and (zero? #f) raising a type error on the way. The
  ;; field that is actually being consumed is the one that must gate the
  ;; consumption, and it is set to #f in the same indivisible region.
  ;;
  ;; A caller who passes no message still gets a dead session that says so:
  ;; the message is defaulted rather than trusted to be truthy.
  (define (tls-session-retire! sess msg)
    (with-interrupts-disabled
      (let ((ssl (tls-session-ssl sess)))
        (when ssl
          (tls-session-ssl-set! sess #f)   ; detach before the free
          (set-box! (tls-session-dead sess)
                    (or msg "tls: session retired"))
          (set! live-sessions (fx- live-sessions 1))
          (unless (zero? ssl)
            (SSL_free ssl))))))            ; frees both BIOs too (SSL owns them)

  ;; ---- session operations ------------------------------------------------
  ;;
  ;; ⭐ EVERY OpenSSL CALL ON A LIVE SESSION GOES THROUGH ONE OF THESE. They
  ;; take the session object, never a bare SSL*, so a caller cannot reach the
  ;; pointer, cannot free it, and cannot use one that has been retired: each
  ;; entry point tests the liveness cell inside the same region it uses the
  ;; pointer in. What is left outside this library is the transport -- sockets,
  ;; timeouts, actor messages -- which is the whole of the cut.

  ;; Client posture on a fresh session. -> #f, or the message to raise.
  ;; Split from tls-session-new! so the caller can tie the free to its
  ;; connection between the two: the session exists after the constructor and
  ;; a kill can land before this runs.
  (define (tls-session-configure-client! sess host)
    (let ((ssl (tls-session-ssl sess))
          (dead (tls-session-dead sess)))
      (or (with-openssl-scope
            (cond
              ((unbox dead))
              ((not ssl) "tls: session has been retired")
              ((ip-literal? host)
               (and (zero? (X509_VERIFY_PARAM_set1_ip_asc
                             (SSL_get0_param ssl) host))
                    "tls: bad ip literal"))
              (else
                ;; SNI is checked too: it can fail, and a handshake that went
                ;; ahead WITHOUT the extension gets whatever certificate the
                ;; virtual host serves by default.
                (cond
                  ((zero? (SSL_ctrl/string
                            ssl SSL_CTRL_SET_TLSEXT_HOSTNAME 0 host))
                   "tls: could not set SNI host name")
                  ((zero? (SSL_set1_host ssl host))
                   "tls: SSL_set1_host failed")
                  (else #f)))))
          ;; the last configuration call, in its own region
          (with-interrupts-disabled
            (let ((d (unbox dead)))
              (unless d (SSL_set_connect_state ssl))
              d)))))

  ;; Server posture: the mirror of the above, and the only other way a session
  ;; is put into a handshake state.
  (define (tls-session-configure-server! sess)
    (with-interrupts-disabled
      (let ((d (unbox (tls-session-dead sess))))
        (unless d (SSL_set_accept_state (tls-session-ssl sess)))
        d)))

  ;; One handshake step. Two values: verdict and payload (see tls-step!).
  (define (tls-session-handshake-step! sess retire-on-failure?)
    (tls-step! (tls-session-dead sess)
               (if retire-on-failure?
                   (lambda (m) (tls-session-poison! sess m))
                   (lambda (m) (void)))
               (tls-session-ssl sess)
               "tls handshake failed"))

  ;; Everything the write BIO holds, or #f. Never retires: a drain on a dead
  ;; session simply has nothing to give.
  (define (tls-session-drain! sess)
    (with-openssl-scope
      (and (not (unbox (tls-session-dead sess)))
           (tls-session-ssl sess)
           (drain-wbio (tls-session-wbio sess)))))

  ;; Feed ciphertext in. -> #f, or (kind . message); kind is 'arg when nothing
  ;; was touched and 'state when the session was retired by the failure.
  (define (tls-session-feed! sess bv)
    (bio-write! (tls-session-dead sess)
                (lambda (m) (tls-session-poison! sess m))
                (tls-session-rbio sess) bv))

  ;; Plaintext in, ciphertext out. Raises the stored message on a dead session.
  (define (tls-session-encrypt! sess bv)
    (let ((ssl (tls-session-ssl sess))
          (dead (tls-session-dead sess))
          (n (bytevector-length bv)))
      (cond
        ;; A RETIRED SESSION ANSWERS THE SAME TO EVERY BYTEVECTOR. Without
        ;; this an empty buffer would return successfully from a dead session.
        ((unbox dead) => die)
        ((zero? n) empty-bv)
        ;; the length argument is a C int; a longer plaintext would be
        ;; truncated by the conversion and its tail never encrypted. Decided
        ;; before OpenSSL is entered, so the session stays usable.
        ((> n max-c-int) (die "tls: plaintext segment too large"))
        (else
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
                                                 (tls-session-poison! sess m)
                                                 m)))))))))
            (when gone (die gone))
            (when err (die err))
            (or (tls-session-drain! sess) empty-bv))))))

  ;; Ciphertext in. Two values: the plaintext read out, and #t when the peer's
  ;; close_notify ended the stream.
  ;;
  ;; ⭐ THE close_notify IS REPORTED, NOT ACTED ON. Synthesising the transport
  ;; EOF is the caller's business -- it owns the socket and the mailbox -- and
  ;; doing it here would put an actor send inside this library.
  (define (tls-session-decrypt! sess raw)
    (let ((ssl (tls-session-ssl sess))
          (dead (tls-session-dead sess))
          (scratch (tls-session-scratch sess)))
      (cond ((unbox dead) => die))
      (let ((werr (tls-session-feed! sess raw)))
        (when werr (die (cdr werr))))
      (let-values (((port get) (open-bytevector-output-port)))
        (let loop ((eof? #f))
          (let-values (((gone n code reason)
                        (ssl-step dead (lambda (m) (tls-session-poison! sess m))
                                  ssl "tls read failed"
                                  (SSL_read ssl scratch 16384))))
            (cond
              (gone (die gone))
              ((> n 0) (put-bytevector port scratch 0 n) (loop eof?))
              ((= code SSL_ERROR_WANT_READ) (values (get) eof?))
              ((= code SSL_ERROR_ZERO_RETURN) (values (get) #t))
              ;; a fatal read finishes the inbound record stream -- a TLS
              ;; session cannot be resynchronised past one
              (else (die (or reason "tls read failed")))))))))

  ;; RFC 5929 tls-server-end-point, or #f.
  (define (tls-session-peer-cb-hash sess)
    (peer-cb-hash (tls-session-dead sess) (tls-session-ssl sess)))

  (meta define tls-seam-mode
    (let ((v (getenv "IGROPYR_INJECT")))
      (if (and v (string=? v "on")) 'on 'off)))

  ;; A cell reads this to see a session that was never freed. It is gated so
  ;; that an ordinary build cannot be measured by it at all: a build that
  ;; answers 0 because the counter was compiled out reads exactly like a
  ;; build with nothing leaking.
  (meta-cond
    ((eq? tls-seam-mode 'on)
     (define (tls-live-session-count)
       (with-interrupts-disabled live-sessions)))
    (else
     (define (tls-live-session-count)
       (assertion-violation 'tls-live-session-count
         "test seam: this artifact was expanded without IGROPYR_INJECT=on"))))

  ;; -> 'mark-count | 'queue-nonempty: which error-attribution implementation
  ;; err-own-entry? settled on. Forcing the decision here is deliberate --
  ;; the value is #f until something asks -- and it is read back rather than
  ;; recomputed, so a build that decided at the wrong moment reports the
  ;; answer it actually decided on. Calling err-own-entry? only peeks or
  ;; counts; it consumes nothing from the error queue.
  ;; -> how many SSL_CTX this library currently holds. +1 at construction,
  ;; -1 in tls-context-retire!, the same shape as the session counter.
  (meta-cond
    ((eq? tls-seam-mode 'on)
     (define (tls-live-context-count)
       (with-interrupts-disabled live-contexts)))
    (else
     (define (tls-live-context-count)
       (assertion-violation 'tls-live-context-count
         "test seam: this artifact was expanded without IGROPYR_INJECT=on"))))

  ;; -> whether THIS context actually had SSL_OP_NO_RENEGOTIATION applied.
  ;;
  ;; ⭐ IT READS THE RECORDED FACT AND DOES NOT RECOMPUTE THE VERSION TEST. A
  ;; seam that re-derived the answer would run its own test at its own moment
  ;; and agree with itself, so a build whose version test is wrong would still
  ;; report "refused" -- the mutation this exists to catch would be invisible.
  ;; Same discipline as tls-error-attribution.
  (meta-cond
    ((eq? tls-seam-mode 'on)
     (define (tls-context-renegotiation-refused? c)
       (tls-context-reneg-refused? c)))
    (else
     (define (tls-context-renegotiation-refused? c)
       (assertion-violation 'tls-context-renegotiation-refused?
         "test seam: this artifact was expanded without IGROPYR_INJECT=on"))))

  (meta-cond
    ((eq? tls-seam-mode 'on)
     (define (tls-error-attribution)
       (err-own-entry?)
       err-attribution))
    (else
     (define (tls-error-attribution)
       (assertion-violation 'tls-error-attribution
         "test seam: this artifact was expanded without IGROPYR_INJECT=on"))))

  ;; ---- context (one per program) ------------------------------------------

  ;; ---- byte plumbing and certificate helpers (moved from (igropyr tls)
  ;; in stage 2a: they touch OpenSSL, so they belong on this side of the
  ;; cut; nothing here reads or writes a socket) --------------------------

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

  (define empty-bv (make-bytevector 0))

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

  ;; ---- contexts ----------------------------------------------------------
  ;;
  ;; ⭐ A CONTEXT IS A RECORD BECAUSE RETIREMENT HAS TO BE ENFORCEABLE. Handing
  ;; back the bare SSL_CTX* could not be: Scheme passes it by value, so freeing
  ;; it cannot clear the caller's copy, retiring the same address twice was a
  ;; double free with nothing able to notice, and any integer at all could be
  ;; handed to the retire procedure and reach native code. The pointer field is
  ;; mutable and swapped to #f by retirement, so a second retire is a no-op and
  ;; a use after retirement is a checked error rather than a dereference of
  ;; freed memory.
  ;;
  ;; reneg-refused? records, at construction, whether SSL_OP_NO_RENEGOTIATION
  ;; was actually applied -- see tls-listen-context! for why that has to be a
  ;; recorded fact rather than something recomputed later.
  (define-record-type tls-context
    (fields (mutable ptr) reneg-refused?)
    (nongenerative)
    (sealed #t))

  (define live-contexts 0)

  (define ctx #f)

  ;; The client context is read by the establish! path in (igropyr tls).
  ;; It is handed out through a procedure because ensure-ctx! assigns it,
  ;; and an assigned variable cannot be exported. What comes back is the
  ;; RECORD: the bare pointer never leaves this library.
  (define (client-ctx) ctx)

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
    (ensure-loaded!)
    (let ((err
            (with-openssl-scope
              ;; ⛔ THE GATE READS THE POINTER FIELD, NOT MERELY WHETHER A
              ;; CONTEXT OBJECT EXISTS. When this tested a bare non-zero
              ;; pointer, retiring the client singleton left the variable
              ;; non-zero, so this branch decided the context was still good
              ;; and never rebuilt it -- and every later client session ran
              ;; against freed memory. Retirement now sets the field to #f,
              ;; which is exactly the condition that must cause a rebuild.
              (if (and ctx (tls-context-ptr ctx))
                  #f
                  (let ((c (SSL_CTX_new (TLS_client_method))))
                    (if (zero? c)
                        (tls-reason "tls: SSL_CTX_new failed")
                        (begin
                          ;; ⭐ COUNTED AT ALLOCATION, for the reason spelled
                          ;; out at the listener constructor: a context
                          ;; abandoned between here and publication has leaked,
                          ;; and a counter that only learns about it on the
                          ;; success path reads 0 for exactly the failure it
                          ;; exists to expose.
                          (with-interrupts-disabled
                            (set! live-contexts (fx+ live-contexts 1)))
                          ;; ⭐ THE COMPENSATION COVERS ALLOCATION TO
                          ;; PUBLICATION. Until ctx holds the record, nothing
                          ;; else in the process can reach this context, so a
                          ;; non-local exit here would leak it with no owner
                          ;; and no way to observe it but the counter.
                          (guard (e (#t (discard-context! c) (raise e)))
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
                                  ;; attempt for the life of the misconfiguration.
                                  ;; This returns normally, so the guard above
                                  ;; does not also fire.
                                  (discard-context! c)
                                  bad)
                                (else
                                  ;; INJECTION POINT 'tls-client-context-after-alloc
                                  ;; -- OWNING GUARD: the compensation guard just
                                  ;; above, which discards the context and
                                  ;; re-raises. Placed before publication, which
                                  ;; is the window the guard exists for.
                                  (inject-fault! 'tls-client-context-after-alloc)
                                  ;; the client context deliberately does NOT
                                  ;; refuse renegotiation: the read path carries
                                  ;; a server-initiated one (see (igropyr tls)).
                                  (set! ctx (make-tls-context c #f))
                                  #f)))))))))))
      (when err (die err))))

  ;; ---- server context (one per listener) ----------------------------------
  ;;
  ;; -> an SSL_CTX presenting this certificate chain and key. THE POSTURE IS
  ;; THE MIRROR OF ensure-ctx!: a server presents a certificate and does not
  ;; verify the peer, so SSL_VERIFY_PEER and the trust store are deliberately
  ;; absent here. Requiring TLS >= 1.2 is the one posture the two share.
  ;;
  ;; EVERY LOAD IS CHECKED AND EVERY MESSAGE NAMES ITS FILE. A context that
  ;; half-loaded is a listener that starts and then fails every handshake
  ;; with an error pointing at the peer; the operator needs to be told which
  ;; of the two paths was wrong, at startup, before a listener exists.
  ;;
  ;; check_private_key is not redundant with the two loads: they each succeed
  ;; on a well-formed file, and it is the only thing that says the key and
  ;; the leaf certificate belong together.
  ;;
  ;; Renegotiation is refused on the context (TLS 1.3 has none; TLS 1.2 lets
  ;; a client ask, and answering costs a full handshake's work per request).
  ;;
  ;; ALPN is not advertised: with no ALPN the protocol is HTTP/1.1 by
  ;; default, which is what this server speaks.
  ;;
  ;; The reason is read before the cleanup and raised outside the scope, for
  ;; the reason ensure-ctx! gives above.
  ;; ⚠ tls-reason's argument is a FALLBACK, used only when OpenSSL queued
  ;; nothing -- and for these calls it always queues something, so a path
  ;; put in that string is never printed. Measured, not assumed: a missing
  ;; certificate file and a missing key file both reported
  ;; "error:0A080002:SSL routines::system lib" and were indistinguishable.
  ;; The file has to be appended to whatever reason comes back, not offered
  ;; as an alternative to it.
  ;; A listener's context is retired here and nowhere else. SSL_CTX_free is
  ;; deliberately not exported: a listener incarnation holds exactly one
  ;; reference to its context and retires it once at teardown, and a context
  ;; freed by any other hand is a listener generation that leaks one.
  ;; Free a context that never became a tls-context, and give back the count
  ;; taken at allocation. Both discard paths in the constructor use this, so
  ;; the pair cannot drift apart.
  (define (discard-context! c)
    (with-interrupts-disabled
      (set! live-contexts (fx- live-contexts 1))
      (SSL_CTX_free c)))

  (define (tls-context-retire! c)
    (with-interrupts-disabled
      (let ((p (tls-context-ptr c)))
        (when p
          (tls-context-ptr-set! c #f)
          (set! live-contexts (fx- live-contexts 1))
          (SSL_CTX_free p)))))

  (define (file-reason default path)
    (string-append (tls-reason default) " [" path "]"))

  (define (tls-listen-context! cert-chain-path key-path)
    (ensure-loaded!)
    ;; ⛔ CHECKED BEFORE ANYTHING IS ALLOCATED. What this uniquely provides is
    ;; THE ERROR ITSELF: a tls-error naming the wrong argument, instead of a
    ;; Chez FFI type error raised from inside one of the loading calls.
    ;;
    ;; ⚠ IT IS NOT WHAT PREVENTS THE LEAK -- not any more. It was, when the
    ;; compensation guard below opened after the cond; the guard was then
    ;; widened to cover the loading calls, so a raise there is discarded and
    ;; counted back whether or not this check exists. Measured: with this
    ;; check removed the context count stays 0 and only the error TYPE goes
    ;; red. The two mechanisms now shadow each other -- deleting either one
    ;; alone leaves the leak cell green -- and the cell that still
    ;; discriminates THIS line is the one asserting a tls-error.
    (unless (and (string? cert-chain-path) (string? key-path))
      (die "tls: certificate and key paths must be strings"))
    (let ((r (with-openssl-scope
               (let ((c (SSL_CTX_new (TLS_server_method))))
                 (if (zero? c)
                     (cons (tls-reason "tls: SSL_CTX_new failed") #f)
                     (begin
                     ;; ⭐ COUNTED AT ALLOCATION, NOT AT PUBLICATION -- the same
                     ;; argument as tls-session-new! above, and it was got
                     ;; wrong here first. Counting on the success path meant a
                     ;; context abandoned between here and publication was one
                     ;; the counter had never seen: it leaked, and the reading
                     ;; stayed 0. That is not merely an under-count, it is an
                     ;; instrument that cannot see the failure it exists for --
                     ;; deleting the compensating guard below left every cell
                     ;; green. What is measured is live SSL_CTX allocations, so
                     ;; the count is taken where the allocation happens and
                     ;; given back on each path that frees it.
                     (with-interrupts-disabled
                       (set! live-contexts (fx+ live-contexts 1)))
                     ;; ⛔ THE GUARD OPENS HERE, BEFORE THE COND, AND THAT
                     ;; POSITION IS THE POINT OF IT. It used to open after
                     ;; the cond -- it was written by replacing the success
                     ;; BRANCH -- which left the four loading calls below
                     ;; outside it. Those calls are lazily bound, so on a
                     ;; library missing any one of them the first call
                     ;; raises while resolving the symbol: exactly the class
                     ;; this guard exists for, and exactly the class it did
                     ;; not cover. Measured in a shadow tree: with the guard
                     ;; after the cond a raise there left the context count
                     ;; at 1; opening it here returns it to 0.
                     (guard (e (#t (discard-context! c) (raise e)))
                     (let ((bad
                             (cond
                               ((zero? (SSL_CTX_ctrl
                                         c SSL_CTRL_SET_MIN_PROTO_VERSION
                                         TLS1_2_VERSION 0))
                                (tls-reason "tls: could not require TLS >= 1.2"))
                               ((zero? (SSL_CTX_use_certificate_chain_file
                                         c cert-chain-path))
                                (file-reason "tls: cannot load certificate chain"
                                             cert-chain-path))
                               ;; INJECTION POINT 'tls-context-during-load -- OWNING GUARD:
                               ;; the compensation guard above, which discards the context and
                               ;; re-raises. It sits INSIDE the cond, between the two loads,
                               ;; because that is the region the guard was widened to cover;
                               ;; without a point here nothing holds the guard at its new
                               ;; position and shrinking it back passes every cell.
                               ((begin (inject-fault! 'tls-context-during-load)
                                       (zero? (SSL_CTX_use_PrivateKey_file
                                                c key-path SSL_FILETYPE_PEM)))
                                (file-reason "tls: cannot load private key"
                                             key-path))
                               ;; ⚠ NOT THE CATCHER IN THIS LOAD ORDER, and
                               ;; measured so: with the certificate loaded
                               ;; first, SSL_CTX_use_PrivateKey_file itself
                               ;; rejects a key that does not match it (it
                               ;; reports "key values mismatch"), so this
                               ;; call is not reached for that input. It is
                               ;; kept because it becomes load-bearing the
                               ;; moment anyone loads the key before the
                               ;; certificate, and it costs one call --
                               ;; and it is also the net under a lost
                               ;; return-code check on either load: the
                               ;; pair is what the cell discriminates,
                               ;; either alone is shadowed by the other.
                               ((zero? (SSL_CTX_check_private_key c))
                                (string-append
                                  (tls-reason
                                    "tls: private key does not match the certificate")
                                  " [key " key-path ", cert " cert-chain-path "]"))
                               (else #f))))
                       (if bad
                           (begin (discard-context! c) (cons bad #f))
                           ;; ⛔ EVERYTHING PAST THE ALLOCATION IS GUARDED. The
                           ;; failure branch above only covers calls that
                           ;; report failure by RETURNING; an allocation
                           ;; failure, or a lazy FFI binding whose symbol will
                           ;; not resolve (which is exactly what happens to
                           ;; SSL_CTX_set_options on LibreSSL), leaves by a
                           ;; route it cannot see, and the context would leak.
                           ;;
                           ;; ⚠ This file's rule is "raise outside the scope,
                           ;; never inside", and that rule is NOT broken here:
                           ;; it governs the DELIBERATE error path, where the
                           ;; reason is captured and returned as a value so
                           ;; that SSL_CTX_free cannot overwrite it. What is
                           ;; re-raised here is an exceptional condition, and
                           ;; the scope's dynamic-wind runs ERR_pop_to_mark and
                           ;; restores interrupts on the way out.
                           (let ()
                             ;; INJECTION POINT 'tls-context-after-alloc --
                             ;; OWNING GUARD: the guard immediately above,
                             ;; which frees the context and re-raises.
                             ;;
                             ;; ⭐ IT EXISTS BECAUSE THAT GUARD HAS NO OTHER
                             ;; WAY TO GO RED. The argument check above runs
                             ;; before the allocation, so a bad argument never
                             ;; reaches here; what is left for the guard to
                             ;; catch -- an allocation failure, or a lazy FFI
                             ;; symbol that will not resolve -- cannot be
                             ;; provoked through the public API. Without a
                             ;; point here, deleting the guard passes every
                             ;; cell.
                             (inject-fault! 'tls-context-after-alloc)
                             ;; ⭐ THREE INDEPENDENT CONDITIONS, ALL REQUIRED.
                             ;;
                             ;; The option bit arrived in OpenSSL 1.1.1, so
                             ;; older versions must not be asked for it.
                             ;;
                             ;; LibreSSL reports exactly 0x20000000 and has
                             ;; neither this bit nor the function as a real
                             ;; symbol -- it is a macro over SSL_CTX_ctrl
                             ;; there. ⚠ THAT VALUE IS AN UNVERIFIED PREMISE:
                             ;; it cannot be checked on the machine this was
                             ;; written on, and it is now the only criterion
                             ;; separating LibreSSL out.
                             ;;
                             ;; foreign-entry? is the backstop for exactly that
                             ;; premise being wrong: if the version test lets a
                             ;; LibreSSL through, the cost is one option not
                             ;; set, not an unresolvable symbol raising inside
                             ;; a listener's construction.
                             ;;
                             ;; ⚠ An earlier form of this test bounded the
                             ;; version ABOVE (v < 0x20000000). OpenSSL 3 is
                             ;; 0x30000000 and up, so that range excluded the
                             ;; very library this runs on, and the option was
                             ;; silently never set. The LibreSSL number is a
                             ;; sentinel to exclude, not an upper bound.
                             (let* ((v (OpenSSL_version_num))
                                    (refuse?
                                      (and (>= v #x10101000)
                                           (not (= v #x20000000))
                                           (and (foreign-entry? "SSL_CTX_set_options")
                                                #t))))
                               (when refuse?
                                 (SSL_CTX_set_options c SSL_OP_NO_RENEGOTIATION))
                               (cons #f (make-tls-context c refuse?)))))))))))))
      (when (car r) (die (car r)))
      (cdr r)))

  )
