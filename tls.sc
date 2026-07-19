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
;;; A verification failure surfaces as #(http-client-error "tls: ...").
;;;
;;; Sessions are closed by freeing (no close_notify): the client speaks
;;; Connection: close and hard-closes the socket right after, and both
;;; framings it accepts (content-length, chunked) detect truncation by
;;; construction.

(library (igropyr tls)
  (export tls-enable!)
  (import (chezscheme) (igropyr actor) (igropyr platform)
          (only (igropyr libuv) tcp-write!)
          (only (igropyr http-client) set-https-connector!))

  ;; ---- shared objects ---------------------------------------------------
  ;; libcrypto first and explicitly: BIO_* / ERR_* / X509_* live there,
  ;; and loading it ourselves guarantees its symbols are visible to
  ;; foreign-procedure regardless of how the platform scopes transitive
  ;; dependencies.

  (define brew-arm "/opt/homebrew/opt/openssl@3/lib/")
  (define brew-x86 "/usr/local/opt/openssl@3/lib/")

  (define (candidates base)
    (case platform-os
      ((macos) (list (string-append brew-arm base ".3.dylib")
                     (string-append brew-x86 base ".3.dylib")
                     (string-append base ".3.dylib")
                     (string-append base ".dylib")))
      (else    (list (string-append base ".so.3")
                     (string-append base ".so.1.1")
                     (string-append base ".so")))))

  (define _libcrypto (load-first-shared-object! 'igropyr-tls (candidates "libcrypto")))
  (define _libssl    (load-first-shared-object! 'igropyr-tls (candidates "libssl")))

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
  (define ERR_error_string_n
    (foreign-procedure "ERR_error_string_n" (unsigned-long u8* size_t) void))

  ;; OpenSSL constants (stable public ABI values)
  (define SSL_VERIFY_PEER 1)
  (define SSL_CTRL_SET_MIN_PROTO_VERSION 123)
  (define TLS1_2_VERSION #x0303)
  (define SSL_CTRL_SET_TLSEXT_HOSTNAME 55)     ; SSL_set_tlsext_host_name
  (define SSL_ERROR_WANT_READ 2)
  (define SSL_ERROR_ZERO_RETURN 6)

  ;; ---- error reporting ---------------------------------------------------

  (define (bv-prefix->string bv)
    (let ((n (bytevector-length bv)))
      (let loop ((i 0))
        (if (or (= i n) (zero? (bytevector-u8-ref bv i)))
            (utf8->string
              (let ((r (make-bytevector i)))
                (bytevector-copy! bv 0 r 0 i)
                r))
            (loop (+ i 1))))))

  ;; First queued OpenSSL error as text (draining the rest), or default.
  (define (tls-reason default)
    (let ((e (ERR_get_error)))
      (if (zero? e)
          default
          (let ((buf (make-bytevector 256 0)))
            (ERR_error_string_n e buf 256)
            (let drain () (unless (zero? (ERR_get_error)) (drain)))
            (string-append "tls: " (bv-prefix->string buf))))))

  (define (die msg) (raise (vector 'http-client-error msg)))

  ;; ---- context (one per program) ------------------------------------------

  (define ctx 0)

  (define (ensure-ctx!)
    (with-interrupts-disabled
      (when (zero? ctx)
        (let ((c (SSL_CTX_new (TLS_client_method))))
          (when (zero? c) (die (tls-reason "tls: SSL_CTX_new failed")))
          (SSL_CTX_ctrl c SSL_CTRL_SET_MIN_PROTO_VERSION TLS1_2_VERSION 0)
          (SSL_CTX_set_verify c SSL_VERIFY_PEER 0)
          (when (zero? (SSL_CTX_set_default_verify_paths c))
            (die (tls-reason "tls: no system trust store")))
          (set! ctx c)))))

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
  (define (drain-wbio wbio)
    (let ((n (BIO_ctrl_pending wbio)))
      (and (> n 0)
           (let ((bv (make-bytevector n)))
             (BIO_read wbio bv n)
             bv))))

  (define (flush-out! c wbio)
    (let ((out (drain-wbio wbio)))
      (when out (tcp-write! c out #f))))

  (define empty-bv (make-bytevector 0))

  ;; ---- the connector --------------------------------------------------------
  ;;
  ;; Runs inside the request's green process; the socket is read-started,
  ;; so ciphertext arrives here as #(tcp-data ...) messages. Returns the
  ;; codec #(encrypt decrypt close) for (igropyr http-client); raises
  ;; #(http-client-error ...) after freeing the session on any failure.

  (define (establish! c host timeout)
    (ensure-ctx!)
    (let ((rbio (BIO_new (BIO_s_mem)))
          (wbio (BIO_new (BIO_s_mem))))
      (when (or (zero? rbio) (zero? wbio))
        (die "tls: BIO_new failed"))
      (let ((ssl (SSL_new ctx)))
        (define (fail! msg) (SSL_free ssl) (die msg))   ; frees both BIOs too
        (when (zero? ssl) (die (tls-reason "tls: SSL_new failed")))
        (SSL_set_bio ssl rbio wbio)
        (if (ip-literal? host)
            (when (zero? (X509_VERIFY_PARAM_set1_ip_asc (SSL_get0_param ssl) host))
              (fail! "tls: bad ip literal"))
            (begin
              (SSL_ctrl/string ssl SSL_CTRL_SET_TLSEXT_HOSTNAME 0 host)  ; SNI
              (when (zero? (SSL_set1_host ssl host))
                (fail! "tls: SSL_set1_host failed"))))
        (SSL_set_connect_state ssl)

        ;; drive the handshake: flush whatever each step produced, wait
        ;; for more ciphertext when OpenSSL wants it
        (let handshake ()
          (let ((r (SSL_do_handshake ssl)))
            (flush-out! c wbio)
            (unless (= r 1)
              (if (= (SSL_get_error ssl r) SSL_ERROR_WANT_READ)
                  (receive (after timeout (fail! "tls handshake timeout"))
                    (`#(tcp-data ,bv)
                      (BIO_write rbio bv (bytevector-length bv))
                      (handshake))
                    (`#(tcp-eof) (fail! "connection closed during tls handshake"))
                    (`#(tcp-error ,e) (fail! "connection error during tls handshake")))
                  (fail! (tls-reason "tls handshake failed"))))))

        ;; ---- established: hand back the codec --------------------------
        (let ((scratch (make-bytevector 16384))
              (closed #f))
          (define (encrypt bv)
            (let ((n (bytevector-length bv)))
              (if (zero? n)
                  empty-bv
                  (begin
                    (unless (= n (SSL_write ssl bv n))
                      (die (tls-reason "tls write failed")))
                    (or (drain-wbio wbio) empty-bv)))))
          (define (decrypt raw)
            (BIO_write rbio raw (bytevector-length raw))
            (let-values (((p get) (open-bytevector-output-port)))
              (let loop ()
                (let ((n (SSL_read ssl scratch 16384)))
                  (if (> n 0)
                      (begin (put-bytevector p scratch 0 n) (loop))
                      (let ((e (SSL_get_error ssl n)))
                        (cond
                          ((= e SSL_ERROR_WANT_READ) 'drained)
                          ((= e SSL_ERROR_ZERO_RETURN)
                           ;; close_notify: the TLS stream is over NOW.
                           ;; A close-wait peer (e.g. openssl s_server)
                           ;; may hold the TCP socket open waiting for
                           ;; our close_notify, so a close-delimited
                           ;; response must not depend on a TCP FIN --
                           ;; synthesize the eof for the client loop.
                           (send self (vector 'tcp-eof)))
                          (else (die (tls-reason "tls read failed"))))))))
              ;; post-handshake protocol output (ticket acks, key updates)
              (flush-out! c wbio)
              (get)))
          (define (close!)
            (unless closed
              (set! closed #t)
              (SSL_free ssl)))
          (vector encrypt decrypt close!)))))

  ;; ---- public entry ---------------------------------------------------------

  (define enabled #f)

  ;; Idempotent; call once at startup, before the first https request.
  (define (tls-enable!)
    (ensure-ctx!)
    (with-interrupts-disabled
      (unless enabled
        (set-https-connector! establish!)
        (set! enabled #t)))
    'ok)
)
