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
;;; Sessions are closed by freeing (no close_notify): the client speaks
;;; Connection: close and hard-closes the socket right after, and both
;;; framings it accepts (content-length, chunked) detect truncation by
;;; construction.

(library (igropyr tls)
  (export tls-enable! tls-establish!)
  (import (chezscheme) (igropyr actor) (igropyr platform)
          (only (igropyr libuv) tcp-write! conn-on-close!)
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
  (define ERR_error_string_n
    (foreign-procedure "ERR_error_string_n" (unsigned-long u8* size_t) void))
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

  (define (die msg) (raise (vector 'tls-error msg)))

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
            ;; free before raising: a caller in a reconnect loop (e.g. a
            ;; database pool retrying every second) would otherwise leak
            ;; one SSL_CTX per attempt for the life of the misconfiguration
            (SSL_CTX_free c)
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

  ;; RFC 5929 tls-server-end-point channel-binding data: the peer
  ;; certificate hashed with its signature hash algorithm, MD5/SHA-1
  ;; upgraded to SHA-256 -- the exact computation PostgreSQL performs
  ;; server-side, so a SCRAM-SHA-256-PLUS client using this value
  ;; interoperates. #f when the hash cannot be determined (no peer
  ;; certificate, or a signature scheme with no retrievable digest).
  (define NID-md5 4)
  (define NID-sha1 64)
  (define (peer-cb-hash ssl)
    (let ((x (SSL_get-peer-cert ssl)))
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
                                 out)))))))))))

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
        ;; free whichever succeeded; ownership passes to the SSL only at
        ;; SSL_set_bio below
        (unless (zero? rbio) (BIO_free rbio))
        (unless (zero? wbio) (BIO_free wbio))
        (die "tls: BIO_new failed"))
      (let ((ssl (SSL_new ctx))
            (closed #f))
        (define (close!)                 ; frees both BIOs too (SSL owns them)
          (unless closed
            (set! closed #t)
            (SSL_free ssl)))
        (define (fail! msg) (close!) (die msg))
        (when (zero? ssl)
          (BIO_free rbio) (BIO_free wbio)
          (die (tls-reason "tls: SSL_new failed")))
        (SSL_set_bio ssl rbio wbio)
        ;; From here the SSL exists and this process can be killed while
        ;; parked in the handshake receive below -- winders and guards do
        ;; not run then, so freeing cannot be owned by this code path.
        ;; Tie it to the connection instead: the owner-death sweep closes
        ;; the conn, and the close completion runs close! (idempotent, so
        ;; the normal-path free through the codec stays correct).
        (conn-on-close! c close!)
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
        (let ((scratch (make-bytevector 16384)))
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
          ;; 4th slot: the tls-server-end-point hash for SCRAM channel
          ;; binding (or #f); https ignores it, the postgresql client
          ;; feeds it into SCRAM-SHA-256-PLUS.
          (vector encrypt decrypt close! (peer-cb-hash ssl))))))

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
