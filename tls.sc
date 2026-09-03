#!chezscheme
;;; (igropyr tls) -- OPTIONAL outbound TLS for (igropyr http-client).
;;;
;;; The core framework stays dependency-free, and nothing loads OpenSSL
;;; unless a program imports this library and calls (tls-enable!) once at
;;; startup:
;;;
;;;   (import (igropyr http-client) (igropyr tls))
;;;   (tls-enable!)
;;;   (http-get "https://example.com/")
;;;
;;; ⭐ THE OpenSSL HALF LIVES IN (igropyr tls-core), NOT HERE. That library
;;; owns the FFI, the sessions and the contexts, and hands out operations
;;; that take a session object; this file owns the transport half -- the
;;; socket, the deadline, the mailbox, the close hook -- and holds no SSL
;;; pointer at all. The split exists because the server-side codec lives
;;; inside (igropyr libuv), which cannot import this file: this one imports
;;; libuv.
;;;
;;; Design: TLS as a pure byte codec, not an I/O owner. The socket, the
;;; event loop, timeouts, and the actor scheduling all stay in libuv /
;;; (igropyr http-client); OpenSSL runs in memory-BIO mode and only ever
;;; transforms bytes (the calls named here are tls-core's):
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
  ;; ⭐ THIS IS THE PROGRAM-FACING SURFACE, listed name by name rather than
  ;; re-exported wholesale from (igropyr tls-core). A program enables TLS,
  ;; makes client connections, and -- if it listens -- builds and retires a
  ;; server context. The session-level primitives (tls-step!,
  ;; tls-session-new!, tls-session-retire!, the live-session seam) are the
  ;; connection codec's tools, not a program's: they are exported from
  ;; (igropyr tls-core), which is what the server-side codec and the cells
  ;; import. Re-exporting them here would advertise a second way in to
  ;; state whose invariants live in that library.
  (export tls-enable! tls-establish!
          tls-listen-context! tls-context-retire!)
  (import (chezscheme) (igropyr actor) (igropyr tls-core)
          (only (igropyr libuv) tcp-write! conn-on-close! now-ms)
          (only (igropyr http-client) set-https-connector!))





  ;; The OpenSSL half is scoped; the socket write is not, and must not be.
  ;; Best-effort by design: a dead codec has nothing to flush, and no
  ;; caller of this needs a flush to have happened to be correct.
  (define (flush-out! sess c)
    (let ((out (tls-session-drain! sess)))
      (when out (tcp-write! c out #f))))


  ;; RFC 5929 tls-server-end-point channel-binding data: the peer
  ;; certificate hashed with its signature hash algorithm, MD5/SHA-1
  ;; upgraded to SHA-256 -- the exact computation PostgreSQL performs
  ;; server-side, so a SCRAM-SHA-256-PLUS client using this value
  ;; interoperates. #f when the hash cannot be determined (no peer
  ;; certificate, or a signature scheme with no retrievable digest).

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
    ;; The session exists from here: BIOs, SSL and SSL_set_bio are one step
    ;; inside (igropyr tls-core), which reads its own failure reason in its
    ;; own scope. Nothing in this file holds an SSL pointer any more.
    (let ((sess (tls-session-new! (client-ctx))))
      (define (retire! msg) (tls-session-retire! sess msg))
      (define (close!) (retire! "tls: codec is closed"))
      (define (fail! msg) (close!) (die msg))
      ;; This process can be killed while parked in the handshake receive
      ;; below -- winders and guards do not run then -- so freeing cannot be
      ;; owned by this code path. Tie it to the connection instead: the
      ;; owner-death sweep closes the conn and the close completion runs
      ;; close!, which is idempotent.
      ;;
      ;; ...AND IT CAN HAVE RUN ALREADY: conn-on-close! runs the thunk
      ;; immediately when the connection is already closed, so close! -- and
      ;; the free inside it -- can happen on this very line. That is not a
      ;; race to lose; it is a straight line. Everything below therefore asks
      ;; whether the session is still there, in the same region it uses it.
      (conn-on-close! c close!)
      (let ((setup-err (tls-session-configure-client! sess host)))
        (when setup-err (fail! setup-err)))

      ;; drive the handshake: flush whatever each step produced, wait for more
      ;; ciphertext when OpenSSL wants it.
      ;;
      ;; ABSOLUTE deadline, not a per-segment budget: this receive re-arms on
      ;; every record, so a peer that dribbles one just inside the window holds
      ;; the process, the connection and this session open indefinitely at no
      ;; cost to itself.
      (let ((deadline (+ (now-ms) timeout)))
        (let handshake ()
          ;; ⭐ CLASSIFY BEFORE FLUSHING. Draining the write BIO is itself
          ;; OpenSSL work and tcp-write! is a preemption point, so a flush
          ;; between the step and its classification would let any process
          ;; scheduled there decide whether this handshake lived.
          ;;
          ;; THE HANDSHAKE DOES NOT RETIRE IN-REGION: retiring frees the SSL,
          ;; and the SSL owns the write BIO -- so poisoning here would throw
          ;; away the alert that the flush below exists to send, and the peer
          ;; would have to infer the failure from a dropped connection.
          ;; Nothing is racing for this session: no codec has been handed out,
          ;; so this code is its only user, and fail! retires it a few lines
          ;; down once the alert is gone.
          (let-values (((verdict payload)
                        (tls-session-handshake-step! sess #f)))
            ;; the connection's close hook can retire this session while the
            ;; handshake is parked below; then there is nothing left to hand
            ;; back and the stored message is the whole answer
            (when (eq? verdict 'gone) (die payload))
            ;; still before anything that blocks, and on the failing path too:
            ;; whatever OpenSSL just produced -- the ClientHello, or the alert
            ;; that explains the failure below -- goes out
            (flush-out! sess c)
            (cond
              ((eq? verdict 'done) 'established)
              ((eq? verdict 'want-read)
               (receive (after (max 1 (- deadline (now-ms)))
                           (fail! "tls handshake timeout"))
                 (`#(tcp-data ,bv)
                   ;; every kind is fatal to a HANDSHAKE -- there is no codec
                   ;; yet to keep usable -- so they share fail!
                   (let ((werr (tls-session-feed! sess bv)))
                     (when werr (fail! (cdr werr))))
                   (handshake))
                 (`#(tcp-eof) (fail! "connection closed during tls handshake"))
                 (`#(tcp-error ,e) (fail! "connection error during tls handshake"))))
              ;; tls-step! withholds a reason for a positive return, a
              ;; want-read and a clean close_notify. The first two are handled
              ;; above; a close_notify DURING a handshake reaches here, and the
              ;; fallback string is what it gets -- an unfinished handshake is
              ;; a failed connection whatever ended it.
              (else (fail! (or payload "tls handshake failed")))))))

      ;; ---- established: hand back the codec ------------------------------
      ;;
      ;; RENEGOTIATION, which this codec half supports -- and the half it
      ;; supports is the one that matters. TLS 1.3 has none; TLS 1.2 does, and
      ;; a server can ask for one mid-connection. The READ path handles it, and
      ;; that is measured rather than intended: against `openssl s_server
      ;; -tls1_2` driven to renegotiate on command, a client built from this
      ;; file completes the second handshake and goes on to receive the
      ;; application data sent after it. SSL_read processes the HelloRequest
      ;; and queues a ClientHello in the write BIO, which the flush at the end
      ;; of decrypt sends; the peer's response arrives as more ciphertext and
      ;; goes through decrypt again. SSL_write is never involved, and a write
      ;; that reported WANT_READ would be an error -- which is why the context
      ;; refuses renegotiation on the server side.
      (let ((encrypt (lambda (bv) (tls-session-encrypt! sess bv)))
            (decrypt
              (lambda (raw)
        (let-values (((out eof?) (tls-session-decrypt! sess raw)))
          ;; ⭐ THE EOF IS SYNTHESISED HERE, NOT IN tls-core. A close_notify
          ;; ends the TLS stream now, and a close-wait peer (openssl s_server
          ;; does this) may hold the socket open waiting for OUR close_notify
          ;; -- so a close-delimited response must not depend on a TCP FIN.
          ;; The mailbox and the socket are this file's, so the send is too.
          (when eof? (send self (vector 'tcp-eof)))
          ;; post-handshake protocol output (ticket acks, key updates)
          (flush-out! sess c)
          out))))
      ;; 4th slot: the tls-server-end-point hash for SCRAM channel binding (or
      ;; #f); https ignores it, the postgresql client feeds it into
      ;; SCRAM-SHA-256-PLUS.
      ;;
      ;; THE LAST LOOK, and it comes after everything that touches the session.
      ;; It is an OBSERVATION, not a promise: the connection can close one
      ;; instruction after establish! returns and no check covers that. What it
      ;; does cover is the window that mattered. A codec retired afterwards is
      ;; not a hazard, because every call on it raises the stored message
      ;; instead of reaching a freed pointer.
      (let ((cb (tls-session-peer-cb-hash sess)))
        (cond ((unbox (tls-session-dead sess)) => die))
        (vector encrypt decrypt close! cb)))))

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
