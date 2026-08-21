#!chezscheme
;;; (igropyr postgresql) -- non-blocking PostgreSQL client (protocol 3.0,
;;; simple query).
;;;
;;; One green process per connection; callers park in receive while the
;;; OS thread keeps serving other requests. The PostgreSQL protocol is
;;; strictly request-response within a connection, so concurrent queries
;;; from many workers are queued in the connection's mailbox and run one
;;; at a time.
;;;
;;;   (define db (postgresql-connect "127.0.0.1" 5432 "user" "password" "db"))
;;;   (postgresql-query db "SELECT id, name FROM users")
;;;     ;; -> #(rows ("id" "name") (("1" "Alice") ("2" "Bob")))
;;;   (postgresql-query db "INSERT INTO users (name) VALUES ('Eve')")
;;;     ;; -> #(ok 1)                          ; affected rows
;;;   (postgresql-execute db "SELECT name FROM users WHERE id = $1" 2)
;;;     ;; -> #(rows ("name") (("Bob")))       ; server-side parameter binding
;;;   (postgresql-close! db)
;;;
;;; postgresql-execute runs one statement over the extended query protocol
;;; (Parse/Bind/Execute): parameters are sent out-of-band as $1..$n values,
;;; never spliced into the SQL text, so no quoting or escaping is needed and
;;; injection through a value is impossible -- prefer it over string
;;; concatenation whenever a statement takes runtime values. Parameters may
;;; be strings, numbers, #f (SQL NULL) or bytevectors (raw text-format
;;; bytes). Unlike postgresql-query it accepts exactly one statement.
;;;
;;; Values arrive as strings (the wire text format); NULL is #f. The
;;; connection asks for client_encoding UTF8 at startup, so text is
;;; always UTF-8 on the wire regardless of the database encoding.
;;;
;;; #(postgresql-error ,tag ,message) is the shape of an OPERATIONAL error
;;; -- one the database, the connection or a timeout produced on a valid
;;; call. Nothing else promises to wear that tag: argument checks raise
;;; ordinary Chez conditions, postgresql-pool-stats passes the pool
;;; library's shape through (see below), and whatever the caller's own
;;; procedure raises inside call-with-postgresql-connection or
;;; postgresql-transaction travels out unchanged. A guard that must not
;;; let anything past needs a clause for conditions as well as for the
;;; vector. The tag is one of exactly three shapes:
;;;   - a 5-char SQLSTATE string: a server-side SQL error; the
;;;     connection stays usable.
;;;   - 'transport: a connection/framing failure; the connection is torn
;;;     down (and rebuilt by a pool).
;;;   - 'timeout: the caller stopped waiting (query timeout, pool
;;;     checkout timeout). A timed-out STATEMENT may still execute on
;;;     the server -- its outcome is unknown, so do not blindly retry
;;;     non-idempotent statements.
;;;
;;; A lone postgresql-connect connection does not survive a transport
;;; failure: the handle is dead and later queries time out. Use
;;; postgresql-pool for automatic rebuild and reconnection.
;;;
;;; Authentication: SCRAM-SHA-256 (RFC 7677, the PostgreSQL default
;;; since v10). MD5 is not implemented. Cleartext password auth is
;;; REFUSED by default: the method is chosen by the server -- i.e. by
;;; anyone who can intercept a plaintext socket -- so honoring it
;;; silently would let an active attacker downgrade past SCRAM and read
;;; the password. Pass '((allow-cleartext-auth . #t)) to permit it
;;; (appropriate over a trusted local socket). SASLprep normalization
;;; is not implemented (its Unicode tables dwarf this driver), so
;;; passwords outside PRINTABLE ASCII (non-ASCII, or the control
;;; characters SASLprep prohibits) are REJECTED with a clear error --
;;; in the caller when SCRAM is the only possible path, and during the
;;; exchange otherwise -- rather than failing with a baffling 28P01.
;;; Printable-ASCII passwords are exact (SASLprep leaves them unchanged).
;;;
;;; TLS: pass the byte-codec connector from (igropyr tls) as the 'tls
;;; option and the connection is upgraded via SSLRequest before startup,
;;; with certificate + hostname verification against the system trust
;;; store (SSL_CERT_FILE / SSL_CERT_DIR apply):
;;;
;;;   (import (igropyr postgresql) (igropyr tls))
;;;   (postgresql-connect host 5432 user pw "db"
;;;                       (list (cons 'tls tls-establish!)))
;;;
;;; The connector travels through the options alist, so this library
;;; never imports (igropyr tls) and stays free of the OpenSSL dependency
;;; unless the application opts in. If the server refuses TLS the
;;; connection FAILS -- no silent plaintext fallback. Over TLS, SCRAM
;;; channel binding is automatic: when the server offers
;;; SCRAM-SHA-256-PLUS the client selects it and binds the exchange to
;;; this TLS channel's server certificate (RFC 5929
;;; tls-server-end-point), so even a relay MITM with a trusted
;;; certificate cannot forward the authentication. Without 'tls the
;;; client speaks plaintext: an on-path attacker can read query text and
;;; results regardless of the auth method, so run plaintext connections
;;; only over a trusted network or a local socket.

(library (igropyr postgresql)
  (export postgresql-connect postgresql-pool postgresql-query
          postgresql-execute postgresql-close! postgresql-pool-stats
          postgresql-transaction call-with-postgresql-connection)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr buffer)
          (igropyr connpool)
          (only (igropyr crypto)
                sha256 hmac-sha256 pbkdf2-hmac-sha256
                base64-encode base64-decode))

  (define connect-timeout-ms 10000)
  ;; A ceiling on the WHOLE startup/auth conversation.
  ;;
  ;; connect-timeout-ms bounds each socket read and re-arms on every
  ;; message, so it never ends the conversation: a server sending one
  ;; NoticeResponse every nine seconds -- perfectly legal, and something a
  ;; hostile or confused peer can keep up indefinitely -- held a connection
  ;; worker forever. The single-connection caller gave up at twelve seconds
  ;; and the worker kept running; a POOL worker never reported pool-up at all,
  ;; so it occupied its slot for the life of the process while the pool
  ;; waited for a connection that was never coming.
  ;;
  ;; This is the same distinction the HTTP reader draws between a gap
  ;; between segments and a deadline on the whole request.
  (define connect-deadline-ms 30000)
  ;; RFC 5802 warns that a hostile server can DoS a client with an extreme
  ;; iteration count -- the client does the work the SERVER asks for.
  ;;
  ;; This number is a TIME budget, not a copy of kdf.sc's ceiling, even
  ;; though both bound "untrusted PBKDF2 iterations". kdf.sc bounds
  ;; libcrypto's; SCRAM here runs (igropyr crypto)'s pure-Scheme one so it
  ;; works without OpenSSL, and the same count costs about ninety times
  ;; more. Measured: 2 000 000 iterations is 152 ms through libcrypto and
  ;; 13 502 ms here. Sharing the constant would have authorised thirteen
  ;; seconds of a single-OS-thread runtime per connection attempt, which a
  ;; reconnecting pool turns into saturation.
  ;;
  ;; 100 000 costs ~660 ms here and is 24x PostgreSQL's own default
  ;; scram_iterations of 4096 (~29 ms), so no ordinary server comes close.
  ;; A deployment that has raised scram_iterations past this can raise the
  ;; ceiling with the 'scram-max-iters option rather than failing to
  ;; connect -- refusing a legitimately configured server would be limiting
  ;; what the server may say, not what an attacker may.
  (define default-scram-max-iters 100000)
  ;; per-socket-read clock while a QUERY is in flight (the caller-facing
  ;; query timeout is (igropyr connpool)'s own, same value); auth-phase
  ;; reads use connect-timeout-ms instead, so a server that stalls
  ;; mid-handshake holds a connect worker for the connect budget, not
  ;; the query budget.
  (define query-timeout-ms 60000)

  ;; Upper bound on a single server message. PostgreSQL rows can be
  ;; large (bytea/text up to 1GB per field), but a length beyond this is
  ;; a desynchronised or hostile peer, not data -- fail instead of
  ;; accumulating gigabytes in the connection process.
  (define max-message-len #x40000000)  ; 1 GiB

  ;; ---- bytevector helpers ------------------------------------------------

  (define empty-bv (make-bytevector 0))

  (define (bv-append . bvs)
    (let* ((total (fold-left (lambda (n x) (+ n (bytevector-length x))) 0 bvs))
           (out (make-bytevector total)))
      (let loop ((l bvs) (off 0))
        (if (null? l)
            out
            (let ((x (car l)))
              (bytevector-copy! x 0 out off (bytevector-length x))
              (loop (cdr l) (+ off (bytevector-length x))))))))

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  (define (bv-xor a b)                  ; a and b are equal length
    (let* ((n (bytevector-length a))
           (out (make-bytevector n)))
      (do ((i 0 (+ i 1))) ((= i n) out)
        (bytevector-u8-set! out i
          (fxxor (bytevector-u8-ref a i) (bytevector-u8-ref b i))))))

  (define (find-u8 bv start byte)
    (let ((n (bytevector-length bv)))
      (let loop ((i start))
        (cond ((>= i n) #f)
              ((fx= (bytevector-u8-ref bv i) byte) i)
              (else (loop (+ i 1)))))))

  ;; ---- big-endian integer codecs (R6RS accessors) ------------------------

  (define (u32 v)
    (let ((bv (make-bytevector 4)))
      (bytevector-u32-set! bv 0 v (endianness big))
      bv))

  (define (read-u32-be bv pos) (bytevector-u32-ref bv pos (endianness big)))
  ;; DataRow column lengths are a signed Int32 (-1 marks SQL NULL).
  (define (read-i32-be bv pos) (bytevector-s32-ref bv pos (endianness big)))
  (define (read-u16-be bv pos) (bytevector-u16-ref bv pos (endianness big)))

  ;; a NUL-terminated string, as the protocol frames identifiers/values
  (define (cstr s) (bv-append (string->utf8 s) (bytevector 0)))

  ;; ---- string helpers (for the SCRAM text messages) ---------------------

  (define (split-on s ch)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n) (reverse (cons (substring s start i) acc)))
          ((char=? (string-ref s i) ch)
           (loop (+ i 1) (+ i 1) (cons (substring s start i) acc)))
          (else (loop (+ i 1) start acc))))))

  ;; ---- framing ----------------------------------------------------------

  ;; a typed message: 1-byte type + Int32 length (covering the length field
  ;; and payload, but not the type byte) + payload. Built in one allocation.
  (define (msg type payload)
    (let* ((n (bytevector-length payload))
           (out (make-bytevector (+ 5 n))))
      (bytevector-u8-set! out 0 type)
      (bytevector-u32-set! out 1 (+ 4 n) (endianness big))
      (bytevector-copy! payload 0 out 5 n)
      out))

  ;; ---- transport ---------------------------------------------------------
  ;; Everything above the socket goes through a transport: the raw libuv
  ;; connection plus an optional TLS byte codec (from (igropyr tls)'s
  ;; tls-establish!, injected via the 'tls option). enc/dec transform
  ;; whole byte runs; closer frees the TLS session. A plain connection
  ;; carries #f in all three at zero cost.

  (define-record-type (tx make-tx tx?)
    (fields c enc dec closer cb))     ; cb: tls-server-end-point hash or #f

  (define (tx-write! t bv)
    (tcp-write! (tx-c t) (let ((e (tx-enc t))) (if e (e bv) bv)) #f))

  (define (tx-decode t bv)
    (let ((d (tx-dec t))) (if d (d bv) bv)))

  (define (tx-close! t)
    (let ((cl (tx-closer t))) (when cl (cl)))
    (tcp-close! (tx-c t)))

  ;; In the framing/protocol functions below (send-msg!, next-msg!,
  ;; wait-data, auth, queries, serve-loop) c is always a tx; only
  ;; setup-transport! and start-connection's connect path handle the
  ;; raw libuv connection.
  (define (send-msg! c type payload) (tx-write! c (msg type payload)))

  (define MSG-QUERY     (char->integer #\Q))
  (define MSG-PASSWORD  (char->integer #\p))   ; password / SASL response
  (define MSG-COPY-FAIL (char->integer #\f))
  (define MSG-TERMINATE (char->integer #\X))
  (define MSG-PARSE     (char->integer #\P))   ; extended query protocol
  (define MSG-BIND      (char->integer #\B))
  (define MSG-DESCRIBE  (char->integer #\D))
  (define MSG-EXECUTE   (char->integer #\E))
  (define MSG-SYNC      (char->integer #\S))

  ;; StartupMessage has no type byte: Int32 length + Int32 protocol(3.0) +
  ;; a run of key\0value\0 pairs + a final \0. client_encoding pins the
  ;; wire text format to what this client actually decodes.
  (define (startup-msg user db)
    (let* ((body (bv-append (u32 196608)          ; protocol 3.0 == 0x00030000
                            (cstr "user") (cstr user)
                            (cstr "database") (cstr db)
                            (cstr "client_encoding") (cstr "UTF8")
                            (bytevector 0)))
           (len (+ 4 (bytevector-length body))))
      (bv-append (u32 len) body)))

  (define (postgresql-fail state msg) (raise (vector 'postgresql-error state msg)))

  ;; wrap any exception as #(postgresql-error ...): an already-tagged error
  ;; (a server SQL error, or a transport error we raised) passes through;
  ;; anything else means the connection is no longer trustworthy.
  (define (as-postgresql-error e context)
    (if (and (vector? e) (eq? (vector-ref e 0) 'postgresql-error))
        e
        (vector 'postgresql-error 'transport
                (string-append context ": "
                  (if (condition? e)
                      (call-with-string-output-port
                        (lambda (p) (display-condition e p)))
                      (call-with-string-output-port
                        (lambda (p) (write e p))))))))

  ;; A transport/protocol failure (as opposed to a server SQL error, which
  ;; carries a real 5-char SQLSTATE) means the framing may be desynchronised
  ;; and the connection must be discarded.
  (define (transport-dead? r)
    (and (vector? r) (eq? (vector-ref r 0) 'postgresql-error)
         (eq? (vector-ref r 1) 'transport)))

  ;; blocking: returns (values type payload); runs in the connection
  ;; process. buf is an (igropyr buffer) inbuf: appends are amortized
  ;; O(1) and consuming a message is O(1), so a result set of many
  ;; DataRow messages costs one copy per message, not one copy of the
  ;; whole remaining buffer per message.
  ;; timeout bounds each socket read: connect-timeout-ms during
  ;; startup/auth, query-timeout-ms while a query is in flight.
  (define (next-msg! c buf timeout)
    (let loop ()
      (if (>= (inbuf-length buf) 5)
          (let* ((bv (inbuf-bv buf))
                 (base (inbuf-start buf))
                 (type (bytevector-u8-ref bv base))
                 (len (read-u32-be bv (fx+ base 1))))
            (when (or (< len 4) (> len max-message-len))
              (postgresql-fail 'transport "invalid message length"))
            (let ((total (+ 1 len)))
              (if (>= (inbuf-length buf) total)
                  (let ((payload (inbuf-sub buf 5 total)))
                    (inbuf-consume! buf total)
                    (values type payload))
                  (wait-data c buf loop timeout))))
          (wait-data c buf loop timeout))))

  ;; How long the next auth read may wait: never past the conversation's
  ;; deadline, and never longer than one message is allowed to take.
  (define (auth-wait-ms deadline)
    (let ((left (- deadline (now-ms))))
      (when (<= left 0)
        (postgresql-fail 'transport "connect deadline exceeded"))
      (max 1 (min connect-timeout-ms left))))

  ;; timeout may be a NUMBER or a thunk. A thunk is what the handshake
  ;; passes: computing the allowance once and re-arming it for every
  ;; fragment leaves the deadline unchecked for the whole of one message,
  ;; so a peer that dribbles a single message forever never trips it -- the
  ;; same re-arming shape the deadline was added to replace, one level down.
  (define (wait-data c buf k timeout)
    (receive (after (if (procedure? timeout) (timeout) timeout) (postgresql-fail 'transport "server timeout"))
      (`#(tcp-data ,bv)
        (inbuf-append! buf (tx-decode c bv))
        (k))
      (`#(tcp-eof) (postgresql-fail 'transport "connection closed by server"))
      (`#(tcp-error ,e) (postgresql-fail 'transport "connection error"))
      ;; The owner died while we were mid-query. serve-loop watches for that
      ;; between statements, but a query is not between statements: once
      ;; inside the wire loop only TCP messages were matched, so against a
      ;; server that keeps dripping data the old query, its fd and its TLS
      ;; session outlived the pool indefinitely -- and rebuilding the pool
      ;; stacked a fresh set on top. Failing here unwinds through the guards,
      ;; which close the socket.
      (`#(DOWN ,pid ,reason) (postgresql-fail 'transport "owner gone"))
      ;; A TEARDOWN has to reach us HERE as well. The pool reclaims a
      ;; connection whose borrower died by marking it dying and sending
      ;; pool-quit -- @kill discards dynamic-wind winders, so the pool's
      ;; monitor is the only path back -- and a receive matching only the
      ;; socket left that message in the mailbox until the statement
      ;; finished. Against a server that has stopped answering, that is the
      ;; whole query timeout, and for all of it the connection is marked
      ;; dying: neither lent out nor rebuilt. Failing here takes the same
      ;; route a transport error already takes.
      (`#(pool-quit)
        (postgresql-fail 'transport "connection closed while a query was in flight"))))

  ;; During startup/auth the server may interleave NoticeResponse ('N')
  ;; messages (an auth hook warning, a standby notice); they are
  ;; informational and must not fail the handshake.
  (define (next-msg!/skip-notices c buf deadline)
    (let loop ()
      (let-values (((t p) (next-msg! c buf (lambda () (auth-wait-ms deadline)))))
        (if (fx= t (char->integer #\N))
            (loop)
            (values t p)))))

  ;; ---- ErrorResponse ('E') ----------------------------------------------

  ;; payload: a run of (1-byte field type + cstring value), ended by a zero
  ;; field-type byte. We keep the human message ('M') and SQLSTATE ('C').
  (define (error-response->fail payload)
    (let ((n (bytevector-length payload)))
      (let loop ((pos 0) (message "") (code "XX000"))
        (if (or (>= pos n) (zero? (bytevector-u8-ref payload pos)))
            (vector 'postgresql-error code message)
            (let* ((f (integer->char (bytevector-u8-ref payload pos)))
                   (z (or (find-u8 payload (+ pos 1) 0) n))
                   (v (utf8->string (bv-sub payload (+ pos 1) z))))
              (loop (+ z 1)
                    (if (char=? f #\M) v message)
                    (if (char=? f #\C) v code)))))))

  ;; ---- SCRAM-SHA-256 (RFC 7677) -----------------------------------------

  ;; 18 random bytes -> base64 (24 chars, no '=' padding, no comma) makes a
  ;; valid SCRAM nonce token. Fail loudly on a short read rather than use
  ;; a weaker nonce.
  (define (make-client-nonce)
    (let ((bv (call-with-port (open-file-input-port "/dev/urandom")
                (lambda (p) (get-bytevector-n p 18)))))
      (unless (and (bytevector? bv) (= 18 (bytevector-length bv)))
        (postgresql-fail 'transport "could not read /dev/urandom"))
      (base64-encode bv)))

  ;; AuthenticationSASL payload: Int32(10) then a run of NUL-terminated
  ;; mechanism names, ended by an empty one. -> list of mechanism strings.
  (define (sasl-mechanisms payload)
    (let ((n (bytevector-length payload)))
      (let loop ((pos 4) (acc '()))
        (let ((z (find-u8 payload pos 0)))
          (if (or (not z) (= z pos))          ; empty string == terminator
              (reverse acc)
              (loop (+ z 1) (cons (utf8->string (bv-sub payload pos z)) acc)))))))

  ;; "k=v,k2=v2,..." -> alist of (char . string); the value keeps any '='
  ;; it contains (base64 padding), only the first '=' is the separator.
  ;; Any token not of the form <char>=<rest> is a protocol violation.
  (define (scram-attrs s)
    (map (lambda (tok)
           (unless (and (>= (string-length tok) 2)
                        (char=? (string-ref tok 1) #\=))
             (postgresql-fail 'transport "malformed SCRAM server message"))
           (cons (string-ref tok 0) (substring tok 2 (string-length tok))))
         (split-on s #\,)))

  (define (attr a key) (cond ((assv key a) => cdr) (else #f)))

  ;; The pure RFC 5802/7677 client-side derivation, separated from the
  ;; wire exchange: -> (values client-proof server-signature).
  (define (scram-derive password salt iters auth-msg)
    (let* ((salted (pbkdf2-hmac-sha256 (string->utf8 password) salt iters 32))
           (client-key (hmac-sha256 salted (string->utf8 "Client Key")))
           (stored-key (sha256 client-key))
           (client-sig (hmac-sha256 stored-key (string->utf8 auth-msg)))
           (server-key (hmac-sha256 salted (string->utf8 "Server Key"))))
      (values (bv-xor client-key client-sig)
              (hmac-sha256 server-key (string->utf8 auth-msg)))))

  ;; Printable ASCII (space..tilde) passes SASLprep (RFC 4013) unchanged,
  ;; so it is exact without the normalization tables (which would dwarf
  ;; this driver). Everything else -- non-ASCII, and the C0/DEL control
  ;; characters SASLprep PROHIBITS -- must be rejected loudly, not hashed
  ;; raw into a proof no SASLprep-ing client could ever reproduce.
  (define (scram-safe-password? s)
    (let ((n (string-length s)))
      (let loop ((i 0))
        (or (= i n)
            (and (char<=? #\space (string-ref s i))
                 (char<? (string-ref s i) #\delete)
                 (loop (+ i 1)))))))

  ;; Drive the SASL exchange to AuthenticationSASLFinal (verifying the
  ;; server signature), then return -- the caller reads the trailing
  ;; AuthenticationOk.
  ;;
  ;; Channel binding (RFC 5929 tls-server-end-point): over TLS the
  ;; transport carries the server certificate's hash; when the server
  ;; also offers SCRAM-SHA-256-PLUS we take it and bind the exchange to
  ;; this exact TLS channel -- a MITM relaying the SCRAM messages
  ;; through its own TLS session presents a different certificate hash
  ;; and the server rejects the proof. The gs2 flag is three-valued:
  ;;   p=tls-server-end-point  binding in use (PLUS chosen)
  ;;   y  TLS is active but binding is not in use (the server offered no
  ;;      PLUS, or the certificate's hash is unavailable, e.g. RSA-PSS /
  ;;      Ed25519 signatures) -- if a server that DID offer PLUS sees
  ;;      this, someone stripped it from the mechanism list: rejected.
  ;;      Keyed on TLS BEING ACTIVE, not on having a hash, or a MITM
  ;;      with an unhashable certificate could downgrade us to "n".
  ;;   n  plaintext connection, no binding possible
  (define (scram-auth! c buf user password sasl-payload max-iters deadline)
    (unless (scram-safe-password? password)
      (postgresql-fail 'transport
        (string-append
          "password contains characters outside printable ASCII, which "
          "require SASLprep normalization; this client does not implement "
          "SASLprep, and SCRAM authentication would fail against a "
          "libpq-written verifier")))
    (let* ((mechs (sasl-mechanisms sasl-payload))
           (cb (tx-cb c))
           (plus? (and cb (member "SCRAM-SHA-256-PLUS" mechs) #t)))
      (unless (or plus? (member "SCRAM-SHA-256" mechs))
        (postgresql-fail 'transport "server offered no SCRAM-SHA-256 mechanism"))
      (let* ((mech (if plus? "SCRAM-SHA-256-PLUS" "SCRAM-SHA-256"))
             (gs2 (cond (plus? "p=tls-server-end-point,,")
                        ((tx-enc c) "y,,")        ; TLS active, no binding
                        (else "n,,")))            ; plaintext
             ;; c= carries base64(gs2-header [+ binding data]); with no
             ;; binding this is base64("n,,") = the fixed "biws"
             (cbind (base64-encode
                      (if plus?
                          (bv-append (string->utf8 gs2) cb)
                          (string->utf8 gs2))))
             (cnonce (make-client-nonce))
             (client-first-bare (string-append "n=,r=" cnonce))
             (client-first (string-append gs2 client-first-bare)))
        (send-msg! c MSG-PASSWORD
          (bv-append (cstr mech)
                     (u32 (string-length client-first))
                     (string->utf8 client-first)))
        (let-values (((t p) (next-msg!/skip-notices c buf deadline)))
          (unless (and (fx= t (char->integer #\R)) (= (read-u32-be p 0) 11))
            (if (fx= t (char->integer #\E))
                (raise (error-response->fail p))
                (postgresql-fail 'transport "expected SASLContinue")))
          (let* ((server-first (utf8->string (bv-sub p 4 (bytevector-length p))))
                 (a (scram-attrs server-first))
                 (snonce (attr a #\r))
                 (salt-b64 (attr a #\s))
                 (iters (let ((s (attr a #\i))) (and s (string->number s)))))
            ;; validate everything before touching it: a missing or bogus
            ;; field is a protocol error, not a raw assertion. The server
            ;; nonce must EXTEND ours (RFC 5802: client nonce + a non-empty
            ;; server part), so strictly longer.
            (unless (and snonce salt-b64 iters (fixnum? iters) (> iters 0)
                         (fx<= iters max-iters)
                         (> (string-length snonce) (string-length cnonce))
                         (string=? (substring snonce 0 (string-length cnonce))
                                   cnonce))
              (postgresql-fail 'transport "malformed SCRAM server-first message"))
            (let* ((salt (base64-decode salt-b64))
                   (final-noproof (string-append "c=" cbind ",r=" snonce))
                   (auth-msg (string-append client-first-bare "," server-first
                                            "," final-noproof)))
              (let-values (((proof server-sig)
                            (scram-derive password salt iters auth-msg)))
                (send-msg! c MSG-PASSWORD
                  (string->utf8
                    (string-append final-noproof ",p=" (base64-encode proof))))
                (let-values (((t2 p2) (next-msg!/skip-notices c buf deadline)))
                  (cond
                    ((and (fx= t2 (char->integer #\R)) (= (read-u32-be p2 0) 12))
                     (let ((v (attr (scram-attrs
                                      (utf8->string
                                        (bv-sub p2 4 (bytevector-length p2))))
                                    #\v)))
                       (unless (and v (bytevector=? (base64-decode v) server-sig))
                         (postgresql-fail 'transport "server signature mismatch"))))
                    ((fx= t2 (char->integer #\E))
                     (raise (error-response->fail p2)))
                    (else
                     (postgresql-fail 'transport "expected SASLFinal")))))))))))

  ;; ---- authentication ----------------------------------------------------

  (define (assq-ref alist key)
    (let ((p (and (pair? alist) (assq key alist))))
      (and p (cdr p))))

  (define (scram-iter-ceiling opts)
    (let ((v (assq-ref opts 'scram-max-iters)))
      (cond
        ((not v) default-scram-max-iters)
        ((and (fixnum? v) (fx> v 0)) v)
        (else
          (assertion-violation 'postgresql-connect
            "'scram-max-iters must be a positive fixnum" v)))))

  ;; 'connect-deadline-ms overrides the ceiling on the whole handshake.
  (define (connect-deadline opts)
    (let ((v (assq-ref opts 'connect-deadline-ms)))
      (cond
        ((not v) connect-deadline-ms)
        ((and (integer? v) (exact? v) (> v 0)) v)
        (else (assertion-violation 'postgresql-connect
                "'connect-deadline-ms must be a positive exact integer" v)))))

  (define (authenticate! c buf user password db opts)
    (tx-write! c (startup-msg user db))
    (let ((deadline (+ (now-ms) (connect-deadline opts))))
      (let loop ()
        (let-values (((t p) (next-msg! c buf (lambda () (auth-wait-ms deadline)))))
        (case (integer->char t)
          ((#\R)
           (let ((code (read-u32-be p 0)))
             (cond
               ((= code 0) (finish-startup! c buf deadline))  ; AuthenticationOk
               ((= code 10)                                 ; AuthenticationSASL
                (scram-auth! c buf user password p
                             (scram-iter-ceiling opts) deadline)
                (loop))                                     ; then AuthenticationOk
               ((= code 3)                                  ; cleartext password
                ;; the auth method is the SERVER's choice, i.e. an active
                ;; MITM's choice on a plaintext socket: sending the password
                ;; verbatim would nullify SCRAM, so it is opt-in only.
                (unless (assq-ref opts 'allow-cleartext-auth)
                  (postgresql-fail 'transport
                    (string-append
                      "server requested cleartext password authentication, "
                      "which would send the password unprotected; pass "
                      "'allow-cleartext-auth to permit it on a trusted socket")))
                ;; the PasswordMessage payload is a NUL-terminated string:
                ;; an embedded NUL would silently truncate the password
                ;; server-side and authenticate against the prefix
                (when (let scan ((i 0))
                        (and (< i (string-length password))
                             (or (char=? (string-ref password i) #\nul)
                                 (scan (+ i 1)))))
                  (postgresql-fail 'transport
                    "password contains a NUL character, which cannot be represented in cleartext authentication"))
                (send-msg! c MSG-PASSWORD (cstr password))
                (loop))
               ((= code 5)
                (postgresql-fail 'transport
                  "MD5 authentication is not supported; use scram-sha-256"))
               (else
                (postgresql-fail 'transport
                  (string-append "unsupported authentication method "
                                 (number->string code)))))))
          ((#\E) (raise (error-response->fail p)))
          ((#\N) (loop))                                    ; NoticeResponse
          (else (postgresql-fail 'transport
                  "unexpected message during authentication")))))))

  ;; After AuthenticationOk the server streams ParameterStatus/BackendKeyData
  ;; and notices; consume through the first ReadyForQuery ('Z').
  (define (finish-startup! c buf deadline)
    (let loop ()
      (let-values (((t p) (next-msg! c buf (lambda () (auth-wait-ms deadline)))))
        (case (integer->char t)
          ((#\Z) 'ok)
          ((#\E) (raise (error-response->fail p)))
          (else (loop))))))

  ;; ---- queries -----------------------------------------------------------

  ;; RowDescription ('T'): Int16 field count, then per field a name cstring
  ;; followed by 18 fixed bytes (tableOID, col#, typeOID, typelen, typemod,
  ;; format) we don't need. -> list of column-name strings.
  (define (parse-row-desc p)
    (let ((n (read-u16-be p 0)))
      (let loop ((i 0) (pos 2) (acc '()))
        (if (= i n)
            (reverse acc)
            (let* ((z (or (find-u8 p pos 0) (bytevector-length p)))
                   (name (utf8->string (bv-sub p pos z))))
              (loop (+ i 1) (+ z 1 18) (cons name acc)))))))

  ;; DataRow ('D'): Int16 column count, then per column an Int32 length
  ;; (-1 == NULL == #f) and that many text bytes.
  (define (parse-data-row p)
    (let ((n (read-u16-be p 0)))
      (let loop ((i 0) (pos 2) (acc '()))
        (if (= i n)
            (reverse acc)
            (let ((len (read-i32-be p pos)))
              (if (= len -1)
                  (loop (+ i 1) (+ pos 4) (cons #f acc))
                  (loop (+ i 1) (+ pos 4 len)
                        (cons (utf8->string (bv-sub p (+ pos 4) (+ pos 4 len)))
                              acc))))))))

  ;; CommandComplete ('C') payload is one cstring tag, e.g. "INSERT 0 5",
  ;; "UPDATE 2", "SELECT 3". The affected-row count is its last integer.
  (define (command-affected p)
    (let* ((z (or (find-u8 p 0 0) (bytevector-length p)))
           (tag (utf8->string (bv-sub p 0 z)))
           (toks (split-on tag #\space)))
      (or (string->number (car (last-pair toks))) 0)))

  ;; Read messages through ReadyForQuery ('Z') and build the result. Shared
  ;; by the simple and extended flows: the extended flow's extra messages
  ;; (ParseComplete '1', BindComplete '2', NoData 'n') fall into the ignore
  ;; clause. A server SQL error ('E') is remembered and raised only after
  ;; 'Z', so the connection stays framed and usable. With multiple simple
  ;; statements the last result is returned.
  ;; COPY: FROM STDIN is refused with CopyFail (the server then reports a
  ;; normal SQL error); TO STDOUT is not supported -- its data stream is
  ;; consumed and a feature-not-supported error is raised, rather than
  ;; silently discarding the rows and reporting success.
  ;; A whole result set is materialised in memory, so it needs a ceiling of
  ;; its own: max-message-len bounds ONE wire message, and a million small
  ;; rows never trip it. An unbounded SELECT is how a client runs the VM out
  ;; of memory on behalf of a query someone wrote by accident. Refusing
  ;; leaves the connection framed (the error is raised after ReadyForQuery,
  ;; like any other), so the pool keeps it.
  (define max-result-rows 1000000)

  (define (read-response! c buf)
    (let loop ((names #f) (rows '()) (result #f) (err #f) (n 0))
      (let-values (((t p) (next-msg! c buf query-timeout-ms)))
        (case (integer->char t)
          ((#\T) (loop (parse-row-desc p) '() result err 0))
          ((#\D)
           (if (>= n max-result-rows)
               ;; keep draining to ReadyForQuery so the connection stays
               ;; usable, but remember the refusal
               (loop names rows result
                     (or err (vector 'postgresql-error "53400"
                                     "result set exceeds max-result-rows"))
                     n)
               (loop names (cons (parse-data-row p) rows) result err (+ n 1))))
          ((#\C)
           (loop #f '()
                 (if names
                     (vector 'rows names (reverse rows))
                     (vector 'ok (command-affected p)))
                 err 0))
          ((#\I) (loop #f '() (vector 'ok 0) err 0))          ; EmptyQueryResponse
          ((#\G #\W)                                        ; CopyIn/CopyBoth
           (send-msg! c MSG-COPY-FAIL
             (cstr "COPY FROM STDIN is not supported by this client"))
           (loop names rows result err n))                   ; server sends E, Z
          ((#\H)                                            ; CopyOutResponse
           (loop names rows result
                 (or err (vector 'postgresql-error "0A000"
                                 "COPY TO STDOUT is not supported by this client"))
                 n))
          ((#\E) (loop names rows result (error-response->fail p) n))
          ((#\Z) (if err (raise err) (or result (vector 'ok 0))))
          (else (loop names rows result err n))))))    ; S, N, K, 1, 2, n, d, c

  (define (run-query! c buf sql)
    (send-msg! c MSG-QUERY (cstr sql))
    (read-response! c buf))

  ;; The extended flow: Parse (unnamed statement) + Bind (params as text,
  ;; already converted to bytevector-or-#f by the caller) + Describe +
  ;; Execute + Sync, pipelined in one write. On any error the server skips
  ;; to Sync and answers ReadyForQuery, so framing holds without special
  ;; casing.
  ;;
  ;; Describe (the unnamed portal) + Execute (no row limit) + Sync never
  ;; change: 22 constant bytes, built once. Parse+Bind are written into
  ;; one sized buffer -- this runs once per execute on the request path,
  ;; so it should not shower the allocator with intermediates.
  (define extended-tail
    (bv-append
      (msg MSG-DESCRIBE (bytevector (char->integer #\P) 0))
      (msg MSG-EXECUTE (bytevector 0 0 0 0 0))
      (msg MSG-SYNC empty-bv)))

  (define (extended-msgs sql params)
    (let* ((sqlbv (string->utf8 sql))
           (sqln (bytevector-length sqlbv))
           (parse-body (fx+ sqln 4))               ; NUL + sql NUL + Int16
           ;; portal NUL + stmt NUL + Int16 fmts + Int16 nparams +
           ;; per param Int32 [+ bytes] + Int16 result fmts
           (bind-body
            (fold-left (lambda (n p)
                         (fx+ n 4 (if p (bytevector-length p) 0)))
                       8 params))
           (tail-n (bytevector-length extended-tail))
           (out (make-bytevector (fx+ 10 parse-body bind-body tail-n))))
      ;; Parse
      (bytevector-u8-set! out 0 MSG-PARSE)
      (bytevector-u32-set! out 1 (fx+ 4 parse-body) (endianness big))
      (bytevector-u8-set! out 5 0)                 ; unnamed statement
      (bytevector-copy! sqlbv 0 out 6 sqln)
      (bytevector-u8-set! out (fx+ 6 sqln) 0)
      (bytevector-u16-set! out (fx+ 7 sqln) 0 (endianness big)) ; no forced types
      ;; Bind
      (let ((b (fx+ 5 parse-body)))
        (bytevector-u8-set! out b MSG-BIND)
        (bytevector-u32-set! out (fx+ b 1) (fx+ 4 bind-body) (endianness big))
        (bytevector-u8-set! out (fx+ b 5) 0)       ; unnamed portal
        (bytevector-u8-set! out (fx+ b 6) 0)       ; unnamed statement
        (bytevector-u16-set! out (fx+ b 7) 0 (endianness big))  ; all text
        (bytevector-u16-set! out (fx+ b 9) (length params) (endianness big))
        (let loop ((ps params) (pos (fx+ b 11)))
          (if (null? ps)
              (begin
                (bytevector-u16-set! out pos 0 (endianness big)) ; all text
                (bytevector-copy! extended-tail 0 out (fx+ pos 2) tail-n)
                out)
              (let ((p (car ps)))
                (if p
                    (let ((pl (bytevector-length p)))
                      (bytevector-u32-set! out pos pl (endianness big))
                      (bytevector-copy! p 0 out (fx+ pos 4) pl)
                      (loop (cdr ps) (fx+ pos 4 pl)))
                    (begin                          ; -1 == NULL
                      (bytevector-u32-set! out pos #xFFFFFFFF (endianness big))
                      (loop (cdr ps) (fx+ pos 4))))))))))

  (define (run-extended! c buf sql params)
    (tx-write! c (extended-msgs sql params))
    (read-response! c buf))

  ;; ---- connection process ------------------------------------------------

  ;; notify (a pid or #f): told #(pool-idle ,self) after each finished query,
  ;; so a pool can hand this connection its next task (the db-* message
  ;; contract is (igropyr connpool)'s). Replies carry the caller's ref so a
  ;; late reply cannot be mis-read by that caller's next query. On a
  ;; transport error the connection replies to its caller, tells the pool
  ;; it already did (so the pool's DOWN handler does not send a second,
  ;; forever-unmatched reply), closes, and exits -- the pool's monitor
  ;; then rebuilds it.
  ;; What an idle connection may hold before it is considered wedged. It is
  ;; only ever reached by data nothing will consume -- notifications after a
  ;; LISTEN, or a server talking out of turn.
  (define max-idle-buffer 262144)

  ;; An adopted connection watches its OWNER.
  ;;
  ;; The pool monitors its connections, not the other way round, and a
  ;; monitor is one-directional: when the pool was killed or died of an
  ;; internal error, actor cleanup dropped the monitoring relationships and
  ;; left every connection actor running, each holding an fd and, over TLS,
  ;; a live session. Only an orderly pool-quit ever closed them. Recreating
  ;; the pool then stacked a second full set on top of the first.
  ;;
  ;; A connection whose owner is gone has nobody to serve and no way to be
  ;; reached, so it closes. Terminate is best-effort for the same reason as
  ;; in pool-quit below.
  (define (owner-gone! c)
    (guard (e (#t (void)))
      (send-msg! c MSG-TERMINATE empty-bv))
    (tx-close! c))

  (define (serve-loop c buf notify)
    (receive
      (`#(DOWN ,pid ,reason)
        (if (and notify (eq? pid notify))
            (owner-gone! c)
            (serve-loop c buf notify)))
      (`#(pool-request ,q ,ref ,from)
        ;; q is a plain SQL string (simple protocol) or (sql . params)
        ;; with params pre-converted by postgresql-execute (extended).
        (let ((r (guard (e (#t (as-postgresql-error e "query failed")))
                   (if (pair? q)
                       (run-extended! c buf (car q) (cdr q))
                       (run-query! c buf q)))))
          (if (transport-dead? r)
              (begin
          ;; THE POOL FIRST, then the caller. Telling the caller first
          ;; releases it, and its check-in can reach the pool before this
          ;; message does -- so the pool put a connection it was about to
          ;; be told was dead back into rotation and lent it to the next
          ;; borrower, whose statement went to a pid that then exited.
          ;; (The pool also refuses to re-lend a connection already marked
          ;; dying; both halves are needed, because that mark is what this
          ;; ordering makes arrive in time.)
          ;;
          ;; The cost of this order is a two-send window in which a kill
          ;; would leave the caller with no reply at all rather than a
          ;; duplicate one. That is a narrower window and a milder failure.
                (when notify (send notify (vector 'pool-conn-dead self)))
                (send from (vector 'pool-reply ref r))
                (tx-close! c))                  ; exit -> DOWN -> rebuild
              (begin
                (send from (vector 'pool-reply ref r))
                (when notify (send notify (vector 'pool-idle self ref)))
                (serve-loop c buf notify)))))
      ;; connpool-call sends this to whatever handle it was given when a call
      ;; times out; only a pool acts on it. Consume it here so it does not
      ;; sit in the mailbox forever, slowing every later selective receive
      ;; (the same accumulation drain-stale! exists to prevent).
      (`#(pool-request-cancel ,ref ,from) (serve-loop c buf notify))
      ;; A single connection is not a pool and keeps none of its
      ;; bookkeeping. Answering #f is what keeps the request from sitting
      ;; here forever; postgresql-pool-stats turns it into a clear error.
      (`#(pool-stats ,ref ,from)
        (send from (vector 'pool-stats-reply ref #f))
        (serve-loop c buf notify))
      (`#(pool-quit)
        ;; best-effort Terminate: over TLS the encrypt can fail when the
        ;; session already saw close_notify -- the close must run anyway,
        ;; or the fd and the SSL session leak
        (guard (e (#t (void)))
          (send-msg! c MSG-TERMINATE empty-bv))
        (tx-close! c))
      (`#(tcp-data ,bv)                          ; stray data between queries
        ;; a codec raise here (corrupted TLS record while idle) must still
        ;; free the session and the fd; the exit's DOWN makes a pool
        ;; rebuild the connection
        ;;
        ;; And the buffer is BOUNDED here. An idle connection accumulates
        ;; whatever the server sends without parsing it, and after a LISTEN
        ;; that is a legitimate, unbounded stream: every NOTIFY from any
        ;; other session arrives as a NotificationResponse nobody consumes.
        ;; max-message-len does not apply -- it bounds one message, and
        ;; these are individually small and endless. There is no delivery
        ;; API for them yet, so the honest answer is to refuse rather than
        ;; grow: the connection is dropped and the pool rebuilds it.
        (if (and (guard (e (#t #f)) (inbuf-append! buf (tx-decode c bv)) #t)
                 (<= (inbuf-length buf) max-idle-buffer))
            (serve-loop c buf notify)
            (tx-close! c)))
      (`#(tcp-eof) (tx-close! c))
      (`#(tcp-error ,e) (tx-close! c))))

  ;; After reporting up, wait to be adopted (the pool or the connecting
  ;; caller answers with pool-adopt). If nobody adopts -- the caller timed
  ;; out and moved on, or the pool was closed while we were still
  ;; authenticating -- close the socket and exit instead of holding an
  ;; authenticated connection forever.
  (define (await-adoption c buf notify)
    (receive (after connect-timeout-ms (tx-close! c))
      (`#(pool-adopt)
        (when notify (monitor notify))
        (serve-loop c buf notify))
      (`#(pool-quit)
        (guard (e (#t (void)))                   ; see serve-loop's pool-quit
          (send-msg! c MSG-TERMINATE empty-bv))
        (tx-close! c))
      (`#(tcp-data ,bv)
        (if (guard (e (#t #f)) (inbuf-append! buf (tx-decode c bv)) #t)
            (await-adoption c buf notify)
            (tx-close! c)))
      (`#(tcp-eof) (tx-close! c))
      (`#(tcp-error ,e) (tx-close! c))))

  ;; Upgrade a freshly connected socket to the negotiated transport. With
  ;; no 'tls option this is just the plain wrapper. With one, send
  ;; SSLRequest and read its answer -- a single RAW byte outside message
  ;; framing -- then hand the socket to the injected connector, which
  ;; drives the handshake and returns the codec
  ;; #(encrypt decrypt close! cb-hash): cb-hash is the RFC 5929
  ;; tls-server-end-point value for SCRAM channel binding, or #f (a
  ;; 3-slot codec is accepted and simply disables binding).
  ;; 'N' (server refuses TLS) fails hard: the caller asked for TLS, so
  ;; falling back to plaintext silently would defeat the point; trailing
  ;; bytes after the answer are injected plaintext and also fail.
  (define (setup-transport! raw host opts)
    (let ((connector (assq-ref opts 'tls)))
      (if (not connector)
          (make-tx raw #f #f #f #f)
          (begin
            (tcp-write! raw (bv-append (u32 8) (u32 80877103)) #f) ; SSLRequest
            (receive (after connect-timeout-ms
                        (postgresql-fail 'transport "tls: no SSLRequest answer"))
              (`#(tcp-data ,bv)
                (cond
                  ((and (= 1 (bytevector-length bv))
                        (fx= (bytevector-u8-ref bv 0) (char->integer #\S)))
                   (let ((codec
                          (guard (e (#t (postgresql-fail 'transport
                                          (tls-failure-reason e))))
                            (let ((v (connector raw host connect-timeout-ms)))
                              ;; validate the shape inside the guard, so a
                              ;; misbehaving custom connector surfaces as a
                              ;; clear tls-tagged error, not a raw assertion.
                              ;; Slot 3, when present, must be the binding
                              ;; hash (bytevector) or #f -- anything else
                              ;; would be mistaken for one and blow up
                              ;; mid-SCRAM.
                              (unless (and (vector? v) (>= (vector-length v) 3)
                                           (or (< (vector-length v) 4)
                                               (let ((cb (vector-ref v 3)))
                                                 (or (not cb) (bytevector? cb)))))
                                (error 'postgresql
                                  "tls: connector returned an invalid codec"))
                              v))))
                     (make-tx raw (vector-ref codec 0) (vector-ref codec 1)
                              (vector-ref codec 2)
                              (and (> (vector-length codec) 3)
                                   (vector-ref codec 3)))))
                  ((and (= 1 (bytevector-length bv))
                        (fx= (bytevector-u8-ref bv 0) (char->integer #\N)))
                   (postgresql-fail 'transport "server refused TLS"))
                  (else
                   (postgresql-fail 'transport
                     "unexpected data after SSLRequest"))))
              (`#(tcp-eof)
                (postgresql-fail 'transport "connection closed by server"))
              (`#(tcp-error ,e)
                (postgresql-fail 'transport "connection error")))))))

  ;; (igropyr tls) raises the neutral #(tls-error "tls: ...") -- keep the
  ;; text (the older http-client tag is accepted too, for any third-party
  ;; connector still using it). Conditions render via display-condition,
  ;; so our own shape-check error keeps its message instead of printing
  ;; as an opaque #<compound condition>.
  (define (tls-failure-reason e)
    (cond
      ((and (vector? e)
            (memq (vector-ref e 0) '(tls-error http-client-error))
            (> (vector-length e) 1) (string? (vector-ref e 1)))
       (vector-ref e 1))
      ((condition? e)
       (call-with-string-output-port (lambda (p) (display-condition e p))))
      (else
       (call-with-string-output-port (lambda (p) (write e p))))))

  ;; spawn a connection worker; reports #(pool-up ,ref ,self status) to
  ;; report-to -- ref lets the receiver ignore a stale report from an
  ;; earlier, timed-out attempt -- then waits for adoption and serves
  ;; queries (notifying `notify` when idle). Every failure path closes the
  ;; socket: the uv handle is freed only by tcp-close!, so skipping it
  ;; (e.g. on a failed auth, retried on a backoff by a pool) would leak
  ;; one fd per attempt until the process runs out.
  (define (start-connection host port user password db opts notify report-to ref)
    (spawn
      (lambda ()
        (define (report! status)
          (send report-to (vector 'pool-up ref self status)))
        (let ((started (guard (e (#t (as-postgresql-error e "connect failed")))
                         (tcp-connect! host port self)
                         'ok)))
          (if (not (eq? started 'ok))
              (report! started)
              (receive (after connect-timeout-ms
                          (report! (vector 'postgresql-error 'transport
                                           "connect timeout"))
                          ;; libuv resolves every connect exactly once;
                          ;; wait for the late callback and free the handle
                          (receive
                            (`#(tcp-connected ,c) (tcp-close! c))
                            (`#(tcp-connect-failed ,e) 'ok)))
                (`#(tcp-connect-failed ,e)
                  (report! (vector 'postgresql-error 'transport (uv-strerror e))))
                (`#(tcp-connected ,raw)
                  (tcp-read-start! raw)
                  (let ((t (guard (e (#t (as-postgresql-error e "connect failed")))
                             (setup-transport! raw host opts))))
                    (if (not (tx? t))
                        (begin (tcp-close! raw) (report! t))
                        (let* ((buf (make-inbuf))
                               (r (guard (e (#t (as-postgresql-error
                                                  e "connect failed")))
                                    (authenticate! t buf user password db opts)
                                    'ok)))
                          (if (eq? r 'ok)
                              (begin (report! 'ok) (await-adoption t buf notify))
                              (begin (tx-close! t) (report! r)))))))))))))

  ;; ---- pool + public API ---------------------------------------------------
  ;; The pool, lease and transaction machinery is (igropyr connpool), shared
  ;; with (igropyr mysql); this driver contributes the wire protocol above
  ;; and its error shapes below.

  (define cfg
    (make-connpool-cfg
      (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'postgresql-error)))
      (vector 'postgresql-error 'transport "connection lost")
      (vector 'postgresql-error 'transport "pool closed")
      (vector 'postgresql-error 'timeout "query timeout")
      (vector 'postgresql-error 'timeout "checkout timeout")
      "BEGIN"))

  (define (conn-args rest user)
    (values (if (and (pair? rest) (car rest)) (car rest) user)
            (if (and (pair? rest) (pair? (cdr rest))) (cadr rest) '())))

  ;; Without 'allow-cleartext-auth, SCRAM is the only auth this client can
  ;; complete that USES the password, so a password SCRAM must reject is
  ;; statically doomed: fail HERE, in the caller. Inside a pool the connect
  ;; worker's failure is invisible -- the pool retries on a backoff and the
  ;; caller sees a timeout with nothing in it about the password.
  ;; (scram-auth! keeps its own check as the backstop for the cleartext-
  ;; opted case where the server picks SCRAM anyway.)
  ;;
  ;; THIS RUNS WHETHER OR NOT THE SERVER WILL ASK. A server on `trust'
  ;; answers AuthenticationOk without looking at the password, and this
  ;; check still refuses the connect. Say so rather than let the sentence
  ;; above read as `this client can only do SCRAM'.
  (define (check-password! who password opts)
    (unless (or (scram-safe-password? password)
                (assq-ref opts 'allow-cleartext-auth))
      (assertion-violation who
        (string-append
          "password contains characters outside printable ASCII; SCRAM "
          "requires SASLprep normalization, which this client does not "
          "implement"))))

  ;; Connect + authenticate a single connection; returns the connection
  ;; process or raises #(postgresql-error tag msg). The database defaults to
  ;; the user name (as PostgreSQL itself defaults). Optional args after the
  ;; password: db name, then an options alist:
  ;;   'allow-cleartext-auth  permit cleartext password auth (see header).
  ;;   'tls                   a byte-codec connector -- pass tls-establish!
  ;;                          from (igropyr tls) to upgrade via SSLRequest
  ;;                          with full certificate verification.
  (define (postgresql-connect host port user password . rest)
    (let-values (((db opts) (conn-args rest user)))
      (check-password! 'postgresql-connect password opts)
      ;; A previous attempt from THIS process that timed out left its
      ;; worker's late up-report behind; its ref can never match again,
      ;; so it is immortal and every selective receive below scans past
      ;; it. A process that reconnects in a loop and never runs a query
      ;; had nothing else that would ever clear them.
      (connpool-drain-stale!)
      (let ((ref (gensym)))
        (start-connection host port user password db opts #f self ref)
        (receive (after (+ connect-timeout-ms 2000)
                    ;; the worker gives up waiting for adoption and closes
                    ;; its socket by itself; the ref keeps its late up-report
                    ;; from ever being mistaken for another connect's.
                    (raise (vector 'postgresql-error 'transport "connect timeout")))
          (`#(pool-up ,@ref ,pid ,status)
            (if (eq? status 'ok)
                (begin (send pid (vector 'pool-adopt)) pid)
                (raise status)))))))

  ;; Pool of n connections; returns the dispatcher, which postgresql-query
  ;; and postgresql-close! accept exactly like a single connection. Usable
  ;; immediately: queries queue until connections come up. Same optional
  ;; db + options as postgresql-connect.
  (define (postgresql-pool n host port user password . rest)
    (let-values (((db opts) (conn-args rest user)))
      (check-password! 'postgresql-pool password opts)
      ;; before the spawn: a bad size checked inside the pool process
      ;; raises where the caller cannot see it, and this returns a pid
      ;; that dies a moment later
      (connpool-check-size! 'postgresql-pool n)
      (spawn
        (lambda ()
          (connpool-loop n
            (lambda (notify report-to ref)
              (start-connection host port user password db opts
                                notify report-to ref))
            cfg)))))

  ;; Run one SQL statement; blocks only the calling green process. A
  ;; 'timeout error means the statement's outcome is UNKNOWN -- it may
  ;; still execute on the server.
  (define (postgresql-query mc sql) (connpool-call mc sql cfg))

  ;; Convert one parameter to its wire form (text-format bytes, or #f for
  ;; NULL). Runs in the CALLER, before anything reaches the connection
  ;; process: an unsupported argument is an assertion here, not a transport
  ;; error that tears down a healthy connection.
  (define (param->wire v)
    (cond
      ((eq? v #f) #f)                              ; SQL NULL
      ((string? v) (string->utf8 v))
      ((bytevector? v) v)                          ; pre-encoded text bytes
      ((number? v)
       (string->utf8
         (cond
           ;; PostgreSQL spells non-finite floats its own way; the Scheme
           ;; literals (+inf.0 etc.) would be rejected with 22P02 even
           ;; though SELECT returns these values as "Infinity"/"NaN"
           ((and (flonum? v) (nan? v)) "NaN")
           ((and (flonum? v) (infinite? v))
            (if (fl> v 0.0) "Infinity" "-Infinity"))
           ;; an exact non-integer would render as "1/3"; send a decimal.
           ;; The conversion itself can overflow to an infinity (a
           ;; rational beyond double range) -- spell that PostgreSQL's
           ;; way too, never the rejected Scheme literal.
           ((and (exact? v) (not (integer? v)))
            (let ((f (exact->inexact v)))
              (if (infinite? f)
                  (if (> f 0.0) "Infinity" "-Infinity")
                  (number->string f))))
           (else (number->string v)))))
      (else (assertion-violation 'postgresql-execute
              "parameter must be a string, number, bytevector or #f" v))))

  ;; Run ONE statement with $1..$n parameters over the extended query
  ;; protocol. Values never touch the SQL text, so they need no quoting
  ;; and cannot inject. Same result shapes and timeout semantics as
  ;; postgresql-query.
  (define (postgresql-execute mc sql . params)
    ;; Bind carries the parameter count as an Int16: 65535 is the
    ;; protocol's hard limit. Reject beyond it HERE -- inside the
    ;; connection process it would surface as a transport error and
    ;; tear down a healthy connection.
    (when (> (length params) 65535)
      (assertion-violation 'postgresql-execute
        "too many parameters (PostgreSQL allows at most 65535)"
        (length params)))
    (connpool-call mc (cons sql (map param->wire params)) cfg))

  ;; Borrow one whole connection from a POOL for the extent of proc, then
  ;; return it -- even if proc raises or exits non-locally. proc receives the
  ;; connection process; run postgresql-query on THAT connection and no other
  ;; caller's query can interleave. Requires a postgresql-pool. Don't send
  ;; queries (or a second checkout) to the pool itself while holding a
  ;; connection.
  (define (call-with-postgresql-connection pool proc)
    (connpool-lease pool proc cfg))

  ;; Run proc inside a transaction on a borrowed pool connection: BEGIN,
  ;; then COMMIT if proc returns normally, or ROLLBACK if it escapes.
  ;; Returns proc's value. Requires a postgresql-pool. If the borrower is
  ;; killed before it can commit/rollback, the pool discards and rebuilds
  ;; the connection, so a half-open transaction is never handed to the
  ;; next caller.
  (define (postgresql-transaction pool proc)
    (sql-transaction pool proc cfg))

  (define (postgresql-close! mc) (connpool-close! mc))

  ;; A snapshot of a pool: in-use, pending, checkout wait, query duration,
  ;; timeout counts and more. See (igropyr connpool) for the full key list.
  ;; This one does NOT re-tag: a pool that stops answering raises
  ;; #(connpool-error stats-timeout ,pool-id), not a postgresql-error.
  ;; Wrapping it would claim the database said something when nothing did.
  (define (postgresql-pool-stats pool) (connpool-stats pool))
)
