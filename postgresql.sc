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
;;;   (postgresql-close! db)
;;;
;;; Values arrive as strings (the wire text format); NULL is #f. The
;;; connection asks for client_encoding UTF8 at startup, so text is
;;; always UTF-8 on the wire regardless of the database encoding.
;;;
;;; Errors raise #(postgresql-error ,tag ,message) in the caller, where
;;; tag is one of exactly three shapes:
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
;;; of non-ASCII passwords is not applied; ASCII passwords (and
;;; passwords the server stored un-normalized) work, but an NFKC-unstable
;;; password that logs in via libpq may fail here.
;;;
;;; This client speaks plaintext; without TLS an on-path attacker can
;;; read query text and results regardless of the auth method. Run it
;;; over a trusted network or a local socket.

(library (igropyr postgresql)
  (export postgresql-connect postgresql-pool postgresql-query postgresql-close!
          postgresql-transaction call-with-postgresql-connection)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr buffer)
          (only (igropyr crypto)
                sha256 hmac-sha256 pbkdf2-hmac-sha256
                base64-encode base64-decode))

  (define connect-timeout-ms 10000)
  (define query-timeout-ms 60000)
  (define checkout-timeout-ms 60000)   ; how long a caller parks for a free lease

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

  (define (send-msg! c type payload) (tcp-write! c (msg type payload) #f))

  (define MSG-QUERY     (char->integer #\Q))
  (define MSG-PASSWORD  (char->integer #\p))   ; password / SASL response
  (define MSG-COPY-FAIL (char->integer #\f))
  (define MSG-TERMINATE (char->integer #\X))

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
  (define (next-msg! c buf)
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
                  (wait-data c buf loop))))
          (wait-data c buf loop))))

  (define (wait-data c buf k)
    (receive (after query-timeout-ms (postgresql-fail 'transport "server timeout"))
      (`#(tcp-data ,bv)
        (inbuf-append! buf bv)
        (k))
      (`#(tcp-eof) (postgresql-fail 'transport "connection closed by server"))
      (`#(tcp-error ,e) (postgresql-fail 'transport "connection error"))))

  ;; During startup/auth the server may interleave NoticeResponse ('N')
  ;; messages (an auth hook warning, a standby notice); they are
  ;; informational and must not fail the handshake.
  (define (next-msg!/skip-notices c buf)
    (let loop ()
      (let-values (((t p) (next-msg! c buf)))
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

  ;; Drive the SASL exchange to AuthenticationSASLFinal (verifying the
  ;; server signature), then return -- the caller reads the trailing
  ;; AuthenticationOk.
  (define (scram-auth! c buf user password sasl-payload)
    (unless (member "SCRAM-SHA-256" (sasl-mechanisms sasl-payload))
      (postgresql-fail 'transport "server offered no SCRAM-SHA-256 mechanism"))
    (let* ((cnonce (make-client-nonce))
           (client-first-bare (string-append "n=,r=" cnonce))
           (client-first (string-append "n,," client-first-bare)))
      (send-msg! c MSG-PASSWORD
        (bv-append (cstr "SCRAM-SHA-256")
                   (u32 (string-length client-first))
                   (string->utf8 client-first)))
      (let-values (((t p) (next-msg!/skip-notices c buf)))
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
          ;; field is a protocol error, not a raw assertion
          (unless (and snonce salt-b64 iters (fixnum? iters) (> iters 0)
                       (>= (string-length snonce) (string-length cnonce))
                       (string=? (substring snonce 0 (string-length cnonce)) cnonce))
            (postgresql-fail 'transport "malformed SCRAM server-first message"))
          (let* ((salt (base64-decode salt-b64))
                 (final-noproof (string-append "c=biws,r=" snonce)) ; biws=base64("n,,")
                 (auth-msg (string-append client-first-bare "," server-first
                                          "," final-noproof)))
            (let-values (((proof server-sig) (scram-derive password salt iters auth-msg)))
              (send-msg! c MSG-PASSWORD
                (string->utf8
                  (string-append final-noproof ",p=" (base64-encode proof))))
              (let-values (((t2 p2) (next-msg!/skip-notices c buf)))
                (cond
                  ((and (fx= t2 (char->integer #\R)) (= (read-u32-be p2 0) 12))
                   (let ((v (attr (scram-attrs
                                    (utf8->string (bv-sub p2 4 (bytevector-length p2))))
                                  #\v)))
                     (unless (and v (bytevector=? (base64-decode v) server-sig))
                       (postgresql-fail 'transport "server signature mismatch"))))
                  ((fx= t2 (char->integer #\E)) (raise (error-response->fail p2)))
                  (else (postgresql-fail 'transport "expected SASLFinal"))))))))))

  ;; ---- authentication ----------------------------------------------------

  (define (assq-ref alist key)
    (let ((p (and (pair? alist) (assq key alist))))
      (and p (cdr p))))

  (define (authenticate! c buf user password db opts)
    (tcp-write! c (startup-msg user db) #f)
    (let loop ()
      (let-values (((t p) (next-msg! c buf)))
        (case (integer->char t)
          ((#\R)
           (let ((code (read-u32-be p 0)))
             (cond
               ((= code 0) (finish-startup! c buf))         ; AuthenticationOk
               ((= code 10)                                 ; AuthenticationSASL
                (scram-auth! c buf user password p)
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
                  "unexpected message during authentication"))))))

  ;; After AuthenticationOk the server streams ParameterStatus/BackendKeyData
  ;; and notices; consume through the first ReadyForQuery ('Z').
  (define (finish-startup! c buf)
    (let loop ()
      (let-values (((t p) (next-msg! c buf)))
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

  ;; Run one simple-query string. A server SQL error ('E') is remembered and
  ;; raised only after ReadyForQuery ('Z'), so the connection stays framed
  ;; and usable. With multiple statements the last result is returned.
  ;; COPY: FROM STDIN is refused with CopyFail (the server then reports a
  ;; normal SQL error); TO STDOUT is not supported -- its data stream is
  ;; consumed and a feature-not-supported error is raised, rather than
  ;; silently discarding the rows and reporting success.
  (define (run-query! c buf sql)
    (send-msg! c MSG-QUERY (cstr sql))
    (let loop ((names #f) (rows '()) (result #f) (err #f))
      (let-values (((t p) (next-msg! c buf)))
        (case (integer->char t)
          ((#\T) (loop (parse-row-desc p) '() result err))
          ((#\D) (loop names (cons (parse-data-row p) rows) result err))
          ((#\C)
           (loop #f '()
                 (if names
                     (vector 'rows names (reverse rows))
                     (vector 'ok (command-affected p)))
                 err))
          ((#\I) (loop #f '() (vector 'ok 0) err))          ; EmptyQueryResponse
          ((#\G #\W)                                        ; CopyIn/CopyBoth
           (send-msg! c MSG-COPY-FAIL
             (cstr "COPY FROM STDIN is not supported by this client"))
           (loop names rows result err))                    ; server sends E, Z
          ((#\H)                                            ; CopyOutResponse
           (loop names rows result
                 (or err (vector 'postgresql-error "0A000"
                                 "COPY TO STDOUT is not supported by this client"))))
          ((#\E) (loop names rows result (error-response->fail p)))
          ((#\Z) (if err (raise err) (or result (vector 'ok 0))))
          (else (loop names rows result err))))))          ; S, N, K, d, c ...

  ;; ---- connection process ------------------------------------------------

  ;; notify (a pid or #f): told #(postgresql-idle ,self) after each finished
  ;; query, so a pool can hand this connection its next task. Replies carry
  ;; the caller's ref so a late reply cannot be mis-read by that caller's
  ;; next query. On a transport error the connection replies to its caller,
  ;; tells the pool it already did (so the pool's DOWN handler does not send
  ;; a second, forever-unmatched reply), closes, and exits -- the pool's
  ;; monitor then rebuilds it.
  (define (serve-loop c buf notify)
    (receive
      (`#(postgresql-query ,sql ,ref ,from)
        (let ((r (guard (e (#t (as-postgresql-error e "query failed")))
                   (run-query! c buf sql))))
          (send from (vector 'postgresql-reply ref r))
          (if (transport-dead? r)
              (begin
                (when notify (send notify (vector 'postgresql-conn-dead self)))
                (tcp-close! c))                 ; exit -> DOWN -> rebuild
              (begin
                (when notify (send notify (vector 'postgresql-idle self)))
                (serve-loop c buf notify)))))
      (`#(postgresql-quit)
        (send-msg! c MSG-TERMINATE empty-bv)     ; Terminate
        (tcp-close! c))
      (`#(tcp-data ,bv)                          ; stray data between queries
        (inbuf-append! buf bv)
        (serve-loop c buf notify))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; After reporting up, wait to be adopted (the pool or the connecting
  ;; caller answers with postgresql-adopt). If nobody adopts -- the caller
  ;; timed out and moved on, or the pool was closed while we were still
  ;; authenticating -- close the socket and exit instead of holding an
  ;; authenticated connection forever.
  (define (await-adoption c buf notify)
    (receive (after connect-timeout-ms (tcp-close! c))
      (`#(postgresql-adopt) (serve-loop c buf notify))
      (`#(postgresql-quit) (send-msg! c MSG-TERMINATE empty-bv) (tcp-close! c))
      (`#(tcp-data ,bv) (inbuf-append! buf bv) (await-adoption c buf notify))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; spawn a connection worker; reports #(postgresql-up ,ref ,self status)
  ;; to report-to -- ref lets the receiver ignore a stale report from an
  ;; earlier, timed-out attempt -- then waits for adoption and serves
  ;; queries (notifying `notify` when idle). Every failure path closes the
  ;; socket: the uv handle is freed only by tcp-close!, so skipping it
  ;; (e.g. on a failed auth, retried every second by a pool) would leak
  ;; one fd per attempt until the process runs out.
  (define (start-connection host port user password db opts notify report-to ref)
    (spawn
      (lambda ()
        (define (report! status)
          (send report-to (vector 'postgresql-up ref self status)))
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
                (`#(tcp-connected ,c)
                  (tcp-read-start! c)
                  (let* ((buf (make-inbuf))
                         (r (guard (e (#t (as-postgresql-error e "connect failed")))
                              (authenticate! c buf user password db opts)
                              'ok)))
                    (if (eq? r 'ok)
                        (begin (report! 'ok) (await-adoption c buf notify))
                        (begin (tcp-close! c) (report! r)))))))))))

  ;; ---- connection pool ---------------------------------------------------

  ;; Fixed pool of n connections behind a dispatcher process. Queries go to
  ;; an idle connection or wait in a FIFO; replies flow directly from the
  ;; connection to the caller. Dead connections are replaced automatically
  ;; (1s backoff on failed connects); a caller whose connection dies
  ;; mid-query gets #(postgresql-error transport ...) exactly once.
  (define (pool-loop n host port user password db opts)
    (define me self)
    (define idle '())
    (define busy (make-eq-hashtable))   ; conn pid -> (caller-pid . ref)
    ;; transaction leases: a whole connection handed to one borrower for the
    ;; extent of a transaction, kept out of query rotation until checked back
    ;; in (or its borrower dies). Each lease is its own record -- keyed by
    ;; connection, carrying the borrower, its monitor and the checkout ref --
    ;; so one borrower holding several leases (nested checkouts) never
    ;; clobbers its own bookkeeping.
    (define leased (make-eq-hashtable))       ; conn pid -> #(borrower mon ref)
    (define dying (make-eq-hashtable))        ; conn pid -> #t (being torn down)
    (define pending-front '())
    (define pending-back '())
    (define (pending?) (or (pair? pending-front) (pair? pending-back)))
    (define (pop-pending!)
      (when (null? pending-front)
        (set! pending-front (reverse pending-back))
        (set! pending-back '()))
      (let ((x (car pending-front)))
        (set! pending-front (cdr pending-front))
        x))
    ;; checkout requests waiting for a free connection; each is (ref . from)
    (define co-front '())
    (define co-back '())
    (define (co-pending?) (or (pair? co-front) (pair? co-back)))
    (define (pop-co!)
      (when (null? co-front)
        (set! co-front (reverse co-back))
        (set! co-back '()))
      (let ((x (car co-front)))
        (set! co-front (cdr co-front))
        x))
    (define (connect!)
      (monitor (start-connection host port user password db opts me me (gensym))))
    ;; a job is #(sql ref from)
    (define (assign! c job)
      (hashtable-set! busy c (cons (vector-ref job 2) (vector-ref job 1)))
      (send c (vector 'postgresql-query (vector-ref job 0)
                      (vector-ref job 1) (vector-ref job 2))))
    ;; hand connection c to a checkout request req = (ref . from), and
    ;; monitor the borrower: the supervisor killing a stuck worker discards
    ;; its dynamic-wind winders (see actor @kill), so the checkin never runs
    ;; -- this monitor is the only thing that reclaims the connection.
    (define (lease! c req)
      (let ((ref (car req)) (from (cdr req)))
        (hashtable-set! leased c (vector from (monitor from) ref))
        (send from (vector 'postgresql-checkout-reply ref c))))
    (define (drop-lease! c entry)
      (demonitor (vector-ref entry 1))
      (hashtable-delete! leased c))
    ;; all (conn . entry) leases held by borrower pid
    (define (leases-of pid)
      (let ((ks (hashtable-keys leased)) (acc '()))
        (do ((i 0 (+ i 1))) ((= i (vector-length ks)) acc)
          (let* ((c (vector-ref ks i)) (e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) pid))
              (set! acc (cons (cons c e) acc)))))))
    ;; the lease created for checkout ref by borrower from, or #f
    (define (lease-by-ref ref from)
      (let ((ks (hashtable-keys leased)))
        (let loop ((i 0))
          (if (= i (vector-length ks))
              #f
              (let* ((c (vector-ref ks i)) (e (hashtable-ref leased c #f)))
                (if (and e (eq? (vector-ref e 0) from) (eq? (vector-ref e 2) ref))
                    (cons c e)
                    (loop (+ i 1))))))))
    ;; alternate between the single-query queue and checkout waiters when
    ;; both are non-empty, so a sustained stream of one kind cannot starve
    ;; the other past its timeout
    (define co-turn #f)
    (define (make-available! c)
      (hashtable-delete! busy c)
      (cond
        ((and (pending?) (co-pending?))
         (if co-turn
             (begin (set! co-turn #f) (lease! c (pop-co!)))
             (begin (set! co-turn #t) (assign! c (pop-pending!)))))
        ((pending?) (assign! c (pop-pending!)))
        ((co-pending?) (lease! c (pop-co!)))
        (else (set! idle (cons c idle)))))
    (do ((i 0 (+ i 1))) ((= i n)) (connect!))
    (let loop ()
      (receive
        (`#(postgresql-query ,sql ,ref ,from)
          (let ((job (vector sql ref from)))
            (if (pair? idle)
                (let ((c (car idle)))
                  (set! idle (cdr idle))
                  (assign! c job))
                (set! pending-back (cons job pending-back))))
          (loop))
        (`#(postgresql-idle ,c)
          ;; a leased connection pings idle after each of its transaction
          ;; queries -- ignore those, it stays with its lessee; likewise skip
          ;; a connection we are tearing down.
          (unless (or (hashtable-ref leased c #f) (hashtable-ref dying c #f))
            (make-available! c))
          (loop))
        (`#(postgresql-conn-dead ,c)
          ;; the connection already sent the transport-error reply to its
          ;; caller and is about to exit: clear the busy entry so the DOWN
          ;; below does not send a duplicate reply, and mark it dying so
          ;; the DOWN still rebuilds it.
          (hashtable-delete! busy c)
          (hashtable-set! dying c #t)
          (loop))
        (`#(postgresql-checkout ,ref ,from)
          (if (pair? idle)
              (let ((c (car idle)))
                (set! idle (cdr idle))
                (lease! c (cons ref from)))
              (set! co-back (cons (cons ref from) co-back)))
          (loop))
        (`#(postgresql-checkin ,from ,c)
          ;; only when c really is leased to `from` -- guards a stale or double
          ;; checkin (e.g. after the connection already died and was rebuilt).
          (let ((e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) from))
              (drop-lease! c e)
              (make-available! c)))
          (loop))
        (`#(postgresql-checkin-broken ,from ,c)
          ;; the lessee could not clean the connection (e.g. ROLLBACK failed):
          ;; drop the lease and destroy+rebuild it rather than ever lending a
          ;; possibly-open transaction to the next caller.
          (let ((e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) from))
              (drop-lease! c e)
              (hashtable-set! dying c #t)
              (send c (vector 'postgresql-quit))))   ; -> DOWN -> rebuild
          (loop))
        (`#(postgresql-checkout-cancel ,ref ,from)
          ;; a checkout timed out: drop its still-queued request so a freed
          ;; connection is never leased to a borrower that has moved on. If the
          ;; pool already leased one to it (raced the timeout), reclaim exactly
          ;; that lease -- matched by ref, so other leases the same borrower
          ;; holds are untouched.
          (set! co-front (filter (lambda (x) (not (eq? (car x) ref))) co-front))
          (set! co-back  (filter (lambda (x) (not (eq? (car x) ref))) co-back))
          (let ((hit (lease-by-ref ref from)))
            (when hit
              (drop-lease! (car hit) (cdr hit))
              (make-available! (car hit))))
          (loop))
        (`#(postgresql-up ,ref ,pid ,status)
          (if (eq? status 'ok)
              (begin
                (send pid (vector 'postgresql-adopt))
                (make-available! pid))
              ;; failed connect: retry after a delay
              (spawn (lambda ()
                       (sleep-ms 1000)
                       (send me (vector 'pool-reconnect)))))
          (loop))
        (`#(pool-reconnect)
          (connect!)
          (loop))
        (`#(DOWN ,pid ,reason)
          (cond
            ;; (1) a transaction borrower died (a crash, or the supervisor
            ;; killing a stuck worker -- winders discarded, so no checkin ran).
            ;; Its connections may hold half-open transactions: destroy every
            ;; one it held and let each connection's own DOWN below rebuild a
            ;; clean replacement.
            ((pair? (leases-of pid))
             (for-each
               (lambda (hit)
                 (drop-lease! (car hit) (cdr hit))
                 (hashtable-set! dying (car hit) #t)
                 (send (car hit) (vector 'postgresql-quit)))
               (leases-of pid)))
            ;; (2) a connection died (idle, mid single-query, leased, or one we
            ;; are already tearing down). Fail any waiting single-query caller,
            ;; drop a lease if it held one, and rebuild.
            ((or (memq pid idle) (hashtable-contains? busy pid)
                 (hashtable-ref leased pid #f) (hashtable-ref dying pid #f))
             (set! idle (remq pid idle))
             (hashtable-delete! dying pid)
             (let ((entry (hashtable-ref busy pid #f)))
               (hashtable-delete! busy pid)
               (when entry
                 (send (car entry)
                       (vector 'postgresql-reply (cdr entry)
                               (vector 'postgresql-error 'transport
                                       "connection lost")))))
             (let ((e (hashtable-ref leased pid #f)))
               (when e (drop-lease! pid e)))
             (connect!)))
          (loop))
        (`#(postgresql-quit)
          (for-each (lambda (c) (send c (vector 'postgresql-quit))) idle)
          (vector-for-each
            (lambda (c) (send c (vector 'postgresql-quit)))
            (hashtable-keys busy))
          (vector-for-each
            (lambda (c) (send c (vector 'postgresql-quit)))
            (hashtable-keys leased))
          ;; connections still authenticating self-terminate: nobody adopts
          ;; them once this process is gone. Queued callers get an error now
          ;; instead of parking until their timeouts.
          (let ((closed (vector 'postgresql-error 'transport "pool closed")))
            (for-each
              (lambda (job)
                (send (vector-ref job 2)
                      (vector 'postgresql-reply (vector-ref job 1) closed)))
              (append pending-front (reverse pending-back)))
            (for-each
              (lambda (req)
                (send (cdr req)
                      (vector 'postgresql-checkout-failed (car req) closed)))
              (append co-front (reverse co-back))))
          'done))))

  ;; ---- public API --------------------------------------------------------

  (define (conn-args rest user)
    (values (if (and (pair? rest) (car rest)) (car rest) user)
            (if (and (pair? rest) (pair? (cdr rest))) (cadr rest) '())))

  ;; Connect + authenticate a single connection; returns the connection
  ;; process or raises #(postgresql-error tag msg). The database defaults to
  ;; the user name (as PostgreSQL itself defaults). Optional args after the
  ;; password: db name, then an options alist:
  ;;   'allow-cleartext-auth  permit cleartext password auth (see header).
  (define (postgresql-connect host port user password . rest)
    (let-values (((db opts) (conn-args rest user)))
      (let ((ref (gensym)))
        (start-connection host port user password db opts #f self ref)
        (receive (after (+ connect-timeout-ms 2000)
                    ;; the worker gives up waiting for adoption and closes
                    ;; its socket by itself; the ref keeps its late up-report
                    ;; from ever being mistaken for another connect's.
                    (raise (vector 'postgresql-error 'transport "connect timeout")))
          (`#(postgresql-up ,@ref ,pid ,status)
            (if (eq? status 'ok)
                (begin (send pid (vector 'postgresql-adopt)) pid)
                (raise status)))))))

  ;; Pool of n connections; returns the dispatcher, which postgresql-query
  ;; and postgresql-close! accept exactly like a single connection. Usable
  ;; immediately: queries queue until connections come up. Same optional
  ;; db + options as postgresql-connect.
  (define (postgresql-pool n host port user password . rest)
    (let-values (((db opts) (conn-args rest user)))
      (spawn (lambda () (pool-loop n host port user password db opts)))))

  ;; Run one SQL statement; blocks only the calling green process. The
  ;; per-call ref (a fresh gensym) is echoed in the reply, so a late reply
  ;; after a timeout will not be matched by the caller's next query. A
  ;; 'timeout error means the statement's outcome is UNKNOWN -- it may
  ;; still execute on the server.
  (define (postgresql-query mc sql)
    (let ((ref (gensym)))
      (send mc (vector 'postgresql-query sql ref self))
      (receive (after query-timeout-ms
                  (raise (vector 'postgresql-error 'timeout "query timeout")))
        (`#(postgresql-reply ,@ref ,r)
          (if (and (vector? r) (eq? (vector-ref r 0) 'postgresql-error))
              (raise r)
              r)))))

  ;; ---- transactions: borrow a whole pool connection ----------------------

  ;; Ask the pool for a dedicated connection and park until one is free (or
  ;; raise #(postgresql-error timeout "checkout timeout") -- the pool is
  ;; saturated, nothing is broken). Internal: callers use
  ;; call-with-postgresql-connection / postgresql-transaction, which
  ;; guarantee checkin.
  (define (pool-checkout pool)
    (let ((ref (gensym)))
      (send pool (vector 'postgresql-checkout ref self))
      (receive (after checkout-timeout-ms
                  (send pool (vector 'postgresql-checkout-cancel ref self))
                  (raise (vector 'postgresql-error 'timeout "checkout timeout")))
        (`#(postgresql-checkout-reply ,@ref ,conn) conn)
        (`#(postgresql-checkout-failed ,@ref ,err) (raise err)))))

  ;; Borrow one whole connection from a POOL for the extent of proc, then
  ;; return it -- even if proc raises or exits non-locally. proc receives the
  ;; connection process; run postgresql-query on THAT connection and no other
  ;; caller's query can interleave. Requires a postgresql-pool. Don't send
  ;; queries (or a second checkout) to the pool itself while holding a
  ;; connection: an exhausted pool deadlocks the former and delays the
  ;; latter.
  (define (call-with-postgresql-connection pool proc)
    (let ((conn (pool-checkout pool)))
      (dynamic-wind
        (lambda () (void))
        (lambda () (proc conn))
        (lambda () (send pool (vector 'postgresql-checkin self conn))))))

  ;; ROLLBACK on a borrowed connection without parking a full query timeout
  ;; when the connection is already dead: monitor it, so a dead process
  ;; answers with an immediate DOWN instead of 60 seconds of silence.
  ;; -> #t when the connection cannot be returned clean.
  (define (rollback! conn)
    (let ((m (monitor conn)) (ref (gensym)))
      (let ((broken
             (guard (e (#t #t))
               (send conn (vector 'postgresql-query "ROLLBACK" ref self))
               (receive (after query-timeout-ms #t)
                 (`#(postgresql-reply ,@ref ,r)
                   (and (vector? r) (eq? (vector-ref r 0) 'postgresql-error)))
                 (`#(DOWN ,@conn ,reason) #t)))))
        (when m
          (demonitor m)
          ;; a DOWN already queued between the reply and the demonitor
          ;; would sit unmatched forever -- drain it
          (receive (after 0 'ok) (`#(DOWN ,@conn ,reason) 'ok)))
        broken)))

  ;; Run proc inside a transaction on a borrowed pool connection: BEGIN
  ;; first, then COMMIT if proc returns normally, or ROLLBACK if it escapes.
  ;; Returns proc's value. proc receives the connection; issue every statement
  ;; of the transaction on it. Requires a postgresql-pool. If the borrower is
  ;; killed before it can commit/rollback, the pool discards and rebuilds the
  ;; connection, so a half-open transaction is never handed to the next caller.
  (define (postgresql-transaction pool proc)
    (let ((conn (pool-checkout pool)))
      (let ((committed #f) (broken #f))
        (dynamic-wind
          (lambda () (void))
          (lambda ()
            (postgresql-query conn "BEGIN")
            (let ((r (proc conn)))
              (postgresql-query conn "COMMIT")
              (set! committed #t)
              r))
          (lambda ()
            (unless committed
              ;; roll back; if ROLLBACK fails (or the connection is dead)
              ;; the transaction may still be open, so flag the connection
              ;; for discard instead of returning it dirty.
              (set! broken (rollback! conn)))
            (send pool (vector (if broken 'postgresql-checkin-broken
                                   'postgresql-checkin)
                               self conn)))))))

  (define (postgresql-close! mc)
    (send mc (vector 'postgresql-quit)))
)
