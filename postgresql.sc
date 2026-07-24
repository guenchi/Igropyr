#!chezscheme
;;; (igropyr postgresql) -- non-blocking PostgreSQL client (protocol 3.0, simple query).
;;;
;;; One green process per connection; callers park in receive while the
;;; OS thread keeps serving other requests. The PostgreSQL protocol is
;;; strictly request-response within a connection, so concurrent queries
;;; from many workers are queued in the connection's mailbox and run one
;;; at a time.
;;;
;;;   (define db (postgresql-connect "127.0.0.1" 5432 "user" "password" "dbname"))
;;;   (postgresql-query db "SELECT id, name FROM users")
;;;     ;; -> #(rows ("id" "name") (("1" "Alice") ("2" "Bob")))
;;;   (postgresql-query db "INSERT INTO users (name) VALUES ('Eve')")
;;;     ;; -> #(ok 1)                          ; affected rows
;;;   (postgresql-close! db)
;;;
;;; Values arrive as strings (the wire text format); NULL is #f. Server
;;; SQL errors raise #(postgresql-error ,sqlstate ,message) in the caller, where
;;; sqlstate is the 5-char SQLSTATE string; a transport/framing failure
;;; raises #(postgresql-error transport ,message) and the connection is torn down
;;; and (in a pool) rebuilt.
;;;
;;; Authentication: SCRAM-SHA-256 (RFC 7677, the PostgreSQL default since
;;; v10) and cleartext password. MD5 is not implemented -- configure the
;;; server for scram-sha-256, or a trusted local socket. This client
;;; speaks plaintext; run it over a trusted network or a local socket.

(library (igropyr postgresql)
  (export postgresql-connect postgresql-pool postgresql-query postgresql-close!
          postgresql-transaction call-with-postgresql-connection)
  (import (chezscheme) (igropyr actor) (igropyr libuv)
          (only (igropyr crypto)
                sha256 hmac-sha256 pbkdf2-hmac-sha256
                base64-encode base64-decode))

  (define connect-timeout-ms 10000)
  (define query-timeout-ms 60000)
  (define checkout-timeout-ms 60000)   ; how long a caller parks for a free lease

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

  ;; ---- big-endian integer codecs ----------------------------------------

  (define (u32 v)                       ; 32-bit big-endian, 4 bytes
    (bytevector (fxand (fxsrl v 24) #xFF) (fxand (fxsrl v 16) #xFF)
                (fxand (fxsrl v 8) #xFF) (fxand v #xFF)))

  (define (read-u32-be bv pos)
    (+ (* (bytevector-u8-ref bv pos) 16777216)
       (* (bytevector-u8-ref bv (+ pos 1)) 65536)
       (* (bytevector-u8-ref bv (+ pos 2)) 256)
       (bytevector-u8-ref bv (+ pos 3))))

  ;; DataRow column lengths are a signed Int32 (-1 marks SQL NULL).
  (define (read-i32-be bv pos)
    (let ((v (read-u32-be bv pos)))
      (if (>= v #x80000000) (- v #x100000000) v)))

  (define (read-u16-be bv pos)
    (+ (fxsll (bytevector-u8-ref bv pos) 8) (bytevector-u8-ref bv (+ pos 1))))

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
  ;; and payload, but not the type byte) + payload.
  (define (msg type payload)
    (let ((n (bytevector-length payload)))
      (bv-append (bytevector type) (u32 (+ 4 n)) payload)))

  (define (send-msg! c type payload) (tcp-write! c (msg type payload) #f))

  (define MSG-QUERY     (char->integer #\Q))
  (define MSG-PASSWORD  (char->integer #\p))   ; password / SASL response
  (define MSG-TERMINATE (char->integer #\X))

  ;; StartupMessage has no type byte: Int32 length + Int32 protocol(3.0) +
  ;; a run of key\0value\0 pairs + a final \0.
  (define (startup-msg user db)
    (let* ((body (bv-append (u32 196608)          ; protocol 3.0 == 0x00030000
                            (cstr "user") (cstr user)
                            (cstr "database") (cstr db)
                            (bytevector 0)))
           (len (+ 4 (bytevector-length body))))
      (bv-append (u32 len) body)))

  (define (postgresql-fail state msg) (raise (vector 'postgresql-error state msg)))

  ;; wrap any exception as #(postgresql-error ...): an already-tagged postgresql-error
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

  ;; blocking: returns (values type payload); runs in the connection process
  (define (next-msg! c bufbox)
    (let loop ()
      (let ((buf (unbox bufbox)))
        (if (>= (bytevector-length buf) 5)
            (let* ((type (bytevector-u8-ref buf 0))
                   (len (read-u32-be buf 1))
                   (total (+ 1 len)))
              (if (>= (bytevector-length buf) total)
                  (begin
                    (set-box! bufbox (bv-sub buf total (bytevector-length buf)))
                    (values type (bv-sub buf 5 total)))
                  (wait-data c bufbox loop)))
            (wait-data c bufbox loop)))))

  (define (wait-data c bufbox k)
    (receive (after query-timeout-ms (postgresql-fail 'transport "server timeout"))
      (`#(tcp-data ,bv)
        (set-box! bufbox (bv-append (unbox bufbox) bv))
        (k))
      (`#(tcp-eof) (postgresql-fail 'transport "connection closed by server"))
      (`#(tcp-error ,e) (postgresql-fail 'transport "connection error"))))

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
  ;; valid SCRAM nonce token.
  (define (make-client-nonce)
    (base64-encode
      (call-with-port (open-file-input-port "/dev/urandom")
        (lambda (p) (get-bytevector-n p 18)))))

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
  (define (scram-attrs s)
    (map (lambda (tok) (cons (string-ref tok 0) (substring tok 2 (string-length tok))))
         (split-on s #\,)))

  (define (attr a key) (cond ((assv key a) => cdr) (else #f)))

  ;; Drive the SASL exchange to AuthenticationSASLFinal (verifying the
  ;; server signature), then return -- the caller reads the trailing
  ;; AuthenticationOk.
  (define (scram-auth! c bufbox user password sasl-payload)
    (unless (member "SCRAM-SHA-256" (sasl-mechanisms sasl-payload))
      (postgresql-fail 'transport "server offered no SCRAM-SHA-256 mechanism"))
    (let* ((cnonce (make-client-nonce))
           ;; SASLprep is skipped: correct for ASCII passwords, which is the
           ;; common case; a non-ASCII password would need normalization here.
           (client-first-bare (string-append "n=,r=" cnonce))
           (client-first (string-append "n,," client-first-bare)))
      (send-msg! c MSG-PASSWORD
        (bv-append (cstr "SCRAM-SHA-256")
                   (u32 (string-length client-first))
                   (string->utf8 client-first)))
      (let-values (((t p) (next-msg! c bufbox)))
        (unless (and (char=? (integer->char t) #\R) (= (read-u32-be p 0) 11))
          (if (char=? (integer->char t) #\E)
              (raise (error-response->fail p))
              (postgresql-fail 'transport "expected SASLContinue")))
        (let* ((server-first (utf8->string (bv-sub p 4 (bytevector-length p))))
               (a (scram-attrs server-first))
               (snonce (attr a #\r))
               (salt (base64-decode (attr a #\s)))
               (iters (string->number (attr a #\i))))
          (unless (and snonce iters
                       (>= (string-length snonce) (string-length cnonce))
                       (string=? (substring snonce 0 (string-length cnonce)) cnonce))
            (postgresql-fail 'transport "server nonce does not extend client nonce"))
          (let* ((salted (pbkdf2-hmac-sha256 (string->utf8 password) salt iters 32))
                 (client-key (hmac-sha256 salted (string->utf8 "Client Key")))
                 (stored-key (sha256 client-key))
                 (final-noproof (string-append "c=biws,r=" snonce))  ; biws=base64("n,,")
                 (auth-msg (string-append client-first-bare "," server-first
                                          "," final-noproof))
                 (client-sig (hmac-sha256 stored-key (string->utf8 auth-msg)))
                 (proof (bv-xor client-key client-sig))
                 (client-final (string-append final-noproof ",p=" (base64-encode proof)))
                 (server-key (hmac-sha256 salted (string->utf8 "Server Key")))
                 (server-sig (hmac-sha256 server-key (string->utf8 auth-msg))))
            (send-msg! c MSG-PASSWORD (string->utf8 client-final))
            (let-values (((t2 p2) (next-msg! c bufbox)))
              (cond
                ((and (char=? (integer->char t2) #\R) (= (read-u32-be p2 0) 12))
                 (let ((v (attr (scram-attrs
                                  (utf8->string (bv-sub p2 4 (bytevector-length p2))))
                                #\v)))
                   (unless (and v (bytevector=? (base64-decode v) server-sig))
                     (postgresql-fail 'transport "server signature mismatch"))))
                ((char=? (integer->char t2) #\E) (raise (error-response->fail p2)))
                (else (postgresql-fail 'transport "expected SASLFinal")))))))))

  ;; ---- authentication ----------------------------------------------------

  (define (authenticate! c bufbox user password db)
    (tcp-write! c (startup-msg user db) #f)
    (let loop ()
      (let-values (((t p) (next-msg! c bufbox)))
        (case (integer->char t)
          ((#\R)
           (let ((code (read-u32-be p 0)))
             (cond
               ((= code 0) (finish-startup! c bufbox))       ; AuthenticationOk
               ((= code 10)                                  ; AuthenticationSASL
                (scram-auth! c bufbox user password p)
                (loop))                                      ; then AuthenticationOk
               ((= code 3)                                   ; cleartext password
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
          (else (postgresql-fail 'transport "unexpected message during authentication"))))))

  ;; After AuthenticationOk the server streams ParameterStatus/BackendKeyData
  ;; and notices; consume through the first ReadyForQuery ('Z').
  (define (finish-startup! c bufbox)
    (let loop ()
      (let-values (((t p) (next-msg! c bufbox)))
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
      (or (and (pair? toks) (string->number (list-ref toks (- (length toks) 1))))
          0)))

  ;; Run one simple-query string. A server SQL error ('E') is remembered and
  ;; raised only after ReadyForQuery ('Z'), so the connection stays framed
  ;; and usable. With multiple statements the last result is returned.
  (define (run-query! c bufbox sql)
    (send-msg! c MSG-QUERY (cstr sql))
    (let loop ((names #f) (rows '()) (result #f) (err #f))
      (let-values (((t p) (next-msg! c bufbox)))
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
          ((#\E) (loop names rows result (error-response->fail p)))
          ((#\Z) (if err (raise err) (or result (vector 'ok 0))))
          (else (loop names rows result err))))))           ; S, N, K, ... ignored

  ;; ---- connection process ------------------------------------------------

  ;; notify (a pid or #f): told #(postgresql-idle ,self) after each finished query,
  ;; so a pool can hand this connection its next task. Replies carry the
  ;; caller's ref so a late reply cannot be mis-read by that caller's next
  ;; query. On a transport error the connection is closed and this process
  ;; exits -- the pool's monitor then rebuilds it.
  (define (serve-loop c bufbox notify)
    (receive
      (`#(postgresql-query ,sql ,ref ,from)
        (let ((r (guard (e (#t (as-postgresql-error e "query failed")))
                   (run-query! c bufbox sql))))
          (send from (vector 'postgresql-reply ref r))
          (if (transport-dead? r)
              (tcp-close! c)                        ; exit -> DOWN -> rebuild
              (begin
                (when notify (send notify (vector 'postgresql-idle self)))
                (serve-loop c bufbox notify)))))
      (`#(postgresql-quit)
        (send-msg! c MSG-TERMINATE empty-bv)         ; Terminate
        (tcp-close! c))
      (`#(tcp-data ,bv)                              ; stray data between queries
        (set-box! bufbox (bv-append (unbox bufbox) bv))
        (serve-loop c bufbox notify))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; spawn a connection worker; reports #(postgresql-up ,self ok-or-error) to
  ;; report-to, then serves queries (notifying `notify` when idle)
  (define (start-connection host port user password db notify report-to)
    (spawn
      (lambda ()
        (let ((outcome
               (guard (e (#t (as-postgresql-error e "connect failed")))
                 (tcp-connect! host port self)
                 (receive (after connect-timeout-ms
                             (postgresql-fail 'transport "connect timeout"))
                   (`#(tcp-connected ,c)
                     (tcp-read-start! c)
                     (let ((bufbox (box empty-bv)))
                       (authenticate! c bufbox user password db)
                       (cons c bufbox)))
                   (`#(tcp-connect-failed ,e)
                     (postgresql-fail 'transport (uv-strerror e)))))))
          (if (pair? outcome)
              (begin
                (send report-to (vector 'postgresql-up self 'ok))
                (serve-loop (car outcome) (cdr outcome) notify))
              (send report-to (vector 'postgresql-up self outcome)))))))

  ;; ---- connection pool ---------------------------------------------------

  ;; Fixed pool of n connections behind a dispatcher process. Queries go to
  ;; an idle connection or wait in a FIFO; replies flow directly from the
  ;; connection to the caller. Dead connections are replaced automatically
  ;; (1s backoff on failed connects); a caller whose connection dies
  ;; mid-query gets #(postgresql-error transport "connection lost").
  (define (pool-loop n host port user password db)
    (define me self)
    (define idle '())
    (define busy (make-eq-hashtable))   ; conn pid -> (caller-pid . ref)
    ;; transaction leases: a whole connection handed to one borrower for the
    ;; extent of a transaction, kept out of query rotation until checked back
    ;; in (or its borrower dies).
    (define leased (make-eq-hashtable))       ; conn pid   -> lessee pid
    (define lessee->conn (make-eq-hashtable)) ; lessee pid -> conn pid
    (define lessee->mon (make-eq-hashtable))  ; lessee pid -> monitor ref
    (define dying (make-eq-hashtable))        ; conn pid   -> #t (being torn down)
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
      (monitor (start-connection host port user password db me me)))
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
        (hashtable-set! leased c from)
        (hashtable-set! lessee->conn from c)
        (hashtable-set! lessee->mon from (monitor from))
        (send from (vector 'postgresql-checkout-reply ref c))))
    (define (make-available! c)
      (hashtable-delete! busy c)
      (cond
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
          (when (eq? (hashtable-ref leased c #f) from)
            (hashtable-delete! leased c)
            (hashtable-delete! lessee->conn from)
            (let ((m (hashtable-ref lessee->mon from #f)))
              (when m (demonitor m)))
            (hashtable-delete! lessee->mon from)
            (make-available! c))
          (loop))
        (`#(postgresql-checkin-broken ,from ,c)
          ;; the lessee could not clean the connection (e.g. ROLLBACK failed):
          ;; drop the lease and destroy+rebuild it rather than ever lending a
          ;; possibly-open transaction to the next caller.
          (when (eq? (hashtable-ref leased c #f) from)
            (hashtable-delete! leased c)
            (hashtable-delete! lessee->conn from)
            (let ((m (hashtable-ref lessee->mon from #f)))
              (when m (demonitor m)))
            (hashtable-delete! lessee->mon from)
            (hashtable-set! dying c #t)
            (send c (vector 'postgresql-quit)))    ; -> DOWN -> rebuild (case 2)
          (loop))
        (`#(postgresql-checkout-cancel ,ref ,from)
          ;; a checkout timed out: drop its still-queued request so a freed
          ;; connection is never leased to a borrower that has moved on. If the
          ;; pool already leased one to it (raced the timeout), reclaim it.
          (set! co-front (filter (lambda (x) (not (eq? (car x) ref))) co-front))
          (set! co-back  (filter (lambda (x) (not (eq? (car x) ref))) co-back))
          (let ((c (hashtable-ref lessee->conn from #f)))
            (when (and c (eq? (hashtable-ref leased c #f) from))
              (hashtable-delete! leased c)
              (hashtable-delete! lessee->conn from)
              (let ((m (hashtable-ref lessee->mon from #f)))
                (when m (demonitor m)))
              (hashtable-delete! lessee->mon from)
              (make-available! c)))
          (loop))
        (`#(postgresql-up ,pid ,status)
          (if (eq? status 'ok)
              (make-available! pid)
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
            ;; Its connection may hold a half-open transaction: destroy it and
            ;; let the connection's own DOWN below rebuild a clean replacement.
            ((hashtable-ref lessee->conn pid #f)
             => (lambda (c)
                  (hashtable-delete! lessee->conn pid)
                  (hashtable-delete! lessee->mon pid)
                  (hashtable-delete! leased c)
                  (hashtable-set! dying c #t)
                  (send c (vector 'postgresql-quit))))
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
                               (vector 'postgresql-error 'transport "connection lost")))))
             (let ((lessee (hashtable-ref leased pid #f)))
               (when lessee
                 (hashtable-delete! leased pid)
                 (hashtable-delete! lessee->conn lessee)
                 (let ((m (hashtable-ref lessee->mon lessee #f)))
                   (when m (demonitor m)))
                 (hashtable-delete! lessee->mon lessee)))
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
          'done))))

  ;; ---- public API --------------------------------------------------------

  ;; Connect + authenticate a single connection; returns the connection
  ;; process or raises #(postgresql-error state msg). The database defaults to the
  ;; user name (as PostgreSQL itself defaults).
  (define (postgresql-connect host port user password . rest)
    (let ((db (if (and (pair? rest) (car rest)) (car rest) user)))
      (start-connection host port user password db #f self)
      (receive (after (+ connect-timeout-ms 2000)
                  (raise (vector 'postgresql-error 'transport "connect timeout")))
        (`#(postgresql-up ,pid ,status)
          (if (eq? status 'ok) pid (raise status))))))

  ;; Pool of n connections; returns the dispatcher, which postgresql-query and
  ;; postgresql-close! accept exactly like a single connection. Usable immediately:
  ;; queries queue until connections come up.
  (define (postgresql-pool n host port user password . rest)
    (let ((db (if (and (pair? rest) (car rest)) (car rest) user)))
      (spawn (lambda () (pool-loop n host port user password db)))))

  ;; Run one SQL statement; blocks only the calling green process. The
  ;; per-call ref (a fresh gensym) is echoed in the reply, so a late reply
  ;; after a timeout will not be matched by the caller's next query.
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
  ;; raise #(postgresql-error transport "checkout timeout")). Internal: callers use
  ;; call-with-postgresql-connection / postgresql-transaction, which guarantee checkin.
  (define (pool-checkout pool)
    (let ((ref (gensym)))
      (send pool (vector 'postgresql-checkout ref self))
      (receive (after checkout-timeout-ms
                  (send pool (vector 'postgresql-checkout-cancel ref self))
                  (raise (vector 'postgresql-error 'transport "checkout timeout")))
        (`#(postgresql-checkout-reply ,@ref ,conn) conn))))

  ;; Borrow one whole connection from a POOL for the extent of proc, then
  ;; return it -- even if proc raises or exits non-locally. proc receives the
  ;; connection process; run postgresql-query on THAT connection and no other caller's
  ;; query can interleave. Requires a postgresql-pool. Don't send queries to the pool
  ;; itself while holding a connection (it can deadlock an exhausted pool);
  ;; use the borrowed connection.
  (define (call-with-postgresql-connection pool proc)
    (let ((conn (pool-checkout pool)))
      (dynamic-wind
        (lambda () (void))
        (lambda () (proc conn))
        (lambda () (send pool (vector 'postgresql-checkin self conn))))))

  ;; Run proc inside a transaction on a borrowed pool connection: BEGIN
  ;; first, then COMMIT if proc returns normally, or ROLLBACK if it escapes.
  ;; Returns proc's value. proc receives the connection; issue every statement
  ;; of the transaction on it. Requires a postgresql-pool. If the borrower is killed
  ;; before it can commit/rollback, the pool discards and rebuilds the
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
              ;; roll back; if ROLLBACK itself fails the transaction may still
              ;; be open, so flag the connection for discard instead of
              ;; returning it dirty.
              (set! broken (guard (e (#t #t)) (postgresql-query conn "ROLLBACK") #f)))
            (send pool (vector (if broken 'postgresql-checkin-broken 'postgresql-checkin)
                               self conn)))))))

  (define (postgresql-close! mc)
    (send mc (vector 'postgresql-quit)))
)
