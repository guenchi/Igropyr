#!chezscheme
;;; (igropyr mysql) -- non-blocking MySQL client (protocol 4.1, text mode).
;;;
;;; One green process per connection; callers park in receive while the
;;; OS thread keeps serving other requests. The MySQL protocol is
;;; strictly request-response, so concurrent queries from many workers
;;; are queued in the connection's mailbox and run one at a time.
;;;
;;;   (define db (mysql-connect "127.0.0.1" 3306 "user" "password" "dbname"))
;;;   (mysql-query db "SELECT id, name FROM users")
;;;     ;; -> #(rows ("id" "name") (("1" "Alice") ("2" "Bob")))
;;;   (mysql-query db "INSERT INTO users (name) VALUES ('Eve')")
;;;     ;; -> #(ok 1 3)                     ; affected rows, last insert id
;;;   (mysql-close! db)
;;;
;;; Values arrive as strings (MySQL text protocol); NULL is #f.
;;; #(mysql-error ,code ,message) is the shape of an OPERATIONAL error --
;;; one the database, the connection or a timeout produced on a valid
;;; call. Nothing else promises to wear that tag: argument checks raise
;;; ordinary Chez conditions, mysql-pool-stats passes the pool library's
;;; shape through (see below), and whatever the caller's own procedure
;;; raises inside call-with-mysql-connection or mysql-transaction travels
;;; out unchanged. A guard that must not let anything past needs a clause
;;; for conditions as well as for the vector.
;;;
;;; Authentication: caching_sha2_password (MySQL 9's default plugin --
;;; what a given server offers is the server's business, and any plugin
;;; other than the two named here is refused as unsupported),
;;; both paths: the SHA-256 scramble fast path, and the full path where
;;; the server's RSA public key encrypts the password (OAEP) over a
;;; plain connection. mysql_native_password is also supported for older
;;; servers via auth-switch.

(library (igropyr mysql)
  (export mysql-connect mysql-pool mysql-query mysql-close! mysql-pool-stats
          mysql-transaction mysql-observe! call-with-mysql-connection)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr connpool)
          (igropyr buffer)
          (only (igropyr crypto) sha1 sha256 base64-decode))

  (define connect-timeout-ms 10000)
  ;; A ceiling on the WHOLE auth handshake.
  ;;
  ;; connect-timeout-ms bounds each socket read and re-arms on every packet,
  ;; so it never ends the handshake: a server sending a legal AuthMoreData
  ;; every nine seconds -- which a hostile or confused peer can keep up
  ;; indefinitely -- held a connection worker forever. The single-connection
  ;; caller gave up at twelve seconds and the worker kept running; a POOL
  ;; worker never reported pool-up at all, so it held its slot for the life of
  ;; the process while the pool waited for a connection never coming.
  (define connect-deadline-ms 30000)

  ;; How long the next handshake read may wait: never past the handshake's
  ;; deadline, and never longer than one packet is allowed to take.
  (define (auth-wait-ms deadline)
    (let ((left (- deadline (now-ms))))
      (when (<= left 0)
        (mysql-fail -1 "connect deadline exceeded"))
      (max 1 (min connect-timeout-ms left))))
  (define query-timeout-ms 60000)

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

  (define (bv-xor a b)   ; b cycled over a's length
    (let* ((n (bytevector-length a))
           (bn (bytevector-length b))
           (out (make-bytevector n)))
      (do ((i 0 (+ i 1))) ((= i n) out)
        (bytevector-u8-set! out i
          (fxxor (bytevector-u8-ref a i)
                 (bytevector-u8-ref b (mod i bn)))))))

  (define (find-u8 bv start byte)
    (let ((n (bytevector-length bv)))
      (let loop ((i start))
        (cond ((>= i n) #f)
              ((fx= (bytevector-u8-ref bv i) byte) i)
              (else (loop (+ i 1)))))))

  ;; SHA-256 and base64-decode (for the caching_sha2 auth scramble and
  ;; the RSA public-key PEM) come from (igropyr crypto).

  ;; ---- minimal DER: extract RSA modulus and exponent from a PEM key --------------

  ;; (der-tlv bv pos) -> (values tag content-start content-end)
  (define (der-tlv bv pos)
    (let ((tag (bytevector-u8-ref bv pos))
          (b (bytevector-u8-ref bv (+ pos 1))))
      (if (< b #x80)
          (values tag (+ pos 2) (+ pos 2 b))
          (let ((nb (fxand b #x7F)))
            (let loop ((i 0) (len 0))
              (if (= i nb)
                  (values tag (+ pos 2 nb) (+ pos 2 nb len))
                  (loop (+ i 1)
                        (+ (* len 256) (bytevector-u8-ref bv (+ pos 2 i))))))))))

  (define (bytes->integer bv start end)
    (let loop ((i start) (v 0))
      (if (= i end) v (loop (+ i 1) (+ (* v 256) (bytevector-u8-ref bv i))))))

  ;; PEM SubjectPublicKeyInfo -> (values modulus exponent)
  (define (parse-rsa-public-key pem)
    (let* ((body (let loop ((lines (string->lines pem)) (acc ""))
                   (cond
                     ((null? lines) acc)
                     ((let ((l (car lines)))
                        (or (string=? l "") (char=? (string-ref l 0) #\-)))
                      (loop (cdr lines) acc))
                     (else (loop (cdr lines) (string-append acc (car lines)))))))
           (der (base64-decode body)))
      (let*-values (((t0 c0 e0) (der-tlv der 0))          ; outer SEQUENCE
                    ((t1 c1 e1) (der-tlv der c0))         ; algorithm SEQUENCE
                    ((t2 c2 e2) (der-tlv der e1)))        ; BIT STRING
        (let*-values (((t3 c3 e3) (der-tlv der (+ c2 1))) ; RSA SEQUENCE (skip pad byte)
                      ((t4 c4 e4) (der-tlv der c3)))      ; INTEGER modulus
          (let-values (((t5 c5 e5) (der-tlv der e4)))     ; INTEGER exponent
            (values (bytes->integer der c4 e4)
                    (bytes->integer der c5 e5)))))))

  (define (string->lines s)
    (let loop ((i 0) (start 0) (acc '()))
      (cond
        ((= i (string-length s)) (reverse (cons (substring s start i) acc)))
        ((char=? (string-ref s i) #\newline)
         (loop (+ i 1) (+ i 1) (cons (substring s start i) acc)))
        (else (loop (+ i 1) start acc)))))

  ;; ---- RSA-OAEP (SHA-1 / MGF1-SHA1, as MySQL uses) ---------------------------------

  (define (mod-expt b e m)
    (let loop ((b (mod b m)) (e e) (acc 1))
      (if (= e 0)
          acc
          (loop (mod (* b b) m)
                (bitwise-arithmetic-shift-right e 1)
                (if (odd? e) (mod (* acc b) m) acc)))))

  ;; big integers welcome: RSA ciphertexts exceed fixnum range
  (define (integer->bytes v len)
    (let ((out (make-bytevector len 0)))
      (let loop ((i (- len 1)) (v v))
        (if (< i 0)
            out
            (begin
              (bytevector-u8-set! out i (bitwise-and v #xFF))
              (loop (- i 1) (bitwise-arithmetic-shift-right v 8)))))))

  (define (mgf1-sha1 seed len)
    (let loop ((counter 0) (parts '()) (got 0))
      (if (>= got len)
          (bv-sub (apply bv-append (reverse parts)) 0 len)
          (let ((h (sha1 (bv-append seed (integer->bytes counter 4)))))
            (loop (+ counter 1) (cons h parts) (+ got 20))))))

  ;; OAEP seed must be unpredictable: read the OS CSPRNG, never a
  ;; time-seeded PRNG.
  (define (random-bytes n)
    (call-with-port (open-file-input-port "/dev/urandom")
      (lambda (p)
        (let ((bv (get-bytevector-n p n)))
          (if (and (bytevector? bv) (= (bytevector-length bv) n))
              bv
              (mysql-fail -1 "could not read /dev/urandom"))))))

  ;; PKCS#1 v2.1 OAEP encrypt; k = modulus size in bytes
  (define (rsa-oaep-encrypt msg n e)
    (let* ((k (div (+ (bitwise-length n) 7) 8))
           (hlen 20)
           (mlen (bytevector-length msg))
           (lhash (sha1 empty-bv))
           (pslen (- k mlen (* 2 hlen) 2))
           (db (bv-append lhash (make-bytevector pslen 0)
                          (bytevector 1) msg))
           (seed (random-bytes hlen))
           (masked-db (bv-xor db (mgf1-sha1 seed (- k hlen 1))))
           (masked-seed (bv-xor seed (mgf1-sha1 masked-db hlen)))
           (em (bv-append (bytevector 0) masked-seed masked-db)))
      (integer->bytes (mod-expt (bytes->integer em 0 k) e n) k)))

  ;; ---- MySQL packet framing -----------------------------------------------------

  ;; The length field is 24 bits. A payload of 0xFFFFFF or more needs the
  ;; protocol's continuation split (0xFFFFFF-byte packets, a short one last),
  ;; which this client does not implement -- and the receive side does not
  ;; reassemble them either, so adding it here alone would not help.
  ;;
  ;; What it must NOT do is what it did: write the low 24 bits and send the
  ;; whole payload anyway. The server then reads the wrong length, and every
  ;; byte after it is misinterpreted as the next packet -- the connection is
  ;; desynchronised rather than failed, which is far worse than a refusal.
  (define max-packet-payload #xFFFFFF)

  (define (frame-packet payload seq)
    (let ((n (bytevector-length payload)))
      (when (>= n max-packet-payload)
        (mysql-fail -1 "packet payload exceeds the 16 MiB protocol limit"))
      (bv-append
        (bytevector (fxand n #xFF)
                    (fxand (fxsrl n 8) #xFF)
                    (fxand (fxsrl n 16) #xFF)
                    (fxand seq #xFF))
        payload)))

  (define (send-packet! c payload seq)
    (tcp-write! c (frame-packet payload seq) #f))

  (define (mysql-fail code msg)
    (raise (vector 'mysql-error code msg)))

  ;; wrap any exception as #(mysql-error ...) with a readable message
  (define (as-mysql-error e context)
    (if (and (vector? e) (eq? (vector-ref e 0) 'mysql-error))
        e
        (vector 'mysql-error -1
                (string-append context ": "
                  (if (condition? e)
                      (call-with-string-output-port
                        (lambda (p) (display-condition e p)))
                      (call-with-string-output-port
                        (lambda (p) (write e p))))))))

  ;; blocking: returns (values payload seq); runs in the connection
  ;; process. timeout bounds each socket read: connect-timeout-ms during
  ;; the auth handshake, query-timeout-ms while a query is in flight --
  ;; a server that stalls mid-handshake holds a connect worker for the
  ;; connect budget, not the query budget.
  ;; The buffer is an (igropyr buffer) inbuf, as PostgreSQL's already was.
  ;; It used to be a bytevector in a box, and every arriving TCP fragment
  ;; copied the WHOLE accumulated buffer to append to it -- quadratic in the
  ;; number of fragments, which for a legitimate near-16 MiB packet split
  ;; into small segments is thousands of copies of a growing multi-megabyte
  ;; bytevector, all of it garbage, on the one scheduler thread. An inbuf
  ;; appends in amortized O(1) and consumes a packet in O(1).
  (define (next-packet! c buf timeout)
    (let loop ()
      (if (>= (inbuf-length buf) 4)
          (let* ((bv (inbuf-bv buf))
                 (base (inbuf-start buf))
                 (len (+ (bytevector-u8-ref bv base)
                         (fxsll (bytevector-u8-ref bv (fx+ base 1)) 8)
                         (fxsll (bytevector-u8-ref bv (fx+ base 2)) 16)))
                 (seq (bytevector-u8-ref bv (fx+ base 3)))
                 (total (+ 4 len)))
            (if (>= (inbuf-length buf) total)
                (let ((payload (inbuf-sub buf 4 total)))
                  (inbuf-consume! buf total)
                  (values payload seq))
                (wait-data c buf loop timeout)))
          (wait-data c buf loop timeout))))

  ;; timeout may be a NUMBER or a thunk. A thunk is what the handshake
  ;; passes: computing the allowance once and re-arming it for every
  ;; fragment leaves the deadline unchecked for the whole of one message,
  ;; so a peer that dribbles a single message forever never trips it -- the
  ;; same re-arming shape the deadline was added to replace, one level down.
  (define (wait-data c buf k timeout)
    (receive (after (if (procedure? timeout) (timeout) timeout) (mysql-fail -1 "server timeout"))
      (`#(tcp-data ,bv)
        (inbuf-append! buf bv)
        (k))
      (`#(tcp-eof) (mysql-fail -1 "connection closed by server"))
      (`#(tcp-error ,e) (mysql-fail -1 "connection error"))
      ;; The owner died while we were mid-query. serve-loop watches for that
      ;; between statements, but a query is not between statements: once
      ;; inside the wire loop only TCP messages were matched, so against a
      ;; server that keeps dripping data the old query, its fd and its TLS
      ;; session outlived the pool indefinitely -- and rebuilding the pool
      ;; stacked a fresh set on top. Failing here unwinds through the guards,
      ;; which close the socket.
      (`#(DOWN ,pid ,reason) (mysql-fail -1 "owner gone"))
      ;; A TEARDOWN has to reach us HERE as well. The pool reclaims a
      ;; connection whose borrower died by marking it dying and sending
      ;; pool-quit -- @kill discards dynamic-wind winders, so the pool's
      ;; monitor is the only path back -- and a receive matching only the
      ;; socket left that message in the mailbox until the statement
      ;; finished. Against a server that has stopped answering, that is the
      ;; whole query timeout, and for all of it the connection is marked
      ;; dying: neither lent out nor rebuilt. Failing here takes the same
      ;; route a transport error already takes.
      (`#(pool-quit) (mysql-fail -1 "connection closed while a query was in flight"))))

  ;; ---- length-encoded values -------------------------------------------------------

  ;; -> (values n next-pos); #f for the NULL marker 0xFB
  (define (lenenc-int bv pos)
    (let ((b (bytevector-u8-ref bv pos)))
      (cond
        ((< b #xFB) (values b (+ pos 1)))
        ((= b #xFB) (values #f (+ pos 1)))
        ((= b #xFC) (values (+ (bytevector-u8-ref bv (+ pos 1))
                               (fxsll (bytevector-u8-ref bv (+ pos 2)) 8))
                            (+ pos 3)))
        ((= b #xFD) (values (+ (bytevector-u8-ref bv (+ pos 1))
                               (fxsll (bytevector-u8-ref bv (+ pos 2)) 8)
                               (fxsll (bytevector-u8-ref bv (+ pos 3)) 16))
                            (+ pos 4)))
        (else (values (bytes->integer-le bv (+ pos 1) (+ pos 9)) (+ pos 9))))))

  (define (bytes->integer-le bv start end)
    (let loop ((i (- end 1)) (v 0))
      (if (< i start) v (loop (- i 1) (+ (* v 256) (bytevector-u8-ref bv i))))))

  ;; -> (values string-or-#f next-pos)
  (define (lenenc-str bv pos)
    (let-values (((n next) (lenenc-int bv pos)))
      (if (not n)
          (values #f next)
          (values (utf8->string (bv-sub bv next (+ next n))) (+ next n)))))

  ;; ---- packets -------------------------------------------------------------------

  (define (err-packet->fail p)
    (let ((code (+ (bytevector-u8-ref p 1) (fxsll (bytevector-u8-ref p 2) 8)))
          ;; skip the '#' + 5-char sql state marker when present
          (msg-start (if (and (> (bytevector-length p) 9)
                              (fx= (bytevector-u8-ref p 3) 35))
                         9 3)))
      (mysql-fail code (utf8->string (bv-sub p msg-start (bytevector-length p))))))

  (define (parse-ok p)
    (let*-values (((affected pos1) (lenenc-int p 1))
                  ((insert-id pos2) (lenenc-int p pos1)))
      (vector 'ok (or affected 0) (or insert-id 0))))

  (define (eof-packet? p)
    (and (fx= (bytevector-u8-ref p 0) #xFE)
         (< (bytevector-length p) 9)))

  ;; ---- authentication ---------------------------------------------------------------

  ;; caching_sha2_password scramble:
  ;; XOR(SHA256(pwd), SHA256(SHA256(SHA256(pwd)) ++ nonce))
  (define (scramble-sha2 password nonce)
    (if (= 0 (string-length password))
        empty-bv
        (let* ((d1 (sha256 (string->utf8 password)))
               (d2 (sha256 d1)))
          (bv-xor d1 (sha256 (bv-append d2 nonce))))))

  ;; mysql_native_password scramble (for auth-switch to old servers):
  ;; XOR(SHA1(pwd), SHA1(nonce ++ SHA1(SHA1(pwd))))
  (define (scramble-sha1 password nonce)
    (if (= 0 (string-length password))
        empty-bv
        (let* ((d1 (sha1 (string->utf8 password)))
               (d2 (sha1 d1)))
          (bv-xor d1 (sha1 (bv-append nonce d2))))))

  ;; parse HandshakeV10 -> (values nonce plugin-name)
  (define (parse-handshake p)
    (unless (fx= (bytevector-u8-ref p 0) 10)
      (if (fx= (bytevector-u8-ref p 0) #xFF)
          (err-packet->fail p)
          (mysql-fail -1 "unsupported protocol version")))
    (let* ((ver-end (find-u8 p 1 0))
           (pos (+ ver-end 1 4))                 ; skip thread id
           (auth1 (bv-sub p pos (+ pos 8)))
           (pos (+ pos 8 1 2 1 2 2))             ; filler caps1 charset status caps2
           (auth-len (bytevector-u8-ref p pos))
           (pos (+ pos 1 10))                    ; reserved
           (n2 (max 0 (- (max 13 (- auth-len 8)) 1)))
           (auth2 (bv-sub p pos (+ pos n2)))
           (pos (+ pos (max 13 (- auth-len 8))))
           (plug-end (or (find-u8 p pos 0) (bytevector-length p)))
           (plugin (utf8->string (bv-sub p pos plug-end))))
      (values (bv-append auth1 auth2) plugin)))

  ;; capability flags we announce
  (define (client-caps db)
    (+ #x1        ; LONG_PASSWORD
       #x200      ; PROTOCOL_41
       #x8000     ; SECURE_CONNECTION
       #x80000    ; PLUGIN_AUTH
       (if db #x8 0)))  ; CONNECT_WITH_DB

  (define (int32->le v)
    (bytevector (fxand v #xFF) (fxand (fxsrl v 8) #xFF)
                (fxand (fxsrl v 16) #xFF) (fxand (fxsrl v 24) #xFF)))

  (define (handshake-response user token db plugin)
    (bv-append
      (int32->le (client-caps db))
      (int32->le #x1000000)                       ; max packet 16MB
      (bytevector 255)                            ; charset utf8mb4
      (make-bytevector 23 0)
      (string->utf8 user) (bytevector 0)
      (bytevector (bytevector-length token)) token
      (if db (bv-append (string->utf8 db) (bytevector 0)) empty-bv)
      (string->utf8 plugin) (bytevector 0)))

  ;; Full caching_sha2 path: the password is sent RSA-encrypted (only the
  ;; scramble hash goes over the wire on the fast path). Encrypting with a
  ;; key fetched over an unauthenticated plaintext connection lets a MITM
  ;; substitute its own key and read the password, so this is refused by
  ;; default. It is allowed only when the caller pins the server's public
  ;; key (opts 'server-public-key, a PEM string) -- then we never trust a
  ;; key from the wire -- or explicitly opts in with 'allow-insecure-auth
  ;; (appropriate over TLS or a trusted local socket).
  (define (full-auth! c buf password nonce seq opts deadline)
    (define pinned (assq-ref opts 'server-public-key))
    (define (encrypt-with n e)
      (let ((plain (bv-xor (bv-append (string->utf8 password) (bytevector 0))
                           nonce)))
        (send-packet! c (rsa-oaep-encrypt plain n e) (+ seq 1))))
    (cond
      (pinned
       (let-values (((n e) (parse-rsa-public-key pinned)))
         (encrypt-with n e)))
      ((assq-ref opts 'allow-insecure-auth)
       (send-packet! c (bytevector 2) seq)          ; request public key
       (let-values (((p sq) (next-packet! c buf (lambda () (auth-wait-ms deadline)))))
         (unless (fx= (bytevector-u8-ref p 0) 1)
           (mysql-fail -1 "expected server public key"))
         (let-values (((n e) (parse-rsa-public-key
                               (utf8->string (bv-sub p 1 (bytevector-length p))))))
           (let ((plain (bv-xor (bv-append (string->utf8 password) (bytevector 0))
                                nonce)))
             (send-packet! c (rsa-oaep-encrypt plain n e) (+ sq 1))))))
      (else
       (mysql-fail -1
         (string-append
           "full authentication would send the password RSA-encrypted "
           "over an unencrypted connection; pass 'server-public-key to "
           "pin the key, or 'allow-insecure-auth to permit it")))))

  (define (assq-ref alist key)
    (let ((p (and (pair? alist) (assq key alist))))
      (and p (cdr p))))

  ;; drive the auth conversation to an OK packet (or raise)
  ;; 'connect-deadline-ms overrides the ceiling on the whole handshake.
  (define (connect-deadline opts)
    (let ((v (assq-ref opts 'connect-deadline-ms)))
      (cond
        ((not v) connect-deadline-ms)
        ((and (integer? v) (exact? v) (> v 0)) v)
        (else (assertion-violation 'mysql-connect
                "'connect-deadline-ms must be a positive exact integer" v)))))

  (define (auth-loop! c buf user password nonce opts deadline)
    (let ()
     (let loop ()
      (let-values (((p seq) (next-packet! c buf (lambda () (auth-wait-ms deadline)))))
        (let ((b0 (bytevector-u8-ref p 0)))
          (cond
            ((fx= b0 0) 'ok)
            ((fx= b0 #xFF) (err-packet->fail p))
            ((fx= b0 1)                            ; AuthMoreData
             (let ((b1 (bytevector-u8-ref p 1)))
               (cond
                 ((fx= b1 3) (loop))               ; fast path ok; OK follows
                 ((fx= b1 4)                       ; full auth required
                  (if (= 0 (string-length password))
                      (begin (send-packet! c (bytevector 0) (+ seq 1)) (loop))
                      (begin (full-auth! c buf password nonce (+ seq 1) opts deadline)
                             (loop))))
                 (else (mysql-fail -1 "unexpected auth data")))))
            ((fx= b0 #xFE)                         ; AuthSwitchRequest
             (let* ((plug-end (or (find-u8 p 1 0) (bytevector-length p)))
                    (plugin (utf8->string (bv-sub p 1 plug-end)))
                    (nonce2 (let ((s (+ plug-end 1))
                                  (e (bytevector-length p)))
                              ;; strip trailing NUL if present
                              (if (and (> e s)
                                       (fx= (bytevector-u8-ref p (- e 1)) 0))
                                  (bv-sub p s (- e 1))
                                  (bv-sub p s e)))))
               (cond
                 ((string=? plugin "mysql_native_password")
                  (send-packet! c (scramble-sha1 password nonce2) (+ seq 1))
                  (loop))
                 ((string=? plugin "caching_sha2_password")
                  (send-packet! c (scramble-sha2 password nonce2) (+ seq 1))
                  (loop))
                 (else (mysql-fail -1 (string-append "unsupported auth plugin: "
                                                     plugin))))))
            (else (mysql-fail -1 "unexpected packet during auth"))))))))

  ;; The deadline is stamped HERE, at the first byte of the handshake, not
  ;; once the greeting has been read. Reading the greeting with the
  ;; per-packet timeout left the very first exchange unbounded -- a server
  ;; sending one byte every nine seconds never trips it and holds a
  ;; connecting slot forever, which is precisely what the deadline exists to
  ;; stop. The RSA public-key read inside full-auth! escaped it the same way.
  (define (authenticate! c buf user password db opts)
    (let ((deadline (+ (now-ms) (connect-deadline opts))))
     (let-values (((p seq) (next-packet! c buf (lambda () (auth-wait-ms deadline)))))
      (let-values (((nonce plugin) (parse-handshake p)))
        (let ((token (cond
                       ((string=? plugin "caching_sha2_password")
                        (scramble-sha2 password nonce))
                       ((string=? plugin "mysql_native_password")
                        (scramble-sha1 password nonce))
                       (else (mysql-fail -1 (string-append
                                              "unsupported auth plugin: " plugin))))))
          (send-packet! c (handshake-response user token db plugin) (+ seq 1))
          ;; full-auth path needs the nonce again
          (auth-loop! c buf user password nonce opts deadline))))))

  ;; ---- queries ------------------------------------------------------------------------

  ;; column name is the 5th length-encoded string in ColumnDefinition41
  (define (column-name p)
    (let*-values (((catalog p1) (lenenc-str p 0))
                  ((schema p2) (lenenc-str p p1))
                  ((table p3) (lenenc-str p p2))
                  ((org-table p4) (lenenc-str p p3))
                  ((name p5) (lenenc-str p p4)))
      name))

  (define (parse-row p ncols)
    (let loop ((i 0) (pos 0) (acc '()))
      (if (= i ncols)
          (reverse acc)
          (let-values (((v next) (lenenc-str p pos)))
            (loop (+ i 1) next (cons v acc))))))

  (define max-result-rows 1000000)

  (define (run-query! c buf sql)
    (send-packet! c (bv-append (bytevector 3) (string->utf8 sql)) 0)
    (let-values (((p seq) (next-packet! c buf query-timeout-ms)))
      (let ((b0 (bytevector-u8-ref p 0)))
        (cond
          ((fx= b0 0) (parse-ok p))
          ((fx= b0 #xFF) (err-packet->fail p))
          (else
           (let-values (((ncols pos) (lenenc-int p 0)))
             ;; column definitions
             (let cols ((i 0) (names '()))
               (if (< i ncols)
                   (let-values (((cp cs) (next-packet! c buf query-timeout-ms)))
                     (cols (+ i 1) (cons (column-name cp) names)))
                   (let ((names (reverse names)))
                     ;; EOF after columns
                     (let-values (((ep es) (next-packet! c buf query-timeout-ms)))
                       (unless (eof-packet? ep)
                         (mysql-fail -1 "expected EOF after columns")))
                     ;; rows until EOF
                     ;; Bounded: the whole result is materialised in memory,
                     ;; and there is no per-result ceiling anywhere else. An
                     ;; unbounded SELECT is how a client runs the VM out of
                     ;; memory for a query someone wrote by accident. Failing
                     ;; here means the connection is left mid-result and gets
                     ;; torn down, which is the right trade against an OOM
                     ;; that takes every other connection with it.
                     (let rows ((acc '()) (n 0))
                       (let-values (((rp rs) (next-packet! c buf query-timeout-ms)))
                         (cond
                           ((eof-packet? rp)
                            (vector 'rows names (reverse acc)))
                           ((fx= (bytevector-u8-ref rp 0) #xFF)
                            (err-packet->fail rp))
                           ((>= n max-result-rows)
                            (mysql-fail -1 "result set exceeds max-result-rows"))
                           (else
                            (rows (cons (parse-row rp ncols) acc)
                                  (+ n 1)))))))))))))))

  ;; ---- connection process ----------------------------------------------------------------

  ;; A transport/protocol failure (as opposed to a server-side SQL error,
  ;; which carries a real positive MySQL error code) means the connection
  ;; is no longer trustworthy: its framing may be desynchronised.
  (define (transport-dead? r)
    (and (vector? r) (eq? (vector-ref r 0) 'mysql-error)
         (< (vector-ref r 1) 0)))

  ;; notify (a pid or #f): told #(pool-idle ,self) after each finished
  ;; query, so a pool can hand this connection its next task. Replies
  ;; carry the caller's ref so a late reply (after the caller timed out)
  ;; cannot be mis-read by that caller's next query. On a transport
  ;; error the connection replies to its caller, tells the pool it
  ;; already did (so the pool's DOWN handler does not send a second,
  ;; forever-unmatched reply), closes, and exits -- the pool's monitor
  ;; then rebuilds it, rather than the dead connection returning to the
  ;; idle set.
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
  ;; reached, so it closes.
  (define (serve-loop c buf notify)
    (receive
      (`#(DOWN ,pid ,reason)
        (if (and notify (eq? pid notify))
            (begin (send-packet! c (bytevector 1) 0)   ; COM_QUIT
                   (tcp-close! c))
            (serve-loop c buf notify)))
      (`#(pool-request ,sql ,ref ,from)
        (let ((r (guard (e (#t (as-mysql-error e "query failed")))
                   (run-query! c buf sql))))
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
                (tcp-close! c))                   ; exit -> DOWN -> rebuild
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
      ;; here forever; mysql-pool-stats turns it into a clear error.
      (`#(pool-stats ,ref ,from)
        (send from (vector 'pool-stats-reply ref #f))
        (serve-loop c buf notify))
      (`#(pool-quit)
        (send-packet! c (bytevector 1) 0)          ; COM_QUIT
        (tcp-close! c))
      (`#(tcp-data ,bv)                            ; stray data between queries
        (inbuf-append! buf bv)
        (serve-loop c buf notify))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; After reporting up, wait to be adopted (the pool or the connecting
  ;; caller answers with pool-adopt). If nobody adopts -- the caller
  ;; timed out and moved on, or the pool was closed while we were still
  ;; authenticating -- close the socket and exit instead of holding an
  ;; authenticated connection forever.
  (define (await-adoption c buf notify)
    (receive (after connect-timeout-ms (tcp-close! c))
      (`#(pool-adopt)
        (when notify (monitor notify))
        (serve-loop c buf notify))
      (`#(pool-quit) (send-packet! c (bytevector 1) 0) (tcp-close! c))
      (`#(tcp-data ,bv)
        (inbuf-append! buf bv)
        (await-adoption c buf notify))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; spawn a connection worker; reports #(pool-up ,ref ,self status) to
  ;; report-to -- ref lets the receiver ignore a stale report from an
  ;; earlier, timed-out attempt -- then waits for adoption and serves
  ;; queries (notifying `notify` when idle). Every failure path closes
  ;; the socket: the uv handle is freed only by tcp-close!, so skipping
  ;; it (e.g. on a failed auth, retried every second by a pool) would
  ;; leak one fd per attempt until the process runs out.
  (define (start-connection host port user password db opts notify report-to ref)
    (spawn
      (lambda ()
        (define (report! status)
          (send report-to (vector 'pool-up ref self status)))
        (let ((started (guard (e (#t (as-mysql-error e "connect failed")))
                         (tcp-connect! host port self)
                         'ok)))
          (if (not (eq? started 'ok))
              (report! started)
              (receive (after connect-timeout-ms
                          (report! (vector 'mysql-error -1 "connect timeout"))
                          ;; libuv resolves every connect exactly once;
                          ;; wait for the late callback and free the handle
                          (receive
                            (`#(tcp-connected ,c) (tcp-close! c))
                            (`#(tcp-connect-failed ,e) 'ok)))
                (`#(tcp-connect-failed ,e)
                  (report! (vector 'mysql-error -1 (uv-strerror e))))
                (`#(tcp-connected ,c)
                  (tcp-read-start! c)
                  (let* ((buf (make-inbuf))
                         (r (guard (e (#t (as-mysql-error e "connect failed")))
                              (authenticate! c buf user password db opts)
                              'ok)))
                    (if (eq? r 'ok)
                        (begin (report! 'ok) (await-adoption c buf notify))
                        (begin (tcp-close! c) (report! r)))))))))))

  ;; ---- pool + public API ---------------------------------------------------
  ;; The pool, lease and transaction machinery is (igropyr connpool), shared
  ;; with (igropyr postgresql); this driver contributes the wire protocol
  ;; above and its error shapes below.

  (define cfg
    (make-connpool-cfg
      (lambda (r) (and (vector? r) (eq? (vector-ref r 0) 'mysql-error)))
      (vector 'mysql-error -1 "connection lost")
      (vector 'mysql-error -1 "pool closed")
      (vector 'mysql-error -1 "query timeout")
      (vector 'mysql-error -1 "checkout timeout")
      "START TRANSACTION"))

  ;; A 'tls option is the postgresql client's idiom; this client does not
  ;; speak TLS. Ignoring it silently would hand the caller a PLAINTEXT
  ;; connection while they believe the traffic is encrypted -- the one
  ;; downgrade that must never be silent -- so it is rejected loudly.
  (define (reject-tls-opt! opts)
    (when (and (pair? opts) (assq 'tls opts))
      (raise (vector 'mysql-error -1
               "the mysql client does not support the 'tls option"))))

  ;; Connect + authenticate a single connection; returns the connection
  ;; process or raises #(mysql-error code msg). Optional args after the
  ;; password: db name, then an options alist, e.g.
  ;;   (mysql-connect host port user pw "mydb"
  ;;     '((server-public-key . "-----BEGIN PUBLIC KEY-----...")))
  ;; Options: 'server-public-key (pin the RSA key for full auth),
  ;;          'allow-insecure-auth (permit fetching it over plaintext).
  ;; TLS is NOT supported; a 'tls option raises rather than silently
  ;; producing a plaintext connection.
  (define (mysql-connect host port user password . rest)
    (let ((db (if (pair? rest) (car rest) #f))
          (opts (if (and (pair? rest) (pair? (cdr rest))) (cadr rest) '())))
      (reject-tls-opt! opts)
      ;; A previous attempt from THIS process that timed out left its
      ;; worker's late up-report behind; its ref can never match again, so
      ;; it is immortal and every selective receive below scans past it. A
      ;; process that reconnects in a loop and never runs a query had
      ;; nothing else that would ever clear them.
      (connpool-drain-stale!)
      (let ((ref (gensym)))
        (start-connection host port user password db opts #f self ref)
        (receive (after (+ connect-timeout-ms 2000)
                    ;; the worker gives up waiting for adoption and closes
                    ;; its socket by itself; the ref keeps its late up-report
                    ;; from ever being mistaken for another connect's.
                    (raise (vector 'mysql-error -1 "connect timeout")))
          (`#(pool-up ,@ref ,pid ,status)
            (if (eq? status 'ok)
                (begin (send pid (vector 'pool-adopt)) pid)
                (raise status)))))))

  ;; Pool of n connections; returns the dispatcher, which mysql-query
  ;; and mysql-close! accept exactly like a single connection. Usable
  ;; immediately: queries queue until connections come up. Same optional
  ;; db + options as mysql-connect.
  (define (mysql-pool n host port user password . rest)
    (let ((db (if (pair? rest) (car rest) #f))
          (opts (if (and (pair? rest) (pair? (cdr rest))) (cadr rest) '())))
      (reject-tls-opt! opts)
      ;; before the spawn: a bad size checked inside the pool process
      ;; raises where the caller cannot see it, and this returns a pid
      ;; that dies a moment later
      (connpool-check-size! 'mysql-pool n)
      (spawn
        (lambda ()
          (connpool-loop n
            (lambda (notify report-to ref)
              (start-connection host port user password db opts
                                notify report-to ref))
            cfg)))))

  ;; Run one SQL statement; blocks only the calling green process. A
  ;; timed-out statement's outcome is UNKNOWN -- it may still execute on
  ;; the server.
  ;; Install a request observer for every statement this driver issues --
  ;; the caller's own queries and the BEGIN/COMMIT/ROLLBACK that
  ;; sql-transaction issues around them, in dispatch order. See the
  ;; observation section in (igropyr connpool) for what the events do and
  ;; do not establish; the scope note there applies directly, since the
  ;; cfg below is this module's and is shared by every pool opened through
  ;; it.
  ;;
  ;; Only this driver has one because only this driver was asked for one.
  ;; The primitive is in connpool, so giving postgresql or qjspool the
  ;; same costs one line each -- their absence here is a decision, not an
  ;; omission.
  (define (mysql-observe! proc) (connpool-cfg-set-observer! cfg proc))

  (define (mysql-query mc sql) (connpool-call mc sql cfg))

  ;; Borrow one whole connection from a POOL for the extent of proc, then
  ;; return it -- even if proc raises or exits non-locally. proc receives
  ;; the connection process; run mysql-query on THAT connection and no
  ;; other caller's query can interleave, which is what makes a
  ;; multi-statement transaction correct. Requires a mysql-pool. Don't
  ;; send queries (or a second checkout) to the pool itself while holding
  ;; a connection.
  (define (call-with-mysql-connection pool proc)
    (connpool-lease pool proc cfg))

  ;; Run proc inside a transaction on a borrowed pool connection: START
  ;; TRANSACTION, then COMMIT if proc returns normally, or ROLLBACK if it
  ;; escapes. Returns proc's value. Requires a mysql-pool. If the borrower
  ;; is killed before it can commit/rollback, the pool discards and
  ;; rebuilds the connection, so a half-open transaction is never handed
  ;; to the next caller.
  (define (mysql-transaction pool proc)
    (sql-transaction pool proc cfg))

  (define (mysql-close! mc) (connpool-close! mc))

  ;; A snapshot of a pool: in-use, pending, checkout wait, query duration,
  ;; timeout counts and more. See (igropyr connpool) for the full key list.
  ;; This one does NOT re-tag: a pool that stops answering raises
  ;; #(connpool-error stats-timeout ,pool-id), not a mysql-error. Wrapping
  ;; it would claim the database said something when nothing did.
  (define (mysql-pool-stats pool) (connpool-stats pool))
)
