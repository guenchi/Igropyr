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
;;; Errors raise #(mysql-error ,code ,message) in the caller.
;;;
;;; Authentication: caching_sha2_password (the only plugin in MySQL 9),
;;; both paths: the SHA-256 scramble fast path, and the full path where
;;; the server's RSA public key encrypts the password (OAEP) over a
;;; plain connection. mysql_native_password is also supported for older
;;; servers via auth-switch.

(library (igropyr mysql)
  (export mysql-connect mysql-pool mysql-query mysql-close!
          mysql-transaction call-with-mysql-connection)
  (import (chezscheme) (igropyr actor) (igropyr libuv)
          (only (igropyr crypto) sha1 sha256 base64-decode))

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

  (define (frame-packet payload seq)
    (let ((n (bytevector-length payload)))
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

  ;; blocking: returns (values payload seq); runs in the connection process
  (define (next-packet! c bufbox)
    (let loop ()
      (let ((buf (unbox bufbox)))
        (if (>= (bytevector-length buf) 4)
            (let* ((len (+ (bytevector-u8-ref buf 0)
                           (fxsll (bytevector-u8-ref buf 1) 8)
                           (fxsll (bytevector-u8-ref buf 2) 16)))
                   (seq (bytevector-u8-ref buf 3))
                   (total (+ 4 len)))
              (if (>= (bytevector-length buf) total)
                  (begin
                    (set-box! bufbox (bv-sub buf total (bytevector-length buf)))
                    (values (bv-sub buf 4 total) seq))
                  (wait-data c bufbox loop)))
            (wait-data c bufbox loop)))))

  (define (wait-data c bufbox k)
    (receive (after query-timeout-ms (mysql-fail -1 "server timeout"))
      (`#(tcp-data ,bv)
        (set-box! bufbox (bv-append (unbox bufbox) bv))
        (k))
      (`#(tcp-eof) (mysql-fail -1 "connection closed by server"))
      (`#(tcp-error ,e) (mysql-fail -1 "connection error"))))

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
  (define (full-auth! c bufbox password nonce seq opts)
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
       (let-values (((p sq) (next-packet! c bufbox)))
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
  (define (auth-loop! c bufbox user password nonce opts)
    (let loop ()
      (let-values (((p seq) (next-packet! c bufbox)))
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
                      (begin (full-auth! c bufbox password nonce (+ seq 1) opts)
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
            (else (mysql-fail -1 "unexpected packet during auth")))))))

  (define (authenticate! c bufbox user password db opts)
    (let-values (((p seq) (next-packet! c bufbox)))
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
          (auth-loop! c bufbox user password nonce opts)))))

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

  (define (run-query! c bufbox sql)
    (send-packet! c (bv-append (bytevector 3) (string->utf8 sql)) 0)
    (let-values (((p seq) (next-packet! c bufbox)))
      (let ((b0 (bytevector-u8-ref p 0)))
        (cond
          ((fx= b0 0) (parse-ok p))
          ((fx= b0 #xFF) (err-packet->fail p))
          (else
           (let-values (((ncols pos) (lenenc-int p 0)))
             ;; column definitions
             (let cols ((i 0) (names '()))
               (if (< i ncols)
                   (let-values (((cp cs) (next-packet! c bufbox)))
                     (cols (+ i 1) (cons (column-name cp) names)))
                   (let ((names (reverse names)))
                     ;; EOF after columns
                     (let-values (((ep es) (next-packet! c bufbox)))
                       (unless (eof-packet? ep)
                         (mysql-fail -1 "expected EOF after columns")))
                     ;; rows until EOF
                     (let rows ((acc '()))
                       (let-values (((rp rs) (next-packet! c bufbox)))
                         (cond
                           ((eof-packet? rp)
                            (vector 'rows names (reverse acc)))
                           ((fx= (bytevector-u8-ref rp 0) #xFF)
                            (err-packet->fail rp))
                           (else
                            (rows (cons (parse-row rp ncols) acc)))))))))))))))

  ;; ---- connection process ----------------------------------------------------------------

  ;; A transport/protocol failure (as opposed to a server-side SQL error,
  ;; which carries a real positive MySQL error code) means the connection
  ;; is no longer trustworthy: its framing may be desynchronised.
  (define (transport-dead? r)
    (and (vector? r) (eq? (vector-ref r 0) 'mysql-error)
         (< (vector-ref r 1) 0)))

  ;; notify (a pid or #f): told #(mysql-idle ,self) after each finished
  ;; query, so a pool can hand this connection its next task. Replies
  ;; carry the caller's ref so a late reply (after the caller timed out)
  ;; cannot be mis-read by that caller's next query. On a transport
  ;; error the connection replies to its caller, tells the pool it
  ;; already did (so the pool's DOWN handler does not send a second,
  ;; forever-unmatched reply), closes, and exits -- the pool's monitor
  ;; then rebuilds it, rather than the dead connection returning to the
  ;; idle set.
  (define (serve-loop c bufbox notify)
    (receive
      (`#(mysql-query ,sql ,ref ,from)
        (let ((r (guard (e (#t (as-mysql-error e "query failed")))
                   (run-query! c bufbox sql))))
          (send from (vector 'mysql-reply ref r))
          (if (transport-dead? r)
              (begin
                (when notify (send notify (vector 'mysql-conn-dead self)))
                (tcp-close! c))                   ; exit -> DOWN -> rebuild
              (begin
                (when notify (send notify (vector 'mysql-idle self)))
                (serve-loop c bufbox notify)))))
      (`#(mysql-quit)
        (send-packet! c (bytevector 1) 0)          ; COM_QUIT
        (tcp-close! c))
      (`#(tcp-data ,bv)                            ; stray data between queries
        (set-box! bufbox (bv-append (unbox bufbox) bv))
        (serve-loop c bufbox notify))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; After reporting up, wait to be adopted (the pool or the connecting
  ;; caller answers with mysql-adopt). If nobody adopts -- the caller
  ;; timed out and moved on, or the pool was closed while we were still
  ;; authenticating -- close the socket and exit instead of holding an
  ;; authenticated connection forever.
  (define (await-adoption c bufbox notify)
    (receive (after connect-timeout-ms (tcp-close! c))
      (`#(mysql-adopt) (serve-loop c bufbox notify))
      (`#(mysql-quit) (send-packet! c (bytevector 1) 0) (tcp-close! c))
      (`#(tcp-data ,bv)
        (set-box! bufbox (bv-append (unbox bufbox) bv))
        (await-adoption c bufbox notify))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; spawn a connection worker; reports #(mysql-up ,ref ,self status) to
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
          (send report-to (vector 'mysql-up ref self status)))
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
                  (let* ((bufbox (box empty-bv))
                         (r (guard (e (#t (as-mysql-error e "connect failed")))
                              (authenticate! c bufbox user password db opts)
                              'ok)))
                    (if (eq? r 'ok)
                        (begin (report! 'ok) (await-adoption c bufbox notify))
                        (begin (tcp-close! c) (report! r)))))))))))

  ;; ---- connection pool -----------------------------------------------------------------------

  ;; Fixed pool of n connections behind a dispatcher process. Queries go
  ;; to an idle connection or wait in a FIFO; replies flow directly from
  ;; the connection to the caller. Dead connections are replaced
  ;; automatically (1s backoff on failed connects); a caller whose
  ;; connection dies mid-query gets #(mysql-error -1 "connection lost").
  (define (pool-loop n host port user password db opts)
    (define me self)
    (define idle '())
    (define busy (make-eq-hashtable))   ; conn pid -> (caller-pid . ref)
    ;; transaction leases: a whole connection handed to one borrower for
    ;; the extent of a transaction, kept out of query rotation until it is
    ;; checked back in (or its borrower dies). Each lease is its own record
    ;; -- keyed by connection, carrying the borrower, its monitor and the
    ;; checkout ref -- so one borrower holding several leases (nested
    ;; checkouts) never clobbers its own bookkeeping.
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
      (send c (vector 'mysql-query (vector-ref job 0)
                      (vector-ref job 1) (vector-ref job 2))))
    ;; hand connection c to a checkout request req = (ref . from), and
    ;; monitor the borrower: the supervisor killing a stuck worker discards
    ;; its dynamic-wind winders (see actor @kill), so the checkin never
    ;; runs -- this monitor is the only thing that reclaims the connection.
    (define (lease! c req)
      (let ((ref (car req)) (from (cdr req)))
        (hashtable-set! leased c (vector from (monitor from) ref))
        (send from (vector 'mysql-checkout-reply ref c))))
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
        (`#(mysql-query ,sql ,ref ,from)
          (let ((job (vector sql ref from)))
            (if (pair? idle)
                (let ((c (car idle)))
                  (set! idle (cdr idle))
                  (assign! c job))
                (set! pending-back (cons job pending-back))))
          (loop))
        (`#(mysql-idle ,c)
          ;; a leased connection pings idle after each of its transaction
          ;; queries -- ignore those, it stays with its lessee; likewise skip
          ;; a connection we are tearing down.
          (unless (or (hashtable-ref leased c #f) (hashtable-ref dying c #f))
            (make-available! c))
          (loop))
        (`#(mysql-conn-dead ,c)
          ;; the connection already sent the transport-error reply to its
          ;; caller and is about to exit: clear the busy entry so the DOWN
          ;; below does not send a duplicate reply, and mark it dying so
          ;; the DOWN still rebuilds it.
          (hashtable-delete! busy c)
          (hashtable-set! dying c #t)
          (loop))
        (`#(mysql-checkout ,ref ,from)
          (if (pair? idle)
              (let ((c (car idle)))
                (set! idle (cdr idle))
                (lease! c (cons ref from)))
              (set! co-back (cons (cons ref from) co-back)))
          (loop))
        (`#(mysql-checkin ,from ,c)
          ;; only when c really is leased to `from` -- guards a stale or double
          ;; checkin (e.g. after the connection already died and was rebuilt).
          (let ((e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) from))
              (drop-lease! c e)
              (make-available! c)))
          (loop))
        (`#(mysql-checkin-broken ,from ,c)
          ;; the lessee could not clean the connection (e.g. ROLLBACK failed):
          ;; drop the lease and destroy+rebuild it rather than ever lending a
          ;; possibly-open transaction to the next caller. Atomic here (single
          ;; loop), so the connection is never made available in between.
          (let ((e (hashtable-ref leased c #f)))
            (when (and e (eq? (vector-ref e 0) from))
              (drop-lease! c e)
              (hashtable-set! dying c #t)
              (send c (vector 'mysql-quit))))   ; -> DOWN -> rebuild (case 2)
          (loop))
        (`#(mysql-checkout-cancel ,ref ,from)
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
        (`#(mysql-up ,ref ,pid ,status)
          (if (eq? status 'ok)
              (begin
                (send pid (vector 'mysql-adopt))
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
            ;; clean replacement, rather than ever returning an open
            ;; transaction to the pool.
            ((pair? (leases-of pid))
             (for-each
               (lambda (hit)
                 (drop-lease! (car hit) (cdr hit))
                 (hashtable-set! dying (car hit) #t)
                 (send (car hit) (vector 'mysql-quit)))
               (leases-of pid)))
            ;; (2) a connection died (idle, mid single-query, leased, or one we
            ;; are already tearing down). Fail any waiting single-query caller,
            ;; drop a lease if it held one, and rebuild. Failed connect workers
            ;; already scheduled their own retry, so they fall through here.
            ((or (memq pid idle) (hashtable-contains? busy pid)
                 (hashtable-ref leased pid #f) (hashtable-ref dying pid #f))
             (set! idle (remq pid idle))
             (hashtable-delete! dying pid)
             (let ((entry (hashtable-ref busy pid #f)))
               (hashtable-delete! busy pid)
               (when entry
                 (send (car entry)
                       (vector 'mysql-reply (cdr entry)
                               (vector 'mysql-error -1 "connection lost")))))
             (let ((e (hashtable-ref leased pid #f)))
               (when e (drop-lease! pid e)))
             (connect!)))
          (loop))
        (`#(mysql-quit)
          (for-each (lambda (c) (send c (vector 'mysql-quit))) idle)
          (vector-for-each
            (lambda (c) (send c (vector 'mysql-quit)))
            (hashtable-keys busy))
          (vector-for-each
            (lambda (c) (send c (vector 'mysql-quit)))
            (hashtable-keys leased))
          ;; connections still authenticating self-terminate: nobody adopts
          ;; them once this process is gone. Queued callers get an error now
          ;; instead of parking until their timeouts.
          (let ((closed (vector 'mysql-error -1 "pool closed")))
            (for-each
              (lambda (job)
                (send (vector-ref job 2)
                      (vector 'mysql-reply (vector-ref job 1) closed)))
              (append pending-front (reverse pending-back)))
            (for-each
              (lambda (req)
                (send (cdr req)
                      (vector 'mysql-checkout-failed (car req) closed)))
              (append co-front (reverse co-back))))
          'done))))

  ;; ---- public API ----------------------------------------------------------------------------

  ;; Connect + authenticate a single connection; returns the connection
  ;; process or raises #(mysql-error code msg). Optional args after the
  ;; password: db name, then an options alist, e.g.
  ;;   (mysql-connect host port user pw "mydb"
  ;;     '((server-public-key . "-----BEGIN PUBLIC KEY-----...")))
  ;; Options: 'server-public-key (pin the RSA key for full auth),
  ;;          'allow-insecure-auth (permit fetching it over plaintext).
  (define (mysql-connect host port user password . rest)
    (let ((db (if (pair? rest) (car rest) #f))
          (opts (if (and (pair? rest) (pair? (cdr rest))) (cadr rest) '())))
      (let ((ref (gensym)))
        (start-connection host port user password db opts #f self ref)
        (receive (after (+ connect-timeout-ms 2000)
                    ;; the worker gives up waiting for adoption and closes
                    ;; its socket by itself; the ref keeps its late up-report
                    ;; from ever being mistaken for another connect's.
                    (raise (vector 'mysql-error -1 "connect timeout")))
          (`#(mysql-up ,@ref ,pid ,status)
            (if (eq? status 'ok)
                (begin (send pid (vector 'mysql-adopt)) pid)
                (raise status)))))))

  ;; Pool of n connections; returns the dispatcher, which mysql-query
  ;; and mysql-close! accept exactly like a single connection. Usable
  ;; immediately: queries queue until connections come up. Same optional
  ;; db + options as mysql-connect.
  (define (mysql-pool n host port user password . rest)
    (let ((db (if (pair? rest) (car rest) #f))
          (opts (if (and (pair? rest) (pair? (cdr rest))) (cadr rest) '())))
      (spawn (lambda () (pool-loop n host port user password db opts)))))

  ;; Run one SQL statement; blocks only the calling green process. The
  ;; per-call ref (a fresh gensym) is echoed in the reply, so if this
  ;; call times out, a late reply carrying the old ref will not be
  ;; matched by the caller's next query.
  (define (mysql-query mc sql)
    (let ((ref (gensym)))
      (send mc (vector 'mysql-query sql ref self))
      (receive (after query-timeout-ms
                  (raise (vector 'mysql-error -1 "query timeout")))
        (`#(mysql-reply ,@ref ,r)
          (if (and (vector? r) (eq? (vector-ref r 0) 'mysql-error))
              (raise r)
              r)))))

  ;; ---- transactions: borrow a whole pool connection ----------------------

  ;; Ask the pool for a dedicated connection and park until one is free
  ;; (or raise #(mysql-error -1 "checkout timeout")). Internal: callers use
  ;; call-with-mysql-connection / mysql-transaction, which guarantee checkin.
  (define (pool-checkout pool)
    (let ((ref (gensym)))
      (send pool (vector 'mysql-checkout ref self))
      (receive (after checkout-timeout-ms
                  ;; tell the pool to drop (or reclaim) this request -- otherwise
                  ;; a connection freed after the timeout is leased to us and
                  ;; never checked in, bleeding the pool under saturation.
                  (send pool (vector 'mysql-checkout-cancel ref self))
                  (raise (vector 'mysql-error -1 "checkout timeout")))
        (`#(mysql-checkout-reply ,@ref ,conn) conn)
        (`#(mysql-checkout-failed ,@ref ,err) (raise err)))))

  ;; Borrow one whole connection from a POOL for the extent of proc, then
  ;; return it -- even if proc raises or exits non-locally. proc receives
  ;; the connection process; run mysql-query on THAT connection and no other
  ;; caller's query can interleave, which is what makes a multi-statement
  ;; transaction (BEGIN..COMMIT, SELECT..FOR UPDATE) correct. Requires a
  ;; mysql-pool -- a lone mysql-connect connection has nothing to lease.
  ;; Don't send queries to the pool itself while holding a connection (it can
  ;; deadlock against an exhausted pool); use the borrowed connection.
  (define (call-with-mysql-connection pool proc)
    (let ((conn (pool-checkout pool)))
      (dynamic-wind
        (lambda () (void))
        (lambda () (proc conn))
        (lambda () (send pool (vector 'mysql-checkin self conn))))))

  ;; ROLLBACK on a borrowed connection without parking a full query timeout
  ;; when the connection is already dead: monitor it, so a dead process
  ;; answers with an immediate DOWN instead of 60 seconds of silence.
  ;; -> #t when the connection cannot be returned clean.
  (define (rollback! conn)
    (let ((m (monitor conn)) (ref (gensym)))
      (let ((broken
             (guard (e (#t #t))
               (send conn (vector 'mysql-query "ROLLBACK" ref self))
               (receive (after query-timeout-ms #t)
                 (`#(mysql-reply ,@ref ,r)
                   (and (vector? r) (eq? (vector-ref r 0) 'mysql-error)))
                 (`#(DOWN ,@conn ,reason) #t)))))
        (when m
          (demonitor m)
          ;; a DOWN already queued between the reply and the demonitor
          ;; would sit unmatched forever -- drain it
          (receive (after 0 'ok) (`#(DOWN ,@conn ,reason) 'ok)))
        broken)))

  ;; Run proc inside a transaction on a borrowed pool connection: START
  ;; TRANSACTION first, then COMMIT if proc returns normally, or ROLLBACK if
  ;; it escapes (exception or non-local exit). Returns proc's value. proc
  ;; receives the connection; issue every statement of the transaction on it.
  ;; Requires a mysql-pool. If the borrower is killed before it can
  ;; commit/rollback, the pool discards and rebuilds the connection, so a
  ;; half-open transaction is never handed to the next caller.
  (define (mysql-transaction pool proc)
    ;; self-manages the lease (rather than call-with-mysql-connection) so the
    ;; single return message can be checkin OR checkin-broken -- no second
    ;; checkin racing the discard. Kill-safety is unchanged: if the borrower is
    ;; killed the winders are discarded, no message is sent, and the pool's
    ;; monitor reclaims + rebuilds the connection.
    (let ((conn (pool-checkout pool)))
      (let ((committed #f) (broken #f))
        (dynamic-wind
          (lambda () (void))
          (lambda ()
            ;; inside the wind: if START TRANSACTION itself fails, the
            ;; after-clause still runs, so the lease is always returned. A
            ;; ROLLBACK with no started transaction is a harmless no-op; if the
            ;; connection is dead it fails there too and gets discarded.
            (mysql-query conn "START TRANSACTION")
            (let ((r (proc conn)))
              (mysql-query conn "COMMIT")
              (set! committed #t)
              r))
          (lambda ()
            (unless committed
              ;; roll back; if ROLLBACK fails (or the connection is dead)
              ;; the transaction may still be open, so flag the connection
              ;; for discard instead of returning it dirty
              (set! broken (rollback! conn)))
            (send pool (vector (if broken 'mysql-checkin-broken 'mysql-checkin)
                               self conn)))))))

  (define (mysql-close! mc)
    (send mc (vector 'mysql-quit)))
)
