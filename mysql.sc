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
  (export mysql-connect mysql-pool mysql-query mysql-close!)
  (import (chezscheme) (igropyr actor) (igropyr uv)
          (only (igropyr websocket) sha1))

  (define connect-timeout-ms 10000)
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

  ;; ---- SHA-256 --------------------------------------------------------------

  (define mask32 #xFFFFFFFF)

  (define (rotr32 x n)
    (fxior (fxsrl x n)
           (fxsll (fxand x (fx- (fxsll 1 n) 1)) (fx- 32 n))))

  (define (shr32 x n) (fxsrl x n))

  (define (add32 . xs) (fxand (apply fx+ xs) mask32))

  (define sha256-k
    '#(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1
       #x923f82a4 #xab1c5ed5 #xd807aa98 #x12835b01 #x243185be #x550c7dc3
       #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174 #xe49b69c1 #xefbe4786
       #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
       #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147
       #x06ca6351 #x14292967 #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
       #x650a7354 #x766a0abb #x81c2c92e #x92722c85 #xa2bfe8a1 #xa81a664b
       #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
       #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a
       #x5b9cca4f #x682e6ff3 #x748f82ee #x78a5636f #x84c87814 #x8cc70208
       #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))

  (define (sha256 msg)
    (let* ((len (bytevector-length msg))
           (padlen (let ((r (mod (+ len 1) 64)))
                     (if (<= r 56) (- 56 r) (- 120 r))))
           (total (+ len 1 padlen 8))
           (buf (make-bytevector total 0))
           (w (make-vector 64 0)))
      (bytevector-copy! msg 0 buf 0 len)
      (bytevector-u8-set! buf len #x80)
      (do ((i 0 (+ i 1))) ((= i 8))
        (bytevector-u8-set! buf (- total 1 i)
          (fxand (bitwise-arithmetic-shift-right (* len 8) (* 8 i)) #xFF)))
      (let blocks ((blk 0)
                   (h0 #x6a09e667) (h1 #xbb67ae85) (h2 #x3c6ef372)
                   (h3 #xa54ff53a) (h4 #x510e527f) (h5 #x9b05688c)
                   (h6 #x1f83d9ab) (h7 #x5be0cd19))
        (if (= blk (div total 64))
            (let ((out (make-bytevector 32)))
              (let put ((i 0) (hs (list h0 h1 h2 h3 h4 h5 h6 h7)))
                (unless (null? hs)
                  (let ((h (car hs)))
                    (bytevector-u8-set! out i (fxsrl h 24))
                    (bytevector-u8-set! out (+ i 1) (fxand (fxsrl h 16) #xFF))
                    (bytevector-u8-set! out (+ i 2) (fxand (fxsrl h 8) #xFF))
                    (bytevector-u8-set! out (+ i 3) (fxand h #xFF)))
                  (put (+ i 4) (cdr hs))))
              out)
            (begin
              (do ((t 0 (+ t 1))) ((= t 16))
                (let ((b (+ (* blk 64) (* t 4))))
                  (vector-set! w t
                    (fxior (fxsll (bytevector-u8-ref buf b) 24)
                           (fxsll (bytevector-u8-ref buf (+ b 1)) 16)
                           (fxsll (bytevector-u8-ref buf (+ b 2)) 8)
                           (bytevector-u8-ref buf (+ b 3))))))
              (do ((t 16 (+ t 1))) ((= t 64))
                (let ((s0 (let ((x (vector-ref w (- t 15))))
                            (fxxor (rotr32 x 7) (rotr32 x 18) (shr32 x 3))))
                      (s1 (let ((x (vector-ref w (- t 2))))
                            (fxxor (rotr32 x 17) (rotr32 x 19) (shr32 x 10)))))
                  (vector-set! w t
                    (add32 (vector-ref w (- t 16)) s0 (vector-ref w (- t 7)) s1))))
              (let rounds ((t 0) (a h0) (b h1) (c h2) (d h3)
                           (e h4) (f h5) (g h6) (h h7))
                (if (= t 64)
                    (blocks (+ blk 1)
                            (add32 h0 a) (add32 h1 b) (add32 h2 c) (add32 h3 d)
                            (add32 h4 e) (add32 h5 f) (add32 h6 g) (add32 h7 h))
                    (let* ((S1 (fxxor (rotr32 e 6) (rotr32 e 11) (rotr32 e 25)))
                           (ch (fxxor (fxand e f) (fxand (fxxor e mask32) g)))
                           (t1 (add32 h S1 ch (vector-ref sha256-k t) (vector-ref w t)))
                           (S0 (fxxor (rotr32 a 2) (rotr32 a 13) (rotr32 a 22)))
                           (mj (fxxor (fxand a b) (fxand a c) (fxand b c)))
                           (t2 (add32 S0 mj)))
                      (rounds (+ t 1)
                              (add32 t1 t2) a b c
                              (add32 d t1) e f g)))))))))

  ;; ---- base64 decode ----------------------------------------------------------

  (define (b64-value ch)
    (cond
      ((and (char<=? #\A ch) (char<=? ch #\Z)) (- (char->integer ch) 65))
      ((and (char<=? #\a ch) (char<=? ch #\z)) (+ 26 (- (char->integer ch) 97)))
      ((and (char<=? #\0 ch) (char<=? ch #\9)) (+ 52 (- (char->integer ch) 48)))
      ((char=? ch #\+) 62)
      ((char=? ch #\/) 63)
      (else #f)))

  (define (base64-decode s)
    (let-values (((p get) (open-bytevector-output-port)))
      (let loop ((i 0) (acc 0) (bits 0))
        (if (= i (string-length s))
            (get)
            (let ((v (b64-value (string-ref s i))))
              (if (not v)
                  (loop (+ i 1) acc bits)   ; skip '=', newlines, etc.
                  (let ((acc (+ (* acc 64) v)) (bits (+ bits 6)))
                    (if (>= bits 8)
                        (let ((keep (- bits 8)))
                          (put-u8 p (fxand (bitwise-arithmetic-shift-right acc keep) #xFF))
                          (loop (+ i 1) (fxand acc (- (fxsll 1 keep) 1)) keep))
                        (loop (+ i 1) acc bits)))))))))

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

  (define (random-bytes n)
    (let ((out (make-bytevector n)))
      (do ((i 0 (+ i 1))) ((= i n) out)
        (bytevector-u8-set! out i (random 256)))))

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

  ;; full caching_sha2 path over a plain connection: fetch the server's
  ;; RSA key and send the nonce-XORed password encrypted with OAEP
  (define (full-auth! c bufbox password nonce seq)
    (send-packet! c (bytevector 2) seq)           ; request public key
    (let-values (((p sq) (next-packet! c bufbox)))
      (unless (fx= (bytevector-u8-ref p 0) 1)
        (mysql-fail -1 "expected server public key"))
      (let-values (((n e) (parse-rsa-public-key
                            (utf8->string (bv-sub p 1 (bytevector-length p))))))
        (let ((plain (bv-xor (bv-append (string->utf8 password) (bytevector 0))
                             nonce)))
          (send-packet! c (rsa-oaep-encrypt plain n e) (+ sq 1))))))

  ;; drive the auth conversation to an OK packet (or raise)
  (define (auth-loop! c bufbox user password nonce)
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
                      (begin (full-auth! c bufbox password nonce (+ seq 1))
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

  (define (authenticate! c bufbox user password db)
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
          (auth-loop! c bufbox user password nonce)))))

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
  ;; error the connection is closed and this process exits -- the pool's
  ;; monitor then rebuilds it, rather than the dead connection returning
  ;; to the idle set.
  (define (serve-loop c bufbox notify)
    (receive
      (`#(mysql-query ,sql ,ref ,from)
        (let ((r (guard (e (#t (as-mysql-error e "query failed")))
                   (run-query! c bufbox sql))))
          (send from (vector 'mysql-reply ref r))
          (if (transport-dead? r)
              (tcp-close! c)                        ; exit -> DOWN -> rebuild
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

  ;; spawn a connection worker; reports #(mysql-up ,self ok-or-error) to
  ;; report-to, then serves queries (notifying `notify` when idle)
  (define (start-connection host port user password db notify report-to)
    (spawn
      (lambda ()
        (let ((outcome
               (guard (e (#t (as-mysql-error e "connect failed")))
                 (tcp-connect! host port self)
                 (receive (after connect-timeout-ms
                             (mysql-fail -1 "connect timeout"))
                   (`#(tcp-connected ,c)
                     (tcp-read-start! c)
                     (let ((bufbox (box empty-bv)))
                       (authenticate! c bufbox user password db)
                       (cons c bufbox)))
                   (`#(tcp-connect-failed ,e)
                     (mysql-fail -1 (uv-strerror e)))))))
          (if (pair? outcome)
              (begin
                (send report-to (vector 'mysql-up self 'ok))
                (serve-loop (car outcome) (cdr outcome) notify))
              (send report-to (vector 'mysql-up self outcome)))))))

  ;; ---- connection pool -----------------------------------------------------------------------

  ;; Fixed pool of n connections behind a dispatcher process. Queries go
  ;; to an idle connection or wait in a FIFO; replies flow directly from
  ;; the connection to the caller. Dead connections are replaced
  ;; automatically (1s backoff on failed connects); a caller whose
  ;; connection dies mid-query gets #(mysql-error -1 "connection lost").
  (define (pool-loop n host port user password db)
    (define me self)
    (define idle '())
    (define busy (make-eq-hashtable))   ; conn pid -> (caller-pid . ref)
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
    (define (connect!)
      (monitor (start-connection host port user password db me me)))
    ;; a job is #(sql ref from)
    (define (assign! c job)
      (hashtable-set! busy c (cons (vector-ref job 2) (vector-ref job 1)))
      (send c (vector 'mysql-query (vector-ref job 0)
                      (vector-ref job 1) (vector-ref job 2))))
    (define (make-available! c)
      (hashtable-delete! busy c)
      (if (pending?)
          (assign! c (pop-pending!))
          (set! idle (cons c idle))))
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
          (make-available! c)
          (loop))
        (`#(mysql-up ,pid ,status)
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
          ;; only react to the death of an ACTIVE connection; failed
          ;; connect workers already scheduled their own retry above
          (when (or (memq pid idle) (hashtable-contains? busy pid))
            (set! idle (remq pid idle))
            (let ((entry (hashtable-ref busy pid #f)))
              (hashtable-delete! busy pid)
              (when entry
                (send (car entry)
                      (vector 'mysql-reply (cdr entry)
                              (vector 'mysql-error -1 "connection lost")))))
            (connect!))
          (loop))
        (`#(mysql-quit)
          (for-each (lambda (c) (send c (vector 'mysql-quit))) idle)
          (vector-for-each
            (lambda (c) (send c (vector 'mysql-quit)))
            (hashtable-keys busy))
          'done))))

  ;; ---- public API ----------------------------------------------------------------------------

  ;; Connect + authenticate a single connection; returns the connection
  ;; process or raises #(mysql-error code msg).
  (define (mysql-connect host port user password . rest)
    (let ((db (if (pair? rest) (car rest) #f)))
      (random-seed (+ 1 (mod (now-ms) 4000000000)))
      (start-connection host port user password db #f self)
      (receive (after (+ connect-timeout-ms 2000)
                  (raise (vector 'mysql-error -1 "connect timeout")))
        (`#(mysql-up ,pid ,status)
          (if (eq? status 'ok)
              pid
              (raise status))))))

  ;; Pool of n connections; returns the dispatcher, which mysql-query
  ;; and mysql-close! accept exactly like a single connection. Usable
  ;; immediately: queries queue until connections come up.
  (define (mysql-pool n host port user password . rest)
    (let ((db (if (pair? rest) (car rest) #f)))
      (random-seed (+ 1 (mod (now-ms) 4000000000)))
      (spawn (lambda () (pool-loop n host port user password db)))))

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

  (define (mysql-close! mc)
    (send mc (vector 'mysql-quit)))
)
