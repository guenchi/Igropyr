#!chezscheme
;;; test/mysql-auth-sequence.sc -- caching_sha2 full authentication sends
;;; the right packet number and encrypts against the right nonce.
;;;
;;; Two defects in one conversation, both invisible against a real server
;;; only because the server rejects the login and the driver reports
;;; "access denied", which looks like a wrong password:
;;;
;;;  * the packet carrying the RSA-encrypted password was numbered one too
;;;    high when the public key is pinned: the AuthMoreData branch passed
;;;    "server sequence + 1" and the pinned branch added one again. A full
;;;    authentication demanded in packet 2 must be answered in packet 3;
;;;    packet 4 went out;
;;;  * after an AuthSwitchRequest the new nonce was used for the immediate
;;;    scramble only. The full authentication that can follow still XORed
;;;    the password with the GREETING's nonce, so the server decrypted a
;;;    password it could never verify.
;;;
;;; An in-process fake server speaks just enough of the protocol to demand
;;; each path, records every client packet with its sequence byte, and the
;;; cell decrypts the RSA-OAEP packet with the matching private key -- a
;;; throwaway 1024-bit test key generated for this file -- and compares the
;;; plaintext with (password NUL) XOR nonce. The password and key are test
;;; constants; nothing here reaches a real database.
;;;
;;; Twins: the fast path; the fetched-key path (whose sequence was already
;;; right, from the key packet's own number); the scramble sent right after
;;; a switch (already computed from the new nonce); an empty password, whose
;;; answer to the demand is a single NUL in the right packet. Also: after a
;;; switch to mysql_native_password, any AuthMoreData -- the full-auth
;;; demand 0x04 and the fast-path 0x03 alike -- is refused ("unexpected auth
;;; data") and nothing more goes out: that plugin has no such exchange, and
;;; the loop now knows which plugin it is in. Not covered: sequence wrap past 255 (a handshake never
;;; gets there). The fake server does not reject a wrong sequence number as
;;; a real server would ("packets out of order"): it records it, so the row
;;; reads the number instead of a login failure.

(import (chezscheme) (igropyr actor) (igropyr tcp) (igropyr crypto) (igropyr mysql))

(define port 18856)
(define password "test-password")
(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

;; ---- byte helpers --------------------------------------------------------------------
(define (bv-append . bvs)
  (let* ((n (apply + (map bytevector-length bvs))) (r (make-bytevector n)))
    (let loop ((bvs bvs) (pos 0))
      (if (null? bvs) r
          (begin (bytevector-copy! (car bvs) 0 r pos (bytevector-length (car bvs)))
                 (loop (cdr bvs) (+ pos (bytevector-length (car bvs)))))))))
(define (bv-sub bv s e) (let ((r (make-bytevector (- e s)))) (bytevector-copy! bv s r 0 (- e s)) r))
(define (u8* . xs) (u8-list->bytevector xs))
(define (zeros n) (make-bytevector n 0))
(define (bv-xor-cycled a b)
  (let* ((n (bytevector-length a)) (bn (bytevector-length b)) (out (make-bytevector n)))
    (do ((i 0 (+ i 1))) ((= i n) out)
      (bytevector-u8-set! out i (fxxor (bytevector-u8-ref a i) (bytevector-u8-ref b (mod i bn)))))))
(define (bv-xor a b) (bv-xor-cycled a b))
(define (bytes->integer bv s e)
  (let loop ((i s) (v 0)) (if (= i e) v (loop (+ i 1) (+ (* v 256) (bytevector-u8-ref bv i))))))
(define (integer->bytes v len)
  (let ((out (make-bytevector len 0)))
    (let loop ((i (- len 1)) (v v))
      (if (< i 0) out (begin (bytevector-u8-set! out i (mod v 256)) (loop (- i 1) (div v 256)))))))
(define (hex->integer s) (string->number s 16))
(define (packet payload seq)
  (let ((n (bytevector-length payload)))
    (bv-append (u8* (fxand n #xFF) (fxand (fxsrl n 8) #xFF) (fxand (fxsrl n 16) #xFF) (fxand seq #xFF))
               payload)))

;; ---- the test key (generated with openssl genrsa 1024 for this file only) -------------
(define rsa-n (hex->integer "aa753cc604348fe410ac4d4ab80bdd1dee6667910617a43bec3c44aa8c34146882d4decb7280ec06aa1875b04916c8a6f84cd3b1da796a77f4101d1d5fe10733f2c537ff292fe900960a04092620d0c4fca97e9b9e0c80e30dbf8655043ad18f44a13ed0be825e29a36065e799c862ff1346c3157c132019ed65400a3a835b05"))
(define rsa-d (hex->integer "6aacd009c45bf8a8ebde48c8b80184b1d49e75b606b008f20f577049a3507c6d236380c2a5b814fddeb94bfdb4dff356bb11a972269dd1899c4df14a8ed44f22a7a5aeeddee3f3b0027355fd2f10e893f9daa8cb3fc2daa132a52fd4f84f0ae2bb512df2b8354d1647a2e2ccbf498ece17efff285c47182f1b9f6c8b9dd26809"))
(define rsa-k 128)
(define public-pem
  (string-append
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqdTzGBDSP5BCsTUq4C90d7mZn\n"
    "kQYXpDvsPESqjDQUaILU3stygOwGqhh1sEkWyKb4TNOx2nlqd/QQHR1f4Qcz8sU3\n"
    "/ykv6QCWCgQJJiDQxPypfpueDIDjDb+GVQQ60Y9EoT7QvoJeKaNgZeeZyGL/E0bD\n"
    "FXwTIBntZUAKOoNbBQIDAQAB\n"
    "-----END PUBLIC KEY-----\n"))

;; RSA-OAEP (SHA-1, empty label) decrypt -> message bytevector, or #f
(define (mgf1-sha1 seed len)
  (let loop ((counter 0) (parts '()) (got 0))
    (if (>= got len)
        (bv-sub (apply bv-append (reverse parts)) 0 len)
        (let ((h (sha1 (bv-append seed (integer->bytes counter 4)))))
          (loop (+ counter 1) (cons h parts) (+ got 20))))))
(define (oaep-decrypt c)
  (and (= (bytevector-length c) rsa-k)
       (let* ((em (integer->bytes (expt-mod (bytes->integer c 0 rsa-k) rsa-d rsa-n) rsa-k))
              (masked-seed (bv-sub em 1 21))
              (masked-db (bv-sub em 21 rsa-k))
              (seed (bv-xor masked-seed (mgf1-sha1 masked-db 20)))
              (db (bv-xor masked-db (mgf1-sha1 seed (- rsa-k 21)))))
         (and (= 0 (bytevector-u8-ref em 0))
              (equal? (bv-sub db 0 20) (sha1 (u8*)))
              (let find ((i 20))
                (cond ((>= i (bytevector-length db)) #f)
                      ((= 1 (bytevector-u8-ref db i)) (bv-sub db (+ i 1) (bytevector-length db)))
                      ((= 0 (bytevector-u8-ref db i)) (find (+ i 1)))
                      (else #f)))))))

;; what the client must have encrypted: (password NUL) XOR nonce, nonce cycled
(define (expected-plain nonce) (bv-xor-cycled (bv-append (string->utf8 password) (u8* 0)) nonce))
(define (scramble-sha2 nonce)
  (let* ((d1 (sha256 (string->utf8 password))) (d2 (sha256 d1)))
    (bv-xor d1 (sha256 (bv-append d2 nonce)))))

;; ---- the fake server --------------------------------------------------------------------
(define greeting-nonce (u8* 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))
(define switch-nonce (u8* 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40))
(define (greeting plugin)
  (bv-append (u8* 10) (string->utf8 "8.0.0-fake") (u8* 0) (u8* 1 0 0 0)
             (bv-sub greeting-nonce 0 8) (u8* 0) (u8* #xFF #xF7) (u8* 33) (u8* 2 0) (u8* #x0F #x80)
             (u8* 21) (zeros 10) (bv-sub greeting-nonce 8 20) (u8* 0)
             (string->utf8 plugin) (u8* 0)))
(define ok-packet (u8* 0 0 0 2 0 0 0))
(define auth-more-full (u8* 1 4))
(define auth-more-fast (u8* 1 3))
(define auth-switch (bv-append (u8* #xFE) (string->utf8 "caching_sha2_password") (u8* 0) switch-nonce (u8* 0)))
(define auth-switch-native (bv-append (u8* #xFE) (string->utf8 "mysql_native_password") (u8* 0) switch-nonce (u8* 0)))
(define request-key (u8* 2))

;; scenario: a list of steps, each (send <payload>) or (expect <tag>); the
;; server sends, then reads one client packet per expect and records
;; (tag seq payload). The server's sequence byte follows the protocol: each
;; packet it sends is numbered one above the last packet it received.
(define scenario (box '()))
(define recorded (box '()))
(define (record! tag seq payload) (set-box! recorded (cons (list tag seq payload) (unbox recorded))))
(define (rec tag) (let ((p (assq tag (unbox recorded)))) (and p (cdr p))))

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid
              (spawn
                (lambda ()
                  (guard (e (#t (record! 'server-raised 0 e)))
                    (let run ((steps (unbox scenario)) (acc (u8*)) (last-seq -1))
                      (cond
                        ((null? steps)
                         (receive (after 2000 (tcp-close! c)) (`#(tcp-eof) (tcp-close! c)) (`#(tcp-error ,_) (tcp-close! c))))
                        ((eq? (caar steps) 'send)
                         (tcp-write! c (packet (cadar steps) (+ last-seq 1)) #f)
                         (run (cdr steps) acc (+ last-seq 1)))
                        (else
                         ;; expect: read until one whole packet is buffered
                         (let ((n (bytevector-length acc)))
                           (if (and (>= n 4)
                                    (>= n (+ 4 (+ (bytevector-u8-ref acc 0) (* 256 (bytevector-u8-ref acc 1))
                                                  (* 65536 (bytevector-u8-ref acc 2))))))
                               (let* ((len (+ (bytevector-u8-ref acc 0) (* 256 (bytevector-u8-ref acc 1))
                                              (* 65536 (bytevector-u8-ref acc 2))))
                                      (seq (bytevector-u8-ref acc 3))
                                      (payload (bv-sub acc 4 (+ 4 len))))
                                 (record! (cadar steps) seq payload)
                                 (run (cdr steps) (bv-sub acc (+ 4 len) n) seq))
                               (receive (after 5000 (record! 'server-timeout 0 (caar steps)) (tcp-close! c))
                                 (`#(tcp-data ,bv) (run steps (bv-append acc bv) last-seq))
                                 (`#(tcp-eof) (record! 'server-eof 0 (caar steps)) (tcp-close! c))
                                 (`#(tcp-error ,e) (record! 'server-error 0 e) (tcp-close! c)))))))))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

;; -> 'connected | (error . message) | (raised . e)
(define (connect-with steps opts . pw)
  (set-box! scenario steps)
  (set-box! recorded '())
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'mysql-error)) (cons 'error (vector-ref e 2)))
            (#t (cons 'raised e)))
    (let ((conn (mysql-connect "127.0.0.1" port "user" (if (pair? pw) (car pw) password) #f
                               (append opts '((connect-deadline-ms . 4000))))))
      (mysql-close! conn)
      'connected)))

(define pinned (list (cons 'server-public-key public-pem)))
(define insecure '((allow-insecure-auth . #t)))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 100)

    ;; ---- twin: the fast path -------------------------------------------------------------
    (let ((r (connect-with `((send ,(greeting "caching_sha2_password")) (expect response)
                             (send ,auth-more-fast) (send ,ok-packet))
                           pinned)))
      (check "twin: fast path (AuthMoreData 3 then OK) connects" (eq? r 'connected) r (unbox recorded))
      (check "twin: the handshake response is packet 1" (equal? (cadr (assq 'response (unbox recorded))) 1)
             (unbox recorded)))

    ;; ---- full authentication with a pinned key, demanded in packet 2 ---------------------
    (let ((r (connect-with `((send ,(greeting "caching_sha2_password")) (expect response)
                             (send ,auth-more-full) (expect encrypted) (send ,ok-packet))
                           pinned)))
      (let ((enc (rec 'encrypted)))
        (check "pinned full auth: the client answers the demand and the login completes" (eq? r 'connected) r)
        (check "pinned full auth: the encrypted password is packet 3 (one above the demand's 2)"
               (and enc (= (car enc) 3)) (and enc (car enc)))
        (check "pinned full auth: it decrypts to (password NUL) XOR the greeting nonce"
               (and enc (equal? (oaep-decrypt (cadr enc)) (expected-plain greeting-nonce)))
               (and enc (oaep-decrypt (cadr enc))))))

    ;; ---- twin: the fetched-key path numbers from the key packet ---------------------------
    (let ((r (connect-with `((send ,(greeting "caching_sha2_password")) (expect response)
                             (send ,auth-more-full) (expect key-request)
                             (send ,(bv-append (u8* 1) (string->utf8 public-pem))) (expect encrypted)
                             (send ,ok-packet))
                           insecure)))
      (let ((req (rec 'key-request)) (enc (rec 'encrypted)))
        (check "twin: fetched key: the login completes" (eq? r 'connected) r)
        (check "twin: fetched key: the request for the key is packet 3 and the encrypted password packet 5"
               (and req enc (= (car req) 3) (= (car enc) 5)) (and req (car req)) (and enc (car enc)))
        (check "twin: fetched key: the request is the single byte 2" (and req (equal? (cadr req) request-key))
               (and req (cadr req)))
        (check "twin: fetched key: it decrypts to the password XOR the greeting nonce"
               (and enc (equal? (oaep-decrypt (cadr enc)) (expected-plain greeting-nonce))))))

    ;; ---- an auth switch, then full authentication: the switched nonce ----------------------
    (let ((r (connect-with `((send ,(greeting "mysql_native_password")) (expect response)
                             (send ,auth-switch) (expect scramble)
                             (send ,auth-more-full) (expect encrypted) (send ,ok-packet))
                           pinned)))
      (let ((scr (rec 'scramble)) (enc (rec 'encrypted)))
        (check "switch then full auth: the login completes" (eq? r 'connected) r)
        (check "twin: the scramble sent right after the switch is packet 3, computed from the switched nonce"
               (and scr (= (car scr) 3) (equal? (cadr scr) (scramble-sha2 switch-nonce))) (and scr (car scr)))
        (check "switch then full auth: the encrypted password is packet 5 (one above the demand's 4)"
               (and enc (= (car enc) 5)) (and enc (car enc)))
        (check "switch then full auth: it decrypts to the password XOR the SWITCHED nonce, not the greeting's"
               (and enc (equal? (oaep-decrypt (cadr enc)) (expected-plain switch-nonce)))
               (and enc (let ((p (oaep-decrypt (cadr enc))))
                          (cond ((equal? p (expected-plain greeting-nonce)) 'greeting-nonce)
                                (else p)))))))

    ;; ---- the same switch, fetched key: both defects together on the other key path --------
    (let ((r (connect-with `((send ,(greeting "mysql_native_password")) (expect response)
                             (send ,auth-switch) (expect scramble)
                             (send ,auth-more-full) (expect key-request)
                             (send ,(bv-append (u8* 1) (string->utf8 public-pem))) (expect encrypted)
                             (send ,ok-packet))
                           insecure)))
      (let ((enc (rec 'encrypted)))
        (check "switch then fetched key: the login completes" (eq? r 'connected) r)
        (check "switch then fetched key: the encrypted password is packet 7"
               (and enc (= (car enc) 7)) (and enc (car enc)))
        (check "switch then fetched key: it decrypts to the password XOR the switched nonce"
               (and enc (equal? (oaep-decrypt (cadr enc)) (expected-plain switch-nonce))))))

    ;; ---- twin: an empty password answers the demand with one NUL byte, in packet 3 ---------
    (let ((r (connect-with `((send ,(greeting "caching_sha2_password")) (expect response)
                             (send ,auth-more-full) (expect empty-answer) (send ,ok-packet))
                           pinned "")))
      (let ((ans (rec 'empty-answer)))
        (check "twin: empty password: the login completes" (eq? r 'connected) r)
        (check "twin: empty password: the answer is a single NUL in packet 3"
               (and ans (= (car ans) 3) (equal? (cadr ans) (u8* 0))) ans)))

    ;; ---- a full-auth demand after a switch to mysql_native_password is refused --------------
    ;; the fake server would answer OK to anything; the rows are the refusal
    ;; and that nothing was sent after the scramble
    (let ((r (connect-with `((send ,(greeting "caching_sha2_password")) (expect response)
                             (send ,auth-switch-native) (expect scramble)
                             (send ,auth-more-full) (expect anything) (send ,ok-packet))
                           pinned)))
      (check "after a switch to mysql_native_password, a full-auth demand is refused as unexpected auth data"
             (and (pair? r) (eq? (car r) 'error) (string? (cdr r))
                  (let loop ((i 0)) (and (<= (+ i 20) (string-length (cdr r)))
                                        (or (string=? (substring (cdr r) i (+ i 20)) "unexpected auth data")
                                            (loop (+ i 1))))))
             r)
      (check "  and nothing was sent after the scramble" (not (rec 'anything)) (rec 'anything)))
    (let ((r (connect-with `((send ,(greeting "caching_sha2_password")) (expect response)
                             (send ,auth-switch-native) (expect scramble)
                             (send ,auth-more-fast) (expect anything) (send ,ok-packet))
                           pinned)))
      (check "after a switch to mysql_native_password, the fast-path AuthMoreData 0x03 is refused too"
             (and (pair? r) (eq? (car r) 'error) (string? (cdr r))
                  (let loop ((i 0)) (and (<= (+ i 20) (string-length (cdr r)))
                                        (or (string=? (substring (cdr r) i (+ i 20)) "unexpected auth data")
                                            (loop (+ i 1))))))
             r)
      (check "  and nothing was sent after that scramble either" (not (rec 'anything)) (rec 'anything)))

    ;; ---- the server side never raised or timed out ---------------------------------------
    (check "the fake server recorded no raise in the last conversation (the eof there is the client's refusal)"
           (not (or (rec 'server-raised) (rec 'server-error)))
           (unbox recorded))

    (if (zero? failures)
        (begin (display "mysql-auth-sequence: all tests passed\n") (exit 0))
        (begin (display "mysql-auth-sequence: ") (display failures) (display " failed\n") (exit 1)))))
