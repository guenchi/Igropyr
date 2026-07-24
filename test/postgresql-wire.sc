#!chezscheme
;;; (igropyr postgresql) wire-level tests against an in-process fake server.
;;;
;;; A loopback listener speaks just enough of the v3 protocol to exercise
;;; the client's real code paths without a PostgreSQL installation, so
;;; these always run. The server implements the RFC 5802 SERVER-side
;;; verification algorithm (reconstruct ClientKey from the proof, hash,
;;; compare against StoredKey) -- structurally different from the client's
;;; derivation, so a swapped XOR, a wrong AuthMessage concatenation or a
;;; misspelled key constant in the driver fails here even though both ends
;;; share (igropyr crypto).
;;;
;;; Covered: SCRAM-SHA-256 success (and that startup announces
;;; client_encoding=UTF8), wrong-password ErrorResponse with its SQLSTATE,
;;; the fd-leak regression on failed auth (conn-count returns to baseline),
;;; cleartext auth refused by default / permitted by opt-in, NoticeResponse
;;; tolerated during auth, invalid message length rejected as a clean
;;; transport error, COPY FROM STDIN answered with CopyFail (server error
;;; surfaces, connection stays usable), and fragmented delivery of a
;;; multi-message result (inbuf reassembly).
;;;
;;; The test server selects its behavior from the startup "database"
;;; parameter: scram / cleartext / notice / badlen.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr postgresql)
        (only (igropyr crypto)
              sha256 hmac-sha256 pbkdf2-hmac-sha256 base64-encode base64-decode))

(define port 54326)
(define scram-password "pencil")
(define clear-password "pw2")

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

;; ---- shared byte helpers -------------------------------------------------

(define (bv-append . bvs)
  (let* ((total (fold-left (lambda (n x) (+ n (bytevector-length x))) 0 bvs))
         (out (make-bytevector total)))
    (let loop ((l bvs) (off 0))
      (if (null? l)
          out
          (let ((x (car l)))
            (bytevector-copy! x 0 out off (bytevector-length x))
            (loop (cdr l) (+ off (bytevector-length x))))))))

(define (bv-sub bv s e)
  (let ((r (make-bytevector (- e s)))) (bytevector-copy! bv s r 0 (- e s)) r))

(define (bv-xor a b)
  (let* ((n (bytevector-length a)) (out (make-bytevector n)))
    (do ((i 0 (+ i 1))) ((= i n) out)
      (bytevector-u8-set! out i
        (fxxor (bytevector-u8-ref a i) (bytevector-u8-ref b i))))))

(define (find-u8 bv start byte)
  (let ((n (bytevector-length bv)))
    (let loop ((i start))
      (cond ((>= i n) #f)
            ((fx= (bytevector-u8-ref bv i) byte) i)
            (else (loop (+ i 1)))))))

(define (u32 v)
  (let ((bv (make-bytevector 4)))
    (bytevector-u32-set! bv 0 v (endianness big)) bv))
(define (u16 v)
  (let ((bv (make-bytevector 2)))
    (bytevector-u16-set! bv 0 v (endianness big)) bv))
(define (ru32 bv pos) (bytevector-u32-ref bv pos (endianness big)))
(define (cstr s) (bv-append (string->utf8 s) (bytevector 0)))
(define (smsg type payload)
  (bv-append (bytevector (char->integer type))
             (u32 (+ 4 (bytevector-length payload))) payload))

(define (string-contains? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring s i (+ i m)) sub) #t)
            (else (loop (+ i 1)))))))

;; ---- fake server ----------------------------------------------------------

;; kv pairs of the startup body (after the 4-byte protocol version)
(define (parse-params body)
  (let ((n (bytevector-length body)))
    (let loop ((pos 4) (acc '()))
      (let ((z (find-u8 body pos 0)))
        (if (or (not z) (= z pos))
            (reverse acc)
            (let* ((k (utf8->string (bv-sub body pos z)))
                   (z2 (find-u8 body (+ z 1) 0))
                   (v (utf8->string (bv-sub body (+ z 1) z2))))
              (loop (+ z2 1) (cons (cons k v) acc))))))))

(define (error-msg code text)
  (smsg #\E (bv-append (bytevector (char->integer #\C)) (cstr code)
                       (bytevector (char->integer #\M)) (cstr text)
                       (bytevector 0))))
(define notice-msg
  (smsg #\N (bv-append (bytevector (char->integer #\M)) (cstr "test notice")
                       (bytevector 0))))
(define auth-ok (smsg #\R (u32 0)))
(define ready (smsg #\Z (string->utf8 "I")))

;; per-connection handler process
(define (serve-conn c)
  (define buf (box (make-bytevector 0)))
  (define (fill!)
    (receive (after 8000 (raise 'server-timeout))
      (`#(tcp-data ,bv) (set-box! buf (bv-append (unbox buf) bv)))
      (`#(tcp-eof) (raise 'server-eof))
      (`#(tcp-error ,e) (raise 'server-error))))
  (define (take! n)
    (let loop ()
      (when (< (bytevector-length (unbox buf)) n) (fill!) (loop)))
    (let* ((b (unbox buf)) (h (bv-sub b 0 n)))
      (set-box! buf (bv-sub b n (bytevector-length b)))
      h))
  (define (read-msg!)                     ; -> (values type-char payload)
    (let* ((head (take! 5))
           (type (integer->char (bytevector-u8-ref head 0)))
           (len (ru32 head 1)))
      (values type (take! (- len 4)))))
  (define (write! bv) (tcp-write! c bv #f))
  ;; write one buffer in 3-byte fragments: exercises the client's reassembly
  (define (write-fragmented! bv)
    (let ((n (bytevector-length bv)))
      (let loop ((i 0))
        (when (< i n)
          (write! (bv-sub bv i (min n (+ i 3))))
          (loop (+ i 3))))))

  ;; RFC 5802 SERVER algorithm: recover ClientKey from the proof and check
  ;; H(ClientKey) = StoredKey; on success answer v=ServerSignature.
  (define (scram-server! password)
    (let-values (((t p) (read-msg!)))                  ; SASLInitialResponse
      (let* ((mech-end (find-u8 p 0 0))
             (n (ru32 p (+ mech-end 1)))
             (client-first (utf8->string
                             (bv-sub p (+ mech-end 5) (+ mech-end 5 n))))
             ;; client-first = "n,," + bare
             (bare (substring client-first 3 (string-length client-first)))
             (salt (make-bytevector 16 7))
             (iters 4096)
             ;; bare = "n=,r=" + cnonce, so the nonce starts at index 5
             (snonce (string-append
                       (substring bare 5 (string-length bare)) "SRVNONCE"))
             (server-first (string-append "r=" snonce ",s="
                                          (base64-encode salt) ",i="
                                          (number->string iters))))
        (write! (smsg #\R (bv-append (u32 11) (string->utf8 server-first))))
        (let-values (((t2 p2) (read-msg!)))            ; SASLResponse
          (let* ((client-final (utf8->string p2))
                 (pi (let loop ((i 0))                 ; index of ",p="
                       (if (string=? (substring client-final i (+ i 3)) ",p=")
                           i (loop (+ i 1)))))
                 (noproof (substring client-final 0 pi))
                 (proof (base64-decode
                          (substring client-final (+ pi 3)
                                     (string-length client-final))))
                 (auth-msg (string-append bare "," server-first "," noproof))
                 (salted (pbkdf2-hmac-sha256 (string->utf8 password) salt iters 32))
                 (stored (sha256 (hmac-sha256 salted (string->utf8 "Client Key"))))
                 (sig (hmac-sha256 stored (string->utf8 auth-msg)))
                 (client-key (bv-xor proof sig)))
            (if (bytevector=? (sha256 client-key) stored)
                (let ((v (hmac-sha256 (hmac-sha256 salted (string->utf8 "Server Key"))
                                      (string->utf8 auth-msg))))
                  (write! (smsg #\R (bv-append (u32 12)
                            (string->utf8 (string-append "v=" (base64-encode v))))))
                  (write! auth-ok) (write! ready)
                  #t)
                (begin
                  (write! (error-msg "28P01" "password authentication failed"))
                  (tcp-close! c)
                  #f)))))))

  ;; simple-query server: "SELECT ..." -> fragmented T/D/C/Z with a NULL
  ;; column; "COPY ..." -> CopyInResponse, expect CopyFail, then E+Z.
  (define (query-loop!)
    (let-values (((t p) (read-msg!)))
      (case t
        ((#\Q)
         (let ((sql (utf8->string (bv-sub p 0 (find-u8 p 0 0)))))
           (if (and (>= (string-length sql) 4)
                    (string=? (substring sql 0 4) "COPY"))
               (begin
                 (write! (smsg #\G (bv-append (bytevector 0) (u16 0))))
                 (let-values (((tf pf) (read-msg!)))   ; expect CopyFail
                   (if (char=? tf #\f)
                       (write! (bv-append
                                 (error-msg "57014" "COPY from stdin failed")
                                 ready))
                       (write! (bv-append
                                 (error-msg "08P01" "expected CopyFail")
                                 ready)))))
               (write-fragmented!
                 (bv-append
                   (smsg #\T (bv-append (u16 2)
                               (cstr "a") (make-bytevector 18 0)
                               (cstr "b") (make-bytevector 18 0)))
                   (smsg #\D (bv-append (u16 2)
                               (u32 2) (string->utf8 "42")
                               (u32 #xFFFFFFFF)))         ; -1 = NULL
                   (smsg #\C (cstr "SELECT 1"))
                   ready)))
           (query-loop!)))
        ((#\X) (tcp-close! c))
        (else (tcp-close! c)))))

  (guard (e (#t (tcp-close! c)))
    ;; startup message (untyped): Int32 len + body
    (let* ((len (ru32 (take! 4) 0))
           (body (take! (- len 4)))
           (params (parse-params body))
           (db (cond ((assoc "database" params) => cdr) (else "")))
           (enc (cond ((assoc "client_encoding" params) => cdr) (else #f))))
      (cond
        ((not (equal? enc "UTF8"))
         ;; every mode requires the client to pin the wire encoding
         (write! (error-msg "08P01" "client_encoding UTF8 not announced"))
         (tcp-close! c))
        ((equal? db "scram")
         (write! (smsg #\R (bv-append (u32 10) (cstr "SCRAM-SHA-256")
                                      (bytevector 0))))
         (when (scram-server! scram-password)
           (query-loop!)))
        ((equal? db "notice")
         ;; notices interleaved through the auth exchange must be skipped
         (write! notice-msg)
         (write! (smsg #\R (bv-append (u32 10) (cstr "SCRAM-SHA-256")
                                      (bytevector 0))))
         (write! notice-msg)
         (when (scram-server! scram-password)
           (query-loop!)))
        ((equal? db "cleartext")
         (write! (smsg #\R (u32 3)))
         (let-values (((t p) (read-msg!)))
           (let ((pw (utf8->string (bv-sub p 0 (find-u8 p 0 0)))))
             (if (equal? pw clear-password)
                 (begin (write! auth-ok) (write! ready) (query-loop!))
                 (begin (write! (error-msg "28P01" "bad password"))
                        (tcp-close! c))))))
        ((equal? db "badlen")
         ;; a desynchronised/hostile peer: type byte + Int32 length 0
         (write! (bv-append (bytevector (char->integer #\R)) (u32 0))))
        (else
         (write! (error-msg "3D000" "unknown test database"))
         (tcp-close! c))))))

;; ---- the tests -------------------------------------------------------------

(start-scheduler
  (lambda ()
    (define (connect-error . args)        ; -> the raised error vector or #f
      (guard (e (#t e))
        (postgresql-close! (apply postgresql-connect args))
        #f))

    (tcp-listen! "127.0.0.1" port 16
      (lambda (c)
        (let ((pid (spawn (lambda () (serve-conn c)))))
          (conn-set-owner! c pid)
          (tcp-read-start! c))))

    ;; 1. SCRAM against the server-side verifier (binds the driver's math),
    ;;    plus client_encoding announcement (server rejects without it)
    (let ((conn (postgresql-connect "127.0.0.1" port "user" scram-password "scram")))
      (check "scram-auth-verified" #t)
      ;; 2. fragmented T/D/C/Z reassembly + NULL column
      (let ((r (postgresql-query conn "SELECT anything")))
        (check "fragmented-rows"
          (equal? r (vector 'rows '("a" "b") '(("42" #f))))))
      ;; 3. COPY FROM STDIN -> CopyFail -> server SQL error, connection
      ;;    stays framed and usable
      (check "copy-in-refused-sqlstate"
        (guard (e (#t (and (vector? e) (equal? (vector-ref e 1) "57014"))))
          (postgresql-query conn "COPY t FROM STDIN") #f))
      (let ((r (postgresql-query conn "SELECT again")))
        (check "usable-after-copy-error"
          (equal? r (vector 'rows '("a" "b") '(("42" #f))))))
      (postgresql-close! conn))

    ;; 4. wrong password -> SQLSTATE 28P01 from the server verifier
    (let ((e (connect-error "127.0.0.1" port "user" "wrong" "scram")))
      (check "wrong-password-28P01"
        (and e (equal? (vector-ref e 1) "28P01"))))

    ;; 5. fd-leak regression: failed auth must release the uv handle
    (sleep-ms 300)                        ; let close callbacks run
    (let ((baseline (conn-count)))
      (do ((i 0 (+ i 1))) ((= i 5))
        (connect-error "127.0.0.1" port "user" "wrong" "scram"))
      (sleep-ms 300)
      (check "no-fd-leak-on-failed-auth" (<= (conn-count) baseline)))

    ;; 6. cleartext refused by default...
    (let ((e (connect-error "127.0.0.1" port "user" clear-password "cleartext")))
      (check "cleartext-refused-by-default"
        (and e (eq? (vector-ref e 1) 'transport)
             (string-contains? (vector-ref e 2) "cleartext"))))
    ;; ...and permitted by explicit opt-in
    (let ((conn (postgresql-connect "127.0.0.1" port "user" clear-password
                                    "cleartext" '((allow-cleartext-auth . #t)))))
      (check "cleartext-opt-in-works" #t)
      (postgresql-close! conn))

    ;; 7. notices during auth are informational, not fatal
    (let ((conn (postgresql-connect "127.0.0.1" port "user" scram-password "notice")))
      (check "notice-during-auth-tolerated" #t)
      (postgresql-close! conn))

    ;; 8. invalid message length -> clean transport error, not an assertion
    (let ((e (connect-error "127.0.0.1" port "user" "x" "badlen")))
      (check "invalid-length-clean-error"
        (and e (eq? (vector-ref e 1) 'transport)
             (string-contains? (vector-ref e 2) "invalid message length"))))

    (tcp-stop-listen!)
    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "postgresql-wire: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
