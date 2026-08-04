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

  ;; Advertise an otherwise valid SCRAM challenge with a hostile PBKDF2
  ;; work factor. The client must reject it before deriving any key.
  (define (scram-cost-server! iters)
    (let-values (((t p) (read-msg!)))
      (let* ((mech-end (find-u8 p 0 0))
             (n (ru32 p (+ mech-end 1)))
             (client-first (utf8->string
                             (bv-sub p (+ mech-end 5) (+ mech-end 5 n))))
             (bare (substring client-first 3 (string-length client-first)))
             (snonce (string-append
                       (substring bare 5 (string-length bare)) "SRVNONCE"))
             (server-first
               (string-append "r=" snonce ",s="
                              (base64-encode (make-bytevector 16 7))
                              ",i=" (number->string iters))))
        (write! (smsg #\R (bv-append (u32 11) (string->utf8 server-first)))))))

  ;; Bind payload -> list of param values (#f for NULL, else string).
  ;; portal cstr + stmt cstr + Int16 nfmt + fmts + Int16 nparams +
  ;; (Int32 len + bytes)* + Int16 nresfmt ...
  (define (parse-bind-params p)
    (let* ((z1 (find-u8 p 0 0))
           (z2 (find-u8 p (+ z1 1) 0))
           (nfmt (bytevector-u16-ref p (+ z2 1) (endianness big)))
           (pos (+ z2 3 (* 2 nfmt)))
           (n (bytevector-u16-ref p pos (endianness big))))
      (let loop ((i 0) (pos (+ pos 2)) (acc '()))
        (if (= i n)
            (reverse acc)
            (let ((len (bytevector-s32-ref p pos (endianness big))))
              (if (= len -1)
                  (loop (+ i 1) (+ pos 4) (cons #f acc))
                  (loop (+ i 1) (+ pos 4 len)
                        (cons (utf8->string (bv-sub p (+ pos 4) (+ pos 4 len)))
                              acc))))))))

  ;; extended-flow server: consume Parse..Sync, then echo the Bind
  ;; parameters back as one row (NULL stays NULL) -- this pins the
  ;; client's Parse/Bind encoding end to end.
  (define (extended-flow! bind-payload)
    (let ((params (parse-bind-params bind-payload)))
      (let drain ()                       ; Describe, Execute, then Sync
        (let-values (((t p) (read-msg!)))
          (unless (char=? t #\S) (drain))))
      (write! (smsg #\1 (make-bytevector 0)))          ; ParseComplete
      (write! (smsg #\2 (make-bytevector 0)))          ; BindComplete
      (write! (smsg #\T (apply bv-append (u16 (length params))
                          (let loop ((i 1) (acc '()))
                            (if (> i (length params))
                                (reverse acc)
                                (loop (+ i 1)
                                      (cons (bv-append
                                              (cstr (string-append
                                                      "p" (number->string i)))
                                              (make-bytevector 18 0))
                                            acc)))))))
      (write! (smsg #\D (apply bv-append (u16 (length params))
                          (map (lambda (v)
                                 (if v
                                     (let ((bv (string->utf8 v)))
                                       (bv-append (u32 (bytevector-length bv)) bv))
                                     (u32 #xFFFFFFFF)))
                               params))))
      (write! (smsg #\C (cstr "SELECT 1")))
      (write! ready)))

  ;; simple-query server: "SELECT ..." -> fragmented T/D/C/Z with a NULL
  ;; column; "COPY ..." -> CopyInResponse, expect CopyFail, then E+Z.
  (define (query-loop!)
    (let-values (((t p) (read-msg!)))
      (case t
        ((#\P)                            ; extended flow: next is Bind
         (let-values (((tb pb) (read-msg!)))
           (extended-flow! pb))
         (query-loop!))
        ((#\Q)
         (let ((sql (utf8->string (bv-sub p 0 (find-u8 p 0 0)))))
           ;; a query this server never answers: the shape a hung server
           ;; has, and the only one in which the connection's own deadline
           ;; is still far away when the pool wants the connection back
           (when (and (>= (string-length sql) 6)
                      (string=? (substring sql 0 6) "SILENT"))
             (let hush () (fill!) (hush)))
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
               ;; a query that never finishes but never stalls: one row
               ;; every 200 ms, forever. Only something that notices the
               ;; owner's death can end this.
               (if (and (>= (string-length sql) 4)
                        (string=? (substring sql 0 4) "DRIP"))
                   (begin
                     (write! (smsg #\T (bv-append (u16 1)
                               (cstr "a") (make-bytevector 18 0))))
                     ;; ends the SERVER process too. Falling back into
                     ;; query-loop! after the client is gone leaves this
                     ;; process parked on a closed connection forever -- and
                     ;; that leftover looked exactly like the client-side
                     ;; leak the case is meant to detect.
                     (let drip ()
                       (receive (after 200
                                   (write! (smsg #\D (bv-append (u16 1)
                                             (u32 2) (string->utf8 "42"))))
                                   (drip))
                         (`#(tcp-eof) (tcp-close! c) (raise 'drip-done))
                         (`#(tcp-error ,_) (tcp-close! c) (raise 'drip-done)))))
               (write-fragmented!
                 (bv-append
                   (smsg #\T (bv-append (u16 2)
                               (cstr "a") (make-bytevector 18 0)
                               (cstr "b") (make-bytevector 18 0)))
                   (smsg #\D (bv-append (u16 2)
                               (u32 2) (string->utf8 "42")
                               (u32 #xFFFFFFFF)))         ; -1 = NULL
                   (smsg #\C (cstr "SELECT 1"))
                   ready))))
           (query-loop!)))
        ((#\X) (tcp-close! c))
        (else (tcp-close! c)))))

  (guard (e (#t (tcp-close! c)))
    ;; startup message (untyped): Int32 len + body. An 8-byte SSLRequest
    ;; (magic 80877103) may arrive first: this server refuses TLS with the
    ;; single raw byte 'N' -- a client that asked for TLS must then fail
    ;; hard rather than continue in plaintext.
    (let* ((len0 (ru32 (take! 4) 0))
           (len (if (and (= len0 8) (= (ru32 (take! 4) 0) 80877103))
                    (begin (write! (string->utf8 "N"))
                           (ru32 (take! 4) 0))     ; next message, if any
                    len0))
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
        ;; A server that never finishes, but never stalls either: one
        ;; NoticeResponse every 300 ms, forever. Every read completes well
        ;; inside connect-timeout-ms, so the per-message timeout re-arms and
        ;; never fires -- which is the point. Only a deadline on the whole
        ;; conversation can end this, and without one the worker ran for the
        ;; life of the process (and, in a pool, held its slot).
        ((equal? db "notice-forever")
         (write! notice-msg)
         (write! (smsg #\R (bv-append (u32 10) (cstr "SCRAM-SHA-256")
                                      (bytevector 0))))
         ;; Stop when the client goes away, so what the counts measure
         ;; afterwards is the CLIENT's worker and nothing else. A drip loop
         ;; that ran forever kept its own process and socket alive and hid
         ;; the one leaked worker inside its own noise.
         (let drip ()
           (receive (after 300 (write! notice-msg) (drip))
             (`#(tcp-eof) (tcp-close! c))
             (`#(tcp-error ,e) (tcp-close! c)))))
        ((equal? db "scram-cost")
         (write! (smsg #\R (bv-append (u32 10) (cstr "SCRAM-SHA-256")
                                      (bytevector 0))))
         (scram-cost-server! 2000001))
        ;; just over the shipped ceiling and far under any loose one: this
        ;; is what pins the DEFAULT rather than merely the mechanism
        ((equal? db "scram-cost-mid")
         (write! (smsg #\R (bv-append (u32 10) (cstr "SCRAM-SHA-256")
                                      (bytevector 0))))
         (scram-cost-server! 150001))
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
        (postgreconnpool-close! (apply postgresql-connect args))
        #f))

    (tcp-listen! "127.0.0.1" port 16
      (lambda (c)
        (let ((pid (spawn (lambda () (guard (e (#t (void))) (serve-conn c))))))
          (conn-set-owner! c pid)
          (tcp-read-start! c))))

    ;; 0. a teardown must reach a connection that is mid-query.
    ;;
    ;; The pool reclaims a connection whose borrower died by sending it
    ;; pool-quit: @kill discards dynamic-wind winders, so no check-in runs and
    ;; the pool's monitor is the only path back. A connection waiting on a
    ;; server that has stopped answering matched only TCP messages, so that
    ;; pool-quit sat in its mailbox for the whole query timeout -- a MINUTE by
    ;; default -- and for all of it the pool had it marked dying: neither
    ;; lent out nor rebuilt. One reaped caller, one connection gone for a
    ;; minute.
    (let ((conn (postgresql-connect "127.0.0.1" port "user" scram-password "scram"))
          (me self))
      (let ((m (monitor conn)))
        (spawn (lambda () (guard (e (#t 'ok)) (postgreconnpool-call conn "SILENT"))))
        (sleep-ms 200)
        (let ((t0 (now-ms)))
          (send conn (vector 'pool-quit))
          (let ((took (receive (after 5000 #f)
                        (`#(DOWN ,@conn ,reason) (- (now-ms) t0)))))
            (check "mid-query-pool-quit" (and took (< took 3000)))
            (display (string-append "  [info] mid-query pool-quit honoured after "
                                    (if took (number->string took) "never")
                                    "ms (the query deadline is 60000)\n"))))))

    ;; 1. SCRAM against the server-side verifier (binds the driver's math),
    ;;    plus client_encoding announcement (server rejects without it)
    (let ((conn (postgresql-connect "127.0.0.1" port "user" scram-password "scram")))
      (check "scram-auth-verified" #t)
      ;; 2. fragmented T/D/C/Z reassembly + NULL column
      (let ((r (postgreconnpool-call conn "SELECT anything")))
        (check "fragmented-rows"
          (equal? r (vector 'rows '("a" "b") '(("42" #f))))))
      ;; 3. COPY FROM STDIN -> CopyFail -> server SQL error, connection
      ;;    stays framed and usable
      (check "copy-in-refused-sqlstate"
        (guard (e (#t (and (vector? e) (equal? (vector-ref e 1) "57014"))))
          (postgreconnpool-call conn "COPY t FROM STDIN") #f))
      (let ((r (postgreconnpool-call conn "SELECT again")))
        (check "usable-after-copy-error"
          (equal? r (vector 'rows '("a" "b") '(("42" #f))))))
      ;; extended protocol: the server echoes the Bind parameters back,
      ;; pinning Parse/Bind encoding (text values, NULL as -1, quoting
      ;; characters as plain data)
      (let ((r (postgresql-execute conn "SELECT $1, $2, $3, $4"
                                   "a'b;--" 42 #f 2.5)))
        (check "execute-bind-echo"
          (equal? r (vector 'rows '("p1" "p2" "p3" "p4")
                            '(("a'b;--" "42" #f "2.5"))))))
      ;; non-finite floats must be spelled PostgreSQL's way on the wire
      (let ((r (postgresql-execute conn "SELECT $1, $2, $3"
                                   +inf.0 -inf.0 +nan.0)))
        (check "execute-nonfinite-spelling"
          (equal? (vector-ref r 2) '(("Infinity" "-Infinity" "NaN")))))
      ;; ...including an exact rational that overflows double on conversion
      (let ((r (postgresql-execute conn "SELECT $1, $2"
                                   (/ (expt 10 400) 3)
                                   (- (/ (expt 10 400) 3)))))
        (check "execute-exact-overflow-spelling"
          (equal? (vector-ref r 2) '(("Infinity" "-Infinity")))))
      ;; >65535 params: caller-side assertion, connection survives
      (check "param-overflow-is-callers-error"
        (guard (e ((not (and (vector? e)
                             (eq? (vector-ref e 0) 'postgresql-error)))
                   #t))
          (apply postgresql-execute conn "SELECT 1"
                 (vector->list (make-vector 65536 1)))
          #f))
      (let ((r (postgreconnpool-call conn "SELECT after-overflow")))
        (check "usable-after-param-overflow"
          (equal? r (vector 'rows '("a" "b") '(("42" #f))))))
      (postgreconnpool-close! conn))

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
      (postgreconnpool-close! conn))

    ;; 7. notices during auth are informational, not fatal
    (let ((conn (postgresql-connect "127.0.0.1" port "user" scram-password "notice")))
      (check "notice-during-auth-tolerated" #t)
      (postgreconnpool-close! conn))

    ;; 7b. A server that keeps the handshake alive forever with legal
    ;; notices must still be given up on -- BY THE WORKER.
    ;;
    ;; The caller's own timeout is not the thing under test: postgresql-connect
    ;; raises after connect-timeout-ms + 2 s whatever the worker does, so a
    ;; test that measured the caller passes against the bug. The worker never
    ;; reaches the adoption wait (that is after pool-up, which never comes), so
    ;; nothing else ended it: it ran, and held its socket, for the life of the
    ;; process. In a POOL, where no caller times out at all, it also held its
    ;; slot forever.
    ;;
    ;; So the assertion is on the worker: its process and its connection must
    ;; be gone. 'connect-deadline-ms is set short to keep the test quick.
    ;; settle first: an earlier case's connection still closing would drift
    ;; the baseline and mask exactly the one leaked worker being looked for
    (sleep-ms 1500)
    (let* ((base-conns (conn-count))
           (base-procs (process-count))
           (t0 (now-ms))
           (e (connect-error "127.0.0.1" port "user" scram-password "notice-forever"
                             '((connect-deadline-ms . 3000))))
           (caller-ms (- (now-ms) t0)))
      (check "trickling-notices-connect-fails" (and e #t))
      (display "  [info] caller gave up after ") (display caller-ms)
      (display " ms; worker deadline 3000 ms\n")
      ;; well past the deadline, so a bounded worker is certainly gone
      (sleep-ms 2000)
      (display "  [info] conns ") (display base-conns) (display " -> ")
      (display (conn-count)) (display ", processes ") (display base-procs)
      (display " -> ") (display (process-count)) (newline)
      ;; EQUAL, not <=: the leak is exactly one worker and one connection,
      ;; and a loose bound is what let this pass against the bug the first
      ;; time it was written
      (check "trickling-notices-releases-conn" (= (conn-count) base-conns))
      (check "trickling-notices-releases-worker"
        (= (process-count) base-procs)))

    ;; 7c. Killing the pool must take its connections with it.
    ;;
    ;; The pool monitors its connections; a monitor is one-directional, so
    ;; when the pool died every connection actor kept running with its fd
    ;; (and, over TLS, its session). Only an orderly pool-quit closed them,
    ;; and a pool that was killed never sends one. Recreating the pool then
    ;; stacked a second full set on top of the first.
    (sleep-ms 1500)
    (let ((base-conns (conn-count))
          (base-procs (process-count)))
      (let ((pool (postgresql-pool 2 "127.0.0.1" port "user" scram-password "scram")))
        ;; wait until both connections are actually up and serving
        (postgreconnpool-call pool "SELECT 1")
        (sleep-ms 500)
        (let ((busy-conns (conn-count)))
          (check "pool-connections-established" (> busy-conns base-conns))
          (kill pool 'reaped)
          (sleep-ms 1500)
          (display "  [info] conns ") (display base-conns) (display " -> ")
          (display busy-conns) (display " -> ") (display (conn-count))
          (display ", processes ") (display base-procs) (display " -> ")
          (display (process-count)) (newline)
          (check "killed-pool-releases-connections"
            (= (conn-count) base-conns))
          (check "killed-pool-releases-processes"
            (<= (process-count) base-procs)))))

    ;; 7d. A process that reconnects in a loop must not accumulate the late
    ;; up-reports of its own timed-out attempts.
    ;;
    ;; Each timed-out connect leaves its worker's #(pool-up ref ...) in this
    ;; mailbox. The ref is a fresh gensym per attempt, so it can never match
    ;; again: the message is immortal, and every selective receive afterwards
    ;; scans past all of them. connpool-call drains them, but a reconnect manager
    ;; or supervisor that only ever calls connect never ran one.
    ;;
    ;; Timing this proves nothing -- a handful of stale messages costs
    ;; microseconds to scan, and enough of them to measure would take
    ;; thousands of timed-out connects. So the stale message is PLANTED and
    ;; then looked for: exactly the shape a real one has, and its absence
    ;; afterwards is the drain, directly observed.
    (let ((planted (gensym)))
      (send self (vector 'pool-up planted self 'ok))
      (connect-error "127.0.0.1" port "user" scram-password "notice-forever"
                     '((connect-deadline-ms . 300)))
      (check "a connect drains an earlier attempt's late up-report"
        (eq? 'gone (receive (after 0 'gone) (`#(pool-up ,@planted ,p ,s) 'still-there)))))

    ;; 7e. Killing the pool must abort a query that is in FLIGHT, not only
    ;; free the connections that were idle.
    ;;
    ;; serve-loop watches for the owner's death between statements, but a
    ;; running query is not between statements: inside the wire loop only
    ;; TCP messages were matched, so against a server that keeps dripping
    ;; rows the old query, its fd and its TLS session outlived the pool --
    ;; and rebuilding the pool stacked a fresh set on top of them.
    (sleep-ms 1500)
    (let ((base-conns (conn-count)) (base-procs (process-count)) (me self))
      (let ((pool (postgresql-pool 1 "127.0.0.1" port "user" scram-password "scram")))
        (spawn (lambda ()
                 (guard (e (#t (send me (vector 'q 'failed))))
                   (postgreconnpool-call pool "DRIP forever")
                   (send me (vector 'q 'returned)))))
        (sleep-ms 800)
        (let ((busy (conn-count)))
          (check "the query is in flight" (> busy base-conns))
          (kill pool 'reaped)
          ;; the caller of the aborted query must be told, not left parked
          ;; for its own 60 s query timeout -- a process per killed pool
          (let ((outcome (receive (after 4000 'never-answered) (`#(q ,v) v))))
            (display "  [info] the in-flight caller: ") (display outcome) (newline)
            (check "the caller of an aborted query is answered"
              (memq outcome '(failed returned))))
          (sleep-ms 500)
          (display "  [info] conns ") (display base-conns) (display " -> ")
          (display busy) (display " -> ") (display (conn-count))
          (display ", processes ") (display base-procs) (display " -> ")
          (display (process-count)) (newline)
          (check "killing the pool aborts the running query"
            (= (conn-count) base-conns))
          (check "and leaves no process behind"
            (<= (process-count) base-procs)))))

    ;; 8. invalid message length -> clean transport error, not an assertion
    (let ((e (connect-error "127.0.0.1" port "user" "x" "badlen")))
      (check "invalid-length-clean-error"
        (and e (eq? (vector-ref e 1) 'transport)
             (string-contains? (vector-ref e 2) "invalid message length"))))

    ;; A malicious server cannot turn SCRAM authentication into minutes of
    ;; client-side PBKDF2 work by choosing an extreme iteration count.
    (let* ((started (now-ms))
           (e (connect-error "127.0.0.1" port "user" scram-password
                             "scram-cost"))
           (elapsed (- (now-ms) started)))
      (check "scram-iteration-cap"
        (and e (vector? e) (eq? (vector-ref e 1) 'transport)
             (string-contains? (vector-ref e 2) "malformed SCRAM server-first")
             (< elapsed 2000))))

    ;; 150 001 is over the shipped ceiling but well under a careless one,
    ;; so this is the case that fails if the default is ever raised toward
    ;; the libcrypto-calibrated number it was mistaken for.
    (check "scram-iteration-cap-default-is-tight"
      (let ((e (connect-error "127.0.0.1" port "user" scram-password
                              "scram-cost-mid")))
        (and e (vector? e) (eq? (vector-ref e 1) 'transport)
             (string-contains? (vector-ref e 2)
                               "malformed SCRAM server-first"))))

    ;; The ceiling has to come from the option, not just exist. Rejecting
    ;; an extreme count proves nothing on its own -- a ceiling stuck at
    ;; zero would pass that too. The ordinary SCRAM server above offers
    ;; 4096 and authenticates fine under the default, so lowering the
    ;; ceiling beneath it must turn that same exchange into a refusal, and
    ;; it costs no PBKDF2 to find out.
    (check "scram-iteration-cap-honours-the-option"
      (let ((e (connect-error "127.0.0.1" port "user" scram-password "scram"
                              '((scram-max-iters . 1000)))))
        (and e (vector? e) (eq? (vector-ref e 1) 'transport)
             (string-contains? (vector-ref e 2)
                               "malformed SCRAM server-first"))))

    ;; 9. passwords outside printable ASCII (SASLprep unimplemented):
    ;;    with SCRAM as the only possible path this is a CALLER-side
    ;;    assertion -- inside a pool a worker-side failure would be an
    ;;    invisible 1s retry loop -- and control characters are rejected
    ;;    too (SASLprep prohibits them)
    (let ((e (connect-error "127.0.0.1" port "user"
                            (string-append "p" (string (integer->char #xE4)) "ss")
                            "scram")))
      (check "non-ascii-password-caller-assertion"
        (and e (not (vector? e)) (condition? e))))
    (let ((e (connect-error "127.0.0.1" port "user"
                            (string-append "p" (string (integer->char 1)) "ss")
                            "scram")))
      (check "control-char-password-caller-assertion"
        (and e (not (vector? e)) (condition? e))))
    ;; with cleartext opted in the caller check defers -- the SCRAM
    ;; backstop still rejects when the server picks SCRAM anyway
    (let ((e (connect-error "127.0.0.1" port "user"
                            (string-append "p" (string (integer->char #xE4)) "ss")
                            "scram" '((allow-cleartext-auth . #t)))))
      (check "scram-backstop-rejects-non-ascii"
        (and e (vector? e) (eq? (vector-ref e 1) 'transport)
             (string-contains? (vector-ref e 2) "SASLprep"))))
    ;; an embedded NUL cannot ride a NUL-terminated PasswordMessage --
    ;; it would silently truncate server-side
    (let ((e (connect-error "127.0.0.1" port "user"
                            (string-append "p" (string #\nul) "w2")
                            "cleartext" '((allow-cleartext-auth . #t)))))
      (check "cleartext-nul-password-rejected"
        (and e (vector? e) (eq? (vector-ref e 1) 'transport)
             (string-contains? (vector-ref e 2) "NUL"))))

    ;; 10. server refusing TLS must fail the connection, never fall back to
    ;;    plaintext (the connector must not even be called)
    (let ((e (connect-error "127.0.0.1" port "user" "x" "scram"
                            (list (cons 'tls (lambda args
                                               (raise 'connector-called)))))))
      (check "tls-refusal-fails-hard"
        (and e (eq? (vector-ref e 1) 'transport)
             (string-contains? (vector-ref e 2) "refused TLS"))))

    (tcp-stop-listen!)
    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "postgresql-wire: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
