;;; test/tls-raw-client.sc -- a raw TLS client for the listener cells.
;;;
;;; Drives tls-core's session operations directly over a libuv connection so
;;; a cell can control what the existing http-client cannot: whether the
;;; client's Finished and its first application record travel in ONE socket
;;; write (H13/H20/Z14 -- "coalesced with the handshake"), or how many TLS
;;; records share one write (RL). It is test support: it lives here, not in
;;; tls-core, and it is the client side only.
;;;
;;; The premise every coalescing cell rests on is asserted by the driver
;;; itself: it counts its socket writes and returns the count, so a cell can
;;; check that Finished+A really went out as one write rather than assume it.
;;; (One client write is still not one server read -- TCP may split it -- so
;;; the server-side raw-read seam is the cell's second half; see the plan.)
;;;
;;; Trust: the client context reads SSL_CERT_FILE, exactly as (igropyr tls)
;;; does; the caller sets it to the test CA before calling.

(library (test tls-raw-client)
  (export raw-tls-exchange raw-tls-send-and-drop raw-tls-two-requests raw-tls-collect
          raw-tls-open raw-tls-send! raw-tls-recv! raw-tls-peer-cb-hash raw-tls-close! raw-tls-closed-by
          raw-tls-stall-then-collect raw-tls-slow-collect)
  (import (chezscheme)
          (igropyr actor)
          (only (igropyr libuv) now-ms) (only (igropyr tcp) tcp-connect! tcp-read-start! tcp-read-stop! tcp-write! tcp-close!)
          (only (igropyr tls-core)
                ensure-ctx! client-ctx tls-session-new! tls-session-retire!
                tls-session-configure-client! tls-session-handshake-step!
                tls-session-drain! tls-session-feed! tls-session-encrypt!
                tls-session-decrypt! tls-session-peer-cb-hash))

  (define (bv-append a b)
    (let ((r (make-bytevector (+ (bytevector-length a) (bytevector-length b)))))
      (bytevector-copy! a 0 r 0 (bytevector-length a))
      (bytevector-copy! b 0 r (bytevector-length a) (bytevector-length b))
      r))

  ;; Two requests on ONE connection (keep-alive): send A, wait until `expect`
  ;; bytes of plaintext have arrived, send B, wait for `expect` more (or eof /
  ;; timeout). -> (values plaintext writes failure). A listener that only
  ;; decrypts the read that completed the handshake answers A and ignores B.
  (define (raw-tls-two-requests host port sni req-a req-b expect timeout-ms)
    (let-values (((plain writes eof? failure)
                  (raw-tls-exchange host port sni req-a #f timeout-ms 'second req-b expect)))
      (values plain writes failure)))

  ;; Handshake, drain the post-handshake tickets, send the request, then close
  ;; the SOCKET without close_notify: a bare FIN right after a complete request,
  ;; with no unread bytes behind it (so it is a FIN, not a reset), the H11(b)
  ;; shape. -> writes | failure string
  (define (raw-tls-send-and-drop host port sni request timeout-ms)
    (let-values (((plain writes eof? failure)
                  (raw-tls-exchange host port sni request #f timeout-ms 'drop)))
      (or failure writes)))

  ;; Handshake, send the request, read to close_notify, then KEEP THE SOCKET
  ;; OPEN 500 ms and keep every raw byte: the cell that uses this looks for
  ;; bytes the server put on the wire AFTER retiring the session (RET').
  ;; -> (values plaintext raw-stream eof-cause) where raw-stream is every ciphertext
  ;; byte received on the socket, from the first server flight to the end of
  ;; the linger; the caller parses it as TLS records and judges the residue.
  ;; In 'collect mode the exchange's failure slot carries that bytevector.
  (define (raw-tls-collect host port sni request timeout-ms)
    (let-values (((plain writes eof? raw)
                  (raw-tls-exchange host port sni request #f timeout-ms 'collect)))
      (values plain (if (bytevector? raw) raw (make-bytevector 0)) eof?)))

  ;; Handshake, request, then STALL: reads stop until the caller (which knows
  ;; this process's pid) sends #(resume); afterwards every byte is collected.
  ;; -> (values plaintext raw-stream eof-cause); must run in its own process.
  (define (raw-tls-stall-then-collect host port sni request timeout-ms)
    (let-values (((plain writes eof? raw)
                  (raw-tls-exchange host port sni request #f timeout-ms 'stall)))
      (values plain (if (bytevector? raw) raw (make-bytevector 0)) eof?)))

  ;; Handshake, request, STALL until #(resume) (so the server's output has
  ;; queued), then read with a pause of pause-ms after every read callback (a
  ;; slow but progressing consumer); collects the raw stream.
  ;; -> (values plaintext raw-stream eof-cause)
  (define (raw-tls-slow-collect host port sni request timeout-ms pause-ms)
    (let-values (((plain writes eof? raw)
                  (raw-tls-exchange host port sni request #f timeout-ms 'slow pause-ms)))
      (values plain (if (bytevector? raw) raw (make-bytevector 0)) eof?)))

  ;; -> (values plaintext-received writes eof? failure)
  ;;   plaintext-received  every decrypted byte the server sent (bytevector)
  ;;   writes              number of socket writes this exchange performed
  ;;   eof?                #f, or WHY the exchange ended: 'close-notify (the
  ;;                       server's TLS alert was decrypted) | 'transport (bare
  ;;                       TCP EOF, no alert) -- callers that only need truth
  ;;                       may test it as a boolean
  ;;   failure             #f, or a string naming why the exchange stopped early
  ;; request  bytevector to send after the handshake
  ;; coalesce? when #t the request is encrypted BEFORE the handshake's final
  ;;          drain, so Finished and the request leave in one write
  ;; Must be called from inside an igropyr process (it receives tcp messages).
  (define (raw-tls-exchange host port sni request coalesce? timeout-ms . mode)
    (ensure-ctx!)
    (call/cc (lambda (k)
    (let ((writes 0) (deadline (+ (now-ms) timeout-ms)))
      (define (remaining) (max 1 (- deadline (now-ms))))
      (define (write! c bv) (set! writes (+ writes 1)) (tcp-write! c bv #f))
      (define (flush! sess c)
        (let ((out (tls-session-drain! sess))) (when out (write! c out))))
      (tcp-connect! host port self)
      (receive (after (remaining) (values (make-bytevector 0) writes #f "connect timeout"))
        (`#(tcp-connect-failed ,e) (values (make-bytevector 0) writes #f "connect failed"))
        (`#(tcp-connected ,c)
          (tcp-read-start! c)   ; reads are opt-in on a fresh conn
          (let ((sess (tls-session-new! (client-ctx))))
            ;; finish is a NON-LOCAL exit: every caller below would otherwise
            ;; fall through and keep driving a retired session (measured: the
            ;; first version did exactly that and read nothing until timeout)
            (define (finish plain eof? failure)
              (tls-session-retire! sess "raw client done")
              (tcp-close! c)
              (k plain writes eof? failure))
            (let ((err (tls-session-configure-client! sess sni)))
              (if err
                  (finish (make-bytevector 0) #f err)
                  (let handshake ()
                    (let-values (((verdict payload) (tls-session-handshake-step! sess)))
                      (cond
                        ((eq? verdict 'gone) (finish (make-bytevector 0) #f payload))
                        ((eq? verdict 'done)
                         ;; the coalescing point: encrypt before the final drain
                         ;; encrypt! drains the write BIO itself and RETURNS THE
                         ;; CIPHERTEXT (http-client writes that value); it raises on
                         ;; failure. Coalescing = take the pending Finished out of the
                         ;; BIO first, encrypt the request, and write both as ONE
                         ;; socket write.
                         (if coalesce?
                             (let* ((fin (or (tls-session-drain! sess) (make-bytevector 0)))
                                    (app (tls-session-encrypt! sess request)))
                               (write! c (bv-append fin app)))
                             (begin
                               (flush! sess c)
                               ;; 'drop only: the server answers our Finished with
                               ;; TLS 1.3 session tickets. Read them out (200 ms of
                               ;; silence) BEFORE the request goes, so the socket is
                               ;; empty when it is closed below: closing with unread
                               ;; bytes makes the kernel send RST instead of FIN and
                               ;; the server records read-error -54, not the truncation
                               ;; this shape exists to produce (seen 1 run in 4).
                               (when (and (pair? mode) (eq? (car mode) 'drop))
                                 (let drain ()
                                   (receive (after 200 (void))
                                     (`#(tcp-data ,bv) (tls-session-decrypt! sess bv) (flush! sess c) (drain))
                                     (`#(tcp-eof) (finish (make-bytevector 0) 'transport "closed before the request"))
                                     (`#(tcp-error ,e) (finish (make-bytevector 0) #f "tcp error")))))
                               (write! c (tls-session-encrypt! sess request))))
                         ;; 'drop: bare FIN right after the request, no close_notify,
                         ;; nothing read after it. The caller keeps the server from
                         ;; answering before the FIN lands (a slow handler); the
                         ;; tickets were drained above, so the close is a FIN.
                         (when (and (pair? mode) (eq? (car mode) 'drop))
                           (finish (make-bytevector 0) #f #f))
                         ;; 'stall: stop reading right after the request and hold the socket
                         ;; open until the test sends #(resume) -- the server's output queues
                         ;; behind a closed receive window (the close-drain cells' stimulus).
                         ;; Reads resume on #(resume) and the exchange continues in collect
                         ;; mode. A stall that nobody resumes ends by the exchange's deadline.
                         (when (and (pair? mode) (memq (car mode) '(stall slow)))
                           (tcp-read-stop! c)
                           (receive (after (remaining) (finish (make-bytevector 0) #f "stalled and never resumed"))
                             (`#(resume) (tcp-read-start! c))))
                         ;; read until eof or timeout; in 'second mode send B once
                         ;; `expect` plaintext bytes have arrived and stop at 2x
                         (let-values (((port get) (open-bytevector-output-port))
                                      ((rport rget) (open-bytevector-output-port)))
                           (let ((second (and (pair? mode) (eq? (car mode) 'second) mode)) (got 0) (sent-b? #f)
                                 (collect? (and (pair? mode) (memq (car mode) '(collect stall slow))))
                                 (slow-ms (and (pair? mode) (eq? (car mode) 'slow) (cadr mode))))
                           ;; 'collect: after close_notify keep reading raw bytes for
                           ;; 500 ms of silence, then hand the whole raw stream back
                           (define (linger-then-finish)
                             (let linger ()
                               (receive (after 500 (finish (get) 'close-notify (rget)))
                                 (`#(tcp-data ,bv) (put-bytevector rport bv) (linger))
                                 (`#(tcp-eof) (finish (get) 'close-notify (rget)))
                                 (`#(tcp-error ,e) (finish (get) 'close-notify (rget))))))
                           (let read-loop ()
                             (receive (after (remaining) (finish (get) #f #f))
                               (`#(tcp-data ,bv)
                                 (when collect? (put-bytevector rport bv))
                                 ;; 'slow: a reader that pauses after every read (a slow consumer)
                                 (when slow-ms (sleep-ms slow-ms))
                                 ;; decrypt! feeds the ciphertext itself (as establish! relies on);
                                 ;; feeding first would enter every byte twice
                                 (let-values (((out eof?) (tls-session-decrypt! sess bv)))
                                   (when out (put-bytevector port out) (set! got (+ got (bytevector-length out))))
                                   (flush! sess c)
                                   (cond
                                     ((and eof? collect?) (linger-then-finish))
                                     (eof? (finish (get) 'close-notify #f))
                                     ((and second (not sent-b?) (>= got (caddr second)))
                                      (set! sent-b? #t)
                                      (write! c (tls-session-encrypt! sess (cadr second)))
                                      (read-loop))
                                     ((and second sent-b? (>= got (* 2 (caddr second)))) (finish (get) #f #f))
                                     (else (read-loop)))))
                               (`#(tcp-eof) (finish (get) 'transport (and collect? (rget))))
                               (`#(tcp-error ,e) (finish (get) #f "tcp error")))))))
                        ((eq? verdict 'want-read)
                         (flush! sess c)
                         (receive (after (remaining) (finish (make-bytevector 0) #f "handshake timeout"))
                           (`#(tcp-data ,bv)
                             (let ((ferr (tls-session-feed! sess bv)))
                               (if ferr (finish (make-bytevector 0) #f (cdr ferr)) (handshake))))
                           (`#(tcp-eof) (finish (make-bytevector 0) #f "closed during handshake"))
                           (`#(tcp-error ,e) (finish (make-bytevector 0) #f "tcp error during handshake"))))
                        (else (finish (make-bytevector 0) #f (or payload "handshake failed")))))))))))))))
  ;; ---- Interactive session -------------------------------------------------
  ;; The exchanges above are one-shot: request bytes in, everything until eof
  ;; out. A handshake that goes challenge -> hello -> welcome needs the caller
  ;; in the loop: connect and complete TLS, then send and receive under the
  ;; caller's control, keep the connection open between steps, tell a timeout
  ;; from a closure, and expose the certificate the server presented (its RFC
  ;; 5929 hash) so a test can compute channel-bound proofs independently.
  ;; All of it runs in the calling process, like establish!: reads arrive as
  ;; #(tcp-data ...) messages and are decrypted here.
  ;;   (raw-tls-open host port sni timeout-ms) -> session or (cons 'failed why)
  ;;   (raw-tls-send! s bytes)                  ; plaintext in, ciphertext out
  ;;   (raw-tls-recv! s timeout-ms)             ; -> plaintext bytevector (maybe empty),
  ;;                                            ;    'timeout, or 'closed (eof/close_notify/error)
  ;;   (raw-tls-peer-cb-hash s)                 ; -> bytevector or #f
  ;;   (raw-tls-close! s)
  ;; closed? = the PEER ended the stream (close_notify / eof / error);
  ;; released? = this side retired the session and closed the socket. They
  ;; are different facts: a peer-closed session still holds an SSL object
  ;; and an open handle until raw-tls-close! runs, and its connection can
  ;; still deliver #(tcp-eof) into the caller's mailbox -- where a later
  ;; raw-tls-open would mistake it for its own handshake ending.
  (define-record-type raw-tls-session
    (fields conn sess (mutable pending) (mutable closed?) (mutable released?) (mutable closed-by)))
  (define (raw-tls-open host port sni timeout-ms)
    (ensure-ctx!)
    (let ((deadline (+ (now-ms) timeout-ms)))
      (define (remaining) (max 1 (- deadline (now-ms))))
      (tcp-connect! host port self)
      (receive (after (remaining) (cons 'failed "connect timeout"))
        (`#(tcp-connect-failed ,e) (cons 'failed "connect failed"))
        (`#(tcp-connected ,c)
          (tcp-read-start! c)
          (let ((sess (tls-session-new! (client-ctx))))
            (define (fail why) (tls-session-retire! sess "raw session failed") (tcp-close! c) (cons 'failed why))
            (define (flush!) (let ((out (tls-session-drain! sess))) (when out (tcp-write! c out #f))))
            (let ((err (tls-session-configure-client! sess sni)))
              (if err
                  (fail err)
                  (let handshake ()
                    (let-values (((verdict payload) (tls-session-handshake-step! sess)))
                      (flush!)
                      (cond
                        ((eq? verdict 'gone) (fail payload))
                        ((eq? verdict 'done)
                         ;; records coalesced with the server's last flight are in the
                         ;; read BIO already; take them now (see the server fixture)
                         (let-values (((out eof?) (tls-session-decrypt! sess (make-bytevector 0))))
                           (flush!)
                           (make-raw-tls-session c sess
                                                 (if (and out (> (bytevector-length out) 0)) (list out) '())
                                                 (and eof? #t) #f (and eof? 'close-notify))))
                        ((eq? verdict 'want-read)
                         (receive (after (remaining) (fail "handshake timeout"))
                           (`#(tcp-data ,bv)
                             (let ((werr (tls-session-feed! sess bv)))
                               (if werr (fail (cdr werr)) (handshake))))
                           (`#(tcp-eof) (fail "closed during handshake"))
                           (`#(tcp-error ,e) (fail "tcp error during handshake"))))
                        (else (fail (or payload "handshake failed")))))))))))))
  (define (raw-tls-send! s bytes)
    (unless (or (raw-tls-session-closed? s) (raw-tls-session-released? s))
      (let ((sess (raw-tls-session-sess s)) (c (raw-tls-session-conn s)))
        (tcp-write! c (tls-session-encrypt! sess bytes) #f)
        (let ((out (tls-session-drain! sess))) (when out (tcp-write! c out #f))))))
  ;; -> plaintext received within timeout-ms (possibly several records joined),
  ;; 'timeout when nothing arrived, 'closed once the peer closed (close_notify,
  ;; eof or error). Bytes decrypted after a close are still returned first.
  (define (raw-tls-recv! s timeout-ms)
    (cond
      ((pair? (raw-tls-session-pending s))
       (let ((p (raw-tls-session-pending s))) (raw-tls-session-pending-set! s '()) (bv-append-all p)))
      ((raw-tls-session-closed? s) 'closed)
      (else
        (let ((sess (raw-tls-session-sess s)) (c (raw-tls-session-conn s)))
          (define (flush!) (let ((out (tls-session-drain! sess))) (when out (tcp-write! c out #f))))
          (receive (after timeout-ms 'timeout)
            (`#(tcp-data ,bv)
              (let-values (((out eof?) (tls-session-decrypt! sess bv)))
                (flush!)
                (when eof? (raw-tls-session-closed?-set! s #t) (raw-tls-session-closed-by-set! s 'close-notify))
                (cond
                  ((and out (> (bytevector-length out) 0)) out)
                  (eof? 'closed)
                  (else (raw-tls-recv! s timeout-ms)))))
            (`#(tcp-eof) (raw-tls-session-closed?-set! s #t) (unless (raw-tls-session-closed-by s) (raw-tls-session-closed-by-set! s 'transport)) 'closed)
            (`#(tcp-error ,e) (raw-tls-session-closed?-set! s #t) (unless (raw-tls-session-closed-by s) (raw-tls-session-closed-by-set! s 'transport)) 'closed))))))
  ;; -> 'close-notify | 'transport | #f (still open): how the peer ended the stream
  (define (raw-tls-closed-by s) (raw-tls-session-closed-by s))
  (define (raw-tls-peer-cb-hash s) (tls-session-peer-cb-hash (raw-tls-session-sess s)))
  ;; ALWAYS retire and close, whether or not the peer closed first: the
  ;; SSL object and the handle are ours to release, and the socket must be
  ;; closed so no late #(tcp-eof) from it reaches the caller's mailbox.
  (define (raw-tls-close! s)
    (unless (raw-tls-session-released? s)
      (raw-tls-session-released?-set! s #t)
      (raw-tls-session-closed?-set! s #t)
      (tls-session-retire! (raw-tls-session-sess s) "raw session closed")
      (tcp-close! (raw-tls-session-conn s))))
  (define (bv-append-all l)
    (let* ((n (apply + (map bytevector-length l))) (out (make-bytevector n)))
      (let loop ((l l) (at 0))
        (if (null? l) out
            (begin (bytevector-copy! (car l) 0 out at (bytevector-length (car l)))
                   (loop (cdr l) (+ at (bytevector-length (car l)))))))))
)
