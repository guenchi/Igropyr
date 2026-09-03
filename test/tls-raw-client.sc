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
  (export raw-tls-exchange raw-tls-send-and-drop raw-tls-two-requests raw-tls-collect)
  (import (chezscheme)
          (igropyr actor)
          (only (igropyr libuv) tcp-connect! tcp-read-start! tcp-write! tcp-close! now-ms)
          (only (igropyr tls-core)
                ensure-ctx! client-ctx tls-session-new! tls-session-retire!
                tls-session-configure-client! tls-session-handshake-step!
                tls-session-drain! tls-session-feed! tls-session-encrypt!
                tls-session-decrypt!))

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
                         ;; read until eof or timeout; in 'second mode send B once
                         ;; `expect` plaintext bytes have arrived and stop at 2x
                         (let-values (((port get) (open-bytevector-output-port))
                                      ((rport rget) (open-bytevector-output-port)))
                           (let ((second (and (pair? mode) (eq? (car mode) 'second) mode)) (got 0) (sent-b? #f)
                                 (collect? (and (pair? mode) (eq? (car mode) 'collect))))
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
                        (else (finish (make-bytevector 0) #f (or payload "handshake failed"))))))))))))))))
