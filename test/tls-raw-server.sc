#!chezscheme
;;; tls-raw-server.sc -- a controllable TLS server for tests.
;;;
;;; The framework's listeners speak HTTP or the mesh protocol on their own;
;;; the cells that test a DIALER need the other end to be a server under the
;;; test's control: a chosen certificate and key, a handshake that can be
;;; held at the server's first flight and released later, and after the
;;; handshake plain send/recv under the caller's control. Each accepted
;;; connection is driven by its own green process using tls-core's session
;;; operations over a raw tcp-listen! connection, exactly as the raw client
;;; drives its side.
;;;
;;;   (raw-tls-server-start host port cert-path key-path opts) -> server
;;;       opts: alist; (hold-flight . #t) withholds the server's first
;;;       handshake flight until (raw-tls-server-release! server)
;;;   (raw-tls-server-accept server timeout-ms) -> session or 'timeout
;;;       (the session is established when this returns)
;;;   (raw-tls-server-release! server)          ; let held flights go
;;;   (raw-tls-server-cb-hash server)           ; -> the listen context's leaf hash
;;;   (raw-tls-session-send! s bytes) (raw-tls-session-recv! s ms) (raw-tls-session-close! s)
;;;   (raw-tls-session-send-raw! s bytes)       ; bytes on the wire as they are, no TLS framing
;;;   close! performs a TLS shutdown first (close_notify on the wire), then closes the socket
;;;   (raw-tls-server-stop! server)
(library (test tls-raw-server)
  (export raw-tls-server-start raw-tls-server-accept raw-tls-server-release! raw-tls-server-abort!
          raw-tls-server-cb-hash raw-tls-server-stop!
          raw-tls-session-send! raw-tls-session-send-raw! raw-tls-session-recv! raw-tls-session-close!)
  (import (chezscheme) (igropyr actor)
          (only (igropyr libuv) now-ms)
          (only (igropyr tcp) tcp-listen! tcp-stop-listen! tcp-read-start! tcp-write! tcp-close!
                conn-set-owner!)
          (only (igropyr tls-core)
                tls-listen-context! tls-context-retire! tls-session-new! tls-session-retire!
                tls-session-configure-server! tls-session-handshake-step!
                tls-session-drain! tls-session-feed! tls-session-encrypt!
                tls-session-decrypt! tls-context-cb-hash tls-session-shutdown!))

  (define-record-type server (fields ctx listener main (mutable hold?) (mutable held)))
  ;; a session lives in the process that accepted it; the test talks to it by message
  (define-record-type session (fields pid))

  (define (raw-tls-server-start host port cert key . opts)
    (let* ((o (if (pair? opts) (car opts) '()))
           (hold? (let ((p (assq 'hold-flight o))) (and p (cdr p))))
           (ctx (tls-listen-context! cert key))
           (main self)
           (srv (make-server ctx #f main hold? '())))
      (let ((l (tcp-listen! host port 16
                 (lambda (c)
                   (let ((p (spawn (lambda () (serve! srv c)))))
                     (conn-set-owner! c p)
                     (tcp-read-start! c))))))
        (make-server ctx l main hold? '()))))

  ;; the per-connection driver: handshake (optionally holding the first flight),
  ;; then a command loop for the test
  (define (serve! srv c)
    (let ((sess (tls-session-new! (server-ctx srv))) (main (server-main srv)))
      (define (flush!)
        (let ((out (tls-session-drain! sess)))
          (when out (tcp-write! c out #f))))
      (define (fail why) (tls-session-retire! sess "raw server done") (tcp-close! c) (send main (vector 'raw-server-failed why)))
      (let ((err (tls-session-configure-server! sess)))
        (if err (fail err)
            (let handshake ((held #f))
              (let-values (((verdict payload) (tls-session-handshake-step! sess)))
                (let ((out (tls-session-drain! sess)))
                  ;; the server's FIRST flight is the one a hold withholds
                  (cond
                    ((and out (server-hold? srv) (not held))
                     (send main (vector 'raw-server-holding self))
                     (receive
                       (`#(release-flight) (tcp-write! c out #f) (handshake #t))
                       ;; abort: close the socket mid-handshake without sending the flight
                       (`#(abort-flight) (fail "aborted while holding the first flight"))))
                    (out (tcp-write! c out #f))))
                (cond
                  ((eq? verdict 'gone) (fail payload))
                  ((eq? verdict 'done)
                   (send main (vector 'raw-server-session (make-session self)))
                   ;; application records that arrived in the same read as the
                   ;; client's last handshake flight are already in the read BIO:
                   ;; decrypt them now or they would wait for a read that never comes
                   (let-values (((out eof?) (tls-session-decrypt! sess (make-bytevector 0))))
                     (flush!)
                     (command-loop sess c main
                                   (if (and out (> (bytevector-length out) 0)) (list out) '())
                                   (and eof? #t))))
                  ((eq? verdict 'want-read)
                   (receive
                     (`#(tcp-data ,bv)
                       (let ((werr (tls-session-feed! sess bv)))
                         (if werr (fail (cdr werr)) (handshake held))))
                     (`#(tcp-eof) (fail "closed during handshake"))
                     (`#(tcp-error ,e) (fail "tcp error during handshake"))
                     (`#(release-flight) (handshake held))
                     (`#(abort-flight) (fail "aborted during handshake"))))
                  (else (fail (or payload "handshake failed"))))))))))

  (define (command-loop sess c main pending0 closed0)
    (define (flush!) (let ((out (tls-session-drain! sess))) (when out (tcp-write! c out #f))))
    (let loop ((pending pending0) (closed? closed0))
      (receive
        (`#(send ,bytes)
          (unless closed? (tcp-write! c (tls-session-encrypt! sess bytes) #f) (flush!))
          (loop pending closed?))
        (`#(send-raw ,bytes)
          ;; straight onto the socket: a malformed record, a truncated header,
          ;; anything the peer's TLS must reject or wait on
          (tcp-write! c bytes #f)
          (loop pending closed?))
        (`#(recv ,who ,ms)
          (cond
            ((pair? pending) (send who (vector 'recvd (bv-append-all pending))) (loop '() closed?))
            (closed? (send who (vector 'recvd 'closed)) (loop pending closed?))
            (else
              (receive (after ms (send who (vector 'recvd 'timeout)) (loop pending closed?))
                (`#(tcp-data ,bv)
                  (let-values (((out eof?) (tls-session-decrypt! sess bv)))
                    (flush!)
                    (cond
                      ((and out (> (bytevector-length out) 0)) (send who (vector 'recvd out)) (loop '() eof?))
                      (eof? (send who (vector 'recvd 'closed)) (loop '() #t))
                      (else (send self (vector 'recv who ms)) (loop '() closed?)))))
                (`#(tcp-eof) (send who (vector 'recvd 'closed)) (loop '() #t))
                (`#(tcp-error ,e) (send who (vector 'recvd 'closed)) (loop '() #t))))))
        (`#(tcp-data ,bv)
          (let-values (((out eof?) (tls-session-decrypt! sess bv)))
            (flush!)
            (loop (if (and out (> (bytevector-length out) 0)) (append pending (list out)) pending) (or closed? eof?))))
        (`#(tcp-eof) (loop pending #t))
        (`#(tcp-error ,e) (loop pending #t))
        (`#(close)
          ;; an authenticated close: close_notify goes out before the socket
          ;; closes, so the peer sees tcp-eof, not a cut
          (guard (e (#t (void))) (tls-session-shutdown! sess) (flush!))
          (tls-session-retire! sess "raw server closed")
          (tcp-close! c)))))

  (define (raw-tls-server-accept srv timeout-ms)
    (receive (after timeout-ms 'timeout)
      (`#(raw-server-session ,s) s)
      (`#(raw-server-failed ,why) (cons 'failed why))))
  (define (raw-tls-server-release! srv)
    ;; release every driver that reported a hold
    (let loop ()
      (receive (after 0 (void))
        (`#(raw-server-holding ,p) (send p (vector 'release-flight)) (loop)))))
  ;; the listen context's own leaf hash (RFC 5929 tls-server-end-point), or #f;
  ;; a cell that needs it must fail on #f rather than treat it as an empty binding
  ;; abort every driver that reported a hold: it closes its socket without
  ;; sending the flight, so the dialer sees a handshake broken by the peer
  (define (raw-tls-server-abort! srv)
    (let loop ()
      (receive (after 0 (void))
        (`#(raw-server-holding ,p) (send p (vector 'abort-flight)) (loop)))))
  (define (raw-tls-server-cb-hash srv) (tls-context-cb-hash (server-ctx srv)))
  (define (raw-tls-server-stop! srv)
    (when (server-listener srv) (tcp-stop-listen! (server-listener srv)))
    (tls-context-retire! (server-ctx srv)))

  (define (raw-tls-session-send! s bytes) (send (session-pid s) (vector 'send bytes)))
  (define (raw-tls-session-send-raw! s bytes) (send (session-pid s) (vector 'send-raw bytes)))
  (define (raw-tls-session-recv! s ms)
    (send (session-pid s) (vector 'recv self ms))
    (receive (`#(recvd ,x) x)))
  (define (raw-tls-session-close! s) (send (session-pid s) (vector 'close)))

  (define (bv-append-all l)
    (let* ((n (apply + (map bytevector-length l))) (out (make-bytevector n)))
      (let loop ((l l) (at 0))
        (if (null? l) out
            (begin (bytevector-copy! (car l) 0 out at (bytevector-length (car l)))
                   (loop (cdr l) (+ at (bytevector-length (car l)))))))))
)
