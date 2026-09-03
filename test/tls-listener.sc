;;; test/tls-listener.sc -- the HTTPS listener (stage 2b), first tranche.
;;;
;;; Cells from the converged plan (archive/igropyr-scratch-2026-09-02/
;;; tls-listener-cells-v11.md and its deltas). This tranche holds the rows
;;; that need neither inject-barrier! nor inject-yield!; the race rows
;;; (RET, GATE(c), Z14, AGG(a)/(b), SER x3, Z6a) are red-listed until those
;;; batches land and are NOT claimed here.
;;;
;;; Every cell reads the instrumented seams before and after, so "back to
;;; baseline" is asserted with the baseline printed on failure. The listener
;;; is real (http-listen with tls-cert/tls-key); clients are the framework's
;;; http-client over TLS, the raw driver (test/tls-raw-client.sc), and raw
;;; TCP for the pre-handshake cases.
;;;
;;; Requires IGROPYR_INJECT=on (seams) and the openssl CLI (test/tls-certs.sh).

(import (chezscheme)
        (igropyr actor) (igropyr libuv) (igropyr http) (igropyr http-client) (igropyr tls)
        (igropyr inject-control) (igropyr inject)
        (only (igropyr libuv) conn-tls-retire! tls-conn-totals tls-eof-deliveries)
        (only (igropyr tls-core) tls-live-session-count tls-live-context-count tls-live-listener-context-count)
        (test tls-raw-client))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))
(define (now-ms) (let ((t (current-time))) (+ (* 1000 (time-second t)) (div (time-nanosecond t) 1000000))))

(define dir "/tmp/igropyr-tls-listener-test")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))
(define (in-dir f) (string-append dir "/" f))
(define port 18480)
(define plain-port 18481)

;; a snapshot of the live-resource seams, compared as a whole
(define (snap)
  (list (cons 'sessions (tls-live-session-count))
        (cons 'watchers (tls-live-watcher-count))
        (cons 'live-timers (tls-live-timer-count))
        (cons 'active-timers (tls-active-timer-count))
        (cons 'handshaking (tls-handshaking-count))
        (cons 'handles (uv-live-handle-count))))
;; wait until the resource seams return to a baseline, bounded
(define (settled-to? base ms)
  (let ((deadline (+ (now-ms) ms)))
    (let loop ()
      (cond ((equal? (snap) base) #t)
            ((> (now-ms) deadline) #f)
            (else (sleep-ms 50) (loop))))))

(define (handler req res) (res-send! res (string->utf8 "ok-over-tls")))
(define (bv . xs) (string->utf8 (apply string-append xs)))
(define GET (bv "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))

;; raw TCP client: connect, optionally send bytes, then wait for eof/error or a deadline
;; -> 'eof | 'error | 'timeout, the ms it took, and the first bytes received (or #f)
(define (raw-tcp-probe port bytes wait-ms)
  (tcp-connect! "127.0.0.1" port self)
  (receive (after 3000 (values 'connect-timeout 0))
    (`#(tcp-connect-failed ,e) (values 'connect-failed 0))
    (`#(tcp-connected ,c)
      (tcp-read-start! c)
      (when bytes (tcp-write! c bytes #f))
      (let ((t0 (now-ms)) (first #f))
        (let loop ()
          (receive (after (max 1 (- (+ t0 wait-ms) (now-ms))) (tcp-close! c) (values 'timeout (- (now-ms) t0) first))
            (`#(tcp-data ,d) (unless first (set! first d)) (loop))
            (`#(tcp-eof) (tcp-close! c) (values 'eof (- (now-ms) t0) first))
            (`#(tcp-error ,e) (tcp-close! c) (values 'error (- (now-ms) t0) first))))))))

(define big (make-bytevector (* 4 1024 1024) 65))
(define (file-symbols path)
  (let ((p (open-input-file path)))
    (let loop ((acc '()))
      (let ((x (read p)))
        (if (eof-object? x) (begin (close-port p) acc)
            (loop (let walk ((x x) (acc acc))
                    (cond ((symbol? x) (cons x acc))
                          ((pair? x) (walk (cdr x) (walk (car x) acc)))
                          ((vector? x) (let vl ((i 0) (acc acc)) (if (= i (vector-length x)) acc (vl (+ i 1) (walk (vector-ref x i) acc)))))
                          (else acc)))))))))

(define (s-client out extra-flags hold-secs . keepalive)
  ;; keepalive: omit Connection: close so the SERVER does not close first
  (system (string-append "((printf 'GET / HTTP/1.1\\r\\nHost: localhost\\r\\n" (if (null? keepalive) "Connection: close\\r\\n" "") "\\r\\n'; sleep " (number->string hold-secs) ") | timeout 8 openssl s_client -quiet " extra-flags " -connect 127.0.0.1:" (number->string port) " -CAfile " (in-dir "ca.pem") " > " out " 2>/dev/null) &")))
(define (slurp path) (guard (e (#t "")) (utf8->string (call-with-port (open-file-input-port path) get-bytevector-all))))

(define (bv-append* bvs)
  (let* ((n (apply + (map bytevector-length bvs))) (r (make-bytevector n)))
    (let loop ((bvs bvs) (i 0))
      (if (null? bvs) r
          (begin (bytevector-copy! (car bvs) 0 r i (bytevector-length (car bvs)))
                 (loop (cdr bvs) (+ i (bytevector-length (car bvs)))))))))
(define (contains? txt needle)
  (let ((n (string-length needle)) (m (string-length txt)))
    (let loop ((i 0)) (cond ((> (+ i n) m) #f) ((string=? (substring txt i (+ i n)) needle) #t) (else (loop (+ i 1)))))))

(start-scheduler
  (lambda ()
    (define ctx-base (tls-live-listener-context-count))   ; listener contexts only: the client singleton never retires
    (define srv (http-listen port handler
                  (list (cons 'host "127.0.0.1") (cons 'workers 2)
                        (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key")))))
    (define plain (http-listen plain-port handler (list (cons 'host "127.0.0.1") (cons 'workers 1))))
    (define base #f)
    (sleep-ms 200)
    (set! base (snap))
    (display (list 'baseline base)) (newline)

    ;; ---- CTX: the listener owns exactly one context
    (check "CTX: starting a TLS listener created exactly one listener context" (= (tls-live-listener-context-count) (+ ctx-base 1)) (tls-live-listener-context-count) ctx-base)

    ;; ---- H1: the framework's client over https gets 200 and the handler's body
    (tls-enable!)
    (let ((r (guard (e (#t #f)) (http-get (string-append "https://127.0.0.1:" (number->string port) "/") '((timeout . 5000))))))
      (check "H1: https GET through the client answers 200" (and r (= (response-status r) 200)) (and r (response-status r)))
      (check "H1: with the handler's body" (and r (equal? (response-body r) (string->utf8 "ok-over-tls"))) (and r (response-body r))))
    ;; the client pools the connection (one client-side session, one
    ;; server-side session, a watcher and a timer stay alive by design);
    ;; close the idle pool before asking for the baseline
    (http-client-close-idle!)
    (check "H1: resources back to baseline once the pooled connection is closed" (settled-to? base 3000) (snap) base)

    ;; ---- H13: request coalesced with the client's Finished (ONE write) is answered
    (let-values (((plain writes eof? fail) (raw-tls-exchange "127.0.0.1" port "localhost" GET #t 5000)))
      (check "H13: premise -- Finished and the request left in one socket write (2 writes total)" (= writes 2) writes)
      (check "H13: the coalesced request was answered" (and (not fail) (> (bytevector-length plain) 0)) fail (bytevector-length plain))
      (check "H13: and the response is the handler's" (let ((s (and (> (bytevector-length plain) 0) (utf8->string plain)))) (and s (let loop ((i 0)) (cond ((> (+ i 11) (string-length s)) #f) ((string=? (substring s i (+ i 11)) "ok-over-tls") #t) (else (loop (+ i 1))))))) plain))
    (check "H13: resources back to baseline" (settled-to? base 3000) (snap) base)

    ;; ---- H2: plaintext GET to the TLS port is closed, no handler ran, sessions to baseline
    (let ((completions-before (tls-accept-callback-completions)))
      (let-values (((how ms first) (raw-tcp-probe port GET 4000)))
        (check "H2: a plaintext request on the TLS port is closed (eof or error), not answered" (memq how '(eof error)) how ms)
        (check "H2: no upper callback ran for it (acceptor completions unchanged)" (= (tls-accept-callback-completions) completions-before) (tls-accept-callback-completions) completions-before)
        (check "H2: resources back to baseline" (settled-to? base 3000) (snap) base)))

    ;; ---- H2': a TLS ClientHello on the PLAINTEXT listener is closed by the
    ;; reader's read timeout (a ClientHello carries no CRLF, so the request
    ;; line never completes); it must not be answered and must not hang past
    ;; that timeout (30 s; there is no setter, so the probe waits it out --
    ;; the same 30 s idle-close.sc already spends).
    (let-values (((how ms first) (raw-tcp-probe plain-port (bytevector 22 3 1 0 5 1 0 0 1 3) 36000)))
      (check "H2': a ClientHello on the plaintext listener is closed at the read timeout (30 s), not answered, not held longer" (and (memq how '(eof error)) (>= ms 29000) (<= ms 33000)) how ms))

    ;; ---- H3: client disconnects mid-handshake -> sessions, timers, handles to baseline
    (let-values (((how ms first) (raw-tcp-probe port (bytevector 22 3 1 0 5 1 0 0 1 3) 300)))
      (check "H3: mid-handshake disconnect -> resources back to baseline" (settled-to? base 3000) (snap) base))

    ;; ---- H9: connect and send nothing -> closed at tls-handshake-ms, not before; baseline after
    (tls-handshake-ms-set! 1500)
    (let-values (((how ms first) (raw-tcp-probe port #f 5000)))
      (check "H9: a silent client is closed by the server" (memq how '(eof error)) how ms)
      (check "H9: at the handshake deadline (1500 ms), not before and not much after" (and (>= ms 1400) (<= ms 2600)) ms)
      (check "H9: resources back to baseline" (settled-to? base 3000) (snap) base))
    (tls-handshake-ms-set! 10000)

    ;; ---- H10: a raise before publication retires the session, closes the handle, no row
    (inject-arm-fault! 'tls-accept-before-publish 1)
    (let-values (((how ms first) (raw-tcp-probe port (bytevector 22 3 1 0 5 1 0 0 1 3) 2000)))
      (let ((hits (inject-hits 'tls-accept-before-publish)))
        (inject-disarm!)
        (check "H10: the pre-publication point was hit once" (eqv? hits 1) hits)
        (check "H10: the client saw the connection go away" (memq how '(eof error)) how ms)
        (check "H10: resources back to baseline (session retired, handle closed)" (settled-to? base 3000) (snap) base)
        (check "H10: the retirement was recorded as pre-publication"
               (let ((r (tls-last-retire-reason))) (and (pair? r) (eq? (car r) 'pre-publication))) (tls-last-retire-reason))))

    ;; ---- H5: a 4 MB response round-trips intact (many TLS records, many chunks)
    (http-swap! srv (lambda (req res) (res-send! res big)))
    (let ((r (guard (e (#t #f)) (http-get (string-append "https://127.0.0.1:" (number->string port) "/big") '((timeout . 15000) (max-response . 8388608))))))
      (check "H5: a 4 MB response arrives with status 200" (and r (= (response-status r) 200)) (and r (response-status r)))
      (check "H5: intact -- exact length and content" (and r (equal? (response-body r) big)) (and r (bytevector-length (response-body r)))))
    (http-client-close-idle!)
    (check "H5: resources back to baseline" (settled-to? base 3000) (snap) base)
    (http-swap! srv handler)

    ;; ---- H19v: a raise inside the watcher (at 'tls-watcher-delay, which RAISES
    ;; when armed -- inject-fault! has no "park") aborts the connection: no
    ;; answer, the gate never opens for it, resources back to baseline.
    ;; H18 proper (the watcher merely delayed, plaintext waiting for it) needs
    ;; a park and is red-listed until the barrier batch.
    (let ((opens-before (car (tls-gate-open-mark))))
      (inject-arm-fault! 'tls-watcher-delay 1)
      (let-values (((plain writes eof? fail) (raw-tls-exchange "127.0.0.1" port "localhost" GET #t 6000)))
        (let ((hits (inject-hits 'tls-watcher-delay)))
          (inject-disarm!)
          (check "H19v: the watcher point was hit once" (eqv? hits 1) hits)
          (check "H19v: the connection was aborted -- no answer" (= (bytevector-length plain) 0) (bytevector-length plain))
          (check "H19v: the gate never opened for it" (= (car (tls-gate-open-mark)) opens-before) (tls-gate-open-mark) opens-before))))
    (check "H19v: resources back to baseline" (settled-to? base 3000) (snap) base)

    ;; ---- H11: close_notify vs bare FIN, seen by the server
    ;; ⚠ (system …) blocks the single scheduler thread for its whole duration,
    ;; so a foreground s_client would starve the very server it talks to
    ;; (measured: nothing arrived until timeout killed it -- a bare FIN).
    ;; The client is started in the background and the test sleeps in the
    ;; scheduler while the exchange happens.
    ;; (a) -ign_eof: the client stays until the server closes; the server closes
    ;;     cleanly (close_notify) after the response -> clean-close recorded
    (let ((out (in-dir "h11a.out")))
      (s-client out "-ign_eof" 3)
      (sleep-ms 2500)
      (let ((txt (slurp out)))
        (check "H11(a): s_client (waits for the server's close) got the response" (and (> (string-length txt) 0) (let loop ((i 0)) (cond ((> (+ i 11) (string-length txt)) #f) ((string=? (substring txt i (+ i 11)) "ok-over-tls") #t) (else (loop (+ i 1)))))) txt)
        (check "H11(a): the retirement was a clean close" (let ((r (tls-last-retire-reason))) (and (pair? r) (eq? (car r) 'clean-close))) (tls-last-retire-reason))))
    (check "H11(a): resources back to baseline" (settled-to? base 4000) (snap) base)
    ;; (b) a BARE FIN right after a complete request (the raw driver closes the
    ;;     socket without close_notify; s_client cannot do this -- it shuts down
    ;;     cleanly on stdin eof) -> the server records the truncation, never a
    ;;     clean close
    ;; The handler is slowed so the FIN reaches the server while the request is
    ;; still in flight: with the default handler the response (Connection: close)
    ;; and the server's own clean close can win the race and clean-close is what
    ;; gets recorded -- a different shape, not this cell's.
    (http-swap! srv (lambda (req res) (sleep-ms 800) (guard (e (#t #f)) (res-send! res (string->utf8 "late")))))
    (let ((r (raw-tls-send-and-drop "127.0.0.1" port "localhost" GET 5000)))
      (check "H11(b): premise -- the request went out before the bare FIN" (and (number? r) (>= r 2)) r)
      (sleep-ms 1500)
      (http-swap! srv handler)
      (check "H11(b): a bare FIN is recorded as truncation, never as a clean close"
             (let ((r (tls-last-retire-reason))) (and (pair? r) (eq? (car r) 'truncated-eof))) (tls-last-retire-reason)))
    (check "H11(b): resources back to baseline" (settled-to? base 4000) (snap) base)

    ;; ---- STRUCT / ARCH: the rules that are text, checked as parsed forms
    (let ((tls-syms (file-symbols "igropyr/tls.sc")))
      (check "ARCH: (igropyr tls) references no OpenSSL entry point or loader (parsed symbols)"
             (not (exists (lambda (s) (let ((n (symbol->string s))) (or (and (> (string-length n) 4) (member (substring n 0 4) '("SSL_" "BIO_" "EVP_" "OBJ_" "ERR_"))) (and (> (string-length n) 5) (string=? (substring n 0 5) "X509_")) (member n '("libssl" "libcrypto"))))) tls-syms))))
    (let ((watch-syms (file-symbols "igropyr/tls-watch.sc")) (uv-syms (append (file-symbols "igropyr/uv.sc") (file-symbols "igropyr/tcp.sc"))))
      ;; positive control: an absence check over a source file is only as good
      ;; as its search surface. When libuv.sc became an 81-line facade the two
      ;; checks below would have stayed green forever; this line reds instead.
      (check "STRUCT: control -- the search surface is real (conn-tls-retire! in tcp.sc, tls-watch-install! in tls-watch.sc)"
             (and (memq 'conn-tls-retire! uv-syms) (memq 'tls-watch-install! watch-syms) #t))
      (check "STRUCT: no #(watching) message anywhere" (and (not (memq 'watching watch-syms)) (not (memq 'watching uv-syms))))
      (check "STRUCT: no 'tls-after-owner-installed point" (and (not (memq 'tls-after-owner-installed watch-syms)) (not (memq 'tls-after-owner-installed uv-syms)))))

    ;; ---- H16': a clean close requested while the holder is mid-aggregate (v9):
    ;; the IN-FLIGHT aggregate completes, later writes are refused (not hung),
    ;; and then the connection closes cleanly. http sends a 4 MB body as several
    ;; writes, so the client sees a prefix -- at least one whole aggregate --
    ;; and a clean close, never a hang. The handler reports how res-send! ended.
    (let ((me self))
      (http-swap! srv (lambda (req res)
                        (let ((c (res-conn res)))
                          (spawn (lambda () (tcp-close! c)))
                          (let ((outcome (guard (e (#t (list 'raised (if (condition? e) (condition-message e) e))))
                                           (res-send! res big) 'returned)))
                            (send me (vector 'h16 outcome)))))))
    (let-values (((plain writes eof? fail) (raw-tls-exchange "127.0.0.1" port "localhost" GET #f 15000)))
      (let ((outcome (receive (after 6000 'no-report) (`#(h16 ,o) o))))
        (check "H16': the handler's write completed (returned or refused), did not hang" (not (eq? outcome 'no-report)) outcome)
        (check "H16': the client received at least one whole aggregate before the close" (> (bytevector-length plain) 0) (bytevector-length plain))
        (check "H16': then the connection closed cleanly (eof seen, clean-close recorded)"
               (and eof? (let ((r (tls-last-retire-reason))) (and (pair? r) (eq? (car r) 'clean-close)))) eof? (tls-last-retire-reason))))
    (check "H16': resources back to baseline" (settled-to? base 4000) (snap) base)

    ;; ---- ABORT-CB: an application write cut short by a hard retirement must
    ;; complete its caller with an error, exactly once, never hang. The handler
    ;; reports what res-send! did to the test process.
    (let ((me self))
      (http-swap! srv (lambda (req res)
                        (let ((c (res-conn res)))
                          (spawn (lambda () (conn-tls-retire! c 'test-abort "tls: aborted by the cell")))
                          (let ((outcome (guard (e (#t (list 'raised (if (condition? e) (condition-message e) e))))
                                           (res-send! res big) 'returned)))
                            (send me (vector 'abort-cb outcome)))))))
    (let-values (((plain writes eof? fail) (raw-tls-exchange "127.0.0.1" port "localhost" GET #f 8000)))
      (let ((outcome (receive (after 6000 'no-report) (`#(abort-cb ,o) o))))
        (check "ABORT-CB: the interrupted write completed its caller (returned or raised), did not hang" (not (eq? outcome 'no-report)) outcome)
        (check "ABORT-CB: the client saw the connection go away, not a full body" (< (bytevector-length plain) (bytevector-length big)) (bytevector-length plain))))
    (check "ABORT-CB: resources back to baseline" (settled-to? base 4000) (snap) base)

    ;; ---- REFUND: a raise between two chunks (injected) must leave the
    ;; accounting settled -- charged = refunded on that conn -- and release
    ;; everything: the handler reports the totals it read after the failure.
    (let ((me self))
      (http-swap! srv (lambda (req res)
                        (let ((c (res-conn res)))
                          (let ((outcome (guard (e (#t 'raised)) (res-send! res big) 'returned)))
                            (sleep-ms 100)
                            (send me (vector 'refund outcome (guard (e (#t (list 'totals-raised))) (tls-conn-totals c)))))))))
    (inject-arm-fault! 'tls-between-chunks 1)
    (let-values (((plain writes eof? fail) (raw-tls-exchange "127.0.0.1" port "localhost" GET #f 8000)))
      (let ((hits (inject-hits 'tls-between-chunks)))
        (inject-disarm!)
        (check "REFUND: the between-chunks point was hit once" (eqv? hits 1) hits)
        (let ((rep (receive (after 6000 'no-report) (`#(refund ,o ,t) (cons o t)))))
          (check "REFUND: the handler's write completed with an error (did not hang)" (and (pair? rep) (eq? (car rep) 'raised)) rep)
          (check "REFUND: charged = refunded after the failure" (and (pair? rep) (pair? (cdr rep)) (equal? (cadr rep) (cddr rep))) rep))))
    (check "REFUND: resources back to baseline" (settled-to? base 4000) (snap) base)
    (http-swap! srv handler)

    ;; ---- HS-ALERT: a fatal handshake failure reaches the client as an ALERT.
    ;; The listener requires TLS >= 1.2. A hand-crafted ClientHello whose
    ;; version is TLS 1.1 (0x0302) must be answered with an alert record
    ;; (content type 0x15, protocol_version 0x46), not a bare close. (openssl
    ;; s_client on this machine refuses to speak 1.1 itself, so the bytes are
    ;; built here.) A step that poisoned the session before the flush destroyed
    ;; every such alert -- caught by review.
    (let* ((rnd (make-bytevector 32 7))
           (body (bv-append* (list (bytevector 3 2) rnd (bytevector 0) (bytevector 0 2 0 47) (bytevector 1 0))))
           (hs (bv-append* (list (bytevector 1 0 0 (bytevector-length body)) body)))
           (rec (bv-append* (list (bytevector 22 3 1 0 (bytevector-length hs)) hs))))
      (let-values (((how ms first) (raw-tcp-probe port rec 4000)))
        (check "HS-ALERT: a TLS 1.1 ClientHello is answered with an ALERT record (0x15), not a bare close"
               (and first (>= (bytevector-length first) 7) (= (bytevector-u8-ref first 0) 21)) how (and first (bytevector-length first)) (and first (>= (bytevector-length first) 1) (bytevector-u8-ref first 0)))
        (check "HS-ALERT: the alert is protocol_version (70)"
               (and first (>= (bytevector-length first) 7) (= (bytevector-u8-ref first 6) 70)) (and first (>= (bytevector-length first) 7) (bytevector-u8-ref first 6)))))
    (check "HS-ALERT: resources back to baseline" (settled-to? base 3000) (snap) base)

    ;; ---- KEEPALIVE-2: the second request on one TLS connection is answered.
    ;; The read that completed the handshake is decrypted specially; every
    ;; later read must be decrypted too, or keep-alive silently dies after
    ;; the first response (found with the eof probe: a close_notify after a
    ;; keep-alive response was fed and never read).
    (let ((ka (bv "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")))
      (let-values (((plain writes fail) (raw-tls-two-requests "127.0.0.1" port "localhost" ka ka 60 8000)))
        (let ((n (let ((s (utf8->string plain))) (let loop ((i 0) (k 0)) (cond ((> (+ i 11) (string-length s)) k) ((string=? (substring s i (+ i 11)) "ok-over-tls") (loop (+ i 11) (+ k 1))) (else (loop (+ i 1) k)))))))
          (check "KEEPALIVE-2: both requests on one connection were answered" (= n 2) n (bytevector-length plain) fail))))
    (check "KEEPALIVE-2: resources back to baseline" (settled-to? base 4000) (snap) base)

    ;; ---- EOF-ONCE: a clean close delivers exactly one eof to the owner
    ;; the CLIENT must close first for the owner to see an eof at all (a
    ;; server-initiated close retires the conn before any peer close_notify);
    ;; s_client without -ign_eof shuts down cleanly on stdin eof
    (let ((d0 (tls-eof-deliveries)))
      ;; keep-alive request: the server answers and keeps the connection, so the
      ;; client's close_notify (s_client on stdin eof, 1 s later) is the first close
      ;; -no_ign_eof: -quiet implies -ign_eof (openssl s_client -help: "default
      ;; when -quiet"), under which stdin eof closes NOTHING -- the client sat
      ;; connected until timeout killed it with a bare FIN, and the server was
      ;; blamed for a close_notify that was never sent (2026-09-03)
      (s-client (in-dir "eof-once.out") "-no_ign_eof" 1 'keepalive)
      (sleep-ms 3000)
      (check "EOF-ONCE: exactly one eof delivered when the client sends close_notify" (= (tls-eof-deliveries) (+ d0 1)) (tls-eof-deliveries) d0))
    (check "EOF-ONCE: resources back to baseline" (settled-to? base 3000) (snap) base)

    ;; ---- SLOT-LEAK: a raise after the handshaking slot is taken, before the
    ;; session is attached, must still release the slot
    (inject-arm-fault! 'tls-accept-after-slot 1)
    (let-values (((how ms first) (raw-tcp-probe port (bytevector 22 3 1 0 5 1 0 0 1 3) 2000)))
      (let ((hits (inject-hits 'tls-accept-after-slot)))
        (inject-disarm!)
        (check "SLOT-LEAK: the point after the slot was hit once" (eqv? hits 1) hits)
        (check "SLOT-LEAK: the slot was released (handshaking and the rest back to baseline)" (settled-to? base 3000) (snap) base)))

    ;; ---- CTX: shutdown retires the context once
    (http-shutdown! srv)
    (http-shutdown! plain)
    (sleep-ms 300)
    (check "CTX: shutting the listener down retired its context (listener count back to base)" (= (tls-live-listener-context-count) ctx-base) (tls-live-listener-context-count) ctx-base)

    (if (zero? failures)
        (begin (display "ALL TLS-LISTENER TESTS PASSED\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
