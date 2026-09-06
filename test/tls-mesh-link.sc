#!chezscheme
;;; tls-mesh-link.sc -- the two inherited invariants on a TLS mesh link (design 11):
;;; M16 (E10 on dist): the link process is the connection's owner AND the
;;; writer of every frame; killed abnormally while it holds the write gate
;;; mid-frame, the connection must still retire, the peer must see the link
;;; end, and nothing may remain. M17 (E9 on dist): closing a link with a frame
;;; queued must deliver the whole frame and close_notify to the peer, not cut
;;; it. The peer is the interactive raw TLS client, which completes the mesh
;;; handshake by hand. Requires IGROPYR_INJECT=on and the openssl CLI.
(import (chezscheme) (igropyr actor) (igropyr node)
        (only (igropyr libuv) now-ms)
        (igropyr inject-control)
        (only (igropyr tls-core) tls-live-session-count)
        (only (igropyr tcp) tls-live-watcher-count)
        (test tls-raw-client) (test mesh-proof))

(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define dir "/tmp/igropyr-tls-mesh-link")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))
(define (in-dir f) (string-append dir "/" f))
(define port 18610)
(define secret "tls-mesh-link-secret-0123456789abcdef")
(define probe-boot-id "feedfacefeedface")
(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))
(define (read-frame s ms)
  (let loop ((acc ""))
    (let* ((n (string-length acc))
           (nl (let scan ((k 0)) (cond ((= k n) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1))))))
           (len (and nl (string->number (substring acc 0 nl)))))
      (if (and len (>= n (+ nl 1 len)))
          (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len))))
          (let ((r (raw-tls-recv! s ms))) (if (bytevector? r) (loop (string-append acc (utf8->string r))) r))))))
;; complete the mesh handshake as peer "b" over an open session -> #t on welcome
(define (join! s)
  (let ((d (read-frame s 4000)))
    (and (pair? d) (eq? (car d) 'challenge)
         (let* ((nonce-a (cadr d)) (bootid-a (cadddr d)) (cb (raw-tls-peer-cb-hash s)))
           (raw-tls-send! s (frame-bytes (list 'hello "b" (v5-proof-d secret nonce-a "b" probe-boot-id 1 "a" bootid-a cb)
                                              "feedfeedfeedfeedfeedfeedfeedfeed" 5 probe-boot-id 1)))
           (let ((w (read-frame s 4000))) (and (pair? w) (eq? (car w) 'welcome)))))))
;; count bytes arriving on the session until it ends or `ms` of silence
(define (drain-bytes! s ms)
  (let loop ((total 0))
    (let ((r (raw-tls-recv! s ms)))
      (if (bytevector? r) (loop (+ total (bytevector-length r))) (cons total r)))))
(define big (make-bytevector (* 4 1024 1024) 66))

(start-scheduler
  (lambda ()
    (register 'main self)
    (node-start! 'a secret port "127.0.0.1"
                 (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))
    (monitor-node 'b)
    (let ((base (list (tls-live-session-count) (tls-live-watcher-count))))

      ;; ---- M17: close the link with a big frame in flight: the peer gets it all + close_notify
      (let ((s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
        (when (pair? s) (check "M17: open" #f (cdr s)))
        (unless (pair? s)
          (check "M17: mesh handshake as b" (join! s))
          (receive (after 3000 (void)) (`#(node-up b) (void)))
          (rsend 'b 'sink big)                          ; queued on the link
          (let ((lp ($node-link-pid 'b)))
            (monitor lp)
            (node-disconnect! 'b)
            (receive (after 5000 (display "  [M17] link DOWN: none within 5 s\n"))
              (`#(DOWN ,p ,reason)
                (display "  [M17] link ") (write p) (display " died with reason ") (write reason) (newline))))                          ; close with the frame in flight
          (let ((r (drain-bytes! s 8000)))
            (check "M17: the peer received the whole frame before the close (>= 4 MB)" (>= (car r) (bytevector-length big)) (car r))
            (check "M17: the stream ended with close_notify, not a cut" (eq? (raw-tls-closed-by s) 'close-notify) (raw-tls-closed-by s) (cdr r)))
          (receive (after 5000 (void)) (`#(node-down b) (void)))
          (raw-tls-close! s)
          (check "M17: baseline" (within? 8000 (lambda () (equal? (list (tls-live-session-count) (tls-live-watcher-count)) base))) (list (tls-live-session-count) (tls-live-watcher-count)) base)))

      ;; ---- M16: the link process holds the gate mid-frame and is killed.
      ;; No barrier here: the link writes from inside a non-preemptible region,
      ;; so 'agg-chunk-boundary is skipped for it. Instead the PEER STOPS READING:
      ;; a 4 MB frame cannot complete against a stalled peer, so the link is the
      ;; gate holder for as long as we like. Killing it then exercises E10 on the
      ;; dist path: the connection must retire, the peer's stream must end once
      ;; it reads again, node-down must arrive, and nothing may remain.
      (let ((s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
        (check "M16: TLS session with the node" (not (pair? s)) s)
        (unless (pair? s)
          (check "M16: mesh handshake as b" (join! s))
          (receive (after 3000 (check "M16: node-up b" #f 'timeout)) (`#(node-up b) (check "M16: node-up b" #t)))
          (let ((link ($node-link-pid 'b)))
            (check "M16: the link process is known" (and link (process-alive? link)) link)
            (when link
              (rsend 'b 'sink big)                        ; the LINK writes a 4 MB frame; we do not read
              (sleep-ms 400)                              ; long past what the socket buffers absorb
              (check "M16: premise -- the link is still alive and mid-frame (peer stalled)" (process-alive? link))
              (kill link 'm16-link-killed-holding-gate)
              (check "M16: the link is dead" (within? 3000 (lambda () (not (process-alive? link)))))
              ;; the raw table, not the node-peers projection (live-entry hides an
              ;; entry whose conn is no longer open): a dead link pid here is a
              ;; stale entry that nobody will ever remove
              (check "M16: the peer entry is gone from the raw table within 5 s"
                     (within? 5000 (lambda () (not ($node-link-pid 'b))))
                     (let ((l ($node-link-pid 'b))) (and l (list 'stale-link-pid (process-id l) (process-alive? l)))))
              (receive (after 8000 (check "M16: node-down b after the link died" #f 'timeout)) (`#(node-down b) (check "M16: node-down b after the link died" #t)))
              (let ((r (drain-bytes! s 4000)))
                (check "M16: the peer's stream ended (the connection was retired, not left hanging)" (eq? (cdr r) 'closed) r))))
          (raw-tls-close! s)
          (check "M16: sessions and watchers back to baseline" (within? 8000 (lambda () (equal? (list (tls-live-session-count) (tls-live-watcher-count)) base))) (list (tls-live-session-count) (tls-live-watcher-count)) base))))

    (if (zero? fails)
        (begin (display "ALL TLS-MESH-LINK TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-LINK VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
