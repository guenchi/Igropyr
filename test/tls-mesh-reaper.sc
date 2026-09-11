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
        (only (igropyr node) rcall monitor-remote)
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
(define dir "/tmp/igropyr-tls-mesh-reaper")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))
(define (in-dir f) (string-append dir "/" f))
(define port 18615)
(define secret "tls-mesh-reaper-secret-0123456789abcdef")
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
(define (hello! s boot-id)
  (let ((d (read-frame s 4000)))
    (and (pair? d) (eq? (car d) 'challenge)
         (let* ((nonce-a (cadr d)) (bootid-a (cadddr d)) (cb (raw-tls-peer-cb-hash s)))
           (raw-tls-send! s (frame-bytes (list 'hello "b" (v5-proof-d secret nonce-a "b" boot-id 1 "a" bootid-a cb)
                                              "feedfeedfeedfeedfeedfeedfeedfeed" 5 boot-id 1)))
           #t))))
(define (welcome? s) (let ((w (read-frame s 4000))) (and (pair? w) (eq? (car w) 'welcome))))
(define (join! s) (and (hello! s probe-boot-id) (welcome? s)))
(define (join-as! s boot-id) (and (hello! s boot-id) (welcome? s)))
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

      ;; ---- M24: the peer closes its socket (raw-tls-close! retires the client
      ;; session and closes TCP -- not an authenticated close_notify); the LINK's
      ;; own guard removes the entry, and the reaper's later DOWN for that link must
      ;; find nothing of its own (mine? #f, entry ABSENT): exactly one node-down,
      ;; and monitor tables plus session/watcher counts back to baseline. This
      ;; exercises the reaper's mine? #f path with e = #f (the entry gone); the
      ;; entry-present-different-conn case is the M22 residual (see the design doc).
      (let ((s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
        (check "M24: TLS session with the node" (not (pair? s)) s)
        (unless (pair? s)
          (check "M24: mesh handshake as b" (join! s))
          (receive (after 3000 (check "M24: node-up b" #f 'timeout)) (`#(node-up b) (check "M24: node-up b" #t)))
          (let ((t-stale (inject-arm-barrier! 'link-reaper-reclaimed-stale 1 30000))
                (link ($node-link-pid 'b)))
            (raw-tls-close! s)   ; the peer closes its socket (no close_notify); the link's guard removes the entry
            (receive (after 5000 (check "M24: node-down b (from the guard's removal)" #f 'timeout))
              (`#(node-down b) (check "M24: node-down b (from the guard's removal)" #t)))
            (let ((w (inject-barrier-wait t-stale 'link-reaper-reclaimed-stale 5000)))
              (check "M24: the reaper's later DOWN ran a removal that found the entry already gone (mine? #f)" (pair? w) w)
              (when (pair? w) (send (cdr w) (vector 'inject-resume t-stale))))
            (check "M24: the link exited" (and link (within? 3000 (lambda () (not (process-alive? link))))))
            (receive (after 800 (check "M24: no second node-down" #t)) (`#(node-down b) (check "M24: no second node-down" #f 'duplicate)))
            (guard (e (#t (void))) (inject-barrier-cleanup! t-stale 'link-reaper-reclaimed-stale 31000)))
          (check "M24: sessions and watchers back to baseline" (within? 8000 (lambda () (equal? (list (tls-live-session-count) (tls-live-watcher-count)) base))) (list (tls-live-session-count) (tls-live-watcher-count)) base)))

      ;; ---- M20: enrolment loss with the reaper alive. The reaper is parked right
      ;; after a rescan that saw no b; b's link installs and is killed before its
      ;; hint; only the reaper's next periodic rescan can find the dead link.
      (let ((t-scan (inject-arm-barrier! 'link-reaper-rescanned 1 30000)))
        (let ((w (inject-barrier-wait t-scan 'link-reaper-rescanned 5000)))
          (check "M20: the reaper parked after a rescan (no b installed yet)" (pair? w) w)
          (let ((t-hint (inject-arm-barrier! 'link-enrol-before-hint 1 30000))
                (s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
            (check "M20: TLS session with the node" (not (pair? s)) s)
            (unless (pair? s)
              (check "M20: hello sent as b" (hello! s probe-boot-id))
              (let ((h (inject-barrier-wait t-hint 'link-enrol-before-hint 5000)))
                (check "M20: b's link parked between install and its hint" (pair? h) h)
                (let ((link (and (pair? h) (cdr h))))
                  (check "M20: premise -- the entry is installed with this link" (and link (eq? ($node-link-pid 'b) link)))
                  (when link (kill link 'm20-killed-before-hint))
                  (check "M20: the link is dead" (and link (within? 2000 (lambda () (not (process-alive? link))))))
                  (guard (e (#t (void))) (inject-release! t-hint))
                  (sleep-ms 300)
                  (check "M20: premise -- with the reaper parked nothing reclaimed the entry" (eq? ($node-link-pid 'b) link))
                  (let ((t0 (now-ms)))
                    (when (pair? w) (send (cdr w) (vector 'inject-resume t-scan)))
                    (check "M20: the next periodic rescan reclaimed the entry within 2 x scan period"
                           (within? 2500 (lambda () (not ($node-link-pid 'b)))) (- (now-ms) t0))
                    (display "  [M20] reclaimed after ms ") (display (- (now-ms) t0)) (newline))
                  (receive (after 3000 (check "M20: node-down b" #f 'timeout)) (`#(node-down b) (check "M20: node-down b" #t)))))
              (raw-tls-close! s))
            (guard (e (#t (void))) (inject-barrier-cleanup! t-hint 'link-enrol-before-hint 31000))))
        (guard (e (#t (void))) (inject-barrier-cleanup! t-scan 'link-reaper-rescanned 31000))
        (check "M20: sessions and watchers back to baseline" (within? 8000 (lambda () (equal? (list (tls-live-session-count) (tls-live-watcher-count)) base))) (list (tls-live-session-count) (tls-live-watcher-count)) base))

      ;; ---- M20s (batch 1 residual): the same enrolment loss, but the reaper is fed
      ;; a hint every 100 ms during the wait. The scan deadline is absolute (4.3):
      ;; a steady trickle of messages must not postpone the rescan. A reaper that
      ;; renewed its deadline on every message would never scan while the hints
      ;; keep coming, and b's dead link would never be reclaimed.
      (let ((t-scan (inject-arm-barrier! 'link-reaper-rescanned 1 30000)))
        (let ((w (inject-barrier-wait t-scan 'link-reaper-rescanned 5000)))
          (check "M20s: the reaper parked after a rescan (no b installed)" (pair? w) w)
          (let ((t-hint (inject-arm-barrier! 'link-enrol-before-hint 1 30000))
                (s (raw-tls-open "127.0.0.1" port "localhost" 5000)))
            (check "M20s: TLS session with the node" (not (pair? s)) s)
            (unless (pair? s)
              (check "M20s: hello sent as b" (hello! s probe-boot-id))
              (let ((h (inject-barrier-wait t-hint 'link-enrol-before-hint 5000)))
                (check "M20s: b's link parked between install and its hint" (pair? h) h)
                (let ((link (and (pair? h) (cdr h))))
                  (when link (kill link 'm20s-killed-before-hint))
                  (check "M20s: the link is dead" (and link (within? 2000 (lambda () (not (process-alive? link))))))
                  (guard (e (#t (void))) (inject-release! t-hint))
                  (sleep-ms 300)
                  (check "M20s: premise -- with the reaper parked nothing reclaimed the entry" (eq? ($node-link-pid 'b) link))
                  ;; the trickle: a hint every 100 ms until the entry is gone
                  (let* ((reaper (and (pair? w) (cdr w)))
                         (hints 0)
                         (hinter (spawn (lambda ()
                                          (let loop ()
                                            (when ($node-link-pid 'b)
                                              (send reaper (vector 'cleanup-published))
                                              (set! hints (+ hints 1))
                                              (sleep-ms 100)
                                              (loop))))))
                         (t0 (now-ms)))
                    (when (pair? w) (send (cdr w) (vector 'inject-resume t-scan)))
                    (check "M20s: the periodic rescan reclaimed the entry within 2 x scan period despite the trickle"
                           (within? 2500 (lambda () (not ($node-link-pid 'b)))) (- (now-ms) t0) hints)
                    (check "M20s: premise -- the trickle was real (hints arrived during the wait)" (>= hints 5) hints)
                    (display "  [M20s] reclaimed after ms ") (display (- (now-ms) t0)) (display " with hints ") (display hints) (newline)
                    (kill hinter 'done))
                  (receive (after 3000 (check "M20s: node-down b" #f 'timeout)) (`#(node-down b) (check "M20s: node-down b" #t)))))
              (raw-tls-close! s))
            (guard (e (#t (void))) (inject-barrier-cleanup! t-hint 'link-enrol-before-hint 31000))))
        (guard (e (#t (void))) (inject-barrier-cleanup! t-scan 'link-reaper-rescanned 31000))
        (check "M20s: sessions and watchers back to baseline" (within? 8000 (lambda () (equal? (list (tls-live-session-count) (tls-live-watcher-count)) base))) (list (tls-live-session-count) (tls-live-watcher-count)) base))

      )

    (if (zero? fails)
        (begin (display "ALL TLS-MESH-REAPER TESTS PASSED\n") (exit 0))
        (begin (display "TLS-MESH-REAPER VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
