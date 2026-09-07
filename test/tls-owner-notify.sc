#!chezscheme
;; A' cells: an ESTABLISHED TLS connection that fails on the transport must
;; tell its owner once, with #(tcp-error reason), and only then.
;;
;; The owner is an ordinary non-trapping process that dialled with
;; tcp-connect-tls! (owner = itself) and forwards every message it receives
;; to the cell; the peer is the raw TLS server fixture, which can put bytes
;; on the wire as they are (a malformed record) or close with close_notify.
;; The retirement path is read from tls-last-retire-reason (INJECT statistic).
;;
;;   O2  malformed record after establishment -> read-raise -> ONE tcp-error
;;   O7  clean close by the peer -> tcp-eof, no tcp-error
;;   O3  the owner closes and keeps running -> no tcp-error, owner alive
;;   O6  (a) abort during the handshake -> tcp-connect-failed only
;;       (b) established then malformed -> tcp-connected, tcp-error, never
;;           tcp-connect-failed
;;   O8  competing causes: garbage-then-close (the read winner is observed
;;       before the owner closes) -> exactly one; close-then-garbage -> zero
(import (chezscheme) (igropyr actor) (igropyr tcp)
        (only (igropyr tls-core) tls-mesh-client-context! tls-live-session-count)
        (only (igropyr tcp) tls-last-retire-reason)
        (only (igropyr tls-watch) tls-watch-install!)
        (only (igropyr libuv) now-ms)
        (test tls-raw-server))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define dir "/tmp/igropyr-tls-owner-notify")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(define (in-dir f) (string-append dir "/" f))
(define port 18613)
(define hold-port 18614)
;; a TLS application-data header advertising an oversized body: rejected by
;; SSL_read as soon as the header is parsed, without waiting for more bytes
(define malformed (bytevector 23 3 3 255 255))

(start-scheduler
  (lambda ()
    ;; ---- helpers (defines first) ------------------------------------------
    (define _install (tls-watch-install!))   ; hooks first (letrec* order): before the TLS listener
    (define main self)
    (define ctx (tls-mesh-client-context! (in-dir "ca.pem")))
    ;; spawn an owner that dials `port`, reports establishment, then forwards
    ;; every socket message and obeys #(do-close) / #(do-exit)
    (define (spawn-owner! p)
      (spawn (lambda ()
               (tcp-connect-tls! "127.0.0.1" p self ctx "localhost")
               (let loop ((c #f))
                 (receive (after 8000 (send main (vector 'owner-msg self 'silent-8s #f)))
                   (`#(tcp-connected ,c2) (send main (vector 'owner-msg self 'tcp-connected #f)) (loop c2))
                   (`#(tcp-connect-failed ,e) (send main (vector 'owner-msg self 'tcp-connect-failed e)) (loop c))
                   (`#(tcp-data ,bv) (send main (vector 'owner-msg self 'tcp-data #f)) (loop c))
                   (`#(tcp-eof) (send main (vector 'owner-msg self 'tcp-eof #f)) (loop c))
                   (`#(tcp-error ,e) (send main (vector 'owner-msg self 'tcp-error e)) (loop c))
                   (`#(do-close) (when c (tcp-close! c)) (send main (vector 'owner-msg self 'closed-by-owner #f)) (loop c))
                   (`#(do-exit) (void)))))))
    ;; next forwarded message tag from owner o (with its payload), or 'timeout
    (define (next-msg o ms)
      (receive (after ms 'timeout)
        (`#(owner-msg ,@o ,tag ,payload) (list tag payload))))
    (define (expect! label o ms . tags)
      (let ((m (next-msg o ms)))
        (check label (and (pair? m) (memq (car m) tags)) m)
        m))
    (define (quiet! label o ms)
      (let ((m (next-msg o ms)))
        (check label (eq? m 'timeout) m)))
    (define (retire-path) (let ((r (tls-last-retire-reason))) (and (pair? r) (car r))))
    (define (established! label srv)
      (let* ((o (spawn-owner! port))
             (s (raw-tls-server-accept srv 5000)))
        (check (string-append label ": raw server session") (not (or (pair? s) (symbol? s))) s)
        (expect! (string-append label ": owner established") o 5000 'tcp-connected)
        (cons o s)))
    (define base (tls-live-session-count))
    (define srv (raw-tls-server-start "127.0.0.1" port (in-dir "good.pem") (in-dir "good.key")))

    ;; ---- O2: malformed record after establishment ---------------------------
    (let* ((os (established! "O2" srv)) (o (car os)) (s (cdr os)))
      (raw-tls-session-send-raw! s malformed)
      (let ((m (expect! "O2: the owner received tcp-error within 2 s" o 2000 'tcp-error)))
        (check "O2: the retirement took a read-path failure branch (read-raise / feed-failed / read-error)"
               (memq (retire-path) '(read-raise feed-failed read-error)) (retire-path) m))
      (quiet! "O2: no second message (no second tcp-error, no tcp-eof) within 500 ms" o 500)
      (check "O2: the owner is alive after the error" (process-alive? o))
      ;; the peer stays open until the retirement was observed above; now it closes
      (raw-tls-session-close! s)
      (send o (vector 'do-exit)))

    ;; ---- O7: clean close by the peer -> authenticated EOF ------------------
    (let* ((os (established! "O7" srv)) (o (car os)) (s (cdr os)))
      (raw-tls-session-close! s)                                   ; close_notify, then the socket
      (expect! "O7: the owner received tcp-eof" o 3000 'tcp-eof)
      (quiet! "O7: no tcp-error after an authenticated EOF" o 500)
      (check "O7: the owner is alive" (process-alive? o))
      (send o (vector 'do-exit)))

    ;; ---- O3: the owner closes and keeps running ----------------------------
    (let* ((os (established! "O3" srv)) (o (car os)) (s (cdr os)))
      (send o (vector 'do-close))
      (expect! "O3: the owner closed" o 2000 'closed-by-owner)
      (check "O3: the retirement was observed as a clean close (closing? was set)"
             (within? 5000 (lambda () (eq? (retire-path) 'clean-close))) (retire-path))
      (quiet! "O3: no tcp-error reached the owner after its own close" o 500)
      (check "O3: the owner survived its own close" (process-alive? o))
      (raw-tls-session-close! s)
      (send o (vector 'do-exit)))

    ;; ---- O8 order 1: garbage, observed read winner, then the owner closes ---
    (let* ((os (established! "O8a" srv)) (o (car os)) (s (cdr os)))
      (raw-tls-session-send-raw! s malformed)
      (expect! "O8a: tcp-error (the read path won the retirement)" o 2000 'tcp-error)
      (check "O8a: winner observed as a read-path retirement, closing? unset" (memq (retire-path) '(read-raise feed-failed read-error)) (retire-path))
      (send o (vector 'do-close))                                  ; a no-op on a retired connection
      (expect! "O8a: the owner's later close returned" o 2000 'closed-by-owner)
      (quiet! "O8a: still exactly one tcp-error" o 500)
      (check "O8a: the owner is alive" (process-alive? o))
      (raw-tls-session-close! s)
      (send o (vector 'do-exit)))

    ;; ---- O8 order 2: the owner closes first, then garbage arrives ----------
    (let* ((os (established! "O8b" srv)) (o (car os)) (s (cdr os)))
      (send o (vector 'do-close))
      (expect! "O8b: the owner closed" o 2000 'closed-by-owner)
      (check "O8b: winner observed as clean-close" (within? 5000 (lambda () (eq? (retire-path) 'clean-close))) (retire-path))
      (raw-tls-session-send-raw! s malformed)
      (quiet! "O8b: zero tcp-error after a close that won" o 800)
      (check "O8b: the owner is alive" (process-alive? o))
      (raw-tls-session-close! s)
      (send o (vector 'do-exit)))

    ;; ---- O6(b): established, then malformed: connected, error, never connect-failed
    (let* ((os (established! "O6b" srv)) (o (car os)) (s (cdr os)))
      (raw-tls-session-send-raw! s malformed)
      (expect! "O6b: tcp-error after tcp-connected" o 2000 'tcp-error)
      (quiet! "O6b: no tcp-connect-failed after a completed dial" o 500)
      (raw-tls-session-close! s)
      (send o (vector 'do-exit)))
    (raw-tls-server-stop! srv)

    ;; ---- O6(a): abort during the handshake -> tcp-connect-failed only ------
    (let* ((hsrv (raw-tls-server-start "127.0.0.1" hold-port (in-dir "good.pem") (in-dir "good.key") '((hold-flight . #t))))
           (o (spawn-owner! hold-port)))
      ;; the server holds its first flight and reports the holder to main; receiving
      ;; that report proves the handshake actually reached the hold, so the abort we
      ;; then send is the cause of the failure (not an unrelated handshake error)
      (let ((holder (receive (after 6000 #f) (`#(raw-server-holding ,p) p))))
        (check "O6a: the server held its first flight (handshake in progress, not yet published)" (and holder #t) holder)
        (when holder (send holder (vector 'abort-flight)))
        (let ((m (expect! "O6a: tcp-connect-failed when the held handshake is aborted" o 6000 'tcp-connect-failed)))
          (check "O6a: the failure is the aborted handshake, concluded through D as (truncated-eof . tls-truncated-eof)"
                 (and (pair? m) (eq? (car m) 'tcp-connect-failed) (equal? (cadr m) '(truncated-eof . tls-truncated-eof))) m)))
      (quiet! "O6a: no tcp-error for a connection that was never published" o 500)
      (check "O6a: the owner is alive" (process-alive? o))
      (send o (vector 'do-exit))
      (raw-tls-server-stop! hsrv))

    (check "baseline: no TLS session left behind"
           (within? 8000 (lambda () (= (tls-live-session-count) base))) (tls-live-session-count) base)
    (if (zero? fails)
        (begin (display "ALL TLS-OWNER-NOTIFY TESTS PASSED\n") (exit 0))
        (begin (display "TLS-OWNER-NOTIFY VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
