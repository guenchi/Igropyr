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
;;   O4/O1b (batch 1 residual) a second process holding the write gate dies:
;;       the watcher retires the connection, the live owner receives exactly
;;       one tcp-error (A' on holder death), and survives the watcher's exit
(import (chezscheme) (igropyr actor) (igropyr tcp)
        (only (igropyr tls-core) tls-mesh-client-context! tls-live-session-count)
        (only (igropyr tcp) tls-last-retire-reason)
        (only (igropyr tls-watch) tls-watch-install!)
        (only (igropyr libuv) now-ms)
        (only (igropyr tcp) tls-live-watcher-count)
        (igropyr inject-control)
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
                   ;; O4: a SECOND process takes the write gate on this connection
                   (`#(do-spawn-writer ,payload)
                     (let ((w (spawn (lambda () (tcp-writev! c (list payload) (lambda (st) (send main (vector 'writer-done st))))))))
                       (send main (vector 'owner-msg self 'writer w)))
                     (loop c))
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
    ;; ---- O4 / O1b: the gate holder (a second process) dies while the owner lives
    (let* ((srv (raw-tls-server-start "127.0.0.1" port (in-dir "good.pem") (in-dir "good.key")))
           (wbase (tls-live-watcher-count))
           ;; a stale report from the earlier hold server (its abort's raw-server-failed
           ;; arrives after O6a stopped waiting) must not be taken for this accept
           (_drain (let drain () (receive (after 0 (void)) (`#(raw-server-failed ,why) (drain)) (`#(raw-server-session ,s0) (raw-tls-session-close! s0) (drain)))))
           (os (established! "O4" srv)) (o (car os)) (s (cdr os))
           (t (inject-arm-barrier! 'tls-after-held 1 30000)))
      (send o (vector 'do-spawn-writer (make-bytevector (* 4 1024 1024) 65)))
      (let ((m (expect! "O4: the owner spawned the writer" o 3000 'writer)))
        (let* ((p (and (pair? m) (cadr m)))
               (w (inject-barrier-wait t 'tls-after-held 5000)))
          (check "O4: the writer parked holding the gate" (and (pair? w) (eq? (cdr w) p)) (and (pair? w) (process-id (cdr w))))
          (cond
            ((pair? w)
             (kill p 'o4-holder-kill)
             (check "O4: the holder is dead" (within? 3000 (lambda () (not (process-alive? p)))))
             (let ((e (expect! "O4: the live owner received a tcp-error (A' on holder death)" o 5000 'tcp-error)))
               (check "O4: ...naming the holder's death" (and (pair? e) (eq? (cadr e) 'o4-holder-kill)) e))
             (check "O4: the retirement path is the holder's death" (eq? (retire-path) 'down) (tls-last-retire-reason))
             (quiet! "O4: exactly one tcp-error, no eof, nothing else" o 800)
             (check "O1b: the non-trapping owner survived the watcher's exit (exited normal, not raised)" (process-alive? o))
             (check "O1b: the watcher is gone" (within? 4000 (lambda () (eqv? (tls-live-watcher-count) wbase))) (tls-live-watcher-count) wbase)
             (guard (e (#t (void))) (inject-release! t)))
            (else (inject-barrier-cleanup! t 'tls-after-held 31000)))))
      (guard (e (#t (void))) (raw-tls-session-close! s))
      (send o (vector 'do-exit))
      (raw-tls-server-stop! srv)
      (check "O4: sessions back to baseline" (within? 5000 (lambda () (= (tls-live-session-count) base))) (tls-live-session-count) base))

    ;; ---- O5 (batch 1 residual): the FINAL handshake flight's queued write fails
    ;; after publication. Every write in both dials is forced onto the queued path
    ;; ('try-write-eagain on every hit), so no completion is inline; the calibration
    ;; dial counts the dial side's flight completions N, and the fault dial forces a
    ;; negative status at occurrence N: the owner must see tcp-connected FIRST
    ;; (publication happened) and then exactly one tcp-error naming
    ;; tls-handshake-write-failed, never tcp-connect-failed.
    (let* ((srv (raw-tls-server-start "127.0.0.1" port (in-dir "good.pem") (in-dir "good.key")))
           (_drain (let drain () (receive (after 0 (void)) (`#(raw-server-failed ,why) (drain)) (`#(raw-server-session ,s0) (raw-tls-session-close! s0) (drain))))))
      ;; calibration
      (inject-arm-return! 'try-write-eagain 0 #f)
      (let ((tcount (inject-arm-barrier! 'tls-handshake-write-status 1000000 60000)))
        (let* ((os (established! "O5 calibration" srv)) (o (car os)) (s (cdr os)))
          (guard (e (#t (void))) (raw-tls-session-close! s))
          (send o (vector 'do-exit))
          (check "O5 calibration: session settled" (within? 5000 (lambda () (= (tls-live-session-count) base))) (tls-live-session-count))
          (let ((n (or (inject-hits 'tls-handshake-write-status) 0)))
            (check "O5 calibration: the dial side completed at least one handshake flight through the seam" (>= n 1) n)
            (guard (e (#t (void))) (inject-release! tcount))
            ;; fault dial: the final flight's completion fails
            (inject-arm-return! 'tls-handshake-write-status -1 n)
            (let* ((o (spawn-owner! port))
                   (s (raw-tls-server-accept srv 5000)))
              (check "O5: raw server session" (not (or (pair? s) (symbol? s))) s)
              (expect! "O5: the owner was published first (tcp-connected)" o 5000 'tcp-connected)
              (let ((e (expect! "O5: then exactly one tcp-error (A' after publication)" o 5000 'tcp-error)))
                (check "O5: ...naming the failed handshake write" (and (pair? e) (eq? (cadr e) 'tls-handshake-write-failed)) e))
              (check "O5: the status injection was delivered exactly once" (eqv? (inject-delivered 'tls-handshake-write-status) 1) (inject-delivered 'tls-handshake-write-status))
              (check "O5: the retirement path is the handshake write failure" (eq? (retire-path) 'handshake-write-failed) (tls-last-retire-reason))
              (quiet! "O5: nothing else (no tcp-connect-failed, no second error)" o 800)
              (check "O5: the owner is alive" (process-alive? o))
              (guard (e (#t (void))) (raw-tls-session-close! s))
              (send o (vector 'do-exit))
              (check "O5: sessions back to baseline" (within? 5000 (lambda () (= (tls-live-session-count) base))) (tls-live-session-count) base)
              ;; polarity control: a MIDDLE flight failing is a pre-publication failure
              (when (> n 1)
                (inject-arm-return! 'tls-handshake-write-status -1 (- n 1))
                (let* ((o2 (spawn-owner! port)) (s2 (raw-tls-server-accept srv 5000)))
                  (expect! "O5 control: a middle flight's failure is tcp-connect-failed, never tcp-connected" o2 6000 'tcp-connect-failed)
                  (quiet! "O5 control: nothing else" o2 500)
                  (guard (e (#t (void))) (when (not (or (pair? s2) (symbol? s2))) (raw-tls-session-close! s2)))
                  (send o2 (vector 'do-exit))))))))
      (inject-disarm!)
      (raw-tls-server-stop! srv)
      (check "O5: sessions back to baseline" (within? 5000 (lambda () (= (tls-live-session-count) base))) (tls-live-session-count) base))

    (if (zero? fails)
        (begin (display "ALL TLS-OWNER-NOTIFY TESTS PASSED\n") (exit 0))
        (begin (display "TLS-OWNER-NOTIFY VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
