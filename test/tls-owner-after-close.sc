#!chezscheme
;; The owner of a TLS connection closes it by its own hand and keeps running.
;;
;; The watcher is linked to the owner (tls-watch, Z13/E10). If the watcher
;; leaves by an uncaught raise, the actor runtime cascades that exit into a
;; non-trapping linked owner: a process that closes its own TLS connection
;; and then continues is killed a moment later, with the watcher's reason.
;; Observed on the real client path before the fix: the owner died with
;; reason tls-watcher-done 300 ms after its own tcp-close!.
;;
;; Two owners are tried, one per side of the same TLS connection:
;;   O1 the dialing owner (tcp-connect-tls! with owner = self);
;;   O2 the accepting side, exercised through a node's mesh listener, whose
;;      accept-side watcher must not kill the node's own link process either
;;      (that is what M16/M17 in tls-mesh-link.sc look at from the other end).
;; Here only O1 is asserted directly; the accept-side watcher's exit reason
;; is reported through the observer so the cell shows both.
(import (chezscheme) (igropyr actor) (igropyr node) (igropyr tcp)
        (only (igropyr tls-core) tls-mesh-client-context! tls-live-session-count)
        (only (igropyr tls-watch) tls-watcher-observer-set!)
        (only (igropyr libuv) now-ms)
        (only (igropyr tcp) tls-last-retire-reason tls-live-watcher-count)
        (igropyr inject-control))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define dir "/tmp/igropyr-tls-owner-after-close")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(define (in-dir f) (string-append dir "/" f))
(define port 18612)
(start-scheduler
  (lambda ()
    (let ((main self))
      (tls-watcher-observer-set! main)
      (node-start! 'a "owner-after-close-secret-0123456789abcdef" port "127.0.0.1"
                   (list (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key"))))
      (let ((owner (spawn (lambda ()
                     (let ((ctx (tls-mesh-client-context! (in-dir "ca.pem"))))
                       (tcp-connect-tls! "127.0.0.1" port self ctx "localhost")
                       (receive (after 5000 (send main (vector 'open-failed 'timeout)))
                         (`#(tcp-connect-failed ,e) (send main (vector 'open-failed e)))
                         (`#(tcp-connected ,c)
                           (tcp-close! c)          ; retire + close by the owner's own hand
                           (sleep-ms 300)          ; yield: the watchers run and leave
                           (send main (vector 'owner-survived)))))))))
        (define (report-with-err er ee ep m) (send m (vector 'o1d er ee ep)) (receive (after 3000 (void))))
        (define (retire-path) (let ((r (tls-last-retire-reason))) (and (pair? r) (car r))))
        (monitor owner)
        ;; collect until the owner is gone. Track every ANNOUNCED watcher pid and
        ;; match each to a normal DOWN, so a watcher that was killed (non-normal)
        ;; or never reported cannot pass.
        (let loop ((survived #f) (owner-reason #f) (announced '()) (downs '()))
          (receive (after 8000
                     (check "O1: the owner reported back after closing its own connection" survived 'no-report)
                     (check "O1: the owner ended normally (not killed by the watcher's exit)" (eq? owner-reason 'normal) owner-reason)
                     (check "O1: at least one watcher was announced" (pair? announced) announced)
                     (check "O1: every announced watcher reported a DOWN"
                            (for-all (lambda (p) (assq p downs)) announced) (list 'announced (length announced) 'downs (length downs)))
                     (check "O1: every watcher left normally (reason = normal)"
                            (for-all (lambda (pr) (eq? (cdr pr) 'normal)) downs) downs))
            (`#(open-failed ,e) (check "O1: TLS connect" #f e))
            (`#(tls-watcher ,p ,c) (monitor p) (loop survived owner-reason (cons p announced) downs))
            (`#(owner-survived) (loop #t owner-reason announced downs))
            (`#(DOWN ,p ,reason)
              (if (eq? p owner)
                  (loop survived reason announced downs)
                  (loop survived owner-reason announced (cons (cons p reason) downs))))))
        (check "O1: watchers back to baseline (live-watcher-count = 0)"
               (within? 5000 (lambda () (= (tls-live-watcher-count) 0))) (tls-live-watcher-count))
        ;; ---- O1d: the watcher itself fails after establishment, under a
        ;; trapping owner: the connection is retired ('watcher-raise), the owner
        ;; receives a non-normal EXIT from the linked watcher and a tcp-error.
        (let ((armed (inject-arm-fault! 'tls-watcher-delay 1)))
          (let ((towner (spawn (lambda ()
                          (process-trap-exit #t)
                          (let ((ctx (tls-mesh-client-context! (in-dir "ca.pem"))))
                            (tcp-connect-tls! "127.0.0.1" port self ctx "localhost")
                            ;; state: EXIT reason seen, the watcher pid that sent it, the tcp-error seen
                            (let loop ((exit-seen #f) (exit-pid #f) (err-seen #f) (deadline (+ (now-ms) 4000)))
                              (define (report!) (send main (vector 'o1d exit-seen err-seen exit-pid)) (receive (after 3000 (void))))
                              (receive (after (max 1 (- deadline (now-ms))) (report!))
                                (`#(tcp-connected ,c) (send main (vector 'o1d-conn c)) (loop exit-seen exit-pid err-seen deadline))
                                (`#(tcp-connect-failed ,e) (send main (vector 'o1d (list 'connect-failed e) err-seen exit-pid)))
                                (`#(EXIT ,p ,reason) (if err-seen (begin (send main (vector 'o1d reason err-seen p)) (receive (after 3000 (void)))) (loop reason p err-seen deadline)))
                                (`#(tcp-error ,e) (if exit-seen (report-with-err exit-seen e exit-pid main) (loop exit-seen exit-pid e deadline)))
                                (`#(tcp-data ,bv) (loop exit-seen exit-pid err-seen deadline))
                                (`#(tcp-eof) (loop exit-seen exit-pid err-seen deadline)))))))))
            ;; attribute the watcher to THIS connection: the observer announces
            ;; (tls-watcher pid conn) and the owner reports its own conn, so the
            ;; accepting-side watcher (same process, different conn) cannot be
            ;; mistaken for it.
            (let oloop ((watchers '()) (oconn #f))
              (receive (after 8000 (check "O1d: the trapping owner reported" #f 'timeout))
                (`#(o1d-conn ,c) (oloop watchers c))
                (`#(tls-watcher ,p ,c) (oloop (cons (cons c p) watchers) oconn))
                (`#(o1d ,exit-reason ,err ,exit-pid)
                 (let ((wpid (and oconn (cond ((assq oconn watchers) => cdr) (else #f)))))
                 (check "O1d: the owner received a non-normal EXIT from the failing watcher" (and exit-reason (not (eq? exit-reason 'normal)) (not (pair? exit-reason))) exit-reason)
                 (check "O1d: the owner received a tcp-error for the retired connection" err err)
                 ;; NOT retire-path here: tls-last-retire-reason is a process-global
                 ;; statistic and the accepting-side connection in this same process can
                 ;; overwrite it before we read. The watcher's guard calls
                 ;; (conn-tls-retire! c 'watcher-raise) immediately before it re-raises,
                 ;; so a non-normal EXIT FROM THIS CONNECTION'S WATCHER already proves the
                 ;; retirement was that watcher's own raise; matching the EXIT pid below is
                 ;; the connection-attributed evidence.
                 (check "O1d: the EXIT came from the connection's watcher"
                        (and wpid exit-pid (eq? exit-pid wpid)) (list 'watcher (and wpid (process-id wpid)) 'exit-from (and exit-pid (process-id exit-pid))))))))
            (check "O1d: the trapping owner is alive" (process-alive? towner))))
        (check "O1: no TLS session left behind"
               (let wait ((n 0)) (cond ((zero? (tls-live-session-count)) #t) ((> n 100) #f) (else (sleep-ms 50) (wait (+ n 1)))))
               (tls-live-session-count))
        (if (zero? fails)
            (begin (display "ALL TLS-OWNER-AFTER-CLOSE TESTS PASSED\n") (exit 0))
            (begin (display "TLS-OWNER-AFTER-CLOSE VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))))
