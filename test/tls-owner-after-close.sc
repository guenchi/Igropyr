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
        (only (igropyr libuv) now-ms))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
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
        (monitor owner)
        ;; collect until the owner is gone: survived + normal DOWN, or a kill
        (let loop ((survived #f) (owner-reason #f) (watcher-reasons '()))
          (receive (after 6000
                     (check "O1: the owner reported back after closing its own connection" survived 'no-report)
                     (check "O1: the owner ended normally (not killed by the watcher's exit)" (eq? owner-reason 'normal) owner-reason)
                     (check "O1: every watcher left normally" (and (pair? watcher-reasons) (for-all (lambda (r) (eq? r 'normal)) watcher-reasons)) watcher-reasons))
            (`#(open-failed ,e) (check "O1: TLS connect" #f e))
            (`#(tls-watcher ,p ,c) (monitor p) (loop survived owner-reason watcher-reasons))
            (`#(owner-survived) (loop #t owner-reason watcher-reasons))
            (`#(DOWN ,p ,reason)
              (if (eq? p owner)
                  (loop survived reason watcher-reasons)
                  (loop survived owner-reason (cons reason watcher-reasons))))))
        (check "O1: no TLS session left behind"
               (let wait ((n 0)) (cond ((zero? (tls-live-session-count)) #t) ((> n 100) #f) (else (sleep-ms 50) (wait (+ n 1)))))
               (tls-live-session-count))
        (if (zero? fails)
            (begin (display "ALL TLS-OWNER-AFTER-CLOSE TESTS PASSED\n") (exit 0))
            (begin (display "TLS-OWNER-AFTER-CLOSE VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))))
