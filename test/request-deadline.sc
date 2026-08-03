#!chezscheme
;;; The whole-request deadline spans BOTH phases of a request.
;;;
;;; read-timeout-ms bounds the gap between segments and re-arms on each one,
;;; so it alone never ends a request -- a client dribbling one byte just
;;; under the interval holds a reader forever. request-deadline-ms exists to
;;; cap the total, and the header phase measured it from the first byte,
;;; correctly.
;;;
;;; The body phase then computed (+ (now-ms) request-deadline-ms): a fresh
;;; budget of the same length, starting at the header/body boundary. A client
;;; could spend almost the whole deadline on the head and almost the whole
;;; deadline again on the body, holding a reader for TWICE what the setting
;;; says -- and the comment above it claimed the phases shared one deadline,
;;; which is what made it easy to miss.
;;;
;;; The test uses a short deadline and a client whose HEAD arrives slowly --
;;; in pieces, completing around the halfway mark -- and which then dribbles
;;; the body. The slow head is the point: with a head sent all at once the
;;; body phase begins at almost the same instant as the first byte, both
;;; formulas give the same answer, and the test passes against the bug. What
;;; is asserted is WHEN the request ends relative to its FIRST byte.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
        (igropyr express))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18783)
(define deadline 2000)

;; Dribbles the request head so it completes around the halfway mark, then
;; dribbles body bytes forever. Reports how long after its FIRST byte the
;; server ended the request.
(define (slow-body-client! report)
  (spawn
    (lambda ()
      (tcp-connect! "127.0.0.1" port self)
      (receive (after 5000 (send report (vector 'done #f #f)))
        (`#(tcp-connect-failed ,e) (send report (vector 'done #f #f)))
        (`#(tcp-connected ,c)
          (tcp-read-start! c)
          (let ((t0 (now-ms)))
            ;; The head arrives in three pieces, finishing at about half the
            ;; deadline. Each gap is under read-timeout-ms, so nothing reaps
            ;; it -- that is the whole shape of a slowloris, and the reason a
            ;; total deadline exists. The header phase alone would end this
            ;; at t0 + deadline; what is being tested is whether crossing
            ;; into the body phase hands it a second budget.
            (tcp-write! c (string->utf8 "POST /sink HTTP/1.1\r\n") #f)
            (sleep-ms (div deadline 4))
            (tcp-write! c (string->utf8 "Host: x\r\n") #f)
            (sleep-ms (div deadline 4))
            (tcp-write! c (string->utf8 "Content-Length: 1000\r\n\r\n") #f)
            (let dribble ()
              (tcp-write! c (string->utf8 "x") #f)
              (receive (after 150 (dribble))
                (`#(tcp-data ,bv)
                  (tcp-close! c)
                  (send report (vector 'done (- (now-ms) t0)
                                       (utf8->string bv))))
                (`#(tcp-eof) (tcp-close! c)
                  (send report (vector 'done (- (now-ms) t0) #f)))
                (`#(tcp-error ,e) (tcp-close! c)
                  (send report (vector 'done (- (now-ms) t0) #f)))))))))))

(start-scheduler
  (lambda ()
    (http-request-deadline! deadline)
    (let ((app (create-app)) (main self))
      ;; never reached: the body never completes
      (app-post app "/sink" (lambda (req res) (send-text! res "ok")))
      (app-listen app port)
      (sleep-ms 300)

      (slow-body-client! main)
      (let* ((r (receive (after 20000 (vector 'done #f #f)) (`#(done ,ms ,t) (vector 'done ms t))))
             (ms (vector-ref r 1))
             (text (vector-ref r 2)))
        (check "the request ended" (and ms #t))
        (display "  [info] ended ") (display ms)
        (display " ms after the first byte (deadline ")
        (display deadline) (display " ms)\n")
        ;; The discriminating assertion. The head completes at ~deadline/2,
        ;; so a restarted deadline ends at ~1.5x; a shared one ends at ~1x.
        (check "ended on the deadline measured from the FIRST byte"
          (and ms (< ms (+ deadline 600))))
        ;; and it is a timeout, not a crash or a silent close
        (check "answered 408 rather than dropping the connection"
          (and text (>= (string-length text) 12)
               (string=? (substring text 9 12) "408"))))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "request-deadline: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
