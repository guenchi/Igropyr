#!chezscheme
;;; #4 regression: a handler that crashes AFTER it began streaming must not
;;; leak its connection.
;;;
;;; res-begin! claims the response token and parks the reader in
;;; await-streaming with NO deadline. If the handler then crashes (or is
;;; killed as stuck), fail-task fell through to a 500 -- but send-response!
;;; is a no-op once the token is claimed, so nothing was sent, the socket
;;; was never closed and the reader waited forever. Both the fd and the
;;; reader process leaked, once per request, at the client's discretion.
;;;
;;; The client must therefore HOLD the connection open for the leak to be
;;; visible: await-streaming does clean up on tcp-eof, so a client that
;;; times out and disconnects hides the bug. These clients are raw sockets
;;; that never close on their own -- they close only when the SERVER does,
;;; which is the behaviour under test. Counted with (conn-count), libuv's
;;; live-connection table (which spans both sides here, so a leaked server
;;; connection also pins its client).

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp) (igropyr http)
        (igropyr express))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18774)
(define n-clients 6)

;; open a raw connection, send one request, then hold it: close only when
;; the peer closes (or on error). Reports 'closed to `report` either way.
(define (hold-request! path report)
  (spawn
    (lambda ()
      (tcp-connect! "127.0.0.1" port self)
      (receive (after 5000 (send report (vector 'closed)))
        (`#(tcp-connect-failed ,e) (send report (vector 'closed)))
        (`#(tcp-connected ,c)
          (tcp-read-start! c)
          (tcp-write! c (string->utf8
                          (string-append "GET " path " HTTP/1.1\r\n"
                                         "Host: 127.0.0.1\r\n\r\n")) #f)
          (let wait ()
            (receive (after 12000 (tcp-close! c) (send report (vector 'closed)))
              (`#(tcp-data ,bv) (wait))          ; consume, never close
              (`#(tcp-eof) (tcp-close! c) (send report (vector 'closed)))
              (`#(tcp-error ,e) (tcp-close! c) (send report (vector 'closed))))))))))

(start-scheduler
  (lambda ()
    (let ((app (create-app)) (main self))
      (app-get app "/crash-midstream"
        (lambda (req res)
          (sse-start! res)                        ; claims the token
          (sse-send! res "first")
          (raise 'deliberate-crash-after-begin)))
      (app-get app "/ok" (lambda (req res) (send-text! res "fine")))
      (app-listen app port)
      (sleep-ms 300)

      (let ((baseline (conn-count)))
        (do ((i 0 (+ i 1))) ((= i n-clients))
          (hold-request! "/crash-midstream" main))
        ;; each client answers 'closed only when the SERVER closes on it;
        ;; with the bug none of them ever does and this times out
        (let count ((got 0))
          (if (= got n-clients)
              (check "server closes every crashed stream" #t)
              (let ((r (receive (after 9000 #f) (`#(closed) 'closed))))
                (if r
                    (count (+ got 1))
                    (check "server closes every crashed stream"
                      (begin (display "    (only ") (display got)
                             (display " of ") (display n-clients)
                             (display " were closed by the server)\n")
                             #f))))))
        (sleep-ms 600)
        (let ((after (conn-count)))
          (display "  [info] conn-count baseline=") (display baseline)
          (display " after ") (display n-clients)
          (display " crashed streams=") (display after) (newline)
          (check "no connections left behind" (<= after baseline))))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "stream-crash: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
