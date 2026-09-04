#!chezscheme
;;; A slow on-chunk handler must slow the SERVER, not fill memory.
;;;
;;; libuv reads as fast as the peer sends and copies every segment into an
;;; actor mailbox, which is unbounded. An on-chunk handler that does real
;;; work -- a database write, a disk write, anything that parks -- yields to
;;; the scheduler, and the event loop goes right on reading. The response
;;; limits do not help: max-resp counts bytes the PARSER has seen, and the
;;; parser is waiting for the handler.
;;;
;;; So a consumer slower than its producer accumulated the difference in
;;; memory. Stopping reads around the handler closes the kernel's receive
;;; window instead, which is where flow control belongs.
;;;
;;; The assertion is on how much the SERVER manages to get ACCEPTED while
;;; the client is deliberately slow -- it sends the next chunk only after
;;; the previous one's write completes. Counting what it hands to libuv
;;; instead measures nothing: libuv's write queue is unbounded, so the
;;; server enqueues the whole body either way. That is what the first
;;; version of this test did, and it failed against the fix.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp) (igropyr http-client))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18791)

;; how many bytes the server has had ACCEPTED (write completed) so far
(define written (box 0))
;; a big chunked body: 64 chunks of 256 KiB = 16 MiB
(define chunk-size (* 256 1024))
(define chunk-count 64)

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid
              (spawn
                (lambda ()
                  (receive (after 5000 (tcp-close! c))
                    (`#(tcp-data ,_)
                      (tcp-write! c (string->utf8
                                      (string-append
                                        "HTTP/1.1 200 OK\r\n"
                                        "Transfer-Encoding: chunked\r\n\r\n"))
                                  #f)
                      (let* ((body (make-string chunk-size #\x))
                             (size-line (string-append
                                          (number->string chunk-size 16) "\r\n"))
                             (payload (string->utf8
                                        (string-append size-line body "\r\n")))
                             (me self))
                        ;; one chunk in flight at a time: the next goes out
                        ;; only when the previous has been ACCEPTED, so
                        ;; `written` tracks what the peer actually took
                        (let send-chunks ((i 0))
                          (if (< i chunk-count)
                              (begin
                                (tcp-write! c payload
                                            (lambda (status)
                                              (send me (vector 'wrote status))))
                                (receive (after 30000 'gave-up)
                                  (`#(wrote ,st) 'ok))
                                (set-box! written (+ (unbox written) chunk-size))
                                (send-chunks (+ i 1)))
                              (tcp-write! c (string->utf8 "0\r\n\r\n") #f))))
                      (receive (after 30000 (tcp-close! c))
                        (`#(tcp-eof) (tcp-close! c))
                        (`#(tcp-error ,_) (tcp-close! c))))
                    (`#(tcp-eof) (tcp-close! c))
                    (`#(tcp-error ,_) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 200)

    (let ((consumed (box 0)) (me self))
      (spawn
        (lambda ()
          (send me
            (vector 'done
              (guard (e (#t 'error))
                (http-request 'GET
                  (string-append "http://127.0.0.1:" (number->string port) "/big")
                  (list (cons 'timeout 60000)
                        (cons 'on-chunk
                              (lambda (bv)
                                ;; a handler that does real work: it parks,
                                ;; which is the whole point
                                (set-box! consumed
                                          (+ (unbox consumed) (bytevector-length bv)))
                                (sleep-ms 40)))))
                'ok)))))

      ;; Look while the transfer is still in flight.
      (sleep-ms 1200)
      (let ((w (unbox written)) (c (unbox consumed)))
        (display "  [info] after 1200 ms: server got ")
        (display (div w 1024)) (display " KiB accepted, handler consumed ")
        (display (div c 1024)) (display " KiB\n")
        ;; The handler sleeps 40 ms per chunk, so in 1200 ms it can absorb
        ;; about 30 chunks. Anything much beyond that is sitting in the
        ;; client's mailbox rather than in the network.
        (check "the server is held back by the slow handler"
          (< w (* chunk-count chunk-size))))

      ;; and the transfer still completes correctly
      (let ((r (receive (after 60000 'lost) (`#(done ,v) v))))
        (check "the response still completes" (eq? r 'ok))
        (check "every byte reached the handler"
          (= (unbox consumed) (* chunk-count chunk-size)))))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "client-read-backpressure: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
