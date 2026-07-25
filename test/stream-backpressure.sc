#!chezscheme
;;; #5 regression: res-write! must wait for each chunk to drain.
;;;
;;; It used to hand every chunk to tcp-writev! with a #f completion and
;;; return immediately. A client that stops reading never leaves
;;; conn-state 'open, and enqueue-write! has no cap and foreign-allocs
;;; each queued block -- so a producer loop grew memory the GC cannot see,
;;; at full speed, until the machine gave out. Its sibling
;;; res-write-fixed! had always parked until each write drained.
;;;
;;; The test: a client that completes the request and then reads NOTHING.
;;; The handler loops writing chunks and reports how many it got through.
;;; With backpressure it blocks once the socket buffers fill, so the count
;;; stops at a small number; without it the loop runs to completion,
;;; queueing every chunk in memory.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
        (igropyr express))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18775)
(define chunk-size 65536)          ; 64 KiB per chunk
(define max-chunks 400)            ; 400 x 64 KiB = 25 MiB if never blocked
(define payload (make-string chunk-size #\x))

(start-scheduler
  (lambda ()
    (let ((app (create-app)) (main self) (written (box 0)))
      (app-get app "/firehose"
        (lambda (req res)
          (sse-start! res)
          (let loop ((i 0))
            (if (>= i max-chunks)
                (begin (send main (vector 'producer-done (unbox written)))
                       (res-end! res))
                (if (res-write! res payload)
                    (begin (set-box! written (+ 1 (unbox written)))
                           (loop (+ i 1)))
                    (send main (vector 'producer-done (unbox written))))))))
      (app-listen app port)
      (sleep-ms 300)

      ;; a client that sends the request and then never reads
      (spawn
        (lambda ()
          (tcp-connect! "127.0.0.1" port self)
          (receive (after 5000 'gone)
            (`#(tcp-connected ,c)
              ;; deliberately NOT tcp-read-start!: nothing is consumed
              (tcp-write! c (string->utf8
                              (string-append "GET /firehose HTTP/1.1\r\n"
                                             "Host: 127.0.0.1\r\n\r\n")) #f)
              (send main (vector 'client-sent c))
              (receive (after 30000 'done))))))     ; hold the socket open

      (receive (after 6000 (check "client connected" #f))
        (`#(client-sent ,c) (check "client connected and sent" #t)))

      ;; give the producer plenty of time; with backpressure it stalls,
      ;; without it it races to the end
      (let ((done (receive (after 6000 #f) (`#(producer-done ,n) n))))
        (display "  [info] chunks written before stalling: ")
        (display (if done done (unbox written)))
        (display " of ") (display max-chunks) (newline)
        ;; unbuffered, a socket takes a few hundred KiB at most before it
        ;; blocks; anything near max-chunks means chunks were queued in
        ;; our own memory instead
        (check "producer is blocked by the stalled reader"
          (and (not done) (< (unbox written) 100))))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "stream-backpressure: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
