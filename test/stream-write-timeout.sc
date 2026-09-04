#!chezscheme
;;; A streamed write must not park forever on a peer that stopped reading.
;;;
;;; Backpressure (stream-backpressure.sc) is the desired half: the producer
;;; blocks once the socket fills, instead of queueing chunks in memory. What
;;; was missing is the bound. The park had no deadline, so a client that
;;; opens an SSE stream and never drains it held its writer process for the
;;; life of the VM -- one leaked process per such client, while whatever
;;; feeds the stream keeps sending into an unbounded mailbox.
;;;
;;; The pool's stuck-ms did NOT cover this. It bounds a POOLED handler, but
;;; the documented shape for a long stream is to detach it into its own
;;; process (res-begin!'s own docstring says so), and a spawned process is
;;; not a pool worker. The recommended shape was the unbounded one.
;;;
;;; The stream is detached here for exactly that reason: a test that wrote
;;; from the pooled handler would be bounded by stuck-ms and would pass
;;; without the timeout existing at all.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp) (igropyr http)
        (igropyr express))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18774)
(define chunk-size 65536)
(define payload (make-string chunk-size #\x))
(define timeout-ms 1500)                 ; short, so the test is not slow

(start-scheduler
  (lambda ()
    (http-write-timeout! timeout-ms)
    (let ((app (create-app)) (main self) (live-conns 0))
      (app-get app "/stall"
        (lambda (req res)
          (sse-start! res)
          ;; detached, as the manual prescribes for a long stream -- and as
          ;; the SSE relays this bounds are written
          (spawn
            (lambda ()
              (let loop ((i 0) (t0 (now-ms)))
                (if (res-write! res payload)
                    (loop (+ i 1) t0)
                    ;; res-write! answers #f when the stream is gone, which
                    ;; is its existing contract for "stop the loop" -- no
                    ;; caller change is needed to benefit from the timeout
                    (send main (vector 'writer-released i (- (now-ms) t0)))))))))
      (app-listen app port)
      (sleep-ms 300)

      ;; a client that asks for the stream and then reads nothing at all
      (spawn
        (lambda ()
          (tcp-connect! "127.0.0.1" port self)
          (receive (after 5000 'gone)
            (`#(tcp-connected ,c)
              (tcp-write! c (string->utf8
                              (string-append "GET /stall HTTP/1.1\r\n"
                                             "Host: 127.0.0.1\r\n\r\n")) #f)
              (send main (vector 'client-sent c))
              (receive (after 30000 'done))))))     ; hold the socket open

      (receive (after 6000 (check "client connected" #f))
        (`#(client-sent ,c) (check "client connected and sent" #t)))


      ;; both halves are up and the writer is stalled mid-stream
      (sleep-ms 300)
      (set! live-conns (conn-count))

      ;; The writer must come back. Waiting well past the deadline but far
      ;; short of forever is the whole assertion: before the timeout existed
      ;; this receive hit its own `after` and the process stayed parked.
      (let ((released (receive (after (* 6 timeout-ms) #f)
                        (`#(writer-released ,n ,ms) (list n ms)))))
        (check "writer is released rather than parked forever"
          (and released #t))
        (when released
          (display "  [info] released after ") (display (cadr released))
          (display " ms, ") (display (car released))
          (display " chunks written (deadline ")
          (display timeout-ms) (display " ms)") (newline)
          ;; it must be the DEADLINE that freed it, not a fluke: earlier than
          ;; the deadline would mean the write failed for some other reason
          ;; and this test would pass with the timeout removed
          (check "released no earlier than the deadline"
            (>= (cadr released) timeout-ms))))

      ;; The TERMINATOR carries the same deadline (res-end!'s 0\r\n\r\n used
      ;; to be fire-and-forget), but there is NO assertion for it here, and
      ;; the honest reason is that I could not build one that discriminates.
      ;; Reaching it requires every earlier write to succeed and the peer to
      ;; stall exactly at the terminator: fill the buffer first and the
      ;; preceding res-write! times out and closes the connection, so
      ;; res-end! returns instantly on a closed conn (measured: 0 ms); write
      ;; too little and nothing stalls at all. Both shapes pass whether or
      ;; not the terminator is bounded, so neither is worth having.
      ;;
      ;; The fix is still right -- an unbounded write there leaves the reader
      ;; in await-streaming, which has no deadline of its own, and
      ;; abort-response! cannot help because the handler FINISHED rather than
      ;; crashed -- but it is carried by inspection, not by this file.

      ;; A write that gave up must close the connection: a chunked or SSE
      ;; body cannot resume mid-chunk, so leaving it open would strand a
      ;; half-written frame and, on keep-alive, corrupt whatever came next.
      ;; The client half is still held open by the probe process above, so
      ;; the assertion is that the SERVER side went away, not that the count
      ;; reached zero.
      (sleep-ms 300)
      (check "abandoning the write closed the server side"
        (< (conn-count) live-conns))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "stream-write-timeout: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
