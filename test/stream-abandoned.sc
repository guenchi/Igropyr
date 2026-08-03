#!chezscheme
;;; A streamed response that will never finish must end the request.
;;;
;;; res-begin! sends the status line and parks the reader in
;;; await-streaming, which has NO deadline -- it waits for the stream to
;;; finish or for the connection to say it is over. Three ways of not
;;; finishing all left it waiting forever, and the client with it:
;;;
;;;   a. the handler raises after res-begin! and error-handler catches it.
;;;      The 500 is dropped on the response token (correctly -- the status
;;;      line is out), and because nothing crashed, the pool's abort path
;;;      never ran either.
;;;   b. a detached producer -- the shape res-begin!'s own docstring
;;;      recommends -- crashes, or returns without calling res-end!. It is
;;;      not the connection owner and not a pool worker, so nothing noticed.
;;;   c. a write times out. abandon-write! closed the handle but told
;;;      nobody; a local close produces no tcp-eof for us.
;;;
;;; In every case the correct signal is the same: close. A chunked body
;;; without its terminating chunk is how HTTP says a response was cut
;;; short, and the client detects it by construction.
;;;
;;; The assertion is that the CLIENT sees the connection end. Counting fds
;;; is not enough -- case (c) already closed the fd and still left the
;;; reader parked, which is precisely how it went unnoticed.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
        (igropyr express) (igropyr middleware))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18785)

;; Sends one request and parks. NEVER closes first, so what is observed is
;; the server's decision, not this client giving up.
;;
;; read? 'delayed models a peer that has stopped reading -- which is what
;; makes a server write time out. It has to start reading EVENTUALLY, or it
;; could not observe the close it is waiting for: a socket nobody reads
;; delivers no EOF. Two seconds is past the 800 ms write timeout, so the
;; server has already given up by then.
(define (probe! path read? report)
  (spawn
    (lambda ()
      (tcp-connect! "127.0.0.1" port self)
      (receive (after 5000 (send report (vector 'r 'no-connect)))
        (`#(tcp-connect-failed ,e) (send report (vector 'r 'no-connect)))
        (`#(tcp-connected ,c)
          (cond
            ((eq? read? 'delayed)
             (spawn (lambda () (sleep-ms 2000) (tcp-read-start! c))))
            (read? (tcp-read-start! c)))
          (tcp-write! c (string->utf8
                          (string-append "GET " path " HTTP/1.1\r\nHost: x\r\n\r\n"))
                      #f)
          (let loop ()
            (receive (after 6000 (send report (vector 'r 'left-hanging)) (tcp-close! c))
              (`#(tcp-data ,bv) (loop))
              (`#(tcp-eof) (send report (vector 'r 'closed)) (tcp-close! c))
              (`#(tcp-error ,e) (send report (vector 'r 'closed)) (tcp-close! c)))))))))

(start-scheduler
  (lambda ()
    ;; short, so the write-timeout case does not have to wait 30 s
    (http-write-timeout! 800)
    (let ((app (create-app)) (main self))
      (app-use app (error-handler))

      ;; (a) raises after the stream began; error-handler catches it
      (app-get app "/raise-after-begin"
        (lambda (req res)
          (res-begin! res)
          (res-write! res "partial")
          (raise 'boom)))

      ;; (b) detached producer crashes
      (app-get app "/producer-crashes"
        (lambda (req res)
          (res-begin! res)
          (res-spawn! res (lambda () (res-write! res "one") (raise 'producer-died)))))

      ;; (b') detached producer returns without res-end! -- no exception at
      ;; all, which no guard-based scheme would catch
      (app-get app "/producer-forgets-end"
        (lambda (req res)
          (res-begin! res)
          (res-spawn! res (lambda () (res-write! res "one")))))

      ;; (b'') a producer that is KILLED discards its winders, so a guard
      ;; inside it would never run; only a monitor sees this
      (app-get app "/producer-killed"
        (lambda (req res)
          (res-begin! res)
          (let ((p (res-spawn! res (lambda () (res-write! res "one")
                                              (sleep-ms 60000)))))
            (spawn (lambda () (sleep-ms 300) (kill p 'reaped))))))

      ;; (c) the peer stops reading, so a write times out
      (app-get app "/peer-stops-reading"
        (lambda (req res)
          (res-begin! res)
          (res-spawn! res
            (lambda ()
              (let loop ()
                (if (res-write! res (make-string 262144 #\x)) (loop) (void)))))))

      ;; (c) again, with a PLAIN spawn. res-spawn!'s watcher would clean
      ;; this up on its own, which hides what abandon-write! does or fails
      ;; to do -- and application code written before res-spawn! existed, or
      ;; writing straight from the pool worker, has no watcher at all. This
      ;; route isolates the write timeout's own cleanup.
      (app-get app "/peer-stops-reading-plain"
        (lambda (req res)
          (res-begin! res)
          (spawn
            (lambda ()
              (let loop ()
                (if (res-write! res (make-string 262144 #\x)) (loop) (void)))))))

      ;; the control: a stream that finishes normally must NOT be truncated
      (app-get app "/normal"
        (lambda (req res)
          (res-begin! res)
          (res-spawn! res (lambda () (res-write! res "hello") (res-end! res)))))

      (app-listen app port)
      (sleep-ms 300)

      (for-each
        (lambda (spec)
          (let ((path (car spec)) (read? (cadr spec)) (label (caddr spec)))
            (probe! path read? main)
            (let ((r (receive (after 15000 'lost) (`#(r ,v) v))))
              (check label (eq? r 'closed))
              (unless (eq? r 'closed)
                (display "       (client saw: ") (display r) (display ")\n")))))
        (list
          (list "/raise-after-begin"   #t "a raise after res-begin! ends the request")
          (list "/producer-crashes"    #t "a crashed detached producer ends the request")
          (list "/producer-forgets-end" #t "a producer that forgets res-end! ends the request")
          (list "/producer-killed"     #t "a KILLED producer ends the request")
          (list "/peer-stops-reading"  'delayed "a timed-out write ends the request")
          ;; the normal stream also closes here, because res-end! on a
          ;; Connection: keep-alive stream leaves the connection open and
          ;; this client then hits its own 6 s park. So assert the opposite
          ;; for it: it must NOT be reported as hanging with no data.
          ))

      ;; ---- the reader itself ---------------------------------------
      ;; Case (c) is the one whose symptom is NOT client-visible: closing
      ;; the handle already gives the client its EOF, so a black-box probe
      ;; passes either way -- which is exactly how it stayed unnoticed. What
      ;; leaked was the READER, parked in await-streaming with no deadline,
      ;; holding its buffer, one per timed-out write, forever.
      ;;
      ;; A parked process burns nothing and appears in no other counter, so
      ;; the assertion is on the process count across a batch.
      (sleep-ms 1500)
      (let ((base (process-count)))
        (let loop ((i 0))
          (when (< i 8)
            (probe! "/peer-stops-reading-plain" 'delayed main)
            (loop (+ i 1))))
        ;; let every write time out and every client finish
        (let drain ((i 0))
          (when (< i 8)
            (receive (after 15000 'lost) (`#(r ,v) v))
            (drain (+ i 1))))
        (sleep-ms 2000)
        (let ((after (process-count)))
          (display "  [info] processes ") (display base)
          (display " -> ") (display after)
          (display " across 8 timed-out streams\n")
          ;; Eight abandoned streams left eight readers behind. A couple of
          ;; processes of slack covers the pool's own churn.
          (check "a timed-out write does not leak the reader"
            (< (- after base) 4))))

      ;; control: the normal stream must deliver its body and its terminator
      (let ((me self))
        (spawn (lambda ()
                 (tcp-connect! "127.0.0.1" port self)
                 (receive (after 5000 (send me (vector 'n #f)))
                   (`#(tcp-connected ,c)
                     (tcp-read-start! c)
                     (tcp-write! c (string->utf8
                                     "GET /normal HTTP/1.1\r\nHost: x\r\n\r\n") #f)
                     (let collect ((acc ""))
                       (receive (after 3000 (tcp-close! c) (send me (vector 'n acc)))
                         (`#(tcp-data ,bv)
                           (collect (string-append acc (utf8->string bv))))
                         (`#(tcp-eof) (tcp-close! c) (send me (vector 'n acc)))))))))
        (let ((text (receive (after 9000 #f) (`#(n ,t) t))))
          (check "a normal stream still delivers its body"
            (and text (let loop ((i 0))
                        (cond ((> (+ i 5) (string-length text)) #f)
                              ((string=? "hello" (substring text i (+ i 5))) #t)
                              (else (loop (+ i 1)))))))
          (check "and its chunked terminator"
            (and text (let loop ((i 0))
                        (cond ((> (+ i 5) (string-length text)) #f)
                              ((string=? "0\r\n\r\n" (substring text i (+ i 5))) #t)
                              (else (loop (+ i 1)))))))))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "stream-abandoned: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
