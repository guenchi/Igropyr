#!chezscheme
;;; A concurrent responder must linearize with session rotation: either the
;;; fresh Set-Cookie is in the claimed header snapshot, or regeneration
;;; refuses before dropping the old store entry. A separate res-answered?
;;; check leaves a check/use window between those two effects.

(import (chezscheme) (igropyr actor) (igropyr express) (igropyr http)
        (igropyr libuv) (igropyr tcp) (igropyr session))

(define port 18814)
(define failures 0)

(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (fail label detail)
  (display "FAIL ") (display label) (display ": ") (write detail) (newline)
  (exit 1))

(define (find-substr hay needle)
  (let ((n (string-length hay)) (m (string-length needle)))
    (let loop ((i 0))
      (cond
        ((> (+ i m) n) #f)
        ((string=? (substring hay i (+ i m)) needle) i)
        (else (loop (+ i 1)))))))

(define (extract-sid response)
  (let ((at (find-substr response "sid=")))
    (and at
         (let scan ((i (+ at 4)))
           (if (or (= i (string-length response))
                   (memv (string-ref response i) '(#\; #\return #\newline)))
               (substring response (+ at 4) i)
               (scan (+ i 1)))))))

(define (join-bytevectors chunks total)
  (let ((out (make-bytevector total)))
    (let loop ((rest (reverse chunks)) (at 0))
      (if (null? rest)
          out
          (let* ((bv (car rest)) (n (bytevector-length bv)))
            (bytevector-copy! bv 0 out at n)
            (loop (cdr rest) (+ at n)))))))

(define (http-get path . headers)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'http-error ref 'connect)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c
              (string->utf8
                (string-append "GET " path " HTTP/1.1\r\nHost: x\r\n"
                  (apply string-append
                    (map (lambda (h) (string-append h "\r\n")) headers))
                  "Connection: close\r\n\r\n"))
              #f)
            (let loop ((chunks '()) (total 0))
              (receive (after 10000
                          (tcp-close! c)
                          (send caller (vector 'http-error ref 'timeout)))
                (`#(tcp-data ,bv)
                  (loop (cons bv chunks) (+ total (bytevector-length bv))))
                (`#(tcp-eof)
                  (send caller (vector 'http-response ref
                                 (utf8->string
                                   (join-bytevectors chunks total)))))
                (`#(tcp-error ,_)
                  (send caller (vector 'http-response ref
                                 (utf8->string
                                   (join-bytevectors chunks total))))))))
          (`#(tcp-connect-failed ,e)
            (send caller (vector 'http-error ref e))))))
    (receive (after 15000 (fail "http-get" 'timeout))
      (`#(http-response ,@ref ,response) response)
      (`#(http-error ,@ref ,e) (fail "http-get" e)))))

(define store (make-session-store))
(define app (create-app))

;; The long, valid Path keeps cookie construction in progress across several
;; scheduler ticks. The responder wakes after the old code's answered? check
;; but before its later set-header!, making the TOCTOU deterministic.
(define long-path (string-append "/" (make-string (* 4 1024 1024) #\a)))
(app-use app
  (session-middleware store
    `((secure . #f) (path . ,long-path))))

(app-get app "/seed"
  (lambda (req res)
    (session-set! (req-session req) 'marker "kept")
    (send-text! res "seeded")))

(define rotation-outcome 'unrun)
(app-get app "/race"
  (lambda (req res)
    (spawn
      (lambda ()
        (sleep-ms 5)
        (send-text! res "concurrent response")))
    (set! rotation-outcome
      (guard (e (#t 'refused))
        (session-regenerate! (req-session req))
        'rotated))))

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (sleep-ms 100)
    (let* ((seed-response (http-get "/seed"))
           (sid (extract-sid seed-response)))
      (check "seed response contains a session id" sid)
      (check "seed session is persisted"
        (and sid
             (let ((data (session-peek store sid)))
               (and data
                    (let ((marker (assq 'marker data)))
                      (and marker (equal? (cdr marker) "kept")))))))
      (when sid
        (http-get "/race" (string-append "Cookie: sid=" sid))
        (let wait ((left 500))
          (when (and (eq? rotation-outcome 'unrun) (> left 0))
            (sleep-ms 10)
            (wait (- left 1))))
        (check "concurrent response makes rotation refuse"
          (eq? rotation-outcome 'refused))
        (check "refused rotation retains the old session"
          (let ((data (session-peek store sid)))
            (and data
                 (let ((marker (assq 'marker data)))
                   (and marker (equal? (cdr marker) "kept"))))))))
    (if (zero? failures)
        (begin (display "session-rotation-race: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
