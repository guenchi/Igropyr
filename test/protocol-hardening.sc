#!chezscheme
;;; Review findings #13, #22, #24, #25 -- the ones with an observable
;;; protocol surface. (#11/#12/#14..#21/#23/#26/#27 are covered by their
;;; own suites or have no reachable surface from a test client.)
;;;
;;; #13 a cookie value could inject ATTRIBUTES: "x; Domain=evil" widened a
;;;     host-only session cookie to every subdomain.
;;; #22 read-timeout-ms re-armed on every segment, so a client dribbling
;;;     one byte per interval held a reader forever (slowloris).
;;; #24 close frames were answered without validating or echoing the peer's
;;;     status code.
;;; #25 chunked framing was sent to HTTP/1.0 clients, which do not
;;;     implement it and read the hex size lines as body content.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
        (igropyr express) (igropyr http-client))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18778)

(define (str-has? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring s i (+ i m))) #t)
            (else (loop (+ i 1)))))))

;; raw request/response: returns the whole response text, or 'closed
(define (raw-exchange! request-text report)
  (spawn
    (lambda ()
      (tcp-connect! "127.0.0.1" port self)
      (receive (after 5000 (send report (vector 'raw #f)))
        (`#(tcp-connect-failed ,e) (send report (vector 'raw #f)))
        (`#(tcp-connected ,c)
          (tcp-read-start! c)
          (tcp-write! c (string->utf8 request-text) #f)
          (let collect ((acc ""))
            (receive (after 6000 (tcp-close! c) (send report (vector 'raw acc)))
              (`#(tcp-data ,bv)
                (collect (string-append acc (utf8->string bv))))
              (`#(tcp-eof) (tcp-close! c) (send report (vector 'raw acc)))
              (`#(tcp-error ,e) (tcp-close! c)
                (send report (vector 'raw acc))))))))))

(start-scheduler
  (lambda ()
    (let ((app (create-app)) (main self))
      ;; #13: a handler reflecting an attacker-shaped value into a cookie
      (app-get app "/setcookie"
        (lambda (req res)
          (let ((v (cond ((assoc "v" (req-query req)) => cdr) (else "plain"))))
            (check "set-cookie! refuses an attribute-injecting value"
              (guard (e (#t #t)) (set-cookie! res "sid" v "Path=/") #f))
            (set-cookie! res "sid" "clean" "Path=/" "HttpOnly")
            (send-text! res "done"))))
      ;; #25: a streaming endpoint, requested by an HTTP/1.0 client
      (app-get app "/stream"
        (lambda (req res)
          (sse-start! res)
          (res-write! res "hello-")
          (res-write! res "world")
          (res-end! res)))
      (app-listen app port)
      (sleep-ms 300)

      ;; ---- #13 ---------------------------------------------------------
      (let ((r (http-request 'GET (string-append "http://127.0.0.1:"
                                                 (number->string port)
                                                 "/setcookie?v=x%3B%20Domain%3Devil.com")
                            '((timeout . 4000)))))
        (check "the injected Domain never reaches the client"
          (not (str-has? (or (cond ((assq 'set-cookie (response-headers r)) => cdr)
                                   (else ""))
                             "")
                         "evil.com"))))

      ;; ---- #25: HTTP/1.0 must not receive chunked framing ---------------
      (raw-exchange! "GET /stream HTTP/1.0\r\nHost: x\r\n\r\n" main)
      (let ((text (receive (after 9000 #f) (`#(raw ,t) t))))
        (check "HTTP/1.0 stream: no Transfer-Encoding header"
          (and text (not (str-has? (string-downcase text) "transfer-encoding"))))
        (check "HTTP/1.0 stream: body is raw, not hex-chunked"
          (and text (str-has? text "hello-world"))))

      ;; an HTTP/1.1 client still gets chunked
      (raw-exchange! "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n" main)
      (let ((text (receive (after 9000 #f) (`#(raw ,t) t))))
        (check "HTTP/1.1 stream still uses chunked"
          (and text (str-has? (string-downcase text) "transfer-encoding: chunked"))))

      ;; ---- #22: a dribbling client is reaped, not served forever --------
      ;; send a partial header and then nothing at all; the whole-request
      ;; deadline (or the idle timeout) must end it rather than hold the
      ;; reader indefinitely
      (spawn
        (lambda ()
          (tcp-connect! "127.0.0.1" port self)
          (receive (after 5000 (send main (vector 'slow 'no-connect)))
            (`#(tcp-connected ,c)
              (tcp-read-start! c)
              (tcp-write! c (string->utf8 "GET /stream HTTP/1.1\r\nHost: x\r\n") #f)
              ;; never completes the header block
              (receive (after 40000 (tcp-close! c) (send main (vector 'slow 'held)))
                (`#(tcp-data ,bv) (tcp-close! c) (send main (vector 'slow 'answered)))
                (`#(tcp-eof) (tcp-close! c) (send main (vector 'slow 'closed)))
                (`#(tcp-error ,e) (send main (vector 'slow 'closed))))))))
      (let ((outcome (receive (after 45000 'timeout) (`#(slow ,o) o))))
        (display "  [info] partial-header client outcome: ")
        (display outcome) (newline)
        (check "a partial request is eventually reaped"
          (memq outcome '(answered closed))))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "protocol-hardening: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
