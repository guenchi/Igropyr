#!chezscheme
;;; (igropyr client) streaming responses: on-chunk delivery over the
;;; three body modes (chunked / content-length / read-until-close),
;;; idle-timeout semantics, and handler-crash surfacing. The chunked
;;; case is the acceptance shape for SSE-over-chunked upstreams
;;; (Gemini streamGenerateContent alt=sse).

(import (chezscheme) (igropyr http) (igropyr express) (igropyr client)
        (igropyr libuv))

(define port 18091)
(define raw-port 18092)
(define bad-port 18093)

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (client-error-message thunk)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'http-client-error))
             (vector-ref e 1)))
    (thunk)
    'no-error))

(define (bv-concat* lst)
  (let* ((total (apply + (map bytevector-length lst)))
         (out (make-bytevector total)))
    (let loop ((l lst) (off 0))
      (if (null? l)
          out
          (let ((x (car l)))
            (bytevector-copy! x 0 out off (bytevector-length x))
            (loop (cdr l) (+ off (bytevector-length x))))))))

;; collect chunks through a box; on-chunk runs in the connection's
;; process, and http-request returns only after the stream is done, so
;; the box is complete when read
(define (collector)
  (let ((b (box '())))
    (values b (lambda (bv) (set-box! b (cons bv (unbox b)))))))

(define (collected b) (reverse (unbox b)))

;; ---- the app -----------------------------------------------------------

(define big-body (make-string 200000 #\x))

(define app (create-app))
;; five SSE events, dripped: five chunked-transfer chunks on the wire
(app-get app "/sse"
  (lambda (req res)
    (sse-start! res)
    (spawn
      (lambda ()
        (do ((i 0 (+ i 1))) ((= i 5))
          (sse-send! res (string-append "e" (number->string i)))
          (sleep-ms 40))
        (res-end! res)))))
;; slow drip for the no-idle-timeout mode
(app-get app "/slow"
  (lambda (req res)
    (sse-start! res)
    (spawn
      (lambda ()
        (do ((i 0 (+ i 1))) ((= i 3))
          (sse-send! res "tick")
          (sleep-ms 300))
        (res-end! res)))))
;; opens a stream and never sends: the idle timeout must reap it
(app-get app "/never"
  (lambda (req res)
    (sse-start! res)))
;; counted body, streamed by the client
(app-get app "/big" (lambda (req res) (send-text! res big-body)))

;; raw server for the read-until-close mode (the framework always sets
;; content-length or chunked, so this one is hand-rolled): headers, two
;; dripped body pieces, then close
(define (start-eof-server!)
  (tcp-listen! "0.0.0.0" raw-port 16
    (lambda (c)
      (let ((pid (spawn
                   (lambda ()
                     (receive
                       (`#(tcp-data ,bv)
                         (tcp-write! c (string->utf8
                                         "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhel") #f)
                         (sleep-ms 80)
                         (tcp-write! c (string->utf8 "lo") #f)
                         (sleep-ms 40)
                         (tcp-close! c))
                       (`#(tcp-eof) (tcp-close! c))
                       (`#(tcp-error ,e) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

;; raw server answering with a NEGATIVE chunk size: both decoders must
;; reject it as a bad chunked response, not misframe the stream or spin
(define (start-badchunk-server!)
  (tcp-listen! "0.0.0.0" bad-port 16
    (lambda (c)
      (let ((pid (spawn
                   (lambda ()
                     (receive
                       (`#(tcp-data ,bv)
                         (tcp-write! c (string->utf8
                                         (string-append
                                           "HTTP/1.1 200 OK\r\n"
                                           "Transfer-Encoding: chunked\r\n\r\n"
                                           "-2\r\nxx\r\n0\r\n\r\n")) #f)
                         (sleep-ms 200)
                         (tcp-close! c))
                       (`#(tcp-eof) (tcp-close! c))
                       (`#(tcp-error ,e) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

;; ---- tests -----------------------------------------------------------------

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (start-eof-server!)
    (start-badchunk-server!)
    (sleep-ms 100)

    ;; chunked (SSE) streaming: one emit per wire chunk, in order,
    ;; empty final body
    (let-values (((b collect) (collector)))
      (let ((r (http-get (string-append "http://127.0.0.1:" (number->string port) "/sse")
                         `((on-chunk . ,collect)))))
        (check "sse-status" (= (response-status r) 200))
        (check "sse-body-empty" (= 0 (bytevector-length (response-body r))))
        (check "sse-chunk-count" (= 5 (length (collected b))))
        (check "sse-order"
          (equal? (utf8->string (bv-concat* (collected b)))
                  "data: e0\n\ndata: e1\n\ndata: e2\n\ndata: e3\n\ndata: e4\n\n"))))

    ;; the same URL without on-chunk still accumulates (regression)
    (let ((r (http-get (string-append "http://127.0.0.1:" (number->string port) "/sse"))))
      (check "sse-accumulated"
        (equal? (utf8->string (response-body r))
                "data: e0\n\ndata: e1\n\ndata: e2\n\ndata: e3\n\ndata: e4\n\n")))

    ;; counted body streaming: all bytes delivered, none retained
    (let-values (((b collect) (collector)))
      (let ((r (http-get (string-append "http://127.0.0.1:" (number->string port) "/big")
                         `((on-chunk . ,collect)))))
        (check "clen-body-empty" (= 0 (bytevector-length (response-body r))))
        (check "clen-total"
          (= (string-length big-body)
             (apply + (map bytevector-length (collected b)))))
        (check "clen-content"
          (equal? (utf8->string (bv-concat* (collected b))) big-body))))

    ;; read-until-close streaming (raw server, no framing headers)
    (let-values (((b collect) (collector)))
      (let ((r (http-get (string-append "http://127.0.0.1:" (number->string raw-port) "/")
                         `((on-chunk . ,collect)))))
        (check "eof-status" (= (response-status r) 200))
        (check "eof-body-empty" (= 0 (bytevector-length (response-body r))))
        (check "eof-content"
          (equal? (utf8->string (bv-concat* (collected b))) "hello"))))

    ;; timeout 0 = no idle limit: a slow drip still completes
    (let-values (((b collect) (collector)))
      (let ((r (http-get (string-append "http://127.0.0.1:" (number->string port) "/slow")
                         `((on-chunk . ,collect) (timeout . 0)))))
        (check "no-idle-completes" (= 3 (length (collected b))))))

    ;; a silent stream is reaped by the idle timeout
    (check "idle-timeout"
      (equal? (client-error-message
                (lambda ()
                  (http-get (string-append "http://127.0.0.1:" (number->string port) "/never")
                            `((on-chunk . ,(lambda (bv) bv)) (timeout . 200)))))
              "response timeout"))
    ;; a non-procedure on-chunk is rejected before any connection
    (check "bad-on-chunk-rejected"
      (equal? (client-error-message
                (lambda ()
                  (http-get (string-append "http://127.0.0.1:" (number->string port) "/sse")
                            '((on-chunk . not-a-procedure)))))
              "on-chunk must be a procedure"))
    ;; timeout 0 means "no idle limit" and only streams may ask for it:
    ;; a plain request with no deadline could only hang, so it is
    ;; rejected loudly (it used to be a silent forever-park)
    (check "plain-timeout-0-rejected"
      (equal? (client-error-message
                (lambda ()
                  (http-get (string-append "http://127.0.0.1:" (number->string port) "/sse")
                            '((timeout . 0)))))
              "timeout 0 (no idle limit) requires on-chunk streaming"))
    (check "non-integer-timeout-rejected"
      (equal? (client-error-message
                (lambda ()
                  (http-get (string-append "http://127.0.0.1:" (number->string port) "/sse")
                            '((timeout . 1500.5)))))
              "timeout must be a nonnegative exact integer (milliseconds)"))

    ;; a negative chunk size is rejected by BOTH decoders (shared
    ;; chunk-size parser), streaming and accumulating alike
    (check "neg-chunk-stream"
      (equal? (client-error-message
                (lambda ()
                  (http-get (string-append "http://127.0.0.1:" (number->string bad-port) "/")
                            `((on-chunk . ,(lambda (bv) bv))))))
              "bad chunked response"))
    (check "neg-chunk-plain"
      (equal? (client-error-message
                (lambda ()
                  (http-get (string-append "http://127.0.0.1:" (number->string bad-port) "/"))))
              "bad chunked response"))

    ;; a crashing handler surfaces as a typed client error, not a hang
    (check "handler-crash"
      (equal? (client-error-message
                (lambda ()
                  (http-get (string-append "http://127.0.0.1:" (number->string port) "/sse")
                            `((on-chunk . ,(lambda (bv) (raise 'boom)))))))
              "on-chunk handler raised"))

    (if (zero? failures)
        (begin (display "client-stream: all tests passed") (newline) (exit 0))
        (begin (display failures) (display " failures") (newline) (exit 1)))))
