#!chezscheme
;;; (igropyr http-client) streaming responses: on-chunk delivery over the
;;; three body modes (chunked / content-length / read-until-close),
;;; idle-timeout semantics, and handler-crash surfacing. The chunked
;;; case is the acceptance shape for SSE-over-chunked upstreams
;;; (Gemini streamGenerateContent alt=sse).

(import (chezscheme) (igropyr http) (igropyr express) (igropyr http-client)
        (igropyr libuv))

(define port 18091)
(define raw-port 18092)
(define bad-port 18093)
(define head-port 18094)
(define interim-port 18095)
(define framing-port 18100)
(define framing-base
  (string-append "http://127.0.0.1:" (number->string framing-port)))

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

;; naive substring test, for the raw HEAD server to branch on the path
(define (str-has? hay needle)
  (let ((hn (string-length hay)) (nn (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i nn) hn) #f)
            ((string=? (substring hay i (+ i nn)) needle) #t)
            (else (loop (+ i 1)))))))

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
;; Keep resetting the connection actor's idle timer until after the
;; caller-facing total deadline, then finish so a surviving child would
;; leave a stale reply in the caller's mailbox.
(app-get app "/late-finish"
  (lambda (req res)
    (sse-start! res)
    (spawn
      (lambda ()
        (do ((i 0 (+ i 1))) ((= i 30))
          (res-write! res "x")
          (sleep-ms 100))
        (res-end! res)))))
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

;; raw server answering with malformed chunk framing: both decoders must
;; reject a negative size, and the streaming decoder must reject a bad data
;; delimiter before exposing that chunk to its caller.
(define (start-badchunk-server!)
  (tcp-listen! "0.0.0.0" bad-port 16
    (lambda (c)
      (let ((pid (spawn
                   (lambda ()
                     (receive
                       (`#(tcp-data ,bv)
                         (let ((req (guard (e (#t "")) (utf8->string bv))))
                           (tcp-write! c (string->utf8
                                           (string-append
                                             "HTTP/1.1 200 OK\r\n"
                                             "Transfer-Encoding: chunked\r\n\r\n"
                                             (if (str-has? req " /separator ")
                                                 "3\r\nabcXX0\r\n\r\n"
                                                 "-2\r\nxx\r\n0\r\n\r\n"))) #f))
                         (sleep-ms 200)
                         (tcp-close! c))
                       (`#(tcp-eof) (tcp-close! c))
                       (`#(tcp-error ,e) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

;; a raw server that answers HEAD with real headers -- Content-Length set --
;; but NO body, exactly as S3 does. A client that is not HEAD-aware would
;; block here waiting for a body that never comes.
(define (start-head-server!)
  (tcp-listen! "0.0.0.0" head-port 16
    (lambda (c)
      (let ((pid (spawn
                   (lambda ()
                     (receive
                       (`#(tcp-data ,bv)
                         (let ((req (guard (e (#t "")) (utf8->string bv))))
                           (tcp-write! c
                             (string->utf8
                               (if (str-has? req "missing")
                                   "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                   (string-append
                                     "HTTP/1.1 200 OK\r\n"
                                     "Content-Length: 42\r\n"    ; a body we never send
                                     "x-amz-restore: ongoing-request=\"false\"\r\n"
                                     "Connection: close\r\n\r\n")))
                             #f))
                         (sleep-ms 40)
                         (tcp-close! c))
                       (`#(tcp-eof) (tcp-close! c))
                       (`#(tcp-error ,e) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

;; a raw server that emits 1xx interim response(s) before the real one: the
;; client must SKIP the interim (100 Continue / 103 Early Hints) and return
;; the final status, not hand the 1xx back as the reply.
(define (start-interim-server!)
  (tcp-listen! "0.0.0.0" interim-port 16
    (lambda (c)
      (let ((pid (spawn
                   (lambda ()
                     (receive
                       (`#(tcp-data ,bv)
                         (let ((req (guard (e (#t "")) (utf8->string bv))))
                           (cond
                             ;; 103 then 200, split across two writes so the
                             ;; parser must resume from 'head after the interim
                             ((str-has? req "early-hints")
                              (tcp-write! c (string->utf8
                                "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n") #f)
                              (sleep-ms 20)
                              (tcp-write! c (string->utf8
                                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello") #f))
                             ;; 100 Continue then 201, one write
                             ((str-has? req "continue")
                              (tcp-write! c (string->utf8
                                (string-append
                                  "HTTP/1.1 100 Continue\r\n\r\n"
                                  "HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")) #f))
                             ;; two interims back to back, then the real 200
                             (else
                              (tcp-write! c (string->utf8
                                (string-append
                                  "HTTP/1.1 100 Continue\r\n\r\n"
                                  "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
                                  "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nyay")) #f))))
                         (sleep-ms 40)
                         (tcp-close! c))
                       (`#(tcp-eof) (tcp-close! c))
                       (`#(tcp-error ,e) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

;; Response framing fields must describe one unambiguous body. This raw
;; server deliberately emits conflicts and duplicates that a proxy and this
;; client could otherwise interpret differently.
(define (start-framing-server!)
  (tcp-listen! "0.0.0.0" framing-port 16
    (lambda (c)
      (let ((pid (spawn
                   (lambda ()
                     (receive
                       (`#(tcp-data ,bv)
                         (let* ((req (guard (e (#t "")) (utf8->string bv)))
                                (resp
                                 (cond
                                   ((str-has? req " /both ")
                                    (string-append
                                      "HTTP/1.1 200 OK\r\n"
                                      "Transfer-Encoding: chunked\r\n"
                                      "Content-Length: 3\r\n\r\n"
                                      "3\r\nabc\r\n0\r\n\r\n"))
                                   ((str-has? req " /cl-conflict ")
                                    (string-append
                                      "HTTP/1.1 200 OK\r\n"
                                      "Content-Length: 5\r\n"
                                      "Content-Length: 6\r\n\r\nhello!"))
                                   ((str-has? req " /cl-same ")
                                    (string-append
                                      "HTTP/1.1 200 OK\r\n"
                                      "Content-Length: 5\r\n"
                                      "Content-Length: 5\r\n\r\nhello"))
                                   ((str-has? req " /te-duplicate ")
                                    (string-append
                                      "HTTP/1.1 200 OK\r\n"
                                      "Transfer-Encoding: chunked\r\n"
                                      "Transfer-Encoding: chunked\r\n\r\n"
                                      "3\r\nabc\r\n0\r\n\r\n"))
                                   (else
                                    (string-append
                                      "HTTP/1.1 200 OK\r\n"
                                      "Transfer-Encoding: gzip\r\n"
                                      "Connection: close\r\n\r\nabc")))))
                           (tcp-write! c (string->utf8 resp) #f))
                         (sleep-ms 40)
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
    (start-head-server!)
    (start-interim-server!)
    (start-framing-server!)
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

    ;; HEAD: real headers + Content-Length but no body -- the client must
    ;; return at once (not block) with an empty body and the headers intact
    (let ((r (http-request 'HEAD
               (string-append "http://127.0.0.1:" (number->string head-port) "/present"))))
      (check "head-status-200" (= 200 (response-status r)))
      (check "head-empty-body" (= 0 (bytevector-length (response-body r))))
      (check "head-headers-intact"
        (equal? (response-header r 'x-amz-restore) "ongoing-request=\"false\"")))
    (let ((r (http-request 'HEAD
               (string-append "http://127.0.0.1:" (number->string head-port) "/missing"))))
      (check "head-status-404" (= 404 (response-status r))))

    ;; 1xx interim responses (100/103) must be skipped, not returned as the
    ;; final reply -- the client keeps reading for the real status
    (let ((r (http-get (string-append "http://127.0.0.1:" (number->string interim-port) "/early-hints"))))
      (check "interim-103-status" (= 200 (response-status r)))
      (check "interim-103-body" (equal? (utf8->string (response-body r)) "hello")))
    (let ((r (http-get (string-append "http://127.0.0.1:" (number->string interim-port) "/continue"))))
      (check "interim-100-status" (= 201 (response-status r)))
      (check "interim-100-body" (equal? (utf8->string (response-body r)) "ok")))
    (let ((r (http-get (string-append "http://127.0.0.1:" (number->string interim-port) "/multi"))))
      (check "interim-multi-status" (= 200 (response-status r)))
      (check "interim-multi-body" (equal? (utf8->string (response-body r)) "yay")))

    (check "transfer-encoding-plus-content-length"
      (equal? (client-error-message
                (lambda () (http-get (string-append framing-base "/both"))))
              "ambiguous response framing"))
    (check "conflicting-content-length"
      (equal? (client-error-message
                (lambda () (http-get (string-append framing-base "/cl-conflict"))))
              "invalid Content-Length"))
    (let ((r (http-get (string-append framing-base "/cl-same"))))
      (check "identical-content-length-accepted"
        (equal? (utf8->string (response-body r)) "hello")))
    (check "duplicate-transfer-encoding"
      (equal? (client-error-message
                (lambda () (http-get (string-append framing-base "/te-duplicate"))))
              "invalid Transfer-Encoding"))
    (check "unsupported-transfer-encoding"
      (equal? (client-error-message
                (lambda () (http-get (string-append framing-base "/te-unsupported"))))
              "invalid Transfer-Encoding"))

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
    ;; Framing and routing headers are owned by the serializer. Allowing a
    ;; caller to duplicate them creates request-smuggling differentials.
    (for-each
      (lambda (name)
        (check (string-append "managed-header-" name)
          (equal? (client-error-message
                    (lambda ()
                      (http-get
                        (string-append "http://127.0.0.1:"
                                       (number->string port) "/sse")
                        `((headers . ((,name . "attacker")))))))
                  (string-append "header is managed by the client: " name))))
      '("Host" "Connection" "Content-Length" "Transfer-Encoding"))
    ;; Accumulating requests have a total deadline in addition to the
    ;; connection actor's idle deadline. The timed-out actor must not later
    ;; deliver a completed reply into the caller's mailbox.
    (check "total-timeout"
      (equal? (client-error-message
                (lambda ()
                  (http-get
                    (string-append "http://127.0.0.1:"
                                   (number->string port) "/late-finish")
                    '((timeout . 200)))))
              "request timeout"))
    (check "total-timeout-kills-child"
      (receive (after 1500 #t)
        (`#(http-reply ,_ ,_) #f)))
    ;; The stale reply above is only half the invariant; the other half is
    ;; that timing out FREES the TLS codec. An identity codec whose close!
    ;; counts stands in for TLS -- no OpenSSL needed -- and the plain HTTP
    ;; server cannot tell the difference. This pins the deadline running
    ;; inside the connection process (err! -> done!): a caller-side kill
    ;; would strand the count at 0, because a killed process runs neither
    ;; its winders nor its guards.
    (let ((codec-closes (box 0)))
      (set-https-connector!
        (lambda (c host timeout)
          (vector (lambda (bv) bv)
                  (lambda (bv) bv)
                  (lambda () (set-box! codec-closes (+ 1 (unbox codec-closes))))
                  #f)))
      (check "total-timeout-frees-codec"
        (and (equal? (client-error-message
                       (lambda ()
                         (http-get
                           (string-append "https://127.0.0.1:"
                                          (number->string port) "/late-finish")
                           '((timeout . 200)))))
                     "request timeout")
             (begin (sleep-ms 200) (= (unbox codec-closes) 1)))))
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

    (let-values (((b collect) (collector)))
      (check "bad-chunk-separator-stream"
        (equal? (client-error-message
                  (lambda ()
                    (http-get
                      (string-append "http://127.0.0.1:"
                                     (number->string bad-port) "/separator")
                      `((on-chunk . ,collect)))))
                "bad chunked response"))
      (check "bad-chunk-not-emitted" (null? (collected b))))

    ;; a crashing handler surfaces as a typed client error, not a hang
    (check "handler-crash"
      (equal? (client-error-message
                (lambda ()
                  (http-get (string-append "http://127.0.0.1:" (number->string port) "/sse")
                            `((on-chunk . ,(lambda (bv) (raise 'boom)))))))
              "on-chunk handler raised"))

    (if (zero? failures)
        (begin (display "http-client-stream: all tests passed") (newline) (exit 0))
        (begin (display failures) (display " failures") (newline) (exit 1)))))
