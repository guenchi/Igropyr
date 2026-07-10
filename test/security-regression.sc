;;; Security and protocol regression tests.
;;; Run from the repository root with:
;;;   CHEZSCHEMELIBDIRS=.. CHEZSCHEMELIBEXTS=.sc chez --script test/security-regression.sc

(import (chezscheme)
        (igropyr actor)
        (igropyr uv)
        (igropyr otp)
        (igropyr http)
        (igropyr express)
        (igropyr json)
        (igropyr redis)
        (igropyr mysql)
        (igropyr websocket))

(define port 18991)

(define (fail label . detail)
  (display "FAIL: ") (display label)
  (unless (null? detail) (display " ") (write (car detail)))
  (newline)
  (exit 1))

(define (check label ok?)
  (unless ok? (fail label))
  (display "ok: ") (display label) (newline))

(define (bv-append a b)
  (let* ((la (bytevector-length a))
         (lb (bytevector-length b))
         (r (make-bytevector (+ la lb))))
    (bytevector-copy! a 0 r 0 la)
    (bytevector-copy! b 0 r la lb)
    r))

(define (string-contains? s needle)
  (let ((sn (string-length s)) (nn (string-length needle)))
    (let loop ((i 0))
      (cond
        ((> (+ i nn) sn) #f)
        ((string=? (substring s i (+ i nn)) needle) #t)
        (else (loop (+ i 1)))))))

;; Send one raw bytevector and collect until the server closes the socket.
(define (raw-exchange request)
  (tcp-connect! "127.0.0.1" port self)
  (receive (after 2000 (fail "client connect timeout"))
    (`#(tcp-connected ,c)
      (tcp-read-start! c)
      (tcp-write! c request #f)
      (let loop ((acc (make-bytevector 0)))
        (receive (after 3000 (tcp-close! c) (fail "response timeout" request))
          (`#(tcp-data ,bv) (loop (bv-append acc bv)))
          (`#(tcp-eof) acc)
          (`#(tcp-error ,e) acc))))
    (`#(tcp-connect-failed ,e) (fail "client connect failed" e))))

(define (raw-http request)
  (utf8->string (raw-exchange (string->utf8 request))))

(define (bv-contains? bv bytes)
  (let ((n (bytevector-length bv)) (m (length bytes)))
    (let scan ((i 0))
      (cond
        ((> (+ i m) n) #f)
        ((let loop ((j 0) (xs bytes))
           (or (null? xs)
               (and (= (bytevector-u8-ref bv (+ i j)) (car xs))
                    (loop (+ j 1) (cdr xs))))) #t)
        (else (scan (+ i 1)))))))

(define (status-is? response code)
  (string-contains? response
    (string-append "HTTP/1.1 " (number->string code) " ")))

(define app (create-app))

(app-get app "/" (lambda (req res) (send-text! res "ok")))

;; '+' is literal in a path, but represents space in an urlencoded query.
(app-get app "/a+b"
  (lambda (req res)
    (let ((v (assoc "v" (req-query req))))
      (if (and v (string=? (cdr v) "a=b c"))
          (send-text! res "decoded")
          (begin (set-status! res 400) (send-text! res "bad query"))))))

(app-get app "/headers"
  (lambda (req res)
    (set-header! res "Bad:Name" "value")
    (set-header! res "X-Evil" "ok\r\nInjected: yes")
    (set-header! res "X-Safe" "yes")
    (send-text! res "headers")))

(app-ws app "/ws-test"
  (lambda (ws req) (ws-recv ws)))

(start-scheduler
  (lambda ()
    ;; Parameter validation must fail before starting broken tickers/pools.
    (check "OTP rejects zero workers"
      (guard (e (#t #t))
        (start-worker-pool 0 (lambda (x) x) (lambda (x) x))
        #f))
    (check "JSON rejects non-finite numbers"
      (guard (e (#t #t)) (json->string +nan.0) #f))
    (check "JSON rejects exact numbers overflowing inexact range"
      (guard (e (#t #t))
        (json->string (/ (expt 10 10000) 3))
        #f))
    (check "MySQL ignores stale request refs"
      (let ((fake (spawn
                    (lambda ()
                      (receive
                        (`#(mysql-query ,sql ,ref ,from)
                          (send from (vector 'mysql-reply (gensym) "stale"))
                          (send from (vector 'mysql-reply ref "current"))))))))
        (string=? (mysql-query fake "SELECT 1") "current")))
    (check "Redis ignores stale request refs"
      (let ((fake (spawn
                    (lambda ()
                      (receive
                        (`#(redis-cmd ,args ,ref ,from)
                          (send from (vector 'redis-reply (gensym) "stale"))
                          (send from (vector 'redis-reply ref "current"))))))))
        (string=? (redis fake "PING") "current")))

    (display "starting test HTTP server\n")
    (app-listen app port '((workers . 2) (check-ms . 100)))
    (display "test HTTP server started\n")

    (check "invalid Content-Length"
      (status-is?
        (raw-http
          "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\nConnection: close\r\n\r\n")
        400))

    (check "negative Content-Length"
      (status-is?
        (raw-http
          "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\nConnection: close\r\n\r\n")
        400))

    (check "oversized complete header"
      (status-is?
        (raw-http
          (string-append "GET / HTTP/1.1\r\nHost: x\r\nX-Fill: "
                         (make-string 8200 #\a)
                         "\r\nConnection: close\r\n\r\n"))
        431))

    (check "unsupported Transfer-Encoding"
      (status-is?
        (raw-http
          "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n")
        400))

    (check "chunk data requires CRLF"
      (status-is?
        (raw-http
          (string-append
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
            "Connection: close\r\n\r\n3\r\nabcXX0\r\n\r\n"))
        400))

    (check "path/query percent semantics"
      (let ((r (raw-http
                 "GET /a+b?v=a=b+c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
        (and (status-is? r 200) (string-contains? r "decoded"))))

    (check "Connection token list honors close"
      (status-is?
        (raw-http
          "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n")
        200))

    (check "malformed percent escape"
      (status-is?
        (raw-http
          "GET /bad%2 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        400))

    (check "signed percent escape is rejected"
      (status-is?
        (raw-http
          "GET /bad%+A HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        400))

    (check "response header validation"
      (let ((r (raw-http
                 "GET /headers HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
        (and (string-contains? r "X-Safe: yes")
             (not (string-contains? r "Bad:Name"))
             (not (string-contains? r "Injected: yes")))))

    (check "WebSocket protocol error uses close code 1002"
      (let* ((head
               (string->utf8
                 (string-append
                   "GET /ws-test HTTP/1.1\r\nHost: x\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")))
             ;; Client frames must be masked; this deliberately is not.
             (reply (raw-exchange (bv-append head (bytevector #x81 1 #x78)))))
        (and (bv-contains? reply (map char->integer (string->list "101 Switching Protocols")))
             (bv-contains? reply (list #x88 2 #x03 #xEA)))))

    (tcp-stop-listen!)
    (display "ALL SECURITY REGRESSION TESTS PASSED\n")
    (exit 0)))
