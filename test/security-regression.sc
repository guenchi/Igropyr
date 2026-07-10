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

(define (wait-for-conn-count wanted timeout-ms)
  (let ((deadline (+ (now-ms) timeout-ms)))
    (let loop ()
      (cond
        ((= (conn-count) wanted) #t)
        ((>= (now-ms) deadline) #f)
        (else (sleep-ms 10) (loop))))))

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
          (`#(tcp-eof) (tcp-close! c) acc)
          (`#(tcp-error ,e) (tcp-close! c) acc))))
    (`#(tcp-connect-failed ,e) (fail "client connect failed" e))))

(define (raw-http request)
  (utf8->string (raw-exchange (string->utf8 request))))

;; Write chunks separately with a scheduler turn between them so the server
;; exercises fragmented reads and cursor-buffer growth/compaction.
(define (raw-exchange-chunks chunks)
  (tcp-connect! "127.0.0.1" port self)
  (receive (after 2000 (fail "fragmented client connect timeout"))
    (`#(tcp-connected ,c)
      (tcp-read-start! c)
      (for-each
        (lambda (chunk)
          (tcp-write! c chunk #f)
          (sleep-ms 2))
        chunks)
      (let loop ((acc (make-bytevector 0)))
        (receive (after 5000 (tcp-close! c) (fail "fragmented response timeout"))
          (`#(tcp-data ,bv) (loop (bv-append acc bv)))
          (`#(tcp-eof) (tcp-close! c) acc)
          (`#(tcp-error ,e) (tcp-close! c) acc))))
    (`#(tcp-connect-failed ,e) (fail "fragmented client connect failed" e))))

(define (raw-http-chunks chunks)
  (utf8->string (raw-exchange-chunks (map string->utf8 chunks))))

(define (raw-writev-exchange chunks)
  (let ((done-count (box 0)))
    (tcp-connect! "127.0.0.1" port self)
    (receive (after 2000 (fail "writev client connect timeout"))
      (`#(tcp-connected ,c)
        (tcp-read-start! c)
        (tcp-writev! c chunks
          (lambda (status)
            (when (>= status 0)
              (set-box! done-count (+ (unbox done-count) 1)))))
        (let loop ((acc (make-bytevector 0)))
          (receive (after 5000 (tcp-close! c) (fail "writev response timeout"))
            (`#(tcp-data ,bv) (loop (bv-append acc bv)))
            (`#(tcp-eof)
              (tcp-close! c)
              (values acc (unbox done-count)))
            (`#(tcp-error ,e)
              (tcp-close! c)
              (values acc (unbox done-count))))))
      (`#(tcp-connect-failed ,e) (fail "writev client connect failed" e)))))

(define (writev-after-close-result)
  (let ((done-count (box 0)) (done-status (box #f)))
    (tcp-connect! "127.0.0.1" port self)
    (receive (after 2000 (fail "closed writev connect timeout"))
      (`#(tcp-connected ,c)
        (tcp-close! c)
        (tcp-writev! c (vector (string->utf8 "too-late"))
          (lambda (status)
            (set-box! done-count (+ (unbox done-count) 1))
            (set-box! done-status status)))
        (sleep-ms 10)
        (values (unbox done-count) (unbox done-status)))
      (`#(tcp-connect-failed ,e) (fail "closed writev connect failed" e)))))

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

(define (string-count s needle)
  (let ((sn (string-length s)) (nn (string-length needle)))
    (let loop ((i 0) (count 0))
      (cond
        ((> (+ i nn) sn) count)
        ((string=? (substring s i (+ i nn)) needle)
         (loop (+ i nn) (+ count 1)))
        (else (loop (+ i 1) count))))))

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

(define mutable-header-value (make-string 1 #\a))
(app-get app "/mutable-header"
  (lambda (req res)
    (set-header! res "X-Mutable" mutable-header-value)
    (send-text! res "mutable")
    (string-set! mutable-header-value 0
      (if (char=? (string-ref mutable-header-value 0) #\a) #\b #\a))))

(app-get app "/delay"
  (lambda (req res)
    (sleep-ms 20)
    (send-text! res "delayed")))

(app-post app "/echo"
  (lambda (req res)
    (set-header! res "Content-Type" "application/octet-stream")
    (res-send! res (req-body req))))

(app-get app "/stream"
  (lambda (req res)
    (res-begin! res)
    (res-write! res "abc")
    (res-write! res (make-bytevector 0))
    (res-end! res)))

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

    ;; app-fast-predicate must observe live route mutations even though its
    ;; empty-list hot path avoids splitting every pooled request path.
    (app-get-fast app "/late-fast"
      (lambda (req res) (send-text! res "late-fast")))
    (check "fast route added after listen remains live"
      (let ((r (raw-http
                 "GET /late-fast HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
        (and (status-is? r 200) (string-contains? r "late-fast"))))

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

    (check "response-head cache handles mutable header strings"
      (let ((first (raw-http
                     "GET /mutable-header HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
            (second (raw-http
                      "GET /mutable-header HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
        (and (string-contains? first "X-Mutable: a")
             (string-contains? second "X-Mutable: b"))))

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

    (check "header parses at every fragmented byte boundary"
      (let* ((request
               "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
             (n (string-length request)))
        (let loop ((i 1))
          (or (= i n)
              (let ((reply
                      (raw-http-chunks
                        (list (substring request 0 i)
                              (substring request i n)))))
                (and (status-is? reply 200) (loop (+ i 1))))))))

    (check "Content-Length body parses at every body boundary"
      (let ((head
              "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nConnection: close\r\n\r\n")
            (body "abcdef"))
        (let loop ((i 0))
          (or (> i (string-length body))
              (let ((reply
                      (raw-http-chunks
                        (list (string-append head (substring body 0 i))
                              (substring body i (string-length body))))))
                (and (status-is? reply 200)
                     (string-contains? reply "abcdef")
                     (loop (+ i 1))))))))

    (check "chunked body parses one byte at a time"
      (let* ((head
               "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
             (wire "3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n")
             (chunks
               (cons head
                 (map string
                      (string->list wire))))
             (reply (raw-http-chunks chunks)))
        (and (status-is? reply 200) (string-contains? reply "abcdef"))))

    (check "pipelined requests share one read buffer"
      (let ((reply
              (raw-http
                (string-append
                  "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                  "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))))
        (= (string-count reply "HTTP/1.1 200 OK") 2)))

    (check "cursor buffer compacts a partial pipelined request"
      (let* ((first "GET /delay HTTP/1.1\r\nHost: x\r\n\r\n")
             (second "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
             (cut 17)
             (reply
               (raw-http-chunks
                 (list (string-append first (substring second 0 cut))
                       (substring second cut (string-length second))))))
        (= (string-count reply "HTTP/1.1 200 OK") 2)))

    (check "tcp-writev handles multiple segments and one callback"
      (let* ((body (make-bytevector 131072 (char->integer #\x)))
             (head
               (string->utf8
                 (string-append
                   "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: "
                   (number->string (bytevector-length body))
                   "\r\nConnection: close\r\n\r\n"))))
        (let-values (((reply done-count)
                      (raw-writev-exchange
                        (vector head (make-bytevector 0) body))))
          (and (= done-count 1)
               (> (bytevector-length reply) (bytevector-length body))
               (= (bytevector-u8-ref reply (- (bytevector-length reply) 1))
                  (char->integer #\x))))))

    (check "streaming response uses valid chunk framing"
      (let ((reply
              (raw-http
                "GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
        (and (string-contains? reply "Transfer-Encoding: chunked")
             (string-contains? reply "\r\n\r\n3\r\nabc\r\n0\r\n\r\n"))))

    (check "tcp-writev closed connection callback runs exactly once"
      (let-values (((done-count done-status) (writev-after-close-result)))
        (and (= done-count 1) (< done-status 0))))

    (check "pipeline overflow closes without retaining connections"
      (and (wait-for-conn-count 0 1000)
           (begin
        (raw-http
          (string-append
            "GET /delay HTTP/1.1\r\nHost: x\r\n\r\n"
            (make-string (+ 8192 1048576 1) #\x)))
             (wait-for-conn-count 0 1000))))

    (tcp-stop-listen!)
    (check "all test TCP connections are released"
      (wait-for-conn-count 0 1000))
    (display "ALL SECURITY REGRESSION TESTS PASSED\n")
    (exit 0)))
