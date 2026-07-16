#!chezscheme
(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http))

(define port 18080)
(define empty-bv (make-bytevector 0))

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

(define (raw-request text)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'raw-error ref 'connect-timeout)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c (string->utf8 text) #f)
            (let loop ((buf empty-bv))
              (receive (after 3000
                          (tcp-close! c)
                          (send caller (vector 'raw-error ref 'response-timeout)))
                (`#(tcp-data ,bv) (loop (bv-append buf bv)))
                (`#(tcp-eof) (send caller (vector 'raw-reply ref buf)))
                (`#(tcp-error ,e) (send caller (vector 'raw-reply ref buf))))))
          (`#(tcp-connect-failed ,e)
            (send caller (vector 'raw-error ref e))))))
    (receive (after 5000 (raise 'raw-request-timeout))
      (`#(raw-reply ,@ref ,bv) (utf8->string bv))
      (`#(raw-error ,@ref ,e) (raise (vector 'raw-request-error e))))))

;; like raw-request, but the text is written in timed pieces -- drives
;; the reader's resumable paths (header-end scan straddling segments,
;; chunked parse resume) instead of the whole-request-in-one-segment
;; fast path
(define (raw-request-dripped pieces)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'raw-error ref 'connect-timeout)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (for-each
              (lambda (p)
                (tcp-write! c (string->utf8 p) #f)
                (sleep-ms 20))
              pieces)
            (let loop ((buf empty-bv))
              (receive (after 3000
                          (tcp-close! c)
                          (send caller (vector 'raw-error ref 'response-timeout)))
                (`#(tcp-data ,bv) (loop (bv-append buf bv)))
                (`#(tcp-eof) (send caller (vector 'raw-reply ref buf)))
                (`#(tcp-error ,e) (send caller (vector 'raw-reply ref buf))))))
          (`#(tcp-connect-failed ,e)
            (send caller (vector 'raw-error ref e))))))
    (receive (after 8000 (raise 'raw-request-timeout))
      (`#(raw-reply ,@ref ,bv) (utf8->string bv))
      (`#(raw-error ,@ref ,e) (raise (vector 'raw-request-error e))))))

(define (contains? s needle)
  (let ((n (string-length s)) (m (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring s i (+ i m)) needle) #t)
            (else (loop (+ i 1)))))))

(define (expect-dripped label pieces status . body)
  (let ((response (raw-request-dripped pieces)))
    (unless (contains? response (string-append "HTTP/1.1 " status " "))
      (error 'http-protocol label "wrong status" response))
    (when (pair? body)
      (unless (contains? response (car body))
        (error 'http-protocol label "missing response body" response)))
    (display label) (display " ok\n")))

(define (expect label request status . body)
  (let ((response (raw-request request)))
    (unless (contains? response (string-append "HTTP/1.1 " status " "))
      (error 'http-protocol label "wrong status" response))
    (when (pair? body)
      (unless (contains? response (car body))
        (error 'http-protocol label "missing response body" response)))
    (display label) (display " ok\n")))

(define (expect-pipelined-empty-trailer)
  (let* ((body (make-string 9000 #\b))
         (response
           (raw-request
             (string-append
               "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
               "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: "
               (number->string (string-length body))
               "\r\nConnection: close\r\n\r\n"
               body))))
    (unless (contains? response "HTTP/1.1 200 ")
      (error 'http-protocol "pipelined empty trailer" "missing first 200" response))
    (when (contains? response "HTTP/1.1 431 ")
      (error 'http-protocol "pipelined empty trailer" "unexpected 431" response))
    (display "pipelined empty trailer ok\n")))

(define (handler req res)
  (set-header! res "Content-Type" "text/plain")
  (if (string=? (req-path req) "/query")
      (let ((p (assoc "token" (req-query req))))
        (res-send! res (string->utf8 (if p (cdr p) "missing"))))
      (res-send! res (req-body req))))

(start-scheduler
  (lambda ()
    (http-listen port handler 2)
    (sleep-ms 50)
    (expect "valid chunked+trailer"
      "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\nX-Test: ok\r\n\r\n"
      "200" "abc")
    (expect "chunked OWS"
      "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: \tchunked \r\nConnection: close\r\n\r\n1\r\na\r\n0\r\n\r\n"
      "200" "a")
    (expect "unknown transfer coding"
      "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n"
      "400")
    (expect "duplicate chunked"
      "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\nConnection: close\r\n\r\n"
      "400")
    (expect "TE plus CL"
      "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0\r\n\r\n"
      "400")
    (expect "bad chunk terminator"
      "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\naXX0\r\n\r\n"
      "400")
    (expect "forbidden trailer"
      "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\nContent-Length: 1\r\n\r\n"
      "400")
    (expect "non-ASCII trailer name"
      (string-append
        "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n"
        (string (integer->char #x00e9)) ": x\r\n\r\n")
      "400")
    (expect "oversized trailer"
      (string-append
        "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\nX-Large: "
        (make-string 8200 #\a) "\r\n\r\n")
      "431")
    (expect-pipelined-empty-trailer)
    (expect "query equals"
      "GET /query?token=a=b=c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
      "200" "a=b=c")
    ;; obs-fold (continuation line) and colonless lines reject the head:
    ;; silently dropping a line a fronting proxy may have honored is
    ;; request-smuggling room
    (expect "obs-fold rejected"
      "GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n folded\r\nConnection: close\r\n\r\n"
      "400")
    (expect "colonless header rejected"
      "GET / HTTP/1.1\r\nHost: x\r\ngarbage-line\r\nConnection: close\r\n\r\n"
      "400")
    ;; header values are OWS-trimmed on both ends: a trailing space must
    ;; not turn Connection: close into keep-alive (this test would time
    ;; out waiting for eof if it did), and a tab before Content-Length
    ;; is legal
    (expect "connection close with trailing space"
      "GET / HTTP/1.1\r\nHost: x\r\nConnection: close \r\n\r\n"
      "200")
    (expect "content-length after tab"
      "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length:\t3\r\nConnection: close\r\n\r\nabc"
      "200" "abc")
    ;; version is validated, not silently treated as 1.0
    (expect "unsupported version"
      "GET / HTTP/9.9\r\nHost: x\r\nConnection: close\r\n\r\n"
      "505")
    ;; Expect: 100-continue gets the interim response before the final one
    (expect "expect-100 interim"
      "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nabc"
      "100")
    (expect "expect-100 final"
      "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nabc"
      "200" "abc")
    ;; dripped delivery drives the resumable paths: the header-end scan
    ;; straddling segments, content-length bodies arriving in pieces,
    ;; and the chunked parser resuming mid-chunk without re-parsing
    (expect-dripped "dripped header"
      '("GET / HTT" "P/1.1\r\nHost: x\r\nConnection: close\r\n\r" "\n")
      "200")
    (expect-dripped "dripped body"
      '("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nConnection: close\r\n\r\n"
        "abc" "def")
      "200" "abcdef")
    (expect-dripped "dripped chunked"
      '("POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        "3\r" "\nab" "c\r\n" "3\r\ndef\r\n" "0\r\n" "\r\n")
      "200" "abcdef")
    ;; ---- configurable body-limit -----------------------------------
    ;; PROCESS-GLOBAL (last http-listen wins), so these run LAST: the
    ;; second listen lowers the limit for every server in this process.
    (unless (guard (e ((assertion-violation? e) #t) (#t #f))
              (http-listen 18082 handler '((body-limit . "big")))
              #f)
      (error 'http-protocol "bad body-limit accepted" "no assertion"))
    (display "bad body-limit rejected at boot ok\n")
    (http-listen 18081 handler '((workers . 2) (body-limit . 100)))
    (set! port 18081)
    (expect "body under configured limit"
      (string-append
        "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\nConnection: close\r\n\r\n"
        (make-string 50 #\a))
      "200")
    (expect "body over configured limit"
      (string-append
        "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 200\r\nConnection: close\r\n\r\n"
        (make-string 200 #\a))
      "413")
    (expect "chunked over configured limit"
      (string-append
        "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        "40\r\n" (make-string 64 #\a) "\r\n40\r\n" (make-string 64 #\a) "\r\n0\r\n\r\n")
      "413")
    (display "ALL HTTP PROTOCOL TESTS PASSED\n")
    (exit 0)))
