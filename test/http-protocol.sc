#!chezscheme
(import (chezscheme) (igropyr util) (igropyr actor) (igropyr libuv)
        (igropyr http) (only (igropyr express) req-form))

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

(define (expect-dripped label pieces status . body)
  (let ((response (raw-request-dripped pieces)))
    (unless (string-contains? response (string-append "HTTP/1.1 " status " "))
      (error 'http-protocol label "wrong status" response))
    (when (pair? body)
      (unless (string-contains? response (car body))
        (error 'http-protocol label "missing response body" response)))
    (display label) (display " ok\n")))

(define (expect label request status . body)
  (let ((response (raw-request request)))
    (unless (string-contains? response (string-append "HTTP/1.1 " status " "))
      (error 'http-protocol label "wrong status" response))
    (when (pair? body)
      (unless (string-contains? response (car body))
        (error 'http-protocol label "missing response body" response)))
    (display label) (display " ok\n")))

(define (many-chunks n)
  (let-values (((p get) (open-string-output-port)))
    (do ((i 0 (+ i 1))) ((= i n)) (display "1\r\na\r\n" p))
    (display "0\r\n\r\n" p)
    (get)))

;; Content-Length counts BYTES, not characters: a non-ASCII boundary makes
;; the two differ, and a short length would truncate the body -- the server
;; would then find no fields for a reason that has nothing to do with what
;; the test is asserting.
(define (multipart-request boundary body)
  (string-append
    "POST /form HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary="
    boundary "\r\nContent-Length: "
    (number->string (bytevector-length (string->utf8 body)))
    "\r\nConnection: close\r\n\r\n" body))


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
    (unless (string-contains? response "HTTP/1.1 200 ")
      (error 'http-protocol "pipelined empty trailer" "missing first 200" response))
    (when (string-contains? response "HTTP/1.1 431 ")
      (error 'http-protocol "pipelined empty trailer" "unexpected 431" response))
    (display "pipelined empty trailer ok\n")))

(define (handler req res)
  (set-header! res "Content-Type" "text/plain")
  (cond
    ((string=? (req-path req) "/query")
     (let ((p (assoc "token" (req-query req))))
       (res-send! res (string->utf8 (if p (cdr p) "missing")))))
    ((string=? (req-path req) "/form")
     (let ((role (assoc "role" (req-form req))))
       (res-send! res (string->utf8 (if role (cdr role) "safe")))))
    ((string=? (req-path req) "/status204")
     (set-status! res 204)
     (res-send! res (string->utf8 "forbidden-body-204")))
    ((string=? (req-path req) "/status304")
     (set-status! res 304)
     (res-send! res (string->utf8 "forbidden-body-304")))
    ;; The streaming writers are a separate path to the same wire, and the
    ;; one where a bodyless status is easiest to get wrong: announcing
    ;; chunked and then sending the terminator is itself a body.
    ((string=? (req-path req) "/stream204")
     (set-status! res 204)
     (res-begin! res)
     (res-write! res "forbidden-stream-204")
     (res-end! res))
    (else (res-send! res (req-body req)))))

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
    ;; Tiny decoded payloads cannot hide unbounded chunk metadata/count.
    (expect "chunk count limit"
      (string-append
        "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        (many-chunks 16385))
      "413")
    (expect "chunk-size line limit"
      (string-append
        "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        "1;" (make-string 4096 #\a) "\r\nx\r\n0\r\n\r\n")
      "413")
 ;; Boundary-looking bytes inside a file are data, not a new field.
    (let* ((b "AaB03x")
           (body (string-append
                   "--" b "\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"x\"\r\n"
                   "Content-Type: text/plain\r\n\r\n"
                   "hello--" b "\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nadmin\r\n"
                   "--" b "--\r\n")))
      (expect "multipart delimiter anchoring"
        (multipart-request b body) "200" "safe"))
    ;; A boundary rejection has to be pinned with a body that WOULD parse,
    ;; and against a length that would be accepted. With an unparseable body
    ;; there are no fields either way, so "no role field" is true whether or
    ;; not the boundary was ever looked at -- the assertion would hold with
    ;; the length check deleted. One valid body on each side of 70 is what
    ;; separates the two.
    (let ((valid-body
            (lambda (b)
              (string-append
                "--" b "\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nuser\r\n"
                "--" b "--\r\n"))))
      (let ((b (make-string 70 #\a)))
        (expect "boundary at the 70-char limit"
          (multipart-request b (valid-body b)) "200" "user"))
      (let ((b (make-string 71 #\a)))
        (expect "boundary over the 70-char limit"
          (multipart-request b (valid-body b)) "200" "safe"))
      ;; RFC 2046 bchars are ASCII. char-alphabetic? / char-numeric? are
      ;; Unicode-aware in Chez, so spelling the set as ranges is what keeps
      ;; these out.
      (let ((b "Aa\x00e9;B"))                  ; LATIN SMALL LETTER E WITH ACUTE
        (expect "non-ASCII boundary rejected"
          (multipart-request b (valid-body b)) "200" "safe"))
      (let ((b "Aa\x0663;B"))                  ; ARABIC-INDIC DIGIT THREE
        (expect "non-ASCII digit boundary rejected"
          (multipart-request b (valid-body b)) "200" "safe")))
    (let* ((b "Aa B")
           (body (string-append
                   "--" b "\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nuser\r\n"
                   "--" b "--\r\n")))
      (expect "quoted multipart boundary"
        (multipart-request (string-append "\"" b "\"") body) "200" "user"))
    ;; Every payload byte begins an overlapping FULL match for this all-dash
    ;; delimiter. The candidates are then rejected by the line/suffix rules.
    ;; Restarting KMP at candidate+1 repeats the whole 72-byte comparison at
    ;; every byte; retaining the fallback state keeps the scan linear. The
    ;; old test ended the boundary in "x", so it covered repeated prefixes
    ;; but never reached this full-match rejection path.
    (let* ((pboundary (make-string 70 #\-))
           (pbody (string-append
                    "--" pboundary
                    "\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\n"
                    (make-string 750000 #\-)
                    "\r\n--" pboundary "--\r\n"))
           (t0 (real-time)))
      (expect "multipart repeated-prefix search"
        (multipart-request pboundary pbody) "200" "safe")
      ;; ~13 ms linear vs ~100 ms naive, end to end; 50 ms sits between them
      ;; with room on both sides so load does not make this flaky
      (let ((ms (- (real-time) t0)))
        (unless (< ms 50)
          (error 'http-protocol "repeated-prefix search too slow (ms)" ms))))
    ;; Handler-provided bytes are suppressed for bodyless status codes.
    (let ((r (raw-request
               "GET /status204 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
      (unless (and (string-contains? r "HTTP/1.1 204 ")
                   (not (string-contains? r "forbidden-body-204"))
                   (not (string-contains? r "Content-Length:")))
        (error 'http-protocol "204 response carried a body/framing" r))
      (display "204 body suppression ok\n"))
    (let ((r (raw-request
               "GET /status304 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
      (unless (and (string-contains? r "HTTP/1.1 304 ")
                   (not (string-contains? r "forbidden-body-304")))
        (error 'http-protocol "304 response carried a body" r))
      (display "304 body suppression ok\n"))
    ;; Suppression is only half of it: what makes a body on a bodyless
    ;; status dangerous is that the client stops at the blank line, so the
    ;; bytes leak into the NEXT response on a kept-alive connection. Both
    ;; cases above use Connection: close, where that cannot show. Pipeline
    ;; a second request behind the bodyless one and require both replies.
    (let ((r (raw-request
               (string-append
                 "GET /status204 HTTP/1.1\r\nHost: x\r\n\r\n"
                 "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
                 "Connection: close\r\n\r\nafter"))))
      (unless (and (string-contains? r "HTTP/1.1 204 ")
                   (string-contains? r "HTTP/1.1 200 ")
                   (string-contains? r "after")
                   (not (string-contains? r "forbidden-body-204")))
        (error 'http-protocol "204 desynchronised the connection" r))
      (display "204 keep-alive framing ok\n"))
    (let ((r (raw-request
               (string-append
                 "GET /status304 HTTP/1.1\r\nHost: x\r\n\r\n"
                 "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
                 "Connection: close\r\n\r\nafter"))))
      (unless (and (string-contains? r "HTTP/1.1 304 ")
                   (string-contains? r "HTTP/1.1 200 ")
                   (string-contains? r "after")
                   (not (string-contains? r "forbidden-body-304")))
        (error 'http-protocol "304 desynchronised the connection" r))
      (display "304 keep-alive framing ok\n"))
    ;; res-begin!/res-write!/res-end! on a bodyless status: no chunked
    ;; framing may be announced and the handler's writes must vanish, with
    ;; the connection still usable afterwards.
    (let ((r (raw-request
               (string-append
                 "GET /stream204 HTTP/1.1\r\nHost: x\r\n\r\n"
                 "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
                 "Connection: close\r\n\r\nafter"))))
      (unless (and (string-contains? r "HTTP/1.1 204 ")
                   (not (string-contains? r "forbidden-stream-204"))
                   (not (string-contains? r "Transfer-Encoding"))
                   (string-contains? r "HTTP/1.1 200 ")
                   (string-contains? r "after"))
        (error 'http-protocol "streamed 204 carried a body or framing" r))
      (display "streamed 204 suppression ok\n"))
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

    ;; The chunk-count ceiling has to move with body-limit. Pinned to a
    ;; constant it silently rejects uploads the operator just made room
    ;; for: a body a third of the configured limit, chunked finely, was
    ;; answered 413. Raise the limit and send more chunks than the old
    ;; fixed 16384 while staying well inside it -- 20 000 x 512 bytes is
    ;; 10 MiB against 32.
    (http-listen 18083 handler '((workers . 2) (body-limit . 33554432)))
    (set! port 18083)
    (expect "fine-grained chunking within a raised body-limit"
      (string-append
        "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        (let-values (((p get) (open-string-output-port)))
          (let ((chunk (make-string 512 #\z)))
            (do ((i 0 (+ i 1))) ((= i 20000))
              (display "200\r\n" p) (display chunk p) (display "\r\n" p)))
          (display "0\r\n\r\n" p)
          (get)))
      "200")

    (display "ALL HTTP PROTOCOL TESTS PASSED\n")
    (exit 0)))
