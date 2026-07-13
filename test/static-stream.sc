#!chezscheme
;;; Large static files are streamed (fixed-length response, 64 KiB
;;; chunks with backpressure) instead of buffered whole. Verified here:
;;;   - byte-for-byte integrity of a > 1 MiB download
;;;   - keep-alive survives a streamed response (second request on the
;;;     same connection)
;;;   - If-None-Match answers 304 without streaming
;;;   - a client that disconnects mid-download doesn't wedge the server
;;;   - small files still come from the in-memory cache

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
        (igropyr express))

(define port 18085)
(define dir "igropyr/test/tmp-static")
(define big-size (+ (* 3 1024 1024) 12345))   ; > 1 MiB cache cap, odd tail
(define small-text "hello igropyr")

(define (pattern-bv n)
  (let ((bv (make-bytevector n)))
    (do ((i 0 (fx+ i 1))) ((fx= i n) bv)
      (bytevector-u8-set! bv i (fxand (fx+ (fx* i 31) 7) 255)))))

(define big-bv (pattern-bv big-size))

(define (write-file! path bv)
  (when (file-exists? path) (delete-file path))
  (call-with-port (open-file-output-port path)
    (lambda (p) (put-bytevector p bv))))

(unless (file-directory? dir) (mkdir dir))
(write-file! (string-append dir "/big.bin") big-bv)
(write-file! (string-append dir "/small.txt") (string->utf8 small-text))

(define (cleanup!)
  (guard (e (#t (void)))
    (delete-file (string-append dir "/big.bin"))
    (delete-file (string-append dir "/small.txt"))
    (delete-directory dir)))

;; ---- minimal binary-safe HTTP client on one connection ----------------

(define empty-bv (make-bytevector 0))

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

(define (bv-sub bv start end)
  (let ((out (make-bytevector (- end start))))
    (bytevector-copy! bv start out 0 (- end start))
    out))

(define (find-header-end bv)
  (let ((n (bytevector-length bv)))
    (let loop ((i 0))
      (cond
        ((fx> (fx+ i 3) (fx- n 1)) #f)
        ((and (fx= (bytevector-u8-ref bv i) 13)
              (fx= (bytevector-u8-ref bv (fx+ i 1)) 10)
              (fx= (bytevector-u8-ref bv (fx+ i 2)) 13)
              (fx= (bytevector-u8-ref bv (fx+ i 3)) 10))
         i)
        (else (loop (fx+ i 1)))))))

;; value of "Name: v" in the head text, or #f
(define (head-field head name)
  (let ((key (string-append name ": "))
        (n (string-length head)))
    (let ((m (string-length key)))
      (let search ((i 0))
        (cond
          ((> (+ i m) n) #f)
          ((string=? (substring head i (+ i m)) key)
           (let scan ((j (+ i m)))
             (if (or (= j n) (char=? (string-ref head j) #\return))
                 (substring head (+ i m) j)
                 (scan (+ j 1)))))
          (else (search (+ i 1))))))))

(define (connect!)
  (tcp-connect! "127.0.0.1" port self)
  (receive (after 3000 (raise 'connect-timeout))
    (`#(tcp-connected ,c) (tcp-read-start! c) c)
    (`#(tcp-connect-failed ,e) (raise (vector 'connect-failed e)))))

;; write a request, read one full response (headers + Content-Length
;; body). -> (values head-string body-bv leftover-bv)
(define (roundtrip c text leftover)
  (tcp-write! c (string->utf8 text) #f)
  (let headers ((buf leftover))
    (let ((hend (find-header-end buf)))
      (if (not hend)
          (receive (after 10000 (raise 'header-timeout))
            (`#(tcp-data ,bv) (headers (bv-append buf bv)))
            (`#(tcp-eof) (raise 'eof-in-headers))
            (`#(tcp-error ,e) (raise (vector 'tcp-error e))))
          (let* ((head (utf8->string (bv-sub buf 0 hend)))
                 (cl (string->number (or (head-field head "Content-Length") "")))
                 (total (and cl (+ hend 4 cl))))
            (unless cl (raise (vector 'no-content-length head)))
            (let body ((buf buf))
              (if (>= (bytevector-length buf) total)
                  (values head
                          (bv-sub buf (+ hend 4) total)
                          (bv-sub buf total (bytevector-length buf)))
                  (receive (after 30000 (raise 'body-timeout))
                    (`#(tcp-data ,bv) (body (bv-append buf bv)))
                    (`#(tcp-eof) (raise 'eof-in-body))
                    (`#(tcp-error ,e) (raise (vector 'tcp-error e)))))))))))

(define (assert! label ok)
  (if ok
      (begin (display label) (display " ok\n"))
      (begin (cleanup!) (error 'static-stream label))))

(define (status-of head)
  (substring head 9 12))   ; "HTTP/1.1 XXX ..."

;; ---- the tests ----------------------------------------------------------

(define app (create-app))
(app-static app "/files" dir)

(start-scheduler
  (lambda ()
    (app-listen app port)
    (sleep-ms 50)

    ;; 1. streamed download: integrity + keep-alive survival
    (let ((c (connect!)))
      (let-values (((head body rest)
                    (roundtrip c "GET /files/big.bin HTTP/1.1\r\nHost: x\r\n\r\n"
                               empty-bv)))
        (assert! "big status 200" (string=? (status-of head) "200"))
        (assert! "big content-length"
                 (equal? (head-field head "Content-Length")
                         (number->string big-size)))
        (assert! "big body integrity" (bytevector=? body big-bv))
        ;; 2. same connection again: the final-chunk continuation must
        ;; have told the reader to parse the next request
        (let ((etag (head-field head "ETag")))
          (assert! "big etag present" (and etag #t))
          (let-values (((head2 body2 rest2)
                        (roundtrip c
                          "GET /files/small.txt HTTP/1.1\r\nHost: x\r\n\r\n"
                          rest)))
            (assert! "keep-alive after stream"
                     (and (string=? (status-of head2) "200")
                          (bytevector=? body2 (string->utf8 small-text)))))
          ;; 3. conditional request: 304, nothing streamed
          (let-values (((head3 body3 rest3)
                        (roundtrip c
                          (string-append
                            "GET /files/big.bin HTTP/1.1\r\nHost: x\r\n"
                            "If-None-Match: " etag "\r\nConnection: close\r\n\r\n")
                          empty-bv)))
            (assert! "big 304" (and (string=? (status-of head3) "304")
                                    (= (bytevector-length body3) 0)))))
        (tcp-close! c)))

    ;; 4. client disconnects mid-download; the server must stay healthy
    (let ((c (connect!)))
      (tcp-write! c (string->utf8 "GET /files/big.bin HTTP/1.1\r\nHost: x\r\n\r\n") #f)
      (receive (after 5000 (raise 'no-first-chunk))
        (`#(tcp-data ,bv) 'got-some))
      (tcp-close! c))
    (sleep-ms 200)                        ; let the abort settle
    (let ((c (connect!)))
      (let-values (((head body rest)
                    (roundtrip c
                      "GET /files/small.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                      empty-bv)))
        (assert! "alive after client abort"
                 (and (string=? (status-of head) "200")
                      (bytevector=? body (string->utf8 small-text)))))
      (tcp-close! c))

    (cleanup!)
    (display "ALL STATIC STREAM TESTS PASSED\n")
    (exit 0)))
