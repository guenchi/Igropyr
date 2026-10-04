#!chezscheme
;;; test/http-client-syntax.sc -- the HTTP client holds the request method
;;; and the response's status line and chunk sizes to HTTP's grammar.
;;;
;;; THE METHOD GOES ON THE WIRE AS GIVEN. A caller that lets outside input
;;; choose the method (a proxy, an API gateway) hands the client whatever that
;;; input holds; with a CR LF inside it, the text after the break becomes a
;;; second request line or an extra header on the wire. RFC 9112 3: a method
;;; is a token -- one or more tchar -- so anything else is refused before DNS
;;; or a connection: the server must accept no connection for it, and no head
;;; it records may carry the injected text. Every tchar class has a positive
;;; row (upper case, lower case, digits, the punctuation), so a validator that
;;; admits only upper-case letters fails them.
;;;
;;; THE STATUS LINE COMES FROM THE SERVER. RFC 9112 4: HTTP-version is "HTTP/"
;;; DIGIT "." DIGIT, case-sensitive; the client accepts any HTTP/1.x (RFC 9110
;;; 2.5: a 1.1 client reads every minor version of major 1). The status code
;;; is exactly three digits: a four-digit one was already refused, a
;;; two-digit one was read as 20 and accepted.
;;;
;;; CHUNK SIZES ARE HEXDIG ONLY (RFC 9112 7.1). The rows here are regression
;;; twins: that half of the review's finding was fixed before 1.8.0. Note that
;;; "2e0" IS a hexadecimal size (736); the invalid shapes are a rational, a
;;; sign, a 0x prefix, an empty size, a leading space and a non-hex letter.
;;;
;;; Both arrive through the same reader for the buffered and the streaming
;;; call, so each shape is tried both ways. Every refusal row asserts the
;;; client's REASON, not merely an error, so a timeout or a closed connection
;;; cannot pass as a refusal.

(import (chezscheme) (igropyr actor) (igropyr tcp) (igropyr http-client))

(define port 18851)
(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define (index-of text sub from)
  (let ((n (string-length text)) (m (string-length sub)))
    (let loop ((i from))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring text i (+ i m))) i)
            (else (loop (+ i 1)))))))
(define (string-has? s sub) (and (index-of s sub 0) #t))
(define (head-path text)
  (let* ((sp1 (index-of text " " 0))
         (sp2 (and sp1 (index-of text " " (+ sp1 1)))))
    (if (and sp1 sp2) (substring text (+ sp1 1) sp2) "/")))

;; what the server saw: accepted connections, and every request head
;; (newest first). A refusal before connecting changes neither.
(define accepts (box 0))
(define heads (box '()))

(define (reply-for path)
  (define (fixed body) (string-append "Content-Length: " (number->string (string-length body)) "\r\n\r\n" body))
  (define (chunked tail) (string-append "Transfer-Encoding: chunked\r\n\r\n" tail))
  (define (status line . rest) (string-append line "\r\nConnection: close\r\n" (apply string-append rest)))
  (cond
    ((string=? path "/ok") (status "HTTP/1.1 200 OK" (fixed "ok")))
    ((string=? path "/http-1.0") (status "HTTP/1.0 200 OK" (fixed "ok")))
    ((string=? path "/http-1.9") (status "HTTP/1.9 200 OK" (fixed "ok")))
    ((string=? path "/not-http") (status "NOTHTTP 200 OK" (fixed "ok")))
    ((string=? path "/no-version") (status "200 OK" (fixed "ok")))
    ((string=? path "/lower-http") (status "http/1.1 200 OK" (fixed "ok")))
    ((string=? path "/http-2") (status "HTTP/2 200 OK" (fixed "ok")))
    ((string=? path "/http-a.b") (status "HTTP/a.b 200 OK" (fixed "ok")))
    ((string=? path "/http-1.x") (status "HTTP/1.x 200 OK" (fixed "ok")))
    ((string=? path "/http-11") (status "HTTP/11 200 OK" (fixed "ok")))
    ((string=? path "/status-2") (status "HTTP/1.1 20 OK" (fixed "ok")))
    ((string=? path "/status-4") (status "HTTP/1.1 2000 OK" (fixed "ok")))
    ((string=? path "/chunked-ok") (status "HTTP/1.1 200 OK" (chunked "2\r\nok\r\n0\r\n\r\n")))
    ((string=? path "/chunked-hex") (status "HTTP/1.1 200 OK" (chunked "A\r\n0123456789\r\n0\r\n\r\n")))
    ((string=? path "/chunked-lower-hex") (status "HTTP/1.1 200 OK" (chunked "a\r\n0123456789\r\n0\r\n\r\n")))
    ((string=? path "/chunked-ext") (status "HTTP/1.1 200 OK" (chunked "2;name=value\r\nok\r\n0\r\n\r\n")))
    ((string=? path "/chunked-2e0")
     (status "HTTP/1.1 200 OK" (chunked (string-append "2e0\r\n" (make-string 736 #\z) "\r\n0\r\n\r\n"))))
    ;; one body byte, so a parser that read 1/1 as 1 would frame it cleanly
    ((string=? path "/chunked-rational") (status "HTTP/1.1 200 OK" (chunked "1/1\r\no\r\n0\r\n\r\n")))
    ((string=? path "/chunked-plus") (status "HTTP/1.1 200 OK" (chunked "+2\r\nok\r\n0\r\n\r\n")))
    ((string=? path "/chunked-0x") (status "HTTP/1.1 200 OK" (chunked "0x2\r\nok\r\n0\r\n\r\n")))
    ((string=? path "/chunked-empty-size") (status "HTTP/1.1 200 OK" (chunked "\r\nok\r\n0\r\n\r\n")))
    ((string=? path "/chunked-space") (status "HTTP/1.1 200 OK" (chunked " 2\r\nok\r\n0\r\n\r\n")))
    ((string=? path "/chunked-g") (status "HTTP/1.1 200 OK" (chunked "2g\r\nok\r\n0\r\n\r\n")))
    (else (status "HTTP/1.1 404 Not Found" (fixed "")))))

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 32
    (lambda (c)
      (set-box! accepts (+ (unbox accepts) 1))
      (let ((pid
              (spawn
                (lambda ()
                  (guard (e (#t (void)))
                    (let loop ((acc ""))
                      (receive (after 30000 (tcp-close! c))
                        (`#(tcp-data ,bv)
                          (let* ((text (string-append acc (utf8->string bv)))
                                 (hend (index-of text "\r\n\r\n" 0)))
                            (if (not hend)
                                (loop text)
                                (begin
                                  (set-box! heads (cons text (unbox heads)))
                                  (tcp-write! c (string->utf8 (reply-for (head-path text))) #f)
                                  (sleep-ms 50)
                                  (tcp-close! c))))))
                        (`#(tcp-eof) (tcp-close! c))
                        (`#(tcp-error ,e) (tcp-close! c))))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(define (url path) (string-append "http://127.0.0.1:" (number->string port) path))

(define (bv-concat bvs)
  (let* ((n (apply + (map bytevector-length bvs))) (out (make-bytevector n)))
    (let loop ((bs bvs) (o 0))
      (if (null? bs) out
          (let ((k (bytevector-length (car bs))))
            (bytevector-copy! (car bs) 0 out o k)
            (loop (cdr bs) (+ o k)))))))
(define (condition-text e)
  (call-with-string-output-port
    (lambda (p)
      (when (who-condition? e) (write (condition-who e) p) (display ": " p))
      (when (message-condition? e) (display (condition-message e) p))
      (when (irritants-condition? e) (display " " p) (write (condition-irritants e) p)))))

;; -> (status . body-string) | (refused . message) | (raised-elsewhere . text).
;; The server closes every connection after answering, so reuse is off: no
;; request may go down a kept connection and be lost there.
(define (attempt method path streaming?)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'http-client-error))
             (cons 'refused (vector-ref e 1)))
            (#t (cons 'raised-elsewhere (if (condition? e) (condition-text e) e))))
    (if streaming?
        (let ((chunks '()))
          (let ((r (http-request method (url path)
                     (list (cons 'timeout 5000) (cons 'reuse #f)
                           (cons 'on-chunk (lambda (bv) (set! chunks (cons bv chunks))))))))
            (cons (response-status r) (utf8->string (bv-concat (reverse chunks))))))
        (let ((r (http-request method (url path) '((timeout . 5000) (reuse . #f)))))
          (cons (response-status r) (utf8->string (response-body r)))))))

(define (refused-for? r why) (and (eq? (car r) 'refused) (string-has? (cdr r) why)))
(define (settle!) (sleep-ms 100))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 100)

    ;; ---- the method (RFC 9112 3) ---------------------------------------------
    (check "twin: GET reaches the server and the body comes back"
           (equal? (attempt 'GET "/ok" #f) '(200 . "ok")) (attempt 'GET "/ok" #f))
    ;; every tchar class, as given: the server answers by path, not by method
    (for-each
      (lambda (sym label)
        (let ((r (attempt sym "/ok" #f)))
          (settle!)
          (check (string-append "twin: a method " label " is sent as given")
                 (and (equal? r '(200 . "ok"))
                      (string-has? (car (unbox heads)) (string-append (symbol->string sym) " /ok HTTP/1.1\r\n")))
                 r (substring (car (unbox heads)) 0 (min 40 (string-length (car (unbox heads))))))))
      (list 'PURGE (string->symbol "get") (string->symbol "M-SEARCH") (string->symbol "X9")
            (string->symbol "!#$%&'*+-.^_`|~"))
      '("that is an extension (PURGE)" "in lower case" "with a hyphen (M-SEARCH)" "with a digit"
        "made of the fifteen tchar punctuation marks"))
    (for-each
      (lambda (sym label)
        (let* ((accepts-before (unbox accepts))
               (r (attempt sym "/ok" #f)))
          (settle!)
          (check (string-append "a method " label " is refused as not a token")
                 (refused-for? r "method must be an HTTP token") r)
          (check (string-append "  and no connection was made for it: " label)
                 (= (unbox accepts) accepts-before) (- (unbox accepts) accepts-before))))
      (list (string->symbol "GET /x HTTP/1.1\r\nX-Injected: yes\r\nGET")
            (string->symbol "GE T")
            (string->symbol "GET\t")
            (string->symbol "")
            (string->symbol "G\x7f;ET")
            (string->symbol "GET\x01;")
            (string->symbol "GET:")
            (string->symbol "G(ET)")
            (string->symbol "GÉT")
            (string->symbol "GET/"))
      '("carrying CR LF and a header" "with a space" "with a tab" "that is empty"
        "with DEL" "with a control character" "with a colon" "with parentheses"
        "with a non-ASCII character" "with a slash"))
    ;; the streaming entry shares the gate, both ways
    (check "twin: the streaming call sends a token method (PURGE) as given"
           (equal? (attempt 'PURGE "/ok" #t) '(200 . "ok")))
    (for-each
      (lambda (sym label)
        (let* ((accepts-before (unbox accepts))
               (r (attempt sym "/ok" #t)))
          (settle!)
          (check (string-append "the streaming call refuses a method " label)
                 (refused-for? r "method must be an HTTP token") r)
          (check (string-append "  and made no connection: " label) (= (unbox accepts) accepts-before))))
      (list (string->symbol "GET\r\nX-Injected: yes\r\nGET") (string->symbol "GET\t"))
      '("carrying CR LF" "with a tab"))
    (check "no request head the server saw carries an injected header"
           (not (exists (lambda (h) (string-has? h "X-Injected")) (unbox heads))))

    ;; ---- the status line (RFC 9112 4; RFC 9110 2.5 for the minor version) ------
    (for-each
      (lambda (streaming?)
        (let ((tag (if streaming? " (streaming)" " (buffered)")))
          (for-each
            (lambda (path label)
              (check (string-append "twin: " label " is accepted" tag)
                     (equal? (attempt 'GET path streaming?) '(200 . "ok")) (attempt 'GET path streaming?)))
            '("/ok" "/http-1.0" "/http-1.9")
            '("HTTP/1.1 200" "HTTP/1.0 200" "HTTP/1.9 200 (any minor version of 1)"))
          (for-each
            (lambda (path label)
              (let ((r (attempt 'GET path streaming?)))
                (check (string-append "a status line " label " is refused as malformed" tag)
                       (refused-for? r "malformed status line") r)))
            '("/not-http" "/lower-http" "/http-2" "/http-a.b" "/http-1.x" "/http-11" "/no-version"
              "/status-2" "/status-4")
            '("reading NOTHTTP 200 OK" "with a lowercase http/1.1"
              "with HTTP/2 (no minor digit)" "with HTTP/a.b (letters for digits)"
              "with HTTP/1.x (a letter for the minor digit)" "with HTTP/11 (no dot)"
              "with no version (refused by the status-code check already)"
              "with a two-digit status" "with a four-digit status (already refused)"))))
      '(#f #t))

    ;; ---- the chunk size (RFC 9112 7.1): regression twins ---------------------------
    (for-each
      (lambda (streaming?)
        (let ((tag (if streaming? " (streaming)" " (buffered)")))
          (for-each
            (lambda (path want label)
              (check (string-append "twin: " label tag)
                     (equal? (attempt 'GET path streaming?) want) (attempt 'GET path streaming?)))
            '("/chunked-ok" "/chunked-hex" "/chunked-lower-hex" "/chunked-ext" "/chunked-2e0")
            (list '(200 . "ok") '(200 . "0123456789") '(200 . "0123456789") '(200 . "ok")
                  (cons 200 (make-string 736 #\z)))
            '("a size of 2 frames two bytes" "an upper-case hex size (A) frames ten bytes"
              "a lower-case hex size (a) frames ten bytes" "a chunk extension after the size is ignored"
              "2e0 is hexadecimal 736 and frames 736 bytes"))
          (for-each
            (lambda (path label)
              (let ((r (attempt 'GET path streaming?)))
                (check (string-append "a chunk size " label " is refused as a bad chunked response" tag)
                       (refused-for? r "bad chunked response") r)))
            '("/chunked-rational" "/chunked-plus" "/chunked-0x" "/chunked-empty-size"
              "/chunked-space" "/chunked-g")
            '("written 1/1 (one body byte, so a rational read as 1 would frame it)" "written +2"
              "written 0x2" "that is empty" "with a leading space" "written 2g"))))
      '(#f #t))

    (if (zero? failures)
        (begin (display "http-client-syntax: all tests passed\n") (exit 0))
        (begin (display "http-client-syntax: ") (display failures) (display " failed\n") (exit 1)))))
