#!chezscheme
;;; s-expression RPC over HTTP, end to end: an app-rpc endpoint
;;; answers (tag arg ...) requests with (ok ...) / (error ...) data.

(import (chezscheme) (igropyr http) (igropyr express)
        (igropyr sexpr) (igropyr libuv))

(define port 18085)
(define empty-bv (make-bytevector 0))

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

(define (fail label detail)
  (display "FAIL ") (display label) (display ": ") (write detail) (newline)
  (exit 1))
(define (expect label got want)
  (unless (equal? got want) (fail label (list 'got got 'want want))))

;; one request on a fresh connection; returns the full response text
(define (http-req text)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'r-err ref 'connect)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c (string->utf8 text) #f)
            (let loop ((buf empty-bv))
              (receive (after 5000
                          (tcp-close! c)
                          (send caller (vector 'r-ok ref (utf8->string buf))))
                (`#(tcp-data ,bv) (loop (bv-append buf bv)))
                (`#(tcp-eof) (send caller (vector 'r-ok ref (utf8->string buf))))
                (`#(tcp-error ,e) (send caller (vector 'r-ok ref (utf8->string buf)))))))
          (`#(tcp-connect-failed ,e)
            (send caller (vector 'r-err ref e))))))
    (receive (after 10000 (fail "http-req" 'timeout))
      (`#(r-ok ,@ref ,s) s)
      (`#(r-err ,@ref ,e) (fail "http-req" e)))))

(define (rpc-post datum)
  (let ((body (sexpr->string datum)))
    (http-req (string-append
                "POST /rpc HTTP/1.1\r\nHost: x\r\nContent-Length: "
                (number->string (string-length body))
                "\r\nConnection: close\r\n\r\n" body))))

;; pull the response body (after the blank line) and parse it
(define (rpc-reply resp)
  (let ((n (string-length resp)))
    (let loop ((i 0))
      (cond
        ((> (+ i 4) n) (fail "rpc-reply" resp))
        ((string=? (substring resp i (+ i 4)) "\r\n\r\n")
         (string->sexpr (substring resp (+ i 4) n)))
        (else (loop (+ i 1)))))))

;;; the server: three handlers behind one rpc endpoint
(define users '((1 . "ada") (2 . "alan")))
(define app (create-app))
(app-rpc app "/rpc"
  `((add      . ,(lambda (args) (apply + args)))
    (get-user . ,(lambda (args)
                   (let ((u (assv (car args) users)))
                     (if u
                         (list 'user (cons 'id (car u)) (cons 'name (cdr u)))
                         'not-found))))
    (boom     . ,(lambda (args) (raise 'kaboom)))))

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (sleep-ms 100)

    ;; plain call: exact numbers survive the wire
    (expect "add" (rpc-reply (rpc-post '(add 1 2 39))) '(ok 42))
    ;; structured reply: symbols, dotted pairs, strings
    (expect "get-user"
      (rpc-reply (rpc-post '(get-user 1)))
      '(ok (user (id . 1) (name . "ada"))))
    (expect "get-user-miss"
      (rpc-reply (rpc-post '(get-user 99)))
      '(ok not-found))
    ;; ratios cross exactly
    (expect "ratio" (rpc-reply (rpc-post '(add 1/3 1/6))) '(ok 1/2))
    ;; unknown tag and hostile payloads answer data, never crash
    (expect "unknown" (rpc-reply (rpc-post '(nope 1)))
            '(error unknown-tag nope))
    (expect "handler-error" (rpc-reply (rpc-post '(boom)))
            '(error handler-failed))
    (let ((resp (http-req (string-append
                            "POST /rpc HTTP/1.1\r\nHost: x\r\nContent-Length: 14"
                            "\r\nConnection: close\r\n\r\n#;(walk in) 42"))))
      (expect "hostile" (rpc-reply resp) '(error bad-payload)))

    (display "sexpr-http: all tests passed") (newline)
    (exit 0)))
