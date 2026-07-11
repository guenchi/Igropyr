#!chezscheme
;;; s-expressions over WebSocket and SSE, end to end: each message is
;;; one datum -- write to send, safe-parse on receive.

(import (chezscheme) (igropyr http) (igropyr express)
        (igropyr sexpr) (igropyr ws-client) (igropyr libuv))

(define port 18086)
(define empty-bv (make-bytevector 0))

(define (fail label detail)
  (display "FAIL ") (display label) (display ": ") (write detail) (newline)
  (exit 1))
(define (expect label got want)
  (unless (equal? got want) (fail label (list 'got got 'want want))))

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

;; one raw HTTP request; returns the full response text (for SSE)
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
              (receive (after 3000
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

;;; the server
(define app (create-app))

;; WebSocket: an RPC-ish session -- each incoming datum answered
(app-ws app "/ws"
  (lambda (ws req)
    (ws-send-sexpr! ws '(hello (proto . sexpr)))
    (let loop ()
      (let ((m (ws-recv-sexpr ws)))
        (cond
          ((eq? m 'close) 'done)
          ((and (pair? m) (eq? (car m) 'add))
           (ws-send-sexpr! ws (list 'sum (apply + (cdr m))))
           (loop))
          ((and (pair? m) (eq? (car m) 'quote-me))
           (ws-send-sexpr! ws (list 'quoted (cdr m)))
           (loop))
          (else (ws-send-sexpr! ws '(error bad-message)) (loop)))))))

;; SSE: three events, one datum each; the middle one carries a string
;; with a literal newline (must split into two data: lines)
(app-get app "/events"
  (lambda (req res)
    (sse-start! res)
    (sse-send-sexpr! res '(tick 1))
    (sse-send-sexpr! res (list 'note (string #\a #\newline #\b)))
    (sse-send-sexpr! res '(done (total . 2)))))

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (sleep-ms 100)

    ;; --- WebSocket round trips (raw client + manual sexpr layer,
    ;;     so the client side is exercised independently) ---
    (let ((w (ws-connect (string-append "ws://127.0.0.1:"
                                        (number->string port) "/ws"))))
      (define (recv-datum)
        (let ((m (ws-recv w)))
          (unless (eq? (vector-ref m 0) 'text) (fail "ws recv" m))
          (string->sexpr (vector-ref m 1))))
      (expect "ws greet" (recv-datum) '(hello (proto . sexpr)))
      (ws-send-text! w (sexpr->string '(add 1 2 1/2)))
      (expect "ws add" (recv-datum) '(sum 7/2))
      (ws-send-text! w (sexpr->string '(quote-me "x\ny" sym)))
      (expect "ws struct" (recv-datum)
              (list 'quoted (list (string #\x #\newline #\y) 'sym)))
      (ws-send-text! w "#;(hostile) 1")
      (expect "ws hostile" (recv-datum) '(error bad-message))
      (ws-close! w))

    ;; --- SSE: parse the event stream, rejoin multi-line data ---
    (let* ((resp (http-req (string-append
                             "GET /events HTTP/1.1\r\nHost: x\r\n"
                             "Connection: close\r\n\r\n")))
           ;; split into events on blank lines, collect data: lines
           (events
            (let loop ((lines (let split ((s resp) (i 0) (start 0) (acc '()))
                                (cond
                                  ((= i (string-length s))
                                   (reverse (cons (substring s start i) acc)))
                                  ((char=? (string-ref s i) #\newline)
                                   (split s (+ i 1) (+ i 1)
                                          (cons (substring s start i) acc)))
                                  (else (split s (+ i 1) start acc)))))
                       (cur '()) (acc '()))
              (cond
                ((null? lines)
                 (reverse (if (null? cur) acc (cons (reverse cur) acc))))
                ((and (> (string-length (car lines)) 5)
                      (string=? (substring (car lines) 0 6) "data: "))
                 (loop (cdr lines)
                       (cons (substring (car lines) 6
                                        (let ((l (car lines)))
                                          (let ((n (string-length l)))
                                            (if (and (> n 0)
                                                     (char=? (string-ref l (- n 1)) #\return))
                                                (- n 1) n))))
                             cur)
                       acc))
                ((and (or (string=? (car lines) "") (string=? (car lines) "\r"))
                      (pair? cur))
                 (loop (cdr lines) '() (cons (reverse cur) acc)))
                (else (loop (cdr lines) cur acc)))))
           (datums (map (lambda (ls)
                          (string->sexpr
                            (fold-left (lambda (acc l)
                                         (if (string=? acc "") l
                                             (string-append acc "\n" l)))
                                       "" ls)))
                        events)))
      (expect "sse count" (length datums) 3)
      (expect "sse tick" (car datums) '(tick 1))
      (expect "sse newline datum" (cadr datums)
              (list 'note (string #\a #\newline #\b)))
      (expect "sse done" (caddr datums) '(done (total . 2))))

    (display "sexpr-ws: all tests passed") (newline)
    (exit 0)))
