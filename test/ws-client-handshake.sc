#!chezscheme
;;; WebSocket client verification against deliberately malformed 101 replies.

(import (chezscheme) (igropyr ws-client) (igropyr libuv) (igropyr tcp)
        (only (igropyr websocket) ws-accept-key))

(define port 18101)
(define failures 0)

(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (find-substr hay needle)
  (let ((hn (string-length hay)) (nn (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i nn) hn) #f)
            ((string=? (substring hay i (+ i nn)) needle) i)
            (else (loop (+ i 1)))))))

(define (request-key req)
  (let* ((label "Sec-WebSocket-Key: ")
         (start (find-substr req label)))
    (and start
         (let* ((vstart (+ start (string-length label)))
                (tail (substring req vstart (string-length req)))
                (vend (find-substr tail "\r\n")))
           (and vend (substring tail 0 vend))))))

(define (response-for req)
  (let* ((key (request-key req))
         (accept (and key (ws-accept-key key)))
         (status (if (find-substr req " /bad-status ")
                     "HTTP/1.1 1012 Not Switching\r\n"
                     "HTTP/1.1 101 Switching Protocols\r\n"))
         (upgrade (if (find-substr req " /missing-upgrade ")
                      ""
                      "Upgrade: websocket\r\n"))
         (connection (if (find-substr req " /missing-connection ")
                         ""
                         "Connection: keep-alive, Upgrade\r\n"))
         (accept-field
          (cond
            ((find-substr req " /accept-other-header ")
             (string-append "X-Sec-WebSocket-Accept: " accept "\r\n"))
            ((find-substr req " /accept-suffix ")
             (string-append "Sec-WebSocket-Accept: " accept "junk\r\n"))
            ((find-substr req " /accept-duplicate ")
             (string-append "Sec-WebSocket-Accept: " accept "\r\n"
                            "Sec-WebSocket-Accept: " accept "\r\n"))
            (else
             (string-append "Sec-WebSocket-Accept: " accept "\r\n")))))
    (string-append status upgrade connection accept-field "\r\n")))

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid
             (spawn
               (lambda ()
                 (let loop ((req ""))
                   (receive
                     (`#(tcp-data ,bv)
                       (let ((next (string-append req (utf8->string bv))))
                         (if (find-substr next "\r\n\r\n")
                             (begin
                               (tcp-write! c (string->utf8 (response-for next)) #f)
                               (sleep-ms 100)
                               (tcp-close! c))
                             (loop next))))
                     (`#(tcp-eof) (tcp-close! c))
                     (`#(tcp-error ,e) (tcp-close! c))))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(define (url path)
  (string-append "ws://127.0.0.1:" (number->string port) path))

(define (connect-error path)
  (guard (e ((and (vector? e)
                  (>= (vector-length e) 2)
                  (eq? (vector-ref e 0) 'ws-client-error))
             (vector-ref e 1))
            (#t 'wrong-error))
    (let ((w (ws-connect (url path))))
      (ws-close! w)
      'no-error)))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 100)

    (check "valid-tokenized-upgrade"
      (eq? (connect-error "/valid") 'no-error))
    (for-each
      (lambda (path)
        (check (string-append "reject-" path)
          (equal? (connect-error path) "handshake rejected")))
      '("/missing-upgrade" "/missing-connection" "/accept-other-header"
        "/accept-suffix" "/accept-duplicate" "/bad-status"))

    (if (= failures 0)
        (begin (display "WS CLIENT HANDSHAKE VALIDATION PASSED\n") (exit 0))
        (begin (display failures) (display " failure(s)\n") (exit 1)))))
