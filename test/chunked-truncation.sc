#!chezscheme
;;; http-client: a chunked response is not complete until its trailer
;;; section terminates.
;;;
;;; The decoders declared 'done the moment they parsed the "0" chunk-size
;;; line. But the last chunk is followed by the trailer section -- zero or
;;; more header lines, then a blank line (RFC 7230 4.1) -- and until that
;;; blank line arrives the response has not ended.
;;;
;;; So a server that sent "0\r\n" and then stopped, or a connection cut at
;;; exactly that point, produced a SUCCESSFUL reply carrying whatever body
;;; had arrived so far. Detecting truncation is the entire reason chunked
;;; framing exists, and tls.sc's comment promising that "the accepted
;;; framings detect truncation" was not true of this client.
;;;
;;; Both decoders are covered: the accumulating one (http-request) and the
;;; streaming one (an on-chunk handler), because they parse separately and
;;; had the same gap in each.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http-client))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18787)

;; What the fake server sends, chosen per connection off this list.
(define scripts '())
(define (next-script!)
  (with-interrupts-disabled
    (let ((x (car scripts))) (set! scripts (cdr scripts)) x)))

;; Sends its script, then holds the connection OPEN. Holding it open is the
;; point: an immediate close would give the client an EOF to notice, and
;; the question is whether the FRAMING is what tells it, not the socket.
(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let* ((script (next-script!))
             (pid (spawn
                    (lambda ()
                      (receive
                        (`#(tcp-data ,_)
                          (tcp-write! c (string->utf8 script) #f)
                          (sleep-ms 4000)
                          (tcp-close! c))
                        (`#(tcp-eof) (tcp-close! c))
                        (`#(tcp-error ,_) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(define head "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")

(define (body-of r) (and r (utf8->string (response-body r))))

;; -> 'ok+body | 'error | 'timeout
(define (fetch! stream?)
  (let ((me self))
    (spawn
      (lambda ()
        (send me
          (vector 'res
            (guard (e (#t 'error))
              (if stream?
                  (let ((acc (box "")))
                    (http-request 'GET
                      (string-append "http://127.0.0.1:" (number->string port) "/x")
                      (list (cons 'timeout 2500)
                            (cons 'on-chunk
                                  (lambda (bv)
                                    (set-box! acc (string-append (unbox acc)
                                                                 (utf8->string bv)))))))
                    (unbox acc))
                  (body-of
                    (http-request 'GET
                      (string-append "http://127.0.0.1:" (number->string port) "/x")
                      '((timeout . 2500)))))))))))
  (receive (after 9000 'timeout) (`#(res ,v) v)))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 200)

    ;; Each case runs against both decoders, so the scripts are listed twice.
    (let* ((cases
             (list
               ;; (label script accept? expected-body)
               (list "complete, empty trailer"
                     (string-append head "3\r\nabc\r\n0\r\n\r\n") #t "abc")
               (list "complete, non-empty trailer"
                     (string-append head "3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n") #t "abc")
               (list "truncated: no CRLF after the 0 line"
                     (string-append head "3\r\nabc\r\n0\r\n") #f #f)
               (list "truncated: trailer line without its blank line"
                     (string-append head "3\r\nabc\r\n0\r\nX-Sum: 1\r\n") #f #f)
               (list "truncated: cut mid-body"
                     (string-append head "3\r\nabc\r\n") #f #f))))
      (for-each
        (lambda (stream?)
          (display (if stream? "  -- streaming decoder\n" "  -- accumulating decoder\n"))
          (for-each
            (lambda (c)
              (let ((label (car c)) (script (cadr c))
                    (accept? (caddr c)) (want (cadddr c)))
                (set! scripts (list script))
                (let ((got (fetch! stream?)))
                  (if accept?
                      (check label (equal? got want))
                      ;; A truncated response must NOT be reported as a
                      ;; successful body. Either outcome that says "this did
                      ;; not complete" is correct -- an error, or the read
                      ;; still waiting when the caller's timeout expires.
                      (check label (memq got '(error timeout)))))))
            cases))
        '(#f #t)))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "chunked-truncation: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
