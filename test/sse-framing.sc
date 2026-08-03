#!chezscheme
;;; sse-send! and the event stream format.
;;;
;;; sse-send! concatenated "data: " + the string + "\n\n". Any line break
;;; inside the string therefore ended the data field, and whatever followed
;;; was read by the client as a new FIELD -- "event:" changes which listener
;;; the browser dispatches on, "id:" moves the reconnection cursor, "retry:"
;;; changes the reconnect delay, and a blank line ends the event and starts
;;; another one. An endpoint streaming user-supplied text (chat, log lines,
;;; model output) handed the writer of that text control of the protocol.
;;;
;;; The fix gives every line its own "data:" prefix; EventSource rejoins
;;; them with \n, so the payload arrives unchanged. Breaks are CRLF, LF and
;;; a bare CR -- the format treats all three as line ends, so splitting on
;;; LF alone would leave a CR inside a line where the client still breaks.
;;;
;;; The assertions are on the BYTES ON THE WIRE, because "the handler sent
;;; the right string" was never in doubt; what the client parses out of it
;;; is the question.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
        (igropyr express))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18781)

(define (str-has? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring s i (+ i m))) #t)
            (else (loop (+ i 1)))))))

;; every line of the response that is not a chunk-size line
(define (body-lines text)
  (let loop ((i 0) (start 0) (out '()))
    (cond
      ((>= i (string-length text)) (reverse out))
      ((char=? (string-ref text i) #\newline)
       (let ((line (substring text start i)))
         (loop (+ i 1) (+ i 1)
               (cons (if (and (> (string-length line) 0)
                              (char=? (string-ref line (- (string-length line) 1))
                                      #\return))
                         (substring line 0 (- (string-length line) 1))
                         line)
                     out))))
      (else (loop (+ i 1) start out)))))

(define (raw-get! path report)
  (spawn
    (lambda ()
      (tcp-connect! "127.0.0.1" port self)
      (receive (after 5000 (send report (vector 'raw #f)))
        (`#(tcp-connect-failed ,e) (send report (vector 'raw #f)))
        (`#(tcp-connected ,c)
          (tcp-read-start! c)
          (tcp-write! c (string->utf8
                          (string-append "GET " path " HTTP/1.1\r\nHost: x\r\n"
                                         "Connection: close\r\n\r\n"))
                      #f)
          (let collect ((acc ""))
            (receive (after 6000 (tcp-close! c) (send report (vector 'raw acc)))
              (`#(tcp-data ,bv) (collect (string-append acc (utf8->string bv))))
              (`#(tcp-eof) (tcp-close! c) (send report (vector 'raw acc)))
              (`#(tcp-error ,e) (tcp-close! c) (send report (vector 'raw acc))))))))))

;; The hostile payload: a plain chat message whose author typed newlines.
(define payload "hello\nevent: logout\ndata: you are signed out\n\nid: 99\nretry: 1\nbye")

(start-scheduler
  (lambda ()
    (let ((app (create-app)) (main self))
      (app-get app "/sse"
        (lambda (req res)
          (sse-start! res)
          (sse-send! res payload)
          (res-end! res)))
      ;; a bare CR is a line break in the event stream format too
      (app-get app "/cr"
        (lambda (req res)
          (sse-start! res)
          (sse-send! res "a\revent: cr-injected\rb")
          (res-end! res)))
      (app-listen app port)
      (sleep-ms 300)

      (raw-get! "/sse" main)
      (let* ((text (receive (after 9000 #f) (`#(raw ,t) t)))
             (lines (if text (body-lines text) '())))
        (check "response received" (and text #t))
        ;; Not one line of what the client parses may be a field other than
        ;; data:. This is the whole point -- the assertion is not "the text
        ;; is in there somewhere", it is "nothing became a field".
        (check "no line is an event: field"
          (not (memp (lambda (l) (and (>= (string-length l) 6)
                                      (string=? (substring l 0 6) "event:")))
                     lines)))
        (check "no line is an id: field"
          (not (memp (lambda (l) (and (>= (string-length l) 3)
                                      (string=? (substring l 0 3) "id:")))
                     lines)))
        (check "no line is a retry: field"
          (not (memp (lambda (l) (and (>= (string-length l) 6)
                                      (string=? (substring l 0 6) "retry:")))
                     lines)))
        ;; and the payload still arrives -- escaping that loses data is a
        ;; different bug, not a fix
        (check "the first line of the payload is delivered as data"
          (str-has? text "data: hello"))
        (check "the last line of the payload is delivered as data"
          (str-has? text "data: bye"))
        (check "the injected text survives, as data"
          (str-has? text "data: event: logout")))

      (raw-get! "/cr" main)
      (let* ((text (receive (after 9000 #f) (`#(raw ,t) t))))
        (check "a bare CR does not open a field either"
          (and text (not (str-has? text "\revent:"))))
        (check "CR-separated payload still delivered"
          (and text (str-has? text "data: event: cr-injected"))))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "sse-framing: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
