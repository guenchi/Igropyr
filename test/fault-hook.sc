#!chezscheme
;;; Failure-hook (on-failure) protocol tests.
;;;
;;; Server A (18081): on-failure = make-fault-handler, short stuck-ms.
;;;   - /crash: retries exhausted -> {"fault":"crash","attempts":4,...}
;;;   - /stuck: killed fast, then  -> {"fault":"stuck",...} well under the
;;;     old 30s wait
;;;   - the failure response keeps the connection alive: a resubmission
;;;     on the same connection succeeds (the remote retry ring)
;;; Server B (18082): on-failure raises -> falls back to the plain 500.
;;; Server C (18083): no on-failure -> plain 500 (default unchanged).

(import (chezscheme) (igropyr http) (igropyr express) (igropyr libuv))

(define empty-bv (make-bytevector 0))

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

(define (contains? s needle)
  (let ((n (string-length s)) (m (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring s i (+ i m)) needle) #t)
            (else (loop (+ i 1)))))))

(define (fail label detail)
  (display "FAIL: ") (display label) (display " ") (write detail) (newline)
  (exit 1))

;; Open a raw connection, send `text`, read until `marker` appears (or
;; the deadline passes), optionally send `text2` and wait for `marker2`.
;; Returns the accumulated response text.
(define (raw-ring port text marker text2 marker2 timeout-ms)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'ring-error ref 'connect-timeout)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c (string->utf8 text) #f)
            (let loop ((buf empty-bv) (stage 1))
              (let ((s (utf8->string buf)))
                (cond
                  ((and (= stage 1) (contains? s marker))
                   (if text2
                       (begin
                         (tcp-write! c (string->utf8 text2) #f)
                         (loop buf 2))
                       (begin (tcp-close! c)
                              (send caller (vector 'ring-reply ref s)))))
                  ((and (= stage 2) (contains? s marker2))
                   (tcp-close! c)
                   (send caller (vector 'ring-reply ref s)))
                  (else
                   (receive (after timeout-ms
                               (tcp-close! c)
                               (send caller (vector 'ring-reply ref s)))
                     (`#(tcp-data ,bv) (loop (bv-append buf bv) stage))
                     (`#(tcp-eof) (send caller (vector 'ring-reply ref s)))
                     (`#(tcp-error ,e) (send caller (vector 'ring-reply ref s)))))))))
          (`#(tcp-connect-failed ,e)
            (send caller (vector 'ring-error ref e))))))
    (receive (after (+ timeout-ms 5000) (fail "raw-ring" 'timeout))
      (`#(ring-reply ,@ref ,s) s)
      (`#(ring-error ,@ref ,e) (fail "raw-ring" e)))))

(define (expect-contains label response . needles)
  (for-each
    (lambda (needle)
      (unless (contains? response needle)
        (fail label (list 'missing needle 'in response))))
    needles)
  (display label) (display " ok\n"))

(define (build-app)
  (let ((app (create-app)))
    (app-get app "/ok"
      (lambda (req res) (send-text! res "fine")))
    (app-get app "/crash"
      (lambda (req res) (raise 'deliberate)))
    (app-get app "/stuck"
      (lambda (req res) (let loop ((n 0)) (loop (+ n 1)))))
    app))

(start-scheduler
  (lambda ()
    ;; A: hook via the bundled template; fast kill for the ring test
    (app-listen (build-app) 18081
      (list '(workers . 2)
            '(stuck-ms . 1500)
            '(check-ms . 300)
            (cons 'on-failure (make-fault-handler))))
    ;; B: a hook that itself crashes -> plain 500 fallback
    (app-listen (build-app) 18082
      (list '(workers . 2)
            (cons 'on-failure (lambda (req res info) (raise 'bad-hook)))))
    ;; C: no hook -> default plain 500
    (app-listen (build-app) 18083 '((workers . 2)))
    (sleep-ms 100)

    ;; crash envelope: retries exhausted -> structured JSON, keep-alive
    (let ((r (raw-ring 18081
               "GET /crash HTTP/1.1\r\nHost: x\r\n\r\n"
               "\"attempts\"" #f #f 4000)))
      (expect-contains "crash envelope" r
        "HTTP/1.1 503 " "\"fault\":\"crash\"" "\"attempts\":4"
        "\"retryable\":true" "Connection: keep-alive"))

    ;; stuck: killed first, told after, fast (well under the stock 30 s)
    (let* ((t0 (now-ms))
           (r (raw-ring 18081
                "GET /stuck HTTP/1.1\r\nHost: x\r\n\r\n"
                "\"fault\"" #f #f 6000))
           (dt (- (now-ms) t0)))
      (expect-contains "stuck envelope" r "\"fault\":\"stuck\"")
      (unless (< dt 5000) (fail "stuck latency" dt))
      (display "stuck latency ok (") (display dt) (display " ms)\n"))

    ;; the ring: failure answer, then a resubmission on the SAME
    ;; connection succeeds with a fresh retry round
    (let ((r (raw-ring 18081
               "GET /crash HTTP/1.1\r\nHost: x\r\n\r\n"
               "\"fault\":\"crash\""
               "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
               "fine" 4000)))
      (expect-contains "retry ring on one connection" r
        "\"fault\":\"crash\"" "HTTP/1.1 200 " "fine"))

    ;; a hook that raises falls back to the plain 500
    (let ((r (raw-ring 18082
               "GET /crash HTTP/1.1\r\nHost: x\r\n\r\n"
               "500" #f #f 4000)))
      (expect-contains "bad hook falls back to 500" r
        "HTTP/1.1 500 " "Internal Server Error"))

    ;; without a hook the behaviour is unchanged
    (let ((r (raw-ring 18083
               "GET /crash HTTP/1.1\r\nHost: x\r\n\r\n"
               "500" #f #f 4000)))
      (expect-contains "default plain 500" r
        "HTTP/1.1 500 " "Internal Server Error"))

    (display "ALL FAULT HOOK TESTS PASSED\n")
    (exit 0)))
