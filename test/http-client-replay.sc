#!chezscheme
;;; test/http-client-replay.sc -- a request that has already delivered data
;;; to its on-chunk handler is never sent again.
;;;
;;; The client keeps a connection after a framed, drained response and
;;; reuses it for the next request to the same host. The keeper process
;;; that owns the connection caught errors with the caller and reference of
;;; the FIRST request it served. When a later, reused request's on-chunk
;;; handler raised, the keeper died reporting to that stale reference; the
;;; current caller saw only a DOWN, took it for a connection that went stale
;;; before anything happened, and retried the request on a fresh
;;; connection -- after its handler had already run once. A handler that
;;; writes or counts did its work twice.
;;;
;;; THE READINGS ARE ON BOTH SIDES: how many times the handler ran, read
;;; from the handler's own counter, and how many requests the server saw
;;; for that path, read from the server.
;;;
;;; The second shape: a handler that consumed its first chunk and then
;;; lost the connection (the server sends part of a framed body and
;;; closes). Nothing raised in the handler, but data was delivered, so the
;;; request is not replayable either: one handler call, one request at the
;;; server, and a failure. That row reads the client's EOF path, which
;;; never retried a request that had made progress. The third shape reaches
;;; the other check: on-chunk runs in the keeper's process, so a handler
;;; that kills its own process ends the keeper after data was delivered;
;;; the caller sees the keeper's DOWN, and only the "handler already
;;; called" check keeps that from being retried as a stale connection.
;;;
;;; The last rows are not the stale retry itself: by the time the next
;;; request is made the client has already seen the server's EOF and
;;; dropped the kept connection, so it simply dials. The stale-retry race
;;; and its counters are test/http-client-keepalive.sc's; here they only
;;; show that a request after a server-side close still succeeds once.

(import (chezscheme) (igropyr actor) (igropyr tcp) (igropyr http-client))

(define port 18855)
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
(define (head-path text)
  (let* ((sp1 (index-of text " " 0))
         (sp2 (and sp1 (index-of text " " (+ sp1 1)))))
    (if (and sp1 sp2) (substring text (+ sp1 1) sp2) "/")))

;; what the server saw: (path . connection-number) per request, newest first
(define requests (box '()))
(define connections (box 0))
(define (seen path)
  (length (filter (lambda (r) (string=? (car r) path)) (unbox requests))))

;; every reply is framed by Content-Length and keeps the connection; the
;; /close-after reply is followed by the server closing the connection
(define (reply-for path)
  (if (string=? path "/half")
      ;; a 10-byte body of which only 5 bytes follow; the server closes after
      (string-append "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello")
      (string-append "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")))

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (set-box! connections (+ (unbox connections) 1))
      (let* ((conn-no (unbox connections))
             (pid (spawn
                    (lambda ()
                      (guard (e (#t (void)))
                        (let loop ((acc ""))
                          (receive (after 30000 (tcp-close! c))
                            (`#(tcp-data ,bv)
                              (let* ((text (string-append acc (utf8->string bv)))
                                     (hend (index-of text "\r\n\r\n" 0)))
                                (if (not hend)
                                    (loop text)
                                    (let ((path (head-path text)))
                                      (set-box! requests (cons (cons path conn-no) (unbox requests)))
                                      (tcp-write! c (string->utf8 (reply-for path)) #f)
                                      (if (member path '("/close-after" "/half"))
                                          (begin (sleep-ms 100) (tcp-close! c))
                                          (loop (substring text (+ hend 4) (string-length text))))))))
                            (`#(tcp-eof) (tcp-close! c))
                            (`#(tcp-error ,e) (tcp-close! c)))))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(define (url path) (string-append "http://127.0.0.1:" (number->string port) path))

(define (condition-text e)
  (if (condition? e)
      (call-with-string-output-port
        (lambda (p)
          (when (message-condition? e) (display (condition-message e) p))
          (when (irritants-condition? e) (display " " p) (write (condition-irritants e) p))))
      e))
;; -> (ok . body) | (error . message) | (raised . text)
(define (request path . opts)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'http-client-error)) (cons 'error (vector-ref e 1)))
            (#t (cons 'raised (condition-text e))))
    (let ((r (http-request 'GET (url path) (append (if (pair? opts) (car opts) '()) '((timeout . 5000))))))
      (cons 'ok (utf8->string (response-body r))))))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 100)

    ;; ---- the pooled connection ------------------------------------------------------
    (let ((r (request "/first")))
      (check "setup: the first request succeeds and leaves a kept connection" (equal? r '(ok . "hello")) r))
    (sleep-ms 100)
    (let ((r (request "/second")))
      (check "setup: a second request reuses it (same connection number at the server)"
             (and (equal? r '(ok . "hello")) (= (unbox connections) 1)) r (unbox connections)))

    ;; ---- a reused request whose handler raises after receiving data ------------------
    (let* ((calls 0)
           (r (request "/raising" (list (cons 'on-chunk (lambda (bv) (set! calls (+ calls 1)) (raise 'handler-boom)))))))
      (sleep-ms 300)
      (check "the request is reported as failed by its handler"
             (and (eq? (car r) 'error) (index-of (cdr r) "on-chunk handler raised" 0)) r)
      (check "the handler ran ONCE: the request was not replayed on a fresh connection"
             (= calls 1) calls)
      (check "and the server saw that path once" (= (seen "/raising") 1) (seen "/raising") (unbox requests)))

    ;; ---- a handler that raises on the FIRST request of a connection -------------------
    ;; (the case the stale caller reference covered by accident): same answer
    (sleep-ms 200)
    (let* ((calls 0)
           (r (request "/raising-fresh" (list (cons 'reuse #f)
                                              (cons 'on-chunk (lambda (bv) (set! calls (+ calls 1)) (raise 'handler-boom)))))))
      (sleep-ms 300)
      (check "a fresh connection's raising handler is reported the same way"
             (and (eq? (car r) 'error) (index-of (cdr r) "on-chunk handler raised" 0)) r)
      (check "a fresh connection's raising handler also runs once" (= calls 1) calls)
      (check "and the server saw that path once" (= (seen "/raising-fresh") 1) (seen "/raising-fresh")))

    ;; ---- a handler that consumed data, then the connection died --------------------------
    ;; established on a kept connection first, so the request is a reused one
    (sleep-ms 200)
    (let ((r (request "/establish")))
      (check "setup: a kept connection is established again" (equal? r '(ok . "hello")) r))
    (sleep-ms 100)
    (let* ((calls 0)
           (conns (unbox connections))
           (r (request "/half" (list (cons 'on-chunk (lambda (bv) (set! calls (+ calls 1))))))))
      (sleep-ms 300)
      (check "setup: /half went on the kept connection" (= (unbox connections) conns) (unbox connections) conns)
      (check "a request whose handler received data before the connection died is reported as failed"
             (eq? (car r) 'error) r)
      (check "its handler ran once" (= calls 1) calls)
      (check "and the server saw that path once" (= (seen "/half") 1) (seen "/half") (unbox requests)))

    ;; ---- a handler that ends the keeper's process after receiving data -------------------
    (sleep-ms 200)
    (let ((r (request "/establish-3")))
      (check "setup: a kept connection is established again" (equal? r '(ok . "hello")) r))
    (sleep-ms 100)
    (let* ((calls 0)
           (conns (unbox connections))
           (r (request "/suicide" (list (cons 'on-chunk (lambda (bv) (set! calls (+ calls 1)) (kill self 'cell-kill)))))))
      (sleep-ms 300)
      (check "setup: /suicide went on the kept connection" (= (unbox connections) conns) (unbox connections) conns)
      (check "a reused request whose handler ended the keeper after receiving data is failed, not retried"
             (and (eq? (car r) 'error) (index-of (cdr r) "not retried" 0)) r)
      (check "its handler ran once" (= calls 1) calls)
      (check "and the server saw that path once" (= (seen "/suicide") 1) (seen "/suicide") (unbox requests)))

    ;; ---- twin: a well-behaved streaming request on a reused connection ------------------
    (sleep-ms 200)
    (let ((r (request "/establish-2")))
      (check "setup: a kept connection is established again" (equal? r '(ok . "hello")) r))
    (sleep-ms 100)
    (let* ((calls 0)
           (conns (unbox connections))
           (r (request "/streamed" (list (cons 'on-chunk (lambda (bv) (set! calls (+ calls 1))))))))
      (check "twin: a streaming request on a kept connection delivers its body once"
             (and (eq? (car r) 'ok) (= calls 1) (= (seen "/streamed") 1)) r calls (seen "/streamed"))
      (check "twin: and it did go on the kept connection" (= (unbox connections) conns) (unbox connections) conns))

    ;; ---- a request after the server closed the kept connection ------------------------------
    ;; (see the header: the client has seen the EOF by then and dials; the
    ;; stale-retry race is measured in http-client-keepalive.sc)
    (let ((r (request "/close-after")))
      (check "setup: the server answered and closed the kept connection" (equal? r '(ok . "hello")) r))
    (sleep-ms 300)
    (let* ((before (unbox connections))
           (r (request "/after-stale")))
      (check "a request after the server closed the kept connection succeeds"
             (equal? r '(ok . "hello")) r)
      (check "  once, on a new connection"
             (and (= (seen "/after-stale") 1) (= (unbox connections) (+ before 1)))
             (seen "/after-stale") before (unbox connections)))

    (if (zero? failures)
        (begin (display "http-client-replay: all tests passed\n") (exit 0))
        (begin (display "http-client-replay: ") (display failures) (display " failed\n") (exit 1)))))
