#!chezscheme
;;; http-client connection reuse.
;;;
;;; The client opened a connection per request and sent Connection: close.
;;; For a service that talks to another service that is a TCP handshake per
;;; call, and over TLS a full handshake -- usually more time than the request
;;; itself.
;;;
;;; What is asserted here is that connections are REUSED, counted at the
;;; server: how many times it accepted, against how many requests it served.
;;; "The requests succeeded" was true before and proves nothing.
;;;
;;; The cases that must NOT reuse are pinned too, because getting those wrong
;;; is worse than not pooling at all: a connection whose response said
;;; `close`, one whose body was delimited by the close itself, and one the
;;; caller opted out of. Reusing any of them desynchronises the next request
;;; on that socket.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http-client))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18793)

(define accepts (box 0))     ; how many TCP connections the server accepted
(define served (box 0))      ; how many requests it answered

;; A minimal keep-alive server. It serves any number of requests per
;; connection and answers per the path:
;;   /ka     Content-Length body, keep-alive
;;   /chunk  chunked body, keep-alive
;;   /close  Content-Length body, Connection: close
;;   /eof    body delimited by the close (no length, no chunking)
(define (index-of text sub from)
  (let ((n (string-length text)) (m (string-length sub)))
    (let loop ((i from))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring text i (+ i m))) i)
            (else (loop (+ i 1)))))))

;; the path of a request head: "GET /x HTTP/1.1"
(define (head-path text)
  (let* ((sp1 (index-of text " " 0))
         (sp2 (and sp1 (index-of text " " (+ sp1 1)))))
    (if (and sp1 sp2) (substring text (+ sp1 1) sp2) "/ka")))

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 32
    (lambda (c)
      (set-box! accepts (+ (unbox accepts) 1))
      (let ((pid
              (spawn
                (lambda ()
                  (let loop ((acc ""))
                    (receive (after 20000 (tcp-close! c))
                      (`#(tcp-data ,bv)
                        (let* ((text (string-append acc (utf8->string bv)))
                               (hend (index-of text "\r\n\r\n" 0)))
                          (if (not hend)
                              (loop text)
                              (let ((path (head-path text))
                                    (rest (substring text (+ hend 4)
                                                     (string-length text))))
                                (set-box! served (+ (unbox served) 1))
                                (cond
                                  ((string=? path "/close")
                                   (tcp-write! c (string->utf8
                                     "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi") #f)
                                   (sleep-ms 50)
                                   (tcp-close! c))
                                  ((string=? path "/eof")
                                   (tcp-write! c (string->utf8
                                     "HTTP/1.1 200 OK\r\n\r\nhi") #f)
                                   (sleep-ms 50)
                                   (tcp-close! c))
                                  ;; says close but does NOT close. Real
                                  ;; intermediaries do this, and it is the
                                  ;; only way to test that the client obeys
                                  ;; the header rather than merely noticing
                                  ;; the socket go away.
                                  ((string=? path "/saysclose")
                                   (tcp-write! c (string->utf8
                                     "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi") #f)
                                   (loop rest))
                                  ;; answers as a normal keep-alive response
                                  ;; and then hangs up at once: the client
                                  ;; pools a connection that is already gone
                                  ((string=? path "/hangup")
                                   (tcp-write! c (string->utf8
                                     "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi") #f)
                                   (tcp-close! c))
                                  ((string=? path "/chunk")
                                   (tcp-write! c (string->utf8
                                     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n") #f)
                                   (loop rest))
                                  (else
                                   (tcp-write! c (string->utf8
                                     "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi") #f)
                                   (loop rest)))))))
                      (`#(tcp-eof) (tcp-close! c))
                      (`#(tcp-error ,_) (tcp-close! c))))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(define (url path) (string-append "http://127.0.0.1:" (number->string port) path))

(define (get path . opts)
  (http-request 'GET (url path) (if (pair? opts) (car opts) '((timeout . 4000)))))

(define (reset!)
  (http-client-close-idle!)
  (sleep-ms 200)
  (set-box! accepts 0)
  (set-box! served 0))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 200)

    ;; ---- the point of the exercise --------------------------------------
    (reset!)
    (let loop ((i 0))
      (when (< i 5)
        (let ((r (get "/ka")))
          (unless (and (= 200 (response-status r))
                       (equal? "hi" (utf8->string (response-body r))))
            (set! failures (+ failures 1))
            (display "FAIL  response ") (display i) (newline)))
        (loop (+ i 1))))
    (display "  [info] 5 requests over ") (display (unbox accepts))
    (display " connection(s), server served ") (display (unbox served)) (newline)
    (check "five requests reuse one connection" (= 1 (unbox accepts)))
    (check "and the server saw all five" (= 5 (unbox served)))

    ;; chunked framing is determinate too, so it pools as well -- and this
    ;; is where the final chunk and its trailer must have been consumed,
    ;; or the next request on the socket would read them as its status line
    (reset!)
    (let loop ((i 0))
      (when (< i 3)
        (let ((r (get "/chunk")))
          (unless (equal? "hi" (utf8->string (response-body r)))
            (set! failures (+ failures 1))
            (display "FAIL  chunked body ") (display i) (newline)))
        (loop (+ i 1))))
    (check "chunked responses reuse the connection too" (= 1 (unbox accepts)))
    (check "and each chunked body is intact" (= 3 (unbox served)))

    ;; ---- what must NOT be reused ----------------------------------------
    (reset!)
    (get "/close")
    (get "/close")
    (check "a response saying close is not reused" (= 2 (unbox accepts)))

    ;; The case above passes even if the header is ignored, because that
    ;; server really does close and the keeper then sees the eof. This one
    ;; says close and keeps the socket open, so only obeying the HEADER
    ;; produces two connections.
    (reset!)
    (get "/saysclose")
    (get "/saysclose")
    (check "Connection: close is obeyed even when the peer lingers"
      (= 2 (unbox accepts)))

    (reset!)
    (get "/eof")
    (get "/eof")
    (check "a close-delimited body is not reused" (= 2 (unbox accepts)))

    (reset!)
    (get "/ka" '((timeout . 4000) (reuse . #f)))
    (get "/ka" '((timeout . 4000) (reuse . #f)))
    (check "opting out dials every time" (= 2 (unbox accepts)))
    ;; and an opted-out request leaves nothing behind for the next one
    (check "opting out leaves the pool empty"
      (= 0 (cdr (assq 'idle (http-client-pool-stats)))))

    ;; ---- a stale pooled connection --------------------------------------
    ;; The keeper notices the server's close while idle and removes itself,
    ;; so the next request dials instead of failing.
    (reset!)
    (get "/ka")
    (check "one connection is pooled after a request"
      (= 1 (cdr (assq 'idle (http-client-pool-stats)))))
    ;; make the server drop it: /close on a NEW connection would not touch
    ;; the pooled one, so close the pool from this side and confirm the
    ;; registry empties
    (http-client-close-idle!)
    (sleep-ms 300)
    (check "closing the pool empties it"
      (= 0 (cdr (assq 'idle (http-client-pool-stats)))))
    (let ((before (unbox accepts)))
      (get "/ka")
      (check "and the next request dials again" (> (unbox accepts) before)))

    ;; ---- a connection that went stale after being handed out -------------
    ;;
    ;; The keeper normally sees the server's close while idle and takes
    ;; itself out of the pool. What it cannot see is a close that lands after
    ;; it has already been handed to a request. Nothing was received in that
    ;; case, so no server acted on the request and it is sent again on a
    ;; fresh connection.
    ;;
    ;; /hangup answers and closes at once, so the next request races the
    ;; keeper's own discovery of the eof. Either ordering must end in a
    ;; served request: whichever wins, the caller must never see the error.
    (reset!)
    (let ((before (http-client-pool-stats)))
      (let loop ((i 0) (ok 0))
        (if (= i 8)
            (begin
              (check "a hung-up pooled connection never reaches the caller"
                (= ok 8))
              (let ((after (http-client-pool-stats)))
                (display "  [info] over 8 rounds: stale ")
                (display (- (cdr (assq 'stale after)) (cdr (assq 'stale before))))
                (display ", retried ")
                (display (- (cdr (assq 'retried after)) (cdr (assq 'retried before))))
                (display ", reused ")
                (display (- (cdr (assq 'reused after)) (cdr (assq 'reused before))))
                (newline)))
            (begin
              (get "/hangup")
              (loop (+ i 1)
                    (+ ok (guard (e (#t 0))
                            (let ((r (get "/ka")))
                              (if (and (= 200 (response-status r))
                                       (equal? "hi" (utf8->string (response-body r))))
                                  1 0)))))))))

    ;; A POST is not replayable, so it is never retried -- but it is still an
    ;; ordinary request, and it must work over a pooled connection like any
    ;; other. (The refusal to retry is only reachable when the race actually
    ;; happens; what is pinned here is that the rule costs POSTs nothing in
    ;; the normal case.)
    (reset!)
    (get "/ka")
    (let ((r (http-request 'POST (url "/ka") '((body . "x") (timeout . 4000)))))
      (check "a POST reuses a pooled connection like any other request"
        (and (= 200 (response-status r)) (= 1 (unbox accepts)))))

    ;; ---- the pool is bounded --------------------------------------------
    (reset!)
    (http-client-pool! 2 8 30000)
    ;; three concurrent requests -> three connections, but only two kept
    (let ((me self))
      (let loop ((i 0))
        (when (< i 3)
          (spawn (lambda () (get "/ka") (send me (vector 'done))))
          (loop (+ i 1))))
      (let wait ((i 0))
        (when (< i 3) (receive (after 5000 'lost) (`#(done) 'ok)) (wait (+ i 1)))))
    (sleep-ms 300)
    (let ((st (http-client-pool-stats)))
      (display "  [info] after 3 concurrent requests: idle ")
      (display (cdr (assq 'idle st))) (display ", accepted ")
      (display (unbox accepts)) (newline)
      (check "the per-origin cap is honoured" (<= (cdr (assq 'idle st)) 2)))
    (http-client-pool! 4 64 30000)

    ;; ---- nothing is left running ----------------------------------------
    ;; Pooling introduces LONG-LIVED processes where there were none, so the
    ;; question "does a request leave anything behind" now has to be asked of
    ;; the process count, not just of fds. A keeper that neither serves nor
    ;; expires is exactly the leak this design could introduce.
    (http-client-close-idle!)
    (sleep-ms 500)
    (let ((base (process-count)))
      (let loop ((i 0)) (when (< i 6) (get "/ka") (loop (+ i 1))))
      (http-client-close-idle!)
      (sleep-ms 700)
      (display "  [info] processes ") (display base) (display " -> ")
      (display (process-count)) (display " across 6 pooled requests\n")
      ;; the registry itself is one process and stays; nothing else may
      (check "pooled requests leave no processes behind"
        (<= (process-count) (+ base 1))))

    (http-client-close-idle!)
    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "http-client-keepalive: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
