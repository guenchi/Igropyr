#!chezscheme
;;; http-client: reported defects in reuse, streaming and caller lifetime.
;;;
;;;   * a caller that dies must end its request. The keeper owns the socket,
;;;     the TLS codec and the on-chunk handler; a stream has no total
;;;     deadline by design, so a caller killed by its supervisor left all of
;;;     that running, delivering into a process that no longer exists, for
;;;     as long as the upstream cared to keep sending.
;;;   * a streaming idle timeout must measure PROGRESS, not bytes. It was
;;;     re-armed on every arriving segment, so an upstream could dribble
;;;     bytes that never complete a chunk: on-chunk never fired and the
;;;     request never timed out.
;;;   * a repeated Connection field is one field with the values joined
;;;     (RFC 7230 3.2.2). Reading only the first meant "keep-alive" then
;;;     "close" was pooled.
;;;   * only HTTP/1.1 defaults to persistent. Excluding the exact string
;;;     "HTTP/1.0" left every other version -- including ones this client
;;;     does not speak -- defaulting to keep-alive.
;;;   * a bodyless POST is not replayable. "Has no body" was treated as
;;;     replayable, so a POST the server had already performed could be
;;;     sent a second time when the connection dropped before its answer.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http-client))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18795)
(define accepts (box 0))
(define effects (box 0))          ; how many times the server DID the thing

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
                                (let ((path (head-path text))
                                      (rest (substring text (+ hend 4)
                                                       (string-length text))))
                                  (cond
                                    ;; two Connection fields, the second decisive
                                    ((string=? path "/dupconn")
                                     (tcp-write! c (string->utf8
                                       (string-append
                                         "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                         "Connection: keep-alive\r\n"
                                         "Connection: close\r\n\r\nhi")) #f)
                                     (loop rest))
                                    ;; a version this client does not speak
                                    ((string=? path "/oddver")
                                     (tcp-write! c (string->utf8
                                       "HTTP/9.9 200 OK\r\nContent-Length: 2\r\n\r\nhi") #f)
                                     (loop rest))
                                    ;; performs the effect, then drops without
                                    ;; answering -- the shape that makes a
                                    ;; retry duplicate work
                                    ((string=? path "/effect")
                                     (set-box! effects (+ (unbox effects) 1))
                                     (tcp-close! c))
                                    ;; a chunked stream that dribbles bytes
                                    ;; which never complete a chunk
                                    ((string=? path "/dribble")
                                     (tcp-write! c (string->utf8
                                       (string-append
                                         "HTTP/1.1 200 OK\r\n"
                                         "Transfer-Encoding: chunked\r\n\r\n"
                                         "ffff\r\n")) #f)
                                     (let drip ()
                                       (tcp-write! c (string->utf8 "x") #f)
                                       (receive (after 100 (drip))
                                         (`#(tcp-eof) (tcp-close! c))
                                         (`#(tcp-error ,_) (tcp-close! c)))))
                                    ;; an endless chunked stream that DOES
                                    ;; deliver, for the caller-death case
                                    ((string=? path "/forever")
                                     (tcp-write! c (string->utf8
                                       (string-append
                                         "HTTP/1.1 200 OK\r\n"
                                         "Transfer-Encoding: chunked\r\n\r\n")) #f)
                                     (let feed ()
                                       (tcp-write! c (string->utf8 "1\r\nx\r\n") #f)
                                       (receive (after 100 (feed))
                                         (`#(tcp-eof) (tcp-close! c))
                                         (`#(tcp-error ,_) (tcp-close! c)))))
                                    (else
                                     (tcp-write! c (string->utf8
                                       "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi") #f)
                                     (loop rest)))))))
                        (`#(tcp-eof) (tcp-close! c))
                        (`#(tcp-error ,_) (tcp-close! c)))))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(define (url path) (string-append "http://127.0.0.1:" (number->string port) path))
(define (get path) (http-request 'GET (url path) '((timeout . 4000))))

(define (reset!)
  (http-client-close-idle!)
  (sleep-ms 300)
  (set-box! accepts 0)
  (set-box! effects 0))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 200)

    ;; ---- a repeated Connection field --------------------------------------
    (reset!)
    (guard (e (#t 'ok)) (get "/dupconn"))
    (guard (e (#t 'ok)) (get "/dupconn"))
    (check "Connection: close in a SECOND field still refuses reuse"
      (= 2 (unbox accepts)))

    ;; ---- a version this client does not speak -----------------------------
    (reset!)
    (guard (e (#t 'ok)) (get "/oddver"))
    (guard (e (#t 'ok)) (get "/oddver"))
    (check "an unknown HTTP version is not pooled" (= 2 (unbox accepts)))

    ;; ---- a bodyless POST is not replayed -----------------------------------
    ;; The server performs the effect and then drops without answering. On a
    ;; POOLED connection that looks exactly like a stale hand-out, and a
    ;; retry would perform it twice. "Nothing was received" means nothing was
    ;; received -- not that nothing was done.
    (reset!)
    (guard (e (#t 'ok)) (get "/ka"))          ; put a connection in the pool
    (sleep-ms 200)
    (let ((r (guard (e (#t 'failed))
               (http-request 'POST (url "/effect") '((timeout . 4000))))))
      (display "  [info] bodyless POST outcome: ") (display r)
      (display ", server effects=") (display (unbox effects)) (newline)
      (check "a bodyless POST is performed at most once" (<= (unbox effects) 1)))

    ;; ...while a GET in the same situation IS retried, because repeating it
    ;; cannot repeat an effect
    (reset!)
    (guard (e (#t 'ok)) (get "/ka"))
    (sleep-ms 200)
    (let ((r (guard (e (#t 'failed)) (get "/ka"))))
      (check "a GET still succeeds over a pooled connection"
        (not (eq? r 'failed))))

    ;; ---- a stream that dribbles without ever completing a chunk ------------
    ;; Run it in its own process and watch from here. Without the fix the
    ;; request NEVER returns, and a test that simply called it would hang the
    ;; whole suite instead of failing -- a hang says "something is wrong
    ;; somewhere", a failure says which assertion.
    (reset!)
    (let ((seen (box 0)) (me self))
      (let ((runner
              (spawn (lambda ()
                       (let ((t0 (now-ms)))
                         (guard (e (#t (send me (vector 'drib (- (now-ms) t0)))))
                           (http-request 'GET (url "/dribble")
                             (list (cons 'timeout 600)
                                   (cons 'on-chunk
                                         (lambda (bv)
                                           (set-box! seen (+ (unbox seen) 1))))))
                           (send me (vector 'drib (- (now-ms) t0)))))))))
        (let ((ms (receive (after 4000 'never-returned) (`#(drib ,v) v))))
          (display "  [info] dribbled stream ended after ") (display ms)
          (display " with ") (display (unbox seen)) (display " chunks delivered\n")
          (check "no chunk was ever delivered" (= 0 (unbox seen)))
          ;; the idle allowance is 600 ms and bytes arrive every 100 ms, so
          ;; only a clock that measures PROGRESS can end this
          (check "a stream with no progress still times out"
            (and (number? ms) (< ms 3000)))
          (kill runner 'done))))

    ;; ---- a caller that dies ------------------------------------------------
    ;; The stream keeps delivering; the caller is killed. Everything after
    ;; that is work for nobody, and a stream has no total deadline to stop it.
    (reset!)
    (let ((calls (box 0)) (me self))
      (let ((victim (spawn (lambda ()
                             (guard (e (#t (void)))
                               (http-request 'GET (url "/forever")
                                 (list (cons 'timeout 0)
                                       (cons 'on-chunk
                                             (lambda (bv)
                                               (set-box! calls
                                                         (+ (unbox calls) 1)))))))))))
        (sleep-ms 500)
        (let ((before (unbox calls)))
          (check "the stream is running" (> before 0))
          (monitor victim)
          (kill victim 'reaped)
          (receive (after 2000 (void)) (`#(DOWN ,@victim ,_) 'ok))
          (sleep-ms 1200)
          (display "  [info] on-chunk calls: ") (display before)
          (display " at the kill, ") (display (unbox calls))
          (display " a second later\n")
          (check "the handler stops when its caller dies"
            (<= (unbox calls) (+ before 1)))
          (check "and the connection goes with it"
            (= 0 (cdr (assq 'idle (http-client-pool-stats))))))))

    (http-client-close-idle!)
    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "http-client-hardening: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
