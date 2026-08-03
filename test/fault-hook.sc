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

(import (chezscheme) (igropyr util) (igropyr http) (igropyr express)
        (igropyr libuv))

(define empty-bv (make-bytevector 0))

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

(define (fail label detail)
  (display "FAIL: ") (display label) (display " ") (write detail) (newline)
  (exit 1))

;; Open a raw connection, send `text`, read until `marker` appears (or
;; Open a connection, send `text`, and hand the conn back so the caller can
;; decide when to close it -- which is the whole point for the disconnect
;; case, where the client must vanish while its task is still queued.
(define (raw-open port text)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'open-failed ref)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c (string->utf8 text) #f)
            (send caller (vector 'opened ref c))
            ;; hold the process alive so the conn is not swept as ownerless
            (receive (after 30000 'done))))))
    (receive (after 5000 (fail "raw-open timeout" port))
      (`#(opened ,@ref ,c) c)
      (`#(open-failed ,@ref) (fail "raw-open connect failed" port)))))

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
                  ((and (= stage 1) (string-contains? s marker))
                   (if text2
                       (begin
                         (tcp-write! c (string->utf8 text2) #f)
                         (loop buf 2))
                       (begin (tcp-close! c)
                              (send caller (vector 'ring-reply ref s)))))
                  ((and (= stage 2) (string-contains? s marker2))
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
      (unless (string-contains? response needle)
        (fail label (list 'missing needle 'in response))))
    needles)
  (display label) (display " ok\n"))

;; Runs of the handler behind a gate: it must NOT run for a client that
;; already disconnected.
(define abandoned-runs 0)
(define gate-open (box #f))

;; How many times the answered-then-crashing handler actually ran. A retry
;; re-executes the WHOLE handler, so this counts business effects, not
;; responses -- the response can only happen once, the token sees to that.
(define answered-crash-runs 0)

(define (build-app)
  (let ((app (create-app)))
    (app-get app "/ok"
      (lambda (req res) (send-text! res "fine")))
    (app-get app "/crash"
      (lambda (req res) (raise 'deliberate)))
    ;; The shape that must NOT be retried: the effect (here, the counter --
    ;; in an application, a charge or an INSERT) lands, the client is
    ;; answered, and only then something raises. Cleanup, logging, or a
    ;; middleware on its way back out; the bundled access logger writes
    ;; after (next) returns, so a broken log port is a real trigger.
    ;; occupies the single worker until released
    (app-get app "/gate"
      (lambda (req res)
        (let loop ()
          (unless (unbox gate-open) (sleep-ms 20) (loop)))
        (send-text! res "gated")))
    ;; queues behind /gate; its client disconnects before it ever starts
    (app-get app "/abandoned"
      (lambda (req res)
        (set! abandoned-runs (+ abandoned-runs 1))
        (send-text! res "ran")))
    (app-get app "/answered-then-crash"
      (lambda (req res)
        (set! answered-crash-runs (+ answered-crash-runs 1))
        (send-text! res "done")
        (raise 'after-the-response)))
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
    ;; D: ONE worker, so a second request provably queues rather than
    ;; finding a free worker
    (app-listen (build-app) 18084 '((workers . 1)))
    (sleep-ms 100)

    ;; crash envelope: retries exhausted -> structured JSON, keep-alive
    (let ((r (raw-ring 18081
               "GET /crash HTTP/1.1\r\nHost: x\r\n\r\n"
               "\"attempts\"" #f #f 4000)))
      (expect-contains "crash envelope" r
        "HTTP/1.1 503 " "\"fault\":\"crash\"" "\"attempts\":4"
        "\"retryable\":true" "Connection: keep-alive"))

    ;; A task whose client disconnected before it started must not run.
    ;; Workers are few, so a slow handler backs requests up in the queue;
    ;; running one later touches the database and any external service for
    ;; a request nobody is waiting on, and after an outage the whole stale
    ;; backlog fires at once.
    (let ((c1 (raw-open 18084 "GET /gate HTTP/1.1\r\nHost: x\r\n\r\n"))
          (c2 #f))
      (sleep-ms 200)                       ; c1 now occupies the only worker
      (set! c2 (raw-open 18084 "GET /abandoned HTTP/1.1\r\nHost: x\r\n\r\n"))
      (sleep-ms 200)                       ; c2's task is queued behind it
      (tcp-close! c2)                      ; the client gives up and leaves
      (sleep-ms 600)                       ; let the server observe the EOF
      (set-box! gate-open #t)              ; free the worker; the queue drains
      (sleep-ms 800)
      (unless (= abandoned-runs 0)
        (fail "abandoned task still ran" abandoned-runs))
      (tcp-close! c1)
      (display "  ok  a disconnected client's queued task does not run\n"))

    ;; A handler that ANSWERED and then crashed must not be re-run. The
    ;; client already holds a success; re-running repeats whatever the
    ;; handler did before answering, and the claimed token means the retry
    ;; could not produce a response even if it wanted to. So the only thing
    ;; a retry can do here is duplicate side effects.
    (let ((r (raw-ring 18081
               "GET /answered-then-crash HTTP/1.1\r\nHost: x\r\n\r\n"
               "done" #f #f 4000)))
      (expect-contains "answered-then-crash answers once" r
        "HTTP/1.1 200 " "done"))
    ;; give the supervisor the time it would have spent on 3 retries
    (sleep-ms 1200)
    (unless (= answered-crash-runs 1)
      (fail "answered-then-crash re-ran the handler" answered-crash-runs))
    (display "  ok  answered handler is not retried\n")

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
