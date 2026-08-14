;;; Igropyr entry point: Express-style HTTP server on libuv with an
;;; Erlang-style worker pool (Let It Crash).
;;;
;;; Run (from the project root):
;;;   ulimit -n 10240        # macOS defaults to 256; ab -c 500 needs more
;;;   export CHEZSCHEMELIBDIRS=.:lib
;;;   export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
;;;   scheme --script test/run-otp.sc
;;;
;;; Acceptance checks (see 需求.md):
;;;   ab -n 50000 -c 500 http://127.0.0.1:8080/     (two rounds, 0 failures)
;;;   printf 'GET / HTTP/1.1\r\nHost: x' | nc 127.0.0.1 8080 &   # half request
;;;   for i in $(seq 8); do curl -m 2 localhost:8080/stuck & done # recovers <=35s
;;;   curl localhost:8080/crash                     # 500, service keeps running

;; (igropyr http) is the core and re-exports the app-facing actor surface
;; (start-scheduler, spawn, receive, ...); express, websocket and the
;; other batteries plug in on demand.
(import (chezscheme)
        (igropyr http)
        (igropyr express)
        (igropyr websocket)
        (igropyr json)
        (igropyr pubsub)
        (igropyr conversation))

(define app (create-app))

;; middleware: request log line (comment out under load testing if noisy)
(app-use app
  (lambda (req res next)
    (next)))

;; Constant responses are encoded ONCE here, at startup, with define --
;; the handler hands the framework a ready bytevector instead of
;; re-encoding (or re-serializing) the same value on every request.
(define home-page
  (string->utf8 "<h1>Igropyr</h1><p>Chez Scheme + libuv + actors</p>"))

(app-get app "/"
  (lambda (req res)
    (send-html! res home-page)))

(define info-json
  (string->utf8
    (json->string (list (cons 'name "igropyr")
                        (cons 'engine "chez-scheme")
                        (cons 'io "libuv")
                        (cons 'workers 8)))))

(app-get app "/json"
  (lambda (req res)
    (send-json! res info-json)))

(app-get app "/users/:id"
  (lambda (req res)
    (send-json! res (list (cons 'user (req-param req "id"))
                          (cons 'q (map (lambda (kv)
                                          (cons (string->symbol (car kv)) (cdr kv)))
                                        (req-query req)))))))

(app-post app "/echo"
  (lambda (req res)
    (send-text! res (utf8->string (req-body req)))))

;; Single-crash takeover demo: for any given :key the FIRST execution
;; raises; the supervisor retries on another worker, which responds.
;; The reply proves the takeover (worker pids differ) and that the task
;; context (key + query) survived the crash. Use a fresh :key per test.
(define once-log (make-hashtable string-hash string=?))
(app-get app "/once/:key"
  (lambda (req res)
    (let* ((k (req-param req "key"))
           (runs (append (hashtable-ref once-log k '())
                         (list (process-id self)))))
      (hashtable-set! once-log k runs)
      (if (= (length runs) 1)
          (raise 'first-attempt-crash)
          (send-json! res
            (list (cons 'attempt (length runs))
                  (cons 'workers runs)
                  (cons 'key k)
                  (cons 'query (map (lambda (kv)
                                      (cons (string->symbol (car kv)) (cdr kv)))
                                    (req-query req)))))))))

(app-get app "/crash"
  (lambda (req res)
    ;; Let It Crash: the worker dies, the supervisor retries 3 times and
    ;; then answers 500; the pool is refilled and service continues.
    (raise 'handler-crashed)))

(app-get app "/stuck"
  (lambda (req res)
    ;; CPU-spinning handler: preemptive scheduling keeps the rest of the
    ;; system responsive; the supervisor kills this worker after 30s.
    (let loop ((n 0)) (loop (+ n 1)))))

(app-static app "/static" "./public")

;; Admin endpoint: dump PGO profile counters to disk. Only meaningful on
;; a profiling build (compiled with compile-profile); a no-op otherwise.
(app-get app "/admin/profdump"
  (lambda (req res)
    (guard (e (#t (send-text! res "no profile data")))
      (profile-dump-data "app.profile")
      (send-text! res "profile dumped to app.profile"))))

;; Forms: urlencoded and multipart both land in req-form; file uploads
;; arrive as #(file name content-type bytes)
(app-post app "/form"
  (lambda (req res)
    (send-json! res
      (map (lambda (kv)
             (cons (car kv)
                   (let ((v (cdr kv)))
                     (if (vector? v)
                         (list (cons 'filename (vector-ref v 1))
                               (cons 'type (vector-ref v 2))
                               (cons 'size (bytevector-length (vector-ref v 3))))
                         v))))
           (req-form req)))))

;; Header injection guard: a CRLF-carrying value is dropped, not emitted
(app-get app "/inject"
  (lambda (req res)
    (set-header! res "X-Test" "safe")
    (set-header! res "X-Evil" "a\r\nInjected: yes")
    (send-text! res "ok")))

;; Cookies: /cookie/set plants one, /cookie/get reads it back
(app-get app "/cookie/set"
  (lambda (req res)
    (set-cookie! res "sid" "abc123" "Path=/" "HttpOnly")
    (send-text! res "cookie set")))

(app-get app "/cookie/get"
  (lambda (req res)
    (send-text! res (or (req-cookie req "sid") "no cookie"))))

;; JSON request body parsing: POST {"name":"x"} -> {"hello":"x"}
(app-post app "/echo-json"
  (lambda (req res)
    (let ((j (req-json req)))
      (if j
          (send-json! res (list (cons 'hello (or (json-ref j "name") 'null))))
          (begin (set-status! res 400)
                 (send-json! res (list (cons 'error "invalid json"))))))))

;; Server-Sent Events: five ticks, one per 300ms, then done. The stream
;; runs in its own process; the pool worker is released immediately.
(app-get app "/sse"
  (lambda (req res)
    (sse-start! res)
    (spawn
      (lambda ()
        (let loop ((i 1))
          (if (and (<= i 5) (sse-send! res (string-append "tick " (number->string i))))
              (begin (sleep-ms 300) (loop (+ i 1)))
              (res-end! res)))))))

;; Hot reload demo: registering a route that already exists replaces it
;; in the live app -- no restart, listener and connections untouched.
;; GET /version -> "v1"; GET /upgrade swaps it; GET /version -> "v2".
(app-get app "/version"
  (lambda (req res)
    (send-text! res "v1")))

(app-get app "/upgrade"
  (lambda (req res)
    (app-get app "/version"
      (lambda (req res)
        (send-text! res "v2 (hot swapped)")))
    (send-text! res "upgraded")))

;; Conversation demo: a two-step transfer as one process. POST /transfer
;; with an amount provisionally holds it and answers a conversation id;
;; POST /transfer/:id with "confirm" commits, anything else cancels.
;; Abandoning the dialogue (TTL) or a crash before the commit rolls the
;; hold back -- the guard around the suspend! IS the transaction boundary,
;; and a resume then gets 410 Gone: guaranteed rolled back. Past the
;; commit! the guard no longer undoes anything, so the same failure is
;; 409 unknown instead; only the first of those may be retried.
(define account (box 1000))
(app-post app "/transfer"
  (lambda (req res)
    (let ((amt (or (string->number (utf8->string (req-body req))) 0)))
      (if (or (<= amt 0) (> amt (unbox account)))
          (begin (set-status! res 400)
                 (send-json! res (list (cons 'error "bad amount"))))
          ;; ONE IDEMPOTENT RELEASER, used by every path that gives the
          ;; hold back. The flow's guard runs when the flow raises; the
          ;; on-killed hook runs when the watchdog kills a step, because
          ;; @kill discards that guard. Those are normally exclusive -- but
          ;; a flow that raises just as the watchdog decides to kill it
          ;; reaches both, and returning the money twice is a worse bug
          ;; than never returning it. A hold in a database does not need
          ;; this; one in a box does.
          (let* ((released (box #f))
                 (release!
                   (lambda ()
                     (unless (unbox released)
                       (set-box! released #t)
                       (set-box! account (+ (unbox account) amt))))))
          (let-values (((id token reply)
                        (conversation-start!
                          (lambda (req suspend! commit!)
                            (set-box! account (- (unbox account) amt))  ; hold
                            (guard (e (#t (release!) (raise e)))
                              (let ((req2 (suspend! (list (cons 'step "confirm")
                                                          (cons 'amount amt)))))
                                (if (equal? (utf8->string (req-body req2)) "confirm")
                                    (begin
                                      ;; committed: the hold becomes the
                                      ;; transfer, so nothing is released.
                                      ;; THROUGH commit!, because that is
                                      ;; what tells the library the money
                                      ;; moved -- a raise on the way out
                                      ;; after this point must be answered
                                      ;; 'unknown, not 'gone, or the client
                                      ;; retries a transfer that happened.
                                      (commit! (lambda () (set-box! released #t)))
                                      (list (cons 'done #t)
                                            (cons 'balance (unbox account))))
                                    (begin
                                      (release!)
                                      (list (cons 'done #f)
                                            (cons 'cancelled #t)))))))
                          req
                          15000                                         ; demo TTL 15s
                          ;; two retries of the same call are two different
                          ;; request records; what identifies the call is
                          ;; its body, and the body is all that is retained
                          req-body
                          release!)))
            ;; The token goes to the client and must come back with the
            ;; next request. It says WHICH reply is being answered, which is
            ;; what stops a double click or a retried request from advancing
            ;; the flow past a reply nobody read -- here, confirming a
            ;; transfer the user never saw the amount for.
            (send-json! res (cons (cons 'conv id)
                                  (cons (cons 'token token) reply)))))))))

;; The token comes back as ?token=N. A request without it, or with an old
;; one, is refused: it was written against a reply that is no longer the
;; one being answered.
(app-post app "/transfer/:id"
  (lambda (req res)
    (let ((token (cond ((assoc "token" (req-query req)) => cdr) (else ""))))
      ;; the STATUS decides, never the reply -- a flow may legitimately
      ;; return the symbol 'gone as an ordinary answer
      (let-values (((r status) (conversation-resume! (req-param req "id") token req)))
        (cond
          ((conversation-gone? status)
           (set-status! res 410)
           (send-json! res (list (cons 'fault "gone") (cons 'rolled-back #t))))
          ;; NOT 410, and note the absent rolled-back: this node cannot
          ;; say whether the transaction committed -- its record aged out,
          ;; was pushed out by newer ones, or belonged to an earlier
          ;; incarnation of this process. The one thing a client must not
          ;; do with this answer is resubmit; reconcile against your own
          ;; state, which is where the truth still is.
          ((conversation-unknown? status)
           (set-status! res 409)
           (send-json! res (list (cons 'fault "unknown")
                                 (cons 'resubmit #f))))
          ;; 409: this request was NOT applied and will not be. It says
          ;; nothing about whether the request it duplicates succeeded --
          ;; read the current state rather than resubmitting.
          ((conversation-stale? status)
           (set-status! res 409)
           (send-json! res (list (cons 'fault "stale")
                                 (cons 'applied #f))))
          ((conversation-done? status) (send-json! res r))
          (else (send-json! res (cons (cons 'token status) r))))))))

(app-get app "/transfer-balance"
  (lambda (req res)
    (send-json! res (list (cons 'balance (unbox account))))))

;; Chat rooms: WebSocket + PubSub. Every message a client sends is
;; published to its room topic; a forwarder process per connection
;; relays room traffic back out. Dead connections clean themselves up
;; (pubsub monitors its subscribers).
(app-ws app "/chat/:room"
  (lambda (ws req)
    (let ((topic (string->symbol
                   (string-append "room-" (req-param req "room")))))
      (let ((fw (spawn
                  (lambda ()
                    (subscribe topic)
                    (let lp ()
                      (receive
                        (`#(pub ,t ,m) (ws-send-text! ws m) (lp))))))))
        (let lp ()
          (let ((m (ws-recv ws)))
            (if (eq? (vector-ref m 0) 'text)
                (begin (publish topic (vector-ref m 1)) (lp))
                (kill fw 'normal))))))))

;; WebSocket echo: each connection runs in its own process; server push
;; is just (ws-send-text! ws ...) from anywhere holding the ws.
(app-ws app "/ws"
  (lambda (ws req)
    (ws-send-text! ws "welcome")
    (let loop ()
      (let ((m (ws-recv ws)))
        (case (vector-ref m 0)
          ((text)
           (ws-send-text! ws (string-append "echo: " (vector-ref m 1)))
           (loop))
          ((binary)
           (ws-send-binary! ws (vector-ref m 1))
           (loop))
          (else 'closed))))))

(start-scheduler
  (lambda ()
    (start-pubsub!)
    ;; pool config is optional: a plain integer means worker count;
    ;; the alist form configures fault tolerance too (values below are
    ;; the defaults)
    (let ((srv (app-listen app 8080
                 '((workers . 8)
                   (max-retries . 3)
                   (stuck-ms . 30000)
                   (check-ms . 5000)))))
      ;; runtime stats: connections, request count, uptime, pool state
      (app-get app "/stats"
        (lambda (req res)
          (send-json! res (http-stats srv)))))))
