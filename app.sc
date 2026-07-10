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

(import (chezscheme)
        (igropyr actor)
        (igropyr libuv)
        (igropyr otp)
        (igropyr http)
        (igropyr websocket)
        (igropyr json)
        (igropyr pubsub)
        (igropyr express))

(define app (create-app))

;; middleware: request log line (comment out under load testing if noisy)
(app-use app
  (lambda (req res next)
    (next)))

(app-get app "/"
  (lambda (req res)
    (send-html! res "<h1>Igropyr</h1><p>Chez Scheme + libuv + actors</p>")))

(app-get app "/json"
  (lambda (req res)
    (send-json! res (list (cons 'name "igropyr")
                          (cons 'engine "chez-scheme")
                          (cons 'io "libuv")
                          (cons 'workers 8)))))

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
