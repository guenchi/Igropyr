# Igropyr

A high-concurrency HTTP server for [Chez Scheme](https://cisco.github.io/ChezScheme/),
built directly on [libuv](https://libuv.org/) through Chez's FFI (no C shim),
with Erlang-style message-passing concurrency and Let-It-Crash fault tolerance.

- **Core / framework split, like Node and Express** — the core exposes one
  entry point, `(http-listen port (lambda (req res) ...))`; the bundled
  `(igropyr express)` layer (`create-app`, `app-get`, `send-json!`, ...) is
  optional, and alternative frameworks can be built on the same core
- **Green processes** — thousands of lightweight processes scheduled over one
  OS thread; continuation-based context switching with preemption, so even a
  CPU-spinning handler cannot freeze the system
- **Pure message passing** — `spawn` / `send` / `receive` / `link` / `monitor`;
  no shared state between processes
- **Fault tolerant by default** — a fixed worker pool behind a supervisor:
  crashed workers are replaced and the task retried (at most 3 times, then
  the client gets a 500); workers stuck for more than 30 s are killed and
  replaced; a slow or half-sent request only ever blocks its own reader process
- **Hot code swapping** — replace the handler (or individual routes) on a
  live server: the listener, open connections and worker pool stay up,
  in-flight requests finish on the old code
- **WebSocket** — RFC 6455 upgrade on the same port; each socket is its own
  green process, so server push is just a message send
- **Streaming responses & SSE** — chunked response body via
  `res-begin!`/`res-write!`/`res-end!`; Server-Sent Events helpers on top
- **OTP building blocks** — `gen-server` (call/cast/info), a process
  registry (`register`/`whereis`), and topic PubSub with automatic
  cleanup of dead subscribers
- **JSON** — a safe recursive-descent parser (no `read`; full escape and
  surrogate handling) and writer
- **Forms & cookies** — `req-form` parses urlencoded and multipart bodies
  (file uploads included); `req-cookie` / `set-cookie!`
- **Chunked transfer-encoding** — `Transfer-Encoding: chunked` request
  bodies are decoded transparently
- **Non-blocking Redis and MySQL clients** — pure Scheme, same event
  loop; callers park their green process while the OS thread keeps
  serving; MySQL comes with a self-healing connection pool
- **Runtime introspection & graceful shutdown** — `http-stats` (live
  connection/request/pool counters), `http-shutdown!` (drain in-flight
  requests, refuse new connections)
- **Multi-process scaling** — `SO_REUSEPORT` bind option for
  kernel-balanced multi-process listening on Linux/FreeBSD (pair with
  pm2 or systemd)
- **HTTP/1.1 keep-alive & pipelining** — persistent connections by default
  on 1.1; each connection's reader process loops over successive requests
- **Hardened** — strict `Content-Length` validation, per-request response
  isolation, response-header injection guard, static-mount boundary
  checks, WebSocket frame validation with a reassembly cap
- **Fast** — ~35 k req/s at 500 concurrent connections on an Apple Silicon
  laptop (`ab -n 50000 -c 500`, zero failed requests)

For architecture, the actor model, the libuv-callback invariant, and
contribution guidelines, see [DEVELOPING.md](DEVELOPING.md).

## Requirements

- Chez Scheme 10.x
- libuv 1.x

```sh
brew install chezscheme libuv        # macOS
# apt install chezscheme libuv1-dev  # Debian/Ubuntu
```

The libuv shared object path is set at the top of `uv.sc`
(`/opt/homebrew/lib/libuv.1.dylib` by default); adjust it for your system,
e.g. `libuv.so.1` on Linux.

## Getting started

Clone the repository into a directory named `igropyr` (the R6RS library name
is lowercase; on case-sensitive file systems the directory name must match):

```sh
git clone https://github.com/guenchi/Igropyr igropyr
export CHEZSCHEMELIBDIRS=.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
scheme --script igropyr/test/run-otp.sc
```

Then:

```sh
curl localhost:8080/
curl localhost:8080/users/42?verbose=1
curl -X POST -d 'hello' localhost:8080/echo
```

## Writing an application

With the bundled Express-style layer:

```scheme
(import (chezscheme)
        (igropyr actor)
        (igropyr http)
        (igropyr express))

(define app (create-app))

;; routes: GET/POST/PUT/DELETE, :param path segments
(app-get app "/hello/:name"
  (lambda (req res)
    (send-text! res (string-append "hello " (req-param req "name")))))

(app-post app "/api/data"
  (lambda (req res)
    (send-json! res (list (cons 'received (utf8->string (req-body req)))))))

;; middleware: call (next) to continue the chain
(app-use app
  (lambda (req res next)
    (if (req-header req 'authorization)
        (next)
        (begin (set-status! res 403) (send-text! res "Forbidden")))))

;; static files: /assets/style.css -> ./public/style.css
(app-static app "/assets" "./public")

;; enter the scheduler and listen; never returns
(start-scheduler
  (lambda ()
    (app-listen app 8080 8)))   ; port 8080, 8 workers (default 8)
```

The pool and its fault tolerance are configurable — pass an alist instead
of the worker count (any key may be omitted; values below are the
defaults):

```scheme
(app-listen app 8080
  '((workers . 8)         ; pool size
    (max-retries . 3)     ; crash retries per task, then 500
    (stuck-ms . 30000)    ; busy longer than this => killed & replaced
    (check-ms . 5000)))   ; how often the ticker checks for stuck workers
```

### Request accessors

| Procedure | Result |
|---|---|
| `(req-method req)` | method symbol: `GET`, `POST`, ... |
| `(req-path req)` | decoded path string |
| `(req-param req "id")` | `:param` path segment value, or `#f` |
| `(req-query req)` | query string as an alist of strings |
| `(req-header req 'content-type)` | header value (keys are lowercase symbols), or `#f` |
| `(req-body req)` | request body as a bytevector |

### Response helpers

Set status and extra headers first, then send exactly once:

```scheme
(set-status! res 201)               ; core primitive
(set-header! res "X-Request-Id" "abc")
(send-text! res "created")     ; text/plain        (express)
(send-html! res "<h1>hi</h1>") ; text/html         (express)
(send-json! res obj)           ; alist -> object, list -> array (express)
(send-file! res "path/to/f")   ; MIME type from extension       (express)
```

A second send on the same request is ignored, so a supervisor fallback can
never corrupt a response that already went out.

## The core API (build your own framework)

The core is framework-agnostic, like Node's `http` module: it owns
parsing, connections, the worker pool and response encoding, and takes a
single handler. Everything express does is expressible in user space:

```scheme
(import (chezscheme) (igropyr actor) (igropyr http))

(start-scheduler
  (lambda ()
    (http-listen 8080
      (lambda (req res)
        (case (req-method req)
          ((GET)
           (set-header! res "Content-Type" "text/plain")
           (res-send! res (string->utf8 (req-path req))))
          (else
           (set-status! res 405)
           (res-send! res (string->utf8 "Method Not Allowed"))))))))
```

Core primitives: `set-status!`, `set-header!`, `res-send!` (body
bytevector; Content-Length, Connection and the one-shot guard are handled
for you). Request accessors as above, minus `req-param` (route params are
a framework concern; the core request carries a free `req-params` slot
for layers to use). The fault-tolerance semantics below come with the
core, whatever layer you put on top.

## Hot code swapping

Two levels, both zero-downtime (listener, open connections and the worker
pool are untouched; requests already executing finish on the old code):

- **Route level (express)**: registering a route that already exists
  *replaces* it on the live app. Re-evaluating a routes file against a
  running app is a hot reload:

  ```scheme
  (app-get app "/version" v2-handler)   ; replaces the old /version
  ```

- **Handler level (core)**: `app-listen` / `http-listen` return the server;
  swap the entire handler — even a different framework layer — atomically:

  ```scheme
  (define srv (app-listen app 8080))
  (http-swap! srv (app->handler another-app))
  (http-set-ws! srv another-ws-resolver)
  ```

Try it on the demo server: `GET /version` answers `v1`; `GET /upgrade`
replaces the route; `GET /version` now answers `v2 (hot swapped)`.

## WebSocket

Served on the same port via the standard upgrade handshake. Each
connection runs in its own green process; `ws-recv` blocks only that
process. Pings are answered and fragmented messages reassembled
automatically.

```scheme
(import (igropyr websocket))

(app-ws app "/ws"                      ; :param segments work here too
  (lambda (ws req)
    (ws-send-text! ws "welcome")
    (let loop ()
      (let ((m (ws-recv ws)))          ; #(text s) | #(binary bv) | #(close)
        (case (vector-ref m 0)
          ((text) (ws-send-text! ws (vector-ref m 1)) (loop))
          ((binary) (ws-send-binary! ws (vector-ref m 1)) (loop))
          (else 'closed))))))
```

Server push from other processes: hand them the `ws` (or its pid) and
call `ws-send-text!` — writes are safe from any green process. On the
bare core, register a resolver with `(http-set-ws! srv (lambda (req)
session-or-#f))`.

## Streaming responses and SSE

Stream a body with chunked transfer-encoding. Detach a long stream from
the pool worker by spawning a producer process, so the worker returns to
the pool immediately:

```scheme
(app-get app "/sse"
  (lambda (req res)
    (sse-start! res)                      ; text/event-stream, chunked
    (spawn
      (lambda ()
        (let loop ((i 1))
          ;; sse-send! returns #f once the client disconnects
          (if (and (<= i 5) (sse-send! res (string-append "tick " (number->string i))))
              (begin (sleep-ms 300) (loop (+ i 1)))
              (res-end! res)))))))
```

The lower-level primitives are `res-begin!`, `res-write!` (string or
bytevector; returns `#f` if the client is gone), and `res-end!`.

## JSON

`(igropyr json)` is a safe recursive-descent parser — it never calls
`read`, so it is safe on untrusted request bodies — plus a writer.
Objects map to alists (string keys), arrays to vectors, `null` to
`'null`.

```scheme
(import (igropyr json))
(string->json "{\"a\":[1,2],\"b\":\"x\"}")   ; => (("a" . #(1 2)) ("b" . "x"))
(json->string '(("ok" . #t) ("n" . 42)))     ; => "{\"ok\":true,\"n\":42}"
(json-ref (string->json "{\"a\":{\"b\":9}}") "a" "b")  ; => 9
```

In a handler, `req-json` parses the request body (returns `#f` on
invalid JSON) and `send-json!` serializes:

```scheme
(app-post app "/api"
  (lambda (req res)
    (let ((j (req-json req)))
      (send-json! res (list (cons 'echo (json-ref j "name")))))))
```

## Forms and cookies

`req-form` parses both `application/x-www-form-urlencoded` and
`multipart/form-data`; text fields are strings and uploads are
`#(file ,filename ,content-type ,bytevector)`.

```scheme
(app-post app "/upload"
  (lambda (req res)
    (for-each
      (lambda (kv)
        (let ((v (cdr kv)))
          (when (vector? v)               ; a file part
            (save-file (vector-ref v 1) (vector-ref v 3)))))
      (req-form req))
    (send-text! res "ok")))

(app-get app "/login"
  (lambda (req res)
    (set-cookie! res "sid" "abc123" "Path=/" "HttpOnly")
    (send-text! res (or (req-cookie req "sid") "no session"))))
```

## OTP building blocks

Beyond raw `spawn`/`send`/`receive`, three OTP-style libraries make
stateful services and fan-out easy.

A `gen-server` is a stateful service reduced to callbacks; calls carry a
unique tag and monitor the server, so a crash surfaces immediately
instead of hanging:

```scheme
(import (igropyr gen-server))
(gen-server-start-named 'counter
  (lambda () 0)                                  ; init -> state
  (lambda (msg from state) (values (+ state 1) (+ state 1)))  ; handle-call
  (lambda (msg state) state))                    ; handle-cast
(gen-server-call 'counter 'incr)                 ; => 1  (by registered name)
```

The process registry decouples a name from the pid behind it, so a
supervised service can be found again after a restart:
`(register 'db pid)`, `(whereis 'db)`.

PubSub is topic fan-out; dead subscribers are pruned automatically, which
pairs naturally with one-process-per-WebSocket chat rooms:

```scheme
(import (igropyr pubsub))
(start-pubsub!)                                  ; once, at boot
(app-ws app "/chat/:room"
  (lambda (ws req)
    (let ((topic (string->symbol (req-param req "room"))))
      (subscribe topic)
      (spawn (lambda ()                          ; relay room traffic to this socket
               (let lp () (receive (`#(pub ,t ,m) (ws-send-text! ws m) (lp))))))
      (let lp ()
        (let ((m (ws-recv ws)))
          (if (eq? (vector-ref m 0) 'text)
              (begin (publish topic (vector-ref m 1)) (lp))
              'closed))))))
```

## Redis and MySQL

Both clients ride the same libuv loop and actor model: each database
connection is one green process; a caller sends it a message and parks
in `receive` until the reply lands. No OS thread ever blocks — a
hundred workers can wait on the database while other requests keep
being served.

```scheme
(import (igropyr redis) (igropyr mysql))

;; Redis (RESP2): concurrent commands are pipelined over one connection
(define r (redis-connect "127.0.0.1" 6379))
(redis r "SET" "greeting" "hello")     ; -> "OK"
(redis r "GET" "greeting")             ; -> "hello"
(redis r "GET" "missing")              ; -> #f        (nil)
(redis r "LRANGE" "l" 0 -1)            ; -> ("a" "b") (arrays -> lists)

;; MySQL (text protocol; caching_sha2_password, both fast and full
;; RSA paths, so it works against MySQL 8/9 out of the box)
(define db (mysql-connect "127.0.0.1" 3306 "user" "password" "mydb"))
(mysql-query db "SELECT id, name FROM users")
  ;; -> #(rows ("id" "name") (("1" "Alice") ("2" "Bob")))  NULL -> #f
(mysql-query db "INSERT INTO users (name) VALUES ('Eve')")
  ;; -> #(ok 1 3)   ; affected rows, last insert id

;; MySQL pool: n real connections behind one dispatcher; queries run in
;; parallel, dead connections are replaced automatically, and the pool
;; is used exactly like a single connection
(define pool (mysql-pool 8 "127.0.0.1" 3306 "user" "password" "mydb"))
(mysql-query pool "SELECT ...")
```

Server errors raise `#(redis-error msg)` / `#(mysql-error code msg)` in
the caller — inside a route handler that means Let It Crash: the worker
dies, the supervisor retries, the service keeps running.

MySQL's `caching_sha2_password` fast path (challenge-response, no
password on the wire) needs no configuration. The *full* auth path sends
the password RSA-encrypted; doing that over a plaintext connection is
refused by default (a MITM could substitute the key). Enable it by
pinning the server key or opting in explicitly:

```scheme
(mysql-connect host port user pw "db"
  '((server-public-key . "-----BEGIN PUBLIC KEY-----...")))   ; pinned key
(mysql-connect host port user pw "db"
  '((allow-insecure-auth . #t)))                              ; TLS/trusted net only
```

## Fast routes

By default every request goes through the worker pool, which buys crash
retry and stuck-kill at the cost of ~4 inter-process messages and a
context switch per request. For a handler that is pure and returns
promptly, that round trip is the dominant per-request cost. Mark such a
route *fast* and it runs inline in the connection's reader process,
skipping the pool:

```scheme
(app-get-fast app "/" (lambda (req res) (send-html! res "hi")))
;; also app-post-fast / app-put-fast / app-delete-fast
```

Measured on a trivial keep-alive route, this cuts per-request CPU by
~20% (roughly 145k -> 200k req/s at one saturated core). The trade-off:
a fast handler loses the pool's fault tolerance — a crash is caught and
answered `500` for that one connection (no retry), and a handler that
blocks or loops freezes only its own connection (no 30 s stuck-kill).
Use it only for pure, prompt handlers; leave anything with side effects,
database calls, or heavy work on the default pooled path.

## Fault tolerance semantics

These apply to pooled routes (the default); nothing to configure:

- **Crash**: a handler that raises kills its worker. The supervisor spawns a
  replacement and retries the task, at most 3 times (4 executions total);
  after that the client receives `500` and the task is dropped. Service is
  never interrupted.
- **Stuck**: a ticker checks the pool every 5 s; any worker busy for more
  than 30 s is killed and replaced. Stuck tasks are *not* retried (retrying
  an infinite loop would re-stick the pool). Even with every worker stuck,
  the service recovers by itself within ~35 s.
- **Slow clients**: each connection is owned by its own reader process; a
  half-sent request parks only that reader and is reaped after 30 s.

## Runtime introspection and graceful shutdown

`app-listen` / `http-listen` return the server. `http-stats` gives a live
snapshot; `http-shutdown!` stops accepting and drains in-flight requests
before returning (call it from a detached process, never from a pool
worker):

```scheme
(define srv (app-listen app 8080))
(app-get app "/stats" (lambda (req res) (send-json! res (http-stats srv))))
;;   => {"connections":12,"requests":34210,"uptime-ms":90000,
;;       "idle":5,"busy":3,"pending":0}
(spawn (lambda () (http-shutdown! srv) (exit 0)))   ; graceful stop
```

## Multi-process scaling

Chez runs on one OS thread, so a single process saturates one core. To
use all cores, run N processes bound to the same port with
`SO_REUSEPORT` and let the kernel balance connections (Linux 3.9+ /
FreeBSD 12+; not macOS):

```scheme
(app-listen app 8080 '((reuseport . #t)))
```

Launch and supervise the N processes with pm2 (fork mode) or systemd.
Because processes share nothing, per-process state (the worker pool, the
route table, PubSub topics, WebSocket rooms) is local to each — share
across processes through Redis, and use Redis pub/sub as a cross-process
event bus.

## Architecture

```
uv.sc      libuv FFI: event loop, TCP, write queue, GC-rooting registries
actor.sc   green processes: spawn/send/receive, link/monitor, preemptive
           scheduler (call/1cc + timer interrupt), run/sleep queues
otp.sc     supervisor + fixed worker pool + stuck-worker ticker
http.sc    core: incremental HTTP/1.1 parser (content-length + chunked),
           connection lifecycle, response encoding, websocket upgrade,
           http-listen / http-swap! / http-set-ws!
websocket.sc  WebSocket codec: SHA-1/base64 handshake key, frame
              encode/decode, ws-recv / ws-send-text! / ws-close!
express.sc framework layer (optional): router with :param segments,
           middleware chain, static files, app-ws, forms/cookies,
           SSE, JSON/text/html/file encoders
json.sc    safe recursive-descent JSON parser + writer
gen-server.sc  OTP gen-server (call/cast/info)
pubsub.sc  topic publish/subscribe with dead-subscriber cleanup
redis.sc   non-blocking Redis client (RESP2), pipelined
mysql.sc   non-blocking MySQL client (caching_sha2_password) + pool
```

The actor scheduler (`register`/`whereis`/`monitor`/`demonitor`) and the
libuv-callback invariant that everything rests on are documented in
[DEVELOPING.md](DEVELOPING.md).

Message protocol between processes:

```
reader     -> supervisor : #(submit-task ,task)
supervisor -> worker     : #(process-task ,task)
worker     -> supervisor : #(task-completed ,task-id ,self)
ticker     -> supervisor : #(check-stuck-workers)        ; every 5 s
worker death             : #(DOWN ,pid ,reason)          ; via monitor
```

The `receive` macro accepts an optional timeout clause, which must come
first, as in Erlang:

```scheme
(receive (after 5000 (handle-timeout))
  (`#(tcp-data ,bv) (consume bv))
  (`#(tcp-eof) (close)))
```

## Building for production

Running from source (`scheme --script`) interprets the libraries. For
deployment, compile. Two options:

```sh
# Per-library .so files (hot-path files at optimize-level 3, rest at 2).
# Loaded automatically in place of the sources (.so precedes .sc in
# CHEZSCHEMELIBEXTS). Good for development, since --script keeps working.
scheme --libdirs .:lib --script igropyr/build.ss

# Whole-program: fold every library + the app into one optimized program
# (cross-library inlining, optimize-level 3). Run it with --program.
scheme --libdirs .:lib --script igropyr/build-whole.ss
scheme --program igropyr/app.so
```

Re-run the build after editing any source. Interrupt traps stay enabled
(preemptive scheduling needs them). optimize-level 3 elides bounds/type
checks; the bytevector loops are all guarded and the full test suite is
run after each build to confirm.

Note on where the time goes: for a trivial handler the per-request cost
is dominated by syscalls, HTTP parsing, and message passing, not Scheme
arithmetic, so compilation buys only a few percent there — it matters
most for CPU-heavy handlers (large JSON, crypto, data munging). To cut
the per-request overhead of a trivial route, mark it *fast* (see below).

## Load testing

macOS defaults to 256 file descriptors per process; raise the limit in both
the server and the benchmark shell:

```sh
ulimit -n 10240
ab -k -n 100000 -c 200 http://127.0.0.1:8080/     # keep-alive
```

A single `ab` process is itself the bottleneck on loopback (one core
saturates the benchmark, not the server); run several in parallel to
find the server's real ceiling — around 145 k req/s on one core for a
trivial keep-alive route on an Apple Silicon laptop.

## Tests

Layered smoke tests, each runnable on its own:

```sh
scheme --script igropyr/test/smoke-echo.sc        # FFI layer: bare echo server
scheme --script igropyr/test/smoke-actor.sc       # scheduler: ping-pong, timeouts, preemption
scheme --script igropyr/test/smoke-echo-actor.sc  # process-per-connection echo
scheme --script igropyr/test/run-otp.sc           # the full HTTP server
```

## License

MIT
