# Igropyr

[English](README.md) | [简体中文](README.zh-CN.md)

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
- **Middleware suite** — cookie sessions (gen-server store, CSPRNG sids),
  CORS with preflight, security headers, and an access logger
- **Chunked transfer-encoding** — `Transfer-Encoding: chunked` request
  bodies are decoded transparently
- **Non-blocking Redis and MySQL clients** — pure Scheme, same event
  loop; callers park their green process while the OS thread keeps
  serving; MySQL comes with a self-healing connection pool
- **Non-blocking HTTP & WebSocket clients** — outbound `http-get` /
  `http-post` and `ws-connect`, both with async DNS (libuv thread pool)
  and the same park-the-caller model
- **Async file reads** — static files are read on libuv's thread pool,
  so a large or cold read never blocks the scheduler
- **gzip compression** — responses negotiated via `Accept-Encoding`;
  static files cache their compressed form
- **Ops-ready** — rate limiting, a global error handler, and a
  Prometheus `/metrics` endpoint
- **Runtime introspection & graceful shutdown** — `http-stats` (live
  connection/request/pool counters), `http-shutdown!` (drain in-flight
  requests, refuse new connections)
- **Multi-process scaling** — `SO_REUSEPORT` bind option for
  kernel-balanced multi-process listening on Linux (pair with
  pm2 or systemd)
- **HTTP/1.1 keep-alive & pipelining** — persistent connections by default
  on 1.1; each connection's reader process loops over successive requests
- **Hardened** — strict `Content-Length` validation, per-request response
  isolation, response-header injection guard, static-mount boundary +
  symlink-escape + NUL-byte checks, pipeline flood cap, WebSocket frame
  validation with strict UTF-8 (1007 close) and a reassembly cap,
  binary-safe Redis replies, request-id matching on all DB/HTTP clients
- **Fast** — ~35 k req/s at 500 concurrent connections on an Apple Silicon
  laptop (`ab -n 50000 -c 500`, zero failed requests)

For architecture, the actor model, the libuv-callback invariant, and
contribution guidelines, see [docs/MANUAL.md](docs/MANUAL.md) or
[简体中文手册](docs/MANUAL.zh-CN.md).

## Requirements

- Chez Scheme 10.x
- libuv 1.x
- zlib 1.x
- macOS or Linux on x86_64/arm64

```sh
brew install chezscheme libuv        # macOS
# apt install chezscheme libuv1-dev zlib1g-dev  # Debian/Ubuntu
```

Igropyr selects the platform ABI and loads libuv, zlib, and the system C
library automatically. Supported Chez machine types are macOS/Linux on
x86_64 and arm64; an unsupported host fails at import time with a clear error.

## Getting started

Clone the repository into a directory named `igropyr` (the R6RS library name
is lowercase; on case-sensitive file systems the directory name must match):

```sh
git clone https://github.com/guenchi/Igropyr igropyr
export CHEZSCHEMELIBDIRS=.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
scheme --script igropyr/test/run-otp.sc   # `chez` also works on some distros
```

Then:

```sh
curl localhost:8080/
curl localhost:8080/users/42?verbose=1
curl -X POST -d 'hello' localhost:8080/echo
```

## Writing an application

With the bundled Express-style layer. `(igropyr http)` is the core and
re-exports the app-facing actor surface (`start-scheduler`, `spawn`,
`receive`, ...); express, websocket and the other batteries plug in on
demand:

```scheme
(import (chezscheme)
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

;; static files: /assets/style.css -> ./public/style.css. Files are read
;; once and cached in memory (re-read only when their mtime changes), so
;; serving an unchanged asset is a hashtable lookup, not a disk read.
;; Responses carry a weak ETag and Cache-Control, and a matching
;; If-None-Match gets 304 Not Modified. Files over 1 MiB are served but
;; not cached.
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
single handler. It re-exports the app-facing actor surface, so it is a
single import too. Everything express does is expressible in user space:

```scheme
(import (chezscheme) (igropyr http))

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
Redis bulk strings are binary-safe: valid UTF-8 comes back as a string,
and non-UTF-8 data comes back as a bytevector.

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

## Outbound HTTP

The HTTP *client* rides the same model: each request runs in its own
green process (async DNS via libuv's thread pool, then connect/send/
read) while the caller parks. Handy for calling other services from
inside a handler.

```scheme
(import (igropyr client))

(let ((r (http-get "http://api.internal/users/42")))
  (response-status r)                       ; -> 200
  (response-header r 'content-type)         ; -> "application/json"
  (utf8->string (response-body r)))          ; body is a bytevector

(http-post "http://api.internal/events" "{\"type\":\"click\"}"
           '((headers . (("Content-Type" . "application/json")))
             (timeout . 5000)))
```

One connection per request (no pooling); a transport failure or timeout
raises `#(http-client-error msg)`. https is not supported directly —
reach TLS-only endpoints through a proxy (see HTTPS below).

## Middleware suite

Ready-made middleware for common needs. Register them with `app-use`;
order matters (outermost first).

```scheme
(import (igropyr session) (igropyr middleware))

(app-use app (error-handler))              ; outermost: catch -> 500 JSON
(app-use app (logger))                     ; "GET /path -> 200 (3ms)"
(app-use app (security-headers '((hsts . #t))))  ; X-Frame-Options, nosniff, ...
(app-use app (cors '((origin . "https://app.example.com")
                     (credentials . #t))))       ; + 204 OPTIONS preflight
(app-use app (rate-limit '((max . 100) (window . 60000))))  ; 429 over limit

;; cookie-based sessions backed by a gen-server store (sids from the OS
;; CSPRNG, TTL-pruned); the session is loaded onto the request and saved
;; after the handler if it changed
(define store (make-session-store))         ; at boot
(app-use app (session-middleware store))

(app-get app "/visits"
  (lambda (req res)
    (let* ((s (req-session req))
           (n (+ 1 (or (session-get s 'visits) 0))))
      (session-set! s 'visits n)             ; persisted automatically
      (send-json! res (list (cons 'visits n))))))
```

Middleware can also stash arbitrary values on the request for later
handlers with `req-set-local!` / `req-local` (this is how sessions ride
along). Writing your own is just `(lambda (req res next) ...)` — call
`(next)` to continue, or respond and return to short-circuit.

Prometheus metrics: a middleware records every request, and an endpoint
renders per-status counts, request-duration, and connection/pool gauges:

```scheme
(import (igropyr metrics))
(define m (make-metrics))                   ; at boot
(app-use app (metrics-middleware m))
;; after app-listen returns the server:
(app-get app "/metrics" (metrics-endpoint m srv))
;;   igropyr_requests_total{status="200"} 1234
;;   igropyr_request_duration_ms_sum 45210
;;   igropyr_connections 12  ... igropyr_pool_busy 3
```

## Outbound WebSocket

`ws-connect` dials a `ws://` URL, does the upgrade handshake, and returns
a client-role session — the same object the server side uses, so
`ws-recv` / `ws-send-text!` / `ws-close!` work unchanged (outbound frames
are masked as RFC 6455 requires).

```scheme
(import (igropyr ws-client))
(let ((w (ws-connect "ws://127.0.0.1:8080/chat/42")))
  (ws-send-text! w "hello")
  (ws-recv w)                 ; -> #(text s) | #(binary bv) | #(close)
  (ws-close! w))
```

`wss` is refused — reach TLS-only endpoints through a proxy.

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

## HTTPS / TLS

Igropyr speaks plain HTTP; terminate TLS in a reverse proxy in front of
it. This is the standard deployment and gets you automatic certificates,
HTTP/2 to the browser, and OCSP stapling for free, without the server
owning TLS or its CVE surface.

**Caddy** (automatic Let's Encrypt certificates, one line per host):

```caddyfile
example.com {
    reverse_proxy 127.0.0.1:8080
}
```

That is the whole config — Caddy obtains and renews the certificate on
its own. WebSocket upgrades pass through unchanged.

**nginx** (manual or certbot-managed certificate), forwarding both plain
requests and WebSocket upgrades, and balancing across the reuseport
processes:

```nginx
upstream igropyr {
    server 127.0.0.1:8080;      # add more if not sharing a port via SO_REUSEPORT
    keepalive 64;
}

server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass http://igropyr;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # WebSocket upgrade
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

With `SO_REUSEPORT` (see above) all worker processes share `:8080`, so
one `upstream` entry suffices; otherwise give each process its own port
and list them all. Read the client's real IP from `X-Forwarded-For` and
the original scheme from `X-Forwarded-Proto`.

## Architecture

```
libuv.sc   libuv FFI: event loop, TCP, async DNS, async file reads,
           write queue, GC roots
actor.sc   green processes: spawn/send/receive, link/monitor/register,
           preemptive scheduler (call/1cc + timer interrupt), run/sleep queues
otp.sc     supervisor + fixed worker pool + stuck-worker ticker
http.sc    core: incremental HTTP/1.1 parser (content-length + chunked),
           connection lifecycle, response encoding, websocket upgrade,
           streaming, http-listen / http-swap! / http-set-ws!
websocket.sc  WebSocket codec (server + client roles): handshake key,
              frame encode/decode, ws-recv / ws-send-text! / ws-close!
ws-client.sc  outbound WebSocket (ws-connect)
express.sc framework layer (optional): router with :param segments,
           middleware chain, static files (cached + gzip), app-ws,
           forms/cookies, SSE, JSON/text/html/file encoders
json.sc    safe recursive-descent JSON parser + writer
gzip.sc    gzip compression via zlib
gen-server.sc  OTP gen-server (call/cast/info)
pubsub.sc  topic publish/subscribe with dead-subscriber cleanup
session.sc     cookie sessions on a gen-server store
middleware.sc  cors / security-headers / logger / rate-limit / error-handler
metrics.sc     Prometheus /metrics endpoint
client.sc  non-blocking outbound HTTP client (async DNS)
redis.sc   non-blocking Redis client (RESP2), pipelined
mysql.sc   non-blocking MySQL client (caching_sha2_password) + pool
```

The actor scheduler (`register`/`whereis`/`monitor`/`demonitor`) and the
libuv-callback invariant that everything rests on are documented in
[docs/MANUAL.md](docs/MANUAL.md) and [docs/MANUAL.zh-CN.md](docs/MANUAL.zh-CN.md).

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
# Per-library .so files (optimize-level 2: full optimization, all
# type/bounds checks kept). Loaded automatically in place of the sources
# (.so precedes .sc in CHEZSCHEMELIBEXTS). Good for development, since
# --script keeps working.
scheme --libdirs .:lib --script igropyr/build.ss

# Whole-program: fold every library + the app into one optimized program
# (cross-library inlining, optimize-level 2). Run it with --program.
scheme --libdirs .:lib --script igropyr/build-whole.ss
scheme --program igropyr/app.so
```

Re-run the build after editing any source. Interrupt traps stay enabled
(preemptive scheduling needs them).

Profile-guided optimization (`build-profile.ss` to instrument,
`/admin/profdump` to collect after driving load, `build-pgo.ss` to
recompile with the profile) is available but **measured no improvement
here** — for an I/O-bound server whose per-request cost is syscalls,
message passing, and scheduling, there is no hot/cold branch structure
for PGO to reorder, and whole-program already inlines across libraries.
Keep it in mind only if you add branch-heavy CPU-bound handlers.

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

Run the complete, self-asserting test suite:

```sh
./igropyr/test/run-all.sh
```

It checks library imports, actor scheduling, asynchronous file reads, strict
HTTP framing/query behavior, and boot-failure propagation. The older echo and
`run-otp.sc` programs remain available as interactive smoke/demo servers.

## License

MIT
