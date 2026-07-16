# Igropyr

A high-concurrency HTTP server framework for [Chez Scheme](https://cisco.github.io/ChezScheme/),
built directly on [libuv](https://libuv.org/) through Chez's FFI (no C shim):
Erlang-style green processes, a Let-It-Crash worker pool, process-per-dialogue
conversations, and s-expression RPC.

**[igropyr.com](https://igropyr.com)** · **[Manual](https://igropyr.com/manual.html)**

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
- **Failure hook (remote retry ring)** — when retries are exhausted or a
  stuck worker is killed (killed first, so no execution is in flight), an
  optional `on-failure` handler answers a structured JSON fault instead
  of the plain 500, on the same keep-alive connection — the client
  resubmits (changed parameters, carried state) and gets a fresh retry
  round; unset, the plain 500 remains
- **Conversations (process-per-dialogue)** — a multi-request dialogue
  (wizard, booking, transfer) runs as one green process holding live
  state — even an open database transaction — across rounds;
  `suspend!` answers and parks, `conversation-resume!` continues, and
  death for any reason (crash, TTL) means guaranteed rollback: a later
  resume gets `gone`
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
- **JWT** — `(igropyr jwt)` signs and verifies HS256 tokens (algorithm
  pinned, constant-time compare, strict base64url, fail-closed); the
  format-neutral `auth` middleware guards routes with a `Bearer` token,
  taking any verifier — `(jwt-verifier key)` today — and answers 401
  otherwise
- **Chunked transfer-encoding** — `Transfer-Encoding: chunked` request
  bodies are decoded transparently
- **Non-blocking Redis and MySQL clients** — pure Scheme, same event
  loop; callers park their green process while the OS thread keeps
  serving; MySQL comes with a self-healing connection pool
- **Non-blocking HTTP & WebSocket clients** — outbound `http-get` /
  `http-post` and `ws-connect`, both with async DNS (libuv thread pool)
  and the same park-the-caller model; `https://` / `wss://` via the
  optional `(igropyr tls)` library (OpenSSL as a byte codec, certificates
  verified — the core stays dependency-free)
- **Static file serving** — hot files come from an in-memory cache (a
  hashtable lookup: no disk read, no `stat` syscall; mtime re-checked at
  most once a second). A cache miss reads once on libuv's thread pool, so
  a cold read never blocks the scheduler; files over 1 MiB stream in
  bounded chunks with backpressure, never read whole
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
- **Distributed actors** — connect nodes into a mesh (`(igropyr node)`):
  `rsend`/`rcall` to a process registered on another node,
  `monitor-node`/`monitor-remote`, cluster-wide PubSub, a distributed
  task pool (`(igropyr dpool)`), and automatic discovery (`(igropyr
  cluster)`, static or Redis)
- **S-expression RPC** — when both ends are Scheme, `(igropyr sexpr)` is
  a safe whitelisted codec (no `read`, depth-limited); `app-rpc` /
  `send-sexpr!` / `ws-send-sexpr!` carry one datum per message. Its
  extended wire mode — used by the node-to-node links and by browser
  clients ([Goeteia](https://goeteia.dev)) — carries vectors, bytevectors
  (`#vu8"…"`, base64) and **every IEEE double bit-exact** (`#f8"…"`, the
  8 IEEE-754 bytes; inf and nan included), so binary and floats cross
  Chez ↔ WebAssembly with no loss and no decimal-printing rounding
- **HTTP/1.1 keep-alive & pipelining** — persistent connections by default
  on 1.1; each connection's reader process loops over successive requests
- **Dev-time contracts** — `(igropyr checked)` adds `define-checked` /
  `define-checked-record` for internal invariants, gated on
  `IGROPYR_CONTRACTS` at compile time: `off` (the default) compiles to
  nothing with zero residue, `full` injects checks that blame the
  offending procedure/argument. The bundled libraries carry boundary
  contracts on their exports under a debug build
- **Fast** — ~35 k req/s at 500 concurrent connections on an Apple Silicon
  laptop (`ab -n 50000 -c 500`, zero failed requests)

## Architecture

A layered stack, each layer a thin surface over the one below:

- **`(igropyr express)`** — routing, middleware, and the `req-*` / `send-*!`
  request and response helpers; optional, and alternative frameworks can be
  built on the core.
- **HTTP core + WebSocket** — HTTP/1.1 parsing, keep-alive and pipelining,
  chunked bodies, and the RFC 6455 upgrade.
- **Actor scheduler** — thousands of green processes over one OS thread,
  continuation-based context switches with preemption; `spawn` / `send` /
  `receive` / `link` / `monitor`, no shared state.
- **libuv FFI** — one event loop, reached through Chez's FFI (no C shim);
  DNS, file reads and socket I/O park the calling process, never the thread.

Fault tolerance is a **supervised worker pool**: a crashed worker is replaced
and its task retried (at most 3 times, then a 500); a worker stuck past 30 s
is killed and replaced; a slow request only ever blocks its own reader
process. `gen-server`, `link` / `monitor` and topic PubSub are the OTP
building blocks — isolation is by process, not by locks.

For the actor model, the libuv-callback invariant, and contribution
guidelines, see [the manual](https://igropyr.com/manual.html).

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
;; once and cached in memory (re-read only when their mtime changes; the
;; mtime itself is re-checked at most once per second), so serving a hot
;; asset is a hashtable lookup -- no disk read, no stat syscall.
;; Responses carry a weak ETag and Cache-Control, and a matching
;; If-None-Match gets 304 Not Modified. Files over 1 MiB are never
;; buffered whole: they stream as a fixed-length response in 64 KiB
;; chunks with backpressure -- each chunk is read from disk only after
;; the previous one drained to the client, so a 10 GB download to a
;; slow peer costs one chunk of memory, and the pool worker is released
;; immediately (the pump runs in its own process).
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

Every encoder also accepts a bytevector, taken as the already-encoded
body. For a response that never changes, do the encoding **once at
startup with `define`** instead of re-encoding the same constant on
every request — the handler then just hands the framework a pointer:

```scheme
(define home-page (string->utf8 "<h1>hi</h1>"))          ; encoded once
(define info-json (string->utf8 (json->string my-alist))) ; serialized once

(app-get app "/"     (lambda (req res) (send-html! res home-page)))
(app-get app "/info" (lambda (req res) (send-json! res info-json)))
```

The same applies to anything derivable at startup (rendered templates,
lookup tables, composed strings): compute it in a `define` at top level,
not inside the handler.

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
raises `#(http-client-error msg)`.

**`https://`** works once you enable the optional `(igropyr tls)`
library — one import plus one call at startup, and every `http-get` /
`http-request` (and `ws-client`'s `wss://`) can reach TLS endpoints:

```scheme
(import (igropyr client) (igropyr tls))
(tls-enable!)                                 ; once, before the first https request

(let ((r (http-get "https://api.github.com/zen"
                   '((headers . (("User-Agent" . "igropyr")))))))
  (response-status r)                          ; -> 200
  (utf8->string (response-body r)))
```

TLS lives in its own library so the core stays dependency-free: nothing
loads OpenSSL unless you import it. It runs as a pure byte codec in
memory-BIO mode — libuv keeps owning the socket, the event loop, and
timeouts; OpenSSL only transforms bytes, and the handshake is driven
inside the request's own green process, so nothing blocks. Certificates
are **verified by default** (peer chain, hostname/IP SANs, TLS ≥ 1.2,
system trust roots — `SSL_CERT_FILE` / `SSL_CERT_DIR` honored); a
verification failure raises `#(http-client-error "tls: …")`. Needs
OpenSSL 3 or 1.1 (or LibreSSL) present as a shared library. See
**Outbound TLS** below.

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
across processes through Redis, or connect them into an actor mesh with
the distribution layer below.

## Distribution across nodes

`SO_REUSEPORT` scales stateless HTTP but leaves each process an island.
`(igropyr node)` connects instances — other cores over loopback, other
machines over the network — into a mesh where a process on one node can
message a **registered name** on another. The semantics deliberately
mirror Erlang distribution.

```scheme
(import (igropyr node))

;; node b: identity + listener (127.0.0.1 unless a host is given)
(node-start! 'b "shared-secret" 4100)
(register 'worker self)

;; node a: dial b (auto-reconnects), then talk to it
(node-start! 'a "shared-secret")
(node-connect! 'b "10.0.0.2" 4100)
(rsend 'b 'worker (vector 'job 42))       ; fire-and-forget -> #t / #f
(rcall 'b 'calc  (vector 'square 7))      ; synchronous gen-server call -> 49
(monitor-node 'b)                         ; -> #(node-up b) / #(node-down b)
(monitor-remote 'b 'worker)               ; -> #(remote-down b worker reason)
```

Addressing is by registered name (pids are memory objects; names survive
restarts). `rsend` is fire-and-forget with per-pair ordering; `rcall` is
its synchronous counterpart. Payloads cross in the extended s-expression
wire mode, so vectors, bytevectors and finite flonums arrive intact and
exact integers/ratios stay exact. `(igropyr pubsub)` becomes cluster-wide
automatically once nodes are linked — a `publish` reaches subscribers on
every node, so the chat-room example works across the mesh unchanged.

**Distributed task pool** — spread work across nodes with the local
worker pool's Let-It-Crash story lifted to node level:

```scheme
(import (igropyr dpool))
(dpool-worker-start 'render (lambda (job) (resize job)))   ; on each member
(define pool (dpool-start '(b c) 'render))                 ; on the submitter
(dpool-await pool (dpool-submit pool (vector 'resize "x.png" 800)))
```

Failure mode is per pool, overridable per task: **at-least-once**
(default; a node death re-dispatches the task — completes for sure, may
run twice, needs idempotent tasks) or **at-most-once** (a node death
fails it — never re-run). Exactly-once isn't offered: no message-passing
system gives both across a crash.

**Automatic discovery** — instead of dialing every peer by hand,
`(igropyr cluster)` periodically asks a strategy for the member list and
dials new ones:

```scheme
(import (igropyr cluster))
(cluster-start `((discover . (static (b "10.0.0.2" 4100) (c "10.0.0.3" 4100)))))
(cluster-start `((name . "myapp") (discover . (redis ,conn "10.0.0.1" 4100))))
```

The **redis** strategy heartbeats each node into a per-cluster sorted set
scored by an expiry timestamp; a crashed node falls out on its own, with
no central bookkeeping.

> **Security:** the dist port is full control of the node — anyone on it
> can message any registered process, including supervisors. The
> handshake is a mutual HMAC-SHA1 challenge/response on the shared
> secret, but there is no TLS and the port binds `127.0.0.1` by default.
> Across machines, keep it on a private network (WireGuard, VPC). For a
> cluster-wide singleton or leader election, use a system that already
> solved consensus (Redis `SET NX`, etcd) — a network partition turns
> in-process election into split-brain.

## HTTPS / TLS

Two directions, handled differently. **Inbound** (browsers reaching your
server) is terminated by a reverse proxy — covered here. **Outbound**
(your code calling `https://` APIs) is the optional `(igropyr tls)`
library — see [Outbound TLS](#outbound-tls) at the end of this section
and the `https://` example under [Outbound HTTP](#outbound-http).

### Inbound: terminate at a reverse proxy

Igropyr's server speaks plain HTTP; terminate inbound TLS in a reverse
proxy in front of it. This is the standard deployment and gets you
automatic certificates, HTTP/2 to the browser, and OCSP stapling for
free, without the server owning TLS or its CVE surface.

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

### Outbound TLS

For the other direction — calling `https://` services from your own code
— import `(igropyr tls)` and call `(tls-enable!)` once at startup; then
the HTTP client and `ws-client` speak `https://` / `wss://`. Unlike the
inbound side, this is a real TLS client *in* the process, so it verifies
certificates itself.

```scheme
(import (igropyr client) (igropyr tls))
(tls-enable!)
(http-get "https://example.com/")
```

Why a separate optional library, not the server:

- **The core stays dependency-free.** Only `(igropyr tls)` touches
  OpenSSL; a program that never imports it never loads it, and the build
  and every other library are unchanged whether or not OpenSSL is
  installed.
- **TLS is a codec, not an I/O owner.** OpenSSL runs in memory-BIO mode:
  libuv still owns the socket, the event loop, and timeouts, and the
  handshake is driven by ordinary `receive` inside the request's own
  green process. No threads, no callbacks, no blocking of other
  processes — the same actor model as a plain request.
- **Client verification is non-negotiable and on by default:**
  `SSL_VERIFY_PEER`, hostname (or IP-literal) SAN matching, TLS ≥ 1.2,
  and the system trust store (override with the standard `SSL_CERT_FILE`
  / `SSL_CERT_DIR`). A bad chain or wrong hostname fails the request with
  `#(http-client-error "tls: …")` rather than silently connecting.

Requires OpenSSL 3 or 1.1 (or LibreSSL) as a shared library — found via
the usual platform paths (including Homebrew's `openssl@3`). Inbound
HTTPS still belongs at the proxy.

## Internals

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
tls.sc     optional outbound TLS (OpenSSL memory-BIO codec) for https/wss
redis.sc   non-blocking Redis client (RESP2), pipelined
mysql.sc   non-blocking MySQL client (caching_sha2_password) + pool
```

The actor scheduler (`register`/`whereis`/`monitor`/`demonitor`) and the
libuv-callback invariant that everything rests on are documented in
[the manual](https://igropyr.com/manual.html).

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
