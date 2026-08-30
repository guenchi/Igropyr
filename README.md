# Igropyr

A distributed, fault-tolerant, high-concurrency backend framework with continuation-based web programming and a remote retry ring, built on [Chez Scheme](https://scheme.com/).

**[igropyr.dev](https://igropyr.dev)** · **[Manual](https://igropyr.dev/manual.html)**

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
  state — even an open database transaction — across rounds; `suspend!`
  answers and parks, `conversation-resume!` continues with a token
  naming the reply it answers, so a repeat replays that answer instead
  of taking a step nobody asked for. Failure speaks a protocol — six
  outcomes, each naming its evidence and its remedy: the answer itself
  when it finished, retry only on `gone` (the rollback provably ran),
  the replay on `stale`, reconcile on `unknown` and `unreachable`, come
  back later on `overloaded`. The record outlives the process, so a
  restart does not turn history into `unknown`
- **Hot code swapping** — replace the handler (or individual routes) on a
  live server: the listener, open connections and worker pool stay up,
  in-flight requests finish on the old code
- **WebSocket** — RFC 6455 upgrade on the same port; each socket is its own
  green process, so server push is just a message send. Upgrades can be
  guarded before the handshake — `app-ws` takes an optional auth guard, so
  an unauthenticated peer never gets a socket
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
- **Authentication** — `(igropyr auth)` is the format-neutral *auth role*.
  The `auth` middleware guards HTTP routes with a `Bearer` token (any
  verifier — `(jwt-verifier key)` today — 401 otherwise), `token-guard` /
  `session-guard` guard WebSocket upgrades before the handshake, and
  `app-rpc` takes a guard like the WebSocket one. **The shapes differ and
  none of them is interchangeable**: `auth` and `token-guard` take a
  *token verifier* `(lambda (token) …)`; `app-ws` and `app-rpc` take a
  *request guard* `(lambda (req) …)`; `app-use` and `admin-listen`'s
  `auth` option take *middleware* `(lambda (req res next))`, which is what
  `auth` returns. All are procedures, so the wrong one is installed
  without complaint and fails on the first request that reaches it. And
  these are separate doors: guarding one is not guarding another, nor does
  any of it reach an app you built yourself with a second `app-listen` /
  `admin-listen`, or a raw `http-listen`.
  `session-guard` takes an `origins` allow-list:
  the same-origin policy does not cover WebSockets and the browser attaches
  the session cookie whatever page opened the socket, so that list is what
  keeps a hostile page from holding an authenticated session. Browser
  origins fail closed until the application configures the list; clients
  without an Origin header remain supported
- **JWT** — `(igropyr jwt)` signs and verifies HS256 tokens (algorithm
  pinned, constant-time compare, strict base64url, fail-closed), the
  credential format plugged into `(igropyr auth)`
- **Password hashing** — `(igropyr kdf)` derives and verifies passwords
  over libcrypto (PBKDF2-HMAC-SHA256, scrypt, argon2id) with
  self-describing hashes, so an app can migrate algorithms on login;
  a verify-time cost ceiling keeps a crafted stored hash from stalling
  the single-threaded scheduler. `(igropyr crypto)` exposes the
  primitives underneath (SHA-1/256, HMAC, base64, hex)
- **Chunked transfer-encoding** — `Transfer-Encoding: chunked` request
  bodies are decoded transparently
- **Non-blocking Redis, MySQL and PostgreSQL clients** — pure Scheme,
  same event loop; callers park their green process while the OS thread
  keeps serving. MySQL and PostgreSQL share a self-healing connection
  pool; the PostgreSQL client authenticates with SCRAM-SHA-256, upgrades
  to optional TLS (`(igropyr tls)`, certificate verified, automatic
  channel binding via SCRAM-SHA-256-PLUS), and offers
  both the simple query protocol and the extended protocol with
  server-side parameter binding (`$1..$n`, injection impossible)
- **Non-blocking HTTP & WebSocket clients** — outbound `http-get` /
  `http-post` and `ws-connect`, both with async DNS (libuv thread pool)
  and the same park-the-caller model; `https://` / `wss://` via the
  optional `(igropyr tls)` library (OpenSSL as a byte codec, certificates
  verified — the core stays dependency-free)
- **Static file serving** — hot files come from an in-memory cache (a
  hashtable lookup: no disk read, no `stat` syscall; mtime re-checked at
  most once a second). A cache miss opens the file beneath its root with
  `openat`, one component at a time and never following a symlink, then
  reads it on libuv's thread pool; files over 1 MiB stream in bounded
  chunks with backpressure, never read whole
- **gzip compression** — responses negotiated via `Accept-Encoding`;
  static files cache their compressed form
- **S3 object storage & AWS service clients** — `(igropyr sigv4)` signs
  requests (AWS Signature V4, pinned by the AWS documented test vectors);
  `(igropyr s3)` speaks the S3 REST API over the HTTP client (put / get /
  head / server-side copy / delete / paginated list / restore — AWS S3,
  Cloudflare R2, MinIO); `(igropyr sts)` vends scoped temporary
  credentials (GetFederationToken), `(igropyr ses)` sends email
  (SES v2), `(igropyr sns)` fans a message out to a topic's
  subscribers (SNS Publish) and `(igropyr cloudwatch)` publishes a
  custom metric data point (CloudWatch PutMetricData), all over the
  same non-blocking signer
- **Vector scoring for embedding search** — `(igropyr blas)`: one call
  scores a query against a row-major float32 matrix at memory bandwidth
  (Accelerate / OpenBLAS via FFI), with a pure-Scheme fallback so it
  runs — slower but correct — on hosts with no BLAS at all
- **Embedded JavaScript** — `(igropyr quickjs)` runs a fixed JS bundle
  in-process via QuickJS (memory/stack/time capped, crash-only rebuild);
  user input is data, never code
- **Cached server-side rendering** — `(igropyr ssr)` runs a baked JS
  render bundle through QuickJS behind a key/TTL cache, so the blocking
  render fires once per (key, ttl) instead of once per request; memory
  or shared-Redis backend, with single-flight collapse of a cold-key
  herd to a single render
- **Ops-ready** — rate limiting, a global error handler, metrics as
  Prometheus / JSON / sexpr with app-defined business counters
  (`metrics-count!`), and a self-contained browser dashboard with a
  cluster view on a loopback-by-default admin port
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
  cluster)`, static, gossip, or Redis — gossip is decentralized
  membership over the node links themselves: configure a few seed
  addresses and every other member's address arrives inside the records)
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
guidelines, see [the manual](https://igropyr.dev/manual.html).

## Requirements

- Chez Scheme 9.5.8 or newer
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

### Portability

Chez Scheme is a requirement, not a preference: the actor runtime is
built directly on Chez compiler internals that have no counterpart in
Gambit, Loko, Guile or other Scheme implementations, so the lower
layers do not port.

- `#%$current-winders` — reads and swaps the `dynamic-wind` winder
  stack. Each green process carries its own winder chain, and "kill
  discards winders" is a semantic the whole library leans on:
  conversation's `on-killed`, connpool's broken check-in and durable's
  fd release are all built against it.
- `#%$current-stack-link` / `#%$null-continuation` — cut the stack
  chain when a new process starts.
- `current-exception-state` / `create-exception-state` — a per-process
  exception-state object, swapped on every context switch.
- `set-timer` and the timer-interrupt handler — Chez's engine ticks,
  the basis of preemptive scheduling.
- The FFI — `foreign-procedure`, `foreign-alloc`, `lock-object` — and
  helpers such as `procedure-arity-mask` are Chez's shapes throughout.

Porting to another implementation would mean rebuilding the scheduler
on that engine's own internals, not porting this one.

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
    (send-json! res (list (cons "received" (utf8->string (req-body req)))))))

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
;; immediately (the pump runs in its own process). Path components are
;; opened atomically beneath the root without following symlinks. The
;; cache is bounded to 4096 entries and 64 MiB, including cached gzip
;; representations, and is keyed by the name the OS resolves to -- so on
;; a case-insensitive filesystem the many spellings of one file share one
;; entry instead of letting a caller mint an entry per spelling. Both
;; ceilings are adjustable: (static-cache-limits! entries bytes), #f to
;; leave either.
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
| `(req-local req key)` | value stashed on this request by earlier middleware, or `#f` |
| `(req-set-local! req key val)` | stash a value for later middleware and the handler |

`req-local` is how middleware hands something to the handler — a session, an
authenticated user, a tenant. Use it rather than a `parameterize`d global:
parameters do **not** isolate concurrent requests here, for the reason in
[Dynamic state and `parameterize`](#dynamic-state-and-parameterize).

### Response helpers

Set status and extra headers first, then send exactly once:

```scheme
(set-status! res 201)               ; core primitive
(set-header! res "X-Request-Id" "abc")
(send-text! res "created")     ; text/plain        (express)
(send-html! res "<h1>hi</h1>") ; text/html         (express)
(send-json! res obj)           ; alist (string keys) -> object,
                               ; vector -> array              (express)
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

### Slow consumers

`res-write!` waits for each chunk to reach the peer, so a producer runs at
the client's pace rather than queueing chunks in memory. That wait is
bounded: a write whose bytes the peer never accepts gives up after
`write-timeout-ms` (default 30 s), closes the connection, and returns
`#f` — which is already the "stop the loop" answer every producer handles,
so no caller changes.

The bound matters most for exactly the shape recommended above. A stream
detached into its own process is **not** a pool worker, so the pool's
`stuck-ms` never applied to it; before this, one client that opened an SSE
stream and stopped reading held its writer process for the life of the
process, while whatever fed the stream kept sending into an unbounded
mailbox.

```scheme
(http-write-timeout! 30000)   ; process-global; 0 restores the unbounded wait
```

This is not a liveness timer for the stream. An SSE connection with nothing
to say is normal and costs no write; only a write whose bytes the kernel
will not take can expire — which means the peer's receive window has been
shut for the whole period. A live consumer drains a chunk in milliseconds,
and a bad mobile link in seconds.

The default matches `read-timeout-ms`, which bounds a peer that will not
*send*, and the pool's `stuck-ms`, so a detached stream is bounded exactly
like the pooled handler it was detached from. Whatever feeds the stream
keeps queueing for this long, so the value is also the ceiling on that
backlog.

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

**One spelling per shape.** An array is a vector and nothing else, and a
key or a string is a string and nothing else. A list where an array was
meant, and a symbol where a key or a string was meant, are refused rather
than converted — two Scheme values that reached the same document could
not both be read back, so the writer says so instead of choosing:

```scheme
(json->string '(1 2 3))     ; "a JSON array is a vector, not a list: use list->vector"
(json->string '((k . 1)))   ; "an object key must be a string, not k: an object member is ("k" . v), a nested array is #(#(...))"
```

Refusals name the offending value where it is small — a symbol, a key —
and otherwise name its KIND, never the value itself, since a value
reaching a refusal may be circular or enormous:

```scheme
(json->string #\a)          ; "not a JSON value: a character"
(json->string 1+2i)         ; "not a JSON value: a complex number"
(string->json 42)           ; "string->json takes a string, not a number"
```

Errors are `#(json-error message position)`. **The position says which
side raised**: reading errors carry an index into the input, writing
errors carry `#f`. `(string->json 42)` reports `0` — nothing was
consumed — rather than `#f`, so a handler can still dispatch on it.

### Reading and rewriting paths

Six verbs, each in two layers. The trailing `*` marks the **lower**
layer, not an enhanced one: a starred procedure takes one locator and can
be applied, while the macro takes a path written at the call site and
flattens it. A locator is a string, a symbol, or an exact non-negative
index; a symbol locator is spelled to a string for the lookup, so nothing
symbolic is ever stored.

| one locator, applicable | over a path |
| --- | --- |
| `(json-ref* x k [absent])` | `(json-ref x k ... [absent])` |
| `(json-set* x k v)` | `(json-set x k ... v)` |
| `(json-drop* x sel)` | `(json-drop x k ... sel)` |
| `(json-update* x sel p)` | `(json-update x k ... sel p)` |
| `(json-push* x member)` | `(json-push x k ... member)` |
| `(json-insert* x k member)` | `(json-insert x k ... loc member)` |

```scheme
(define doc (string->json "{\"a\":{\"b\":[10,20]}}"))
(json-ref doc "a" "b" 1)                      ; => 20
(json-ref doc "a" "z" (lambda () 'missing))   ; => missing
(json-set doc "a" "b" 0 99)                   ; => (("a" ("b" . #(99 20))))
(json-set doc "a" "z" 0 99)                   ; => #f
```

`sel` selects: a locator, a predicate on the key, `#t` for every member,
or `#f` for none. Selecting nothing is not failing — the container comes
back, having had zero members changed — while `#f` means the operation
did not complete. The macros read down and rebuild on the way out, so a
break anywhere answers `#f` for the whole expression and the original is
left alone; the container and every locator are evaluated exactly once.
Only `json-ref` takes a trailing thunk, because the other verbs end in a
value and a value may well be a procedure.

`json-object?`, `json-array?` and `json-null?` classify a value in this
representation. They are cheap and non-recursive, so they are not
writability checks: a value can satisfy `json-object?` and still be
refused by `json->string`, which validates all the way down.

In a handler, `req-json` parses the request body (returns `#f` on
invalid JSON) and `send-json!` serializes:

```scheme
(app-post app "/api"
  (lambda (req res)
    (let ((j (req-json req)))
      (send-json! res (list (cons "echo" (json-ref j "name")))))))
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

Beyond raw `spawn`/`send`/`receive`, OTP-style building blocks make
stateful services and fan-out easy: `(igropyr gen-server)` for stateful
services, `(igropyr otp)` for a supervised worker pool, `(igropyr pubsub)`
for fan-out, and `(igropyr dpool)` lifting the worker pool across a mesh.
The process registry is not a library of its own — it is `register` /
`unregister` / `whereis` in `(igropyr actor)` itself.

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
(import (igropyr http-client))

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
(import (igropyr http-client) (igropyr tls))
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

## Vector scoring

`(igropyr blas)` is the compute kernel for embedding search: one call
fills `scores[i] = row_i · query` over a flat row-major float32 matrix,
via `cblas_sgemv` when a native BLAS loads (Accelerate on macOS,
OpenBLAS on Linux/FreeBSD) and via a pure-Scheme loop otherwise —
`blas-available?` tells you which, correctness never depends on it.
Top-k, thresholds and storage stay yours; this is the scan, at memory
bandwidth.

```scheme
(import (igropyr blas))
(blas-scores! base n dim query scores)   ; base [n x dim] f32, scores [n] f32
```

One scheduling note: an FFI call cannot be preempted, so a full scan
stalls the calling scheduler for its duration (~0.2 ms at 5k×512 f32,
~5 ms at 100k). Spread those stalls — every process scanning its own
replica inline keeps the per-process stall duty cycle `q·s/N`
negligible; don't funnel searches into a few dedicated processes. If
that duty cycle ever grows, tile the scan and yield between tiles, or
shard the corpus and scatter-gather — spread out, never centralize.

## Embedded JavaScript

`(igropyr quickjs)` embeds a JavaScript engine (QuickJS) in-process for
running a **fixed** JS bundle baked at build time — a reference
implementation you must match byte-for-byte, a sandboxed expression
evaluator, a JS template. User input is the string **argument**, never
code:

```scheme
(import (igropyr quickjs))
(qjs-boot! "function slugify(s){ return s.toLowerCase().replace(/\\s+/g,'-') }")
(qjs-call! "slugify" "Hello World")   ; -> "hello-world"
```

It runs in **pure Scheme** over a stock shared **quickjs-ng** (`libqjs`),
bound directly through the FFI (no custom C): a memory cap, a stack cap, a wall-clock
interrupt deadline, and **crash-only rebuild** — a throwing or runaway call
discards the whole JS heap and reboots it from the bundle (`qjs-generation`
counts rebuilds), so one bad call can't poison the next. The engine is
serialized on the single OS thread and each call runs with interrupts
disabled, so a call blocks the scheduler for its duration (sub-millisecond
typically, `timeout-ms` worst case) — cap input size on latency-sensitive
paths. `qjs-boot!` reports if no library is found, and refuses to bind
unless `JS_FreeValue` resolves as a real function -- which bellard's
`libquickjs` does not export, so a process loading only that one will not
start. Point it at a
library with `IGROPYR_LIBQUICKJS_SO` or `(so-path . "...")`.

A **C-shim binding with identical exports** — self-contained, with QuickJS
statically linked and version-pinned — is a drop-in fallback at
[guenchi/igropyr-quickjs](https://github.com/guenchi/igropyr-quickjs),
for when a stock shared library is awkward to obtain (e.g. Homebrew ships only a
static archive).

## Cached SSR

`(igropyr ssr)` puts a key/TTL cache in front of QuickJS so server-side
rendering — good for SEO, but the pages that need it are public and
slow-changing — runs the *blocking* render once per (key, ttl) instead
of once per request. A hit is a lookup that never touches the engine; a
miss renders once and caches the HTML.

```scheme
(import (igropyr ssr))
;; at boot: ONE bundle per process (the engine is process-global)
(define r (make-ssr "
  function renderPost(j){ var p = JSON.parse(j);
    return '<article><h1>'+p.title+'</h1>'+p.body+'</article>'; }"))

;; in a handler: props (any Scheme value) is JSON-encoded and handed to
;; the JS function; the returned string is the HTML, cached under key
(send-html! res (ssr-render r "renderPost"
                  '(("title" . "Hi") ("body" . "<p>…</p>"))
                  '((key . "/blog/42"))))     ; explicit key = the URL

(ssr-invalidate! r "/blog/42")   ; drop one entry on a content change
(ssr-clear! r)                   ; drop all (e.g. after a deploy)
(ssr-stats r)                    ; ((hits . N) (misses . M) (renders . K) …)
```

The backend is `memory` by default — an in-process gen-server (TTL
ticker, size cap, exact stats) shared across the process's workers. Pass
`(cache . (redis <conn> "ssr:"))` and the HTML lives in Redis (`SET … PX`
for server-side TTL), so a render on one node is a hit on the others.
**Single-flight** is on by default: N concurrent misses on the same cold
key collapse to one render — the first claimant renders, the rest wait
for its result — so a thundering herd on a cold key renders once, not N
times (`(single-flight . #f)` disables it). Other options: `(ttl-ms . …)`,
`(max-entries . …)`, and `(quickjs . …)` passed through to the engine.
`ssr-render` re-raises a JS throw/timeout (let-it-crash, never cached);
`ssr-try-render` returns `(values ok? text)` instead for a non-raising
path.

## Object storage and AWS

`(igropyr sigv4)` signs requests with AWS Signature V4 (pinned to the AWS
documented test vectors); the service libraries build on it over the
non-blocking HTTP client, so they park the calling process like any other
request and work against AWS or any compatible endpoint.

```scheme
(import (igropyr s3))
(define bkt (make-s3 '((endpoint . "https://s3.us-east-1.amazonaws.com")
                       (bucket . "assets") (region . "us-east-1")
                       (access-key . "…") (secret . "…"))))   ; other endpoint = R2 / MinIO
(s3-put! bkt "k/logo.png" bytes "image/png")   ; -> etag
(s3-get bkt "k/logo.png")                       ; -> bytevector | #f on 404
(s3-copy! bkt "k/logo.png" "k/logo-bak.png")    ; server-side copy
(s3-delete! bkt "k/logo.png")                   ; idempotent
(s3-list bkt "k/")                              ; -> (key …), follows continuation tokens
```

`(igropyr sts)` vends **scoped, temporary** credentials for a client
(GetFederationToken with a caller-supplied session policy — e.g. narrow
S3 access), and `(igropyr ses)` sends one already-rendered email (SES v2
SendEmail; a non-ASCII From display name is RFC 2047 mime-word encoded so
clients show it, not just the address):

```scheme
(import (igropyr sts) (igropyr ses))
(define sts (make-sts '((region . "us-east-1") (access-key . "…") (secret . "…"))))
(sts-get-federation-token sts "u-abc" policy-json 3600)
;;   -> ((access-key-id . "…") (secret-access-key . "…")
;;       (session-token . "…") (expiration . "2026-…Z"))

(define ses (make-ses '((region . "eu-west-3") (access-key . "…") (secret . "…"))))
(ses-send-email ses "noreply@example.com" "Example" "u@x.com" subject html)  ; -> MessageId
```

`(igropyr sns)` fans one message out to a topic's subscribers (SNS
Publish — email / SMS / SQS / Lambda / HTTP; the topic and its
subscriptions are provisioned out of band), returning the MessageId. The
`subject` only reaches email delivery, so pass `#f` or `""` to omit it.
`(igropyr cloudwatch)` publishes one custom metric data point (CloudWatch
PutMetricData) — build it as a counter or gauge and alarm on it in
CloudWatch; the unit defaults to `"Count"` and `dims` is an alist of
`(name . value)`. PutMetricData answers a 2xx with an empty body, so it
returns `#t` rather than an id:

```scheme
(import (igropyr sns) (igropyr cloudwatch))
(define sns (make-sns '((region . "us-east-1") (access-key . "…") (secret . "…"))))
(sns-publish sns "arn:aws:sns:us-east-1:123:alerts" "subject" "body")  ; -> MessageId
(sns-publish sns "arn:aws:sns:us-east-1:123:alerts" #f "body")        ; no subject

(define cw (make-cloudwatch '((region . "us-east-1") (access-key . "…") (secret . "…"))))
(cloudwatch-put-metric cw "myapp" "requests" 1)                        ; -> #t, unit "Count"
(cloudwatch-put-metric cw "myapp" "latency_ms" 42 "Milliseconds"
                       '(("route" . "/checkout")))                     ; unit + a dimension
```

Each raises a structured `#(s3-error …)` / `#(sts-error …)` / `#(ses-error
…)` / `#(sns-error …)` / `#(cloudwatch-error …)` on a non-2xx response, so
a caller can catch and retry.

## Password hashing

`(igropyr kdf)` derives and verifies passwords over the already-loaded
libcrypto (the same OpenSSL `(igropyr tls)` uses), offered as
infrastructure so an app **chooses** its algorithm — and migrates between
them without a flag day. Self-describing hashes carry the algorithm and
cost params in the string, so one `password-verify` dispatches across all
three and a login can rehash to a stronger algorithm transparently.

```scheme
(import (igropyr kdf))
(password-hash "hunter2" 'scrypt   '())   ; -> "scrypt$32768$8$1$<salt>$<dk>"
(password-hash "hunter2" 'pbkdf2   '())   ; -> "pbkdf2-sha256$600000$<salt>$<dk>"
(password-hash "hunter2" 'argon2id '())   ; -> "argon2id$2$19456$1$<salt>$<dk>" (OWASP min)
(password-verify "hunter2" stored)        ; -> #t | #f, constant-time compare

;; raw derivations too, when you pick the cost params yourself:
(kdf-pbkdf2-sha256 pw salt iterations dk-len)
(kdf-scrypt        pw salt N r p dk-len)
(kdf-argon2id      pw salt t m p dk-len)

;; argon2id needs OpenSSL 3.2+; scrypt and pbkdf2 do not. There is no
;; default algorithm, so an older libcrypto costs you that one choice:
(kdf-argon2id-available?)                 ; -> #t | #f
```

A blocking KDF freezes the single-threaded scheduler for its duration, so
`password-verify` enforces a cost ceiling (~one 256 MiB fill, ~0.1–0.2 s)
before running: a **crafted** stored hash with an enormous cost is
rejected fast (`#f`) instead of turning a login into a multi-second
stall. Defaults track OWASP minimums; the parameters are validated
strictly (a non-string password or a malformed hash returns `#f`, never a
crash). `(igropyr crypto)` keeps a pure-Scheme PBKDF2 for hosts without
libcrypto.

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
      (send-json! res (list (cons "visits" n))))))

;; Rotate an established anonymous id when authentication/privilege changes.
;; Must happen BEFORE the response goes out -- the replacement arrives as a
;; Set-Cookie header, so afterwards it could not reach the client. Called
;; on an answered response it raises rather than dropping the live id.
(app-post app "/login"
  (lambda (req res)
    ;; ...verify the submitted credential first...
    (let ((s (req-session req)))
      (session-regenerate! s)                 ; prevents session fixation
      (session-set! s 'user "alice")
      (send-json! res '(("ok" . #t))))))
```

Middleware can also stash arbitrary values on the request for later
handlers with `req-set-local!` / `req-local` (this is how sessions ride
along). Writing your own is just `(lambda (req res next) ...)` — call
`(next)` to continue, or respond and return to short-circuit.

Metrics: a middleware records every request into one collector, which
`(igropyr metrics)` then renders three ways off the same numbers — the
signal is format-agnostic and does not care whether the reader is
Prometheus, a browser, or a Scheme program:

```scheme
(import (igropyr metrics))
(define m (make-metrics))                   ; at boot
(app-use app (metrics-middleware m))
;; after app-listen returns the server:
(app-get app "/metrics"     (metrics-endpoint m srv))  ; Prometheus text
(app-get app "/stats.json"  (metrics-json m srv))      ; JSON snapshot
(app-get app "/stats.sexpr" (metrics-sexpr m srv))     ; sexpr snapshot
;;   igropyr_requests_total{status="200"} 1234
;;   igropyr_request_duration_ms_sum 45210  ...  igropyr_pool_busy 3
```

`metrics-snapshot` returns that same datum as a Scheme value for
in-process callers. Business counters ride the collector too — register
nothing, just `(metrics-count! m "jobs_done_total" '() 5)`.

The presentation layer is a separate library, `(igropyr dashboard)`,
so the page never couples to the signal. It ships a self-contained
browser dashboard (inline CSS/JS, no external assets, works air-gapped:
requests/s and latency sparklines, connection/pool gauges, per-status
counts, every counter family, refreshed every 2 s) and — since the
monitoring surface exposes operational detail — a turnkey admin
listener that binds **loopback by default**:

```scheme
(import (igropyr dashboard))
;; mount onto an app you already have (guard it yourself):
(mount-dashboard! app m srv)                 ; GET /dash , /dash/data[.sexpr]
;; or a dedicated admin port, 127.0.0.1 by default, with a guard:
(admin-listen m srv `((port . 9090) (auth . ,(auth verify))))
;; NOT (token-guard verify): this slot is app-use middleware, and a
;; request guard installed here raises on the first admin request.
```

The front-end is swappable: pass `(html . <string|procedure>)` to serve
your own page — a file kept outside the web root via `send-file!`, or a
[Goeteia](https://github.com/guenchi/Goeteia) app reading the sexpr
endpoint — decoupled from the data routes, so its source can live
anywhere and render however you like.

On a node (after `node-start!`), announce the local summary once and
every peer that did the same appears in the snapshot's `cluster` member
(uptime, connections, requests, 5xx, pool) — gathered over the existing
node links by `rcall`, so no peer needs to expose HTTP:

```scheme
(metrics-announce! m srv)
```

The data routes expose operational detail. `admin-listen` defaults to
loopback for that reason; mounting onto a public app instead, guard the
routes like `/metrics` (an `(auth . …)`, a reverse proxy, or network
policy). Any listener's bind interface is now configurable —
`(app-listen app port '((host . "127.0.0.1")))` keeps it off-box.

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

## Design model

Four commitments shape the concurrency and distribution layers. They are
deliberate: a review comparing this library to Erlang/OTP or Swish will
find several OTP mechanisms missing, and each absence traces to one of
these.

1. **Crash-only, with the real supervisor outside the process.** Inside
   the process: let-it-crash workers, resource reclamation through owner
   monitors, task-level retry that knows its side effects. At the process
   level: die loudly and let the service manager (rc.d, `daemon -r`,
   systemd) restart the whole image. Recovery means rebuilding from
   durable state, not surgically restarting a subtree in place — so there
   is no in-process supervision tree, and its absence is a decision, not
   a gap.

2. **A single scheduler means an in-process supervision tree could not
   help with the hardest failures anyway.** A supervisor process shares
   the scheduler with everything it supervises: when the scheduler itself
   stalls — a foreign call that never returns — the tree stalls with it.
   The only supervisor that survives that failure class lives outside the
   process, and it is already there.

3. **The node mesh is a control plane: names, small messages,
   fail-closed, slow-is-dead.** Registered names cross the wire, pids do
   not. A protocol confusion closes the connection rather than guessing.
   A peer that cannot keep up is treated as dead — close and reconnect —
   never paused: pausing a control link delays heartbeats and monitor
   traffic, and turns one slow peer into cascading false failures. Bulk
   data never rides the control link; it gets its own connection.

4. **The mesh is small and fully trusted, and that is a feature.** A
   shared secret, a full mesh, and a modest node ceiling assume a cluster
   administered as one unit and upgraded in lockstep. Scaling is
   processes times machines under that assumption, not a thousand-node
   substrate.

### Lineage: ChezErlang

Igropyr's actor runtime descends from ChezErlang, a Swish fork, rewritten
from scratch after the fork collapsed under high-concurrency load. The
divergence from Swish's design is therefore half philosophy and half scar
tissue. Four pitfalls were diagnosed and verified on the fork before the
rewrite:

1. **`receive`'s `after` clause only took effect in first position** — placed
   after other clauses it silently became a pattern that never matches: a
   semantic trap with no signal at all.
2. **The listener was held only weakly** — an accept loop that did not keep it
   alive by hand was silently collected, and the server died faster the
   busier it got: the root cause of the high-concurrency collapse.
3. **A blocking TCP read stalled the calling process** — parsing had to live in
   a per-connection reader process, or one slow-dripping client wedged the
   whole server.
4. **An fd had to be closed exactly once** — including connections that reached
   EOF without ever carrying data — or fds leaked one-to-one with
   connections.

Each shaped a rule here, and the rules were checked against the code rather
than remembered:

1. `after` is **structural, not a pattern**. Its clause is recognised at
   expansion, and the clause that handles a plain pattern list carries a
   fender rejecting any list containing `after`. So `after` in a later
   position matches neither clause and is a compile error — *invalid
   syntax*, at expansion, not a pattern that quietly never fires.
2. Listener handles are kept in a strong table whose stated job includes
   rooting them for the collector. Nothing is required of the accept loop,
   and the only thing that removes a listener is stopping it on purpose.
3. Bytes arrive as messages to the connection's owner process, which parks
   in `receive` — so a read never blocks the caller, and the pitfall is
   gone. It does **not** follow that a slow peer costs nothing but its own
   process: delivery *can* be stopped, which closes the kernel's receive
   window and slows the sender, but stopping it is a call an owner has to
   make, and the node link does not make it. An owner that consumes more
   slowly than its peer sends accumulates an unbounded mailbox. The
   mechanism exists; it is not automatically in force.
4. Closing is idempotent by construction: the close guard tests the
   connection's own state and the handle's closing flag, so every path that
   can reach a close — EOF, error, owner death, explicit close — may call
   it without closing twice. That is **at most once**, which is the half
   the guard can prove. Not at least once: EOF and error only deliver a
   message, and an owner that ignores it leaves the connection open. The
   node link's own paths do close, so exactly-once holds there; it is not a
   property of the underlying layer.

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

## Dynamic state and `parameterize`

**`make-parameter` does not give you per-request state.** Reach for
`req-set-local!` / `req-local` instead, or pass the value as an argument.

Chez implements `parameterize` by swapping a *global* cell and registering a
winder to swap it back — printing one shows it plainly:

```
#[critical-winder #<procedure swap> #<procedure swap> ()]
``` The scheduler saves and restores each process's winder
list across a switch but never runs the hooks — correct for `dynamic-wind`,
whose after-thunk must not fire merely because a process yielded, and wrong for
`parameterize`, whose whole mechanism *is* that hook. Whoever wrote the cell
last owns it, for everyone.

Three processes, each either setting or reading one parameter across a yield:

| process | expected | actual |
|---|---|---|
| set `alice`, yield, read | `alice` | **`bob`** |
| set `bob`, yield, read | `bob` | **`nobody`** |
| never parameterized, read | `nobody` | **`bob`** |

Note the middle row: a process cannot even read back *its own* binding. And the
last: a process that never touched the parameter sees another's value. So the
failure is not only a leak between requests — it is that the binding means
nothing at all once anything yields, and every handler yields (any I/O does).

There is no clean fix available. Running the winders on every switch would
break `dynamic-wind`; saving and restoring the values instead would require
enumerating every live parameter, which Chez does not expose. So this is a
documented limitation rather than a bug to be filed.

Nothing warns you. A guard that reads the wrong identity usually *denies*, so
the visible symptom is an occasional unexplained `401` under concurrency —
which is a rough thing to chase, and the reason this section exists.

## Runtime introspection and graceful shutdown

`app-listen` / `http-listen` return the server. `http-stats` gives a live
snapshot; `http-shutdown!` stops accepting and drains in-flight requests
before returning (call it from a detached process, never from a pool
worker):

```scheme
(define srv (app-listen app 8080))
(app-get app "/stats" (lambda (req res) (send-json! res (http-stats-json srv))))
;;   => {"connections":12,"requests":34210,"uptime-ms":90000,
;;       "idle":5,"busy":3,"pending":0}
;; http-stats itself keys by symbol, for Scheme callers reading it with
;; assq; http-stats-json is the same snapshot with the keys spelled out,
;; because a JSON object key is a string.
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
(monitor-node/token 'b)                   ; -> #(node-up b token seq)
(monitor-remote 'b 'worker)               ; -> #(remote-down b worker reason)
```

`node-connect!` and `node-disconnect!` **return once the request is
accepted, not once it has taken effect.** Both hand the change to an
internal registrar whose mailbox orders such changes against each other,
and return immediately. The promise has always been "start dialling",
never "the link is up" — reconnection is a background loop. Wait for
`#(node-up peer)` from `monitor-node` if you need the link, rather than
for the call to return.

> **Upgrading:** this narrowed in the same release as wire version 4. A
> caller that dialled and then immediately inspected node state may now
> observe it a moment earlier than the connector exists; nothing that
> waited for `node-up` is affected.

**Topology notices are delivered at least once.** A single supervised
process delivers them, and an event leaves its queue only once it has
been handed to every subscriber — a delivery interrupted half way
through is started again rather than dropped. A subscriber can therefore
see the same notice twice.

`monitor-node/token` is the form that lets you tell. It returns a
subscription token, and its notices are `#(node-up peer token seq)`,
where `seq` rises across all notices: ignore anything whose token is not
the one you hold, then ignore a sequence number you have already passed.
`demonitor-node/token` cancels that subscription and nothing else.

The two-element form is unchanged and stays unchanged, which is the
point of it — but it carries neither a token nor a sequence number, so a
receiver using it cannot distinguish a repeat from a new event. If that
matters, use the token form; if it does not, nothing needs to change.

**Node names are wire syntax, not a local label.** A node name is
non-empty, at most 255 characters, and drawn from `[0-9a-z-]` — lowercase
letters, digits and the hyphen, which is legal in any position including
first and last. The rule is enforced at `node-start!` and `node-connect!`
as well as against the name a peer claims, so a name this node would
accept is always one it can also dial. Anything outside that set is
refused at startup with an `assertion-violation`, not later as a link
that mysteriously never comes up.

> **Upgrading from a wire version 3 node:** this narrowed in wire
> version 4. Names carrying uppercase, `_` or `.` used to start and now
> fail in `node-start!` immediately. A mesh must be upgraded as a
> whole in any case: a version 4 node refuses a version 3 one, saying why
> on the side that dialled it and closing without a word on the side that
> was dialled — a stranger reaching the listener is told nothing on
> purpose. Rename while planning that upgrade.

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
(cluster-start `((name . "myapp")                     ; no shared store at all
                 (discover . (gossip (advertise "10.0.0.1" 4100)
                                     (seeds (b "10.0.0.2" 4100))))))
(cluster-start `((name . "myapp") (discover . (redis ,conn "10.0.0.1" 4100))))
```

The **gossip** strategy is fully decentralized: each node keeps a
replicated member table and push-pulls it with a few random peers per
cycle, over the authenticated node links themselves. Member addresses
travel inside the records, so one configured seed contact is enough to
learn (and be learned by) everyone — a seed node runs with no seeds at
all. Records carry an incarnation (the owner's boot stamp; a restart
outranks the old life) and an owner-advanced heartbeat; a record that
stops advancing ages out on every node's own clock within `ttl-ms`
(~2× worst case), so stale echoes cannot resurrect a removed member.
There is no from-zero discovery anywhere: like every membership system,
the first contact — the seeds here, Redis's address below — is
configuration, not magic; gossip just shrinks it to a few peer addresses
and removes the external service.

The **redis** strategy is the same expiry semantics arbitrated by a
shared store instead of peer-to-peer: each node heartbeats into a
per-cluster sorted set scored by an expiry timestamp, and a crashed node
falls out on its own. Reach for it when you already run Redis.

`(max-members . N)` (default 256) caps the gossip view size and the
members dialed per redis cycle — also the anti-flood bound, so a flooded
discovery source can't make a node open an unbounded number of
connectors (`static` isn't capped; you list peers explicitly). The mesh
is **full** — every node links every other — so connections grow O(N²)
and each node holds ~N−1 links; the 256 default keeps that sane. Raise
it (`(cluster-start `((discover . (gossip ...)) (max-members . 512)))`)
if you genuinely need a few hundred nodes, but beyond that shard the
actor keyspace across several ≤256 clusters rather than growing one flat
mesh — `rcall` is direct with no multi-hop routing, so a single
fully-addressable mesh caps out at a few hundred nodes by nature.

> **Security:** the dist port is full control of the node — anyone on it
> can message any registered process, including supervisors. The
> handshake is a mutual HMAC-SHA256 challenge/response on the shared
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
(import (igropyr http-client) (igropyr tls))
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
auth.sc        auth role: auth middleware + token-guard / session-guard for ws
middleware.sc  cors / security-headers / logger / rate-limit / error-handler
metrics.sc     metrics signal: Prometheus / JSON / sexpr, cluster snapshot
dashboard.sc   metrics dashboard + turnkey admin listener (loopback default)
client.sc  non-blocking outbound HTTP client (async DNS)
sigv4.sc   AWS Signature V4 request signing (pure)
s3.sc      S3-compatible object storage (AWS S3 / R2 / MinIO)
blas.sc    vector scoring kernel: optional CBLAS sgemv, pure fallback
quickjs.sc embed a JS engine in-process (QuickJS, pure Scheme FFI)
tls.sc     optional outbound TLS (OpenSSL memory-BIO codec) for https/wss
redis.sc   non-blocking Redis client (RESP2), pipelined
mysql.sc   non-blocking MySQL client (caching_sha2_password) + pool
```

The actor scheduler (`register`/`whereis`/`monitor`/`demonitor`) and the
libuv-callback invariant that everything rests on are documented in
[the manual](https://igropyr.dev/manual.html).

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

Native libraries are `dlopen`ed at runtime, not folded into `app.so` —
compiling a library only compiles its Scheme. So if the app uses
`(igropyr quickjs)`, make a stock quickjs-ng (`libqjs`) resolvable (or
point `IGROPYR_LIBQUICKJS_SO` / `(so-path . "...")` at one; bellard's
`libquickjs` alone does not satisfy that check); likewise a native
BLAS for `(igropyr blas)`'s fast lane and OpenSSL for `(igropyr tls)`.
Each degrades without its library — blas to the pure loop, tls/quickjs
to a clear error — so this only bites the capability that needs it. When
a stock shared library is awkward to obtain, the self-contained C-shim
binding at [guenchi/igropyr-quickjs](https://github.com/guenchi/igropyr-quickjs)
is a drop-in replacement.

Profile-guided optimization (`build-profile.ss` to instrument,
`/admin/profdump` to collect after driving load, `build-pgo.ss` to
recompile with the profile) is available but **made no measurable
difference to keep-alive throughput on the machine quoted above**, which
is the only thing that was measured — for an I/O-bound server whose
per-request cost is syscalls,
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
