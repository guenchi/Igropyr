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
- **Chunked transfer-encoding** — `Transfer-Encoding: chunked` request
  bodies are decoded transparently
- **Fast** — ~35 k req/s at 500 concurrent connections on an Apple Silicon
  laptop (`ab -n 50000 -c 500`, zero failed requests)

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

## Fault tolerance semantics

These apply automatically; nothing to configure:

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
           middleware chain, static files, app-ws, JSON/text/html/file
           encoders
```

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

## Load testing

macOS defaults to 256 file descriptors per process; raise the limit in both
the server and the benchmark shell:

```sh
ulimit -n 10240
ab -n 50000 -c 500 http://127.0.0.1:8080/
```

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
