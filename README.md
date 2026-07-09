# Igropyr

A high-concurrency HTTP server for [Chez Scheme](https://cisco.github.io/ChezScheme/),
built directly on [libuv](https://libuv.org/) through Chez's FFI (no C shim),
with Erlang-style message-passing concurrency and Let-It-Crash fault tolerance.

- **Express-style API** — `create-app`, `app-get`, `app-listen`, `send-json!`, ...
- **Green processes** — thousands of lightweight processes scheduled over one
  OS thread; continuation-based context switching with preemption, so even a
  CPU-spinning handler cannot freeze the system
- **Pure message passing** — `spawn` / `send` / `receive` / `link` / `monitor`;
  no shared state between processes
- **Fault tolerant by default** — a fixed worker pool behind a supervisor:
  crashed workers are replaced and the task retried (at most 3 times, then
  the client gets a 500); workers stuck for more than 30 s are killed and
  replaced; a slow or half-sent request only ever blocks its own reader process
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

```scheme
(import (chezscheme)
        (igropyr actor)
        (igropyr http))

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
(set-status! res 201)
(set-header! res "X-Request-Id" "abc")
(send-text! res "created")     ; text/plain
(send-html! res "<h1>hi</h1>") ; text/html
(send-json! res obj)           ; alist -> object, list -> array
(send-file! res "path/to/f")   ; MIME type from extension
```

A second send on the same request is ignored, so a supervisor fallback can
never corrupt a response that already went out.

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
uv.sc     libuv FFI: event loop, TCP, write queue, GC-rooting registries
actor.sc  green processes: spawn/send/receive, link/monitor, preemptive
          scheduler (call/1cc + timer interrupt), run/sleep queues
otp.sc    supervisor + fixed worker pool + stuck-worker ticker
http.sc   incremental HTTP/1.1 parser, router, middleware, static files,
          Express-style API
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
