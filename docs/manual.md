# Igropyr Manual

This manual covers the architecture, design patterns, and implementation details of Igropyr for developers building on or contributing to the framework.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [The Actor Model](#the-actor-model)
3. [The Core Invariant](#the-core-invariant)
4. [Writing an HTTP Handler](#writing-an-http-handler)
5. [WebSocket](#websocket)
6. [Streaming and SSE](#streaming-and-sse)
7. [Hot Code Swapping and Graceful Shutdown](#hot-code-swapping-and-graceful-shutdown)
8. [Fault Tolerance](#fault-tolerance)
9. [OTP Patterns](#otp-patterns)
10. [Conversations](#conversations)
11. [Middleware Suite](#middleware-suite)
12. [Authentication](#authentication)
13. [Sessions](#sessions)
14. [JSON Web Tokens (JWT)](#json-web-tokens-jwt)
15. [Metrics](#metrics)
16. [Outbound HTTP Client](#outbound-http-client)
17. [Database Clients](#database-clients)
18. [Async File Reads](#async-file-reads)
19. [JSON and gzip](#json-and-gzip)
20. [S-Expression RPC](#s-expression-rpc)
21. [Distribution](#distribution)
    - [Node links, rsend / rcall, monitors](#distribution)
    - [Automatic discovery (static, Redis)](#automatic-discovery)
    - [Distributed task pool](#distributed-task-pool)
22. [Running and Building](#running-and-building)
23. [Testing](#testing)
24. [Development Contracts](#development-contracts)
25. [Code Style](#code-style)
26. [Common Pitfalls](#common-pitfalls)

---

## Architecture Overview

Igropyr is organized as a layered stack:

```
┌─────────────────────────────────────────┐
│        Express (Framework Layer)         │
│  create-app, app-get, send-json!, etc.  │
└─────────────────┬───────────────────────┘
┌─────────────────┴───────────────────────┐
│  HTTP Core + WebSocket + Supervision    │
│  http-listen, OTP worker pool           │
└─────────────────┬───────────────────────┘
┌─────────────────┴───────────────────────┐
│        Actor Scheduler                  │
│  spawn, send, receive, link, monitor    │
└─────────────────┬───────────────────────┘
┌─────────────────┴───────────────────────┐
│     libuv FFI Layer                     │
│  tcp-listen!, tcp-read-start!, etc.     │
└─────────────────────────────────────────┘

Independent libraries:
  • JSON parser/serializer
  • gen-server (OTP pattern)
  • pubsub (topic-based pub/sub)
  • Redis client
  • MySQL client
```

### Each Layer's Responsibility

- **libuv (libuv.sc)**: Direct FFI bindings to libuv. Manages TCP handles, read/write buffers, and event polling. Delivers data into the upper layers via callbacks.

- **Actor (actor.sc)**: Green process scheduler with continuation-based context switching. One OS thread, preemptive scheduling via timer interrupt, message-passing mailboxes, link/monitor for process relationships.

- **OTP (otp.sc)**: Worker pool with supervisor. Spawns N workers, distributes tasks, detects crashes and stuck workers (>30s), auto-retries failed tasks (≤3 times), kills stuck workers without retrying.

- **HTTP (http.sc)**: Protocol layer. Parses HTTP/1.1 requests (headers, body, chunked encoding), manages per-connection reader processes, invokes user handler in a pool worker, encodes responses, handles keep-alive and pipelining.

- **Express (express.sc)**: Framework layer. Router with path parameters (`:id`), middleware chain, convenience response encoders (`send-json!`, `send-file!`), cookie parsing, form parsing (urlencoded and multipart), static file serving.

- **WebSocket (websocket.sc)**: RFC 6455 codec, handshake, frame masking, fragmentation, ping/pong. Each socket is a green process that calls a user session handler.

- **JSON, gen-server, pubsub, Redis, MySQL**: Standalone libraries with no interdependencies (except JSON uses Scheme primitives, gen-server uses actor, pubsub uses gen-server+actor, redis/mysql use actor+uv).

### Data Flow: An HTTP Request

```
1. libuv calls on-connection callback (disabled interrupts)
   ↓
2. on-connection delivers 'accept message to event-loop process
   ↓
3. Event-loop spawns reader process for this connection
   ↓
4. Reader process calls tcp-read-start! (registers on-read callback)
   ↓
5. Client sends request; on-read callback (disabled interrupts)
   → receives bytes, parses request line/headers incrementally
   → when body complete: #(submit-task #(task ,id ,conn ,request))
   → sends to supervisor
   ↓
6. Supervisor enqueues task in pending queue
   ↓
7. Idle worker receives #(process-task ,task)
   → runs user handler (req res)
   → handler calls set-status!, set-header!, res-send!, etc.
   ↓
8. res-send! queues write via tcp-write!
   ↓
9. on-write callback (disabled interrupts)
   → signals completion to reader via #(write-done)
   ↓
10. Reader receives #(write-done)
    → if keep-alive: loop to step 4
    → else: close connection, yield
```

---

## The Actor Model

Igropyr's concurrency is Erlang-style message passing over green processes. No shared mutable state between processes; coordination happens entirely through messages.

### Core Concepts

**Green Process**: A lightweight thread scheduled by the Igropyr runtime over a single OS thread. Context switch via `call/1cc` (continuation capture). One process per accepted connection, one per worker, one per database session, etc.

**Process ID (pid)**: An opaque process record. Compare with `eq?` or use `process-alive?` to check status; use `process-id` only for the numeric debug id.

**Message**: A Scheme value (typically a vector or list) in the process's mailbox. Received by the `receive` macro.

**Mailbox**: An intrusive doubly-linked queue of messages. Received messages are consumed; messages wait until a matching pattern is found.

### API Reference

#### `(spawn thunk) → pid`

Spawn a new green process that calls `(thunk)` in its own context. The process runs until the thunk returns (normal exit) or raises an exception (crash).

```scheme
(define counter-pid
  (spawn (lambda ()
           (let loop ((n 0))
             (receive
               (`(inc) (loop (+ n 1)))
               (`(get-reply ,from) (send from n) (loop n)))))))
```

#### `(send pid message) → void`

Send a message to a process's mailbox. Non-blocking; the message is queued immediately and delivered when the receiver calls `receive`. Safe to call from any context.

```scheme
(send counter-pid '(inc))
(send counter-pid (vector 'get-reply self))
```

#### `(receive clause ...)`

Block until a message matches one of the patterns. Each clause is `(pattern body ...)`. The pattern can use quasiquote syntax with unquote (``) to extract fields.

**Critical rule**: If one clause has an `(after timeout-ms ...)` timeout, it **must be the first clause**.

```scheme
;; Without timeout:
(receive
  (`(ping ,from) (send from 'pong))
  (`(quit) (exit 0)))

;; With timeout (must be first):
(receive
  ((after 5000 (display "timeout\n")))
  (`(ping ,from) (send from 'pong))
  (`(quit) (exit 0)))
```

The timeout in milliseconds is measured from the moment `receive` is called. If no message matches and the timeout elapses, the timeout branch executes.

#### `self → pid`

Identifier syntax that expands to the current process's pid. Use `self` directly; it is not a procedure call.

```scheme
(send server (vector 'work-item self))
(receive
  (`(result ,v) v))
```

#### `(link pid) → void`

Link the current process to another. If the other process dies, this one receives an `#(EXIT ,pid ,reason)` message and, by default, dies too (unless `process-trap-exit` is set). Both processes are linked.

```scheme
(spawn (lambda ()
         (link other-pid)
         (receive
           (`#(EXIT ,p ,r) (display "linked process died\n")))))
```

#### `(monitor pid) → monitor-reference | #f`

Monitor another process. If it dies, this one receives an `#(DOWN ,pid ,reason)` message but is not linked (won't die automatically). Many processes can monitor one target. Returns a monitor reference for `demonitor`, or `#f` if the target is already dead (the `DOWN` message is delivered immediately in that case).

```scheme
(spawn (lambda ()
         (monitor database-pid)
         (receive
           (`#(DOWN ,p ,reason)
             (display "database crashed, reconnecting...\n")))))
```

#### `(demonitor monitor-reference) → void`

Cancel a previous `(monitor pid)` call using the monitor reference it returned.

#### `(process-trap-exit flag) → void`

Call with `#t` to convert `#(EXIT ...)` messages to normal messages (won't die). Call with `#f` to restore normal behavior.

```scheme
(spawn (lambda ()
         (process-trap-exit #t)
         (link other-pid)
         (receive
           (`#(EXIT ,p ,r) (display "other died but we keep going\n")))))
```

#### `(kill pid reason) → void`

Kill a process with a given reason (an arbitrary Scheme value). The process is removed from all queues and unregistered. Linked processes receive `#(EXIT ,pid ,reason)`.

```scheme
(kill worker-pid 'overloaded)
```

#### `(register name pid) → pid`

Register a process by a symbol name in the global registry. Returns `pid`.

```scheme
(register 'logger (spawn logger-thunk))
```

#### `(unregister name) → void`

Remove a process from the registry by name.

#### `(whereis name) → pid | #f`

Look up a process's pid by registered name. Returns `#f` if not registered.

```scheme
(define db (whereis 'database))
(when db (send db (vector 'query ...)))
```

#### `(process-alive? pid) → boolean`

Check whether a process is still running (not crashed or killed).

#### `(sleep-ms ms) → void`

Park the current process for at least `ms` milliseconds. The scheduler will resume it when the time elapses or sooner.

```scheme
(spawn (lambda ()
         (display "starting...\n")
         (sleep-ms 1000)
         (display "1 second later\n")))
```

#### `(process-id self) → integer`

Return the internal process id (an integer, distinct from the opaque `pid`). Useful for debugging; in HTTP handlers, included in error logs and example output.

```scheme
(define worker-id (process-id self))
(send log (vector 'msg (string-append "worker-" (number->string worker-id))))
```

#### `(start-scheduler thunk) → never`

Enter the main event loop. This spawns the event-loop process, starts the scheduler, and runs the thunk. Never returns; call this at the end of your initialization.

```scheme
(start-scheduler
  (lambda ()
    (app-listen app 8080)
    ;; or: (http-listen 8080 handler 8)
    ))
```

### Example: Simple Echo Server

```scheme
(start-scheduler
  (lambda ()
    ;; Spawn an echo service
    (register 'echo-service
      (spawn (lambda ()
               (let loop ()
                 (receive
                   (`(echo ,msg ,from)
                    (send from (list 'response msg))
                    (loop)))))))
    
    ;; Spawn a client
    (spawn (lambda ()
             (let ((echo (whereis 'echo-service)))
               (send echo (vector 'echo "hello" self))
               (receive
                 (`(response ,msg)
                  (display (string-append "got: " msg "\n")))))))
    
    ;; Keep the scheduler alive
    (sleep-ms 10000)))
```

---

## The Core Invariant

### Rule: Never Yield Inside a libuv Callback

The most critical invariant in Igropyr:

> **Code running inside a libuv callback (reached from `uv-poll!`) must never call `yield`, `receive`, or `raise`. Callbacks may only copy data, mutate registries, and send messages.**

**Why**: Yielding a continuation that crosses a C stack frame (libuv's call stack) would corrupt the C runtime. The continuation captures Chez Scheme's stack pointer and register state, but libuv's stack frame would remain active — resuming the continuation would skip the C frame's cleanup (unlocking mutexes, freeing temporaries, etc.), and the C frame would still be active when the next C function is entered.

### Where Callbacks Run

The libuv event loop is a tight C loop in `uv-poll!`, called from the event-loop process. Callbacks that run during `uv_run(UV-RUN-ONCE)` are:

- **on-connection**: Called when a listening socket accepts a client. Sets up a new TCP handle.
- **on-read**: Called when data arrives on a TCP socket or when the read would block.
- **on-write**: Called when a pending write completes.
- **on-close**: Called when `uv_close` has finished releasing the handle.
- **on-timer**: Called when a timer fires.

All of these run with interrupts disabled (Chez's timer interrupt is masked) so the scheduler state cannot be corrupted by preemption.

### Safe Callback Patterns

A callback can:

1. **Copy data** into buffers or local structures:
   ```scheme
   ;; In on-read callback:
   (let ((buf-copy (bytes->string (subbv buf 0 len))))
     ...)
   ```

2. **Mutate a process's private state** (if that state is not accessed from other processes):
   ```scheme
   ;; Private to the reader process's event:
   (let ((accumulated-bytes
          (bytevector-append accumulated-bytes buf)))
     ...)
   ```

3. **Send a message** to another process:
   ```scheme
   ;; In on-read callback, when a request is complete:
   (deliver-message supervisor (vector 'submit-task task))
   ```

   The `deliver-message` function is internal to (igropyr libuv). It's hooked by `uv-set-deliver!` and simply enqueues the message in the target process's mailbox without yielding.

4. **Read from the process registry** (read-only):
   ```scheme
   ;; Look up a registered process:
   (let ((logger (whereis 'logger)))
     (when logger (deliver-message logger msg)))
   ```

### Debugging Yield Violations

If you see an error like "Continuation escape from C code" or a segfault, a yield or receive has crossed a C frame. Check:

- Are you calling `receive` inside a handler passed to `tcp-read-start!` or `http-listen`?
- Are you calling a blocking operation (wait on a semaphore, sleep, etc.) inside a callback?
- Are you using a library that implicitly yields (e.g., a stream operation)?

Move the blocking logic into a separate spawned process and use message passing to signal completion.

---

## Writing an HTTP Handler

### Using the Express Layer

The Express layer provides a familiar web framework API. Most applications use Express; direct HTTP core use is rare.

#### Creating an App and Routes

```scheme
(import (chezscheme)
        (igropyr actor)
        (igropyr http)
        (igropyr express))

(define app (create-app))

;; GET /users/:id?verbose=1
(app-get app "/users/:id"
  (lambda (req res)
    (let ((id (req-param req "id"))
          (verbose? (assoc "verbose" (req-query req))))
      (if verbose?
          (send-json! res (list (cons 'user id)
                               (cons 'verbose #t)))
          (send-text! res id)))))

;; POST /api/data with JSON body
(app-post app "/api/data"
  (lambda (req res)
    (let ((body (req-json req)))
      (if body
          (send-json! res (list (cons 'echo body)))
          (begin (set-status! res 400)
                 (send-json! res (list (cons 'error "bad json"))))))))

;; PUT, DELETE likewise
(app-put app "/item/:id" (lambda (req res) ...))
(app-delete app "/item/:id" (lambda (req res) ...))
```

#### Path Parameters

The pattern `:name` in a route captures a path segment. Extract with `(req-param req "name")`.

```scheme
(app-get app "/blog/:year/:month/:slug"
  (lambda (req res)
    (let ((y (req-param req "year"))
          (m (req-param req "month"))
          (s (req-param req "slug")))
      (send-text! res (string-append y "/" m "/" s)))))
```

#### Query String

`(req-query req)` returns an alist of decoded query parameters.

```scheme
;; GET /search?q=hello&limit=10
(app-get app "/search"
  (lambda (req res)
    (let ((q (assoc "q" (req-query req)))
          (limit (assoc "limit" (req-query req))))
      ...)))
```

#### Request Accessors

- `(req-method req)` → symbol (GET, POST, etc.)
- `(req-path req)` → string ("/users/42")
- `(req-headers req)` → alist of (symbol . string) pairs (downcase keys)
- `(req-header req 'name)` → string or #f
- `(req-body req)` → bytevector (decoded, with chunked encoding decompressed)
- `(req-keep-alive? req)` → boolean (HTTP/1.1 default keep-alive)
- `(request? x)` → boolean — is `x` a request object? (exported by `(igropyr http)`; useful in your own contracts)

#### Request Body Parsing

- `(req-json req)` → parsed JSON object (alist/vector/etc.) or #f if invalid
- `(req-sexpr req)` → parsed s-expression datum or #f (see [S-Expression RPC](#s-expression-rpc))
- `(req-form req)` → alist from urlencoded or multipart bodies
  - Text fields: `(name . "value")`
  - Files: `(name . #(file "filename" "content-type" #bytes))`
- `(req-cookie req "name")` → string or #f

#### Response Helpers

- `(send-text! res text-string)` → sets Content-Type: text/plain; charset=utf-8
- `(send-html! res html-string)` → sets Content-Type: text/html; charset=utf-8
- `(send-json! res object)` → serializes and sets Content-Type: application/json
- `(send-sexpr! res datum)` → serializes and sets Content-Type: application/sexpr (see [S-Expression RPC](#s-expression-rpc))
- `(send-file! res path)` → sends a file to the client (streamed if large; see [Async File Reads](#async-file-reads))
- `(set-status! res code)` → set HTTP status (default 200)
- `(set-header! res "Name" "value")` → add/replace a response header
- `(set-cookie! res "name" "value" "Path=/" "HttpOnly")` → add Set-Cookie header
- `(res? x)` → boolean — is `x` a response object? (exported by `(igropyr http)`, alongside `request?`)

Every encoder also accepts a **bytevector**, taken as the already-encoded
body. When a response never changes, encode it **once at startup with
`define`** rather than re-encoding the same constant on every request —
the handler then just hands the framework a pointer, skipping the
`string->utf8` (or JSON/s-expr serialization) each time:

```scheme
(define home-page (string->utf8 "<h1>hi</h1>"))            ; encoded once
(define info-json (string->utf8 (json->string my-alist)))  ; serialized once

(app-get app "/"     (lambda (req res) (send-html! res home-page)))
(app-get app "/info" (lambda (req res) (send-json! res info-json)))
```

The same holds for anything derivable at startup (rendered templates,
lookup tables, composed strings): compute it in a top-level `define`, not
inside the handler. `send-text!`/`send-html!` take a string or bytevector;
`send-json!` takes a value to serialize or a bytevector of ready JSON;
`send-sexpr!` likewise.

#### Streaming Response

For large or long-running responses, use `res-begin!`, `res-write!`, `res-end!`:

```scheme
(app-get app "/stream"
  (lambda (req res)
    (set-status! res 200)
    (set-header! res "Content-Type" "text/plain")
    (res-begin! res)
    (res-write! res (string->utf8 "line 1\n"))
    (sleep-ms 100)
    (res-write! res (string->utf8 "line 2\n"))
    (res-end! res)))
```

#### Server-Sent Events (SSE)

Use `sse-start!` and `sse-send!` to push events to the client over a persistent connection:

```scheme
(app-get app "/sse"
  (lambda (req res)
    (sse-start! res)  ; sets headers and flushes
    ;; Now spawn a separate process to send events:
    (spawn (lambda ()
             (let loop ((i 1))
               (when (<= i 5)
                 ;; sse-send! returns #f if the connection is closed:
                 (when (sse-send! res (string-append "event: " (number->string i) "\n"))
                   (sleep-ms 1000)
                   (loop (+ i 1))))
             (res-end! res)))))
```

#### WebSocket

Use `app-ws` to handle WebSocket connections. The handler receives a `ws` object and the `req`. Call `ws-recv` to receive frames and `ws-send-text!`/`ws-send-binary!` to send.

```scheme
(app-ws app "/ws"
  (lambda (ws req)
    (ws-send-text! ws "welcome")
    (let loop ()
      (let ((frame (ws-recv ws)))
        (case (vector-ref frame 0)
          ((text) (ws-send-text! ws (string-append "echo: " (vector-ref frame 1)))
                  (loop))
          ((binary) (ws-send-binary! ws (vector-ref frame 1))
                    (loop))
          ((close) (ws-close! ws)))))))
```

#### Middleware

Middleware is a function `(lambda (req res next) ...)` that can inspect/modify the request, call `(next)` to pass to the next handler, or send a response and not call `(next)`.

```scheme
;; Logging middleware
(app-use app
  (lambda (req res next)
    (display (string-append (symbol->string (req-method req)) " " (req-path req) "\n"))
    (next)))

;; Authorization
(app-use app
  (lambda (req res next)
    (if (req-header req 'authorization)
        (next)
        (begin (set-status! res 403)
               (send-text! res "Forbidden")))))

;; CORS headers
(app-use app
  (lambda (req res next)
    (set-header! res "Access-Control-Allow-Origin" "*")
    (next)))
```

Middleware is invoked in the order added, before the matching route handler.

#### Static File Serving

```scheme
(app-static app "/assets" "./public")
;; GET /assets/style.css -> read ./public/style.css
```

Files up to 1 MiB are read once and cached in memory; the file's mtime
is re-checked at most once per second, so serving a hot asset is a
hashtable lookup — no disk read and no `stat` syscall. Responses carry a
weak ETag and `Cache-Control`, and a matching `If-None-Match` gets a 304.

Files over 1 MiB are never buffered whole. They stream as a fixed-length
response in 256 KiB chunks with backpressure — each chunk is read from
disk only after the previous one has drained to the client, so a
multi-gigabyte download to a slow peer costs one chunk of memory, and the
pool worker is released immediately (the pump runs in its own process).
Chunks go straight from libuv's read buffer to the socket without passing
through the Scheme heap, so a large download generates no GC traffic. For
a large file, a revalidation (`If-None-Match`) is answered from cached
metadata with no file operation at all.

#### Listening

```scheme
(start-scheduler
  (lambda ()
    (let ((srv (app-listen app 8080)))
      ;; Optionally, add routes after startup for hot reload:
      (app-get app "/version" (lambda (req res) (send-text! res "v2"))))))
```

Or with worker pool configuration:

```scheme
(app-listen app 8080 '((workers . 16)
                       (max-retries . 2)
                       (stuck-ms . 60000)
                       (check-ms . 10000)))
```

Configuration options:
- `workers`: Number of worker processes (default 8)
- `max-retries`: Maximum task retries on crash (default 3, so 4 executions total)
- `stuck-ms`: Time threshold to consider a worker stuck (default 30000 = 30s)
- `check-ms`: Ticker interval to check for stuck workers (default 5000 = 5s)

On startup, `app-listen` prints one line naming the contract level baked
into the build:

```
igropyr contracts: off
```

It reads `full` or `off` — the value of `(contract-level)` at compile
time (see [Development Contracts](#development-contracts)). Treat it as a
build canary: a production process should log `off`, and seeing `full`
there means a debug `.so` slipped into the deployment. If a mixed build
disagrees between libraries, this line reports only what the entry point
was compiled with.

### Using the HTTP Core Directly

For frameworks or applications that don't fit Express, use the HTTP core directly:

```scheme
(import (chezscheme)
        (igropyr actor)
        (igropyr http))

(start-scheduler
  (lambda ()
    (http-listen 8080
      (lambda (req res)
        (case (req-method req)
          ((GET)
           (set-status! res 200)
           (set-header! res "Content-Type" "text/plain")
           (res-send! res (string->utf8 "hello")))
          ((POST)
           (set-status! res 201)
           (set-header! res "Content-Type" "application/json")
           (res-send! res (string->utf8 "{\"ok\":true}")))
          (else
           (set-status! res 405)
           (res-send! res (string->utf8 "method not allowed")))))
      16)))  ; 16 workers
```

The handler receives `req` and `res` objects. Accessors and response functions are the same as Express.

---

## WebSocket

Igropyr implements the WebSocket protocol (RFC 6455) with two sides: server-side handlers and an outbound client.

### Server-Side WebSocket

A WebSocket route is registered with `app-ws` and runs in its own process per connection. The handler receives a `ws` session object and the upgrade request.

#### API

- `(app-ws app pattern (lambda (ws req) ...) [guard])` — register a WebSocket route with a session handler; the optional `guard` authenticates the upgrade (see below)
- `(ws-recv ws)` → `#(text ,string) | #(binary ,bytevector) | #(close)` — block until a complete message arrives (handles fragmentation, ping/pong, UTF-8 validation)
- `(ws-send-text! ws string)` → boolean — send a text message; #f if closed
- `(ws-send-binary! ws bytevector)` → boolean — send binary data
- `(ws-close! ws)` — idempotent close (sends close frame and closes the socket)

#### UTF-8 Validation and Frame Limits

Text messages are validated for strict UTF-8 (RFC 3629): overlong encodings, surrogates, and code points above U+10FFFF are rejected. Invalid UTF-8 triggers a 1007 (Invalid frame payload data) close.

Frame size is capped at 1 MiB (max-frame); reassembled messages are capped at 8 MiB (max-message). Violations trigger a 1009 (Message too big) close.

#### One Process Per Connection

Each WebSocket connection runs in its own spawned green process. When the handler calls `ws-recv`, it blocks in that process's message loop until a frame arrives from the network. Multiple concurrent WebSocket connections run in parallel processes on the single OS thread.

#### Example: Echo Server

```scheme
(app-ws app "/echo"
  (lambda (ws req)
    (ws-send-text! ws "welcome")
    (let loop ()
      (let ((msg (ws-recv ws)))
        (case (vector-ref msg 0)
          ((text)
           (ws-send-text! ws (string-append "echo: " (vector-ref msg 1)))
           (loop))
          ((binary)
           (ws-send-binary! ws (vector-ref msg 1))
           (loop))
          ((close) (ws-close! ws)))))))
```

#### Authenticating the Upgrade

The upgrade request never runs the middleware chain, so `app-ws` takes an optional 4th argument — a guard `(lambda (req) claims-or-#f)` from `(igropyr auth)`, run **before** the 101 handshake. Truthy claims proceed and are stashed on the request (`(req-claims req)` inside the session); `#f` refuses the upgrade with a plain **HTTP 401** and no socket. An unknown route is still a **404**.

```scheme
(app-ws app "/chat" chat-session (token-guard (jwt-verifier key)))
(app-ws app "/feed" feed-session (session-guard store))
```

See the [Authentication](#authentication) chapter for `token-guard` (Bearer header with a `?token=` query fallback for browsers) and `session-guard` (cookie session).

### WebSocket Client

Connect to a remote WebSocket server with the same session object. Outbound frames are masked per RFC 6455 (client role); the server-side role is automatic.

#### API

- `(ws-connect "ws://host:port/path" [extra-headers])` → ws session (blocks until handshake completes) or raises `#(ws-client-error ,message)`. The optional `extra-headers` is an alist of additional handshake headers — e.g. the credential for a guarded route:

  ```scheme
  (ws-connect url `(("Authorization" . ,(string-append "Bearer " tok))))
  ```
- `(ws-send-text! ws string)`, `(ws-send-binary! ws bv)`, `(ws-close! ws)` — same as server-side
- `(ws-recv ws)` — same as server-side

Note: `wss://` works once the optional `(igropyr tls)` library is enabled — `(import (igropyr tls))` then `(tls-enable!)` once at startup. See [Outbound TLS](#outbound-tls) under the HTTP client section. Without it, `wss://` is refused.

#### Example: Client

```scheme
(spawn (lambda ()
         (let ((ws (ws-connect "ws://127.0.0.1:8080/echo")))
           (ws-send-text! ws "hello")
           (let ((msg (ws-recv ws)))
             (display (vector-ref msg 1))
             (ws-close! ws)))))
```

---

## Streaming and SSE

HTTP handlers run in the worker pool and are expected to complete quickly. For long-running responses (file uploads, real-time updates), detach the response into its own process.

### Streaming Primitives

The low-level streaming API lets you write chunked responses (`Transfer-Encoding: chunked`, unknown length):

- `(res-begin! res)` — set response headers (Content-Type, etc.) and start streaming; must be called before any `res-write!`
- `(res-write! res bytevector)` — write a chunk to the TCP buffer (non-blocking; may queue internally)
- `(res-end! res)` — flush and close the response

```scheme
(app-get app "/download"
  (lambda (req res)
    (set-header! res "Content-Type" "application/octet-stream")
    (set-header! res "Content-Disposition" "attachment; filename=\"data.bin\"")
    (res-begin! res)
    (res-write! res (string->utf8 "part 1\n"))
    (sleep-ms 100)
    (res-write! res (string->utf8 "part 2\n"))
    (res-end! res)))
```

When the length is known up front (a file, a proxied download), the
**fixed-length** variant sends a real `Content-Length` and applies
backpressure — each write parks the producer until the chunk has drained
to the client, so the producer runs at exactly the client's pace with one
chunk in flight:

- `(res-begin-file! res length)` — send status + headers + `Content-Length`; call from the worker, then spawn a pump for the writes (a long download must not occupy a worker)
- `(res-write-file! res data)` → `'more | 'done | #f` — write one chunk (string or bytevector) and wait for it to drain; `#f` means the connection is gone
- `(res-abort-file! res)` — a fixed-length response that can't be finished has one correct exit: close the connection (the promised length can never be met)

This is what `app-static` and `send-file!` use internally to stream large
files; reach for it directly only when you are producing a
known-length body yourself.

### Server-Sent Events (SSE)

SSE is a persistent connection where the server pushes text events to the client over HTTP/1.1. Use `sse-start!` to begin, then spawn a separate process to push events.

#### API

- `(sse-start! res)` — set SSE headers (Content-Type: text/event-stream, no caching) and begin streaming
- `(sse-send! res "data\n")` → boolean or void — write an event line; returns #f if the client is gone, otherwise void

#### Example: Real-Time Updates

```scheme
(app-get app "/sse"
  (lambda (req res)
    (sse-start! res)
    ;; Detach the event producer into its own process so the handler returns quickly
    (spawn (lambda ()
             (let loop ((i 1))
               (when (<= i 10)
                 ;; sse-send! returns #f when the client closes the connection
                 (when (sse-send! res (string-append "event: count\ndata: "
                                                     (number->string i) "\n\n"))
                   (sleep-ms 1000)
                   (loop (+ i 1))))
               ;; Close the response when done (or when client closed)
               (res-end! res))))))
```

The spawned process runs independently: the handler returns, the worker is freed, and the event loop pumps the persistent connection to the client. If the client closes the browser tab or connection is lost, `sse-send!` detects it and returns `#f`, allowing the producer loop to exit cleanly.

---

## Hot Code Swapping and Graceful Shutdown

Igropyr supports replacing the request handler and individual routes without stopping the server or dropping in-flight requests.

### Hot Swapping the Handler

Use `http-swap!` to replace the entire handler:

```scheme
(let ((srv (app-listen app 8080)))
  (spawn (lambda ()
           (sleep-ms 60000)
           ;; After 1 minute, reload routes and swap handler
           (let ((new-app (load-routes!)))  ; your app-reloading code
             (http-swap! srv (app->handler new-app))))))
```

The server's in-flight requests finish normally. New requests use the new handler.

### Updating Individual Routes

Routes on an app object are live: re-registering a route (same method + pattern) replaces the old handler in-place.

```scheme
(define app (create-app))
(app-listen app 8080)

;; Initially:
(app-get app "/version" (lambda (req res) (send-text! res "v1")))

;; Later, hot-swap this one route:
(app-get app "/version" (lambda (req res) (send-text! res "v2")))
```

### Runtime Statistics

Use `http-stats` to inspect the pool and connection state:

```scheme
(let ((srv (app-listen app 8080)))
  (app-get app "/stats"
    (lambda (req res)
      (send-json! res (http-stats srv)))))
```

Returns:

```scheme
((idle . 5)          ; idle workers
 (busy . 2)          ; workers processing a task
 (pending . 1)       ; queued tasks waiting for a worker
 (total-requests . 12345)      ; cumulative requests served
 (active-connections . 23)     ; open TCP connections
 (uptime-ms . 3600000))        ; server uptime in milliseconds
```

### Graceful Shutdown

`http-shutdown!` stops accepting new connections and waits until all in-flight requests complete:

```scheme
(let ((srv (app-listen app 8080)))
  (spawn (lambda ()
           ;; Graceful shutdown after 5 minutes
           (sleep-ms (* 5 60 1000))
           (http-shutdown! srv)
           (exit 0))))
```

The server will:
1. Stop calling `tcp-listen!` to accept new connections.
2. Poll the pool state until all workers are idle and the queue is empty.
3. Return.

Your code can then clean up and exit.

---

## Fault Tolerance

Igropyr's fault tolerance is based on Erlang's "Let It Crash" principle: don't try to recover from all errors in the handler; instead, let workers crash and have a supervisor restart them.

### The Worker Pool

A fixed pool of `N` workers (default 8) executes tasks submitted by reader processes. The supervisor tracks:

- **Idle workers**: Waiting for a task
- **Busy workers**: Currently executing a task, with a start timestamp
- **Pending tasks**: Queued waiting for an idle worker
- **Task attempts**: For each task id, the number of times it has been retried

### Crash Recovery

1. A worker crashes (uncaught exception) while executing a task.
2. The supervisor detects this via a `#(DOWN ,worker-pid ,reason)` monitor message.
3. Supervisor increments the task's attempt count.
4. If attempt count ≤ max-retries (default 3, so up to 4 attempts total):
   - A replacement worker is spawned.
   - The task is re-queued at the front of the pending list (to give it priority).
5. If attempt count > max-retries:
   - The `fail-task` handler is called (writes HTTP 500 to the client).
   - The task is dropped.
6. A replacement worker is spawned to maintain pool size.

### Stuck Worker Detection

1. The supervisor runs a ticker process that sends `#(check-stuck-workers)` every `check-ms` (default 5s).
2. For each busy worker, the supervisor checks if `now-ms - start-time > stuck-ms` (default 30s).
3. If a worker is stuck:
   - It is killed with `(kill worker-pid 'stuck)`.
   - The task is **not** retried (to avoid re-hanging the pool).
   - The `fail-task` handler is called (HTTP 500).
   - A replacement worker is spawned.

This ensures that even a CPU-spinning handler cannot freeze the HTTP service. Other requests continue being served by healthy workers.

### Configuration

Pass configuration as an alist to `app-listen` or `http-listen`:

```scheme
(app-listen app 8080
  '((workers . 16)
    (max-retries . 2)
    (stuck-ms . 60000)
    (check-ms . 10000)))
```

Or as a worker-count shortcut when only the pool size changes:

```scheme
(http-listen 8080 handler 12)
;; Params: port handler workers
```

### The Failure Hook (remote retry ring)

By default a given-up task answers a plain `500` and closes the
connection. The `on-failure` pool option replaces that with your own
handler, run on a **fresh worker**, answering through the normal
response path — so **keep-alive is preserved** and the client can
resubmit on the same connection:

```scheme
(app-listen app 8080
  `((stuck-ms . 3000)          ; fail fast: kill stuck workers early
    (check-ms . 1000)
    (on-failure . ,(make-fault-handler))))   ; bundled template, or your own
```

The bundled template replies
`{"fault":"crash"|"stuck","attempts":n,"elapsed-ms":t,"retryable":true}`
with status 503 (`(make-fault-handler 500)` overrides the status). A
custom handler is `(lambda (req res info) ...)` with `info`:

| key | meaning |
|---|---|
| `kind` | `crash` (retries exhausted) or `stuck` (worker killed) |
| `reason` | the raise value / exit reason of the last execution |
| `id` | the task id, for log correlation |
| `attempts` | total executions of this request |
| `elapsed-ms` | duration of the last execution |

Semantics the client can rely on — the **kill happens first**, so when
the failure answer arrives there is **no in-flight execution left**:

| kind | server state | sensible client action |
|---|---|---|
| `crash` | handler body ran `attempts` times; each run's side effects may have landed | resubmit with changed parameters, or query state and compensate |
| `stuck` | worker killed mid-flight; side effects partially applied at an unknown point | resubmit carrying state, or roll back |

Every resubmission is a **new task**: fresh attempt budget, a full new
retry round (deliberate — a transient failure yesterday must not
poison today's request). With a short `stuck-ms` the client learns the
definite state in seconds instead of waiting out the old 30 s, and can
ring through several informed retries in the same wall-clock time.

Two fences keep the hook safe: it runs **once** (a raise inside it is
caught and falls back to the plain 500 — no retry loop), and if it
gets stuck it is reaped by the same ticker and also falls back. If a
partial (streaming) response already went out, the hook cannot run —
the connection just closes, as before.

Caveat: the `error-handler` middleware wraps handlers in a `guard`, so
crashes never reach the supervisor — retries and `on-failure` never
trigger behind it. Use `error-handler` for *expected* business errors,
the failure hook for Let-It-Crash faults; do not wrap crash-prone
handlers in a blanket guard.

### Monitoring the Pool

Use `(http-stats srv)` to get current pool state:

```scheme
(app-get app "/stats"
  (lambda (req res)
    (send-json! res (http-stats srv))))
```

Returns:

```scheme
((idle . 3)
 (busy . 2)
 (pending . 1)
 (total-requests . 5234)
 (active-connections . 12)
 (uptime-ms . 31234))
```

### Handling Errors in the Handler

Since handlers run in pool workers, an uncaught exception triggers the crash-recovery path. This is intentional:

```scheme
(app-get app "/crash-demo"
  (lambda (req res)
    ;; Any uncaught exception here crashes the worker and retries.
    (raise 'something-went-wrong)))

;; This is **not** an error condition; it's a normal use of fault tolerance.
;; The client receives a 500 after all retries are exhausted.
```

For known error cases, catch exceptions and respond appropriately:

```scheme
(app-get app "/divide/:a/:b"
  (lambda (req res)
    (let ((a (string->number (req-param req "a")))
          (b (string->number (req-param req "b"))))
      (guard (e ((and (number? e) (zero? e))
                 (set-status! res 400)
                 (send-json! res (list (cons 'error "division by zero")))))
        (if (zero? b) (raise 0) #f)
        (send-json! res (list (cons 'result (/ a b))))))))
```

---

## OTP Patterns

### gen-server: The Stateful Service Pattern

A `gen-server` is a process that manages state and handles two types of requests:

- **Call** (synchronous): The caller blocks waiting for a reply.
- **Cast** (asynchronous): The caller sends a message and doesn't wait.

The server's loop, request/reply matching, and timeout handling are implemented once in `gen-server-start`; you provide callbacks.

#### Defining a gen-server

```scheme
(import (chezscheme) (igropyr actor) (igropyr gen-server))

;; A simple counter service
(define counter-server
  (gen-server-start
    ;; init: () -> state
    (lambda () 0)
    
    ;; handle-call: (msg from state) -> (values reply new-state)
    (lambda (msg from state)
      (case msg
        ((inc) (let ((new (+ state 1))
                 (values new new)))
        ((get) (values state state))
        (else (values 'unknown state))))
    
    ;; handle-cast: (msg state) -> new-state
    (lambda (msg state)
      (case msg
        ((noop) state)
        ((reset) 0)
        (else state)))))
```

#### Calling a gen-server

```scheme
(gen-server-call counter-server 'inc)      ; blocks, returns 1
(gen-server-call counter-server 'get)      ; blocks, returns 2
(gen-server-cast counter-server 'reset)    ; returns immediately
(gen-server-call counter-server 'get)      ; blocks, returns 0
```

The default call timeout is 5 seconds. To customize:

```scheme
(gen-server-call counter-server 'get 10000)  ; 10-second timeout
```

If the server crashes, the caller immediately gets `#(gen-server-error server-died reason)` (because the caller monitors the server).

#### Registering a gen-server by Name

```scheme
(define logger
  (gen-server-start-named 'global-logger
    (lambda () (make-eq-hashtable))  ; state: hashtable of log lines
    
    (lambda (msg from state)
      (case (vector-ref msg 0)
        ((log)
         (let ((topic (vector-ref msg 1))
               (line (vector-ref msg 2)))
           (let ((logs (hashtable-ref state topic '())))
             (hashtable-set! state topic (cons line logs)))
           (values 'ok state)))
        (else (values 'bad-request state))))
    
    (lambda (msg state) state)))  ; no casts

;; Later, look it up by name:
(define log-server (whereis 'global-logger))
(gen-server-call log-server (vector 'log 'requests "GET / 200"))
```

#### The handle-info Callback

In addition to handle-call and handle-cast, you can provide a handle-info callback to process other messages (e.g., monitor DOWN messages):

```scheme
(gen-server-start
  (lambda () 0)
  (lambda (msg from state) (values 'ok state))  ; handle-call
  (lambda (msg state) state)                     ; handle-cast
  (lambda (msg state)                            ; handle-info (optional)
    (if (and (vector? msg) (eq? (vector-ref msg 0) 'DOWN))
        ;; A monitored process died; handle it
        (display "dependency died\n")
        state)))
```

### pubsub: Topic-Based Publish/Subscribe

The pubsub library provides a central registry of subscribers by topic. Publishers and subscribers are decoupled.

#### Starting pubsub

Call once at boot:

```scheme
(import (igropyr pubsub))

(start-scheduler
  (lambda ()
    (start-pubsub!)
    ...))
```

This spawns a gen-server named `'igropyr-pubsub` that you never interact with directly.

#### Subscribing to a Topic

```scheme
(spawn (lambda ()
         (subscribe 'room-1)
         (let loop ()
           (receive
             (`#(pub ,topic ,payload)
              (display (string-append "topic " (symbol->string topic) ": " payload "\n"))
              (loop))))))
```

The process receives `#(pub ,topic ,payload)` messages whenever someone publishes to that topic.

#### Publishing

```scheme
(publish 'room-1 "hello everyone")
```

All subscribers to `'room-1` receive `#(pub room-1 "hello everyone")`.

#### Unsubscribing

```scheme
(unsubscribe 'room-1)
```

Dead subscribers are unregistered automatically (the pubsub server monitors them), so if a WebSocket closes, its process dies and is cleaned up.

#### Example: Chat Room

```scheme
(app-ws app "/chat/:room"
  (lambda (ws req)
    (let ((room (string->symbol (req-param req "room"))))
      ;; Spawn a forwarder process to relay room messages to this WebSocket
      (let ((forwarder (spawn
                        (lambda ()
                          (subscribe room)
                          (let loop ()
                            (receive
                              (`#(pub ,t ,msg)
                               (ws-send-text! ws msg)
                               (loop))))))))
        ;; Main loop: receive WebSocket messages and publish them
        (let loop ()
          (let ((frame (ws-recv ws)))
            (if (eq? (vector-ref frame 0) 'text)
                (begin
                  (publish room (vector-ref frame 1))
                  (loop))
                ;; Close received
                (kill forwarder 'normal))))))))
```

### When to Use gen-server vs. Bare spawn

Use **gen-server** when:

- You need request/reply (synchronous communication).
- The process manages mutable state and must handle concurrent requests safely.
- You want automatic timeout and crash detection.

Use **bare spawn** when:

- The process is driven by external events (e.g., a WebSocket reader waiting for frames).
- There's no request/reply pattern (one-way messages).
- You want full control over the receive loop.

---

## Conversations

`(igropyr conversation)` runs a multi-request dialogue as **one green
process** — the actor-model formulation of "web programming with
continuations". The process's local bindings are the conversation
state, including live resources a session store cannot hold: an open
database transaction, a file handle, a reservation with a TTL. Control
flow is program text — "the user is at the confirm step" means the
process is parked *at that line*, and a step order the code cannot
express cannot happen.

```scheme
(app-post app "/transfer"
  (lambda (req res)
    (let-values (((id reply)
                  (conversation-start!
                    (lambda (req suspend!)
                      (let ((tx (begin-tx!)))          ; live, held across rounds
                        (guard (e (#t (rollback! tx) (raise e)))
                          (let ((req2 (suspend! confirm-page-data)))
                            (commit! tx)
                            done-data))))
                    req)))
      (send-json! res (cons (cons 'conv id) reply)))))

(app-post app "/transfer/:id"
  (lambda (req res)
    (let ((r (conversation-resume! (req-param req "id") req)))
      (if (conversation-gone? r)
          (begin (set-status! res 410)
                 (send-json! res '((fault . "gone") (rolled-back . #t))))
          (send-json! res r)))))
```

API: `(conversation-start! flow req [ttl-ms])` spawns the flow and
returns `(values id first-reply)`; inside the flow, `(suspend! reply)`
answers the current round and parks until the next
`(conversation-resume! id req)`, which returns the flow's next reply —
or `'gone`. The flow's return value is the final reply; the process
then exits. Default TTL 300 000 ms; expiry raises
`'conversation-expired` inside the flow so a `guard` can roll back.

The conversation never touches the connection: pool workers stay the
protocol adapters, parking until the flow replies, so the pool's
stuck-killer and failure hook keep protecting every round.

**The `gone` guarantee.** Death for any reason — crash, TTL, normal
completion — automatically unregisters the process, and every later
resume returns `'gone`. For a flow holding a database transaction,
dead process = dropped connection = the database itself rolled back:
`gone` *guarantees* nothing committed. Combined with the failure
hook's `crash`/`stuck` codes, a client always knows the definite
server state — the full remote transaction ring.

**Where to use it** — critical transactional flows: payments against
internal strong-transaction operations, booking (the seat hold is the
process's local state and `after` is its TTL), strictly ordered
protocol dialogues. **Where not to** — ordinary stateless requests
(they should stay zero-state with client-carried retries), and any
step that waits on *human* think time while holding row locks: hold
application-level reservations across human pauses, live transactions
only across machine-paced rounds.

---

## Middleware Suite

Igropyr includes a standard set of middleware for common concerns: CORS, security headers, logging, rate limiting, and error handling. Each middleware is a function `(lambda (req res next) ...)` that can inspect/modify the request, optionally call `(next)` to continue the chain, or respond directly.

### CORS

Handle Cross-Origin Resource Sharing with configurable options.

```scheme
(import (igropyr middleware))

;; Permissive (allow all origins):
(app-use app (cors))

;; Strict (specify origin, methods, etc.):
(app-use app (cors '((origin . "https://app.example.com")
                      (methods . "GET,POST,PUT")
                      (headers . "Content-Type,Authorization")
                      (credentials . #t)
                      (max-age . "86400"))))
```

The middleware sets `Access-Control-Allow-*` headers. If the request is an OPTIONS preflight, it answers with 204 No Content and does not call `(next)`.

### Security Headers

Add conservative security headers by default:

```scheme
(app-use app (security-headers))

;; Or customize:
(app-use app (security-headers '((frame-options . "SAMEORIGIN")
                                 (referrer-policy . "strict-origin-when-cross-origin")
                                 (hsts . #t)
                                 (content-security-policy . "default-src 'self'"))))
```

Sets `X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Referrer-Policy`, optionally `Strict-Transport-Security` and `Content-Security-Policy`.

### Logger

Log each request (method, path, status) after it completes:

```scheme
(app-use app (logger))

;; Or log to a file:
(let ((p (open-file-output-port "/var/log/app.log"
                                (file-options replace))))
  (app-use app (logger '((port . p)))))
```

Output format: `METHOD path -> status (Nms)`.

### Rate Limiter

Limit request rate by IP or custom key:

```scheme
(app-use app (rate-limit))

;; Or customize:
(app-use app (rate-limit '((max-requests . 100)
                            (window-ms . 60000)
                            (key-fn . (lambda (req)
                                        (req-header req 'x-forwarded-for))))))
```

The default allows 100 requests per 60 seconds per IP. When a client exceeds the limit, they receive HTTP 429 (Too Many Requests).

### Error Handler

Catch unhandled exceptions and respond with a nice error page:

```scheme
(app-use app (error-handler))

;; Or customize the response:
(app-use app (error-handler '((show-details . #f))))
```

When a handler raises an exception that the middleware chain doesn't catch, the error handler responds with HTTP 500 and a JSON error body. If `show-details` is true, includes the exception message (useful for development).

### Auth

Authentication lives in its own library, `(igropyr auth)`, because it spans both HTTP middleware and WebSocket upgrade guards — beyond this suite's request-decorator scope. See the [Authentication](#authentication) chapter.

### Request-Local Storage

Middleware can pass data to downstream handlers via `req-local` and `req-set-local!`:

```scheme
(app-use app
  (lambda (req res next)
    ;; Authentication middleware: set user on the request
    (let ((auth (req-header req 'authorization)))
      (if auth
          (let ((user (parse-auth-header auth)))
            (req-set-local! req 'user user)
            (next))
          (begin (set-status! res 401) (send-text! res "Unauthorized"))))))

;; Later, in a handler:
(app-get app "/me"
  (lambda (req res)
    (let ((user (req-local req 'user)))
      (if user
          (send-json! res (list (cons 'name (car user))))
          (begin (set-status! res 403)
                 (send-text! res "Forbidden"))))))
```

---

## Authentication

Authentication lives in its own library, `(igropyr auth)`. It is the *authentication role* layer — credential-format neutral — and it spans **both channels**: HTTP routes (via middleware) and WebSocket routes (via an upgrade guard checked before the handshake). Token *formats* live elsewhere; `(igropyr jwt)` is one such format today.

```scheme
(import (igropyr auth) (igropyr jwt))
```

All three channels — HTTP routes, WebSocket upgrades, and sexpr RPC
endpoints (`app-rpc`) — share the same request-guard protocol
`(lambda (req) claims-or-#f)`, so one guard works everywhere. Each leaves
verified claims on a request-local slot, read the same way:

- `(req-claims req)` → claims or `#f` — the claims left by `auth`, an `app-ws` guard, or an `app-rpc` guard.

### HTTP Middleware

`auth` guards HTTP routes. It takes any verifier `(lambda (token) claims-or-#f)` — a good token yields a claims value, a bad one yields `#f`. The middleware itself knows nothing about JWTs; the token format is the verifier's business. Today that verifier is `(jwt-verifier key)` from `(igropyr jwt)`; tomorrow it could be an s-expression token verifier plugged into the same `auth`.

```scheme
;; verify every request against a JWT key
(app-use app (auth (jwt-verifier key)))

;; pass verification options through the verifier; make auth optional
(app-use app (auth (jwt-verifier key '((leeway . 30)))
                   '((optional . #t))))
```

Claims land on a request-local slot; read them in a handler with `(req-claims req)`:

```scheme
(app-get app "/me"
  (lambda (req res)
    (let ((claims (req-claims req)))         ; guaranteed present here
      (send-json! res (list (cons 'sub (json-ref claims "sub")))))))
```

A missing or invalid token answers **401** with a `WWW-Authenticate: Bearer` header and a `{"error":"unauthorized"}` JSON body. Options:

- `(optional . #t)` — let a request **without** a token through (`req-claims` stays `#f`); a present-but-invalid token still answers 401.
- `(on-fail . (lambda (req res) ...))` — override the refusal. Handy for an s-expression RPC endpoint that would rather answer a sexpr body than JSON.

### WebSocket Upgrade Guards

A WebSocket upgrade request never runs the middleware chain — it is intercepted before the worker pool. So `app-ws` takes the guard **directly**, as an optional 4th argument:

```scheme
(app-ws app "/chat" chat-session (token-guard (jwt-verifier key)))
(app-ws app "/feed" feed-session (session-guard store))
```

A guard is `(lambda (req) claims-or-#f)`, run by the resolver **before** the 101 handshake:

- truthy claims → stashed on the request (read via `(req-claims req)` inside the session) and the upgrade proceeds;
- `#f` → the upgrade is refused with a plain **HTTP 401**, no handshake — an unauthenticated peer never gets a socket.

An unknown route is still a **404**; only a *matched* route with a refusing guard answers 401. `(igropyr auth)` exports two guards.

#### `(token-guard verify [options])`

Lifts a token verifier into a request guard. It reads `Authorization: Bearer` first, then falls back to a `?token=` query parameter — because the browser WebSocket API cannot set request headers.

```scheme
(app-ws app "/chat" chat-session (token-guard (jwt-verifier key)))

;; rename the query parameter, or disable the fallback entirely
(app-ws app "/chat" chat-session (token-guard verify '((query . "access_token"))))
(app-ws app "/chat" chat-session (token-guard verify '((query . #f))))
```

- `(query . "name")` — rename the fallback parameter (default `"token"`).
- `(query . #f)` — disable the query fallback for header-capable clients.

> **Caveat:** query-string tokens can end up in proxy and access logs. Prefer the `Authorization` header wherever the client can set one, and keep query-string tokens short-lived.

#### `(session-guard store [options])`

A request guard on the cookie session: the `sid` cookie must name a live session in the store, and that session's `data` alist becomes the claims.

```scheme
(app-ws app "/feed" feed-session (session-guard store))

;; match a session-middleware configured with a custom cookie name
(app-ws app "/feed" feed-session (session-guard store '((cookie . "session"))))
```

- `(cookie . "name")` — match a `session-middleware` using a custom cookie name (default `"sid"` on both sides).

The claims are a **read-only snapshot** taken at upgrade time. A long-lived WebSocket session does not see later mutations of that session (nor does it persist anything back).

### Authenticating an Outbound Client

For a guarded route, a non-browser client passes the credential as a handshake header via `ws-connect`'s optional extra-headers alist (see [WebSocket Client](#websocket)):

```scheme
(ws-connect url `(("Authorization" . ,(string-append "Bearer " tok))))
```

---

## Sessions

Igropyr provides cookie-based session storage with a TTL, automatic pruning, and CSPRNG-generated session IDs.

### Setup

At boot, create a session store and register the middleware:

```scheme
(import (igropyr session))

(define app (create-app))
(define store (make-session-store))  ; default: 30-min TTL
(app-use app (session-middleware store))
(app-listen app 8080)
```

### API

- `(make-session-store [ttl-ms])` → store — create a session store (default TTL 30 min = 1800000 ms)
- `(session-middleware store)` → middleware — register the session middleware
- `(req-session req)` → session object — get the current request's session (or create one)
- `(session-get session key)` → value or #f — read a key from the session
- `(session-set! session key value)` → void — write a key to the session
- `(session-clear! session)` → void — clear all data and send a Set-Cookie with empty value
- `(session-peek store sid)` → data alist or `#f` — read-only store lookup by sid: the `data` alist of a live session, or `#f`. Unlike `req-session`, it touches no request and persists nothing; it is the channel `(igropyr auth)`'s `session-guard` uses to authenticate a WebSocket upgrade, where the middleware never runs.

### Implementation Details

Sessions are stored in a gen-server (actor) with a string-keyed hashtable: `sid -> (data . expiry-timestamp)`. The middleware reads the session cookie (defaults to "sid"), loads the session onto the request, and after the handler runs, persists changes back to the store. If a new session was created, it sends a Set-Cookie header with a fresh sid (16 random bytes from `/dev/urandom`, hex-encoded).

A background process wakes every 1 minute and prunes expired sessions.

### Weak Consistency Note

If the same client makes two concurrent requests with the same session ID, both handlers see the session data as it was at the start of the request. Writes from one handler will be silently overwritten if the other handler's write completes later. For consistent updates, use a database transaction or a serialization lock (e.g., a gen-server).

### Example

```scheme
(app-post app "/login"
  (lambda (req res)
    (let ((username (assoc "username" (req-form req)))
          (password (assoc "password" (req-form req))))
      (if (and username password (valid-password? (cdr username) (cdr password)))
          (let ((s (req-session req)))
            (session-set! s 'user (cdr username))
            (send-json! res (list (cons 'ok #t))))
          (begin (set-status! res 401)
                 (send-json! res (list (cons 'error "bad credentials"))))))))

(app-get app "/profile"
  (lambda (req res)
    (let ((s (req-session req)))
      (let ((user (session-get s 'user)))
        (if user
            (send-json! res (list (cons 'user user)))
            (begin (set-status! res 403)
                   (send-text! res "Not logged in")))))))
```

---

## JSON Web Tokens (JWT)

`(igropyr jwt)` signs and verifies JSON Web Tokens using the HS256 JWS
compact serialization (`header.payload.signature`). It is a stateless
alternative to cookie sessions: the claims travel in the token, so no
server-side store is needed.

This library is the **credential format** layer only (the J is JSON). The
HTTP-side guard is the format-neutral `auth` middleware from
[`(igropyr middleware)`](#middleware-suite) — the *role* layer, which
protects s-expression RPC endpoints just as well as JSON ones.
`jwt-verifier` bridges the two: it packages a key (plus verification
options) into the `(lambda (token) claims-or-#f)` verifier that `auth`
expects.

A token is **external input**, so everything in this library is
always-on business code — none of it is gated on `IGROPYR_CONTRACTS`. The
contracts on the exported procedures only guard your own callers' argument
types.

### Security Decisions

These are deliberate and non-configurable:

- **The algorithm is pinned.** A token verifies as HS256 or not at all.
  The header's `alg` must literally be `"HS256"`; `"none"` and everything
  else is rejected, so algorithm-confusion downgrades are
  unrepresentable.
- **Signatures compare in constant time** (no early exit), so a
  byte-at-a-time timing oracle cannot forge one.
- **base64url decoding is strict** — any character outside the url
  alphabet rejects the token (fail closed, no silent skipping).
- **`exp`/`nbf` must be numbers when present**; a malformed time claim
  rejects the token rather than skipping the check.
- **Every verification failure returns the same `#f`** — no reason oracle
  for an attacker to probe.

### API

- `(jwt-sign claims key [options])` → token string. `claims` is an alist
  with symbol or string keys. `options` is an alist; `(expires-in . N)`
  stamps `iat = now` and `exp = now + N` seconds unless the caller already
  supplied them. All other registered claims are the caller's
  responsibility.
- `(jwt-verify token key [options])` → claims alist (with **string** keys)
  or `#f`. `options` may carry `(leeway . secs)`, `(iss . string)`, and
  `(aud . string)`. The `aud` claim matches a string or an array
  (list/vector) of strings.
- `(jwt-decode token)` → `(header . claims)` or `#f`. Parses **without
  verifying** — logging and debugging only, never authorization.
- `(jwt-verifier key [options])` → a `(lambda (token) claims-or-#f)`
  verifier for the `auth` middleware (see below). `options` are the same
  `leeway`/`iss`/`aud` alist that `jwt-verify` takes. A bad key type is
  rejected once, at boot, not per request.

The `key` is a string (taken as UTF-8) or a bytevector. Use **at least 32
random bytes**; the `/dev/urandom` pattern in `(igropyr session)`'s sid
generator is a good source. Because verified claims have string keys (the
`(igropyr json)` object convention), read them with `json-ref`, which also
accepts symbols.

### Signing and Verifying

```scheme
(import (igropyr jwt) (igropyr json))

;; 32 random bytes, e.g. read from /dev/urandom at boot; keep it secret
(define key
  (call-with-port (open-file-input-port "/dev/urandom")
    (lambda (p) (get-bytevector-n p 32))))

(define token
  (jwt-sign '(("sub" . "42") ("role" . "admin")) key
            '((expires-in . 3600))))       ; iat/exp stamped for one hour

(let ((claims (jwt-verify token key '((leeway . 30)
                                      (iss . "api.example.com")))))
  (if claims
      (json-ref claims "role")             ; -> "admin"
      'invalid))
```

### Guarding Routes

To protect routes with JWTs, hand a `jwt-verifier` to the `auth`
middleware from [`(igropyr auth)`](#authentication). `auth` reads the `Bearer`
token from the `Authorization` header, runs the verifier, and puts the
claims on a request-local slot for `req-claims`:

```scheme
(import (igropyr auth) (igropyr jwt))

(app-use app (auth (jwt-verifier key)))

(app-get app "/me"
  (lambda (req res)
    (let ((claims (req-claims req)))        ; guaranteed present here
      (send-json! res (list (cons 'sub (json-ref claims "sub")))))))
```

Verification options ride along inside the verifier; `auth`'s own options
(such as `(optional . #t)` and `(on-fail . proc)`) come after it:

```scheme
(app-use app (auth (jwt-verifier key '((leeway . 30)))
                   '((optional . #t))))
```

See the [Authentication](#authentication) chapter for the full refusal
behavior — and for guarding WebSocket upgrades with the same verifier via
`token-guard`. Because the verifier is just a procedure, the same route
guard works for any future token format — JWT is only today's credential.

### Not Implemented

RS256/ES256 (no RSA/EC in `(igropyr crypto)`), HS384/HS512 (no
SHA-384/512), JWE, and multi-signature JWS JSON serialization are out of
scope. Adding an algorithm means extending sign and verify in lockstep,
with the verifier staying pinned to an explicit list.

---

## Metrics

Collect and expose Prometheus-format metrics for request counts, latencies, and pool health.

### Setup

Create a metrics collector and register the middleware:

```scheme
(import (igropyr metrics))

(define app (create-app))
(define metrics (make-metrics))
(app-use app (metrics-middleware metrics))
(let ((srv (app-listen app 8080)))
  ;; Expose metrics on /metrics
  (app-get app "/metrics" (metrics-endpoint metrics srv)))
```

### API

- `(make-metrics)` → collector — create a metrics gen-server
- `(metrics-middleware collector)` → middleware — record each request's status and latency
- `(metrics-endpoint collector server)` → handler — HTTP handler that renders metrics in Prometheus text format

### Output Example

```
# HELP igropyr_requests_total HTTP requests by status
# TYPE igropyr_requests_total counter
igropyr_requests_total{status="200"} 1234
igropyr_requests_total{status="404"} 10
igropyr_requests_total{status="500"} 2
# HELP igropyr_request_duration_ms Request duration summary
# TYPE igropyr_request_duration_ms summary
igropyr_request_duration_ms_sum 45678
igropyr_request_duration_ms_count 1246
# TYPE igropyr_connections gauge
igropyr_connections 5
# TYPE igropyr_busy_workers gauge
igropyr_busy_workers 2
# TYPE igropyr_idle_workers gauge
igropyr_idle_workers 6
# TYPE igropyr_pending_tasks gauge
igropyr_pending_tasks 0
# TYPE igropyr_uptime_ms gauge
igropyr_uptime_ms 3600000
```

Scrape this endpoint every 10-15 seconds with Prometheus, Grafana, or similar.

---

## Outbound HTTP Client

Make outbound HTTP/1.1 requests from your handlers or background processes. The client runs in the caller's green process and parks until the response arrives, allowing other work to continue on the OS thread.

### API

- `(http-get url)` → response — fetch a URL (GET)
- `(http-post url body [options])` → response — POST a body (string or bytevector)
- `(http-request method url [options])` → response — generic request

Response accessors:
- `(response-status resp)` → integer (200, 404, etc.)
- `(response-headers resp)` → alist of (string . string) pairs
- `(response-header resp "Name")` → value or #f
- `(response-body resp)` → bytevector (decoded if chunked)

Options:
- `(body . ,bytevector)` or `(body . ,string)` — request body
- `(headers . ((("Header" . "value") ...)))` — custom headers
- `(timeout . ,ms)` — default 30000 ms

### Error Handling

Transport errors or timeouts raise `#(http-client-error ,message)`.

```scheme
(guard (e ((and (vector? e) (eq? (vector-ref e 0) 'http-client-error))
            (let ((msg (vector-ref e 1)))
              (display (string-append "HTTP error: " msg "\n")))))
  (http-get "http://example.com/"))
```

### Async DNS

The client performs DNS resolution asynchronously on libuv's thread pool, so the scheduler is never blocked by a slow DNS server.

### Example

```scheme
(app-get app "/proxy"
  (lambda (req res)
    (let* ((target (req-param req "url"))
           (resp (http-get target)))
      (if (= (response-status resp) 200)
          (begin
            (set-header! res "Content-Type" (response-header resp "Content-Type"))
            (res-send! res (response-body resp)))
          (begin
            (set-status! res (response-status resp))
            (send-text! res "upstream error"))))))
```

### Outbound TLS

`https://` (and `ws-client`'s `wss://`) work once you enable the optional `(igropyr tls)` library. Import it and call `(tls-enable!)` once at startup — before the first `https` request — and every `http-get` / `http-request` can reach TLS endpoints:

```scheme
(import (igropyr client) (igropyr tls))
(tls-enable!)                                 ; once, at startup

(let ((r (http-get "https://api.github.com/zen"
                   '((headers . (("User-Agent" . "igropyr")))))))
  (response-status r)                          ; -> 200
  (utf8->string (response-body r)))
```

**Why a separate optional library.** The core stays dependency-free: only `(igropyr tls)` touches OpenSSL, so a program that never imports it never loads it, and the build is unchanged whether or not OpenSSL is installed.

**How it works.** TLS runs as a pure byte codec in OpenSSL's memory-BIO mode: libuv keeps owning the socket, the event loop, and timeouts, while OpenSSL only transforms bytes. The handshake is driven by ordinary `receive` inside the request's own green process — no threads, no callbacks, no blocking of other processes. It is the same actor model as a plain request, with an encrypt/decrypt step spliced in.

**Certificate verification is on by default and non-negotiable:**

- `SSL_VERIFY_PEER` — the handshake fails on an unverifiable chain
- hostname (or IP-literal) matching against the certificate's SANs
- TLS 1.2 minimum
- system trust roots (override with the standard `SSL_CERT_FILE` / `SSL_CERT_DIR`)

A bad chain or a wrong hostname fails the request with `#(http-client-error "tls: …")` rather than silently connecting.

**Requirements.** OpenSSL 3 or 1.1 (or LibreSSL) present as a shared library, found via the usual platform paths (including Homebrew's `openssl@3`). This is a TLS *client* only; inbound HTTPS still belongs at a reverse proxy.

---

## Database Clients

### Redis

The Redis client is a single green process managing one TCP connection to a Redis server. Commands are pipelined over this connection, and replies are matched FIFO to requests.

#### Basic Usage

```scheme
(import (igropyr redis))

(define redis-server (redis-connect "127.0.0.1" 6379))

(redis redis-server "SET" "name" "alice")     ; -> "OK"
(redis redis-server "GET" "name")             ; -> "alice"
(redis redis-server "INCR" "counter")         ; -> 1 (integer)
(redis redis-server "GET" "missing")          ; -> #f (nil)
(redis redis-server "LRANGE" "list" 0 -1)    ; -> ("a" "b" "c") (array as list)

(redis-close! redis-server)
```

The `redis` function sends a command and parks the caller until the reply arrives. It accepts any number of arguments (all converted to strings and sent as RESP2 array elements).

**Return values**:

- Simple string: `"OK"`, `"PONG"`, etc. → string
- Bulk string: `"hello"` → string for valid UTF-8, bytevector for binary data
- Null: `nil` → `#f`
- Integer: `:42` → number
- Array: `[1,2,3]` → list (or vector, depending on context)
- Set: Same as array

**Errors**: Redis errors (`-ERR ...`) raise `#(redis-error ,message)` in the caller. If the connection drops, all waiting callers get the same error.

#### Pipelining

Multiple processes can call `redis` concurrently on the same connection; commands are queued and processed in order:

```scheme
;; Worker 1
(spawn (lambda ()
         (let loop ((i 0))
           (redis redis-server "SET" (string-append "k" (number->string i)) "v")
           (loop (+ i 1)))))

;; Worker 2
(spawn (lambda ()
         (let loop ((i 0))
           (redis redis-server "GET" (string-append "k" (number->string i)))
           (loop (+ i 1)))))
```

Both workers pipeline commands over the same connection. The OS thread never blocks; each worker parks in `receive` and is resumed when its reply arrives. This is the idiomatic way to use Redis in Igropyr.

#### Transactions

Redis transactions (`MULTI`, `EXEC`) work normally:

```scheme
(redis redis-server "MULTI")                    ; -> "OK"
(redis redis-server "SET" "x" "1")              ; -> "QUEUED"
(redis redis-server "SET" "y" "2")              ; -> "QUEUED"
(redis redis-server "EXEC")                     ; -> ("OK" "OK")
```

### MySQL

The MySQL client is likewise one green process per connection. Queries are synchronous (the caller parks until the reply).

#### Basic Usage

```scheme
(import (igropyr mysql))

(define db (mysql-connect "127.0.0.1" 3306 "user" "password" "mydb"))

(mysql-query db "SELECT id, name FROM users")
;; -> #(rows ("id" "name") (("1" "Alice") ("2" "Bob")))

(mysql-query db "INSERT INTO users (name) VALUES ('Eve')")
;; -> #(ok 2 3)    ; 2 affected rows, last insert id is 3

(mysql-query db "UPDATE users SET name = 'Bob2' WHERE id = 2")
;; -> #(ok 1 0)    ; 1 affected row, no insert id

(mysql-close! db)
```

Return values:

- **SELECT**: `#(rows ,column-names ,rows)` where `rows` is a list of lists.
- **INSERT/UPDATE/DELETE**: `#(ok ,affected ,last-insert-id)`.
- **Values**: Strings (MySQL text protocol). `NULL` → `#f`. Numeric strings are not converted.

**Errors**: Raise `#(mysql-error ,code ,message)` in the caller.

#### Authentication

MySQL 9 uses `caching_sha2_password` by default. Igropyr supports:

1. **Fast path**: SHA-256 scramble (default). Requires no server configuration.
2. **Full path**: Server's RSA public key encrypts the password (OAEP) over the plain connection. Used when the fast path fails.

For older servers, `mysql_native_password` is also supported via auth-switch.

The full path is refused by default on plaintext connections because a
MITM could substitute the server key. Pin the key, or explicitly opt in
only on TLS or a trusted network:

```scheme
(mysql-connect host port user password database
  '((server-public-key . "-----BEGIN PUBLIC KEY-----...")))
(mysql-connect host port user password database
  '((allow-insecure-auth . #t)))
```

**Security note**: Always use TLS for remote connections.

#### Connection Pool

For applications with many concurrent workers, instead of one connection, use `mysql-pool`:

```scheme
(define pool (mysql-pool 8 "127.0.0.1" 3306 "user" "password" "mydb"))
;; Creates a pool of 8 connections

;; Workers query the pool; an idle connection is allocated:
(mysql-query pool "SELECT * FROM users")

;; When done, the connection is returned to the pool.
;; Pool self-heals: if a connection dies, it's replaced on next use.
```

#### Example: Async Database Access in a Handler

```scheme
(app-get app "/users"
  (lambda (req res)
    (let ((rows (mysql-query db "SELECT id, name FROM users")))
      (if (eq? (vector-ref rows 0) 'rows)
          (send-json! res (map (lambda (row)
                                 (list (cons 'id (car row))
                                       (cons 'name (cadr row))))
                               (caddr rows)))
          (begin (set-status! res 500)
                 (send-json! res (list (cons 'error "database error"))))))))
```

From the HTTP perspective, the database query is non-blocking: the worker's process parks in `receive`, but the OS thread keeps serving other requests via other workers and connections.

---

## Async File Reads

Reading files is a blocking operation at the OS level. Igropyr provides `file-read-async!` to offload file I/O to libuv's thread pool, so the scheduler never blocks.

### API

Whole-file read (small files, buffered in one bytevector):

- `(file-read-async! path owner)` → void — start an async file read on the thread pool; the owner process receives `#(file-read ,bytevector)` on success or `#(file-error ,code)` on failure

Consumer-driven stream (large files, one chunk in flight):

- `(file-stream-open! path owner)` → stream — open a file as a chunk stream; the owner later receives `#(file-stream ,stream ,size)` (ready; `size` from `fstat`) or `#(file-error ,code)`
- `(file-stream-read! stream)` → void — pull the next chunk; the owner receives `#(file-chunk ,x)`, `#(file-eof)`, or `#(file-error ,code)`. Exactly one pull may be in flight, so a slow consumer holds one chunk of memory, not the file
- `(file-stream-raw! stream)` → void — deliver chunk *lengths* instead of bytevectors; the bytes stay in the stream's C buffer (`file-stream-chunk-ptr`) so a consumer that only forwards them never touches the Scheme heap
- `(file-stream-own! stream pid)` → void — hand delivery to another process (e.g. a pump spawned after opening)
- `(file-stream-close! stream)` → void — abort/release early (idempotent); a pull in flight is cleaned up when its callback returns

These are internal to `(igropyr libuv)` but used by the static file serving code in Express.

### Implementation

Behind the scenes, each read is an open → fstat → read → close chain, all on libuv's thread pool:
1. Open the file with `uv_fs_open`.
2. `uv_fs_fstat` for the size (and to reject non-regular files).
3. Read with `uv_fs_read` — the whole file (whole mode) or one bounded chunk per pull (stream mode).
4. Close with `uv_fs_close`.
5. Deliver the result to the owner process via a message.

All of this happens on a separate thread, so a large or slow read (network mount, spinning disk, etc.) never blocks the scheduler.

### Why Static Files Use It

The Express layer's `app-static` uses these primitives to serve static files without blocking:

```scheme
(app-static app "/assets" "./public")
```

When a request hits `/assets/style.css`, the handler:
1. Checks the static file cache (hashtable lookup, O(1)); within a 1-second window a hit needs no `stat` at all.
2. On a miss it opens the file as a stream, so the size is known from `fstat` before any bytes are read.
3. A file up to 1 MiB is pulled whole, cached, and served from memory. A larger file is streamed with backpressure from a detached pump process (raw chunks: libuv buffer → socket, no Scheme allocation), and only its metadata is cached — a later revalidation answers 304 with no file operation.
4. The pool worker parks in `receive` only for the small-file case; a large-file worker returns as soon as the response head is written.

During any wait the worker is not consuming CPU; other workers keep serving requests.

### Custom Async File Reads

If you need to read a file in a handler:

```scheme
(app-get app "/file/:name"
  (lambda (req res)
    (let ((name (req-param req "name")))
      (file-read-async! (string-append "./data/" name) self)
      (receive (after 30000 #f)
        (`#(file-read ,bv)
          (send-file! res (string-append "./data/" name)))
        (`#(file-error ,code)
          (set-status! res 500)
          (send-text! res "read error"))))))
```

---

## JSON and gzip

Igropyr includes a complete JSON parser/serializer and gzip compression support.

### JSON

The `(igropyr json)` library provides safe JSON parsing for untrusted input (HTTP request bodies).

#### Data Model

JSON is mapped to Scheme types:
- Object `{}` → alist with string keys: `(("a" . 1) ("b" . 2))`
- Array `[]` → vector: `#(1 2 3)`
- String → string
- Number → number
- `true`, `false` → `#t`, `#f`
- `null` → `'null`

#### API

- `(string->json s)` → parsed value; raises `#(json-error ,msg ,pos)` on bad input
- `(json->string x)` → JSON string (alists → objects, vectors → arrays, plain lists also become arrays)
- `(json-ref x key ...)` → value or #f; recursive descent by string/symbol key (objects) or integer index (arrays)

The parser is a recursive-descent, safe for untrusted input.

#### Example

```scheme
(let ((body (utf8->string (req-body req))))
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'json-error))
              (begin (set-status! res 400)
                     (send-json! res (list (cons 'error "malformed json"))))))
    (let ((data (string->json body)))
      ;; data is an alist
      (let ((name (assoc "name" data)))
        (if name
            (send-json! res (list (cons 'greeting (string-append "hi " (cdr name)))))
            (begin (set-status! res 400)
                   (send-json! res (list (cons 'error "missing name")))))))))
```

Path access via `json-ref`:

```scheme
(let ((data (string->json body)))
  (let ((first-name (json-ref data "person" "name" "first")))
    ;; if data is {"person":{"name":{"first":"alice",...},...},...}
    ;; then first-name is "alice"
    ))
```

### gzip Compression

The `(igropyr gzip)` library compresses bytevectors to gzip format (used by browsers). Compression is done via FFI to zlib.

#### API

- `(gzip-compress bv level)` → compressed bytevector or #f on failure (level 1..9; 6 is default)
- `(gzip-acceptable? accept-encoding-header)` → boolean; checks if client sent Accept-Encoding: gzip

The Express layer uses these automatically:
- Dynamic responses (JSON, HTML) are gzip-encoded if the client accepts it and the result is >1 KiB.
- Cached static files (up to 1 MiB) are stored uncompressed but gzip-encoded on-demand — and the compressed form is memoized — if the client accepts it. Large streamed files are sent as-is (never held in memory to compress).

You can also manually compress:

```scheme
(let ((gz (gzip-compress (string->utf8 "some large text") 6)))
  (if gz
      (begin
        (set-header! res "Content-Encoding" "gzip")
        (res-send! res gz))
      (res-send! res (string->utf8 "some large text"))))
```

---

## S-Expression RPC

When both ends of the wire speak Scheme, there is no codec to design:
`write` on one side, `read` on the other, and the data is already
structured. `(igropyr sexpr)` is the read side's discipline — a safe
parser for untrusted bodies — and the Express layer builds
request/reply, streaming, and REST-style resources on top. The browser
counterpart is [Goeteia](https://goeteia.dev)'s
`(web rpc)` / `(web ws)` / `(web sse)`, so a web app can be Scheme end
to end: exact integers and ratios cross the wire intact, and there is
no JSON in the middle.

### The (igropyr sexpr) Library

Safe s-expression parsing and serialization. Recursive-descent, **not**
the host reader — no `#`-syntax, no `eval`, depth-limited on parse and
on write, safe for untrusted HTTP bodies.

#### Wire Whitelist

- Lists (proper and dotted — so alists work)
- Symbols, strings
- Exact integers, exact ratios
- `#t` / `#f`, `()`

Anything else fails loudly, on parse and on write alike. A
numeric-shaped token must *be* a whitelisted number — `1.5` cannot slip
through as a symbol.

#### API

- `(string->sexpr s [depth])` → one datum; raises `#(sexpr-error ,msg ,pos)` on bad input (default depth limit 64)
- `(sexpr->string x)` → serialized string; raises on non-whitelist data (floats, vectors, procedures, cyclic lists)

#### Extended Wire Mode

`string->sexpr-extended` / `sexpr->string-extended` add three types,
used by the node-to-node links and by browser clients
([Goeteia](https://goeteia.dev), whose `(web sexpr)` is byte-for-byte
the same codec):

- vectors `#(...)` — no dotted tail, depth-limited like lists
- bytevectors `#vu8"<base64>"` — the raw bytes as base64, decoded in one
  pass (no O(n) intermediate list)
- flonums `#f8"<base64>"` — the 8 IEEE-754 bytes of the double,
  little-endian, base64: **bit-exact for every double, `inf` and `nan`
  included**. Nothing is ever printed as a decimal, so a peer whose
  floats print lossily (Goeteia) still round-trips every double
  perfectly (`-0.0` may read back as `0.0` on such a peer; numerically
  equal).

The strict mode is untouched — it stays the minimal HTTP-facing subset
and still rejects all three.

#### Interop Notes

Strings escape only `\"` and `\\` on the wire; a literal newline inside
a string is legal; `\n \t \r` are also accepted on read. These
conventions match Goeteia's reader/writer exactly, so the two
implementations round-trip byte for byte (verified both directions with
a shared fixture of bignums, ratios, escaped strings, and dotted pairs).

### Express Integration

`req-sexpr` / `send-sexpr!` mirror `req-json` / `send-json!`:

- `(req-sexpr req)` → parsed datum, or `#f` when the body is invalid or over 1 MiB
- `(send-sexpr! res x)` → serializes and sets `Content-Type: application/sexpr; charset=utf-8`

They aren't tied to any one endpoint — any route can serve
`application/sexpr`, exactly like JSON.

#### REST-Style Resources

```scheme
(define users '((1 . "ada") (2 . "alan")))

(app-get app "/users/:id"
  (lambda (req res)
    (let ((u (assv (string->number (req-param req "id")) users)))
      (if u
          (send-sexpr! res (list 'user (cons 'id (car u)) (cons 'name (cdr u))))
          (begin (set-status! res 404)
                 (send-sexpr! res '(error not-found)))))))
```

Browser side — Goeteia's `(web rpc)`:

```scheme
(let ((u (rpc-get "/users/42")))     ; direct style over JSPI
  u)                                  ; => (user (id . 42) (name . "ada"))
```

### app-rpc: Tagged Dispatch

For request/reply RPC, `app-rpc` turns one endpoint into a dispatcher.
Requests are `(tag arg ...)`; the tag selects a handler from an alist.
Handlers receive the argument list and return the reply datum. Unknown
tags and bad payloads answer `(error ...)` data — never a crash, never
an evaluation.

```scheme
(define users '((1 . "ada") (2 . "alan")))

(app-rpc app "/rpc"
  `((add      . ,(lambda (args) (apply + args)))
    (get-user . ,(lambda (args)
                   (let ((u (assv (car args) users)))
                     (if u
                         (list 'user (cons 'id (car u)) (cons 'name (cdr u)))
                         'not-found))))))
```

Every reply is wrapped: `(ok <result>)` on success;
`(error unknown-tag <tag>)`, `(error handler-failed)`, or
`(error bad-payload)` on failure.

Like `app-ws`, `app-rpc` takes an optional 4th argument — an auth guard
`(lambda (req) claims-or-#f)`, the same request-guard protocol, so
`(igropyr auth)`'s `token-guard` works here too. A refusal answers
**HTTP 401** with the sexpr datum `(error unauthorized)` — this is a
sexpr channel, so the refusal stays in the same `(error ...)` data
family as `(error bad-payload)`, never JSON. Truthy claims are stashed on
the request and read back with `(req-claims req)`.

A handler that can take **two** arguments is called with `(args req)`, so
it can read the claims for per-tag authorization; one-argument handlers
`(lambda (args) ...)` are unchanged.

```scheme
(app-rpc app "/rpc"
  `((whoami . ,(lambda (args req) (json-ref (req-claims req) "sub")))
    (add    . ,(lambda (args) (apply + args))))
  (token-guard (jwt-verifier key)))
```

Browser side — Goeteia's `(web rpc)`:

```scheme
(rpc "/rpc" '(add 1 2 1/2))          ; => (ok 7/2)   -- the ratio survives
(rpc "/rpc" '(get-user 1))           ; => (ok (user (id . 1) (name . "ada")))
```

That `1/2` is the whole point: it crosses the wire as an exact ratio and
comes back as one. No floating-point JSON approximation anywhere in the
path.

### Pushed Data: WebSocket and SSE

For datum streams, every message is one s-expression — the natural
framing for discrete events.

#### WebSocket

- `(ws-send-sexpr! ws x)` → serialize and send one datum
- `(ws-recv-sexpr ws)` → datum, or `'close` (connection over), or `#f` (a binary frame or an unparseable datum — the connection survives hostile input)

```scheme
(app-ws app "/chat/:room"
  (lambda (ws req)
    (let ((topic (string->symbol
                   (string-append "room-" (req-param req "room")))))
      ;; a forwarder relays room traffic back to this socket
      (spawn (lambda ()
               (subscribe topic)
               (let lp () (receive (`#(pub ,t ,m) (ws-send-sexpr! ws m) (lp))))))
      (let loop ()
        (let ((m (ws-recv-sexpr ws)))
          (cond
            ((eq? m 'close) 'done)
            ((and (pair? m) (eq? (car m) 'say))
             (publish topic (list 'msg (cadr m)))
             (loop))
            (else (ws-send-sexpr! ws '(error bad-message)) (loop))))))))
```

Browser side — Goeteia's `(web ws)`:

```scheme
(define w (ws-connect! "wss://host/chat/lobby"
            (lambda (datum) (render! datum))))   ; one datum per message
(ws-send! w '(say "hello everyone"))
```

#### SSE

- `(sse-send-sexpr! res x)` → frame one datum as an SSE event; a datum with embedded newlines splits into multiple `data:` lines, which `EventSource` rejoins losslessly on the client

```scheme
(app-get app "/progress"
  (lambda (req res)
    (sse-start! res)
    (let loop ((i 1))
      (when (<= i 100)
        (when (sse-send-sexpr! res (list 'progress (cons 'percent i)))
          (sleep-ms 100)
          (loop (+ i 1)))))))
```

Browser side — Goeteia's `(web sse)`:

```scheme
(sse-connect! "/progress"
  (lambda (datum)                      ; (progress (percent . 42))
    (update-bar! (cdr (assq 'percent (cdr datum))))))
```

### Why This Matters

A JSON API forces an impedance mismatch: Scheme data is serialized down
to JSON's smaller type system (no exact rationals, no symbols, objects
keyed only by strings), parsed back into whatever the other language
models JSON as, and every field access is stringly-typed. When both ends
are Scheme, none of that happens — the value you `write` is the value
the peer `read`s, structure and exactness preserved. `(igropyr sexpr)`
adds exactly one thing to that picture: the safety a network boundary
demands — a whitelist, a depth limit, no evaluation — so untrusted bytes
can never become code.

---

## Distribution

`(igropyr node)` connects igropyr instances — other cores on the same
machine via loopback, or other machines over the network — into a mesh
where a process on one node can message a **registered name** on
another. The semantics deliberately mirror Erlang distribution:

```scheme
(import (chezscheme) (igropyr http) (igropyr node))

;; node "a" (listens for peers; 127.0.0.1 unless a host is given)
(start-scheduler
  (lambda ()
    (node-start! 'a "shared-secret" 4100)
    (register 'metrics self)
    (let loop ()
      (receive (`#(report ,from ,data) (record! from data) (loop))))))

;; node "b" (dials a; reconnects automatically whenever the link drops)
(start-scheduler
  (lambda ()
    (node-start! 'b "shared-secret")
    (node-connect! 'a "10.0.0.1" 4100)
    (monitor-node 'a)                 ; -> #(node-up a) / #(node-down a)
    (rsend 'a 'metrics (vector 'report 'b stats))))
```

### API

- `(node-start! name secret [port [host]])` — set this node's identity and shared secret; with a port, also accept peers (bound to 127.0.0.1 unless a host is given)
- `(node-connect! peer host port)` — dial a peer and keep dialing whenever the link is down
- `(node-disconnect! peer)` — stop dialing and drop the live link
- `(rsend node reg-name msg)` → `#t`/`#f` — send `msg` to the process registered as `reg-name` on `node`; `#t` means handed to a live link (delivery still unconfirmed), `#f` means no link. The own node name is a plain local send.
- `(rcall node reg-name msg [timeout])` → reply — synchronous call to the **gen-server** registered as `reg-name` on `node`; blocks the caller (default 5s). Raises `#(rcall-error ,reason ,target)` on no link, timeout, or a remote failure (no such server, it died, a non-serializable reply). The own node name is a plain local `gen-server-call`.
- `(monitor-node name)` / `(demonitor-node name)` — receive `#(node-up ,name)` and `#(node-down ,name)`
- `(monitor-remote node name)` → ref / `(demonitor-remote ref)` — watch the process registered as `name` on `node`; the watcher receives one `#(remote-down ,node ,name ,reason)` where `reason` is the target's exit reason, `noproc` (name not registered when the watch is established), or `noconnection` (the link dropped first — across a broken link the target being alive or dead is indistinguishable, as in Erlang). This is the **process-level** counterpart to `monitor-node`.
- `(node-peers)` — connected peer names; `(node-self)` — own name

`(igropyr pubsub)` is **cluster-aware** once nodes are linked: a
`publish` is delivered to local subscribers and forwarded one hop to
every directly-connected peer, whose pubsub server delivers to its own
subscribers. This assumes a fully-connected mesh (as Erlang does): one
hop reaches everyone, and a forwarded message is never re-forwarded, so
there are no loops or duplicates — the chat-room example works across
nodes with no code change. With no node started, `publish` is exactly
the single-node version.

### Semantics

- Addressing is by **registered name**, never by raw pid — names survive
  restarts, pids don't.
- `rsend` is fire-and-forget. Between one pair of nodes messages arrive
  in send order (one TCP connection per pair); on a dead link they are
  silently dropped — use `monitor-node` and application-level replies.
  `rcall` is the synchronous counterpart, for when you need the answer.
- Payloads cross in the **extended sexpr wire mode**: vectors,
  bytevectors and finite flonums arrive bit-intact, exact
  integers/ratios stay exact. Anything outside the whitelist (closures,
  records, pids, conns) raises at the sender — loudly, at `rsend` time.
- Both sides dialing at once resolves deterministically: the connection
  dialed by the smaller node name survives on both ends.
- `monitor-remote` watches a remote *process* by registered name (the
  process-level companion to `monitor-node`). There is deliberately no
  cross-node **link**: a link is a bidirectional cascading kill, which
  would need remote termination and mis-fires on a partition (a dropped
  link looks like a peer death and would wrongly kill healthy
  processes). One-way observation via monitor covers the need.

### Security

The handshake is a mutual HMAC-SHA1 challenge/response on the shared
secret: the secret never crosses the wire and a recorded proof cannot
be replayed. But the dist port is **full control of the node** — anyone
on it can message any registered process, including supervisors. It
binds 127.0.0.1 by default, and there is no TLS: across machines, keep
it on a private network (WireGuard, VPC). Never expose it publicly.

### What this is for

One igropyr process is one scheduler on one core. `SO_REUSEPORT` (or an
upstream load balancer) already scales stateless HTTP across cores and
machines — but each process is an island: its PubSub topics, registry
and gen-servers are invisible to the others. Node links are the bridge:
same-machine processes mesh over loopback, machines mesh over the
network, and stateful coordination (chat fan-out, singleton services,
work spraying with failover) becomes ordinary message passing again.

### Automatic Discovery

`node-connect!` is manual: to form a mesh, every node dials every other,
knowing each peer's name, host and port — O(N) config that has to change
whenever the membership does. `(igropyr cluster)` adds the thin layer
above it. A background process asks a **discovery strategy** for the
member list each cycle and dials any peer it isn't linked to yet;
`node-connect!`'s own reconnect and `monitor-node`'s up/down do the rest.

```scheme
(node-start! 'a secret 4100 "0.0.0.0")

;; a fixed list (self is skipped)
(cluster-start `((discover . (static (b "10.0.0.2" 4100)
                                     (c "10.0.0.3" 4100)))))

;; via Redis: no central bookkeeping, membership is self-maintaining
(cluster-start `((name . "myapp")
                 (discover . (redis ,conn "10.0.0.1" 4100))))  ; advertise self

;; or any thunk returning ((name host port) ...)
(cluster-start `((discover . ,(lambda () (my-lookup)))))
```

The **static** strategy is a fixed list. The **redis** strategy heartbeats
each node's own `(name host port)` into a per-cluster sorted set scored by
an expiry timestamp, prunes entries whose time has passed, and reads the
live set — a crashed node falls out after `ttl-ms` on its own, with one
key and no `SCAN`. A discovery failure (Redis down, a DNS blip) skips the
round and keeps the links already up, so it never tears the mesh down.

Options: `(name . "default")` namespaces the Redis key; `(interval-ms .
5000)` the discovery period; `(ttl-ms . 15000)` how long a Redis
registration lives without a heartbeat (keep it a few intervals).
`(cluster-stop handle)` stops discovering; existing links stay up.

For a singleton or leader across the cluster, this is still the wrong
layer — see the note under the task pool below.

### Distributed Task Pool

`(igropyr dpool)` spreads tasks across member nodes and runs them
concurrently — the local worker pool's Let-It-Crash story lifted from
process level to node level. A coordinator round-robins tasks to live
members and, driven by `monitor-node`, handles a node death at once.

```scheme
;; on every member node (b, c, ...): a worker under a shared name
(node-start! 'b secret 4100)
(dpool-worker-start 'render (lambda (job) (resize job)))

;; on the submitting node:
(node-start! 'a secret)
(node-connect! 'b "10.0.0.2" 4100)   ; (and the other members)
(define pool (dpool-start '(b c) 'render))
(define t (dpool-submit pool (vector 'resize "x.png" 800)))
(dpool-await pool t)                  ; -> the handler's return value
```

**Failure semantics are chosen per pool and overridable per task** —
only the caller knows whether a task may safely run twice:

- **`at-least-once`** (default) — if the node running a task dies before
  its result returns, the task is re-dispatched to another live node. It
  *will* complete (while any node lives) but *may* run twice (the node
  might have finished and died with the reply in flight). Use for
  **idempotent** tasks. It's the default because a silently dropped task
  is harder to notice than a duplicated one.
- **`at-most-once`** — a node death fails the task; `dpool-await` raises
  `#(dpool-error node-down ,id)` and it is never re-run. For side effects
  that can't be made idempotent ("charge once").

```scheme
(dpool-start '(b c) 'render '((mode . at-most-once)))     ; pool default
(dpool-submit pool payload '((mode . at-most-once)))       ; per task
```

Exactly-once is not on offer: no message-passing system gives both
"never dropped" and "never duplicated" across a crash — that needs
downstream cooperation (idempotency keys, a transactional inbox). A task
whose **handler crashes on a live node** is different from a node death:
the node replies with the error, `dpool-await` raises
`#(dpool-error task-error ,id)`, and the task is not retried — a
deterministic crash would only re-crash elsewhere.

Task payloads and results must be extended-wire-safe (they cross links).

API:

- `(dpool-worker-start name handler)` — on each member; `handler` is `(lambda (payload) result)`, each task in its own process
- `(dpool-start members worker-name [opts])` → pool — on the submitter; `opts` may set `(mode . at-least-once|at-most-once)`
- `(dpool-submit pool payload [opts])` → task-id — async; `opts` may override `mode`
- `(dpool-await pool task-id [timeout])` → value — blocks; raises `#(dpool-error ,reason ,id)` (`task-error` / `node-down` / `await-timeout`)
- `(dpool-stats pool)` → `((live . n) (inflight . n) (queued . n))`

For a **singleton** across the cluster (one global scheduler, one lock
holder) rather than spread work, dpool is the wrong tool — that needs
consensus, which a partition turns into split-brain. Use a system that
already solved it (Redis `SET NX`, etcd, Consul) instead of electing in
igropyr.

---

## Running and Building

### Environment Variables

Before running Igropyr, set these two environment variables:

```bash
export CHEZSCHEMELIBDIRS=.:lib:/Users/guenchi/Scheme/lib
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
```

- **CHEZSCHEMELIBDIRS**: Colon-separated list of directories to search for R6RS libraries. Include `.` for the current directory.
- **CHEZSCHEMELIBEXTS**: Colon-separated list of file extensions and their compiled forms (`.so`). Chez tries each extension in order.

Igropyr uses the `.sc` extension for all source files. The library search will find `igropyr/libuv.sc`, `igropyr/actor.sc`, etc.

One optional variable controls dev-time contracts:

- **IGROPYR_CONTRACTS**: read at **compile time** by `(igropyr checked)`.
  Unset or `off` (the production default) compiles contracts to nothing;
  `full` injects them; any other value is a compile-time error. After
  changing it, do a **clean rebuild**. See
  [Development Contracts](#development-contracts).

### Directory Case Sensitivity

On case-sensitive file systems (Linux), the directory name must match the library name exactly. Igropyr's libraries are lowercase `igropyr.*`, so the directory must be named `igropyr`, not `Igropyr`.

On macOS (case-insensitive by default), this is not enforced, but it's good practice to be consistent.

### File Descriptors Limit

libuv's TCP listen/accept uses one file descriptor per open connection. The OS default is often 256 (macOS) or 1024 (Linux). For stress testing or production under load, increase it:

```bash
ulimit -n 10240
```

Then run the application. Without this, you'll hit "too many open files" after ~200 connections.

### Running an Application

```bash
# Set up environment
export CHEZSCHEMELIBDIRS=.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
ulimit -n 10240

# Run
scheme --script myapp.sc
```

The script should call `(start-scheduler thunk)` at the end. The scheduler never returns; run in the foreground or wrap with your process supervisor (systemd, supervisor, etc.).

### Native Libraries and Supported Platforms

Igropyr supports Chez Scheme 10 on macOS and Linux, on x86_64 and arm64.
The internal platform layer automatically selects the correct ABI layout and
loads libuv, zlib, and the system C library from standard shared-object names.
Unsupported machine types fail during import with a list of expected platforms.

```bash
# macOS
brew install chezscheme libuv

# Debian/Ubuntu
sudo apt-get install chezscheme libuv1-dev zlib1g-dev
```

### Building from Source (Advanced)

Igropyr is pure Scheme with no build step. All `.sc` files are interpreted by Chez Scheme at runtime. If you want to precompile libraries for faster startup:

```bash
# Per-library optimized build
chez --libdirs .:lib --script igropyr/build.ss

# Whole-program optimized build
chez --libdirs .:lib --script igropyr/build-whole.ss
```

Then Chez will load `.chezscheme.so` instead of `.sc`. This can reduce startup time but is not required.

---

## Testing

### Smoke Tests

The test directory contains self-asserting regression tests and interactive
smoke/demo servers. Run every automated check with:

```sh
./igropyr/test/run-all.sh
```

The suite verifies all library imports, the actor scheduler, asynchronous file
reads (empty, multi-chunk, and missing files), HTTP framing/trailers/query
parsing over real TCP, and observable boot failures. GitHub Actions runs the
same entry point on macOS and Ubuntu.

`smoke-echo.sc`, `smoke-echo-actor.sc`, and `run-otp.sc` remain interactive
servers for manual exploration and load testing.

Then in another terminal:

```bash
# Test a route
curl localhost:8080/

# Stress test (Apache Bench)
ab -n 50000 -c 500 http://127.0.0.1:8080/

# Test half-sent request (should timeout and be reaped):
printf 'GET / HTTP/1.1\r\nHost: x' | nc 127.0.0.1 8080 &

# Test stuck worker recovery:
for i in $(seq 8); do curl -m 2 localhost:8080/stuck & done
# Should recover within 35 seconds (30s stuck timeout + some overhead)

# Test crash recovery:
curl localhost:8080/crash       # Returns 500 after 4 attempts
curl localhost:8080/            # Still works
```

### Writing New Tests

Create a test script:

```scheme
#!chezscheme
(import (chezscheme)
        (igropyr actor)
        (igropyr http)
        (igropyr express))

(define failures 0)

(define (assert cond msg)
  (unless cond
    (display (string-append "FAIL: " msg "\n"))
    (set! failures (+ failures 1))))

(start-scheduler
  (lambda ()
    ;; Test 1: Simple spawn and send
    (let ((p (spawn (lambda ()
                      (receive
                        (`(hello ,x) x))))))
      (send p '(hello 42))
      (assert (process-alive? p) "Process should be alive after send")
      (sleep-ms 100))
    
    ;; Test 2: HTTP handler
    (define app (create-app))
    (app-get app "/test"
      (lambda (req res)
        (send-json! res (list (cons 'ok #t)))))
    (app-listen app 8888)
    
    ;; Test 3: Query via curl (in real tests, use a Scheme HTTP client)
    ;; curl localhost:8888/test
    
    (display (string-append "Tests: " (number->string failures) " failed\n"))
    (if (= failures 0)
        (begin (display "All tests passed\n") (exit 0))
        (exit 1))))
```

Run it:

```bash
scheme --script test-myfeature.sc
echo $?  # Exit code 0 = success
```

### Load Testing

For concurrent load tests, use Apache Bench or `wrk`:

```bash
# 50,000 requests, 500 concurrent
ab -n 50000 -c 500 http://localhost:8080/

# Or wrk (more sophisticated)
wrk -t 4 -c 500 -d 30s http://localhost:8080/
```

Watch the supervisor's pool state via the `/stats` endpoint:

```bash
watch -n 1 'curl -s localhost:8080/stats | jq'
```

---

## Development Contracts

`(igropyr checked)` provides dev-time contract macros for **internal
invariants** — bugs in your own code, caught at module boundaries. They
are compiled away by default: with `IGROPYR_CONTRACTS` unset (or `off`),
`define-checked` becomes a plain `define` and `define-checked-record`
becomes a plain `define-record-type`, with **zero residue and zero runtime
dependency** on the library.

> **Never rely on this library for a production requirement.** Contracts
> default to OFF, so anything they check may not run in production.
> Validation of external input — request ranges, lengths, paths,
> permissions — is ordinary always-on business code and must not live in a
> contract.

> **Never put a return contract (`-> pred`) on a tail-recursive or looping
> procedure.** The return check must capture the return value, which
> structurally destroys tail calls: the loop grows memory with depth.
> **Argument contracts are TCO-safe** — they run once on entry and never
> touch the return path.

### Where Each Kind of Checking Belongs

| Kind | Where |
| --- | --- |
| External input, semantics (range/length/path/permission) | ordinary code — your duty, always on |
| External input, shape (json/form/wire → values) | ordinary code, or a hand-written `parse-x` |
| Internal invariants (our own bugs) | `define-checked` / `define-checked-record` |
| Last resort | Chez safe primitives + let-it-crash |

### API

```scheme
(import (igropyr checked))

;; argument contracts only (TCO-safe):
(define-checked (find-route (table route-table?) (path string?))
  (let loop ((segs (split path)))   ; internal named let: unchecked, free
    ...))

;; with a return contract (never on a loop):
(define-checked (canonical-host (h string?)) -> string?
  (string-downcase h))
```

- `(define-checked (name (arg pred) ...) body ...)` — each `pred` is a
  one-place predicate expression; prefer **named** predicates
  (`route-table?`) over inline lambdas, since blame prints the predicate's
  source text. A bare argument with no predicate is allowed and unchecked.
  Fixed arity only: no optional/rest args, no `case-lambda`.
- `(define-checked (name (arg pred) ...) -> ret-pred body ...)` — adds a
  single-value return contract. Procedures returning multiple values may
  use argument contracts but no `->`.
- `(define-checked-record name (field pred) (mutable field pred) ...)` —
  expands to `define-record-type` with the usual names (`make-name`,
  `name?`, `name-field`, `name-field-set!`). The constructor and setters
  check contracts; the predicate and accessors are the raw record ones, so
  **reads are free**. Only `make-name` is generated (no `parse-x`, parent,
  protocol, or nongenerative clause — records needing those use the plain
  form).
- `(contract-level)` — expands to the literal `'full` or `'off` baked at
  the expansion site. `app-listen` prints it at startup; assert it at the
  top of a test suite.

A violation raises `&assertion` naming the procedure, the argument/field,
and the expected predicate, with the offending value as the irritant:

```
Exception in find-route: argument 'path' violated contract string?
  with irritant 42
```

### The Switch

`IGROPYR_CONTRACTS` is read **once per compiling process, at expansion
time** — not at run time:

- unset or `off` → **off** (production default, zero residue)
- `full` → checks are injected
- any other value → an **expansion-time error**, so a misspelled value can
  never silently disable checking

The level is baked into each compiled `.so` at that `.so`'s compile time.
**After changing the flag, do a CLEAN rebuild** — otherwise different
libraries disagree, and only `app-listen`'s startup line tells you what
the entry point was compiled with.

### Boundary Contracts in the Built-in Libraries

The exported procedures of `(igropyr express)` (and `(igropyr session)`,
`(igropyr jwt)`) carry argument contracts under a debug build. Pass the
wrong type — a string where a request object is expected — and you get
blame naming the procedure, the parameter, the expected predicate, and the
value you actually passed. A production build (`IGROPYR_CONTRACTS` unset)
compiles all of it away, so there is **zero overhead** on the request path.

---

## Code Style

### The `.sc` Extension

Igropyr deliberately uses the `.sc` extension for every source file. The author advocates `.sc` as a statement of intent: the code is written against strict R6RS semantics and is aimed at production use — as opposed to the anything-goes connotation of `.scm` or the Chez-flavored `.ss`. Looking ahead, the project will (very likely) move toward R7RS Large.

### Naming Conventions

- **Predicates** end with `?`: `process-alive?`, `queue-empty?`
- **Mutators** end with `!`: `send!`, `set-header!`, `hashtable-set!`
- **Constructors** start with `make-`: `make-queue`, `make-pcb`
- **Record accessors** are bare: `queue-next`, `pcb-id`
- **Library names** are lowercase with hyphens: `(igropyr actor)`, `(igropyr http)`

---

## Common Pitfalls

### Receive with Timeout Must Be First

The `receive` macro recognizes `(after ms ...)` only in the first clause. Putting it elsewhere will not work:

```scheme
;; ✓ Correct
(receive
  ((after 5000 (display "timeout\n")))
  (`(message ,x) x))

;; ✗ Wrong - timeout is ignored
(receive
  (`(message ,x) x)
  ((after 5000 (display "timeout\n"))))
```

### Yielding Inside a libuv Callback

Never call `receive`, `send` (blocking), or `raise` inside a callback. Only send messages via the internal deliver mechanism.

Check the stack trace for function names like `on-read`, `on-write`, `on-connection`. If you see one, you're in a callback context.

### Unquote Syntax in Receive Patterns

Use backtick (`` ` ``) for quasiquote and comma (`,`) for unquote in patterns:

```scheme
;; ✓ Correct
(receive
  (`(ping ,from) (send from 'pong)))

;; ✗ Wrong - will not match
(receive
  ((ping from) (send from 'pong)))
```

### Box-and-Identifier-Syntax for Cross-Library Mutable State

If two libraries need to share mutable state (rare, should be avoided), one library wraps it in a box and uses identifier-syntax to share:

```scheme
;; library-a.sc
(define counter-cell (box 0))
(define-syntax counter-ref
  (identifier-syntax
    (unbox counter-cell)
    ((set! id v) (set-box! counter-cell v))))
(export counter-ref)

;; library-b.sc
(import (library-a))
;; counter-ref is now usable like a variable
(set! counter-ref (+ counter-ref 1))
```

Without this, direct references to assigned library variables across library boundaries raise an error (R6RS rule).

### Large Integer Operations

`fxand`, `fxor`, etc. work only on fixnums (typically 61-bit on 64-bit Chez). For large integers, use `bitwise-and`, `bitwise-or`, etc. from `(chezscheme)`:

```scheme
;; ✓ Large integers
(bitwise-and big-num #xFF)

;; ✗ Fixnum only
(fxand big-num #xFF)  ; raises an error if big-num > 2^60
```

### Multi-byte UTF-8 Percent Decoding

When decoding percent-encoded URLs, `%XX` represents octets, not characters. Multi-byte UTF-8 sequences like `%E4%B8%AD` (UTF-8 for "中") must be collected as bytes first, then decoded as a whole:

```scheme
;; ✓ Correct - collect bytes, then decode
(let ((bytes (make-bytevector 3)))
  (bytevector-u8-set! bytes 0 #xE4)
  (bytevector-u8-set! bytes 1 #xB8)
  (bytevector-u8-set! bytes 2 #xAD)
  (utf8->string bytes))  ; -> "中"

;; ✗ Wrong - decodes each %XX as a character
(string-append (string (integer->char #xE4))
               (string (integer->char #xB8))
               (string (integer->char #xAD)))  ; -> mojibake
```

The `percent-decode` function in `(igropyr http)` does this correctly.

### Parenthesis Pairing in Deep Nesting

Use an editor with paren matching or linting. If you suspect imbalance, use awk to count:

```bash
# Count opening and closing parens in a file
awk 'BEGIN{o=0;c=0} {o+=gsub(/\(/,$0); c+=gsub(/\)/,$0)} END{print "Open:",o,"Close:",c}' file.sc
```

If they don't match, the file has a syntax error. Look for mismatched quotes or unclosed comments.

### Process Registry Lookups

`whereis` returns `#f` if the process is not registered. Always guard the result:

```scheme
;; ✓ Correct
(let ((logger (whereis 'logger)))
  (when logger (send logger msg)))

;; ✗ Wrong - crashes if logger is not registered
(send (whereis 'logger) msg)  ; sends to #f, which raises an error
```

### Task Context Loss on Crash and Retry

When a task crashes and is retried, the handler is called again with the same `req` and `res` objects. Avoid side effects in the handler:

```scheme
;; ✓ Safe (stateless)
(app-get app "/users/:id"
  (lambda (req res)
    (send-json! res (list (cons 'id (req-param req "id"))))))

;; ✗ Unsafe (side effect will happen twice on retry)
(define call-count 0)
(app-get app "/users/:id"
  (lambda (req res)
    (set! call-count (+ call-count 1))
    (send-json! res (list (cons 'calls call-count)))))
```

Use process-local state (e.g., gen-server) or a database if the side effect must happen once.

---

## Appendix: Performance Tips

### Connection Pooling

For database clients, use connection pools (MySQL supports this directly; for Redis, wrap multiple connections in a round-robin dispatcher).

### Worker Count

The default 8 workers is tuned for a single CPU core. For multi-core systems, increase it (though Igropyr runs all workers on one OS thread, so the bottleneck is CPU, not I/O).

### Memory

Each green process is ~1 KB of metadata. Thousands of processes are feasible. The main memory use is buffers for request/response bodies. Keep body size limits reasonable (default 1 MB for HTTP, 8 MB for WebSocket).

### Monitoring

Use `/stats` and process-level tools (`top`, `Activity Monitor`) to watch CPU, memory, and open file descriptors. Stuck workers (detected by the supervisor) should be rare; if they're common, your handlers have blocking operations.

---

## Further Reading

- Chez Scheme documentation: https://cisco.github.io/ChezScheme/
- libuv documentation: https://docs.libuv.org/
- R6RS Scheme specification: https://r6rs.org/
- Erlang/OTP documentation: https://erlang.org/doc/

---

*Last updated: 2026-07-10*
