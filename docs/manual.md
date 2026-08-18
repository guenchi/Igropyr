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
15. [RSA Keys and Signatures](#rsa-keys-and-signatures)
16. [Metrics](#metrics)
17. [Outbound HTTP Client](#outbound-http-client)
18. [Database Clients](#database-clients)
19. [Async File Reads](#async-file-reads)
20. [Durable Writes](#durable-writes)
21. [JSON and gzip](#json-and-gzip)
22. [S-Expression RPC](#s-expression-rpc)
23. [Distribution](#distribution)
24. [Vector Scoring](#vector-scoring)
25. [Embedded JavaScript](#embedded-javascript)
26. [Cached SSR](#cached-ssr)
27. [Object Storage and AWS](#object-storage-and-aws)
28. [Password Hashing](#password-hashing)
29. [Running and Building](#running-and-building)
30. [Testing](#testing)
31. [Development Contracts](#development-contracts)
32. [Code Style](#code-style)
33. [Common Pitfalls](#common-pitfalls)
34. [Appendix: Performance Tips](#appendix-performance-tips)
35. [Further Reading](#further-reading)

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
  • PostgreSQL client
```

### Each Layer's Responsibility

- **libuv (libuv.sc)**: Direct FFI bindings to libuv. Manages TCP handles, read/write buffers, and event polling. Delivers data into the upper layers via callbacks.

- **Actor (actor.sc)**: Green process scheduler with continuation-based context switching. One OS thread, preemptive scheduling via timer interrupt, message-passing mailboxes, link/monitor for process relationships.

- **OTP (otp.sc)**: Worker pool with supervisor. Spawns N workers, distributes tasks, detects crashes and stuck workers (>30s), auto-retries failed tasks (≤3 times), kills stuck workers without retrying.

- **HTTP (http.sc)**: Protocol layer. Parses HTTP/1.1 requests (headers, body, chunked encoding), manages per-connection reader processes, invokes user handler in a pool worker, encodes responses, handles keep-alive and pipelining.

- **Express (express.sc)**: Framework layer. Router with path parameters (`:id`), middleware chain, convenience response encoders (`send-json!`, `send-file!`), cookie parsing, form parsing (urlencoded and multipart), static file serving.

- **WebSocket (websocket.sc)**: RFC 6455 codec, handshake, frame masking, fragmentation, ping/pong. Each socket is a green process that calls a user session handler.

- **JSON, gen-server, pubsub, Redis, MySQL, PostgreSQL**: Standalone libraries with no interdependencies (except JSON uses Scheme primitives, gen-server uses actor, pubsub uses gen-server+actor, redis/mysql/postgresql use actor+uv; MySQL, PostgreSQL and the render pool share the `(igropyr connpool)` connection-pool engine).

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
- `body-limit`: Request body cap in bytes (default 1 MiB; 413 beyond it).
  Validated at boot (must be a positive fixnum). PROCESS-GLOBAL: the last
  `http-listen`/`app-listen` in the process wins, across all servers
- `reuseport`: SO_REUSEPORT bind — run N OS processes on the same port,
  kernel-balanced (Linux only)
- `on-failure`: failure hook `(lambda (req res info))` when retries are
  exhausted or a stuck worker was killed (see the fault handler section)

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
    (let-values (((id token reply)
                  (conversation-start!
                    (lambda (req suspend! commit!)
                      (let ((tx (begin-tx!)))          ; live, held across rounds
                        (guard (e (#t (rollback! tx) (raise e)))
                          (let ((req2 (suspend! confirm-page-data)))
                            (commit! (lambda () (commit-tx! tx)))  ; through commit!
                            done-data))))
                    req
                    300000
                    req-body)))          ; what identifies a retry
      ;; the token goes to the client and must come back with the next request
      (send-json! res (cons (cons 'conv id)
                            (cons (cons 'token token) reply))))))

(app-post app "/transfer/:id"
  (lambda (req res)
    ;; the token stays a STRING — it is opaque hex, and one that has been
    ;; through a decoder that changed its type compares 'stale
    (let ((token (cond ((assoc "token" (req-query req)) => cdr) (else ""))))
      ;; the STATUS decides, never the reply
      (let-values (((r status) (conversation-resume! (req-param req "id") token req)))
        (cond
          ((conversation-gone? status)             ; died: rolled back
           (set-status! res 410)
           (send-json! res '((fault . "gone") (rolled-back . #t))))
          ((conversation-settled? status)          ; finished; answer not kept
           (set-status! res 409)
           (send-json! res '((fault . "settled") (committed . #t))))
          ((conversation-stale? status)            ; a different question
           (set-status! res 409)
           (send-json! res '((fault . "stale") (applied . #f))))
          ((conversation-done? status) (send-json! res r))
          (else (send-json! res (cons (cons 'token status) r))))))))
```

API: `(conversation-start! flow req [ttl-ms [request-key [on-killed]]])`
spawns the flow and returns `(values id token first-reply)` — note that
the id arrives only after the first `suspend!`, so a caller that needs it
*before* anything happens wants the two-phase form below. The flow is
called as `(flow req suspend! commit!)`: `(suspend! reply)` answers the
current round and parks until the next `(conversation-resume! id token
req)`, which returns `(values reply status)`. Default TTL 300 000 ms; a
conversation that sat *parked* past it is raised at —
`'conversation-expired` reaches the flow, so a `guard` can roll back. A
*step* that overruns is killed instead, and a kill runs no winders —
that path is `on-killed`, below.

### Commit through `commit!`

`(commit! thunk)` runs the thunk, marks the
conversation committed the instant it *returns*, and passes its values
back unchanged. This is not bookkeeping — it is the only way the library
can tell two exits apart that otherwise look identical. An exception
leaving the flow proves the winders ran; it does **not** prove the
transaction was undone, because the flow may have been unwinding from a
commit that had already succeeded — an after-thunk that raised, a `guard`
that re-raised. Recorded as a rollback, that exit answers `'gone`, and a
client that retries on `'gone` performs the whole thing twice. With
`commit!` the two are recorded apart and only the genuine rollback is
`'gone`.

#### One conversation is one logical transaction

`commit!` is the
conversation's last state change — no new transaction is opened after it
— and the mark it sets is **sticky**: never cleared, so a flow that
commits, parks, is resumed and only then fails is still `'unknown`, not
`'gone`. Wrap only the commit itself; a non-local exit out of the thunk
(an escaping continuation, or `suspend!` called inside it) skips the mark
and is outside the contract.

#### A commit can also end in "maybe"

A commit primitive is sometimes certain it succeeded, sometimes certain it
never left, and sometimes **neither** — a request that timed out, a
connection reset after the write, a cancelled call, a reply that would not
parse. For that third case the thunk raises

```scheme
#(commit-uncertain reason)
```

from inside `commit!`, and the conversation is recorded as having a commit
that **may** have landed.

The mark behind `commit!` therefore has three values and only ever rises
through them — no commit, a *maybe*, a confirmed one — never falling back.
A flow that catches its own uncertainty and retries the same idempotent
commit successfully ends at confirmed, which is the truth; one that raises
uncertain again after a confirmed commit stays confirmed, because the
first fact does not expire. An ordinary (untagged) exception never erases
what an earlier attempt asserted.

**What `settled?` means against each.** A later resume answers `'unknown`
on the library's own evidence, where before it would have said `'gone` and
invited a retry. It is *not* frozen there, and that is the whole point of
keeping this separate from a confirmed commit:

| the mark | a `settled?` predicate answering `#f` | result |
|---|---|---|
| a *maybe* | is the fact that **settles** it — the library only knew "possibly" | `'gone` |
| confirmed | **contradicts** evidence the library holds: it watched the thunk return | stays `'unknown` |

So the third outcome exists to make reconciliation *possible*, not to add
a second way of refusing it. (That refusal needs a witness in hand for
that call — read from this node's table, or carried back by an owner that
read its own — and nothing caches one between calls.)

**The adapter owes this for every ambiguous failure**, and the obligation
is easy to under-fill. Anything a commit can raise after the request has
been dispatched *and* that cannot authoritatively rule out its having
taken effect — the timeout, the reset, the cancellation, the unparseable
response, an exception in your own post-dispatch code — is a "maybe" and
must arrive as this tag. (A definite, authoritative rejection is not
ambiguous, even though the request did leave.) What the library reads into
every **other** exception is that this attempt added no reason to think a
commit landed. That is not a fact the library can establish about somebody
else's driver; it is **an assertion your thunk makes by not raising the
tag**.

Raise it **inside the commit thunk** — that is the only place with a
promise attached. The flow-exit path recognises the tag as well, so
raising it elsewhere is usually still understood, but only usually: the
flow's own `guard` may catch it first, and a kill discards winders so
nothing recognises anything.

The `reason` never reaches the record. The raise is passed on unchanged,
so it travels wherever the flow lets it, but the tombstone holds a symbol
and must stay small — log the detail before raising if you want it kept.

### Two phases, when the id has to exist first

`conversation-start!` mints the conversation's id inside the same call
that spawns the flow, and does not hand it back until the first
`suspend!`. Between those two moments the flow has begun acting on the
world and **nothing outside can name it** — so a caller cannot write "I am
about to start X" anywhere durable, a `#(conversation-failed ...)` had no
id to carry, and a starter killed during the first step left a
conversation still running, still talking to whatever the flow talks to,
whose id no longer existed anywhere.

Splitting the call puts the identity first:

```scheme
(let ((h (conversation-prepare! flow req)))      ; inert
  (record-intent! (conversation-ref-id h))       ; durable, before any effect
  (let-values (((token reply) (conversation-run! h)))
    ...))
```

| call | |
|---|---|
| `(conversation-prepare! flow req [ttl-ms [request-key [on-killed]]])` | validates the options, mints the id, returns an opaque **handle**. **Inert**: no process, no registration, no timer. (Not *pure* — minting an id reads the random source, the node identity and the clock.) |
| `(conversation-ref-id h)` | the id, available immediately |
| `(conversation-run! h)` | starts it and parks until the first `suspend!` → `(values token first-reply)` |
| `(conversation-abandon! h)` | give up a prepared conversation that was never run |

`conversation-start!` is exactly `prepare!` + `run!`, and still returns
`(values id token first-reply)`.

No lifetime clock starts before `run!`, so a handle may sit for as long as
you like. A handle may be handed to another **process** on this node — the
first reply goes to whoever calls `run!` — but never to another **node**:
it holds closures, and `run!` refuses if the node identity has changed
since the id was minted. Running, abandoning, or simply dropping a handle
releases the flow and request it was holding; the handle is single-use in
every direction, and a second `run!` (or an `abandon!` after one) is an
`assertion-violation`.

A `run!` that **raised** has been used up too, and that is the part worth
knowing before you write the handler. The flow may have run part-way and
had effects, so what the handle spent is its one chance to spawn — a
second `run!` would be a second conversation wearing the first one's id.
So do **not** call `abandon!` from a failure handler wrapped around
`run!`: it raises an `assertion-violation` of its own and buries the
error you were handling. `abandon!` is for the window **between**
`prepare!` and `run!` — the claim collided, a gate closed, a hold expired
— and once `run!` has been called, the way to settle what happened is to
reconcile by **id**.

#### Recovering a conversation whose starter died

This is what the id bought. Persist it **before** `run!`; on recovery, ask
`(conversation-peek id)`:

| answer | what it means |
|---|---|
| `'parked` with a token | **adopt it.** That token is live: `conversation-resume!` with it and this process becomes the one the conversation answers. A conversation whose starter died is otherwise perfectly healthy — parked, holding its transaction, waiting. (peek hands back the reply it is waiting to have answered; `resume!` consumes the token and returns the *next* round's reply.) |
| `'completed` | the flow returned; the reply is its final answer and there is nothing to adopt. peek never answers "running" — a peek that arrives mid-step is answered when that step parks. |
| `'gone` | it rolled back; nothing to adopt, and safe to start afresh |
| `'settled` | it finished earlier; only the record is left |
| `'unknown` / `'unreachable` | **not an answer, and possibly transient.** Registration happens inside the conversation's own process, so a peek between spawn and registration answers `'unknown`; a remote peek before the owner's router exists answers `'unreachable`. Look again. |

Neither `'unknown` nor `'unreachable` licenses a second attempt. That
licence comes only from reconciling downstream, or from the downstream
operation being idempotent.

**One adopter.** Two recoverers both peek and both see the same token; the
first `resume!` wins and the other is `'stale` (or replayed, if its
request-key matches). The library will not choose between them — the store
the ids live in has to: a claim, a lease, something.

**The id is a bearer credential**, and this recipe deliberately puts it in
a database. Whoever can read it can peek — which discloses the last reply,
whatever that contains — and can present the live token with a request of
their own choosing, which *advances the flow*. The entropy is not the
exposure; distribution is. Treat a persisted id as a session control
credential: not in logs, not in URLs, not in a table half the organisation
can read.

After a restart the process is gone and so is the conversation: a local
peek on an old id answers `'unknown`, a remote one `'unreachable` until the
restarted owner has built its router.

### When the first step dies

When the first step dies, `conversation-start!` (or `conversation-run!`)
raises — and one of the
two raises must be caught. Nothing has been answered yet at that point,
so the failure surfaces in the caller rather than as a status:

| raise | meaning | what to do |
|---|---|---|
| `#(conversation-failed id reason)` | the flow raised before its first `suspend!` **and** before its `commit!`; its winders ran, so it rolled back | let it crash — retrying is correct |
| `#(conversation-uncertain id outcome reason)` | the first step may have got past its `COMMIT` — killed for overrunning, killed from outside, taken down by a link, or raising after `commit!` returned | **catch it**; do not run the work again |

The distinction matters more than it looks, because of what a *host* does
with an uncaught exception. A host that re-runs a task which never
answered — this framework's own worker pool is one, and it will re-run a
handler up to its retry limit — cannot tell an uncertain raise from an
ordinary crash. So the one signal that exists to say *do not run this
again* is exactly what makes it run again, up to the retry limit, on a
first step that may already have committed. "Not retryable" is a property
of the fact, not a protection.

Catch it where it is raised and turn it into an **answer** — answering is
what takes the task out of the re-run set, and the id is what makes the
answer actionable:

```scheme
(guard (e ((and (vector? e)
                (eq? (vector-ref e 0) 'conversation-uncertain))
           ;; answered, so nothing re-runs it; the id goes to the client
           ;; (or an operator) to reconcile against
           (set-status! res 409)
           (send-json! res `((fault . "uncertain")
                             (conv . ,(vector-ref e 1))
                             (resubmit . #f)))))
  (conversation-start! flow req))
```

**Match these by their tag, never by length or exact shape.** The guard
above tests `(vector-ref e 0)` and nothing else, and that is the contract:
the tag identifies the raise, the arity does not and is not promised. It
has already changed once — `conversation-failed` carried two elements and
now carries three, because a retryable failure that cannot name what
failed is of little use — and a consumer that had written
`(= (vector-length e) 2)` stopped matching the moment it did. That failure
is silent, and it is the worst shape: the clause simply never fires, so
the *error* path quietly stops being handled while every ordinary request
still works.

`#(conversation-failed ...)` is deliberately *not* caught there. It is the
one raise whose work is safe to repeat, so it is left to the host's
ordinary failure handling — whatever that is in this assembly.

### The status is the answer; the reply is only data

A flow may
legitimately return the symbol `'gone` as its final value, so control
outcomes never share a position with it:

| status | meaning |
|---|---|
| a token string | the step ran — present it to continue |
| `'done` | the flow finished; `reply` is its final answer |
| `'settled` | it finished, but the answer is no longer retained |
| `'stale` | not applied, and will not be |
| `'gone` | it left through its winders *before* `commit!` returned — for a transactional flow, rolled back |
| `'unknown` | it is not here and this node cannot say whether it committed |
| `'unreachable` | no definite reply came back from the owner node — equally consistent with the request having arrived and the owner still working on it |
| `'overloaded` | the owner **refused** the forward before touching the conversation: it was already hosting its limit of them. Nothing was started, the token is still good, and asking again later is right |

`conversation-done?`, `conversation-settled?`, `conversation-stale?`,
`conversation-gone?`, `conversation-unknown?`, `conversation-unreachable?`
and `conversation-overloaded?` are applied to the *status*.

#### `'unknown` is not `'gone`

`'gone` promises a rollback, so it is
answered only from **positive evidence**: a record on this node saying
this conversation left through its winders without having committed.
Never from an absence — "no process and no record" is `'unknown`,
because the ways of dying that write no record (a kill from outside, a
link cascade, a VM going down, a record that aged out, an id from an
earlier incarnation) are an open set, and reading a rollback guarantee
off any of them is a positive claim derived from missing evidence.
Never from a record that merely says the flow raised, either: that is
what `commit!` splits in two.

The library keeps five outcomes apart, and every answer is read off one:

| record | meaning | answer |
|---|---|---|
| settled | the flow returned | `'settled` |
| rolled back | left through its winders, `commit!` had not returned | `'gone` |
| committed then failed | left through its winders *after* `commit!` returned | `'unknown` |
| commit uncertain then failed | left through its winders after `commit!` reported the commit as a *maybe* | `'unknown` |
| killed / no record | stopped in flight, or stopped in a way nothing recorded | `'unknown` |

The last three answer alike here and are still three records, not one.
The two failure records part company under a `settled?` predicate
answering `#f`: against a commit this library watched return that is a
contradiction and the answer stays `'unknown`, while against a commit
the flow only called a maybe it is the new information that settles the
question, and the answer becomes `'gone`. Folding them together would
close the one reconciliation route that is legitimate — see *Answering
`'unknown` yourself* below.

`'unknown` licenses one thing less than `'gone`: **do not resubmit**.
Reconcile against your own state, which is where the truth still is. It
appears wherever this node cannot produce the evidence — including for a
fabricated id, which it cannot tell from a real one it has forgotten.

The record is **bounded**, by age and by count (`conversation-set-limits!`),
because an unbounded log of every conversation that ever finished is a
leak with a long fuse. Past either bound an entry is dropped and the
conversation becomes `'unknown` — the honest limit of the mechanism, and
the reason both bounds are settable. What a forgotten record can no
longer do is become `'gone`.

#### Answering `'unknown` yourself

`conversation-resume!` and
`conversation-peek` take an optional predicate — `(conversation-resume!
id token req settled?)` — consulted *only* when the answer would be
`'unknown`: `#t` gives `'settled`, `#f` gives `'gone`, and anything else,
including a raise, leaves `'unknown` standing. It is applied on the
asking node, so it covers a forwarded resume too.

This is where an application that wrote the conversation id **in the same
transaction as the effect** hands the library the truth: durable, atomic
with the thing it describes, and outliving both the record and the
process.

#### Keeping the record past the process

The predicate above answers one conversation at a time, from a store the
application already keeps. The other way round is to give the library
somewhere to put the record itself:

```scheme
(conversation-record-hooks! writer reader)   ; both, or #f #f to uninstall
```

`writer` is called as `(writer id outcome)` the moment an outcome becomes
final; `reader` as `(reader id)` when nothing local is left to answer
from, and returns that outcome or `#f`. Together they extend the
in-memory record past its bounds, past a restart, and past the death of
the node that ran the conversation.

**There is no translation table to learn, and deliberately so.** The
outcome handed to the writer is the record itself — the same value the
library keeps in memory — and the reader hands it straight back.
`settled-or-lost-answer` in `conversation.sc` is the single place a
record becomes a status, and it does not know or care whether the record
came from memory or from a hook. Anything written here that restated
that mapping would be a second copy of it, correct until the day it
wasn't. Store the value; do not interpret it.

What a record can be is fixed: `#t`, `'rolled-back`,
`'committed-then-failed`, `'commit-uncertain-then-failed`, `'killed`.
A reader answering with anything else is treated as having no record and
counted in `conversation-hook-stats` — an invented word would otherwise
fall through to `'unknown` in silence, and a reader inventing vocabulary
is worth seeing.

A minimal pair, durable because it goes through `(igropyr durable)`:

```scheme
(import (igropyr durable))

(define (record-path id) (string-append "/var/lib/conv/" id))

(conversation-record-hooks!
  (lambda (id outcome)
    (durable-write-file! (record-path id)
                         (string->utf8 (format "~s" outcome))))
  (lambda (id)
    (and (file-exists? (record-path id))
         (with-input-from-file (record-path id) read))))
```

**The writer is called with interrupts enabled**, after the record is
already committed to memory. What that does and does not buy you is
worth being precise about, because this runtime has one OS thread:

- A writer that **yields** — waits on a message, sleeps, parks — gives
  the scheduler its turn, and costs only the process that called it.
  Under the earlier arrangement such a writer could never be answered at
  all, because the process that would answer it could not run. Which
  process pays depends on the path: on the two below where the
  conversation publishes for itself, the conversation waits and is still
  counted by a drain; on the watchdog's paths the conversation is
  already gone and the waiting is the watchdog's, which nothing counts.
- A writer that makes a **blocking call** still stops every green
  process for its whole duration. Interrupts are not a second thread,
  and a synchronous `fsync` that has not returned is not a point at
  which anything can be scheduled. This is the normal mode of
  `durable-write-file!`. Measured: a 192 MiB durable write took 72ms,
  and the longest gap between two scheduler turns in that run was also
  72ms, against 12ms otherwise. Size your records accordingly — the cost
  is the syscall's, and it is charged to the whole node.

**Which process it runs in depends on which path published.** Normal
completion and a failing flow publish from the conversation's own
process. The watchdog publishes from *its* process on two paths — the
backstop for a conversation that died some way it never described, and
a kill it performs itself. A writer that reads `self` or anything
process-local sees a different process there.

Three further consequences:

- The final value is handed back only after the writer **returns or
  raises**. A caller is therefore told "committed" after the write was
  *attempted*, not after it succeeded: a writer that raises is swallowed
  and counted, and the reply goes out regardless. If a durable copy is a
  precondition for answering, the writer must be the thing that reports
  failure — the counters are the only other signal.
- A `conversation-peek` waits for the writer where the conversation is
  still alive to be asked — normal completion, a failing flow — exactly
  as it waits out any slow step; `conversation-peek/timeout` is the
  bounded form. On the watchdog's paths it does not wait: the
  conversation is already dead, so the peek reads the record straight
  out of the table. That answer is correct *because* the table is
  written first.
- A conversation whose writer is still running on its own process still
  has a census entry, so **draining a node waits for those record
  writes** rather than cutting them off — and a writer that never
  returns holds a drain open indefinitely.
- **The conversation's `ttl` does not bound the writer, on any path.**
  It bounds time spent executing a step. Where the conversation
  publishes for itself — normal completion, a failing flow — the
  watchdog's clock is stopped first, deliberately: a writer killed
  part-way leaves an outcome that exists only in memory, which is the
  failure the record was there to prevent. Where the watchdog publishes,
  the writer is running *in the watchdog*, and there is no second
  watchdog behind it. Either way a writer is bounded by nothing but
  itself. Give one that can wait its own deadline.

**The writer must be idempotent in `(id, outcome)`.** Storing the same
outcome twice has to be storing it once. First-write-wins governs the
in-memory table, and an entry that has been pruned is no longer a first
write: a conversation whose record was evicted and which is later killed
has that outcome re-established from the conversation's own state, and
published again with the same value. Overwrite a row or a file; do not
append.

**A record read through the hook is a record like any other**, including
against the `settled?` predicate: a `'committed-then-failed` from disk
contradicts a predicate answering `#f` and holds the answer at
`'unknown`, while a `'commit-uncertain-then-failed` lets that same `#f`
resolve to `'gone`. The distinction is the reason those are two records
rather than one, and it survives the trip through storage.

**A writer that raises cannot fail the transaction it is recording.** The
raise is swallowed and counted, because a failure to *note* what happened
must not become a second, larger failure on the path that has just
finished the work. The counters are the only signal that this is
happening, so watch them:

```scheme
(conversation-hook-stats)   ; => (... (record-writer-errors . 0)
                            ;         (record-reader-errors . 0))
```

Installing validates the pair together — two procedures, or `#f` and
`#f`. There is no half-installed state to be caught in, and an uninstall
cannot interrupt a publication already decided on: the pair in force
when the record was made is the pair that publishes it, and it is called
once for that decision. (Once *per decision* — which is not the same as
once per conversation; see the idempotence requirement above.)

##### What the library cannot check for you

The hooks are a capability, not a validation layer. The library asks the
reader a question and believes the answer; a reader that says
`'rolled-back` about a conversation that committed will produce a
`'gone`, and a `'gone` is a licence to retry. **A lying reader is
undetectable from in here** — there is nothing to compare it against, which
is exactly why the record is worth keeping in the first place.

That makes the integrity of the store the adapter's job, and it has a
shape:

- **Never rewrite a record.** First write wins in memory for a reason;
  the same must hold on disk. In particular a `#t`,
  `'committed-then-failed` or `'commit-uncertain-then-failed` must never
  later become `'rolled-back` — that single edit converts "reconcile
  this" into "retry this" and performs a committed transfer twice.
- **Do not let a caller supply outcomes.** The writer is for the library;
  an endpoint that accepts an id and an outcome from a request is a
  double-charge primitive with an HTTP interface.
- **Key it the way the id is keyed.** Ids are opaque strings and are
  compared whole; a store that trims, folds case or truncates them can
  answer one conversation's question with another's record.

A shared store lets a **restarted** node answer for conversations its
previous incarnation ran, which is what makes the record outlive the
process and the VM. It does not make any node able to answer for any
other: a clustered id names its owner, and a resume or peek for it is
forwarded to that owner rather than answered from the local reader — if
the owner cannot be reached the answer is `'unreachable`, and no reader
is consulted. The reader answers where the question is answered
locally: an unclustered id, or a node that has come back under the same
identity.

#### Setting the forwarding deadline

The same two procedures take an optional forwarding deadline in
milliseconds — `(conversation-resume! id token req 12000)` — bounding how
long a resume or peek forwarded to another node waits before answering
`'unreachable`. It defaults to 300000, which stays the value when nothing
is passed.

How long to wait belongs to the caller's budget rather than to this
library: a payment step and a status poll want different numbers, and one
constant can only give them the same. On a call that is not forwarded it
does nothing — there is no wait to bound.

**The two optionals are told apart by type, not by position.** A procedure
is the predicate, a positive integer is the deadline, either may be given
without the other, and in either order:

```scheme
(conversation-peek id settled?)          ; predicate only
(conversation-peek id 12000)             ; deadline only
(conversation-peek id settled? 12000)    ; both, either order
```

An argument that is neither is refused by name rather than ignored. The
reason it works this way: with positions, a caller who wanted only a
deadline would have to pass a predicate first — and the predicate decides
how `'unknown` is interpreted, which is not a thing to invent in order to
reach a different parameter.

`conversation-peek/timeout` does **not** take it, because it never
forwards: against a remote owner it answers `'unreachable` immediately
rather than pretending. A forwarding deadline there would control nothing
while reading as though it bounded a forwarded peek.

#### A local witness beats the predicate

Where this node's own record
says *committed then failed*, a `#f` — "durably not committed" — is not
new information filling a gap; it contradicts evidence already in hand,
and the honest answer to a contradiction is `'unknown`, not `'gone`. A
store that lags, a read served by a replica, or an id written under a
different key all produce that `#f`, and honouring it would invite a
retry of a transaction this node watched commit. Everywhere else — a
kill, an aged-out record, no record at all — there is no witness to
contradict, `#f` is the only evidence there is, and it still resolves to
`'gone`. The check is local by nature: for a forwarded resume the owner's
record is on the owner, so the predicate's own contract carries that case
alone.

`(conversation-peek id [settled?])` asks what a conversation is waiting
for without advancing it — `(values state token last-reply)`, with the same states.
It is what a caller does after an `'unreachable`, once the link is back,
instead of resubmitting.

`request-key` says what identifies a request, for replay. It is computed
when a request is accepted and compared with `equal?`; the default
`values` compares the request itself, which is right for plain data and
never matches for HTTP request records — so an HTTP flow passes
`req-body`. The key is also all that is retained.

If it raises, the request is `'stale`. Raising says the application
cannot tell this request apart from another, and two requests it cannot
tell apart must not replay each other's replies — that is the case
`'stale` exists for. It is bounded like a step: it runs with the
watchdog watching, so a key function that hangs does not park the
conversation forever.

### Asking without waiting for the step to finish

`conversation-peek` waits for a running conversation to reach its next
park, because that is when the conversation can answer. On a
reconciliation path that is right. On a request path with a deadline of
its own it is not, and the deadline that matters there belongs to the
asker, not to the conversation.

```scheme
(let-values (((state token reply) (conversation-peek/timeout id 300)))
  (cond ((conversation-no-answer-yet? state) 'ask-again-later)
        ((eq? state 'parked) (adopt token))
        (else (reconcile state))))
```

`'parked` and `'completed` are peek's own phases and have no predicates —
the `conversation-...?` predicates cover the statuses a *resume* can also
answer with, so compare those two directly. (Stated without a count on
purpose: this sentence has already been wrong once, when `'overloaded`
arrived and the number moved.)

The timeout is **required and has no default**: how long to wait is a
property of the caller's own budget, and no number the library picked
would be about that.

`'no-answer-yet` is a new status, and the thing to get right is that it
is **not** `'unknown`. All three of `'no-answer-yet`, `'unknown` and
`'unreachable` forbid the same thing — none of them licenses starting a
second attempt — but they call for different next steps:

| status | what it says | what to do |
|---|---|---|
| `'no-answer-yet` | nothing arrived within *your* limit | ask again |
| `'unknown` | this node cannot say what became of it | reconcile against your own records |
| `'unreachable` | no definite reply came back from the owner | reconcile against your own records |
| `'overloaded` | the owner declined to start it | retry later; nothing to reconcile |

`'no-answer-yet` reports the **wait**, not the conversation. The usual
cause is a conversation busy in a step — it does not answer until it
parks — but the limit can equally expire before the question was asked
at all. Read it as "no answer yet", never as "no conversation".

Two more things follow from that. A request that was already asked stays
queued at the conversation and is answered when the step parks, with the
reply then going nowhere: retrying hard against a slow step accumulates
those, so throttle on the calling side. And this entry point takes no
`settled?` predicate — when a predicate is involved, use the unbounded
`conversation-peek`, which is the one that can weigh a `#f` against the
record.

### The `on-killed` hook

`on-killed` runs after the watchdog kills an overrunning step. TTL
expiry has two paths and only one of them raises. A conversation that sat
*parked* too long is raised at, so the flow's `guard` runs and gives back
what it held. A *step* that overruns is **killed** — a step stuck in a
loop or a foreign call cannot be raised at — and `@kill` discards
`dynamic-wind` winders, so that `guard` does not run at all. A pooled
database connection survives regardless: the pool monitors its borrower
and rebuilds a connection whose borrower died, which drops the
transaction. Anything held **in process** does not — a reservation, a
file handle, an in-memory hold stays held for the life of the VM. That is
what this hook is for; it runs after the kill, in the watchdog's process,
and reaches what the flow held through whatever it closed over.

It takes **one argument** — whether the conversation had committed when
the kill landed — because the hook has two jobs that need different
answers:

```scheme
(lambda (committed?)
  (release-handle!)                  ; held in process: always
  (unless committed? (undo-hold!)))  ; the transaction: only if it did not happen
```

Releasing what this process holds is unconditional — the flow is dead and
nothing else will ever give it back. **Undoing the transaction is right
only where the transaction did not happen**: run against a flow that
committed, it reverses work that succeeded, which is the same damage
`'gone` would have done arriving by another route. The library does not
make the split itself, because only the application knows which of its
own effects are which.

#### `committed?` is one-sided

`#t` is never wrong: the mark is set only
by a commit thunk that returned, and it is never cleared. `#f` can be one
instant stale — a kill landing between that return and the mark being set
passes `#f` for a transaction that did happen, and the window is the
return itself, which cannot be closed from another process. So `#f` means
*no witness*, not *proof it did not commit*. An undo that is destructive
when wrong must be idempotent, or consult the authoritative store, rather
than rest on this flag alone.

A hook that cannot accept one argument is **rejected at
`conversation-start!`**, with an `assertion-violation` in the caller. It
is checked there because it is *called* inside a guard that swallows
everything — the watchdog must survive a bad hook — so a hook of the
wrong shape would otherwise fail silently: the compensation never runs,
whatever the flow held stays held, and nothing anywhere says why.
Accepting one argument, not exactly one: a variadic hook and one with
optionals are both fine.

### The token names the reply being answered

A conversation hands one
out with every reply and consumes it the moment a request is accepted.
Send it to the client alongside the reply and take it back with the next
request — it is a short hex string, so it crosses JSON, a query string
and a node link unchanged. It is drawn from the system random source,
not counted up: a token a caller can guess is a token it can queue
ahead of, which is the whole mechanism gone.

Without it, the only thing separating "the answer to what I just said"
from "a duplicate of what you said before" is arrival order, and arrival
order is not causality. A double click, a client retry or a second front
end sends two requests against the *same* reply; if the duplicate is
delayed — a slower path, a forwarding hop, a busy scheduler — it arrives
after the flow has moved on and would be taken as the next step. The
flow then advances on input written before the reply it claims to
answer: a confirmation skipped, or one stage's payload applied to the
next. With the token the duplicate is refused however it is scheduled,
and a genuine answer is accepted however late it arrives.

#### A repeat is answered, not refused

Presenting the token that was
just spent hands back the reply it produced, together with the token
that came with it — exactly what the original caller received. A double
click, a client retry and a lost response therefore all end the same
way: the step ran once, and everyone who asked gets the answer to what
they asked. This is what an idempotency key buys in a payment API.

Only the *last* step is replayable — one reply is retained, not a
history. An older token is `'stale`: its answer is long superseded, and
keeping every step's reply would be unbounded memory for a case nobody
can act on anyway.

`'stale` means the token belongs to no step this conversation can still
answer. The request was **not** applied and will not be — a fact about
this conversation, unlike `'unreachable`. It says nothing about whether
the request it duplicates succeeded. Read the current state; do not
resubmit, and note there is no valid token to resubmit with.

### Completion lingers, then leaves a record

After the flow
returns, the conversation stays reachable for one more TTL and can still
replay that final reply. Exiting at once was a live double-charge path:
the client's final confirm commits, the reply is lost, the retry meets a
process that no longer exists and is told `'gone` — which this library
documents as *the transaction rolled back*. The client believes the
transfer failed and performs it again.

The linger holds a whole process, so it cannot be long. A tombstone is
an id and an outcome, so it can be: past the linger a completed
conversation answers `'settled` rather than `'gone` — the answer is no
longer available, but *it committed* is what a reconciling caller needs,
and it is the opposite of what `'gone` would have said. Bounded by age
and count through `conversation-set-limits!`, because an unbounded
record of everything that ever finished is a leak with a long fuse; past
either bound the entry is dropped — and the answer becomes `'unknown`
rather than a `'gone` it can no longer support. Size both to cover the
retry window your clients actually use; past it, callers get an honest
"I cannot say" instead of a confident wrong answer.

The conversation never touches the connection: pool workers stay the
protocol adapters, parking until the flow replies, so the pool's
stuck-killer and failure hook keep protecting every round.

### The `gone` guarantee — and what it is *not*

For a flow holding a
database transaction, a death that ran the flow's winders before its
commit is the rollback guarantee: dead process = dropped connection =
the database itself rolled back, so `'gone` *proves* nothing committed,
and it is the one status a client may retry on.

It does not follow from death as such. "Death for any reason returns
`'gone`" was the earlier reading, and each way of dying that it covered
by accident made it false: normal completion (that is `'done`, then
`'settled`), a kill from outside, a step the watchdog stopped, a link
cascade, an after-thunk raising on the way out of a successful commit.
Each of those answers `'unknown`, and each of them was a double charge
while it answered `'gone`. Retry on `'gone`; on `'unknown` and
`'unreachable`, reconcile. Combined with the failure hook's
`crash`/`stuck` codes, that is the full remote transaction ring — the
difference being that the ring now carries "I cannot say" as a
first-class answer rather than guessing.

### A host that gives up does not end the conversation

The worker pool kills a handler it has declared stuck, and gives up on a
task whose retries are spent. Either way the process that called `run!`
goes away — and **the conversation does not**. It is spawned unlinked, so
it keeps running, keeps holding whatever it holds, and may still commit.
That is the intended semantics, not a missing feature.

Reaping it along with the handler would manufacture the one outcome this
whole mechanism exists to prevent: a transaction that **may already have
committed**, destroyed on the way out and reported as though it never
happened. The kill would land at an arbitrary instant, which is precisely
the instant at which nobody can say which side of the commit it fell on.

What bounds it instead:

- **The conversation's own ttl.** It ends whether or not anyone is still
  asking, so nothing runs forever on the strength of a caller that left.
- **`on-killed`.** When the ttl does end it, the caller's own
  compensation runs, with `committed?` saying which way to go.
- **`prepare!` for the case that looks worst** — the client got a bare
  500 and holds no id. Take the id *before* anything can have an effect
  and persist it; the conversation is then reachable by id no matter what
  became of the process that started it.

### Refusing rather than going quiet

An owner spawns a process per forwarded resume or peek, and hosts a bounded
number of them (256 by default, `conv-set-forward-limit!`). Past that it
**refuses**, and the asker gets `'overloaded`.

The refusal is the point rather than a consequence of running out. Without
it, forwards queue behind each other on the owner's single scheduler thread
until the asker's deadline expires — and the asker is told `'unreachable`,
which says the link is broken when the truth is that the owner is busy, and
sends the caller to reconcile a conversation nobody had begun. `'overloaded`
says the owner declined before touching anything: retry later, reconcile
nothing.

**A slot is not held for ever.** A worker whose asker gave up keeps running
— nothing tells the owner the answer is no longer wanted — so each one is
given a hold (`conv-set-forward-hold-ms!`, 300000 by default) after which
the owner takes its slot back. That hold is the owner's slot lifetime, a
different quantity from the asker's forwarding deadline even though they
default to the same number: pass a longer call-level ttl and the owner may
still give up first.

What is reclaimed is the waiting, not the work. The forwarded worker is a
courier; ending it leaves the conversation itself untouched, so the step
finishes and the flow parks as it would have. The asker sees `'unreachable`,
which already means the request may have been acted on — reconcile rather
than retry. A rising `reaped` count is the signal that capacity is going to
work nobody is waiting for — read it as pressure rather than as a tally, since
a worker that finishes at the instant its hold expires is counted too.

Each admitted forward costs the owner two processes, the worker and the one
watching its deadline, so a node at the default limit carries 512 of them
rather than 256.

`conversation-forward-stats` reads the forwarding side: `attempted`,
`refused`, `completed`, `unreachable`, `reaped`, the live `hosted` count and
the `limit`. The counters are monotonic and reading does not reset them.

**They are two ledgers in one alist.** `attempted`, `refused`, `completed`
and `unreachable` count what this node asked of others; `hosted` and
`reaped` count what others asked of it. Mixing `hosted` into an equation
with the asking counts compares two different populations — and on a single
node they coincide, which is exactly what a local test sees, so a local test
cannot notice the difference.

**Do not expect any of them to balance.** Even within the asking side an
attempt need not reach an outcome: an asker killed while waiting is neither
still waiting nor ever recorded as completed, refused or unreachable, and
that shortfall grows with every such death. Read these as rates and ratios,
not as a conservation law.

> The node layer has its own unrelated `'overload`, answered when it sheds a
> cross-node call. The spellings differ deliberately: `'overloaded` is a
> conversation status, `'overload` is an rcall error.

### Taking a node out of rotation

Two questions, both answered locally — nothing here crosses a link or changes
a frame, so a mesh can run any mixture of versions while you use them.

- `(conversation-census)` → alist of `running`, `parked`, `lingering` and
  `total`. `running` is executing a step, `parked` is waiting in `suspend!`
  for the next request, and `lingering` is the window after the flow
  returned where its final reply can still be replayed. A lingering
  conversation still holds its name, so **a drain is not finished while any
  remain**.
- `(conversation-quiesce! #t)` stops this node accepting **new**
  conversations; `(conversation-quiesce! #f)` puts it back. It is a switch,
  not a ratchet.
- `(conversation-quiescing?)` → boolean.

`conversation-run!` raises `#(conversation-quiescing <node>)` while quiescing,
before the handle is claimed — so a refused run leaves it still prepared and
runnable elsewhere. It raises rather than returning a status because a caller
who ignored a status would carry on as though a conversation had started.

**What quiesce does not stop is the point.** Resuming or peeking a
conversation that is already here keeps working, including a resume forwarded
from another node — those are how the conversations you are waiting for make
progress, and a node that refused them could never finish draining.
`prepare!` keeps working too; it has no effect to withhold, and the refusal
lands at `run!`.

Draining is a question you ask rather than a fourth call: quiescing, and a
census `total` of zero.

```scheme
(conversation-quiesce! #t)
(let wait ()
  (unless (zero? (cdr (assq 'total (conversation-census))))
    (sleep-ms 200)
    (wait)))
```

Three words, three different situations, and they are worth keeping apart:
`'unreachable` means nothing definite came back and the request may still
have been acted on — reconcile. `'overloaded` means the owner is busy right
now — retry shortly, here. Quiescing means this node is going away — go
somewhere else, and do not wait for it.

### Upgrading a mesh has a direction

An owner that refuses answers with a frame older code does not know. A new
entry node reads it and reports `'overloaded`. An old one matches nothing,
waits out its deadline, reports `'unreachable`, and leaves the frame in the
asking process's mailbox where nothing collects it — one per refusal, in a
process that is often long-lived.

**Upgrade entry nodes first — but know what that buys.** A node upgraded as
an entry becomes a refusing *owner* at the same instant. On a symmetric
deployment, where any node may be an entry, that is every node: upgrading A
closes A's asking side and opens A's refusing side together, and a
not-yet-upgraded B forwarding to A meets exactly the frame it cannot read.

So on a symmetric mesh no ordering removes the window; entry-first only
shrinks it, and finishing quickly matters more than the sequence. Where the
roles are separate — dedicated entry nodes in front of dedicated owners —
upgrading the front rank first does close it completely. Which shape your
deployment has decides whether the order is a fix or a mitigation.

**Separately, and not fixed by upgrade order:** a node already deployed
under a name containing `~` is mis-routing *today*. The id parser has
always split at the first one, so every clustered id that node minted
already resolves to the wrong owner. The name is now refused at startup,
so such a node will not start until renamed — rename it before upgrading,
and expect the ids it minted under the old name to be unreachable.

### What the cluster has to look like

Three constraints on the deployment, all of which are contracts rather
than observations about the current implementation.

**Forwarding needs a direct link from the entry node to the owner — in
practice, a full mesh.** A resume that lands on the wrong node is forwarded
one hop or not at all; there is no relay routing, by design. On a topology
that is not fully connected — a star, or a mesh with a link down — nothing
fails at startup. The symptom is that every resume for a conversation owned
by an unreachable node answers `'unreachable` for as long as the gap lasts,
and neither the entry node nor the caller can tell that from an owner that
is simply down.

Relaying is left out because routing is a different shape of problem from
this library's: it needs a view of the topology, a policy for choosing among
paths, and answers for loops and for a relay that dies mid-hop. The
distribution layer is where those would belong if they are ever wanted.

One hop is also what the cost is: a forwarded resume or peek is one
request and one reply across the link, so it completes in one round trip
and no more. Measured on an intercontinental link of about 199 ms RTT,
that is what both cost — and a refusal costs the same, so `'overloaded`
comes back within a round trip rather than at a timeout. That matters
more at real latency than at loopback: it is what keeps "busy" and
"unreachable" distinguishable by how fast they answer, instead of both
arriving as a wait that ran out.

**A node accepts peers on 127.0.0.1 unless told otherwise.**
`(node-start! name secret [port [host]])` binds the loopback address when
the fourth argument is omitted, which is the right default for a single
machine and silently wrong for a mesh spanning several: the listener
starts, the node looks healthy, and peers on other machines simply cannot
reach it. Nothing reports a misconfiguration — the first symptom is that
every cross-machine forward times out, which reads exactly like a peer
that is down. Pass the address the other nodes will dial (`"0.0.0.0"`, or
the interface the private network is on).

**The node name is part of every id that node mints**, which makes it a
durable identifier rather than a label — and it may not contain `~`,
which is what separates the node name from the id body; `node-start!`
refuses one that does. Rename a node and every id it owns
is orphaned: a resume carrying the old name is forwarded to a node nobody
answers to and comes back `'unreachable`, while the conversations are still
parked on the renamed node — alive, and no longer reachable by their own
ids.

There is deliberately no alias mechanism. One would have to be consulted on
every forward, kept consistent across the cluster, and garbage-collected
when the last id bearing an old name expired, which is a naming service
rather than a feature of this library. Keep a node's name for at least as
long as the conversations it owns, and drain a node before renaming it.

### Where to use it

Critical transactional flows: payments against
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

#### Why not `parameterize`?

`make-parameter` is the obvious-looking alternative and it does **not** work
here: it gives no isolation between concurrent requests.

Chez implements `parameterize` by swapping a *global* cell and registering a
winder to swap it back — printing one shows exactly that:

```
#[critical-winder #<procedure swap> #<procedure swap> ()]
```

The scheduler saves and restores each process's winder list across a context
switch but never runs the hooks. That is right for `dynamic-wind`, whose
after-thunk must not fire merely because a process yielded, and fatal for
`parameterize`, whose entire mechanism *is* that hook. The cell belongs to
whichever process wrote it last.

Three processes, each setting or reading one parameter across a yield:

| process | expected | actual |
|---|---|---|
| set `alice`, yield, read | `alice` | **`bob`** |
| set `bob`, yield, read | `bob` | **`nobody`** |
| never parameterized, read | `nobody` | **`bob`** |

Note the second row: a process cannot read back *its own* binding. And the
third: a process that never touched the parameter sees another's value. So it
is not only a leak between requests — the binding means nothing at all once
anything yields, and every handler yields, because any I/O does.

There is no clean fix available. Running the winders on every switch would
break `dynamic-wind`; saving and restoring the values instead would require
enumerating every live parameter, which Chez does not expose. Use
`req-set-local!` for request-scoped state, or pass the value as an argument.

Nothing warns you if you get this wrong. A guard that reads the wrong identity
usually *denies*, so the symptom is an occasional unexplained `401` under
concurrency.

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

## RSA Keys and Signatures

`(igropyr rsa)` signs and verifies **arbitrary bytes** with RSA-SHA256
(PKCS#1 v1.5 — what JOSE calls RS256 and what `openssl dgst -sha256
-sign` produces). It knows about keys, byte strings and signatures, and
nothing about tokens or claims.

```scheme
(import (igropyr rsa))
(define k   (rsa-load-private-key "/etc/keys/signing.pem"))
(define sig (rsa-sign-sha256 k (string->utf8 "any bytes at all")))

(define pub (rsa-load-public-key "/etc/keys/signing.pub"))   ; or a cert
(rsa-verify-sha256 pub (string->utf8 "any bytes at all") sig)  ; => #t
```

Loading: `rsa-private-key-from-pem` / `rsa-public-key-from-pem` from PEM
text or bytes, `rsa-public-key-from-modulus` for formats that publish the
raw magnitudes, and `rsa-load-private-key` / `rsa-load-public-key` from a
path. Inspection: `rsa-key?`, `rsa-key-private?`, `rsa-key-bits`,
`rsa-key-modulus`, `rsa-key-exponent`, `rsa-key-consistency-checked`.
Release with `rsa-key-free!` when rotating; a key held for the life of
the process needs none.

`rsa-verify-sha256` answers `#t` or `#f` and never raises on a bad
signature — a signature is attacker-supplied, so "no" is an answer, not
an error. It *does* raise when the machine could not perform the check at
all, because "this signature is forged" and "this host cannot check
signatures" must not arrive as the same value.

### A key that loaded is not a key that was checked

A private key can be well-encoded and still not self-consistent — a PEM
whose `d`/`p`/`q` do not match `n`/`e` decodes fine and cannot sign
verifiably. Loading checks for that where it can, and
`rsa-key-consistency-checked` reports what the check actually
established:

| value | meaning |
|---|---|
| `'checked` | the check ran and passed |
| `'unavailable` | this libcrypto has no `EVP_PKEY_check` (before 1.1.1, and LibreSSL): nothing was judged |
| `'not-implemented` | the provider declined to judge the key: nothing was judged |
| `'not-applicable` | a public key, which has no parameters to cross-check |

A key that is judged *bad* is refused at load, so these four are all
"loaded". The two non-checked answers are deliberate — refusing to load
on an older libcrypto would be a much larger change than this check is
worth, and a provider that cannot judge must not thereby reject every key
— but they were previously indistinguishable from a pass. Code that must
not run on an unverified key asks for `'checked`; code that only wants a
key ignores this, exactly as before.

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

### Business Counters

The same collector holds app-defined counters — register nothing, just count:

```scheme
(metrics-count! metrics "iter_lookup_outcome_total" '(("outcome" . "hit")))
(metrics-count! metrics "jobs_done_total" '() 5)   ; labels optional, +n form
;; -> iter_lookup_outcome_total{outcome="hit"} 1
;;    jobs_done_total 5
```

Each name renders as its own `# TYPE ... counter` family. Input is validated
at the call site (the cast is fire-and-forget, so a bad name or non-number
increment must fail loudly here rather than crash the shared collector);
labels are sorted so two orderings of one label set stay a single series;
the `igropyr_` prefix is reserved for the built-in families.

### JSON and S-Expression Snapshots

The collector is format-agnostic — it collects, and it serializes three
ways off the same numbers. The reader (Prometheus, a browser, a Scheme or
Goeteia program) is not its concern:

```scheme
(app-get app "/metrics"     (metrics-endpoint metrics srv))  ; Prometheus text
(app-get app "/stats.json"  (metrics-json metrics srv))      ; JSON snapshot
(app-get app "/stats.sexpr" (metrics-sexpr metrics srv))     ; sexpr snapshot
```

- `(metrics-json collector server)` / `(metrics-sexpr collector server)` →
  handler — the whole snapshot (uptime, connections, pool, per-status
  counts, duration sum/count, every counter family, and the cluster view)
  as JSON or as one s-expression datum.
- `(metrics-snapshot collector server)` → the same datum as a Scheme value
  for in-process callers.

JSON and sexpr share one snapshot builder, so the two encodings can never
drift.

### Browser Dashboard

`(igropyr dashboard)` is the presentation layer over the metrics signal —
kept separate so the page never couples to the collector. It ships a
self-contained browser dashboard (inline CSS/JS, no external assets, works
air-gapped: requests/s and latency sparklines computed from snapshot
deltas, connection and worker-pool gauges, per-status counts, every
counter family, refreshed every 2 s) and a turnkey admin listener.

```scheme
(import (igropyr dashboard))

;; mount onto an app you already have (guard it yourself):
(mount-dashboard! app metrics srv)     ; GET /dash , /dash/data[.sexpr]

;; or a DEDICATED admin port, 127.0.0.1 by DEFAULT so the monitoring
;; surface is not reachable off-box unless you widen it:
(define admin (admin-listen metrics srv `((port . 9090))))
(admin-listen metrics srv `((host . "10.0.0.5") (port . 9090)
                            (auth . ,(token-guard verify))))  ; internal + auth
```

- `(mount-dashboard! app collector server [opts])` — register the data
  routes (JSON + sexpr) and the page onto `app`. `(prefix . "/dash")` sets
  the route root; `(html . X)` makes the front-end swappable: the built-in
  page (default), `#f` for data-only, an inline HTML string, or a
  `(lambda (req res) ...)` handler (serve your own file via `send-file!`,
  or a [Goeteia](https://goeteia.dev) app reading the sexpr endpoint).
- `(admin-listen collector server [opts])` → server — a dedicated listener
  carrying only the dashboard, **loopback by default**. `(host . ...)`,
  `(port . 9090)`, `(auth . middleware)` applied first, `(prefix . "/")`,
  `(html . X)`. `http-shutdown!` it to stop.
- `(dashboard-html data-path)` → string — the built-in page pointed at a
  JSON route (a single quote in the path is rejected, not spliced).

The data routes expose operational detail; `admin-listen` defaults to
loopback for that reason. Mounting onto a public app instead, guard the
routes (an `(auth . …)`, a reverse proxy, or network policy) as you would
`/metrics`.

### Cluster View

On a node (after `node-start!`), announce the local summary once and every
peer that did the same appears in the snapshot's `cluster` member — uptime,
connections, requests, 5xx, pool — gathered over the existing node links by
`rcall`, so no peer needs to expose HTTP and there are no cross-origin
fetches:

```scheme
(metrics-announce! metrics srv)   ; register the summary for peers to rcall
```

Each peer call is bounded (1 s); a peer without an announce, a timeout, or a
garbled reply renders as `no data` with null fields rather than failing the
endpoint. Without `node-start!` the `cluster` member is null and the
dashboard's cluster table stays hidden.

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
(import (igropyr http-client) (igropyr tls))
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

**A generic connector for other protocols.** `(igropyr tls)` also exports `tls-establish!`, the same handshake as a bare byte-codec connector, not tied to HTTP. It performs the same verification (peer chain, hostname/IP, TLS 1.2 minimum, system trust store) and raises the neutral `#(tls-error "tls: …")` on failure — the https connector that `tls-enable!` installs is a thin re-tag of it. Other clients accept it directly: the PostgreSQL client takes it as its `'tls` option (see [PostgreSQL](#postgresql)). The MySQL client, by contrast, has no TLS support yet and **rejects** a `'tls` option loudly rather than silently sending plaintext.

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

### PostgreSQL

The PostgreSQL client speaks protocol 3.0 and follows the same design as MySQL: one green process per connection, queries synchronous (the caller parks until the reply), the PostgreSQL request-response protocol serialized through the connection's mailbox. It shares the same `(igropyr connpool)` connection-pool engine, so pooling, transactions and self-healing behave identically.

#### Basic Usage

```scheme
(import (igropyr postgresql))

(define db (postgresql-connect "127.0.0.1" 5432 "user" "password" "mydb"))

(postgresql-query db "SELECT id, name FROM users")
;; -> #(rows ("id" "name") (("1" "Alice") ("2" "Bob")))

(postgresql-query db "INSERT INTO users (name) VALUES ('Eve')")
;; -> #(ok 1)    ; affected rows

(postgresql-close! db)
```

Return values:

- **SELECT**: `#(rows ,column-names ,rows)` where `rows` is a list of lists.
- **INSERT/UPDATE/DELETE**: `#(ok ,affected)`.
- **Values**: Strings (the wire text format). `NULL` → `#f`. The connection pins `client_encoding` to `UTF8` at startup, so text is always UTF-8 on the wire regardless of the database encoding.

The database name defaults to the user name when omitted. An options alist (`'((tls . ...) (allow-cleartext-auth . #t))`) may follow the database argument.

#### Parameterized Queries

`postgresql-execute` runs one statement over the extended query protocol (Parse/Bind/Execute). Parameters are sent out-of-band as `$1..$n` values, never spliced into the SQL text, so no quoting or escaping is needed and **injection through a value is impossible** — prefer it over string concatenation whenever a statement takes runtime values:

```scheme
(postgresql-execute db "SELECT name FROM users WHERE id = $1" 2)
;; -> #(rows ("name") (("Bob")))

(postgresql-execute db "INSERT INTO users (name, note) VALUES ($1, $2)"
                    "Eve" #f)
;; -> #(ok 1)      ; #f binds SQL NULL
```

- Parameters may be strings, numbers, `#f` (SQL `NULL`) or bytevectors (raw text-format bytes).
- Unlike `postgresql-query`, it accepts **exactly one** statement, and at most **65535** parameters.
- Non-finite floats are sent as `Infinity` / `-Infinity` / `NaN`.

The result shapes are the same as `postgresql-query` (`#(rows ...)` / `#(ok ...)`).

#### Errors

Errors raise `#(postgresql-error ,tag ,message)` in the caller, where `tag` is one of exactly three shapes:

- **a 5-character SQLSTATE string** — a server-side SQL error (constraint violation, syntax error, …). The connection stays usable.
- **`'transport`** — a connection or framing failure. The connection is torn down (and rebuilt by a pool).
- **`'timeout`** — the caller stopped waiting (query timeout or pool checkout timeout). A timed-out **statement may still execute** on the server: its outcome is unknown, so do **not** blindly retry a non-idempotent statement.

A lone `postgresql-connect` handle does **not** survive a transport failure: the handle is dead and later queries time out. Use `postgresql-pool` for automatic rebuild and reconnection.

#### Authentication

The client authenticates with **SCRAM-SHA-256** (RFC 7677, the PostgreSQL default since v10). MD5 is not implemented. Cleartext password auth is **refused by default**: the method is chosen by the server — i.e. by anyone who can intercept a plaintext socket — so honoring it silently would let an active attacker downgrade past SCRAM and read the password. Opt in only over a trusted local socket:

```scheme
(postgresql-connect host port user password database
  '((allow-cleartext-auth . #t)))
```

SASLprep normalization is not implemented (its Unicode tables would dwarf the driver), so passwords outside **printable ASCII** — non-ASCII, or the control characters SASLprep prohibits — are rejected with a clear error: in the caller (`postgresql-connect`/`postgresql-pool` raise an assertion up front) when SCRAM is the only possible auth path, and during the exchange otherwise, instead of failing with a baffling `28P01`. Printable-ASCII passwords are exact — SASLprep leaves them unchanged.

#### TLS

Pass the byte-codec connector from `(igropyr tls)` as the `'tls` option and the connection is upgraded via `SSLRequest` before the startup message, with full certificate + hostname/IP verification against the system trust store (`SSL_CERT_FILE` / `SSL_CERT_DIR` apply):

```scheme
(import (igropyr postgresql) (igropyr tls))

(postgresql-connect host 5432 user password "mydb"
                    (list (cons 'tls tls-establish!)))
```

The connector travels through the options alist, so this library never imports `(igropyr tls)` and stays free of the OpenSSL dependency unless the application opts in. If the server refuses TLS the connection **fails** — there is no silent plaintext fallback. Over TLS, SCRAM **channel binding** is automatic: when the server offers `SCRAM-SHA-256-PLUS` the client selects it and binds the authentication to this TLS channel's server certificate (RFC 5929 `tls-server-end-point`), so even a relay MITM holding a trusted certificate cannot forward the exchange. Without `'tls` the client speaks plaintext: an on-path attacker can read query text and results regardless of the auth method, so run plaintext connections only over a trusted network or a local socket.

#### Connection Pool and Transactions

For applications with many concurrent workers, use `postgresql-pool` instead of a single connection:

```scheme
(define pool (postgresql-pool 8 "127.0.0.1" 5432 "user" "password" "mydb"))
;; Creates a pool of 8 connections; queries and executes route to an
;; idle one, replies flow straight back to the caller, dead connections
;; are replaced automatically.

(postgresql-query pool "SELECT * FROM users")
```

`postgresql-transaction` borrows one whole connection from the pool for the extent of a procedure: `BEGIN` first, then `COMMIT` if the procedure returns, or `ROLLBACK` if it escapes. `call-with-postgresql-connection` borrows a connection without opening a transaction. Both guarantee the connection is returned — even if the body raises or the worker is killed mid-transaction, the pool's monitor reclaims and rebuilds it, so a half-open transaction is never handed to the next caller:

```scheme
(postgresql-transaction pool
  (lambda (db)
    (postgresql-execute db "UPDATE accounts SET bal = bal - $1 WHERE id = $2"
                        100 from-id)
    (postgresql-execute db "UPDATE accounts SET bal = bal + $1 WHERE id = $2"
                        100 to-id)))
;; COMMIT on normal return, ROLLBACK on any escape

(call-with-postgresql-connection pool
  (lambda (db)
    (postgresql-query db "SET application_name = 'report'")
    (postgresql-query db "SELECT * FROM big_report")))
```

#### Limitations

- `client_encoding` is pinned to `UTF8` and cannot be changed.
- `COPY FROM STDIN` is refused via `CopyFail` (it surfaces as a server error); `COPY TO STDOUT` raises `0A000`.

### The `(igropyr connpool)` Engine

This subsection is for authors building a **third** SQL driver; applications never touch it directly.

`(igropyr mysql)`, `(igropyr postgresql)` and `(igropyr qjspool)` sit on one shared engine, `(igropyr connpool)`. It owns the whole pool architecture — a fixed pool of connections behind a dispatcher, whole-connection leases, and monitor-based crash reclaim — while staying **protocol-blind**: the wire protocol, authentication and result parsing stay in each driver. Keeping it a single copy means a fix to a subtle race (checkout-cancel, reclaim of a borrower killed mid-lease, adoption of a worker that finished connecting after its pool is gone, refusing to re-lend a connection already on its way out) can never land in one driver but not the others.

It was written for the two SQL drivers and was called `sqlpool`. What it models is both narrower than SQL and wider: a scarce **exclusive** resource whose work happens on the far side of a socket, borrowed for the length of one request. Adding the render pool as a third driver needed exactly one generalization — the deadlines moved from module constants into the per-driver config, because a minute is right for a database and wrong for a render — and nothing else.

Exports:

- `make-connpool-cfg` — build the per-driver config record (once per driver): the driver's error *values* for lost / closed / query-timeout / checkout-timeout events, a predicate that recognizes an error reply, the `BEGIN` statement (`"BEGIN"` / `"START TRANSACTION"`), and optionally the query and checkout deadlines (both default to 60 s).
- `connpool-loop` — the dispatcher loop: `(connpool-loop n spawn-conn! cfg)`, a fixed pool of `n` connection workers.
- `connpool-call` — run one request on a connection or a pool.
- `sql-transaction` / `connpool-lease` — borrow a whole connection (with or without a transaction), with guaranteed return.
- `connpool-close!` — close a pool or a lone connection.
- `connpool-check-size!` — reject a bad pool size where the caller wrote it, rather than inside a pool that then answers nothing.
- `connpool-drain-stale!` / `connpool-stats` — recycle idle connections; read pool counters.
- `connpool-cfg-set-observer!` / `connpool-observer-failures` — see *Watching every request* below.

Each driver's connection process must speak a small message contract:

- `#(pool-request ,req ,ref ,from)` — do `req`, then reply `#(pool-reply ,ref ,r)` to `from`.
- `#(pool-adopt)` / `#(pool-quit)` — adoption handshake / shutdown.
- `#(pool-idle ,self ,ref)` — sent to its pool after each finished request, naming the one it just finished, so a late idle cannot free a connection that has since been given something else.
- `#(pool-conn-dead ,self)` — sent to its pool *before* it replies a transport error.
- `#(pool-up ,ref ,self ,status)` — reported by a connecting worker.
- `#(pool-stats ,ref ,from)` — answer `#(pool-stats-reply ,ref #f)`; answering is what stops the request sitting in the mailbox forever.

A connection must also answer `pool-quit` and `pool-request-cancel` **while it is waiting** for the far side. A receive that matches only the socket strands both: the pool cannot reclaim it and the caller cannot abandon it.

Query and checkout both time out at 60 s. Leases are per-checkout records (keyed by connection, carrying the borrower, its monitor and the checkout ref), so one borrower holding several leases never clobbers its own bookkeeping; a borrower killed mid-transaction is reclaimed by the pool's monitor (the actor's `@kill` discards `dynamic-wind` winders, so no checkin ever runs). Closing a pool quits leased connections immediately — a transaction still in flight on one times out on its next statement, so close a pool only after its borrowers are done.

### What a lease guarantees

`connpool-lease` hands one whole connection to `proc` for its extent. The
promises are about the **pool**, and stop there:

1. It never re-points a handle. For the extent of `proc` the handle
   denotes the same connection process — no sibling is swapped in, not
   even an idle one.
2. Once that process is gone, **the next call on the old handle** raises
   the driver's lost-error. Nothing watches the connection on `proc`'s
   behalf, so a `proc` that simply stops calling returns normally: the
   failure is delivered to the next call, not announced to the borrower.
3. A dead worker's handle is never given to its replacement — **provided
   the `spawn-conn!` you supplied returns a process id it has never
   returned before.** That is the one clause here guaranteed by the
   caller rather than by the pool: the message contract above does not
   demand it, the pool does not check it, and a `spawn-conn!` that
   recycled identities would break this with nothing noticing. The
   bundled drivers satisfy it because each call is a fresh actor spawn.
   (Connections themselves *are* reused across leases by later
   borrowers; what is not reused is the identity of one that died.)

**One peer session for the whole lease — the thing callers actually want
— follows from (1) only if the driver's worker does not re-dial inside
itself.** That is a condition on the driver, not a promise made here, and
the pool can neither see nor report a breach of it: the process id is
unchanged, so from where the pool stands nothing happened. Cite the
condition along with the guarantee.

Three things it does **not** say:

- Nothing about what a driver does inside its worker (above).
- Nothing about the peer's own continuity: a server that holds the socket
  open while resetting what the session contains is outside this model.
- A live handle is not an open transaction. If the borrower is killed its
  winders are discarded and no check-in is sent; what keeps a half-open
  transaction away from the next borrower is the pool's monitor
  reclaiming and rebuilding on `DOWN`, not the lease.

And the handle is a **capability**: exclusivity is the pool declining to
lend the connection to anyone else, not a restriction on who may send to
that worker. A handle that escapes `proc` — passed to another process, or
kept past the lease — lets those calls land in the same session.
Comparing handles with `eq?` establishes none of this: a worker that
re-dialled its own socket is `eq?` to itself while the session behind it
changed.

### Watching every request

An application that wraps its own query function sees its own statements
and nothing else — the `BEGIN`, the `COMMIT` and the `ROLLBACK` are
issued inside the engine. A trace built that way can show three
statements in a row and still not distinguish one transaction from three,
and cannot show that no `COMMIT` slipped in between, which is usually the
only reason such a trace exists.

Observing at dispatch puts all of them in one stream, already in order:

```scheme
(mysql-observe! (lambda (conn sql) (trace! conn sql)))
```

- `(connpool-cfg-set-observer! cfg proc)` — the primitive, for a driver
  author. `proc` is `(conn sql)` and is called **when the request is
  dispatched**, once; the outcome is the caller's own return value and is
  deliberately not repeated here. `#f` clears it.
- `(mysql-observe! proc)` — the same for `(igropyr mysql)`. Only this
  driver has one because only this driver was asked for one; the
  primitive is in the engine, so any other driver costs one line.
- `(connpool-observer-failures)` — how many times an observer raised. It
  is guarded at every call site, so a raise is counted and the statement
  proceeds; this counter exists because there is no logging here and a
  silently failing observer would otherwise look exactly like an idle
  one.

Four boundaries, each of which a reader will otherwise assume wrongly:

- **Scope is one driver module, not one pool.** The config holding the
  observer is built once per driver, so two pools opened through the same
  driver report to the same observer, with nothing but the connection to
  tell them apart. Install before there is traffic.
- **It runs in the borrower's process**, which is why it is safe to
  expose: a slow observer delays only the caller that provoked it and
  cannot stall the pool.
- **It is called on the exception path too.** The `ROLLBACK` is issued
  from a `dynamic-wind` after-thunk, so an observer will find itself
  running during an unwind, usually with an exception already in flight.
  Raising there is a mistake.
- **A killed borrower emits no `ROLLBACK`.** That rollback lives in a
  winder, and a kill discards winders, so that path produces *no event at
  all*. The absence of a rollback event therefore says neither "the
  transaction is still open" nor "it committed" — what protects the next
  borrower is the pool's monitor rebuilding the connection. Expect no
  event and a rebuilt connection.

An event is **evidence, not authority**. It reports what was dispatched;
an observer is not a participant in the transaction it is watching.

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
## Durable Writes

`(igropyr durable)` writes a file so that a crash cannot leave a reader looking at half of it, and so that what was written is still there after the machine loses power. It is a small library and the interesting part is not its API but its **order of operations**.

### The sequence is the contract

```
write body -> close it -> fsync body -> rename -> fsync PARENT DIRECTORY
```

The body is flushed through a descriptor opened for that purpose, after the writing port has been closed — a Chez port does not hand out its file descriptor, and `fsync` wants a descriptor for the file rather than a writable channel to it. One consequence is worth knowing: the temporary path is resolved a second time, so anything able to write that directory could swap what the name refers to in between. Closing that would need `O_NOFOLLOW`/`openat` or a flush on the writing descriptor itself, neither of which is reachable from here; it is recorded as a known limit rather than approximated.

Writing to a temporary file and renaming it into place is the well-known half. The half that gets left out is the last step: a rename is a change to a *directory*, and a directory is a file that has to be flushed like any other. Leave it out and the code still passes every test that writes a file and reads it back, on every machine that does not lose power during the test — which is why it is the step that goes missing.

### API

- `(durable-write-file! path bytes)` → path — write `bytes` (a bytevector) to `path` through a temporary file, a rename, and a directory flush. The target either holds the old contents or the new ones; a reader never sees a partial file
- `(durable-dir-ensure! path)` → path — create the directory if it is not there and flush its parent. A second call on an existing directory does no writing at all. It makes **its own** creation durable and does not underwrite an unflushed one by another process: if someone else created the directory a moment ago without flushing, this call finds it present and returns, and a crash can still take it away. Losing a `mkdir` race is not an error — the directory is there, which is what was asked
- `(fs-trace-hook-set! hook)` → void — install a procedure `(hook op path outcome)` called around every filesystem operation, or `#f` to remove it
- `(with-fs-trace hook thunk)` → any — run `thunk` with `hook` installed, restoring the previous hook on the way out, including when `thunk` raises

### Errors

Two kinds, raised differently on purpose:

- **A mistake in the calling program** — a path that cannot name a file, a hook that is not a procedure — raises an `assertion-violation`, like the other startup checks in this framework.
- **The world refusing** — a write, a rename or a flush that fails — raises a three-element tagged vector, the shape the other libraries here raise:

```scheme
(guard (e ((durable-error? e)
           (log-error (durable-error-op e) (durable-error-path e))))
  (durable-write-file! "state.json" bytes))
```

- `(durable-error? x)` → boolean
- `(durable-error-op e)` → symbol — which step gave up
- `(durable-error-path e)` → string — the path that step was working on

**The arity and field order are part of the interface.** The predicate checks the length, and adding a field is a breaking change to be announced rather than a compatible addition. A sibling of this vector elsewhere in the framework once grew from two fields to three without changing its name, and callers matching on `vector-length` failed silently against the new one.

**Failures from every step arrive in this shape**, including the steps that go through Chez rather than through libc — creating the temporary file, the rename, `mkdir`. Those would otherwise raise a Chez I/O condition, a second error shape to catch, and they are reached by exactly the environmental failures that most need to stop a write: a full disk, a missing directory, permissions.

### What `op` tells you

The step names are `'write`, `'open`, `'fsync`, `'fullfsync`, `'close`, `'rename`, `'mkdir` for the temporary file and the rename, and `'dir-open`, `'dir-fsync`, `'dir-fullfsync`, `'dir-close` for the parent directory flush.

The directory flush has its own symbols because the distinction they draw is the reason the library exists:

- a failure **before** the rename leaves the target untouched and its old contents intact — safe to retry;
- a failure **flushing the directory** happens **after** the rename, so the new contents may already be visible and merely not yet durable.

Those want different handling, and a caller should not have to compare path strings to tell them apart. **The set is not closed**: a step added later brings a symbol with it, so match with a fallback rather than exhaustively.

`op` is for deciding what to do next. It is **not** a verdict on durability — nothing in this library can give one, for the reason in the next section.

### What cannot be checked from inside the process

Whether any of this reached the medium. `fsync` returning zero says the kernel believes it handed the data to the device; a device with a volatile write cache can say so and lose it. On macOS `F_FULLFSYNC` asks for more than `fsync` does, which is why it is issued there — and no other platform defines it.

So the tests around this library assert the **call sequence** and the **error behaviour**, and claim nothing about durability itself. A test that claimed otherwise would be measuring its own expectations. If you write a test for your own use of this library, assert the same kind of thing.

### It blocks the whole runtime

Every call here is a synchronous syscall, and green processes share one OS thread — so an `fsync` stops **every process in the runtime** for as long as it takes, not just the caller.

**The bound comes from the storage, not from how often you call it.** On a local disk it is milliseconds. On a network or fuse filesystem it can be seconds or longer, and an operation that eventually returns an error can take just as long to do it. "Call this rarely" is therefore not the same as "this is cheap": rare calls on slow storage still stop the world for as long as the storage takes.

The right places are startup, configuration changes, and the handful of writes whose loss would actually matter. A hot path needs the file I/O moved off this thread entirely, which this library does not do.

### The trace hook

`fs-trace-hook-set!` installs a procedure called around every operation, which is how the ordering above is testable at all — the sequence is not visible in the resulting file.

**It is one global, set once, and deliberately not a parameter.** A parameter would offer `parameterize`, which reads as "just for this extent" and is not: green processes here share one dynamic environment, so one process's binding is visible to every other, and two concurrent users interleave. Rather than document against a form the API invites, the form is not offered.

`with-fs-trace` exists so that a caller who installs a hook has a way to take it back that survives an exception. **It is not isolation**: what it restores is that same single box, so two green processes using it at once still overwrite each other. What it buys is that a raise does not strand a hook for whatever runs next.

Two properties of hook calls worth knowing:

- **A hook that raises cannot turn one failure into two.** Every call is guarded and anything the hook raises is dropped, so reporting a failure can never replace the failure being reported.
- **A hook that blocks is not defended against.** It runs on the one OS thread, so a hook that waits stops the runtime, and no wrapper here can make that safe. That one is the caller's responsibility.

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

;; gossip: no shared store at all, membership rides the node links
(cluster-start `((name . "myapp")
                 (discover . (gossip (advertise "10.0.0.1" 4100)
                                     (seeds (b "10.0.0.2" 4100))))))

;; via Redis: self-maintaining membership through one sorted set
(cluster-start `((name . "myapp")
                 (discover . (redis ,conn "10.0.0.1" 4100))))  ; advertise self

;; or any thunk returning ((name host port) ...)
(cluster-start `((discover . ,(lambda () (my-lookup)))))
```

The **static** strategy is a fixed list.

The **gossip** strategy is fully decentralized. Each node keeps a
replicated member table and once per cycle push-pulls it with a few random
peers, over the authenticated node links themselves. Member addresses
travel inside the records, so one configured seed contact is enough to
learn (and be learned by) everyone — a seed node runs with no seeds at all.
Records carry an incarnation (the owner's boot stamp; a restart outranks
the old life) and an owner-advanced heartbeat; a record that stops
advancing ages out on every node's own clock within `ttl-ms` (~2× worst
case), so a stale echo can never resurrect a removed member.
`(fanout . 3)` sets how many peers to exchange with per cycle. There is no
from-zero discovery anywhere: like every membership system, the first
contact — the seeds here, Redis's address below — is configuration, not
magic; gossip just shrinks it to a few peer addresses and removes the
external service.

The **redis** strategy is the same expiry semantics arbitrated by a shared
store instead of peer-to-peer: each node heartbeats its own `(name host
port)` into a per-cluster sorted set scored by an expiry timestamp, prunes
expired entries, and reads the live set — a crashed node falls out after
`ttl-ms` on its own, with one key and no `SCAN`. Reach for it when you
already run Redis, or when you need a central point external tooling can
query or an operator can evict from; gossip can only age a node out.

A discovery failure (Redis down, a partition, a DNS blip) skips the round
and keeps the links already up, so it never tears the mesh down.

Options: `(name . "default")` namespaces the Redis key / gossip service;
`(interval-ms . 5000)` the discovery period; `(ttl-ms . 15000)` how long a
registration (Redis) or a member record (gossip) lives without a heartbeat
(keep it a few intervals). `(cluster-stop handle)` stops discovering;
existing links stay up.

#### Cluster size — `(max-members . N)`

`(max-members . N)` (default 256, validated as a positive fixnum) caps the
gossip view size for the gossip strategy, and the number of members dialed
per discovery cycle for the redis strategy. It doubles as the anti-flood
bound: a poisoned or runaway discovery source — a Redis key any node can
write, a gossip peer echoing a flood of records — cannot make a node open
an unbounded number of connectors. The `static` strategy is not capped;
there you list the peers explicitly.

```scheme
(cluster-start `((name . "myapp")
                 (discover . (gossip (advertise "10.0.0.1" 4100)
                                     (seeds (b "10.0.0.2" 4100))))
                 (max-members . 512)))
```

Why the cap exists, and why 256: the cluster mesh is **full** — every node
links every other node — so each node holds roughly N−1 persistent
connections and the total number of links grows O(N²). The 256 default
keeps per-node link counts sane while covering the vast majority of real
deployments. Raise it if you genuinely need a few hundred nodes, but beyond
that don't grow one flat mesh: shard the actor keyspace across several
≤256 clusters instead. igropyr's `rcall` is direct — it addresses a
process on a named node with no multi-hop routing — so a single
fully-addressable mesh caps out at a few hundred nodes by nature, and
sharding is the way past that ceiling.

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

## Vector Scoring

`(igropyr blas)` is the compute kernel for embedding search: one call fills
`scores[i] = row_i · query` over a flat row-major float32 matrix — the scan
behind RAG lookups, semantic dedup, recommendations. It uses `cblas_sgemv`
when a native BLAS loads (Accelerate on macOS, OpenBLAS on Linux/FreeBSD)
and a pure-Scheme loop otherwise, so correctness never depends on the native
library — `blas-available?` tells you which lane is active.

```scheme
(import (igropyr blas))

;; base is [n x dim] float32, row-major; query is [dim]; scores is [n]
(blas-scores! base n dim query scores)   ; scores[i] = row_i . query
(blas-available?)                        ; #t when a native BLAS backs it
```

- `(blas-scores! base n dim query scores)` — total function; base/query/
  scores are float32 bytevectors. Bounds are checked at entry (the native
  call reads raw pointers, so a short buffer must fail as a Scheme error,
  not a heap overrun).
- `(blas-available?)` → boolean — decided once at load.

Top-k, thresholds, and storage stay yours; this is the scan, at memory
bandwidth (≈0.2 ms for 5k×512 float32, ≈5 ms at 100k).

### Distributing the Load Across Nodes

A blas scan is a blocking FFI call, but distributing that blocking across
igropyr nodes to share the work raises total responsiveness. With one igropyr
node per CPU core, offloading the blas FFI to a separate thread does not lower
total response time; it only adds thread-switch overhead.

Collecting the blas requests onto another thread just moves the call to
another core: it adds a context switch and a handoff, is more likely to fully
occupy that core, and total throughput can even drop.

### BLAS Thread Count

OpenBLAS spawns its own threads per `sgemv`. With one node per core, those
threads oversubscribe the cores against the nodes, so pin the BLAS to one
thread per process. The count comes from an environment variable read when the
shared library loads, so set it before the process starts; setting it afterward
has no effect. There is no library option (Accelerate has no runtime setter in
any case).

```sh
# in the launcher (rc.d/systemd unit, deploy script), before exec
OPENBLAS_NUM_THREADS=1    # OpenBLAS (Linux/FreeBSD)
OMP_NUM_THREADS=1         # OpenBLAS built with OpenMP
VECLIB_MAXIMUM_THREADS=1  # macOS Accelerate
```

Pin to 1 only when running one node per core. On a single node with spare cores
you can leave BLAS multi-threaded, though small matrices rarely repay the
threading overhead.

The native BLAS is optional. Without one, the pure lane runs — slower but
exact — so nothing breaks; on a build that uses whole-program compilation
the BLAS is `dlopen`ed at runtime, not folded into `app.so`.

---

## Embedded JavaScript

`(igropyr quickjs)` embeds a JavaScript engine (QuickJS) in-process for
running a **fixed** JS bundle baked at build time — a reference
implementation you must match byte-for-byte, a sandboxed expression
evaluator, a JS template. User input is the string **argument**, never
code.

```scheme
(import (igropyr quickjs))

(qjs-boot! "function slugify(s){ return s.toLowerCase().replace(/\\s+/g,'-') }")
(qjs-call! "slugify" "Hello World")   ; -> "hello-world"
```

- `(qjs-boot! source [opts])` — load (or reload) the bundle. opts:
  `(mem-mb . 64)`, `(stack-kb . 1024)`, `(timeout-ms . 2000)`,
  `(so-path . "...")`.
- `(qjs-call fname arg)` → `(values ok? string)` — call a global function
  with one string argument; result on `#t`, JS error text on `#f`.
- `(qjs-call! fname arg)` → string — the raising variant.
- `(qjs-healthy?)` / `(qjs-generation)` / `(qjs-shutdown!)`.

It runs in **pure Scheme** over a stock shared `libquickjs`, bound directly
through the FFI — no custom C. A boot-time ABI probe reads the JSValue
`ref_count` offset from the loaded library (so it adapts across QuickJS
builds) and refuses an unknown layout rather than corrupting memory. The
guards: a memory cap, a stack cap, a wall-clock interrupt deadline (a Chez
`foreign-callable` the engine polls), an exception boundary, and
**crash-only rebuild** — a throwing or runaway call discards the whole JS
heap and reboots it from the bundle (`qjs-generation` counts rebuilds), so
one bad call can't poison the next. The engine is serialized on the single
OS thread and each call runs with interrupts disabled, so a call blocks the
scheduler for its duration (sub-millisecond typically, `timeout-ms` worst
case) — cap input size on latency-sensitive paths.

`qjs-boot!` reports if no library is found; point it at one with
`IGROPYR_LIBQUICKJS_SO` or `(so-path . "...")`.

#### Which QuickJS: quickjs-ng is recommended

Two upstreams are supported and detected automatically — the binding picks
its bindings from what the loaded library actually exports, so the same
build runs against either:

| | library name | `JS_FreeValue` |
|---|---|---|
| [quickjs-ng](https://github.com/quickjs-ng/quickjs) (**recommended**) | `libqjs` | exported as a real function |
| [bellard/quickjs](https://bellard.org/quickjs/) | `libquickjs` | a header inline; only the `__JS_FreeValue` slow path is exported |

**quickjs-ng** is the recommended target for two reasons. It is the
actively maintained fork; and because it exports a real `JS_FreeValue`,
releasing a value is one FFI call instead of a hand-written replica of the
inline function (read the tag, compute the `ref_count` address, decrement
it, and call the slow path at zero). That replica depends on the private
`ref_count` layout — which is exactly why the ABI probe exists — so with
ng there is simply less to get wrong.

It is also measurably cheaper per call. Measured on FreeBSD 15 / amd64,
best of three runs of 20 000 calls each:

| workload | quickjs-ng | bellard |
|---|---|---|
| near-empty function (call overhead only) | **0.50 µs/call** | 0.70 µs/call |
| argument in, result out | **0.65 µs/call** | 0.80 µs/call |
| 200 000-iteration numeric loop | 5.05 ms/call | 4.96 ms/call |
| `toLowerCase` + regexp replace | 5.15 µs/call | **2.35 µs/call** |

Read that carefully before switching: the **call overhead** is ~30 % lower
on ng (three JSValue releases per call, one FFI call each instead of a
read-modify-write plus a conditional call), and raw interpreter speed is
within 2 %. But engine internals differ per workload — the regexp/string
case above is more than twice as fast on bellard. If your bundle is
dominated by one such operation, measure your own bundle rather than
trusting either default.

### Fallback: the C-shim binding

When no stock shared library is available — for example Homebrew ships
QuickJS as a static archive only — a **C-shim binding with identical
exports**,
self-contained (QuickJS statically linked and version-pinned), is a drop-in
replacement:

- [guenchi/igropyr-quickjs](https://github.com/guenchi/igropyr-quickjs)

Build its shim with `build-quickjs-shim.sh`; it resolves as the same
`(igropyr quickjs)`, so the two are interchangeable and no application code
changes.

---

## Cached SSR

`(igropyr ssr)` puts a key/TTL cache in front of `(igropyr quickjs)` so
server-side rendering runs the **blocking** render once per `(key, ttl)`
instead of once per request. SSR helps SEO, but the content that needs
SEO is public and slow-changing — so the right shape is a cache in *front*
of the engine, not a render per request. A `qjs-call` blocks the calling
scheduler for the render's duration (FFI is non-preemptible); with the
cache it fires only on a miss, and hits are a lookup that never touches
the engine.

```scheme
(import (igropyr ssr))

;; at boot: ONE bundle per process (the QuickJS engine is process-global).
;; Export as many render functions as you like and call them by name.
(define r (make-ssr "
  function renderPost(j){ var p = JSON.parse(j);
    return '<article><h1>'+p.title+'</h1>'+p.body+'</article>'; }"))

;; in a handler: props (any Scheme value) is JSON-encoded and handed to the
;; JS function as one string; the string it returns is the HTML, cached.
(send-html! res (ssr-render r "renderPost"
                  '(("title" . "Hi") ("body" . "<p>…</p>"))
                  '((key . "/blog/42"))))       ; explicit key = the URL
```

### API

- `(make-ssr bundle [opts]) → ssr` — boot the engine on `bundle` and build
  the cache. `opts` is an alist:
  - `(cache . 'memory)` (default) or `(cache . (redis <conn> [prefix]))`
  - `(ttl-ms . 60000)` — entry lifetime
  - `(max-entries . 1024)` — memory-backend size cap
  - `(single-flight . #t)` — collapse a cold-key herd (see below)
  - `(quickjs . <opts>)` — passed to `qjs-boot!` (`timeout-ms`, `mem-mb`, …)
  - `(engine . <qjspool>)` — render in worker **processes** instead of on
    this thread (see [Renders out of process](#renders-out-of-process)).
    In this mode `bundle` is not evaluated here at all: the workers own it.
- `(ssr-render r fn props [opts]) → html` — cached render; raises a JS
  error on a **miss** (failures are never cached). `props` is any Scheme
  value (JSON-encoded) or a string (passed raw as the JSON argument).
  `opts`: `(key . "…")` — the cache key, typically the URL; defaults to
  `sha256(fn+props)`.
- `(ssr-try-render r fn props [opts]) → (values ok? text)` — non-raising:
  a failing render is returned, never cached.
- `(ssr-invalidate! r key)` — drop one entry (a content change).
- `(ssr-clear! r)` — drop all (e.g. after a deploy).
- `(ssr-stats r) → alist` — `((hits . N) (misses . M) (renders . K)
  (size . S))`.

### Cache backends

The `memory` backend is an in-process gen-server (`key → html . expiry`)
with a TTL ticker and a size cap that evicts the soonest-to-expire entry;
it is shared across the process's workers and its stats are exact. The
`redis` backend stores the HTML in Redis with `SET … PX` for server-side
TTL, so a render on one **node** is a hit on the others; `<conn>` is an
`(igropyr redis)` connection and `prefix` defaults to `"ssr:"`. Its
hit/miss stats are per-node and approximate.

### Single-flight

On by default, `single-flight` makes N concurrent misses for the **same
cold key** collapse to one render: the first claimant renders and the rest
wait for its result. This dedups a process's workers, which all share the
one mutex-serialized engine. A cross-node herd is still spread across
nodes (each renders once), not globally locked. If the rendering worker is
killed mid-render, waiters fall back to rendering themselves after a
timeout — the stuck claim self-heals. Set `(single-flight . #f)` to have
every concurrent miss render independently.

The render function's contract is `(fn jsonString) → htmlString`, **pure**:
props in, HTML out, no side effects (the JS heap is shared across calls, so
do not accumulate per-request state in globals). A JS throw / timeout / OOM
is handled by the shim (crash-only rebuild + wall-clock deadline);
`ssr-render` re-raises it (let-it-crash) and does not cache the failure.

### Renders out of process

The cache makes a render **rare**. It does not make one cheap, and it does
not bound how many happen at once.

A `qjs-call` runs on the scheduler's own OS thread with interrupts
disabled. Its deadline bounds one call, but while that call runs nothing
else in the process runs: no accepts, no reads, no timers — and no
watchdog, because every watchdog here is a green process too, so the HTTP
pool's stuck-worker killer is stopped along with the thing it exists to
protect. A render that reaches the deadline costs the whole node its
availability, and the crash-only rebuild that follows re-evaluates the
bundle on the same thread with ten times the call budget. Misses for
*different* keys stack: single-flight collapses repeats of one key, not a
wave of distinct ones — which is exactly what a deploy, an `ssr-clear!`,
or a batch of TTL expiries produces.

That cannot be fixed from the inside. Aborting a render is cooperative —
the interrupt handler can only ask, and the engine polls it only in its
interpreter loop, so a long C builtin overruns it — and the runtime that
would enforce a wall clock is the one being blocked. Only something
*outside* the call can bound it.

`(igropyr qjspool)` moves the engine to the far side of a socket, which
makes a render structurally identical to a query: an exclusive resource,
borrowed for one request, whose work happens elsewhere. It is the same
pool engine the SQL drivers use — checkout, deadlines, monitor reclaim,
rebuild on death, statistics — with a wire protocol on top.

```sh
# one worker process per parallel render; loopback only
scheme --script igropyr/qjs-worker.sc 127.0.0.1 9701 site.js timeout-ms=1500 &
scheme --script igropyr/qjs-worker.sc 127.0.0.1 9702 site.js timeout-ms=1500 &
```

```scheme
(import (igropyr qjspool) (igropyr ssr))

(define pool (qjspool '(("127.0.0.1" . 9701) ("127.0.0.1" . 9702))
                      '((render-timeout-ms . 1500)
                        (checkout-timeout-ms . 500))))

;; the bundle now lives in the workers, so make-ssr is given none
(define r (make-ssr "" `((engine . ,pool))))

(send-html! res (ssr-render r "renderPost" props '((key . "/blog/42"))))
```

A runaway render now blocks its own worker process and nothing else: the
caller's deadline is an ordinary parked receive, the scheduler keeps
running, and the pool discards and rebuilds the connection.

- `(qjspool endpoints [opts]) → pool` — one connection per endpoint.
  `opts`: `(checkout-timeout-ms . 2000)` — how long to wait for a *free*
  worker before giving up, and `(render-timeout-ms . 5000)` — how long the
  render itself may then take. Two deadlines, because the two are
  different problems: waiting for a worker means the pool is saturated and
  nothing is wrong, so shed early rather than hold an HTTP worker for the
  length of a render that has not started.
- `(qjspool-render pool fn json) → (values ok? html-or-error-text)` — and
  `qjspool-render/bytes` for raw UTF-8. Same contract as `qjs-call/bytes`:
  a JS throw, a timeout and a dead worker all arrive as `(values #f text)`.
- `(qjspool-connect host port [opts]) → pool` — a single connection, no
  pool behind it.
- `(qjspool-stats pool)`, `(qjspool-close! pool)`. A render is a lease, so
  it is counted under `checkouts`, and `checkout-wait-ms-*` is the wait for
  a free worker — the number that says whether to run more of them.
  `queries` and `query-ms-*` stay **zero**: the pool hands the worker over
  and the reply goes straight to the caller, so the pool never sees the
  render. Measure render duration at the call site.

**One connection per worker.** A worker is single-threaded and holds one
engine, so two connections to the same worker serialize inside it. Size
the pool by the endpoint *list*; parallel renders come from running more
worker processes, not from a bigger pool against one.

**What this does not do.** Nothing starts, stops or kills a worker — they
are supervised like a database is. A worker wedged in a runaway render
stays wedged; what is guaranteed is that the *caller* is not, and that the
other endpoints keep serving. There is also **no authentication**: whoever
reaches the port can call any function the bundle exports, so workers
belong on `127.0.0.1`.

---

## Object Storage and AWS

`(igropyr sigv4)` signs requests with AWS Signature V4 (pinned to the AWS
documented test vectors). The service libraries build on it over the
non-blocking `(igropyr http-client)`, so each call parks the calling
process like any other outbound request and works against AWS or any
compatible endpoint. `(igropyr aws)` is the small shared layer
(`aws-signed-post`, `endpoint->host`, `form-encode`, `xml-first`) the
service clients are written on.

### S3 (and S3-compatible: R2, MinIO)

```scheme
(import (igropyr s3))

(define bkt (make-s3 '((endpoint . "https://s3.us-east-1.amazonaws.com")
                       (bucket . "assets") (region . "us-east-1")
                       (access-key . "…") (secret . "…"))))
```

`make-s3` requires `endpoint` (an `http[s]://host[:port]` with **no** path
— it is signed byte-for-byte, so a stray path 403s) and `bucket`,
`access-key`, `secret`; `region` defaults to `"auto"` (fine for R2), and
`timeout` / `max-response` are optional.

- `(s3-put! s key data content-type) → etag`
- `(s3-get s key) → bytevector | #f` (`#f` on 404)
- `(s3-head s key) → headers-alist | #f` (read `x-amz-restore`,
  `x-amz-storage-class`, …)
- `(s3-copy! s src-key dst-key)` — server-side copy within the bucket
- `(s3-delete! s key)` — idempotent (404 counts as deleted)
- `(s3-list s prefix) → (key …)` — follows continuation tokens
- `(s3-delete-prefix! s prefix)` — list + delete each
- `(s3-restore! s key days tier) → 'accepted | 'in-progress | 'ok` —
  restore a Glacier / Deep Archive object

A non-2xx response raises `#(s3-error status body)`.

### STS: scoped temporary credentials

`(igropyr sts)` calls **GetFederationToken** to vend scoped, temporary AWS
credentials to a client (e.g. narrow S3 access for a mobile app). The
session policy that narrows the grant is the caller's; this signs the call
and returns the credentials.

```scheme
(import (igropyr sts))
(define sts (make-sts '((region . "us-east-1") (access-key . "…") (secret . "…"))))
(sts-get-federation-token sts "u-abc" policy-json 3600)
;;   -> ((access-key-id . "…") (secret-access-key . "…")
;;       (session-token . "…") (expiration . "2026-…Z"))
```

Raises `#(sts-error status message)` on a non-2xx response.

### SES: sending email

`(igropyr ses)` sends one already-rendered message (subject + HTML) via
SES v2 **SendEmail** (the JSON API). A non-ASCII From display name is RFC
2047 mime-word encoded, or clients (Gmail) show only the address
local-part.

```scheme
(import (igropyr ses))
(define ses (make-ses '((region . "eu-west-3") (access-key . "…") (secret . "…"))))
(ses-send-email ses "noreply@example.com" "Example" "u@x.com" subject html)
;;   -> the MessageId string
```

Raises `#(ses-error status body)` on a non-2xx response.

### SNS: topic fan-out

`(igropyr sns)` calls **Publish** to fan one message out to a topic's
subscribers — email, SMS, SQS, Lambda, HTTP. The topic and its
subscriptions are provisioned out of band; this signs the call and returns
the MessageId. `subject` only shows up in email delivery, so pass `#f` or
`""` to omit it.

```scheme
(import (igropyr sns))
(define sns (make-sns '((region . "us-east-1") (access-key . "…") (secret . "…"))))
(sns-publish sns "arn:aws:sns:us-east-1:123:alerts" "subject" "body")
;;   -> the MessageId string
(sns-publish sns "arn:aws:sns:us-east-1:123:alerts" #f "body")   ; no subject
```

Raises `#(sns-error status message)` on a non-2xx response.

### CloudWatch: custom metrics

`(igropyr cloudwatch)` calls **PutMetricData** to publish one custom metric
data point — a namespace, metric name and value, optionally a unit and
dimensions. Build it as a counter or a gauge and alarm on it in CloudWatch.
`unit` defaults to `"Count"`; `dims` is an alist of `(name . value)` (a
metric carries up to 30 dimensions). PutMetricData answers a 2xx with an
empty body, so there is no id to read back — the call returns `#t`.

```scheme
(import (igropyr cloudwatch))
(define cw (make-cloudwatch '((region . "us-east-1") (access-key . "…") (secret . "…"))))
(cloudwatch-put-metric cw "myapp" "requests" 1)                  ; -> #t, unit "Count"
(cloudwatch-put-metric cw "myapp" "latency_ms" 42 "Milliseconds"
                       '(("route" . "/checkout")))               ; unit + a dimension
```

Raises `#(cloudwatch-error status message)` on a non-2xx response.

---

## Password Hashing

`(igropyr kdf)` derives and verifies passwords over the already-loaded
libcrypto (the same OpenSSL `(igropyr tls)` and `(igropyr apple-jws)`
use), offered as infrastructure so an app **chooses** its algorithm — and
migrates between them without a flag day. There are two layers.

Raw derivations (`bytevector → bytevector`; you pick the cost params):

```scheme
(import (igropyr kdf))
(kdf-pbkdf2-sha256 pw salt iterations dk-len)   ; PKCS5_PBKDF2_HMAC
(kdf-scrypt        pw salt N r p dk-len)         ; EVP_PBE_scrypt (memory-hard)
(kdf-argon2id      pw salt t m p dk-len)         ; EVP_KDF argon2id
```

Self-describing password hashes — the algorithm and params live in the
string, so `password-verify` dispatches on the prefix and an app can
rehash-on-login to a stronger algorithm transparently:

```scheme
(password-hash "hunter2" 'scrypt   '())   ; -> "scrypt$32768$8$1$<salt>$<dk>"
(password-hash "hunter2" 'pbkdf2   '())   ; -> "pbkdf2-sha256$600000$<salt>$<dk>"
(password-hash "hunter2" 'argon2id '())   ; -> "argon2id$2$19456$1$<salt>$<dk>"
(password-verify "hunter2" stored)         ; -> #t | #f  (constant-time compare)
```

The defaults follow OWASP minimums (scrypt N=32768; PBKDF2 600 000
iterations; argon2id m=19 MiB, t=2, p=1). Override per call with the
params alist, e.g. `(password-hash pw 'scrypt '((N . 65536)))`.

### The cost ceiling

A blocking KDF freezes Igropyr's single-threaded scheduler for its whole
duration, so `password-verify` enforces a resource ceiling (≈ one 256 MiB
fill of KDF work, ~0.1–0.2 s) **before** running the KDF. A **crafted**
stored hash carrying an enormous cost — an attacker-controlled
`argon2id$…$262144$…` — is rejected fast (`#f`) instead of turning a login
into a multi-second stall. This is a ceiling, not the per-verify cost: a
normal verify at the OWASP defaults is ~11–47 ms. Parameters are validated
strictly; a non-string password or a malformed / unknown-algorithm hash
returns `#f`, never a crash and never "matches anything". `(igropyr
crypto)` keeps a pure-Scheme `pbkdf2-hmac-sha256` for hosts without
libcrypto.

---

## Running and Building

### Environment Variables

Before running Igropyr, set these two environment variables:

```bash
export CHEZSCHEMELIBDIRS=.:lib:/path/to/libs
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
```

- **CHEZSCHEMELIBDIRS**: Colon-separated list of directories to search for R6RS libraries. Include `.` for the current directory, plus the directory that holds your `igropyr` checkout — replace `/path/to/libs` with it. Igropyr is itself a library, so Chez resolves `(igropyr ...)` by finding an `igropyr/` subdirectory in one of these paths. (When you run from inside the checkout's own parent, `.` alone already exposes it.)
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

### BLAS Threads

If the app uses `(igropyr blas)` with a native BLAS, run one node per core and pin the BLAS to one thread per process — otherwise its internal threads oversubscribe the cores against the nodes. Set the environment variable before the process starts (the BLAS reads it when its shared library loads): `OPENBLAS_NUM_THREADS=1` / `OMP_NUM_THREADS=1` on Linux/FreeBSD, `VECLIB_MAXIMUM_THREADS=1` on macOS. See [Vector Scoring](#vector-scoring).

### Memory

Each green process is ~1 KB of metadata. Thousands of processes are feasible. The main memory use is buffers for request/response bodies. Keep body size limits reasonable (default 1 MB for HTTP, 8 MB for WebSocket).

### Monitoring

Use `/stats` and process-level tools (`top`, `Activity Monitor`) to watch CPU, memory, and open file descriptors. Stuck workers (detected by the supervisor) should be rare; if they're common, your handlers have blocking operations.

---

## Further Reading

- Chez Scheme documentation: https://scheme.com/
- libuv documentation: https://docs.libuv.org/
- R6RS Scheme specification: https://r6rs.org/
- Erlang/OTP documentation: https://erlang.org/doc/

---

*Last updated: 2026-07-19*
