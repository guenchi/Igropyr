# Igropyr 手册

本手册面向基于 Igropyr 构建应用或参与框架贡献的开发者，介绍 Igropyr 的架构、设计模式和实现细节。

## 目录

1. [架构概览](#架构概览)
2. [Actor 模型](#actor-模型)
3. [核心不变量](#核心不变量)
4. [编写 HTTP Handler](#编写-http-handler)
5. [容错](#容错)
6. [OTP 模式](#otp-模式)
7. [对话](#对话)
8. [数据库客户端](#数据库客户端)
9. [运行和构建](#运行和构建)
10. [测试](#测试)
11. [代码风格](#代码风格)
12. [常见陷阱](#常见陷阱)

---

## 架构概览

Igropyr 组织为分层 stack：

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

独立 library：
  • JSON parser/serializer
  • gen-server (OTP pattern)
  • pubsub (topic-based pub/sub)
  • Redis client
  • MySQL client
```

### 各层职责

- **libuv (libuv.sc)**：直接绑定 libuv 的 FFI。管理 TCP handle、读写 buffer 和 event polling。通过 callback 把数据交付给上层。

- **Actor (actor.sc)**：基于 continuation 上下文切换的绿色进程 scheduler。单 OS 线程，通过 timer interrupt 做抢占式调度，使用消息传递 mailbox，并提供 link/monitor 进程关系。

- **OTP (otp.sc)**：带 supervisor 的 worker pool。生成 N 个 worker、分发任务、检测 crash 和 stuck worker（>30s）、自动重试失败任务（≤3 次），并杀死 stuck worker 且不重试。

- **HTTP (http.sc)**：协议层。解析 HTTP/1.1 请求（header、body、chunked encoding），管理每连接 reader 进程，在 pool worker 中调用用户 handler，编码响应，并处理 keep-alive 和 pipelining。

- **Express (express.sc)**：框架层。提供带 path parameter（`:id`）的 router、middleware chain、便捷响应 encoder（`send-json!`、`send-file!`）、cookie parsing、form parsing（urlencoded 和 multipart）以及 static file serving。

- **WebSocket (websocket.sc)**：RFC 6455 codec、handshake、frame masking、fragmentation、ping/pong。每个 socket 都是一个调用用户 session handler 的绿色进程。

- **JSON, gen-server, pubsub, Redis, MySQL**：独立 library，没有相互依赖（除了 JSON 使用 Scheme primitive，gen-server 使用 actor，pubsub 使用 gen-server+actor，redis/mysql 使用 actor+uv）。

### HTTP 请求的数据流

```
1. libuv 调用 on-connection callback（interrupt disabled）
   ↓
2. on-connection 向 event-loop process 交付 'accept 消息
   ↓
3. Event-loop 为这个连接生成 reader process
   ↓
4. Reader process 调用 tcp-read-start!（注册 on-read callback）
   ↓
5. Client 发送请求；on-read callback（interrupt disabled）
   → 接收字节，增量解析 request line/header
   → body 完整后：#(submit-task #(task ,id ,conn ,request))
   → 发送给 supervisor
   ↓
6. Supervisor 把 task 放入 pending queue
   ↓
7. Idle worker 接收 #(process-task ,task)
   → 运行用户 handler (req res)
   → handler 调用 set-status!, set-header!, res-send! 等
   ↓
8. res-send! 通过 tcp-write! 排队写入
   ↓
9. on-write callback（interrupt disabled）
   → 通过 #(write-done) 通知 reader 完成
   ↓
10. Reader 接收 #(write-done)
    → 如果 keep-alive：回到第 4 步
    → 否则：关闭连接，yield
```

---

## Actor 模型

Igropyr 的并发模型是在绿色进程之上做 Erlang 风格消息传递。进程之间没有共享可变状态；协调完全通过消息完成。

### 核心概念

**Green Process**：由 Igropyr runtime 在单个 OS 线程上调度的轻量线程。通过 `call/1cc`（捕获 continuation）切换上下文。每个已接受连接、每个 worker、每个数据库 session 等都对应一个进程。

**Process ID (pid)**：不透明的进程 record。用 `eq?` 比较，或用 `process-alive?` 检查状态；只有调试数值 id 才使用 `process-id`。

**Message**：进程 mailbox 中的 Scheme value（通常是 vector 或 list）。由 `receive` macro 接收。

**Mailbox**：侵入式双向链表消息队列。已接收的消息会被消费；消息会等待，直到找到匹配 pattern。

### API 参考

#### `(spawn thunk) → pid`

生成一个新的绿色进程，在自己的上下文中调用 `(thunk)`。进程会运行到 thunk 返回（normal exit）或抛出异常（crash）。

```scheme
(define counter-pid
  (spawn (lambda ()
           (let loop ((n 0))
             (receive
               (`(inc) (loop (+ n 1)))
               (`(get-reply ,from) (send from n) (loop n)))))))
```

#### `(send pid message) → void`

向进程 mailbox 发送消息。非阻塞；消息会立即入队，并在接收者调用 `receive` 时交付。可在任何上下文安全调用。

```scheme
(send counter-pid '(inc))
(send counter-pid (vector 'get-reply self))
```

#### `(receive clause ...)`

阻塞直到某条消息匹配其中一个 pattern。每个 clause 是 `(pattern body ...)`。pattern 可以使用 quasiquote 语法并用 unquote（`,`）提取字段。

**关键规则**：如果某个 clause 有 `(after timeout-ms ...)` timeout，它**必须是第一个 clause**。

```scheme
;; 没有 timeout：
(receive
  (`(ping ,from) (send from 'pong))
  (`(quit) (exit 0)))

;; 有 timeout（必须放第一项）：
(receive
  ((after 5000 (display "timeout\n")))
  (`(ping ,from) (send from 'pong))
  (`(quit) (exit 0)))
```

timeout 以毫秒为单位，从调用 `receive` 的时刻开始计时。如果没有消息匹配且 timeout 到期，则执行 timeout branch。

#### `self → pid`

identifier syntax，会展开为当前进程的 pid。直接使用 `self`；它不是 procedure call。

```scheme
(send server (vector 'work-item self))
(receive
  (`(result ,v) v))
```

#### `(link pid) → void`

把当前进程 link 到另一个进程。如果另一个进程死亡，当前进程会收到 `#(EXIT ,pid ,reason)` 消息，并且默认也会死亡（除非设置了 `process-trap-exit`）。link 是双向的。

```scheme
(spawn (lambda ()
         (link other-pid)
         (receive
           (`#(EXIT ,p ,r) (display "linked process died\n")))))
```

#### `(monitor pid) → monitor-reference | #f`

monitor 另一个进程。如果目标死亡，当前进程会收到 `#(DOWN ,pid ,reason)` 消息，但不会被 link（不会自动死亡）。多个进程可以 monitor 同一个目标。返回供 `demonitor` 使用的 monitor reference；如果目标已经死亡，返回 `#f`（此时 `DOWN` 消息会立即交付）。

```scheme
(spawn (lambda ()
         (monitor database-pid)
         (receive
           (`#(DOWN ,p ,reason)
             (display "database crashed, reconnecting...\n")))))
```

#### `(demonitor monitor-reference) → void`

使用之前 `(monitor pid)` 返回的 monitor reference 取消监控。

#### `(process-trap-exit flag) → void`

传 `#t` 会把 `#(EXIT ...)` 信号转换为普通消息（不会死亡）。传 `#f` 恢复默认行为。

```scheme
(spawn (lambda ()
         (process-trap-exit #t)
         (link other-pid)
         (receive
           (`#(EXIT ,p ,r) (display "other died but we keep going\n")))))
```

#### `(kill pid reason) → void`

用给定 reason（任意 Scheme value）杀死进程。该进程会从所有 queue 中移除并 unregister。被 link 的进程会收到 `#(EXIT ,pid ,reason)`。

```scheme
(kill worker-pid 'overloaded)
```

#### `(register name pid) → pid`

用 symbol 名称把进程注册到全局 registry。返回 `pid`。

```scheme
(register 'logger (spawn logger-thunk))
```

#### `(unregister name) → void`

按名称从 registry 中移除进程。

#### `(whereis name) → pid | #f`

按注册名查找进程 pid。如果未注册，返回 `#f`。

```scheme
(define db (whereis 'database))
(when db (send db (vector 'query ...)))
```

#### `(process-alive? pid) → boolean`

检查进程是否仍在运行（没有 crash 或被 kill）。

#### `(sleep-ms ms) → void`

暂停当前进程至少 `ms` 毫秒。scheduler 会在时间到期或更早时恢复它。

```scheme
(spawn (lambda ()
         (display "starting...\n")
         (sleep-ms 1000)
         (display "1 second later\n")))
```

#### `(process-id self) → integer`

返回内部进程 id（integer，不同于不透明的 `pid`）。用于调试；HTTP handler 中的错误日志和示例输出会包含它。

```scheme
(define worker-id (process-id self))
(send log (vector 'msg (string-append "worker-" (number->string worker-id))))
```

#### `(start-scheduler thunk) → never`

进入主 event loop。这会生成 event-loop process、启动 scheduler 并运行 thunk。永不返回；在初始化结束处调用它。

```scheme
(start-scheduler
  (lambda ()
    (app-listen app 8080)
    ;; 或者：(http-listen 8080 handler 8)
    ))
```

### 示例：简单 Echo Server

```scheme
(start-scheduler
  (lambda ()
    ;; 生成 echo service
    (register 'echo-service
      (spawn (lambda ()
               (let loop ()
                 (receive
                   (`(echo ,msg ,from)
                    (send from (list 'response msg))
                    (loop)))))))
    
    ;; 生成 client
    (spawn (lambda ()
             (let ((echo (whereis 'echo-service)))
               (send echo (vector 'echo "hello" self))
               (receive
                 (`(response ,msg)
                  (display (string-append "got: " msg "\n")))))))
    
    ;; 保持 scheduler 运行
    (sleep-ms 10000)))
```

---

## 核心不变量

### 规则：绝不能在 libuv Callback 中 Yield

Igropyr 最关键的不变量：

> **运行在 libuv callback 中（从 `uv-poll!` 到达）的代码绝不能调用 `yield`、`receive` 或 `raise`。Callback 只能复制数据、修改 registry，并发送消息。**

**原因**：yield 一个跨越 C stack frame（libuv call stack）的 continuation 会破坏 C runtime。continuation 捕获 Chez Scheme 的 stack pointer 和 register state，但 libuv 的 stack frame 仍会保持 active；恢复 continuation 会跳过 C frame 的 cleanup（解锁 mutex、释放临时对象等），并且下次进入 C function 时 C frame 仍然 active。

### Callback 在哪里运行

libuv event loop 是 `uv-poll!` 中的紧密 C loop，由 event-loop process 调用。运行在 `uv_run(UV-RUN-ONCE)` 期间的 callback 包括：

- **on-connection**：listening socket 接受 client 时调用。设置新的 TCP handle。
- **on-read**：TCP socket 上有数据到达或 read would block 时调用。
- **on-write**：pending write 完成时调用。
- **on-close**：`uv_close` 完成 handle 释放后调用。
- **on-timer**：timer 触发时调用。

所有这些 callback 都在 interrupts disabled 状态下运行（Chez 的 timer interrupt 被屏蔽），因此 scheduler state 不会被抢占破坏。

### 安全 Callback 模式

callback 可以：

1. **复制数据**到 buffer 或本地结构：
   ```scheme
   ;; 在 on-read callback 中：
   (let ((buf-copy (bytes->string (subbv buf 0 len))))
     ...)
   ```

2. **修改进程私有状态**（前提是该状态不被其它进程访问）：
   ```scheme
   ;; reader process 事件私有：
   (let ((accumulated-bytes
          (bytevector-append accumulated-bytes buf)))
     ...)
   ```

3. **向另一个进程发送消息**：
   ```scheme
   ;; 在 on-read callback 中，请求完整时：
   (deliver-message supervisor (vector 'submit-task task))
   ```

   `deliver-message` 是 `(igropyr libuv)` 的内部函数。它由 `uv-set-deliver!` 接入，只把消息入队到目标进程 mailbox，不会 yield。

4. **读取进程 registry**（只读）：
   ```scheme
   ;; 查找已注册进程：
   (let ((logger (whereis 'logger)))
     (when logger (deliver-message logger msg)))
   ```

### 调试 Yield 违规

如果看到类似 "Continuation escape from C code" 的错误或 segfault，说明某次 yield 或 receive 跨越了 C frame。检查：

- 是否在传给 `tcp-read-start!` 或 `http-listen` 的 handler 内调用了 `receive`？
- 是否在 callback 中调用了阻塞操作（等待 semaphore、sleep 等）？
- 是否使用了会隐式 yield 的 library（例如某些 stream 操作）？

把阻塞逻辑移入单独 spawn 的进程，并通过消息传递发出完成信号。

---

## 编写 HTTP Handler

### 使用 Express 层

Express 层提供熟悉的 Web framework API。大多数应用会使用 Express；直接使用 HTTP core 比较少见。

#### 创建 App 和路由

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

;; PUT、DELETE 同理
(app-put app "/item/:id" (lambda (req res) ...))
(app-delete app "/item/:id" (lambda (req res) ...))
```

#### 路径参数

route 中的 pattern `:name` 会捕获一个 path segment。用 `(req-param req "name")` 提取。

```scheme
(app-get app "/blog/:year/:month/:slug"
  (lambda (req res)
    (let ((y (req-param req "year"))
          (m (req-param req "month"))
          (s (req-param req "slug")))
      (send-text! res (string-append y "/" m "/" s)))))
```

#### Query String

`(req-query req)` 返回已解码 query parameter 的 alist。

```scheme
;; GET /search?q=hello&limit=10
(app-get app "/search"
  (lambda (req res)
    (let ((q (assoc "q" (req-query req)))
          (limit (assoc "limit" (req-query req))))
      ...)))
```

#### Request Accessors

- `(req-method req)` → symbol（GET、POST 等）
- `(req-path req)` → string（"/users/42"）
- `(req-headers req)` → `(symbol . string)` pair 的 alist（key 已 downcase）
- `(req-header req 'name)` → string 或 #f
- `(req-body req)` → bytevector（已解码，chunked encoding 已 decompressed）
- `(req-keep-alive? req)` → boolean（HTTP/1.1 默认 keep-alive）

#### Request Body Parsing

- `(req-json req)` → parsed JSON object（alist/vector 等）或 invalid 时 #f
- `(req-form req)` → urlencoded 或 multipart body 解析得到的 alist
  - Text field：`(name . "value")`
  - File：`(name . #(file "filename" "content-type" #bytes))`
- `(req-cookie req "name")` → string 或 #f

#### Response Helpers

- `(send-text! res text-string)` → 设置 Content-Type: text/plain; charset=utf-8
- `(send-html! res html-string)` → 设置 Content-Type: text/html; charset=utf-8
- `(send-json! res object)` → 序列化并设置 Content-Type: application/json
- `(send-file! res path)` → 向 client stream 一个文件
- `(set-status! res code)` → 设置 HTTP status（默认 200）
- `(set-header! res "Name" "value")` → 添加 / 替换 response header
- `(set-cookie! res "name" "value" "Path=/" "HttpOnly")` → 添加 Set-Cookie header

#### Streaming Response

对于大型或长时间运行的响应，使用 `res-begin!`、`res-write!`、`res-end!`：

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

使用 `sse-start!` 和 `sse-send!` 通过持久连接向 client push event：

```scheme
(app-get app "/sse"
  (lambda (req res)
    (sse-start! res)  ; 设置 headers 并 flush
    ;; 现在生成独立进程发送 event：
    (spawn (lambda ()
             (let loop ((i 1))
               (when (<= i 5)
                 ;; 连接关闭时 sse-send! 返回 #f：
                 (when (sse-send! res (string-append "event: " (number->string i) "\n"))
                   (sleep-ms 1000)
                   (loop (+ i 1))))
             (res-end! res)))))
```

#### WebSocket

使用 `app-ws` 处理 WebSocket 连接。handler 接收 `ws` 对象和 `req`。调用 `ws-recv` 接收 frame，调用 `ws-send-text!`/`ws-send-binary!` 发送。

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

Middleware 是 `(lambda (req res next) ...)` 函数，它可以检查 / 修改 request，调用 `(next)` 传给下一个 handler，或者发送响应且不调用 `(next)`。

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

Middleware 会按添加顺序调用，并位于匹配 route handler 之前。

#### Static File Serving

```scheme
(app-static app "/assets" "./public")
;; GET /assets/style.css -> read ./public/style.css
```

#### Listening

```scheme
(start-scheduler
  (lambda ()
    (let ((srv (app-listen app 8080)))
      ;; 可选：startup 后添加 route，用于 hot reload：
      (app-get app "/version" (lambda (req res) (send-text! res "v2"))))))
```

或配置 worker pool：

```scheme
(app-listen app 8080 '((workers . 16)
                       (max-retries . 2)
                       (stuck-ms . 60000)
                       (check-ms . 10000)))
```

配置项：
- `workers`：worker process 数量（默认 8）
- `max-retries`：crash 时最大 task retry 次数（默认 3，因此总共执行 4 次）
- `stuck-ms`：判断 worker stuck 的时间阈值（默认 30000 = 30s）
- `check-ms`：检查 stuck worker 的 ticker 间隔（默认 5000 = 5s）

### 直接使用 HTTP Core

对于不适合 Express 的框架或应用，可以直接使用 HTTP core：

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
      16)))  ; 16 个 worker
```

handler 接收 `req` 和 `res` 对象。Accessor 和 response function 与 Express 相同。

---

## 容错

Igropyr 的容错基于 Erlang 的 "Let It Crash" 原则：不要试图在 handler 中恢复所有错误；让 worker crash，并由 supervisor 重启它们。

### Worker Pool

固定的 `N` 个 worker（默认 8）执行 reader process 提交的 task。supervisor 跟踪：

- **Idle workers**：等待 task
- **Busy workers**：正在执行 task，并记录 start timestamp
- **Pending tasks**：排队等待 idle worker
- **Task attempts**：每个 task id 已重试的次数

### Crash Recovery

1. worker 在执行 task 时 crash（未捕获异常）。
2. supervisor 通过 `#(DOWN ,worker-pid ,reason)` monitor message 检测到。
3. supervisor 增加 task 的 attempt count。
4. 如果 attempt count ≤ max-retries（默认 3，因此最多执行 4 次）：
   - 生成 replacement worker。
   - task 被重新放到 pending list 前端（给它优先级）。
5. 如果 attempt count > max-retries：
   - 调用 `fail-task` handler（向 client 写 HTTP 500）。
   - 丢弃 task。
6. 生成 replacement worker，以保持 pool size。

### Stuck Worker Detection

1. supervisor 运行 ticker process，每 `check-ms`（默认 5s）发送 `#(check-stuck-workers)`。
2. 对每个 busy worker，supervisor 检查 `now-ms - start-time > stuck-ms`（默认 30s）。
3. 如果 worker stuck：
   - 用 `(kill worker-pid 'stuck)` 杀死它。
   - task **不会**重试（避免再次卡住 pool）。
   - 调用 `fail-task` handler（HTTP 500）。
   - 生成 replacement worker。

这保证即使某个 handler CPU 自旋，也不能冻结 HTTP service。其它请求继续由健康 worker 服务。

### 配置

向 `app-listen` 或 `http-listen` 传入 alist 配置：

```scheme
(app-listen app 8080
  '((workers . 16)
    (max-retries . 2)
    (stuck-ms . 60000)
    (check-ms . 10000)))
```

或者只在修改 pool size 时使用 worker-count shortcut：

```scheme
(http-listen 8080 handler 12)
;; Params: port handler workers
```

### 故障钩子（remote 重试环）

默认情况下，被放弃的 task 回复裸 `500` 并关闭连接。池选项 `on-failure`
用你自己的 handler 替换它：在一个**新 worker** 上运行，走正常响应路径——
因此 **keep-alive 得以保留**，客户端可以在同一条连接上重新提交：

```scheme
(app-listen app 8080
  `((stuck-ms . 3000)          ; 快失败：尽早杀掉卡死的 worker
    (check-ms . 1000)
    (on-failure . ,(make-fault-handler))))   ; 内置模版，也可自定义
```

内置模版以 503 状态回复
`{"fault":"crash"|"stuck","attempts":n,"elapsed-ms":t,"retryable":true}`
（`(make-fault-handler 500)` 可覆盖状态码）。自定义 handler 形如
`(lambda (req res info) ...)`，`info` 为：

| key | 含义 |
|---|---|
| `kind` | `crash`（重试耗尽）或 `stuck`（worker 被杀） |
| `reason` | 最后一次执行的 raise 值 / 退出原因 |
| `id` | task id，用于日志串联 |
| `attempts` | 该请求的总执行次数 |
| `elapsed-ms` | 最后一次执行的耗时 |

客户端可以依赖的语义——**先杀后告**，故障响应到达时**没有在途执行**：

| kind | 服务端状态 | 客户端的合理动作 |
|---|---|---|
| `crash` | handler 体执行了 `attempts` 次，各次副作用可能已落地 | 换参数重提，或查询状态后补偿 |
| `stuck` | worker 执行中被杀，副作用部分执行、断点未知 | 带状态重提，或回滚 |

每次重新提交都是**新 task**：全新的重试预算、完整的新一轮重试
（有意如此——昨天的瞬时故障不应污染今天的请求）。把 `stuck-ms` 调短后，
客户端几秒内就能得知确定状态，在原来干等 30 秒的时间里可以带着信息环绕
重试多轮。

两道栅栏保证钩子安全：它只运行**一次**（钩子内的 raise 被捕获并回落到
裸 500——不会形成重试循环）；钩子自身卡死会被同一个 ticker 收割，同样
回落。若（流式）响应已部分发出，钩子无法运行——连接照旧关闭。

注意：`error-handler` 中间件用 `guard` 包住 handler，崩溃到不了
supervisor——在它后面重试和 `on-failure` 都不会触发。`error-handler`
用于*预期内*的业务错误，故障钩子用于 Let-It-Crash 类故障；不要用兜底
guard 包住可能崩溃的 handler。

### 监控 Pool

使用 `(http-stats srv)` 获取当前 pool 状态：

```scheme
(app-get app "/stats"
  (lambda (req res)
    (send-json! res (http-stats srv))))
```

返回：

```scheme
((idle . 3)
 (busy . 2)
 (pending . 1)
 (total-requests . 5234)
 (active-connections . 12)
 (uptime-ms . 31234))
```

### Handler 中的错误处理

因为 handler 运行在 pool worker 中，未捕获异常会触发 crash-recovery path。这是有意设计：

```scheme
(app-get app "/crash-demo"
  (lambda (req res)
    ;; 这里的任何未捕获异常都会 crash worker 并触发 retry。
    (raise 'something-went-wrong)))

;; 这不是 error condition；这是 fault tolerance 的正常用法。
;; client 在所有 retry 耗尽后收到 500。
```

对于已知错误场景，捕获异常并适当响应：

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

## OTP 模式

### gen-server：有状态服务模式

`gen-server` 是管理状态并处理两类请求的进程：

- **Call**（同步）：调用者阻塞等待 reply。
- **Cast**（异步）：调用者发送消息但不等待。

server loop、request/reply matching 和 timeout handling 在 `gen-server-start` 中统一实现；你只需要提供 callback。

#### 定义 gen-server

```scheme
(import (chezscheme) (igropyr actor) (igropyr gen-server))

;; 一个简单 counter service
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

#### 调用 gen-server

```scheme
(gen-server-call counter-server 'inc)      ; blocks, returns 1
(gen-server-call counter-server 'get)      ; blocks, returns 2
(gen-server-cast counter-server 'reset)    ; returns immediately
(gen-server-call counter-server 'get)      ; blocks, returns 0
```

默认 call timeout 是 5 秒。自定义：

```scheme
(gen-server-call counter-server 'get 10000)  ; 10 秒 timeout
```

如果 server crash，调用者会立即得到 `#(gen-server-error server-died reason)`（因为调用者 monitor server），而不是一直等待到 timeout。

#### 按名称注册 gen-server

```scheme
(define logger
  (gen-server-start-named 'global-logger
    (lambda () (make-eq-hashtable))  ; state：保存 log line 的 hashtable
    
    (lambda (msg from state)
      (case (vector-ref msg 0)
        ((log)
         (let ((topic (vector-ref msg 1))
               (line (vector-ref msg 2)))
           (let ((logs (hashtable-ref state topic '())))
             (hashtable-set! state topic (cons line logs)))
           (values 'ok state)))
        (else (values 'bad-request state))))
    
    (lambda (msg state) state)))  ; 没有 cast

;; 之后按名称查找：
(define log-server (whereis 'global-logger))
(gen-server-call log-server (vector 'log 'requests "GET / 200"))
```

#### handle-info Callback

除了 handle-call 和 handle-cast，也可以提供 handle-info callback 处理其它消息（例如 monitor DOWN message）：

```scheme
(gen-server-start
  (lambda () 0)
  (lambda (msg from state) (values 'ok state))  ; handle-call
  (lambda (msg state) state)                     ; handle-cast
  (lambda (msg state)                            ; handle-info（可选）
    (if (and (vector? msg) (eq? (vector-ref msg 0) 'DOWN))
        ;; 被 monitor 的进程死亡；在这里处理
        (display "dependency died\n")
        state)))
```

### pubsub：基于 Topic 的 Publish/Subscribe

pubsub library 提供按 topic 组织 subscriber 的中央 registry。publisher 和 subscriber 解耦。

#### 启动 pubsub

在 boot 时调用一次：

```scheme
(import (igropyr pubsub))

(start-scheduler
  (lambda ()
    (start-pubsub!)
    ...))
```

这会生成一个名为 `'igropyr-pubsub` 的 gen-server，你不需要直接与它交互。

#### 订阅 Topic

```scheme
(spawn (lambda ()
         (subscribe 'room-1)
         (let loop ()
           (receive
             (`#(pub ,topic ,payload)
              (display (string-append "topic " (symbol->string topic) ": " payload "\n"))
              (loop))))))
```

只要有人向该 topic publish，进程就会收到 `#(pub ,topic ,payload)` 消息。

#### 发布

```scheme
(publish 'room-1 "hello everyone")
```

`'room-1` 的所有 subscriber 都会收到 `#(pub room-1 "hello everyone")`。

#### 取消订阅

```scheme
(unsubscribe 'room-1)
```

死亡 subscriber 会自动 unregister（pubsub server monitor 它们），因此 WebSocket 关闭时，其进程死亡并被清理。

#### 示例：聊天室

```scheme
(app-ws app "/chat/:room"
  (lambda (ws req)
    (let ((room (string->symbol (req-param req "room"))))
      ;; 生成 forwarder 进程，把 room 消息转发到这个 WebSocket
      (let ((forwarder (spawn
                        (lambda ()
                          (subscribe room)
                          (let loop ()
                            (receive
                              (`#(pub ,t ,msg)
                               (ws-send-text! ws msg)
                               (loop))))))))
        ;; 主循环：接收 WebSocket 消息并 publish
        (let loop ()
          (let ((frame (ws-recv ws)))
            (if (eq? (vector-ref frame 0) 'text)
                (begin
                  (publish room (vector-ref frame 1))
                  (loop))
                ;; 收到 close
                (kill forwarder 'normal))))))))
```

### 何时使用 gen-server，何时使用裸 spawn

使用 **gen-server** 当：

- 需要 request/reply（同步通信）。
- 进程管理可变状态，且必须安全处理并发请求。
- 想要自动 timeout 和 crash detection。

使用 **bare spawn** 当：

- 进程由外部事件驱动（例如等待 frame 的 WebSocket reader）。
- 没有 request/reply pattern（单向消息）。
- 想要完全控制 receive loop。

---

## 对话

`(igropyr conversation)` 把一个多请求对话作为**一个绿色进程**运行——
"web programming with continuations" 的 actor 模型表述。进程的局部绑定
就是对话状态，包括 session 存储永远放不进去的活资源：打开的数据库事务、
文件句柄、带 TTL 的预订。控制流即程序文本——"用户在确认步"意味着进程
就停在那一行；代码表达不出来的步骤顺序不可能发生。

```scheme
(app-post app "/transfer"
  (lambda (req res)
    (let-values (((id reply)
                  (conversation-start!
                    (lambda (req suspend!)
                      (let ((tx (begin-tx!)))          ; 活事务，跨轮持有
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

API：`(conversation-start! flow req [ttl-ms])` 生成 flow 进程，返回
`(values id 首轮回复)`；flow 内部 `(suspend! reply)` 应答当前轮并停车，
直到下一次 `(conversation-resume! id req)`——后者返回 flow 的下一轮回复，
或 `'gone`。flow 的返回值即最终回复，随后进程退出。默认 TTL 300 000 ms；
过期在 flow 内 raise `'conversation-expired`，`guard` 里做回滚。

对话进程从不接触连接：池 worker 仍是协议适配层，停车等 flow 出回复。
因此池的 stuck-killer 与故障钩子继续保护每一轮。

**`gone` 保证。** 进程因任何原因死亡——崩溃、TTL、正常结束——注册名
自动清除，之后所有 resume 都返回 `'gone`。对持有数据库事务的 flow：
进程死 = 连接断 = 数据库自己回滚，`gone` **保证**没有提交。与故障钩子
的 `crash`/`stuck` code 合起来，客户端对服务端状态的认知完备——完整的
远程事务环。

**用在哪**——关键事务流程：内部强事务操作的支付、预订（座位锁就是进程
局部状态，`after` 就是它的 TTL）、严格顺序的协议对话。**不用在哪**——
普通无状态请求（应保持归零 + 客户端带状态重试）；以及任何持有行锁等待
**人**思考的步骤：人的停顿用应用级预留跨越，活事务只跨机器节奏的轮次。

---

## 数据库客户端

### Redis

Redis client 是一个管理到 Redis server 的 TCP 连接的绿色进程。命令会在该连接上 pipeline，reply 按 FIFO 与 request 匹配。

#### 基本用法

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

`redis` 函数发送命令，并暂停调用者直到 reply 到达。它接收任意数量参数（全部转换为 string，并作为 RESP2 array element 发送）。

**返回值**：

- Simple string：`"OK"`、`"PONG"` 等 → string
- Bulk string：`"hello"` → 合法 UTF-8 返回 string，binary data 返回 bytevector
- Null：`nil` → `#f`
- Integer：`:42` → number
- Array：`[1,2,3]` → list（或 vector，视上下文而定）
- Set：与 array 相同

**错误**：Redis error（`-ERR ...`）会在调用者中 raise `#(redis-error ,message)`。如果连接断开，所有等待中的调用者会得到同一个 error。

#### Pipelining

多个进程可以在同一个连接上并发调用 `redis`；命令排队并按顺序处理：

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

两个 worker 都在同一个连接上 pipeline 命令。OS 线程从不阻塞；每个 worker 暂停在 `receive` 中，并在 reply 到达后恢复。这是在 Igropyr 中使用 Redis 的惯用方式。

#### Transactions

Redis transaction（`MULTI`、`EXEC`）正常工作：

```scheme
(redis redis-server "MULTI")                    ; -> "OK"
(redis redis-server "SET" "x" "1")              ; -> "QUEUED"
(redis redis-server "SET" "y" "2")              ; -> "QUEUED"
(redis redis-server "EXEC")                     ; -> ("OK" "OK")
```

### MySQL

MySQL client 同样是每个连接一个绿色进程。query 是同步的（调用者暂停直到 reply）。

#### 基本用法

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

返回值：

- **SELECT**：`#(rows ,column-names ,rows)`，其中 `rows` 是 list of lists。
- **INSERT/UPDATE/DELETE**：`#(ok ,affected ,last-insert-id)`。
- **Values**：string（MySQL text protocol）。`NULL` → `#f`。numeric string 不会转换。

**错误**：在调用者中 raise `#(mysql-error ,code ,message)`。

#### Authentication

MySQL 9 默认使用 `caching_sha2_password`。Igropyr 支持：

1. **Fast path**：SHA-256 scramble（默认）。不需要 server 配置。
2. **Full path**：server 的 RSA public key 在明文连接上加密密码（OAEP）。fast path 失败时使用。

对于较旧 server，也通过 auth-switch 支持 `mysql_native_password`。

full path 在明文连接上默认被拒绝，因为 MITM 可能替换 server key。应 pin key，
或仅在 TLS 或可信网络上显式 opt in：

```scheme
(mysql-connect host port user password database
  '((server-public-key . "-----BEGIN PUBLIC KEY-----...")))
(mysql-connect host port user password database
  '((allow-insecure-auth . #t)))
```

**安全说明**：远程连接始终应使用 TLS。

#### Connection Pool

对于有很多并发 worker 的应用，可以使用 `mysql-pool` 而不是单连接：

```scheme
(define pool (mysql-pool 8 "127.0.0.1" 3306 "user" "password" "mydb"))
;; 创建包含 8 个连接的 pool

;; Worker 查询 pool；会分配 idle connection：
(mysql-query pool "SELECT * FROM users")

;; 完成后，connection 返回 pool。
;; Pool 会自愈：如果连接死亡，下次使用时会替换。
```

#### Handler 中的异步数据库访问示例

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

从 HTTP 视角看，数据库 query 是非阻塞的：worker 的进程暂停在 `receive` 中，但 OS 线程继续通过其它 worker 和连接服务其它请求。

---

## 运行和构建

### 环境变量

运行 Igropyr 前，设置这两个环境变量：

```bash
export CHEZSCHEMELIBDIRS=.:lib:/Users/guenchi/Scheme/lib
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
```

- **CHEZSCHEMELIBDIRS**：R6RS library 搜索目录的 colon-separated list。包含 `.` 以搜索当前目录。
- **CHEZSCHEMELIBEXTS**：文件扩展名及其 compiled form（`.so`）的 colon-separated list。Chez 会按顺序尝试每个扩展名。

Igropyr 对所有 source file 使用 `.sc` 扩展名。library search 会找到 `igropyr/libuv.sc`、`igropyr/actor.sc` 等。

### 目录大小写

在大小写敏感文件系统（Linux）上，目录名必须精确匹配 library 名。Igropyr 的 library 是小写 `igropyr.*`，因此目录必须命名为 `igropyr`，不能是 `Igropyr`。

macOS 默认大小写不敏感，不会强制这一点，但保持一致是好习惯。

### File Descriptors Limit

libuv 的 TCP listen/accept 会为每个打开连接使用一个 file descriptor。OS 默认值通常是 256（macOS）或 1024（Linux）。压力测试或生产高负载时，需要提高它：

```bash
ulimit -n 10240
```

然后运行应用。否则在约 200 个连接后会遇到 "too many open files"。

### 运行应用

```bash
# 设置环境
export CHEZSCHEMELIBDIRS=.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
ulimit -n 10240

# 运行
scheme --script myapp.sc
```

脚本应在末尾调用 `(start-scheduler thunk)`。scheduler 永不返回；在前台运行，或用 process supervisor（systemd、supervisor 等）包装。

### Native Libraries 和支持平台

Igropyr 支持 macOS 和 Linux 上的 Chez Scheme 10，架构为 x86_64 和 arm64。
内部 platform layer 会自动选择正确的 ABI layout，并从标准 shared-object 名称加载 libuv、zlib 和系统 C library。
不支持的 machine type 会在 import 期间失败，并列出期望的平台。

```bash
# macOS
brew install chezscheme libuv

# Debian/Ubuntu
sudo apt-get install chezscheme libuv1-dev zlib1g-dev
```

### 从源码构建（进阶）

Igropyr 是纯 Scheme，没有必需 build step。所有 `.sc` 文件都由 Chez Scheme 在 runtime 解释执行。如果想预编译 library 以加快启动：

```bash
# 分库优化构建
chez --libdirs .:lib --script igropyr/build.ss

# Whole-program 优化构建
chez --libdirs .:lib --script igropyr/build-whole.ss
```

之后 Chez 会加载 `.chezscheme.so` 而不是 `.sc`。这可以减少启动时间，但不是必需的。

---

## 测试

### Smoke Tests

test 目录包含自断言 regression test 和交互式 smoke/demo server。运行所有自动检查：

```sh
./igropyr/test/run-all.sh
```

该套件验证所有 library import、actor scheduler、异步文件读取（空文件、多 chunk、缺失文件）、真实 TCP 上的 HTTP framing/trailers/query parsing，以及可观察的 boot failure。GitHub Actions 在 macOS 和 Ubuntu 上运行相同入口。

`smoke-echo.sc`、`smoke-echo-actor.sc` 和 `run-otp.sc` 仍保留为可手工探索和压测的交互式 server。

然后在另一个 terminal 中：

```bash
# 测试 route
curl localhost:8080/

# 压力测试（Apache Bench）
ab -n 50000 -c 500 http://127.0.0.1:8080/

# 测试半发送请求（应 timeout 并被回收）：
printf 'GET / HTTP/1.1\r\nHost: x' | nc 127.0.0.1 8080 &

# 测试 stuck worker recovery：
for i in $(seq 8); do curl -m 2 localhost:8080/stuck & done
# 应在 35 秒内恢复（30s stuck timeout + 一些 overhead）

# 测试 crash recovery：
curl localhost:8080/crash       # 4 次 attempt 后返回 500
curl localhost:8080/            # 仍然工作
```

### 编写新测试

创建一个 test script：

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
    ;; Test 1：简单 spawn 和 send
    (let ((p (spawn (lambda ()
                      (receive
                        (`(hello ,x) x))))))
      (send p '(hello 42))
      (assert (process-alive? p) "Process should be alive after send")
      (sleep-ms 100))
    
    ;; Test 2：HTTP handler
    (define app (create-app))
    (app-get app "/test"
      (lambda (req res)
        (send-json! res (list (cons 'ok #t)))))
    (app-listen app 8888)
    
    ;; Test 3：通过 curl 查询（真实测试中应使用 Scheme HTTP client）
    ;; curl localhost:8888/test
    
    (display (string-append "Tests: " (number->string failures) " failed\n"))
    (if (= failures 0)
        (begin (display "All tests passed\n") (exit 0))
        (exit 1))))
```

运行：

```bash
scheme --script test-myfeature.sc
echo $?  # Exit code 0 = success
```

### Load Testing

并发压测可使用 Apache Bench 或 `wrk`：

```bash
# 50,000 requests, 500 concurrent
ab -n 50000 -c 500 http://localhost:8080/

# 或 wrk（更复杂）
wrk -t 4 -c 500 -d 30s http://localhost:8080/
```

通过 `/stats` endpoint 观察 supervisor 的 pool state：

```bash
watch -n 1 'curl -s localhost:8080/stats | jq'
```

---

## 代码风格

### 只使用圆括号

Igropyr 代码只使用圆括号 `()`。不要使用方括号 `[]`。

```scheme
;; ✓ Correct
(let ((x 1)) x)
(lambda (x) x)
(define (foo x) x)

;; ✗ Wrong
(let ([x 1]) x)
(lambda [x] x)
(define [foo x] x)
```

方括号在深层嵌套代码中容易混淆。统一风格可以避免配对错误。这是项目级不变量。

### 英文注释

所有注释都使用英文。使用清晰、简洁的语言。注释解释 *why*，不要解释 *what*（代码已经说明 what）。

```scheme
;; ✓ Good
;; Skip whitespace at the start of the input; return the position of
;; the first non-whitespace character.
(define (skip-ws s i)
  (if (and (< i (string-length s))
           (char-whitespace? (string-ref s i)))
      (skip-ws s (+ i 1))
      i))

;; ✗ Poor
(define (skip-ws s i)
  ;; Check if character is whitespace
  (if (and (< i (string-length s))
           ;; Get the character
           (char-whitespace? (string-ref s i)))
      ;; Increment i and recurse
      (skip-ws s (+ i 1))
      ;; Return i
      i))
```

### 文件头

源文件应以 library declaration 和 module docstring 开头：

```scheme
#!chezscheme
;;; (igropyr mylib) -- brief description of what this library does.
;;;
;;; Longer explanation: key concepts, entry points, assumptions.
;;;
;;; Example usage:
;;;   (import (igropyr mylib))
;;;   (my-function 42)

(library (igropyr mylib)
  (export my-function another-function)
  (import (chezscheme))
  
  ;; ... implementation
)
```

当代码使用 Chez-specific feature（例如 `@` identifier、`#%$` primitive）时，`#!chezscheme` header 是必需的。

### R6RS Libraries

所有代码都使用 R6RS library form。使用显式 import 和 export。避免 top-level mutation（在 library 内部使用 private state，或在进程中共享状态；不要使用 library variable）。

### `.sc` 后缀

Igropyr 的全部源文件刻意使用 `.sc` 后缀。作者倡导以 `.sc` 表明意图：代码遵循严格的 R6RS 语义、面向生产环境——以区别于 `.scm` 的"什么方言都可能"和 Chez 私有味道的 `.ss`。展望未来，本项目（很可能）会迈向 R7RS Large。

### 命名约定

- **Predicate** 以 `?` 结尾：`process-alive?`、`queue-empty?`
- **Mutator** 以 `!` 结尾：`send!`、`set-header!`、`hashtable-set!`
- **Constructor** 以 `make-` 开头：`make-queue`、`make-pcb`
- **Record accessor** 不加额外标记：`queue-next`、`pcb-id`
- **Library name** 使用小写和 hyphen：`(igropyr actor)`、`(igropyr http)`

---

## 常见陷阱

### 带 Timeout 的 Receive 必须放在第一位

`receive` macro 只有在第一项才识别 `(after ms ...)`。放在其它位置不会工作：

```scheme
;; ✓ Correct
(receive
  ((after 5000 (display "timeout\n")))
  (`(message ,x) x))

;; ✗ Wrong - timeout 被忽略
(receive
  (`(message ,x) x)
  ((after 5000 (display "timeout\n"))))
```

### 在 libuv Callback 中 Yield

绝不要在 callback 中调用 `receive`、`send`（blocking）或 `raise`。只能通过内部 deliver mechanism 发送消息。

检查 stack trace 中是否有 `on-read`、`on-write`、`on-connection` 等函数名。如果看到了，说明你在 callback context 中。

### Receive Pattern 中的 Unquote 语法

在 pattern 中使用 backtick（`` ` ``）做 quasiquote，使用 comma（`,`）做 unquote：

```scheme
;; ✓ Correct
(receive
  (`(ping ,from) (send from 'pong)))

;; ✗ Wrong - 不会匹配
(receive
  ((ping from) (send from 'pong)))
```

### 跨 Library 可变状态的 Box-and-Identifier-Syntax

如果两个 library 需要共享可变状态（少见，应避免），一个 library 应把它包在 box 中，并使用 identifier-syntax 共享：

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
;; counter-ref 现在可以像变量一样使用
(set! counter-ref (+ counter-ref 1))
```

否则，跨 library boundary 直接引用被赋值的 library variable 会报错（R6RS 规则）。

### 大整数运算

`fxand`、`fxor` 等只适用于 fixnum（64-bit Chez 通常是 61-bit）。对于大整数，使用 `(chezscheme)` 中的 `bitwise-and`、`bitwise-or` 等：

```scheme
;; ✓ Large integers
(bitwise-and big-num #xFF)

;; ✗ Fixnum only
(fxand big-num #xFF)  ; 如果 big-num > 2^60，会 raise error
```

### 多字节 UTF-8 Percent Decoding

解码 percent-encoded URL 时，`%XX` 表示 octet，不是 character。像 `%E4%B8%AD`（"中" 的 UTF-8）这样的多字节 UTF-8 sequence，必须先收集为 bytes，再整体 decode：

```scheme
;; ✓ Correct - 收集 bytes，然后 decode
(let ((bytes (make-bytevector 3)))
  (bytevector-u8-set! bytes 0 #xE4)
  (bytevector-u8-set! bytes 1 #xB8)
  (bytevector-u8-set! bytes 2 #xAD)
  (utf8->string bytes))  ; -> "中"

;; ✗ Wrong - 把每个 %XX 解码为一个 character
(string-append (string (integer->char #xE4))
               (string (integer->char #xB8))
               (string (integer->char #xAD)))  ; -> mojibake
```

`(igropyr http)` 中的 `percent-decode` 正确处理了这一点。

### 深层嵌套中的括号配对

使用带括号匹配或 linting 的编辑器。如果怀疑不平衡，用 awk 计数：

```bash
# 统计文件中开括号和闭括号数量
awk 'BEGIN{o=0;c=0} {o+=gsub(/\(/,$0); c+=gsub(/\)/,$0)} END{print "Open:",o,"Close:",c}' file.sc
```

如果数量不匹配，文件有语法错误。检查 mismatched quote 或未闭合 comment。

### Process Registry Lookups

`whereis` 在进程未注册时返回 `#f`。始终 guard 结果：

```scheme
;; ✓ Correct
(let ((logger (whereis 'logger)))
  (when logger (send logger msg)))

;; ✗ Wrong - logger 未注册时 crash
(send (whereis 'logger) msg)  ; 向 #f 发送，会 raise error
```

### Crash 和 Retry 中的 Task Context Loss

task crash 并重试时，handler 会再次以相同的 `req` 和 `res` 对象调用。避免 handler 中的副作用：

```scheme
;; ✓ Safe（无状态）
(app-get app "/users/:id"
  (lambda (req res)
    (send-json! res (list (cons 'id (req-param req "id"))))))

;; ✗ Unsafe（retry 时副作用会发生两次）
(define call-count 0)
(app-get app "/users/:id"
  (lambda (req res)
    (set! call-count (+ call-count 1))
    (send-json! res (list (cons 'calls call-count)))))
```

如果副作用必须只发生一次，使用 process-local state（例如 gen-server）或数据库。

---

## 附录：性能建议

### Connection Pooling

数据库客户端应使用 connection pool（MySQL 直接支持；Redis 可以用多个连接包装一个 round-robin dispatcher）。

### Worker Count

默认 8 个 worker 针对单 CPU core 调优。多 core 系统可以增加它（不过 Igropyr 的所有 worker 都运行在一个 OS 线程上，所以瓶颈是 CPU，不是 I/O）。

### Memory

每个绿色进程约 1 KB metadata。数千个进程是可行的。主要内存使用来自 request/response body buffer。保持合理 body size limit（HTTP 默认 1 MB，WebSocket 默认 8 MB）。

### Monitoring

使用 `/stats` 和进程级工具（`top`、Activity Monitor）观察 CPU、内存和 open file descriptor。stuck worker（由 supervisor 检测）应该很少见；如果频繁出现，说明 handler 有 blocking operation。

---

## 延伸阅读

- Chez Scheme documentation: https://cisco.github.io/ChezScheme/
- libuv documentation: https://docs.libuv.org/
- R6RS Scheme specification: https://r6rs.org/
- Erlang/OTP documentation: https://erlang.org/doc/

---

*Last updated: 2026-07-10*
