# Igropyr 开发者指南

[English](DEVELOPING.md) | **简体中文**

本文面向需要阅读核心实现、扩展协议层或向 Igropyr 贡献代码的开发者。快速使用方法请先阅读[中文 README](README.zh-CN.md)。

## 目录

- [架构概览](#架构概览)
- [Actor 模型](#actor-模型)
- [核心不变量：libuv callback 中禁止 yield](#核心不变量libuv-callback-中禁止-yield)
- [编写 HTTP handler](#编写-http-handler)
- [容错机制](#容错机制)
- [OTP 模式](#otp-模式)
- [数据库客户端](#数据库客户端)
- [运行与构建](#运行与构建)
- [测试](#测试)
- [代码规范](#代码规范)
- [常见陷阱](#常见陷阱)
- [性能建议](#性能建议)

## 架构概览

Igropyr 自底向上分为以下层次：

```text
┌─────────────────────────────────────────────────────────────┐
│ 应用：路由、业务服务、WebSocket session                     │
├─────────────────────────────────────────────────────────────┤
│ express.sc：router、middleware、静态文件、SSE、表单/Cookie │
├─────────────────────────────────────────────────────────────┤
│ http.sc / websocket.sc：HTTP/1.1 与 RFC 6455               │
├─────────────────────────────────────────────────────────────┤
│ otp.sc / gen-server.sc / pubsub.sc：监督与有状态服务       │
├─────────────────────────────────────────────────────────────┤
│ actor.sc：绿色进程、邮箱、link/monitor、抢占式调度         │
├─────────────────────────────────────────────────────────────┤
│ uv.sc：libuv FFI、TCP、事件循环、foreign memory 生命周期   │
└─────────────────────────────────────────────────────────────┘
```

配套组件：

- `json.sc`：安全 JSON parser/writer。
- `redis.sc`：RESP2 客户端，一条连接支持多个调用者 pipeline。
- `mysql.sc`：MySQL text protocol、`caching_sha2_password` 和连接池。
- `build.ss`：按依赖顺序编译各 library。
- `build-whole.ss`：whole-program 编译入口。

### 各层职责

- **uv** 只做 I/O、foreign memory 管理和消息投递，不理解绿色进程调度和 HTTP。
- **actor** 提供调度、邮箱、进程关系和超时，不理解 TCP 协议。
- **http** 拥有 request framing、keep-alive、pipelining、worker pool 接入和 response 生命周期。
- **express** 只实现框架能力，可以被其它框架替换。
- **业务代码** 不应直接操作 libuv handle；应通过 request、response、WebSocket 或数据库客户端工作。

### 一个 HTTP 请求的数据流

```text
libuv read callback
  │ 复制输入 bytevector，并投递 #(tcp-data ...)
  ▼
连接 reader 绿色进程
  │ 增量解析 request line / headers / body
  ▼
worker-pool supervisor
  │ 分配给空闲 worker
  ▼
handler(req, res)
  │ send-response! -> tcp-write!
  ▼
libuv write callback
  │ 通知 reader 继续解析下一请求或关闭连接
  ▼
keep-alive 下一请求
```

每个请求都拥有独立 response token。旧任务、重试任务或 fallback 无法写入后续 keep-alive 请求的响应窗口。

## Actor 模型

### 核心概念

- **pid**：绿色进程的不透明标识。
- **mailbox**：每个进程私有的消息队列。
- **send**：立即入队，不等待接收方处理。
- **receive**：选择性匹配邮箱中的消息；未匹配消息保留。
- **link**：双向失败传播关系。
- **monitor**：单向死亡通知，不会自动连带退出。
- **scheduler**：单 OS 线程上的抢占式绿色进程调度器。

进程之间应通过消息传递共享信息，不要通过顶层可变变量共享业务状态。

### API 参考

#### `(spawn thunk) → pid`

创建绿色进程并放入 runnable queue。`thunk` 返回或抛出未捕获异常时进程退出。

```scheme
(define counter
  (spawn
    (lambda ()
      (let loop ((n 0))
        (receive
          (`(inc) (loop (+ n 1)))
          (`(get ,from)
           (send from (vector 'value n))
           (loop n)))))))
```

#### `(send pid message) → void`

非阻塞地把消息放入目标邮箱。

```scheme
(send counter '(inc))
(send counter (vector 'get self))
```

#### `(receive clause ...)`

阻塞当前绿色进程，直到某条消息与 pattern 匹配。使用 quasiquote 和 unquote 提取字段：

```scheme
(receive
  (`#(value ,n) n)
  (`#(error ,reason) (raise reason)))
```

带 timeout 时，`after` 必须放在第一项：

```scheme
(receive (after 5000 (raise 'timeout))
  (`#(reply ,value) value))
```

timeout 单位为毫秒。`(after 'infinity ...)` 可用于无期限等待。

#### `self`

`self` 是当前进程 pid，可直接放入请求消息：

```scheme
(send server (vector 'work item self))
```

#### `(link pid) → void`

建立双向 link。默认情况下，一方异常退出会让另一方退出。设置 trap-exit 后会改为接收 `#(EXIT ,pid ,reason)`。

```scheme
(process-trap-exit #t)
(link child)
(receive
  (`#(EXIT ,pid ,reason)
   (display "child exited\n")))
```

#### `(monitor pid) → void`

建立单向监控。目标退出时收到 `#(DOWN ,pid ,reason)`，监控者本身不会退出。

```scheme
(monitor database-pid)
(receive
  (`#(DOWN ,pid ,reason)
   (display "database process stopped\n")))
```

#### `(demonitor pid) → void`

取消监控，并丢弃待处理的对应 `DOWN` 消息。

#### `(process-trap-exit flag) → void`

`#t` 表示将 linked process 的退出转换成普通 `EXIT` 消息；`#f` 恢复默认失败传播。

#### `(kill pid reason) → void`

使用任意 Scheme 值作为 reason 终止进程。目标会从调度队列和注册表移除，并通知 link/monitor。

#### `(register name pid) → pid`

使用 symbol 注册进程名称：

```scheme
(register 'logger logger-pid)
```

#### `(unregister name) → void`

从全局注册表移除名称。

#### `(whereis name) → pid | #f`

查找已注册进程。调用方必须处理 `#f`：

```scheme
(let ((logger (whereis 'logger)))
  (when logger (send logger msg)))
```

#### `(process-alive? pid) → boolean`

判断进程是否仍在运行。

#### `(sleep-ms ms) → void`

挂起当前绿色进程至少指定毫秒，不阻塞 OS 线程。

#### `(process-id pid) → integer`

返回用于日志和调试的内部整数 ID。

#### `(start-scheduler thunk) → never`

初始化 libuv、启动事件循环并执行 boot thunk。应用入口应以它结束：

```scheme
(start-scheduler
  (lambda ()
    (app-listen app 8080)))
```

## 核心不变量：libuv callback 中禁止 yield

> 从 `uv-poll!` 进入的 libuv callback 绝不能调用 `yield`、`receive`、`sleep-ms` 或 `raise`。callback 只能复制数据、维护 registry、更新简单状态并投递消息。

### 原因

libuv callback 运行在 C 调用栈中。跨 C frame 捕获或恢复 Scheme continuation 会跳过 C frame 的正常清理，可能导致栈损坏、重复释放、锁未释放或随机崩溃。

### callback 范围

- `on-connection`：新连接到达。
- `on-read`：收到数据、EOF 或 socket error。
- `on-write`：异步写完成。
- `on-close`：handle 已关闭，可释放 foreign memory。
- `on-timer`：libuv timer 到期。

这些 callback 中不要直接运行用户 handler，也不要等待其它进程。

### 安全模式

```scheme
;; callback 中：复制数据并投递，不等待
(let ((copy (make-bytevector nread)))
  (memcpy-from-c copy source nread)
  (deliver owner (vector 'tcp-data copy)))
```

真正的解析和业务逻辑放在绿色进程中：

```scheme
(let loop ((buffer empty-bv))
  (receive
    (`#(tcp-data ,chunk)
     (loop (bv-append buffer chunk)))
    (`#(tcp-eof) (finish))))
```

若看到 continuation 跨 C code 的异常、随机 segfault，或堆栈中包含 `on-read`/`on-write`/`on-connection`，首先检查 callback 是否间接调用了会 yield 的函数。

## 编写 HTTP handler

### 使用 Express 层

```scheme
(import (chezscheme)
        (igropyr actor)
        (igropyr http)
        (igropyr express))

(define app (create-app))

(app-get app "/users/:id"
  (lambda (req res)
    (let ((id (req-param req "id"))
          (verbose? (assoc "verbose" (req-query req))))
      (send-json! res
        (list (cons 'user id)
              (cons 'verbose (and verbose? #t)))))))

(app-post app "/api/data"
  (lambda (req res)
    (let ((body (req-json req)))
      (if body
          (send-json! res (list (cons 'echo body)))
          (begin
            (set-status! res 400)
            (send-json! res '((error . "bad json"))))))))
```

`app-put`、`app-delete` 与上面相同。`app-get-fast`、`app-post-fast`、`app-put-fast`、`app-delete-fast` 只适合纯函数且快速返回的 handler。

### 路径参数和 query

路由中的 `:name` 捕获一个路径段：

```scheme
(app-get app "/blog/:year/:slug"
  (lambda (req res)
    (send-text! res
      (string-append (req-param req "year") "/"
                     (req-param req "slug")))))
```

`(req-query req)` 返回解码后的字符串 alist。query 中 `+` 代表空格；URL path 中 `+` 保持字面含义。值只在第一个 `=` 处分割。

### Request API

- `(req-method req)`：method symbol。
- `(req-path req)`：已解码路径。
- `(req-query req)`：query alist。
- `(req-headers req)`：`(symbol . string)` alist，header 名为小写。
- `(req-header req 'name)`：单个 header 值或 `#f`。
- `(req-body req)`：已完成 framing 解码的 bytevector。
- `(req-keep-alive? req)`：连接是否保持。
- `(req-param req "name")`：Express 路由参数。
- `(req-json req)`：解析后的 JSON，失败时为 `#f`。
- `(req-form req)`：urlencoded/multipart alist。
- `(req-cookie req "name")`：Cookie 值或 `#f`。

默认 HTTP body 上限为 1 MiB，header/trailer 上限为 8 KiB。非法 `Content-Length`、冲突 framing 或不支持的 `Transfer-Encoding` 会返回 `400` 并关闭连接。

### Response API

- `(set-status! res code)`：默认状态为 `200`。
- `(set-header! res "Name" "value")`：设置额外 header。
- `(res-send! res bytevector)`：核心一次性发送。
- `(send-text! res string)`：`text/plain; charset=utf-8`。
- `(send-html! res string)`：`text/html; charset=utf-8`。
- `(send-json! res value)`：JSON。
- `(send-file! res path)`：按扩展名选择 MIME。
- `(set-cookie! res name value attributes ...)`：追加 Cookie。

响应 header 名必须符合 HTTP token 规则，值不得包含 CR、LF 或 NUL。框架统一管理 `Content-Length`、`Connection` 和 `Transfer-Encoding`。

### 流式响应

```scheme
(app-get app "/stream"
  (lambda (req res)
    (set-header! res "Content-Type" "text/plain")
    (res-begin! res)
    (spawn
      (lambda ()
        (when (res-write! res "line 1\n")
          (sleep-ms 100)
          (res-write! res "line 2\n"))
        (res-end! res)))))
```

长 producer 必须 `spawn` 出去，否则会占用 worker。连接关闭后 `res-write!` 返回 `#f`，producer 应停止。

### SSE

```scheme
(app-get app "/events"
  (lambda (req res)
    (sse-start! res)
    (spawn
      (lambda ()
        (let loop ((i 1))
          (if (and (<= i 5)
                   (sse-send! res
                     (string-append "event " (number->string i))))
              (begin (sleep-ms 1000) (loop (+ i 1)))
              (res-end! res)))))))
```

### WebSocket

```scheme
(app-ws app "/ws"
  (lambda (ws req)
    (let loop ()
      (let ((frame (ws-recv ws)))
        (case (vector-ref frame 0)
          ((text)
           (ws-send-text! ws (vector-ref frame 1))
           (loop))
          ((binary)
           (ws-send-binary! ws (vector-ref frame 1))
           (loop))
          (else (ws-close! ws)))))))
```

客户端 frame 必须 masked。RSV、opcode、control frame、continuation 顺序和长度都会校验；协议错误使用 `1002`，UTF-8 错误使用 `1007`，消息过大使用 `1009`。

### 中间件

中间件签名为 `(lambda (req res next) ...)`。发送响应后不要调用 `next`。

```scheme
(app-use app
  (lambda (req res next)
    (display (symbol->string (req-method req)))
    (display " ")
    (display (req-path req))
    (newline)
    (next)))

(app-use app
  (lambda (req res next)
    (if (req-header req 'authorization)
        (next)
        (begin
          (set-status! res 403)
          (send-text! res "Forbidden")))))
```

中间件按注册顺序包裹路由。

### 静态文件

```scheme
(app-static app "/assets" "./public")
```

挂载使用路径段边界匹配。URL 解码后的 `..`、NUL 和挂载根目录内的符号链接会被拒绝，避免访问 root 外的文件。静态文件当前在 worker 中整文件读取，适合小型本地资源，不适合充当大文件服务器。

### 启动与配置

```scheme
(start-scheduler
  (lambda ()
    (define srv
      (app-listen app 8080
        '((workers . 16)
          (max-retries . 2)
          (stuck-ms . 60000)
          (check-ms . 10000))))
    srv))
```

所有数值选项必须是合理的精确整数：worker 数量、`stuck-ms`、`check-ms` 必须大于 0；`max-retries` 不能小于 0。

### 直接使用 HTTP 核心

```scheme
(start-scheduler
  (lambda ()
    (http-listen 8080
      (lambda (req res)
        (case (req-method req)
          ((GET)
           (set-header! res "Content-Type" "text/plain")
           (res-send! res (string->utf8 "hello")))
          (else
           (set-status! res 405)
           (res-send! res (string->utf8 "method not allowed"))))))))
```

核心和 Express 使用相同 request/response record。自定义框架可使用 request 的 `req-params` 槽保存路由上下文。

## 容错机制

Igropyr 使用固定 worker pool 和 supervisor 实现 Let-It-Crash。

### pool 状态

- **idle**：等待任务的 worker。
- **busy**：正在执行任务，以及开始时间。
- **pending**：等待空闲 worker 的 FIFO。
- **attempts**：任务已经崩溃重试的次数。

### worker 崩溃

1. handler 抛出未捕获异常，worker 退出。
2. supervisor 通过 `#(DOWN ,worker ,reason)` 得知退出。
3. 创建替代 worker，保持 pool 大小。
4. 若未超过 `max-retries`，将原 task 放回队列前端。
5. 超过次数后调用 `fail-task`，HTTP 层通常发送 `500`。

默认 `max-retries=3`，因此任务最多执行 4 次。包含外部副作用的 handler 必须幂等。

### 卡死检测

ticker 每 `check-ms` 发送一次检查消息。busy 时间超过 `stuck-ms` 的 worker 会被 `kill`；该任务不重试，以免无限循环再次占满 pool。supervisor 随后补充 worker 并执行 fallback。

### 已响应请求

每个 request token 只能 claim 一次。handler 已开始发送普通或流式响应后，即使 worker 随后崩溃，fallback 也不会重复写入连接。

### 监控 pool

```scheme
(define srv (app-listen app 8080))
(http-stats srv)
;; => ((connections . ...)
;;     (requests . ...)
;;     (uptime-ms . ...)
;;     (idle . ...) (busy . ...) (pending . ...))
```

### 已知错误与未知错误

可预期的输入错误应由 handler 捕获并返回 `4xx`；不变量破坏和未知异常应允许 worker 崩溃，由 supervisor 处理。

```scheme
(app-get app "/divide/:a/:b"
  (lambda (req res)
    (let ((a (string->number (req-param req "a")))
          (b (string->number (req-param req "b"))))
      (if (or (not a) (not b) (zero? b))
          (begin
            (set-status! res 400)
            (send-json! res '((error . "invalid operands"))))
          (send-json! res (list (cons 'result (/ a b))))))))
```

## OTP 模式

### gen-server

`gen-server` 管理状态，并统一实现同步 call、异步 cast、timeout 和 server 死亡检测。

```scheme
(import (igropyr gen-server))

(define counter
  (gen-server-start
    (lambda () 0)
    ;; handle-call: msg from state -> reply new-state
    (lambda (msg from state)
      (case msg
        ((inc)
         (let ((next (+ state 1)))
           (values next next)))
        ((get) (values state state))
        (else (values 'unknown state))))
    ;; handle-cast: msg state -> new-state
    (lambda (msg state)
      (case msg
        ((reset) 0)
        (else state)))))

(gen-server-call counter 'inc)
(gen-server-cast counter 'reset)
(gen-server-call counter 'get 10000)
```

call 默认 timeout 为 5 秒。server 崩溃时，调用方会通过 monitor 立即获得 `#(gen-server-error server-died reason)`。

需要按名称访问时：

```scheme
(gen-server-start-named 'counter init handle-call handle-cast)
(gen-server-call 'counter 'get)
```

可选的 `handle-info` callback 用于处理不属于 call/cast 的消息，例如依赖进程的 `DOWN`。

### PubSub

```scheme
(import (igropyr pubsub))

(start-pubsub!)

(spawn
  (lambda ()
    (subscribe 'room-1)
    (let loop ()
      (receive
        (`#(pub ,topic ,payload)
         (display payload)
         (loop))))))

(publish 'room-1 "hello")
(unsubscribe 'room-1)
```

PubSub server 会 monitor 订阅进程并自动清理死亡订阅者，适合 WebSocket room。

### 选择 gen-server 还是 bare spawn

使用 `gen-server`：

- 需要同步 request/reply。
- 一个进程拥有可变状态，需要串行处理并发请求。
- 希望统一获得 timeout 和 server 死亡检测。

使用 bare `spawn`：

- 进程主要由 TCP、WebSocket 等外部事件驱动。
- 只有单向消息，不需要 call/reply。
- 需要完全控制 receive loop。

## 数据库客户端

### Redis

```scheme
(import (igropyr redis))

(define redis-server (redis-connect "127.0.0.1" 6379))
(redis redis-server "SET" "name" "alice") ; => "OK"
(redis redis-server "GET" "name")         ; => "alice"
(redis redis-server "INCR" "counter")     ; => 1
(redis redis-server "GET" "missing")      ; => #f
(redis redis-server "LRANGE" "list" 0 -1) ; => ("a" "b")
(redis-close! redis-server)
```

返回值：

- simple string：字符串。
- bulk string：合法 UTF-8 返回字符串，否则返回 bytevector。
- nil：`#f`。
- integer：Scheme number。
- array：list，可递归嵌套。
- Redis error：抛出 `#(redis-error message)`。

多个进程可以并发调用同一连接。命令按 FIFO 写入，waiter 使用 request ref 关联回复。调用超时后旧回复会被消费并丢弃，不能污染下一次调用。

```scheme
(redis redis-server "MULTI")
(redis redis-server "SET" "x" "1")
(redis redis-server "SET" "y" "2")
(redis redis-server "EXEC")
```

注意：并发进程共享同一连接时，不要把跨多个命令的事务分散在不同进程中；否则其它命令可能插入事务序列。需要严格事务隔离时使用独占连接。

### MySQL

```scheme
(import (igropyr mysql))

(define db
  (mysql-connect "127.0.0.1" 3306 "user" "password" "mydb"))

(mysql-query db "SELECT id, name FROM users")
;; => #(rows ("id" "name") (("1" "Alice") ("2" "Bob")))

(mysql-query db "INSERT INTO users (name) VALUES ('Eve')")
;; => #(ok 1 3)

(mysql-close! db)
```

返回值：

- SELECT：`#(rows ,column-names ,rows)`。
- INSERT/UPDATE/DELETE：`#(ok ,affected ,last-insert-id)`。
- MySQL text protocol 字段保持字符串，`NULL` 为 `#f`。
- 错误抛出 `#(mysql-error code message)`。

#### 认证

支持 `caching_sha2_password` 快速路径和完整 RSA 路径，也支持服务端 auth-switch 到 `mysql_native_password`。

完整认证默认要求固定服务端 RSA 公钥：

```scheme
(mysql-connect host port user password "db"
  '((server-public-key . "-----BEGIN PUBLIC KEY-----...")))
```

只有本地或其它可信网络才应明确允许从明文连接获取 key：

```scheme
(mysql-connect host port user password "db"
  '((allow-insecure-auth . #t)))
```

OAEP seed 来自 `/dev/urandom`，不能改用时间种子的普通 PRNG。

#### 连接池

```scheme
(define pool
  (mysql-pool 8 "127.0.0.1" 3306 "user" "password" "mydb"))

(mysql-query pool "SELECT * FROM users")
(mysql-close! pool)
```

连接池大小是第一个参数，必须大于 0。idle connection 执行请求，繁忙时请求进入 FIFO。SQL error 不会淘汰健康连接；socket、EOF、timeout、协议解析等 transport error 会关闭连接，由 pool 重建。

每个查询携带 request ref。调用超时时会发送 cancel；繁忙连接被关闭或隔离，旧回复也不会被下一次调用误收。

#### 在 handler 中查询

```scheme
(app-get app "/users"
  (lambda (req res)
    (let ((result (mysql-query pool "SELECT id, name FROM users")))
      (send-json! res
        (map
          (lambda (row)
            (list (cons 'id (car row))
                  (cons 'name (cadr row))))
          (vector-ref result 2))))))
```

查询会挂起当前 worker 绿色进程，但 OS 线程仍可为其它连接执行 libuv I/O。

## 运行与构建

### 环境变量

从 `igropyr` 的父目录运行：

```bash
export CHEZSCHEMELIBDIRS=.:lib
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
```

- `CHEZSCHEMELIBDIRS`：R6RS library 搜索目录。
- `CHEZSCHEMELIBEXTS`：源码和编译产物扩展名的尝试顺序。

源码使用 `.sc`，因此父目录中应存在 `igropyr/uv.sc`、`igropyr/actor.sc` 等文件。Linux 大小写敏感，目录必须为小写 `igropyr`。

### 文件描述符

每条 socket 使用一个文件描述符。压测和生产环境应提高限制：

```bash
ulimit -n 10240
```

### 启动应用

```bash
export CHEZSCHEMELIBDIRS=.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
ulimit -n 10240
chez --script myapp.sc
```

脚本末尾必须调用 `start-scheduler`。生产环境可由 systemd、supervisor 或其它进程管理器托管。

### libuv 加载

`uv.sc` 会尝试：

- `libuv.1.dylib` / `libuv.dylib`
- Homebrew ARM 与 Intel 常见绝对路径
- `libuv.so.1` / `libuv.so`

系统 C library 同样按 macOS/Linux 常见 soname 探测。自定义路径应通过系统动态链接器环境配置，而不是在业务代码中硬编码。

### 编译

按 library 编译：

```bash
chez --libdirs .:lib --script igropyr/build.ss
```

whole-program 编译：

```bash
chez --libdirs .:lib --script igropyr/build-whole.ss
chez --program igropyr/app.so
```

热路径使用较高 optimize level，但必须保留 interrupt trap，因为抢占式调度依赖 timer interrupt。

## 测试

### 分层测试

- `test/smoke-actor.sc`：调度、消息、timeout、monitor、link 和抢占。
- `test/smoke-echo.sc`：裸 libuv echo。
- `test/smoke-echo-actor.sc`：每连接一个绿色进程的 echo。
- `test/run-otp.sc`：完整 HTTP/Express/OTP/WebSocket/PubSub 示例服务。
- `test/security-regression.sc`：请求 framing、header、chunked、URL、数据库 request ref、WebSocket close code 和配置校验。

从仓库父目录运行：

```bash
chez --script igropyr/test/smoke-actor.sc
chez --script igropyr/test/security-regression.sc
```

若在仓库目录内运行，设置：

```bash
CHEZSCHEMELIBDIRS=.. CHEZSCHEMELIBEXTS=.sc \
  chez --script test/security-regression.sc
```

安全回归会在本机回环地址启动临时 HTTP 服务，结束后释放端口。

### 手工验收

```bash
curl localhost:8080/
ab -n 50000 -c 500 http://127.0.0.1:8080/

# 半包请求，约 30 秒后应被回收
printf 'GET / HTTP/1.1\r\nHost: x' | nc 127.0.0.1 8080

# handler 崩溃后返回 500，服务仍可用
curl localhost:8080/crash
curl localhost:8080/

# 卡死 worker 应在 stuck-ms + check-ms 范围内恢复
for i in $(seq 8); do curl -m 2 localhost:8080/stuck & done
```

### 编写测试

测试应：

1. 使用独立端口，避免与 demo server 冲突。
2. 给所有 `receive` 配置合理 timeout，失败时以非零状态退出。
3. 覆盖原始输入，而不只测试高级 helper。
4. 对 keep-alive、pipelining 和 timeout bug 同时验证连接生命周期。
5. 完成后关闭 listener，不留下进程和端口。

### 压测

```bash
ab -n 50000 -c 500 http://localhost:8080/
wrk -t 4 -c 500 -d 30s http://localhost:8080/
watch -n 1 'curl -s localhost:8080/stats | jq'
```

压测前先确认客户端自身没有成为单核或文件描述符瓶颈。

## 代码规范

### 只使用圆括号

项目统一使用 `()`，不使用 `[]`：

```scheme
;; 正确
(let ((x 1)) x)
(lambda (x) x)

;; 错误
(let ([x 1]) x)
(lambda [x] x)
```

### 源码注释使用英文

中文文档不改变源码规范。源码注释应使用简洁英文，重点说明“为什么”，不要逐行复述代码。

```scheme
;; Good: explain the invariant and the reason.
;; Copy bytes before returning from the libuv callback because the
;; source buffer is reused by the next read.
```

### 文件头

```scheme
#!chezscheme
;;; (igropyr mylib) -- brief description.
;;;
;;; Invariants, entry points, and a short example.

(library (igropyr mylib)
  (export my-function)
  (import (chezscheme))

  ;; implementation
)
```

使用 Chez 专有语法时保留 `#!chezscheme`。所有模块采用 R6RS library form，并显式列出 import/export。

### 命名

- predicate：以 `?` 结尾，例如 `process-alive?`。
- mutator：以 `!` 结尾，例如 `set-header!`。
- constructor：以 `make-` 开头。
- record accessor：使用名词，例如 `pcb-id`。
- library：小写并使用连字符，例如 `(igropyr gen-server)`。

### 状态所有权

可变状态应归单个绿色进程所有，通过消息访问。跨 library 顶层可变变量会受到 R6RS 限制，也容易破坏容错和热更新。

## 常见陷阱

### `after` 必须是 receive 第一项

```scheme
;; 正确
(receive (after 5000 'timeout)
  (`#(reply ,v) v))

;; 错误：timeout 不会按预期展开
(receive
  (`#(reply ,v) v)
  (after 5000 'timeout))
```

### libuv callback 中 yield

不要在 callback 中调用 `receive`、`sleep-ms`、用户 handler 或可能抛出异常的复杂逻辑。通过 `deliver` 投递消息，由绿色进程继续处理。

### receive pattern 的 unquote

```scheme
(receive
  (`#(ping ,from) (send from '#(pong))))
```

反引号开始 quasiquote，逗号提取字段。普通 list 不会完成变量匹配。

### 跨 library 可变状态

若确实必须共享，可由一个 library 用 box 保存，再通过 `identifier-syntax` 暴露；更推荐创建拥有该状态的 actor。

```scheme
(define counter-cell (box 0))
(define-syntax counter-ref
  (identifier-syntax
    (unbox counter-cell)
    ((set! id value) (set-box! counter-cell value))))
```

### fixnum 与大整数

`fxand`、`fxior`、`fxsll` 等只接受 fixnum。RSA、64-bit length 等可能超出 fixnum，应使用 `bitwise-and`、`bitwise-arithmetic-shift-right` 等通用过程。

```scheme
(bitwise-and big-integer #xFF) ; 正确
;; (fxand big-integer #xFF)    ; 可能异常
```

### UTF-8 百分号解码

`%XX` 表示字节，不是 Unicode code point。必须先收集所有字节，再统一调用 `utf8->string`。例如 `%E4%B8%AD` 应解码为“中”。非法或截断的 percent escape 必须拒绝。

### header framing

- `Content-Length` 只能是非负十进制整数。
- 重复的 `Content-Length` 必须完全一致。
- `Content-Length` 与 `Transfer-Encoding` 不能同时使用。
- 不支持的 transfer coding 必须拒绝，不能当成无 body 请求。
- chunk data 后必须有 CRLF，trailer 和 pipeline buffer 必须有限制。

这些规则关系到后续 keep-alive 请求的边界，不能宽松解析。

### 括号配对

使用编辑器的 paren matching。必要时可做简单计数，但字符串和注释中的括号会让纯文本计数产生误报：

```bash
awk 'BEGIN{o=0;c=0} {o+=gsub(/\(/,$0); c+=gsub(/\)/,$0)} END{print o,c}' file.sc
```

最终应以 Chez import/compile 结果为准。

### 注册表查找

`whereis` 可能返回 `#f`，不要直接把结果传给 `send`。

### 崩溃重试与副作用

同一个 task 可能多次执行：

```scheme
;; 安全：只根据输入构造响应
(app-get app "/users/:id"
  (lambda (req res)
    (send-json! res
      (list (cons 'id (req-param req "id"))))))
```

写数据库、发邮件、扣款等副作用需要幂等 key、事务或独立服务保证，不能假设 handler 只执行一次。

### 超时后的旧回复

同步 actor API 必须为请求分配 ref，并在回复中回传。超时后仅按消息类型匹配会让旧回复污染下一次调用。MySQL/Redis 客户端会消费 stale ref，并在必要时取消或淘汰连接。

### 静态文件路径

字符串前缀不等于路径边界。`/assets-private` 不能匹配 `/assets`。URL 解码后重新检查路径段，并考虑符号链接。

## 性能建议

### 连接池

并发数据库访问使用 MySQL pool。Redis 若单连接成为瓶颈，可在应用层建立多连接并进行 round-robin；事务使用独占连接。

### worker 数量

默认 8 个 worker 适合单核事件循环的常见 I/O 工作负载。提高 worker 数量能容纳更多同时等待数据库的 handler，但不会让单进程使用多个 CPU core。

### fast route

只有没有副作用、不会阻塞、快速返回的 handler 才使用 fast route。性能收益不能替代 crash retry 和 stuck-kill。

### 内存

绿色进程本身较轻，主要内存来自请求 body、pipeline buffer、WebSocket 分片和应用响应。不要移除协议层上限；大文件应使用真正的流式 I/O。

### 多核

Linux/FreeBSD 可使用 `reuseport` 启动多个进程。跨进程状态通过 Redis 或其它外部服务协调。macOS 应由反向代理或上层负载均衡分发到不同端口。

### 监控

结合 `http-stats`、系统 CPU/内存、open file 数量和错误率观察运行状态。经常触发 stuck-kill 通常意味着 handler 内存在阻塞调用或无限计算。

## 延伸阅读

- [Chez Scheme 文档](https://cisco.github.io/ChezScheme/)
- [libuv 文档](https://docs.libuv.org/)
- [R6RS 规范](https://r6rs.org/)
- [Erlang/OTP 文档](https://www.erlang.org/doc/)

---

*最后更新：2026-07-10*
