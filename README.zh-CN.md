# Igropyr

Igropyr 是面向 [Chez Scheme](https://cisco.github.io/ChezScheme/) 的高并发 HTTP 服务器，
通过 Chez 的 FFI 直接构建在 [libuv](https://libuv.org/) 之上（没有 C shim），
提供 Erlang 风格的消息传递并发模型和 Let-It-Crash 容错能力。

- **核心 / 框架分层，类似 Node 和 Express** — 核心只暴露一个入口：
  `(http-listen port (lambda (req res) ...))`；内置的 `(igropyr express)`
  层（`create-app`、`app-get`、`send-json!` 等）是可选的，也可以在同一核心之上构建其它框架
- **绿色进程** — 在单个 OS 线程上调度数千个轻量进程；基于 continuation 做上下文切换并支持抢占，
  因此即使 handler 陷入 CPU 自旋也不会冻结整个系统
- **纯消息传递** — `spawn` / `send` / `receive` / `link` / `monitor`；
  进程之间没有共享状态
- **默认容错** — supervisor 后面有固定 worker 池：
  崩溃的 worker 会被替换，任务会重试（最多 3 次，之后客户端得到 500）；
  卡住超过 30 s 的 worker 会被杀死并替换；慢请求或半发送请求只会阻塞自己的 reader 进程
- **故障钩子（remote 重试环）** — 重试耗尽或卡死 worker 被杀后（先杀后告，
  故障响应到达时没有在途执行），可选的 `on-failure` handler 在同一条
  keep-alive 连接上回复结构化 JSON 故障码而非裸 500——客户端换参数、带状态
  重新提交，获得全新一轮重试；不配置则维持原有 500
- **对话（每对话一进程）** — 多请求对话（向导、预订、转账）作为一个绿色进程运行，
  跨轮次持有活状态——甚至一个打开的数据库事务；`suspend!` 应答并停车,
  `conversation-resume!` 继续；进程因任何原因死亡（崩溃、TTL）都意味着保证回滚：
  之后的 resume 得到 `gone`
- **热代码替换** — 在运行中的服务器上替换 handler（或单条路由）：
  listener、已有连接和 worker 池保持运行，正在处理的请求继续使用旧代码完成
- **WebSocket** — 在同一端口上执行 RFC 6455 upgrade；每个 socket 都是自己的绿色进程，
  因此 server push 就是一次消息发送
- **流式响应和 SSE** — 通过 `res-begin!`/`res-write!`/`res-end!` 写 chunked response body；
  上层提供 Server-Sent Events 辅助函数
- **OTP 构件** — `gen-server`（call/cast/info）、进程注册表（`register`/`whereis`），
  以及会自动清理死亡订阅者的 topic PubSub
- **JSON** — 安全的递归下降解析器（不用 `read`；完整处理 escape 和 surrogate）以及 writer
- **表单和 cookie** — `req-form` 解析 urlencoded 和 multipart body（包括文件上传）；
  `req-cookie` / `set-cookie!`
- **中间件套件** — cookie session（gen-server 存储、CSPRNG sid）、
  带 preflight 的 CORS、安全响应头以及访问日志
- **Chunked transfer-encoding** — `Transfer-Encoding: chunked` 请求 body 会被透明解码
- **非阻塞 Redis 和 MySQL 客户端** — 纯 Scheme，使用同一个 event loop；
  调用者只暂停自己的绿色进程，OS 线程继续服务；MySQL 带自愈连接池
- **非阻塞 HTTP 和 WebSocket 客户端** — 出站 `http-get` / `http-post` 和 `ws-connect`，
  都支持 async DNS（libuv 线程池）并使用同样的“暂停调用者”模型；`https://` / `wss://`
  由可选库 `(igropyr tls)` 提供（OpenSSL 作为字节 codec，证书经校验——本体保持零依赖）
- **静态文件服务** — 热文件来自内存缓存（一次 hashtable lookup：不读盘、不做
  `stat` 系统调用，mtime 最多每秒复查一次）。缓存未命中在 libuv 线程池上读一次，
  因此冷读不会阻塞 scheduler；超过 1 MiB 的文件按块带背压流式传输，从不整体读入
- **gzip 压缩** — 通过 `Accept-Encoding` 协商响应；静态文件会缓存压缩后的 representation
- **运维就绪** — rate limiting、全局错误处理器和 Prometheus `/metrics` endpoint
- **运行时 introspection 和优雅停机** — `http-stats`（实时连接 / 请求 / pool 计数器）、
  `http-shutdown!`（排空 in-flight 请求，拒绝新连接）
- **多进程扩展** — `SO_REUSEPORT` bind 选项，用于 Linux 上 kernel-balanced 的多进程监听
  （可配合 pm2 或 systemd）
- **分布式 actor** — 把节点连成 mesh（`(igropyr node)`）：`rsend`/`rcall`
  发给另一节点上注册的进程、`monitor-node`/`monitor-remote`、集群级 PubSub、
  分布式任务池（`(igropyr dpool)`）、以及自动发现（`(igropyr cluster)`，静态或 Redis）
- **S 表达式 RPC** — 两端都是 Scheme 时，`(igropyr sexpr)` 是安全的白名单
  codec（无 `read`、深度限制）；`app-rpc` / `send-sexpr!` / `ws-send-sexpr!`
  每条消息携带一个 datum。扩展线模式（节点间链路与浏览器客户端
  [Goeteia](https://goeteia.dev) 共用）携带 vector、bytevector（`#vu8"…"`，
  base64）和**每个 IEEE double 的原字节**（`#f8"…"`，8 字节 IEEE-754，含
  inf/nan），二进制与浮点在 Chez ↔ WebAssembly 间无损、不经十进制舍入
- **HTTP/1.1 keep-alive 和 pipelining** — 1.1 默认持久连接；
  每个连接的 reader 进程循环处理连续请求
- **快速** — 在 Apple Silicon 笔记本上，500 个并发连接约 35 k req/s
  （`ab -n 50000 -c 500`，0 个失败请求）

关于架构、actor 模型、libuv callback 不变量和贡献指南，请参阅
[手册](https://igropyr.com/manual.html?lang=zh)。

## 环境要求

- Chez Scheme 10.x
- libuv 1.x
- zlib 1.x
- x86_64/arm64 上的 macOS 或 Linux

```sh
brew install chezscheme libuv        # macOS
# apt install chezscheme libuv1-dev zlib1g-dev  # Debian/Ubuntu
```

Igropyr 会自动选择平台 ABI，并加载 libuv、zlib 和系统 C 库。
支持的 Chez machine type 是 x86_64 和 arm64 上的 macOS/Linux；
不支持的主机会在 import 时给出清晰错误。

## 快速开始

把仓库 clone 到名为 `igropyr` 的目录中（R6RS library 名称是小写；
在大小写敏感文件系统上，目录名必须匹配）：

```sh
git clone https://github.com/guenchi/Igropyr igropyr
export CHEZSCHEMELIBDIRS=.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
scheme --script igropyr/test/run-otp.sc   # 部分发行版下命令名为 `chez`
```

然后：

```sh
curl localhost:8080/
curl localhost:8080/users/42?verbose=1
curl -X POST -d 'hello' localhost:8080/echo
```

## 编写应用

使用内置的 Express 风格层。`(igropyr http)` 是核心层，重导出了面向应用的
actor 接口（`start-scheduler`、`spawn`、`receive` 等）；express、websocket
及其他组件按需插拔：

```scheme
(import (chezscheme)
        (igropyr http)
        (igropyr express))

(define app (create-app))

;; 路由：GET/POST/PUT/DELETE，支持 :param path segment
(app-get app "/hello/:name"
  (lambda (req res)
    (send-text! res (string-append "hello " (req-param req "name")))))

(app-post app "/api/data"
  (lambda (req res)
    (send-json! res (list (cons 'received (utf8->string (req-body req)))))))

;; 中间件：调用 (next) 继续执行链
(app-use app
  (lambda (req res next)
    (if (req-header req 'authorization)
        (next)
        (begin (set-status! res 403) (send-text! res "Forbidden")))))

;; 静态文件：/assets/style.css -> ./public/style.css。文件读取一次后缓存在内存中
;;（只有 mtime 变化时才重新读取，mtime 本身最多每秒复查一次），因此服务热资源
;; 是 hashtable lookup——没有磁盘读取，也没有 stat 系统调用。响应带 weak ETag 和 Cache-Control，匹配的 If-None-Match
;; 会得到 304 Not Modified。超过 1 MiB 的文件不会整体读入内存：以定长响应
;; （Content-Length）按 64 KiB 分块流式发送，且带背压——上一块写完才读下一块，
;; 慢客户端下载 10 GB 也只占一块内存；worker 立即释放（泵在独立进程里跑）。
(app-static app "/assets" "./public")

;; 进入 scheduler 并监听；永不返回
(start-scheduler
  (lambda ()
    (app-listen app 8080 8)))   ; 端口 8080，8 个 worker（默认 8）
```

pool 及其容错行为可配置；传入 alist 代替 worker 数量即可
（任意 key 都可省略；下面是默认值）：

```scheme
(app-listen app 8080
  '((workers . 8)         ; pool 大小
    (max-retries . 3)     ; 每个任务的崩溃重试次数，之后返回 500
    (stuck-ms . 30000)    ; 忙碌超过此时间 => kill 并替换
    (check-ms . 5000)))   ; ticker 检查卡住 worker 的频率
```

### Request accessors

| Procedure | Result |
|---|---|
| `(req-method req)` | method symbol：`GET`、`POST` 等 |
| `(req-path req)` | 已解码的 path string |
| `(req-param req "id")` | `:param` path segment 的值，或 `#f` |
| `(req-query req)` | query string，以 string alist 表示 |
| `(req-header req 'content-type)` | header value（key 为小写 symbol），或 `#f` |
| `(req-body req)` | request body，bytevector |

### Response helpers

先设置 status 和额外 header，然后只发送一次：

```scheme
(set-status! res 201)               ; 核心 primitive
(set-header! res "X-Request-Id" "abc")
(send-text! res "created")     ; text/plain        (express)
(send-html! res "<h1>hi</h1>") ; text/html         (express)
(send-json! res obj)           ; alist -> object, list -> array (express)
(send-file! res "path/to/f")   ; MIME type from extension       (express)
```

同一请求的第二次发送会被忽略，因此 supervisor fallback 永远不会破坏已经发出的响应。

每个编码器也接受 bytevector，视为已编码好的响应体。对于内容不变的响应，
应当在**启动时用 `define` 编码一次**，而不是每个请求重复编码同一个常量——
handler 只需把指针交给框架：

```scheme
(define home-page (string->utf8 "<h1>hi</h1>"))           ; 只编码一次
(define info-json (string->utf8 (json->string my-alist))) ; 只序列化一次

(app-get app "/"     (lambda (req res) (send-html! res home-page)))
(app-get app "/info" (lambda (req res) (send-json! res info-json)))
```

一切能在启动时算出的东西（渲染好的模板、查找表、拼接好的字符串）都同理：
在顶层 `define` 里算好，不要放在 handler 里。

## 核心 API（构建自己的框架）

核心与框架无关，类似 Node 的 `http` module：它负责 parsing、连接、worker pool 和 response encoding，
并接收一个 handler。它重导出了面向应用的 actor 接口，因此单个 import 即可。
express 做的所有事情都可以在用户空间表达：

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

核心 primitive：`set-status!`、`set-header!`、`res-send!`
（body bytevector；Content-Length、Connection 和 one-shot guard 都由核心处理）。
Request accessor 如上，但不包括 `req-param`（route params 是框架关注点；
核心 request 带一个供上层使用的自由 `req-params` slot）。下面的容错语义属于核心，
无论上层放什么 layer 都一样。

## 热代码替换

两层都支持 zero-downtime（listener、已有连接和 worker pool 不受影响；
已经执行中的请求使用旧代码完成）：

- **Route level（express）**：注册已存在的 route 会在 live app 上*替换*它。
  对运行中的 app 重新求值 routes file 就是 hot reload：

  ```scheme
  (app-get app "/version" v2-handler)   ; 替换旧 /version
  ```

- **Handler level（core）**：`app-listen` / `http-listen` 返回 server；
  可以原子替换整个 handler，甚至换成不同的 framework layer：

  ```scheme
  (define srv (app-listen app 8080))
  (http-swap! srv (app->handler another-app))
  (http-set-ws! srv another-ws-resolver)
  ```

在 demo server 上试试：`GET /version` 返回 `v1`；`GET /upgrade`
替换 route；之后 `GET /version` 返回 `v2 (hot swapped)`。

## WebSocket

通过标准 upgrade handshake 在同一端口服务。每个连接运行在自己的绿色进程中；
`ws-recv` 只阻塞该进程。Ping 会自动回复，fragmented message 会自动重组。

```scheme
(import (igropyr websocket))

(app-ws app "/ws"                      ; 这里也支持 :param segment
  (lambda (ws req)
    (ws-send-text! ws "welcome")
    (let loop ()
      (let ((m (ws-recv ws)))          ; #(text s) | #(binary bv) | #(close)
        (case (vector-ref m 0)
          ((text) (ws-send-text! ws (vector-ref m 1)) (loop))
          ((binary) (ws-send-binary! ws (vector-ref m 1)) (loop))
          (else 'closed))))))
```

其它进程做 server push：把 `ws`（或它的 pid）交给它们并调用 `ws-send-text!`；
从任何绿色进程写入都是安全的。在 bare core 上，用
`(http-set-ws! srv (lambda (req) session-or-#f))` 注册 resolver。

## 流式响应和 SSE

用 chunked transfer-encoding 流式发送 body。长流应通过 spawn 一个 producer 进程从 pool worker 中分离，
这样 worker 会立即回到 pool：

```scheme
(app-get app "/sse"
  (lambda (req res)
    (sse-start! res)                      ; text/event-stream, chunked
    (spawn
      (lambda ()
        (let loop ((i 1))
          ;; 客户端断开后 sse-send! 返回 #f
          (if (and (<= i 5) (sse-send! res (string-append "tick " (number->string i))))
              (begin (sleep-ms 300) (loop (+ i 1)))
              (res-end! res)))))))
```

更底层的 primitive 是 `res-begin!`、`res-write!`
（string 或 bytevector；客户端断开时返回 `#f`）和 `res-end!`。

## JSON

`(igropyr json)` 是安全的递归下降解析器，它从不调用 `read`，
因此可以安全处理不可信 request body；并提供 writer。
Object 映射为 alist（string key），array 映射为 vector，`null` 映射为 `'null`。

```scheme
(import (igropyr json))
(string->json "{\"a\":[1,2],\"b\":\"x\"}")   ; => (("a" . #(1 2)) ("b" . "x"))
(json->string '(("ok" . #t) ("n" . 42)))     ; => "{\"ok\":true,\"n\":42}"
(json-ref (string->json "{\"a\":{\"b\":9}}") "a" "b")  ; => 9
```

在 handler 中，`req-json` 解析 request body（JSON 非法时返回 `#f`），
`send-json!` 负责序列化：

```scheme
(app-post app "/api"
  (lambda (req res)
    (let ((j (req-json req)))
      (send-json! res (list (cons 'echo (json-ref j "name")))))))
```

## 表单和 cookie

`req-form` 同时解析 `application/x-www-form-urlencoded` 和
`multipart/form-data`；文本字段是 string，上传文件是
`#(file ,filename ,content-type ,bytevector)`。

```scheme
(app-post app "/upload"
  (lambda (req res)
    (for-each
      (lambda (kv)
        (let ((v (cdr kv)))
          (when (vector? v)               ; file part
            (save-file (vector-ref v 1) (vector-ref v 3)))))
      (req-form req))
    (send-text! res "ok")))

(app-get app "/login"
  (lambda (req res)
    (set-cookie! res "sid" "abc123" "Path=/" "HttpOnly")
    (send-text! res (or (req-cookie req "sid") "no session"))))
```

## OTP 构件

除了裸 `spawn`/`send`/`receive`，三个 OTP 风格 library 让有状态服务和 fan-out 更容易。

`gen-server` 把有状态服务归约为 callback；call 带唯一 tag 并 monitor server，
因此 crash 会立即浮现，而不是一直挂起：

```scheme
(import (igropyr gen-server))
(gen-server-start-named 'counter
  (lambda () 0)                                  ; init -> state
  (lambda (msg from state) (values (+ state 1) (+ state 1)))  ; handle-call
  (lambda (msg state) state))                    ; handle-cast
(gen-server-call 'counter 'incr)                 ; => 1  (通过注册名调用)
```

进程注册表把名称和背后的 pid 解耦，因此 supervised service 重启后仍能再次找到：
`(register 'db pid)`、`(whereis 'db)`。

PubSub 是 topic fan-out；死亡 subscriber 会被自动清理，这和 one-process-per-WebSocket 聊天室天然匹配：

```scheme
(import (igropyr pubsub))
(start-pubsub!)                                  ; boot 时调用一次
(app-ws app "/chat/:room"
  (lambda (ws req)
    (let ((topic (string->symbol (req-param req "room"))))
      (subscribe topic)
      (spawn (lambda ()                          ; 把 room 流量转发到这个 socket
               (let lp () (receive (`#(pub ,t ,m) (ws-send-text! ws m) (lp))))))
      (let lp ()
        (let ((m (ws-recv ws)))
          (if (eq? (vector-ref m 0) 'text)
              (begin (publish topic (vector-ref m 1)) (lp))
              'closed))))))
```

## Redis 和 MySQL

两个客户端都使用同一个 libuv loop 和 actor 模型：每个数据库连接是一个绿色进程；
调用者向它发送消息，然后在 `receive` 中暂停直到回复到达。不会有 OS 线程阻塞；
一百个 worker 可以等待数据库，同时其它请求继续被服务。

```scheme
(import (igropyr redis) (igropyr mysql))

;; Redis (RESP2)：并发命令会在一个连接上 pipeline
(define r (redis-connect "127.0.0.1" 6379))
(redis r "SET" "greeting" "hello")     ; -> "OK"
(redis r "GET" "greeting")             ; -> "hello"
(redis r "GET" "missing")              ; -> #f        (nil)
(redis r "LRANGE" "l" 0 -1)            ; -> ("a" "b") (array -> list)

;; MySQL（text protocol；caching_sha2_password，fast 和 full RSA path 都支持，
;; 因此可直接用于 MySQL 8/9）
(define db (mysql-connect "127.0.0.1" 3306 "user" "password" "mydb"))
(mysql-query db "SELECT id, name FROM users")
  ;; -> #(rows ("id" "name") (("1" "Alice") ("2" "Bob")))  NULL -> #f
(mysql-query db "INSERT INTO users (name) VALUES ('Eve')")
  ;; -> #(ok 1 3)   ; affected rows, last insert id

;; MySQL pool：一个 dispatcher 背后有 n 个真实连接；query 可并行运行，
;; 死连接会自动替换，pool 的使用方式和单连接完全一样
(define pool (mysql-pool 8 "127.0.0.1" 3306 "user" "password" "mydb"))
(mysql-query pool "SELECT ...")
```

Server error 会在调用者中 raise `#(redis-error msg)` / `#(mysql-error code msg)`；
在 route handler 中，这意味着 Let It Crash：worker 死亡，supervisor 重试，服务继续运行。
Redis bulk string 是二进制安全的：合法 UTF-8 返回 string，非 UTF-8 数据返回 bytevector。

MySQL 的 `caching_sha2_password` fast path（challenge-response，密码不上 wire）无需配置。
*full* auth path 会发送 RSA 加密后的密码；默认拒绝在明文连接上这么做
（MITM 可能替换 key）。可以通过 pin server key 或显式 opt in 启用：

```scheme
(mysql-connect host port user pw "db"
  '((server-public-key . "-----BEGIN PUBLIC KEY-----...")))   ; pinned key
(mysql-connect host port user pw "db"
  '((allow-insecure-auth . #t)))                              ; 仅限 TLS/可信网络
```

## 出站 HTTP

HTTP *client* 使用同样的模型：每个请求运行在自己的绿色进程中
（通过 libuv 线程池 async DNS，然后 connect/send/read），调用者暂停。
这适合在 handler 内调用其它服务。

```scheme
(import (igropyr client))

(let ((r (http-get "http://api.internal/users/42")))
  (response-status r)                       ; -> 200
  (response-header r 'content-type)         ; -> "application/json"
  (utf8->string (response-body r)))          ; body 是 bytevector

(http-post "http://api.internal/events" "{\"type\":\"click\"}"
           '((headers . (("Content-Type" . "application/json")))
             (timeout . 5000)))
```

每个请求一个连接（无 pooling）；transport failure 或 timeout 会 raise
`#(http-client-error msg)`。

启用可选库 `(igropyr tls)` 后即可用 **`https://`** —— 一次 import 加启动时一次
调用，之后每个 `http-get` / `http-request`（以及 `ws-client` 的 `wss://`）都能
访问 TLS endpoint：

```scheme
(import (igropyr client) (igropyr tls))
(tls-enable!)                                 ; 首个 https 请求前调用一次

(let ((r (http-get "https://api.github.com/zen"
                   '((headers . (("User-Agent" . "igropyr")))))))
  (response-status r)                          ; -> 200
  (utf8->string (response-body r)))
```

TLS 独立成库，本体因此保持零依赖：不 import 它就不会加载 OpenSSL。它以
memory-BIO 模式作为纯字节 codec 运行——libuv 仍然拥有 socket、event loop 和
timeout，OpenSSL 只做字节变换，握手在请求自己的绿色进程内驱动，不阻塞。
证书**默认校验**（对端链、主机名 / IP SAN、TLS ≥ 1.2、系统信任根——遵循
`SSL_CERT_FILE` / `SSL_CERT_DIR`）；校验失败 raise
`#(http-client-error "tls: …")`。需要系统装有 OpenSSL 3 或 1.1（或 LibreSSL）
共享库。详见下面 **出站 TLS**。

## 中间件套件

常见需求的现成 middleware。使用 `app-use` 注册；顺序很重要（最外层优先）。

```scheme
(import (igropyr session) (igropyr middleware))

(app-use app (error-handler))              ; 最外层：catch -> 500 JSON
(app-use app (logger))                     ; "GET /path -> 200 (3ms)"
(app-use app (security-headers '((hsts . #t))))  ; X-Frame-Options, nosniff, ...
(app-use app (cors '((origin . "https://app.example.com")
                     (credentials . #t))))       ; + 204 OPTIONS preflight
(app-use app (rate-limit '((max . 100) (window . 60000))))  ; 超限返回 429

;; 基于 cookie 的 session，背后是 gen-server store（sid 来自 OS CSPRNG，
;; TTL pruning）；session 被加载到 request 上，handler 之后若有变化则保存
(define store (make-session-store))         ; boot 时
(app-use app (session-middleware store))

(app-get app "/visits"
  (lambda (req res)
    (let* ((s (req-session req))
           (n (+ 1 (or (session-get s 'visits) 0))))
      (session-set! s 'visits n)             ; 自动持久化
      (send-json! res (list (cons 'visits n))))))
```

Middleware 也可以用 `req-set-local!` / `req-local` 把任意值藏到 request 上供后续 handler 使用
（session 就是这样传下去的）。自己写 middleware 只是
`(lambda (req res next) ...)`；调用 `(next)` 继续，或者直接响应并返回以短路。

Prometheus metrics：一个 middleware 记录每个请求，一个 endpoint 渲染每状态计数、
request-duration 和 connection/pool gauge：

```scheme
(import (igropyr metrics))
(define m (make-metrics))                   ; boot 时
(app-use app (metrics-middleware m))
;; app-listen 返回 server 之后：
(app-get app "/metrics" (metrics-endpoint m srv))
;;   igropyr_requests_total{status="200"} 1234
;;   igropyr_request_duration_ms_sum 45210
;;   igropyr_connections 12  ... igropyr_pool_busy 3
```

## 出站 WebSocket

`ws-connect` 拨号到 `ws://` URL，执行 upgrade handshake，并返回 client-role session；
它和 server side 使用同一个对象，因此 `ws-recv` / `ws-send-text!` / `ws-close!`
都照常工作（outbound frame 按 RFC 6455 要求 mask）。

```scheme
(import (igropyr ws-client))
(let ((w (ws-connect "ws://127.0.0.1:8080/chat/42")))
  (ws-send-text! w "hello")
  (ws-recv w)                 ; -> #(text s) | #(binary bv) | #(close)
  (ws-close! w))
```

`wss` 会被拒绝；TLS-only endpoint 应通过 proxy 访问。

## 容错语义

每个请求都经过 worker pool，因此这些语义适用于所有 route；无需配置：

- **Crash**：handler raise 会杀死其 worker。supervisor 生成替代 worker 并重试任务，
  最多 3 次（总共执行 4 次）；之后客户端收到 `500`，任务被丢弃。服务不会中断。
- **Stuck**：ticker 每 5 s 检查 pool；任何忙碌超过 30 s 的 worker 都会被杀死并替换。
  Stuck task *不会*重试（重试无限循环会再次卡住 pool）。即使每个 worker 都卡住，
  服务也会在约 35 s 内自行恢复。
- **Slow clients**：每个连接由自己的 reader 进程拥有；
  半发送请求只暂停该 reader，并在 30 s 后被回收。

## 运行时 introspection 和优雅停机

`app-listen` / `http-listen` 返回 server。`http-stats` 给出实时 snapshot；
`http-shutdown!` 停止 accept 并在返回前排空 in-flight 请求
（从 detached process 调用，绝不要从 pool worker 调用）：

```scheme
(define srv (app-listen app 8080))
(app-get app "/stats" (lambda (req res) (send-json! res (http-stats srv))))
;;   => {"connections":12,"requests":34210,"uptime-ms":90000,
;;       "idle":5,"busy":3,"pending":0}
(spawn (lambda () (http-shutdown! srv) (exit 0)))   ; graceful stop
```

## 多进程扩展

Chez 运行在一个 OS 线程上，所以单个进程会饱和一个 core。要使用所有 core，
运行 N 个绑定到同一端口的进程，使用 `SO_REUSEPORT` 让 kernel 平衡连接
（Linux 3.9+ / FreeBSD 12+；macOS 不支持）：

```scheme
(app-listen app 8080 '((reuseport . #t)))
```

用 pm2（fork mode）或 systemd 启动并 supervise 这 N 个进程。因为进程之间没有共享状态，
每进程状态（worker pool、route table、PubSub topic、WebSocket room）都是本地的；
跨进程共享请通过 Redis，或用下面的分布式层把它们连成 actor mesh。

## 跨节点分布式

`SO_REUSEPORT` 能摊开无状态 HTTP，但每个进程是孤岛。`(igropyr node)` 把实例
连成 mesh——同机其它核心走 loopback、其它机器走网络——一个节点上的进程可以给
另一节点上的**注册名**发消息。语义刻意照抄 Erlang distribution。

```scheme
(import (igropyr node))

;; 节点 b：身份 + 监听（不给 host 就绑 127.0.0.1）
(node-start! 'b "shared-secret" 4100)
(register 'worker self)

;; 节点 a：拨号 b（自动重连），然后与它对话
(node-start! 'a "shared-secret")
(node-connect! 'b "10.0.0.2" 4100)
(rsend 'b 'worker (vector 'job 42))       ; 发后不理 -> #t / #f
(rcall 'b 'calc  (vector 'square 7))      ; 同步 gen-server 调用 -> 49
(monitor-node 'b)                         ; -> #(node-up b) / #(node-down b)
(monitor-remote 'b 'worker)               ; -> #(remote-down b worker reason)
```

寻址用注册名（pid 是内存对象；名字跨重启存活）。`rsend` 发后不理、同一对节点
保序；`rcall` 是它的同步对应物。载荷走扩展 s 表达式线模式，vector、bytevector、
有限浮点无损过线，精确整数/分数保持精确。节点连上后 `(igropyr pubsub)` 自动
变成集群级——一次 `publish` 到达每个节点的订阅者，聊天室例子无需改动就跨 mesh 工作。

**分布式任务池** — 把工作摊到多节点，本地 worker pool 的 Let-It-Crash 升到节点级：

```scheme
(import (igropyr dpool))
(dpool-worker-start 'render (lambda (job) (resize job)))   ; 每个成员
(define pool (dpool-start '(b c) 'render))                 ; 提交端
(dpool-await pool (dpool-submit pool (vector 'resize "x.png" 800)))
```

故障模式按池选、按任务可覆盖：**at-least-once**（默认；节点死则重派任务——一定完成、
可能跑两次、需幂等）或 **at-most-once**（节点死则任务失败——绝不重跑）。不提供
exactly-once：跨越崩溃时没有任何消息传递系统能同时做到两者。

**自动发现** — 不用手动拨号每个 peer，`(igropyr cluster)` 定期向策略要成员列表
并拨号新增的：

```scheme
(import (igropyr cluster))
(cluster-start `((discover . (static (b "10.0.0.2" 4100) (c "10.0.0.3" 4100)))))
(cluster-start `((name . "myapp") (discover . (redis ,conn "10.0.0.1" 4100))))
```

**redis** 策略把每个节点心跳进一个按过期时间戳打分的有序集合；崩溃的节点自己
掉出，无需中心记账。

> **安全：** dist 端口等于对节点的完全控制——连上它就能给任何注册进程发消息，
> 包括 supervisor。握手是共享秘钥上的双向 HMAC-SHA1 挑战应答，但**没有 TLS**，
> 端口默认绑 `127.0.0.1`。跨机器请放在私有网络（WireGuard、VPC）里。要跨集群
> 单例或选主，请用已解决共识的系统（Redis `SET NX`、etcd）——网络分裂会把进程内
> 选主变成脑裂。

## HTTPS / TLS

两个方向，处理方式不同。**入站**（浏览器访问你的 server）由 reverse proxy 终止——
本节介绍。**出站**（你的代码调用 `https://` API）是可选库 `(igropyr tls)`——见本节末尾的
[出站 TLS](#出站-tls) 及[出站 HTTP](#出站-http) 里的 `https://` 示例。

### 入站：在 reverse proxy 终止

Igropyr 的 server 讲明文 HTTP；入站 TLS 应在前面的 reverse proxy 终止。这是标准部署方式，
可以免费获得自动证书、浏览器侧 HTTP/2 和 OCSP stapling，而不让 server 拥有 TLS 或其 CVE surface。

**Caddy**（自动 Let's Encrypt 证书，每个 host 一行）：

```caddyfile
example.com {
    reverse_proxy 127.0.0.1:8080
}
```

这就是全部配置 — Caddy 会自行获取并续期证书。WebSocket upgrade 会原样通过。

**nginx**（手动或 certbot 管理证书），同时转发普通请求和 WebSocket upgrade，
并在 reuseport 进程之间做 balance：

```nginx
upstream igropyr {
    server 127.0.0.1:8080;      # 如果没有通过 SO_REUSEPORT 共享端口，在这里添加更多 server
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

使用 `SO_REUSEPORT`（见上文）时，所有 worker process 共享 `:8080`，
所以一个 `upstream` entry 就够了；否则给每个进程单独端口，并全部列出。
从 `X-Forwarded-For` 读取客户端真实 IP，从 `X-Forwarded-Proto` 读取原始 scheme。

### 出站 TLS

另一个方向——从自己的代码调用 `https://` 服务——import `(igropyr tls)` 并在启动时
调用一次 `(tls-enable!)`；之后 HTTP client 和 `ws-client` 就能讲 `https://` / `wss://`。
与入站侧不同，这是进程*内*的真正 TLS 客户端，因此它自己校验证书。

```scheme
(import (igropyr client) (igropyr tls))
(tls-enable!)
(http-get "https://example.com/")
```

为什么做成独立可选库、而非放进 server：

- **本体保持零依赖。** 只有 `(igropyr tls)` 触碰 OpenSSL；从不 import 它的程序永不
  加载它，无论系统是否装了 OpenSSL，构建和其它所有库都不受影响。
- **TLS 是 codec，不是 I/O 拥有者。** OpenSSL 以 memory-BIO 模式运行：libuv 仍然
  拥有 socket、event loop 和 timeout，握手由请求自己绿色进程内的普通 `receive` 驱动。
  无线程、无回调、不阻塞其它进程——和普通请求同一个 actor 模型。
- **客户端校验默认开启且不可绕过：** `SSL_VERIFY_PEER`、主机名（或 IP 字面量）SAN
  匹配、TLS ≥ 1.2、系统信任根（可用标准的 `SSL_CERT_FILE` / `SSL_CERT_DIR` 覆盖）。
  链有问题或主机名不匹配会让请求以 `#(http-client-error "tls: …")` 失败，而不是静默连上。

需要系统装有 OpenSSL 3 或 1.1（或 LibreSSL）共享库——通过常见平台路径查找
（含 Homebrew 的 `openssl@3`）。入站 HTTPS 仍应放在 proxy：server 侧 TLS 意味着
自己承担证书续期和 TLS CVE surface，而 proxy 做得更好。`(igropyr tls)` 有意
只提供**客户端校验**。

## 架构

```
libuv.sc   libuv FFI：event loop、TCP、async DNS、async file read、
           write queue、GC roots
actor.sc   绿色进程：spawn/send/receive、link/monitor/register、
           抢占式 scheduler（call/1cc + timer interrupt）、run/sleep queue
otp.sc     supervisor + 固定 worker pool + stuck-worker ticker
http.sc    核心：增量 HTTP/1.1 parser（content-length + chunked）、
           connection lifecycle、response encoding、websocket upgrade、
           streaming、http-listen / http-swap! / http-set-ws!
websocket.sc  WebSocket codec（server + client role）：handshake key、
              frame encode/decode、ws-recv / ws-send-text! / ws-close!
ws-client.sc  出站 WebSocket（ws-connect）
express.sc framework layer（可选）：带 :param segment 的 router、
           middleware chain、static files（cached + gzip）、app-ws、
           forms/cookies、SSE、JSON/text/html/file encoder
json.sc    安全递归下降 JSON parser + writer
gzip.sc    通过 zlib 做 gzip compression
gen-server.sc  OTP gen-server（call/cast/info）
pubsub.sc  topic publish/subscribe，自动清理死亡 subscriber
session.sc     gen-server store 上的 cookie session
middleware.sc  cors / security-headers / logger / rate-limit / error-handler
metrics.sc     Prometheus /metrics endpoint
client.sc  非阻塞出站 HTTP client（async DNS）
tls.sc     可选出站 TLS（OpenSSL memory-BIO codec），用于 https/wss
redis.sc   非阻塞 Redis client（RESP2），pipelined
mysql.sc   非阻塞 MySQL client（caching_sha2_password）+ pool
```

actor scheduler（`register`/`whereis`/`monitor`/`demonitor`）以及一切依赖的
libuv-callback 不变量记录在[手册](https://igropyr.com/manual.html?lang=zh)。

进程之间的消息协议：

```
reader     -> supervisor : #(submit-task ,task)
supervisor -> worker     : #(process-task ,task)
worker     -> supervisor : #(task-completed ,task-id ,self)
ticker     -> supervisor : #(check-stuck-workers)        ; 每 5 s
worker death             : #(DOWN ,pid ,reason)          ; 通过 monitor
```

`receive` macro 接受一个可选 timeout clause，它必须放在第一位，类似 Erlang：

```scheme
(receive (after 5000 (handle-timeout))
  (`#(tcp-data ,bv) (consume bv))
  (`#(tcp-eof) (close)))
```

## 生产构建

从源码运行（`scheme --script`）会解释执行 library。部署时应编译。两个选项：

```sh
# 分库 .so 文件（optimize-level 2：完整优化，保留全部 type/bounds check）。
# 当 CHEZSCHEMELIBEXTS 中 .so 位于 .sc 前面时，会自动加载 .so 而不是源码。
# 这适合开发，因为 --script 仍然可用。
scheme --libdirs .:lib --script igropyr/build.ss

# Whole-program：把每个 library + app 折叠进一个优化后的 program
#（cross-library inlining，optimize-level 2）。用 --program 运行它。
scheme --libdirs .:lib --script igropyr/build-whole.ss
scheme --program igropyr/app.so
```

编辑任何源码后都要重新构建。Interrupt trap 保持启用（抢占式调度需要它）。

Profile-guided optimization（`build-profile.ss` 做 instrumentation，
压测后通过 `/admin/profdump` 收集，`build-pgo.ss` 用 profile 重新编译）可用，
但**这里测得没有提升** — 对于 I/O-bound server，每请求成本是 syscall、message passing 和 scheduling，
没有供 PGO 重排的 hot/cold branch structure，whole-program 已经跨 library inline。
只有添加 branch-heavy CPU-bound handler 时才需要考虑。

关于时间花在哪里：对 trivial handler 来说，每请求成本主要是 syscall、HTTP parsing 和 message passing，
不是 Scheme arithmetic，因此编译只带来几个百分点收益；它对 CPU-heavy handler
（大型 JSON、crypto、data munging）最有价值。要降低 trivial route 的 per-request overhead，
把它标记为 *fast*（见上文）。

## 压力测试

macOS 默认每进程 256 个 file descriptor；在 server 和 benchmark shell 中都提高限制：

```sh
ulimit -n 10240
ab -k -n 100000 -c 200 http://127.0.0.1:8080/     # keep-alive
```

单个 `ab` 进程本身会成为 loopback 上的瓶颈（benchmark 的一个 core 饱和，而不是 server）；
并行运行多个 `ab` 才能找到 server 的真实上限 — 在 Apple Silicon 笔记本上，
一个 core 的 trivial keep-alive route 约 145 k req/s。

## 测试

运行完整、自断言的测试套件：

```sh
./igropyr/test/run-all.sh
```

它检查 library import、actor scheduling、异步文件读取、严格 HTTP framing/query 行为，
以及 boot-failure propagation。较旧的 echo 和 `run-otp.sc` 程序仍可作为交互式 smoke/demo server 使用。

## 许可证

MIT
