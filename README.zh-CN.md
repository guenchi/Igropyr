# Igropyr

[English](README.md) | **简体中文**

Igropyr 是一个面向 [Chez Scheme](https://cisco.github.io/ChezScheme/) 的高并发 HTTP 服务器。它通过 Chez FFI 直接连接 [libuv](https://libuv.org/)，不依赖 C 中间层，并提供 Erlang 风格的消息传递并发模型和 Let-It-Crash 容错机制。

- **核心与框架分离**：核心只暴露 `(http-listen port handler)`；内置的 `(igropyr express)` 提供路由、中间件、JSON、静态资源等能力，也可以在同一核心上实现其它框架。
- **绿色进程**：单个 OS 线程上可以调度成千上万个轻量进程；基于 continuation 切换并支持抢占，CPU 死循环的 handler 不会冻结整个服务。
- **纯消息传递**：使用 `spawn`、`send`、`receive`、`link`、`monitor` 协作，进程之间不共享可变状态。
- **默认容错**：固定 worker pool 由 supervisor 管理。崩溃的 worker 会被替换，任务最多重试 3 次；运行超过 30 秒的 worker 会被杀死并补充。慢请求只会阻塞自己的 reader 进程。
- **热更新**：可以替换在线服务器的整个 handler 或单条路由，不重启 listener、连接和 worker pool；正在执行的请求继续使用旧代码。
- **WebSocket**：同端口完成 RFC 6455 Upgrade，每条连接由独立绿色进程管理。
- **流式响应与 SSE**：通过 `res-begin!`、`res-write!`、`res-end!` 发送 chunked 响应，并提供 SSE 辅助函数。
- **OTP 组件**：包含 `gen-server`、进程注册表和自动清理死亡订阅者的 PubSub。
- **JSON、表单和 Cookie**：安全的递归下降 JSON 解析器、JSON writer、urlencoded/multipart 表单、文件上传与 Cookie 辅助函数。
- **非阻塞 Redis/MySQL 客户端**：数据库等待只挂起调用方绿色进程，不阻塞 OS 线程；MySQL 自带可恢复连接池。
- **运行时观测和优雅退出**：`http-stats` 提供连接、请求和 pool 指标；`http-shutdown!` 停止接收新连接并排空在途请求。
- **多进程扩展**：Linux/FreeBSD 可通过 `SO_REUSEPORT` 让多个进程共享端口，由内核分发连接。
- **HTTP/1.1 keep-alive 与 pipelining**：每条连接的 reader 进程可以连续解析多个请求。
- **安全加固**：严格校验请求 framing、header、chunked body、WebSocket frame、响应 header 和静态目录边界；每个请求拥有独立响应 token。

架构、Actor 模型、libuv callback 不变量和贡献规范请阅读[中文开发指南](DEVELOPING.zh-CN.md)。

## 环境要求

- Chez Scheme 10.x
- libuv 1.x

```sh
brew install chezscheme libuv        # macOS
# apt install chezscheme libuv1-dev  # Debian/Ubuntu
```

`uv.sc` 会探测 macOS、Linux 的标准 libuv soname 和常见 Homebrew 路径。使用自定义安装目录时，请将其加入系统动态链接器的搜索路径。

## 快速开始

仓库目录必须命名为小写 `igropyr`，因为 R6RS library 名称区分大小写：

```sh
git clone https://github.com/guenchi/Igropyr igropyr
export CHEZSCHEMELIBDIRS=.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so
chez --script igropyr/test/run-otp.sc
```

随后可在另一个终端验证：

```sh
curl localhost:8080/
curl 'localhost:8080/users/42?verbose=1'
curl -X POST -d 'hello' localhost:8080/echo
```

## 编写应用

使用内置 Express 风格框架：

```scheme
(import (chezscheme)
        (igropyr actor)
        (igropyr http)
        (igropyr express))

(define app (create-app))

;; GET/POST/PUT/DELETE 路由，:name 捕获路径参数
(app-get app "/hello/:name"
  (lambda (req res)
    (send-text! res
      (string-append "hello " (req-param req "name")))))

(app-post app "/api/data"
  (lambda (req res)
    (send-json! res
      (list (cons 'received (utf8->string (req-body req)))))))

;; 中间件必须调用 (next) 才会继续执行后续链路
(app-use app
  (lambda (req res next)
    (if (req-header req 'authorization)
        (next)
        (begin
          (set-status! res 403)
          (send-text! res "Forbidden")))))

;; /assets/style.css -> ./public/style.css
(app-static app "/assets" "./public")

(start-scheduler
  (lambda ()
    (app-listen app 8080 8)))
```

worker pool 可以使用 alist 配置；所有键都可以省略：

```scheme
(app-listen app 8080
  '((workers . 8)         ; pool 大小
    (max-retries . 3)     ; 崩溃后的最大重试次数
    (stuck-ms . 30000)    ; 超过该时间视为卡死
    (check-ms . 5000)))   ; 卡死检查间隔
```

### 请求访问器

| 过程 | 返回值 |
|---|---|
| `(req-method req)` | `GET`、`POST` 等 method symbol |
| `(req-path req)` | 已解码的路径字符串 |
| `(req-param req "id")` | `:param` 捕获值，未找到时为 `#f` |
| `(req-query req)` | 字符串组成的 query alist |
| `(req-header req 'content-type)` | header 值；键为小写 symbol |
| `(req-body req)` | bytevector 请求体 |
| `(req-keep-alive? req)` | 是否保持连接 |

### 响应辅助函数

先设置状态和 header，再且只发送一次：

```scheme
(set-status! res 201)
(set-header! res "X-Request-Id" "abc")
(send-text! res "created")
(send-html! res "<h1>hi</h1>")
(send-json! res obj)
(send-file! res "path/to/file")
```

同一请求的第二次发送会被忽略，因此 supervisor 的 fallback 不会破坏已经发出的响应。

## 核心 API：构建自己的框架

HTTP 核心负责协议解析、连接生命周期、worker pool 和响应编码，只接收一个 handler：

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

核心响应原语为 `set-status!`、`set-header!` 和 `res-send!`。框架自动管理 `Content-Length`、`Connection` 和一次性响应 token。路由参数属于上层框架，但核心 request 提供了可由框架使用的 `req-params` 槽位。

## 热更新

两种热更新都不会中断 listener、现有连接或 worker pool：

- 路由级：再次注册相同 method 和 pattern 会替换旧 handler。

  ```scheme
  (app-get app "/version" v2-handler)
  ```

- 核心 handler 级：`app-listen` 和 `http-listen` 返回 server，可原子替换整个 handler 或 WebSocket resolver。

  ```scheme
  (define srv (app-listen app 8080))
  (http-swap! srv (app->handler another-app))
  (http-set-ws! srv another-ws-resolver)
  ```

## WebSocket

WebSocket 与 HTTP 共用端口。`ws-recv` 只挂起当前连接进程；ping、分片重组和协议错误处理由框架完成。

```scheme
(import (igropyr websocket))

(app-ws app "/ws"
  (lambda (ws req)
    (ws-send-text! ws "welcome")
    (let loop ()
      (let ((m (ws-recv ws)))
        (case (vector-ref m 0)
          ((text)
           (ws-send-text! ws (vector-ref m 1))
           (loop))
          ((binary)
           (ws-send-binary! ws (vector-ref m 1))
           (loop))
          (else 'closed))))))
```

其它绿色进程持有 `ws` 后也可以调用发送函数完成服务端推送。直接使用 HTTP 核心时，通过 `http-set-ws!` 注册 resolver。

## 流式响应与 SSE

长连接或大响应应让 producer 在独立进程中运行，使 worker 立即归还 pool：

```scheme
(app-get app "/sse"
  (lambda (req res)
    (sse-start! res)
    (spawn
      (lambda ()
        (let loop ((i 1))
          (if (and (<= i 5)
                   (sse-send! res
                     (string-append "tick " (number->string i))))
              (begin (sleep-ms 300) (loop (+ i 1)))
              (res-end! res)))))))
```

底层接口为 `res-begin!`、`res-write!` 和 `res-end!`。客户端断开后 `res-write!` 返回 `#f`。

## JSON

`(igropyr json)` 使用递归下降解析，不调用 `read`，适用于不可信 HTTP body。对象映射为以字符串为键的 alist，数组映射为 vector，`null` 映射为 `'null`。

```scheme
(import (igropyr json))
(string->json "{\"a\":[1,2],\"b\":\"x\"}")
;; => (("a" . #(1 2)) ("b" . "x"))
(json->string '(("ok" . #t) ("n" . 42)))
;; => "{\"ok\":true,\"n\":42}"
(json-ref (string->json "{\"a\":{\"b\":9}}") "a" "b")
;; => 9
```

JSON 不支持 NaN、无穷大、复数以及超出支持范围的数值；序列化这些值会抛出异常。

## 表单和 Cookie

`req-form` 支持 `application/x-www-form-urlencoded` 和 `multipart/form-data`。普通字段为字符串，文件为 `#(file ,filename ,content-type ,bytevector)`。

```scheme
(app-post app "/upload"
  (lambda (req res)
    (for-each
      (lambda (kv)
        (let ((v (cdr kv)))
          (when (vector? v)
            (save-file (vector-ref v 1) (vector-ref v 3)))))
      (req-form req))
    (send-text! res "ok")))

(app-get app "/login"
  (lambda (req res)
    (set-cookie! res "sid" "abc123" "Path=/" "HttpOnly")
    (send-text! res (or (req-cookie req "sid") "no session"))))
```

## OTP 组件

`gen-server` 把有状态服务规约为 callback；同步 call 使用唯一 tag 并监控 server，server 崩溃会立即反馈给调用者。

```scheme
(import (igropyr gen-server))
(gen-server-start-named 'counter
  (lambda () 0)
  (lambda (msg from state)
    (values (+ state 1) (+ state 1)))
  (lambda (msg state) state))

(gen-server-call 'counter 'incr) ; => 1
```

进程注册表通过 `(register 'db pid)` 和 `(whereis 'db)` 解耦名称与 pid。PubSub 按 topic 广播，并自动清理死亡订阅者：

```scheme
(import (igropyr pubsub))
(start-pubsub!)
(subscribe 'room-1)
(publish 'room-1 "hello")
;; 订阅者收到 #(pub room-1 "hello")
```

## Redis 与 MySQL

每条数据库连接由一个绿色进程拥有。调用方等待回复时只挂起自己的绿色进程，OS 线程继续处理网络事件。

```scheme
(import (igropyr redis) (igropyr mysql))

(define r (redis-connect "127.0.0.1" 6379))
(redis r "SET" "greeting" "hello") ; => "OK"
(redis r "GET" "greeting")         ; => "hello"
(redis r "GET" "missing")          ; => #f
(redis r "LRANGE" "l" 0 -1)        ; => ("a" "b")

(define db
  (mysql-connect "127.0.0.1" 3306 "user" "password" "mydb"))
(mysql-query db "SELECT id, name FROM users")
;; => #(rows ("id" "name") (("1" "Alice") ("2" "Bob")))
(mysql-query db "INSERT INTO users (name) VALUES ('Eve')")
;; => #(ok 1 3)

(define pool
  (mysql-pool 8 "127.0.0.1" 3306 "user" "password" "mydb"))
(mysql-query pool "SELECT ...")
```

Redis 的合法 UTF-8 bulk string 返回字符串，任意二进制 bulk string 返回 bytevector。Redis/MySQL 服务端错误分别以 `#(redis-error msg)` 和 `#(mysql-error code msg)` 抛出。

MySQL `caching_sha2_password` 快速路径无需配置。完整认证路径默认拒绝从未认证明文连接获取 RSA key；应固定服务端公钥，或仅在可信环境中明确允许不安全认证：

```scheme
(mysql-connect host port user password "db"
  '((server-public-key . "-----BEGIN PUBLIC KEY-----...")))

(mysql-connect host port user password "db"
  '((allow-insecure-auth . #t)))
```

## Fast 路由

默认请求经过 worker pool，从而获得崩溃重试和卡死检测。纯函数且快速返回的 handler 可以标记为 fast，直接在连接 reader 中运行：

```scheme
(app-get-fast app "/" (lambda (req res) (send-html! res "hi")))
;; 另有 app-post-fast / app-put-fast / app-delete-fast
```

代价是 fast handler 不再拥有 pool 容错：崩溃只会让当前连接返回 `500`，不会重试；阻塞或死循环会冻结当前连接。含副作用、数据库访问或重计算的路由应继续使用默认 pooled 路径。

## 容错语义

- **崩溃**：worker 抛出未捕获异常后，supervisor 创建替代 worker 并重试任务。默认最多重试 3 次，即最多执行 4 次；仍失败则返回 `500`。
- **卡死**：ticker 每 5 秒检查一次；繁忙超过 30 秒的 worker 会被杀死并替换。卡死任务不会重试，避免再次卡住 pool。
- **慢客户端**：每条连接都有独立 reader。半包请求只挂起该 reader，并在 30 秒后回收。

由于任务可能重试，handler 中的副作用必须幂等，或交给数据库、`gen-server` 等组件保证一次性语义。

## 运行时观测和优雅退出

```scheme
(define srv (app-listen app 8080))

(app-get app "/stats"
  (lambda (req res)
    (send-json! res (http-stats srv))))

(spawn
  (lambda ()
    (http-shutdown! srv)
    (exit 0)))
```

`http-stats` 返回连接数、请求数、运行时间以及 idle/busy/pending worker 数量。`http-shutdown!` 必须从独立进程调用，不能从 pool worker 内调用。

## 多进程扩展

Chez 在一个 OS 线程上运行。Linux 3.9+ 和 FreeBSD 12+ 可以启动多个进程并共享端口：

```scheme
(app-listen app 8080 '((reuseport . #t)))
```

每个进程的路由、worker pool、PubSub topic 和 WebSocket 房间相互独立。跨进程状态应放入 Redis，并可使用 Redis Pub/Sub 作为事件总线。macOS 不支持该模式。

## 架构

```text
uv.sc         libuv FFI、事件循环、TCP、写队列、GC root registry
actor.sc      绿色进程、消息邮箱、link/monitor、抢占式调度器
otp.sc        supervisor、固定 worker pool、卡死检测 ticker
http.sc       HTTP/1.1 解析、连接生命周期、响应、WebSocket Upgrade
websocket.sc  RFC 6455 frame codec、握手、接收与发送
express.sc    路由、中间件、静态文件、表单/Cookie、SSE、编码器
json.sc       安全 JSON parser/writer
gen-server.sc OTP gen-server
pubsub.sc     topic PubSub 与死亡订阅者清理
redis.sc      非阻塞 RESP2 客户端
mysql.sc      非阻塞 MySQL text protocol 客户端与连接池
```

HTTP worker pool 的主要消息协议：

```text
reader     -> supervisor : #(submit-task ,task)
supervisor -> worker     : #(process-task ,task)
worker     -> supervisor : #(task-completed ,task-id ,self)
ticker     -> supervisor : #(check-stuck-workers)
worker death -> supervisor: #(DOWN ,worker-pid ,reason)
```

## 生产构建

源码模式使用 `chez --script` 解释 library。生产环境可以选择：

```sh
# 按 library 编译，热路径使用 optimize-level 3
chez --libdirs .:lib --script igropyr/build.ss

# whole-program 编译，支持跨 library 内联
chez --libdirs .:lib --script igropyr/build-whole.ss
chez --program igropyr/app.so
```

修改源文件后必须重新构建。抢占调度依赖 interrupt trap，因此构建脚本不会关闭它。

## 压力测试

macOS 默认文件描述符上限较低，测试前应在服务器和测试终端中提高：

```sh
ulimit -n 10240
ab -k -n 100000 -c 200 http://127.0.0.1:8080/
```

单个 `ab` 进程可能先成为瓶颈，可使用多个压测进程或 `wrk` 继续提高负载。

## 测试

```sh
chez --script igropyr/test/smoke-echo.sc
chez --script igropyr/test/smoke-actor.sc
chez --script igropyr/test/smoke-echo-actor.sc
chez --script igropyr/test/run-otp.sc
chez --script igropyr/test/security-regression.sc
```

`security-regression.sc` 覆盖 HTTP framing、header、chunked、URL 解码、请求 ref 隔离、WebSocket close code 和关键配置校验。

## 许可证

MIT
