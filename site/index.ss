;; The Igropyr homepage, authored in Scheme and rendered by Goeteia.
;; The header's honeycomb is a WebGL fire (fire.wasm, compiled from
;; site/fire.ss); everything else is static (web html) SXML. The
;; syntax-highlighted code blocks come from (code-blocks) verbatim.
(import (rnrs) (web html) (chrome) (code-blocks) (rpc-code))

(define (fitem term . desc)
  `(div (@ (class "fitem"))
     (span (@ (class "fterm")) (b ,term))
     (span (@ (class "fdesc")) ,@desc)))

(define body
  (list
   (nav)
   ;; ---- hero ----
   `(header
      (canvas (@ (class "hive") (id "hive") (width "1120") (height "760")))
      (div (@ (class "wrap"))
        (div (@ (class "lam")) "λ")
        (h1 "Igropyr")
        (p (@ (class "tag")) "A distributed backend framework where " (b "crashes self-heal")
           ", " (b "code hot-swaps") ", " (b "faults speak a protocol") ", and "
           (b "continuations drive conversations") ".")
        (p (@ (class "sub"))
           "Pure Chez Scheme · Erlang-style actors · libuv event loop · MIT")
        (div (@ (class "cta"))
          (a (@ (class "btn primary") (href "https://github.com/guenchi/Igropyr"))
             "Get the code")
          (a (@ (class "btn ghost") (href "manual.html")) "Read the manual"))
        (pre (@ (class "quick")) ,(raw hero-quick))))

   ;; ---- 1. let it crash ----
   `(section (@ (id "crash"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "01 · Fault tolerance")
        (h2 "Let It Crash")
        (p (@ (class "lead")) "HTTP requests run in a supervised worker pool. "
           "Handlers don't defend—they crash, and the system recovers. "
           "(WebSocket sessions own their own processes, so a crash kills "
           "only that connection, leaving the pool untouched.)")
        (div (@ (class "feature"))
          (div (@ (class "txt"))
            (h3 "Crashes self-heal")
            (ul
              (li "A crashed worker is " (b "replaced instantly") ". The task is "
                  "seamlessly retried on a fresh worker, up to 3 times, before "
                  "the client ever sees an error.")
              (li "A worker stuck for over 30s—even in a deadlocked CPU "
                  "loop—is " (b "ruthlessly killed and replaced") ". Preemptive "
                  "scheduling guarantees that no single handler can freeze the "
                  "server.")
              (li "A half-sent, slow-drip request parks only "
                  (b "its own reader process")
                  " and is quietly reaped by a timeout. Other connections "
                  "never notice."))
            (p "Write the happy path. The supervisor owns the sad one."))
          (pre ,(raw crash-code)))))

   ;; ---- 2. hot swap ----
   `(section (@ (id "hotswap"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "02 · Live systems")
        (h2 "Hot code swapping")
        (p (@ (class "lead")) "Swap the entire handler—or just patch a single "
           "route—on a live server. The TCP listener, open connections, and the "
           "worker pool remain completely untouched. In-flight requests "
           "gracefully drain on the old code, while new traffic instantly hits "
           "the new logic.")
        (div (@ (class "feature flip"))
          (div (@ (class "txt"))
            (h3 "Deploy without a restart")
            (p "Routes live in a mutable registry behind the worker pool. "
               "Re-registering a path " (b "patches it atomically")
               " for the very next request; " (code "http-swap!")
               " replaces the entire top-level handler with the exact same "
               "guarantee.")
            (p "Combined with graceful shutdown (" (code "http-shutdown!")
               " safely drains in-flight work) and " (code "SO_REUSEPORT")
               " multi-process listening, zero-downtime operation isn't an "
               "engineering project—it's the default."))
          (pre ,(raw hotswap-code)))))

   ;; ---- 3. failure hook ----
   `(section (@ (id "faults"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "03 · The remote retry ring")
        (h2 "Faults speak a protocol")
        (p (@ (class "lead")) "When retries are exhausted or a stuck worker is "
           "killed, Igropyr doesn't just throw a black-box 500 error—it tells "
           "the client exactly what happened, on a connection that stays open.")
        (div (@ (class "feature"))
          (div (@ (class "txt"))
            (h3 "Killed first, told after")
            (p "The " (code "on-failure") " hook returns a structured JSON fault "
               "only " (b "after") " the stuck worker is physically dead. When "
               "the client hears " (code "stuck") ", it comes with an absolute "
               "guarantee: there is " (b "no execution left in flight")
               ". The state is definite.")
            (ul
              (li (b "crash") " — retries exhausted; safely resubmit with changed "
                  "parameters, or compensate.")
              (li (b "stuck") " — killed mid-flight; safely resubmit carrying "
                  "state, or roll back."))
            (p "Keep-alive survives the fault. The client resubmits on the "
               (b "very same connection") " and gets a fresh retry round. Dial "
               "down the " (code "stuck-ms") " limit, and a user who once stared "
               "at a spinner for 30 seconds now transparently cycles through "
               "several informed retries in the exact same time. Failures become "
               "invisible at the UI."))
          (pre ,(raw faults-code)))))

   ;; ---- 4. conversations ----
   `(section (@ (id "conversations"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "04 · Web programming with continuations")
        (h2 "Conversations are continuations")
        (p (@ (class "lead")) "A multi-request workflow—a checkout wizard, a "
           "booking, a fund transfer—runs as " (b "one single green process")
           ". Its local lexical bindings are the conversation state. This allows "
           "it to hold resources that a disconnected session store could never "
           "serialize: like a " (b "live, open database transaction")
           " spanning across multiple network roundtrips.")
        (div (@ (class "feature flip"))
          (div (@ (class "txt"))
            (h3 "Control flow is program text")
            (p "\"The user is at the confirm step\" literally means the process "
               "is parked " (b "at that exact line of code") ". A sequence of "
               "events that the code cannot express simply cannot happen—there "
               "is no external state machine to get wrong, and no replay attack "
               "to defend against.")
            (p (b "The " (code "gone") " guarantee"))
            (p "The transaction declares its point of no return through the "
               (code "commit!") " primitive, giving the framework a razor-sharp "
               "boundary to judge any death.")
            (ul
              (li (b "Before " (code "commit!") ":") " A dead process means a "
                  "dropped connection, which means the database itself "
                  "automatically rolled back. The framework answers "
                  (code "gone") "—absolute physical proof that nothing "
                  "committed. This is the one status you may safely retry on.")
              (li (b "After " (code "commit!")
                     " (or an unknown kill/missing record):")
                  " The framework answers " (code "unknown")
                  ". It refuses to guess. Reconcile; never resubmit."))
            (p "Combined with the fault protocols above, the client always knows "
               "the definite server state. Just as importantly, it is told "
               "plainly—and honestly—when the state cannot be known. The "
               "complete remote transaction ring is finally closed."))
          (pre ,(raw conv-code)))))

   ;; ---- 5. s-expression rpc ----
   `(section (@ (id "rpc"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "05 · Scheme talks to Scheme")
        (h2 "Communicate in S-expressions")
        (p (@ (class "lead")) "When the client is Scheme too, requests and replies "
           "are pure s-expressions. There is no codec to design, agree upon, or "
           "debug. " (code "(igropyr sexpr)") " acts as the safe boundary parser, "
           "while " (code "app-rpc") " dispatches exactly one datum per "
           "message—seamlessly across HTTP, WebSocket, or SSE.")
        (div (@ (class "feature"))
          (div (@ (class "txt"))
            (h3 "No codec on the wire")
            (p "Exact ratios and bignums cross the network intact. There is no "
               "lossy JSON floating-point approximation anywhere in the stack. A "
               "call like " (code "(rpc \"/rpc\" '(add 1 2 1/2))") " comes back "
               "as " (code "(ok 7/2)") "—the mathematical ratio perfectly "
               "preserved.")
            (p (b "The WebAssembly peer"))
            (p "The natural partner to this backend is "
               (a (@ (href "https://goeteia.dev")) "Goeteia") ", a Scheme "
               "compiler running natively in WebAssembly. Its browser-side "
               (code "(web rpc)") ", " (code "(web ws)") ", and "
               (code "(web sse)") " modules speak this exact same wire format, "
               "turning the browser into a first-class Scheme runtime.")
            (p "This very site is written in pure Scheme and compiled down to "
               "bare HTML and CSS. That honeycomb fire effect above? It is "
               "compiled and rendered in real time, directly in your browser, by "
               (a (@ (href "https://goeteia.dev")) "Goeteia") "."))
          (div (@ (class "rpccol"))
            (div (@ (class "rpcwire"))
              (a (@ (class "wnode") (href "https://igropyr.dev"))
                (img (@ (src "favicon.svg") (alt "Igropyr") (width "30") (height "30")))
                "Igropyr")
              (span (@ (class "warrow")) "⇄")
              (a (@ (class "wnode gt") (href "https://goeteia.dev"))
                (img (@ (src "goeteia-icon.svg") (alt "Goeteia") (width "26") (height "26")))
                "Goeteia"))
            (pre ,(raw rpc-code))))))

   ;; ---- 6. clustering ----
   `(section (@ (id "cluster"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "06 · From node to hive")
        (h2 "Write once, run distributed")
        (p (@ (class "lead")) "Nodes discover each other and wire up a full, true "
           "mesh—no central coordinator, and no fragile registry to babysit. "
           "Links self-heal, and work fluidly spreads across every live member.")
        (div (@ (class "feature flip"))
          (div (@ (class "txt"))
            (h3 "Self-expanding distributed cluster")
            (p "Point " (code "cluster-start") " at a discovery strategy, and it "
               "keeps the topology honest: it actively dials any member it isn't "
               "linked to yet, and mercilessly drops anyone that leaves. The "
               (code "static") " strategy uses a fixed list; with " (code "redis")
               ", nodes heartbeat themselves into a transient set. If a node "
               "stops beating, it simply " (b "falls out of the mesh")
               ". There is no central bookkeeping to drift out of sync.")
            (p (b "Secure, name-based routing"))
            (p "Underneath lies a pure node-to-node distribution layer. A mutual "
               (b "HMAC-SHA256") " handshake strictly gates who may join. Once "
               "inside, " (code "rsend") " and " (code "rcall") " reach registered "
               "processes on remote machines purely by name. "
               (code "monitor-node") " watches members come and go, while the "
               "links themselves stubbornly reconnect through network blips.")
            (p (b "Distributed execution pools"))
            (p (code "(igropyr dpool)") " rides on top of this mesh. Submit a "
               "task, and it lands on an available live node. If that node "
               "suffers a physical death mid-execution, the mesh notices, and the "
               "work instantly reappears elsewhere. You get a guaranteed "
               (b "at-least-once") " execution primitive, seamlessly stretched "
               "across the entire cluster."))
          (pre ,(raw cluster-code)))))

   ;; ---- foundations ----
   `(section (@ (id "foundations"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "Foundations")
        (h2 "What it stands on")
        (div (@ (class "cards"))
          (div (@ (class "card"))
            (div (@ (class "ic")) "λ")
            (h3 "Pure Chez Scheme")
            (p "Every line is Scheme — R6RS libraries in " (code ".sc") ", no C "
               "shim. libuv, zlib and the crypto for MySQL auth are reached "
               "through Chez's FFI directly. Whole-program compilation folds the "
               "framework and your app into one optimized binary."))
          (div (@ (class "card"))
            (div (@ (class "ic")) "✉")
            (h3 "Erlang-style actors")
            (p "Green processes with " (code "spawn / send / receive") ", "
               (code "link") " and " (code "monitor") ", a process registry, "
               (code "gen-server") " and PubSub. One OS thread, preemptive "
               "scheduling, pure message passing — no shared state, no locks."))
          (div (@ (class "card"))
            (div (@ (class "ic")) "⚡")
            (h3 "Async on libuv")
            (p "One event loop feeds thousands of parked processes. DNS, file "
               "reads and database round-trips park " (em "the calling process")
               ", never the thread. Non-blocking HTTP/WebSocket clients and "
               "Redis, MySQL and PostgreSQL drivers included.")))
        (div (@ (class "strip"))
          (div (div (@ (class "num")) "150k+") (div (@ (class "lbl")) "req/s, keep-alive, M4 Pro"))
          (div (div (@ (class "num")) "0") (div (@ (class "lbl")) "failed requests under ab -c 500"))
          (div (div (@ (class "num")) "≤35s") (div (@ (class "lbl")) "full recovery from a stuck pool"))
          (div (div (@ (class "num")) "1") (div (@ (class "lbl")) "OS thread")))))

   ;; ---- full feature list ----
   `(section (@ (id "features"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "What comes with it")
        (div (@ (class "fgrid"))
          ,(fitem "Core / framework split, like Node and Express"
             "the core exposes one entry point, " '(code "(http-listen port (lambda (req res) ...))")
             "; the bundled " '(code "(igropyr express)") " layer ("
             '(code "create-app") ", " '(code "app-get") ", " '(code "send-json!")
             ", ...) is optional, and alternative frameworks can be built on the same core")
          ,(fitem "Green processes"
             "thousands of lightweight processes scheduled over one OS thread; "
             "continuation-based context switching with preemption, so even a "
             "CPU-spinning handler cannot freeze the system")
          ,(fitem "Pure message passing"
             '(code "spawn") " / " '(code "send") " / " '(code "receive") " / "
             '(code "link") " / " '(code "monitor") "; no shared state between processes")
          ,(fitem "Fault tolerant by default"
             "a fixed worker pool behind a supervisor: crashed workers are "
             "replaced and the task retried (at most 3 times, then the client "
             "gets a 500); workers stuck for more than 30 s are killed and "
             "replaced; a slow or half-sent request only ever blocks its own reader process")
          ,(fitem "Failure hook (remote retry ring)"
             "when retries are exhausted or a stuck worker is killed (killed "
             "first, so no execution is in flight), an optional " '(code "on-failure")
             " handler answers a structured JSON fault instead of the plain 500, "
             "on the same keep-alive connection — the client resubmits (changed "
             "parameters, carried state) and gets a fresh retry round; unset, the plain 500 remains")
          ,(fitem "Conversations (process-per-dialogue)"
             "a multi-request dialogue runs as one green process holding live "
             "state — even an open database transaction — across rounds; "
             '(code "suspend!") " answers and parks, " '(code "conversation-resume!")
             " continues — carrying a token that names the reply it answers, so a "
             "double click or a retried request replays that answer instead of "
             "taking a step nobody asked for; the transaction commits through "
             '(code "commit!") ", so a death that left the flow before it is "
             "the rollback guarantee — a later resume gets " '(code "gone")
             " and may be retried — while one after it is " '(code "unknown")
             ", which may not")
          ,(fitem "Hot code swapping"
             "replace the handler (or individual routes) on a live server: the "
             "listener, open connections and worker pool stay up, in-flight "
             "requests finish on the old code")
          ,(fitem "WebSocket"
             "RFC 6455 upgrade on the same port; each socket is its own green "
             "process, so server push is just a message send")
          ,(fitem "Streaming responses & SSE"
             "chunked response body via " '(code "res-begin!") "/" '(code "res-write!")
             "/" '(code "res-end!") "; Server-Sent Events helpers on top")
          ,(fitem "OTP building blocks"
             '(code "gen-server") " (call/cast/info), a process registry ("
             '(code "register") "/" '(code "whereis") "), and topic PubSub with "
             "automatic cleanup of dead subscribers")
          ,(fitem "JSON"
             "a safe recursive-descent parser (no " '(code "read")
             "; full escape and surrogate handling) and writer")
          ,(fitem "S-expression RPC"
             "when the peer is also Scheme there is no codec: " '(code "(igropyr sexpr)")
             " is a safe whitelisted parser (no " '(code "read") ", depth-limited), and "
             '(code "app-rpc") " / " '(code "send-sexpr!") " / " '(code "ws-send-sexpr!")
             " / " '(code "sse-send-sexpr!") " carry one datum per message — exact "
             "ratios and bignums cross intact. The browser end is "
             '(a (@ (href "https://goeteia.dev")) "Goeteia") "'s "
             '(code "(web rpc/ws/sse)"))
          ,(fitem "Forms & cookies"
             '(code "req-form") " parses urlencoded and multipart bodies (file "
             "uploads included); " '(code "req-cookie") " / " '(code "set-cookie!"))
          ,(fitem "Middleware suite"
             "cookie sessions (gen-server store, CSPRNG sids), CORS with "
             "preflight, security headers, and an access logger")
          ,(fitem "Chunked transfer-encoding"
             '(code "Transfer-Encoding: chunked") " request bodies are decoded transparently")
          ,(fitem "Non-blocking Redis, MySQL and PostgreSQL clients"
             "pure Scheme, same event loop; callers park their green process "
             "while the OS thread keeps serving; both SQL drivers come with a self-healing connection pool")
          ,(fitem "Non-blocking HTTP & WebSocket clients"
             "outbound " '(code "http-get") " / " '(code "http-post") " and "
             '(code "ws-connect") ", both with async DNS (libuv thread pool) and "
             "the same park-the-caller model")
          ,(fitem "Static file serving & streaming"
             "hot files come from an in-memory cache — a hashtable lookup, no "
             "disk read and no stat syscall (mtime re-checked at most once a "
             "second). A cache miss reads once on libuv's thread pool, so a cold "
             "read never blocks the scheduler; files over 1 MiB stream in bounded "
             "chunks with backpressure (constant memory, no GC traffic), never "
             "read whole")
          ,(fitem "gzip compression"
             "responses negotiated via " '(code "Accept-Encoding")
             "; static files cache their compressed form")
          ,(fitem "Ops-ready"
             "rate limiting, a global error handler, and a Prometheus "
             '(code "/metrics") " endpoint")
          ,(fitem "Runtime introspection & graceful shutdown"
             '(code "http-stats") " (live connection/request/pool counters), "
             '(code "http-shutdown!") " (drain in-flight requests, refuse new connections)")
          ,(fitem "Multi-process scaling"
             '(code "SO_REUSEPORT") " bind option for kernel-balanced "
             "multi-process listening on Linux (pair with pm2 or systemd)")
          ,(fitem "HTTP/1.1 keep-alive & pipelining"
             "persistent connections by default on 1.1; each connection's reader "
             "process loops over successive requests")
          ,(fitem "Fast"
             "~150 k req/s with keep-alive at 100 connections, and ~32 k req/s "
             "at 500 concurrent connections (" '(code "ab -n 50000 -c 500")
             ", zero failed requests), on an Apple M4 Pro"))))

   ;; ---- acknowledgements ----
   `(section (@ (id "thanks"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "Acknowledgements")
        (h2 "Built on the shoulders of others")
        (p (@ (class "lead")) "Igropyr is built on " (b "Chez Scheme")
           " — the fastest Scheme compiler, with a first-class FFI that reaches "
           "libuv directly. With deep gratitude for "
           (a (@ (class "name") (href "https://github.com/dybvig")) (b "Kent Dybvig"))
           "'s life work, and to " (b "Cisco") " for open-sourcing it.")
        (p (@ (class "lead") (style "margin-top:18px"))
           "The primary inspirations: " (b "Node.js") " is the event-loop server "
           "on libuv, and the lean core / optional-framework split that Node and "
           "Express made the norm. The actor model, the supervisor, and Let It "
           "Crash come from " (b "Erlang/OTP") "; " (b "Swish") " — a Chez Scheme "
           "system built on those ideas — was the concrete blueprint for the "
           "scheduler, the " (code "receive") " macro, and the supervisor. The "
           "conversation model is the actor-native take on " (b "web programming "
           "with continuations") " — a great idea from the Scheme and "
           "functional-programming community.")
        (div (@ (class "credits"))
          (a (@ (class "credit") (href "https://www.scheme.com"))
             (img (@ (src "chez-icon.png") (alt "Chez Scheme") (width "24") (height "24")))
             (span "Chez Scheme"))
          (a (@ (class "credit") (href "https://www.cisco.com"))
             (img (@ (src "cisco-icon.svg") (alt "Cisco") (width "30") (height "30")))
             (span "Cisco"))
          (a (@ (class "credit") (href "https://nodejs.org"))
             (img (@ (src "nodejs-icon.svg") (alt "Node.js") (width "26") (height "26")))
             (span "Node.js"))
          (a (@ (class "credit") (href "https://www.erlang.org"))
             (img (@ (src "erlang-icon.svg") (alt "Erlang") (width "26") (height "26")))
             (span "Erlang"))
          (a (@ (class "credit") (href "https://github.com/becls/swish"))
             (img (@ (src "swish-icon.png") (alt "Swish") (width "24") (height "24")))
             (span "Swish")))))

   (foot (list `(a (@ (href "https://github.com/guenchi/Igropyr")) "GitHub")
               `(a (@ (href "manual.html")) "Manual")
               `(a (@ (href "https://github.com/guenchi/Igropyr/blob/master/LICENSE")) "MIT License"))
         "Igropyr — a high-concurrency HTTP server for Chez Scheme, built on "
         "libuv with Erlang-style message passing.")))

(write-file "index.html"
  (render-page
   "Igropyr — a distributed backend framework in pure Chez Scheme"
   (string-append "A distributed, fault-tolerant, high-concurrency backend "
                  "framework with continuations, built on Chez Scheme. "
                  "Erlang-style actors on libuv.")
   body
   (list `(script (@ (type "module") (src "fire.js"))))))
