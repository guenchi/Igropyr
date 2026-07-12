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
        (p (@ (class "tag")) "A web server where " (b "crashes heal themselves")
           ", " (b "code hot-swaps") ", " (b "faults speak a protocol") ", and "
           (b "dialogues are processes") ".")
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
        (p (@ (class "lead")) "Every request runs in a supervised worker pool. "
           "Handlers don't defend — they crash, and the system recovers.")
        (div (@ (class "feature"))
          (div (@ (class "txt"))
            (h3 "Crashes heal themselves")
            (ul
              (li "A crashed worker is " (b "replaced instantly") "; the task is "
                  "retried on a fresh worker, up to 3 times, before the client "
                  "sees an error.")
              (li "A worker stuck longer than 30 s — even a CPU-spinning "
                  "loop — is " (b "killed and replaced") ": preemptive scheduling "
                  "means nothing can freeze the server.")
              (li "A half-sent request parks only " (b "its own reader process")
                  " and is reaped by timeout. Other connections never notice."))
            (p "Write the happy path. The supervisor owns the sad one."))
          (pre ,(raw crash-code)))))

   ;; ---- 2. hot swap ----
   `(section (@ (id "hotswap"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "02 · Live systems")
        (h2 "Hot code swapping")
        (p (@ (class "lead")) "Replace the handler — or a single route — on a "
           "running server. The listener, open connections and the worker pool "
           "stay up; in-flight requests finish on the old code.")
        (div (@ (class "feature flip"))
          (div (@ (class "txt"))
            (h3 "Deploy without a restart")
            (p "Routes live in a mutable registry behind the pool. Re-registering "
               "a path " (b "replaces it atomically") " for the next request; "
               (code "http-swap!") " replaces the whole handler the same way.")
            (p "Combined with graceful shutdown (" (code "http-shutdown!")
               " drains in-flight work) and " (code "SO_REUSEPORT")
               " multi-process listening, zero-downtime operation is the "
               "default, not a project."))
          (pre ,(raw hotswap-code)))))

   ;; ---- 3. failure hook ----
   `(section (@ (id "faults"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "03 · The remote retry ring")
        (h2 "Faults speak a protocol")
        (p (@ (class "lead")) "When retries are exhausted or a stuck worker is "
           "killed, Igropyr doesn't just throw a 500 — it can tell the client "
           "exactly what happened, on a connection that stays open.")
        (div (@ (class "feature"))
          (div (@ (class "txt"))
            (h3 "Killed first, told after")
            (p "The " (code "on-failure") " hook answers a structured fault "
               (b "after") " the stuck worker is dead — so when the client hears "
               (code "stuck") ", there is " (b "no execution left in flight")
               ". The state is definite.")
            (ul
              (li (b "crash") " — retries exhausted; resubmit with changed "
                  "parameters, or compensate.")
              (li (b "stuck") " — killed mid-flight; resubmit carrying state, "
                  "or roll back."))
            (p "Keep-alive survives the fault, so the client resubmits on the "
               (b "same connection") " and gets a fresh retry round. Shorten "
               (code "stuck-ms") " and a user who once stared at a spinner for "
               "30 s now rings through several informed retries in the same "
               "time — failures become invisible at the UI."))
          (pre ,(raw faults-code)))))

   ;; ---- 4. conversations ----
   `(section (@ (id "conversations"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "04 · Web programming with continuations")
        (h2 "Dialogues are processes")
        (p (@ (class "lead")) "A multi-request dialogue — a wizard, a booking, a "
           "transfer — runs as " (b "one green process") ". Its local bindings are "
           "the conversation state, including things a session store can never "
           "hold: an " (b "open database transaction") ", spanning rounds.")
        (div (@ (class "feature flip"))
          (div (@ (class "txt"))
            (h3 "Control flow is program text")
            (p "\"The user is at the confirm step\" means the process is parked "
               (b "at that line") ". A step order the code cannot express cannot "
               "happen — no state machine to get wrong, no replay to defend "
               "against.")
            (p (b "The " (code "gone") " guarantee:") " death for any reason — "
               "crash, TTL, completion — unregisters the process, and a later "
               "resume answers " (code "gone") ". Dead process = dropped "
               "connection = the database itself rolled back: " (code "gone")
               " " (b "proves") " nothing committed. Together with the fault "
               "codes above, the client always knows the definite server state "
               "— a complete remote transaction ring."))
          (pre ,(raw conv-code)))))

   ;; ---- 5. s-expression rpc ----
   `(section (@ (id "rpc"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "05 · Scheme talks to Scheme")
        (h2 "Communicate in S-expressions")
        (p (@ (class "lead")) "When the client is Scheme too, requests and replies "
           "are s-expressions — there is no codec to design. " (code "(igropyr sexpr)")
           " is the safe parser; " (code "app-rpc") " dispatches one datum per "
           "message, over HTTP, WebSocket or SSE.")
        (div (@ (class "feature"))
          (div (@ (class "txt"))
            (h3 "No codec on the wire")
            (p "Exact ratios and bignums cross the wire intact — no floating-point "
               "JSON approximation anywhere. " (code "(rpc \"/rpc\" '(add 1 2 1/2))")
               " comes back " (code "(ok 7/2)") ", the ratio preserved.")
            (p "The peer is " (a (@ (href "https://goeteia.dev")) "Goeteia") ", a "
               "self-hosting Scheme-to-WebAssembly compiler; its " (code "(web rpc)")
               " / " (code "(web ws)") " / " (code "(web sse)") " speak the same wire "
               "format.")
            (p "This site itself is written in pure Scheme, and compiled to HTML, "
               "CSS and WebAssembly by " (a (@ (href "https://goeteia.dev")) "Goeteia")
               " — the honeycomb fire above included."))
          (div (@ (class "rpccol"))
            (div (@ (class "rpcwire"))
              (a (@ (class "wnode") (href "https://igropyr.com"))
                (img (@ (src "favicon.svg") (alt "Igropyr") (width "30") (height "30")))
                "Igropyr")
              (span (@ (class "warrow")) "⇄")
              (a (@ (class "wnode") (href "https://goeteia.dev"))
                (img (@ (src "goeteia-icon.svg") (alt "Goeteia") (width "26") (height "26")))
                "Goeteia"))
            (pre ,(raw rpc-code))))))

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
               "Redis/MySQL drivers included.")))
        (div (@ (class "strip"))
          (div (div (@ (class "num")) "120k+") (div (@ (class "lbl")) "req/s, keep-alive, laptop"))
          (div (div (@ (class "num")) "0") (div (@ (class "lbl")) "failed requests under ab -c 500"))
          (div (div (@ (class "num")) "≤35s") (div (@ (class "lbl")) "full recovery from a stuck pool"))
          (div (div (@ (class "num")) "1") (div (@ (class "lbl")) "OS thread")))))

   ;; ---- full feature list ----
   `(section (@ (id "features"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "Everything included")
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
             " continues, and death for any reason (crash, TTL) means guaranteed "
             "rollback: a later resume gets " '(code "gone"))
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
          ,(fitem "Non-blocking Redis and MySQL clients"
             "pure Scheme, same event loop; callers park their green process "
             "while the OS thread keeps serving; MySQL comes with a self-healing connection pool")
          ,(fitem "Non-blocking HTTP & WebSocket clients"
             "outbound " '(code "http-get") " / " '(code "http-post") " and "
             '(code "ws-connect") ", both with async DNS (libuv thread pool) and "
             "the same park-the-caller model")
          ,(fitem "Async file reads"
             "static files are read on libuv's thread pool, so a large or cold "
             "read never blocks the scheduler")
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
             "~35 k req/s at 500 concurrent connections on an Apple Silicon "
             "laptop (" '(code "ab -n 50000 -c 500") ", zero failed requests)"))))

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
   "Igropyr — a fault-tolerant web server in pure Chez Scheme"
   (string-append "Igropyr: crashes heal themselves, code hot-swaps, faults "
                  "speak a protocol, and dialogues are processes. Erlang-style "
                  "actors on libuv, written entirely in Chez Scheme.")
   body
   (list `(script (@ (type "module") (src "fire.js"))))))
