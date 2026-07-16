;; The Igropyr agents page, in Scheme. Static (web html) SXML. Two AI
;; coding agents: igropyr-dev (build on Igropyr) and node-to-igropyr
;; (port an existing Node/Express app).
(import (rnrs) (web html) (chrome))

;; one mapping-table row: left cell (Node/Express), right cell (Igropyr)
(define (row left right)
  `(tr (td ,@left) (td ,@right)))

(define body
  (list
   (nav)
   `(header
      (div (@ (class "wrap"))
        (div (@ (class "lam")) "λ")
        (h1 "Agents for Igropyr")
        (p (@ (class "tag")) "Two AI coding agents — one to " (b "build") " new "
           "services in Igropyr's actor model, one to " (b "port") " an existing "
           "Node/Express app.")
        (p (@ (class "sub")) "Self-contained Markdown · verified against Igropyr 1.1.8 source")
        (div (@ (class "cta"))
          (a (@ (class "btn primary") (href "#dev")) "Build on Igropyr")
          (a (@ (class "btn ghost") (href "#port")) "Port from Node"))))

   ;; ---- agent 1: igropyr-dev ----
   `(section (@ (id "dev"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "Build on Igropyr")
        (h2 "igropyr-dev — the development agent")
        (p (@ (class "lead")) "Hand it a spec, a single endpoint, or the framework "
           "itself. " (code "igropyr-dev") " writes idiomatic Chez Scheme on Igropyr — "
           "direct blocking style, let-it-crash error handling, and a verified v1.1.8 "
           "API it reads from source before writing a line.")
        (div (@ (class "cards"))
          (div (@ (class "card"))
            (div (@ (class "ic")) "≡")
            (h3 "Direct blocking style")
            (p "No async/await, no callbacks. " (code "mysql-query") ", "
               (code "http-get") " and " (code "receive") " park only the calling "
               "green process — Node's " (code "await") " chains flatten into "
               "ordinary sequential lines."))
          (div (@ (class "card"))
            (div (@ (class "ic")) "✓")
            (h3 "Verified API, never guessed")
            (p "Rule zero: it greps the " (code ".sc") " source headers before "
               "writing. A module map of every v1.1.8 export stops it from "
               "hallucinating procedure names — when in doubt, the source wins."))
          (div (@ (class "card"))
            (div (@ (class "ic")) "◆")
            (h3 "Records first, contracts at the edges")
            (p (code "define-checked-record") " for structured data, "
               (code "define-checked") " at module boundaries — the type discipline "
               "that replaces TS interfaces, and that knows never to break a tail "
               "call.")))
        (div (@ (class "cta") (style "justify-content:flex-start;margin-top:38px"))
          (a (@ (class "btn primary") (href "agent/igropyr-dev.md") (download #t))
             "Download igropyr-dev.md")
          (a (@ (class "btn ghost") (href "agent/igropyr-dev.md")) "View raw"))
        (p (@ (class "backlink")) "Covers the actor model, the whole module map, "
           "records & contracts, the build/test incantation (" (code ".sc")
           " extension mapping and all), and every gotcha — one Markdown file, "
           "fed to any AI coding agent as its instructions.")))

   ;; ---- agent 2: node-to-igropyr ----
   `(section (@ (id "port"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "Port from Node")
        (h2 "node-to-igropyr — the porting agent")
        (p (@ (class "lead")) "Hand it a Node.js route, a middleware, or a whole small "
           "Express app — get back the " (b "Igropyr port") ". Node's single-threaded "
           "event loop with Promises, " (code "async/await") " and defensive "
           (code "try/catch") " becomes Igropyr's actor model with " (code "spawn")
           "/" (code "send") "/" (code "receive") ", a supervised worker pool, and Let "
           "It Crash — Scheme a maintainer would have written, not JavaScript wearing "
           "parentheses.")
        (div (@ (class "cards"))
          (div (@ (class "card"))
            (div (@ (class "ic")) "⟶")
            (h3 "async/await → straight-line")
            (p "The scheduler yields for you. I/O calls already block only the "
               "calling process, so promise chains flatten into ordinary sequential "
               "code — no promise type invented."))
          (div (@ (class "card"))
            (div (@ (class "ic")) "✦")
            (h3 "try/catch → Let It Crash")
            (p "Blanket 500-catchers are deleted: that is the worker supervisor's "
               "job. A " (code "guard") " stays only where there is a specific, "
               "meaningful recovery."))
          (div (@ (class "card"))
            (div (@ (class "ic")) "⚙")
            (h3 "shared state → gen-server")
            (p "A module-level " (code "Map") " shared across requests becomes a "
               "process (gen-server), because workers never share mutable state "
               "except through a process.")))
        (table (@ (class "maptable"))
          (thead (tr (th "Node.js / Express") (th "Igropyr")))
          (tbody
           ,(row '((code "async function") " / " (code "await p"))
                 '("straight-line synchronous Scheme; I/O parks the calling process only"))
           ,(row '((code "try { } catch → 500"))
                 '("delete it — the supervisor retries then answers 500 (Let It Crash)"))
           ,(row '((code "app.get('/x', h)"))
                 '((code "(app-get app \"/x\" (lambda (req res) ...))")))
           ,(row '((code "(req, res, next)"))
                 '((code "(lambda (req res next) ...)") " — call " (code "(next)")))
           ,(row '((code "req.params.id"))
                 '((code "(req-param req \"id\")")))
           ,(row '((code "req.body") " (json)")
                 '((code "(req-json req)") "; read with " (code "(json-ref j \"name\")")))
           ,(row '((code "res.json(obj)"))
                 '((code "(send-json! res alist)")))
           ,(row '((code "res.status(c)"))
                 '((code "(set-status! res c)") " then a " (code "send-*!")))
           ,(row '("SSE / " (code "res.write"))
                 '((code "(sse-start! res)") " + " (code "(sse-send! res msg)") " in a spawned process"))
           ,(row '((code "ws.on('message')"))
                 '((code "(app-ws app \"/p\" (lambda (ws req) ...))") ", loop on " (code "(ws-recv ws)")))
           ,(row '((code "setInterval") " / worker")
                 '((code "(spawn (lambda () (let loop () ... (sleep-ms n) (loop))))")))
           ,(row '((code "EventEmitter") " / pub-sub")
                 '((code "(igropyr pubsub)") ": " (code "subscribe") " / " (code "publish")))
           ,(row '("stateful singleton")
                 '("a " (code "gen-server") " (" (code "(igropyr gen-server)") ")"))
           ,(row '((code "JSON.parse") " / " (code "stringify"))
                 '((code "(string->json s)") " / " (code "(json->string v)")))))
        (div (@ (class "cta") (style "justify-content:flex-start;margin-top:38px"))
          (a (@ (class "btn primary") (href "agent/node-to-igropyr.md") (download #t))
             "Download node-to-igropyr.md")
          (a (@ (class "btn ghost") (href "agent/node-to-igropyr.md")) "View raw"))
        (p (@ (class "backlink")) "Hard rules it never breaks: round parens only, "
           "English comments, and it reads the real " (code ".sc") " source before "
           "writing — flagging anything with no clean Igropyr equivalent rather "
           "than inventing an API.")))

   (foot (list `(a (@ (href "index.html")) "Igropyr")
               `(a (@ (href "manual.html")) "Manual")
               `(a (@ (href "https://github.com/guenchi/Igropyr")) "GitHub"))
         "Two AI agents for Igropyr — build new services in the actor model, "
         "or port an existing Node/Express app.")))

(write-file "agent.html"
  (render-page
   "Agents for Igropyr — AI coding agents that build and port"
   (string-append "Two AI coding agents for Igropyr: igropyr-dev writes idiomatic "
                  "Chez Scheme on the actor framework, and node-to-igropyr "
                  "re-architects Node.js/Express services into it — both verified "
                  "against Igropyr 1.1.8 source.")
   body))
