;; The node-to-igropyr agent page, in Scheme. Static (web html) SXML.
(import (rnrs) (web html) (chrome))

;; one mapping-table row: left cell (Node/Express), right cell (Igropyr)
(define (row left right)
  `(tr (td ,@left) (td ,@right)))

(define body
  (list
   (nav)
   `(header
      (div (@ (class "wrap"))
        (div (@ (class "lam")
                (style "display:flex;align-items:center;justify-content:center;gap:18px"))
          (img (@ (src "nodejs-icon.svg") (alt "Node.js") (width "46") (height "46")))
          (span (@ (style "color:var(--dim);font-weight:300")) "→")
          (span "λ"))
        (h1 "node-to-igropyr")
        (p (@ (class "tag")) "Hand it a Node.js route, a middleware, or a whole "
           "small Express app — get back the " (b "Igropyr port") ".")
        (p (@ (class "sub")) "An AI coding agent · re-architecture, not transliteration")
        (div (@ (class "cta"))
          (a (@ (class "btn primary") (href "agent/node-to-igropyr.md")) "Get the agent")
          (a (@ (class "btn ghost") (href "index.html")) "Back to Igropyr"))))

   `(section (@ (id "what"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "What it does")
        (h2 "Re-architecture, not transliteration")
        (p (@ (class "lead")) "Node's single-threaded event loop with Promises, "
           (code "async/await") " and defensive " (code "try/catch") " becomes "
           "Igropyr's Erlang-style actor model with " (code "spawn") "/" (code "send")
           "/" (code "receive") ", a supervised worker pool, and Let It Crash. The "
           "agent produces Scheme a maintainer of the repo would have written — not "
           "JavaScript wearing parentheses.")
        (div (@ (class "cards"))
          (div (@ (class "card"))
            (div (@ (class "ic")) "⟶")
            (h3 "async/await → straight-line")
            (p "The scheduler yields for you. I/O calls already block only the "
               "calling process, so promise chains flatten into ordinary "
               "sequential code — no promise type invented."))
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
               "except through a process.")))))

   `(section (@ (id "mapping"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "The mapping")
        (h2 "How Node constructs land in Igropyr")
        (p (@ (class "lead")) "A selection from the agent's conversion table. It "
           "reads the real library source before writing, since the API evolves.")
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
                 '((code "(string->json s)") " / " (code "(json->string v)")))))))

   `(section (@ (id "use"))
      (div (@ (class "wrap"))
        (div (@ (class "kicker")) "Get it")
        (h2 "The agent, in one file")
        (p (@ (class "lead")) "It is a single Markdown agent definition — house "
           "rules, the full conversion table, the invariants, the workflow, and "
           "the current public API surface. Feed it to any AI coding agent as its "
           "instructions and point it at the Node code to port.")
        (div (@ (class "cta") (style "justify-content:flex-start"))
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
         "node-to-igropyr — an AI agent for porting Node.js/Express to Igropyr.")))

(write-file "agent.html"
  (render-page
   "node-to-igropyr — an AI agent that ports Node.js to Igropyr"
   (string-append "node-to-igropyr: an AI coding agent that re-architects "
                  "Node.js/Express services into Igropyr's actor model — "
                  "async/await to straight-line, try/catch to Let It Crash.")
   body))
