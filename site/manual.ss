;; The Igropyr manual page, in Scheme. A thin shell: marked.js renders
;; docs/manual.md client-side; the loader script comes from (manual-js)
;; verbatim.
(import (rnrs) (web html) (chrome) (manual-js))

(define body
  (list
   (nav)
   `(div (@ (class "manualhead"))
      (div (@ (class "wrap"))
        (h1 "Manual")))
   `(main (@ (id "md") (class "md-body"))
      (p (@ (class "md-loading")) "Loading the manual…"))
   (foot (list `(a (@ (href "index.html")) "Igropyr")
               `(a (@ (href "agent.html")) "Agent")
               `(a (@ (href "https://github.com/guenchi/Igropyr")) "GitHub")))))

(write-file "manual.html"
  (render-page
   "Manual — Igropyr"
   (string-append "The Igropyr manual: architecture, the actor model, the "
                  "libuv-callback invariant, fault tolerance, conversations, "
                  "clients, and more.")
   body
   (list `(script (@ (src "https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js")))
         `(script ,(raw manual-loader)))))
