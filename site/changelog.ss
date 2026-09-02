;; The Igropyr changelog page, in Scheme. The same thin shell as the
;; manual: marked.js renders docs/changelog.md client-side, and the
;; loader comes from (md-js), so both pages fetch and render the same way.
(import (rnrs) (web html) (chrome) (md-js))

(define body
  (list
   (nav)
   `(div (@ (class "manualhead"))
      (div (@ (class "wrap"))
        (h1 "Changelog")))
   `(main (@ (id "md") (class "md-body"))
      (p (@ (class "md-loading")) "Loading the changelog…"))
   (foot (list `(a (@ (href "index.html")) "Igropyr")
               `(a (@ (href "manual.html")) "Manual")
               `(a (@ (href "agent.html")) "Agent")
               `(a (@ (href "https://github.com/guenchi/Igropyr")) "GitHub")))))

(write-file "changelog.html"
  (render-page
   "Changelog — Igropyr"
   (string-append "Every published version of Igropyr: what each release "
                  "added, changed and fixed, which names entered or left "
                  "the public API, and how the numbering was reconciled "
                  "with the registry.")
   body
   (list `(script (@ (src "https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js")))
         `(script ,(raw (md-loader "docs/changelog.md" "the changelog"))))))
