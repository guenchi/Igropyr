;; Shared chrome for the Igropyr site, authored in Scheme and rendered
;; by Goeteia. igropyr-styles is the whole stylesheet as (web css) data
;; (the flame theme, ported from the old hand-written style.css); nav,
;; foot and render-page assemble each page. One shared sheet, like the
;; original single style.css.
(library (chrome)
  (export render-page read-file write-file igropyr-styles nav foot)
  (import (rnrs) (web html) (web css))

  ;; ---- the stylesheet, as data ----
  (define sans
    "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif")
  (define mono
    "ui-monospace, \"SF Mono\", SFMono-Regular, Menlo, Consolas, \"Liberation Mono\", monospace")

  (define (igropyr-styles)
    `((:root (--bg "#ffffff") (--bg2 "#f6f8fa") (--panel "#f6f8fa")
             (--line "#e2e7ee") (--fg "#1f2430") (--dim "#57606a")
             (--acc "#e8590c") (--acc2 "#0969da") (--warn "#9a6700")
             (--kw "#8250df") (--str "#0a7227") (--com "#6e7781") (--num "#953800"))
      ("*" (margin 0) (padding 0) (box-sizing border-box))
      (html (scroll-behavior smooth))
      (body (background (var bg)) (color (var fg))
            (font ,(string-append "16px/1.65 " sans))
            (-webkit-font-smoothing antialiased))
      ("code, pre, .mono" (font-family ,mono))
      (a (color (var acc2)) (text-decoration none))
      ("a:hover" (text-decoration underline))
      ("a.name" (color (var fg)) (text-decoration underline)
                (text-underline-offset (px 2)) (text-decoration-color (var line)))
      ("a.name:hover" (text-decoration-color (var dim)))
      (.wrap (max-width (px 1060)) (margin 0 auto) (padding 0 (px 24)))

      ;; ---- nav ----
      (nav (position sticky) (top 0) (z-index 10)
           (background (rgba 255 255 255 (dec 0 88)))
           (backdrop-filter "blur(8px)")
           (border-bottom (px 1) solid (var line)))
      ("nav .wrap" (display flex) (align-items center) (height (px 56)) (gap (px 22)))
      ("nav .logo" (font-weight 700) (color (var fg)) (font-size (px 17)))
      ("nav .logo span" (color (var acc)) (font-size (px 21)) (vertical-align "-1px"))
      ("nav .links" (margin-left auto) (display flex) (gap (px 18)) (font-size (px 14)))
      ("nav .links a" (color (var dim)))
      ("nav .links a:hover" (color (var fg)) (text-decoration none))

      ;; ---- hero ----
      (header (padding (px 84) 0 (px 64)) (text-align center)
              (background "radial-gradient(62% 52% at 50% 0%, #fff0e6 0%, transparent 100%)")
              (position relative) (overflow hidden))
      ("header .wrap" (position relative) (z-index 1))
      (.lam (font-size (px 52)) (color (var acc)) (line-height 1))
      (h1 (font-size (px 56)) (letter-spacing "-1px") (margin (px 10) 0 (px 14)))
      (.tag (font-size (px 21)) (color (var dim)) (max-width (px 640)) (margin 0 auto (px 12)))
      (".tag b" (color (var fg)) (font-weight 600))
      (.sub (color (var dim)) (font-size (px 15)) (margin-bottom (px 34)))
      (.cta (display flex) (gap (px 14)) (justify-content center) (margin-bottom (px 40)))
      (.btn (display inline-block) (padding (px 11) (px 22)) (border-radius (px 8))
            (font-size (px 15)) (font-weight 600))
      (".btn.primary" (background (var acc)) (color "#ffffff"))
      (".btn.primary:hover" (filter "brightness(1.1)") (text-decoration none))
      (".btn.ghost" (border (px 1) solid (var line)) (color (var fg)))
      (".btn.ghost:hover" (border-color (var dim)) (text-decoration none))
      (.quick (max-width (px 620)) (margin 0 auto) (text-align left)
              (background (var panel)) (border (px 1) solid (var line))
              (border-radius (px 10)) (padding (px 18) (px 22)) (font-size (px 14)))
      (".quick .c" (color (var com)))
      ;; the hero canvas (fire honeycomb), bled off the top-right corner;
      ;; visible on every width — bigger footprint on narrow screens so it
      ;; still reads as a burning honeycomb behind the hero
      (.hive (position absolute) (top "-80px") (right "-120px")
             (width "min(72vw, 1120px)") (height auto) (pointer-events none))
      ;; on phones the fire fills the whole hero instead of a corner
      (@media "(max-width: 700px)"
        (.hive (top 0) (right auto) (left (pct 50)) (width "160vw")
               (transform "translateX(-50%)") (height auto)))
      (@media "(prefers-reduced-motion: reduce)" (.hive (display none)))

      ;; ---- sections ----
      (section (padding (px 72) 0) (border-top (px 1) solid (var line)))
      (.kicker (color (var acc)) (font-size (px 13)) (font-weight 700)
               (letter-spacing (px 2)) (text-transform uppercase))
      (h2 (font-size (px 34)) (margin (px 8) 0 (px 14)) (letter-spacing "-.5px"))
      (.lead (color (var dim)) (font-size (px 17)) (max-width (px 680)))
      (".lead code" (color (var acc)) (font-size (em 0 82)) (background (var bg2))
                    (padding (px 1) (px 5)) (border-radius (px 4)))
      (.feature (display grid) (grid-template-columns "1fr 1fr") (gap (px 44))
                (align-items center) (margin-top (px 40)))
      (".feature.flip .txt" (order 2))
      (".feature > *" (min-width 0))   ; let overflow-x on inner <pre> win, not overflow the page
      (".feature h3" (font-size (px 24)) (margin-bottom (px 12)))
      (".feature p" (color (var dim)) (margin-bottom (px 12)))
      (".feature p b, .feature li b" (color (var fg)) (font-weight 600))
      (".feature ul" (color (var dim)) (padding-left (px 20)))
      (".feature li" (margin (px 6) 0))
      ;; inline code in feature prose: the same chip every other prose
      ;; context wears -- full-size mono loose in 16px sans reads as
      ;; broken letter-spacing
      (".feature p code, .feature li code"
       (color (var acc)) (font-size (em 0 82)) (background (var bg2))
       (padding (px 1) (px 5)) (border-radius (px 4)))
      (pre (background (var bg2)) (border (px 1) solid (var line))
           (border-radius (px 10)) (padding (px 20)) (overflow-x auto)
           (font-size (px 13 50)) (line-height (dec 1 6)))
      (.k (color (var kw))) (.s (color (var str)))
      (.c (color (var com)) (font-style italic))
      (.n (color (var num))) (.f (color (var acc2)))

      ;; ---- Igropyr <-> Goeteia interaction badge (section 05) ----
      (.rpcwire (display flex) (align-items center) (justify-content center)
                (gap (px 16)) (margin-bottom (px 22)))
      (".rpcwire .wnode" (display inline-flex) (align-items center) (gap (px 9))
                         (font-weight 600) (color (var fg)) (font-size (px 15))
                         (text-decoration none))
      (".rpcwire .wnode:hover" (color (var acc)) (text-decoration none))
      (".rpcwire .wnode.gt:hover" (color "#1550c4"))   ; Goeteia's lapis
      (".rpcwire .wnode img" (display block))
      (".rpcwire .warrow" (font-size (px 26)) (color (var dim)))

      ;; ---- secondary cards ----
      (.cards (display grid) (grid-template-columns "repeat(3, 1fr)") (gap (px 20))
              (margin-top (px 40)))
      (.card (background (var panel)) (border (px 1) solid (var line))
             (border-radius (px 12)) (padding (px 26)))
      (".card .ic" (font-size (px 26)) (margin-bottom (px 12)))
      (".card h3" (font-size (px 18)) (margin-bottom (px 10)))
      (".card p" (color (var dim)) (font-size (px 14 50)))
      (".card code" (color (var acc)) (font-size (px 13)))

      ;; ---- full feature list ----
      (.fgrid (max-width (px 780)) (margin-top (px 40)))
      (.fitem (margin-bottom (px 22)) (padding-bottom (px 22))
              (border-bottom (px 1) solid (var line)))
      (".fitem:last-child" (border-bottom none))
      (.fterm (display block) (color (var fg)) (font-weight 700)
              (font-size (px 18)) (margin-bottom (px 7)) (letter-spacing "-.2px"))
      (".fterm b" (font-weight 700))
      (.fdesc (display block) (color (var dim)) (font-size (px 15 50)) (line-height (dec 1 65)))
      (".fitem code" (color (var acc)) (font-size (px 13 50)) (background (var bg2))
                     (padding (px 1) (px 5)) (border-radius (px 4)))

      ;; ---- credits ----
      (.credits (display flex) (flex-wrap wrap) (gap (px 14)) (margin-top (px 26)))
      (.credit (display inline-flex) (align-items center) (gap (px 9))
               (padding (px 9) (px 16) (px 9) (px 12)) (border (px 1) solid (var line))
               (border-radius (px 10)) (background (var panel))
               (color (var fg)) (font-size (px 15)) (font-weight 600))
      (".credit:hover" (border-color (var dim)) (text-decoration none))
      (".credit img" (display block))

      ;; ---- numbers strip ----
      (.strip (display flex) (justify-content center) (gap (px 64))
              (flex-wrap wrap) (margin-top (px 44)) (text-align center))
      (".strip .num" (font-size (px 34)) (font-weight 700) (color (var acc)))
      (".strip .lbl" (color (var dim)) (font-size (px 13 50)))

      (footer (border-top (px 1) solid (var line)) (padding (px 40) 0 (px 56))
              (color (var dim)) (font-size (px 14)) (text-align center))
      ("footer .links" (margin-bottom (px 10)) (display flex) (gap (px 22))
                       (justify-content center))
      ("footer .powered" (margin-top (px 12)) (font-size (px 13)))
      ("footer .powered a" (color (var acc)))
      ("footer .powered a:hover" (color (var acc2)))
      (@media "(max-width: 840px)"
        (h1 (font-size (px 40)))
        (.feature (grid-template-columns "1fr"))
        (".feature.flip .txt" (order 0))
        (.cards (grid-template-columns "1fr"))
        (.strip (gap (px 34))))

      ;; ---- mapping table (agent page) ----
      (.maptable (width (pct 100)) (border-collapse collapse) (margin-top (px 34))
                 (font-size (px 14 50)))
      (".maptable th" (text-align left) (color (var dim)) (font-weight 600)
                      (font-size (px 12)) (letter-spacing (px 1 50)) (text-transform uppercase)
                      (padding 0 (px 16) (px 12) 0) (border-bottom (px 1) solid (var line)))
      (".maptable td" (padding (px 13) (px 16) (px 13) 0) (border-bottom (px 1) solid (var line))
                      (vertical-align top) (color (var dim)))
      (".maptable td:first-child" (color (var fg)) (white-space nowrap))
      (".maptable code" (color (var acc)) (font-size (px 12 50)) (background (var bg2))
                        (padding (px 1) (px 5)) (border-radius (px 4)))
      (.backlink (display inline-block) (margin-top (px 8)) (color (var dim)) (font-size (px 14)))

      ;; ---- rendered markdown (manual) ----
      (.manualhead (padding (px 40) 0 (px 8)))
      (".manualhead .wrap" (display flex) (align-items center) (gap (px 16)))
      (".manualhead h1" (font-size (px 34)) (letter-spacing "-.5px") (margin 0))
      (.langtoggle (margin-left auto) (display flex) (gap (px 6)))
      (".langtoggle button" (font inherit) (font-size (px 14)) (font-weight 600) (cursor pointer)
                            (padding (px 6) (px 14)) (border (px 1) solid (var line))
                            (border-radius (px 8)) (background (var bg)) (color (var dim)))
      (".langtoggle button.on" (background (var acc)) (color "#fff") (border-color (var acc)))
      (.md-body (max-width (px 820)) (margin 0 auto) (padding (px 20) (px 24) (px 90))
                (color "#2b303a") (font-size (px 16)) (line-height (dec 1 7)))
      (".md-body h1, .md-body h2, .md-body h3, .md-body h4"
       (color (var fg)) (letter-spacing "-.3px") (line-height (dec 1 3))
       (margin "1.9em 0 .6em") (scroll-margin-top (px 72)))
      (".md-body h1" (font-size (px 30)))
      (".md-body h2" (font-size (px 24)) (padding-bottom (em 0 30)) (border-bottom (px 1) solid (var line)))
      (".md-body h3" (font-size (px 19)))
      (".md-body h4" (font-size (px 16)))
      (".md-body p, .md-body li" (color "#2b303a"))
      (".md-body a" (color (var acc2)))
      (".md-body ul, .md-body ol" (padding-left (px 26)) (margin "0.6em 0"))
      (".md-body li" (margin "0.32em 0"))
      (".md-body code" (font-family ,mono) (font-size (em 0 86)) (background (var bg2))
                       (color "#b02a4a") (padding "1.5px 6px") (border-radius (px 5)))
      (".md-body pre" (background "#0f141c") (border (px 1) solid "#0f141c") (border-radius (px 10))
                      (padding (px 18) (px 20)) (overflow-x auto) (margin "1em 0"))
      (".md-body pre code" (background none) (color "#d7dde8") (padding 0)
                           (font-size (px 13 50)) (line-height (dec 1 6)))
      (".md-body table" (border-collapse collapse) (width (pct 100)) (margin "1.2em 0")
                        (font-size (px 14 50)) (display block) (overflow-x auto))
      (".md-body th, .md-body td" (border (px 1) solid (var line)) (padding (px 8) (px 12))
                                  (text-align left) (vertical-align top))
      (".md-body th" (background (var bg2)) (color (var fg)) (font-weight 600))
      (".md-body blockquote" (margin "1em 0") (padding "0.3em 1em") (color (var dim))
                             (border-left (px 3) solid (var line)))
      (".md-body hr" (border none) (border-top (px 1) solid (var line)) (margin "2em 0"))
      (".md-body img" (max-width (pct 100)))
      (.md-loading (max-width (px 820)) (margin (px 40) auto) (padding 0 (px 24)) (color (var dim)))))

  ;; ---- shared nav + footer ----
  (define (nav)
    `(nav (div (@ (class "wrap"))
            (div (@ (class "logo"))
              (a (@ (href "index.html") (style "color:inherit")) (span "λ") " Igropyr"))
            (div (@ (class "links"))
              (a (@ (href "manual.html")) "Manual")
              (a (@ (href "agent.html")) "Agent")
              (a (@ (href "https://github.com/guenchi/Igropyr")) "GitHub")))))
  ;; links: a list of (a ...) nodes; tagline: the remaining nodes
  ;; (omitted entirely when none are given)
  (define (foot links . tagline)
    `(footer
       (div (@ (class "links")) ,@links)
       ,@(if (null? tagline) '() (list `(div ,@tagline)))
       (div (@ (class "powered"))
         "Powered by " (a (@ (href "https://goeteia.dev")) "Goeteia"))))

  ;; ---- assemble a document ----
  ;; head-extra: extra nodes for <head>; body-nodes: the page body;
  ;; scripts: trailing <script> nodes.
  (define (render-page title desc body-nodes . opts)
    (let ((scripts (if (pair? opts) (car opts) '())))
      (html->document
       `(html (@ (lang "en"))
          (head
           (meta (@ (charset "utf-8")))
           (meta (@ (name "viewport") (content "width=device-width, initial-scale=1")))
           (title ,title)
           (meta (@ (name "description") (content ,desc)))
           (link (@ (rel "icon") (href "favicon.svg") (type "image/svg+xml")))
           (style ,(css->string (igropyr-styles))))
          (body ,@body-nodes ,@scripts)))))

  ;; ---- build-time file I/O ----
  (define (read-file path)
    (call-with-input-file path
      (lambda (p)
        (let loop ((acc '()))
          (let ((c (read-char p)))
            (if (eof-object? c) (list->string (reverse acc))
                (loop (cons c acc))))))))
  (define (write-file path s)
    (call-with-output-file path (lambda (p) (display s p)))))
