#!chezscheme
;;; (igropyr ssr) -- cached SSR over quickjs: a render caches by key, a
;;; second identical call HITS (no re-render, proven by a JS render counter),
;;; invalidate/clear drop entries, stats report hits/misses, and a throwing
;;; render surfaces via ssr-try-render without being cached (the engine
;;; recovers via crash-only rebuild). SHIM-GATED like test/quickjs.sc: skips
;;; cleanly when the QuickJS dylib is absent, so run-all stays green without it.

(import (chezscheme) (igropyr actor) (igropyr ssr)
        (only (igropyr quickjs) qjs-call!))

(define (shim-present?)
  (or (let ((e (getenv "IGROPYR_QUICKJS_SO"))) (and e (> (string-length e) 0)))
      (file-exists? "igropyr/libigropyr-quickjs.dylib")
      (file-exists? ".build-links/igropyr/libigropyr-quickjs.dylib")
      (file-exists? "libigropyr-quickjs.dylib")
      (file-exists? "igropyr/libigropyr-quickjs.so")
      (file-exists? ".build-links/igropyr/libigropyr-quickjs.so")
      (file-exists? "libigropyr-quickjs.so")))

(unless (shim-present?)
  (display "ssr: shim not built, test skipped\n") (exit 0))

(define failures 0)
(define (check label ok)
  (unless ok (set! failures (+ failures 1)) (display "FAIL ") (display label) (newline)))

;; render() counts its calls in a JS global so a cache HIT is provable (N does
;; not advance on a hit); count() reads it; boom() throws.
(define bundle "
var N = 0;
function render(j){ N++; var p = JSON.parse(j); return '<h1>'+p.t+'</h1>'; }
function count(_){ return '' + N; }
function boom(j){ throw new Error('render failed'); }
")

(start-scheduler
  (lambda ()
    (define r (make-ssr bundle))
    (define (N) (string->number (qjs-call! "count" "")))

    ;; miss -> render (N=1)
    (check "render-a"   (string=? (ssr-render r "render" '(("t" . "A")) '((key . "/a"))) "<h1>A</h1>"))
    (check "rendered-1" (= 1 (N)))
    ;; same key -> HIT, no re-render (N stays 1)
    (check "render-a2"  (string=? (ssr-render r "render" '(("t" . "A")) '((key . "/a"))) "<h1>A</h1>"))
    (check "hit-no-rerender" (= 1 (N)))
    ;; different key -> miss (N=2)
    (check "render-b"   (string=? (ssr-render r "render" '(("t" . "B")) '((key . "/b"))) "<h1>B</h1>"))
    (check "rendered-2" (= 2 (N)))
    ;; invalidate /a then render -> miss (N=3)
    (ssr-invalidate! r "/a")
    (check "render-a3"  (string=? (ssr-render r "render" '(("t" . "A")) '((key . "/a"))) "<h1>A</h1>"))
    (check "rerender-after-invalidate" (= 3 (N)))
    ;; stats
    (let ((s (ssr-stats r)))
      (check "stats-hits"   (>= (cdr (assq 'hits s)) 1))
      (check "stats-misses" (>= (cdr (assq 'misses s)) 3))
      (check "stats-size"   (>= (cdr (assq 'size s)) 1)))
    ;; clear then render /b -> miss (N=4)
    (ssr-clear! r)
    (check "render-b2"  (string=? (ssr-render r "render" '(("t" . "B")) '((key . "/b"))) "<h1>B</h1>"))
    (check "rerender-after-clear" (= 4 (N)))
    ;; default key (sha256 of props): same props hits the second time
    (let ((n0 (N)))
      (ssr-render r "render" '(("t" . "C")))
      (let ((n1 (N)))
        (check "default-key-rendered-once" (= (+ n0 1) n1))
        (ssr-render r "render" '(("t" . "C")))
        (check "default-key-hit" (= n1 (N)))))
    ;; try-render on a throwing fn -> (values #f text), not cached
    (let-values (((ok txt) (ssr-try-render r "boom" '(("t" . "X")) '((key . "/boom")))))
      (check "try-render-fails" (not ok))
      (check "try-render-text"  (and (string? txt) (> (string-length txt) 0))))
    ;; engine recovers after the throw (crash-only rebuild)
    (check "recovers" (string=? (ssr-render r "render" '(("t" . "Z")) '((key . "/z"))) "<h1>Z</h1>"))

    (if (zero? failures)
        (begin (display "ssr: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
