#!chezscheme
;;; (igropyr quickjs) -- the pure-Scheme QuickJS binding: boot + call,
;;; JSON round-trip, the return-based string contract, JS-error boundary with
;;; crash-only rebuild (generation bumps, engine recovers), the no-such-fn
;;; path, and the two HARD guards a pure-Scheme embedding must still enforce:
;;; the interrupt-deadline (a runaway loop is aborted, not a scheduler freeze)
;;; and the memory cap (an allocation bomb -> in-JS OOM, not process death).
;;; A perf probe reports the interrupt-handler's per-call overhead.
;;;
;;; Needs a stock shared libquickjs: set IGROPYR_LIBQUICKJS_SO or install one
;;; on a standard path. Skips cleanly (exit 0) when absent, so run-all stays
;;; green on hosts without QuickJS.

(import (chezscheme) (igropyr quickjs))

(define (raw-quickjs-present?)
  (or (let ((e (getenv "IGROPYR_LIBQUICKJS_SO"))) (and e (> (string-length e) 0) (file-exists? e)))
      (file-exists? "libquickjs.dylib") (file-exists? "libquickjs.so")
      (file-exists? "/opt/homebrew/lib/quickjs/libquickjs.dylib")
      (file-exists? "/usr/local/lib/quickjs/libquickjs.so")
      (file-exists? "/usr/lib/quickjs/libquickjs.so")))

(unless (raw-quickjs-present?)
  (display "quickjs: no stock libquickjs found, test skipped\n") (exit 0))

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1)) (display "FAIL  ") (display label) (newline))))


(define bundle "
var N = 0;
function slugify(s){ N++; return s.toLowerCase().replace(/\\s+/g,'-'); }
function greet(j){ N++; var p = JSON.parse(j); return '<h1>Hi '+p.name+'</h1>'; }
function count(_){ return '' + N; }
function boom(_){ throw new Error('render failed'); }
function notstr(_){ return {a:1}; }          // not string-coercible in the useful sense
function spin(_){ while(true){} }            // runaway loop -> interrupt deadline
function eat(_){ var a=[]; while(true){ a.push(new Float64Array(100000)); } } // OOM bomb -> JS_SetMemoryLimit
")

;; ---- boot + basic calls ----
(qjs-boot! bundle '((timeout-ms . 500) (mem-mb . 32)))
(check "healthy-after-boot" (qjs-healthy?))
(check "generation-1" (= 1 (qjs-generation)))

(let-values (((ok s) (qjs-call "slugify" "Hello World")))
  (check "slugify-ok" ok)
  (check "slugify-val" (equal? s "hello-world")))

(check "greet-json"
  (equal? (qjs-call! "greet" "{\"name\":\"Ann\"}") "<h1>Hi Ann</h1>"))

;; the JS side kept state across calls (N advanced) -- proves ONE live engine
(check "state-persists" (>= (string->number (qjs-call! "count" "")) 2))

;; ---- no such function ----
(let-values (((ok s) (qjs-call "nope" "")))
  (check "no-such-fn-ok?" (not ok))
  (check "no-such-fn-msg" (and (string? s) (> (string-length s) 0))))

;; ---- JS throw -> (#f msg), NOT a raise; engine rebuilds (crash-only) ----
(let ((gen0 (qjs-generation)))
  (let-values (((ok s) (qjs-call "boom" "")))
    (check "boom-not-ok" (not ok))
    (check "boom-msg" (and (string? s) (>= (string-length s) 1))))
  (check "boom-rebuilt" (> (qjs-generation) gen0))     ; generation bumped
  (check "boom-recovers" (qjs-healthy?))
  ;; N reset to 0 by the rebuild, then slugify bumps it to 1
  (check "recover-call" (equal? (qjs-call! "slugify" "A B") "a-b")))

;; qjs-call! raises on a JS error
(check "call!-raises"
  (guard (e (#t #t)) (qjs-call! "boom" "") #f))

;; ---- interrupt deadline: a runaway loop is ABORTED, not a hang ----
(let ((gen0 (qjs-generation)) (t0 (real-time)))
  (let-values (((ok s) (qjs-call "spin" "")))
    (let ((ms (- (real-time) t0)))
      (check "spin-aborted" (not ok))
      (check "spin-bounded" (< ms 3000))          ; timeout-ms=500, aborted well under 3s
      (display "  [perf] spin aborted in ") (display ms) (display " ms (timeout-ms=500)\n")))
  (check "spin-rebuilt" (> (qjs-generation) gen0))
  (check "spin-recovers" (equal? (qjs-call! "slugify" "X Y") "x-y")))

;; ---- memory cap: an allocation bomb -> in-JS OOM, process stays up ----
(let-values (((ok s) (qjs-call "eat" "")))
  (check "eat-not-ok" (not ok))
  (check "eat-msg" (and (string? s) (> (string-length s) 0)))
  (display "  [info] eat -> ") (write s) (newline))
(check "eat-recovers" (qjs-healthy?))
(check "eat-recover-call" (equal? (qjs-call! "slugify" "P Q") "p-q"))

;; ---- perf: interrupt-handler overhead (trivial calls/sec) ----
(let* ((iters 20000) (t0 (real-time)))
  (do ((i 0 (+ i 1))) ((= i iters)) (qjs-call! "slugify" "Perf Test"))
  (let* ((ms (- (real-time) t0)) (per (/ ms iters)))
    (display "  [perf] ") (display iters) (display " calls in ") (display ms)
    (display " ms = ") (display (exact->inexact per)) (display " ms/call\n")))

(qjs-shutdown!)
(check "shutdown-clears" (not (qjs-healthy?)))

(if (zero? failures)
    (begin (display "quickjs: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
