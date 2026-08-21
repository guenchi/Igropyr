#!chezscheme
;;; (igropyr quickjs) -- the pure-Scheme QuickJS binding: boot + call,
;;; JSON round-trip, the return-based string contract, JS-error boundary with
;;; crash-only rebuild (generation bumps, engine recovers), the no-such-fn
;;; path, and the two HARD guards a pure-Scheme embedding must still enforce:
;;; the interrupt-deadline (a runaway loop is aborted, not a scheduler freeze)
;;; and the memory cap (an allocation bomb -> in-JS OOM, not process death).
;;; A perf probe reports the interrupt-handler's per-call overhead.
;;;
;;; Needs a shared QuickJS engine library that resolves JS_FreeValue --
;;; install quickjs-ng (libqjs), or anything exporting the same
;;; interface; bellard's build, loaded on its own, is refused. Set
;;; IGROPYR_LIBQUICKJS_SO or install on a standard path. Skips cleanly
;;; (exit 0) when absent, so run-all stays green on hosts without
;;; QuickJS.

(import (chezscheme) (igropyr quickjs))

(define (raw-quickjs-present?)
  (or (let ((e (getenv "IGROPYR_LIBQUICKJS_SO"))) (and e (> (string-length e) 0) (file-exists? e)))
      (file-exists? "libquickjs.dylib") (file-exists? "libquickjs.so")
      (file-exists? "/opt/homebrew/lib/quickjs/libquickjs.dylib")
      ;; FreeBSD packages install straight under lib/ (see quickjs.sc)
      (file-exists? "/usr/local/lib/libquickjs.so")
      (file-exists? "/usr/local/lib/libquickjs.so.0")
      ;; quickjs-ng ships as libqjs, not libquickjs
      (file-exists? "libqjs.dylib") (file-exists? "libqjs.so")
      (file-exists? "/usr/local/lib/libqjs.so")
      (file-exists? "/usr/local/lib/libqjs.so.0")
      (file-exists? "/opt/homebrew/lib/libqjs.dylib")
      (file-exists? "/usr/lib/libqjs.so")
      (file-exists? "/usr/local/lib/quickjs/libquickjs.so")
      (file-exists? "/usr/lib/libquickjs.so")
      (file-exists? "/usr/lib/quickjs/libquickjs.so")))

;; A bellard libquickjs also counts as "present" here, DELIBERATELY:
;; the gate is candidate-path file presence -- it does not check the
;; file is QuickJS or even loadable -- and everything past existence is
;; decided at load and at qjs-boot!, loudly, the latter by the driver's
;; own refusal naming the remedy (a bellard build loaded on its own
;; does not resolve JS_FreeValue). A wrong engine installed is an
;; environment defect and must be loud; a skip would make it look like
;; no engine.
(unless (raw-quickjs-present?)
  (display "quickjs: no QuickJS library found, test skipped\n")
  (display "  (install quickjs-ng -- it ships libqjs -- or point\n")
  (display "   IGROPYR_LIBQUICKJS_SO at one; bellard's libquickjs, on its\n")
  (display "   own, boots only far enough to be refused)\n")
  (exit 0))

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1)) (display "FAIL  ") (display label) (newline))))

(define (str-has? s sub)                       ; is sub a substring of s?
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring s i (+ i m))) #t)
            (else (loop (+ i 1)))))))


(define bundle "
var N = 0;
function slugify(s){ N++; return s.toLowerCase().replace(/\\s+/g,'-'); }
function greet(j){ N++; var p = JSON.parse(j); return '<h1>Hi '+p.name+'</h1>'; }
function count(_){ return '' + N; }
function boom(_){ throw new Error('render failed'); }
function sym(_){ return Symbol('s'); }        // not string-coercible -> pending exception
function thrower(_){ return { toString: function(){ throw new Error('toString boom'); } }; }
Object.defineProperty(globalThis, 'badgetter', { get: function(){ throw new Error('getter boom'); } });
function spin(_){ while(true){} }            // runaway loop -> interrupt deadline
function eat(_){ var a=[]; while(true){ a.push(new Float64Array(100000)); } } // OOM bomb -> JS_SetMemoryLimit

// values whose STRINGIFICATION runs hostile JS: JS_ToCStringLen2 invokes
// toString/valueOf, so the interrupt deadline must still be armed there
globalThis.evilResult = function(a){ return { toString(){ for(;;){} } }; };
globalThis.evilThrow  = function(a){ throw { toString(){ for(;;){} } }; };
")

;; ---- boot + basic calls ----
(qjs-boot! bundle '((timeout-ms . 500) (mem-mb . 32)))
(check "healthy-after-boot" (qjs-healthy?))
(check "generation-1" (= 1 (qjs-generation)))

(let-values (((ok s) (qjs-call "slugify" "Hello World")))
  (check "slugify-ok" ok)
  (check "slugify-val" (equal? s "hello-world")))

;; qjs-call/bytes returns the same result as raw UTF-8 bytes (no decode)
(let-values (((ok b) (qjs-call/bytes "slugify" "Hello World")))
  (check "slugify-bytes-ok" ok)
  (check "slugify-bytes-val" (and (bytevector? b) (equal? (utf8->string b) "hello-world"))))

(check "greet-json"
  (equal? (qjs-call! "greet" "{\"name\":\"Ann\"}") "<h1>Hi Ann</h1>"))

;; the JS side kept state across calls (N advanced) -- proves ONE live engine
(check "state-persists" (>= (string->number (qjs-call! "count" "")) 2))

;; ---- no such function ----
(let-values (((ok s) (qjs-call "nope" "")))
  (check "no-such-fn-ok?" (not ok))
  (check "no-such-fn-msg" (and (string? s) (> (string-length s) 0))))

;; ---- non-string-coercible result: -> (#f msg), pending exception DRAINED so
;;      the next call is NOT poisoned (F1) ----
(let-values (((ok s) (qjs-call "sym" "")))
  (check "sym-not-ok" (not ok))
  (check "sym-drained-msg" (and (string? s) (> (string-length s) 0))))
(check "sym-next-clean" (equal? (qjs-call! "slugify" "A B") "a-b"))   ; not poisoned
(let-values (((ok s) (qjs-call "thrower" "")))
  (check "thrower-not-ok" (not ok)))
(check "thrower-next-clean" (equal? (qjs-call! "slugify" "C D") "c-d"))

;; ---- a throwing property getter on the name: reported accurately, not
;;      "no such function", and the pending exception is drained (F4) ----
(let-values (((ok s) (qjs-call "badgetter" "")))
  (check "getter-not-ok" (not ok))
  (check "getter-msg-accurate" (and (string? s) (not (string=? s "no such function")))))
(check "getter-next-clean" (equal? (qjs-call! "slugify" "E F") "e-f"))

;; ---- bad options are rejected (and a negative cap can't silently bypass the
;;      memory limit) (B3) ----
(check "reject-negative-mem"
  (guard (e (#t #t)) (qjs-boot! "function f(x){return x;}" '((mem-mb . -1))) #f))
(check "reject-bad-timeout"
  (guard (e (#t #t)) (qjs-boot! "function f(x){return x;}" '((timeout-ms . 0))) #f))
;; the rejected boots must not have torn down the live engine
(check "engine-survives-bad-boot" (equal? (qjs-call! "slugify" "G H") "g-h"))

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

;; ---- the deadline must cover STRINGIFICATION, not just the call ----------
;; JS_ToCStringLen2 invokes a value's own toString/valueOf, so reading the
;; result (or the exception) runs attacker-authored JS. Disarming the
;; deadline when JS_Call returns froze the entire scheduler permanently --
;; one OS thread, interrupts disabled, an interrupt callback that reads
;; deadline = 0 and never aborts. Each of these must come back promptly.
(let ((t0 (real-time)))
  (check "hostile-toString-on-result-interrupted"
    (let-values (((ok r) (qjs-call "evilResult" "x"))) (not ok)))
  (check "  ... promptly" (< (- (real-time) t0) 10000)))

(let ((t0 (real-time)))
  (check "hostile-toString-on-exception-interrupted"
    (let-values (((ok r) (qjs-call "evilThrow" "x"))) (not ok)))
  (check "  ... promptly" (< (- (real-time) t0) 10000)))

(check "engine-usable-after-hostile-stringification"
  (let-values (((ok r) (qjs-call "slugify" "Hello World"))) ok))

(qjs-shutdown!)
(check "shutdown-clears" (not (qjs-healthy?)))
;; a call after shutdown reports cleanly ("qjs-boot! first"), not a raw
;; bytevector-length error from bundle-bytes = #f inside boot-locked! (B1)
(check "post-shutdown-clean-error"
  (guard (e ((and (message-condition? e) (str-has? (condition-message e) "qjs-boot")) #t)
            (#t #f))
    (qjs-call "slugify" "z") #f))

;; A value whose toString throws is a failed call like any other, and the
;; header promises crash-only: the runtime goes. This path used to report
;; the error while keeping the same heap -- which matters because reaching
;; it means the bundle's own toString ran, and it could have written to a
;; global before throwing. Keeping the runtime keeps that write, visible to
;; every later request.
(qjs-boot!
  (string-append
    "var leaked = 'clean';"
    "function tainter(x){ return { toString: function(){"
    "  leaked = 'tainted'; throw new Error('nope'); } }; }"
    "function peek(x){ return leaked; }")
  '((timeout-ms . 500) (mem-mb . 32)))
(let ((gen0 (qjs-generation)))
  (let-values (((ok s) (qjs-call "tainter" "")))
    (check "tainting-call-not-ok" (not ok)))
  (check "tainting-call-rebuilt" (> (qjs-generation) gen0))
  ;; the rebuild is what makes this 'clean again
  (check "global-write-did-not-survive" (equal? (qjs-call! "peek" "") "clean")))


(if (zero? failures)
    (begin (display "quickjs: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
