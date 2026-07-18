#!chezscheme
;;; (igropyr quickjs) end to end: boot a tiny JS bundle, call globals,
;;; the JS-error boundary, and the crash-only rebuild (a throwing call
;;; discards the heap, bumps the generation, and recovers -- the next
;;; call still works). SHIM-GATED: the native dylib is a build artifact
;;; (build-quickjs-shim.sh, needs QuickJS installed), so when it is
;;; absent this test SKIPS cleanly rather than failing -- run-all stays
;;; green on hosts without QuickJS.

(import (chezscheme) (igropyr util) (igropyr quickjs))

;; the resolution paths (igropyr quickjs)'s load-so! searches, plus the
;; env override; if none resolves, the shim was never built -> skip
(define (shim-present?)
  (or (let ((e (getenv "IGROPYR_QUICKJS_SO"))) (and e (> (string-length e) 0)))
      (file-exists? "igropyr/libigropyr-quickjs.dylib")
      (file-exists? ".build-links/igropyr/libigropyr-quickjs.dylib")
      (file-exists? "libigropyr-quickjs.dylib")
      (file-exists? "igropyr/libigropyr-quickjs.so")
      (file-exists? ".build-links/igropyr/libigropyr-quickjs.so")
      (file-exists? "libigropyr-quickjs.so")))

(unless (shim-present?)
  (display "quickjs: shim not built (run build-quickjs-shim.sh), test skipped\n")
  (exit 0))

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

;; user input is DATA (the arg), never code -- the bundle is fixed here
(define bundle "
function greet(x){ return 'hi ' + x; }
function echo(x){ return x; }
function boom(x){ throw new Error('nope: ' + x); }
")

(qjs-boot! bundle)
(check "healthy-after-boot" (qjs-healthy?))
(check "generation-1" (= 1 (qjs-generation)))

;; a plain call: global function, one string arg, string back
(let-values (((ok s) (qjs-call "greet" "world")))
  (check "call-ok" ok)
  (check "call-result" (string=? s "hi world")))

;; utf-8 round-trips across the C boundary (multibyte + astral)
(check "unicode" (string=? (qjs-call! "echo" "café—漢字🙂") "café—漢字🙂"))

;; a missing global is an error, not a crash
(let-values (((ok s) (qjs-call "nope" "x")))
  (check "missing-fn-flag" (not ok))
  (check "missing-fn-text" (string-contains? s "no such function")))

;; the JS-exception boundary: qjs-call returns #f + the error text, and
;; crash-only rebuild fires -- generation bumps, engine stays healthy
(let-values (((ok s) (qjs-call "boom" "z")))
  (check "throw-flag" (not ok))
  (check "throw-text" (string-contains? s "nope: z")))
(check "generation-bumped" (= 2 (qjs-generation)))
(check "healthy-after-throw" (qjs-healthy?))

;; ...and the engine still works after the rebuild
(check "recovers-after-throw" (string=? (qjs-call! "greet" "again") "hi again"))

;; the raising variant surfaces a JS throw as a Scheme error
(check "call!-raises"
  (guard (e (#t #t)) (qjs-call! "boom" "q") #f))

(qjs-shutdown!)

(if (zero? failures)
    (begin (display "quickjs: all tests passed") (newline) (exit 0))
    (begin (display failures) (display " failures") (newline) (exit 1)))
