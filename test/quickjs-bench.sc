#!chezscheme
;;; QuickJS engine benchmark -- a MEASUREMENT, not a pass/fail test, so it
;;; is not part of run-all.sh. It backs the per-call-overhead numbers the
;;; manual's engine table quotes, and re-runs on an engine that gets
;;; past the driver's symbol check (see bind!): quickjs-ng in practice.
;;;
;;; THE BELLARD COLUMN IN THE TABLE BELOW IS HISTORY, NOT RE-RUNNABLE
;;; FROM THIS TREE. Those numbers were taken when this library still
;;; carried the ref_count replica that made bellard's libquickjs
;;; loadable; that machinery was deliberately deleted, and pointing
;;; IGROPYR_LIBQUICKJS_SO at a bellard build, loaded on its own, is
;;; refused at boot before any benchmark runs. Re-measuring that column would mean
;;; resurrecting the replica in a scratch tree.
;;;
;;; It separates two effects a single end-to-end figure conflates:
;;;   (a) per-CALL overhead -- the FFI round trip and the JSValue release
;;;       path, which is where the two upstreams genuinely differed
;;;       (ng exports a real JS_FreeValue; bellard's is a header inline,
;;;       and the replica this library once carried read and wrote the
;;;       ref_count itself)
;;;   (b) interpreter speed -- the engine executing JS, where they were
;;;       within a couple of percent
;;; A near-empty function is almost all (a); a heavy loop is almost all (b).
;;;
;;; Run (the driver picks up the engine it accepts):
;;;   IGROPYR_LIBQUICKJS_SO=/usr/local/lib/libqjs.so \
;;;     scheme --script igropyr/test/quickjs-bench.sc
;;;
;;; Measured on FreeBSD 15/amd64 (best of three, 20000 calls each):
;;;   near-empty  ng 0.50 us/call   bellard 0.70 us/call
;;;   arg+result  ng 0.65 us/call   bellard 0.80 us/call
;;;   200k loop   ng 5.05 ms/call   bellard 4.96 ms/call
;;;   regexp      ng 5.15 us/call   bellard 2.35 us/call   <- engine, not FFI

(import (chezscheme) (igropyr quickjs))

(qjs-boot! "
globalThis.noop  = function(a){ return ''; };
globalThis.echo  = function(a){ return a; };
globalThis.slug  = function(a){ return a.toLowerCase().replace(/[^a-z0-9]+/g,'-'); };
globalThis.heavy = function(a){ var s=0; for(var i=0;i<200000;i++){ s+=i%7; } return ''+s; };
" '((timeout-ms . 20000)))

(define (bench label fn arg iters)
  ;; warm up, then take the best of 3 to damp scheduler noise
  (do ((i 0 (+ i 1))) ((= i 200)) (qjs-call! fn arg))
  (let loop ((run 0) (best #f))
    (if (= run 3)
        (begin
          (display "  ") (display label)
          (display "  ") (display best) (display " ms / ") (display iters)
          (display " calls = ")
          (display (exact->inexact (/ best iters))) (display " ms/call\n")
          best)
        (let ((t0 (real-time)))
          (do ((i 0 (+ i 1))) ((= i iters)) (qjs-call! fn arg))
          (let ((ms (- (real-time) t0)))
            (loop (+ run 1) (if (or (not best) (< ms best)) ms best)))))))

(display "engine: ")
(display (or (getenv "IGROPYR_LIBQUICKJS_SO") "(default)"))
(newline)
(define n-call (bench "noop  (call overhead)" "noop" "x" 20000))
(bench "echo  (+ arg/result)  " "echo" "hello world" 20000)
(bench "slug  (light JS)      " "slug" "Hello World Example" 20000)
(define n-heavy (bench "heavy (200k-iter loop)" "heavy" "x" 200))
(display "  ---\n")
(display "  per-call overhead share of a light call: ")
(display (exact->inexact (/ n-call 20000)))
(display " ms\n")
