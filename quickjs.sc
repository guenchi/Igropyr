#!chezscheme
;;; (igropyr quickjs) -- embed a JavaScript engine (QuickJS) in-process, in
;;; PURE Scheme: no custom C shim, it binds a stock shared libquickjs directly
;;; over the FFI. Load a fixed JS bundle at boot, then call its global
;;; functions with one UTF-8 string argument and get a string back; user input
;;; is data, never code.
;;;
;;; A C-shim binding with the SAME exports lives at
;;;   https://github.com/guenchi/igropyr-quickjs (branch `igropyr`)
;;; -- a drop-in replacement to use when a stock libquickjs is awkward to
;;; obtain (e.g. Homebrew ships only a static archive) or when you want a
;;; self-contained, version-pinned artifact.
;;;
;;;   (qjs-boot! bundle-source)
;;;   (qjs-boot! bundle-source '((mem-mb . 64) (stack-kb . 1024)
;;;                              (timeout-ms . 2000) (so-path . "libquickjs.so")))
;;;   (qjs-call  "fname" "arg")   ; -> (values ok? string)
;;;   (qjs-call! "fname" "arg")   ; -> string, raises on JS error
;;;   (qjs-healthy?) (qjs-generation) (qjs-shutdown!)
;;;
;;; Why this exists: the by-value JSValue ABI and the refcount teardown are
;;; the tricky parts of embedding QuickJS from Scheme; both are handled here
;;; (a JSValue is a 16-byte {u,tag} struct passed via (& ftype); JS_FreeValue
;;; is a header inline, so its refcount decrement is reproduced faithfully and
;;; the exported __JS_FreeValue is called only at ref-count zero).
;;;
;;; Hardening (in-Scheme substitutes for the C shim's guards):
;;;   - JS_SetMemoryLimit  : allocation past the cap -> in-JS OOM exception.
;;;   - JS_SetMaxStackSize + JS_UpdateStackTop per call : deep recursion ->
;;;     RangeError, not a C stack smash (stack base re-anchored each call).
;;;   - JS_SetInterruptHandler + a monotonic deadline : a call over timeout-ms
;;;     is aborted by the engine. The handler is a Chez foreign-callable that
;;;     QuickJS invokes from inside its interpreter loop; it only reads a clock
;;;     and compares -- it never yields (it runs across a C frame).
;;;   - Exception boundary : every call is checked; a JS error comes back as a
;;;     string, nothing propagates past qjs-call.
;;;   - Crash-only rebuild : ANY failed call discards the whole runtime and
;;;     re-evaluates the saved bundle; qjs-generation counts rebuilds.
;;;
;;; Concurrency: igropyr runs one OS thread, so the engine is serialized with
;;; with-interrupts-disabled (no pthread mutex needed) -- the preemptive actor
;;; scheduler cannot interleave two callers. A call blocks the OS thread for
;;; its duration (fractions of a ms typically; timeout-ms worst case).

(library (igropyr quickjs)
  ;; Exports match the C-shim binding at guenchi/igropyr-quickjs exactly, so
  ;; the two are interchangeable.
  (export qjs-boot! qjs-call qjs-call! qjs-healthy? qjs-generation qjs-shutdown!)
  (import (chezscheme) (igropyr platform))

  ;; ---- JSValue: a 16-byte struct { JSValueUnion u; int64_t tag; } --------
  ;; (64-bit build, NaN-boxing off -- verified sizeof/offsets on the target)
  (define-ftype JSValue (struct (u unsigned-64) (tag integer-64)))
  (define tag-undefined 3)
  (define tag-exception 6)
  (define tag-object   -1)

  ;; ---- shared object + FFI ----------------------------------------------
  (define so-loaded #f)
  (define (load-so! explicit)
    (unless so-loaded
      (ensure-supported-platform!)
      (load-first-shared-object! 'quickjs
        (append (if explicit (list explicit) '())
                (let ((e (getenv "IGROPYR_LIBQUICKJS_SO"))) (if e (list e) '()))
                (list "libquickjs.dylib" "libquickjs.so"
                      "/opt/homebrew/lib/quickjs/libquickjs.dylib"
                      "/usr/local/lib/quickjs/libquickjs.so"
                      "/usr/lib/quickjs/libquickjs.so")))
      (set! so-loaded #t)))

  (define _memcpy #f)
  (define _new-runtime #f) (define _free-runtime #f)
  (define _new-context #f) (define _free-context #f)
  (define _set-mem #f) (define _set-stack #f) (define _update-stack #f)
  (define _set-interrupt #f)
  (define _eval #f) (define _global #f) (define _get-prop #f)
  (define _is-function #f) (define _new-string #f) (define _call #f)
  (define _tocstr #f) (define _free-cstr #f) (define _get-exception #f)
  (define __free-value #f)
  (define bound #f)
  (define (bind!)
    (unless bound
      (set! _memcpy       (foreign-procedure "memcpy" (u8* void* size_t) void*))
      (set! _new-runtime  (foreign-procedure "JS_NewRuntime" () void*))
      (set! _free-runtime (foreign-procedure "JS_FreeRuntime" (void*) void))
      (set! _new-context  (foreign-procedure "JS_NewContext" (void*) void*))
      (set! _free-context (foreign-procedure "JS_FreeContext" (void*) void))
      (set! _set-mem      (foreign-procedure "JS_SetMemoryLimit" (void* size_t) void))
      (set! _set-stack    (foreign-procedure "JS_SetMaxStackSize" (void* size_t) void))
      (set! _update-stack (foreign-procedure "JS_UpdateStackTop" (void*) void))
      (set! _set-interrupt (foreign-procedure "JS_SetInterruptHandler" (void* void* void*) void))
      (set! _eval         (foreign-procedure "JS_Eval" (void* u8* size_t string int) (& JSValue)))
      (set! _global       (foreign-procedure "JS_GetGlobalObject" (void*) (& JSValue)))
      (set! _get-prop     (foreign-procedure "JS_GetPropertyStr" (void* (& JSValue) string) (& JSValue)))
      (set! _is-function  (foreign-procedure "JS_IsFunction" (void* (& JSValue)) int))
      (set! _new-string   (foreign-procedure "JS_NewStringLen" (void* u8* size_t) (& JSValue)))
      (set! _call         (foreign-procedure "JS_Call" (void* (& JSValue) (& JSValue) int void*) (& JSValue)))
      (set! _tocstr       (foreign-procedure "JS_ToCStringLen2" (void* void* (& JSValue) int) void*))
      (set! _free-cstr    (foreign-procedure "JS_FreeCString" (void* void*) void))
      (set! _get-exception (foreign-procedure "JS_GetException" (void*) (& JSValue)))
      (set! __free-value  (foreign-procedure "__JS_FreeValue" (void* (& JSValue)) void))
      (set! bound #t)))

  ;; ---- engine state ------------------------------------------------------
  (define rt #f) (define ctx #f)
  (define healthy #f)
  (define generation 0)
  (define deadline 0)                    ; real-time ms; 0 = no deadline armed
  (define rc-offset -4)                   ; ref_count byte offset from JS_VALUE_GET_PTR;
                                          ; re-determined by the boot probe (quickjs-ng
                                          ; = -4, bellard/quickjs = 0)
  (define bundle-bytes #f)               ; NUL-terminated, kept for rebuild
  (define mem-mb 64) (define stack-kb 1024) (define timeout-ms 2000)

  ;; reusable JSValue scratch (calls are serialized, so buffers are shared)
  (define (alloc-jsval) (make-ftype-pointer JSValue (foreign-alloc 16)))
  (define g-buf #f) (define f-buf #f) (define a-buf #f)
  (define this-buf #f) (define r-buf #f) (define ex-buf #f)
  (define argv-buf #f) (define lenp #f)
  (define scratch-ready #f)
  (define (ensure-scratch!)
    (unless scratch-ready
      (set! g-buf (alloc-jsval)) (set! f-buf (alloc-jsval)) (set! a-buf (alloc-jsval))
      (set! this-buf (alloc-jsval)) (set! r-buf (alloc-jsval)) (set! ex-buf (alloc-jsval))
      (set! argv-buf (alloc-jsval)) (set! lenp (foreign-alloc 8))
      (set! scratch-ready #t)))

  (define (mkundef! v) (ftype-set! JSValue (u) v 0) (ftype-set! JSValue (tag) v tag-undefined))

  ;; ---- the interrupt handler: a JSCFunction-free callback QuickJS polls --
  ;; int handler(JSRuntime*, void*) -> non-zero aborts the running job.
  ;; Runs across a C frame with interrupts disabled: read a clock, compare,
  ;; return. NOTHING that could yield.
  (define interrupt-cb
    (let ((cb (foreign-callable
                (lambda (_rt _opaque)
                  (if (and (not (eqv? deadline 0)) (> (real-time) deadline)) 1 0))
                (void* void*) int)))
      (lock-object cb)                    ; keep it pinned for the engine's life
      cb))

  ;; ---- faithful JS_FreeValue (header inline): decrement the object's
  ;; ref_count, and only at zero call the exported slow path. Needed for the
  ;; per-call setup values (global, function, argument, result). --------------
  (define (js-free! v)
    (let ((tag (ftype-ref JSValue (tag) v)))
      (when (< tag 0)                                   ; JS_VALUE_HAS_REF_COUNT
        ;; ref_count lives rc-offset bytes from JS_VALUE_GET_PTR(v): quickjs-ng
        ;; puts it 4 bytes BEFORE the pointer (__js_rc = (uint32_t*)ptr - 1),
        ;; bellard/quickjs at offset 0. The boot probe set rc-offset.
        (let* ((rca (+ (ftype-ref JSValue (u) v) rc-offset))  ; &p->ref_count
               (rc  (foreign-ref 'int rca 0)))
          (foreign-set! 'int rca 0 (- rc 1))
          (when (<= (- rc 1) 0) (__free-value ctx v))))))

  ;; read a JS string value into a Scheme string (via one JS_ToCStringLen2 /
  ;; JS_FreeCString pair) or #f if it is not string-coercible.
  (define (read-jsstring v)
    (let ((cstr (_tocstr ctx lenp v 0)))
      (if (eqv? cstr 0)
          #f
          (let* ((n (foreign-ref 'size_t lenp 0)) (bv (make-bytevector n)))
            (unless (= n 0) (_memcpy bv cstr n))
            (_free-cstr ctx cstr)
            (utf8->string bv)))))

  (define (read-exception)
    (_get-exception ex-buf ctx)
    (let ((s (read-jsstring ex-buf)))
      (js-free! ex-buf)
      (or s "unknown JS exception")))

  ;; ---- boot / teardown ---------------------------------------------------
  (define (teardown!)
    (when ctx (_free-context ctx) (set! ctx #f))
    (when rt  (_free-runtime rt)  (set! rt #f))
    (set! healthy #f))

  (define (arm-deadline! factor)
    (set! deadline (if (> timeout-ms 0) (+ (real-time) (* timeout-ms factor)) 0)))

  ;; ---- ABI probe: DISCOVER ref_count's offset instead of hard-coding it ---
  ;; Pure decision: three successive reads of the two candidate int slots
  ;; (offset 0 and offset -4) taken as we add one reference each time; the slot
  ;; that increments by exactly 1 on BOTH steps is ref_count. Only string
  ;; length/hash and object shape sit in the other slot and they do NOT move
  ;; when a reference is taken, so the match is unambiguous. Exported so the
  ;; test can drive both branches without a second QuickJS build.
  (define (decide-rc-offset a0 am4 b0 bm4 c0 cm4)
    (let ((d0?  (and (= (- b0 a0) 1) (= (- c0 b0) 1)))       ; offset 0 tracks refs?
          (dm4? (and (= (- bm4 am4) 1) (= (- cm4 bm4) 1))))  ; offset -4 tracks refs?
      (cond ((and dm4? (not d0?)) -4)     ; quickjs-ng: ref_count 4 bytes before ptr
            ((and d0?  (not dm4?)) 0)      ; bellard/quickjs: ref_count at offset 0
            (else #f))))                   ; ambiguous / unknown -> caller refuses

  ;; Determine rc-offset by perturb-and-observe on the global object
  ;; (JS_GetGlobalObject bumps its ref_count by 1 each call). Also VALIDATES
  ;; the JSValue struct layout: the global's tag must read as JS_TAG_OBJECT,
  ;; which proves u is a real pointer and we are not on a NaN-boxed build.
  ;; Requires ctx. Leaves the global's ref_count balanced on success; on
  ;; failure it tears down and raises (a wrong ABI is refused, never guessed).
  (define (probe-abi!)
    (_global g-buf ctx)                                     ; ref #1
    (unless (= (ftype-ref JSValue (tag) g-buf) tag-object)
      (teardown!)
      (error 'qjs-boot!
        "global tag != JS_TAG_OBJECT: JSValue layout mismatch (NaN-boxing / wrong QuickJS build?)"))
    (let ((ptr (ftype-ref JSValue (u) g-buf)))
      (let ((a0 (foreign-ref 'int ptr 0)) (am4 (foreign-ref 'int (- ptr 4) 0)))
        (_global g-buf ctx)                                 ; ref #2 (same object)
        (let ((b0 (foreign-ref 'int ptr 0)) (bm4 (foreign-ref 'int (- ptr 4) 0)))
          (_global g-buf ctx)                               ; ref #3
          (let ((c0 (foreign-ref 'int ptr 0)) (cm4 (foreign-ref 'int (- ptr 4) 0)))
            (let ((off (decide-rc-offset a0 am4 b0 bm4 c0 cm4)))
              (unless off
                (teardown!)
                (error 'qjs-boot! "cannot determine ref_count offset: unknown QuickJS ABI"))
              (set! rc-offset off)
              ;; release the three refs we took (js-free! now uses rc-offset)
              (js-free! g-buf) (js-free! g-buf) (js-free! g-buf)))))))

  ;; (re)create runtime + context and evaluate the saved bundle. -> #t | error text
  (define (boot-locked!)
    (teardown!)
    (set! rt (let ((p (_new-runtime))) (and (not (eqv? p 0)) p)))
    (unless rt (error 'qjs-boot! "JS_NewRuntime failed"))
    (when (> mem-mb 0)   (_set-mem   rt (* mem-mb 1048576)))
    (_set-stack rt (if (> stack-kb 0) (* stack-kb 1024) 0))
    (_set-interrupt rt (foreign-callable-entry-point interrupt-cb) 0)
    (set! ctx (let ((p (_new-context rt))) (and (not (eqv? p 0)) p)))
    (unless ctx (teardown!) (error 'qjs-boot! "JS_NewContext failed"))
    (_update-stack rt)
    (probe-abi!)                          ; validate layout + discover rc-offset
    (arm-deadline! 10)                    ; bundle parse gets 10x the call budget
    (_eval r-buf ctx bundle-bytes (- (bytevector-length bundle-bytes) 1) "<bundle>" 0)
    (set! deadline 0)
    (if (= (ftype-ref JSValue (tag) r-buf) tag-exception)
        (let ((msg (read-exception))) (teardown!) (error 'qjs-boot! msg))
        (begin (js-free! r-buf)         ; eval result (undefined) -> no-op
               (set! healthy #t)
               (set! generation (+ generation 1))
               #t)))

  ;; ---- public API --------------------------------------------------------
  (define (opt opts key default)
    (let ((p (assq key opts))) (if p (cdr p) default)))

  (define (utf8z s)                       ; NUL-terminated UTF-8 (JS_Eval needs it)
    (let* ((b (string->utf8 s)) (n (bytevector-length b)) (z (make-bytevector (+ n 1) 0)))
      (bytevector-copy! b 0 z 0 n) z))

  (define (qjs-boot! source . rest)
    ;; JSValue is bound as a 16-byte struct; that is the 64-bit, non-NaN-boxed
    ;; layout. A 32-bit host uses an 8-byte NaN-boxed JSValue -> refuse rather
    ;; than misread it. (igropyr's supported targets are all 64-bit anyway.)
    (unless (> (fixnum-width) 32)
      (error 'qjs-boot! "requires a 64-bit Chez (JSValue is bound as a 16-byte struct)"))
    (let* ((opts (if (pair? rest) (car rest) '()))
           (tmo (opt opts 'timeout-ms 2000))
           (mem (opt opts 'mem-mb 64))
           (stk (opt opts 'stack-kb 1024)))
      ;; validate everything BEFORE any side effect (dlopen / FFI bind / alloc);
      ;; reject negative caps -- a negative fixnum into a size_t arg wraps to a
      ;; huge value and would silently disable the memory/stack guard.
      (unless (string? source)
        (assertion-violation 'qjs-boot! "source must be a string" source))
      (unless (and (fixnum? tmo) (fx> tmo 0))
        (assertion-violation 'qjs-boot! "timeout-ms must be a positive fixnum" tmo))
      (unless (and (fixnum? mem) (fx>= mem 0))
        (assertion-violation 'qjs-boot! "mem-mb must be a non-negative fixnum" mem))
      (unless (and (fixnum? stk) (fx>= stk 0))
        (assertion-violation 'qjs-boot! "stack-kb must be a non-negative fixnum" stk))
      (load-so! (opt opts 'so-path #f))
      (bind!)
      (ensure-scratch!)
      (set! mem-mb mem)
      (set! stack-kb stk)
      (set! timeout-ms tmo)
      (set! bundle-bytes (utf8z source))
      (with-interrupts-disabled (boot-locked!))))

  ;; -> (values ok? string): result on #t, JS error text on #f.
  (define (qjs-call fname arg)
    (unless bound (error 'qjs-call "qjs-boot! first"))
    (let ((abytes (string->utf8 arg)))
      (with-interrupts-disabled
        ;; lazy re-boot if a previous rebuild failed; a failed re-boot must NOT
        ;; escape as a raise -- honour the (values ok? string) contract.
        (unless healthy (guard (e (#t #f)) (boot-locked!)))
        (if (not healthy)
            (values #f "quickjs engine unavailable")
            (begin
              (_update-stack rt)
              (arm-deadline! 1)
              (_global g-buf ctx)
              (_get-prop f-buf ctx g-buf fname)
              (cond
                ((= (ftype-ref JSValue (tag) f-buf) tag-exception)
                 ;; the property access itself threw (e.g. a throwing getter):
                 ;; drain the pending exception (keeps the next call clean) and
                 ;; report it, rather than the misleading "no such function"
                 (js-free! g-buf) (set! deadline 0)
                 (values #f (read-exception)))
                ((fx= 0 (_is-function ctx f-buf))
                 (js-free! f-buf) (js-free! g-buf) (set! deadline 0)
                 (values #f "no such function"))
                (else
                 (_new-string a-buf ctx abytes (bytevector-length abytes))
                 (ftype-set! JSValue (u)   argv-buf (ftype-ref JSValue (u) a-buf))
                 (ftype-set! JSValue (tag) argv-buf (ftype-ref JSValue (tag) a-buf))
                 (mkundef! this-buf)
                 (_call r-buf ctx f-buf this-buf 1 (ftype-pointer-address argv-buf))
                 (set! deadline 0)
                 (let ((exc? (= (ftype-ref JSValue (tag) r-buf) tag-exception)))
                   (js-free! a-buf) (js-free! f-buf) (js-free! g-buf)
                   (cond
                     (exc?
                      (let ((msg (read-exception)))
                        (guard (e (#t #f)) (boot-locked!))  ; crash-only, best-effort
                        (values #f msg)))
                     (else
                      (let ((s (read-jsstring r-buf)))
                        (js-free! r-buf)
                        (if s
                            (values #t s)
                            ;; not string-coercible: JS_ToCStringLen2 left a
                            ;; pending exception -> drain it and report
                            (values #f (read-exception))))))))))))))

  (define (qjs-call! fname arg)
    (let-values (((ok s) (qjs-call fname arg)))
      (if ok s (error 'qjs-call! s fname))))

  (define (qjs-healthy?) (and healthy #t))
  (define (qjs-generation) generation)
  (define (qjs-shutdown!)
    (when bound
      (with-interrupts-disabled
        (teardown!)
        (set! bundle-bytes #f)
        ;; clear bound so a later qjs-call cleanly reports "qjs-boot! first"
        ;; instead of tripping over bundle-bytes = #f inside boot-locked!
        (set! bound #f))))
)
