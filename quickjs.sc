#!chezscheme
;;; (igropyr quickjs) -- embed a JavaScript engine (QuickJS) in-process, in
;;; PURE Scheme: no custom C shim, it binds a stock shared libquickjs directly
;;; over the FFI. Load a fixed JS bundle at boot, then call its global
;;; functions with one UTF-8 string argument and get a string back; user input
;;; is data, never code.
;;;
;;; INSTALL quickjs-ng (libqjs); 0.15+ is what this is developed against.
;;; What the code enforces is narrower: a real exported JS_FreeValue.
;;; bellard/quickjs makes JS_FreeValue a header inline and exports only the
;;; ref-count-zero slow path, which forced this library to reproduce the
;;; inline: decrement a ref_count whose offset differs between the two
;;; upstreams and so had to be DISCOVERED at boot, by reading both candidate
;;; positions on a live object. One candidate sits 4 bytes BEFORE the object.
;;; That read is undefined behaviour -- harmless under a plain allocator,
;;; a crash under ASan, Guard Malloc, or whenever an object lands at a page
;;; boundary -- and it ran three times per boot, on every boot, including
;;; each crash-only rebuild.
;;;
;;; Requiring the export deletes that machinery instead of guarding it: with
;;; the offset gone there is nothing to discover and nothing reads outside an
;;; object. A build without the symbol is refused at boot with a clear
;;; message rather than silently taking a different path. Releasing a value
;;; is also ~30% cheaper as one FFI call than as the reproduced inline.
;;;
;;; A C-shim binding with the SAME exports lives at
;;;   https://github.com/guenchi/igropyr-quickjs
;;; -- a drop-in replacement to use when a stock shared library is awkward to
;;; obtain (e.g. Homebrew ships only a static archive) or when you want a
;;; self-contained, version-pinned artifact.
;;;
;;;   (qjs-boot! bundle-source)
;;;   (qjs-boot! bundle-source '((mem-mb . 64) (stack-kb . 1024)
;;;                              (timeout-ms . 2000) (so-path . "libqjs.so")))
;;;   (qjs-call  "fname" "arg")   ; -> (values ok? string)
;;;   (qjs-call! "fname" "arg")   ; -> string, raises on JS error
;;;   (qjs-healthy?) (qjs-generation) (qjs-shutdown!)
;;;
;;; Why this exists: the by-value JSValue ABI and the refcount teardown are
;;; the tricky parts of embedding QuickJS from Scheme; both are handled here
;;; (a JSValue is a 16-byte {u,tag} struct passed via (& ftype); releasing one
;;; is a single call to the exported JS_FreeValue, which is what bind!
;;; insists on).
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
  (export qjs-boot! qjs-call qjs-call/bytes qjs-call! qjs-healthy? qjs-generation qjs-shutdown!)
  (import (chezscheme) (igropyr platform))

  ;; ---- JSValue: a 16-byte struct { JSValueUnion u; int64_t tag; } --------
  ;; (64-bit build, NaN-boxing off.) This layout is an ABI assumption,
  ;; and the thing that keeps it from being a silent one is validate-abi!
  ;; below: qjs-boot! reads the tag of a known-object global through this
  ;; ftype and refuses the build if it is not tag-object. That catches a
  ;; NaN-boxed or re-ordered build at startup rather than later through
  ;; wrong tags -- unless the other layout happens to put an object tag
  ;; where this one expects it, which the check cannot see. To settle it
  ;; directly, print sizeof(JSValue) and offsetof(JSValue, tag) from C
  ;; against the library actually being linked.
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
                ;; Two upstreams, two library names: bellard/quickjs ships
                ;; libquickjs, quickjs-ng ships libqjs. FreeBSD's packages
                ;; install either straight under lib/, not in a quickjs/
                ;; subdirectory.
                ;;
                ;; libqjs FIRST, everywhere. What bind! enforces rules out
                ;; bellard's build (see the JS_FreeValue check there), and
                ;; on a machine
                ;; carrying both builds the old order dlopened bellard's
                ;; libquickjs first. That fails the bind -- and it fails it
                ;; AFTER the library is in the process's global symbol
                ;; namespace, where Chez's foreign-procedure resolves from.
                ;; Falling through to the next candidate would then be worse
                ;; than stopping: JS_NewRuntime would still resolve to the
                ;; first library loaded while JS_FreeValue came from the
                ;; second, which is a mixed-ABI free on every value. The only
                ;; safe order is to look for the right one first.
                ;; Grouped by LIBRARY, not by how the name is written: EVERY
                ;; libqjs candidate, bare and absolute, comes before the
                ;; first libquickjs one. Interleaving them is not enough and
                ;; was measured not to be -- a bare "libqjs.dylib" does not
                ;; resolve where the library lives outside the dynamic
                ;; loader's default path (/opt/homebrew/lib on macOS), so a
                ;; bare "libquickjs.dylib" sitting anywhere on the search
                ;; path still won.
                (list "libqjs.dylib" "libqjs.so"
                      "/opt/homebrew/lib/libqjs.dylib"
                      "/usr/local/lib/libqjs.so"
                      "/usr/local/lib/libqjs.so.0"
                      "/usr/lib/libqjs.so"
                      "libquickjs.dylib" "libquickjs.so"
                      "/opt/homebrew/lib/quickjs/libquickjs.dylib"
                      "/usr/local/lib/libquickjs.so"
                      "/usr/local/lib/libquickjs.so.0"
                      "/usr/local/lib/quickjs/libquickjs.so"
                      "/usr/lib/libquickjs.so"
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
  (define _free-value #f)                 ; the exported JS_FreeValue (required)
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
      ;; A real exported JS_FreeValue is REQUIRED. bellard/quickjs makes it a
      ;; header inline and exports only the ref-count-zero slow path, which
      ;; left this library reproducing the inline itself: decrement a count
      ;; whose offset had to be discovered by reading both candidate
      ;; positions on a live object -- and one candidate, ptr-4, is BEFORE
      ;; the object. That is undefined behaviour a plain allocator hides and
      ;; ASan, Guard Malloc or a page boundary turns into a crash, and it ran
      ;; three times per boot, every boot, including each crash-only rebuild.
      ;;
      ;; Requiring the exported symbol deletes that machinery rather than
      ;; guarding it: there is no offset to find, so nothing reads outside an
      ;; object. The cost is bellard/quickjs support, paid deliberately --
      ;; a narrower set of usable builds in exchange for deleting that
      ;; out-of-bounds read.
      ;; Refuse loudly here rather than silently taking a different path.
      ;; NOTE WHAT THIS ASKS. foreign-entry? resolves in the PROCESS's
      ;; global symbol namespace, not in the library just loaded -- the
      ;; same namespace whose hazards the candidate-order comment above
      ;; describes. In a process that has loaded no other QuickJS it is
      ;; the library just loaded that must export the symbol; in one that
      ;; has, this passes on someone else's export and the mixed-ABI risk
      ;; up there is live.
      (unless (foreign-entry? "JS_FreeValue")
        (assertion-violation 'qjs-boot!
          (string-append
            "this QuickJS build does not export JS_FreeValue (quickjs-ng "
            "exports it; bellard/quickjs makes it inline). The library "
            "found is most likely bellard's libquickjs; install quickjs-ng "
            "(libqjs) or point IGROPYR_LIBQUICKJS_SO at it. Loading another "
            "candidate instead is not attempted on purpose: this one is "
            "already in the global symbol namespace, so the result would be "
            "one library's functions with another's ABI")))
      (set! _free-value
        (foreign-procedure "JS_FreeValue" (void* (& JSValue)) void))
      (set! bound #t)))

  ;; ---- engine state ------------------------------------------------------
  (define rt #f) (define ctx #f)
  (define healthy #f)
  (define generation 0)
  (define deadline 0)                    ; real-time ms; 0 = no deadline armed
  (define bundle-bytes #f)               ; NUL-terminated, kept for rebuild
  (define mem-mb 64) (define stack-kb 1024) (define timeout-ms 2000)

  ;; reusable JSValue scratch (calls are serialized, so buffers are shared)
  (define (alloc-jsval) (make-ftype-pointer JSValue (foreign-alloc 16)))
  (define g-buf #f) (define f-buf #f) (define a-buf #f)
  (define this-buf #f) (define r-buf #f) (define ex-buf #f)
  (define argv-buf #f) (define lenp #f)
  (define g-cache #f)     ; the global object's BITS (borrowed), set per boot
  (define scratch-ready #f)
  (define (ensure-scratch!)
    (unless scratch-ready
      (set! g-buf (alloc-jsval)) (set! f-buf (alloc-jsval)) (set! a-buf (alloc-jsval))
      (set! this-buf (alloc-jsval)) (set! r-buf (alloc-jsval)) (set! ex-buf (alloc-jsval))
      (set! argv-buf (alloc-jsval)) (set! g-cache (alloc-jsval)) (set! lenp (foreign-alloc 8))
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

  ;; ---- release a JSValue: one call to the exported JS_FreeValue. On the
  ;; successful call path that is three -- function, argument, result. The
  ;; global is borrowed from g-cache, so no call frees it; boot-locked!
  ;; releases it once per (re)boot when it re-reads it. Error paths free
  ;; the owned references they reached; some carry immediates such as
  ;; JS_EXCEPTION, which need none. ----------------------------------------
  ;; That export owns the whole operation, including the has-ref-count test,
  ;; so hand it the value as is. The decrement still dereferences the object
  ;; pointer -- inside the library, where it belongs; what is gone is Scheme
  ;; computing an offset and reading there itself. See bind! for why that
  ;; distinction is the whole point.
  (define (js-free! v) (_free-value ctx v))

  ;; read a JS string value's UTF-8 bytes into a fresh bytevector (via one
  ;; JS_ToCStringLen2 / JS_FreeCString pair) or #f if not string-coercible.
  ;; The memcpy runs while the C string is still ref-held, so the bytes are
  ;; safe once copied; the caller that wants a Scheme string decodes them.
  (define (read-jsbytes v)
    (let ((cstr (_tocstr ctx lenp v 0)))
      (if (eqv? cstr 0)
          #f
          (let* ((n (foreign-ref 'size_t lenp 0)) (bv (make-bytevector n)))
            (unless (= n 0) (_memcpy bv cstr n))
            (_free-cstr ctx cstr)
            bv))))
  (define (read-jsstring v)
    (let ((bv (read-jsbytes v)))
      (and bv (utf8->string bv))))

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

  ;; ---- ABI probe: the JSValue layout, with no offset to discover ---------
  ;; Read the global object's tag through this binding's ftype: it must be
  ;; JS_TAG_OBJECT. A NaN-boxed or re-ordered build fails that unless its
  ;; layout happens to agree at this one position (see the ftype comment).
  ;; Cheap, and it reads only OUR OWN JSValue buffer, never the object's
  ;; memory -- unlike the ref_count probe this replaces, which had to read
  ;; both candidate offsets on a live object to find one of them.
  (define (validate-abi!)
    (_global g-buf ctx)
    (unless (= (ftype-ref JSValue (tag) g-buf) tag-object)
      (teardown!)
      (error 'qjs-boot!
        "global tag != JS_TAG_OBJECT: JSValue layout mismatch (NaN-boxing / wrong QuickJS build?)"))
    (js-free! g-buf))

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
    (validate-abi!)                       ; tag must read JS_TAG_OBJECT here
    (arm-deadline! 10)                    ; bundle parse gets 10x the call budget
    (_eval r-buf ctx bundle-bytes (- (bytevector-length bundle-bytes) 1) "<bundle>" 0)
    ;; NOTE: the deadline stays ARMED past _eval -- read-exception below
    ;; stringifies an attacker-authored value and that runs JS (see the
    ;; note in qjs-call*). It is cleared only after the last such call.
    (if (= (ftype-ref JSValue (tag) r-buf) tag-exception)
        (let ((msg (read-exception)))
          (set! deadline 0)
          (teardown!) (error 'qjs-boot! msg))
        (begin (js-free! r-buf)         ; eval result (undefined) -> no-op
               ;; cache the global object's BITS (borrowed): take a ref, keep
               ;; the bits, drop the ref. globalThis is owned by the context and
               ;; is neither moved nor reassigned, so every call reuses these
               ;; bits without a per-call JS_GetGlobalObject + free. Re-set here
               ;; on every (re)boot, so it always points at the live context.
               (_global g-cache ctx) (js-free! g-cache)
               (set! deadline 0)        ; no more JS runs on this path
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

  ;; core call, parameterized by how the JS result is read out (read-result
  ;; is read-jsstring or read-jsbytes) -> (values ok? result): result on #t
  ;; (string or bytevector per read-result), JS error TEXT (always a string)
  ;; on #f.
  (define (qjs-call* read-result fname arg)
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
              (_get-prop f-buf ctx g-cache fname)   ; g-cache = borrowed global
              (cond
                ((= (ftype-ref JSValue (tag) f-buf) tag-exception)
                 ;; the property access itself threw (e.g. a throwing getter):
                 ;; drain the pending exception (keeps the next call clean) and
                 ;; report it, rather than the misleading "no such function"
                 (let ((msg (read-exception)))   ; runs JS: keep the deadline
                   (set! deadline 0)
                   (values #f msg)))
                ((fx= 0 (_is-function ctx f-buf))
                 (js-free! f-buf) (set! deadline 0)
                 (values #f "no such function"))
                (else
                 (_new-string a-buf ctx abytes (bytevector-length abytes))
                 ;; JS_NewStringLen returns an exception when the argument
                 ;; pushes the heap past its limit. Passing that value on
                 ;; as argv[0] would run the bundle against a garbage
                 ;; argument with an exception already pending -- the call
                 ;; could then report success for input it never received,
                 ;; and the stale exception surface on a later call.
                 (if (= (ftype-ref JSValue (tag) a-buf) tag-exception)
                     (let ((msg (read-exception)))
                       (js-free! f-buf)
                       (set! deadline 0)
                       (values #f msg))
                     (begin
                 (ftype-set! JSValue (u)   argv-buf (ftype-ref JSValue (u) a-buf))
                 (ftype-set! JSValue (tag) argv-buf (ftype-ref JSValue (tag) a-buf))
                 (mkundef! this-buf)
                 (_call r-buf ctx f-buf this-buf 1 (ftype-pointer-address argv-buf))
                 ;; The deadline MUST stay armed past _call. Reading the
                 ;; result or the exception goes through JS_ToCStringLen2,
                 ;; which on a non-string value invokes the object's own
                 ;; toString/valueOf/Symbol.toPrimitive -- i.e. arbitrary
                 ;; JS, on this single OS thread, with interrupts disabled.
                 ;; Disarming here would let `return {toString(){for(;;);}}`
                 ;; freeze the whole scheduler permanently: the interrupt
                 ;; callback reads deadline = 0 and never aborts. The
                 ;; remaining budget is the call's own, so a bundle cannot
                 ;; buy extra time by stalling in toString either.
                 (let ((exc? (= (ftype-ref JSValue (tag) r-buf) tag-exception)))
                   (js-free! a-buf) (js-free! f-buf)   ; g-cache is borrowed: no free
                   (cond
                     (exc?
                      (let ((msg (read-exception)))
                        (set! deadline 0)
                        (guard (e (#t #f)) (boot-locked!))  ; crash-only, best-effort
                        (values #f msg)))
                     (else
                      (let ((s (read-result r-buf)))
                        (js-free! r-buf)
                        (if s
                            (begin (set! deadline 0) (values #t s))
                            ;; Not string-coercible: JS_ToCStringLen2 left a
                            ;; pending exception. REBUILD, like any other
                            ;; failed call -- the header promises crash-only,
                            ;; and this path had been reporting the error
                            ;; while keeping the same heap and generation.
                            ;;
                            ;; It matters more than it looks: reaching here
                            ;; means the bundle's own toString or valueOf
                            ;; ran and threw, and it could have written to a
                            ;; global first. Keeping the runtime keeps that
                            ;; write, visible to every later request.
                            (let ((msg (read-exception)))
                              (set! deadline 0)
                              (guard (e (#t #f)) (boot-locked!))
                              (values #f msg))))))))))))))))

  ;; -> (values ok? string):     result HTML/text as a Scheme string on #t.
  (define (qjs-call fname arg) (qjs-call* read-jsstring fname arg))
  ;; -> (values ok? bytevector): result as raw UTF-8 bytes on #t (skips the
  ;; decode; hand straight to a socket / hash / byte cache), error text on #f.
  (define (qjs-call/bytes fname arg) (qjs-call* read-jsbytes fname arg))

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
