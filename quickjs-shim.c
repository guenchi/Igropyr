/* quickjs-shim.c -- libigropyr-quickjs: a minimal, hardened embedding of
 * QuickJS behind a 4-function C ABI for (igropyr quickjs).
 *
 * Model: ONE global runtime evaluating a fixed JS bundle at boot; after
 * that the host only calls global functions with a UTF-8 string argument
 * and gets a UTF-8 string back. User input is DATA, never code -- the
 * bundle is baked at build time, so the attack surface is "C library
 * parsing a user string", same class as zlib/yaml/mysql-proto.
 *
 * Robustness layers (in-process substitutes for worker isolation):
 *   - JS_SetMemoryLimit: allocation beyond the cap -> in-JS OOM exception,
 *     never touches system memory.
 *   - JS_SetMaxStackSize + JS_UpdateStackTop per call: deep recursion ->
 *     RangeError instead of a C stack overflow (stack base is re-anchored
 *     each call, so calls may come from any host thread).
 *   - JS_SetInterruptHandler + monotonic deadline: a call exceeding
 *     timeout_ms is aborted by the engine.
 *   - Exception boundary: every call is checked; errors come back as a
 *     string, nothing propagates past the ABI.
 *   - Crash-only rebuild: ANY failed call throws the whole JS heap away
 *     and reboots the runtime from the saved bundle (no attempt to repair
 *     a poisoned heap). qjs_generation() exposes a rebuild counter.
 *   - pthread mutex serializes everything (JSRuntime is not thread-safe).
 *
 * ABI (all strings are UTF-8 byte buffers, never NUL-terminated JS side):
 *   int  qjs_boot(src, len, mem_mb, stack_kb, timeout_ms)  0 ok / -1 error
 *   long qjs_call(fn, arg, arglen)   >=0 result length / -1 error (text kept)
 *   long qjs_fetch(out, cap)         copy last result/error, -> bytes copied
 *   int  qjs_healthy(void)           1 = runtime alive
 *   long qjs_generation(void)        rebuild count (starts at 1)
 *   void qjs_shutdown(void)
 *
 * qjs_call/qjs_fetch are a pair; callers must not interleave calls from
 * concurrent threads between them (the Scheme wrapper runs the pair inside
 * a critical section).
 *
 * Build: cc -O2 -shared -fPIC quickjs-shim.c -lquickjs -o libigropyr-quickjs.dylib
 */

#include <quickjs/quickjs.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static JSRuntime *rt = NULL;
static JSContext *ctx = NULL;
static int healthy = 0;
static long generation = 0;

/* boot parameters, kept for crash-only rebuild */
static char *bundle = NULL;
static long bundle_len = 0;
static int mem_mb = 0, stack_kb = 0, timeout_ms = 0;

/* last result or error text */
static char *resbuf = NULL;
static long reslen = 0, rescap = 0;

static uint64_t deadline_ns = 0;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* engine polls this during execution; non-zero aborts the running job */
static int interrupt_cb(JSRuntime *r, void *opaque) {
    (void)r; (void)opaque;
    return deadline_ns != 0 && now_ns() > deadline_ns;
}

static void set_result(const char *p, long n) {
    if (n + 1 > rescap) {
        long cap = n + 1;
        char *nb = realloc(resbuf, cap);
        if (!nb) { reslen = 0; return; }
        resbuf = nb; rescap = cap;
    }
    memcpy(resbuf, p, n);
    resbuf[n] = 0;
    reslen = n;
}

/* capture the pending exception (message + stack if present) as the result */
static void set_error_from_exception(void) {
    JSValue e = JS_GetException(ctx);
    size_t n = 0;
    const char *s = JS_ToCStringLen(ctx, &n, e);
    if (s) {
        set_result(s, (long)n);
        JS_FreeCString(ctx, s);
    } else {
        set_result("unknown JS exception", 20);
    }
    JS_FreeValue(ctx, e);
}

static void teardown(void) {
    if (ctx) { JS_FreeContext(ctx); ctx = NULL; }
    if (rt)  { JS_FreeRuntime(rt);  rt = NULL; }
    healthy = 0;
}

/* (re)create runtime + context and evaluate the saved bundle. lock held. */
static int boot_locked(void) {
    teardown();
    rt = JS_NewRuntime();
    if (!rt) { set_result("JS_NewRuntime failed", 20); return -1; }
    if (mem_mb > 0)   JS_SetMemoryLimit(rt, (size_t)mem_mb << 20);
    if (stack_kb > 0) JS_SetMaxStackSize(rt, (size_t)stack_kb << 10);
    JS_SetInterruptHandler(rt, interrupt_cb, NULL);
    ctx = JS_NewContext(rt);
    if (!ctx) { set_result("JS_NewContext failed", 20); teardown(); return -1; }
    JS_UpdateStackTop(rt);
    /* bundle eval gets 10x the call budget (parse of a MB-scale bundle) */
    deadline_ns = timeout_ms > 0 ? now_ns() + (uint64_t)timeout_ms * 10000000ull : 0;
    JSValue v = JS_Eval(ctx, bundle, (size_t)bundle_len, "<bundle>", JS_EVAL_TYPE_GLOBAL);
    deadline_ns = 0;
    if (JS_IsException(v)) {
        set_error_from_exception();
        teardown();
        return -1;
    }
    JS_FreeValue(ctx, v);
    healthy = 1;
    generation++;
    return 0;
}

int qjs_boot(const char *src, long len, int mem, int stack, int tmo) {
    pthread_mutex_lock(&lock);
    char *nb = malloc(len);
    if (!nb) { set_result("bundle malloc failed", 20); pthread_mutex_unlock(&lock); return -1; }
    memcpy(nb, src, len);
    free(bundle);
    bundle = nb; bundle_len = len;
    mem_mb = mem; stack_kb = stack; timeout_ms = tmo;
    int r = boot_locked();
    pthread_mutex_unlock(&lock);
    return r;
}

long qjs_call(const char *fn, const char *arg, long arglen) {
    pthread_mutex_lock(&lock);
    /* lazy re-boot if a previous rebuild failed */
    if (!healthy && boot_locked() < 0) { pthread_mutex_unlock(&lock); return -1; }
    JS_UpdateStackTop(rt);
    deadline_ns = timeout_ms > 0 ? now_ns() + (uint64_t)timeout_ms * 1000000ull : 0;

    JSValue g = JS_GetGlobalObject(ctx);
    JSValue f = JS_GetPropertyStr(ctx, g, fn);
    long out = -1;
    if (!JS_IsFunction(ctx, f)) {
        set_result("no such function", 16);
        JS_FreeValue(ctx, f);
        JS_FreeValue(ctx, g);
    } else {
        JSValue a = JS_NewStringLen(ctx, arg, (size_t)arglen);
        JSValue r = JS_Call(ctx, f, JS_UNDEFINED, 1, &a);
        JS_FreeValue(ctx, a);
        JS_FreeValue(ctx, f);
        JS_FreeValue(ctx, g);
        if (JS_IsException(r)) {
            set_error_from_exception();
            JS_FreeValue(ctx, r);
            /* crash-only: discard the whole heap, eager rebuild so the
               NEXT call is fast; on rebuild failure retry lazily later */
            boot_locked();
        } else {
            size_t n = 0;
            const char *s = JS_ToCStringLen(ctx, &n, r);
            if (s) {
                set_result(s, (long)n);
                JS_FreeCString(ctx, s);
                out = reslen;
            } else {
                set_result("result not a string", 19);
            }
            JS_FreeValue(ctx, r);
        }
    }
    deadline_ns = 0;
    pthread_mutex_unlock(&lock);
    return out;
}

long qjs_fetch(char *out, long cap) {
    pthread_mutex_lock(&lock);
    long n = reslen < cap ? reslen : cap;
    memcpy(out, resbuf, n);
    pthread_mutex_unlock(&lock);
    return n;
}

int qjs_healthy(void) { return healthy; }
long qjs_generation(void) { return generation; }

void qjs_shutdown(void) {
    pthread_mutex_lock(&lock);
    teardown();
    free(bundle); bundle = NULL; bundle_len = 0;
    pthread_mutex_unlock(&lock);
}
