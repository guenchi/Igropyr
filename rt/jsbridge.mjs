// The js.* import bridge shared by every Goeteia host.
// Copyright (c) 2026 guenchi. MIT license; see LICENSE.

export function makeJsBridge(getExports) {
    let nameBuf = [];
    let argStack = [];
    let staged = [];
    const cbStack = [];
    const utf8Decoder = new TextDecoder();
    const utf8Encoder = new TextEncoder();
    const localGlobals = new Map();
    const isLocalGlobal = key => typeof key === 'string' &&
        key.startsWith('__goeteia_');
    let instanceGlobal;
    // eval'd code sees `globalThis` bound to this instance's proxy, so
    // `globalThis.__goeteia_*` resolves to per-instance state. Only the
    // `globalThis` identifier is shadowed -- a bare unqualified
    // `__goeteia_*` inside eval would still reach the real global, but
    // Scheme codegen always accesses globals qualified (js-get), so it
    // never emits that form.
    const scopedEval = code => Function(
        'globalThis', 'code', 'return eval(code);'
    )(instanceGlobal, String(code));
    instanceGlobal = new Proxy(globalThis, {
        get(target, key) {
            if (key === 'eval') return scopedEval;
            if (key === '__goeteia_mem') return getExports()?.memory;
            if (localGlobals.has(key)) return localGlobals.get(key);
            return Reflect.get(target, key, target);
        },
        set(target, key, value) {
            if (isLocalGlobal(key)) { localGlobals.set(key, value); return true; }
            // propagate a real failure (e.g. a non-writable global) so a
            // strict-mode assignment throws instead of silently no-op'ing
            return Reflect.set(target, key, value, target);
        },
    });
    const takeName = () => {
        // Goeteia strings are UTF-8 byte arrays; decode to a real JS
        // string so non-ASCII (Γ, —, →) crosses correctly
        const s = utf8Decoder.decode(new Uint8Array(nameBuf));
        nameBuf = [];
        return s;
    };
    const takeArgs = () => {
        const a = argStack;
        argStack = [];
        return a;
    };
    return {
        arg_byte: b => nameBuf.push(b),
        global: () => instanceGlobal,
        get: obj => obj[takeName()],
        set: (obj, v) => { obj[takeName()] = v; },
        push: v => argStack.push(v),
        call: (f, thisv) => f.apply(
            thisv === instanceGlobal ? globalThis : thisv, takeArgs()),
        new: ctor => new ctor(...takeArgs()),
        string: () => takeName(),
        str_len: s => { staged = [...utf8Encoder.encode(String(s))]; return staged.length; },
        str_byte: i => staged[i],
        number: x => x,
        to_number: v => Number(v),
        eq: (a, b) => (a === b ? 1 : 0),
        bool: v => (v ? 1 : 0),
        undefined: () => undefined,
        fn: closure => (...args) => {
            const frame = { args, ret: undefined };
            cbStack.push(frame);
            try {
                getExports()['$jscb'](closure);
            } finally {
                cbStack.pop();
            }
            return frame.ret;
        },
        cb_argc: () => cbStack[cbStack.length - 1].args.length,
        cb_arg: i => cbStack[cbStack.length - 1].args[i],
        cb_ret: v => { cbStack[cbStack.length - 1].ret = v; },
        // suspend the whole wasm stack on a promise (JSPI); without
        // engine support this is the identity and js-await is a no-op
        await: (typeof WebAssembly.Suspending === 'function')
            ? new WebAssembly.Suspending(p => Promise.resolve(p))
            : p => p,
    };
}

// call an exported main through JSPI when available, so js-await can
// suspend; falls back to a plain call (and a plain value) without it
export function callMain(ex) {
    return (typeof WebAssembly.promising === 'function')
        ? WebAssembly.promising(ex.main)()
        : ex.main();
}

export const jsBridgeStubs = {
    arg_byte: () => {}, global: () => undefined, get: () => undefined,
    set: () => {}, push: () => {}, call: () => undefined,
    new: () => undefined, string: () => '', str_len: () => 0,
    str_byte: () => 0, number: () => 0, to_number: () => 0,
    eq: () => 0, bool: () => 0, undefined: () => undefined,
    fn: () => undefined, cb_argc: () => 0, cb_arg: () => undefined,
    cb_ret: () => {}, await: p => p,
};
