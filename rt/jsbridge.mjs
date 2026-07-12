// The js.* import bridge shared by every Goeteia host.
// Copyright (c) 2026 guenchi. MIT license; see LICENSE.

export function makeJsBridge(getExports) {
    let nameBuf = [];
    let argStack = [];
    let staged = [];
    const cbStack = [];
    const utf8Decoder = new TextDecoder();
    const utf8Encoder = new TextEncoder();
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
        global: () => globalThis,
        get: obj => obj[takeName()],
        set: (obj, v) => { obj[takeName()] = v; },
        push: v => argStack.push(v),
        call: (f, thisv) => f.apply(thisv, takeArgs()),
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
        // suspend the whole wasm stack on a promise (JSPI); require BOTH
        // halves of the API — some engines expose WebAssembly.Suspending
        // without promising, and passing a Suspending object where a plain
        // callable is expected fails instantiation ("must be callable").
        // Without full support this is the identity and js-await is a no-op.
        await: (typeof WebAssembly.Suspending === 'function'
                && typeof WebAssembly.promising === 'function')
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
