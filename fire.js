// Compile the hero fire in the browser: Goeteia (goeteia.wasm) compiles
// site/fire.ss + its libraries client-side, then the fresh module runs
// against a real WebGL bridge. No precompiled binary is shipped — the
// site's fire is literally compiled by Goeteia in your browser.
// Copyright (c) 2026 guenchi. MIT license; see LICENSE.
// The compiler, the loader bridge and the library sources it is fed all
// come from one versioned CDN prefix, so they cannot drift apart; only
// this site's own sources (site/*.ss) are fetched from here.
const CDN = 'https://cdn.goeteia.dev/1.5.8';
import { makeJsBridge, jsBridgeStubs } from 'https://cdn.goeteia.dev/1.5.8/jsbridge.mjs';

// prelude + the libraries fire.ss imports, then fire.ss itself. The
// compiler splices each (library ...) and treats (import ...) as a
// no-op, so imports resolve against these definitions; dependencies
// come before their dependents (gl needs js).
const SOURCES = [
    CDN + '/src/prelude.ss',
    CDN + '/lib/web/js.ss',
    CDN + '/lib/web/dom.ss',
    CDN + '/lib/gfx/glsl.ss',
    CDN + '/lib/gfx/gl.ss',
    CDN + '/lib/gfx/mat.ss',
    CDN + '/lib/gfx/fx.ss',
    'site/hive-data.ss',
    'site/fire.ss',
];

const enc = new TextEncoder();
const stubs = {
    path_byte: () => {}, open_read: () => -1, open_write: () => -1,
    fread: () => -1, fwrite: () => {}, fclose: () => {},
};

(async () => {
    if (!document.getElementById('hive')) return;   // no canvas, nothing to do
    let wasmBuf, texts;
    try {
        [wasmBuf, ...texts] = await Promise.all([
            fetch(CDN + '/goeteia.wasm').then(r => r.arrayBuffer()),
            ...SOURCES.map(p => fetch(p).then(r => r.text())),
        ]);
    } catch { return; }                              // offline: skip the fire

    // ---- compile: feed the source to goeteia.wasm, collect its output ----
    const input = enc.encode(texts.join('\n'));
    const out = [];
    let pos = 0;
    const { instance: compiler } = await WebAssembly.instantiate(wasmBuf, {
        io: {
            write_byte: b => out.push(b),
            read_byte: () => (pos < input.length ? input[pos++] : -1),
            ...stubs,
        },
        js: jsBridgeStubs,                           // the compiler never calls JS
    });
    compiler.exports.main();
    if (out.length === 0) return;                    // compile error
    const fireWasm = new Uint8Array(out);

    // ---- instantiate the fresh module against the DOM/WebGL bridge ----
    let ex;
    const io = { write_byte: () => {}, read_byte: () => -1, ...stubs };
    let instance;
    try {
        ({ instance } = await WebAssembly.instantiate(fireWasm, {
            io, js: makeJsBridge(() => ex),
        }));
    } catch {
        // engine advertised WebAssembly.Suspending but rejected the import
        const js = makeJsBridge(() => ex);
        js.await = p => p;
        ({ instance } = await WebAssembly.instantiate(fireWasm, { io, js }));
    }
    ex = instance.exports;
    // expose the staging memory so (gfx gl) can build typed-array views
    if (ex.memory) globalThis.__goeteia_mem = ex.memory;
    ex.main();
})();
