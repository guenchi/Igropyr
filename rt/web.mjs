// Browser loader for compiled Goeteia modules, main thread: full DOM
// access through the js bridge.
// Copyright (c) 2026 guenchi. MIT license; see LICENSE.

import { makeJsBridge, callMain } from './jsbridge.mjs';

export async function loadGoeteia(url) {
    let exportsRef = null;
    const { instance } = await WebAssembly.instantiate(
        await (await fetch(url)).arrayBuffer(),
        {
            io: {
                write_byte: b => loadGoeteia._out.push(b),
                read_byte: () => -1,
                path_byte: () => {}, open_read: () => -1, open_write: () => -1,
                fread: () => -1, fwrite: () => {}, fclose: () => {},
            },
            js: makeJsBridge(() => exportsRef),
        });
    exportsRef = instance.exports;
    await callMain(instance.exports);
    return instance.exports;
}
loadGoeteia._out = [];

// Run a module in a Worker over an OffscreenCanvas: the render loop
// leaves the main thread entirely (a busy main thread no longer
// drops frames).  Input forwards as messages -- keys from the
// window, pointer events from the canvas -- and rt/worker.mjs
// re-dispatches them to the module's listeners.  The module finds
// its canvas at (js-get (js-global) "__goeteia_canvas").
// Does this engine run WasmGC?  Validate a minimal module carrying
// one struct type -- pre-GC engines reject the typecode
export function hasWasmGC() {
    try {
        return WebAssembly.validate(new Uint8Array(
            [0, 97, 115, 109, 1, 0, 0, 0, 1, 3, 1, 95, 0]));
    } catch { return false; }
}

const browserIO = () => ({
    write_byte: b => loadGoeteia._out.push(b),
    read_byte: () => -1,
    path_byte: () => {}, open_read: () => -1, open_write: () => -1,
    fread: () => -1, fwrite: () => {}, fclose: () => {},
});

// Run a --js compiled module from inline text (a single-file page
// carries it in an inert <script> tag).  The text is an ES module;
// scoping it through Function needs only the export keywords gone.
export function runGoeteiaInline(text) {
    const body = String(text).replace(/^export /gm, '');
    const main = new Function(body + '\nreturn main;')();
    main(browserIO());
}

// The two-artifact entry: the wasm module when the engine has WasmGC,
// otherwise the --js compiled fallback.  `fallback` is either a CSS
// selector for an inert inline <script> tag (the single-file page,
// zero extra requests) or a .js/.mjs URL fetched only when actually
// needed -- the lazy shape: WasmGC users never download the fallback,
// and the file caches independently of the page.  ?goeteia=js forces
// the fallback, for testing it on a GC engine.
export async function loadGoeteiaAuto(url, fallback = 'script[type="goeteia/js"]') {
    const forced = new URLSearchParams(location.search).get('goeteia') === 'js';
    if (!forced && hasWasmGC()) return loadGoeteia(url);
    if (/\.m?js([?#]|$)/.test(fallback)) {
        const m = await import(new URL(fallback, location.href).href);
        return m.main(browserIO());
    }
    const tag = document.querySelector(fallback);
    if (!tag) throw new Error('no Goeteia fallback on this page');
    return runGoeteiaInline(tag.textContent);
}

export function loadGoeteiaWorker(url, canvas) {
    const off = canvas.transferControlToOffscreen();
    const worker = new Worker(new URL('./worker.mjs', import.meta.url),
                              { type: 'module' });
    worker.postMessage(
        { wasm: new URL(url, location.href).href, canvas: off }, [off]);
    const fwd = (kind, extra) =>
        worker.postMessage(Object.assign({ event: kind }, extra));
    window.addEventListener('keydown', e => fwd('keydown', { key: e.key }));
    window.addEventListener('keyup', e => fwd('keyup', { key: e.key }));
    for (const k of ['pointermove', 'pointerdown', 'pointerup', 'click'])
        canvas.addEventListener(k, e =>
            fwd(k, { offsetX: e.offsetX, offsetY: e.offsetY }));
    return worker;
}
