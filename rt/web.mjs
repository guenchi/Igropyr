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
    // expose the staging memory so Scheme can build typed-array views
    if (instance.exports.memory) globalThis.__goeteia_mem = instance.exports.memory;
    await callMain(instance.exports);
    return instance.exports;
}
loadGoeteia._out = [];
