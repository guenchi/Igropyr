// schwasm host runner: instantiate a compiled module, call main,
// print whatever the program wrote followed by its decoded result.
// Copyright (c) 2026 guenchi. MIT license; see LICENSE.

import fs from 'fs';
import { makeJsBridge } from './jsbridge.mjs';

export async function runModule(bytes, input = []) {
    const out = [];
    let pos = 0;

    // file ports: path pushed byte by byte, then opened
    let pathBuf = [];
    const files = new Map();
    let nextFd = 1;
    const fileIO = {
        path_byte: b => pathBuf.push(b),
        open_read: () => {
            const p = Buffer.from(pathBuf).toString(); pathBuf = [];
            try {
                const data = fs.readFileSync(p);
                const fd = nextFd++;
                files.set(fd, { data, pos: 0 });
                return fd;
            } catch { return -1; }
        },
        open_write: () => {
            const p = Buffer.from(pathBuf).toString(); pathBuf = [];
            const fd = nextFd++;
            files.set(fd, { path: p, out: [] });
            return fd;
        },
        fread: fd => {
            const f = files.get(fd);
            return f && f.pos < f.data.length ? f.data[f.pos++] : -1;
        },
        fwrite: (fd, b) => { files.get(fd).out.push(b); },
        fclose: fd => {
            const f = files.get(fd);
            if (f && f.out) fs.writeFileSync(f.path, Buffer.from(f.out));
            files.delete(fd);
        },
    };

    let exportsRef = null;
    const { instance } = await WebAssembly.instantiate(bytes, {
        io: {
            write_byte: b => out.push(b),
            read_byte: () => (pos < input.length ? input[pos++] : -1),
            ...fileIO,
        },
        js: makeJsBridge(() => exportsRef),
    });
    exportsRef = instance.exports;
    const ex = instance.exports;
    const result = decode(ex.main(), ex);
    return { text: Buffer.from(out).toString('latin1'), result };
}

export function decode(v, ex) {
    // i31ref surfaces in JS as a number; fixnums and characters share
    // it with a one-bit tag
    if (typeof v === 'number') {
        return (v & 1) ? `#\\${String.fromCharCode(v >> 1)}` : String(v >> 1);
    }
    if (v === ex.false.value) return '#f';
    if (v === ex.true.value) return '#t';
    if (v === ex.null.value) return '()';
    if (v === ex.void.value) return '';
    return '#<object>';
}

if (import.meta.url === `file://${process.argv[1]}`) {
    const file = process.argv[2];
    if (!file) {
        console.error('usage: node run.mjs <module.wasm> [input-file]');
        process.exit(1);
    }
    const input = process.argv[3] ? fs.readFileSync(process.argv[3]) : [];
    runModule(fs.readFileSync(file), input)
        .then(({ text, result }) => {
            if (text) process.stdout.write(text);
            if (text && !text.endsWith('\n') && result) process.stdout.write('\n');
            if (result) console.log(result);
            if (text && !result && !text.endsWith('\n')) process.stdout.write('\n');
        })
        .catch(e => { console.error(e.message); process.exit(1); });
}
