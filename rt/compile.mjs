// Run the self-hosted schwasm compiler (a wasm module): feed it the
// prelude plus a source file (with imports resolved), collect the
// wasm bytes it emits.
// Copyright (c) 2026 guenchi. MIT license; see LICENSE.

import fs from 'fs';
import { jsBridgeStubs } from './jsbridge.mjs';
import path from 'path';
import url from 'url';

const here = path.dirname(url.fileURLToPath(import.meta.url));

// ---- library resolution (mirrors src/chez-driver.ss) ----
// Top-level (import (a b) ...) forms pull in a/b.ss, a single
// (library ...) form per file, dependencies first, each once.

function topLevelSpans(text) {
    // spans of top-level parenthesized forms (paren counting, aware
    // of strings, comments and character literals)
    const spans = [];
    let depth = 0, start = -1;
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (c === ';') { while (i < text.length && text[i] !== '\n') i++; continue; }
        if (c === '"') { i++; while (i < text.length && text[i] !== '"') { if (text[i] === '\\') i++; i++; } continue; }
        if (c === '#' && text[i + 1] === '\\') { i += 2; continue; }
        if (c === '(') { if (depth === 0) start = i; depth++; }
        else if (c === ')') { depth--; if (depth === 0) spans.push([start, i + 1]); }
    }
    return spans;
}

// a minimal sexpr reader for import clauses: symbols and nesting
function parseSexpr(text) {
    let i = 0;
    function skip() { while (i < text.length && /[\s]/.test(text[i])) i++; }
    function one() {
        skip();
        if (text[i] === '(') {
            i++;
            const items = [];
            for (skip(); text[i] !== ')'; skip()) items.push(one());
            i++;
            return items;
        }
        const start = i;
        while (i < text.length && !/[\s()]/.test(text[i])) i++;
        return text.slice(start, i);
    }
    return one();
}

function parseSpecs(form) {
    // "(import (a b) (only (c) d))" -> [["a","b"],["only",["c"],"d"]]
    return parseSexpr(form).slice(1);
}

function specTarget(spec) {
    return ['only', 'except', 'rename', 'prefix'].includes(spec[0])
        ? spec[1] : spec;
}
function specAliases(spec) {
    if (spec[0] !== 'rename') return '';
    return spec.slice(2)
        .map(pr => `(define ${pr[1]} ${pr[0]})`)
        .join('\n');
}

function libraryImports(text) {
    // the (import ...) clause: a depth-1 subform of the (library ...)
    // form (regexes can't balance the nested specs)
    let depth = 0, start = -1;
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (c === ';') { while (i < text.length && text[i] !== '\n') i++; continue; }
        if (c === '"') { i++; while (i < text.length && text[i] !== '"') { if (text[i] === '\\') i++; i++; } continue; }
        if (c === '#' && text[i + 1] === '\\') { i += 2; continue; }
        if (c === '(') { if (depth === 1) start = i; depth++; }
        else if (c === ')') {
            depth--;
            if (depth === 1 && start >= 0) {
                const clause = text.slice(start, i + 1);
                if (/^\(\s*import[\s)]/.test(clause)) return parseSpecs(clause);
            }
        }
    }
    return [];
}

function resolveImports(text, dirs, visited = new Set()) {
    // replace top-level (import ...) spans with the inlined
    // libraries; every other byte passes through untouched
    let result = '';
    let at = 0;
    for (const [start, end] of topLevelSpans(text)) {
        const form = text.slice(start, end);
        if (/^\(\s*import[\s)]/.test(form)) {
            result += text.slice(at, start);
            result += parseSpecs(form)
                .map(spec => loadLibrary(specTarget(spec), dirs, visited)
                             + '\n' + specAliases(spec))
                .join('\n');
            at = end;
        }
    }
    return result + text.slice(at);
}

function loadLibrary(spec, dirs, visited) {
    // (rnrs ...) and (schwasm ...) come from the prelude
    if (spec[0] === 'rnrs' || spec[0] === 'schwasm') return '';
    const key = spec.join('/');
    if (visited.has(key)) return '';
    visited.add(key);
    for (const d of dirs) {
        const p = path.join(d, ...spec) + '.ss';
        if (fs.existsSync(p)) {
            const text = fs.readFileSync(p, 'latin1');
            const deps = libraryImports(text)
                .map(s => loadLibrary(s, dirs, visited))
                .join('\n');
            return deps + '\n' + text;
        }
    }
    throw new Error(`library not found: (${spec.join(' ')})`);
}

async function main() {
    const [compilerWasm, sourceFile, outFile] = process.argv.slice(2);
    if (!outFile) {
        console.error('usage: node compile.mjs <compiler.wasm> <input.ss> <output.wasm>');
        process.exit(1);
    }
    const inDir = path.dirname(path.resolve(sourceFile));
    const dirs = [inDir, path.join(inDir, 'lib'), path.join(here, '../lib')];
    const prelude = fs.readFileSync(path.join(here, '../src/prelude.ss'), 'latin1');
    const source = resolveImports(fs.readFileSync(sourceFile, 'latin1'), dirs);
    const input = Buffer.from(prelude + '\n' + source, 'latin1');

    const out = [];
    let pos = 0;
    const { instance } = await WebAssembly.instantiate(
        fs.readFileSync(compilerWasm),
        {
            io: {
                write_byte: b => out.push(b),
                read_byte: () => (pos < input.length ? input[pos++] : -1),
                // the compiler itself does no file I/O
                path_byte: () => {}, open_read: () => -1, open_write: () => -1,
                fread: () => -1, fwrite: () => {}, fclose: () => {},
            },
            js: jsBridgeStubs,
        });
    try {
        instance.exports.main();
    } catch (e) {
        // compile errors print through the output channel before trapping
        process.stderr.write(Buffer.from(out).toString('latin1'));
        console.error(`\ncompile failed: ${e.message}`);
        process.exit(1);
    }
    fs.writeFileSync(outFile, Buffer.from(out));
}

main();
