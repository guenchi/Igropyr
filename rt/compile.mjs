// Run the self-hosted goeteia compiler (a wasm module): feed it the
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

// a (%loc "file" line) marker: the compiler maps stream lines back
// to source lines with these, so errors can say file:line
function locMark(file, line) {
    return `\n(%loc ${JSON.stringify(file)} ${line})\n`;
}
function lineAt(text, idx) {
    let n = 1;
    for (let i = 0; i < idx && i < text.length; i++)
        if (text[i] === '\n') n++;
    return n;
}

function resolveImports(text, dirs, visited = new Set(), file = 'input') {
    // replace top-level (import ...) spans with the inlined
    // libraries; every other byte passes through untouched
    let result = locMark(file, 1);
    let at = 0;
    for (const [start, end] of topLevelSpans(text)) {
        const form = text.slice(start, end);
        if (/^\(\s*import[\s)]/.test(form)) {
            result += text.slice(at, start);
            result += parseSpecs(form)
                .map(spec => loadLibrary(specTarget(spec), dirs, visited)
                             + '\n' + specAliases(spec))
                .join('\n');
            result += locMark(file, lineAt(text, end));
            at = end;
        }
    }
    return result + text.slice(at);
}

function loadLibrary(spec, dirs, visited) {
    // (rnrs ...) and (goeteia ...) come from the prelude
    if (spec[0] === 'rnrs' || spec[0] === 'goeteia') return '';
    const key = spec.join('/');
    if (visited.has(key)) return '';
    visited.add(key);
    for (const d of dirs) {
        const p = path.join(d, ...spec) + '.ss';
        if (fs.existsSync(p)) {
            const text = fs.readFileSync(p, 'latin1');
            const deps = libraryImports(text)
                .map(s => loadLibrary(specTarget(s), dirs, visited)
                          + '\n' + specAliases(s))
                .join('\n');
            return deps + locMark(p, 1) + text;
        }
    }
    throw new Error(`library not found: (${spec.join(' ')})`);
}

// the bundled self-hosted compiler, shipped at the package root
const defaultCompiler = path.join(here, '../goeteia.wasm');

// feed a prelude+source stream to the compiler, collect wasm bytes
async function runCompiler(input, compilerWasm) {
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
        const err = new Error(`compile failed: ${e.message}`);
        err.output = Buffer.from(out).toString('latin1');
        throw err;
    }
    return Buffer.from(out);
}

// Compile a source file to wasm bytes.  Resolves (import ...) forms
// against the source directory, its lib/, and the bundled lib/, then
// prepends the prelude and feeds the whole stream to the compiler.
export async function compileToBytes(sourceFile, { compilerWasm = defaultCompiler } = {}) {
    const inDir = path.dirname(path.resolve(sourceFile));
    const dirs = [inDir, path.join(inDir, 'lib'), path.join(here, '../lib')];
    const preludePath = path.join(here, '../src/prelude.ss');
    const prelude = fs.readFileSync(preludePath, 'latin1');
    const source = resolveImports(fs.readFileSync(sourceFile, 'latin1'),
                                  dirs, new Set(), sourceFile);
    const input = Buffer.from(locMark(preludePath, 1) + prelude
                              + '\n' + source, 'latin1');
    return runCompiler(input, compilerWasm);
}

// Compile source text (a REPL session, a playground snippet): imports
// resolve against baseDir, its lib/, and the bundled lib/.
export async function compileSource(text,
    { baseDir = process.cwd(), compilerWasm = defaultCompiler,
      name = 'repl' } = {}) {
    const dirs = [baseDir, path.join(baseDir, 'lib'), path.join(here, '../lib')];
    const preludePath = path.join(here, '../src/prelude.ss');
    const prelude = fs.readFileSync(preludePath, 'latin1');
    // utf-8 text to one-byte-per-char, matching the byte reader
    const raw = Buffer.from(text, 'utf8').toString('latin1');
    const source = resolveImports(raw, dirs, new Set(), name);
    const input = Buffer.from(locMark(preludePath, 1) + prelude
                              + '\n' + source, 'latin1');
    return runCompiler(input, compilerWasm);
}

// Compile a source file straight to an output file.
export async function compileFile(sourceFile, outFile, opts = {}) {
    fs.writeFileSync(outFile, await compileToBytes(sourceFile, opts));
}

async function main() {
    const args = process.argv.slice(2);
    // legacy form: compile.mjs <compiler.wasm> <input.ss> <output.wasm>
    // new form:    compile.mjs <input.ss> <output.wasm>  (bundled compiler)
    let compilerWasm, sourceFile, outFile;
    if (args.length >= 3) [compilerWasm, sourceFile, outFile] = args;
    else [sourceFile, outFile] = args;
    if (!sourceFile || !outFile) {
        console.error('usage: node compile.mjs [<compiler.wasm>] <input.ss> <output.wasm>');
        process.exit(1);
    }
    try {
        await compileFile(sourceFile, outFile, compilerWasm ? { compilerWasm } : {});
    } catch (e) {
        if (e.output) process.stderr.write(e.output);
        console.error(`\n${e.message}`);
        process.exit(1);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
