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
    function skip() {
        for (;;) {
            while (i < text.length && /[\s]/.test(text[i])) i++;
            if (text[i] !== ';') return;
            while (i < text.length && text[i] !== '\n') i++;
        }
    }
    function one() {
        skip();
        if (text[i] === '(') {
            i++;
            const items = [];
            for (skip(); i < text.length && text[i] !== ')'; skip())
                items.push(one());
            if (i >= text.length) throw new Error('unterminated import clause');
            i++;
            return items;
        }
        const start = i;
        while (i < text.length && !/[\s();]/.test(text[i])) i++;
        if (i === start) throw new Error('invalid import clause');
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

// outermost mount points, lexically (same string / comment /
// char-literal awareness as topLevelSpans); each is an independent
// import scope resolved separately below.  The define- family are
// mount points too -- keep this list in step with the chez driver's,
// or an import inside a define-wasm body resolves on one host only
const $mountHeads = /^\(\s*(?:conjure|define-js|define-wasm|define-wasm-js)[\s(]/;

// Skip a complete quoted datum without disturbing the surrounding
// parenthesis depth: mount-shaped data must never become an import scope.
function listDatumEnd(text, open) {
    let depth = 0;
    for (let i = open; i < text.length; i++) {
        const c = text[i];
        if (c === ';') { while (i < text.length && text[i] !== '\n') i++; continue; }
        if (c === '"') { i++; while (i < text.length && text[i] !== '"') { if (text[i] === '\\') i++; i++; } continue; }
        if (c === '#' && text[i + 1] === '\\') { i += 2; continue; }
        if (c === '(') depth++;
        else if (c === ')' && --depth === 0) return i + 1;
    }
    return text.length;
}

function datumEnd(text, at) {
    let i = at;
    for (;;) {
        while (i < text.length && /[\s]/.test(text[i])) i++;
        if (text[i] !== ';') break;
        while (i < text.length && text[i] !== '\n') i++;
    }
    if (i >= text.length) return i;
    if (text[i] === '\'' || text[i] === '`') return datumEnd(text, i + 1);
    if (text[i] === ',') return datumEnd(text, i + (text[i + 1] === '@' ? 2 : 1));
    if (text[i] === '"') {
        for (i++; i < text.length && text[i] !== '"'; i++)
            if (text[i] === '\\') i++;
        return Math.min(i + 1, text.length);
    }
    if (text[i] === '#' && text[i + 1] === '\\') {
        i += 2;
        if (i < text.length && /[\s()]/.test(text[i])) return i + 1;
        while (i < text.length && !/[\s();]/.test(text[i])) i++;
        return i;
    }
    if (text[i] === '(') return listDatumEnd(text, i);
    if (text.startsWith('#(', i)) return listDatumEnd(text, i + 1);
    if (text.startsWith('#vu8(', i)) return listDatumEnd(text, i + 4);
    while (i < text.length && !/[\s();]/.test(text[i])) i++;
    return i;
}

function embedBlocks(text) {
    const blocks = [];
    let depth = 0, embedStart = -1, embedDepth = 0;
    // quasiquote suspends mounting by nesting depth and unquote
    // resumes it, mirroring the compiler's embed-expand: a mount head
    // is data under ` and a mount point again under , -- qqAt[d] is
    // the quasiquote depth entered at paren depth d
    let qq = 0;
    const qqAt = [];
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (c === ';') { while (i < text.length && text[i] !== '\n') i++; continue; }
        if (c === '"') { i++; while (i < text.length && text[i] !== '"') { if (text[i] === '\\') i++; i++; } continue; }
        if (c === '#' && text[i + 1] === '\\') { i += 2; continue; }
        if (c === '\'') { i = datumEnd(text, i + 1) - 1; continue; }
        if (c === '`') { qq++; qqAt.push([depth, +1]); continue; }
        if (c === ',' && qq > 0) {
            qq--; qqAt.push([depth, -1]);
            if (text[i + 1] === '@') i++;
            continue;
        }
        if (c === '(') {
            if (/^\(\s*quote[\s(]/.test(text.slice(i, i + 16))) {
                i = datumEnd(text, i) - 1;
                continue;
            }
            if (/^\(\s*quasiquote[\s(]/.test(text.slice(i, i + 20))) {
                qq++; qqAt.push([depth, +1]);
            } else if (qq > 0
                       && /^\(\s*unquote(-splicing)?[\s(]/.test(text.slice(i, i + 22))) {
                qq--; qqAt.push([depth, -1]);
            }
            if (qq === 0 && embedStart < 0
                && $mountHeads.test(text.slice(i, i + 24))) {
                embedStart = i; embedDepth = depth;
            }
            depth++;
        } else if (c === ')') {
            depth--;
            // a reader-macro prefix binds to the next datum, so any
            // shift recorded at this depth expires with the list
            while (qqAt.length && qqAt[qqAt.length - 1][0] >= depth) {
                qq -= qqAt.pop()[1];
            }
            if (embedStart >= 0 && depth === embedDepth) {
                blocks.push([embedStart, i + 1]);
                embedStart = -1;
            }
        }
    }
    return blocks;
}

// resolve the imports inside each outermost embed block, each in a
// fresh scope: the embed compiles as an independent unit, so the
// host's already-spliced libraries must not deduplicate its own
function resolveEmbedImports(text, dirs, file) {
    let result = '', at = 0;
    for (const [start, end] of embedBlocks(text)) {
        const block = text.slice(start, end);
        const head = block.match(/^\(\s*([a-z-]+)/)[1];
        const open = block.indexOf(head) + head.length;
        const inner = block.slice(open, block.length - 1);
        result += text.slice(at, start);
        // leave the block untouched unless it actually imports (or
        // nests another block that might): quoted data that merely
        // LOOKS like a mount point -- the compiler's own sources
        // hold such tables -- must pass through byte-for-byte, or
        // self-compilation loses its fixed point
        const needsWork = embedBlocks(inner).length > 0
            || topLevelSpans(inner).some(([s2, e2]) =>
                /^\(\s*import[\s)]/.test(inner.slice(s2, e2)));
        result += needsWork
            ? '(' + head
              + resolveImports(resolveEmbedImports(inner, dirs, file),
                               dirs, new Set(), file + ':embed') + ')'
            : block;
        at = end;
    }
    return result + text.slice(at);
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
            // a library body may itself hold mount points, whose
            // imports resolve in their own scope (the chez driver
            // walks library forms the same way)
            const text = resolveEmbedImports(fs.readFileSync(p, 'latin1'),
                                             dirs, p);
            const deps = libraryImports(text)
                .map(s => loadLibrary(specTarget(s), dirs, visited)
                          + '\n' + specAliases(s))
                .join('\n');
            return deps + locMark(p, 1) + text;
        }
    }
    throw new Error(`library not found: (${spec.join(' ')})`);
}


// the runtime glue a default conjure section inlines: jsbridge +
// web.mjs with the module plumbing stripped, non-ASCII normalized
// (both drivers must produce the identical string)
let conjureGlueCache = null;
function conjureGlue() {
    if (conjureGlueCache !== null) return conjureGlueCache;
    const strip = t => t.split('\n')
        .filter(l => !/^\s*import\s.*jsbridge/.test(l))
        .join('\n')
        .replace(/^export /gm, '');
    const clean = t => {
        let r = '';
        for (const ch of t) r += ch.charCodeAt(0) > 126 ? ' ' : ch;
        return r;
    };
    const jb = fs.readFileSync(path.join(here, 'jsbridge.mjs'), 'latin1');
    const wb = fs.readFileSync(path.join(here, 'web.mjs'), 'latin1');
    conjureGlueCache = clean(strip(jb) + '\n' + strip(wb));
    return conjureGlueCache;
}
function conjureGlueDirective() {
    const esc = conjureGlue().replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return '(%conjure-rt "' + esc + '")\n';
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
// script: true compiles at -O0 -- the optimization passes stand
// down, for callers who compile on every keystroke.
export async function compileToBytes(sourceFile,
    { compilerWasm = defaultCompiler, script = false, target = null } = {}) {
    const inDir = path.dirname(path.resolve(sourceFile));
    const dirs = [inDir, path.join(inDir, 'lib'), path.join(here, '../lib')];
    const preludePath = path.join(here, '../src/prelude.ss');
    const prelude = fs.readFileSync(preludePath, 'latin1');
    const source = resolveImports(
        resolveEmbedImports(fs.readFileSync(sourceFile, 'latin1'),
                            dirs, sourceFile),
        dirs, new Set(), sourceFile);
    const input = Buffer.from((target ? `(%target ${target})\n` : '')
                              + (script ? '(%opt 0)\n' : '')
                              + locMark(preludePath, 1) + prelude
                              + '\n' + conjureGlueDirective() + '(%prelude-end)\n' + source, 'latin1');
    return runCompiler(input, compilerWasm);
}

// Compile source text (a REPL session, a playground snippet): imports
// resolve against baseDir, its lib/, and the bundled lib/.
export async function compileSource(text,
    { baseDir = process.cwd(), compilerWasm = defaultCompiler,
      name = 'repl', script = false, target = null } = {}) {
    const dirs = [baseDir, path.join(baseDir, 'lib'), path.join(here, '../lib')];
    const preludePath = path.join(here, '../src/prelude.ss');
    const prelude = fs.readFileSync(preludePath, 'latin1');
    // utf-8 text to one-byte-per-char, matching the byte reader
    const raw = Buffer.from(text, 'utf8').toString('latin1');
    const source = resolveImports(resolveEmbedImports(raw, dirs, name),
                                  dirs, new Set(), name);
    const input = Buffer.from((target ? `(%target ${target})\n` : '')
                              + (script ? '(%opt 0)\n' : '')
                              + locMark(preludePath, 1) + prelude
                              + '\n' + conjureGlueDirective() + '(%prelude-end)\n' + source, 'latin1');
    return runCompiler(input, compilerWasm);
}

// Compile a source file straight to an output file.
export async function compileFile(sourceFile, outFile, opts = {}) {
    fs.writeFileSync(outFile, await compileToBytes(sourceFile, opts));
}

async function main() {
    const argv = process.argv.slice(2);
    // --script / -O0: compile without the optimization passes
    const script = argv.some(a => a === '--script' || a === '-O0');
    // --js: emit a JavaScript module instead of wasm
    const js = argv.some(a => a === '--js');
    const args = argv.filter(a => a !== '--script' && a !== '-O0'
                                  && a !== '--js');
    // legacy form: compile.mjs <compiler.wasm> <input.ss> <output.wasm>
    // new form:    compile.mjs <input.ss> <output.wasm>  (bundled compiler)
    let compilerWasm, sourceFile, outFile;
    if (args.length >= 3) [compilerWasm, sourceFile, outFile] = args;
    else [sourceFile, outFile] = args;
    if (!sourceFile || !outFile) {
        console.error('usage: node compile.mjs [--script] [--js] [<compiler.wasm>] <input.ss> <output.wasm|.js>');
        process.exit(1);
    }
    try {
        await compileFile(sourceFile, outFile,
                          { ...(compilerWasm ? { compilerWasm } : {}), script,
                            ...(js ? { target: 'js' } : {}) });
    } catch (e) {
        if (e.output) process.stderr.write(e.output);
        console.error(`\n${e.message}`);
        process.exit(1);
    }
}

if (process.argv[1] &&
    import.meta.url === url.pathToFileURL(path.resolve(process.argv[1])).href) main();
