#!/bin/sh
# Rebuild every page from its Scheme source (site/*.ss) with Goeteia,
# then recompile the hero fire program. Run from the site root.
set -e
cd "$(dirname "$0")"
for p in index manual agent; do
    node rt/compile.mjs goeteia.wasm "site/$p.ss" "/tmp/ig-$p.wasm"
    node rt/run.mjs "/tmp/ig-$p.wasm"
    echo "built $p.html ($(wc -c < "$p.html" | tr -d ' ') bytes)"
done
# the hero fire (site/fire.ss) is compiled in the browser by fire.js, not here
