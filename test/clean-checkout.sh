#!/bin/sh
# A FRESH CHECKOUT RESOLVES THE LIBRARIES. The working tree used to carry an
# untracked `igropyr -> .` link that mapped the library name; a clone or an
# archive has no such link, and from one, (igropyr util) was not found by
# the very environment run-all.sh set up. test/env.sh now maps the name by
# itself. This proves it on an archive of the tracked files only, placed
# under a different directory name, below a path with a space, and run from
# a working directory that is not the tree.
#
# The control first: with the mapping withheld (CHEZSCHEMELIBDIRS pointing at
# the tree alone), the import must FAIL from that archive. A check whose
# failure branch has never been seen is not known to be looking at anything.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
IGROPYR_ROOT="$ROOT"
. "$ROOT/test/env.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/igropyr-clean.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/with space/not-the-library-name"
git archive HEAD | (cd "$work/with space/not-the-library-name" && tar -xf -)
tree="$work/with space/not-the-library-name"
if [ -e "$tree/igropyr" ]; then
  echo "FAIL clean-checkout: the archive carries an igropyr entry; this cell proves nothing"
  exit 1
fi
probe='(import (igropyr util)) (display "clean-checkout: (igropyr util) imported") (newline)'
printf '%s\n' "$probe" > "$work/probe.ss"
fails=0
# control: the tree alone, no mapping -- must fail
if (cd "$work" && env -u IGROPYR_LIBMAP CHEZSCHEMELIBDIRS="$tree" "$SCHEME_BIN" --script "$work/probe.ss" >/dev/null 2>&1); then
  echo "FAIL clean-checkout control: the import succeeded without the mapping (what is answering?)"
  fails=$((fails+1))
else
  echo "  ok  clean-checkout control: without the mapping, (igropyr util) is not found"
fi
# the reading: the archive's own test/env.sh, sourced from elsewhere
if (cd "$work" && env -u IGROPYR_LIBMAP -u CHEZSCHEMELIBDIRS sh -c 'IGROPYR_ROOT="$1"; . "$1/test/env.sh" && "$SCHEME_BIN" --script "$2" && rm -rf "$IGROPYR_LIBMAP"' sh "$tree" "$work/probe.ss" 2>&1 | grep -q "clean-checkout: (igropyr util) imported"); then
  echo "  ok  clean-checkout: a fresh archive under another name, below a path with a space, imports (igropyr util)"
else
  echo "FAIL clean-checkout: the fresh archive could not import (igropyr util) through its test/env.sh"
  fails=$((fails+1))
fi
if [ "$fails" -eq 0 ]; then echo "clean-checkout: all tests passed"; exit 0; fi
echo "clean-checkout: $fails failed"; exit 1
