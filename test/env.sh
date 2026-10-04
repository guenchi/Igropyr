#!/bin/sh
# Source this from the repository root (or let run-all.sh do it) to run a
# suite from source:  . test/env.sh && "$SCHEME_BIN" --script test/foo.sc
# The mapping directory it makes is tiny (one link) and is removed by
# run-all.sh at exit; a shell that sourced this by hand leaves it in $TMPDIR.
#
# THE LIBRARY NAME IS MAPPED HERE, NOT BY A LINK SOMEONE MADE BY HAND. The
# libraries are (igropyr ...), so Chez looks for igropyr/util.sc under some
# directory in CHEZSCHEMELIBDIRS. A working tree used to answer that with
# an untracked `igropyr -> .` link in the repository root -- which a fresh
# clone or archive does not have, so from there (igropyr util) was simply
# not found. This file makes a private directory holding one link,
# igropyr -> this tree, and puts it first; the tree itself stays second so
# the (test ...) fixtures resolve as before. The clone can have any name,
# the path may contain spaces, and the caller's working directory does not
# matter: the tree is located from this file.
#
# THE OBJECT EXTENSION POINTS AT A SUFFIX THAT DOES NOT EXIST, so a stale
# .so can never answer for a source file. Chez picks by timestamp, which is
# why this has not bitten yet -- every edited source here is newer than the
# objects left in the tree -- but "has not bitten" is not a property: an
# object built after its source, from a tree that has since moved, wins
# and nothing says so. Leaving the object extension EMPTY does not do this;
# it still resolves to .so (measured). Naming an extension nothing produces
# is what excludes them.
# The tree: IGROPYR_ROOT if the caller set it, else the parent of this
# file's directory (when run as a script), else the working directory
# (when sourced, $0 is the shell, not this file).
if [ -z "${IGROPYR_ROOT:-}" ]; then
  IGROPYR_ROOT="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
  if [ ! -f "$IGROPYR_ROOT/test/env.sh" ]; then IGROPYR_ROOT="$(pwd)"; fi
fi
if [ ! -f "$IGROPYR_ROOT/util.sc" ]; then
  echo "test/env.sh: not an igropyr tree: $IGROPYR_ROOT" >&2
  return 1 2>/dev/null || exit 1
fi
IGROPYR_LIBMAP="${IGROPYR_LIBMAP:-$(mktemp -d "${TMPDIR:-/tmp}/igropyr-libmap.XXXXXX")}"
if [ ! -e "$IGROPYR_LIBMAP/igropyr" ]; then
  ln -s "$IGROPYR_ROOT" "$IGROPYR_LIBMAP/igropyr"
fi
export IGROPYR_LIBMAP
export CHEZSCHEMELIBDIRS="$IGROPYR_LIBMAP:$IGROPYR_ROOT"
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.no-obj:.ss::.no-obj:.sls::.no-obj:.scm::.no-obj:.sch::.no-obj:.sc::.no-obj
if [ -z "${SCHEME_BIN:-}" ]; then
  if command -v chez >/dev/null 2>&1; then SCHEME_BIN=chez; else SCHEME_BIN=scheme; fi
fi
export SCHEME_BIN
