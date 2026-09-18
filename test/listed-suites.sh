#!/bin/sh
# Every file that ends like a suite must be named in run-all.sh.
#
# WHY THIS SHAPE. run-all.sh names its suites one line at a time rather than
# globbing, which is the right choice -- suites need different environments and
# some must not run at all -- but it means a new suite that nobody adds a line
# for simply never runs, and nothing says so. That has happened: three cells
# were written, committed, and never executed. The criterion here is the file's
# OWN shape, so it does not depend on anyone remembering to update a list.
#
# WHAT IT DOES NOT CATCH, stated so this is not mistaken for evidence of it: a
# suite that IS listed but has lost a section. A file can be named here, run,
# print its pass line, and cover half of what it used to. That is a different
# hole and needs a different instrument.
#
# EXCLUSIONS ARE EXPLICIT, and a stale exclusion is also an error. A file listed
# below that HAS since been added to run-all.sh means the reason no longer
# holds, and the line must go -- otherwise the exception list becomes the same
# kind of silent decay the check exists to prevent.
set -eu
cd "$(cd "$(dirname "$0")/.." && pwd)"

# name:reason
EXCLUDED='write-block-window:the mechanism it tests is not implemented; listing it would be a red nobody asked for'

suite_shaped() { grep -qE "ALL .* PASSED|all tests passed" "$1"; }
listed() { grep -q "test/$1\.sc" test/run-all.sh; }
excluded() { echo "$EXCLUDED" | tr ' ' '\n' >/dev/null; case "$EXCLUDED" in *"$1:"*) return 0;; esac; return 1; }

fails=0
shaped=0
for f in test/*.sc; do
  b=$(basename "$f" .sc)
  if suite_shaped "$f"; then
    shaped=$((shaped + 1))
    if listed "$b"; then
      if excluded "$b"; then
        echo "STALE EXCLUSION: $b is listed in run-all.sh; remove it from EXCLUDED"
        fails=$((fails + 1))
      fi
    elif ! excluded "$b"; then
      echo "NEVER RUN: $b ends like a suite but no line in run-all.sh names it"
      fails=$((fails + 1))
    fi
  fi
done

# THE CONTROL. A detector that matched nothing would print nothing and read as
# a clean run, which is the failure this whole file is about. Ten is far below
# the real count and far above zero.
if [ "$shaped" -lt 10 ]; then
  echo "DETECTOR BROKEN: only $shaped files matched the suite-ending shape"
  fails=$((fails + 1))
fi

if [ "$fails" -eq 0 ]; then
  echo "listed-suites: $shaped suite-shaped files, all accounted for"
  exit 0
fi
echo "listed-suites: $fails problem(s)"
exit 1
