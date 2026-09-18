#!/bin/sh
# Every test/*.sc is either named in run-all.sh or excluded here with a reason.
#
# WHY THE OBLIGATION IS THIS WIDE. run-all.sh names its suites one line at a
# time rather than globbing, which is right -- they need different environments
# and some must not run at all -- but it means a suite nobody adds a line for is
# silently never executed. That has happened: three cells were written,
# committed, and never ran.
#
# AN EARLIER VERSION OF THIS FILE ASKED A NARROWER QUESTION AND WAS WRONG. It
# only demanded a line for files that END LIKE A SUITE -- grep for the pass
# line -- and reported "149 suite-shaped files, all accounted for". Measured:
# 19 listed suites do not match that shape, among them import-all (prints ALL
# LIBRARIES IMPORTED) and public-names (prints public names: all present).
# Deleting either from run-all.sh would not have reddened anything. The
# criterion was "is this a suite", the evidence was a string at the end of the
# file, and those are not the same question -- so the detector is gone rather
# than widened. Widening it is one more guess at how the next suite will end.
#
# WHAT IT STILL DOES NOT CATCH, said plainly so this is not mistaken for more: a
# suite that IS listed but has lost a section. A file can be named, run, print
# its pass line and cover half of what it used to. Different hole, different
# instrument.
#
# A STALE EXCLUSION IS ALSO AN ERROR. A file excluded here that HAS since been
# added to run-all.sh means its reason no longer holds. The exception list is a
# structure built to stop silent decay, and it decays the same way if nothing
# watches it.
set -eu
cd "$(cd "$(dirname "$0")/.." && pwd)"

# name|why it is not in run-all.sh. Every reason below was checked by reading
# the file or by finding who references it, not assumed from the name.
# bash 3.2 mis-parses a here-document inside $( ), so this is a plain
# single-quoted string; that is also why no reason below contains an
# apostrophe.
EXCLUSIONS='cluster-child|child process, spawned by cluster.sc and the conv-cluster suites
conv-admission-child|child process, spawned by conv-admission.sc
conv-census-child|child process, spawned by conv-census.sc and conv-record.sc
conv-cluster-child|child process, spawned by conv-cluster.sc
conv-mixed-child|child process, spawned by conv-mixed.sc
conv-mixed-overload-child|child process, spawned by conv-mixed-overload.sc
dpool-child|child process, spawned by dpool.sc
node-child|child process, spawned by a dozen suites including node.sc and barrier.sc
node-listener-child|child process, spawned by registrar-supervision.sc
mesh-proof|shared fixture, imported by the tls-mesh suites and plain-peer.sc
json-number-oracles|shared fixture, imported by the json writer and number suites
soak-load|soak driver, run by hand; long-running by design
soak-mesh|soak driver, run by hand; long-running by design
soak-pair|soak driver, run by hand; long-running by design
jbench|microbenchmark; its own header says timing assertions flake and a flaky red teaches people to ignore red
quickjs-bench|benchmark backing the manual per-call overhead table; a measurement, not a pass/fail run
run-otp|demo server, run by hand with ulimit and an external load generator
smoke-echo|demo server, runs until interrupted
smoke-echo-actor|demo server, runs until interrupted
write-block-window|cells for a mechanism that is not implemented; listing it would be a red nobody asked for'

listed() { grep -q "test/$1\.sc" test/run-all.sh; }
# awk, not a read loop: under set -e a loop whose last iteration ends in a
# false test exits non-zero, the command substitution inherits it, and the
# script dies with no output at all -- which is what the first version did.
reason_for() { printf '%s\n' "$EXCLUSIONS" | awk -F'|' -v n="$1" '$1 == n { print $2 }'; }

fails=0
scanned=0
for f in test/*.sc; do
  b=$(basename "$f" .sc)
  scanned=$((scanned + 1))
  r=$(reason_for "$b")
  if listed "$b"; then
    if [ -n "$r" ]; then
      echo "STALE EXCLUSION: $b is named in run-all.sh; drop its line from EXCLUSIONS"
      fails=$((fails + 1))
    fi
  elif [ -z "$r" ]; then
    echo "NEVER RUN: $b is not named in run-all.sh and has no reason in EXCLUSIONS"
    fails=$((fails + 1))
  fi
done

# THE CONTROLS. Both failures this script can have are silent ones: a glob that
# matched nothing, and a listed() that answers yes to everything. Either would
# print no findings and read as a clean run.
if [ "$scanned" -lt 100 ]; then
  echo "CONTROL FAILED: only $scanned files scanned; the glob is wrong"
  fails=$((fails + 1))
fi
if listed "definitely-not-a-suite-name-xyzzy"; then
  echo "CONTROL FAILED: listed() answers yes for a name that cannot be there"
  fails=$((fails + 1))
fi

if [ "$fails" -eq 0 ]; then
  echo "listed-suites: $scanned files, every one listed or excluded with a reason"
  exit 0
fi
echo "listed-suites: $fails problem(s)"
exit 1
