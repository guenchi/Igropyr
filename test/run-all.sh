#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [[ -n "${SCHEME_BIN:-}" ]]; then
  scheme_bin="$SCHEME_BIN"
elif command -v chez >/dev/null 2>&1; then
  scheme_bin=chez
else
  scheme_bin=scheme
fi

export CHEZSCHEMELIBDIRS=.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so

"$scheme_bin" --script igropyr/test/import-all.sc
"$scheme_bin" --script igropyr/test/smoke-actor.sc
"$scheme_bin" --script igropyr/test/file-read.sc
"$scheme_bin" --script igropyr/test/http-protocol.sc

set +e
boot_output=$("$scheme_bin" --script igropyr/test/smoke-boot-failure.sc 2>&1)
boot_status=$?
set -e
if [[ $boot_status -ne 70 || "$boot_output" != *"PANIC: boot"* ||
      "$boot_output" != *"deliberate boot failure"* ]]; then
  printf '%s\n' "$boot_output"
  echo "boot failure propagation test failed" >&2
  exit 1
fi
echo "BOOT FAILURE PROPAGATION PASSED"

