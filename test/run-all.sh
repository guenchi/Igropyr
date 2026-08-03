#!/bin/sh
# POSIX sh, no bashisms: FreeBSD (a deployment target) has no bash in
# the base system, and the suite must run where the code runs.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [ -n "${SCHEME_BIN:-}" ]; then
  scheme_bin="$SCHEME_BIN"
elif command -v chez >/dev/null 2>&1; then
  scheme_bin=chez
else
  scheme_bin=scheme
fi

export CHEZSCHEMELIBDIRS=.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so

"$scheme_bin" --script igropyr/test/import-all.sc
IGROPYR_CONTRACTS=full "$scheme_bin" --script igropyr/test/checked-full.sc
env -u IGROPYR_CONTRACTS "$scheme_bin" --script igropyr/test/checked-off.sc
"$scheme_bin" --script igropyr/test/smoke-actor.sc
"$scheme_bin" --script igropyr/test/file-read.sc
"$scheme_bin" --script igropyr/test/crypto.sc
"$scheme_bin" --script igropyr/test/sexpr.sc
"$scheme_bin" --script igropyr/test/sexpr-http.sc
"$scheme_bin" --script igropyr/test/sexpr-ws.sc
"$scheme_bin" --script igropyr/test/jwt.sc
# a hostile JSON number: what it may cost (an unbounded digit run went to
# string->number and froze the scheduler for seconds) and what it may claim
# (an out-of-range exponent became +inf.0, which passes any real? guard --
# including the one on a JWT expiry)
"$scheme_bin" --script igropyr/test/json-numbers.sc
"$scheme_bin" --script igropyr/test/sigv4.sc
"$scheme_bin" --script igropyr/test/blas.sc
"$scheme_bin" --script igropyr/test/quickjs.sc
# separate process: bind! resolves the library once per process, so the
# refusal cannot be tested after a successful boot in the same one
"$scheme_bin" --script igropyr/test/quickjs-require-ng.sc
"$scheme_bin" --script igropyr/test/ssr.sc
"$scheme_bin" --script igropyr/test/s3.sc
"$scheme_bin" --script igropyr/test/aws.sc
"$scheme_bin" --script igropyr/test/s3-control.sc
"$scheme_bin" --script igropyr/test/metrics.sc
"$scheme_bin" --script igropyr/test/dashboard.sc
"$scheme_bin" --script igropyr/test/auth.sc
"$scheme_bin" --script igropyr/test/ws-client-request.sc
# session id rotation: the header-publication contract (no timing), and the
# race it exists to survive (a concurrent responder claiming the same token)
"$scheme_bin" --script igropyr/test/response-header-claim.sc
"$scheme_bin" --script igropyr/test/session-rotation-race.sc
"$scheme_bin" --script igropyr/test/express-routes.sc
# path normalization: middleware guards and the router must agree on the
# path, or an extra slash routes to a handler while skipping its guard
"$scheme_bin" --script igropyr/test/path-normalization.sc
# a handler crashing after it began streaming must close the connection,
# not leave the reader parked forever on a leaked fd
"$scheme_bin" --script igropyr/test/stream-crash.sc
# a chunked producer must run at the client's pace, not queue unboundedly
"$scheme_bin" --script igropyr/test/stream-backpressure.sc
# ...and that wait must be bounded: a detached stream is not a pool
# worker, so stuck-ms never covered the peer that stops reading
"$scheme_bin" --script igropyr/test/stream-write-timeout.sc
# static/send-file! hardening (dotfiles, NUL, root) and HEAD framing
"$scheme_bin" --script igropyr/test/serving-hardening.sc
# cookie attribute injection, HTTP/1.0 framing, slowloris deadline
"$scheme_bin" --script igropyr/test/protocol-hardening.sc
# a newline in the string handed to sse-send! must not become an SSE FIELD
"$scheme_bin" --script igropyr/test/sse-framing.sc
# the whole-request deadline must span head AND body, not restart between
"$scheme_bin" --script igropyr/test/request-deadline.sc
"$scheme_bin" --script igropyr/test/http-client-stream.sc
"$scheme_bin" --script igropyr/test/ws-client-handshake.sc
"$scheme_bin" --script igropyr/test/http-protocol.sc
# RESP parsing, both against a fake server so neither needs a live redis:
# the same value at every split offset, and a fragmented reply parsed in
# linear rather than quadratic time
"$scheme_bin" --script igropyr/test/redis-splits.sc
"$scheme_bin" --script igropyr/test/redis-incremental.sc
# ceilings on what a reply may cost, each case lowering the one it tests
"$scheme_bin" --script igropyr/test/redis-limits.sc
"$scheme_bin" --script igropyr/test/static-stream.sc
"$scheme_bin" --script igropyr/test/static-cache-capacity.sc
# one file must be one cache entry: self-skips on a case-sensitive
# filesystem (naming why), where there are no variant spellings to collapse
"$scheme_bin" --script igropyr/test/static-cache-key.sc
"$scheme_bin" --script igropyr/test/node.sc
# worker slot accounting: a killed or stuck task must not hold its slot
"$scheme_bin" --script igropyr/test/dpool-slots.sc
"$scheme_bin" --script igropyr/test/dpool.sc
"$scheme_bin" --script igropyr/test/cluster.sc
"$scheme_bin" --script igropyr/test/fault-hook.sc
"$scheme_bin" --script igropyr/test/conversation.sc
"$scheme_bin" --script igropyr/test/conv-cluster.sc
"$scheme_bin" --script igropyr/test/tls.sc
"$scheme_bin" --script igropyr/test/apple-jws.sc
# needs the openssl CLI to mint its ephemeral RSA keys, same as tls.sc above
"$scheme_bin" --script igropyr/test/jwks.sc
# pbkdf2/scrypt always run; the argon2id derivations self-skip (naming what
# is missing) on a libcrypto older than OpenSSL 3.2, which is what Debian 12
# and Ubuntu 22.04 ship. The argon2id guard tests still run there.
"$scheme_bin" --script igropyr/test/kdf.sc
# a gen-server must not run a call whose caller was killed while it
# waited: the effects would be applied for nobody, and the retry
# applies them again
"$scheme_bin" --script igropyr/test/gen-server-dead-caller.sc
# pool settings must be refused at startup: every bad value here fails
# silently at runtime (0 workers = queue forever, negative check-ms =
# no stuck detection, bad pool size = unbounded connect loop)
"$scheme_bin" --script igropyr/test/pool-config.sc
# pool bookkeeping against fake connection workers (no server needed):
# a caller that dies or times out WHILE QUEUED must cost neither a
# healthy connection nor a later, unwanted execution
"$scheme_bin" --script igropyr/test/sqlpool-lifecycle.sc
# a connection worker that dies BEFORE reporting db-up is in none of the
# pool's tables; its DOWN used to match no branch and the slot was lost
"$scheme_bin" --script igropyr/test/sqlpool-connect-death.sc
# mysql option validation (no server needed, always runs)
"$scheme_bin" --script igropyr/test/mysql-opts.sc
# opt-in (needs a live MySQL): runs for real only when IGROPYR_MYSQL_TEST is
# set, otherwise self-skips, so this is a no-op on machines without a database.
"$scheme_bin" --script igropyr/test/mysql.sc
# SCRAM-SHA-256 (igropyr postgresql) against the RFC 7677 vectors -- pure
# crypto, no server needed, so it always runs.
"$scheme_bin" --script igropyr/test/postgresql.sc
# wire-level tests against an in-process fake server (loopback only, always
# runs): SCRAM verified server-side, auth failure fd-leak regression,
# cleartext opt-in gate, framing hardening, COPY refusal.
"$scheme_bin" --script igropyr/test/postgresql-wire.sc
# opt-in (needs a live PostgreSQL): runs for real only when IGROPYR_PG_TEST is
# set, otherwise self-skips, so this is a no-op on machines without a database.
"$scheme_bin" --script igropyr/test/postgresql-e2e.sc

set +e
badenv_output=$(IGROPYR_CONTRACTS=on "$scheme_bin" --script igropyr/test/checked-badenv.sc 2>&1)
badenv_status=$?
set -e
case "$badenv_output" in
  *IGROPYR_CONTRACTS*) badenv_msg=1 ;;
  *)                   badenv_msg=0 ;;
esac
if [ "$badenv_status" -eq 0 ] || [ "$badenv_msg" -eq 0 ]; then
  printf '%s\n' "$badenv_output"
  echo "checked bad-env rejection test failed" >&2
  exit 1
fi
echo "CHECKED BAD-ENV REJECTION PASSED"

set +e
boot_output=$("$scheme_bin" --script igropyr/test/smoke-boot-failure.sc 2>&1)
boot_status=$?
set -e
case "$boot_output" in
  *"PANIC: boot"*) boot_panic=1 ;;
  *)               boot_panic=0 ;;
esac
case "$boot_output" in
  *"deliberate boot failure"*) boot_msg=1 ;;
  *)                           boot_msg=0 ;;
esac
if [ "$boot_status" -ne 70 ] || [ "$boot_panic" -eq 0 ] || [ "$boot_msg" -eq 0 ]; then
  printf '%s\n' "$boot_output"
  echo "boot failure propagation test failed" >&2
  exit 1
fi
echo "BOOT FAILURE PROPAGATION PASSED"

