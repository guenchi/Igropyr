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

# Suites that start child processes read this rather than hardcoding a
# name. Without it they invoke `scheme` while the run itself may be using
# `chez` or $SCHEME_BIN, and the child simply never starts -- which the
# parent reports as whatever it was waiting for timing out, never as a
# missing interpreter.
export SCHEME_BIN="$scheme_bin"

export CHEZSCHEMELIBDIRS=.
# THE OBJECT EXTENSION POINTS AT A SUFFIX THAT DOES NOT EXIST, so a
# stale .so can never answer for a source file. Chez picks by timestamp,
# which is why this has not bitten yet -- every edited source here is
# newer than the objects left in the tree -- but "has not bitten" is not
# a property: an object built after its source, from a tree that has
# since moved, wins and nothing says so. Leaving the object extension
# EMPTY does not do this; it still resolves to .so (measured). Naming an
# extension nothing produces is what excludes them.
export CHEZSCHEMELIBEXTS=.chezscheme.sls::.no-obj:.ss::.no-obj:.sls::.no-obj:.scm::.no-obj:.sch::.no-obj:.sc::.no-obj

# A RUN THAT STOPPED EARLY MUST NOT READ LIKE A RUN THAT PASSED. set -e
# is deliberate -- the suites are serial and expensive, and the first red
# decides the round -- but its cost is that everything after the failure
# is never executed, and "never executed" leaves exactly the same trace as
# "executed and silent": nothing. A run that died in the middle has been
# quoted as a whole-suite result more than once, and the suites it never
# reached were counted as fine. This banner is the only thing standing
# between those two readings.
trap 'st=$?; if [ "$st" -ne 0 ]; then
  echo ""
  echo "=== PARTIAL RUN: STOPPED AT THE SUITE ABOVE (exit $st) ==="
  echo "=== The suites after it were NOT RUN. This is not a whole-suite"
  echo "=== result and must not be reported as one."
fi' EXIT

"$scheme_bin" --script igropyr/test/import-all.sc
# the names applications import, each named ONE BY ONE: a rename that
# rewrites a substring inside them moves every use with every definition,
# so nothing else in the suite would notice
"$scheme_bin" --script igropyr/test/public-names.sc
# the status vocabulary must stay importable without the runtime: its own
# process, so what it loads is observable at all
"$scheme_bin" --script igropyr/test/conv-status.sc
# the durable write is a SEQUENCE, and a sequence is the one thing reading
# the file back cannot check: leave the directory flush out and every
# read-after-write still passes. So this asserts the order of the calls,
# and says nothing about whether anything reached the medium -- that is
# not observable from inside this process.
"$scheme_bin" --script igropyr/test/durable.sc
IGROPYR_CONTRACTS=full "$scheme_bin" --script igropyr/test/checked-full.sc
env -u IGROPYR_CONTRACTS "$scheme_bin" --script igropyr/test/checked-off.sc
"$scheme_bin" --script igropyr/test/smoke-actor.sc
"$scheme_bin" --script igropyr/test/file-read.sc
# the async write bindings are judged by what runs BESIDE the write: a
# green process must keep ticking while an 8 MiB write sits on the pool
# thread. Wrapping a synchronous call in the async API scores zero there.
"$scheme_bin" --script igropyr/test/libuv-fs-write.sc
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
# every byte in must come back out, checked against the system gzip(1)
# tool in a separate process. Also the regression for zlib coexistence:
# with the runtime's embedded zlib and a dlopened libz sharing one
# process, deflate() faults or emits unbounded output with no error
# code, so this script surviving is part of the check
"$scheme_bin" --script igropyr/test/gzip.sc
# a compression killed between its allocations and its winder must still
# give the memory back. Separate from gzip.sc because that file is shared
# with the standalone gzip repository and may import nothing but the
# library itself; this one needs a scheduler to do the killing. Takes
# about ten seconds: the discriminating part is a sweep over slice
# lengths, since a kill aimed by wall-clock never lands in the window
"$scheme_bin" --script igropyr/test/gzip-reclaim.sc
"$scheme_bin" --script igropyr/test/sigv4.sc
"$scheme_bin" --script igropyr/test/blas.sc
"$scheme_bin" --script igropyr/test/quickjs.sc
# separate process: bind! resolves the library once per process, so the
# refusal cannot be tested after a successful boot in the same one
"$scheme_bin" --script igropyr/test/quickjs-require-ng.sc
# with BOTH upstream builds on the loader path, the ng one must be chosen:
# picking bellard fails the boot, and falling through would mix two ABIs
"$scheme_bin" --script igropyr/test/quickjs-so-order.sc
"$scheme_bin" --script igropyr/test/ssr.sc
# the render protocol against fake workers: needs no libquickjs, so unlike
# the test below it runs on every host, and it is where the wire's failure
# modes live (dribbled, oversized, silent, truncated, unsolicited)
"$scheme_bin" --script igropyr/test/qjspool-wire.sc
# single-flight sequences that only became constructible once renders left
# the process: a leader caught mid-render, invalidated under, or killed
"$scheme_bin" --script igropyr/test/ssr-flight.sc
# spawns real worker PROCESSES: the point of the library is that a render
# which never returns cannot stop this scheduler, and that is only provable
# with the engine on the other side of a socket
"$scheme_bin" --script igropyr/test/qjspool.sc
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
# five ways a stream can be abandoned (a raise after res-begin!, a producer
# that crashes / forgets res-end! / is killed, a timed-out write): each must
# end the request, or the reader waits in await-streaming forever
"$scheme_bin" --script igropyr/test/stream-abandoned.sc
# static/send-file! hardening (dotfiles, NUL, root) and HEAD framing
"$scheme_bin" --script igropyr/test/serving-hardening.sc
# cookie attribute injection, HTTP/1.0 framing, slowloris deadline
"$scheme_bin" --script igropyr/test/protocol-hardening.sc
# a newline in the string handed to sse-send! must not become an SSE FIELD
"$scheme_bin" --script igropyr/test/sse-framing.sc
# the whole-request deadline must span head AND body, not restart between
"$scheme_bin" --script igropyr/test/request-deadline.sc
"$scheme_bin" --script igropyr/test/http-client-stream.sc
# connection reuse, counted at the SERVER (accepts vs requests served),
# plus the cases that must NOT be pooled and the stale-handout retry
"$scheme_bin" --script igropyr/test/http-client-keepalive.sc
# reported client defects: repeated Connection fields, unknown versions,
# bodyless non-idempotent replay, a streaming idle clock that measured
# bytes rather than progress, and a caller that dies mid-stream
"$scheme_bin" --script igropyr/test/http-client-hardening.sc
# a chunked response is not complete until its trailer section terminates:
# declaring done at the 0 line accepted a truncated body as a success
"$scheme_bin" --script igropyr/test/chunked-truncation.sc
# a slow on-chunk handler must slow the SERVER: without stopping reads the
# event loop fills an unbounded mailbox with raw bytes no limit applies to
"$scheme_bin" --script igropyr/test/client-read-backpressure.sc
"$scheme_bin" --script igropyr/test/ws-client-handshake.sc
"$scheme_bin" --script igropyr/test/http-protocol.sc
# RESP parsing, both against a fake server so neither needs a live redis:
# the same value at every split offset, and a fragmented reply parsed in
# linear rather than quadratic time
"$scheme_bin" --script igropyr/test/redis-splits.sc
"$scheme_bin" --script igropyr/test/redis-incremental.sc
# ceilings on what a reply may cost, each case lowering the one it tests
"$scheme_bin" --script igropyr/test/redis-limits.sc
# a bad command argument must be refused in the CALLER; encoding it inside
# the connection actor killed a connection shared by the whole application
"$scheme_bin" --script igropyr/test/redis-bad-arg.sc
# a file stream whose owner changes must still be reclaimed: the owner
# INDEX is what teardown consults, and moving only the field leaked the fd
"$scheme_bin" --script igropyr/test/fs-owner-transfer.sc
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
# rolling-upgrade, against a REAL old node: a worktree of the pre-wide
# protocol revision runs node b from source while node a runs this tree.
# Covers the narrow-reply branch a positive ref lands in -- a branch no
# all-new mesh ever takes. Skips (and says so) without full git history
"$scheme_bin" --script igropyr/test/conv-mixed.sc
# admission is judged by the PAIR (what came back, how fast): a refusal
# that takes as long as the silence it replaces refuses nothing. Also the
# only rig that can kill the router with live workers in flight, which is
# what proved the slot accounting survives the router that took the slots
"$scheme_bin" --script igropyr/test/conv-admission.sc
# what a PRE-refusal asker experiences against a refusing owner, run
# against the real pinned old code: full ttl then 'unreachable (its own
# vocabulary), and the token untouched. Skips (and says so) without
# full git history
"$scheme_bin" --script igropyr/test/conv-mixed-overload.sc
"$scheme_bin" --script igropyr/test/tls.sc
"$scheme_bin" --script igropyr/test/apple-jws.sc
# needs the openssl CLI to mint its ephemeral RSA keys, same as tls.sc above
"$scheme_bin" --script igropyr/test/jwks.sc
# pbkdf2/scrypt always run; the argon2id derivations self-skip (naming what
# is missing) on a libcrypto older than OpenSSL 3.2, which is what Debian 12
# and Ubuntu 22.04 ship. The argon2id guard tests still run there.
"$scheme_bin" --script igropyr/test/kdf.sc
# RSA-SHA256 against the RFC 7515 A.2 published signature (always runs) and
# against the openssl CLI in both directions, byte for byte -- the CLI part
# mints throwaway keys in /tmp and self-skips, naming what is missing, where
# openssl is absent
"$scheme_bin" --script igropyr/test/rsa.sc
# AES-256-GCM against the published AES-256 GCM test vectors (always runs)
# and against a second implementation in another process (python3's
# cryptography, or node), which self-skips naming both
"$scheme_bin" --script igropyr/test/aead.sc
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
"$scheme_bin" --script igropyr/test/connpool-lifecycle.sc
# a connection worker that dies BEFORE reporting pool-up is in none of the
# pool's tables; its DOWN used to match no branch and the slot was lost
"$scheme_bin" --script igropyr/test/connpool-connect-death.sc
# pool statistics: every number checked against a situation the test
# constructs (saturation, a timed statement, a lease waited on, both
# timeout paths), not merely read back
"$scheme_bin" --script igropyr/test/connpool-stats.sc
# mysql option validation (no server needed, always runs)
"$scheme_bin" --script igropyr/test/mysql-opts.sc
# mysql-observe! and mysql-query share one cfg object (no server needed,
# always runs): the engine is covered elsewhere against fake cfgs; only
# driving the real driver cfg can see an install that wrote into a copy
"$scheme_bin" --script igropyr/test/mysql-observe.sc
# mysql wire-level, against an in-process fake server (always runs): the
# handshake, a result set reassembled across 256 fragment boundaries, and
# refusal of a packet the 24-bit length field cannot describe
"$scheme_bin" --script igropyr/test/mysql-wire.sc
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

# reached only when every suite above ran and passed
echo "=== WHOLE SUITE RUN: every suite was reached ==="

