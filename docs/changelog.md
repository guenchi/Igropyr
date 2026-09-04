# Changelog

## 1.5.2 — 2026-09-04

*140 commits.* Wire protocol v4 and the accounting behind hosted monitors; then
server-side TLS, and a libuv layer split in two.

### API

Five new libraries: `(igropyr tcp)` — the connection and owner layer, split out
of `(igropyr libuv)`; `(igropyr tls-core)` — TLS sessions and contexts, the only
place OpenSSL is called; `(igropyr tls-watch)` — the per-connection watcher;
`(igropyr inject)` and `(igropyr inject-control)` — fault injection for the test
suite, compiled out unless `IGROPYR_INJECT=on`.

`(igropyr node)` gains `monitor-node/token`, `demonitor-node/token`,
`node-install-rule-order`, `node-orphan-count`, `node-dead-letters`,
`node-dead-letter-stats`, `node-redeliver-dead-letter!` and the
`quarantine-reason` accessors; `(igropyr http)` gains `http-server-ready?`,
`http-server-backlog` and `http-server-backlog-effective`; `(igropyr libuv)`
gains `uv-live-handle-count` and `uv-owner-index-count`.
**Curated: 17 added, none removed** — but see **Breaking** for 38 names that
moved library.

⚠️ `(igropyr libuv)` also exports about 85 raw libuv bindings — `uv-fs-open`,
`uv-write`, `memcpy-cc`, the `*-size` constants and their kin — which were
internal to that file before the split. They are the **low-level face of the
binding layer and are not stable API**: they exist because the layer is now a
library of its own, and they may be narrowed without a major version. The stable
surface is `(igropyr tcp)` and everything above it.

### Breaking

- **`(igropyr libuv)` is now only the libuv binding layer.** The connection and
  owner layer moved to the new `(igropyr tcp)`: 38 names left `(igropyr libuv)`,
  among them `tcp-listen!`, `tcp-connect!`, `tcp-close!`, `tcp-read-start!`,
  `tcp-write!`, `tcp-writev!`, `tcp-write-foreign!`, `dns-resolve!`,
  `file-read-async!`, `file-realpath`, the `file-stream-*` family, the
  `fs-*-async!` family, `fs-count`, `fs-fd-count`, `fs-job-count`, the `conn`
  record accessors (`conn?`, `conn-handle`, `conn-owner`, `conn-set-owner!`,
  `conn-peer-ip`, `conn-state`, `conn-on-close!`, `conn-count`),
  `uv-owner-died!` and `uv-set-deliver!`.

  **Migration.** A file that took any of those from `(igropyr libuv)` must now
  import `(igropyr tcp)` as well:

  ```scheme
  (import (igropyr libuv) (igropyr tcp))
  ```

  Code that used only binding-layer names — `now-ms`, `uv-init!`, `uv-poll!`,
  `uv-live-handle-count` and the like — needs no change. The two libraries
  export disjoint sets, so importing both is always safe.

### Added

- **node**: wire protocol v4 — boot ids, dial generations, target-bound proofs.
  Dial decisions are installed as an ordered rule table and carried out one
  process per attempt, with a registrar issuing the permission to dial and
  ordering endpoint changes against disconnects.
- **node**: topology subscriptions can carry a token, and events carry a
  sequence number. Deduplication is within a variant and not across them, so
  ending a legacy subscription cannot end a token one.
- **dpool**: subscribes with a token and drops what it has already seen.
- **http, tls**: **HTTPS server.** `http-listen` accepts `tls-cert` and
  `tls-key` (both or neither); the connection layer carries the TLS codec, and
  every OpenSSL call is confined to `(igropyr tls-core)`. Each TLS connection
  gets a watcher process that owns the write gate and the connection's timers.
  A write gate serialises whole aggregates, so two writers cannot interleave
  their records.
- **node**: **dead letters.** An event that fails delivery three times is
  quarantined instead of taking the node down; `node-dead-letters`,
  `node-dead-letter-stats` and `node-redeliver-dead-letter!` read and replay
  them, an observer is told through an `event-quarantined` notice, and the
  reason is a record (`quarantine-reason-kind`, `quarantine-reason-payload`)
  rather than a bare symbol.
- **tcp**: `stat`, `unlink` and `scandir` run on the thread pool
  (`file-stat-async!`, `file-unlink-async!`, `file-scandir-async!`).
- **http**: the listen backlog is an option with a default, and both the asked
  and the granted value read back; readiness asks the listener and the pool, and
  shutdown survives a dead pool.
- **inject**: fault injection for the test suite, switched at expansion time and
  compiled out entirely unless `IGROPYR_INJECT=on`. Fault, return, override and
  barrier points; a barrier parks a process between two expressions so a test
  can act in a window that is otherwise too short to reach.

### Fixed

- **node**: hosted-monitor accounting — the hosting ceiling counts what holds a
  process, arming is idempotent, a reaper returns credits and is found by name
  so it can be replaced, and a warden backs off, counts, and eventually gives up.
- **node**: admission slots know their holder, come back when the holder dies,
  and an install that stops half way undoes itself.
- **libuv**: a connect or listen that fails partway releases what it took; a DNS
  request retires its owner-index entry on both exits.
- **tls**: **a clean close now drains before the handle closes.** Closing a TLS
  connection submitted the alert and retired in the next expression — and
  retirement calls `uv_close`, which cancels every queued write request on the
  handle. A connection with application ciphertext still queued lost all of it
  along with the `close_notify`, and the peer saw a truncated stream. The
  connection is now retired by the alert's own completion or by an idle bound
  that only successful completions extend. Nothing reported the old behaviour,
  because cancelled requests still run their completions and still refund.
- **tls**: the gate's open-and-drain decides "the buffer is empty" and opens the
  gate in one region. Split across two, a read callback could append plaintext
  in between; the drain runs once, so those bytes were stranded for the life of
  the connection.
- **node**: the death-log renderer caps format-directive parameters. A message
  carrying `~50000000a` allocated 572 MB before anything could trim it;
  parameters above 4096, and argument-supplied `~v` parameters, now fall back to
  printing the message literally with its irritants.
- **node**: the death-log renderer pins every print parameter that changes what
  it writes.
- **tcp**: `fs-start-fd!` owns its descriptor from its first instruction.
- **node**: the registrar is supervised, and what it was asked to do survives
  its death.

### Changed

- **actor**: interrupt regions unwind; about 5% on send and receive.
- **build**: one library list, compared against the directory.
- **imports**: every library names what it takes from `(igropyr libuv)` and
  `(igropyr tcp)`, so an import list is now the dependency rather than a
  starting point for one.
- **http, libuv**: the reuseport option says which platforms it works on, and
  FreeBSD is one of them.
- **comments**: the emoji markers are gone from the source.

---

## 1.5.1 — 2026-08-29

*24 commits.* The node handshake, and what a link does when a frame cannot go.

### API

`(igropyr actor)` gains `critical!`, `uncritical!` and `process-monitor-count`;
`(igropyr http)` gains `http-server-sup` and `http-server-pool-alive?`;
`(igropyr node)` gains `node-outbound-stats`, `reconnect-delay` and
`submission-failure?`. **8 added, none removed.**

### Added

- **otp**: crash-only completion for the worker pool, and a critical-component
  mark, so a listener can decline the critical mark it would otherwise inherit.

### Fixed

- **node**: the handshake is versioned, and a proof-forgery collision is closed.
  The documentation said HMAC-SHA1; the code has always been HMAC-SHA256.
- **node**: backpressure closeouts. A refused submission answers as no link; a
  control frame that cannot go means the link goes; a DOWN that cannot be spoken
  costs the link on every path; link state — not report shape — tells a dead link
  from a refused frame. The backoff threshold is seeded with the pair's real
  first delay.
- **sigv4, http**: header names are gated at the call.

### Changed

- A generational-failover batch for node and dpool was written, reviewed, and
  **reverted before release**; five corrected comments from it were kept.

---

## 1.5.0 — 2026-08-27

*8 commits.* One spelling per JSON shape.

### API

`(igropyr json)` gains the accessors and updaters `json-ref*`, `json-set`,
`json-set*`, `json-update`, `json-update*`, `json-insert`, `json-insert*`,
`json-push`, `json-push*`, `json-drop`, `json-drop*`, and the predicates
`json-null?`, `json-array?`, `json-object?`. `(igropyr http)` gains
`http-stats-json`. New library `(igropyr json-internal)` — `json-number-text?`,
`number-text`, `before-precision-tag`, `repair-precision-tag` — the grammar the
writer is judged against. **19 added, none removed.**

### Breaking

- **The JSON writer accepts one spelling per shape.** Arrays are vectors; object
  keys and values are strings. A plain list is refused instead of being written
  as an array, with a message naming `list->vector`. This removes the ambiguity
  family around values that could be read as either an array or an object, and it
  lets the new `json-` operations address everything the writer accepts.

### Fixed

- **json**: every numeral the writer emits is validated against the JSON grammar
  by an independent internal library, so the writer cannot emit what the reader
  would refuse. The reader's cap is the writer's only bound, and now says so.

---

## 1.3.3 — 2026-08-22

*13 commits.* No API change. The JSON reader's acceptance surface.

### Fixed

- **json**: a digit is required on both sides of the decimal point.

### Changed

- The reader's acceptance surface is pinned row by row, each row carrying the
  RFC text that decides it, with the should-be-green half enumerated across the
  grammar.

---

## 1.3.2 — 2026-08-21

*73 commits.* Session identity, the s-expression symbol corpus, and a
documentation truth pass.

### API

`(igropyr express)` gains `app-route-list`, a read-only projection of what got
registered; `(igropyr durable-async)` gains `durable-fsync-dir-async!`.
**2 added, none removed.**

### Fixed

- **session**: `secure` may be a predicate, because one process can serve two
  schemes. Clearing a session ends its identity, not only its data; logging out
  retires the identifier.
- **express**: replacing a handler no longer moves its route.
- **sexpr**: the writer asks what the reader will do with a name, and will not
  emit a token the reader must refuse. Pinned by a symbol corpus driven from a
  vendored conformance fixture (190 names, later 1593).
- **gen-server**: the error slot holds a printable scalar — the output is
  bounded, a label is built rather than the value printed, and clipping happens
  before framing.
- **connpool**: a stats timeout raises a shape carrying the pool's id, not a
  bare symbol.
- **durable-async**: the directory flush refuses a non-directory.

### Changed

- A documentation truth pass across README, quickjs, gzip and platform: claims
  that described deleted machinery, install guidance left half-behind, and counts
  that had drifted were corrected at every site rather than at the one a reviewer
  named.

---

## 1.3.1 — 2026-08-19

*13 commits.* The durable write, off the scheduler thread.

### API

New library `(igropyr durable-async)` — `durable-write-file-async!`,
`durable-dir-ensure-async!`, and the `durable-error?` accessors.
`(igropyr libuv)` gains `fs-mkdir-async!`, `fs-o-cloexec` and `fs-o-directory`;
`(igropyr durable)` gains `fs-trace-step`. **9 added, none removed.**

### Added

- **durable-async**: the same atomic-write sequence as `(igropyr durable)`, run
  off the scheduler thread, with the failure paths its contract had quietly been
  missing.
- **durable**: exports the traced step, so a second implementation shares one
  trace and one set of op names.

### Fixed

- **libuv**: a descriptor is closed after the last job that names it, never
  before, and a descriptor number is treated as a lease — identity is the number
  *and* a generation.

---

## 1.3.0 — 2026-08-18

*50 commits.* The libuv write side, and admission control for conversations.

### API

`(igropyr libuv)` gains the asynchronous write side — `fs-open-async!`,
`fs-write-async!`, `fs-rename-async!`, `fs-fsync-async!`, `fs-close-async!`,
`fs-fd-count`, `fs-job-count` and the `fs-o-*` flags. `(igropyr conversation)`
gains `conversation-census`, `conversation-quiesce!`, `conversation-quiescing?`,
`conversation-overloaded?`, `conversation-forward-stats`,
`conversation-record-hooks!`, `conv-set-forward-limit!` and
`conv-set-forward-hold-ms!`. **21 added, none removed.**

### Added

- **libuv**: an asynchronous filesystem write side — open, write, rename, fsync,
  close, one syscall per job, off the scheduler thread — with the open flags
  exported and a read port for held descriptors.
- **conversation**: census and quiesce, both node-local, counting a conversation
  at admission rather than when it first runs. Outcome records may outlive the
  process without being persisted, and the forwarding deadline is per call.

### Fixed

- **conversation**: hosted forwards are capped and refused promptly instead of
  silently; a forward may not hold its slot indefinitely; an abandoned wait gives
  its slot back while the work survives.
- **qjspool**: failure kinds are decided by position — a render that never
  reached the wire keeps its connection.

---

## 1.2.9 — 2026-08-18

*60 commits.* The commit witness, and a test suite that stops overclaiming.

### API

New libraries `(igropyr durable)` — `durable-write-file!`,
`durable-dir-ensure!`, `with-fs-trace`, `fs-trace-hook-set!` and the
`durable-error?` accessors — and `(igropyr conv-status)`, the status predicates
on their own, askable without the runtime that answers them.
`(igropyr conversation)` gains `conversation-prepare!`, `conversation-run!`,
`conversation-abandon!`, `conversation-peek/timeout`, `conversation-ref-id`,
`conversation-unreachable?`, `conversation-no-answer-yet?` and
`conversation-hook-stats`; `(igropyr connpool)` gains
`connpool-cfg-set-observer!` and `connpool-observer-failures`;
`(igropyr mysql)` gains `mysql-observe!`; `(igropyr rsa)` gains
`rsa-key-consistency-checked`. **26 added, none removed.**

### Added

- **durable**: atomic file write with the directory flush the sequence needs.
- **connpool, mysql**: a caller can observe the statements the pool issues itself.

### Fixed

- **conversation**: the commit witness goes through `commit!`, so a post-commit
  failure is never reported as `'gone`; the outcome is remembered so a pruned
  record cannot become a kill; the witness crosses the link; a commit can end in
  *maybe*, and maybe is not a rollback; the `on-killed` hook is supervised, and a
  hook that did not return is not a success.
- **gzip**: hardening of the embedded-zlib binding — probe descriptors are
  close-on-exec and closed on every exit, a libc without `pipe2` is survived,
  there is no descriptor window before the wind, and native buffers are given
  back after the process holding them is killed.
- **crypto, rsa, aead**: key loading and buffer handling hardened; portable
  non-blocking key open; a correct `EVP_PKEY_check` verdict; atomic close-on-exec.
- **tls**: the error queue is cleared before each `SSL_*` call and what OpenSSL
  returns is checked; a closed connection stops the handshake; a broken codec
  stays broken.

---

## 1.2.8 — 2026-08-13

*6 commits.* RSA and AES-256-GCM.

### API

New libraries `(igropyr rsa)` — key loading from PEM or modulus,
`rsa-sign-sha256`, `rsa-verify-sha256`, and the key accessors — and
`(igropyr aead)` — `aes-256-gcm-seal`, `aes-256-gcm-open`, the raw
encrypt/decrypt pair, `aead-random-bytes`, and the size constants.
**21 added, none removed.**

### Fixed

- A verification that could be forged, and a passphrase that was not a refusal.
- **tls**: a dirty error queue turned want-read into a dead connection.
- **gzip**: binds the zlib embedded in the Chez runtime on FreeBSD, instead of a
  second copy from the system.

---

## 1.2.7 — 2026-08-07

*126 commits.* The largest release in the series: conversations, the connection
pool, and the HTTP client were reworked, and a long tail of lifetime and leak
defects closed.

### API

New libraries `(igropyr connpool)` — the pool engine under its right name — and
`(igropyr qjspool)`, QuickJS renders in worker processes.
`(igropyr conversation)` gains `conversation-peek`, `conversation-done?`,
`conversation-settled?`, `conversation-stale?`, `conversation-unknown?` and
`conversation-set-limits!`; `(igropyr http)` gains `http-request-deadline!`,
`http-write-timeout!`, `res-abort!`, `res-spawn!` and `res-streaming?`;
`(igropyr http-client)` gains `http-client-pool!`, `http-client-pool-stats` and
`http-client-close-idle!`; `(igropyr actor)` gains `process-count`;
`(igropyr libuv)` gains `tcp-read-stop!` and `fs-count`;
`(igropyr websocket)` gains `ws-write-timeout!`; the drivers gain
`mysql-pool-stats` and `postgresql-pool-stats`. **39 added, 6 removed.**

### Breaking

- **`(igropyr sqlpool)` is now `(igropyr connpool)`.** It was never about SQL.
  Six public names in mysql and postgresql that the rename ate were restored.
- **A conversation resume must name the reply it is answering.** Step tokens are
  unguessable rather than consecutive, a new token never repeats the one just
  spent, a replay must answer the question that was asked, and a request nobody
  can key replays nothing. Chosen over an optional token deliberately: a default
  that falls back to arrival order leaves the framework wrong for everyone who
  does not opt in.

### Added

- **qjspool**: QuickJS renders run in worker processes, with
  `(engine . <qjspool>)` wiring them into `ssr`; a render borrows its worker with
  its own deadline, a teardown reaches a connection mid-render, leftover bytes
  after a response are a desync rather than the next answer, and a request that
  arrived whole is always answered.
- **http-client**: connections are reused instead of dialled per request, with a
  pool.

### Fixed

- **conversation**: a status vocabulary that says what it means — `'gone` now
  means the flow rolled back and is derived from evidence rather than absence,
  `'unknown` says the rest, an unreachable owner is not a dead one, the TTL is a
  running bound and not merely an idle one, publishing a completion is one
  indivisible act, and there is an `on-killed` hook because TTL expiry does not
  always raise.
- **http**: whole-request deadlines spanning head and body, a write deadline on
  `res-end!`'s terminator, HEAD suppression on the streaming paths, refusal of
  two inbound framings the two ends would read differently, no handler run for a
  client that has gone, and a stream that will never finish ends the request.
- **http-client**: a bounded response head and chunk-size line, a chunked
  response that ends at its trailer rather than at the `0` line, and a slow
  `on-chunk` handler that slows the server rather than memory.
- **libuv**: owned resources are indexed by owner instead of scanning every
  table, and ownership is published atomically.
- Across the tree: rcall pending entries leaking in node; gen-server calls to a
  dead caller and to yourself; dpool surviving an unsendable payload; redis
  paying O(N) per command to enqueue a waiter; a one-byte WebSocket close payload
  treated as an index rather than a protocol error; JSON number tokens unbounded
  and non-finite; an SSE payload newline treated as a field; connection-pool
  workers that died before reporting; result sets materialising without a row cap.

---

## 1.2.6 — 2026-08-03

*21 commits.* No API change. Registry rebinding and protocol validation.

### Fixed

- **actor**: process-registry rebinding; registry aliases are preserved when
  rebinding.
- **websocket, ws-client**: unsafe request headers rejected; client handshakes
  validated.
- **http**: ambiguous response framing rejected; streaming chunk terminators
  validated.
- **jwks**: unknown-kid refreshes are bounded, and cache mutations are serialised.

### Changed

- Documented that `parameterize` gives no per-process isolation.

---

## 1.2.5 — 2026-07-31

*10 commits.* RS256 and JWKS.

### API

New library `(igropyr jwks)` — `jwks-sign`, `jwks-verify`, `jwks-document`,
`jwks-load-key`, `jwks-fetch!`, `jwks-key-id`, `jwks-cache-clear!`.
`(igropyr crypto)` gains `base64url-encode` and `base64url-decode`;
`(igropyr platform)` gains `shared-object-candidates`. **10 added, none removed.**

### Fixed

- Impossible base64url lengths are rejected; Apple JWS uses the shared decoder,
  and KDF the shared OpenSSL candidate list, instead of private copies.

---

## 1.2.3 — 2026-07-31

*87 commits.* A hardening batch, largely from externally contributed and
independently reviewed pull requests, each landing with a test that fails
without it.

### API

`(igropyr express)` gains `static-cache-limits!`, `static-cache-stats` and
`set-cookie-if-unanswered!`; `(igropyr http)` gains `res-answered?` and
`set-header-if-unanswered!`; `(igropyr session)` gains `session-regenerate!`;
`(igropyr libuv)` gains `conn-on-close!`, `file-realpath` and
`file-stream-open-under!`; `(igropyr redis)` gains `redis-set-limits!`;
`(igropyr node)` gains `node-monitor-stats`; `(igropyr websocket)` gains
`ws-valid-client-key?`; `(igropyr blas)` gains `blas-scores-pure!`;
`(igropyr kdf)` gains `kdf-argon2id-available?`. **14 added, none removed.**

### Fixed

- **express**: multipart boundary semantics enforced and held to the ASCII
  grammar; the boundary search made linear with a KMP failure table bound to its
  needle and built once; the static cache gained a capacity ceiling, a byte cap,
  stale eviction, adjustable limits, and a key on the resolved name rather than
  the request.
- **session**: ID regeneration, documented as idempotent; refusal to regenerate
  once the response has gone out; valid rotations preserved on handler failure;
  writes committed after answered failures; no resurrection of a retired ID;
  rotation cookies published atomically.
- **node**: remote monitors released when callers exit; an absolute handshake
  deadline; a cap on handshakes in flight from unauthenticated peers; missing
  self monitors released.
- **libuv, http**: libuv resources reclaimed when owners die; static file opens
  confined beneath their roots; bodies suppressed for bodyless statuses;
  timed-out HTTP request actors cancelled; chunked request metadata bounded;
  client-managed headers rejected.
- **redis**: fragmented RESP replies parsed incrementally, with reply resource
  limits.
- **postgresql**: SCRAM iteration counts capped, derived from a time budget.
- **websocket**: opening handshakes validated; fragmented message frame counts
  capped.
- **auth**: fails closed before session lookup; `session-guard` can require an
  Origin.

---

## 1.2.2 — 2026-07-26

*19 commits.* A whole-codebase review, applied in three passes — security
findings, correctness findings, then the regressions the first two introduced.

### API

`(igropyr http)` gains `req-peer`, `req-version`, `res-head-request?` and
`res-send-head!`; `(igropyr libuv)` gains `conn-peer-ip` and `uv-owner-died!`.
**6 added, none removed.**

### Fixed

- **http**: the request path is normalised so every layer agrees on it; a
  streaming handler that crashes closes the connection; chunked streaming gained
  the backpressure its sibling already had.
- **express**: `send-file!` root confinement, dotfile refusal, HEAD framing,
  decode contracts.
- **dpool**: a worker slot the task itself never releases is reclaimed.
- **quickjs**: quickjs-ng's ABI is supported alongside bellard's, and the library
  is found where FreeBSD's package puts it. The interrupt deadline stays armed
  through stringification.

### Changed

- The test suite runs in POSIX `sh`, not bash.

---

## 1.2.1 — 2026-07-25

*21 commits.* PostgreSQL, and the pool engine behind the drivers.

### API

New libraries `(igropyr postgresql)` — connect, query, `postgresql-execute`,
transactions, pooling — `(igropyr sqlpool)`, the shared connection-pool engine,
and the query-protocol clients `(igropyr sns)`, `(igropyr cloudwatch)` and
`(igropyr s3-control)`. `(igropyr tls)` gains `tls-establish!`.
**22 added, none removed.**

### Added

- **postgresql**: a non-blocking client with the extended query protocol, TLS
  through an injected byte-codec connector, SCRAM channel binding, and explicit
  rejection of non-ASCII passwords. Its review findings were carried across to
  the MySQL connection lifecycle.
- **metrics**: request duration as a histogram.
- **cluster**: `max-members` is configurable, default 256.

---

## 1.1.20 — 2026-07-23

*8 commits.* Bounded password hashing, and a bytes render path.

### API

`(igropyr express)` gains `app-patch`; `(igropyr libuv)` gains `now-ns`;
`(igropyr quickjs)` gains `qjs-call/bytes`; `(igropyr ssr)` gains
`ssr-render/bytes` and `ssr-try-render/bytes`. **5 added, none removed.**

### Fixed

- **kdf**: scrypt verify time bounded, argon2 threads pinned, password length
  capped, `RAND_bytes` used for salts.

### Changed

- **ssr, quickjs**: a bytes render path that skips the UTF-8 round trip; the
  global object is cached, saving a `JS_GetGlobalObject` and free per call.
- **cluster**: gossip fanout exchanges run concurrently.

---

## 1.1.19 — 2026-07-21

*9 commits.* No API change. QuickJS without the C shim.

### Changed

- **quickjs**: the C shim is replaced by a pure-Scheme `(igropyr quickjs)`.

### Fixed

- **quickjs**: error paths in `qjs-call`, `qjs-boot!` and `qjs-shutdown!`.

---

## 1.1.18 — 2026-07-20

*19 commits.* FreeBSD, cached rendering, and password hashing.

### API

New libraries `(igropyr ssr)` — `make-ssr`, `ssr-render`, `ssr-try-render`,
`ssr-invalidate!`, `ssr-clear!`, `ssr-stats` — and `(igropyr kdf)` —
`password-hash`, `password-verify`, `kdf-scrypt`, `kdf-pbkdf2-sha256`,
`kdf-argon2id`. **11 added, none removed.**

### Added

- **platform**: FreeBSD support (`ta6fb` / `tarm64fb`), probing multiple libc and
  libz sonames.
- **ssr**: cached server-side rendering, with a redis backend for cross-node
  sharing and single-flight collapsing of concurrent misses on one key.
- **kdf**: scrypt, PBKDF2 and argon2id over libcrypto, with password-verify
  hardened against crafted-hash denial of service.

### Changed

- The QuickJS C shim moved to `c/quickjs-shim.c` and ships in the npm files.

---

## 1.1.17 — 2026-07-19

*12 commits.* Apple JWS, and the SigV4 service clients.

### API

New libraries `(igropyr apple-jws)` — `verify-apple-jws`, `verify-jws-x5c`,
`apple-root-ca-g3-der` — `(igropyr aws)`, `(igropyr sts)` and `(igropyr ses)`.
`(igropyr crypto)` gains `pbkdf2-hmac-sha256`; `(igropyr mysql)` gains
`mysql-transaction` and `call-with-mysql-connection`; `(igropyr s3)` gains
`s3-head` and `s3-restore!`. **16 added, none removed.**

### Added

- **apple-jws**: verification of Apple App Store Server (v2) JWS, with pinned
  leaf and intermediate OIDs, a pinned algorithm, and strict base64url.
- **aws, sts, ses**: SigV4 service clients — STS federation, SES email — with
  SigV4 host consistency and SES From encoding hardened.
- **mysql**: transaction leases.

### Fixed

- **http-client**: 1xx interim responses are skipped, not returned.
- Silent-failure hardening across the worker pool, crypto, routing, metrics,
  quickjs and blas.

---

## 1.1.16 — 2026-07-19

*3 commits.* The client library is renamed.

### API

`(igropyr client)` becomes `(igropyr http-client)`, carrying all 19 of its names
across unchanged. **19 added, 19 removed** — the same names under a new library.

### Breaking

- **`(igropyr client)` is now `(igropyr http-client)`.** The old library name is
  gone; every name it exported is unchanged under the new one.

### Added

- **express**: literal-prefix route params, e.g. `/@:username`.

---

## 1.1.15 — 2026-07-18

*3 commits.* No API change.

### Added

- **cluster**: gossip, the fourth discovery strategy — decentralised membership.
  Discovery strategies are ordered static, gossip, redis.

---

## 1.1.11 — 2026-07-18

*9 commits.* The metrics dashboard, vector scoring, and an embedded JS engine.
Republished unchanged as **1.1.12** and **1.1.13** within four minutes; no
commits separate the three.

### API

New libraries `(igropyr dashboard)` — `mount-dashboard!`, `dashboard-html`,
`admin-listen` — `(igropyr blas)` — `blas-scores!`, `blas-available?` — and
`(igropyr quickjs)` — `qjs-boot!`, `qjs-call`, `qjs-call!`, `qjs-shutdown!`,
`qjs-healthy?`, `qjs-generation`. `(igropyr metrics)` gains `metrics-json`,
`metrics-sexpr`, `metrics-snapshot` and `metrics-announce!`.
**15 added, none removed.**

### Added

- **metrics**: a browser dashboard with a cluster view aggregated over rcall,
  signal split from presentation, a configurable bind host, and an sexpr admin
  listener.
- **blas**: a vector scoring kernel — optional CBLAS `sgemv`, pure-Scheme
  fallback.
- **quickjs**: an in-process JS engine over QuickJS, through a C shim that ships
  separately from the Scheme sources.

---

## 1.1.10 — 2026-07-17

*10 commits.* Object storage, and the signing under it.

### API

New libraries `(igropyr s3)` — `make-s3`, `s3-put!`, `s3-get`, `s3-copy!`,
`s3-delete!`, `s3-delete-prefix!`, `s3-list` — `(igropyr sigv4)` — the canonical
request, string-to-sign, signing key and authorization steps — and
`(igropyr util)`. `(igropyr metrics)` gains `metrics-count!`.
**23 added, none removed.**

### Added

- **sigv4, s3**: AWS Signature V4 signing pinned by the documented AWS test
  vectors, and S3-compatible object storage over the HTTP client (put, get,
  server-side copy, delete, paginated ListObjectsV2, path-style for R2 and
  MinIO, explicit zero content-length on bodyless PUT).
- **metrics**: `metrics-count!` for application counters, hardened against input
  that would kill the collector or break a scrape.
- **util**: one home for helpers that had been copy-pasted.

### Fixed

- **http-client**: streaming responses via `(on-chunk . proc)`; a bounded caller
  on every path; a single chunked-transfer grammar with negative chunk sizes
  rejected; Host carries non-default ports; a configurable response cap.

---

## 1.1.9 — 2026-07-17

*7 commits.* No API change.

### Added

- **http**: `body-limit` is configurable through `http-listen` and validated at
  boot.
- **express**: splat `*` routes, with a non-trailing splat rejected at
  registration.

---

## 1.1.8 — 2026-07-16

*3 commits.* The resumable input buffer.

### API

New library `(igropyr buffer)` — `make-inbuf`, `inbuf-append!`, `inbuf-consume!`,
`inbuf-find-header-end`, `inbuf-sub`, and the accessors.
**11 added, none removed.**

### Fixed

- **http**: a resumable input buffer kills the O(n²) reader family, and a hybrid
  head parser scans by index with no hot-path interning. Adopted by websocket,
  node, the HTTP client and ws-client.

---

## 1.1.7 — 2026-07-16

*8 commits.* Tokens and guards.

### API

New libraries `(igropyr jwt)` — `jwt-sign`, `jwt-verify`, `jwt-decode`,
`jwt-verifier` — and `(igropyr auth)` — `auth`, `token-guard`, `session-guard`,
`req-claims`. `(igropyr session)` gains `session-peek`.
**9 added, none removed.**

### Added

- **jwt**: HS256 JSON Web Tokens with express middleware.
- **auth**: format-neutral bearer middleware, WebSocket upgrade guards in both
  token and session forms, and a per-route auth guard for app-rpc handlers.

---

## 1.1.6 — 2026-07-16

*4 commits.* Development-time contracts.

### API

New library `(igropyr checked)` — `define-checked`, `define-checked-record`,
`->`, `contract-level`. `(igropyr http)` gains `request?` and `res?`.
**6 added, none removed.**

### Added

- **checked**: contract macros for internal invariants, piloted on the express
  and session boundaries.

### Fixed

- **build**: `sexpr.sc` is compiled; as a source-only library it had been
  invalidating every dependent object file.

---

## 1.1.5 — 2026-07-15

*3 commits.* Outbound TLS.

### API

New library `(igropyr tls)` — `tls-enable!`. `(igropyr client)` gains
`set-https-connector!`. **2 added, none removed.**

### Added

- **tls**: optional outbound TLS, with `https://` support in the HTTP client.

---

## 1.1.3 — 2026-07-14

*2 commits.* No API change.

### Fixed

- **conversation**: clustered resumes are routed to the owning node.

---

## 1.1.2 — 2026-07-14

*3 commits.* No API change.

### Changed

- **sexpr**: flonums travel as `#f8"<IEEE base64>"` — bit-exact, infinities and
  NaN included.

---

## 1.1.1 — 2026-07-13

*2 commits.* No API change.

### Added

- **express**: binary values cross the s-expression web RPC in extended mode.

---

## 1.1.0 — 2026-07-13

*4 commits.* The sleep queue, and crypto in its own library.

### API

New library `(igropyr crypto)` — `sha1`, `sha256`, `hmac-sha1`, `hmac-sha256`,
`base64-encode`, `base64-decode`, `bytevector->hex`. `(igropyr node)` gains
`node-set-limits!`. **8 added, 2 removed.**

### Breaking

- **`(igropyr websocket)` no longer exports `base64-encode` and `sha1`.** They
  moved to the new `(igropyr crypto)`.

### Changed

- **actor**: an O(log n) sleep queue and a fixnum clock on the hot path.
- The distribution layer is hardened, and the wire carries base64 bytevectors.

---

## 1.0.3 — 2026-07-13

*9 commits.* The distribution layer.

### API

New libraries `(igropyr node)` — `node-start!`, `node-connect!`,
`node-disconnect!`, `node-peers`, `node-self`, `rsend`, `rcall`, `monitor-node`,
`monitor-remote` and the demonitor pair — `(igropyr dpool)` — `dpool-start`,
`dpool-submit`, `dpool-await`, `dpool-stats`, `dpool-worker-start` — and
`(igropyr cluster)` — `cluster-start`, `cluster-stop`. `(igropyr sexpr)` gains
`sexpr->string-extended` and `string->sexpr-extended`.
**20 added, none removed.**

### Added

- The distribution layer, in four phases: node-to-node links, `rcall` with
  cluster-wide pubsub, a distributed task pool, and cross-node process monitors —
  then `(igropyr cluster)` for automatic mesh discovery.
- **sexpr**: an extended wire mode carrying vectors, bytevectors and finite
  flonums.

---

## 1.0.2 — 2026-07-13

*10 commits.* A performance release.

### API

`(igropyr http)` gains `res-begin-file!`, `res-write-file!`, `res-write-chunk!`
and `res-abort-file!`; `(igropyr libuv)` gains the `file-stream-*` family and
`tcp-write-foreign!`. **11 added, none removed.**

### Changed

- **actor**: the current process is kept in virtual register 0.
- **http**: response framing constants are precomputed; the parse fast paths
  allocate nothing.
- **express**: the middleware chain is precomposed; pre-encoded bodies are
  accepted; the static cache gained a stat window.
- **json**: output goes through one string port — linear instead of quadratic on
  large values.
- Large static files stream through a fixed-length chunked pump with
  backpressure, zero-allocation raw chunks, 256 KiB reads and metadata-cached
  304s.

---

## 1.0.1 — 2026-07-12

*3 commits.* No API change. Packaging only.

### Changed

- The Homebrew formula is dropped in favour of npm; `start` and `test` scripts
  added.

---

## 1.0.0 — 2026-07-12

*68 commits.* The first published rewrite release: an HTTP server on Chez Scheme
and libuv with Erlang-style green processes.

### API

20 libraries, 197 exported names: the core `(igropyr http)` and `(igropyr actor)`,
the `(igropyr express)` layer, `(igropyr websocket)`, `(igropyr json)`,
`(igropyr mysql)`, `(igropyr redis)`, `(igropyr client)`, `(igropyr ws-client)`,
`(igropyr session)`, `(igropyr middleware)`, `(igropyr metrics)`,
`(igropyr gen-server)`, `(igropyr pubsub)`, `(igropyr otp)`, `(igropyr conversation)`,
`(igropyr sexpr)`, `(igropyr gzip)`, `(igropyr libuv)` and `(igropyr platform)`.

### Added

- HTTP/1.1 core split from an Express-style layer; a let-it-crash worker pool
  with configurable size, retries and stuck threshold; hot code swapping.
- WebSocket, chunked request bodies, chunked responses and SSE.
- Static files with ETag/304, `Cache-Control`, and large-file streaming.
- gzip response compression; cookies; urlencoded and multipart form parsing.
- Middleware suite: sessions, CORS, security headers, logger, rate limiting,
  error handler.
- `(igropyr json)`: a safe recursive-descent parser and writer.
- `(igropyr mysql)` verified against MySQL 9, with a self-healing pool; a
  non-blocking Redis client (RESP2); a non-blocking HTTP client with async DNS; a
  WebSocket client.
- OTP trio: gen-server, process registry, PubSub. Runtime stats, graceful
  shutdown, `SO_REUSEPORT`, and a Prometheus metrics endpoint.
- `(igropyr conversation)`: process-per-dialogue state across requests.
- `(igropyr sexpr)`: s-expression bodies for Scheme-to-Scheme RPC, over HTTP,
  WebSocket and SSE.
- Async file reads on libuv's thread pool; per-library and whole-program
  production builds.

### Fixed

- Several security passes: strict `Content-Length`, per-request response tokens,
  header-injection guards, static prefix boundaries, WebSocket frame validation
  and message-size caps, MySQL `caching_sha2` full-auth hardening, and protocol
  hardening ported from contributed patches.
