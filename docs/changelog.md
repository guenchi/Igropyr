# Changelog

Every released version of Igropyr, reconstructed from the published packages and
the git history. **npm is the authority for version numbers**: where the registry
and this repository disagree, the registry wins, and the disagreements are listed
under [Numbering](#numbering) below.

Releases are newest first. The commit count after each date is the number of
commits that landed between that release and the one before it. "API" lists the
public names a release added or removed; it is derived mechanically from each
library's `(export ...)` form, so it sees names, not signatures — a name that
stayed while its arguments or behaviour changed appears under Breaking or Changed
instead. The method, and its known limits, are in [How this file was built](#how-this-file-was-built).

---

## Unreleased

`package.json` says `1.5.2`; nothing above 1.5.1 has been published. 77 commits so far.

- **node**: wire protocol v4 — boot ids, dial generations, target-bound proofs.
  Dial decisions are installed as an ordered rule table and carried out one
  process per attempt, with a registrar issuing the permission to dial and
  ordering endpoint changes against disconnects.
- **node**: hosted-monitor accounting reworked — the hosting ceiling counts what
  holds a process, arming is idempotent, a reaper returns credits and is found by
  name so it can be replaced, and a warden backs off, counts, and eventually gives up.
- **node**: topology subscriptions can carry a token and events carry a sequence
  number; `monitor-node/token` / `demonitor-node/token`. Deduplication is within
  a variant, not across them, so ending a legacy subscription cannot end a token one.
- **node**: admission slots know their holder, come back when the holder dies, and
  an install that stops half way undoes itself.
- **dpool**: subscribes with a token and drops what it has already seen.
- **libuv**: a connect or listen that fails partway releases what it took; a DNS
  request retires its owner-index entry on both exits.
- **actor**: interrupt regions unwind; about 5% on send and receive.
- **build**: one library list, compared against the directory.
- API: `uv-live-handle-count`, `uv-owner-index-count`, `node-install-rule-order`,
  `node-orphan-count`, `monitor-node/token`, `demonitor-node/token`.

---

## 1.5.1 — 2026-08-29 (24 commits)

- **node**: the handshake is versioned, and a proof-forgery collision is closed.
  The documentation said HMAC-SHA1; the code has always been HMAC-SHA256.
- **node**: backpressure closeouts. A refused submission answers as no link; a
  control frame that cannot go means the link goes; a DOWN that cannot be spoken
  costs the link on every path; link state — not report shape — tells a dead link
  from a refused frame. The backoff threshold is seeded with the pair's real first delay.
- **otp**: crash-only completion for the worker pool, and a critical-component
  mark, so a listener can decline the critical mark it would otherwise inherit.
- **sigv4, http**: header names are gated at the call.
- A generational-failover batch for node and dpool was written, reviewed, and
  **reverted before release**; five corrected comments from it were kept.
- API: `critical!`, `uncritical!`, `process-monitor-count`, `http-server-sup`,
  `http-server-pool-alive?`, `node-outbound-stats`, `reconnect-delay`,
  `submission-failure?`.

## 1.5.0 — 2026-08-27 (8 commits)

- **Breaking — the JSON writer accepts one spelling per shape.** Arrays are
  vectors; object keys and values are strings. A plain list is refused instead of
  being written as an array, with a message naming `list->vector`. This removes
  the ambiguity family around values that could be read as either an array or an
  object, and it lets the new `json-` operations address everything the writer accepts.
- **json**: every numeral the writer emits is validated against the JSON grammar
  by an independent internal library, so the writer cannot emit what the reader
  would refuse. The reader's cap is the writer's only bound, and now says so.
- API: new module `(igropyr json-internal)`; `json-ref*`, `json-set`, `json-set*`,
  `json-update`, `json-update*`, `json-insert`, `json-insert*`, `json-push`,
  `json-push*`, `json-drop`, `json-drop*`, `json-null?`, `json-array?`,
  `json-object?`, `http-stats-json`.

## 1.3.3 — 2026-08-22 (13 commits)

- **json**: a digit is required on both sides of the decimal point.
- The JSON reader's acceptance surface is pinned row by row, each row carrying the
  RFC text that decides it, with the should-be-green half enumerated across the grammar.
- README: Chez is a requirement, not a preference.

## 1.3.2 — 2026-08-21 (73 commits)

- **session**: `secure` may be a predicate, because one process can serve two
  schemes. Clearing a session ends its identity, not only its data; logging out
  retires the identifier.
- **express**: `app-route-list`, a read-only projection of what got registered.
  Replacing a handler no longer moves its route.
- **sexpr**: the writer asks what the reader will do with a name, and will not emit
  a token the reader must refuse. Pinned by a symbol corpus driven from a vendored
  conformance fixture (190 names, later 1593).
- **gen-server**: the error slot holds a printable scalar — the output is bounded,
  a label is built rather than the value printed, and clipping happens before framing.
- **connpool**: a stats timeout raises a shape carrying the pool's id, not a bare symbol.
- **durable-async**: exports the directory flush, which refuses a non-directory.
- A documentation truth pass across README, quickjs, gzip and platform: claims that
  described deleted machinery, install guidance left half-behind, and counts that
  had drifted were corrected at every site rather than at the one a reviewer named.
- API: `app-route-list`, `durable-fsync-dir-async!`.

## 1.3.1 — 2026-08-19 (13 commits)

- **libuv**: `fs-mkdir-async!`, the one write-side step that was missing, plus
  `O_CLOEXEC` and `O_DIRECTORY`. A descriptor is closed after the last job that
  names it, never before, and a descriptor number is treated as a lease — identity
  is the number *and* a generation.
- **durable-async**: the same atomic-write sequence as `(igropyr durable)`, run off
  the scheduler thread, with the failure paths its contract had quietly been missing.
- **durable**: exports the traced step, so a second implementation shares one trace
  and one set of op names.
- API: new module `(igropyr durable-async)`; `fs-mkdir-async!`, `fs-o-cloexec`,
  `fs-o-directory`, `fs-trace-step`.

## 1.3.0 — 2026-08-18 (50 commits)

- **libuv**: an asynchronous filesystem write side — open, write, rename, fsync,
  close, one syscall per job, off the scheduler thread — with the open flags exported
  and a read port for held descriptors.
- **conversation**: hosted forwards are capped and refused promptly instead of
  silently; a forward may not hold its slot indefinitely; an abandoned wait gives its
  slot back while the work survives. Census and quiesce, both node-local, count a
  conversation at admission rather than when it first runs. Outcome records may
  outlive the process without being persisted. The forwarding deadline is per call.
- **qjspool**: failure kinds are decided by position — a render that never reached
  the wire keeps its connection.
- API: `fs-open-async!`, `fs-write-async!`, `fs-rename-async!`, `fs-fsync-async!`,
  `fs-close-async!`, `fs-fd-count`, `fs-job-count`, the `fs-o-*` flags,
  `conversation-census`, `conversation-quiesce!`, `conversation-quiescing?`,
  `conversation-overloaded?`, `conversation-forward-stats`,
  `conversation-record-hooks!`, `conv-set-forward-limit!`, `conv-set-forward-hold-ms!`.

## 1.2.9 — 2026-08-18 (60 commits)

- **gzip**: hardening of the embedded-zlib binding — probe descriptors are
  close-on-exec and closed on every exit, a libc without `pipe2` is survived, there
  is no descriptor window before the wind, and native buffers are given back after
  the process holding them is killed.
- **crypto / rsa / aead**: key loading and buffer handling hardened; portable
  non-blocking key open; a correct `EVP_PKEY_check` verdict; atomic close-on-exec.
- **tls**: the error queue is cleared before each `SSL_*` call and what OpenSSL
  returns is checked; a closed connection stops the handshake; a broken codec stays broken.
- **conversation**: the commit witness goes through `commit!`, so a post-commit
  failure is never reported as `'gone`; the outcome is remembered so a pruned record
  cannot become a kill; the witness crosses the link; a commit can end in *maybe*,
  and maybe is not a rollback; the `on-killed` hook is supervised and a hook that did
  not return is not a success.
- **connpool / mysql**: a caller can observe the statements the pool issues itself.
- **durable**: atomic file write with the directory flush the sequence needs.
- Renamed `(igropyr conversation-status)` to `(igropyr conv-status)` — both
  introduced in this release, so nothing published carried the old name.
- API: new modules `(igropyr durable)`, `(igropyr conv-status)`;
  `conversation-prepare!`, `conversation-run!`, `conversation-abandon!`,
  `conversation-peek/timeout`, `conversation-ref-id`, `conversation-unreachable?`,
  `conversation-no-answer-yet?`, `conversation-hook-stats`,
  `connpool-cfg-set-observer!`, `connpool-observer-failures`, `mysql-observe!`,
  `rsa-key-consistency-checked`.

## 1.2.8 — 2026-08-13 (6 commits)

- New: `(igropyr rsa)` and `(igropyr aead)` — RSA and AES-256-GCM, pinned against
  implementations that are not this one.
- Fixed: a verification that could be forged, and a passphrase that was not a refusal.
- **tls**: a dirty error queue turned want-read into a dead connection.
- **gzip**: binds the zlib embedded in the Chez runtime on FreeBSD, instead of a
  second copy from the system.
- API: new modules `(igropyr rsa)`, `(igropyr aead)`.

## 1.2.7 — 2026-08-07 (126 commits)

The largest release in the series: conversations, the connection pool, and the
HTTP client were reworked, and a long tail of lifetime and leak defects closed.

- **Breaking — `(igropyr sqlpool)` is now `(igropyr connpool)`.** It was never
  about SQL. Six public names in mysql and postgresql that the rename ate were restored.
- **Breaking — a conversation resume must name the reply it is answering.** Step
  tokens are unguessable rather than consecutive, a new token never repeats the one
  just spent, a replay must answer the question that was asked, and a request nobody
  can key replays nothing. Chosen over an optional token deliberately: a default that
  falls back to arrival order leaves the framework wrong for everyone who does not opt in.
- **conversation**: a status vocabulary that says what it means — `'gone` now means
  the flow rolled back and is derived from evidence rather than absence, `'unknown`
  says the rest, an unreachable owner is not a dead one, the TTL is a running bound
  and not merely an idle one, publishing a completion is one indivisible act, and
  there is an `on-killed` hook because TTL expiry does not always raise.
- **http-client**: connections are reused instead of dialled per request, with a
  pool, bounded response head and chunk-size line, a chunked response that ends at
  its trailer rather than at the `0` line, and a slow `on-chunk` handler that slows
  the server rather than memory.
- **http**: whole-request deadlines spanning head and body, a write deadline on
  `res-end!`'s terminator, HEAD suppression on the streaming paths, refusal of two
  inbound framings the two ends would read differently, no handler run for a client
  that has gone, and a stream that will never finish ends the request.
- **qjspool**: QuickJS renders run in worker processes, with `(engine . <qjspool>)`
  wiring them into `ssr`; a render borrows its worker with its own deadline, a
  teardown reaches a connection mid-render, leftover bytes after a response are a
  desync rather than the next answer, and a request that arrived whole is always answered.
- **libuv**: owned resources are indexed by owner instead of scanning every table,
  and ownership is published atomically.
- Fixed across the tree: rcall pending entries leaking in node; gen-server calls to
  a dead caller and to yourself; dpool surviving an unsendable payload; redis paying
  O(N) per command to enqueue a waiter; a one-byte WebSocket close payload treated as
  an index rather than a protocol error; JSON number tokens unbounded and non-finite;
  an SSE payload newline treated as a field; connection-pool workers that died before
  reporting; result sets materialising without a row cap.
- API: new modules `(igropyr connpool)`, `(igropyr qjspool)`; `process-count`,
  `http-request-deadline!`, `http-write-timeout!`, `res-abort!`, `res-spawn!`,
  `res-streaming?`, `tcp-read-stop!`, `ws-write-timeout!`, `http-client-pool!`,
  `http-client-pool-stats`, `http-client-close-idle!`, `mysql-pool-stats`,
  `postgresql-pool-stats`, `fs-count`, `jwks-key-free!`, `conversation-peek`,
  `conversation-done?`, `conversation-settled?`, `conversation-stale?`,
  `conversation-unknown?`, `conversation-set-limits!`.

## 1.2.6 — 2026-08-03 (21 commits)

- **actor**: process-registry rebinding fixed; registry aliases are preserved when rebinding.
- **websocket / ws-client**: unsafe request headers rejected; client handshakes validated.
- **http**: ambiguous response framing rejected; streaming chunk terminators validated.
- **jwks**: unknown-kid refreshes are bounded, and cache mutations are serialised.
- Documented that `parameterize` gives no per-process isolation.

## 1.2.5 — 2026-07-31 (10 commits)

- New: `(igropyr jwks)` — RS256 signing, verification, and JWKS documents.
- Base64url moved into `(igropyr crypto)` and shared by Apple JWS; impossible
  base64url lengths are rejected. KDF reuses the shared OpenSSL candidate list.
- API: new module `(igropyr jwks)`; `base64url-encode`, `base64url-decode`,
  `shared-object-candidates`.

## 1.2.3 — 2026-07-31 (87 commits)

A hardening batch, largely from externally contributed and independently reviewed
pull requests, each landing with a test that fails without it:

- **express**: multipart boundary semantics enforced and held to the ASCII grammar;
  the boundary search made linear with a KMP failure table bound to its needle and
  built once; the static cache gained a capacity ceiling, a byte cap, stale eviction,
  adjustable limits, and a key on the resolved name rather than the request.
- **session**: ID regeneration, documented as idempotent; refusal to regenerate once
  the response has gone out; valid rotations preserved on handler failure; writes
  committed after answered failures; no resurrection of a retired ID; rotation
  cookies published atomically.
- **node**: remote monitors released when callers exit; an absolute handshake
  deadline; a cap on handshakes in flight from unauthenticated peers; missing self
  monitors released.
- **libuv / http**: libuv resources reclaimed when owners die; static file opens
  confined beneath their roots; bodies suppressed for bodyless statuses; timed-out
  HTTP request actors cancelled; chunked request metadata bounded; client-managed
  headers rejected.
- **redis**: fragmented RESP replies parsed incrementally, with reply resource limits.
- **postgresql**: SCRAM iteration counts capped, derived from a time budget.
- **websocket**: opening handshakes validated; fragmented message frame counts capped.
- **auth**: fails closed before session lookup; `session-guard` can require an Origin.
- API: `static-cache-limits!`, `static-cache-stats`, `set-cookie-if-unanswered!`,
  `set-header-if-unanswered!`, `res-answered?`, `session-regenerate!`,
  `redis-set-limits!`, `node-monitor-stats`, `conn-on-close!`, `file-realpath`,
  `file-stream-open-under!`, `ws-valid-client-key?`, `blas-scores-pure!`,
  `kdf-argon2id-available?`.

## 1.2.2 — 2026-07-26 (19 commits)

- A whole-codebase review, applied in three passes — security findings, correctness
  findings, then the regressions the first two introduced.
- **http**: the request path is normalised so every layer agrees on it; a streaming
  handler that crashes closes the connection; chunked streaming gained the
  backpressure its sibling already had.
- **express**: `send-file!` root confinement, dotfile refusal, HEAD framing, decode contracts.
- **dpool**: a worker slot the task itself never releases is reclaimed.
- **quickjs**: quickjs-ng's ABI is supported alongside bellard's, and the library is
  found where FreeBSD's package puts it. The interrupt deadline stays armed through
  stringification.
- The test suite runs in POSIX `sh`, not bash.
- API: `req-peer`, `req-version`, `res-head-request?`, `res-send-head!`,
  `conn-peer-ip`, `uv-owner-died!`.

## 1.2.1 — 2026-07-25 (21 commits)

Absorbs the `1.1.21` and `1.2.0` version bumps, which exist in git but were never published.

- New: `(igropyr postgresql)` — a non-blocking client with the extended query
  protocol, TLS through an injected byte-codec connector, SCRAM channel binding, and
  explicit rejection of non-ASCII passwords. Its review findings were carried across
  to the MySQL connection lifecycle.
- New: `(igropyr sqlpool)`, the shared connection-pool engine extracted from the drivers.
- New: `(igropyr sns)`, `(igropyr cloudwatch)`, `(igropyr s3-control)`.
- **metrics**: request duration as a histogram.
- **cluster**: `max-members` is configurable, default 256.
- API: new modules as above; `tls-establish!`.

## 1.1.20 — 2026-07-23 (8 commits)

- **kdf**: scrypt verify time bounded, argon2 threads pinned, password length
  capped, `RAND_bytes` used for salts.
- **ssr / quickjs**: a bytes render path that skips the UTF-8 round trip; the global
  object is cached, saving a `JS_GetGlobalObject` and free per call.
- **cluster**: gossip fanout exchanges run concurrently.
- API: `now-ns`, `app-patch`, `qjs-call/bytes`, `ssr-render/bytes`, `ssr-try-render/bytes`.

## 1.1.19 — 2026-07-21 (9 commits)

- **quickjs**: the C shim is replaced by a pure-Scheme `(igropyr quickjs)`; error
  paths in `qjs-call` / `qjs-boot!` / `qjs-shutdown!` hardened.
- Homepage moved to https://igropyr.dev.

## 1.1.18 — 2026-07-20 (19 commits)

- **platform**: FreeBSD support (`ta6fb` / `tarm64fb`), probing multiple libc and
  libz sonames.
- New: `(igropyr ssr)` — cached server-side rendering, with a redis backend for
  cross-node sharing and single-flight collapsing of concurrent misses on one key.
- New: `(igropyr kdf)` — scrypt, PBKDF2 and argon2id over libcrypto, with
  password-verify hardened against crafted-hash denial of service.
- The QuickJS C shim moved to `c/quickjs-shim.c` and ships in the npm files.
- API: new modules `(igropyr ssr)`, `(igropyr kdf)`.

## 1.1.17 — 2026-07-19 (12 commits)

- New: `(igropyr apple-jws)` — verification of Apple App Store Server (v2) JWS, with
  pinned leaf and intermediate OIDs, a pinned algorithm, and strict base64url.
- New: `(igropyr aws)`, `(igropyr sts)`, `(igropyr ses)` — SigV4 service clients
  (STS federation, SES email), with SigV4 host consistency and SES From encoding hardened.
- **mysql**: transaction leases — `mysql-transaction`, `call-with-mysql-connection`.
- **s3**: `s3-head`, `s3-restore!`, and a HEAD-aware HTTP client.
- **http-client**: 1xx interim responses are skipped, not returned.
- Silent-failure hardening across the worker pool, crypto, routing, metrics, quickjs and blas.
- API: new modules as above; `pbkdf2-hmac-sha256`, `mysql-transaction`,
  `call-with-mysql-connection`, `s3-head`, `s3-restore!`.

## 1.1.16 — 2026-07-19 (3 commits)

- **Breaking — `(igropyr client)` is now `(igropyr http-client)`.** The old library
  name is gone; every name it exported is unchanged under the new one.
- **express**: literal-prefix route params, e.g. `/@:username`.

## 1.1.15 — 2026-07-18 (3 commits)

- **cluster**: gossip, the fourth discovery strategy — decentralised membership.
  Discovery strategies are ordered static, gossip, redis.

## 1.1.11 — 2026-07-18 (9 commits)

Republished unchanged as **1.1.12** and **1.1.13** within four minutes; no commits
separate the three.

- **metrics**: a browser dashboard (`metrics-dashboard`, `metrics-json`) with a
  cluster view aggregated over rcall, signal split from presentation, a configurable
  bind host, and an sexpr admin listener.
- New: `(igropyr blas)` — a vector scoring kernel, optional CBLAS `sgemv` with a
  pure-Scheme fallback.
- New: `(igropyr quickjs)` — an in-process JS engine over QuickJS, through a C shim
  that ships separately from the Scheme sources.
- API: new modules `(igropyr blas)`, `(igropyr dashboard)`, `(igropyr quickjs)`;
  `metrics-json`, `metrics-sexpr`, `metrics-snapshot`, `metrics-announce!`.

## 1.1.10 — 2026-07-17 (10 commits)

- New: `(igropyr sigv4)` and `(igropyr s3)` — AWS Signature V4 signing pinned by the
  documented AWS test vectors, and S3-compatible object storage over the HTTP client
  (put / get / server-side copy / delete / paginated ListObjectsV2, path-style for
  R2 and MinIO, explicit zero content-length on bodyless PUT).
- New: `(igropyr util)` — one home for helpers that had been copy-pasted.
- **http-client**: streaming responses via `(on-chunk . proc)`; a bounded caller on
  every path; a single chunked-transfer grammar with negative chunk sizes rejected;
  Host carries non-default ports; a configurable response cap.
- **metrics**: `metrics-count!` for application counters, hardened against input
  that would kill the collector or break a scrape.
- API: new modules as above; `metrics-count!`.

## 1.1.9 — 2026-07-17 (7 commits)

- **http**: `body-limit` is configurable through `http-listen` and validated at boot.
- **express**: splat `*` routes, with a non-trailing splat rejected at registration.

## 1.1.8 — 2026-07-16 (3 commits)

- New: `(igropyr buffer)` — a resumable input buffer that kills the O(n²) reader
  family, adopted by websocket, node, the HTTP client and ws-client.
- **http**: a hybrid head parser that scans by index and does no hot-path interning.

## 1.1.7 — 2026-07-16 (8 commits)

- New: `(igropyr jwt)` — HS256 JSON Web Tokens with express middleware.
- New: `(igropyr auth)` — format-neutral bearer middleware, WebSocket upgrade guards
  in both token and session forms, and a per-route auth guard for app-rpc handlers.
- API: new modules as above; `session-peek`.

## 1.1.6 — 2026-07-16 (4 commits)

- New: `(igropyr checked)` — development-time contract macros for internal
  invariants, piloted on the express and session boundaries.
- **build**: `sexpr.sc` is compiled; as a source-only library it had been
  invalidating every dependent object file.
- API: new module `(igropyr checked)`; `request?`, `res?`.

## 1.1.5 — 2026-07-15 (3 commits)

- New: `(igropyr tls)` — optional outbound TLS, with `https://` support in the HTTP
  client through `set-https-connector!`.

## 1.1.3 — 2026-07-14 (2 commits)

- **conversation**: clustered resumes are routed to the owning node.

## 1.1.2 — 2026-07-14 (3 commits)

- **sexpr**: flonums travel as `#f8"<IEEE base64>"` — bit-exact, infinities and NaN included.

## 1.1.1 — 2026-07-13 (2 commits)

- **express**: binary values cross the s-expression web RPC in extended mode.

## 1.1.0 — 2026-07-13 (4 commits)

- **Breaking — `(igropyr websocket)` no longer exports `base64-encode` and `sha1`.**
  They moved to the new `(igropyr crypto)`.
- **actor**: an O(log n) sleep queue and a fixnum clock on the hot path.
- The distribution layer is hardened, and the wire carries base64 bytevectors.
- API: new module `(igropyr crypto)`; `node-set-limits!`.

## 1.0.3 — 2026-07-13 (9 commits)

- The distribution layer, in four phases: `(igropyr node)` node-to-node links,
  `rcall` with cluster-wide pubsub, `(igropyr dpool)` distributed task pool, and
  cross-node process monitors — then `(igropyr cluster)` for automatic mesh discovery.
- **sexpr**: an extended wire mode carrying vectors, bytevectors and finite flonums.
- API: new modules `(igropyr node)`, `(igropyr dpool)`, `(igropyr cluster)`;
  `sexpr->string-extended`, `string->sexpr-extended`.

## 1.0.2 — 2026-07-13 (10 commits)

A performance release.

- **actor**: the current process is kept in virtual register 0.
- **http**: response framing constants are precomputed; the parse fast paths allocate nothing.
- **express**: the middleware chain is precomposed; pre-encoded bodies are accepted;
  the static cache gained a stat window.
- **json**: output goes through one string port — linear instead of quadratic on large values.
- Large static files stream through a fixed-length chunked pump with backpressure,
  zero-allocation raw chunks, 256 KiB reads and metadata-cached 304s.
- API: `res-begin-file!`, `res-write-file!`, `res-write-chunk!`, `res-abort-file!`,
  the `file-stream-*` family, `tcp-write-foreign!`.

## 1.0.1 — 2026-07-12 (3 commits)

- Packaging only: the Homebrew formula is dropped in favour of npm; `start` and
  `test` scripts added.

## 1.0.0 — 2026-07-12 (68 commits)

The first published release, and a rewrite: an HTTP server on Chez Scheme and libuv
with Erlang-style green processes.

- HTTP/1.1 core split from an Express-style layer; a let-it-crash worker pool with
  configurable size, retries and stuck threshold; hot code swapping.
- WebSocket, chunked request bodies, chunked responses and SSE.
- Static files with ETag/304, `Cache-Control`, and large-file streaming.
- gzip response compression; cookies; urlencoded and multipart form parsing.
- Middleware suite: sessions, CORS, security headers, logger, rate limiting, error handler.
- `(igropyr json)`: a safe recursive-descent parser and writer.
- `(igropyr mysql)` verified against MySQL 9, with a self-healing pool; a
  non-blocking Redis client (RESP2); a non-blocking HTTP client with async DNS; a
  WebSocket client.
- OTP trio: gen-server, process registry, PubSub. Runtime stats, graceful shutdown,
  `SO_REUSEPORT`, and a Prometheus metrics endpoint.
- `(igropyr conversation)`: process-per-dialogue state across requests.
- `(igropyr sexpr)`: s-expression bodies for Scheme-to-Scheme RPC, over HTTP,
  WebSocket and SSE.
- Async file reads on libuv's thread pool; per-library and whole-program production builds.
- Several security passes: strict `Content-Length`, per-request response tokens,
  header-injection guards, static prefix boundaries, WebSocket frame validation and
  message-size caps, MySQL `caching_sha2` full-auth hardening, and protocol hardening
  ported from contributed patches.

---

## Numbering

- **npm is authoritative.** Published versions run 1.0.0 through 1.5.1, 37 of them.
- **In git but never published**: version bumps to `1.1.21` and `1.2.0` (both
  2026-07-23). Their content shipped in 1.2.1.
- **Published but never tagged**: 1.1.19, 1.1.20, 1.5.1.
- **Republished without changes**: 1.1.12 and 1.1.13 followed 1.1.11 within four
  minutes, with no commits in between.
- **Numbers that never existed anywhere**: 1.0.4, 1.1.4, 1.1.14, 1.2.4, and the whole
  1.4 series — 1.3.3 is followed by 1.5.0.
- **Before 1.0.0**: eight tags from 0.1.0 to 0.2.10 (2018-03-01 to 2018-04-20) belong
  to an earlier codebase of the same name. They are not ancestors of the current
  `master`, whose root commit is the 2026-07-10 rewrite, and none of them was ever
  published to npm. They are outside this changelog.
- On 2026-08-07 the history was rewritten to strip tool trailers from commit
  messages. Commits before that point have different hashes than they had when the
  corresponding versions were published; their content is unchanged.

## How this file was built

1. The version list and its dates come from `npm view igropyr versions` and
   `npm view igropyr time` — publish times, in UTC.
2. Each commit on `master` is attributed to the first release whose publish time is
   at or after the commit's own timestamp. This is what "N commits" counts.
3. Where a tag exists, it is a second opinion on the same boundary. For 24 of the 32
   tagged releases the tag lands exactly on the last commit attributed to it; the
   other eight differ by one to six commits, except 1.0.0, whose tag sits at the
   version bump 17 commits before the publish.
4. The API lines are computed by extracting the `(export ...)` form of every library
   at each release's last commit and diffing consecutive releases. **This sees names
   only.** A name that survived while its arguments, return values or behaviour
   changed does not appear there; those changes are described in prose, taken from
   the commit that made them. Renamed libraries show up as one module gone and one
   module added.
5. Across the whole 1.x series the export surface is otherwise additive: 197 names in
   20 libraries at 1.0.0, 525 names in 54 libraries at 1.5.1, and the only names ever
   withdrawn are the two that moved out of `(igropyr websocket)` in 1.1.0 and the two
   libraries that were renamed.
