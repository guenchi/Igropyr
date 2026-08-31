#!chezscheme
;;; (igropyr node) -- node-to-node links: distribution phase 1.
;;;
;;; Connects igropyr instances (other cores via loopback, other machines
;;; via the network) into a mesh where a process on one node can message
;;; a REGISTERED NAME on another:
;;;
;;;   (node-start! 'a secret 4100)              ; identity + listener
;;;   (node-connect! 'b "10.0.0.2" 4100)        ; outbound, auto-reconnect
;;;   (rsend 'b 'worker-pool #(job 42))         ; -> (whereis 'worker-pool) on b
;;;   (monitor-node 'b)                         ; -> #(node-up b) / #(node-down b)
;;;
;;; TOPOLOGY NOTICES ARE AT LEAST ONCE. One supervised process delivers
;;; them, and an event leaves its queue only once it has been handed to
;;; every subscriber -- so a delivery that dies half way through is
;;; started again by the next dispatcher rather than lost. A subscriber
;;; can therefore see the same notice twice. The token form exists to
;;; make that absorbable:
;;;
;;;   (define t (monitor-node/token 'b))        ; -> #(node-up b t seq)
;;;
;;; It carries the subscription token and a sequence number that rises
;;; across all notices, which is what a receiver deduplicates with:
;;; ignore anything whose token is not yours, then ignore a sequence
;;; number you have already passed. The two-element form above carries
;;; neither and cannot tell a repeat from a new event. It is kept exactly
;;; as it is for code written before the token form existed; that is the
;;; trade, and it is stated rather than papered over.
;;;
;;; NODE-CONNECT! AND NODE-DISCONNECT! RETURN WHEN THE REQUEST IS
;;; ACCEPTED, NOT WHEN IT HAS TAKEN EFFECT. Both hand the change to the
;;; registrar, whose mailbox is the order such changes happen in, and
;;; return. The promise has always been "start dialling", never "the link
;;; is up" -- reconnection is a background loop and a first connect could
;;; never have meant a link existed. What did change is narrower and is
;;; worth saying plainly: on return, the connector process for that peer
;;; may not exist yet. Code that dialled and then immediately looked for
;;; internal state saw it before; it now has to wait for what it actually
;;; wants, which is #(node-up peer) from monitor-node.
;;;
;;; Waiting for the registrar here was considered and refused: it would
;;; tie a public call's return to the scheduling delay of an internal
;;; process, for a guarantee the call never made.
;;;
;;; Semantics mirror Erlang distribution deliberately:
;;;   - addressing is by registered name, never by raw pid (pids are
;;;     memory objects; names survive restarts, pids don't)
;;;   - rsend is fire-and-forget: #t means handed to a live link, #f
;;;     means no link -- delivery is never confirmed. Use monitor-node
;;;     (and application-level replies) for failure handling.
;;;   - messages between one pair of nodes arrive in send order (one
;;;     TCP connection per pair)
;;;   - rsend to the OWN node name is a plain local send (location
;;;     transparency)
;;;
;;; Wire protocol: length-prefixed frames -- "<decimal-len>\n<datum>" --
;;; carrying one EXTENDED-mode s-expression each (vectors, bytevectors
;;; and finite flonums cross intact; see (igropyr sexpr)). A frame that
;;; fails to parse, an oversized frame, or an unknown shape drops the
;;; connection: a confused peer is a dead peer, never a guessed-at one.
;;;
;;; Handshake (before anything else): mutual HMAC-SHA256 challenge/response
;;; on a shared secret. The secret itself never crosses the wire and a
;;; recorded proof cannot be replayed against a fresh nonce:
;;;   acceptor -> (challenge <nonce-a> <version> <bootid-A>)
;;;   dialer   -> (hello <name-D> <proof-D> <nonce-b> <version>
;;;                      <bootid-D> <dial-gen>)
;;;   acceptor -> (welcome <name-A> <proof-A>)
;;;
;;; where
;;;   proof-D = hmac(secret, nonce-a:name-D:version:bootid-D:dial-gen
;;;                          :name-A:bootid-A)
;;;   proof-A = hmac(secret, nonce-b:name-A:version:bootid-A)
;;;
;;; EACH SIDE STATES ITS BOOT ID IN THE FIRST FRAME IT SPEAKS -- the
;;; acceptor in the challenge, the dialer in the hello -- and the welcome
;;; does not repeat one, because by then each end has the other's. A boot
;;; id is minted once per node-start!, never per connection: the acceptor
;;; both states it and hashes it into the proof it verifies, so a second
;;; spelling would make a node fail to authenticate a peer that answered
;;; it correctly.
;;;
;;; THE DIALER'S PROOF BINDS ITS TARGET, the acceptor's does not bind the
;;; dialer, and that asymmetry is deliberate. proof-D says "I am name-D,
;;; talking to name-A at bootid-A", so a proof collected by one acceptor
;;; is not a proof any other acceptor sharing the secret would accept.
;;; What carries the acceptor's identity in the other direction is three
;;; facts together rather than the digest alone: proof-A binds name-A and
;;; bootid-A so forging it needs the secret; the dialer compares the
;;; welcomed name against the peer IT configured; and nonce-b is fresh.
;;; Binding the dialer into proof-A would add a field and no property.
;;;
;;; A NODE NAME IS A STRING ON THE WIRE over [0-9a-z-], non-empty, AT
;;; MOST 255 CHARACTERS -- wire syntax rather than a local convenience.
;;; The charset is narrower than a symbol can hold, and deliberately: it
;;; makes the colon-joined proof encoding injective with no escaping
;;; rule, and it removes the one place two honest implementations could
;;; disagree about the bytes of a frame. A hyphen is legal anywhere,
;;; first and last position included -- there is no technical reason to
;;; refuse it, and saying so is what stops the next reader from
;;; narrowing it further on taste. The rule is checked where a name is
;;; configured AND where one is claimed in a hello, and it has to be
;;; both: checked only locally, this node would refuse to DIAL a name it
;;; would happily ACCEPT, an asymmetry with no reason behind it and
;;; nothing to say when it bites. The length comes from the handshake
;;; frame budget -- see max-name-length.
;;;
;;; VERSION 4 NARROWED THAT CHARSET, and it is a breaking change at the
;;; API rather than only on the wire: a deployment whose node names carry
;;; uppercase, underscores or dots fails in node-start! at STARTUP, not
;;; as a degraded link later. That is the loud failure on purpose, but it
;;; belongs in the release notes rather than being discovered.
;;;
;;; A NONCE IS EXACTLY 32 LOWERCASE HEXADECIMAL DIGITS. That is wire
;;; syntax, not a description of what this implementation happens to mint:
;;; a peer sending 32 uppercase digits is refused, in both nonce
;;; positions. The narrowing is only legitimate BECAUSE it is written here
;;; -- a rule that lived solely in the code would be an accident from the
;;; outside -- and it is affordable because this wire has no third-party
;;; senders: the mesh is exact-match and upgrades in lockstep, so a peer
;;; spelling nonces differently is another protocol, refused the way a
;;; different version is. A name is a symbol the writer can serialise,
;;; containing no colon.
;;;
;;; The version is STATED in those first two frames -- not negotiated, and
;;; there is no fallback: both ends require strict equality with one
;;; compiled constant. It is bound into
;;; both proofs, so the field cannot be edited on its own; welcome needs no
;;; version slot because by then both ends have stated and agreed one. EVERY
;;; RAISE OF THIS NUMBER IS A BREAK, and two have happened: version 2
;;; introduced the field itself (the pre-versioning handshake -- challenge
;;; of 2, hello of 4 -- is refused in both directions), and version 3
;;; widened the call frame to carry the caller's own timeout. Both were
;;; made while this
;;; layer carried no production traffic, and from here every wire evolution
;;; goes through the version rather than through a shape that older nodes
;;; can only read as garbage. Mismatches are refused with a reason on the
;;; dial side, silently on the accept side -- see protocol-version.
;;;
;;; SECURITY: the dist port is FULL CONTROL of the node -- anyone on it
;;; can message any registered process, including supervisors. The
;;; listener binds 127.0.0.1 unless told otherwise, and there is no TLS:
;;; across machines, keep it on a private network (WireGuard, VPC).
;;;
;;; ---- Design model ----------------------------------------------------
;;;
;;; Four commitments shape the concurrency and distribution layers. They
;;; are deliberate: a review comparing this library to Erlang/OTP or Swish
;;; will find several OTP mechanisms missing, and each absence traces to
;;; one of these. Two of them are this file's own, and are given in full;
;;; the other two live in (igropyr otp) and are summarised here.
;;;
;;; 3. THE NODE MESH IS A CONTROL PLANE: names, small messages,
;;;    fail-closed, slow-is-dead. Registered names cross the wire, pids do
;;;    not. A protocol confusion closes the connection rather than guessing.
;;;    A peer that cannot keep up is treated as dead -- close and reconnect
;;;    -- never paused: pausing a control link delays heartbeats and
;;;    monitor traffic, and turns one slow peer into cascading false
;;;    failures. That is enforced in both directions: inbound by the
;;;    ceilings on what a peer can make this node spawn, outbound by a
;;;    ceiling on bytes queued for a peer that has stopped reading (see
;;;    max-outbound-bytes). Bulk data never rides the control link; it
;;;    gets its own connection.
;;;
;;; 4. THE MESH IS SMALL AND FULLY TRUSTED, AND THAT IS A FEATURE. A shared
;;;    secret, a full mesh, and a modest node ceiling assume a cluster
;;;    administered as one unit and upgraded in lockstep. Scaling is
;;;    processes times machines under that assumption, not a thousand-node
;;;    substrate.
;;;
;;; 1 and 2, in one line each: the failure model is crash-only and the real
;;; supervisor is the service manager outside the process; and a single
;;; scheduler means an in-process supervision tree could not survive the
;;; hardest failure class anyway, since it shares the scheduler with
;;; everything it supervises. See (igropyr otp) for both in full.
;;;
;;; Duplicate connections (both sides dialing at once) are resolved
;;; deterministically: the connection whose DIALER has the smaller node
;;; name survives; both ends apply the same rule, so they converge.

(library (igropyr node)
  (export node-start! node-connect! node-disconnect! node-self
          rsend rcall monitor-node demonitor-node node-peers
          monitor-remote demonitor-remote node-set-limits!
          node-monitor-stats node-outbound-stats reconnect-delay
          submission-failure? node-install-rule-order node-orphan-count
          monitor-node/token demonitor-node/token)
  (import (chezscheme) (igropyr buffer)
          (igropyr actor) (igropyr libuv) (igropyr sexpr)
          (igropyr gen-server)
          (only (igropyr crypto) hmac-sha256 bytevector->hex))

  (define max-frame 8388608)        ; 8 MiB per datum, once authenticated
  ;; Pre-auth, an unauthenticated peer may only send this many bytes per
  ;; frame. The handshake datums -- (challenge n v), (hello name proof n v),
  ;; (welcome name proof) -- are a few hundred bytes; 4 KiB is generous.
  ;; This is the hard cap on how much attacker-chosen input reaches the
  ;; parser before the HMAC is verified, so a stranger cannot make the
  ;; node parse (allocate lists for, intern symbols from, build
  ;; bytevectors out of) a multi-megabyte datum.
  (define handshake-max-frame 4096)

  ;; A NODE NAME IS BOUNDED SO THE HANDSHAKE FRAMES ALWAYS ARE. The name
  ;; is the only variable-length field in hello and welcome, and those two
  ;; are read under handshake-max-frame, so an unbounded name is a node
  ;; that starts, dials, and is refused by every peer for a frame it built
  ;; itself -- the failure appearing at the far end, about a value chosen
  ;; here.
  ;;
  ;; IT IS WIRE SYNTAX, NOT A LOCAL LIMIT, and is enforced on both sides
  ;; for that reason: at node-start! and node-connect! for the names this
  ;; node is given, and in the acceptor for the name a peer claims. A peer
  ;; that is not this implementation could otherwise present a longer name
  ;; with a valid proof and be installed under it, leaving a node that can
  ;; be CONNECTED TO by a name it would refuse to DIAL. Being written down
  ;; in the protocol notes at the top of this file is what makes the
  ;; narrowing legitimate rather than an accident of this implementation
  ;; -- the same argument as the nonce grammar.
  ;;
  ;; The arithmetic, and it holds twice over. Everything else in a hello
  ;; is fixed: tag, a 64-character proof, a 32-character nonce, a small
  ;; version, and the punctuation -- 112 bytes, measured. A wire-safe
  ;; symbol is restricted by the writer to a printable ASCII subset, so
  ;; today a name is one byte per character and 255 of them make a
  ;; 367-byte frame. That margin does not depend on the charset staying
  ;; that way: even if the writer grew full \xNNNNNN; escaping, nine bytes
  ;; per character, this bound yields 2407 bytes and still fits.
  (define max-name-length 255)

  ;; THE WIRE PROTOCOL VERSION. Everything on this link is fail-closed by
  ;; design -- an unknown frame shape drops the connection -- which means a
  ;; peer running older code cannot be told anything, it can only be
  ;; confused. So the version is STATED in the first two frames, before
  ;; there is anything to be confused about, and a mismatch is refused with
  ;; a reason instead of read as a malformed frame. Stated, not negotiated:
  ;; there is no selection and no fallback, only strict equality against
  ;; this one constant. Two nodes either share it or do not connect.
  ;;
  ;; EVERY RAISE OF THIS NUMBER IS A BREAK, and each one was taken
  ;; deliberately at a moment when it was free.
  ;;   2: introduced the field. A node speaking the pre-versioning
  ;;      handshake (challenge of 2, hello of 4) cannot talk to this one in
  ;;      either direction, and cannot be told why -- the unversioned wire
  ;;      is version 1 by convention only; it never carried the field, so
  ;;      nothing can be negotiated with it.
  ;;   3: widened the call frame from four elements to five, adding the
  ;;      caller's timeout (see dispatch!). A v2 and a v3 node cannot
  ;;      interoperate on calls even in principle: to a v2 callee the fifth
  ;;      element is a malformed frame, and a v2 caller's four-element
  ;;      frame is malformed here. Refusing at the handshake is the
  ;;      feature; the alternative is two nodes agreeing on a frame they
  ;;      read differently.
  ;;   4: rebuilt the handshake frames. challenge grows a boot-id slot
  ;;      (arity 4), hello grows the dialer's boot-id and a dial
  ;;      generation (arity 7), and a name crosses the wire as a STRING
  ;;      rather than a symbol. The dialer's proof binds its target as
  ;;      well as itself, so a proof collected by one acceptor cannot be
  ;;      replayed at another. Thirteen separate breaking decisions were
  ;;      collected into this one raise rather than each being smuggled
  ;;      into the shape a v3 node would misread: a version bump is
  ;;      cheap, and a mismatch is refused with a reason, where a shape
  ;;      change is refused as "malformed" and retried forever.
  ;; The first three were made while the distributed layer carried no
  ;; production traffic. From here on every wire evolution goes through
  ;; this number.
  (define protocol-version 4)
  (define handshake-timeout-ms 5000)
  (define tick-ms 15000)            ; heartbeat interval
  (define dead-ms 60000)            ; silence longer than this = dead link
  ;; Reconnect backoff bounds; the delay itself is reconnect-delay.
  (define reconnect-base-ms 3000)
  (define reconnect-max-ms 60000)

  ;; ---- identity ------------------------------------------------------

  (define self-name #f)             ; symbol, set by node-start!
  (define self-secret #f)           ; bytevector

  ;; THIS NODE'S BOOT ID: 16 lowercase hex characters, minted ONCE per
  ;; node-start! and never per connection. It is what lets the other end
  ;; tell "the same node, still up" from "the same name, restarted", and
  ;; both halves of that need it to be stable: the acceptor states it in
  ;; every challenge AND hashes it into every proof it checks, so a value
  ;; that changed per connection would not merely be useless -- the
  ;; acceptor would fail to verify a proof computed over the boot id it
  ;; had just sent. The failure of the per-connection spelling is
  ;; therefore loud here and silent everywhere else, which is the reason
  ;; to say plainly where it is minted.
  (define self-boot-id #f)          ; 16 lowercase hex chars

  ;; DIAL GENERATION: ONE PER AUTHORISATION, ISSUED BY THE REGISTRAR.
  ;;
  ;; It moved here from the dial site, and the move changed what the word
  ;; "monotonic" means rather than merely relocating a counter. Per DIAL
  ;; it would count attempts; per AUTHORISATION it names the epoch a
  ;; connection belongs to -- and one authorisation outlives many
  ;; attempts, because a connector retries under the same permission it
  ;; was already given.
  ;;
  ;; So retries carry the SAME generation, and that has a consequence
  ;; worth stating rather than discovering: a second connection minted
  ;; under one authorisation cannot displace the first, because ordering
  ;; compares generations and equal is not greater. One authorisation,
  ;; one installed connection. A NEW generation is issued only when the
  ;; authorisation itself is replaced -- the endpoint changed, the
  ;; connector died, the peer was disconnected.
  ;;
  ;; Numbering starts at 1 per peer: generations are only ever compared
  ;; against another generation for the SAME peer under the same boot id,
  ;; so two peers both starting at 1 is not a collision.
  (define dial-gens (make-eq-hashtable))

  ;; ---- the registrar's authorisation table ---------------------------
  ;;
  ;; ONE WRITER, MANY READERS. The registrar is the only process that
  ;; writes this table; an attempt only reads it, and only ever CONSUMES
  ;; the one row addressed to itself. That split is what lets the check
  ;; and the commit share an atomic region without either of them being a
  ;; message round trip: an attempt that had to ask the registrar
  ;; "may I still?" would have to `receive`, and `receive` parks -- so the
  ;; answer could go stale between the reply and the connect, which is
  ;; the hole this arrangement exists to close.
  ;;
  ;; A row is IMMUTABLE and consumed by replacing it whole, after
  ;; re-reading the table and confirming it is still the same object.
  ;; Setting a "consumed" bit in place would look equivalent and is not:
  ;; between reading the row and writing the bit, a revocation could have
  ;; replaced the row, and the write would then mark the NEW row as
  ;; consumed -- authorising the old attempt and cancelling the new one
  ;; in a single step. Whole replacement plus an eq? recheck is a real
  ;; compare-and-swap; a mutable bit is not one.
  ;;
  ;; auth-record = #(endpoint parent child gen consumed?)
  (define peers-auth (make-eq-hashtable))
  (define (auth-endpoint r) (vector-ref r 0))
  (define (auth-parent r)   (vector-ref r 1))
  (define (auth-child r)    (vector-ref r 2))
  (define (auth-gen r)      (vector-ref r 3))
  (define (auth-consumed? r)(vector-ref r 4))

  ;; The domain is unsigned 64-bit. Exhausting it locally is a
  ;; fail-stop: there is no correct value left to send, and continuing
  ;; would mean reusing one. That is the exact opposite of what a peer's
  ;; out-of-range value earns -- see the hello reader, where an untrusted
  ;; number is a protocol refusal and must never become a node-level
  ;; stop, or one malformed frame from anywhere would end this node.
  (define dial-gen-limit (expt 2 64))

  ;; EXHAUSTION IS NOT A HANDSHAKE FAILURE, and saying so takes its own
  ;; value. Every exception raised inside dial! is caught by a guard whose
  ;; job is "retry later" -- which is right for a refused proof and wrong
  ;; here, where retrying means either reusing a generation or dialling
  ;; this peer forever without ever sending a valid one. An
  ;; assertion-violation raised here was swallowed exactly like a bad
  ;; proof and the peer simply never came up, with nothing said. So the
  ;; condition carries a token the handshake guards re-raise, the way
  ;; 'stop already is, and the connector stops rather than looping.
  ;;
  ;; WHAT THIS IS NOT: the specification calls local exhaustion a NODE
  ;; fail-stop, and this is a connector-level stop plus a loud report --
  ;; there is no node-wide stop primitive at this layer to call. The
  ;; difference is recorded rather than papered over; escalating it is a
  ;; design decision, not an implementation one. What is settled is the
  ;; part that was actually wrong: it is no longer silent, and it no
  ;; longer retries.
  ;;
  ;; ATOMIC, because read-increment-write is not. Endpoint replacement
  ;; spawns the new connector before killing the old one, so two of them
  ;; can exist at once; a preemption between the read and the write would
  ;; hand both the same generation, which is the one thing this counter
  ;; exists to prevent.
  (define dial-gen-exhausted (list 'dial-gen-exhausted))

  ;; The current epoch's generation, minting one if this peer has none.
  ;; Called only by the registrar, so the read-modify-write needs no
  ;; region of its own -- but it keeps one anyway, because "only the
  ;; registrar calls it" is a fact about today's callers and the counter
  ;; would be silently wrong if that stopped being true.
  (define (peer-gen peer)
    (or (atomically (hashtable-ref dial-gens peer #f))
        (next-dial-gen! peer)))

  (define (next-dial-gen! peer)
    (let ((n (atomically
               (let ((n (+ 1 (hashtable-ref dial-gens peer 0))))
                 (if (>= n dial-gen-limit)
                     #f
                     (begin (hashtable-set! dial-gens peer n) n))))))
      (unless n
        (display (string-append
                   "igropyr node: dial generations for peer "
                   (symbol->string peer)
                   " are exhausted; this node cannot dial it again without"
                   " reusing one. The connector for it is stopping.\n")
                 (current-error-port))
        (raise dial-gen-exhausted))
      n))

  (define (node-self) self-name)

  ;; ---- shared tables --------------------------------------------------
  ;; Mutated from several green processes: every multi-step update runs
  ;; with interrupts disabled so preemption cannot interleave them (the
  ;; same discipline as the actor registry).

  ;; node-name -> #(conn link-pid dialer-name)
  (define peers (make-eq-hashtable))
  ;; node-name -> #(connector-pid host port). The endpoint is part of the
  ;; value because a node keeps its name across a move: keyed on name
  ;; alone, a connector for the OLD address counts as "already dialing"
  ;; and retries it forever after the new one is published.
  (define connectors (make-eq-hashtable))
  ;; node-name -> list of watcher pids
  (define watchers (make-eq-hashtable))
  ;; rcall ref -> waiting caller pid (this node is the caller)
  (define pending (make-eqv-hashtable))
  (define rcall-counter 0)
  (define (next-rcall-ref!)
    (atomically (set! rcall-counter (+ rcall-counter 1)) rcall-counter))

  ;; cross-node process monitors. On the WATCHER node:
  ;;   rmonitors: mref -> #(caller node name)   (for demonitor + the
  ;;              noconnection synthesized when the link to node drops)
  ;;   caller-agents: mref -> agent pid         (self-watch only)
  ;;   owner-agents: mref -> agent pid          (cleans up when caller dies)
  ;; On the TARGET node:
  ;;   callee-agents: (peer . mref) -> agent pid  (one local monitor per
  ;;              remote watch; killed on demon). Keyed by (peer . mref)
  ;;              because mref is chosen by the watcher's own counter, so
  ;;              two watchers collide on it -- the pair namespaces them.
  (define rmonitors (make-eqv-hashtable))
  (define caller-agents (make-eqv-hashtable))
  (define owner-agents (make-eqv-hashtable))
  (define callee-agents (make-hashtable equal-hash equal?))
  (define mref-counter 0)
  (define (next-mref!)
    (atomically (set! mref-counter (+ mref-counter 1)) mref-counter))

  (define-syntax atomically
    (syntax-rules ()
      ((_ body ...) (with-interrupts-disabled body ...))))

  ;; ---- inbound backpressure -------------------------------------------
  ;; A remote (call ...) spawns a process to serve it; a remote (mon ...)
  ;; spawns a long-lived monitor agent. Both are driven purely by frames
  ;; the peer sends, so without a ceiling one buggy or hostile -- but
  ;; authenticated -- member could make this node spawn processes without
  ;; bound. Two global caps hold the line (see dispatch!):
  ;;   - serve-rcall processes in flight: over the cap the call is SHED,
  ;;     answered at once with (error overload) so the caller fails fast
  ;;     rather than hanging (queuing is pointless -- rcall has its own
  ;;     timeout, and a held slot is a parked process either way).
  ;;   - hosted monitors (callee-agents): over the cap the monitor is
  ;;     REFUSED with (mdown ... overload).
  ;; Those two bound what an AUTHENTICATED member can make this node do.
  ;; A COUNT OF SLOTS IS ONLY HALF OF THAT BOUND, though: concurrency is
  ;; leases times how long each is held, so the first of them is paired
  ;; with a ceiling on the time one call may occupy a slot --
  ;; serve-timeout-cap-ms, just below. Without it the count bounds how
  ;; many calls run at once and nothing bounds how long, which a peer
  ;; chooses. (Memory queued for a peer that stops READING is a third
  ;; quantity again, and has its own ceiling -- see max-outbound-bytes.)
  ;; A stranger gets a third:
  ;;   - handshakes in flight: over the cap the connection is CLOSED in
  ;;     the accept callback, without answering and without spawning --
  ;;     a stranger must not be able to make this node create a process.
  ;; Per connection the pre-auth cost was already bounded (4 KiB of parse
  ;; input, one absolute deadline), but nothing bounded how many of them
  ;; could be held at once, and each is an fd as well as a process. The fd
  ;; budget belongs to the OS process and is shared with every other
  ;; listener the program runs, so exhausting it here is not contained to
  ;; the mesh.
  ;; Generous by default -- a ceiling on a flood, not a throttle on
  ;; healthy traffic; tune with node-set-limits!.
  (define max-rcall-serving 256)
  (define max-hosted-monitors 4096)

  ;; ---- what the hosting ceiling counts -------------------------------
  ;;
  ;; NOT THE SIZE OF THE TABLE. The table holds the monitors this node is
  ;; currently hosting; the ceiling has to cover everything that is still
  ;; holding a physical process, and those two stop agreeing the moment an
  ;; eviction removes an entry while its agent is still being torn down.
  ;; Counting entries then reads zero for agents that are alive, and the
  ;; ceiling lets another full set in beside them.
  ;;
  ;; The quantity is ACCOUNTED = ACTIVE + RETIRING:
  ;;   active   -- has an entry in the table;
  ;;   retiring -- entry already removed, agent's DOWN not yet seen.
  ;; and the rule is `accounted <= cap`. The bound is stated apart from
  ;; the definition on purpose: folding it in makes the quantity and its
  ;; limit read as two definitions of one thing.
  ;;
  ;; RETIRING IS DERIVED, NOT COUNTED, and the reason the second term
  ;; never acquired a writer is worth keeping rather than quietly
  ;; dropping: it is not a missing addend. A permit is taken when a
  ;; monitor is armed and returned when its agent's DOWN arrives, and it
  ;; spans both phases -- active while the node is on its peer's chain,
  ;; retiring after an eviction has spliced that chain away. Eviction
  ;; moves nodes between the phases without changing the total, which is
  ;; why the splice can never fail: it asks for nothing.
  ;;
  ;; So this counter is `accounted` outright, and the split into active
  ;; and retiring is read off the two chains when somebody asks (see
  ;; mon-phase-counts). Keeping two counters would mean decrementing one
  ;; and incrementing the other for every node of a spliced chain, inside
  ;; the region -- the linear cost the chain arrangement exists to avoid.
  (define active-monitors 0)

  ;; The table used to hold a bare pid. It holds a record now because
  ;; idempotence is a question about the whole request, not about the key:
  ;; the name being watched and the connection the request arrived on are
  ;; both part of what the agent was built from, so both have to be
  ;; comparable when the same reference is offered again.
  ;; THE RECORD IS THE CHAIN NODE. Two chains run through the same
  ;; objects, and they answer two different questions:
  ;;
  ;;   the per-peer chain -- "everything this peer parked here", so that
  ;;   evicting a peer is one pointer operation rather than a scan;
  ;;   the global chain -- "everything hosted", so that a reaper coming
  ;;   back can walk it in bounded chunks and re-establish its watches.
  ;;
  ;; They are two JOBS, not two copies. A path that unlinks from one and
  ;; not the other leaks, and leaks without a symptom -- so unlinking
  ;; happens in exactly one procedure rather than at each call site.
  ;;
  ;; Node identity is never reused: a record is built once, for one
  ;; monitor, and is not recycled after it retires. That is what removes
  ;; the ABA question a token would otherwise have to answer.
  (define (make-agent-rec pid name conn key peer)
    (vector pid name conn key peer #f #f #f #f))
  (define (agent-pid r)  (vector-ref r 0))
  (define (agent-name r) (vector-ref r 1))
  (define (agent-conn r) (vector-ref r 2))
  (define (agent-key r)  (vector-ref r 3))
  (define (agent-peer r) (vector-ref r 4))
  (define (agent-pnext r) (vector-ref r 5))   ; per-peer chain
  (define (agent-pprev r) (vector-ref r 6))
  (define (agent-gnext r) (vector-ref r 7))   ; global chain
  (define (agent-gprev r) (vector-ref r 8))
  (define (agent-pnext-set! r v) (vector-set! r 5 v))
  (define (agent-pprev-set! r v) (vector-set! r 6 v))
  (define (agent-gnext-set! r v) (vector-set! r 7 v))
  (define (agent-gprev-set! r v) (vector-set! r 8 v))
  (define (agent-matches? r conn name)
    (and (eq? (agent-conn r) conn) (eq? (agent-name r) name)))

  ;; The per-peer heads. Present only while that peer has something
  ;; parked -- the same rule the orphan chain follows, and for the same
  ;; reason: a table that keeps a row per name ever seen is the structure
  ;; this design already refused, and it needs somebody to clean it.
  ;;
  ;; NOT ON THE PEERS ENTRY, deliberately. Living there would be cheaper,
  ;; but an entry is replaced whole, and replacing it is an implicit
  ;; destruction of whatever hangs on it. A hosted monitor retires by its
  ;; key, through retire-agent!, and does not travel with the entry -- so
  ;; its chain must not either.
  (define mon-heads (make-eq-hashtable))
  (define mon-chain #f)                        ; global chain head

  ;; Region-safe: pointer writes only, no allocation, no table growth
  ;; except the per-peer head row -- which is why arming takes the ceiling
  ;; decision first and this second.
  (define (mon-link! r)
    (let ((ph (hashtable-ref mon-heads (agent-peer r) #f)))
      (agent-pnext-set! r ph)
      (when ph (agent-pprev-set! ph r))
      (hashtable-set! mon-heads (agent-peer r) r))
    (agent-gnext-set! r mon-chain)
    (when mon-chain (agent-gprev-set! mon-chain r))
    (set! mon-chain r))

  ;; THE ONLY PLACE A NODE LEAVES A CHAIN. Both chains, always, in one
  ;; call: "unlink from both" is then a property of the structure rather
  ;; than something every caller has to remember.
  ;;
  ;; The two halves are separable on purpose -- eviction takes a whole
  ;; per-peer chain out in one operation and then walks it -- so each half
  ;; is idempotent and safe to call on a node already out of that chain.
  ;;
  ;; ⭐ SECOND TIME IN THIS FILE that a property is bought by collapsing
  ;; call sites rather than by asking each of them to behave: retire-agent!
  ;; did it for "the count comes down in one place". Said once so the
  ;; pattern reads as a decision rather than a coincidence -- when a rule
  ;; has to hold at every call site, the cheapest way to make it hold is
  ;; to leave one call site.
  (define (mon-unlink-peer! r)
    (let ((n (agent-pnext r)) (p (agent-pprev r)))
      (if p (agent-pnext-set! p n)
            (when (eq? (hashtable-ref mon-heads (agent-peer r) #f) r)
              (if n
                  (hashtable-set! mon-heads (agent-peer r) n)
                  (hashtable-delete! mon-heads (agent-peer r)))))
      (when n (agent-pprev-set! n p))
      (agent-pnext-set! r #f)
      (agent-pprev-set! r #f)))

  (define (mon-unlink-global! r)
    (let ((n (agent-gnext r)) (p (agent-gprev r)))
      (if p (agent-gnext-set! p n) (when (eq? mon-chain r) (set! mon-chain n)))
      (when n (agent-gprev-set! n p))
      (agent-gnext-set! r #f)
      (agent-gprev-set! r #f)))

  (define (mon-unlink! r)
    (mon-unlink-peer! r)
    (mon-unlink-global! r))

  ;; EVICTION IS ONE POINTER OPERATION. The whole of a peer's chain leaves
  ;; in a single step and the head row goes with it; the nodes are dealt
  ;; with afterwards, outside, where the scheduler can interrupt. Sending
  ;; each agent its notice inside the region would put a walk proportional
  ;; to one peer's parked monitors in a place nothing can interrupt, which
  ;; is exactly the shape a peer could aim at by parking as many as the
  ;; ceiling allows.
  ;;
  ;; The nodes stay on the GLOBAL chain, deliberately -- and it is worth
  ;; being precise about WHEN that matters, because the ordinary path does
  ;; not depend on it. An evicted agent gets its notice, exits, and the
  ;; reaper returns its permit from the DOWN; none of that reads the chain,
  ;; so removing them from it here would leave every ordinary run green.
  ;;
  ;; It matters when a reaper is replaced while these nodes are still
  ;; retiring. The new one rebuilds its watches by walking the global
  ;; chain, and a node that is on neither chain is one it can never find:
  ;; its DOWN would go to a process that no longer exists, and its permit
  ;; would never come back. So the property is real and its only witness
  ;; is the restart path.
  ;;
  ;; Being on the global chain and not on a peer's is the state this design
  ;; calls retiring.
  ;;
  ;; -> the first node, or #f. Caller walks it via agent-pnext.
  (define (mon-splice-peer! peer)
    (let ((head (hashtable-ref mon-heads peer #f)))
      (when head (hashtable-delete! mon-heads peer))
      head))

  ;; Retiring: on the global chain, off its peer's. Derived rather than
  ;; counted, because the alternative is decrementing one counter and
  ;; incrementing another for every node of a spliced chain -- inside the
  ;; region, which is the O(N) this arrangement exists to avoid.
  ;;
  ;; ⭐ BEING DERIVED IS ALSO WHY EVICTION CANNOT FAIL, and that is the
  ;; part worth guarding. There is no retiring table, so there is no
  ;; insertion into one, so there is nothing on that path that allocates
  ;; and nothing that can raise for want of memory. Storing the phase
  ;; instead -- a set of retiring nodes, say -- would put a failable
  ;; allocation back inside the splice, and a splice that can fail is a
  ;; cleanup that can fail, which is the shape this design refused.
  ;;
  ;; ⚠ THE DESIGN NOTE ON THIS SAYS SOMETHING ELSE, and it would go on
  ;; saying it. Its argument is that each admitted monitor pre-pays the
  ;; slot it will need at retirement, so eviction always has room. That
  ;; is true and it is not what makes eviction infallible here: paying in
  ;; advance answers "cannot afford it", and having nothing to pay for
  ;; answers something stronger. Anyone changing this to a stored phase
  ;; would find the design still vouching for a property their change
  ;; had just removed.
  ;; BOTH NUMBERS FROM ONE WALK. Two walks would each be honest and the
  ;; pair could still be impossible -- a node retiring between them counts
  ;; in neither, and the sum stops matching the permit count. The claim
  ;; being checked from outside is that eviction moves nodes between the
  ;; two phases WITHOUT changing their total, and a pair taken at two
  ;; instants cannot check that.
  ;;
  ;; -> (values active retiring)
  (define (mon-phase-counts)
    (let loop ((r mon-chain) (a 0) (t 0))
      (cond
        ((not r) (values a t))
        ((or (agent-pprev r)
             (eq? (hashtable-ref mon-heads (agent-peer r) #f) r))
         (loop (agent-gnext r) (fx+ a 1) t))
        (else (loop (agent-gnext r) a (fx+ t 1))))))

  ;; For assertions from outside: how many nodes each chain holds.
  (define (mon-chain-length)
    (let loop ((r mon-chain) (n 0)) (if r (loop (agent-gnext r) (fx+ n 1)) n)))
  (define (mon-peer-chain-length peer)
    (let loop ((r (hashtable-ref mon-heads peer #f)) (n 0))
      (if r (loop (agent-pnext r) (fx+ n 1)) n)))

  ;; THE ONE PLACE THE COUNT COMES BACK DOWN, and it is one place on
  ;; purpose: a quantity with several decrement sites is a quantity whose
  ;; conservation nobody can check by reading.
  ;;
  ;; THE CALLER IS THE REAPER, on the DOWN it observes -- not the agent on
  ;; its own way out. An agent that is killed does not run its exit branch
  ;; and one that hangs never reaches it; in both cases the permit would
  ;; never come back.
  ;;
  ;; It reached that shape in two steps, and the order was deliberate: the
  ;; three inline deletions were collapsed here BEFORE the reaper existed,
  ;; so that "the count comes down in one place" was true from that moment
  ;; rather than becoming true later. What the reaper changed was who
  ;; calls this, not how many places decrement.
  ;; ---- the reaper, and the one process that keeps it alive ----------
  ;;
  ;; THE CREDIT COMES BACK ON A DOWN, NOT ON AN EXIT BRANCH. An agent that
  ;; is killed never runs its own cleanup and one that hangs never reaches
  ;; it; in both cases the count would stay up for a process that is gone
  ;; or going. A watcher outside the agent sees both, so the return lives
  ;; there.
  ;;
  ;; The reaper holds its own pid -> key index because a DOWN carries only
  ;; a pid. That index is PRIVATE and rebuildable: a restarted reaper walks
  ;; the global chain and re-establishes every watch.
  ;;
  ;; THE REBUILD IS SELF-HEALING, and it is worth saying why, because it
  ;; removes a failure that would otherwise be permanent. `monitor`
  ;; delivers DOWN immediately for a process that is already dead, so an
  ;; agent that died while no reaper was running is not lost: re-watching
  ;; it produces its DOWN at once and the credit comes back. Without that,
  ;; every death inside a reaper outage would leak a permit forever. That
  ;; is a property of the runtime rather than of this file.
  ;; THE REAPER IS FOUND BY NAME, NEVER BY A CACHED PID. A pid held
  ;; anywhere outside the warden goes stale the moment the reaper is
  ;; replaced, and the holder then talks to a corpse without any
  ;; indication that it is doing so. Looking the name up each time costs a
  ;; hashtable read on a path that runs once per armed monitor, and it
  ;; makes "there is no reaper right now" a value the caller can see
  ;; rather than a silence it cannot.
  ;;
  ;; The name is also the only handle anything outside has: a test that
  ;; wants to prove the warden can rebuild has to be able to kill the
  ;; reaper, and killing it is the only way to test that claim rather than
  ;; argue it. That makes this name part of what this file promises, not
  ;; an accident of the implementation.
  (define reaper-name 'igropyr-node-reaper)
  (define (reaper-pid) (whereis reaper-name))

  (define reaper-warden #f)
  ;; The warden carries a registered name for the same reason its child
  ;; does: the two branches below that report a mistake can only be shown
  ;; to work by a harness that can put a message in front of them, and a
  ;; guard nobody can reach is a sentence, not a mechanism.
  (define warden-name 'igropyr-node-warden)
  (define reaper-chunk 64)

  ;; Re-establish watches from the global chain, in bounded pieces.
  ;;
  ;; RESTARTS FROM THE HEAD EACH CHUNK rather than carrying a cursor. A
  ;; cursor into a chain other processes are unlinking from can be left
  ;; pointing at a node whose next pointer has been cleared, and the walk
  ;; would then stop early and silently leave the rest unwatched. Starting
  ;; over is quadratic in the worst case and correct under concurrent
  ;; unlinking; this runs only when a reaper restarts, so the cheaper
  ;; version would buy speed on a path that almost never executes at the
  ;; cost of a correctness question on the path that matters.
  (define (reaper-rescan! watched)
    (let outer ()
      (let ((fresh
             (let scan ((r (atomically mon-chain)) (n 0) (acc (list)))
               (cond
                 ((not r) (reverse acc))
                 ((fx= n reaper-chunk) (reverse acc))
                 ((hashtable-ref watched (agent-pid r) #f)
                  (scan (atomically (agent-gnext r)) n acc))
                 (else
                  (scan (atomically (agent-gnext r)) (fx+ n 1)
                        (cons (cons (agent-pid r) (agent-key r)) acc)))))))
        (unless (null? fresh)
          (for-each (lambda (pk)
                      ;; index first: monitor may deliver the DOWN before it
                      ;; returns, and that DOWN has to find the key
                      (hashtable-set! watched (car pk) (cdr pk))
                      (monitor (car pk)))
                    fresh)
          (outer))))
    ;; THE SECOND CHAIN. A replacement reaper has to rebuild both, and
    ;; only one of them used to exist -- so "the reaper was restarted"
    ;; would have said nothing about the leases it inherited.
    ;;
    ;; Monitoring a process that is already dead delivers its DOWN at
    ;; once, so a holder that died while no reaper was running is
    ;; collected here rather than being missed: the rescan is what makes
    ;; the announcement message a shortcut instead of the mechanism.
    (let outer ()
      (let ((fresh
             (let scan ((x (atomically leases)) (n 0) (acc (list)))
               (cond
                 ((not x) (reverse acc))
                 ((fx= n reaper-chunk) (reverse acc))
                 ((or (not (lease-pid x))
                      (hashtable-ref watched (lease-pid x) #f))
                  (scan (atomically (lease-next x)) n acc))
                 (else
                  (scan (atomically (lease-next x)) (fx+ n 1)
                        (cons (lease-pid x) acc)))))))
        (unless (null? fresh)
          (for-each (lambda (pid)
                      (hashtable-set! watched pid #f)   ; #f: leases only
                      (monitor pid))
                    fresh)
          (outer)))))

  (define (reaper-loop)
    ;; THE INDEX BELONGS TO THIS INCARNATION, so it is created here rather
    ;; than beside the other module state.
    ;;
    ;; It used to live at module scope with a comment calling it private,
    ;; and the comment was the only thing making it so. A replacement
    ;; reaper inherited the table its predecessor had filled in -- while
    ;; the monitors that table described had died with the process that
    ;; held them. The rescan then found every pid already indexed, skipped
    ;; every one of them, and established no watches at all: the reaper
    ;; was running, its index looked complete, and no DOWN would ever
    ;; arrive again. Nothing reported it except credit that stopped
    ;; coming back.
    ;;
    ;; Clearing the table on entry would have fixed that instance. Scoping
    ;; it to the process fixes the class: a new reaper cannot see the old
    ;; one's index, because there is no longer anywhere for it to persist.
    (let ((watched (make-eq-hashtable)))
      (register reaper-name self)
      (reaper-rescan! watched)
      (let loop ()
        (receive
          (`#(watch ,pid ,key)
            ;; A pid already watched for one reason keeps its key: the
            ;; DOWN below runs BOTH sweeps regardless of why it was
            ;; indexed, so arriving twice costs nothing and losing the
            ;; key would cost an agent.
            (unless (hashtable-ref watched pid #f)
              (hashtable-set! watched pid key))
            (monitor pid)
            (loop))
          (`#(DOWN ,pid ,reason)
            ;; BOTH SWEEPS, ALWAYS. One process can be an agent and hold
            ;; leases, or hold two leases of different kinds; deciding
            ;; which sweep to run from how the pid happened to be indexed
            ;; would give back one resource and quietly keep the other.
            (let ((key (hashtable-ref watched pid #f)))
              (hashtable-delete! watched pid)
              (when key (retire-agent! key)))
            (lease-retire-owner! pid)
            (loop))
          (`#(node-stop) (void))))))

  ;; THE WARDEN DOES THREE THINGS AND MAY NEVER DO A FOURTH: monitor the
  ;; reaper, spawn a replacement, and let the replacement rescan. Anything
  ;; added here has to pass the critical bar again, because this process is
  ;; critical and its death stops the node.
  ;;
  ;; WHAT IS FAIL-STOP HERE IS THE WARDEN, NOT THE REAPER. The design says
  ;; a reaper failure must not take the node down, and it still does not --
  ;; it is restarted. What cannot be recovered from is losing the thing
  ;; that restarts it, and that is a dozen lines with no business logic in
  ;; them. This is a trade rather than a removal: the risk moves from a
  ;; process that runs with the workload to one that runs only when the
  ;; first one dies. Recorded as a residue, not as a fix.
  ;; A SUPERVISOR THAT ONLY EVER RESTARTS HAS NO WAY TO SAY "I CANNOT FIX
  ;; THIS". Recovery hides the difference between a reaper that died once
  ;; and one that cannot start at all: the second becomes a quiet loop
  ;; whose only symptom is that credit stops coming back, with no crash
  ;; visible anywhere. That is the failure mode this whole design treats
  ;; as the worst one, arrived at by adding the thing meant to prevent
  ;; failures.
  ;;
  ;; So three rules, and none of them is optional:
  ;;   - back off, so a tight failure cannot spin the scheduler;
  ;;   - count within a window, and give up when the count says the
  ;;     problem is not transient -- giving up here means raising, and
  ;;     this process is critical, so the node stops loudly;
  ;;   - say every restart out loud, with the count, so a node that is
  ;;     limping is visible before it reaches the limit.
  (define child-restart-window-ms 60000)
  (define child-restart-max 5)
  (define child-restart-cap-ms 1000)

  ;; ---- the warden ------------------------------------------------------
  ;;
  ;; IT MONITORS A LIST OF CHILDREN, RESTARTS THEM, AND LETS EACH ONE
  ;; REBUILD ITSELF. Three verbs, and it may never acquire a fourth: this
  ;; process is critical, so anything added here has to earn that again.
  ;; Going from one child to several changed how many things it watches
  ;; and not what it does with them, which is why the bar it was held to
  ;; still holds.
  ;;
  ;; What is fail-stop here is the warden, never a child. A child failing
  ;; is recovered from; losing the thing that recovers is not, and that
  ;; thing is a page with no business logic in it.
  ;;
  ;; EACH CHILD IS THROTTLED SEPARATELY. A shared count would let a healthy
  ;; child's restarts dilute a sick one's, and the give-up rule -- so many
  ;; deaths inside a window means the problem is not transient -- would
  ;; then never fire for the child that actually cannot start.
  ;;
  ;; A child spec is #(name start-thunk consequence), where consequence is
  ;; the sentence an operator needs: what stops working while this child
  ;; is down. It is part of the spec rather than the message so that
  ;; giving up names the child that gave up -- a precise fail-stop
  ;; reported under the wrong name is worse than none.
  (define (child-name c) (vector-ref c 0))
  (define (child-thunk c) (vector-ref c 1))
  (define (child-consequence c) (vector-ref c 2))

  (define (warden-loop specs)
    (let* ((v (list->vector specs))
           (n (vector-length v))
           (pids (make-vector n #f))
           (deaths (make-vector n (list)))
           (delays (make-vector n 0)))
      (define (start! i)
        (let ((p (spawn (child-thunk (vector-ref v i)))))
          (vector-set! pids i p)
          (monitor p)))
      (define (index-of p)
        (let loop ((i 0))
          (cond ((fx= i n) #f)
                ((eq? (vector-ref pids i) p) i)
                (else (loop (fx+ i 1))))))
      (register warden-name self)
      (let init ((i 0)) (when (fx< i n) (start! i) (init (fx+ i 1))))
      (let loop ()
        (receive
          (`#(DOWN ,p ,reason)
            (let ((i (index-of p)))
              (if (not i)
                  ;; A DOWN for something we are not managing. It costs
                  ;; nothing to handle and it says our dispatch is wrong,
                  ;; so it gets said out loud: a silent branch here would
                  ;; turn a bookkeeping bug into a state that never shows
                  ;; up anywhere -- no error, no loss, just a warden that
                  ;; has quietly stopped watching something.
                  (display (string-append
                             "igropyr node: warden saw a DOWN from a process "
                             "it does not manage (" (claimed-version-text reason)
                             "); this means a child was started or replaced "
                             "outside the warden\n")
                           (current-error-port))
                (let* ((spec (vector-ref v i))
                       (nm (symbol->string (child-name spec)))
                       (now (now-ms))
                       (recent (cons now
                                     (filter (lambda (t)
                                               (> t (- now child-restart-window-ms)))
                                             (vector-ref deaths i))))
                       (k (length recent)))
                  (vector-set! deaths i recent)
                  (display (string-append
                             "igropyr node: " nm " exited ("
                             (claimed-version-text reason)
                             "); restart " (number->string k) " of at most "
                             (number->string child-restart-max) " in "
                             (number->string (quotient child-restart-window-ms 1000))
                             "s\n")
                           (current-error-port))
                  (when (fx>= k child-restart-max)
                    (display (string-append
                               "igropyr node: " nm " has not stayed up "
                               (number->string k)
                               " restarts running; this is not transient and "
                               (child-consequence spec)
                               ". Stopping the node.\n")
                             (current-error-port))
                    (raise (list 'child-will-not-start (child-name spec) k)))
                  (let ((d (vector-ref delays i)))
                    (when (fx> d 0) (sleep-ms d))
                    (vector-set! delays i
                      (fxmin child-restart-cap-ms
                             (if (fx= d 0) 50 (fx* d 2)))))
                  (start! i))))
            (loop))
          ;; EVERY CHILD, not the first one. Missing one here produces no
          ;; symptom at all: a child outlives the node's shutdown and
          ;; nothing is watching for that.
          (`#(node-stop)
            (let stop ((i 0))
              (when (fx< i n)
                (let ((p (vector-ref pids i)))
                  (when (and p (process-alive? p)) (send p (vector 'node-stop))))
                (stop (fx+ i 1)))))
          ;; Anything else. THIS CLAUSE MUST STAY LAST: it is a bare
          ;; identifier, which match-msg treats as a catch-all, so moving
          ;; it up one line silently swallows every clause below it. The
          ;; clause list is source order and there is nowhere to hang an
          ;; assertion on it, so this sentence is the whole guard -- if
          ;; the warden ever grows a third message, add it above here.
          ;;
          ;; Without this clause an unrecognised message is
          ;; not an error -- it simply stays in the mailbox, and the next
          ;; one after it, forever. That is a leak whose only symptom is
          ;; memory, which is to say no symptom at all until it is large.
          (other
            (display "igropyr node: warden discarded an unrecognised message\n"
                     (current-error-port))
            (loop))))))

  ;; Undo a half-finished install. THE CALLER HOLDS THE REGION, and that
  ;; is the whole reason this is allowed to exist.
  ;;
  ;; The design refused "exception-safe undo" once already, and the
  ;; refusal was right: the objection recorded against it is that a
  ;; compensating action is hand-written and can fail on its own, leaving
  ;; a worse state than the one it was cleaning up. THIS ONE ESCAPES THAT
  ;; OBJECTION, and the escape has to be written down or the next reader
  ;; will apply the old refusal to it unchanged. Both actions here are
  ;; allocation-free: hashtable-delete! cannot grow a table, mon-unlink!
  ;; is pointer writes plus at most an existing-key update or a delete,
  ;; and kill of a process nothing is watching sends nothing.
  ;;
  ;; ⭐ "NOTHING IS WATCHING IT" IS NOT A CLAIM ABOUT TIMING. The whole
  ;; install runs in one region, and the reaper is told about the new
  ;; agent only after that region is left. So at the moment this runs,
  ;; nothing outside has had the opportunity to do anything at all --
  ;; not because it happens to be early, but because nothing else has
  ;; run. Move the guard that calls this outside the region and that
  ;; argument is gone: another link could read the half-installed entry,
  ;; be told the monitor is armed, and then have it deleted underneath.
  ;;
  ;; It never touches the count. The increment is the last step of the
  ;; install and cannot raise, so reaching it means the install
  ;; succeeded; nothing that gets here has been counted.
  (define (undo-install! key p)                  ; caller already holds the region
    (let ((cur (hashtable-ref callee-agents key #f)))
      (when (and cur p (eq? (agent-pid cur) p))
        (hashtable-delete! callee-agents key)
        (mon-unlink! cur)))
    (when (and p (process-alive? p)) (kill p 'install-failed)))

  (define (retire-agent-locked! key)             ; caller already holds the region
    (let ((r (hashtable-ref callee-agents key #f)))
      (when r
        (hashtable-delete! callee-agents key)
        (mon-unlink! r)
        (set! active-monitors (fx- active-monitors 1)))))

  (define (retire-agent! key)
    (atomically (retire-agent-locked! key)))

  (define (accounted-monitors) active-monitors)
  (define max-preauth-conns 256)

  ;; The callee's own ceiling on how long it will serve one remote call.
  ;; The caller states its timeout in the call frame and this node honours
  ;; the SMALLER of the two: a caller may ask this node for less work than
  ;; it is willing to do, never for more.
  ;;
  ;; WHAT THE FIELD CARRIES IS A DURATION, NOT A DEADLINE, and the two are
  ;; not the same promise. The callee starts counting when the frame
  ;; ARRIVES, so time the frame spent in a queue is not subtracted: a call
  ;; stated at five seconds that waited four in an outbound queue can be
  ;; served until nine, four seconds after its caller gave up. A deadline
  ;; would be the stronger statement and this wire cannot make it -- it
  ;; would have to be an absolute time, and there is no clock these two
  ;; nodes share. So the field bounds the callee's wait against the
  ;; caller's intent, and does not synchronise the two ends' clocks.
  ;;
  ;; BOTH HALVES ARE LOAD-BEARING, and they fail in opposite directions.
  ;; Without the stated field the callee waits a fixed default and
  ;; abandons a legitimately slow call while its caller is still waiting
  ;; for it -- the caller then gets an error for work that was proceeding,
  ;; which is the worse failure because nothing about it looks like a
  ;; timeout policy. Without the cap the field is a lever: a peer parks
  ;; one of the max-rcall-serving leases for as long as it likes by
  ;; stating as long a timeout as it likes.
  ;;
  ;; WHAT THIS DOES NOT DO: it bounds how long this node WAITS, not how
  ;; long the gen-server runs. A server that overruns goes on running with
  ;; nobody waiting for it, exactly as it does for a local caller that
  ;; times out. That is gen-server-call's contract, not a gap here.
  (define serve-timeout-cap-ms 60000)

  ;; ---- admission leases -------------------------------------------------
  ;;
  ;; A SLOT HAS AN OWNER. These two ceilings used to be bare integers:
  ;; they recorded how many were in use and not who was using them, so
  ;; nothing could ever reconcile them. A process killed while holding one
  ;; took it away permanently, and the counter drifts in one direction
  ;; only -- down -- which presents as a node that sheds every remote call
  ;; as overload while looking perfectly healthy. Nothing can be built on
  ;; top of a count with no owner; the reaper below has no one to watch
  ;; and no way to know how much to give back.
  ;;
  ;; The link is a field of the slot record, not an entry in a table.
  ;; A hashtable insert can rehash, rehashing allocates, and allocation
  ;; raises -- inside a region, which is exactly the residual already on
  ;; the ledger for the orphan index. Adding a new instance of a defect
  ;; while its family is being counted is not a trade worth making. Two
  ;; pointer writes join a chain and cannot fail.
  ;; The ceiling counts SLOTS; a LEASE is one process's holding of one.
  ;; The record is named for the holding rather than the unit because the
  ;; holding is what has an owner, and having an owner is the entire
  ;; point of it. (`slot` is also already this file's wire-field
  ;; accessor, which is how the name collision announced itself.)
  (define-record-type lease
    (fields kind (mutable pid) (mutable next) (mutable on?)))

  (define leases #f)                       ; the chain: THE truth
  (define leases-serving 0)                ; O(1) caches of its length, by kind
  (define leases-preauth 0)

  ;; The chain is authoritative and the counters are a cache of it -- that
  ;; is a different thing from two fields checking each other, which has
  ;; no truth in it. The reaper acts on the chain; if a count disagrees,
  ;; the count is what is wrong, and node-monitor-stats reports both so
  ;; that disagreement is visible rather than inferred.
  (define (lease-bump! kind d)
    (case kind
      ((serving) (set! leases-serving (fx+ leases-serving d)))
      ((preauth) (set! leases-preauth (fx+ leases-preauth d)))))

  (define (lease-count kind)
    (case kind ((serving) leases-serving) ((preauth) leases-preauth) (else 0)))

  (define (lease-chain-length kind)         ; the truth, walked
    (let loop ((x leases) (n 0))
      (cond ((not x) n)
            ((eq? (lease-kind x) kind) (loop (lease-next x) (fx+ n 1)))
            (else (loop (lease-next x) n)))))

  (define (lease-attach! s)                 ; caller holds the region
    (lease-next-set! s leases)
    (lease-on?-set! s #t)
    (set! leases s)
    (lease-bump! (lease-kind s) 1))

  ;; CONDITIONAL, and by the identity of THIS RECORD. Same shape as
  ;; qhead-done!: the removal happens only if the record is still on the
  ;; chain, so a second release reports #f instead of taking somebody
  ;; else's slot away. And it is the record that is removed, never "this
  ;; pid's record" -- one process can hold a serving slot and a pre-auth
  ;; slot at the same time, and deleting by owner would take both. That
  ;; is not a hypothetical: demonitor-node deleted watcher entries by
  ;; bare pid and removed the token subscriptions sitting beside them.
  ;; The same mistake, with a different resource's name on it.
  (define (lease-detach! s)                 ; caller holds the region
    (and (lease-on? s)
         (let loop ((prev #f) (x leases))
           (cond
             ((not x) #f)
             ((eq? x s)
              (if prev (lease-next-set! prev (lease-next x)) (set! leases (lease-next x)))
              (lease-next-set! s #f)
              (lease-on?-set! s #f)
              (lease-bump! (lease-kind s) -1)
              #t)
             (else (loop x (lease-next x)))))))

  (define (lease-free! s) (atomically (lease-detach! s)))

  ;; Give back every lease this process was holding. ONE AT A TIME, and by
  ;; walking to find them: the alternative -- subtracting however many the
  ;; owner is thought to have held -- needs a second record of that number
  ;; and would be wrong the moment the two disagree. Retiring by identity
  ;; cannot over-return.
  ;;
  ;; Only the reaper looks a lease up by owner, and only because the owner
  ;; is dead: everything it was holding must come back. Every other path
  ;; releases the record it was given.
  (define (lease-retire-owner! pid)
    (atomically
      (let loop ((x leases) (n 0))
        (if (not x)
            n
            (let ((next (lease-next x)))
              (if (eq? (lease-pid x) pid)
                  (begin (lease-detach! x) (loop next (fx+ n 1)))
                  (loop next n)))))))

  ;; Tell the reaper to watch a new holder. A lost message costs nothing:
  ;; the lease is on the chain, and a reaper that restarts rescans it.
  ;; The message is a shortcut, not the mechanism.
  (define (lease-announce! p)
    (let ((rp (reaper-pid)))
      (when rp (send rp (vector 'watch p #f)))))

  ;; Admit one holder, or refuse. Returns the new process, or #f.
  ;;
  ;; ⭐ THE SPAWN IS INSIDE THE REGION, AND THAT IS THE WHOLE POINT: while
  ;; this process holds interrupts off, the child it just created cannot
  ;; be scheduled, so there is no instant at which a slot exists with no
  ;; owner recorded, and none at which a child is serving before it is
  ;; known to have been admitted. Taking the slot first and spawning
  ;; afterwards -- which is what this used to do -- is two commits with a
  ;; gap between them; spawning first and checking the ceiling afterwards
  ;; is worse still, because the child can start serving before anyone
  ;; has decided it may.
  ;;
  ;; ⚠ THIS IS ONLY SAFE BECAUSE INTERRUPT REGIONS NOW UNWIND. The spawn
  ;; is the one thing left in here that allocates, and allocation raises.
  ;; Before that change, a raise in here would have left this process's
  ;; interrupt count high and its preemption off for good -- silently.
  ;; Anyone tempted to give this region back the faster non-unwinding
  ;; form would be turning an out-of-memory into a process that never
  ;; runs again.
  ;;
  ;; The pre-check outside is an optimisation and nothing more: it keeps
  ;; a flood from allocating a record and a process per refused call.
  ;; ⛔ THE CHECK INSIDE THE REGION IS THE ONLY AUTHORITY. The one out
  ;; here can be wrong in both directions, and simplifying it into the
  ;; only check would move the ceiling out of the one place where it is
  ;; ordered against everything else.
  ;;
  ;; The residual, stated: between the two checks a slot can free up, so
  ;; a call is occasionally refused that would have fit, and a record and
  ;; a process are occasionally built for a call that is then refused.
  ;; Neither leaks; both are bounded by the race window.
  (define (lease-admit! kind cap body)
    (let ((p (lease-admit-locked! kind cap body)))
      ;; Outside the region: it allocates a message, and the region is
      ;; the one place that must not.
      (when p (lease-announce! p))
      p))

  (define (lease-admit-locked! kind cap body)
    (and (fx< (lease-count kind) cap)
         (let ((s (make-lease kind #f #f #f)))   ; (R0) built outside
           (atomically
             (and (fx< (lease-count kind) cap)
                  (let ((p (spawn (lambda () (body s)))))
                    (lease-pid-set! s p)
                    (lease-attach! s)
                    p))))))


  ;; ---- outbound backpressure -------------------------------------------
  ;; The ceilings above bound what a peer can make this node DO. This one
  ;; bounds what a peer can make this node HOLD.
  ;;
  ;; A write that cannot go out now is copied into a foreign block and
  ;; parked in libuv's write queue, and nothing on that path has a
  ;; ceiling -- so a peer that stops reading (a process wedged rather than
  ;; dead, a machine frozen rather than down, a member stalling on
  ;; purpose) turns every frame this node sends it into retained memory.
  ;; TCP's own flow control stops the KERNEL buffer from growing; it does
  ;; nothing about ours behind it. NOR DOES dead-ms: that clock measures
  ;; silence FROM the peer, and a peer that keeps sending while never
  ;; reading is not silent, so that clock never fires: it can hold the
  ;; link open for as long as it keeps sending, while the queue grows.
  ;;
  ;; PER CONNECTION, NOT PER PEER, and the difference is the point. A
  ;; per-peer quota has to be keyed on a node name, and a node name is a
  ;; CLAIM made during a handshake: frames written to a peer that has not
  ;; finished handshaking (challenge, welcome) would be unbilled or billed
  ;; to a name the far end chose. A connection is a physical thing this
  ;; node holds a file descriptor for. It cannot be forged, it exists
  ;; before any name does, and it is what the queued memory actually hangs
  ;; off.
  ;;
  ;; Over the ceiling the connection is CLOSED, never paused -- the same
  ;; slow-is-dead rule the rest of this link follows. Pausing a control
  ;; link delays heartbeats and monitor traffic and turns one slow peer
  ;; into cascading false failures; closing costs a peer that is merely
  ;; slow a redial, after which it has a fresh link with an empty queue.
  (define max-outbound-bytes 16777216)   ; 16 MiB queued per connection

  ;; conn -> bytes charged and not yet completed.
  ;;
  ;; AN ENTRY IS CREATED BY THE FIRST WRITE ON A CONNECTION AND REMOVED
  ;; WHEN THAT CONNECTION CLOSES -- deliberately not when its count
  ;; returns to zero. Zero is the ordinary resting state of a healthy
  ;; link, so deleting there would make the entry count follow traffic
  ;; rather than connections, and would mean re-registering the close hook
  ;; on every quiet moment. Removal is owned by the resource: a killed
  ;; writer runs no winders, so cleanup that hung off control flow here
  ;; would be skipped exactly when it is needed.
  (define outbound (make-eq-hashtable))

  ;; Charge n bytes to c, creating its entry if this is the first write.
  ;; -> #t if THIS charge is what put the connection over the ceiling.
  ;;
  ;; THE ENTRY AND THE HOOK THAT REMOVES IT ARE ONE UNINTERRUPTIBLE STEP.
  ;; Written as two -- store, leave the atomic section, then register --
  ;; a kill landing between them leaves an entry nothing will ever remove:
  ;; a kill in this system DISCARDS the victim's winders rather than
  ;; running them, so no cleanup owned by this procedure's control flow
  ;; survives it, and the writer never reaches tcp-writev! either, so not
  ;; one refund is ever issued against the charge. The connection then
  ;; carries a permanent phantom balance; later writers find the entry
  ;; already present and do not re-register the hook; and the close that
  ;; should have swept it finds an empty cleanup slot. node-outbound-stats
  ;; reports the phantom for the life of the node, and a connection that
  ;; starts its life that much closer to the ceiling can be closed for
  ;; backpressure under traffic it could carry. This is the hazard
  ;; arm-rmonitor! is written against, and it takes the same answer: keep
  ;; interrupts off across both halves.
  ;;
  ;; REGISTERING AFTER THE STORE, inside the section, is also what makes
  ;; an already-closed connection come out right. conn-on-close! runs its
  ;; thunk immediately when the handle is already closed, so the entry
  ;; just written is deleted again before the section ends -- which is the
  ;; correct state: tcp-writev! is about to refuse the write and refund
  ;; against an account that should not exist. (The reverse order deletes
  ;; nothing and then writes the entry, which is the leak above by another
  ;; route.)
  ;;
  ;; The verdict is returned from inside the section rather than read back
  ;; afterwards. Between the two a completion can refund the bytes and put
  ;; the count under the ceiling again, so a caller that re-read it would
  ;; miss the excursion it just caused -- the ceiling would then catch
  ;; only a peer that is slow at the instant we happen to look.
  ;;
  ;; conn-on-close! holds ONE thunk per connection. This library is its
  ;; only user on the connections it owns (TLS uses it on TLS connections,
  ;; which this layer neither creates nor writes to); a second user here
  ;; would silently displace this one.
  (define (outbound-charge! c n)
    (atomically
      (let* ((cur (hashtable-ref outbound c #f))
             (v (+ (or cur 0) n)))
        (hashtable-set! outbound c v)
        (unless cur (conn-on-close! c (lambda () (outbound-forget! c))))
        (> v max-outbound-bytes))))

  ;; Refund n bytes. A missing entry is not an error: the connection
  ;; closed while this write was in flight and its account is already
  ;; gone. Silently doing nothing is right, and creating an entry here
  ;; with a negative count would be wrong.
  (define (outbound-discharge! c n)
    (atomically
      (let ((cur (hashtable-ref outbound c #f)))
        (when cur (hashtable-set! outbound c (- cur n)))))
    (void))

  ;; Runs in libuv callback context (conn-on-close!): no yielding, no
  ;; parking, no raising. A table delete under disabled interrupts is all
  ;; of that.
  (define (outbound-forget! c)
    (atomically (hashtable-delete! outbound c))
    (void))

  ;; Is this connection over its ceiling right now? A read, not a charge:
  ;; it is how a link process notices a ceiling that was crossed by
  ;; somebody else's write, or that was itself lowered underneath a
  ;; connection already above the new value.
  (define (outbound-over? c)
    (atomically
      (let ((cur (hashtable-ref outbound c #f)))
        (and cur (> cur max-outbound-bytes)))))

  ;; The live outbound account: how many connections have an entry, and
  ;; how many bytes they hold between them.
  ;;
  ;; Exported for the same reason as node-monitor-stats: without it the
  ;; mechanism has no reader. A refund that never runs shows up as a link
  ;; that closes for backpressure under traffic it was handling fine an
  ;; hour ago -- a leak wearing the mask of the ceiling working -- and
  ;; there is no way to tell those apart from outside except by watching
  ;; the count return to its baseline when the traffic stops.
  (define (node-outbound-stats)
    (atomically
      (let ((total 0))
        (vector-for-each (lambda (v) (set! total (+ total v)))
                         (hashtable-values outbound))
        (list (cons 'conns (hashtable-size outbound))
              (cons 'bytes total)))))

  ;; ---- the peers entry ----------------------------------------------
  ;;
  ;; SIX FIELDS BEHIND NAMES, and the names are the point. The entry used
  ;; to be a bare three-slot vector read as `(vector-ref e 0)` all over
  ;; this file -- and three other tables (rmonitors, connectors, the
  ;; rsend-error report) are ALSO vectors read the same way, so a
  ;; mechanical widening of "slot 0" would have edited them too. Naming
  ;; the accessors makes the peers entry a type the reader can see, and
  ;; leaves the other vectors visibly untouched.
  ;;
  ;; The entry is IMMUTABLE and replaced whole. That is not a style
  ;; choice: the replacement sequence's atomic region swaps peers[name]
  ;; in place precisely so the name never goes absent, and a mutable
  ;; entry would let a reader see a half-updated one instead.
  (define (make-entry conn link dialer boot-id gen head)
    (vector conn link dialer boot-id gen head))
  (define (entry-conn e)    (vector-ref e 0))
  (define (entry-link e)    (vector-ref e 1))   ; the link process
  (define (entry-dialer e)  (vector-ref e 2))   ; who dialled, for tie-break
  (define (entry-boot-id e) (vector-ref e 3))   ; the peer's boot id, or #f
  (define (entry-gen e)     (vector-ref e 4))   ; its dial generation, or #f
  (define (entry-head e)    (vector-ref e 5))   ; topology queue head slot

  ;; ---- the per-peer topology queue ------------------------------------
  ;;
  ;; ONE QUEUE PER PEER, AND IT LIVES ON THE PEER'S ENTRY. Every producer
  ;; of a topology event -- a replacement, a real death, a first install
  ;; -- appends at its own linearisation point, so the order a consumer
  ;; sees inside one peer is the order the transitions happened in. The
  ;; ordering promise is per peer; nothing here claims one across peers.
  ;;
  ;; THE HEAD IS BUILT WITH THE ENTRY, never on first use. A head created
  ;; lazily means the enqueue that finds none has to CREATE one, and
  ;; creating one inside the swap region is a container growth: it can
  ;; allocate, it can rehash, and it can raise -- inside a region that
  ;; does not roll back. Building it with the entry, outside, turns every
  ;; later enqueue into two pointer writes.
  ;;
  ;; THE HEAD IS NOT AN EVENT IDENTITY. It is a long-lived container that
  ;; outlives the entries it hangs on -- it survives replacement, it
  ;; survives the peer's death while events are still undelivered, and it
  ;; is adopted again if the peer comes back. Anything that has to say
  ;; "this exact event completed" needs its own per-event object; reusing
  ;; the head for that would make a completion match a later event that
  ;; merely shares the container. Same argument as the fair-ring node,
  ;; and they are separate roles for the same reason.
  ;; THE CUT TRAVELS WITH THE EVENT. It used to be an argument to the
  ;; drain, which was possible only because the process that queued the
  ;; event was also the one that delivered it. A dispatcher that finds
  ;; the event later was not there when the watcher list was read, and
  ;; re-reading it at delivery time would be a different list: watchers
  ;; that subscribed after the event happened would receive it. The
  ;; snapshot has to be part of the event or the rule "you are told
  ;; about what happened while you were watching" has no owner.
  (define-record-type qnode
    (fields event (mutable next) (mutable cut)))

  ;; `onext` is the head's OWN link into the global orphan chain. A
  ;; separate chain cell would have to be allocated at the moment of
  ;; handover -- and that handover happens inside the atomic region that
  ;; removes the peer, where an allocation that raises would leave the
  ;; entry gone and the queue unreachable, with the peer's own death
  ;; notice still in it. Carrying the link in the head removes the
  ;; allocation rather than pre-arranging one, so the failure it guards
  ;; against cannot occur.
  ;; `rnext` is the head's own link into the ready chain, for the same
  ;; reason `onext` is its link into the orphan chain: the moment a head
  ;; becomes ready is inside a region that must not allocate. The two
  ;; chains are separate because a head can be on both at once and they
  ;; answer different questions -- the orphan chain says "the entry that
  ;; held this is gone", the ready chain says "there is undelivered work
  ;; in here". `ronq` is the membership flag; without it, pushing a
  ;; second event would link the head to itself.
  (define-record-type qhead
    (fields (mutable first) (mutable last) (mutable onext) (mutable oname)
            (mutable rnext) (mutable ronq)))

  (define (new-qhead) (make-qhead #f #f #f #f #f #f))

  ;; Splice a PRE-BUILT node. Two writes, no allocation, no growth: safe
  ;; to call from inside an atomic region.
  (define (qhead-push! h n)
    (if (qhead-last h)
        (qnode-next-set! (qhead-last h) n)
        (qhead-first-set! h n))
    (qhead-last-set! h n))

  ;; TAKING AND FINISHING ARE TWO STEPS, and keeping them apart is the
  ;; whole point. A single pop hands the event over and forgets it in one
  ;; motion, so a delivery that dies after the pop and before the send
  ;; takes the event with it -- silently, because nothing is left to say
  ;; anything was ever queued. Peeking leaves the event in place; it is
  ;; removed only once a delivery has been made and says so.
  ;;
  ;; The confirmation is CONDITIONAL: the node just delivered is removed
  ;; only if it is still at the front. Two deliverers can otherwise
  ;; overlap -- one resumes after another has already finished the same
  ;; head and moved on -- and an unconditional pop would then discard the
  ;; NEXT event, which nobody delivered. Comparing the object rather than
  ;; a position is what makes that check exact, and it is why a node is
  ;; never reused for a second event.
  ;;
  ;; The cost is duplicates: dying between the delivery and the
  ;; confirmation means the next deliverer sends the same event again.
  ;; That is the trade this design took deliberately -- a repeat can be
  ;; absorbed by the consumer, a loss cannot be reconstructed by anyone.
  ;; Stamp and load in one motion, because the two have to happen in the
  ;; same region as the push and there is no valid state where a node is
  ;; queued carrying one and not the other.
  (define (stamp-qnode! n cut) (stamp-event! (qnode-event n)) (qnode-cut-set! n cut) n)

  (define (qhead-peek h) (qhead-first h))

  (define (qhead-done! h n)
    (when (eq? (qhead-first h) n)
      (qhead-first-set! h (qnode-next n))
      (unless (qhead-first h) (qhead-last-set! h #f))
      (qnode-next-set! n #f)
      #t))

  (define (qhead-empty? h) (not (qhead-first h)))

  ;; ---- the ready chain ---------------------------------------------------
  ;;
  ;; THE LIST OF HEADS THAT HOLD UNDELIVERED WORK. It exists so that the
  ;; question "is there anything to deliver" has an answer that outlives
  ;; the process asking it. A dispatcher's mailbox cannot be that answer:
  ;; a mailbox dies with its process, and the events it was told about
  ;; would then be sitting in heads nobody knows to look at.
  ;;
  ;; Same shape as the orphan chain and for the same reason -- the link
  ;; is a field of the head, so joining costs two pointer writes and no
  ;; allocation, which is what lets it happen inside the region that
  ;; queued the event.
  (define ready #f)                       ; qhead | #f

  (define (ready-attach! h)
    (unless (qhead-ronq h)
      (qhead-rnext-set! h ready)
      (qhead-ronq-set! h #t)
      (set! ready h)))

  (define (ready-detach! h)
    (let loop ((prev #f) (x ready))
      (cond
        ((not x) #f)
        ((eq? x h)
         (if prev (qhead-rnext-set! prev (qhead-rnext x)) (set! ready (qhead-rnext x)))
         (qhead-rnext-set! x #f)
         (qhead-ronq-set! x #f)
         #t)
        (else (loop x (qhead-rnext x))))))

  ;; PUSHING AND BECOMING READY ARE ONE ACT. As two calls they could be
  ;; separated by a later edit, and a head holding an event while off the
  ;; ready chain is precisely the failure this arrangement exists to
  ;; remove: the container is there and nobody will ever look inside it.
  ;; There is no caller that wants one without the other.
  (define (qhead-enqueue! h n cut)
    (qhead-push! h (stamp-qnode! n cut))
    (ready-attach! h))

  ;; THE ORPHAN CHAIN EXISTS ONLY WHILE SOMETHING IS ON IT. It is a bare
  ;; pointer, not a table keyed by peer name: a table would be the
  ;; O(number of names ever seen) structure this design already refused,
  ;; and it would need somebody to clean it. A chain is empty when the
  ;; last head leaves it, with nothing to sweep. The cost is that finding
  ;; one peer's head is a walk -- bounded by the number of peers that are
  ;; dead AND still undrained at the same instant, which is the smallest
  ;; set any of these arrangements could be walked over.
  (define orphans #f)                     ; qhead | #f

  (define (orphan-attach! h name)         ; region-safe: pointer writes only
    (qhead-oname-set! h name)
    (qhead-onext-set! h orphans)
    (set! orphans h))

  ;; Unlink and return this peer's orphaned head, or #f. Used by the
  ;; install path to adopt it back, and by the dispatcher to drop a head
  ;; that has emptied -- "only while non-empty" is enforced by actually
  ;; removing it, not by a flag saying it is gone.
  ;; Read-only: is this peer's head on the chain? Separated from the
  ;; unlink so the install path can decide WHICH head the new entry will
  ;; carry before it changes anything -- see the ordering note there.
  (define (orphan-find name)
    (let loop ((h orphans))
      (cond ((not h) #f)
            ((eq? (qhead-oname h) name) h)
            (else (loop (qhead-onext h))))))

  (define (orphan-detach! name)
    (let loop ((prev #f) (h orphans))
      (cond
        ((not h) #f)
        ((eq? (qhead-oname h) name)
         (if prev (qhead-onext-set! prev (qhead-onext h))
                  (set! orphans (qhead-onext h)))
         (qhead-onext-set! h #f)
         (qhead-oname-set! h #f)
         h)
        (else (loop h (qhead-onext h))))))

  ;; EXPORTED, because "the orphan chain is empty again" is a claim that
  ;; has to be checkable from outside. The chain exists only while some
  ;; dead peer still has undelivered events; a build that leaked heads
  ;; onto it would behave correctly in every other respect and grow
  ;; without bound, which is precisely the failure nothing else would
  ;; report. Reading it is O(chain), and the chain is empty on an idle
  ;; system.
  (define (node-orphan-count)
    (atomically
      (let loop ((h orphans) (n 0)) (if h (loop (qhead-onext h) (fx+ n 1)) n))))

  (define (peer-entry name)
    (atomically (hashtable-ref peers name #f)))

  (define (live-entry name)
    (let ((e (peer-entry name)))
      (and e (eq? (conn-state (entry-conn e)) 'open) e)))

  (define (node-peers)
    (filter live-entry
            (vector->list (atomically (hashtable-keys peers)))))

  ;; Live sizes of the cross-node monitor tables. Every entry is an active
  ;; watch: rmonitors is what this node is watching elsewhere, callee-agents
  ;; what it hosts for others, and the two agent tables are the processes
  ;; keeping those honest. All four must return to their baseline once the
  ;; watches they belong to have ended -- an entry that outlives its monitor
  ;; is retained forever, since nothing sweeps them.
  ;;
  ;; Exported because that is otherwise unobservable: a leak here shows up
  ;; only as a long-lived node growing, with no way to attribute it. It is
  ;; also what lets a test assert reclamation rather than just delivery.
  (define (node-monitor-stats)
    (atomically
      (list (cons 'rmonitors (hashtable-size rmonitors))
            (cons 'caller-agents (hashtable-size caller-agents))
            (cons 'owner-agents (hashtable-size owner-agents))
            (cons 'callee-agents (hashtable-size callee-agents))
            ;; THE TWO CHAINS, SEPARATELY, because the failure this
            ;; makes visible is asymmetric. A node on the global chain but
            ;; not its peer's is the DESIGNED middle of an eviction: the
            ;; reaper still sees it, so its DOWN will arrive. A node on a
            ;; peer chain but not the global one is the opposite -- the
            ;; reaper can never see it, its credit never comes back, and
            ;; nothing else reports it. One number covering both would
            ;; hide exactly the direction that matters.
            (cons 'mon-chain (mon-chain-length))
            (cons 'mon-peer-chains
                  (let-values (((ks vs) (hashtable-entries mon-heads)))
                    (let loop ((i 0) (n 0))
                      (if (fx= i (vector-length ks)) n
                          (loop (fx+ i 1)
                                (fx+ n (mon-peer-chain-length
                                         (vector-ref ks i))))))))
            ;; THE TWO ADMISSION CEILINGS, each reported twice: the cached
            ;; count and the chain walked. A ceiling with no reading at
            ;; all is what these were until now -- the counters existed,
            ;; nothing published them, and the failure they drift into
            ;; (a node refusing every remote call while healthy) had
            ;; therefore no observable at all. Reporting the cache beside
            ;; the walk is what makes a drift between them a fact somebody
            ;; can assert rather than infer from behaviour.
            (cons 'serving-slots leases-serving)
            (cons 'serving-slots-walked (lease-chain-length 'serving))
            (cons 'preauth-slots leases-preauth)
            (cons 'preauth-slots-walked (lease-chain-length 'preauth))
            ;; active and retiring come from ONE walk, so their sum can be
            ;; compared against the permit count meaningfully: the property
            ;; worth checking is that eviction moves nodes between the two
            ;; without changing the total.
            (let-values (((a t) (mon-phase-counts)))
              (cons 'phases (list (cons 'active a) (cons 'retiring t))))
            (cons 'accounted (accounted-monitors))
            ;; watcher PIDS, not names: the leak this exists to make
            ;; visible is pids piling up under one name, which a count of
            ;; names cannot show.
            (cons 'watchers
                  (let ((total 0))
                    (vector-for-each
                      (lambda (l) (set! total (+ total (length l))))
                      (hashtable-values watchers))
                    total)))))

  ;; ---- node up/down notification --------------------------------------

  ;; REGISTRATION IS THE SECOND MOMENT THE LIST IS IN HAND. notify! already
  ;; drops dead pids, but only for a name that has an event; a watcher that
  ;; died under a name which never goes up or down was never swept at all.
  ;; Sweeping here closes that, and closes it in the same atomic section
  ;; that does the memq, so no pid is judged alive in one step and inserted
  ;; in another.
  ;;
  ;; WHAT REMAINS, and the shape of it is PER NAME. A dead watcher under a
  ;; name that has no event and no further registration stays in the
  ;; table. Sweeping happens at two moments -- an event for that name, a
  ;; registration for that name -- and both are scoped to one name, so
  ;; nothing here reclaims a name that is never touched again.
  ;;
  ;; AN EARLIER VERSION OF THIS PARAGRAPH SAID THE TABLE IS BOUNDED BY ITS
  ;; OWN HISTORICAL PEAK. That is false, and measurably so in two
  ;; different directions:
  ;;   - across names: registering and killing one watcher under each of
  ;;     five distinct quiet names leaves five stored pids, while at most
  ;;     one was ever alive;
  ;;   - within one name: twenty processes may each monitor the same quiet
  ;;     name and all die, and twenty pids are retained. The per-name
  ;;     residue is the largest watcher population that name has held
  ;;     since its last sweep, not one.
  ;; The reasoning that produced the false claim was that growth requires
  ;; a registration and a registration sweeps -- true, and it sweeps only
  ;; the name being registered, which is the half that was not written
  ;; down.
  ;;
  ;; This is left as an accepted residue rather than repaired, because a
  ;; global sweep would put a whole-table scan on the registration path.
  ;; It is a residue and NOT a bound: nothing here caps the table. Names
  ;; come from the application, so an application with a finite set of
  ;; node names has a finite table, and one that mints names has not.
  (define (monitor-node name)
    (atomically
      (let ((l (filter (lambda (w) (process-alive? (w-pid w)))
                       (hashtable-ref watchers name (list)))))
        (hashtable-set! watchers name
          ;; DEDUPLICATION IS WITHIN THE VARIANT, NOT ACROSS IT. Asking
          ;; only "has this process subscribed" makes the answer depend on
          ;; which call came first: a process that took a token and then
          ;; asked for the older subscription was told it already had one,
          ;; got void back, and had nothing. The same two calls in the
          ;; other order produced both. Two orders disagreeing is not a
          ;; choice of semantics -- it is neither of them.
          (if (find (lambda (w) (and (eq? (w-pid w) self) (not (w-token w))))
                    l)
              l
              (cons (make-legacy-watcher self) l)))))
    (void))

  ;; THE TOKEN VARIANT, added beside the old call rather than replacing
  ;; it. A caller that never asks for a token sees nothing change: same
  ;; procedure, same return value, same message. A caller that does gets
  ;; back an object it must keep, and every message for that subscription
  ;; carries it.
  ;;
  ;; SUBSCRIBING AGAIN STARTS A NEW GENERATION -- it does not hand back the
  ;; token you already had. The point of the token is to tell this
  ;; subscription's messages from a previous one's, and returning the old
  ;; object would make those two indistinguishable, which is the single
  ;; thing it exists to prevent.
  (define (monitor-node/token name)
    (let ((tok (new-sub-token name)))
      (atomically
        (let ((l (filter (lambda (w) (process-alive? (w-pid w)))
                         (hashtable-ref watchers name (list)))))
          (hashtable-set! watchers name
            (cons (make-token-watcher self tok)
                  ;; a previous generation of THIS process's token
                  ;; subscription is replaced, not accumulated
                  (filter (lambda (w)
                            (not (and (eq? (w-pid w) self) (w-token w))))
                          l)))))
      tok))

  ;; Removes exactly the subscription that token names, and nothing else:
  ;; a process may hold several, and may also hold a legacy one alongside.
  ;;
  ;; ONE ARGUMENT, ON PURPOSE. Taking the name as well would let a caller
  ;; pass a name that does not match the token, and the call would then do
  ;; nothing at all with no way to tell -- a new silent failure introduced
  ;; to save a lookup. The token carries its own name instead, so there is
  ;; nothing for a caller to get wrong and no table to scan.
  ;;
  ;; ⚠ EXPLICIT PREMISE: holding the token IS the authority to end that
  ;; subscription. Tokens are not meant to be passed around, and nothing
  ;; here enforces that -- a process given someone else's token can
  ;; unsubscribe them. Said out loud because it is the kind of assumption
  ;; that is obvious to whoever wrote it and invisible afterwards.
  (define (demonitor-node/token tok)
    (unless (sub-token? tok)
      (assertion-violation 'demonitor-node/token
        "want a token returned by monitor-node/token" tok))
    (let ((name (sub-token-name tok)))
      (atomically
        (hashtable-set! watchers name
          (filter (lambda (w) (not (eq? (w-token w) tok)))
                  (hashtable-ref watchers name (list))))))
    (void))

  ;; REMOVES THE LEGACY SUBSCRIPTION AND NOTHING ELSE. Matching on the pid
  ;; alone took a token subscription of the same process with it --
  ;; silently, and in the direction hardest to notice: the caller asked for
  ;; its old subscription to end and it did, so the visible half was
  ;; exactly right. What went with it was a subscription whose holder still
  ;; has a token and simply never hears anything again.
  ;;
  ;; ⭐ The shape is worth naming: a defect that does MORE than it was
  ;; asked passes every check that only asks whether the requested thing
  ;; happened.
  (define (demonitor-node name)
    (atomically
      (hashtable-set! watchers name
        (filter (lambda (w)
                  (not (and (eq? (w-pid w) self) (not (w-token w)))))
                (hashtable-ref watchers name (list)))))
    (void))

  ;; Fan out to a snapshot taken by the caller. The replacement sequence
  ;; needs this: its cut has to happen inside the atomic region that
  ;; swaps the entry, or a watcher that finishes registering between the
  ;; read and the swap misses the pair permanently -- not late, missing.
  ;; Reading the list here instead would be exactly that read.
  ;; ---- what a subscriber gets ----------------------------------------
  ;;
  ;; ONE PLACE DECIDES THE SHAPE OF A NOTIFICATION, and that is why this
  ;; is a procedure rather than two sends in two branches. The older
  ;; subscription has to keep receiving exactly what it always received --
  ;; a two-element vector -- while the newer one receives a wider message.
  ;; Two code paths would each be correct on the day they were written and
  ;; would drift on the day one of them was edited; one dispatch point
  ;; cannot drift against itself.
  ;;
  ;; Fifth time in this file that a property is bought by leaving exactly
  ;; one call site rather than asking every call site to behave: one
  ;; decrement, one unlink, one number, one removal, one message shape.
  ;; Same family each time -- remove the second supplier instead of
  ;; strengthening the assertion.
  (define (notify-one! w name what seq)
    (let ((p (w-pid w)))
      (if (process-alive? p)
          (send p (if (w-token w)
                      ;; The wider message exists so a holder can tell a
                      ;; message meant for THIS subscription from one left
                      ;; over by a previous one, and an old delivery from a
                      ;; current one. Both questions are asked by the
                      ;; receiver, so both answers travel with the message.
                      (vector what name (w-token w) seq)
                      ;; Unchanged, and it has to stay unchanged: the
                      ;; SHAPE an older subscriber receives is exactly the
                      ;; shape it has always received. That is the whole
                      ;; promise, and it is deliberately smaller than it
                      ;; reads -- a new shape that is wrong gets noticed,
                      ;; an old shape that quietly grew a field does not.
                      ;;
                      ;; THE COUNT IS NOT PROMISED. Delivery is at least
                      ;; once: a node is taken off the queue only after it
                      ;; has been handed to everyone, so a dispatcher that
                      ;; dies mid-fan-out is succeeded by one that starts
                      ;; the same node again. A token holder can absorb
                      ;; that -- the token and the sequence number are in
                      ;; its message. This branch carries neither, so an
                      ;; older subscriber has nothing to deduplicate with
                      ;; and WILL see the repeat.
                      ;;
                      ;; The fix is not to widen this vector. Widening it
                      ;; is the exact change the paragraph above forbids,
                      ;; and it would break every existing receiver to
                      ;; spare it a duplicate it can also just tolerate.
                      ;; It is declared instead, and the declaration is
                      ;; carried in the breaking-surface list rather than
                      ;; here, because a consumer decides what to do about
                      ;; it and consumers do not read this file.
                      (vector what name)))
          (drop-watcher! name w))))

  (define (notify-list! l name what seq)
    (for-each (lambda (w) (notify-one! w name what seq)) l))

  ;; ---- watcher entries ------------------------------------------------
  ;;
  ;; A TAGGED SUM, because there are now two kinds of subscription and they
  ;; are not one shape with a field left empty. The older kind has no token
  ;; and never will; the newer kind has one, and that token is what makes a
  ;; stale subscription's messages recognisable to its holder. Writing it
  ;; as "the same record with #f in the token slot" would leave every
  ;; reader to carry the distinction itself, which is where two kinds of
  ;; thing quietly become one.
  ;; A SUBSCRIPTION TOKEN IS AN OBJECT WITH NO NAME, and that is the whole
  ;; requirement. It has to be unrepeatable across the entire span in which
  ;; a late message might still exist -- not merely across the life of the
  ;; subscription, which is the narrower claim that was rejected. A symbol
  ;; would carry a name, and anything with a name can be written down and
  ;; read back; a fresh pair cannot be reconstructed by any reader, so the
  ;; only way to hold one is to have been given it. Comparison is by
  ;; identity, never by contents.
  ;; The name rides along so an unsubscribe can find the right bucket
  ;; without a second table and without asking the caller to remember it
  ;; too. ⚠ It is routing information, never identity: two tokens for the
  ;; same name are different objects and are never equal, because nothing
  ;; ever compares their contents.
  (define (new-sub-token name) (list 'node-subscription name))
  (define (sub-token? x)
    (and (pair? x) (eq? (car x) 'node-subscription) (pair? (cdr x))))
  (define (sub-token-name t) (cadr t))

  ;; ONE COUNTER FOR THE WHOLE NODE, and it is handed out INSIDE the region
  ;; that publishes the event it numbers. A replacement publishes two
  ;; events, and their numbers have to bracket that transition with nothing
  ;; of the same peer's slipping between them -- which they do here for a
  ;; structural reason rather than a remembered one: both nodes were built
  ;; outside and are enqueued in the same region, so their numbers are
  ;; taken in the same uninterruptible turn.
  ;;
  ;; A redelivery reuses the node it was queued in, and the number lives in
  ;; that node, so a replay cannot mint a fresh one. Consumers compare per
  ;; peer, which a globally monotonic sequence satisfies with room to
  ;; spare; the sequence is not a count of anything and no reader may treat
  ;; it as one.
  (define event-seq-counter 0)

  (define (next-event-seq!)                   ; caller holds the region
    (set! event-seq-counter (+ event-seq-counter 1))
    event-seq-counter)

  (define (event-kind e) (vector-ref e 0))
  (define (event-name e) (vector-ref e 1))
  (define (event-seq e)  (vector-ref e 2))
  (define (make-event kind name) (vector kind name #f))
  (define (stamp-event! e)                    ; caller holds the region
    (when (not (vector-ref e 2))
      (vector-set! e 2 (next-event-seq!)))
    e)

  (define (make-legacy-watcher p) (vector 'watcher 'legacy p #f))
  (define (make-token-watcher p tok) (vector 'watcher 'token p tok))
  (define (w-kind w)  (vector-ref w 1))
  (define (w-pid w)   (vector-ref w 2))
  (define (w-token w) (vector-ref w 3))       ; #f on a legacy entry

  (define (drop-watcher! name w)
    (atomically
      (hashtable-set! watchers name
        (remq w (hashtable-ref watchers name (list))))))

  (define (demonitor-dead! name p)
    (atomically
      (hashtable-set! watchers name
        (filter (lambda (w) (not (eq? (w-pid w) p)))
                (hashtable-ref watchers name (list))))))

  ;; ---- framing ----------------------------------------------------------

  ;; one frame: decimal length, newline, body. Serialized here, written
  ;; as one writev, so frames from different processes never interleave.
  ;; Raise unless datum is representable on the wire. Serializing and
  ;; discarding is the honest test: the whitelist lives in
  ;; sexpr->string-extended, and a second copy of it here would be a second
  ;; thing to keep in step.
  (define (wire-check who datum)
    (guard (e (#t (assertion-violation who
                    "message contains data outside the wire whitelist"
                    datum)))
      (sexpr->string-extended datum)
      (void)))

  ;; SERIALIZING AND SUBMITTING ARE SEPARATE BECAUSE THEY FAIL
  ;; DIFFERENTLY. frame-segments raises -- the writer refuses the datum,
  ;; or the frame is over the limit -- while write-body! reports its
  ;; submission by returning. (It is not exception-free: three allocating
  ;; steps sit outside its guard, and it says so where it is defined.
  ;; What matters here is that the failures a CALLER can act on are the
  ;; ones this split moves in front of the publication point.) A caller
  ;; that has to
  ;; publish something before it writes (rcall's pending entry,
  ;; monitor-remote's rmonitors entry, both of which must exist before the
  ;; write because the write is a safe point and the answer can arrive
  ;; first) can therefore do the part that fails BEFORE it publishes, and
  ;; the failure then needs no unwinding at all.
  ;;
  ;; That ordering is not merely tidier than unwinding. An unwind cannot
  ;; be made correct here: between publishing and raising, the link can
  ;; drop, and the teardown path answers the published entry -- delivering
  ;; an rcall-reply, or a remote-down -- so undoing the entry afterwards
  ;; leaves a message in the caller's mailbox that its selective receive
  ;; will never match. For the monitor case it cannot even be drained:
  ;; remote-down carries no mref, so a drain pattern would just as happily
  ;; eat a different monitor's DOWN. Raising before publishing is the only
  ;; version with nothing left over.
  (define (frame-segments datum)
    (let ((body (string->utf8 (sexpr->string-extended datum))))
      ;; NEVER SEND A FRAME THIS IMPLEMENTATION WOULD ITSELF REFUSE. The
      ;; reader drops the connection on an oversized frame -- correctly, it
      ;; cannot know a confused peer from a hostile one -- so writing one
      ;; costs every other conversation on that link, over a payload one
      ;; local caller chose. Refusing here turns that into an error at the
      ;; call site, where the payload is.
      ;;
      ;; NOT raised as 'protocol. That symbol means "the far end is
      ;; confused" and ends the link wherever it is caught; this is the
      ;; near end's own caller passing too much data, and it must read as
      ;; the local mistake it is. rsend and rcall surface it to their
      ;; caller; serve-rcall!'s existing guard turns it into a
      ;; not-serializable reply, which is the same answer it already gives
      ;; a reply that will not go on the wire.
      (when (> (bytevector-length body) max-frame)
        (assertion-violation 'write-frame!
          "message is larger than the wire frame limit"
          (list 'bytes (bytevector-length body) 'limit max-frame)))
      ;; THE WHOLE FRAME IS MATERIALIZED HERE, header included, so that a
      ;; caller which must publish state before writing has nothing left
      ;; that can fail on it except the submission itself. Building the
      ;; header in the submitting procedure would put an allocation after
      ;; the publication point, which is the shape this split exists to
      ;; remove.
      (list (string->utf8
              (string-append (number->string (bytevector-length body)) "\n"))
            body)))

  ;; The single-valued form, for the paths that cannot act on a failed
  ;; submission anyway: ping and pong, the three handshake frames, and
  ;; dispatch!'s overload answers. IT DROPS THE CONDITION ON PURPOSE.
  ;; Each of those has a reader on the far side with its own timeout, so
  ;; a frame that never goes out arrives as silence -- which those paths
  ;; already treat as a dead link -- and there is no second thing this
  ;; node could do with the knowledge. The paths that CAN act on it call
  ;; write-body! directly: rsend and link-write raise, rcall and
  ;; monitor-remote answer their caller.
  (define (write-frame! c datum)
    (let-values (((ok failure) (write-body! c (frame-segments datum))))
      ok))

  ;; The one shape both loud paths raise. It carries the peer the frame
  ;; was for and the original condition, because a bare "it failed" turns
  ;; an out-of-memory into an unexplained one.
  (define (submission-failure peer e)
    (vector 'rsend-error 'submission-failed peer e))

  ;; Submit an already-materialized frame.
  ;; -> (values submitted? failure)
  ;;      #t #f       handed to libuv
  ;;      #f #f       nothing was submitted and no condition was
  ;;                  produced: read as "there is no link"
  ;;      #f <why>    the submission failed and said something about it;
  ;;                  <why> is the condition it raised, or the symbol
  ;;                  'submission-refused when libuv declined without
  ;;                  raising anything to carry
  ;;
  ;; <why> DOES NOT IMPLY THE CONNECTION IS STILL OPEN, and an earlier
  ;; version of this list said it did. A partial write whose remainder
  ;; cannot be queued closes the connection and then raises, so
  ;; (#f . condition) arrives with the connection already gone. The
  ;; connection's state is consulted separately, at the end of this
  ;; procedure, and what it decides there is whether to wake the link --
  ;; not which of these two rows applies.
  ;;
  ;; TWO VALUES AND NOT A THREE-WAY SINGLE ONE, because a condition object
  ;; is TRUE. Every caller written as `(unless (write-body! ...) ...)`
  ;; would read a failed submission as a success, and the reading would
  ;; look right. The shape has to make that mistake impossible to write,
  ;; not merely wrong.
  ;;
  ;; WHY THE TWO FAILURES ARE KEPT APART AT ALL: they are the same event
  ;; to a caller that has published state (rcall, monitor-remote -- both
  ;; answer noconnection either way) and different events to a caller
  ;; that reports upward. #f-with-nothing means the link is gone, which
  ;; is a thing callers reason about and depend on; a failed submission
  ;; on a healthy link is not that, and saying it is was the defect this
  ;; work exists to repair.
  ;;
  ;; THE LINE BETWEEN THEM IS THE CONNECTION'S STATE, NOT WHETHER AN
  ;; EXCEPTION WAS RAISED. An earlier version drew it at the exception,
  ;; and that was wrong in a way worth leaving written down: raising is
  ;; one of TWO ways the layer below reports a failed submission. The
  ;; other is a plain #f -- uv_write declining immediately with a
  ;; negative errno, which frees its block, calls the completion, and
  ;; returns, without raising anything at all. Neither of them means the
  ;; connection is gone -- which is the distinction being drawn -- though
  ;; neither proves it is healthy either: uv_write can refuse with EPIPE
  ;; or ENOTCONN on a connection this side still has in 'open. What the
  ;; state test establishes is only that this side has not yet observed
  ;; the connection go away, and that is exactly what "#f means no link"
  ;; needs to promise. Keying on the exception therefore repaired one half and
  ;; left the other reporting "no link" for a link that was up, which is
  ;; exactly the failure being repaired. What actually distinguishes the
  ;; two cases is whether the connection is still open, so that is what
  ;; is asked -- and asked inside the same uninterruptible region as the
  ;; write, so the answer belongs to the moment of the failure.
  ;;
  ;; THE FAILURE DOMAIN AFTER A CALLER'S PUBLICATION POINT, written to the
  ;; shape it actually has. frame-segments has already built every byte,
  ;; so nothing is left to serialize; what remains is the submission, and
  ;; it fails in two quite ordinary ways as well as in the OOM domain --
  ;; the connection is no longer open by the time the submitting region
  ;; observes it, or uv_write refuses it outright with a negative errno.
  ;; Those two report by returning #f already. The OOM cases -- the
  ;; queued path's allocation, and the table entry that publishes its
  ;; completion -- are caught below and reported the same way, because a
  ;; caller that has published state can act on a returned #f and cannot
  ;; act on an exception.
  ;;
  ;; THAT GUARD IS NOT THE WHOLE PROCEDURE, and three things sit outside
  ;; it:
  ;;   - outbound-charge! runs BEFORE it and allocates (a table entry, and
  ;;     on a first write a close hook);
  ;;   - close-for-backpressure! runs AFTER it and both allocates
  ;;     (conn-link-pid walks the peers table) and sends;
  ;;   - the wake-up for a connection found closed does the same two
  ;;     things, and was added to this procedure after this list was
  ;;     first written -- which is how a list like this goes wrong.
  ;; An OOM in any of the three still leaves this procedure by raising.
  ;; The close-for-backpressure! one
  ;; is the worst of them and is stated rather than smoothed over:
  ;; when it is reached after a SUCCESSFUL submission -- which is the
  ;; usual way to reach it -- the frame is already with libuv, so the
  ;; peer may act on it and reply, while this caller sees an exception
  ;; and its pending entry stays behind; a reply arriving later has
  ;; nothing left to match and remains in the mailbox. (It is also
  ;; reached after a FAILED submission, when the charge that was refunded
  ;; still leaves the connection over its ceiling. Nothing was handed to
  ;; libuv on that path.) Both are named here and not mechanised;
  ;; catching them would mean answering #f for a frame that may already
  ;; be on its way.
  ;;
  ;; REFUNDING ONCE IS CORRECT, and the reason lives in libuv.sc rather
  ;; than here, so it is named to be checked: in enqueue-write!
  ;; everything that can raise -- the allocation, the fill, the table
  ;; insert -- happens BEFORE the completion is registered, and every
  ;; path after the registration reports failure by returning rather than
  ;; raising. An exception arriving here therefore means no completion
  ;; exists to refund a second time. If that ever stops being true, this
  ;; refund becomes a double refund, which drives the count negative and
  ;; raises the effective ceiling instead of enforcing it.
  ;;
  ;; THE ONLY OUTBOUND PATH ON A NODE LINK. Every frame this library
  ;; sends -- handshake, heartbeat, send, call, reply, monitor traffic --
  ;; leaves through here, and tcp-writev! appears nowhere else in this
  ;; file. That is what makes the byte accounting a property of the LINK
  ;; rather than of whichever callers remembered to ask for it: a second
  ;; write path would be unbilled, and the ceiling would then bound only
  ;; the frames that happened to go through this one.
  ;;
  ;; THE CHARGE IS MADE BEFORE THE WRITE, and the ordering is not
  ;; cosmetic. on-done can run synchronously inside tcp-writev! -- the
  ;; connection is not open (status -1), or uv_try_write takes the whole
  ;; frame in one go (status 0) -- so charging afterwards would let the
  ;; refund land before the charge and drive the count negative on the
  ;; ordinary fast path, not in some rare interleaving.
  ;;
  ;; on-done CLOSES OVER `total` because its argument is not a byte
  ;; count: it is 0 for a completed write and a negative errno otherwise.
  ;; Success and failure refund the same amount, because the bytes have
  ;; stopped being queued either way -- and a failed write is NOT a
  ;; backpressure close: it leaves the link to end the way write failures
  ;; already end it, with the peer no longer readable.
  (define (write-body! c segs)
    (let ((total (fold-left (lambda (a b) (+ a (bytevector-length b)))
                            0 segs)))
      ;; THE CHARGE AND THE SUBMISSION ARE ONE UNINTERRUPTIBLE STEP. A
      ;; kill between them leaves bytes charged that no completion will
      ;; ever refund, because the write was never submitted and a killed
      ;; process runs no winders; the connection then carries that much
      ;; less headroom for as long as it lives, and enough of them close a
      ;; link that was keeping up. Making the pair atomic removes the
      ;; window rather than describing it.
      ;;
      ;; The cost is that the queued path's allocation and copy run with
      ;; interrupts off. What bounds it is max-frame: one frame, so at
      ;; most 8 MiB, which copied on this machine took about 0.1 ms. That
      ;; number is a measurement and not a guarantee -- a first touch of
      ;; fresh pages, or an allocator that has to go to the OS, costs
      ;; more, and nothing in the code holds frames below the limit;
      ;; keeping bulk data off the control link is advice this file gives
      ;; and does not enforce. Lower max-frame to lower the stall.
      ;;
      ;; It is kill-safe by the region and exception-safe by the handler
      ;; below; the two failures need different answers because a kill
      ;; leaves nothing to run and an exception leaves a handler.
      ;;
      ;; THE REGION ENDS WHERE THE SUBMISSION DOES. close-for-backpressure!
      ;; stays outside it: it sends a message, which is not work for an
      ;; interrupt-free region. That leaves a narrower window -- killed
      ;; after the write, before the close -- in which a connection stays
      ;; over its ceiling without being closed. The next frame written to
      ;; it crosses the ceiling again and closes it. THE TICK PING IS NOT
      ;; A BACKSTOP FOR THIS, though it looks like one: link-loop restarts
      ;; its receive on every inbound frame, so a peer that sends anything
      ;; at all more often than tick-ms holds the ping off for as long as
      ;; it keeps sending -- and a peer that is not reading its socket
      ;; while still sending is exactly the peer this ceiling is about.
      ;; WHAT DOES COVER IT is the check at the top of link-loop's drain,
      ;; which runs on every wake-up: the traffic that suppresses the
      ;; timer is the same traffic that supplies the check.
      (let ((over? #f) (failure #f))
        (let ((r (atomically
                   (set! over? (outbound-charge! c total))
                   (let ((res
                   (guard (e (#t (set! failure e)
                                 (outbound-discharge! c total)
                                 ;; RE-READ, do not clear. These bytes
                                 ;; never queued, so the verdict must not
                                 ;; rest on them -- but the verdict was
                                 ;; about the connection's whole balance,
                                 ;; and the rest of it can be over the
                                 ;; ceiling on somebody else's in-flight
                                 ;; writes. Clearing outright drops a
                                 ;; close that was due; asking again after
                                 ;; the refund answers about what is
                                 ;; actually still queued.
                                 (set! over? (outbound-over? c))
                                 #f))
                     (tcp-writev! c segs
                       (lambda (status) (outbound-discharge! c total))))))
                     ;; A calm #f on a connection that is STILL OPEN is a
                     ;; refusal, not a dead link. There is no condition to
                     ;; carry for it -- libuv reported by returning -- so
                     ;; one is named here rather than leaving the caller
                     ;; to infer a link failure that did not happen.
                     (when (and (not res) (not failure)
                                (eq? (conn-state c) 'open))
                       (set! failure 'submission-refused))
                     res))))
          ;; A WRITE THAT FINDS THE CONNECTION GONE WAKES WHOEVER IS
          ;; RUNNING THE LINK. Closing notifies nobody -- libuv's close
          ;; completion runs the connection's cleanup and frees the
          ;; handle, and the link process is parked in a receive that
          ;; knows nothing about it. Left alone, a link whose connection
          ;; died elsewhere (the transport closed it under a truncated
          ;; frame, say, or another writer closed it) is discovered by
          ;; whichever comes first of an EOF that may never arrive, the
          ;; next tick's ping, or dead-ms a minute later. This is a
          ;; fourth path and the only one with no delay in it.
          ;;
          ;; UNCONDITIONAL, not "only if it looks freshly closed". The
          ;; other source of this outcome -- a link that died a while ago
          ;; and this writer is only now finding out -- may equally have
          ;; a link process that has not seen the EOF yet, so waking it
          ;; is an improvement there too; and a process that has already
          ;; gone simply does not receive. tcp-close! is idempotent and
          ;; the message carries the connection, so a link that has since
          ;; been replaced refuses it (see stop-link!).
          ;;
          ;; When this runs IN the link process -- a ping, a reply -- the
          ;; message goes to its own mailbox and is matched at its next
          ;; receive. That is the same answer by a slightly longer route.
          ;;
          ;; The reason is 'write-to-closed whatever closed it. A
          ;; connection the transport dropped for its own reasons (see
          ;; the partial-write branches in libuv.sc) arrives here looking
          ;; exactly like any other closed connection, because that is
          ;; all this side can observe.
          ;; THE TEST IS THE CONNECTION'S STATE, not whether a condition
          ;; was captured -- the same measure R1 above settled on, applied
          ;; here too. Keying it on `failure` missed the case where the
          ;; transport closed the connection AND raised (a partial write
          ;; whose remainder could not be queued does exactly that): the
          ;; connection was gone and nobody was woken, because a condition
          ;; had been captured.
          ;;
          ;; READING IT HERE, OUTSIDE THE ATOMIC REGION, IS SOUND IN ONE
          ;; DIRECTION ONLY, and that is the direction to be in. A
          ;; connection's state moves open -> closing -> closed and never
          ;; back. What that buys is NOT "not open now means it was
          ;; already not open when the write failed" -- an earlier version
          ;; of this comment claimed exactly that, and it is backwards:
          ;; the write can be refused on a connection that is still open
          ;; and be closed by someone else a moment later. What
          ;; monotonicity gives is the forward direction -- once this read
          ;; says "not open", it will not become open again -- and that is
          ;; enough, because the action taken is about the connection's
          ;; state NOW: close it (idempotent) and wake whoever is running
          ;; it.
          ;;
          ;; The error this can make is the other one: reading 'open just
          ;; before it closes, and skipping a wake-up. Not every other
          ;; path covers that -- a local close produces no tcp-eof, and if
          ;; nothing more is written there is no next write either. What
          ;; covers it is the tick.
          (cond (over? (close-for-backpressure! c))
                ((and (not r) (not (eq? (conn-state c) 'open)))
                 (stop-link! c (conn-link-pid c) 'write-to-closed)))
          (values (and r #t) failure)))))

  ;; Over the ceiling: this connection is done.
  ;;
  ;; CLOSING IS NOT ENOUGH ON ITS OWN, and that is the whole reason this
  ;; is a procedure rather than a call to tcp-close!. This runs in the
  ;; SENDER's process -- whoever called rsend -- while the link process is
  ;; parked in link-loop's receive. libuv's close completion notifies
  ;; nobody: it runs the connection's cleanup thunk and frees the handle.
  ;; So the link process would sit there until its next tick, write a ping
  ;; into a closed connection (which write-frame! reports by returning #f,
  ;; to nobody), and go on not updating last-seen until dead-ms -- a
  ;; minute in which this node still believes the peer is up, still routes
  ;; rsend to it, and has told no watcher anything. The message is what
  ;; makes the close a LINK DOWN rather than a socket that quietly stopped
  ;; working.
  ;;
  ;; It is addressed via the peers table rather than to conn-owner,
  ;; because the question being asked is not "who owns this socket" but
  ;; "is there a link process running on it": a connection still
  ;; handshaking has an owner too, and waking that one would leave a
  ;; message in a mailbox whose receive has no clause for it. Finding the
  ;; entry means the far end was authenticated and installed, which is
  ;; exactly when link-loop is the reader.
  ;;
  ;; THE MESSAGE NAMES THE CONNECTION, and it has to. A connector process
  ;; is long-lived and runs one connection after another, so its pid does
  ;; not identify a link -- only a series of them. Between the lookup and
  ;; the send this process can be preempted (tcp-close! alone is a safe
  ;; point), and in that window the link being closed can end and the same
  ;; connector can redial and be sitting in link-loop on a NEW, healthy
  ;; connection. A bare wake-up would then be read as that connection's
  ;; cause of death and tear it down, with the node-down, the noconnection
  ;; monitors and the failed pending calls that go with it. Pids are never
  ;; reused here, so this is not stale-pid confusion: it is the same pid
  ;; holding a different connection, and only the connection tells the two
  ;; apart. link-loop drops one that is not about its own c.
  ;;
  ;; The reason travels with it and is raised by link-loop, so the link
  ;; dies with 'outbound-backpressure the way another dies with 'closed or
  ;; 'protocol. Nothing is printed: this runs in an arbitrary caller's
  ;; process, and a diagnostic here would turn an error port that refuses
  ;; writes into a failure of the unrelated rsend that happened to be the
  ;; frame over the line.
  ;; Take a link down. It is written for a process that is NOT the link
  ;; process -- which is the usual caller, since the link process can
  ;; close and raise directly -- but nothing restricts it to that, and
  ;; the link process does reach it: a ping or a reply that crosses the
  ;; outbound ceiling arrives here through close-for-backpressure!. In
  ;; that case the wake-up goes to its own mailbox and is matched at its
  ;; next receive, which is the same outcome by a slightly longer route. Enforce first, then wake -- the close does not
  ;; depend on the other process ever running, and the message is what
  ;; turns a closed socket into a link that has gone down (libuv's close
  ;; completion notifies nobody).
  ;;
  ;; BOTH THE CONNECTION AND ITS PROCESS ARE PASSED IN, never looked up
  ;; by node name here. A name maps to whatever connection is current,
  ;; and by the time a failure is being acted on, the name may already
  ;; have been reconnected onto a healthy one -- taking down the
  ;; replacement for the sins of its predecessor. Callers know which
  ;; connection failed and say so; the conn also rides in the message, so
  ;; link-loop's eq? check refuses one that arrives after its own link
  ;; has been replaced.
  (define (stop-link! c link why)
    (tcp-close! c)                              ; enforce first, then wake
    (when (and link (process-alive? link))
      (send link (vector 'link-stop c why))))

  (define (close-for-backpressure! c)
    (stop-link! c (conn-link-pid c) 'outbound-backpressure))

  ;; Is this the condition rsend raises when a frame was built but could
  ;; not be handed to libuv?
  ;;
  ;; EXPORTED BECAUSE A CALLER CANNOT ACT ON WHAT IT CANNOT NAME. rsend
  ;; distinguishes three outcomes and two of them are values; the third
  ;; is this condition, and a caller that wants to treat it the way it
  ;; treats #f -- which is the right answer wherever "reachable right
  ;; now" is the question being asked -- needs a predicate for it that is
  ;; not a shape match written out again at every call site.
  (define (submission-failure? e)
    (and (vector? e)
         (fx>= (vector-length e) 2)
         (eq? (vector-ref e 0) 'rsend-error)
         (eq? (vector-ref e 1) 'submission-failed)))

  ;; The link process running on connection c, or #f if no installed peer
  ;; owns it (a connection still in its handshake, or one already torn
  ;; down). A scan, because peers is keyed by node name and this asks the
  ;; question from the other end; the mesh is small by design (see the
  ;; fourth commitment). It used to run once per backpressure close;
  ;; since the wake-up above it also runs for every writer that finds a
  ;; connection already closed, so concurrent writers can each scan once
  ;; before the link process consumes the first wake-up. They send
  ;; messages tagged with the same connection. The first one that reaches
  ;; a link-loop ends it, so the duplicates do not accumulate there; they
  ;; go one of three other ways -- drained by a long-lived connector's
  ;; wait, discarded with an acceptor that is exiting anyway, or refused
  ;; by a LATER link-loop whose connection is not the one in the message.
  (define (conn-link-pid c)
    (atomically
      (let-values (((names entries) (hashtable-entries peers)))
        (let loop ((i 0))
          (cond
            ((fx= i (vector-length entries)) #f)
            ((eq? (entry-conn (vector-ref entries i)) c)
             (entry-link (vector-ref entries i)))
            (else (loop (fx+ i 1))))))))

  ;; unique incomplete marker: a peer legitimately sending the DATUM
  ;; `more` must not read as an incomplete frame (the old (eq? d 'more)
  ;; contract had exactly that confusion)
  (define incomplete (list 'more))

  ;; Try to split one frame off the inbuf. `limit` bounds the body
  ;; length -- handshake-max-frame during the handshake, max-frame once
  ;; the link is authenticated. A complete frame is consumed from the
  ;; buffer (an offset bump, not a copy of everything behind it).
  ;; -> datum | incomplete ; raises 'protocol on junk
  (define (parse-frame buf limit)
    (let ((bv (inbuf-bv buf)) (base (inbuf-start buf)) (n (inbuf-length buf)))
      (let scan ((i 0) (len 0))
        (cond
          ((fx> i 8) (raise 'protocol))            ; length header too long
          ((fx>= i n) (values incomplete #f))
          ((fx= (bytevector-u8-ref bv (fx+ base i)) 10)   ; newline
           (when (or (fx= i 0) (> len limit)) (raise 'protocol))
           (let ((total (fx+ i 1 len)))
             (if (< n total)
                 (values incomplete #f)
                 (let ((text (utf8->string (inbuf-sub buf (fx+ i 1) total))))
                   (inbuf-consume! buf total)
                   (values (string->sexpr-extended text) text)))))
          (else
           (let ((b (bytevector-u8-ref bv (fx+ base i))))
             (unless (and (fx>= b 48) (fx<= b 57)) (raise 'protocol))
             (scan (fx+ i 1) (+ (* len 10) (fx- b 48)))))))))

  ;; Block (in the calling process) until one whole frame arrives.
  ;; -> datum ; raises 'closed / 'timeout / 'protocol /
  ;; the sexpr-error vector on a malformed datum
  ;; -> (values datum body-text). The text is what canonical? compares
  ;; against; a caller that does not need it ignores the second value.
  (define (read-frame c buf timeout limit)
    (let ((deadline (+ (now-ms) timeout)))
      (let loop ()
        (let-values (((d text) (parse-frame buf limit)))
          (if (eq? d incomplete)
              (let ((remaining (- deadline (now-ms))))
                (when (<= remaining 0) (raise 'timeout))
                (receive (after remaining (raise 'timeout))
                  (`#(tcp-data ,bv) (inbuf-append! buf bv) (loop))
                  (`#(tcp-eof) (raise 'closed))
                  (`#(tcp-error ,e) (raise 'closed))
                  (`#(node-stop) (raise 'stop))))
              (values d text))))))

  ;; THE FRAME'S BYTES MUST BE THE CANONICAL SPELLING OF WHAT THEY MEAN.
  ;;
  ;; The wire specification fixes the bytes, not merely the values: one
  ;; ASCII space between elements, quoted strings, a bare decimal for the
  ;; version and the generation, no leading zeros and no sign. The reader
  ;; cannot enforce any of that on its own, because it NORMALISES -- it
  ;; answers 1 for `1/1`, 0 for `-0`, 4 for `04` -- so a check written
  ;; against the parsed value passes every one of those spellings and the
  ;; refusal the specification asks for never happens.
  ;;
  ;; Rather than write a second parser to see the bytes the first one
  ;; consumed, re-serialise what was parsed and compare: our writer emits
  ;; the canonical form (the three golden frames round-trip through it
  ;; byte for byte), so equality here IS the specification's rule, and it
  ;; covers every lexical clause at once instead of one predicate per
  ;; field. An honest peer of any implementation passes; a peer that
  ;; spells a value some other way is refused, which is the point -- the
  ;; alternative is two implementations that agree on values and diverge
  ;; on bytes, and the version number exists to prevent exactly that.
  ;;
  ;; APPLIED AFTER THE VERSION COMPARISON, with the other field grammars:
  ;; the ordering rule of this handshake is that a peer stating another
  ;; version is answered about its version, never about a rule that was
  ;; never its rule.
  (define (canonical? datum text)
    (and (string? text)
         (guard (e (#t #f))
           (string=? (sexpr->string-extended datum) text))))

  ;; ---- HMAC-SHA256 handshake proofs --------------------------------------
  ;; hmac-sha256 and bytevector->hex come from (igropyr crypto).

  ;; A RECEIVED NONCE MUST BE EXACTLY WHAT WE WOULD HAVE SENT: 32 lowercase
  ;; hex characters. This is load-bearing, not hygiene. The proof is
  ;; HMAC over nonce ":" name ":" version, and that encoding needs ONE of
  ;; its variable fields to be separator-free: a colon-free nonce lets the
  ;; tuple be split from the left, a colon-free name lets it be split from
  ;; the right, and either alone is enough. Both are enforced, because they
  ;; guard different fields and neither costs anything. We generate hex,
  ;; so the sent nonce never can -- but a RECEIVED nonce arrives from the
  ;; other end, and checking it with string? alone accepted "X:evil".
  ;;
  ;; What that bought an attacker, before this check existed: get an honest
  ;; node named `a` to dial you, answer with the nonce "X:evil" where X is a
  ;; nonce you were just given by the node you want to enter, and it returns
  ;; HMAC(secret, "X:evil:a:3"). Send that to the target as
  ;; (hello evil:a <proof> ... 3) and the target computes HMAC over
  ;; "X" ":" "evil:a" ":" "3" -- the same bytes. It authenticates a peer
  ;; that never had the secret. The two digests were measured equal; the
  ;; value is not quoted here because reproducing it needs the key and the
  ;; nonce, which live in the cell that owns this, not in this comment.
  ;;
  ;; THE PROPERTY BELONGS TO THE PATH, NOT TO THE NAME. An earlier comment
  ;; argued injectivity from "nonce is hex" -- true of the nonce we mint,
  ;; and not of the one we are handed. The same identifier names two
  ;; different quantities on the two sides, and the guarantee only exists
  ;; on the side that produces it. The same care applies to the name: what
  ;; the proof needs of it is not "it is a symbol" but "it contains no
  ;; colon", and what the node needs of it is wider still -- that the
  ;; writer can serialise it. See wire-name?.
  (define (hex-nonce? s)
    (and (string? s)
         (fx= (string-length s) 32)
         (let loop ((i 0))
           (or (fx= i 32)
               (and (let ((c (string-ref s i)))
                      (or (and (char>=? c #\0) (char<=? c #\9))
                          (and (char>=? c #\a) (char<=? c #\f))))
                    (loop (fx+ i 1)))))))

  ;; A BOOT ID IS EXACTLY 16 LOWERCASE HEX CHARACTERS, and like the nonce
  ;; grammar this is wire syntax rather than a local habit: it goes into
  ;; the proof between two colons, so it has to be separator-free, and
  ;; both ends have to agree on its width or the same node presents two
  ;; different identities. Uppercase is refused for the same reason a
  ;; nonce refuses it -- two spellings of one value is one value too
  ;; many, and the refusal costs nothing.
  (define (hex16? s)
    (and (string? s)
         (fx= (string-length s) 16)
         (let loop ((i 0))
           (or (fx= i 16)
               (and (let ((c (string-ref s i)))
                      (or (and (char>=? c #\0) (char<=? c #\9))
                          (and (char>=? c #\a) (char<=? c #\f))))
                    (loop (fx+ i 1)))))))

  ;; A NAME ON THE WIRE IS A STRING over [0-9a-z-], non-empty, at most
  ;; max-name-length characters. The charset is narrower than what a
  ;; symbol can hold, and deliberately so: it makes the proof encoding
  ;; injective without any escaping rule, and it removes the one place
  ;; where two honest implementations could disagree about the bytes of a
  ;; frame. A hyphen is allowed anywhere, first and last position
  ;; included -- there is no technical reason to refuse it, and writing
  ;; that down is what stops the next reader from narrowing it further on
  ;; aesthetic grounds.
  (define (wire-name-string? s)
    (and (string? s)
         (let ((n (string-length s)))
           (and (fx> n 0) (fx<= n max-name-length)
                (let loop ((i 0))
                  (or (fx= i n)
                      (and (let ((c (string-ref s i)))
                             (or (and (char>=? c #\0) (char<=? c #\9))
                                 (and (char>=? c #\a) (char<=? c #\z))
                                 (char=? c #\-)))
                           (loop (fx+ i 1)))))))))

  ;; TWO SEPARATE REQUIREMENTS, and they are not the same one.
  ;;
  ;; NO COLON, because a colon is the proof's separator. This is a real
  ;; repair and not only depth: with colon-free names the encoding is
  ;; injective even for a nonce that contains colons, since the tuple can
  ;; be split from the right. hex-nonce? is the other repair, and either
  ;; alone would close the collision -- both are enforced because they
  ;; guard different fields and each is cheap. What a colon check CANNOT
  ;; do is act on the two public entry points alone: the name an attacker
  ;; CLAIMS arrives in a hello frame, so it has to be checked there, and
  ;; it is.
  ;;
  ;; WRITABLE BY THE SEXPR WRITER, which is a wider requirement than
  ;; having no colon and is asked here with the authoritative writer
  ;; rather than a second grammar. A symbol this library cannot serialise
  ;; makes a node that starts, accepts configuration, and then fails every
  ;; handshake at the point of writing hello -- late, repeatedly, and with
  ;; nothing pointing back at the name. `a b` was such a name: it passed a
  ;; hand-written colon check and the writer refuses it. Start and connect
  ;; happen once per peer, so the cost of asking the real writer is not
  ;; worth a second, drifting copy of its grammar.
  ;; v4 NARROWED THIS TO THE WIRE'S OWN CHARSET. It used to refuse only a
  ;; colon, which kept the proof encoding injective but left the API able
  ;; to accept names the wire cannot carry -- the asymmetry this file
  ;; argues against everywhere else, arrived at from the other side. A
  ;; name that cannot cross the wire is not a name this node may be
  ;; given, and the refusal belongs at the two entry points rather than
  ;; at the first hello that carries it.
  (define (wire-name? x)
    (not (wire-name-complaint x)))

  ;; WHAT IS WRONG WITH IT, not merely that something is. A single
  ;; predicate behind a single message was survivable while the rule was
  ;; a single rule ("no colon"); v4 folded charset, emptiness and length
  ;; into it, and one message for four rules means an operator whose node
  ;; is called `Alpha` is told its name contains a colon. It also made
  ;; the specific length diagnostics further down unreachable, since the
  ;; general check now refuses a long name first.
  ;;
  ;; -> #f when the name is usable, else a string naming the actual
  ;; violation. Order matters only for readability: at most one clause
  ;; can be reported, so the most specific comes first.
  (define (wire-name-complaint x)
    (cond
      ((not (symbol? x)) "a node name must be a symbol")
      ((fx= (string-length (symbol->string x)) 0) "a node name cannot be empty")
      ((fx> (string-length (symbol->string x)) max-name-length)
       (string-append "a node name is at most "
                      (number->string max-name-length)
                      " characters -- it has to fit the handshake frames"))
      ((not (wire-name-string? (symbol->string x)))
       (string-append
         "a node name is wire syntax: lowercase letters, digits and `-`"
         " only ([0-9a-z-]). Uppercase, `_`, `.` and `:` are refused --"
         " `:` because it separates the fields of the handshake proof,"
         " the rest because the wire fixes one spelling per name"))
      ((guard (e (#t #t)) (sexpr->string-extended (list x)) #f)
       "the wire writer cannot serialise this name")
      (else #f)))

  (define (random-hex nbytes)
    (call-with-port (open-file-input-port "/dev/urandom")
      (lambda (p)
        (let ((bv (get-bytevector-n p nbytes)))
          (unless (and (bytevector? bv) (= (bytevector-length bv) nbytes))
            (raise 'entropy))                   ; short read: fail closed
          (bytevector->hex bv)))))

  ;; THE VERSION IS BOUND INTO THE PROOF, not merely carried beside it. The
  ;; explicit field is what lets a refusal name its cause; binding is what
  ;; stops that field from being edited on its own. Without it a peer could
  ;; send a proof computed for one version and claim another, and both ends
  ;; would agree on a number neither had authenticated.
  ;;
  ;; v4 SPLIT THE ONE FORMULA INTO TWO, and they are not symmetric. The
  ;; asymmetry is the point, so it is written out rather than left to be
  ;; inferred from the code.
  ;;
  ;; proof-D, the dialer's, binds WHO IT THINKS IT IS TALKING TO as well
  ;; as itself: nonce-a, its own name and boot id, the generation, and
  ;; then the target's name and the boot id it just read out of the
  ;; challenge. Without those last two, a proof handed to one acceptor is
  ;; a proof that would satisfy any other acceptor sharing the secret --
  ;; the digest says "I am d", never "I am d, talking to e".
  ;;
  ;; proof-A, the acceptor's, does NOT bind the dialer back. Symmetry
  ;; looks like the safer choice and here it would buy nothing, which is
  ;; worth stating because the next reader will want to add it. What
  ;; carries the acceptor's identity is three facts together, not the
  ;; digest alone: the HMAC binds name-A and bootid-A so forging it needs
  ;; the secret; the dialer compares the welcomed name against the peer
  ;; IT configured, not against whatever arrived; and nonce-b is fresh
  ;; for this handshake, so a recording is not a key. Binding name-D into
  ;; proof-A would add a field to the formula and no property to the
  ;; argument -- and a transparent relay between two ends that genuinely
  ;; want to talk to each other is not stopped by either spelling.
  ;;
  ;; Every field is separator-free by its own grammar (hex, or the wire
  ;; name charset, or a decimal), so the colon-joined encoding is
  ;; injective without escaping.
  (define (proof-d nonce-a name-d bootid-d dialgen name-a bootid-a)
    (bytevector->hex
      (hmac-sha256 self-secret
        (string->utf8
          (string-append nonce-a ":" name-d ":"
                         (number->string protocol-version) ":"
                         bootid-d ":" (number->string dialgen) ":"
                         name-a ":" bootid-a)))))

  (define (proof-a nonce-b name-a bootid-a)
    (bytevector->hex
      (hmac-sha256 self-secret
        (string->utf8
          (string-append nonce-b ":" name-a ":"
                         (number->string protocol-version) ":"
                         bootid-a)))))

  ;; The nth element, or #f when the datum is too short. Used to look at a
  ;; version slot before the shape as a whole has been accepted: the point
  ;; of the ordering below is that a future peer is told its version is
  ;; wrong rather than that its frame is malformed.
  (define (slot d n)
    (let loop ((l d) (i n))
      (cond ((not (pair? l)) #f)
            ((fx= i 0) (car l))
            (else (loop (cdr l) (fx- i 1))))))

  ;; What the other end claimed, for a diagnostic. A peer's datum is
  ;; untrusted input and may be a cycle or a megabyte, so this is bounded
  ;; by construction rather than by hoping the value is small: print-graph
  ;; removes the cycle warning (which is a raised condition, not merely a
  ;; printed line), print-length and print-level bound the traversal, and
  ;; the substring bounds a single enormous atom.
  (define (claimed-version-text v)
    (if (eq? v #f)
        "pre-2 (no version field)"
        (let ((t (parameterize ((print-length 4) (print-level 2)
                                (print-graph #t))
                   (format "~s" v))))
          (if (fx> (string-length t) 32)
              (string-append (substring t 0 32) "...")
              t))))

  ;; constant-time compare: an attacker probing digests byte by byte
  ;; learns nothing from response timing
  (define (proof=? a b)
    (and (string? a) (string? b)
         (fx= (string-length a) (string-length b))
         (let loop ((i 0) (acc 0))
           (if (fx= i (string-length a))
               (fx= acc 0)
               (loop (fx+ i 1)
                     (fxior acc (fxxor (char->integer (string-ref a i))
                                       (char->integer (string-ref b i)))))))))

  ;; ---- peer install / removal ---------------------------------------------
  ;; The tie-break: of two simultaneous connections between the same
  ;; pair, keep the one dialed by the smaller node name. Both ends see
  ;; the same dialer for the same physical connection, so both converge
  ;; on the same survivor.

  (define (name<? a b)
    (string<? (symbol->string a) (symbol->string b)))

  ;; ---- the install decision tree -------------------------------------
  ;;
  ;; ORDERED DATA, NOT A COND, AND THE ORDER IS THE SEMANTICS. The table
  ;; is first-match-wins, so a rule's position IS its priority -- and a
  ;; position expressed as source layout is a requirement no test can
  ;; see. I0 in particular has to be physically first: move it after I1
  ;; and behaviour differs only when a parent dies inside one window,
  ;; which is to say every run stays green while the rule is gone. As a
  ;; list, the order is a value: `(car install-rules)` is I0, and that is
  ;; an assertion something can make.
  ;;
  ;; THE RULES ARE DELIBERATELY NOT MUTUALLY EXCLUSIVE, which is the one
  ;; arrangement that needs saying out loud. I1 and I2 share their
  ;; opening condition and split on metadata; I3 hands back to the top so
  ;; a torn-down current is re-judged from I0. Everywhere else an overlap
  ;; would be a defect, so the permitted pairs are written down (see
  ;; install-rule-overlaps) rather than left as "whatever the order does"
  ;; -- otherwise ordering slides from a decision into a default.
  (define-record-type irule
    (fields name applies act))

  ;; The request, as one value: the tree reads nothing else, so a rule
  ;; cannot quietly depend on ambient state.
  (define-record-type ireq
    (fields name conn dialer boot-id gen parent))

  ;; Same connection, same story? The metadata is what the peer told us
  ;; about itself; a repeat of the identical request is idempotent, a
  ;; repeat that says something different is a protocol error and gets
  ;; its own answer rather than being folded into replacement.
  (define (meta=? e r)
    (and (eq? (entry-dialer e) (ireq-dialer r))
         (equal? (entry-boot-id e) (ireq-boot-id r))
         (equal? (entry-gen e) (ireq-gen r))))

  (define (entry-healthy? e)
    (and (eq? (conn-state (entry-conn e)) 'open)
         (let ((l (entry-link e)))
           (or (not l) (process-alive? l)))))

  (define (same-conn? e r) (eq? (entry-conn e) (ireq-conn r)))

  ;; Decisions the tree can reach. The action returns one of these; the
  ;; table work for `replace` and `install` has already happened inside
  ;; the atomic region by the time it is returned.
  ;;   installed | idempotent | replaced | refused | protocol-error | retry
  ;; `retry` is I3's: tear the current entry down, then judge again from
  ;; the top -- the candidate is then not current and unhealthy, so it
  ;; lands on I4.

  (define (install-rules)
    (list
      ;; I0 -- PHYSICALLY FIRST. An install request whose parent is gone
      ;; is an orphan: whatever asked for it is no longer there to own
      ;; the result. Placed after I1 it would never fire, because a
      ;; repeat request from a live child of a dead parent answers
      ;; "idempotent success" first.
      (make-irule 'I0
        (lambda (e r) (and (ireq-parent r)
                           (not (process-alive? (ireq-parent r)))))
        (lambda (e r) 'refused))
      ;; I1 -- the same connection saying the same thing. Idempotent
      ;; success, and NEVER a close: the caller is the owner of a working
      ;; link and closing it here would kill what it just proved.
      (make-irule 'I1
        (lambda (e r) (and e (same-conn? e r) (entry-healthy? e) (meta=? e r)))
        (lambda (e r) 'idempotent))
      ;; I2 -- the same connection saying something else. Not a
      ;; replacement candidate: one connection cannot have two identities,
      ;; so this is a protocol error and is answered as one.
      (make-irule 'I2
        (lambda (e r) (and e (same-conn? e r) (entry-healthy? e)))
        (lambda (e r) 'protocol-error))
      ;; I3 -- the current entry IS this connection but is not healthy.
      ;; Tear it down and judge again from the top; reporting success
      ;; here would install nothing and say it had.
      (make-irule 'I3
        (lambda (e r) (and e (same-conn? e r)))
        (lambda (e r) 'retry))
      ;; I4 -- a candidate that is not current and not healthy. Refuse
      ;; without touching current: an unhealthy newcomer must never
      ;; displace a working link.
      (make-irule 'I4
        (lambda (e r) (not (conn-open? (ireq-conn r))))
        (lambda (e r) 'refused))
      ;; I5 -- no entry. Install, and it is a genuine up.
      ;;
      ;; ANY GENERATION IS ACCEPTED HERE, deliberately. A generation is
      ;; only meaningful against a current value, and with no entry there
      ;; is no current value to compare against -- the two share a
      ;; lifetime. The cost is recorded in the design rather than
      ;; repaired: a stale high generation arriving first is taken as a
      ;; fresh start.
      (make-irule 'I5
        (lambda (e r) (not e))
        (lambda (e r) 'install))
      ;; I6 -- a different boot id is a different incarnation of the
      ;; peer. Nothing about the old one survives it, so no ordering
      ;; question arises and no tie-break applies.
      (make-irule 'I6
        (lambda (e r) (not (equal? (entry-boot-id e) (ireq-boot-id r))))
        (lambda (e r) 'replace))
      ;; I7 -- same incarnation, old connection already gone. Same dialer
      ;; still has to pass the generation gate: without it a late request
      ;; carrying a SMALLER generation would slip in behind "the old one
      ;; is not open anyway" and undo the ordering. A different dialer
      ;; does not take part in ordering at all.
      (make-irule 'I7
        (lambda (e r) (not (conn-open? (entry-conn e))))
        (lambda (e r)
          (if (eq? (entry-dialer e) (ireq-dialer r))
              (if (gen>? (ireq-gen r) (entry-gen e)) 'replace 'refused)
              'replace)))
      ;; I8a -- same incarnation, old connection open, same dialer:
      ;; ordering decides, and it decides by replacing, not by "just
      ;; swapping the table" and not by reporting success and doing
      ;; nothing.
      (make-irule 'I8a
        (lambda (e r) (eq? (entry-dialer e) (ireq-dialer r)))
        (lambda (e r)
          (if (gen>? (ireq-gen r) (entry-gen e)) 'replace 'refused)))
      ;; I8b -- same incarnation, both open, different dialers: the
      ;; simultaneous-connection tie-break. Both ends see the same dialer
      ;; for the same physical connection, so both converge on the same
      ;; survivor.
      (make-irule 'I8b
        (lambda (e r) #t)
        (lambda (e r)
          (if (name<? (ireq-dialer r) (entry-dialer e)) 'replace 'refused)))))

  ;; The pairs allowed to overlap, each with why. Any other two rules
  ;; true at once is a defect: the tree would then be deciding by
  ;; position on a case nobody chose.
  (define install-rule-overlaps
    '((I1 I2 . "same opening condition -- they split on metadata, and I1 must win")
      (I1 I3 . "I3's condition is I1's without the health test")
      (I2 I3 . "same: I3 is the unhealthy tail of the same shape")
      (I3 I4 . "after I3 tears down, the re-judged candidate lands on I4")))

  ;; A generation gate that is honest about absence. #f is what an entry
  ;; installed before generations existed carries, and "unknown" must not
  ;; read as "smaller than everything".
  (define (gen>? new old)
    (and (integer? new) (integer? old) (> new old)))

  (define (conn-open? c) (eq? (conn-state c) 'open))

  ;; -> installed | idempotent | replaced | refused | protocol-error
  ;;
  ;; A refusal has already closed the candidate; a success has not.
  (define (install-peer! name c dialer boot-id gen parent)
    (let ((r (make-ireq name c dialer boot-id gen parent)))
      (let judge ((fuel 2))
        ;; (R0) EVERYTHING THAT CAN ALLOCATE IS BUILT HERE, outside. The
        ;; region below may take a head, two event nodes, or none of
        ;; them; building all three unconditionally costs three small
        ;; objects on a path that runs once per connection, and buys the
        ;; property that the region contains no allocation at all. A
        ;; region that allocates can raise, and `atomically` does not
        ;; roll back -- a half-finished handover there is unreachable
        ;; state, not a retryable failure.
        (let* ((spare (list (new-qhead)
                            (make-qnode (make-event 'node-down name) #f '())
                            (make-qnode (make-event 'node-up name) #f '())))
               (cut #f)
               (old #f)
               (decision
                 (atomically
                   (let* ((e (hashtable-ref peers name #f))
                          (rule (let loop ((rs (install-rules)))
                                  (cond ((null? rs) #f)
                                        (((irule-applies (car rs)) e r) (car rs))
                                        (else (loop (cdr rs))))))
                          (d (and rule ((irule-act rule) e r))))
                     (case d
                       ((install)
                        ;; ADOPT AN ORPHANED QUEUE IF THIS PEER LEFT ONE.
                        ;; A peer that died with events still undelivered
                        ;; put its head on the orphan chain; coming back
                        ;; under a new entry must take it back rather
                        ;; than start an empty one beside it. Two heads
                        ;; for one peer would let this install's `up` be
                        ;; delivered before the previous `down` that is
                        ;; still sitting in the older queue.
                        ;; ORDER INSIDE THE REGION IS THE ARGUMENT, and
                        ;; it is worth spelling out because `atomically`
                        ;; does not roll back: whatever raises here
                        ;; leaves behind exactly what ran before it.
                        ;;   1. make-entry -- the ONE allocation in this
                        ;;      region, placed first, where a failure has
                        ;;      changed nothing at all;
                        ;;   2. hashtable-set! -- a NEW key, so this one
                        ;;      can grow the table and can raise. Nothing
                        ;;      has been queued yet when it does, so a
                        ;;      failure here publishes nothing and
                        ;;      announces nothing;
                        ;;   3. the enqueue -- pointer writes, and they
                        ;;      run only once the entry is published;
                        ;;   4. the unlink -- pointer writes only, so by
                        ;;      the time the head leaves the chain there
                        ;;      is nothing left that can fail.
                        ;; Detaching first would invert that: a failure
                        ;; at step 3 would leave the head off the chain
                        ;; and out of the table, with the peer's earlier
                        ;; undelivered events on it and no way to reach
                        ;; them.
                        (set! cut (hashtable-ref watchers name '()))
                        ;; ⚠ STEPS 2 AND 3 USED TO BE THE OTHER WAY
                        ;; ROUND, and the argument for that order was
                        ;; correct when it was written. It said the push
                        ;; was safe because the head was reachable either
                        ;; way -- "still on the orphan chain, or the
                        ;; spare nobody else can see" -- so a failure at
                        ;; the table would leave an unpublished entry and
                        ;; a queue nobody was looking at.
                        ;;
                        ;; A later change made that false without
                        ;; touching this code. Queueing an event now also
                        ;; puts its head on the dispatcher's ready chain,
                        ;; deliberately and in the same call, so the head
                        ;; IS something else can see -- both the fresh
                        ;; spare and the adopted orphan. A raise at the
                        ;; table would have left a node-up queued and
                        ;; announced for a peer that was never installed,
                        ;; and the dispatcher would have delivered it.
                        ;;
                        ;; Publishing first restores the original
                        ;; argument rather than patching around it:
                        ;; everything after the table write is a pointer
                        ;; write and cannot fail, so there is no longer a
                        ;; step whose failure leaves an announcement
                        ;; standing. Queueing and announcing stay one
                        ;; call -- a head holding an event while off the
                        ;; ready chain is the state that arrangement
                        ;; exists to prevent, and splitting them here to
                        ;; fix this would have traded one silent failure
                        ;; for another.
                        (let* ((oh (orphan-find name))
                               (h (or oh (car spare)))
                               (ne (make-entry c self dialer boot-id gen h)))
                          (hashtable-set! peers name ne)
                          (qhead-enqueue! h (caddr spare) cut)   ; an install is an `up`
                          (when oh (orphan-detach! name)))
                        'installed)
                       ((replace)
                        ;; (R1). THREE THINGS, ONE REGION.
                        ;;
                        ;; The swap is IN PLACE: peers[name] never goes
                        ;; absent, which is what lets a reader elsewhere
                        ;; keep treating "no entry" as "unreachable"
                        ;; without that becoming true for an instant
                        ;; during a handover.
                        ;;
                        ;; The old connection is CLOSED HERE, by actually
                        ;; calling tcp-close!, not by writing a state
                        ;; flag meaning "will be closed". Between the
                        ;; swap and a later close, inbound frames on the
                        ;; old connection still pass the link's gate and
                        ;; take effect -- the old generation still acting
                        ;; after the handover is the exact thing this
                        ;; ordering exists to end. And a flag would be
                        ;; worse than late: tcp-close! is guarded on the
                        ;; state it would have written, so the real close
                        ;; would then be skipped and the handle never
                        ;; reclaimed. uv_close only files the handle for
                        ;; its callback and does not block, so doing it
                        ;; here costs nothing this region cares about.
                        ;;
                        ;; The watcher list root is captured HERE, at the
                        ;; same linearisation point. Reading it before
                        ;; the swap lets a watcher that finishes
                        ;; registering in between miss the pair for good.
                        ;; The list is immutable, so this is a pointer.
                        ;; THE QUEUE MOVES TO THE NEW ENTRY, and it has
                        ;; to: the head hangs on the entry, and replacing
                        ;; an entry is otherwise an implicit destruction
                        ;; of everything hanging on it -- including
                        ;; events already queued and not yet delivered.
                        ;; One pointer, carried across. This event is
                        ;; appended AFTER them, so the peer's own order
                        ;; survives the handover.
                        ;; Same ordering rule as the install branch, and
                        ;; here it closes completely: make-entry first,
                        ;; and the hashtable-set! that follows replaces an
                        ;; EXISTING key, so it cannot grow the table and
                        ;; cannot raise. Everything after the allocation
                        ;; is a pointer write.
                        (set! old e)
                        (set! cut (hashtable-ref watchers name '()))
                        (let* ((h (entry-head e))
                               (ne (make-entry c self dialer boot-id gen h)))
                          ;; two numbers, one turn -- see next-event-seq!
                          (qhead-enqueue! h (cadr spare) cut)
                          (qhead-enqueue! h (caddr spare) cut)
                          (hashtable-set! peers name ne))
                        (tcp-close! (entry-conn e))
                        'replaced)
                       (else d)))))) 
          (case decision
            ((retry)
             ;; I3: the current entry is this connection and unhealthy.
             ;; Tear it down, then judge again -- once. The fuel is not
             ;; defensive decoration: a tree that could ask for a third
             ;; pass would be a tree whose teardown did not remove the
             ;; condition that sent it here.
             (let ((e (peer-entry name)))
               (when (and e (same-conn? e r)) (remove-peer! name c)))
             (if (> fuel 0) (judge (- fuel 1)) 'refused))
            ((replaced)
             ;; (R2)(R3)(R4). The queue is drained OUTSIDE the region:
             ;; the cut was taken inside, at the same instant as the
             ;; swap, and only the fan-out is out here. Moving the cut
             ;; out with it would let a watcher that finishes registering
             ;; between the read and the swap miss the pair for good --
             ;; late is recoverable, missing is not.
             ;;
             ;; (R2) wake the old link process, (R3) settle what the old
             ;; generation left behind, (R4) hand the head to the
             ;; dispatcher, which fans out down then up to the snapshot
             ;; cut taken inside. R4 is now a wake-up rather than a
             ;; fan-out: this process asks for the work to be done and
             ;; does not do it, so its own death no longer takes the
             ;; events with it.
             ;;
             ;; R3 IS THE CONSERVATIVE READING and is flagged as such:
             ;; the design says "the old generation's pending calls and
             ;; hosted monitors are settled per the channel contract"
             ;; without spelling that contract out. Pending calls are
             ;; unambiguous -- no reply can arrive on a closed
             ;; connection. Hosted monitors are the open question: for a
             ;; new incarnation (I6) they are certainly dead, and for a
             ;; new connection of the SAME incarnation the peer may or
             ;; may not re-register. Dropping them is the reading that
             ;; cannot lose a resource; keeping them would be the reading
             ;; that cannot lose a registration.
             (stop-link! (entry-conn old) (entry-link old) 'replaced)
             (drop-hosted-monitors! name)
             (fail-pending-for! name)
             (dispatch-wake!)
             'replaced)
            ((installed) (dispatch-wake!) 'installed)
            ((idempotent) 'idempotent)
            ((protocol-error) (tcp-close! c) 'protocol-error)
            (else (tcp-close! c) 'refused))))))

  ;; ---- the dispatcher ----------------------------------------------------
  ;;
  ;; ONE PROCESS DELIVERS EVERY TOPOLOGY EVENT. Until now delivery ran in
  ;; whichever process had queued the event -- a link process or a dial
  ;; attempt -- which put the delivery inside the death it was reporting.
  ;; done(head) made that death a retention rather than a loss, but a
  ;; retained event still needs somebody to come back for it, and there
  ;; was nobody: the container was there and the way in was gone. This is
  ;; the way in.
  ;;
  ;; ⭐ WHAT A SUCCESSOR INHERITS IS THE WHOLE DESIGN. The ready chain is
  ;; module state, not this process's mailbox. A replacement walks the
  ;; same chain and finds the same heads, including the one it was in the
  ;; middle of when its predecessor died, and including heads queued
  ;; while no dispatcher existed at all. The `work` message is a wake-up
  ;; hint and nothing more -- losing one costs latency, never an event.
  ;; That is the only reason the receive has a timeout: it is the
  ;; backstop for a hint sent to a pid that had already died, and if it
  ;; ever becomes the thing that makes delivery work, something above is
  ;; broken.
  ;;
  ;; ⚠ THE PRICE IS A DUPLICATE, and it is not evenly paid. Dying after
  ;; the delivery and before the confirmation leaves the node at the
  ;; front, so the successor sends it again. A token subscriber has the
  ;; token and the sequence number in the message and can drop the
  ;; repeat; a legacy two-element message carries neither, so an older
  ;; subscriber sees it. That is declared, not absorbed -- see the shape
  ;; promise at notify-one!.
  ;;
  ;; FAIRNESS IS ONE EVENT PER HEAD PER ROUND, not draining a head to
  ;; empty. A peer flapping fast enough to keep its own queue non-empty
  ;; would otherwise hold the only deliverer for as long as it kept
  ;; flapping, and every other peer's notices would wait behind it.
  (define dispatcher-name 'igropyr-node-dispatcher)
  (define dispatch-idle-ms 1000)

  (define (dispatch-wake!)
    (let ((d (whereis dispatcher-name)))
      (when d (send d (vector 'work)))))

  ;; At most one event from this head. The answer is also the signal that
  ;; another round is worth running.
  (define (dispatch-one! h)
    (let ((n (atomically (qhead-peek h))))
      (and n
           (let ((ev (qnode-event n)))
             (notify-list! (qnode-cut n) (event-name ev) (event-kind ev) (event-seq ev))
             ;; delivered, and only now is it gone. A death anywhere above
             ;; this line leaves the event where it was, for the successor.
             (atomically (qhead-done! h n))
             #t))))

  ;; A head leaves the chains only when it is empty, and emptiness is
  ;; re-tested inside the region: something may have been queued on it
  ;; between the delivery above and this test, and a head dropped while
  ;; holding an event is unreachable work.
  (define (dispatch-retire! h)
    (atomically
      (when (qhead-empty? h)
        (ready-detach! h)
        (when (qhead-oname h) (orphan-detach! (qhead-oname h))))))

  (define (dispatch-round!)
    (let loop ((h (atomically ready)) (any #f))
      (if (not h)
          any
          ;; next FIRST: retiring this head clears its own link, and
          ;; reading it afterwards walks into a node that is nowhere.
          (let ((next (atomically (qhead-rnext h))))
            (let ((did (dispatch-one! h)))
              (dispatch-retire! h)
              (loop next (or any did)))))))

  (define (dispatcher-loop)
    (register dispatcher-name self)
    ;; A ROUND BEFORE THE FIRST RECEIVE. This is what makes a restart
    ;; recover rather than merely resume: whatever was queued while the
    ;; previous dispatcher was dying is on the chain now, and no hint
    ;; about it survived.
    (let loop ()
      (if (dispatch-round!)
          (loop)
          (let ((m (receive
                     (after dispatch-idle-ms 'idle)
                     (`#(work) 'work)
                     (`#(node-stop) 'stop)
                     ;; MUST STAY LAST -- bare identifier, catch-all.
                     ;; Said out loud rather than dropped: nothing else
                     ;; should be sending here, so a message that arrives
                     ;; is a mistake somewhere, and a silent branch would
                     ;; make it a mistake nobody can find.
                     (other
                       (display "igropyr node: dispatcher discarded an unrecognised message\n"
                                (current-error-port))
                       'other))))
            (unless (eq? m 'stop) (loop))))))

  ;; Did the install succeed, in the sense the caller cares about: is
  ;; this connection now the one in the table?
  (define (installed? outcome)
    (memq outcome '(installed idempotent replaced)))

  ;; THE ORDER, AS A VALUE. Exported because the requirement "I0 is
  ;; first" is otherwise expressed only as source layout, and source
  ;; layout is the one property a test cannot read. With this, the
  ;; requirement becomes an equality a cell can assert, and moving a rule
  ;; is a visible change rather than a silent one.
  ;;
  ;; It reports names, not procedures: the point is the sequence, and
  ;; handing out the predicates would invite a caller to depend on the
  ;; tree's internals instead of on its decisions.
  (define (node-install-rule-order)
    (map irule-name (install-rules)))


  ;; idempotent: only removes the entry if it still belongs to this conn
  ;; The link to `name` is gone, so every monitor we HOST on its behalf
  ;; is now unreportable: tear them down (each demon-local demonitors the
  ;; local process and frees its callee-agents slot). Without this a peer
  ;; that connects, parks monitors, and drops -- over and over -- would
  ;; leak agents and eventually exhaust max-hosted-monitors.
  (define (drop-hosted-monitors! name)
    (let ((head (atomically (mon-splice-peer! name))))
      (let walk ((r head))
        (when r
          ;; next FIRST: this node's own links are about to be cleared by
          ;; whoever retires it, and reading them afterwards would walk
          ;; into a node that is no longer anywhere.
          (let ((next (agent-pnext r)))
            (agent-pnext-set! r #f)
            (agent-pprev-set! r #f)
            (send (agent-pid r) (vector 'demon-local))
            (walk next))))))

  ;; A REAL DEATH, and the queue has to outlive the entry it hangs on.
  ;; The entry goes in the same region that queues this peer's own
  ;; `node-down`, so deleting the entry would delete the notice about the
  ;; deletion -- the notification destroyed by the very thing it is
  ;; about. The head therefore moves to the orphan chain, and onto the
  ;; ready chain in the same region, so the dispatcher finds it with no
  ;; entry to reach it through; it leaves both chains when it empties.
  (define (remove-peer! name c)
    (let* ((node (make-qnode (make-event 'node-down name) #f '()))  ; (R0): outside
           (cut #f)
           (mine?
             (atomically
               (let ((e (hashtable-ref peers name #f)))
                 (and e (eq? (entry-conn e) c)
                      (let ((h (entry-head e)))
                        (set! cut (hashtable-ref watchers name '()))
                        (qhead-enqueue! h node cut)
                        (hashtable-delete! peers name)
                        (orphan-attach! h name)
                        #t))))))
      (tcp-close! c)
      (when mine?
        (drop-hosted-monitors! name)       ; free monitors this peer parked here
        (fail-monitors-for! name)          ; DOWN(noconnection) for watchers
        (fail-pending-for! name)           ; nothing will answer these now
        (dispatch-wake!))))

  ;; Calls waiting on a peer that just went: no reply can arrive for them,
  ;; so the entry would sit here until its caller's own timeout removed it
  ;; -- and a caller killed while waiting never runs that, leaving a dead
  ;; PCB pinned in this global table for the life of the VM. Waking the
  ;; live ones now is also strictly better than making them serve out a
  ;; timeout for an answer that cannot come; the caller sees the same
  ;; rcall-error it would have seen, only sooner. The message is harmless
  ;; to a caller that has already moved on, whose ref can never match again.
  (define (fail-pending-for! name)
    (let ((doomed
            (atomically
              (let ((ks (hashtable-keys pending)) (acc '()))
                (do ((i 0 (fx+ i 1))) ((fx= i (vector-length ks)) acc)
                  (let* ((ref (vector-ref ks i))
                         (slot (hashtable-ref pending ref #f)))
                    (when (and slot (eq? (vector-ref slot 1) name))
                      (hashtable-delete! pending ref)
                      (set! acc (cons (cons ref (vector-ref slot 0)) acc)))))))))
      (for-each
        (lambda (p)
          (send (cdr p) (vector 'rcall-reply (car p) (list 'error 'noconnection))))
        doomed)))

  ;; ---- the link: one process per live connection ---------------------------

  ;; the wire shapes a link may carry (peer is the node at the far end of
  ;; c). Anything else is a confused peer -> drop the link.
  (define (dispatch! c peer d)
    (cond
      ;; (send ,reg-name ,msg) -> deliver to that registered process
      ((and (frame? d 'send 3) (symbol? (cadr d)))
       (let ((p (whereis (cadr d))))
         (when p (send p (caddr d)))))          ; unregistered name: drop
      ;; (call ,reg-name ,ref ,msg ,timeout-ms) -> serve a cross-node
      ;; rcall, unless we are already serving the maximum: then shed,
      ;; answering (error overload) at once. The slot is released when the
      ;; server finishes.
      ;;
      ;; THE CALLER STATES HOW LONG IT WILL WAIT (version 3 widened this
      ;; frame from four elements to five for it). Before, the callee
      ;; waited a fixed default and a caller willing to wait longer got an
      ;; error for a call that was still running. What the callee keeps is
      ;; a ceiling of its own -- serve-timeout-cap-ms -- so the field asks
      ;; for less work, never more. It is a duration and not a deadline;
      ;; serve-timeout-cap-ms says what that does and does not promise.
      ((and (frame? d 'call 5) (symbol? (cadr d)))
       (let ((reg (cadr d)) (ref (caddr d)) (m (cadddr d))
             (timeout (list-ref d 4)))
         ;; VALIDATED HERE, IN THE LINK PROCESS, AND BEFORE THE SPAWN.
         ;; Deliberately wider than what rcall will SEND (a fixnum): any
         ;; positive exact integer is usable here, because min caps it
         ;; against this node's own ceiling whatever its size, and there
         ;; is no reason to drop a link over a number this side can use.
         ;; See rcall for the other half of that asymmetry.
         ;; Both this and a check inside the server would notice a bad
         ;; value; only this one is a protocol refusal. A raise inside the
         ;; spawned process kills that process and leaves the link up, so
         ;; a peer sending (call n r m "abc") would go on being talked
         ;; to -- and a peer that puts an unusable value in a field is the
         ;; definition of the confused peer this link drops. Before the
         ;; spawn, and before the slot is taken, so a refused call cannot
         ;; leak a serving slot either.
         (unless (and (integer? timeout) (exact? timeout) (> timeout 0))
           (raise 'protocol))
         (if (lease-admit! 'serving max-rcall-serving
               (lambda (s)
                      ;; THE SLOT IS RELEASED WHETHER OR NOT THE SERVER
                      ;; RETURNS NORMALLY. serve-rcall! can raise -- its
                      ;; fallback reply goes through link-write, which
                      ;; reports a failed submission by raising -- and a
                      ;; raise here would skip the release. A ceiling
                      ;; meant to bound concurrency would then ratchet
                      ;; downwards instead, until every remote call was
                      ;; shed as overload: the failure mode is a node
                      ;; that answers nothing while looking busy.
                      ;;
                      ;; THIS IS AN ESCAPE BRANCH AND IT SWALLOWS
                      ;; SOMETHING. What it swallows is the failure to
                      ;; send a reply -- either the reply frame or the
                      ;; fallback that stands in for it. That is
                      ;; tolerable here and nowhere near tolerable in
                      ;; general: the peer waiting for this reply has its
                      ;; own rcall timeout, so the cost is one call that
                      ;; times out instead of erroring, which is what
                      ;; happens today when a reply is lost in the
                      ;; network. A leaked slot, by contrast, has nothing
                      ;; that ever gives it back.
                      ;;
                      ;; IT IS ONE OF TWO WAYS THIS SLOT CAN BE LOST, and
                      ;; the other is now repaired elsewhere: the release
                      ;; below is still skipped if this process is KILLED,
                      ;; since a kill runs no handlers, and no guard can
                      ;; cover that. What covers it is that the slot knows
                      ;; who holds it, so the reaper gives it back on the
                      ;; DOWN it sees. This branch handles the raise; the
                      ;; owner handles the kill.
                 (guard (e (#t (void)))
                   (serve-rcall! peer reg ref m timeout))
                 (lease-free! s)))
             (void)
             ;; REFUSED. The admission returned #f, which is the only way
             ;; to get here: an admitted call has a process of its own and
             ;; nothing more to do on this one.
             (guard (e (#t (void)))
               (write-frame! c (list 'reply ref (list 'error 'overload)))))))
      ;; (reply ,ref ,result) -> route back to the waiting rcall caller,
      ;; but only if the reply arrives from the node that call targeted
      ;; (a ref is bound to its node, so one peer can't answer a call
      ;; the caller sent to another)
      ((frame? d 'reply 3)
       (let ((ref (cadr d)) (result (caddr d)))
         ;; Delete here, not only in the caller's branches. Both of those --
         ;; the reply clause and the timeout handler -- run in the CALLER's
         ;; process, so a caller killed while waiting (a stuck worker reaped
         ;; by its supervisor, say) runs neither, and its entry stays in this
         ;; global table forever, pinning a dead PCB and a node name. A ref
         ;; is answered at most once, so removing it as the reply is routed
         ;; is correct for a live caller too: it has the message by then.
         (let ((slot (atomically
                       (let ((v (hashtable-ref pending ref #f)))
                         (when v (hashtable-delete! pending ref))
                         v))))
           (when (and slot (eq? (vector-ref slot 1) peer))
             (send (vector-ref slot 0) (vector 'rcall-reply ref result))))))
      ;; (mon ,name ,mref) -> watch our local reg-name for the peer at the
      ;; far end of this link. The watcher node is `peer` (the identity
      ;; the handshake authenticated), NOT a field in the frame: a node
      ;; must not be able to name a THIRD node as the monitor origin and
      ;; have our mdown notifications routed there. Register the agent in
      ;; callee-agents SYNCHRONOUSLY (before it can run) so a demon frame
      ;; that follows on this same link always finds it -- the agent spawn
      ;; alone would race the demon.
      ((and (frame? d 'mon 3) (symbol? (cadr d)))
       (let* ((name (cadr d)) (mref (caddr d))
              (key (cons peer mref)))
         ;; A REPEAT OF THIS EXACT REQUEST IS FREE; A DIFFERENT REQUEST
         ;; UNDER THE SAME KEY IS A PROTOCOL ERROR.
         ;;
         ;; What used to be here was an unconditional set!, and the hole
         ;; had no floor: the same (peer . mref) sent again spawned
         ;; another agent and overwrote the pid of the last one. The table
         ;; stayed at one entry, so the ceiling always passed -- while
         ;; every overwritten agent stayed alive and became invisible,
         ;; the only handle on it being the pid just replaced. One key was
         ;; enough to make unbounded processes.
         ;;
         ;; Idempotence is judged on the whole triple -- this connection,
         ;; the reference, and the name being watched -- because those are
         ;; what the agent was built from. Matching the key alone would
         ;; let a peer re-point an existing reference at a different name
         ;; and be told "already done" for something it never asked for.
         ;; A mismatch is not a replacement request: one reference cannot
         ;; mean two things, so the link goes.
         (unless (atomically
                   (let* ((found (hashtable-ref callee-agents key #f))
                          ;; A STALE ENTRY MUST NOT ANSWER "already done".
                          ;; Returning the credit on the DOWN a reaper
                          ;; observes -- rather than on the agent's own way
                          ;; out -- also moves WHEN the entry disappears: it
                          ;; outlives its agent by however long that DOWN
                          ;; takes to be processed. In that window the same
                          ;; request arriving again would match the triple
                          ;; and be told it was already armed, while the
                          ;; agent behind it is dead and the watch is
                          ;; silently doing nothing.
                          ;;
                          ;; So liveness is part of the match. A dead record
                          ;; for this exact request is retired here and the
                          ;; request treated as new; the reaper's DOWN then
                          ;; finds nothing left to do, which is what
                          ;; retire-agent! being idempotent is for.
                          (cur (and found
                                    (if (process-alive? (agent-pid found))
                                        found
                                        (begin (retire-agent-locked! key) #f)))))
                     (cond
                       ((and cur (agent-matches? cur c name)) #t)
                       (cur (raise 'protocol))
                       ((fx< (accounted-monitors) max-hosted-monitors)
                        ;; THREE STEPS THAT MUST NOT BE LEFT HALF DONE.
                        ;; Each of them can raise -- the record and the
                        ;; process are allocations, and the table takes a
                        ;; NEW key, so it can grow. Stopping in the middle
                        ;; used to leave one of two states nobody would
                        ;; ever notice: a process running with no entry
                        ;; anywhere, or an entry on no chain and in no
                        ;; count, which the reaper walks past forever
                        ;; while a later request for the same key reads it
                        ;; as current.
                        ;;
                        ;; ⭐ THE GUARD IS INSIDE THE REGION. It is not a
                        ;; style choice: outside it, the moment between
                        ;; the failure and the cleanup is a moment another
                        ;; link can read the half-installed entry, be told
                        ;; the monitor is armed, and then watch it be
                        ;; deleted. Inside, there is no such moment,
                        ;; because nothing else has run at all -- which is
                        ;; also what makes the cleanup's own actions
                        ;; provably harmless. See undo-install!.
                        (let ((p #f))
                          (guard (e (#t (undo-install! key p) (raise e)))
                            (set! p (spawn (lambda () (mon-agent peer key name))))
                            (let ((r (make-agent-rec p name c key peer)))
                              (hashtable-set! callee-agents key r)
                              (mon-link! r)
                              ;; last, and it cannot raise: reaching it
                              ;; means there is nothing left to undo
                              (set! active-monitors (fx+ active-monitors 1))))
                          ;; ⛔ DELIBERATELY OUTSIDE THE GUARD. By here the
                          ;; state is complete and consistent, and this
                          ;; send allocates a mailbox node, so it can
                          ;; raise. Undoing the install because the
                          ;; ANNOUNCEMENT failed would delete a monitor
                          ;; that is correctly armed -- and the rescan
                          ;; already covers a watch that never arrives,
                          ;; which is why the send was made asynchronous
                          ;; in the first place. The scope of the guard is
                          ;; the documentation: what is inside it is what
                          ;; is not yet safe to leave behind.
                          (let ((rp (reaper-pid)))
                            (when rp
                              (send rp (vector 'watch p key)))))
                        #t)
                       (else #f))))
           ;; At the hosting ceiling: refuse, and tell the watcher at
           ;; once. THIS REFUSAL IS A CONTROL FRAME NOBODY TIMES OUT --
           ;; monitor-remote has no clock of its own, so a watcher that
           ;; never hears the refusal stays armed for a monitor this node
           ;; declined to host. Same test as link-write/critical: if the
           ;; frame does not go, the far end never learns anything, so
           ;; the link goes instead.
           ;;
           ;; We ARE the link process here, so the way to take the link
           ;; down is to raise -- no message to send to ourselves. The
           ;; old guard swallowed everything; nothing it protected
           ;; against remains (this frame is (mdown <int> overload),
           ;; which always serializes).
           (let-values (((ok failure)
                         (write-body! c (frame-segments
                                          (list 'mdown mref 'overload)))))
             (when (and (not ok) failure)
               (raise (submission-failure peer failure)))))))
      ;; (mdown ,mref ,reason) -> the watched process/link is gone; only
      ;; honor it from the node the monitor actually targets
      ((frame? d 'mdown 3)
       (let ((mref (cadr d)) (reason (caddr d)))
         (let ((entry (atomically (hashtable-ref rmonitors mref #f))))
           (when (and entry (eq? (vector-ref entry 1) peer))
             (fire-remote-down! mref reason)))))
      ;; (demon ,mref) -> stop a monitor we host for this peer
      ((frame? d 'demon 2)
       (let ((rec (atomically
                    (hashtable-ref callee-agents (cons peer (cadr d)) #f))))
         (when rec (send (agent-pid rec) (vector 'demon-local)))))
      ((equal? d '(ping)) (write-frame! c '(pong)))
      ((equal? d '(pong)) (void))
      (else (raise 'protocol))))                ; confused peer: drop it

  (define (frame? d tag len)
    (and (pair? d) (eq? (car d) tag) (list? d) (= (length d) len)))

  ;; callee side of an rcall: run the local gen-server call (which brings
  ;; its own monitor + timeout), then ship the result back over the link.
  ;; Any failure -- no such server, it died, it timed out, or a reply
  ;; that will not serialize -- comes back as (error <reason-symbol>) so
  ;; the caller never hangs.
  ;;
  ;; The wait is the SMALLER of what the caller asked for and what this
  ;; node is willing to spend on one call; see serve-timeout-cap-ms for
  ;; why neither half can be dropped. Timing out here does not stop the
  ;; gen-server, exactly as it does not for a local caller.
  (define (serve-rcall! peer reg ref m timeout)
    (let ((result (guard (e (#t (list 'error (rcall-reason e))))
                    (list 'ok (gen-server-call reg m
                                (min timeout serve-timeout-cap-ms))))))
      (let ((e (live-entry peer)))
        (when e
          (guard (e2 (#t (link-write peer (list 'reply ref
                                                (list 'error 'not-serializable)))))
            (write-frame! (entry-conn e) (list 'reply ref result)))))))

  (define (rcall-reason e)
    (if (and (vector? e) (> (vector-length e) 1) (symbol? (vector-ref e 1)))
        (vector-ref e 1)                        ; e.g. gen-server-error tag
        'unavailable))

  ;; Write one datum to a peer by name, if the link is live.
  ;; -> #t if there was a live link to write to.
  ;;
  ;; ONE CALLER, ENUMERATED FROM THE FILE AND NOT FROM MEMORY:
  ;; serve-rcall!'s fallback reply, and it does not read the answer. (An
  ;; earlier version of this comment said rcall and monitor-remote read
  ;; it -- they do not call this procedure at all -- and a later one
  ;; listed three callers, which was true until the monitor traffic moved
  ;; to link-write/critical. A claim about which call sites exist is
  ;; refutable by one grep and has to be written from one, every time it
  ;; is written.)
  ;;
  ;; THE REMAINING CALLER IS HERE AND NOT IN link-write/critical BECAUSE
  ;; ITS FRAME'S LOSS IS DETECTABLE BY THE FAR END: an rcall that gets no
  ;; reply times out. Losing it costs one call an error instead of an
  ;; answer, which is what losing a reply in the network already costs,
  ;; and is not grounds for taking a working link away from every other
  ;; conversation on it.
  ;;
  ;; It raises on a failed submission, in the shape rsend uses -- the
  ;; same event on an internal path. That raise leaves serve-rcall!, and
  ;; the process running it releases its serving slot regardless: see the
  ;; guard at the spawn in dispatch!.
  (define (link-write peer datum)
    (let ((e (live-entry peer)))
      (and e
           (let-values (((ok failure)
                         (write-body! (entry-conn e)
                                      (frame-segments datum))))
             (cond (ok #t)
                   (failure (raise (submission-failure peer failure)))
                   (else #f))))))

  ;; THE CONTRACT THIS PATH KEEPS: either the frame goes, or the link
  ;; goes. Its callers are agents that have already dropped their own
  ;; state, so "neither" is the one outcome that strands a watcher on a
  ;; healthy link -- which is what all of this is for.
  ;;
  ;; WHERE THE CONTRACT ENDS. It holds on every path the program can act
  ;; on; its last link -- the failure handling's own allocations -- can
  ;; still give way in the OOM domain, because any action taken on
  ;; failure needs resources and some link is always last. Stated once,
  ;; here, where the contract is made: a reader who has just been told
  ;; "either the frame goes or the link goes" is exactly the reader who
  ;; needs its boundary, and three copies at the call sites would rot
  ;; separately.
  ;;
  ;; For a control frame WHOSE LOSS THE FAR END CANNOT DETECT. That is
  ;; the test, and it is not "is this frame important": an rcall reply
  ;; matters more than a demon, and its loss costs the peer a timeout it
  ;; already has. An mdown or a demon that never goes out costs the peer
  ;; a wait with no end in it, because nothing over there is counting.
  ;;
  ;; So a failed submission takes the LINK down instead of being
  ;; swallowed: slow-is-dead, the same rule the rest of this layer
  ;; follows. A link that cannot carry its own control traffic is not
  ;; serving anyone, and dropping it is what turns an unbounded wait into
  ;; the answer the far end already knows how to produce -- its own
  ;; fail-monitors-for! synthesizes noconnection for every watch that
  ;; crossed the link.
  ;;
  ;; TAKES AN ALREADY-MATERIALIZED FRAME, not a datum. That is what
  ;; separates the two failures this path must not confuse: building the
  ;; frame can fail because the writer refuses the datum, and that is the
  ;; CALLER's business (mon-agent answers it by degrading the reason to
  ;; 'exit), while submitting it can fail because the link cannot carry
  ;; it, and that is this procedure's business. Splitting them by WHERE
  ;; THEY HAPPEN needs no predicate to tell them apart -- an earlier
  ;; version reasoned that no reliable predicate exists and concluded
  ;; that the two could not be separated at all, which confused "this
  ;; particular mechanism does not work" with "the thing cannot be done".
  ;;
  ;; THE CONNECTION THAT FAILED IS THE ONE TAKEN DOWN -- but only if it
  ;; is still the connection this peer is reached on.
  ;;
  ;; A LINK CAN BE REPLACED UNDER THIS CALL. Between taking the entry and
  ;; finishing the write there are safe points, and a duplicate dial can
  ;; win the tie-break in that window: install-peer! swaps the table over
  ;; to the new connection and condemns the old one. If the write then
  ;; fails on the old connection, taking "the link" down accomplishes
  ;; nothing -- that connection was already dying, and remove-peer!
  ;; deliberately skips its monitor cleanup because the table no longer
  ;; points at it, so the far end is told nothing by anybody. The frame
  ;; is simply retried on the connection that is now current.
  ;;
  ;; IT TERMINATES because a retry is only taken when the current
  ;; connection is not the one just written to, so each iteration
  ;; requires another generation to have been INSTALLED AS CURRENT.
  ;; (Not "to have won a tie-break": install-peer! replaces a connection
  ;; that is no longer open without comparing anything, so the stronger
  ;; phrasing an earlier version used named a path that need not be
  ;; taken.) The iteration count is bounded by real reconnections; a
  ;; failure on a connection that is still current never retries; and
  ;; when the peer has no current connection at all, the next round's
  ;; live-entry ends the loop.
  ;;
  ;; A SERIALIZATION FAILURE STILL PROPAGATES. Only a failed submission is
  ;; handled: a datum the writer refuses is a different event with a
  ;; different repair, and mon-agent's degrade-to-'exit path depends on
  ;; still seeing it.
  (define (link-write/critical peer segs why)
    (let retry ()
      (let ((e (live-entry peer)))
        (and e
             (let ((c (entry-conn e)) (link (entry-link e)))
               ;; EVERY WAY THIS CAN FAIL IS TREATED THE SAME, so none of
               ;; them is distinguished. The frame is already built, so
               ;; what remains is the submission: it can answer #f for a
               ;; connection that was not open, answer #f for a refusal,
               ;; or raise from the allocating steps outside write-body!'s
               ;; own guard.
               ;;
               ;; WHAT THEY SHARE IS NOT "THE FRAME DID NOT ARRIVE" -- an
               ;; earlier version of this comment said that and it is
               ;; false. close-for-backpressure! runs AFTER a successful
               ;; submission, so a raise from it is caught here with the
               ;; frame already handed over and possibly delivered. What
               ;; they share is that SUCCESS CANNOT BE CONFIRMED, and the
               ;; safe way to converge on that is to treat it as failure:
               ;; a repeated mdown or demon is harmless (both are keyed by
               ;; mref and the second finds nothing to act on), and a
               ;; connection over its outbound ceiling was due to be
               ;; closed anyway.
               ;;
               ;; Letting a raise escape instead would break the contract
               ;; in the worst way available: the caller is an agent that
               ;; has already dropped its state, so the frame would not go
               ;; AND the link would not go, which is the outcome this
               ;; whole path exists to prevent.
               (let ((ok (guard (e2 (#t #f))
                           (let-values (((ok failure) (write-body! c segs)))
                             ok))))
                 (cond
                   (ok #t)
                   ;; THE GENERATION TEST AND THE CLOSE ARE ONE STEP.
                   ;; install-peer! does its table swap inside an atomic
                   ;; region, so holding interrupts across the test and
                   ;; the close excludes it entirely -- the connection
                   ;; cannot be replaced between deciding that it is
                   ;; current and acting on that. Testing and then
                   ;; closing as two steps only narrows the window: a
                   ;; replacement landing in between leaves this call
                   ;; closing a connection that was already condemned and
                   ;; NOT retrying on the live one, while the old
                   ;; connection's teardown skips its monitor cleanup
                   ;; because the table has moved on. Narrowing a window
                   ;; is not closing it, and a test whose answer can go
                   ;; stale before it is used is the same mistake as
                   ;; keying on how a failure was reported instead of on
                   ;; what state the connection is in.
                   ((atomically
                      (and (eq? c (current-conn peer))
                           (begin (stop-link! c link why) #t)))
                    #f)
                   (else (retry)))))))))

  ;; The connection this peer is currently reached on, or #f. Used to ask
  ;; whether a connection in hand is still the current one.
  (define (current-conn peer)
    (let ((e (peer-entry peer)))
      (and e (entry-conn e))))

  ;; Take down whatever connection this peer is currently reached on.
  ;;
  ;; BY NAME, WHICH THE REST OF THIS FILE IS CAREFUL NOT TO DO, and the
  ;; exception is the point rather than a lapse. Everywhere else a link
  ;; is taken down because a SPECIFIC connection failed, and looking the
  ;; peer up again could condemn a healthy replacement for its
  ;; predecessor's failure. Here there is no such connection: the frame
  ;; was never built, so nothing was written anywhere, and there is
  ;; nothing to blame a particular generation for.
  ;;
  ;; What is left is the intent, and the intent is about the PEER: a
  ;; monitor this node can no longer report on has to fail over, and the
  ;; only mechanism that produces that is a link going down so the far
  ;; end synthesizes noconnection. Closing the current connection
  ;; achieves it whichever generation that is. The cost of closing one
  ;; that just replaced the old is a reconnect -- and the failover still
  ;; happens, which is what was being asked for.
  (define (drop-link-by-name! peer why)
    (let ((e (peer-entry peer)))
      (when e (stop-link! (entry-conn e) (entry-link e) why))))

  ;; ---- cross-node process monitor ----------------------------------------

  ;; target side: one process per remote watch. It locally monitors the
  ;; registered process and reports its death back over the link. A
  ;; missing name is an immediate 'noproc. The reason is shipped as-is
  ;; when wire-safe, else degraded to 'exit: a reason that will not
  ;; serialize must not be allowed to swallow the DOWN, which is what
  ;; this degradation is for. (It is not a promise that a DOWN always
  ;; arrives -- see the submission note below for the case where the
  ;; frame carrying it never goes out.)
  ;; key is (peer . mref); dispatch registered us under it before we ran.
  ;; watcher is that same peer -- the authenticated far end -- and is the
  ;; only node we ever report this DOWN back to.
  ;;
  ;; IF THE mdown FRAME IS NEVER SUBMITTED, THE LINK GOES DOWN. By then
  ;; this agent has dropped its state and is about to exit, so nothing
  ;; here can carry the DOWN any further; and the watcher has no timeout
  ;; of its own, so a lost frame would leave it waiting on an answer that
  ;; is not coming. Taking the link down instead hands the far end a
  ;; question it already knows how to answer: its own fail-monitors-for!
  ;; synthesizes noconnection for every watch that crossed that link,
  ;; this one included. The demon frame in remove-target-watch! is the
  ;; same case and takes the same route. See link-write/critical for the
  ;; rule, and for why an rcall reply is deliberately NOT in this class.
  (define (mon-agent watcher key name)
    (let ((mref (cdr key))
          (p (whereis name)))
      (if (not p)
          (begin
            (void)
            ;; Building the frame can fail too -- the allocation, not the
            ;; writer, since this datum always serializes -- and by here
            ;; the agent has dropped its state and is leaving. Same
            ;; contract as the submission: if the frame does not go, the
            ;; link does.
            (guard (e (#t (drop-link-by-name! watcher 'mdown-lost)))
              (link-write/critical watcher
                                   (frame-segments (list 'mdown mref 'noproc))
                                   'mdown-lost)))
          (let ((m (monitor p)))
            (receive
              (`#(DOWN ,@p ,reason)
                (void)
                ;; THE GUARD COVERS BUILDING THE FRAME AND NOTHING ELSE,
                ;; which is what it was always meant to cover. A reason
                ;; that will not serialize is degraded to 'exit; the
                ;; submission that follows is link-write/critical's
                ;; problem and is not inside this guard at all.
                ;;
                ;; It got here by scope, not by a predicate. Two earlier
                ;; versions of this comment are worth remembering: one
                ;; claimed the guard handled serialization failures "and
                ;; only that" while it was a bare (#t ...) catching
                ;; everything; the next admitted the breadth and argued
                ;; it was unavoidable because no predicate can tell a
                ;; serializer's refusal from an allocation failure. The
                ;; predicate part was true and the conclusion did not
                ;; follow -- moving one of the two operations out of the
                ;; guarded region separates them by WHERE THEY RUN, and
                ;; needs to recognise nothing.
                ;; TWO GUARDS, TWO QUESTIONS. The inner one asks whether
                ;; the REASON can be written and degrades it to 'exit if
                ;; not. The outer one asks nothing: any failure at all --
                ;; including the fallback materialization raising, which
                ;; the inner handler is not itself protected against --
                ;; means this DOWN is not going to be delivered, and the
                ;; contract for that is the link, not silence.
                (guard (e2 (#t (drop-link-by-name! watcher 'mdown-lost)))
                  (let ((segs (guard (e (#t (frame-segments
                                              (list 'mdown mref 'exit))))
                                (frame-segments (list 'mdown mref reason)))))
                    (link-write/critical watcher segs 'mdown-lost))))
              (`#(demon-local)
                (demonitor m)
                (void)))))))

  (define (stop-owner-agent! mref)
    (let ((agent (atomically
                   (let ((a (hashtable-ref owner-agents mref #f)))
                     (when a (hashtable-delete! owner-agents mref))
                     a))))
      (when (and agent (process-alive? agent))
        (send agent (vector 'owner-stop)))))

  (define (remove-target-watch! mref entry)
    (let ((node (vector-ref entry 1)))
      (if (eq? node self-name)
          (let ((agent (atomically
                         (let ((a (hashtable-ref caller-agents mref #f)))
                           (when a (hashtable-delete! caller-agents mref))
                           a))))
            (when (and agent (process-alive? agent))
              (send agent (vector 'demon-local))))
          ;; Same contract as the mdown paths: this side has already
          ;; dropped its rmonitors entry, so a demon that is never built
          ;; leaves the target's agent parked with nobody to free it.
          (guard (e (#t (drop-link-by-name! node 'demon-lost)))
            (link-write/critical node (frame-segments (list 'demon mref))
                                 'demon-lost)))))

  ;; One small local monitor ties the global/remote state to the process
  ;; that requested it. Without this, rmonitors roots a dead pcb and the
  ;; target node retains its monitor until the target or link dies.
  (define (owner-mon-agent caller mref)
    (let ((m (monitor caller)))
      (receive
        (`#(DOWN ,@caller ,_)
          (atomically (hashtable-delete! owner-agents mref))
          (let ((entry (atomically
                         (let ((e (hashtable-ref rmonitors mref #f)))
                           (when e (hashtable-delete! rmonitors mref))
                           e))))
            (when entry (remove-target-watch! mref entry))))
        (`#(owner-stop) (demonitor m)))))

  ;; THE ENTRY AND ITS RELEASER MUST APPEAR TOGETHER. The rmonitors entry
  ;; roots the caller's pcb; the owner agent is the only thing that clears
  ;; that entry when the caller dies. Written as two separate atomic steps
  ;; they can be split by a kill, leaving an entry rooted with nothing left
  ;; to release it -- reclaimed only if the link to that node later drops,
  ;; which on a mesh that stays up never happens. That is precisely the
  ;; leak this mechanism exists to prevent, moved one table over.
  ;;
  ;; Interrupts stay off across the whole arming, so no kill can land in
  ;; the middle of it. The rule the two former helpers carried -- publish
  ;; the agent's pid before the agent can run -- still holds, and holds
  ;; more simply: nothing runs at all until the region ends.
  ;; Undo an arming that stopped part way. UNCONDITIONAL, and it can be:
  ;; the mref was minted for this call and nothing else can be filed
  ;; under it, so deleting all three keys removes only what this arming
  ;; put there, and a key that was never written is a no-op. That is why
  ;; there are no "did I do this step" flags here -- the freshness of the
  ;; key does the work bookkeeping would otherwise have to do.
  ;;
  ;; ⭐ IT MUST REACH THE RMONITORS ENTRY, not only the agents. Undoing
  ;; the agents alone would leave a monitor that is armed, has nobody to
  ;; fire it, AND has consistent-looking books -- turning a residue two
  ;; exported counts disagree about into one that nothing disagrees
  ;; about. A repair that makes a defect harder to see is worse than the
  ;; defect.
  ;;
  ;; Caller holds the region. Both actions are allocation-free: deletes
  ;; cannot grow a table, and killing a process nothing is watching yet
  ;; sends nothing -- see undo-install! for why that is a structural fact
  ;; here and not a claim about timing.
  (define (undo-remote-arm! mref oa sa)          ; caller holds the region
    (hashtable-delete! rmonitors mref)
    (hashtable-delete! owner-agents mref)
    (hashtable-delete! caller-agents mref)
    (when (and oa (process-alive? oa)) (kill oa 'arm-failed))
    (when (and sa (process-alive? sa)) (kill sa 'arm-failed)))

  ;; THE REMOTE PATH'S ARMING, and the same shape as the local one above.
  ;; The entry and the agent that tears it down go in together or neither
  ;; goes in.
  ;;
  ;; ⚠ THE REASON TO REPAIR THIS IS NOT THE COUNT. If the agent fails to
  ;; install, the stranded rmonitors entry IS collected: the sweep for a
  ;; dropped peer walks every entry naming that node and does not consult
  ;; owner-agents, so the books come back on their own. What does not
  ;; come back is what the missing agent was for. Its job is to notice
  ;; the local caller dying and tell the far node to drop the monitor it
  ;; is holding on our behalf; without it, that registration stays on the
  ;; OTHER node for as long as it runs.
  ;;
  ;; ⭐ So "recoverable" has to be asked about the consequence and not
  ;; about the bookkeeping. Every reading this node has is local, which
  ;; means a residue that lands on the peer looks, from here, exactly
  ;; like nothing happening.
  (define (arm-rmonitor! mref node name)
    (atomically
      (let ((caller self) (oa #f))
        (guard (e (#t (undo-remote-arm! mref oa #f) (raise e)))
          (hashtable-set! rmonitors mref (vector caller node name))
          (set! oa (spawn (lambda () (owner-mon-agent caller mref))))
          (hashtable-set! owner-agents mref oa)))))

  ;; watcher side: deliver #(remote-down node name reason) to the caller
  ;; that installed mref, once. Used for both a target-side mdown and a
  ;; link drop (which synthesizes 'noconnection).
  (define (fire-remote-down! mref reason)
    (let ((entry (atomically
                   (let ((e (hashtable-ref rmonitors mref #f)))
                     (when e (hashtable-delete! rmonitors mref))
                     e))))
      (when entry
        (stop-owner-agent! mref)
        (send (vector-ref entry 0)
              (vector 'remote-down (vector-ref entry 1) (vector-ref entry 2)
                      reason)))))

  ;; self-watch agent: same contract, but the target is local, so the
  ;; DOWN is delivered straight to the caller (no link involved).
  (define (self-mon-agent caller mref name)
    (let ((p (whereis name)))
      (if (not p)
          (begin
            (atomically (hashtable-delete! caller-agents mref))
            (fire-remote-down! mref 'noproc))
          (let ((m (monitor p)))
            (receive
              (`#(DOWN ,@p ,reason)
                (atomically (hashtable-delete! caller-agents mref))
                (fire-remote-down! mref reason))
              (`#(demon-local)
                (demonitor m)
                (atomically (hashtable-delete! caller-agents mref))))))))

  ;; every rmonitor watching a node whose link just dropped gets a
  ;; synthesized noconnection (the target may be alive or dead -- across
  ;; a broken link they're indistinguishable, as in Erlang)
  (define (fail-monitors-for! node)
    (let-values (((mrefs entries) (atomically (hashtable-entries rmonitors))))
      (vector-for-each
        (lambda (mref e)
          (when (eq? (vector-ref e 1) node)
            (fire-remote-down! mref 'noconnection)))
        mrefs entries)))

  (define (link-loop c peer buf last-seen)
    (let drain ()
      ;; EVERY WAKE-UP IS A CHECK ON THE OUTBOUND CEILING, and it is the
      ;; only check that does not depend on this node writing something. A
      ;; connection can sit over the ceiling with nobody about to notice:
      ;; the writer that crossed it was killed before it could close, or
      ;; the ceiling was lowered under a connection already above the new
      ;; value.
      ;;
      ;; THE TICK PING IS NOT THAT CHECK, and neither is a complete frame.
      ;; This loop's receive restarts on every inbound BYTE, so a peer
      ;; that dribbles holds the ping off for as long as it keeps
      ;; dribbling -- and it need never complete a frame to do it: a
      ;; valid length header followed
      ;; by one body byte every few seconds keeps parse-frame answering
      ;; `incomplete` for years -- max-frame bounds it, and the bound is
      ;; that long at one byte per tick -- so a check placed
      ;; after dispatch! is never reached. The check belongs where the
      ;; loop is entered, which is every wake-up: arriving bytes are what
      ;; suppresses the timer, and now they are also what supplies the
      ;; check. It runs before the frame is parsed, so a connection
      ;; already condemned does not first serve one more call.
      ;;
      ;; This process IS the link, so it closes and raises rather than
      ;; sending itself the wake-up that close-for-backpressure! sends
      ;; from a writer's process. Same reason, same value.
      (when (outbound-over? c)
        (tcp-close! c)
        (raise 'outbound-backpressure))
      (let-values (((d _text) (parse-frame buf max-frame)))
        (if (eq? d incomplete)
            (receive (after tick-ms
                        (if (> (- (now-ms) last-seen) dead-ms)
                            (raise 'closed)
                            (begin (write-frame! c '(ping))
                                   (link-loop c peer buf last-seen))))
              (`#(tcp-data ,bv)
                (inbuf-append! buf bv)
                (link-loop c peer buf (now-ms)))
              (`#(tcp-eof) (raise 'closed))
              (`#(tcp-error ,e) (raise 'closed))
              ;; a close decided elsewhere -- see close-for-backpressure!.
              ;; ONLY IF IT NAMES THIS CONNECTION: the sender addressed a
              ;; pid, and a connector pid outlives the connection it was
              ;; running, so one aimed at a link that has already ended can
              ;; arrive after this process has taken up a new one. Anything
              ;; else is news about a connection that is already gone, and
              ;; dropping it is the point. The reason is raised as-is: on
              ;; this link the value that ends the loop IS the reason the
              ;; link died.
              (`#(link-stop ,which ,why)
                (if (eq? which c)
                    (raise why)
                    (link-loop c peer buf last-seen)))
              (`#(node-stop) (raise 'stop)))
            (begin (dispatch! c peer d) (drain))))))

  ;; Run the link until it drops, then clean up.
  ;; -> the moment the link STOPPED CARRYING TRAFFIC, read before the
  ;; teardown rather than after it.
  ;;
  ;; The guard catches every way link-loop ends -- 'closed, 'protocol,
  ;; 'stop, 'outbound-backpressure -- so no link failure reaches the
  ;; caller. What is left is the teardown's own failure domain: it sends
  ;; messages and touches tables, so an allocation failure there does
  ;; propagate. Stated rather than promised away.
  ;;
  ;; The distinction matters because dial! subtracts this to get the
  ;; link's lifetime, and the backoff decides on that number. The teardown
  ;; is not bounded work: it walks every monitor hosted for this peer,
  ;; every remote monitor watching it, every pending call, and a watcher
  ;; list this file documents elsewhere as having no ceiling. Timing that
  ;; as part of the link's life would let a peer that authenticates and
  ;; drops at once be scored as one that stayed up -- on a node whose
  ;; tables have grown, and only on such a node, which is the worst way
  ;; for a measurement to be wrong.
  (define (run-link c peer buf)
    (guard (e (#t (let ((ended (now-ms))) (remove-peer! peer c) ended)))
      (link-loop c peer buf (now-ms))
      (now-ms)))                        ; link-loop only ever exits by raising

  ;; ---- accept side -----------------------------------------------------------

  ;; Runs holding a pre-auth slot, taken by the accept callback. The slot
  ;; covers the handshake only: it is released the moment the peer is
  ;; authenticated, because run-link is no longer a stranger's connection
  ;; and would otherwise pin a slot for the life of the link. Every other
  ;; exit -- a bad proof, a timeout, the 'stop raised at node-stop! -- goes
  ;; through the guard, and free! is idempotent so the two cannot
  ;; double-count. Nothing here is killed abruptly (shutdown is a
  ;; node-stop message, not a kill), so the guard is enough to keep the
  ;; count from drifting.
  (define (acceptor c s)
    (let ()
      ;; No local "already freed" flag: lease-free! is conditional on the
      ;; record still being on the chain, so calling it twice is already
      ;; a no-op the second time. A boolean beside it would be a second
      ;; supplier of the same fact, and the two could disagree.
      (define (free!) (lease-free! s))
      ;; A FAILED HANDSHAKE CLOSES WITHOUT A WORD, and that is deliberate
      ;; here even for a version mismatch. This side faces strangers: a
      ;; scanner that has learned the frame format can reach it, and
      ;; nothing it sends proves it knows the secret, so anything printed
      ;; here is printed at an attacker's request. The dial side is the
      ;; opposite case and does speak -- see report-version-mismatch!.
      ;; The raised value still distinguishes the causes, for a future
      ;; diagnostic that has somewhere safe to put them.
      (guard (e (#t (free!) (tcp-close! c)))    ; failed handshake: just close
        (let ((nonce (random-hex 16))
              (buf (make-inbuf)))
          (write-frame! c (list 'challenge nonce protocol-version self-boot-id))
          (let-values (((d dtext) (read-frame c buf handshake-timeout-ms
                                              handshake-max-frame)))
            ;; ORDER MATTERS, and it is the same on both sides: tag, then
            ;; the pre-versioning arity, then version, then the rest. Checking the shape first would report
            ;; a future peer's longer hello as malformed, which is true and
            ;; useless; checking the version first lets the refusal name
            ;; what is actually wrong. A hello of exactly 4 is the
            ;; pre-versioning shape and gets its own answer rather than
            ;; being folded into "wrong version".
            ;; THE NONCE GRAMMAR IS THIS VERSION'S, SO IT IS APPLIED ONLY
            ;; AFTER THE VERSION MATCHES. Tag, then the pre-versioning
            ;; arity, then the stated version, and only then anything that
            ;; v3 in particular requires of the fields. A v4 that mints
            ;; base64 nonces, or carries an extra element, has to be
            ;; answered "your version differs" rather than refused for
            ;; breaking a rule that was never its rule -- hoisting a
            ;; field-grammar check above the version comparison would
            ;; misclassify exactly the peers this ordering exists for.
            ;;
            ;; A consequence to state rather than leave to be discovered:
            ;; a frame that is malformed AND mismatched is reported as
            ;; mismatched. (challenge "x" 999) answers 999, not "bad
            ;; nonce". That is the policy, not an oversight.
            (unless (and (pair? d) (eq? (car d) 'hello)) (raise 'auth))
            (when (= (length d) 4) (raise (list 'bad-version #f protocol-version)))
            (let ((theirs (slot d 4)))
              (unless (equal? theirs protocol-version)
                (raise (list 'bad-version theirs protocol-version))))
            ;; The field grammars are applied here, after the version
            ;; comparison and for the reason above: they are THIS
            ;; version's wire syntax. A name arrives as a string in v4,
            ;; so the charset check is on the string and the symbol is
            ;; minted only once the string has passed -- interning
            ;; whatever a stranger sent, and then inspecting it, would
            ;; grow this process's symbol table at an attacker's request.
            ;;
            ;; THE GENERATION IS RANGE-CHECKED, AND THE REFUSAL IS A
            ;; PROTOCOL REFUSAL. Exhausting the domain locally is a
            ;; fail-stop, because there is no next value to send; a
            ;; number arriving from outside the domain is one bad frame
            ;; and earns one closed connection. Reading the second as the
            ;; first would let any peer end this node by sending a large
            ;; integer, so the two live in different places on purpose.
            (unless (and (canonical? d dtext)
                         (= (length d) 7)
                         (wire-name-string? (cadr d))
                         (not (string=? (cadr d) (symbol->string self-name)))
                         (hex-nonce? (cadddr d))
                         (hex16? (list-ref d 5))
                         (let ((g (list-ref d 6)))
                           (and (integer? g) (exact? g)
                                (>= g 0) (< g dial-gen-limit)))
                         (proof=? (caddr d)
                                  (proof-d nonce (cadr d) (list-ref d 5)
                                           (list-ref d 6)
                                           (symbol->string self-name)
                                           self-boot-id)))
              (raise 'auth))
            (let ((peer (string->symbol (cadr d))) (nonce-b (cadddr d)))
              ;; RELEASED HERE, BEFORE THE INSTALL DECISION, and that is
              ;; deliberate: the slot covers the HANDSHAKE, and the
              ;; handshake is over. A connection refused below is still an
              ;; authenticated one; holding a stranger's slot while we
              ;; decide whether it wins would let refusals count against a
              ;; ceiling that exists to bound unauthenticated peers.
              (free!)
              ;; NO PARENT ON THIS SIDE. An acceptor's connection was not
              ;; requested by anything of ours, so there is nobody whose
              ;; death would orphan it -- I0 has nothing to refuse here.
              ;; (The dial side does have one: its attempt runs in its own
              ;; process and passes the connector as parent.) Said rather
              ;; than left to be read off a #f, because a rule that never
              ;; fires looks exactly like a rule that is working.
              ;;
              ;; THE WELCOME COMES AFTER THE DECISION, NOT BEFORE IT.
              ;; Writing it first was harmless while the only refusal was
              ;; the tie-break: that comparison is symmetric, both ends
              ;; compute the same winner, and the loser knows it lost. A
              ;; generation comparison is NOT symmetric -- this side
              ;; compares against the generation in ITS table, which the
              ;; dialer cannot know -- so an early welcome tells a peer it
              ;; is connected and then drops it. That peer installs, emits
              ;; a node-up, then reads the close as a node-down: one pair
              ;; of events for a connection that was never accepted. The
              ;; rule says refuse, close, and notify nothing, and the last
              ;; of those three is only half true if the far end has
              ;; already been welcomed.
              ;;
              ;; Installing before writing is safe in the other direction
              ;; too: a replacement closes the OLD connection, never this
              ;; one, so the welcome still goes out on a connection that
              ;; is open. If the write fails, the entry we just published
              ;; has to go with it -- remove-peer! is guarded on this
              ;; connection's identity, so it removes ours and nobody
              ;; else's.
              (if (installed? (install-peer! peer c peer (list-ref d 5)
                                             (list-ref d 6) #f))
                  (if (write-frame! c
                        (list 'welcome (symbol->string self-name)
                              (proof-a nonce-b (symbol->string self-name)
                                       self-boot-id)))
                      (run-link c peer buf)
                      (remove-peer! peer c))
                  (tcp-close! c))))))))         ; lost the tie-break

  ;; ---- dial side --------------------------------------------------------------

  (define (bad-version? e)
    (and (pair? e) (eq? (car e) 'bad-version)))

  ;; THE DIAL SIDE HAS TO SPEAK. Its peer is one an operator configured, so
  ;; the trade-off that keeps the acceptor silent is reversed: nothing here
  ;; was reached at a stranger's invitation. And the failure is one that
  ;; has no voice of its own -- connector retries forever, so a version
  ;; mismatch presents as a link that simply never comes up, with nothing
  ;; in any log saying why. That is the shape a maintainer cannot debug:
  ;; not an error, an absence.
  ;;
  ;; It prints on EVERY attempt rather than once. That is noisy, and the
  ;; noise is the point: it stops when someone upgrades a node, which is
  ;; exactly the action being asked for. The backoff bounds how noisy --
  ;; attempts thin out to one a minute (reconnect-delay), which is quiet
  ;; enough to live with and frequent enough to be found.
  ;; THE PORT IS FETCHED AT PRINT TIME, not captured when this library is
  ;; loaded. current-error-port is a parameter: a caller that rebinds it --
  ;; to collect diagnostics, to route them into a log -- must see this line
  ;; go where it points now. Caching it at load time would send every one
  ;; of these to whatever the port happened to be at import.
  (define (report-version-mismatch! peer e)
    (let ((p (current-error-port)))
      (fprintf p
        "igropyr node: cannot dial ~a -- protocol version mismatch (peer ~a, this node ~a). Upgrade the older node; the versions must match.\n"
        peer (claimed-version-text (cadr e)) (caddr e))
      (flush-output-port p)))

  ;; One connect attempt; returns when the link is gone. Raises only 'stop.
  ;; -> how many milliseconds the AUTHENTICATED link lasted, or #f if the
  ;; handshake never completed.
  ;;
  ;; A DURATION AND NOT A BOOLEAN, because the backoff resets on this and
  ;; `it connected' is not the property worth resetting on. Two failures
  ;; hide behind a successful handshake. One is the socket: a connection
  ;; that is accepted and then fails its handshake -- wrong secret, wrong
  ;; version -- must keep backing off, and looks most like success from
  ;; the socket's side; measuring authentication rather than connection
  ;; covers that. The other is the link: a peer that completes the
  ;; handshake and drops immediately, over and over, would reset the count
  ;; every round and pin this node at the shortest retry interval
  ;; forever -- the exact peer the backoff exists for, defeating it by
  ;; succeeding at the one thing that was being measured. Authentication
  ;; proves identity; it says nothing about whether the link stayed up.
  ;;
  ;; THE CLOCK STARTS AT install-peer! AND STOPS WHEN THE LINK STOPS, and
  ;; both ends of it are chosen against the same attack. A handshake may
  ;; legitimately take up to handshake-timeout-ms, so timing from the dial
  ;; would let a peer that stalls its handshake and then drops report a
  ;; lifetime longer than one retry interval without the link ever having
  ;; carried anything; and the teardown after the link ends is unbounded
  ;; work (see run-link), so timing to the end of THAT would hand the same
  ;; free lifetime to the same peer on any node whose tables have grown.
  ;; What is measured is the life of the authenticated link and nothing
  ;; on either side of it.
  ;;
  ;; Losing the duplicate-connection tie-break reports ~0: no link ran on
  ;; this connection. That charges the dial as a failure even though the
  ;; peer is up on the surviving connection -- an inflated count that is
  ;; then never used while that link lives (connector skips dialing), and
  ;; costs one extra backoff step whenever it eventually drops. Same
  ;; trade-off, and same reasoning, as leaving the count alone on a
  ;; skipped dial.
  ;;
  ;; WHAT RESTS ON THIS VALUE, and cannot be seen from here: when an
  ;; INBOUND link drops, this node redials promptly rather than after
  ;; whatever interval its own outbound failures had grown to -- because
  ;; the OTHER side is not in a long backoff in that situation. An inbound
  ;; link exists only because some dial of theirs authenticated, and a
  ;; dial whose link then lasted a base interval is exactly what puts that
  ;; side's count back to zero. (A link that died faster leaves both ends
  ;; backing off, which is the intended answer to a peer that flaps.) That
  ;; argument is what makes it safe for connector to leave its own count
  ;; alone when it skips a dial, and it holds only while this value
  ;; measures the life of the AUTHENTICATED link.
  ;;
  ;; So do not narrow it back. Returning a boolean again lets a peer that
  ;; handshakes and drops reset the count every round; timing from the
  ;; dial instead of from install-peer! lets a stalled handshake buy the
  ;; same thing. NOTHING WOULD GO RED for either change: this value moves
  ;; a delay and never a connection, so every test still passes while the
  ;; guarantee above is gone.
  (define (dial! peer host port parent)
    (define dial-gen #f)
    (guard (e ((eq? e 'stop) (raise 'stop))
              ((eq? e dial-gen-exhausted) (raise e))   ; not a retryable failure
              (#t #f))                          ; any failure: retry later
      ;; AUTHORISED FIRST, AND THE CONNECT IS PART OF THE AUTHORISATION.
      ;; The generation is not minted here any more -- it is read out of
      ;; the row the registrar published, so every retry under one
      ;; permission carries the same number and a fresh permission
      ;; carries a new one.
      (let ((gen (authorised-connect! peer host port parent)))
        (unless gen (raise 'unauthorised))
        (set! dial-gen gen))
      (receive (after handshake-timeout-ms (raise 'timeout))
        (`#(tcp-connected ,c)
          (guard (e ((eq? e 'stop) (tcp-close! c) (raise 'stop))
                    ((eq? e dial-gen-exhausted) (tcp-close! c) (raise e))
                    ;; CLOSE FIRST, THEN SPEAK. The outer guard turns every
                    ;; failure into (void) so the connector can retry, so
                    ;; this line has to be said on the way past -- but if
                    ;; the report raises (an error port that is closed, or
                    ;; one a caller installed that refuses writes) then in
                    ;; the other order the close never runs, and every
                    ;; retry leaks a connection. Ordering is the fix rather
                    ;; than wrapping the report in a guard of its own: a
                    ;; guard is another thing that has to be written
                    ;; correctly, while an ordering cannot be half right.
                    ;; This bounds ONE failure mode -- the connection is
                    ;; closed whatever the report then does. A port that
                    ;; blocks still blocks the only scheduler, after the
                    ;; close; that is not fixed here, and not claimed to be.
                    ((bad-version? e) (tcp-close! c)
                                      (report-version-mismatch! peer e)
                                      #f)
                    (#t (tcp-close! c) #f))
            (tcp-read-start! c)
            (let* ((buf (make-inbuf))
                   (dpair (call-with-values
                            (lambda () (read-frame c buf handshake-timeout-ms
                                                   handshake-max-frame))
                            list))
                   (d (car dpair)) (dtext (cadr dpair)))
              ;; same order as the acceptor: tag, version, then shape
              ;; THE NONCE GRAMMAR IS THIS VERSION'S, SO IT IS APPLIED ONLY
              ;; AFTER THE VERSION MATCHES. Tag, then the pre-versioning
              ;; arity, then the stated version, and only then anything that
              ;; v3 in particular requires of the fields. A v4 that mints
              ;; base64 nonces, or carries an extra element, has to be
              ;; answered "your version differs" rather than refused for
              ;; breaking a rule that was never its rule -- hoisting a
              ;; field-grammar check above the version comparison would
              ;; misclassify exactly the peers this ordering exists for.
              ;;
              ;; A consequence to state rather than leave to be discovered:
              ;; a frame that is malformed AND mismatched is reported as
              ;; mismatched. (challenge "x" 999) answers 999, not "bad
              ;; nonce". That is the policy, not an oversight.
              (unless (and (pair? d) (eq? (car d) 'challenge)) (raise 'auth))
              (when (= (length d) 2)
                (raise (list 'bad-version #f protocol-version)))
              (let ((theirs (slot d 2)))
                (unless (equal? theirs protocol-version)
                  (raise (list 'bad-version theirs protocol-version))))
              ;; CHECKED BEFORE THE PROOF IS COMPUTED. What must not happen
              ;; is SENDING a proof over an attacker-shaped nonce: a digest
              ;; computed and then discarded is harmless, and it is
              ;; transmission, not computation, that hands over a usable
              ;; token. Checking first, rather than merely checking before
              ;; the write, is the cheaper and the more obviously correct
              ;; arrangement -- there is then no window in which such a
              ;; token exists in this process at all, and no later edit can
              ;; move a write above the check by accident.
              (unless (and (canonical? d dtext)
                           (= (length d) 4) (hex-nonce? (cadr d))
                           (hex16? (cadddr d)))
                (raise 'auth))
              ;; The generation is taken here, at the dial, and that is
              ;; the staged spelling: see dial-gens. Nothing on this side
              ;; reads it back yet.
              (let ((nonce-b (random-hex 16))
                    (bootid-a (cadddr d))
                    (gen dial-gen))
                (write-frame! c
                  (list 'hello (symbol->string self-name)
                        (proof-d (cadr d) (symbol->string self-name)
                                 self-boot-id gen
                                 (symbol->string peer) bootid-a)
                        nonce-b protocol-version self-boot-id gen))
                (let-values (((d2 d2text) (read-frame c buf handshake-timeout-ms
                                                      handshake-max-frame)))
                  ;; welcome keeps its three-element shape: by now both
                  ;; ends have stated and agreed a version, so there is
                  ;; nothing left to state. Its proof still moves with
                  ;; the formula, so a peer that agreed to the version in
                  ;; words but computed the proof without it is refused
                  ;; here -- the binding is checked in both directions.
                  ;;
                  ;; THE NAME IS COMPARED AGAINST THE ONE WE DIALLED, not
                  ;; merely parsed: that comparison is one of the three
                  ;; facts carrying the acceptor's identity, the other
                  ;; two being the HMAC over its name and boot id, and
                  ;; the freshness of nonce-b. proof-A binds no dialer
                  ;; field, so removing this comparison would remove a
                  ;; load-bearing check and leave a digest that any
                  ;; acceptor sharing the secret could have produced.
                  (unless (and (pair? d2) (eq? (car d2) 'welcome)
                               (canonical? d2 d2text)
                               (= (length d2) 3)
                               (string? (cadr d2))
                               (string=? (cadr d2) (symbol->string peer))
                               (proof=? (caddr d2)
                                        (proof-a nonce-b (symbol->string peer)
                                                 bootid-a)))
                    (raise 'auth))
                  (if (installed?
                        (install-peer! peer c self-name bootid-a gen parent))
                      (let ((up (now-ms)))
                        (- (run-link c peer buf) up))
                      (begin (tcp-close! c) 0)))))))
        (`#(tcp-connect-failed ,e) #f)
        (`#(node-stop) (raise 'stop)))))

  ;; ---- reconnect backoff ------------------------------------------------

  ;; How long to wait before the next dial to `peer`, after `attempt`
  ;; consecutive failed attempts: exponential from reconnect-base-ms to
  ;; reconnect-max-ms, plus or minus a quarter.
  ;;
  ;; EXPORTED, AND PURE, BECAUSE PHASE IS NOT OTHERWISE OBSERVABLE. What
  ;; the jitter exists to prevent is a herd -- every node that lost the
  ;; same peer redialing in lockstep, forever, because they all started
  ;; their clocks at the same instant -- and a herd is a property of the
  ;; SET of delays, which nothing inside a single node can see. Anything
  ;; asserting that the set spreads has to be able to compute members of
  ;; it. (The same argument as node-monitor-stats: a mechanism whose
  ;; failure has no reader is one nobody will notice failing.)
  ;;
  ;; THE OFFSET IS DERIVED, NOT DRAWN, and random-hex must not be used
  ;; here. It reads /dev/urandom and raises 'entropy on a short read, and
  ;; the connector's guard turns any raise into a return -- which ends the
  ;; connector process. That peer would then never be dialed again, with
  ;; nothing said anywhere. A backoff that can silently disable
  ;; reconnection is worse than no jitter at all. Deriving it also makes
  ;; the phase reproducible, which is what lets a spread be asserted
  ;; rather than sampled.
  ;;
  ;; The three fields are concatenated to be hashed, and that
  ;; concatenation deliberately need NOT be injective. A collision costs
  ;; two peers the same phase offset, which is the no-jitter case: the
  ;; ordinary situation, not a failure. Nothing here is an identity, a
  ;; key, or a proof -- the injectivity rule that governs the handshake
  ;; encoding is about a different kind of string.
  (define (reconnect-delay self peer attempt)
    (unless (symbol? self)
      (assertion-violation 'reconnect-delay "self must be a symbol" self))
    (unless (symbol? peer)
      (assertion-violation 'reconnect-delay "peer must be a symbol" peer))
    (unless (and (integer? attempt) (exact? attempt) (>= attempt 0))
      (assertion-violation 'reconnect-delay
        "attempt must be a non-negative exact integer" attempt))
    (let ((base
            ;; min(base * 2^attempt, max) by doubling rather than by
            ;; (expt 2 attempt): attempt is unbounded -- a peer can be
            ;; down for a week -- and the closed form would build a
            ;; bignum of that many bits before min discarded it.
            (let loop ((b reconnect-base-ms) (k attempt))
              (cond ((>= b reconnect-max-ms) reconnect-max-ms)
                    ((= k 0) b)
                    (else (loop (* b 2) (- k 1)))))))
      ;; +/- 25%, in exact arithmetic: the offset is in ten-thousandths so
      ;; that the truncation below can still land on every millisecond in
      ;; the window. Coarser units quantise the delays into a few buckets,
      ;; and a spread that only takes a few values is most of a herd.
      (let ((offset (- (modulo (jitter-hash self peer attempt) 5001) 2500)))
        (+ base (quotient (* base offset) 10000)))))

  ;; FNV-1a over the three fields. Written out rather than taken from
  ;; string-hash because the value has to be the same in every process
  ;; that computes it and across host Scheme versions: a peer's phase is
  ;; only worth having if it is that peer's phase everywhere. It is a
  ;; spread, not a digest -- it resists no adversary and does not need to,
  ;; since the most a chosen node name buys is a colliding phase.
  (define (jitter-hash self peer attempt)
    (let ((bv (string->utf8
                (string-append (symbol->string self) ":"
                               (symbol->string peer) ":"
                               (number->string attempt)))))
      (let loop ((i 0) (h 2166136261))
        (if (fx= i (bytevector-length bv))
            h
            (loop (fx+ i 1)
                  (bitwise-and
                    (* (bitwise-xor h (bytevector-u8-ref bv i)) 16777619)
                    #xffffffff))))))

  ;; the reconnect supervisor for one peer; lives until node-disconnect!
  ;;
  ;; `attempt` counts DIALS THAT DID NOT PRODUCE A LINK WORTH HAVING. It
  ;; resets when a dial produced an authenticated link that then outlived
  ;; THE DELAY THIS NODE WAS ABOUT TO WAIT, so a link that comes up,
  ;; works, and later drops is redialed promptly rather than at whatever
  ;; interval the last outage had grown to -- while a link that dies
  ;; faster than the retry it replaced counts as the failure it is.
  ;;
  ;; THE BAR IS THE INTERVAL THE PREVIOUS ROUND WAS SET TO WAIT, carried
  ;; forward as `waited`.
  ;;
  ;; IT IS A NOMINAL INTERVAL AND NOT A MEASUREMENT, and it is off in
  ;; BOTH directions:
  ;;   - too harsh, by at most one nominal interval: an inbound link that
  ;;     survives most of the interval and drops near its end leaves the
  ;;     dial replacing very little downtime, while the bar is still the
  ;;     whole of it;
  ;;   - too lax, WITHOUT BOUND: the deadline stops a straggler from
  ;;     restarting the wait, but nothing bounds how long after it this
  ;;     process is next scheduled. Stalled ten minutes past a nominal
  ;;     six seconds, the next link clears the bar by living six.
  ;; The lax direction is the one with no ceiling, and it is not bounded
  ;; by anything the backoff is built out of.
  ;;
  ;; The bar rises with the backoff: each failure lengthens the next wait,
  ;; and that wait is what the peer must then outlast to earn a short
  ;; interval back. At the ceiling that is most of a minute, which is what
  ;; a working peer does anyway, and it needs no constant of its own.
  ;;
  ;; WHAT THIS DOES NOT DO, so nobody reads more into it: a peer that
  ;; stays up a little longer than the bar, every time, holds this node at
  ;; the shortest interval. Every threshold has that shape -- T is beaten
  ;; by T plus epsilon, and a multiple of T only moves T. What changed is
  ;; the price: such a peer must hold an authenticated link for as long as
  ;; the interval it is dodging, roughly half the time, completing the
  ;; handshake every round. That is not the dead peer a backoff exists to
  ;; stop hammering. A ceiling on dials per unit time would be the
  ;; mechanism for that, and this is not it.
  ;;
  ;; A dial that was SKIPPED because an inbound link is already up leaves
  ;; the count alone: nothing was attempted, so there is nothing to count
  ;; in either direction.
  ;; THE BACKOFF IS A DEADLINE, NOT A TIMEOUT ARGUMENT, because messages
  ;; arrive during it that must not shorten it. A dial that gave up at
  ;; handshake-timeout-ms leaves its connect request outstanding, and the
  ;; OS completes it whenever it completes -- delivering tcp-connected or
  ;; tcp-connect-failed to this mailbox seconds later. Handling those by
  ;; re-entering the loop restarts the whole cycle, and the top of the
  ;; cycle DIALS: a peer whose connects consistently complete just after
  ;; the handshake deadline would then be redialed at roughly that
  ;; interval forever, with attempt climbing and its delay never once
  ;; being waited out. The backoff would be inert, and nothing about a
  ;; growing counter that is never used shows up as a failure. Draining
  ;; against a fixed deadline keeps the wait the wait.
  ;; ---- one process per attempt (C16) ---------------------------------
  ;;
  ;; THE PROCESS THAT CALLS tcp-connect! IS THE CONNECTION'S OWNER FROM
  ;; THE FIRST INSTANT, and it is a fresh process for every attempt.
  ;; Both halves carry weight.
  ;;
  ;; Owner from the start means there is no window in which a connection
  ;; exists and belongs to nobody, and no conn-set-owner! call on this
  ;; path to get the transfer wrong -- the property is enforced by
  ;; construction rather than by a later assignment that could be
  ;; reordered or skipped. (The accept path still assigns an owner: there
  ;; the socket is handed to us by libuv, so there is no call of ours to
  ;; move earlier.)
  ;;
  ;; A fresh process per attempt means an attempt's identity is not
  ;; reusable. A late message from an abandoned attempt -- a connect that
  ;; completes after we gave up on it, a handshake frame that arrives
  ;; after a newer attempt won -- lands in a mailbox nobody is reading,
  ;; instead of in the mailbox of the attempt that replaced it. Attributing
  ;; a stale event to a live attempt is the whole class this removes.
  ;;
  ;; The connector stays the PARENT and stays alive across attempts,
  ;; which is what gives install-peer!'s I0 something real to test: an
  ;; attempt whose connector has been killed is an orphan, and the
  ;; install it is about to request has nobody left to own it.
  ;;
  ;; -> the same value dial! returned: how long the authenticated link
  ;; lasted, or #f. The connector's backoff is unchanged by this
  ;; restructuring, which is deliberate -- the reconnect accounting
  ;; argument above depends on that number meaning the life of the
  ;; AUTHENTICATED link, and moving where the code runs must not quietly
  ;; move where the clock starts.
  ;; ---- the registrar --------------------------------------------------
  ;;
  ;; ITS MAILBOX IS THE TOTAL ORDER. Everything that changes who may dial
  ;; a peer -- a new attempt asking permission, an endpoint change, a
  ;; disconnect -- arrives here as a message, so those changes are
  ;; sequenced against each other by construction rather than by each
  ;; caller remembering to take the same lock.
  ;;
  ;; It issues and revokes; it never consumes. Consumption happens in the
  ;; attempt's own atomic region, on the one row addressed to that
  ;; attempt. See peers-auth for why the two cannot be swapped.
  (define registrar #f)

  (define (registrar-loop)
    (let loop ()
      (receive
        (`#(attempt-register ,peer ,endpoint ,parent ,child)
          ;; ONE LIVE AUTHORISATION PER PEER. An existing row whose child
          ;; is still alive and has not consumed it means another attempt
          ;; is already holding permission; a second one would dial the
          ;; same name in parallel, and both would reach the far end.
          (let* ((cur (atomically (hashtable-ref peers-auth peer #f)))
                 (held (and cur
                            (not (auth-consumed? cur))
                            (process-alive? (auth-child cur))
                            (not (eq? (auth-child cur) child)))))
            (if held
                (when (process-alive? child) (send child (vector 'no-go)))
                (begin
                  ;; The generation belongs to the EPOCH, not to this
                  ;; attempt: a retry under the same authorisation reads
                  ;; the same number back.
                  (atomically
                    (hashtable-set! peers-auth peer
                      (vector endpoint parent child (peer-gen peer) #f)))
                  (when (process-alive? child) (send child (vector 'go))))))
          (loop))
        ;; A revocation ends the epoch: the next authorisation for this
        ;; peer gets a NEW generation, which is what makes "a fresh
        ;; permission outranks the one it replaced" true.
        (`#(auth-revoke ,peer)
          (atomically (hashtable-delete! peers-auth peer))
          (next-dial-gen! peer)
          (loop))
        (`#(disconnect ,peer)
          (let ((p (atomically
                     (let ((e (hashtable-ref connectors peer #f)))
                       (hashtable-delete! connectors peer)
                       (and e (vector-ref e 0))))))
            (when (and p (process-alive? p)) (send p (vector 'node-stop))))
          (atomically (hashtable-delete! peers-auth peer))
          (next-dial-gen! peer)
          (let ((e (peer-entry peer)))
            (when e (send (entry-link e) (vector 'node-stop))))
          (loop))
        ;; The endpoint change, in the order the design calls (0)-(4).
        ;; The steps are numbered there and named here so the two can be
        ;; read against each other.
        (`#(set-endpoint ,peer ,host ,port)
          (let* ((cur (atomically (hashtable-ref connectors peer #f)))
                 (same? (and cur (process-alive? (vector-ref cur 0))
                             (string=? (vector-ref cur 1) host)
                             (equal? (vector-ref cur 2) port))))
            (if same?
                ;; The base case, and it has to stay one: asking for the
                ;; endpoint that is already being dialled must not tear
                ;; down a working link to rebuild the same thing.
                (void)
                (let* ((old-conn (atomically   ; (0) take, then forget
                                   (let ((e (hashtable-ref connectors peer #f)))
                                     (hashtable-delete! connectors peer)
                                     (and e (vector-ref e 0)))))
                       (ent (peer-entry peer))
                       ;; (2) HAS A BRANCH. A child holding a connection
                       ;; THIS node dialled is dialling the old endpoint
                       ;; and must go. A child holding a connection the
                       ;; PEER dialled to us is not ours to end: the
                       ;; endpoint being changed is the one we dial, and
                       ;; the inbound link is unaffected by it. Killing it
                       ;; would drop a working link to change an address
                       ;; nobody was using for it.
                       (outbound? (and ent (eq? (entry-dialer ent) self-name))))
                  ;; (1) the old connector, by the pid taken in (0) --
                  ;; never from a parent's private state, which is what
                  ;; made this unimplementable when the pid lived there.
                  (when (and old-conn (process-alive? old-conn))
                    (kill old-conn 'endpoint-changed))
                  ;; (3) the teardown consequences, reached the same way
                  ;; an ordinary death reaches them: stop-link! closes
                  ;; first and then wakes, and the link's own exit path
                  ;; runs remove-peer!, which is the one place those five
                  ;; consequences live. Reimplementing them here would be
                  ;; a second copy that drifts.
                  (when outbound?
                    (stop-link! (entry-conn ent) (entry-link ent)
                                'endpoint-changed))
                  ;; the old permission ends with the old endpoint, so the
                  ;; next one carries a new generation
                  (atomically (hashtable-delete! peers-auth peer))
                  (next-dial-gen! peer)
                  ;; (4) publish the new mapping and the connector that
                  ;; serves it in one region, so nothing can observe a
                  ;; mapping with no connector or the reverse.
                  (atomically
                    (hashtable-set! connectors peer
                      (vector (spawn (lambda () (connector peer host port)))
                              host port))))))
          (loop))
        (`#(node-stop) (void)))))

  ;; -> the generation this attempt is authorised under, or #f. The
  ;; connect is submitted INSIDE the region that consumes the row: an
  ;; authorisation checked and then acted on afterwards is an
  ;; authorisation that could have been revoked in between, and the
  ;; revocation exists precisely because somebody decided this dial must
  ;; not happen.
  (define (authorised-connect! peer host port parent)
    (send registrar (vector 'attempt-register peer (cons host port) parent self))
    (receive (after handshake-timeout-ms #f)
      (`#(no-go) #f)
      (`#(go)
        (atomically
          (let ((r (hashtable-ref peers-auth peer #f)))
            (and r
                 (eq? (auth-child r) self)
                 (not (auth-consumed? r))
                 (equal? (auth-endpoint r) (cons host port))
                 (or (not (auth-parent r)) (process-alive? (auth-parent r)))
                 ;; the compare half of the compare-and-swap: still the
                 ;; same row we just read, not a replacement published
                 ;; between the read and here
                 (eq? (hashtable-ref peers-auth peer #f) r)
                 (let ((gen (auth-gen r)))
                   (hashtable-set! peers-auth peer
                     (vector (auth-endpoint r) (auth-parent r) (auth-child r)
                             gen #t))
                   (tcp-connect! host port self)
                   gen)))))))

  (define (attempt! peer host port)
    (let* ((parent self)
           (ref (gensym))
           (child (spawn (lambda ()
                           ;; THE EXHAUSTION TOKEN CROSSES THE PROCESS
                           ;; BOUNDARY. dial! is careful to let it past
                           ;; three catch-alls whose policy is "retry
                           ;; later", and putting the call inside a
                           ;; process adds a fourth. A plain (#t #f) here
                           ;; would swallow it again and restore exactly
                           ;; the silent forever-retry that token exists
                           ;; to end -- so it is reported to the parent
                           ;; and re-raised there, where the connector's
                           ;; guard can stop instead of loop.
                           (let ((outcome
                                   (guard (e ((eq? e dial-gen-exhausted)
                                              (cons 'fatal e))
                                             ((eq? e 'stop) (cons 'up #f))
                                             (#t (cons 'up #f)))
                                     (cons 'up (dial! peer host port parent)))))
                             (when (process-alive? parent)
                               (send parent (vector ref (car outcome)
                                                    (cdr outcome))))))))) 
      (receive
        (`#(,@ref up ,up) up)
        (`#(,@ref fatal ,e) (raise e))
        ;; A node-stop reaching the connector while an attempt is in
        ;; flight has to reach the attempt too: it owns the socket, and
        ;; the connector cannot close what it does not hold.
        (`#(node-stop)
          (when (process-alive? child) (send child (vector 'node-stop)))
          (raise 'stop)))))

  (define (connector peer host port)
    (guard (e ((eq? e dial-gen-exhausted) (void))  ; reported already; stop
              (#t (void)))                      ; 'stop lands here too
      ;; The first round waited nothing -- the connector dials as soon as
      ;; it starts -- so there is no interval behind it to carry forward.
      ;; The bar is instead the delay THIS PAIR would wait at attempt 0:
      ;; a floor rather than a replaced interval, and deliberately the
      ;; jittered value reconnect-delay gives for attempt 0, not the
      ;; un-jittered constant it is drawn from. Those two differ by up to
      ;; a quarter in EITHER direction, so seeding with the constant
      ;; misjudges the first link both ways -- one that outlasted this
      ;; pair's real shortest delay recorded as a failure, or one that
      ;; never reached it recorded as a success.
      ;;
      ;; Seeding it at zero, which is what this was, is worse than either:
      ;; any authenticated link clears a bar of nothing, including a
      ;; tie-break loser that never ran.
      (let loop ((attempt 0) (waited (reconnect-delay self-name peer 0)))
        (let* ((next (if (live-entry peer)      ; a surviving inbound counts
                         attempt
                         (let ((up (attempt! peer host port)))
                           (if (and up (>= up waited)) 0 (+ attempt 1)))))
               (delay (reconnect-delay self-name peer next))
               (deadline (+ (now-ms) delay)))
          (let wait ()
            (let ((remaining (- deadline (now-ms))))
              (if (<= remaining 0)
                  (loop next delay)
                  (receive (after remaining (loop next delay))
                    (`#(node-stop) (void))
                    ;; stragglers from a timed-out dial: release and go on
                    ;; waiting out the rest of this interval
                    (`#(tcp-connected ,c) (tcp-close! c) (wait))
                    (`#(tcp-connect-failed ,e2) (wait))
                    ;; A backpressure close aimed at a link process which,
                    ;; on this side, IS this process -- and which reaches
                    ;; here only when that link had already ended. The
                    ;; clause exists so the message cannot sit in this
                    ;; long-lived mailbox forever, which is what a
                    ;; selective receive without it would do: one stranded
                    ;; message per occurrence, never read, never collected.
                    (`#(link-stop ,which ,why) (wait))))))))))

  ;; ---- public API ---------------------------------------------------------------

  ;; Set this node's identity and shared secret; with a port, also
  ;; accept peers -- on 127.0.0.1 unless a host is given (the dist port
  ;; must never face the public internet).
  (define (node-start! name secret . rest)
    (unless (and (symbol? name) (string? secret))
      (assertion-violation 'node-start! "want (name-symbol secret-string)" name))
    ;; A NAME CANNOT CONTAIN `~`, and the refusal belongs here rather
    ;; than wherever the damage shows up. Conversation ids are minted as
    ;; "<node>~<body>" and parsed by splitting at the first tilde, so a
    ;; node called a~b mints ids that parse as owned by `a`: every resume
    ;; is forwarded off the very node holding the conversation, and comes
    ;; back 'unreachable while the conversation sits parked in the
    ;; process doing the asking. Nothing about that failure points here,
    ;; and it appears hours later at the first resume rather than at the
    ;; call that caused it.
    ;; `:` IS THE SAME RULE ON A DIFFERENT SEPARATOR, and it was missing
    ;; until a colon in a name turned out to break the handshake proof's
    ;; encoding. NOTE WHAT THIS DOES NOT DO: the name an attacker CLAIMS
    ;; arrives in a hello frame and never passes through here, so this is
    ;; depth, not the repair. The repair is hex-nonce?, which fixes the
    ;; field that actually has to be separator-free.
    ;; THE TILDE CHECK RUNS FIRST, and the order is the message. Since
    ;; v4 the wire alphabet excludes `~` too, so the generic complaint
    ;; would refuse a~b for the right reason with the wrong words -- and
    ;; the words are what sends the reader to the conversation-id rule
    ;; rather than to a character table. A refusal that names the wrong
    ;; rule is a diagnostic regression even when the verdict is correct.
    (when (let loop ((i 0))
            (cond ((= i (string-length (symbol->string name))) #f)
                  ((char=? (string-ref (symbol->string name) i) #\~) #t)
                  (else (loop (+ i 1)))))
      (assertion-violation 'node-start!
        (string-append
          "`~` separates the node name from the id body; a name"
          " containing it mis-routes every clustered id this node mints")
        name))
    (let ((why (wire-name-complaint name)))
      (when why (assertion-violation 'node-start! why name)))
    ;; A short secret makes the HMAC handshake brute-forceable; an empty
    ;; one disables auth entirely. Refuse both. (The length is reported,
    ;; never the secret itself.)
    (when (< (string-length secret) 8)
      (assertion-violation 'node-start!
        "secret must be at least 8 characters" (string-length secret)))
    (when self-name
      (assertion-violation 'node-start! "node already started" self-name))
    (set! self-name name)
    (set! self-secret (string->utf8 secret))
    ;; ONCE PER BOOT, HERE, AND NOWHERE ELSE. Minting it per connection
    ;; would not merely weaken the identity it carries -- the acceptor
    ;; states this value in the challenge and hashes the same value into
    ;; the proof it then verifies, so a second spelling would make this
    ;; node fail to authenticate a peer that answered it correctly.
    (set! self-boot-id (random-hex 8))
    ;; The registrar starts with the node, not with the first dial: its
    ;; mailbox is the order in which permission to dial changes, and an
    ;; order that only begins once somebody dials is not one.
    (set! registrar (spawn registrar-loop))
    ;; The warden starts with the node and is marked critical: it is the
    ;; root the reaper's recoverability hangs from, so its own death is
    ;; not something to survive quietly.
    (set! reaper-warden
      (spawn (lambda ()
               (warden-loop
                 (list (vector 'reaper reaper-loop
                               "hosted-monitor credit is no longer being returned")
                       (vector 'dispatcher dispatcher-loop
                               "topology notifications are no longer being delivered"))))))
    (critical! reaper-warden 'node-warden)
    (when (pair? rest)
      (let ((port (car rest))
            (host (if (pair? (cdr rest)) (cadr rest) "127.0.0.1")))
        (tcp-listen! host port 128
          (lambda (c)
            ;; libuv callback context: spawn + own + read-start only,
            ;; or -- over the pre-auth ceiling -- close and do none of it
            (let ((pid (lease-admit! 'preauth max-preauth-conns
                         (lambda (s) (acceptor c s)))))
              (if pid
                  (begin (conn-set-owner! c pid) (tcp-read-start! c))
                  (tcp-close! c)))))))
    name)

  ;; Dial a peer (and keep dialing whenever the link is down).
  ;;
  ;; RETURNS ON ACCEPTANCE, NOT ON EFFECT -- see the note at the top of
  ;; this file. The work is done by the registrar, in its order.
  (define (node-connect! peer host port)
    (unless self-name
      (assertion-violation 'node-connect! "call node-start! first" peer))
    ;; A PEER NAME IS A SYMBOL, and it is worth refusing here rather than
    ;; where the damage appears: this value becomes a hashtable key, is the
    ;; name the welcome proof is verified against, and is printed in
    ;; diagnostics. (It does not itself go on the wire -- hello carries
    ;; self-name -- so what is at stake here is the colon half of
    ;; wire-name?, not the writability half.) The
    ;; same argument already refuses a bad name at node-start!; this is the
    ;; other end of the same rule, and it was missing.
    ;; The same rule from the other end, and the same complaint: this
    ;; name is what the welcome proof is verified against and what the
    ;; dialer's proof binds as its target, so a peer this node cannot
    ;; name is a peer it can never accept.
    (let ((why (wire-name-complaint peer)))
      (when why (assertion-violation 'node-connect! why peer)))
    (when (eq? peer self-name)
      (assertion-violation 'node-connect! "cannot connect to self" peer))
    ;; Keyed by NAME, but the endpoint has to be part of the decision. A
    ;; node that moves to a new address keeps its name -- that is what a
    ;; rolling migration looks like -- and a connector keyed on name alone
    ;; was considered "already dialing" forever, so it went on retrying the
    ;; old host after the new one had been published. The link never came
    ;; back, and nothing said why.
    ;; THE CHANGE GOES THROUGH THE REGISTRAR, and that is the whole point
    ;; of it having a mailbox. Two endpoint changes racing here used to be
    ;; able to interleave -- A kills the old connector and has not spawned
    ;; yet, B sees none and spawns its own, A resumes and spawns over it
    ;; -- and the endpoint that survived was not necessarily the one asked
    ;; for last. A mailbox is a total order for free.
    (unless registrar
      (assertion-violation 'node-connect! "call node-start! first" peer))
    (send registrar (vector 'set-endpoint peer host port))
    (void))

  ;; Stop dialing and drop the live link, if any.
  ;;
  ;; THROUGH THE REGISTRAR, for the same reason node-connect! is: this
  ;; changes who may dial the peer, and every such change has to be in
  ;; one order with the others. Writing the connector table here as well
  ;; would give it a second writer, and a second writer is exactly the
  ;; interleaving the mailbox exists to rule out -- a disconnect landing
  ;; between an endpoint change's take and its publish would be undone by
  ;; the publish.
  (define (node-disconnect! peer)
    (when registrar (send registrar (vector 'disconnect peer)))
    (void))

  ;; Tune this node's ceilings, in order: the max serve-rcall processes in
  ;; flight, the max monitors hosted for remote watchers, and -- each
  ;; optional -- the max handshakes in flight from peers that are not
  ;; authenticated yet, the max bytes queued for one connection before it
  ;; is closed, and the longest this node will serve one remote call
  ;; whatever its caller asked for. #f leaves any of them at its current
  ;; value, and so does leaving it off the end. The defaults
  ;; (256 / 4096 / 256 / 16 MiB / 60 s) suit ordinary meshes; raise them
  ;; for a hub node, lower them to bound a node more tightly. Takes effect
  ;; immediately: for new frames, for the next connection accepted, and
  ;; for the next write. A LOWERED OUTBOUND CEILING ALSO BITES ON THE NEXT
  ;; INBOUND FRAME: connections already above the new value are closed by
  ;; the link's own check (see link-loop), not only when something is next
  ;; written to them -- otherwise lowering the ceiling would leave exactly
  ;; the connections it was lowered for running until they happened to be
  ;; written to.
  ;;
  ;; The last two are bytes and milliseconds rather than counts, and they
  ;; get the same check as the counts, because the failure it exists to
  ;; catch is the same one: a value of the wrong shape -- a float, a
  ;; string, a zero -- quietly turning a ceiling into no ceiling.
  (define (node-set-limits! rcall-cap monitor-cap . rest)
    (define (check-cap who cap)
      (unless (and (integer? cap) (exact? cap) (> cap 0))
        (assertion-violation 'node-set-limits!
          (string-append who " cap must be a positive integer") cap)))
    (define (optional who n install!)
      ;; slot answers #f both for an argument that was omitted and for one
      ;; passed as #f, which are the same instruction here: leave it be.
      (let ((v (slot rest n)))
        (when v (check-cap who v) (install! v))))
    (when rcall-cap
      (check-cap "rcall" rcall-cap)
      (set! max-rcall-serving rcall-cap))
    (when monitor-cap
      (check-cap "monitor" monitor-cap)
      (set! max-hosted-monitors monitor-cap))
    (optional "pre-auth connection" 0 (lambda (v) (set! max-preauth-conns v)))
    (optional "outbound queue" 1 (lambda (v) (set! max-outbound-bytes v)))
    (optional "serve timeout" 2 (lambda (v) (set! serve-timeout-cap-ms v)))
    (void))

  ;; Send msg to the process registered as reg-name on node. #t = handed
  ;; to a live link (delivery still unconfirmed, as within a node); #f =
  ;; no link. Own node name = plain local send. Raises if msg contains
  ;; data outside the extended wire whitelist.
  (define (rsend node reg-name msg)
    (cond
      ((eq? node self-name)
       ;; The same contract as a remote send, including on this node. It
       ;; used to skip the check, so a payload outside the wire whitelist
       ;; -- a procedure, a port -- was DELIVERED here and refused
       ;; everywhere else: the same task succeeded or failed depending on
       ;; which node a round-robin happened to pick. A contract that holds
       ;; only when the scheduler cooperates is not a contract, and the
       ;; local case is exactly where such a payload gets written and
       ;; never noticed.
       (wire-check 'rsend msg)
       (let ((p (whereis reg-name)))
         (and p (begin (send p msg) #t))))
      ((live-entry node)
       => (lambda (e)
            ;; THREE OUTCOMES, THREE ANSWERS, AND NO TWO OF THEM SHARE A
            ;; VALUE. That separation is the whole point of this shape:
            ;;   #t     the frame is with libuv. Delivery is still not
            ;;          confirmed -- it never is here -- so a caller must
            ;;          tolerate #t and a lost message, as it always had
            ;;          to.
            ;;   #f     THERE IS NO LINK. Callers depend on exactly this
            ;;          and act on it: one of them takes #f as evidence
            ;;          the node is gone and drops it from its scheduling
            ;;          set. Nothing else may be reported this way.
            ;;   raise  the link is up and THIS frame did not go. Named,
            ;;          carrying the node and the original condition.
            ;;
            ;; The middle one is a theorem, not a convention. Overloading
            ;; #f with "the link is fine, this frame was refused" removed
            ;; a node from a pool over a transient, with no node-down to
            ;; ever undo it; that is what this shape exists to prevent,
            ;; and it is why the third outcome raises instead of joining
            ;; #f.
            ;;
            ;; A serialization failure raises too, out of frame-segments,
            ;; and always did. So a caller that guards this call catches
            ;; both kinds of "it did not go", and neither kind quietly
            ;; reports success.
            (let-values (((ok failure)
                          (write-body! (entry-conn e)
                                       (frame-segments
                                         (list 'send reg-name msg)))))
              (cond (ok #t)
                    (failure (raise (submission-failure node failure)))
                    (else #f)))))
      (else #f)))

  ;; Synchronous cross-node call to the GEN-SERVER registered as
  ;; reg-name on node; returns its reply, blocking the caller (default
  ;; 5s timeout). The own node name is a plain local gen-server-call.
  ;; The timeout is STATED IN THE CALL FRAME, so the callee waits on this
  ;; caller's terms rather than on a fixed default of its own (bounded by
  ;; a ceiling of its own -- see serve-timeout-cap-ms, which also says why
  ;; a stated duration is not the same as a shared deadline). It bounds
  ;; the WAIT and not the work: a remote server that overruns goes on
  ;; running, as a local one does.
  ;; Raises #(rcall-error <reason> <target>) on no link, timeout, a
  ;; remote failure (no such server / it died / a non-serializable
  ;; reply), or 'overload when the target is already serving its maximum
  ;; concurrent rcalls (see node-set-limits!). Both msg and the reply
  ;; must be extended-wire-safe.
  ;; <target> is the registered name, with one exception: 'noconnection
  ;; names the NODE. That reason is a statement about the link, not about
  ;; anything registered on the far side, and it is raised from three
  ;; places -- no link at all, a link that dropped while the call was
  ;; outstanding, and a frame that was never submitted. All three carry
  ;; the node, so the same reason never arrives carrying two different
  ;; kinds of thing.
  (define (rcall node reg-name msg . rest)
    (let ((timeout (if (pair? rest) (car rest) 5000)))
      ;; REFUSED HERE BECAUSE IT GOES ON THE WIRE. The far end drops the
      ;; link on a timeout field it cannot use, which is the right answer
      ;; to a confused peer and a terrible diagnostic for a local typo:
      ;; every other call to that node dies with it. Narrow what is sent
      ;; so the mistake is an error at the call site instead.
      ;;
      ;; A FIXNUM, WHICH IS STRICTLY NARROWER THAN WHAT dispatch! ACCEPTS,
      ;; and the asymmetry is the point rather than an inconsistency: be
      ;; strict in what you send, liberal in what you accept. `positive
      ;; exact integer' is not narrow enough to send, because an integer
      ;; has no size limit and this one is written out in decimal -- a
      ;; timeout of (expt 10 8388608) encodes to a frame past max-frame
      ;; and is dropped by the peer's framer before any timeout logic sees
      ;; it, taking the whole link with it. Bounding it at a fixnum bounds
      ;; the encoding, and costs nothing real: a fixnum of milliseconds is
      ;; already tens of millions of years.
      (unless (and (fixnum? timeout) (fx> timeout 0))
        (assertion-violation 'rcall
          "timeout must be a positive fixnum of milliseconds" timeout))
      (cond
        ((eq? node self-name) (gen-server-call reg-name msg timeout))
        ((live-entry node)
         => (lambda (e)
              ;; SERIALIZED FIRST, PUBLISHED SECOND. The entry has to be
              ;; published before the write, because the write is a safe
              ;; point and the reply can be routed by the link process
              ;; before this one runs again -- it would find nothing. So
              ;; everything that can fail happens first: frame-segments
              ;; refuses an oversized or unwritable payload here, where
              ;; nothing has been published and there is nothing to undo.
              ;; (Undoing afterwards would not be enough anyway -- see
              ;; frame-segments.)
              (let* ((ref (next-rcall-ref!))
                     (segs (frame-segments
                             (list 'call reg-name ref msg timeout))))
                (atomically (hashtable-set! pending ref (vector self node)))
                ;; A REFUSED SUBMISSION IS ANSWERED AS NO LINK. Nothing
                ;; went out, so nothing will ever reply; waiting out the
                ;; caller's whole timeout for an answer that cannot come
                ;; is the hang this layer exists to avoid, and the reason
                ;; is the one the no-link branch below already uses.
                ;;
                ;; ONLY IF THIS PROCESS STILL OWNS THE ENTRY. Between
                ;; publishing and here, the link can drop and
                ;; fail-pending-for! can remove the entry and deliver its
                ;; own rcall-reply. Raising then would leave that message
                ;; in this mailbox with no receive left to match it --
                ;; the orphan this ordering was rebuilt to prevent. If
                ;; the entry is already gone, someone else has TAKEN ON
                ;; answering -- taken the entry atomically, and sends
                ;; after -- so fall through and let the receive collect
                ;; it. Taken on, not done: if that path then fails, no
                ;; answer arrives from either side and this call waits
                ;; out its timeout, which is the outcome it has anyway
                ;; when a reply is lost.
                (let-values (((ok failure)
                              (write-body! (entry-conn e) segs)))
                  ;; BOTH FAILURES ANSWER THE SAME. A caller that has
                  ;; already published a pending entry needs an answer,
                  ;; not a diagnosis: no link and a frame that did not go
                  ;; both mean nothing will reply. The condition is not
                  ;; discarded for want of a place -- it is discarded
                  ;; because this caller's answer does not depend on it.
                  (unless ok
                    (when (atomically
                            (let ((v (hashtable-ref pending ref #f)))
                              (when v (hashtable-delete! pending ref))
                              (and v #t)))
                      (raise (vector 'rcall-error 'noconnection node)))))
                (receive (after timeout
                            (atomically (hashtable-delete! pending ref))
                            (raise (vector 'rcall-error 'timeout reg-name)))
                  (`#(rcall-reply ,@ref ,result)
                    (atomically (hashtable-delete! pending ref))
                    ;; a well-formed reply is (ok ,v) or (error ,reason);
                    ;; anything else is a broken peer, not a hang
                    (cond
                      ((and (pair? result) (eq? (car result) 'ok) (pair? (cdr result)))
                       (cadr result))
                      ((and (pair? result) (eq? (car result) 'error) (pair? (cdr result)))
                       ;; 'noconnection is a statement about the NODE, and
                       ;; carries the node in every other place it is
                       ;; raised. It reaches here when the link dropped
                       ;; while this call was outstanding; reporting the
                       ;; registered name there made the same reason carry
                       ;; two different things depending on which path
                       ;; produced it.
                       (raise (vector 'rcall-error (cadr result)
                                      (if (eq? (cadr result) 'noconnection)
                                          node
                                          reg-name))))
                      (else
                       (raise (vector 'rcall-error 'bad-reply reg-name)))))))))
        (else (raise (vector 'rcall-error 'noconnection node))))))

  ;; Watch the process registered as name on node. The caller later
  ;; receives exactly one #(remote-down ,node ,name ,reason):
  ;;   - reason = the target's exit reason when it dies
  ;;   - 'noproc       if no such name is registered when the watch is
  ;;                   established (which is asynchronous, so a target
  ;;                   that dies in that window also reports noproc --
  ;;                   monitor before the event that can kill it)
  ;;   - 'noconnection if the link to node drops first (the target may
  ;;                   be alive or dead -- indistinguishable across a
  ;;                   broken link, as in Erlang)
  ;;   - 'overload     if node is already hosting its maximum number of
  ;;                   remote monitors and refuses another (node-set-limits!)
  ;; Returns a monitor ref for demonitor-remote. The own node name is a
  ;; local watch (still reported as remote-down, for a uniform API).
  ;; This is process-level; monitor-node is the node-level counterpart.
  (define (monitor-remote node name)
    (unless self-name
      (assertion-violation 'monitor-remote "call node-start! first" node))
    (let ((mref (next-mref!)))
      (cond
        ((eq? node self-name)
         ;; The owner must exist before the target agent can report DOWN;
         ;; otherwise that fast path cannot stop it and leaves another dead
         ;; agent rooted after the monitor has already completed. It must
         ;; also exist before this process can be killed -- see
         ;; arm-rmonitor!, which is why the two are one step.
         ;; ONE REGION FOR BOTH HALVES, and the guard inside it.
         ;;
         ;; These were two regions in a row. If the second raised -- it
         ;; spawns and it writes a new key, so it can -- the monitor
         ;; stayed armed with nothing to fire it, and that residue was
         ;; permanent: the sweep that collects armed monitors fires only
         ;; for a peer whose link dropped, and this node's own name never
         ;; drops. The caller simply never heard anything again.
         ;;
         ;; It was also not assertable. caller-agents and rmonitors are
         ;; both reported, but only LOCAL monitors have a caller agent
         ;; and nothing reports how many monitors are local, so there is
         ;; no equality between the counts to check. What there is, is a
         ;; baseline: rmonitors is reported, and after a failed arming it
         ;; has to be what it was before.
         ;; ⚠ `caller` IS READ HERE, NOT IN THE AGENTS. `self` is a
         ;; property of whoever is running, so the same expression means
         ;; a different process once it is inside a spawned thunk -- it
         ;; would name the agent instead of the process being watched
         ;; over, and the agent would then wait for its own death. The
         ;; two helpers this replaced took the caller as a parameter,
         ;; which is what kept the reading on this side of the spawn.
         (atomically
           (let ((caller self) (oa #f) (sa #f))
             (guard (e (#t (undo-remote-arm! mref oa sa) (raise e)))
               (hashtable-set! rmonitors mref (vector caller node name))
               (set! oa (spawn (lambda () (owner-mon-agent caller mref))))
               (hashtable-set! owner-agents mref oa)
               (set! sa (spawn (lambda () (self-mon-agent caller mref name))))
               (hashtable-set! caller-agents mref sa)))))
        ((live-entry node)
         => (lambda (e)
              ;; no origin field: the target derives the watcher from the
              ;; authenticated far end of this very link (see dispatch!)
              ;;
              ;; Materialized before the watch is armed, for the reason
              ;; frame-segments gives: arming must precede the write, so
              ;; the only way a refused frame leaves nothing behind is for
              ;; the refusal to come first.
              ;;
              ;; A REFUSED SUBMISSION IS ANSWERED AS NO LINK, exactly as
              ;; the branch below does for a peer with no link at all: the
              ;; target never heard of this mref, so it will never report
              ;; anything, and a watch that reports nothing is the one
              ;; outcome this API promises cannot happen. Disarm, then
              ;; deliver the DOWN this caller is owed.
              ;;
              ;; ONLY IF THIS PROCESS STILL OWNS THE ENTRY -- if the link
              ;; dropped in between, fail-monitors-for! has taken the
              ;; entry and is on its way to delivering a noconnection of
              ;; its own, and a second one would be a DOWN for a watch
              ;; that has already ended. Taken, not necessarily
              ;; delivered: the atomic step transfers who answers, not
              ;; the answer itself.
              (let ((segs (frame-segments (list 'mon name mref))))
                (arm-rmonitor! mref node name)
                (let-values (((ok failure)
                              (write-body! (entry-conn e) segs)))
                 (unless ok
                  (let ((entry (atomically
                                 (let ((x (hashtable-ref rmonitors mref #f)))
                                   (when x (hashtable-delete! rmonitors mref))
                                   x))))
                    (when entry
                      (stop-owner-agent! mref)
                      (send self (vector 'remote-down node name
                                         'noconnection)))))))))
        (else
         ;; no link at all: report immediately, nothing to install
         (send self (vector 'remote-down node name 'noconnection))))
      mref))

  ;; Cancel a monitor-remote. No further remote-down for it will arrive
  ;; (a DOWN already in flight may still be delivered, as in Erlang).
  (define (demonitor-remote mref)
    (let ((entry (atomically
                   (let ((e (hashtable-ref rmonitors mref #f)))
                     (when e (hashtable-delete! rmonitors mref))
                     e))))
      (when entry
        (stop-owner-agent! mref)
        (remove-target-watch! mref entry)))
    (void))

  ;; ---- load-time structural checks ------------------------------------
  ;; Library bodies put every definition before every expression, so this
  ;; sits at the end rather than beside the tree it guards. What it
  ;; guards is a requirement source layout expresses and no test can
  ;; read: first-match-wins makes a rule's POSITION its priority, and I0
  ;; refuses an install whose parent is already gone. Demoted below I1, a
  ;; repeat request from a live child of a dead parent answers "idempotent
  ;; success" first and I0 never sees the orphan -- a change that leaves
  ;; every run green. A cell can assert the same thing and a cell can
  ;; also be deleted; this refuses to load.
  (unless (eq? 'I0 (car (node-install-rule-order)))
    (assertion-violation 'node
      "I0 must be the first install rule -- first-match-wins makes position the priority"
      (node-install-rule-order)))
)
