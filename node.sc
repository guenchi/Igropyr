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
;;;   - messages between one pair of nodes arrive in send order WITHIN
;;;     ONE CONNECTION. Across a replacement the guarantee does not
;;;     hold: the old and new links coexist while the old one drains
;;;     its buffer, and it can go on to drain arbitrarily many tcp-data
;;;     messages queued ahead of link-stop in its mailbox -- unbounded,
;;;     not a brief window, though an earlier EOF or error can end it
;;;     sooner -- so
;;;     two messages sent
;;;     either side of a replacement can arrive in either order. The
;;;     mon/demon case is worked through where it bites; grep for
;;;     "reordered" in this file. One TCP connection per pair is the
;;;     steady state, and a replacement is the exception to it.
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
;;; RAISE OF THIS NUMBER IS A BREAK. The constant is 4, so three have
;;; happened: version 2 introduced the field itself (the pre-versioning
;;; handshake -- challenge of 2, hello of 4 -- is refused in both
;;; directions), version 3 widened the call frame to carry the caller's
;;; own timeout, and version 4 added boot-id and dial-gen to hello.
;;;
;;; ⚠ THIS SENTENCE COUNTS SOMETHING THAT CHANGES, so check it against
;;; protocol-version rather than trusting it: the count of raises is
;;; that constant minus one. It said "two" while the constant already
;;; read 4.
;;;
;;; All were made while this
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
;;;    max-outbound-bytes). Bulk data is not meant to ride the control
;;;    link and should get its own connection -- ⚠ that is advice, not
;;;    something this layer enforces: rsend will carry whatever it is
;;;    given, and the suite sends a 70 000-character message through it.
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
          node-dead-letters node-dead-letter-stats
          node-redeliver-dead-letter!
          submission-failure? node-install-rule-order node-orphan-count
          monitor-node/token demonitor-node/token)
  ;; ⭐ (igropyr inject) IS A COMPILE-TIME ONLY DEPENDENCY WHEN OFF -- see
  ;; the note in libuv.sc; test/inject-isolation.ss is what measures it.
  (import (chezscheme) (igropyr buffer)
          (igropyr actor) (igropyr libuv) (igropyr sexpr)
          (igropyr gen-server) (igropyr inject)
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
  ;; is the longest variable-length field in hello and welcome (dial-gen
  ;; is variable too, but bounded at 20 digits), and those two
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
  ;; The arithmetic, and it holds twice over. Measured on the CURRENT
  ;; (v4) hello, with this library's own writer -- a 255-character name,
  ;; a 64-character proof, a 32-character nonce, version 4, a 16-hex
  ;; boot-id and a dial-gen at its largest issued value (2^64-1, twenty
  ;; digits): a maximal hello is 409 bytes and a challenge is 67. A
  ;; wire-safe symbol is restricted by the writer to a printable ASCII
  ;; subset, so a name is one byte per character today.
  ;;
  ;; ⭐ RE-MEASURE RATHER THAN TRUST THESE. They were 112 and 367 for the
  ;; v3 shape and went stale the day boot-id and dial-gen were added, so
  ;; the next wire change stales them again:
  ;;
  ;;   (import (igropyr sexpr))
  ;;   (bytevector-length
  ;;     (string->utf8
  ;;       (sexpr->string-extended
  ;;         (list 'hello (make-string 255 #\a) (make-string 64 #\f)
  ;;               (make-string 32 #\0) 4 (make-string 16 #\a)
  ;;               (- (expt 2 64) 1))))) That margin does not depend on the charset staying
  ;; that way: even if the writer grew full \xNNNNNN; escaping, nine
  ;; bytes per character, the same measurement gives 2449 bytes -- still
  ;; under handshake-max-frame, which is 4096.
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
  ;; TWO WRITERS, AND THE REGION IS WHAT MAKES THAT SAFE. The registrar
  ;; writes this table, and so does an attempt: authorised-connect!
  ;; replaces the row addressed to itself, inside an atomic region, after
  ;; re-reading it and comparing with eq?.
  ;;
  ;; ⭐ THE CORRECTNESS COMES FROM THE REGION, NOT FROM THE RE-READ. The
  ;; region is uninterruptible under this scheduler, so nothing can land
  ;; between the read and the replace; that alone is why no update is
  ;; lost. The eq? comparison is redundant defence, not a synchronisation
  ;; protocol -- remove the region and it does not hold, so do not read
  ;; it as a compare-and-swap. (An earlier version of this note said the
  ;; registrar was the only writer, which a grep of hashtable-set! on
  ;; this table refutes.)
  ;;
  ;; An attempt only ever touches the one row addressed to itself.
  ;; That split is what lets the check
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
  ;; in a single step. Whole replacement plus an eq? recheck has the
  ;; shape a compare-and-swap has, and a mutable bit does not -- but see
  ;; the note above: the guarantee comes from the atomic region, not
  ;; from the recheck, and calling either of these a CAS invites the
  ;; conclusion that the region is removable.
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
  ;; condition carries a token so that a guard which sees it re-raises
  ;; rather than treating it as a refused proof.
  ;;
  ;; ⛔ THAT TOKEN DOES NOT CROSS INTO THE CONNECTOR, AND AN EARLIER
  ;; VERSION HERE SAID IT DID. Written from a grep: every path to
  ;; next-dial-gen! runs in registrar-loop -- three direct calls, plus
  ;; peer-gen, whose only caller is also there. None of them is inside
  ;; the dynamic extent of dial! or of the process attempt! spawns, so
  ;; no handshake guard is on this stack and no connector is stopped by
  ;; it. What actually happens on exhaustion is that the REGISTRAR
  ;; reports and dies -- and with it every future dial, since it is the
  ;; process that hands out generations.
  ;;
  ;; ⚠ NAMED RESIDUAL: the registrar is spawned bare, with no
  ;; supervision, so an unexpected raise inside it ends it with nothing
  ;; restarting it. THIS trigger attempts to print a diagnostic first
  ;; (see the display below; display can itself raise or block, so even
  ;; this is not guaranteed) -- but an unexpected raise from
  ;; anywhere else in the loop would be. Reachability here is the
  ;; 2^64th advancing call to next-dial-gen! for one peer, after
  ;; 2^64-1 generations have been issued; those calls are not dials --
  ;; revoke, disconnect and endpoint change reach it too. That is why
  ;; this trigger is recorded rather than fixed; the supervision gap is
  ;; the part worth fixing, and it is its own item.
  ;;
  ;; WHAT THIS IS NOT: the specification calls local exhaustion a NODE
  ;; fail-stop, and this is neither that nor the connector-level stop an
  ;; earlier version of this paragraph claimed -- it is a loud report
  ;; followed by the death of the registrar, which is the process that
  ;; issues generations, so no NEW attempt can be authorised for any
  ;; peer. An attempt already authorised and in flight still completes.
  ;; There is no node-wide stop primitive at this layer to call. The
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

  ;; node-name -> a six-field entry: see make-entry and the entry-*
  ;; accessors, which are the definition. (This line said
  ;; #(conn link-pid dialer-name) long after the entry grew; a schema
  ;; written out here is a copy of something that moves, so it names the
  ;; constructor instead.)
  (define peers (make-eq-hashtable))
  ;; node-name -> #(connector-pid host port). The endpoint is part of the
  ;; value because a node keeps its name across a move: keyed on name
  ;; alone, a connector for the OLD address counts as "already dialing"
  ;; and retries it forever after the new one is published.
  (define connectors (make-eq-hashtable))
  ;; node-name -> list of watcher records, not bare pids: see
  ;; make-legacy-watcher / make-token-watcher for the shape.
  (define watchers (make-eq-hashtable))
  ;; rcall ref -> #(caller-pid node) (this node is the caller); the node
  ;; is in the value so a reply can be matched against where it came
  ;; from.
  (define pending (make-eqv-hashtable))
  ;; ALSO A COUNTER, and unlike the monitor reference it is safe across a
  ;; restart -- for a reason worth stating, since the two look alike.
  ;;
  ;; This number and the table it keys are both OURS. A ref appears in a
  ;; reply only because we put it in a call, and if this node restarts,
  ;; the counter and the table restart together: an old ref coming back
  ;; finds an empty table and matches nothing. A monitor reference is the
  ;; opposite -- the peer mints it and we file entries under it, so its
  ;; counter can restart while our entries have not gone yet.
  ;;
  ;; ⇒ "It is a counter" is not by itself an argument for either. What
  ;; settles it is whether the counter and the table that keys on it live
  ;; in the same process.
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
  ;; ⚠ THIS IS A COUNTER, NOT A GENSYM, and code elsewhere depends on the
  ;; difference. Within one run of this process it does not repeat, so
  ;; anything filed under an mref can be found again by that mref alone.
  ;; That is what lets several tables key on it without also recording
  ;; which connection an entry belongs to.
  ;;
  ;; ⛔ ACROSS A RESTART IT REPEATS: it starts at zero again, so a peer
  ;; that restarts sends mref 1 for something new. What keeps that from
  ;; colliding is not this counter. Two things share the work, and the
  ;; division matters:
  ;;   - a real drop, and a replacement BY A NEW RUN, run the sweep that
  ;;     tells this peer's hosted monitors to stop, so entries filed
  ;;     under the old run's mrefs are on their way out;
  ;;   - ⛔ a replacement by the SAME run does not, deliberately: those
  ;;     watches are still wanted, and their mrefs did not restart.
  ;; The removal is not instant either way, and the window where an old
  ;; run's entry is still present is covered by the arming clause's
  ;; staleness test -- which compares the RUN, so it catches exactly the
  ;; case this counter creates and leaves the other alone.
  ;;
  ;; Anyone replacing this with something that survives a restart, or
  ;; removing either call to drop-hosted-monitors! -- the unconditional
  ;; one in remove-peer!, or the new-incarnation-only one in the
  ;; replacement branch -- is removing that protection and not this
  ;; counter, which will look untouched.
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
  ;; the name being watched and the RUN the request came from are both
  ;; part of what the agent was built from, so both have to be comparable
  ;; when the same reference is offered again. (The connection used to
  ;; stand in for the run here, and no longer does -- see the note on the
  ;; record's third slot.)
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
  ;; ⭐ SLOT 2 IS THE PEER'S BOOT ID, AND IT USED TO BE THE CONNECTION.
  ;; What this record has to answer is "is the request in front of me the
  ;; same watch as this one", and a connection is the wrong name for that
  ;; now that the outbound write is fenced on the run: an agent armed on
  ;; a connection that has since been replaced still reports correctly
  ;; TO THE SAME RUN -- against a different run the incarnation fence is
  ;; supposed to suppress it, which is the other half of this change --
  ;; so calling it stale was measuring something that had stopped
  ;; mattering -- and the protocol advertises a repeat of the same
  ;; request as free, so peers are entitled to send one.
  ;; ⛔ MERELY DELETING THE COMPARISON WOULD BE WRONG THE OTHER WAY: a
  ;; NEW run reusing the same mref and name would then be told "already
  ;; armed" by the previous run's still-exiting agent, because that
  ;; counter restarts. The run has to be PART of the identity, not
  ;; absent from it.
  ;;
  ;; ⛔ THIS SLOT'S MEANING IS NOT PROTECTED BY THE COMPILER. Renaming
  ;; the accessor catches every NAMED reader, and that is the whole of
  ;; what it catches: a positional (vector-ref r 2) elsewhere would go on
  ;; compiling and would now be reading a boot id where it meant a
  ;; connection. When this slot changed, the sweep for such readers was
  ;; done by hand -- every (vector-ref _ 2) in the file was read and
  ;; judged, and make-agent-rec's single call site was confirmed -- and
  ;; it came back clean. ⚠ That is an enumeration, not a guarantee, and
  ;; it expires the moment somebody adds a POSITIONAL reader.
  ;; ⛔ So do it again before changing this slot, and do not mistake the
  ;; accessor rename for cover.
  (define (make-agent-rec pid name boot-id key peer)
    (vector pid name boot-id key peer #f #f #f #f))
  (define (agent-pid r)  (vector-ref r 0))
  (define (agent-name r) (vector-ref r 1))
  (define (agent-boot-id r) (vector-ref r 2))
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
  ;; equal?, not eq?: a boot id is a string that arrived off the wire.
  (define (agent-matches? r boot-id name)
    (and (equal? (agent-boot-id r) boot-id) (eq? (agent-name r) name)))

  ;; The per-peer heads. Present only while that peer has something
  ;; parked -- the same rule the orphan chain follows, and for the same
  ;; reason: a table that keeps a row per name ever seen is the structure
  ;; this design already refused, and it needs somebody to clean it.
  ;;
  ;; NOT ON THE PEERS ENTRY, deliberately. Living there would be cheaper,
  ;; but an entry is replaced whole, and replacing it is an implicit
  ;; destruction of whatever hangs on it. A hosted monitor retires by its
  ;; key and by identity, through retire-agent-of-rec-locked!, and does not
  ;; travel with the entry -- so
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
  ;; call sites rather than by asking each of them to behave:
  ;; retire-rec-locked! does it for "the count comes down in one place". Said once so the
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
  ;; ⭐ THE CAPTURE IS NOW HELD BY THE CALLER'S TRANSACTION. Both callers
  ;; run this inside the same atomic region that publishes or removes the
  ;; peers entry, and hang the returned head under a sentinel they
  ;; allocated beforehand. This procedure therefore has exactly one job
  ;; left -- take the chain off mon-heads -- and no opinion about who
  ;; walks it.
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
              (when key (retire-agent-of-pid! key pid)))
            (lease-retire-owner! pid)
            (loop))
          (`#(node-stop) (void))))))

  ;; THE WARDEN'S JOB IS TO KEEP ITS CHILDREN RUNNING, and every
  ;; addition has to earn its place. ⚠ An earlier version of this line
  ;; said it "does three things and may never do a fourth" -- monitor
  ;; the reaper, spawn a replacement, let it rescan -- which the body no
  ;; longer matches: it supervises two children, keeps death windows and
  ;; counters, backs off, reports, applies a give-up policy and shuts
  ;; children down. The bar on additions is the point and it stands; the
  ;; count did not. Anything
  ;; added here has to pass the critical bar again, because this process is
  ;; critical and its death stops the node.
  ;;
  ;; WHAT IS FAIL-STOP HERE IS THE WARDEN, NOT THE REAPER. The design says
  ;; a reaper failure must not take the node down, and it still does not --
  ;; it is restarted. What cannot be recovered from is losing the thing
  ;; that restarts it. ⚠ That was "a dozen lines with no business logic"
  ;; when this was written and is no longer: the body now carries death
  ;; windows, counters, backoff, diagnostics, a persistence rule, the
  ;; fail-stop policy and child shutdown. The argument does not depend on
  ;; its size, so the size claim is dropped rather than re-measured.
  ;;
  ;; This is a trade rather than a removal: the risk moves from a process
  ;; that does ordinary per-workload work to one that does none (it is
  ;; live alongside the workload, it just has no part in it) -- ⚠ not to
  ;; one
  ;; that "runs only when the first one dies", which an earlier version
  ;; of this line said and which is false: the warden starts both
  ;; children during initialisation, handles node shutdown, and discards
  ;; unexpected messages. Recorded as a residue, not as a fix.
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
  (define child-restart-min-count 5)
  (define child-restart-cap-ms 1000)
  ;; How long the failures have to have been going on before giving up is
  ;; the right answer. A count alone cannot say that: five deaths are
  ;; five deaths whether they took a third of a second or an hour, and
  ;; the first of those is the definition of transient.
  ;;
  ;; ⚠ THE COUNT IS A FLOOR, NOT A CEILING, and it used to be the other
  ;; way round. While it was the only test, "max" was its name and its
  ;; meaning. As one half of a conjunction it is the number of deaths
  ;; before the elapsed-time test begins to apply, and restarts routinely
  ;; go past it -- with the delays below, the give-up lands around the
  ;; tenth. The name changed with the meaning, because someone wanting
  ;; the node to give up sooner will reach for whatever is called max and
  ;; find that lowering it changes almost nothing: the time test is the
  ;; gate, and child-min-persist-ms is the dial.
  ;;
  ;; The actual ceiling is not written down here on purpose. It falls out
  ;; of four constants -- the first delay, the doubling, the cap, and the
  ;; threshold -- so a number here would be a copy of something four
  ;; other lines own, and none of their owners would think to come and
  ;; change it. To find it: add up the delays until the total passes
  ;; child-min-persist-ms; the death that crosses it is the one that
  ;; raises.
  ;;
  ;; ⚠ THAT DEATH IS NOT FOLLOWED BY A RESTART. The give-up raises
  ;; before start!, so the last restart is the one before the crossing --
  ;; a sentence here used to say "the restart that crosses it is the last
  ;; one", which counts one restart that never happens.
  (define child-min-persist-ms 5000)

  ;; ---- the warden ------------------------------------------------------
  ;;
  ;; IT MONITORS A LIST OF CHILDREN, RESTARTS THEM, AND LETS EACH ONE
  ;; REBUILD ITSELF -- that is the shape, not a count of what the body
  ;; does; see the fail-stop paragraph above for what it actually
  ;; carries. This process is critical, so anything added here has to
  ;; earn that again.
  ;; Going from one child to several changed how many things it watches
  ;; and not what it does with them, which is why the bar it was held to
  ;; still holds.
  ;;
  ;; What is fail-stop here is the warden, never a child. A child failing
  ;; is recovered from; losing the thing that recovers is not, and that
  ;; thing is no longer the "page with no business logic" an earlier
  ;; version of this line claimed; see the fail-stop paragraph above for
  ;; what it actually carries. ⚠ No size claim replaces it -- "smaller
  ;; than the reaper" would be one more unmeasured comparison, and the
  ;; argument here never needed one.
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
                             "it does not manage (" (raised-object-text reason)
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
                             (raised-object-text reason)
                             "); death " (number->string k)
                             ", giving up after "
                             (number->string child-restart-min-count)
                             " within " (number->string (quotient child-restart-window-ms 1000))
                             "s AND " (number->string (quotient child-min-persist-ms 1000))
                             "s of failing\n")
                           (current-error-port))
                  ;; BACK OFF FIRST, DECIDE AFTER, and the order is the
                  ;; repair. Deciding first meant the give-up was reached
                  ;; before any of the waiting happened: the fifth death
                  ;; raised before its own delay ran, so the four earlier
                  ;; delays -- nothing, 50, 100, 200 -- were the entire
                  ;; life of the budget. A child that could not start
                  ;; took the node down in about a third of a second,
                  ;; while the message said the problem was not
                  ;; transient. A third of a second IS transient.
                  ;;
                  ;; Two of the three constants were decoration on that
                  ;; path. The sixty-second window filtered nothing,
                  ;; since every death fell inside it, and the delay cap
                  ;; was never reached, since the delay only ever doubled
                  ;; to 400 before the raise.
                  (let ((d (vector-ref delays i)))
                    (when (fx> d 0) (sleep-ms d))
                    (vector-set! delays i
                      (fxmin child-restart-cap-ms
                             (if (fx= d 0) 50 (fx* d 2)))))
                  ;; A CONJUNCTION, and ⚠ NEITHER HALF IS MONOTONE. Both
                  ;; can fall: the count drops as timestamps leave the
                  ;; window, and the elapsed time shrinks when the oldest
                  ;; retained death is the one that left. An earlier note
                  ;; here claimed monotonicity and concluded that a child
                  ;; which cannot start must eventually stop the node.
                  ;; That conclusion is true for failures fast enough to
                  ;; keep the window full, and false otherwise.
                  ;;
                  ;; What is guaranteed: a child failing often enough to
                  ;; hold the required count inside the window will cross
                  ;; the elapsed-time test, because the backoff runs
                  ;; before the decision and its cap bounds how slowly
                  ;; time can accumulate. A child that fails more slowly
                  ;; than the window -- once every twenty seconds, say --
                  ;; never reaches the count and is restarted forever.
                  ;; That is the window's own long-standing meaning, not
                  ;; something introduced here, and it is written down
                  ;; because the sentence it replaces said otherwise.
                  ;;
                  ;; The trade, stated: a mistaken stop is exchanged for
                  ;; a late one, and the child's work is not being done
                  ;; during the wait.
                  (let* ((earliest (let loop ((xs recent) (m (car recent)))
                                     (cond ((null? xs) m)
                                           ((< (car xs) m) (loop (cdr xs) (car xs)))
                                           (else (loop (cdr xs) m)))))
                         (persisted (- (now-ms) earliest)))
                    (when (and (fx>= k child-restart-min-count)
                               (>= persisted child-min-persist-ms))
                      (display (string-append
                                 "igropyr node: " nm " died "
                                 (number->string k)
                                 " times over "
                                 (number->string (quotient persisted 1000))
                                 "s; this is not transient and "
                                 (child-consequence spec)
                                 ". Stopping the node.\n")
                               (current-error-port))
                      (raise (list 'child-will-not-start (child-name spec) k))))
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
  (define (undo-install-of-pid! key p)                  ; caller already holds the region
    (let ((cur (hashtable-ref callee-agents key #f)))
      (when (and cur p (eq? (agent-pid cur) p))
        (hashtable-delete! callee-agents key)
        (mon-unlink! cur)))
    (when (and p (process-alive? p)) (kill p 'install-failed)))

  ;; RETIRING IS BY IDENTITY, NOT BY KEY. The key outlives the record
  ;; filed under it: an entry can be retired here and a new one installed
  ;; under the same key before the old agent's DOWN is processed, and a
  ;; retirement that trusted the key alone would then delete the
  ;; REPLACEMENT -- leaving a live agent in no table, on no chain, in no
  ;; count, findable by no later demon, and its credit returned twice.
  ;;
  ;; ⚠ THE NOTE THAT USED TO STAND FOR THIS SAID retire-agent! WAS
  ;; IDEMPOTENT. It is, and that is not the property required.
  ;; Idempotence says deleting twice does not break; it says nothing
  ;; about deleting the same thing twice. The distinction is the whole
  ;; defect: the second call was well-formed, harmless-looking, and
  ;; removed a record that had never been asked about.
  ;;
  ;; Same shape as the queue's delivery confirmation, the admission
  ;; lease's release, and the half-install undo: whoever hands the
  ;; resource back names WHICH ONE, and the removal happens only if that
  ;; one is still the one on file.
  (define (retire-rec-locked! key r)            ; r is known to be current
    (hashtable-delete! callee-agents key)
    (mon-unlink! r)
    (set! active-monitors (fx- active-monitors 1)))

  ;; For a caller holding the record it just examined.
  (define (retire-agent-of-rec-locked! key rec)   ; caller already holds the region
    (let ((r (hashtable-ref callee-agents key #f)))
      (when (and r (eq? r rec)) (retire-rec-locked! key r))))

  ;; For the reaper, which knows the pid that died and nothing else. It
  ;; must not retire whatever happens to be under the key now.
  (define (retire-agent-of-pid! key pid)
    (atomically
      (let ((r (hashtable-ref callee-agents key #f)))
        (when (and r (eq? (agent-pid r) pid)) (retire-rec-locked! key r)))))

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
  ;; ⚠ THE PARAGRAPH ABOVE IS TRUE AND IT IS NARROWER THAN IT READS.
  ;; Everything it describes about the phantom balance is right, and the
  ;; measure it prescribes -- keep interrupts off across both halves --
  ;; closes exactly one of the two ways to land between them. It closes
  ;; the kill. It does not close a raise, because this region gives
  ;; mutual exclusion and not rollback: an exception leaves behind
  ;; precisely what ran before it, and what ran was the store.
  ;;
  ;; That is not a case nobody thought of. It is a complete and correct
  ;; hazard analysis paired with a measure covering one of its triggers,
  ;; written in words that read as though they covered both. The store
  ;; allocates -- a new key can grow the table -- and so does the closure
  ;; handed to conn-on-close!, which is built before the call it is an
  ;; argument to. Either raising used to leave the entry with no hook.
  ;;
  ;; Measured, not argued: injecting a raise between the two halves
  ;; leaves conns=1 bytes=70 still standing after the baseline cell has
  ;; polled for ten seconds. Moving the same raise to just after the hook
  ;; registration -- one bit of difference, and a larger disturbance,
  ;; since it fires three times to the other's one -- leaves the suite
  ;; green. The red is the missing hook and not the interrupted
  ;; handshake. That an out-of-memory really can land on the closure is
  ;; an argument rather than a measurement: it escapes into the conn
  ;; record, so it cannot be stack-allocated.
  ;;
  ;; The guard covers both halves, argument evaluation included, since
  ;; that is where the closure is built. The compensation asks for
  ;; nothing -- restoring a balance writes a key already present, and
  ;; removing one cannot grow a table -- so on the implementation this
  ;; runs on there is nothing in it that allocates, which was measured
  ;; rather than assumed. ⚠ That is a statement about this Chez and these
  ;; two operations, not a law: a hashtable whose delete could compact,
  ;; or a rewrite that made the restore anything but an update in place,
  ;; would end it. "Cannot fail" is shorthand for that, and shorthand is
  ;; what the sentence above this one used to be.
  ;;
  ;; ⚠ The re-raise is `raise`, so a continuable condition arriving here
  ;; leaves as non-continuable. Nothing in this file raises one on this
  ;; path today; it is said because a future one would be silently
  ;; downgraded rather than refused. It does not
  ;; touch the order of the two halves -- registering after the store is
  ;; what makes an already-closed connection come out right, as above.
  (define (outbound-charge! c n)
    (atomically
      (let* ((cur (hashtable-ref outbound c #f))
             (v (+ (or cur 0) n)))
        (guard (e (#t (if cur
                          (hashtable-set! outbound c cur)
                          (hashtable-delete! outbound c))
                      (raise e)))
          (hashtable-set! outbound c v)
          (unless cur (conn-on-close! c (lambda () (outbound-forget! c)))))
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
  ;; `failures` counts how many delivery attempts have been STARTED for
  ;; THIS event -- not how many have failed. The last one counted may
  ;; still have been in flight when its dispatcher was killed, so its
  ;; outcome is unknown; see the block above dispatch-one! for why the
  ;; count has to be taken before the attempt rather than after it.
  ;; It lives on the node because the node is what a retry, a handover to
  ;; the orphan chain and a redelivery all carry along. (The event would
  ;; do as well -- redelivery reuses it and stamp-event! keeps its seq --
  ;; but the head would not: an event moves between heads.) Redelivery resets it to 0:
  ;; an operator asking for another attempt is asking for a fresh three,
  ;; not for the next failure to quarantine it again.
  (define-record-type qnode
    (fields event (mutable next) (mutable cut) (mutable failures)))

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

  ;; #t if it removed n, #f if n was not this head's first node.
  ;;
  ;; ⚠ `and`, NOT `when`. A `when` whose test fails yields the unspecified
  ;; value, and that value is TRUE -- so every caller asking "did the
  ;; removal happen?" would have been told yes. The sibling comment on
  ;; lease-detach! already described this procedure as reporting #f; it
  ;; did not, and nothing noticed because until now no caller looked.
  (define (qhead-done! h n)
    (and (eq? (qhead-first h) n)
         (begin
           (qhead-first-set! h (qnode-next n))
           (unless (qhead-first h) (qhead-last-set! h #f))
           (qnode-next-set! n #f)
           #t)))

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
  ;; ⛔ THERE IS NO THIRD MOMENT. A sweeper that filtered this table by
  ;; pid used to sit in this file with no caller: it had been superseded
  ;; by the two above and left behind. It is deleted, and this sentence
  ;; replaces it, because a procedure that looks like a cleanup path is
  ;; read as one -- and someone comparing the two moments listed here
  ;; against a third one they can see would conclude the list was
  ;; incomplete rather than that the procedure was dead.
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
          (drop-watcher-of-rec! name w))))

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

  (define (drop-watcher-of-rec! name w)
    (atomically
      (hashtable-set! watchers name
        (remq w (hashtable-ref watchers name (list))))))

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
  ;; is a procedure rather than a call to tcp-close!. This runs in
  ;; WHICHEVER process reached write-body! -- an rsend caller most
  ;; obviously, but rcall, monitor-remote, dispatch!, link-write and
  ;; link-write/critical all get here too, and the note further down
  ;; already says the link process itself can, via a ping or a reply.
  ;; What matters for the argument is only that it is not necessarily
  ;; the link process, which may be parked in link-loop's receive. libuv's close completion notifies
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

  ;; The whole rendered line, marker included, fits in reason-text-total.
  ;; The marker's own length is reserved up front, so the number below is
  ;; the number a reader can rely on rather than a number the truncation
  ;; suffix then overruns -- the earlier spelling capped the CONTENT at
  ;; 512 and returned 539.
  (define reason-text-total 512)
  (define reason-text-marker "...[truncated]")
  (define reason-text-budget
    (fx- reason-text-total (string-length reason-text-marker)))

  ;; One line of log text for an object somebody raised -- a dead child's
  ;; exit reason, or whatever a guard caught. Used wherever such an object
  ;; is shown to a person.
  ;;
  ;; ⛔ IT CANNOT BE format's ~s. Chez prints a condition under both ~s
  ;; and ~a as the single token `#<compound condition>` -- no message, no
  ;; irritants, no name -- and an uncaught raise becomes the process's
  ;; exit reason unchanged. Every child that died of a condition was
  ;; logged as that one useless word for as long as the warden existed.
  ;;
  ;; ⛔ NOR IS display-condition ENOUGH, though it renders correctly.
  ;; Measured, not assumed, on Chez 10.1.0: print-length and print-level
  ;; DO NOT reach inside it (it applies its own). With who = x and a
  ;; 100000-character message it renders 100016 characters; with who = x,
  ;; message "oops" and a 100000-character string irritant, 100037. The
  ;; fixtures are named because the numbers are theirs -- a message-only
  ;; condition of the same size gives 100011. A
  ;; log renderer that can emit a hundred kilobytes on the path where a
  ;; supervisor is already reporting a death is worse than the defect it
  ;; replaced -- and this is called from the warden, which is critical,
  ;; so a raise here stops the node.
  ;;
  ;; So it is built from the condition's parts instead:
  ;;   - the whole procedure is guarded, both branches, and any failure
  ;;     becomes a fixed placeholder -- rendering a reason must never
  ;;     itself raise;
  ;;   - a string handed to put! is cut to the remaining budget BEFORE it
  ;;     is scanned, so the scrubbed copy is bounded;
  ;;   - control characters go to spaces on every string that is kept --
  ;;     C0, DEL, C1 and U+2028/2029 -- because a log line is not just
  ;;     newline-free, it is also free of tabs, NULs and terminal
  ;;     escapes;
  ;;   - print-length and print-level are on `show`, which is every ~s
  ;;     this does. They no longer purport to bound display-condition,
  ;;     which is the claim that was false; they do not reach inside the
  ;;     format expansion below either.
  ;;
  ;; ⚠ RESIDUAL, and the earlier statement of it was too narrow. Only the
  ;; RETAINED RESULT is size-bounded. Not bounded: the time and temporary
  ;; allocation of rendering a piece before put! ever sees it (`show` and
  ;; the format expansion both build their whole result first); the
  ;; termination of a custom record-writer that ~s may call; and that
  ;; writer's allocations and side effects. Nor is the input's size the
  ;; limit on any of it -- `(format "~1000000a" 'x)` returns a million
  ;; characters from a tiny condition, so a small reason is not a small
  ;; rendering.
  ;;
  ;; ⛔ WHAT WOULD ACTUALLY BOUND IT is a different shape, recorded as a
  ;; gap rather than half-built here: an output port that stops accepting
  ;; characters, a printer that never calls a record-writer somebody else
  ;; wrote, and a restricted reading of the format string rather than
  ;; Chez's. Those are liveness guarantees; this batch has no timeout and
  ;; no restricted printer to build them from, and a half-made liveness
  ;; guarantee reads exactly like a whole one.
  (define (raised-object-text v)
    (guard (ex (#t "<reason could not be rendered>"))
      (let ((acc '()) (used 0) (cut #f))
        ;; cut to budget, scrub, append -- one pass, no second copy
        (define (put! s)
          (unless cut
            (let* ((s (if (string? s) s "?"))
                   (n (string-length s))
                   (room (fx- reason-text-budget used))
                   (s (if (fx<= n room) s (begin (set! cut #t) (substring s 0 room))))
                   (m (string-length s))
                   (out (make-string m)))
              (do ((i 0 (fx+ i 1))) ((fx= i m))
                (let* ((ch (string-ref s i)) (c (char->integer ch)))
                  (string-set! out i
                    (if (or (fx< c 32) (fx= c 127)
                            (and (fx>= c 128) (fx<= c 159))
                            (fx= c 8232) (fx= c 8233))
                        #\space ch))))
              (set! acc (cons out acc))
              (set! used (fx+ used m)))))
        (define (show x)
          (parameterize ((print-length 4) (print-level 2) (print-graph #t))
            (format "~s" x)))
        (define (put-shown! x) (unless cut (put! (show x))))
        (if (condition? v)
            (let ((who (and (who-condition? v) (condition-who v)))
                  (msg (and (message-condition? v) (condition-message v)))
                  (irr (if (irritants-condition? v) (condition-irritants v) '())))
              (put! "Exception")
              (when who (put! " in ") (put-shown! who))
              (put! ": ")
              ;; A Chez runtime condition keeps a FORMAT STRING as its
              ;; message and the values to fill it as its irritants, so
              ;; printing them apart gives "~s is not a pair with
              ;; irritants ()". Filling it is what display-condition does.
              ;;
              ;; ⛔ WHICH CONDITIONS THOSE ARE IS NOT A GUESS. Chez marks
              ;; them: format-condition? is true of the runtime's own and
              ;; of errorf, false of an ordinary assertion-violation.
              ;; This used to test `(string? msg)` and `(pair? irr)`
              ;; instead and get it deterministically WRONG -- given
              ;; (assertion-violation 'foo "literal ~a text" 'bar), whose
              ;; tilde is literal text, the counts happened to match, so
              ;; it printed "literal bar text" and swallowed the irritant
              ;; entirely. Directives like ~* can drop one silently. A
              ;; genuine format condition may also have NO irritants and
              ;; still need expanding, for ~~, so the count is not a
              ;; secondary test either.
              (let ((filled (and (not cut)          ; nothing to render into
                                 (format-condition? v)
                                 (string? msg)
                                 (guard (e2 (#t #f)) (apply format msg irr)))))
                (if filled
                    (put! filled)
                    (begin
                      ;; ⚠ put-shown!, not put! + show: show runs the
                      ;; printer, and it must not run once the budget is
                      ;; gone.
                      (cond ((string? msg) (put! msg))
                            (msg (put-shown! msg))
                            (else (put! "condition")))
                      (cond ((null? irr) (values))
                            ((null? (cdr irr))
                             (put! " with irritant ") (put-shown! (car irr)))
                            (else
                             (put! " with irritants ") (put-shown! irr)))))))
            (put-shown! v))
        (let ((s (apply string-append (reverse acc))))
          (if cut (string-append s reason-text-marker) s)))))

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

  ;; Is the request coming from a DIFFERENT run of the peer? I6 uses it to
  ;; decide that nothing about the old entry survives; the replacement
  ;; path uses it to decide whether a watch parked here is still owned by
  ;; anybody. See I6 for why it is one definition and not two.
  (define (new-incarnation? e r)
    (not (equal? (entry-boot-id e) (ireq-boot-id r))))

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
      ;;
      ;; ⭐ THE PREDICATE IS NAMED BECAUSE TWO PLACES ASK IT. This rule
      ;; sends a new incarnation down the replacement path, and the
      ;; replacement path then has to treat it as the one case that is
      ;; NOT the same peer on a different connection. Spelled out twice
      ;; the two would drift, and the drift would be silent: each
      ;; spelling reads as correct on its own.
      (make-irule 'I6 new-incarnation? (lambda (e r) 'replace))
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
        ;; (R0) THE CONDITIONAL ALLOCATIONS ARE BUILT HERE, outside. The
        ;; region below takes, ON A SUCCESSFUL PASS: the spare head and
        ;; one event for a fresh install, one event when adopting an
        ;; orphaned head, two events and no head for a replacement, and
        ;; nothing for a non-mutating outcome. ⚠ A pass that raises part
        ;; way can consume fewer -- see step 3 -- so this is the
        ;; successful-path enumeration, not an invariant.
        ;;
        ;; `spare` is built unconditionally on each pass through judge --
        ;; not once per connection: a retry outcome calls judge again for
        ;; the same connection and rebuilds it. That keeps the spare
        ;; head, the two queue nodes,
        ;; their two event vectors and the list spine out of the region.
        ;; (An earlier version said "three small objects": three is the
        ;; number of SLOTS, not of allocations, and "small" was never
        ;; measured.) It does NOT remove every decision-dependent
        ;; allocation: make-entry runs only on install and replace, the
        ;; hashtable-set! on a new key can grow the table, and the
        ;; enqueue's sequence stamp can allocate a bignum (the enqueue
        ;; itself touches no table).
        ;;
        ;; ⚠ It does not make the region allocation-free -- see
        ;; the note a few lines down, which lists what still allocates
        ;; inside it. An earlier version of this sentence claimed the
        ;; stronger property and was contradicted by its own neighbour. A
        ;; region that allocates can raise, and `atomically` does not
        ;; roll back -- a half-finished handover there is unreachable
        ;; state, not a retryable failure.
        (let* ((spare (list (new-qhead)
                            (make-qnode (make-event 'node-down name) #f '() 0)
                            (make-qnode (make-event 'node-up name) #f '() 0)))
               ;; (R0) THE SWEEP'S ANCHOR, BUILT OUT HERE WITH EVERYTHING
               ;; ELSE. The capture in the region below is two pointer
               ;; writes plus an eq-hashtable delete; building the record
               ;; there would add an allocation to a step that has none.
               ;; ⚠ THE REGION AS A WHOLE IS NOT ALLOCATION-FREE, and an
               ;; earlier version of this note implied it was: the rule
               ;; list is built inside it, make-entry runs inside it, and
               ;; qhead-enqueue!'s sequence counter can allocate a bignum
               ;; at fixnum overflow. That is the pre-existing shape this
               ;; spare list exists to reduce, not one this line
               ;; achieves.
               ;; Unused unless the decision is a new incarnation, which
               ;; costs one small object on a path that runs once per
               ;; connection -- the same trade the spares above make.
               (root (make-agent-rec #f #f #f #f #f))
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
                        ;;   1. make-entry -- the first step in this
                        ;;      branch that can FAIL, and it runs before
                        ;;      anything is published; it builds a local
                        ;;      vector and publishes nothing itself. It
                        ;;      is neither the only allocation in this
                        ;;      region nor the first one: install-rules
                        ;;      allocates before the branch is chosen.
                        ;;      What the argument needs is the converse
                        ;;      -- that no PUBLICATION precedes a step
                        ;;      that can fail -- and step 3 shows that
                        ;;      is not currently true;
                        ;;   2. hashtable-set! -- a NEW key, so this one
                        ;;      can grow the table and can raise. Nothing
                        ;;      has been queued yet when it does, so a
                        ;;      failure here publishes nothing and
                        ;;      announces nothing;
                        ;;   3. the enqueue -- pointer writes plus one
                        ;;      thing that is not: qhead-enqueue! stamps
                        ;;      a sequence number, and that increment can
                        ;;      allocate a bignum at fixnum overflow.
                        ;;      ⚠ SO THIS STEP CAN RAISE AFTER THE ENTRY
                        ;;      IS PUBLISHED, which the rest of this list
                        ;;      assumes cannot happen: the install branch
                        ;;      would then hold peers[name] with no
                        ;;      node-up queued. Recorded, not fixed --
                        ;;      reaching it needs a sequence counter past
                        ;;      the fixnum range, and the fix belongs
                        ;;      with the ordering argument, not beside
                        ;;      it. The table growth is not here; it is
                        ;;      the hashtable-set! in step 2;
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
                        ;; write EXCEPT the enqueue's sequence stamp,
                        ;; which can allocate a bignum and so can raise
                        ;; (step 3 records this; it is the one hole left
                        ;; in the argument). Setting that aside there is
                        ;; no longer a
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
                        ;; here it closes further than in install --
                        ;; though not completely, since both enqueues
                        ;; stamp sequence numbers and a stamp can raise:
                        ;; make-entry first, and the hashtable-set! that
                        ;; follows replaces an EXISTING key, so it cannot
                        ;; grow the table and
                        ;; cannot raise. Everything after the allocation
                        ;; is a pointer write EXCEPT the two sequence
                        ;; stamps named just above -- the same hole as in
                        ;; install, and the third place this paragraph
                        ;; family stated the pointer-write claim without
                        ;; it.
                        (set! old e)
                        (set! cut (hashtable-ref watchers name '()))
                        (let* ((h (entry-head e))
                               (ne (make-entry c self dialer boot-id gen h)))
                          ;; two numbers, one turn -- see next-event-seq!
                          (qhead-enqueue! h (cadr spare) cut)
                          (qhead-enqueue! h (caddr spare) cut)
                          (hashtable-set! peers name ne))
                        (tcp-close! (entry-conn e))
                        ;; ⭐ CAPTURE THE HOSTED CHAIN HERE, IN THE SAME
                        ;; TRANSACTION THAT PUBLISHED THE NEW ENTRY. It
                        ;; used to happen later, in a region of its own,
                        ;; and the gap between the two was a window: a
                        ;; new incarnation arming in it filed its agent
                        ;; under the head this sweep was about to take,
                        ;; and the sweep carried the new run's monitor
                        ;; away with the old run's.
                        ;; ⭐ Publishing and capturing being one step is
                        ;; what closes it -- any arm at all is now either
                        ;; before the capture (and belongs to the old run)
                        ;; or after it, under a head this walk cannot
                        ;; reach. C5 stops being a property the splice
                        ;; happened to buy and becomes one the transaction
                        ;; guarantees.
                        ;;
                        ;; ⚠ LAST IN THE REGION, and that is not tidiness.
                        ;; Everything above can still raise; if one of
                        ;; them did after mon-heads had been cleared, the
                        ;; chain would be off the table with nobody
                        ;; holding it. Placed here, a failure earlier
                        ;; leaves mon-heads untouched.
                        ;; Pointer writes only -- mon-splice-peer! does an
                        ;; eq-hashtable lookup and delete, neither of
                        ;; which can grow a table.
                        (when (new-incarnation? e r)
                          (let ((h (mon-splice-peer! name)))
                            (when h
                              (agent-pnext-set! root h)
                              (agent-pprev-set! h root))))
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
             ;; ⭐ TWO SWEEPS THE DEATH PATH RUNS AND THIS ONE MUST
             ;; NOT. A replacement is not a death: it is the same peer on
             ;; a different connection, and a watch that crossed the old
             ;; one has to survive. Only state tied to the CONNECTION
             ;; goes.
             ;;
             ;;   - fail-monitors-for! would tell every watcher that a
             ;;     peer which is reachable right now has become
             ;;     unreachable -- a lie, once per watcher, and one they
             ;;     would act on.
             ;;   - drop-hosted-monitors! would tear down the OTHER HALF
             ;;     of those same watches: the agents this node hosts for
             ;;     the peer. The watcher keeps its rmonitors entry and
             ;;     nothing re-arms it, so the watch would go on existing
             ;;     on one side and being unserviceable on the other.
             ;;
             ;; ⭐ EXCEPT FOR I6, AND IT IS THE WHOLE REASON THE SECOND
             ;; SWEEP IS CONDITIONAL RATHER THAN GONE. Two rules send
             ;; work here and they want opposite things. I7/I8 are the
             ;; same peer on a different connection, and its watches must
             ;; survive. I6 is a DIFFERENT RUN of the peer: the process
             ;; that armed those watches no longer exists, so what is
             ;; parked here is a dead registration that nothing will ever
             ;; come back for.
             ;;
             ;; ⛔ LEAVING I6'S BEHIND IS NOT A LEAK, IT IS A MISREPORT.
             ;; A stale agent still watches a live local process. When
             ;; that process dies the agent writes mdown to the PEER
             ;; NAME, which now resolves to the new incarnation -- whose
             ;; mref counter has also restarted, so the reference can
             ;; name one of ITS watches. The far side then hears that a
             ;; process died which did not, and acts on it.
             ;;
             ;; ⭐ AND IT IS NOT EXTRA CAUTION. Without the condition
             ;; the stale records are still reclaimed -- but only lazily,
             ;; and only in part: the mon admission path retires a record
             ;; whose connection is no longer current, so it reaches
             ;; exactly those keys the new incarnation happens to re-arm.
             ;; Its mref counter restarts too, so that is a prefix of
             ;; what the old run held and nothing reaches the rest. With
             ;; the condition there is no residue at all.
             ;;
             ;; ⚠ THE TWO WERE ONE BRANCH ONCE AND THE ARGUMENT FOR
             ;; REMOVING THE SWEEP WAS CHECKED ON I7/I8 ONLY. It was also
             ;; called a return to what this path did before generations
             ;; existed -- and I6 did not exist before generations, so
             ;; there was no old behaviour for it to return to. A revert
             ;; only covers the paths the old version had.
             ;;
             ;; ⚠ THE SECOND ONE WAS HERE AND HAD TO BE TAKEN OUT. It
             ;; was argued as the reading that "cannot lose a resource",
             ;; against a reading that "cannot lose a registration", with
             ;; the peer's re-registration left open. That symmetry is
             ;; false: the peer runs this same library, monitor-remote is
             ;; the only thing that writes rmonitors or sends a mon
             ;; frame, and nothing calls it again -- so the peer NEVER
             ;; re-registers, and the cost of that reading is not "may
             ;; lose a registration" but "loses it, silently, every
             ;; time".
             ;;
             ;; ⛔ THAT FACT NOW CARRIES TWO PROPERTIES, AND A RE-ARMING
             ;; PATH WOULD BREAK BOTH AT ONCE. It is the reason the sweep
             ;; can be skipped here, and it is also the only thing
             ;; keeping the mon admission's stale-record retirement from
             ;; detaching live agents (see the note beside that
             ;; retirement). Adding a re-arm is not a local change to
             ;; whoever adds it.
             ;;
             ;; ⭐ AND THE RESOURCE ARGUMENT DOES NOT SURVIVE EITHER.
             ;; What drop-hosted-monitors! is for is a peer that
             ;; connects, parks monitors and DROPS, over and over; that
             ;; path is remove-peer! and still calls it. Here the same
             ;; fact that makes the loss real -- nothing re-arms -- is
             ;; what stops the retained agents accumulating, and the
             ;; admission ceiling bounds them even against a peer that
             ;; does re-arm.
             ;;
             ;; ⛔ THE OMISSION IS DELIBERATE, AND IT LOOKS LIKE AN
             ;; OVERSIGHT: a diff shows the death path doing three things
             ;; and this path doing one, and the natural tidy-up is to
             ;; make them agree. Making them agree is how this broke the
             ;; first time.
             ;;
             ;; ⚠ WHAT IS STILL OPEN is the semantics, not this: whether
             ;; a hosted watch belongs to the connection it was armed on
             ;; or to the peer. Until that is decided, this path does
             ;; what it did before generations existed.
             ;; ⛔ THE WALK GOES FIRST, AND THE ORDER IS LOAD-BEARING.
             ;; After the region, root is the only thing that can lead a
             ;; SWEEP to the captured chain: the records are still on the
             ;; global chain and still in callee-agents -- which is how
             ;; the reaper collects one whose agent happens to die -- but
             ;; nothing else will ever send them demon-local. stop-link!
             ;; sends, and a send allocates: a raise there unwinds past
             ;; root and leaves those agents running with no path that
             ;; ends them.
             ;;
             ;; ⚠ AND A KILL BETWEEN THE REGION AND HERE DOES THE SAME.
             ;; Interrupts are back on the moment the region ends, and a
             ;; killed process's continuation is dropped, so this
             ;; ordering shortens the exposure and does not remove it.
             ;; Recorded rather than repaired: making the handoff
             ;; kill-safe means the captured chain has to live somewhere
             ;; other than a stack slot, which is a lifetime-management
             ;; surface wider than the window it would close. The same
             ;; hazard existed at the exit of the old splice
             ;; transaction.
             ;; ⚠ Unconditional: for a same-incarnation replacement the
             ;; region captured nothing, root is empty, and this is a
             ;; no-op. The condition that used to be here now lives at
             ;; the capture, where it belongs -- deciding what to take is
             ;; the transaction's business, not the walker's.
             (drop-hosted-monitors! root)
             (stop-link! (entry-conn old) (entry-link old) 'replaced)
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
  ;; One failed attempt, counted and possibly quarantined. Runs INSIDE the
  ;; guard's handler, and makes its whole decision in one region.
  ;;
  ;; ⭐ THE COUNT AND THE QUARANTINE ARE ONE STEP. Splitting them leaves a
  ;; window: a process killed after the third failure was recorded but
  ;; before the event was set aside leaves the successor to find it still
  ;; queued with failures = 3 and try a fourth time. Taking it off the
  ;; queue and putting it in the ring in the same region removes that
  ;; window rather than narrowing it.
  ;;
  ;; The condition is carried in as an argument, not re-raised: it is the
  ;; reason recorded with the event, and here is the only place it exists.
  (define observer-name 'igropyr-node-observer)

  ;; Say that an event was set aside. Best effort, and the guard is the
  ;; point: this runs on the dispatcher's stack, and a raise from here --
  ;; a formatting error, a write to a closed stderr -- would escape into
  ;; the dispatcher loop, which has none. Losing the notice is survivable;
  ;; losing the dispatcher is what this whole batch exists to prevent.
  ;;
  ;; ⚠ A send to a dead observer is silently dropped, which matches the
  ;; contract. The ring is the record -- in memory, overwritable when
  ;; full, and emptied by redelivery -- and this is the announcement.
  (define (notify-observer! n why failures)
    (guard (e (#t (void)))
      (let* ((ev (qnode-event n))
             (msg (vector 'event-quarantined
                          (event-name ev) (event-kind ev) (event-seq ev)
                          why failures)))
        (let ((p (whereis observer-name)))
          (if p
              (send p msg)
              ;; stderr, not stdout: a cross-process test that merges the
              ;; two and reads by line position would take this for data.
              ;;
              ;; ⭐ THE REASON IS RENDERED BEFORE ANY OF IT IS WRITTEN,
              ;; and by the same procedure the warden uses. Writing it
              ;; straight to the port can raise partway, leaving half a
              ;; line with no newline for the next write to join onto.
              ;;
              ;; ⛔ AND `display` WAS THE WRONG RENDERER. why is whatever
              ;; was raised, which is usually a condition, and display
              ;; gives `#<compound condition>` for one -- the identical
              ;; defect that had made the warden's death log useless,
              ;; written here in the same batch that fixed it there.
              ;; Fixing one of two sites is not fixing the shape.
              ;;
              ;; ⚠ Without a reason at all the two quarantine outcomes
              ;; were the same line: the reason is the only field that
              ;; separates an ordinary poisoned event from one whose
              ;; dispatcher was killed mid-attempt, and a deployment with
              ;; no observer registered has nothing else to read.
              (let ((e (current-error-port))
                    (r (raised-object-text why)))
                (display "igropyr node: event set aside after " e)
                (display failures e)
                ;; ⚠ "attempts", not "failed deliveries": on the
                ;; lost-outcome path the last attempt's result is exactly
                ;; what is not known.
                (display " attempts: " e)
                (display (event-kind ev) e) (display " " e)
                (display (event-name ev) e) (display " seq " e)
                (display (event-seq ev) e)
                (display " reason " e) (display r e) (newline e)))))))

  ;; ⭐ THE ONLY DOOR INTO THE RING. Both quarantine paths come through
  ;; here so that the check below cannot hold at one of them and be
  ;; missing at the other. Written at the caller instead, in poison-step!,
  ;; it would not cover the k > limit route at all -- and that route is
  ;; reached on its own account, by a predecessor dying after it reserved
  ;; the final attempt and before it got to poison-step!, for any reason
  ;; a process dies.
  ;;
  ;; ⚠ It is NOT reached by this assertion firing. That was the argument
  ;; first written here and it was wrong: the assertion fires only when n
  ;; is not the head, and the successor peeks the head afresh, so the
  ;; successor never sees that n at all.
  ;;
  ;; ⚠ WHY IT RAISES. A false qhead-done! says directly only that n is no
  ;; longer this head's first node -- not that n is still queued. But the
  ;; removal paths are a closed set, so more follows: n was the head when
  ;; it was peeked, pushes only append, and the sole way the head advances
  ;; is a successful qhead-done!. So another remover did not merely
  ;; probably win, it NECESSARILY won. What is unknown is only which
  ;; outcome it took -- delivery, or a quarantine of its own.
  ;;
  ;; ⇒ Skipping the insertion would therefore lose NOTHING: each of the
  ;; two removal paths records as it removes -- the delivered branch runs
  ;; only after notify-list! returned, and the quarantine path removes and
  ;; inserts in one region. The reason to raise is not that skipping is
  ;; unsafe. It is that skipping is SILENT, and what it would silence is a
  ;; second deliverer that this design says does not exist. Losing the
  ;; event is not the risk being managed here; losing the news is.
  ;;
  ;; ⚠ WHERE THE RAISE GOES, and it differs by caller: from poison-step!
  ;; it escapes a guard handler that is already running (an R6RS guard
  ;; handler is not active during its own clause, so it does not catch
  ;; itself); from the k > limit branch it is raised before that guard is
  ;; ever entered. dispatch-one! does contain a guard -- the delivery one
  ;; on the line above -- but it is inactive in its own clause on the
  ;; first path and unentered on the second, and neither dispatch-round!
  ;; nor dispatcher-loop installs another. So the dispatcher dies. The
  ;; warden logs the reason -- readably, via raised-object-text, which is
  ;; a separate repair from this one -- and normally restarts it, unless
  ;; its give-up policy fires instead and stops the node.
  ;;
  ;; ⚠ ONE FIRING IS ONE DISPATCHER DEATH -- and that is as far as the
  ;; guarantee goes. This particular n does not drag the successor down
  ;; with it: the successor peeks the head afresh, and the condition for
  ;; the assertion is precisely that n is not there.
  ;;
  ;; ⛔ BUT IT DOES NOT FOLLOW THAT A RESTART HAPPENS. The warden counts
  ;; recent deaths of this child WITHOUT LOOKING AT WHY THEY DIED, so this
  ;; death is added to whatever unrelated dispatcher deaths came before
  ;; it, and it may be the one that crosses the give-up threshold -- and
  ;; the crossing death is not restarted, it stops the node. Nothing here
  ;; requires the race to recur for that to happen.
  ;;
  ;; ⛔ NO CELL, AND NOT REACHABLE TODAY: qhead-push! appends at the tail,
  ;; every qhead-done! call is dynamically reached from dispatch-one!
  ;; (the two syntactic ones are here and in the delivered branch; this
  ;; one is reached only via poison-step! or the k > limit branch), and
  ;; the dispatcher is a warden child restarted only on DOWN, so no
  ;; second deliverer is ever live to displace n. This assertion is not
  ;; for today's code. It is for the second deliverer somebody adds
  ;; later, who will not read the paragraph above.
  (define (quarantine! h n reason)          ; caller does NOT hold the region
    (atomically
      (unless (qhead-done! h n)
        (assertion-violation 'quarantine!
          "event was not at the head of its queue when quarantined" n))
      (ring-put! n h reason)))

  ;; The decision after an attempt has failed. The count was already
  ;; taken before the attempt, so this only reads it.
  (define (poison-step! h n k e)            ; -> 'retry | 'quarantined
    (if (fx< k poison-event-limit)
        'retry
        (begin
          ;; ⭐ LEAVING THE QUEUE AND ENTERING THE RING ARE ONE STEP, so
          ;; no kill lands between them. See quarantine! for why the
          ;; removal is checked rather than assumed.
          (quarantine! h n e)
          'quarantined)))

  ;; ⚠ WHY THE ATTEMPT IS COUNTED BEFORE IT IS MADE. Counting a FAILURE
  ;; leaves a window nothing covers: interrupts are enabled between
  ;; notify-list! raising and the handler running, so a dispatcher killed
  ;; there leaves its successor reading the old count and making one more
  ;; attempt than the limit allows. Counting the ATTEMPT instead makes
  ;; every kill err in the same direction -- the count can only be too
  ;; high, which quarantines early and never retries too often.
  ;;
  ;; ⇒ The invariant is "at most poison-event-limit attempts are STARTED",
  ;; which is a statement that survives a kill anywhere. The previous one
  ;; ("up to three failures") did not.
  ;;
  ;; ⛔ NO CELL COVERS THAT KILL WINDOW -- it cannot be aimed at with what
  ;; the suite has, and this is closed by construction rather than
  ;; demonstrated. Recorded as such; it is the fourth thing waiting on a
  ;; barrier primitive.
  ;;
  ;; A successful delivery is counted too. That count stops being
  ;; reachable only once qhead-done! has run -- notify-list! returning is
  ;; not the end of the attempt, and a kill in between leaves the node
  ;; queued with its count already stored, for the successor to read and
  ;; increment. That is the same window that makes delivery at-least-once
  ;; rather than exactly-once; it is not closed here and is not meant to
  ;; be. A redelivery resets the count, so a redelivered event's first
  ;; attempt is again 1.
  (define (dispatch-one! h)
    (let ((n (atomically (qhead-peek h))))
      (and n
           (let ((ev (qnode-event n)))
             (let attempt ()
               (let ((k (atomically
                          (let ((k (fx+ (qnode-failures n) 1)))
                            (if (fx> k poison-event-limit)
                                k                ; do not record another
                                (begin (qnode-failures-set! n k) k))))))
                 (if (fx> k poison-event-limit)
                     ;; ⚠ THE LIMIT WAS ALREADY REACHED: a previous
                     ;; incarnation reserved the final attempt and died
                     ;; before removing the node. It is not known whether
                     ;; that attempt ever began -- the kill may have
                     ;; landed between storing the count and entering the
                     ;; guarded delivery -- let alone whether it
                     ;; succeeded. Quarantining without starting another
                     ;; is what keeps the start limit; note this branch
                     ;; does NOT record a further failure, it leaves the
                     ;; stored count alone and says the outcome is
                     ;; indeterminate.
                     (begin
                       (quarantine! h n 'lost-outcome-after-kill)
                       (notify-observer! n 'lost-outcome-after-kill
                                         poison-event-limit)
                       #t)
                     ;; ⭐ why IS CAPTURED LEXICALLY, and neither value in
                     ;; the notice may be re-read later: the reason cannot
                     ;; come from the ring slot (a redelivery may have
                     ;; cleared it by then) and the count cannot come from
                     ;; the qnode (a redelivery resets it). Both are true
                     ;; at the moment of quarantine and only then.
                     (let* ((why #f)
                            (r (guard (e (#t (set! why e)
                                             (poison-step! h n k e)))
                                 ;; INJECTION POINT 'notify-deliver --
                                 ;; OWNING GUARD: the guard on the line
                                 ;; above, which is the subject: it turns
                                 ;; a raise into a counted attempt. Both
                                 ;; this call and notify-list! are
                                 ;; lexically inside it, so a synchronous
                                 ;; raise from either reaches it before
                                 ;; any dynamically outer handler. How
                                 ;; many guards lie beyond it depends on
                                 ;; the runner and cannot be read off
                                 ;; this file.
                                 (inject-fault! 'notify-deliver)
                                 (notify-list! (qnode-cut n) (event-name ev)
                                               (event-kind ev) (event-seq ev))
                                 'delivered)))
                       (case r
                         ;; delivered, and only now is it gone. A death
                         ;; anywhere above leaves the event where it was.
                         ;;
                         ;; ⚠ THIS ONE DISCARDS THE RESULT, and the reason
                         ;; is that a failure here is unreachable while
                         ;; there is one dispatcher -- NOT that a failure
                         ;; would be harmless. If a second deliverer ever
                         ;; existed, a false result could equally mean it
                         ;; had already quarantined this event, which
                         ;; would leave it delivered AND listed as a dead
                         ;; letter. That is misleading state, not the
                         ;; at-least-once redelivery this library
                         ;; promises. Whoever adds one checks here too.
                         ((delivered) (atomically (qhead-done! h n)) #t)
                         ;; ⚠ sleep-ms 1, NOT 0. A zero wake time has
                         ;; already passed when the receive is entered, so
                         ;; the timeout branch runs without yielding and
                         ;; the retry would spin inside this process.
                         ((retry) (sleep-ms 1) (attempt))
                         ((quarantined)
                          (notify-observer! n why poison-event-limit)
                          #t))))))))))

  ;; A head leaves the chains only when it is empty, and emptiness is
  ;; re-tested inside the region: something may have been queued on it
  ;; between the delivery above and this test, and a head dropped while
  ;; holding an event is unreachable work.
  ;; ---- dead letters ----------------------------------------------------
  ;;
  ;; ⛔ AN EVENT THAT CANNOT BE DELIVERED USED TO TAKE THE DISPATCHER WITH
  ;; IT. A raise from notify-list! escaped dispatch-one! into a loop with
  ;; no guard: the process died, every queue it served stopped draining,
  ;; and the only symptom was silence.
  ;;
  ;; ⚠ No subscriber callback runs. The raises to expect are from
  ;; process-alive?, from building the notification vector, from send and
  ;; the message it allocates, from reading the watcher record -- and, on
  ;; the branch taken when the process is dead, from drop-watcher-of-rec!,
  ;; which allocates a filtered list and mutates the watcher table. None
  ;; of it is code a subscriber supplied, and all of it can raise. Retrying forever is the other bad answer -- one poisoned
  ;; event then starves every other peer's queue.
  ;;
  ;; So: three attempts, then the event is set aside and the dispatcher
  ;; goes on. Three is a ruling, not a measurement.
  (define poison-event-limit 3)

  ;; The ring holds set-aside events. Four parallel vectors rather than a
  ;; record per slot: everything here is written inside a no-allocation
  ;; region, and a record would have to be built there.
  ;;
  ;; ordinal is the insertion order and doubles as the occupancy flag --
  ;; 0 means empty. Order cannot come from the slot index because
  ;; redelivery leaves holes anywhere in the ring.
  (define dead-letter-capacity 1024)
  (define dl-node    (make-vector dead-letter-capacity #f))
  (define dl-head    (make-vector dead-letter-capacity #f))
  (define dl-reason  (make-vector dead-letter-capacity #f))
  (define dl-ordinal (make-vector dead-letter-capacity 0))
  ;; Scratch for the renumbering below, allocated once so the region that
  ;; uses it allocates nothing.
  (define dl-work    (make-vector dead-letter-capacity 0))
  (define dl-ordinal-counter 1)
  (define dl-lifetime 0)            ; ever set aside, saturating
  (define dl-dropped 0)             ; overwritten because the ring was full

  (define (dl-bump n)
    (if (fx< n (greatest-fixnum)) (fx+ n 1) n))

  ;; Give every stored slot a fresh ordinal, keeping their order. Caller
  ;; holds the region; no allocation -- dl-work is preallocated.
  ;;
  ;; ⚠ THE OBVIOUS ALTERNATIVE IS WRONG. Subtracting (min-live - 1) from
  ;; every ordinal looks equivalent and is not: an operator may redeliver
  ;; anything at any time, so the live span is unbounded and subtraction
  ;; cannot bring the counter down. It could even leave duplicates, or
  ;; overflow inside ring-put! -- at a point where the event has already
  ;; been taken off its queue by qhead-done! and exists nowhere else.
  ;;
  ;; Insertion sort over at most 1024 entries, on a path taken roughly
  ;; once per (greatest-fixnum) insertions -- about 2^60 on a 64-bit
  ;; Chez, though nothing here checks the width. Only roughly: the first
  ;; renumber happens at (greatest-fixnum) - capacity, and each one
  ;; resets the counter to one past the number of occupied slots, so
  ;; later intervals are shorter by that much. ~5*10^5 comparisons in the
  ;; worst case, inside a region; recorded rather than optimised.
  (define (dl-renumber!)                    ; caller holds the region
    (let scan ((i 0) (k 0))
      (if (fx< i dead-letter-capacity)
          (if (fx> (vector-ref dl-ordinal i) 0)
              (begin (vector-set! dl-work k i) (scan (fx+ i 1) (fx+ k 1)))
              (scan (fx+ i 1) k))
          ;; k slots collected; insertion-sort dl-work[0..k) by ordinal
          (begin
            (let sort ((a 1))
              (when (fx< a k)
                (let ((v (vector-ref dl-work a)))
                  (let shift ((b (fx- a 1)))
                    (if (and (fx>= b 0)
                             (fx> (vector-ref dl-ordinal (vector-ref dl-work b))
                                  (vector-ref dl-ordinal v)))
                        (begin
                          (vector-set! dl-work (fx+ b 1) (vector-ref dl-work b))
                          (shift (fx- b 1)))
                        (vector-set! dl-work (fx+ b 1) v))))
                (sort (fx+ a 1))))
            (let assign ((a 0))
              (if (fx< a k)
                  (begin (vector-set! dl-ordinal (vector-ref dl-work a) (fx+ a 1))
                         (assign (fx+ a 1)))
                  (set! dl-ordinal-counter (fx+ k 1))))))))

  ;; Set an event aside. Caller holds the region; no allocation.
  (define (ring-put! n h reason)            ; caller holds the region
    (when (fx>= dl-ordinal-counter (fx- (greatest-fixnum) dead-letter-capacity))
      (dl-renumber!))
    (let find ((i 0) (empty -1) (oldest 0))
      (cond
        ((fx= i dead-letter-capacity)
         (let ((slot (if (fx>= empty 0) empty oldest)))
           (when (fx< empty 0) (set! dl-dropped (dl-bump dl-dropped)))
           (vector-set! dl-node slot n)
           (vector-set! dl-head slot h)
           (vector-set! dl-reason slot reason)
           (vector-set! dl-ordinal slot dl-ordinal-counter)
           (set! dl-ordinal-counter (dl-bump dl-ordinal-counter))
           (set! dl-lifetime (dl-bump dl-lifetime))))
        ((fx= (vector-ref dl-ordinal i) 0)
         (find (fx+ i 1) (if (fx< empty 0) i empty) oldest))
        ((fx< (vector-ref dl-ordinal i) (vector-ref dl-ordinal oldest))
         (find (fx+ i 1) empty i))
        (else (find (fx+ i 1) empty oldest)))))

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

  ;; ---- dead-letter API -------------------------------------------------

  ;; What is set aside, newest first. The scratch vectors are allocated
  ;; OUTSIDE the region and the region copies out of the slots rather
  ;; than handing back the qnode, whose failures field a redelivery
  ;; resets.
  ;;
  ;; ⚠ THE SNAPSHOT IS SHALLOW. Name, kind, seq and the failure count are
  ;; values taken at one atomic instant and cannot change afterwards. The
  ;; REASON is a reference: R6RS lets any object be raised, so it may be
  ;; a mutable one, and what comes back is the object that occupied the
  ;; slot at that instant -- not a copy, which is not possible for an
  ;; arbitrary object.
  ;;
  ;; ⚠ It aliases the ring only for as long as the slot still holds it.
  ;; The region ends before the sort and the result list are built, so a
  ;; redelivery or an overwrite can take the slot before the caller ever
  ;; sees the snapshot, and a mutation would then change nothing the ring
  ;; will report. It may equally alias the originally raised object or
  ;; anything else still holding it. Treat a reason as read-only: which
  ;; of those is true is not something the caller can tell.
  (define (node-dead-letters)
    (let ((ords (make-vector dead-letter-capacity 0))
          (nms  (make-vector dead-letter-capacity #f))
          (kds  (make-vector dead-letter-capacity #f))
          (sqs  (make-vector dead-letter-capacity #f))
          (rsns (make-vector dead-letter-capacity #f))
          (fls  (make-vector dead-letter-capacity 0)))
      (atomically                            ; read-only: copy, decide nothing
        (let loop ((i 0))
          (when (fx< i dead-letter-capacity)
            (let ((o (vector-ref dl-ordinal i)))
              (vector-set! ords i o)
              (when (fx> o 0)
                (let* ((n (vector-ref dl-node i)) (ev (qnode-event n)))
                  (vector-set! nms i (event-name ev))
                  (vector-set! kds i (event-kind ev))
                  (vector-set! sqs i (event-seq ev))
                  (vector-set! rsns i (vector-ref dl-reason i))
                  (vector-set! fls i (qnode-failures n)))))
            (loop (fx+ i 1)))))
      (let collect ((i 0) (acc '()))
        (if (fx= i dead-letter-capacity)
            (map (lambda (p) (cdr p))
                 (list-sort (lambda (a b) (> (car a) (car b))) acc))
            (collect (fx+ i 1)
                     (if (fx> (vector-ref ords i) 0)
                         (cons (cons (vector-ref ords i)
                                     (vector (vector-ref nms i)
                                             (vector-ref kds i)
                                             (vector-ref sqs i)
                                             (vector-ref rsns i)
                                             (vector-ref fls i)))
                               acc)
                         acc))))))

  ;; ⚠ lifetime and dropped SATURATE. Once either reaches the fixnum
  ;; ceiling it stops moving, so both are lower bounds from then on, and
  ;; an observer watching deltas would read a saturated counter as
  ;; recovery.
  (define (node-dead-letter-stats)
    (let ((s 0) (l 0) (d 0))
      (atomically
        (let loop ((i 0) (k 0))
          (if (fx< i dead-letter-capacity)
              (loop (fx+ i 1) (if (fx> (vector-ref dl-ordinal i) 0) (fx+ k 1) k))
              (begin (set! s k) (set! l dl-lifetime) (set! d dl-dropped)))))
      (list (cons 'stored s) (cons 'lifetime l) (cons 'dropped d))))

  ;; Put one back on a queue. #f if that seq is not set aside OR if no
  ;; dispatcher is registered -- the two are not distinguished, and in
  ;; both cases nothing has been touched.
  ;;
  ;; ⭐ THE HEAD IS RESOLVED, NOT REMEMBERED. dl-head records where the
  ;; event came from, but by now that head may have been retired. The
  ;; peer's current head is whatever peers says, and if the peer is gone
  ;; the orphan chain has it; only if neither does the spare get attached.
  ;; ⛔ Using live-entry here would be wrong: an entry that is not yet
  ;; open still owns the canonical head, and creating a second one breaks
  ;; the one-head-per-peer invariant.
  (define (node-redeliver-dead-letter! seq)
    ;; ⛔ NO DISPATCHER, NO REDELIVERY -- checked before anything moves.
    ;; Redelivery promises an attempt, and an event put back on a queue
    ;; nobody drains is not an attempt: it would leave the ring, report
    ;; success, and never be delivered or listed again. Refusing leaves
    ;; it where the operator can still see it and try later.
    (let ((spare (new-qhead))                ; (R0): allocated outside
          (work (vector 'work)))             ; (R0): allocated outside
      (let ((woke                            ; the dispatcher, or #f
             (atomically
               ;; ⛔ THE DISPATCHER IS RESOLVED IN HERE, with the slot
               ;; clearing, not before it. Read outside, the answer can
               ;; go stale: the dispatcher may exit and unregister
               ;; between the check and the transaction, and the letter
               ;; would then leave the ring, be reported delivered, and
               ;; sit on a queue nobody drains -- the exact outcome the
               ;; check exists to prevent, only harder to notice.
               ;;
               ;; ⚠ ONLY THE LOOKUP HAS TO BE IN HERE. The wake does not:
               ;; qhead-enqueue! ends in ready-attach!, so by the time
               ;; this region ends the event is already on the chain that
               ;; dispatch-round! walks, and dispatch-round! runs without
               ;; being asked. A dispatcher that dies after the region is
               ;; replaced by one that runs a round BEFORE its first
               ;; receive; one that lives has a 1000ms timed receive. So
               ;; a lost wake costs latency, not the event -- and keeping
               ;; the send out keeps its two allocations out with it.
               ;; (⚠ that bound is on a live dispatcher noticing queued
               ;; work. During node shutdown, or after the warden gives
               ;; up, there is no successor and the work simply waits.)
               (let ((d (whereis dispatcher-name)))
                (and d
                 (let find ((i 0))
                  (cond
                   ((fx= i dead-letter-capacity) #f)
                   ((and (fx> (vector-ref dl-ordinal i) 0)
                         (equal? (event-seq (qnode-event (vector-ref dl-node i)))
                                 seq))
                    (let* ((n (vector-ref dl-node i))
                           (name (event-name (qnode-event n)))
                           (e (hashtable-ref peers name #f))
                           (h (cond (e (entry-head e))
                                    ((orphan-find name))
                                    (else (orphan-attach! spare name) spare))))
                      (vector-set! dl-node i #f)
                      (vector-set! dl-head i #f)
                      (vector-set! dl-reason i #f)
                      (vector-set! dl-ordinal i 0)
                      (qnode-failures-set! n 0)
                      (qhead-enqueue! h n (qnode-cut n))
                      d))
                   (else (find (fx+ i 1))))))))))
        ;; ⚠ THE STATE CHANGE IS ALREADY COMMITTED HERE. send allocates a
        ;; message, and a raise from that allocation leaves the caller an
        ;; exception for a redelivery that did happen. Nothing can undo
        ;; it -- a region has no rollback -- so this is a declared
        ;; residual of the exported API, not something the ordering
        ;; fixes; the ordering only keeps the region itself to pointer
        ;; writes.
        (when woke (send woke work))
        (and woke #t))))

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


  ;; The peer is GONE -- not replaced, gone -- so every monitor we HOST on
  ;; its behalf is now unreportable: tear them down (each demon-local
  ;; demonitors the local process and frees its callee-agents slot).
  ;; Without this a peer that connects, parks monitors, and drops -- over
  ;; and over -- would leak agents and eventually exhaust
  ;; max-hosted-monitors.
  ;;
  ;; ⛔ TWO CALLERS, AND THE CONDITION ON THE SECOND IS LOAD-BEARING.
  ;; The death path calls it unconditionally. The replacement path calls
  ;; it ONLY for a new incarnation (I6) -- see new-incarnation?. Calling
  ;; it for a same-incarnation replacement is the defect this condition
  ;; exists to prevent: the peer is still reachable and still holds the
  ;; watcher's half of every watch, so tearing this half down leaves the
  ;; watch alive on one side and unserviceable on the other, with nothing
  ;; on either side that reports the difference.
  ;;
  ;; ⚠ THE LEAK ARGUMENT ABOVE DOES NOT JUSTIFY AN UNCONDITIONAL CALL,
  ;; though it reads as though it does. The accumulation it describes
  ;; comes from DROPS, which arrive through the death path.
  ;; ⭐ THE WALK HANGS OFF A SENTINEL THAT NOTHING CAN RETIRE, and that
  ;; is the whole of the arrangement. `root` is a full record built out
  ;; here, before the region; it is never filed in callee-agents and
  ;; never joins the global chain, so the reaper has no way to reach it
  ;; and no reason to retire it. Its only job is to be the pprev of
  ;; whatever record is currently first.
  ;;
  ;; That one job is enough, because of what the reaper does to a
  ;; predecessor: retiring any record runs (agent-pnext-set! prev next).
  ;; With root as the predecessor of the first survivor, every
  ;; retirement re-links root to whatever follows -- so root reaches
  ;; every record still on the chain, no matter which ones leave while
  ;; the walk is between steps.
  ;;
  ;; ⛔ AN EARLIER VERSION KEPT THE CURSOR IN A LOCAL AND WAS TRUNCATED.
  ;; It read `next` before sending, on the argument -- written in the
  ;; comment it carried -- that this node's own links were about to be
  ;; cleared by whoever retires it. That argument protects the node the
  ;; walk has FINISHED with. It says nothing about the one it is holding:
  ;; when the reaper retired THAT node during the send, mon-unlink-peer!
  ;; set its pnext to #f, the next step read #f, and the walk stopped
  ;; early -- every record after it kept its agent alive and never heard
  ;; that it should stop. Such a record is not absent from everything: it
  ;; stays in callee-agents and stays on the global chain, since the
  ;; splice removes only the per-peer head. What it has lost is the one
  ;; thing that would have ended it -- no later sweep of this peer can
  ;; reach it, because the chain it was on is gone.
  ;; ⛔ Reading further ahead does not fix it; it moves the exposed node
  ;; one place along. The cursor has to be a thing that cannot be
  ;; retired, which is what root is.
  ;;
  ;; ⚠ EACH POP IS ITS OWN REGION, and the send is outside it. A record
  ;; the walk has popped is fully detached before it is used, so a
  ;; concurrent retirement of it is a no-op: mon-unlink-peer! finds both
  ;; links already #f, so it touches no neighbour, and its head branch
  ;; refuses because that branch compares IDENTITY --
  ;; (eq? (hashtable-ref mon-heads (agent-peer r) #f) r) -- and the head
  ;; on file is not this record.
  ;;
  ;; ⛔ THE REASON IS THE IDENTITY TEST, NOT THE MISSING KEY, and the
  ;; difference is reachable. A note here said the branch could not fire
  ;; because the splice had deleted this peer's head; that holds on the
  ;; death path, where nothing re-creates it, and fails on the
  ;; replacement path, where a new incarnation arms and mon-heads holds
  ;; the peer again -- with ITS record, which is why the comparison still
  ;; says no.
  ;;
  ;; (The splice's delete does do the other job it is credited with: a
  ;; new incarnation's monitors are filed under a fresh head, so they are
  ;; not in this snapshot.)
  ;;
  ;; ⛔ NO CELL DISCRIMINATES THE RACE, and the reason is worth stating
  ;; rather than leaving the surrounding green to imply otherwise. The
  ;; window is between a pop and the send that follows it, and reaching
  ;; it needs this process to yield there:
  ;;   - `send` does not CALL yield: it links the message into the
  ;;     target's inbox and wakes a parked target, inside a
  ;;     with-interrupts-disabled region.
  ;;     ⚠ But LEAVING that region re-enables interrupts, and a timer
  ;;     that expired inside it is delivered right there -- so a walk CAN
  ;;     be preempted at a send's exit. What that does not change is the
  ;;     conclusion: the delivery still waits on the tick budget expiring
  ;;     first, and a short chain finishes inside one slice.
  ;;   - So the walk yields only on timer preemption, and a time slice
  ;;     is 100000 ticks -- more than a sweep costs at the default cap.
  ;;   - The retirement that would truncate it is usually several hops
  ;;     away: the target dies, its agent notices, the agent exits, the
  ;;     reaper sees THAT death, and only then does it unlink.
  ;; ⚠ NEITHER OF THOSE IS A BOUND, and an earlier version of this note
  ;; stated them as though they were. max-hosted-monitors is settable
  ;; without a ceiling, so a large enough cap makes a sweep outlast a
  ;; slice; and a DOWN already sitting in the reaper's mailbox when the
  ;; sweep starts collapses the hop count to one handoff. ⇒ What is
  ;; true is narrower: nothing in the SUITE constructs the interleaving,
  ;; and no cell here discriminates it.
  ;; ⭐ THIS PARAGRAPH HAS BEEN NARROWED THREE TIMES -- "the cap bounds
  ;; the sweep and the reaper is several hops away", then "the suite does
  ;; not construct it", then the send bullet above -- and each time the
  ;; correction was the same one: something stated as impossible was only
  ;; something we had not built. ⛔ So do not cite it as an impossibility
  ;; proof; it is a statement about this suite.
  ;; ⭐ The structure never moved through any of that. The fix does not
  ;; rest on any timing claim -- it rests on the sentinel above, which is
  ;; why it survived all three. There is
  ;; a happy-path cell that sweeps many monitors and checks they are all
  ;; stopped; it guards this loop against ordinary mistakes and ⛔ is not
  ;; coverage of the race. Do not read its green as though it were.
  (define (drop-hosted-monitors! root)
    ;; (R0): the one allocation, and it is out here where a failure has
    ;; changed nothing.
    ;; ⭐ ROOT ARRIVES CAPTURED. The caller took this peer's chain off
    ;; mon-heads and hung it under root inside its OWN atomic transaction,
    ;; the same one that published the new entry or removed the old one.
    ;; ⛔ This function does not read mon-heads and must not: doing the
    ;; capture here would put it in a second transaction, and between the
    ;; two a new incarnation could file an arm under a head this walk
    ;; would then take away.
    ;; A root with nothing under it is the ordinary case for a
    ;; same-incarnation replacement; the walk is then a no-op.
    (let loop ()
      (let ((r #f))
        (atomically
          (set! r (agent-pnext root))
          (when r
            (let ((n (agent-pnext r)))
              (agent-pnext-set! root n)
              (when n (agent-pprev-set! n root))
              (agent-pnext-set! r #f)
              (agent-pprev-set! r #f))))
        (when r
          (send (agent-pid r) (vector 'demon-local))
          (loop)))))

  ;; A REAL DEATH, and the queue has to outlive the entry it hangs on.
  ;; The entry goes in the same region that queues this peer's own
  ;; `node-down`, so deleting the entry would delete the notice about the
  ;; deletion -- the notification destroyed by the very thing it is
  ;; about. The head therefore moves to the orphan chain, and onto the
  ;; ready chain in the same region, so the dispatcher finds it with no
  ;; entry to reach it through; it leaves both chains when it empties.
  (define (remove-peer! name c)
    (let* ((node (make-qnode (make-event 'node-down name) #f '() 0))  ; (R0): outside
           ;; (R0) The sweep's anchor, as on the replacement path.
           (root (make-agent-rec #f #f #f #f #f))
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
                        ;; ⭐ CAPTURE IN THE SAME TRANSACTION, LAST, and
                        ;; for the same reasons the replacement path
                        ;; gives at length: nothing after this point in
                        ;; the region can fail, so mon-heads is cleared
                        ;; only once the removal is certain, and a peer
                        ;; that comes back files its arms under a head
                        ;; this capture cannot reach.
                        ;; ⛔ AND THIS PATH HAD THE SAME WINDOW, which an
                        ;; earlier note here denied on the grounds that
                        ;; the entry is deleted in this very region.
                        ;; Deleting it does not prevent a reinstall -- it
                        ;; ENABLES one: with peers[name] gone, another
                        ;; process could install a new incarnation, serve
                        ;; a mon, and have mon-link! build a fresh head,
                        ;; all before this process reached the separate
                        ;; splice transaction it used to run. That splice
                        ;; would then take the NEW peer's chain.
                        ;; ⭐ Capturing here closes it, exactly as on the
                        ;; replacement path; the two paths are the same
                        ;; shape because they had the same defect, not
                        ;; only for tidiness.
                        (let ((h (mon-splice-peer! name)))
                          (when h
                            (agent-pnext-set! root h)
                            (agent-pprev-set! h root)))
                        #t))))))
      (tcp-close! c)
      (when mine?
        (drop-hosted-monitors! root)       ; free monitors this peer parked here
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
  ;; ⭐ IF YOU ARE ADDING A CLAUSE HERE, READ THIS FIRST.
  ;;
  ;; A frame arrives on a connection, and a connection is one GENERATION
  ;; of a peer. The peer's name outlives it: the same name is reachable
  ;; again the moment a replacement is installed. So a clause that writes
  ;; something outliving this connection, and later resolves who it
  ;; belongs to by NAME, commits work begun under one generation against
  ;; the next one.
  ;;
  ;; The question to ask is not "did I remember to check". It is:
  ;;
  ;;   ⭐ DOES THE KEY I FILE THIS UNDER CONTAIN AN IDENTITY?
  ;;
  ;; A key that is a connection or a process is safe by construction. A
  ;; key that is a name, or a number scoped to a peer, is not: something
  ;; has to compare identities explicitly, and it has to do it in the
  ;; same region that writes the state -- outside one, the answer can go
  ;; stale between deciding and acting.
  ;;
  ;; Four clauses here needed that comparison and did not have it, and a
  ;; gate placed in the frame loop instead could not supply it, because a
  ;; check and a dispatch are two steps. See the arming, cancelling and
  ;; mdown clauses for what the comparison looks like, and
  ;; retire-rec-locked! for the same idea applied to handing a resource
  ;; back rather than taking one.
  ;;
  ;; Clauses that write nothing durable -- a delivered message, a reply
  ;; that a fresh key makes unambiguous -- do not need it. Say which of
  ;; those two your clause is; the answer is short and it is the thing a
  ;; reader will want.
  (define (dispatch! c peer boot-id d)
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
                 ;; ⭐ AND THE WORKER OUTLIVES THIS CONNECTION. It resolves
                 ;; the peer by name when it answers, so a service begun
                 ;; under one generation can write its reply down the
                 ;; next one. That is the same shape as the defects fixed
                 ;; in this batch and it is harmless for the same reason
                 ;; the reply clause is: the ref it carries is ours and
                 ;; unrepeated, so the far side either matches it to the
                 ;; call still waiting -- the answer it wanted -- or
                 ;; matches nothing.
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
      ;; ⭐ NO GENERATION TEST HERE, AND THE REASON IS THE KEY. A ref is
      ;; minted by this node and never repeats within a run, so a reply
      ;; arriving on a superseded connection carries the ref of its own
      ;; call and nothing else: either that call is still waiting, in
      ;; which case this is the answer it asked for and handing it over
      ;; is right, or the link teardown already failed it and the lookup
      ;; finds nothing. Late, not wrong.
      ;;
      ;; ⚠ What makes the first case correct is the match below, which
      ;; compares the peer NAME and not the connection. That looks like
      ;; the omission this file spent a batch fixing elsewhere, and here
      ;; it is the point: the answer came from the peer this call was
      ;; sent to, and which of that peer's connections carried it back
      ;; does not change whose answer it is.
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
              (key (cons peer mref))
              ;; (R0) ALLOCATED OUT HERE, WRITTEN INSIDE, READ AFTER.
              ;; Set when this key already holds a LIVING agent armed on
              ;; a connection that is no longer current. Telling that
              ;; agent to stop allocates a mailbox node, which a
              ;; no-interrupt region may not do, so the region hands the
              ;; record out through this box -- a pointer write, which
              ;; cannot fail -- and the send happens outside, the same
              ;; division the replacement sequence uses for its queue.
              (stale-live #f))
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
         ;; ⭐ WHICH GENERATION ASKED. This is the authoritative test and
         ;; it is here rather than in the frame loop because here it is
         ;; atomic: the table that says which connection is current and
         ;; the table this clause writes are read and written inside one
         ;; region, so nothing can replace the peer between deciding and
         ;; installing. A test in the loop cannot say that -- it releases
         ;; its region before dispatch runs.
         ;;
         ;; ⭐ THE TEST IS THE INCARNATION, NOT THE CONNECTION. It used
         ;; to be the connection, and that discarded a request from a
         ;; SUPERSEDED LINK OF THE SAME RUN -- a peer that is reachable
         ;; right now, whose request still means what it said, and which
         ;; the protocol never told it to repeat. Since a replacement of
         ;; the same run no longer tears its hosted monitors down, there
         ;; is also nothing left to justify dropping it.
         ;;
         ;; A request from a DIFFERENT run is still dropped rather than
         ;; refused: the process that sent it is gone, and refusing would
         ;; write a frame to a socket nobody is reading.
         ;;
         ;; ⚠ THAT IS ONE OF TWO WAYS THE TEST ANSWERS NO, and the note
         ;; used to name only it. current-incarnation-locked? also
         ;; answers no when this peer has NO CURRENT ENTRY AT ALL -- the
         ;; window between an entry being removed and a reconnection
         ;; being installed -- and a frame of the SAME run, buffered on a
         ;; superseded link and drained inside that window, lands here
         ;; too.
         ;;
         ;; Dropping is right for that one as well, for a different
         ;; reason: with no current entry there is no link to carry a
         ;; report, so a monitor armed now could not deliver anything it
         ;; observed. What it costs is the same thing every unanswered
         ;; mon costs -- the watcher is not told, because this protocol
         ;; has no arm-ack. That gap is recorded elsewhere; this is a
         ;; third way of reaching it, not a new one.
         (unless (atomically
                   (or (not (current-incarnation-locked? peer boot-id))
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
                          ;; request treated as new.
                          ;;
                          ;; ⚠ WHAT MAKES THAT SAFE IS NOT IDEMPOTENCE.
                          ;; This note used to say the reaper's DOWN would
                          ;; then find nothing left to do, because
                          ;; retiring is idempotent. Retiring is
                          ;; idempotent, and that is a different claim:
                          ;; it says a second removal does not break, not
                          ;; that a second removal takes the same thing.
                          ;; Between this retirement and that DOWN a new
                          ;; agent can be filed under the same key, and a
                          ;; removal trusting the key alone would take
                          ;; THAT one. Retirement is by identity for
                          ;; exactly this reason -- see retire-rec-locked!.
                          ;; STALE HAS TWO SHAPES AND THEY NO LONGER GET
                          ;; ONE ANSWER. A record whose agent has died is
                          ;; retired here and the request treated as new.
                          ;; A record left by a PREVIOUS RUN is a
                          ;; different thing: its agent may still be
                          ;; running, so it is stopped and the request is
                          ;; refused rather than replaced -- see the cond
                          ;; below.
                          ;; ⛔ A record from a superseded CONNECTION of
                          ;; the current run is not made stale by that
                          ;; supersession alone -- if its agent has died
                          ;; it is stale by the liveness test below, which
                          ;; is a different question. It used
                          ;; to be treated as such, and that cancelled
                          ;; working watches for peers doing what the
                          ;; protocol permits.
                          ;;
                          ;; ⚠ "NO LONGER EXISTS" WOULD BE TOO STRONG for
                          ;; the second shape, and it is the whole reason
                          ;; this branch now splits. A record left by a
                          ;; superseded connection may still have a LIVING
                          ;; agent, and retiring such a record does not
                          ;; stop it: retirement deletes the row, unlinks
                          ;; both chains and decrements the count, and
                          ;; sends nothing. So liveness decides which of
                          ;; two different things happens -- see the cond
                          ;; below, where the living case refuses instead
                          ;; of replacing.
                          ;;
                          ;; ⛔ AN EARLIER NOTE HERE SAID THE RESULTING
                          ;; WINDOW CLOSED BY ITSELF, on two mechanisms.
                          ;; Neither carried it, and how they failed is
                          ;; worth more than the conclusion:
                          ;;   - "the sweep sends it a stop message":
                          ;;     the sweep is conditional on the peer
                          ;;     being a NEW RUN, so a same-incarnation
                          ;;     replacement sends nothing at all;
                          ;;   - "its DOWN will find the key holding
                          ;;     somebody else and leave it alone": this
                          ;;     one is real -- the reaper's
                          ;;     identity-checked retirement, which runs
                          ;;     on every agent DOWN the reaper
                          ;;     processes, whether a
                          ;;     stop caused it or its own target happened
                          ;;     to die. What it is not is a CLOSER of the
                          ;;     window: it collects the orphan if and
                          ;;     when the orphan dies, and an orphan whose
                          ;;     target stays alive stays alive with it.
                          ;;
                          ;; ⚠ THAT SECOND SENTENCE HAS BEEN WRONG TWICE
                          ;; IN OPPOSITE DIRECTIONS -- once claiming the
                          ;; mechanism does not exist, once claiming it is
                          ;; reachable only through the sweep. Both errors
                          ;; came from naming a mechanism instead of
                          ;; naming the path that reaches it. The reaper
                          ;; watches agent pids; the agent exits for its
                          ;; own reasons; neither fact is about the sweep.
                          ;;
                          ;; ⭐ WHAT HOLDS IT UP IS NO LONGER AN ARGUMENT
                          ;; ABOUT THE PEER. It used to be: reaching the
                          ;; living case needs a SECOND mon under a key
                          ;; that already has an agent, and this library
                          ;; has no path that sends one -- monitor-remote
                          ;; mints a fresh mref per call and nothing
                          ;; re-arms.
                          ;; ⛔ THAT IS A FACT ABOUT THIS IMPLEMENTATION
                          ;; AND WAS WRITTEN HERE AS ONE ABOUT CONFORMING
                          ;; PEERS, which it is not: the protocol makes an
                          ;; exact repeat free, a restarted peer's counter
                          ;; starts over, and test/node.sc sends the same
                          ;; mon three times on purpose. So the support
                          ;; was never what it claimed, and a ceiling
                          ;; advertised against a HOSTILE authenticated
                          ;; peer rested on peers being well behaved.
                          ;; It now rests
                          ;; on this branch instead: the living case takes
                          ;; nothing and gives nothing back, so however
                          ;; many times it is reached, the permit and the
                          ;; process stay in step.
                          (cur (and found
                                    (if (and (process-alive? (agent-pid found))
                                             (equal? (agent-boot-id found)
                                                     boot-id))
                                        found
                                        (begin
                                          (if (process-alive? (agent-pid found))
                                              (set! stale-live found)
                                              (retire-agent-of-rec-locked! key found))
                                          #f)))))
                     (cond
                       ;; ⭐ A LIVING AGENT OF ANOTHER RUN DOES NOT MAKE
                       ;; WAY, AND THE PERMIT IS WHY. The design fixes when a permit
                       ;; comes back -- "returned when its agent's DOWN
                       ;; arrives" -- so retiring a record whose process
                       ;; is still running hands the permit back early and
                       ;; lets the next request take another. Done in a
                       ;; loop, that IS the ceiling being bypassed: live
                       ;; agents grow while the count stands still.
                       ;;
                       ;; So this case changes NOTHING. The row stays,
                       ;; both chains stay, the count stays; the agent is
                       ;; told to stop outside the region and this request
                       ;; is refused. The key becomes free when that
                       ;; agent's DOWN reaches the reaper, which is where
                       ;; the permit was always meant to come back.
                       ;;
                       ;; ⚠ THE DEAD CASE ABOVE IS NOT THE SAME CASE.
                       ;; There the process is already gone, so no permit
                       ;; is still in use and there is nothing to stop;
                       ;; retiring it there is what that branch has always
                       ;; been for.
                       ;;
                       ;; ⭐ AND A REPEAT FROM THE SAME RUN NO LONGER
                       ;; ARRIVES HERE AT ALL. It matches, so it takes
                       ;; the idempotent arm below -- which is what the
                       ;; protocol advertises when it calls an exact
                       ;; repeat free. Only a record left by a DIFFERENT
                       ;; run reaches this line, and that run is gone.
                       (stale-live #f)
                       ((and cur (agent-matches? cur boot-id name)) #t)
                       ;; ⛔ THIS ARM IS REACHABLE, AND A CELL HAS BEEN
                       ;; PROVING IT EVERY RUN. A note here once said it
                       ;; was not, on the reasoning that reaching it would
                       ;; need two current connections for one peer. That
                       ;; reasoning read one half of the test above: the
                       ;; match compares the RUN AND THE NAME, so a peer
                       ;; asking to watch a different name under a
                       ;; reference it has already used lands here, with
                       ;; one connection and one run involved. (It read
                       ;; "the connection and the name" while that was
                       ;; what the match compared; the shape of the
                       ;; argument is unchanged.) test/node.sc does
                       ;; exactly that and asserts the link closes.
                       ;;
                       ;; Worth keeping as a lesson about the claim and
                       ;; not only about the code: a sentence saying
                       ;; something cannot happen can be checked against
                       ;; the suite before it is written, and this one
                       ;; would have been refuted in one grep. A green
                       ;; suite does not check the comments; it answers
                       ;; only what it is asked.
                       ;;
                       ;; What the arm means: one reference, two
                       ;; different requests. That is a peer contradicting
                       ;; itself, and the link goes rather than this side
                       ;; guessing which request was meant. A stale
                       ;; generation is NOT that, which is why the test
                       ;; above retires such a record instead of arriving
                       ;; here with it.
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
                        ;; provably harmless. See undo-install-of-pid!.
                        (let ((p #f))
                          (guard (e (#t (undo-install-of-pid! key p) (raise e)))
                            (set! p (spawn (lambda () (mon-agent peer key name boot-id))))
                            (let ((r (make-agent-rec p name boot-id key peer)))
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
                          ;; that is correctly armed.
                          ;;
                          ;; ⚠ AND THE RESCAN COVERS A LOST ANNOUNCEMENT
                          ;; ON THE NEXT REAPER RESTART, NOT BEFORE. An
                          ;; earlier note said it "already covers" one,
                          ;; which reads as a standing backstop; the walk
                          ;; over the global chain runs when a reaper
                          ;; starts, and a reaper that is not replaced
                          ;; never runs it again. So if this send raises
                          ;; -- it allocates a mailbox node, so only
                          ;; under memory pressure -- the agent is
                          ;; watched by nobody until then, and its record
                          ;; and permit stay behind after it dies.
                          ;; ⛔ Recorded rather than mechanised: the
                          ;; residue is OOM-only, and the repair for it
                          ;; is not another announcement. The scope of the guard is
                          ;; the documentation: what is inside it is what
                          ;; is not yet safe to leave behind.
                          (let ((rp (reaper-pid)))
                            (when rp
                              (send rp (vector 'watch p key)))))
                        #t)
                       (else #f)))))
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
           ;; ⭐ THE STOP GOES FIRST, and that ordering is load-bearing.
           ;; Both it and the refusal below allocate and can therefore
           ;; raise; with the stop second, a failed refusal would swallow
           ;; it. This way the agent is on its way out even when the peer
           ;; never hears why its request was declined.
           ;;
           ;; ⚠ WHAT IS AND IS NOT A NO-OP HERE, stated narrowly because
           ;; a wider version of this sentence stood here and was false.
           ;; Nothing above this point touches the monitor accounting --
           ;; no row, no chain, no count -- so a raise BEFORE the stop
           ;; leaves that accounting as the frame found it. ⛔ A raise
           ;; AFTER the stop does not: the agent has the message, so the
           ;; watch is already leaving, and the next repeat meets a
           ;; different state from the one this one met.
           ;; ⭐ WHAT IS BEING STOPPED BELONGS TO A RUN THAT IS OVER.
           ;; Reaching here means the key holds a living agent whose boot
           ;; id is not the one now installed -- an agent the peer's
           ;; previous incarnation armed, whose stop from the replacement
           ;; sweep has not been processed yet. Ending it loses nothing:
           ;; the process that asked for that watch no longer exists.
           ;;
           ;; ⛔ AN EARLIER VERSION OF THIS BRANCH ALSO CAUGHT SAME-RUN
           ;; REPEATS, and cancelled a working watch for one. The note
           ;; here then argued that no conforming CALLER could produce
           ;; such a repeat, which was true and answered the wrong
           ;; question: the protocol tells PEERS an exact repeat is free
           ;; (see the head of this clause), so a conforming peer was
           ;; entitled to send one and lost its watch for it. This file
           ;; has made that mistake at this line once before, in the
           ;; other direction -- see the frame loop's note about calling
           ;; such a peer a protocol violator.
           ;; ⛔ The lesson is about which conformance is being claimed:
           ;; "our caller cannot do this" is not "no correct peer can".
           (when stale-live
             (send (agent-pid stale-live) (vector 'demon-local)))
           ;; ⚠ THE REFUSAL GOES BACK ON THE CONNECTION IT ARRIVED ON,
           ;; which may be a superseded one and therefore closed. What
           ;; that costs is now bounded: the watch being refused is one
           ;; the CURRENT run was trying to arm, so a peer that hears
           ;; nothing is in the same position as a peer whose arming
           ;; frame was dropped -- the standing gap that this protocol
           ;; has no arm-ack for, recorded elsewhere, and not made worse
           ;; here.
           ;;
           ;; ⛔ IT USED TO COST MORE THAN THAT, and the sentence that
           ;; stood here got it wrong twice over. It said "nothing
           ;; downstream depends on it hearing: the permit and the
           ;; process stay in step" -- the second half true, the first
           ;; not following from it, because accounting staying in step
           ;; says nothing about whether the watcher still has a watch.
           ;; ⭐ It answered a narrower question than it appeared to.
           ;; What actually happened then was a working same-run watch
           ;; being stopped while its owner was told nothing at all; that
           ;; path is gone with the identity change above, not with this
           ;; sentence.
           (let-values (((ok failure)
                         (write-body! c (frame-segments
                                          (list 'mdown mref 'overload)))))
             (when (and (not ok) failure)
               (raise (submission-failure peer failure)))))
         ))
      ;; (mdown ,mref ,reason) -> the watched process/link is gone; only
      ;; honor it from the node the monitor actually targets
      ((frame? d 'mdown 3)
       ;; ⭐ THE MIRROR OF THE TEST IN mon-agent, and it asks the same
       ;; question: is this the run we are currently talking to? That one
       ;; keeps this node from sending a dead RUN's notice; this one keeps
       ;; a dead run's notice from ending a watch the new run set up. The
       ;; key is an mref and the match compares only the peer NAME, and a
       ;; restarted peer's mref counter restarts too, so without this the
       ;; notice lands on whatever that mref means now.
       ;;
       ;; ⚠ WHY THE OLD CONNECTION TEST WAS WRONG HERE. An mdown can be
       ;; submitted successfully on a link that is replaced before the
       ;; frame is dispatched, and a superseded link still serves what it
       ;; has buffered. Keyed on the connection, this dropped a notice
       ;; from the peer we are still talking to -- and the replacement
       ;; path deliberately does not run fail-monitors-for!, so nothing
       ;; else ever reported that death. The watch stayed armed forever.
       ;;
       ;; Unlike its mirror, this one IS atomic: the test and the lookup
       ;; are in one region, and the only thing that happens outside it is
       ;; acting on a decision already made.
       (let ((mref (cadr d)) (reason (caddr d)))
         (let ((entry (atomically
                        (and (current-incarnation-locked? peer boot-id)
                             (hashtable-ref rmonitors mref #f)))))
           (when (and entry (eq? (vector-ref entry 1) peer))
             (fire-remote-down! mref reason)))))
      ;; (demon ,mref) -> stop a monitor we host for this peer
      ((frame? d 'demon 2)
       ;; ⭐ SAME INCARNATION TEST, AND THIS IS THE CLAUSE WHERE THE
       ;; CHANGE COSTS SOMETHING. The key here is (peer . mref) and
       ;; carries no connection. Keyed on the connection, a cancellation
       ;; buffered on a replaced link was dropped; that lost a
       ;; cancellation the peer had every right to expect, since the
       ;; peer's run had not ended. Keyed on the incarnation it is
       ;; honoured, which is correct on its own and admits a case the
       ;; connection test excluded:
       ;;
       ;; ⛔ THE mon/demon PAIR CAN NOW ARRIVE OUT OF ORDER. Same peer,
       ;; same run, two connections, the same mref: nothing orders a
       ;; frame buffered on the old link against one sent on the new. A
       ;; demon overtaken by a re-arm cancels a watch that is wanted; a
       ;; re-arm overtaken by its own demon revives one that was
       ;; cancelled -- and the second of those breaks the promise
       ;; demonitor-remote makes below, because the DOWN it would produce
       ;; is created AFTER the cancellation and so is not covered by that
       ;; promise's "already in flight" exception.
       ;;
       ;; ⚠ THIS IS RECORDED, NOT REPAIRED, AND THE TRADE IS DELIBERATE.
       ;; Four failure shapes went away and these two appeared; the
       ;; trigger narrowed from "one late legitimate control frame" to
       ;; "same mref, same run, across two links, opposite operations,
       ;; and reordered". That is a count of shapes, not of odds. Closing
       ;; it needs a per-incarnation epoch admitted before run-link and
       ;; retired on abnormal death too -- a lifetime-management surface
       ;; wider than the ordering window it would close.
       ;; ⛔ So do not read this clause as a complete fix.
       ;;
       ;; The test is inside the same region as the lookup, which is what
       ;; makes it a decision rather than a guess.
       (let ((rec (atomically
                    (and (current-incarnation-locked? peer boot-id)
                         (hashtable-ref callee-agents (cons peer (cadr d)) #f)))))
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
  ;; ⭐ THE OPTIONAL FOURTH ARGUMENT IS AN INCARNATION FENCE, AND IT
  ;; LIVES HERE BECAUSE THE COMPARISON AND THE CONNECTION MUST COME FROM
  ;; ONE ENTRY. ⛔ It was called a lock, and that word promised more than
  ;; it does: it excludes nothing, as the paragraph below says. A caller that only matters to one
  ;; incarnation of the peer -- a hosted monitor agent, which was armed
  ;; against a particular run and whose reference means nothing to any
  ;; other -- can pass the boot id it was armed under. The comparison
  ;; then happens against the SAME entry the connection is taken from.
  ;; ⚠ That is not the same as saying no replacement can land in
  ;; between: it can, and this file says so a few lines up. What it
  ;; buys is that the decision and the connection describe ONE entry, so
  ;; a replacement landing afterwards cannot redirect this write onto the
  ;; new run -- the write goes to the connection that was matched, and a
  ;; failure on it retries and re-compares.
  ;; ⛔ Said the other way round because the first phrasing claimed
  ;; atomicity this does not have, which is the same over-claim the gate
  ;; it replaced was written with.
  ;;
  ;; ⛔ ASKING THE SAME QUESTION BEFORE THE CALL DOES NOT WORK, and that
  ;; is what this replaced. A predicate that reads the table, returns,
  ;; and leaves the caller to write is two operations: the entry can be
  ;; replaced in between, and the write then resolves the peer by NAME
  ;; and lands on the new run carrying a reference minted by the old one.
  ;; Moving the comparison in here is not tidier, it is a different
  ;; property.
  ;;
  ;; ⚠ A MISMATCH RETURNS #f AND TAKES NOTHING DOWN. It is the same
  ;; answer as "this peer has no current entry", and it means the same
  ;; thing to the caller: the node this frame was for is not reachable
  ;; any more, and the run it was for is gone. It is NOT a submission
  ;; failure, so the link must not be dropped for it. No retry either --
  ;; a retry would re-read the entry that just failed to match.
  ;;
  ;; DEFAULT IS #f, MEANING NO COMPARISON. Callers whose frame is
  ;; addressed to the peer rather than to one of its runs -- the demon in
  ;; remove-target-watch! is the standing example -- keep the three
  ;; argument form and keep exactly the behaviour they had.
  (define link-write/critical
    (case-lambda
      ((peer segs why) (link-write/critical peer segs why #f))
      ((peer segs why want-boot-id)
    (let retry ()
      (let ((e (live-entry peer)))
        (and e
             (or (not want-boot-id)
                 (equal? (entry-boot-id e) want-boot-id))
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
               ;; INJECTION POINT 'critical-submit -- OWNING GUARD: the
               ;; guard opened on the next line, and it is the one under
               ;; test. It converts the raise to ok = #f, which selects
               ;; the failure branch below: the atomic test that this
               ;; connection is still the current one, then stop-link!.
               ;; That branch is the assertion's subject.
               ;;
               ;; ⭐ TWO GUARDS STAND BETWEEN THIS POINT AND THE
               ;; ASSERTION, AND ONLY THE INNER ONE FIRES. The inner one
               ;; is the guard on the next line, and it is the subject:
               ;; it turns the raise into ok = #f, which selects the
               ;; failure branch below.
               ;;
               ;; The outer ones are at the call sites. There are
               ;; THREE, and they are named here by their `why` token
               ;; rather than by line, because a line number is exactly
               ;; the thing that goes stale: 'mdown, 'mdown-lost and
               ;; 'demon, each wrapping this in (guard (e (#t
               ;; (drop-link-by-name! ...)))). Recover them with
               ;; `grep -n "(link-write/critical" node.sc`, which is
               ;; also how this count must be re-checked. None of them sees this
               ;; raise, because the inner guard has already consumed
               ;; it. They are there for a DIFFERENT failure --
               ;; frame-segments allocating -- and are why a frame that
               ;; cannot even be built still takes the link down.
               ;;
               ;; What the call sites share is not that they are agents
               ;; -- the demon path is the watcher side, which has
               ;; dropped its rmonitors entry -- but that each has
               ;; ALREADY discarded the state this frame accounts for.
               ;; That is why losing the frame silently is not an option
               ;; and why the raise must not escape.
               ;;
               ;; (Written from a grep of the call sites, as the note
               ;; above this procedure requires. This comment has now
               ;; been wrong three times: it once said there was no
               ;; second guard and that every caller was an agent, and
               ;; the correction to THAT said two call sites when a
               ;; grep gives three. The count is the part that keeps
               ;; going stale. The correction after that spelled the
               ;; sites with LINE NUMBERS to keep them checkable -- and
               ;; the same edit that added them pushed every one of them
               ;; down by ten, so they were wrong on arrival. Tokens,
               ;; not lines.)
               ;;
               ;; ⚠ THE COUNT ABOVE IS PRODUCT-SIDE. A test cell adds
               ;; its own guards outside these; they receive nothing
               ;; here, because the inner guard consumes the raise, but
               ;; a point whose cell asserts on a RAISE rather than on
               ;; state must count those too.
               (let ((ok (guard (e2 (#t #f))
                           (inject-fault! 'critical-submit)
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
                   (else (retry)))))))))))

  ;; The connection this peer is currently reached on, or #f. Used to ask
  ;; whether a connection in hand is still the current one.
  ;; Which connection is this peer reached on right now. ONE SUPPLIER:
  ;; the locked form is what callers already inside a region use, and the
  ;; other is that form with a region around it. A second implementation
  ;; of the same question was added in this batch and removed again --
  ;; two of them answer the same thing today and drift apart tomorrow.
  (define (current-conn-locked peer)            ; caller holds the region
    (let ((e (hashtable-ref peers peer #f)))
      (and e (entry-conn e))))

  (define (current-conn peer)
    (atomically (current-conn-locked peer)))

  ;; ⭐ IS THIS FRAME'S CONNECTION THE PEER'S CURRENT INCARNATION? The
  ;; reverse of new-incarnation?, asked from the other side: that one has
  ;; two entries in hand and asks whether they are different runs; this
  ;; one has a boot id carried up from a link and asks whether it is
  ;; still the run currently installed.
  ;;
  ;; ⚠ IT DELIBERATELY DOES NOT ASK ABOUT THE CONNECTION. A superseded
  ;; connection of the SAME run is still that run: its control frames
  ;; mean what they said, and dropping them was the defect this replaces.
  ;; Only a different run makes them meaningless, because the process
  ;; that sent them is gone.
  ;;
  ;; ⛔ #f IS NOT AN INCARNATION, and this is the whole reason the test is
  ;; not a bare equal?. equal? calls two unknowns equal, so an entry with
  ;; no boot id and a frame with no boot id would be judged the same run
  ;; of the same node -- the one answer this must never give. Both
  ;; install points supply one today (the accepted handshake's field, and
  ;; the dialler's own), so the #f arm cannot be reached from here.
  ;; ⛔ It is written anyway: "no caller passes #f today" is a property of
  ;; the callers, not of this predicate, and the callers are what change.
  (define (current-incarnation-locked? peer boot-id)   ; caller holds the region
    (let ((e (hashtable-ref peers peer #f)))
      (and e boot-id (entry-boot-id e)
           (equal? (entry-boot-id e) boot-id))))

  ;; ⛔ THERE IS NO UNLOCKED FORM OF THIS, AND THERE WAS ONE. It wrapped
  ;; the locked form in a region and handed the answer back, which is
  ;; exactly the shape the outbound fence stopped using: outside a
  ;; region the answer is stale the instant it is returned, and every
  ;; user of it wanted to ACT on the entry it had just asked about.
  ;; Callers that need to act take the boot id to the step that reads the
  ;; entry -- link-write/critical's fourth argument -- instead of asking
  ;; here first.
  ;; ⛔ Re-adding the wrapper is how the window comes back.

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
  ;; ⭐ THE OPTIONAL BOOT ID IS THE SAME DEVICE AS link-write/critical'S,
  ;; and deliberately spelled the same way. A caller that failed to
  ;; deliver something belonging to ONE run must not take down the link
  ;; of another: "by name" resolves to whatever incarnation is current,
  ;; and after a restart that is a healthy link owned by a peer that
  ;; never saw the frame. Comparison and use come from the same entry, so
  ;; this is a lock and not a check.
  ;;
  ;; ⚠ THE CALLER THAT NEEDS IT IS mon-agent, AND IT NEEDS IT BECAUSE OF
  ;; A CHANGE MADE NEARBY. It used to skip building its frame once the
  ;; run was gone, so it never reached its own failure handler; the fence
  ;; moved into the write, so construction now happens first and a
  ;; failure to build reaches here with the old run's business.
  ;;
  ;; Default #f means no comparison, so callers whose frame is addressed
  ;; to the peer rather than to one of its runs are unchanged.
  (define drop-link-by-name!
    (case-lambda
      ((peer why) (drop-link-by-name! peer why #f))
      ((peer why want-boot-id)
       (let ((e (peer-entry peer)))
         (when (and e (or (not want-boot-id)
                          (equal? (entry-boot-id e) want-boot-id)))
           (stop-link! (entry-conn e) (entry-link e) why))))))

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
  ;; ⚠ IT WRITES TO THE PEER, NOT TO A CONNECTION, and that is now a
  ;; decision rather than an accident. The watcher is a peer name and the
  ;; write resolves that name when the monitor fires, so a monitor armed
  ;; before a replacement reports down the connection that replaced it.
  ;;
  ;; ⛔ A CONNECTION-KEYED GATE WAS TRIED HERE AND REMOVED. It carried
  ;; the connection the agent was armed on and wrote only while that
  ;; connection was still current. The argument for dropping the notice
  ;; otherwise was that the watcher's own fail-monitors-for! had already
  ;; told the far side -- TRUE ON THE DEATH PATH AND FALSE ON THE
  ;; REPLACEMENT PATH, where that sweep deliberately does not run. On a
  ;; replacement the gate was therefore not narrow but total: the
  ;; connection it held could never be current again, so it discarded
  ;; every notice for the rest of the monitor's life, and the watcher
  ;; heard nothing.
  ;;
  ;; ⭐ THE LESSON IS ABOUT THE MEASUREMENT, not about that gate. It was
  ;; described, and accepted, as NARROWING a window -- and a narrowing
  ;; whose remaining width is zero is a closure wearing a compromise's
  ;; name. Ask what is left after a narrowing, not how much came off.
  ;;
  ;; ⭐ WHAT REPLACES IT IS A FENCE ON THE INCARNATION. The agent records
  ;; the peer's boot id at arming and writes only while that run is still
  ;; the one installed. The difference from what was removed is the whole
  ;; point: a replacement of the SAME run leaves the fence open, because
  ;; the watcher is still there and still wants the notice; a replacement
  ;; by a DIFFERENT run closes it, because the process that armed the
  ;; watch no longer exists and its mref counter has restarted, so
  ;; delivering the notice would end one of the NEW run's watches and
  ;; report a death that did not happen.
  ;;
  ;; ⭐ AND THE FENCE IS PART OF THE WRITE, NOT A TEST IN FRONT OF IT.
  ;; The boot id goes to link-write/critical, which compares it against
  ;; the same entry it takes the connection from. A replacement can still
  ;; land while that write is in progress; what it cannot do is redirect
  ;; a write already aimed at the entry that matched. There is no
  ;; pre-check here to keep in agreement
  ;; with it, and that is deliberate: a second place asking the same
  ;; question is a second place that can answer it differently.
  ;;
  ;; ⛔ A PRE-CHECK IS WHAT THIS REPLACED, AND IT DID NOT WORK. Reading
  ;; the table, returning, and then writing is two operations; a new run
  ;; installed in the gap was written to anyway, carrying a reference the
  ;; previous run had minted. It was a narrowing described as a closure,
  ;; which is the same mistake as the connection gate it succeeded.
  ;;
  ;; ⚠ NO CELL DISCRIMINATES THIS. Its window is the gap between two
  ;; statements, and nothing in the suite can open it; the argument for
  ;; the fix is the structure, not a red run. Recorded so that nobody
  ;; reads the surrounding green as coverage of it.
  ;;
  ;; ⛔ IT IS ALSO NOT A COMPLETE ANSWER TO THE QUESTION IT LOOKS LIKE IT
  ;; ANSWERS. Whether a hosted watch belongs to the connection it was
  ;; armed on or to the peer is still open; this fence only settles what
  ;; happens across a change of RUN. Ordering between two links of the
  ;; same run is untouched -- see the demon clause in dispatch! for the
  ;; shape that leaves behind.
  (define (mon-agent watcher key name boot-id)
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
            (guard (e (#t (drop-link-by-name! watcher 'mdown-lost boot-id)))
              (link-write/critical watcher
                                   (frame-segments (list 'mdown mref 'noproc))
                                   'mdown-lost boot-id)))
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
                (guard (e2 (#t (drop-link-by-name! watcher 'mdown-lost boot-id)))
                  (let ((segs (guard (e (#t (frame-segments
                                              (list 'mdown mref 'exit))))
                                (frame-segments (list 'mdown mref reason)))))
                    (link-write/critical watcher segs 'mdown-lost boot-id))))
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
  ;; sends nothing -- see undo-install-of-pid! for why that is a structural fact
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

  (define (link-loop c peer boot-id buf last-seen)
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
                                   (link-loop c peer boot-id buf last-seen))))
              (`#(tcp-data ,bv)
                (inbuf-append! buf bv)
                (link-loop c peer boot-id buf (now-ms)))
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
                    (link-loop c peer boot-id buf last-seen)))
              (`#(node-stop) (raise 'stop)))
            ;; ⚠ A SUPERSEDED LINK CAN STILL SERVE WHAT IT HAS BUFFERED.
            ;; Replacing a peer's connection sends the old link a stop
            ;; message, and a message is only read where this loop reads
            ;; its mailbox -- the branch above, taken when no whole frame
            ;; is buffered. With frames still decoded and waiting, the old
            ;; link goes on serving them until its buffer runs out.
            ;;
            ;; A gate was tried here and removed. It could not give the
            ;; property it claimed: the check and the dispatch are
            ;; separate operations with a preemption point between them,
            ;; so a link could pass the check and be superseded before it
            ;; dispatched. It also cost an allocation on every frame,
            ;; which in a change set about what an out-of-memory leaves
            ;; behind is the wrong direction. The judgement belongs where
            ;; the state is written, inside the regions that write it --
            ;; see the arming and cancelling clauses.
            ;;
            ;; WHAT THAT LEAVES, STATED: a superseded link still delivers
            ;; its buffered `send`s and still serves its buffered `call`s.
            ;; A `send` is a message the peer really did send, arriving
            ;; late -- so a subscriber can receive a message from a peer
            ;; AFTER that peer's node-down has been announced. A `call`
            ;; costs one wasted service and a reply written to a closed
            ;; connection; its admission lease is released by the serving
            ;; process itself, so no accounting is lost.
            ;;
            ;; ⛔ THE BOUND IS NOT "WHAT FITS IN THE BUFFER", and an
            ;; earlier sentence here said it was. This loop reads its
            ;; mailbox ONLY on the incomplete branch, so while buf still
            ;; holds a whole frame it neither takes new segments nor sees
            ;; link-stop. When buf finally runs out it goes to the
            ;; mailbox -- and what it finds there first is every tcp-data
            ;; queued AHEAD of link-stop, which it appends, which can
            ;; complete another frame, and so on. The real bound is buf
            ;; PLUS everything already sitting in this process's mailbox
            ;; at the moment of the stop, and that mailbox is unbounded
            ;; (libuv.sc says so where it delivers into it).
            ;;
            ;; ⚠ THE CORRECTION MATTERS BECAUSE OF WHAT THIS SENTENCE IS
            ;; USED FOR. It is the line anyone reaches for to argue that
            ;; a superseded link's window is small, and any decision to
            ;; leave a residue unrepaired rests on that quantity.
            ;;
            ;; OLD TEXT, KEPT FOR ITS REASONING: Replacing a peer's
            ;; connection sends the old link a stop message, and a
            ;; message is only read where this loop reads its mailbox --
            ;; which is the branch above, taken only when no whole frame
            ;; is buffered. With frames still decoded and waiting, the
            ;; old link went on serving them, for as long as its buffer
            ;; lasted, after its generation had been superseded. Nothing
            ;; downstream asked which generation it was speaking for.
            ;;
            ;; That produced two things. An arming request served here
            ;; installed a monitor recorded against the old connection,
            ;; after the sweep that clears the old generation's monitors
            ;; had already run, so it was collected by nothing until the
            ;; next replacement. And when the same request arrived again
            ;; on the new link -- which this protocol advertises as free
            ;; -- the entry it found named a connection that was not the
            ;; new one, and the answer was to call the peer a protocol
            ;; violator and drop the link. A peer doing exactly what the
            ;; documentation permits got a link dropped for it.
            ;;
            ;; The check is here rather than in the clause that showed
            ;; the symptoms because the property is about the link and
            ;; not about one message: a superseded generation should not
            ;; be serving anything. Guarding the arming clause alone
            ;; would fix the two symptoms that were noticed and leave
            ;; every other clause served by a connection that has been
            ;; replaced.
            ;;
            ;; The reason raised is the one stop-link! would have
            ;; delivered anyway, so this makes an existing ending arrive
            ;; earlier and introduces no new outcome downstream.
            (begin (dispatch! c peer boot-id d) (drain))))))

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
  (define (run-link c peer boot-id buf)
    (guard (e (#t (let ((ended (now-ms))) (remove-peer! peer c) ended)))
      (link-loop c peer boot-id buf (now-ms))
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
              ;; ONE BINDING FOR THE PEER'S BOOT ID. The entry is
              ;; installed with it and the link is run with it, and the
              ;; frame gates compare what the link carries against what
              ;; the entry holds -- so these two must be the same value,
              ;; not the same expression written twice.
              (let ((peer-boot-id (list-ref d 5)))
                (if (installed? (install-peer! peer c peer peer-boot-id
                                               (list-ref d 6) #f))
                    (if (write-frame! c
                          (list 'welcome (symbol->string self-name)
                                (proof-a nonce-b (symbol->string self-name)
                                         self-boot-id)))
                        (run-link c peer peer-boot-id buf)
                        (remove-peer! peer c))
                    (tcp-close! c)))))))))        ; lost the tie-break

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
                        (- (run-link c peer bootid-a buf) up))
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
                  ;; ⚠ AN ALLOCATION IN ARGUMENT POSITION IS NOT FREE OF
                  ;; CONSEQUENCE HERE. Building the value before the one
                  ;; write is the shape that keeps a table from being
                  ;; half-updated, and it does that here too -- but one
                  ;; of the arguments is a spawn, and a spawn leaves
                  ;; something behind whether or not the write that was
                  ;; going to publish it succeeds. The write takes a NEW
                  ;; key and can grow the table, so it can raise, and
                  ;; what it left was a connector process dialling a peer
                  ;; that nothing has a record of -- for as long as the
                  ;; node runs, and visible in no count this file keeps.
                  ;;
                  ;; The compensation is only the kill. Nothing before
                  ;; the write wrote anything, so there is no entry to
                  ;; remove, and deleting unconditionally could take out
                  ;; an entry that was already here. What has to be
                  ;; undone is exactly what could already have happened.
                  (atomically
                    (let ((p #f))
                      (guard (e (#t (when (and p (process-alive? p))
                                      (kill p 'connector-unpublished))
                                    (raise e)))
                        (set! p (spawn (lambda () (connector peer host port))))
                        (hashtable-set! connectors peer
                          (vector p host port))))))))
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
                 ;; still the same row we just read, not a replacement
                 ;; published between the read and here.
                 ;;
                 ;; ⚠ NOT A COMPARE-AND-SWAP, though it has that shape,
                 ;; and this comment used to call it one. The whole
                 ;; sequence runs in an atomic region that cannot be
                 ;; interrupted under this scheduler, and THAT is why no
                 ;; update is lost; this re-read is redundant defence.
                 ;; Reading it as a lock-free protocol would suggest the
                 ;; region could be removed, and it cannot.
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
                           ;; ⛔ THE EXHAUSTION TOKEN DOES NOT REACH HERE,
                           ;; and this paragraph used to say it did.
                           ;; next-dial-gen! is called only from
                           ;; registrar-loop (three direct calls plus
                           ;; peer-gen, whose sole caller is there), so
                           ;; the token never enters this process at all
                           ;; -- exhaustion kills the registrar instead.
                           ;;
                           ;; The passing-through machinery below stays
                           ;; correct for dial-gen-exhausted if that token
                           ;; ever does arise in here; the current paths
                           ;; simply never raise it in this process. A
                           ;; plain
                           ;; (#t #f) would swallow whatever does arise,
                           ;; so it is reported to the parent and
                           ;; re-raised there, where the connector's
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
  ;;   - 'overload     if node will not host this watch right now: either
  ;;                   it is already at its maximum number of remote
  ;;                   monitors (node-set-limits!), or a watch under this
  ;;                   reference from a PREVIOUS RUN OF THIS NODE -- the
  ;;                   watcher, not the target -- has not finished
  ;;                   leaving yet. Both are refusals to take a
  ;;                   new permit, which is why they answer alike; a
  ;;                   later attempt can succeed.
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
               ;; ⚠ WHAT REMOVES A caller-agents ROW, and whether
               ;; the agent has to be alive for it. The agent itself
               ;; deletes its row on each of self-mon-agent's three
               ;; exits. remove-target-watch! deletes it by mref --
               ;; reached from demonitor-remote and from the owner
               ;; agent's DOWN -- and needs nothing of the agent at all.
               ;; undo-remote-arm! deletes it when an arming stops part
               ;; way. The reaper is not on this list: it walks the
               ;; monitor chain and the lease chain, not this table.
               ;;
               ;; ⚠ AN EARLIER NOTE SAID A KILLED AGENT WOULD LEAVE ITS
               ;; ROW BEHIND "FOR GOOD". Too strong -- the two mref-keyed
               ;; deletions still reach it. What is true is narrower and
               ;; still worth avoiding: the row then survives until the
               ;; caller demonitors or dies, and forever if it does
               ;; neither.
               ;;
               ;; ⭐ THE SAFETY ARGUMENT IS ABOUT THE ONE KILL PATH,
               ;; NOT ABOUT THERE BEING NONE. The note this replaces said
               ;; "no path in here kills them -- so nothing can kill
               ;; one", and undo-remote-arm! kills exactly this agent.
               ;; The conclusion survived only because that path deletes
               ;; all three rows BEFORE it kills, so it leaves nothing
               ;; behind. Safety rests on that ORDER.
               ;;
               ;; ⛔ A second kill path that does not delete first
               ;; breaks this while every sentence above it still reads
               ;; as true; giving these agents a name reaches the same
               ;; place by another route. Either way this table would
               ;; need a sweeper it does not have. The row leaks alone --
               ;; no credit is attached to it -- so the accounting that
               ;; catches the other agent table would not notice.
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
