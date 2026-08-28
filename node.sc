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
;;;   acceptor -> (challenge <nonce-a> <version>)
;;;   dialer   -> (hello <name> <hmac(secret, nonce-a:name:version)>
;;;                      <nonce-b> <version>)
;;;   acceptor -> (welcome <name> <hmac(secret, nonce-b:name:version)>)
;;;
;;; A NODE NAME IS AT MOST 255 CHARACTERS, and that too is wire syntax
;;; rather than a local convenience. It is checked where a name is
;;; configured AND where one is claimed in a hello, and it has to be
;;; both: checked only locally, this node would refuse to DIAL a name it
;;; would happily ACCEPT, an asymmetry with no reason behind it and
;;; nothing to say when it bites. The number comes from the handshake
;;; frame budget -- see max-name-length.
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
          node-monitor-stats node-outbound-stats reconnect-delay)
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
  ;; Both were made while the distributed layer carried no production
  ;; traffic. From here on every wire evolution goes through this number.
  (define protocol-version 3)
  (define handshake-timeout-ms 5000)
  (define tick-ms 15000)            ; heartbeat interval
  (define dead-ms 60000)            ; silence longer than this = dead link
  ;; Reconnect backoff bounds; the delay itself is reconnect-delay.
  (define reconnect-base-ms 3000)
  (define reconnect-max-ms 60000)

  ;; ---- identity ------------------------------------------------------

  (define self-name #f)             ; symbol, set by node-start!
  (define self-secret #f)           ; bytevector

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
  ;; slots times how long each is held, so the first of them is paired
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
  ;; one of the max-rcall-serving slots for as long as it likes by
  ;; stating as long a timeout as it likes.
  ;;
  ;; WHAT THIS DOES NOT DO: it bounds how long this node WAITS, not how
  ;; long the gen-server runs. A server that overruns goes on running with
  ;; nobody waiting for it, exactly as it does for a local caller that
  ;; times out. That is gen-server-call's contract, not a gap here.
  (define serve-timeout-cap-ms 60000)
  (define rcall-serving 0)
  (define preauth-conns 0)

  ;; take a serve-rcall slot iff one is free; #t if taken
  (define (rcall-slot-take!)
    (atomically
      (and (fx< rcall-serving max-rcall-serving)
           (begin (set! rcall-serving (fx+ rcall-serving 1)) #t))))
  (define (rcall-slot-free!)
    (atomically (set! rcall-serving (fx- rcall-serving 1))))

  ;; take a pre-auth handshake slot iff one is free; #t if taken
  (define (preauth-slot-take!)
    (atomically
      (and (fx< preauth-conns max-preauth-conns)
           (begin (set! preauth-conns (fx+ preauth-conns 1)) #t))))
  (define (preauth-slot-free!)
    (atomically (set! preauth-conns (fx- preauth-conns 1))))

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

  (define (peer-entry name)
    (atomically (hashtable-ref peers name #f)))

  (define (live-entry name)
    (let ((e (peer-entry name)))
      (and e (eq? (conn-state (vector-ref e 0)) 'open) e)))

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
      (let ((l (filter process-alive? (hashtable-ref watchers name '()))))
        (hashtable-set! watchers name
          (if (memq self l) l (cons self l)))))
    (void))

  (define (demonitor-node name)
    (atomically
      (hashtable-set! watchers name
        (remq self (hashtable-ref watchers name '()))))
    (void))

  (define (notify! name what)               ; what: node-up | node-down
    (let ((l (atomically (hashtable-ref watchers name '()))))
      (for-each
        (lambda (p)
          (if (process-alive? p)
              (send p (vector what name))
              (demonitor-dead! name p)))
        l)))

  (define (demonitor-dead! name p)
    (atomically
      (hashtable-set! watchers name
        (remq p (hashtable-ref watchers name '())))))

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

  ;; SERIALIZING AND SUBMITTING ARE SEPARATE BECAUSE ONLY ONE OF THEM CAN
  ;; FAIL. frame-segments raises -- the writer refuses the datum, or the
  ;; frame is over the limit -- and write-body! reports instead. A caller
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

  (define (write-frame! c datum)
    (write-body! c (frame-segments datum)))

  ;; Submit an already-materialized frame. -> #t if it was handed to
  ;; libuv, #f if it was not.
  ;;
  ;; THE FAILURE DOMAIN AFTER A CALLER'S PUBLICATION POINT, written to the
  ;; shape it actually has. frame-segments has already built every byte,
  ;; so the submission itself can only fail in the OOM domain -- the
  ;; queued path's allocation, and the table entry that publishes its
  ;; completion. Those are caught below and reported as #f, the same
  ;; answer a write to a closed connection gives, because a caller that
  ;; has published state can act on a returned #f and cannot act on an
  ;; exception.
  ;;
  ;; THAT GUARD IS NOT THE WHOLE PROCEDURE, and two things sit outside it:
  ;;   - outbound-charge! runs BEFORE it and allocates (a table entry, and
  ;;     on a first write a close hook);
  ;;   - close-for-backpressure! runs AFTER it and both allocates
  ;;     (conn-link-pid walks the peers table) and sends.
  ;; An OOM in either still leaves this procedure by raising. The second
  ;; is the worse of the two and is stated rather than smoothed over: by
  ;; then the frame HAS been handed to libuv, so the peer may act on it
  ;; and reply, while this caller sees an exception and its pending entry
  ;; stays behind -- a reply that arrives later has nothing left to match
  ;; and remains in the mailbox. All of it is the OOM domain, named here
  ;; and not mechanised; catching it would mean answering #f for a frame
  ;; that is already on its way.
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
      (let ((over? #f))
        (let ((r (atomically
                   (set! over? (outbound-charge! c total))
                   (guard (e (#t (outbound-discharge! c total)
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
                       (lambda (status) (outbound-discharge! c total)))))))
          (when over? (close-for-backpressure! c))
          r))))

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
  (define (close-for-backpressure! c)
    (let ((link (conn-link-pid c)))
      (tcp-close! c)                            ; enforce first, then wake
      (when (and link (process-alive? link))
        (send link (vector 'link-stop c 'outbound-backpressure)))))

  ;; The link process running on connection c, or #f if no installed peer
  ;; owns it (a connection still in its handshake, or one already torn
  ;; down). A scan, because peers is keyed by node name and this asks the
  ;; question from the other end; the mesh is small by design (see the
  ;; fourth commitment) and this runs once per backpressure close.
  (define (conn-link-pid c)
    (atomically
      (let-values (((names entries) (hashtable-entries peers)))
        (let loop ((i 0))
          (cond
            ((fx= i (vector-length entries)) #f)
            ((eq? (vector-ref (vector-ref entries i) 0) c)
             (vector-ref (vector-ref entries i) 1))
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
          ((fx>= i n) incomplete)
          ((fx= (bytevector-u8-ref bv (fx+ base i)) 10)   ; newline
           (when (or (fx= i 0) (> len limit)) (raise 'protocol))
           (let ((total (fx+ i 1 len)))
             (if (< n total)
                 incomplete
                 (let ((text (utf8->string (inbuf-sub buf (fx+ i 1) total))))
                   (inbuf-consume! buf total)
                   (string->sexpr-extended text)))))
          (else
           (let ((b (bytevector-u8-ref bv (fx+ base i))))
             (unless (and (fx>= b 48) (fx<= b 57)) (raise 'protocol))
             (scan (fx+ i 1) (+ (* len 10) (fx- b 48)))))))))

  ;; Block (in the calling process) until one whole frame arrives.
  ;; -> datum ; raises 'closed / 'timeout / 'protocol /
  ;; the sexpr-error vector on a malformed datum
  (define (read-frame c buf timeout limit)
    (let ((deadline (+ (now-ms) timeout)))
      (let loop ()
        (let ((d (parse-frame buf limit)))
          (if (eq? d incomplete)
              (let ((remaining (- deadline (now-ms))))
                (when (<= remaining 0) (raise 'timeout))
                (receive (after remaining (raise 'timeout))
                  (`#(tcp-data ,bv) (inbuf-append! buf bv) (loop))
                  (`#(tcp-eof) (raise 'closed))
                  (`#(tcp-error ,e) (raise 'closed))
                  (`#(node-stop) (raise 'stop))))
              d)))))

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
  (define (wire-name? x)
    (and (symbol? x)
         (let* ((t (symbol->string x)) (n (string-length t)))
           (let loop ((i 0))
             (or (fx= i n)
                 (and (not (char=? (string-ref t i) #\:))
                      (loop (fx+ i 1))))))
         (guard (e (#t #f))
           (sexpr->string-extended (list x))
           #t)))

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
  ;; The version goes LAST and is a plain decimal, so no separator question
  ;; arises: nonce is hex, name is a symbol, and only the version can end
  ;; the string. Both directions use this formula -- the welcome proof too,
  ;; so the dialer is checking a version-bound proof as well.
  (define (proof nonce name)
    (bytevector->hex
      (hmac-sha256 self-secret
        (string->utf8
          (string-append nonce ":" (symbol->string name) ":"
                         (number->string protocol-version))))))

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

  ;; -> #t if this conn was installed, #f if it lost the tie-break
  (define (install-peer! name c dialer)
    (let ((won?
           (atomically
             (let ((e (hashtable-ref peers name #f)))
               (if (and e (eq? (conn-state (vector-ref e 0)) 'open))
                   (if (name<? dialer (vector-ref e 2))
                       (begin                    ; new conn wins: evict old
                         (send (vector-ref e 1) (vector 'node-stop))
                         (hashtable-set! peers name (vector c self dialer))
                         'replaced)
                       #f)                       ; old conn wins
                   (begin
                     (hashtable-set! peers name (vector c self dialer))
                     #t))))))
      (when (eq? won? #t) (notify! name 'node-up))   ; a replacement is not a new up
      (and won? #t)))

  ;; idempotent: only removes the entry if it still belongs to this conn
  ;; The link to `name` is gone, so every monitor we HOST on its behalf
  ;; is now unreportable: tear them down (each demon-local demonitors the
  ;; local process and frees its callee-agents slot). Without this a peer
  ;; that connects, parks monitors, and drops -- over and over -- would
  ;; leak agents and eventually exhaust max-hosted-monitors.
  (define (drop-hosted-monitors! name)
    (let-values (((keys agents) (atomically (hashtable-entries callee-agents))))
      (vector-for-each
        (lambda (k agent) (when (eq? (car k) name) (send agent (vector 'demon-local))))
        keys agents)))

  (define (remove-peer! name c)
    (let ((mine?
           (atomically
             (let ((e (hashtable-ref peers name #f)))
               (and e (eq? (vector-ref e 0) c)
                    (begin (hashtable-delete! peers name) #t))))))
      (tcp-close! c)
      (when mine?
        (drop-hosted-monitors! name)       ; free monitors this peer parked here
        (fail-monitors-for! name)          ; DOWN(noconnection) for watchers
        (fail-pending-for! name)           ; nothing will answer these now
        (notify! name 'node-down))))

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
         (if (rcall-slot-take!)
             (spawn (lambda ()
                      (serve-rcall! peer reg ref m timeout)
                      (rcall-slot-free!)))
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
         (unless (atomically
                   (and (fx< (hashtable-size callee-agents) max-hosted-monitors)
                        (begin
                          (hashtable-set! callee-agents key
                            (spawn (lambda () (mon-agent peer key name))))
                          #t)))
           ;; at the hosting ceiling: refuse, tell the watcher at once
           (guard (e (#t (void)))
             (write-frame! c (list 'mdown mref 'overload))))))
      ;; (mdown ,mref ,reason) -> the watched process/link is gone; only
      ;; honor it from the node the monitor actually targets
      ((frame? d 'mdown 3)
       (let ((mref (cadr d)) (reason (caddr d)))
         (let ((entry (atomically (hashtable-ref rmonitors mref #f))))
           (when (and entry (eq? (vector-ref entry 1) peer))
             (fire-remote-down! mref reason)))))
      ;; (demon ,mref) -> stop a monitor we host for this peer
      ((frame? d 'demon 2)
       (let ((agent (atomically
                      (hashtable-ref callee-agents (cons peer (cadr d)) #f))))
         (when agent (send agent (vector 'demon-local)))))
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
            (write-frame! (vector-ref e 0) (list 'reply ref result)))))))

  (define (rcall-reason e)
    (if (and (vector? e) (> (vector-length e) 1) (symbol? (vector-ref e 1)))
        (vector-ref e 1)                        ; e.g. gen-server-error tag
        'unavailable))

  ;; Write one datum to a peer by name, if the link is live.
  ;; -> #t if there was a live link to write to.
  ;;
  ;; ITS THREE CALLERS, ENUMERATED FROM THE FILE AND NOT FROM MEMORY --
  ;; serve-rcall!'s fallback reply, mon-agent's noproc and mdown, and
  ;; remove-target-watch!'s demon -- AND NONE OF THEM READS THE ANSWER.
  ;; (An earlier version of this comment said rcall and monitor-remote
  ;; read it. They do not call this procedure at all. A claim about which
  ;; call sites exist is refutable by one grep, and must be written from
  ;; one.)
  ;;
  ;; What the callers can and cannot fall back on differs, and it is not
  ;; uniform the way that earlier comment implied:
  ;;   - serve-rcall!'s reply: the rcall waiting for it has its own
  ;;     timeout, so a lost frame costs that caller a timeout, not a hang;
  ;;   - mon-agent's mdown and remove-target-watch!'s demon: THERE IS NO
  ;;     TIMEOUT ON THE OTHER SIDE. A remote monitor waits until its
  ;;     target's node says something or the link drops. See mon-agent
  ;;     for what that means when a submission fails.
  (define (link-write peer datum)
    (let ((e (live-entry peer)))
      (and e (begin (write-frame! (vector-ref e 0) datum) #t))))

  ;; ---- cross-node process monitor ----------------------------------------

  ;; target side: one process per remote watch. It locally monitors the
  ;; registered process and reports its death back over the link. A
  ;; missing name is an immediate 'noproc. The reason is shipped as-is
  ;; when wire-safe, else degraded to 'exit -- a monitor must always
  ;; deliver a DOWN, never wedge on a non-serializable reason.
  ;; key is (peer . mref); dispatch registered us under it before we ran.
  ;; watcher is that same peer -- the authenticated far end -- and is the
  ;; only node we ever report this DOWN back to.
  ;;
  ;; IF THE mdown FRAME IS NEVER SUBMITTED -- the OOM domain, see
  ;; write-body! -- THIS AGENT HAS ALREADY DROPPED ITS STATE AND EXITS,
  ;; AND THE WATCHER WAITS FOREVER. There is no timeout on that side: a
  ;; remote monitor ends when its target's node says something or when
  ;; the link drops, and neither happens here. The same is true of the
  ;; demon frame in remove-target-watch!, which leaves this side's agent
  ;; parked until the target dies or the link goes. Both are named as OOM
  ;; residues rather than mechanised: a retry would need its own queue
  ;; and its own failure domain, on a path that only runs when the
  ;; process is already out of memory.
  (define (mon-agent watcher key name)
    (let ((mref (cdr key))
          (p (whereis name)))
      (if (not p)
          (begin
            (atomically (hashtable-delete! callee-agents key))
            (link-write watcher (list 'mdown mref 'noproc)))
          (let ((m (monitor p)))
            (receive
              (`#(DOWN ,@p ,reason)
                (atomically (hashtable-delete! callee-agents key))
                (guard (e (#t (link-write watcher (list 'mdown mref 'exit))))
                  (link-write watcher (list 'mdown mref reason))))
              (`#(demon-local)
                (demonitor m)
                (atomically (hashtable-delete! callee-agents key))))))))

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
          (link-write node (list 'demon mref)))))

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
  ;; Interrupts stay off across both, so no kill can land between them.
  ;; install-owner-agent! disables them again inside; the counter nests.
  ;; Its own rule -- publish the agent's pid before the agent can run --
  ;; still holds, because nothing runs until this region ends.
  (define (arm-rmonitor! mref node name)
    (atomically
      (hashtable-set! rmonitors mref (vector self node name))
      (install-owner-agent! self mref)))

  (define (install-owner-agent! caller mref)
    ;; Publish the pid before it can run and observe an already-dead caller;
    ;; otherwise that fast DOWN path could delete the not-yet-present entry
    ;; and the installer would then leave a dead agent rooted forever.
    (atomically
      (let ((agent (spawn (lambda () (owner-mon-agent caller mref)))))
        (hashtable-set! owner-agents mref agent))))

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

  (define (install-self-agent! caller mref name)
    ;; As with owner-agents, publish the pid before it can run. In
    ;; particular, a missing name takes the immediate noproc path above;
    ;; publishing afterwards would reinsert that already-dead agent.
    (atomically
      (let ((agent (spawn (lambda () (self-mon-agent caller mref name)))))
        (hashtable-set! caller-agents mref agent))))

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
      (let ((d (parse-frame buf max-frame)))
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
  (define (acceptor c)
    (let ((freed #f))
      (define (free!)
        (unless freed (set! freed #t) (preauth-slot-free!)))
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
          (write-frame! c (list 'challenge nonce protocol-version))
          (let ((d (read-frame c buf handshake-timeout-ms
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
            ;; The name grammar is applied here, with the nonce grammar
            ;; and for the same reason: it is this version's wire syntax,
            ;; so it belongs after the version comparison, never before
            ;; it. A peer stating a different version is answered about
            ;; the version.
            (unless (and (= (length d) 5)
                         (wire-name? (cadr d))
                         (<= (string-length (symbol->string (cadr d)))
                             max-name-length)
                         (not (eq? (cadr d) self-name))
                         (hex-nonce? (cadddr d))
                         (proof=? (caddr d) (proof nonce (cadr d))))
              (raise 'auth))
            (let ((peer (cadr d)) (nonce-b (cadddr d)))
              (write-frame! c (list 'welcome self-name (proof nonce-b self-name)))
              (free!)                           ; authenticated: no longer pre-auth
              (if (install-peer! peer c peer)   ; dialer = the remote side
                  (run-link c peer buf)
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
  (define (dial! peer host port)
    (guard (e ((eq? e 'stop) (raise 'stop))
              (#t #f))                          ; any failure: retry later
      (tcp-connect! host port self)
      (receive (after handshake-timeout-ms (raise 'timeout))
        (`#(tcp-connected ,c)
          (guard (e ((eq? e 'stop) (tcp-close! c) (raise 'stop))
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
                   (d (read-frame c buf handshake-timeout-ms
                                  handshake-max-frame)))
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
              (unless (and (= (length d) 3) (hex-nonce? (cadr d)))
                (raise 'auth))
              (let ((nonce-b (random-hex 16)))
                (write-frame! c
                  (list 'hello self-name (proof (cadr d) self-name)
                        nonce-b protocol-version))
                (let ((d2 (read-frame c buf handshake-timeout-ms
                                      handshake-max-frame)))
                  ;; welcome keeps its three-element shape: by now both
                  ;; ends have stated and agreed a version, so there is
                  ;; nothing left to state. Its proof still moves with
                  ;; the formula, so a peer that agreed to the version in
                  ;; words but computed the proof without it is refused
                  ;; here -- the binding is checked in both directions.
                  (unless (and (pair? d2) (eq? (car d2) 'welcome)
                               (= (length d2) 3)
                               (eq? (cadr d2) peer)   ; it must BE who we dialed
                               (proof=? (caddr d2) (proof nonce-b peer)))
                    (raise 'auth))
                  (if (install-peer! peer c self-name)
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
  (define (connector peer host port)
    (guard (e (#t (void)))                      ; 'stop lands here too
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
                         (let ((up (dial! peer host port)))
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
    (unless (wire-name? name)
      (assertion-violation 'node-start!
        "`:` separates the fields of the handshake proof; a name containing it makes that encoding ambiguous"
        name))
    (when (> (string-length (symbol->string name)) max-name-length)
      (assertion-violation 'node-start!
        "name is too long for the handshake frames it goes into"
        (list 'characters (string-length (symbol->string name))
              'limit max-name-length)))
    (when (let loop ((i 0))
            (cond ((= i (string-length (symbol->string name))) #f)
                  ((char=? (string-ref (symbol->string name) i) #\~) #t)
                  (else (loop (+ i 1)))))
      (assertion-violation 'node-start!
        (string-append
          "`~` separates the node name from the id body; a name"
          " containing it mis-routes every clustered id this node mints")
        name))
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
    (when (pair? rest)
      (let ((port (car rest))
            (host (if (pair? (cdr rest)) (cadr rest) "127.0.0.1")))
        (tcp-listen! host port 128
          (lambda (c)
            ;; libuv callback context: spawn + own + read-start only,
            ;; or -- over the pre-auth ceiling -- close and do none of it
            (if (preauth-slot-take!)
                (let ((pid (spawn (lambda () (acceptor c)))))
                  (conn-set-owner! c pid)
                  (tcp-read-start! c))
                (tcp-close! c))))))
    name)

  ;; Dial a peer (and keep dialing whenever the link is down).
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
    (unless (wire-name? peer)
      (assertion-violation 'node-connect!
        "peer must be a symbol without `:`" peer))
    ;; Same bound as node-start!, for the same reason and from the other
    ;; end: this name is what the welcome proof is verified against, so a
    ;; peer this node cannot name is a peer it can never accept.
    (when (> (string-length (symbol->string peer)) max-name-length)
      (assertion-violation 'node-connect!
        "peer name is too long for the handshake frames it goes into"
        (list 'characters (string-length (symbol->string peer))
              'limit max-name-length)))
    (when (eq? peer self-name)
      (assertion-violation 'node-connect! "cannot connect to self" peer))
    ;; Keyed by NAME, but the endpoint has to be part of the decision. A
    ;; node that moves to a new address keeps its name -- that is what a
    ;; rolling migration looks like -- and a connector keyed on name alone
    ;; was considered "already dialing" forever, so it went on retrying the
    ;; old host after the new one had been published. The link never came
    ;; back, and nothing said why.
    (let ((stale
            (atomically
              (let ((e (hashtable-ref connectors peer #f)))
                (cond
                  ;; already dialing this exact endpoint: leave it alone
                  ((and e (process-alive? (vector-ref e 0))
                        (string=? (vector-ref e 1) host)
                        (equal? (vector-ref e 2) port))
                   #f)
                  (else
                   (hashtable-set! connectors peer
                     (vector (spawn (lambda () (connector peer host port)))
                             host port))
                   ;; a live connector for a DIFFERENT endpoint must stop,
                   ;; or two of them dial the same name in parallel
                   (and e (process-alive? (vector-ref e 0))
                        (vector-ref e 0))))))))
      (when stale (kill stale 'endpoint-changed)))
    (void))

  ;; Stop dialing and drop the live link, if any.
  (define (node-disconnect! peer)
    (let ((p (atomically
               (let ((e (hashtable-ref connectors peer #f)))
                 (hashtable-delete! connectors peer)
                 (and e (vector-ref e 0))))))
      (when (and p (process-alive? p)) (send p (vector 'node-stop))))
    (let ((e (peer-entry peer)))
      (when e (send (vector-ref e 1) (vector 'node-stop))))
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
            ;; #t WHENEVER THERE WAS A LIVE LINK, whether or not the frame
            ;; reached the socket -- and that is not the lie it looks
            ;; like. This call is fire-and-forget by contract: delivery is
            ;; never confirmed, so every caller already has to tolerate
            ;; "#t and the message was lost". A packet dropped in the
            ;; network, or a peer that receives and dies before acting,
            ;; are indistinguishable from a frame that never left this
            ;; process. Reporting a refused submission as #f would be
            ;; narrowly more accurate and would break something real:
            ;; #f means NO LINK, and callers depend on that -- one of
            ;; them treats it as evidence the node is gone and removes it
            ;; from its scheduling set, which no node-up will undo while
            ;; the link is still up. A truer #t is worth less than a
            ;; theorem the callers rely on.
            (write-frame! (vector-ref e 0) (list 'send reg-name msg))
            #t))
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
                (unless (write-body! (vector-ref e 0) segs)
                  (when (atomically
                          (let ((v (hashtable-ref pending ref #f)))
                            (when v (hashtable-delete! pending ref))
                            (and v #t)))
                    (raise (vector 'rcall-error 'noconnection node))))
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
         (arm-rmonitor! mref node name)
         (install-self-agent! self mref name))
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
                (unless (write-body! (vector-ref e 0) segs)
                  (let ((entry (atomically
                                 (let ((x (hashtable-ref rmonitors mref #f)))
                                   (when x (hashtable-delete! rmonitors mref))
                                   x))))
                    (when entry
                      (stop-owner-agent! mref)
                      (send self (vector 'remote-down node name
                                         'noconnection))))))))
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
)
