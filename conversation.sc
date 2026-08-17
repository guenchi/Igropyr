#!chezscheme
;;; (igropyr conversation) -- process-per-conversation dialogues.
;;;
;;; The actor-model formulation of "web programming with continuations":
;;; a conversation is a green process that lives across several HTTP
;;; requests. Its local bindings ARE the conversation state -- including
;;; live resources a session store could never hold (an open database
;;; transaction, a file handle, a reservation with a TTL). Control flow
;;; is program text: "the user is at the confirm step" means the process
;;; is parked at the confirm step's suspend!, and a state that the code
;;; cannot reach cannot exist.
;;;
;;; The conversation process never touches the connection: pool workers
;;; stay the protocol adapters. A worker starts or resumes a conversation
;;; and parks until the flow yields a reply, then renders it. So the
;;; pool's guarantees keep applying: a runaway step leaves the waiting
;;; worker busy until the stuck-killer reaps it (and the failure hook,
;;; if configured, tells the client), while the conversation itself is
;;; bounded by its TTL.
;;;
;;;   (define-values (id token reply)
;;;     (conversation-start!
;;;       (lambda (req suspend! commit!)
;;;         (let ((tx (begin-tx!)))          ; live state, held across rounds
;;;           (guard (e (#t (rollback! tx) (raise e)))
;;;             (let ((req2 (suspend! first-reply)))   ; answer, park, resume
;;;               (commit! (lambda () (commit-tx! tx)))  ; commit THROUGH here
;;;               final-reply))))
;;;       req))
;;;
;;; A COMMIT CAN ALSO END IN "MAYBE", and the flow is the only code that
;;; can say so. A commit primitive is sometimes certain it succeeded,
;;; sometimes certain it never left, and sometimes neither -- a request
;;; that timed out, a connection reset after the write, a cancelled call,
;;; a reply that would not parse. For that third case the thunk raises
;;;
;;;   #(commit-uncertain reason)
;;;
;;; from inside commit!, and the conversation is recorded as having a
;;; commit that MAY have landed: a later resume answers 'unknown on its
;;; own evidence, where before it would have said 'gone and invited a
;;; retry. It is NOT frozen there, and that is the point of keeping this
;;; separate from a confirmed commit -- a settled? predicate answering #f
;;; is, against a mere "maybe", the fact that settles it, and the answer
;;; becomes 'gone. (Against a CONFIRMED commit the same #f is a
;;; contradiction and is refused; see resolve-unknown. That refusal needs
;;; a witness in hand for THAT call -- read from this node's table, or
;;; carried back by an owner that read its own -- and nothing caches one
;;; between calls, so a record pruned before it is read for a given call
;;; simply leaves that call without a witness, wherever it was going to
;;; come from.)
;;; Retrying the same
;;; idempotent commit and succeeding upgrades the mark to confirmed; it
;;; never falls back.
;;;
;;; THE ADAPTER OWES THIS FOR EVERY AMBIGUOUS FAILURE, and the obligation
;;; is easy to under-fill. Anything a commit can raise after the request
;;; has been dispatched AND that cannot authoritatively rule out its
;;; having taken effect -- the timeout, the reset, the cancellation, the
;;; unparseable response, an exception in the application's own
;;; post-dispatch code -- is a "maybe", and must arrive here as this tag.
;;; (A definite, authoritative rejection is not ambiguous, even though the
;;; request did leave.)
;;; What the library reads into every OTHER exception is that THIS attempt
;;; added no reason to think a commit landed -- so if nothing had been
;;; asserted before it, the conversation is a rollback, safe to retry.
;;; (Where an earlier attempt did assert something, the sticky mark keeps
;;; that answer; an untagged failure never erases it.) That reading is not
;;; a fact this library can establish about somebody else's driver; it is
;;; an
;;; ASSERTION THE THUNK MAKES by not raising the tag.
;;;
;;; Where it may be raised: inside the commit thunk is the only place with
;;; a promise attached. The flow-exit path recognises the tag as well, so a
;;; thunk that raises it elsewhere is usually still understood -- but only
;;; usually: the flow's own guard may catch it first, and a kill discards
;;; winders so nothing recognises anything. Raise it where the commit is.
;;;
;;; The reason never reaches the RECORD. The raise is passed on unchanged,
;;; so it travels wherever the flow lets it -- including out as the
;;; process's exit reason -- but the tombstone holds a symbol and must stay
;;; small, so nothing of the reason is kept there. A thunk that wants the
;;; detail on the record should log it before raising. (Of the wrappers this library
;;; builds for a caller, the only one that keeps it is the first round's
;;; #(conversation-uncertain id outcome reason), where it is nested; the
;;; raise itself of course goes on being visible to whatever observes the
;;; flow or the process.)
;;;
;;; TWO PHASES, WHEN THE ID HAS TO EXIST FIRST. conversation-start! mints
;;; the id inside the call that spawns the flow and does not hand it back
;;; until the first suspend! -- so between those two moments the flow has
;;; begun acting on the world and nothing outside can name it. Split the
;;; call and the id comes first:
;;;
;;;   (let ((h (conversation-prepare! flow req)))
;;;     (record-intent! (conversation-ref-id h))     ; durable, before any effect
;;;     (let-values (((token reply) (conversation-run! h)))
;;;       ...))
;;;
;;; prepare! is INERT: no process, no registration, no timer. (Not "pure":
;;; minting an id reads /dev/urandom, the node identity and the clock.)
;;; No LIFETIME clock -- the step watchdog, the park deadline, the linger
;;; -- starts before run! (the last two start later still, when the flow
;;; first parks and when it finishes), so a handle may
;;; sit for as long as the caller likes. A handle that is never run holds
;;; no process, no registration and no timer -- but it does hold the flow,
;;; the request and everything they close over, until it is abandoned or
;;; collected. Dropping it is enough; conversation-abandon! is for saying
;;; so on purpose, and both it and a completed run! release that payload
;;; while keeping the id. conversation-start! is exactly
;;; these two calls together.
;;;
;;; The handle may be handed to another PROCESS on this node -- the reply
;;; goes to whoever calls run! -- but never to another NODE: it holds
;;; closures, and the conversation is pinned to the node whose identity
;;; minted the id. run! refuses if that identity has changed since.
;;;
;;; RECOVERING A CONVERSATION WHOSE STARTER DIED. This is what the id
;;; bought, and it works for any death, including one that took the token
;;; with it:
;;;
;;;   - persist the id BEFORE run!;
;;;   - on recovery, (conversation-peek id):
;;;     'parked with a token -> ADOPT IT. That token is live; resume! with
;;;       it and this process becomes the one the conversation answers.
;;;       (peek hands back the reply the conversation is waiting to have
;;;       answered; resume! consumes the token and returns the NEXT round's
;;;       reply.) A conversation whose starter died is otherwise perfectly
;;;       healthy -- it is parked, holding its transaction, waiting.
;;;     'completed -> the flow returned; the reply is its final answer and
;;;       there is nothing to adopt. (peek never answers "running": a peek
;;;       that arrives mid-step is answered when that step parks.)
;;;     'gone -> it rolled back; nothing to adopt and safe to start afresh.
;;;     'settled -> it finished earlier and only the record is left.
;;;     'unknown or 'unreachable -> NOT AN ANSWER, and possibly transient:
;;;       registration happens inside the conversation's own process, so a
;;;       peek between spawn and registration answers 'unknown, and a
;;;       remote peek before the owner's router exists answers
;;;       'unreachable. Look again. Do NOT read either as licence to start
;;;       a second attempt -- that licence comes only from reconciling
;;;       downstream, or from the downstream operation being idempotent.
;;;     'no-answer-yet -> only from conversation-peek/timeout, and under
;;;       the same prohibition: it is not licence to start anything. What
;;;       differs is the remedy. 'unknown and 'unreachable say this
;;;       library cannot tell you what happened, so go and reconcile
;;;       against your own records. 'no-answer-yet says only that nothing
;;;       arrived within the limit -- typically a conversation still in a
;;;       step, which does not answer until it parks -- so ask again.
;;;       Reconciling on it risks reconciling against a conversation that
;;;       is alive and was about to answer.
;;;
;;;   ONE ADOPTER. Two recoverers both peek and both see the same token;
;;;   the first resume! wins and the other is 'stale (or replayed, if its
;;;   request-key matches). The library will not pick between them, so the
;;;   store the ids live in has to: a claim, a lease, something.
;;;
;;;   THE ID IS A BEARER CREDENTIAL, and this recipe deliberately puts it
;;;   in a database. Whoever can read it can peek -- which discloses the
;;;   last reply, whatever that contains -- and can present the live token
;;;   with a request of their own choosing, which ADVANCES the flow. The
;;;   entropy is not the exposure; distribution is. Treat a persisted id
;;;   as a session control credential: not in logs, not in URLs, not in a
;;;   table half the organisation can read.
;;;
;;;   AFTER A RESTART the process is gone and so is the conversation. A
;;;   local peek on an old id answers 'unknown; a remote one answers
;;;   'unreachable until the restarted owner has built its router.
;;;
;;;   A HOST THAT GIVES UP ON A REQUEST DOES NOT END THE CONVERSATION,
;;;   and that is the semantics rather than a gap. A worker pool that
;;;   kills a handler it has declared stuck, or abandons a task after its
;;;   retries, takes down the process that CALLED run! -- the
;;;   conversation is spawned unlinked, so it keeps running, keeps
;;;   holding whatever it holds, and may still commit.
;;;
;;;   Making the host reap it would produce the one outcome this library
;;;   exists to prevent: a transaction that MAY ALREADY HAVE COMMITTED,
;;;   destroyed on the way out and reported as though it never happened.
;;;   The kill would land at an arbitrary point, which is exactly the
;;;   point where nobody can say which side of the commit it fell on.
;;;
;;;   What bounds it instead: the conversation's own ttl ends it whether
;;;   or not anyone is still asking, so nothing runs forever on the
;;;   strength of a caller that left; on-killed runs the caller's own
;;;   compensation when that happens, with committed? telling it which
;;;   way to go. And the case that looks worst -- the client got a bare
;;;   500 and holds no id -- is what prepare! is for: take the id before
;;;   anything can have an effect, persist it, and the conversation is
;;;   reachable by id no matter what became of the process that started
;;;   it.
;;;   That wait is not shortened by the router being absent. The
;;;   forwarding path does watch the owner's router, but only so the
;;;   watch can be cleaned up after a kill -- what ENDS the wait is the
;;;   reply, the link going down, or the forwarding TTL. An owner that is
;;;   up but has no router yet is still reachable, and saying otherwise
;;;   on its behalf would be a guess about a node that is plainly there.
;;;
;;; A FLOW COMMITS THROUGH commit!, and the library learns what the flow
;;; is able to say about the transaction, at the moment the flow can say
;;; it. Everything else it could observe
;;; -- the flow returned, something was raised -- fails to separate a flow
;;; that rolled back from one that committed and then tripped on the way
;;; out, and those two get opposite answers ('gone, which invites a retry,
;;; versus 'unknown, which does not). ONE CONVERSATION IS ONE LOGICAL
;;; TRANSACTION: commit! runs the conversation's last state change, and no
;;; new transaction is opened after it. What the flow asserted is STICKY --
;;; once a conversation has claimed a commit, confirmed or merely
;;; possible, nothing that happens to it afterwards makes this library
;;; call it a rollback of its own accord, in that round or any later one.
;;; (A settled? predicate can still turn a MERELY POSSIBLE one into 'gone;
;;; that is the point of keeping the two apart, and it is the caller's
;;; evidence doing it, not this library's.)
;;;
;;;   (conversation-resume! id token req)
;;;     ; -> (values reply next-token), or 'stale / 'gone / 'unreachable
;;;
;;; THE TOKEN NAMES THE REPLY BEING ANSWERED. A conversation hands one out
;;; with every reply, and the next request must present it; it is consumed
;;; the moment a request is accepted. Send it to the client alongside the
;;; reply (a field, a hidden input, a query parameter) and take it back with
;;; the next request -- it is an opaque hex STRING and crosses links, JSON
;;; and a query parameter unchanged. Compared as a string: a number, or a
;;; token that has been through a decoder that changed its type, is
;;; 'stale.
;;;
;;; Without it the only thing distinguishing "the answer to what I just
;;; said" from "a duplicate of what you said before" is arrival order, and
;;; arrival order is not causality. A double click, a client retry or a
;;; second front end sends two requests against the SAME reply; if the
;;; duplicate is delayed -- a slower path, a forwarding hop, a busy
;;; scheduler -- it arrives after the flow has moved on and is taken as the
;;; next step. The flow then advances on input written before the reply it
;;; claims to answer: a confirmation skipped, or one stage's payload applied
;;; to the next. With the token the duplicate is refused however it is
;;; scheduled, and a genuine answer is accepted however late it arrives.
;;;
;;; A REPEAT IS ANSWERED, NOT REFUSED. Presenting the token that was just
;;; spent hands back the reply it produced, together with the token that
;;; came with it -- exactly what the original caller received. So a double
;;; click, a client retry or a lost response all end the same way: the step
;;; ran once, and everyone who asked gets the answer to what they asked.
;;; This is what an idempotency key buys in a payment API, and it is the
;;; half that refusing cannot give: a caller whose reply was lost would
;;; otherwise be unable to either advance or learn the outcome.
;;;
;;; Only the LAST step is replayable -- one reply is retained, not a
;;; history. A token older than that is 'stale: its answer is long
;;; superseded, and keeping every step's reply would be unbounded memory
;;; for a case nobody can act on anyway.
;;;
;;; 'stale: the token belongs to no step this conversation can still answer.
;;; The request was NOT applied and will not be -- a fact about this
;;; conversation, not a guess. It says nothing about whether the request it
;;; duplicates succeeded. Read the current state; do not resubmit (there is
;;; no valid token to resubmit with, which is the point).
;;;
;;; AFTER THE FLOW RETURNS the conversation LINGERS for one more TTL, still
;;; reachable, still able to replay that final reply. Exiting at once is
;;; what made a lost final reply dangerous: the client retries, the process
;;; is gone, and the resume answers 'gone -- which this library documents
;;; as "the transaction rolled back". For a flow that had just COMMITTED
;;; that is false, and a client acting on it performs the whole thing
;;; again. The cost is one parked process per completed conversation until
;;; the window closes. Past it the record still says what happened
;;; ('settled), but the ANSWER is no longer retained -- so size the TTL to
;;; cover the retry window your clients actually use.
;;;
;;; Fault semantics (the transaction-ring contract):
;;;   - 'gone IS EVIDENCE, NEVER AN ABSENCE. It is answered only where
;;;     this node holds a record saying the conversation ROLLED BACK: the
;;;     flow raised and its winders ran, or its park deadline passed and
;;;     the raise that carries went uncaught out of the flow -- and in
;;;     either case nothing had asserted a commit: not one that returned,
;;;     and not one reported as a maybe. For a flow
;;;     holding a database transaction that is the rollback guarantee --
;;;     dead process = dropped connection = the database rolled back on
;;;     its own -- and it is the only answer that carries it. Retry only
;;;     on 'gone.
;;;   - COMMITTED, THEN FAILED, IS 'unknown. An exception can leave the
;;;     flow after its commit! has returned: an after-thunk that raises
;;;     while the flow is unwinding, a guard that re-raises, anything on
;;;     the way out. The winders ran, so nothing is still held -- but the
;;;     transaction is permanent, so this is not a rollback and must never
;;;     be answered 'gone. Without commit! the library could not tell this
;;;     apart from a flow that failed before committing: both arrive as one
;;;     raise through one set of winders, and calling both 'gone is how a
;;;     committed transfer gets retried into a double spend.
;;;     THE SAME ANSWER HOLDS HOWEVER LATE THE FAILURE COMES. A flow that
;;;     commits, parks, is resumed and only then raises has still
;;;     committed; the conversation was one transaction and it is
;;;     permanent, so that raise is 'unknown too. The mark commit! sets is
;;;     never cleared, which is what makes the answer independent of how
;;;     many rounds sit between the commit and the failure.
;;;   - EVERY OTHER WAY OF DYING IS 'unknown. A kill from outside, a link
;;;     cascade, a step the watchdog stopped, a record that aged
;;;     out, an id from an earlier incarnation: none of them say anything
;;;     about the transaction, because the commit happens INSIDE the flow
;;;     and a stopped step leaves no record of where it got to. "No process and no
;;;     record" used to be reported as 'gone, which derives a positive
;;;     claim from missing evidence -- and the death paths that write no
;;;     record are an open set nobody can enumerate, so the claim was
;;;     wrong an unbounded number of ways. On 'unknown the outcome is not
;;;     knowable from here: reconcile, do not resubmit.
;;;   - 'unreachable is NOT that guarantee either. A resume forwarded to another
;;;     node answers it when the link went down or the forwarding wait
;;;     expired: both prove that WE could not reach the owner, neither
;;;     proves the owner died. Under a partition the conversation keeps
;;;     running and may still commit. Treating it as 'gone and retrying is
;;;     how a flow's effects get applied twice -- exactly what the ring
;;;     exists to prevent. Retry only on 'gone; on 'unreachable the
;;;     outcome is unknown, so reconcile rather than resubmit.
;;;   - TTL EXPIRY HAS TWO PATHS, and only one of them raises -- which is
;;;     also why they answer differently.
;;;     A conversation that sat PARKED too long is raised at:
;;;     'conversation-expired reaches the flow, a guard runs, and it can
;;;     roll back explicitly (re-raise, or don't catch, so the process
;;;     exits). An expiry that leaves the flow that way ran its winders,
;;;     so it is recorded as rolled back and answers 'gone -- UNLESS a
;;;     commit had already been asserted through commit!, confirmed or
;;;     merely reported as a maybe, in which case the winders running does
;;;     not undo it and it answers 'unknown. A
;;;     flow that asserts a commit -- either kind -- and then parks until
;;;     its deadline is the case that tells those two apart, and it holds
;;;     however many rounds later the expiry comes: the mark is never
;;;     cleared.
;;;     A STEP that overruns is KILLED -- that is what the watchdog is
;;;     for, and a step stuck in a loop or a foreign call cannot be raised
;;;     at. @kill discards dynamic-wind winders, so the flow's guard does
;;;     NOT run and nothing it held was given back by the flow itself;
;;;     that is recorded as a kill and answers 'unknown, because a step
;;;     stopped in flight may have committed already. A pooled database
;;;     connection is still safe: the pool
;;;     monitors its borrower and rebuilds the connection when it dies,
;;;     which drops the transaction. Anything held IN PROCESS is not --
;;;     a reservation, a file handle, an in-memory hold. Pass an
;;;     on-killed procedure (conversation-start!'s fifth argument) to
;;;     release those; it runs after the kill, in a supervised process of
;;;     its own -- bounded by the conversation's ttl, and its outcome
;;;     counted in conversation-hook-stats, so a hook that raises or hangs
;;;     is visible instead of silent. That bound covers anything the
;;;     scheduler can preempt; a hook that blocks the OS thread (a
;;;     blocking foreign call) is beyond it. It runs outside the dead
;;;     process,
;;;     and is called with one argument: whether a commit had been
;;;     ASSERTED when the kill landed -- either one that returned, or one
;;;     the flow reported might have landed. Both forbid compensating. Release what is held in process
;;;     unconditionally; undo the transaction only under (not
;;;     committed?), because undoing one that succeeded is the same
;;;     damage 'gone would have done, arriving by another route.
;;;     EVERY ACTION IN THE HOOK MUST BE IDEMPOTENT -- the release as
;;;     much as the undo. "The winders did not run" is true of the kill
;;;     itself and not of every conversation that reaches this hook: one
;;;     whose exception had already finished unwinding, but whose outcome
;;;     was not yet published when the kill landed, arrives here having
;;;     released once already. The hook then releases a second time.
;;;     THAT ARGUMENT CAN BE A FALSE NEGATIVE, and the window is not
;;;     always small. A kill landing between the commit thunk's return and
;;;     the mark being set passes #f for a transaction that did happen --
;;;     that part is one instant. But a driver that has already sent the
;;;     request and is waiting to find out what happened has not raised
;;;     anything yet, so a kill anywhere in that wait -- which can be the
;;;     whole of a timeout -- also passes #f, for a transaction that may
;;;     well have taken effect. The window cannot be
;;;     closed from outside the dead process, so an undo that would be
;;;     destructive if wrong must be idempotent, or check the
;;;     authoritative store itself, rather than trust this flag alone.
;;;     #t is never wrong about there having been an assertion; only
;;;     #f carries doubt about the timing. What #t does NOT promise is
;;;     that the transaction is confirmed -- an uncertain commit reaches
;;;     the hook as #t too, because the safe action is the same.
;;;   - a flow that RAISES before its first suspend! with NO COMMIT
;;;     ASSERTED -- no commit! that returned, and none that reported a
;;;     maybe -- makes
;;;     conversation-start! (or conversation-run!) raise
;;;     #(conversation-failed id reason) in the caller -- with the id, so
;;;     that even the retryable failure names what it was. What that raise ASSERTS is narrow and does not depend on
;;;     who is listening: nothing had been answered yet, and a raise that
;;;     left the flow ran its winders, so the record says rolled back --
;;;     the work is undone and repeating it is safe.
;;;   - ...and only then. A first step that may have got past its COMMIT --
;;;     killed for overrunning, killed from outside, taken down by a link,
;;;     raising after its commit! had returned, or reporting through the
;;;     commit-uncertain tag that it may have landed -- would be repeated by
;;;     re-running an unanswered task. That
;;;     raises #(conversation-uncertain id outcome reason) instead, which
;;;     is NOT retryable: the id is there so the caller can reconcile.
;;;
;;;   - CATCH THE UNCERTAIN ONE. Both of these are raised in the CALLER,
;;;     and WHO RETRIES DEPENDS ON HOW THE HOST IS ASSEMBLED, which is not
;;;     this library's business and must not be assumed by it. Left to
;;;     propagate under this framework's worker pool, the worker crashes
;;;     and the pool re-runs the unanswered task. Under an outermost
;;;     error-handler middleware -- the recommended assembly -- the raise
;;;     is caught there instead, the client gets a 500, and the retry is
;;;     the client's. Both are correct for #(conversation-failed ...),
;;;     because the fact it asserts is "safe to repeat" rather than "the
;;;     pool will repeat it". (This paragraph used to say the pool retry
;;;     WAS the design; with an error-handler installed that retry never
;;;     happens, so the two documents contradicted each other while both
;;;     were being followed. See (igropyr middleware)'s error-handler.)
;;;
;;;     For #(conversation-uncertain ...) neither assembly is acceptable,
;;;     and that is the point of this whole entry. "Not retryable" is a
;;;     property of the fact, not a protection: an uncertain raise that is
;;;     left to propagate is indistinguishable, to a pool or to a client,
;;;     from an ordinary crash -- so the one signal that exists to say "do
;;;     not run this again" is handed to whatever decides whether to run it
;;;     again, saying nothing.
;;;
;;;     So an uncertain first step must be caught where it is raised and
;;;     turned into an ANSWER. Answering is what takes the task out of the
;;;     re-run set; the id is what makes the answer actionable:
;;;
;;;       (guard (e ((and (vector? e)
;;;                       (eq? (vector-ref e 0) 'conversation-uncertain))
;;;                  ;; answered, so nothing re-runs it; the id goes to the
;;;                  ;; client (or an operator) to reconcile against
;;;                  (set-status! res 409)
;;;                  (send-json! res `((fault . "uncertain")
;;;                                    (conv . ,(vector-ref e 1))
;;;                                    (resubmit . #f)))))
;;;         (conversation-start! flow req))
;;;
;;;     MATCH THESE BY THEIR TAG, NEVER BY LENGTH OR EXACT SHAPE. The
;;;     guard above tests (vector-ref e 0) and nothing else, and that is
;;;     the contract: the tag identifies the raise, the arity does not and
;;;     is not promised. It has already changed once -- conversation-failed
;;;     carried two elements and now carries three, because a retryable
;;;     failure that cannot name what failed is of little use -- and a
;;;     consumer that had written (= (vector-length e) 2) stopped matching
;;;     the moment it did. That failure is silent and it is the worst
;;;     shape: the clause simply never fires, so the ERROR path quietly
;;;     stops being handled while every ordinary request still works.
;;;
;;;     #(conversation-failed ...) is deliberately NOT caught there. It is
;;;     the one raise whose work is safe to repeat, so it is left to the
;;;     host's ordinary failure handling -- whatever that is in this
;;;     assembly -- rather than being converted into an answer here.
;;;
;;; Clustered: a conversation is PINNED to the node that created it --
;;; its continuation and open transaction cannot migrate. The id carries
;;; that owner ("<node>~<hex>"), so conversation-resume! on ANY node
;;; reaches the right one: a resume that lands elsewhere (round-robin LB,
;;; a reconnect landing on a different node) is forwarded to the owner
;;; over the node mesh, concurrently -- one process per forwarded resume,
;;; never a serial router. A forward that cannot reach the owner node
;;; yields 'unreachable, not 'gone: a broken link says nothing about
;;; whether the process behind it died. Forwarded req and reply cross a link, so
;;; they must be extended-wire-safe (as with rsend / rcall). With one
;;; node (node-start! never called) the id has no prefix and every
;;; resume stays local -- no dependency on the distribution layer at
;;; run time.

(library (igropyr conversation)
  (export conversation-start! conversation-resume! conversation-peek
          conversation-peek/timeout
          conversation-prepare! conversation-run! conversation-abandon!
          conversation-ref-id
          conversation-set-limits! conversation-hook-stats
          ;; re-exported from (igropyr conversation-status), so that
          ;; importing this library still gives the whole vocabulary
          conversation-gone? conversation-stale? conversation-done?
          conversation-settled? conversation-unknown?
          conversation-unreachable? conversation-no-answer-yet?)
  (import (chezscheme) (igropyr actor)
          (igropyr conversation-status)
          (only (igropyr libuv) now-ms)
          (only (igropyr node)
                node-self rsend node-peers monitor-remote demonitor-remote))

  (define default-ttl-ms 300000)      ; 5 minutes

  ;; CSPRNG conversation ids: resuming is authorization, so ids must be
  ;; unguessable (same reasoning as session sids)
  ;; A SHORT READ FAILS. get-bytevector-n! can return fewer bytes than
  ;; asked for, and the rest of a make-bytevector is zeros: ignoring the
  ;; count still produced a full-length hex string, carrying however much
  ;; less entropy the read happened to deliver. A secret that looks the
  ;; right length and is not is worse than no secret at all, so this
  ;; raises rather than returning something weaker than it appears.
  (define (conv-hex/n! n)
    (let ((bv (make-bytevector n)))
      (call-with-port (open-file-input-port "/dev/urandom")
        (lambda (p)
          (let ((got (get-bytevector-n! p bv 0 n)))
            (unless (eqv? got n)
              (assertion-violation 'conversation
                "short read from /dev/urandom" got)))))
      (apply string-append
        (map (lambda (i)
               (let ((h (number->string (bytevector-u8-ref bv i) 16)))
                 (if (= (string-length h) 1) (string-append "0" h) h)))
             (iota n)))))

  (define (conv-hex!) (conv-hex/n! 16))

  ;; Step tokens come from the same source as ids, and for the same reason.
  ;;
  ;; A counter would have been enough to make arrival order stop being
  ;; load-bearing -- that is all causality needs. But a token is presented
  ;; as authorization to take a step, and a consecutive integer is one
  ;; anybody holding the id can produce without ever having read a reply.
  ;; The id is the capability, so this is not a new way in; it is the
  ;; difference between "a wrong guess is impossible" and "a wrong guess is
  ;; off by one". In a flow that moves money, that difference is the whole
  ;; margin.
  ;;
  ;; Eight bytes, not sixteen: a token is scoped to one conversation and
  ;; lives for one step, so it needs to be unguessable, not globally
  ;; unique. It stays a string, which crosses a node link, JSON and a query
  ;; parameter unchanged.
  (define (conv-token!) (conv-hex/n! 8))

  ;; ---- the step protocol: state, rules, control ---------------------------
  ;;
  ;; These three are kept apart on purpose. The step protocol was written
  ;; four times over -- tokens, replay, request keys, the completion linger
  ;; -- and every one of those was a MODIFICATION of a single receive loop
  ;; that already held seven mutable variables, with the same classification
  ;; written out twice (once for a parked conversation, once for a completed
  ;; one) and drifting between them. Adding a rule should be adding a rule.
  ;;
  ;;   step-state -- what a conversation is waiting for and what it last did
  ;;   classify   -- the rules, in one place, valid in every phase
  ;;   serve-steps! -- the control structure, which knows no rules at all
  ;;
  ;; phase is the single source of truth for "is a step running", and
  ;; set-phase! is the only writer of the boxes the watchdog reads. That
  ;; ordering was a defect once: publishing "running" before publishing WHEN
  ;; it started let the watchdog kill a step against the previous step's
  ;; clock. Writing it in one place is why that cannot come back.

  (define-record-type (step-state make-step-state step-state?)
    (fields (mutable phase)        ; 'running | 'parked | 'completed
            (mutable awaiting)     ; token that advances from here, or #f
            (mutable consumed)     ; token most recently accepted
            (mutable key)          ; key of the request that was accepted
            (mutable reply)        ; what accepting it produced
            (mutable steps)        ; completed suspends, for the watchdog
            running-box run-start-box watch-box))

  ;; ENTERING 'running starts the clock; re-marking a phase that is already
  ;; running does not. Computing a request key marks and restores the phase
  ;; around itself, and inside an accepted step the phase it restores to IS
  ;; 'running -- so a restore that restamped would refund whatever the key
  ;; function had just spent, and a slow one would quietly hand the step a
  ;; second full allowance of the very limit the watchdog is there to keep.
  (define (set-phase! st phase)
    (let ((entering (and (eq? phase 'running)
                         (not (eq? (step-state-phase st) 'running)))))
      (step-state-phase-set! st phase)
      (when entering
        ;; TIMESTAMP BEFORE THE FLAG. The watchdog reads the flag and then
        ;; the timestamp, so publishing them the other way round leaves a
        ;; window in which it sees a step running against the PREVIOUS
        ;; step's start.
        (set-box! (step-state-run-start-box st) (now-ms)))
      (set-box! (step-state-running-box st) (eq? phase 'running))
      ;; ...AND THE FLAGS BEFORE THE WAKE-UP, for the same reason one line
      ;; up. Waking the watchdog first lets it read the flag before this
      ;; process has set it, find nothing running, and go back to waiting
      ;; -- and no second notification is ever sent for that step, so the
      ;; bound falls back to the poll floor.
      ;;
      ;; HOW NARROW THAT IS, stated because it was once overstated here:
      ;; send enqueues without yielding, so the watchdog cannot run
      ;; between these forms unless this process is preempted inside the
      ;; two set-box! calls or the now-ms call. Reverting the order alone
      ;; measures the same 22-26ms as this one over a thousand trials.
      ;; The 53ms belongs to LOSING the notification, which is a different
      ;; mutation and is what the latency test actually pins.
      (when entering
        (let ((w (unbox (step-state-watch-box st))))
          (when w (send w (vector 'conv-step-started)))))))

  (define (token=? a b)
    (and a b (string? a) (string? b) (string=? a b)))

  ;; The next token, different from every token this conversation has
  ;; issued -- BY CONSTRUCTION, because it names the step it belongs to.
  ;;
  ;; Excluding only the previous one left the invariant probabilistic where
  ;; it mattered: a token repeating one from two steps back becomes the
  ;; live `awaiting`, and a delayed copy of the request that carried it the
  ;; first time then classifies as 'advance -- before the request key is
  ;; ever computed. An old payload is applied to a later step and its
  ;; sender receives that step's reply. Sixty-four random bits make it
  ;; unlikely; the list makes it impossible, and the list is one entry per
  ;; suspend of one conversation.
  ;; Keeping every issued token in a list made uniqueness a property of
  ;; MEMORY: unbounded for a long dialogue, and quadratic because each new
  ;; token scanned the whole history. A step number in the token makes it a
  ;; property of the token itself -- two steps cannot collide however many
  ;; there have been -- and costs one small string. The random half is
  ;; unchanged and is still what makes a token unguessable; the step number
  ;; is not a secret and was never doing that work.
  (define (fresh-token step)
    (string-append (ms->b36 step) "-" (conv-token!)))

  ;; THE RULES. key-of is a thunk, so an invented token costs no application
  ;; code at all: only a request that already matched the spent token is
  ;; ever reduced to a key.
  ;;
  ;;   'advance -- the answer to the reply this conversation is waiting on
  ;;   'replay  -- a repeat of the request that was already accepted: same
  ;;               token AND same request. Not the token alone: two callers
  ;;               can hold one token and ask different things, and handing
  ;;               the second the first one's result told a caller who asked
  ;;               to cancel that it was confirmed.
  ;;   'stale   -- anything else. Not applied, and will not be.
  ;;
  ;; A completed conversation has no `awaiting`, so 'advance simply cannot
  ;; fire there -- the same rules serve both phases without a special case,
  ;; which is what stops the two copies drifting apart again.
  (define (classify st token key-of)
    (cond
      ((token=? token (step-state-awaiting st)) 'advance)
      ((and (token=? token (step-state-consumed st))
            ;; both sides are (key) if the key was computed, #f if the key
            ;; function raised. A failure equals nothing -- not even
            ;; another failure, or two requests nobody could key would
            ;; replay each other's answers.
            (let ((now (key-of)) (then (step-state-key st)))
              (and (pair? now) (pair? then)
                   (equal? (car now) (car then)))))
       'replay)
      (else 'stale)))

  ;; THE CONTROL STRUCTURE. It knows no rules: it receives, asks classify
  ;; what a request is, and acts. Both phases use it -- a parked
  ;; conversation waiting for its next step, and a completed one still able
  ;; to replay its final answer -- because the only thing that differs is
  ;; what 'advance means and when the deadline falls.
  ;;
  ;; on-advance is called with (from ref token request) and does not return:
  ;; it resumes the flow. on-expire is called when the deadline passes.
  ;;
  ;; ONE deadline for the whole wait, not one per message. Rearming it per
  ;; message let a caller repeating a spent or invented token keep a
  ;; conversation -- and its open transaction -- parked indefinitely, which
  ;; the watchdog will not touch because idling between rounds is not what
  ;; it bounds.
  (define (serve-steps! st deadline safe-key on-advance on-expire)
    (let loop ()
      (let ((left (- deadline (now-ms))))
        (if (<= left 0)
            (on-expire)
            (receive (after left (on-expire))
              ;; READ-ONLY, in every phase. This is the only way a caller
              ;; who was told 'unreachable can ever settle the question: a
              ;; link that came back is not permission to resubmit, and
              ;; resubmitting is how a flow's effects get applied twice.
              (`#(conv-peek ,from ,ref2)
                (send from (vector 'conv-peeked ref2
                                   (step-state-phase st)
                                   (step-state-awaiting st)
                                   (step-state-reply st)))
                (loop))
              (`#(conv-step ,from ,ref2 ,token ,r)
                ;; THE DEADLINE IS CHECKED AGAIN HERE. A receive answers a
                ;; matching message that is already in the mailbox before
                ;; it consults its timer, so a step that arrived after the
                ;; deadline -- while this process was waiting its turn to
                ;; run -- was advanced instead of expiring. The park TTL is
                ;; the caller's statement of how long this dialogue may
                ;; wait, and a message cannot be inside a window it arrived
                ;; after just because nobody had looked yet.
                (if (>= (now-ms) deadline)
                    ;; ANSWER IT FIRST. Expiring without a word leaves the
                    ;; sender in local-resume's receive, which waits for a
                    ;; reply or a DOWN and has neither deadline nor default
                    ;; -- so a flow whose guard swallows 'conversation-expired
                    ;; and parks again holds that caller for as long as it
                    ;; cares to. 'stale is also the true answer whatever the
                    ;; flow does next: this request was not applied and will
                    ;; not be.
                    ;;
                    ;; NOT COVERED BY A TEST, and for the same reason the
                    ;; re-check itself is not: reaching it needs a step to
                    ;; arrive after the deadline but before the conversation
                    ;; is next scheduled. A test that merely waits past the
                    ;; deadline finds a conversation that has already expired
                    ;; on its own, and exercises the ordinary stale path.
                    (begin
                      ;; ...but only while a reply is what the sender would
                      ;; otherwise never get. In the LINGER the expiry just
                      ;; returns, the process exits, and the caller's monitor
                      ;; turns that into 'settled off the tombstone --
                      ;; which carries the one thing a client that lost its
                      ;; final reply needs to know: the flow RAN TO
                      ;; COMPLETION -- it left through its own end and not
                      ;; through its winders -- so no token continues it
                      ;; and nothing here will re-run it. That is a fact
                      ;; about the CONTROL FLOW, not about what the flow
                      ;; did: one that never calls commit! settles, and so
                      ;; does one that caught its own error and rolled its
                      ;; transaction back deliberately before returning.
                      ;; What settled rules out is this library answering
                      ;; 'gone -- not a rollback.
                      ;; Answering 'stale first is true but poorer, and it
                      ;; wins the race.
                      (unless (eq? (step-state-phase st) 'completed)
                        (send from (vector 'conv-reply ref2 #f 'stale)))
                      (on-expire))
                (case (classify st token (lambda () (safe-key r)))
                  ((advance) (on-advance from ref2 token r))
                  ((replay)
                   ;; the token that came with the reply, so the caller
                   ;; continues exactly as the original one would have
                   (send from (vector 'conv-reply ref2 (step-state-reply st)
                                      (if (eq? (step-state-phase st) 'completed)
                                          'done
                                          (step-state-awaiting st))))
                   (loop))
                  (else
                   (send from (vector 'conv-reply ref2 #f 'stale))
                   (loop))))))))))

  ;; ---- how a conversation ended: the tombstone ---------------------------
  ;;
  ;; A tombstone is an id and an OUTCOME, and every answer about a
  ;; conversation with no process behind it is read off one. There are
  ;; five, and the whole design of this file rests on keeping them apart:
  ;;
  ;;   #t             the flow returned: it SETTLED. -> 'settled
  ;;   'rolled-back   the flow raised (or its park deadline raised into it
  ;;                  and nothing caught it) and left through its winders
  ;;                  with NOTHING HAVING ASSERTED A COMMIT -- neither one
  ;;                  that returned nor one reported as a maybe -- so
  ;;                  whatever it held was given back and nothing was made
  ;;                  permanent. -> 'gone
  ;;   'committed-then-failed
  ;;                  the same exit, but ANY TIME AFTER commit! returned --
  ;;                  in that round or a later one: the winders ran, and
  ;;                  the transaction stands anyway. -> 'unknown
  ;;   'commit-uncertain-then-failed
  ;;                  the same exit, after the flow reported that its
  ;;                  commit MAY have taken effect (#(commit-uncertain
  ;;                  ...)) and never afterwards confirmed it. -> 'unknown
  ;;   'killed        it was stopped in flight: the winders did not run and
  ;;                  the flow may have committed first. -> 'unknown
  ;;
  ;; ...and NO RECORD is 'unknown too, which is the point. 'gone is the
  ;; rollback guarantee a caller retries on, so ON THIS LIBRARY'S OWN
  ;; EVIDENCE it has to come from a record that SAYS rolled back -- never
  ;; from the absence of one, and
  ;; never from a record that merely says the flow left through its
  ;; winders. The absence reading was the first half of that defect: a
  ;; process killed from outside, a link cascade, a VM going down all
  ;; leave no record, and every one of them was answered 'gone. Those
  ;; paths are an open set; the rule that
  ;; only positive evidence answers 'gone covers all of them at once,
  ;; including the ones nobody has thought of. The second half was reading
  ;; every exception out of the flow as a rollback, which made 'gone a
  ;; retry invitation for a flow that had committed; commit! is what
  ;; splits that record apart, into one per thing a flow can have
  ;; asserted about its commit.
  ;;
  ;; The linger covers the window just after completion, but it holds a
  ;; whole process and the retained reply, so it cannot be long. A record
  ;; is two words, so it can be: the answer is no longer available, but
  ;; what a reconciling caller actually needs is which of these happened,
  ;; and for a conversation that finished, "this settled" is the opposite
  ;; of what 'gone would have said.
  ;;
  ;; BOUNDED, by age and by count, because an unbounded record of every
  ;; conversation that ever finished is a leak with a long fuse. Past
  ;; either bound an entry is dropped and the conversation becomes
  ;; 'unknown -- that is the honest limit of this mechanism, and the
  ;; reason both bounds are settable. What it can no longer do is become
  ;; 'gone by being forgotten.
  (define tombstone-max 10000)
  (define tombstone-ttl-ms 3600000)    ; one hour

  (define tombstones (make-hashtable string-hash string=?))
  (define tomb-front '())              ; oldest first
  (define tomb-back '())               ; newest, reversed
  (define tomb-n 0)

  ;; HOW FAR BACK THIS NODE REMEMBERS.
  ;;
  ;; "No process and no record" was once read as "it never completed", and
  ;; that reading needs a premise nobody was checking: WOULD I STILL HAVE
  ;; THE RECORD? Past the age limit, past the count limit, or on the other
  ;; side of a restart, the answer is no -- and the same absence then meant
  ;; nothing at all while still being reported as 'gone.
  ;;
  ;; NOTHING IS DECIDED FROM THIS ANY MORE, and that is deliberate. The
  ;; horizon made the absence reading correct where it applied, but it
  ;; could only ever cover the absences it knew the reason for: a record
  ;; that aged out, one pushed out by newer ones, one from before a
  ;; restart. It cannot cover a conversation killed from outside or taken
  ;; down by a link, which leave a young id, an empty table, and no reason
  ;; at all. 'gone now comes from a 'rolled-back record -- written only
  ;; where nothing had asserted a commit at all, not even a maybe -- and,
  ;; out of what this library itself can see, from nothing else, which
  ;; subsumes every case this bounded the damage of.
  ;;
  ;; It is kept because the table still moves it and it costs one
  ;; comparison per eviction: how far back this node can speak is a true
  ;; and cheap thing to know, and an answer derived from an absence would
  ;; need it again.
  ;;
  ;; Initialised to THIS PROCESS'S START, so every conversation older than
  ;; this incarnation is outside what it can speak for. That is the restart
  ;; case, and it costs nothing.
  (define tomb-horizon (now-ms))
  (define (raise-horizon! t)
    (when (> t tomb-horizon) (set! tomb-horizon t)))

  ;; -> #t when this node would still hold a record of the conversation.
  ;;
  ;; STRICT, and it has to stay strict on the eviction side: the horizon is
  ;; raised to the moment a dropped record was WRITTEN, and now-ms is whole
  ;; milliseconds, so an id born in that same millisecond may be exactly
  ;; the one just forgotten. Relaxing to >= would call it remembered. The
  ;; cost is at the other end -- an id minted in the very millisecond the
  ;; initial horizon was taken reads as older than this process -- and
  ;; that direction is the safe one, so the two are not worth separating
  ;; while nothing reads this.
  (define (tomb-remembers? id)
    (let ((born (conv-created-at id)))
      (and born (> born tomb-horizon))))

  (define (tomb-pop-oldest!)
    (when (null? tomb-front)
      (set! tomb-front (reverse tomb-back))
      (set! tomb-back '()))
    (unless (null? tomb-front)
      (let ((e (car tomb-front)))
        (set! tomb-front (cdr tomb-front))
        (set! tomb-n (- tomb-n 1))
        ;; forgetting this one is what moves the horizon: from here on,
        ;; anything at least this old is something we cannot speak for
        (raise-horizon! (cdr e))
        (hashtable-delete! tombstones (car e)))))

  ;; ALL THREE OF THESE RUN WITH INTERRUPTS DISABLED. They are pure memory
  ;; and never yield, and the alternative is a race with teeth: prune reads
  ;; the oldest entry, checks its age, and then calls a pop that re-reads
  ;; the head. Two conversations completing at once could interleave there
  ;; -- the second prune drops the entry the first had just approved of,
  ;; and the first then drops whatever moved up, which is a YOUNGER record
  ;; still inside both limits. The transaction it belonged to answers
  ;; 'gone afterwards, and 'gone is documented as "rolled back".
  ;; One POP is atomic; the sweep is not. Holding interrupts across the
  ;; whole loop -- a list reversal plus every expired entry, with a limit
  ;; the caller sets and nothing in the source bounding it -- stops the
  ;; event loop, every step and every watchdog for as long as it runs,
  ;; while the clock those watchdogs read keeps moving. A step could come
  ;; back from that already past its deadline and still publish.
  ;;
  ;; -> #t if it removed one, so the caller can come back for the next
  ;; with interrupts on in between.
  (define (tomb-pop-one-if-stale!)
    (with-interrupts-disabled
      (and (> tomb-n 0)
           (begin
             (when (null? tomb-front)
               (set! tomb-front (reverse tomb-back))
               (set! tomb-back '()))
             (let ((e (and (pair? tomb-front) (car tomb-front))))
               (and e
                    (or (> tomb-n tombstone-max)
                        (> (- (now-ms) (cdr e)) tombstone-ttl-ms))
                    (begin (tomb-pop-oldest!) #t)))))))

  (define (tomb-prune!)
    (let loop () (when (tomb-pop-one-if-stale!) (loop))))

  ;; The INSERT alone, for a caller that already holds interrupts. Splitting
  ;; it out is what lets a conversation publish its completion -- phase,
  ;; running flag and tombstone -- as one indivisible act; the prune loop
  ;; stays outside, where it belongs.
  ;; WHAT THE RECORD SAYS, not merely that there is one. #t settled,
  ;; 'rolled-back left through its winders with no commit asserted at all,
  ;; 'committed-then-failed left through them after one that returned, and
  ;; 'commit-uncertain-then-failed after a commit that may or may not have
  ;; landed; 'killed was stopped in flight -- see the head of this section
  ;; for why those five and not one.
  ;;
  ;; First write wins, and that is the right order in every direction: a
  ;; flow that published before the kill keeps its 'settled, a flow killed
  ;; before it could publish can never publish afterwards, and the
  ;; watchdog's backstop -- which writes 'killed for a death it did not
  ;; cause and cannot classify -- never overwrites a flow that had already
  ;; said what happened to it.
  ;;
  ;; ...WHILE THE RECORD IS STILL HERE, which is all this rule can
  ;; promise. An entry that has been pruned is not a first write any more,
  ;; so a later insert wins by default; what actually preserves a
  ;; classification across an eviction is the conversation's own
  ;; outcome-box, which the kill path re-inserts from. This function is
  ;; the tie-breaker between two live writers, not the memory.
  (define (tomb-insert-as! id what)
    (unless (hashtable-contains? tombstones id)
      (hashtable-set! tombstones id what)
      (set! tomb-back (cons (cons id (now-ms)) tomb-back))
      (set! tomb-n (+ tomb-n 1))))

  (define (tomb-insert! id) (tomb-insert-as! id #t))

  ;; THE ONE WRITER for a caller that is not already holding interrupts:
  ;; write, then prune outside the region. Every exit shape reaches the
  ;; table through this, so there is one place where a record is committed
  ;; and one place where the table is trimmed after it. (The completion
  ;; path and the watchdog's kill both publish the record inside a larger
  ;; atom of their own and call tomb-prune! themselves; see each.)
  (define (tomb-record-as! id what)
    (with-interrupts-disabled (tomb-insert-as! id what))
    (tomb-prune!))

  ;; WHAT THE RECORD SAYS, or #f for no record. Reading it in one place is
  ;; what keeps the mapping from records to answers in one place too: see
  ;; settled-or-lost, which is the only caller and the only thing that
  ;; decides what a record MEANS.
  (define (tomb-outcome id)
    (tomb-prune!)
    (with-interrupts-disabled
      (hashtable-ref tombstones id #f)))

  ;; Size the record of completed conversations. #f leaves one alone.
  (define (conversation-set-limits! max-entries ttl-ms)
    (when max-entries
      (unless (and (integer? max-entries) (exact? max-entries) (> max-entries 0))
        (assertion-violation 'conversation-set-limits!
          "max-entries must be a positive exact integer" max-entries))
      (set! tombstone-max max-entries))
    (when ttl-ms
      (unless (and (integer? ttl-ms) (exact? ttl-ms) (> ttl-ms 0))
        (assertion-violation 'conversation-set-limits!
          "ttl-ms must be a positive exact integer" ttl-ms))
      (set! tombstone-ttl-ms ttl-ms))
    (tomb-prune!)
    (void))

  ;; The id carries the owner node so a resume on any node reaches it, and
  ;; the time it was created so this node can tell whether it would still
  ;; remember the conversation:
  ;;
  ;;   "<node>~<base36 ms>-<hex>"  clustered
  ;;   "<base36 ms>-<hex>"         single node
  ;;
  ;; The hex stays unguessable; neither the node prefix nor the timestamp
  ;; is a secret, and neither is load-bearing for authorization -- see
  ;; conv-created-at for what the timestamp is FOR.
  (define (ms->b36 n)
    (let loop ((n n) (acc '()))
      (if (= n 0)
          (if (null? acc) "0" (list->string acc))
          (loop (div n 36)
                (cons (string-ref "0123456789abcdefghijklmnopqrstuvwxyz"
                                  (mod n 36))
                      acc)))))

  (define (b36->ms s)
    (let ((n (string-length s)))
      (and (> n 0)
           (let loop ((i 0) (acc 0))
             (if (= i n)
                 acc
                 (let* ((c (string-ref s i))
                        (d (cond ((and (char>=? c #\0) (char<=? c #\9))
                                  (- (char->integer c) (char->integer #\0)))
                                 ((and (char>=? c #\a) (char<=? c #\z))
                                  (+ 10 (- (char->integer c) (char->integer #\a))))
                                 (else #f))))
                   (and d (loop (+ i 1) (+ (* acc 36) d)))))))))

  ;; WHICH RUN OF THIS PROCESS MINTED IT.
  ;;
  ;; now-ms is uv_hrtime: monotonic, with an origin nobody promises
  ;; anything about. Within one process it is exactly what a horizon needs.
  ;; Across a HOST REBOOT it starts over near zero, so an id minted before
  ;; the reboot carries a LARGER number than the new horizon and reads as
  ;; "newer than anything I have forgotten" -- 'gone, for a conversation
  ;; that may well have committed. That is the reading this whole change
  ;; exists to remove, arrived at from the other side.
  ;;
  ;; So the timestamp is only ever compared within the run that wrote it.
  ;; The incarnation says which run that was; anything else is 'unknown.
  ;; 128 bits, not 32. A new run that happens to draw the same value as an
  ;; old one adopts that run's ids as its own, and after a host reboot --
  ;; where the clock has restarted low -- their timestamps read as newer
  ;; than this run's horizon: 'gone, for conversations that may have
  ;; committed. At 32 bits the birthday bound puts that at one percent
  ;; after about nine thousand restarts, which a long-lived service reaches.
  (define incarnation (conv-hex/n! 16))

  ;; -> (values id owner). The owner is the node identity THIS id was
  ;; minted under, handed back with it rather than re-read later: an id
  ;; carries its owner in its text, so the two are one fact and anything
  ;; that reads them apart can see them disagree. (conversation-prepare!
  ;; keeps the owner to compare at run! -- see there for what a
  ;; disagreement would mean.)
  (define (conversation-id!)
    (let ((hex (conv-hex!)) (n (node-self))
          (stamp (ms->b36 (now-ms))))
      (values
        (if n
            (string-append (symbol->string n) "~" incarnation "." stamp "-" hex)
            (string-append incarnation "." stamp "-" hex))
        n)))

  ;; When this id was made, or #f if THIS RUN cannot say. #f covers an id
  ;; from another incarnation, an id in the pre-incarnation format, and an
  ;; id that is simply malformed -- all of which are treated the same way,
  ;; as "older than anything I remember", which is the safe direction.
  ;;
  ;; The timestamp field is length-capped before it is converted. Exact
  ;; integers do not overflow in Chez, they GROW: a few million base36
  ;; digits from a stranger would otherwise be multiplied one at a time
  ;; into an ever larger bignum, which is a whole worker for one lookup.
  ;; Twelve digits covers any value uv_hrtime will produce.
  (define max-stamp-chars 12)

  (define (conv-created-at id)
    (let* ((len (string-length id))
           (start (let loop ((i 0))
                    (cond ((= i len) 0)
                          ((char=? (string-ref id i) #\~) (+ i 1))
                          (else (loop (+ i 1))))))
           (dot (let loop ((i start))
                  (cond ((= i len) #f)
                        ((char=? (string-ref id i) #\.) i)
                        ((char=? (string-ref id i) #\-) #f)   ; no incarnation
                        (else (loop (+ i 1))))))
           (dash (and dot
                      (let loop ((i (+ dot 1)))
                        (cond ((= i len) #f)
                              ((char=? (string-ref id i) #\-) i)
                              (else (loop (+ i 1))))))))
      (and dot dash
           (string=? (substring id start dot) incarnation)
           (<= (- dash (+ dot 1)) max-stamp-chars)
           (b36->ms (substring id (+ dot 1) dash)))))

  ;; owner node of an id, or #f (bare id -> single node, always local)
  (define (conv-owner id)
    (let ((len (string-length id)))
      (let loop ((i 0))
        (cond ((= i len) #f)
              ((char=? (string-ref id i) #\~)
               (string->symbol (substring id 0 i)))
              (else (loop (+ i 1)))))))

  (define (conversation-name id)
    (string->symbol (string-append "igropyr-conv-" id)))

  ;; consume a DOWN that raced the reply, so it cannot rot in the inbox
  ;; of a reused pool worker
  (define (flush-down! p)
    (receive (after 0 'ok)
      (`#(DOWN ,@p ,r) 'ok)))

  ;; ---- cross-node forwarding (owner routing) -----------------------
  ;;
  ;; A resume that lands on a node other than the owner is forwarded over
  ;; the mesh. The owner runs one router process (conv-router) that
  ;; SPAWNS a worker per forwarded resume, so a slow flow never blocks
  ;; other conversations -- there is no serial bottleneck. Correlation
  ;; must survive the wire, so the reply name is an INTERNED symbol (a
  ;; gensym is uninterned and would not round-trip via eq?) and the ref
  ;; is an integer (equal?-matchable across the codec).

  (define conv-router-name 'igropyr-conv-router)
  (define conv-forward-ttl-ms 300000)   ; forwarding-layer safety timeout

  (define reply-name-counter 0)
  (define (fresh-reply-name!)
    (with-interrupts-disabled
      (set! reply-name-counter (+ reply-name-counter 1))
      (string->symbol
        (string-append "igropyr-conv-r-" (number->string reply-name-counter)))))

  ;; Refs count up from 1, which is what leaves the negative range free to
  ;; mean something (see the router). Nothing ever produces 0 or less here.
  (define ref-counter 0)
  (define (fresh-ref!)
    (with-interrupts-disabled
      (set! ref-counter (+ ref-counter 1))
      ref-counter))

  ;; A ref this node minted to say "answer me with the wide frame".
  ;; fail-closed: anything else at all is treated as an old asker.
  (define (wide-ref? r) (and (fixnum? r) (fx< r 0)))

  ;; WHAT CROSSES THE MESH IS A VERDICT, NOT THE RECORD. The tombstone
  ;; values are this file's private vocabulary and would become wire format
  ;; the moment they were sent; these three say only what the far side
  ;; needs in order to decide, and can be extended without the reader
  ;; having to know every tombstone this library will ever write.
  (define (rec->evidence rec)
    (cond ((eq? rec 'committed-then-failed) 'commit-witness)
          ((eq? rec record-not-read) 'record-not-read)
          (else 'no-commit-witness)))

  ;; ...and coming back, ONLY an exact 'commit-witness is believed.
  ;;
  ;; The three verdicts collapse to two here because that is all today's
  ;; resolver distinguishes: a commit witness stops a #f predicate from
  ;; producing 'gone, and everything else leaves the predicate to decide as
  ;; it does locally. The distinction is kept ON THE WIRE anyway, because
  ;; "the owner looked and found no witness" and "the owner never looked"
  ;; are different facts, and a later reader may want them apart.
  ;;
  ;; Anything unrecognised -- an old value, a new one, a corrupted field --
  ;; is read as NO INFORMATION, which is the same thing an old owner's
  ;; narrow reply carries. It is not a stronger guarantee than that: with
  ;; no information the predicate decides, exactly as it has always done on
  ;; this path, and a predicate answering #f still produces 'gone. What
  ;; unrecognised evidence cannot do is MANUFACTURE A WITNESS -- it can
  ;; never be the thing that blocks a legitimate 'gone, and it can never
  ;; upgrade a caller's belief. Believing only one exact symbol is what
  ;; buys that, and it is the invariant worth stating; "bad data can only
  ;; end at 'unknown" would be a larger claim than this code makes.
  (define (evidence->rec ev)
    (if (eq? ev 'commit-witness) 'committed-then-failed record-not-read))

  ;; The owner's router: for each forwarded resume, spawn a worker that
  ;; runs the resume locally and sends the reply straight back to the
  ;; requesting node's temporary reply name. The router itself only
  ;; dispatches, so it is never the bottleneck.
  (define (conv-router-loop)
    (let loop ()
      (receive
        ;; THE ASKER SAYS WHAT IT CAN READ, in the ref it sends.
        ;;
        ;; These reply frames carry the owner's VERDICT on what it read --
        ;; not the tombstone itself, which is this file's private
        ;; vocabulary -- because without it the asking node's settled?
        ;; predicate can override a
        ;; commit witness the owner is holding -- exactly the misreading
        ;; the local path already refuses. But widening a frame is not a
        ;; compatible change here: replies are matched by vector SHAPE, and
        ;; a node that has not been upgraded does not fail to understand a
        ;; wider frame, it fails to MATCH it -- then waits out
        ;; conv-forward-ttl-ms and answers 'unreachable, for EVERY
        ;; forwarded call rather than only the ones a witness would help.
        ;;
        ;; The obvious repair is a two-step release: teach every node to
        ;; accept both shapes, wait for the fleet, then start sending the
        ;; wide one. That was the plan and it is not workable -- it needs a
        ;; barrier across machines that nothing enforces, and one node left
        ;; behind turns every forwarded call into a five-minute timeout.
        ;;
        ;; So the asker declares its own capability in a field the old code
        ;; already round-trips without interpreting: the ref. Refs are a
        ;; counter from 1 (see fresh-ref!), so the negative range is free
        ;; and unambiguous. A NEGATIVE ref means "I can read a wide reply".
        ;; That makes one release safe in every direction:
        ;;   old asker -> new owner: positive ref, narrow reply, unchanged
        ;;   new asker -> old owner: the old router echoes the ref without
        ;;     looking at it and answers narrow; the new asker matches
        ;;     narrow too, and simply has no witness
        ;;   new asker -> new owner: wide reply, witness delivered
        ;; Anything not a negative fixnum answers narrow, so a malformed or
        ;; unexpected ref degrades to today's behaviour rather than to a
        ;; frame the peer cannot match.
        (`#(conv-peek-fwd ,from-node ,reply-name ,ref ,id)
          (spawn
            (lambda ()
              (let-values (((state token reply rec) (local-peek id)))
                (rsend from-node reply-name
                       (if (wide-ref? ref)
                           (vector 'conv-peek-reply ref state token reply
                                   (rec->evidence rec))
                           (vector 'conv-peek-reply ref state token reply))))))
          (loop))
        (`#(conv-resume ,from-node ,reply-name ,ref ,id ,token ,req)
          (spawn
            (lambda ()
              (let-values (((reply status rec) (local-resume id token req)))
                (rsend from-node reply-name
                       (if (wide-ref? ref)
                           (vector 'conv-forward-reply ref reply status
                                   (rec->evidence rec))
                           (vector 'conv-forward-reply ref reply status))))))
          (loop))
        (,_ (loop)))))

  ;; Start the owner-side router once per node. Idempotent and atomic:
  ;; only meaningful when clustered (node-self set).
  (define (ensure-router!)
    (when (node-self)
      (with-interrupts-disabled
        (unless (whereis conv-router-name)
          (register conv-router-name (spawn conv-router-loop))))))

  ;; Forward a peek, with the same failure semantics as a forwarded resume:
  ;; anything that is not an answer is 'unreachable, never 'gone.
  ;; -> (values state token last-reply record). That last value is this
  ;; path's PROJECTION of the owner's verdict onto what resolve-unknown
  ;; reads: 'committed-then-failed when the owner said it holds a commit
  ;; witness, record-not-read for everything else -- an owner too old to
  ;; send a verdict, a verdict saying there is no witness, an unreadable
  ;; one, or any failure to get an answer at all. It is never a tombstone
  ;; value the owner did not vouch for.
  ;; WATCHING THE ROUTER, NOT THE NODE, because this process can be
  ;; KILLED and a kill discards its winders. The after-thunk below is
  ;; therefore not a teardown anything may depend on: whatever it releases
  ;; must ALSO be reclaimable by something that outlives the kill.
  ;;
  ;; The registered reply name is: the scheduler drops every alias of a
  ;; process it kills. A node-level watcher is not. It sits in a table
  ;; swept only when that node's up/down actually fires, so on a mesh that
  ;; never flaps, a killed process's entry -- and the dead pcb it points
  ;; at -- stays there for the life of the VM. The sweep exists; it is
  ;; just driven by an event that a healthy cluster never produces, which
  ;; is the worst shape for a leak: correct on the path anyone tests, and
  ;; unbounded on the path that actually runs.
  ;;
  ;; monitor-remote instead installs an agent that monitors THIS process
  ;; and dismantles the monitor when it goes down -- reclamation by an
  ;; owner that survives the kill, the same discipline a lease pool uses.
  ;; Earlier detection is not why it is here -- see the rule below, where
  ;; every remote-down defers to the link's own state. It does still
  ;; produce some: when the link really has dropped, this message is what
  ;; brings the wait to an end before the TTL would.
  ;;
  ;; The mref is #f when this node was never named. monitor-remote
  ;; requires node-start! where the node-level watcher did not, and an id
  ;; minted on a cluster can be handed to a node that never joined one --
  ;; ids travel as bearer tokens. That has to keep answering 'unreachable
  ;; rather than start raising.
  ;;
  ;; THE LINK'S STATE ENDS THE WAIT, NOT THE remote-down. The watch is
  ;; here for cleanup that survives a kill, NOT to detect failures
  ;; earlier, and those are different jobs. So a remote-down is treated as
  ;; a prompt to go and look, and what is looked at is whether the owner
  ;; is still a live peer. If it is, the message said nothing about this
  ;; request and the wait continues unwatched -- which is exactly the
  ;; world this path lived in before there was a watch at all, ended by
  ;; the reply or the TTL. A false 'unreachable is far worse than a slow
  ;; true one: on a resume it sends a caller to reconcile a step that ran.
  ;;
  ;; THE REASON FIELD CANNOT CARRY THIS DECISION, which is worth spelling
  ;; out because trusting it is the obvious thing to do and it is wrong
  ;; three separate ways. 'noconnection is not evidence that the link for
  ;; THIS call is down:
  ;;   - a target's exit reason is relayed verbatim, so a router killed
  ;;     with the reason 'noconnection produces one that has nothing to do
  ;;     with connectivity;
  ;;   - monitor-remote queues one immediately when there is no link at
  ;;     the moment of asking, and the link can be back before the request
  ;;     is sent;
  ;;   - remote-down carries no ref, so one left over from an earlier call
  ;;     is matched by a later call -- over a link that may since have
  ;;     been rebuilt and be working.
  ;; Each of those turns a healthy owner into 'unreachable. The peer list
  ;; has none of the problem: it is the state of the link now rather than
  ;; a claim about it earlier, and it belongs to no particular call. (Not
  ;; an atomic snapshot either -- the peer keys are taken under one lock
  ;; and then tested one by one, so a busy moment can be read across
  ;; several. It does not need to be exact: what it must not do is speak
  ;; for a different call, and it cannot.) A stale message can still send
  ;; us to look; it cannot decide what we find.
  ;;
  ;; Two other reasons deserve naming, because they show why the reason
  ;; field would be the wrong input even if it were trustworthy:
  ;;   'overload -- the owner's monitor quota is full. That is all it
  ;;     says: it is not a statement about the router, which may be
  ;;     serving this very call. It fires under LOAD rather than under
  ;;     partition, so trusting it would manufacture 'unreachable
  ;;     systematically, exactly when a cluster is busiest.
  ;;   the router dying -- the router only spawns a worker per request,
  ;;     and a worker it has ALREADY spawned outlives it and still
  ;;     replies. Giving up would discard an answer on its way. (Dying
  ;;     before it dispatches leaves no worker, and that call does wait
  ;;     out the TTL -- the wait is still right, just unrewarded.)
  ;;
  ;; WHAT THIS COSTS THE OWNER, because it is not free and the next person
  ;; to tune it should see the bill. monitor-node was purely local: it
  ;; touched a table here and sent nothing. A remote monitor occupies a
  ;; hosting slot on the OWNER plus an agent process there, for as long as
  ;; the call lasts -- and a forwarded resume can last a long time. The
  ;; ceiling (node-set-limits!) is shared with every other monitor-remote
  ;; user on that node. Reaching it DEGRADES rather than fails: refused
  ;; watches fall back to the unwatched wait above. The trade is a bounded
  ;; remote cost with a graceful ceiling in place of an unbounded local
  ;; leak that never self-heals -- but it is a trade, not a free win.
  (define (forward-peek owner id)
    (let ((reply-name (fresh-reply-name!))
          ;; negative: this node can read the wide reply (see the router)
          (ref (- (fresh-ref!)))
          (router conv-router-name))
      (register reply-name self)
      (let ((mref (and (node-self) (monitor-remote owner router))))
        (dynamic-wind
          (lambda () (void))
          (lambda ()
            (if (rsend owner router
                       (vector 'conv-peek-fwd (node-self) reply-name ref id))
                (let loop ((deadline (+ (now-ms) conv-forward-ttl-ms)))
                  (let ((left (- deadline (now-ms))))
                    (if (<= left 0)
                        ;; ONE LAST LOOK BEFORE GIVING UP, and it is not
                        ;; optional. A plain receive drains its mailbox
                        ;; before it ever runs a timeout handler, so a
                        ;; reply already queued always beats the clock.
                        ;; Looping re-checks the deadline OUTSIDE any
                        ;; receive, which throws that away: consume a
                        ;; stale remote-down, come back to find the
                        ;; deadline has just passed, and an answer sitting
                        ;; behind it in the same mailbox would never be
                        ;; looked at. The unrelated message would decide
                        ;; the call. This scan restores that precedence
                        ;; for THIS CALL'S REPLY, which is the part that
                        ;; was lost -- not the whole FIFO order of the
                        ;; original single receive, since it deliberately
                        ;; does not match remote-down (see below).
                        (receive (after 0
                                    (values 'unreachable
                                            #f #f record-not-read))
                          (`#(conv-peek-reply ,@ref ,state ,token ,reply ,ev)
                            (values state token reply (evidence->rec ev)))
                          (`#(conv-peek-reply ,@ref ,state ,token ,reply)
                            (values state token reply record-not-read)))
                        (receive (after left
                                    (values 'unreachable
                                            #f #f record-not-read))
                          ;; wide first: an owner that answers narrow is
                          ;; simply one that has not been upgraded, and both
                          ;; must be accepted for as long as a mesh can be
                          ;; mixed -- which is always.
                          ;;
                          ;; That tolerance is for the CONVERSATION
                          ;; protocol only. Watching the router needs the
                          ;; node layer's monitor frame, so a peer old
                          ;; enough to predate that frame is not a mixed
                          ;; version this path degrades against -- it would
                          ;; treat the frame as unknown and drop the link.
                          ;; The mesh floor is the node protocol, not this
                          ;; file's.
                          (`#(conv-peek-reply ,@ref ,state ,token ,reply ,ev)
                            (values state token reply (evidence->rec ev)))
                          (`#(conv-peek-reply ,@ref ,state ,token ,reply)
                            (values state token reply record-not-read))
                          (`#(remote-down ,@owner ,@router ,why)
                            (if (memq owner (node-peers))
                                (loop deadline)
                                (values 'unreachable
                                        #f #f record-not-read)))))))
                (values 'unreachable #f #f record-not-read)))
          (lambda ()
            ;; Unregister and demonitor BEFORE draining. This closes more
            ;; than the other order did -- a reply arriving between a drain
            ;; and a later unregister would be neither consumed nor
            ;; prevented -- but it does NOT make the drain exhaustive, and
            ;; the difference matters enough to name.
            ;;
            ;; Two interleavings still get past it, both because delivery
            ;; is decided a step before it happens:
            ;;   - a forwarded reply is dispatched as `whereis` and THEN
            ;;     `send`. Preempted between the two, this process can
            ;;     unregister and drain, and the send still lands on the
            ;;     pid already in hand.
            ;;   - a remote-down is fired by deleting the monitor entry and
            ;;     THEN sending. Preempted between the two, demonitor-remote
            ;;     finds nothing to cancel and the drain sees nothing, and
            ;;     the message arrives afterwards.
            ;; Neither can be closed from this side; both would have to be
            ;; made atomic where they are produced.
            ;;
            ;; A leftover reply is claimed by no later call of this kind
            ;; -- its ref is unique to this one. That is not the same as
            ;; harmless: this process is typically a pooled worker, and a
            ;; broad receive in whatever it does next can still take the
            ;; message, which is the whole reason it is drained here at
            ;; all. A leftover remote-down is worse:
            ;; it carries no ref, so the next forward from this process to
            ;; the same owner and router matches it immediately. What makes
            ;; that survivable is that matching it decides nothing: the
            ;; rule above then reads the live peer list, and a stale
            ;; message about a link that is now up costs a loop and a scan
            ;; of the peers rather than producing a false 'unreachable. It
            ;; is not free -- a backlog of them is a scan apiece -- and the
            ;; deadline is what bounds it. An earlier version of this
            ;; comment claimed the reason value made the leftover safe --
            ;; it does not, and that is precisely why the decision was
            ;; moved off the reason and onto the link.
            (unregister reply-name)
            (when mref (demonitor-remote mref))
            ;; Neither call retracts what is already queued: demonitor-remote
            ;; does not cancel a remote-down in flight, and a reply sent
            ;; before the unregister has already been placed. So both still
            ;; have to be drained.
            (receive (after 0 'ok)
              (`#(remote-down ,@owner ,@router ,why) 'ok))
            ;; ONE scan with both shapes, not two scans with one each: a
            ;; reply landing between two separate drains would be missed by
            ;; the first (not there yet) and by the second (wrong arity), and
            ;; stay in a mailbox this process does not own for long.
            (receive (after 0 'ok)
              (`#(conv-peek-reply ,@ref ,a ,b ,c ,d) 'ok)
              (`#(conv-peek-reply ,@ref ,a ,b ,c) 'ok)))))))

  ;; Forward a resume to the owner node and wait for its reply.
  ;;
  ;; Every failure here answers 'unreachable, NOT 'gone. A link that is
  ;; down and a wait that expired both say the same thing -- we could not
  ;; reach the owner -- and neither says the owner died. Under a partition
  ;; the conversation is still running and can still commit, so calling that
  ;; 'gone would hand the caller a rollback guarantee this layer cannot
  ;; make, and a caller that retries on it duplicates the flow's effects.
  ;;
  ;; Nothing here DECIDES 'gone -- this function can only carry back one
  ;; the owner's node already read from its RECORD. Note what does the work
  ;; there: a record saying the flow left through its winders with no
  ;; commit asserted, never the mere absence of a registry entry -- an
  ;; absence says the process is not here and nothing more, which is why it
  ;; answers 'unknown. A network failure cannot produce even that much. (A
  ;; caller's own settled? predicate can also produce 'gone, on evidence
  ;; this library does not hold -- see resolve-unknown, which is where that
  ;; authority is bounded.)
  ;; -> (values reply status record), the same projection as forward-peek.
  ;; Watches the owner's router rather than the node, and for the same
  ;; kill-safety reason -- see forward-peek, where it is written out.
  (define (forward-resume owner id token req)
    (let ((reply-name (fresh-reply-name!))
          (ref (- (fresh-ref!)))
          (router conv-router-name))
      (register reply-name self)
      (let ((mref (and (node-self) (monitor-remote owner router))))
        (dynamic-wind
          (lambda () (void))
          (lambda ()
            ;; rsend is #f when the link is already down. That, the link
            ;; dropping mid-flight, and the forwarding TTL are all the
            ;; same statement: unreachable. The owner may be dead, or may
            ;; be committing right now -- from here they are
            ;; indistinguishable. The ROUTER going down is not on that
            ;; list: a worker it has already spawned outlives it and
            ;; answers, so that case waits like any other -- see the rule
            ;; at the receive below. (A router that dies before dispatching
            ;; leaves no worker and nothing to wait for, and that call does
            ;; run out the TTL.)
            (if (rsend owner router
                       (vector 'conv-resume (node-self) reply-name ref
                               id token req))
                (let loop ((deadline (+ (now-ms) conv-forward-ttl-ms)))
                  (let ((left (- deadline (now-ms))))
                    (if (<= left 0)
                        ;; last look before giving up -- see forward-peek:
                        ;; without it a stale remote-down consumed at the
                        ;; deadline would hide an answer queued behind it
                        (receive (after 0
                                    (values #f 'unreachable record-not-read))
                          (`#(conv-forward-reply ,@ref ,reply ,status ,ev)
                            (values reply status (evidence->rec ev)))
                          (`#(conv-forward-reply ,@ref ,reply ,status)
                            (values reply status record-not-read)))
                        (receive (after left
                                    (values #f 'unreachable record-not-read))
                          (`#(conv-forward-reply ,@ref ,reply ,status ,ev)
                            (values reply status (evidence->rec ev)))
                          (`#(conv-forward-reply ,@ref ,reply ,status)
                            (values reply status record-not-read))
                          (`#(remote-down ,@owner ,@router ,why)
                            ;; see forward-peek: the LINK's current state
                            ;; decides, not the reason. Here a premature
                            ;; give-up is worse than there -- this call may
                            ;; have ALREADY advanced the flow on the owner,
                            ;; and the caller would be sent to reconcile a
                            ;; step that in fact ran.
                            (if (memq owner (node-peers))
                                (loop deadline)
                                (values #f 'unreachable record-not-read)))))))
                (values #f 'unreachable record-not-read)))
          (lambda ()
            ;; stop new deliveries, then drain -- see forward-peek
            (unregister reply-name)
            (when mref (demonitor-remote mref))
            ;; demonitor-remote does not retract a #(remote-down ...)
            ;; already delivered. Left behind, a LATER forward to the same
            ;; owner matches that stale message at once -- it carries no
            ;; ref to tell the calls apart. It no longer decides anything
            ;; on its own (the rule at the receive reads the live peer
            ;; list, so a recovered owner just costs a loop), but draining
            ;; it here is what keeps that cost from accumulating.
            ;; (This used to answer 'gone, which was worse: the caller was
            ;; told the transaction had certainly rolled back.)
            (receive (after 0 'ok)
              (`#(remote-down ,@owner ,@router ,why) 'ok))
            ;; same for a reply that arrived after we stopped waiting
            ;; one scan, both shapes -- see forward-peek's drain
            (receive (after 0 'ok)
              (`#(conv-forward-reply ,@ref ,a ,b ,c) 'ok)
              (`#(conv-forward-reply ,@ref ,a ,b) 'ok)))))))

  ;; ---- on-killed health ---------------------------------------------------
  ;;
  ;; THE ONE PLACE THIS FILE COULD NOT SEE INTO. on-killed is application
  ;; code run after a kill, and it had two ways to fail without leaving a
  ;; trace anywhere: it could RAISE, and the guard around it -- which has
  ;; to be there, or a bad hook takes the watchdog with it -- swallowed
  ;; that silently, so a handle went unreleased and a compensation went
  ;; unrun with nothing recorded; or it could HANG, which no guard covers
  ;; at all, and the watchdog then sat inside it forever, never reaching
  ;; its loop, leaking a green process per killed conversation.
  ;;
  ;; Counters, not an observer hook. A callback would run application code
  ;; back inside the watchdog's timing, and would itself be able to fail
  ;; the same two ways -- the thing being fixed. If "react to every hook
  ;; failure" is ever a real requirement, adding it later is additive;
  ;; reading a count is enough to know it is happening at all.
  ;;
  ;; None of this reaches the conversation's status or its tombstone.
  ;; 'gone / 'settled / 'unknown describe the TRANSACTION, and hook health
  ;; is orthogonal to it: a committed transaction can have a failing
  ;; release hook, and a killed uncommitted one is 'unknown whether its
  ;; compensation succeeded or not. Folding one into the other would hide
  ;; the more important classification behind the less important one.
  (define hook-attempted (box 0))
  (define hook-succeeded (box 0))
  (define hook-raised (box 0))
  (define hook-timed-out (box 0))
  (define hook-killed (box 0))
  (define hook-running (box 0))
  ;; SUCCESS IS PROVED OFF-CHANNEL, not by the exit reason.
  ;;
  ;; A process's exit reason is whatever it raised, and a clean return
  ;; produces 'normal -- which is also what killing it with reason 'normal
  ;; produces, so "returned" and "stopped from outside" arrive identical.
  ;; Tagging only the FAILURE closes half of that: a hook raising 'normal
  ;; can no longer look like success, but an outside kill still can.
  ;;
  ;; The obvious repair -- exit with a private token instead of returning
  ;; -- was tried and is wrong twice over. An exit reason is BROADCAST: it
  ;; goes to every monitor and is kept on the dead process, where a later
  ;; monitor of that pid hands it out again, so the token stops being
  ;; private the first time a hook succeeds and can then be used to forge
  ;; the next success. And a non-'normal exit CASCADES: anything the hook
  ;; had linked, and that does not trap exits, is killed along with it --
  ;; measured, a background process a hook spawn&links and leaves running
  ;; survives a plain return and does not survive a token exit.
  ;;
  ;; So the proof does not travel through the actor's exit machinery at
  ;; all: the child sets a box that only this wrapper holds, as the last
  ;; thing it does. Nothing publishes it, nothing outside can write it,
  ;; and being killed -- with any reason at all, 'normal included -- leaves
  ;; it unset. The hook exits 'normal exactly as before.
  ;; The last failure, WITH THE CONVERSATION ID -- counters alone tell an
  ;; application that something failed but not what to reconcile, and
  ;; between two reads the second failure would overwrite the first with
  ;; no way back to the id. Only the newest is kept, which bounds this;
  ;; The reason field differs by kind: for `raised` it is the wrapper's
  ;; tagged form of what the hook threw, for `timed-out` it is this
  ;; library's own timeout symbol, and for `killed` it is whatever reason
  ;; the outside used. The first of those can hold a large object graph, or
  ;; one carrying data the application would not otherwise retain, since it
  ;; is the application's own exception. Read it and let go of it.
  (define hook-last-failure (box #f))

  (define (hook-bump! b) (set-box! b (+ 1 (unbox b))))

  ;; Cumulative since process start, like the rest of this framework's
  ;; counters: never reset, so a caller that wants a delta takes its own
  ;; baseline.
  ;;
  ;; WHAT EACH ONE MEANS, precisely, because the useful ones are the ones
  ;; that are easy to over-read:
  ;;   attempted   a hook was started
  ;;   succeeded   the wrapper saw the hook RETURN. Not that anything was
  ;;               released -- a hook that swallows its own errors, or does
  ;;               nothing at all, returns.
  ;;   raised      the hook raised, and the wrapper tagged it. An external
  ;;               kill whose reason is deliberately shaped like that tag
  ;;               also lands here rather than in `killed` -- both are
  ;;               failures, so the miscount costs a distinction, not a
  ;;               guarantee. Success is the one that cannot be forged.
  ;;   timed-out   it outlived the conversation's ttl and was killed here
  ;;   killed      it neither returned nor raised: something outside ended
  ;;               it -- an external kill, or a link cascade from something
  ;;               the hook itself linked to
  ;;   running     an APPROXIMATE gauge, and it can be permanently high: it
  ;;               is decremented by the same function that incremented it,
  ;;               so a watchdog that dies DURING a hook never decrements.
  ;;               Accepted rather than fixed -- exactness would mean
  ;;               unwind-safe bookkeeping in a function that can be killed
  ;;               outright -- but do not read a standing non-zero value as
  ;;               proof that a hook is running now.
  (define (conversation-hook-stats)
    (with-interrupts-disabled
      (list (cons 'attempted (unbox hook-attempted))
            (cons 'succeeded (unbox hook-succeeded))
            (cons 'raised (unbox hook-raised))
            (cons 'timed-out (unbox hook-timed-out))
            (cons 'killed (unbox hook-killed))
            (cons 'running (unbox hook-running))
            (cons 'last-failure (unbox hook-last-failure)))))

  ;; Run on-killed in its own supervised process, and outlive it either way.
  ;;
  ;; LINKED AND MONITORED, BOTH. The monitor is how the outcome comes back;
  ;; the link is what stops the hook from being orphaned when the watchdog
  ;; itself dies -- spawn&link establishes that before the child can run,
  ;; so there is no window where the child exists unattached. Trapping
  ;; exits for the duration is what turns the child's death into a message
  ;; instead of a cascade; it is turned back off afterwards so the
  ;; watchdog's own behaviour is unchanged everywhere else.
  ;;
  ;; THE RAISE IS RE-TAGGED, and it has to be: a process's exit reason IS
  ;; the object it raised, so a hook doing (raise 'normal) would produce
  ;; exactly the reason a clean return produces, and a failure would be
  ;; counted as a success. Wrapping it makes 'normal mean one thing.
  ;;
  ;; THE TIMEOUT IS THE CONVERSATION'S OWN ttl. It is already the caller's
  ;; statement of how long this dialogue may take, and cleanup getting a
  ;; fresh allowance of it is the same rule the expiry path follows. A
  ;; fixed number would be unrelated to the application's operation, and a
  ;; new parameter would ask every caller to describe something they have
  ;; already described. (It is a deadline on the whole attempt, queueing
  ;; included: under a burst of kills a hook can be timed out having had
  ;; little CPU. That is the honest reading of "took too long" on a
  ;; cooperatively scheduled runtime.)
  ;;
  ;; WHAT THIS DOES NOT COVER: a hook that blocks the OS THREAD. The child
  ;; process bounds anything the scheduler can preempt -- sleeps, receives,
  ;; async I/O, a CPU loop with interrupts on. A blocking foreign call, a
  ;; synchronous OS call, or a loop with interrupts disabled stops the one
  ;; thread everything runs on, and `after` never gets to fire. Bounding
  ;; those needs a second OS thread, which this library does not have.
  (define (run-on-killed! id on-killed committed? ttl)
    (with-interrupts-disabled
      (hook-bump! hook-attempted)
      (hook-bump! hook-running))
    (process-trap-exit #t)
    (let* ((returned (box #f))          ; the private proof; see above
           (child (spawn&link
                    (lambda ()
                      (guard (e (#t (raise (vector 'conversation-hook-raised e))))
                        (on-killed committed?)
                        ;; last act, and unreachable from anywhere else
                        (set-box! returned #t)))))
           (m (monitor child))
           (outcome
             (receive (after ttl
                        ;; the kill discards the hook's own winders, just
                        ;; as the kill that summoned it discarded the
                        ;; flow's -- a hook must not put its releasing in
                        ;; a winder for that reason
                        (begin
                          (kill child 'conversation-hook-timeout)
                          (receive (after 0 'ok) (`#(DOWN ,@child ,r) 'ok))
                          (cons 'timed-out 'conversation-hook-timeout)))
               (`#(DOWN ,@child ,reason)
                 (cond
                   ;; the box first: it is the only thing here that cannot
                   ;; be produced from outside this wrapper
                   ((unbox returned) (cons 'succeeded #f))
                   ((and (vector? reason)
                         (fx= 2 (vector-length reason))
                         (eq? (vector-ref reason 0) 'conversation-hook-raised))
                    (cons 'raised reason))
                   ;; did not finish and did not raise: something outside
                   ;; ended it -- an external kill (any reason, 'normal
                   ;; included), or a cascade from something it linked
                   (else (cons 'killed reason)))))))
      (when m (demonitor m))
      ;; the link's EXIT, however the child ended; left behind it would sit
      ;; in the watchdog's mailbox and never match anything it receives
      (receive (after 0 'ok) (`#(EXIT ,@child ,r) 'ok))
      (process-trap-exit #f)
      (with-interrupts-disabled
        (set-box! hook-running (- (unbox hook-running) 1))
        (case (car outcome)
          ((succeeded) (hook-bump! hook-succeeded))
          (else
            (hook-bump! (case (car outcome)
                          ((raised) hook-raised)
                          ((timed-out) hook-timed-out)
                          (else hook-killed)))
            (set-box! hook-last-failure
              (vector 'conversation-hook-failure id (car outcome)
                      (cdr outcome) committed? (now-ms))))))))

  ;; Start a conversation. flow: (lambda (req suspend! commit!) ... final-reply).
  ;; suspend! answers the current round and parks until the next resume,
  ;; returning the next request; on TTL expiry it raises
  ;; 'conversation-expired inside the flow. commit! takes a thunk and runs
  ;; it, marking the conversation committed the moment it RETURNS, or
  ;; may-have-committed if it raises #(commit-uncertain reason). Run the
  ;; transaction's commit through it: with no commit asserted either way,
  ;; an exception on the way out of the flow is recorded as a rollback and
  ;; answered 'gone. One
  ;; conversation is one logical transaction: commit! is the CONVERSATION's
  ;; last state change, and the mark it sets is sticky -- never cleared or
  ;; lowered, so nothing that happens afterwards makes this library record
  ;; a rollback on its own evidence. The flow's
  ;; return value is
  ;; the final round's reply; the process then lingers one more TTL, so a
  ;; lost final reply can still be replayed, and unregisters after it.
  ;; Returns (values id token first-reply); the caller parks meanwhile.
  ;; Optional trailing arguments: ttl-ms (default 300000), request-key
  ;; (default values), on-killed (default #f) -- each documented at its
  ;; binding below. on-killed takes one argument, committed?, and is
  ;; rejected here if it cannot accept one.
  ;; ---- the handle -----------------------------------------------------
  ;;
  ;; WHAT PREPARE! HANDS BACK, and it is opaque on purpose: the id is
  ;; reachable through conversation-ref-id and nothing else here is a
  ;; caller's business.
  ;;
  ;; `state` is 'prepared, 'consumed or 'abandoned, and the last two are
  ;; TERMINAL. A run! that raised does not go back to 'prepared: its flow
  ;; may have run part-way and had effects, so what is used up is the
  ;; handle's one chance to spawn, not "a live process" -- and a second
  ;; run! of the same handle would be a second conversation wearing the
  ;; first one's id.
  ;;
  ;; `launch` is the closure that spawns, and it holds the flow, the
  ;; request and everything they close over. It is dropped on the way into
  ;; either terminal state, because a handle that has been used or thrown
  ;; away would otherwise pin all of that for as long as anyone keeps the
  ;; handle -- and the handle is the thing a caller is told to persist.
  (define-record-type (conv-handle make-conv-handle conv-handle?)
    (fields id
            owner                  ; node-self as it was when id was minted
            (mutable state)
            (mutable launch)))

  (define (conversation-ref-id h)
    (unless (conv-handle? h)
      (assertion-violation 'conversation-ref-id "not a conversation handle" h))
    (conv-handle-id h))

  ;; Give up a prepared conversation without ever starting it. Nothing was
  ;; spawned, so there is nothing to stop; this marks the handle so a later
  ;; run! is refused rather than quietly starting a conversation the caller
  ;; had already written off, and drops the payload.
  ;;
  ;; Dropping a handle on the floor instead is free and needs no call --
  ;; the payload goes with it. Use this when the handle has been persisted
  ;; or handed on, and "I decided not to" needs to be a fact rather than an
  ;; absence.
  (define (conversation-abandon! h)
    (unless (conv-handle? h)
      (assertion-violation 'conversation-abandon! "not a conversation handle" h))
    (let ((bad (with-interrupts-disabled
                 (let ((s (conv-handle-state h)))
                   (cond ((eq? s 'prepared)
                          (conv-handle-state-set! h 'abandoned)
                          (conv-handle-launch-set! h #f)
                          #f)
                         (else s))))))
      (when bad
        (assertion-violation 'conversation-abandon!
          "conversation handle is not prepared" bad))))

  ;; prepare! + run! in one call, and the shape this library had before
  ;; there were two. It still returns (values id token first-reply) -- but
  ;; the id arrives only after the first suspend!, so a caller that needs
  ;; the id BEFORE anything happens wants the two calls, not this one.
  (define (conversation-start! flow req . opts)
    (let ((h (apply prepare/who 'conversation-start! flow req opts)))
      (let-values (((token reply) (conversation-run! h)))
        (values (conv-handle-id h) token reply))))

  ;; Mint the id and get everything ready, WITHOUT starting anything.
  ;;
  ;; The point is that the id exists before the first effect does. Under
  ;; conversation-start! the id is minted inside the same call that spawns
  ;; the flow and is not handed back until the flow's first suspend! --
  ;; so between those two moments the conversation has begun to act on the
  ;; world and nobody outside can name it. A starter killed in that window
  ;; leaves a conversation that is still running, still talking to whatever
  ;; the flow talks to, and whose id no longer exists anywhere. Preparing
  ;; first lets a caller write "I am about to start <id>" somewhere durable
  ;; and then start it.
  ;;
  ;; INERT: no process, no registration, no timer is started here. (Not
  ;; "pure" -- minting an id reads /dev/urandom, the node identity and the
  ;; clock.) No clock this conversation lives by starts before run!.
  ;;
  ;; The handle must not be sent to another node: it holds closures. It
  ;; can be handed to another process on THIS node, and run! from there --
  ;; that is a supported shape, and the reply goes to whoever calls run!.
  (define (conversation-prepare! flow req . opts)
    (apply prepare/who 'conversation-prepare! flow req opts))

  (define (prepare/who who flow req . opts)
    ;; A ttl that is not a positive exact integer reaches receive's `after`
    ;; and raises THERE -- inside the conversation process, after it has
    ;; already handed back an id and a token. The caller sees a healthy
    ;; start and a 'gone on its next resume, with nothing anywhere saying
    ;; why. Checked here, where it was written.
    (when (pair? opts)
      (let ((t (car opts)))
        (unless (and (integer? t) (exact? t) (> t 0))
          (assertion-violation who
            "ttl-ms must be a positive exact integer" t))))
    ;; ...and on-killed is checked here for a sharper version of the same
    ;; reason. It is CALLED much later, in a process of its own, where an
    ;; arity error would be just another way for the hook to fail: counted
    ;; as `raised`, but arriving long after the call that got the shape
    ;; wrong, in a different process, with nothing pointing back at the
    ;; conversation-start! that accepted it. The compensation would not
    ;; run and whatever the flow was holding would stay held. That is the
    ;; worst way for an interface change to be discovered, so the shape is
    ;; settled at the point it was written, where the raise reaches the
    ;; code that is wrong.
    ;;
    ;; Accepting one argument, not accepting EXACTLY one: a variadic hook
    ;; and one with optionals are both fine, and the only thing worth
    ;; refusing is a hook that cannot be told whether a commit was
    ;; asserted.
    (when (and (pair? opts) (pair? (cdr opts)) (pair? (cddr opts))
               (caddr opts))
      (let ((h (caddr opts)))
        (unless (and (procedure? h) (logbit? 1 (procedure-arity-mask h)))
          (assertion-violation who
            "on-killed must be a procedure accepting one argument (committed?)"
            h))))
    (let-values (((id owner) (conversation-id!)))
     (make-conv-handle
      id owner 'prepared
      ;; EVERYTHING BELOW HAPPENS AT run!, not here. The closure is built
      ;; now and called then, with the runner's identity passed in.
      (lambda (starter ref)
       (let* ((ttl (if (pair? opts) (car opts) default-ttl-ms))
           ;; WHAT IDENTIFIES A REQUEST, for replay.
           ;;
           ;; A repeat is replayed; a DIFFERENT question bearing the same
           ;; token is not, because answering "cancel" with the result of
           ;; someone else's "confirm" is worse than refusing. Deciding
           ;; sameness needs to know what the request IS, and only the
           ;; application does: over HTTP the resumed value is a request
           ;; record, and two retries of the same call are two different
           ;; records, so a bare equal? never matches there.
           ;;
           ;; A KEY function, not a comparator, and the difference is not
           ;; cosmetic. The key is computed ONCE, when the request is
           ;; accepted, inside the step's own bounded window; comparison is
           ;; then plain equal? on the key. A comparator would have been
           ;; application code run at REPLAY time -- while the conversation
           ;; is parked, where the watchdog deliberately does not look --
           ;; so one that blocked would have held an open transaction
           ;; indefinitely, one that raised would have killed the
           ;; conversation and turned a committed flow into 'gone, and one
           ;; that returned any non-#f value at all would have authorized
           ;; the replay. And the key is what is RETAINED: retaining the
           ;; request itself keeps a body, and whatever it references, alive
           ;; for the rest of the conversation.
           ;;
           ;;   (lambda (r) (req-body r))     ; over HTTP
           ;;   values                        ; plain data, the default
           (request-key
             (if (and (pair? opts) (pair? (cdr opts)) (cadr opts))
                 (cadr opts)
                 values))
           ;; RUN WHEN THE WATCHDOG KILLS A RUNNING STEP.
           ;;
           ;; The library says TTL expiry raises 'conversation-expired
           ;; inside the flow so a guard can roll back. That is true of a
           ;; conversation that sat parked too long -- and false of the one
           ;; the watchdog exists for. A step that overruns is KILLED, and
           ;; @kill discards dynamic-wind winders, so the flow's guard does
           ;; not run at all.
           ;;
           ;; A pooled database connection survives that anyway: the pool
           ;; monitors its borrower, and a dead borrower means destroy and
           ;; rebuild, which drops the connection and the server rolls the
           ;; transaction back. Anything the flow holds IN PROCESS does not.
           ;; A reservation, a file handle, an in-memory hold -- the money
           ;; deducted from a balance and restored in a guard -- stays held
           ;; for the life of the VM.
           ;;
           ;; So: a procedure of one argument, run after the kill, in a
           ;; dedicated supervised process of its own. It cannot touch the
           ;; flow's stack (that is gone); it releases what the flow was
           ;; holding, which the application reaches through whatever it
           ;; closed over.
           ;;
           ;; WHAT "ITS OWN PROCESS" CHANGES, and what it does not. The
           ;; heap is the same one: same OS thread, same boxes, same
           ;; handles, so everything the hook closed over is exactly what
           ;; the flow was holding. What differs is the process identity
           ;; around it -- `self`, the mailbox, and who owns any link,
           ;; monitor or registration the hook makes. A hook that spawns
           ;; and links, or registers a name, is doing it from a process
           ;; that ends when the hook does.
           ;;
           ;; It is bounded by the conversation's ttl and its outcome is
           ;; counted (see run-on-killed! and conversation-hook-stats):
           ;; raising no longer disappears, and hanging no longer strands
           ;; the watchdog. Three things the hook still owes:
           ;;   - BE IDEMPOTENT, in every action and not only the undo --
           ;;     see below for the windows where it runs after the flow's
           ;;     winders already released once.
           ;;   - BE CANCELLABLE. A hook that overruns is killed, and that
           ;;     kill discards its dynamic-wind winders exactly as the
           ;;     kill that summoned it discarded the flow's. Releasing
           ;;     from a winder is releasing from something that may not
           ;;     run.
           ;;   - RETURNING IS NOT EVIDENCE. A hook that swallows its own
           ;;     errors, or does nothing, returns cleanly and is counted
           ;;     as a success. The counters say the hook finished, never
           ;;     that the resource came back.
           ;; And the most reliable shape is not a long hook at all: let an
           ;; owner process monitor whoever borrowed a resource and reclaim
           ;; it on DOWN, and let this hook be one idempotent message to
           ;; that owner.
           ;;
           ;; THE ARGUMENT IS committed? -- whether anything had asserted a
           ;; commit for this conversation when the kill landed, either one
           ;; that returned or one reported as a maybe. The hook has two
           ;; jobs and they need different answers. RELEASING what is held
           ;; in this process -- a handle, a reservation, a slot -- is
           ;; unconditional: the flow is dead and nothing else will ever
           ;; give it back. UNDOING the transaction is only right where
           ;; the transaction did not happen; run against a flow that
           ;; committed, it reverses work that succeeded, and the client
           ;; has already been told 'unknown rather than 'gone precisely
           ;; because that work stands. So: release unconditionally,
           ;; compensate under (not committed?).
           ;;
           ;;   (lambda (committed?) (release-handle!)
           ;;                        (unless committed? (undo-hold!)))
           ;;
           ;; The library does not make that split itself, because only
           ;; the application knows which of its own effects are which.
           ;;
           ;; committed? MEANS "A COMMIT WAS ASSERTED", not "the commit is
           ;; confirmed". The mark behind it has three values -- no commit,
           ;; a commit the flow said MAY have landed, and a confirmed one
           ;; -- and the last two arrive here as the same #t, because the
           ;; hook's right action is the same for both: do not compensate.
           ;; Undoing a maybe-committed transaction is the same hazard as
           ;; undoing a committed one, so a distinction the hook cannot act
           ;; on differently is not worth a third break of its signature.
           ;;
           ;; It is still ONE-SIDED. #t is never wrong in the direction
           ;; that matters -- something did assert a commit, and nothing
           ;; ever clears the mark. #f can be stale, and by more than an
           ;; instant: between a commit thunk's return and the mark being
           ;; set is indeed one instant, but a driver that has dispatched
           ;; its request and is waiting to learn the outcome has raised
           ;; nothing yet, so the whole of that wait -- a timeout's worth,
           ;; potentially -- also reads #f, for a transaction that may
           ;; already have taken effect. Neither window can be closed from
           ;; another process (see the watchdog's
           ;; call site). So #f means "no witness", not "proof
           ;; it did not commit". An undo that is destructive when wrong
           ;; must be idempotent, or consult the authoritative store,
           ;; rather than rest on this flag alone.
           ;;
           ;; EVERY ACTION IN THE HOOK MUST BE IDEMPOTENT, not only the
           ;; compensation. This used to say that releasing a handle,
           ;; being unconditional anyway, never had the problem -- which
           ;; is wrong in the two windows the kill gate cannot close: a
           ;; flow whose winders have ALREADY run (they released once) but
           ;; whose outcome had not yet been published when the kill
           ;; landed reaches this hook as well, and releases a second
           ;; time. The gate below narrows those windows; nothing closes
           ;; them, because "the winders have finished running" is not a
           ;; fact any other process can observe.
           (on-killed
             (if (and (pair? opts) (pair? (cdr opts)) (pair? (cddr opts)))
                 (caddr opts)
                 #f))
           (name (conversation-name id))
           ;; shared with the watchdog below: step-box counts completed
           ;; suspends (progress), running-box says whether the flow is
           ;; executing rather than parked waiting for the next request
           (step-box (box 0))
           (running-box (box #t))
           ;; when the step now running actually began. The watchdog used
           ;; to sample on a fixed period and decide from "has the counter
           ;; moved since my last look", which gives a step anything from
           ;; almost nothing to almost twice the TTL depending on where it
           ;; starts in that cycle -- measured, a step killed 301 ms into a
           ;; 2000 ms allowance. Sampling can stay periodic; the DECISION
           ;; has to come from the clock.
           (run-start-box (box (now-ms)))
           ;; set when the flow returns: from then on nothing the watchdog
           ;; sees is a step that overran, whatever marks the phase running
           (settled-box (box #f))
           ;; WHAT SOMETHING THAT KNEW WHAT HAPPENED SAID -- not merely
           ;; THAT it said something. #f until published; then #t for a
           ;; flow that returned, or the outcome symbol an exception left
           ;; ('rolled-back / 'commit-uncertain-then-failed /
           ;; 'committed-then-failed), or 'killed.
           ;;
           ;; It is a BOX rather than a lookup in the table for the same
           ;; reason settled-box is: THE TABLE FORGETS. A conversation
           ;; whose record is evicted while its watchdog is still winding
           ;; down would otherwise be described a second time, by the one
           ;; process that does not know what happened to it -- which
           ;; costs a slot, evicts a live record to get it, and puts the
           ;; wrong outcome in the entry it leaves behind.
           ;;
           ;; It holds the OUTCOME and not just a flag because "first
           ;; write wins" only protects a record that is still in the
           ;; table. A flow can publish 'rolled-back, have that record
           ;; pruned -- by age, or by another conversation's insert under
           ;; the count limit -- and still be alive on its way out of the
           ;; guard when the watchdog kills it; the kill then finds no
           ;; record, and a KNOWN rollback becomes 'killed, which answers
           ;; 'unknown. A caller that could have retried is told to
           ;; reconcile instead. Carrying the outcome lets the kill path
           ;; re-establish the classification it found rather than
           ;; overwrite it with the weakest one.
           (outcome-box (box #f))
           ;; WHAT HAS BEEN ASSERTED ABOUT THIS CONVERSATION'S COMMIT.
           ;; Three values, and it only ever rises through them:
           ;;   #f          nothing has claimed a commit
           ;;   'uncertain  a commit thunk raised #(commit-uncertain ...):
           ;;               it may have landed and may not have
           ;;   'confirmed  a commit thunk RETURNED
           ;; Set by commit! -- 'confirmed the instant the thunk returns,
           ;; 'uncertain when it raises the tag -- and NEVER CLEARED OR
           ;; LOWERED; there is no such point anywhere in this file. One
           ;; conversation is one logical transaction, so once that
           ;; transaction is permanent, no later death of this conversation
           ;; may be described as a rollback: the effects are out in the
           ;; world and 'gone would invite a caller to produce them again.
           ;; A mark that reset each round said the opposite -- commit,
           ;; park, resume, raise, and the answer was 'gone for a
           ;; transaction that had already happened, which is the defect
           ;; this box exists to close, one round later.
           ;;
           ;; Nothing else in the library can know this: under
           ;; standard dynamic-wind an exception arriving from the flow
           ;; looks the same whether the body raised (a real rollback) or
           ;; the after-thunk raised while the body was RETURNING from a
           ;; commit that succeeded. The first is 'gone, the second must be
           ;; 'unknown, and reading them off one raise is not possible from
           ;; outside; the flow has to say. So it does, by committing
           ;; THROUGH the library.
           (committed-box (box #f))
           ;; the watchdog, so entering running can WAKE it instead of
           ;; being noticed by a poll. Polling fast enough to catch the
           ;; start of a step meant polling every ttl for a small ttl --
           ;; a conversation with a 1ms allowance woke its watchdog a
           ;; thousand times a second while parked, and a few of those
           ;; crowd out everything else on the one thread. Being told is
           ;; both cheaper and sharper than looking more often.
           (watch-box (box #f))
           (conv
             (spawn
               (lambda ()
                 (register name self)
                 ;; A WATCHDOG, because the TTL below only bounds time spent
                 ;; parked in suspend!. A step that runs long -- slow I/O, a
                 ;; wait that never returns, a CPU loop -- leaves that receive
                 ;; entirely, and nothing else was counting: the conversation
                 ;; could hold its transaction, its reservation or its
                 ;; connection indefinitely. The pool's stuck-killer does not
                 ;; cover it either; that reaps the WORKER waiting for the
                 ;; reply, while the conversation is its own process.
                 ;;
                 ;; Rearmed by each suspend!, so an idle-but-healthy dialogue
                 ;; is not killed for being slow between rounds; what it
                 ;; bounds is one step.
                 (let ((watched self))
                   (set-box! watch-box
                     (spawn
                     (lambda ()
                       ;; Parked, poll; RUNNING, sleep until that step's
                       ;; own deadline. A fixed tick made the bound
                       ;; ttl + tick rather than ttl: a step could overrun
                       ;; by most of a tick and finish between samples,
                       ;; and it was accepted -- reply sent, effects kept
                       ;; -- because the next sample saw nothing running.
                       ;; Waking at the deadline itself removes the
                       ;; granularity from the guarantee. Sleeping too long
                       ;; is harmless: every wake re-reads the phase and
                       ;; the start time, so a step that began meanwhile
                       ;; simply gets its own deadline computed next.
                       ;; The parked wait is a RECEIVE, not a sleep: a step
                       ;; starting says so, and the poll behind it is only a
                       ;; backstop for the window before this box is set.
                       ;; Chasing the start by polling faster meant polling
                       ;; every ttl for a small ttl -- a thousand wake-ups a
                       ;; second for a 1ms allowance, on the one thread that
                       ;; runs everything.
                       ;; ARMED MEANS RUNNING, full stop. A running phase
                       ;; always has a deadline, and settling does not
                       ;; change that: safe-key marks the phase running so
                       ;; a key function that hangs is this process's
                       ;; problem, and the linger -- when replays actually
                       ;; arrive -- is settled by definition. Asking for
                       ;; unsettled here excused exactly the case the mark
                       ;; was put there for, and a hung key took the
                       ;; conversation, its caller and every later request
                       ;; to that id with it.
                       ;;
                       ;; What settling does change is whether anything is
                       ;; owed on the way out: see the hook below.
                       (let ((tick (max 50 (div ttl 4)))
                             (armed? (lambda () (unbox running-box))))
                         (let loop ()
                           (if (armed?)
                               (sleep-ms
                                 (max 1 (- (+ (unbox run-start-box) ttl 1)
                                           (now-ms))))
                               (receive (after tick 'tick)
                                 (`#(conv-step-started) 'started)))
                           ;; DECIDE AND KILL AS ONE ACT.
                           ;;
                           ;; Three reads and a kill with interrupts open is
                           ;; not a decision, it is four of them. Between
                           ;; "still running" and the kill the flow can
                           ;; return, publish, and enter its linger -- and
                           ;; the kill then lands on a conversation that has
                           ;; COMMITTED, taking the linger with it. The
                           ;; final reply that linger exists to preserve is
                           ;; gone, and every later retry gets 'settled with
                           ;; no answer instead of the answer.
                           ;;
                           ;; WHAT IS GATED IS THE HOOK, NOT THE KILL. The
                           ;; kill asks two things only: is the process
                           ;; alive, and has the running phase outlived its
                           ;; allowance. A settled conversation can still
                           ;; meet both -- computing a request key marks the
                           ;; phase running during the linger too, so a slow
                           ;; key on a replay is killed like any other
                           ;; overrun. That is deliberate: the alternative
                           ;; is a key function that wedges and holds a
                           ;; process, registered and unreachable, for the
                           ;; life of the VM. The linger and the reply it
                           ;; was retaining are lost, which costs a late
                           ;; retry its answer; the OUTCOME survives, because
                           ;; the kill below re-establishes the record it
                           ;; found rather than overwriting it, so that
                           ;; retry is told 'settled and never something
                           ;; wrong.
                           ;; (This comment used to claim settled-box gated
                           ;; the kill. It never did -- the condition below
                           ;; has always been alive-and-overrun -- so it
                           ;; described an intention the code did not carry
                           ;; out.)
                           ;;
                           ;; on-killed is application code and runs OUTSIDE
                           ;; the region.
                           (let ((overrun?
                                  (lambda ()
                                    (and (armed?)
                                         (> (- (now-ms) (unbox run-start-box))
                                            ttl)))))
                           (cond
                             ((not (process-alive? watched))
                              ;; THE BACKSTOP. This process outlives the one
                              ;; it watches, so it is the last thing that
                              ;; can say anything about a conversation that
                              ;; died some way the conversation itself never
                              ;; got to describe: killed from outside, taken
                              ;; down by a link, a death between deciding
                              ;; and publishing. (An after-thunk raising on
                              ;; the way out of a COMMIT is no longer one of
                              ;; them: the flow's own guard writes
                              ;; 'committed-then-failed for it.)
                              ;; Those paths are an open set --
                              ;; they cannot be enumerated and so cannot be
                              ;; instrumented one by one -- and what they
                              ;; have in common is that they leave the table
                              ;; empty. 'killed is the honest reading of
                              ;; that: it was stopped, and what it had done
                              ;; by then is not knowable from here.
                              ;;
                              ;; First write wins, so a conversation that
                              ;; already published -- settled, or left
                              ;; through its winders whatever it had
                              ;; asserted about its
                              ;; commit -- keeps the answer it gave itself;
                              ;; this only ever fills in a silence.
                              ;;
                              ;; THE OUTCOME-BOX GUARD IS THE REAL ONE
                              ;; here, because first-write-wins only holds
                              ;; while the record exists: a published
                              ;; outcome whose record was pruned would
                              ;; otherwise be overwritten with 'killed by
                              ;; this very line. Unlike the kill branch
                              ;; below, this backstop does not re-insert
                              ;; the outcome it remembers -- it declines to
                              ;; write instead, so such a conversation
                              ;; answers 'unknown rather than a wrong
                              ;; 'gone. It runs for a process that is
                              ;; already dead and cannot be given a second
                              ;; record's worth of table pressure.
                              ;;
                              ;; OUTSIDE the kill atom below, deliberately:
                              ;; that region exists to make deciding and
                              ;; killing indivisible, and this is
                              ;; bookkeeping about something that already
                              ;; happened.
                              (unless (unbox outcome-box)
                                (tomb-record-as! id 'killed))
                              'done)
                             ((not (overrun?)) (loop))
                             (else
                              ;; ONE GRACE TICK. The atom below cannot cover
                              ;; the gap between a flow RETURNING and this
                              ;; process reaching its publication: nothing
                              ;; in the system records that a flow is on its
                              ;; way back. A millisecond is enough for that
                              ;; process to be scheduled, and it moves the
                              ;; bound from ttl to ttl+1ms rather than
                              ;; leaving a committed transaction to be
                              ;; killed and reported rolled back.
                              (sleep-ms 1)
                              (let-values
                                  (((killed run-hook?)
                                    (with-interrupts-disabled
                                      (if (not (and (process-alive? watched)
                                                    (overrun?)))
                                          (values #f #f)
                                          ;; READ BEFORE KILLING, INSIDE THE
                                          ;; ATOM. What decides whether the
                                          ;; hook runs is whether anything
                                          ;; had already described this
                                          ;; conversation when the kill
                                          ;; landed -- and this region is
                                          ;; about to describe it itself, so
                                          ;; the snapshot has to be taken
                                          ;; before that write and before
                                          ;; the kill. Asking afterwards
                                          ;; reads what this very region
                                          ;; just wrote, which would silence
                                          ;; the hook on every kill; asking
                                          ;; outside the atom re-opens the
                                          ;; race the atom exists to close.
                                          (let ((had (unbox outcome-box)))
                                            (kill watched 'conversation-expired)
                                              ;; SAY THAT WE DID IT, in the
                                              ;; same atom. A step killed
                                              ;; after its COMMIT returned
                                              ;; but before it could publish
                                              ;; has not rolled back, and
                                              ;; the kill discarded its
                                              ;; winders, so nothing gave
                                              ;; anything back either:
                                              ;; 'killed, which reads as
                                              ;; 'unknown, is the whole of
                                              ;; what is knowable. First
                                              ;; write wins, so a flow that
                                              ;; published first keeps its
                                              ;; 'settled -- or its
                                              ;; 'rolled-back, written the
                                              ;; instant its exception left
                                              ;; the flow, while the process
                                              ;; is still on its way to
                                              ;; dying of it.
                                              ;;
                                              ;; ...AND SO DOES ONE WHOSE
                                              ;; RECORD WAS PRUNED. First
                                              ;; write wins is decided by
                                              ;; what is in the table, and
                                              ;; a record can be evicted
                                              ;; while its conversation is
                                              ;; still alive -- lingering
                                              ;; after settling, or on its
                                              ;; way out of the guard that
                                              ;; just published a rollback.
                                              ;; Re-inserting the outcome
                                              ;; this region SAW is what
                                              ;; keeps that classification;
                                              ;; the old code re-inserted
                                              ;; 'killed and turned a known
                                              ;; rollback into 'unknown.
                                              ;; (Where the record is still
                                              ;; there, tomb-insert-as! is
                                              ;; first-write-wins and this
                                              ;; changes nothing.)
                                              (let ((o (cond
                                                         (had had)
                                                         ((unbox settled-box) #t)
                                                         (else 'killed))))
                                                (tomb-insert-as! id o)
                                                (unless had
                                                  (set-box! outcome-box o)))
                                              ;; the hook is for a
                                              ;; conversation nothing had
                                              ;; described yet
                                              (values #t (not had)))))))
                                ;; DECLINING TO KILL IS NOT BEING DONE.
                                ;; Before the grace period this branch
                                ;; always killed, so falling out of it was
                                ;; the end of the watchdog's job. Now the
                                ;; re-check can find the step finished in
                                ;; that millisecond -- and returning there
                                ;; left the conversation alive, healthy,
                                ;; and with NOTHING BOUNDING ANY LATER
                                ;; STEP: its wake-up goes to a dead pid,
                                ;; and a step that never returns holds
                                ;; whatever it holds for the life of the
                                ;; VM while its caller waits in a receive
                                ;; that has no deadline.
                                ;; THE KILL PATH PRUNES TOO. Every other
                                ;; way a tombstone is written prunes after
                                ;; it; this one did not, so a workload of
                                ;; nothing but killed conversations grew
                                ;; the table past both its limits -- and
                                ;; those ids are never handed to a caller,
                                ;; so no later query would prune either.
                                ;; Outside the atom: pruning is bookkeeping
                                ;; and does not belong in a region that
                                ;; exists to make the kill indivisible.
                                (when killed (tomb-prune!))
                                (if killed
                                    ;; ...BUT ONLY IF NOTHING SETTLED.
                                    ;; Killing a settled conversation
                                    ;; costs only its linger: its value is
                                    ;; published and its tombstone
                                    ;; written, so a replay falls back to
                                    ;; the record and is told 'settled,
                                    ;; and there is nothing left to give
                                    ;; back.
                                    (when (and on-killed
                                               run-hook?
                                               (not (unbox settled-box)))
                                      ;; AND IT IS TOLD WHETHER A COMMIT
                                      ;; WAS EVER ASSERTED -- confirmed, or
                                      ;; only reported as a maybe. A killed
                                      ;; flow's winders did not run, so
                                      ;; this hook is the last act that can
                                      ;; give anything back -- but "give it
                                      ;; back" means two different things
                                      ;; and only one of them is always
                                      ;; right. A file handle, a
                                      ;; reservation, an in-process hold is
                                      ;; released whatever happened; an
                                      ;; UNDO of the transaction is correct
                                      ;; only where the transaction did not
                                      ;; happen, and running it on a flow
                                      ;; that committed reverses work that
                                      ;; succeeded. The library cannot tell
                                      ;; those two apart inside somebody
                                      ;; else's hook, so it does not try:
                                      ;; it passes the witness and the
                                      ;; application branches. This comment
                                      ;; used to describe that distinction
                                      ;; as though the code made it, while
                                      ;; the condition consulted only
                                      ;; settled-box -- there was nothing
                                      ;; to consult until commit! existed.
                                      ;;
                                      ;; THE WITNESS CAN BE STALE, and not
                                      ;; always by an instant. A kill
                                      ;; landing between the commit
                                      ;; thunk's return and the mark being
                                      ;; set reads #f -- that part is one
                                      ;; instant. But a driver that has
                                      ;; dispatched its request and is
                                      ;; waiting to learn the outcome has
                                      ;; raised nothing yet, so a kill
                                      ;; anywhere in that wait -- which
                                      ;; can be the whole of a timeout --
                                      ;; also reads #f, for a transaction
                                      ;; that may well have taken effect.
                                      ;; Either way the compensation runs
                                      ;; after something may already have
                                      ;; happened. Neither window can be
                                      ;; closed from out here -- the two
                                      ;; facts live in different processes.
                                      ;; So this is not a guarantee that
                                      ;; compensation never follows a
                                      ;; commit; it is a guarantee that it
                                      ;; is not INVITED to. A compensation
                                      ;; that would be destructive if wrong
                                      ;; must be idempotent, or check the
                                      ;; authoritative store itself, rather
                                      ;; than trust this flag alone.
                                      ;; ...in its own supervised process,
                                      ;; so that a hook which raises or
                                      ;; hangs is counted rather than
                                      ;; swallowed -- see run-on-killed!
                                      ;; a BOOLEAN, still: the mark now has
                                      ;; three values but the hook has only
                                      ;; two right answers, and 'uncertain
                                      ;; belongs on the same side as
                                      ;; 'confirmed -- see committed? below
                                      (run-on-killed!
                                        id on-killed
                                        (and (unbox committed-box) #t) ttl))
                                    (loop))))))))))))
                 (let ((who starter) (tag ref)
                       (st (make-step-state 'running #f #f #f #f 0
                                            running-box run-start-box
                                            watch-box)))

                   ;; The one place application code is run on an incoming
                   ;; request. It is bounded -- the phase is marked running,
                   ;; so the watchdog covers a key function that hangs --
                   ;; and it fails safe: a raise yields #f, which the
                   ;; replay rule refuses to match, so the caller gets
                   ;; 'stale rather than somebody else's answer.
                   ;;
                   ;; A computed key is wrapped -- (key), not key -- so
                   ;; that failure is one value no key can collide with,
                   ;; #f included.
                   (define (safe-key r)
                     (let ((k (box #f))
                           (was (step-state-phase st)))
                       (set-phase! st 'running)
                       (guard (e (#t (void)))
                         (set-box! k (list (request-key r))))
                       (set-phase! st was)
                       (unbox k)))

                   (define (suspend! reply)
                     (step-state-steps-set! st (+ 1 (step-state-steps st)))
                     (step-state-awaiting-set! st
                       (fresh-token (step-state-steps st)))
                     (step-state-reply-set! st reply)
                     (set-box! step-box (step-state-steps st))
                     (set-phase! st 'parked)
                     ;; the reply carries the token that answers it
                     ;; ONE SHOT. The destination is whoever is waiting
                     ;; right now, and once answered there is nobody. A
                     ;; flow whose guard swallows 'conversation-expired and
                     ;; parks again would otherwise send its next reply to
                     ;; the caller that finished rounds ago -- a message
                     ;; nothing will ever read, accumulating in a pool
                     ;; worker's mailbox for every round it does that.
                     (when who
                       (send who (vector 'conv-reply tag reply
                                         (step-state-awaiting st)))
                       (set! who #f) (set! tag #f))
                     (serve-steps! st (+ (now-ms) ttl) safe-key
                       (lambda (from ref2 token r)
                         (step-state-consumed-set! st token)
                         (step-state-awaiting-set! st #f)   ; spent
                         (set! who from) (set! tag ref2)
                         (set-phase! st 'running)
                         ;; the key is application code, computed inside the
                         ;; running window the watchdog bounds
                         (step-state-key-set! st (safe-key r))
                         r)
                       ;; RUNNING AGAIN BEFORE THE RAISE. What this raise
                       ;; reaches is application code -- the guard that
                       ;; rolls back what the flow was holding -- and while
                       ;; the phase said 'parked the watchdog skipped it,
                       ;; so a rollback that blocked left a process that was
                       ;; alive, registered, and never coming back. Callers
                       ;; wait for a reply or a DOWN and would have had
                       ;; neither, forever.
                       ;;
                       ;; Entering running restamps the clock, so cleanup
                       ;; gets a TTL of its own rather than the remains of
                       ;; the step's. That is the right allowance: it is a
                       ;; different piece of work.
                       (lambda ()
                         (set-phase! st 'running)
                         (raise 'conversation-expired))))

                   ;; COMMIT THROUGH HERE, or the library cannot tell a
                   ;; rollback from a commit that was followed by a failure.
                   ;;
                   ;; The commit happens INSIDE the flow, and everything the
                   ;; library learns about the flow arrives as "it returned"
                   ;; or "something was raised". Those two do not separate
                   ;; the case that matters: an after-thunk that raises while
                   ;; the flow is unwinding from a SUCCESSFUL commit produces
                   ;; the same raise, through the same winders, as a body
                   ;; that failed before committing anything. Recorded as a
                   ;; rollback, the first tells a caller to retry a
                   ;; transaction that already happened -- and 'gone is the
                   ;; one answer this library says may be retried on.
                   ;;
                   ;; So the fact travels the only way it can: the flow runs
                   ;; its commit as (commit! (lambda () ...)), and the mark
                   ;; is set to 'confirmed the instant that thunk RETURNS.
                   ;; Not before -- a thunk that raises never returns, so
                   ;; nothing is confirmed by it; a thunk that raises the
                   ;; uncertain tag moves the mark to 'uncertain instead,
                   ;; and any other raise leaves it where it was. Between
                   ;; the real commit and the mark there is at best the
                   ;; return itself -- the closest two separate facts can be
                   ;; brought without being one -- and at worst everything
                   ;; the driver does before it decides what to report.
                   ;;
                   ;; WHAT THE MARK ACTUALLY SAYS is what the THUNK said:
                   ;; 'confirmed that it returned, 'uncertain that it
                   ;; reported a maybe, #f that it has claimed nothing.
                   ;; Returning is as close to "the transaction is
                   ;; permanent" as anything outside the thunk can get.
                   ;;
                   ;; A commit primitive that raises AFTER the server made
                   ;; the transaction durable -- an acknowledgement lost on
                   ;; the way back -- cannot be told apart from one that
                   ;; never got there BY ANYTHING OUT HERE. That residue
                   ;; belongs to the commit primitive, and the tag is how it
                   ;; hands it over: a thunk that cannot tell the two apart
                   ;; raises #(commit-uncertain reason) and the conversation
                   ;; is recorded as neither committed nor rolled back. A
                   ;; thunk that raises something else has said the commit
                   ;; did not happen, and is taken at its word.
                   ;;
                   ;; A NON-LOCAL EXIT OUT OF THE THUNK skips the mark too
                   ;; -- an escaping continuation, or suspend! called from
                   ;; inside it. Both are outside the contract (commit! runs
                   ;; the commit and nothing else), and neither can be
                   ;; detected from here; a thunk that does either after a
                   ;; real commit gets the conversation called a rollback.
                   ;;
                   ;; The contract this rests on: ONE CONVERSATION IS ONE
                   ;; LOGICAL TRANSACTION, and commit! is the last state
                   ;; change of THE CONVERSATION -- not of a round, and no
                   ;; new transaction is opened after it. Which is why the
                   ;; mark is STICKY: it is never cleared or lowered, so
                   ;; every later way this conversation can die is described
                   ;; against what the flow had already asserted -- a
                   ;; transaction that happened, or one that may have. A
                   ;; flow that
                   ;; commits, parks, resumes and only then fails is the
                   ;; case that makes the difference -- per-round the answer
                   ;; would have been 'gone, and the caller would have been
                   ;; invited to produce the same effects a second time.
                   ;; A flow that commits, then opens a second transaction
                   ;; and fails in it, is likewise described as "committed,
                   ;; then failed": that is all one mark can say, and it is
                   ;; the safe half to say.
                   ;;
                   ;; The thunk's values are passed back unchanged, HOWEVER
                   ;; MANY there are, so wrapping a commit changes nothing
                   ;; the flow can observe. Binding one value would have
                   ;; been enough for every commit anyone writes -- and a
                   ;; thunk returning none, or two, would then have raised
                   ;; BEFORE the mark was set, so a commit that had already
                   ;; happened would be recorded as a rollback and answered
                   ;; 'gone. That is the very failure this exists to remove,
                   ;; and refusing an arity nobody needs is not worth
                   ;; reintroducing it.
                   ;; A THIRD OUTCOME: "I did something that MAY have taken
                   ;; effect". A commit primitive can be certain it
                   ;; succeeded, certain it never left, or neither -- a
                   ;; request that timed out, a connection reset after the
                   ;; write, a cancelled call, a reply that would not parse.
                   ;; The thunk is the only code that can tell those apart,
                   ;; and until now it had two words for three situations,
                   ;; so the third had to be squeezed into one of them:
                   ;; report failure and the conversation is called rolled
                   ;; back (a retry invitation for something that may have
                   ;; happened), or report success and a rollback is called
                   ;; a commit.
                   ;;
                   ;; So a thunk says it by raising #(commit-uncertain
                   ;; reason). The mark then has three values and rises
                   ;; through them, never falling: #f, 'uncertain,
                   ;; 'confirmed. A flow that catches its own uncertainty
                   ;; and retries the same idempotent commit successfully
                   ;; ends at 'confirmed, which is the truth; one that
                   ;; raises uncertain again after a confirmed commit stays
                   ;; 'confirmed, because the first fact does not expire.
                   ;;
                   ;; MATCHED BY TAG, with a length guard. The vector is a
                   ;; convention, not a type, and an application may raise
                   ;; anything at all -- an empty vector included, which a
                   ;; bare (vector-ref e 0) would turn into an error of this
                   ;; library's own making, inside a commit path.
                   ;;
                   ;; RE-RAISED AS THE SAME OBJECT, not a copy: the flow's
                   ;; own guard is expected to recognise it, and eq? is the
                   ;; cheapest thing to recognise it by.
                   (define (commit-uncertain? e)
                     (and (vector? e)
                          (fx> (vector-length e) 0)
                          (eq? (vector-ref e 0) 'commit-uncertain)))

                   (define (note-uncertain!)
                     (unless (unbox committed-box)     ; never demote
                       (set-box! committed-box 'uncertain)))

                   (define (commit! thunk)
                     (call-with-values
                       (lambda ()
                         (guard (e ((commit-uncertain? e)
                                    (note-uncertain!)
                                    (raise e)))
                           (thunk)))            ; the commit itself
                       (lambda vals
                         (set-box! committed-box 'confirmed)
                         (apply values vals))))

                   ;; THE ONLY PLACE A ROLLBACK IS WITNESSED.
                   ;;
                   ;; An exception that leaves the flow has already run the
                   ;; flow's winders -- its guards, its dynamic-wind
                   ;; after-thunks -- so whatever it held has been given
                   ;; back, and THAT is what 'gone claims. Nothing else in
                   ;; the system was recording it: the process simply died,
                   ;; and the answer was read off an empty table, which is
                   ;; also what a kill from outside leaves.
                   ;;
                   ;; This is one wrapper for every raise the flow can
                   ;; produce, because there is one flow lambda: the first
                   ;; call and every resumed step run inside it, and the
                   ;; park deadline raises 'conversation-expired THROUGH it
                   ;; (see suspend!'s on-expire above), so an expiry the
                   ;; application does not catch arrives here too and is the
                   ;; same fact. A flow that catches it and returns settled
                   ;; instead, and says so below.
                   ;;
                   ;; A GUARD, not an exception handler: the handler would
                   ;; run at the point of the raise, BEFORE the flow's own
                   ;; winders, and would witness a rollback that had not
                   ;; happened yet. A cleanup that then wedges is killed by
                   ;; the watchdog, which is 'killed and 'unknown -- the
                   ;; honest answer, and the one this ordering preserves.
                   ;; Re-raised unchanged, so the process still dies of what
                   ;; the application raised and every monitor sees it.
                   ;;
                   ;; AND WHAT IT WITNESSES IS NOT ALWAYS A ROLLBACK. Leaving
                   ;; the flow through its winders says everything the flow
                   ;; held was given back; it does NOT say the transaction is
                   ;; undone, because an after-thunk can raise while the flow
                   ;; is returning from a commit that already succeeded. This
                   ;; branch used to record every such exit as 'rolled-back,
                   ;; which answers 'gone -- the retry guarantee -- for a
                   ;; conversation that had committed, and the retry performs
                   ;; the transfer a second time. commit! is what tells
                   ;; those apart, and this is the only reader of its mark.
                   ;; PUBLISHED AS ONE ACT, for the reason the completion
                   ;; path below is: the box and the record are one fact
                   ;; about this conversation, and the watchdog reads them.
                   ;; Written separately, a kill could land between them and
                   ;; find a conversation that had already decided it rolled
                   ;; back but had not said so where the kill could see.
                   ;; The prune stays outside -- it walks the table, and a
                   ;; region that cannot be preempted should not.
                   ;; THREE MARKS, THREE RECORDS. The uncertain one is its
                   ;; own tombstone rather than being folded into either
                   ;; neighbour: folded into 'rolled-back it would invite a
                   ;; retry of something that may have happened, and folded
                   ;; into 'committed-then-failed it would carry a
                   ;; certainty the flow never claimed -- and would block
                   ;; the one reconciliation route that is legitimate here
                   ;; (see resolve-unknown).
                   ;;
                   ;; The tag is recognised HERE TOO, as a backstop for a
                   ;; thunk that raised it somewhere other than inside
                   ;; commit!. That is a courtesy, not a guarantee, and the
                   ;; file header says so: the flow's own guard may swallow
                   ;; it first, and a kill discards winders so this handler
                   ;; never runs at all. Raising it inside the commit thunk
                   ;; is the only place with a promise attached.
                   (let ((final (guard (e (#t (begin
                                                (when (commit-uncertain? e)
                                                  (note-uncertain!))
                                                (let ((o (case (unbox committed-box)
                                                           ((confirmed) 'committed-then-failed)
                                                           ((uncertain) 'commit-uncertain-then-failed)
                                                           (else 'rolled-back))))
                                                  (with-interrupts-disabled
                                                    (set-box! outcome-box o)
                                                    (tomb-insert-as! id o))
                                                  (tomb-prune!)))
                                              (raise e)))
                                  (flow req suspend! commit!))))
                     ;; ONE INDIVISIBLE ACT. The watchdog reads the running
                     ;; flag and the clock; between a flow returning and its
                     ;; completion being published there were four separate
                     ;; writes, and the deadline can fall inside them. The
                     ;; watchdog then found a step still marked running and
                     ;; past its allowance, killed a conversation that had
                     ;; ALREADY COMMITTED, and left no tombstone -- so the
                     ;; caller was told 'gone, which this library documents
                     ;; as a rollback guarantee. Committing and then being
                     ;; told it did not happen is the one outcome none of
                     ;; the rest of this file is worth anything without.
                     (with-interrupts-disabled
                       (step-state-reply-set! st final)
                       (step-state-awaiting-set! st #f)
                       (set-phase! st 'completed)
                       (set-box! settled-box #t)
                       (set-box! outcome-box #t)
                       (tomb-insert! id))
                     (tomb-prune!)
                     (when who
                       (send who (vector 'conv-reply tag final 'done))
                       (set! who #f) (set! tag #f))
                     ;; LINGER, then unregister.
                     ;;
                     ;; Exiting here is what made a lost FINAL reply
                     ;; dangerous: the client retries, the process is gone,
                     ;; the resume answers 'gone -- which this library
                     ;; documents as "the transaction rolled back". For a
                     ;; flow that had just COMMITTED that is false, and a
                     ;; client acting on it does the whole thing again.
                     ;;
                     ;; Staying reachable for one more TTL lets that retry
                     ;; be answered with the final reply it lost. The cost
                     ;; is one parked process per completed conversation
                     ;; until the window closes; the TTL is reused because
                     ;; it is already the caller's statement of how long
                     ;; this dialogue may take.
                     ;; the SAME control structure and the SAME rules. A
                     ;; completed conversation has no `awaiting`, so
                     ;; 'advance cannot fire and this needs no special case
                     ;; -- which is what stops a second copy of the
                     ;; classification drifting away from the first.
                     (serve-steps! st (+ (now-ms) ttl) safe-key
                       (lambda (from ref2 token r) 'unreachable)
                       (lambda () 'done))
                     (unregister name)))))))
         conv)))))

  ;; Start the prepared conversation and park until its first suspend!.
  ;; -> (values token first-reply). The id was already handed out by
  ;; prepare!, which is the whole point; this returns what only running it
  ;; can produce.
  ;;
  ;; THE RUNNER IS THE STARTER, deliberately. Everything about who is
  ;; waiting is captured here rather than at prepare!: a handle can be
  ;; prepared in one process and run in another, and the first reply must
  ;; reach whoever is actually parked for it. Captured at prepare!, that
  ;; reply would be sent to the preparer -- an unasked-for message if it is
  ;; alive, and dropped on the floor if it is not, with the runner waiting
  ;; for something that will never come.
  ;;
  ;; The step clock starts here for the same kind of reason. Stamped at
  ;; prepare!, the wait between preparing and running would count as time
  ;; the first step had already spent: prepare, sit for longer than the
  ;; ttl, run, and the watchdog kills the first step the moment it begins.
  (define (conversation-run! h)
    (unless (conv-handle? h)
      (assertion-violation 'conversation-run! "not a conversation handle" h))
    (let ((id (conv-handle-id h)))
      (let* ((ref (gensym))
             (starter self)
             ;; CLAIM, CHECK THE NODE, AND SPAWN AS ONE ACT.
             ;;
             ;; Between "it is still prepared" and "it is mine now" another
             ;; process must not be able to claim it too, and there must be
             ;; no instant where the state says consumed but nothing was
             ;; spawned -- a handle that can never run again and never ran.
             ;; spawn only queues the new process, so it belongs inside;
             ;; the monitor below does not, because monitoring an
             ;; already-dead process delivers its DOWN immediately rather
             ;; than waiting.
             ;;
             ;; THE NODE CHECK IS IN HERE TOO, and that placement is the
             ;; whole of its value. An id carries its owner, and a
             ;; conversation is reachable from other nodes only through
             ;; that; prepare with no node identity, call node-start!, then
             ;; run, and the conversation lives on a clustered node while
             ;; its id has no owner prefix -- so every node, this one
             ;; included, treats it as local and no forwarded resume can
             ;; ever find it. Checked outside the region, that is exactly
             ;; the sequence that still gets through: compare, be
             ;; preempted, have node-start! run, then spawn. There is no
             ;; fixing it afterwards either -- the id is already the
             ;; caller's and may already be persisted -- so the comparison
             ;; and the spawn have to be one act.
             (claim
               (with-interrupts-disabled
                 (let ((s (conv-handle-state h)))
                   (cond
                     ((not (eq? s 'prepared)) (cons 'bad s))
                     ((not (eq? (conv-handle-owner h) (node-self)))
                      (cons 'node (list 'prepared-under (conv-handle-owner h)
                                        'now (node-self))))
                     (else
                       (let ((launch (conv-handle-launch h)))
                         (conv-handle-state-set! h 'consumed)
                         (conv-handle-launch-set! h #f)
                         ;; THE ROUTER GOES UP WITH IT, in this same act.
                         ;; It is what remote peeks and resumes reach, and
                         ;; only a run! ever creates it. Called before the
                         ;; region, an abandoned or mis-noded handle left a
                         ;; router behind; called after it, a runner killed
                         ;; in between leaves a conversation that runs,
                         ;; registers and parks with no router on the node
                         ;; -- so a holder of its id gets 'unreachable for
                         ;; as long as no other conversation happens to
                         ;; start. That is precisely the case this whole
                         ;; two-phase API exists to make recoverable, so
                         ;; the router cannot be left outside the atom.
                         ;; It is idempotent and does nothing unclustered.
                         (ensure-router!)
                         (cons 'ok (launch starter ref)))))))))
        ;; raised out here, as everywhere else in this file
        (when (eq? (car claim) 'bad)
          (assertion-violation 'conversation-run!
            "conversation handle is not prepared" (cdr claim)))
        (when (eq? (car claim) 'node)
          (assertion-violation 'conversation-run!
            "node identity changed between prepare! and run!" (cdr claim)))
        (let ((conv (cdr claim)))
      (let ((m (monitor conv)))
        (receive
          ;; the first suspend! publishes a token, so `status` here is that
          ;; token -- or 'done if the flow returned without suspending at all
          (`#(conv-reply ,@ref ,reply ,status)
            (when m (demonitor m))
            (flush-down! conv)
            (values status reply))
          ;; ASK THE RECORD BEFORE CALLING IT A FAILURE. The retry that
          ;; makes a crash here harmless rests on "nothing had been
          ;; answered yet, and the dead process rolled back" -- and the
          ;; second half is only true where something WITNESSED it. A flow
          ;; that raised left through its winders and says so, and this
          ;; raises the ordinary retryable failure for it. A first step
          ;; that reached its COMMIT and was then stopped has not rolled
          ;; back, and a worker pool re-runs an unanswered task by design,
          ;; so raising the same failure for both is how that commit
          ;; happens twice. The classification comes from settled-or-lost
          ;; and from nowhere else, so it moved with the rest of the rule
          ;; when 'gone stopped being derivable from an absence: a death
          ;; nothing recorded is now 'unknown, and 'unknown is uncertain.
          ;; The id goes with it: without it the caller cannot even
          ;; reconcile what it started.
          (`#(DOWN ,@conv ,reason)
            (let ((outcome (settled-or-lost id)))
              (if (eq? outcome 'gone)
                  (raise (vector 'conversation-failed id reason))
                  (raise (vector 'conversation-uncertain id outcome reason)))))))))))

  ;; Resume the conversation with the next request; parks until the flow
  ;; yields its reply. Returns 'gone when the record says the flow rolled
  ;; back -- for a transactional flow that is the rollback guarantee --
  ;; and 'unknown when the conversation is not here and nothing in reach
  ;; establishes a rollback: no record at all, or a record that says
  ;; something other than one.
  ;; TURNING 'unknown BACK INTO AN ANSWER.
  ;;
  ;; 'unknown is honest and useless: the caller is told not to resubmit and
  ;; left to reconcile. The only construction that can do better is the one
  ;; payment systems already use -- write the conversation id in the SAME
  ;; transaction as the effect -- because then the truth is durable, atomic
  ;; with the thing it describes, and outlives both the record and the
  ;; process. This is the hole that lets the library ask.
  ;;
  ;; It is applied on the ASKING node, not the owner: a predicate is a
  ;; closure and does not cross a link, and the database it consults is the
  ;; application's, which is the same database from either side. So it
  ;; covers the forwarded case without any of it having to travel.
  ;;
  ;; #t -> 'settled, #f -> 'gone, anything else (or a raise) leaves
  ;; 'unknown. A predicate that fails must not turn an honest "I cannot
  ;; say" into a confident wrong answer, and it must not take the caller
  ;; down either.
  ;;
  ;; ...EXCEPT AGAINST A COMMIT WITNESS, which beats the predicate. Some
  ;; node watched commit!'s thunk return and wrote that down -- this one,
  ;; or the owner, which now sends its verdict back with the reply -- so a
  ;; #f --
  ;; "durably not committed" -- is not new information filling a gap, it
  ;; is evidence CONTRADICTING evidence already in hand. A store that
  ;; lags, a read that landed on a replica, an id written under a
  ;; different key: any of them produce that #f, and honouring it answers
  ;; 'gone for a transaction some node saw commit -- which is a retry
  ;; invitation, and the one outcome the whole file is built to refuse. On
  ;; contradiction the honest answer is 'unknown: two sources disagree,
  ;; and neither of them is "it rolled back".
  ;;
  ;; The predicate keeps every case it was added for. It is asked in the
  ;; first place because 'unknown usually means this node knows NOTHING --
  ;; a kill, a record that aged out, no record at all -- and there a #f is
  ;; the only evidence there is, so it still resolves to 'gone. What
  ;; changed is only the one record that already says the commit happened.
  ;;
  ;; THE WITNESS TRAVELS NOW, so this is no longer a local-only defence.
  ;; The predicate is applied on the ASKING node while the tombstone lives
  ;; on the OWNER, and for a while that meant a forwarded call could not
  ;; be defended: the asking node had nothing to contradict a wrong #f
  ;; with. The owner's verdict is carried back in the reply frame (see the
  ;; router), so on a forwarded call `rec` here is this path's projection
  ;; of that verdict -- the owner's tombstone never crosses the mesh.
  ;;
  ;; It is still not universal, and the gap is worth naming: an owner too
  ;; old to send the verdict answers the narrow frame, `rec` is
  ;; record-not-read, and the forwarded call falls back to trusting the
  ;; predicate exactly as it always did. That is the predicate's own
  ;; contract (#f means the authoritative store holds no commit) doing the
  ;; work alone -- correct where the predicate is, which is the same
  ;; assumption the whole `settled?` mechanism rests on.
  ;;
  ;; A CARRIED WITNESS CAN BE STALE, and it does not matter. It reports
  ;; what the owner's record said at the moment it looked, and that record
  ;; may be pruned while the reply is in flight. What it attests -- that commit!
  ;; once returned -- is monotone: no eviction makes that untrue later. A
  ;; stale witness can therefore only hold an answer at 'unknown, never
  ;; open a path to 'gone.
  (define (resolve-unknown id status settled? rec)
    (if (and settled? (eq? status 'unknown))
        ;; call-with-values and a variadic consumer, both INSIDE the guard.
        ;; A predicate that returns no value or several is not a raise, so
        ;; it escaped a guard that only wrapped the call: the wrong-number
        ;; -of-values condition was signalled when the result met a
        ;; single-value binding, outside the handler, and took the whole
        ;; public call down instead of leaving 'unknown standing.
        (guard (e (#t 'unknown))
          (call-with-values
            (lambda () (settled? id))
            (lambda v
              (cond ((and (pair? v) (null? (cdr v)) (eq? (car v) #t)) 'settled)
                    ((and (pair? v) (null? (cdr v)) (eq? (car v) #f))
                     ;; 'killed and no-record carry no commit witness, so
                     ;; the predicate is the only evidence and #f still
                     ;; means rolled back. 'committed-then-failed is the
                     ;; one record that contradicts it.
                     ;;
                     ;; AND 'commit-uncertain-then-failed DELIBERATELY DOES
                     ;; NOT, which is the whole reason the two are separate
                     ;; records. The difference is what a #f MEANS against
                     ;; each of them:
                     ;;   - against a confirmed commit it is a
                     ;;     CONTRADICTION. This library watched commit!'s
                     ;;     thunk return; a store that says otherwise is
                     ;;     lagging, or replicated, or keyed differently,
                     ;;     and the honest answer to two sources
                     ;;     disagreeing is 'unknown.
                     ;;   - against an uncertain one it is NEW
                     ;;     INFORMATION. All this library knows is that the
                     ;;     flow said "this may have landed"; the
                     ;;     authoritative store saying it did not is
                     ;;     precisely the fact that resolves the doubt, and
                     ;;     'gone -- with its licence to retry -- is then
                     ;;     the correct and useful answer.
                     ;; Folding the two records into one would close that
                     ;; second route permanently, leaving every uncertain
                     ;; commit stuck at 'unknown even for a caller that CAN
                     ;; settle the question. The point of the third outcome
                     ;; is to make reconciliation possible, not to add a
                     ;; second way of refusing it.
                     ;;
                     ;; Across a forwarded call this needs nothing extra:
                     ;; rec->evidence maps every record but
                     ;; 'committed-then-failed to 'no-commit-witness, so
                     ;; the new one already travels as "no witness" and
                     ;; arrives here as record-not-read -- the predicate
                     ;; decides, exactly as it does locally.
                     ;;
                     ;; THE RECORD IS THE ONE ALREADY READ, not a second
                     ;; lookup. Asking the table again would be asking a
                     ;; different table: tomb-outcome prunes on the way in,
                     ;; so an entry seen a moment ago can be gone by now --
                     ;; by age, or pushed out by another conversation's
                     ;; insert -- and the witness would vanish exactly when
                     ;; a busy node needs it. record-not-read arrives from
                     ;; the forwarded path, where this node consulted no
                     ;; table at all; it is not a witness and does not
                     ;; pretend to be one.
                     (if (eq? rec 'committed-then-failed)
                         'unknown
                         'gone))
                    (else 'unknown)))))
        status))

  (define (opt-settled? rest who)
    (if (pair? rest)
        (let ((f (car rest)))
          (unless (procedure? f)
            (assertion-violation who
              "settled? must be a procedure of one argument (the id)" f))
          f)
        #f))

  (define (conversation-resume! id token req . rest)
    (let ((owner (conv-owner id))
          (settled? (opt-settled? rest 'conversation-resume!)))
      ;; the forwarded path reads no table on this node, and says so
      (if (or (not owner) (eq? owner (node-self)))
          (let-values (((r status rec) (local-resume id token req)))
            (values r (resolve-unknown id status settled? rec)))
          ;; the verdict now comes FROM THE OWNER when the owner can send
          ;; one -- the whole point of the wide frame -- and this is its
          ;; projection; record-not-read otherwise, exactly as before
          (let-values (((r status rec) (forward-resume owner id token req)))
            (values r (resolve-unknown id status settled? rec))))))

  ;; Resume a conversation that lives on THIS node.
  ;; -> (values reply next-token), where next-token is #f when the
  ;; conversation is over ('gone, 'stale, or a final reply).
  ;; -> (values reply status)
  ;;
  ;; STATUS IS THE ANSWER, reply is only data. A flow may legitimately
  ;; return the symbol 'gone (or 'stale, or 'unreachable) as its final
  ;; value, and putting the control outcome in the same position made that
  ;; indistinguishable from process death -- telling a caller the
  ;; transaction rolled back when it had just committed. The two live in
  ;; different places now, and nothing a flow can return is examined for
  ;; control meaning.
  ;;
  ;;   a token string -- the step ran; present it to continue
  ;;   'done          -- the flow finished; reply is its final answer
  ;;   'stale         -- not applied, and will not be; reply is #f
  ;;   'settled       -- it finished earlier; the answer is not retained
  ;;   'gone          -- it rolled back, on the record; reply is #f
  ;;   'unknown       -- not here, and no rollback established; reply is #f
  ;;   'unreachable   -- the owner node could not be reached; reply is #f
  ;; WHAT THE RECORD MEANS. The only place in this library that turns a
  ;; tombstone into an answer, and the only place that decides what may be
  ;; called 'gone -- everything else either writes a record or asks this.
  ;;
  ;; EVERY ANSWER HERE IS POSITIVE EVIDENCE. 'gone is the rollback
  ;; guarantee, the one answer a caller is told it may retry on, so out of
  ;; what this function can see it comes from a record that says the flow
  ;; rolled back and from nothing else. (A caller's own settled? predicate
  ;; can also produce it, on evidence this library does not hold -- see
  ;; resolve-unknown, which is where that authority is bounded.) It used to
  ;; come from an ABSENCE as well -- no process, no record, and an id young
  ;; enough that a record should still have been there -- which reads a
  ;; positive claim off missing evidence, and every way of dying that
  ;; writes no record made that claim false: a kill from outside, a link
  ;; cascade, a VM going down mid-step. There is no enumerating those.
  ;; Requiring the evidence closes all of them at once, at the cost of
  ;; answering 'unknown where the old code guessed right.
  ;;
  ;; A RECORD IS NOT AUTOMATICALLY A ROLLBACK EITHER, which is the other
  ;; half of the same rule. An exception leaving the flow proves its
  ;; winders ran; it does not prove the transaction was undone, because the
  ;; flow may have been unwinding from a commit that had already succeeded.
  ;; The flow says which by committing through commit!, and the outcomes
  ;; are recorded apart -- 'rolled-back, 'commit-uncertain-then-failed and
  ;; 'committed-then-failed -- so that only the first is ever answered
  ;; 'gone on this evidence alone.
  ;; NO RECORD WAS CONSULTED on this path -- which is not the same fact as
  ;; #f, "the table was consulted and held nothing". A forwarded resume
  ;; never reads this node's table, and saying so explicitly is what keeps
  ;; the witness check below from treating a missing lookup as evidence.
  (define record-not-read 'record-not-read)

  ;; -> (values answer record). The record travels with the answer because
  ;; a second reader would not be asking the same table: tomb-outcome
  ;; prunes on the way in, so between two calls an entry can age out or be
  ;; pushed out by another conversation's insert -- and the second question
  ;; (does this node hold a commit witness?) would then be answered off a
  ;; table that no longer says what the first one saw. One read, two uses.
  (define (settled-or-lost/record id)
    (let ((rec (tomb-outcome id)))
      (values (settled-or-lost-answer rec) rec)))

  (define (settled-or-lost id)
    (let-values (((answer rec) (settled-or-lost/record id)))
      answer))

  (define (settled-or-lost-answer rec)
    (cond ((eq? rec #t) 'settled)
            ;; left through its winders with nothing having asserted a
            ;; commit -- not one that returned, not one reported as a
            ;; maybe -- so it gave back what it held and nothing was made
            ;; permanent
            ((eq? rec 'rolled-back) 'gone)
            ;; left through its winders AFTER its commit returned -- an
            ;; after-thunk, or anything else on the way out, raised once the
            ;; transaction was already permanent. The winders ran, so this
            ;; is not a kill; the commit stands, so it is not a rollback.
            ;; The `else` below would answer 'unknown anyway; it is spelled
            ;; out because a reader asking "what does a flow that committed
            ;; and then failed get told" should find the answer here rather
            ;; than infer it from a fall-through.
            ((eq? rec 'committed-then-failed) 'unknown)
            ;; the flow said its commit MAY have taken effect and then left
            ;; through its winders. Evidence of NEITHER a rollback nor a
            ;; commit -- the transaction really is one or the other, this
            ;; record just cannot say which -- and the `else` below would
            ;; answer 'unknown anyway; spelled out because "may have" is
            ;; exactly the case a reader comes here looking for.
            ((eq? rec 'commit-uncertain-then-failed) 'unknown)
            ;; 'killed, and no record at all, are the same statement --
            ;; stopped, or stopped in a way nothing recorded. A step
            ;; stopped in flight may have committed and may not have;
            ;; saying 'gone is what performs a committed transfer twice.
            (else 'unknown)))

  ;; -> (values reply status record); the record is what settled-or-lost
  ;; read, or record-not-read where the answer came from the live process
  ;; and no table was consulted.
  (define (local-resume id token req)
    (let ((p (whereis (conversation-name id))))
      (if (not p)
          ;; no process -- but did it FINISH, or die? The difference is the
          ;; difference between "your transaction committed" and "it rolled
          ;; back", and answering 'gone for both is how a committed
          ;; transfer gets performed twice.
          (let-values (((status rec) (settled-or-lost/record id)))
            (values #f status rec))
          (let ((ref (gensym))
                (m (monitor p)))
            (send p (vector 'conv-step self ref token req))
            (receive
              (`#(conv-reply ,@ref ,reply ,status)
                (when m (demonitor m))
                (flush-down! p)
                (values reply status record-not-read))
              ;; the process died while we waited: it may have finished
              ;; and lingered out in between, so ask the record
              (`#(DOWN ,@p ,reason)
                (let-values (((status rec) (settled-or-lost/record id)))
                  (values #f status rec))))))))

  ;; What is this conversation waiting for, and what did it last say?
  ;;
  ;; -> (values state token last-reply)
  ;;      'parked    -- present `token` to continue; last-reply is the
  ;;                    reply it is waiting to have answered
  ;;      'completed -- the flow returned; last-reply is its final answer
  ;;                    and no token continues it
  ;;      'settled   -- it finished earlier; only the record is left
  ;;      'gone      -- the record says it rolled back
  ;;      'unknown   -- not here, and nothing in reach establishes a
  ;;                    rollback: no record at all, or a record that says
  ;;                    something other than one
  ;;      'unreachable -- the owner node could not be reached; nothing is
  ;;                    known, exactly as for a resume
  ;;
  ;; conversation-peek/timeout answers from this same set plus one more,
  ;; 'no-answer-yet, which THIS entry point never returns: it waits.
  ;;
  ;; This exists because 'unreachable is not a rollback guarantee and never
  ;; can be: a broken link says nothing about the process behind it. A
  ;; caller left holding that answer had no way to ever settle the
  ;; question -- and the one thing it must not do is resubmit, which is how
  ;; a flow's effects get applied twice. Asking is the alternative.
  ;;
  ;; It NEVER advances the flow. A peek that arrives while a step is
  ;; RUNNING is answered when that step parks, so it can take as long as
  ;; the step does (bounded by the TTL). Reconciliation is not on a
  ;; latency path; taking the answer early would mean guessing.
  ;;
  ;; A caller that DOES have a deadline wants conversation-peek/timeout,
  ;; which gives up at a stated bound and says so, rather than guessing.
  ;; This unbounded form stays the default: the answer it waits for is the
  ;; conversation's own, and for reconciliation that is worth waiting for.
  (define (conversation-peek id . rest)
    (let ((owner (conv-owner id))
          (settled? (opt-settled? rest 'conversation-peek)))
      (if (or (not owner) (eq? owner (node-self)))
          (let-values (((state token reply rec) (local-peek id)))
            (values (resolve-unknown id state settled? rec) token reply))
          (let-values (((state token reply rec) (forward-peek owner id)))
            (values (resolve-unknown id state settled? rec)
                    token reply)))))

  ;; ---- bounded peek ------------------------------------------------------
  ;;
  ;; conversation-peek waits for a RUNNING conversation to reach its next
  ;; park, which is unbounded by design: the question is answered by the
  ;; conversation itself, between steps. That is the right default and the
  ;; wrong thing to have on a latency path, where the asker is usually a
  ;; request handler with a deadline far shorter than a conversation TTL.
  ;;
  ;; Told not to use peek there, a caller's only remaining move is to run
  ;; it in a process of their own and kill that process on a timer -- and
  ;; that is precisely the shape the forwarding paths above had to be made
  ;; safe for. A library whose documented workaround lands on its own
  ;; unsafe path should provide the bounded form instead.
  ;;
  ;; WHY A THROWAWAY PROCESS IS UNAVOIDABLE. The obvious cheaper design --
  ;; keep one process, put `after timeout-ms` on the caller's own receive
  ;; -- does not work, and its failure is not visible from the timeout
  ;; path itself. The answer is not late-and-queued; it does not exist
  ;; yet. The conversation reaches its park AFTER the caller gave up, and
  ;; only then sends. A drain of the mailbox cannot collect a send that
  ;; has not happened, so the message lands later, in whatever this
  ;; process has become -- typically a pooled worker already serving an
  ;; unrelated request, where some broader receive can take it.
  ;;
  ;; Killing a process closes that off, and nothing else does: after the
  ;; kill the inbox is gone and @send drops every later message on the
  ;; floor. On one OS thread there is no third interleaving -- the send
  ;; either happened before the kill (so it is in the mailbox, and the
  ;; drain below finds it) or it happens after (and is discarded).
  ;;
  ;; THE RACE RESOLVES TOWARD THE ANSWER. receive scans the mailbox before
  ;; it takes the timeout branch, so a reply already queued when the timer
  ;; expires wins, and the drain after the kill gives it a second chance.
  ;; 'no-answer-yet is returned only when nothing had arrived by then.
  ;;
  ;; NO settled? PREDICATE HERE, deliberately. Everywhere else it is an
  ;; optional argument; here the mechanism kills the process the call runs
  ;; in, and a predicate is caller code that may hold a database handle or
  ;; a pool lease. Accepting one would mean defining what a kill-safe
  ;; predicate is and making every caller honour it -- a whole contract in
  ;; exchange for an option.
  ;;
  ;; THAT IS A REAL DIFFERENCE IN WHAT THE TWO CALLS CAN ANSWER, and it
  ;; cannot be closed by the caller afterwards. resolve-unknown weighs a
  ;; predicate's #f against the RECORD, and the record is what stops a #f
  ;; from turning a confirmed commit into a retryable 'gone: against
  ;; 'committed-then-failed a #f is a contradiction and is refused, while
  ;; against 'commit-uncertain-then-failed the same #f is the fact that
  ;; settles it. This entry point does not return the record, so a caller
  ;; who takes an 'unknown from here and applies its own predicate cannot
  ;; make that distinction -- it would answer 'gone for a commit this
  ;; library watched succeed, which is a licence to do the work twice.
  ;;
  ;; So the two calls can genuinely disagree about one id, and the
  ;; unbounded conversation-peek is the one to use when a predicate is
  ;; involved. Bounded is for "is there an answer right now", not for
  ;; reconciliation.
  ;;
  ;; LOCAL ONLY IN THIS FORM. A forwarded peek answers 'unreachable rather
  ;; than pretending: bounding it properly means carrying the caller's
  ;; deadline to the owner, or the owner's worker keeps running to the
  ;; forwarding TTL and only the caller has stopped waiting -- a bound in
  ;; name. Carrying it means widening the forwarded frame, which is a
  ;; mixed-version compatibility question of its own.
  ;;
  ;; The timeout has NO DEFAULT because there is no defensible one, and
  ;; because the two ways of being wrong are not symmetric. Too large
  ;; merely waits. Too small reports 'no-answer-yet for a healthy
  ;; conversation the caller could have adopted, and reports it without an
  ;; error, a log line, or any other signal -- a degradation that looks
  ;; exactly like a correct answer.
  ;;
  ;; A request that was already asked when the limit expired is still
  ;; QUEUED at the conversation and is answered when that step parks; the
  ;; reply then goes nowhere. It costs a mailbox entry until then, so a
  ;; caller retrying hard on a slow step accumulates them. (A limit short
  ;; enough to expire before the question was asked leaves nothing queued
  ;; -- which is not a reason to prefer one, only a reason not to read
  ;; 'no-answer-yet as proof that anything was asked.)
  ;;
  ;; Peeks neither advance nor alter the conversation,
  ;; so this is a memory and latency cost rather than a correctness one --
  ;; but throttle on the calling side. Merging concurrent peeks inside the
  ;; library would not remove the queue entry (the answer still comes from
  ;; the conversation), only the duplicates, at the price of a long-lived
  ;; table of waiters here.
  ;;
  ;; -> (values state token reply); state may be 'no-answer-yet
  (define (conversation-peek/timeout id timeout-ms)
    (unless (and (integer? timeout-ms) (exact? timeout-ms) (> timeout-ms 0))
      (assertion-violation 'conversation-peek/timeout
        "timeout must be a positive exact integer number of milliseconds"
        timeout-ms))
    (let ((owner (conv-owner id)))
      (if (or (not owner) (eq? owner (node-self)))
          (bounded-local-peek id timeout-ms)
          (values 'unreachable #f #f))))

  (define (bounded-local-peek id timeout-ms)
    (let* ((caller self)
           ;; Fresh per call, and matched on. Without it the late answer to
           ;; call N is taken by call N+1 out of the same long-lived
           ;; worker's mailbox -- one request served another's answer.
           (ref (fresh-ref!))
           (probe
             ;; spawn, NOT spawn&link. A kill cascades along links, and the
             ;; link here would run straight back to the caller: a
             ;; non-trapping caller would die in the cascade it started, at
             ;; its own timeout. Keep this unlinked -- it looks like an
             ;; oversight and is not.
             (spawn
               (lambda ()
                 ;; Nothing to answer if the caller is already gone: skip
                 ;; the work rather than wake a parked conversation for it.
                 ;; (monitor answers #f when the target is already dead.)
                 ;; This catches a caller that died BEFORE the probe ran;
                 ;; one that dies while the probe waits is caught by the
                 ;; bound below, not by this monitor -- see local-peek*.
                 (let ((m (monitor caller)))
                   (when m
                     (let-values (((state token reply rec)
                                   (local-peek* id timeout-ms)))
                       (demonitor m)
                       ;; If the caller died meanwhile this is dropped: a
                       ;; send to a dead process has nowhere to go.
                       (send caller (vector 'conv-peek-bounded
                                            ref state token reply)))))))))
      (receive (after timeout-ms
                  (begin
                    ;; Kill FIRST, drain second. In this order the kill
                    ;; establishes that no further message can be queued,
                    ;; which is what makes the drain exhaustive rather than
                    ;; a guess; draining first would leave the interval
                    ;; between the two scans open.
                    (kill probe 'peek-timeout)
                    (receive (after 0 (values 'no-answer-yet #f #f))
                      (`#(conv-peek-bounded ,@ref ,state ,token ,reply)
                        (values state token reply)))))
        (`#(conv-peek-bounded ,@ref ,state ,token ,reply)
          (values state token reply)))))

  ;; -> (values state token last-reply record), the record as in local-resume
  (define (local-peek id) (local-peek* id #f))

  ;; limit-ms #f waits for the conversation however long it takes, which is
  ;; what conversation-peek wants. A number bounds the wait and answers
  ;; 'no-answer-yet instead, which is what the bounded probe needs -- and
  ;; needs for its own sake, not the caller's. The probe cannot see its
  ;; caller die: it is parked in the receive below, which matches the
  ;; conversation's reply and the conversation's DOWN and nothing else, so
  ;; a DOWN for the caller would sit unread behind them. A caller killed
  ;; from outside before its own timeout fires therefore kills nobody, and
  ;; an unbounded probe would then wait on a conversation that may never
  ;; park again -- one stranded process per killed caller, permanently.
  ;; The bound is what makes the probe's lifetime its own business.
  (define (local-peek* id limit-ms)
    (let ((p (whereis (conversation-name id))))
      (if (not p)
          (let-values (((state rec) (settled-or-lost/record id)))
            (values state #f #f rec))
          (let ((ref (gensym))
                (m (monitor p)))
            (send p (vector 'conv-peek self ref))
            (let ((answered
                    (lambda (state token reply)
                      (when m (demonitor m))
                      (flush-down! p)
                      (values state token reply record-not-read)))
                  (died
                    (lambda ()
                      (let-values (((state rec) (settled-or-lost/record id)))
                        (values state #f #f rec)))))
              (if limit-ms
                  (receive (after limit-ms
                              (begin
                                (when m (demonitor m))
                                (values 'no-answer-yet #f #f record-not-read)))
                    (`#(conv-peeked ,@ref ,state ,token ,reply)
                      (answered state token reply))
                    (`#(DOWN ,@p ,reason) (died)))
                  (receive
                    (`#(conv-peeked ,@ref ,state ,token ,reply)
                      (answered state token reply))
                    (`#(DOWN ,@p ,reason) (died)))))))))

  ;; The status predicates live in (igropyr conversation-status) and are
  ;; re-exported above. They are one-line eq? tests with no dependencies,
  ;; and keeping them here forced anyone who only wanted to CLASSIFY a
  ;; status to load the scheduler, libuv, the node layer, and this file's
  ;; load-time work -- a clock stamp and a read from /dev/urandom. See
  ;; that file for why it imports nothing beyond (chezscheme).
)
