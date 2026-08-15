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
;;; A FLOW COMMITS THROUGH commit!, and the library learns the transaction
;;; became permanent at the moment it did. Everything else it could observe
;;; -- the flow returned, something was raised -- fails to separate a flow
;;; that rolled back from one that committed and then tripped on the way
;;; out, and those two get opposite answers ('gone, which invites a retry,
;;; versus 'unknown, which does not). ONE CONVERSATION IS ONE LOGICAL
;;; TRANSACTION: commit! runs the conversation's last state change, and no
;;; new transaction is opened after it. The fact is STICKY -- once a
;;; conversation has committed, nothing that happens to it afterwards, in
;;; that round or any later one, is ever reported as a rollback.
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
;;;     either case commit! had NOT returned. For a flow
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
;;;     so it is recorded as rolled back and answers 'gone -- UNLESS the
;;;     conversation had already committed through commit!, in which case
;;;     the winders running does not undo it and it answers 'unknown. A
;;;     flow that commits and then parks until its deadline is the case
;;;     that separates the two, and it holds however many rounds later the
;;;     expiry comes: the commit mark is never cleared.
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
;;;     release those; it runs after the kill, outside the dead process,
;;;     and is called with one argument: whether the conversation had
;;;     COMMITTED when the kill landed. Release what is held in process
;;;     unconditionally; undo the transaction only under (not
;;;     committed?), because undoing one that succeeded is the same
;;;     damage 'gone would have done, arriving by another route.
;;;     THAT ARGUMENT CAN BE A FALSE NEGATIVE, in one instant: a kill
;;;     landing between the commit thunk's return and the mark being set
;;;     passes #f for a transaction that did happen. The window cannot be
;;;     closed from outside the dead process, so an undo that would be
;;;     destructive if wrong must be idempotent, or check the
;;;     authoritative store itself, rather than trust this flag alone.
;;;     #t is never wrong; only #f carries the doubt.
;;;   - a flow that RAISES before its first suspend! AND BEFORE ITS
;;;     commit! makes
;;;     conversation-start! raise #(conversation-failed reason) in the
;;;     caller -- the worker crashes, and the pool's normal retry handles
;;;     it (nothing had been answered yet, and a raise that left the flow
;;;     ran its winders, so the record says rolled back).
;;;   - ...and only then. A first step that may have got past its COMMIT --
;;;     killed for overrunning, killed from outside, taken down by a link,
;;;     or raising after its commit! had returned -- would be repeated by
;;;     re-running an unanswered task. That
;;;     raises #(conversation-uncertain id outcome reason) instead, which
;;;     is NOT retryable: the id is there so the caller can reconcile.
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
          conversation-gone? conversation-stale? conversation-done?
          conversation-settled? conversation-unknown? conversation-set-limits!)
  (import (chezscheme) (igropyr actor)
          (only (igropyr libuv) now-ms)
          (only (igropyr node) node-self rsend monitor-node demonitor-node))

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
                      ;; turns that into 'settled off the tombstone -- which
                      ;; carries the one thing a client that lost its final
                      ;; reply needs to know: it committed. Answering 'stale
                      ;; first is true but poorer, and it wins the race.
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
  ;; four, and the whole design of this file rests on keeping them apart:
  ;;
  ;;   #t             the flow returned: it SETTLED. -> 'settled
  ;;   'rolled-back   the flow raised (or its park deadline raised into it
  ;;                  and nothing caught it) and left through its winders
  ;;                  WITHOUT its commit! having returned, so whatever it
  ;;                  held was given back and nothing was made permanent.
  ;;                  -> 'gone
  ;;   'committed-then-failed
  ;;                  the same exit, but ANY TIME AFTER commit! returned --
  ;;                  in that round or a later one: the winders ran, and
  ;;                  the transaction stands anyway. -> 'unknown
  ;;   'killed        it was stopped in flight: the winders did not run and
  ;;                  the flow may have committed first. -> 'unknown
  ;;
  ;; ...and NO RECORD is 'unknown too, which is the point. 'gone is the
  ;; rollback guarantee a caller retries on, so it has to come from a
  ;; record that SAYS rolled back -- never from the absence of one, and
  ;; never from a record that merely says the flow left through its
  ;; winders. The absence reading was the first half of that defect: a
  ;; process killed from outside, a link cascade, a VM going down all
  ;; leave no record, and every one of them was answered 'gone. Those
  ;; paths are an open set; the rule that
  ;; only positive evidence answers 'gone covers all of them at once,
  ;; including the ones nobody has thought of. The second half was reading
  ;; every exception out of the flow as a rollback, which made 'gone a
  ;; retry invitation for a flow that had committed; commit! is what
  ;; splits that record in two.
  ;;
  ;; The linger covers the window just after completion, but it holds a
  ;; whole process and the retained reply, so it cannot be long. A record
  ;; is two words, so it can be: the answer is no longer available, but
  ;; "this committed" is what a reconciling caller actually needs, and it
  ;; is the opposite of what 'gone would have said.
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
  ;; at all. 'gone now comes from a 'rolled-back record -- and only the
  ;; ones written where commit! had not returned -- and from nothing
  ;; else, which subsumes every case this bounded the damage of.
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
  ;; 'rolled-back left through its winders before committing,
  ;; 'committed-then-failed left through them after, 'killed was stopped in
  ;; flight -- see the head of this section for why those four and not one.
  ;;
  ;; First write wins, and that is the right order in every direction: a
  ;; flow that published before the kill keeps its 'settled, a flow killed
  ;; before it could publish can never publish afterwards, and the
  ;; watchdog's backstop -- which writes 'killed for a death it did not
  ;; cause and cannot classify -- never overwrites a flow that had already
  ;; said what happened to it.
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

  (define (conversation-id!)
    (let ((hex (conv-hex!)) (n (node-self))
          (stamp (ms->b36 (now-ms))))
      (if n
          (string-append (symbol->string n) "~" incarnation "." stamp "-" hex)
          (string-append incarnation "." stamp "-" hex))))

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

  (define ref-counter 0)
  (define (fresh-ref!)
    (with-interrupts-disabled
      (set! ref-counter (+ ref-counter 1))
      ref-counter))

  ;; The owner's router: for each forwarded resume, spawn a worker that
  ;; runs the resume locally and sends the reply straight back to the
  ;; requesting node's temporary reply name. The router itself only
  ;; dispatches, so it is never the bottleneck.
  (define (conv-router-loop)
    (let loop ()
      (receive
        (`#(conv-peek-fwd ,from-node ,reply-name ,ref ,id)
          (spawn
            (lambda ()
              (let-values (((state token reply) (local-peek id)))
                (rsend from-node reply-name
                       (vector 'conv-peek-reply ref state token reply)))))
          (loop))
        (`#(conv-resume ,from-node ,reply-name ,ref ,id ,token ,req)
          (spawn
            (lambda ()
              (let-values (((reply status) (local-resume id token req)))
                (rsend from-node reply-name
                       (vector 'conv-forward-reply ref reply status)))))
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
  (define (forward-peek owner id)
    (let ((reply-name (fresh-reply-name!))
          (ref (fresh-ref!)))
      (register reply-name self)
      (monitor-node owner)
      (dynamic-wind
        (lambda () (void))
        (lambda ()
          (if (rsend owner conv-router-name
                     (vector 'conv-peek-fwd (node-self) reply-name ref id))
              (receive (after conv-forward-ttl-ms (values 'unreachable #f #f))
                (`#(conv-peek-reply ,@ref ,state ,token ,reply)
                  (values state token reply))
                (`#(node-down ,@owner) (values 'unreachable #f #f)))
              (values 'unreachable #f #f)))
        (lambda ()
          (demonitor-node owner)
          (receive (after 0 'ok) (`#(node-down ,@owner) 'ok))
          ;; and the answer itself, if it landed after we gave up. Left
          ;; behind it sits in this process's mailbox -- a pool worker's,
          ;; reused for unrelated work -- where a later broad receive can
          ;; read it as its own.
          (receive (after 0 'ok) (`#(conv-peek-reply ,@ref ,a ,b ,c) 'ok))
          (unregister reply-name)))))

  ;; Forward a resume to the owner node and wait for its reply.
  ;;
  ;; Every failure here answers 'unreachable, NOT 'gone. A link that is
  ;; down and a wait that expired both say the same thing -- we could not
  ;; reach the owner -- and neither says the owner died. Under a partition
  ;; the conversation is still running and can still commit, so calling that
  ;; 'gone would hand the caller a rollback guarantee this layer cannot
  ;; make, and a caller that retries on it duplicates the flow's effects.
  ;;
  ;; Only local-resume can answer 'gone, and only because it asks the
  ;; registry ON THE OWNER'S OWN NODE: no entry there means the process
  ;; really is gone, which for a flow holding a transaction means the
  ;; connection dropped and the database rolled back. That is a fact about
  ;; a process, not about a network.
  (define (forward-resume owner id token req)
    (let ((reply-name (fresh-reply-name!))
          (ref (fresh-ref!)))
      (register reply-name self)
      (monitor-node owner)
      (dynamic-wind
        (lambda () (void))
        (lambda ()
          ;; rsend is #f when the link is already down. That, a node-down
          ;; mid-flight, and the forwarding TTL are all the same statement:
          ;; unreachable. The owner may be dead, or may be committing right
          ;; now -- from here they are indistinguishable.
          (if (rsend owner conv-router-name
                     (vector 'conv-resume (node-self) reply-name ref id token req))
              (receive (after conv-forward-ttl-ms (values #f 'unreachable))
                (`#(conv-forward-reply ,@ref ,reply ,status) (values reply status))
                (`#(node-down ,@owner) (values #f 'unreachable)))
              (values #f 'unreachable)))
        (lambda ()
          (demonitor-node owner)
          ;; demonitor-node does not retract a #(node-down ...) already
          ;; delivered. Left behind, a LATER forward to the same owner --
          ;; after it rebooted -- would match that stale message at once
          ;; and answer 'unreachable at once for an owner that is in fact
          ;; up -- turning a healthy forward into a false failure. Drain it.
          ;; (This used to answer 'gone, which was worse: the caller was
          ;; told the transaction had certainly rolled back.)
          (receive (after 0 'ok) (`#(node-down ,@owner) 'ok))
          ;; same for a reply that arrived after we stopped waiting
          (receive (after 0 'ok) (`#(conv-forward-reply ,@ref ,a ,b) 'ok))
          (unregister reply-name)))))

  ;; Start a conversation. flow: (lambda (req suspend! commit!) ... final-reply).
  ;; suspend! answers the current round and parks until the next resume,
  ;; returning the next request; on TTL expiry it raises
  ;; 'conversation-expired inside the flow. commit! takes a thunk, runs it,
  ;; and marks the conversation committed the moment it returns -- run the
  ;; transaction's commit through it, or an exception on the way out of the
  ;; flow will be recorded as a rollback and answered 'gone. One
  ;; conversation is one logical transaction: commit! is the CONVERSATION's
  ;; last state change, and the mark it sets is sticky -- never cleared, so
  ;; nothing that happens afterwards can call this a rollback. The flow's
  ;; return value is
  ;; the final round's reply; the process then lingers one more TTL, so a
  ;; lost final reply can still be replayed, and unregisters after it.
  ;; Returns (values id token first-reply); the caller parks meanwhile.
  ;; Optional trailing arguments: ttl-ms (default 300000), request-key
  ;; (default values), on-killed (default #f) -- each documented at its
  ;; binding below. on-killed takes one argument, committed?, and is
  ;; rejected here if it cannot accept one.
  (define (conversation-start! flow req . opts)
    (ensure-router!)
    ;; A ttl that is not a positive exact integer reaches receive's `after`
    ;; and raises THERE -- inside the conversation process, after it has
    ;; already handed back an id and a token. The caller sees a healthy
    ;; start and a 'gone on its next resume, with nothing anywhere saying
    ;; why. Checked here, where it was written.
    (when (pair? opts)
      (let ((t (car opts)))
        (unless (and (integer? t) (exact? t) (> t 0))
          (assertion-violation 'conversation-start!
            "ttl-ms must be a positive exact integer" t))))
    ;; ...and on-killed is checked here for a sharper version of the same
    ;; reason. It is CALLED in the watchdog's process, inside a guard that
    ;; swallows everything so that a bad hook cannot take the watchdog down
    ;; -- which means a hook of the wrong shape does not fail loudly, it
    ;; fails SILENTLY: the arity error is caught, the compensation never
    ;; runs, and whatever the flow was holding is held for the life of the
    ;; VM with nothing anywhere saying why. That is the worst way for an
    ;; interface change to be discovered, so the shape is settled at the
    ;; point it was written, where the raise reaches the code that is
    ;; wrong.
    ;;
    ;; Accepting one argument, not accepting EXACTLY one: a variadic hook
    ;; and one with optionals are both fine, and the only thing worth
    ;; refusing is a hook that cannot be told whether the transaction
    ;; committed.
    (when (and (pair? opts) (pair? (cdr opts)) (pair? (cddr opts))
               (caddr opts))
      (let ((h (caddr opts)))
        (unless (and (procedure? h) (logbit? 1 (procedure-arity-mask h)))
          (assertion-violation 'conversation-start!
            "on-killed must be a procedure accepting one argument (committed?)"
            h))))
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
           ;; So: a procedure of one argument, run after the kill, in the
           ;; watchdog's own
           ;; process. It cannot touch the flow's stack (that is gone); it
           ;; releases what the flow was holding, which the application
           ;; reaches through whatever it closed over. Its own exceptions
           ;; are swallowed -- the watchdog must survive a bad hook.
           ;;
           ;; THE ARGUMENT IS committed? -- whether this conversation had
           ;; got past its commit! when the kill landed. The hook has two
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
           ;; committed? IS ONE-SIDED. #t is never wrong -- the mark is
           ;; only ever set by a commit thunk that returned, and it is
           ;; never cleared. #f can be one instant stale: a kill landing
           ;; between that return and the mark being set reads #f for a
           ;; transaction that did happen, and the window is the return
           ;; itself, which cannot be closed from another process (see the
           ;; watchdog's call site). So #f means "no witness", not "proof
           ;; it did not commit". An undo that is destructive when wrong
           ;; must be idempotent, or consult the authoritative store,
           ;; rather than rest on this flag alone; releasing a handle,
           ;; which is unconditional anyway, never has the problem.
           (on-killed
             (if (and (pair? opts) (pair? (cdr opts)) (pair? (cddr opts)))
                 (caddr opts)
                 #f))
           (id (conversation-id!))
           (name (conversation-name id))
           (starter self)
           (ref (gensym))
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
           ;; SET WHEN SOMETHING THAT KNEW WHAT HAPPENED SAID SO -- the
           ;; flow returning, an exception leaving the flow, or the
           ;; watchdog's own kill. It is what the backstop below asks
           ;; before filling in a silence, and it is a BOX rather than a
           ;; lookup in the table for the same reason settled-box is: the
           ;; table forgets. A conversation whose record is evicted while
           ;; its watchdog is still winding down would otherwise be
           ;; described a second time, by the one process that does not
           ;; know what happened to it -- which costs a slot, evicts a
           ;; live record to get it, and puts the wrong outcome in the
           ;; entry it leaves behind.
           (recorded-box (box #f))
           ;; DID THIS CONVERSATION GET PAST ITS COMMIT? Set by commit! the
           ;; instant the thunk it was given returns, and NEVER CLEARED --
           ;; there is no clearing point anywhere in this file. One
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
                           ;; A flow that already returned is never a step
                           ;; that overran, so settled-box gates the KILL and
                           ;; not merely the hook: computing a request key
                           ;; marks the phase running during the linger too,
                           ;; and a slow key on a replay would otherwise
                           ;; still bring the watchdog down on a finished
                           ;; conversation. It holds nothing by then.
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
                              ;; through its winders either side of its
                              ;; commit -- keeps the answer it gave itself;
                              ;; this only ever fills in a silence.
                              ;;
                              ;; OUTSIDE the kill atom below, deliberately:
                              ;; that region exists to make deciding and
                              ;; killing indivisible, and this is
                              ;; bookkeeping about something that already
                              ;; happened.
                              (unless (unbox recorded-box)
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
                              (let ((killed
                                     (with-interrupts-disabled
                                       (and (process-alive? watched)
                                            (overrun?)
                                            (begin
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
                                              ;; a settled record can be
                                              ;; evicted while its
                                              ;; conversation is still
                                              ;; lingering -- after which
                                              ;; this would overwrite a
                                              ;; certain answer with an
                                              ;; uncertain one. The flag is
                                              ;; still here to be read.
                                              (tomb-insert-as!
                                                id
                                                (if (unbox settled-box)
                                                    #t
                                                    'killed))
                                              (set-box! recorded-box #t)
                                              #t)))))
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
                                               (not (unbox settled-box)))
                                      ;; AND IT IS TOLD WHETHER THE
                                      ;; TRANSACTION COMMITTED. A killed
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
                                      ;; THE WITNESS CAN BE ONE INSTANT
                                      ;; STALE. A kill landing between the
                                      ;; commit thunk's return and the mark
                                      ;; being set reads #f, and the
                                      ;; compensation runs after a commit
                                      ;; that really happened. The window
                                      ;; is the return itself and cannot be
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
                                      (guard (e (#t (void)))
                                        (on-killed (unbox committed-box))))
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
                   ;; is set the instant that thunk RETURNS. Not before -- a
                   ;; thunk that raises never returns, and the mark stays
                   ;; off. The window between the real commit and the
                   ;; mark is the return itself, which is the closest two
                   ;; separate facts can be brought without being one.
                   ;;
                   ;; WHAT THE MARK ACTUALLY SAYS is "the thunk returned",
                   ;; and that is as close to "the transaction is permanent"
                   ;; as anything outside the thunk can get. A commit
                   ;; primitive that raises AFTER the server made the
                   ;; transaction durable -- an acknowledgement lost on the
                   ;; way back -- is indistinguishable here from one that
                   ;; never got there, and this records the second. That
                   ;; residue belongs to the commit primitive, not to this:
                   ;; a thunk that cannot tell the two apart should raise
                   ;; something the flow turns into its own uncertainty
                   ;; rather than let the conversation be called a rollback.
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
                   ;; mark is STICKY: it is never cleared, so every later
                   ;; way this conversation can die is described against a
                   ;; transaction that already happened. A flow that
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
                   (define (commit! thunk)
                     (call-with-values thunk   ; the commit itself
                       (lambda vals
                         (set-box! committed-box #t)
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
                   ;; the transfer a second time. commit! is what separates
                   ;; the two, and this is the only reader of its mark.
                   (let ((final (guard (e (#t (set-box! recorded-box #t)
                                              (tomb-record-as! id
                                                (if (unbox committed-box)
                                                    'committed-then-failed
                                                    'rolled-back))
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
                       (set-box! recorded-box #t)
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
      (let ((m (monitor conv)))
        (receive
          ;; the first suspend! publishes a token, so `status` here is that
          ;; token -- or 'done if the flow returned without suspending at all
          (`#(conv-reply ,@ref ,reply ,status)
            (when m (demonitor m))
            (flush-down! conv)
            (values id status reply))
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
                  (raise (vector 'conversation-failed reason))
                  (raise (vector 'conversation-uncertain id outcome reason)))))))))

  ;; Resume the conversation with the next request; parks until the flow
  ;; yields its reply. Returns 'gone when the record says the flow rolled
  ;; back -- for a transactional flow that is the rollback guarantee --
  ;; and 'unknown when the conversation is not here and no record says
  ;; what became of it.
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
  ;; ...EXCEPT AGAINST A LOCAL WITNESS, which beats the predicate. This
  ;; node watched commit!'s thunk return and wrote that down, so a #f --
  ;; "durably not committed" -- is not new information filling a gap, it
  ;; is evidence CONTRADICTING evidence already in hand. A store that
  ;; lags, a read that landed on a replica, an id written under a
  ;; different key: any of them produce that #f, and honouring it answers
  ;; 'gone for a transaction that this node saw commit -- which is a retry
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
  ;; ASYMMETRIC ACROSS A FORWARD, deliberately. The predicate is applied
  ;; on the ASKING node, and for a forwarded resume the owner's tombstone
  ;; is on the OWNER -- so there is no local witness to contradict and
  ;; this check cannot fire. That is a defence for the local case only,
  ;; and it is not a weakening of the forwarded one: the predicate's own
  ;; contract (#f means the authoritative store holds no commit) is what
  ;; carries both, and this adds a degenerate cross-check where a second,
  ;; independent record happens to be within reach.
  (define (resolve-unknown id status settled?)
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
                     (if (eq? (tomb-outcome id) 'committed-then-failed)
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
      (let-values (((r status)
                    (if (or (not owner) (eq? owner (node-self)))
                        (local-resume id token req)
                        (forward-resume owner id token req))))
        (values r (resolve-unknown id status settled?)))))

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
  ;;   'unknown       -- not here and not knowable from here; reply is #f
  ;;   'unreachable   -- the owner node could not be reached; reply is #f
  ;; WHAT THE RECORD MEANS. The only place in this library that turns a
  ;; tombstone into an answer, and the only place that decides what may be
  ;; called 'gone -- everything else either writes a record or asks this.
  ;;
  ;; EVERY ANSWER HERE IS POSITIVE EVIDENCE. 'gone is the rollback
  ;; guarantee, the one answer a caller is told it may retry on, so it
  ;; comes from a record that says the flow rolled back and from nothing
  ;; else. It used to come from an ABSENCE as well -- no process, no
  ;; record, and an id young enough that a record should still have been
  ;; there -- which reads a positive claim off missing evidence, and every
  ;; way of dying that writes no record made that claim false: a kill from
  ;; outside, a link cascade, a VM going down mid-step. There is no
  ;; enumerating those. Requiring
  ;; the evidence closes all of them at once, at the cost of answering
  ;; 'unknown where the old code guessed right.
  ;;
  ;; A RECORD IS NOT AUTOMATICALLY A ROLLBACK EITHER, which is the other
  ;; half of the same rule. An exception leaving the flow proves its
  ;; winders ran; it does not prove the transaction was undone, because the
  ;; flow may have been unwinding from a commit that had already succeeded.
  ;; The flow says which by committing through commit!, and the two
  ;; outcomes are recorded apart -- 'rolled-back and 'committed-then-failed
  ;; -- so that only the first is ever answered 'gone.
  (define (settled-or-lost id)
    (let ((rec (tomb-outcome id)))
      (cond ((eq? rec #t) 'settled)
            ;; left through its winders WITHOUT having committed: it gave
            ;; back what it held, and there is nothing to give back that it
            ;; had already made permanent
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
            ;; 'killed, and no record at all, are the same statement --
            ;; stopped, or stopped in a way nothing recorded. A step
            ;; stopped in flight may have committed and may not have;
            ;; saying 'gone is what performs a committed transfer twice.
            (else 'unknown))))

  (define (local-resume id token req)
    (let ((p (whereis (conversation-name id))))
      (if (not p)
          ;; no process -- but did it FINISH, or die? The difference is the
          ;; difference between "your transaction committed" and "it rolled
          ;; back", and answering 'gone for both is how a committed
          ;; transfer gets performed twice.
          (values #f (settled-or-lost id))
          (let ((ref (gensym))
                (m (monitor p)))
            (send p (vector 'conv-step self ref token req))
            (receive
              (`#(conv-reply ,@ref ,reply ,status)
                (when m (demonitor m))
                (flush-down! p)
                (values reply status))
              ;; the process died while we waited: it may have finished
              ;; and lingered out in between, so ask the record
              (`#(DOWN ,@p ,reason)
                (values #f (settled-or-lost id))))))))

  ;; What is this conversation waiting for, and what did it last say?
  ;;
  ;; -> (values state token last-reply)
  ;;      'parked    -- present `token` to continue; last-reply is the
  ;;                    reply it is waiting to have answered
  ;;      'completed -- the flow returned; last-reply is its final answer
  ;;                    and no token continues it
  ;;      'settled   -- it finished earlier; only the record is left
  ;;      'gone      -- the record says it rolled back
  ;;      'unknown   -- not here, and no record says what became of it
  ;;      'unreachable -- the owner node could not be reached; nothing is
  ;;                    known, exactly as for a resume
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
  (define (conversation-peek id . rest)
    (let ((owner (conv-owner id))
          (settled? (opt-settled? rest 'conversation-peek)))
      (let-values (((state token reply)
                    (if (or (not owner) (eq? owner (node-self)))
                        (local-peek id)
                        (forward-peek owner id))))
        (values (resolve-unknown id state settled?) token reply))))

  (define (local-peek id)
    (let ((p (whereis (conversation-name id))))
      (if (not p)
          (values (settled-or-lost id) #f #f)
          (let ((ref (gensym))
                (m (monitor p)))
            (send p (vector 'conv-peek self ref))
            (receive
              (`#(conv-peeked ,@ref ,state ,token ,reply)
                (when m (demonitor m))
                (flush-down! p)
                (values state token reply))
              (`#(DOWN ,@p ,reason)
                (values (settled-or-lost id) #f #f)))))))

  ;; THE ROLLBACK GUARANTEE, and the only answer that is one. A record
  ;; says the flow rolled back: it raised, or its park deadline raised
  ;; into it and nothing caught that, and either way it left through its
  ;; winders. This is what a caller may retry on.
  ;;
  ;; Applied to the STATUS, never to the reply. A flow may return the
  ;; symbol 'gone as a perfectly ordinary answer; only the status carries
  ;; control meaning.
  (define (conversation-gone? x) (eq? x 'gone))

  ;; Neither confirmed. The conversation is not here and no record says
  ;; what became of it -- it was stopped in flight, killed from outside,
  ;; taken down by a link, or its record aged out, was pushed out by newer
  ;; ones, or belonged to an earlier incarnation of this process. DO NOT
  ;; RESUBMIT: that is the one action this answer cannot license.
  ;; Reconcile against your own state instead, which is the only place the
  ;; truth still is.
  ;;
  ;; THIS IS THE DEFAULT, and that is the change worth knowing about.
  ;; Everywhere this appears, 'gone was previously returned as though a
  ;; missing record were a rollback guarantee -- a positive claim read off
  ;; an absence, and wrong for every death path that writes no record.
  (define (conversation-unknown? x) (eq? x 'unknown))

  ;; The flow returned: reply is its final answer, and no token continues
  ;; it. Distinguishing this from 'gone is what tells a caller whether the
  ;; transaction committed.
  (define (conversation-done? x) (eq? x 'done))

  ;; The flow finished, but its answer is no longer retained -- the linger
  ;; window closed and only the record of completion is left. For a
  ;; transactional flow this is the OPPOSITE of 'gone: it committed. Read
  ;; your own state for the details; do not resubmit.
  (define (conversation-settled? x) (eq? x 'settled))

  ;; The request named a reply that is no longer the one being answered --
  ;; a duplicate, a retry, a second front end. It was NOT applied and will
  ;; not be, which is a fact about this conversation rather than a guess.
  ;;
  ;; It says nothing about whether the request it duplicates succeeded: the
  ;; step it was trying to repeat may well have run for whoever got there
  ;; first. A caller that reaches here should read the current state, not
  ;; resubmit -- it has no valid token to resubmit with, which is the point.
  (define (conversation-stale? x) (eq? x 'stale))
)
