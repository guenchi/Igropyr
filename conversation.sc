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
;;;       (lambda (req suspend!)
;;;         (let ((tx (begin-tx!)))          ; live state, held across rounds
;;;           (guard (e (#t (rollback! tx) (raise e)))
;;;             (let ((req2 (suspend! first-reply)))   ; answer, park, resume
;;;               (commit! tx)
;;;               final-reply))))
;;;       req))
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
;;; the window closes. Past it, 'gone can no longer tell a flow that died
;;; from one that finished long ago, so size the TTL to cover the retry
;;; window your clients actually use.
;;;
;;; Fault semantics (the transaction-ring contract):
;;;   - flow crashes, TTL expires, or the process dies for any reason
;;;     -> the process is unregistered automatically; every later resume
;;;     returns 'gone. For a flow holding a database transaction, dead
;;;     process = dropped connection = the database itself rolled back:
;;;     'gone GUARANTEES the transaction did not commit.
;;;   - 'unreachable is NOT that guarantee. A resume forwarded to another
;;;     node answers it when the link went down or the forwarding wait
;;;     expired: both prove that WE could not reach the owner, neither
;;;     proves the owner died. Under a partition the conversation keeps
;;;     running and may still commit. Treating it as 'gone and retrying is
;;;     how a flow's effects get applied twice -- exactly what the ring
;;;     exists to prevent. Retry only on 'gone; on 'unreachable the
;;;     outcome is unknown, so reconcile rather than resubmit.
;;;   - TTL EXPIRY HAS TWO PATHS, and only one of them raises.
;;;     A conversation that sat PARKED too long is raised at:
;;;     'conversation-expired reaches the flow, a guard runs, and it can
;;;     roll back explicitly (re-raise, or don't catch, so the process
;;;     exits).
;;;     A STEP that overruns is KILLED -- that is what the watchdog is
;;;     for, and a step stuck in a loop or a foreign call cannot be raised
;;;     at. @kill discards dynamic-wind winders, so the flow's guard does
;;;     NOT run. A pooled database connection is still safe: the pool
;;;     monitors its borrower and rebuilds the connection when it dies,
;;;     which drops the transaction. Anything held IN PROCESS is not --
;;;     a reservation, a file handle, an in-memory hold. Pass an
;;;     on-killed thunk (conversation-start!'s fifth argument) to release
;;;     those; it runs after the kill, outside the dead process.
;;;   - a crash before the first suspend! makes conversation-start!
;;;     raise #(conversation-failed reason) in the caller -- the worker
;;;     crashes, and the pool's normal retry handles it (nothing had
;;;     been answered yet, and the dead process rolled back).
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
          conversation-settled? conversation-set-limits!)
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
            (mutable issued)       ; every token handed out by this dialogue
            running-box run-start-box))

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
      (set-box! (step-state-running-box st) (eq? phase 'running))))

  (define (token=? a b)
    (and a b (string? a) (string? b) (string=? a b)))

  ;; The next token, guaranteed different from EVERY token this
  ;; conversation has issued -- not merely from the one just spent.
  ;;
  ;; Excluding only the previous one left the invariant probabilistic where
  ;; it mattered: a token repeating one from two steps back becomes the
  ;; live `awaiting`, and a delayed copy of the request that carried it the
  ;; first time then classifies as 'advance -- before the request key is
  ;; ever computed. An old payload is applied to a later step and its
  ;; sender receives that step's reply. Sixty-four random bits make it
  ;; unlikely; the list makes it impossible, and the list is one entry per
  ;; suspend of one conversation.
  (define (fresh-token issued)
    (let loop ((t (conv-token!)))
      (if (memp (lambda (x) (token=? t x)) issued)
          (loop (conv-token!))
          t)))

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
                    (on-expire)
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

  ;; ---- completed-conversation tombstones ---------------------------------
  ;;
  ;; 'gone means "no process here". For a conversation that DIED -- crashed,
  ;; expired -- that is the rollback guarantee, because a dead process is a
  ;; dropped connection and the database rolled back on its own. For one
  ;; that COMPLETED it is false: the flow committed and then exited, and a
  ;; caller told "rolled back" does the whole thing again.
  ;;
  ;; The linger covers the window just after completion, but it holds a
  ;; whole process and the retained reply, so it cannot be long. A
  ;; tombstone is an id and an outcome, so it can be: the answer is no
  ;; longer available, but "this committed" is what a reconciling caller
  ;; actually needs, and it is the opposite of what 'gone would have said.
  ;;
  ;; BOUNDED, by age and by count, because an unbounded record of every
  ;; conversation that ever finished is a leak with a long fuse. Past
  ;; either bound an entry is dropped and 'gone becomes ambiguous again --
  ;; that is the honest limit of this mechanism, and the reason both bounds
  ;; are settable.
  (define tombstone-max 10000)
  (define tombstone-ttl-ms 3600000)    ; one hour

  (define tombstones (make-hashtable string-hash string=?))
  (define tomb-front '())              ; oldest first
  (define tomb-back '())               ; newest, reversed
  (define tomb-n 0)

  (define (tomb-pop-oldest!)
    (when (null? tomb-front)
      (set! tomb-front (reverse tomb-back))
      (set! tomb-back '()))
    (unless (null? tomb-front)
      (let ((e (car tomb-front)))
        (set! tomb-front (cdr tomb-front))
        (set! tomb-n (- tomb-n 1))
        (hashtable-delete! tombstones (car e)))))

  ;; ALL THREE OF THESE RUN WITH INTERRUPTS DISABLED. They are pure memory
  ;; and never yield, and the alternative is a race with teeth: prune reads
  ;; the oldest entry, checks its age, and then calls a pop that re-reads
  ;; the head. Two conversations completing at once could interleave there
  ;; -- the second prune drops the entry the first had just approved of,
  ;; and the first then drops whatever moved up, which is a YOUNGER record
  ;; still inside both limits. The transaction it belonged to answers
  ;; 'gone afterwards, and 'gone is documented as "rolled back".
  (define (tomb-prune!)
    (with-interrupts-disabled
    (let loop ()
      (when (> tomb-n 0)
        (when (null? tomb-front)
          (set! tomb-front (reverse tomb-back))
          (set! tomb-back '()))
        (let ((e (and (pair? tomb-front) (car tomb-front))))
          (when (and e (or (> tomb-n tombstone-max)
                           (> (- (now-ms) (cdr e)) tombstone-ttl-ms)))
            (tomb-pop-oldest!)
            (loop)))))))

  (define (tomb-record! id)
    (with-interrupts-disabled
      (unless (hashtable-contains? tombstones id)
        (hashtable-set! tombstones id #t)
        (set! tomb-back (cons (cons id (now-ms)) tomb-back))
        (set! tomb-n (+ tomb-n 1))))
    (tomb-prune!))

  (define (tomb-settled? id)
    (tomb-prune!)
    (with-interrupts-disabled
      (hashtable-contains? tombstones id)))

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

  ;; The id carries the owner node so a resume on any node reaches it:
  ;; "<node>~<hex>" when clustered, bare "<hex>" on a single node. The
  ;; hex stays unguessable either way; the node prefix is not a secret.
  (define (conversation-id!)
    (let ((hex (conv-hex!)) (n (node-self)))
      (if n (string-append (symbol->string n) "~" hex) hex)))

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

  ;; Start a conversation. flow: (lambda (req suspend!) ... final-reply).
  ;; suspend! answers the current round and parks until the next resume,
  ;; returning the next request; on TTL expiry it raises
  ;; 'conversation-expired inside the flow. The flow's return value is
  ;; the final round's reply; the process then unregisters and exits.
  ;; Returns (values id first-reply); the caller parks meanwhile.
  ;; Optional trailing argument: ttl-ms (default 300000).
  (define (conversation-start! flow req . opts)
    (ensure-router!)
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
           ;; So: a thunk, run after the kill, in the watchdog's own
           ;; process. It cannot touch the flow's stack (that is gone); it
           ;; releases what the flow was holding, which the application
           ;; reaches through whatever it closed over. Its own exceptions
           ;; are swallowed -- the watchdog must survive a bad hook.
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
                       (let ((tick (max 50 (div ttl 4))))
                         (let loop ()
                           (sleep-ms
                             (if (unbox running-box)
                                 (max 1 (- (+ (unbox run-start-box) ttl 1)
                                           (now-ms)))
                                 tick))
                           (cond
                             ((not (process-alive? watched)) 'done)
                             ;; parked in suspend!: idle between rounds is
                             ;; not what this bounds
                             ((not (unbox running-box)) (loop))
                             ;; running, and running for longer than one
                             ;; step is allowed
                             ((> (- (now-ms) (unbox run-start-box)) ttl)
                              (kill watched 'conversation-expired)
                              ;; the flow's winders did not run; this is
                              ;; the only chance to release what it held
                              (when on-killed
                                (guard (e (#t (void))) (on-killed))))
                             (else (loop))))))))
                 (let ((who starter) (tag ref)
                       (st (make-step-state 'running #f #f #f #f 0 '()
                                            running-box run-start-box)))

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
                     (let ((t (fresh-token (step-state-issued st))))
                       (step-state-issued-set! st
                         (cons t (step-state-issued st)))
                       (step-state-awaiting-set! st t))
                     (step-state-reply-set! st reply)
                     (set-box! step-box (step-state-steps st))
                     (set-phase! st 'parked)
                     ;; the reply carries the token that answers it
                     (send who (vector 'conv-reply tag reply
                                       (step-state-awaiting st)))
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

                   (let ((final (flow req suspend!)))
                     (step-state-reply-set! st final)
                     (step-state-awaiting-set! st #f)
                     (set-phase! st 'completed)
                     (tomb-record! id)
                     (send who (vector 'conv-reply tag final 'done))
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
          (`#(DOWN ,@conv ,reason)
            (raise (vector 'conversation-failed reason)))))))

  ;; Resume the conversation with the next request; parks until the flow
  ;; yields its reply. Returns 'gone when the conversation is over,
  ;; expired, or crashed -- for a transactional flow that means the
  ;; database already rolled back.
  (define (conversation-resume! id token req)
    (let ((owner (conv-owner id)))
      (if (or (not owner) (eq? owner (node-self)))
          (local-resume id token req)
          (forward-resume owner id token req))))

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
  ;;   'gone          -- unreachable here; reply is #f
  ;;   'unreachable   -- the owner node could not be reached; reply is #f
  (define (local-resume id token req)
    (let ((p (whereis (conversation-name id))))
      (if (not p)
          ;; no process -- but did it FINISH, or die? The difference is the
          ;; difference between "your transaction committed" and "it rolled
          ;; back", and answering 'gone for both is how a committed
          ;; transfer gets performed twice.
          (values #f (if (tomb-settled? id) 'settled 'gone))
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
                (values #f (if (tomb-settled? id) 'settled 'gone))))))))

  ;; What is this conversation waiting for, and what did it last say?
  ;;
  ;; -> (values state token last-reply)
  ;;      'parked    -- present `token` to continue; last-reply is the
  ;;                    reply it is waiting to have answered
  ;;      'completed -- the flow returned; last-reply is its final answer
  ;;                    and no token continues it
  ;;      'gone      -- not reachable here (died, expired, or its linger
  ;;                    window closed)
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
  (define (conversation-peek id)
    (let ((owner (conv-owner id)))
      (if (or (not owner) (eq? owner (node-self)))
          (local-peek id)
          (forward-peek owner id))))

  (define (local-peek id)
    (let ((p (whereis (conversation-name id))))
      (if (not p)
          (values (if (tomb-settled? id) 'settled 'gone) #f #f)
          (let ((ref (gensym))
                (m (monitor p)))
            (send p (vector 'conv-peek self ref))
            (receive
              (`#(conv-peeked ,@ref ,state ,token ,reply)
                (when m (demonitor m))
                (flush-down! p)
                (values state token reply))
              (`#(DOWN ,@p ,reason)
                (values (if (tomb-settled? id) 'settled 'gone) #f #f)))))))

  ;; Applied to the STATUS, never to the reply. A flow may return the
  ;; symbol 'gone as a perfectly ordinary answer; only the status carries
  ;; control meaning.
  (define (conversation-gone? x) (eq? x 'gone))

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
