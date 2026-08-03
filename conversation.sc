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
;;; the next request -- it is a small integer and crosses links and JSON
;;; unchanged.
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
;;; 'stale: this request named a reply that is no longer the one being
;;; answered. It was NOT applied and will not be -- a fact about this
;;; conversation, not a guess. It says nothing about whether the request it
;;; duplicates succeeded: the step it was repeating may well have run for
;;; whoever got there first. Read the current state; do not resubmit (there
;;; is no valid token to resubmit with, which is the point).
;;;
;;; What 'stale does NOT give you is recovery from a LOST REPLY. A caller
;;; whose response never arrived holds a spent token and can neither
;;; advance nor learn the outcome; it has to reconcile out of band. Handing
;;; back the reply that step already produced -- making resume idempotent,
;;; the way payment APIs treat an idempotency key -- would cover that, at
;;; the cost of retaining a reply per step. It is deliberately not done
;;; here, and the token protocol makes it addable later without breaking
;;; anything.
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
;;;   - TTL expiry raises 'conversation-expired inside the flow, so a
;;;     guard can roll back explicitly; re-raise (or don't catch) so the
;;;     process exits.
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
  (export conversation-start! conversation-resume!
          conversation-gone? conversation-stale?)
  (import (chezscheme) (igropyr actor)
          (only (igropyr libuv) now-ms)
          (only (igropyr node) node-self rsend monitor-node demonitor-node))

  (define default-ttl-ms 300000)      ; 5 minutes

  ;; CSPRNG conversation ids: resuming is authorization, so ids must be
  ;; unguessable (same reasoning as session sids)
  (define (conv-hex!)
    (let ((bv (make-bytevector 16)))
      (call-with-port (open-file-input-port "/dev/urandom")
        (lambda (p) (get-bytevector-n! p bv 0 16)))
      (apply string-append
        (map (lambda (i)
               (let ((h (number->string (bytevector-u8-ref bv i) 16)))
                 (if (= (string-length h) 1) (string-append "0" h) h)))
             (iota 16)))))

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
        (`#(conv-resume ,from-node ,reply-name ,ref ,id ,token ,req)
          (spawn
            (lambda ()
              (let-values (((reply next) (local-resume id token req)))
                (rsend from-node reply-name
                       (vector 'conv-forward-reply ref reply next)))))
          (loop))
        (,_ (loop)))))

  ;; Start the owner-side router once per node. Idempotent and atomic:
  ;; only meaningful when clustered (node-self set).
  (define (ensure-router!)
    (when (node-self)
      (with-interrupts-disabled
        (unless (whereis conv-router-name)
          (register conv-router-name (spawn conv-router-loop))))))

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
              (receive (after conv-forward-ttl-ms (values 'unreachable #f))
                (`#(conv-forward-reply ,@ref ,reply ,next) (values reply next))
                (`#(node-down ,@owner) (values 'unreachable #f)))
              (values 'unreachable #f)))
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
                       (let ((tick (max 50 (div ttl 4))))
                         (let loop ()
                           (sleep-ms tick)
                           (cond
                             ((not (process-alive? watched)) 'done)
                             ;; parked in suspend!: idle between rounds is
                             ;; not what this bounds
                             ((not (unbox running-box)) (loop))
                             ;; running, and running for longer than one
                             ;; step is allowed
                             ((> (- (now-ms) (unbox run-start-box)) ttl)
                              (kill watched 'conversation-expired))
                             (else (loop))))))))
                 ;; `awaiting` is the token the flow is currently waiting to
                 ;; be answered with, or #f while a step is running. It is
                 ;; the whole mechanism: a resume is accepted when it names
                 ;; the reply it is answering, and refused otherwise.
                 (let ((who starter) (tag ref) (step 0) (awaiting #f))
                   ;; One resume per step. Two concurrent resumes -- a double
                   ;; click, a client retry, two front ends -- both land in
                   ;; the mailbox; the first wakes this suspend! and the
                   ;; SECOND was then consumed by the NEXT one. That request
                   ;; never saw the reply in between, yet advanced the flow
                   ;; past it: a confirmation step skipped, or one stage's
                   ;; payload applied to the next. The per-caller ref cannot
                   ;; help -- it says who to answer, not which step this is.
                   ;;
                   ;; Answering 'busy is the honest outcome: the conversation
                   ;; is mid-step, and the caller can retry when it is not.
                   (define (suspend! reply)
                     (set! step (+ step 1))
                     (set! awaiting step)
                     (set-box! step-box step)
                     (set-box! running-box #f)      ; parked from here
                     ;; the reply carries the token that answers it
                     (send who (vector 'conv-reply tag reply step))
                     ;; A resume must name the reply it is answering.
                     ;;
                     ;; Arrival order used to stand in for that: everything
                     ;; already queued when a reply went out was drained as
                     ;; stale, and whatever came next was presumed to be the
                     ;; answer. That is exact only while delivery is prompt
                     ;; and ordered. A duplicate sent DURING the previous
                     ;; step -- a double click, a client retry, a second
                     ;; front end -- that was delayed past the drain (a
                     ;; slower path, a forwarding hop, a busy scheduler)
                     ;; arrived afterwards and was taken as the next step:
                     ;; the flow advanced on input written before the reply
                     ;; it claims to answer, skipping a confirmation or
                     ;; applying one stage's payload to the next. Draining
                     ;; cannot see that -- the message did not exist yet.
                     ;; The mirror error was a genuine answer refused as
                     ;; 'busy for landing inside the send/drain window.
                     ;;
                     ;; The token settles both. It is consumed the moment a
                     ;; request is accepted, so a second request bearing it
                     ;; -- concurrent or late, it makes no difference -- is
                     ;; refused, and a request that really did read the
                     ;; reply is accepted whenever it arrives.
                     ;;
                     ;; 'stale means the request was NOT applied and will
                     ;; not be. It is not replayed: keeping every step's
                     ;; reply to hand one back would make resume idempotent,
                     ;; which is a separate decision with a memory cost, and
                     ;; one the token protocol makes addable later without
                     ;; breaking anything.
                     (let wait ()
                       (receive (after ttl (raise 'conversation-expired))
                         (`#(conv-step ,from ,ref2 ,token ,r)
                           (if (and awaiting (eqv? token awaiting))
                               (begin
                                 (set! awaiting #f)   ; consumed
                                 (set! who from) (set! tag ref2)
                                 (set-box! running-box #t)
                                 (set-box! run-start-box (now-ms))
                                 r)
                               (begin
                                 (send from (vector 'conv-reply ref2 'stale #f))
                                 (wait)))))))
                   (let ((final (flow req suspend!)))
                     (unregister name)
                     ;; the flow is over: no token can answer this
                     (send who (vector 'conv-reply tag final #f))))))))
      (let ((m (monitor conv)))
        (receive
          (`#(conv-reply ,@ref ,reply ,token)
            (when m (demonitor m))
            (flush-down! conv)
            (values id token reply))
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
  (define (local-resume id token req)
    (let ((p (whereis (conversation-name id))))
      (if (not p)
          (values 'gone #f)
          (let ((ref (gensym))
                (m (monitor p)))
            (send p (vector 'conv-step self ref token req))
            (receive
              (`#(conv-reply ,@ref ,reply ,next)
                (when m (demonitor m))
                (flush-down! p)
                (values reply next))
              (`#(DOWN ,@p ,reason) (values 'gone #f)))))))

  (define (conversation-gone? x) (eq? x 'gone))

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
