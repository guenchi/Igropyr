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
;;;   (define-values (id reply)
;;;     (conversation-start!
;;;       (lambda (req suspend!)
;;;         (let ((tx (begin-tx!)))          ; live state, held across rounds
;;;           (guard (e (#t (rollback! tx) (raise e)))
;;;             (let ((req2 (suspend! first-reply)))   ; answer, park, resume
;;;               (commit! tx)
;;;               final-reply))))
;;;       req))
;;;
;;;   (conversation-resume! id req)   ; -> reply, or 'gone
;;;
;;; Fault semantics (the transaction-ring contract):
;;;   - flow crashes, TTL expires, or the process dies for any reason
;;;     -> the process is unregistered automatically; every later resume
;;;     returns 'gone. For a flow holding a database transaction, dead
;;;     process = dropped connection = the database itself rolled back:
;;;     'gone GUARANTEES the transaction did not commit.
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
;;; never a serial router. The owner node being gone (link down, crash)
;;; yields 'gone, and that is honest: the process died, so its
;;; transaction rolled back. Forwarded req and reply cross a link, so
;;; they must be extended-wire-safe (as with rsend / rcall). With one
;;; node (node-start! never called) the id has no prefix and every
;;; resume stays local -- no dependency on the distribution layer at
;;; run time.

(library (igropyr conversation)
  (export conversation-start! conversation-resume! conversation-gone?)
  (import (chezscheme) (igropyr actor)
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
        (`#(conv-resume ,from-node ,reply-name ,ref ,id ,req)
          (spawn
            (lambda ()
              (rsend from-node reply-name
                     (vector 'conv-forward-reply ref (local-resume id req)))))
          (loop))
        (,_ (loop)))))

  ;; Start the owner-side router once per node. Idempotent and atomic:
  ;; only meaningful when clustered (node-self set).
  (define (ensure-router!)
    (when (node-self)
      (with-interrupts-disabled
        (unless (whereis conv-router-name)
          (register conv-router-name (spawn conv-router-loop))))))

  ;; Forward a resume to the owner node and wait for its reply. Owner
  ;; link down (monitor-node) or timeout both mean 'gone -- honest,
  ;; because a dead owner process rolled its transaction back.
  (define (forward-resume owner id req)
    (let ((reply-name (fresh-reply-name!))
          (ref (fresh-ref!)))
      (register reply-name self)
      (monitor-node owner)
      (dynamic-wind
        (lambda () (void))
        (lambda ()
          ;; rsend is #f when the owner link is already down -> 'gone at
          ;; once (its process died, so its transaction rolled back);
          ;; otherwise wait, and node-down mid-flight is the same 'gone.
          (if (rsend owner conv-router-name
                     (vector 'conv-resume (node-self) reply-name ref id req))
              (receive (after conv-forward-ttl-ms 'gone)
                (`#(conv-forward-reply ,@ref ,reply) reply)
                (`#(node-down ,@owner) 'gone))
              'gone))
        (lambda ()
          (demonitor-node owner)
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
           (conv
             (spawn
               (lambda ()
                 (register name self)
                 (let ((who starter) (tag ref))
                   (define (suspend! reply)
                     (send who (vector 'conv-reply tag reply))
                     (receive (after ttl (raise 'conversation-expired))
                       (`#(conv-step ,from ,ref2 ,req2)
                         (set! who from)
                         (set! tag ref2)
                         req2)))
                   (let ((final (flow req suspend!)))
                     (unregister name)
                     (send who (vector 'conv-reply tag final))))))))
      (let ((m (monitor conv)))
        (receive
          (`#(conv-reply ,@ref ,reply)
            (when m (demonitor m))
            (flush-down! conv)
            (values id reply))
          (`#(DOWN ,@conv ,reason)
            (raise (vector 'conversation-failed reason)))))))

  ;; Resume the conversation with the next request; parks until the flow
  ;; yields its reply. Returns 'gone when the conversation is over,
  ;; expired, or crashed -- for a transactional flow that means the
  ;; database already rolled back.
  (define (conversation-resume! id req)
    (let ((owner (conv-owner id)))
      (if (or (not owner) (eq? owner (node-self)))
          (local-resume id req)
          (forward-resume owner id req))))

  ;; Resume a conversation that lives on THIS node.
  (define (local-resume id req)
    (let ((p (whereis (conversation-name id))))
      (if (not p)
          'gone
          (let ((ref (gensym))
                (m (monitor p)))
            (send p (vector 'conv-step self ref req))
            (receive
              (`#(conv-reply ,@ref ,reply)
                (when m (demonitor m))
                (flush-down! p)
                reply)
              (`#(DOWN ,@p ,reason) 'gone))))))

  (define (conversation-gone? x) (eq? x 'gone))
)
