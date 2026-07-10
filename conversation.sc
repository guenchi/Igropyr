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

(library (igropyr conversation)
  (export conversation-start! conversation-resume! conversation-gone?)
  (import (chezscheme) (igropyr actor))

  (define default-ttl-ms 300000)      ; 5 minutes

  ;; CSPRNG conversation ids: resuming is authorization, so ids must be
  ;; unguessable (same reasoning as session sids)
  (define (conversation-id!)
    (let ((bv (make-bytevector 16)))
      (call-with-port (open-file-input-port "/dev/urandom")
        (lambda (p) (get-bytevector-n! p bv 0 16)))
      (apply string-append
        (map (lambda (i)
               (let ((h (number->string (bytevector-u8-ref bv i) 16)))
                 (if (= (string-length h) 1) (string-append "0" h) h)))
             (iota 16)))))

  (define (conversation-name id)
    (string->symbol (string-append "igropyr-conv-" id)))

  ;; consume a DOWN that raced the reply, so it cannot rot in the inbox
  ;; of a reused pool worker
  (define (flush-down! p)
    (receive (after 0 'ok)
      (`#(DOWN ,@p ,r) 'ok)))

  ;; Start a conversation. flow: (lambda (req suspend!) ... final-reply).
  ;; suspend! answers the current round and parks until the next resume,
  ;; returning the next request; on TTL expiry it raises
  ;; 'conversation-expired inside the flow. The flow's return value is
  ;; the final round's reply; the process then unregisters and exits.
  ;; Returns (values id first-reply); the caller parks meanwhile.
  ;; Optional trailing argument: ttl-ms (default 300000).
  (define (conversation-start! flow req . opts)
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
