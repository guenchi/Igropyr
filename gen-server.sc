#!chezscheme
;;; (igropyr gen-server) -- the OTP gen-server pattern for Igropyr actors.
;;;
;;; A stateful service process reduced to three callbacks; the loop,
;;; request/reply matching, timeouts and death detection are done here,
;;; once, correctly:
;;;
;;;   (define counter
;;;     (gen-server-start
;;;       (lambda () 0)                            ; init -> state
;;;       (lambda (msg from state)                 ; handle-call
;;;         (values (+ state 1) (+ state 1)))      ;   (values reply new-state)
;;;       (lambda (msg state) state)))             ; handle-cast -> new-state
;;;
;;;   (gen-server-call counter 'incr)              ; sync; 5s default timeout
;;;   (gen-server-cast counter 'noop)              ; async
;;;
;;; Every call carries a unique tag, so replies can never be delivered
;;; to the wrong request; the caller monitors the server, so a server
;;; crash raises #(gen-server-error server-died reason) immediately
;;; instead of hanging until the timeout. Servers may be addressed by
;;; registered name (a symbol) or pid.
;;;
;;; The last slot of every #(gen-server-error ...) is a printable scalar
;;; of at most 200 characters: a value that already is one is passed
;;; through, so it stays eq?-comparable, and anything else is rendered
;;; under bounds on both the walk and the output. See scalar-summary.

(library (igropyr gen-server)
  (export gen-server-start gen-server-start-named
          gen-server-call gen-server-cast)
  (import (chezscheme) (igropyr actor))

  (define default-timeout-ms 5000)

  ;; guarded like actor.sc's pid-counter: this is a read-modify-write on
  ;; shared state under preemptive scheduling. It happens to be leaf
  ;; fixnum code today, which makes it incidentally atomic -- but a lost
  ;; update would roll the counter back and re-issue a ref that a stale
  ;; reply still matches, so it must not depend on codegen.
  (define ref-counter 0)
  (define (next-ref!)
    (with-interrupts-disabled
      (set! ref-counter (+ ref-counter 1))
      ref-counter))

  ;; ---- what goes in the error vector's last slot ------------------------
  ;; That slot used to hold the caller's own message, or a DOWN reason,
  ;; whatever they were. A message names its replier -- sending `self' is
  ;; how a request says where to answer -- so the slot could hold a live
  ;; process, and a process is a pcb record whose fields include its
  ;; continuation, its links and its inbox. `write' on such a vector walks
  ;; into a cycle and takes the runtime down, printing the mailbox on the
  ;; way; the operator reading the error is the one who triggers it.
  ;;
  ;; So the slot holds a printable scalar of bounded length. A value that
  ;; already is one passes through UNCHANGED, which is what keeps
  ;; 'server-died's `normal' and a registered name eq?-dispatchable at the
  ;; call site. Anything else is rendered, and the rendering is bounded on
  ;; BOTH axes, because they fail differently:
  ;;
  ;;   - structure: print-level and print-length bound the walk, so a
  ;;     cycle or a pcb is summarised rather than chased;
  ;;   - output: the port itself stops accepting after the budget. Those
  ;;     parameters do not bound an ATOM -- a 5000-character string, a
  ;;     5000-digit bignum and a record whose writer emits 5000 characters
  ;;     each render in full before any clip could see them -- so bounding
  ;;     the walk alone would leave the cost unbounded and only the result
  ;;     small.
  ;;
  ;; A writer that raises is caught: the slot becomes "<unprintable>"
  ;; rather than the writer's exception replacing the gen-server-error the
  ;; caller was about to receive. A writer that hangs is not covered;
  ;; nothing here can bound it.
  ;;
  ;; Symbols are bounded BY LENGTH as well as by kind. A symbol cannot
  ;; cycle and cannot reach a pcb, so a long one is not the hazard above,
  ;; but "bounded scalar" is a claim other files make about this value,
  ;; and a megabyte-long name would falsify it.
  ;;
  ;; The three numbers are measured-enough values, not a contract: at
  ;; level 3 / length 8 a pcb renders to about 185 characters, which
  ;; identifies the message shape without becoming the message.
  (define summary-print-level 3)
  (define summary-print-length 8)
  (define summary-max-chars 200)          ; of the RESULT, ellipsis included

  (define summary-overflow (list 'gen-server-summary-overflow))

  (define (render-bounded x)
    (let* ((acc (open-output-string))
           (budget (- summary-max-chars 3))   ; room for the ellipsis
           (n 0))
      (define (emit! str start count)
        (let ((room (- budget n)))
          (when (<= room 0) (raise summary-overflow))
          (let ((take (if (< count room) count room)))
            (put-string acc str start take)
            (set! n (+ n take))
            (when (< take count) (raise summary-overflow))
            count)))
      (let ((port (make-custom-textual-output-port
                    "gen-server-error-summary" emit! #f #f #f)))
        (guard (e ((eq? e summary-overflow)
                   (string-append (get-output-string acc) "..."))
                  (#t (string-append (get-output-string acc) "<unprintable>")))
          (parameterize ((print-level summary-print-level)
                         (print-length summary-print-length))
            (write x port)
            (flush-output-port port))
          (get-output-string acc)))))

  (define (short-enough? s) (<= (string-length s) summary-max-chars))

  (define (scalar-summary x)
    (if (or (fixnum? x) (boolean? x) (null? x) (char? x)
            (and (symbol? x) (short-enough? (symbol->string x)))
            (and (string? x) (short-enough? x)))
        x
        (render-bounded x)))

  (define (resolve srv)
    (if (symbol? srv)
        (or (whereis srv)
            (raise (vector 'gen-server-error 'no-such-server
                           (scalar-summary srv))))
        srv))

  ;; init: () -> state
  ;; handle-call: (msg from state) -> (values reply new-state)
  ;; handle-cast: (msg state) -> new-state
  ;; handle-info: (msg state) -> new-state    (optional; other messages,
  ;;                                           e.g. DOWN from monitors)
  (define (gen-server-start init handle-call handle-cast . rest)
    (let ((handle-info (if (pair? rest) (car rest) (lambda (m s) s))))
      (spawn
        (lambda ()
          (let loop ((state (init)))
            (receive
              (`#(gen-call ,from ,ref ,msg)
                ;; Skip a call whose caller is already gone. A busy server
                ;; queues work in its mailbox, and a caller can be killed
                ;; while waiting -- a stuck worker reaped by its supervisor,
                ;; say. Running it then applies effects nobody will observe,
                ;; and the application's retry applies them again: one
                ;; charge becomes two. A dead caller is a FACT, so this is
                ;; safe; a caller that merely timed out is still running and
                ;; indistinguishable from one still waiting, so that case is
                ;; deliberately not guessed at here -- see gen-server-call.
                (if (process-alive? from)
                    (let-values (((reply new-state) (handle-call msg from state)))
                      (send from (vector 'gen-reply ref reply))
                      (loop new-state))
                    (loop state)))
              (`#(gen-cast ,msg)
                (loop (handle-cast msg state)))
              (other
                (loop (handle-info other state)))))))))

  (define (gen-server-start-named name . args)
    (register name (apply gen-server-start args)))

  ;; A call that timed out leaves the server's late #(gen-reply ref v)
  ;; in our mailbox: refs are never reused, so no future receive can
  ;; ever match it and selective receive keeps it forever -- every later
  ;; receive in this process rescans it. Since a call is synchronous
  ;; within one green process, any gen-reply present at ENTRY is by
  ;; construction such a leftover, so draining here is race-free.
  (define (drain-stale-replies!)
    (let loop ()
      (receive (after 0 'done)
        (`#(gen-reply ,r ,v) (loop)))))

  ;; demonitor does not retract a DOWN that was already delivered; left
  ;; behind it would be misread by any later DOWN-matching receive in
  ;; this process (a supervisor would treat it as a worker death).
  (define (release-monitor! m p)
    (when m
      (demonitor m)
      (receive (after 0 'ok) (`#(DOWN ,@p ,reason) 'ok))))

  ;; A TIMEOUT DOES NOT CANCEL THE CALL. The request is already in the
  ;; server's mailbox and this side has no way to retract it; a caller that
  ;; gave up is still running and looks exactly like one still waiting, so
  ;; the server cannot tell them apart either. The handler may therefore run
  ;; afterwards and apply its effects. Treat 'timeout as "outcome unknown",
  ;; not as "did not happen": retrying a call with effects can apply them
  ;; twice. Make such handlers idempotent, or carry a request id the server
  ;; can deduplicate on.
  ;;
  ;; A caller that DIES is a different matter -- that is a fact, and the
  ;; server skips those calls rather than acting for nobody.
  (define (gen-server-call srv msg . rest)
    (drain-stale-replies!)
    (let* ((timeout (if (pair? rest) (car rest) default-timeout-ms))
           (p (resolve srv))
           (ref (next-ref!)))
      ;; Calling yourself cannot work and never could: the request lands in
      ;; this process's own mailbox and this process then waits for a reply
      ;; that only its own loop can produce -- and its loop is right here,
      ;; inside the handler, waiting. It is a deadlock with no way out, and
      ;; the way it FAILED hid that: the default timeout made it a 'timeout
      ;; error five seconds later, usually killing the server, and a timeout
      ;; of 'infinity parked the server for good.
      ;;
      ;; Answering immediately turns an unexplained stall into the mistake it
      ;; is. A handler that wants its own service should call the plain
      ;; procedure the handler calls, not route back through the mailbox.
      (when (eq? p self)
        (raise (vector 'gen-server-error 'calling-self
                       (scalar-summary msg))))
      (let ((m (monitor p)))
        (send p (vector 'gen-call self ref msg))
        (receive (after timeout
                    (release-monitor! m p)
                    (raise (vector 'gen-server-error 'timeout
                                   (scalar-summary msg))))
          (`#(gen-reply ,@ref ,reply)
            (release-monitor! m p)
            reply)
          (`#(DOWN ,@p ,reason)
            (raise (vector 'gen-server-error 'server-died
                           (scalar-summary reason))))))))

  (define (gen-server-cast srv msg)
    (send (resolve srv) (vector 'gen-cast msg)))
)
