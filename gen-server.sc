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
;;; The last slot of every #(gen-server-error ...) is a value at most 200
;;; characters long: a small one passes through and stays eq?-comparable,
;;; anything else is replaced by a label describing its shape. Nothing
;;; prints the caller's value to build that label -- printing is what was
;;; unbounded. (Writing a string slot adds Scheme's quoting on top of
;;; those 200.) See scalar-summary.

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
  ;; So the slot holds a small value the caller may print freely. Values
  ;; that already are such pass through UNCHANGED, which keeps
  ;; 'server-died's `normal' and a registered name eq?-dispatchable.
  ;; Everything else is replaced by a LABEL describing its shape.
  ;;
  ;; NOTHING HERE PRINTS THE VALUE, and that is the design, not an
  ;; optimisation. Bounding a rendering does not bound producing it: a
  ;; bignum's decimal expansion is built before any output port can
  ;; refuse it (half a million digits costs ~90ms and ~9MB), and a record
  ;; whose writer builds its string first spends whatever it likes before
  ;; a single character is offered. A writer may also raise, or hang, or
  ;; keep the port it was handed. Labels are built from predicates and
  ;; accessors that run no user code at all, so none of that is reachable
  ;; from here.
  ;;
  ;; What the slot is FOR is telling an operator WHICH call this was, and
  ;; a request's tag does that: #(do-thing <pid>) becomes "#(do-thing
  ;; ...)". It is not a rendering of the message and does not try to be.
  ;;
  ;; PASSTHROUGH HAS A LENGTH LIMIT, and the limit is part of the
  ;; contract: a symbol longer than 200 characters arrives as a string,
  ;; so `(eq? some-registered-name (vector-ref e 2))` holds for names up
  ;; to that length and not beyond. register accepts longer ones. A
  ;; gensym never passes through -- its unique name goes on the wire when
  ;; the caller writes it, and that name is unbounded -- so it arrives as
  ;; its pretty name in a label.
  (define summary-max-chars 200)

  (define (clip s)
    (if (> (string-length s) summary-max-chars)
        (string-append (substring s 0 (- summary-max-chars 3)) "...")
        s))

  ;; one bounded label, built without printing anything
  (define (label-of x)
    (cond
      ((symbol? x)
       (if (gensym? x)
           (clip (string-append "#<gensym " (symbol->string x) ">"))
           (clip (symbol->string x))))
      ((string? x) (clip x))
      ((char? x) (string x))
      ((number? x) "#<number>")
      ((procedure? x) "#<procedure>")
      ((vector? x)
       (let ((n (vector-length x)))
         (if (and (fx> n 0) (symbol? (vector-ref x 0))
                  (not (gensym? (vector-ref x 0))))
             (clip (string-append "#(" (symbol->string (vector-ref x 0))
                                  " ...)"))
             "#(...)")))
      ((pair? x) "(...)")
      ((null? x) "()")
      ((boolean? x) (if x "#t" "#f"))
      ((record? x)
       (clip (string-append "#<"
                            (symbol->string (record-type-name (record-rtd x)))
                            ">")))
      (else "#<value>")))

  (define (short-enough? s) (<= (string-length s) summary-max-chars))

  (define (scalar-summary x)
    (if (or (fixnum? x) (boolean? x) (null? x) (char? x)
            (and (symbol? x) (not (gensym? x)) (short-enough? (symbol->string x)))
            (and (string? x) (short-enough? x)))
        x
        (label-of x)))

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
