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

  (define (resolve srv)
    (if (symbol? srv)
        (or (whereis srv)
            (raise (vector 'gen-server-error 'no-such-server srv)))
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
           (ref (next-ref!))
           (m (monitor p)))
      (send p (vector 'gen-call self ref msg))
      (receive (after timeout
                  (release-monitor! m p)
                  (raise (vector 'gen-server-error 'timeout msg)))
        (`#(gen-reply ,@ref ,reply)
          (release-monitor! m p)
          reply)
        (`#(DOWN ,@p ,reason)
          (raise (vector 'gen-server-error 'server-died reason))))))

  (define (gen-server-cast srv msg)
    (send (resolve srv) (vector 'gen-cast msg)))
)
