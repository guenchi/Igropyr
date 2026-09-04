#!chezscheme
;;; (igropyr tls-watch) -- the per-connection TLS watcher.
;;;
;;; THIS LIBRARY EXISTS BECAUSE OF A LAYERING FACT. Each established TLS
;;; connection needs one green process that links, monitors and parks in a
;;; timed receive; none of that exists in (igropyr libuv), which sits BELOW
;;; (igropyr actor) and cannot import it. So libuv asks for a watcher through
;;; a hook, and the body of the watcher lives here, above actor.
;;;
;;; IT TOUCHES NO RECORD FIELD OF A CONNECTION. Everything it does to the
;;; shared gate state goes through the operations libuv exports -- the same
;;; ones application writers use -- so the gate has one discipline rather than
;;; one per caller.
;;;
;;; Order inside the watcher is guard -> link -> monitor -> open-and-drain ->
;;; loop, and that order is Z13's, not Z12's: Z12 says "the first act is
;;; monitor" and Z13 revises it to put (link owner) first. Both sentences use
;;; the words "first act", and following the earlier one silently drops the
;;; link -- which no cell can see, because Z15 keeps the link only as a
;;; backstop for non-trapping owners and claims nothing for it.

(library (igropyr tls-watch)
  (export tls-watch-install! tls-watcher-idle-ms-set!
          tls-watcher-observer-set!)
  (import (chezscheme) (igropyr actor) (igropyr inject)
          (only (igropyr tcp) conn-owner conn-tls-retire! tls-conn-holder tls-conn-set-holder-monitor! tls-gate-grant-next! tls-open-gate-and-drain! tls-watcher-exited! uv-set-gate-wait! uv-set-tls-watcher-spawner!))

  (define tls-watcher-idle-ms 1000)
  (define (tls-watcher-idle-ms-set! n) (set! tls-watcher-idle-ms n))

  ;; THE OBSERVER MONITORS THE WATCHER ITSELF. Recording an exit reason
  ;; from inside the watcher's own guard handler would record its INTENTION to
  ;; re-raise: after writing it, it can still be killed, or die on the way out
  ;; for another reason. monitor reports only to its caller, so the watcher's
  ;; pid is handed to the registered observer and the observer monitors it --
  ;; the reason it then receives is the real one. The pid is not exported, not
  ;; registered, and reaches nobody else (R-i stands).
  (define observer #f)
  (define (tls-watcher-observer-set! pid) (set! observer pid))

  ;; THE DECREMENT IS GATED, because the exit paths NEST. A DOWN branch
  ;; decrements and then raises to leave the loop -- and that raise is caught
  ;; by the guard, which decrements again. The live count went to -1 in the
  ;; second end-to-end run for exactly that reason. One flag, checked and set
  ;; in the same step, so "the watcher ended" is counted once however many
  ;; layers it leaves through.
  (define (make-exit-once c)
    (let ((done? #f))
      (lambda ()
        (let ((first? (with-interrupts-disabled
                        (and (not done?) (begin (set! done? #t) #t)))))
          (when first? (tls-watcher-exited! c))))))

  (define (watcher-body c)
    ;; THE GUARD IS THE MECHANISM (Z15). On any raise the connection is
    ;; retired by this process's own hand and the condition is re-raised; that
    ;; path does not depend on who the owner is or whether it traps exits. A
    ;; WSS owner runs arbitrary code and may trap, in which case a link only
    ;; delivers an EXIT it may never read -- so the link below is belt and
    ;; braces for non-trapping owners and nothing is claimed for it.
    ;; THE COUNT IS GIVEN BACK ON BOTH EXITS. Returning it only on the
    ;; normal path would leave the live count rising forever after any abort,
    ;; and then "still 1 after retirement" would say nothing about whether this
    ;; process actually ended -- which is how that reading was misread once.
    (let ((exited! (make-exit-once c)))
    (guard (e (#t (exited!)
                  (conn-tls-retire! c 'watcher-raise e)
                  (raise e)))
      (let ((owner (conn-owner c)))
        (inject-fault! 'tls-watcher-link)
        (when owner (link owner))
        (inject-fault! 'tls-watcher-monitor)
        (when owner (monitor owner))
        ;; THIS POINT RAISES; IT DOES NOT DELAY. inject-fault! can only
        ;; raise, so arming it aborts the connection through the guard above
        ;; rather than holding the watcher back -- which makes it a usable
        ;; "watcher died before opening the gate" point, and NOT the delay
        ;; H18 needs. H18 wants this process parked while the callback is
        ;; already gone, and parking needs the barrier tranche's handoff.
        ;; The name is kept because that is what the plan calls it; what it
        ;; does is written here so nobody arms it expecting a pause.
        (inject-fault! 'tls-watcher-delay)
        (tls-open-gate-and-drain! c)
        ;; hm carries the monitor of the CURRENT holder. It lives here and
        ;; not on the connection because demonitor needs the monitor object
        ;; itself, and only this process ever holds one.
        (let loop ((hm #f))
          (let ((next
                  (receive (after tls-watcher-idle-ms 'idle)
                    ;; a lost ping costs latency only: every wake re-reads the
                    ;; list
                    (`#(tls-gate-ping) 'ping)
                    ;; EVERY GRANT IS ANNOUNCED, so the holder is monitored
                    ;; from the moment it holds (Z5). Both the uncontended
                    ;; acquisition and a release's hand-off send this; the
                    ;; uncontended one is the common case and was previously
                    ;; unmonitored.
                    (`#(tls-gate-granted ,pid)
                      (when hm (demonitor hm))
                      (cons 'granted (monitor pid)))
                    (`#(tls-gate-released)
                      (when hm (demonitor hm))
                      'released)
                    (`#(tls-retire) (exited!) (raise 'tls-watcher-done))
                    ;; A DOWN IS ONLY OURS IF IT NAMES THE CURRENT HOLDER OR
                    ;; THE OWNER. A former holder that dies later still
                    ;; produces one, and acting on it would retire a healthy
                    ;; connection because somebody who finished writing has
                    ;; since exited.
                    (`#(DOWN ,pid ,reason)
                      (if (or (eq? pid (tls-conn-holder c))
                              (eq? pid (conn-owner c)))
                          (begin (exited!)
                                 (conn-tls-retire! c 'down reason)
                                 (raise 'tls-watcher-done))
                          'stale)))))
            ;; grant the gate to whoever is next; the grant announces itself
            ;; through the same message the uncontended path uses
            (let ((granted (tls-gate-grant-next! c)))
              (when granted
                (let ((p (car granted)))
                  (tls-conn-set-holder-monitor! c p)
                  (send p (vector 'tls-gate-held)))))
            (loop (if (and (pair? next) (eq? (car next) 'granted))
                      (cdr next)
                      hm))))))))

  (define (spawn-watcher c)
    (let ((p (spawn (lambda () (watcher-body c)))))
      ;; the observer, when one is registered, is told the pid so it can
      ;; monitor the watcher itself
      (when observer (send observer (vector 'tls-watcher p c)))
      p))

  ;; CALLED EXPLICITLY, NOT RELIED ON AS AN INVOKE SIDE EFFECT. Chez invokes
  ;; a library when one of its exports is first referenced; a program that
  ;; imports this library but only calls libuv's own entries would never
  ;; invoke it, and the hook would silently stay uninstalled. http.sc's TLS
  ;; listen entry calls this, so the wiring is a statement rather than a
  ;; consequence of load order.
  ;; HOW A PARKED WRITER WAITS, supplied from above because receive does not
  ;; exist in libuv. No timeout: Z7/Z8 guarantee every waiter gets exactly one
  ;; outcome -- it is answered by whichever of release or retirement atomically
  ;; took it off the list -- so a timeout could only turn a guaranteed answer
  ;; into a guess.
  (define (gate-wait)
    (receive
      (`#(tls-gate-held) 'held)
      (`#(tcp-write-refused ,why) (cons 'refused why))))

  (define (tls-watch-install!)
    (uv-set-tls-watcher-spawner! spawn-watcher)
    (uv-set-gate-wait! gate-wait))
  )
