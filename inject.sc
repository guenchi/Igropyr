;;; inject.sc -- fault-injection primitives for igropyr's own test suite.
;;;
;;; ⛔ THIS LIBRARY IS A TEST INSTRUMENT AND MUST NOT SHIP ARMED. What
;;; makes that true is not discipline; it is that the switch is read at
;;; EXPANSION time, exactly as (igropyr checked) reads IGROPYR_CONTRACTS,
;;; so a build made with IGROPYR_INJECT unset contains no injection code
;;; at all -- not a disabled branch, not a flag test, nothing.
;;;
;;; Four primitives, and each is placed under a rule:
;;;
;;;   (inject-fault! 'point)         -- raises when armed. Region-safe:
;;;                                     it allocates nothing and may sit
;;;                                     anywhere a raise is already
;;;                                     possible.
;;;   (inject-return! 'point expr)   -- when armed, returns the
;;;                                     configured value and ⛔ DOES NOT
;;;                                     EVALUATE expr AT ALL. See the
;;;                                     rule below for why that is the
;;;                                     only safe reading.
;;;   (inject-barrier! 'point)       -- reports and parks. Not in this
;;;                                     tranche; the 'on expansion is a
;;;                                     stub that refuses.
;;;
;;; ⛔ THE RULE FOR inject-return!, and it is not a style note. The
;;; guarded call is SKIPPED, not called-then-overridden: faking "the
;;; write failed" while actually performing the write would hand the
;;; buffer to libuv and then free it on the failure path. Replacing a
;;; return value is therefore only sound when skipping the call leaves
;;; the world as if it had failed -- which means the call must have done
;;; NOTHING ELSE. The value being faked must satisfy: no externally
;;; visible work, no output parameter initialised, no ownership
;;; transferred, no callback scheduled. A raw FFI call that failed
;;; satisfies this; anything that may have partially succeeded does not.
;;; ⚠ The concrete counter-example is uv_try_write: injecting a positive
;;; partial count there would make the caller queue only the suffix of a
;;; message whose prefix was never sent. Wrap the raw call, never a
;;; wrapper that has already acted on the result.
;;;
;;; ⛔ AND A SECOND RULE, GOVERNING SOMETHING ELSE. The one above says
;;; which VALUE may be injected -- the faked answer must be one the
;;; skipped call could have given with nothing else done. This one says
;;; where a point may be PLACED:
;;;
;;;   an injection point must sit INSIDE the guard that owns the failure
;;;   branch you intend to exercise.
;;;
;;; ⚠ Outside it, what you measure is the OUTER recovery policy and not
;;; the inner failure handling -- and an outer policy is usually the
;;; thing that makes the whole event look like nothing happened. Two
;;; instances turned up in one day, both silent:
;;;   - a test fixture whose fail! was changed from exit to raise, which
;;;     put it in reach of the the catch-all guards in the libraries it drives (about thirty; count them, do not quote this number) in the
;;;     libraries it drives: a swallowed assertion leaves the cell
;;;     passing, not failing;
;;;   - a design draft that placed the mdown/demon point outside the
;;;     caller's guard, where the raise was caught and dropped and the
;;;     submission-failure branch never ran at all.
;;;
;;; ⛔ AND A THIRD RULE, ABOUT WHICH PRIMITIVE TO USE. inject-return!
;;; SKIPS the call it wraps and answers in its place; inject-override!
;;; RUNS it and then replaces the answer. They are not interchangeable:
;;;
;;;   skipping a call is the same as that call failing ONLY IF the call
;;;   has no side effect the code after it depends on
;;;
;;; ⚠ Measured, not reasoned: 'accept-refused was written with
;;; inject-return! and produced a state no real failure produces. In
;;; libuv's unix stream.c, uv__server_io accept()s into
;;; server->accepted_fd BEFORE calling the connection callback, and when
;;; the callback returns without consuming it, uv__io_stop takes the
;;; listener out of the poll set. A real uv_accept failure closes that fd
;;; and calls uv__io_start, so the listener survives; skipping the call
;;; left accepted_fd set and froze the listener for good. Same errno to
;;; the caller, two different states underneath -- and the cell saw it as
;;; "the second connection was never accepted".
;;;
;;; ⭐ So: use inject-return! for a submission that can genuinely be
;;; refused without running (uv_write, uv_getaddrinfo, uv_tcp_connect),
;;; and inject-override! wherever the call itself moves state the caller
;;; depends on.
;;;
;;; ⚠ AND COUNT THEM OVER THE WHOLE DYNAMIC PATH, NOT THE LEXICAL ONE.
;;; The line you assert on is in the CELL, so the cell's own guards --
;;; including whatever the runner wraps every cell in -- are on that
;;; path and are part of the count. Every point comment in this batch
;;; was first written with the product-side count only, and every one
;;; of them therefore undercounted; the review that found it counted
;;; dynamically, which is what the rule already said to do.
;;;
;;; ⭐ THE CHECK IS CHEAPER THAN THE RULE. Count the `guard`s between the
;;; injection point and the line you mean to assert on. If the answer is
;;; not zero, say for each of them why it does not catch this first --
;;; in the design table, where the next round can read it, and not in a
;;; message.
;;;
;;; ⭐ THE 'on EXPANSION DELIBERATELY REFERENCES A RUNTIME IDENTIFIER OF
;;; THIS LIBRARY. That is what makes the invoke-time check below reachable
;;; from a compiled artifact: a library is invoked when something refers
;;; to its runtime part, and an expansion that inlined everything would
;;; leave the check unreachable in exactly the artifact it exists to
;;; catch. Measured, not assumed -- with IGROPYR_CONTRACTS the analogous
;;; consumer reports invoke-requirements () when off and ((igropyr
;;; checked)) when on, at optimize-level 2.
(library (igropyr inject)
  (export inject-fault! inject-return! inject-override! inject-barrier!
          $inject-arm! $inject-release! $inject-disarm! $inject-hits
          $inject-ticket $inject-armed-points $inject-delivered-count)
  (import (chezscheme))

  ;; ---- the switch, read once at expansion time --------------------------
  ;; Same shape as (igropyr checked)'s contract-mode, and for the same
  ;; reason: the value is decided by the process doing the COMPILING.
  ;; ⚠ It is re-evaluated when this library is visited, so a compiled .so
  ;; does not carry a baked answer into a downstream build -- verified by
  ;; measurement, and the reason the stale-.so worry is narrower than it
  ;; looks. What a stale .so can still carry is its OWN injection code.
  (meta define inject-mode
    (let ((v (getenv "IGROPYR_INJECT")))
      (cond
        ((or (not v) (string=? v "off")) 'off)
        ((string=? v "on") 'on)
        (else (assertion-violation 'igropyr-inject
                "IGROPYR_INJECT must be \"on\", \"off\", or unset" v)))))

  ;; ⚠ A BANNER, AND ⛔ NOT EVEN A TRIPWIRE. It says "this expansion is
  ;; happening with injection on", which is a statement about the CURRENT
  ;; process: inject-mode is recomputed from this process's environment
  ;; every time the library is visited. A tree still holding an armed .so,
  ;; visited with the variable unset, therefore stays perfectly silent --
  ;; an earlier note here claimed the opposite and it is the one thing
  ;; this line cannot do.
  ;;
  ;; ⭐ WHAT ACTUALLY STOPS AN ARMED ARTIFACT, in the order it acts:
  ;; build-units.ss refuses to compile anything while the switch is on;
  ;; the inject suite is run from source with --libexts .sc so it never
  ;; produces one; and if one exists anyway, the invoke-time check below
  ;; refuses when its runtime part is reached.
  (meta define $inject-visit-ok
    (begin (when (eq? inject-mode 'on)
             (display "igropyr: EXPANDING WITH FAULT INJECTION ON\n"
                      (current-error-port)))
           #t))

  (meta-cond
    ((eq? inject-mode 'on)
     ;; ---- armed state ---------------------------------------------------
     ;; ⭐ EVERY CELL IS ALLOCATED WHEN A POINT IS ARMED, never when one is
     ;; hit. A hit does fx+ on an existing fixnum and set! on an existing
     ;; slot, so a point may sit inside a no-interrupt region without
     ;; putting an allocation there.
     ;; Slot layout: #(point kind value occurrence hits ticket ok? delivered)
     ;;
     ;; ⭐ delivered LIVES IN THE ARMING, NOT BESIDE IT. It was a separate
     ;; process-lifetime table, which neither release nor disarm cleared:
     ;; re-arming a point reset hits and kept deliveries, so one old
     ;; delivery could satisfy "delivered = 1" for a later run that never
     ;; delivered at all -- the counter added to restore discriminating
     ;; power could have it taken back. In the vector it is reset by
     ;; every arm, for free.
     (define $inject-table (make-eq-hashtable))
     (define $inject-next-ticket 0)

     ;; Tickets are global and monotone and are NEVER reused, across
     ;; re-arms of the same point included: a report carrying a ticket
     ;; names one arming and no other, which is what lets a controller
     ;; match a report it may receive out of order.
     (define ($inject-ticket)
       (set! $inject-next-ticket (fx+ $inject-next-ticket 1))
       $inject-next-ticket)

     ;; ⛔ THE RULES ARE ENFORCED HERE, NOT IN THE CONTROL LIBRARY. They
     ;; began one level up, where the values are chosen, which reads as
     ;; the natural place -- and left this procedure exported and
     ;; unguarded, so any importer could arm anything and could overwrite
     ;; a validated arm with an unvalidated one. A check placed anywhere
     ;; but at the boundary it protects is a convention.
     ;;
     ;; ⭐ THE FIELDS CHECKED HERE ARE occurrence AND, FOR 'return, THE
     ;; POINT/VALUE PAIR -- not every field. `point`, `kind` and `ok?`
     ;; are stored unvalidated, so a bad `ok?` raises at the HIT rather
     ;; than at the arm -- which is the very thing this procedure exists
     ;; to prevent. That is a named gap, not a claim of completeness.
     ;; occurrence
     ;; and the hit counter meet fx= and fx+ inside a write path that is
     ;; dynamically interrupt-disabled; a string or a flonum arriving
     ;; there raises at the hit, in the region, far from the line that
     ;; chose it. Refusing at arm time puts the error where the mistake is.
     (define (check-arm! point kind value occurrence)
       (unless (or (not occurrence)
                   (and (fixnum? occurrence) (fx> occurrence 0)))
         (assertion-violation '$inject-arm!
           "occurrence must be #f (every hit) or a positive fixnum" occurrence))
       (when (eq? kind 'return)
         (case point
           ;; uv_write returning >= 0 means libuv accepted the request and
           ;; owns the block; the value also escapes to on-done as a
           ;; purported errno, so it has to be one a C int could hold.
           ;; ⭐ THE BOUND IS libuv's OWN ERROR RANGE, NOT A SANITY
           ;; BOUND. On Unix libuv's codes are -errno, and its own most
           ;; negative code is UV_EOF = -4095 (uv-errno.h), so [-4095,-1]
           ;; is what the real API can return. An earlier version here
           ;; allowed anything above -65536 and called that "C int
           ;; range", which it is not: it admitted values such as -65535
           ;; that libuv never produces, and the value is not consumed
           ;; internally -- it reaches on-done, #(dns-failed r) and
           ;; uv-strerror unchanged. A cell asserting on it would be
           ;; asserting on behaviour the real system cannot produce.
           ;; uv_accept declining an announced connection joins them:
           ;; same errno domain, and its caller reads only "negative
           ;; means refused".
           ((uv-write-neg getaddrinfo-refused tcp-connect-refused
             accept-refused)
            (unless (and (fixnum? value) (fx< value 0) (fx>= value -4095))
              (assertion-violation '$inject-arm!
                "this point needs an exact libuv error code in [-4095,-1]"
                value)))
           ;; a positive count would claim a prefix reached the wire and
           ;; make the caller queue only the suffix.
           ;; 0 is a deliberate stand-in: real uv_try_write does not
           ;; return it for a non-empty write, but it is what selects
           ;; the queue-everything branch, which is the branch under
           ;; test. Negatives are bounded like the errno points above.
           ((try-write-eagain try-write-foreign-eagain)
            (unless (and (fixnum? value) (fx<= value 0) (fx>= value -4095))
              (assertion-violation '$inject-arm!
                "this point needs 0 or a libuv error code in [-4095,-1]"
                value)))
           ;; ⛔ A WHITELIST, AND THE DEFAULT IS REFUSAL. It read (void)
           ;; before -- an unlisted return point armed with whatever it
           ;; was given, so the one kind of mistake this table exists to
           ;; catch (a value the point's own caller cannot mean) was
           ;; caught for the points already reasoned about and for no
           ;; other. That is backwards: the points needing the check are
           ;; exactly the ones nobody has reasoned about yet.
           ;;
           ;; ⚠ Adding a return point therefore means adding a clause
           ;; here, and that is the intent -- the clause is where you say
           ;; what the point's caller can possibly read. A fault point
           ;; carries no value, so nothing here constrains it.
           (else
            (assertion-violation '$inject-arm!
              "unknown return point -- add a clause to check-arm! saying what values its caller can read"
              point)))))

     (define ($inject-arm! point kind value occurrence ok?)
       (check-arm! point kind value occurrence)
       (let ((t ($inject-ticket)))
         (hashtable-set! $inject-table point
                         (vector point kind value occurrence 0 t ok? 0))
         t))

     (define ($inject-release! ticket)
       (let-values (((ks vs) (hashtable-entries $inject-table)))
         (vector-for-each
           (lambda (k v) (when (eqv? (vector-ref v 5) ticket)
                           (hashtable-delete! $inject-table k)))
           ks vs)))

     (define ($inject-disarm!) (hashtable-clear! $inject-table))

     (define ($inject-hits point)
       (let ((v (hashtable-ref $inject-table point #f)))
         (and v (vector-ref v 4))))

     ;; How many times a substitute value was returned for the CURRENT
     ;; arming. ⭐ NOT the same as hits: an occurrence is spent when the
     ;; point is entered, so a wrapped expression that raises spends one
     ;; and delivers nothing. A cell asserting only on hits proves that
     ;; an eligible call reached the point, not that the injected value
     ;; was ever seen.
     ;;
     ;; ⚠ It answers 0 both for "never armed" and for "armed and never
     ;; delivered"; those are not distinguished.
     (define (inject-note-delivered! v)          ; v is the arming vector
       (vector-set! v 7 (fx+ (vector-ref v 7) 1)))
     (define ($inject-delivered-count point)
       (let ((v (hashtable-ref $inject-table point #f)))
         (if v (vector-ref v 7) 0)))

     (define ($inject-armed-points)
       (vector->list (hashtable-keys $inject-table)))

     ;; -> the slot when this hit should fire, else #f. Allocation-free.
     (define ($inject-take! point kind)
       (let ((v (hashtable-ref $inject-table point #f)))
         (and v
              (eq? (vector-ref v 1) kind)
              ;; ⭐ THE PROCESS FILTER IS A PREDICATE SUPPLIED BY THE
              ;; ARMING SIDE, not a pid compared here. This library
              ;; imports (chezscheme) and nothing else -- it has no idea
              ;; what a process is, and giving it one would make the
              ;; instrument depend on the layer it is meant to perturb.
              ;; Calling a closure allocates nothing.
              (let ((ok? (vector-ref v 6)))
                (or (not ok?) (ok?)))
              (let ((n (fx+ (vector-ref v 4) 1)))
                (vector-set! v 4 n)
                (let ((k (vector-ref v 3)))
                  (and (or (not k) (fx= n k)) v))))))

     ;; ⭐ INVOKE-TIME CHECK. It runs because an armed expansion refers to
     ;; $inject-take!, which makes this library's runtime part reachable.
     ;; An artifact compiled with injection on therefore cannot be loaded
     ;; and used by a process that did not ask for injection.
     (define $inject-invoke-ok
       (let ((v (getenv "IGROPYR_INJECT")))
         (unless (and v (string=? v "on"))
           (assertion-violation 'igropyr-inject
             "this artifact was compiled with fault injection ON; refusing to run without IGROPYR_INJECT=on"
             v))
         #t)))
    (else
     ;; ---- off: the names exist so the export list is ONE text, and no
     ;; PRODUCTION unit refers to them, so a production consumer's
     ;; invoke-requirements stay empty. That is the property, and it is
     ;; not kept by hand: test/inject-isolation.ss walks the invoke and
     ;; import closures of every unit in library-units and fails if the
     ;; instrument appears anywhere in them. (igropyr inject) is itself a
     ;; production unit -- libuv imports it -- so it is excluded from the
     ;; roots and looked for in everything else's closure; the question
     ;; that gate asks is whether anything ELSE reaches it.
     ;;
     ;; ⚠ A TEST FIXTURE MAY REFER TO THEM -- test/inject.sc's mode probe
     ;; calls $inject-ticket -- and that is OUTSIDE the property, not an
     ;; exception to it: the gate's denominator is library-units, which
     ;; no fixture is in. An earlier version of this note said "nothing
     ;; refers to them", which the probe made false the day it landed;
     ;; it stated the state instead of the mechanism that keeps it, so a
     ;; reader finding the probe would have read a violated design.
     (define ($inject-ticket) 0)
     (define ($inject-arm! point kind value occurrence ok?) 0)
     (define ($inject-release! ticket) (void))
     (define ($inject-disarm!) (void))
     (define ($inject-hits point) #f)
     (define ($inject-delivered-count point) 0)
     (define ($inject-armed-points) '())))

  ;; ---- the four primitives ----------------------------------------------

  ;; ⛔ THE OFF EXPANSION IS (void), NOT (begin), AND THE DIFFERENCE IS NOT
  ;; COSMETIC. (begin) with no forms is valid only in a definition context,
  ;; where it splices away to nothing. A guard body is NOT such a context
  ;; in this implementation -- it is a sequence of expressions -- so a
  ;; point placed inside a guard failed to expand at all, with an error
  ;; naming this line and not the call site.
  ;;
  ;; ⭐ THAT IS EXACTLY WHERE THE RULE AT THE TOP OF THIS FILE SENDS EVERY
  ;; POINT. Tranche 1 placed all of its points in ordinary bodies, so the
  ;; off expansion had never once been asked to stand where the placement
  ;; rule requires -- the rule's first application is what found this.
  ;; That is not a recollection: had any tranche-1 point sat in a guard
  ;; body, no ordinary build would have expanded at all, and they did.
  ;; (void) is an expression everywhere a statement is allowed and expands
  ;; to the same primitive (begin) does, which is why the isolation gate's
  ;; "expands to nothing" comparison still holds.
  ;;
  ;; ⚠ What (void) does NOT do is splice: it cannot stand before a define
  ;; in a body the way (begin) could. No point does that today; one that
  ;; needs to belongs after the definitions anyway.
  (define-syntax inject-fault!
    (lambda (x)
      (syntax-case x ()
        ((_ point)
         (if (eq? inject-mode 'on)
             #'(when ($inject-take! point 'fault)
                 (assertion-violation 'inject-fault! "injected failure" point))
             #'(void))))))

  (define-syntax inject-return!
    (lambda (x)
      (syntax-case x ()
        ((_ point expr)
         (if (eq? inject-mode 'on)
             #'(let ((slot ($inject-take! point 'return)))
                 (if slot
                     (begin (inject-note-delivered! slot)
                            (vector-ref slot 2))
                     expr))
             #'expr)))))

  ;; Run the call, then answer with the armed value instead of its
  ;; result. Same table, same kind, same hit accounting as
  ;; inject-return!; the difference is that the wrapped expression is
  ;; EVALUATED.
  ;;
  ;; ⚠ ONE OCCURRENCE IS SPENT BEFORE THE EXPRESSION RUNS -- the arm
  ;; itself is not removed, only that occurrence is consumed -- so
  ;; that "a hit" means the same thing for both primitives: this point
  ;; consumed one arming. An earlier version evaluated first, which meant
  ;; an expression that RAISED left the arm unconsumed -- inject-return!
  ;; would have counted it, and the two would have disagreed about what
  ;; the hit count measures. The cost is that a raising expression still
  ;; spends the arm; that is the intended reading.
  (define-syntax inject-override!
    (lambda (x)
      (syntax-case x ()
        ((_ point expr)
         (if (eq? inject-mode 'on)
             #'(let ((slot ($inject-take! point 'return)))
                 (let ((actual expr))
                   (if slot
                       (begin (inject-note-delivered! slot)
                              (vector-ref slot 2))
                       actual)))
             #'expr)))))

  (define-syntax inject-barrier!
    (lambda (x)
      (syntax-case x ()
        ((_ point)
         (if (eq? inject-mode 'on)
             #'(assertion-violation 'inject-barrier!
                 "not implemented in tranche 1" point)
             ;; (void) for the reason given at inject-fault!; a barrier is
             ;; if anything MORE likely to be placed inside a guard.
             #'(void)))))))
