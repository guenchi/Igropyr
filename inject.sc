;;; inject.sc -- fault-injection primitives for igropyr's own test suite.
;;;
;;; ⛔ THIS LIBRARY IS A TEST INSTRUMENT AND MUST NOT SHIP ARMED. What
;;; makes that true is not discipline; it is that the switch is read at
;;; EXPANSION time, exactly as (igropyr checked) reads IGROPYR_CONTRACTS,
;;; so a build made with IGROPYR_INJECT unset contains no injection code
;;; at all -- not a disabled branch, not a flag test, nothing.
;;;
;;; Three primitives, and each is placed under a rule:
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
;;; ⭐ THE 'on EXPANSION DELIBERATELY REFERENCES A RUNTIME IDENTIFIER OF
;;; THIS LIBRARY. That is what makes the invoke-time check below reachable
;;; from a compiled artifact: a library is invoked when something refers
;;; to its runtime part, and an expansion that inlined everything would
;;; leave the check unreachable in exactly the artifact it exists to
;;; catch. Measured, not assumed -- with IGROPYR_CONTRACTS the analogous
;;; consumer reports invoke-requirements () when off and ((igropyr
;;; checked)) when on, at optimize-level 2.
(library (igropyr inject)
  (export inject-fault! inject-return! inject-barrier!
          $inject-arm! $inject-release! $inject-disarm! $inject-hits
          $inject-ticket $inject-armed-points)
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
     ;; Slot layout: #(point kind value occurrence hits ticket ok?)
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
     ;; ⭐ EVERY FIELD IS CHECKED, not only the injected value. occurrence
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
           ((uv-write-neg)
            (unless (and (fixnum? value) (fx< value 0) (fx> value -65536))
              (assertion-violation '$inject-arm!
                "uv-write-neg needs an exact negative errno in C int range"
                value)))
           ;; a positive count would claim a prefix reached the wire and
           ;; make the caller queue only the suffix.
           ((try-write-eagain)
            (unless (and (fixnum? value) (fx<= value 0))
              (assertion-violation '$inject-arm!
                "try-write-eagain needs an exact value <= 0" value)))
           ;; a point nobody has reasoned about yet arrives with its own
           ;; argument; this table constrains the ones we have.
           (else (void)))))

     (define ($inject-arm! point kind value occurrence ok?)
       (check-arm! point kind value occurrence)
       (let ((t ($inject-ticket)))
         (hashtable-set! $inject-table point
                         (vector point kind value occurrence 0 t ok?))
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
     ;; ---- off: names exist so the export list is one text, and nothing
     ;; refers to them, so a consumer's invoke-requirements stay empty.
     (define ($inject-ticket) 0)
     (define ($inject-arm! point kind value occurrence ok?) 0)
     (define ($inject-release! ticket) (void))
     (define ($inject-disarm!) (void))
     (define ($inject-hits point) #f)
     (define ($inject-armed-points) '())))

  ;; ---- the three primitives ---------------------------------------------

  (define-syntax inject-fault!
    (lambda (x)
      (syntax-case x ()
        ((_ point)
         (if (eq? inject-mode 'on)
             #'(when ($inject-take! point 'fault)
                 (assertion-violation 'inject-fault! "injected failure" point))
             #'(begin))))))

  (define-syntax inject-return!
    (lambda (x)
      (syntax-case x ()
        ((_ point expr)
         (if (eq? inject-mode 'on)
             #'(let ((slot ($inject-take! point 'return)))
                 (if slot (vector-ref slot 2) expr))
             #'expr)))))

  (define-syntax inject-barrier!
    (lambda (x)
      (syntax-case x ()
        ((_ point)
         (if (eq? inject-mode 'on)
             #'(assertion-violation 'inject-barrier!
                 "not implemented in tranche 1" point)
             #'(begin)))))))
