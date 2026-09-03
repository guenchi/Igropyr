;;; inject-isolation.ss -- the gate that keeps the instrument out of the
;;; product. Run from the project root, in the FIRST (ordinary) pass:
;;;
;;;   scheme --libdirs . --libexts .sc --script igropyr/test/inject-isolation.ss
;;;
;;; IT MUST RUN IN ITS OWN PROCESS, and with IGROPYR_INJECT unset. The
;;; switch is read when a library is visited, so a process that has
;;; already expanded something with injection on would answer for that
;;; expansion and not for the build under test.
;;;
;;; IT ASKS TWO QUESTIONS, and they fail differently on purpose:
;;;   1. does an ordinary build refer to the injection runtime at all?
;;;   2. do the three primitives expand to nothing (or to the guarded
;;;      expression) when the switch is off?
;;; The first is the property that matters and the second is what makes
;;; the first true; a failure of (2) with (1) still passing would mean
;;; the expansion changed shape without yet reaching the runtime -- worth
;;; hearing about before it does.
(import (chezscheme))

(define failures 0)
(define (fail! label . info)
  (set! failures (+ failures 1))
  (display "  FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))

;; ---- 0. the process must not be armed -----------------------------------
(let ((v (getenv "IGROPYR_INJECT")))
  (when (and v (string=? v "on"))
    (display "inject-isolation: refusing to run with IGROPYR_INJECT=on\n"
             (current-error-port))
    (exit 2)))

;; ---- 1. the graph, over the WHOLE production set --------------------
;; THE ROOTS ARE THE BUILD LIST, NOT A HANDFUL I CHOSE. A first version
;; walked four libraries I happened to think of; adding an inject-control
;; dependency to any of the other fifty would have gone unseen, and the
;; gate would have said so cheerfully. The denominator has to be the set
;; that actually ships, and that set is already written down once.
(load "igropyr/build-units.ss")

;; The list holds paths; the library names are read out of the sources
;; rather than derived from the paths, because a path is not a name and
;; guessing the mapping is one rename away from being wrong.
(define (library-name-of path)
  (guard (e (#t #f))
    (let* ((port (open-input-file path)) (form (read port)))
      (close-port port)
      (and (pair? form) (eq? (car form) 'library) (cadr form)))))

(define production-libs
  (let loop ((ps library-units) (acc '()))
    (cond ((null? ps) (reverse acc))
          ((library-name-of (car ps)) => (lambda (n) (loop (cdr ps) (cons n acc))))
          (else (fail! "unreadable-unit" (car ps)) (loop (cdr ps) acc)))))

;; A FAILURE TO ASK IS NOT AN ANSWER OF "NO". The first version wrapped
;; both the import and the requirements query in a guard that produced
;; the empty list, so a library that would not load shrank the graph and
;; the gate still printed success -- a check whose failure action is to
;; pass. Each failure is now counted, and counted failures fail the run.
(define (import! lib)
  (guard (e (#t (fail! "library-would-not-import" lib) #f))
    (eval `(import ,lib) (interaction-environment))
    #t))

;; THE INSTRUMENT IS NOT ONE OF ITS OWN ROOTS. (igropyr inject) is a
;; production unit -- libuv imports it, so it has to resolve in a
;; compiled build -- which means it appears in the list this gate reads.
;; Rooting the walk at it makes it trivially a member of its own closure,
;; and the first run of the widened gate failed exactly that way. The
;; question is whether anything ELSE reaches it, so it is excluded from
;; the roots and looked for in the closure of everything else.
(define instrument '((igropyr inject) (igropyr inject-control)))

;; ONLY (igropyr inject) MAY BE EXCLUDED, and the asymmetry is the
;; point. It is a production unit on purpose -- libuv imports it -- so
;; rooting the walk at it would make it trivially its own closure member.
;; (igropyr inject-control) is a different case: its presence in this
;; list is ITSELF the failure, and excluding it unconditionally would
;; have filtered out the exact thing the gate exists to reject.
(when (member '(igropyr inject-control) production-libs)
  (fail! "inject-control-is-a-production-unit"
         "the arming side is listed in build-units.ss"))

(define importable
  (filter import! (filter (lambda (l) (not (equal? l '(igropyr inject))))
                          production-libs)))

;; THE PROGRAMS ARE NOT LIBRARIES AND ARE NOT IN THAT LIST. app.sc is
;; compiled by every whole-program build and qjs-worker.sc is run as a
;; script; neither can be walked with library-requirements, so a direct
;; dependency from either on the instrument would be invisible to the
;; closure above. They are checked the only way they can be -- by reading
;; what they import.
;; A textual check, and weaker than the graph: it sees an import form
;; and not a transitive edge. It is here because the alternative was
;; nothing at all.
(for-each
  (lambda (path)
    (guard (e (#t (fail! "unreadable-program" path)))
      (let* ((port (open-input-file path))
             (text (get-string-all port)))
        (close-port port)
        (for-each
          (lambda (name)
            (when (and (>= (string-length text) 0)
                       (let loop ((i 0))
                         (cond ((> (+ i (string-length name)) (string-length text)) #f)
                               ((string=? (substring text i (+ i (string-length name))) name) #t)
                               (else (loop (+ i 1))))))
              (fail! "program-names-the-instrument" path name)))
          '("(igropyr inject)" "(igropyr inject-control)")))))
  '("igropyr/app.sc" "igropyr/qjs-worker.sc"))

(define (closure-of roots opt)
  (let loop ((todo roots) (seen '()))
    (cond
      ((null? todo) seen)
      ((member (car todo) seen) (loop (cdr todo) seen))
      (else
       (let* ((lib (car todo))
              (reqs (guard (e (#t (fail! "requirements-query-failed" lib) '()))
                      (library-requirements lib opt))))
         (loop (append reqs (cdr todo)) (cons lib seen)))))))

(let ((inv (closure-of importable (library-requirements-options invoke)))
      (imp (closure-of importable (library-requirements-options import))))
  (display "  production roots: ") (display (length production-libs))
  (display "; invoke closure: ") (display (length inv))
  (display "; import closure: ") (display (length imp)) (newline)
  ;; BOTH CLOSURES, AND THEY CATCH DIFFERENT MISTAKES. invoke is the
  ;; property that matters -- nothing shipped may RUN the instrument.
  ;; import is wider and catches the mistake one edit earlier: a library
  ;; that names inject-control even only for expansion.
  (when (member '(igropyr inject-control) inv)
    (fail! "inject-control-reachable-at-runtime"
           "a production library invokes the arming side of the instrument"))
  (when (member '(igropyr inject-control) imp)
    (fail! "inject-control-named-at-expansion"
           "a production library imports the arming side; runtime reach is one edit away"))
  (when (member '(igropyr inject) inv)
    (fail! "inject-runtime-reachable"
           "an ordinary build refers to the injection runtime; the switch was on when it was compiled")))

;; ---- 2. the off expansions ----------------------------------------------
;; One outer form per primitive, compared as data. The comparison is on
;; the EXPANSION, not on behaviour: behaviour can be right for a build
;; that still carries a disabled branch, and a disabled branch is the
;; thing this whole arrangement exists not to ship.
(define (expansion-of form)
  (syntax->datum (expand form (interaction-environment))))

(eval '(import (igropyr inject)) (interaction-environment))

;; COMPARED AGAINST A REFERENCE EXPANSION, NOT A GUESSED LITERAL.
;; (begin) does not expand to the datum (begin) -- it expands to whatever
;; this Chez uses for "no value", which was ($primitive 2 void) the first
;; time this check ran and is nobody's business to predict. Expanding the
;; equivalent form in the same process and comparing the two answers is
;; the same question asked in a way that cannot go stale.
(define nothing (expansion-of '(begin)))

(let ((e (expansion-of '(inject-fault! 'p))))
  (unless (equal? e nothing)
    (fail! "inject-fault-off-expansion" e 'expected nothing)))

(let ((e (expansion-of '(inject-return! 'p 41))))
  (unless (equal? e (expansion-of '41))
    (fail! "inject-return-off-expansion" e)))

(let ((e (expansion-of '(inject-barrier! 'p))))
  (unless (equal? e nothing)
    (fail! "inject-barrier-off-expansion" e 'expected nothing)))

;; ---- the barrier's atomicity, at the form level -------------------------
;; No instrument can force a take and a release to interleave, so the one
;; claim that CAN be checked is that each of them is one region: the body
;; of $inject-take!, $inject-release! and $inject-disarm! begins with
;; with-interrupts-disabled, and $inject-barrier holds exactly ONE such
;; sub-form with the parker call outside it (parking inside a region would
;; hand the region's atomicity to the victim's scheduler).
;;
;; THE `on` CLAUSE IS SELECTED FIRST. The two meta-cond branches are not
;; symmetric -- three of the four primitives have an off-mode stub and one
;; does not -- so "the define with this name" answers differently per name
;; unless the clause is fixed before the name is looked up.
;;
;; This proves "wrapped", not "wrapped correctly": what the region encloses
;; is read by people, not by this file.
(define inject-forms
  (guard (e (#t (fail! "inject-source-unreadable" "igropyr/inject.sc") '()))
    (let ((port (open-input-file "igropyr/inject.sc")))
      (let loop ((acc '()))
        (let ((x (read port)))
          (if (eof-object? x) (begin (close-port port) (reverse acc)) (loop (cons x acc))))))))

(define (find-forms pred tree)
  (cond ((pred tree) (list tree))
        ((pair? tree) (append (find-forms pred (car tree)) (find-forms pred (cdr tree))))
        (else '())))

(define on-clause
  (let ((mc (find-forms (lambda (x) (and (pair? x) (eq? (car x) 'meta-cond))) inject-forms)))
    (if (null? mc)
        (begin (fail! "inject-meta-cond-not-found") '())
        (let ((cl (filter (lambda (c) (and (pair? c) (equal? (car c) '(eq? inject-mode 'on)))) (cdr (car mc)))))
          (if (= (length cl) 1) (cdr (car cl)) (begin (fail! "inject-on-clause-count" (length cl)) '()))))))

(define (definition-body name)
  (let ((ds (filter (lambda (d) (and (pair? d) (eq? (car d) 'define) (pair? (cadr d)) (eq? (car (cadr d)) name))) on-clause)))
    (if (= (length ds) 1) (cddr (car ds)) (begin (fail! "inject-definition-count" name (length ds)) '()))))

(for-each
  (lambda (name)
    (let ((body (definition-body name)))
      (unless (and (pair? body) (pair? (car body)) (eq? (car (car body)) 'with-interrupts-disabled) (null? (cdr body)))
        (fail! "inject-primitive-not-one-region" name (and (pair? body) (car body))))))
  '($inject-take! $inject-release! $inject-disarm!))

(let* ((body (definition-body '$inject-barrier))
       (regions (find-forms (lambda (x) (and (pair? x) (eq? (car x) 'with-interrupts-disabled))) body))
       (parker-calls (find-forms (lambda (x) (and (pair? x) (pair? (car x)) (eq? (car (car x)) 'vector-ref) (equal? (cdr (car x)) '(v 2)))) body)))
  (unless (= (length regions) 1)
    (fail! "inject-barrier-region-count" (length regions)))
  (unless (= (length parker-calls) 1)
    (fail! "inject-barrier-parker-call-count" (length parker-calls)))
  (when (and (= (length regions) 1) (= (length parker-calls) 1)
             (pair? (find-forms (lambda (x) (eq? x (car parker-calls))) (car regions))))
    (fail! "inject-barrier-parker-called-inside-region")))

(if (= failures 0)
    (begin (display "inject isolation: instrument absent from an ordinary build\n") (exit 0))
    (begin (display "inject isolation: FAILED\n") (exit 1)))
