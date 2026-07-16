#!chezscheme
;;; (igropyr checked) -- dev-time contract macros for internal invariants.
;;;
;;; WARNING: never rely on this library for production requirements.
;;; Contracts default to OFF (IGROPYR_CONTRACTS unset) and compile to
;;; nothing: plain define / define-record-type, zero residue, zero
;;; runtime dependency on this library. Validation of external input
;;; is ordinary business code, always on, and must not live here.
;;;
;;; Where each kind of checking belongs:
;;;
;;;   external input, semantics (range/length/path/permission)
;;;     -> ordinary code, your duty; not a contract, not this library
;;;   external input, shape (json/form/wire -> values)
;;;     -> ordinary code, or a hand-written parse-x; not this library
;;;   internal invariants (bugs in our own code)
;;;     -> define-checked / define-checked-record; IGROPYR_CONTRACTS
;;;   last resort
;;;     -> Chez safe primitives + let-it-crash; always on
;;;
;;; WARNING: never put a return contract (-> pred) on a tail-recursive
;;; or looping procedure. The return check must capture the return
;;; value, which structurally destroys tail calls: the loop grows
;;; memory with depth. Argument contracts are TCO-safe -- they run
;;; once on entry and never touch the return path. Canonical idiom:
;;;
;;;   (define-checked (find-route (table route-table?) (path string?))
;;;     (let loop ((segs (split path)))  ; internal named let: unchecked,
;;;       ...))                          ; free, and cannot take -> anyway
;;;
;;; API:
;;;
;;;   (define-checked (name (arg pred) ...) body ...)
;;;   (define-checked (name (arg pred) ...) -> ret-pred body ...)
;;;
;;;     pred is any one-place predicate expression; prefer named
;;;     predicates (route-table?) over inline lambdas -- blame prints
;;;     the predicate's source text. A bare arg (no pred) is allowed
;;;     and unchecked; keep those rare and deliberate. Fixed arity
;;;     only: no optional/rest args, no case-lambda. The return
;;;     contract checks a single value only; procedures returning
;;;     multiple values may use argument contracts but no ->.
;;;     Cross-argument invariants belong in the body, not here.
;;;
;;;   (define-checked-record name
;;;     (field pred)             ; immutable (the default)
;;;     (mutable field pred))    ; mutable, with a checked setter
;;;
;;;     Expands to define-record-type with the usual names: make-name,
;;;     name?, name-field, name-field-set!. The constructor and the
;;;     setters check field contracts; the predicate and accessors are
;;;     the raw record ones -- reads are free. Only make-name is
;;;     generated: no parse-x, no parent, no protocol, no
;;;     nongenerative. Records needing those use the plain form.
;;;
;;;   (contract-level)
;;;
;;;     Expands to the literal 'full or 'off baked at the expansion
;;;     site. Print it at startup; assert it at the top of test suites.
;;;
;;; Switch: IGROPYR_CONTRACTS, read once per compiling process at
;;; expansion time. Unset or "off" -> off; "full" -> full; anything
;;; else -> expansion-time error, so a misspelled value can never
;;; silently disable checking. The level is baked into each compiled
;;; .so at that .so's compile time: after changing the flag, do a
;;; CLEAN rebuild, or different libraries will disagree.
;;;
;;; Blame: violations raise &assertion via assertion-violation, with
;;; who = the procedure, a message naming the argument/field and the
;;; expected predicate, and the offending value as the irritant:
;;;
;;;   Exception in f: argument 'x' violated contract string?
;;;     with irritant 42
;;;
;;; Guidelines: use define-checked on exported procedures (module
;;; boundaries); keep internal helpers plain. New exported procedures
;;; default to define-checked; new records default to
;;; define-checked-record with immutable fields.

(library (igropyr checked)
  (export define-checked define-checked-record contract-level ->)
  (import (chezscheme))

  ;; -> is exported as an auxiliary keyword (like else or fields) so the
  ;; return-contract pattern matches by binding at every import site.
  (define-syntax ->
    (lambda (x)
      (syntax-violation '-> "misplaced auxiliary keyword" x)))

  ;; ---- switch: read once per compiling process, at visit time ----------

  (meta define contract-mode
    (let ((v (getenv "IGROPYR_CONTRACTS")))
      (cond
        ((or (not v) (string=? v "off")) 'off)
        ((string=? v "full") 'full)
        (else (assertion-violation 'igropyr-checked
                "IGROPYR_CONTRACTS must be \"full\", \"off\", or unset"
                v)))))

  ;; ---- expand-time helpers ----------------------------------------------

  (meta define (stx->list stx)
    (syntax-case stx ()
      (() '())
      ((x . rest) (cons #'x (stx->list #'rest)))))

  ;; build an identifier in ctx's scope from strings and identifiers
  (meta define (mk-id ctx . parts)
    (datum->syntax ctx
      (string->symbol
        (apply string-append
          (map (lambda (p)
                 (if (string? p) p (symbol->string (syntax->datum p))))
               parts)))))

  ;; ---- runtime blame helpers (referenced only by full expansions) ------

  (define ($blame-arg who arg pred val)
    (assertion-violation who
      (format "argument '~a' violated contract ~s" arg pred)
      val))

  (define ($blame-ret who pred val)
    (assertion-violation who
      (format "return value violated contract ~s" pred)
      val))

  (define ($blame-field who rec field pred val)
    (assertion-violation who
      (format "field '~a' of record '~a' violated contract ~s"
              field rec pred)
      val))

  ;; ---- (contract-level) -------------------------------------------------

  (define-syntax contract-level
    (lambda (x)
      (syntax-case x ()
        ((k) #`(quote #,(datum->syntax #'k contract-mode))))))

  ;; ---- define-checked -----------------------------------------------------

  (define-syntax define-checked
    (lambda (x)
      (define (formal-id f)
        (syntax-case f ()
          (id (identifier? #'id) #'id)
          ((id pred) (identifier? #'id) #'id)
          (_ (syntax-violation 'define-checked "malformed parameter" x f))))
      (define (formal-check name f)
        (syntax-case f ()
          (id (identifier? #'id) #f)         ; bare arg: unchecked
          ((id pred)
           #`(unless (pred id) ($blame-arg '#,name 'id 'pred id)))))
      (define (build name formals ret-pred bodies)
        (let ((args (map formal-id formals)))
          (if (eq? contract-mode 'off)
              #`(define (#,name #,@args) #,@bodies)
              (let ((checks (filter values
                              (map (lambda (f) (formal-check name f))
                                   formals))))
                ;; (let () body ...) keeps internal defines legal after
                ;; the checks and sits in tail position, so argument
                ;; contracts do not break TCO. A return contract must
                ;; capture the value -- structurally non-tail.
                (if ret-pred
                    #`(define (#,name #,@args)
                        #,@checks
                        (let ((r (let () #,@bodies)))
                          (unless (#,ret-pred r)
                            ($blame-ret '#,name '#,ret-pred r))
                          r))
                    #`(define (#,name #,@args)
                        #,@checks
                        (let () #,@bodies)))))))
      (syntax-case x (->)
        ((_ (name f ...) -> ret-pred body0 body ...)
         (identifier? #'name)
         (build #'name (stx->list #'(f ...)) #'ret-pred
                (stx->list #'(body0 body ...))))
        ((_ (name f ...) body0 body ...)
         (identifier? #'name)
         (build #'name (stx->list #'(f ...)) #f
                (stx->list #'(body0 body ...)))))))

  ;; ---- define-checked-record ----------------------------------------------

  (define-syntax define-checked-record
    (lambda (x)
      ;; field spec -> (mutable? id pred)
      (define (parse-field f)
        (syntax-case f ()
          ((kw id pred)
           (and (identifier? #'kw)
                (eq? (syntax->datum #'kw) 'mutable)
                (identifier? #'id))
           (list #t #'id #'pred))
          ((id pred)
           (identifier? #'id)
           (list #f #'id #'pred))
          (_ (syntax-violation 'define-checked-record "malformed field" x f))))
      (syntax-case x ()
        ((_ name fld ...)
         (identifier? #'name)
         ;; NB: this expand-time list must NOT be named `fields` -- a
         ;; transformer-local binding shadows the identifier inside the
         ;; templates below, and (fields ...) would no longer refer to
         ;; define-record-type's auxiliary keyword.
         (let* ((flds (map parse-field (stx->list #'(fld ...))))
                (name-id #'name)
                (maker (mk-id name-id "make-" name-id))
                (rpred (mk-id name-id name-id "?"))
                (acc (lambda (f) (mk-id name-id name-id "-" (cadr f))))
                (mut (lambda (f) (mk-id name-id name-id "-" (cadr f) "-set!"))))
           (if (eq? contract-mode 'off)
               ;; plain record, public names bound directly: zero residue
               #`(define-record-type (#,name-id #,maker #,rpred)
                   (fields
                     #,@(map (lambda (f)
                               (if (car f)
                                   #`(mutable #,(cadr f) #,(acc f) #,(mut f))
                                   #`(immutable #,(cadr f) #,(acc f))))
                             flds)))
               ;; full: raw record under internal names, checked wrappers
               ;; for the constructor and setters; predicate and accessors
               ;; stay raw -- reads are free
               (let ((imaker (car (generate-temporaries '(make))))
                     (imuts (map (lambda (f)
                                   (and (car f)
                                        (car (generate-temporaries '(set)))))
                                 flds)))
                 #`(begin
                     (define-record-type (#,name-id #,imaker #,rpred)
                       (fields
                         #,@(map (lambda (f im)
                                   (if (car f)
                                       #`(mutable #,(cadr f) #,(acc f) #,im)
                                       #`(immutable #,(cadr f) #,(acc f))))
                                 flds imuts)))
                     (define (#,maker #,@(map cadr flds))
                       #,@(map (lambda (f)
                                 #`(unless (#,(caddr f) #,(cadr f))
                                     ($blame-field '#,maker '#,name-id
                                                   '#,(cadr f) '#,(caddr f)
                                                   #,(cadr f))))
                               flds)
                       (#,imaker #,@(map cadr flds)))
                     #,@(filter values
                          (map (lambda (f im)
                                 (and (car f)
                                      #`(define (#,(mut f) r v)
                                          (unless (#,(caddr f) v)
                                            ($blame-field '#,(mut f) '#,name-id
                                                          '#,(cadr f) '#,(caddr f)
                                                          v))
                                          (#,im r v))))
                               flds imuts)))))))))))
