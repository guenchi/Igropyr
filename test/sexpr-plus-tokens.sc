#!chezscheme
;; A conforming writer spells NaN and the infinities +nan.0 +inf.0 -inf.0. This
;; reader turned each into a SYMBOL of that name, silently, while the same
;; writer's 1.5 was refused out loud: numeric-shape? catches a leading digit
;; or '-' plus a digit, and a leading '+' fell through to the symbol path.
;; Ruling: the strict profile REFUSES them (it carries no flonum, so there is
;; no value for them to be), the extended profile READS exactly those three as
;; flonums, and in both profiles a bare name is held to wire-symbol? -- the
;; writer's own predicate -- so bare and escaped spellings of one name agree.
;; Every check is pure.
(import (chezscheme) (igropyr sexpr))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
;; a refusal must be this reader's own #(sexpr-error msg pos)
(define (verdict reader text)
  (guard (e (#t (if (and (vector? e) (fx>= (vector-length e) 2) (eq? (vector-ref e 0) 'sexpr-error))
                    'REFUSED
                    (vector 'UNEXPECTED e))))
    (let ((v (reader (string-append "(x " text ")"))))
      (if (and (pair? v) (pair? (cdr v)) (null? (cddr v))) (cadr v) (vector 'SHAPE v)))))
(define (strict text) (verdict string->sexpr text))
(define (ext text) (verdict string->sexpr-extended text))
(define (sym name) (string->symbol name))

;; ---- STRICT: the six are refused, with the reader's own error ------------------
(for-each (lambda (t) (check (string-append "strict refuses " t) (eq? (strict t) 'REFUSED) (strict t)))
          '("+nan.0" "+inf.0" "-inf.0" "-nan.0" "+15" "+i"))
;; the writer could never have produced any of them
(for-each (lambda (t) (check (string-append "the writer refuses the symbol " t)
                             (guard (e (#t #t)) (sexpr->string (list 'x (sym t))) #f)))
          '("+nan.0" "+inf.0" "-inf.0" "-nan.0" "+15" "+i"))
;; ---- STRICT: what must not change --------------------------------------------------
(check "strict: 15 is the number 15" (eqv? (strict "15") 15) (strict "15"))
(check "strict: -15 is the number -15" (eqv? (strict "-15") -15) (strict "-15"))
(check "strict: 1/2 is a rational" (eqv? (strict "1/2") 1/2) (strict "1/2"))
(check "strict: 1.5 is still refused (no flonum in this profile)" (eq? (strict "1.5") 'REFUSED) (strict "1.5"))
(for-each (lambda (t) (check (string-append "strict: " t " is still a symbol") (eq? (strict t) (sym t)) (strict t)))
          '("+" "-" "..." "+a" "a+b" "a->b" "set!" "*-+<=>?!._%&^~:@"))
(check "strict: a plus inside a name is fine" (eq? (strict "x+15") (sym "x+15")) (strict "x+15"))
;; the rest of the refusal set: the bare dot, and dot- or sign-leading tokens
;; that Chez reads as numbers. Complete-token recognition: +1a, +1/0, .5i, ...
;; are NOT numbers and stay symbols
(for-each (lambda (t) (check (string-append "strict refuses " t " (a numeral in Chez's eyes, unwritable here)") (eq? (strict t) 'REFUSED) (strict t)))
          '("." "-.5" ".5" "+1/2" ".5e2" "-NaN.0" "+I"))
;; NOT through the wrapper: "(x " + ". a" + ")" is "(x . a)", which is the
;; DOTTED PAIR syntax and must keep working. The rows below say what was
;; meant -- a dot where a datum is expected is refused, a dot between two
;; data is a pair
(check "a dot where a datum is expected is refused" (eq? (guard (e (#t 'REFUSED)) (string->sexpr "(. a)")) 'REFUSED))
(check "a bare dot is refused" (eq? (guard (e (#t 'REFUSED)) (string->sexpr ".")) 'REFUSED))
(check "a dotted pair still reads" (equal? (guard (e (#t 'REFUSED)) (string->sexpr "(x . a)")) '(x . a))
       (guard (e (#t 'REFUSED)) (string->sexpr "(x . a)")))
;; A SHAPE THAT IS NOT A BARE TOKEN and changes side with this batch: the first
;; dot is eaten by the list parser as the pair marker, the SECOND goes through
;; parse-atom, so (x . .) used to build a pair whose cdr is the symbol "." --
;; a pair the writer refuses to write. It is refused now, which is the
;; invariant applied in a position the single-token corpus never reaches
(check "(x . .) is refused: its cdr would be a symbol the writer cannot write"
       (eq? (guard (e (#t 'REFUSED)) (string->sexpr "(x . .)")) 'REFUSED)
       (guard (e (#t 'REFUSED)) (string->sexpr "(x . .)")))
(check "(a b . .) likewise" (eq? (guard (e (#t 'REFUSED)) (string->sexpr "(a b . .)")) 'REFUSED))
(check "and the writer does refuse that pair"
       (guard (e (#t #t)) (sexpr->string (cons 'x (string->symbol "."))) #f))
;; THE TOKEN CAP BOUNDS THE CHANGE. A name past the cap was refused before and
;; is refused now, by the cap and not by this rule, so it does NOT change side:
;; the rule's domain is tokens within the cap. The pair below is the boundary
(check "a +-and-zeros name inside the cap changes side (refused now)"
       (eq? (verdict string->sexpr (string-append "+" (make-string 65535 #\0))) 'REFUSED))
(check "one past the cap was already refused, by the cap"
       (eq? (verdict string->sexpr (string-append "+" (make-string 65536 #\0))) 'REFUSED))
(for-each (lambda (t) (check (string-append "strict: " t " stays a symbol (not a complete numeral)") (eq? (strict t) (sym t)) (strict t)))
          '("+1a" "+1/0" ".5i" ".a" "-a"))

;; ---- EXTENDED: the three spellings read as flonums ----------------------------------
(let ((v (ext "+nan.0")))
  (check "extended: +nan.0 is a NaN flonum" (and (flonum? v) (nan? v)) v))
(check "extended: +inf.0 is +inf.0" (and (flonum? (ext "+inf.0")) (= (ext "+inf.0") +inf.0)) (ext "+inf.0"))
(check "extended: -inf.0 is -inf.0" (and (flonum? (ext "-inf.0")) (= (ext "-inf.0") -inf.0)) (ext "-inf.0"))
;; nested positions go through the same atom parser: a vector element, a pair
;; tail, and after the symbol quote (which is only a symbol in this grammar).
;; NaN is asserted with nan?, never with =
(let ((v (guard (e (#t 'REFUSED)) (string->sexpr-extended "#(+nan.0)"))))
  (check "extended: +nan.0 inside a vector is a NaN" (and (vector? v) (= (vector-length v) 1) (flonum? (vector-ref v 0)) (nan? (vector-ref v 0))) v))
(let ((v (guard (e (#t 'REFUSED)) (string->sexpr-extended "(a . +inf.0)"))))
  (check "extended: +inf.0 as a pair tail" (and (pair? v) (flonum? (cdr v)) (= (cdr v) +inf.0)) v))
(let ((v (guard (e (#t 'REFUSED)) (string->sexpr-extended "(quote -inf.0)"))))
  (check "extended: -inf.0 after the symbol quote is still the number" (and (pair? v) (pair? (cdr v)) (flonum? (cadr v)) (= (cadr v) -inf.0)) v))
;; the spellings are exact: case and sign matter
;; the three spellings are exact, and the boundary is NOT "how close it looks":
;; +NaN.0, +Inf.0 and -Nan.0 are refused because CHEZ READS THEM AS NUMBERS, so
;; the writer refuses those names and the reader must too. +nan.00, +inf and
;; inf.0 are not numbers to Chez, the writer writes them, and refusing them
;; would build the mirror image of the asymmetry this batch removes: writable
;; and not receivable. The first version of this list had all six, and also
;; had inf.0 in the "still a symbol" list below -- two rows of one file
;; asserting opposite things about one token
(for-each (lambda (t) (check (string-append "extended refuses " t " (Chez reads it as a number, so the writer refuses the name)") (eq? (ext t) 'REFUSED) (ext t)))
          '("+NaN.0" "+Inf.0" "-Nan.0" "-NAN.0"))
(for-each (lambda (t) (check (string-append "extended: " t " stays a symbol (the writer can write it)") (eq? (ext t) (sym t)) (ext t)))
          '("+nan.00" "+inf" "inf.0" "nan.0" "+inf.00"))
;; ...and nothing else becomes a number
(for-each (lambda (t) (check (string-append "extended refuses " t) (eq? (ext t) 'REFUSED) (ext t)))
          '("-nan.0" "1.5" "1e3" "+15" "+i" "+1" "+5"))
(for-each (lambda (t) (check (string-append "extended: " t " is still a symbol") (eq? (ext t) (sym t)) (ext t)))
          '("+" "+a" "a+b" "nan.0" "inf.0"))
;; the writer keeps its own spelling: read the conforming one, write ours, read again
;; the write is guarded: on the old tree the value is a SYMBOL the writer
;; refuses, and a row may be red there but must not take the file down
(define (write-ext v) (guard (e (#t 'WRITE-REFUSED)) (sexpr->string-extended (list 'x v))))
(let* ((v (ext "+inf.0")) (w (write-ext v)))
  (check "extended round trip: +inf.0 -> #f8 -> +inf.0"
         (and (string? w) (let ((back (ext (substring w 3 (- (string-length w) 1))))) (and (flonum? back) (= back +inf.0)))) w))
(let* ((v (ext "+nan.0")) (w (write-ext v)))
  (check "extended round trip: NaN -> #f8 -> NaN"
         (and (string? w) (let ((back (ext (substring w 3 (- (string-length w) 1))))) (and (flonum? back) (nan? back)))) w))
(check "extended: the writer still emits #f8, never +inf.0"
       (let ((w (sexpr->string-extended (list 'x +inf.0)))) (and (string? w) (not (string=? w "(x +inf.0)")) (string=? (substring w 0 7) "(x #f8\"")))
       (sexpr->string-extended (list 'x +inf.0)))
;; strict still does not read them, whatever extended does
(check "strict: +inf.0 is refused, not a flonum" (eq? (strict "+inf.0") 'REFUSED) (strict "+inf.0"))

;; ---- bare and escaped spellings of one name give one verdict ------------------------
;; the first character hex-escaped; a name is a name however it is spelled
(define (escaped-first t)
  (string-append "\\x" (number->string (char->integer (string-ref t 0)) 16) ";" (substring t 1 (string-length t))))
;; in STRICT, for every candidate name: one verdict however it is spelled
(for-each
  (lambda (t)
    (let ((a (strict t)) (b (strict (escaped-first t))))
      (check (string-append "strict: bare and escaped agree on " t) (equal? a b) a b (escaped-first t))))
  '("+15" "+i" "+nan.0" "-.5" "." "+a" "abc" "a->b" "+" "..."))
;; in EXTENDED the three literals are the one exemption: bare +nan.0 is a
;; flonum and an escape can only ever spell a SYMBOL, so \x2b;nan.0 stays
;; refused. Everything else agrees
(for-each
  (lambda (t)
    (let ((a (ext t)) (b (ext (escaped-first t))))
      (check (string-append "extended: bare and escaped agree on " t) (equal? a b) a b (escaped-first t))))
  '("+15" "+i" "-nan.0" "-.5" "." "+a" "abc" "+"))
(check "extended: the escaped spelling of +nan.0 is refused (it can only name a symbol)" (eq? (ext (escaped-first "+nan.0")) 'REFUSED) (ext (escaped-first "+nan.0")))

;; ---- the two vendored rows that move ---------------------------------------------------
;; read-plus-int (+1), read-plus-five (+5), read-dot-alone (.) and read-symbol-dot
;; ((. a)) were generated from the hole and recorded as accepted; they are
;; refused now. test/sexpr-fixture-read.sc
;; names them on its exception list -- a row moving sides has to be named in
;; both places
(check "golden read-plus-int now refuses" (eq? (ext "+1") 'REFUSED) (ext "+1"))
(check "golden read-plus-five now refuses" (eq? (ext "+5") 'REFUSED) (ext "+5"))
(check "golden read-dot-alone now refuses" (eq? (verdict string->sexpr-extended ".") 'REFUSED))
(check "golden read-symbol-dot now refuses" (eq? (guard (e (#t 'REFUSED)) (string->sexpr-extended "(. a)")) 'REFUSED))

;; ---- THE RULING AS ONE INVARIANT ------------------------------------------------
;; Everything above is an instance of this: in the strict profile a bare token
;; reads as a symbol EXACTLY WHEN the writer can write that symbol. Derived
;; from the writer at run time rather than from a list someone kept in their
;; head -- the near-miss list above got three of six wrong precisely because
;; it was such a list, and a self-contradicting one
(define (writer-takes? name) (guard (e (#t #f)) (sexpr->string (list 'x (sym name))) #t))
(for-each
  (lambda (name)
    ;; NOT (symbol? r): the refusal marker is the symbol REFUSED, so every
;; refusal counted as "read back as a symbol". Accepted means it read back
    ;; as EXACTLY this name
    (let* ((w (writer-takes? name)) (r (strict name)) (accepted (eq? r (sym name))))
      (check (string-append "reader and writer agree on " name
                            (if w " (writable, so readable)" " (unwritable, so refused)"))
             (eq? w accepted) 'writer w 'reader r)))
  '("+nan.0" "+inf.0" "-inf.0" "-nan.0" "+15" "+i" "+1/2" "-.5" ".5" ".5e2" "+I" "-NaN.0"
    "+nan.00" "+inf" "inf.0" "nan.0" "+" "-" "..." "+a" "-a" "a+b" "abc" "a->b" "set!"
    "+1a" "+1/0" ".5i" ".a" "x+15" "*-+<=>?!._%&^~:@"))

;; ---- THE TOKEN WHERE LOOKING AND ASKING DISAGREE ----------------------------------
;; Every other row in this file answers the same under "refuse a leading +" and
;; under "ask the writer". Only these separate them, and they are the shape a
;; reader of the prose gets wrong: a consumer of the other implementation
;; narrowed their own core against a changelog sentence that had flattened the
;; rule into one about how a token starts. The rows above test the code, which
;; was right; nothing tested the description.
(for-each (lambda (t) (check (string-append "a leading + is NOT the rule: " t " is still a symbol") (eq? (strict t) (sym t)) (strict t)))
          '("+x" "+xyz" "+_" "+." "+-"))

(if (zero? fails)
    (begin (display "ALL SEXPR-PLUS-TOKENS TESTS PASSED\n") (exit 0))
    (begin (display "SEXPR-PLUS-TOKENS VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
