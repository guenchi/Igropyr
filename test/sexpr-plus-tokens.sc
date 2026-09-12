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

;; ---- EXTENDED: the three spellings read as flonums ----------------------------------
(let ((v (ext "+nan.0")))
  (check "extended: +nan.0 is a NaN flonum" (and (flonum? v) (nan? v)) v))
(check "extended: +inf.0 is +inf.0" (and (flonum? (ext "+inf.0")) (= (ext "+inf.0") +inf.0)) (ext "+inf.0"))
(check "extended: -inf.0 is -inf.0" (and (flonum? (ext "-inf.0")) (= (ext "-inf.0") -inf.0)) (ext "-inf.0"))
;; ...and nothing else becomes a number
(for-each (lambda (t) (check (string-append "extended refuses " t) (eq? (ext t) 'REFUSED) (ext t)))
          '("-nan.0" "1.5" "1e3" "+15" "+i" "+1" "+5"))
(for-each (lambda (t) (check (string-append "extended: " t " is still a symbol") (eq? (ext t) (sym t)) (ext t)))
          '("+" "+a" "a+b" "nan.0" "inf.0"))
;; the writer keeps its own spelling: read the conforming one, write ours, read again
(let* ((v (ext "+inf.0")) (w (sexpr->string-extended (list 'x v))))
  (check "extended round trip: +inf.0 -> #f8 -> +inf.0" (and (string? w) (= (ext (substring w 3 (- (string-length w) 1))) +inf.0)) w))
(let* ((v (ext "+nan.0")) (w (sexpr->string-extended (list 'x v))))
  (check "extended round trip: NaN -> #f8 -> NaN" (and (string? w) (nan? (ext (substring w 3 (- (string-length w) 1))))) w))
(check "extended: the writer still emits #f8, never +inf.0"
       (let ((w (sexpr->string-extended (list 'x +inf.0)))) (and (string? w) (not (string=? w "(x +inf.0)")) (string=? (substring w 0 7) "(x #f8\"")))
       (sexpr->string-extended (list 'x +inf.0)))
;; strict still does not read them, whatever extended does
(check "strict: +inf.0 is refused, not a flonum" (eq? (strict "+inf.0") 'REFUSED) (strict "+inf.0"))

;; ---- bare and escaped spellings of one name give one verdict ------------------------
;; the first character hex-escaped; a name is a name however it is spelled
(define (escaped-first t)
  (string-append "\\x" (number->string (char->integer (string-ref t 0)) 16) ";" (substring t 1 (string-length t))))
(for-each
  (lambda (t)
    (let ((a (strict t)) (b (strict (escaped-first t))))
      (check (string-append "bare and escaped agree on " t) (equal? a b) a b (escaped-first t))))
  '("+15" "+i" "+nan.0" "+a" "abc" "a->b" "+" "..."))

;; ---- the two vendored rows that move ---------------------------------------------------
;; read-plus-int (+1) and read-plus-five (+5) were generated from the hole and
;; recorded as accepted; they are refused now. test/sexpr-fixture-read.sc
;; names them on its exception list -- a row moving sides has to be named in
;; both places
(check "golden read-plus-int now refuses" (eq? (ext "+1") 'REFUSED) (ext "+1"))
(check "golden read-plus-five now refuses" (eq? (ext "+5") 'REFUSED) (ext "+5"))

(if (zero? fails)
    (begin (display "ALL SEXPR-PLUS-TOKENS TESTS PASSED\n") (exit 0))
    (begin (display "SEXPR-PLUS-TOKENS VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
