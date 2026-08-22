#!chezscheme
;;; (igropyr json) read-side acceptance surface, pinned row by row.
;;;
;;; LOCKSTEP CONTRACT. This reader has a wire counterpart: the
;;; browser-side (Goeteia) JSON reader, each parsing what the other
;;; side's writer -- or the same third-party client -- produces. The
;;; two readers share a small set of DELIBERATELY DOCUMENTED
;;; deviations from RFC 8259's read grammar, and tightening any of
;;; them on ONE side manufactures a wire asymmetry: input one side
;;; accepts and the other refuses. So every row below is pinned,
;;; the deviations included -- a "fix" that flips an ACCEPT row goes
;;; red here on purpose, and the answer is not to update the row but
;;; to coordinate a lockstep change with the counterpart first.
;;;
;;; The deviation set was measured by survey, not collected from
;;; reports: every token the number tokenizer can hand to Chez's
;;; string->number was probed class by class. TWO classes deviate,
;;; and both are SHARED with the counterpart:
;;;
;;;   A. leading zeros in the integer part      "01" "-01" "00" "01.5"
;;;   C. bare control characters inside strings (RFC requires \u
;;;      escapes; the scanner passes them through)
;;;
;;; Those two rows are ACCEPT because the counterpart accepts them too,
;;; and that is the whole of the reason. IF BOTH SIDES EVER TIGHTEN
;;; THEM IN ONE COORDINATED CHANGE, THESE ROWS AND THIS PARAGRAPH ARE
;;; DELETED, NOT EDITED -- a retention clause that outlives its reason
;;; keeps looking valid long after the world moved.
;;;
;;; A third class existed on this side alone -- missing digits beside
;;; the dot ("5." "5.e3" "-.5"), out of the same string->number
;;; delegation -- and was REMOVED rather than documented: the lockstep
;;; rule forbids unilaterally tightening the SHARED surface, but a
;;; deviation only one side has IS the asymmetry, and removing it is
;;; the fix. The counterpart's hand-written grammar always rejected
;;; these; the rows below now pin this side to the same answer.
;;;
;;; TWO SETS, NOT ONE. The deviation set answers "where does this
;;; reader depart from RFC 8259"; the lockstep concern answers "where
;;; do the two readers disagree with each other". A row can be in
;;; either without the other: the finite-range refusal below is no
;;; deviation (RFC 6 lets an implementation set limits) yet was an
;;; asymmetry until the counterpart converged on it, and the dot rows
;;; were a deviation this side held alone. Rows carry which one they
;;; are, because the remedies differ -- a deviation is documented or
;;; removed, an asymmetry is closed by whichever side is the outlier.
;;;
;;; SELF-DESTRUCT CLAUSE, shared with the counterpart's row set: a
;;; deviating row outside the shared classes A and C -- on either
;;; side -- fails the survey that produced this table, and BOTH
;;; sides' tables are re-surveyed whole; do not just append the find.
;;; The row set here is the shared seed; the counterpart pins the
;;; same rows with its own verdicts, and shared rows must agree.
;;;
;;; Duplicate keys are RFC 4 SHOULD territory, not a deviation. This
;;; side's semantics, pinned below: the alist RETAINS every pair in
;;; order, and json-ref answers the FIRST.

(import (chezscheme) (igropyr json))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))

(define (status s)
  (guard (e (#t 'REJECT)) (string->json s) 'ACCEPT))

(define (pin rows what)
  (for-each
    (lambda (row)
      (let ((input (car row)) (expected (cdr row)))
        (check (string-append what ": "
                              (call-with-string-output-port
                                (lambda (p) (write input p))))
               (eq? expected (status input))
               (status input))))
    rows))

;; ---- the three deviation classes: pinned as ACCEPT ----------------------
(pin '(("01" . ACCEPT) ("-01" . ACCEPT) ("00" . ACCEPT)
       ("01.5" . ACCEPT) ("-00" . ACCEPT))
     "deviation A, leading zeros")
;; the removed unilateral deviation: digits are required on both
;; sides of a decimal point, as the counterpart always required
(pin `(("5." . REJECT) ("5.e3" . REJECT) ("1.e2" . REJECT)
       ("-3." . REJECT) ("-.5" . REJECT))
     "converged: missing digits beside the dot")
(pin `((,(string #\" #\newline #\") . ACCEPT)
       (,(string #\" #\tab #\") . ACCEPT)
       (,(string #\" #\nul #\") . ACCEPT))
     "deviation C, bare control characters in strings")

;; ---- the rejections RFC requires and this reader delivers ---------------
(pin '(("[1,2,]" . REJECT) ("{\"a\":1,}" . REJECT)     ; trailing commas
       ("'a'" . REJECT) ("{'a':1}" . REJECT)           ; single quotes
       ("NaN" . REJECT) ("Infinity" . REJECT)
       ("-Infinity" . REJECT)
       (".5" . REJECT) ("+5" . REJECT)                 ; numbers cannot
       ("+.5" . REJECT) ("-." . REJECT)                ;   start there
       ("1e" . REJECT) ("1E" . REJECT) ("1e+" . REJECT)
       ("5..2" . REJECT) ("1e5.5" . REJECT)
       ("1_000" . REJECT) ("1/2" . REJECT) ("#x10" . REJECT)
       ("{a:1}" . REJECT)                              ; bare key
       ("[1] // c" . REJECT) ("/* c */ 1" . REJECT)    ; comments
       ("\"\\ud800\"" . REJECT)                        ; lone surrogate
       ("1 2" . REJECT) ("[1] extra" . REJECT)         ; trailing content
       ("" . REJECT) ("   " . REJECT))
     "required rejection")

;; ---- valid JSON that must stay accepted ---------------------------------
;; THE SHOULD-BE-GREEN DIRECTION, ENUMERATED, NOT SAMPLED. Tightening
;; the number grammar is the half of this file most able to overshoot:
;; an implementation that demands a frac before an exp, or refuses a
;; sign in the exponent, passes every REJECT row above while breaking
;; ordinary documents. So the RFC's three number parts -- int, frac,
;; exp -- are pinned across their present/absent combinations, plus
;; the signs and the range edges each part allows.
(pin '(;; int alone, both signs, the zero forms
       ("0" . ACCEPT) ("-0" . ACCEPT) ("7" . ACCEPT) ("-7" . ACCEPT)
       ("1234567890" . ACCEPT)
       ;; int + frac
       ("0.0" . ACCEPT) ("0.5" . ACCEPT) ("-0.0" . ACCEPT)
       ("7.25" . ACCEPT) ("1.0000000001" . ACCEPT)
       ;; int + exp, every sign form, both cases
       ("1e5" . ACCEPT) ("1E5" . ACCEPT) ("1e+5" . ACCEPT)
       ("1e-5" . ACCEPT) ("1E+5" . ACCEPT) ("1E-5" . ACCEPT)
       ("0e0" . ACCEPT) ("-0e0" . ACCEPT)
       ;; int + frac + exp together
       ("1.5e10" . ACCEPT) ("-0.0e0" . ACCEPT) ("-1.5E-10" . ACCEPT)
       ;; exponent with leading zeros is RFC-legal (exp = 1*DIGIT)
       ("1e01" . ACCEPT) ("-0.5e01" . ACCEPT)
       ;; magnitudes near, but inside, the representable range
       ("1e308" . ACCEPT) ("1e-308" . ACCEPT)
       ("179769313486231570000000000000000000000" . ACCEPT))
     "valid number")

;; ---- the round trip an accepted number must survive ---------------------
;; The counterpart reached the null-round-trip through its reader; this
;; side is shielded by refusing at read time, and this cell is what
;; keeps that shield honest: whatever the reader accepts, the writer
;; must emit as a number, never as null. A future widening of the
;; reader that let a non-finite through would show up here rather than
;; in someone's data.
(for-each
  (lambda (input)
    (let* ((v (string->json input))
           (out (json->string v)))
      (check (string-append "accepted number survives the round trip: "
                            input)
             (and (string? out) (not (string=? out "null"))
                  (not (string=? out "\"null\"")))
             out)))
  '("1e308" "1e-308" "0" "-0" "-0.0e0" "1.5e10"
    "179769313486231570000000000000000000000"))

;; ---- duplicate keys: both retained, json-ref answers the first ----------
(let ((d (string->json "{\"a\":1,\"a\":2}")))
  (check "duplicate keys: every pair retained, in order"
         (equal? d '(("a" . 1) ("a" . 2))) d)
  (check "duplicate keys: json-ref answers the first"
         (eqv? 1 (json-ref d "a"))))

;; NOT a deviation -- RFC 8259 section 6 lets an implementation set
;; range limits -- but it WAS an asymmetry: the counterpart accepted
;; the literal as +inf.0, and its writer emits non-finite values as
;; null, so a number survived one round trip as `null`. It converged
;; on refusing at read time, which is where this side already stood.
;; Pinned so the refusal stays a refusal.
(check "an overflowing literal is refused, not wrapped"
       (eq? 'REJECT (status "1e309")))
(check "...and the refusal is at read time, before any round trip"
       (eq? 'REJECT (status "[1e309,1]")))

(if (zero? failures)
    (begin (display "json-rfc-surface: all tests passed\n") (exit 0))
    (begin (display (number->string failures))
           (display " failures\n") (exit 1)))
