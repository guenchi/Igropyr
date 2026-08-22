#!chezscheme
;;; (igropyr json) read-side acceptance surface, pinned row by row,
;;; each row anchored to the text of RFC 8259 that decides it.
;;;
;;; LOCKSTEP CONTRACT. This reader has a wire counterpart: the
;;; browser-side (Goeteia) JSON reader, each parsing what the other
;;; side's writer -- or the same third-party client -- produces. Rows
;;; the two sides share must agree; a unilateral change to a shared
;;; row manufactures input one side accepts and the other refuses. So
;;; a red row here means "coordinate", not "update the row".
;;;
;;; TWO SETS, NOT ONE. The deviation set answers "where does this
;;; reader depart from RFC 8259"; the lockstep concern answers "where
;;; do the two readers disagree with each other". A row can be in
;;; either without the other, and the remedies differ: a deviation is
;;; documented or removed, an asymmetry is closed by whichever side is
;;; the outlier.
;;;
;;; EVERY ROW CARRIES ITS ANCHOR -- section number and the words that
;;; decide it -- because the first survey's failure was not a missed
;;; row, it was classification from intuition. "\uDEAD" sat under
;;; "rejections the RFC requires" while section 8.2 names that exact
;;; string as something the grammar ALLOWS. A row whose anchor cannot
;;; be written down is a row somebody guessed.
;;;
;;; The deviations, all measured by survey:
;;;
;;;   A. leading zeros in the integer part -- "01" "-01" "00" "01.5"
;;;      Section 6: int = zero / ( digit1-9 *DIGIT ), zero = %x30.
;;;      SHARED with the counterpart.
;;;   C. bare control characters inside strings
;;;      Section 7: unescaped = %x20-21 / %x23-5B / %x5D-10FFFF --
;;;      anything below %x20 must be escaped. SHARED.
;;;   D. escaped lone surrogates -- "\ud800", the RFC's own "\uDEAD"
;;;      Section 7: escape %x75 4HEXDIG, any four hex digits, no
;;;      pairing requirement; section 8.2: "the ABNF in this
;;;      specification allows ... bit sequences that cannot encode
;;;      Unicode characters; for example, \"\\uDEAD\" (a single
;;;      unpaired UTF-16 surrogate)"; section 9: "A JSON parser MUST
;;;      accept all texts that conform to the JSON grammar."
;;;      THIS READER REFUSES THEM ANYWAY, and the refusal is a
;;;      deliberate, costed non-conformance, not a correctness win:
;;;      accepting would mean carrying WTF-8 through a library whose
;;;      strings are UTF-8 byte sequences, and every consumer of a
;;;      parsed string would inherit that. The counterpart refuses
;;;      identically, so the wire is symmetric; the RFC is not
;;;      satisfied. Direction is opposite to A and C: they accept what
;;;      the grammar forbids, this refuses what the grammar allows.
;;;
;;; A and C are ACCEPT because the counterpart accepts them too, and
;;; that is the whole of the reason. IF BOTH SIDES EVER TIGHTEN THEM
;;; IN ONE COORDINATED CHANGE, THOSE ROWS AND THIS PARAGRAPH ARE
;;; DELETED, NOT EDITED -- a retention clause that outlives its reason
;;; keeps looking valid long after the world moved.
;;;
;;; SELF-DESTRUCT CLAUSE, shared with the counterpart's row set: a
;;; deviating row outside A, C and D -- on either side -- fails the
;;; survey that produced this table, and BOTH sides re-survey whole;
;;; do not just append the find. It has fired once already, on D, and
;;; the re-survey is what added the anchors.

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

;; rows are (input expected anchor): the anchor is the RFC text that
;; decides the row, and a row without one has not been derived
(define (pin what rows)
  (for-each
    (lambda (row)
      (let ((input (car row)) (expected (cadr row)) (anchor (caddr row)))
        (check (string-append
                 what ": "
                 (call-with-string-output-port (lambda (p) (write input p)))
                 "  [" anchor "]")
               (eq? expected (status input))
               (status input))))
    rows))

;; ---- deviation A: leading zeros (shared, documented) -------------------
(pin "deviation A, leading zeros"
     '(("01" ACCEPT "6: int = zero / (digit1-9 *DIGIT)")
       ("-01" ACCEPT "6: int = zero / (digit1-9 *DIGIT)")
       ("00" ACCEPT "6: zero = %x30, one zero only")
       ("01.5" ACCEPT "6: int precedes frac, same rule")
       ("-00" ACCEPT "6: minus int, int = zero")))

;; ---- deviation C: bare control characters (shared, documented) ---------
(pin "deviation C, bare control characters in strings"
     `((,(string #\" #\newline #\") ACCEPT "7: unescaped excludes %x00-1F")
       (,(string #\" #\tab #\") ACCEPT "7: unescaped excludes %x00-1F")
       (,(string #\" #\nul #\") ACCEPT "7: unescaped excludes %x00-1F")
       (,(string #\" #\x1f #\") ACCEPT "7: unescaped starts at %x20")))

;; ---- deviation D: escaped lone surrogates (shared, costed) -------------
;; the grammar allows these and section 9 says a parser MUST accept
;; conforming texts; this reader refuses, knowingly, to keep strings
;; UTF-8. Pinned so the non-conformance stays deliberate and visible.
(pin "deviation D, escaped lone surrogates refused"
     '(("\"\\ud800\"" REJECT "7: %x75 4HEXDIG; 8.2 names \\uDEAD as allowed")
       ("\"\\udead\"" REJECT "8.2: the RFC's own example of an allowed text")
       ("\"\\udfff\"" REJECT "7: 4HEXDIG, no pairing requirement")))

;; ---- escapes that are in the grammar and must work ---------------------
(pin "escape sequence"
     `(("\"\\ud834\\udd1e\"" ACCEPT "7: a surrogate pair encodes U+1D11E")
       ("\"a\\u005Cb\"" ACCEPT "8.3: names \\u005C as a legitimate escape")
       ("\"\\u0041\"" ACCEPT "7: %x75 4HEXDIG")
       ("\"\\u00e9\"" ACCEPT "7: %x75 4HEXDIG")
       ("\"\\uFFFF\"" ACCEPT "7: 4HEXDIG; a noncharacter is still a char")
       ("\"\\/\"" ACCEPT "7: %x2F is an escapable character")
       ("\"\\b\"" ACCEPT "7: %x62 backspace")
       ("\"\\f\"" ACCEPT "7: %x66 form feed")
       ("\"\\n\"" ACCEPT "7: %x6E line feed")
       ("\"\\r\"" ACCEPT "7: %x72 carriage return")
       ("\"\\t\"" ACCEPT "7: %x74 tab")
       ("\"\\\"\"" ACCEPT "7: %x22 quotation mark")
       ("\"\\\\\"" ACCEPT "7: %x5C reverse solidus")
       ("\"\\q\"" REJECT "7: char = unescaped / escape (one of the listed)")
       ("\"\\x41\"" REJECT "7: x is not among the escapable characters")
       (,(string #\" #\x7f #\") ACCEPT "7: unescaped = ... %x5D-10FFFF")))

;; ---- rejections the grammar requires ----------------------------------
(pin "required rejection"
     '(("[1,2,]" REJECT "5: array = [ value *( value-separator value ) ]")
       ("{\"a\":1,}" REJECT "4: object = [ member *( , member ) ]")
       ("'a'" REJECT "7: string = quotation-mark *char quotation-mark")
       ("{'a':1}" REJECT "4: member = string name-separator value")
       ("NaN" REJECT "3: value = false / null / true / object / array"
                     )
       ("Infinity" REJECT "6: numeric values that cannot be represented")
       ("-Infinity" REJECT "6: number = [minus] int [frac] [exp]")
       (".5" REJECT "6: number begins with minus or int")
       ("+5" REJECT "6: number = [ minus ] int ...; no plus")
       ("+.5" REJECT "6: number = [ minus ] int ...")
       ("-." REJECT "6: int is required after minus")
       ("5." REJECT "6: frac = decimal-point 1*DIGIT")
       ("5.e3" REJECT "6: frac = decimal-point 1*DIGIT")
       ("1.e2" REJECT "6: frac = decimal-point 1*DIGIT")
       ("-3." REJECT "6: frac = decimal-point 1*DIGIT")
       ("-.5" REJECT "6: int is required before frac")
       ("1e" REJECT "6: exp = e [ minus / plus ] 1*DIGIT")
       ("1E" REJECT "6: exp = e [ minus / plus ] 1*DIGIT")
       ("1e+" REJECT "6: exp = e [ minus / plus ] 1*DIGIT")
       ("5..2" REJECT "6: one frac at most")
       ("1e5.5" REJECT "6: exp = e [sign] 1*DIGIT, no frac after")
       ("1_000" REJECT "6: DIGIT only")
       ("1/2" REJECT "6: number grammar has no solidus")
       ("#x10" REJECT "3: no such value form")
       ("{a:1}" REJECT "4: member names are strings")
       ("[1] // c" REJECT "2: ws = space / tab / LF / CR only")
       ("/* c */ 1" REJECT "2: ws = space / tab / LF / CR only")
       ("1 2" REJECT "2: JSON-text = ws value ws, one value")
       ("[1] extra" REJECT "2: JSON-text = ws value ws")
       ("" REJECT "2: JSON-text requires a value")
       ("   " REJECT "2: JSON-text requires a value")))

;; ---- the should-be-green direction, enumerated ------------------------
;; Tightening the number grammar is the half most able to overshoot: an
;; implementation that demands a frac before an exp, or refuses a signed
;; exponent, passes every rejection row above while breaking ordinary
;; documents. So the three parts of section 6's number -- int, frac, exp
;; -- are pinned across their present/absent combinations.
(pin "valid number"
     '(("0" ACCEPT "6: int = zero")
       ("-0" ACCEPT "6: [ minus ] int")
       ("7" ACCEPT "6: int = digit1-9 *DIGIT")
       ("-7" ACCEPT "6: [ minus ] int")
       ("1234567890" ACCEPT "6: digit1-9 *DIGIT")
       ("0.0" ACCEPT "6: int frac")
       ("0.5" ACCEPT "6: int frac")
       ("-0.0" ACCEPT "6: minus int frac")
       ("7.25" ACCEPT "6: int frac")
       ("1.0000000001" ACCEPT "6: frac = . 1*DIGIT, any length")
       ("1e5" ACCEPT "6: exp = e 1*DIGIT")
       ("1E5" ACCEPT "6: e = %x65 / %x45")
       ("1e+5" ACCEPT "6: exp = e [ minus / plus ] 1*DIGIT")
       ("1e-5" ACCEPT "6: exp = e [ minus / plus ] 1*DIGIT")
       ("1E+5" ACCEPT "6: e = %x65 / %x45, with plus")
       ("1E-5" ACCEPT "6: e = %x65 / %x45, with minus")
       ("0e0" ACCEPT "6: int exp, no frac needed")
       ("-0e0" ACCEPT "6: minus int exp")
       ("1.5e10" ACCEPT "6: int frac exp")
       ("-0.0e0" ACCEPT "6: all three parts, signed")
       ("-1.5E-10" ACCEPT "6: all three parts, both signs")
       ("1e01" ACCEPT "6: exp = e [sign] 1*DIGIT; leading zeros legal")
       ("-0.5e01" ACCEPT "6: exp leading zeros are legal")
       ("1e308" ACCEPT "6: within IEEE 754 double range")
       ("1e-308" ACCEPT "6: within IEEE 754 double range")
       ("179769313486231570000000000000000000000" ACCEPT
        "6: an exact integer, no range limit applied")))

;; ---- range limits: allowed by the RFC, and an asymmetry once ----------
;; Section 9: "An implementation may set limits on the ... range and
;; precision of numbers." So refusing is no deviation. It WAS an
;; asymmetry: the counterpart accepted the literal as +inf.0, and its
;; writer emits non-finite values as null, so a number survived one
;; round trip as `null`. It converged on refusing at read time, which
;; is where this side already stood.
(pin "range limit"
     '(("1e309" REJECT "9: an implementation may limit range")
       ("[1e309,1]" REJECT "9: the refusal is at read time")))

;; ---- the round trip an accepted number must survive -------------------
;; Whatever the reader accepts, the writer must emit as a number, never
;; as null: this is what keeps the read-time refusal above load-bearing
;; instead of decorative.
(for-each
  (lambda (input)
    (let* ((v (string->json input))
           (out (json->string v)))
      (check (string-append "accepted number survives the round trip: "
                            input)
             (and (string? out) (not (string=? out "null")))
             out)))
  '("1e308" "1e-308" "0" "-0" "-0.0e0" "1.5e10"
    "179769313486231570000000000000000000000"))

;; ---- duplicate keys: section 4 SHOULD, so this pins our answer --------
;; "The names within an object SHOULD be unique" -- a SHOULD, so a
;; document with duplicates is not malformed and the reader must have
;; an answer. Ours: keep every pair in order, json-ref answers the
;; first. The counterpart matches, verified on both sides.
(let ((d (string->json "{\"a\":1,\"a\":2}")))
  (check "duplicate keys: every pair retained, in order  [4: SHOULD be unique]"
         (equal? d '(("a" . 1) ("a" . 2))) d)
  (check "duplicate keys: json-ref answers the first  [4: our documented answer]"
         (eqv? 1 (json-ref d "a"))))

(if (zero? failures)
    (begin (display "json-rfc-surface: all tests passed\n") (exit 0))
    (begin (display (number->string failures))
           (display " failures\n") (exit 1)))
