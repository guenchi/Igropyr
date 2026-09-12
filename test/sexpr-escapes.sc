#!chezscheme
;; The sexpr READER and the escapes a writer of this format can emit.
;;
;; This library's own writer emits RAW control bytes -- a form feed goes out
;; as byte 12 -- and the reader has always accepted raw control characters,
;; so the write/read pair here is closed and loses nothing. What it refused
;; was text from ANY OTHER writer: a conforming R6RS `write` emits
;; (ok "a\fb") for the same value, and this reader answered "bad string
;; escape". sexpr.sc names this library as the authority for the wire format,
;; so the authority was the narrow implementation.
;;
;; Every check is pure. The rows are written as the TEXT a sender would put
;; on the wire, because that is the thing under test; the expected value is
;; built with integer->char so that no escape syntax of the host reader
;; stands between the row and what it claims.
(import (chezscheme) (igropyr sexpr))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (read1 text) (guard (e (#t 'REFUSED)) (string->sexpr text)))
;; a row: the text `(ok <datum>)` must read as the list (ok <want>)
(define (accepts label text want)
  (let ((got (read1 (string-append "(ok " text ")"))))
    (check label (equal? got (list 'ok want)) got (list 'ok want) text)))
(define (refuses label text)
  (let ((got (read1 (string-append "(ok " text ")"))))
    (check label (eq? got 'REFUSED) got text)))
(define (q s) (string-append "\"" s "\""))
(define (ch n) (string (integer->char n)))

;; ---- the five escapes that were refused ------------------------------------
(accepts "\\a is the alarm" (q "a\\ab") (string-append "a" (ch 7) "b"))
(accepts "\\b is the backspace" (q "a\\bb") (string-append "a" (ch 8) "b"))
(accepts "\\v is the vertical tab" (q "a\\vb") (string-append "a" (ch 11) "b"))
(accepts "\\f is the form feed" (q "a\\fb") (string-append "a" (ch 12) "b"))
;; the row the report was about, spelled the way an R6RS writer spells it
(accepts "an R6RS writer's whole datum reads" "\"a\\fb\"" (string-append "a" (ch 12) "b"))
;; ---- the five that already worked keep working -------------------------------
(accepts "\\n still" (q "a\\nb") (string-append "a" (ch 10) "b"))
(accepts "\\t still" (q "a\\tb") (string-append "a" (ch 9) "b"))
(accepts "\\r still" (q "a\\rb") (string-append "a" (ch 13) "b"))
(accepts "\\\" still" (q "a\\\"b") "a\"b")
(accepts "\\\\ still" (q "a\\\\b") "a\\b")
;; raw control characters still read: that is what our own writer emits
(accepts "a RAW form feed still reads" (q (string-append "a" (ch 12) "b"))
         (string-append "a" (ch 12) "b"))
;; ---- \x<hex>; ------------------------------------------------------------------
(accepts "\\x41; is A" (q "\\x41;") "A")
(accepts "lower-case hex digits" (q "\\x6a;") "j")
(accepts "upper-case hex digits (only the DIGITS vary in case)" (q "\\x6A;") "j")
(accepts "\\x0; is NUL" (q "\\x0;") (ch 0))
(accepts "one digit" (q "\\x9;") (ch 9))
(accepts "six digits: the last code point" (q "\\x10FFFF;") (ch #x10FFFF))
(accepts "leading zeros inside the bound" (q "\\x00041;") "A")
;; VARIABLE LENGTH: the reading loop cannot advance by a constant
(accepts "two escapes in a row" (q "\\x41;\\x42;") "AB")
(accepts "an escape at the end" (q "a\\x41;") "aA")
(accepts "an escape at the start" (q "\\x41;b") "Ab")
(accepts "an escape between other escapes" (q "\\n\\x41;\\t") (string-append (ch 10) "A" (ch 9)))
;; ---- refusals ------------------------------------------------------------------
(refuses "\\X is refused: R6RS spells the escape lower case" (q "\\X41;"))
(refuses "no digits" (q "\\x;"))
(refuses "no terminator" (q "\\x41"))
(refuses "a non-hex digit" (q "\\xG1;"))
(refuses "seven digits is past the bound" (q "\\x0010FFFF;"))
(refuses "past the last code point" (q "\\x110000;"))
(refuses "a surrogate" (q "\\xD800;"))
(refuses "the top of the surrogate block" (q "\\xDFFF;"))
(refuses "an unknown escape letter is still unknown" (q "a\\qb"))
(refuses "a dangling backslash" "\"a\\")
;; ---- the astral row: a Chez string holds CODE POINTS, not bytes -----------------
;; a table lifted from an implementation whose strings hold UTF-8 bytes would
;; expect four here; this row is where that transplant shows
(let ((got (read1 (string-append "(ok " (q "\\x1F600;") ")"))))
  (check "an astral escape is ONE character on this implementation"
         (and (pair? got) (string? (cadr got)) (= (string-length (cadr got)) 1)
              (= (char->integer (string-ref (cadr got) 0)) #x1F600))
         got))
;; ---- bounded WHILE consumed, not after -------------------------------------------
;; 100000 hex digits: refused by the length bound, and the whole parse answers
;; within a second. This is a BOUND witness, not a hang witness -- an escape
;; that accumulated its digits before looking at the value would build an
;; enormous integer first.
;; NOTE ON THIS ROW'S EVIDENCE: before the widening it passes for a reason it
;; does not name -- \x is not an escape at all yet, so the text is refused at
;; the first character. It only discriminates once \x<hex>; is accepted, which
;; is the state it exists for. Do not read its green on the old tree as cover.
(let* ((huge (string-append "(ok \"\\x" (make-string 100000 #\9) ";\")"))
       (t0 (real-time))
       (got (read1 huge))
       (ms (- (real-time) t0)))
  (check "100000 hex digits are refused" (eq? got 'REFUSED) got)
  (check "...and the parse answers within a second (the run is bounded while consumed)"
         (< ms 1000) ms))
;; ---- symbols: the escape DISAMBIGUATES a name, it does not EXTEND the set ----------
(accepts "a symbol may carry a hex escape" "a\\x41;b" 'aAb)
(accepts "a symbol escape at the start" "\\x41;bc" 'Abc)
(refuses "a decoded name outside the symbol set: '('" "\\x28;")
(refuses "a decoded name outside the symbol set: a space" "a\\x20;b")
;; the row where this implementation deliberately differs from R6RS: an inline
;; hex escape is identifier syntax there, so \x31; would be the symbol 1. This
;; format's symbol set is whatever the WRITER can produce, and the writer
;; refuses the symbol 1 (numeric shape) -- accepting it would make the read
;; side wider than the write side
(refuses "a decoded name the WRITER could not write: the symbol 1" "\\x31;")
(refuses "the same for a numeric-shaped name spelled partly with escapes" "\\x31;23")
;; ---- the pair is still closed: read, write, read again ------------------------------
(for-each
  (lambda (label text)
    (let* ((v (read1 (string-append "(ok " text ")"))))
      (if (eq? v 'REFUSED)
          (check (string-append "round trip: " label) #f 'refused-on-first-read text)
          (let* ((w (guard (e (#t 'WRITE-REFUSED)) (sexpr->string v)))
                 (again (if (string? w) (read1 w) 'not-written)))
            (check (string-append "round trip: " label) (equal? again v) v w again)))))
  '("form feed" "alarm" "hex A" "astral" "symbol with an escape" "two escapes")
  (list (q "a\\fb") (q "a\\ab") (q "\\x41;") (q "\\x1F600;") "a\\x41;b" (q "\\x41;\\x42;")))
;; ---- the three vendored golden rows keep their verdicts ------------------------------
;; asserted here as well, so a future widening that moves one has to move it in
;; two places rather than quietly in the fixture alone
(accepts "golden read-escapes-n-t-r" (q "a\\nb\\tc\\rd")
         (string-append "a" (ch 10) "b" (ch 9) "c" (ch 13) "d"))
(refuses "golden read-escape-bad" (q "a\\qb"))
(refuses "golden read-dangling-escape" "\"a\\")

(if (zero? fails)
    (begin (display "ALL SEXPR-ESCAPES TESTS PASSED\n") (exit 0))
    (begin (display "SEXPR-ESCAPES VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
