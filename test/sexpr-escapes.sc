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
;; A refusal must be THIS READER'S refusal. Turning every raised object into
;; REFUSED would let an out-of-bounds access or an integer->char assertion
;; satisfy a malformed-escape row, and the rows that claim "refused" would
;; then also pass on a crash. The documented shape is #(sexpr-error msg pos).
(define (read1 text)
  (guard (e (#t (if (and (vector? e) (fx>= (vector-length e) 2) (eq? (vector-ref e 0) 'sexpr-error))
                    'REFUSED
                    (vector 'UNEXPECTED-EXCEPTION e))))
    (string->sexpr text)))
;; a row: the text `(ok <datum>)` must read as the list (ok <want>)
(define (accepts label text want)
  (let ((got (read1 (string-append "(ok " text ")"))))
    (check label (equal? got (list 'ok want)) got (list 'ok want) text)))
(define (refuses label text)
  (let ((got (read1 (string-append "(ok " text ")"))))
    (check label (eq? got 'REFUSED) got text)))
(define (q s) (string-append "\"" s "\""))
;; the rows above wrap their text in "(ok ...)", which supplies a closing
;; paren; an input that ENDS in an unfinished escape must be submitted whole,
;; or the parser meets ")" where the cell means it to meet end of input
(define (refuses-raw label text)
  (let ((got (read1 text)))
    (check label (eq? got 'REFUSED) got text)))
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
;; the DIGIT COUNT bound, isolated from the value: both of these decode to A,
;; so only the number of digits can separate them. The previous spelling of
;; this row used \x0010FFFF; -- EIGHT digits, which an implementation allowing
;; seven would have passed
(accepts "six digits, all leading zeros" (q "\\x000041;") "A")
(refuses "seven digits is past the bound, though the value is A" (q "\\x0000041;"))
(refuses "past the last code point" (q "\\x110000;"))
(refuses "a surrogate" (q "\\xD800;"))
(refuses "the top of the surrogate block" (q "\\xDFFF;"))
(refuses "an unknown escape letter is still unknown" (q "a\\qb"))
(refuses-raw "input ends inside a string after a backslash" "(ok \"a\\")
(refuses-raw "input ends after \\x" "(ok \"a\\x")
(refuses-raw "input ends inside the hex digits" "(ok \"a\\x41")
(refuses-raw "input ends inside a symbol's escape" "(ok a\\x41")
(refuses-raw "input ends after a symbol's backslash" "(ok a\\")
;; the vendored fixture's own dangling input, passed through unchanged
(refuses-raw "the vendored read-dangling-escape input verbatim" "\"a\\")
;; ---- the astral row: a Chez string holds CODE POINTS, not bytes -----------------
;; a table lifted from an implementation whose strings hold UTF-8 bytes would
;; expect four here; this row is where that transplant shows
(let ((got (read1 (string-append "(ok " (q "\\x1F600;") ")"))))
  (check "an astral escape is ONE character on this implementation"
         (and (pair? got) (string? (cadr got)) (= (string-length (cadr got)) 1)
              (= (char->integer (string-ref (cadr got) 0)) #x1F600))
         got))
;; ---- the digit run does not become an integer before it is bounded ------------
;; What this row pins, exactly: that the run is NOT accumulated into an exact
;; integer over its whole length. Measured on this machine, string->number on
;; a hex run of 300000 nines takes 7949 ms (100000 takes 898 -- the cost is
;; quadratic), so an implementation that converts first and checks afterwards
;; cannot come back inside the bound below.
;; What it does NOT pin, and neither does anything else here: whether the
;; reader stops CONSUMING characters early. A reader that scans the whole run
;; and then refuses does linear work in its input, which is proportional and
;; not the amplifier this batch is about; separating "stopped scanning" from
;; "scanned then refused" needs a work budget around the scanner, recorded as
;; a residual rather than pretended here.
;; A value-based early exit (stop once the accumulated value passes the code
;; point ceiling) also answers fast and is legitimate; the DIGIT COUNT rule is
;; pinned separately by the six/seven-digit pair above, where the value is A
;; either way.
(let* ((huge (string-append "(ok \"\\x" (make-string 300000 #\9) ";\")"))
       (t0 (real-time))
       (got (read1 huge))
       (ms (- (real-time) t0)))
  (check "300000 hex digits are refused" (eq? got 'REFUSED) got)
  (check "...within a second, so the run was never converted whole (it would take ~8 s)"
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
;; ---- ADDITIVITY: a name the reader accepts today must still be accepted -----------
;; The gap this pins is exactly the leading-plus family: +15, +i and +nan.0 read
;; as symbols here and sexpr->string then refuses them, because the reader's
;; numeric-shape? looks only for a leading digit or '-' plus a digit while
;; wire-symbol? asks string->number. That is PRE-EXISTING and out of scope; what
;; matters here is that the new rule reaches decoded ESCAPED names only. An
;; implementation that ran wire-symbol? over every token would narrow the format
;; and still pass every other row in this file.
;; The reader admits some bare tokens wire-symbol? refuses -- +i is one, and
;; it is accepted here today while sexpr->string raises on it. So the new rule
;; must be applied to a DECODED ESCAPED name only, never to every token: an
;; implementation that ran wire-symbol? over all tokens would pass every other
;; row in this file and silently narrow the format.
(accepts "bare +i is still accepted (it was before this change)" "+i" (string->symbol "+i"))
(accepts "bare +15 is still accepted" "+15" (string->symbol "+15"))
(accepts "bare +nan.0 is still accepted" "+nan.0" (string->symbol "+nan.0"))
(accepts "bare + and - are symbols and are writable" "+" (string->symbol "+"))
(refuses "but the same name spelled with an escape is refused" "\\x2B;i")
(refuses "and so is a partly escaped spelling of it" "+\\x69;")

;; ---- why the R6RS objection to refusing \x31; does not apply ----------------------
;; The objection is that an inline hex escape is identifier syntax in R6RS, so
;; \x31; ought to be the symbol 1. These rows record the premise that answers
;; it: this reader was never an R6RS reader, its symbol set was already
;; narrower than R6RS's before any escape existed, so one escape is not being
;; held to a standard the surrounding grammar implements. If a later change
;; makes these three read, the ruling has to be re-argued rather than inherited.
(refuses "a$b is a legal R6RS identifier and this reader refuses it" "a$b")
(refuses "a#b likewise" "a#b")
(refuses "|a b| likewise" "|a b|")
(accepts "while a->b and set! read, as they always did" "a->b" (string->symbol "a->b"))

;; ---- the escape and the token length bound ----------------------------------------
;; default-max-token is 65536 and bounds the DECODED name, not the source text:
;; 65531 letters plus one six-character escape is 65532 characters decoded and
;; 65537 on the wire. The bound is unchanged by this batch; these rows say which
;; length it counts, so a future reading of "length" cannot drift unnoticed.
(let* ((n 65531)
       (body (make-string n #\a)))
  (accepts "a decoded name just inside the bound, with an escape at its end"
           (string-append body "\\x41;")
           (string->symbol (string-append body "A")))
  (refuses "a decoded name past the bound"
           (string-append (make-string 65536 #\a) "\\x41;")))
;; strings are explicitly NOT under the token cap (sexpr.sc says so); a long
;; string, raw or escaped, still reads
(let ((n 70000))
  (accepts "a string longer than the token cap still reads, raw"
           (q (make-string n #\a)) (make-string n #\a))
  (accepts "...and with an escape in it"
           (string-append (q (string-append (make-string n #\a) "\\x41;")))
           (string-append (make-string n #\a) "A")))

;; ---- decoded characters are VALUES, not syntax ---------------------------------------
;; \x22; is a quote and \x5C; a backslash: if the decoded character were fed
;; back through the tokenizer, these would end the string or start an escape
(accepts "a hex-decoded quote does not end the string" (q "a\\x22;b") "a\"b")
(accepts "a hex-decoded backslash does not start an escape" (q "a\\x5C;nb")
         (string-append "a\\" "nb"))
(accepts "a hex-decoded backslash before a real escape" (q "\\x5C;\\n")
         (string-append "\\" (ch 10)))
;; the same for symbols: a decoded dot or plus is part of the NAME
(accepts "a symbol with a decoded dot" "a\\x2E;b" (string->symbol "a.b"))
(refuses "a decoded name that is just a dot" "\\x2E;")
(refuses "a decoded name that is a complex numeral" "\\x2B;\\x69;")

;; ---- the code point boundaries on both sides of the surrogate block ---------------------
(accepts "the scalar just below the surrogates" (q "\\xD7FF;") (ch #xD7FF))
(accepts "the scalar just above the surrogates" (q "\\xE000;") (ch #xE000))
(refuses "a surrogate in the middle of the block" (q "\\xDC00;"))
(accepts "the last scalar below the astral planes" (q "\\xFFFF;") (ch #xFFFF))

;; ---- the extended entry point reads the same escapes ------------------------------------
;; string->sexpr-extended is a second door into the same grammar; a widening
;; applied at one door only is a drift between two entry points of one library
(let ((got (guard (e (#t 'REFUSED)) (string->sexpr-extended (string-append "(ok " (q "a\\fb") ")")))))
  (check "the extended reader takes the new escapes too"
         (equal? got (list 'ok (string-append "a" (ch 12) "b"))) got))
(let ((got (guard (e (#t 'REFUSED)) (string->sexpr-extended (string-append "(ok " (q "\\x41;") ")")))))
  (check "the extended reader takes \\x<hex>; too" (equal? got '(ok "A")) got))

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
