#!chezscheme
;;; (igropyr json) -- safe JSON parser and writer.
;;;
;;; A recursive-descent parser over the input string: no reader tricks,
;;; safe for untrusted input (HTTP request bodies). Full string escape
;;; handling including \uXXXX and surrogate pairs.
;;;
;;; Data model (compatible with guenchi/json's path DSL):
;;;   object -> alist with string keys      {"a":1}   -> (("a" . 1))
;;;   array  -> vector                      [1,2]     -> #(1 2)
;;;   string -> string, number -> number
;;;   true/false -> #t/#f, null -> 'null
;;;
;;; (string->json s)   parse; raises #(json-error msg pos) on bad input,
;;;                    pos being the index into s where it gave up
;;; (json->string x)   serialize (alists -> objects, vectors -> arrays;
;;;                    a list serializes as an array only when it is
;;;                    NEITHER empty NOR shaped like an alist: '() is
;;;                    written {}, and a list whose every element is a
;;;                    pair with a string or symbol car is an object,
;;;                    even when it was meant as an array of pairs);
;;;                    raises the
;;;                    same #(json-error msg pos) shape with pos = #f,
;;;                    there being no text to point into. Both directions
;;;                    use one tag on purpose: a guard dispatching only
;;;                    on the tag catches the writer too -- one that also
;;;                    tests the third slot for a fixnum will not. The
;;;                    vector is
;;;                    exactly three slots and that is not a place to
;;;                    grow: an older guard doing arithmetic on the third
;;;                    slot meets #f there now, and one answering 400 to
;;;                    any json-error will report our own serialisation
;;;                    fault as the client's. Anything richer wants its
;;;                    own tag, not a longer vector.
;;; (json-ref x k ...) path access: string/symbol key for objects,
;;;                    integer index for arrays; #f when absent

(library (igropyr json)
  (export string->json json->string json-ref)
  (import (chezscheme) (only (igropyr json-internal) number-text))

  ;; nesting cap for untrusted input. THIS ONE IS NOT ADJUSTABLE per
  ;; call, and the reason is the next paragraph. (igropyr sexpr) is worth
  ;; reading alongside; what it guards against and how is its own file's
  ;; to state.
  ;;
  ;; THIS FILE TREATS THE NUMBER AS FIXED, not as a tuning knob, because
  ;; a depth one reader accepts and another refuses splits a document in
  ;; two. Whether a second implementation currently agrees, and on what,
  ;; is recorded in test/json-rfc-surface.sc and nowhere in this comment.
  ;; Read it before changing the number: if it records an agreement, that
  ;; agreement is what has to move too; if it records none, this is a
  ;; local decision after all. Either way the record changes in the same
  ;; commit as the number. It is NOT
  ;; the writer's bound -- see
  ;; write-guard-depth, which is deliberately a different number for a
  ;; different purpose. Do not align them WITHOUT DECIDING THE TRADE
  ;; BELOW -- the trade is genuinely open, so equality is a possible
  ;; conclusion; what is not allowed is arriving at it by tidiness.
  ;;
  ;; IT COUNTS PARENT-TO-CHILD DESCENTS, the top-level value being 0,
  ;; and the guard runs on every value entered, leaves included -- 64
  ;; containers around a number enters 65 values and passes at depth 64.
  ;; Say it any other way and you will get the boundary wrong, so state
  ;; the unit before quoting a number:
  ;;   in WRAPPING LAYERS, the bottom makes no difference -- 64 layers
  ;;     around a number and 64 around an empty array both pass, 65 of
  ;;     either does not, because the bottom value is charged too;
  ;;   in TOTAL CONTAINERS, an empty one at the bottom is worth an extra
  ;;     level -- 64 containers with a number inside, but 65 when the
  ;;     innermost is [] -- because that empty container IS the charged
  ;;     bottom instead of holding one.
  ;; Both readings are true of the same rule and they disagree by one,
  ;; which is why neither number is "the maximum container nesting".
  ;; The writer's guard is charged identically, so the two sides differ
  ;; in size, not in what they count.
  (define max-depth 64)

  ;; The writer's bound. A RESOURCE GUARD, not a contract: it is here so
  ;; that a self-referential value cannot recurse without end. A caller
  ;; can find where it sits by building a deep enough value, so it is not
  ;; hidden -- it is simply not promised.
  ;;
  ;; WHY IT IS CURRENTLY NOT max-depth, stated as the trade it is rather
  ;; than as a rule. A server reads a document, wraps it, and writes the
  ;; result, so the writer sees the reader's depth plus however many
  ;; layers the application adds -- one {"result": ...} is enough. At 64
  ;; a document we just accepted becomes one we cannot write: a legal
  ;; input turned into a server error. Above 64 we can instead emit a
  ;; reply the paired reader will refuse. BOTH COSTS ARE REAL AND THE
  ;; TRADE IS NOT SETTLED; this file currently takes the second.
  ;;
  ;; WHAT THIS NUMBER IS. A heuristic finite threshold, known to cut
  ;; cycles short. It does not guarantee cover for any application's
  ;; wrapping, and it has not been derived from Chez's resource-safe
  ;; bound. Two things it is easy to claim and neither is true: that the
  ;; wrapping argument selects it -- the condition is really
  ;; write-guard minus reader depth being at least the largest wrapping
  ;; an application performs, and that quantity is unknown here, so any
  ;; talk of "room to spare" is assuming a value for it; and that any
  ;; finite height would do -- a billion is finite and would exhaust the
  ;; machine long before the guard was reached, so a real upper bound
  ;; exists, set by memory and time, and it has not been measured.
  (define write-guard-depth 1024)

  (define (jfail msg pos)
    (raise (vector 'json-error msg pos)))

  ;; ---- parser -----------------------------------------------------------

  (define (string->json s)
    (let ((n (string-length s)))
      (define (skip-ws i)
        (if (and (< i n) (memv (string-ref s i) '(#\space #\tab #\newline #\return)))
            (skip-ws (+ i 1))
            i))
      (define (expect ch i)
        (if (and (< i n) (char=? (string-ref s i) ch))
            (+ i 1)
            (jfail (string-append "expected " (string ch)) i)))
      ;; Untrusted input must not be able to drive unbounded recursion:
      ;; a few MB of '[' would otherwise cost millions of live frames.
      ;; (igropyr sexpr) is worth reading alongside; what it does is its
      ;; own file's to say.
      (define (parse-value i) (parse-value* i 0))
      (define (parse-value* i depth)
        (when (> depth max-depth) (jfail "nesting too deep" i))
        (let ((i (skip-ws i)))
          (when (>= i n) (jfail "unexpected end of input" i))
          (let ((ch (string-ref s i)))
            (cond
              ((char=? ch #\{) (parse-object (+ i 1) (+ depth 1)))
              ((char=? ch #\[) (parse-array (+ i 1) (+ depth 1)))
              ((char=? ch #\") (parse-string (+ i 1)))
              ((char=? ch #\t) (parse-literal i "true" #t))
              ((char=? ch #\f) (parse-literal i "false" #f))
              ((char=? ch #\n) (parse-literal i "null" 'null))
              ((or (char=? ch #\-) (char-numeric? ch)) (parse-number i))
              (else (jfail "unexpected character" i))))))
      (define (parse-literal i word value)
        (let ((end (+ i (string-length word))))
          (if (and (<= end n) (string=? (substring s i end) word))
              (values value end)
              (jfail "bad literal" i))))
      (define (parse-object i depth)
        (let ((i (skip-ws i)))
          (if (and (< i n) (char=? (string-ref s i) #\}))
              (values '() (+ i 1))
              (let loop ((i i) (acc '()))
                (let ((i (skip-ws i)))
                  (unless (and (< i n) (char=? (string-ref s i) #\"))
                    (jfail "expected object key" i))
                  (let-values (((key i) (parse-string (+ i 1))))
                    (let ((i (expect #\: (skip-ws i))))
                      (let-values (((val i) (parse-value* i depth)))
                        (let ((i (skip-ws i)))
                          (cond
                            ((and (< i n) (char=? (string-ref s i) #\,))
                             (loop (+ i 1) (cons (cons key val) acc)))
                            ((and (< i n) (char=? (string-ref s i) #\}))
                             (values (reverse (cons (cons key val) acc)) (+ i 1)))
                            (else (jfail "expected , or } in object" i))))))))))))
      (define (parse-array i depth)
        (let ((i (skip-ws i)))
          (if (and (< i n) (char=? (string-ref s i) #\]))
              (values (vector) (+ i 1))
              (let loop ((i i) (acc '()))
                (let-values (((val i) (parse-value* i depth)))
                  (let ((i (skip-ws i)))
                    (cond
                      ((and (< i n) (char=? (string-ref s i) #\,))
                       (loop (+ i 1) (cons val acc)))
                      ((and (< i n) (char=? (string-ref s i) #\]))
                       (values (list->vector (reverse (cons val acc))) (+ i 1)))
                      (else (jfail "expected , or ] in array" i)))))))))
      (define (hex4 i)
        (unless (<= (+ i 4) n) (jfail "bad \\u escape" i))
        (let ((v (let ((sub (substring s i (+ i 4))))
                   ;; strictly four hex digits: string->number would also
                   ;; accept "-abc" (negative -> integer->char raises a
                   ;; raw assertion, escaping the json-error contract)
                   ;; and radix/sign prefixes like "#x41" / "+041"
                   (let scan ((k 0))
                     (cond
                       ((= k 4) (string->number sub 16))
                       ((let ((c (string-ref sub k)))
                          (or (char<=? #\0 c #\9)
                              (char<=? #\a c #\f)
                              (char<=? #\A c #\F)))
                        (scan (+ k 1)))
                       (else #f))))))
          (unless v (jfail "bad \\u escape" i))
          v))
      (define (parse-string i)   ; i points after the opening quote
        (call-with-values
          (lambda ()
            (let ((p (open-output-string)))
              (let loop ((i i))
                (when (>= i n) (jfail "unterminated string" i))
                (let ((ch (string-ref s i)))
                  (cond
                    ((char=? ch #\") (values (get-output-string p) (+ i 1)))
                    ((char=? ch #\\)
                     (when (>= (+ i 1) n) (jfail "bad escape" i))
                     (let ((e (string-ref s (+ i 1))))
                       (case e
                         ((#\") (write-char #\" p) (loop (+ i 2)))
                         ((#\\) (write-char #\\ p) (loop (+ i 2)))
                         ((#\/) (write-char #\/ p) (loop (+ i 2)))
                         ((#\b) (write-char (integer->char 8) p) (loop (+ i 2)))
                         ((#\f) (write-char (integer->char 12) p) (loop (+ i 2)))
                         ((#\n) (write-char #\newline p) (loop (+ i 2)))
                         ((#\r) (write-char #\return p) (loop (+ i 2)))
                         ((#\t) (write-char #\tab p) (loop (+ i 2)))
                         ((#\u)
                          (let ((v (hex4 (+ i 2))))
                            (if (and (>= v #xD800) (<= v #xDBFF))
                                ;; high surrogate: expect \uDC00-\uDFFF
                                (begin
                                  (unless (and (<= (+ i 12) n)
                                               (char=? (string-ref s (+ i 6)) #\\)
                                               (char=? (string-ref s (+ i 7)) #\u))
                                    (jfail "lone high surrogate" i))
                                  (let ((lo (hex4 (+ i 8))))
                                    (unless (and (>= lo #xDC00) (<= lo #xDFFF))
                                      (jfail "bad low surrogate" i))
                                    (write-char
                                      (integer->char
                                        (+ #x10000
                                           (* (- v #xD800) #x400)
                                           (- lo #xDC00)))
                                      p)
                                    (loop (+ i 12))))
                                (begin
                                  (when (and (>= v #xDC00) (<= v #xDFFF))
                                    (jfail "lone low surrogate" i))
                                  (write-char (integer->char v) p)
                                  (loop (+ i 6))))))
                         (else (jfail "bad escape" i)))))
                    ;; A DEPARTURE FROM RFC 8259, and one to look up before
                    ;; removing: section 7 says a
                    ;; control character below U+0020 must be escaped, and
                    ;; this branch copies whatever it finds -- a raw tab or
                    ;; newline inside a string is taken. BEFORE CHANGING
                    ;; THIS BRANCH, read the rows for it in
                    ;; test/json-rfc-surface.sc and act on what they say:
                    ;; if they still record the laxity as shared, tighten
                    ;; both ends in one change or not at all, because
                    ;; refusing on one side makes the same document
                    ;; readable at one end and not the other. If they no
                    ;; longer do, this note has outlived its subject and
                    ;; goes with the rows. What the other end accepts
                    ;; today is not written here -- this file cannot
                    ;; check it, and a copy of it would go stale in
                    ;; silence.
                    (else (write-char ch p) (loop (+ i 1))))))))
          values))
      ;; A number token is BOUNDED. Without a limit the whole run of digits
      ;; goes to string->number, which builds an arbitrary-precision integer:
      ;; measured, 262144 digits takes 4.5 SECONDS, and that is one request
      ;; freezing the single scheduler thread for every other connection.
      ;; The default body limit allows nearly a megabyte of digits, so a
      ;; handful of requests occupies every worker indefinitely.
      ;;
      ;; 64 was chosen for what a NUMBER needs -- IEEE doubles carry 17
      ;; significant digits, a nanosecond timestamp 19 -- and that was the
      ;; wrong question for a general-purpose JSON parser. JSON integers are
      ;; unbounded by the grammar, and applications really do send big ones:
      ;; a uint256, the largest integer Ethereum and friends work in, is 78
      ;; digits. Refusing those is a compatibility regression, not a defence.
      ;;
      ;; The right question is what a limit BUYS. Measured, string->number
      ;; costs about 2 us at 64 digits, 28 us at 512, 91 us at 1024, and
      ;; 1204 us at 4096 -- superlinear, which is why an unbounded run was a
      ;; 4.5-second freeze at 262144. At 512 the worst a full 1 MiB body can
      ;; buy is roughly 2000 numbers x 28 us, about 57 ms: the same order as
      ;; other per-request work, and three orders below the freeze this
      ;; guards against. So 512 keeps the defence and drops the regression.
      (define max-number-chars 512)

      ;; JSON's grammar wants a digit on BOTH sides of a decimal point and
      ;; after an exponent marker. Chez's reader does not: string->number
      ;; takes "5.", "5.e3", "1.e2", "-3." and "-.5", so a scanner that
      ;; slices a token by character class and hands the whole thing over
      ;; inherits that. This checks the token's SHAPE before delegating --
      ;; one pass over characters already scanned, no allocation -- and
      ;; leaves what the delegation is actually for untouched: magnitude,
      ;; exactness, and the non-finite refusal below.
      ;;
      ;; WHAT IT DELIBERATELY DOES NOT ENFORCE: `int = 0 | [1-9]digit*`.
      ;; A leading zero -- "01", "-00", "01.5" -- stays accepted. WHETHER
      ;; REMOVING IT CONVERGES THE TWO READERS OR PARTS THEM DEPENDS ON
      ;; SOMETHING THIS FILE DOES NOT KNOW: a laxity only one side has
      ;; comes out on its own, one both sides have comes out on both at
      ;; once, and which this is lives in the rows, not here. Read them
      ;; before touching the branch; see the note on parse-number's
      ;; acceptance surface below for where they are.
      ;; ---- before changing what this file accepts -------------------------
      ;; A second reader for the same wire format exists elsewhere. Where
      ;; two readers disagree about accepting a document, the line is
      ;; asymmetric: the same bytes mean different things depending on
      ;; which end read them -- so a change here MAY need coordinating,
      ;; and whether this one does is written in the row set in
      ;; test/json-rfc-surface.sc. Look there first. If it records a
      ;; decision covering this branch, that decision moves with the code;
      ;; if it records none, treat the change as local and say so there.
      ;;
      ;; WHAT THAT ROW SET IS, precisely, because calling it "the
      ;; authority" overstates it: A HAND-MAINTAINED RECORD. It imports
      ;; this library and no other, so it exercises THIS reader and can
      ;; say nothing about any other one by running. It is where the
      ;; decisions are written down and it is exactly as current as the
      ;; last person who wrote in it. Consult it, and change it in the
      ;; same commit -- but never read a green run of it as evidence
      ;; about the far end.
      ;;
      ;; THIS FILE ACCEPTS, past what RFC 8259 allows:
      ;;   - a leading zero in the integer part: "01", "-00", "01.5";
      ;;   - a bare control character inside a string (see parse-string).
      ;; That list is what to look up before changing either branch; it is
      ;; not an inventory of anything. A departure can also run the other
      ;; way, a reader refusing what the grammar allows, and that kind is
      ;; not repaired by loosening one side either. Classification and
      ;; tally live in the record; never restate a count of deviations
      ;; here.
      ;;
      ;; The dot rows above came out earlier, and the note explaining them
      ;; came out in the same change -- which is the pattern: when a
      ;; laxity goes, the prose about it goes with it. A retained clause
      ;; with no expiry goes on looking like it still holds.
      ;;
      ;; WHERE THE DELEGATION IS ALREADY NARROWED, and it matters for
      ;; comparing the two: string->number would read "+5", "1/2" and
      ;; "#x10". No whole spelling reaches it, but they are cut at two
      ;; different points and only one of those points is in parse-number.
      ;; "+5" and "#x10" are cut in parse-value*, whose dispatch admits
      ;; only `-` or char-numeric?, so neither gets as far as this
      ;; procedure. "1/2" does reach it -- the scanner stops at `/`,
      ;; the legal prefix "1" IS delegated and does parse, and what
      ;; refuses the document is the trailing content. Those cuts are THIS
      ;; implementation's, at those points. A reader that hands a whole
      ;; token to Number() or parseFloat cuts somewhere else, which is the
      ;; kind of difference the row set exists to catch.
      ;;
      ;; KNOWN, AND DELIBERATELY NOT A DEVIATION: char-numeric? is
      ;; Unicode-aware, so an Arabic-Indic or fullwidth digit passes the
      ;; value dispatch and is taken into the token by the scanner. It is
      ;; then refused as "bad number" when number-shape? below returns #f,
      ;; its digit test being ASCII-only: that jfail dominates the
      ;; delegation, so string->number is not reached. WHETHER THIS IS A
      ;; DEVIATION IS NOT DECIDABLE FROM HERE. This side refuses, and a
      ;; reader dispatching on /[0-9]/ would refuse one step earlier --
      ;; but "would" is a reader we imagined, and what any real second
      ;; implementation answers is not something this file can find out.
      ;; If both refuse, the difference is only in where and with what
      ;; message, and matching diagnostics is not something we hold each
      ;; other to; if one accepts, that is a real difference and belongs
      ;; in the record with the others. Look there before concluding
      ;; either way.
      (define (json-digit? c) (char<=? #\0 c #\9))

      ;; index after a run of one or more digits from k, or #f for none
      (define (digit-run k to)
        (let loop ((k k) (any #f))
          (if (and (fx< k to) (json-digit? (string-ref s k)))
              (loop (fx+ k 1) #t)
              (and any k))))

      ;; [-] int [frac] [exp], a digit required in each part present
      (define (number-shape? from to)
        (let* ((k (if (and (fx< from to) (char=? (string-ref s from) #\-))
                      (fx+ from 1)
                      from))
               (k (digit-run k to)))
          (and k
               (let ((k (if (and (fx< k to) (char=? (string-ref s k) #\.))
                            (digit-run (fx+ k 1) to)
                            k)))
                 (and k
                      (let ((k (if (and (fx< k to)
                                        (memv (string-ref s k) '(#\e #\E)))
                                   (let ((k (fx+ k 1)))
                                     (digit-run
                                       (if (and (fx< k to)
                                                (memv (string-ref s k)
                                                      '(#\+ #\-)))
                                           (fx+ k 1)
                                           k)
                                       to))
                                   k)))
                        (and k (fx= k to))))))))

      (define (parse-number i)
        (let scan ((j (if (char=? (string-ref s i) #\-) (+ i 1) i))
                   (float? #f))
          (when (> (- j i) max-number-chars)
            (jfail "number too long" i))
          (if (and (< j n)
                   (let ((c (string-ref s j)))
                     (or (char-numeric? c)
                         (memv c '(#\. #\e #\E #\+ #\-)))))
              (scan (+ j 1)
                    (or float? (memv (string-ref s j) '(#\. #\e #\E))))
              (let ()
                (unless (number-shape? i j) (jfail "bad number" i))
                (let ((v (string->number (substring s i j) 10)))
                ;; The shape check leaves string->number nothing to
                ;; refuse in the shapes it admits: measured over the
                ;; representative alphabet {0,1,9,.,e,E,+,-} to length 6,
                ;; 8385 shaped tokens, none unreadable. That alphabet is
                ;; one digit class and the punctuation, NOT the scanner's
                ;; continuation set, which carries all ten digits and,
                ;; through char-numeric?, non-ASCII ones as well. A
                ;; bounded measurement, then, not a proof of
                ;; unreachability. So this #f is a floor, not a filter --
                ;; keep it, or a later loosening of the shape check
                ;; returns a wrong value where it now raises.
                (unless v (jfail "bad number" i))
                ;; An out-of-range exponent becomes +inf.0, which is a REAL
                ;; and therefore passes any (real? v) guard downstream --
                ;; a caller asking "is this a number I can compare?" gets
                ;; yes, and then compares against infinity. An expiry
                ;; check is the shape of code that goes wrong that way.
                ;; JSON has no infinities, so refusing here
                ;; is also the more faithful parse.
                (when (and (real? v) (or (nan? v) (infinite? v)))
                  (jfail "number is not finite" i))
                (values (if (and float? (exact? v)) (exact->inexact v) v) j))))))
      ;; top level: one value, then only whitespace
      (let-values (((v end) (parse-value 0)))
        (unless (= (skip-ws end) n) (jfail "trailing characters" end))
        v)))

  ;; ---- writer ------------------------------------------------------------
  ;; Everything is emitted into ONE string output port: linear in the
  ;; output size. (The previous string-append accumulation re-copied the
  ;; accumulator for every element -- quadratic on large arrays/objects.)

  ;; does s need any escaping at all? If not it is emitted with a single
  ;; put-string -- the common case for keys and plain values.
  (define (json-clean? s)
    (let ((n (string-length s)))
      (let loop ((i 0))
        (or (fx= i n)
            (let ((ch (string-ref s i)))
              (and (not (char=? ch #\"))
                   (not (char=? ch #\\))
                   (fx>= (char->integer ch) #x20)
                   (loop (fx+ i 1))))))))

  (define (write-json-string s p)
    (put-char p #\")
    (if (json-clean? s)
        (put-string p s)
        (string-for-each
          (lambda (ch)
            (let ((code (char->integer ch)))
              (cond
                ((char=? ch #\") (put-string p "\\\""))
                ((char=? ch #\\) (put-string p "\\\\"))
                ((char=? ch #\newline) (put-string p "\\n"))
                ((char=? ch #\return) (put-string p "\\r"))
                ((char=? ch #\tab) (put-string p "\\t"))
                ((fx< code #x20)
                 (put-string p "\\u")
                 (let ((h (number->string code 16)))
                   (do ((i (string-length h) (fx+ i 1))) ((fx= i 4))
                     (put-char p #\0))
                   (put-string p h)))
                (else (put-char p ch)))))
          s))
    (put-char p #\"))

  ;; number-text answers about text and does not raise; the exception is
  ;; this library's, because the error shape is this library's contract.
  ;; Every exact integer and every finite inexact real passes through
  ;; this procedure, so arriving is ordinary. It is REACHING THE RAISE
  ;; that means the formatter produced something outside JSON syntax
  ;; which the one known repair did not fix -- our fault, not the
  ;; caller's, and the message says so.
  (define (checked-number-text v)
    (or (number-text v)
        (raise (vector 'json-error
                       "internal: number formatted outside JSON syntax"
                       #f))))

  (define (number->json v)
    (cond
      ;; TWO RULES, IN ORDER, and they answer different questions.
      ;;
      ;; FIRST, THE REPRESENTATION. What is serialized is a Scheme value,
      ;; not a mathematical object, so the test is real? -- the type
      ;; predicate. Every complex representation is refused, INCLUDING
      ;; one whose imaginary part is zero: (make-rectangular 1.0 0.0)
      ;; satisfies real-valued? and JSON plainly has 1.0 to hold it, and
      ;; it is refused anyway. THE DATA MODEL IS DEFINED OVER SCHEME'S
      ;; REPRESENTATIONS, and it admits real? and nothing else; it does
      ;; not project a complex representation onto a real one when the
      ;; imaginary part happens to vanish. That is the whole reason: a
      ;; policy, stated. Two earlier attempts to give it a better one
      ;; were both false -- that the alternative predicate is
      ;; unavailable (a caller can ask real-valued?, or read imag-part),
      ;; and that real? is the predicate a caller would classify with
      ;; (there is no single such predicate; number?, flonum?,
      ;; real-valued? are all things callers use). A choice does not
      ;; become better justified by acquiring a reason that is not true.
      ;; It leaves as the same
      ;; #(json-error "not a JSON value" #f) as a char or a port. It used
      ;; to leave as an assertion-violation, which a guard written for
      ;; json-error did not catch, and that was invisible only because
      ;; every other branch here wrote "null" instead of raising at all.
      ;;
      ;; SO "COMPLEX" IS TWO CASES HERE, NOT ONE, AND A TEST NEEDS BOTH.
      ;; A complex with a non-zero imaginary part is refused by real? and
      ;; by real-valued? alike, so it cannot tell which predicate this
      ;; line uses; only a zero-imaginary one can. Swap real? for
      ;; real-valued? and (make-rectangular 1.0 0.0) walks past this
      ;; check and dies at nan? with a native condition instead of the
      ;; json-error above -- and a suite whose only complex input is
      ;; 1+2i stays green through that. The example was named in this
      ;; comment three drafts before any cell used it -- so, stated as a
      ;; rule that stays true after the cell exists: PROSE THAT NAMES THE
      ;; INPUT DISTINGUISHING TWO CHOICES HAS NAMED A REQUIRED TEST, AND
      ;; IF NOTHING FEEDS IT, THAT TEST IS MISSING. The thinking is
      ;; already done at that point; only the feeding is left, which is
      ;; why this is a cheaper thing to hunt than an input nobody thought
      ;; of.
      ((not (real? v))
       (raise (vector 'json-error "not a JSON value" #f)))
      ;; An exact integer is written exactly, at whatever width it takes
      ;; -- BUT THIS LIBRARY WILL NOT READ BACK WHAT IT WRITES HERE past
      ;; the reader's max-number-chars: 10^511 is 512 digits and comes
      ;; home, 10^512 is 513 and comes back "number too long". That is
      ;; the second member of a family, the first being depth: a reader
      ;; bound with no writer counterpart makes the two directions
      ;; disagree in the same shape. Both are recorded and neither is
      ;; repaired, because tightening the writer refuses values it
      ;; writes correctly today and loosening the reader moves a
      ;; resource limit; the trade wants deciding once, for the family.
      ((and (exact? v) (integer? v)) (checked-number-text v))
      ;; SECOND, AND ONLY THEN, FINITENESS. JSON has no NaN or Infinity,
      ;; and this emits null for them as JSON.stringify does. The check
      ;; is AFTER the conversion, and there is exactly one of it, because
      ;; the conversion is where a finite input can become a non-finite
      ;; output: an exact ratnum is never infinite? itself, so
      ;; (/ (expt 10 4000) 3) passed a check placed before the conversion
      ;; and left as the literal text +inf.0 -- not JSON at all, and
      ;; refused by this library's own reader.
      ;;
      ;; What survives here is LOSSY BY CONTRACT, in both directions: a
      ;; ratnum is rounded (1/3 goes out as 0.333...), and a magnitude
      ;; below flonum range collapses (1/(expt 10 400) goes out as 0.0).
      ;; Neither is a round trip. What is promised is a legal JSON
      ;; number, not the value you put in.
      (else
        (let ((f (if (exact? v) (exact->inexact v) v)))
          (if (or (nan? f) (infinite? f)) "null" (checked-number-text f))))))

  ;; The message is deliberately the reader's word for word: when a
  ;; document dies of depth, both directions say the same thing.
  (define (write-json x p) (write-json* x p 0))

  (define (write-json* x p depth)
    (when (fx> depth write-guard-depth)
      (raise (vector 'json-error "nesting too deep" #f)))
    (cond
      ((eq? x #t) (put-string p "true"))
      ((eq? x #f) (put-string p "false"))
      ((eq? x 'null) (put-string p "null"))
      ((number? x) (put-string p (number->json x)))
      ((string? x) (write-json-string x p))
      ((symbol? x) (write-json-string (symbol->string x) p))
      ((vector? x)
       (put-char p #\[)
       (let ((n (vector-length x)))
         (do ((i 0 (fx+ i 1))) ((fx= i n))
           (when (fx> i 0) (put-char p #\,))
           (write-json* (vector-ref x i) p (fx+ depth 1))))
       (put-char p #\]))
      ((null? x) (put-string p "{}"))
      ;; THE WRITER IS NOT INJECTIVE over Scheme representations, and
      ;; this branch is where it bites hardest, because (cdr kv) is
      ;; taken as the value: (("a" . #("b"))) and (("a" "b")) both emit
      ;; {"a":["b"]}, and the wire does not record whether the value was
      ;; a vector in the cdr or a one-element list tail. It is not the
      ;; only place -- the symbol x and the string "x" agree, so do the
      ;; list (1) and the vector #(1), and so do a symbol key and a
      ;; string key of the same name. What follows is NOT that a round
      ;; trip changes the value -- one representative of each collision
      ;; comes home unchanged, and here it is the vector form: read
      ;; {"a":["b"]} and you get a string key with a vector value, equal?
      ;; to the input that produced it. What follows is that the document
      ;; cannot say WHICH preimage it came from, so a round trip is not
      ;; guaranteed to return what was written -- the other members of
      ;; the collision come back as the survivor. This is distinct from
      ;; the reading-side ambiguity recorded elsewhere: there one shape
      ;; had two readings, here two values have one document.
      ;;
      ;; alist -> object. EVERY entry must be a pair with a string or
      ;; symbol key: a list of lists (a nested array) also has a pair as
      ;; its car, and treating it as an object used to crash on the
      ;; non-string key. Note (("a" "b")) stays genuinely ambiguous --
      ;; it is both a one-entry alist and a one-element array of
      ;; strings -- and is still written as an object; use a vector for
      ;; an unambiguous array.
      ((and (list? x) (pair? (car x))
            (let all ((l x))
              (or (null? l)
                  (and (pair? (car l))
                       (let ((k (caar l))) (or (string? k) (symbol? k)))
                       (all (cdr l))))))
       (put-char p #\{)
       (let loop ((l x) (first #t))
         (unless (null? l)
           (unless first (put-char p #\,))
           (let ((kv (car l)))
             (write-json-string
               (if (symbol? (car kv)) (symbol->string (car kv)) (car kv))
               p)
             (put-char p #\:)
             (write-json* (cdr kv) p (fx+ depth 1)))
           (loop (cdr l) #f)))
       (put-char p #\}))
      ((list? x)                                   ; plain list -> array
       (put-char p #\[)
       (let loop ((l x) (first #t))
         (unless (null? l)
           (unless first (put-char p #\,))
           (write-json* (car l) p (fx+ depth 1))
           (loop (cdr l) #f)))
       (put-char p #\]))
      ;; NOT A JSON VALUE. This used to write "null", which is the one
      ;; answer a caller cannot tell from a real one: null is a value
      ;; they may legitimately have meant, so a mistyped field left the
      ;; library as a document that looked right. Everything reaching
      ;; here -- a char, a bytevector, a procedure, a record, an
      ;; improper pair, a circular list, which is not a list? -- is a
      ;; caller's type error, and none of them has a sensible rendering.
      ;; The set is OPEN, not the list above: it is whatever the dispatch
      ;; does not name, and Chez keeps adding kinds (fxvector, flvector,
      ;; box, ports, conditions all land here). Treat the list as
      ;; examples; do not turn it into an enumeration.
      ;;
      ;; AND DO NOT WIDEN IT TO FIT ONE. An fxvector or an flvector is an
      ;; ordinary sequence of numbers and rendering it as an array looks
      ;; like an easy win. The reason not to is a POLICY, not a proof.
      ;;
      ;; WHAT FOLLOWS IS THE OUTER DISPATCH -- which branch a value is
      ;; sent down -- AND NOT THE SET OF VALUES THAT SERIALISE. The two
      ;; are different and an earlier draft called the list both at once.
      ;; A vector is dispatched as an array whatever it holds, and
      ;; #(#\a) is refused at its element; a value of any shape here is
      ;; refused if it is too deep or self-referential. Membership below
      ;; decides the branch; whether the whole value comes out is decided
      ;; recursively, by these same rules applied to what it contains.
      ;;
      ;; The branches: booleans; the symbol null, which becomes the JSON
      ;; literal; numbers, the branch taken by number?, within which
      ;; real? decides and the non-finite ones become null; strings;
      ;; symbols OTHER THAN null, which become JSON strings; vectors; the
      ;; empty list; a non-empty alist-shaped list; a non-empty list that
      ;; is not alist-shaped.
      ;;
      ;; MOST OF THOSE CARRY QUALIFIERS AND THE QUALIFIERS ARE THE POINT.
      ;; A bare "numbers" readmits what the real? gate above turns away,
      ;; since (make-rectangular 1.0 0.0) satisfies number?. A bare
      ;; "symbols" is wrong in the other direction: 'null is a symbol and
      ;; does not become a string. (An earlier draft said TWO of them
      ;; carry qualifiers, which was a count of the two that had just
      ;; been repaired; the list qualifies at least five.) FOUR REWRITES
      ;; SO FAR, each repairing
      ;; the word that had just been pointed at and leaving the next one:
      ;; "the scalars" (a character is an ordinary Scheme scalar and is
      ;; refused here), then "numbers", then "symbols", then the
      ;; conflation of dispatch with serialisability. Whether this
      ;; version is finally right is not something the version itself can
      ;; say -- what can be said is the method: THE DEFECT IS THE WORD,
      ;; AND A LIST USUALLY HAS MORE THAN ONE, so go through every entry
      ;; asking who defines its extension rather than repairing the one
      ;; named. Every kind admitted past that list is
      ;; another spelling a caller has to learn and this library has to
      ;; keep working. A caller with an flvector converts it,
      ;; (list->vector (flvector->list v)), and the cost lands on the
      ;; side that knows what it meant.
      ;;
      ;; AN ARGUMENT THAT WAS TRIED HERE AND IS NOT AVAILABLE, written
      ;; down so the next reader does not spend the same afternoon on it:
      ;; that admitting an fxvector would break symmetry with the second
      ;; implementation. Whether it would cannot be settled in this file
      ;; -- the claim is about another implementation's input domain, and
      ;; nothing here can check that. Two attempts to rescue it also
      ;; failed. Saying an fxvector "just becomes an array" needs the
      ;; same unavailable fact. Saying we are already asymmetric -- this
      ;; writer does accept a list that is neither empty nor alist-shaped
      ;; as an array, a symbol as a
      ;; string, a symbol as an object key, none of which its own reader
      ;; produces -- is true and checkable, but it is about OUR reader,
      ;; not the other one, so it does not reach the claim either.
      ;;
      ;; The policy above stands without it. It is a chosen data model,
      ;; and a chosen model needs no proof that the alternative is
      ;; impossible, only a reason to prefer it.
      ;; Our own reader has no such case -- it is reading text, not
      ;; values -- so this wording is not the reader's being reused. What
      ;; the second implementation's writer says is deliberately not
      ;; recorded here: it is not a fact this file can check.
      (else (raise (vector 'json-error "not a JSON value" #f)))))

  (define (json->string x)
    (call-with-string-output-port
      (lambda (p) (write-json x p))))

  ;; ---- path access -------------------------------------------------------

  (define (ref1 x k)
    (cond
      ((and (vector? x) (integer? k))
       (and (>= k 0) (< k (vector-length x)) (vector-ref x k)))
      ((and (list? x) (or (string? k) (symbol? k)))
       (let ((key (if (symbol? k) (symbol->string k) k)))
         (let loop ((l x))
           (cond
             ((null? l) #f)
             ((and (pair? (car l)) (equal? (caar l) key)) (cdar l))
             (else (loop (cdr l)))))))
      (else #f)))

  (define (json-ref x . keys)
    (fold-left (lambda (acc k) (and acc (ref1 acc k))) x keys))
)
