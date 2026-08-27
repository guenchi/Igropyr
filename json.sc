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
;;; (json->string x)   serialize. AN ARRAY IS A VECTOR AND NOTHING ELSE:
;;;                    a list is either an object (every element a
;;;                    pair), or '() which is written {}, or refused
;;;                    with a message naming list->vector. A key that is
;;;                    not a string is refused too, by name. It used to
;;;                    serialize as an array,
;;;                    which left the pair as the only thing separating
;;;                    an array from an object. Raises the
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
;;; PATHS come in two layers, and the trailing * is THE LOWER ONE -- as
;;; in write-json*, and unlike the convention elsewhere in Scheme where a
;;; star means an enhanced variant. The starred procedures take a single
;;; locator and can be applied; the macros take a path written out at
;;; the call site and flatten it into nested calls to them. Each path
;;; element is an expression, not a literal, and the container and every
;;; locator are evaluated EXACTLY ONCE.
;;;
;;;   (json-ref*    x k [absent])  read one step; absent is a thunk
;;;   (json-set*    x k v)         replace at an existing locator
;;;   (json-drop*   x sel)         remove what sel selects
;;;   (json-update* x sel p)       transform what sel selects; p takes
;;;                                (key old) -- the index, for a vector
;;;   (json-ref x k ... [absent]) and json-set / json-drop / json-update
;;;                                likewise, over a written-out path.
;;;                                Only json-ref takes the trailing
;;;                                thunk; the others end in a value.
;;;
;;;   (json-object? x) (json-array? x) (json-null? x)
;;;     classify a value in this representation. NOT writability checks:
;;;     a value can satisfy json-object? and still be refused by
;;;     json->string, which validates recursively.
;;;
;;; json-update* CALLS A PROCEDURE IN ITS VALUE POSITION rather than
;;; storing it. That is a property of json-update*, not of the value
;;; position in general: json-push* and json-insert* store whatever they
;;; are given, a procedure included, and the writer refuses it later.
;;; sel is a locator, a predicate on the key, #t for every member, or #f
;;; for none.
;;;
;;; #f MEANS FOUR THINGS HERE and they are worth reading together:
;;;   json-ref* -> #f      no value at that locator
;;;   a writer  -> #f      the operation failed: broken path, or a
;;;                        locator that is not there
;;;   sel = #f             select nothing: the container comes back
;;;                        unchanged, which is not a failure
;;;   the datum #f         a JSON false, stored and read back like any
;;;                        other value
;;; A failing writer answers #f while one told to select nothing answers
;;; the container, so those two are distinguishable. An absent member and
;;; a member whose value is false are NOT, on a read with no thunk: pass
;;; one, to either layer, to tell them apart.
;;;
;;; Selecting nothing is not failing. (json-update* x sel p) with a sel
;;; that matches no member answers a container equal to x: zero members
;;; were transformed, and that is what was asked for. EQUAL, not eq?.
;;; Nothing here promises to share structure with its argument or to copy
;;; it; both happen, and which one is an implementation choice that is
;;; free to change. Code that needs to know whether a value was rebuilt
;;; must compare contents.

(library (igropyr json)
  (export string->json json->string
          json-object? json-array? json-null?
          json-ref  json-ref*
          json-set  json-set*
          json-drop json-drop*
          json-push json-push*
          json-insert json-insert*
          json-update json-update*)
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
      ;; A SYMBOL IS NOT A STRING HERE. It was written as one, which made
      ;; 'foo and "foo" the same document and left the wire unable to say
      ;; which had been written. The one symbol that remains is null, and
      ;; it is caught above: 'null is not a symbol used as a string, it
      ;; is this representation's spelling of the JSON literal.
      ((symbol? x)
       (raise (vector 'json-error
                      (format "a JSON string is a string, not the symbol ~s: quote it" x)
                      #f)))
      ((vector? x)
       (put-char p #\[)
       (let ((n (vector-length x)))
         (do ((i 0 (fx+ i 1))) ((fx= i n))
           (when (fx> i 0) (put-char p #\,))
           (write-json* (vector-ref x i) p (fx+ depth 1))))
       (put-char p #\]))
      ((null? x) (put-string p "{}"))
      ;; HOW THE SHAPE COLLISIONS WERE CLOSED, since the way matters more
      ;; than the fact. (("a" . #("b"))) and (("a" "b")) once emitted the
      ;; same document; so did the list (1) and the vector #(1); so did
      ;; the symbol x and the string "x", and a symbol key and a string
      ;; key of the same name. NONE of those was closed by choosing a
      ;; winner and writing it: each was closed by REFUSING the other
      ;; spelling, so a caller who held the losing one is told, rather
      ;; than quietly served the survivor's document. That is why the
      ;; refusals above exist and why turning any of them back into a
      ;; conversion reopens a collision rather than adding a convenience.
      ;;
      ;; THE WRITER IS STILL NOT INJECTIVE, in the number domain: an
      ;; exact ratio and its rounded decimal reach the same text, and
      ;; every non-finite reaches null. Those are not shape collisions
      ;; and are not closed by any refusal here. This comment does not
      ;; say how many there are or which ones survive -- that set is
      ;; defined by the number tests, and a count written here would go
      ;; stale in a file that never has to be opened to change it.
      ;;
      ;; What non-injective means here is NOT that a round trip changes
      ;; the value -- one representative of each collision comes home
      ;; unchanged. It is that the document cannot say WHICH preimage it
      ;; came from, so the other member comes back as the survivor. This
      ;; is distinct from the reading-side ambiguity recorded elsewhere:
      ;; there one shape had two readings, here two values have one
      ;; document.
      ;;
      ;; alist -> object. EVERY entry must be a pair; the key inside it
      ;; must be a string, and that is checked in the loop rather than
      ;; here, so the message can name the key. Note (("a" "b")) is
      ;; genuinely ambiguous -- it is both a one-entry alist and a
      ;; one-element array of strings -- and it is NOT written: it
      ;; classifies as an object, and then its value ("b") is a list,
      ;; which the writer refuses. Use a vector for an unambiguous array.
      ;; THE CLASSIFIER LOOKS AT SHAPE, NOT AT KEYS. Every element being
      ;; a pair is what makes this an object; whether the keys are usable
      ;; is then decided in the loop, where the offending key is in hand
      ;; and can be named. Deciding it here instead sent a bad key to the
      ;; list branch below, which answered that an array must be a vector
      ;; -- a true statement about how the value was classified, and a
      ;; false lead about what the caller did wrong.
      ((and (list? x) (pair? (car x))
            (let all ((l x))
              (or (null? l) (and (pair? (car l)) (all (cdr l))))))
       (put-char p #\{)
       (let loop ((l x) (first #t))
         (unless (null? l)
           (unless first (put-char p #\,))
           (let ((kv (car l)))
             (write-json-string
               (let ((k (car kv)))
                 (if (string? k)
                     k
                     ;; NAMING THE KEY IS THE WHOLE POINT. The condition
                     ;; carries no path and no member ordinal, so without
                     ;; the datum the caller is told a true thing about a
                     ;; value they cannot find. Both spellings are offered
                     ;; because this branch is reached by two different
                     ;; mistakes -- a symbol where a key belongs, and a
                     ;; list of lists meant as a nested array -- and the
                     ;; writer cannot tell which was intended.
                     (raise (vector 'json-error
                                    (format "an object key must be a string, not ~s: an object member is (\"k\" . v), a nested array is #(#(...))" k)
                                    #f))))
               p)
             (put-char p #\:)
             (write-json* (cdr kv) p (fx+ depth 1)))
           (loop (cdr l) #f)))
       (put-char p #\}))
      ;; A LIST IS NOT AN ARRAY HERE. It was once: a non-empty list that
      ;; was not alist-shaped came out as a JSON array, which made the
      ;; pair the only thing standing between an array and an object and
      ;; put the decision inside the elements. (("a" . #("b"))) and
      ;; (("a" "b")) then produced the same document. One spelling is
      ;; enough, and the vector is the one that cannot be mistaken for
      ;; an object, so a list reaching here is refused and told what to
      ;; write instead.
      ((list? x)
       (raise (vector 'json-error
                      "a JSON array is a vector, not a list: use list->vector"
                      #f)))
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
      ;; symbols OTHER THAN null, which are refused and named; vectors;
      ;; the empty list; a list whose every element is a pair. Any other
      ;; non-empty list has its own branch and is refused there -- it is
      ;; listed among the branches because it is one, not because it is
      ;; accepted, and the same is true of the symbol branch above it.
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
      ;; THE REASON, STATED POSITIVELY, because the argument that used to
      ;; sit here has been withdrawn and a withdrawn argument must be
      ;; replaced rather than patched.
      ;;
      ;; What this writer accepts in the SHAPE domain is now exactly what
      ;; its reader produces: objects as alists with string keys, arrays
      ;; as vectors, strings as strings. Narrowing arrays to vectors and
      ;; refusing symbols closed the last two places where a caller could
      ;; hand over a shape no document would ever have come from. An
      ;; fxvector would reopen that: it is a shape with no counterpart on
      ;; the reading side, and admitting it would mean the set of things
      ;; that can be written is once again larger than the set of things
      ;; that can be read back, for no reason except that the conversion
      ;; is easy to write here rather than at the call site.
      ;;
      ;; THE NUMBER DOMAIN IS STILL WIDER, DELIBERATELY, and it is worth
      ;; saying so rather than claiming a symmetry the file does not
      ;; have: an exact ratio is accepted and rounded though no document
      ;; yields one, a non-finite is accepted and written as null though
      ;; the reader refuses non-finites, and an exact integer wider than
      ;; the reader's number-token limit is written and cannot be read
      ;; back. Those are numeric policies, taken here so that every call
      ;; site does not have to take them; they are not a precedent for
      ;; widening the shapes.
      ;;
      ;; (The withdrawn argument was that admitting an fxvector would
      ;; break symmetry with a second implementation. It cannot be
      ;; settled here -- the claim is about another implementation's
      ;; input domain and nothing in this file can check that. It was
      ;; rescued twice and both rescues failed the same way, by needing
      ;; that same unavailable fact or by talking about OUR reader
      ;; instead of the other one.)
      ;;
      ;; The policy above stands without it. It is a chosen data model,
      ;; and a chosen model needs no proof that the alternative is
      ;; impossible, only a reason to prefer it.
      ;; Our own reader has no such case -- it is reading text, not
      ;; values -- so this wording is not the reader's being reused. What
      ;; the second implementation's writer says is deliberately not
      ;; recorded here: it is not a fact this file can check.
      ;;
      ;; THIS MESSAGE MUST NAME A KIND AND NEVER THE VALUE, and the day
      ;; someone improves the localisation here is the day to read this.
      ;; Two reasons; the second is the wider one.
      ;;   - A CIRCULAR VALUE LANDS HERE, because list? answers #f for
      ;;     one. The objection is NOT that printing it would hang:
      ;;     measured, Chez detects the cycle, prints "Warning in write:
      ;;     cycle detected", switches to print-graph, and returns
      ;;     "#0=(1 2 3 . #0#)" -- sixteen characters, exit 0. The
      ;;     objection is that WARNING: an error path must not emit
      ;;     console output of its own, and a caller who sees that line
      ;;     has nothing telling them it came from here.
      ;;   - print-length AND print-level BOTH DEFAULT TO #f, so a
      ;;     message built from the value has no size bound. A
      ;;     200000-element list formats to 400001 characters
      ;;     (measured). This is true of every large value that reaches
      ;;     this branch and has nothing to do with cycles, which is why
      ;;     it, not the circular case, is the reason that generalises.
      ;; The bounded, safe, locating form names the kind instead: "not a
      ;; JSON value: a character". Do not "improve" this by adding ~s.
      (else (raise (vector 'json-error "not a JSON value" #f)))))

  (define (json->string x)
    (call-with-string-output-port
      (lambda (p) (write-json x p))))

  ;; ---- classifiers --------------------------------------------------------
  ;;
  ;; THESE CLASSIFY VALUES IN THIS LIBRARY'S REPRESENTATION -- what
  ;; string->json produces, where a key is always a string and a value is
  ;; always writable. They are NOT writability checks: a value can satisfy
  ;; json-object? and still be refused by json->string, which validates
  ;; recursively. (("a" "b")) is such a value: it is a pair whose car is a
  ;; pair, so it classifies as an object, and its member's value is a list,
  ;; which the writer refuses.
  ;;
  ;; WHAT json-object? ACTUALLY ADMITS is a pair whose car is a pair. It
  ;; does not walk the spine and does not look at the keys, so ((1 . 2))
  ;; and the improper (("a" . 1) . 2) both satisfy it. The second can make
  ;; a path operation raise a native condition; that is the price of the
  ;; one-pair test and it is written down here rather than implied.
  ;;
  ;; They are cheap on purpose. A stricter version is possible without
  ;; going recursive -- walking the spine and requiring a string car at
  ;; every member would cost O(members) and would not touch the values --
  ;; and it was not chosen, because the writer must validate anyway and a
  ;; second supplier of a decision is what this batch has been removing.
  ;; That is a choice about duplication, not a claim that agreement would
  ;; require recursion: FULL agreement would, spine agreement would not,
  ;; and an earlier version of this paragraph offered only the first of
  ;; those and read as though no cheaper option existed.

  (define (json-object? x)
    (or (null? x) (and (pair? x) (pair? (car x)))))

  (define (json-array? x) (vector? x))

  (define (json-null? x) (eq? x 'null))

  ;; ---- path access ---------------------------------------------------------
  ;;
  ;; #f MEANS FOUR DIFFERENT THINGS ACROSS THIS SECTION, and they are set
  ;; out together here rather than left to be assembled from four places:
  ;;
  ;;   json-ref*    returns #f     the path had no value there
  ;;   the writers  return #f      the operation failed: a broken path, or
  ;;                               a locator that does not exist
  ;;   sel = #f     returns the container unchanged: select nothing, so
  ;;                               nothing is dropped or updated
  ;;   the datum #f                a JSON false, which is a value like any
  ;;                               other and can be stored and read back
  ;;
  ;; The first two are distinguishable from the third by what comes back: a
  ;; failing writer answers #f, a writer told to select nothing answers the
  ;; container. The first and the fourth are NOT distinguishable on a read
  ;; with no thunk -- a member whose value is false reads the same as a
  ;; member that is absent. Pass one, to either layer, to tell them apart.

  ;; An index is a member of a vector only when it is an exact non-negative
  ;; integer below the length. integer? alone is wider than that: 1.0
  ;; satisfies it and vector-ref does not accept it, so a predicate written
  ;; that way admits an input to an operation it cannot guard.
  (define (index-of x k)
    (and (vector? x) (exact? k) (integer? k)
         (>= k 0) (< k (vector-length x)) k))

  ;; A STORED KEY IS A STRING; A LOCATOR NEED NOT BE. The writer refuses a
  ;; symbol key because two spellings of one object would reach the same
  ;; document. Nothing of the kind is at stake when a symbol is used to
  ;; POINT AT a member: it is spelled to a string, the lookup happens
  ;; against the string that is really there, and no symbol is ever stored.
  ;; The two rules look opposed and are not, but the asymmetry is real and
  ;; a reader who has just met the writer's refusal will not expect it:
  ;;
  ;;   (json->string '((a . 1)))       refused, the key is a symbol
  ;;   (json-ref* '(("a" . 1)) 'a)     1, the locator is a symbol
  ;;
  ;; It applies to every locator and selector position -- ref, set, drop,
  ;; insert, update -- and not to json-push*, which takes a member rather
  ;; than a locator and therefore stores what it is given.
  (define (key-of k) (if (symbol? k) (symbol->string k) k))

  (define (member-index x k)
    (and (json-object? x) (not (null? x)) (or (string? k) (symbol? k))
         (let ((key (key-of k)))
           (let loop ((l x) (i 0))
             (cond
               ((null? l) #f)
               ((and (pair? (car l)) (equal? (caar l) key)) i)
               (else (loop (cdr l) (+ i 1))))))))

  ;; Reads one step. With no thunk an absent member answers #f; with one,
  ;; the thunk is called with no arguments and its value answers instead.
  (define json-ref*
    (case-lambda
      ((x k) (json-ref* x k (lambda () #f)))
      ((x k absent)
       (let ((i (index-of x k)))
         (if i
             (vector-ref x i)
             (let ((j (member-index x k)))
               (if j (cdr (list-ref x j)) (absent))))))))

  ;; A value position takes either a value or a procedure, and a procedure
  ;; there is a transformation of the old value rather than a value to
  ;; store. A procedure is not a JSON value, so nothing is lost by that
  ;; reading, but it does mean a caller cannot store one.
  (define (apply-value v old)
    (if (procedure? v) (v old) v))

  (define (list-set l i f)
    (let loop ((l l) (i i) (acc '()))
      (if (fx= i 0)
          (append (reverse acc) (cons (f (car l)) (cdr l)))
          (loop (cdr l) (fx- i 1) (cons (car l) acc)))))

  (define (list-insert-at l i item)
    (let loop ((l l) (i i) (acc '()))
      (if (fx= i 0)
          (append (reverse acc) (cons item l))
          (loop (cdr l) (fx- i 1) (cons (car l) acc)))))

  (define (list-drop-at l i)
    (let loop ((l l) (i i) (acc '()))
      (if (fx= i 0)
          (append (reverse acc) (cdr l))
          (loop (cdr l) (fx- i 1) (cons (car l) acc)))))

  ;; Replaces the value at an existing locator. A locator that is not there
  ;; is a failure, not an insertion -- adding is json-push* and json-insert*.
  (define (json-set* x k v)
    (let ((i (index-of x k)))
      (cond
        (i (let ((new (vector-copy x)))
             (vector-set! new i (apply-value v (vector-ref x i)))
             new))
        ((member-index x k)
         => (lambda (j)
              (list-set x j (lambda (kv)
                              (cons (car kv) (apply-value v (cdr kv)))))))
        (else #f))))

  ;; Removes what sel selects. sel is a key or index, a predicate on the
  ;; key, #t for every member, or #f for none -- and #f answers the
  ;; container, because selecting nothing is not a failure.
  (define (selected? sel k)
    (cond
      ((eq? sel #t) #t)
      ((eq? sel #f) #f)
      ((procedure? sel) (and (sel k) #t))
      ((string? sel) (and (string? k) (string=? sel k)))
      ((symbol? sel) (and (string? k) (string=? (symbol->string sel) k)))
      (else (equal? sel k))))

  (define (json-drop* x sel)
    (cond
      ((eq? sel #f) (and (or (json-array? x) (json-object? x)) x))
      ((json-array? x)
       (let ((keep (let loop ((i 0) (acc '()))
                     (if (fx= i (vector-length x))
                         (reverse acc)
                         (loop (fx+ i 1)
                               (if (selected? sel i)
                                   acc
                                   (cons (vector-ref x i) acc)))))))
         (if (fx= (length keep) (vector-length x))
             (and (or (eq? sel #t) (procedure? sel)) x)
             (list->vector keep))))
      ((json-object? x)
       ;; The empty object is an object here. Dropping every member of
       ;; {} drops zero members and succeeds, the way updating zero
       ;; members succeeds: #f is reserved for an operation that did
       ;; not complete. Excluding it made these two verbs disagree on
       ;; the same container.
       (let ((keep (let loop ((l x) (acc '()))
                     (cond
                       ((null? l) (reverse acc))
                       ((and (pair? (car l)) (selected? sel (caar l)))
                        (loop (cdr l) acc))
                       (else (loop (cdr l) (cons (car l) acc)))))))
         (if (= (length keep) (length x))
             (and (or (eq? sel #t) (procedure? sel)) x)
             keep)))
      (else #f)))

  ;; A member of an array is a VALUE; a member of an object is a PAIR.
  ;; That is why these two take the member itself rather than a key and a
  ;; value: three arguments cannot carry a container, a locator, a new key
  ;; and a value, and an earlier shape that tried left the key with nowhere
  ;; to come from on the object side.
  (define (object-member? m) (and (pair? m) (string? (car m))))

  (define (json-push* x v)
    (cond
      ((json-array? x) (list->vector (append (vector->list x) (list v))))
      ((json-object? x) (and (object-member? v) (append x (list v))))
      (else #f)))

  (define (json-insert* x k v)
    (let ((i (index-of x k)))
      (if i
          (list->vector (list-insert-at (vector->list x) i v))
          (let ((j (and (json-object? x) (member-index x k))))
            (and j (object-member? v) (list-insert-at x j v))))))

  ;; Transforms what sel selects, leaving the rest. p is called with the key
  ;; (or index) and the old value. Selecting nothing is not a failure: the
  ;; container comes back unchanged, having had zero members transformed.
  (define (json-update* x sel p)
    (cond
      ((eq? sel #f) (and (or (json-array? x) (json-object? x)) x))
      ((json-array? x)
       (let ((new (vector-copy x)))
         (let loop ((i 0))
           (if (fx= i (vector-length x))
               new
               (begin
                 (when (selected? sel i)
                   (vector-set! new i (p i (vector-ref x i))))
                 (loop (fx+ i 1)))))))
      ((json-object? x)
       (map (lambda (kv)
              (if (and (pair? kv) (selected? sel (car kv)))
                  (cons (car kv) (p (car kv) (cdr kv)))
                  kv))
            x))
      (else #f)))

  ;; ---- paths -------------------------------------------------------------
  ;;
  ;; TWO LAYERS, AND THE STAR IS THE LOWER ONE. In this library a trailing
  ;; * means the more primitive layer, as it does in write-json* -- it is
  ;; NOT an enhanced variant, which is what the trailing star means in much
  ;; of Scheme. The starred procedures take one locator and can be applied;
  ;; the macros take a path of literal locators and flatten it into nested
  ;; calls to them.
  ;;
  ;; The macros rebuild on the way out. A write into a path reads down to
  ;; the innermost container, performs the operation there, and then stores
  ;; each rebuilt container back into its parent -- so a failure anywhere
  ;; on the way answers #f for the whole expression, rather than being
  ;; stored as the value #f in the level above it.
  ;;
  ;; EACH LEVEL BINDS ITS CONTAINER AND ITS LOCATOR ONCE, before either
  ;; pass. That is not tidiness. The two passes are two references to the
  ;; same two expressions, and evaluating them twice meant the read and
  ;; the write could reach different objects: a root expression with a
  ;; side effect handed the second pass a different tree, and the rebuilt
  ;; subtree was stored into a container it had never been read from.
  ;; Nothing about that needs a second thread; the expression does it to
  ;; itself. Any new macro here inherits the requirement.
  ;;
  ;; A path is written out at the call site: the elements are spliced at
  ;; expansion, so their NUMBER is fixed there. Each element is an
  ;; ordinary expression, evaluated at run time and evaluated EXACTLY
  ;; ONCE, as is the container. A path whose length is decided at run
  ;; time is what the starred layer is for.
  ;;
  ;; json-ref takes a trailing thunk, the way json-ref* does: if the last
  ;; argument evaluates to a procedure it is the absent-thunk rather than a
  ;; locator. The test is on the value, it happens at run time, and it is
  ;; made only at the end of the path. Nothing else could be meant there,
  ;; because no procedure is a valid locator -- a locator is a string, a
  ;; symbol, or an exact non-negative integer. Only json-ref has this; the
  ;; other macros end in a value, and a value may well be a procedure.
  ;;
  ;; The cost is that the SYNTAX no longer fixes the path length: whether
  ;; (json-ref d "a" k) is a two-step read or a one-step read with a
  ;; default depends on what k evaluates to, and a reader of that line
  ;; cannot tell. It is a real cost, accepted because the alternative is
  ;; that the macro layer cannot express a default at all.
  ;;
  ;; The thunk answers for a break at ANY level, not only the last one. A
  ;; step that locates nothing answers #f, #f is not a container, so every
  ;; remaining step also locates nothing, and the same final call is the
  ;; one that runs the thunk. There is no separate not-found path to keep
  ;; in step with this one.

  (define-syntax json-ref
    (syntax-rules ()
      ((_ x) x)
      ((_ x k) (json-ref* x k))
      ((_ x k last)
       (let ((end last))
         (if (procedure? end)
             (json-ref* x k end)
             (json-ref* (json-ref* x k) end))))
      ((_ x k rest ...) (json-ref (json-ref* x k) rest ...))))

  (define-syntax json-set
    (syntax-rules ()
      ((_ x k v) (json-set* x k v))
      ((_ x k rest ... v)
       (let ((container x) (locator k))
         (let* ((inner (json-ref* container locator))
                (updated (json-set inner rest ... v)))
           (and updated (json-set* container locator updated)))))))

  (define-syntax json-drop
    (syntax-rules ()
      ((_ x sel) (json-drop* x sel))
      ((_ x k rest ... sel)
       (let ((container x) (locator k))
         (let* ((inner (json-ref* container locator))
                (updated (json-drop inner rest ... sel)))
           (and updated (json-set* container locator updated)))))))

  (define-syntax json-push
    (syntax-rules ()
      ((_ x v) (json-push* x v))
      ((_ x k rest ... v)
       (let ((container x) (locator k))
         (let* ((inner (json-ref* container locator))
                (updated (json-push inner rest ... v)))
           (and updated (json-set* container locator updated)))))))

  (define-syntax json-insert
    (syntax-rules ()
      ((_ x k v) (json-insert* x k v))
      ((_ x k rest ... loc v)
       (let ((container x) (locator k))
         (let* ((inner (json-ref* container locator))
                (updated (json-insert inner rest ... loc v)))
           (and updated (json-set* container locator updated)))))))

  (define-syntax json-update
    (syntax-rules ()
      ((_ x sel p) (json-update* x sel p))
      ((_ x k rest ... sel p)
       (let ((container x) (locator k))
         (let* ((inner (json-ref* container locator))
                (updated (json-update inner rest ... sel p)))
           (and updated (json-set* container locator updated)))))))
)
