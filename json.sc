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
;;; (string->json s)   parse; raises #(json-error msg pos) on bad input
;;; (json->string x)   serialize (alists -> objects, vectors -> arrays;
;;;                    plain lists also serialize as arrays)
;;; (json-ref x k ...) path access: string/symbol key for objects,
;;;                    integer index for arrays; #f when absent

(library (igropyr json)
  (export string->json json->string json-ref)
  (import (chezscheme))

  ;; nesting cap for untrusted input (same guard as (igropyr sexpr))
  (define max-depth 64)

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
      ;; Mirrors (igropyr sexpr)'s cap for the same threat model.
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
                    ;; SHARED DEPARTURE, held in lockstep: RFC 8259 says a
                    ;; control character below U+0020 must be escaped, and
                    ;; this branch copies whatever it finds -- a raw tab or
                    ;; newline inside a string is taken. The browser-side
                    ;; reader takes them too, so refusing here alone would
                    ;; make the same document readable at one end and not
                    ;; the other. The rows that pin this are in
                    ;; test/json-rfc-surface.sc; when both sides refuse
                    ;; together, in one change, this note and those rows
                    ;; are deleted rather than reworded.
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
      ;; A leading zero -- "01", "-00", "01.5" -- stays accepted. That
      ;; laxity is SHARED with the browser-side reader; the missing digit
      ;; beside a point was ours alone. Removing what only one side has
      ;; converges the two; removing what both have makes them disagree.
      ;; The distinction is the lockstep contract, not taste -- see the
      ;; note on parse-number's acceptance surface below.
      ;; ---- lockstep with the browser-side reader -------------------------
      ;; A second reader for the same wire format lives on the browser
      ;; side. Where the two disagree about accepting a document, the line
      ;; is asymmetric: the same bytes mean different things depending on
      ;; which end read them. So the ACCEPTANCE SURFACE is held in lockstep
      ;; and the authority for it is the row set in
      ;; test/json-rfc-surface.sc -- not this comment, and not a count.
      ;;
      ;; The LAXITIES BELOW stay, under the lockstep decisions the row
      ;; set records -- both readers accept what RFC 8259 does not:
      ;;   - a leading zero in the integer part: "01", "-00", "01.5";
      ;;   - a bare control character inside a string (see parse-string).
      ;; That is a warning about these two, not an inventory. Shared
      ;; departures can also run the other way, both readers refusing what
      ;; the grammar allows, and those are not repaired by loosening one
      ;; side either. The row set owns the classification and the tally;
      ;; what this comment owns is the instruction not to move these two
      ;; alone. Never restate a count of deviations here.
      ;; TIGHTENING EITHER ONE HERE ALONE WOULD BREAK THE LINE, not fix it.
      ;; They come out when both sides come out together, in one change --
      ;; and when that happens these lines are DELETED, not edited: a
      ;; retained clause with no expiry goes on looking like it still holds.
      ;;
      ;; The dot rows above were different in kind: this side alone took
      ;; them, so removing them converged the two readers rather than
      ;; parting them. That is the whole test -- shared or ours alone --
      ;; and it is why the leading zero survives three lines from code
      ;; that refuses a missing digit.
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
      ;; delegation, so string->number is not reached. A reader
      ;; dispatching on /[0-9]/ refuses one step earlier still. All
      ;; refuse. Lockstep is over the verdict, not the diagnostic --
      ;; error text and position are not a contract here -- so this is
      ;; not an additional deviation and should not be reported as one.
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
                ;; and therefore passes any (real? v) guard downstream. jwt's
                ;; expiry check was exactly such a guard: a correctly signed
                ;; token carrying exp=1e999 got a non-finite expiry and never
                ;; expired. JSON has no infinities, so refusing here is also
                ;; the more faithful parse.
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

  (define (number->json v)
    (cond
      ;; a non-real (e.g. complex) would serialize to invalid JSON
      ((not (real? v))
       (assertion-violation 'json->string "JSON numbers must be real" v))
      ((and (exact? v) (integer? v)) (number->string v))
      ;; JSON has no NaN/Infinity; emit null as JSON.stringify does
      ((or (nan? v) (infinite? v)) "null")
      ((exact? v) (number->string (exact->inexact v)))
      (else (number->string v))))

  (define (write-json x p)
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
           (write-json (vector-ref x i) p)))
       (put-char p #\]))
      ((null? x) (put-string p "{}"))
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
             (write-json (cdr kv) p))
           (loop (cdr l) #f)))
       (put-char p #\}))
      ((list? x)                                   ; plain list -> array
       (put-char p #\[)
       (let loop ((l x) (first #t))
         (unless (null? l)
           (unless first (put-char p #\,))
           (write-json (car l) p)
           (loop (cdr l) #f)))
       (put-char p #\]))
      (else (put-string p "null"))))

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
