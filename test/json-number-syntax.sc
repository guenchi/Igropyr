#!chezscheme
;;; The number-syntax gate whose REFUSALS no formatter output reaches.
;;;
;;; WHY THIS FILE EXISTS, AND WHY (igropyr json-internal) EXISTS.
;;; json->string validates every numeral it is about to emit against JSON
;;; grammar, and repairs the one deviation this Scheme is known to
;;; produce. BOTH CHECKS RUN ON ORDINARY OUTPUT -- the grammar check sees
;;; every number->string result, and the repair sees the tagged
;;; spellings this Scheme really does emit, "5e-324|1" among them. What
;;; formatter output never produces is a case where either one says NO.
;;; That is the distinction the whole file rests on, and it is easy to
;;; state wrongly: the gates are reached constantly; their refusals are
;;; not reached at all. A guard that only ever returns true and a guard
;;; that always returns true are the same thing from outside, which is
;;; why a black-box suite is green whether these are correct, wrong, or
;;; deleted.
;;; That was measured, not assumed: relaxing the production validator to
;;; accept leading zeros left every cell of json-writer-limits.sc green
;;; -- all 105 of them, as that file stood that day; it has more now,
;;; and the number is written here only to date the measurement.
;;;
;;; So the predicates live in a separate internal library and are fed
;;; here directly. FOLDING THAT LIBRARY BACK INTO json.sc WOULD TAKE
;;; THIS FILE'S REACH WITH IT. Done carelessly it is loud -- the imports
;;; here stop resolving. Done thoroughly, with this file adjusted to
;;; match, it is silent, and silence is the outcome to design against.
;;;
;;; THE JUDGES ARE TWO INDEPENDENT MECHANISMS, and they live in
;;; test/json-number-oracles.sc so that both can be put to the same
;;; input. They used to sit one per suite, and only one of them was ever
;;; put opposite production: the state machine had this corpus, so a
;;; drift in IT would have shown as a disagreement. The descent judge in
;;; json-writer-limits.sc had only its own small table and then judged
;;; whatever the formatter emitted -- so that one could have drifted
;;; with both suites green. Sharing them fixes the asymmetry, not an
;;; impossibility: what made the comparison impossible was that neither
;;; was exported, never that they sat in different files.

;;; ---- WHAT THE PROSE IN THIS FILE IS, AND WHICH PART OWES A CELL ----
;;; Nine review rounds went looking for statements here that no assertion
;;; owns, and the list kept regrowing -- because writing a cell means
;;; writing a paragraph, and a paragraph makes claims of its own. The
;;; count of assertions across the two suites rose 97 -> 258 (119 here,
;;; 139 in json-writer-limits.sc) while the number of unowned claims
;;; stayed roughly flat. That is not a coverage problem; it is a
;;; bookkeeping one. FOUR KINDS OF SENTENCE LIVE IN THESE FILES AND ONLY
;;; ONE OF THEM CAN OWE A CELL:
;;;
;;;   BEHAVIOURAL REQUIREMENT -- "the repair refuses a suffix that is not
;;;     |digits". Testable, and owed an assertion that is red when it is
;;;     false and red for no other reason. This is the only kind that
;;;     belongs in a coverage ledger.
;;;
;;;   EXPERIMENT RECORD -- "deleting this conjunct left both suites
;;;     green". A fact about a measurement that was taken, not about the
;;;     code as it stands. Cannot be re-derived by running the suite; it
;;;     is written down BECAUSE nothing else remembers it. Marked
;;;     "measured" where it appears.
;;;
;;;   SOURCE-REVIEW INVARIANT -- "the two judges are independent
;;;     implementations", "production calls this exported helper rather
;;;     than an inlined copy of it". IMPOSSIBLE to own by input and
;;;     output: a behaviourally identical copy answers identically to
;;;     every input there is. Carried as a permanent gap it would make
;;;     the ledger read as permanently in debt; it is not debt, it is a
;;;     constraint that reading the source enforces and running it
;;;     cannot.
;;;
;;;   DERIVED CONSEQUENCE -- "so the two limits differing is a document
;;;     this library will not read". Follows from cells stated elsewhere;
;;;     it needs those cells to exist, not a cell of its own.
;;;
;;; A claim of the third kind recorded as an uncovered requirement is not
;;; an omission waiting to be fixed -- it is an entry that can never be
;;; closed, and an entry that can never be closed makes every later
;;; reading of the ledger wrong in the same direction.
;;;
;;; PUTTING A SENTENCE IN THE THIRD DRAWER IS ITSELF A CLAIM, so it says
;;; who decided and on what ground. Otherwise the label becomes the thing
;;; that protects a statement from being questioned -- exactly the move
;;; this batch kept catching in other forms, where a considered-sounding
;;; position stopped anyone from checking the half of it that had a truth
;;; value. Each classification below names the argument that put it
;;; there, and the argument is the part to attack.

(import (chezscheme) (igropyr json-internal) (igropyr json)
        (igropyr test json-number-oracles))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (shown x) (let ((o (open-output-string))) (write x o) (get-output-string o)))
(define (check label c . info) (if c (ok label) (apply fail label info)))

;; The judge answers for itself first. Every line below names the
;; production boundary it stands on, because a list of examples chosen
;; for looking interesting covers whatever its author happened to think
;; of; a list keyed to productions covers the grammar.
(for-each
  (lambda (p)
    (check (string-append "the state machine itself: " (shown (car p)))
           (eq? (cdr p) (rfc-number-machine? (car p)))))
  '(("0" . #t) ("-0" . #t)                     ; int = "0", with and without minus
    ("9" . #t) ("10" . #t) ("-10" . #t)        ; int = digit1-9 *DIGIT
    ("01" . #f) ("00" . #f) ("-00" . #f)       ; int rejects a leading zero
    ("0.5" . #t) ("0.50" . #t)                 ; frac = "." 1*DIGIT
    ("0." . #f) (".5" . #f) ("0..5" . #f)      ; frac needs a digit, and a point
    ("1e5" . #t) ("1E5" . #t)                  ; exp, both cases
    ("1e+5" . #t) ("1e-5" . #t)                ; exp with either sign
    ("1e" . #f) ("1e+" . #f) ("1e5.0" . #f)    ; exp needs a digit, takes no point
    ("0.5e-5" . #t)                            ; frac and exp together
    ("+1" . #f) ("-" . #f) ("" . #f)           ; no leading plus, no bare sign
    ("1 " . #f) (" 1" . #f)))                  ; no surrounding space

;; ---- the branches, fed directly ----------------------------------------
;; These are the cells that json->string cannot host. Each names what it
;; would catch, since a cell whose label is only its input tells a later
;; reader nothing about what breaking it would mean.
(for-each
  (lambda (t)
    (check (string-append "a leading zero is refused: " (shown t))
           (not (json-number-text? t))))
  '("01" "00" "-00" "01.5" "0123" "-01e5"))

(for-each
  (lambda (t)
    (check (string-append "a well-formed numeral is passed: " (shown t))
           (and (json-number-text? t) #t)))
  '("0" "-0" "9" "10" "0.5" "1e5" "1E+5" "5e-324" "-1.5e-308"))

;; EVERY LETTER, IN EVERY POSITION, AGAINST ALL THREE JUDGES.
;; Scheme's number syntax has five exponent markers -- e, s, f, d, l --
;; and JSON has one. Carrying all of them in the main corpus alphabet
;; would multiply it several times over, so each letter gets its own
;; small corpus instead: every string up to length five over
;; {0, 1, ., e, L} for each of the 52 letters L. Length five, not four,
;; for the reason given at the generator below.
;;
;; TWO THINGS ARE ASSERTED PER STRING, and they fail differently.
;; The differential part puts production and both judges to it, which is
;; what catches a judge drifting. The absolute part says that a letter
;; other than e or E makes a string illegal WHEREVER it appears -- and
;; that one holds no matter what the judges think, which is what catches
;; production and both judges drifting together.
;;
;; THE POSITION IS THE POINT. An earlier version probed only "1" + L +
;; "0", which pins the marker slot and nothing else: a validator that
;; accepted f as an exponent SIGN takes 1eF0 while still refusing 1F0,
;; and that cell stayed green -- measured. Enumerating positions is not
;; something to do by listing the ones worth worrying about; the corpus
;; reaches them because it is a corpus.
(let ((bad-differential '()) (bad-absolute '()) (letters 0) (strings 0)
      (seen-letters (make-eqv-hashtable)) (short-corpora '()))
  (define (letter-corpus L)
    (let ((alphabet (let dedup ((cs (list #\0 #\1 #\. #\e L)) (acc '()))
                      (cond ((null? cs) (reverse acc))
                            ((memv (car cs) acc) (dedup (cdr cs) acc))
                            (else (dedup (cdr cs) (cons (car cs) acc))))))
          (marker? (memv L '(#\e #\E)))
          (mine (make-hashtable string-hash string=?)))
      (set! letters (+ letters 1))
      (hashtable-set! seen-letters L #t)
      (let build ((prefix '()) (depth 0))
        (let* ((str (list->string (reverse prefix)))
               (a (and (json-number-text? str) #t))
               (b (rfc-number-machine? str))
               (c (rfc-number-descent? str)))
          (set! strings (+ strings 1))
          (hashtable-set! mine str #t)
          (unless (and (eq? a b) (eq? b c))
            (when (< (length bad-differential) 8)
              (set! bad-differential
                    (cons (list str 'production a 'machine b 'descent c)
                          bad-differential))))
          ;; the absolute half: a non-marker letter anywhere is illegal,
          ;; and this holds without asking any judge
          (when (and (not marker?) (memv L (string->list str)) a)
            (when (< (length bad-absolute) 8)
              (set! bad-absolute (cons str bad-absolute)))))
        ;; LENGTH FIVE, NOT FOUR. Four reaches every state, but a drift
        ;; confined to ONE transition needs a string that arrives at that
        ;; transition with characters left over. Mutating only the state
        ;; machine's fraction-then-exponent edge to take f is exposed by
        ;; "0.0f0" and by nothing shorter: "0f0" uses the integer edge,
        ;; "0.f0" wants a fraction digit, "0.0f" ends mid-exponent.
        ;; Measured: that mutation was green at four.
        (when (< depth 5)
          (for-each (lambda (c) (build (cons c prefix) (+ depth 1)))
                    alphabet)))
      ;; this letter's own denominator: every distinct string over ITS
      ;; alphabet, counted here rather than folded into the total
      (let* ((k (length alphabet))
             (want (let sum ((len 0) (acc 0))
                     (if (> len 5) acc (sum (+ len 1) (+ acc (expt k len)))))))
        (unless (= (hashtable-size mine) want)
          (set! short-corpora
                (cons (list L 'distinct (hashtable-size mine) 'expected want)
                      short-corpora))))))
  (do ((i 0 (+ i 1))) ((= i 26))
    (letter-corpus (integer->char (+ 97 i)))
    (letter-corpus (integer->char (+ 65 i))))
  ;; The denominators are asserted, not just accumulated. Counting calls
  ;; to letter-corpus proves only that the outer loop ran 52 times: it
  ;; would stay green if the generator were shortened, or if one letter
  ;; were visited twice while another was skipped. The distinct letters
  ;; and the total string count are what say the corpus is the corpus.
  ;; The main corpus already guards itself this way; this block did not.
  ;; MEMBERSHIP, NOT CARDINALITY. "52 distinct characters" is satisfied
  ;; by @A-Y as readily as by A-Z -- start the uppercase loop one code
  ;; point early and both the distinct count and the total stay put. The
  ;; set has to be named, not counted.
  (check "the letters were exactly a-z and A-Z"
         (let ((want (make-eqv-hashtable)))
           (do ((i 0 (+ i 1))) ((= i 26))
             (hashtable-set! want (integer->char (+ 97 i)) #t)
             (hashtable-set! want (integer->char (+ 65 i)) #t))
           (and (= letters 52)
                (= (hashtable-size seen-letters) 52)
                (for-all (lambda (c) (hashtable-ref seen-letters c #f))
                         (vector->list (hashtable-keys want)))))
         (list->string (list-sort char<? (vector->list (hashtable-keys seen-letters)))))
  ;; AND THE TOTAL IS NOT A COMPLETENESS PROOF EITHER. An aggregate
  ;; count survives one corpus duplicating a string while another omits
  ;; one. What says each corpus is whole is a distinct-string count
  ;; taken per letter, which is what this asserts.
  (check "...and each letter's corpus held every distinct string over its alphabet"
         (null? short-corpora)
         (reverse short-corpora))
  (check "...summing to the expected total"
         (= strings (+ (* 51 3906) 1365))
         (list 'strings strings 'expected (+ (* 51 3906) 1365)))
  (check "no letter but e or E appears in a numeral production accepts"
         (null? bad-absolute) (reverse bad-absolute))
  (check "production and both judges agree on every letter corpus"
         (null? bad-differential) (reverse bad-differential)))

;; DIGITS MEANS ASCII DIGITS, and the predicate has to say so itself.
;; Chez's char-numeric? is true of Arabic-Indic and fullwidth digits, so
;; writing the grammar with it instead of an explicit #\0..#\9 range
;; admits numerals JSON does not have -- and measured, that swap leaves
;; every corpus green, because a corpus built from an ASCII alphabet can
;; never contain the characters that would show it. This is the same
;; shape as the exponent-marker letters: the alphabet cannot enumerate
;; what it does not contain, so the question gets asked directly.
(for-each
  (lambda (p)
    (let ((t (car p)) (what (cdr p)))
      (check (string-append "not a JSON digit: " what)
             (not (json-number-text? t))
             t)))
  ;; integer->char, not #\xNNNN. The character literal takes a trailing
  ;; semicolon in string escapes but not here, and writing one starts a
  ;; comment that swallows the rest of the line -- the list still reads,
  ;; just not as written. Spelling the code point arithmetically has no
  ;; such edge.
  (let ((arabic-one (integer->char #x0661))     ; ARABIC-INDIC DIGIT ONE
        (fullwidth-one (integer->char #xFF11))) ; FULLWIDTH DIGIT ONE
    (list (cons (string arabic-one) "Arabic-Indic one, alone")
          (cons (string-append "1" (string arabic-one)) "...after an ASCII digit")
          (cons (string-append "1." (string arabic-one)) "...as a fraction digit")
          (cons (string-append "1e" (string arabic-one)) "...as an exponent digit")
          (cons (string fullwidth-one) "fullwidth one, alone")
          (cons (string-append "1|" (string arabic-one))
                "...and in a numeral with a tag, refused before the tag is read"))))

;; THE TAG'S DIGITS ARE A SECOND ASCII CHECK, and the cell above does not
;; reach it. json-number-text? refuses at the bar, before any suffix is
;; inspected, so feeding it "1|<Arabic-Indic one>" says nothing about the
;; scan inside before-precision-tag -- which has its own #\0..#\9 range
;; and its own way of being widened to char-numeric?. Measured: changing
;; only that one left all three files green while the cell above kept
;; passing, which is what a label claiming to cover it buys you.
(let ((arabic-one (integer->char #x0661)))
  (check "the precision tag's own digit scan is ASCII too"
         (eq? #f (before-precision-tag (string-append "1|" (string arabic-one))))
         (before-precision-tag (string-append "1|" (string arabic-one))))
  (check "...and it still takes an ASCII tag"
         (equal? "1" (before-precision-tag "1|2"))
         (before-precision-tag "1|2")))

;; BOTH ENDS OF BOTH RANGES, AND THE CHARACTER JUST OUTSIDE EACH.
;; A Unicode digit kills the char-numeric? substitution but says nothing
;; about the range bounds themselves: widening #\0..#\9 by one character
;; in either direction admits / or : and no cell above would know. The
;; accepted endpoints and their neighbours are four cheap inputs, and
;; both scans -- the grammar's and the tag's -- have their own copy of
;; the range, so both get all four.
(for-each
  (lambda (p)
    (let ((t (car p)) (want (cdr p)))
      (check (string-append "grammar digit range: " (shown t)
                            (if want " is a numeral" " is not"))
             (eq? want (and (json-number-text? t) #t))
             (json-number-text? t))))
  '(("0" . #t) ("9" . #t)          ; the accepted endpoints
    ("/" . #f) (":" . #f)          ; the characters just below and above
    ("1/" . #f) ("1:" . #f)        ; and after a digit, where digits loops
    ("1.0/" . #f) ("1e0:" . #f)))  ; in the fraction and exponent scans

(for-each
  (lambda (p)
    (let ((t (car p)) (want (cdr p)))
      (check (string-append "tag digit range: " (shown t) " -> " (shown want))
             (equal? want (before-precision-tag t))
             (before-precision-tag t))))
  '(("1|0" . "1") ("1|9" . "1")    ; the accepted endpoints, as a whole tag
    ("1|/" . #f) ("1|:" . #f)      ; just outside, at the tag's first digit
    ("1|0/" . #f) ("1|9:" . #f)))  ; and after a tag digit, where tail loops

;; PROPAGATION: number-text must hand back what the repair gave it.
;; I had this written down as uncoverable without parameterising
;; number-text over the repair, and that was wrong -- both are exported,
;; so the two can simply be run side by side on the same input. The
;; mutation it catches is a normalisation: returning the repaired text
;; upcased, or with e as E, is still a legal numeral that still reads
;; back eqv?, so every other cell in both suites stays green while the
;; document says something the repair did not.
(for-each
  (lambda (v)
    (let ((direct (number-text v))
          (via (let ((t (number->string v)))
                 (if (json-number-text? t) t (repair-precision-tag t v)))))
      (check (string-append "number-text returns the repair's answer unchanged: "
                            (shown v))
             (equal? direct via)
             (list 'number-text direct 'repair via))))
  (list 5e-324 1e-320 -5e-324 1.0 7 (exact->inexact 1/3)))

;; THE VALUES ABOVE ARE THE ONES json.sc ACTUALLY SENDS, and that is
;; exactly why they are not enough. The cross-check compares number-text
;; against the repair on the same v -- a sound shape, but its
;; discriminating power lives entirely in which v it is given, and every
;; v above either takes the grammar fast path (where the repair is never
;; consulted, so the two sides are not really being compared) or is a
;; value the two already agree on.
;;
;; Non-finite flonums are the values where they can disagree. json.sc
;; writes those as null before number-text is ever reached, so nothing
;; that goes through json->string can get here; the call has to be
;; direct. Measured: falling back to "0" for a flonum the repair refused
;; --  (or (repair-precision-tag t v) (and (flonum? v) "0"))  -- left
;; both suites entirely green, while turning infinity and NaN from "we
;; cannot write this" into the number zero.
;;
;; The assertion is eq? #f and not "did not return a string": the mutant
;; returns a string too. What separates them is which answer, not
;; whether there was one.
(for-each
  (lambda (v)
    (check (string-append "number-text refuses a non-finite flonum: " (shown v))
           (eq? #f (number-text v))
           (number-text v)))
  (list +inf.0 -inf.0 +nan.0))

;; AND THE WRITER MUST EMIT THAT EXACT TEXT, not merely a legal numeral
;; that reads back to the same value. json.sc could normalise what
;; number-text hands it -- upcase the exponent, say -- and every writer
;; cell above would still pass, because they ask for legality and for an
;; eqv? readback and a repaired subnormal survives both. The propagation
;; cross-check catches that normalisation INSIDE number-text; this
;; catches it in json.sc, one layer further out. Same mutation, two
;; places it could live, and neither cell covers the other's.
;;
;; BE EXACT ABOUT WHICH CELLS WOULD MISS IT: the ones that judge a
;; REPAIRED spelling by legality and readback. An unconditional
;; normalisation -- upcasing every exponent, not just repaired ones --
;; is caught already, by the clean-output cells in json-writer-limits.sc
;; that compare ordinary
;; magnitudes character for character. What survives those is a
;; normalisation confined to the repair's output, which is exactly the
;; narrow shape this cell is for.
(for-each
  (lambda (v)
    (check (string-append "json->string emits number-text's exact text: " (shown v))
           (string=? (json->string v) (number-text v))
           (list 'writer (json->string v) 'number-text (number-text v))))
  (list 5e-324 1e-320 -5e-324 1.5 7 1e300))

;; The repair exists for one thing only: Chez may append a precision tag
;; to a numeral. It must take the numeral and nothing else. A repair that
;; cut at the first bar and stopped looking would turn "1|junk" into "1"
;; -- a silently different document, which is the failure this whole file
;; is here to make impossible.
(for-each
  (lambda (p)
    (check (string-append "precision tag cut: " (shown (car p)))
           (equal? (cdr p) (before-precision-tag (car p)))
           (before-precision-tag (car p))))
  '(("5e-324|1" . "5e-324")     ; the real shape, taken
    ("1|23" . "1")              ; multi-digit tag, taken
    ("1|" . #f)                 ; empty tag, refused
    ("1|garbage" . #f)          ; non-digit tag, refused
    ("1|2junk" . #f)            ; digits then junk: the trailing junk is seen
    ("1||2" . #f)               ; a bar inside the tag, refused
    ("1" . #f)))                ; nothing to cut is not a repair

;; ---- the third gate, once it had two inputs ----------------------------
;; The repair does not just check the shape of what it cuts: it reads the
;; shortened text back and requires the value to be eqv? to the one the
;; text was made from. That gate had NO CELL ANYWHERE while the only way
;; in was number-text, which formats its own text -- so a test could
;; supply a value but never a text that disagreed with it. Being able to
;; import the procedure was not the same as being able to feed it: it has
;; two inputs and only one of them was ours. Reachability is counted in
;; arguments, not in exported names.
;;
;; With text and value given separately, a disagreeing pair is an
;; ordinary input, and the pairs below are what a formatter that mislabels
;; its own output would produce.
(for-each
  (lambda (p)
    (let ((text (car p)) (v (cadr p)) (want (caddr p)))
      (check (string-append "repair " (shown text) " for " (shown v)
                            " -> " (shown want))
             (equal? want (repair-precision-tag text v))
             (repair-precision-tag text v))))
  (list
    ;; the tag says this text needs one extra bit to read back as the
    ;; value it came from -- but the value handed in is a different
    ;; number, so the shortened text would be a quiet substitution
    (list "1|23" 2 #f)
    (list "1|23" 1 "1")                        ; the same pair, agreeing
    (list "5e-324|1" 1.0 #f)                   ; real tag, wrong value
    (list "5e-324|1" 5e-324 "5e-324")          ; real tag, right value
    ;; EACH OF THE NEXT TWO IS REFUSED BY A DIFFERENT CONDITION, and
    ;; the conditions are a short-circuiting and, so an input does not
    ;; reach the ones after the one that refuses it: "1|garbage" stops
    ;; at the suffix check and never runs the grammar or the equality.
    ;; That is why one input cannot stand in for the others -- not
    ;; because each reaches only its own gate, but because the later
    ;; gates are never executed on it at all. "01|5" has a legal
    ;; suffix and a prefix that reads back as 1, so suffix and equality
    ;; both pass it and only the grammar refuses. "1|garbage" has a legal
    ;; prefix that reads back correctly, so only the suffix refuses.
    ;; Drop either input and the condition it isolates can be deleted
    ;; without a cell noticing.
    (list "01|5" 1 #f)                         ; grammar gate, alone
    (list "1|garbage" 1 #f)                    ; suffix gate, alone
    (list "01" 1 #f)                           ; no tag, still not a numeral
    (list "" 0 #f)                             ; nothing to repair
    ;; THE EQUALITY IS eqv?, NOT =, AND THAT IS THE WHOLE OF IT. The
    ;; shortened "1" reads back as the EXACT integer 1. Handed the
    ;; inexact 1.0, the repair must refuse: the two are numerically
    ;; equal, so a repair comparing with = accepts, hands back "1", and
    ;; the document now says an integer where the caller had a float.
    ;; Every other cell here survives that weakening -- measured -- and
    ;; so does every subnormal in json-writer-limits.sc, because their
    ;; repairs are eqv? already and therefore = as well.
    (list "1|23" 1.0 #f)                       ; same number, wrong exactness
    (list "0|1" 0.0 #f)                        ; the same trap at zero
    (list "0|1" -0.0 #f)                       ; and -0.0, which = calls 0
    (list "0|1" 0 "0")))                       ; the exact zero is the one taken

;; number-text is the whole gate end to end. It answers text or #f, and
;; #f is what json.sc turns into its own error. ITS DOMAIN IS NOT "every
;; real": 1/3 answers #f, and so do the non-finite reals -- the cells
;; just below pin that boundary deliberately. What these cells say is
;; narrower and is the thing worth pinning: for the values json.sc
;; actually hands it -- exact integers, and the finite inexact reals its
;; callers have already decided to write -- the answer is always text,
;; on both entry paths.
(for-each
  (lambda (v)
    (check (string-append "number-text yields JSON text for "
                          (shown v))
           (let ((t (number-text v)))
             (and (string? t) (rfc-number-machine? t)))
           (number-text v)))
  ;; 5e-324 and 4.9406564584124654e-324 are one double under two spellings;
  ;; the second subnormal here is a different bit pattern on purpose.
  (list 0 -0.0 1 -1 1.5 1e300 5e-324 1e-320
        (expt 2 200) (- (expt 2 200)) (exact->inexact 1/3)))

;; WHERE THE TWO LIBRARIES DIVIDE, pinned from both sides. An exact
;; ratio has no JSON text at all, and number-text says so rather than
;; inventing one -- it answers about text, and "1/3" is not a numeral.
;; It never meets one in production because json.sc converts exact
;; non-integers to inexact before asking. Both halves of that sentence
;; get a cell: drop the conversion in json.sc and the second one reds,
;; teach number-text to handle ratios and the first one does.
(check "number-text refuses an exact ratio rather than inventing text"
       (eq? #f (number-text 1/3)) (number-text 1/3))
;; The second half asks for more than "1/3 writes a legal numeral",
;; which is true of any ratio handling anyone might write. It asks that
;; the ratio and its flonum produce the SAME text. NOTE WHAT THAT DOES
;; AND DOES NOT SHOW: it rules out a formatter that writes ratios to a
;; different precision, but not one that formats ratios directly and
;; happens to land on the same decimal. The label says what is measured
;; rather than naming the mechanism, because the mechanism is not what
;; this cell can see -- json.sc is where the conversion is written, and
;; a cell here cannot watch it happen.
(check "...and 1/3 writes the same text its inexact conversion does"
       (let ((t (json->string 1/3)))
         (and (string? t)
              (rfc-number-machine? t)
              (string=? t (json->string (exact->inexact 1/3)))))
       (list (json->string 1/3) (json->string (exact->inexact 1/3))))

;; ---- the corpus: both judges, every short string ------------------------
;; Every string up to length five over the alphabet below is generated and
;; put to both judges. This is the cell a mutation to either grammar has to
;; survive, and it is why the second implementation was worth writing.
;;
;; THE ALPHABET IS PART OF THE ASSERTION, not a detail of the generator.
;; An earlier version listed nine characters and checked only that 7380
;; strings were visited -- a count that stays 7380 if you swap a character
;; for a duplicate, so the alphabet could lose | and the cell would not
;; notice. Every character below is here for a class the grammars branch
;; on, and each is named, because a character nobody can give a reason for
;; is one a later reader will drop.
;;
;; d and D are the ones worth explaining: JSON has no such exponent
;; marker, but Scheme does, and the thing being guarded against is this
;; Scheme's formatter changing under us. A validator that accepted 1d0
;; would be wrong in exactly the way that matters and no JSON-shaped
;; corpus would ever say so.
;;
;; Length five, not four, for a similar reason: four reaches every state
;; in the machine, but the shortest string that separates "one optional
;; exponent sign" from "any number of them" is 0e++0, which is five.
;; Reaching every state is not the same as reaching every way of leaving
;; one.
(define corpus-alphabet
  (string->list
    (string-append "0"      ; int's special case
                   "19"     ; digit1-9, both ends of the range
                   "-"      ; minus, legal only in two places
                   "+"      ; plus, legal only in an exponent
                   "."      ; the frac point
                   "eE"     ; JSON's exponent markers, both cases
                   "dD"     ; Scheme's, which JSON must refuse
                   "|")))   ; the precision tag's separator
(let* ((k (length corpus-alphabet))
       (expected (let sum ((len 0) (acc 0))          ; lengths 0..5
                   (if (> len 5)
                       acc
                       (sum (+ len 1) (+ acc (expt k len))))))
       (seen (make-hashtable string-hash string=?))
       (n 0) (agreed-yes 0) (disagree '()))
  (define (visit s)
    (set! n (+ n 1))
    (hashtable-set! seen s #t)
    (let ((a (and (json-number-text? s) #t))
          (b (rfc-number-machine? s))
          (c (rfc-number-descent? s)))
      ;; counted on agreement, so the label is literally true. Counting a
      ;; alone would call a string "accepted" on production's own word,
      ;; and this cell is the positive control for the one below it.
      (when (and a b c) (set! agreed-yes (+ agreed-yes 1)))
      (unless (and (eq? a b) (eq? b c))
        (when (< (length disagree) 12)
          (set! disagree
                (cons (list s 'production a 'machine b 'descent c)
                      disagree))))))
  ;; length 0 is in the corpus on purpose. Production handles it by
  ;; measuring the length first and guarding every index, which is
  ;; correct -- and precisely the kind of correctness that a corpus
  ;; starting at length 1 would never have put a judge opposite. The
  ;; guard is one character wide: relaxing fx> to fx>= makes the empty
  ;; string index position zero. The per-letter corpora reach it too --
  ;; each of the 52 starts at length zero -- so this is not the only
  ;; cell that runs it, and the earlier claim that it was is the kind of
  ;; exclusivity a file cannot check about itself.
  (let build ((prefix '()) (depth 0))
    (visit (list->string (reverse prefix)))
    (when (< depth 5)
      (for-each (lambda (c) (build (cons c prefix) (+ depth 1)))
                corpus-alphabet)))
  ;; The denominator is asserted before the verdict, and asserted as
  ;; DISTINCT strings against a count derived from the alphabet -- not
  ;; against a number typed in by hand, which is what let the alphabet
  ;; drift in the first place. A generator that silently built nothing,
  ;; or built the same string repeatedly, would otherwise read exactly
  ;; like a pass.
  (check "the corpus is every distinct string of length 0..5 over the alphabet"
         (and (= n expected) (= (hashtable-size seen) expected))
         (list 'visited n 'distinct (hashtable-size seen) 'expected expected))
  (check "...and the alphabet still carries every class it names"
         (let ((have (lambda (c) (and (memv c corpus-alphabet) #t))))
           (and (= k 11)
                (for-all have (string->list "019-+.eEdD|"))))
         (list->string corpus-alphabet))
  (check "the corpus contains numerals all three accept"
         (> agreed-yes 100) agreed-yes)
  (check "production and both judges agree on every string in the corpus"
         (null? disagree) (reverse disagree)))

;; ---- how the three gates became reachable ------------------------------
;; THIS SECTION USED TO LIST THREE CHECKS WITH NO CELL ANYWHERE. They now
;; have cells, and the reason is not that better cells were found: it is
;; that the repair was given its text and its value as SEPARATE
;; ARGUMENTS. BE EXACT ABOUT WHAT WAS UNREACHABLE: not the gates. On a
;; tagged numeral the old interface ran all three of them, and they all
;; passed. What no input could produce was their REFUSING -- the answer
;; each one gives when the text is wrong in its particular way. A gate
;; that only ever returns true is indistinguishable from one that always
;; returns true, and that is the shape a black-box suite cannot see.
;;
;; The reason is that the only texts a test could obtain were the ones
;; the formatter produces. Those are not JSON -- a precision tag is the
;; whole reason the repair exists -- but they are well formed in the
;; sense that matters here: their prefix is a numeral, their suffix is
;; digits, and the value reads back. So every gate saw exactly the input
;; it was built to wave through. No corpus of numbers, however wide,
;; reaches a refusal whose input the test cannot construct. Being able to import the procedure was never the
;; same as being able to feed it: reachability is counted in arguments,
;; not in exported names.
;;
;; THIS IS WRITTEN DOWN BECAUSE THE REPAIR NO LONGER LOOKS LIKE IT WAS
;; EVER BROKEN. A later reader sees a two-argument procedure whose FIRST
;; argument is always (number->string v) at its only call site, decides
;; the parameter is redundant, and folds it back -- restoring the exact
;; shape that made three conditions untestable.
;;
;; BE PRECISE ABOUT WHAT THAT EDIT COSTS, because an overstated warning
;; is one a reader can dismiss by trying it once. Dropping the parameter
;; outright is an arity error, and ignoring the supplied text reds the
;; cells above: the refactor announces itself. What does NOT announce
;; itself is the same refactor done thoroughly -- parameter folded back
;; AND these cells rewritten to match, or left calling a helper that
;; production no longer uses. Then everything is green and nothing here
;; tests a path production can take. The parameter is not a convenience;
;; it is the reachability, and a tidy-looking commit is what removes it.
;;
;; WHAT STILL HAS NO CELL, and cannot have one. rfc-number-machine? can
;; be redefined as a call to rfc-number-descent?. Every cell in this file
;; stays green -- measured, not reasoned -- because two implementations
;; that agree on every input are indistinguishable BY input, and every
;; instrument here is an input. The three-way comparison would silently
;; become a two-way one. Note that this is not the same risk the
;; comparison was built to catch: a judge drifting away from the grammar
;; still shows, because production disagrees. What disappears is the
;; independence itself -- the reason two agreeing judges were evidence
;; in the first place. It is visible only by reading
;; test/json-number-oracles.sc, and that is where it is written down.
;;
;; And note what the old entry was NOT saying. "No input reaches this
;; branch" was never "this branch is fine" -- no input reaches it TODAY,
;; under THIS formatter, and a formatter free to change under us is the
;; entire reason the branch exists.

(display "json-number-syntax: ")
(display (if (= failures 0) "all tests passed" "FAILURES"))
(newline)
(when (> failures 0) (exit 1))
