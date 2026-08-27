#!chezscheme
;;; (igropyr json-internal) -- the JSON number grammar, on its own.
;;;
;;; NOT PART OF THE PUBLIC API OF (igropyr json). It is a separate file so
;;; that three guards can be seen to REFUSE. Text the grammar already
;;; accepts leaves at number-text's fast path and never reaches them.
;;; Text that does reach them meets a SHORT-CIRCUITED and, so how far it
;;; gets depends on the text: "1|garbage" stops at the first guard,
;;; "01|5" passes the first and stops at the second. What can be said of
;;; the measurements is narrower than "tagged text reaches all three":
;;; every measured output carrying a well-formed tag passed guard 1, its
;;; prefix passed guard 2, and it therefore reached and passed guard 3.
;;; none carried a leading zero, none a malformed precision tag, and every
;;; annotation measured was redundant. No output in the corpus we have
;;; measured reaches a refusal --
;;; a sampled claim, not a proof about all output -- so today each guard can
;;; be deleted with every black-box check still passing. A GUARD THAT ONLY
;;; EVER RETURNS TRUE AND A GUARD THAT ALWAYS RETURNS TRUE ARE THE SAME
;;; THING FROM OUTSIDE.
;;;
;;; THE INVARIANTS THAT KEEP THEM REACHABLE, since prose about "being
;;; careful" will not:
;;;   - production's number-text calls the SAME exported repair procedure the
;;;     tests call. Not a copy of it, not an inlined equivalent.
;;;     BUT NO BLACK-BOX BEHAVIOURAL TEST CAN OWN THIS ONE: a copy that
;;;     behaves identically is, by construction, invisible to any finite
;;;     set of inputs. A test CAN own it by other means -- reading the
;;;     source, walking the form, a lint -- so "no test can own it",
;;;     which an earlier draft said, was too wide and contradicted its
;;;     own next sentence. It is a structural rule owned by inspection
;;;     rather than by behaviour. Do not carry it in a coverage ledger as an
;;;     unowned behaviour; it will never be owned there, and an entry
;;;     that can never close makes the ledger look permanently in debt.
;;;   - the tests call it with a text and a value chosen INDEPENDENTLY.
;;;     Importability alone is not enough: a caller who can only supply a
;;;     value can never present a text that disagrees with it, and that
;;;     disagreement is the whole of the third guard.
;;;   - the three mutations are killed by ("01|5", 1), ("1|garbage", 1) and
;;;     ("1|23", 2) respectively -- one input each, and none of them catches
;;;     another's mutation.
;;;   - THE SUITE THAT MAKES THOSE CALLS IS COLLECTED BY THE DEFAULT RUNNER
;;;     and shown reached by the whole-suite banner. Existing, and being
;;;     runnable on its own, are not the same as being run: a suite the
;;;     runner stops collecting satisfies THE FIRST THREE invariants above
;;;     and reaches none of them. Nor is being collected sufficient -- a
;;;     suite can be collected, print that it was reached, and skip past
;;;     those assertions before making them. What has to hold is that ONE
;;;     DISCRIMINATING ASSERTION PER GUARD IS EXECUTED AND PASSES in a
;;;     default run. The number is deliberately written as "one per guard"
;;;     and not as a figure: the guards are below, in this file, and adding
;;;     one changes the requirement in the same edit that a reader is
;;;     already making. A figure here would be a count of cells in another
;;;     file, and nothing in that file's edit path passes through this
;;;     paragraph. This is not hypothetical -- a suite in this repository
;;;     spent its whole life outside the runner before anyone noticed.
;;;
;;; WHAT THOSE FOUR DO NOT COVER, and it is worth being exact about the
;;; boundary rather than lengthening the list. They are about one subject
;;; in four parts: the repair's refusals must be REACHABLE by a test (1,
;;; 2), each must be reachable SEPARATELY so the witnesses discriminate
;;; (3), and the reaching must actually HAPPEN in a default run (4). None
;;; of them says anything about what production does with the answer once
;;; it has it.
;;;
;;; So there is a SEPARATE, END-TO-END REQUIREMENT, and it spans two
;;; handoffs rather than one. The chain has three segments:
;;;   1. repair-precision-tag -- the three predicates, each separately
;;;      reachable. Checked by direct (text, value) cells.
;;;   2. number-text -- takes the grammar fast path, otherwise calls the
;;;      repair, and PASSES ITS ANSWER ALONG, string or #f, inventing
;;;      nothing.
;;;   3. json.sc -- writes the string, and turns #f into its internal
;;;      error rather than into any text at all. NOT ONE PLACE: segment 3
;;;      is entered from two call sites, one for exact integers and one
;;;      for the finite inexact reals, and a mutation can spoil either
;;;      one while the other stays correct. EACH CALL SITE IS ITS OWN
;;;      GUARD, and a guard is only covered by inputs that reach it -- so
;;;      the shadow cell drives an exact integer and a flonum, one per
;;;      call site. It also drives a ratio, but note what that third line
;;;      does and does not own: the shadow answers #f for anything, so a
;;;      ratio misrouted to the exact-integer site would raise the
;;;      identical error and the cell would not notice. THAT A RATIO
;;;      CONVERTS AND ARRIVES BY THE SECOND SITE IS READ OFF THIS SOURCE,
;;;      NOT PROVED BY THAT CELL -- it is a redundant witness, kept for
;;;      the entry and not for the route. Counting the procedure instead
;;;      of the paths into it is how one of these went uncovered.
;;; Note that json.sc never calls the repair; it only ever sees what
;;; number-text hands it. An earlier version of this paragraph said json.sc
;;; passes the repair's answer through, which put a handoff in the wrong
;;; place.
;;;
;;; Writing `(or (number-text v) "0")` in segment 3 satisfies every one of
;;; the four invariants -- the same helper is called, the tests still
;;; supply their own texts, the three witnesses still die where they died,
;;; the suite still runs -- and a formatter spelling we could not repair
;;; would leave as the number zero.
;;;
;;; SEGMENT 3'S TEST is the shadow cell in test/json-writer-limits.sc: a
;;; shadow (igropyr json-internal) whose number-text always answers #f,
;;; put in front of the real json.sc in a child process, asserting
;;; json->string raises. That cell and ITS OWN harness-failure control
;;; must both execute and pass in a default run -- the control is what
;;; keeps "the shadow is in front" from being answered by the thing under
;;; test. It says nothing about segment 2, because it replaces the whole
;;; of this library rather than watching it work.
;;;
;;; SEGMENT 2 IS NOT ONE THING, and saying it is untested was wrong. It
;;; has FIVE ways through -- that count is this file's control flow and
;;; is owned here. HOW MANY OF THEM ARE COVERED IS NOT: that is decided
;;; by cells in the JSON suites, which change without anyone opening this
;;; file, so the ways are listed below with the reason each is reachable
;;; and the coverage question is left to the suites to answer. Never
;;; restate a coverage count here. (An earlier line did say four and
;;; three: it listed four covered ways, added a fifth in the next
;;; paragraph, and never went back to the total. Adding a member below a
;;; total is how a total goes stale, and the repair is to stop keeping
;;; the total, not to correct it.) The ways that a cell can drive:
;;;   - the grammar fast path -- any ordinary value;
;;;   - the repair succeeding -- the subnormals;
;;;   - the repair refusing an out-of-domain value -- 1/3, which is not
;;;     a flonum and has no text here;
;;;   - the repair refusing a non-finite -- +inf.0, -inf.0, +nan.0, each
;;;     pinned to #f directly, since json.sc turns those into "null"
;;;     before this is reached and so cannot drive them.
;;; A number-text that swallowed #f unconditionally, or for ratios, or
;;; for non-finites, is caught by those.
;;;
;;; WHAT REMAINS UNCOVERED IS ONE MEMBER, not the segment: the repair
;;; refusing a FINITE FLONUM that json.sc would really hand over. No such
;;; flonum is known: every spelling MEASURED from this formatter is
;;; either a JSON number already or a repairable tag, which is a survey
;;; and not a proof that none exists. Nor does not knowing one mean none
;;; can be constructed -- it means nobody here has found how. STATED THAT
;;; WAY IT IS A FACT ABOUT US, WHICH NOTHING CAN TEST; the testable
;;; version is narrower and belongs in the ledger instead: no value in
;;; the corpora those suites enumerate produces such a spelling. Covering
;;; the real case needs either such an input or the formatter's text
;;; supplied as a parameter. That is written down rather than closed.
;;; Note how narrow the surviving mutants have become: `(or
;;; (repair-precision-tag t v) (and (flonum? v) "0"))` was green until
;;; the non-finite cells landed, which KILLED it. What happened next was
;;; not that cell narrowing anything -- it was a person writing a
;;; narrower mutant that the new cell does not reach. Cells eliminate
;;; mutants; the narrowing is done by whoever writes the next one, and
;;; saying the cells narrow them credits the tests with an activity that
;;; is entirely the reviewer's.
;;;
;;; DELETING THIS FILE CANNOT FAIL SILENTLY -- an import that does not
;;; resolve is an immediate non-zero exit, for every importer there is;
;;; how many there are is a question for the repository, not for this
;;; line -- which is not the same as safe. The dangerous edit is quieter: keep the
;;; helper for the tests, and give production its own inlined copy. The tests
;;; then exercise dead code and NOTHING GOES RED.
;;;
;;; Names and behaviour may change in any release. APPLICATION CODE MUST NOT
;;; IMPORT IT -- the test suite must, and that is the whole point, so "do not
;;; import it" would be false as written.
;;;
;;; It answers about text: no ports, no error shapes, and WITHIN ITS INPUT
;;; DOMAIN it does not raise -- a caller wanting an exception builds one from
;;; #f. Handed something outside that domain (a non-string to the predicates,
;;; a non-number to number-text) it does whatever Chez does, which is to
;;; raise; these are not total functions and do not pretend to be.

(library (igropyr json-internal)
  (export json-number-text? before-precision-tag
          repair-precision-tag number-text)
  (import (chezscheme))

  ;; JSON's number grammar, strictly: int is 0 | [1-9]digit*, so "01"
  ;; fails here. A reader for the same format may well be wider -- widths
  ;; get conceded for compatibility and are recorded where such decisions
  ;; are recorded -- and if one is, that is not an inconsistency to be
  ;; tidied away by loosening this. A writer has no such excuse, because
  ;; everything it emits it chose to emit. Narrow out, wide in.
  ;;
  ;; It exists because a writer must not trust the text a BORROWED
  ;; FORMATTER hands back. number->string produces Scheme's external
  ;; representation, whose grammar overlaps JSON's nearly everywhere --
  ;; which is what made it usable for years and what made the gap
  ;; invisible when it finally appeared. One pass, no allocation, run on
  ;; every candidate numeric text handed to it rather than on the
  ;; spellings already known about: one never seen is caught by the same
  ;; test as one that has been.
  (define (json-number-text? t)
    (let* ((n (string-length t))
           (digit-at? (lambda (k)
                        (and (fx< k n) (char<=? #\0 (string-ref t k) #\9))))
           (digits (lambda (k)
                     (let loop ((k k) (any #f))
                       (if (digit-at? k) (loop (fx+ k 1) #t) (and any k))))))
      (let* ((k (if (and (fx> n 0) (char=? (string-ref t 0) #\-)) 1 0))
             (k (and (digit-at? k)
                     (if (char=? (string-ref t k) #\0) (fx+ k 1) (digits k)))))
        (and k
             (let ((k (if (and (fx< k n) (char=? (string-ref t k) #\.))
                          (digits (fx+ k 1))
                          k)))
               (and k
                    (let ((k (if (and (fx< k n)
                                      (memv (string-ref t k) '(#\e #\E)))
                                 (let ((k (fx+ k 1)))
                                   (digits (if (and (fx< k n)
                                                    (memv (string-ref t k)
                                                          '(#\+ #\-)))
                                               (fx+ k 1) k)))
                                 k)))
                      (and k (fx= k n)))))))))

  ;; The text after a | must be a run of digits reaching the end, or this
  ;; is not the annotation and no prefix is offered.
  (define (before-precision-tag t)
    (let ((n (string-length t)))
      (let loop ((i 0))
        (cond
          ((fx= i n) #f)
          ((char=? (string-ref t i) #\|)
           (and (fx< (fx+ i 1) n)
                (let tail ((j (fx+ i 1)))
                  (cond ((fx= j n) #t)
                        ((char<=? #\0 (string-ref t j) #\9) (tail (fx+ j 1)))
                        (else #f)))
                (substring t 0 i)))
          (else (loop (fx+ i 1)))))))

  ;; Chez marks a flonum needing extra precision to read back exactly by
  ;; appending |<bits>, which is Scheme syntax and not JSON: 5e-324
  ;; arrives as "5e-324|1". Every subnormal sampled was spelled that way,
  ;; and so was an
  ;; exact ratnum small enough to land there after conversion -- sampled,
  ;; not enumerated, which is why nothing here depends on that being the
  ;; whole set.
  ;;
  ;; THE SHORTENED CANDIDATE IS CHECKED AGAINST THREE STATED PREDICATES,
  ;; in order and no further than the first that fails -- which is a
  ;; smaller claim than "the repair proves itself", and the smaller claim
  ;; is the true one. The three are listed
  ;; below with what they do and do not establish. What is worth saying
  ;; here is only that they are checked on THE NUMBER IN HAND rather than
  ;; inferred from a sample: offline measurement said the annotation is
  ;; redundant across the values it covered; these predicates say
  ;; something about this call. Anything else foreign is not guessed at
  ;; -- an earlier version cut at the first | and turned "1|garbage" into
  ;; "1" without a word.
  ;;
  ;; NOT A VERIFIER OF "t denotes v", and the name is chosen to avoid
  ;; claiming that. Given a text that is NOT already a JSON number, it
  ;; answers with a shortened text when, and only when, ALL THREE of
  ;; these hold -- and it promises nothing beyond them. They are tested
  ;; in this order and the first failure returns, so a refused input has
  ;; not been put to the later ones:
  ;;   1. after the FIRST |, at least one ASCII digit, and digits all the
  ;;      way to the end of the string;
  ;;   2. the part before that | is a JSON number by the grammar above;
  ;;   3. Chez reading THAT PREFIX at radix 10 gives a value eqv? to the
  ;;      value passed in.
  ;; The three witnesses each die at a different one, which is what makes
  ;; them witnesses rather than three spellings of one test:
  ;; "1|garbage" at 1, "01|5" at 2 (it passes 1), ("1|23", 2) at 3 (it
  ;; passes 1 and 2).
  ;;
  ;; eqv? IN 3 IS LOAD-BEARING, AND WEAKENING IT IS SILENT UNLESS SOMETHING
  ;; FEEDS IT A MISMATCHED PAIR. Change it to = and ("1|23", 1.0) answers
  ;; "1": the prefix reads back as the exact integer 1, numerically equal
  ;; to the flonum handed in and not the same value, so a float leaves as
  ;; an integer. Any input that exercises only pairs where the two
  ;; predicates agree survives that change -- which was the whole corpus
  ;; until cells contrasting exactness were added for exactly this. They
  ;; are what makes the change loud; without them the sentence above would
  ;; still be true.
  ;;
  ;; NOTE WHAT 3 IS NOT. It does not compare the original text's readback
  ;; with the prefix's -- the original is never read. Those two can
  ;; differ and the answer still be yes: (string->number "1|23") is the
  ;; flonum 1.0 and (string->number "1") is the exact 1, not eqv?, yet
  ;; ("1|23", 1) returns "1", because 1 is what was passed in. That
  ;; counterexample is a cell in the tests already -- as guard 3's POSITIVE
  ;; control, the pair that must succeed -- which is how this went
  ;; unnoticed: an input with a role stops being read for its other
  ;; properties. (Its role is not what an earlier draft said either. What
  ;; proves guard 3 has teeth is ("1|23", 2) and the exactness pairs; this
  ;; one proves the guard lets the right thing through.)
  ;;
  ;; Nor does 3 say the decimal denotes v mathematically:
  ;; ("1e9999|23", +inf.0) yields "1e9999", legal JSON whose value is not
  ;; an infinity, because Chez overflows reading it back and the two
  ;; agree. For the one caller that matters -- a text this library's
  ;; formatter just produced from v -- that is the property wanted. All
  ;; of this is spelled out because the procedure is exported, and an
  ;; exported name gets read as a promise.
  ;;
  ;; The value parameter is what makes guard 3 testable at all. Fed only
  ;; a number, no measured formatter output provoked its refusal -- every
  ;; annotation sampled was redundant, so deleting the eqv? test changed
  ;; nothing observable and no black-box check went red. That is a
  ;; statement about the outputs measured, not about every output the
  ;; formatter can produce; an unsampled annotation whose cut is not eqv?
  ;; would provoke it from a single-value call. Given a text and a value
  ;; chosen independently -- ("1|23", 2) -- it refuses today, and a test
  ;; can say so today.
  ;; Returns the text, or #f.
  (define (repair-precision-tag t v)
    (let ((cut (before-precision-tag t)))
      (and cut
           (json-number-text? cut)
           (eqv? (string->number cut 10) v)
           cut)))

  ;; DOMAIN, which is narrower than "a number": an exact integer, or a
  ;; finite inexact real that the caller's own policy has already decided
  ;; to write. An exact non-integer gives #f here, because the decision
  ;; to round it -- to write 1/3 as some finite decimal, and which one --
  ;; belongs to the caller and is taken before this is reached; a caller
  ;; wanting a ratnum written converts it first and hands over the
  ;; flonum. NaN, infinity and complex likewise give #f rather than a
  ;; policy: null, or a refusal, is the caller's word, not this file's.
  (define (number-text v)
    (let ((t (number->string v)))
      (if (json-number-text? t) t (repair-precision-tag t v))))
)
