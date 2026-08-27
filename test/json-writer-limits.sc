#!chezscheme
;;; What json->string refuses, and how fast it says so.
;;;
;;; Three separate failures used to share one silent answer, and they
;;; need three separate cells because none of them stands in for the
;;; others:
;;;
;;;   THE SPINE. A list closed into a cycle with set-cdr! is not deep,
;;;   it is endless. The depth counter IS consulted -- it is checked on
;;;   every value entered, this one included -- but it never gets the
;;;   chance to grow, because nothing descends the spine: Chez's list?
;;;   terminates on such a value (R6RS requires it) and answers #f, so
;;;   the writer used to fall through to its catch-all instead. A limit
;;;   on depth cannot catch a value whose problem is length.
;;;
;;;   THE DEPTH. A vector holding itself IS deep: the writer recurses
;;;   until the process dies. Measured before the fix, on the real
;;;   parser, with the exit status read without a pipe in the way:
;;;   exit 124 at a 12s limit, RSS 5368 MB at t=3s and 9907 MB at t=8s.
;;;   That is not a contained crash; it is roughly a gigabyte a second
;;;   of allocation, and the machine's other processes pay for it.
;;;
;;;   THE CATCH-ALL. Values the writer does not recognise all produced
;;;   the string "null" and a successful return -- a document that
;;;   looks right and is not. The kinds below are the ones measured,
;;;   not a closed list: the branch is a catch-all and anything new
;;;   this Scheme grows falls into it. Each measured kind is a caller's
;;;   type error and none is a meaningful null, so the branch raises
;;;   now. (NaN and infinity are a different null: that one is
;;;   deliberate, and the cells below check it here rather than say
;;;   another file does -- a sentence about another file's coverage is
;;;   one this file cannot check.)
;;;
;;; THE WRITER'S DEPTH LIMIT IS NOT THE READER'S, TODAY. The reader's
;;; cap is a wire contract -- json.sc says what it is contracted with,
;;; and that is where the claim belongs, since a statement about
;;; another library goes stale in a file nobody opens when it changes.
;;; The writer's is a local resource guard. They are currently different
;;; numbers because the pipeline is read, wrap, write -- what the
;;; writer sees is the reader's maximum plus however many layers the
;;; application adds, and the library cannot know that constant, so
;;; equal numbers would let a client's legal document raise on the way
;;; out. The cost of them differing is the other side of the same
;;; trade: the writer can emit documents deeper than any reader here
;;; accepts. BOTH COSTS ARE REAL AND THE TRADE IS NOT SETTLED -- see
;;; json.sc, where the trade is set out. The cells below pin what is
;;; true now; they are not an argument that this is the right pair of
;;; numbers.

(import (chezscheme) (igropyr json)
        (only (igropyr test json-number-oracles) rfc-number-descent?))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))
(define (shown x) (let ((o (open-output-string))) (write x o) (get-output-string o)))

(define (result thunk)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'json-error))
             (list 'json-error (vector-ref e 1)))
            (#t (list 'other-raise e)))
    (list 'returned (thunk))))

(define (refused-as? r msg)
  (and (pair? r) (eq? (car r) 'json-error) (equal? (cadr r) msg)))

(define (wrote? r) (and (pair? r) (eq? (car r) 'returned) (string? (cadr r))))

;; The judge is rfc-number-descent? from test/json-number-oracles.sc,
;; NOT this library's own reader: that reader deliberately accepts
;; leading zeros, so asking it whether the writer's output is legal JSON
;; would let "01" pass in both directions at once -- the check and the
;; thing checked sharing one mistake.
;;
;; IT USED TO BE DEFINED HERE, and json-number-syntax.sc had a second,
;; differently written judge of the same grammar. THE TWO WERE NOT
;; EQUALLY EXPOSED, which is worth stating precisely rather than as a
;; symmetrical-sounding story: that one had a corpus putting it opposite
;; the production predicate, so its drift would have shown. THIS one had
;; only the table below and then judged whatever the formatter emitted
;; -- so it could have started accepting 1d0 with every suite green.
;; Exporting it is what lets json-number-syntax.sc put it to a corpus
;; too, which is the only thing that would notice.
;;
;; It still answers for itself here before anything is judged by it: a
;; shared judge is not a trusted one, and this suite should say so on
;; its own inputs rather than rely on the other file having asked.
(for-each
  (lambda (p)
    (check (string-append "the shared descent judge: " (car p)
                          (if (cdr p) " is a JSON number" " is not one"))
           (eq? (cdr p) (and (rfc-number-descent? (car p)) #t))))
  '(("0" . #t) ("-0" . #t) ("1.5" . #t) ("1e5" . #t) ("1E+5" . #t)
    ("5e-324" . #t) ("1e-308" . #t) ("1e-5" . #t)
    ("01" . #f) ("00" . #f) ("-00" . #f) ("01.5" . #f)
    ("1e" . #f) ("5." . #f) (".5" . #f) ("+1" . #f)
    ("5e-324|1" . #f) ("1|" . #f) ("1|junk" . #f)))

;; ---- the spine: a cyclic list ------------------------------------------
;; It is NOT deep, so the depth counter -- which does see it, on entry --
;; never rises. Before the fix this returned the string "null"; the cell
;; asserts a refusal, and the
;; nested forms assert that the refusal survives being reached through a
;; container rather than only at the top.
(define (cyclic-list)
  (let ((x (list 1 2))) (set-cdr! (cdr x) x) x))

(check "a cyclic list is refused, not written as null"
       (refused-as? (result (lambda () (json->string (cyclic-list))))
                    "not a JSON value: an improper or circular list, and an object with one member is ((\"k\" . v))")
       (result (lambda () (json->string (cyclic-list)))))
(check "...inside a vector too"
       (refused-as? (result (lambda () (json->string (vector (cyclic-list)))))
                    "not a JSON value: an improper or circular list, and an object with one member is ((\"k\" . v))"))
(check "...and as an object's value"
       (refused-as? (result (lambda ()
                              (json->string (list (cons "k" (cyclic-list))))))
                    "not a JSON value: an improper or circular list, and an object with one member is ((\"k\" . v))"))

;; ---- the depth: a self-referential vector ------------------------------
;; RUN IN A CHILD PROCESS, because the failure this guards against has
;; no voice of its own. Without the guard this input allocates about a
;; gigabyte a second until something outside the process stops it: in
;; this runner it would hang the whole suite, and a suite that never
;; reaches its summary reads as a broken machine, not as a failed
;; assertion. A child with a deadline converts that silence into a
;; result we can print. (The exit status is read from the child
;; directly -- never through a pipe, which substitutes its own.)
(define (self-vector-probe-source)
  (string-append
    "(import (chezscheme) (igropyr json))"
    "(let ((v (vector #f)))"
    "  (vector-set! v 0 v)"
    "  (display (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'json-error))"
    "                      (vector-ref e 1))"
    "                     (#t 'other-raise))"
    "             (begin (json->string v) 'returned)))"
    "  (newline))"))

;; UNIQUE PER PROCESS: two runs of this suite would otherwise write the
;; same file, and a collision produces a red that looks like a defect
;; and a green worth nothing. Same convention as gzip.sc.
(let* ((tag (format "~a-~a" (get-process-id) (real-time)))
       (src (format "/tmp/igropyr-json-selfvec-probe-~a.sc" tag))
       (out (format "/tmp/igropyr-json-selfvec-probe-~a.out" tag)))
  (call-with-output-file src
    (lambda (p) (put-string p (self-vector-probe-source)))
    'truncate)
  (let* ((cmd (string-append
                "CHEZSCHEMELIBEXTS='" (or (getenv "CHEZSCHEMELIBEXTS") "") "' "
                "timeout 10 scheme -q --libdirs . --script " src
                " > " out " 2>&1"))
         (status (system cmd))
         (text (guard (e (#t ""))
                 (call-with-input-file out get-string-all))))
    (check "a self-referential vector is refused, not chased"
           (and (= 0 status)
                ;; the child prints the message and a newline; compare
                ;; against the message's own length rather than a
                ;; number typed here, which is where this cell was
                ;; wrong once -- and the mistake hid, because the cell
                ;; was already red on the status while the guard was
                ;; missing, so the off-by-one only surfaced after the
                ;; fix landed and the cell went on failing for a
                ;; different reason under the same name
                (let ((expected "nesting too deep"))
                  (and (>= (string-length text) (string-length expected))
                       (string=? (substring text 0 (string-length expected))
                                 expected))))
           (list 'status status 'said text))
    ;; the timing IS the assertion here: exit 124 means the child hit
    ;; its deadline, which is what unbounded recursion looks like
    (check "...and the child finished rather than hitting its deadline"
           (not (= 124 (if (fixnum? status) (div status 256) -1)))
           status)))

;; ---- the catch-all: the kinds that were measured -----------------------
;; NOT A CLOSED LIST. The branch these fall into is a catch-all, so it
;; holds whatever the dispatch does not name -- today's Scheme, a later
;; Scheme, a record type someone defines tomorrow. What is enumerated
;; here is what was measured returning "null" before the change, and
;; the fxvector/flvector/box cells further down are more members of the
;; same open set, listed separately only because the argument for
;; refusing them is different.
(for-each
  (lambda (entry)
    (let ((name (car entry)) (make (cadr entry)) (msg (cddr entry)))
      (check (string-append "unrecognised value refused: " name)
             (refused-as? (result (lambda () (json->string (make))))
                          msg)
             (result (lambda () (json->string (make)))))))
  ;; each row now pins ITS OWN message: the refusal names a kind, and the
  ;; pair rows get the two-part sentence -- the true thing about the
  ;; value, and the shape that was probably meant. Neither half is a
  ;; guess, which is why both are given. The last row is the open-set
  ;; fallback, and it earned its keep: (void) is the input that proved
  ;; the fallback reachable after seventeen hand-picked kinds never
  ;; touched it.
  (list (cons* "improper pair (1 . 2)" (lambda () (cons 1 2))
               "not a JSON value: an improper or circular list, and an object with one member is ((\"k\" . v))")
        (cons* "improper pair (\"a\" . 1)" (lambda () (cons "a" 1))
               "not a JSON value: an improper or circular list, and an object with one member is ((\"k\" . v))")
        (cons* "alist with a non-null tail"
               (lambda () (cons (cons "k" 1) 7))
               "not a JSON value: an improper or circular list, and an object with one member is ((\"k\" . v))")
        (cons* "char" (lambda () #\a) "not a JSON value: a character")
        (cons* "bytevector" (lambda () (bytevector 1 2))
               "not a JSON value: a bytevector")
        (cons* "procedure" (lambda () car) "not a JSON value: a procedure")
        (cons* "hashtable" (lambda () (make-eq-hashtable))
               "not a JSON value: a hashtable")
        (cons* "eof object" (lambda () (eof-object))
               "not a JSON value: the eof object")
        (cons* "void" (lambda () (void))
               "not a JSON value: a value of some other type")))

;; ---- and the values that must still be written -------------------------
;; The should-be-green half, enumerated across what the dispatch DOES
;; name: a catch-all that raises is one over-eager predicate away from
;; refusing values this library documents as writable. ("Ordinary data"
;; stood here, and had no definition in the code -- the class this batch
;; kept getting wrong is the one named by an adjective nobody can look
;; up.)
(for-each
  (lambda (entry)
    (let ((name (car entry)) (make (cdr entry)))
      (check (string-append "still written: " name)
             (wrote? (result (lambda () (json->string (make)))))
             (result (lambda () (json->string (make)))))))
  (list (cons "empty list" (lambda () '()))
        (cons "alist" (lambda () (list (cons "k" "v"))))
        (cons "vector" (lambda () (vector 1 2)))
        (cons "empty vector" (lambda () (vector)))
        (cons "string" (lambda () "s"))
        (cons "exact integer" (lambda () 5))
        (cons "flonum" (lambda () 1.5))
        (cons "true" (lambda () #t))
        (cons "false" (lambda () #f))
        (cons "the null symbol" (lambda () 'null))
        (cons "nested containers"
              (lambda () (list (cons "a" (vector 1 (list (cons "b" 2)))))))))

;; ---- the two limits, and what each side of the trade costs -------------
;; They are different numbers today. A document at the reader's cap,
;; wrapped the way a handler wraps it, must still be writable -- that is
;; what equal numbers would cost. The other side of the same trade is
;; that the writer can emit documents no reader here accepts, which is
;; the gap recorded further down. Both costs are real and the trade is
;; not settled; these cells pin what is true now.
(define (nest-text k)
  (let loop ((k k) (s "1")) (if (zero? k) s (loop (- k 1) (string-append "[" s "]")))))

(check "a document at the reader's limit still writes after wrapping"
       (wrote? (result (lambda ()
                         (json->string
                          (list (cons "result" (string->json (nest-text 64)))))))))
(check "...and after two layers of wrapping"
       (wrote? (result (lambda ()
                         (json->string
                          (list (cons "d" (list (cons "result"
                                                      (string->json (nest-text 64)))))))))))

;; the writer's own limit does exist, well above the reader's. Depths
;; here and below are WRAPPING LAYERS -- the unit is defined in full
;; further down. Depth numbers in this file are in that unit unless a
;; cell says otherwise -- a file-wide claim is one nothing here checks.
(define (nest-value k)
  (let loop ((k k) (v 1)) (if (zero? k) v (loop (- k 1) (vector v)))))

(check "the writer's guard is far above the reader's cap (512 layers)"
       (wrote? (result (lambda () (json->string (nest-value 512))))))
(check "...but it is a guard, not an absence of one (2048 layers)"
       (refused-as? (result (lambda () (json->string (nest-value 2048))))
                    "nesting too deep")
       (result (lambda () (json->string (nest-value 2048)))))

;; ---- lists are refused as arrays, with the repair in the message -------
;; Narrowing arrays to vectors means every plain-list shape that used to
;; write as an array now refuses, and refuses with the fix spelled out.
;; The message is pinned exactly: an error that tells the reader what to
;; do is part of the contract, not decoration.
(for-each
  (lambda (entry)
    (let ((name (car entry)) (make (cdr entry)))
      (check (string-append "a list is refused as an array, with repair: " name)
             (refused-as? (result (lambda () (json->string (make))))
                          "a JSON array is a vector, not a list: use list->vector")
             (result (lambda () (json->string (make)))))))
  (list (cons "top-level plain list" (lambda () (list 1 2 3)))
        (cons "list of strings" (lambda () (list "a" "b")))
        (cons "as an object's value" (lambda () (list (cons "a" (list "b")))))
        (cons "nested inside a vector" (lambda () (vector (list 1))))
        ;; a nested list whose FIRST member is not a pair stays in the
        ;; array branch; all-pair members route to the object branch and
        ;; its key message -- that case is pinned separately below
        (cons "nested lists refuse at the first level" (lambda () (list 1 (list 2))))))

;; THE MISCLASSIFIABLE CORNER, pinned honestly. ((1)) -- every member a
;; pair, no string key -- cannot say whether its author meant a nested
;; array or an object; routing it to the key message swapped the false
;; lead's direction rather than removing it, so the message names BOTH
;; spellings and guesses neither. This cell pins that whole sentence.
(check "an all-pair list without string keys gets the key message, both repairs named"
       (refused-as? (result (lambda () (json->string '(((1))))))
                    "an object key must be a string, not (1): an object member is (\"k\" . v), a nested array is #(#(...))")
       (result (lambda () (json->string '(((1)))))))

;; ---- the boundary, on each descending path -----------------------------
;; The depth counter is incremented where the writer recurses: a vector's
;; elements and an object's values. (A third site -- a list's elements --
;; existed until arrays were narrowed to vectors; nested plain lists now
;; refuse at the first level and never reach the counter, so walking them
;; proves nothing about it.) A guard reaching only one of the two sites
;; would still pass a test that nests only vectors, so each is walked to
;; the limit and one past it, separately.
(define (nest-alist k)
  (let loop ((k k) (v 1)) (if (zero? k) v (loop (- k 1) (list (cons "k" v))))))

(for-each
  (lambda (entry)
    (let ((name (car entry)) (build (cdr entry)))
      (check (string-append name ": 1024 wrapping layers are written")
             (wrote? (result (lambda () (json->string (build 1024))))))
      (check (string-append name ": 1025 wrapping layers are refused")
             (refused-as? (result (lambda () (json->string (build 1025))))
                          "nesting too deep")
             (result (lambda () (json->string (build 1025)))))))
  (list (cons "vectors" nest-value)
        (cons "objects" nest-alist)))

;; STATE THE UNIT BEFORE QUOTING THE NUMBER. What is counted is
;; parent-to-child descents, the top-level value being 0, and the guard
;; runs on every value entered, leaves included -- 64 containers around
;; a number enters 65 values and passes at depth 64. So the same rule
;; reads two ways that differ by one, and two people measuring
;; correctly will think the other is wrong:
;;
;;   in WRAPPING LAYERS, the bottom makes no difference. 1024 vectors
;;   around a number and 1024 around an empty vector both write; 1025
;;   of either is refused, because whatever sits at the bottom is
;;   charged too. The reader behaves the same way at 64 and 65.
;;
;;   in TOTAL CONTAINERS, an empty one at the bottom is worth a level:
;;   counting the brackets in the output gives 1024 for the number
;;   case and 1025 for the empty-vector case, both accepted.
;;
;; The cells below use the WRAPPING count. Neither number is "the
;; maximum container nesting", and json.sc's own note states the same
;; rule in the container reading -- the two are the same fact under
;; different units, which is worth knowing before someone tries to
;; make one of them match the other.
;; BOTH SIDES OF THE BOUNDARY, because the claim is that an empty bottom
;; is charged exactly like any other value -- and only the refusing side
;; was checked here for a while. A rule that charged an empty container
;; one extra level would refuse at 1025 just the same, and pass the cell
;; that only asks for a refusal. It is the accepting side at 1024 that
;; says the extra level is not being charged.
(let ((nest-empty (lambda (k)
                    (let loop ((k k) (v (vector)))
                      (if (zero? k) v (loop (- k 1) (vector v)))))))
  (check "an empty container at the bottom does not buy a level"
         (refused-as? (result (lambda () (json->string (nest-empty 1025))))
                      "nesting too deep"))
  (check "...and one level less is written, so the bottom cost nothing"
         (wrote? (result (lambda () (json->string (nest-empty 1024)))))
         (result (lambda () (json->string (nest-empty 1024))))))
(let ((deep (lambda (k)
              (let loop ((k k) (s "[]"))
                (if (zero? k) s (loop (- k 1) (string-append "[" s "]")))))))
  (check "...and the reader charges the same way"
         (refused-as? (result (lambda () (string->json (deep 65))))
                      "nesting too deep"))
  (check "...on both sides of its own boundary too"
         (let ((r (result (lambda () (string->json (deep 64))))))
           (and (pair? r) (eq? (car r) 'returned)))
         (result (lambda () (string->json (deep 64))))))

;; OBJECTS ARE NESTED CONTAINERS TOO, and the cells above only ever used
;; arrays. "Both sides charge alike" was demonstrated for one of the two
;; container kinds and stated for both -- a rule that counted object
;; nesting differently would satisfy every cell above it.
(let ((deep-obj (lambda (k)
                  (let loop ((k k) (s "{}"))
                    (if (zero? k) s (loop (- k 1)
                                          (string-append "{\"a\":" s "}")))))))
  (check "the reader charges object nesting the same as array nesting"
         (refused-as? (result (lambda () (string->json (deep-obj 65))))
                      "nesting too deep"))
  (check "...and accepts one level less, as it does for arrays"
         (let ((r (result (lambda () (string->json (deep-obj 64))))))
           (and (pair? r) (eq? (car r) 'returned)))
         (result (lambda () (string->json (deep-obj 64))))))

;; WHAT EACH SCHEME SHAPE BECOMES, asserted as text. The claims: an
;; empty list writes as an object, an alist writes as an object, and
;; any other list REFUSES -- it stopped writing as an array when arrays
;; narrowed to vectors, and the refusal cells above own that. Until
;; these cells existed the only check was wrote?, which asks whether a
;; string came back; it cannot tell {} from [] and cannot tell an
;; object from an array. These claims belong to this
;; batch: the sentence that makes them was rewritten here, and a claim
;; is owed a cell by whoever writes it, not by whoever wrote the code.
(for-each
  (lambda (p)
    (let ((v (car p)) (want (cadr p)) (what (caddr p)))
      (check (string-append "classification: " what)
             (equal? want (json->string v))
             (json->string v))))
  (list (list '() "{}" "the empty list is an object, not an empty array")
        (list '(("a" . 1)) "{\"a\":1}" "a list of string-keyed pairs is an object")
        (list '(("a" . 1) ("b" . 2)) "{\"a\":1,\"b\":2}" "...with every pair present, comma-separated")
        ;; '(1 2 3) sat here as "any other list is an array" until arrays
        ;; were narrowed to vectors; its refusal is owned by the repair
        ;; cells above
        (list (vector 1 2 3) "[1,2,3]" "a vector is an array")
        ;; THE PAIR AND THE TWO-ELEMENT LIST ARE DIFFERENT DOCUMENTS, and
        ;; the difference is one dot. ("a" . #("b")) has the vector as
        ;; the value; ("a" #("b")) has a LIST containing the vector, so
        ;; the value is a one-element array whose element is the array.
        ;; This cell was first written with the dotted result expected
        ;; for the undotted input, and it went red -- the expectation was
        ;; wrong, not the writer. It is kept as a pair of cells because
        ;; that is exactly the confusion the shape admits.
        (list (list (cons "a" (vector "b"))) "{\"a\":[\"b\"]}"
              "a dotted pair whose value is a vector")
        (list '(("a" . "b")) "{\"a\":\"b\"}"
              "the dotted pair of two strings is a plain value")))

;; THE CONFUSABLE SHAPES NOW REFUSE INSTEAD OF WRITING SOMETHING ELSE.
;; ("a" #("b")) and ("a" "b") -- the undotted forms, one dot away from
;; the pairs above -- used to write one level deeper than their authors
;; expected; the author of THIS file wrote the wrong expectation for one
;; of them and a reviewer caught the other as a third preimage that was
;; really a second. Narrowing arrays to vectors turns both mistakes from
;; silently different documents into refusals with the repair named.
(for-each
  (lambda (v)
    (check (string-append "a one-dot slip now refuses instead of writing: "
                          (shown v))
           (refused-as? (result (lambda () (json->string v)))
                        "a JSON array is a vector, not a list: use list->vector")
           (result (lambda () (json->string v)))))
  (list '(("a" #("b"))) '(("a" "b"))))

;; ---- the collision family, and how it was closed -----------------------
;; This section once pinned an uncomfortable fact: several different
;; Scheme values produced the same document. Three preimages of
;; {"a":["b"]} at the worst -- string key with vector, two-element
;; list, symbol key with vector. Narrowing arrays to vectors refused
;; the list form; narrowing keys and values to strings refused the
;; symbol form. What remains is one accepted spelling per document, in
;; the shape domain. THAT IS NOT A CLAIM THAT THE WRITER IS INJECTIVE
;; -- the numeric domain still collapses (1/3 and .3333333333333333
;; write the same text; +inf.0 and +nan.0 both write null), and no cell
;; here enumerates the whole value domain. The cells below pin the two
;; closures and keep the one survivor honest.
;;
;; This is worth separating from the ambiguity on the reading side, which
;; is "one document, two readings". This is "several inputs, one
;; document" -- and it is the direction our writing about representation
;; has not covered, because that writing has always been about readers.
(let ((as-string (list (cons "a" (vector "b"))))
      (as-symbol (list (cons 'a (vector "b")))))
  (check "the string-key form writes, and survives the round trip"
         (and (string=? "{\"a\":[\"b\"]}" (json->string as-string))
              (equal? as-string (string->json (json->string as-string))))
         (json->string as-string))
  (check "...and the symbol-key form that once collided with it now refuses"
         (refused-as? (result (lambda () (json->string as-symbol)))
                      "an object key must be a string, not a: an object member is (\"k\" . v), a nested array is #(#(...))")
         (result (lambda () (json->string as-symbol)))))

;; ---- the classifier looks at every entry, not just the first ----------
;; Deciding "is this an alist" walks the whole list. Stopping after the
;; first entry is a one-token edit, and it needs a NEAR MISS to catch:
;; a list whose first entry has the alist shape and whose second does
;; not. Everything else in this file misses it -- (1 2 3) fails at the
;; first entry, and a two-entry alist has both entries legal, so it
;; shows that the OUTPUT loop keeps the second pair, which is a
;; different decision point entirely. One assertion was credited to
;; both; it owns only the second.
(check "a list whose first entry looks like a pair but whose second does not is not an object"
       ;; refused as a list-shaped array now, not as "not a JSON value":
       ;; failing the alist test routes it to the list branch, and that
       ;; branch refuses with the repair. The discriminating power is
       ;; unchanged -- a classifier that stopped at the first entry would
       ;; call this an object and write it.
       (refused-as? (result (lambda () (json->string '(("a" . 1) 2))))
                    "a JSON array is a vector, not a list: use list->vector")
       (result (lambda () (json->string '(("a" . 1) 2)))))

;; ---- symbols refuse, except the one that is a literal ------------------
;; Symbols used to write as strings, in both positions. Narrowing the
;; representation to string keys and string values closed that: the only
;; symbol with a meaning here is 'null, which is not "a symbol as a
;; value" -- it IS the representation of null. Both refusals carry their
;; repair, and both messages are pinned whole.
(check "a symbol value refuses, naming the symbol, told to quote it"
       (refused-as? (result (lambda () (json->string 'foo)))
                    "a JSON string is a string, not the symbol foo: quote it")
       (result (lambda () (json->string 'foo))))
(check "...a symbol key refuses, naming the key, both repairs shown"
       (refused-as? (result (lambda () (json->string '((sym . 1)))))
                    "an object key must be a string, not sym: an object member is (\"k\" . v), a nested array is #(#(...))")
       (result (lambda () (json->string '((sym . 1))))))
(check "...and 'null still writes as null"
       (equal? "null" (json->string 'null)) (json->string 'null))
(check "...including as a value inside an object"
       (equal? "{\"a\":null}" (json->string '(("a" . null))))
       (json->string '(("a" . null))))

;; ---- the reader's output, sampled against the shared vocabulary --------
;; The writer's shape vocabulary now equals the reader's output: the
;; extra spellings it once accepted -- plain-list arrays, symbol values,
;; symbol keys -- all refuse, and their refusal cells are above. These
;; three cells pin the reader's side of that equation on three sample
;; documents. They do not assert "never": a sample says what three
;; documents produced, and "never" is a claim about a reader this file
;; does not enumerate.
(let ((arr (string->json "[1,2]"))
      (obj (string->json "{\"a\":1}"))
      (str (string->json "\"s\"")))
  ;; the labels name what these three documents produced. The prose
  ;; above withdrew the word "never"; leaving it in the labels would put
  ;; the withdrawn claim back where it is most read.
  (check "reading [1,2] gives a vector, not a plain list"
         (and (vector? arr) (not (list? arr))) arr)
  (check "reading {\"a\":1} gives an alist with a string key"
         (and (list? obj) (pair? (car obj)) (string? (caar obj))) obj)
  (check "reading a JSON string gives a string, not a symbol"
         (and (string? str) (not (symbol? str))) str))

;; ---- the two limits, put together in one direction --------------------
;; Elsewhere this file proves the writer emits values deeper than 64 and
;; that the reader refuses text deeper than 64. Those are two separate
;; facts about two separate components; NEITHER hands the writer's actual
;; output to the reader. This does, because the cost of the two limits
;; differing is not hypothetical -- it is a document this library
;; produces and this library will not read.
(let* ((deep (let loop ((k 100) (v 1)) (if (zero? k) v (loop (- k 1) (vector v)))))
       (text (result (lambda () (json->string deep)))))
  ;; this one owns only "a string came back" -- deliberately, because
  ;; the cell below is what owns the gap, and crediting this one with
  ;; "and it was well-formed" would be crediting it with the next cell's
  ;; work
  (check "the writer returns a string for a value at depth 100"
         (wrote? text) text)
  (check "...and this library's own reader refuses to read it back"
         (refused-as? (result (lambda () (string->json (cadr text))))
                      "nesting too deep")
         (result (lambda () (string->json (cadr text))))))

;; ---- values this Scheme has and this writer's model does not ----------
;; fxvector, flvector and box are ordinary containers here and are not
;; in the model this library documents. Refusing them is a policy about
;; that model and nothing more: the writer's vocabulary is what the
;; documentation names, not everything this Scheme can hold, and a
;; caller who wants one serialised converts it, which costs a line on
;; the side that knows what it meant.
;;
;; One argument for refusing them was tried and dropped: that writing
;; them would produce documents another implementation could read but
;; never write. It needs a fact about that implementation, which this
;; file cannot check, and it does not reach its own conclusion anyway
;; -- a serialised fxvector is an ordinary array once it is text. It is
;; recorded here as tried and not relied on, so the next reader does
;; not spend the same afternoon on it.
(for-each
  (lambda (entry)
    (check (string-append "outside this writer's model, refused: " (car entry))
           (refused-as? (result (lambda () (json->string ((cadr entry)))))
                        (caddr entry))
           (result (lambda () (json->string ((cadr entry)))))))
  (list (list "fxvector" (lambda () (fxvector 1 2)) "not a JSON value: an fxvector")
        (list "flvector" (lambda () (flvector 1.0 2.0)) "not a JSON value: a flvector")
        (list "box" (lambda () (box 1)) "not a JSON value: a box")))

;; ---- one tag for every refusal, complex numbers included ---------------
;; A complex number used to leave as an assertion-violation while every
;; neighbour left as a json-error vector, so a guard written for this
;; library's errors missed exactly one kind of value. It stayed
;; invisible because the neighbours were not raising at all -- they were
;; writing "null" -- and it became visible only once they did.
(check "a complex number raises this library's error, not a condition"
       (refused-as? (result (lambda () (json->string (make-rectangular 1 2))))
                    "not a JSON value: a complex number")
       (result (lambda () (json->string (make-rectangular 1 2)))))
(check "...inside a vector too"
       (refused-as? (result (lambda ()
                              (json->string (vector (make-rectangular 1 2)))))
                    "not a JSON value: a complex number"))
(check "...and as an object's value"
       (refused-as? (result (lambda ()
                              (json->string
                               (list (cons "k" (make-rectangular 1 2))))))
                    "not a JSON value: a complex number"))
;; the reals stay written: refusing complex is about the representation
;; not being real?, not about exactness. What "written" means for an
;; inexact conversion is bounded on both sides, and both bounds are
;; measured here rather than left to the word "lossy": a ratnum too
;; large to convert becomes the same null every non-finite value gets,
;; and one too small underflows to zero.
(check "a ratnum still writes, as the flonum JSON can hold"
       (equal? '(returned "0.3333333333333333")
               (result (lambda () (json->string 1/3))))
       (result (lambda () (json->string 1/3))))
(check "an exact integer still writes exactly"
       (equal? '(returned "5") (result (lambda () (json->string 5)))))
(check "a ratnum that overflows the conversion joins the non-finite null"
       (equal? '(returned "null")
               (result (lambda () (json->string (/ (expt 10 4000) 3)))))
       (result (lambda () (json->string (/ (expt 10 4000) 3)))))
(check "...negative too"
       (equal? '(returned "null")
               (result (lambda () (json->string (- (/ (expt 10 4000) 3)))))))
(check "...and the null it writes is legal JSON, unlike the +inf.0 it wrote before"
       (equal? (list 'returned 'null)
               (result (lambda ()
                         (string->json
                          (json->string (/ (expt 10 4000) 3))))))
       (result (lambda ()
                 (string->json (json->string (/ (expt 10 4000) 3))))))
(check "a ratnum that underflows writes zero, losing the value quietly"
       (equal? '(returned "0.0")
               (result (lambda () (json->string (/ 1 (expt 10 400))))))
       (result (lambda () (json->string (/ 1 (expt 10 400))))))

;; ---- written wide, and refused on the way back in ----------------------
;; An exact integer is written at whatever width it has, and the reader
;; caps a numeral at max-number-chars, so this library writes integers
;; it will not read. That is the same shape as the depth gap above --
;; a reader-side limit with no writer-side counterpart -- and naming
;; the family matters more than either instance: we hunted the depth
;; one for three rounds while calling it "the depth gap", and the
;; number-width one sat beside it the whole time. Both are recorded,
;; neither is fixed here, and the cells state the boundary rather than
;; a promise.
(check "an integer just inside the reader's numeral cap comes back unchanged"
       (equal? (list 'returned (expt 10 511))
               (result (lambda ()
                         (string->json (json->string (expt 10 511))))))
       (result (lambda () (string->json (json->string (expt 10 511))))))
(check "one past it is written as a legal numeral of the right width"
       (let ((r (result (lambda () (json->string (expt 10 512))))))
         (and (wrote? r)
              (rfc-number-descent? (cadr r))
              (= 513 (string-length (cadr r)))))
       (result (lambda () (json->string (expt 10 512)))))
(check "...and then refused by our own reader"
       (refused-as?
        (result (lambda ()
                  (string->json (json->string (expt 10 512)))))
        "number too long"))
;; Two gaps of this shape are recorded here, and the set is not claimed
;; closed. The method that found them can be rerun: walk every jfail in
;; the reader and ask which of its limits the writer has no counterpart
;; for. Strings, measured, are not among them -- neither side caps
;; their length -- but "measured not to be" is a fact about the
;; members checked, not a count of the family.
;;
;; A THIRD GAP OF THE SAME SYMPTOM HAS A DIFFERENT MECHANISM: the
;; subnormal formatting below also produced text this library could not
;; read back, and it comes from the formatter rather than from any
;; reader limit -- which is why "gaps between writer and our own
;; reader" and "reader limits without a writer counterpart" must not be
;; counted as one set.
;; The value read back is compared, not discarded. An earlier version of
;; this cell ran the round trip and returned the string "OK", so it
;; asserted only that neither direction raised -- a writer that turned
;; the 5000 a's into any other legal JSON value passed it.
(check "long strings round-trip: not a member of this family"
       (let ((s (make-string 5000 #\a)))
         (equal? (list 'returned s)
                 (result (lambda () (string->json (json->string s)))))))

;; ---- the formatter's own spelling is not JSON's ------------------------
;; Chez writes a subnormal flonum with a precision annotation -- 5e-324
;; comes back as "5e-324|1" -- which is a legal Scheme numeral and not a
;; legal JSON number, so this library used to emit text it could not
;; read. Every value sampled on the subnormal side was spelled that way
;; and every one sampled above least-normal was not -- 2.2e-308 dirty,
;; 2.3e-308 clean -- but that is a sample, not an enumeration of the
;; formatter's behaviour, and nothing below leans on it being the whole
;; set. What the cells hold is the output, checked against the grammar,
;; whatever the formatter's reason for producing it.
;;
;; Both entries matter. The annotation is produced by the formatter, so
;; it is reached by any value that arrives at it as a subnormal double
;; -- a flonum written directly, and an exact ratnum that becomes one
;; through the conversion. A repair attached to the flonum branch would
;; miss the second; these cells hold it to the place the repair belongs,
;; which is after the number has been turned into text.
(for-each
  (lambda (entry)
    (let ((name (car entry)) (make (cdr entry)))
      (let* ((r (result (lambda () (json->string (make)))))
             (text (and (pair? r) (eq? (car r) 'returned) (cadr r))))
        ;; judged by the grammar above, not by the absence of one
        ;; character: "no pipe in it" would pass an output that is
        ;; wrong some other way, and it is the borrowed formatter we
        ;; are refusing to trust
        (check (string-append "subnormal writes a JSON numeral: " name)
               (and (string? text) (rfc-number-descent? text))
               r)
        (check (string-append "...and the value survives, bit for bit: " name)
               (and (string? text)
                    (let ((back (result (lambda () (string->json text)))))
                      (and (pair? back) (eq? (car back) 'returned)
                           (eqv? (cadr back) (exact->inexact (make))))))
               r))))
  (list (cons "least positive, as a flonum" (lambda () 5e-324))
        (cons "negative least positive" (lambda () -5e-324))
        (cons "1e-310" (lambda () 1e-310))
        (cons "just under least-normal" (lambda () 2.2e-308))
        ;; the exact ratnum entry: it is not a flonum until the
        ;; conversion, so a repair bound to the flonum branch skips it
        (cons "an exact ratnum that converts to a subnormal"
              (lambda () (/ 1 (expt 2 1074))))))

;; the clean side, so a repair cannot pass by mangling everything
(for-each
  (lambda (v)
    (check (string-append "normal magnitudes are untouched: "
                          (number->string v))
           (equal? (list 'returned (number->string v))
                   (result (lambda () (json->string v))))
           (result (lambda () (json->string v)))))
  (list 2.3e-308 1e-307 3.14159 1e308 1.7976931348623157e308 -0.0 0.1))

;; SEVEN CLEAN VALUES AND FIVE DIRTY ONES DO NOT SHOW A REPAIR WORKS.
;; They show it works on twelve values, and a repair hard-coded to those
;; twelve would pass every cell above. So the subnormals are swept by
;; bit pattern: every double whose payload is a power of two, plus a
;; spread of dense payloads, written and read back and required to be
;; eqv?. The sweep is what makes the cells above evidence rather than
;; examples.
(let ((bad-format 0) (bad-round 0) (checked 0) (not-subnormal 0)
      (seen (make-eqv-hashtable)))
  (define (sweep bits)
    (let* ((v (* bits 4.9406564584124654e-324))   ; payload x 2^-1074
           (r (result (lambda () (json->string v))))
           (text (and (pair? r) (eq? (car r) 'returned) (cadr r))))
      (set! checked (+ checked 1))
      (hashtable-set! seen bits #t)
      ;; The value is checked against the class this sweep claims to
      ;; cover. Without this, the cells below hold for any payloads at
      ;; all: multiplying every generated payload by three keeps the call
      ;; count at 122 and the distinct count at 120, carries the largest
      ;; values out of the subnormal range entirely, and leaves the
      ;; format and round-trip cells green -- they judge any finite
      ;; double perfectly well, subnormal or not, which is exactly why
      ;; they cannot notice that the sweep stopped covering subnormals. The count said the sweep ran; nothing
      ;; said what it ran over.
      (unless (and (not (= v 0.0))
                   (< (abs v) 2.2250738585072014e-308))   ; least normal
        (set! not-subnormal (+ not-subnormal 1)))
      (cond ((not (and (string? text) (rfc-number-descent? text)))
             (set! bad-format (+ bad-format 1)))
            (else
             (let ((back (result (lambda () (string->json text)))))
               (unless (and (pair? back) (eq? (car back) 'returned)
                            (eqv? (cadr back) v))
                 (set! bad-round (+ bad-round 1))))))))
  ;; every power-of-two payload in the subnormal range, both signs
  (do ((k 0 (+ k 1))) ((= k 52))
    (sweep (expt 2 k))
    (sweep (- (expt 2 k))))
  ;; dense payloads: all ones, alternating bits, and a scatter
  (for-each (lambda (b) (sweep b) (sweep (- b)))
            (list 1 3 7 (- (expt 2 52) 1) #x5555555555 #xAAAAAAAAAA
                  123456789 999999999999 (- (expt 2 51) 1)))
  (check "every value swept really is subnormal"
         (= 0 not-subnormal) (list 'not-subnormal not-subnormal 'of checked))
  (check "every subnormal bit pattern swept writes a JSON numeral"
         (= 0 bad-format) (list 'bad bad-format 'of checked))
  (check "...and comes back eqv? to what went out"
         (= 0 bad-round) (list 'bad bad-round 'of checked))
  ;; This cell asserts the sweep RAN, and nothing more. It is not a
  ;; coverage claim: 120 payloads out of 2^52 subnormals is not "most of
  ;; them", and the two cells above are the ones that judge behaviour.
  ;; What it catches is a sweep that silently stopped early -- a broken
  ;; loop bound leaves the two cells above green, because zero failures
  ;; out of zero runs is zero failures. The count is exact rather than a
  ;; floor for the same reason: a floor still passes at 101. It is 120
  ;; distinct payloads from 122 calls, because payload 1 is reached
  ;; twice -- as 2^0 in the loop and again in the dense list -- and the
  ;; duplicate is counted once here on purpose, so that this number
  ;; measures the enumeration and not the number of times it was walked.
  (check "...and the sweep ran over every payload it enumerates"
         (and (= checked 122) (= (hashtable-size seen) 120))
         (list 'calls checked 'distinct (hashtable-size seen))))

;; ---- non-finite values, checked here rather than delegated -------------
;; This file used to say another suite covered these. A statement about
;; another file's coverage is one this file cannot check, and the
;; writer's own entry points deserve their own cells: infinity and NaN
;; leave as null, which is a deliberate choice and the same answer a
;; ratnum that overflows the conversion now gets.
(for-each
  (lambda (entry)
    (check (string-append "non-finite writes null: " (car entry))
           (equal? '(returned "null")
                   (result (lambda () (json->string ((cdr entry))))))
           (result (lambda () (json->string ((cdr entry)))))))
  (list (cons "+inf.0" (lambda () +inf.0))
        (cons "-inf.0" (lambda () -inf.0))
        (cons "+nan.0" (lambda () +nan.0))))

;; ---- the third slot says whether there is a position at all ------------
;; The reader's errors carry an index into the text they were reading.
;; The writer has no text, so it carries #f -- not 0, which is a real
;; position and would dress "does not apply" up as "at the beginning".
;; The cost of getting this wrong is not visible from inside this file.
;; The distinction it guards is for the caller who wants to tell a
;; client's bad document (answer 4xx) from our own bad value (answer
;; 5xx): with a fixed 0 the two shapes are identical -- same tag, same
;; arity, same third slot -- leaving only the message text between
;; them, and message text is not something to dispatch on. Whether
;; anyone reads the slot today is a fact about other files, and a fact
;; about other files is not something this one should assert; what
;; these cells own is the shape itself.
(define (error-of thunk)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'json-error)) e)
            (#t #f))
    (thunk)
    #f))

(let ((reader-err (error-of (lambda () (string->json "@"))))
      (reader-err-late (error-of (lambda () (string->json "[1,"))))
      (writer-type (error-of (lambda () (json->string #\a))))
      (writer-depth (error-of (lambda ()
                                (json->string (nest-value 2048))))))
  (check "the reader reports a position, and it is an index"
         (and (vector? reader-err) (fixnum? (vector-ref reader-err 2)))
         reader-err)
  (check "...including one past the start"
         (and (vector? reader-err-late)
              (fixnum? (vector-ref reader-err-late 2))
              (> (vector-ref reader-err-late 2) 0))
         reader-err-late)
  (check "the writer reports #f: there is no text to point into"
         (and (vector? writer-type) (eq? #f (vector-ref writer-type 2)))
         writer-type)
  (check "...for the depth guard too"
         (and (vector? writer-depth) (eq? #f (vector-ref writer-depth 2)))
         writer-depth)
  ;; and the pair a future caller would have to separate
  ;; The pair a future caller would have to separate. The reader error
  ;; here must actually BE at offset 0 -- "@" is bad at the first
  ;; character -- because the confusion being ruled out is between a
  ;; writer's #f and a reader's 0, and a cell that only asked for
  ;; "different from #f" was satisfied by any fixnum at all, including
  ;; the -1 that would make the two indistinguishable in the other
  ;; direction.
  (check "the reader really is at offset 0 for a first-character fault"
         (and (vector? reader-err) (eqv? 0 (vector-ref reader-err 2)))
         reader-err)
  (check "a writer error is distinguishable from an error at offset 0"
         (and (vector? reader-err) (vector? writer-type)
              (eqv? 0 (vector-ref reader-err 2))
              (eq? #f (vector-ref writer-type 2)))
         (list reader-err writer-type))
  ;; the shape itself does not change: still three slots, still the tag
  (for-each
    (lambda (e)
      (check "the error keeps its shape: tag and three slots"
             (and (vector? e) (= 3 (vector-length e))
                  (eq? 'json-error (vector-ref e 0))
                  (string? (vector-ref e 1)))
             e))
    (list reader-err writer-type writer-depth)))

;; ---- the last link in the chain, reached through a shadow library ----
;; number-text answering #f is what json.sc turns into an internal error.
;; NOTHING ELSE IN EITHER SUITE EXERCISES THAT: the direct cells call
;; repair-precision-tag and never go through json.sc, and the formatter
;; has never once produced a spelling the repair could not fix, so the #f
;; branch is not reachable by any value. That left a mutation green in
;; all three files -- replacing json.sc's
;;
;;     (or (number-text v) (raise ...))     with     (or (number-text v) "0")
;;
;; which turns "this Scheme emitted something we cannot write" into a
;; document quietly containing 0.
;;
;; So what gets substituted here is not a value -- it is the LIBRARY. A
;; shadow (igropyr json-internal) whose number-text always answers #f is
;; put on the library path of a CHILD process, and the real json.sc is
;; loaded against it.
;;
;; ONE VALUE IS NOT ENOUGH, and an earlier version of this cell used only
;; the integer 7. json.sc reaches number-text from more than one place:
;; exact integers take one branch, finite inexact reals another, and an
;; exact non-integer is converted before it gets there. Mutating ONLY the
;; inexact branch to fall back on "0" left every file green, because the
;; probe never sent a value down it. Each call site is its own guard, and
;; a guard is only covered by an input that reaches IT.
;;
;; WHAT THESE CELLS DO NOT CHECK: the other half of the requirement, that
;; a SUCCESSFUL repair answer is passed through unchanged. The shadow
;; always answers #f, so it can only exercise the refusing half. The
;; passing half is held up elsewhere, and only partly here: the ordinary
;; write cells notice a numeral that became illegal or changed value,
;; but NOT a normalisation that stays legal and still reads back eqv? --
;; upcasing a repaired exponent, say. That one is caught in
;; json-number-syntax.sc, which compares json->string's text against
;; number-text's directly. Neither file forces both halves together in
;; one assertion, and that is worth knowing before reading these as
;; complete.
;;
;; Three things the shadow directory must get right, each learned the
;; hard way. The link to json.sc is ABSOLUTE -- not because the child
;; runs elsewhere, it inherits this directory, but because a relative
;; symlink target is resolved against the directory holding the LINK,
;; which is the shadow, not the repository. Not one .so goes in it, or a
;; stale object answers instead of the source. And nothing is ever
;; written into the real tree,
;; which is a working directory this suite shares. The directory name
;; carries the process id, because a fixed name makes concurrent runs
;; delete each other's shadow -- isolation has to come from the harness,
;; not from nobody happening to run at the same time.
;;
;; IF YOU ARE ABOUT TO DELETE THESE CELLS, read this first.
;; json-internal.sc states an end-to-end requirement. Word the handoff
;; correctly, because an earlier version here did not: json.sc never
;; sees the repair's answer. number-text does that handoff; json.sc
;; receives number-text's answer, emits it unchanged, and turns #f into
;; its internal error rather than into any text. THESE CELLS ARE THE ONLY CHECKER OF
;; ITS REFUSING HALF. Removing them does not return the requirement to
;; "documented but uncovered"; it leaves a written requirement with
;; nothing in the world that would notice it being broken. The mutation
;; they exist for was green in all three files before them.
;;
;; The self-check below is NOT what stops a false green -- an earlier
;; comment here claimed that and was wrong. If the shadow silently
;; stopped being loaded, the real number-text would answer "7", the
;; child would return normally, and the behaviour cells would fail
;; anyway, because they demand the error. What the self-check buys is
;; DIAGNOSIS AND INDEPENDENCE: it says which of the two things broke,
;; and it fails on its own evidence rather than on the same string the
;; behaviour cells read. Measured both ways: break the chain and only
;; the behaviour cells red; break the harness and the self-check reds
;; too, first.
(let* ((dir (format "/tmp/igropyr-json-shadow-~a-~a"
                    (get-process-id) (real-time)))
       (root (current-directory))
       (q (lambda (x) (string-append "'" x "'"))))   ; the tree may sit under a path with spaces
  (if (not (file-exists? (string-append root "/json.sc")))
      ;; standalone invocation from somewhere else: say why, do not pretend
      (fail "shadow-library cell: not run from the library root"
            (list 'current-directory root))
      (dynamic-wind
        (lambda ()
          (system (string-append "rm -rf " (q dir) " && mkdir -p " (q (string-append dir "/igropyr")))))
        (lambda ()
          (call-with-output-file (string-append dir "/igropyr/json-internal.sc")
            (lambda (p)
              (put-string p
                (string-append
                  "#!chezscheme\n"
                  "(library (igropyr json-internal)\n"
                  "  (export json-number-text? before-precision-tag\n"
                  "          repair-precision-tag number-text)\n"
                  "  (import (chezscheme))\n"
                  "  (define (json-number-text? t) #f)\n"
                  "  (define (before-precision-tag t) #f)\n"
                  "  (define (repair-precision-tag t v) #f)\n"
                  "  (define (number-text v) #f))\n")))
            'truncate)
          (system (string-append "ln -s " (q (string-append root "/json.sc"))
                                 " " (q (string-append dir "/igropyr/json.sc"))))
          (let* ((src (string-append dir "/probe.sc"))
                 (out (string-append dir "/probe.out")))
            (call-with-output-file src
              (lambda (p)
                (put-string p
                  (string-append
                    "(import (chezscheme) (igropyr json)"
                    "        (only (igropyr json-internal) number-text))"
                    ;; line 1 answers "is the shadow in front?" without
                    ;; asking json.sc anything
                    "(write (number-text 7)) (newline)"
                    ;; One line per ENTRY into the guarded path, which
                    ;; is not the same as one per call site: json.sc
                    ;; calls checked-number-text from two places, one
                    ;; for exact integers and one for finite inexact
                    ;; reals, and an exact ratio is converted and
                    ;; arrives through the second. BE HONEST ABOUT THE
                    ;; THIRD: the ratio is redundant here. The shadow
                    ;; refuses every argument alike, so it cannot see
                    ;; whether the conversion happened -- an unconverted
                    ;; 1/3 would produce the identical error. It stays
                    ;; as a cheap second witness for the same call site;
                    ;; the conversion itself is pinned elsewhere, by
                    ;; "1/3 writes the same text its inexact conversion
                    ;; does".
                    ;; the WHOLE vector is printed, not just the tag and
                    ;; message: this raise is its own (vector ...) in the
                    ;; source, so its shape -- three slots, position #f --
                    ;; is owned here or nowhere. The cells that pin the
                    ;; shape for the catch-all and the depth guard do not
                    ;; reach this construction site.
                    "(for-each (lambda (v)"
                    "  (write (guard (e ((and (vector? e)"
                    "                         (eq? (vector-ref e 0) 'json-error))"
                    "                    (list 'json-error (vector-length e)"
                    "                          (vector-ref e 1) (vector-ref e 2)))"
                    "                   (#t 'other-raise))"
                    "           (list 'returned (json->string v))))"
                    "  (newline))"
                    "  (list 7 7.0 1/3))")))
              'truncate)
            (let* ((cmd (string-append
                          "CHEZSCHEMELIBEXTS='" (or (getenv "CHEZSCHEMELIBEXTS") "") "' "
                          "timeout 30 " (or (getenv "SCHEME_BIN") "scheme")
                          " -q --libdirs " (q dir) " --script " (q src)
                          " > " (q out) " 2>&1"))
                   (status (system cmd))
                   (text (guard (e (#t "")) (call-with-input-file out get-string-all)))
                   (lines (let split ((i 0) (start 0) (acc '()))
                            (cond ((= i (string-length text))
                                   (reverse (if (> i start)
                                                (cons (substring text start i) acc)
                                                acc)))
                                  ((char=? (string-ref text i) #\newline)
                                   (split (+ i 1) (+ i 1)
                                          (cons (substring text start i) acc)))
                                  (else (split (+ i 1) start acc)))))
                   (line (lambda (k) (if (> (length lines) k) (list-ref lines k) "")))
                   ;; written with write, so the message keeps its quotes.
                   ;; Three slots and a #f position are part of the string
                   ;; compared, which is how the shape gets owned here.
                   (want (string-append "(json-error 3 \"internal: number "
                                        "formatted outside JSON syntax\" #f)")))
              (check "the shadow library, not the real one, is what the child loaded"
                     (and (= 0 status) (string=? (line 0) "#f"))
                     (list 'status status 'text text))
              (for-each
                (lambda (k what)
                  (check (string-append
                           "a numeral this Scheme cannot write raises, and writes"
                           " no document: " what)
                         (and (= 0 status) (string=? (line k) want))
                         (list 'status status 'line (line k))))
                '(1 2 3)
                ;; the third input's label says what it OWNS: it reaches
                ;; the same call site the flonum does. It does not own
                ;; "the conversion happened" -- the shadow refuses every
                ;; argument alike, so an unconverted ratio would print
                ;; the identical line. The conversion is pinned in
                ;; json-number-syntax.sc instead.
                ;; the third label names its ENTRY, not its route. That
                ;; the ratio converts and arrives by the second call site
                ;; is read from json.sc's source, not shown by this cell:
                ;; the shadow refuses every argument alike, so a ratio
                ;; wrongly routed to the FIRST call site would print the
                ;; identical line. Kept as a redundant witness for an
                ;; entry that is already witnessed, and owning nothing
                ;; else.
                '("exact integer"
                  "finite inexact"
                  "exact ratio, a second witness for the same entry")))
))
        (lambda ()
          (system (string-append "rm -rf " (q dir))))))) 

;; ---- complex numbers are not one kind here ----------------------------
;; json.sc decides what is writable with real?, and the choice matters
;; only for ONE member of this family: a complex whose imaginary part is
;; zero. real? asks about the representation and says no; real-valued?
;; asks about the value and says yes. For a complex with a non-zero
;; imaginary part both say no, so a cell built from 1+2i cannot tell the
;; two apart -- and every complex cell here was built from 1+2i.
;;
;; That was measured: swapping real? for real-valued? left all three
;; files green while turning 1.0+0.0i from this library's refusal into a
;; native condition raised deep inside nan?, which no caller of this
;; library is expecting to catch.
;;
;; THE INPUT THAT SEPARATES THEM WAS ALREADY WRITTEN DOWN -- in json.sc,
;; in the sentence explaining why real? was chosen. A comment that names
;; the case distinguishing two options has named a missing cell; the
;; thinking was done and only the feeding was missing. That is a cheaper
;; thing to look for than an unimagined input, and this file had it
;; sitting in view.
(for-each
  (lambda (p)
    (let ((v (car p)) (what (cdr p)))
      ;; THE SHAPE IS CHECKED HERE TOO, at this raise. The cells that pin
      ;; "three slots, position #f" for the catch-all and the depth guard
      ;; do not reach this one: a shape contract is owned per CONSTRUCTION
      ;; SITE, not per error kind, and this is its own (vector ...) in the
      ;; source. Measured: giving this raise a position of 0 instead of #f
      ;; left every other cell in both files green.
      (check (string-append "a complex is refused as this library's error: " what)
             (let ((e (error-of (lambda () (json->string v)))))
               (and (vector? e)
                    (= 3 (vector-length e))
                    (eq? 'json-error (vector-ref e 0))
                    (equal? "not a JSON value: a complex number" (vector-ref e 1))
                    (eq? #f (vector-ref e 2))))
             (error-of (lambda () (json->string v))))))
  (list (cons (make-rectangular 1.0 0.0) "zero imaginary part, the one real? and real-valued? disagree on")
        (cons (make-rectangular 1 2) "non-zero imaginary part, exact")
        (cons (make-rectangular 0.0 1.0) "zero real part")))


;; ---- the entry gate: string->json takes a string ----------------------
;; A non-string input used to surface as a native condition from deep
;; inside the parse -- raised where the caller's guard, written for
;; #(json-error ...), could not catch it. The gate names the kind (never
;; the value: kinds are bounded, values are not) and carries position 0.
(for-each
  (lambda (p)
    (let ((v (car p)) (want (cadr p)) (what (caddr p)))
      (check (string-append "entry gate: " what)
             (let ((e (error-of (lambda () (string->json v)))))
               (and (vector? e)
                    (eq? 'json-error (vector-ref e 0))
                    (equal? want (vector-ref e 1))
                    (eqv? 0 (vector-ref e 2))))
             (error-of (lambda () (string->json v))))))
  (list (list 42 "string->json takes a string, not a number" "a number")
        (list 'sym "string->json takes a string, not a symbol" "a symbol")
        (list (vector 1) "string->json takes a string, not a vector" "a vector")
        (list #t "string->json takes a string, not a boolean" "a boolean")
        (list '() "string->json takes a string, not the empty list" "the empty list")
        (list (bytevector 1) "string->json takes a string, not a bytevector"
              "a bytevector: the caller decodes, this library does not guess an encoding")))

;; ---- the third slot separates the sides, and now says so ---------------
;; Every reader-side error carries an integer position; every writer-side
;; error carries #f. That held by accident until the entry gate was
;; added; jfail's comment now states it as a rule, and these two cells
;; are the rule's owners -- one per side, including the newest member of
;; each side.
(check "reader-side errors, entry gate included, carry an integer position"
       (and (integer? (vector-ref (error-of (lambda () (string->json 42))) 2))
            (integer? (vector-ref (error-of (lambda () (string->json "@"))) 2))
            (integer? (vector-ref (error-of (lambda () (string->json "[1,"))) 2)))
       (list (error-of (lambda () (string->json 42)))
             (error-of (lambda () (string->json "[1,")))))
(check "writer-side errors, kind messages included, carry #f"
       (and (eq? #f (vector-ref (error-of (lambda () (json->string #\a))) 2))
            (eq? #f (vector-ref (error-of (lambda () (json->string 'oops))) 2))
            (eq? #f (vector-ref (error-of (lambda () (json->string (cons 1 2)))) 2)))
       (list (error-of (lambda () (json->string #\a)))))

(if (zero? failures)
    (begin (display "json-writer-limits: all tests passed\n") (exit 0))
    (begin (display (number->string failures))
           (display " failures\n") (exit 1)))
