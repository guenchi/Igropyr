#!chezscheme
;;; What json->string refuses, and how fast it says so.
;;;
;;; Three separate failures used to share one silent answer, and they
;;; need three separate cells because none of them stands in for the
;;; others:
;;;
;;;   THE SPINE. A list closed into a cycle with set-cdr! is not deep,
;;;   it is endless -- a depth counter is never consulted on that path.
;;;   Chez's list? terminates on such a value (R6RS requires it) and
;;;   answers #f, so the writer used to fall through to its catch-all.
;;;
;;;   THE DEPTH. A vector holding itself IS deep: the writer recurses
;;;   until the process dies. Measured before the fix, on the real
;;;   parser, with the exit status read without a pipe in the way:
;;;   exit 124 at a 12s limit, RSS 5368 MB at t=3s and 9907 MB at t=8s.
;;;   That is not a contained crash; it is roughly a gigabyte a second
;;;   of allocation, and the machine's other processes pay for it.
;;;
;;;   THE CATCH-ALL. Nine kinds of value the writer does not recognise
;;;   all produced the string "null" and a successful return -- a
;;;   document that looks right and is not. Every one of them is a
;;;   caller's type error, and none of them is a meaningful null, so
;;;   the else branch raises now. (NaN and infinity are a different
;;;   null: that one is deliberate, matches JSON.stringify, and is
;;;   pinned in test/json-numbers.sc. Do not merge the two.)
;;;
;;; THE WRITER'S DEPTH LIMIT IS NOT THE READER'S. The reader's cap is a
;;; wire contract, matched word for word with the browser-side twin;
;;; the writer's is a local resource guard. They cannot be the same
;;; number, because the pipeline is read, wrap, write: what the writer
;;; sees is the reader's maximum PLUS however many layers the
;;; application adds, and the library cannot know that constant. Set
;;; them equal and a client's perfectly legal document, wrapped once by
;;; the handler, raises on the way out -- turning a bad response into
;;; an externally triggerable error. Hence a different number and a
;;; different name; only the message is shared.

(import (chezscheme) (igropyr json))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))

(define (result thunk)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'json-error))
             (list 'json-error (vector-ref e 1)))
            (#t (list 'other-raise e)))
    (list 'returned (thunk))))

(define (refused-as? r msg)
  (and (pair? r) (eq? (car r) 'json-error) (equal? (cadr r) msg)))

(define (wrote? r) (and (pair? r) (eq? (car r) 'returned) (string? (cadr r))))

;; ---- the spine: a cyclic list ------------------------------------------
;; It is NOT deep, so a depth counter never sees it. Before the fix this
;; returned the string "null"; the cell asserts a refusal, and the
;; nested forms assert that the refusal survives being reached through a
;; container rather than only at the top.
(define (cyclic-list)
  (let ((x (list 1 2))) (set-cdr! (cdr x) x) x))

(check "a cyclic list is refused, not written as null"
       (refused-as? (result (lambda () (json->string (cyclic-list))))
                    "not a JSON value")
       (result (lambda () (json->string (cyclic-list)))))
(check "...inside a vector too"
       (refused-as? (result (lambda () (json->string (vector (cyclic-list)))))
                    "not a JSON value"))
(check "...and as an object's value"
       (refused-as? (result (lambda ()
                              (json->string (list (cons "k" (cyclic-list))))))
                    "not a JSON value"))

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

(let* ((src "/tmp/igropyr-json-selfvec-probe.sc")
       (out "/tmp/igropyr-json-selfvec-probe.out"))
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
                (>= (string-length text) 17)
                (string=? (substring text 0 17) "nesting too deep"))
           (list 'status status 'said text))
    ;; the timing IS the assertion here: exit 124 means the child hit
    ;; its deadline, which is what unbounded recursion looks like
    (check "...and the child finished rather than hitting its deadline"
           (not (= 124 (if (fixnum? status) (div status 256) -1)))
           status)))

;; ---- the catch-all: nine unrecognised kinds ----------------------------
;; Enumerated, not sampled: these are every kind the dispatch does not
;; name. Each one used to be written as "null".
(for-each
  (lambda (entry)
    (let ((name (car entry)) (make (cdr entry)))
      (check (string-append "unrecognised value refused: " name)
             (refused-as? (result (lambda () (json->string (make))))
                          "not a JSON value")
             (result (lambda () (json->string (make)))))))
  (list (cons "improper pair (1 . 2)" (lambda () (cons 1 2)))
        (cons "improper pair (\"a\" . 1)" (lambda () (cons "a" 1)))
        (cons "alist with a non-null tail"
              (lambda () (cons (cons "k" 1) 7)))
        (cons "char" (lambda () #\a))
        (cons "bytevector" (lambda () (bytevector 1 2)))
        (cons "procedure" (lambda () car))
        (cons "hashtable" (lambda () (make-eq-hashtable)))
        (cons "eof object" (lambda () (eof-object)))
        (cons "void" (lambda () (void)))))

;; ---- and the values that must still be written -------------------------
;; The should-be-green half, enumerated across what the dispatch DOES
;; name: a catch-all that raises is one over-eager predicate away from
;; refusing ordinary data.
(for-each
  (lambda (entry)
    (let ((name (car entry)) (make (cdr entry)))
      (check (string-append "still written: " name)
             (wrote? (result (lambda () (json->string (make)))))
             (result (lambda () (json->string (make)))))))
  (list (cons "empty list" (lambda () '()))
        (cons "alist" (lambda () (list (cons "k" "v"))))
        (cons "alist with symbol keys" (lambda () (list (cons 'k 1))))
        (cons "plain list" (lambda () (list 1 2 3)))
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

;; ---- the two limits are not the same number ----------------------------
;; The reader's cap is a wire contract; the writer's is a local guard.
;; A document at the reader's limit, wrapped the way a handler wraps it,
;; must still be writable -- that is the whole reason the numbers differ.
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

;; the writer's own limit does exist, well above the reader's
(define (nest-value k)
  (let loop ((k k) (v 1)) (if (zero? k) v (loop (- k 1) (vector v)))))

(check "the writer's guard is far above the reader's cap"
       (wrote? (result (lambda () (json->string (nest-value 512))))))
(check "...but it is a guard, not an absence of one"
       (refused-as? (result (lambda () (json->string (nest-value 2048))))
                    "nesting too deep")
       (result (lambda () (json->string (nest-value 2048)))))

(if (zero? failures)
    (begin (display "json-writer-limits: all tests passed\n") (exit 0))
    (begin (display (number->string failures))
           (display " failures\n") (exit 1)))
