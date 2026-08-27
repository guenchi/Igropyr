#!chezscheme
;;; The six verbs, both layers: which cells own which rulings.
;;;
;;; Every cell names the decision it discriminates. The rulings live in
;;; the export comment of json.sc; the cells here are their tests --
;;; where a ruling has no owner yet, that is a gap in THIS file, and a
;;; review that finds one should say so rather than assume coverage.
;;; Vocabulary, stated precisely because a looser version of each was
;;; caught: reads answer #f for "nothing there"; writes answer #f for
;;; FAILURE -- the operation not completing -- while a selector that
;;; matches nothing is success with zero work and returns the
;;; container; the trailing absence-thunk belongs to json-ref alone;
;;; macros take literal-length paths whose ELEMENTS may still be
;;; runtime values, and the starred layer is a procedure, so it can be
;;; applied.

(import (chezscheme) (igropyr json))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))

(define doc '(("a" . (("b" . #(10 20)) ("c" . #f))) ("z" . 1)))

;; ---- ref: one key, one layer; the thunk is the missing-case voice ------
(check "ref* finds"            (equal? '(("b" . #(10 20)) ("c" . #f))
                                       (json-ref* doc "a")))
(check "ref* missing is #f"    (eq? #f (json-ref* doc "nope")))
(check "ref* found #f is #f"   (eq? #f (json-ref* (json-ref* doc "a") "c")))
;; the thunk separates those two: value #f returns #f, absence calls it
(check "ref* thunk fires on absence only"
       (and (eq? 'gone (json-ref* doc "nope" (lambda () 'gone)))
            (eq? #f    (json-ref* (json-ref* doc "a") "c" (lambda () 'gone))))
       (list (json-ref* doc "nope" (lambda () 'gone))
             (json-ref* (json-ref* doc "a") "c" (lambda () 'gone))))
(check "ref* on a vector takes an index"
       (= 20 (json-ref* (vector 10 20) 1)))
(check "ref* out-of-range index is #f, not a native condition"
       (eq? #f (json-ref* (vector 10 20) 5)))
(check "ref* inexact index is #f, not a native condition"
       (eq? #f (json-ref* (vector 10 20) 1.0)))
;; the macro walks a literal path and the last-argument thunk still works
(check "ref macro walks a path"      (= 20 (json-ref doc "a" "b" 1)))
(check "ref macro broken path is #f" (eq? #f (json-ref doc "a" "x" 1)))
(check "ref macro thunk on a path"
       (eq? 'gone (json-ref doc "a" "x" (lambda () 'gone))))

;; ---- writes: a container on success, #f on nothing-happened ------------
;; #f is not in the container domain, so one if separates the outcomes.
(check "set* sets a value"
       (equal? '(("z" . 9)) (json-set* '(("z" . 1)) "z" 9)))
(check "set* takes a transform of the old value"
       (equal? '(("z" . 2)) (json-set* '(("z" . 1)) "z" (lambda (o) (+ o 1)))))
(check "set* missing key is #f"
       (eq? #f (json-set* '(("z" . 1)) "nope" 9)))
(check "set macro rebuilds the spine along a literal path"
       (equal? '(("a" . (("b" . #(10 99)) ("c" . #f))) ("z" . 1))
               (json-set doc "a" "b" 1 99)))
(check "set macro broken path is #f, and the tree is untouched"
       (and (eq? #f (json-set doc "a" "x" 1 99))
            (equal? doc '(("a" . (("b" . #(10 20)) ("c" . #f))) ("z" . 1)))))
;; the #f-propagation ruling: a user transform may STORE #f -- that is
;; JSON false -- while a broken inner path fails the whole operation.
;; The two share a spelling and must not share a channel.
(check "a transform can store #f as a value"
       (equal? '(("z" . #f)) (json-set* '(("z" . 1)) "z" (lambda (o) #f))))
(check "...even at the end of a macro path"
       (equal? '(("a" . (("b" . #(#f 20)) ("c" . #f))) ("z" . 1))
               (json-set doc "a" "b" 0 #f)))
(check "...while an inner break fails the whole write"
       (eq? #f (json-set '(("a" . #f)) "a" "b" 1)))

;; ---- drop: the sweeping selector lives here ----------------------------
(check "drop* by key"        (equal? '(("z" . 1)) (json-drop* doc "a")))
(check "drop* missing key is #f" (eq? #f (json-drop* doc "nope")))
(check "drop* by predicate sweeps"
       (equal? '(("z" . 1))
               (json-drop* '(("t_a" . 1) ("z" . 1) ("t_b" . 2))
                           (lambda (k) (and (string? k)
                                            (>= (string-length k) 2)
                                            (string=? (substring k 0 2) "t_"))))))
(check "drop* #t drops all"  (equal? '() (json-drop* doc #t)))
(check "drop* #f drops none, returning the container -- not #f"
       (equal? doc (json-drop* doc #f)))
;; the two roles of #f meet here and stay apart: selector #f returns the
;; container, failure returns #f. Different values for different calls.
(check "selector #f and failure #f are distinguishable"
       (and (equal? doc (json-drop* doc #f))
            (eq? #f (json-drop* doc "nope"))))

;; ---- push: the member IS the argument ----------------------------------
(check "push* appends to a vector at the END"
       (equal? (vector 1 2 3) (json-push* (vector 1 2) 3)))
(check "push* appends an object member at the end"
       (equal? '(("a" . 1) ("b" . 2))
               (json-push* '(("a" . 1)) (cons "b" 2))))
(check "push* object member must be a pair"
       (eq? #f (json-push* '(("a" . 1)) 5)))
(check "push* member key must be a string"
       (eq? #f (json-push* '(("a" . 1)) (cons 'b 2))))
(check "push macro walks then appends"
       (equal? '(("a" . (("b" . #(10 20 30)) ("c" . #f))) ("z" . 1))
               (json-push doc "a" "b" 30)))
(check "push macro broken path is #f"
       (eq? #f (json-push doc "a" "x" 30)))

;; ---- insert: before the named position ---------------------------------
(check "insert* before an index"
       (equal? (vector 1 99 2) (json-insert* (vector 1 2) 1 99)))
(check "insert* before a key"
       (equal? '(("a" . 1) ("b" . 2) ("c" . 3))
               (json-insert* '(("a" . 1) ("c" . 3)) "c" (cons "b" 2))))
(check "insert* missing anchor is #f"
       (eq? #f (json-insert* (vector 1 2) 5 99)))
(check "insert macro walks a path"
       (equal? '(("a" . (("b" . #(5 10 20)) ("c" . #f))) ("z" . 1))
               (json-insert doc "a" "b" 0 5)))

;; ---- update: the horizontal verb; zero selected is not failure ---------
(check "update* transforms every member under #t"
       (equal? (vector 2 4) (json-update* (vector 1 2) #t (lambda (k v) (* 2 v)))))
(check "update*'s p receives the key"
       (equal? '(("a" . "a") ("b" . "b"))
               (json-update* '(("a" . 1) ("b" . 2)) #t (lambda (k v) k))))
(check "update* by predicate touches only the selected"
       (equal? '(("a" . 10) ("b" . 2))
               (json-update* '(("a" . 1) ("b" . 2))
                             (lambda (k) (string=? k "a"))
                             (lambda (k v) (* 10 v)))))
;; the ruling this cell owns: a selector that matches nothing performed
;; "zero transformations", which is success with nothing to do -- the
;; container comes back, NOT #f. Failure is reserved for the operation
;; not completing at all.
(check "update* zero selected returns the container, not #f"
       (equal? '(("a" . 1))
               (json-update* '(("a" . 1)) (lambda (k) #f) (lambda (k v) 99))))
(check "update* on a non-container is #f"
       (eq? #f (json-update* 42 #t (lambda (k v) v))))

;; ---- failure leaves no fingerprints ------------------------------------
;; every failing call above must also have left its input untouched;
;; sampling the deepest one, byte for byte.
(check "a failed deep write left the original tree byte-identical"
       (let ((before (json->string doc)))
         (and (eq? #f (json-set doc "a" "x" 1 99))
              (string=? before (json->string doc))))
       doc)

;; ---- the macros evaluate root and locators exactly once ----------------
;; Red first: written against the two-pass expansion that evaluated the
;; root and every intermediate locator twice -- reading one container
;; and writing into a second when the expression had a side effect. Not
;; a concurrency question: the second evaluation is the same expression
;; run again. Each counter asserts arity-of-evaluation, not results.
(let* ((n 0)
       (docs (vector '(("a" . (("b" . 1)))) '(("a" . (("b" . 2))))))
       (next (lambda () (set! n (+ n 1)) (vector-ref docs 0))))
  (let ((r (json-set (next) "a" "b" 9)))
    (check "the write macro evaluates its root exactly once"
           (= n 1) (list 'evaluations n 'result r))))
(let* ((n 0)
       (key (lambda () (set! n (+ n 1)) "a")))
  (let ((r (json-set '(("a" . (("z" . 1)))) (key) "z" 9)))
    (check "...and each locator exactly once"
           (= n 1) (list 'evaluations n 'result r))
    (check "...and the write landed where the locator pointed"
           (equal? '(("a" . (("z" . 9)))) r) r)))
;; each verb's RECURSIVE case, not its base case: a single-layer call
;; expands straight to the starred procedure and never enters the
;; two-pass shape, so a one-level counter would be green against the
;; very defect these exist for. Every path below is two layers.
(let* ((n 0)
       (root (lambda () (set! n (+ n 1)) '(("a" . #(1 2))))))
  (json-push (root) "a" 3)
  (check "push macro: root exactly once on a nested path" (= n 1) n))
(let* ((n 0)
       (root (lambda () (set! n (+ n 1)) '(("a" . (("b" . 1)))))))
  (json-drop (root) "a" "b")
  (check "drop macro: root exactly once on a nested path" (= n 1) n))
(let* ((n 0)
       (root (lambda () (set! n (+ n 1)) '(("a" . #(1))))))
  (json-update (root) "a" #t (lambda (k v) v))
  (check "update macro: root exactly once on a nested path" (= n 1) n))
(let* ((n 0)
       (root (lambda () (set! n (+ n 1)) '(("a" . #(1 2))))))
  (json-insert (root) "a" 0 9)
  (check "insert macro: root exactly once on a nested path" (= n 1) n))

;; ---- the two macros no cell had ever invoked ---------------------------
(check "the drop macro walks a path"
       (equal? '(("a" . (("c" . #f))) ("z" . 1))
               (json-drop '(("a" . (("b" . 1) ("c" . #f))) ("z" . 1)) "a" "b")))
(check "the update macro walks a path"
       (equal? '(("a" . #(2 4)))
               (json-update '(("a" . #(1 2))) "a" #t (lambda (k v) (* 2 v)))))
(check "...and both fail as #f on a broken path"
       (and (eq? #f (json-drop doc "nope" "b"))
            (eq? #f (json-update doc "nope" #t (lambda (k v) v)))))

;; ---- the thunk: exactly once, and from any depth of miss ---------------
(let* ((n 0) (thunk (lambda () (set! n (+ n 1)) 'gone)))
  (let ((r (json-ref doc "a" "x" thunk)))
    (check "the absence thunk fires exactly once"
           (and (eq? 'gone r) (= n 1)) (list 'calls n))))
(let* ((n 0) (thunk (lambda () (set! n (+ n 1)) 'gone)))
  (let ((r (json-ref doc "missing" "b" thunk)))
    (check "...including when the FIRST level is the miss"
           (and (eq? 'gone r) (= n 1)) (list 'calls n 'result r))))
(let* ((n 0) (thunk (lambda () (set! n (+ n 1)) 'gone)))
  (json-ref doc "a" "b" 1 thunk)
  (check "...and zero times on a hit" (= n 0) n))

;; ---- update's other two selector states --------------------------------
(check "update* selects by key"
       (equal? '(("a" . 10) ("b" . 2))
               (json-update* '(("a" . 1) ("b" . 2)) "a" (lambda (k v) (* 10 v)))))
(check "update* literal #f selects none and returns the container"
       (equal? '(("a" . 1)) (json-update* '(("a" . 1)) #f (lambda (k v) 99))))
(check "update*'s transform can store #f"
       (equal? '(("a" . #f))
               (json-update* '(("a" . 1)) "a" (lambda (k v) #f))))

;; ---- non-container input fails all five writes -------------------------
(for-each
  (lambda (p)
    (check (string-append "a non-container input is #f for " (car p))
           (eq? #f ((cdr p)))
           ((cdr p))))
  (list (cons "set*"    (lambda () (json-set* 42 "k" 1)))
        (cons "drop*"   (lambda () (json-drop* 42 "k")))
        (cons "push*"   (lambda () (json-push* 42 1)))
        (cons "insert*" (lambda () (json-insert* 42 0 1)))))

;; ---- failure immutability, sampled where reconstruction runs -----------
;; The earlier sample failed during DESCENT -- before any rebuild -- so
;; it mainly proved short-circuiting. These fail at the point of edit,
;; on mutable containers, and check the containers afterwards.
(let ((v (vector 1 2)))
  (check "a missing-anchor insert left the mutable vector untouched"
         (and (eq? #f (json-insert* v 5 9))
              (equal? v (vector 1 2)))
         v))
(let ((o (list (cons "a" 1))))
  (check "an invalid-member push left the mutable object untouched"
         (and (eq? #f (json-push* o (cons 'bad 2)))
              (equal? o '(("a" . 1))))
         o))
(let* ((shared (vector 10 20))
       (tree (list (cons "a" shared) (cons "b" shared))))
  (check "a failed nested write left aliases intact and unduplicated"
         (and (eq? #f (json-set tree "a" 9 99))     ; index 9: missing anchor
              (eq? (cdr (car tree)) (cdr (cadr tree)))
              (equal? shared (vector 10 20)))
         tree))

;; ---- the starred layer is a procedure: a runtime path is one fold ------
(check "starred procedures fold over a runtime path"
       (= 20 (fold-left (lambda (acc k) (and acc (json-ref* acc k)))
                        doc (list "a" "b" 1))))
(check "...and apply reaches them"
       (= 1 (apply json-ref* (list doc "z"))))

(display "json-ops: ")
(display (if (= failures 0) "all tests passed" "FAILURES"))
(newline)
(when (> failures 0) (exit 1))
