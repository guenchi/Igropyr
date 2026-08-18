#!chezscheme
;;; (igropyr conv-status) exists to be importable by code that
;;; wants none of the runtime. That is a property of what it LOADS, not of
;;; what it exports, so it cannot be checked from inside a process that
;;; also imports the rest -- by then everything is already resident. This
;;; runs in its own process, imports only the status library, and asks the
;;; library manager what got loaded.
;;;
;;; If this ever fails, someone gave the status library an import. The
;;; predicates would still work, and every other test would stay green:
;;; the only thing lost is the reason the library was separated at all,
;;; and nothing else would notice.

(import (chezscheme) (igropyr conv-status))

(define (fail label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

;; every (igropyr ...) library resident in this process
(define loaded
  (let loop ((ls (library-list)) (acc '()))
    (cond ((null? ls) acc)
          ((and (pair? (car ls)) (eq? (caar ls) 'igropyr))
           (loop (cdr ls) (cons (car ls) acc)))
          (else (loop (cdr ls) acc)))))

(unless (= 1 (length loaded))
  (fail "importing the status vocabulary loaded more than itself" loaded))

(unless (equal? (car loaded) '(igropyr conv-status))
  (fail "the one library loaded is not the one imported" loaded))

;; ...and it is the whole vocabulary, answering for every status the
;; resume/peek API can return. A predicate missing here is what sends a
;; consumer back to comparing symbols by hand.
(for-each
  (lambda (probe)
    (let ((name (car probe)) (pred (cadr probe)) (yes (caddr probe)))
      (unless (pred yes)
        (fail "predicate does not recognise its own status" name yes))
      (unless (eq? #f (pred 'definitely-not-a-status))
        (fail "predicate accepted something that is not its status" name))))
  (list (list 'gone conversation-gone? 'gone)
        (list 'stale conversation-stale? 'stale)
        (list 'done conversation-done? 'done)
        (list 'settled conversation-settled? 'settled)
        (list 'unknown conversation-unknown? 'unknown)
        (list 'unreachable conversation-unreachable? 'unreachable)
        (list 'overloaded conversation-overloaded? 'overloaded)))

;; the two refusal-shaped statuses call for opposite responses --
;; 'unreachable must be reconciled, 'overloaded may simply be retried --
;; so the pair is checked against each other, not only against garbage
(when (conversation-overloaded? 'unreachable)
  (fail "overloaded? accepted 'unreachable"))
(when (conversation-unreachable? 'overloaded)
  (fail "unreachable? accepted 'overloaded"))

(display "the status vocabulary loads nothing but itself ok\n")
(display "ALL CONV-STATUS TESTS PASSED\n")
