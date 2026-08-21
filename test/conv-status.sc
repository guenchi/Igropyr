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

;; ...and the list below is the vocabulary -- but "whole" is not a claim
;; this file gets to make by hand. It once said "whole vocabulary" while
;; probing seven of the eight exported predicates: the missing one
;; (conversation-no-answer-yet?) could have regressed or been deleted
;; without a single line here going red. So each probe now carries the
;; predicate's exported NAME, and the probe list is compared against the
;; library's own export face in both directions further down. A ninth
;; predicate added to the library turns this suite red until it is
;; probed here.
(define probes
  ;; (status-word  exported-name  predicate  accepted-value)
  (list (list 'gone 'conversation-gone? conversation-gone? 'gone)
        (list 'stale 'conversation-stale? conversation-stale? 'stale)
        (list 'done 'conversation-done? conversation-done? 'done)
        (list 'settled 'conversation-settled? conversation-settled? 'settled)
        (list 'unknown 'conversation-unknown? conversation-unknown? 'unknown)
        (list 'unreachable 'conversation-unreachable?
              conversation-unreachable? 'unreachable)
        (list 'overloaded 'conversation-overloaded?
              conversation-overloaded? 'overloaded)
        ;; not a status: the word only conversation-peek/timeout answers
        ;; with, reporting on the asker's deadline -- probed all the same,
        ;; because it is on the export face and consumers classify with it
        (list 'no-answer-yet 'conversation-no-answer-yet?
              conversation-no-answer-yet? 'no-answer-yet)))

(for-each
  (lambda (probe)
    (let ((name (car probe)) (pred (caddr probe)) (yes (cadddr probe)))
      (unless (pred yes)
        (fail "predicate does not recognise its own status" name yes))
      (unless (eq? #f (pred 'definitely-not-a-status))
        (fail "predicate accepted something that is not its status" name))))
  probes)

;; the export face is the authority on "whole": every conversation-...?
;; export must be probed above, and every probed name must be exported
(let ((exported (filter
                  (lambda (n)
                    (let* ((s (symbol->string n)) (m (string-length s)))
                      (and (> m 13)
                           (string=? (substring s 0 13) "conversation-")
                           (char=? (string-ref s (- m 1)) #\?))))
                  (library-exports '(igropyr conv-status))))
      (probed (map cadr probes)))
  (for-each (lambda (p)
              (unless (memq p probed)
                (fail "an exported predicate has no probe in this suite" p)))
            exported)
  (for-each (lambda (p)
              (unless (memq p exported)
                (fail "a probed name is not on the export face" p)))
            probed))

;; the two refusal-shaped statuses call for opposite responses --
;; 'unreachable must be reconciled, 'overloaded may simply be retried --
;; so the pair is checked against each other, not only against garbage
(when (conversation-overloaded? 'unreachable)
  (fail "overloaded? accepted 'unreachable"))
(when (conversation-unreachable? 'overloaded)
  (fail "unreachable? accepted 'overloaded"))

;; 'no-answer-yet is NOT 'unknown -- the manual leans on that distinction
;; (ask again vs reconcile), so the pair is checked against each other
(when (conversation-no-answer-yet? 'unknown)
  (fail "no-answer-yet? accepted 'unknown"))
(when (conversation-unknown? 'no-answer-yet)
  (fail "unknown? accepted 'no-answer-yet"))

(display "the status vocabulary loads nothing but itself ok\n")
(display "ALL CONV-STATUS TESTS PASSED\n")
