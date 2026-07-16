#!chezscheme
;;; (igropyr checked) tests, full mode. Run with IGROPYR_CONTRACTS=full
;;; (run-all.sh bakes the variable in); the guard below refuses to run
;;; otherwise, so a mis-set environment can never pass vacuously.

(import (chezscheme) (igropyr checked))

(unless (eq? (contract-level) 'full)
  (display "checked-full: IGROPYR_CONTRACTS is not \"full\"") (newline)
  (exit 1))

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (substring? needle hay)
  (let ((nl (string-length needle)) (hl (string-length hay)))
    (let loop ((i 0))
      (cond ((> (+ i nl) hl) #f)
            ((string=? needle (substring hay i (+ i nl))) #t)
            (else (loop (+ i 1)))))))

;; expects thunk to raise &assertion with complete blame:
;; who, message containing msg-part, irritants = (irritant)
(define (blames? thunk who msg-part irritant)
  (guard (c ((assertion-violation? c)
             (and (eq? (condition-who c) who)
                  (substring? msg-part (condition-message c))
                  (equal? (condition-irritants c) (list irritant)))))
    (thunk)
    #f))

;; ---- argument contracts ------------------------------------------------

(define-checked (f2 (a string?) (b fixnum?))
  (list a b))

(check "args-ok" (equal? (f2 "x" 1) '("x" 1)))
(check "arg1-blame"
  (blames? (lambda () (f2 42 1)) 'f2 "argument 'a' violated contract string?" 42))
(check "arg2-blame"
  (blames? (lambda () (f2 "x" 'no)) 'f2 "argument 'b' violated contract fixnum?" 'no))

;; bare argument: unchecked by design
(define-checked (fbare (a string?) b)
  (list a b))
(check "bare-arg-unchecked" (equal? (fbare "x" 'anything) '("x" anything)))

;; internal defines stay legal after the injected checks
(define-checked (fdef (x fixnum?))
  (define y (fx* x 2))
  (fx+ x y))
(check "internal-defines" (= (fdef 3) 9))

;; multiple values pass through when there is no return contract
(define-checked (fmv (x fixnum?))
  (values x (fx* x 2)))
(check "multi-value-passthrough"
  (equal? (call-with-values (lambda () (fmv 4)) list) '(4 8)))

;; ---- return contract -----------------------------------------------------

(define-checked (fret (x fixnum?)) -> string?
  (if (fx> x 0) "pos" 'neg))

(check "ret-ok" (equal? (fret 1) "pos"))
(check "ret-blame"
  (blames? (lambda () (fret -1)) 'fret "return value violated contract string?" 'neg))

;; ---- records ---------------------------------------------------------------

(define-checked-record point
  (x real?)
  (mutable y real?))

(define p (make-point 1 2))
(check "record-make" (and (point? p) (= (point-x p) 1) (= (point-y p) 2)))
(point-y-set! p 3)
(check "record-set" (= (point-y p) 3))
(check "record-make-blame"
  (blames? (lambda () (make-point "a" 2)) 'make-point
           "field 'x' of record 'point' violated contract real?" "a"))
(check "record-make-blame-2nd-field"
  (blames? (lambda () (make-point 1 "b")) 'make-point
           "field 'y' of record 'point' violated contract real?" "b"))
(check "record-set-blame"
  (blames? (lambda () (point-y-set! p "z")) 'point-y-set!
           "field 'y' of record 'point' violated contract real?" "z"))
;; immutable field generates no setter
(check "immutable-no-setter"
  (guard (c (#t #t)) (eval 'point-x-set! (interaction-environment)) #f))

;; ---- residue detector positive control ------------------------------------
;; proves the substring probe used by checked-off.sc is able to detect
;; contract residue at all: in full mode it MUST be present.

(define residue
  (with-output-to-string
    (lambda ()
      (pretty-print
        (expand/optimize
          '(lambda (q)
             (let ()
               (define-checked (g (s string?)) (string-length s))
               (g q))))))))
(check "full-mode-has-residue" (substring? "blame" residue))

;; ---- TCO regression --------------------------------------------------------
;; argument contracts must not break tail calls: at the bottom of a
;; 30M-deep self-recursion the memory delta stays flat. A non-tail
;; expansion would hold ~30M frames live (hundreds of MB) here.

(define base-mem (current-memory-bytes))
(define-checked (countdown (n fixnum?))
  (if (fx= n 0)
      (- (current-memory-bytes) base-mem)
      (countdown (fx- n 1))))
(check "arg-contracts-preserve-tco"
  (< (countdown 30000000) (* 64 1024 1024)))

(if (zero? failures)
    (begin (display "checked-full: all tests passed") (newline))
    (begin (display failures) (display " failures") (newline) (exit 1)))
