#!chezscheme
;;; (igropyr checked) tests, off mode. Run with IGROPYR_CONTRACTS unset
;;; (run-all.sh uses env -u); the guard below refuses to run otherwise.
;;; Off is the production default: contracts must expand to nothing.

(import (chezscheme) (igropyr checked))

(unless (eq? (contract-level) 'off)
  (display "checked-off: IGROPYR_CONTRACTS is set; run with it unset") (newline)
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

;; ---- contracts are gone: violating calls just run -------------------------

(define-checked (f2 (a string?) (b fixnum?))
  (list a b))
(check "violating-call-passes" (equal? (f2 42 'no) '(42 no)))

(define-checked (fret (x fixnum?)) -> string?
  (if (fx> x 0) "pos" 'neg))
(check "ret-contract-gone" (eq? (fret -1) 'neg))

(define-checked-record point
  (x real?)
  (mutable y real?))
(define p (make-point "not-a-real" 2))
(check "record-make-unchecked" (and (point? p) (equal? (point-x p) "not-a-real")))
(point-y-set! p "also-not")
(check "record-set-unchecked" (equal? (point-y p) "also-not"))

;; ---- zero residue -----------------------------------------------------------
;; the optimized expansion must contain no trace of the contract
;; machinery. checked-full.sc proves this probe can detect residue
;; ("full-mode-has-residue"), so absence here is meaningful.

(define (residue-free? form)
  (let ((s (with-output-to-string
             (lambda () (pretty-print (expand/optimize form))))))
    (and (not (substring? "blame" s))
         (not (substring? "violated" s))
         (not (substring? "assertion" s)))))

(check "proc-zero-residue"
  (residue-free?
    '(lambda (q)
       (let ()
         (define-checked (g (s string?)) (string-length s))
         (g q)))))

(check "ret-zero-residue"
  (residue-free?
    '(lambda (q)
       (let ()
         (define-checked (g (s string?)) -> fixnum? (string-length s))
         (g q)))))

(check "record-zero-residue"
  (residue-free?
    '(let ()
       (define-checked-record pt (x fixnum?) (mutable y fixnum?))
       (let ((r (make-pt 1 2)))
         (pt-y-set! r 3)
         (pt-y r)))))

;; off-mode define-checked still compiles to working code: the body's
;; primitive survives optimization (the wrapper truly is a plain define,
;; inlined away just like the unchecked version would be)
(check "off-body-survives"
  (let ((s (with-output-to-string
             (lambda ()
               (pretty-print
                 (expand/optimize
                   '(lambda (q)
                      (let ()
                        (define-checked (g (s string?)) (string-length s))
                        (g q)))))))))
    (substring? "string-length" s)))

(if (zero? failures)
    (begin (display "checked-off: all tests passed") (newline))
    (begin (display failures) (display " failures") (newline) (exit 1)))
