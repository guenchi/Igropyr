#!chezscheme
;;; (igropyr sexpr) tests: whitelist round-trips, hostile input.

(import (chezscheme) (igropyr sexpr))

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))
(define (round-trips? x)
  (equal? x (string->sexpr (sexpr->string x))))
(define (parse-fails? s)
  (guard (e ((vector? e) (eq? (vector-ref e 0) 'sexpr-error)))
    (string->sexpr s)
    #f))
(define (write-fails? x)
  (guard (e ((vector? e) (eq? (vector-ref e 0) 'sexpr-error)))
    (sexpr->string x)
    #f))

;; round trips over the whitelist
(check "list" (round-trips? '(get-user 42)))
(check "nested" (round-trips? '(user (id . 42) (name . "ada") (roles admin editor))))
(check "dotted" (round-trips? '(a . b)))
(check "alist" (round-trips? '(("x" . 1) ("y" . 2))))
(check "empty" (round-trips? '()))
(check "bools" (round-trips? '(#t #f)))
(check "negatives" (round-trips? '(-1 0 42 -99999999999999999999999999)))
(check "bignum" (round-trips? (expt 10 40)))
(check "ratio" (round-trips? '(1/3 -7/2)))
(check "string-escapes" (round-trips? '("say \"hi\"" "back\\slash")))
(check "string-newline" (round-trips? (list (string #\a #\newline #\b))))
(check "symbols" (round-trips? '(fl* set! <=? %raw a.b :kw @x)))

;; the exact wire text of the doc example
(check "wire-text"
       (string=? (sexpr->string '(user (id . 42) (name . "ada")))
                 "(user (id . 42) (name . \"ada\"))"))

;; reader accepts \n \t \r escapes (Goeteia may emit literal newlines;
;; both must parse)
(check "read-escapes"
       (equal? (string->sexpr "(\"a\\nb\" \"c\\td\")")
               (list (string #\a #\newline #\b) (string #\c #\tab #\d))))

;; hostile input fails loudly, never evaluates
(check "no-eval" (parse-fails? "#;(walk in) 42"))
(check "no-vector" (parse-fails? "#(1 2 3)"))
(check "no-char" (parse-fails? "#\\a"))
(check "no-float" (parse-fails? "(1.5)"))
(check "no-quote-hash" (parse-fails? "#'x"))
(check "unterminated" (parse-fails? "(a (b"))
(check "trailing" (parse-fails? "(a) (b)"))
(check "bad-escape" (parse-fails? "\"\\q\""))
(check "depth-bomb"
       (parse-fails?
        (let loop ((i 0) (s "42"))
          (if (= i 100) s (loop (+ i 1) (string-append "(" s ")"))))))
(check "depth-ok"
       (equal? 42 (let loop ((i 0) (x 42) (s "42"))
                    (if (= i 50)
                        (let unwrap ((v (string->sexpr s)) (k 50))
                          (if (zero? k) v (unwrap (car v) (- k 1))))
                        (loop (+ i 1) x (string-append "(" s ")"))))))

;; the writer refuses non-whitelist data (payloads stay data)
(check "no-write-float" (write-fails? 1.5))
(check "no-write-vector" (write-fails? (vector 1 2)))
(check "no-write-proc" (write-fails? car))
(check "no-write-weird-symbol" (write-fails? (string->symbol "has space")))
(check "no-write-cycle"
       (write-fails? (let ((x (list 1 2))) (set-cdr! (cdr x) x) x)))

(if (zero? failures)
    (begin (display "sexpr: all tests passed") (newline))
    (begin (display failures) (display " failures") (newline) (exit 1)))
