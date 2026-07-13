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

;; ---- extended mode: vectors, bytevectors, finite flonums ---------------

(define (ext-round-trips? x)
  (equal? x (string->sexpr-extended (sexpr->string-extended x))))
(define (ext-parse-fails? s)
  (guard (e ((vector? e) (eq? (vector-ref e 0) 'sexpr-error)))
    (string->sexpr-extended s)
    #f))
(define (ext-write-fails? x)
  (guard (e ((vector? e) (eq? (vector-ref e 0) 'sexpr-error)))
    (sexpr->string-extended x)
    #f))

(check "ext-vector" (ext-round-trips? '#(1 two "three" #t)))
(check "ext-vector-empty" (ext-round-trips? '#()))
(check "ext-vector-nested" (ext-round-trips? '#(#(1 2) (a . #(b)) #vu8(7))))
(check "ext-bytevector" (ext-round-trips? (bytevector 0 127 255)))
(check "ext-bytevector-empty" (ext-round-trips? (bytevector)))
(check "ext-flonums"
       (ext-round-trips?
        '(0.5 -3.25 1e300 1.7976931348623157e308 5e-324 -0.0 100.0)))
(check "ext-flonum-bit-exact"
       (eqv? 0.1 (string->sexpr-extended (sexpr->string-extended 0.1))))
(check "ext-actor-message" (ext-round-trips? '#(tcp-data #vu8(1 2 3))))
(check "ext-strict-subset"
       (ext-round-trips? '(user (id . 42) (name . "ada") 1/3 #t)))
(check "ext-wire-text"
       (string=? (sexpr->string-extended '#(1 #vu8(2 3) 4.5))
                 "#(1 #vu8\"AgM=\" 4.5)"))

;; extended mode still rejects everything outside ITS whitelist
(check "ext-no-inf-read" (ext-parse-fails? "1e999"))       ; reads as +inf.0
(check "ext-no-inf-write" (ext-write-fails? +inf.0))
(check "ext-no-nan-write" (ext-write-fails? +nan.0))
(check "ext-no-char" (ext-parse-fails? "#\\a"))
(check "ext-no-eval" (ext-parse-fails? "#;(walk in) 42"))
(check "ext-no-dotted-vector" (ext-parse-fails? "#(1 . 2)"))
(check "ext-vector-unterminated" (ext-parse-fails? "#(1 2"))
(check "ext-bv-base64-decode"                          ; "AgM=" -> bytes 2,3
       (equal? (bytevector 2 3) (string->sexpr-extended "#vu8\"AgM=\"")))
(check "ext-bv-base64-empty"
       (equal? (bytevector) (string->sexpr-extended "#vu8\"\"")))
(check "ext-bv-no-paren" (ext-parse-fails? "#vu8(1 2 3)"))   ; old form gone
(check "ext-bv-bad-base64" (ext-parse-fails? "#vu8\"@@@\""))  ; not base64
(check "ext-bv-unterminated" (ext-parse-fails? "#vu8\"AgM"))  ; no closing "
(check "ext-bv-bad-prefix" (ext-parse-fails? "#vu9\"\""))
(check "ext-no-write-proc" (ext-write-fails? car))
(check "ext-depth-bomb"
       (ext-parse-fails?
        (let loop ((i 0) (s "42"))
          (if (= i 100) s (loop (+ i 1) (string-append "#(" s ")"))))))

;; the extension must not leak into strict mode
(check "strict-still-no-vector" (parse-fails? "#(1 2 3)"))
(check "strict-still-no-bv" (parse-fails? "#vu8\"AgM=\""))
(check "strict-still-no-float" (parse-fails? "1.5"))
(check "strict-still-no-write-bv" (write-fails? (bytevector 1)))

(if (zero? failures)
    (begin (display "sexpr: all tests passed") (newline))
    (begin (display failures) (display " failures") (newline) (exit 1)))
