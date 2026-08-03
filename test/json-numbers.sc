#!chezscheme
;;; (igropyr json) number handling: what a hostile document may cost, and
;;; what it may claim.
;;;
;;; Both cases here reach the parser from request bodies, which are
;;; attacker-controlled by definition.

(import (chezscheme) (igropyr json) (igropyr jwt) (igropyr libuv))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define (refuses? s)
  (guard (e (#t #t)) (string->json s) #f))

;; ---- cost -----------------------------------------------------------------
;; An unbounded digit run goes to string->number, which builds an
;; arbitrary-precision integer. Measured before the limit: 262144 digits took
;; 4549 ms -- one request freezing the single scheduler thread for four and a
;; half seconds, with the default body limit allowing nearly a megabyte of
;; them. The assertion is on TIME, because the parse "succeeding" was never
;; the problem.
(let* ((s (string-append "{\"n\":" (make-string 262144 #\9) "}"))
       (t0 (now-ms))
       (refused (refuses? s))
       (ms (- (now-ms) t0)))
  (check "a 262144-digit number is refused" refused)
  (display "  [info] refused in ") (display ms) (display " ms (was 4549 ms to accept)\n")
  (check "and refused quickly" (< ms 200)))

;; ordinary numbers keep working -- the limit must not be so tight that real
;; documents trip it
(check "ordinary integer" (= 42 (json-ref (string->json "{\"n\":42}") "n")))
(check "negative" (= -17 (json-ref (string->json "{\"n\":-17}") "n")))
(check "float" (< 3.13 (json-ref (string->json "{\"n\":3.14}") "n") 3.15))
(check "exponent" (= 1e10 (json-ref (string->json "{\"n\":1e10}") "n")))
;; nanosecond timestamps are 19 digits; the limit is 64
(check "nanosecond timestamp"
  (= 1722674400123456789 (json-ref (string->json "{\"n\":1722674400123456789}") "n")))

;; ---- non-finite -----------------------------------------------------------
;; An out-of-range exponent used to parse to +inf.0, which IS a real -- so it
;; passed every (real? v) guard downstream. jwt's expiry check was one: a
;; correctly signed token carrying exp=1e999 got a non-finite expiry and
;; therefore never expired. JSON has no infinities, so refusing is also the
;; more faithful parse.
(check "1e999 is refused" (refuses? "{\"exp\":1e999}"))
(check "-1e999 is refused" (refuses? "{\"exp\":-1e999}"))

;; The jwt guard does not rely on the parser: claims can arrive from any
;; decoder, and an expiry is the last place to take a value on trust.
(let* ((key "0123456789abcdef0123456789abcdef")
       (tok (jwt-sign `(("sub" . "u1") ("exp" . ,(inexact (/ 1.0 0.0)))) key)))
  (check "a token with a non-finite exp does not verify"
    (not (jwt-verify tok key))))

;; and a normal token still does
(let ((key "0123456789abcdef0123456789abcdef"))
  (check "a token with a normal exp still verifies"
    (and (jwt-verify (jwt-sign '(("sub" . "u1")) key '((expires-in . 300))) key)
         #t)))

(if (zero? failures)
    (begin (display "json-numbers: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
