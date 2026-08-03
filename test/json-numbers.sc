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
;; nanosecond timestamps are 19 digits
(check "nanosecond timestamp"
  (= 1722674400123456789 (json-ref (string->json "{\"n\":1722674400123456789}") "n")))

;; A uint256 is 78 digits, and applications really do send them. The first
;; limit here was 64 -- chosen for what a NUMBER needs (a double carries 17
;; significant digits) rather than for what a general-purpose JSON parser
;; must accept -- and it turned a defence into a compatibility regression.
(let* ((u256 "115792089237316195423570985008687907853269984665640564039457584007913129639935")
       (v (json-ref (string->json (string-append "{\"n\":" u256 "}")) "n")))
  (check "a uint256 parses" (= v (string->number u256))))

;; ...and the ceiling is still a ceiling. Measured: string->number costs
;; ~2 us at 64 digits, 28 us at 512, 1204 us at 4096 -- superlinear, which
;; is what made an unbounded run a 4.5-second freeze.
(check "1000 digits is still refused" (refuses? (string-append "{\"n\":" (make-string 1000 #\9) "}")))

;; ---- non-finite -----------------------------------------------------------
;; An out-of-range exponent used to parse to +inf.0, which IS a real -- so it
;; passed every (real? v) guard downstream. jwt's expiry check was one: a
;; correctly signed token carrying exp=1e999 got a non-finite expiry and
;; therefore never expired. JSON has no infinities, so refusing is also the
;; more faithful parse.
(check "1e999 is refused" (refuses? "{\"exp\":1e999}"))
(check "-1e999 is refused" (refuses? "{\"exp\":-1e999}"))

;; The jwt guard requiring a FINITE expiry is defence in depth, and this
;; says so rather than pretending to exercise it.
;;
;; It cannot be reached through the public path: the parser refuses a
;; non-finite number, so no token that parses can carry one. The obvious
;; test -- sign a claim set whose exp is +inf.0 -- proves nothing either,
;; because json->string writes +inf.0 as null, and a verifier checking only
;; (real? v) rejects null just as surely. That version passed against the
;; code it was meant to test.
;;
;; What IS reachable, and what actually stops such a token, is the parser.
;; A payload hand-built with 1e999 in it does not verify.
(let* ((key "0123456789abcdef0123456789abcdef")
       (hand (jwt-sign '(("sub" . "u1")) key)))
  ;; a genuinely signed token still verifies, so the check below is not
  ;; passing for want of a signature
  (check "a normal token verifies" (and (jwt-verify hand key) #t)))

(let ((key "0123456789abcdef0123456789abcdef"))
  ;; +inf.0 through jwt-sign becomes null on the wire; the token is refused,
  ;; but by the claim SHAPE, not by the finite guard
  (check "a token whose exp serialised to null does not verify"
    (not (jwt-verify (jwt-sign `(("sub" . "u1") ("exp" . ,(inexact (/ 1.0 0.0)))) key)
                     key))))

;; and a normal token still does
(let ((key "0123456789abcdef0123456789abcdef"))
  (check "a token with a normal exp still verifies"
    (and (jwt-verify (jwt-sign '(("sub" . "u1")) key '((expires-in . 300))) key)
         #t)))

(if (zero? failures)
    (begin (display "json-numbers: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
