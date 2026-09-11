#!chezscheme
;; The S3 XML unescaper's numeric character reference (&#...; / &#x...;) used to
;; accumulate every digit into an exact integer and compare against the code
;; point ceiling only at the ';': a reference of n digits cost n squared. A
;; listing body from a server is the input. The accumulation must stop as soon
;; as the value passes the ceiling (work linear in the text), and the text is
;; then copied literally as before. Seam: $xml-unescape.
(import (chezscheme) (igropyr s3) (only (igropyr libuv) now-ms))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (t label got want) (check label (equal? got want) got want))
(define u $xml-unescape)

(t "&#65; is A" (u "&#65;") "A")
(t "&#x41; is A" (u "&#x41;") "A")
(t "&#X41; is A" (u "&#X41;") "A")
(t "leading zeros keep their value" (u "&#000065;") "A")
(t "many leading zeros keep their value (the bound is on the value, not the digit count)" (u (string-append "&#" (make-string 40 #\0) "65;")) "A")
(t "the last code point" (u "&#1114111;") (string (integer->char #x10FFFF)))
(t "one past the ceiling is copied literally" (u "&#1114112;") "&#1114112;")
(t "a surrogate is copied literally" (u "&#xD800;") "&#xD800;")
(t "no digits: copied literally" (u "&#;") "&#;")
(t "named entities still work" (u "a&amp;b&lt;c&gt;d&quot;e&apos;f") "a&b<c>d\"e'f")
(t "an unterminated reference is copied literally" (u "&#65") "&#65")
;; the red proof: 400000 nines. Quadratic accumulation takes seconds (2.9 s for
;; 200000 on the reference machine); the bounded loop answers in tens of ms
(let* ((s (string-append "&#" (make-string 400000 #\9) ";"))
       (t0 (now-ms)) (r (u s)) (ms (- (now-ms) t0)))
  (check "a 400000-digit reference is copied literally" (equal? r s) (string-length r))
  (check "...and answers within one second (the accumulation stops at the ceiling)" (< ms 1000) ms))
(let* ((s (string-append "&#x" (make-string 400000 #\f) ";"))
       (t0 (now-ms)) (r (u s)) (ms (- (now-ms) t0)))
  (check "a 400000-digit hex reference is copied literally" (equal? r s) (string-length r))
  (check "...and answers within one second" (< ms 1000) ms))

(if (zero? fails)
    (begin (display "ALL S3-XML-REF TESTS PASSED\n") (exit 0))
    (begin (display "S3-XML-REF VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
