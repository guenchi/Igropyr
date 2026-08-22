#!chezscheme
;;; (igropyr json) read-side acceptance surface, pinned row by row.
;;;
;;; LOCKSTEP CONTRACT. This reader has a wire counterpart: the
;;; browser-side (Goeteia) JSON reader, each parsing what the other
;;; side's writer -- or the same third-party client -- produces. The
;;; two readers share a small set of DELIBERATELY DOCUMENTED
;;; deviations from RFC 8259's read grammar, and tightening any of
;;; them on ONE side manufactures a wire asymmetry: input one side
;;; accepts and the other refuses. So every row below is pinned,
;;; the deviations included -- a "fix" that flips an ACCEPT row goes
;;; red here on purpose, and the answer is not to update the row but
;;; to coordinate a lockstep change with the counterpart first.
;;;
;;; The deviation set was measured by survey, not collected from
;;; reports: every token the number tokenizer can hand to Chez's
;;; string->number was probed class by class. Three classes deviate:
;;;
;;;   A. leading zeros in the integer part      "01" "-01" "00" "01.5"
;;;   B. missing digits beside the dot          "5." "5.e3" "-.5"
;;;      (both come from delegating the numeral to string->number,
;;;       which accepts a superset of JSON's number grammar within
;;;       the tokenizer's charset)
;;;   C. bare control characters inside strings (RFC requires \u
;;;      escapes; the scanner passes them through)
;;;
;;; SELF-DESTRUCT CLAUSE, shared with the counterpart's survey: if a
;;; row outside these three classes is ever found deviating, the
;;; survey that produced this closed set has failed, and BOTH sides'
;;; tables are re-surveyed whole -- do not just append the find.
;;;
;;; Duplicate keys are RFC 4 SHOULD territory, not a deviation. This
;;; side's semantics, pinned below: the alist RETAINS every pair in
;;; order, and json-ref answers the FIRST.

(import (chezscheme) (igropyr json))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))

(define (status s)
  (guard (e (#t 'REJECT)) (string->json s) 'ACCEPT))

(define (pin rows what)
  (for-each
    (lambda (row)
      (let ((input (car row)) (expected (cdr row)))
        (check (string-append what ": "
                              (call-with-string-output-port
                                (lambda (p) (write input p))))
               (eq? expected (status input))
               (status input))))
    rows))

;; ---- the three deviation classes: pinned as ACCEPT ----------------------
(pin '(("01" . ACCEPT) ("-01" . ACCEPT) ("00" . ACCEPT)
       ("01.5" . ACCEPT) ("-00" . ACCEPT))
     "deviation A, leading zeros")
(pin `(("5." . ACCEPT) ("5.e3" . ACCEPT) ("1.e2" . ACCEPT)
       ("-3." . ACCEPT) ("-.5" . ACCEPT))
     "deviation B, missing digits beside the dot")
(pin `((,(string #\" #\newline #\") . ACCEPT)
       (,(string #\" #\tab #\") . ACCEPT)
       (,(string #\" #\nul #\") . ACCEPT))
     "deviation C, bare control characters in strings")

;; ---- the rejections RFC requires and this reader delivers ---------------
(pin '(("[1,2,]" . REJECT) ("{\"a\":1,}" . REJECT)     ; trailing commas
       ("'a'" . REJECT) ("{'a':1}" . REJECT)           ; single quotes
       ("NaN" . REJECT) ("Infinity" . REJECT)
       ("-Infinity" . REJECT)
       (".5" . REJECT) ("+5" . REJECT)                 ; numbers cannot
       ("+.5" . REJECT) ("-." . REJECT)                ;   start there
       ("1e" . REJECT) ("1E" . REJECT) ("1e+" . REJECT)
       ("5..2" . REJECT) ("1e5.5" . REJECT)
       ("1_000" . REJECT) ("1/2" . REJECT) ("#x10" . REJECT)
       ("{a:1}" . REJECT)                              ; bare key
       ("[1] // c" . REJECT) ("/* c */ 1" . REJECT)    ; comments
       ("\"\\ud800\"" . REJECT)                        ; lone surrogate
       ("1 2" . REJECT) ("[1] extra" . REJECT)         ; trailing content
       ("" . REJECT) ("   " . REJECT))
     "required rejection")

;; ---- valid JSON that must stay accepted ---------------------------------
(pin '(("0.5" . ACCEPT) ("1e+5" . ACCEPT) ("-0.5e01" . ACCEPT)
       ("0" . ACCEPT) ("-0" . ACCEPT))
     "valid number")

;; ---- duplicate keys: both retained, json-ref answers the first ----------
(let ((d (string->json "{\"a\":1,\"a\":2}")))
  (check "duplicate keys: every pair retained, in order"
         (equal? d '(("a" . 1) ("a" . 2))) d)
  (check "duplicate keys: json-ref answers the first"
         (eqv? 1 (json-ref d "a"))))

;; range limits are allowed by RFC 8259 section 6, not a deviation;
;; pinned so the refusal stays a refusal
(check "an overflowing literal is refused, not wrapped"
       (eq? 'REJECT (status "1e309")))

(if (zero? failures)
    (begin (display "json-rfc-surface: all tests passed\n") (exit 0))
    (begin (display (number->string failures))
           (display " failures\n") (exit 1)))
