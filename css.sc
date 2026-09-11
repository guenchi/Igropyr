#!chezscheme
;;; Copyright 2018 - 2026 guenchi.
;;;
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;;
;;; http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

;;; (igropyr css) -- render a rule list to a CSS string.
;;;
;;; A stylesheet is a list of rules; a rule is (selector (prop value ...)
;;; ...). Selectors are symbols (element names) or strings (anything
;;; carrying . # : > or a space).
;;;
;;; NO FLOATS ANYWHERE, and that is a decision about exactness rather
;;; than taste: a printed flonum is not guaranteed to be the number that
;;; was written. Unit forms take variable arity instead. (unit W) is the
;;; whole value, (unit W F) adds the fraction's digits AS WRITTEN, and
;;; (unit W F width) states a minimum width so a leading zero can be
;;; recovered -- the reader has already dropped it from the literal by
;;; the time this sees it. Whole values stay natural, fractions stay
;;; exact integers, and every value is expressible:
;;;   (em 1)   -> "1em"     (em 0 92) -> "0.92em"  (em 3 40) -> "3.4em"
;;;   (em 3 4) -> "3.4em"   (em 3 4 2) -> "3.04em" (px 13)   -> "13px"
;;;   (pct 50) -> "50%"     (vh 100)  -> "100vh"   (deg 120) -> "120deg"
;;;
;;; Non-unit values:
;;;   integer           -> itself ("0", "650" for z-index or rgb parts)
;;;   string            -> literal ("#fff", "solid")
;;;   symbol            -> its name (none, inherit, ...)
;;;   (dec 1 60)        -> "1.6"   ; a unitless decimal, e.g. line-height
;;;   (var ink)         -> "var(--ink)"
;;;   (calc V ...)      -> "calc(V ...)"
;;;   (rgba 16 20 42 (dec 0 6)) -> "rgba(16,20,42,0.6)"
;;;   (A B ...)         -> "A B ..."  ; a space-joined compound value
;;; @media, @keyframes and @supports nest rules.
;;;
;;;   (css->string
;;;     `((:root (--bg "#f2f4fa"))
;;;       (body (margin 0) (background (var bg)) (line-height "1.6"))
;;;       (".nav a" (color (var dim)) (font-size (em 0 92)))
;;;       (@media "(max-width: 42em)"
;;;         (".nav" (gap (em 1))))))
;;;
;;; THE #!chezscheme ABOVE IS LOAD-BEARING. A library is read in #!r6rs
;;; mode by default, where `@media` and its siblings are not readable
;;; symbols. Removing that line does not break a test; it stops the file
;;; being readable at all.

(library (igropyr css)
  (export css->string num->css palette->root)
  (import (rnrs))

  ;; PAD FIRST, THEN STRIP, and the order is the whole of the rule.
  ;; (em 0 50 3) is 0.05: 50 becomes "050" and then loses its trailing
  ;; zero. Stripping first would leave "5", pad that to "005", and answer
  ;; 0.005 instead.
  ;;
  ;; THE CONTRACT STOPS AT THE DIGITS. This answers a string that may be
  ;; empty; it knows nothing of a decimal point, a sign or a whole part.
  ;; The caller decides what an empty answer means -- here it means the
  ;; point is dropped, because "1.em" is not a CSS value.
  (define (frac-digits f width)
    (let pad ((s (number->string f)))
      (if (< (string-length s) width)
          (pad (string-append "0" s))
          (let strip ((n (string-length s)))
            (cond
             ((= n 0) "")
             ((char=? #\0 (string-ref s (- n 1))) (strip (- n 1)))
             (else (substring s 0 n)))))))

  ;; a palette alist ((name value) ...) as a :root rule of custom
  ;; properties, so one binding names a colour for both Scheme and CSS:
  ;;   (palette->root '((ink "#14203a"))) -> (:root (--ink "#14203a"))
  (define (palette->root palette)
    (cons ':root
          (map (lambda (p)
                 (list (string->symbol
                        (string-append "--" (symbol->string (car p))))
                       (cadr p)))
               palette)))

  (define (join parts sep)
    (cond
     ((null? parts) "")
     ((null? (cdr parts)) (car parts))
     (else (string-append (car parts) sep (join (cdr parts) sep)))))

  ;; a scalar: exact integers pass through, strings pass through. No
  ;; floats -- a fraction is written with the two-argument unit form.
  (define (num->css n)
    (cond
     ((string? n) n)
     ((and (integer? n) (exact? n)) (number->string n))
     (else (error 'css "use an exact integer, a unit form, or a string" n))))

  ;; a unit value: (em 1) -> "1em"; (em 0 92) -> "0.92em" (whole and
  ;; fraction); (em 3 4) -> "3.4em"; (em 3 4 2) -> "3.04em", the third
  ;; operand being the fraction's MINIMUM width, left-padded with zeros.
  ;;
  ;; THE OPERANDS ARE CHECKED RATHER THAN TAKEN ON TRUST. Extra ones used
  ;; to be dropped in silence, so (em 1 5 2 9) rendered as though the 9
  ;; had never been written.
  (define (unit->css args suffix)
    (unless (pair? args) (error 'css "unit form needs an argument"))
    (when (and (pair? (cdr args)) (pair? (cddr args)) (pair? (cdddr args)))
      (error 'css "a unit form takes at most a whole, a fraction and a width"
             args))
    (string-append
     (if (null? (cdr args))
         (num->css (car args))
         (let ((f (cadr args)))
           (unless (and (integer? f) (exact? f) (not (< f 0)))
             (error 'css "a unit fraction is an exact non-negative integer; the sign belongs to the whole part" f))
           (let* ((width (if (pair? (cddr args)) (caddr args)
                             (string-length (number->string f))))
                  (_ (unless (and (integer? width) (exact? width)
                                  (not (< width 0)))
                       (error 'css "a unit width is an exact non-negative integer" width)))
                  (d (frac-digits f width)))
             ;; no digits left means no decimal point: "1.em" is not a
             ;; CSS value, and this is the case that used to emit one
             (if (string=? d "")
                 (num->css (car args))
                 (string-append (num->css (car args)) "." d)))))
     suffix))

  (define units
    '((px . "px") (em . "em") (rem . "rem") (pct . "%") (vh . "vh")
      (vw . "vw") (vmin . "vmin") (vmax . "vmax") (fr . "fr") (deg . "deg")
      (s . "s") (ms . "ms") (ch . "ch") (ex . "ex")))

  (define (val->css v)
    (cond
     ((string? v) v)
     ((number? v) (num->css v))
     ((symbol? v) (symbol->string v))
     ((pair? v)
      (let* ((h (car v)) (u (and (symbol? h) (assq h units))))
        (cond
         (u (unit->css (cdr v) (cdr u)))
         ;; a unitless decimal, same whole/fraction convention as a unit:
         ;; (dec 0 6) -> "0.6" for an alpha, (dec 1 6) -> "1.6" for a
         ;; line-height
         ((eq? h 'dec) (unit->css (cdr v) ""))
         ((eq? h 'var) (string-append "var(--" (symbol->string (cadr v)) ")"))
         ((eq? h 'calc) (string-append "calc(" (join (map val->css (cdr v)) " ") ")"))
         ((eq? h 'rgba) (string-append "rgba(" (join (map val->css (cdr v)) ",") ")"))
         ((eq? h 'rgb) (string-append "rgb(" (join (map val->css (cdr v)) ",") ")"))
         ;; a compound value, space-joined: 1px solid ...
         (else (join (map val->css v) " ")))))
     (else (error 'css "bad value" v))))

  ;; ---- selectors, declarations, rules ----

  (define (sel->css s)
    (cond ((string? s) s)
          ((symbol? s) (symbol->string s))
          (else (error 'css "bad selector" s))))

  (define (decl->css d)
    (string-append (sel->css (car d)) ":"
                   (join (map val->css (cdr d)) " ") ";"))

  (define (rule->css r)
    (let ((head (car r)))
      (cond
       ((eq? head '@media)
        (string-append "@media " (cadr r) "{"
                       (apply string-append (map rule->css (cddr r))) "}"))
       ((eq? head '@keyframes)
        (string-append "@keyframes " (val->css (cadr r)) "{"
                       (apply string-append (map rule->css (cddr r))) "}"))
       ((eq? head '@supports)
        (string-append "@supports " (cadr r) "{"
                       (apply string-append (map rule->css (cddr r))) "}"))
       (else
        (string-append (sel->css head) "{"
                       (apply string-append (map decl->css (cdr r))) "}")))))

  (define (css->string rules)
    (apply string-append (map rule->css rules))))
