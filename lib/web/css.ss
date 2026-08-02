;; Express CSS in Scheme: render a rule list to a CSS string.
;;
;; The CSS analogue of (web html). A stylesheet is a list of rules;
;; a rule is (selector (prop value ...) ...). Selectors are symbols
;; (element names) or strings (anything with . # : > space).
;;
;; No floats anywhere -- the flonum printer isn't exact. Unit forms take
;; variable arity: one integer is the whole value, two are the whole
;; part and the fraction-in-hundredths. Whole values stay natural (no
;; x100 inflation), fractions stay exact integers (no floats), and every
;; value -- including a leading zero -- is expressible:
;;   (em 1)   -> "1em"     (em 0 92) -> "0.92em"  (em 3 40) -> "3.4em"
;;   (em 3 4) -> "3.04em"  (px 13 50) -> "13.5px" (px 13)   -> "13px"
;;   (pct 50) -> "50%"     (vh 100)  -> "100vh"   (deg 120) -> "120deg"
;; Non-unit values:
;;   integer           -> itself ("0", "650" for z-index / rgb parts)
;;   string            -> literal ("#fff", "solid")
;;   symbol            -> its name (none, inherit, ...)
;;   (dec 1 60)        -> "1.6"   ; a unitless decimal (line-height)
;;   (var ink)         -> "var(--ink)"
;;   (calc V ...)      -> "calc(V ...)"
;;   (rgba 16 20 42 (dec 0 6)) -> "rgba(16,20,42,0.06)"  ; alpha
;;   (A B ...)         -> "A B ..."  ; a space-joined compound value
;; @media / @keyframes / @supports nest rules.
;;
;;   (css->string
;;     `((:root (--bg "#f2f4fa"))
;;       (body (margin 0) (background (var bg)) (line-height "1.6"))
;;       (".nav a" (color (var dim)) (font-size (em 0 92)))
;;       (@media "(max-width: 42em)"
;;         (".nav" (gap (em 1))))))
;;
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (web css)
  (export css->string num->css palette->root)
  (import (rnrs))

  ;; a palette alist ((name value) ...) as a :root rule of custom
  ;; properties -- one binding names a colour for Scheme AND css:
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
  ;; floats -- fractions are written with the two-argument unit form.
  (define (num->css n)
    (cond
     ((string? n) n)
     ((and (integer? n) (exact? n)) (number->string n))
     (else (error 'css "use an exact integer, a two-arg unit form, or a string" n))))

  ;; the fractional part is in hundredths, padded to two digits then
  ;; trailing zeros dropped -- so a leading zero survives and every
  ;; value is expressible: 92 -> ".92", 4 -> ".04", 40 -> ".4", 6 ->
  ;; ".06". More digits give more precision: 625 -> ".625".
  (define (strip-trailing-zeros s)
    (let loop ((i (string-length s)))
      (if (and (> i 0) (char=? (string-ref s (- i 1)) #\0))
          (loop (- i 1))
          (substring s 0 i))))
  (define (frac->css f)
    (let loop ((s (number->string f)))
      (if (< (string-length s) 2)
          (loop (string-append "0" s))
          (strip-trailing-zeros s))))
  ;; a unit value: (em 1) -> "1em"; (em 0 92) -> "0.92em" (whole . frac);
  ;; (em 3 4) -> "3.04em", (em 3 40) -> "3.4em"
  (define (unit->css args suffix)
    (string-append
     (cond
      ((null? args) (error 'css "unit form needs an argument"))
      ((null? (cdr args)) (num->css (car args)))
      (else (string-append (num->css (car args)) "." (frac->css (cadr args)))))
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
         ;; a unitless decimal, same whole/frac convention as units:
         ;; (dec 0 6) -> "0.06" (rgba alpha), (dec 1 6) -> "1.6" (line-height)
         ((eq? h 'dec) (unit->css (cdr v) ""))
         ((eq? h 'var) (string-append "var(--" (symbol->string (cadr v)) ")"))
         ((eq? h 'calc) (string-append "calc(" (join (map val->css (cdr v)) " ") ")"))
         ((eq? h 'rgba) (string-append "rgba(" (join (map val->css (cdr v)) ",") ")"))
         ((eq? h 'rgb) (string-append "rgb(" (join (map val->css (cdr v)) ",") ")"))
         (else (join (map val->css v) " ")))))       ; compound: 1px solid ...
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
