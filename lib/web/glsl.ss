;; Express GLSL in Scheme: render a shader form list to GLSL source.
;;
;; The (web css) of shaders -- a pure function from s-expressions to a
;; GLSL string, so shaders compose with Scheme's own abstraction
;; (append, map, helper functions) and verify headlessly.
;;
;;   (glsl->string
;;     '((attribute vec2 p)
;;       (uniform float u_time)
;;       (define (main) void
;;         (local float w (+ (* p.x (fl 0 50)) u_time))
;;         (set! gl_Position (vec4 p (fl 0) (fl 1)))
;;         (set! gl_PointSize (fl 2)))))
;;
;; Top-level forms:
;;   (attribute T name) (uniform T name) (varying T name)
;;   (precision P T)
;;   (define (name (T arg) ...) RET stmt ...)
;; Statements:
;;   (local T name expr)   -> "T name = expr;"
;;   (set! lhs expr)       -> "lhs = expr;"
;;   (return expr) (return)
;;   (if c stmt ...)       / (if-else c (stmt ...) (stmt ...))
;;   (discard)
;; Expressions:
;;   symbols pass through verbatim (p, gl_Position, v.xy);
;;   exact integers as themselves; (fl W [F]) is a float literal with
;;   the fraction in hundredths ((fl 2)="2.0", (fl 0 50)="0.5") -- no
;;   Scheme flonums, so no printer noise;
;;   (+ - * /) are infix, (- x) negates; (< > <= >= ==) compare;
;;   anything else (vec4 sin dot mix ...) is a call.
;;
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (web glsl)
  (export glsl->string)
  (import (rnrs))

  (define (join parts sep)
    (cond
     ((null? parts) "")
     ((null? (cdr parts)) (car parts))
     (else (string-append (car parts) sep (join (cdr parts) sep)))))

  (define (strip-trailing-zeros s)
    (let loop ((i (string-length s)))
      (if (and (> i 1) (char=? (string-ref s (- i 1)) #\0))
          (loop (- i 1))
          (substring s 0 i))))
  (define (frac->glsl f)
    (let loop ((s (number->string f)))
      (if (< (string-length s) 2)
          (loop (string-append "0" s))
          (strip-trailing-zeros s))))

  (define (expr->glsl e)
    (cond
     ((symbol? e) (symbol->string e))
     ((and (integer? e) (exact? e)) (number->string e))
     ((string? e) e)
     ((pair? e)
      (let ((h (car e)))
        (cond
         ;; float literal: (fl 2) -> 2.0, (fl 0 50) -> 0.5, (fl 1 25) -> 1.25
         ((eq? h 'fl)
          (string-append (number->string (cadr e)) "."
                         (if (null? (cddr e)) "0" (frac->glsl (caddr e)))))
         ;; unary minus
         ((and (eq? h '-) (null? (cddr e)))
          (string-append "(-" (expr->glsl (cadr e)) ")"))
         ;; infix operators, left-folded, parenthesized
         ((memq h '(+ - * /))
          (string-append "(" (join (map expr->glsl (cdr e))
                                   (string-append " " (symbol->string h) " "))
                         ")"))
         ((memq h '(< > <= >= ==))
          (string-append "(" (expr->glsl (cadr e)) " " (symbol->string h)
                         " " (expr->glsl (caddr e)) ")"))
         ;; a call: vec4(...), sin(...), dot(...), user functions
         (else
          (string-append (symbol->string h) "("
                         (join (map expr->glsl (cdr e)) ", ") ")")))))
     (else (error 'glsl "bad expression" e))))

  (define (stmt->glsl s)
    (let ((h (car s)))
      (case h
        ((local)
         (string-append (symbol->string (cadr s)) " "
                        (symbol->string (caddr s)) " = "
                        (expr->glsl (cadddr s)) "; "))
        ((set!)
         (string-append (expr->glsl (cadr s)) " = "
                        (expr->glsl (caddr s)) "; "))
        ((return)
         (if (null? (cdr s)) "return; "
             (string-append "return " (expr->glsl (cadr s)) "; ")))
        ((discard) "discard; ")
        ((if)
         (string-append "if (" (expr->glsl (cadr s)) ") { "
                        (apply string-append (map stmt->glsl (cddr s)))
                        "} "))
        ((if-else)
         (string-append "if (" (expr->glsl (cadr s)) ") { "
                        (apply string-append (map stmt->glsl (caddr s)))
                        "} else { "
                        (apply string-append (map stmt->glsl (cadddr s)))
                        "} "))
        (else (error 'glsl "bad statement" s)))))

  (define (param->glsl p)                 ; (T name)
    (string-append (symbol->string (car p)) " " (symbol->string (cadr p))))

  (define (form->glsl f)
    (case (car f)
      ((attribute uniform varying)
       (string-append (symbol->string (car f)) " "
                      (symbol->string (cadr f)) " "
                      (symbol->string (caddr f)) "; "))
      ((precision)
       (string-append "precision " (symbol->string (cadr f)) " "
                      (symbol->string (caddr f)) "; "))
      ((define)
       ;; (define (name (T a) ...) RET stmt ...)
       (let* ((head (cadr f))
              (name (car head))
              (params (cdr head))
              (ret (caddr f))
              (body (cdddr f)))
         (string-append (symbol->string ret) " " (symbol->string name) "("
                        (join (map param->glsl params) ", ") ") { "
                        (apply string-append (map stmt->glsl body))
                        "} ")))
      (else (error 'glsl "bad top-level form" f))))

  (define (glsl->string forms)
    (apply string-append (map form->glsl forms))))
