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
;;   (for (T name init cond step) stmt ...)
;;                         -> "for (T name = init; cond; name = step)"
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
  (export glsl->string glsl-attributes glsl-uniforms glsl-varyings
          glsl300-vs->string glsl300-fs->string)
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
         ;; array indexing: (at u_joints i) -> u_joints[i]
         ((eq? h 'at)
          (string-append (expr->glsl (cadr e)) "["
                         (expr->glsl (caddr e)) "]"))
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
        ((for)
         ;; (for (T name init cond step) stmt ...) -- step is an
         ;; expression assigned back to name each iteration
         (let* ((h (cadr s))
                (ty (car h)) (name (cadr h)) (init (caddr h))
                (c (cadddr h)) (step (list-ref h 4)))
           (string-append "for (" (symbol->string ty) " "
                          (symbol->string name) " = " (expr->glsl init)
                          "; " (expr->glsl c) "; "
                          (symbol->string name) " = " (expr->glsl step)
                          ") { "
                          (apply string-append (map stmt->glsl (cddr s)))
                          "} ")))
        (else (error 'glsl "bad statement" s)))))

  (define (param->glsl p)                 ; (T name)
    (string-append (symbol->string (car p)) " " (symbol->string (cadr p))))

  (define (form->glsl f)
    (case (car f)
      ((attribute uniform varying)
       (if (pair? (cadr f))              ; (array T N) declarations
           (string-append (symbol->string (car f)) " "
                          (symbol->string (cadr (cadr f))) " "
                          (symbol->string (caddr f))
                          "[" (number->string (caddr (cadr f))) "]; ")
           (string-append (symbol->string (car f)) " "
                          (symbol->string (cadr f)) " "
                          (symbol->string (caddr f)) "; ")))
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
    (apply string-append (map form->glsl forms)))

  ;; ---- the ES 3.00 dialect: the same forms, respelled ----
  ;; The form language is dialect-neutral; these render it as
  ;; "#version 300 es" source: attribute -> in, varying -> out (VS)
  ;; / in (FS), gl_FragColor -> a declared output, texture2D and
  ;; textureCube -> the unified texture().  (uniform-block Name
  ;; (T field) ...) becomes a std140 uniform block -- the syntax
  ;; UBOs need, which 1.00 does not have.
  (define ($glsl-subst x alist)
    (cond
     ((symbol? x) (let ((hit (assq x alist))) (if hit (cdr hit) x)))
     ((pair? x) (cons ($glsl-subst (car x) alist)
                      ($glsl-subst (cdr x) alist)))
     (else x)))

  (define $glsl300-renames
    '((texture2D . texture) (textureCube . texture)
      (gl_FragColor . goe_FragColor)))

  (define ($form300->glsl f stage)
    (case (car f)
      ((attribute varying)
       (let ((kw (if (eq? (car f) 'attribute)
                     "in"
                     (if (eq? stage 'vertex) "out" "in"))))
         (if (pair? (cadr f))
             (string-append kw " " (symbol->string (cadr (cadr f))) " "
                            (symbol->string (caddr f))
                            "[" (number->string (caddr (cadr f))) "]; ")
             (string-append kw " " (symbol->string (cadr f)) " "
                            (symbol->string (caddr f)) "; "))))
      ((uniform-block)
       ;; members carry explicit highp: the vertex default is highp,
       ;; a mediump fragment default would otherwise disagree, and
       ;; block layouts must match exactly across stages
       (string-append
        "layout(std140) uniform " (symbol->string (cadr f)) " { "
        (apply string-append
               (map (lambda (m)
                      (string-append "highp "
                                     (symbol->string (car m)) " "
                                     (symbol->string (cadr m)) "; "))
                    (cddr f)))
        "}; "))
      (else (form->glsl f))))

  (define ($glsl300 forms stage head)
    (string-append
     "#version 300 es\n" head
     (apply string-append
            (map (lambda (f) ($form300->glsl f stage))
                 ($glsl-subst forms $glsl300-renames)))))

  (define (glsl300-vs->string forms)
    ($glsl300 forms 'vertex ""))
  (define (glsl300-fs->string forms)
    ($glsl300 forms 'fragment "out highp vec4 goe_FragColor; "))

  ;; the interface, extracted: shader forms are data, so the
  ;; attribute/uniform declarations that (web fx) wires up come from
  ;; the same list that rendered the source -- one source of truth
  (define ($glsl-components t)          ; f32 components per attribute
    (case t
      ((float) 1) ((vec2) 2) ((vec3) 3) ((vec4) 4)
      (else (error 'glsl "no component count for attribute type" t))))

  (define (glsl-attributes forms)       ; ((name type count) ...) in order
    (let loop ((fs forms))
      (cond
       ((null? fs) '())
       ((eq? (caar fs) 'attribute)
        (let ((ty (cadar fs)) (name (caddr (car fs))))
          (cons (list name ty ($glsl-components ty)) (loop (cdr fs)))))
       (else (loop (cdr fs))))))

  (define (glsl-uniforms forms)         ; ((name type) ...) in order
    (let loop ((fs forms))
      (cond
       ((null? fs) '())
       ((eq? (caar fs) 'uniform)
        (cons (list (caddr (car fs)) (cadar fs)) (loop (cdr fs))))
       (else (loop (cdr fs))))))

  (define (glsl-varyings forms)         ; names in order -- what a
    (let loop ((fs forms))              ; transform feedback captures
      (cond
       ((null? fs) '())
       ((eq? (caar fs) 'varying)
        (cons (caddr (car fs)) (loop (cdr fs))))
       (else (loop (cdr fs)))))))
