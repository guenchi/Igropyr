;; Express HTML in Scheme: render SXML to an HTML string.
;;
;; The same SXML vocabulary (web sx) turns into live DOM, this turns
;; into a string -- so one notation authors both static pages and
;; dynamic fragments:
;;
;;   (html->document
;;     `(html (@ (lang "en"))
;;        (head (title "Hi") (style ,(raw "body{margin:0}")))
;;        (body (h1 "Hello") (p "n = " 42))))
;;
;; A node is: a string (escaped text), a number, (raw "literal"),
;; or (tag (@ (attr val) ...) child ...). Void elements emit no close
;; tag; script/style emit raw text; boolean attributes are #t (present)
;; or #f (omitted).
;;
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (web html)
  (export sxml->html html->document html-escape raw raw?)
  (import (rnrs))

  (define void-tags
    '(area base br col embed hr img input link meta param source track wbr))
  (define raw-tags '(script style))
  (define (tag-in? t ls) (and (memq t ls) #t))

  ;; a verbatim node: its string is emitted unescaped
  (define (raw s) (list '%raw s))
  (define (raw? x) (and (pair? x) (eq? (car x) '%raw)))

  (define (write-escaped s specials o)
    (string-for-each
     (lambda (c)
       (let ((hit (assv c specials)))
         (if hit (display (cdr hit) o) (write-char c o))))
     s))
  (define text-specials '((#\& . "&amp;") (#\< . "&lt;") (#\> . "&gt;")))
  (define attr-specials '((#\& . "&amp;") (#\" . "&quot;") (#\< . "&lt;")))

  (define (html-escape s)
    (let ((o (open-output-string)))
      (write-escaped s text-specials o)
      (get-output-string o)))

  (define (->text v)
    (cond
     ((string? v) v)
     ((number? v) (number->string v))
     ((symbol? v) (symbol->string v))
     (else (error 'sxml->html "cannot render as text" v))))

  (define (emit-attrs attrs o)
    (for-each
     (lambda (a)
       (let ((name (symbol->string (car a)))
             (val (cadr a)))
         (cond
          ((eq? val #f) 'omit)                  ; absent attribute
          ((eq? val #t)                         ; boolean attribute
           (write-char #\space o) (display name o))
          (else
           (write-char #\space o) (display name o) (display "=\"" o)
           (write-escaped (->text val) attr-specials o) (write-char #\" o)))))
     attrs))

  (define (emit node o)
    (cond
     ((string? node) (write-escaped node text-specials o))
     ((number? node) (display (number->string node) o))
     ((null? node) 'nothing)
     ((raw? node) (display (cadr node) o))
     ((pair? node)
      (let* ((tag (car node))
             (rest (cdr node))
             (has-attrs (and (pair? rest) (pair? (car rest))
                             (eq? (car (car rest)) '@)))
             (attrs (if has-attrs (cdr (car rest)) '()))
             (kids (if has-attrs (cdr rest) rest))
             (t (symbol->string tag)))
        (write-char #\< o) (display t o)
        (emit-attrs attrs o)
        (cond
         ((tag-in? tag void-tags) (write-char #\> o))
         (else
          (write-char #\> o)
          (if (tag-in? tag raw-tags)
              ;; script/style content is emitted unescaped; a (raw ...)
              ;; node here is fine too -- emit its literal, don't ->text it
              (for-each (lambda (k)
                          (display (if (raw? k) (cadr k) (->text k)) o))
                        kids)
              (for-each (lambda (k) (emit k o)) kids))
          (display "</" o) (display t o) (write-char #\> o)))))
     (else (error 'sxml->html "bad node" node))))

  (define (sxml->html node)
    (let ((o (open-output-string)))
      (emit node o)
      (get-output-string o)))

  (define (html->document node)
    (string-append "<!DOCTYPE html>\n" (sxml->html node) "\n")))
