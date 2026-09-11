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

;;; (igropyr html) -- render an SXML tree to an HTML string.
;;;
;;;   (html->document
;;;     `(html (@ (lang "en"))
;;;        (head (title "Hi") (style ,(raw "body{margin:0}")))
;;;        (body (h1 "Hello") (p "n = " 42))))
;;;
;;; A node is a string (emitted as escaped text), a number, a (raw
;;; "literal"), or (tag (@ (attr val) ...) child ...). Void elements emit
;;; no closing tag; script and style emit their children unescaped;
;;; boolean attributes are #t (present) or #f (omitted).
;;;
;;; THE #!chezscheme ABOVE IS LOAD-BEARING, not decoration. A library is
;;; read in #!r6rs mode by default, and `@` is not a readable symbol
;;; there -- the attribute marker in every example above would be a read
;;; error. Removing that line does not break a test; it stops the file
;;; being readable at all.

(library (igropyr html)
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

  ;; THE TWO TABLES DIFFER ON PURPOSE. A quote cannot end an attribute
  ;; value that never contains one, and a `>` inside an attribute cannot
  ;; close a tag, so each context escapes what can hurt it and leaves the
  ;; rest alone.
  (define text-specials '((#\& . "&amp;") (#\< . "&lt;") (#\> . "&gt;")))
  (define attr-specials '((#\& . "&amp;") (#\" . "&quot;") (#\< . "&lt;")))

  (define (html-escape s)
    (let-values (((o get) (open-string-output-port)))
      (write-escaped s text-specials o)
      (get)))

  ;; Text for the places that accept one: attribute values, and the
  ;; children of a raw-text element. A node in ordinary element content
  ;; does NOT come through here -- see emit's final clause.
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
          ;; absent attribute
          ((eq? val #f) 'omit)
          ;; boolean attribute: the name alone
          ((eq? val #t)
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
              ;; script and style content is emitted unescaped, and a raw
              ;; node here is emitted for its literal rather than passed
              ;; through ->text
              (for-each (lambda (k)
                          (display (if (raw? k) (cadr k) (->text k)) o))
                        kids)
              (for-each (lambda (k) (emit k o)) kids))
          (display "</" o) (display t o) (write-char #\> o)))))
     ;; A SYMBOL REACHES HERE AND IS REFUSED. It is text only where
     ;; ->text is used -- an attribute value, or a child of script or
     ;; style; in ordinary element content there is no clause for it, so
     ;; (p foo) is an error rather than the text "foo".
     (else (error 'sxml->html "bad node" node))))

  (define (sxml->html node)
    (let-values (((o get) (open-string-output-port)))
      (emit node o)
      (get)))

  (define (html->document node)
    (string-append "<!DOCTYPE html>\n" (sxml->html node) "\n")))
