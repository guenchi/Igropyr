;; DOM sugar over (web js).
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (web dom)
  (export window document body
          get-element-by-id query-selector create-element make-text
          append-child! replace-child! insert-before! remove-child!
          remove-all-children!
          set-inner-html! inner-text set-text!
          set-attribute! set-style!
          add-event-listener! console-log alert)
  (import (rnrs) (web js))

  (define (window) (js-global))
  (define (document) (js-get (js-global) "document"))
  (define (body) (js-get (document) "body"))
  (define (get-element-by-id id)
    (js-method (document) "getElementById" id))
  (define (query-selector sel)
    (js-method (document) "querySelector" sel))
  (define (create-element tag)
    (js-method (document) "createElement" tag))
  (define (make-text s)
    (js-method (document) "createTextNode" s))
  (define (append-child! parent child)
    (js-method parent "appendChild" child))
  (define (replace-child! parent new old)
    (js-method parent "replaceChild" new old))
  (define (insert-before! parent new ref)
    (js-method parent "insertBefore" new ref))
  (define (remove-child! parent child)
    (js-method parent "removeChild" child))
  (define (remove-all-children! el)
    (js-set! el "textContent" ""))
  (define (set-inner-html! el s) (js-set! el "innerHTML" s))
  (define (inner-text el) (js->string (js-get el "innerText")))
  (define (set-text! el s) (js-set! el "textContent" s))
  (define (set-attribute! el name v)
    (js-method el "setAttribute" name v))
  (define (set-style! el prop v)
    (js-set! (js-get el "style") prop v))
  (define (add-event-listener! el event handler)
    (js-method el "addEventListener" event handler))
  (define (console-log x)
    (js-method (js-get (js-global) "console") "log"
               (if (string? x) x (with-output-to-string (lambda () (write x))))))
  (define (alert s)
    (js-method (js-global) "alert" s)))
