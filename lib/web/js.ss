;; JavaScript interop for Goeteia.
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (web js)
  (export js-ref? js-global js-undefined js-eq? js-truthy?
          js-get js-set! js-call js-method js-new js-index
          string->js js->string number->js js->number ->js js-eval
          js-await)
  (import (rnrs))

  (define (js-ref? x) (%js-ref? x))
  (define (js-global) (%js-global))
  (define (js-undefined) (%js-undefined))
  (define (js-eq? a b) (%js-eq a b))
  (define (js-truthy? a) (%js-bool a))

  (define ($send-name s)
    (string-for-each (lambda (c) (%js-arg-byte (char->integer c))) s))

  (define (string->js s)
    ($send-name s)
    (%js-string))
  (define (js->string r)
    (let* ((n (%js-str-len r))
           (s (%make-string n)))
      (let loop ((i 0))
        (if (= i n)
            s
            (begin
              (string-set! s i (integer->char (%js-str-byte i)))
              (loop (+ i 1)))))))
  (define (number->js x) (%js-number (exact->inexact x)))
  (define (js->number r)
    (let ((f (%js-to-number r)))
      (if (and (integer? f)
               (fl<? (fixnum->flonum -536870912) f)
               (fl<? f (fixnum->flonum 536870911)))
          (%fl->fx f)
          f)))

  ;; Scheme value -> JS value; closures become callable JS functions
  (define (->js v)
    (cond
     ((js-ref? v) v)
     ((number? v) (number->js v))
     ((string? v) (string->js v))
     ((symbol? v) (string->js (symbol->string v)))
     ((eq? v #t) (js-eval "true"))
     ((eq? v #f) (js-eval "false"))
     ((procedure? v) (%js-fn v))
     (else (error '->js "cannot convert to a JS value" v))))

  ;; the host calls this with the closure when a wrapped JS function
  ;; is invoked; arguments arrive through the cb imports
  (define ($jscb f)
    (let ((n (%js-cb-argc)))
      (let gather ((i (- n 1)) (args '()))
        (if (< i 0)
            (%js-cb-ret
             (guard (e (#t (js-undefined)))
               (->js (apply f args))))
            (gather (- i 1) (cons (%js-cb-arg i) args))))))
  (export $jscb)

  (define (js-get obj name)
    ($send-name name)
    (%js-get obj))
  (define (js-set! obj name v)
    ;; convert first: a string value passes through the same name
    ;; buffer and would swallow a name already staged
    (let ((jv (->js v)))
      ($send-name name)
      (%js-set! obj jv)))
  (define (js-call f thisv . args)
    (for-each (lambda (a) (%js-push (->js a))) args)
    (%js-call f thisv))
  (define (js-method obj name . args)
    (let ((m (js-get obj name)))
      (for-each (lambda (a) (%js-push (->js a))) args)
      (%js-call m obj)))
  (define (js-new ctor . args)
    (for-each (lambda (a) (%js-push (->js a))) args)
    (%js-new ctor))
  (define (js-index obj i)
    (js-get obj (number->string i)))
  (define (js-eval code)
    (js-call (js-get (js-global) "eval") (js-global) code))

  ;; suspend the whole wasm stack on a promise and return its value
  ;; (JSPI). Only legal on the main stack -- not inside a $jscb
  ;; callback re-entered from JS. Without engine support (host fell
  ;; back to the identity import) the promise comes back unawaited.
  (define (js-await p) (%js-await p)))
