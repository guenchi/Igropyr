#!chezscheme
;; sexpr->string must refuse a symbol whose name is a poisoned numeral without
;; converting it: wire-symbol? asked string->number BEFORE walking the name's
;; characters, so (string->symbol "#e1e99999999") serialized never returned.
;; The writer is reached by any text the process turned into a symbol, the
;; reader never runs on that path. Child-under-timeout construction as in
;; test/kdf-cost.sc, witness first: a shadow tree whose wire-symbol? has the
;; raw conversion restored in front of the walk must hang (124).
(import (chezscheme) (igropyr sexpr) (only (igropyr libuv) now-ms))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define scheme-bin (or (getenv "SCHEME_BIN") "chez"))
(define dir "/tmp/igropyr-sexpr-poison")
(system (string-append "rm -rf " dir " && mkdir -p " dir))
(define tree (let ((d (getenv "IGROPYR_TREE"))) (or d ".")))
(define (run-child! root name seconds)
  (let ((f (string-append dir "/child.sc")))
    (call-with-output-file f
      (lambda (o) (display (string-append "(import (chezscheme) (igropyr sexpr)) (display \"pre \") (flush-output-port) (write (guard (e (#t (if (and (vector? e) (eq? (vector-ref e 0) 'sexpr-error)) (vector-ref e 1) 'other))) (sexpr->string (list 'a (string->symbol \"" name "\"))))) (newline)") o)) 'truncate)
    (system (string-append "cd " root " && IGROPYR_CONTRACTS=full CHEZSCHEMELIBDIRS=. CHEZSCHEMELIBEXTS='.sc::.no-obj' timeout "
                           (number->string seconds) " " scheme-bin " --script " f " > " dir "/out.txt 2>&1"))))
(define (child-output) (guard (e (#t "")) (call-with-input-file (string-append dir "/out.txt") get-string-all)))
(define (exit-code r) (if (and (integer? r) (>= r 256)) (quotient r 256) r))
(define poison "#e1e99999999")

;; witness: the shadow tree's wire-symbol? converts before it walks; the anchor
;; is the guard's own marker line so that a rewrite of the walk cannot leave a
;; stale witness standing. The conversion's result feeds a side effect: an
;; unused (string->number s) is dropped at optimize-level 3 and the witness
;; would then stand for nothing
(define witness (string-append dir "/witness"))
(system (string-append "rm -rf " witness " && mkdir -p " witness " && cp " tree "/*.sc " witness "/ && ln -s . " witness "/igropyr"))
(define (witness-built?)
  (eqv? 0 (exit-code (system (string-append "grep -q '(define (wire-symbol? s)' " witness "/sexpr.sc && sed -i.bak 's/(define (wire-symbol? s)/(define (wire-symbol? s) (if (string->number s) (display \"\" (current-error-port)) (display \"\" (current-error-port)))/' " witness "/sexpr.sc && grep -q '(define (wire-symbol? s) (if (string->number s)' " witness "/sexpr.sc")))))
(check "witness: the raw conversion was put in front of the walk in the shadow tree" (witness-built?))
(let ((r (exit-code (run-child! witness poison 5))))
  ;; the marker attributes the 124 to the call, not to a stalled start-up
  (check "witness: with the conversion first the poisoned name hangs the child (timeout exit 124, after the marker)" (and (eqv? r 124) (equal? (child-output) "pre ")) r (child-output)))

(let* ((t0 (now-ms)) (r (exit-code (run-child! tree poison 5))) (ms (- (now-ms) t0)))
  (check "poisoned symbol name: sexpr->string refuses with its own error, no hang" (and (eqv? r 0) (equal? (child-output) "pre \"symbol not wire-safe\"\n")) r (child-output))
  (check "...well within the bound" (< ms 4000) ms))
;; the ordinary semantics, in-process
(check "an ordinary symbol serializes" (equal? (sexpr->string '(a b)) "(a b)"))
(check "a numeral-shaped name is refused (reader would read a number)" (guard (e (#t #t)) (sexpr->string (list (string->symbol "12abc"))) #f))
(check "a name the raw conversion accepts is still refused after the reorder (+i: the writer over-refuses on purpose)" (guard (e (#t #t)) (sexpr->string (list (string->symbol "+i"))) #f))
(check "a short radix form is refused (pins the answer; the raw conversion is cheap here)" (guard (e (#t #t)) (sexpr->string (list (string->symbol "#e1024"))) #f))
(check "a name with an exponent but no # is refused (by numeric-shape?, pins the answer)" (guard (e (#t #t)) (sexpr->string (list (string->symbol "1e99999999"))) #f))

(if (zero? fails)
    (begin (display "ALL SEXPR-POISON TESTS PASSED\n") (exit 0))
    (begin (display "SEXPR-POISON VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
