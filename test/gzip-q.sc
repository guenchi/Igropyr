#!chezscheme
;; gzip-acceptable? reads the q= value of a client's Accept-Encoding header; a
;; poisoned q= ("#e1e99999999") must be refused by shape, never converted. Same
;; child-under-timeout construction as test/kdf-cost.sc, witness first.
(import (chezscheme) (igropyr gzip) (only (igropyr libuv) now-ms))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define scheme-bin (or (getenv "SCHEME_BIN") "chez"))
(define dir "/tmp/igropyr-gzip-q")
(system (string-append "rm -rf " dir " && mkdir -p " dir))
(define tree (let ((d (getenv "IGROPYR_TREE"))) (or d ".")))
(define (run-child! root header seconds)
  (let ((f (string-append dir "/child.sc")))
    (call-with-output-file f
      (lambda (o) (display (string-append "(import (chezscheme) (igropyr gzip)) (write (gzip-acceptable? \"" header "\")) (newline)") o)) 'truncate)
    (system (string-append "cd " root " && IGROPYR_CONTRACTS=full CHEZSCHEMELIBDIRS=. CHEZSCHEMELIBEXTS='.sc::.no-obj' timeout "
                           (number->string seconds) " " scheme-bin " --script " f " > " dir "/out.txt 2>&1"))))
(define (child-output) (guard (e (#t "")) (call-with-input-file (string-append dir "/out.txt") get-string-all)))
(define (exit-code r) (if (and (integer? r) (>= r 256)) (quotient r 256) r))
(define poison "gzip;q=#e1e99999999")

;; witness: the supplier call in gzip.sc replaced by the raw conversion
(define witness (string-append dir "/witness"))
(system (string-append "rm -rf " witness " && mkdir -p " witness " && cp " tree "/*.sc " witness "/ && ln -s . " witness "/igropyr"))
(define (witness-built?)
  (eqv? 0 (exit-code (system (string-append "grep -q 'decimal-fraction->number' " witness "/gzip.sc && sed -i.bak 's/(decimal-fraction->number \\(.*\\) [0-9]*)/(string->number \\1)/' " witness "/gzip.sc && ! grep -q 'decimal-fraction->number' " witness "/gzip.sc")))))
(check "witness: the supplier call was found and replaced by the raw conversion" (witness-built?))
(let ((r (exit-code (run-child! witness poison 5))))
  (check "witness: without the guard the poisoned q= hangs the child (timeout exit 124)" (eqv? r 124) r (child-output)))

(let* ((t0 (now-ms)) (r (exit-code (run-child! tree poison 5))) (ms (- (now-ms) t0)))
  (check "poisoned q=: gzip-acceptable? answers without hanging" (eqv? r 0) r (child-output))
  (check "...well within the bound" (< ms 4000) ms))
;; the ordinary semantics, in-process
(check "gzip alone is acceptable" (gzip-acceptable? "gzip"))
(check "q=0 refuses" (not (gzip-acceptable? "gzip;q=0")))
(check "q=0.5 accepts" (gzip-acceptable? "gzip;q=0.5"))
(check "q=1.000 accepts" (gzip-acceptable? "gzip;q=1.000"))
(check "a q= that is not a decimal fraction is treated as unparsable, i.e. not zero" (gzip-acceptable? "gzip;q=abc"))

(if (zero? fails)
    (begin (display "ALL GZIP-Q TESTS PASSED\n") (exit 0))
    (begin (display "GZIP-Q VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
