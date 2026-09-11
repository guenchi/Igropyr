#!chezscheme
;; password-verify must refuse a poisoned cost field without converting it:
;; (string->number "#e1e99999999") builds 10^99999999 exactly and never returns,
;; so a stored hash carrying that text hung the whole process at the next login.
;; The verification runs in a CHILD chez under `timeout`: a hang is exit 124,
;; the guarded library answers #f and exits 0. The WITNESS runs first: the same
;; child against a copy of kdf.sc with the guard (seven cost fields) replaced by the raw conversion
;; must hang (124) -- that proves the stimulus reaches the conversion, so the
;; green that follows is the guard's and not the fixture's.
(import (chezscheme) (igropyr kdf) (only (igropyr libuv) now-ms))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define scheme-bin (or (getenv "SCHEME_BIN") "chez"))
(define dir "/tmp/igropyr-kdf-cost")
(system (string-append "rm -rf " dir " && mkdir -p " dir "/igropyr"))
(define poison "scrypt$#e1e99999999$8$1$AA==$AA==")
;; the child: verify `stored` and print the answer; run with the library resolved
;; from `root` (the tree, or the witness copy)
(define (child-script stored)
  (string-append
    "(import (chezscheme) (igropyr kdf)) (write (password-verify \"hunter2\" \"" stored "\")) (newline)"))
(define (run-child! root stored seconds)
  (let ((f (string-append dir "/child.sc")))
    (call-with-output-file f (lambda (o) (display (child-script stored) o)) 'truncate)
    (system (string-append "cd " root " && IGROPYR_CONTRACTS=full CHEZSCHEMELIBDIRS=. CHEZSCHEMELIBEXTS='.sc::.no-obj' timeout "
                           (number->string seconds) " " scheme-bin " --script " f " > " dir "/out.txt 2>&1"))))
(define (child-output) (guard (e (#t "")) (call-with-input-file (string-append dir "/out.txt") get-string-all)))
(define (exit-code r) (if (and (integer? r) (>= r 256)) (quotient r 256) r))
(define tree (let ((d (getenv "IGROPYR_TREE"))) (or d ".")))

;; ---- witness: the guard removed, the poison hangs the child --------------------
;; a copy of the tree's library files with kdf.sc's supplier replaced by the raw
;; conversion; if the anchor is absent the witness cannot be built and says so
(define witness (string-append dir "/witness"))
(system (string-append "rm -rf " witness " && mkdir -p " witness " && cp " tree "/*.sc " witness "/ && ln -s . " witness "/igropyr"))
(define (witness-built?)
  (let ((r (system (string-append "grep -q 'define (cost-field->number' " witness "/kdf.sc"))))
    (and (eqv? (exit-code r) 0)
         (eqv? (exit-code (system (string-append "sed -i.bak 's/(define (cost-field->number s) .*/(define (cost-field->number s) (string->number s))/' " witness "/kdf.sc && grep -q '(define (cost-field->number s) (string->number s))' " witness "/kdf.sc"))) 0))))
(check "witness: the guard's definition was found and replaced by the raw conversion" (witness-built?))
(let ((r (exit-code (run-child! witness poison 5))))
  (check "witness: without the guard the poisoned field hangs the child (timeout exit 124)" (eqv? r 124) r (child-output)))

;; ---- the guarded library answers #f within the bound ------------------------------
(let* ((t0 (now-ms)) (r (exit-code (run-child! tree poison 5))) (ms (- (now-ms) t0)))
  (check "poisoned scrypt N: password-verify answers #f, no hang" (and (eqv? r 0) (equal? (child-output) "#f\n")) r (child-output))
  (check "...well within the bound" (< ms 4000) ms))
(let ((r (exit-code (run-child! tree "pbkdf2-sha256$#e1e99999999$AA==$AA==" 5))))
  (check "poisoned pbkdf2 iters: #f, no hang" (and (eqv? r 0) (equal? (child-output) "#f\n")) r (child-output)))
(let ((r (exit-code (run-child! tree "argon2id$1$#e1e99999999$1$AA==$AA==" 5))))
  (check "poisoned argon2id m: #f, no hang" (and (eqv? r 0) (equal? (child-output) "#f\n")) r (child-output)))
;; all seven cost fields, not only the first of each family
(for-each
  (lambda (label stored)
    (let ((r (exit-code (run-child! tree stored 5))))
      (check label (and (eqv? r 0) (equal? (child-output) "#f\n")) r (child-output))))
  '("poisoned scrypt r: #f, no hang" "poisoned scrypt p: #f, no hang"
    "poisoned argon2id t: #f, no hang" "poisoned argon2id p: #f, no hang")
  '("scrypt$1024$#e1e99999999$1$AA==$AA==" "scrypt$1024$8$#e1e99999999$AA==$AA=="
    "argon2id$#e1e99999999$1$1$AA==$AA==" "argon2id$1$1$#e1e99999999$AA==$AA=="))

;; ---- twins: a real hash still verifies; a leading zero keeps its value; junk refused --
(let* ((s (password-hash "hunter2" 'scrypt '((N . 1024))))
       (parts (let split ((s s) (acc '()))
                (let ((i (let scan ((k 0)) (cond ((= k (string-length s)) #f) ((char=? (string-ref s k) #\$) k) (else (scan (+ k 1)))))))
                  (if i (split (substring s (+ i 1) (string-length s)) (cons (substring s 0 i) acc)) (reverse (cons s acc))))))
       (rejoin (lambda (ps) (let loop ((ps ps) (acc "")) (if (null? ps) acc (loop (cdr ps) (if (string=? acc "") (car ps) (string-append acc "$" (car ps))))))))
       (with-n (lambda (n) (rejoin (cons (car parts) (cons n (cddr parts)))))))
  (check "twin: the real hash verifies" (password-verify "hunter2" s))
  (check "twin: N written with a leading zero verifies (value kept)" (password-verify "hunter2" (with-n "01024")))
  (check "twin: N with a trailing letter is refused" (not (password-verify "hunter2" (with-n "1024x"))))
  (check "twin: N in exponent notation is refused" (not (password-verify "hunter2" (with-n "1e3"))))
  (check "twin: N with a radix prefix is refused" (not (password-verify "hunter2" (with-n "#e1024"))))
  ;; the three twins above and this one pin the answer, not the guard: they are
  ;; refused by the raw conversion or the later ceiling as well. The "#e1024"
  ;; twin is the one the raw conversion accepts, so it alone discriminates here
  (check "twin: an eleven-digit N is refused" (not (password-verify "hunter2" (with-n "10000000000"))))
  (check "twin: the wrong password is still refused" (not (password-verify "wrong" s))))

(if (zero? fails)
    (begin (display "ALL KDF-COST TESTS PASSED\n") (exit 0))
    (begin (display "KDF-COST VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))
