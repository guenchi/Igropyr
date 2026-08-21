#!chezscheme
;;; (igropyr sexpr) tests: whitelist round-trips, hostile input.

(import (chezscheme) (igropyr sexpr))

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))
(define (round-trips? x)
  (equal? x (string->sexpr (sexpr->string x))))
(define (parse-fails? s)
  (guard (e ((vector? e) (eq? (vector-ref e 0) 'sexpr-error)))
    (string->sexpr s)
    #f))
(define (write-fails? x)
  (guard (e ((vector? e) (eq? (vector-ref e 0) 'sexpr-error)))
    (sexpr->string x)
    #f))

;; round trips over the whitelist
(check "list" (round-trips? '(get-user 42)))
(check "nested" (round-trips? '(user (id . 42) (name . "ada") (roles admin editor))))
(check "dotted" (round-trips? '(a . b)))
(check "alist" (round-trips? '(("x" . 1) ("y" . 2))))
(check "empty" (round-trips? '()))
(check "bools" (round-trips? '(#t #f)))
(check "negatives" (round-trips? '(-1 0 42 -99999999999999999999999999)))
(check "bignum" (round-trips? (expt 10 40)))
(check "ratio" (round-trips? '(1/3 -7/2)))
(check "string-escapes" (round-trips? '("say \"hi\"" "back\\slash")))
(check "string-newline" (round-trips? (list (string #\a #\newline #\b))))
(check "symbols" (round-trips? '(fl* set! <=? %raw a.b :kw @x)))

;; the exact wire text of the doc example
(check "wire-text"
       (string=? (sexpr->string '(user (id . 42) (name . "ada")))
                 "(user (id . 42) (name . \"ada\"))"))

;; reader accepts \n \t \r escapes (Goeteia may emit literal newlines;
;; both must parse)
(check "read-escapes"
       (equal? (string->sexpr "(\"a\\nb\" \"c\\td\")")
               (list (string #\a #\newline #\b) (string #\c #\tab #\d))))

;; hostile input fails loudly, never evaluates
(check "no-eval" (parse-fails? "#;(walk in) 42"))
(check "no-vector" (parse-fails? "#(1 2 3)"))
(check "no-char" (parse-fails? "#\\a"))
(check "no-float" (parse-fails? "(1.5)"))
(check "no-quote-hash" (parse-fails? "#'x"))
(check "unterminated" (parse-fails? "(a (b"))
(check "trailing" (parse-fails? "(a) (b)"))
(check "bad-escape" (parse-fails? "\"\\q\""))
(check "depth-bomb"
       (parse-fails?
        (let loop ((i 0) (s "42"))
          (if (= i 100) s (loop (+ i 1) (string-append "(" s ")"))))))
(check "depth-ok"
       (equal? 42 (let loop ((i 0) (x 42) (s "42"))
                    (if (= i 50)
                        (let unwrap ((v (string->sexpr s)) (k 50))
                          (if (zero? k) v (unwrap (car v) (- k 1))))
                        (loop (+ i 1) x (string-append "(" s ")"))))))

;; the writer refuses non-whitelist data (payloads stay data)
(check "no-write-float" (write-fails? 1.5))
(check "no-write-vector" (write-fails? (vector 1 2)))
(check "no-write-proc" (write-fails? car))
(check "no-write-weird-symbol" (write-fails? (string->symbol "has space")))
(check "no-write-cycle"
       (write-fails? (let ((x (list 1 2))) (set-cdr! (cdr x) x) x)))

;; ---- extended mode: vectors, bytevectors, finite flonums ---------------

(define (ext-round-trips? x)
  (equal? x (string->sexpr-extended (sexpr->string-extended x))))
(define (ext-parse-fails? s)
  (guard (e ((vector? e) (eq? (vector-ref e 0) 'sexpr-error)))
    (string->sexpr-extended s)
    #f))
(define (ext-write-fails? x)
  (guard (e ((vector? e) (eq? (vector-ref e 0) 'sexpr-error)))
    (sexpr->string-extended x)
    #f))

(check "ext-vector" (ext-round-trips? '#(1 two "three" #t)))
(check "ext-vector-empty" (ext-round-trips? '#()))
(check "ext-vector-nested" (ext-round-trips? '#(#(1 2) (a . #(b)) #vu8(7))))
(check "ext-bytevector" (ext-round-trips? (bytevector 0 127 255)))
(check "ext-bytevector-empty" (ext-round-trips? (bytevector)))
(check "ext-flonums"
       (ext-round-trips?
        '(0.5 -3.25 1e300 1.7976931348623157e308 5e-324 -0.0 100.0)))
(check "ext-flonum-bit-exact"
       (eqv? 0.1 (string->sexpr-extended (sexpr->string-extended 0.1))))
(check "ext-actor-message" (ext-round-trips? '#(tcp-data #vu8(1 2 3))))
(check "ext-strict-subset"
       (ext-round-trips? '(user (id . 42) (name . "ada") 1/3 #t)))
(check "ext-wire-text"
       (string=? (sexpr->string-extended '#(1 #vu8(2 3) 4.5))
                 "#(1 #vu8\"AgM=\" #f8\"AAAAAAAAEkA=\")"))
(check "ext-f8-decode"
       (eqv? 4.5 (string->sexpr-extended "#f8\"AAAAAAAAEkA=\"")))

;; extended mode still rejects everything outside ITS whitelist
(check "ext-no-decimal-float" (ext-parse-fails? "4.5"))  ; #f8 is the only form
(check "ext-no-inf-read" (ext-parse-fails? "1e999"))
;; inf and nan DO cross now -- they are ordinary IEEE bit patterns
(check "ext-inf-round-trip"
       (eqv? +inf.0 (string->sexpr-extended (sexpr->string-extended +inf.0))))
(check "ext-nan-round-trip"
       (let ((r (string->sexpr-extended (sexpr->string-extended +nan.0))))
         (and (flonum? r) (nan? r))))
(check "ext-f8-wrong-length" (ext-parse-fails? "#f8\"AgM=\""))   ; 3 bytes
(check "ext-f8-unterminated" (ext-parse-fails? "#f8\"AAAAAAAAEkA="))
(check "ext-false-still-false" (equal? '(#f #t) (string->sexpr-extended "(#f #t)")))
(check "strict-no-f8" (parse-fails? "#f8\"AAAAAAAAEkA=\""))
(check "ext-no-char" (ext-parse-fails? "#\\a"))
(check "ext-no-eval" (ext-parse-fails? "#;(walk in) 42"))
(check "ext-no-dotted-vector" (ext-parse-fails? "#(1 . 2)"))
(check "ext-vector-unterminated" (ext-parse-fails? "#(1 2"))
(check "ext-bv-base64-decode"                          ; "AgM=" -> bytes 2,3
       (equal? (bytevector 2 3) (string->sexpr-extended "#vu8\"AgM=\"")))
(check "ext-bv-base64-empty"
       (equal? (bytevector) (string->sexpr-extended "#vu8\"\"")))
(check "ext-bv-no-paren" (ext-parse-fails? "#vu8(1 2 3)"))   ; old form gone
(check "ext-bv-bad-base64" (ext-parse-fails? "#vu8\"@@@\""))  ; not base64
(check "ext-bv-unterminated" (ext-parse-fails? "#vu8\"AgM"))  ; no closing "
(check "ext-bv-bad-prefix" (ext-parse-fails? "#vu9\"\""))
(check "ext-no-write-proc" (ext-write-fails? car))
(check "ext-depth-bomb"
       (ext-parse-fails?
        (let loop ((i 0) (s "42"))
          (if (= i 100) s (loop (+ i 1) (string-append "#(" s ")"))))))

;; ---- writer/reader symbol agreement ------------------------------------
;; The writer's question is "how will the READER read this name back",
;; not "does Chez think it is a number". The gap between those two
;; judgments was a self-incompatible wire: |0x10| went out bare and came
;; back "bad number". A numeric-shaped name (leading digit, or '-' then
;; a digit) is read as a number or refused -- never as a symbol -- so
;; the writer must refuse it, in both modes.
(check "no-write-hexlike-symbol" (write-fails? (string->symbol "0x10")))
(check "no-write-digitlead-symbol" (write-fails? (string->symbol "12abc")))
(check "no-write-zero-denom-symbol" (write-fails? (string->symbol "1/0")))
(check "no-write-neg-digitlead-symbol" (write-fails? (string->symbol "-1x")))
(check "ext-no-write-hexlike-symbol"
       (ext-write-fails? (string->symbol "0x10")))
;; the old refusals stay refusals
(check "no-write-number-named-symbol" (write-fails? (string->symbol "12")))
(check "no-write-dot-symbol" (write-fails? (string->symbol ".")))
;; |+i| is Chez-number but NOT numeric-shaped: its refusal is supplied
;; ONLY by the retained string->number check. Without this pin, an
;; implementation that swapped that check for numeric-shape (instead of
;; adding to it) would pass every other case here.
(check "no-write-chez-number-symbol" (write-fails? (string->symbol "+i")))
;; and every name the writer DOES pass must read back as itself -- the
;; round-trip property the refusals exist to protect
(check "symbol-write-read-identity"
       (for-all (lambda (name)
                  (let ((sym (string->symbol name)))
                    (eq? sym (string->sexpr (sexpr->string sym)))))
                '("a1" "x0x10" "a.b" "-" "+" "..." "-a" "a-1"
                  "<=?" ":kw" "@x" "%raw" "a/b" "-x/y")))

;; ---- depth: the exact boundary, both directions ------------------------
;; depth-bomb (100) and depth-ok (50) bracket the limit without pinning
;; it. 64 must round-trip and 65 must be refused by BOTH ends -- a
;; writer that allowed 65 would emit wire the reader rejects, the same
;; asymmetry class as the numeric-shape and token-length fixes.
(check "depth-64-roundtrips"
       (let ((x (let lp ((k 64) (x 42)) (if (zero? k) x (lp (- k 1) (list x))))))
         (equal? x (string->sexpr (sexpr->string x)))))
(check "no-write-depth-65"
       (write-fails?
        (let lp ((k 65) (x 42)) (if (zero? k) x (lp (- k 1) (list x))))))
(check "no-read-depth-65"
       (parse-fails?
        (let lp ((k 65) (s "42"))
          (if (zero? k) s (lp (- k 1) (string-append "(" s ")"))))))

;; ---- token length: the writer honours the reader's bound ---------------
;; The reader caps bare tokens at 65536 chars ("token too long"). A
;; writer without the same cap emits wire the peer must reject -- the
;; error surfaces at the WRONG end, after the bytes crossed. The bound
;; is measured on the whole token, sign included: a length check that
;; counts digits only passes the negative case below.
(check "sym-at-bound-roundtrips"
       (let ((sym (string->symbol (make-string 65536 #\a))))
         (eq? sym (string->sexpr (sexpr->string sym)))))
(check "no-write-sym-over-bound"
       (write-fails? (string->symbol (make-string 65537 #\a))))
(check "int-at-bound-roundtrips"
       (let ((n (- (expt 10 65536) 1)))          ; 65536 digits
         (= n (string->sexpr (sexpr->string n)))))
(check "no-write-int-over-bound"
       (write-fails? (expt 10 65536)))            ; 65537 digits
(check "no-write-neg-int-at-digit-bound"
       (write-fails? (- (expt 10 65535))))        ; sign makes it 65537
(check "no-write-ratio-over-bound"
       (write-fails? (/ (expt 10 65536) 3)))

;; ---- adversarial name corpus (61 names, cross-checked downstream) ------
;; The accept/refuse split below was measured against this
;; implementation and independently matched, name for name, by two
;; downstream codecs. A name moving sides here is a wire-compat break,
;; not a tuning knob. Written names must read back as themselves --
;; the property the refusals exist to protect.
(for-each
 (lambda (n)
   (check (string-append "corpus-written |" n "|")
          (let ((sym (string->symbol n)))
            (eq? sym (string->sexpr (sexpr->string sym))))))
 '("--1" "+" "-" "..." "a1" "/" ".foo" "a.b" "OK" "_x" ":kw" "a@b"
   "%x" "^x" "~x" "&x" "*x*" "<=>" "set!" "null?" "list->vector"
   "e" "inf.0" "nan.0" "+." ".." "ok"))
(for-each
 (lambda (n)
   (check (string-append "corpus-refused |" n "|")
          (write-fails? (string->symbol n))))
 (list "12" "-7" "1.5" "-7/2" "." "0x10" "1e3" "12abc" "+1" "-0" ".5"
       "1." "1E3" "1e+3" "+inf.0" "-inf.0" "+nan.0" "1/2" "" "#x10"
       "1+2i" "007" "-007" "1/-2" "1//2" "1/0" "a b" "7"
       (string #\a #\tab #\b) (string #\a #\newline #\b)
       "a(b" "a\"b" "\x4e2d;\x6587;" "\x1f600;"))

;; the extension must not leak into strict mode
(check "strict-still-no-vector" (parse-fails? "#(1 2 3)"))
(check "strict-still-no-bv" (parse-fails? "#vu8\"AgM=\""))
(check "strict-still-no-float" (parse-fails? "1.5"))
(check "strict-still-no-write-bv" (write-fails? (bytevector 1)))

(if (zero? failures)
    (begin (display "sexpr: all tests passed") (newline))
    (begin (display failures) (display " failures") (newline) (exit 1)))
