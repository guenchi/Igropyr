#!chezscheme
;;; Every byte the writer emits, judged by an independent grammar.
;;;
;;; WHY THIS FILE EXISTS. An enumeration of the writer's decision points
;;; found the string-escape and container-structure paths almost wholly
;;; unowned: the suites' wrote? asked only whether a string came back.
;;; Five mutations were measured green under that judge -- deleting the
;;; quote escape, writing only an object's first member, a semicolon for
;;; the comma, and rewriting the three literals -- every one an invalid
;;; or silently different document. The judge below is rfc-json-text?
;;; from test/json-number-oracles.sc, written from RFC 8259 and not from
;;; this library's reader, whose two deliberate deviations (leading
;;; zeros, raw controls) would otherwise excuse the writer's output in
;;; exactly the places this file exists to check.
;;;
;;; Two kinds of cell, and both are needed: the VALIDATOR cells prove
;;; the output is legal JSON at all; the EXACT-TEXT cells prove it is
;;; the right document -- a writer that emitted {"b":2} for (("a" . 1))
;;; would be perfectly legal and perfectly wrong.

(import (chezscheme) (igropyr json)
        (only (igropyr test json-number-oracles) rfc-json-text?))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))
(define (shown x) (let ((o (open-output-string))) (write x o) (get-output-string o)))

;; ---- the sweep: everything the writer accepts must serialize legally ---
;; A zoo of accepted values, nested through both container kinds. The
;; denominator is asserted: zero failures over zero values reads like a
;; pass, so the count is pinned before the verdict.
(let ((zoo (list '() (vector) "s" "" 0 -1 1.5 5e-324 #t #f 'null
                 (vector 1 "two" #t 'null (vector))
                 '(("k" . "v"))
                 '(("a" . 1) ("b" . #(1 2)) ("c" . (("d" . null))))
                 (vector '(("x" . #f)) (vector "y"))
                 '(("empty-obj" . ()) ("empty-arr" . #()))))
      (bad '()) (count 0))
  (for-each
    (lambda (v)
      (set! count (+ count 1))
      (let ((t (json->string v)))
        (unless (rfc-json-text? t)
          (set! bad (cons (list v t) bad)))))
    zoo)
  (check "every accepted value serializes to grammatical JSON"
         (null? bad) (reverse bad))
  (check "...and the sweep visited the whole zoo"
         (= count 16) count))

;; ---- strings: every escape decision, by exact text ---------------------
;; The escape table is a per-character dispatch, so each row is its own
;; decision point and gets its own pinned output. The writer's spelling
;; choices are contract: \n \r \t short, backspace and formfeed as
;; four-hex-digit escapes with UPPERCASE hex, slash unescaped, non-BMP
;; passed through raw.
(for-each
  (lambda (p)
    (let ((v (car p)) (want (cadr p)) (what (caddr p)))
      (check (string-append "string escape: " what)
             (equal? want (json->string v))
             (json->string v))))
  (list
    (list "\"" "\"\\\"\""             "the quote itself")
    (list "\\" "\"\\\\\""             "the backslash itself")
    (list "\n" "\"\\n\""              "newline, short form")
    (list "\r" "\"\\r\""              "return, short form")
    (list "\t" "\"\\t\""              "tab, short form")
    (list (string (integer->char 8))  "\"\\u0008\"" "backspace, four hex digits")
    (list (string (integer->char 12)) "\"\\u000C\"" "formfeed, uppercase hex")
    (list (string (integer->char 31)) "\"\\u001F\"" "US, the top of the control range")
    (list (string (integer->char 0))  "\"\\u0000\"" "NUL, the bottom")
    (list "/" "\"/\""                 "slash stays raw")
    (list "a\"b\\c" "\"a\\\"b\\\\c\"" "escapes inside surrounding text")
    (list "名" "\"名\""               "non-ASCII passes through raw")
    (list (string (integer->char #x1F600))
          (string #\" (integer->char #x1F600) #\")
          "non-BMP passes through raw")))

;; the whole control range, not the sampled corners: each of the 32
;; controls must come out as SOME legal escape and read back as itself
;; under the independent grammar. Chosen corners above pin the exact
;; spellings; this loop pins that no control in between leaks out raw.
(let ((bad '()))
  (do ((i 0 (+ i 1))) ((= i 32))
    (let* ((v (string (integer->char i)))
           (t (json->string v)))
      (unless (rfc-json-text? t)
        (set! bad (cons (list i t) bad)))))
  (check "all 32 control characters escape to grammatical text"
         (null? bad) (reverse bad)))

;; keys pass through the same escaper as values -- a key with a quote in
;; it must not break the object around it
(check "a key needing escapes still yields a grammatical document"
       (let ((t (json->string (list (cons "a\"b" 1)))))
         (and (rfc-json-text? t) (equal? t "{\"a\\\"b\":1}")))
       (json->string (list (cons "a\"b" 1))))

;; ---- containers: structure, by exact text ------------------------------
(for-each
  (lambda (p)
    (let ((v (car p)) (want (cadr p)) (what (caddr p)))
      (check (string-append "structure: " what)
             (equal? want (json->string v))
             (json->string v))))
  (list
    (list '(("a" . 1) ("b" . 2) ("c" . 3)) "{\"a\":1,\"b\":2,\"c\":3}"
          "three members, two commas, three colons, source order kept")
    (list (vector 1 2 3) "[1,2,3]"
          "three elements, two commas")
    (list (vector 1) "[1]" "one element, no comma")
    (list '(("only" . 1)) "{\"only\":1}" "one member, no comma")
    (list (vector (vector) '() "x") "[[],{},\"x\"]"
          "empty containers as elements")
    (list '(("t" . #t) ("f" . #f) ("n" . null)) "{\"t\":true,\"f\":false,\"n\":null}"
          "the three literals, spelled exactly")))

;; duplicate keys are preserved in order, not collapsed -- this is the
;; documented behaviour and nothing owned it
(check "duplicate keys write in order, uncollapsed"
       (equal? "{\"a\":1,\"a\":2}"
               (json->string '(("a" . 1) ("a" . 2))))
       (json->string '(("a" . 1) ("a" . 2))))

;; ---- reader-writer agreement on the deviations -------------------------
;; The reader accepts two deviations the strict judge refuses: leading
;; zeros and raw controls. The WRITER must emit neither -- its output
;; must satisfy the strict judge even where its own reader would be
;; forgiving, or the deviations would leak into documents other parsers
;; refuse. Both are pinned by feeding the deviation through a read-write
;; round trip: what comes back out must be strict.
(check "a read leading-zero numeral is rewritten strictly on the way out"
       (let ((t (json->string (string->json "01"))))
         (and (rfc-json-text? t) (equal? t "1")))
       (json->string (string->json "01")))
(check "a read raw control is escaped on the way out"
       (let ((t (json->string (string->json (string #\" (integer->char 1) #\")))))
         (and (rfc-json-text? t) (equal? t "\"\\u0001\"")))
       (json->string (string->json (string #\" (integer->char 1) #\"))))

(display "json-writer-syntax: ")
(display (if (= failures 0) "all tests passed" "FAILURES"))
(newline)
(when (> failures 0) (exit 1))
