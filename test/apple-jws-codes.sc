#!chezscheme
;;; test/apple-jws-codes.sc -- the reason codes apple-jws.sc raises are the
;;; ones its header lists.
;;;
;;; The header tells a caller which CODE symbols #(apple-jws-error CODE
;;; MESSAGE) can carry, so the caller can map them to HTTP statuses. That
;;; list is prose; nothing held it to the code. This reads both out of the
;;; source: every (ajws-fail 'code ...) literal in the library, and the
;;; symbols in the header's list (the lines after "map it to an HTTP
;;; status" up to the next blank comment line). The two sets must be equal
;;; -- a code raised but not listed is one a caller cannot classify; a code
;;; listed but never raised is a promise the library does not keep. Every
;;; ajws-fail call must pass a literal, or this file cannot read it and
;;; says so.

(import (chezscheme))

(define src (call-with-input-file "apple-jws.sc" get-string-all))
(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define (index-of text sub from)
  (let ((n (string-length text)) (m (string-length sub)))
    (let loop ((i from))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring text i (+ i m))) i)
            (else (loop (+ i 1)))))))
(define (code-char? c)
  (or (char-alphabetic? c) (char-numeric? c) (char=? c #\-)))
(define (read-symbol-at text i)
  (let loop ((j i))
    (if (and (< j (string-length text)) (code-char? (string-ref text j)))
        (loop (+ j 1))
        (string->symbol (substring text i j)))))

;; every call site: "(ajws-fail " followed by a quote and a literal, or not;
;; the definition "(define (ajws-fail code msg)" is the one site skipped
(define-values (raised non-literal)
  (let loop ((from 0) (codes '()) (bad 0))
    (let ((i (index-of src "(ajws-fail " from)))
      (cond
        ((not i) (values codes bad))
        ((and (>= i 8) (string=? (substring src (- i 8) i) "(define "))
         (loop (+ i 1) codes bad))
        (else
         (let ((j (+ i (string-length "(ajws-fail "))))
           (if (char=? (string-ref src j) #\')
               (let ((c (read-symbol-at src (+ j 1))))
                 (loop (+ i 1) (if (memq c codes) codes (cons c codes)) bad))
               (loop (+ i 1) codes (+ bad 1)))))))))

;; the header list: the comment lines after the anchor line, until a blank
;; ";;;" line; every word made of code characters on them is a code
(define (symbols-on-line line)
  (let words ((k 0) (codes '()))
    (cond ((>= k (string-length line)) (reverse codes))
          ((code-char? (string-ref line k))
           (let ((c (read-symbol-at line k)))
             (words (+ k (string-length (symbol->string c))) (cons c codes))))
          (else (words (+ k 1) codes)))))
(define listed
  (let ((a (index-of src "map it to an HTTP status" 0)))
    (if (not a)
        'no-anchor
        ;; the prose runs on past the anchor until a line ending in "):";
        ;; the list starts on the line after that one
        (let loop ((i (+ 3 (index-of src "):\n" a))) (codes '()))
          (let* ((eol (index-of src "\n" i))
                 (line (substring src i eol))
                 (body (if (and (>= (string-length line) 3) (string=? (substring line 0 3) ";;;"))
                           (substring line 3 (string-length line))
                           #f)))
            (cond ((or (not body) (string=? body "")) codes)
                  (else (loop (+ eol 1) (append codes (symbols-on-line body))))))))))

(define (set-minus a b) (filter (lambda (x) (not (memq x b))) a))

(check "the header's list was found at its anchor" (list? listed) listed)
(check "every ajws-fail call passes a literal code" (= non-literal 0) non-literal)
(check "at least six codes are raised (the extraction is reading something)" (>= (length raised) 6) raised)
(when (list? listed)
  (check "every code the library raises is in the header's list"
         (null? (set-minus raised listed)) (set-minus raised listed))
  (check "every code the header lists is raised somewhere"
         (null? (set-minus listed raised)) (set-minus listed raised)))
(display "  [info] codes: ") (write (list-sort (lambda (a b) (string<? (symbol->string a) (symbol->string b))) raised)) (newline)

(if (zero? failures)
    (begin (display "apple-jws-codes: all tests passed\n") (exit 0))
    (begin (display "apple-jws-codes: ") (display failures) (display " failed\n") (exit 1)))
