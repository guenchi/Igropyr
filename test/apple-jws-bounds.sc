#!chezscheme
;;; test/apple-jws-bounds.sc -- the x5c count and entry-size bounds, at
;;; their boundaries.
;;;
;;; verify-jws-x5c refuses an x5c of fewer than 3 or more than 8 entries,
;;; and any entry longer than 8192 characters, before it decodes a byte of
;;; DER. The guards existed with no row at either edge. Each row here builds
;;; a header whose only defect past the bound under test is that its
;;; entries are not certificates, so what distinguishes "refused by the
;;; bound" from "passed the bound" is the code and message: the bound
;;; answers no-x5c (count) or "missing or too large" (size); past it, the
;;; next check answers "not a DER certificate". No chain is verified here.

(import (chezscheme) (igropyr apple-jws)
        (only (igropyr crypto) base64-encode))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define (b64url-of str)
  (let* ((std (base64-encode (string->utf8 str))) (n (string-length std)))
    (let loop ((i 0) (acc '()))
      (if (= i n)
          (list->string (reverse acc))
          (let ((c (string-ref std i)))
            (loop (+ i 1)
                  (cond ((char=? c #\+) (cons #\- acc))
                        ((char=? c #\/) (cons #\_ acc))
                        ((char=? c #\=) acc)
                        (else (cons c acc)))))))))

;; a token whose header carries `entries` as x5c; the payload and
;; signature never matter, the header is refused first
(define (token-with entries)
  (let ((x5c (let loop ((es entries) (acc ""))
               (if (null? es) acc
                   (loop (cdr es) (string-append acc (if (string=? acc "") "" ",") "\"" (car es) "\""))))))
    (string-append (b64url-of (string-append "{\"alg\":\"ES256\",\"x5c\":[" x5c "]}")) ".e30.AA")))

;; -> (code . message) of the refusal
(define (refusal entries)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'apple-jws-error))
             (cons (vector-ref e 1) (vector-ref e 2)))
            (#t (cons 'raised e)))
    (verify-jws-x5c (token-with entries) '())
    '(accepted . "")))

(define (index-of text sub)
  (let ((n (string-length text)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring text i (+ i m))) i)
            (else (loop (+ i 1)))))))
(define (refused-as? r code text)
  (and (eq? (car r) code) (string? (cdr r)) (index-of (cdr r) text) #t))

(define (entries n) (let loop ((i 0) (acc '())) (if (= i n) acc (loop (+ i 1) (cons "AAAA" acc)))))

;; ---- count ----------------------------------------------------------------------------------
(let ((r (refusal (entries 2))))
  (check "2 entries: refused as no-x5c, shorter than 3" (refused-as? r 'no-x5c "shorter than 3") r))
(let ((r (refusal (entries 3))))
  (check "3 entries: past the count bounds (refused later, as not a DER certificate)"
         (refused-as? r 'cert-parse-failed "not a DER certificate") r))
(let ((r (refusal (entries 8))))
  (check "8 entries: past the count bounds (refused later, as not a DER certificate)"
         (refused-as? r 'cert-parse-failed "not a DER certificate") r))
(let ((r (refusal (entries 9))))
  (check "9 entries: refused as no-x5c, longer than 8" (refused-as? r 'no-x5c "longer than 8") r))

;; ---- entry size -------------------------------------------------------------------------------
(let ((r (refusal (list (make-string 8192 #\A) "AAAA" "AAAA"))))
  (check "an 8192-character entry: past the size bound (refused later, as not a DER certificate)"
         (refused-as? r 'cert-parse-failed "not a DER certificate") r))
(let ((r (refusal (list (make-string 8193 #\A) "AAAA" "AAAA"))))
  (check "an 8193-character entry: refused as too large, before any decoding"
         (refused-as? r 'cert-parse-failed "too large") r))
(let ((r (refusal (list "AAAA" "AAAA" (make-string 8193 #\A)))))
  (check "  also when it is the last entry" (refused-as? r 'cert-parse-failed "too large") r))

(if (zero? failures)
    (begin (display "apple-jws-bounds: all tests passed\n") (exit 0))
    (begin (display "apple-jws-bounds: ") (display failures) (display " failed\n") (exit 1)))
