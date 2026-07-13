#!chezscheme
;;; (igropyr sexpr) -- safe s-expression parser and writer.
;;;
;;; The wire format for Scheme-to-Scheme RPC: when both ends speak
;;; Scheme there is no codec to design -- write on one side, read on
;;; the other. This is the read side's discipline, in the same spirit
;;; as (igropyr json): a recursive-descent parser over the input
;;; string, NOT the host reader -- no #-syntax surprises, no eval, a
;;; depth limit, safe for untrusted HTTP bodies. Payloads are DATA:
;;; dispatch on a leading symbol tag, never evaluate.
;;;
;;; Wire datum whitelist (both directions):
;;;   lists (proper and dotted -- alists work), symbols, strings,
;;;   exact integers, exact ratios, #t / #f, ()
;;; Anything else fails loudly, on parse and on write alike.
;;;
;;; (string->sexpr s)        parse one datum; raises
;;;                          #(sexpr-error msg pos) on bad input
;;; (string->sexpr s depth)  with a custom depth limit (default 64)
;;; (sexpr->string x)        serialize; raises on non-whitelist data
;;;
;;; EXTENDED mode (string->sexpr-extended / sexpr->string-extended)
;;; adds three types to the whitelist, for igropyr-to-igropyr links
;;; (node meshes) where the peer is this same codec:
;;;   vectors      #(...)       -- no dotted tail, depth-limited
;;;   bytevectors  #vu8(...)    -- bare exact integers 0..255 only
;;;   flonums      1.5, -2e10   -- FINITE only; inf/nan are rejected
;;;                                on read AND write; Chez prints the
;;;                                shortest form that reads back
;;;                                bit-identically
;;; The strict mode is untouched: it stays the HTTP-facing and
;;; Goeteia-compatible format, and still rejects all three.
;;;
;;; Interop notes (verified against Goeteia's reader/writer): strings
;;; escape only \" and \\ on the wire -- a literal newline inside a
;;; string is legal; \n \t \r are also accepted when reading.

(library (igropyr sexpr)
  (export string->sexpr sexpr->string
          string->sexpr-extended sexpr->string-extended)
  (import (chezscheme))

  (define default-max-depth 64)

  (define (sfail msg pos)
    (raise (vector 'sexpr-error msg pos)))

  ;; ---- parser -----------------------------------------------------------

  (define (string->sexpr s . opts)
    ($parse s (if (pair? opts) (car opts) default-max-depth) #f))

  (define (string->sexpr-extended s . opts)
    ($parse s (if (pair? opts) (car opts) default-max-depth) #t))

  (define ($parse s max-depth ext?)
    (let ((n (string-length s)))
      (define (ws? c) (memv c '(#\space #\tab #\newline #\return)))
      (define (skip i)
        (if (and (< i n) (ws? (string-ref s i))) (skip (+ i 1)) i))
      (define (delim? c)
        (or (ws? c) (char=? c #\() (char=? c #\)) (char=? c #\")))
      (define (parse-value i depth)
        (when (> depth max-depth) (sfail "nesting too deep" i))
        (let ((i (skip i)))
          (when (>= i n) (sfail "unexpected end of input" i))
          (let ((c (string-ref s i)))
            (cond
              ((char=? c #\() (parse-list (+ i 1) depth))
              ((char=? c #\)) (sfail "unexpected )" i))
              ((char=? c #\") (parse-string (+ i 1)))
              ((char=? c #\#) (parse-hash (+ i 1) depth))
              (else (parse-atom i))))))
      (define (parse-list i depth)
        (let loop ((i i) (acc '()))
          (let ((i (skip i)))
            (when (>= i n) (sfail "unterminated list" i))
            (cond
              ((char=? (string-ref s i) #\))
               (values (reverse acc) (+ i 1)))
              ;; a lone dot: dotted tail, then the close paren
              ((and (char=? (string-ref s i) #\.)
                    (or (>= (+ i 1) n) (delim? (string-ref s (+ i 1))))
                    (pair? acc))
               (let-values (((tail j) (parse-value (+ i 1) (+ depth 1))))
                 (let ((j (skip j)))
                   (unless (and (< j n) (char=? (string-ref s j) #\)))
                     (sfail "expected ) after dotted tail" j))
                   (values (append (reverse (cdr acc))
                                   (cons (car acc) tail))
                           (+ j 1)))))
              (else
               (let-values (((v j) (parse-value i (+ depth 1))))
                 (loop j (cons v acc))))))))
      (define (parse-string i)
        (let loop ((i i) (acc '()))
          (when (>= i n) (sfail "unterminated string" i))
          (let ((c (string-ref s i)))
            (cond
              ((char=? c #\")
               (values (list->string (reverse acc)) (+ i 1)))
              ((char=? c #\\)
               (when (>= (+ i 1) n) (sfail "dangling escape" i))
               (let ((e (string-ref s (+ i 1))))
                 (loop (+ i 2)
                       (cons (case e
                               ((#\n) #\newline) ((#\t) #\tab)
                               ((#\r) #\return)
                               ((#\" #\\) e)
                               (else (sfail "bad string escape" i)))
                             acc))))
              (else (loop (+ i 1) (cons c acc)))))))
      (define (parse-hash i depth)
        (when (>= i n) (sfail "dangling #" i))
        (let ((c (string-ref s i)))
          (case c
            ((#\t #\f)
             (unless (or (>= (+ i 1) n) (delim? (string-ref s (+ i 1))))
               (sfail "bad # literal" i))
             (values (char=? c #\t) (+ i 1)))
            ((#\()                               ; extended: vector
             (unless ext? (sfail "bad # literal" i))
             (parse-vector (+ i 1) depth))
            ((#\v)                               ; extended: #vu8(...)
             (unless (and ext?
                          (< (+ i 3) n)
                          (char=? (string-ref s (+ i 1)) #\u)
                          (char=? (string-ref s (+ i 2)) #\8)
                          (char=? (string-ref s (+ i 3)) #\())
               (sfail "bad # literal" i))
             (parse-bytevector (+ i 4)))
            (else (sfail "bad # literal" i)))))
      ;; extended: like a list body, but a dotted tail is illegal
      (define (parse-vector i depth)
        (let loop ((i i) (acc '()))
          (let ((i (skip i)))
            (when (>= i n) (sfail "unterminated vector" i))
            (cond
              ((char=? (string-ref s i) #\))
               (values (list->vector (reverse acc)) (+ i 1)))
              ((and (char=? (string-ref s i) #\.)
                    (or (>= (+ i 1) n) (delim? (string-ref s (+ i 1)))))
               (sfail "dot not allowed in vector" i))
              (else
               (let-values (((v j) (parse-value i (+ depth 1))))
                 (loop j (cons v acc))))))))
      ;; extended: elements are BARE exact integers 0..255, nothing else
      (define (parse-bytevector i)
        (let loop ((i i) (acc '()))
          (let ((i (skip i)))
            (when (>= i n) (sfail "unterminated bytevector" i))
            (if (char=? (string-ref s i) #\))
                (values (u8-list->bytevector (reverse acc)) (+ i 1))
                (let-values (((v j) (parse-atom i)))
                  (unless (and (integer? v) (exact? v) (<= 0 v 255))
                    (sfail "bytevector element out of range" i))
                  (loop j (cons v acc)))))))
      (define (digits? str a b)
        (and (< a b)
             (let lp ((i a))
               (or (= i b)
                   (and (char<=? #\0 (string-ref str i) #\9)
                        (lp (+ i 1)))))))
      (define (token->number tok)
        ;; [-]digits or [-]digits/digits, nothing else
        (let* ((m (string-length tok))
               (a (if (and (> m 0) (char=? (string-ref tok 0) #\-)) 1 0))
               (slash (let lp ((i a))
                        (cond ((= i m) #f)
                              ((char=? (string-ref tok i) #\/) i)
                              (else (lp (+ i 1)))))))
          (cond
            ((and slash (digits? tok a slash) (digits? tok (+ slash 1) m))
             (let ((d (string->number (substring tok (+ slash 1) m) 10)))
               (and d (not (zero? d))
                    (/ (let ((v (string->number (substring tok a slash) 10)))
                         (if (= a 1) (- v) v))
                       d))))
            ((digits? tok a m)
             (let ((v (string->number (substring tok a m) 10)))
               (and v (if (= a 1) (- v) v))))
            (else #f))))
      (define (symbol-char? c)
        (or (char<=? #\a c #\z) (char<=? #\A c #\Z) (char<=? #\0 c #\9)
            (memv c '(#\- #\+ #\* #\/ #\< #\> #\= #\? #\! #\. #\_
                      #\% #\& #\^ #\~ #\: #\@))))
      (define (valid-symbol? tok)
        (let ((m (string-length tok)))
          (and (> m 0)
               (let lp ((i 0))
                 (or (= i m)
                     (and (symbol-char? (string-ref tok i)) (lp (+ i 1))))))))
      (define (numeric-shape? tok)
        ;; starts like a number: it must BE a whitelisted number, so
        ;; 1.5 or 1e9 can't slip through as symbols
        (let ((m (string-length tok)))
          (and (> m 0)
               (let ((c (string-ref tok 0)))
                 (or (char<=? #\0 c #\9)
                     (and (char=? c #\-) (> m 1)
                          (char<=? #\0 (string-ref tok 1) #\9)))))))
      ;; extended: a numeric-shaped token carrying '.' or an exponent
      ;; must parse to a FINITE flonum ("1e999" reads as +inf.0 in the
      ;; host and is rejected here; so are nan and complex results)
      (define (token->flonum tok)
        (and (let ((m (string-length tok)))
               (let lp ((i 0))
                 (and (< i m)
                      (or (memv (string-ref tok i) '(#\. #\e #\E))
                          (lp (+ i 1))))))
             (let ((v (string->number tok 10)))
               (and (flonum? v) (not (nan? v)) (not (infinite? v)) v))))
      (define (parse-atom i)
        (let ((j (let lp ((j i))
                   (if (or (>= j n) (delim? (string-ref s j))) j (lp (+ j 1))))))
          (let ((tok (substring s i j)))
            (cond
              ((token->number tok) => (lambda (v) (values v j)))
              ((and ext? (token->flonum tok)) => (lambda (v) (values v j)))
              ((numeric-shape? tok) (sfail "bad number" i))
              ((valid-symbol? tok) (values (string->symbol tok) j))
              (else (sfail "bad token" i))))))
      (let-values (((v i) (parse-value 0 0)))
        (unless (= (skip i) n) (sfail "trailing data after datum" i))
        v)))

  ;; ---- writer -----------------------------------------------------------

  (define (sexpr->string x)
    (call-with-string-output-port
     (lambda (p) (emit x p 0 #f))))

  (define (sexpr->string-extended x)
    (call-with-string-output-port
     (lambda (p) (emit x p 0 #t))))

  (define (emit x p depth ext?)
    (when (> depth default-max-depth)
      (sfail "nesting too deep (cyclic data?)" 0))
    (cond
      ((null? x) (put-string p "()"))
      ((pair? x)
       (put-char p #\()
       (emit (car x) p (+ depth 1) ext?)
       ;; the spine is bounded too: a cycle along cdr never nests, so
       ;; the depth counter alone would spin forever
       (let tail ((x (cdr x)) (k 0))
         (when (> k 1000000) (sfail "list too long (cyclic data?)" 0))
         (cond
           ((null? x) (put-char p #\)))
           ((pair? x)
            (put-char p #\space)
            (emit (car x) p (+ depth 1) ext?)
            (tail (cdr x) (+ k 1)))
           (else
            (put-string p " . ")
            (emit x p (+ depth 1) ext?)
            (put-char p #\))))))
      ((symbol? x)
       (let ((s (symbol->string x)))
         (unless (wire-symbol? s)
           (sfail "symbol not wire-safe" 0))
         (put-string p s)))
      ((string? x)
       (put-char p #\")
       (string-for-each
        (lambda (c)
          (when (or (char=? c #\") (char=? c #\\)) (put-char p #\\))
          (put-char p c))
        x)
       (put-char p #\"))
      ((eq? x #t) (put-string p "#t"))
      ((eq? x #f) (put-string p "#f"))
      ((and (integer? x) (exact? x)) (put-string p (number->string x)))
      ((and (rational? x) (exact? x)) (put-string p (number->string x)))
      ;; extended whitelist; in strict mode these fall through to the
      ;; refusal below, exactly as before
      ((and ext? (vector? x))
       (put-string p "#(")
       (let ((m (vector-length x)))
         (do ((i 0 (+ i 1))) ((= i m))
           (when (> i 0) (put-char p #\space))
           (emit (vector-ref x i) p (+ depth 1) ext?)))
       (put-char p #\)))
      ((and ext? (bytevector? x))
       (put-string p "#vu8(")
       (let ((m (bytevector-length x)))
         (do ((i 0 (+ i 1))) ((= i m))
           (when (> i 0) (put-char p #\space))
           (put-string p (number->string (bytevector-u8-ref x i)))))
       (put-char p #\)))
      ((and ext? (flonum? x))
       (when (or (nan? x) (infinite? x))
         (sfail "non-finite flonum" 0))
       (put-string p (number->string x)))
      (else (sfail "datum not in the wire whitelist" 0))))

  (define (wire-symbol? s)
    (let ((m (string-length s)))
      (and (> m 0)
           (let lp ((i 0))
             (or (= i m)
                 (and (let ((c (string-ref s i)))
                        (or (char<=? #\a c #\z) (char<=? #\A c #\Z)
                            (char<=? #\0 c #\9)
                            (memv c '(#\- #\+ #\* #\/ #\< #\> #\= #\? #\! #\.
                                      #\_ #\% #\& #\^ #\~ #\: #\@))))
                      (lp (+ i 1)))))))))
