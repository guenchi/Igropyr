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
;;;   bytevectors  #vu8"b64"    -- base64 (RFC 4648) of the raw bytes;
;;;                                ~1.33x on the wire and decoded in one
;;;                                pass, vs the ~4x text and O(n)-list
;;;                                blowup a #vu8(0 1 255 ...) form costs
;;;   flonums      #f8"b64"     -- the 8 IEEE-754 bytes of the double,
;;;                                little-endian, base64: bit-exact for
;;;                                EVERY double, inf and nan included --
;;;                                no decimal printing anywhere, so a
;;;                                peer without exact float printing
;;;                                (Goeteia) round-trips perfectly.
;;;                                (-0.0 may read back as 0.0 on a peer
;;;                                whose floats cannot carry a signed
;;;                                zero; numerically equal.)
;;; The strict mode is untouched: it stays the HTTP-facing and
;;; Goeteia-compatible format, and still rejects all three.
;;;
;;; Interop notes (verified against Goeteia's reader/writer): strings
;;; escape only \" and \\ on the wire -- a literal newline inside a
;;; string is legal; \n \t \r are also accepted when reading.

(library (igropyr sexpr)
  (export string->sexpr sexpr->string
          string->sexpr-extended sexpr->string-extended)
  (import (chezscheme) (only (igropyr crypto) base64-encode base64-decode))

  (define default-max-depth 64)
  ;; Cap on a single atom token (symbol or number). Bounds two costs an
  ;; untrusted sender could otherwise inflate without limit: interning a
  ;; multi-megabyte symbol into the global symbol table, and the
  ;; superlinear bignum build of an enormous digit run. 64 KiB is far
  ;; above any real wire tag, name, or number; strings are not tokens
  ;; and stay bounded by the caller's frame/body size limit instead.
  (define default-max-token 65536)

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
             ;; extended #f8"..." (a flonum) must be told apart from the
             ;; #f boolean: the 8-and-quote lookahead decides
             (if (and ext? (char=? c #\f)
                      (< (+ i 2) n)
                      (char=? (string-ref s (+ i 1)) #\8)
                      (char=? (string-ref s (+ i 2)) #\"))
                 (parse-flonum-b64 (+ i 3))
                 (begin
                   (unless (or (>= (+ i 1) n) (delim? (string-ref s (+ i 1))))
                     (sfail "bad # literal" i))
                   (values (char=? c #\t) (+ i 1)))))
            ((#\()                               ; extended: vector
             (unless ext? (sfail "bad # literal" i))
             (parse-vector (+ i 1) depth))
            ((#\v)                               ; extended: #vu8"<base64>"
             (unless (and ext?
                          (< (+ i 3) n)
                          (char=? (string-ref s (+ i 1)) #\u)
                          (char=? (string-ref s (+ i 2)) #\8)
                          (char=? (string-ref s (+ i 3)) #\"))
               (sfail "bad # literal" i))
             (parse-bytevector-b64 (+ i 4)))
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
      ;; Scan a base64 payload to its closing quote and decode it in one
      ;; pass -- no per-element list, so no O(n) allocation blowup. The
      ;; base64 alphabet has no " or \, so there is nothing to escape; a
      ;; stray char fails loudly. -> (values bytes next-i)
      (define (parse-b64 start what)
        (let loop ((j start))
          (cond
            ((>= j n) (sfail (string-append "unterminated " what) start))
            ((char=? (string-ref s j) #\")
             ;; base64-decode raises &assertion on a non-canonical tail (the
             ;; unused bits of the last character must be zero), and this
             ;; input is a peer's. Keep it inside the documented
             ;; #(sexpr-error ...) contract rather than letting a raw
             ;; assertion escape into a node's distribution process.
             (values (guard (e (#t (sfail (string-append "bad base64 in " what)
                                          start)))
                       (base64-decode (substring s start j)))
                     (+ j 1)))
            ((let ((c (string-ref s j)))
               (or (char<=? #\A c #\Z) (char<=? #\a c #\z) (char<=? #\0 c #\9)
                   (char=? c #\+) (char=? c #\/) (char=? c #\=)))
             (loop (+ j 1)))
            (else (sfail (string-append "bad base64 in " what) j)))))
      (define (parse-bytevector-b64 start)
        (parse-b64 start "bytevector"))
      ;; extended: the 8 IEEE-754 bytes of a double, little-endian
      (define (parse-flonum-b64 start)
        (let-values (((bv j) (parse-b64 start "flonum")))
          (unless (= (bytevector-length bv) 8)
            (sfail "flonum wants exactly 8 bytes" start))
          (values (bytevector-ieee-double-ref bv 0 (endianness little)) j)))
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
      ;; No decimal flonum text on the wire in EITHER mode: a flonum
      ;; crosses only as #f8"<base64>" (extended), so a numeric-shaped
      ;; token carrying '.' or an exponent is always a bad number.
      (define (parse-atom i)
        (let ((j (let lp ((j i))
                   (if (or (>= j n) (delim? (string-ref s j))) j (lp (+ j 1))))))
          (when (> (- j i) default-max-token) (sfail "token too long" i))
          (let ((tok (substring s i j)))
            (cond
              ((token->number tok) => (lambda (v) (values v j)))
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
      ;; MEASURED ON THE NUMERAL, ONCE, AND WITH ITS SIGN. The reader
      ;; caps a token at default-max-token characters, so a numeral
      ;; longer than that is one this library can write and cannot read
      ;; back -- the failure landing at the far end, after the sender saw
      ;; success. Refusing here puts the error on the end that can still
      ;; do something about it.
      ;;
      ;; The cap counts the whole token, sign included: -(10^65535) has
      ;; 65536 digits and 65537 characters, and a check that counted
      ;; digits would pass exactly the value the reader rejects. The
      ;; string produced here is the one measured and the one written,
      ;; so no numeral is rendered twice.
      ((and (integer? x) (exact? x)) (put-numeral p (number->string x)))
      ((and (rational? x) (exact? x)) (put-numeral p (number->string x)))
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
       (put-string p "#vu8\"")
       (put-string p (base64-encode x))
       (put-char p #\"))
      ;; the 8 IEEE bytes, little-endian: bit-exact for every double,
      ;; inf and nan included -- decimal printing never touches the wire
      ((and ext? (flonum? x))
       (put-string p "#f8\"")
       (let ((bv (make-bytevector 8)))
         (bytevector-ieee-double-set! bv 0 x (endianness little))
         (put-string p (base64-encode bv)))
       (put-char p #\"))
      (else (sfail "datum not in the wire whitelist" 0))))

  ;; Exact integers and ratios reach the wire as their printed numeral,
  ;; and the reader will not accept one past the token cap. Same limit,
  ;; same constant -- there is one supplier of it in this file and both
  ;; ends read it, which is a mechanism rather than an obligation.
  (define (put-numeral p str)
    (when (> (string-length str) default-max-token)
      ;; The same failure shape the symbol refusal already uses, because
      ;; a caller catching one has to catch the other: both are "this
      ;; datum cannot go on the wire", raised by the writer.
      (sfail "token too long for the wire -- carry a value this large as a bytevector, which needs the extended mode (sexpr->string-extended)" 0))
    (put-string p str))

  ;; A bare token is re-read by parse-atom, which tries a number first
  ;; and treats "." as the improper-list marker. So a symbol whose name
  ;; reads back as a number (|12|, |1.5|) or as the dot would return
  ;; from the wire as a DIFFERENT datum -- an integer instead of a
  ;; symbol, or an improper pair instead of a 3-element list. There is
  ;; no escaped symbol form in this grammar, so such symbols are
  ;; refused by the writer (the whole point of the whitelist) rather
  ;; than silently corrupted in transit.
  ;;
  ;; THE QUESTION IS WHAT THE READER WILL DO WITH THE NAME, NOT WHAT
  ;; CHEZ THINKS OF IT. string->number alone was the wrong judge, and
  ;; the two are not even nested: parse-atom commits to reading a number
  ;; the moment a token STARTS like one (a digit, or '-' then a digit)
  ;; and then fails if the rest is not one. So |0x10| passed
  ;; string->number's test -- Chez does not read it as a number -- went
  ;; out on the wire bare, and came back as "bad number" at the far end:
  ;; a datum this library wrote and could not read, which is the one
  ;; failure a whitelist exists to prevent. |12abc|, |1/0| and |-1x| are
  ;; the same shape.
  ;;
  ;; The reader's own test is mirrored here -- COPIED, not shared, which
  ;; is a maintenance obligation and not a guarantee: whoever widens
  ;; numeric-shape? in the reader has to widen this one in the same
  ;; commit, or the same class of defect comes straight back. Keeping
  ;; them textually identical is what makes that check a glance.
  ;; string->number stays as well, and the overlap is not redundant: it
  ;; refuses names the reader would accept, such as |+i|, which is an
  ;; over-refusal rather than a corruption and costs a caller nothing
  ;; but a rename.
  (define (wire-symbol? s)
    (let ((m (string-length s)))
      (and (> m 0)
           ;; Before the character walk, because it is one comparison and
           ;; the walk is not: a name past the reader's token cap comes
           ;; back as "token too long" at the far end, so it is refused
           ;; here for the same reason the numeric shapes are.
           (<= m default-max-token)
           (not (string->number s))
           ;; the reader's numeric-shape?, kept identical to it
           (not (let ((c (string-ref s 0)))
                  (or (char<=? #\0 c #\9)
                      (and (char=? c #\-) (> m 1)
                           (char<=? #\0 (string-ref s 1) #\9)))))
           (not (string=? s "."))
           (let lp ((i 0))
             (or (= i m)
                 (and (let ((c (string-ref s i)))
                        (or (char<=? #\a c #\z) (char<=? #\A c #\Z)
                            (char<=? #\0 c #\9)
                            (memv c '(#\- #\+ #\* #\/ #\< #\> #\= #\? #\! #\.
                                      #\_ #\% #\& #\^ #\~ #\: #\@))))
                      (lp (+ i 1)))))))))
