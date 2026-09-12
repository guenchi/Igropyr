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
;;; Interop notes. These describe what Goeteia's reader/writer do; what
;;; the tree checks is conformance TO THIS implementation --
;;; test/sexpr-vectors.json names (igropyr sexpr) as the authority and
;;; the commit it was generated from, and the other side is regenerated
;;; against it. Two independent implementations agreeing is a different
;;; claim and is not the one being made.
;;;
;;; THE WRITER AND THE READER ARE DELIBERATELY NOT THE SAME WIDTH, and
;;; the direction matters. The writer escapes two characters and no
;;; others -- the double quote and the backslash. Every control
;;; character goes out as a raw byte, which is legal in
;;; this grammar and loses nothing -- our own write/read pair is closed.
;;; The reader is wider because it also has to accept what OTHER writers
;;; of this format emit: a conforming R6RS `write` renders a form feed
;;; as \f, and refusing that made text produced by any other Scheme
;;; unreadable here. So reading accepts \a \b \t \n \v \f \r \" \\
;;; and \x<hex>;, and raw control characters as before.
;;;
;;; Symbols accept \x<hex>; too, and the DECODED name must still be one
;;; this library's writer could have produced (wire-symbol?). An escape
;;; disambiguates a name; it does not extend the set of names this
;;; format has.

(library (igropyr sexpr)
  (export string->sexpr sexpr->string
          string->sexpr-extended sexpr->string-extended)
  (import (chezscheme) (only (igropyr crypto) base64-encode base64-decode)
          ;; hex-digits->exact: the tree's one supplier for "text from
          ;; outside, converted only after its shape is checked". The
          ;; escape below is external text by definition.
          (only (igropyr util) hex-digits->exact))

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
      ;; ---- escapes -----------------------------------------------------
      ;;
      ;; \x<hex>; IS THE ONLY VARIABLE-LENGTH FORM IN THIS GRAMMAR. Every
      ;; other escape is two characters, and the loops below used to
      ;; advance by that constant; each caller is now handed back the
      ;; index to continue from instead.
      (define max-hex-digits 6)
      ;; THE DIGIT RUN IS BOUNDED WHILE IT IS SCANNED, NOT AFTER IT.
      ;; At most max-hex-digits + 1 positions are examined, so a hundred
      ;; thousand hex digits cost a constant HERE rather than a full scan
      ;; and then a refusal. That is the shape this tree removed
      ;; everywhere else on 2026-09-11: bounded-looking input asking for
      ;; unbounded work, with the check that would have stopped it placed
      ;; after the work rather than before.
      ;;
      ;; "HERE" IS THE WHOLE OF THE CLAIM, and the rest of the token path
      ;; is not constant: parse-atom scans to a delimiter before it
      ;; applies the token cap, so an over-long token costs one pass over
      ;; its characters whether or not it contains an escape (measured:
      ;; 16 MB of token, 33 ms with an escape and 35 ms without -- the
      ;; escape adds nothing, the scan is the cost). That pass is
      ;; proportional to input the sender already had to transmit and is
      ;; bounded upstream by the frame and body size limits; it predates
      ;; escapes entirely.
      (define (hex-escape-end i)
        (let lp ((j i))
          (and (< j n)
               (<= (- j i) max-hex-digits)
               (if (char=? (string-ref s j) #\;) j (lp (+ j 1))))))
      ;; i is the index of the first character after the "x", so the
      ;; backslash that opened the escape is at i - 2 and that is the
      ;; position a failure reports.
      ;; -> (values char index-after-the-semicolon)
      (define (read-hex-escape i what)
        (let ((j (hex-escape-end i)))
          (unless j (sfail what (- i 2)))
          ;; The text handed to the supplier is at most max-hex-digits
          ;; characters long, and the supplier is what decides whether it
          ;; is hex at all: no conversion here ever sees text whose shape
          ;; was not checked first.
          (let ((v (hex-digits->exact (substring s i j) max-hex-digits)))
            (unless (and v
                         (< v #x110000)
                         (not (and (>= v #xD800) (<= v #xDFFF))))
              (sfail what (- i 2)))
            (values (integer->char v) (+ j 1)))))
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
                 ;; LOWERCASE x ONLY. R6RS spells the escape itself in
                 ;; lower case and lets only the DIGITS vary in case, so
                 ;; \X is not something a conforming writer emits and
                 ;; accepting it would widen the format past its source.
                 (if (char=? e #\x)
                     (let-values (((ch j)
                                   (read-hex-escape (+ i 2)
                                                    "bad string escape")))
                       (loop j (cons ch acc)))
                     (loop (+ i 2)
                           (cons (case e
                                   ((#\a) #\alarm) ((#\b) #\backspace)
                                   ((#\t) #\tab)   ((#\n) #\newline)
                                   ((#\v) #\vtab)  ((#\f) #\page)
                                   ((#\r) #\return)
                                   ((#\" #\\) e)
                                   (else (sfail "bad string escape" i)))
                                 acc)))))
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
      ;; Asked before anything else, because an escaped token is a symbol
      ;; by construction: no number in this grammar has an escape form,
      ;; and the character walk below answers "is this character legal in
      ;; a name", which a backslash is not.
      (define (token-escaped? i j)
        (let lp ((k i))
          (and (< k j)
               (or (char=? (string-ref s k) #\\) (lp (+ k 1))))))
      ;; An escape's span is hex digits and a ';', none of which is a
      ;; delimiter, so a well-formed escape cannot reach past j; a
      ;; malformed one is refused by read-hex-escape rather than by a
      ;; second bound here.
      (define (decode-token i j)
        (let-values (((p get) (open-string-output-port)))
          (let lp ((k i))
            (cond
              ((>= k j) (get))
              ((char=? (string-ref s k) #\\)
               (unless (and (< (+ k 1) j)
                            (char=? (string-ref s (+ k 1)) #\x))
                 (sfail "bad token escape" k))
               (let-values (((ch m)
                             (read-hex-escape (+ k 2) "bad token escape")))
                 (write-char ch p)
                 (lp m)))
              (else (write-char (string-ref s k) p) (lp (+ k 1)))))))
      ;; No decimal flonum text on the wire in EITHER mode: a flonum
      ;; crosses only as #f8"<base64>" (extended), so a numeric-shaped
      ;; token carrying '.' or an exponent is always a bad number.
      (define (parse-atom i)
        (let ((j (let lp ((j i))
                   (if (or (>= j n) (delim? (string-ref s j))) j (lp (+ j 1))))))
          ;; The cap is applied to the RAW span, before decoding: it
          ;; bounds the work, and decoding only ever shortens.
          (when (> (- j i) default-max-token) (sfail "token too long" i))
          (if (token-escaped? i j)
              ;; HELD TO wire-symbol?, WHICH IS THE WRITER'S OWN SET, and
              ;; that is the ruling this form turns on. R6RS treats an
              ;; inline hex escape as identifier syntax, so \x31; is the
              ;; symbol |1| there. This format's symbol set is not
              ;; R6RS's: the writer REFUSES |1| because its name has
              ;; numeric shape, and accepting a name we cannot write back
              ;; would make the read side wider than the write side -- a
              ;; value you can receive and cannot echo. An escape
              ;; disambiguates a name; it does not extend the set.
              ;;
              ;; The order inside wire-symbol? is load-bearing here: it
              ;; walks the characters BEFORE it asks string->number, and a
              ;; decoded name is arbitrary text -- this decoder is a new
              ;; supplier of exactly that. The walk admits no '#', so no
              ;; exactness prefix can reach the conversion.
              ;;
              ;; THIS IS THE READER'S FIRST CALLER OF wire-symbol?, whose
              ;; last conjunct is a full numeric conversion, and it is
              ;; worth stating what that costs and what it does not.
              ;; Measured at 60000 characters: a bare `+<digits>` name is
              ;; a symbol in 0 ms because the plain path never converts
              ;; it, while the same name spelled `\x2b;<digits>` costs
              ;; 279 ms here. The CEILING is not new -- a bare numeral of
              ;; the same length is 283 ms today, which is what accepting
              ;; big integers costs and is bounded by the token cap --
              ;; but this is a second route to it, and the two spellings
              ;; of one name are not equally cheap. Recorded rather than
              ;; smoothed over: narrowing it means changing which
              ;; predicate an escaped name is held to, which is a
              ;; decision about the format and not about this loop.
              (let ((name (decode-token i j)))
                (if (wire-symbol? name)
                    (values (string->symbol name) j)
                    (sfail "bad token" i)))
              (let ((tok (substring s i j)))
                (cond
                  ((token->number tok) => (lambda (v) (values v j)))
                  ((numeric-shape? tok) (sfail "bad number" i))
                  ((valid-symbol? tok) (values (string->symbol tok) j))
                  (else (sfail "bad token" i)))))))
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
  ;; symbol, or an improper pair instead of a 3-element list. So such
  ;; symbols are refused by the writer (the whole point of the
  ;; whitelist) rather than silently corrupted in transit.
  ;;
  ;; THE READER NOW HAS AN ESCAPED SYMBOL FORM AND THAT DOES NOT CHANGE
  ;; THIS. \x<hex>; lets a sender disambiguate a name, and the reader
  ;; holds the DECODED name to this very predicate -- so |12| is no more
  ;; receivable than it is writable, and this whitelist is still the one
  ;; description of the format's symbol set rather than one of two.
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
                      (lp (+ i 1)))))
           ;; LAST, AND THE ORDER IS THE GUARD. string->number reads the
           ;; whole numeric syntax, so an exactness prefix asks it to build
           ;; the number it names: this conjunct standing FIRST meant that
           ;; serialising the symbol `#e1e99999999` never returned, and a
           ;; symbol is whatever this process turned into one -- the reader
           ;; is not the only supplier of them.
           ;;
           ;; It stays, because it is still the only thing that refuses a
           ;; name the walk admits and the reader would read back as a
           ;; number (`+i` is the example). After the walk it can only ever
           ;; see letters, digits and the punctuation listed above -- `#` is
           ;; not among them -- so no prefix reaches it, and no exponent
           ;; without one is exact.
           (not (string->number s))))))
