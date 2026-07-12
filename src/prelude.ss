;; schwasm prelude: the runtime library, written in schwasm's own
;; Scheme and compiled into every module.
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.

(define (newline . p)
  (if (null? p) ($wb 10) ($write-byte-port (car p) 10)))

(define (display x . p)
  (if (null? p) ($display x) ($with-out (car p) (lambda () ($display x)))))
(define ($display x)
  (cond
   ((number? x) (%display-number x))
   ((char? x) ($wb (char->integer x)))
   ((string? x) (%display-string x 0))
   ((symbol? x) (%display-string (symbol->string x) 0))
   ((null? x) ($wb 40) ($wb 41))
   ((eq? x #t) ($wb 35) ($wb 116))
   ((eq? x #f) ($wb 35) ($wb 102))
   ((pair? x)
    ($wb 40)
    (display (car x))
    (%display-tail (cdr x)))
   ((vector? x)
    ($wb 35) ($wb 40)                    ; #(
    (let loop ((i 0))
      (when (< i (vector-length x))
        (unless (zero? i) ($wb 32))
        ($display (vector-ref x i))
        (loop (+ i 1))))
    ($wb 41))
   ((bytevector? x)
    (%display-string "#vu8(" 0)
    (let loop ((i 0))
      (when (< i (bytevector-length x))
        (unless (zero? i) ($wb 32))
        ($display (bytevector-u8-ref x i))
        (loop (+ i 1))))
    ($wb 41))
   ((%recbase? x)
    (%display-string "#<" 0)
    ($display (car (%record-rtd x)))
    ($wb 62))
   ((procedure? x) (%display-string "#<procedure>" 0))
   (else (%display-string "#<unknown>" 0))))

(define (%display-tail x)
  (cond
   ((null? x) ($wb 41))
   ((pair? x)
    ($wb 32)
    (display (car x))
    (%display-tail (cdr x)))
   (else
    ($wb 32) ($wb 46) ($wb 32)
    (display x)
    ($wb 41))))

(define (%display-string s i)
  (when (< i (string-length s))
    ($wb (char->integer (string-ref s i)))
    (%display-string s (+ i 1))))

(define (%display-number n)
  (cond
   ((flonum? n) ($display-flonum n))
   ((%bignum? n) ($display-bignum n))
   ((%ratio? n)
    (%display-number (%ratio-num n))
    ($wb 47)
    (%display-number (%ratio-den n)))
   ((%complex? n)
    (%display-number (%cx-re n))
    (let ((im (%cx-im n)))
      (unless (or (< im 0) (and (flonum? im) (fl<? im (fixnum->flonum 0))))
        ($wb 43))
      (%display-number im))
    ($wb 105))
   ((< n 0) ($wb 45) (%display-digits (- 0 n)))
   (else (%display-digits n))))
(define ($display-bignum b)
  (when ($bn-neg? b) ($wb 45))
  ($display-mag (%bignum-limbs b)))
(define ($display-mag m)
  (if (and (= ($mag-len m) 1) (< (vector-ref m 0) 10))
      ($wb (+ 48 (vector-ref m 0)))
      (let ((qr ($mag-divmod-small m 10)))
        ($display-mag (car qr))
        ($wb (+ 48 (cdr qr))))))
(define ($display-flonum x)
  (if (not (fl=? x x))
      (%display-string "+nan.0" 0)
      ($display-flonum* x)))
(define ($display-flonum* x)
  (let* ((zero (fixnum->flonum 0))
         (neg (fl<? x zero))
         (mag (if neg (fl- zero x) x)))
    (when neg ($wb 45))
    (if (fl<? (fixnum->flonum 536870911) mag)
        (%display-string "<big-flonum>" 0)
        (let* ((ip (%fl->fx mag))
               (frac (fl- mag (fixnum->flonum ip))))
          (%display-digits ip)
          ($wb 46)
          ($display-frac frac 0)))))
(define ($display-frac f i)
  ;; up to 12 digits, trimmed via lookahead: stop when the rest is 0
  (if (or (= i 12) (fl=? f (fixnum->flonum 0)))
      (when (zero? i) ($wb 48))
      (let* ((scaled (fl* f (fixnum->flonum 10)))
             (d (%fl->fx scaled)))
        ($wb (+ 48 d))
        ($display-frac (fl- scaled (fixnum->flonum d)) (+ i 1)))))

(define (%display-digits n)
  (if (< n 10)
      ($wb (+ 48 n))
      (begin
        (%display-digits (quotient n 10))
        ($wb (+ 48 (remainder n 10))))))

(define (string=? a b)
  (and (= (string-length a) (string-length b))
       (%string-eq-from a b 0)))

(define (%string-eq-from a b i)
  (or (= i (string-length a))
      (and (eq? (string-ref a i) (string-ref b i))
           (%string-eq-from a b (+ i 1)))))

(define (list . args) args)

(define (length ls)
  (%length ls 0))
(define (%length ls n)
  (if (null? ls) n (%length (cdr ls) (+ n 1))))

(define (append . ls)
  (cond
   ((null? ls) '())
   ((null? (cdr ls)) (car ls))
   (else ($append2 (car ls) (apply append (cdr ls))))))
(define ($append2 a b)
  ($rev-onto (reverse a) b))
(define ($rev-onto rev tail)
  (if (null? rev)
      tail
      ($rev-onto (cdr rev) (cons (car rev) tail))))

(define (filter pred ls) ($filter-acc pred ls '()))
(define ($filter-acc pred ls acc)
  (cond
   ((null? ls) (reverse acc))
   ((pred (car ls)) ($filter-acc pred (cdr ls) (cons (car ls) acc)))
   (else ($filter-acc pred (cdr ls) acc))))

(define (reverse ls)
  (%reverse ls '()))
(define (%reverse ls acc)
  (if (null? ls) acc (%reverse (cdr ls) (cons (car ls) acc))))

(define (memq x ls)
  (cond
   ((null? ls) #f)
   ((eq? (car ls) x) ls)
   (else (memq x (cdr ls)))))

(define (assq x ls)
  (cond
   ((null? ls) #f)
   ((eq? (caar ls) x) (car ls))
   (else (assq x (cdr ls)))))

(define (remq x ls)
  (cond
   ((null? ls) '())
   ((eq? (car ls) x) (remq x (cdr ls)))
   (else (cons (car ls) (remq x (cdr ls))))))

(define (caar p) (car (car p)))
(define (cadr p) (car (cdr p)))
(define (cdar p) (cdr (car p)))
(define (cddr p) (cdr (cdr p)))

(define (equal? a b)
  (cond
   ((pair? a) (and (pair? b)
                   (equal? (car a) (car b))
                   (equal? (cdr a) (cdr b))))
   ((string? a) (and (string? b) (string=? a b)))
   ((vector? a)
    (and (vector? b)
         (= (vector-length a) (vector-length b))
         (let loop ((i 0))
           (or (= i (vector-length a))
               (and (equal? (vector-ref a i) (vector-ref b i))
                    (loop (+ i 1)))))))
   (else (eqv? a b))))

;; Multiple values: a list tagged with a unique pair, collapsing to
;; the value itself in the single-value case.
(define $values-tag (cons 0 0))

(define (values . args)
  (if (and (pair? args) (null? (cdr args)))
      (car args)
      (cons $values-tag args)))

(define (call-with-values producer consumer)
  (let ((v (producer)))
    (if (and (pair? v) (eq? (car v) $values-tag))
        (apply consumer (cdr v))
        (consumer v))))

;; ---- strings <-> lists ----

(define (list->string ls)
  (let ((s (%make-string (length ls))))
    (%fill-string s ls 0)
    s))
(define (%fill-string s ls i)
  (unless (null? ls)
    (string-set! s i (car ls))
    (%fill-string s (cdr ls) (+ i 1))))

(define (string->list s)
  (%string->list s (- (string-length s) 1) '()))
(define (%string->list s i acc)
  (if (< i 0)
      acc
      (%string->list s (- i 1) (cons (string-ref s i) acc))))

;; ---- runtime symbol interning ----
;;
;; The table starts as the compile-time interned symbols (pulled
;; lazily from the module), so read and string->symbol agree with
;; symbol literals under eq?.

(define $symtab #f)

(define (string->symbol s)
  (when (eq? $symtab #f)
    (set! $symtab (%interned-symbols)))
  (%intern s $symtab))
(define (%intern s tab)
  (cond
   ((null? tab)
    (let ((sym (%make-symbol s)))
      (set! $symtab (cons sym $symtab))
      sym))
   ((string=? (symbol->string (car tab)) s) (car tab))
   (else (%intern s (cdr tab)))))

;; ---- ports ----
;;
;; Console I/O rides the two host imports; string ports are plain
;; records.  The reader and the printers dispatch through the current
;; ports, so with-output-to-string and friends need no host support.

(define-record-type ($port $make-port port?)
  (fields (immutable kind $port-kind)
          (mutable a $port-a $port-a!)
          (mutable b $port-b $port-b!)))
;; kinds: console-in (a = one-byte pushback), console-out,
;;        string-in (a = string, b = position),
;;        string-out (a = reversed char list)

(define $console-in ($make-port 'console-in -2 0))
(define $console-out ($make-port 'console-out 0 0))
(define $cip $console-in)
(define $cop $console-out)
(define (current-input-port) $cip)
(define (current-output-port) $cop)
(define (input-port? p)
  (and (port? p) (memq ($port-kind p) '(console-in string-in file-in))))
(define (output-port? p)
  (and (port? p) (memq ($port-kind p) '(console-out string-out file-out))))

(define (open-input-string s) ($make-port 'string-in s 0))
(define (open-output-string) ($make-port 'string-out '() 0))
(define (get-output-string p) (list->string (reverse ($port-a p))))

(define ($peek-byte-port p)
  (let ((k ($port-kind p)))
    (cond
     ((eq? k 'console-in)
      (when (= ($port-a p) -2) ($port-a! p (%read-byte)))
      ($port-a p))
     ((eq? k 'string-in)
      (let ((s ($port-a p)) (i ($port-b p)))
        (if (< i (string-length s))
            (char->integer (string-ref s i))
            -1)))
     ((eq? k 'file-in)
      (when (= ($port-b p) -2) ($port-b! p (%fread ($port-a p))))
      ($port-b p))
     (else (errorf 'read "not an input port")))))
(define ($next-byte-port p)
  (let ((b ($peek-byte-port p)))
    (let ((k ($port-kind p)))
      (cond
       ((eq? k 'console-in) ($port-a! p -2))
       ((eq? k 'file-in) ($port-b! p -2))
       ((eq? k 'string-in)
        (when (< -1 b) ($port-b! p (+ ($port-b p) 1))))))
    b))
(define ($write-byte-port p byte)
  (let ((k ($port-kind p)))
    (cond
     ((eq? k 'console-out) (%write-byte byte))
     ((eq? k 'string-out)
      ($port-a! p (cons (integer->char byte) ($port-a p))))
     ((eq? k 'file-out) (%fwrite ($port-a p) byte))
     (else (errorf 'write "not an output port")))))

(define (%peek-byte) ($peek-byte-port $cip))
(define (%next-byte) ($next-byte-port $cip))
(define ($wb byte) ($write-byte-port $cop byte))

(define ($with-out p thunk)
  (let ((old $cop))
    (dynamic-wind
      (lambda () (set! $cop p))
      thunk
      (lambda () (set! $cop old)))))
(define ($with-in p thunk)
  (let ((old $cip))
    (dynamic-wind
      (lambda () (set! $cip p))
      thunk
      (lambda () (set! $cip old)))))
(define (with-output-to-string thunk)
  (let ((p (open-output-string)))
    ($with-out p thunk)
    (get-output-string p)))
(define (with-input-from-string s thunk)
  ($with-in (open-input-string s) thunk))

(define (read-char . p)
  (let ((b ($next-byte-port (if (null? p) $cip (car p)))))
    (if (< b 0) (eof-object) (integer->char b))))
(define (peek-char . p)
  (let ((b ($peek-byte-port (if (null? p) $cip (car p)))))
    (if (< b 0) (eof-object) (integer->char b))))
(define (write-char c . p)
  ($write-byte-port (if (null? p) $cop (car p)) (char->integer c)))

;; ---- the reader ----

(define (read . p)
  (if (null? p)
      ($read)
      ($with-in (car p) (lambda () ($read)))))
(define ($read)
  (%skip-blanks)
  (let ((b (%peek-byte)))
    (cond
     ((< b 0) (eof-object))
     ((= b 40) (%next-byte) (%read-list))          ; (
     ((= b 39) (%next-byte) (list 'quote ($read)))  ; '
     ((= b 96) (%next-byte) (list 'quasiquote ($read))) ; `
     ((= b 44)                                     ; , or ,@
      (%next-byte)
      (if (= (%peek-byte) 64)
          (begin (%next-byte) (list 'unquote-splicing ($read)))
          (list 'unquote ($read))))
     ((= b 34) (%next-byte) (%read-string '()))    ; "
     ((= b 35) (%next-byte) (%read-hash))          ; #
     (else (%finish-atom (%read-token '()))))))

(define (%delimiter? b)
  (or (< b 0) (= b 32) (= b 10) (= b 9) (= b 13)
      (= b 40) (= b 41) (= b 59) (= b 34)))

(define (%skip-blanks)
  (let ((b (%peek-byte)))
    (cond
     ((or (= b 32) (= b 10) (= b 9) (= b 13))
      (%next-byte)
      (%skip-blanks))
     ((= b 59)                                     ; ;
      (%skip-line)
      (%skip-blanks))
     (else #f))))
(define (%skip-line)
  (let ((b (%next-byte)))
    (unless (or (< b 0) (= b 10))
      (%skip-line))))

(define (%read-token acc)
  (if (%delimiter? (%peek-byte))
      (reverse acc)
      (%read-token (cons (%next-byte) acc))))

(define (%finish-atom bs)
  (cond
   ((%number-token? bs) (%parse-int bs))
   ((%decimal-token? bs) (%parse-decimal bs))
   ((%ratio-token? bs) (%parse-ratio bs))
   ((%complex-token? bs) (%parse-complex bs))
   (else (string->symbol (%bytes->string bs)))))
(define (%split-at bs byte)
  ;; -> (before . after) at the first occurrence, or #f
  (let loop ((pre '()) (bs bs))
    (cond
     ((null? bs) #f)
     ((= (car bs) byte) (cons (reverse pre) (cdr bs)))
     (else (loop (cons (car bs) pre) (cdr bs))))))
(define (%ratio-token? bs)
  (let ((halves (%split-at bs 47)))                ; /
    (and halves
         (%number-token? (car halves))
         (pair? (cdr halves))
         (%all-digits? (cdr halves)))))
(define (%parse-ratio bs)
  (let ((halves (%split-at bs 47)))
    ($make-rat (%parse-int (car halves))
               (%digits->int (cdr halves) 0))))
(define (%real-token? bs)
  (or (%number-token? bs) (%decimal-token? bs) (%ratio-token? bs)))
(define (%parse-real bs)
  (cond
   ((%number-token? bs) (%parse-int bs))
   ((%decimal-token? bs) (%parse-decimal bs))
   (else (%parse-ratio bs))))
(define (%complex-token? bs)
  ;; [real](+|-)[real]i  or  (+|-)[real]i  or  [real]i
  (and (pair? bs)
       (let ((rev (reverse bs)))
         (and (= (car rev) 105)                    ; trailing i
              (let ((body (reverse (cdr rev))))
                (let ((split (%split-imag body)))
                  (and split
                       (or (null? (car split)) (%real-token? (car split)))
                       (let ((im (cdr split)))
                         (or (equal? im '(43)) (equal? im '(45))
                             (%real-token?
                              (if (= (car im) 43) (cdr im) im)))))))))))
(define (%split-imag body)
  ;; split at the last +/- that isn't the leading sign; the imaginary
  ;; part must carry a sign (R6RS: +2i, -i, 3+4i -- never bare 2i)
  (let loop ((i (- (length body) 1)))
    (cond
     ((< i 1)
      (if (and (pair? body) (memv (car body) '(43 45)))
          (cons '() body)
          #f))
     ((memv (list-ref body i) '(43 45))
      (cons ($take-n body i) (list-tail body i)))
     (else (loop (- i 1))))))
(define ($take-n ls n)
  (if (zero? n) '() (cons (car ls) ($take-n (cdr ls) (- n 1)))))
(define (%parse-complex bs)
  (let* ((body (reverse (cdr (reverse bs))))       ; strip the i
         (split (%split-imag body))
         (re (if (null? (car split)) 0 (%parse-real (car split))))
         (imbs (cdr split))
         (im (cond
              ((null? imbs) 1)
              ((equal? imbs '(43)) 1)              ; +
              ((equal? imbs '(45)) -1)             ; -
              (else (%parse-real
                     (if (= (car imbs) 43) (cdr imbs) imbs))))))
    ($cx re im)))
(define (%parse-decimal bs)
  ;; exact digits over a power of ten, converted to a flonum in one
  ;; rounding -- deterministic across hosts, unlike floating-point
  ;; accumulation
  (let* ((neg (and (pair? bs) (= (car bs) 45)))
         (bs (if neg (cdr bs) bs)))
    (let loop ((bs bs) (digits 0) (fraclen 0) (seen-dot #f))
      (cond
       ((null? bs)
        (let* ((den (let tens ((k fraclen) (acc 1))
                      (if (zero? k) acc (tens (- k 1) (* acc 10)))))
               (v ($->fl ($make-rat digits den))))
          (if neg (fl- (fixnum->flonum 0) v) v)))
       ((= (car bs) 46) (loop (cdr bs) digits fraclen #t))
       (else (loop (cdr bs)
                   (+ (* digits 10) (- (car bs) 48))
                   (if seen-dot (+ fraclen 1) fraclen)
                   seen-dot))))))

(define (%number-token? bs)
  (if (and (pair? bs) (= (car bs) 45))             ; leading -
      (and (pair? (cdr bs)) (%all-digits? (cdr bs)))
      (and (pair? bs) (%all-digits? bs))))
(define (%decimal-token? bs)
  (let ((bs (if (and (pair? bs) (= (car bs) 45)) (cdr bs) bs)))
    (let scan ((bs bs) (digits-before 0) (seen-dot #f) (digits-after 0))
      (cond
       ((null? bs) (and seen-dot (< 0 digits-before) (< 0 digits-after)))
       ((= (car bs) 46)
        (and (not seen-dot) (scan (cdr bs) digits-before #t 0)))
       ((and (< 47 (car bs)) (< (car bs) 58))
        (if seen-dot
            (scan (cdr bs) digits-before #t (+ digits-after 1))
            (scan (cdr bs) (+ digits-before 1) #f 0)))
       (else #f)))))
(define (%all-digits? bs)
  (if (null? bs)
      #t
      (and (< 47 (car bs)) (< (car bs) 58)
           (%all-digits? (cdr bs)))))
(define (%parse-int bs)
  (if (= (car bs) 45)
      (- 0 (%digits->int (cdr bs) 0))
      (%digits->int bs 0)))
(define (%digits->int bs acc)
  (if (null? bs)
      acc
      (%digits->int (cdr bs) (+ (* acc 10) (- (car bs) 48)))))

(define (%bytes->string bs)
  (let ((s (%make-string (length bs))))
    (%fill-bytes s bs 0)
    s))
(define (%fill-bytes s bs i)
  (unless (null? bs)
    (string-set! s i (integer->char (car bs)))
    (%fill-bytes s (cdr bs) (+ i 1))))

(define (%read-list)
  (%skip-blanks)
  (let ((b (%peek-byte)))
    (cond
     ((< b 0) (errorf 'read "unexpected end of input in list"))
     ((= b 41) (%next-byte) '())                   ; )
     ((= b 46)                                     ; . -- dotted tail
      (%next-byte)                                 ;      or dot-initial
      (if (%delimiter? (%peek-byte))               ;      symbol
          (let ((d ($read)))
            (%skip-blanks)
            (%next-byte)                           ; consume )
            d)
          (cons (%finish-atom (cons 46 (%read-token '())))
                (%read-list))))
     (else
      (let ((x ($read)))
        (cons x (%read-list)))))))

(define (%read-string acc)
  (let ((b (%next-byte)))
    (cond
     ((= b 34) (%bytes->string (reverse acc)))
     ((= b 92) (%read-string (cons (%read-escape (%next-byte)) acc))) ; backslash
     (else (%read-string (cons b acc))))))
(define (%read-escape b)
  ;; translate the byte after a backslash; \" and \\ fall through to
  ;; themselves, \n \t \r become the control characters
  (cond
   ((= b 110) 10)      ; \n -> newline
   ((= b 116) 9)       ; \t -> tab
   ((= b 114) 13)      ; \r -> return
   (else b)))

(define (%read-hash)
  (let ((b (%next-byte)))
    (cond
     ((= b 116) #t)                                ; t
     ((= b 102) #f)                                ; f
     ((= b 39) (list 'syntax ($read)))              ; ' -- #'x
     ((= b 40) (list->vector (%read-list)))        ; ( -- #(...) vector
     ((= b 120) (%read-hex 0))                     ; x -- hex literal
     ((= b 92)                                     ; \ -- character
      (let ((first (%next-byte)))
        (if (%delimiter? (%peek-byte))
            (integer->char first)
            (%named-char (%bytes->string
                          (cons first (%read-token '())))))))
     (else (eof-object)))))

(define (%read-hex acc)
  (let ((b (%peek-byte)))
    (cond
     ((and (< 47 b) (< b 58))                      ; 0-9
      (%next-byte)
      (%read-hex (+ (* acc 16) (- b 48))))
     ((and (< 96 b) (< b 103))                     ; a-f
      (%next-byte)
      (%read-hex (+ (* acc 16) (+ 10 (- b 97)))))
     ((and (< 64 b) (< b 71))                      ; A-F
      (%next-byte)
      (%read-hex (+ (* acc 16) (+ 10 (- b 65)))))
     (else acc))))

(define (%named-char name)
  ;; the full R6RS set; an unknown name is an error, not a silent
  ;; first-character guess (#\return once read as #\r that way)
  (cond
   ((string=? name "space") #\space)
   ((string=? name "newline") #\newline)
   ((string=? name "tab") (integer->char 9))
   ((string=? name "return") (integer->char 13))
   ((string=? name "linefeed") (integer->char 10))
   ((string=? name "nul") (integer->char 0))
   ((string=? name "alarm") (integer->char 7))
   ((string=? name "backspace") (integer->char 8))
   ((string=? name "vtab") (integer->char 11))
   ((string=? name "page") (integer->char 12))
   ((string=? name "esc") (integer->char 27))
   ((string=? name "delete") (integer->char 127))
   ((= (string-length name) 1) (string-ref name 0))
   (else (error 'read "unknown character name" name))))

;; ---- write ----

(define (write x . p)
  (if (null? p) ($write x) ($with-out (car p) (lambda () ($write x)))))
(define ($write x)
  (cond
   ((string? x)
    ($wb 34)
    (%write-escaped x 0)
    ($wb 34))
   ((char? x)
    ($wb 35) ($wb 92)
    (%write-char-name x))
   ((pair? x)
    ($wb 40)
    (write (car x))
    (%write-tail (cdr x)))
   ((vector? x)
    ($wb 35) ($wb 40)
    (let loop ((i 0))
      (when (< i (vector-length x))
        (unless (zero? i) ($wb 32))
        (write (vector-ref x i))
        (loop (+ i 1))))
    ($wb 41))
   (else (display x))))

(define (%write-tail x)
  (cond
   ((null? x) ($wb 41))
   ((pair? x)
    ($wb 32)
    (write (car x))
    (%write-tail (cdr x)))
   (else
    ($wb 32) ($wb 46) ($wb 32)
    (write x)
    ($wb 41))))

(define (%write-escaped s i)
  (when (< i (string-length s))
    (let ((c (char->integer (string-ref s i))))
      (when (or (= c 34) (= c 92))
        ($wb 92))
      ($wb c))
    (%write-escaped s (+ i 1))))

(define (%write-char-name c)
  (let ((n (char->integer c)))
    (cond
     ((= n 32) (%display-string "space" 0))
     ((= n 10) (%display-string "newline" 0))
     ((= n 9) (%display-string "tab" 0))
     (else ($wb n)))))

;; ---- additions for self-hosting ----

(define (void) (begin))

(define (> a b) (< b a))
(define (<= a b) (if (< b a) #f #t))
(define (>= a b) (if (< a b) #f #t))
(define (max a b) (if (< a b) b a))
(define (min a b) (if (< a b) a b))

(define (list? x)
  (if (null? x) #t (and (pair? x) (list? (cdr x)))))

(define (memv x ls) (memq x ls))
(define (assv x ls) (assq x ls))
(define (member x ls)
  (cond
   ((null? ls) #f)
   ((equal? (car ls) x) ls)
   (else (member x (cdr ls)))))
(define (assoc x ls)
  (cond
   ((null? ls) #f)
   ((equal? (caar ls) x) (car ls))
   (else (assoc x (cdr ls)))))

(define (list-tail ls n)
  (if (zero? n) ls (list-tail (cdr ls) (- n 1))))
(define (list-ref ls n)
  (car (list-tail ls n)))

(define (fold-left f init ls)
  (if (null? ls)
      init
      (fold-left f (f init (car ls)) (cdr ls))))
(define (fold-right f init ls)
  (if (null? ls)
      init
      (f (car ls) (fold-right f init (cdr ls)))))

(define (caddr p) (car (cddr p)))
(define (cdddr p) (cdr (cddr p)))
(define (cadddr p) (car (cdddr p)))
(define (cdadr p) (cdr (cadr p)))
(define (caadr p) (car (cadr p)))

(define (make-list n x)
  (if (zero? n) '() (cons x (make-list (- n 1) x))))

(define (number->string n)
  (with-output-to-string (lambda () (display n))))
(define (string->number s)
  (let ((bs (map (lambda (c) (char->integer c)) (string->list s))))
    (cond
     ((%number-token? bs) (%parse-int bs))
     ((%decimal-token? bs) (%parse-decimal bs))
     (else #f))))

;; gensyms: fresh uninterned symbol structs; identity comes from the
;; struct allocation, so even same-named gensyms are distinct
(define $gensym-count 0)
(define (gensym prefix)
  (set! $gensym-count (+ $gensym-count 1))
  (%make-symbol (string-append prefix (number->string $gensym-count))))


(define (%abort) (%unreachable))

;; compatible with the host Chez errorf; format directives print as-is
(define (errorf who msg . irritants)
  (raise ($make-error who msg irritants)))

(define (eqv? a b)
  (or (eq? a b)
      (and (flonum? a) (flonum? b) (fl=? a b))
      (and (%bignum? a) (%bignum? b) ($eq2 a b))
      (and (%ratio? a) (%ratio? b) ($eq2 a b))
      (and (%complex? a) (%complex? b)
           (eqv? (%cx-re a) (%cx-re b))
           (eqv? (%cx-im a) (%cx-im b)))))
(define (number? x)
  (or (fixnum? x) (flonum? x) (%bignum? x) (%ratio? x) (%complex? x)))
(define (integer? x)
  (or (fixnum? x) (%bignum? x)
      (and (flonum? x) (fl=? x (flfloor x)))))
(define (exact? x)
  (or (fixnum? x) (%bignum? x) (%ratio? x)
      (and (%complex? x) (exact? (%cx-re x)) (exact? (%cx-im x)))))
(define (inexact? x) (and (number? x) (not (exact? x))))
(define (cadar p) (car (cdar p)))

;; ---- derived binding forms (macros live in the prelude too) ----

;; both bind sequentially
(define-syntax let-values
  (syntax-rules ()
    ((_ () body1 body2 ...) (let () body1 body2 ...))
    ((_ ((formals expr) rest ...) body1 body2 ...)
     (call-with-values (lambda () expr)
       (lambda formals (let-values (rest ...) body1 body2 ...))))))
(define-syntax let*-values
  (syntax-rules ()
    ((_ bindings body1 body2 ...) (let-values bindings body1 body2 ...))))

(define-syntax assert
  (syntax-rules ()
    ((_ e) (let ((t e)) (if t t (errorf 'assert "assertion failed"))))))

(define (cons* a . rest) ($cons* a rest))
(define ($cons* a rest)
  (if (null? rest) a (cons a ($cons* (car rest) (cdr rest)))))

;; n-ary map and for-each
(define (map f ls . more)
  (if (null? more) ($map1 f ls) ($mapn f (cons ls more))))
(define ($map1 f ls) ($map1-acc f ls '()))
(define ($map1-acc f ls acc)
  (if (null? ls)
      (reverse acc)
      ($map1-acc f (cdr ls) (cons (f (car ls)) acc))))
(define ($mapn f lists)
  (if ($any-null? lists)
      '()
      (cons (apply f ($heads lists)) ($mapn f ($tails lists)))))
(define ($any-null? ls)
  (and (pair? ls) (or (null? (car ls)) ($any-null? (cdr ls)))))
(define ($heads ls) (if (null? ls) '() (cons (caar ls) ($heads (cdr ls)))))
(define ($tails ls) (if (null? ls) '() (cons (cdar ls) ($tails (cdr ls)))))
(define (for-each f ls . more)
  (if (null? more) ($for-each1 f ls) ($for-eachn f (cons ls more))))
(define ($for-each1 f ls)
  (unless (null? ls)
    (f (car ls))
    ($for-each1 f (cdr ls))))
(define ($for-eachn f lists)
  (unless ($any-null? lists)
    (apply f ($heads lists))
    ($for-eachn f ($tails lists))))

;; ---- dynamic-wind ----
;;
;; $winders holds (before . after) frames.  Escaping continuations
;; capture the winder stack; $escape runs the after thunks of every
;; frame being exited, then throws to the matching call/cc.

(define $winders '())

(define (dynamic-wind before thunk after)
  (before)
  (set! $winders (cons (cons before after) $winders))
  (let ((r (thunk)))
    (set! $winders (cdr $winders))
    (after)
    r))

(define ($escape tok saved v)
  ($unwind-to saved)
  (%throw-k tok v))
(define ($unwind-to saved)
  (unless (eq? $winders saved)
    (let ((w (car $winders)))
      (set! $winders (cdr $winders))
      ((cdr w))
      ($unwind-to saved))))

;; ---- vectors ----

(define (make-vector n . fill)
  (%make-vector n (if (null? fill) 0 (car fill))))
(define (vector . els) (list->vector els))
(define (list->vector ls)
  (let ((v (%make-vector (length ls) 0)))
    ($vfill! v ls 0)
    v))
(define ($vfill! v ls i)
  (unless (null? ls)
    (vector-set! v i (car ls))
    ($vfill! v (cdr ls) (+ i 1))))
(define (vector->list v)
  ($v->l v (- (vector-length v) 1) '()))
(define ($v->l v i acc)
  (if (< i 0) acc ($v->l v (- i 1) (cons (vector-ref v i) acc))))
(define (vector-fill! v x)
  ($vf! v x 0))
(define ($vf! v x i)
  (when (< i (vector-length v))
    (vector-set! v i x)
    ($vf! v x (+ i 1))))
(define (vector-map f v) (list->vector (map f (vector->list v))))
(define (vector-for-each f v) (for-each f (vector->list v)))

;; ---- bytevectors ----

(define (make-bytevector n . fill)
  (%make-bytevector n (if (null? fill) 0 (car fill))))
(define (bytevector . bytes)
  (let ((bv (%make-bytevector (length bytes) 0)))
    ($bvfill! bv bytes 0)
    bv))
(define ($bvfill! bv ls i)
  (unless (null? ls)
    (bytevector-u8-set! bv i (car ls))
    ($bvfill! bv (cdr ls) (+ i 1))))
(define (bytevector=? a b)
  (and (= (bytevector-length a) (bytevector-length b))
       ($bv= a b 0)))
(define ($bv= a b i)
  (or (= i (bytevector-length a))
      (and (= (bytevector-u8-ref a i) (bytevector-u8-ref b i))
           ($bv= a b (+ i 1)))))
(define (utf8->string bv)
  (let ((s (%make-string (bytevector-length bv))))
    ($bv->s bv s 0)
    s))
(define ($bv->s bv s i)
  (when (< i (bytevector-length bv))
    (string-set! s i (integer->char (bytevector-u8-ref bv i)))
    ($bv->s bv s (+ i 1))))
(define (string->utf8 str)
  (let ((bv (%make-bytevector (string-length str) 0)))
    ($s->bv str bv 0)
    bv))
(define ($s->bv str bv i)
  (when (< i (string-length str))
    (bytevector-u8-set! bv i (char->integer (string-ref str i)))
    ($s->bv str bv (+ i 1))))

;; ---- hashtables (buckets of alists over vectors) ----

(define-record-type (hashtable $make-ht hashtable?)
  (fields (immutable hash $ht-hash)
          (immutable equiv $ht-equiv)
          (mutable size $ht-size $ht-size-set!)
          (mutable buckets $ht-buckets $ht-buckets-set!)))

(define (make-eq-hashtable . _) ($new-ht $eqv-hash eq?))
(define (make-eqv-hashtable . _) ($new-ht $eqv-hash eqv?))
(define (make-hashtable hash equiv . _) ($new-ht hash equiv))
(define ($new-ht h e) ($make-ht h e 0 (make-vector 8 '())))

(define (abs n) (if (< n 0) (- 0 n) n))
(define (string-hash s) ($sh s 0 7))
(define ($sh s i h)
  (if (< i (string-length s))
      ($sh s (+ i 1)
           (remainder (+ (* h 31) (char->integer (string-ref s i)))
                      536870911))
      h))
(define ($eqv-hash k)
  (cond
   ((fixnum? k) (abs k))
   ((number? k) 0)
   ((char? k) (char->integer k))
   ((symbol? k) (string-hash (symbol->string k)))
   ((eq? k #t) 1)
   ((eq? k #f) 2)
   ((null? k) 3)
   (else 0)))
(define (equal-hash k)
  (cond
   ((string? k) (string-hash k))
   ((pair? k) (remainder (+ (* 31 (equal-hash (car k)))
                            (equal-hash (cdr k)))
                         536870911))
   (else ($eqv-hash k))))

(define ($ht-index ht k)
  (remainder (abs (($ht-hash ht) k))
             (vector-length ($ht-buckets ht))))
(define ($bucket-find equiv k bucket)
  (cond
   ((null? bucket) #f)
   ((equiv (caar bucket) k) (car bucket))
   (else ($bucket-find equiv k (cdr bucket)))))

(define (hashtable-ref ht k default)
  (let ((hit ($bucket-find ($ht-equiv ht) k
                           (vector-ref ($ht-buckets ht) ($ht-index ht k)))))
    (if hit (cdr hit) default)))
(define (hashtable-contains? ht k)
  (if ($bucket-find ($ht-equiv ht) k
                    (vector-ref ($ht-buckets ht) ($ht-index ht k)))
      #t
      #f))
(define (hashtable-set! ht k v)
  (let* ((i ($ht-index ht k))
         (bucket (vector-ref ($ht-buckets ht) i))
         (hit ($bucket-find ($ht-equiv ht) k bucket)))
    (if hit
        (set-cdr! hit v)
        (begin
          (vector-set! ($ht-buckets ht) i (cons (cons k v) bucket))
          ($ht-size-set! ht (+ ($ht-size ht) 1))
          (when (< (* 2 (vector-length ($ht-buckets ht))) ($ht-size ht))
            ($ht-grow! ht))))))
(define (hashtable-delete! ht k)
  (let* ((i ($ht-index ht k))
         (bucket (vector-ref ($ht-buckets ht) i)))
    (vector-set! ($ht-buckets ht) i
                 ($bucket-remove ($ht-equiv ht) k bucket
                                 (lambda () ($ht-size-set! ht (- ($ht-size ht) 1)))))))
(define ($bucket-remove equiv k bucket shrink!)
  (cond
   ((null? bucket) '())
   ((equiv (caar bucket) k) (shrink!) (cdr bucket))
   (else (cons (car bucket)
               ($bucket-remove equiv k (cdr bucket) shrink!)))))
(define (hashtable-size ht) ($ht-size ht))
(define (hashtable-update! ht k proc default)
  (hashtable-set! ht k (proc (hashtable-ref ht k default))))
(define (hashtable-keys ht)
  (list->vector ($ht-fold ht (lambda (k v acc) (cons k acc)) '())))
(define ($ht-fold ht f acc)
  (let ((buckets ($ht-buckets ht)))
    (let loop ((i 0) (acc acc))
      (if (= i (vector-length buckets))
          acc
          (loop (+ i 1)
                (let scan ((b (vector-ref buckets i)) (acc acc))
                  (if (null? b)
                      acc
                      (scan (cdr b) (f (caar b) (cdar b) acc)))))))))
(define ($ht-grow! ht)
  (let ((old ($ht-buckets ht)))
    ($ht-buckets-set! ht (make-vector (* 2 (vector-length old)) '()))
    ($ht-size-set! ht 0)
    (let loop ((i 0))
      (when (< i (vector-length old))
        (let scan ((b (vector-ref old i)))
          (unless (null? b)
            (hashtable-set! ht (caar b) (cdar b))
            (scan (cdr b))))
        (loop (+ i 1))))))

;; ---- the numeric tower: bignums and flonum contagion ----
;;
;; Bignums: sign flag plus a vector of 15-bit limbs, little-endian.
;; The compiler's inline fixnum paths call $add2/$sub2/$mul2/$quot2/
;; $rem2/$lt2/$eq2 on overflow or non-fixnum operands.

(define ($bn-limbs-of n)                ; fixnum magnitude -> limb vector
  (let count ((m n) (k 0))
    (if (zero? m)
        (let ((v (make-vector (if (< 0 k) k 1) 0)))
          (let fill ((m n) (i 0))
            (if (zero? m)
                v
                (begin (vector-set! v i (remainder m 16384))
                       (fill (quotient m 16384) (+ i 1))))))
        (count (quotient m 16384) (+ k 1)))))
(define ($fx->bn n)
  (cond
   ((< n 0)
    ;; negating -2^29 overflows back into the slow path; its limbs
    ;; are known
    (if (= n (* -2 268435456))
        (%make-bignum 1 (vector 0 0 2))
        (%make-bignum 1 ($bn-limbs-of (- 0 n)))))
   (else (%make-bignum 0 ($bn-limbs-of n)))))
(define ($->bn x) (if (fixnum? x) ($fx->bn x) x))
(define ($bn-neg? b) (= (%bignum-sign b) 1))

(define ($bn-norm sign limbs)
  ;; strip leading zeroes; collapse to a fixnum when the value fits
  ;; (three limbs still fit when the top one is 0 or 1)
  (let strip ((n (vector-length limbs)))
    (cond
     ((and (< 1 n) (zero? (vector-ref limbs (- n 1)))) (strip (- n 1)))
     ;; the asymmetric fixnum boundary: -2^29 fits, +2^29 does not
     ;; (the product below stays on the inline fast path)
     ((and (= n 3) (= sign 1)
           (= (vector-ref limbs 2) 2)
           (zero? (vector-ref limbs 1))
           (zero? (vector-ref limbs 0)))
      (* -2 268435456))
     ((or (< n 3) (and (= n 3) (< (vector-ref limbs 2) 2)))
      (let ((v (+ (vector-ref limbs 0)
                  (if (< 1 n) (* (vector-ref limbs 1) 16384) 0)
                  (if (< 2 n) (* (vector-ref limbs 2) 268435456) 0))))
        (if (= sign 1) (- 0 v) v)))
     (else
      (%make-bignum sign
                    (if (= n (vector-length limbs))
                        limbs
                        (let ((w (make-vector n 0)))
                          (let copy ((i 0))
                            (if (= i n)
                                w
                                (begin (vector-set! w i (vector-ref limbs i))
                                       (copy (+ i 1))))))))))))

(define ($mag-cmp a b)                  ; limb vectors -> -1 0 1
  (let ((la ($mag-len a)) (lb ($mag-len b)))
    (cond
     ((< la lb) -1)
     ((< lb la) 1)
     (else
      (let loop ((i (- la 1)))
        (cond
         ((< i 0) 0)
         ((< (vector-ref a i) (vector-ref b i)) -1)
         ((< (vector-ref b i) (vector-ref a i)) 1)
         (else (loop (- i 1)))))))))
(define ($mag-len v)                    ; length ignoring leading zeroes
  (let loop ((n (vector-length v)))
    (if (and (< 1 n) (zero? (vector-ref v (- n 1))))
        (loop (- n 1))
        n)))

(define ($mag-add a b)
  (let* ((la ($mag-len a)) (lb ($mag-len b))
         (n (+ (if (< la lb) lb la) 1))
         (r (make-vector n 0)))
    (let loop ((i 0) (carry 0))
      (if (= i n)
          r
          (let ((s (+ carry
                      (+ (if (< i la) (vector-ref a i) 0)
                         (if (< i lb) (vector-ref b i) 0)))))
            (vector-set! r i (remainder s 16384))
            (loop (+ i 1) (quotient s 16384)))))))
(define ($mag-sub a b)                  ; assumes a >= b
  (let* ((la ($mag-len a))
         (r (make-vector la 0)))
    (let loop ((i 0) (borrow 0))
      (if (= i la)
          r
          (let ((d (- (- (vector-ref a i) borrow)
                      (if (< i ($mag-len b)) (vector-ref b i) 0))))
            (if (< d 0)
                (begin (vector-set! r i (+ d 16384)) (loop (+ i 1) 1))
                (begin (vector-set! r i d) (loop (+ i 1) 0))))))))
(define ($mag-mul a b)
  (let* ((la ($mag-len a)) (lb ($mag-len b))
         (r (make-vector (+ la lb) 0)))
    (let outer ((i 0))
      (if (= i la)
          r
          (begin
            (let inner ((j 0) (carry 0))
              (if (= j lb)
                  (vector-set! r (+ i j)
                               (+ (vector-ref r (+ i j)) carry))
                  (let ((t (+ (+ (vector-ref r (+ i j)) carry)
                              (* (vector-ref a i) (vector-ref b j)))))
                    (vector-set! r (+ i j) (remainder t 16384))
                    (inner (+ j 1) (quotient t 16384)))))
            (outer (+ i 1)))))))
(define ($mag-divmod-small v d)         ; -> (quotient-vec . rem-fixnum)
  (let* ((n ($mag-len v))
         (q (make-vector n 0)))
    (let loop ((i (- n 1)) (rem 0))
      (if (< i 0)
          (cons q rem)
          (let ((cur (+ (* rem 16384) (vector-ref v i))))
            (vector-set! q i (quotient cur d))
            (loop (- i 1) (remainder cur d)))))))

(define ($bn-add a b)                   ; bignum x bignum
  (let ((sa (%bignum-sign a)) (sb (%bignum-sign b))
        (ma (%bignum-limbs a)) (mb (%bignum-limbs b)))
    (cond
     ((= sa sb) ($bn-norm sa ($mag-add ma mb)))
     ((< ($mag-cmp ma mb) 0) ($bn-norm sb ($mag-sub mb ma)))
     (else ($bn-norm sa ($mag-sub ma mb))))))
(define ($bn-negate b)
  (%make-bignum (- 1 (%bignum-sign b)) (%bignum-limbs b)))

(define ($->fl x)
  (cond
   ((flonum? x) x)
   ((fixnum? x) (fixnum->flonum x))
   ((%ratio? x) (fl/ ($->fl (%ratio-num x)) ($->fl (%ratio-den x))))
   (else
    (let* ((m (%bignum-limbs x))
           (base (fixnum->flonum 16384))
           (mag (let loop ((i (- ($mag-len m) 1)) (acc (fixnum->flonum 0)))
                  (if (< i 0)
                      acc
                      (loop (- i 1)
                            (fl+ (fl* acc base)
                                 (fixnum->flonum (vector-ref m i))))))))
      (if ($bn-neg? x) (fl- (fixnum->flonum 0) mag) mag)))))

(define ($add2 a b)
  (cond
   ((or (%complex? a) (%complex? b))
    ($cx ($add2 (real-part a) (real-part b))
         ($add2 (imag-part a) (imag-part b))))
   ((or (flonum? a) (flonum? b))
    (fl+ ($->fl a) ($->fl b)))
   ((or (%ratio? a) (%ratio? b))
    ($make-rat ($add2 ($mul2 (numerator a) (denominator b))
                      ($mul2 (numerator b) (denominator a)))
               ($mul2 (denominator a) (denominator b))))
   (else ($bn-add ($->bn a) ($->bn b)))))
(define ($sub2 a b)
  (cond
   ((or (%complex? a) (%complex? b))
    ($cx ($sub2 (real-part a) (real-part b))
         ($sub2 (imag-part a) (imag-part b))))
   ((or (flonum? a) (flonum? b))
    (fl- ($->fl a) ($->fl b)))
   ((or (%ratio? a) (%ratio? b))
    ($make-rat ($sub2 ($mul2 (numerator a) (denominator b))
                      ($mul2 (numerator b) (denominator a)))
               ($mul2 (denominator a) (denominator b))))
   (else ($bn-add ($->bn a) ($bn-negate ($->bn b))))))
(define ($mul2 a b)
  (cond
   ((or (%complex? a) (%complex? b))
    (let ((ar (real-part a)) (ai (imag-part a))
          (br (real-part b)) (bi (imag-part b)))
      ($cx ($sub2 ($mul2 ar br) ($mul2 ai bi))
           ($add2 ($mul2 ar bi) ($mul2 ai br)))))
   ((or (flonum? a) (flonum? b))
    (fl* ($->fl a) ($->fl b)))
   ((or (%ratio? a) (%ratio? b))
    ($make-rat ($mul2 (numerator a) (numerator b))
               ($mul2 (denominator a) (denominator b))))
   (else
    (let ((ba ($->bn a)) (bb ($->bn b)))
      ($bn-norm (if (= (%bignum-sign ba) (%bignum-sign bb)) 0 1)
                ($mag-mul (%bignum-limbs ba) (%bignum-limbs bb)))))))
(define ($quot2 a b)
  (cond
   ((or (flonum? a) (flonum? b))
    (fltruncate (fl/ ($->fl a) ($->fl b))))
   ((and (%bignum? a) (fixnum? b) (< 0 b) (< b 16385))
    (let ((qr ($mag-divmod-small (%bignum-limbs a) b)))
      ($bn-norm (%bignum-sign a) (car qr))))
   ((and (integer? a) (integer? b))
    (when ($eq2 b 0) (errorf 'quotient "division by zero"))
    (let* ((ba ($->bn a)) (bb ($->bn b))
           (qr ($mag-divmod (%bignum-limbs ba) (%bignum-limbs bb))))
      ($bn-norm (if (= (%bignum-sign ba) (%bignum-sign bb)) 0 1)
                (car qr))))
   (else (errorf 'quotient "unsupported operand combination"))))
(define ($rem2 a b)
  (cond
   ((or (flonum? a) (flonum? b))
    (let ((q (fltruncate (fl/ ($->fl a) ($->fl b)))))
      (fl- ($->fl a) (fl* q ($->fl b)))))
   ((and (%bignum? a) (fixnum? b) (< 0 b) (< b 16385))
    (let ((r (cdr ($mag-divmod-small (%bignum-limbs a) b))))
      (if ($bn-neg? a) (- 0 r) r)))
   ((and (integer? a) (integer? b))
    (when ($eq2 b 0) (errorf 'remainder "division by zero"))
    (let* ((ba ($->bn a)) (bb ($->bn b))
           (qr ($mag-divmod (%bignum-limbs ba) (%bignum-limbs bb)))
           (r ($bn-norm 0 (cdr qr))))
      (if ($bn-neg? ba) (- 0 r) r)))
   (else (errorf 'remainder "unsupported operand combination"))))
(define ($lt2 a b)
  (cond
   ((or (%complex? a) (%complex? b))
    (errorf '< "complex numbers are not ordered"))
   ((or (flonum? a) (flonum? b))
    (fl<? ($->fl a) ($->fl b)))
   ((or (%ratio? a) (%ratio? b))
    ;; denominators are positive, so cross-multiplication is safe
    ($lt2 ($mul2 (numerator a) (denominator b))
          ($mul2 (numerator b) (denominator a))))
   (else
    (let* ((ba ($->bn a)) (bb ($->bn b))
           (sa (%bignum-sign ba)) (sb (%bignum-sign bb)))
      (cond
       ((< sa sb) #f)
       ((< sb sa) #t)
       ((= sa 1) (< 0 ($mag-cmp (%bignum-limbs ba) (%bignum-limbs bb))))
       (else (< ($mag-cmp (%bignum-limbs ba) (%bignum-limbs bb)) 0)))))))
(define ($eq2 a b)
  (cond
   ((or (%complex? a) (%complex? b))
    (and ($eq2 (real-part a) (real-part b))
         ($eq2 (imag-part a) (imag-part b))))
   ((or (flonum? a) (flonum? b))
    (fl=? ($->fl a) ($->fl b)))
   ((or (%ratio? a) (%ratio? b))
    (and ($eq2 (numerator a) (numerator b))
         ($eq2 (denominator a) (denominator b))))
   (else
    (let ((ba ($->bn a)) (bb ($->bn b)))
      (and (= (%bignum-sign ba) (%bignum-sign bb))
           (zero? ($mag-cmp (%bignum-limbs ba) (%bignum-limbs bb))))))))

;; division and conversions
(define (/ a . rest)
  (if (null? rest)
      ($div2 1 a)
      (fold-left $div2 a rest)))
(define ($div2 a b)
  (cond
   ((or (%complex? a) (%complex? b))
    (let* ((ar (real-part a)) (ai (imag-part a))
           (br (real-part b)) (bi (imag-part b))
           (den ($add2 ($mul2 br br) ($mul2 bi bi))))
      ($cx ($div2 ($add2 ($mul2 ar br) ($mul2 ai bi)) den)
           ($div2 ($sub2 ($mul2 ai br) ($mul2 ar bi)) den))))
   ((or (flonum? a) (flonum? b))
    (fl/ ($->fl a) ($->fl b)))
   (else
    ($make-rat ($mul2 (numerator a) (denominator b))
               ($mul2 (denominator a) (numerator b))))))
(define (exact->inexact x) ($->fl x))
(define (inexact x) ($->fl x))
(define ($fl->exact-integer m)
  ;; integral non-negative flonum -> exact, in 2^24 chunks
  (let ((two24 (fixnum->flonum 16777216)))
    (let loop ((m m) (acc 0) (scale 1))
      (if (fl<? m (fixnum->flonum 1))
          acc
          (let* ((q (flfloor (fl/ m two24)))
                 (digit (%fl->fx (fl- m (fl* q two24)))))
            (loop q (+ acc (* digit scale)) (* scale 16777216)))))))
(define (inexact->exact x)
  (if (flonum? x)
      (let* ((zero (fixnum->flonum 0))
             (neg (fl<? x zero))
             (mag (if neg (fl- zero x) x)))
        (let loop ((m mag) (k 1))
          (if (fl=? m (flfloor m))
              (let ((v ($make-rat ($fl->exact-integer m) k)))
                (if neg (- 0 v) v))
              (loop (fl* m (fixnum->flonum 2)) (* k 2)))))
      x))
(define (exact x) (inexact->exact x))
(define (floor x) (if (flonum? x) (flfloor x) x))
(define (truncate x) (if (flonum? x) (fltruncate x) x))
(define (sqrt x)
  (if (and (real? x) (< x 0))
      ($cx 0 (flsqrt ($->fl (- 0 x))))
      (flsqrt ($->fl x))))

;; ---- the string library ----

(define (make-string n . fill)
  (let ((s (%make-string n)))
    (unless (null? fill) (string-fill! s (car fill)))
    s))
(define (string-fill! s c)
  (let loop ((i 0))
    (when (< i (string-length s))
      (string-set! s i c)
      (loop (+ i 1)))))
(define (string . chars) (list->string chars))
(define (substring s start end)
  (let ((r (%make-string (- end start))))
    (let loop ((i start))
      (when (< i end)
        (string-set! r (- i start) (string-ref s i))
        (loop (+ i 1))))
    r))
(define (string-copy s) (substring s 0 (string-length s)))
(define (string-append . ss)
  ($strings-join ss))
(define ($strings-join ss)
  (let* ((total (fold-left (lambda (n s) (+ n (string-length s))) 0 ss))
         (r (%make-string total)))
    (let outer ((ss ss) (at 0))
      (if (null? ss)
          r
          (let ((s (car ss)))
            (let inner ((i 0))
              (when (< i (string-length s))
                (string-set! r (+ at i) (string-ref s i))
                (inner (+ i 1))))
            (outer (cdr ss) (+ at (string-length s))))))))

(define ($string-cmp a b)               ; lexicographic: -1 0 1
  (let ((la (string-length a)) (lb (string-length b)))
    (let loop ((i 0))
      (cond
       ((and (= i la) (= i lb)) 0)
       ((= i la) -1)
       ((= i lb) 1)
       ((< (char->integer (string-ref a i)) (char->integer (string-ref b i))) -1)
       ((< (char->integer (string-ref b i)) (char->integer (string-ref a i))) 1)
       (else (loop (+ i 1)))))))
(define (string<? a b) (< ($string-cmp a b) 0))
(define (string>? a b) (< 0 ($string-cmp a b)))
(define (string<=? a b) (< ($string-cmp a b) 1))
(define (string>=? a b) (< -1 ($string-cmp a b)))

(define (char=? a b) (eq? a b))
(define (char<? a b) (< (char->integer a) (char->integer b)))
(define (char>? a b) (< (char->integer b) (char->integer a)))
(define (char<=? a b) (not (char>? a b)))
(define (char>=? a b) (not (char<? a b)))
(define (char-upcase c)
  (let ((n (char->integer c)))
    (if (and (< 96 n) (< n 123)) (integer->char (- n 32)) c)))
(define (char-downcase c)
  (let ((n (char->integer c)))
    (if (and (< 64 n) (< n 91)) (integer->char (+ n 32)) c)))
(define (char-alphabetic? c)
  (let ((n (char->integer c)))
    (or (and (< 64 n) (< n 91)) (and (< 96 n) (< n 123)))))
(define (char-numeric? c)
  (let ((n (char->integer c)))
    (and (< 47 n) (< n 58))))
(define (char-whitespace? c)
  (memv (char->integer c) '(32 9 10 13 12)))

(define (string-upcase s) (string-map (lambda (c) (char-upcase c)) s))
(define (string-downcase s) (string-map (lambda (c) (char-downcase c)) s))
(define (string-map f s) (list->string (map f (string->list s))))
(define (string-for-each f s) (for-each f (string->list s)))

;; ---- exceptions: raise and guard over escape continuations ----
;;
;; A guard pushes its escape continuation on a handler stack; raise
;; pops the nearest one and escapes to it (running dynamic-wind after
;; thunks on the way).  An unmatched guard clause re-raises outward.

(define $handlers '())
(define $exn-mark (cons 0 0))

(define (raise obj)
  (if (null? $handlers)
      ($unhandled obj)
      (let ((k (car $handlers)))
        (set! $handlers (cdr $handlers))
        (k (cons $exn-mark obj)))))
(define (raise-continuable obj) (raise obj))

(define ($try thunk)
  ;; -> result, or ($exn-mark . obj) if something raised
  (call/cc
   (lambda (k)
     (set! $handlers (cons k $handlers))
     (let ((v (thunk)))
       (set! $handlers (cdr $handlers))
       v))))
(define ($guard-hit? r)
  (and (pair? r) (eq? (car r) $exn-mark)))

(define-syntax guard
  (syntax-rules ()
    ((_ (var clause ...) body ...)
     (let ((r ($try (lambda () body ...))))
       (if ($guard-hit? r)
           (let ((var (cdr r)))
             (cond clause ... (else (raise var))))
           r)))))

;; error conditions
(define-record-type ($error-object $make-error error?)
  (fields (immutable who condition-who)
          (immutable msg condition-message)
          (immutable irritants condition-irritants)))
(define (error who msg . irritants)
  (raise ($make-error who msg irritants)))
(define ($unhandled obj)
  (display "unhandled exception: ")
  (if (error? obj)
      (begin
        (display (condition-who obj)) (display ": ")
        (display (condition-message obj))
        (for-each (lambda (x) (display " ") (write x))
                  (condition-irritants obj)))
      (write obj))
  (newline)
  (%abort))

;; ---- full bignum division (shift-subtract, bit at a time) ----

(define ($mag-shl1! v)                  ; v <<= 1 in place, returns carry-out
  (let loop ((i 0) (carry 0))
    (if (= i (vector-length v))
        carry
        (let ((t (+ (* (vector-ref v i) 2) carry)))
          (vector-set! v i (remainder t 16384))
          (loop (+ i 1) (quotient t 16384))))))
(define ($mag-copy v n)
  (let ((r (make-vector n 0)))
    (let loop ((i 0))
      (when (and (< i n) (< i (vector-length v)))
        (vector-set! r i (vector-ref v i))
        (loop (+ i 1))))
    r))
(define $powers2 (vector 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192))
(define ($mag-bit v p)                  ; bit p, lsb-indexed
  (remainder (quotient (vector-ref v (quotient p 14))
                       (vector-ref $powers2 (remainder p 14)))
             2))
(define ($mag-divmod a b)               ; -> (quotient-vec . remainder-vec)
  (let* ((la ($mag-len a))
         (bits (* la 14))
         (q (make-vector la 0))
         (r (make-vector (+ ($mag-len b) 1) 0)))
    (let loop ((p (- bits 1)))
      (if (< p 0)
          (cons q r)
          (begin
            ($mag-shl1! r)
            (when (= 1 ($mag-bit a p))
              (vector-set! r 0 (+ (vector-ref r 0) 1)))
            (when (< -1 ($mag-cmp r b))
              (let ((d ($mag-sub r b)))
                (let copy ((j 0))
                  (when (< j (vector-length r))
                    (vector-set! r j (if (< j (vector-length d))
                                         (vector-ref d j)
                                         0))
                    (copy (+ j 1)))))
              (vector-set! q (quotient p 14)
                           (+ (vector-ref q (quotient p 14))
                              (vector-ref $powers2 (remainder p 14)))))
            (loop (- p 1)))))))

;; ---- rationals ----

(define (gcd a b)
  (let loop ((a (abs a)) (b (abs b)))
    (if ($eq2 b 0) a (loop b (remainder a b)))))
(define (lcm a b)
  (if (or ($eq2 a 0) ($eq2 b 0))
      0
      (abs (* (quotient a (gcd a b)) b))))

(define ($make-rat n d)
  (when ($eq2 d 0) (errorf '/ "division by zero"))
  (let* ((neg (if (< d 0) (not (< n 0)) (< n 0)))
         (n (abs n))
         (d (abs d))
         (g (gcd n d))
         (n (quotient n g))
         (d (quotient d g))
         (n (if neg (- 0 n) n)))
    (if ($eq2 d 1) n (%make-ratio n d))))
(define (numerator x) (if (%ratio? x) (%ratio-num x) x))
(define (denominator x) (if (%ratio? x) (%ratio-den x) 1))
(define (rational? x)
  (or (integer? x) (%ratio? x) (flonum? x)))
(define (real? x) (and (number? x) (not (%complex? x))))
(define (complex? x) (number? x))

;; ---- complex numbers ----

(define ($cx re im)                     ; collapse an exact zero imaginary
  (if (and (exact? im) ($eq2 im 0)) re (%make-complex re im)))
(define (make-rectangular re im) ($cx re im))
(define (real-part x) (if (%complex? x) (%cx-re x) x))
(define (imag-part x) (if (%complex? x) (%cx-im x) 0))
(define (magnitude x)
  (let ((re (real-part x)) (im (imag-part x)))
    (flsqrt ($->fl (+ (* re re) (* im im))))))

;; ---- file ports ----
;;
;; The host accumulates a path pushed byte by byte, then opens it;
;; reads and writes move single bytes through the fd imports.

(define ($send-path s)
  (string-for-each (lambda (c) (%path-byte (char->integer c))) s))
(define (open-input-file path)
  ($send-path path)
  (let ((fd (%open-read)))
    (when (< fd 0) (errorf 'open-input-file "cannot open" path))
    ($make-port 'file-in fd -2)))
(define (open-output-file path)
  ($send-path path)
  (let ((fd (%open-write)))
    (when (< fd 0) (errorf 'open-output-file "cannot open" path))
    ($make-port 'file-out fd 0)))
(define (close-port p)
  (let ((k ($port-kind p)))
    (when (memq k '(file-in file-out))
      (%fclose ($port-a p)))))
(define (close-input-port p) (close-port p))
(define (close-output-port p) (close-port p))
(define (file-exists? path)
  ($send-path path)
  (let ((fd (%open-read)))
    (if (< fd 0)
        #f
        (begin (%fclose fd) #t))))
(define (call-with-input-file path proc)
  (let* ((p (open-input-file path))
         (r (proc p)))
    (close-port p)
    r))
(define (call-with-output-file path proc)
  (let* ((p (open-output-file path))
         (r (proc p)))
    (close-port p)
    r))
(define (with-input-from-file path thunk)
  (let ((p (open-input-file path)))
    (let ((r ($with-in p thunk)))
      (close-port p)
      r)))
(define (with-output-to-file path thunk)
  (let ((p (open-output-file path)))
    (let ((r ($with-out p thunk)))
      (close-port p)
      r)))
