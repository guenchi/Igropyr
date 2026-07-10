#!chezscheme
;;; (igropyr json) -- safe JSON parser and writer.
;;;
;;; A recursive-descent parser over the input string: no reader tricks,
;;; safe for untrusted input (HTTP request bodies). Full string escape
;;; handling including \uXXXX and surrogate pairs.
;;;
;;; Data model (compatible with guenchi/json's path DSL):
;;;   object -> alist with string keys      {"a":1}   -> (("a" . 1))
;;;   array  -> vector                      [1,2]     -> #(1 2)
;;;   string -> string, number -> number
;;;   true/false -> #t/#f, null -> 'null
;;;
;;; (string->json s)   parse; raises #(json-error msg pos) on bad input
;;; (json->string x)   serialize (alists -> objects, vectors -> arrays;
;;;                    plain lists also serialize as arrays)
;;; (json-ref x k ...) path access: string/symbol key for objects,
;;;                    integer index for arrays; #f when absent

(library (igropyr json)
  (export string->json json->string json-ref)
  (import (chezscheme))

  (define (jfail msg pos)
    (raise (vector 'json-error msg pos)))

  ;; ---- parser -----------------------------------------------------------

  (define (string->json s)
    (let ((n (string-length s)))
      (define (skip-ws i)
        (if (and (< i n) (memv (string-ref s i) '(#\space #\tab #\newline #\return)))
            (skip-ws (+ i 1))
            i))
      (define (expect ch i)
        (if (and (< i n) (char=? (string-ref s i) ch))
            (+ i 1)
            (jfail (string-append "expected " (string ch)) i)))
      (define (parse-value i)
        (let ((i (skip-ws i)))
          (when (>= i n) (jfail "unexpected end of input" i))
          (let ((ch (string-ref s i)))
            (cond
              ((char=? ch #\{) (parse-object (+ i 1)))
              ((char=? ch #\[) (parse-array (+ i 1)))
              ((char=? ch #\") (parse-string (+ i 1)))
              ((char=? ch #\t) (parse-literal i "true" #t))
              ((char=? ch #\f) (parse-literal i "false" #f))
              ((char=? ch #\n) (parse-literal i "null" 'null))
              ((or (char=? ch #\-) (char-numeric? ch)) (parse-number i))
              (else (jfail "unexpected character" i))))))
      (define (parse-literal i word value)
        (let ((end (+ i (string-length word))))
          (if (and (<= end n) (string=? (substring s i end) word))
              (values value end)
              (jfail "bad literal" i))))
      (define (parse-object i)
        (let ((i (skip-ws i)))
          (if (and (< i n) (char=? (string-ref s i) #\}))
              (values '() (+ i 1))
              (let loop ((i i) (acc '()))
                (let ((i (skip-ws i)))
                  (unless (and (< i n) (char=? (string-ref s i) #\"))
                    (jfail "expected object key" i))
                  (let-values (((key i) (parse-string (+ i 1))))
                    (let ((i (expect #\: (skip-ws i))))
                      (let-values (((val i) (parse-value i)))
                        (let ((i (skip-ws i)))
                          (cond
                            ((and (< i n) (char=? (string-ref s i) #\,))
                             (loop (+ i 1) (cons (cons key val) acc)))
                            ((and (< i n) (char=? (string-ref s i) #\}))
                             (values (reverse (cons (cons key val) acc)) (+ i 1)))
                            (else (jfail "expected , or } in object" i))))))))))))
      (define (parse-array i)
        (let ((i (skip-ws i)))
          (if (and (< i n) (char=? (string-ref s i) #\]))
              (values (vector) (+ i 1))
              (let loop ((i i) (acc '()))
                (let-values (((val i) (parse-value i)))
                  (let ((i (skip-ws i)))
                    (cond
                      ((and (< i n) (char=? (string-ref s i) #\,))
                       (loop (+ i 1) (cons val acc)))
                      ((and (< i n) (char=? (string-ref s i) #\]))
                       (values (list->vector (reverse (cons val acc))) (+ i 1)))
                      (else (jfail "expected , or ] in array" i)))))))))
      (define (hex4 i)
        (unless (<= (+ i 4) n) (jfail "bad \\u escape" i))
        (let ((v (string->number (substring s i (+ i 4)) 16)))
          (unless v (jfail "bad \\u escape" i))
          v))
      (define (parse-string i)   ; i points after the opening quote
        (call-with-values
          (lambda ()
            (let ((p (open-output-string)))
              (let loop ((i i))
                (when (>= i n) (jfail "unterminated string" i))
                (let ((ch (string-ref s i)))
                  (cond
                    ((char=? ch #\") (values (get-output-string p) (+ i 1)))
                    ((char=? ch #\\)
                     (when (>= (+ i 1) n) (jfail "bad escape" i))
                     (let ((e (string-ref s (+ i 1))))
                       (case e
                         ((#\") (write-char #\" p) (loop (+ i 2)))
                         ((#\\) (write-char #\\ p) (loop (+ i 2)))
                         ((#\/) (write-char #\/ p) (loop (+ i 2)))
                         ((#\b) (write-char (integer->char 8) p) (loop (+ i 2)))
                         ((#\f) (write-char (integer->char 12) p) (loop (+ i 2)))
                         ((#\n) (write-char #\newline p) (loop (+ i 2)))
                         ((#\r) (write-char #\return p) (loop (+ i 2)))
                         ((#\t) (write-char #\tab p) (loop (+ i 2)))
                         ((#\u)
                          (let ((v (hex4 (+ i 2))))
                            (if (and (>= v #xD800) (<= v #xDBFF))
                                ;; high surrogate: expect \uDC00-\uDFFF
                                (begin
                                  (unless (and (<= (+ i 12) n)
                                               (char=? (string-ref s (+ i 6)) #\\)
                                               (char=? (string-ref s (+ i 7)) #\u))
                                    (jfail "lone high surrogate" i))
                                  (let ((lo (hex4 (+ i 8))))
                                    (unless (and (>= lo #xDC00) (<= lo #xDFFF))
                                      (jfail "bad low surrogate" i))
                                    (write-char
                                      (integer->char
                                        (+ #x10000
                                           (* (- v #xD800) #x400)
                                           (- lo #xDC00)))
                                      p)
                                    (loop (+ i 12))))
                                (begin
                                  (when (and (>= v #xDC00) (<= v #xDFFF))
                                    (jfail "lone low surrogate" i))
                                  (write-char (integer->char v) p)
                                  (loop (+ i 6))))))
                         (else (jfail "bad escape" i)))))
                    (else (write-char ch p) (loop (+ i 1))))))))
          values))
      (define (parse-number i)
        (let scan ((j (if (char=? (string-ref s i) #\-) (+ i 1) i))
                   (float? #f))
          (if (and (< j n)
                   (let ((c (string-ref s j)))
                     (or (char-numeric? c)
                         (memv c '(#\. #\e #\E #\+ #\-)))))
              (scan (+ j 1)
                    (or float? (memv (string-ref s j) '(#\. #\e #\E))))
              (let ((v (string->number (substring s i j) 10)))
                (unless v (jfail "bad number" i))
                (values (if (and float? (exact? v)) (exact->inexact v) v) j)))))
      ;; top level: one value, then only whitespace
      (let-values (((v end) (parse-value 0)))
        (unless (= (skip-ws end) n) (jfail "trailing characters" end))
        v)))

  ;; ---- writer ------------------------------------------------------------

  (define (json-escape s)
    (call-with-string-output-port
      (lambda (p)
        (string-for-each
          (lambda (ch)
            (let ((code (char->integer ch)))
              (cond
                ((char=? ch #\") (display "\\\"" p))
                ((char=? ch #\\) (display "\\\\" p))
                ((char=? ch #\newline) (display "\\n" p))
                ((char=? ch #\return) (display "\\r" p))
                ((char=? ch #\tab) (display "\\t" p))
                ((< code #x20)
                 (display "\\u" p)
                 (let ((h (number->string code 16)))
                   (do ((i (string-length h) (+ i 1))) ((= i 4))
                     (write-char #\0 p))
                   (display h p)))
                (else (write-char ch p)))))
          s))))

  (define (number->json v)
    (cond
      ((and (exact? v) (integer? v)) (number->string v))
      ((and (real? v) (or (nan? v) (infinite? v))) "null")
      ((exact? v) (number->string (exact->inexact v)))
      (else (number->string v))))

  (define (json->string x)
    (cond
      ((eq? x #t) "true")
      ((eq? x #f) "false")
      ((eq? x 'null) "null")
      ((number? x) (number->json x))
      ((string? x) (string-append "\"" (json-escape x) "\""))
      ((symbol? x) (string-append "\"" (json-escape (symbol->string x)) "\""))
      ((vector? x)
       (string-append
         "["
         (let loop ((i 0) (acc ""))
           (if (= i (vector-length x))
               acc
               (loop (+ i 1)
                     (if (string=? acc "")
                         (json->string (vector-ref x i))
                         (string-append acc "," (json->string (vector-ref x i)))))))
         "]"))
      ((null? x) "{}")
      ((and (list? x) (pair? (car x)))            ; alist -> object
       (string-append
         "{"
         (fold-right
           (lambda (kv acc)
             (let ((entry (string-append
                            "\"" (json-escape
                                   (if (symbol? (car kv))
                                       (symbol->string (car kv))
                                       (car kv)))
                            "\":" (json->string (cdr kv)))))
               (if (string=? acc "") entry (string-append entry "," acc))))
           "" x)
         "}"))
      ((list? x)                                   ; plain list -> array
       (string-append
         "["
         (fold-right
           (lambda (v acc)
             (if (string=? acc "")
                 (json->string v)
                 (string-append (json->string v) "," acc)))
           "" x)
         "]"))
      (else "null")))

  ;; ---- path access -------------------------------------------------------

  (define (ref1 x k)
    (cond
      ((and (vector? x) (integer? k))
       (and (>= k 0) (< k (vector-length x)) (vector-ref x k)))
      ((and (list? x) (or (string? k) (symbol? k)))
       (let ((key (if (symbol? k) (symbol->string k) k)))
         (let loop ((l x))
           (cond
             ((null? l) #f)
             ((and (pair? (car l)) (equal? (caar l) key)) (cdar l))
             (else (loop (cdr l)))))))
      (else #f)))

  (define (json-ref x . keys)
    (fold-left (lambda (acc k) (and acc (ref1 acc k))) x keys))
)
