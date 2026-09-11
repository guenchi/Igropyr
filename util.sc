#!chezscheme
;;; (igropyr util) -- tiny dependency-free helpers.
;;;
;;; The bottom of the library graph: this file imports only
;;; (chezscheme), so anything may import it. Home for the helpers that
;;; used to be copy-pasted per module (the opt/need option-alist
;;; readers, naive substring search).

(library (igropyr util)
  (export opt need string-search string-contains? string-suffix?
          digits->exact signed-digits->exact hex-digits->exact
          decimal-fraction->number)
  (import (chezscheme))

  ;; option alist reader: value of key, or default when absent
  (define (opt alist key default)
    (let ((p (assq key alist))) (if p (cdr p) default)))

  ;; required option: who names the complaining API in the violation
  (define (need who alist key)
    (let ((p (assq key alist)))
      (unless p (assertion-violation who "missing option" key))
      (cdr p)))

  ;; index of needle in hay at or after start, or #f
  (define (string-search hay needle start)
    (let ((hn (string-length hay)) (nn (string-length needle)))
      (let loop ((i start))
        (cond ((> (+ i nn) hn) #f)
              ((let check ((j 0))
                 (or (= j nn)
                     (and (char=? (string-ref hay (+ i j)) (string-ref needle j))
                          (check (+ j 1)))))
               i)
              (else (loop (+ i 1)))))))

  (define (string-contains? s needle)
    (and (string-search s needle 0) #t))

  (define (string-suffix? suffix s)
    (let ((n (string-length s)) (m (string-length suffix)))
      (and (>= n m) (string=? suffix (substring s (- n m) n)))))

  ;; ---- numeric text that came from outside this process -------------------
  ;;
  ;; string->number READS THE WHOLE NUMERIC SYNTAX, not just the digits a
  ;; caller had in mind: radix and exactness prefixes and an exponent are all
  ;; honoured. So eleven characters of attacker-chosen text can ask for an
  ;; exact 10^99999999 -- and building it neither returns nor stops growing.
  ;; Measured on this implementation: that one call under `timeout 5` exits
  ;; 124, and an overnight run had taken 20 GB before it was noticed.
  ;;
  ;; A BOUND CHECKED AFTERWARDS IS NOT A GUARD. Every site that does this
  ;; already rejects an out-of-range answer -- a port above 65535, a cost
  ;; field over its ceiling, a negative length. None of those lines is ever
  ;; reached, because the conversion they were going to check does not come
  ;; back. The shape has to be constrained BEFORE the conversion, which is
  ;; what these four do: they look at the characters, and only text that is
  ;; already nothing but digits is handed on.
  ;;
  ;; Each answers #f for anything it will not convert, which is the answer
  ;; the callers already have a branch for.

  (define (ascii-digit? c) (and (char>=? c #\0) (char<=? c #\9)))

  (define (ascii-hex-digit? c)
    (or (ascii-digit? c)
        (and (char>=? c #\a) (char<=? c #\f))
        (and (char>=? c #\A) (char<=? c #\F))))

  ;; 1..max-len ASCII digits and nothing else -- no sign, no #, no ., no
  ;; exponent, no whitespace.
  ;;
  ;; LEADING ZEROS KEEP THEIR DECIMAL VALUE: "032768" is 32768, not an octal
  ;; 13624 and not a refusal. Stored fields and wire formats pad, and a
  ;; guard that changed the value of text the system already accepts would
  ;; be a compatibility break wearing a security hat.
  (define (digits->exact s max-len)
    (and (string? s)
         (let ((n (string-length s)))
           (and (fx>= n 1) (fx<= n max-len)
                (let loop ((i 0))
                  (cond
                    ((fx= i n) (string->number s))
                    ((ascii-digit? (string-ref s i)) (loop (fx+ i 1)))
                    (else #f)))))))

  ;; as above with an optional single leading '-', for the wire formats that
  ;; use -1 as a sentinel. max-len bounds the DIGITS; the sign is not counted.
  (define (signed-digits->exact s max-len)
    (and (string? s)
         (let ((n (string-length s)))
           (and (fx>= n 1)
                (if (char=? (string-ref s 0) #\-)
                    (let ((v (digits->exact (substring s 1 n) max-len)))
                      (and v (- v)))
                    (digits->exact s max-len))))))

  ;; 1..max-len ASCII hex digits, either case, read in base 16.
  ;;
  ;; A RADIX ARGUMENT DOES NOT DISABLE THE PREFIXES. string->number with 16
  ;; still honours a leading #e, so a short line of text is as dangerous
  ;; here as anywhere else and the digits have to be checked the same way.
  (define (hex-digits->exact s max-len)
    (and (string? s)
         (let ((n (string-length s)))
           (and (fx>= n 1) (fx<= n max-len)
                (let loop ((i 0))
                  (cond
                    ((fx= i n) (string->number s 16))
                    ((ascii-hex-digit? (string-ref s i)) (loop (fx+ i 1)))
                    (else #f)))))))

  ;; digits with at most one '.', at least one digit somewhere, nothing else.
  ;; Answers an EXACT rational: the checked text is read with an exactness
  ;; prefix this procedure supplies itself, which is safe precisely because
  ;; no exponent survived the shape check.
  ;;
  ;; A LEADING OR TRAILING POINT IS ACCEPTED -- ".5" is 1/2 and "1." is 1.
  ;; Neither is well-formed in the header grammar this serves, but refusing
  ;; them would be this guard inventing a stricter syntax than the thing it
  ;; protects, and a guard that also changes which inputs are legal is two
  ;; changes reported as one.
  (define (decimal-fraction->number s max-len)
    (and (string? s)
         (let ((n (string-length s)))
           (and (fx>= n 1) (fx<= n max-len)
                (let loop ((i 0) (dots 0) (digits 0))
                  (cond
                    ((fx= i n)
                     (and (fx>= digits 1)
                          (string->number (string-append "#e" s))))
                    ((ascii-digit? (string-ref s i))
                     (loop (fx+ i 1) dots (fx+ digits 1)))
                    ((char=? (string-ref s i) #\.)
                     (and (fx= dots 0) (loop (fx+ i 1) 1 digits)))
                    (else #f)))))))
)
