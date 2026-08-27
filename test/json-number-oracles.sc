#!chezscheme
;;; Two independent judges of JSON number syntax, for tests only.
;;;
;;; NEITHER OF THESE IS THE LIBRARY UNDER TEST, and that is the point.
;;; (igropyr json)'s reader deliberately accepts leading zeros, so asking
;;; it whether the writer's output is legal JSON would let "01" pass in
;;; both directions at once -- the check and the thing checked sharing
;;; one mistake. Both judges below are written from RFC 8259 section 6:
;;;
;;;   number = [ minus ] int [ frac ] [ exp ]
;;;   int    = "0" / ( digit1-9 *DIGIT )
;;;   frac   = "." 1*DIGIT
;;;   exp    = ("e" / "E") [ "+" / "-" ] 1*DIGIT
;;;
;;; THEY ARE TWO MECHANISMS, NOT TWO COPIES. One is recursive descent
;;; over the productions; the other is an explicit state machine whose
;;; states are named for the production they sit inside. Two mechanisms
;;; that agree are evidence about the grammar; two copies of one
;;; mechanism agree even when the mechanism is wrong.
;;;
;;; THIS FILE IS IMPORTED, NEVER RUN. It has no entry in run-all.sh
;;; because it is not a suite, and a file with no entry is exactly the
;;; shape that stops being reached without anyone noticing. What keeps
;;; that from being a risk here is that an import which does not resolve
;;; is an immediate non-zero exit: the two suites cannot start without
;;; it. That is not an argument -- it is how a rename in the library
;;; under test was caught, by the whole run stopping at exit 255.
;;;
;;; BE EXACT ABOUT WHAT THAT PROVES, because it is one step short of
;;; what matters. A suite starting proves this file was resolved and
;;; loaded. It does NOT prove both judges are used -- one of them could
;;; be imported and never called, and every suite would still start.
;;; What proves they are both used is the three-way comparison in
;;; json-number-syntax.sc, which names each of them per string. Two
;;; separate facts, two separate mechanisms; run them together in one
;;; sentence and the weaker one borrows the other's certainty.
;;;
;;; WHY THEY LIVE IN ONE FILE, STATED WITHOUT THE EXAGGERATION IT IS
;;; EASY TO WRITE HERE. They used to live one per suite, and the two
;;; were in different positions -- not symmetrically neglected. The
;;; state machine was already put opposite the production predicate over
;;; a large corpus, so a drift in IT would have shown up as a
;;; disagreement. The descent judge had only its own small table and
;;; then judged whatever the formatter happened to emit, so THAT one
;;; could have drifted with every suite green.
;;;
;;; And separate files were never what prevented the comparison: neither
;;; judge was exported. Co-location is convenience. What actually does
;;; the work is that json-number-syntax.sc imports both and puts them,
;;; with production, to every string in its corpora.
;;;
;;; SOURCE-REVIEW INVARIANT, not a behavioural one. That these are two
;;; independent implementations cannot be asserted by any test: a judge
;;; redefined as a call to the other answers identically to every input
;;; there is, so no input distinguishes independence from imitation. It
;;; is enforced by reading this file, and by nothing else. Recording it
;;; as an uncovered behavioural claim would put a permanently unclosable
;;; entry in a coverage ledger.
;;;
;;; If you are tempted to delete one because it duplicates the other:
;;; the duplication is the mechanism. Delete one -- or, more quietly,
;;; define one as a call to the other -- and the three-way comparison in
;;; json-number-syntax.sc becomes a two-way one, WITH EVERY CELL STILL
;;; GREEN. That was measured. Nothing here can detect it, because two
;;; implementations that agree on every input are indistinguishable by
;;; input; it is visible only in this file, by reading.

(library (igropyr test json-number-oracles)
  (export rfc-number-descent? rfc-number-machine?)
  (import (chezscheme))

  ;; ---- judge one: recursive descent over the productions ---------------
  (define (rfc-number-descent? s)
    (let ((n (string-length s)))
      (define (digits i)
        (let loop ((i i) (any #f))
          (if (and (< i n) (char<=? #\0 (string-ref s i) #\9))
              (loop (+ i 1) #t)
              (and any i))))
      (define (int i)
        (cond ((>= i n) #f)
              ((char=? (string-ref s i) #\0) (+ i 1))
              ((char<=? #\1 (string-ref s i) #\9) (digits i))
              (else #f)))
      (let* ((i (if (and (> n 0) (char=? (string-ref s 0) #\-)) 1 0))
             (i (int i)))
        (and i
             (let ((i (if (and (< i n) (char=? (string-ref s i) #\.))
                          (digits (+ i 1))
                          i)))
               (and i
                    (let ((i (if (and (< i n)
                                      (memv (string-ref s i) '(#\e #\E)))
                                 (let ((j (+ i 1)))
                                   (digits (if (and (< j n)
                                                    (memv (string-ref s j)
                                                          '(#\+ #\-)))
                                               (+ j 1)
                                               j)))
                                 i)))
                      (and i (= i n)))))))))

  ;; ---- judge two: an explicit state machine ----------------------------
  ;; The states are named for the production they sit inside, so a reader
  ;; can put each against the grammar above without running anything.
  (define (rfc-number-machine? s)
    (let ((n (string-length s)))
      (define (digit? c) (char<=? #\0 c #\9))
      (define (at i) (and (fx< i n) (string-ref s i)))
      (let loop ((i 0) (state 'start))
        (let ((c (at i)))
          (case state
            ;; accepting states are the ones that may see end-of-string
            ((int-zero int-more frac-more exp-more)
             (if (not c)
                 #t
                 (case state
                   ((int-zero)
                    (cond ((char=? c #\.) (loop (fx+ i 1) 'frac-first))
                          ((memv c '(#\e #\E)) (loop (fx+ i 1) 'exp-sign))
                          (else #f)))
                   ((int-more)
                    (cond ((digit? c) (loop (fx+ i 1) 'int-more))
                          ((char=? c #\.) (loop (fx+ i 1) 'frac-first))
                          ((memv c '(#\e #\E)) (loop (fx+ i 1) 'exp-sign))
                          (else #f)))
                   ((frac-more)
                    (cond ((digit? c) (loop (fx+ i 1) 'frac-more))
                          ((memv c '(#\e #\E)) (loop (fx+ i 1) 'exp-sign))
                          (else #f)))
                   (else                     ; exp-more
                    (and (digit? c) (loop (fx+ i 1) 'exp-more))))))
            ;; non-accepting states: end-of-string here is a truncated
            ;; numeral, so every one of these requires a character
            ((start)
             (and c (cond ((char=? c #\-) (loop (fx+ i 1) 'int-first))
                          (else (loop i 'int-first)))))
            ((int-first)
             (and c (cond ((char=? c #\0) (loop (fx+ i 1) 'int-zero))
                          ((digit? c) (loop (fx+ i 1) 'int-more))
                          (else #f))))
            ((frac-first)
             (and c (digit? c) (loop (fx+ i 1) 'frac-more)))
            ((exp-sign)
             (and c (if (memv c '(#\+ #\-))
                        (loop (fx+ i 1) 'exp-first)
                        (loop i 'exp-first))))
            ((exp-first)
             (and c (digit? c) (loop (fx+ i 1) 'exp-more)))
            (else #f))))))
)
