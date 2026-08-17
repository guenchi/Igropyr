;;; manual-names.ss -- every igropyr-shaped name the manual prints must exist
;;;
;;; Run:  scheme --script tools/manual-names.ss [manual.md] [library-dir]
;;; Defaults: docs/manual.md and ../01-igropyr (a checkout of the master
;;; branch, which is where the sources live -- the manual is on its own
;;; branch and cannot reach them any other way).
;;;
;;; WHAT THIS CATCHES, and it is one specific failure, not a style rule:
;;; a manual section that documents an API which is not there at all --
;;; names that were renamed, or that were never written, or that a writer
;;; invented because they were the obvious name for the thing being
;;; described. Two of those have happened here: a connection-pool section
;;; naming five procedures that no longer existed, and a peek example
;;; calling a predicate that had never existed. Both read perfectly well.
;;; Nothing else in the tree can notice them: the sources compile, the
;;; suite passes, and the manual is prose.
;;;
;;; WHAT IT DOES NOT CATCH, so that nobody reads a pass as more than it is:
;;;   - a name that exists but is documented with the wrong arity, the
;;;     wrong argument order, or the wrong meaning;
;;;   - a name the manual mentions without any code marking around it;
;;;   - anything about examples that are wrong while naming real things.
;;; It answers exactly one question: does this name exist in this library.
;;;
;;; HOW IT DECIDES WHAT TO LOOK AT. A hyphenated token is treated as a
;;; claim about this library when its first segment is also the first
;;; segment of some exported name (`conversation-`, `connpool-`, ...).
;;; Without that filter ordinary hyphenated English drowns the signal.
;;; In prose every backticked token counts, because that is where the
;;; connection-pool section went stale; inside a fenced block only the
;;; head of a form counts, because the other identifiers there belong to
;;; the example, not to us.
;;;
;;; A hit is not automatically a defect: an example may legitimately name
;;; a procedure from another library, or a signature heading may name its
;;; own parameter. Those go in ACCEPTED below, each with the reason it is
;;; not a defect -- an entry with no reason is not an entry.

(import (chezscheme))

(define ACCEPTED
  '(("monitor-reference" . "parameter name in the (demonitor ...) signature heading")
    ("load-routes!"      . "the example's own application code, marked as such")
    ("ws-connect!"       . "Goeteia's (web ws), shown as the browser side")
    ("ws-send!"          . "Goeteia's (web ws), shown as the browser side")
    ("sse-connect!"      . "Goeteia's (web sse), shown as the browser side")))

;; ---- the library's own names -------------------------------------------

(define (library-form? x) (and (pair? x) (eq? (car x) 'library)))

(define (export-clause x)
  (let loop ((rest (cddr x)))
    (cond ((null? rest) '())
          ((and (pair? (car rest)) (eq? (caar rest) 'export)) (cdar rest))
          (else (loop (cdr rest))))))

(define (flatten-export e)
  (cond ((symbol? e) (list e))
        ((and (pair? e) (eq? (car e) 'rename))
         (map (lambda (p) (if (pair? p) (cadr p) p)) (cdr e)))
        ((pair? e) (apply append (map flatten-export e)))
        (else '())))

(define (exports-of file)
  (guard (c (#t '()))
    (call-with-input-file file
      (lambda (p)
        (let loop ((acc '()))
          (let ((x (read p)))
            (cond ((eof-object? x) acc)
                  ((library-form? x)
                   (loop (append (flatten-export (export-clause x)) acc)))
                  (else (loop acc)))))))))

;; ---- tokens -------------------------------------------------------------

(define (token-char? c)
  (or (char-alphabetic? c) (char-numeric? c)
      (memv c '(#\- #\! #\? #\* #\/ #\< #\> #\= #\+ #\_))))

(define (tokens-in str)
  (let loop ((i 0) (start #f) (out '()))
    (cond
      ((>= i (string-length str))
       (reverse (if start (cons (substring str start i) out) out)))
      ((token-char? (string-ref str i)) (loop (+ i 1) (or start i) out))
      (else (loop (+ i 1) #f (if start (cons (substring str start i) out) out))))))

;; Inside a fenced block only the head of a form is a claim about this
;; library; a bare identifier there is usually the example's own variable.
(define (call-position-tokens str)
  (let loop ((i 0) (out '()))
    (cond
      ((>= i (string-length str)) (reverse out))
      ((char=? (string-ref str i) #\()
       (let scan ((j (+ i 1)))
         (cond ((and (< j (string-length str)) (token-char? (string-ref str j)))
                (scan (+ j 1)))
               ((> j (+ i 1)) (loop j (cons (substring str (+ i 1) j) out)))
               (else (loop (+ i 1) out)))))
      (else (loop (+ i 1) out)))))

(define (backtick-spans str)
  (let loop ((i 0) (out '()))
    (cond
      ((>= i (string-length str)) (reverse out))
      ((char=? (string-ref str i) #\`)
       (let scan ((j (+ i 1)))
         (cond ((>= j (string-length str)) (reverse out))
               ((char=? (string-ref str j) #\`)
                (loop (+ j 1) (cons (substring str (+ i 1) j) out)))
               (else (scan (+ j 1))))))
      (else (loop (+ i 1) out)))))

(define (fence-line? line)
  (let skip ((k 0))
    (cond ((>= (+ k 3) (string-length line)) #f)
          ((char=? (string-ref line k) #\space) (skip (+ k 1)))
          (else (string=? (substring line k (+ k 3)) "```")))))

(define (head-segment s)
  (let loop ((i 0))
    (cond ((>= i (string-length s)) s)
          ((char=? (string-ref s i) #\-) (substring s 0 i))
          (else (loop (+ i 1))))))

(define (string-suffix? suf s)
  (let ((n (string-length s)) (m (string-length suf)))
    (and (>= n m) (string=? (substring s (- n m) n) suf))))

;; ---- the check ----------------------------------------------------------

(define (run manual libdir)
  (unless (file-exists? manual)
    (printf "manual-names: no manual at ~a\n" manual)
    (exit 1))
  (unless (file-directory? libdir)
    ;; Not a pass. Say what is missing and how to supply it, so that a
    ;; skip cannot be mistaken for a clean run.
    (printf "manual-names: SKIPPED -- no library sources at ~a.\n" libdir)
    (printf "  This check needs a checkout of the master branch (the manual\n")
    (printf "  lives on its own branch and the sources are not beside it).\n")
    (printf "  Pass one:  scheme --script tools/manual-names.ss ~a <dir>\n" manual)
    (exit 2))
  (let* ((files (map (lambda (f) (string-append libdir "/" f))
                     (filter (lambda (f) (string-suffix? ".sc" f))
                             (directory-list libdir))))
         (names (map symbol->string (apply append (map exports-of files))))
         (name-set (let ((h (make-hashtable string-hash string=?)))
                     (for-each (lambda (n) (hashtable-set! h n #t)) names)
                     ;; A name that is defined but not exported still exists;
                     ;; this check is about absence, not about visibility.
                     (for-each
                       (lambda (f)
                         (call-with-input-file f
                           (lambda (p)
                             (let loop ()
                               (let ((line (get-line p)))
                                 (unless (eof-object? line)
                                   (for-each (lambda (t) (hashtable-set! h t #t))
                                             (tokens-in line))
                                   (loop)))))))
                       files)
                     h))
         (head-set (let ((h (make-hashtable string-hash string=?)))
                     (for-each (lambda (n) (hashtable-set! h (head-segment n) #t))
                               names)
                     h))
         (hits '()))
    (when (null? files)
      (printf "manual-names: SKIPPED -- ~a holds no .sc sources\n" libdir)
      (exit 2))
    (call-with-input-file manual
      (lambda (p)
        (let loop ((lineno 1) (in-block #f))
          (let ((line (get-line p)))
            (unless (eof-object? line)
              (cond
                ((fence-line? line) (loop (+ lineno 1) (not in-block)))
                (else
                  (for-each
                    (lambda (span)
                      (for-each
                        (lambda (tok)
                          (when (and (> (string-length tok) 2)
                                     (memv #\- (string->list tok))
                                     (hashtable-ref head-set (head-segment tok) #f)
                                     (not (hashtable-ref name-set tok #f)))
                            (set! hits (cons (cons tok lineno) hits))))
                        (if in-block
                            (call-position-tokens span)
                            (tokens-in span))))
                    (if in-block (list line) (backtick-spans line)))
                  (loop (+ lineno 1) in-block))))))))
    (let* ((hits (reverse hits))
           (unexplained
             (filter (lambda (h) (not (assoc (car h) ACCEPTED))) hits)))
      (printf "manual-names: ~a name prefixes, ~a hit~a, ~a accepted\n"
              (hashtable-size head-set) (length hits)
              (if (= 1 (length hits)) "" "s")
              (- (length hits) (length unexplained)))
      (cond
        ((null? unexplained)
         (printf "manual-names: ok -- no igropyr-shaped name is missing\n")
         (exit 0))
        (else
          (for-each
            (lambda (h)
              (printf "  ~a:~a: ~a is not in the library\n"
                      manual (cdr h) (car h)))
            unexplained)
          (printf "manual-names: ~a name~a the manual prints do~a not exist.\n"
                  (length unexplained)
                  (if (= 1 (length unexplained)) "" "s")
                  (if (= 1 (length unexplained)) "es" ""))
          (printf "  Fix the manual, or add the name to ACCEPTED with the\n")
          (printf "  reason it is not a defect.\n")
          (exit 1))))))

(let ((a (command-line-arguments)))
  (run (if (>= (length a) 1) (car a) "docs/manual.md")
       (if (>= (length a) 2) (cadr a) "../01-igropyr")))
