#!chezscheme
;;; Every kind registered in the owner index (tcp.sc) must be retired somewhere.
;;;
;;; index-owner! files a resource under its owner so uv-owner-died! can
;;; reclaim it; unindex-owner! takes it back out when the resource goes on
;;; its own. The two are matched by a literal tag, and a tag that appears
;;; on only one side leaks one entry per operation for the whole life of
;;; that owner. There is no symptom but growth, and growth is invisible
;;; without a number to compare -- which is why this file compares the two
;;; sides of the source instead of waiting for a count to be noticed.
;;;
;;; THIS IS THE SECOND LEG, NOT THE SAME ONE TWICE. dns-owner-index.sc
;;; measures the count at run time for one tag; this reads the pairing for
;;; all of them. A tag with no test still gets read here, and a pairing
;;; that is right in the source but wrong at run time still fails there.
;;;
;;; ⚠ TWO ASSUMPTIONS, BOTH LOAD-BEARING, BOTH GUARDED BY THE CONTROL:
;;;   - the tag is on the SAME LINE as the call. Split a call across lines
;;;     and this file stops seeing it -- silently, which is the failure
;;;     mode it exists to prevent.
;;;   - the owner argument may be anything, including a parenthesised
;;;     call. The control below is 'conn precisely because its removal
;;;     side reads (unindex-owner! (conn-owner c) 'conn handle): the
;;;     hardest shape in the file. An earlier scanner matched the owner
;;;     position as one token and lost BOTH sides of 'conn; the control is
;;;     what said so. A control on a tag whose sides are both simple would
;;;     have stayed green while the scanner was broken.

(import (chezscheme))

(define source "tcp.sc")
(define control 'conn)

(define (lines-of path)
  (call-with-input-file path
    (lambda (p)
      (let loop ((acc '()))
        (let ((l (get-line p)))
          (if (eof-object? l) (reverse acc) (loop (cons l acc))))))))

;; drop a trailing ;; comment so a tag mentioned in prose is not counted
(define (uncomment s)
  (let loop ((i 0))
    (cond ((>= (+ i 1) (string-length s)) s)
          ((and (char=? (string-ref s i) #\;)
                (char=? (string-ref s (+ i 1)) #\;))
           (substring s 0 i))
          (else (loop (+ i 1))))))

(define (find-from s pat start)
  (let ((n (string-length s)) (m (string-length pat)))
    (let loop ((i start))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring s i (+ i m)) pat) i)
            (else (loop (+ i 1)))))))

(define (tag-char? c)
  (or (char-alphabetic? c) (char-numeric? c) (char=? c #\-)))

;; the first quoted symbol after position `from` on this line
(define (tag-after s from)
  (let ((n (string-length s)))
    (let loop ((i from))
      (cond ((>= i n) #f)
            ((char=? (string-ref s i) #\')
             (let scan ((j (+ i 1)))
               (if (and (< j n) (tag-char? (string-ref s j)))
                   (scan (+ j 1))
                   (and (> j (+ i 1))
                        (string->symbol (substring s (+ i 1) j))))))
            (else (loop (+ i 1)))))))

(define (tags-for call)
  (let loop ((ls (lines-of source)) (acc '()))
    (if (null? ls) acc
        (let* ((l (uncomment (car ls)))
               (i (find-from l call 0)))
          (loop (cdr ls)
                (if i
                    (let ((t (tag-after l (+ i (string-length call)))))
                      (if (and t (not (memq t acc))) (cons t acc) acc))
                    acc))))))

(let* ((ins  (tags-for "(index-owner!"))
       (outs (tags-for "(unindex-owner!"))
       (all  (let loop ((xs (append ins outs)) (acc '()))
               (cond ((null? xs) acc)
                     ((memq (car xs) acc) (loop (cdr xs) acc))
                     (else (loop (cdr xs) (cons (car xs) acc)))))))
  ;; ⭐ THE CONTROL RUNS FIRST AND HAS ITS OWN NAME. A scanner that matches
  ;; nothing reports zero one-sided tags, which reads exactly like a clean
  ;; source. These two outcomes must never share a message.
  (if (not (and (memq control ins) (memq control outs)))
      (begin
        (display "FAIL owner-index-tag-scanner-broken: control ")
        (write control)
        (display " not found on both sides (in=")
        (write ins) (display " out=") (write outs) (display ")\n")
        (exit 2))
      (let loop ((xs all) (bad 0))
        (cond
          ((null? xs)
           (if (zero? bad)
               (begin (display "owner-index tags: all paired (")
                      (display (length all)) (display ")\n") (exit 0))
               (exit 1)))
          (else
            (let ((t (car xs)))
              (cond
                ((not (memq t outs))
                 (display "FAIL owner-index-tag-one-sided ") (write t)
                 (display " index-owner! only\n")
                 (loop (cdr xs) (+ bad 1)))
                ((not (memq t ins))
                 (display "FAIL owner-index-tag-one-sided ") (write t)
                 (display " unindex-owner! only\n")
                 (loop (cdr xs) (+ bad 1)))
                (else (loop (cdr xs) bad)))))))))
