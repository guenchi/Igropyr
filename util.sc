#!chezscheme
;;; (igropyr util) -- tiny dependency-free helpers.
;;;
;;; The bottom of the library graph: this file imports only
;;; (chezscheme), so anything may import it. Home for the helpers that
;;; used to be copy-pasted per module (the opt/need option-alist
;;; readers, naive substring search).

(library (igropyr util)
  (export opt need string-search string-contains? string-suffix?)
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
)
