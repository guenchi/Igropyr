#!chezscheme
;;; test/import-all.sc -- every library in the tree loads.
;;;
;;; The list is READ FROM THE DIRECTORY, not written here. A version of this
;;; file named the libraries one by one, and for a long time ten of them
;;; were missing from it -- aws, sts, ses, sns, cloudwatch, s3-control,
;;; apple-jws, kdf, rsa, aead -- while the last line still said ALL
;;; LIBRARIES IMPORTED. A list by name cannot shout for the entry nobody
;;; added. This takes every *.sc in the root, checks that it declares
;;; (library (igropyr <its basename>) ...), imports it by that name, and
;;; prints the count beside the number of files, so a library that fails
;;; to load, or a file that is not the library its name says, is a red
;;; exit here and not a surprise in whichever suite happens to import it.
;;;
;;; Two root files are programs, not libraries, and are named as such:
;;; app.sc (the example application) and qjs-worker.sc (the quickjs worker
;;; process). A third would have to be added here -- and this file will
;;; say so, because an unlisted non-library fails the declaration check.

(import (chezscheme))

(define programs '("app.sc" "qjs-worker.sc"))

(define (library-declaration? path name)
  ;; the first non-comment form of the file is (library (igropyr name) ...)
  (call-with-input-file path
    (lambda (p)
      (let ((form (guard (e (#t #f)) (read p))))
        (and (pair? form) (eq? (car form) 'library)
             (equal? (cadr form) (list 'igropyr name)))))))

(define files
  (sort string<?
        (filter (lambda (f)
                  (and (> (string-length f) 3)
                       (string=? ".sc" (substring f (- (string-length f) 3) (string-length f)))
                       (not (member f programs))))
                (directory-list "."))))

(define (basename f) (substring f 0 (- (string-length f) 3)))

;; one mutable environment: each import is a definition into it
(define env (copy-environment (environment '(chezscheme)) #t))

(define failures 0)
(for-each
  (lambda (f)
    (let ((name (string->symbol (basename f))))
      (cond
        ((not (library-declaration? f name))
         (set! failures (+ failures 1))
         (display "FAIL  ") (display f) (display " does not declare (library (igropyr ")
         (display name) (display ") ...) as its first form\n"))
        (else
         (guard (e (#t (set! failures (+ failures 1))
                       (display "FAIL  (igropyr ") (display name) (display ") did not load: ")
                       (display (if (condition? e)
                                    (call-with-string-output-port
                                      (lambda (o)
                                        (when (message-condition? e) (display (condition-message e) o))
                                        (when (irritants-condition? e) (display " " o) (write (condition-irritants e) o))))
                                    e))
                       (newline)))
           (eval `(import (igropyr ,name)) env)
           (display "  ok  (igropyr ") (display name) (display ")\n"))))))
  files)

(display "import-all: ") (display (- (length files) failures)) (display " of ")
(display (length files)) (display " libraries imported, ")
(display (length programs)) (display " programs named\n")
(if (zero? failures)
    (begin (display "ALL LIBRARIES IMPORTED\n") (exit 0))
    (begin (display "import-all: ") (display failures) (display " failed\n") (exit 1)))
