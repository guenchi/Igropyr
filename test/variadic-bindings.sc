#!chezscheme
;;; test/variadic-bindings.sc -- a variadic C function's optional argument
;;; arrives where the callee reads it.
;;;
;;; open(2) and openat(2) are variadic: the mode is a variadic argument, read
;;; when O_CREAT (or, on Linux, O_TMPFILE) is set. On arm64 macOS a variadic argument is passed on
;;; the stack while fixed arguments are passed in registers, so a binding
;;; that declares the mode as an ordinary fixed argument puts it where the
;;; callee does not look, and the file is created with whatever the stack
;;; held. On x86_64 the two conventions agree and the same binding works.
;;; (igropyr libuv) exports c-open and c-openat with a mode argument; these
;;; rows create a file through each and read its mode back.
;;;
;;; No caller in this library passed O_CREAT through them when this was
;;; written, so these rows are about what the exports promise, not about a
;;; failure seen in the library's own use.
;;;
;;; TWO MODES, BOTH UNDER A UMASK THIS PROCESS SETS TO 0, so the file's mode
;;; is exactly the mode given: #o600 and #o640. Two values, so a binding that
;;; always delivered one of them cannot pass both.
;;;
;;; THESE ROWS DISCRIMINATE ON arm64 ONLY. On x86_64 a fixed-arity binding
;;; passes them too (measured on FreeBSD), so a green there says nothing
;;; about the declaration.
;;;
;;; NOT COVERED: (igropyr durable) binds open and fcntl for itself and does
;;; not export them, and its only calls pass O_RDONLY and F_FULLFSYNC, which
;;; read no variadic argument. No row can reach those two declarations.

(import (chezscheme)
        (only (igropyr libuv) c-open c-openat c-close
              fs-o-wronly fs-o-creat fs-o-excl fs-o-rdonly))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define dir
  (let ((t (current-time)))
    (string-append "/tmp/igropyr-variadic-"
                   (number->string (time-second t)) "-" (number->string (time-nanosecond t)))))
(system (string-append "mkdir -p '" dir "'"))
(define (in-dir f) (string-append dir "/" f))
(define (mode-of f) (fxlogand (get-mode f) #o777))

(define create-flags (fxior fs-o-wronly fs-o-creat fs-o-excl))

;; this process's umask is set to 0 for the creating rows and restored after
(define c-umask (foreign-procedure "umask" (int) int))

(define (created-mode label opener mode)
  (let ((fd (opener mode)))
    (check (string-append label ": the call returned a descriptor") (>= fd 0) fd)
    (when (>= fd 0) (c-close fd))))

;; ---- open ------------------------------------------------------------------
(define old-umask (c-umask 0))
(created-mode "c-open #o600" (lambda (m) (c-open (in-dir "open-600") create-flags m)) #o600)
(check "c-open with O_CREAT creates the file with the mode it was given (#o600)"
       (and (file-exists? (in-dir "open-600")) (eqv? (mode-of (in-dir "open-600")) #o600))
       (and (file-exists? (in-dir "open-600")) (number->string (mode-of (in-dir "open-600")) 8)))

(created-mode "c-open #o640" (lambda (m) (c-open (in-dir "open-640") create-flags m)) #o640)
(check "c-open with O_CREAT creates the file with the mode it was given (#o640)"
       (and (file-exists? (in-dir "open-640")) (eqv? (mode-of (in-dir "open-640")) #o640))
       (and (file-exists? (in-dir "open-640")) (number->string (mode-of (in-dir "open-640")) 8)))

;; ---- openat -----------------------------------------------------------------
(let ((dirfd (c-open dir fs-o-rdonly 0)))
  (check "setup: the scratch directory opens" (>= dirfd 0) dirfd)
  (when (>= dirfd 0)
    (created-mode "c-openat #o600" (lambda (m) (c-openat dirfd "openat-600" create-flags m)) #o600)
    (check "c-openat with O_CREAT creates the file with the mode it was given (#o600)"
           (and (file-exists? (in-dir "openat-600")) (eqv? (mode-of (in-dir "openat-600")) #o600))
           (and (file-exists? (in-dir "openat-600")) (number->string (mode-of (in-dir "openat-600")) 8)))
    (created-mode "c-openat #o640" (lambda (m) (c-openat dirfd "openat-640" create-flags m)) #o640)
    (check "c-openat with O_CREAT creates the file with the mode it was given (#o640)"
           (and (file-exists? (in-dir "openat-640")) (eqv? (mode-of (in-dir "openat-640")) #o640))
           (and (file-exists? (in-dir "openat-640")) (number->string (mode-of (in-dir "openat-640")) 8)))
    (c-close dirfd)))

(c-umask old-umask)

;; ---- the twin: a call that passes no variadic argument the callee reads ------
;; On a file this process made WITHOUT the bindings under test, so a wrong
;; mode above cannot make it unreadable and fail this row for them.
(call-with-output-file (in-dir "plain") (lambda (p) (display "x" p)))
(let ((fd (c-open (in-dir "plain") fs-o-rdonly 0)))
  (check "twin: opening an existing file read-only works" (>= fd 0) fd)
  (when (>= fd 0) (c-close fd)))

(system (string-append "rm -rf '" dir "'"))
(if (zero? failures)
    (begin (display "variadic-bindings: all tests passed\n") (exit 0))
    (begin (display "variadic-bindings: ") (display failures) (display " failed\n") (exit 1)))
