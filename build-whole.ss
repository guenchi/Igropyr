;;; build-whole.ss -- whole-program compile: fold every library and the
;;; app into one optimized program object (app.so), enabling cross-library
;;; inlining that per-library .so files cannot get.
;;;
;;;   scheme --libdirs .:lib --script igropyr/build-whole.ss
;;;   scheme --program igropyr/app.so         # run the server
;;;
;;; Interrupt traps stay on (preemptive scheduling needs them).
;;;
;;; optimize-level 2: full cross-library procedure integration with all
;;; type/bounds checks kept -- safe by default for release builds.

(import (chezscheme))

(generate-wpo-files #t)                 ; emit .wpo alongside each .so

;; THE LIBRARY LIST IS NOT KEPT HERE. This script used to carry its own
;; copy, and that copy was missing twenty-one libraries -- silently,
;; because a library left out of a build is not an error, it just stays
;; source-only. One list, loaded, checked against the directory.
;;
;; app.sc is not in it and must not be: it is the PROGRAM, compiled
;; below with compile-program.
(load "igropyr/build-units.ss")

(define libs library-units)
(check-library-list! "build-whole.ss" libs)

(parameterize ((optimize-level 2)
               (generate-inspector-information #f))
  (for-each
    (lambda (f)
      (printf "compiling library ~a\n" f)
      (compile-library f))
    libs)
  (printf "compiling program igropyr/app.sc\n")
  (compile-program "igropyr/app.sc")
  ;; merge app + all its libraries into one whole-program-optimized .so
  (printf "whole-program optimizing -> igropyr/app.so\n")
  (compile-whole-program "igropyr/app.wpo" "igropyr/app.so" #t))

(printf "done\n")
