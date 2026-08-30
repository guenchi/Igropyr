;;; build-pgo.ss -- profile-guided (PGO step 2) build.
;;;
;;; Loads the profile collected by an instrumented run (app.profile) and
;;; recompiles, letting the compiler use the hot-path data for block
;;; ordering and inlining. Same optimize-level 2 whole-program output.
;;;
;;;   scheme --libdirs .:lib --script igropyr/build-pgo.ss
;;;   scheme --program igropyr/app.so

(import (chezscheme))

(unless (file-exists? "app.profile")
  (error 'build-pgo "app.profile not found; run build-profile.ss + collect first"))

(compile-profile #f)                    ; no more instrumentation
(profile-load-data "app.profile")       ; use the collected profile
(generate-wpo-files #t)

;; THE LIBRARY LIST IS NOT KEPT HERE. This script used to carry its own
;; copy, and that copy was missing twenty-one libraries -- silently,
;; because a library left out of a build is not an error, it just stays
;; source-only. One list, loaded, checked against the directory.
;;
;; app.sc is not in it and must not be: it is the PROGRAM, compiled
;; below with compile-program.
(load "igropyr/build-units.ss")

(define libs library-units)
(check-library-list! "build-pgo.ss" libs)

(parameterize ((optimize-level 2)
               (generate-inspector-information #f))
  (for-each
    (lambda (f) (printf "compiling (pgo) ~a\n" f) (compile-library f))
    libs)
  (compile-program "igropyr/app.sc")
  (compile-whole-program "igropyr/app.wpo" "igropyr/app.so" #t))

(printf "pgo build done\n")
