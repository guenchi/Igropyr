;;; build-profile.ss -- instrumented (PGO step 1) build.
;;;
;;; Compiles everything with source-level profiling so the running server
;;; records execution counts. Drive real load against it, hit
;;; /admin/profdump to write app.profile, then rebuild with build-pgo.ss.
;;;
;;;   scheme --libdirs .:lib --script igropyr/build-profile.ss
;;;   scheme --program igropyr/app.so        # instrumented; run load
;;;   curl localhost:8080/admin/profdump      # writes app.profile

(import (chezscheme))

(compile-profile 'source)               ; instrument for source profiling
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
(check-library-list! "build-profile.ss" libs)

(parameterize ((optimize-level 2)
               (generate-inspector-information #f))
  (for-each
    (lambda (f) (printf "compiling (profiled) ~a\n" f) (compile-library f))
    libs)
  (compile-program "igropyr/app.sc")
  (compile-whole-program "igropyr/app.wpo" "igropyr/app.so" #t))

(printf "instrumented build done\n")
