;;; build.ss -- compile all Igropyr libraries to .so for production.
;;;
;;; Run from the project root (the parent of igropyr/):
;;;   scheme --libdirs .:lib --script igropyr/build.ss
;;; or with CHEZSCHEMELIBDIRS set. Produces one .so per source file;
;;; because CHEZSCHEMELIBEXTS lists .so before .sc, they are then loaded
;;; in preference to the sources. Re-run after editing any source.
;;;
;;; Everything is compiled at optimize-level 2: full optimization with
;;; all type/bounds checks kept -- safe by default. Interrupt traps are
;;; left ON -- preemptive scheduling depends on them.

(import (chezscheme))

;; The refusal to build with fault injection armed is NOT here: it is at
;; the head of build-units.ss, which every build entry point loads. It
;; was here first, and three other entry points compiled the same list
;; without it.

;; (source . optimize-level), in dependency order so each library's
;; already-compiled dependencies are picked up as .so.
;; The list itself lives in build-units.ss, loaded rather than copied:
;; it used to be written out here and again in each whole-program build,
;; and the copies fell behind. Optimize level is this script's business,
;; the membership is not.
(load "igropyr/build-units.ss")

(define units (map (lambda (p) (cons p 2)) library-units))
(check-library-list! "build.ss" library-units)

(define (so-path src)
  (string-append (substring src 0 (- (string-length src) 3)) ".so"))

(for-each
  (lambda (unit)
    (let ((src (car unit)) (level (cdr unit)))
      (parameterize ((optimize-level level)
                     ;; keep source info out of the .so; smaller, faster load
                     (generate-inspector-information #f))
        (printf "compiling ~a (optimize-level ~a)\n" src level)
        (compile-library src (so-path src)))))
  units)

(printf "done: ~a libraries compiled\n" (length units))
