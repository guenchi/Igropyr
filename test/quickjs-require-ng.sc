#!chezscheme
;;; (igropyr quickjs) requires quickjs-ng: a build whose JS_FreeValue is not
;;; exported must be refused at boot, not booted onto a different path.
;;;
;;; bellard/quickjs makes JS_FreeValue a header inline, which is what used to
;;; force this library to discover the ref_count offset by reading BOTH
;;; candidate positions on a live object -- one of them 4 bytes BEFORE it.
;;; That undefined read is gone because the offset is gone; this pins the
;;; contract that replaced it.
;;;
;;; A SEPARATE PROCESS on purpose: bind! resolves the library exactly once per
;;; process, so a refusal cannot be tested after any successful boot in the
;;; same process -- the second boot would skip binding entirely and pass for
;;; the wrong reason.

(import (chezscheme) (igropyr quickjs))

(define shared-ext
  ;; A bellard build is a .dylib on macOS and a .so everywhere else.
  ;; Hardcoding one of them does not make this suite macOS-only, it makes
  ;; it UNSATISFIABLE off macOS: the probe looks for a filename the
  ;; platform never produces, so the skip message asks for something that
  ;; would still not be found. That is how two other suites here went
  ;; silently skipped on every machine for months.
  (let* ((m (symbol->string (machine-type))) (n (string-length m)))
    (if (and (>= n 3) (string=? (substring m (- n 3) n) "osx")) ".dylib" ".so")))

(define path
  (string-append (or (getenv "HOME") "")
                 "/.local/lib/igropyr/libquickjs-bellard" shared-ext))

(cond
  ((not (file-exists? path))
   ;; Named, not silent: this is real missing coverage, not a free pass.
   (display "quickjs-require-ng: SKIP -- no ")
   (display path)
   (display "\n  (build one from bellard/quickjs to cover the refusal path)\n")
   (exit 0))
  (else
   (let ((refused
           (guard (e (#t (if (message-condition? e) (condition-message e) "")))
             (qjs-boot! "function f(x){return x;}"
                        `((timeout-ms . 500) (mem-mb . 32) (so-path . ,path)))
             #f)))
     (cond
       ((not refused)
        (display "FAIL  a build without JS_FreeValue was accepted\n")
        (exit 1))
       ;; the message must say WHAT is missing and WHAT is required, or the
       ;; operator hitting it has no idea which library to install
       ((not (and (string? refused)
                  (let loop ((i 0))
                    (cond ((> (+ i 12) (string-length refused)) #f)
                          ((string=? (substring refused i (+ i 12)) "JS_FreeValue") #t)
                          (else (loop (+ i 1)))))))
        (display "FAIL  refused, but the message does not name JS_FreeValue: ")
        (write refused) (newline)
        (exit 1))
       (else
        (display "quickjs-require-ng: refusal pinned\n")
        (exit 0))))))
