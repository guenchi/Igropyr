#!chezscheme
;;; (igropyr quickjs) -- embed a JavaScript engine (QuickJS) in-process.
;;;
;;; General-purpose: load ANY fixed JS bundle at boot, then call global
;;; functions on it with one UTF-8 string argument and get a string back.
;;; The bundle is baked at build time -- user input is data, never code.
;;;
;;;   (qjs-boot! bundle-source)                       ; defaults
;;;   (qjs-boot! bundle-source '((mem-mb . 64) (stack-kb . 1024)
;;;                              (timeout-ms . 2000) (so-path . "...")))
;;;   (qjs-call "fname" "arg")     ; -> (values ok? string)
;;;   (qjs-call! "fname" "arg")    ; -> string, raises on JS error
;;;   (qjs-healthy?) (qjs-generation) (qjs-shutdown!)
;;;
;;; Robustness (see c/quickjs-shim.c): memory limit / stack limit / wall-clock
;;; interrupt deadline / exception boundary / crash-only rebuild (a failed
;;; call discards the whole JS heap and reboots it from the bundle;
;;; qjs-generation counts rebuilds) / pthread-mutex serialized engine.
;;;
;;; The call+fetch ABI pair runs inside with-interrupts-disabled so the
;;; preemptive actor scheduler cannot interleave two callers between them.
;;; A call blocks the OS thread for its duration (typical fractions of a
;;; millisecond; worst case = timeout-ms) -- cap input size at the caller
;;; for latency-sensitive paths.

(library (igropyr quickjs)
  (export qjs-boot! qjs-call qjs-call! qjs-healthy? qjs-generation qjs-shutdown!)
  (import (chezscheme) (igropyr platform))

  ;; The shim links libquickjs statically; only our own dylib is needed.
  ;; Resolution order: explicit (opt so-path) > IGROPYR_QUICKJS_SO env var >
  ;; relative igropyr dirs > plain name for a system-installed copy.
  (define so-loaded #f)
  (define (load-so! explicit)
    (unless so-loaded
      (ensure-supported-platform!)
      (load-first-shared-object! 'quickjs
        (append (if explicit (list explicit) '())
                (let ((e (getenv "IGROPYR_QUICKJS_SO"))) (if e (list e) '()))
                (list "igropyr/libigropyr-quickjs.dylib"
                      ".build-links/igropyr/libigropyr-quickjs.dylib"
                      "libigropyr-quickjs.dylib"
                      "igropyr/libigropyr-quickjs.so"
                      ".build-links/igropyr/libigropyr-quickjs.so"
                      "libigropyr-quickjs.so")))
      (set! so-loaded #t)))

  (define c-boot #f) (define c-call #f) (define c-fetch #f)
  (define c-healthy #f) (define c-generation #f) (define c-shutdown #f)
  (define (bind!)
    (set! c-boot (foreign-procedure "qjs_boot" (u8* long int int int) int))
    (set! c-call (foreign-procedure "qjs_call" (string u8* long) long))
    (set! c-fetch (foreign-procedure "qjs_fetch" (u8* long) long))
    (set! c-healthy (foreign-procedure "qjs_healthy" () int))
    (set! c-generation (foreign-procedure "qjs_generation" () long))
    (set! c-shutdown (foreign-procedure "qjs_shutdown" () void)))

  (define (opt opts key default)
    (let ((p (assq key opts))) (if p (cdr p) default)))

  ;; fetch the last result/error while still inside the critical section;
  ;; trims to the byte count c-fetch actually copied.
  (define (fetch cap)
    (let* ((bv (make-bytevector cap))
           (n (c-fetch bv cap)))
      (if (= n cap)
          (utf8->string bv)
          (let ((b2 (make-bytevector n)))
            (bytevector-copy! bv 0 b2 0 n)
            (utf8->string b2)))))

  ;; Boot (or re-boot) the engine on a JS source string. -> ok? ; on #f the
  ;; error text is retrievable via the next qjs-call's failure path, so we
  ;; fetch and raise here instead -- a boot failure is always a bug.
  (define (qjs-boot! source . rest)
    (let ((opts (if (pair? rest) (car rest) '())))
      (load-so! (opt opts 'so-path #f))
      (unless c-boot (bind!))
      (let ((timeout-ms (opt opts 'timeout-ms 2000)))
        ;; a non-positive timeout disables the shim's wall-clock deadline
        ;; entirely (interrupt handler never fires), so a runaway call would
        ;; hold the engine mutex forever and wedge every caller. Require a
        ;; positive bound.
        (unless (and (fixnum? timeout-ms) (fx> timeout-ms 0))
          (assertion-violation 'qjs-boot! "timeout-ms must be a positive fixnum"
                               timeout-ms))
        (let ((bv (string->utf8 source)))
          (with-interrupts-disabled
            (let ((r (c-boot bv (bytevector-length bv)
                             (opt opts 'mem-mb 64)
                             (opt opts 'stack-kb 1024)
                             timeout-ms)))
              (if (= r 0)
                  #t
                  (error 'qjs-boot! (fetch 4096)))))))))

  ;; -> (values ok? string): result on #t, JS error text on #f.
  (define (qjs-call fname arg)
    (unless c-call (error 'qjs-call "qjs-boot! first"))
    (let ((bv (string->utf8 arg)))
      (with-interrupts-disabled
        (let ((n (c-call fname bv (bytevector-length bv))))
          (if (>= n 0)
              (values #t (fetch n))
              (values #f (fetch 4096)))))))

  ;; raising variant
  (define (qjs-call! fname arg)
    (let-values (((ok s) (qjs-call fname arg)))
      (if ok s (error 'qjs-call! s fname))))

  (define (qjs-healthy?) (and c-healthy (= 1 (c-healthy))))
  (define (qjs-generation) (if c-generation (c-generation) 0))
  (define (qjs-shutdown!) (when c-shutdown (c-shutdown)))
)
