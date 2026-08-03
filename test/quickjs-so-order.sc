#!chezscheme
;;; (igropyr quickjs) must find quickjs-ng even when bellard/quickjs is also
;;; on the loader's search path.
;;;
;;; The two upstreams use different library names -- quickjs-ng ships libqjs,
;;; bellard ships libquickjs -- and this driver requires ng (see the
;;; JS_FreeValue check in bind!). The candidate list used to try libquickjs
;;; first, so on a machine carrying both it dlopened the unusable one and the
;;; boot failed with ng installed and working right beside it.
;;;
;;; Falling through to the next candidate would not fix that; it would make it
;;; worse. Chez's foreign-procedure resolves from the process-global symbol
;;; namespace, so once bellard is loaded its JS_NewRuntime stays visible: the
;;; runtime would come from one library and JS_FreeValue from the other, and
;;; every value would be freed through the wrong ABI. The only safe answer is
;;; to look for the right library FIRST.
;;;
;;; A first attempt at that ordering put the bare "libqjs" names ahead of the
;;; bare "libquickjs" ones but left ng's ABSOLUTE paths behind them, and it
;;; did not work: a bare "libqjs.dylib" does not resolve where the library
;;; lives outside the loader's default path (/opt/homebrew/lib on macOS), so
;;; a bare "libquickjs.dylib" anywhere on the search path still won. The
;;; candidates have to be grouped by library. This test is what showed that.
;;;
;;; A SEPARATE PROCESS, because the library is resolved once per process.

(import (chezscheme))

(define bellard
  (string-append (or (getenv "HOME") "")
                 "/.local/lib/igropyr/libquickjs-bellard.dylib"))

(define staged "/tmp/igropyr-so-order-test")

(define (skip! why)
  (display "quickjs-so-order: SKIP -- ") (display why) (newline)
  (exit 0))

(cond
  ((not (file-exists? bellard))
   ;; Named, not silent: this is real missing coverage.
   (skip! (string-append "no " bellard
                         " (build one from bellard/quickjs to cover this)")))
  ((let* ((m (symbol->string (machine-type)))
          (n (string-length m)))
     (not (and (>= n 3) (string=? (substring m (- n 3) n) "osx"))))
   ;; The staging trick is DYLD_LIBRARY_PATH, and the only bellard build
   ;; kept around is a macOS dylib.
   (skip! "the staged bellard build is a macOS dylib"))
  (else
   (system (string-append "rm -rf " staged " && mkdir -p " staged))
   (system (string-append "cp " bellard " " staged "/libquickjs.dylib"))
   ;; Boot quickjs in a child process that sees BOTH libraries. It must come
   ;; up: picking bellard's libquickjs is the failure this pins.
   (let* ((script (string-append staged "/boot.sc"))
          (out (string-append staged "/out.txt")))
     (call-with-output-file script
       (lambda (p)
         (display "(import (chezscheme) (igropyr quickjs))\n" p)
         (display "(qjs-boot! \"function f(x){return x+'!';}\"\n" p)
         (display "           '((timeout-ms . 500) (mem-mb . 32)))\n" p)
         ;; call it too: booting proves the library loaded, calling proves
         ;; the one that loaded is actually usable
         (display "(let-values (((ok s) (qjs-call \"f\" \"hi\")))\n" p)
         (display "  (unless (and ok (string=? s \"hi!\")) (exit 1)))\n" p)))
     (let ((status
             (system
               (string-append
                 "DYLD_LIBRARY_PATH=" staged
                 " CHEZSCHEMELIBDIRS=\"" (or (getenv "CHEZSCHEMELIBDIRS") ".") "\""
                 " CHEZSCHEMELIBEXTS=\"" (or (getenv "CHEZSCHEMELIBEXTS") "") "\""
                 " scheme --script " script " > " out " 2>&1"))))
       (let ((text (call-with-input-file out get-string-all)))
         (system (string-append "rm -rf " staged))
         (cond
           ((not (zero? status))
            (display "FAIL  quickjs did not boot with bellard's libquickjs also present\n")
            (display text) (newline)
            (exit 1))
           (else
            (display "  ok  quickjs-ng is chosen over a bellard build on the same path\n")
            (display "quickjs-so-order: all tests passed\n")
            (exit 0))))))))
