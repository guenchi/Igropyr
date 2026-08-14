#!chezscheme
;;; (igropyr gzip): every byte that goes in must come back out.
;;;
;;; gzip-compress output is decompressed with the system gzip(1) tool:
;;; an implementation in a separate process that shares nothing with
;;; the library under test, so agreement really is agreement. A
;;; compressor that produced a well-formed header and then garbage
;;; would pass a self-consistency check and fails this one. (Do NOT
;;; "improve" this to inflate via FFI: that loads a second zlib into
;;; the test process next to the one the runtime embeds, and two zlibs
;;; with identically named globals in one process is exactly the
;;; combination (igropyr gzip) exists to avoid -- see gzip.sc.)
;;;
;;; This is also the regression test for that coexistence: with a bad
;;; zlib binding, deflate() either faults -- no error code, no
;;; exception, the process dies -- or emits unbounded output on
;;; incompressible input. Against such a binding this script crashes
;;; or reports #f/mismatch; its clean exit is itself part of what is
;;; being asserted.

(import (chezscheme) (igropyr gzip))

(define failures 0)
(define (fail label)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label) (newline))
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline)) (fail label)))

;; ---- the independent decompressor ------------------------------------
;; pid keeps two concurrently running test processes off each other's
;; files; real-time alone can collide across processes
(define scratch
  (format "/tmp/igropyr-gzip-test-~a-~a" (get-process-id) (real-time)))

(define (gunzip bv)
  ;; -> the decompressed bytes, or #f if gzip(1) refuses the stream
  (let ((fin (string-append scratch ".gz"))
        (fout (string-append scratch ".out")))
    (define (rm f) (when (file-exists? f) (delete-file f)))
    (rm fin) (rm fout)
    (call-with-port (open-file-output-port fin)
      (lambda (p) (put-bytevector p bv)))
    (let* ((rc (system (format "gzip -dc < ~a > ~a 2>/dev/null" fin fout)))
           (res (and (= rc 0)
                     (file-exists? fout)
                     (call-with-port (open-file-input-port fout)
                       (lambda (p)
                         (let ((out (get-bytevector-all p)))
                           (if (eof-object? out) (make-bytevector 0) out)))))))
      (rm fin) (rm fout)
      res)))

;; ---- inputs ----------------------------------------------------------
(define (repeated n byte) (make-bytevector n byte))

;; deterministic pseudo-random bytes: incompressible, and the same on
;; every run, so a failure can be reproduced
(define (noise n)
  (let ((bv (make-bytevector n))
        (seed 2463534242))
    (do ((i 0 (+ i 1))) ((= i n) bv)
      (set! seed (bitwise-and (+ (* seed 1103515245) 12345) #xFFFFFFFF))
      (bytevector-u8-set! bv i (bitwise-and (bitwise-arithmetic-shift-right seed 16) 255)))))

;; text-like data: compressible, but not trivially so
(define (proseish n)
  (let* ((unit (string->utf8 "the quick brown fox jumps over the lazy dog; "))
         (u (bytevector-length unit))
         (bv (make-bytevector n)))
    (do ((i 0 (+ i 1))) ((= i n) bv)
      (bytevector-u8-set! bv i (bytevector-u8-ref unit (mod i u))))))

(define cases
  (list (cons "empty" (make-bytevector 0))
        (cons "one byte" (repeated 1 65))
        (cons "short string" (string->utf8 "hello, gzip"))
        (cons "1 KiB of one byte" (repeated 1024 65))
        (cons "1 KiB of prose" (proseish 1024))
        (cons "1 KiB of noise" (noise 1024))
        ;; past zlib's internal buffer sizes so the deep deflate paths
        ;; (sym_buf, block flushes) really run
        (cons "300 KiB of prose" (proseish (* 300 1024)))
        ;; incompressible at scale: the case that drives a bad binding
        ;; into unbounded output instead of a crash
        (cons "300 KiB of noise" (noise (* 300 1024)))
        (cons "300 KiB of zeros" (repeated (* 300 1024) 0))))

;; ---- round trip at every level ---------------------------------------
(for-each
  (lambda (level)
    (for-each
      (lambda (c)
        (let* ((label (string-append (car c) " @" (number->string level)))
               (input (cdr c))
               (gz (gzip-compress input level)))
          (cond
            ((not gz) (fail (string-append label ": gzip-compress returned #f")))
            ((< (bytevector-length gz) 2)
             (fail (string-append label ": output too short to be gzip")))
            (else
              (check (string-append label ": gzip magic")
                (and (= #x1f (bytevector-u8-ref gz 0))
                     (= #x8b (bytevector-u8-ref gz 1))))
              (let ((back (gunzip gz)))
                (check (string-append label ": gzip -dc round trip")
                  (and back (bytevector=? back input))))))))
      cases))
  '(1 6 9))

;; compression must actually compress something compressible -- a
;; round trip would also pass on a stored (uncompressed) deflate block
(let ((gz (gzip-compress (proseish (* 300 1024)) 6)))
  (check "compressible input gets smaller"
    (and gz (< (bytevector-length gz) (* 64 1024)))))

;; repeated calls: the compressor holds per-call resources, and a leak or
;; a stale reused buffer would show up as a later call differing from the
;; first on identical input
(let ((input (proseish 4096)))
  (let ((first (gzip-compress input 6)))
    (check "1000 calls all agree with the first"
      (let loop ((i 0))
        (or (= i 1000)
            (let ((gz (gzip-compress input 6)))
              (and gz (bytevector=? gz first) (loop (+ i 1)))))))
    (check "and the last one still round-trips"
      (let ((back (gunzip (gzip-compress input 6))))
        (and back (bytevector=? back input))))))

;; ---- level edges -----------------------------------------------------
;; 10 is refused by deflateInit2 and must surface as #f, not an error;
;; 0 (store-only) is allowed by zlib and must still round-trip
(check "level 10 refused" (not (gzip-compress (proseish 64) 10)))
(let* ((input (proseish 4096))
       (gz (gzip-compress input 0)))
  (check "level 0 still round-trips"
    (and gz (let ((back (gunzip gz)))
              (and back (bytevector=? back input))))))

;; ---- the 32-bit stream-counter bound ---------------------------------
;; zlib's avail_in/avail_out are 32-bit: past n = 4290676491 the output
;; bound no longer fits and the call must refuse with #f -- not raise,
;; not compress a truncated prefix. Needs a ~4.3 GB allocation, so
;; opt-in.
(if (getenv "IGROPYR_GZIP_HUGE_TEST")
    (check "input past the 32-bit bound returns #f"
      (not (gzip-compress (make-bytevector 4290676492 0) 1)))
    (begin
      (display "  skip  huge-input bound (set IGROPYR_GZIP_HUGE_TEST to run; allocates ~4.3 GB)")
      (newline)))

;; ---- Accept-Encoding negotiation -------------------------------------
(check "plain gzip" (gzip-acceptable? "gzip"))
(check "in a list" (gzip-acceptable? "deflate, gzip;q=1.0, *;q=0.5"))
(check "legacy alias" (gzip-acceptable? "x-gzip"))
(check "wildcard" (gzip-acceptable? "*"))
(check "case-insensitive" (gzip-acceptable? "GZip"))
(check "absent header" (not (gzip-acceptable? #f)))
(check "empty header" (not (gzip-acceptable? "")))
(check "identity only" (not (gzip-acceptable? "identity")))
;; q=0 means NOT acceptable: clients send it precisely when they cannot
;; decode the coding, so compressing anyway breaks them
(check "gzip;q=0 refused" (not (gzip-acceptable? "gzip;q=0")))
(check "gzip;q=0 among others" (not (gzip-acceptable? "deflate, gzip;q=0")))
(check "explicit beats wildcard" (gzip-acceptable? "*;q=0, gzip"))
(check "wildcard q=0" (not (gzip-acceptable? "*;q=0")))
;; a bare substring search would fire on this
(check "not a substring match" (not (gzip-acceptable? "notgzip")))
;; ...and a bare search for "q=0" would refuse this one: the parameter is
;; named xq, so it says nothing about quality and gzip stays acceptable
(check "xq= is not q=" (gzip-acceptable? "gzip;xq=0"))

(if (zero? failures)
    (begin (display "gzip: all tests passed") (newline) (exit 0))
    (begin (display failures) (display " failures") (newline) (exit 1)))
