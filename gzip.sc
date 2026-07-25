#!chezscheme
;;; (igropyr gzip) -- gzip compression via zlib (deflateInit2 windowBits 31).
;;;
;;; (gzip-compress bv level) -> a gzip-format bytevector (browser
;;; Content-Encoding: gzip), or #f on failure. level 1..9 (6 is a good
;;; default). Used by the express layer to compress responses when the
;;; client sends Accept-Encoding: gzip.

(library (igropyr gzip)
  (export gzip-compress gzip-acceptable?)
  (import (chezscheme) (igropyr platform))

  (define zlib-loaded
    (begin
      (ensure-supported-platform!)
      (load-first-shared-object! 'zlib
        (case platform-os
          ((macos) '("libz.1.dylib" "libz.dylib"))
          ((freebsd) '("libz.so.6" "libz.so.5" "libz.so"))
          (else '("libz.so.1" "libz.so"))))
      (load-first-shared-object! 'libc
        (case platform-os
          ((macos) '("libSystem.B.dylib" "libSystem.dylib"))
          ;; FreeBSD libc soname tracks the major release (8.0+ = .7,
          ;; 7.x = .6); probe newest first, then the bare name.
          ((freebsd) '("libc.so.7" "libc.so.6" "libc.so"))
          (else '("libc.so.6" "libc.so"))))))

  (define zlib-version   (foreign-procedure "zlibVersion" () string))
  (define deflate-init2  (foreign-procedure "deflateInit2_"
                           (void* int int int int int string int) int))
  (define deflate*       (foreign-procedure "deflate" (void* int) int))
  (define deflate-end    (foreign-procedure "deflateEnd" (void*) int))
  (define memset*        (foreign-procedure "memset" (void* int size_t) void*))
  (define memcpy-to-c    (foreign-procedure "memcpy" (void* u8* size_t) void*))
  (define memcpy-from-c  (foreign-procedure "memcpy" (u8* void* size_t) void*))

  ;; z_stream field offsets on LP64 (see zlib.h):
  ;;   next_in @0 (ptr), avail_in @8 (u32), next_out @24 (ptr),
  ;;   avail_out @32 (u32), total_out @40 (u64). deflateInit2_ needs the
  ;;   real sizeof(z_stream) = 112.
  (define z-stream-size 112)
  (define Z-DEFLATED 8)
  (define Z-GZIP-WINDOW 31)          ; 16 + 15 -> gzip wrapper
  (define Z-DEFAULT-STRATEGY 0)
  (define Z-FINISH 4)
  (define Z-OK 0)
  (define Z-STREAM-END 1)

  ;; Compress bv to gzip format. Returns #f on any zlib error.
  (define (gzip-compress bv level)
    (let* ((n (bytevector-length bv))
           (strm (foreign-alloc 128))                 ; >= z-stream-size, zeroed
           (src (foreign-alloc (max 1 n)))
           (bound (+ n (quotient n 1000) 128))        ; safe deflate upper bound
           (dst (foreign-alloc bound)))
      (define (cleanup) (foreign-free strm) (foreign-free src) (foreign-free dst))
      (memset* strm 0 128)                            ; zalloc/zfree/opaque = 0
      (memcpy-to-c src bv n)
      (if (not (= Z-OK (deflate-init2 strm level Z-DEFLATED Z-GZIP-WINDOW
                                      8 Z-DEFAULT-STRATEGY (zlib-version)
                                      z-stream-size)))
          (begin (cleanup) #f)
          (begin
            (foreign-set! 'void* strm 0 src)          ; next_in
            (foreign-set! 'unsigned-32 strm 8 n)      ; avail_in
            (foreign-set! 'void* strm 24 dst)         ; next_out
            (foreign-set! 'unsigned-32 strm 32 bound) ; avail_out
            (let ((rc (deflate* strm Z-FINISH)))
              (let ((out-len (foreign-ref 'unsigned-long strm 40)))  ; total_out
                (deflate-end strm)
                (if (= rc Z-STREAM-END)
                    (let ((res (make-bytevector out-len)))
                      (memcpy-from-c res dst out-len)
                      (cleanup)
                      res)
                    (begin (cleanup) #f))))))))

  ;; does an Accept-Encoding header value allow gzip? Case-insensitive
  ;; search in place: no downcased copy, no per-position substring.
  ;; Accept-Encoding is a list of "coding[;q=value]" entries: a bare
  ;; substring search would compress for a client that explicitly said
  ;; "gzip;q=0" (RFC 9110: q=0 means NOT acceptable -- clients send it
  ;; precisely because they cannot decode it) and would also fire on an
  ;; unrelated coding that merely contains the letters.
  (define (gzip-acceptable? accept-encoding)
    (and accept-encoding
         (let ((n (string-length accept-encoding)))
           ;; Walk every comma-separated entry and keep the most specific
           ;; verdict: an explicit "gzip" (or its legacy alias "x-gzip",
           ;; RFC 9110 8.4.1.3) overrides a wildcard, so "*;q=0, gzip"
           ;; still compresses. Only when no explicit entry names gzip
           ;; does the wildcard decide.
           (let entry ((start 0) (explicit #f) (star #f))
             (if (>= start n)
                 (if (eq? explicit #f) (eq? star #t) explicit)
                 (let* ((end (let scan ((i start))
                               (cond ((>= i n) n)
                                     ((char=? (string-ref accept-encoding i) #\,) i)
                                     (else (scan (+ i 1))))))
                        (semi (let scan ((i start))
                                (cond ((>= i end) end)
                                      ((char=? (string-ref accept-encoding i) #\;) i)
                                      (else (scan (+ i 1))))))
                        (name (trim accept-encoding start semi))
                        (ok (not (q-zero? accept-encoding semi end))))
                   (cond
                     ((or (string-ci=? name "gzip") (string-ci=? name "x-gzip"))
                      (entry (+ end 1) ok star))
                     ((string=? name "*") (entry (+ end 1) explicit ok))
                     (else (entry (+ end 1) explicit star)))))))))

  (define (trim s start end)
    (let* ((b (let scan ((i start))
                (if (and (< i end) (memv (string-ref s i) '(#\space #\tab)))
                    (scan (+ i 1)) i)))
           (e (let scan ((i end))
                (if (and (> i b) (memv (string-ref s (- i 1)) '(#\space #\tab)))
                    (scan (- i 1)) i))))
      (substring s b e)))

  ;; Is there a q= parameter equal to zero in [from,to)? Parameters are
  ;; ';'-separated, and the NAME must be exactly "q" -- ";xq=0" is a
  ;; different parameter and must not be read as a quality value.
  (define (q-zero? s from to)
    (let param ((start from))
      (and (< start to)
           (let* ((semi (let scan ((i (if (and (< start to)
                                               (char=? (string-ref s start) #\;))
                                          (+ start 1)
                                          start)))
                          (cond ((>= i to) to)
                                ((char=? (string-ref s i) #\;) i)
                                (else (scan (+ i 1))))))
                  (body-start (if (and (< start to)
                                       (char=? (string-ref s start) #\;))
                                  (+ start 1)
                                  start))
                  (eq-pos (let scan ((i body-start))
                            (cond ((>= i semi) #f)
                                  ((char=? (string-ref s i) #\=) i)
                                  (else (scan (+ i 1)))))))
             (if (and eq-pos
                      (string-ci=? (trim s body-start eq-pos) "q")
                      (let ((v (string->number (trim s (+ eq-pos 1) semi))))
                        (and v (zero? v))))
                 #t
                 (param semi))))))
)
