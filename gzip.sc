#!chezscheme
;;; (igropyr gzip) -- gzip compression via zlib (deflateInit2 windowBits 31).
;;;
;;; (gzip-compress bv level) -> a gzip-format bytevector (browser
;;; Content-Encoding: gzip), or #f on failure. level 1..9 (6 is a good
;;; default). Used by the express layer to compress responses when the
;;; client sends Accept-Encoding: gzip.

(library (igropyr gzip)
  (export gzip-compress gzip-acceptable?)
  (import (chezscheme))

  (define zlib-loaded
    (begin (load-shared-object "libz.dylib")
           (load-shared-object "libSystem.dylib")))

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

  ;; does an Accept-Encoding header value allow gzip?
  (define (gzip-acceptable? accept-encoding)
    (and accept-encoding
         (let ((s (string-downcase accept-encoding))
               (needle "gzip"))
           (let ((n (string-length s)) (m (string-length needle)))
             (let loop ((i 0))
               (cond
                 ((> (+ i m) n) #f)
                 ((string=? (substring s i (+ i m)) needle) #t)
                 (else (loop (+ i 1)))))))))
)
