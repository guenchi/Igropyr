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

  (define libc-loaded
    (begin
      (ensure-supported-platform!)
      (load-first-shared-object! 'libc
        (case platform-os
          ((macos) '("libSystem.B.dylib" "libSystem.dylib"))
          ;; FreeBSD libc soname tracks the major release (8.0+ = .7,
          ;; 7.x = .6); probe newest first, then the bare name.
          ((freebsd) '("libc.so.7" "libc.so.6" "libc.so"))
          (else '("libc.so.6" "libc.so"))))))

  (define memset*        (foreign-procedure "memset" (void* int size_t) void*))
  (define memcpy-to-c    (foreign-procedure "memcpy" (void* u8* size_t) void*))
  (define memcpy-from-c  (foreign-procedure "memcpy" (u8* void* size_t) void*))

  ;; ------------------------------------------------------------------
  ;; Which zlib?
  ;;
  ;; The Chez Scheme runtime embeds a complete zlib (it compresses fasl
  ;; files with it), and on FreeBSD the chez-scheme executable exports
  ;; every zlib symbol. Loading the system libz there puts a SECOND
  ;; zlib with identically named globals into the process, and deflate
  ;; breaks in that combination: deflateInit2_ reports success but
  ;; leaves a deflate_state whose sym_buf holds only the low 32 bits of
  ;; pending_buf -- deflate() then faults as soon as the C heap sits
  ;; above 4 GB, and incompressible input drives it into emitting
  ;; unbounded output. The same call sequence against the embedded copy
  ;; alone behaves, and so does the system libz from a plain C program;
  ;; the defect belongs to the coexistence, not to either zlib.
  ;;
  ;; So on FreeBSD this library binds the embedded zlib and never loads
  ;; a second one. chez-scheme there is a non-PIE executable, so the
  ;; addresses in its own dynamic symbol table ARE its runtime
  ;; addresses, and foreign-procedure accepts an address as an entry.
  ;; If any assumption fails (a PIE build, missing symbols), gzip stays
  ;; disabled -- gzip-compress returns #f, which callers already treat
  ;; as "send this uncompressed" -- rather than bind the combination
  ;; known to corrupt memory.
  ;; ------------------------------------------------------------------

  ;; The absolute path of the running executable, via
  ;; sysctl kern.proc.pathname; #f if the kernel will not say.
  (define (freebsd-executable-path)
    (let ((sysctl* (foreign-procedure "sysctl"
                     (void* unsigned-int void* void* void* size_t) int))
          (mib (foreign-alloc 16))
          (cap 1024))
      (let ((buf (foreign-alloc cap))
            (len (foreign-alloc 8)))
        (foreign-set! 'int mib 0 1)          ; CTL_KERN
        (foreign-set! 'int mib 4 14)         ; KERN_PROC
        (foreign-set! 'int mib 8 12)         ; KERN_PROC_PATHNAME
        (foreign-set! 'int mib 12 -1)        ; the calling process
        (foreign-set! 'unsigned-long len 0 cap)
        (let* ((rc (sysctl* mib 4 buf len 0 0))
               (path (and (= rc 0)
                          (let scan ((i 0) (acc '()))
                            (and (< i cap)
                                 (let ((b (foreign-ref 'unsigned-8 buf i)))
                                   (if (fx= b 0)
                                       (utf8->string
                                         (u8-list->bytevector (reverse acc)))
                                       (scan (fx+ i 1) (cons b acc)))))))))
          (foreign-free mib) (foreign-free buf) (foreign-free len)
          path))))

  ;; Addresses of the `wanted` dynamic symbols in a little-endian
  ;; non-PIE ELF64 executable, where link address = runtime address.
  ;; -> list of (name address . entry-bytes), or #f when the image does
  ;; not satisfy those assumptions (wrong magic, PIE, no .dynsym).
  ;; entry-bytes are the file's first bytes at the symbol (up to 64,
  ;; located through the PT_LOAD segments) -- the caller compares them
  ;; with live memory before trusting an address, because the file at
  ;; this path is not necessarily the image this process is running
  ;; (a package upgrade can replace the file after exec).
  (define (elf-dynamic-symbol-addresses path wanted)
    (guard (e (#t #f))
      (let ((p (open-file-input-port path)))
        (dynamic-wind
          (lambda () (void))
          (lambda ()
            (define (bytes at n)
              (set-port-position! p at)
              (let ((bv (get-bytevector-n p n)))
                (and (bytevector? bv) (= (bytevector-length bv) n) bv)))
            (define (u16 bv i) (bytevector-u16-ref bv i 'little))
            (define (u32 bv i) (bytevector-u32-ref bv i 'little))
            (define (u64 bv i) (bytevector-u64-ref bv i 'little))
            (define (name-at bv i)             ; NUL-terminated, ASCII
              (let scan ((e i) (acc '()))
                (let ((b (bytevector-u8-ref bv e)))
                  (if (fx= b 0)
                      (list->string (reverse acc))
                      (scan (fx+ e 1) (cons (integer->char b) acc))))))
            (let ((eh (bytes 0 64)))
              (and eh
                   (= (u32 eh 0) #x464C457F)        ; "\x7fELF"
                   (fx= (bytevector-u8-ref eh 4) 2) ; ELFCLASS64
                   (fx= (bytevector-u8-ref eh 5) 1) ; little-endian
                   (fx= (u16 eh 16) 2)              ; ET_EXEC: non-PIE only
                   (let* ((shoff (u64 eh 40))
                          (shentsize (u16 eh 58))
                          (shnum (u16 eh 60))
                          (shs (bytes shoff (* shnum shentsize)))
                          (phoff (u64 eh 32))
                          (phentsize (u16 eh 54))
                          (phnum (u16 eh 56))
                          (phs (bytes phoff (* phnum phentsize))))
                     (define (file-bytes-at vaddr want)
                       ;; the file's bytes for a virtual address, found
                       ;; through the PT_LOAD segment that carries it
                       (let seek ((i 0))
                         (and (fx< i phnum)
                              (let ((ph (fx* i phentsize)))
                                (if (not (= 1 (u32 phs ph)))    ; PT_LOAD
                                    (seek (fx+ i 1))
                                    (let ((p-off (u64 phs (fx+ ph 8)))
                                          (p-vaddr (u64 phs (fx+ ph 16)))
                                          (p-filesz (u64 phs (fx+ ph 32))))
                                      (if (and (>= vaddr p-vaddr)
                                               (< vaddr (+ p-vaddr p-filesz)))
                                          (bytes (+ p-off (- vaddr p-vaddr))
                                                 (min want (- (+ p-vaddr p-filesz)
                                                              vaddr)))
                                          (seek (fx+ i 1)))))))))
                     (and shs phs
                          (let find-dynsym ((i 0))
                            (and (fx< i shnum)
                                 (let ((sh (fx* i shentsize)))
                                   (if (not (= 11 (u32 shs (fx+ sh 4)))) ; SHT_DYNSYM
                                       (find-dynsym (fx+ i 1))
                                       ;; sh_link names the paired string
                                       ;; table's section index
                                       (let* ((strsh (fx* (u32 shs (fx+ sh 40))
                                                          shentsize))
                                              (syms (bytes (u64 shs (fx+ sh 24))
                                                           (u64 shs (fx+ sh 32))))
                                              (entsz (u64 shs (fx+ sh 56)))
                                              (strs (bytes (u64 shs (fx+ strsh 24))
                                                           (u64 shs (fx+ strsh 32)))))
                                         (and syms strs (>= entsz 24)
                                              (let collect ((o 0) (acc '()))
                                                (if (> (+ o entsz)
                                                       (bytevector-length syms))
                                                    acc
                                                    (let ((nameoff (u32 syms o))
                                                          (shndx (u16 syms (fx+ o 6)))
                                                          (value (u64 syms (fx+ o 8))))
                                                      (collect
                                                        (+ o entsz)
                                                        (if (and (not (fx= shndx 0)) ; defined here
                                                                 (not (fx= nameoff 0))
                                                                 (not (= value 0)))
                                                            (let ((nm (name-at strs nameoff)))
                                                              (if (member nm wanted)
                                                                  (let* ((size (u64 syms (fx+ o 16)))
                                                                         (want (max 8 (min 64 (if (= size 0) 16 size))))
                                                                         (slice (file-bytes-at value want)))
                                                                    (if slice
                                                                        (cons (cons nm (cons value slice)) acc)
                                                                        acc))
                                                                  acc))
                                                            acc))))))))))))))))
          (lambda () (close-port p))))))

  (define zlib-symbol-names
    '("zlibVersion" "deflateInit2_" "deflate" "deflateEnd"
      "inflateInit2_" "inflate" "inflateEnd"))

  ;; Is memory at addr mapped in this process AND byte-for-byte equal
  ;; to `expected`? mincore first, so an address that is not mapped
  ;; here fails cleanly instead of faulting on the read. This is what
  ;; stands between "the file at the executable's path" and "the image
  ;; this process is actually running": when an upgrade has replaced
  ;; the file after exec, its symbol addresses describe the wrong
  ;; image, and no symbol may be called on that evidence.
  (define getpagesize* (foreign-procedure "getpagesize" () int))
  (define mincore*     (foreign-procedure "mincore" (void* size_t u8*) int))
  (define (mapped-and-matching? addr expected)
    (let* ((count (bytevector-length expected))
           (ps (getpagesize*))
           (base (* ps (div addr ps)))
           (span (- (* ps (div (+ addr count ps -1) ps)) base))
           (vec (make-bytevector (div span ps) 0)))
      (and (fx> count 0)
           (fx= 0 (mincore* base span vec))
           (let loop ((i 0))
             (cond ((fx= i count) #t)
                   ((fx= (foreign-ref 'unsigned-8 addr i)
                         (bytevector-u8-ref expected i))
                    (loop (fx+ i 1)))
                   (else #f))))))

  (define zlib-addresses
    (and (eq? platform-os 'freebsd)
         (let ((path (freebsd-executable-path)))
           (and path
                (let ((syms (elf-dynamic-symbol-addresses path zlib-symbol-names)))
                  (and syms
                       (for-all
                         (lambda (n)
                           (let ((e (assoc n syms)))
                             (and e (mapped-and-matching? (cadr e) (cddr e)))))
                         zlib-symbol-names)
                       (map (lambda (e) (cons (car e) (cadr e))) syms)))))))

  ;; 'embedded -> entries are addresses inside the running executable
  ;; 'system   -> the platform zlib, referenced by name
  ;; 'disabled -> no safe zlib here; gzip-compress yields #f
  (define zlib-source
    (cond
      (zlib-addresses 'embedded)
      ((eq? platform-os 'freebsd) 'disabled)
      (else (load-first-shared-object! 'zlib
              (case platform-os
                ((macos) '("libz.1.dylib" "libz.dylib"))
                (else '("libz.so.1" "libz.so"))))
            'system)))

  (define (zlib-entry name)
    (case zlib-source
      ((embedded) (cdr (assoc name zlib-addresses)))
      ((system) name)
      (else #f)))

  ;; When disabled, bind a stub whose return value no caller reads as
  ;; success (Z_OK = 0, Z_STREAM_END = 1).
  (define-syntax define-zlib-procedure
    (syntax-rules ()
      ((_ id name (arg ...) res)
       (define id
         (let ((entry (zlib-entry name)))
           (if entry
               (foreign-procedure entry (arg ...) res)
               (lambda ignored -1)))))))

  (define zlib-version
    (let ((entry (zlib-entry "zlibVersion")))
      (if entry
          (foreign-procedure entry () string)
          (lambda () "unavailable"))))
  (define-zlib-procedure deflate-init2 "deflateInit2_"
    (void* int int int int int string int) int)
  (define-zlib-procedure deflate* "deflate" (void* int) int)
  (define-zlib-procedure deflate-end "deflateEnd" (void*) int)
  ;; inflate side: used only by the load-time self-check below
  (define-zlib-procedure inflate-init2 "inflateInit2_"
    (void* int string int) int)
  (define-zlib-procedure inflate* "inflate" (void* int) int)
  (define-zlib-procedure inflate-end "inflateEnd" (void*) int)

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

  ;; z_stream's avail_in/avail_out are 32-bit. The largest n whose
  ;; output bound (n + n/1000 + 128) still fits in one is 4290676491;
  ;; past that the stream cannot be described to deflate in one call,
  ;; so refuse with #f up front instead of overflowing the counters
  ;; (which would raise mid-call, or silently truncate at optimize
  ;; levels that elide the foreign-set! range check).
  (define max-input-size 4290676491)

  ;; The worker. Returns #f on any zlib error.
  (define (gzip-compress* bv level)
    (if (> (bytevector-length bv) max-input-size)
        #f
        (gzip-compress-in-range bv level)))

  (define (gzip-compress-in-range bv level)
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

  ;; Inflate `gz` expecting exactly n bytes back; self-check only.
  (define (gunzip-for-self-check gz n)
    (let* ((glen (bytevector-length gz))
           (strm (foreign-alloc 128))
           (src (foreign-alloc (max 1 glen)))
           (dst (foreign-alloc (max 1 n))))
      (define (cleanup) (foreign-free strm) (foreign-free src) (foreign-free dst))
      (memset* strm 0 128)
      (memcpy-to-c src gz glen)
      (if (not (= Z-OK (inflate-init2 strm Z-GZIP-WINDOW (zlib-version)
                                      z-stream-size)))
          (begin (cleanup) #f)
          (begin
            (foreign-set! 'void* strm 0 src)
            (foreign-set! 'unsigned-32 strm 8 glen)
            (foreign-set! 'void* strm 24 dst)
            (foreign-set! 'unsigned-32 strm 32 n)
            (let* ((rc (inflate* strm Z-FINISH))
                   (out-len (foreign-ref 'unsigned-long strm 40))
                   (in-len (foreign-ref 'unsigned-long strm 16))) ; total_in
              (inflate-end strm)
              ;; in-len = glen rejects a stream whose first member
              ;; reproduces the sample but which carries trailing bytes
              ;; -- Z_STREAM_END alone stops at the first member's end
              (if (and (= rc Z-STREAM-END) (= out-len n) (= in-len glen))
                  (let ((res (make-bytevector n)))
                    (memcpy-from-c res dst n)
                    (cleanup)
                    res)
                  (begin (cleanup) #f)))))))

  ;; A load-time round trip through whatever was bound: compress a
  ;; sample and inflate it back, and refuse the binding unless the
  ;; bytes return intact. This guards every process that loads the
  ;; library, not only the ones a test suite runs next to.
  (define zlib-usable?
    (and (not (eq? zlib-source 'disabled))
         (guard (e (#t #f))
           (let* ((sample (string->utf8
                            "gzip self-check: 0123456789 0123456789"))
                  (gz (gzip-compress* sample 6)))
             (and gz
                  (>= (bytevector-length gz) 18)     ; gzip header + trailer
                  (fx= #x1f (bytevector-u8-ref gz 0))
                  (fx= #x8b (bytevector-u8-ref gz 1))
                  (let ((back (gunzip-for-self-check
                                gz (bytevector-length sample))))
                    (and back (bytevector=? back sample))))))))

  ;; Compress bv to gzip format. Returns #f on any zlib error, and on a
  ;; host with no safe zlib binding -- callers already treat #f as
  ;; "send this body uncompressed".
  (define (gzip-compress bv level)
    (and zlib-usable? (gzip-compress* bv level)))

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
