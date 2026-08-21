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
  ;; The three buffers are freed by a winder rather than by the one exit
  ;; below, so a raise between the first allocation and the last -- an
  ;; exhausted allocator, a bad argument -- does not strand the earlier
  ;; ones. They are allocated in the BODY, not the before-thunk: a raise
  ;; inside a before-thunk propagates without the extent ever being
  ;; entered, so the after-thunk would not run and a partly-completed set
  ;; would leak exactly as before.
  ;;
  ;; This covers the RAISE path only. A winder does not survive a kill,
  ;; and nothing here reclaims after one.
  (define (freebsd-executable-path)
    (let ((sysctl* (foreign-procedure "sysctl"
                     (void* unsigned-int void* void* void* size_t) int))
          (cap 1024)
          (mib #f) (buf #f) (len #f))
      (dynamic-wind
        (lambda () (void))
        (lambda ()
          (set! mib (foreign-alloc 16))
          (set! buf (foreign-alloc cap))
          (set! len (foreign-alloc 8))
          (foreign-set! 'int mib 0 1)          ; CTL_KERN
          (foreign-set! 'int mib 4 14)         ; KERN_PROC
          (foreign-set! 'int mib 8 12)         ; KERN_PROC_PATHNAME
          (foreign-set! 'int mib 12 -1)        ; the calling process
          (foreign-set! 'unsigned-long len 0 cap)
          (let ((rc (sysctl* mib 4 buf len 0 0)))
            (and (= rc 0)
                 (let scan ((i 0) (acc '()))
                   (and (< i cap)
                        (let ((b (foreign-ref 'unsigned-8 buf i)))
                          (if (fx= b 0)
                              (utf8->string
                                (u8-list->bytevector (reverse acc)))
                              (scan (fx+ i 1) (cons b acc)))))))))
        (lambda ()
          (when len (foreign-free len))
          (when buf (foreign-free buf))
          (when mib (foreign-free mib))))))

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
                                          ;; the whole want or nothing: a
                                          ;; slice shortened by the segment
                                          ;; end would weaken the identity
                                          ;; comparison below, possibly to a
                                          ;; single byte
                                          (and (>= (- (+ p-vaddr p-filesz) vaddr)
                                                   want)
                                               (bytes (+ p-off (- vaddr p-vaddr))
                                                      want))
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

  ;; Is memory at addr readable in this process AND byte-for-byte equal
  ;; to `expected`? This is what stands between "the file at the
  ;; executable's path" and "the image this process is actually
  ;; running": when an upgrade has replaced the file after exec, its
  ;; symbol addresses describe the wrong image, and no symbol may be
  ;; called on that evidence.
  ;;
  ;; Readability is probed by handing the range to write(2) on a pipe:
  ;; the kernel copies from the address and reports EFAULT instead of
  ;; faulting the process, which covers unmapped pages and PROT_NONE
  ;; mappings alike -- mincore cannot (it reports existence, not
  ;; readability), and a /dev/null fd cannot either: its driver never
  ;; reads the buffer, so write(2) to it reports success for any
  ;; address, mapped or not. (To re-check, write to /dev/null from an
  ;; address the process never mapped and observe the byte count.)
  ;; The probe only runs on FreeBSD, and pipe2 is only resolved there;
  ;; the guard turns a host whose libc lacks the symbol (releases
  ;; before 10) into pipe2* = #f, which fails the probe below and
  ;; lands in the disabled state instead of throwing out of the
  ;; library's initialization. O_CLOEXEC stops the fds leaking into a
  ;; child should another thread fork+exec mid-probe.
  (define pipe2* (and (eq? platform-os 'freebsd)
                      (guard (e (#t #f))
                        (foreign-procedure "pipe2" (u8* int) int))))
  (define write* (foreign-procedure "write" (int void* size_t) integer-64))
  (define close* (foreign-procedure "close" (int) int))
  (define O-CLOEXEC #x100000)                    ; FreeBSD fcntl.h
  (define (readable-and-matching? addr expected)
    (let ((count (bytevector-length expected))
          (fds (make-bytevector 8)))
      (and (fx> count 0)
           pipe2*
           ;; interrupts stay off from fd creation to the closes, so no
           ;; asynchronous non-local exit can slip in between pipe2 and
           ;; the dynamic-wind that owns the fds; the wind itself still
           ;; covers any exit from inside the body
           (with-interrupts-disabled
             (and (fx= 0 (pipe2* fds O-CLOEXEC))
                  (let ((rfd (bytevector-s32-native-ref fds 0))
                        (wfd (bytevector-s32-native-ref fds 4)))
                    (dynamic-wind
                      (lambda () (void))
                      (lambda ()
                        (and (= count (write* wfd addr count)) ; count <= 64 << PIPE_BUF
                             (let loop ((i 0))
                               (cond ((fx= i count) #t)
                                     ((fx= (foreign-ref 'unsigned-8 addr i)
                                           (bytevector-u8-ref expected i))
                                      (loop (fx+ i 1)))
                                     (else #f)))))
                      (lambda () (close* rfd) (close* wfd)))))))))

  (define zlib-addresses
    (and (eq? platform-os 'freebsd)
         (let ((path (freebsd-executable-path)))
           (and path
                (let ((syms (elf-dynamic-symbol-addresses path zlib-symbol-names)))
                  (and syms
                       (for-all
                         (lambda (n)
                           (let ((e (assoc n syms)))
                             (and e (readable-and-matching? (cadr e) (cddr e)))))
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

  ;; ---- native buffers that outlive a kill ---------------------------------
  ;;
  ;; One compression owns three foreign-allocs and an initialised zlib
  ;; stream. The dynamic-wind below frees all four on every path this
  ;; process can take by itself -- a normal return, a raise from any of
  ;; them. It cannot cover a KILL: the runtime discards winders, by
  ;; design, so a process killed mid-compression runs no cleanup at all.
  ;;
  ;; The teardown that survives a kill is an owner reclaiming on the
  ;; holder's death. There is no owner here -- these blocks belong to
  ;; whoever called -- so the owner is the collector: the three native
  ;; pointers live in one record, together with the end function for
  ;; whatever zlib initialised (the fourth resource is that internal
  ;; state, which is not a pointer this code holds); the record is
  ;; registered with a guardian, and a record that becomes unreachable is
  ;; handed back and freed.
  ;;
  ;; WHAT PINS THE RECORD IS THE AFTER-THUNK, AND THAT IS THE WHOLE
  ;; DESIGN. A guardian reports that an object is UNREACHABLE, which is
  ;; not the same fact as "its holder died" -- a live process that simply
  ;; stops mentioning the record makes it garbage just as effectively,
  ;; and freeing those buffers would be a use-after-free on a
  ;; compression still running. What keeps the two apart is that the
  ;; after-thunk closes over the RECORD: a winder is reachable exactly
  ;; while the process is inside the extent, which is exactly while the
  ;; buffers are in use, and @kill clears the winder list, which is
  ;; exactly the case being covered. Lifetime and use-interval are the
  ;; same interval by construction, not by anyone remembering to keep a
  ;; reference.
  ;;
  ;; So: the after-thunk must mention the RECORD. Closing over the three
  ;; pointers individually instead would read like a simplification and
  ;; would remove the pin, and nothing would report it.
  ;;
  ;; RECLAMATION IS EVENTUAL AND HAS NO TIME BOUND. Foreign memory exerts
  ;; no pressure on the collector, so nothing here provokes a collection.
  ;; Two things have to happen, in order, and neither is on a clock: a
  ;; collection that covers the record's generation has to find it
  ;; unreachable and put it in the guardian's queue, and then some later
  ;; call has to reach one of this library's entry points and drain that
  ;; queue. A GC alone frees nothing here. In a process that keeps
  ;; compressing this is self-limiting -- more compression means more
  ;; Scheme garbage, a collection, and a poll -- but after a kill with no
  ;; further compression the memory stays, however much other activity
  ;; collects, because nothing polls. The bound is one compression's
  ;; allocation per killed compression. Forcing a collection here would
  ;; trade that bounded, quiet cost for an unpredictable full-heap pause,
  ;; which is worse -- and it would still not free anything without a
  ;; poll after it.
  (define gz-guard (make-guardian))

  ;; `ender` is the zlib end function for whatever was initialised on this
  ;; stream -- deflate-end or inflate-end -- or #f if nothing was. Naming
  ;; the function rather than a boolean is what lets both directions share
  ;; one free path, and one free path is one thing to keep correct.
  (define-record-type (gz-buf make-gz-buf gz-buf?)
    (fields (mutable strm) (mutable src) (mutable dst)
            (mutable ender) (mutable freed)))

  ;; Free once, whoever gets there first. The check, the flag and the
  ;; frees are one non-preemptible act: the normal path and the collector
  ;; can both reach a record -- the normal path frees it, and the record
  ;; becomes garbage afterwards and is handed back anyway -- so `freed`
  ;; is what makes the second arrival a no-op instead of a double free.
  (define (gz-free! e)
    (with-interrupts-disabled
      (unless (gz-buf-freed e)
        (gz-buf-freed-set! e #t)
        ;; only end a stream that was actually initialised: ending one
        ;; that was not is not a no-op
        (let ((end (gz-buf-ender e)))
          (when end (end (gz-buf-strm e))))
        (let ((d (gz-buf-dst e))) (when d (foreign-free d)))
        (let ((s (gz-buf-src e))) (when s (foreign-free s)))
        (let ((m (gz-buf-strm e))) (when m (foreign-free m))))))

  ;; Collect whatever the guardian has for us. Called at the start of a
  ;; compression: it is the one moment this library is certainly running,
  ;; and it costs nothing when there is nothing to take.
  ;;
  ;; TAKING AND FREEING ARE ONE ACT. Reading from the guardian REMOVES the
  ;; record from its queue, and nothing re-registers it, so a kill landing
  ;; between the read and the free would drop the only remaining reference
  ;; to buffers that will now never be handed back -- a permanent leak
  ;; that `freed` cannot help with, since nothing would ever look at the
  ;; record again. The region covers one record at a time rather than the
  ;; whole queue: preemption stays off no longer than a single free.
  (define (gz-drain-guard!)
    (let loop ()
      (when (with-interrupts-disabled
              (let ((e (gz-guard)))
                (and e (begin (gz-free! e) #t))))
        (loop))))

  (define (gzip-compress-in-range bv level)
    (gz-drain-guard!)
    (let* ((n (bytevector-length bv))
           (bound (+ n (quotient n 1000) 128))   ; safe deflate upper bound
           (e (make-gz-buf #f #f #f #f #f)))
      (gz-guard e)
      (dynamic-wind
        (lambda () (void))
        (lambda ()
          ;; Each allocation is published into the record before a kill
          ;; can land between the two: an allocation the record does not
          ;; know about is one the collector cannot hand back. They are in
          ;; the BODY rather than the before-thunk on purpose -- a raise
          ;; inside a before-thunk propagates without the extent ever
          ;; being entered, so the after-thunk would not run and a
          ;; partly-completed set of allocations would leak.
          (with-interrupts-disabled
            (gz-buf-strm-set! e (foreign-alloc 128))   ; >= z-stream-size
            (gz-buf-src-set! e (foreign-alloc (max 1 n)))
            (gz-buf-dst-set! e (foreign-alloc bound)))
          (let ((strm (gz-buf-strm e))
                (src (gz-buf-src e))
                (dst (gz-buf-dst e)))
            (memset* strm 0 128)                ; zalloc/zfree/opaque = 0
            (memcpy-to-c src bv n)
            ;; init and recording the ender are one act: a kill in
            ;; between would leave the collector freeing three buffers
            ;; and leaving zlib's own state allocated
            (and (with-interrupts-disabled
                   (and (= Z-OK (deflate-init2 strm level Z-DEFLATED
                                               Z-GZIP-WINDOW 8
                                               Z-DEFAULT-STRATEGY
                                               (zlib-version) z-stream-size))
                        (begin (gz-buf-ender-set! e deflate-end) #t)))
                 (begin
                   (foreign-set! 'void* strm 0 src)          ; next_in
                   (foreign-set! 'unsigned-32 strm 8 n)      ; avail_in
                   (foreign-set! 'void* strm 24 dst)         ; next_out
                   (foreign-set! 'unsigned-32 strm 32 bound) ; avail_out
                   ;; deflate itself is deliberately NOT inside a
                   ;; non-preemptible region: a large input takes real
                   ;; time, and stopping every green process for it would
                   ;; trade a bounded leak for a stalled runtime
                   (let* ((rc (deflate* strm Z-FINISH))
                          (out-len (foreign-ref 'unsigned-long strm 40)))
                     (and (= rc Z-STREAM-END)
                          (let ((res (make-bytevector out-len)))
                            (memcpy-from-c res dst out-len)
                            res)))))))
        ;; mentions e, and that is the pin -- see above
        (lambda () (gz-free! e)))))

  ;; Inflate `gz` expecting exactly n bytes back; self-check only.
  ;; Same ownership shape as the compressor above, for the same reason:
  ;; this runs once per process from the self-check, and a kill landing in
  ;; it leaks exactly as the compressor would. Branch-per-exit cleanup
  ;; does not even cover the raises -- a throw from the second allocation
  ;; strands the first -- so the record, the guardian and the after-thunk
  ;; go here too, and the after-thunk mentions the record for the same
  ;; pinning reason spelled out above.
  (define (gunzip-for-self-check gz n)
    (gz-drain-guard!)
    (let* ((glen (bytevector-length gz))
           (e (make-gz-buf #f #f #f #f #f)))
      (gz-guard e)
      (dynamic-wind
        (lambda () (void))
        (lambda ()
          (with-interrupts-disabled
            (gz-buf-strm-set! e (foreign-alloc 128))
            (gz-buf-src-set! e (foreign-alloc (max 1 glen)))
            (gz-buf-dst-set! e (foreign-alloc (max 1 n))))
          (let ((strm (gz-buf-strm e))
                (src (gz-buf-src e))
                (dst (gz-buf-dst e)))
            (memset* strm 0 128)
            (memcpy-to-c src gz glen)
            (and (with-interrupts-disabled
                   (and (= Z-OK (inflate-init2 strm Z-GZIP-WINDOW
                                               (zlib-version) z-stream-size))
                        (begin (gz-buf-ender-set! e inflate-end) #t)))
                 (begin
                   (foreign-set! 'void* strm 0 src)
                   (foreign-set! 'unsigned-32 strm 8 glen)
                   (foreign-set! 'void* strm 24 dst)
                   (foreign-set! 'unsigned-32 strm 32 n)
                   (let* ((rc (inflate* strm Z-FINISH))
                          (out-len (foreign-ref 'unsigned-long strm 40))
                          (in-len (foreign-ref 'unsigned-long strm 16)))
                     ;; in-len = glen rejects a stream whose first member
                     ;; reproduces the sample but which carries trailing
                     ;; bytes -- Z_STREAM_END alone stops at the first
                     ;; member's end
                     (and (= rc Z-STREAM-END) (= out-len n) (= in-len glen)
                          (let ((res (make-bytevector n)))
                            (memcpy-from-c res dst n)
                            res)))))))
        (lambda () (gz-free! e)))))

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
