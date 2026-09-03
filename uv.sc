#!chezscheme
;;; (igropyr uv) -- the raw libuv binding layer.
;;;
;;; ⭐ THE CUT IS BY OWNERSHIP, NOT BY SUBJECT. What lives here is what belongs
;;; to the LOOP: the FFI bindings and their constants, the loop handle and the
;;; process-wide buffers allocated with it, and the two callbacks the loop
;;; itself drives (its wakeup timer and uv_walk). Everything owned by a
;;; connection or by an owning process -- conns, listeners, DNS, files, the
;;; TLS codec -- is (igropyr tcp), one layer up.
;;;
;;; ⛔ NEVER IMPORT (igropyr tcp) OR (igropyr tls-core) HERE. This library is
;;; below both; (igropyr libuv) is a façade above them that re-exports the
;;; public API name for name, so existing consumers see no change at all.
;;;
;;; ⚠ THE SHARED BUFFERS ARE HANDED OUT AS LEASES, NOT AS POINTERS. Their
;;; whole safety argument is "packed and used inside one interrupt-disabled
;;; region, with no yield between the pack and the syscall" -- and that
;;; argument lives HERE, next to the buffer. Exporting the raw address would
;;; move the argument out of sight of every caller that depends on it, so a
;;; caller instead passes a thunk that runs inside the region.

(library (igropyr uv)
  (export
    ;; loop lifecycle and observation
    uv-init! uv-poll! uv-wakeup! uv-in-callback? uv-loop-handle
    uv-live-handle-count uv-strerror check now-ms now-ns
    ;; the leases and the read buffer's constants
    uv-sockaddr-lease uv-scratch-lease uv-peername-lease
    uv-read-buf-base uv-read-buf-size uv-write-scratch-size
    ;; sizes
    uv-handle-size uv-req-size tcp-handle-size timer-handle-size
    write-req-size connect-req-size getaddrinfo-req-size fs-req-size buf-t-size
    ;; constants
    UV-RUN-NOWAIT UV-RUN-ONCE UV-TCP UV-TIMER UV-WRITE UV-EOF UV-CONNECT
    UV-GETADDRINFO UV-FS UV-EINVAL S-IFMT S-IFREG AF-INET uv-enomem
    O-RDONLY O-DIRECTORY O-NOFOLLOW O-CLOEXEC
    fs-o-rdonly fs-o-wronly fs-o-creat fs-o-trunc fs-o-excl
    fs-o-directory fs-o-cloexec
    ;; raw entry points, used by (igropyr tcp)
    uv-loop-size uv-loop-init uv-run uv-hrtime uv-ip4-addr
    uv-tcp-init uv-tcp-connect uv-getaddrinfo uv-freeaddrinfo
    uv-fs-open uv-fs-read uv-fs-close uv-fs-fstat uv-fs-realpath
    uv-fs-stat uv-fs-unlink uv-fs-scandir uv-fs-scandir-next
    uv-fs-get-ptr uv-fs-get-result uv-fs-get-statbuf uv-fs-req-cleanup
    uv-fs-write uv-fs-fsync uv-fs-rename uv-fs-mkdir
    uv-tcp-bind uv-tcp-nodelay uv-listen uv-accept
    uv-read-start uv-read-stop uv-write uv-try-write
    uv-close uv-is-closing uv-is-active
    uv-timer-init uv-timer-start uv-timer-stop
    memcpy-from-c memcpy-to-c memcpy-cc
    c-open c-openat c-close uv-fileno c-getsockopt)

  ;; ⭐ (igropyr inject) IS A COMPILE-TIME ONLY DEPENDENCY WHEN OFF, the same
  ;; arrangement the rest of the tree documents.
  (import (chezscheme) (igropyr platform) (igropyr inject))


  ;; Shared objects must be loaded before the foreign-procedure
  ;; definitions below are evaluated (library body runs in order).
  (define shared-objects
    (begin
      (ensure-supported-platform!)
      (load-first-shared-object! 'libuv
        (case platform-os
          ((macos) '("/opt/homebrew/lib/libuv.1.dylib" "libuv.1.dylib" "libuv.dylib"))
          ((freebsd) '("/usr/local/lib/libuv.so.1" "libuv.so.1" "libuv.so"))
          (else '("libuv.so.1" "libuv.so"))))
      (load-first-shared-object! 'libc
        (case platform-os
          ((macos) '("libSystem.B.dylib" "libSystem.dylib"))
          ;; FreeBSD libc soname tracks the major release: 8.0+ is
          ;; libc.so.7, 7.x is libc.so.6; try newest first, then the
          ;; bare name. load-first-shared-object! probes each in order.
          ((freebsd) '("libc.so.7" "libc.so.6" "libc.so"))
          (else '("libc.so.6" "libc.so"))))))

  ;; libuv enum constants (from uv.h, libuv 1.50)
  (define UV-RUN-NOWAIT 2)
  (define UV-RUN-ONCE 1)
  (define UV-TCP 12)
  (define UV-TIMER 13)
  (define UV-WRITE 3)
  (define UV-EOF -4095)

  ;; foreign procedures
  (define uv-loop-size   (foreign-procedure "uv_loop_size" () size_t))
  (define uv-loop-init   (foreign-procedure "uv_loop_init" (void*) int))
  (define uv-run         (foreign-procedure "uv_run" (void* int) int))
  (define uv-hrtime      (foreign-procedure "uv_hrtime" () unsigned-64))
  (define uv-handle-size (foreign-procedure "uv_handle_size" (int) size_t))
  (define uv-req-size    (foreign-procedure "uv_req_size" (int) size_t))
  (define uv-ip4-addr    (foreign-procedure "uv_ip4_addr" (string int void*) int))
  (define uv-tcp-init    (foreign-procedure "uv_tcp_init" (void* void*) int))
  (define uv-tcp-connect (foreign-procedure "uv_tcp_connect" (void* void* void* void*) int))
  (define uv-getaddrinfo (foreign-procedure "uv_getaddrinfo" (void* void* void* string void* void*) int))
  (define uv-freeaddrinfo (foreign-procedure "uv_freeaddrinfo" (void*) void))
  (define uv-fs-open  (foreign-procedure "uv_fs_open" (void* void* string int int void*) int))
  (define uv-fs-read  (foreign-procedure "uv_fs_read" (void* void* int void* unsigned-int long void*) int))
  (define uv-fs-close (foreign-procedure "uv_fs_close" (void* void* int void*) int))
  (define uv-fs-fstat (foreign-procedure "uv_fs_fstat" (void* void* int void*) int))
  (define uv-fs-realpath
    (foreign-procedure "uv_fs_realpath" (void* void* string void*) int))
  ;; The three path-only operations. They take no descriptor and open
  ;; none: uv_fs_scandir's int is its flags word, which libuv ignores.
  (define uv-fs-stat
    (foreign-procedure "uv_fs_stat" (void* void* string void*) int))
  (define uv-fs-unlink
    (foreign-procedure "uv_fs_unlink" (void* void* string void*) int))
  (define uv-fs-scandir
    (foreign-procedure "uv_fs_scandir" (void* void* string int void*) int))
  ;; Pulls one entry out of a completed scandir request into a caller-owned
  ;; uv_dirent_t. Returns UV_EOF when the listing is exhausted.
  (define uv-fs-scandir-next
    (foreign-procedure "uv_fs_scandir_next" (void* void*) int))

  ;; ⚠ THE ONLY ERRNO THIS FILE INVENTS. Every other #(file-error ,e)
  ;; carries a number libuv returned; this one is reported when the
  ;; scandir callback itself runs out of memory building Scheme strings,
  ;; a failure libuv never saw and has no code for. It is spelled the way
  ;; libuv spells it so a consumer's existing errno handling covers it:
  ;; uv/errno.h defines UV__ENOMEM as UV__ERR(ENOMEM), and UV__ERR(x) is
  ;; -(x) on everything but Windows, with ENOMEM = 12.
  (define uv-enomem -12)

  (define uv-fs-get-ptr (foreign-procedure "uv_fs_get_ptr" (void*) void*))
  (define uv-fs-get-result (foreign-procedure "uv_fs_get_result" (void*) ssize_t))
  (define uv-fs-get-statbuf (foreign-procedure "uv_fs_get_statbuf" (void*) void*))
  (define uv-fs-req-cleanup (foreign-procedure "uv_fs_req_cleanup" (void*) void))
  ;; write side. Same shapes as their read-side siblings above; rename
  ;; takes two paths and no descriptor.
  (define uv-fs-write
    (foreign-procedure "uv_fs_write"
      (void* void* int void* unsigned-int long void*) int))
  (define uv-fs-fsync
    (foreign-procedure "uv_fs_fsync" (void* void* int void*) int))
  (define uv-fs-rename
    (foreign-procedure "uv_fs_rename" (void* void* string string void*) int))
  (define uv-fs-mkdir
    (foreign-procedure "uv_fs_mkdir" (void* void* string int void*) int))
  (define uv-tcp-bind    (foreign-procedure "uv_tcp_bind" (void* void* unsigned-int) int))
  (define uv-tcp-nodelay (foreign-procedure "uv_tcp_nodelay" (void* int) int))
  (define uv-listen      (foreign-procedure "uv_listen" (void* int void*) int))
  (define uv-accept      (foreign-procedure "uv_accept" (void* void*) int))
  (define uv-read-start  (foreign-procedure "uv_read_start" (void* void* void*) int))
  (define uv-read-stop   (foreign-procedure "uv_read_stop" (void*) int))
  (define uv-write       (foreign-procedure "uv_write" (void* void* void* unsigned-int void*) int))
  (define uv-try-write   (foreign-procedure "uv_try_write" (void* void* unsigned-int) int))
  (define uv-close       (foreign-procedure "uv_close" (void* void*) void))
  (define uv-is-closing  (foreign-procedure "uv_is_closing" (void*) int))
  (define uv-is-active   (foreign-procedure "uv_is_active" (void*) int))
  (define uv-strerror    (foreign-procedure "uv_strerror" (int) string))
  (define uv-timer-init  (foreign-procedure "uv_timer_init" (void* void*) int))
  (define uv-timer-start (foreign-procedure "uv_timer_start" (void* void* unsigned-64 unsigned-64) int))
  (define uv-timer-stop  (foreign-procedure "uv_timer_stop" (void*) int))
  (define memcpy-from-c  (foreign-procedure "memcpy" (u8* void* size_t) void*))
  (define memcpy-to-c    (foreign-procedure "memcpy" (void* u8* size_t) void*))
  (define memcpy-cc      (foreign-procedure "memcpy" (void* void* size_t) void*))
  (define c-open          (foreign-procedure "open" (string int int) int))
  (define c-openat        (foreign-procedure "openat" (int string int int) int))
  (define c-close         (foreign-procedure "close" (int) int))
  (define uv-fileno       (foreign-procedure "uv_fileno" (void* void*) int))
  (define c-getsockopt    (foreign-procedure "getsockopt"
                            (int int int void* void*) int))

  (define UV-CONNECT 2)
  (define UV-GETADDRINFO 8)
  (define UV-FS 6)
  (define O-RDONLY 0)
  ;; open(2) flags differ across the supported Unix families. Static-file
  ;; confinement uses openat one component at a time with O_NOFOLLOW, so
  ;; no pathname component can be swapped to a symlink between validation
  ;; and the actual open.
  (define O-DIRECTORY
    (case platform-os ((linux) #o200000) ((macos) #x100000)
                      ((freebsd) #x20000) (else 0)))
  (define O-NOFOLLOW
    (case platform-os ((linux) #o400000) ((macos freebsd) #x100)
                      (else 0)))
  (define O-CLOEXEC
    (case platform-os ((linux) #o2000000) ((macos) #x1000000)
                      ((freebsd) #x100000) (else 0)))
  ;; THE WRITE SIDE'S open(2) FLAGS, exported for the same reason the
  ;; group above is defined here rather than at each use: the values
  ;; differ by Unix family, and a caller that hardcodes one set is
  ;; correct on the machine it was written on and wrong on the next.
  ;; The BSDs agree with each other and Linux does not, which is the
  ;; combination that hides the mistake -- developed on macOS, deployed
  ;; on FreeBSD, and only a third platform reveals it.
  ;;
  ;; Measured, compiled against <fcntl.h>: macOS 15 (arm64) gives
  ;; O_WRONLY 1, O_CREAT 512, O_TRUNC 1024, O_EXCL 2048. The Linux
  ;; column is the documented asm-generic set; a Linux deployment should
  ;; compile them there before trusting this line, exactly as the
  ;; durable library's note says of its own constants.
  (define fs-o-rdonly O-RDONLY)
  (define fs-o-wronly 1)
  (define fs-o-creat
    (case platform-os ((linux) #o100) ((macos freebsd) #o1000) (else 0)))
  (define fs-o-trunc
    (case platform-os ((linux) #o1000) ((macos freebsd) #o2000) (else 0)))
  (define fs-o-excl
    (case platform-os ((linux) #o200) ((macos freebsd) #o4000) (else 0)))

  ;; O_DIRECTORY IS THE ONE THAT DOES NOT MERGE. The four above share a
  ;; value across macOS and FreeBSD, which is why they are written as one
  ;; branch; this one does not, and a merged branch would have been wrong
  ;; on whichever platform was not the one it was written on -- the same
  ;; trap the note above describes, sprung by a fifth constant.
  ;;
  ;; Measured this time, compiled against <fcntl.h> on both:
  ;;   macOS 15 (arm64)      O_DIRECTORY = 0o4000000  (0x100000)
  ;;   FreeBSD 15.0-RELEASE  O_DIRECTORY = 0o400000   (0x20000)
  ;; Each run also printed O_RDONLY, O_CREAT and O_EXCL and got the
  ;; values already recorded above, which is what says the measurement
  ;; itself is trustworthy rather than just plausible. The Linux column
  ;; is again the documented asm-generic value and was NOT measured here;
  ;; compile it there before trusting it.
  ;;
  ;; It exists so that a caller with no stat can still tell a directory
  ;; from a file: opening a path with it succeeds only for a directory,
  ;; and answers -ENOTDIR for anything else.
  (define fs-o-directory
    (case platform-os
      ((linux) #o200000) ((macos) #o4000000) ((freebsd) #o400000) (else 0)))

  ;; AND THE CLEAREST ARGUMENT FOR MEASURING EACH ONE. FreeBSD's
  ;; O_CLOEXEC is 0o4000000 -- the same number as macOS's O_DIRECTORY
  ;; above. A value carried across from one platform to the other does
  ;; not fail here; it asks for a different flag and succeeds, which is
  ;; the kind of wrong that no test reports.
  ;;
  ;; Measured, compiled against <fcntl.h>:
  ;;   macOS 15 (arm64)      O_CLOEXEC = 0o100000000 (0x1000000)
  ;;   FreeBSD 15.0-RELEASE  O_CLOEXEC = 0o4000000   (0x100000)
  ;; Both runs also printed O_RDONLY, O_EXCL and O_DIRECTORY and matched
  ;; what is recorded above. Linux is the documented asm-generic value
  ;; and was NOT measured; compile it there before trusting it.
  (define fs-o-cloexec
    (case platform-os
      ((linux) #o2000000) ((macos) #o100000000) ((freebsd) #o4000000)
      (else 0)))

  (define UV-EINVAL -22)
  (define S-IFMT #o170000)
  (define S-IFREG #o100000)
  (define tcp-handle-size (uv-handle-size UV-TCP))
  (define timer-handle-size (uv-handle-size UV-TIMER))
  (define write-req-size (uv-req-size UV-WRITE))
  (define connect-req-size (uv-req-size UV-CONNECT))
  (define getaddrinfo-req-size (uv-req-size UV-GETADDRINFO))
  (define fs-req-size (uv-req-size UV-FS))
  (define buf-t-size 16)             ; uv_buf_t on arm64: {void* base; size_t len}

  ;; Monotonic milliseconds. uv_hrtime is nanoseconds since an
  ;; arbitrary epoch (boot); it stays below 2^60 for ~36 years of
  ;; uptime, so the value is always a fixnum and fxdiv avoids the
  ;; generic-arithmetic div on this hot path (called per receive
  ;; timeout and per event-loop pass).
  (define (now-ms) (fxdiv (uv-hrtime) 1000000))

  ;; Monotonic nanoseconds (same clock as now-ms, undivided) -- for timing
  ;; sub-millisecond spans where now-ms rounds to 0. A raw value is a fixnum
  ;; (see now-ms), so a difference of two is exact and allocation-free.
  (define (now-ns) (uv-hrtime))

  ;; walk the addrinfo linked list, return the first IPv4 as "a.b.c.d".
  ;; Supported LP64 addrinfo layouts share ai_family @ 4 and ai_next @ 40;
  ;; ai_addr is selected by (igropyr platform). sockaddr_in.sin_addr @ 4.
  (define AF-INET 2)

  (define (check who r)
    (if (< r 0)
        (error who (uv-strerror r))
        r))


  ;; global libuv state, allocated in uv-init!
  (define uv-loop 0)
  (define wakeup-timer 0)
  (define sockaddr-buf 0)
  (define peername-buf 0)            ; conn-peer-ip scratch (own buffer:
  (define peername-len 0)            ; sockaddr-buf holds connect state)
  (define read-buf 0)
  (define read-buf-size 65536)
  ;; reusable scratch for the uv_try_write fast path (single OS thread,
  ;; used only for the duration of a synchronous try_write)
  (define write-scratch 0)
  (define write-scratch-size 65536)
  (define scratch-buf 0)             ; one reusable uv_buf_t


  ;; ⭐ ARE WE IN A CALLBACK FRAME? Set around uv_run, which is the only place
  ;; libuv callbacks run from. This is used instead of comparing pids against
  ;; the event-loop process: it is the direct mechanism rather than an identity
  ;; test standing in for one, and it needs no second hook to tell us which pid
  ;; the loop is.
  (define in-uv-run? #f)

  ;; walk_cb: counts. uv_walk is the only way to ask libuv how many
  ;; handles the loop is holding, and that question has no answer
  ;; anywhere on the Scheme side -- a handle that was initialised and
  ;; then abandoned is in no table here, so nothing short of asking the
  ;; loop can see it. Without this, "the handle is not leaked" is a
  ;; sentence with no measurement behind it.
  (define walk-tally 0)

  (define on-walk-code
    (foreign-callable
      (lambda (handle arg) (set! walk-tally (fx+ walk-tally 1)))
      (void* void*)
      void))

  ;; timer_cb for the poll wakeup timer: exists only to bound the
  ;; blocking uv_run(ONCE) wait; does nothing.
  (define on-timer-code
    (foreign-callable
      (lambda (handle) (void))
      (void*)
      void))


  ;; ⭐ THE LOCK TABLE IS SPLIT BY OWNERSHIP, NOT MOVED WHOLE. Only these two
  ;; code objects belong to the loop itself -- its wakeup timer and uv_walk.
  ;; The other eleven reach into connection and file tables and are locked in
  ;; (igropyr tcp), beside the state they touch. libuv holds raw entry
  ;; pointers, so every code object must be locked wherever it lives or the
  ;; loop jumps into collected code; the invariant is the ORDER -- construct,
  ;; lock, take the entry point, hand it over -- not any registration with
  ;; this library, which C never sees.
  (define locked-callbacks
    (begin
      (lock-object on-timer-code)
      (lock-object on-walk-code)
      (vector on-timer-code on-walk-code)))

  (define on-timer-entry (foreign-callable-entry-point on-timer-code))
  (define on-walk-entry (foreign-callable-entry-point on-walk-code))

  (define uv-walk-c
    (foreign-procedure "uv_walk" (void* void* void*) void))



  ;; Every handle the loop still holds, counted. Includes the internal
  ;; wakeup timer, so the number is compared against a baseline taken in
  ;; the same process rather than against zero.
  ;;
  ;; ⚠ A CLOSING HANDLE IS STILL A HANDLE. uv_close is asynchronous: the
  ;; handle leaves the loop when its close callback runs, which needs the
  ;; loop to turn. Read this number straight after a close and it counts
  ;; something that is on its way out, which reads exactly like a leak.
  ;; A caller measuring "was it released" has to let the loop run first
  ;; -- a sleep long enough to be sure, and that sleep is waiting for the
  ;; LOOP, not waiting for a fix to take effect. The first measurement
  ;; written against this counter got that wrong and reported five leaked
  ;; handles that were all already closing.
  (define (uv-live-handle-count)
    (with-interrupts-disabled
      (set! walk-tally 0)
      (uv-walk-c uv-loop on-walk-entry 0)
      walk-tally))

  (define (uv-init!)
    (set! uv-loop (foreign-alloc (uv-loop-size)))
    (check 'uv-loop-init (uv-loop-init uv-loop))
    (set! wakeup-timer (foreign-alloc timer-handle-size))
    (check 'uv-timer-init (uv-timer-init uv-loop wakeup-timer))
    (set! sockaddr-buf (foreign-alloc 128))
    (set! peername-buf (foreign-alloc 128))
    (set! peername-len (foreign-alloc 8))
    (set! read-buf (foreign-alloc read-buf-size))
    (set! write-scratch (foreign-alloc write-scratch-size))
    (set! scratch-buf (foreign-alloc buf-t-size)))

  ;; Pump the event loop. timeout-ms = 0: poll without blocking.
  ;; timeout-ms > 0: block in the OS poller until I/O arrives or the
  ;; wakeup timer fires -- zero busy-wait when idle.
  (define (uv-poll! timeout-ms)
    (dynamic-wind
      (lambda () (set! in-uv-run? #t))
      (lambda ()
        (if (<= timeout-ms 0)
            (uv-run uv-loop UV-RUN-NOWAIT)
            (begin
              (uv-timer-start wakeup-timer on-timer-entry timeout-ms 0)
              (uv-run uv-loop UV-RUN-ONCE)
              (uv-timer-stop wakeup-timer))))
      (lambda () (set! in-uv-run? #f))))


  ;; -> the loop's address. A procedure and not the variable itself: uv-init!
  ;; assigns it, and R6RS forbids exporting an assigned variable -- the same
  ;; rule that put ctx and live-sessions behind accessors in tls-core.
  (define (uv-loop-handle) uv-loop)

  ;; -> #t while the loop is inside uv_run, i.e. while any libuv callback is
  ;; running. A predicate rather than the flag, for the reason above.
  (define (uv-in-callback?) in-uv-run?)

  ;; Wake a loop that is blocked in the OS poller.
  (define (uv-wakeup!)
    (uv-timer-start wakeup-timer on-timer-entry 0 0))

  ;; A constant, and exported as one: the fast-write path has to choose its
  ;; branch on the staging area's size BEFORE it takes the lease, so this one
  ;; value cannot live behind the lease that hands out the buffer itself.
  ;; Safe to export directly -- unlike the buffers and the loop, it is never
  ;; assigned.
  (define uv-write-scratch-size write-scratch-size)

  (define (uv-read-buf-base) read-buf)
  (define (uv-read-buf-size) read-buf-size)

  ;; ---- buffer leases -------------------------------------------------
  ;;
  ;; Each hands its buffer to a thunk INSIDE one interrupt-disabled region and
  ;; takes it back when the thunk returns. The caller's whole sequence runs in
  ;; there, in its original order -- that is what makes "nothing yields
  ;; between the pack and the syscall" still true after the split, and why the
  ;; address is never returned to a caller who could hold it past the region.
  (define (uv-sockaddr-lease proc)
    (with-interrupts-disabled (proc sockaddr-buf)))

  (define (uv-peername-lease proc)
    (with-interrupts-disabled (proc peername-buf peername-len)))

  ;; two buffers, because the fast write path needs both the staging area and
  ;; the uv_buf_t that points at it
  (define (uv-scratch-lease proc)
    (with-interrupts-disabled (proc write-scratch write-scratch-size scratch-buf)))
  )

