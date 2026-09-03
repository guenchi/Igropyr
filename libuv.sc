;;; (igropyr libuv) -- minimal libuv FFI layer for Igropyr.
;;;
;;; This library talks to libuv directly through Chez's FFI: no C shim.
;;; It knows nothing about green processes; message delivery to the
;;; upper layer goes through a hook installed with uv-set-deliver!.
;;;
;;; INVARIANT: code running inside a libuv callback (anything reached
;;; from uv-poll!) must never yield, never block in receive, and never
;;; raise. Callbacks only copy data, mutate registries, and deliver
;;; messages. Yielding would unwind a continuation through a C stack
;;; frame and corrupt the process.

(library (igropyr libuv)
  (export uv-init! uv-poll! now-ms now-ns uv-set-deliver! uv-owner-died!
          tcp-listen! tcp-stop-listen! listener-open? listener-token
          tcp-connect! dns-resolve!
          file-read-async! file-realpath
          file-stream-open! file-stream-open-under!
          file-stream-read! file-stream-close!
          file-stream-own! file-stream-raw! file-stream-chunk-ptr
          fs-open-async! fs-write-async! fs-fsync-async!
          fs-rename-async! fs-close-async! fs-mkdir-async!
          fs-job-count fs-fd-count
          fs-o-rdonly fs-o-wronly fs-o-creat fs-o-trunc fs-o-excl
          fs-o-directory fs-o-cloexec
          fs-count dns-count listener-backlog-effective
          uv-accept-failure-counts
          tcp-read-start! tcp-read-stop! tcp-write! tcp-writev! tcp-write-foreign!
          tcp-close!
          conn? conn-handle conn-owner conn-set-owner! conn-peer-ip
          conn-on-close!
          conn-state conn-count uv-owner-index-count uv-live-handle-count
          uv-strerror)
  ;; ⭐ (igropyr inject) IS A COMPILE-TIME ONLY DEPENDENCY WHEN OFF.
  ;; Its four macros expand to the guarded expression or to nothing
  ;; unless IGROPYR_INJECT was on when this file was compiled, so an
  ;; ordinary build refers to none of its runtime part and does not
  ;; invoke it. Measured, not assumed: a consumer of it reports
  ;; invoke-requirements () when off and ((igropyr inject)) when on.
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

  (define (check who r)
    (if (< r 0)
        (error who (uv-strerror r))
        r))

  ;; connection record; one per accepted TCP client
  (define-record-type (conn make-conn conn?)
    (fields
      (immutable handle conn-handle)             ; foreign address of uv_tcp_t
      (mutable owner conn-owner conn-set-owner-field!) ; pid of the reader process
      (mutable state conn-state conn-set-state!) ; open | closing | closed
      ;; one thunk, run exactly once when the handle's close completes --
      ;; see conn-on-close! below for why cleanup hangs off the conn
      (mutable cleanup conn-cleanup conn-set-cleanup!)))

  ;; GC roots (the "keep-live" story):
  ;; - conn-table roots every live connection's Scheme state while libuv
  ;;   holds the raw handle pointer; doubles as fd-leak accounting.
  ;; - write-table roots write-completion closures until the write_cb runs.
  ;; - locked-callbacks below roots the foreign-callable code objects; if
  ;;   the accept callback were collected, the next connection would jump
  ;;   into freed memory -- the classic crash under high concurrency.
  (define conn-table (make-eqv-hashtable))
  (define write-table (make-eqv-hashtable))
  ;; pending outbound connects: req address -> (handle . owner-pid)
  (define connect-table (make-eqv-hashtable))
  ;; pending DNS lookups: getaddrinfo req address -> owner-pid
  (define getaddrinfo-table (make-eqv-hashtable))
  ;; pending async file reads: fs req address -> fs-op record
  (define fs-table (make-eqv-hashtable))
  (define (conn-count) (hashtable-size conn-table))

  ;; delivery hook: (deliver owner-pid msg); installed by (igropyr actor)
  (define deliver (lambda (owner msg) (void)))
  (define (uv-set-deliver! proc) (set! deliver proc))

  ;; owner pid -> list of resources it may own. This is an INDEX, not the
  ;; truth: entries are added when ownership is established and removed
  ;; by unindex-owner! when a resource is finished with -- but a resource
  ;; handed to another owner leaves its entry behind on purpose, so the
  ;; list is still a superset and every candidate is re-checked against
  ;; the real owner before anything is closed. That
  ;; asymmetry is deliberate -- a stale entry costs one failed check, while
  ;; a MISSING entry would silently skip a resource that had to be freed,
  ;; and conn-set-owner! is exported, so ownership can move at any time.
  ;;
  ;; It exists because uv-owner-died! runs on EVERY process death, and
  ;; scanning four global tables there made each death cost O(all open
  ;; connections): measured at 34.5 us with none and 67.5 us with 6000, so
  ;; a busy server paid for its own concurrency on every request that
  ;; ended. The two quantities that grow under load were multiplying.
  (define owner-index (make-eq-hashtable))

  ;; ⛔ THE READ AND THE WRITE ARE ONE STEP. Both of these are
  ;; read-modify-write on a table several green processes touch, and
  ;; neither was uninterruptible: a preemption between the read and the
  ;; write dropped whatever the other process had just added. The region
  ;; is nested wherever a caller already holds one -- that is safe, the
  ;; disable is counted -- so callers do not have to know.
  (define (index-owner! owner kind key)
    (when owner
      (with-interrupts-disabled
        (hashtable-set! owner-index owner
          (cons (cons kind key) (hashtable-ref owner-index owner '()))))))

  ;; A cell for owner-index-publish!, built where allocation is allowed.
  ;; Two pairs: the entry itself and the list cell that will carry it.
  ;; ⚠ Publishing is set-cdr! plus hashtable-set!, and the latter CAN
  ;; allocate -- it adds a key the first time an owner appears, and may
  ;; grow. ⚠ Preparing separately no longer shortens the region -- both
  ;; callers now prepare INSIDE theirs -- it survives because publishing
  ;; is then a set-cdr! and a store with the key already in hand, not
  ;; the region allocating nothing; an earlier version of this note
  ;; claimed the latter.
  ;; ⚠ THE KEY IS FILLED IN AT PUBLISH TIME, not here, because the key
  ;; is a foreign address that does not exist yet: the allocation that
  ;; produces it happens inside the region, so that a kill before the
  ;; region can lose nothing but Scheme objects the collector reclaims.
  (define (owner-index-prepare! kind)
    (cons (cons kind #f) '()))

  ;; Push a prepared cell, filling in the key. Caller holds the region.
  ;; ⚠ NOT allocation-free: the hashtable-set! can add a key or grow the
  ;; table, and either allocates. The split survives because publishing
  ;; is then a set-cdr! and a store with the key already in hand -- ⛔
  ;; not because it makes the region allocation-free, which an earlier
  ;; version of this note claimed.
  (define (owner-index-publish! owner cell key)
    (when owner
      (set-cdr! (car cell) key)
      (set-cdr! cell (hashtable-ref owner-index owner '()))
      (hashtable-set! owner-index owner cell)))

  ;; Undo owner-index-publish!, and ONLY when the cell is still the head.
  ;; Caller holds the region.
  ;;
  ;; ⭐ IT IS A NO-OP OTHERWISE, ON PURPOSE. Inside one region nothing
  ;; else can have pushed, so if the cell is the head it was published
  ;; here and popping it is exact.
  ;;
  ;; ⚠ "NOT THE HEAD" DOES NOT MEAN "NEVER PUBLISHED" IN GENERAL -- a
  ;; synchronous re-entry that called index-owner! after this publish
  ;; would leave the cell below the new head, and this would silently do
  ;; nothing. Nothing does that today (the publish is the last expression
  ;; in every region that uses it), and that is the condition to recheck
  ;; before adding anything after a publish. Where the cell is not the
  ;; head, an
  ;; unindex-owner! sweep here would be a linear search removing an
  ;; entry that some other operation legitimately owns.
  (define (owner-index-unpublish-head! owner cell)
    (when owner
      (when (eq? (hashtable-ref owner-index owner '()) cell)
        (let ((rest (cdr cell)))
          (if (null? rest)
              (hashtable-delete! owner-index owner)
              (hashtable-set! owner-index owner rest))))))

  ;; Drop an entry when the resource is finished with.
  ;;
  ;; Leaving them was defensible while a stale entry only cost a failed
  ;; re-check -- but the list is per OWNER, and an owner can be long-lived.
  ;; A process that reconnects, resolves and reads files for days
  ;; accumulated one entry per operation it ever performed, held for the
  ;; life of that process, and then walked every one of them inside a
  ;; no-interrupts region when it finally died. Removal keeps the cost
  ;; proportional to what removal has reached rather than to what has
  ;; ever happened. ⚠ It is still a superset of what the owner holds: a
  ;; resource handed to another owner leaves its entry behind on purpose
  ;; (see conn-set-owner!).
  ;;
  ;; Still a superset, not the truth: a resource handed on to another owner
  ;; leaves its entry behind under the old one, and uv-owner-died! re-checks
  ;; every candidate against the real owner before touching it.
  ;; Total entries across every owner. Exported for the same reason as
  ;; conn-count and fs-count: a registration that is never paired with a
  ;; removal has no symptom other than growth, and growth cannot be shown
  ;; to have stopped without a number to compare. It counts entries, not
  ;; owners -- one owner with a thousand stale registrations is the shape
  ;; this is here to catch, and an owner count would read as 1.
  (define (uv-owner-index-count)
    (with-interrupts-disabled
      (let-values (((ks vs) (hashtable-entries owner-index)))
        (let loop ((i 0) (n 0))
          (if (fx= i (vector-length vs))
              n
              (loop (fx+ i 1) (fx+ n (length (vector-ref vs i)))))))))

  ;; ⚠ THE SEARCH RUNS INSIDE THE REGION, AND THAT COST IS REAL. remp is
  ;; O(n) and allocates, and n is the number of resources this owner has
  ;; OPEN -- so a long-lived owner holding many open resources makes the
  ;; region correspondingly long. That is the price of the read-modify-
  ;; write being atomic, and it is named here rather than hidden: the
  ;; bound is the length of that owner's index list. ⚠ That list is a
  ;; SUPERSET of what the owner still holds -- a resource handed to
  ;; another owner leaves its entry behind on purpose, see the note at
  ;; conn-set-owner! -- so it is not exactly "open resources", only
  ;; bounded by what removal has not yet reached.
  (define (unindex-owner! owner kind key)
    (when owner
      (with-interrupts-disabled
      (let ((xs (hashtable-ref owner-index owner '())))
        (unless (null? xs)
          (let ((rest (remp (lambda (e)
                              (and (eq? (car e) kind) (equal? (cdr e) key)))
                            xs)))
            (if (null? rest)
                (hashtable-delete! owner-index owner)
                (hashtable-set! owner-index owner rest))))))))

  ;; Ownership is public and mutable -- an application hands a conn to the
  ;; process that will read it, and may hand it on again. The index has to
  ;; learn about every such move, so the setter is the hook rather than the
  ;; raw record field. The old owner's entry is left behind on purpose: it
  ;; becomes a stale candidate, which costs one failed re-check, whereas
  ;; forgetting to add the new one would skip a live resource at teardown.
  ;; The field and the index entry are ONE step. A safe point between them
  ;; is a window in which the new owner can die: uv-owner-died! for that pid
  ;; then finds no entry and skips the resource, and the entry that arrives
  ;; afterwards names a process already gone -- nothing will ever reclaim
  ;; it. Same family as the enqueue-write! and conn-on-close! windows.
  (define (conn-set-owner! c owner)
    (with-interrupts-disabled
      (conn-set-owner-field! c owner)
      (index-owner! owner 'conn (conn-handle c))))

  ;; Reclaim what a dead owner can no longer close itself. A killed
  ;; process does not run its dynamic-wind winders (see actor.sc @kill),
  ;; so a handler killed mid-download would otherwise leak its open fd,
  ;; its 256 KiB foreign chunk buffer and the uv_fs_t for the life of
  ;; the VM -- fs-table roots them, so the GC cannot help. The actor
  ;; layer calls this from its process-teardown path.
  (define (uv-owner-died! owner)
    (with-interrupts-disabled
      (let ((owned (hashtable-ref owner-index owner '())))
        (hashtable-delete! owner-index owner)
        (for-each
          (lambda (entry)
            (let ((kind (car entry)) (key (cdr entry)))
              (case kind
                ;; conn-table is the GC root for both the Scheme record and
                ;; the libuv handle, so leaving one here leaks an fd for the
                ;; lifetime of the VM. Re-check the owner: the index may name
                ;; a conn this process handed on to someone else.
                ((conn)
                 (let ((c (hashtable-ref conn-table key #f)))
                   (when (and c (eq? (conn-owner c) owner)) (tcp-close! c))))
                ;; A DESCRIPTOR THE DEAD PROCESS STILL HELD. The write
                ;; side hands fds back to the caller and takes them again
                ;; one syscall at a time, so a process that dies between
                ;; two of its own calls leaves one open with nobody left
                ;; to close it. Closed synchronously here: the fd is
                ;; already ours to release and there is no one to tell.
                ;;
                ;; IT IS A RESOURCE BACKSTOP, NOT A TRANSACTION. What the
                ;; descriptor pointed at may be a half-written file, and
                ;; that is left exactly as it lies -- nothing here
                ;; truncates, deletes or rolls anything back. Reconciling
                ;; a partial write is the caller's protocol, and reading
                ;; this as "the framework tidied up" would be reading it
                ;; as the one thing it does not do.
                ((fsfd)
                 (let ((e (hashtable-ref fsw-fds key #f)))
                   (when (and e (eq? (car e) owner))
                     (let ((gen (cdr e)))
                     (hashtable-delete! fsw-fds key)
                     ;; A RECLAIM MUST COME AFTER THE LAST JOB THAT NAMES
                     ;; IT, or what gets closed is a NUMBER and not a
                     ;; file. A job already handed to the pool has not
                     ;; necessarily entered its syscall yet: close the
                     ;; descriptor here and the number can be reissued to
                     ;; something else before that thread runs, at which
                     ;; point a late write lands in an unrelated file and
                     ;; a late close shuts one. Owner death does not
                     ;; cancel jobs -- it only stops their answers being
                     ;; delivered -- so the wait is real and has to be
                     ;; waited out.
                     ;;
                     ;; THIS COVERS THE CLOSES THIS LIBRARY ISSUES -- the
                     ;; reclaim here and the orphaned-open return -- and
                     ;; not a close the CALLER submits. Ordering its own
                     ;; close after its own outstanding jobs on the same
                     ;; descriptor is the caller's, exactly as it is in C:
                     ;; one thread writing a descriptor while another
                     ;; closes it races the same reissue, and no
                     ;; descriptor API promises otherwise. (igropyr
                     ;; durable-async) is the worked example -- it keeps
                     ;; one job in flight at a time, so the question never
                     ;; arises for it.
                     (if (fd-in-flight? key)
                         (hashtable-set! fsw-closing key gen)
                         (close-fd-now! key))))))
                ;; An in-flight job: the callback is still coming and
                ;; still has to free the request, so only the delivery is
                ;; suppressed. Clearing the owner is what does that --
                ;; the callback checks it before delivering. Deleting the
                ;; entry instead would lose the record that this request
                ;; is outstanding.
                ((fsjob)
                 (let ((j (hashtable-ref fsw-table key #f)))
                   (when (and j (eq? (fsw-job-owner j) owner))
                     (fsw-job-owner-set! j #f))))
                ;; A connect request cannot be synchronously cancelled on
                ;; every supported libuv. Clear its owner instead; on-connect
                ;; then closes a late successful handle rather than
                ;; registering it for a dead pid.
                ((connect)
                 (let ((e (hashtable-ref connect-table key #f)))
                   (when (and e (eq? (cdr e) owner)) (set-cdr! e #f))))
                ;; DNS has no handle to close. Suppress its eventual delivery
                ;; while RETAINING the request entry so the callback still
                ;; frees it. Do NOT "simplify" this into a hashtable-delete!:
                ;; on-getaddrinfo runs either way and does the foreign-free,
                ;; so dropping the key here only loses the record that this
                ;; request is still outstanding. Setting #f is safe because
                ;; both delivery sites are guarded by (when owner ...).
                ((dns)
                 (when (eq? (hashtable-ref getaddrinfo-table key #f) owner)
                   (hashtable-set! getaddrinfo-table key #f)))
                ;; an fs op holds an open fd, a 256 KiB foreign chunk buffer
                ;; and the uv_fs_t; fs-table roots them, so the GC cannot help
                ((fs)
                 (let ((op (hashtable-ref fs-table key #f)))
                   (when (and op (eq? (fs-op-owner op) owner))
                     (file-stream-close! op))))
                (else (void)))))
          owned))))

  ;; live listeners: handle address -> #(token on-accept), one entry per
  ;; tcp-listen!. Keyed dispatch (not a single global) so several
  ;; servers can listen on different ports in one process; the table
  ;; also roots each listener's accept hook, which nothing else holds
  ;; (the handles themselves are foreign-alloc'd and are not the GC's
  ;; business).
  (define listener-table (make-eqv-hashtable))

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

  ;; ---- callbacks ----------------------------------------------------

  ;; alloc_cb: hand libuv one shared static buffer. Safe because libuv
  ;; is single-threaded and calls alloc_cb immediately before each
  ;; read_cb; the data is copied out before the next read.
  (define on-alloc-code
    (foreign-callable
      (lambda (handle suggested buf)
        (foreign-set! 'void* buf 0 read-buf)
        (foreign-set! 'unsigned-64 buf 8 read-buf-size))
      (void* size_t void*)
      void))

  ;; read_cb: copy bytes into a fresh bytevector and deliver to the
  ;; connection's owner process. Errors/EOF are delivered as messages,
  ;; never raised.
  (define on-read-code
    (foreign-callable
      (lambda (stream nread buf)
        (let ((c (hashtable-ref conn-table stream #f)))
          (when (and c (conn-owner c))
            (cond
              ((> nread 0)
               (let ((bv (make-bytevector nread)))
                 (memcpy-from-c bv (foreign-ref 'void* buf 0) nread)
                 (deliver (conn-owner c) (vector 'tcp-data bv))))
              ((= nread 0) (void))   ; spurious wakeup; ignore
              ((= nread UV-EOF)
               (deliver (conn-owner c) (vector 'tcp-eof)))
              (else
               (deliver (conn-owner c) (vector 'tcp-error nread)))))))
      (void* ssize_t void*)
      void))

  ;; close_cb: the single place where handle memory is freed.
  (define on-close-code
    (foreign-callable
      (lambda (handle)
        (let ((c (hashtable-ref conn-table handle #f)))
          (hashtable-delete! conn-table handle)
          (when c
            (unindex-owner! (conn-owner c) 'conn handle)
            (conn-set-state! c 'closed)
            (let ((clean (conn-cleanup c)))
              (when clean
                (conn-set-cleanup! c #f)
                ;; callback context: an escaping raise would unwind into C
                (guard (e (#t (void))) (clean))))))
        (foreign-free handle))
      (void*)
      void))

  ;; write_cb: run the stored completion closure, free the whole
  ;; [uv_write_t][uv_buf_t][payload] block in one shot.
  (define on-write-code
    (foreign-callable
      (lambda (req status)
        (let ((done (hashtable-ref write-table req #f)))
          (hashtable-delete! write-table req)
          (foreign-free req)
          (when done (done status))))
      (void* int)
      void))

  ;; connection_cb: accept, register, hand the conn to the upper layer.
  ;; Accept errors are swallowed; the listener must stay alive.
  ;; Accept failures, counted rather than logged. Two of them, because
  ;; they mean different things: `error` is the listener callback being
  ;; handed a negative status by libuv; `refused` is uv_accept declining
  ;; a connection that was already announced.
  ;;
  ;; ⭐ COUNTED BECAUSE THE ALTERNATIVE WAS NOTHING AT ALL. Both branches
  ;; discard silently -- correctly, since the listener has to stay alive
  ;; -- so a server dropping every arrival looked exactly like a server
  ;; nobody was calling. The kernel counts what it refuses itself; this
  ;; is the half that happens after the kernel handed the connection up.
  ;;
  ;; ⚠ SATURATING, NOT WRAPPING. A wrapped counter reports a small number
  ;; after a large failure, and small numbers are the ones that get
  ;; ignored; at the ceiling this one stops moving instead, which is
  ;; "at least this many".
  ;;
  ;; ⛔ THAT IS STILL A LOSS, AND IN A MISLEADING DIRECTION: an observer
  ;; watching deltas sees a saturated counter stop changing and can read
  ;; that as recovery. Saturation is chosen because the alternative is
  ;; worse, not because it is safe.
  (define accept-error-count 0)
  (define accept-refused-count 0)
  (define (bump-saturating n)
    (if (fx< n (greatest-fixnum)) (fx+ n 1) n))
  ;; ⚠ BOTH VALUES ARE READ IN ONE REGION, then the list is built
  ;; outside it. Reading them across the allocations of the list would
  ;; let a bump land in between, so the pair returned could pair an old
  ;; error count with a new refused count -- a combination that never
  ;; existed. Individual fixnums are never torn; it is the PAIR that
  ;; needs the region, and callers comparing deltas are exactly who
  ;; would be misled.
  (define (uv-accept-failure-counts)
    (let-values (((e r) (with-interrupts-disabled
                          (values accept-error-count
                                  accept-refused-count))))
      (list (cons 'error e) (cons 'refused r))))

  (define on-connection-code
    (foreign-callable
      (lambda (server status)
        (if (< status 0)
            ;; ⚠ NO CELL COVERS THIS BRANCH. Making libuv hand a negative
            ;; status to a listener callback needs a condition this suite
            ;; cannot create; the counter is here so it is visible if it
            ;; happens in the field, and it is recorded as uncovered
            ;; rather than counted as tested.
            ;;
            ;; It is not the same event as a refusal: this is the accept
            ;; itself having failed, possibly before the kernel had a
            ;; connection to hand up at all, which is why the two are
            ;; counted separately.
            (set! accept-error-count (bump-saturating accept-error-count))
            (let ((client (foreign-alloc tcp-handle-size)))
              (uv-tcp-init uv-loop client)
              ;; INJECTION POINT 'accept-refused -- OWNING GUARD: none in
              ;; this callback, and none may be added: it runs in foreign
              ;; callback context, where an escaping raise unwinds into C.
              ;; The injected value is a return rather than a raise, so it
              ;; takes the refusal branch as a real failure would.
              ;;
              ;; ⛔ OVERRIDE, NOT RETURN, AND THE DIFFERENCE IS THE WHOLE
              ;; POINT HERE. uv_accept must actually RUN. libuv's
              ;; uv__server_io accept()s into server->accepted_fd before
              ;; calling this callback, and if the callback returns
              ;; without consuming it, uv__io_stop removes the listener
              ;; from the poll set -- permanently. A real uv_accept
              ;; failure closes that fd and calls uv__io_start, so the
              ;; listener survives one refusal. Skipping the call
              ;; therefore does not simulate a refusal; it simulates a
              ;; dead listener, which is a different defect wearing the
              ;; same errno. Measured: with inject-return! here, the cell
              ;; saw the second connection never accepted.
              ;;
              ;; What override leaves behind was checked and is clean: the
              ;; real accepted socket is closed by uv-close, its block is
              ;; freed by the close callback, no conn is built, and
              ;; neither conn-table nor owner-index gains an entry. ⚠ The
              ;; timing differs from a real failure -- which closes the
              ;; descriptor inside uv_accept rather than attaching it to a
              ;; handle first -- but nothing persistent is left.
              (if (< (inject-override! 'accept-refused
                                       (uv-accept server client)) 0)
                  (begin
                    (set! accept-refused-count
                          (bump-saturating accept-refused-count))
                    (uv-close client on-close-entry))
                (let ((c (make-conn client #f 'open #f))
                      ;; #(token on-accept) -- see tcp-listen!
                      (v (hashtable-ref listener-table server #f)))
                  (uv-tcp-nodelay client 1)
                  (hashtable-set! conn-table client c)
                  (if v
                      ((vector-ref v 1) c)
                      ;; listener already stopped: refuse the straggler
                      (tcp-close! c)))))))
      (void* int)
      void))

  ;; walk the addrinfo linked list, return the first IPv4 as "a.b.c.d".
  ;; Supported LP64 addrinfo layouts share ai_family @ 4 and ai_next @ 40;
  ;; ai_addr is selected by (igropyr platform). sockaddr_in.sin_addr @ 4.
  (define AF-INET 2)
  (define (addrinfo->ipv4 ai)
    (let loop ((ai ai))
      (if (= ai 0)
          #f
          (if (= (foreign-ref 'int ai 4) AF-INET)
              (let ((sa (foreign-ref 'void* ai addrinfo-address-offset)))
                (string-append
                  (number->string (foreign-ref 'unsigned-8 sa 4)) "."
                  (number->string (foreign-ref 'unsigned-8 sa 5)) "."
                  (number->string (foreign-ref 'unsigned-8 sa 6)) "."
                  (number->string (foreign-ref 'unsigned-8 sa 7))))
              (loop (foreign-ref 'void* ai addrinfo-next-offset))))))

  ;; Async file reads as an open -> fstat -> bounded read -> close
  ;; chain, all on libuv's thread pool. Two modes share the machinery:
  ;;   whole  -- accumulate every chunk, deliver #(file-read ,body) once
  ;;             (file-read-async!)
  ;;   stream -- deliver one #(file-chunk ,bv) per read and park until
  ;;             the consumer pulls again (file-stream-read!): flow
  ;;             control is the consumer's write pace, so a large file
  ;;             is served in constant memory (one chunk in flight).
  ;;             With file-stream-raw! the chunk STAYS in the op's C
  ;;             buffer and only its length is delivered -- the consumer
  ;;             sends it with tcp-write-foreign! (buffer -> kernel, no
  ;;             per-chunk Scheme allocation, no GC traffic).
  (define file-read-chunk-size 65536)
  ;; stream reads use bigger chunks: fewer thread-pool round trips per
  ;; GB; memory per in-flight download is still just one chunk
  (define stream-chunk-size 262144)

  (define-record-type (fs-op make-fs-op fs-op?)
    (fields
      (mutable owner fs-op-owner fs-op-owner-set!)   ; delivery target pid
      (immutable path fs-op-path)
      (immutable mode fs-op-mode)                    ; whole | stream
      ;; ⚠ MUTABLE ONLY SO IT CAN BE FILLED IN AFTER THE ALLOCATION. The
      ;; record is built with req = #f and the foreign-alloc happens a
      ;; few lines later -- both inside the region now; see fs-start!.
      ;; Nothing else ever writes it, and it is set exactly once, before
      ;; the op is published anywhere.
      (mutable req fs-op-req fs-op-req-set!)         ; uv_fs_t address
      (mutable phase fs-op-phase fs-op-phase-set!)   ; open|fstat|idle|read|close
      (mutable aborted? fs-op-aborted? fs-op-aborted?-set!)
      (mutable raw? fs-op-raw? fs-op-raw?-set!)      ; deliver lengths, not bvs
      (mutable fd fs-op-fd fs-op-fd-set!)
      (mutable size fs-op-size fs-op-size-set!)
      (mutable offset fs-op-offset fs-op-offset-set!)
      (mutable chunks fs-op-chunks fs-op-chunks-set!)
      (mutable data fs-op-data fs-op-data-set!)       ; C read buffer
      (mutable buf fs-op-buf fs-op-buf-set!)))         ; uv_buf_t

  (define (fs-chunk-cap op)
    (if (eq? (fs-op-mode op) 'stream) stream-chunk-size file-read-chunk-size))

  (define (fs-body op)
    (let ((out (make-bytevector (fs-op-offset op))))
      (let loop ((xs (reverse (fs-op-chunks op))) (off 0))
        (unless (null? xs)
          (let ((bv (car xs)))
            (bytevector-copy! bv 0 out off (bytevector-length bv))
            (loop (cdr xs) (+ off (bytevector-length bv))))))
      out))

  (define (fs-cleanup! op req)
    (when (> (fs-op-data op) 0) (foreign-free (fs-op-data op)))
    (when (> (fs-op-buf op) 0) (foreign-free (fs-op-buf op)))
    (unindex-owner! (fs-op-owner op) 'fs req)
    (hashtable-delete! fs-table req)
    (foreign-free req))

  (define (fs-fail! op req errno)
    ;; if a fd is open, close it (fire-and-forget) before reporting
    (when (>= (fs-op-fd op) 0)
      (let ((creq (foreign-alloc fs-req-size)))
        (uv-fs-close uv-loop creq (fs-op-fd op) 0)   ; sync close, ignore
        (uv-fs-req-cleanup creq)
        (foreign-free creq)))
    (deliver (fs-op-owner op) (vector 'file-error errno))
    (fs-cleanup! op req))

  (define (regular-file-mode? mode)
    (= (bitwise-and mode S-IFMT) S-IFREG))

  ;; Deliver the completion and release the op. Reached only after
  ;; every read completed, so a close error (rare; e.g. NFS) must not
  ;; discard the data -- success is reported regardless of how close
  ;; went. whole mode reports the accumulated body; stream mode reports
  ;; end-of-stream; an aborted stream reports nothing.
  (define (fs-finish! op req)
    (unless (fs-op-aborted? op)
      (deliver (fs-op-owner op)
        (if (eq? (fs-op-mode op) 'stream)
            (vector 'file-eof)
            (vector 'file-read (fs-body op)))))
    (fs-cleanup! op req))

  ;; Release an aborted stream: close the fd (if open) reusing the op's
  ;; req, then free everything. Nothing is delivered.
  (define (fs-quiet-close! op req)
    (if (< (fs-op-fd op) 0)
        (fs-cleanup! op req)
        (begin
          (fs-op-phase-set! op 'close)
          (let ((r (uv-fs-close uv-loop req (fs-op-fd op) on-fs-entry)))
            (when (< r 0)
              (uv-fs-req-cleanup req)
              (let ((creq (foreign-alloc fs-req-size)))
                (uv-fs-close uv-loop creq (fs-op-fd op) 0)   ; sync close
                (uv-fs-req-cleanup creq)
                (foreign-free creq))
              (fs-cleanup! op req))))))

  ;; A callback fired on a stream that was aborted while the op was in
  ;; flight: unwind quietly whatever phase it was in.
  (define (fs-abort-step! op req result)
    (uv-fs-req-cleanup req)
    (case (fs-op-phase op)
      ((close) (fs-cleanup! op req))
      ((open)
       (when (>= result 0) (fs-op-fd-set! op result))
       (fs-quiet-close! op req))
      (else (fs-quiet-close! op req))))

  (define (start-fs-close! op req)
    (fs-op-phase-set! op 'close)
    (let ((r (uv-fs-close uv-loop req (fs-op-fd op) on-fs-entry)))
      (when (< r 0)
        ;; could not queue the close: close synchronously instead, and
        ;; still deliver -- the data was fully read before this point
        (uv-fs-req-cleanup req)
        (let ((creq (foreign-alloc fs-req-size)))
          (uv-fs-close uv-loop creq (fs-op-fd op) 0)   ; sync close, ignore
          (uv-fs-req-cleanup creq)
          (foreign-free creq))
        (fs-finish! op req))))

  (define (start-fs-fstat! op req)
    (fs-op-phase-set! op 'fstat)
    (let ((r (uv-fs-fstat uv-loop req (fs-op-fd op) on-fs-entry)))
      (when (< r 0)
        (uv-fs-req-cleanup req)
        (fs-fail! op req r))))

  (define (start-fs-read! op req)
    (let ((remaining (- (fs-op-size op) (fs-op-offset op))))
      (if (<= remaining 0)
          (start-fs-close! op req)
          (let ((n (min (fs-chunk-cap op) remaining)))
            (fs-op-phase-set! op 'read)
            (foreign-set! 'unsigned-64 (fs-op-buf op) 8 n)
            (let ((r (uv-fs-read uv-loop req (fs-op-fd op) (fs-op-buf op) 1
                                 (fs-op-offset op) on-fs-entry)))
              (when (< r 0)
                (uv-fs-req-cleanup req)
                (fs-fail! op req r)))))))

  (define on-fs-code
    (foreign-callable
      (lambda (req)
        (let ((op (hashtable-ref fs-table req #f))
              (result (uv-fs-get-result req)))
          (when op
            (if (fs-op-aborted? op)
                (fs-abort-step! op req result)
                (case (fs-op-phase op)
                  ((open)
                   (uv-fs-req-cleanup req)
                   (if (< result 0)
                       (fs-fail! op req result)
                       (begin
                         (fs-op-fd-set! op result)
                         (start-fs-fstat! op req))))
                  ((fstat)
                   (if (< result 0)
                       (begin
                         (uv-fs-req-cleanup req)
                         (fs-fail! op req result))
                       (let* ((st (uv-fs-get-statbuf req))
                              (mode (foreign-ref 'unsigned-64 st uv-stat-mode-offset))
                              (size (foreign-ref 'unsigned-64 st uv-stat-size-offset)))
                         (uv-fs-req-cleanup req)
                         (fs-op-size-set! op size)
                         (cond
                           ((not (regular-file-mode? mode))
                            (fs-fail! op req UV-EINVAL))
                           ((eq? (fs-op-mode op) 'stream)
                            ;; ready: report the size, then park until the
                            ;; consumer pulls the first chunk
                            (when (> size 0)
                              (let* ((data (foreign-alloc (fs-chunk-cap op)))
                                     (buf (foreign-alloc 16)))
                                (fs-op-data-set! op data)
                                (fs-op-buf-set! op buf)
                                (foreign-set! 'void* buf 0 data)))
                            (fs-op-phase-set! op 'idle)
                            (deliver (fs-op-owner op)
                                     (vector 'file-stream op size)))
                           ((= size 0)
                            (start-fs-close! op req))
                           (else
                            (let* ((data (foreign-alloc (fs-chunk-cap op)))
                                   (buf (foreign-alloc 16)))
                              (fs-op-data-set! op data)
                              (fs-op-buf-set! op buf)
                              (foreign-set! 'void* buf 0 data)
                              (start-fs-read! op req)))))))
                  ((read)
                   (uv-fs-req-cleanup req)
                   (cond
                     ((< result 0) (fs-fail! op req result))
                     ((= result 0) (start-fs-close! op req))   ; early EOF
                     (else
                      (let* ((remaining (- (fs-op-size op) (fs-op-offset op)))
                             (n (min result remaining)))
                        (fs-op-offset-set! op (+ (fs-op-offset op) n))
                        (cond
                          ((fs-op-raw? op)
                           ;; the bytes stay in the op's C buffer; hand
                           ;; over just the length -- the consumer writes
                           ;; straight from the buffer, zero Scheme alloc
                           (fs-op-phase-set! op 'idle)
                           (deliver (fs-op-owner op) (vector 'file-chunk n)))
                          ((eq? (fs-op-mode op) 'stream)
                           ;; hand over one chunk; the next read waits
                           ;; for the consumer's file-stream-read!
                           (let ((bv (make-bytevector n)))
                             (memcpy-from-c bv (fs-op-data op) n)
                             (fs-op-phase-set! op 'idle)
                             (deliver (fs-op-owner op) (vector 'file-chunk bv))))
                          (else
                           (let ((bv (make-bytevector n)))
                             (memcpy-from-c bv (fs-op-data op) n)
                             (fs-op-chunks-set! op (cons bv (fs-op-chunks op)))
                             (if (>= (fs-op-offset op) (fs-op-size op))
                                 (start-fs-close! op req)
                                 (start-fs-read! op req)))))))))
                  ((close)
                   (uv-fs-req-cleanup req)
                   (fs-finish! op req)))))))
      (void*)
      void))

  ;; getaddrinfo_cb: tell the owner #(dns-resolved ,ip) or #(dns-failed ,e)
  (define on-getaddrinfo-code
    (foreign-callable
      (lambda (req status ai)
        (let ((owner (hashtable-ref getaddrinfo-table req #f)))
          (hashtable-delete! getaddrinfo-table req)
          ;; THE OTHER HALF OF dns-resolve!'s index-owner!, and this is
          ;; one of TWO places that owe it -- see the submission for the
          ;; other. A no-op when owner is #f: uv-owner-died! cleared it
          ;; and deleted that owner's whole index list in the same step,
          ;; so there is nothing left to remove. That is not the same
          ;; question as the getaddrinfo-table entry a few lines up,
          ;; which is deliberately RETAINED for a dead owner because this
          ;; callback still has to free the request.
          ;; ⛔ THE FREE BELOW IS MANDATORY AND THIS CALL CAN RAISE.
          ;; unindex-owner! filters the owner's list with remp, so it
          ;; allocates. Unguarded it would skip the free -- and, in a
          ;; foreign callback, unwind into C; the same rule and the same
          ;; shape as the close callback above. Swallowing is the lesser
          ;; residue: a stale index entry costs growth, which
          ;; uv-owner-index-count reports, while the alternatives cost a
          ;; foreign block that nothing will ever free again.
          ;;
          ;; ⚠ IT MUST STAY BEFORE THE FREE, not after. The key IS the
          ;; freed pointer: once the block is returned, the same address
          ;; can be handed to the next getaddrinfo request, and a removal
          ;; running then would delete that request's registration
          ;; instead of this one's.
          (guard (e (#t (void))) (unindex-owner! owner 'dns req))
          (foreign-free req)
          (if (< status 0)
              (when owner (deliver owner (vector 'dns-failed status)))
              (let ((ip (addrinfo->ipv4 ai)))
                (uv-freeaddrinfo ai)
                (when owner
                  (deliver owner
                    (if ip (vector 'dns-resolved ip) (vector 'dns-failed -1))))))))
      (void* int void*)
      void))

  ;; connect_cb for outbound connections: register the conn and tell the
  ;; owner process #(tcp-connected ,conn) or #(tcp-connect-failed ,errno).
  (define on-connect-code
    (foreign-callable
      (lambda (req status)
        (let ((entry (hashtable-ref connect-table req #f)))
          (hashtable-delete! connect-table req)
          ;; THE OTHER HALF OF index-owner!. Registering the request
          ;; against its owner and never taking it back left one entry
          ;; per connect on that owner's list, for the life of the
          ;; process -- a connector that reconnects on a timer grows it
          ;; without bound, and teardown walks all of it. There is no
          ;; symptom before that: the entry names a request that is
          ;; gone, and the teardown branch for it looks the request up
          ;; and finds nothing. A missing entry is silent, and so is a
          ;; surplus one.
          ;;
          ;; #f owner means uv-owner-died! already emptied that owner's
          ;; list, so there is nothing left to remove.
          (when (and entry (cdr entry))
            (unindex-owner! (cdr entry) 'connect req))
          (foreign-free req)
          (when entry
            (let ((handle (car entry)) (owner (cdr entry)))
              (cond
                ((< status 0)
                 (uv-close handle on-close-entry)
                 (when owner (deliver owner (vector 'tcp-connect-failed status))))
                ((not owner)
                 ;; The owner died while connect was in flight.
                 (uv-close handle on-close-entry))
                (else
                 (let ((c (make-conn handle owner 'open #f)))
                   ;; index and table together: an owner dying between them
                   ;; is told about a conn that teardown cannot find
                   (with-interrupts-disabled
                     (index-owner! owner 'conn handle)
                     (uv-tcp-nodelay handle 1)
                     (hashtable-set! conn-table handle c))
                   (deliver owner (vector 'tcp-connected c)))))))))
      (void* int)
      void))

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

  ;; Lock the callback code objects forever: libuv holds raw entry-point
  ;; pointers into them for the whole process lifetime.

  ;; ---- fs write side: one syscall per job -------------------------------
  ;;
  ;; DELIBERATELY NOT THE SHAPE OF THE READ SIDE ABOVE. That one hides a
  ;; composite sequence -- open, fstat, read, close -- behind a phase
  ;; machine and delivers once at the end, which is right when the library
  ;; owns the whole sequence. Here the caller owns it: a durable write is
  ;; write, flush, rename, flush the directory, and which of those to do,
  ;; in what order, and what to do when one fails are the caller's
  ;; decisions. So each job is one syscall, and the caller awaits them in
  ;; its own green process.
  ;;
  ;; WHAT THIS BUYS is the only reason it exists: the syscall runs on a
  ;; libuv thread-pool thread, so the scheduler keeps running. The
  ;; synchronous equivalents stop every green process in the runtime for
  ;; the duration -- measured elsewhere in this tree at 641ms for one
  ;; call on a busy filesystem.
  ;;
  ;; THE POOL IS SHARED AND SMALL. Four threads by default, shared with
  ;; DNS, and UV_THREADPOOL_SIZE is read once when the pool is first used
  ;; -- so it must be set in the environment before the process starts,
  ;; not from inside it. Enough concurrent file jobs will queue behind
  ;; each other and behind name resolution.
  ;;
  ;; The sequence a durable write needs is plain POSIX. ZFS honours it
  ;; with stronger semantics rather than weaker (the flush goes through
  ;; the intent log, rename is transactional, and the directory flush
  ;; degrades to a harmless no-op), so nothing here probes for a
  ;; filesystem or branches on one.
  (define fsw-table (make-eqv-hashtable))

  ;; fd -> (owner . gen), for the death cleanup below -- the pair, not a
  ;; bare owner; the generation note further down says why. A descriptor
  ;; opened here
  ;; belongs to the caller between calls, which is what "one syscall per
  ;; job" means -- and a caller that dies holding one would otherwise
  ;; leak it with no signal at all. That silent shape is the one this
  ;; library keeps removing; it is not going to be reintroduced by a new
  ;; entry point.
  ;; fd -> (owner . gen); see the generation note further down for why
  ;; the owner alone is not enough to identify a descriptor.
  (define fsw-fds (make-eqv-hashtable))

  (define fsw-next-id 0)

  (define (fsw-fresh-id!)
    (set! fsw-next-id (+ fsw-next-id 1))
    fsw-next-id)

  (define-record-type (fsw-job make-fsw-job fsw-job?)
    (fields
      (immutable id fsw-job-id)
      (mutable owner fsw-job-owner fsw-job-owner-set!)
      (immutable kind fsw-job-kind)         ; open|write|fsync|rename|close
      (immutable fd fsw-job-fd)             ; the fd acted on, or -1
      ;; WHICH TENANCY OF THAT NUMBER THIS JOB MEANT. Captured when the
      ;; job is submitted; see the generation note below.
      (mutable gen fsw-job-gen fsw-job-gen-set!)
      (mutable data fsw-job-data fsw-job-data-set!)   ; C copy of the bytes
      (mutable buf fsw-job-buf fsw-job-buf-set!)))    ; uv_buf_t

  (define (fsw-count) (hashtable-size fsw-table))
  (define (fs-job-count) (fsw-count))

  ;; HOW MANY DESCRIPTORS THIS SIDE IS HOLDING FOR CALLERS. Without it
  ;; the death cleanup above is code that was reviewed rather than
  ;; behaviour that is watched: a test can kill a process holding an fd,
  ;; but with nothing to read it cannot tell a close that happened from
  ;; one that did not. Approximate in the same sense as the job count --
  ;; it is read outside any lock and a job in flight may be about to
  ;; change it.
  (define (fs-fd-count) (hashtable-size fsw-fds))

  ;; Hand a descriptor back to the kernel with no owner to tell. Used
  ;; both when an owner dies and when one dies before its open finishes.
  ;; ITS RESULT IS NOT READ, and its callers say "closed" on the
  ;; strength of that. If this close fails and the OS still holds the
  ;; descriptor, it is now off every book here and nothing will reclaim
  ;; it -- the same unrepairable leak the asynchronous close branch
  ;; already admits to, reached a different way. Retrying is not the
  ;; repair: POSIX leaves the descriptor's state unspecified after a
  ;; failed close, so a second attempt can reach a number that has since
  ;; been reissued.
  (define (close-fd-now! fd)
    (let ((creq (foreign-alloc fs-req-size)))
      (uv-fs-close uv-loop creq fd 0)
      (uv-fs-req-cleanup creq)
      (foreign-free creq)))

  ;; Descriptors whose owner has died while a job still refers to them.
  ;; See uv-owner-died!: closing one while a pool thread is about to act
  ;; on it closes a NUMBER, not a file.
  (define fsw-closing (make-eqv-hashtable))

  ;; HOW MANY IN-FLIGHT JOBS NAME EACH DESCRIPTOR. Counted rather than
  ;; searched: the question is asked once per descriptor when an owner
  ;; dies and again on every completion of a job that named a marked one,
  ;; and a scan of the whole job table each time is quadratic in the
  ;; queue. That work would happen inside owner teardown and inside
  ;; event-loop callbacks -- both places where nothing else in the
  ;; runtime can run -- so a deep queue would turn a bookkeeping question
  ;; into a pause.
  ;; A FILE DESCRIPTOR NUMBER IS A LEASE FROM THE OS, NOT AN IDENTITY.
  ;; The kernel reissues the smallest free number, so the same integer
  ;; names a different file the moment one is closed. Anything of ours
  ;; keyed only by that integer will eventually be asked about a tenancy
  ;; it was not talking about -- a close callback arriving after the
  ;; number has been handed to a new open would strike that new
  ;; registration off the books, and the descriptor it belongs to could
  ;; then never be reclaimed.
  ;;
  ;; So identity here is the number PLUS a generation: fsw-fds holds
  ;; (owner . gen), and each job captures the generation current when it
  ;; was submitted.
  ;;
  ;; WHAT EVERY REMOVAL SITE HAS IN COMMON is the intent -- establish
  ;; that the entry on the books is the one this code is talking about
  ;; before touching it. WHAT DIFFERS is the test, because they are
  ;; answering different questions:
  ;;
  ;;   a completion that arrives late  compares the GENERATION
  ;;                                   -- "is this still the tenancy I
  ;;                                      acted on?"
  ;;   the owner-death reclaim         compares the OWNER
  ;;                                   -- "is this descriptor mine to
  ;;                                      take back?", which a
  ;;                                      generation cannot answer
  ;;
  ;; Stating it as one uniform rule was the earlier wording here, and it
  ;; was wrong about the reclaim; the intent is shared, the test is not.
  ;; None of this reaches the public surface -- the primitives still take
  ;; and return plain descriptors.
  (define fsw-gen 0)
  (define (fsw-next-gen!)
    (set! fsw-gen (+ fsw-gen 1))
    fsw-gen)

  (define (fd-gen fd)
    (let ((e (hashtable-ref fsw-fds fd #f)))
      (and e (cdr e))))

  (define fsw-fd-refs (make-eqv-hashtable))

  (define (fd-ref+! fd)
    (when (>= fd 0)
      (hashtable-set! fsw-fd-refs fd (+ 1 (hashtable-ref fsw-fd-refs fd 0)))))

  (define (fd-ref-! fd)
    (when (>= fd 0)
      (let ((n (- (hashtable-ref fsw-fd-refs fd 0) 1)))
        (if (<= n 0)
            (hashtable-delete! fsw-fd-refs fd)
            (hashtable-set! fsw-fd-refs fd n)))))

  (define (fd-in-flight? fd)
    (> (hashtable-ref fsw-fd-refs fd 0) 0))

  ;; Called once a job has been removed from the table: if it was the
  ;; last one holding a descriptor that was waiting to be closed, this is
  ;; the moment the close is finally safe.
  (define (close-if-drained! fd gen)
    (let ((marked (and (>= fd 0) (hashtable-ref fsw-closing fd #f))))
      (when (and marked (eqv? marked gen) (not (fd-in-flight? fd)))
        (hashtable-delete! fsw-closing fd)
        (close-fd-now! fd))))

  (define (fsw-free! job req)
    (fd-ref-! (fsw-job-fd job))
    (when (> (fsw-job-data job) 0) (foreign-free (fsw-job-data job)))
    (when (> (fsw-job-buf job) 0) (foreign-free (fsw-job-buf job)))
    (unindex-owner! (fsw-job-owner job) 'fsjob req)
    (hashtable-delete! fsw-table req)
    (uv-fs-req-cleanup req)
    (foreign-free req))

  ;; A job whose owner died is completed and dropped rather than
  ;; delivered: the callback still runs, and it still has to free the
  ;; request and the copied bytes.
  (define on-fsw-code
    (foreign-callable
      (lambda (req)
        (let ((job (hashtable-ref fsw-table req #f)))
          (when job
            (let ((rc (uv-fs-get-result req))
                  (owner (fsw-job-owner job)))
              ;; an open that succeeded hands the caller a descriptor, so
              ;; it goes on the books; a close takes it off whether it
              ;; succeeded or not, for the reason spelled out on that
              ;; branch
              (case (fsw-job-kind job)
                ((open)
                 (cond
                   ((< rc 0) (void))
                   (owner
                    (hashtable-set! fsw-fds rc (cons owner (fsw-next-gen!)))
                    (index-owner! owner 'fsfd rc))
                   ;; AN OPEN THAT SUCCEEDED FOR A CALLER THAT IS GONE.
                   ;; Nobody will ever be told this descriptor exists, so
                   ;; it can never be closed by anyone: the owner sweep
                   ;; has already run and found nothing, and it is not on
                   ;; the books to be found later. The only correct thing
                   ;; to do with it is give it straight back.
                   (else (close-fd-now! rc))))
                ((close)
                 (let* ((fd (fsw-job-fd job))
                        (e (hashtable-ref fsw-fds fd #f)))
                   ;; ONLY IF THE BOOKS STILL MEAN THE FILE WE CLOSED.
                   ;; A callback that arrives after the number has been
                   ;; reissued would otherwise strike off a registration
                   ;; belonging to a live owner, whose descriptor could
                   ;; then never be reclaimed.
                   (when (and e (eqv? (cdr e) (fsw-job-gen job)))
                     (hashtable-delete! fsw-fds fd)
                     (unindex-owner! owner 'fsfd fd))
                   ;; STRUCK OFF WHETHER OR NOT IT CLOSED. On success it
                   ;; is closed and anything waiting to close it must not
                   ;; close the number again. On failure POSIX leaves the
                   ;; descriptor's state unspecified, and trying again can
                   ;; reach a number that has since been reissued -- so
                   ;; there is nothing safe left to do with it either. The
                   ;; books are cleared in both cases because in neither
                   ;; case may this side touch the number again; on the
                   ;; failing one that means a descriptor the OS may still
                   ;; hold is no longer tracked, which is a real leak with
                   ;; no safe repair from here.
                   (let ((marked (hashtable-ref fsw-closing fd #f)))
                     (when (and marked (eqv? marked (fsw-job-gen job)))
                       (hashtable-delete! fsw-closing fd)))))
                (else (void)))
              (when owner
                (deliver owner (vector 'fs-done (fsw-job-id job) rc)))
              (let ((fd (fsw-job-fd job)) (gen (fsw-job-gen job)))
                (fsw-free! job req)
                ;; After the job leaves the table, so this cannot see
                ;; itself as a reason to keep waiting.
                (close-if-drained! fd gen))))))
      (void*) void))

  ;; Submit one job. The id comes back at once and names the completion;
  ;; without it two jobs from the same process would arrive as the same
  ;; message and could not be told apart.
  ;; REGISTERING AND SUBMITTING ARE ONE ACT. Between the table entry and
  ;; the call that hands the request to libuv, this process can be
  ;; preempted and killed -- and then its continuation is discarded, `go`
  ;; never runs, and no callback is ever coming for a job that is on the
  ;; books. The owner sweep finds that job, waits for a completion that
  ;; cannot arrive, and everything it names is stranded: the request, the
  ;; copied bytes, and now the descriptor too, since a job that never
  ;; completes keeps fd-in-flight? true for ever and the deferred close
  ;; is never reached. Making the pair indivisible is what stops a job
  ;; existing that nothing will finish.
  ;; WHAT THIS REGION DOES NOT COVER. The request block, and for a write
  ;; the C buffer and the byte-by-byte copy into it, are allocated by the
  ;; caller of this procedure and therefore BEFORE the region opens. A
  ;; process killed in the middle of that copy leaks exactly those
  ;; allocations: nothing has them on any book yet, and the continuation
  ;; that would free them is gone.
  ;;
  ;; Pulling them inside is not the repair it looks like. The copy is
  ;; proportional to the payload -- a 192 MiB write is tens of
  ;; milliseconds of it -- and running that with interrupts held would
  ;; stop every green process for the duration, which is the single
  ;; thing the asynchronous path exists to avoid. So the region covers
  ;; what it can cover cheaply: from the moment anything is on the books
  ;; to the moment the request is in libuv's hands. A descriptor is never
  ;; stranded by the gap, because the reference count is not incremented
  ;; until inside; what the gap can lose is C memory.
  (define (fsw-submit! owner kind fd data buf go)
    (with-interrupts-disabled
      (let* ((req (foreign-alloc fs-req-size))
             (job (make-fsw-job (fsw-fresh-id!) owner kind fd #f data buf)))
        ;; Captured here, inside the atom that registers the job: which
        ;; tenancy of this number the job meant.
        (fsw-job-gen-set! job (fd-gen fd))
        (hashtable-set! fsw-table req job)
        (index-owner! owner 'fsjob req)
        (fd-ref+! fd)
        (let ((r (guard (e (#t
                            ;; THE SUBMISSION RAISED, so no callback is
                            ;; coming for a job that is on the books.
                            ;; Releasing it here is the whole reason the
                            ;; failure paths live inside this region: an
                            ;; exception leaves the tables exactly as it
                            ;; found them, which is not something the
                            ;; region gives for free -- interrupts are
                            ;; restored on the way out, table writes are
                            ;; not.
                            (fsw-free! job req)
                            (raise e)))
                   (go req))))
          (if (< r 0)
              ;; REFUSED BEFORE IT EVER REACHED THE POOL, and released
              ;; INSIDE the region. Doing this after leaving it left a
              ;; window of exactly the kind the region was added to
              ;; close: the job was on the books, the reference was
              ;; counted, no callback was ever coming, and a caller
              ;; killed in that window discarded the continuation that
              ;; was going to clean up -- stranding the request, the
              ;; bytes, and a descriptor that could then never drain.
              (begin
                (when owner
                  (deliver owner (vector 'fs-done (fsw-job-id job) r)))
                (fsw-free! job req)
                (fsw-job-id job))
              (fsw-job-id job))))))

  (define (fs-open-async! path flags mode owner)
    (fsw-submit! owner 'open -1 0 0
      (lambda (req)
        (uv-fs-open uv-loop req path flags mode on-fsw-entry))))

  ;; THE BYTES ARE COPIED INTO C MEMORY, and that copy is not free on a
  ;; large payload. It is not avoidable: the collector may move a
  ;; bytevector, and libuv reads the buffer on a pool thread at a moment
  ;; nothing here controls.
  (define (fs-write-async! fd bytes offset owner)
    (let* ((n (bytevector-length bytes))
           (data (foreign-alloc (max n 1)))
           (buf (foreign-alloc 16)))
      (let loop ((i 0))
        (when (< i n)
          (foreign-set! 'unsigned-8 data i (bytevector-u8-ref bytes i))
          (loop (+ i 1))))
      (foreign-set! 'void* buf 0 data)
      (foreign-set! 'unsigned-64 buf 8 n)
      (fsw-submit! owner 'write fd data buf
        (lambda (req)
          (uv-fs-write uv-loop req fd buf 1 offset on-fsw-entry)))))

  (define (fs-fsync-async! fd owner)
    (fsw-submit! owner 'fsync fd 0 0
      (lambda (req) (uv-fs-fsync uv-loop req fd on-fsw-entry))))

  (define (fs-rename-async! from to owner)
    (fsw-submit! owner 'rename -1 0 0
      (lambda (req) (uv-fs-rename uv-loop req from to on-fsw-entry))))

  (define (fs-close-async! fd owner)
    (fsw-submit! owner 'close fd 0 0
      (lambda (req) (uv-fs-close uv-loop req fd on-fsw-entry))))

  ;; No fd and no buffer, like rename: the completion carries only the rc.
  ;; An existing directory comes back as -EEXIST rather than as an error
  ;; here, which is what lets a caller treat "already there" as success
  ;; without a prior stat -- and a prior stat would be a race anyway.
  (define (fs-mkdir-async! path mode owner)
    (fsw-submit! owner 'mkdir -1 0 0
      (lambda (req) (uv-fs-mkdir uv-loop req path mode on-fsw-entry))))

  (define locked-callbacks
    (begin
      (lock-object on-alloc-code)
      (lock-object on-read-code)
      (lock-object on-close-code)
      (lock-object on-write-code)
      (lock-object on-connection-code)
      (lock-object on-connect-code)
      (lock-object on-getaddrinfo-code)
      (lock-object on-fs-code)
      (lock-object on-fsw-code)
      (lock-object on-timer-code)
      (lock-object on-walk-code)
      (vector on-alloc-code on-read-code on-close-code
              on-write-code on-connection-code on-connect-code
              on-getaddrinfo-code on-fs-code on-fsw-code
              on-timer-code on-walk-code)))

  (define on-fsw-entry (foreign-callable-entry-point on-fsw-code))
  (define on-alloc-entry (foreign-callable-entry-point on-alloc-code))
  (define on-read-entry (foreign-callable-entry-point on-read-code))
  (define on-close-entry (foreign-callable-entry-point on-close-code))
  (define on-write-entry (foreign-callable-entry-point on-write-code))
  (define on-connection-entry (foreign-callable-entry-point on-connection-code))
  (define on-connect-entry (foreign-callable-entry-point on-connect-code))
  (define on-getaddrinfo-entry (foreign-callable-entry-point on-getaddrinfo-code))
  (define on-fs-entry (foreign-callable-entry-point on-fs-code))
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

  ;; ---- public API ----------------------------------------------------

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
    (if (<= timeout-ms 0)
        (uv-run uv-loop UV-RUN-NOWAIT)
        (begin
          (uv-timer-start wakeup-timer on-timer-entry timeout-ms 0)
          (uv-run uv-loop UV-RUN-ONCE)
          (uv-timer-stop wakeup-timer))))

  ;; optional trailing arg: uv_tcp_bind flags (UV_TCP_REUSEPORT = 2,
  ;; kernel-balanced multi-process listening).
  ;;
  ;; ⭐ FreeBSD IS ON THE LIST, AND IT REACHES IT BY A DIFFERENT OPTION.
  ;; This matters here more than anywhere else: every igropyr deployment
  ;; runs on FreeBSD, and a note saying "Linux only" would tell the one
  ;; audience that needs this flag that it has nothing to gain.
  ;;
  ;; libuv's own header lists Linux 3.9+, DragonFlyBSD 3.6+, FreeBSD
  ;; 12.0+, Solaris 11.4 and AIX 7.2.5+ -- and NOT macOS. On FreeBSD the
  ;; kernel option is SO_REUSEPORT_LB, not SO_REUSEPORT: a different name
  ;; with the load-balancing semantics Linux gives the plain one, which
  ;; is why the platform note has to name the option and not just the
  ;; system.
  ;;
  ;; ⚠ HOW FAR THE EVIDENCE GOES, because two different things are being
  ;; claimed and only one of them is checked here:
  ;;   - The platform list above is read from libuv's uv.h. Confirmed in
  ;;     two versions independently: 1.50.0 (locally) and 1.52.1 (the
  ;;     version installed on the deployment machines). They agree.
  ;;   - That FreeBSD's path is SO_REUSEPORT_LB is read from libuv's
  ;;     uv__sock_reuseport, in 1.52.1. NOT re-read here: this machine has
  ;;     only libuv's headers installed, not its C source.
  ;;   - ⛔ THAT IT ACTUALLY DISTRIBUTES CONNECTIONS ON OUR MACHINES HAS
  ;;     NOT BEEN OBSERVED. That needs two processes on one port and a
  ;;     load run, and nobody has done it. What is written above is what
  ;;     libuv implements, not what we have measured.
  (define (tcp-listen! host port backlog on-accept . opts)
    (with-interrupts-disabled          ; shared sockaddr-buf: see tcp-connect!
    (let ((flags (if (pair? opts) (car opts) 0))
          (l (foreign-alloc tcp-handle-size))
          (inited? #f))
      ;; EVERY ONE OF THESE FOUR CAN FAIL, and one of them fails as a
      ;; matter of routine: a bind onto a port somebody else already
      ;; holds. Without this the handle allocated above is simply
      ;; abandoned -- and once uv_tcp_init has run it is not just memory,
      ;; it is a handle registered with the loop that nothing will ever
      ;; close. A server that retries its bind leaks one per attempt.
      ;;
      ;; Which release is right depends on how far we got: before init
      ;; the block is plain memory and is freed here; after it, the
      ;; handle belongs to libuv and has to go out through uv_close,
      ;; whose callback frees the block. Getting that backwards frees
      ;; memory the loop still holds a pointer to.
      (guard (e (#t (if inited? (uv-close l on-close-entry) (foreign-free l))
                    (raise e)))
        (check 'uv-tcp-init (uv-tcp-init uv-loop l))
        (set! inited? #t)
        (check 'uv-ip4-addr (uv-ip4-addr host port sockaddr-buf))
        (check 'uv-tcp-bind (uv-tcp-bind l sockaddr-buf flags))
        (check 'uv-listen (uv-listen l backlog on-connection-entry))
        ;; #(token on-accept). The token is a fresh Scheme object per
        ;; LISTENER INCARNATION, and it is what makes an address safe to
        ;; use as an identity. Addresses alone are not: uv_handle_size
        ;; for a TCP handle was 264 bytes on the build this was measured
        ;; on (uv_handle_size is queried at run time and is not a
        ;; cross-platform constant; the argument does not depend on the
        ;; number, only on same-size reuse), and a foreign-alloc of that
        ;; size right after the close callback frees one returns the SAME
        ;; address -- measured, not feared. Without the token, a stopped
        ;; server's handle value would match a later listener's, so the
        ;; old server would report itself live and its shutdown would
        ;; stop somebody else's listener.
        (hashtable-set! listener-table l (vector (list 'listener) on-accept))
        l))))

  ;; Stop accepting new connections (graceful shutdown step 1);
  ;; established connections are unaffected. With a listener handle
  ;; (tcp-listen!'s return value) stops the listener at that address --
  ;; pass the token too if this caller may be stale, see the note there;
  ;; with no
  ;; argument stops every listener in the process.
  ;; Is this handle registered here under THIS incarnation? A lookup in
  ;; a table this library maintains -- not a question put to libuv, and
  ;; not an observation of the socket. What it is good for is that it
  ;; never DEREFERENCES the handle: once tcp-stop-listen! has run and the
  ;; close callback has freed the block, anything that reads through the
  ;; pointer -- uv_fileno included -- is a use-after-free, while using it
  ;; as a key is not.
  ;;
  ;; ⛔ THE ADDRESS ALONE IS NOT AN IDENTITY, WHICH IS WHY THE TOKEN IS
  ;; REQUIRED. A freed address does not stay unmatched: a uv_tcp handle
  ;; was 264 bytes on the measured build -- the size is read at run time,
  ;; so treat the number as an illustration and the reuse as the point --
  ;; and a foreign-alloc of that size immediately after the
  ;; free returned the same address, so a later listener can be
  ;; registered under a stopped one's address. Membership alone would
  ;; then answer #t for a dead listener, and a stale owner's
  ;; tcp-stop-listen! would stop the new one.
  ;;
  ;; ⚠ IT CAN ANSWER #f WHILE THE HANDLE IS STILL OPEN. The row is
  ;; removed when the stop is REQUESTED and the handle lives until the
  ;; close callback runs, which is a later turn of the loop -- so the
  ;; conservative interval is that whole asynchronous close, not the gap
  ;; to the next line. Early "not listening" is the safe direction; the
  ;; reverse is what the token prevents.
  ;; The token currently registered for this handle, or #f. Take it
  ;; immediately after tcp-listen! and keep it beside the handle; the
  ;; pair is the identity, neither half alone is.
  (define (listener-token h)
    (let ((v (and h (hashtable-ref listener-table h #f))))
      (and v (vector-ref v 0))))

  (define (listener-open? h token)
    (let ((v (and h (hashtable-ref listener-table h #f))))
      (and v (eq? token (vector-ref v 0)))))

  ;; (tcp-stop-listen!)            -- every listener in this process
  ;; (tcp-stop-listen! h)          -- that handle, whatever incarnation
  ;; (tcp-stop-listen! h token)    -- that handle ONLY if it is still the
  ;;                                  incarnation the token came from
  ;;
  ;; ⚠ THE TWO-ARGUMENT FORM IS THE ONE TO USE FROM A LONG-LIVED OWNER.
  ;; A handle address can be reused by a later listener (see tcp-listen!),
  ;; so a stale owner calling the one-argument form stops whoever holds
  ;; that address now. The token form makes that a no-op instead.
  ;;
  ;; ⛔ HOLDING THE HANDLE DOES NOT MAKE A CALLER SAFE, and an earlier
  ;; version of this note said it did ("a caller that created a listener
  ;; and stops it without ever releasing it cannot be stale"). Keeping
  ;; the number keeps nothing: the no-argument form, called by anyone,
  ;; stops and frees that listener, after which the address may belong
  ;; to someone else. The one-argument form is kept for compatibility --
  ;; every caller of it in this repository is a test that creates a
  ;; listener and stops it within one flow, checked by grep -- and new
  ;; code should pass the token.
  (define (tcp-stop-listen! . rest)
    ;; ⛔ THE TEST AND THE CLOSE ARE ONE UNINTERRUPTIBLE STEP, for the
    ;; reason stated once for every call that passes a handle to libuv.
    ;; Two failures follow from splitting them, and both were reachable
    ;; before this region existed:
    ;;   - preempted after the TOKEN check, this call resumes and closes
    ;;     whatever now holds that address, because stop! re-tests only
    ;;     membership -- the stale-owner close the token exists to stop;
    ;;   - preempted after stop!'s own membership test, two callers each
    ;;     pass the same handle to uv_close.
    ;; The membership test inside stop! is therefore not redundant with
    ;; the token test outside it: it is what makes the no-argument sweep
    ;; safe over a snapshot that may already be stale.
    (define (stop! l)                        ; caller holds the region
      (when (hashtable-ref listener-table l #f)
        (hashtable-delete! listener-table l)
        (uv-close l on-close-entry)))
    (cond
      ((null? rest)
       ;; The key vector is built OUTSIDE any region -- hashtable-keys
       ;; allocates -- and each stop is atomic on its own. A key that
       ;; goes away between the snapshot and its turn is handled by
       ;; stop!'s test; a listener created after the snapshot is simply
       ;; not in this sweep, which is what "every listener at the moment
       ;; of the call" means.
       (let ((ks (hashtable-keys listener-table)))
         (vector-for-each
           (lambda (l) (with-interrupts-disabled (stop! l)))
           ks)))
      ((null? (cdr rest))
       (with-interrupts-disabled (stop! (car rest))))
      (else
       (with-interrupts-disabled
         (when (listener-open? (car rest) (cadr rest))
           (stop! (car rest)))))))

  ;; ⛔ NOTHING THAT NEEDS RETURNING EXISTS OUTSIDE THE REGION. The
  ;; foreign allocation and both publications happen inside it -- the
  ;; state vector is built outside, but it is a Scheme object the
  ;; collector reclaims -- so a kill before the region can discard
  ;; nothing that has to be handed back. That
  ;; closes a window this function used to have: req allocated, then a
  ;; preemption during the Scheme allocations that followed, then a kill
  ;; -- which discards the continuation without running any guard,
  ;; leaving a malloc'd request in no table, where uv-owner-died! cannot
  ;; find it either. There is no cell for that window (a kill cannot be
  ;; aimed into it with what the suite has); it is closed by
  ;; construction, and recorded as such.
  ;;
  ;; Allocation inside the region is allowed: a collect request is
  ;; deferred until the region is left, and the only failure shape is a
  ;; raise, which the handler catches. ⚠ The prepare/publish split is
  ;; NOT about the region being allocation-free: hashtable-set! may
  ;; allocate when it adds a key or grows, and both callers now prepare
  ;; inside their region anyway.
  ;; ⭐ SHAPED LIKE fs-start-fd!: the submission is INSIDE the region.
  ;; Publishing and submitting have to be one step, because the state
  ;; between them is one nothing can reclaim -- a published op whose
  ;; phase is 'open has no callback coming, and uv-owner-died! reaches it
  ;; only to call file-stream-close!, which does real work solely for
  ;; phase 'idle. So it sets the aborted flag and returns, and the row
  ;; and the request stay for the life of the process.
  ;;
  ;; ⚠ An earlier version of this comment said pulling the submission in
  ;; "would buy nothing". It buys exactly that window. The cost is an
  ;; uninterruptible foreign call, and it is the right trade here because
  ;; uv_fs_open with a callback is an enqueue, not the I/O itself.
  ;; Roll back a partly-started fs operation. TOP LEVEL, and taking its
  ;; state as a vector, for two reasons that both bit earlier versions:
  ;;
  ;; ⭐ A LOCAL PROCEDURE WOULD ALLOCATE A CLOSURE BEFORE THE GUARD that
  ;; is supposed to protect it. fs-start-fd! owns the caller's descriptor
  ;; from its first instruction, so an allocation failure there escaped
  ;; with the fd still open.
  ;;
  ;; ⭐ ONE COPY, TWO CALL SITES. The handler and the refused-submission
  ;; branch both need exactly this, and when they were written separately
  ;; they drifted -- see the cleanup-safe? note below for what that cost.
  ;;
  ;; State vector: #(cell req cleanup-safe? fd fd-open?).
  ;;
  ;; ⚠ AT MOST ONCE, NOT EXACTLY ONCE. Each slot is cleared BEFORE the
  ;; operation it guards, so a raise part way cannot make a second call
  ;; repeat a free or a close. The price is the other direction: a raise
  ;; BEFORE the operation takes effect loses that one resource. No flag
  ;; order gives exactly-once for an operation that may raise on either
  ;; side of its effect; leaking one block beats freeing one twice.
  ;; ⛔ This is exactly-once only under the premise that these calls do
  ;; not raise, which is where they stand today.
  (define (fs-undo! st owner)
    (let ((cell (vector-ref st 0)) (req (vector-ref st 1)))
      ;; ⭐ THE BOUNDARY IS DRAWN PER OPERATION, not uniformly. An
      ;; idempotent step keeps its slot live across itself, so a retry
      ;; after a raise can complete it; a step that must not run twice
      ;; has its slot cleared first, at the price of leaking on a raise
      ;; before the effect. unpublish-head! and hashtable-delete! are
      ;; retry-safe (a completed one makes the next a no-op); free and
      ;; close are not.
      (when cell
        (owner-index-unpublish-head! owner cell)
        (vector-set! st 0 #f))
      (when req
        (hashtable-delete! fs-table req)
        (vector-set! st 1 #f)
        ;; ⚠ ONLY A REQUEST libuv HAS INITIALISED MAY BE CLEANED UP. Before
        ;; the submission this is raw foreign-alloc memory and
        ;; uv_fs_req_cleanup would be reading fields nothing wrote. The
        ;; separate pre-submission and post-submission paths had this
        ;; right; merging them into one rollback is what lost it.
        ;;
        ;; ⭐ cleanup-safe? (slot 2) IS SET AFTER THE CALL RETURNS,
        ;; WHATEVER IT RETURNED, and that is safe because libuv
        ;; initialises the request before anything that can fail.
        ;; Verified by reading
        ;; src/unix/fs.c of libuv 1.50.0, 1.51.0, 1.52.0 and 1.52.1 --
        ;; every version this runs on today: INIT(subtype) is the first
        ;; statement of both uv_fs_open and uv_fs_fstat, the only earlier
        ;; failure is req == NULL, and a later PATH/uv__strdup failure
        ;; returns UV_ENOMEM with INIT already done and the very fields
        ;; uv_fs_req_cleanup reads left NULL.
        ;;
        ;; ⚠ RE-READ THIS AGAINST A NEWER libuv BEFORE TRUSTING IT. The
        ;; property is whether INIT still precedes every failing path in
        ;; those two functions. Nothing here breaks loudly if it stops
        ;; being true -- cleanup on a request libuv never saw is
        ;; undefined, and undefined has been observed to mean SIGABRT
        ;; (measured, with a deliberately poisoned request).
        (when (vector-ref st 2) (uv-fs-req-cleanup req))
        (foreign-free req))
      (when (vector-ref st 4)
        (vector-set! st 4 #f)
        (c-close (vector-ref st 3)))))

  (define (fs-start! path owner mode)
    ;; ⚠ THE STATE VECTOR AND THE GUARD'S OWN CONTINUATION ARE ALLOCATED
    ;; BEFORE ANY HANDLER EXISTS. That is true of every guard in this
    ;; file and is not repaired here: a Chez allocation failure is an
    ;; unrecoverable out-of-memory condition, not something a handler
    ;; could act on. Recorded as a residual rather than papered over.
    ;; This path holds nothing but Scheme objects at that moment anyway.
    (let ((st (vector #f #f #f -1 #f)) (op #f) (rc 0))
      (with-interrupts-disabled
        (guard (e (#t (fs-undo! st owner) (raise e)))
          (set! op (make-fs-op owner path mode #f 'open #f #f -1 0 0 '() 0 0))
          (vector-set! st 0 (owner-index-prepare! 'fs))
          (vector-set! st 1 (foreign-alloc fs-req-size))
          (fs-op-req-set! op (vector-ref st 1))
          (hashtable-set! fs-table (vector-ref st 1) op)
          ;; INJECTION POINT 'fs-publish-second-half-open -- OWNING
          ;; GUARD: the guard above.
          (inject-fault! 'fs-publish-second-half-open)
          (owner-index-publish! owner (vector-ref st 0) (vector-ref st 1))
          ;; INJECTION POINT 'fs-submit-gap-open -- OWNING GUARD: the
          ;; same one. It stands for ANY raise between publishing and
          ;; submitting, the state nothing reclaims: file-stream-close!
          ;; acts only on phase 'idle, so a published, unsubmitted op is
          ;; merely flagged and its row and request stay forever.
          (inject-fault! 'fs-submit-gap-open)
          (set! rc (uv-fs-open uv-loop (vector-ref st 1) path
                               O-RDONLY 0 on-fs-entry))
          ;; ⭐ THE SLOT MEANS "cleanup is defined on this request", NOT
          ;; "it was submitted" -- an earlier name said submitted? and
          ;; was false: uv_fs_open can return UV_ENOMEM having submitted
          ;; nothing, and the request is still initialised and safe to
          ;; clean. Set here because this is the earliest point at which
          ;; that holds; the reading that establishes it, and the one
          ;; case it depends on not happening (req == NULL, which
          ;; foreign-alloc makes impossible by raising instead of
          ;; returning null), are with the consumer in fs-undo!.
          (vector-set! st 2 #t)
          (when (< rc 0)
            (fs-undo! st owner)
            ;; ⚠ REPORTED INSIDE THE REGION, and that is deliberate.
            ;; owner is an explicit parameter of the exported API and
            ;; need not be the process that called: A may submit on
            ;; behalf of B. Telling the owner outside the region let a
            ;; kill in between leave B with neither an error nor any
            ;; callback to come, and for a whole-file read B holds no
            ;; handle to ask with -- it would wait forever.
            (deliver owner (vector 'file-error rc)))))
      op))

 ;; Start the ordinary asynchronous fstat/read pipeline from an fd that
  ;; has already been opened securely with openat.
  ;; ⛔ THIS FUNCTION TAKES OWNERSHIP OF fd, INCLUDING WHEN IT FAILS. The
  ;; caller opened fd with openat and has no other handle on it, so a
  ;; raise that leaves this frame without closing it leaks a descriptor
  ;; that nothing in the process can name again -- it is not in fs-table,
  ;; not in the owner index, and not reachable from op, because op is
  ;; exactly what failed to be built. Measured, not argued: injecting a
  ;; failure between the allocation and the publish moved the /dev/fd
  ;; count from 12 to 13 with fs-count still 0.
  ;;
  ;; ⭐ THE GUARD SPANS EVERYTHING, PUBLICATION AND SUBMISSION INCLUDED.
  ;; Earlier versions of this note said it stopped before publication and
  ;; that an fs-table row alone made the request reachable to
  ;; uv-owner-died!. Both were wrong: teardown walks the OWNER INDEX
  ;; first and needs both entries, and stopping the guard before the
  ;; publish left the state that has no reclaimer at all -- published,
  ;; unsubmitted, phase not 'idle, so file-stream-close! only flags it.
  ;;
  ;; ⚠ ONE ALLOCATION STILL PRECEDES THE REGION: the state vector. If
  ;; Chez fails to allocate it, this frame is already holding the fd and
  ;; nothing closes it. ⛔ SO THIS PATH IS NOT YET INDEPENDENT OF ITS
  ;; CALLER, and file-stream-open-under!'s enclosing region is what
  ;; covers that instant today. Three versions of this comment have now
  ;; claimed independence: the first while op and cell were built in the
  ;; let initialisers, the second while a local undo! allocated a closure
  ;; there, and the third while this vector did. Each time the claim was
  ;; written before the last allocation had actually moved.
  ;;
  ;; What is left is irreducible without changing the interface -- a Chez
  ;; allocation failure is unrecoverable and no handler could act on it,
  ;; and the alternative is preparing the vector before the caller opens
  ;; the descriptor. Recorded as a residual; the honest statement is that
  ;; this window exists and is covered only by the caller.
  ;;
  ;; Past that, a raise anywhere inside reaches the handler and a kill
  ;; cannot land inside at all. (The guard's setup is itself inside the
  ;; disabled region -- Chez expands guard within the dynamic-wind body
  ;; -- so only the vector above is outside.) Scheme allocation inside the region
  ;; is allowed: a collect request is deferred until the region is left,
  ;; and the only failure shape is a raise, which this handler catches.
  ;;
  ;; This function OWNS fd from the call, success or failure. Its caller
  ;; opened it with openat and holds no other handle on it.
  ;; ⛔ THIS FUNCTION OWNS fd FROM ITS FIRST INSTRUCTION, success or
  ;; failure. Its caller opened it with openat and holds no other handle
  ;; on it, so every exit has to close it.
  ;;
  ;; ⚠ Same residual as fs-start!: the state vector and the guard's own
  ;; continuation are allocated before any handler exists. Unlike that
  ;; path, this one already holds the descriptor at that moment -- so if
  ;; Chez fails to allocate there, the fd leaks. It is left as a declared
  ;; residual because an allocation failure in Chez is an unrecoverable
  ;; out-of-memory condition; the honest statement is that this window
  ;; exists and is not covered, not that nothing precedes the guard.
  (define (fs-start-fd! fd path owner mode)
    (let ((st (vector #f #f #f fd #t)) (op #f) (rc 0))
      (with-interrupts-disabled
        (guard (e (#t (fs-undo! st owner) (raise e)))
          (set! op (make-fs-op owner path mode #f 'fstat #f #f fd 0 0 '() 0 0))
          (vector-set! st 0 (owner-index-prepare! 'fs))
          ;; INJECTION POINT 'fs-oom-fd -- OWNING GUARD: the guard above,
          ;; the only one on this path. It stands for the allocation
          ;; below failing; either Scheme allocation reaches it too.
          (inject-fault! 'fs-oom-fd)
          (vector-set! st 1 (foreign-alloc fs-req-size))
          (fs-op-req-set! op (vector-ref st 1))
          (hashtable-set! fs-table (vector-ref st 1) op)
          ;; INJECTION POINT 'fs-publish-second-half -- OWNING GUARD: the
          ;; same one. A failure between the two publications.
          (inject-fault! 'fs-publish-second-half)
          (owner-index-publish! owner (vector-ref st 0) (vector-ref st 1))
          ;; INJECTION POINT 'fs-submit-gap-fd -- OWNING GUARD: the same
          ;; one. See fs-start! for what this window costs if it is left
          ;; outside the guard.
          (inject-fault! 'fs-submit-gap-fd)
          (fs-op-phase-set! op 'fstat)
          (set! rc (uv-fs-fstat uv-loop (vector-ref st 1)
                                (fs-op-fd op) on-fs-entry))
          (vector-set! st 2 #t)
          (when (< rc 0)
            (fs-undo! st owner)
            (deliver owner (vector 'file-error rc)))))
      op))

  (define (relative-parts rel)
    (let ((n (string-length rel)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n)
           (let ((part (substring rel start i)))
             (reverse (if (or (string=? part "") (string=? part "."))
                          acc (cons part acc)))))
          ((char=? (string-ref rel i) #\/)
           (let ((part (substring rel start i)))
             (loop (+ i 1) (+ i 1)
                   (if (or (string=? part "") (string=? part "."))
                       acc (cons part acc)))))
          (else (loop (+ i 1) start acc))))))

  ;; Open rel beneath root without following any untrusted path component.
  ;; The trusted root is opened once per call; every child is then resolved
  ;; relative to that stable directory fd. Returns an fd or -1.
  ;;
  ;; Do NOT hoist the root open into a cached fd. A directory fd names an
  ;; inode, not a path -- which is exactly why the walk below cannot be
  ;; raced, and exactly why keeping one across requests would pin the
  ;; directory that was there when it was opened. A deployment that swaps
  ;; its root atomically (ln -sfn releases/v2 current) would go on serving
  ;; the previous release until the process restarted, with nothing to
  ;; indicate it. The saving would be one syscall out of the 1 + 2N this
  ;; makes, on the cache-miss path only.
  (define (open-under root rel)
    (let ((parts (relative-parts rel)))
      (if (or (null? parts)
              (exists (lambda (p)
                        (or (string=? p "..")
                            (let loop ((i 0))
                              (and (< i (string-length p))
                                   (or (char=? (string-ref p i) #\nul)
                                       (loop (+ i 1)))))))
                      parts))
          -1
          (let ((root-fd
                  (c-open root
                    (bitwise-ior O-RDONLY O-DIRECTORY O-CLOEXEC) 0)))
            (if (< root-fd 0)
                -1
                (let loop ((dir root-fd) (xs parts))
                  (let* ((last? (null? (cdr xs)))
                         (flags (bitwise-ior O-RDONLY O-CLOEXEC O-NOFOLLOW
                                  (if last? 0 O-DIRECTORY)))
                         (next (c-openat dir (car xs) flags 0)))
                    (c-close dir)
                    (cond ((< next 0) -1)
                          (last? next)
                          (else (loop next (cdr xs)))))))))))

  ;; The path the OS itself would call this file: symlinks and . / ..
  ;; resolved, and on a case-insensitive filesystem the spelling corrected
  ;; to the one on disk, so every way of naming one file gives one answer.
  ;; #f if it does not resolve.
  ;;
  ;; SYNCHRONOUS -- a passed callback of 0 makes uv_fs_* block -- so this
  ;; stalls the scheduler for one path lookup. That is the same cost the
  ;; surrounding code already pays for file-exists?; do not put it on a
  ;; path that runs per request when the answer can be cached.
  (define (file-realpath path)
    (let ((req (foreign-alloc fs-req-size)))
      (dynamic-wind
        (lambda () (void))
        (lambda ()
          (let ((r (uv-fs-realpath uv-loop req path 0)))
            (and (>= r 0)
                 (let ((p (uv-fs-get-ptr req)))
                   (and (not (eqv? p 0))
                        ;; the string is owned by the request; copy before
                        ;; the cleanup below frees it
                        (let loop ((i 0) (acc '()))
                          (let ((b (foreign-ref 'unsigned-8 p i)))
                            (if (fx= b 0)
                                (utf8->string
                                  (u8-list->bytevector (reverse acc)))
                                (loop (fx+ i 1) (cons b acc))))))))))
        (lambda ()
          (uv-fs-req-cleanup req)
          (foreign-free req)))))

  ;; Read a whole file on libuv's thread pool. The owner process later
  ;; receives #(file-read ,bytevector) or #(file-error ,errno). Never
  ;; blocks the scheduler, even for large files or slow filesystems.
  (define (file-read-async! path owner)
    (fs-start! path owner 'whole)
    (void))

  ;; Open a file as a consumer-driven chunk stream; returns the stream
  ;; handle (also carried by the ready message, and needed to close a
  ;; stream whose open never completed). The owner later receives
  ;; #(file-stream ,stream ,size) (ready; size from fstat) or
  ;; #(file-error ,errno). Then each file-stream-read! yields exactly
  ;; one of: #(file-chunk ,x) (a bytevector, or its length after
  ;; file-stream-raw!), #(file-eof) (all bytes delivered or the file
  ;; shrank -- the fd is already closed), or #(file-error ,errno) (fd
  ;; closed). One pull may be in flight at a time, so a slow consumer
  ;; holds one chunk of memory, not the file.
  (define (file-stream-open! path owner)
    (fs-start! path owner 'stream))

  ;; Confined counterpart used by app-static and rooted send-file!. #f is
  ;; an immediate refusal (missing path, symlink, or invalid component).
  (define (file-stream-open-under! root rel owner)
    ;; Keep the raw fd continuously protected: before fs-start-fd! installs
    ;; it in fs-table, actor teardown has no way to discover and close it.
    ;;
    ;; ⚠ THE REGION COVERS PREEMPTION AND NOTHING ELSE. It stops actor
    ;; teardown from running here; it does not unwind, so it never
    ;; covered fs-start-fd! RAISING with the fd in hand -- that half is
    ;; fs-start-fd!'s own contract, which is why that function closes fd
    ;; on any pre-publication failure. Read the two together: this line
    ;; hands the descriptor over, and the callee owns it from the call,
    ;; success or failure.
    (with-interrupts-disabled
      (let ((fd (open-under root rel)))
        (and (>= fd 0) (fs-start-fd! fd rel owner 'stream)))))

  ;; Switch chunk delivery to lengths: the bytes stay in the stream's C
  ;; buffer (file-stream-chunk-ptr) until the next pull, so a consumer
  ;; that only forwards them (tcp-write-foreign!) never touches the
  ;; Scheme heap. Set it before the first pull.
  (define (file-stream-raw! op)
    (fs-op-raw?-set! op #t))

  (define (file-stream-chunk-ptr op)
    (fs-op-data op))

  ;; Transfer delivery of subsequent messages to another process (e.g.
  ;; a pump spawned after the stream was opened). Call it before the
  ;; new owner's first pull, with no pull in flight.
  ;; How many file streams are open. Same purpose as conn-count: an fd,
  ;; a uv_fs_t and a 256 KiB foreign buffer that outlive their owner are
  ;; invisible from Scheme -- fs-table roots them, so the GC will not
  ;; report them either -- and a leak that nothing can count is a leak
  ;; nothing can assert about.
  (define (fs-count) (hashtable-size fs-table))

  ;; In-flight getaddrinfo requests. Exported for the reason fs-count and
  ;; uv-owner-index-count are: the failure this pairs with -- a request
  ;; row that outlives its resolution -- has no symptom except growth,
  ;; and the owner index alone cannot show it, because that index is a
  ;; superset that a cell can watch return to baseline while this table
  ;; keeps a row nothing will ever reach.
  (define (dns-count) (hashtable-size getaddrinfo-table))

  ;; The accept-queue limit the kernel actually kept for this listener,
  ;; or #f where it cannot be read. listen() silently clamps the backlog
  ;; it is given to a system maximum (kern.ipc.soacceptqueue on FreeBSD,
  ;; somaxconn on Linux), and reports nothing: a server can ask for 8192,
  ;; be given 128, and overflow under a burst with no local symptom -- the
  ;; drops are counted in the kernel, not here.
  ;;
  ;; ⛔ #f IS AN HONEST ANSWER AND A WRONG NUMBER IS NOT. Both the option
  ;; and its level come from (igropyr platform) and are #f until read
  ;; from the target's headers; while either is #f this returns #f rather
  ;; than calling getsockopt with a guessed constant, which would answer
  ;; for some other option and hand back a plausible integer.
  ;; ⛔ ALL THREE BLOCKS ARE ALLOCATED TOGETHER SO ONE HANDLER CAN NAME
  ;; ALL THREE. The first version allocated val and len INSIDE a guard
  ;; whose handler knew only about fdbuf, so a raise from getsockopt
  ;; would have returned one block and leaked two. That raise was not
  ;; reachable in practice -- the arguments are fixnums and pointers,
  ;; and the read is from a block allocated three lines above -- which
  ;; is why the SHAPE is what was wrong, not the symptom. It was the
  ;; third instance of that shape in one day; the check that catches it
  ;; is to ask, at every foreign-alloc, which handler knows this name.
  ;;
  ;; ⚠ ONE RESIDUAL, STATED RATHER THAN PAPERED OVER: if the second or
  ;; third foreign-alloc raises, the first is still leaked, because the
  ;; bindings run before any handler is installed. That is an allocation
  ;; failure of twelve bytes total, and covering it would need three
  ;; nested guards for a case where the process is already out of
  ;; memory. The gap is named here so a reader can weigh it rather than
  ;; assume it was handled.
  ;; ⛔ THE CHECK AND THE FOREIGN USE ARE ONE UNINTERRUPTIBLE STEP, which
  ;; is the rule this file already states for every call that passes a
  ;; handle to libuv. A membership test on its own does NOT make this
  ;; safe: between the test and uv_fileno the process can be preempted,
  ;; another can stop the listener, and the loop can free the handle --
  ;; so the region has to span the test AND both foreign calls. The three
  ;; buffers are therefore allocated OUTSIDE it; the region does pointer
  ;; work, two FFI calls and the three foreign-frees done! performs --
  ;; no allocation.
  ;;
  ;; The token is checked, not just membership: a later listener can hold
  ;; this very address (see tcp-listen!), and answering for it would
  ;; report somebody else's backlog as this server's.
  (define (listener-backlog-effective l token)
    (and so-listenqlimit sol-socket
         (let ((fdbuf (foreign-alloc 4))
               (val   (foreign-alloc 4))
               (len   (foreign-alloc 4)))
           (define (done! x)
             (foreign-free fdbuf) (foreign-free val) (foreign-free len)
             x)
           (guard (e (#t (done! #f) (raise e)))
             (foreign-set! 'int len 0 4)
             (with-interrupts-disabled
               (if (not (listener-open? l token))
                   (done! #f)
                   (if (< (uv-fileno l fdbuf) 0)
                       (done! #f)
                       (let* ((fd (foreign-ref 'int fdbuf 0))
                              (rc (c-getsockopt fd sol-socket so-listenqlimit
                                                val len))
                              (answer (and (>= rc 0)
                                           (foreign-ref 'int val 0))))
                         (done! (and answer (> answer 0) answer))))))))))

  (define (file-stream-own! op pid)
    (with-interrupts-disabled
      (fs-op-owner-set! op pid)
    ;; The INDEX has to learn about the move too, exactly as conn-set-owner!
    ;; does for connections. Setting only the field meant uv-owner-died! for
    ;; the new owner found nothing to reclaim: a pump killed mid-download
    ;; left its fd, its uv_fs_t and its 256 KiB foreign buffer rooted by
    ;; fs-table for the life of the VM, which is the leak the index exists
    ;; to prevent.
      (index-owner! pid 'fs (fs-op-req op))))

  (define (file-stream-read! op)
    (when (and (not (fs-op-aborted? op)) (eq? (fs-op-phase op) 'idle))
      (start-fs-read! op (fs-op-req op))))

  ;; Abort/release a stream early (consumer done or gone). Idempotent;
  ;; nothing further is delivered. With an op in flight the completion
  ;; callback performs the close.
  (define (file-stream-close! op)
    (unless (fs-op-aborted? op)
      (fs-op-aborted?-set! op #t)
      (when (eq? (fs-op-phase op) 'idle)
        (fs-quiet-close! op (fs-op-req op)))))

  ;; Async DNS. The owner process later receives #(dns-resolved ,ip-string)
  ;; or #(dns-failed ,errno). libuv resolves on its thread pool, so the
  ;; scheduler is not blocked.
  ;; ⚠ TWO EXITS, AND BOTH OWE AN unindex-owner!. A submission that
  ;; libuv refuses never reaches the callback, so the request is torn
  ;; down here instead; a submission it accepts is torn down there. The
  ;; index registration made below is one, and whichever exit runs has to
  ;; retire it -- neither of them covers the other.
  ;;
  ;; ⛔ NEITHER OF THEM DID, AND NOTHING SAID SO. The entry survived every
  ;; completed resolution for the life of the owning process; only owner
  ;; death cleared it, by deleting that owner's list wholesale. The
  ;; symptom was growth alone, which is why unindex-owner! reports a
  ;; count -- and that count is what a cell reads here.
  (define (dns-resolve! host owner)
    (let ((req (foreign-alloc getaddrinfo-req-size)))
      (hashtable-set! getaddrinfo-table req owner)
      (index-owner! owner 'dns req)
      ;; INJECTION POINT 'getaddrinfo-refused -- OWNING GUARD: none. There
      ;; is no guard between here and the assertion; a negative return is
      ;; a value, not a raise, and it is read by the (when (< r 0) ...)
      ;; immediately below, which is the branch the cell exercises.
      (let ((r (inject-return! 'getaddrinfo-refused
                 (uv-getaddrinfo uv-loop req on-getaddrinfo-entry host 0 0))))
        (when (< r 0)
          (hashtable-delete! getaddrinfo-table req)
          ;; Same ordering and the same reason as the callback's copy,
          ;; and a different handler: this runs on the caller's own
          ;; stack, not in a foreign callback, so an allocation failure
          ;; is reportable and is reported. What must not differ is the
          ;; free -- nothing else will ever reach this request, because
          ;; the table row is gone and a refused submission produces no
          ;; callback.
          ;;
          ;; ⛔ ZERO COVERAGE, AND THE REASON IS NAMED. This branch runs
          ;; only when uv_getaddrinfo refuses SYNCHRONOUSLY. A name that
          ;; does not resolve is refused by the resolver instead, through
          ;; the callback with a negative status, so the suite's bad-host
          ;; case exercises the copy above and not this one: mutating
          ;; this line leaves test/dns-owner-index.sc green. host is
          ;; always a string here, so it is not currently known whether
          ;; any public call can reach it at all.
          ;; ⛔ Do not manufacture reachability by changing this code to
          ;; suit a test.
          (guard (e (#t (foreign-free req) (raise e)))
            (unindex-owner! owner 'dns req))
          (foreign-free req)
          (deliver owner (vector 'dns-failed r))))))

  ;; Outbound TCP connection. The owner process later receives
  ;; #(tcp-connected ,conn) or #(tcp-connect-failed ,errno). Call
  ;; tcp-read-start! on the conn after the connected message arrives.
  (define (tcp-connect! host port owner)
    ;; sockaddr-buf is a process-wide singleton and the allocations
    ;; below are preemption points: another green process starting its
    ;; own connect (or a listener binding) would overwrite the address
    ;; we just resolved, and we would connect to ITS host. Also covers
    ;; the connect-table mutation. Nothing here yields.
    (with-interrupts-disabled
    (check 'uv-ip4-addr (uv-ip4-addr host port sockaddr-buf))
    (let ((h (foreign-alloc tcp-handle-size))
          (inited? #f)
          (req #f)
          (indexed? #f))
      ;; WHAT HAS BEEN TAKEN SO FAR, AND NOTHING ELSE. Each flag is set
      ;; immediately after the step that makes the resource ours, so the
      ;; release below never guesses: it undoes exactly what happened.
      ;; The alternative -- one cleanup that assumes the common case --
      ;; is what turns a failure in the middle into either a leak or a
      ;; double free, depending on where it stopped.
      ;;
      ;; It runs at most once. The guard re-raises after releasing, and
      ;; the synchronous-failure path below runs it only after the guard
      ;; has already been left behind.
      (define (release!)
        (when indexed?
          (unindex-owner! owner 'connect req)
          (set! indexed? #f))
        (when req
          (hashtable-delete! connect-table req)
          (foreign-free req)
          (set! req #f))
        (if inited? (uv-close h on-close-entry) (foreign-free h))
        (set! inited? #f))
      (let ((r (guard (e (#t (release!) (raise e)))
                 (check 'uv-tcp-init (uv-tcp-init uv-loop h))
                 (set! inited? #t)
                 ;; INJECTION POINT 'connect-oom -- OWNING GUARD: the guard
                 ;; opened on the line above, and it is MEANT to catch this.
                 ;; That is the branch under test: the handle is inited and
                 ;; nothing else is, so release! must close it and free
                 ;; nothing else. There is no other guard between here and
                 ;; the assertion; the re-raise leaves tcp-connect! and the
                 ;; cell reads the two counts after the loop has run.
                 (inject-fault! 'connect-oom)
                 (set! req (foreign-alloc connect-req-size))
                 (hashtable-set! connect-table req (cons h owner))
                 (index-owner! owner 'connect req)
                 (set! indexed? #t)
                 ;; INJECTION POINT 'tcp-connect-refused -- OWNING GUARD:
                 ;; the same guard lexically, but it does NOT catch this
                 ;; one and must not: a refused submission is a negative
                 ;; RETURN, not a raise, so it flows out of the guard to
                 ;; the (when (< r 0) (release!) ...) below. The two
                 ;; points share a guard and exercise different branches,
                 ;; which is why they are separate points and not one.
                 (inject-return! 'tcp-connect-refused
                   (uv-tcp-connect req h sockaddr-buf on-connect-entry)))))
        (when (< r 0)
          (release!)
          (error 'tcp-connect! (uv-strerror r)))
        #t))))

  (define uv-tcp-getpeername
    (foreign-procedure "uv_tcp_getpeername" (void* void* void*) int))

  ;; The peer's IPv4 address as "a.b.c.d", or #f (not open, IPv6, or the
  ;; socket is gone). This is the ONLY caller-visible identity a remote
  ;; client cannot forge -- unlike any header it sends -- so it is what
  ;; per-client policy (rate limiting, banning) must key on.
  ;; THE STATE TEST AND THE HANDLE USE ARE ONE UNINTERRUPTIBLE STEP, here
  ;; and at every other FFI call that passes conn-handle -- ⚠ a rule
  ;; this file has not always followed: tcp-stop-listen! split its test
  ;; from its uv-close until the incarnation work put them back
  ;; together, and listener-backlog-effective did the same. This is the
  ;; invariant, stated once for all of them:
  ;;
  ;;   a conn's handle may be passed to libuv only inside a region where
  ;;   its state has been observed 'open WITHOUT an intervening safe point
  ;;
  ;; It is not hygiene. close_cb -- the only place handle memory is freed
  ;; (see on-close-code) -- runs in the event-loop process, so it can only
  ;; interleave where this process can be preempted. Testing the state,
  ;; yielding, and then using the handle is a use-after-free: another
  ;; process closes, the loop runs the close callback, foreign-free
  ;; returns the memory, and the FFI call that follows hands libuv a dead
  ;; pointer. Inside a with-interrupts-disabled region there is no
  ;; preemption, the event loop cannot run, and the observation still
  ;; holds when the call is made.
  ;;
  ;; The test is for 'open specifically, not for "not closed": a handle
  ;; that has been submitted to uv_close is 'closing, and no FFI call
  ;; should touch it again even though its memory is still there.
  (define (conn-peer-ip c)
    (with-interrupts-disabled          ; shared peername buffers
      (and (eq? (conn-state c) 'open)
           (begin
             (foreign-set! 'int peername-len 0 128)
             (and (>= (uv-tcp-getpeername (conn-handle c)
                                          peername-buf peername-len) 0)
                ;; sockaddr_in: sin_family differs in layout across
                ;; platforms, but sin_addr is always at offset 4
                (let ((fam (case platform-os
                             ((macos freebsd) (foreign-ref 'unsigned-8 peername-buf 1))
                             (else (foreign-ref 'unsigned-16 peername-buf 0)))))
                  (and (= fam AF-INET)
                       (string-append
                         (number->string (foreign-ref 'unsigned-8 peername-buf 4)) "."
                         (number->string (foreign-ref 'unsigned-8 peername-buf 5)) "."
                         (number->string (foreign-ref 'unsigned-8 peername-buf 6)) "."
                         (number->string (foreign-ref 'unsigned-8 peername-buf 7))))))))))

  ;; Start delivering #(tcp-data ...) messages to the conn's owner.
  ;; Call after conn-set-owner!.
  (define (tcp-read-start! c)
    (with-interrupts-disabled          ; test and use: see conn-peer-ip
      (when (eq? (conn-state c) 'open)
        (uv-read-start (conn-handle c) on-alloc-entry on-read-entry))))

  ;; Stop delivering #(tcp-data ...), so the kernel's receive window closes
  ;; and the PEER is slowed down.
  ;;
  ;; Without this the loop reads as fast as the peer sends and copies every
  ;; segment into an unbounded actor mailbox, so a consumer that is slower
  ;; than its producer accumulates raw bytes in memory instead of exerting
  ;; back pressure -- and before any parser limit applies, because those
  ;; run on bytes that have already been queued. An actor mailbox is not a
  ;; substitute for the kernel's flow control.
  ;;
  ;; Safe to call when reads are already stopped, and on a closed conn.
  (define (tcp-read-stop! c)
    (with-interrupts-disabled          ; test and use: see conn-peer-ip
      (when (eq? (conn-state c) 'open)
        (uv-read-stop (conn-handle c))))
    (void))

  ;; Queue `len` bytes for an async write. fill-data! copies them into
  ;; the foreign data area. Allocates one block [uv_write_t][uv_buf_t]
  ;; [payload]; write_cb frees it and runs on-done in callback context
  ;; (must not yield). Returns #t if queued, #f on immediate error.
  (define (enqueue-write! c len fill-data! on-done)
    ;; ⭐ INJECTION POINT (E1, allocation failure). Placed BEFORE the
    ;; allocation and before anything is published, so an injected raise
    ;; leaves exactly the state a real out-of-memory would: no block, no
    ;; write-table entry, nothing for the caller to unwind.
    ;;
    ;; ⚠ IT IS NOT OUTSIDE EVERY INTERRUPT REGION, and an earlier note
    ;; here said it was -- checked lexically, where it does sit before
    ;; this procedure's own region, and not against the callers.
    ;; tcp-writev!'s small-write path enters a region and reaches here
    ;; without leaving it, and node.sc calls tcp-writev! inside
    ;; `atomically` as well. Raising there is nonetheless right: the
    ;; allocation this stands in for is in the same place, so the
    ;; injection reproduces the real failure rather than a tidier one.
    (inject-fault! 'writev-oom)
    (let* ((block (foreign-alloc (+ write-req-size buf-t-size len)))
           (buf-ptr (+ block write-req-size))
           (data-ptr (+ buf-ptr buf-t-size)))
      (fill-data! data-ptr)
      (foreign-set! 'void* buf-ptr 0 data-ptr)
      (foreign-set! 'unsigned-64 buf-ptr 8 len)
      ;; PUBLISH BEFORE SUBMITTING. uv-write can complete before it returns
      ;; (a fast loopback write), and the callback looks the block up in
      ;; write-table -- so registering afterwards is a race the writer
      ;; loses: the completion finds nothing, frees the block, and the
      ;; writer then registers a freed address that nothing will ever
      ;; answer. Upstream that is a stream, a node send or a database
      ;; operation parked forever.
      ;;
      ;; Registering first cannot leak: the only way out without a
      ;; completion is uv-write failing, and that path removes the entry
      ;; again. The whole publish/submit pair is interrupt-free so the
      ;; callback cannot observe a half-built state.
      ;; The caller tested the state, but that was before this block was
      ;; allocated and filled -- both safe points. Re-testing HERE, inside
      ;; the region that submits, is what satisfies the invariant stated
      ;; at conn-peer-ip; the earlier test is an early-out, not a
      ;; guarantee. A connection closed in between takes the same exit as
      ;; a rejected uv-write: the block is freed and on-done reports the
      ;; failure, so the caller's accounting balances either way.
      (with-interrupts-disabled
        (if (not (eq? (conn-state c) 'open))
            (begin
              (foreign-free block)
              (when on-done (on-done -1))
              #f)
            (begin
              (hashtable-set! write-table block
                (or on-done (lambda (status) (void))))
              ;; ⭐ INJECTION POINT (E1, negative errno). It wraps the RAW
              ;; FFI call and nothing else, which is what inject-return!
              ;; requires: when armed the call is SKIPPED, so the block is
              ;; never handed to libuv and the failure path below is free
              ;; to free it. Wrapping anything that had already acted on
              ;; the result would fake a failure after the work was done.
              (let ((r (inject-return! 'uv-write-neg
                         (uv-write block (conn-handle c) buf-ptr 1 on-write-entry))))
                (if (< r 0)
                    (begin
                      (hashtable-delete! write-table block)
                      (foreign-free block)
                      (when on-done (on-done r))
                      #f)
                    #t)))))))

  ;; Write a sequence of bytevectors as one response. Small writes take
  ;; the uv_try_write fast path: the segments are packed into the shared
  ;; scratch buffer and written synchronously, skipping the write_req /
  ;; write_cb / hashtable / foreign-alloc of the queued path entirely --
  ;; on-done runs inline with status 0. A partial write or EAGAIN falls
  ;; back to the queued path for the unwritten remainder; writes larger
  ;; than the scratch go straight to the queued path. on-done runs in
  ;; caller context on the fast path (safe: not inside a libuv callback)
  ;; and in callback context on the queued path; either way it must not
  ;; yield. Returns #f if the connection is not open (on-done ran -1).
  (define (tcp-writev! c segs on-done)
    (if (not (eq? (conn-state c) 'open))
        (begin (when on-done (on-done -1)) #f)
        (let ((total (fold-left (lambda (a b) (+ a (bytevector-length b))) 0 segs)))
          (cond
            ((<= total write-scratch-size)
             ;; write-scratch and scratch-buf are process-wide singletons,
             ;; and this runs in ordinary green processes (an HTTP worker
             ;; writing a response, a db client sending a query) with the
             ;; preemption timer live. The packing loop and its foreign
             ;; calls are safe points, so without this guard a second
             ;; writer could overwrite the scratch between our pack and
             ;; our uv_try_write -- and we would send ITS bytes on OUR
             ;; socket. with-interrupts-disabled is exit-safe; nothing in
             ;; here yields.
             (with-interrupts-disabled
             ;; The state test at the top of this procedure is an
             ;; early-out; the fold above it is a safe point, so the
             ;; observation that matters is this one, made in the same
             ;; region as the call. See conn-peer-ip for the invariant.
             (if (not (eq? (conn-state c) 'open))
                 (begin (when on-done (on-done -1)) #f)
                 (begin
                   ;; pack segments into scratch, then write in one shot
                   (let loop ((ss segs) (off 0))
                     (unless (null? ss)
                       (let ((n (bytevector-length (car ss))))
                         (memcpy-to-c (+ write-scratch off) (car ss) n)
                         (loop (cdr ss) (+ off n)))))
                   (foreign-set! 'void* scratch-buf 0 write-scratch)
                   (foreign-set! 'unsigned-64 scratch-buf 8 total)
                   ;; ⭐ INJECTION POINT (E1, "nothing went out yet").
                   ;; Frames up to the scratch size finish here and never
                   ;; reach the queued path, so without this knob the
                   ;; small control frames -- mon, mdown, demon, a short
                   ;; rsend -- can never be made to fail. Injecting 0
                   ;; (EAGAIN) sends the caller down the queue-it-all
                   ;; branch, where the other two knobs live.
                   ;;
                   ;; ⛔ ZERO, NEVER A POSITIVE PARTIAL COUNT. ⚠ 0 is not
                   ;; something uv_try_write actually returns for a
                   ;; non-empty buffer -- libuv gives a positive count or
                   ;; a negative UV_EAGAIN -- so this is a surrogate, and
                   ;; it is chosen as the smallest value that lands on
                   ;; the queue-everything branch below without claiming
                   ;; any byte was written. A positive count would
                   ;; make the caller queue only the suffix -- the
                   ;; counter-example inject-return!'s rule is written
                   ;; against, and unrecoverable at every layer above.
                   (let ((n (inject-return! 'try-write-eagain
                              (uv-try-write (conn-handle c) scratch-buf 1))))
                     (cond
                       ((= n total)                 ; fully written now
                        (when on-done (on-done 0)) #t)
                       ((and (> n 0) (< n total))   ; partial: queue the rest
                       ;; A PARTIAL WRITE HAS ALREADY PUT BYTES ON THE
                       ;; WIRE, so failing to queue the remainder is not
                       ;; a failure to send -- it is a stream that now
                       ;; carries a truncated message with no way to
                       ;; retract it. Whatever is written next would be
                       ;; read as the missing tail. There is no recovery
                       ;; from that at this layer or any layer above it,
                       ;; so the connection is closed: the peer sees a
                       ;; connection drop, which every protocol on top of
                       ;; this already knows how to handle, instead of a
                       ;; framing error it has no vocabulary for.
                       ;; The close covers both ways queueing can fail --
                       ;; a returned #f, and a raise on the way there.
                        (let ((queued
                                (guard (e (#t (tcp-close! c) (raise e)))
                                  (enqueue-write! c (- total n)
                                    (lambda (dest)
                                      (memcpy-cc dest (+ write-scratch n)
                                                 (- total n)))
                                    on-done))))
                          (unless queued (tcp-close! c))
                          queued))
                       (else                        ; EAGAIN/0: queue all
                        (enqueue-write! c total
                          (lambda (dest) (memcpy-cc dest write-scratch total))
                          on-done))))))))
            (else                                    ; too big for scratch
             (enqueue-write! c total
               (lambda (dest)
                 (let loop ((ss segs) (off 0))
                   (unless (null? ss)
                     (let ((n (bytevector-length (car ss))))
                       (memcpy-to-c (+ dest off) (car ss) n)
                       (loop (cdr ss) (+ off n))))))
               on-done))))))

  ;; single-bytevector write (websocket / redis / mysql)
  (define (tcp-write! c bv on-done)
    (tcp-writev! c (list bv) on-done))

  ;; Write len bytes straight from foreign memory (e.g. a file stream's
  ;; chunk buffer): the fast path is buffer -> kernel with no copy at
  ;; all; a partial write or EAGAIN copies only the unwritten remainder
  ;; into the queued write block. The source buffer is free for reuse
  ;; as soon as this returns. on-done as in tcp-writev!.
  (define (tcp-write-foreign! c ptr len on-done)
    (if (not (eq? (conn-state c) 'open))
        (begin (when on-done (on-done -1)) #f)
        (with-interrupts-disabled          ; shared scratch-buf: see tcp-writev!
          (if (not (eq? (conn-state c) 'open))   ; see conn-peer-ip
              (begin (when on-done (on-done -1)) #f)
              (begin
                (foreign-set! 'void* scratch-buf 0 ptr)
                (foreign-set! 'unsigned-64 scratch-buf 8 len)
                ;; INJECTION POINT 'try-write-foreign-eagain -- OWNING
                ;; GUARD: none here. The guard further down covers the
                ;; partial branch's enqueue-write!, not this call, and a
                ;; 0 return is a value that the cond below reads: it
                ;; selects the queue-everything branch, which is the one
                ;; the cell follows to delivery.
                (let ((n (inject-return! 'try-write-foreign-eagain
                           (uv-try-write (conn-handle c) scratch-buf 1))))
                  (cond
                    ((= n len)                    ; fully written now
                     (when on-done (on-done 0)) #t)
                    ((and (> n 0) (< n len))      ; partial: queue the rest
                     ;; same as tcp-writev!'s partial branch: a prefix is
                     ;; already on the wire, so a remainder that cannot be
                     ;; queued leaves a truncated message behind it
                     (let ((queued
                             (guard (e (#t (tcp-close! c) (raise e)))
                               (enqueue-write! c (- len n)
                                 (lambda (dest)
                                   (memcpy-cc dest (+ ptr n) (- len n)))
                                 on-done))))
                       (unless queued (tcp-close! c))
                       queued))
                    (else                         ; EAGAIN/0: queue all
                     (enqueue-write! c len
                       (lambda (dest) (memcpy-cc dest ptr len))
                       on-done)))))))))

  ;; Idempotent close; memory is freed only in close_cb, so there is no
  ;; double-close and no fd leak.
  ;; Attach a cleanup thunk to a connection: it runs exactly once, when
  ;; libuv reports the handle closed -- WHOEVER closed it. That is the
  ;; point of hanging it off the conn instead of a code path: an owner
  ;; killed mid-request closes the conn via uv-owner-died!, and a killed
  ;; process runs neither winders nor guards, so any cleanup owned by
  ;; control flow is skipped. Cleanup owned by the resource is not.
  ;; Registering on an already-closed conn runs the thunk immediately.
  ;; The thunk runs in libuv callback context: it must not yield, park,
  ;; or raise (a raise here would unwind into C; it is swallowed).
  (define (conn-on-close! c thunk)
    ;; The state test and the store must be ONE operation. Between them the
    ;; close completion can run, and then the thunk is filed on a conn that
    ;; will never close again -- so it never runs at all, which for the TLS
    ;; user of this hook means a leaked SSL session, exactly what it exists
    ;; to prevent. Running it here instead is correct: the resource is gone,
    ;; so the cleanup is due now.
    (let ((run-now?
            (with-interrupts-disabled
              (if (eq? (conn-state c) 'closed)
                  #t
                  (begin (conn-set-cleanup! c thunk) #f)))))
      (when run-now? (thunk))))

  ;; THE TEST AND THE CLOSE ARE ONE STEP, and that is what makes this
  ;; idempotent rather than merely usually-idempotent. The state test and
  ;; uv-close are separated by a safe point, so two closers -- and this
  ;; connection has them, since a writer over its outbound ceiling closes
  ;; from its own process while the reader's error path closes from
  ;; another -- can both read 'open, both set 'closing, and both call
  ;; uv_close on the same handle. libuv answers a second uv_close on a
  ;; closing handle with an assert, which is not an exception this process
  ;; can catch. Disabling interrupts across the pair is the precondition
  ;; for the guarantee this procedure advertises, NOT an optimisation, and
  ;; it costs nothing: uv_close only files the handle for its close
  ;; callback and does not block.
  (define (tcp-close! c)
    (with-interrupts-disabled
      (when (and (eq? (conn-state c) 'open)
                 (= 0 (uv-is-closing (conn-handle c))))
        (conn-set-state! c 'closing)
        (uv-close (conn-handle c) on-close-entry))))
)
