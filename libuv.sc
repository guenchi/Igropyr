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
          file-stat-async! file-unlink-async! file-scandir-async!
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
          tcp-read-start! tcp-read-stop! tcp-write! tcp-writev! tcp-writev-raw!
          uv-set-self! tcp-write-foreign!
          tcp-listen-tls! uv-set-tls-watcher-spawner! uv-set-gate-wait!
          tls-watcher-exited!
          tls-handshake-max-set! tls-handshake-ms-set! tls-shutdown-ms-set!
          ;; the watcher's whole interface to a connection's shared state
          tls-gate-grant-next! tls-gate-waiters-length tls-conn-holder
          tls-conn-holder-monitor tls-conn-set-holder-monitor!
          tls-open-gate-and-drain! conn-tls-retire!
          ;; seams
          tls-raw-sink-writes tls-ssl-op-count tls-server-raw-reads
          tls-accept-callback-completions tls-gate-open-mark
          tls-live-watcher-count tls-live-timer-count tls-active-timer-count
          tls-handshaking-count tls-retire-effect-depths
          tls-raw-blocks tls-conn-charge tls-conn-totals tls-conn-timer-id
          tls-last-retire-reason tls-listener-context-id tls-eof-deliveries
          tls-swallowed-errors tls-read-trace
          tls-timer-free-path tls-conn-in-table?
          tls-inject-ciphertext!
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
  ;; ⚠ (igropyr tls-core) SITS BELOW THIS FILE and imports only chezscheme
  ;; and platform. That is what lets the server codec here drive OpenSSL
  ;; without a cycle: (igropyr tls) imports THIS file, so this file could
  ;; never import that one.
  (import (chezscheme) (igropyr platform) (igropyr inject) (igropyr tls-core))

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
      (mutable cleanup conn-cleanup conn-set-cleanup!)
      ;; ⭐ ONE FIELD, NOT FIFTEEN, AND THE CHOICE IS AN INVARIANT. #f on a
      ;; plaintext connection; otherwise the conn-tls record below. Retirement
      ;; DETACHES IT with a single assignment inside one interrupt-disabled
      ;; region, so every later caller sees #f -- which is what makes
      ;; conn-tls-retire! idempotent by shape rather than by agreement between
      ;; its callers. Fifteen separate fields would need fifteen detaches, and
      ;; "half detached" would be a state someone has to reason about; owner
      ;; death and watcher death can arrive together, so no caller can promise
      ;; to run the retirement only once.
      (mutable tls conn-tls conn-set-tls!)
      ;; ⭐ THE HANDSHAKING SLOT, HELD FROM BEFORE THE TLS RECORD EXISTS. It
      ;; cannot live on conn-tls, because the window this closes is precisely
      ;; the one before that record is built.
      (mutable slot conn-slot conn-set-slot!)))

  ;; ---- TLS state of one connection ---------------------------------------
  ;;
  ;; Reached only through conn-tls, and only while that field is non-#f. The
  ;; session is an opaque (igropyr tls-core) object: this file never holds an
  ;; SSL pointer, and every OpenSSL call goes through a session operation.
  ;;
  ;; The gate fields are shared state that both a writer and the watcher touch,
  ;; so every read-modify-write of them happens in one interrupt-disabled step
  ;; (Z8): a writer appends itself to waiters, the watcher pops it, and
  ;; retirement TAKES THE WHOLE LIST and refuses whoever it took -- whichever
  ;; of the two atomically takes a non-empty list is the one that answers, so
  ;; there is no double wake and no test of whether the watcher is still alive.
  (define-record-type (conn-tls-state make-conn-tls conn-tls?)
    (fields
      (immutable session conn-tls-session)      ; opaque tls-core session
      (immutable listener conn-tls-listener)    ; listener incarnation, or #f
      ;; inbound plaintext decrypted before the owner could receive it
      (mutable established? conn-tls-established? conn-tls-set-established!)
      (mutable eof? conn-tls-eof? conn-tls-set-eof!)
      ;; ⭐ 'seen' AND 'delivered' ARE TWO FACTS. eof? alone meant a
      ;; close_notify followed by a FIN delivered two EOFs, and a FIN
      ;; arriving while the gate was shut delivered one AHEAD of the
      ;; buffered request -- the owner saw EOF, data, EOF.
      (mutable eof-sent? conn-tls-eof-sent? conn-tls-set-eof-sent!)
      (mutable gated? conn-tls-gated? conn-tls-set-gated!)
      (mutable inbound conn-tls-inbound conn-tls-set-inbound!)
      ;; write gate
      (mutable holder conn-tls-holder conn-tls-set-holder!)
      (mutable holder-monitor conn-tls-holder-monitor conn-tls-set-holder-monitor!)
      (mutable waiters conn-tls-waiters conn-tls-set-waiters!)
      (mutable closed? conn-tls-closed? conn-tls-set-closed!)
      (mutable closing? conn-tls-closing? conn-tls-set-closing!)
      (mutable aggregate conn-tls-aggregate conn-tls-set-aggregate!)
      ;; the one timer, live for the conn's whole life (Y3): armed for the
      ;; handshake, stopped on establishment, re-armed for clean shutdown
      (mutable timer conn-tls-timer conn-tls-set-timer!)
      (immutable timer-id conn-tls-timer-id)
      ;; armed? is tracked because active-timer accounting has three
      ;; movers -- arm, stop, close -- and only a flag makes each of them
      ;; idempotent with respect to the count.
      (mutable timer-armed? conn-tls-timer-armed? conn-tls-set-timer-armed!)
      ;; watcher
      (mutable watcher conn-tls-watcher conn-tls-set-watcher!)
      ;; accounting (X4)
      (mutable bio-held conn-tls-bio-held conn-tls-set-bio-held!)
      (mutable raw-queued conn-tls-raw-queued conn-tls-set-raw-queued!)
      (mutable charged conn-tls-charged conn-tls-set-charged!)
      (mutable refunded conn-tls-refunded conn-tls-set-refunded!)
      ;; the handshaking-ceiling slot, released exactly once (Y1)
      (mutable slot? conn-tls-slot? conn-tls-set-slot!)
      ;; recorded facts the seams read back
      (mutable gate-opened-ms conn-tls-gate-opened-ms conn-tls-set-gate-opened-ms!)
      (mutable retire-path conn-tls-retire-path conn-tls-set-retire-path!)
      (mutable retire-reason conn-tls-retire-reason conn-tls-set-retire-reason!)
      ;; (entry shared-min shared-max refusal-max session-retire-max
      ;;  uv-close-max), written ONLY by the retirement that wins the detach;
      ;; #f in a slot means that kind of effect did not happen.
      (mutable effect-depths conn-tls-effect-depths conn-tls-set-effect-depths!)
      ;; carries a terminalised aggregate's callback OUT of the retirement
      ;; region, so user code runs outside it
      (mutable abort-cb conn-tls-abort-cb conn-tls-set-abort-cb!))
    (nongenerative)
    (sealed #t))

  ;; ---- TLS observation seams ---------------------------------------------
  ;;
  ;; ⭐ THE RECORDING IS GATED TOO, not just the reader. These counters sit on
  ;; the write and read paths -- once per raw write, once per SSL call -- so an
  ;; ordinary build compiles them out entirely and pays nothing. That differs
  ;; from tls-core's live-session counter deliberately: that one moves once per
  ;; connection and its recording is always on.
  ;;
  ;; Gating both halves together also means there is never a recorded fact
  ;; with no way to read it, nor a reader of a variable that was compiled out.
  (meta define tls-seam-mode
    (let ((v (getenv "IGROPYR_INJECT")))
      (if (and v (string=? v "on")) 'on 'off)))

  ;; The interrupt-disable depth. Safe to call INSIDE a region -- the probe
  ;; raises the count and lowers it again, so it never reaches 0 there.
  ;;
  ;; ⚠ AT DEPTH 0 THE PROBE IS NOT FREE: enable-interrupts reaching 0 may run
  ;; a pending interrupt, so calling it outside a region manufactures a
  ;; preemption point. That is harmless where the design already says the code
  ;; is preemptible, and it is why no assertion anywhere may read this and
  ;; conclude "depth is 0 here" about a line that must NOT be preemptible.
  (define (region-depth)
    (let ((n (disable-interrupts)))
      (enable-interrupts)
      (fx- n 1)))

  (meta-cond
    ((eq? tls-seam-mode 'on)
     (define raw-sink-writes 0)
     (define ssl-op-count 0)
     (define server-raw-reads 0)
     (define server-raw-read-bytes 0)
     (define accept-callback-completions 0)
     (define gate-opens 0)
     (define live-watchers 0)
     (define live-timers 0)
     (define active-timers 0)
     (define handshaking-count 0)
     (define (bump-raw-sink-writes!)
       (set! raw-sink-writes (fx+ raw-sink-writes 1)))
     (define (bump-ssl-op!) (set! ssl-op-count (fx+ ssl-op-count 1)))
     (define (bump-server-raw-read! n)
       (set! server-raw-reads (fx+ server-raw-reads 1))
       (set! server-raw-read-bytes (fx+ server-raw-read-bytes n)))
     (define (bump-accept-completion!)
       (set! accept-callback-completions (fx+ accept-callback-completions 1)))
     (define (bump-gate-open!) (set! gate-opens (fx+ gate-opens 1)))
     (define eof-deliveries 0)
     ;; every tcp-eof handed to an owner, counted once at the one place
     ;; that delivers it -- the row asserting "exactly one EOF" reads this
     (define (bump-eof-delivery!) (set! eof-deliveries (fx+ eof-deliveries 1)))
     ;; ⭐ WHAT THE NON-ESCAPING GUARDS SWALLOWED. Stopping exceptions from
     ;; unwinding into C is necessary, but it also destroyed the evidence:
     ;; a connection that raised twice in its read callback left NO trace --
     ;; no EOF, no retire reason, no error -- and looked exactly like a
     ;; connection that had simply gone quiet. The condition object is kept
     ;; as-is rather than rendered: rendering can itself fail, and this runs
     ;; in the one place that must not raise.
     (define swallowed-count 0)
     (define swallowed-where #f)
     (define swallowed-what #f)
     (define (note-swallowed! where e)
       (set! swallowed-count (fx+ swallowed-count 1))
       (set! swallowed-where where)
       (set! swallowed-what e))
     (define (tls-swallowed-errors)
       (list swallowed-count swallowed-where swallowed-what))

     ;; ⭐ A BOUNDED TRACE OF THE READ PATH'S STAGES. Two rounds of reasoning
     ;; from the source failed to explain a read that increments the raw-read
     ;; counter, swallows no exception, records no retirement, and never
     ;; reaches the decrypt -- each of those readings is consistent with the
     ;; code as written, which means the model is wrong somewhere invisible.
     ;; This records which stages were actually ENTERED, in order, instead of
     ;; inviting a third guess.
     (define read-trace '())
     (define read-trace-max 32)
     (define (note-read-stage! s)
       (set! read-trace
             (let ((l (append read-trace (list s))))
               (if (fx> (length l) read-trace-max) (cdr l) l))))
     (define (tls-read-trace) read-trace)
     (define (tls-eof-deliveries) eof-deliveries)
     (define (note-gate-open-ms! ms) (set! last-gate-open-ms ms))
     (define (bump-watchers! d) (set! live-watchers (fx+ live-watchers d)))
     (define (bump-live-timers! d) (set! live-timers (fx+ live-timers d)))
     (define (bump-active-timers! d) (set! active-timers (fx+ active-timers d)))
     (define (bump-handshaking! d) (set! handshaking-count (fx+ handshaking-count d)))
     (define (tls-raw-sink-writes) raw-sink-writes)
     (define (tls-ssl-op-count) ssl-op-count)
     (define (tls-server-raw-reads) (cons server-raw-reads server-raw-read-bytes))
     (define (tls-accept-callback-completions) accept-callback-completions)
     ;; ⭐ GLOBAL, AND IT HAS TO BE: the cell watching this is the CLIENT, and
     ;; a client has no handle on the server's conn record -- when the bug is
     ;; that no handler ever ran, there is nothing to ask for one. A count plus
     ;; the last opening's timestamp answers "did the gate open, and when"
     ;; without needing the connection.
     (define last-gate-open-ms #f)
     (define (tls-gate-open-mark) (cons gate-opens last-gate-open-ms))
     (define (tls-live-watcher-count) live-watchers)
     (define (tls-live-timer-count) live-timers)
     (define (tls-active-timer-count) active-timers)
     (define (tls-handshaking-count) handshaking-count)
     ;; ⛔ NO ABSOLUTE DEPTH SEAM. The event-loop process runs with
     ;; interrupts PERMANENTLY disabled (actor.sc's header), so inside a
     ;; callback frame the depth is always >= 1 and the 0->1 transition
     ;; never happens. A token keyed on "this entry left depth 0" would
     ;; never fire in the only host this code runs in -- measured in a
     ;; plain script, where depth starts at 0, it looked like it worked.
     ;; What survives is DIFFERENCES relative to a sampled entry depth.
     ;; (entry shared-min shared-max refusal-max session-retire-max
     ;;  uv-close-max); #f where that kind of effect never happened.
     (define (retire-entry-depth) (region-depth))
     (define (retire-depths-init! t entry)
       (conn-tls-set-effect-depths! t (vector entry #f #f #f #f #f)))
     (define (note-shared-depth! t)
       (let ((v (conn-tls-effect-depths t)) (d (region-depth)))
         (when v
           (let ((lo (vector-ref v 1)) (hi (vector-ref v 2)))
             (when (or (not lo) (fx< d lo)) (vector-set! v 1 d))
             (when (or (not hi) (fx> d hi)) (vector-set! v 2 d))))))
     (define (note-effect-depth! t kind)
       (let ((v (conn-tls-effect-depths t)) (d (region-depth)))
         (when v
           (let ((i (case kind ((refusal) 3) ((session-retire) 4) (else 5))))
             (let ((cur (vector-ref v i)))
               (when (or (not cur) (fx> d cur)) (vector-set! v i d)))))))
     ;; ⚠ READ IT OFF THE RECORD THE RETIREMENT WROTE, which means the caller
     ;; must hold the conn-tls state -- by the time retirement is done,
     ;; (conn-tls c) is #f. The cell keeps the record it was handed before the
     ;; close, which is why this takes the state and not the conn.
     ;; ⭐ REGISTERED BEFORE SUBMISSION, so a snapshot list never records a
     ;; block after its own inline completion. Each entry is
     ;; (id aggregate-id size pending sealed? completed?) sampled at
     ;; registration; the monotonic completion order is appended as blocks
     ;; finish, so the cell can read the ORDER rather than infer it.
     (define next-raw-block-id 0)
     (define raw-blocks-by-conn (make-eqv-hashtable))
     (define (note-raw-block! t agg size)
       (let ((id next-raw-block-id))
         (set! next-raw-block-id (fx+ id 1))
         (hashtable-set! raw-blocks-by-conn t
           (append (hashtable-ref raw-blocks-by-conn t '())
                   (list (list id (tls-agg-id agg) size
                               (tls-agg-pending agg)
                               (tls-agg-sealed? agg)
                               (tls-agg-done? agg)))))
         id))
     (define raw-completions-by-conn (make-eqv-hashtable))
     (define (note-raw-block-done! t agg sz status)
       (hashtable-set! raw-completions-by-conn t
         (append (hashtable-ref raw-completions-by-conn t '())
                 (list (list (tls-agg-id agg) sz status
                             (tls-agg-pending agg)
                             (tls-agg-sealed? agg)
                             (tls-agg-done? agg))))))
     ;; -> (registered . completed); registered in submission order, completed
     ;; in the order the completions actually ran.
     (define (tls-raw-blocks t)
       (cons (hashtable-ref raw-blocks-by-conn t '())
             (hashtable-ref raw-completions-by-conn t '())))
     (define (tls-conn-charge c)
       (let ((t (conn-tls c)))
         (and t (cons (conn-tls-bio-held t) (conn-tls-raw-queued t)))))
     (define (tls-conn-totals c)
       (let ((t (conn-tls c)))
         (and t (cons (conn-tls-charged t) (conn-tls-refunded t)))))
     (define (tls-conn-timer-id c)
       (let ((t (conn-tls c))) (and t (conn-tls-timer-id t))))
     ;; ⭐ GLOBAL AND ARGUMENT-FREE, for the reason the gate mark is: when the
     ;; question is "who closed this connection and why", the asker generally
     ;; cannot reach the connection any more -- retirement has detached it.
     (define last-retire-reason #f)
     (define (note-retire-reason! path reason)
       (set! last-retire-reason (cons path reason)))
     (define (tls-last-retire-reason) last-retire-reason)

     ;; Which listener incarnation holds which context. The identity that
     ;; matters is the INCARNATION's, not the handle's: a later listener at
     ;; the same address is a different generation with its own context, and
     ;; the row this serves is "exactly one reference, retired once per
     ;; generation".
     (define (tls-listener-context-id h)
       (let ((v (hashtable-ref listener-table h #f)))
         (and v (let ((ctx (vector-ref v 3)))
                  (and ctx (cons (vector-ref v 0) ctx))))))

     ;; ⭐ WHICH PATH GAVE THE TIMER BACK, because the two are not
     ;; interchangeable (Y4): an uninitialised handle is freed directly and
     ;; must never reach uv_close, while an initialised one must go out
     ;; through uv_close and be freed only by its close callback. A count of
     ;; timers cannot tell those apart; this records the route each one took.
     (define timer-free-paths '())
     (define (note-timer-free! how)
       (set! timer-free-paths (append timer-free-paths (list how))))
     (define (tls-timer-free-path) timer-free-paths)

     ;; Publication, as X2 defines it: membership of conn-table, asked by
     ;; handle so a cell can ask about a connection it no longer holds.
     (define (tls-conn-in-table? h)
       (and (hashtable-ref conn-table h #f) #t))
     (define (tls-retire-effect-depths t)
       (let ((v (and t (conn-tls-effect-depths t))))
         (and v (vector->list v)))))
    (else
     (define (bump-raw-sink-writes!) (void))
     (define (bump-ssl-op!) (void))
     (define (bump-server-raw-read! n) (void))
     (define (bump-accept-completion!) (void))
     (define (bump-gate-open!) (void))
     (define (bump-eof-delivery!) (void))
     (define (note-swallowed! where e) (void))
     (define (note-read-stage! s) (void))
     (define (note-gate-open-ms! ms) (void))
     (define (bump-watchers! d) (void))
     (define (bump-live-timers! d) (void))
     (define (bump-active-timers! d) (void))
     (define (bump-handshaking! d) (void))
     (define-syntax define-absent-seam
       (syntax-rules ()
         ((_ name)
          (define (name . _)
            (assertion-violation 'name
              "test seam: this artifact was expanded without IGROPYR_INJECT=on")))))
     (define-absent-seam tls-eof-deliveries)
     (define-absent-seam tls-swallowed-errors)
     (define-absent-seam tls-read-trace)
     (define-absent-seam tls-raw-sink-writes)
     (define-absent-seam tls-ssl-op-count)
     (define-absent-seam tls-server-raw-reads)
     (define-absent-seam tls-accept-callback-completions)
     (define-absent-seam tls-gate-open-mark)
     (define-absent-seam tls-live-watcher-count)
     (define-absent-seam tls-live-timer-count)
     (define-absent-seam tls-active-timer-count)
     (define-absent-seam tls-handshaking-count)
     (define (retire-entry-depth) 0)
     (define (retire-depths-init! t entry) (void))
     (define (note-shared-depth! t) (void))
     (define (note-retire-reason! path reason) (void))
     (define (note-timer-free! how) (void))
     (define-absent-seam tls-listener-context-id)
     (define-absent-seam tls-timer-free-path)
     (define-absent-seam tls-conn-in-table?)
     (define-absent-seam tls-last-retire-reason)
     (define (note-effect-depth! t kind) (void))
     (define (note-raw-block! t agg size) 0)
     (define (note-raw-block-done! t agg sz status) (void))
     (define-absent-seam tls-raw-blocks)
     (define-absent-seam tls-conn-charge)
     (define-absent-seam tls-conn-totals)
     (define-absent-seam tls-conn-timer-id)
     (define-absent-seam tls-retire-effect-depths)))

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

  ;; ⭐ WHO IS CALLING. The write gate has to record the HOLDER's pid so the
  ;; watcher can monitor it, and this library sits BELOW (igropyr actor) --
  ;; actor imports it, never the other way round -- so identity arrives the
  ;; same way delivery does: a hook the upper layer installs at startup.
  ;;
  ;; #f until installed. A pure libuv program never installs it and never
  ;; needs it: only an APPLICATION write on a TLS connection asks, and such a
  ;; write cannot exist without the actor layer. Asking while it is #f is
  ;; therefore a wiring error and says so, rather than proceeding with no
  ;; identity and a gate nobody can be monitored through.
  (define uv-self #f)
  (define (uv-set-self! proc) (set! uv-self proc))

  ;; ⭐ WHO MAKES THE WATCHER. Each established TLS connection needs one green
  ;; process, and it must link, monitor and park in a timed receive -- none of
  ;; which exists at this layer. (igropyr tls-watch) installs this hook when it
  ;; is invoked, and http.sc's TLS listen entry imports that library, so any
  ;; program that can open a TLS listener has necessarily installed it while a
  ;; plaintext or pure-libuv program pulls in nothing above actor.
  (define uv-tls-watcher-spawner #f)
  (define (uv-set-tls-watcher-spawner! proc) (set! uv-tls-watcher-spawner proc))

  ;; ⭐ HOW A PARKED WRITER WAITS. receive is an actor primitive and does not
  ;; exist at this layer, so the wait is supplied from above like identity and
  ;; the watcher are. It is legal to park here precisely because the writer is
  ;; a green process: the identity assertion above has already refused any
  ;; caller running inside a libuv callback frame.
  (define uv-gate-wait #f)
  (define (uv-set-gate-wait! proc) (set! uv-gate-wait proc))

  ;; ⭐ ARE WE IN A CALLBACK FRAME? Set around uv_run, which is the only place
  ;; libuv callbacks run from. This is used instead of comparing pids against
  ;; the event-loop process: it is the direct mechanism rather than an identity
  ;; test standing in for one, and it needs no second hook to tell us which pid
  ;; the loop is.
  (define in-uv-run? #f)

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
                   (when (and c (eq? (conn-owner c) owner))
                     ;; ⛔ THIS OVERRIDE DISABLES A REAL PROTECTION, and it
                     ;; exists only so a cell can make the WATCHER the sole
                     ;; supplier of the close and see whether it actually
                     ;; supplies it. With owner death closing the conn here
                     ;; AND the watcher aborting on DOWN, either one alone
                     ;; produces the same visible outcome -- so neither can be
                     ;; shown to work while the other is present. It is not a
                     ;; configuration switch: an ordinary build has no such
                     ;; branch at all.
                     (unless (inject-override! 'tls-owner-close-skip #f)
                       (tcp-close! c)))))
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
        ;; ⭐ MARKED BEFORE ANY BRANCH. "No tls-branch in the trace" has two
        ;; very different causes -- libuv never called us, or it called us and
        ;; we took the plaintext arm because the tls field was gone -- and the
        ;; existing marks cannot tell them apart. This one is entered on every
        ;; read callback whatever happens next.
        (note-read-stage! (if (fx> nread 0) 'cb+ (if (fx= nread 0) 'cb0 'cb-)))
        (let ((c (hashtable-ref conn-table stream #f)))
          (unless c (note-read-stage! 'cb-no-conn))
          (when c
            (let ((t (conn-tls c)))
              (unless t (note-read-stage! 'cb-plain))
              (cond
                ;; ⭐ THE TLS BRANCH COMES FIRST, AND DELIBERATELY DOES NOT
                ;; TEST conn-owner. A TLS connection has NO owner until its
                ;; handshake completes (Z12 installs it at establishment), so
                ;; the owner gate below would drop every handshake byte and
                ;; the handshake would never advance.
                (t (note-read-stage! 'tls-branch) (tls-on-read c t nread buf))
                ;; the plaintext path, unchanged: still owner-gated
                ((conn-owner c)
                 (cond
                   ((> nread 0)
                    (let ((bv (make-bytevector nread)))
                      (memcpy-from-c bv (foreign-ref 'void* buf 0) nread)
                      (deliver (conn-owner c) (vector 'tcp-data bv))))
                   ((= nread 0) (void))   ; spurious wakeup; ignore
                   ((= nread UV-EOF)
                    (deliver (conn-owner c) (vector 'tcp-eof)))
                   (else
                    (deliver (conn-owner c) (vector 'tcp-error nread)))))
                (else (void)))))))
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
       ;; ⛔ AN OUTER GUARD, BECAUSE THIS IS A FOREIGN CALLABLE FRAME. Before
       ;; tls-accept! is even entered, foreign-alloc and make-conn can raise
       ;; under allocation pressure, and an exception leaving here unwinds
       ;; into C. The handler does the least it can and cannot itself raise.
       (guard (e (#t (note-swallowed! 'on-connection e)
                     (set! accept-error-count (bump-saturating accept-error-count))
                     (void)))
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
                (let ((c (make-conn client #f 'open #f #f #f))
                      ;; #(token on-accept handshaking tls-ctx handle)
                      (v (hashtable-ref listener-table server #f)))
                  (uv-tcp-nodelay client 1)
                  (let ((ctx (incarnation-tls-ctx v)))
                    (cond
                      ((not v)
                       (hashtable-set! conn-table client c)
                       ;; listener already stopped: refuse the straggler
                       (tcp-close! c))
                      ;; ⭐ THE TLS PATH PUBLISHES ITSELF. X2 requires the
                      ;; session to be installed in the conn BEFORE the conn
                      ;; reaches conn-table, so that a failure before
                      ;; publication is cleaned up by the only code that can
                      ;; see the session. The insert therefore moves inside
                      ;; tls-accept! rather than happening here.
                      (ctx (tls-accept! c v ctx))
                      (else
                        (hashtable-set! conn-table client c)
                        ((vector-ref v 1) c))))))))))
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
                   (fs-finish! op req))
                  ;; ---- the three path-only operations ----------------
                  ;; Each delivers once and retires the op; none of them
                  ;; ever held a descriptor, so none goes near the close
                  ;; machinery above.
                  ((stat)
                   (if (< result 0)
                       (begin (uv-fs-req-cleanup req) (fs-fail! op req result))
                       (let ((sb (uv-fs-get-statbuf req)))
                         ;; ⭐ READ EVERY FIELD BEFORE THE CLEANUP. The
                         ;; statbuf belongs to the request; cleanup is
                         ;; free to release it, so a field fetched
                         ;; afterwards would be reading freed memory.
                         (let ((fields
                                (list
                                  (cons 'dev   (foreign-ref 'unsigned-64 sb uv-stat-dev-offset))
                                  (cons 'mode  (foreign-ref 'unsigned-64 sb uv-stat-mode-offset))
                                  (cons 'nlink (foreign-ref 'unsigned-64 sb uv-stat-nlink-offset))
                                  (cons 'uid   (foreign-ref 'unsigned-64 sb uv-stat-uid-offset))
                                  (cons 'gid   (foreign-ref 'unsigned-64 sb uv-stat-gid-offset))
                                  (cons 'ino   (foreign-ref 'unsigned-64 sb uv-stat-ino-offset))
                                  (cons 'size  (foreign-ref 'unsigned-64 sb uv-stat-size-offset))
                                  (cons 'mtime-sec  (foreign-ref 'long sb uv-stat-mtime-sec-offset))
                                  (cons 'mtime-nsec (foreign-ref 'long sb uv-stat-mtime-nsec-offset))
                                  (cons 'ctime-sec  (foreign-ref 'long sb uv-stat-ctime-sec-offset))
                                  (cons 'ctime-nsec (foreign-ref 'long sb uv-stat-ctime-nsec-offset)))))
                           (uv-fs-req-cleanup req)
                           (unless (fs-op-aborted? op)
                             (deliver (fs-op-owner op) (vector 'file-stat fields)))
                           (fs-cleanup! op req)))))
                  ((unlink)
                   (uv-fs-req-cleanup req)
                   (if (< result 0)
                       (fs-fail! op req result)
                       (begin
                         (unless (fs-op-aborted? op)
                           (deliver (fs-op-owner op) (vector 'file-unlinked)))
                         (fs-cleanup! op req))))
                  ((scandir)
                   (if (< result 0)
                       (begin (uv-fs-req-cleanup req) (fs-fail! op req result))
                       ;; ⛔ NOTHING MAY UNWIND OUT OF HERE INTO C. This is
                       ;; a libuv callback (see the file header); an
                       ;; exception crossing the C frame corrupts the
                       ;; process. The copy loop below allocates one
                       ;; Scheme string per entry, so on a large listing
                       ;; it is the most likely place in this file to run
                       ;; out of memory -- hence a guard that turns any
                       ;; raise into an errno the owner can read.
                       ;;
                       ;; ⚠ ORDER: copy every name, THEN clean up, THEN
                       ;; deliver. libuv owns the name buffers and
                       ;; uv_fs_req_cleanup frees them, so a name
                       ;; retained past the cleanup is a dangling
                       ;; pointer. Nothing here keeps one.
                       ;;
                       ;; ⚠ AND IT IS O(N) INSIDE THE CALLBACK. The
                       ;; scheduler is not running while this loop does;
                       ;; a directory of a million entries pauses the
                       ;; process for the length of a million string
                       ;; allocations. That is the cost of one message
                       ;; carrying a whole listing.
                       (let ((ent (foreign-alloc uv-dirent-size)))
                         (let ((names
                                (guard (e (#t 'oom))
                                  (let loop ((acc '()))
                                    (if (< (uv-fs-scandir-next req ent) 0)
                                        (reverse acc)
                                        (let ((p (foreign-ref 'void* ent
                                                   uv-dirent-name-offset)))
                                          (loop
                                            (cons (let rd ((i 0) (bs '()))
                                                    (let ((b (foreign-ref 'unsigned-8 p i)))
                                                      (if (fx= b 0)
                                                          (utf8->string
                                                            (u8-list->bytevector (reverse bs)))
                                                          (rd (fx+ i 1) (cons b bs)))))
                                                  acc))))))))
                           (foreign-free ent)
                           (uv-fs-req-cleanup req)
                           (unless (fs-op-aborted? op)
                             (deliver (fs-op-owner op)
                               (if (eq? names 'oom)
                                   (vector 'file-error uv-enomem)
                                   (vector 'file-entries names))))
                           (fs-cleanup! op req))))))))))
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
                 (let ((c (make-conn handle owner 'open #f #f #f)))
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

  ;; The per-conn TLS timer and its close callback. Both are locked with the
  ;; rest below: libuv holds their raw entry points, so a collected code
  ;; object would have the loop jump into freed memory.
  (define on-tls-timer-code
    (foreign-callable
      (lambda (handle) (on-tls-timer handle))
      (void*)
      void))

  (define on-tls-timer-close-code
    (foreign-callable
      (lambda (handle) (on-tls-timer-close handle))
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
      (lock-object on-tls-timer-code)
      (lock-object on-tls-timer-close-code)
      (lock-object on-walk-code)
      (vector on-alloc-code on-read-code on-close-code
              on-write-code on-connection-code on-connect-code
              on-getaddrinfo-code on-fs-code on-fsw-code
              on-timer-code on-walk-code
              on-tls-timer-code on-tls-timer-close-code)))

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
  (define on-tls-timer-entry (foreign-callable-entry-point on-tls-timer-code))
  (define on-tls-timer-close-entry
    (foreign-callable-entry-point on-tls-timer-close-code))
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
  ;; opts: (flags [tls-ctx]). The context is taken HERE rather than patched
  ;; in afterwards -- see the incarnation vector below for why.
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
        ;; ⭐ THE HANDSHAKING COUNT LIVES ON THIS OBJECT, not on the table
        ;; row (Y1). A handshaking conn holds a reference to this vector, so
        ;; the slot can still be released after the row is gone -- which is
        ;; exactly what happens when a listener is stopped while handshakes
        ;; are in flight. Slots 0/1 keep their meaning for every existing
        ;; reader; 2 is the count and 3 is the server context (#f = plaintext).
        ;; slot 4 is the handle this incarnation belongs to, so a conn
        ;; holding the incarnation can ask whether it is STILL the current one
        ;; (X3) without a reverse scan of the table.
        ;; ⛔ PUBLISHED COMPLETE, INCLUDING THE CONTEXT. Filling slot 3 after
        ;; this row was already in the table was a window, not an untidiness:
        ;; between publication and the patch the event loop can accept a
        ;; queued connection, read ctx = #f, and take the PLAINTEXT branch --
        ;; a plain HTTP request reaching the reader on an https port. The
        ;; caller's context therefore arrives as an argument and is in the
        ;; vector the moment anything can see it.
        (hashtable-set! listener-table l
          (vector (list 'listener) on-accept 0
                  (if (and (pair? opts) (pair? (cdr opts))) (cadr opts) #f)
                  l))
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
        ;; ⭐ THE INCARNATION OWNS ITS CONTEXT, so stopping it gives the
        ;; context back. Leaving that to the caller meant a direct
        ;; tcp-listen-tls! / tcp-stop-listen! lifecycle leaked one SSL_CTX per
        ;; generation, which contradicts the ownership this vector claims.
        (let ((v (hashtable-ref listener-table l #f)))
          (let ((ctx (and v (vector-ref v 3))))
            (when ctx (tls-context-retire! ctx))))
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

  ;; The three operations that need no descriptor: stat, unlink, scandir.
  ;; One routine because their submission sequence is identical and only
  ;; the libuv call at the end differs -- three copies would be three
  ;; places to keep the region discipline in step.
  ;;
  ;; ⛔ fd IS -1 HERE AND MUST STAY -1, and that is not cosmetic. When the
  ;; owner dies, uv-owner-died! reaches these ops through the same 'fs
  ;; arm as a stream read: file-stream-close! marks the op aborted, the
  ;; completion lands in fs-abort-step!, falls to its `else`, and calls
  ;; fs-quiet-close! -- whose FIRST test is (< fd 0), and which therefore
  ;; frees the request and delivers nothing. Give one of these ops an fd
  ;; and that same path will close a descriptor it does not own. The
  ;; reclaim path is correct for them BECAUSE the field is -1.
  ;;
  ;; ⚠ THE OPERATION IS THE PHASE, not the mode. fs-op-mode already means
  ;; whole|stream -- the read pipeline's chunking policy, read in four
  ;; places -- and on-fs-code dispatches on phase alone. These ops carry
  ;; mode 'whole, which nothing on their path ever reads.
  ;;
  ;; The state vector is allocated before the region for the reason
  ;; fs-start! gives: at that instant nothing is owned, so the only
  ;; residual is the guard's own entry allocation, the file-wide floor.
  (define (fs-start-simple! path owner phase)
    (let ((st (vector #f #f #f -1 #f)) (op #f) (rc 0))
      (with-interrupts-disabled
        (guard (e (#t (fs-undo! st owner) (raise e)))
          (set! op (make-fs-op owner path 'whole #f phase #f #f -1 0 0 '() 0 0))
          (vector-set! st 0 (owner-index-prepare! 'fs))
          (vector-set! st 1 (foreign-alloc fs-req-size))
          (fs-op-req-set! op (vector-ref st 1))
          (hashtable-set! fs-table (vector-ref st 1) op)
          (owner-index-publish! owner (vector-ref st 0) (vector-ref st 1))
          ;; INJECTION POINT 'fs-simple-submit-gap -- OWNING GUARD: the
          ;; guard above. Same window and same consequence as
          ;; 'fs-submit-gap-open: a published, unsubmitted op is only
          ;; flagged by file-stream-close!, so its row and request would
          ;; stay forever.
          (inject-fault! 'fs-simple-submit-gap)
          (set! rc
            (case phase
              ((stat)   (uv-fs-stat   uv-loop (vector-ref st 1) path on-fs-entry))
              ((unlink) (uv-fs-unlink uv-loop (vector-ref st 1) path on-fs-entry))
              (else     (uv-fs-scandir uv-loop (vector-ref st 1) path 0
                                       on-fs-entry))))
          ;; Set for the reason fs-start! sets it: the request is
          ;; initialised and safe to clean whatever the call returned.
          (vector-set! st 2 #t)
          (when (< rc 0)
            (fs-undo! st owner)
            ;; Inside the region, and for fs-start!'s reason: owner need
            ;; not be the caller, and it holds no handle to ask with.
            (deliver owner (vector 'file-error rc)))))
      op))

  ;; -> #(file-stat ,alist) or #(file-error ,errno) to owner.
  ;; ⭐ THE FIELDS ARE KEYED, NOT POSITIONAL. A consumer reads with assq,
  ;; so a field added later breaks nothing that reads the ones before it.
  ;; Times are delivered as seconds AND nanoseconds, unconverted: a
  ;; consumer wanting milliseconds does that arithmetic itself, and one
  ;; wanting the full resolution still has it.
  (define (file-stat-async! path owner) (fs-start-simple! path owner 'stat))

  ;; -> #(file-unlinked) or #(file-error ,errno) to owner.
  (define (file-unlink-async! path owner) (fs-start-simple! path owner 'unlink))

  ;; -> #(file-entries ,names) or #(file-error ,errno) to owner. Names
  ;; only, without "." or "..", in whatever order the filesystem gave.
  ;;
  ;; ⚠ EVERY ENTRY IS DELIVERED; there is no cap. A directory with a
  ;; million names produces a million strings, built inside the libuv
  ;; callback -- see the scandir arm for what that costs. Truncating and
  ;; reporting success would be worse: the consumer cannot tell a short
  ;; listing from a complete one. A directory big enough for that to
  ;; matter wants a batched opendir/readdir API, which this is not.
  (define (file-scandir-async! path owner) (fs-start-simple! path owner 'scandir))

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
  ;; ⭐ THE STATE VECTOR IS THE CALLER'S, AND IT IS OLDER THAN THE fd.
  ;; This function used to allocate it here, after it already owned the
  ;; descriptor -- so the one allocation that could fail while holding an
  ;; unclosable fd was the first thing it did. Now the caller builds the
  ;; vector BEFORE openat and only writes the fd into it once openat has
  ;; returned one, inside its own region. There is no moment at which
  ;; this function owns an fd and has not yet allocated the thing that
  ;; records it.
  ;;
  ;; ⭐ AND THAT IS WHY THE CALLER'S REGION IS NO LONGER LOAD-BEARING for
  ;; the fd. It was: the correctness of this function depended on being
  ;; called from inside one, which made it a part whose behaviour changed
  ;; with its context. It is self-contained now, and a cell can prove it
  ;; by deleting the caller's region and watching nothing leak.
  ;;
  ;; ⚠ WHAT REMAINS, and it is smaller than what was here before but not
  ;; nothing: entering the guard allocates a continuation, and that
  ;; allocation is outside the guard it establishes -- the same floor
  ;; every guard in this file stands on (see fs-start!). The fd IS owned
  ;; at that instant, because the caller transferred it before the call.
  ;; So the honest statement is that the window shrank from "a vector and
  ;; a continuation" to "a continuation", not that it closed.
  (define (fs-start-fd! st fd path owner mode)
    (with-interrupts-disabled
        (guard (e (#t (fs-undo! st owner) (raise e)))
          ;; INJECTION POINT 'fs-preregion-fd -- OWNING GUARD: this one,
          ;; and it is placed first on purpose: it stands for "the very
          ;; first thing after ownership raises", which is the case the
          ;; old shape could not survive. A cell arming it must see the
          ;; fd closed.
          (inject-fault! 'fs-preregion-fd)
          (let ((op (make-fs-op owner path mode #f 'fstat #f #f fd 0 0 '() 0 0)))
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
            (let ((rc (uv-fs-fstat uv-loop (vector-ref st 1)
                                   (fs-op-fd op) on-fs-entry)))
              (vector-set! st 2 #t)
              (when (< rc 0)
                (fs-undo! st owner)
                (deliver owner (vector 'file-error rc))))
            op))))

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
    ;; ⭐ THE STATE VECTOR IS BUILT BEFORE THE fd EXISTS. If this
    ;; allocation fails there is no descriptor yet to leak; built after
    ;; openat, the same failure would strand one. The two writes below
    ;; are the ownership transfer, and they happen only once openat has
    ;; actually returned a descriptor.
    (with-interrupts-disabled
      (let ((st (vector #f #f #f -1 #f)))
        (let ((fd (open-under root rel)))
          (and (>= fd 0)
               (begin
                 (vector-set! st 3 fd)
                 (vector-set! st 4 #t)
                 (fs-start-fd! st fd rel owner 'stream)))))))

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
  ;; ⛔ ASK WHETHER IT IS ALREADY READING; DO NOT DECODE AN ERRNO. Both the
  ;; accept path and the delayed on-accept start reading on a TLS connection,
  ;; so the second call is expected and must not read as a failure. An earlier
  ;; version compared the return against a hardcoded UV_EALREADY of -114 --
  ;; which is Linux's errno. EALREADY is 37 on macOS and on FreeBSD, where
  ;; every igropyr deployment runs, so on the machines that matter the normal
  ;; second start was counted as an error.
  ;;
  ;; uv_is_active answers the actual question and has no per-platform number
  ;; in it, so the redundant call is skipped rather than made and forgiven --
  ;; and any negative return that does happen is then a real failure.
  (define (tcp-read-start! c)
    (with-interrupts-disabled          ; test and use: see conn-peer-ip
      (if (not (eq? (conn-state c) 'open))
          #f
          (if (not (fx= 0 (uv-is-active (conn-handle c))))
              #t                        ; already reading: nothing to do
              (let ((r (uv-read-start (conn-handle c)
                                      on-alloc-entry on-read-entry)))
                (if (fx>= r 0)
                    #t
                    (begin (set! accept-error-count
                                 (bump-saturating accept-error-count))
                           #f)))))))

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
  ;; ⭐ THE RAW SINK. Bytes go out exactly as given: no codec, no gate, no
  ;; accounting. For a TLS connection these bytes are always CIPHERTEXT, and
  ;; every kind of it comes through here -- handshake records, close_notify,
  ;; and application records alike (W1). tls-raw-sink-writes counts them all,
  ;; which makes it a consistency check and NOT an oracle: the discriminator
  ;; for "handshake output went through the codec-aware entry by mistake" is
  ;; the handshake failing from double encryption, not this counter moving.
  (define (tcp-writev-raw! c segs on-done)
    (bump-raw-sink-writes!)
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
  ;; A TLS listener is an ordinary listener whose incarnation carries a
  ;; server context. The context belongs to THIS incarnation and is retired
  ;; once when the listener is stopped -- a listener that changes incarnation
  ;; without retiring leaks one context per generation.
  (define (tcp-listen-tls! host port backlog on-accept ctx . opts)
    (apply tcp-listen! host port backlog on-accept
           (if (pair? opts) (car opts) 0) ctx '()))

  ;; ---- the conn's one timer (X3 / Y3 / Y4 / Z2) ---------------------------
  ;;
  ;; ⭐ ONE TIMER FOR THE CONNECTION'S WHOLE LIFE. It is armed for the
  ;; handshake, STOPPED (not freed) on establishment, and re-armed for the
  ;; clean-shutdown deadline. So after a successful handshake the live timer
  ;; count is 1 and the active count is 0 -- allocating a second timer for
  ;; shutdown is the mutation that row exists to catch.
  (define tls-handshake-ms 10000)
  (define tls-shutdown-ms 2000)
  (define (tls-handshake-ms-set! n) (set! tls-handshake-ms n))
  (define (tls-shutdown-ms-set! n) (set! tls-shutdown-ms n))

  (define timer-conns (make-eqv-hashtable))   ; timer address -> conn
  (define next-timer-id 0)

  ;; ⭐ INIT FAILURE AND START FAILURE ARE NOT THE SAME BOOKKEEPING (Y4).
  ;; uv_timer_init failing means the handle was never initialised: it is freed
  ;; DIRECTLY and must not be handed to uv_close. A uv_timer_start failure
  ;; after a successful init means libuv owns it, so it goes out through
  ;; uv_close and the close callback frees the memory -- the same distinction
  ;; the listener allocation already makes.
  ;; -> the timer address, or #f (the caller closes the conn).
  (define (tls-timer-new! c ms)
    (let ((tm (foreign-alloc timer-handle-size)))
      (if (fx< (inject-override! 'tls-timer-init-fail
                                 (uv-timer-init uv-loop tm)) 0)
          (begin (note-timer-free! 'direct-free-uninitialised)
                 (foreign-free tm) #f)          ; never initialised
          (begin
            (bump-live-timers! 1)
            (hashtable-set! timer-conns tm c)
            (if (fx< (inject-override! 'tls-timer-start-fail
                                       (uv-timer-start tm on-tls-timer-entry ms 0)) 0)
                (begin
                  ;; initialised, so libuv owns it: out through uv_close
                  (hashtable-delete! timer-conns tm)
                  (uv-close tm on-tls-timer-close-entry)
                  #f)
                (begin (bump-active-timers! 1)
                       (conn-tls-set-timer-armed! (conn-tls c) #t)
                       tm))))))

  (define (tls-timer-stop! t)
    (let ((tm (conn-tls-timer t)))
      (when (and tm (conn-tls-timer-armed? t))
        (conn-tls-set-timer-armed! t #f)
        (uv-timer-stop tm)
        (bump-active-timers! -1))))

  ;; ⛔ ONE REGION, AND THE HANDLE IS RE-READ INSIDE IT. As three separate
  ;; steps this both drifted the count -- a timer due immediately could fire
  ;; and be closed before the armed flag was published, so nothing decremented
  ;; -- and, far worse, allowed uv_timer_start on freed memory: the handle was
  ;; captured, another process retired the connection, the close callback
  ;; freed it, and the original process then started it.
  (define (tls-timer-rearm! t ms)
    (with-interrupts-disabled
      (let ((tm (conn-tls-timer t)))     ; re-read: retirement sets it to #f
        (when (and tm (not (conn-tls-timer-armed? t)))
          (when (fx>= (uv-timer-start tm on-tls-timer-entry ms 0) 0)
            (conn-tls-set-timer-armed! t #t)
            (bump-active-timers! 1))))))

  ;; Idempotent, and the ONLY path that gives the timer back: stop, then
  ;; uv_close, and only the close callback frees the memory.
  (define (tls-timer-close! t)
    (let ((tm (conn-tls-timer t)))
      (when tm
        ;; ⛔ AN ARMED TIMER GIVES ITS ACTIVE COUNT BACK HERE. Closing one
        ;; without decrementing left active at 1 while live was already 0 --
        ;; which is what the clean-close path produced, because it RE-ARMS the
        ;; timer for the shutdown deadline and then closes it.
        (when (conn-tls-timer-armed? t)
          (conn-tls-set-timer-armed! t #f)
          (bump-active-timers! -1))
        (conn-tls-set-timer! t #f)
        (uv-timer-stop tm)
        (hashtable-delete! timer-conns tm)
        (uv-close tm on-tls-timer-close-entry))))

  (define on-tls-timer-close
    (lambda (tm)
      (bump-live-timers! -1)
      (note-timer-free! 'close-callback)
      (foreign-free tm)))

  (define on-tls-timer
    (lambda (tm)
      (let ((c (hashtable-ref timer-conns tm #f)))
        (when c
          (conn-tls-retire! c 'timer-expiry 'tls-timeout)))))

  ;; ---- the per-listener handshaking ceiling (Y1) --------------------------
  (define tls-handshake-max 1024)
  (define (tls-handshake-max-set! n) (set! tls-handshake-max n))

  (define (listener-incarnation h) (hashtable-ref listener-table h #f))
  (define (incarnation-tls-ctx v) (and v (vector-ref v 3)))
  (define (listener-handle-of v) (and v (vector-ref v 4)))

  ;; -> #t when a slot was taken. Refusal is the caller's business: an
  ;; over-ceiling conn is closed at once, with no SSL object created (X3).
  (define (listener-slot-take! v)
    (and v
         (with-interrupts-disabled
           (let ((n (vector-ref v 2)))
             (and (fx< n tls-handshake-max)
                  (begin (vector-set! v 2 (fx+ n 1))
                         (bump-handshaking! 1)
                         #t))))))

  ;; ⭐ RELEASED EXACTLY ONCE, and the flag that guarantees it lives on the
  ;; CONN, not on the listener: every exit path -- establishment, handshake
  ;; failure, timer expiry, hard or clean close, pre-publication failure --
  ;; converges here, and only the first of them decrements.
  ;; Released exactly once, and it reads the slot off the CONN so it works
  ;; both before and after the TLS record exists.
  (define (conn-slot-release! c)
    (let ((v (with-interrupts-disabled
               (let ((v (conn-slot c)))
                 (when v (conn-set-slot! c #f))
                 v))))
      (when v
        (vector-set! v 2 (fx- (vector-ref v 2) 1))
        (bump-handshaking! -1))))

  ;; ---- accepting a TLS connection ----------------------------------------
  ;;
  ;; ⛔ NOTHING HERE MAY RAISE INTO C. This runs in a libuv callback frame, so
  ;; every step that can raise -- session construction allocates and reads the
  ;; OpenSSL queue -- sits inside a guard that converts a raise into a local
  ;; close. Interrupt exclusion is no substitute: it has no rollback.
  (define (tls-accept! c v ctx)
    ;; ⛔ A FAILURE HERE IS AN ABORT, NOT A CLEAN CLOSE. Calling tcp-close!
    ;; was wrong in a way a cell caught: by this point conn-set-tls! has run,
    ;; so tcp-close! dispatched to the CLEAN-close path -- which sends a
    ;; close_notify on a session that never established, and recorded the
    ;; retirement as (clean-close . tls-closed). X2/X5 say the opposite: a
    ;; pre-publication failure retires the session and closes the unpublished
    ;; handle, with no alert, and the reason recorded is this one.
    ;; ⚠ THE HANDLER ITSELF MUST NOT RAISE. In R6RS a raise from the selected
    ;; guard clause propagates outward, so cleanup that can fail -- a deliver,
    ;; a close -- would escape this frame after all. It is wrapped again.
    (guard (e (#t (note-swallowed! 'tls-accept e)
                  (guard (e2 (#t (note-swallowed! 'tls-accept-cleanup e2)))
                    (if (conn-tls c)
                      (conn-tls-retire! c 'pre-publication e)
                      (begin
                        ;; nothing was attached, so retirement cannot run --
                        ;; but the slot may already be held (it is taken
                        ;; before any allocation), and it is released here or
                        ;; nowhere.
                        (note-retire-reason! 'pre-publication e)
                        (conn-slot-release! c)
                        (tcp-close-raw! c))))
                  #f))
      ;; ⭐ THE CEILING IS CHECKED BEFORE ANY SSL OBJECT EXISTS (X3): an
      ;; over-limit connection costs a handle and nothing else.
      (if (not (listener-slot-take! v))
          (begin (tcp-close-raw! c) #f)
          (begin
            ;; ⭐ THE SLOT IS RECORDED ON THE CONN BEFORE ANY ALLOCATION. It
            ;; used to be tracked only on the conn-tls record, which does not
            ;; exist yet -- so a raise between taking the slot and attaching
            ;; that record leaked the slot for the life of the listener, and
            ;; the ceiling drifted down one place per failure.
            (conn-set-slot! c v)
            (inject-fault! 'tls-accept-after-slot)
          (let ((sess (tls-session-new! ctx)))
            (let ((why (tls-session-configure-server! sess)))
              (if why
                  (begin
                    ;; same shape as above: nothing is published yet, so this
                    ;; is a direct retire-and-close, and it says so.
                    (note-retire-reason! 'pre-publication why)
                    (tls-session-retire! sess why)
                    (conn-slot-release! c)
                    (tcp-close-raw! c)
                    #f)
                  (let ((t (make-conn-tls
                             sess v
                             #f          ; established?
                             #f          ; eof?
                             #f          ; eof-sent?
                             #t          ; gated? -- Z12: nothing is delivered
                             '()         ; inbound
                             #f #f '()   ; holder, holder-monitor, waiters
                             #f #f #f    ; closed?, closing?, aggregate
                             #f          ; timer
                             (let ((i next-timer-id))
                               (set! next-timer-id (fx+ i 1)) i)
                             #f          ; timer-armed?
                             #f          ; watcher
                             0 0 0 0     ; bio-held raw-queued charged refunded
                             #t          ; slot? -- taken above
                             #f #f #f    ; gate-opened-ms, retire-path, reason
                             #f          ; effect-depths
                             #f)))       ; abort-cb
                    ;; ⭐ INSTALLED BEFORE THE CONN IS PUBLISHED (X2). Until
                    ;; conn-table has this handle nothing else in the process
                    ;; can reach the session, so a failure from here on is
                    ;; ours alone to clean up.
                    (conn-set-tls! c t)
                    (inject-fault! 'tls-accept-before-publish)
                    (hashtable-set! conn-table (conn-handle c) c)
                    (inject-fault! 'tls-accept-after-publish)
                    (let ((tm (tls-timer-new! c tls-handshake-ms)))
                      (if (not tm)
                          (begin (conn-tls-retire! c 'timer-failed 'tls-timer-failed) #f)
                          (begin
                            (conn-tls-set-timer! t tm)
                            ;; the handshake is driven by the read callback, so
                            ;; reading has to start before there is an owner
                            (tcp-read-start! c)
                            (tls-pump! c t)
                            #t)))))))))))

  ;; ⭐ CIPHERTEXT STRAIGHT INTO THE READ PATH, for rows that must control how
  ;; many raw reads a flight arrives in. TCP may split or coalesce whatever a
  ;; client writes, so "the client sent two records in one write" is not
  ;; something a cell can assert from the client side; this hands the bytes to
  ;; the same code the read callback would, in one delivery.
  (define (tls-inject-ciphertext! c bv)
    (guard (e (#t (note-swallowed! 'tls-inject e)
                  (guard (e2 (#t (note-swallowed! 'tls-inject-cleanup e2)))
                    (conn-tls-retire! c 'inject-raise 'tls-read-failed))
                  #f))
    (let ((t (conn-tls c)))
      (when t
        (bump-server-raw-read! (bytevector-length bv))
        (let ((werr (tls-session-feed! (conn-tls-session t) bv)))
          (if werr
              (conn-tls-retire! c 'feed-failed 'tls-read-failed)
              (tls-pump! c t)))))))

  ;; ---- the handshake driver and the read path ----------------------------
  (define (tls-on-read c t nread buf)
    ;; same shape as the accept guard: the handler's own cleanup is wrapped,
    ;; because a raise from a guard clause propagates out of this callback.
    (guard (e (#t (note-swallowed! 'tls-on-read e)
                  (guard (e2 (#t (note-swallowed! 'tls-on-read-cleanup e2)))
                    (conn-tls-retire! c 'read-raise 'tls-read-failed))
                  #f))
      (cond
        ((> nread 0)
         (let ((bv (make-bytevector nread)))
           (memcpy-from-c bv (foreign-ref 'void* buf 0) nread)
           (bump-server-raw-read! nread)
           (note-read-stage! 'data)
           (inject-fault! 'tls-read-step)
           (let ((werr (tls-session-feed! (conn-tls-session t) bv)))
             (note-read-stage! (if werr 'fed-err 'fed-ok))
             (if werr
                 (conn-tls-retire! c 'feed-failed 'tls-read-failed)
                 (tls-pump! c t)))))
        ((= nread 0) (note-read-stage! 'zero))
        ((= nread UV-EOF)
         (note-read-stage! 'fin)
         ;; ⭐ A BARE FIN IS NOT AN EOF. close_notify sets eof? on the way
         ;; through the read loop; without it the stream was cut, and saying
         ;; "eof" would let a truncated response read as a complete one.
         ;;
         ;; ⛔ AND IT WAITS FOR THE GATE. Delivering here while the gate is
         ;; shut put the EOF in front of plaintext that was still buffered.
         (if (conn-tls-eof? t)
             (tls-deliver-eof-once! c t)
             (let ((o (conn-owner c)))
               (when o (deliver o (vector 'tcp-error 'tls-truncated-eof)))
               (conn-tls-retire! c 'truncated-eof 'tls-truncated-eof))))
        (else (note-read-stage! 'err) (conn-tls-retire! c 'read-error nread)))))

  ;; Not established: step, drain to the raw sink, stop when OpenSSL wants
  ;; more. Established: decrypt and deliver or buffer.
  (define (tls-pump! c t)
    (note-read-stage! (if (conn-tls-established? t) 'pump-est 'pump-hs))
    (if (conn-tls-established? t)
        (tls-read-plaintext! c t)
        (let loop ()
          (bump-ssl-op!)
          ;; ⭐ THE OVERRIDE REPLACES BOTH VALUES, BEFORE ANY SUCCESS TEST
          ;; (W3). The real step runs -- the state is genuine -- and only the
          ;; verdict is forced; replacing a pair assembled after a success
          ;; branch had already been taken would change nothing.
          (let-values (((verdict payload)
                        (let-values (((v p) (tls-session-handshake-step!
                                              (conn-tls-session t))))
                          (let ((forced (inject-override! 'tls-handshake-result #f)))
                            (if forced (values forced #f) (values v p))))))
            ;; classify BEFORE draining, then send whatever the step produced
            ;; -- including the alert that explains a failure
            (let ((out (tls-session-drain! (conn-tls-session t))))
              (when out (tcp-writev-raw! c (list out) #f)))
            (case verdict
              ((done)
               (tls-established! c t)
               ;; ⭐ DECRYPT IMMEDIATELY, AND THIS LINE IS THE WHOLE OF X3/H13.
               ;; A client normally sends its request in the SAME flight as its
               ;; Finished, so by the time the handshake reports done those
               ;; bytes are ALREADY in the read BIO. There will be no further
               ;; read callback -- the client has said everything it intends to
               ;; and is waiting for the response -- so if nothing decrypts
               ;; here the request is never seen and both ends wait forever.
               ;; Measured before this line existed: handshake complete, two
               ;; raw reads with the request in the second, ssl-op-count frozen
               ;; at the handshake's three, and the client giving up after 4 s.
               ;;
               ;; The gate is still closed at this point (Z12), so what comes
               ;; out is buffered and the watcher delivers it in order.
               (tls-read-plaintext! c t))
              ((want-read) (void))                 ; wait for more ciphertext
              ((gone) (conn-tls-retire! c 'session-gone 'tls-conn-closed))
              ;; ⭐ want-write IS AN ERROR HERE (W3), not a state to wait in:
              ;; the write BIO is unbounded, so OpenSSL asking for room means
              ;; something this code does not model.
              (else
                (conn-tls-retire! c 'handshake-failed
                                  (or payload 'tls-handshake-failed))))))))

  ;; ⭐ ESTABLISHMENT ORDER (Z12). The callback may not yield, and a spawned
  ;; process only runs after it returns, so this installs the owner, asks for
  ;; a watcher, leaves the gate CLOSED and returns. The watcher opens the gate
  ;; and drains what was buffered -- which is why the first plaintext of a TLS
  ;; connection arrives one scheduling turn later than on a plaintext one
  ;; (declared residual R-h).
  (define (tls-established! c t)
    (conn-tls-set-established! t #t)
    (tls-timer-stop! t)                      ; stopped, NOT freed (Z2/Y3)
    (conn-slot-release! c)
    ;; revalidate the incarnation: the listener row can go during a handshake
    (let ((v (conn-tls-listener t)))
      (if (not (and v (eq? v (hashtable-ref listener-table
                                            (listener-handle-of v) #f))))
          (conn-tls-retire! c 'listener-gone 'tls-listener-stopped)
          (begin
            ((vector-ref v 1) c)             ; the delayed on-accept: owner in
            (unless uv-tls-watcher-spawner
              (assertion-violation 'tls-accept!
                "a TLS listener needs (igropyr tls-watch) imported: it installs the watcher spawner hook"))
            (conn-tls-set-watcher! t (uv-tls-watcher-spawner c))
            (bump-watchers! 1)
            ;; ⭐ THE LAST LINE OF THE CALLBACK FRAME, which is exactly what
            ;; H18(a) needs: it asserts this frame RETURNED before the watcher
            ;; ran. Establishment happens inside the read callback, so this --
            ;; not the accept callback -- is where that frame ends.
            ;;
            ;; ⚠ IT COUNTS ARRIVAL AT THIS LINE, NOT SUCCESS. Reading it as
            ;; "the owner was installed" would be reading more than it says.
            ;; It had no call site at all until now, so any earlier reading of
            ;; it was structurally 0 and meant nothing.
            (bump-accept-completion!)))))

  ;; EOF goes to the owner at most once, and only once the gate is open --
  ;; before that it stays recorded and the watcher delivers it after the
  ;; buffered plaintext, in order.
  (define (tls-deliver-eof-once! c t)
    (let ((send? (with-interrupts-disabled
                   (and (not (conn-tls-gated? t))
                        (not (conn-tls-eof-sent? t))
                        (begin (conn-tls-set-eof-sent! t #t) #t)))))
      (when send?
        (let ((o (conn-owner c))) (when o (deliver o (vector 'tcp-eof)))
          (bump-eof-delivery!)))))

  ;; Decrypt what arrived and either deliver it or hold it until the watcher
  ;; opens the gate.
  (define (tls-read-plaintext! c t)
    (note-read-stage! 'decrypt)
    (bump-ssl-op!)
    (let-values (((out eof?) (tls-session-decrypt! (conn-tls-session t) #vu8())))
      (when eof? (conn-tls-set-eof! t #t))
      ;; post-handshake protocol output (ticket acks, key updates)
      (let ((back (tls-session-drain! (conn-tls-session t))))
        (when back (tcp-writev-raw! c (list back) #f)))
      (when (fx> (bytevector-length out) 0)
        (if (conn-tls-gated? t)
            (conn-tls-set-inbound! t (append (conn-tls-inbound t) (list out)))
            (let ((o (conn-owner c)))
              (when o (deliver o (vector 'tcp-data out))))))
      (note-read-stage! (if eof? 'decrypt-eof 'decrypt-done))
      (when eof? (tls-deliver-eof-once! c t))))

  ;; ---- retirement of a TLS connection ------------------------------------
  ;;
  ;; ⭐ IDEMPOTENT BY SHAPE. The conn's tls field is the gate: the region below
  ;; detaches it, and whoever loses that race finds #f and does nothing. That
  ;; matters because owner death and watcher death can arrive together, so no
  ;; caller can promise to run this once -- "exactly once" here means exactly
  ;; one EFFECTIVE retirement, not one call.
  ;;
  ;; ⭐ THE REGION HOLDS SHARED-STATE EDITS ONLY (Delta 11). The refusal sends,
  ;; the session free and uv_close all happen after it: N sends and an
  ;; SSL_free inside one disabled region would be the widest region in this
  ;; file, and the waiter list has already been TAKEN, so nothing else can
  ;; answer those waiters no matter how long we take to do it.
  (define (conn-tls-retire! c path reason)
    (let* ((entry (retire-entry-depth))
           (taken
             (with-interrupts-disabled
               (let ((t (conn-tls c)))
                 (and t
                      (begin
                        (conn-set-tls! c #f)          ; <- the gate
                        ;; the accumulator lives ON THE RECORD, not in a
                        ;; module variable: the effects below are preemptible,
                        ;; so another conn's retirement can interleave with
                        ;; them and would clobber a shared one.
                        ;; ⭐ RECORDED IMMEDIATELY AFTER THE DETACH. It used
                        ;; to be written near the end of the region, so a
                        ;; failure in between left a retirement that had
                        ;; certainly happened with no reason attached -- and
                        ;; "no reason" reads exactly like "never retired".
                        (note-retire-reason! path reason)
                        (retire-depths-init! t entry)
                        (note-shared-depth! t)
                        (conn-tls-set-closed! t #t)
                        (conn-slot-release! c)
                        ;; the aggregate is shared state, so it is terminalised
                        ;; here; unconditionally on pending (Z4)
                        (let ((a (conn-tls-aggregate t)))
                          (when a
                            (conn-tls-set-abort-cb! t
                              (tls-agg-terminalise! a reason))))
                        ;; ⭐ ONLY THE WINNER WRITES THE REASON. A later
                        ;; idempotent call must not overwrite it with a
                        ;; generic one: the first cause is the one worth
                        ;; keeping.
                        (conn-tls-set-retire-path! t path)
                        (conn-tls-set-retire-reason! t reason)
                        (let ((ws (conn-tls-waiters t)))
                          (conn-tls-set-waiters! t '())
                          (note-shared-depth! t)
                          ;; ⭐ THE TIMER AND THE SESSION GO BACK INSIDE THE
                          ;; REGION. They are foreign calls that allocate no
                          ;; Scheme memory, so they do not break the rule the
                          ;; region exists for -- and leaving them outside was
                          ;; measured to be worse: once conn-tls is detached,
                          ;; a kill before them orphans the timer and the
                          ;; session forever, because every later retirement
                          ;; sees #f and does nothing, and the expiring timer
                          ;; routes back through the same detached field.
                          ;;
                          ;; ⚠ ONLY THE REFUSAL SENDS STAY OUTSIDE: they
                          ;; allocate, and there are as many of them as there
                          ;; are waiters.
                          (note-effect-depth! t 'session-retire)
                          (tls-session-retire! (conn-tls-session t)
                                               "tls: connection retired")
                          (when (conn-tls-timer t) (tls-timer-close! t))
                          (note-effect-depth! t 'uv-close)
                          (unless (eq? (conn-state c) 'closed)
                            (tcp-close-raw! c))
                          (cons t ws))))))))
      (when taken
        (let ((t (car taken)) (ws (cdr taken)))
          ;; whoever took the list answers it; these are sends, so they are
          ;; out here
          (for-each (lambda (w)
                      (note-effect-depth! t 'refusal)
                      (deliver (car w) (vector 'tcp-write-refused reason)))
                    ws)
          ;; ⭐ THE CURRENT HOLDER IS REFUSED TOO. A writer granted the gate is
          ;; no longer on the waiter list, so refusing only the list left it
          ;; parked forever whenever the process that granted it died between
          ;; recording it as holder and telling it so. Refusing the holder
          ;; closes that case; the residual -- a kill between the atomic take
          ;; and the send -- needs a deterministic handoff and is declared,
          ;; not fixed, here.
          (let ((h (conn-tls-holder t)))
            (when h
              (note-effect-depth! t 'refusal)
              (deliver h (vector 'tcp-write-refused reason))))
          ;; the aborted write's own callback, fired outside the region
          (let ((cb (conn-tls-abort-cb t)))
            (when cb
              (conn-tls-set-abort-cb! t #f)
              (cb (if (fixnum? reason) reason -1))))
          ;; the watcher's exit is a consequence of the close, never a
          ;; prerequisite: nothing below waits for it
          (let ((w (conn-tls-watcher t)))
            (when w (deliver w (vector 'tls-retire))))
          #t))))

  ;; ---- application writes on a TLS connection ----------------------------
  ;;
  ;; Bounded chunks so that computing the charge cannot itself create an
  ;; unbounded transient (W4/X4).
  (define tls-chunk-size 16384)

  ;; ONE aggregate per application write, however many TLS records it becomes
  ;; (X1). Raw completions -- which may run INLINE on a full uv_try_write --
  ;; may only decrement pending, record first-error, and mark completed? once
  ;; sealed? and pending = 0; they never call user code and never re-enter SSL.
  (define next-agg-id 0)
  (define (fresh-agg-id) (let ((i next-agg-id)) (set! next-agg-id (fx+ i 1)) i))

  (define-record-type (tls-agg make-tls-agg tls-agg?)
    (fields
      (immutable id tls-agg-id)
      (mutable pending tls-agg-pending tls-agg-set-pending!)
      (mutable sealed? tls-agg-sealed? tls-agg-set-sealed!)
      (mutable error tls-agg-error tls-agg-set-error!)
      (mutable done? tls-agg-done? tls-agg-set-done!)
      (mutable cb tls-agg-cb tls-agg-set-cb!))
    (nongenerative)
    (sealed #t))

  ;; ⭐ TERMINALISATION IS UNCONDITIONAL ON pending (Z4). An inline completion
  ;; can leave an unsealed aggregate at pending = 0, and an abort that skipped
  ;; it would let a surviving writer seal it later and fire the callback.
  ;; ⭐ -> THE CALLBACK TO FIRE, OR #f, AND THE CALLER FIRES IT OUTSIDE THE
  ;; REGION. Clearing cb without ever calling it meant an application write in
  ;; flight when the connection was retired NEVER completed: the raw
  ;; completion afterwards saw done? and did nothing, and the writer waited
  ;; for an answer that could not come. Terminalising is a shared-state edit
  ;; and belongs in the region; invoking user code does not.
  (define (tls-agg-terminalise! a why)
    (and (not (tls-agg-sealed? a))
         (let ((cb (tls-agg-cb a)))
           (unless (tls-agg-error a) (tls-agg-set-error! a why))
           (tls-agg-set-done! a #t)
           (tls-agg-set-cb! a #f)
           cb)))

  ;; The user callback runs exactly once, OUTSIDE the serialised unit, by
  ;; whichever side observes sealed? and pending = 0 first.
  (define (tls-agg-maybe-finish! a)
    (let ((cb (with-interrupts-disabled
                (and (tls-agg-sealed? a)
                     (fx= (tls-agg-pending a) 0)
                     (not (tls-agg-done? a))
                     (let ((cb (tls-agg-cb a)))
                       (tls-agg-set-done! a #t)
                       (tls-agg-set-cb! a #f)
                       cb)))))
      (when cb (cb (or (tls-agg-error a) 0)))))

  ;; Acquire the write gate. ONE interrupt-disabled step on shared state, and
  ;; the message to the watcher is only a ping (Z8): testing the gate and then
  ;; sending would lose the request when retirement runs between the two.
  ;;
  ;; -> 'held when this caller now holds it, 'refused with the reason, or
  ;; 'parked when it was appended to the waiter list.
  ;; -> the pid of the process making an APPLICATION write.
  ;;
  ;; ⛔ INTERNAL OUTPUT NEVER ASKS. Handshake records, close_notify and the
  ;; post-handshake protocol output go straight to the raw sink and take no
  ;; gate: they originate in a libuv callback frame, where the caller is the
  ;; event-loop process, and making that process a gate HOLDER would mean the
  ;; watcher monitoring the loop itself. The assertion below states that as a
  ;; mechanism rather than a convention -- if internal output ever reaches the
  ;; gate, it fails here instead of installing an unmonitorable holder.
  (define (tls-writer-identity)
    (when in-uv-run?
      (assertion-violation 'tls-gate-acquire!
        "internal TLS output must use the raw sink, not the write gate"))
    (unless uv-self
      (assertion-violation 'tls-gate-acquire!
        "an application write on a TLS connection needs the actor layer's identity hook (uv-set-self!); a pure libuv program cannot make one"))
    (uv-self))

  (define (tls-gate-acquire! t me agg)
    (with-interrupts-disabled
      (cond
        ((conn-tls-closed? t) (cons 'refused 'tls-conn-closed))
        ((conn-tls-closing? t) (cons 'refused 'tls-closing))
        ((conn-tls-holder t)
         ;; a pointer write on a cell the caller allocated before the region
         (conn-tls-set-waiters! t (append (conn-tls-waiters t) (list (cons me agg))))
         (cons 'parked #f))
        (else
          (conn-tls-set-holder! t me)
          (conn-tls-set-aggregate! t agg)
          (cons 'held #f)))))

  ;; ⭐ EVERY GRANT IS ANNOUNCED, INCLUDING THE UNCONTENDED ONE. Z5 requires
  ;; the holder to be monitored FROM THE MOMENT IT HOLDS, and the watcher is
  ;; the only process that can monitor on anyone's behalf. Recording a holder
  ;; without telling the watcher left the common case -- an uncontended
  ;; acquisition -- unwatched: a WebSocket sender that died mid-aggregate
  ;; produced no DOWN at all and the gate stayed held for the connection's
  ;; life. The rare contended path was watched and the ordinary one was not,
  ;; which is the worst way round.
  (define (tls-gate-announce-holder! t pid)
    (let ((w (conn-tls-watcher t)))
      (when w (deliver w (vector 'tls-gate-granted pid)))))

  ;; Application write. The gate is held for the WHOLE aggregate; preemption
  ;; between chunk units is preserved (Y5), so what is serialised is
  ;; aggregates, not steps.
  (define (tls-conn-writev! c t segs on-done)
    (let* ((agg (make-tls-agg (fresh-agg-id) 0 #f #f #f on-done))
           (me  (tls-writer-identity))
           (got (tls-gate-acquire! t me agg)))
      (when (eq? (car got) 'held) (tls-gate-announce-holder! t me))
      (case (car got)
        ((refused)
         (when on-done (on-done -1))
         #f)
        ((parked)
         ;; ⛔ A PARKED WRITER MUST WAIT. Writing anyway was a defect: two
         ;; writers on one connection would interleave their TLS records, and
         ;; serialising aggregates is the entire reason this gate exists
         ;; (Z3/Z5). It went unnoticed because HTTP allows one outstanding
         ;; write per connection, so the gate is uncontended there -- the
         ;; WebSocket senders it was built for are where it would have bitten.
         ;;
         ;; No timeout: every waiter gets exactly one outcome, because both
         ;; release and retirement answer whoever they atomically took off the
         ;; list (Z7/Z8).
         (tls-gate-ping! t)
         (unless uv-gate-wait
           (assertion-violation 'tls-conn-writev!
             "an application write on a TLS connection needs the actor layer's gate wait hook (uv-set-gate-wait!), installed by (igropyr tls-watch)"))
         (let ((answer (uv-gate-wait)))
           (if (eq? answer 'held)
               (tls-conn-write-chunks! c t agg segs on-done)
               (begin (when on-done (on-done -1)) #f))))
        (else
          (tls-conn-write-chunks! c t agg segs on-done)))))

  ;; The watcher tells us it is gone. Without this the live count only ever
  ;; rises, and a reading of 1 after retirement says nothing about whether the
  ;; watcher actually exited -- which is exactly how it was read once.
  (define (tls-watcher-exited! c) (bump-watchers! -1))

  ;; ---- what the watcher may touch ----------------------------------------
  ;;
  ;; ⭐ THE WATCHER LIVES ABOVE actor AND TOUCHES NO RECORD FIELD. It reaches
  ;; the connection's shared state only through the operations below, which
  ;; are the same ones writers use, so there is exactly one discipline for the
  ;; gate rather than one per caller.

  ;; -> the entry granted the gate (pid . aggregate), or #f. Takes it in one
  ;; step, so a retirement racing this either finds the entry on the list or
  ;; does not see it at all.
  (define (tls-gate-grant-next! c)
    (let ((t (conn-tls c)))
      (and t
           (with-interrupts-disabled
             (let ((ws (conn-tls-waiters t)))
               (cond
                 ((or (null? ws) (conn-tls-closed? t) (conn-tls-holder t)) #f)
                 (else
                   (conn-tls-set-waiters! t (cdr ws))
                   (conn-tls-set-holder! t (car (car ws)))
                   (conn-tls-set-aggregate! t (cdr (car ws)))
                   (car ws))))))))

  ;; The live shared list's length -- read off the list itself, never off a
  ;; count kept beside it: a separate counter zeroed at teardown would answer
  ;; for a list that still had entries on it.
  (define (tls-gate-waiters-length c)
    (let ((t (conn-tls c)))
      (if (not t) 0 (with-interrupts-disabled (length (conn-tls-waiters t))))))

  (define (tls-conn-holder c)
    (let ((t (conn-tls c))) (and t (conn-tls-holder t))))

  (define (tls-conn-holder-monitor c)
    (let ((t (conn-tls c))) (and t (conn-tls-holder-monitor t))))

  (define (tls-conn-set-holder-monitor! c m)
    (let ((t (conn-tls c))) (when t (conn-tls-set-holder-monitor! t m))))

  ;; ⭐ GATE-OPEN AND THE ORDERED DRAIN ARE ONE TRANSITION (Z14). libuv
  ;; callbacks run only when the scheduler polls the loop, which cannot happen
  ;; inside this region, so no read callback can slip new plaintext between
  ;; clearing the flag and the last buffered send: bytes either arrived before
  ;; (buffered, drained here, in order) or after (delivered directly).
  ;; ⭐ THE GATE STAYS SHUT UNTIL THE BUFFER IS EMPTY. Taking the batch and
  ;; opening the gate in one region, then delivering outside it, let newer
  ;; plaintext overtake older: the watcher was preempted after opening and a
  ;; read callback delivered B directly while A was still in its hand, so the
  ;; owner saw B before A. Z14's argument covers the region; it did not cover
  ;; the window between leaving the region and the last send. Now each round
  ;; takes a batch with the gate STILL CLOSED, delivers it, and only opens the
  ;; gate once a round finds nothing left -- so anything arriving meanwhile is
  ;; appended to the buffer and cannot pass what is already in flight.
  ;;
  ;; ⛔ THE OWNER IS CHECKED BEFORE THE BUFFER IS TAKEN. Clearing first and
  ;; then finding no owner discarded that plaintext permanently. on-accept is
  ;; external code and may simply not install one, so the connection is
  ;; retired instead -- with a reason a cell can read.
  (define (tls-open-gate-and-drain! c)
    (let ((t (conn-tls c)))
      (when t
        (if (not (conn-owner c))
            (conn-tls-retire! c 'no-owner 'tls-no-owner)
            (let loop ()
              (let ((batch (with-interrupts-disabled
                             (let ((held (conn-tls-inbound t)))
                               (conn-tls-set-inbound! t '())
                               held))))
                (cond
                  ((pair? batch)
                   (let ((o (conn-owner c)))
                     (for-each (lambda (bv) (deliver o (vector 'tcp-data bv)))
                               batch))
                   (loop))
                  (else
                    (with-interrupts-disabled
                      (conn-tls-set-gated! t #f)
                      (conn-tls-set-gate-opened-ms! t (now-ms))
                      (bump-gate-open!)
                      (note-gate-open-ms! (now-ms)))
                    ;; the recorded close_notify, now that order is safe
                    (when (conn-tls-eof? t)
                      (tls-deliver-eof-once! c t))))))))))

  ;; Best-effort nudge. A lost ping costs latency only: the watcher has a
  ;; timed receive and re-reads the waiter list on every wake (Z8).
  (define (tls-gate-ping! t)
    ;; ⛔ SUPPRESSION IS A TEST CONTROL, NOT A FAILURE MODE. Armed, it drops
    ;; the ping so a waiter can only be woken by a release -- which is how the
    ;; row that claims "a lost ping costs latency only" is made to prove it
    ;; rather than assert it.
    (unless (inject-override! 'tls-ping-suppress #f)
      (let ((w (conn-tls-watcher t)))
        (when w (deliver w (vector 'tls-gate-ping))))))

  ;; Release the gate and hand it to the next waiter, in ONE step on the shared
  ;; state; the reply to the woken writer is sent OUTSIDE it.
  ;;
  ;; ⭐ WHOEVER TAKES THE ENTRY IS THE ONE WHO ANSWERS IT. The list is read and
  ;; rewritten inside the region, so a retirement racing this either finds the
  ;; entry still on the list (and refuses it) or does not see it at all (and
  ;; this call answers it). There is no test of whether the watcher is alive
  ;; and no way for a waiter to get two answers.
  (define (tls-gate-release! c t)
    ;; the holder is stepping down, so its monitor should go with it --
    ;; otherwise a writer that finishes and later exits produces a DOWN for a
    ;; connection it no longer has anything to do with.
    (let ((w (conn-tls-watcher t)))
      (when w (deliver w (vector 'tls-gate-released))))
    (let ((next (with-interrupts-disabled
                  (conn-tls-set-holder! t #f)
                  (conn-tls-set-holder-monitor! t #f)
                  (conn-tls-set-aggregate! t #f)
                  (let ((ws (conn-tls-waiters t)))
                    (cond
                      ((null? ws) #f)
                      ((conn-tls-closed? t) #f)
                      (else
                        (conn-tls-set-waiters! t (cdr ws))
                        (conn-tls-set-holder! t (car (car ws)))
                        (conn-tls-set-aggregate! t (cdr (car ws)))
                        (car ws)))))))
      (cond
        (next
          (deliver (car next) (vector 'tls-gate-held))
          ;; the new holder is monitored by the watcher, not by us (Z5)
          (tls-gate-announce-holder! t (car next)))
        (else
          ;; ⭐ A CLEAN CLOSE THAT WAS WAITING FOR THIS RELEASE FINISHES HERE,
          ;; and until now nothing did it. tls-conn-close-clean! returns when a
          ;; holder is mid-aggregate, and its comment said "its release finds
          ;; the closing flag and finishes the shutdown" -- a mechanism that
          ;; did not exist, so the connection was left open with no
          ;; close_notify, no retirement and no uv_close. The comment was
          ;; describing an intention; this is the code.
          (when (and (conn-tls c) (conn-tls-closing? t))
            (tls-conn-finish-shutdown! c t))))))

  (define (tls-conn-write-chunks! c t agg segs on-done)
    (let loop ((ss segs) (off 0))
      (cond
        ((null? ss)
         ;; sealing is the whole-aggregate act; the callback fires outside it
         (with-interrupts-disabled (tls-agg-set-sealed! agg #t))
         (tls-gate-release! c t)
         (tls-agg-maybe-finish! agg)
         #t)
        (else
          (let* ((bv (car ss))
                 (n (bytevector-length bv))
                 (take (fxmin tls-chunk-size (fx- n off))))
            ;; ⭐ ONE OUTER REGION PER CHUNK UNIT (Y5), and its FIRST act is
            ;; the field test (Delta 12). A conn retired between two chunks
            ;; must not start another one: the session it would write into has
            ;; been freed. The field is the same one retirement detaches, so
            ;; this needs no second agreement with the retirement path.
            (let ((r (with-interrupts-disabled
                       (inject-fault! 'tls-chunk-step)
                       (if (not (conn-tls c))
                           'retired
                           (let ((piece (if (and (fx= off 0) (fx= take n))
                                            bv
                                            (let ((b (make-bytevector take)))
                                              (bytevector-copy! bv off b 0 take)
                                              b))))
                             (bump-ssl-op!)
                             ;; no override here: forcing the CLASSIFICATION
                             ;; of SSL_write is done where the classification
                             ;; happens, inside (igropyr tls-core). Replacing
                             ;; the ciphertext at this level would leave the
                             ;; success branch already taken.
                             (let ((out (tls-session-encrypt!
                                          (conn-tls-session t) piece)))
                               (tls-agg-set-pending!
                                 agg (fx+ (tls-agg-pending agg) 1))
                               ;; ⭐ THE BLOCK IS REGISTERED BEFORE IT IS
                               ;; SUBMITTED. uv_try_write can complete INLINE,
                               ;; so a completion can run before this call
                               ;; returns -- registering afterwards would
                               ;; record the block after its own completion
                               ;; had already been recorded, and the ordering
                               ;; the cell reads would be a lie.
                               (let ((sz (bytevector-length out)))
                                 (note-raw-block! t agg sz)
                                 (inject-fault! 'tls-between-chunks)
                                 ;; ⭐ CHARGED ONLY ONCE THE SUBMISSION IS
                                 ;; ACCEPTED. Charging before this point left
                                 ;; the money unrecoverable when anything
                                 ;; between the two raised: the completion
                                 ;; that refunds is installed BY this call, so
                                 ;; a raise before it means no completion will
                                 ;; ever exist to give it back.
                                 (tls-conn-charge! t sz)
                                 ;; ⭐ THE SIZE TRAVELS IN THE CLOSURE. A side
                                 ;; table keyed by (conn . aggregate) would
                                 ;; answer for the LAST block of an aggregate,
                                 ;; refunding the wrong amount whenever an
                                 ;; application write became more than one
                                 ;; record -- which is the normal case.
                                 (tcp-writev-raw!
                                   c (list out)
                                   (lambda (status)
                                     (tls-raw-done! c t agg sz status))))
                               'wrote))))))
              (cond
                ((eq? r 'retired)
                 ;; the stored reason is the whole answer; the aggregate is
                 ;; terminal and the gate is already closed by the retirement
                 (let ((cb (tls-agg-terminalise! agg 'tls-conn-closed)))
                   (when cb (cb -1)))
                 #f)
                ((fx< (fx+ off take) n) (loop ss (fx+ off take)))
                (else (loop (cdr ss) 0)))))))))

  ;; Accounting transfers (X4): ciphertext produced is bio-held until it is
  ;; submitted, then raw-queued until its completion runs.
  (define (tls-conn-charge! t n)
    (conn-tls-set-raw-queued! t (fx+ (conn-tls-raw-queued t) n))
    (conn-tls-set-charged! t (fx+ (conn-tls-charged t) n)))

  ;; ⭐ THE REFUND HAPPENS ON EVERY OUTCOME (X4), and it is asserted BEFORE
  ;; teardown clears the counters: charged-total and refunded-total are
  ;; monotonic, so a skipped refund shows up as an inequality that teardown
  ;; cannot hide.
  (define (tls-raw-done! c t agg sz status)
    (with-interrupts-disabled
      (tls-agg-set-pending! agg (fx- (tls-agg-pending agg) 1))
      (when (and (fx< status 0) (not (tls-agg-error agg)))
        (tls-agg-set-error! agg status)))
    (tls-conn-refund! t sz)
    ;; ⭐ THE COMPLETION IS APPENDED, so the snapshot carries the ORDER blocks
    ;; finished in rather than leaving a reader to infer it from registration
    ;; order. Inline completions make those two orders differ, which is the
    ;; whole reason the registration happens before the submit.
    (note-raw-block-done! t agg sz status)
    (inject-fault! 'tls-after-refund)
    (tls-agg-maybe-finish! agg))

  (define (tls-conn-refund! t n)
    (when t
      (with-interrupts-disabled
        (conn-tls-set-raw-queued! t (fx- (conn-tls-raw-queued t) n))
        (conn-tls-set-refunded! t (fx+ (conn-tls-refunded t) n)))))

  ;; ⭐ THE CODEC-AWARE ENTRY, and the only one an application should call.
  ;; A plaintext connection goes straight to the raw sink, which is exactly
  ;; what it did before this split -- one field test more. A TLS connection
  ;; has its plaintext encrypted first, under the conn's write gate, and the
  ;; ciphertext reaches the socket through the raw sink above.
  ;;
  ;; ⚠ THE TEST IS THE FIELD, not a flag someone sets alongside it: the same
  ;; field retirement detaches. A conn retired mid-write therefore stops being
  ;; a TLS conn for every subsequent write, which is the behaviour the chunk
  ;; loop relies on (Delta 12).
  (define (tcp-writev! c segs on-done)
    (let ((t (conn-tls c)))
      (if t
          (tls-conn-writev! c t segs on-done)
          (tcp-writev-raw! c segs on-done))))

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
  ;; ⭐ A TLS CONNECTION CLOSES CLEANLY, A PLAINTEXT ONE CLOSES. The dispatch
  ;; is on the same field retirement detaches, so a conn already retired takes
  ;; the plain path -- which is what retirement itself relies on when it calls
  ;; this after detaching.
  (define (tcp-close! c)
    (if (conn-tls c)
        (tls-conn-close-clean! c)
        (tcp-close-raw! c)))

  (define (tcp-close-raw! c)
    (with-interrupts-disabled
      (when (and (eq? (conn-state c) 'open)
                 (= 0 (uv-is-closing (conn-handle c))))
        (conn-set-state! c 'closing)
        (uv-close (conn-handle c) on-close-entry))))

  ;; ⭐ CLEAN CLOSE REFUSES THE ALREADY-PARKED (Z9). Entering the closing
  ;; state refuses EVERY waiter already on the list, in the same step that
  ;; sets the flag -- refusing only new acquirers would leave whoever was
  ;; parked at that instant waiting for a gate that will never be granted.
  ;; Only the current holder's aggregate is allowed to seal.
  ;;
  ;; The alert then goes out under the shutdown deadline, on the SAME timer
  ;; the handshake used (Y3): re-armed, not re-allocated.
  (define (tls-conn-close-clean! c)
    (let* ((t (conn-tls c))
           (parked (and t (with-interrupts-disabled
                            (conn-tls-set-closing! t #t)
                            (let ((ws (conn-tls-waiters t)))
                              (conn-tls-set-waiters! t '())
                              ws)))))
      (when t
        (for-each (lambda (w)
                    (deliver (car w) (vector 'tcp-write-refused 'tls-closing)))
                  (or parked '()))
        (if (conn-tls-holder t)
            ;; a holder is mid-aggregate: it seals, and its release finds the
            ;; closing flag and finishes the shutdown. Nothing is torn here --
            ;; a half-emitted application frame on the wire is worse than a
            ;; late close.
            (void)
            (tls-conn-finish-shutdown! c t)))))

  (define (tls-conn-finish-shutdown! c t)
    (bump-ssl-op!)
    (tls-session-shutdown! (conn-tls-session t))
    (inject-fault! 'tls-closenotify-delay)
    (let ((out (tls-session-drain! (conn-tls-session t))))
      (when out (tcp-writev-raw! c (list out) #f)))
    (tls-timer-rearm! t tls-shutdown-ms)
    (conn-tls-retire! c 'clean-close 'tls-closed))
)
