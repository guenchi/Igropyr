#!chezscheme
;;; (igropyr platform) -- supported-host detection and shared-library loading.

(library (igropyr platform)
  (export platform-os platform-arch ensure-supported-platform!
          so-listenqlimit sol-socket
          load-first-shared-object! shared-object-candidates
          addrinfo-address-offset addrinfo-next-offset
          uv-stat-dev-offset uv-stat-mode-offset uv-stat-nlink-offset
          uv-stat-uid-offset uv-stat-gid-offset uv-stat-ino-offset
          uv-stat-size-offset
          uv-stat-mtime-sec-offset uv-stat-mtime-nsec-offset
          uv-stat-ctime-sec-offset uv-stat-ctime-nsec-offset
          uv-dirent-size uv-dirent-name-offset
          ;; child processes
          uv-process-options-size
          uv-po-exit-cb-offset uv-po-file-offset uv-po-args-offset
          uv-po-env-offset uv-po-cwd-offset uv-po-flags-offset
          uv-po-stdio-count-offset uv-po-stdio-offset
          uv-po-uid-offset uv-po-gid-offset
          uv-stdio-container-size uv-sc-flags-offset uv-sc-data-offset
          UV-IGNORE UV-CREATE-PIPE UV-INHERIT-FD
          UV-READABLE-PIPE UV-WRITABLE-PIPE
          uv-handle-queue-next-offset uv-handle-queue-prev-offset)
  (import (chezscheme) (igropyr util))

  (define machine-name (symbol->string (machine-type)))

  (define platform-os
    (cond
      ((string-suffix? "osx" machine-name) 'macos)
      ((string-suffix? "fb" machine-name) 'freebsd)   ; ta6fb / tarm64fb
      ((string-suffix? "le" machine-name) 'linux)
      (else 'unsupported)))

  (define platform-arch
    (cond
      ((string-contains? machine-name "arm64") 'arm64)
      ((string-contains? machine-name "a6") 'x86_64)
      (else 'unsupported)))

  (define (ensure-supported-platform!)
    (unless (and (memq platform-os '(macos linux freebsd))
                 (memq platform-arch '(x86_64 arm64)))
      (assertion-violation 'igropyr
        "unsupported platform; expected Chez Scheme 10 on macOS/Linux/FreeBSD x86_64/arm64"
        (machine-type))))

  ;; Filename candidates for an OpenSSL-family library, most specific first.
  ;; Homebrew keeps openssl@3 keg-only, so its lib directory is not on the
  ;; default search path and has to be named outright; elsewhere the soname
  ;; carries the ABI version and the bare name is the last resort (a system
  ;; without a -dev package often ships only the versioned file).
  ;; Every caller needing libcrypto/libssl shares this list: a fix for one
  ;; platform's layout must not have to be repeated per module.
  (define (shared-object-candidates base)
    (case platform-os
      ((macos) (list (string-append "/opt/homebrew/opt/openssl@3/lib/" base ".3.dylib")
                     (string-append "/usr/local/opt/openssl@3/lib/" base ".3.dylib")
                     (string-append base ".3.dylib")
                     (string-append base ".dylib")))
      (else    (list (string-append base ".so.3")
                     (string-append base ".so.1.1")
                     (string-append base ".so")))))

  ;; Try names in order and report every candidate when none can be loaded.
  (define (load-first-shared-object! who candidates)
    (let loop ((xs candidates))
      (cond
        ((null? xs)
         (assertion-violation who "could not load any shared library candidate"
                              candidates))
        ((guard (e (#t #f)) (load-shared-object (car xs)) #t) (car xs))
        (else (loop (cdr xs))))))

  ;; LP64 struct addrinfo layouts differ in the ordering of ai_addr and
  ;; ai_canonname. macOS and FreeBSD put ai_canonname first, so ai_addr
  ;; sits at 32; Linux orders ai_addr first, at 24. ai_next is at 40 on
  ;; all three.
  ;;
  ;; NOTHING CHECKS THIS AT RUN TIME. The addrinfo comes from the
  ;; resolver; a wrong offset makes addrinfo->ipv4 read the wrong field
  ;; of it -- ai_canonname, a null, whatever sits there -- and use that
  ;; as a sockaddr*, which is a wrong address or a fault inside the FFI
  ;; call. To check one, print offsetof(struct addrinfo, ai_addr) and
  ;; ai_next from C on that target; this comment is not evidence.
  (define addrinfo-address-offset
    (case platform-os ((macos freebsd) 32) ((linux) 24) (else 0)))
  (define addrinfo-next-offset 40)

  ;; SO_LISTENQLIMIT: the socket option that reports a listening socket's
  ;; ACTUAL accept-queue limit -- what the kernel kept after clamping the
  ;; backlog listen() was given to kern.ipc.soacceptqueue. FreeBSD has it;
  ;; Linux and macOS have no equivalent (checked on macOS: undefined).
  ;;
  ;; #f MEANS "NOT KNOWN HERE", AND THAT IS DELIBERATELY NOT A GUESS.
  ;; A wrong option number does not fail loudly: getsockopt would answer
  ;; for whatever option that number names and hand back a plausible
  ;; integer, which the caller would report as the effective backlog. The
  ;; number must come from the target's own headers:
  ;;
  ;;   echo '#include <sys/socket.h>
  ;;   #include <stdio.h>
  ;;   int main(){printf("%d\n", SO_LISTENQLIMIT);}' > /tmp/q.c \
  ;;     && cc -o /tmp/q /tmp/q.c && /tmp/q
  ;;
  ;; Until that value is filled in, callers get #f, which reports "cannot
  ;; be read here" -- the honest answer, and one that no reader will
  ;; mistake for a measurement.
  (define so-listenqlimit
    (case platform-os
      ;; 4113 = 0x1011, printed from <sys/socket.h> on FreeBSD 15.0.
      ;; SO_LISTENQLEN is 4114 -- adjacent -- and SO_LISTENINCQLEN is
      ;; 4115, two away. Both report queue DEPTH, not the limit, so an
      ;; off-by-one here returns a real, plausible, wrong number rather
      ;; than an error.
      ((freebsd) 4113)
      (else #f)))

  ;; SOL_SOCKET, needed as the `level` argument alongside the option
  ;; above. It is 0xffff on the BSDs and 1 on Linux, but it is left
  ;; unset for the same reason: this pair is only ever used together,
  ;; and a level that is wrong in the same silent way as a wrong option
  ;; number buys nothing. Read it from <sys/socket.h> on the target when
  ;; so-listenqlimit is filled in, and fill in both at once.
  (define sol-socket
    (case platform-os
      ((freebsd) 65535)                 ; 0xffff, from the same header
      (else #f)))

  ;; ---- uv_stat_t ------------------------------------------------------
  ;; libuv's own struct, not the platform's: twelve uint64_t fields, then
  ;; four uv_timespec_t. Read from include/uv.h of libuv 1.52.1 (the
  ;; version on the deployment machines) and cross-checked against 1.50.0
  ;; locally -- the declaration is identical.
  ;;
  ;;   uint64_t st_dev st_mode st_nlink st_uid st_gid st_rdev
  ;;            st_ino st_size st_blksize st_blocks st_flags st_gen
  ;;   uv_timespec_t st_atim st_mtim st_ctim st_birthtim
  ;;
  ;; THE TIMESTAMP OFFSETS ARE 64-BIT-SPECIFIC and the field offsets
  ;; above them are not. uv_timespec_t is two `long`s: 16 bytes here, 8
  ;; on a 32-bit target, where every offset from st_atim onward moves.
  ;; The twelve uint64_t fields are the same width everywhere, so only
  ;; the four timestamps carry that dependency -- which is why they are
  ;; the only ones this comment singles out.
  ;;
  ;; mode and size were here before the rest and their values were
  ;; arrived at independently; recomputing the whole layout reproduced
  ;; both. That agreement is the only check this table gets, so it is
  ;; worth saying that it happened.
  (define uv-stat-dev-offset         0)
  (define uv-stat-mode-offset        8)
  (define uv-stat-nlink-offset      16)
  (define uv-stat-uid-offset        24)
  (define uv-stat-gid-offset        32)
  ;; st_rdev is 40 -- not exported, nothing asks for it yet
  (define uv-stat-ino-offset        48)
  (define uv-stat-size-offset       56)
  ;; st_blksize 64, st_blocks 72, st_flags 80, st_gen 88 -- likewise
  ;; st_atim is 96/104
  (define uv-stat-mtime-sec-offset  112)
  (define uv-stat-mtime-nsec-offset 120)
  (define uv-stat-ctime-sec-offset  128)
  (define uv-stat-ctime-nsec-offset 136)
  ;; st_birthtim is 144/152

  ;; ---- uv_dirent_t ----------------------------------------------------
  ;; `{ const char* name; uv_dirent_type_t type; }` -- a pointer then an
  ;; enum, padded to a pointer boundary. Only the name is read; the type
  ;; is deliberately not surfaced yet (see the scandir comment in
  ;; libuv.sc), so no offset is given for it.
  (define uv-dirent-size 16)
  (define uv-dirent-name-offset 0)

  ;; ---- child processes (uv_process_options_t / uv_stdio_container_t) ------
  ;;
  ;; PUBLIC ABI, AND IDENTICAL ON EVERY LP64 HOST WE SUPPORT. These are not
  ;; internal libuv structures: uv.h declares both, so a version bump cannot
  ;; move a field without breaking every compiled consumer at the same time.
  ;; That is why there is no `case platform-os` here and no self-check -- the
  ;; layout is part of the contract the header publishes.
  ;;
  ;;   uv_process_options_t: exit_cb @0, file @8, args @16, env @24, cwd @32,
  ;;                         flags @40 (unsigned), stdio_count @44 (int),
  ;;                         stdio @48, uid @56, gid @60; size 64.
  ;;
  ;; flags and stdio_count share the eight bytes at 40 as two 32-bit fields,
  ;; which is why stdio is at 48 and not 52.
  (define uv-process-options-size     64)
  (define uv-po-exit-cb-offset         0)
  (define uv-po-file-offset            8)
  (define uv-po-args-offset           16)
  (define uv-po-env-offset            24)
  (define uv-po-cwd-offset            32)
  (define uv-po-flags-offset          40)
  (define uv-po-stdio-count-offset    44)
  (define uv-po-stdio-offset          48)
  (define uv-po-uid-offset            56)
  (define uv-po-gid-offset            60)

  ;;   uv_stdio_container_t: flags @0 (int, padded), data @8; size 16.
  (define uv-stdio-container-size     16)
  (define uv-sc-flags-offset           0)
  (define uv-sc-data-offset            8)

  ;; uv_stdio_flags. UV_NONBLOCK_PIPE (#x40) is deliberately absent: it
  ;; describes the CHILD's end of the pipe, and the Unix spawn path already
  ;; makes the parent's end non-blocking on its own.
  (define UV-IGNORE                    0)
  (define UV-CREATE-PIPE               1)
  (define UV-INHERIT-FD                2)
  (define UV-READABLE-PIPE          #x10)
  (define UV-WRITABLE-PIPE          #x20)

  ;; ---- uv_handle_t's queue node ------------------------------------------
  ;;
  ;; UNLIKE EVERYTHING ABOVE, THIS IS INTERNAL LAYOUT. uv.h's UV_HANDLE_FIELDS
  ;; puts data @0, loop @8, type @16, close_cb @24 and handle_queue @32, so the
  ;; two pointers of that queue node are at 32 and 40. No public API exposes
  ;; them.
  ;;
  ;; They exist for ONE repair and no other use: libuv 1.52.0's uv_spawn
  ;; removes a failed process handle from the loop's handle queue without
  ;; re-initialising the node, and uv__finish_close later removes it again --
  ;; a second removal writing through whatever neighbours the node held at the
  ;; first. The caller re-initialises the node so that second removal is a
  ;; no-op.
  ;;
  ;; BECAUSE THIS IS INTERNAL, THE CALLER SELF-CHECKS IT BEFORE RELYING ON IT
  ;; and refuses the whole facility if the check fails. A wrong offset here
  ;; does not raise; it writes a pointer into the middle of another structure.
  (define uv-handle-queue-next-offset 32)
  (define uv-handle-queue-prev-offset 40)
)
