#!chezscheme
;;; (igropyr platform) -- supported-host detection and shared-library loading.

(library (igropyr platform)
  (export platform-os platform-arch ensure-supported-platform!
          so-listenqlimit sol-socket
          load-first-shared-object! shared-object-candidates
          addrinfo-address-offset addrinfo-next-offset
          uv-stat-mode-offset uv-stat-size-offset)
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
  ;; ⛔ #f MEANS "NOT KNOWN HERE", AND THAT IS DELIBERATELY NOT A GUESS.
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

  ;; libuv's uv_stat_t is a platform-independent struct of uint64_t fields
  ;; before its timestamp fields.
  (define uv-stat-mode-offset 8)
  (define uv-stat-size-offset 56)
)
