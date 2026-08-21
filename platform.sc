#!chezscheme
;;; (igropyr platform) -- supported-host detection and shared-library loading.

(library (igropyr platform)
  (export platform-os platform-arch ensure-supported-platform!
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

  ;; libuv's uv_stat_t is a platform-independent struct of uint64_t fields
  ;; before its timestamp fields.
  (define uv-stat-mode-offset 8)
  (define uv-stat-size-offset 56)
)
