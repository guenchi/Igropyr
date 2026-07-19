#!chezscheme
;;; (igropyr platform) -- supported-host detection and shared-library loading.

(library (igropyr platform)
  (export platform-os platform-arch ensure-supported-platform!
          load-first-shared-object!
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
  ;; ai_canonname. macOS and FreeBSD (BSD tradition -- verified against
  ;; FreeBSD netdb.h) put ai_canonname first, so ai_addr sits at 32;
  ;; Linux orders ai_addr first, at 24. ai_next is at 40 on all three.
  (define addrinfo-address-offset
    (case platform-os ((macos freebsd) 32) ((linux) 24) (else 0)))
  (define addrinfo-next-offset 40)

  ;; libuv's uv_stat_t is a platform-independent struct of uint64_t fields
  ;; before its timestamp fields.
  (define uv-stat-mode-offset 8)
  (define uv-stat-size-offset 56)
)
