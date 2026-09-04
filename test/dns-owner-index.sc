#!chezscheme
;;; The owner index must not grow with the number of DNS resolutions.
;;;
;;; dns-resolve! indexes the request under its owner so that uv-owner-died!
;;; can reclaim it, and TWO exits owe the matching removal: the submission
;;; that libuv refuses outright, and the callback. They do not cover each
;;; other -- a refused submission never reaches the callback -- and for a
;;; long time neither of them removed anything.
;;;
;;; A REGISTRATION THAT IS NEVER PAIRED WITH A REMOVAL HAS NO SYMPTOM
;;; OTHER THAN GROWTH. The owner does not die, so uv-owner-died! (which
;;; deletes the whole list in one step) never runs; the freed request
;;; leaves a dangling key behind that nothing walks until the owner
;;; finally exits. Nothing fails, nothing is refused, and the only reading
;;; that moves is the count -- which is why the count is exported and why
;;; this file reads it rather than anything else.
;;;
;;; WHAT THIS FILE DOES NOT COVER, stated rather than implied: the
;;; submission exit. Reaching it needs uv_getaddrinfo to refuse a request
;;; outright, which a hostname cannot ask for -- a name that does not
;;; resolve is refused by the RESOLVER, in the callback, with a negative
;;; status. Both shapes below therefore leave through the same exit. The
;;; submission exit has no coverage here.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp))

(define failures 0)
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "  FAIL  ") (display label) (newline))))

(define rounds 12)

(start-scheduler
  (lambda ()
    ;; settle anything the scheduler start left in flight
    (sleep-ms 100)
    (let ((base (uv-owner-index-count)))

      ;; ---- resolutions that SUCCEED -----------------------------------
      (let loop ((i 0))
        (when (< i rounds)
          (dns-resolve! "127.0.0.1" self)
          (receive (after 5000
                     (begin (set! failures (+ failures 1))
                            (display "  FAIL  a resolution never answered\n")))
            (`#(dns-resolved ,ip) 'ok)
            (`#(dns-failed ,e) 'ok))
          (loop (+ i 1))))
      (sleep-ms 200)
      (check "successful resolutions leave the owner index where they found it"
        (= (uv-owner-index-count) base))

      ;; ---- resolutions that FAIL in the resolver -----------------------
      ;; Same exit, different status: the callback runs either way, and it
      ;; is the callback that owes the removal.
      (let loop ((i 0))
        (when (< i rounds)
          (dns-resolve! "no-such-host.invalid" self)
          (receive (after 5000
                     (begin (set! failures (+ failures 1))
                            (display "  FAIL  a failing resolution never answered\n")))
            (`#(dns-failed ,e) 'ok)
            (`#(dns-resolved ,ip) 'ok))
          (loop (+ i 1))))
      (sleep-ms 200)
      (check "failed resolutions leave the owner index where they found it"
        (= (uv-owner-index-count) base))

      ;; ---- the reading has to be able to move at all --------------------
      ;; A count that never changes would pass both checks above without
      ;; saying anything. One live registration must be visible while it is
      ;; in flight, or the two greens are about a number that does not
      ;; respond to this code at all.
      (dns-resolve! "127.0.0.1" self)
      (check "a resolution in flight is visible in the index"
        (> (uv-owner-index-count) base))
      (receive (after 5000 (void)) (`#(dns-resolved ,ip) 'ok) (`#(dns-failed ,e) 'ok))
      (sleep-ms 200))

    (if (zero? failures)
        (begin (display "dns-owner-index: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
