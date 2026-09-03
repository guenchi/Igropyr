;;; test/tls-server.sc -- the server-side TLS context layer.
;;;
;;; Stage 1 of the HTTPS server: only what can be checked without a
;;; listener. tls-listen-context! must refuse a mismatched or missing file
;;; AT STARTUP and NAME THE FILE it refused -- the operator reads this once,
;;; before any listener exists, and "system lib" tells them nothing.
;;;
;;; What discriminates here (mutations run against this file):
;;;   - dropping the return-code check on SSL_CTX_use_PrivateKey_file
;;;     hands back a context for a mismatched pair  -> H7 red
;;;   - dropping the return-code check on SSL_CTX_use_certificate_chain_file
;;;     hands back a context for a missing certificate -> C3 red
;;;   - offering the path as tls-reason's FALLBACK instead of appending it
;;;     loses the file name (OpenSSL always queues something here) -> C2..C4 red
;;; check_private_key is deliberately NOT what H7 pins: in the cert-then-key
;;; load order OpenSSL rejects the mismatch inside the key load, so a cell
;;; on the check alone is green with or without it.
;;;
;;; Two mechanism cells sit before the context cells, because both are about
;;; what happens BEFORE the first context exists:
;;;   L1  OpenSSL is not loaded by importing the library (foreign-entry? on
;;;       an SSL symbol is #f right after import) -- a #t here means eager
;;;       loading came back, which would make libssl a hard dependency of
;;;       every libuv program once libuv imports tls-core. Only the #t
;;;       direction is hard evidence (#f is merely consistent with "not
;;;       loaded"); the positive control after the first context is what
;;;       makes the #f reading mean something.
;;;   A1  error attribution selects the ERR_count_to_mark implementation on
;;;       a libcrypto that has it. The selection must be deferred to first
;;;       use: made at library-invoke time it runs before libcrypto is in
;;;       the process, answers #f forever and silently degrades attribution
;;;       to "queue non-empty" on every platform (a regression that shipped
;;;       for one gate on 2026-09-03 and that no context cell can see,
;;;       because every provokable context failure pushes an entry and both
;;;       implementations then peek the same newest one).
;;;
;;;   X1  the constructor checks its arguments before allocating (a bad
;;;       argument comes back as a tls-error, nothing to free);
;;;   X1b the compensation guard frees the context on a non-local exit after
;;;       the allocation (injected at 'tls-context-after-alloc);
;;;   X1d the compensation also covers the certificate/key loads themselves
;;;       (injected at 'tls-context-during-load);
;;;   X1c the client singleton's allocate-then-publish window has the same
;;;       guarantee (injected at 'tls-client-context-after-alloc);
;;;   X2  retiring a context twice frees once and moves the counter once;
;;;   R1  the renegotiation refusal was applied (recorded by the constructor).
;;;
;;; Requires the openssl CLI (test/tls-certs.sh mints the ephemeral PKI) and
;;; IGROPYR_INJECT=on for the seams. No port is used.

(import (chezscheme) (igropyr inject-control) (igropyr inject) (igropyr tls) (only (igropyr tls-core) tls-error-attribution tls-session-new! tls-session-retire! tls-live-session-count
                                 tls-context? tls-live-context-count tls-context-renegotiation-refused?))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(unless (zero? (system "command -v openssl >/dev/null 2>&1"))
  (display "tls-server: openssl is not on PATH; this suite mints its PKI with it\n")
  (display "            (test/tls-certs.sh). Install openssl.\n")
  (exit 1))

;; L1 -- before anything touches OpenSSL. The library must be INVOKED first:
;; Chez invokes a library on the first reference to one of its bindings, so a
;; probe taken before any reference measures "not invoked yet", not
;; "invoked without loading" -- an eager-loading mutant stayed green on
;; exactly that (2026-09-03). The session counter reads a variable and
;; touches no OpenSSL entry, so it forces the invoke and nothing else.
(check "L1: premise -- the library is invoked (session counter readable) before the probe"
       (= (tls-live-session-count) 0) (tls-live-session-count))
(check "L1: invoking the library does not load OpenSSL (SSL_new not visible after invoke)"
       (not (foreign-entry? "SSL_new")))

;; A1 -- the deferred selection, forced here before any context exists
(let ((sel (tls-error-attribution)))
  (check "A1: error attribution selected the ERR_count_to_mark implementation (libcrypto >= 3.2 here)"
         (eq? sel 'mark-count) sel)
  ;; premise: the symbol really is in this libcrypto, so 'queue-nonempty would be a wrong choice, not an old library
  (check "A1: premise -- ERR_count_to_mark is present once OpenSSL is loaded"
         (foreign-entry? "ERR_count_to_mark")))

;; L1 positive control -- the seam above loaded OpenSSL; the probe must now see it
(check "L1: positive control -- after first use SSL_new is visible" (foreign-entry? "SSL_new"))

(define dir "/tmp/igropyr-tls-server-test")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(define (in-dir f) (string-append dir "/" f))

;; -> the tls-error message raised by (thunk), or #f when nothing was raised
(define (refusal thunk)
  (call/cc
    (lambda (k)
      (with-exception-handler
        (lambda (e)
          (k (if (and (vector? e) (= (vector-length e) 2) (eq? (vector-ref e 0) 'tls-error)
                      (string? (vector-ref e 1)))
                 (vector-ref e 1)
                 (list 'not-a-tls-error e))))
        (lambda () (thunk) #f)))))

(define (mentions? msg path)
  (and (string? msg)
       (let ((n (string-length path)) (m (string-length msg)))
         (let loop ((i 0))
           (cond ((> (+ i n) m) #f)
                 ((string=? (substring msg i (+ i n)) path) #t)
                 (else (loop (+ i 1))))))))

;; C1 a matching pair yields a context
(let* ((base (tls-live-context-count))
       (ctx (tls-listen-context! (in-dir "good.pem") (in-dir "good.key"))))
  (check "C1: a matching certificate/key pair yields a context" (tls-context? ctx) ctx)
  (check "C1: and it is counted" (= (tls-live-context-count) (+ base 1)) (tls-live-context-count) base)
  ;; R1 -- the renegotiation refusal was actually applied on this box (OpenSSL
  ;; 3.6.3: version >= 1.1.1, not the LibreSSL sentinel, SSL_CTX_set_options a
  ;; real symbol). The seam reads back what the constructor recorded, it does
  ;; not recompute the version test -- a version-interval mutant that skips the
  ;; option must show up here, and H12 (a real renegotiation over a listener)
  ;; is stage 2's.
  (check "R1: premise -- SSL_CTX_set_options is a real symbol here" (foreign-entry? "SSL_CTX_set_options"))
  (check "R1: the constructor recorded that renegotiation was refused" (tls-context-renegotiation-refused? ctx))
  ;; X2 -- retiring a context is idempotent and gated on the record, not on a
  ;; raw value: a second retire frees nothing and moves the counter nowhere
  (tls-context-retire! ctx)
  (check "X2: retiring returns the counter to base" (= (tls-live-context-count) base) (tls-live-context-count) base)
  (let ((raised (call/cc (lambda (k) (with-exception-handler (lambda (e) (k e)) (lambda () (tls-context-retire! ctx) #f))))))
    (check "X2: a second retire raises nothing" (not raised) raised)
    (check "X2: and moves the counter nowhere" (= (tls-live-context-count) base) (tls-live-context-count) base)))

;; X1 -- the constructor is exception-safe: a bad argument type after the
;; allocation has happened (good certificate path, then a non-string key
;; argument) must come back as a tls-error, and the context it had already
;; allocated must be freed -- the counter is unchanged across the call. A
;; foreign-procedure type error used to leave the SSL_CTX_free branch unrun.
(let ((base (tls-live-context-count)))
  (let ((msg (refusal (lambda () (tls-listen-context! (in-dir "good.pem") 17)))))
    (check "X1: a non-string key argument is refused as a tls-error, not a Chez condition" (string? msg) msg)
    (check "X1: and no context leaked (counter unchanged)" (= (tls-live-context-count) base) (tls-live-context-count) base))
  (let ((msg (refusal (lambda () (tls-listen-context! 17 (in-dir "good.key"))))))
    (check "X1: a non-string certificate argument is refused as a tls-error" (string? msg) msg)
    (check "X1: and no context leaked" (= (tls-live-context-count) base) (tls-live-context-count) base)))

;; H7 a mismatched pair is refused, and the refusal names the key file
(let ((msg (refusal (lambda () (tls-listen-context! (in-dir "good.pem") (in-dir "wrong.key"))))))
  (check "H7: a key that does not match the certificate is refused" (string? msg) msg)
  (check "H7: the refusal names the key file" (mentions? msg (in-dir "wrong.key")) msg))

;; C3 a missing certificate file is refused by name
(let ((msg (refusal (lambda () (tls-listen-context! (in-dir "absent.pem") (in-dir "good.key"))))))
  (check "C3: a missing certificate file is refused" (string? msg) msg)
  (check "C3: the refusal names the certificate file" (mentions? msg (in-dir "absent.pem")) msg))

;; C4 a missing key file is refused by name
(let ((msg (refusal (lambda () (tls-listen-context! (in-dir "good.pem") (in-dir "absent.key"))))))
  (check "C4: a missing key file is refused" (string? msg) msg)
  (check "C4: the refusal names the key file" (mentions? msg (in-dir "absent.key")) msg))

;; X1b -- the compensation guard itself: a non-local exit AFTER the
;; allocation (injected here, since no public input reaches that window)
;; must free the context on the way out. The raise is the injected
;; condition, not a tls-error, and the cell says so.
(let ((base (tls-live-context-count)))
  (inject-arm-fault! 'tls-context-after-alloc 1)
  (let* ((r (refusal (lambda () (tls-listen-context! (in-dir "good.pem") (in-dir "good.key")))))
         (hits (inject-hits 'tls-context-after-alloc)))   ; read before disarm: disarm clears it
    (inject-disarm!)
    (check "X1b: the injected raise after the allocation left the constructor (hit once)"
           (eqv? hits 1) hits)
    (check "X1b: it surfaced as the injected condition, not a tls-error and not a context" (and (pair? r) (eq? (car r) 'not-a-tls-error)) r)
    (check "X1b: and the allocated context was freed (counter unchanged)" (= (tls-live-context-count) base) (tls-live-context-count) base)))

;; X1d -- the compensation covers the LOADS, not just the tail after them.
;; The certificate and key loads are lazily bound FFI calls: on a library
;; missing one of the symbols the first call raises at symbol resolution,
;; and that raise must free the context too. A guard that began after the
;; loads (the shape this file shipped with for one gate) left exactly that
;; window open; the injection point sits inside the loads.
(let ((base (tls-live-context-count)))
  (inject-arm-fault! 'tls-context-during-load 1)
  (let* ((r (refusal (lambda () (tls-listen-context! (in-dir "good.pem") (in-dir "good.key")))))
         (hits (inject-hits 'tls-context-during-load)))
    (inject-disarm!)
    (check "X1d: the injected raise during the loads left the constructor (hit once)" (eqv? hits 1) hits)
    (check "X1d: it surfaced as the injected condition" (and (pair? r) (eq? (car r) 'not-a-tls-error)) r)
    (check "X1d: and the context allocated before the loads was freed (counter unchanged)" (= (tls-live-context-count) base) (tls-live-context-count) base)))

;; X1c -- the client singleton has the same shape: ensure-ctx! allocates,
;; then publishes. A raise between the two (injected at
;; 'tls-client-context-after-alloc) must free the allocation, leave the
;; singleton unbuilt, and a later tls-enable! must build it normally.
(let ((base (tls-live-context-count)))
  (inject-arm-fault! 'tls-client-context-after-alloc 1)
  (let* ((r (refusal (lambda () (tls-enable!))))
         (hits (inject-hits 'tls-client-context-after-alloc)))
    (inject-disarm!)
    (check "X1c: the injected raise after the client allocation left tls-enable! (hit once)" (eqv? hits 1) hits)
    (check "X1c: it surfaced as the injected condition" (and (pair? r) (eq? (car r) 'not-a-tls-error)) r)
    (check "X1c: and the client context was freed (counter unchanged)" (= (tls-live-context-count) base) (tls-live-context-count) base))
  (tls-enable!)
  (check "X1c: an unarmed tls-enable! then builds the client context (counted once)"
         (= (tls-live-context-count) (+ base 1)) (tls-live-context-count) base))

;; S1 retiring a session is idempotent and gated on the session itself, not
;; on the message: the second retire of the same session must neither free
;; again nor move the counter (a gate on the message's truth value let
;; (retire s #f) leave the session "not retired", so the next retire took the
;; counter to -1 and freed through a #f field -- caught by review 2026-09-03).
(let ((ctx (tls-listen-context! (in-dir "good.pem") (in-dir "good.key"))))
  ;; let*: the base must be read BEFORE the session exists (let's binding
  ;; order is unspecified, and Chez evaluated the new! first)
  (let* ((base (tls-live-session-count))
         (s (tls-session-new! ctx)))
    (check "S1: a new session is counted" (= (tls-live-session-count) (+ base 1)) (tls-live-session-count) base)
    (tls-session-retire! s #f)
    (check "S1: retiring with no message still retires (count back to base)" (= (tls-live-session-count) base) (tls-live-session-count) base)
    (let ((raised (call/cc (lambda (k) (with-exception-handler (lambda (e) (k e)) (lambda () (tls-session-retire! s "again") #f))))))
      (check "S1: a second retire of the same session raises nothing" (not raised) raised)
      (check "S1: and moves the counter nowhere (not -1)" (= (tls-live-session-count) base) (tls-live-session-count) base)))
  (tls-context-retire! ctx))

;; C5 the two missing-file refusals are distinguishable from each other --
;; the reason OpenSSL gives for both is the same "system lib" string
(let ((a (refusal (lambda () (tls-listen-context! (in-dir "absent.pem") (in-dir "good.key")))))
      (b (refusal (lambda () (tls-listen-context! (in-dir "good.pem") (in-dir "absent.key"))))))
  (check "C5: missing-cert and missing-key refusals differ" (and (string? a) (string? b) (not (string=? a b))) a b))

(if (zero? failures)
    (begin (display "ALL TLS-SERVER TESTS PASSED\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
