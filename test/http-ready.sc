#!chezscheme
;;; Readiness is the listener AND the pool, and the two questions are kept
;;; apart. http-server-pool-alive? answers only whether the worker pool's
;;; supervisor is alive: its #f is conclusive, its #t is not, because the
;;; listener can be gone while the pool lives on. http-server-ready? asks
;;; both. The discriminating pair is a server whose listener has been
;;; stopped: pool-alive? still #t, ready? #f. Then the other side: a pool
;;; that died under a live listener, ready? #f as well.
(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http))   ; libuv for the no-argument tcp-stop-listen!

(define (fail label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline) (exit 1))
(define (handler req res) (res-send! res (string->utf8 "ok")))

(start-scheduler
  (lambda ()
    ;; ---- both up: ready ---------------------------------------------------
    (let ((srv (http-listen 18114 handler '((host . "127.0.0.1") (workers . 1)))))
      (sleep-ms 100)
      (unless (http-server-pool-alive? srv) (fail "pool-not-alive-at-start"))
      (unless (http-server-ready? srv) (fail "not-ready-with-listener-and-pool"))
      ;; ---- listener gone, pool alive: NOT ready, though pool-alive? says yes
      (http-shutdown! srv)
      (sleep-ms 200)
      (unless (http-server-pool-alive? srv)
        (fail "pool-died-with-listener-stop" 'pool-alive? #f))
      (when (http-server-ready? srv)
        (fail "ready-without-listener")))
    (display "listener stopped: pool-alive? #t, ready? #f ok\n")
    ;; ---- pool dead under a live listener: not ready either ----------------
    (let ((srv (http-listen 18115 handler '((host . "127.0.0.1") (workers . 1) (critical . #f)))))
      (sleep-ms 100)
      (unless (http-server-ready? srv) (fail "second-server-not-ready"))
      (kill (http-server-sup srv) 'for-the-cell)
      (sleep-ms 300)
      (when (http-server-pool-alive? srv) (fail "pool-survived-kill"))
      (when (http-server-ready? srv) (fail "ready-without-pool"))
      (http-shutdown! srv))
    (display "pool killed: pool-alive? #f, ready? #f ok\n")
    ;; ---- the listener stopped BEHIND the server's back --------------------
    ;; tcp-stop-listen! is exported, and with no argument it stops every
    ;; listener in the process without touching any http-server's fields.
    ;; ready?'s first conjunct therefore cannot be the server's own field.
    ;; It asks the listener table -- libuv.sc's bookkeeping of which
    ;; incarnation currently owns each handle, keyed by the token minted
    ;; at tcp-listen!, not an observation of libuv -- and the
    ;; effective-backlog read asks the same table, inside the same
    ;; interrupt-disabled step as its FFI calls, before it touches the
    ;; handle: after the stop the handle is freed by its close callback,
    ;; and a read through it would be a use-after-free.
    ;; The raw handle is deliberately not exported for this cell: handing
    ;; that pointer out is exactly how the two use-after-frees arose.
    (let ((srv (http-listen 18117 handler '((host . "127.0.0.1") (workers . 1)))))
      (sleep-ms 100)
      (unless (http-server-ready? srv) (fail "fourth-server-not-ready"))
      (tcp-stop-listen!)
      (let poll ((n 0))
        (cond ((not (http-server-ready? srv)) 'ok)
              ((= n 60) (fail "ready-after-stop-all-listeners"))
              (else (sleep-ms 50) (poll (+ n 1)))))
      (when (http-server-backlog-effective srv) (fail "effective-after-stop-all-listeners"))
      (http-shutdown! srv))
    (display "all listeners stopped: ready? #f, effective #f ok\n")
    ;; ---- the freed handle's address is reused by a NEW listener ----------
    ;; libuv frees a stopped handle in its close callback, and an allocator
    ;; hands a block of the same size straight back: the next tcp-listen!
    ;; can sit at the very address a stale server record still holds. A
    ;; readiness keyed on the address alone would then say #t for the dead
    ;; server, and a shutdown of the dead server would stop the LIVE one.
    ;; The listener table therefore keys each incarnation by a token, and
    ;; every question about a listener is asked with its token. Reuse of the
    ;; address is not guaranteed to happen here; every assertion below holds
    ;; whether it did or not, and the comment says so rather than claiming
    ;; a reproduction the test cannot force.
    (let ((old (http-listen 18118 handler '((host . "127.0.0.1") (workers . 1)))))
      (sleep-ms 100)
      (unless (http-server-ready? old) (fail "old-server-not-ready"))
      (let ((h0 (uv-live-handle-count)))
        (tcp-stop-listen!)                       ; stop it behind the server's back
        ;; wait for the close callback: the handle count must actually fall
        (let poll ((n 0))
          (cond ((< (uv-live-handle-count) h0) 'freed)
                ((= n 100) (fail "old-listener-never-freed" (uv-live-handle-count) h0))
                (else (sleep-ms 20) (poll (+ n 1))))))
      ;; a new listener, likely at the freed address
      (let ((new (http-listen 18119 handler '((host . "127.0.0.1") (workers . 1)))))
        (sleep-ms 100)
        (unless (http-server-ready? new) (fail "new-server-not-ready"))
        (when (http-server-ready? old) (fail "stale-server-reads-ready-after-address-reuse"))
        (when (http-server-backlog-effective old) (fail "stale-server-reads-effective-backlog"))
        ;; shutting down the stale server must not touch the live one
        (http-shutdown! old)
        (sleep-ms 100)
        (unless (http-server-ready? new) (fail "stale-shutdown-stopped-the-live-listener"))
        (http-shutdown! new)))
    (display "stale server after address reuse: not ready, not effective, and its shutdown leaves the live one alone ok\n")
    (display "ALL HTTP READY TESTS PASSED\n")
    (exit 0)))
