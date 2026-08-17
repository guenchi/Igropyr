#!chezscheme
;;; The names applications import must not move by accident.
;;;
;;; A mechanical rename inside this repo silently rewrote six of them:
;;; `sql-query` -> `connpool-call` also matched the SUBSTRING inside
;;; `mysql-query` and `postgresql-query`, and the same for `sql-close!`
;;; and `sql-pool-stats`. Every use moved with every definition, so the
;;; whole suite stayed green while `mysql-query` had stopped existing --
;;; a break that would only surface in the applications that import it.
;;;
;;; Importing each name by hand is what catches that. `(only ...)` fails
;;; at expansion time when a name is absent, so this file does not need
;;; to call anything: loading it IS the assertion.

(import (chezscheme)
        (only (igropyr connpool)
              make-connpool-cfg connpool-loop connpool-call
              connpool-drain-stale! connpool-check-size!
              sql-transaction connpool-lease connpool-close! connpool-stats
              connpool-cfg-set-observer! connpool-observer-failures)
        (only (igropyr mysql)
              mysql-connect mysql-pool mysql-query mysql-close!
              mysql-pool-stats mysql-transaction call-with-mysql-connection
              mysql-observe!)
        (only (igropyr postgresql)
              postgresql-connect postgresql-pool postgresql-query
              postgresql-execute postgresql-close! postgresql-pool-stats
              postgresql-transaction call-with-postgresql-connection)
        (only (igropyr qjspool)
              qjs-worker-serve! qjspool qjspool-connect qjspool?
              qjspool-render qjspool-render/bytes
              qjspool-timeout-ms qjspool-stats qjspool-close!)
        (only (igropyr ssr)
              make-ssr ssr-render ssr-render/bytes ssr-try-render
              ssr-try-render/bytes ssr-invalidate! ssr-clear! ssr-stats)
        (only (igropyr conversation)
              conversation-start! conversation-resume! conversation-peek
              conversation-gone? conversation-stale? conversation-done?
              conversation-settled? conversation-unknown?
              conversation-unreachable?
              conversation-set-limits! conversation-hook-stats
              conversation-prepare! conversation-run!
              conversation-abandon! conversation-ref-id
              conversation-peek/timeout conversation-no-answer-yet?)
        ;; the same predicates again, from the library that has no
        ;; initialisation of its own: a pure consumer imports THIS one, and
        ;; that it exports the whole vocabulary is part of the public face
        ;; rsa joins the list with rsa-key-consistency-checked, which is
        ;; the whole point of that accessor: a caller that must not sign
        ;; on an unverified key asks for it by name, and a rename that
        ;; took the name away would leave the question unanswerable while
        ;; every suite stayed green.
        (only (igropyr rsa)
              rsa-key? rsa-key-private? rsa-key-bits
              rsa-key-consistency-checked
              rsa-key-modulus rsa-key-exponent rsa-key-free!
              rsa-private-key-from-pem rsa-public-key-from-pem
              rsa-public-key-from-modulus
              rsa-load-private-key rsa-load-public-key
              rsa-sign-sha256 rsa-verify-sha256)
        (only (igropyr conversation-status)
              conversation-gone? conversation-stale? conversation-done?
              conversation-settled? conversation-unknown?
              conversation-unreachable? conversation-no-answer-yet?))

(display "public names: all present\n")
