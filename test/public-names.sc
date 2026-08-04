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
              sql-transaction connpool-lease connpool-close! connpool-stats)
        (only (igropyr mysql)
              mysql-connect mysql-pool mysql-query mysql-close!
              mysql-pool-stats mysql-transaction call-with-mysql-connection)
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
              conversation-set-limits!))

(display "public names: all present\n")
