#!chezscheme
;;; (igropyr libuv) -- the façade over (igropyr uv) and (igropyr tcp).
;;;
;;; ZERO DEFINITIONS, BY DESIGN. Every name below is re-exported from the
;;; library that defines it, so a consumer importing this one gets THE SAME
;;; BINDING it got before the split -- not a wrapper around it. That matters
;;; for more than tidiness: a façade that wrapped each name in
;;; (lambda args (apply f args)) would pass a name-by-name export check while
;;; changing arity introspection and adding an indirection on hot paths. The
;;; check that pins this is binding identity, not the export list.
;;;
;;; THE SPLIT IS INVISIBLE FROM HERE ON PURPOSE. Consumers -- actor, http,
;;; node, qjspool, tls -- were not touched by this batch and must not need to
;;; be: the public API is unchanged name for name and binding for binding.
;;; New code should import (igropyr uv) or (igropyr tcp) directly and say
;;; which layer it depends on; this façade exists so that existing code did
;;; not have to be rewritten to find out.
;;;
;;; The 98 names below are exactly the export list of (igropyr libuv) at
;;; f435135, the commit before the split.

(library (igropyr libuv)
  (export
          conn-count conn-handle conn-on-close! conn-owner
          conn-peer-ip conn-set-owner! conn-state conn-tls-retire!
          conn? dns-count dns-resolve! file-read-async!
          file-realpath file-scandir-async! file-stat-async! file-stream-chunk-ptr
          file-stream-close! file-stream-open! file-stream-open-under! file-stream-own!
          file-stream-raw! file-stream-read! file-unlink-async! fs-close-async!
          fs-count fs-fd-count fs-fsync-async! fs-job-count
          fs-mkdir-async! fs-o-cloexec fs-o-creat fs-o-directory
          fs-o-excl fs-o-rdonly fs-o-trunc fs-o-wronly
          fs-open-async! fs-rename-async! fs-write-async! listener-backlog-effective
          listener-open? listener-token now-ms now-ns
          tcp-close! tcp-connect! tcp-listen! tcp-listen-tls!
          tcp-read-start! tcp-read-stop! tcp-stop-listen! tcp-write!
          tcp-write-foreign! tcp-writev! tcp-writev-raw! tls-accept-callback-completions
          tls-active-timer-count tls-conn-charge tls-conn-holder tls-conn-holder-monitor
          tls-conn-in-table? tls-conn-set-holder-monitor! tls-conn-timer-id tls-conn-totals
          tls-eof-deliveries tls-gate-grant-next! tls-gate-open-mark tls-gate-waiters-length
          tls-handshake-max-set! tls-handshake-ms-set! tls-handshaking-count tls-inject-ciphertext!
          tls-last-retire-reason tls-listener-context-id tls-live-timer-count tls-live-watcher-count
          tls-open-gate-and-drain! tls-raw-blocks tls-raw-sink-writes tls-read-trace
          tls-retire-effect-depths tls-server-raw-reads tls-shutdown-ms-set! tls-ssl-op-count
          tls-swallowed-errors tls-timer-free-path tls-watcher-exited! uv-accept-failure-counts
          uv-init! uv-live-handle-count uv-owner-died! uv-owner-index-count
          uv-poll! uv-set-deliver! uv-set-gate-wait! uv-set-self!
          uv-set-tls-watcher-spawner! uv-strerror)

  ;; (only …) ON BOTH IMPORTS. Importing wholesale and re-exporting by name
  ;; would work today and would silently publish anything either library adds
  ;; later; naming what is taken keeps the façade's contract a statement
  ;; rather than a consequence.
  (import (only (igropyr uv)
          fs-o-cloexec fs-o-creat fs-o-directory fs-o-excl
          fs-o-rdonly fs-o-trunc fs-o-wronly now-ms
          now-ns uv-init! uv-live-handle-count uv-poll!
          uv-strerror)
          (only (igropyr tcp)
          conn-count conn-handle conn-on-close! conn-owner
          conn-peer-ip conn-set-owner! conn-state conn-tls-retire!
          conn? dns-count dns-resolve! file-read-async!
          file-realpath file-scandir-async! file-stat-async! file-stream-chunk-ptr
          file-stream-close! file-stream-open! file-stream-open-under! file-stream-own!
          file-stream-raw! file-stream-read! file-unlink-async! fs-close-async!
          fs-count fs-fd-count fs-fsync-async! fs-job-count
          fs-mkdir-async! fs-open-async! fs-rename-async! fs-write-async!
          listener-backlog-effective listener-open? listener-token tcp-close!
          tcp-connect! tcp-listen! tcp-listen-tls! tcp-read-start!
          tcp-read-stop! tcp-stop-listen! tcp-write! tcp-write-foreign!
          tcp-writev! tcp-writev-raw! tls-accept-callback-completions tls-active-timer-count
          tls-conn-charge tls-conn-holder tls-conn-holder-monitor tls-conn-in-table?
          tls-conn-set-holder-monitor! tls-conn-timer-id tls-conn-totals tls-eof-deliveries
          tls-gate-grant-next! tls-gate-open-mark tls-gate-waiters-length tls-handshake-max-set!
          tls-handshake-ms-set! tls-handshaking-count tls-inject-ciphertext! tls-last-retire-reason
          tls-listener-context-id tls-live-timer-count tls-live-watcher-count tls-open-gate-and-drain!
          tls-raw-blocks tls-raw-sink-writes tls-read-trace tls-retire-effect-depths
          tls-server-raw-reads tls-shutdown-ms-set! tls-ssl-op-count tls-swallowed-errors
          tls-timer-free-path tls-watcher-exited! uv-accept-failure-counts uv-owner-died!
          uv-owner-index-count uv-set-deliver! uv-set-gate-wait! uv-set-self!
          uv-set-tls-watcher-spawner!)))
