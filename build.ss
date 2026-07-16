;;; build.ss -- compile all Igropyr libraries to .so for production.
;;;
;;; Run from the project root (the parent of igropyr/):
;;;   scheme --libdirs .:lib --script igropyr/build.ss
;;; or with CHEZSCHEMELIBDIRS set. Produces one .so per source file;
;;; because CHEZSCHEMELIBEXTS lists .so before .sc, they are then loaded
;;; in preference to the sources. Re-run after editing any source.
;;;
;;; Everything is compiled at optimize-level 2: full optimization with
;;; all type/bounds checks kept -- safe by default. Interrupt traps are
;;; left ON -- preemptive scheduling depends on them.

(import (chezscheme))

;; (source . optimize-level), in dependency order so each library's
;; already-compiled dependencies are picked up as .so.
(define units
  '(("igropyr/checked.sc" . 2)
    ("igropyr/buffer.sc" . 2)
    ("igropyr/platform.sc" . 2)
    ("igropyr/crypto.sc" . 2)
    ("igropyr/libuv.sc" . 2)
    ("igropyr/actor.sc" . 2)
    ("igropyr/json.sc" . 2)
    ("igropyr/gzip.sc" . 2)
    ;; sexpr must be compiled too: a source-only library gets a fresh
    ;; UID per process, which invalidates every dependent .so ("reloading
    ;; because a dependency has changed") -- node/express/dpool would be
    ;; silently re-expanded from source on every start
    ("igropyr/sexpr.sc" . 2)
    ("igropyr/otp.sc" . 2)
    ("igropyr/websocket.sc" . 2)
    ("igropyr/ws-client.sc" . 2)
    ("igropyr/gen-server.sc" . 2)
    ("igropyr/node.sc" . 2)
    ("igropyr/conversation.sc" . 2)
    ("igropyr/http.sc" . 2)
    ("igropyr/pubsub.sc" . 2)
    ("igropyr/dpool.sc" . 2)
    ("igropyr/express.sc" . 2)
    ("igropyr/session.sc" . 2)
    ("igropyr/auth.sc" . 2)
    ("igropyr/middleware.sc" . 2)
    ("igropyr/jwt.sc" . 2)
    ("igropyr/metrics.sc" . 2)
    ("igropyr/client.sc" . 2)
    ("igropyr/tls.sc" . 2)
    ("igropyr/redis.sc" . 2)
    ("igropyr/mysql.sc" . 2)
    ("igropyr/cluster.sc" . 2)))

(define (so-path src)
  (string-append (substring src 0 (- (string-length src) 3)) ".so"))

(for-each
  (lambda (unit)
    (let ((src (car unit)) (level (cdr unit)))
      (parameterize ((optimize-level level)
                     ;; keep source info out of the .so; smaller, faster load
                     (generate-inspector-information #f))
        (printf "compiling ~a (optimize-level ~a)\n" src level)
        (compile-library src (so-path src)))))
  units)

(printf "done: ~a libraries compiled\n" (length units))
