;;; build.ss -- compile all Igropyr libraries to .so for production.
;;;
;;; Run from the project root (the parent of igropyr/):
;;;   scheme --libdirs .:lib --script igropyr/build.ss
;;; or with CHEZSCHEMELIBDIRS set. Produces one .so per source file;
;;; because CHEZSCHEMELIBEXTS lists .so before .sc, they are then loaded
;;; in preference to the sources. Re-run after editing any source.
;;;
;;; Hot-path files (uv, actor, http) are compiled at optimize-level 3
;;; (their bytevector loops are all bounded by explicit < n guards and
;;; their record access is type-safe); the rest use level 2. Interrupt
;;; traps are left ON -- preemptive scheduling depends on them.

(import (chezscheme))

;; (source . optimize-level), in dependency order so each library's
;; already-compiled dependencies are picked up as .so.
(define units
  '(("igropyr/libuv.sc" . 3)
    ("igropyr/actor.sc" . 3)
    ("igropyr/json.sc" . 2)
    ("igropyr/gzip.sc" . 2)
    ("igropyr/otp.sc" . 2)
    ("igropyr/websocket.sc" . 2)
    ("igropyr/ws-client.sc" . 2)
    ("igropyr/gen-server.sc" . 2)
    ("igropyr/http.sc" . 3)
    ("igropyr/pubsub.sc" . 2)
    ("igropyr/express.sc" . 2)
    ("igropyr/session.sc" . 2)
    ("igropyr/middleware.sc" . 2)
    ("igropyr/metrics.sc" . 2)
    ("igropyr/client.sc" . 2)
    ("igropyr/redis.sc" . 2)
    ("igropyr/mysql.sc" . 2)))

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
