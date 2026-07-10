;;; build-whole.ss -- whole-program compile: fold every library and the
;;; app into one optimized program object (app.so), enabling cross-library
;;; inlining that per-library .so files cannot get.
;;;
;;;   scheme --libdirs .:lib --script igropyr/build-whole.ss
;;;   scheme --program igropyr/app.so         # run the server
;;;
;;; Interrupt traps stay on (preemptive scheduling needs them).
;;;
;;; optimize-level 3 (unsafe): cross-library procedure integration PLUS
;;; elided type/bounds checks. Safe here because every bytevector loop is
;;; bounded by an explicit < n / >= n guard and record access is
;;; type-correct -- verified by the full test suite after each build.

(import (chezscheme))

(generate-wpo-files #t)                 ; emit .wpo alongside each .so

(define libs
  '("igropyr/platform.sc" "igropyr/libuv.sc" "igropyr/actor.sc" "igropyr/json.sc"
    "igropyr/gzip.sc" "igropyr/otp.sc" "igropyr/websocket.sc" "igropyr/ws-client.sc"
    "igropyr/gen-server.sc" "igropyr/http.sc" "igropyr/pubsub.sc"
    "igropyr/express.sc" "igropyr/session.sc" "igropyr/middleware.sc" "igropyr/metrics.sc" "igropyr/client.sc"
    "igropyr/redis.sc" "igropyr/mysql.sc"))

(parameterize ((optimize-level 3)
               (generate-inspector-information #f))
  (for-each
    (lambda (f)
      (printf "compiling library ~a\n" f)
      (compile-library f))
    libs)
  (printf "compiling program igropyr/app.sc\n")
  (compile-program "igropyr/app.sc")
  ;; merge app + all its libraries into one whole-program-optimized .so
  (printf "whole-program optimizing -> igropyr/app.so\n")
  (compile-whole-program "igropyr/app.wpo" "igropyr/app.so" #t))

(printf "done\n")
