;;; build-profile.ss -- instrumented (PGO step 1) build.
;;;
;;; Compiles everything with source-level profiling so the running server
;;; records execution counts. Drive real load against it, hit
;;; /admin/profdump to write app.profile, then rebuild with build-pgo.ss.
;;;
;;;   scheme --libdirs .:lib --script igropyr/build-profile.ss
;;;   scheme --program igropyr/app.so        # instrumented; run load
;;;   curl localhost:8080/admin/profdump      # writes app.profile

(import (chezscheme))

(compile-profile 'source)               ; instrument for source profiling
(generate-wpo-files #t)

(define libs
  '("igropyr/checked.sc" "igropyr/platform.sc" "igropyr/libuv.sc" "igropyr/actor.sc" "igropyr/json.sc"
    "igropyr/gzip.sc" "igropyr/sexpr.sc" "igropyr/otp.sc" "igropyr/websocket.sc" "igropyr/ws-client.sc"
    "igropyr/gen-server.sc" "igropyr/conversation.sc" "igropyr/http.sc" "igropyr/pubsub.sc"
    "igropyr/express.sc" "igropyr/session.sc" "igropyr/auth.sc" "igropyr/middleware.sc" "igropyr/jwt.sc" "igropyr/metrics.sc" "igropyr/client.sc"
    "igropyr/redis.sc" "igropyr/mysql.sc"))

(parameterize ((optimize-level 2)
               (generate-inspector-information #f))
  (for-each
    (lambda (f) (printf "compiling (profiled) ~a\n" f) (compile-library f))
    libs)
  (compile-program "igropyr/app.sc")
  (compile-whole-program "igropyr/app.wpo" "igropyr/app.so" #t))

(printf "instrumented build done\n")
