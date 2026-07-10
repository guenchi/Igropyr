;;; build-pgo.ss -- profile-guided (PGO step 2) build.
;;;
;;; Loads the profile collected by an instrumented run (app.profile) and
;;; recompiles, letting the compiler use the hot-path data for block
;;; ordering and inlining. Same optimize-level 3 whole-program output.
;;;
;;;   scheme --libdirs .:lib --script igropyr/build-pgo.ss
;;;   scheme --program igropyr/app.so

(import (chezscheme))

(unless (file-exists? "app.profile")
  (error 'build-pgo "app.profile not found; run build-profile.ss + collect first"))

(compile-profile #f)                    ; no more instrumentation
(profile-load-data "app.profile")       ; use the collected profile
(generate-wpo-files #t)

(define libs
  '("igropyr/libuv.sc" "igropyr/actor.sc" "igropyr/json.sc"
    "igropyr/gzip.sc" "igropyr/otp.sc" "igropyr/websocket.sc" "igropyr/ws-client.sc"
    "igropyr/gen-server.sc" "igropyr/http.sc" "igropyr/pubsub.sc"
    "igropyr/express.sc" "igropyr/session.sc" "igropyr/middleware.sc" "igropyr/client.sc"
    "igropyr/redis.sc" "igropyr/mysql.sc"))

(parameterize ((optimize-level 3)
               (generate-inspector-information #f))
  (for-each
    (lambda (f) (printf "compiling (pgo) ~a\n" f) (compile-library f))
    libs)
  (compile-program "igropyr/app.sc")
  (compile-whole-program "igropyr/app.wpo" "igropyr/app.so" #t))

(printf "pgo build done\n")
