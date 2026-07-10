;;; Compile profile-instrumented libraries in a temporary benchmark copy.
;;; Run from the parent of the directory named `igropyr`.

(import (chezscheme))

(define units
  '("igropyr/uv.sc" "igropyr/actor.sc" "igropyr/json.sc"
    "igropyr/otp.sc" "igropyr/websocket.sc" "igropyr/gen-server.sc"
    "igropyr/http.sc" "igropyr/pubsub.sc" "igropyr/express.sc"
    "igropyr/redis.sc" "igropyr/mysql.sc"))

(parameterize ((compile-profile #t)
               (optimize-level 2)
               (generate-inspector-information #t))
  (for-each
    (lambda (src)
      (printf "profile compiling ~a\n" src)
      (compile-library src))
    units))

(printf "profile build complete\n")
