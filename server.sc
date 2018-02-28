(import (igropyr http))

(printf "server is start, listen on port..~a\n" 8080)

(server 
    (set 
        ('staticpath "/users/iter/igropyr/www/"))
    (listen 8081))



;; to use 
;;
;;(get
;;  ("/"         index)
;;  ("/index"    index)
;;  ("/user"     user)
;;  ("/data"     auth    data))
;;
;;
;;

