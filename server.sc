(import (igropyr http))

(printf "server is start, listen on port..~a\n" 8080)

(server 
    (set 
        ('path "/users/iter/igropyr/www/"))
    (listen 8080))



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
;;  (server (set) (listen))
;;
;;  (set) 
;;may define the static path
;;  (set 
;;      ('path "/usr/local/www"))
;;
;;  (listen) 
;;may define the specific port as
;;  (listen 8080) 
;;or writen like this
;;  (listen 
;;      ('port 8080))
;;or define the specific ip as
;;  (listen "127.0.0.1")
;;or writen like this
;;  (listen 
;;      ('ip "127.0.0.1"))
;;or define the two
;;  (listen "127.0.0.1" 8080)
;;or writen like this 
;;  (listen 
;;      ('ip "127.0.0.1")
;;      ('port 8080))
;;if you don't define
;;server will listen on 0.0.0.0:80
