# Igropyr
a async Scheme http server base on libuv


***Igropyr*** is

```
.a async Scheme Webserver

.a async Scheme Httpserver

.a async Scheme Socketserver

.a async files reader/writer

.a Scheme version's Node.js


.base on libuv


Node = Javascript + V8 + libuv

Igropyr = Scheme + ChezScheme + libuv
```


use the default value to start server:

`(server (set) (listen))`


(set) may define like:

```
(set 
    ('staticpath    "/usr/local/www")   ;to define the static path    
    ('connections   1024)               ;to define the max connections, default 3600
    ('keepalive     36000))             ;to define the keepalive timeout, 0 for short connection, default 36000 (s)
```

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
