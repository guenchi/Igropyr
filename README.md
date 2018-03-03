# Igropyr
a async Scheme http server base on libuv

api: https://guenchi.gitbooks.io/igropyr/

***Igropyr*** is

```
.a async Scheme web-server

.a async Scheme http-server

.a async Scheme socket-server

.a async files reader/writer

.a Scheme version's Node.js


.base on libuv


Node = Javascript + V8 + libuv

Igropyr = Scheme + ChezScheme + libuv
```

***install Igropyr***

Igropyr dependence libuv, make sure you have installed it.

then 

`$ cd igropyr/src && cc -fPIC -shared httpc.c membuf.c -luv -o httpc.so`

or simply use Raven to install Igropyr:

`$ raven install igropyr`


***start server:***

```

(define hello
    (lambda ()
        (response 200 "text/plain" "Hello World")))

(define get
    (request
        (lambda (request_header pathinfo query_string)
            (hello)))
                
(define post
    (request
        (lambda (request_header pathinfo payload)
            (hello)))

(server 
    get 
    post 
    (set) 
    (listen))
```


(set) may define like:

```
(set 
    ('staticpath    "/usr/local/www")   ;to define the static path    
    ('connections   3600)               ;to define the max connections, default is 1024
    ('keepalive     3600))             ;keepalive timeout, 0 for short connection, default is 5000 (ms)
```

(listen) may define like:

```
(listen "127.0.0.1" 8080)               ;define the ip and port that server listen on
(listen "127.0.0.1")                    ;if only define the ip, port use default 80
(listen 8080)                           ;if only define the port, ip use default "0.0.0.0"

```

then

```
`$ raven run test.sc`
```

We recommand use ***Catapult*** as Webframework

https://github.com/guenchi/Catapult

