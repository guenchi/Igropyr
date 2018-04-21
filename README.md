# Igropyr
for Chez Scheme, support Unix, MacOS, Linux, Windows

How fast？ (test on single thread)
![image](https://github.com/guenchi/Igropyr/blob/master/benckmark.png?raw=true)
(MacBook Pro Retina, High Sierra 10.13.3, Mid 2014 2.2 GHz Intel Core i7, 16 GB 1600 MHz DDR3)

Chez Scheme run with the --script option and don't compile scheme code

***Igropyr*** is

```
.a async Scheme web-server

.a async Scheme http-server

.a async Scheme socket-server

.a async files reader/writer

.a Scheme version's Node.js

```
***Node*** = Javascript + V8 + libuv

***Igropyr*** = Scheme + ChezScheme + libuv



***install Igropyr***

Igropyr dependence libuv, make sure you have installed it.

then 

`$ cd igropyr/src && cc -fPIC -shared httpc.c membuf.c -luv -o httpc.so && mv httpc.so ../`

or simply use Raven to install Igropyr:

`$ raven install igropyr`


***start server:***

```
(define get
    (lambda (request-header path-info query-string)
        (response 200 "text/plain" "Hello World")))
                
(define post
    (lambda (request-header path-info payload)
        (response 200 "text/plain" "Hello World")))

(server 
    (request get) 
    (request post)
    (set) 
    (listen))
```


(set) may define like:

```
(set 
    ('staticpath    "/usr/local/www")   ;to define the static path    
    ('connections   3600)               ;to define the max connections, default is 1024
    ('keepalive     3600))              ;keepalive timeout, 0 for short connection, default is 5000 (ms)
```

(listen) may define like:

```
(listen "127.0.0.1" 8080)               ;define the ip and port that server listen on
(listen "127.0.0.1")                    ;if only define the ip, port use default 80
(listen 8080)                           ;if only define the port, ip use default "0.0.0.0"
```

then

```
$ raven run example.sc
```

***Igropyr's manuel***:  https://guenchi.gitbooks.io/igropyr/


## Libraries may help:


***Ballista***: Webframework `raven install ballista` https://github.com/guenchi/Ballista (Express style)

***Trabutium***: Webframework `raven install trabutium` https://github.com/guenchi/Trabutium (functional)

***JSON*** library `raven install json` https://github.com/guenchi/json

***mySQL*** bingding `raven install mysql` https://github.com/chclock/mysql 

***Liber***: HTML Template `raven install liber` https://github.com/guenchi/Liber


## todo list

```
https

http/2.0

connections limite

long-connection
```
