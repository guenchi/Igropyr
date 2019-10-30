![image](img/greekfire.jpg)

## What is the Igropyr?

Igropyr (gr.Υγρόν πυρ: Greek fire) is the secret weapon of the Schemers.

Igropyr implements a high concurrent server based on libuv, in another way, Igropyr is the Scheme's version of Node.

Igropyr is committed to providing efficient, stable industrial grade servers.

![image](img/ab.png)
(MacBook Pro Retina, High Sierra 10.13.3, Mid 2014 2.2 GHz Intel Core i7, 16 GB 1600 MHz DDR3)

## Will it be better?

In the second edition being designed, Igropyr draws on the wisdom of Erlang and will automatically extend the thread to other hosts. Automated distributed service provisioning and load balancing are its main goals.


## Installation

***Igropyr dependence libuv, make sure you have installed it.***

- use [Raven](http://ravensc.com) to install Igropyr:

`$ raven install igropyr`

- use gitclone 

`$ cd igropyr/src && cc -fPIC -shared httpc.c membuf.c -luv -o ../httpc.so`

## Use

`(import (igropyr http))`

## Procedures

### server

```
procedure: (server get post set listen)

return: unspecified
```

`server` turn on the server listening.

The first two arguments to accept a callback procedure, who is run when the server received a GET and POST request.

like:`(request do-when-request)`

The second two arguments to accept a association list, the server will configured depending the list before open the listening.

The last two lists one is struct with the key of 'staticpath, 'connection and 'keepalive, and the other with the key of 'ip and 'port.

example for use `server`:

```
(server
  (request do-when-get-request)
  (request do-when-post-request)
  (set)
  (listen))
```

### request

```
procedure: (request callback)

(func list -> string -> string -> string) -> unspecified
```

`request` accept a procedure that takes three arguments as a callback.

When a GET request received, request will passe three arguments (request_header, path_info, query_string) to the callback.

When a POST request received, request will passe three arguments (request_header, path_info, payload) to the callback.

This callback must return a string which include a standard http header then request calls the Igropyr's C functionl to send it back to client.


### response

```
procedure: (response status type content)

int -> string -> string / list -> string
```

`response` accepts three parameters: `http status code`, `return type` and `content`, which `status` must be a number, `type` must be a string.

When `content` is a list, the first element will seted as `cookie` and the second will seted as `response content`.

When `content` is a string, it will send as `response content` with a empty cookie.

`response` format these information to a stirng with a standard http header, prepare to use for the request. Usually use to build the callback of request.


### sendfile

```
procedure: (sendfile type path_file)

string -> string -> string
```

`sendfile` accepts two parameters: `MIME type` and `path_file`.

When type is `""`, the `MIME type` is automatelly detected.

`sendfile` usually use to build the callback of request.


### set

```
procedure: (set (name value) ...)

(symbol any) -> ... -> association list
```

`set` accepts any number of s-expressions which is used to configure server settings.

Valid values ​​for `name` are:

`'staticpath` is used to set the server static file path. The corresponding value is string, the default value is"".

`'connection` is used to set the maximum number of connections. The corresponding value is int, the default value is 1024

`'keepalive` is used to set the server keep-alive timeout. Corresponding to the value is int, the default value is 5000 (ms), 0 for close the long connections.

The missing settings automatically apply defaults.


### listen

```
procedure: (listen)

() ->  association list
```

```
procedure: (listen ip)

string ->  association list
```

```
procedure: (listen port)

number ->  association list
```

```
procedure: (listen ip port)

string -> number ->  association list
```

`listen` accepts zero to two arguments to set the ip and port that server listen on.

When `listen` accepts a string argument, its value is used to set the ip.

When `listen` accepts a int parameter, its value is used to set the port.

When `listen` accepts two parameters, the values is used to set the listen ip and port by order.

The missing settings automatically apply defaults:ip: 0.0.0.0 port: 80


### errorpage

```
procedure: (errorpage error_code)

number -> string
```

```
procedure: (errorpage error_code error_info)

number -> string -> string
```

`errorpage` accepts one or two arguments, the first arguments is the `status code`, the second arguments is an error message.

`errorpage` Returns prepare a string with standard http headers for easily return error page to the client.


### par

```
procedure: (par router_path request_path)

string -> string -> boolean
```

`par` is an efficient string fuzzy comparison procedure.

Its first argument accepts the path set by the router, and the second argument accepts the request path.

When the first argument contains "*", the second argument is ignored from the "*" character to the next "/" sign.

so:

```
(par "/foo" "/foo") => #t

(par "/foo" "/bar") => #f

(par "/*" "/foo") => #t

(par "/foo/*" "/foo/bar") => #t

(par "/*/bar" "/foo/bar") => #t

(par "/f*/bar" "/foo/bar") => #t

(par "/f*/bar" "/boo/bar") => #f

(par "/foo/b*" "/foo/bar") => #t

(par "/foo/b*" "/foo/far") => #f
```

### header-parser

```
procedure: (header-parser header key)

string -> string -> string
```

`header-parser` is an efficient implementation for finding the corresponding value in the http-header.


### path-parser

```
procedure: (header-parser path index)

string -> number -> string
```

`path-parser` return the specific element in the path.

```
(path-parser "/foo/bar/baz" 0) => "foo"

(path-parser "/foo/bar/baz" 1) => "bar"

(path-parser "/foo/bar/baz" 2) => "baz"

(path-parser "/foo/bar/baz" 3) => ""
```

## Example

```
(define get
  (lambda (header path query)
    (response 200 "text/plain" "Hello World")))
                
(define post
  (lambda (header path payload)
    (response 200 "text/plain" "Hello World")))

(server 
  (request get) 
  (request post)
  (set) 
  (listen))
```

`(set)` may define like:

```
(set 
  ('staticpath    "/usr/local/www")   ;to define the static path    
  ('connections   3600)               ;to define the max connections, default is 1024
  ('keepalive     3600))              ;keepalive timeout, 0 for short connection, default is 5000 (ms)
```

`(listen)` may define like:

```
(listen "127.0.0.1" 8080)               ;define the ip and port that server listen on
(listen "127.0.0.1")                    ;if only define the ip, port use default 80
(listen 8080)                           ;if only define the port, ip use default "0.0.0.0"
```

then

```
$ raven run example.sc
```

more information, see [example.sc](https://github.com/guenchi/Igropyr/blob/master/example/example.sc)


## Igropyr ecosystem

***[Ballista](https://github.com/guenchi/Ballista)*** : Express style webframework

***[Catapult](https://github.com/guenchi/Catapult)*** : purely functional webframework 

***[Core](https://github.com/guenchi/Core)*** : commonly used small functions 

***[JSON](https://github.com/guenchi/json)*** : Json parser and toolfunctions

***[JWT](https://github.com/guenchi/jwt)*** : Json Web Token

***[mySQL](https://github.com/chclock/mysql)*** : mySQL Chez Scheme bingding

***[Liber](https://github.com/guenchi/Liber)*** : HTML Template
