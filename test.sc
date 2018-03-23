(import 
    (igropyr http)
    (igropyr igropyr))

(define header "HTTP/1.1\r\n Host: 127.0.0.1:8081\r\nUpgrade-Insecure-Requests: 1\r\nAccept: text/html,application/xhtml+xml,application/xml,q=0.9,*/*,q=0.8\r\nUser-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10_13_3) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6\r\nAccept-Language: zh-cn\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n")

(define querylist (list (cons "user" "igropyr") (cons "psw" "catapult")))

(define testlist
    (list
        (cons 'a 'a)
        (cons 'b "b")
        (cons "c" 'c)
        (cons 'num 123)))

(define serverset 
    (set 
        ('staticpath "/usr/local/www/")
        ('connections 1024)
        ('keepalive 5000)))


(newline)
(display "Start test...")
(newline)
(newline)



(display "test procedure ref...")
(display
    (if 
        (and 
            (equal? (ref testlist 'a) 'a)
            (equal? (ref testlist 'b) "b")
            (equal? (ref testlist "c") 'c)
            (equal? (ref testlist 'num) 123))
        "           ok"
        "           error"))
(newline)

(display "test procedure val...")
(display
    (if 
        (and 
            (equal? (val testlist 'a) 'a)
            (equal? (val testlist "b") 'b)
            (equal? (val testlist 'c) "c")
            (equal? (val testlist 123) 'num))
        "           ok"
        "           error"))
(newline)

(display "test procedure set...")
(display
    (if 
        (and 
            (equal? (ref serverset 'staticpath) "/usr/local/www/")
            (equal? (ref serverset 'connections) 1024)
            (equal? (ref serverset 'keepalive) 5000))
        "           ok"
        "           error"))
(newline)


(display "test procedure listen...")
(display
    (if 
        (and 
            (equal? (ref (listen 80) 'port) 80)
            (equal? (ref (listen "127.0.0.1") 'ip) "127.0.0.1")
            (equal? (ref (listen "127.0.0.1" 80) 'ip) "127.0.0.1")
            (equal? (ref (listen "127.0.0.1" 80) 'port) 80))
        "        ok"
        "        error"))
(newline)

(display "test procedure head-parser...")
(display
    (if 
        (and 
            (equal? (header-parser header "Host") "127.0.0.1:8081")
            (equal? (header-parser header "Accept") "text/html,application/xhtml+xml,application/xml,q=0.9,*/*,q=0.8")
            (equal? (header-parser header "User-Agent") "Mozilla/5.0 (Macintosh, Intel Mac OS X 10_13_3) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6")
            (equal? (header-parser header "Accept-Language") "zh-cn")
            (equal? (header-parser header "Accept-Encoding") "gzip, deflate")
            (equal? (header-parser header "Connection") "keep-alive")
            (equal? (header-parser header "Cookie") ""))
        "   ok"
        "   error"))
(newline)


(display "test procedure par...")
(display
    (if 
        (and 
            (par "/abc" "/abc")
            (not (par "/abc" "/123"))
            (par "/*" "/abc")
            (par "/*/abc" "/efg/abc")
            (not (par "/*/abc" "/abc/efg"))
            (par "/abc/*/efg" "/abc/ace/efg")
            (par "/a*/abc" "/alm/abc"))
        "           ok"
        "           error"))
(newline)


(display "test procedure list->json...")
(display
    (if 
            (equal? (list->json querylist) "{\"user\":\"igropyr\",\"psw\":\"catapult\"}")
        "    ok"
        "    error"))
(newline)
(newline)



(display "Test complished!")
(newline)
(newline)
