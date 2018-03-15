(import 
    (igropyr http)
    (igropyr igropyr))

(define header "HTTP/1.1\r\n Host: 127.0.0.1:8081\r\nUpgrade-Insecure-Requests: 1\r\nAccept: text/html,application/xhtml+xml,application/xml,q=0.9,*/*,q=0.8\r\nUser-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10_13_3) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6\r\nAccept-Language: zh-cn\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n")

(display "Start test...")
(newline)
(newline)

(display "test procedure head-parser")
(display
    (if 
        (and 
            (equal? (header-parser header "Host") "127.0.0.1:8081")
            (equal? (header-parser header "Accept") "text/html,application/xhtml+xml,application/xml,q=0.9,*/*,q=0.8")
            (equal? (header-parser header "User-Agent") "Mozilla/5.0 (Macintosh, Intel Mac OS X 10_13_3) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6")
            (equal? (header-parser header "Accept-Language") "zh-cn")
            (equal? (header-parser header "Accept-Encoding") "gzip, deflate")
            (equal? (header-parser header "Connection") "keep-alive"))
        "     ...ok"
        "     ...error\n"))
(newline)
(newline)

(display "Test complished")
(newline)
(newline)
