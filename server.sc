(import (igropyr http))

(printf "server is start, listen on port..~a\n" 8080)

(define request
    (callback
        (lambda (request_header pathinfo query_string)
                    (respone "200 OK" "text/html" 
                        (string-append "<p>path is:" pathinfo "</br>query is:" (if query_string query_string "nothing"))))))
(server 
    request
    (set 
        ('staticpath "/users/iter/igropyr/www/"))
    (listen 8081))

