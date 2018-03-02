(import (igropyr http))

(printf "server is start, listen on port..~a\n" 8080)

(define get
    (request
        (lambda (request_header pathinfo query_string)
            (response 200 "text/html"
                (string-append "<p>path is:" pathinfo "</br>query is:" (if query_string query_string "nothing"))))))
                
(define post
    (request
        (lambda (request_header pathinfo payload)
            (response 200 "application/json" "{\"hello\":\"world\"}"))))

(server get post (set) (listen))



