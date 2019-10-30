(import (igropyr http))

(printf "server is start, listen on port..~a\n" 8080)

(define get
  (lambda (header path query)
    (response 200 "text/html"
      (string-append "<p>path is:" path "</br>query is:" (if query query "nothing")))))
                
(define post
  (lambda (header path payload)
    (response 200 "application/json" "{\"hello\":\"world\"}")))

(server 
  (request get)
  (request post)
  (set)
  (listen))



