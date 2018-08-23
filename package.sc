(("name" . "igropyr")
("version" . "0.2.12")
("description" . "a async Scheme http server base on libuv")
("keywords"
    ("Scheme" "http-server" "async"))
("author" 
    ("guenchi" "chclock"))
("private" . #f)
("scripts" 
    ("build" . "cd ./lib/igropyr/src && cc -fPIC -shared httpc.c membuf.c -luv -o ../httpc.so")
    ("run" . "scheme --script")
    ("test" . "scheme --script server.sc"))
("dependencies")
("devDependencies"))
