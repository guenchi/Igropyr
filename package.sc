(("name" . "igropyr")
("version" . "0.2.13")
("description" . "a async Scheme http server base on libuv")
("keywords"
    ("Scheme" "http-server" "async"))
("author" 
    ("guenchi" "chclock"))
("private" . #f)
("scripts" 
    ("build" . "cd ./lib/igropyr/src && cc -o3 -fPIC -shared httpc.c membuf.c -luv -o ../httpc.so")
    ("run" . "scheme --script")
    ("test" . "scheme --script server.sc"))
("dependencies"
    ("core" . "1.0.0"))
("devDependencies"))
