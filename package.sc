(("name" . "igropyr")
("version" . "0.1.0")
("description" . "a async Scheme http server base on libuv")
("keywords"
    ("Scheme" "http" "server" "async"))
("author" 
    ("guenchi" "chclock"))
("private" . #f)
("scripts" 
    ("build" . "cd igropyr/src && cc -fPIC -shared httpc.c membuf.c -luv -o httpc.so")
    ("run" . "scheme --script")
    ("test" . "scheme --script server.sc"))
("dependencies")
("devDependencies"))
