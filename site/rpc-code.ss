(library (rpc-code)
  (export rpc-code)
  (import (rnrs))
  (define rpc-code "(<span class=\"f\">app-rpc</span> app <span class=\"s\">\"/rpc\"</span>                     <span class=\"c\">; one s-expression per message</span>
  `((add      . ,(<span class=\"k\">lambda</span> (args) (apply + args)))
    (get-user . ,(<span class=\"k\">lambda</span> (args) (find-user (car args))))))

<span class=\"c\">;; a Scheme browser -- Goeteia -- calls it. no JSON, no codec:</span>
(<span class=\"f\">rpc</span> <span class=\"s\">\"/rpc\"</span> '(add <span class=\"n\">1</span> <span class=\"n\">2</span> <span class=\"n\">1/2</span>))

<span class=\"c\">;; the Igropyr server returns</span>
(ok <span class=\"n\">7/2</span>) <span class=\"c\">;; -- exact ratio intact</span>"))
