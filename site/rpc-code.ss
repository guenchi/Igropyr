(library (rpc-code)
  (export rpc-code)
  (import (rnrs))
  (define rpc-code "(<span class=\"f\">app-rpc</span> app <span class=\"s\">\"/rpc\"</span>                     <span class=\"c\">; one s-expression per message</span>
  `((add      . ,(<span class=\"k\">lambda</span> (args) (apply + args)))
    (get-user . ,(<span class=\"k\">lambda</span> (args) (find-user (car args))))))

<span class=\"c\">;; a Scheme browser -- Goeteia -- calls it. no JSON, no codec:</span>
<span class=\"c\">;;   (rpc \"/rpc\" '(add 1 2 1/2))  =&gt;  (ok 7/2)</span>
<span class=\"c\">;;   exact ratios and bignums cross the wire intact.</span>"))
