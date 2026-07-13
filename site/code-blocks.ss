(library (code-blocks)
  (export hero-quick crash-code hotswap-code faults-code conv-code cluster-code)
  (import (rnrs))
  (define hero-quick "<span class=\"c\">$</span> npm i igropyr")
  (define crash-code "(<span class=\"f\">app-get</span> app <span class=\"s\">\"/crash\"</span>
  (<span class=\"k\">lambda</span> (req res)
    <span class=\"c\">;; the worker dies; the supervisor retries on a</span>
    <span class=\"c\">;; fresh worker -- the pool refills itself</span>
    (<span class=\"k\">raise</span> <span class=\"n\">'handler-crashed</span>)))

(<span class=\"f\">app-get</span> app <span class=\"s\">\"/stuck\"</span>
  (<span class=\"k\">lambda</span> (req res)
    <span class=\"c\">;; a hot loop cannot freeze the system: preemption</span>
    <span class=\"c\">;; keeps serving, the ticker kills this worker</span>
    (<span class=\"k\">let</span> loop ((n <span class=\"n\">0</span>)) (loop (+ n <span class=\"n\">1</span>)))))")
  (define hotswap-code "(<span class=\"f\">app-get</span> app <span class=\"s\">\"/version\"</span>
  (<span class=\"k\">lambda</span> (req res) (<span class=\"f\">send-text!</span> res <span class=\"s\">\"v1\"</span>)))

<span class=\"c\">;; hit /upgrade on the LIVE server:</span>
(<span class=\"f\">app-get</span> app <span class=\"s\">\"/upgrade\"</span>
  (<span class=\"k\">lambda</span> (req res)
    (<span class=\"f\">app-get</span> app <span class=\"s\">\"/version\"</span>          <span class=\"c\">; re-register =</span>
      (<span class=\"k\">lambda</span> (req res)                <span class=\"c\">; hot replace</span>
        (<span class=\"f\">send-text!</span> res <span class=\"s\">\"v2 (hot swapped)\"</span>)))
    (<span class=\"f\">send-text!</span> res <span class=\"s\">\"upgraded\"</span>)))")
  (define faults-code "(<span class=\"f\">app-listen</span> app <span class=\"n\">8080</span>
  `((stuck-ms . <span class=\"n\">3000</span>)          <span class=\"c\">; fail fast</span>
    (check-ms . <span class=\"n\">1000</span>)
    (on-failure . ,(<span class=\"f\">make-fault-handler</span>))))

<span class=\"c\">;; the client receives, connection kept alive:</span>
<span class=\"c\">;;   {\"fault\":\"crash\",\"attempts\":4,\"retryable\":true}</span>
<span class=\"c\">;;   {\"fault\":\"stuck\",\"elapsed-ms\":3012,...}</span>
<span class=\"c\">;; unset? the plain 500 remains. zero breakage.</span>")
  (define conv-code "(<span class=\"f\">conversation-start!</span>
  (<span class=\"k\">lambda</span> (req suspend!)
    (<span class=\"k\">let</span> ((tx (begin-tx!)))       <span class=\"c\">; live, across requests</span>
      (<span class=\"k\">guard</span> (e (#t (rollback! tx) (<span class=\"k\">raise</span> e)))
        (<span class=\"k\">let</span> ((req2 (suspend! confirm-page)))
          (commit! tx)
          done))))
  req)

(<span class=\"f\">conversation-resume!</span> id req)   <span class=\"c\">; =&gt; reply | 'gone</span>
<span class=\"c\">;; 'gone means: rolled back. guaranteed.</span>")
  (define cluster-code "(<span class=\"f\">node-start!</span> <span class=\"n\">'web-1</span> secret <span class=\"n\">8888</span> <span class=\"s\">\"0.0.0.0\"</span>)

<span class=\"c\">;; discover peers via redis; nodes heartbeat</span>
<span class=\"c\">;; themselves in and expire on their own</span>
(<span class=\"f\">cluster-start</span>
  `((name . <span class=\"s\">\"render-farm\"</span>)
    (discover . (redis ,conn <span class=\"s\">\"10.0.0.1\"</span> <span class=\"n\">8888</span>))))

<span class=\"c\">;; fan work across every live member; a node</span>
<span class=\"c\">;; dying mid-task -&gt; the task reruns elsewhere</span>
(<span class=\"k\">define</span> pool (<span class=\"f\">dpool-start</span> <span class=\"n\">'(web-1 web-2 web-3)</span> <span class=\"n\">'render</span>))
(<span class=\"f\">dpool-await</span> pool
  (<span class=\"f\">dpool-submit</span> pool #(resize <span class=\"s\">\"x.png\"</span> <span class=\"n\">800</span>)))")
)
