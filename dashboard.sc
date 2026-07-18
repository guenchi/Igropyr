#!chezscheme
;;; (igropyr dashboard) -- the presentation + serving layer over
;;; (igropyr metrics). metrics produces the signal; this decides how it
;;; reaches a reader. Three ways to wire it, smallest to most turnkey:
;;;
;;;   ;; 1. mount the routes onto an app you already have
;;;   (mount-dashboard! app m srv)
;;;     ;; -> GET /dash          the built-in page
;;;     ;;    GET /dash/data     JSON snapshot   (metrics-json)
;;;     ;;    GET /dash/data.sexpr  sexpr snapshot (metrics-sexpr)
;;;
;;;   ;; 2. a DEDICATED admin listener -- loopback by DEFAULT, so the
;;;   ;;    monitoring surface is not reachable off-box unless you say so
;;;   (define admin (admin-listen m srv))            ; 127.0.0.1:9090
;;;   (admin-listen m srv `((host . "10.0.0.5") (port . 9090)
;;;                         (auth . ,(token-guard verify))))  ; internal + auth
;;;
;;;   ;; 3. bring your own front-end -- a static string, a handler, a
;;;   ;;    file kept OUTSIDE the web root, or a Goeteia app reading the
;;;   ;;    sexpr endpoint. The page is decoupled from the data routes,
;;;   ;;    so its source can live anywhere and render however you like.
;;;   (mount-dashboard! app m srv
;;;     `((html . ,(lambda (req res) (send-file! res "/opt/dash.html")))))
;;;
;;; The built-in page is fully self-contained (inline CSS/JS, no external
;;; assets, works air-gapped): requests/s and latency sparklines computed
;;; from snapshot deltas, connection/pool gauges, per-status counts, every
;;; metrics-count! family, and -- when the process is a node with
;;; metrics-announce! -- a live cluster table. It polls the JSON route
;;; every 2s and keeps a rolling 3-minute window in the browser.
;;;
;;; The data routes expose operational detail. admin-listen defaults to
;;; loopback for that reason; when you mount onto a public app instead,
;;; guard the routes (an (auth . middleware), a reverse proxy, or network
;;; policy) exactly as you would /metrics.

(library (igropyr dashboard)
  (export dashboard-html mount-dashboard! admin-listen)
  (import (chezscheme) (igropyr util)
          (only (igropyr express)
                create-app app-get app-use app-listen send-html!)
          (only (igropyr metrics) metrics-json metrics-sexpr))

  ;; ---- the built-in page ------------------------------------------------

  ;; Single-quoted HTML/JS so the whole page is one plain Scheme string,
  ;; split where the data path is spliced into a JS string literal.
  (define page-head "<!doctype html>
<html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>igropyr</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#c9d1d9;--dim:#8b949e;--acc:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:24px;max-width:1100px;margin:0 auto}
h1{font-size:18px;display:flex;align-items:baseline;gap:12px}
h1 small{color:var(--dim);font-weight:normal;font-size:12px}
#state{margin-left:auto;font-size:12px;color:var(--ok)}
#state.down{color:var(--bad)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px}
.card h2{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;font-weight:normal}
.card .v{font-size:26px;margin:4px 0}
.card canvas{width:100%;height:36px;display:block}
.dim{color:var(--dim);font-size:12px}
section{margin-top:20px}
section h2{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;font-weight:normal}
section h3{font-size:13px;margin:10px 0 4px}
table{width:100%;border-collapse:collapse;font-size:13px}
td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line)}
td.n{text-align:right;white-space:nowrap}
td.ok{color:var(--ok)}td.warn{color:var(--warn)}td.bad{color:var(--bad)}
.bar{height:6px;border-radius:3px;background:var(--line);overflow:hidden}
.bar i{display:block;height:100%;background:var(--acc)}
</style></head><body>
<h1>igropyr <small id='uptime'></small><span id='state'>&hellip;</span></h1>
<div class='grid'>
<div class='card'><h2>requests / s</h2><div class='v' id='rps'>&ndash;</div><canvas id='c-rps'></canvas></div>
<div class='card'><h2>latency, 2s window</h2><div class='v' id='lat'>&ndash;</div><canvas id='c-lat'></canvas></div>
<div class='card'><h2>connections</h2><div class='v' id='conn'>&ndash;</div><canvas id='c-conn'></canvas></div>
<div class='card'><h2>requests total</h2><div class='v' id='total'>&ndash;</div><div class='dim'>avg <span id='avg'>&ndash;</span> lifetime</div></div>
</div>
<section id='cluster-sec' style='display:none'><h2>cluster</h2><table><tbody id='cluster'></tbody></table></section>
<section><h2>worker pool</h2><table><tbody id='pool'></tbody></table></section>
<section><h2>status codes</h2><table><tbody id='codes'></tbody></table></section>
<section><h2>business counters</h2><div id='custom'></div></section>
<script>
const DATA='")

  (define page-tail "';
const POLL=2000,KEEP=90;
const hist={rps:[],lat:[],conn:[]};
let prev=null,prevT=0;
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const fmt=n=>n>=100?Math.round(n).toLocaleString():String(Math.round(n*10)/10);
function push(a,v){a.push(v);if(a.length>KEEP)a.shift();}
function spark(id,arr){
  const c=$(id),dpr=window.devicePixelRatio||1;
  const w=Math.max(1,c.clientWidth*dpr),h=Math.max(1,c.clientHeight*dpr);
  if(c.width!==w)c.width=w;
  if(c.height!==h)c.height=h;
  const g=c.getContext('2d');
  g.clearRect(0,0,w,h);
  if(arr.length<2)return;
  const max=Math.max.apply(null,arr.concat([1e-9]));
  g.beginPath();
  for(let i=0;i<arr.length;i++){
    const x=1+i*(w-2)/(KEEP-1),y=h-2-(arr[i]/max)*(h-6);
    if(i)g.lineTo(x,y);else g.moveTo(x,y);
  }
  g.strokeStyle='#58a6ff';g.lineWidth=dpr;g.stroke();
}
function fmtUp(ms){
  const s=Math.floor(ms/1000),d=Math.floor(s/86400),
        h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return (d?d+'d ':'')+h+'h '+m+'m '+(s%60)+'s';
}
function bar(pct){return '<div class=bar><i style=width:'+Math.min(100,pct)+'%></i></div>';}
const num=v=>typeof v==='number';
const nodesPrev={};
function clusterRow(n,t){
  let rps='&mdash;',lat='&mdash;';
  if(num(n.requests)){
    const p=nodesPrev[n.name];
    if(p){
      const dt=Math.max(0.001,(t-p.t)/1000);
      rps=fmt(Math.max(0,(n.requests-p.req)/dt));
      const dc=n.duration_count-p.dc;
      if(dc>0)lat=fmt(Math.max(0,(n.duration_sum_ms-p.ds)/dc))+' ms';
    }
    nodesPrev[n.name]={t:t,req:n.requests,dc:n.duration_count,ds:n.duration_sum_ms};
  }
  const live=num(n.uptime_ms);
  const st=n.self?'self':live?'live':'no data';
  return '<tr><td>'+esc(n.name)+'</td><td class='+(live?'ok':'warn')+'>'+st+
    '</td><td class=n>'+(live?fmtUp(n.uptime_ms):'&mdash;')+
    '</td><td class=n>'+(num(n.connections)?n.connections:'&mdash;')+
    '</td><td class=n>'+rps+'</td><td class=n>'+lat+
    '</td><td class=n>'+(num(n.err_5xx)?n.err_5xx.toLocaleString():'&mdash;')+
    '</td><td class=n>'+(num(n.pool_busy)?n.pool_busy+'/'+(n.pool_busy+n.pool_idle):'&mdash;')+
    '</td></tr>';
}
function renderCluster(cl,t){
  if(!cl)return;
  $('cluster-sec').style.display='';
  $('cluster').innerHTML=
    '<tr class=dim><td>node</td><td>status</td><td class=n>uptime</td>'+
    '<td class=n>conns</td><td class=n>req/s</td><td class=n>latency</td>'+
    '<td class=n>5xx</td><td class=n>busy/pool</td></tr>'+
    Array.from(cl.nodes||[]).map(n=>clusterRow(n,t)).join('');
}
function render(d){
  const reqs=d.requests||{},codes=Object.keys(reqs).sort();
  const total=codes.reduce((a,k)=>a+reqs[k],0);
  $('uptime').textContent='up '+fmtUp(d.uptime_ms);
  $('conn').textContent=d.connections;
  $('total').textContent=total.toLocaleString();
  $('avg').textContent=fmt(d.duration_count?d.duration_sum_ms/d.duration_count:0)+' ms';
  const p=d.pool||{},pt=Math.max(1,(p.busy||0)+(p.idle||0)+(p.pending||0));
  $('pool').innerHTML=['busy','idle','pending'].map(k=>
    '<tr><td>'+k+'</td><td class=n>'+(p[k]||0)+
    '</td><td style=width:60%>'+bar(100*(p[k]||0)/pt)+'</td></tr>').join('');
  $('codes').innerHTML=codes.map(k=>{
    const cls=k<'300'?'ok':k<'500'?'warn':'bad';
    return '<tr><td class='+cls+'>'+esc(k)+'</td><td class=n>'+reqs[k].toLocaleString()+
      '</td><td style=width:60%>'+bar(100*reqs[k]/Math.max(1,total))+'</td></tr>';
  }).join('');
  const fams=Array.from(d.custom||[]);
  $('custom').innerHTML=fams.length?fams.map(f=>
    '<h3>'+esc(f.name)+'</h3><table><tbody>'+Array.from(f.series).map(s=>
      '<tr><td>'+(esc(s.labels)||'&mdash;')+'</td><td class=n>'+
      s.value.toLocaleString()+'</td></tr>').join('')+'</tbody></table>').join('')
    :'<p class=dim>none yet &mdash; count with metrics-count!</p>';
  renderCluster(d.cluster,Date.now());
  return total;
}
async function tick(){
  try{
    const r=await fetch(DATA);
    if(!r.ok)throw 0;
    const d=await r.json(),t=Date.now(),total=render(d);
    if(prev){
      const dt=Math.max(0.001,(t-prevT)/1000);
      push(hist.rps,Math.max(0,(total-prev.total)/dt));
      const dc=d.duration_count-prev.count;
      push(hist.lat,dc>0?Math.max(0,(d.duration_sum_ms-prev.sum)/dc)
                        :(hist.lat.length?hist.lat[hist.lat.length-1]:0));
      push(hist.conn,d.connections);
      $('rps').textContent=fmt(hist.rps[hist.rps.length-1]);
      $('lat').textContent=fmt(hist.lat[hist.lat.length-1])+' ms';
      spark('c-rps',hist.rps);spark('c-lat',hist.lat);spark('c-conn',hist.conn);
    }
    prev={total:total,sum:d.duration_sum_ms,count:d.duration_count};prevT=t;
    $('state').textContent='live';$('state').className='';
  }catch(e){
    $('state').textContent='disconnected';$('state').className='down';
  }
}
tick();setInterval(tick,POLL);
</script></body></html>
")

  ;; the built-in page pointed at data-path (where metrics-json is
  ;; mounted). data-path is spliced into a single-quoted JS string, so a
  ;; quote in it must fail HERE, not break out and XSS the page.
  (define (dashboard-html data-path)
    (do ((i 0 (+ i 1))) ((= i (string-length data-path)))
      (when (char=? (string-ref data-path i) #\')
        (assertion-violation 'dashboard-html
          "data path must not contain a single quote" data-path)))
    (string-append page-head data-path page-tail))

  ;; ---- mounting ---------------------------------------------------------

  (define (norm-prefix p)
    (if (and (> (string-length p) 1)
             (char=? (string-ref p (- (string-length p) 1)) #\/))
        (substring p 0 (- (string-length p) 1))
        p))

  (define (path-join prefix leaf)
    (if (string=? prefix "/")
        (string-append "/" leaf)
        (string-append prefix "/" leaf)))

  ;; Register the data routes and (unless suppressed) the page onto app.
  ;; opts:
  ;;   (prefix . "/dash")   route root; data at <prefix>/data[.sexpr]
  ;;   (html . X)           page source:
  ;;                          #t / absent  -- the built-in page (default)
  ;;                          #f           -- no page route, data only
  ;;                          <string>     -- serve this HTML verbatim
  ;;                          <procedure>  -- (lambda (req res) ...) handler
  ;;                                          (send-file!, a Goeteia app, ...)
  (define (mount-dashboard! app m srv . rest)
    (let* ((opts (if (pair? rest) (car rest) '()))
           (prefix (norm-prefix (opt opts 'prefix "/dash")))
           (html (opt opts 'html #t))
           (json-path (path-join prefix "data"))
           (sexpr-path (path-join prefix "data.sexpr")))
      (app-get app json-path (metrics-json m srv))
      (app-get app sexpr-path (metrics-sexpr m srv))
      (cond
        ((eq? html #f))                        ; data only
        ((procedure? html) (app-get app prefix html))
        ((string? html)
         (app-get app prefix (lambda (req res) (send-html! res html))))
        (else
         (let ((page (dashboard-html json-path)))
           (app-get app prefix (lambda (req res) (send-html! res page))))))
      (void)))

  ;; ---- turnkey admin listener -------------------------------------------

  ;; A dedicated listener carrying only the dashboard, LOOPBACK by
  ;; default: the monitoring surface stays off the public interface
  ;; unless you pass a broader (host . ...). Returns the admin server
  ;; (http-shutdown! it to stop). opts:
  ;;   (host . "127.0.0.1")  bind interface (default loopback)
  ;;   (port . 9090)         admin port
  ;;   (auth . middleware)   an (app-use)-shaped guard, applied first
  ;;   (prefix . "/")        route root on the admin app (page at "/")
  ;;   (html . X)            as mount-dashboard!
  ;;   (workers . 2)         admin pool size
  (define (admin-listen m srv . rest)
    (let* ((opts (if (pair? rest) (car rest) '()))
           (host (opt opts 'host "127.0.0.1"))
           (port (opt opts 'port 9090))
           (auth (opt opts 'auth #f))
           (prefix (opt opts 'prefix "/"))
           (html (opt opts 'html #t))
           (workers (opt opts 'workers 2))
           (app (create-app)))
      (when auth (app-use app auth))
      (mount-dashboard! app m srv `((prefix . ,prefix) (html . ,html)))
      (app-listen app port `((host . ,host) (workers . ,workers)))))
)
