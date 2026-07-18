#!chezscheme
;;; (igropyr metrics) -- Prometheus metrics.
;;;
;;; A gen-server accumulates per-status request counts and request
;;; duration; a middleware records each request; an endpoint renders
;;; everything (plus http-stats connection/pool gauges) in Prometheus
;;; text format.
;;;
;;;   (define m (make-metrics))                    ; at boot
;;;   (app-use app (metrics-middleware m))         ; record every request
;;;   ;; after app-listen returns the server:
;;;   (app-get app "/metrics" (metrics-endpoint m srv))
;;;
;;; Business counters ride the same collector -- register nothing,
;;; just count; each name renders as its own TYPE counter family:
;;;
;;;   (metrics-count! m "iter_lookup_outcome_total" '(("outcome" . "hit")))
;;;   (metrics-count! m "jobs_done_total" '() 5)    ; labels optional, +n form
;;;   ;; -> iter_lookup_outcome_total{outcome="hit"} 1
;;;
;;; A browser dashboard rides the same collector: one self-contained
;;; page (inline CSS/JS, no external assets) polling a JSON snapshot --
;;;
;;;   (app-get app "/dash/data" (metrics-json m srv))
;;;   (app-get app "/dash"      (metrics-dashboard "/dash/data"))
;;;
;;; Both routes expose operational detail: guard them the same way as
;;; /metrics itself (auth middleware, network policy).
;;;
;;; Cluster view: on a node (after node-start!), announce the local
;;; summary once --
;;;
;;;   (metrics-announce! m srv)
;;;
;;; -- and every peer that did the same shows up in this dashboard's
;;; cluster table (uptime, connections, req/s, latency, 5xx, pool),
;;; fetched over the existing node links by rcall; no extra HTTP
;;; exposure, no cross-origin fetches. Without node-start! the JSON's
;;; "cluster" is null and the section stays hidden.

(library (igropyr metrics)
  (export make-metrics metrics-middleware metrics-endpoint metrics-count!
          metrics-json metrics-dashboard metrics-announce!)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr gen-server)
          (igropyr http) (igropyr express)
          (only (igropyr node) node-self node-peers rcall))

  ;; state: #(status-count-ht duration-sum-box duration-count-box
  ;;          custom-ht)  where custom-ht: name -> (label-string -> count)
  (define (metrics-init)
    (vector (make-eqv-hashtable) (box 0) (box 0)
            (make-hashtable string-hash string=?)))

  (define (metrics-cast msg st)
    (case (vector-ref msg 0)
      ((record)
       (let ((status (vector-ref msg 1)) (dur (vector-ref msg 2)))
         (hashtable-update! (vector-ref st 0) status (lambda (n) (+ n 1)) 0)
         (set-box! (vector-ref st 1) (+ (unbox (vector-ref st 1)) dur))
         (set-box! (vector-ref st 2) (+ (unbox (vector-ref st 2)) 1))))
      ((count)
       (let* ((name (vector-ref msg 1))
              (labels (vector-ref msg 2))
              (n (vector-ref msg 3))
              (custom (vector-ref st 3))
              (inner (or (hashtable-ref custom name #f)
                         (let ((h (make-hashtable string-hash string=?)))
                           (hashtable-set! custom name h)
                           h))))
         (hashtable-update! inner labels (lambda (v) (+ v n)) 0))))
    st)

  (define (hashtable->alist ht)
    (let-values (((ks vs) (hashtable-entries ht)))
      (let loop ((i 0) (acc '()))
        (if (= i (vector-length ks))
            acc
            (loop (+ i 1) (cons (cons (vector-ref ks i) (vector-ref vs i)) acc))))))

  ;; call 'dump -> #(status-alist duration-sum duration-count custom-alist)
  ;; custom-alist: ((name . ((label-string . count) ...)) ...)
  (define (metrics-call msg from st)
    (values
      (vector
        (hashtable->alist (vector-ref st 0))
        (unbox (vector-ref st 1))
        (unbox (vector-ref st 2))
        (map (lambda (kv) (cons (car kv) (hashtable->alist (cdr kv))))
             (hashtable->alist (vector-ref st 3))))
      st))

  ;; a metrics collector is just the gen-server pid
  (define (make-metrics)
    (gen-server-start metrics-init metrics-call metrics-cast))

  ;; Prometheus label escaping: backslash, double-quote, newline
  (define (escape-label-value v)
    (let-values (((p get) (open-string-output-port)))
      (do ((i 0 (+ i 1))) ((= i (string-length v)) (get))
        (let ((c (string-ref v i)))
          (case c
            ((#\\) (put-string p "\\\\"))
            ((#\") (put-string p "\\\""))
            ((#\newline) (put-string p "\\n"))
            (else (put-char p c)))))))

  ;; Prometheus name rules: metric [a-zA-Z_:][a-zA-Z0-9_:]*, label name
  ;; the same minus the colon
  (define (valid-name? s colon-ok?)
    (and (string? s) (> (string-length s) 0)
         (let loop ((i 0))
           (or (= i (string-length s))
               (let ((c (string-ref s i)))
                 (and (or (char<=? #\a c #\z) (char<=? #\A c #\Z)
                          (char=? c #\_)
                          (and colon-ok? (char=? c #\:))
                          (and (> i 0) (char<=? #\0 c #\9)))
                      (loop (+ i 1))))))))

  ;; labels alist -> "{k=\"v\",...}" or "" -- validated and SORTED by
  ;; label name: Prometheus treats label order as insignificant, so two
  ;; orderings of one set must map to ONE series -- unsorted they would
  ;; render as duplicate samples and fail the whole scrape. Cached per
  ;; distinct label set (label sets on the request path are near-
  ;; constant), so sort/escape work runs per series, not per increment;
  ;; the cache grows exactly as the collector's own series table does.
  (define label-cache (make-hashtable equal-hash equal?))

  (define (build-label-string labels)
    (for-each
      (lambda (kv)
        (unless (and (pair? kv) (valid-name? (car kv) #f) (string? (cdr kv)))
          (assertion-violation 'metrics-count! "bad label (name . value)" kv)))
      labels)
    (let ((sorted (sort (lambda (a b) (string<? (car a) (car b))) labels)))
      (let dup ((l sorted))
        (when (and (pair? l) (pair? (cdr l)))
          (when (string=? (caar l) (caadr l))
            (assertion-violation 'metrics-count! "duplicate label name" (caar l)))
          (dup (cdr l))))
      (if (null? sorted)
          ""
          (let-values (((p get) (open-string-output-port)))
            (put-char p #\{)
            (let loop ((l sorted) (first #t))
              (unless (null? l)
                (unless first (put-char p #\,))
                (put-string p (caar l))
                (put-string p "=\"")
                (put-string p (escape-label-value (cdar l)))
                (put-string p "\"")
                (loop (cdr l) #f)))
            (put-char p #\})
            (get)))))

  (define (label-string labels)
    (or (hashtable-ref label-cache labels #f)
        (let ((s (build-label-string labels)))
          (hashtable-set! label-cache labels s)
          s)))

  ;; count a business event: name is the Prometheus family, labels an
  ;; alist of (name . value) strings, n the increment (default 1).
  ;; Validated HERE, in the caller: gen-server-cast is fire-and-forget,
  ;; so bad input must fail the call site loudly instead of raising
  ;; inside the shared collector and silently killing every metric.
  ;; igropyr_* is reserved -- a custom family colliding with a built-in
  ;; one would render a duplicate # TYPE block and invalidate the scrape.
  (define reserved-prefix "igropyr_")

  (define (reserved-name? name)
    (let ((n (string-length reserved-prefix)))
      (and (>= (string-length name) n)
           (string=? (substring name 0 n) reserved-prefix))))

  (define metrics-count!
    (case-lambda
      ((m name labels) (metrics-count! m name labels 1))
      ((m name labels n)
       (unless (valid-name? name #t)
         (assertion-violation 'metrics-count! "bad metric name" name))
       (when (reserved-name? name)
         (assertion-violation 'metrics-count!
           "igropyr_ names are reserved for built-in families" name))
       (unless (and (real? n) (not (nan? n)))
         (assertion-violation 'metrics-count! "increment must be a real number" n))
       (gen-server-cast m (vector 'count name (label-string labels) n)))))

  ;; record each request's final status and wall-clock duration
  (define (metrics-middleware m)
    (lambda (req res next)
      (let ((t0 (now-ms)))
        (next)
        (gen-server-cast m (vector 'record (res-status res) (- (now-ms) t0))))))

  ;; ---- Prometheus text rendering ---------------------------------------

  (define (line . parts) (apply string-append (append parts (list "\n"))))

  (define (render-custom custom)
    (apply string-append
      (map (lambda (family)
             (string-append
               (line "# TYPE " (car family) " counter")
               (apply string-append
                 (map (lambda (lv)
                        (line (car family) (car lv) " "
                              (number->string (cdr lv))))
                      (cdr family)))))
           custom)))

  (define (render dump stats)
    (let ((counts (vector-ref dump 0))
          (sum (vector-ref dump 1))
          (count (vector-ref dump 2))
          (custom (vector-ref dump 3)))
      (define (stat key) (number->string (cdr (assq key stats))))
      (string-append
        (render-custom custom)
        (line "# HELP igropyr_requests_total HTTP requests by status")
        (line "# TYPE igropyr_requests_total counter")
        (apply string-append
          (map (lambda (kv)
                 (line "igropyr_requests_total{status=\""
                       (number->string (car kv)) "\"} "
                       (number->string (cdr kv))))
               counts))
        (line "# HELP igropyr_request_duration_ms Request duration summary")
        (line "# TYPE igropyr_request_duration_ms summary")
        (line "igropyr_request_duration_ms_sum " (number->string sum))
        (line "igropyr_request_duration_ms_count " (number->string count))
        (line "# TYPE igropyr_connections gauge")
        (line "igropyr_connections " (stat 'connections))
        (line "# TYPE igropyr_uptime_ms gauge")
        (line "igropyr_uptime_ms " (stat 'uptime-ms))
        (line "# TYPE igropyr_pool_workers gauge")
        (line "igropyr_pool_busy " (stat 'busy))
        (line "igropyr_pool_idle " (stat 'idle))
        (line "igropyr_pool_pending " (stat 'pending)))))

  ;; endpoint handler; srv is the http-server from app-listen
  (define (metrics-endpoint m srv)
    (lambda (req res)
      (let ((dump (gen-server-call m (vector 'dump)))
            (stats (http-stats srv)))
        (set-header! res "Content-Type" "text/plain; version=0.0.4")
        (res-send! res (string->utf8 (render dump stats))))))

  ;; ---- cluster view -------------------------------------------------------

  ;; the registered name peers rcall for a node's summary
  (define node-service 'igropyr-metrics)
  (define peer-timeout-ms 1000)

  ;; compact summary of this node, wire-safe (symbols/numbers only in
  ;; the alist -- it crosses node links)
  (define (node-summary m srv)
    (let ((dump (gen-server-call m (vector 'dump)))
          (stats (http-stats srv)))
      (define (stat k) (cdr (assq k stats)))
      (let loop ((l (vector-ref dump 0)) (total 0) (err5 0))
        (if (pair? l)
            (loop (cdr l) (+ total (cdar l))
                  (if (>= (caar l) 500) (+ err5 (cdar l)) err5))
            `((uptime-ms . ,(stat 'uptime-ms))
              (connections . ,(stat 'connections))
              (busy . ,(stat 'busy))
              (idle . ,(stat 'idle))
              (pending . ,(stat 'pending))
              (requests . ,total)
              (err5xx . ,err5)
              (duration-sum . ,(vector-ref dump 1))
              (duration-count . ,(vector-ref dump 2)))))))

  ;; Serve this node's summary to the mesh under the well-known name.
  ;; Call once after node-start! and app-listen; every peer that did
  ;; the same appears in each other's dashboard cluster table.
  (define (metrics-announce! m srv)
    (gen-server-start-named node-service
      (lambda () #f)
      (lambda (msg from st) (values (node-summary m srv) st))
      (lambda (msg st) st)))

  ;; summary alist -> JSON fields; anything missing or garbled in a
  ;; peer's reply becomes null -- a broken peer must not take the local
  ;; endpoint down
  (define summary-fields
    '((uptime-ms . "uptime_ms") (connections . "connections")
      (busy . "pool_busy") (idle . "pool_idle") (pending . "pool_pending")
      (requests . "requests") (err5xx . "err_5xx")
      (duration-sum . "duration_sum_ms") (duration-count . "duration_count")))

  (define (summary-json summary)
    (map (lambda (f)
           (cons (cdr f)
                 (let ((p (guard (e (#t #f)) (assq (car f) summary))))
                   (if (and (pair? p) (number? (cdr p))) (cdr p) 'null))))
         summary-fields))

  ;; the "cluster" JSON member: self plus one rcall per connected peer
  ;; (each bounded by peer-timeout-ms; a peer without metrics-announce!
  ;; renders up=false with null data). 'null when node-start! never ran.
  (define (cluster-json m srv)
    (if (not (node-self))
        'null
        `(("self" . ,(symbol->string (node-self)))
          ("nodes"
           . ,(list->vector
                (cons
                  (append
                    `(("name" . ,(symbol->string (node-self)))
                      ("self" . #t) ("up" . #t))
                    (summary-json (node-summary m srv)))
                  (map (lambda (peer)
                         (let ((s (guard (e (#t #f))
                                    (rcall peer node-service 'summary
                                           peer-timeout-ms))))
                           (append
                             `(("name" . ,(symbol->string peer))
                               ("self" . #f) ("up" . ,(and s #t)))
                             (summary-json (or s '())))))
                       (node-peers))))))))

  ;; ---- browser dashboard ------------------------------------------------

  ;; machine-readable snapshot of everything /metrics renders; the
  ;; dashboard polls it, and it doubles as a JSON metrics API
  (define (metrics-json m srv)
    (lambda (req res)
      (let ((dump (gen-server-call m (vector 'dump)))
            (stats (http-stats srv)))
        (define (stat key) (cdr (assq key stats)))
        (send-json! res
          `(("uptime_ms" . ,(stat 'uptime-ms))
            ("connections" . ,(stat 'connections))
            ("pool" . (("busy" . ,(stat 'busy))
                       ("idle" . ,(stat 'idle))
                       ("pending" . ,(stat 'pending))))
            ("requests" . ,(map (lambda (kv)
                                  (cons (number->string (car kv)) (cdr kv)))
                                (vector-ref dump 0)))
            ("duration_sum_ms" . ,(vector-ref dump 1))
            ("duration_count" . ,(vector-ref dump 2))
            ("custom"
             . ,(list->vector
                  (map (lambda (fam)
                         `(("name" . ,(car fam))
                           ("series"
                            . ,(list->vector
                                 (map (lambda (lv)
                                        `(("labels" . ,(car lv))
                                          ("value" . ,(cdr lv))))
                                      (cdr fam))))))
                       (vector-ref dump 3))))
            ("cluster" . ,(cluster-json m srv)))))))

  ;; The page: requests/s and latency sparklines (computed client-side
  ;; from snapshot deltas), connection/pool gauges, per-status counts,
  ;; every metrics-count! family; refreshes every 2s, keeps a rolling
  ;; 3-minute window. Single-quoted HTML/JS so the whole page lives in
  ;; one plain Scheme string, split where data-path is spliced in.
  (define dashboard-head "<!doctype html>
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

  (define dashboard-tail "';
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

  ;; dashboard page handler: fully self-contained (works air-gapped),
  ;; assembled ONCE at registration. data-path is the URL where
  ;; metrics-json is registered; it is spliced into a single-quoted JS
  ;; string, so a quote in it must fail here, not XSS the page.
  (define (metrics-dashboard data-path)
    (do ((i 0 (+ i 1))) ((= i (string-length data-path)))
      (when (char=? (string-ref data-path i) #\')
        (assertion-violation 'metrics-dashboard
          "data path must not contain a single quote" data-path)))
    (let ((page (string-append dashboard-head data-path dashboard-tail)))
      (lambda (req res) (send-html! res page))))
)
