#!chezscheme
;;; (igropyr ssr) -- cached server-side rendering.
;;;
;;; Run a baked JS render bundle through (igropyr quickjs) and cache the
;;; HTML by key, so the (blocking) render runs once per (key, ttl) instead
;;; of once per request. SSR helps SEO, but the content that needs SEO is
;;; public and slow-changing -- so the right shape is a cache in FRONT of
;;; the engine, not a render per request. A qjs-call blocks the calling
;;; scheduler for the render's duration (FFI is non-preemptible), so with
;;; the cache it fires only on a MISS; hits are a lookup that never touches
;;; the engine.
;;;
;;;   ;; at boot -- ONE bundle per process (the engine is process-global);
;;;   ;; export as many render functions as you like and call them by name.
;;;   (define r (make-ssr "
;;;     function renderPost(j){ var p = JSON.parse(j);
;;;       return '<article><h1>'+p.title+'</h1>'+p.body+'</article>'; }"))
;;;
;;;   ;; in a handler: props (a Scheme value) is JSON-encoded and handed to
;;;   ;; the JS function as one string; the string it returns is the HTML.
;;;   (send-html! res (ssr-render r "renderPost"
;;;                     '(("title" . "Hi") ("body" . "<p>...</p>"))
;;;                     '((key . "/blog/42"))))    ; explicit key = the URL
;;;
;;;   (ssr-invalidate! r "/blog/42")   ; drop one entry on a content change
;;;   (ssr-clear! r)                   ; drop all (e.g. after a deploy)
;;;   (ssr-stats r)                    ; ((hits . N) (misses . M) ...)
;;;
;;; Cache backend (make-ssr opt (cache . ...)):
;;;   'memory   (default) -- an in-process gen-server (key -> html . expiry)
;;;             with a TTL ticker and a size cap; shared across this process's
;;;             workers, exact stats.
;;;   (redis <conn> [prefix]) -- a shared Redis (SET ... PX for server-side
;;;             TTL), so a render on one NODE is a hit on the others. <conn>
;;;             is an (igropyr redis) connection; prefix defaults to "ssr:".
;;;             Stats (hits/misses) are per-node and approximate.
;;;
;;; Render function contract: (fn jsonString) -> htmlString, PURE -- props
;;; in, HTML out, no side effects (the JS heap is shared across calls, so do
;;; not accumulate per-request state in globals). A JS throw / timeout / OOM
;;; is handled by the shim (crash-only rebuild + wall-clock deadline);
;;; ssr-render re-raises it (let-it-crash) and does NOT cache a failure --
;;; use ssr-try-render for a non-raising (values ok? text) result.
;;;
;;; Keys default to sha256(fn+props); pass (key . "...") -- typically the URL
;;; -- so hits skip prop hashing. NOT single-flight: N concurrent misses for
;;; the same cold key each render once -- spread that load across cluster
;;; nodes rather than funnel it. One ssr per process (make-ssr reboots the
;;; one engine; a second bundle would replace the first).

(library (igropyr ssr)
  (export make-ssr ssr-render ssr-try-render
          ssr-invalidate! ssr-clear! ssr-stats)
  (import (chezscheme)
          (igropyr actor) (igropyr libuv) (igropyr gen-server)
          (only (igropyr quickjs) qjs-boot! qjs-call qjs-call!)
          (only (igropyr json) json->string)
          (only (igropyr crypto) sha256 bytevector->hex)
          (only (igropyr redis) redis))

  (define default-ttl-ms 60000)        ; 1 minute
  (define default-cap    1024)         ; max cached entries (memory backend)
  (define prune-interval-ms 30000)     ; TTL sweep cadence (memory backend)

  (define (opt-ref o k d) (let ((p (assq k o))) (if p (cdr p) d)))

  ;; ---- a cache backend is #(get put drop clear stats) -------------------
  ;;   get  : key -> html-string or #f      put : key html ttl-ms -> _
  ;;   drop : key -> _   clear : -> _        stats : -> alist
  (define (b-get b k)       ((vector-ref b 0) k))
  (define (b-put b k h ttl) ((vector-ref b 1) k h ttl))
  (define (b-drop b k)      ((vector-ref b 2) k))
  (define (b-clear b)       ((vector-ref b 3)))
  (define (b-stats b)       ((vector-ref b 4)))

  ;; ---- in-process backend: a gen-server (the session-store shape) -------
  ;; state #(tbl hits misses cap); tbl : key -> (html . expiry-ms)
  (define (make-cache-init cap)
    (lambda () (vector (make-hashtable string-hash string=?) 0 0 cap)))
  (define (bump! st i) (vector-set! st i (+ 1 (vector-ref st i))))

  (define (cache-call msg from st)
    (let ((tbl (vector-ref st 0)))
      (case (vector-ref msg 0)
        ((get)
         (let ((e (hashtable-ref tbl (vector-ref msg 1) #f)))
           (if (and e (> (cdr e) (now-ms)))
               (begin (bump! st 1) (values (car e) st))   ; hit
               (begin (bump! st 2) (values #f st)))))     ; miss
        ((stats)
         (values (list (cons 'hits (vector-ref st 1))
                       (cons 'misses (vector-ref st 2))
                       (cons 'size (hashtable-size tbl))
                       (cons 'backend 'memory))
                 st))
        (else (values 'bad-request st)))))

  (define (cache-cast msg st)
    (let ((tbl (vector-ref st 0)) (cap (vector-ref st 3)))
      (case (vector-ref msg 0)
        ((put)                                  ; msg = #(put key html ttl-ms)
         (hashtable-set! tbl (vector-ref msg 1)
           (cons (vector-ref msg 2) (+ (now-ms) (vector-ref msg 3))))
         (when (> (hashtable-size tbl) cap) (evict! tbl cap)))
        ((drop)  (hashtable-delete! tbl (vector-ref msg 1)))
        ((clear) (hashtable-clear! tbl))
        ((prune) (drop-expired! tbl))))
    st)

  (define (drop-expired! tbl)
    (let ((now (now-ms)))
      (let-values (((ks vs) (hashtable-entries tbl)))
        (vector-for-each
          (lambda (k v) (when (<= (cdr v) now) (hashtable-delete! tbl k)))
          ks vs))))

  ;; over cap: drop expired first, then the single soonest-to-expire entry
  (define (evict! tbl cap)
    (drop-expired! tbl)
    (when (> (hashtable-size tbl) cap)
      (let-values (((ks vs) (hashtable-entries tbl)))
        (let loop ((i 0) (mk #f) (me #f))
          (if (fx= i (vector-length ks))
              (when mk (hashtable-delete! tbl mk))
              (let ((e (cdr (vector-ref vs i))))
                (if (or (not me) (< e me))
                    (loop (fx+ i 1) (vector-ref ks i) e)
                    (loop (fx+ i 1) mk me))))))))

  (define (prune-loop pid)
    (sleep-ms prune-interval-ms)
    (gen-server-cast pid (vector 'prune))
    (prune-loop pid))

  (define (make-memory-backend cap)
    (let ((pid (gen-server-start (make-cache-init cap) cache-call cache-cast)))
      (spawn (lambda () (prune-loop pid)))
      (vector
        (lambda (k)       (gen-server-call pid (vector 'get k)))
        (lambda (k h ttl) (gen-server-cast pid (vector 'put k h ttl)))
        (lambda (k)       (gen-server-cast pid (vector 'drop k)))
        (lambda ()        (gen-server-cast pid (vector 'clear)))
        (lambda ()        (gen-server-call pid (vector 'stats))))))

  ;; ---- redis backend: cross-node, TTL server-side (SET ... PX) ----------
  ;; get/put/drop are one round-trip each on the caller's green process (the
  ;; connection pipelines across workers). Hits/misses are per-node counters.
  (define (bump-box! b) (set-box! b (+ 1 (unbox b))))

  (define (redis-clear! conn prefix)     ; SCAN + DEL over the prefix
    (let loop ((cursor "0"))
      (let* ((r (redis conn "SCAN" cursor "MATCH" (string-append prefix "*")
                       "COUNT" 200))
             (next (car r)) (keys (cadr r)))
        (unless (null? keys) (apply redis conn "DEL" keys))
        (unless (string=? next "0") (loop next)))))

  (define (make-redis-backend conn prefix)
    (let ((hits (box 0)) (misses (box 0)))
      (define (k* k) (string-append prefix k))
      (vector
        (lambda (k)
          (let ((v (redis conn "GET" (k* k))))
            (if v (begin (bump-box! hits) v) (begin (bump-box! misses) #f))))
        (lambda (k h ttl) (redis conn "SET" (k* k) h "PX" ttl))   ; sync put
        (lambda (k) (redis conn "DEL" (k* k)))
        (lambda () (redis-clear! conn prefix))
        (lambda () (list (cons 'hits (unbox hits))
                         (cons 'misses (unbox misses))
                         (cons 'backend 'redis))))))

  (define (make-backend spec cap)
    (cond
      ((eq? spec 'memory) (make-memory-backend cap))
      ((and (pair? spec) (eq? (car spec) 'redis))
       (make-redis-backend (cadr spec)
         (if (pair? (cddr spec)) (caddr spec) "ssr:")))
      (else (assertion-violation 'make-ssr
              "cache must be 'memory or (redis conn [prefix])" spec))))

  ;; ---- public ssr: #(backend ttl) --------------------------------------
  (define (make-ssr bundle . opt)
    (let* ((opts (if (pair? opt) (car opt) '()))
           (ttl  (opt-ref opts 'ttl-ms default-ttl-ms))
           (cap  (opt-ref opts 'max-entries default-cap))
           (qopts (opt-ref opts 'quickjs '()))
           (backend (make-backend (opt-ref opts 'cache 'memory) cap)))
      (qjs-boot! bundle qopts)          ; process-global engine; one per process
      (vector backend ttl)))

  (define (ssr-backend r) (vector-ref r 0))
  (define (ssr-ttl r) (vector-ref r 1))

  (define (props->json props) (if (string? props) props (json->string props)))
  (define (render-key fn json)
    (string-append fn ":" (bytevector->hex (sha256 (string->utf8 json)))))
  (define (cache-key opts fn json)
    (or (opt-ref opts 'key #f) (render-key fn json)))

  ;; Render fn(props) to HTML, cached. props: a Scheme value (JSON-encoded)
  ;; or a pre-encoded JSON string. Raises a JS error like qjs-call! (on a
  ;; miss only; failures are never cached).
  (define (ssr-render r fn props . opt)
    (let* ((opts (if (pair? opt) (car opt) '()))
           (json (props->json props))
           (key  (cache-key opts fn json))
           (hit  (b-get (ssr-backend r) key)))
      (or hit
          (let ((html (qjs-call! fn json)))       ; blocks this worker (rare)
            (b-put (ssr-backend r) key html (ssr-ttl r))
            html))))

  ;; Non-raising: -> (values ok? html-or-error-text). A failing render is
  ;; returned, never cached.
  (define (ssr-try-render r fn props . opt)
    (let* ((opts (if (pair? opt) (car opt) '()))
           (json (props->json props))
           (key  (cache-key opts fn json))
           (hit  (b-get (ssr-backend r) key)))
      (if hit
          (values #t hit)
          (let-values (((ok s) (qjs-call fn json)))
            (when ok (b-put (ssr-backend r) key s (ssr-ttl r)))
            (values ok s)))))

  (define (ssr-invalidate! r key) (b-drop (ssr-backend r) key))
  (define (ssr-clear! r)          (b-clear (ssr-backend r)))
  (define (ssr-stats r)           (b-stats (ssr-backend r)))
)
