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
;;; Single-flight (on by default; (single-flight . #f) to disable): N
;;; concurrent misses for the SAME cold key collapse to ONE render -- the
;;; first claimant renders, the rest wait for its result. This is per-process
;;; (it dedups a process's workers, which all share the one mutex-serialized
;;; engine); a cross-NODE herd is still spread across nodes, not locked. If
;;; the rendering worker is killed mid-render, waiters fall back to rendering
;;; themselves after a timeout (the stuck claim self-heals).
;;;
;;; Render function contract: (fn jsonString) -> htmlString, PURE -- props in,
;;; HTML out, no side effects (the JS heap is shared across calls, so do not
;;; accumulate per-request state in globals). A JS throw / timeout / OOM is
;;; handled by the shim (crash-only rebuild + wall-clock deadline); ssr-render
;;; re-raises it (let-it-crash) and does NOT cache a failure -- use
;;; ssr-try-render for a non-raising (values ok? text) result.
;;;
;;; Keys default to sha256(fn+props); pass (key . "...") -- typically the URL
;;; -- so hits skip prop hashing. One ssr per process (make-ssr reboots the
;;; one engine; a second bundle would replace the first).
;;;
;;; Where the render RUNS (make-ssr opt (engine . ...)):
;;;   omitted   in this process, on the scheduler's thread. A miss blocks
;;;             everything for the render's duration -- see the qjs-call
;;;             note above -- which the cache makes rare but does not bound.
;;;   <qjspool> in worker PROCESSES. A miss then blocks only the calling
;;;             green process, so a wave of misses for different keys costs
;;;             latency instead of the node's availability. `bundle` is not
;;;             evaluated here at all in this mode: the workers own it.
;;;
;;;   (define p (qjspool '(("127.0.0.1" . 9701) ("127.0.0.1" . 9702))))
;;;   (define r (make-ssr "" `((engine . ,p))))   ; bundle lives in the workers

(library (igropyr ssr)
  (export make-ssr ssr-render ssr-render/bytes ssr-try-render ssr-try-render/bytes
          ssr-invalidate! ssr-clear! ssr-stats)
  (import (chezscheme)
          (igropyr actor) (igropyr gen-server)
          (only (igropyr libuv) now-ms)
          (only (igropyr quickjs) qjs-boot! qjs-call/bytes)
          (only (igropyr qjspool) qjspool? qjspool-render/bytes qjspool-timeout-ms)
          (only (igropyr json) json->string)
          (only (igropyr crypto) sha256 bytevector->hex)
          (only (igropyr redis) redis))

  (define default-ttl-ms 60000)        ; 1 minute
  (define default-cap    1024)         ; max cached entries (memory backend)
  (define prune-interval-ms 30000)     ; TTL sweep cadence (memory backend)
  (define flight-wait-margin-ms 1000)  ; follower wait = the engine deadline + this

  (define (opt-ref o k d) (let ((p (assq k o))) (if p (cdr p) d)))

  ;; ---- a cache backend is #(get put drop clear stats) -------------------
  ;;   get  : key -> html-string or #f      put : key html ttl-ms -> _
  ;;   drop : key -> _   clear : -> _        stats : -> alist
  ;; A cache outage must DEGRADE to rendering, never become an outage of
  ;; its own: with the redis backend, a dropped connection made b-get raise
  ;; before the engine was ever asked, so every request 500'd while quickjs
  ;; sat there perfectly able to render. A failed b-put is likewise just a
  ;; miss next time -- and it must not escape after a successful render,
  ;; which would strand the single-flight followers waiting on a publish
  ;; that never comes.
  (define (b-get b k)       (guard (e (#t #f)) ((vector-ref b 0) k)))
  (define (b-put b k h ttl) (guard (e (#t #f)) ((vector-ref b 1) k h ttl)))
  (define (b-drop b k)      (guard (e (#t #f)) ((vector-ref b 2) k)))
  (define (b-clear b)       (guard (e (#t #f)) ((vector-ref b 3))))
  (define (b-stats b)       (guard (e (#t '())) ((vector-ref b 4))))

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
  (define (bump-box! b) (set-box! b (+ 1 (unbox b))))

  ;; escape Redis glob metachars so a prefix like "a*b:" matches literally
  (define (glob-escape s)
    (list->string
      (fold-right (lambda (c acc)
                    (if (memv c '(#\* #\? #\[ #\] #\\)) (cons #\\ (cons c acc)) (cons c acc)))
                  '() (string->list s))))

  (define (redis-clear! conn prefix)     ; SCAN + DEL over the prefix
    (let loop ((cursor "0"))
      (let* ((r (redis conn "SCAN" cursor "MATCH" (string-append (glob-escape prefix) "*")
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
            ;; the cache currency is a bytevector, but the value is UTF-8
            ;; HTML so the client decodes it to a string -- re-encode to
            ;; bytes (the one conversion redis can't avoid; the socket send
            ;; would encode anyway). A bytevector reply passes through; nil = miss
            (cond ((string? v) (bump-box! hits) (string->utf8 v))
                  ((bytevector? v) (bump-box! hits) v)
                  (else (bump-box! misses) #f))))
        (lambda (k h ttl)                                          ; sync put (h: bytevector)
          (when (> ttl 0) (redis conn "SET" (k* k) h "PX" ttl)))   ; PX 0 -> redis -ERR
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

  ;; ---- single-flight coordinator: a gen-server, key -> waiter pids ------
  (define (flight-init) (make-hashtable string-hash string=?))

  ;; Monotone across the coordinator's life: identifies one round of a key,
  ;; so a publish can be checked against the round that is actually live.
  (define flight-generation 0)

  ;; An entry is #(generation leader waiters). waiters are (who . ref): the
  ;; ref keeps a late publish from being matched by the caller's NEXT wait.
  ;; The generation does the other half -- it keeps a late publish from an
  ;; ABANDONED round from waking the waiters of the round that replaced it,
  ;; which would hand them an arbitrarily stale render and delete the live
  ;; round's entry underneath it. A ref cannot cover that: the waiters it
  ;; would wake are new, and their refs are exactly the ones the stale
  ;; publish carries no knowledge of.
  ;;
  ;; The LEADER is recorded because a round whose leader is gone is not a
  ;; round. Without it, a request joining such a key waited out the whole
  ;; timeout before rendering, every time, for as long as the key stayed
  ;; cold -- and a waiter that was killed rather than timing out never
  ;; unclaimed, so the entry never emptied and never dropped: the key was
  ;; wedged in follower-forever mode permanently.
  (define (entry-gen e) (vector-ref e 0))
  (define (entry-leader e) (vector-ref e 1))
  (define (entry-waiters e) (vector-ref e 2))
  (define (live-waiters ws) (filter (lambda (w) (process-alive? (car w))) ws))

  (define (flight-call msg from tbl)      ; claim -> 'leader | 'follower
    (case (vector-ref msg 0)
      ((claim)
       (let ((key (vector-ref msg 1)) (who (vector-ref msg 2))
             (ref (vector-ref msg 3)))
         (let* ((e (hashtable-ref tbl key #f))
                ;; a dead leader's round is not one to join
                (e (and e (process-alive? (entry-leader e)) e)))
           (if e
               (begin (hashtable-set! tbl key
                        (vector (entry-gen e) (entry-leader e)
                                (cons (cons who ref)
                                      (live-waiters (entry-waiters e)))))
                      (values (cons 'follower (entry-gen e)) tbl))
               (let ((g (begin (set! flight-generation (+ flight-generation 1))
                               flight-generation)))
                 (hashtable-set! tbl key (vector g who '()))
                 (values (cons 'leader g) tbl))))))
      (else (values 'bad-request tbl))))

  (define (flight-cast msg tbl)
    (case (vector-ref msg 0)
      ((publish)                          ; leader done: wake waiters, drop key
       (let* ((key (vector-ref msg 1)) (res (vector-ref msg 2))
              (g (vector-ref msg 3))
              (e (hashtable-ref tbl key #f)))
         ;; Only the round that is still live may publish. A leader whose
         ;; round was abandoned (its followers gave up and started a new
         ;; one) still finishes and still publishes -- silently dropping
         ;; that is the point, because waking the new round's waiters with
         ;; the old round's render is how a caller receives content from
         ;; before whatever invalidated the key.
         (when (and e (= (entry-gen e) g))
           (for-each (lambda (w) (send (car w) (vector 'ssr-flight (cdr w) res)))
                     (entry-waiters e))
           (hashtable-delete! tbl key))))
      ((retire)
       ;; EVERY round in progress is producing content that has just been
       ;; invalidated. The epoch already stops those renders reaching the
       ;; cache, but it does not stop them reaching a caller: a request
       ;; arriving AFTER the invalidation joined the round that was already
       ;; running and was handed its pre-invalidation HTML. Invalidating has
       ;; to draw a line for readers, not only for the cache.
       ;;
       ;; Waiters are woken with #f rather than left to time out -- they
       ;; have a fresh render to do and no reason to wait for one that no
       ;; longer counts.
       (let ((ks (hashtable-keys tbl)))
         (vector-for-each
           (lambda (k)
             (let ((e (hashtable-ref tbl k #f)))
               (when e
                 (for-each
                   (lambda (w) (send (car w) (vector 'ssr-flight (cdr w) #f)))
                   (entry-waiters e)))))
           ks)
         (hashtable-clear! tbl)))
      ((unclaim)                          ; a follower timed out (dead leader)
       (let ((key (vector-ref msg 1)) (ref (vector-ref msg 2))
             (g (vector-ref msg 3)))
         (let ((e (hashtable-ref tbl key #f)))
           (when (and e (= (entry-gen e) g))
             ;; dead waiters go too: one that was KILLED never unclaims, and
             ;; while it is counted the entry can never empty
             (let ((ws (live-waiters
                         (remp (lambda (w) (eq? (cdr w) ref))
                               (entry-waiters e)))))
               ;; last waiter gone with no publish -> the leader is stuck; drop
               ;; the entry so the key isn't wedged in follower-forever mode
               (if (null? ws) (hashtable-delete! tbl key)
                   (hashtable-set! tbl key
                     (vector g (entry-leader e) ws)))))))))
    tbl)

  ;; render (non-raising) + cache on success -> (ok . text). Each call is one
  ;; actual engine render, so it bumps the render counter -- under single-flight
  ;; `misses` (cache misses) can exceed `renders` (followers miss but don't render).
  ;; Bumped by every invalidate and clear. A render reads it before it
  ;; starts and refuses to write its result if it changed meanwhile: the
  ;; single-flight generation guarded only the PUBLISH, so an in-flight
  ;; render still put its result into the cache after the entry it was
  ;; producing had been dropped -- reinstating exactly the content the
  ;; invalidation existed to remove, with a fresh TTL.
  ;;
  ;; One counter for all keys, not one per key. Invalidating A therefore
  ;; also suppresses a concurrent render of B, which costs that render a
  ;; re-run and can never serve anything stale. The other direction would
  ;; not be worth the bookkeeping.
  (define cache-epoch 0)
  (define (bump-epoch!) (set! cache-epoch (+ cache-epoch 1)))

  ;; WHERE THE RENDER HAPPENS. The in-process engine and a pool of worker
  ;; processes answer the same question the same way -- (values ok?
  ;; bytes-or-error-text) -- so everything above this line is identical for
  ;; both and the choice is one field of the ssr record.
  ;;
  ;; They are not equivalent, and the difference is not about speed. An
  ;; in-process render blocks the scheduler for its whole duration, so a
  ;; miss storm is an availability event; a pooled one blocks only the
  ;; calling green process. See the header of (igropyr qjspool).
  (define (render-with engine fn json)
    (if engine
        (qjspool-render/bytes engine fn json)
        (qjs-call/bytes fn json)))

  (define (call+cache renders backend key fn json ttl engine)
    (set-box! renders (+ 1 (unbox renders)))
    (let ((epoch cache-epoch)
          (res (guard (e (#t (cons #f (flight-error-text e))))
                 ;; bytes are the cache currency: skips a utf8->string of the
                 ;; render output on every miss, and lets a byte consumer send
                 ;; the memory-cache hit straight through with no re-encode
                 (let-values (((ok s) (render-with engine fn json))) (cons ok s)))))
      (when (and (car res) (= epoch cache-epoch))
        (b-put backend key (cdr res) ttl)
        ;; ...and again AFTER. The check above is not atomic with the write:
        ;; the memory backend's put is a cast the invalidation's drop can be
        ;; queued ahead of, and the redis backend's is a network call that
        ;; parks for as long as the round trip takes. An invalidation
        ;; landing in that window left the render it existed to remove
        ;; sitting in the cache with a fresh TTL -- exactly the outcome the
        ;; epoch was added to prevent, just through a narrower door.
        ;;
        ;; Undoing it can at worst drop a NEWER entry somebody else wrote in
        ;; the same window, which costs one re-render and can never serve
        ;; anything stale. The other way round is not a trade worth making.
        (unless (= epoch cache-epoch)
          (b-drop backend key)))
      res))

  (define (flight-error-text e)
    (cond ((string? e) e)
          ((and (condition? e) (message-condition? e)) (condition-message e))
          (else "ssr render error")))

  ;; the miss path: single-flight around call+cache. -> (ok . text)
  (define (render-miss r fn json key)
    (let ((flight (ssr-flight r)) (backend (ssr-backend r)) (ttl (ssr-ttl r))
          (rnd (ssr-renders r)) (eng (ssr-engine r)))
      (if (not flight)
          (call+cache rnd backend key fn json ttl eng)
          (begin
          ;; drop the late answer to any earlier round we abandoned: its
          ;; ref can never match again, so it would linger forever
          (let drain () (receive (after 0 'done) (`#(ssr-flight ,r ,v) (drain))))
          (let* ((ref (gensym))
                 ;; claim answers (role . generation): the generation names
                 ;; THIS round, so a publish or unclaim from a round that has
                 ;; since been abandoned is ignored rather than applied to
                 ;; whatever round replaced it
                 (claimed (gen-server-call flight (vector 'claim key self ref)))
                 (role (car claimed))
                 (gen (cdr claimed)))
            ;; What a follower does when it stops waiting -- because it
            ;; gave up, or because an invalidation retired the round.
            ;; It LOOKS IN THE CACHE FIRST. The leader may have finished
            ;; and written and then died before publishing, or simply have
            ;; taken longer than the wait allowed for -- the wait covers a
            ;; render, not the leader's own cache round trips, which with a
            ;; remote cache are network calls of their own. Rendering
            ;; without looking turns both into a herd on a key that is
            ;; already warm.
            (define (fallback!)
              (let ((again (b-get backend key)))
                (if again
                    (cons #t again)
                    (call+cache rnd backend key fn json ttl eng))))
            (if (eq? role 'leader)
                (let* ((again (b-get backend key))       ; double-check
                       (res (if again (cons #t again)
                                (call+cache rnd backend key fn json ttl eng))))
                  (gen-server-cast flight (vector 'publish key res gen))
                  res)
                (receive (after (ssr-flight-wait r)
                            ;; leader vanished -> render ourselves
                            (gen-server-cast flight (vector 'unclaim key ref gen))
                            (fallback!))
                  ;; #f is a RETIREMENT: an invalidation ended this round,
                  ;; so there is nothing to wait for and the answer it would
                  ;; have given is one this caller must not receive
                  (`#(ssr-flight ,@ref ,res)
                    (if res res (fallback!))))))))))

  ;; ---- public ssr: #(backend ttl flight wait renders engine) ------------
  ;;
  ;; (engine . <a qjspool>) renders in WORKER PROCESSES instead of on this
  ;; thread. Then `bundle` is not evaluated here at all -- the workers own
  ;; it, and were this process to boot a second copy of the engine it would
  ;; be paying for a runtime nothing would ever call. Everything else about
  ;; the cache, single-flight and invalidation is unchanged: what moves is
  ;; only where the miss is served.
  (define (make-ssr bundle . opt)
    (let* ((opts (if (pair? opt) (car opt) '()))
           (ttl  (opt-ref opts 'ttl-ms default-ttl-ms))
           (cap  (opt-ref opts 'max-entries default-cap))
           (qopts (opt-ref opts 'quickjs '()))
           (engine (opt-ref opts 'engine #f))
           ;; a follower must wait AT LEAST the leader's own render deadline,
           ;; or it would time out mid-render and start the very herd that
           ;; single-flight exists to prevent (quickjs timeout-ms default 2000)
           (wait (+ (if engine
                        (qjspool-timeout-ms engine)
                        (opt-ref qopts 'timeout-ms 2000))
                    flight-wait-margin-ms))
           (backend (make-backend (opt-ref opts 'cache 'memory) cap))
           (flight (and (opt-ref opts 'single-flight #t)
                        (gen-server-start flight-init flight-call flight-cast))))
      (when (and engine (not (qjspool? engine)))
        (assertion-violation 'make-ssr
          "the engine option takes a render pool from (igropyr qjspool)" engine))
      (unless engine
        (qjs-boot! bundle qopts))       ; process-global engine; one per process
      (vector backend ttl flight wait (box 0) engine)))

  (define (ssr-backend r)     (vector-ref r 0))
  (define (ssr-ttl r)         (vector-ref r 1))
  (define (ssr-flight r)      (vector-ref r 2))
  (define (ssr-flight-wait r) (vector-ref r 3))
  (define (ssr-renders r)     (vector-ref r 4))
  (define (ssr-engine r)      (vector-ref r 5))

  ;; a STRING props is the raw JSON arg (caller guarantees it is valid JSON);
  ;; any other Scheme value is JSON-encoded
  (define (props->json props) (if (string? props) props (json->string props)))
  (define (render-key fn json)
    (string-append fn ":" (bytevector->hex (sha256 (string->utf8 json)))))
  (define (cache-key opts fn json)
    (or (opt-ref opts 'key #f) (render-key fn json)))

  ;; Render fn(props) to HTML, cached. props: any Scheme value -> json->string,
  ;; OR a string, passed RAW as the JSON argument (you guarantee it is valid
  ;; JSON; a non-JSON string makes the render's JSON.parse throw). Raises a JS
  ;; error like qjs-call! (on a miss only; failures are never cached).
  ;; The cache currency is a UTF-8 bytevector: ssr-render/bytes returns it
  ;; raw (hand straight to a socket, no re-encode); ssr-render decodes to a
  ;; Scheme string for back-compat.
  (define (ssr-render/bytes r fn props . opt)
    (let* ((opts (if (pair? opt) (car opt) '()))
           (json (props->json props))
           (key  (cache-key opts fn json))
           (hit  (b-get (ssr-backend r) key)))
      (or hit
          (let ((res (render-miss r fn json key)))
            (if (car res) (cdr res) (error 'ssr-render (cdr res) fn))))))
  (define (ssr-render r fn props . opt)
    (utf8->string (apply ssr-render/bytes r fn props opt)))

  ;; Non-raising: -> (values ok? html-or-error-text). A failing render is
  ;; returned, never cached. /bytes yields the HTML as UTF-8 bytes on ok;
  ;; the error text is always a string.
  (define (ssr-try-render/bytes r fn props . opt)
    (let* ((opts (if (pair? opt) (car opt) '()))
           (json (props->json props))
           (key  (cache-key opts fn json))
           (hit  (b-get (ssr-backend r) key)))
      (if hit
          (values #t hit)
          (let ((res (render-miss r fn json key)))
            (values (car res) (cdr res))))))
  (define (ssr-try-render r fn props . opt)
    (let-values (((ok v) (apply ssr-try-render/bytes r fn props opt)))
      (if ok (values #t (utf8->string v)) (values #f v))))

  ;; The epoch bump goes FIRST. Dropping the entry and then bumping leaves
  ;; a window in which a render that finished in between still writes.
  ;;
  ;; Retiring the in-flight rounds goes with it. The epoch keeps a render
  ;; that began before the invalidation out of the CACHE; it does not keep
  ;; it away from a caller that arrived after and joined that round. Both
  ;; halves are the same statement -- content from before this call must
  ;; not be served after it -- so they happen together.
  (define (retire-rounds! r)
    (bump-epoch!)
    (let ((f (ssr-flight r)))
      (when f (gen-server-cast f (vector 'retire)))))
  (define (ssr-invalidate! r key) (retire-rounds! r) (b-drop (ssr-backend r) key))
  (define (ssr-clear! r)          (retire-rounds! r) (b-clear (ssr-backend r)))
  (define (ssr-stats r)
    (cons (cons 'renders (unbox (ssr-renders r))) (b-stats (ssr-backend r))))
)
