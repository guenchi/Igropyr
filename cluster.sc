#!chezscheme
;;; (igropyr cluster) -- automatic mesh discovery over node links.
;;;
;;; node-connect! is manual: to form a mesh every node must dial every
;;; other, knowing each peer's name, host and port. This library adds the
;;; thin layer above that -- "who is in the cluster right now" -- and
;;; leaves the rest to the primitives already in (igropyr node):
;;; node-connect! reconnects on its own, monitor-node reports comings and
;;; goings. A background process periodically asks a DISCOVERY strategy
;;; for the member list and dials any it isn't linked to yet.
;;;
;;;   (node-start! 'a secret 4100 "0.0.0.0")
;;;   (cluster-start
;;;     `((discover . (static (b "10.0.0.2" 4100)     ; fixed list
;;;                           (c "10.0.0.3" 4100)))))
;;;
;;;   (cluster-start                                  ; via Redis
;;;     `((name . "myapp")
;;;       (discover . (redis ,conn "10.0.0.1" 4100))))  ; advertise self
;;;
;;;   (cluster-start `((discover . ,(lambda () (my-lookup)))))  ; custom
;;;
;;; A discover strategy is either a thunk returning ((name host port)...)
;;; or one of the three built-ins:
;;;   1. (static (name host port) ...) -- a fixed list (self may be
;;;                                    included; it is skipped)
;;;   2. (gossip (advertise host port)       -- fully decentralized: no
;;;           [(seeds (name host port) ...)]    shared store at all. Each
;;;           [(fanout . 3)])                   node keeps a replicated
;;;     member table and once per cycle PUSH-PULLs it with up to fanout
;;;     random connected peers, over the existing authenticated node
;;;     links. Addresses travel INSIDE the records, so knowing one member
;;;     is enough to learn every other; seeds are the configured first
;;;     contacts (bootstrap + rejoin rendezvous) -- permanent dial hints,
;;;     never expired -- and a seed node itself may run with no seeds.
;;;     A record is #(name host port incarnation heartbeat): only its
;;;     OWNER advances the heartbeat (incarnation = the owner's boot
;;;     stamp, so a restarted node outranks every record its old life
;;;     gossiped); a record whose (incarnation . heartbeat) has not
;;;     advanced for ttl-ms of LOCAL time is dropped -- expiry semantics
;;;     with no central store: a stale echo can never refresh a dead
;;;     record, so removed nodes age out everywhere within ~2 ttl,
;;;     zombie-free. All members of one cluster must use the same
;;;     (name . ...) option -- the membership server registers as
;;;     igropyr-gossip:<name> and peers rcall it by that name.
;;;   3. (redis conn host port)        -- each cycle the node heartbeats
;;;     its own (name host port) into a per-cluster sorted set keyed by an
;;;     expiry timestamp, prunes entries whose time has passed, and reads
;;;     the live set. A node that stops heartbeating (crash, shutdown)
;;;     falls out after ttl-ms with no central bookkeeping. Same expiry
;;;     model as gossip, but arbitrated by a shared Redis instead of
;;;     peer-to-peer -- reach for it when you already run Redis.
;;;
;;; Options: (name . "default") namespaces the Redis key / the gossip
;;; service; (interval-ms . 5000) how often to discover + heartbeat;
;;; (ttl-ms . 15000) how long a registration (Redis) or a member record
;;; (gossip) lives without a heartbeat (keep it a few intervals, so a
;;; node doesn't expire between beats).

(library (igropyr cluster)
  (export cluster-start cluster-stop)
  (import (chezscheme) (igropyr util) (igropyr actor) (igropyr node)
          (igropyr redis) (igropyr gen-server)
          (only (igropyr libuv) now-ms))

  ;; Discovery records come from a shared store (a Redis key any node can
  ;; write); treat them as untrusted. These bound what one poisoned or
  ;; runaway record can cost us: an unbounded name interned as a symbol,
  ;; a garbage host string driving DNS, an out-of-range port, or a flood
  ;; of members each spawning a connector.
  (define max-node-name 64)
  (define max-host-len 253)          ; DNS name ceiling
  (define max-members 256)           ; dialed per discovery cycle

  (define (valid-port? p)
    (and (integer? p) (exact? p) (<= 1 p 65535)))

  (define (valid-host? h)
    (let ((n (string-length h)))
      (and (fx> n 0) (fx<= n max-host-len)
           (let lp ((i 0))
             (or (fx= i n)
                 (let ((c (string-ref h i)))
                   (and (or (char<=? #\a c #\z) (char<=? #\A c #\Z)
                            (char<=? #\0 c #\9) (memv c '(#\. #\- #\:)))
                        (lp (fx+ i 1)))))))))

  (define (valid-node-name? s)
    (let ((n (string-length s)))
      (and (fx> n 0) (fx<= n max-node-name)
           (let lp ((i 0))
             (or (fx= i n)
                 (let ((c (string-ref s i)))
                   (and (or (char<=? #\a c #\z) (char<=? #\A c #\Z)
                            (char<=? #\0 c #\9) (memv c '(#\- #\_ #\.)))
                        (lp (fx+ i 1)))))))))

  ;; ---- discovery strategies ---------------------------------------------

  (define (split-spaces s)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n) (reverse (if (> i start) (cons (substring s start i) acc) acc)))
          ((char=? (string-ref s i) #\space)
           (loop (+ i 1) (+ i 1)
                 (if (> i start) (cons (substring s start i) acc) acc)))
          (else (loop (+ i 1) start acc))))))

  ;; "name host port" -> (name host port), or #f if malformed or if any
  ;; field fails validation (bad name, host, or out-of-range port)
  (define (parse-member str)
    (let ((parts (split-spaces str)))
      (and (= (length parts) 3)
           (valid-node-name? (car parts))
           (valid-host? (cadr parts))
           (let ((port (string->number (caddr parts))))
             (and port (valid-port? port)
                  (list (string->symbol (car parts)) (cadr parts) port))))))

  (define (redis-discover conn cluster-key self-name self-host self-port ttl-ms)
    ;; self-member is a stable string so a re-heartbeat updates the score
    ;; rather than adding a duplicate
    (let ((self-member (string-append (symbol->string self-name) " "
                                      self-host " " (number->string self-port))))
      (lambda ()
        (let ((now (now-ms)))
          (redis conn "ZADD" cluster-key (number->string (+ now ttl-ms)) self-member)
          (redis conn "ZREMRANGEBYSCORE" cluster-key "-inf"
                 (number->string (- now 1)))          ; drop expired members
          (let ((members (redis conn "ZRANGEBYSCORE" cluster-key
                                (number->string now) "+inf")))
            ;; members is a list of strings; parse and dedupe by node
            ;; name, and stop at max-members so a flooded key cannot make
            ;; us spawn an unbounded number of connectors
            (let dedupe ((ms (if (list? members) members '()))
                         (seen '()) (acc '()) (k 0))
              (if (or (null? ms) (fx>= k max-members))
                  (reverse acc)
                  (let ((p (parse-member (car ms))))
                    (if (and p (not (memq (car p) seen)))
                        (dedupe (cdr ms) (cons (car p) seen) (cons p acc) (fx+ k 1))
                        (dedupe (cdr ms) seen acc k))))))))))

  ;; ---- gossip strategy ----------------------------------------------------

  (define exchange-timeout-ms 1000)

  ;; k distinct elements, uniform, one pass (selection sampling)
  (define (pick-random lst k)
    (let loop ((l lst) (n (length lst)) (k k) (acc '()))
      (cond ((or (fx= k 0) (null? l)) acc)
            ((< (random n) k) (loop (cdr l) (- n 1) (- k 1) (cons (car l) acc)))
            (else (loop (cdr l) (- n 1) k acc)))))

  ;; One membership server per cluster handle, registered under svc so
  ;; peers can rcall it. View entry:
  ;;   name -> #(host port incarnation heartbeat last-advance-ms)
  ;; last-advance is LOCAL arrival time of the last record that actually
  ;; advanced (incarnation . heartbeat) -- the zombie-killer: a stale
  ;; echo merges as not-newer and cannot refresh it, so dead records age
  ;; out on every node's own clock. Records arrive over authenticated
  ;; links but are validated like any discovery input (bad name/host/
  ;; port dropped, view capped at max-members).
  (define (start-gossip-server! svc self-host self-port ttl-ms)
    (let ((table (make-eq-hashtable))
          (inc (now-ms))       ; boot stamp: a restart outranks the old life
          (hb 0))
      (define (newer? i1 h1 i2 h2)
        (or (> i1 i2) (and (= i1 i2) (> h1 h2))))
      (define (merge-one! r now)
        (when (and (vector? r) (fx= (vector-length r) 5))
          (let ((nm (vector-ref r 0)) (host (vector-ref r 1))
                (port (vector-ref r 2))
                (ri (vector-ref r 3)) (rh (vector-ref r 4)))
            (when (and (symbol? nm) (valid-node-name? (symbol->string nm))
                       (string? host) (valid-host? host) (valid-port? port)
                       (integer? ri) (exact? ri) (>= ri 0)
                       (integer? rh) (exact? rh) (>= rh 0))
              (if (eq? nm (node-self))
                  ;; an echo of us outranking the live us (a pre-restart
                  ;; record under clock skew): refute by jumping above it
                  (when (newer? ri rh inc hb) (set! inc (+ ri 1)))
                  (let ((e (hashtable-ref table nm #f)))
                    (cond
                      ((not e)
                       (when (< (hashtable-size table) max-members)
                         (hashtable-set! table nm (vector host port ri rh now))))
                      ((newer? ri rh (vector-ref e 2) (vector-ref e 3))
                       (hashtable-set! table nm (vector host port ri rh now))))))))))
      (define (prune! now)
        (vector-for-each
          (lambda (nm)
            (let ((e (hashtable-ref table nm #f)))
              (when (and e (> (- now (vector-ref e 4)) ttl-ms))
                (hashtable-delete! table nm))))
          (hashtable-keys table)))
      (define (wire now)              ; live records incl our own
        (prune! now)
        (let-values (((ks vs) (hashtable-entries table)))
          (let loop ((i 0)
                     (acc (list (vector (node-self) self-host self-port inc hb))))
            (if (fx= i (vector-length ks))
                acc
                (let ((e (vector-ref vs i)))
                  (loop (fx+ i 1)
                        (cons (vector (vector-ref ks i)
                                      (vector-ref e 0) (vector-ref e 1)
                                      (vector-ref e 2) (vector-ref e 3))
                              acc)))))))
      (define (members now)           ; ((name host port) ...) incl self
        (prune! now)                  ; (reconcile! filters self out)
        (let-values (((ks vs) (hashtable-entries table)))
          (let loop ((i 0)
                     (acc (list (list (node-self) self-host self-port))))
            (if (fx= i (vector-length ks))
                acc
                (let ((e (vector-ref vs i)))
                  (loop (fx+ i 1)
                        (cons (list (vector-ref ks i)
                                    (vector-ref e 0) (vector-ref e 1))
                              acc)))))))
      ;; a fresh cluster-start supersedes any previous membership server
      ;; for this cluster name (its handle degrades to failed discovery)
      (let ((old (whereis svc)))
        (when old (unregister svc) (kill old 'shutdown)))
      (register svc
        (gen-server-start
          (lambda () #f)
          ;; calls answer fast and never rcall out -- two servers
          ;; exchanging concurrently must not be able to deadlock
          (lambda (msg from st)
            (let ((now (now-ms)))
              (cond
                ((and (pair? msg) (eq? (car msg) 'exchange) (list? (cdr msg)))
                 (for-each (lambda (r) (merge-one! r now)) (cdr msg))
                 (values (wire now) st))
                ((eq? msg 'beat)
                 (set! hb (+ hb 1))
                 (values (wire now) st))
                ((eq? msg 'members)
                 (values (members now) st))
                (else (values #f st)))))
          (lambda (msg st)            ; cast: merge a pulled reply
            (when (and (pair? msg) (eq? (car msg) 'merge) (list? (cdr msg)))
              (let ((now (now-ms)))
                (for-each (lambda (r) (merge-one! r now)) (cdr msg))))
            st)))))

  (define (resolve-discover spec cname cluster-key ttl-ms)
    (cond
      ((procedure? spec) spec)
      ((and (pair? spec) (eq? (car spec) 'static))
       (let ((peers (cdr spec)))
         (unless (for-all (lambda (p) (and (list? p) (= 3 (length p))
                                           (symbol? (car p)) (string? (cadr p))
                                           (valid-host? (cadr p))
                                           (valid-port? (caddr p))))
                          peers)
           (assertion-violation 'cluster-start "static peers want (name host valid-port)" peers))
         (lambda () peers)))
      ((and (pair? spec) (eq? (car spec) 'gossip))
       (let* ((gopts (cdr spec))
              (adv (opt gopts 'advertise #f))
              (seeds (opt gopts 'seeds '()))
              (fanout (opt gopts 'fanout 3)))
         (unless (and (list? adv) (= 2 (length adv))
                      (string? (car adv)) (valid-host? (car adv))
                      (valid-port? (cadr adv)))
           (assertion-violation 'cluster-start
             "gossip wants (advertise host valid-port)" spec))
         (unless (for-all (lambda (p) (and (list? p) (= 3 (length p))
                                           (symbol? (car p)) (string? (cadr p))
                                           (valid-host? (cadr p))
                                           (valid-port? (caddr p))))
                          seeds)
           (assertion-violation 'cluster-start
             "gossip seeds want (name host valid-port)" seeds))
         (unless (and (fixnum? fanout) (fx> fanout 0))
           (assertion-violation 'cluster-start
             "gossip fanout wants a positive fixnum" fanout))
         (let ((svc (string->symbol (string-append "igropyr-gossip:" cname))))
           (start-gossip-server! svc (car adv) (cadr adv) ttl-ms)
           (lambda ()
             ;; push-pull: bump our heartbeat, trade full tables with up
             ;; to fanout random connected peers (each bounded; a peer
             ;; without the service just skips), then answer with the
             ;; merged view plus seed hints for names not in it -- the
             ;; bootstrap AND the rejoin path ride those seeds.
             (let ((mine (gen-server-call svc 'beat)))
               (for-each
                 (lambda (peer)
                   (let ((theirs (guard (e (#t #f))
                                   (rcall peer svc (cons 'exchange mine)
                                          exchange-timeout-ms))))
                     (when (list? theirs)
                       (gen-server-cast svc (cons 'merge theirs)))))
                 (pick-random (node-peers) fanout))
               (let ((view (gen-server-call svc 'members)))
                 (append view
                         (filter (lambda (s) (not (assq (car s) view)))
                                 seeds))))))))
      ((and (pair? spec) (eq? (car spec) 'redis))
       (let ((conn (cadr spec)) (host (caddr spec)) (port (cadddr spec)))
         (redis-discover conn cluster-key (node-self) host port ttl-ms)))
      (else (assertion-violation 'cluster-start "bad discover strategy" spec))))

  ;; ---- the maintainer process -------------------------------------------

  ;; Bring the live mesh in line with a successful discovery result:
  ;; dial members we have no link to, and DROP members this cluster
  ;; previously maintained that have now vanished from discovery.
  ;; `connected` is this handle's own responsibility set (the last
  ;; desired set); returns the new one. Only names we introduced are
  ;; ever disconnected, so a manual node-connect! or another cluster
  ;; handle's peers are left alone.
  (define (reconcile! connected peers)
    (let ((desired (filter (lambda (nm) (not (eq? nm (node-self))))
                           (map car peers))))
      (for-each
        (lambda (p)
          (let ((name (car p)))
            ;; node-connect! is idempotent and self-reconnecting, so we
            ;; only dial names we have no live link to yet
            (unless (or (eq? name (node-self)) (memq name (node-peers)))
              (node-connect! name (cadr p) (caddr p)))))
        peers)
      ;; a member removed from discovery (Redis entry expired/deleted, or
      ;; dropped from a static list) must actually lose its connector --
      ;; otherwise revoking a node in the registry never revokes access
      (for-each
        (lambda (nm) (unless (memq nm desired) (node-disconnect! nm)))
        connected)
      desired))

  (define (cluster-loop discover interval-ms)
    (let loop ((connected '()))
      ;; A discovery FAILURE (Redis down, DNS blip) yields #f and we skip
      ;; reconciling -- keep the links already up, retry next round. Only
      ;; a successful result (a list, possibly empty) is authoritative
      ;; enough to disconnect vanished members against.
      (let* ((result (guard (e (#t #f)) (discover)))
             (connected2 (if (list? result)
                             (reconcile! connected result)
                             connected)))
        (receive (after interval-ms (loop connected2))
          (`#(cluster-stop) 'done)))))

  ;; ---- public API --------------------------------------------------------

  ;; Start maintaining cluster membership; returns a handle for
  ;; cluster-stop. Call after node-start!.
  (define (cluster-start opts)
    (unless (node-self)
      (assertion-violation 'cluster-start "call node-start! first" opts))
    (let* ((cname (opt opts 'name "default"))
           (interval (opt opts 'interval-ms 5000))
           (ttl (opt opts 'ttl-ms 15000))
           (spec (opt opts 'discover #f))
           (cluster-key (string-append "igropyr:cluster:" cname)))
      (unless spec
        (assertion-violation 'cluster-start "no discover strategy" opts))
      (let ((discover (resolve-discover spec cname cluster-key ttl)))
        (spawn (lambda () (cluster-loop discover interval))))))

  ;; Stop maintaining membership. Existing links stay up (and keep
  ;; auto-reconnecting); no new discovery runs.
  (define (cluster-stop handle)
    (when (process-alive? handle)
      (send handle (vector 'cluster-stop)))
    (void))
)
