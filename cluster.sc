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
;;; or one of the two built-ins:
;;;   (static (name host port) ...) -- a fixed list (self may be included;
;;;                                    it is skipped)
;;;   (redis conn host port)        -- each cycle the node heartbeats its
;;;     own (name host port) into a per-cluster sorted set keyed by an
;;;     expiry timestamp, prunes entries whose time has passed, and reads
;;;     the live set. A node that stops heartbeating (crash, shutdown)
;;;     falls out after ttl-ms with no central bookkeeping.
;;;
;;; Options: (name . "default") namespaces the Redis key; (interval-ms .
;;; 5000) how often to discover + heartbeat; (ttl-ms . 15000) how long a
;;; Redis registration lives without a heartbeat (keep it a few
;;; intervals, so a node doesn't expire between beats).

(library (igropyr cluster)
  (export cluster-start cluster-stop)
  (import (chezscheme) (igropyr actor) (igropyr node) (igropyr redis)
          (only (igropyr libuv) now-ms))

  (define (opt alist key default)
    (let ((p (assq key alist))) (if p (cdr p) default)))

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

  (define (resolve-discover spec cluster-key ttl-ms)
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
      (let ((discover (resolve-discover spec cluster-key ttl)))
        (spawn (lambda () (cluster-loop discover interval))))))

  ;; Stop maintaining membership. Existing links stay up (and keep
  ;; auto-reconnecting); no new discovery runs.
  (define (cluster-stop handle)
    (when (process-alive? handle)
      (send handle (vector 'cluster-stop)))
    (void))
)
