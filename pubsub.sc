#!chezscheme
;;; (igropyr pubsub) -- topic-based publish/subscribe.
;;;
;;; A registered gen-server keeps topic -> subscriber lists. Publishers
;;; and subscribers never know about each other; dead subscribers are
;;; removed automatically (the server monitors each one), so WebSocket
;;; processes can subscribe and simply die when their connection closes.
;;;
;;;   (start-pubsub!)                 ; once, at boot
;;;   (subscribe 'room-1)             ; caller now receives...
;;;   (publish 'room-1 "hi")          ; ... #(pub room-1 "hi")
;;;   (unsubscribe 'room-1)
;;;
;;; Distribution: when (igropyr node) links are up, a publish is also
;;; forwarded ONE HOP to every directly-connected peer, whose pubsub
;;; server delivers it to its own local subscribers. This assumes a
;;; fully-connected mesh (as Erlang does): with every node dialed to
;;; every other, one hop reaches all subscribers, and a forwarded
;;; message is never re-forwarded, so there are no loops or duplicates.
;;; A distributed payload must be extended-wire-safe (see (igropyr
;;; sexpr)); a payload that will not serialize is still delivered
;;; locally, just not forwarded. With no node started, node-peers is
;;; empty and publish behaves exactly as the single-node version.

(library (igropyr pubsub)
  (export start-pubsub! subscribe unsubscribe publish)
  (import (chezscheme) (igropyr actor) (igropyr gen-server)
          (igropyr node))

  (define server-name 'igropyr-pubsub)

  ;; State is #(topics mons):
  ;;   topics: eq-hashtable topic -> list of subscriber pids
  ;;   mons:   eq-hashtable subscriber pid -> monitor ref
  ;; mons MUST live in the state, not in a library global: a supervisor
  ;; restart gives the new server a fresh state, and a global would keep
  ;; the dead server's monitor refs -- so a re-subscribing process would
  ;; look already-monitored, never be monitored by the NEW server, and
  ;; never be cleaned up when it dies.
  (define (init) (vector (make-eq-hashtable) (make-eq-hashtable)))
  (define (st-topics st) (vector-ref st 0))
  (define (st-mons st) (vector-ref st 1))

  (define (subscribed-anywhere? topics p)
    (let ((ks (hashtable-keys topics)))
      (let loop ((i 0))
        (and (< i (vector-length ks))
             (or (memq p (hashtable-ref topics (vector-ref ks i) '()))
                 (loop (+ i 1)))))))

  (define (handle-call msg from st)
    (let ((tag (vector-ref msg 0))
          (topic (vector-ref msg 1))
          (topics (st-topics st))
          (mons (st-mons st)))
      (case tag
        ((sub)
         (let ((subs (hashtable-ref topics topic '())))
           (unless (memq from subs)
             ;; one monitor per subscriber, not per subscription: a
             ;; process that joins and leaves topics repeatedly would
             ;; otherwise accumulate a monitor record per cycle (and get
             ;; one DOWN per record when it finally dies)
             (unless (hashtable-ref mons from #f)
               (hashtable-set! mons from (monitor from)))
             (hashtable-set! topics topic (cons from subs))))
         (values 'ok st))
        ((unsub)
         (let ((rest (remq from (hashtable-ref topics topic '()))))
           (if (null? rest)
               (hashtable-delete! topics topic)   ; don't keep empty topics
               (hashtable-set! topics topic rest)))
         ;; drop the monitor once this subscriber holds no subscriptions
         (unless (subscribed-anywhere? topics from)
           (let ((m (hashtable-ref mons from #f)))
             (when m
               (demonitor m)
               (hashtable-delete! mons from))))
         (values 'ok st))
        (else (values 'bad-request st)))))

  (define (deliver-local! topics topic payload)
    (for-each
      (lambda (p) (send p (vector 'pub topic payload)))
      (hashtable-ref topics topic '())))

  ;; forward one hop to every directly-connected peer's pubsub server,
  ;; as a remote publish (rpub) it will deliver locally but not re-emit.
  ;; Guarded per peer: a non-serializable payload degrades to local-only
  ;; rather than crashing this server.
  (define (forward! topic payload)
    (for-each
      (lambda (peer)
        (guard (e (#t (void)))
          (rsend peer server-name
                 (vector 'gen-cast (vector 'rpub topic payload)))))
      (node-peers)))

  ;; pub  = a local publish: deliver here, then fan out to peers
  ;; rpub = a publish arriving from a peer: deliver here only (no loop)
  (define (handle-cast msg st)
    (let ((tag (vector-ref msg 0))
          (topic (vector-ref msg 1))
          (payload (vector-ref msg 2)))
      (deliver-local! (st-topics st) topic payload)
      (when (eq? tag 'pub) (forward! topic payload))
      st))

  ;; DOWN from a dead subscriber: drop it from every topic
  (define (handle-info msg st)
    (if (and (vector? msg) (= 3 (vector-length msg))
             (eq? (vector-ref msg 0) 'DOWN))
        (let ((dead (vector-ref msg 1))
              (topics (st-topics st))
              (mons (st-mons st)))
          (vector-for-each
            (lambda (topic)
              (let ((rest (remq dead (hashtable-ref topics topic '()))))
                (if (null? rest)
                    (hashtable-delete! topics topic)
                    (hashtable-set! topics topic rest))))
            (hashtable-keys topics))
          (hashtable-delete! mons dead)     ; the monitor already fired
          st)
        st))

  (define (start-pubsub!)
    (gen-server-start-named server-name init handle-call handle-cast handle-info))

  (define (subscribe topic)
    (gen-server-call server-name (vector 'sub topic)))

  (define (unsubscribe topic)
    (gen-server-call server-name (vector 'unsub topic)))

  ;; async: the publisher never blocks
  (define (publish topic payload)
    (gen-server-cast server-name (vector 'pub topic payload)))
)
