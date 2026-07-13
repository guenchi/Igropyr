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

  ;; state: eq-hashtable topic -> list of subscriber pids
  (define (init) (make-eq-hashtable))

  (define (handle-call msg from topics)
    (let ((tag (vector-ref msg 0))
          (topic (vector-ref msg 1)))
      (case tag
        ((sub)
         (let ((subs (hashtable-ref topics topic '())))
           (unless (memq from subs)
             (monitor from)     ; auto-cleanup when the subscriber dies
             (hashtable-set! topics topic (cons from subs))))
         (values 'ok topics))
        ((unsub)
         (hashtable-set! topics topic
           (remq from (hashtable-ref topics topic '())))
         (values 'ok topics))
        (else (values 'bad-request topics)))))

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
  (define (handle-cast msg topics)
    (let ((tag (vector-ref msg 0))
          (topic (vector-ref msg 1))
          (payload (vector-ref msg 2)))
      (deliver-local! topics topic payload)
      (when (eq? tag 'pub) (forward! topic payload))
      topics))

  ;; DOWN from a dead subscriber: drop it from every topic
  (define (handle-info msg topics)
    (if (and (vector? msg) (= 3 (vector-length msg))
             (eq? (vector-ref msg 0) 'DOWN))
        (let ((dead (vector-ref msg 1)))
          (vector-for-each
            (lambda (topic)
              (hashtable-set! topics topic
                (remq dead (hashtable-ref topics topic '()))))
            (hashtable-keys topics))
          topics)
        topics))

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
