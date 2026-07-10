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

(library (igropyr pubsub)
  (export start-pubsub! subscribe unsubscribe publish)
  (import (chezscheme) (igropyr actor) (igropyr gen-server))

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

  (define (handle-cast msg topics)
    (let ((topic (vector-ref msg 1))
          (payload (vector-ref msg 2)))
      (for-each
        (lambda (p) (send p (vector 'pub topic payload)))
        (hashtable-ref topics topic '()))
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
