#!chezscheme
;;; (igropyr cluster) integration test.
;;;   - static strategy: node a and a child node form a mesh with NO
;;;     explicit node-connect! on either side -- discovery dials for them
;;;   - redis strategy: a and a child discover each other purely through
;;;     a Redis sorted set (skipped cleanly if no server on 6379)
;;;   - redis registration format + expiry pruning, verified against the
;;;     live server

(import (chezscheme) (igropyr actor) (igropyr node)
        (igropyr redis) (igropyr cluster))

(define a-port 18093)
(define secret "cluster-secret")

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info) (newline)
  (exit 1))

(define (spawn-child! name port strategy)
  (system (string-append "scheme --script igropyr/test/cluster-child.sc "
                         name " " (number->string port) " " secret " "
                         strategy " " (number->string a-port) " &")))

;; confirm a two-way link to `who`: ping its 'ping process, await pong
(define (confirm-link! who)
  (let wait ((tries 0))
    (when (> tries 40) (fail! "no-mesh" who))
    (if (memq who (node-peers))
        (begin
          (rsend who 'ping (vector 'ping 'a))    ; 'a is our own node name
          (receive (after 500 (wait (+ tries 1)))
            (`#(pong ,@who) 'ok)))
        (begin (sleep-ms 250) (wait (+ tries 1))))))

(define (redis-up?)
  (guard (e (#t #f))
    (let ((r (redis-connect "127.0.0.1" 6379)))
      (redis r "PING") (redis-close! r) #t)))

(start-scheduler
  (lambda ()
    (node-start! 'a secret a-port "127.0.0.1")
    (register 'main self)

    ;; ---- static strategy: mesh forms with no node-connect! ----
    (cluster-start `((interval-ms . 1000)
                     (discover . (static (b "127.0.0.1" 18094)))))
    (spawn-child! "b" 18094 "static")
    (confirm-link! 'b)
    (display "static discovery auto-mesh ok\n")
    (rsend 'b 'ping (vector 'quit))         ; not a ping; child ignores
    (rsend 'b 'main (vector 'quit))         ; no 'main on child; harmless
    (system "pkill -f 'cluster-child.sc b ' 2>/dev/null")
    (sleep-ms 1500)

    ;; ---- redis strategy (guarded) ----
    (if (not (redis-up?))
        (display "redis discovery test skipped (no server on 6379)\n")
        (let ((r (redis-connect "127.0.0.1" 6379))
              (key "igropyr:cluster:test-cluster"))
          (redis r "DEL" key)               ; clean slate

          ;; a joins via redis, advertising itself; a child 'c joins too
          (cluster-start `((name . "test-cluster")
                           (interval-ms . 1000) (ttl-ms . 5000)
                           (discover . (redis ,r "127.0.0.1" ,a-port))))
          (spawn-child! "c" 18095 "redis")

          ;; both must register in the sorted set
          (let poll ((tries 0))
            (let ((members (redis r "ZRANGE" key 0 -1)))
              (cond
                ((and (member (string-append "a 127.0.0.1 " (number->string a-port))
                              members)
                      (member "c 127.0.0.1 18095" members))
                 (display "redis registration format ok\n"))
                ((> tries 30) (fail! "redis-register" members))
                (else (sleep-ms 250) (poll (+ tries 1))))))

          ;; and they must discover each other and mesh, via redis only
          (confirm-link! 'c)
          (display "redis discovery auto-mesh ok\n")

          ;; pruning: an already-expired member is dropped next cycle
          (redis r "ZADD" key "1" "ghost 10.0.0.9 9999")   ; score 1 = ancient
          (sleep-ms 1500)                                   ; a discover cycle runs
          (when (member "ghost 10.0.0.9 9999" (redis r "ZRANGE" key 0 -1))
            (fail! "redis-prune"))
          (display "redis expiry pruning ok\n")

          (rsend 'c 'ping (vector 'quit))
          (system "pkill -f 'cluster-child.sc c ' 2>/dev/null")
          (redis r "DEL" key)
          (redis-close! r)))

    (display "ALL CLUSTER TESTS PASSED\n")
    (exit 0)))
