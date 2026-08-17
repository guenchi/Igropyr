#!chezscheme
;;; (igropyr cluster) integration test.
;;;   - static strategy: node a and a child node form a mesh with NO
;;;     explicit node-connect! on either side -- discovery dials for them
;;;   - redis strategy: a and a child discover each other purely through
;;;     a Redis sorted set (skipped cleanly if no server on 6379)
;;;   - redis registration format + expiry pruning, verified against the
;;;     live server
;;;   - gossip strategy: two children know ONLY the seed (a) yet must
;;;     find and dial EACH OTHER (addresses travel inside the records);
;;;     a killed member's record ages out of the seed's view within ttl
;;;     (not just its link dying); a fresh member rejoins through the
;;;     seed with a new incarnation

(import (chezscheme) (igropyr actor) (igropyr node)
        (igropyr redis) (igropyr cluster) (igropyr gen-server))

;; The run may be using `chez` or $SCHEME_BIN rather than `scheme`, and a
;; child started with the wrong name simply never appears -- which this
;; suite would report as whatever it was waiting for timing out, not as a
;; missing interpreter. run-all.sh exports the name it chose.
(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))


(define a-port 18093)
(define secret "cluster-secret")

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info) (newline)
  (exit 1))

;; Children are killed BY PID, recorded when they start.
;;
;; `pkill -f` does not match here -- in a sandboxed run the pattern never
;; finds them -- so every run left its children alive, holding their ports.
;; The next run then joined the PREVIOUS run's nodes: a node this test had
;; just killed went on answering, and the record-expiry case failed with
;; every later run inheriting the mess. A pid file cannot be wrong about
;; which process it means.
(define (child-pid-file name)
  (string-append "/tmp/igropyr-cluster-" name ".pid"))

(define (spawn-child! name port strategy)
  (system (string-append scheme-bin " --script igropyr/test/cluster-child.sc "
                         name " " (number->string port) " " secret " "
                         strategy " " (number->string a-port)
                         " & echo $! > " (child-pid-file name))))

(define (kill-child! name)
  (system (string-append
            "kill -9 $(cat " (child-pid-file name) " 2>/dev/null) 2>/dev/null;"
            " rm -f " (child-pid-file name))))

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

;; ask a child for ITS peer list (via its 'ping process); #f on timeout
(define (peers-of who)
  (rsend who 'ping (vector 'peers? 'a))
  (receive (after 1000 #f)
    (`#(peers ,@who ,ps) ps)))

(define (redis-up?)
  (guard (e (#t #f))
    (let ((r (redis-connect "127.0.0.1" 6379)))
      (redis r "PING") (redis-close! r) #t)))

(start-scheduler
  (lambda ()
    (node-start! 'a secret a-port "127.0.0.1")
    (register 'main self)

    ;; ---- max-members option: bad value rejected, custom value accepted ----
    (unless (guard (e (#t #t))
              (cluster-start `((name . "mm-bad") (max-members . -1)
                               (discover . (static)))) #f)
      (fail! "max-members-reject-bad"))
    (let ((h (cluster-start `((name . "mm-ok") (max-members . 512)
                              (discover . (static))))))
      (unless (process-alive? h) (fail! "max-members-accept"))
      (cluster-stop h)
      (display "max-members option ok\n"))

    ;; ---- static strategy: mesh forms with no node-connect! ----
    (cluster-start `((interval-ms . 1000)
                     (discover . (static (b "127.0.0.1" 18094)))))
    (spawn-child! "b" 18094 "static")
    (confirm-link! 'b)
    (display "static discovery auto-mesh ok\n")
    (rsend 'b 'ping (vector 'quit))         ; not a ping; child ignores
    (rsend 'b 'main (vector 'quit))         ; no 'main on child; harmless
    (kill-child! "b")
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
          (kill-child! "c")
          (redis r "DEL" key)
          (redis-close! r)))

    ;; ---- gossip strategy ----
    ;; a runs seedless (it IS the seed); d and e are configured with a
    ;; as their only contact. e's address must reach d THROUGH gossip.
    (cluster-start `((name . "gossip-cluster")
                     (interval-ms . 400) (ttl-ms . 2000)
                     (discover . (gossip (advertise "127.0.0.1" ,a-port)))))
    (spawn-child! "d" 18098 "gossip")
    (spawn-child! "e" 18099 "gossip")
    (confirm-link! 'd)
    (confirm-link! 'e)

    ;; the transitive edge: d was never told about e, yet holds a live
    ;; link to it -- e's (name host port) travelled inside gossip records
    (let poll ((tries 0))
      (let ((ps (peers-of 'd)))
        (cond ((and (list? ps) (memq 'e ps))
               (display "gossip transitive mesh ok\n"))
              ((> tries 40) (fail! "gossip-transitive" ps))
              (else (sleep-ms 250) (poll (+ tries 1))))))

    ;; kill e: its record stops advancing, so it must age OUT OF THE
    ;; VIEW within ttl -- stale echoes between a and d must not keep the
    ;; zombie alive (the record-level assertion, not just link death)
    (kill-child! "e")
    (let poll ((tries 0))
      (let ((view (gen-server-call 'igropyr-gossip:gossip-cluster 'members)))
        (cond ((not (assq 'e view))
               (display "gossip record expiry ok\n"))
              ((> tries 40) (fail! "gossip-record-expiry" view))
              (else (sleep-ms 250) (poll (+ tries 1))))))
    (let poll ((tries 0))
      (let ((ps (peers-of 'd)))
        (cond ((and (list? ps) (not (memq 'e ps)))
               (display "gossip peer drop ok\n"))
              ((> tries 40) (fail! "gossip-peer-drop" ps))
              (else (sleep-ms 250) (poll (+ tries 1))))))

    ;; rejoin through the seed: a fresh e (new incarnation outranks
    ;; anything the old life gossiped) comes back via a alone
    (spawn-child! "e" 18099 "gossip")
    (confirm-link! 'e)
    (display "gossip seed rejoin ok\n")

    (kill-child! "d")
    (kill-child! "e")

    (display "ALL CLUSTER TESTS PASSED\n")
    (exit 0)))
