#!chezscheme
;;; Forward admission: an overloaded owner REFUSES, promptly and without
;;; touching anything, instead of going silent.
;;;
;;; THE JUDGE IS THE PAIR (what came back, how fast). Before this change
;;; an owner past capacity queued forwards until the asker's deadline and
;;; answered 'unreachable -- indistinguishable from a broken link, and
;;; carrying the reconcile obligation that 'unreachable exists to impose.
;;; So every refusal case here asserts BOTH the word 'overloaded AND that
;;; it arrived in a fraction of the TTL: a refusal that takes as long as
;;; the silence it replaces refuses nothing.
;;;
;;; The other half of the claim is "without touching anything": a refused
;;; resume must leave the token valid and the flow un-advanced, proven by
;;; replaying the SAME token after a slot frees and counting exactly one
;;; application in the flow's own step counter.
;;;
;;; Slots are released by worker DEATH (a monitor held by the router),
;;; not by the last line of the worker body. The suite exercises the
;;; death edge two ways: normal completion, and a worker killed by its
;;; own reply (a non-wire-safe value raises inside the worker's rsend).
;;; What it cannot exercise from the public API is a worker killed
;;; ABRUPTLY -- nothing outside the module ever holds a worker's pid --
;;; so the monitor-vs-dynamic-wind distinction (kills discard winders,
;;; actor.sc documents it) rests on the code and its comment, and this
;;; file says so rather than pretending a green run proved it.
;;;
;;; Also deliberately NOT tested: a per-peer-cap misimplementation
;;; (occupancy is one module-level integer; a second asker node would
;;; buy a real second machine's worth of suite for a shape the code
;;; cannot take by accident).

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation))

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))

(define (fail label . info)
  (display "FAIL: ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))
(define (ok label) (display "  ok  ") (display label) (newline))

(define (contains? hay needle)
  (let ((hl (string-length hay)) (nl (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i nl) hl) #f)
            ((string=? (substring hay i (+ i nl)) needle) #t)
            (else (loop (+ i 1)))))))

(define port 19789)
(define secret "admission-secret")

(define repo (string-append (current-directory) "/igropyr"))
(define child (string-append repo "/test/conv-admission-child.sc"))

(start-scheduler
  (lambda ()

    (define (ask cmd) (rsend 'b 'ctrl cmd))
    (define tag-counter 0)
    (define (fresh-tag)
      (set! tag-counter (+ tag-counter 1))
      tag-counter)
    (define (await tag timeout label)
      (receive (after timeout (fail label 'timeout tag))
        (`#(res ,@tag ,payload) payload)))
    (define (ask/wait cmd-of-tag timeout label)
      (let ((tag (fresh-tag)))
        (ask (cmd-of-tag tag))
        (await tag timeout label)))
    (define (child-stats)
      (ask/wait (lambda (tag) (vector 'stats tag)) 5000 "child stats"))
    (define (stat alist key) (cdr (assq key alist)))
    (define (hosted) (stat (conversation-forward-stats) 'hosted))
    (define (poll-hosted want label)
      (let poll ((k 0))
        (cond ((= (hosted) want) 'ok)
              ((> k 250) (fail label 'hosted-stuck-at (hosted) 'wanted want))
              (else (sleep-ms 20) (poll (+ k 1))))))

    ;; ---- the flows -----------------------------------------------------
    ;; gated: parks 'ready, then a 'block step waits for #(go) sent to
    ;; the name it registered -- that wait is what holds an owner-side
    ;; slot open while the suite looks around
    (define (gated-flow name)
      (lambda (req suspend! commit!)
        (register name self)
        (let loop ((r (suspend! 'ready)))
          (case r
            ((block) (receive (`#(go) 'ok))
                     (loop (suspend! 'unblocked)))
            ((done) (commit! (lambda () 'ok)) 'finished)
            (else (loop (suspend! (vector 'echo r))))))))
    ;; echo with a step counter: n is the number of requests APPLIED, so
    ;; a refused resume that secretly ran the flow shows up as a skipped
    ;; number when the same token is replayed
    (define (echo-flow req suspend! commit!)
      (let loop ((n 1) (r req))
        (if (eq? r 'done)
            (begin (commit! (lambda () 'ok)) 'finished)
            (loop (+ n 1) (suspend! (vector 'echo r n))))))
    ;; the reply to 'bad cannot cross the wire: the worker's own rsend
    ;; raises, which is this suite's only public-API way to make a
    ;; forward worker die abnormally
    (define (bad-flow req suspend! commit!)
      (let loop ((r (suspend! 'ready)))
        (if (eq? r 'bad)
            (loop (suspend! (vector 'evil (lambda () 1))))
            (loop (suspend! 'again)))))

    ;; ---- the id separator is refused IN the name, at naming time ------
    ;; The assertion that discriminates is (node-self) staying #f: the
    ;; conversation router does not exist until a conversation starts, so
    ;; "no router" would pass even if the bad name had been accepted.
    (for-each
      (lambda (bad)
        (guard (e (#t (unless (and (message-condition? e)
                                   (contains? (condition-message e)
                                              "mis-routes"))
                        (fail "tilde refusal raised the wrong error" bad))))
          (node-start! bad secret port)
          (fail "a node name containing ~ was accepted" bad))
        (when (node-self)
          (fail "the refused node-start! still set the node identity" bad)))
      (list (string->symbol "a~b")
            (string->symbol "~a")
            (string->symbol "a~")))
    (ok "a name containing the id separator is refused, identity unset")

    ;; ...and the same port then serves a valid name: the refusal left
    ;; nothing half-claimed behind
    (node-start! 'a secret port)
    (register 'adm self)
    (ok "a valid name starts on the same port after the refusals")

    ;; ---- child asker ---------------------------------------------------
    (system (string-append
              "cd " (current-directory) " && "
              "CHEZSCHEMELIBDIRS=. "
              "CHEZSCHEMELIBEXTS=\"" (or (getenv "CHEZSCHEMELIBEXTS") "") "\" "
              scheme-bin " --script " child " "
              (number->string port) " " secret
              " > /tmp/conv-admission-child.log 2>&1 &"))
    (monitor-node 'b)
    (receive (after 15000 (fail "asker node never came up"))
      (`#(node-up b) 'ok))

    ;; ---- the default is the node layer's number, then the setter ------
    (unless (= 256 (stat (conversation-forward-stats) 'limit))
      (fail "the default limit is not the settled 256"))
    (let ((c0 (child-stats)))
      (for-each (lambda (k)
                  (unless (zero? (stat c0 k))
                    (fail "asker counters not zero before any traffic" k)))
                '(attempted refused completed unreachable))
      (unless (= 256 (stat c0 'limit))
        (fail "the asker node's default limit is not 256")))
    (guard (e (#t 'ok))
      (conv-set-forward-limit! 'many)
      (fail "a non-integer forward limit was accepted"))
    (conv-set-forward-limit! 2)
    (unless (= 2 (stat (conversation-forward-stats) 'limit))
      (fail "the setter did not take"))
    (ok "default 256 on both nodes; setter validates and takes")

    ;; ---- the flows -----------------------------------------------------
    (let*-values (((id1 t1 r1) (conversation-start! (gated-flow 'g1) 'hi))
                  ((id2 t2 r2) (conversation-start! (gated-flow 'g2) 'hi))
                  ((id3 t3 r3) (conversation-start! echo-flow 'hi))
                  ((id4 t4 r4) (conversation-start! bad-flow 'hi)))
      (unless (and (eq? r1 'ready) (eq? r2 'ready) (eq? r4 'ready)
                   (equal? r3 (vector 'echo 'hi 1)))
        (fail "the flows did not park as expected" r1 r2 r3 r4))

      ;; ---- saturate: two blocked forwards hold both slots -------------
      (let ((tagA (fresh-tag)) (tagB (fresh-tag)))
        (ask (vector 'resume-async tagA id1 t1 'block 60000))
        (ask (vector 'resume-async tagB id2 t2 'block 60000))
        (poll-hosted 2 "the two blocked forwards never occupied the slots")
        (ok "two blocked forwards hold both slots")

        ;; ---- the refusal: 'overloaded, promptly, exact shape ----------
        (let* ((before (child-stats))
               (r (ask/wait (lambda (tag) (vector 'resume tag id3 t3 5 10000))
                            15000 "refused resume"))
               (after (child-stats)))
          (unless (and (eq? (car r) #f) (eq? (cadr r) 'overloaded))
            (fail "a saturated owner did not answer (values #f 'overloaded)" r))
          (unless (< (caddr r) 1000)
            (fail "the refusal took a TTL-sized silence to arrive" (caddr r)))
          (unless (conversation-overloaded? (cadr r))
            (fail "the predicate does not recognise the refusal"))
          ;; exact deltas, unchanged fields included: a counter that
          ;; bumps everything on every event passes any single-key check
          (for-each
            (lambda (key want)
              (unless (= (stat after key) (+ want (stat before key)))
                (fail "asker counter delta wrong after a refusal" key
                      (stat before key) (stat after key))))
            '(attempted refused completed unreachable) '(1 1 0 0)))
        (ok "refused resume: exact shape, prompt, counters exact")

        ;; ---- peek shares the same pool --------------------------------
        (let ((r (ask/wait (lambda (tag) (vector 'peek tag id3 10000))
                           15000 "refused peek")))
          (unless (eq? (car r) 'overloaded)
            (fail "a saturated owner did not refuse the peek" r))
          (unless (< (cadr r) 1000)
            (fail "the peek refusal was not prompt" (cadr r))))
        (ok "forwarded peek is refused from the same pool")

        ;; ---- the cap gates forwards only ------------------------------
        (let-values (((reply status) (conversation-resume! id4 t4 'poke)))
          (unless (eq? reply 'again)
            (fail "a LOCAL resume was refused while the cap was full" reply))
          (set! t4 status))
        (let-values (((st tok last) (conversation-peek id3)))
          (unless (eq? st 'parked)
            (fail "a LOCAL peek was refused while the cap was full" st)))
        (ok "local resume and peek ignore the cap")

        ;; ---- release: completion is a death, and the DOWN frees -------
        (send (whereis 'g1) (vector 'go))
        (send (whereis 'g2) (vector 'go))
        (let* ((ra (await tagA 15000 "blocked forward a never returned"))
               (rb (await tagB 15000 "blocked forward b never returned")))
          (unless (and (eq? (car ra) 'unblocked) (eq? (car rb) 'unblocked))
            (fail "the released forwards did not complete" ra rb))
          (set! t1 (cadr ra))
          (set! t2 (cadr rb)))
        (poll-hosted 0 "completed workers did not give their slots back")
        (ok "completion returns both slots"))

      ;; ---- the refusal touched nothing: same token, applied once ------
      (let ((r (ask/wait (lambda (tag) (vector 'resume tag id3 t3 5 10000))
                         15000 "replayed resume")))
        (unless (equal? (car r) (vector 'echo 5 2))
          (fail "the refused token did not replay as the SECOND application"
                (car r)))
        (set! t3 (cadr r)))
      (ok "a refused resume left the token valid and the flow untouched")

      ;; ---- a worker that dies raising also frees its slot -------------
      (let* ((before (child-stats))
             (r (ask/wait (lambda (tag) (vector 'resume tag id4 t4 'bad 1500))
                          15000 "unserialisable reply"))
             (after (child-stats)))
        (unless (eq? (cadr r) 'unreachable)
          (fail "a worker killed by its reply should look unreachable" r))
        (for-each
          (lambda (key want)
            (unless (= (stat after key) (+ want (stat before key)))
              (fail "asker counter delta wrong after an unreachable" key)))
          '(attempted refused completed unreachable) '(1 0 0 1)))
      (poll-hosted 0 "the raising worker's slot was never freed")
      ;; ...and the slot is genuinely usable again
      (let ((r (ask/wait (lambda (tag) (vector 'resume tag id3 t3 7 10000))
                         15000 "post-crash resume")))
        (unless (equal? (car r) (vector 'echo 7 3))
          (fail "the pool did not admit after the crashed worker" r))
        (set! t3 (cadr r)))
      (ok "a worker death by raise frees its slot for the next forward")

      ;; ---- monotonic: reading is not resetting ------------------------
      (let ((s1 (child-stats)) (s2 (child-stats)))
        (for-each
          (lambda (key)
            (unless (= (stat s1 key) (stat s2 key))
              (fail "reading the stats changed them" key)))
          '(attempted refused completed unreachable)))
      (ok "stats survive being read")

      ;; ---- the router dies; the accounting must not ------------------
      ;; Occupancy is module state, so a restarted router still refuses
      ;; while the old workers run (the count must not reset). But the
      ;; DOWNs of those workers were promised to the DEAD router -- the
      ;; release path must not depend on the router that took the slot
      ;; being the router that is alive when the worker dies.
      (let ((tagA (fresh-tag)) (tagB (fresh-tag)))
        (ask (vector 'resume-async tagA id1 t1 'block 60000))
        (ask (vector 'resume-async tagB id2 t2 'block 60000))
        (poll-hosted 2 "re-saturation never took")
        (kill (whereis 'igropyr-conv-router) 'admission-test)
        ;; any conversation start re-ensures the router
        (let-values (((idx tx rx) (conversation-start! echo-flow 'hi)))
          (let ((r (ask/wait (lambda (tag) (vector 'resume tag idx tx 1 10000))
                             15000 "resume against restarted router")))
            (unless (eq? (cadr r) 'overloaded)
              (fail "a restarted router forgot the live workers" r)))
          (ok "a restarted router still counts the old workers")
          (send (whereis 'g1) (vector 'go))
          (send (whereis 'g2) (vector 'go))
          (await tagA 15000 "blocked forward a never returned (round 2)")
          (await tagB 15000 "blocked forward b never returned (round 2)")
          (poll-hosted 0
            "slots taken under the old router leaked when it was replaced")
          (let ((r (ask/wait (lambda (tag) (vector 'resume tag idx tx 1 10000))
                             15000 "admission after router restart")))
            (unless (equal? (car r) (vector 'echo 1 2))
              (fail "the pool never recovered after the router restart" r))))
        (ok "worker slots survive the router that took them")))

    (ask (vector 'quit))
    (display "ALL CONV-ADMISSION TESTS PASSED\n")
    (exit 0)))
