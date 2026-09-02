#!chezscheme
;;; (igropyr node) integration test: two real OS processes.
;;;   - handshake + node-up
;;;   - rsend round-trip with extended-whitelist payload fidelity
;;;     (vector, bytevector, flonum, ratio through the wire and back)
;;;   - node-down when the peer exits
;;;   - a peer with the WRONG secret never becomes a node
;;;   - rsend to a disconnected node returns #f; to self delivers locally
;;;   - v3 call frames carry the caller's timeout; the stale 4-element
;;;     arity and a malformed timeout slot drop the link
;;;   - per-connection outbound backpressure: a slow reader is closed
;;;     promptly, paced traffic is not, the accounting dies with the conn
;;;   - reconnect delay: bounded, deterministic, dispersed across names

(import (chezscheme) (igropyr actor) (igropyr libuv)
        (igropyr node) (igropyr pubsub)
        (only (igropyr crypto) hmac-sha256 bytevector->hex))

;; The run may be using `chez` or $SCHEME_BIN rather than `scheme`, and a
;; child started with the wrong name simply never appears -- which this
;; suite would report as whatever it was waiting for timing out, not as a
;; missing interpreter. run-all.sh exports the name it chose.
(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))


(define port 18091)
(define secret "test-mesh-secret")

(define (fail! label . info)
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

(define (spawn-child! name secret)
  (system (string-append
            scheme-bin " --script igropyr/test/node-child.sc "
            name " " (number->string port) " " secret " &")))

;; ---- raw handshake probe helpers ---------------------------------------
;; The adversarial cells below speak the wire by hand, and they encode
;; only what must FAIL. The one acceptance path -- two current nodes --
;; is the real child handshake later in this suite, so the current proof
;; formula is deliberately NOT duplicated here: probe proofs use the
;; PRE-VERSIONING formula (nonce:name), exactly what a current peer has
;; to refuse.

(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      ;; handshake datums are ASCII: string length = byte length
      (string->utf8 (string-append (number->string (string-length body))
                                   "\n" body)))))

;; One SEGMENT holding many whole frames. The point is the backlog: the
;; link loop reads its mailbox ONLY in the `incomplete` branch, so while
;; whole frames remain decoded it keeps dispatching and never looks at
;; the stop message a replacement sent it. See node.sc's "A SUPERSEDED
;; LINK CAN STILL SERVE WHAT IT HAS BUFFERED".
;; The filler is (send <unregistered> 0): dispatch!'s first clause drops
;; an unregistered name, so a filler frame writes nothing back, touches
;; no table, and costs only the parse.
(define (burst-bytes filler-count tail-data)
  (let ((o (open-output-string)))
    (define (emit! d)
      (let ((b (let ((q (open-output-string))) (write d q) (get-output-string q))))
        (display (string-length b) o) (display "\n" o) (display b o)))
    (let loop ((i 0))
      (when (< i filler-count) (emit! (list 'send 'zzz-burst-filler 0)) (loop (+ i 1))))
    (for-each emit! tail-data)
    (string->utf8 (get-output-string o))))

(define (pre-versioning-proof nonce name)
  (bytevector->hex
    (hmac-sha256 (string->utf8 secret)
      (string->utf8 (string-append nonce ":" (symbol->string name))))))

;; accumulate tcp-data on the CURRENT process until one whole frame
;; parses; fail on timeout. A close is reported as 'closed only when NO
;; bytes preceded it -- a refusal that dribbles partial output before
;; closing is not the silent close the spec asks for, and collapsing the
;; two would let it pass.
(define (read-frame-or-closed label)
  (let loop ((acc ""))
    (let* ((n (string-length acc))
           (nl (let scan ((k 0))
                 (cond ((= k n) #f)
                       ((char=? (string-ref acc k) #\newline) k)
                       (else (scan (+ k 1))))))
           (len (and nl (string->number (substring acc 0 nl)))))
      (if (and len (>= n (+ nl 1 len)))
          (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len))))
          (receive (after 4000 (fail! label 'frame-timeout acc))
            (`#(tcp-data ,bv) (loop (string-append acc (utf8->string bv))))
            (`#(tcp-eof)
              (if (zero? (string-length acc)) 'closed 'closed-with-bytes))
            (`#(tcp-error ,_)
              (if (zero? (string-length acc)) 'closed 'closed-with-bytes)))))))

;; the CURRENT proof formula, and its anchor. The digest below is a
;; literal computed by an INDEPENDENT implementation (python hmac) over
;; the exact bytes "0123456789abcdef0123456789abcdef:a:3" with the key
;; "test-mesh-secret". Without it, every proof cell would only show that
;; the library agrees with itself (or with this helper) -- both sides of
;; such a comparison can drift together. If THIS check fails, the test
;; helper diverged, not the library.
(define (versioned-proof nonce name v)
  (bytevector->hex
    (hmac-sha256 (string->utf8 secret)
      (string->utf8 (string-append nonce ":" (symbol->string name)
                                   ":" (number->string v))))))
;; A nonce carrying the separator: 32 characters, correct alphabet, ONE
;; colon, so a refusal can only be about injectivity, not length. Purity
;; by construction, not by ordering: the arity and version gates happen
;; to run before the nonce gate today, which keeps the other cells
;; discriminating -- but only until someone reorders the checks, and the
;; day that happens nothing goes red, the cells just quietly start
;; refusing for the new reason. (Counted, not eyeballed: 16 + 1 + 15. An
;; earlier spelling was 31 characters, which let the length gate refuse
;; it -- a pass for a build with no colon check at all.)
(define colon-nonce "0123456789abcdef:123456789abcdef")
(define kat-nonce "0123456789abcdef0123456789abcdef")
(define kat-hello-proof
  "2f8cc2827c8770ca1b3d5d61682cdbf066fbce46c22b68b62d04bba4e2f53c75")
(unless (equal? (versioned-proof kat-nonce 'a 3) kat-hello-proof)
  (fail! "versioned-proof-helper-diverged-from-known-answer"))

(define (has-substr? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring s i (+ i m)) sub) #t)
            (else (loop (+ i 1)))))))

;; Dial node a and complete a CURRENT-version handshake by hand, as
;; `name`; returns the open conn. Runs in the calling process, which
;; owns the socket. This is the doorway to the post-auth cells below:
;; what they probe only exists on an authenticated link, so each one
;; must first BE a peer. Any surprise here is a fail!, not a report --
;; the handshake itself already has its own cells.
;; v4: the proof binds the TARGET as well, and the target's boot-id
;; arrives in the challenge -- so this cannot be precomputed, it has to
;; read slot 4 first. `name` is a string on the wire (v4 §8 item 3b);
;; the node's own name here is 'a, spelled out because the proof binds
;; who we think we are talking to.
(define wire-name-of-this-node "a")
(define probe-boot-id "feedfacefeedface")
(define (v4-hmac msg)
  (bytevector->hex (hmac-sha256 (string->utf8 secret) (string->utf8 msg))))
(define (v4-proof-d nonce-a name-d bootid-d dialgen name-a bootid-a)
  (v4-hmac (string-append nonce-a ":" name-d ":4:" bootid-d ":"
                          dialgen ":" name-a ":" bootid-a)))
(define (v4-proof-a nonce-b name-a bootid-a)
  (v4-hmac (string-append nonce-b ":" name-a ":4:" bootid-a)))
(define (hex16? s)
  (and (string? s) (= (string-length s) 16)
       (let ok ((i 0))
         (or (= i 16)
             (and (let ((ch (string-ref s i)))
                    (or (char<=? #\0 ch #\9) (char<=? #\a ch #\f)))
                  (ok (+ i 1)))))))
(define (handshake-as! name label)
  (tcp-connect! "127.0.0.1" port self)
  (receive (after 3000 (fail! label 'no-connect))
    (`#(tcp-connected ,c)
      (tcp-read-start! c)
      (let ((d (read-frame-or-closed label)))
        (unless (and (pair? d) (= (length d) 4) (eq? (car d) 'challenge)
                     (string? (cadr d)) (eqv? (caddr d) 4)
                     (string? (cadddr d)))
          (fail! label 'challenge-shape d))
        (let* ((nonce-a (cadr d)) (bootid-a (cadddr d))
               (name-s (if (symbol? name) (symbol->string name) name)))
          (tcp-write! c (frame-bytes
                          (list 'hello name-s
                                (v4-proof-d nonce-a name-s probe-boot-id "1"
                                            wire-name-of-this-node bootid-a)
                                "feedfeedfeedfeedfeedfeedfeedfeed" 4
                                probe-boot-id 1))
                      #f)
          (let ((w (read-frame-or-closed label)))
            (unless (and (pair? w) (eq? (car w) 'welcome))
              (fail! label 'no-welcome w)))))
      c)
    (`#(tcp-connect-failed ,e) (fail! label 'no-connect e))))

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (node-set-limits! 64 2)
    (start-pubsub!)
    (register 'main self)
    (monitor-node 'b)

    ;; ---- reconnect delay: bounds, determinism, dispersion ---------------
    ;; The schedule is a pure exported function precisely so this can be
    ;; measured: the property that matters -- a herd of nodes that lost
    ;; the same peer at the same moment must not knock again in unison --
    ;; lives in the spread across (self, peer) pairs, which no single
    ;; reconnect timing could show without a flaky multi-process clock.
    (let ()
      (define (base a) (min (* 3000 (expt 2 a)) 60000))
      ;; bounds: inside +/-25% of the capped exponential base at every
      ;; attempt, so backoff neither collapses toward zero nor overshoots
      ;; the cap (exact arithmetic: 0.75b <= d <= 1.25b as 3b <= 4d <= 5b)
      (do ((a 0 (+ a 1))) ((> a 20))
        (let ((d (reconnect-delay 'a 'b a)) (b (base a)))
          (unless (and (integer? d) (exact? d)
                       (>= (* 4 d) (* 3 b))
                       (<= (* 4 d) (* 5 b)))
            (fail! "reconnect-delay-bounds" a b d))))
      ;; deterministic: jitter comes from the names, not from clocks or
      ;; random state -- a retrying node can be reasoned about, and the
      ;; entropy-starved failure mode of a random source (a raise the
      ;; connector's guard would silently turn into "never dial again")
      ;; has no place on the reconnect path
      (unless (= (reconnect-delay 'a 'b 3) (reconnect-delay 'a 'b 3))
        (fail! "reconnect-delay-not-deterministic"))
      ;; ...including across a real clock tick: two adjacent calls can
      ;; land inside one millisecond, where a clock-seeded jitter still
      ;; reads as deterministic
      (let ((d1 (reconnect-delay 'a 'b 3)))
        (sleep-ms 50)
        (unless (= d1 (reconnect-delay 'a 'b 3))
          (fail! "reconnect-delay-clock-seeded")))
      ;; dispersion, in both directions the mesh actually has: one node
      ;; dialing many peers, and many nodes dialing one hub. 16 names
      ;; into a 12000ms-wide band; a working hash gives nearly 16
      ;; distinct delays, a name-blind jitter gives exactly 1. The
      ;; threshold 8 is lenient to collisions while unreachable by any
      ;; implementation that ignores the varying name.
      (let ()
        (define (distinct-count l)
          (let loop ((l l) (seen '()) (n 0))
            (cond ((null? l) n)
                  ((member (car l) seen) (loop (cdr l) seen n))
                  (else (loop (cdr l) (cons (car l) seen) (+ n 1))))))
        (define (nm k) (string->symbol (string-append "n" (number->string k))))
        (define (sweep f)
          (let loop ((k 0) (acc '()))
            (if (= k 16) acc (loop (+ k 1) (cons (f (nm k)) acc)))))
        (let ((across-peers (sweep (lambda (p) (reconnect-delay 'a p 3))))
              (across-selves (sweep (lambda (s) (reconnect-delay s 'hub 3)))))
          (when (< (distinct-count across-peers) 8)
            (fail! "reconnect-delay-peer-dispersion" across-peers))
          (when (< (distinct-count across-selves) 8)
            (fail! "reconnect-delay-self-dispersion" across-selves))
          ;; ...and with ATTEMPT: normalize the exponential base away
          ;; and the residual phase must still walk as attempt climbs
          ;; with both names fixed. A jitter that hashes only the names
          ;; gives one ratio for every attempt.
          (let ((ratios
                  (let loop ((a 0) (acc '()))
                    (if (= a 16) acc
                        (loop (+ a 1)
                              (cons (/ (reconnect-delay 'a 'b a) (base a))
                                    acc))))))
            (when (< (distinct-count ratios) 8)
              (fail! "reconnect-delay-attempt-dispersion" ratios))))))
    (display "reconnect delay bounded, deterministic, dispersed ok\n")

    ;; The pre-auth handshake has one absolute deadline. Dripping a byte
    ;; before each idle timeout must not hold an unauthenticated fd forever.
    (tcp-connect! "127.0.0.1" port self)
    (let ((slow
            (receive (after 2000 (fail! "slow-handshake-connect"))
              (`#(tcp-connected ,c) c)
              (`#(tcp-connect-failed ,e) (fail! "slow-handshake-connect" e)))))
      (tcp-read-start! slow)
      (tcp-write! slow (string->utf8 "10\n(") #f)
      ;; Drip a byte every second rather than once. A single drip has to
      ;; land inside the server's own window to prove anything: if the
      ;; scheduler drifts past it, the server closes on its own schedule
      ;; and the check passes against the very code it exists to reject --
      ;; moving one sleep from 4000 to 5200 was enough to make this report
      ;; ok against a per-receive timeout. Dripping continuously removes
      ;; the dependency: a refreshing window outlives the whole loop no
      ;; matter where individual bytes land, and an absolute deadline is
      ;; moved by none of them.
      (let ((t0 (now-ms)))
        (let loop ((k 0))
          (if (= k 8)
              (begin (tcp-close! slow) (fail! "slow-handshake-deadline"))
              (receive (after 1000
                          (tcp-write! slow (string->utf8 "x") #f)
                          (loop (+ k 1)))
                (`#(tcp-eof) 'ok)
                (`#(tcp-error ,_) 'ok))))
        ;; reaching k = 8 already fails; this keeps the check honest if the
        ;; deadline is ever made longer than the loop
        (let ((elapsed (- (now-ms) t0)))
          (when (>= elapsed 7000)
            (fail! "slow-handshake-deadline-not-absolute" elapsed))))
      (display "absolute pre-auth handshake deadline ok\n"))

    ;; Each pre-auth connection is bounded in bytes and in time, but a
    ;; stranger must not be able to hold an unbounded NUMBER of them --
    ;; every one is an fd and a process, and the fd budget belongs to the
    ;; whole OS process, not just the mesh. Over the ceiling the node must
    ;; close without answering and without spawning. Runs before any child
    ;; node exists, so nothing else is competing for a slot.
    (node-set-limits! #f #f 4)
    (let ((me self) (ref (gensym)))
      ;; one prober process per connection: tcp-data carries no connection,
      ;; so a shared mailbox could not tell which socket was answered
      (do ((i 0 (+ i 1))) ((= i 8))
        (spawn
          (lambda ()
            (tcp-connect! "127.0.0.1" port self)
            (receive (after 3000 (send me (vector ref 'no-connect)))
              (`#(tcp-connected ,c)
                (tcp-read-start! c)
                (receive (after 3000 (send me (vector ref 'silent)))
                  (`#(tcp-data ,_)
                    ;; report, then HOLD. Closing here would free the slot
                    ;; and let the next prober take it, so the eight
                    ;; connections would never be in flight at once and the
                    ;; ceiling would never be reached.
                    (send me (vector ref 'challenged))
                    (receive (after 6000 (tcp-close! c))
                      (`#(tcp-eof) 'ok)
                      (`#(tcp-error ,_) 'ok)))
                  (`#(tcp-eof) (send me (vector ref 'refused)))
                  (`#(tcp-error ,_) (send me (vector ref 'refused)))))
              (`#(tcp-connect-failed ,e) (send me (vector ref 'refused)))))))
      (let loop ((k 0) (challenged 0) (refused 0))
        (if (= k 8)
            (begin
              (unless (= challenged 4)
                (fail! "preauth-cap-challenged" challenged))
              (unless (= refused 4)
                (fail! "preauth-cap-refused" refused)))
            (receive (after 8000 (fail! "preauth-cap-timeout" k))
              (`#(,@ref ,tag)
                (case tag
                  ((challenged) (loop (+ k 1) (+ challenged 1) refused))
                  ((refused) (loop (+ k 1) challenged (+ refused 1)))
                  (else (fail! "preauth-cap-unexpected" tag))))))))
    ;; back to a ceiling that cannot interfere with the real handshakes below
    (node-set-limits! #f #f 256)
    (display "pre-auth connection ceiling ok\n")

    ;; ---- dead watchers on a quiet name ----------------------------------
    ;; notify! sweeps dead watcher pids when an event for that name fires;
    ;; a name that never has an event never runs that sweep, so a watcher
    ;; that died under a quiet name was retained forever. Registration is
    ;; the other moment the list is in hand: monitor-node must sweep it
    ;; there. 'ghost never connects, so nothing here is cleaned by events.
    (let ((watcher-count
            (lambda ()
              (let ((e (assq 'watchers (node-monitor-stats))))
                (unless e (fail! "node-monitor-stats-lacks-watchers"))
                (cdr e))))
          (me self))
      (define (expect! n label)
        (let ((w (watcher-count)))
          (unless (= w n) (fail! label n w))))
      (let* ((w0 (watcher-count))
             (p (spawn (lambda ()
                         (monitor-node 'ghost)
                         (send me (vector 'ghost-armed))
                         (receive (after 10000 'done))))))
        (receive (after 2000 (fail! "ghost-watcher-arm-timeout"))
          (`#(ghost-armed) 'ok))
        (expect! (+ w0 1) "ghost-watcher-not-counted")
        (kill p 'gone)
        (sleep-ms 50)
        ;; the dead pid is STILL stored and still counted: the statistic
        ;; reports stored watchers, not live ones. This reading is also
        ;; the documented residual itself -- death alone, on a quiet
        ;; name, cleans nothing.
        (expect! (+ w0 1) "watcher-stats-filters-dead-pids")
        ;; the registration-time sweep: adding a live watcher for the same
        ;; quiet name must drop the dead one in the same motion
        (monitor-node 'ghost)
        (expect! (+ w0 1) "dead-watcher-retained-on-quiet-name")
        ;; a SECOND live watcher on the same name must raise the count:
        ;; a statistic that counts names instead of stored pids stays
        ;; flat here, and every earlier delta in this cell happened to
        ;; move name-count and pid-count together
        (let ((q (spawn (lambda ()
                          (monitor-node 'ghost)
                          (send me (vector 'q-armed))
                          (receive (`#(q-done)
                                     (demonitor-node 'ghost)
                                     (send me (vector 'q-cleared))))))))
          (receive (after 2000 (fail! "second-watcher-arm-timeout"))
            (`#(q-armed) 'ok))
          (expect! (+ w0 2) "watcher-stats-counts-names-not-pids")
          (send q (vector 'q-done))
          (receive (after 2000 (fail! "second-watcher-clear-timeout"))
            (`#(q-cleared) 'ok))
          (expect! (+ w0 1) "demonitor-removed-wrong-entry")
          (demonitor-node 'ghost)
          (expect! w0 "main-demonitor-not-accounted")))
      ;; The bound is PER NAME, and saying so is the point. A sweep runs
      ;; only for the name being registered, so N quiet names that each
      ;; saw one dead watcher retain N entries -- never more than one per
      ;; name, and no name reachable by events retains any. This cell
      ;; pins the real shape so the prose beside the table cannot drift
      ;; back into claiming a global bound.
      (let ((w0 (watcher-count)) (me self))
        (do ((i 0 (+ i 1))) ((= i 5))
          (let ((nm (string->symbol
                      (string-append "quiet-" (number->string i)))))
            (let ((p (spawn (lambda ()
                              (monitor-node nm)
                              (send me (vector 'armed))
                              (receive (after 10000 'done))))))
              (receive (after 2000 (fail! "quiet-name-arm-timeout" i))
                (`#(armed) 'ok))
              (kill p 'gone))))
        (sleep-ms 100)
        (let ((w (watcher-count)))
          (unless (= w (+ w0 5))
            (fail! "per-name-retention-shape" (+ w0 5) w)))))
    (display "dead watcher swept at registration; bound is per name ok\n")

    ;; ---- the two variants share a table, and each unsubscribe owns a
    ;; ---- part of it ------------------------------------------------------
    ;; The token variant was added to the SAME watchers table, so every
    ;; operation on that table now meets two shapes. This cell is about
    ;; the one operation whose scope is easy to get wrong in the direction
    ;; that says nothing: the old demonitor-node.
    ;;
    ;; BOTH HALVES ARE ASSERTED, and that is the whole point. A
    ;; demonitor-node that removes nothing passes a cell which only checks
    ;; "the token subscription survived"; a demonitor-node that removes
    ;; everything owned by this pid passes a cell which only checks "the
    ;; legacy one is gone". Each half is green under the other's defect,
    ;; so neither alone is a judge.
    ;;
    ;; The over-removing direction is the one with no voice: the holder
    ;; still has its token, the call returned normally, and nothing is
    ;; reported -- the subscription simply never delivers again. It is
    ;; also the direction the design ruled out by name, which is why the
    ;; scope belongs in a cell rather than in a sentence.
    (let ((watcher-count
            (lambda ()
              (let ((e (assq 'watchers (node-monitor-stats))))
                (unless e (fail! "node-monitor-stats-lacks-watchers"))
                (cdr e)))))
      (let ((w0 (watcher-count)))
        (monitor-node 'mixed)
        (let ((tok (monitor-node/token 'mixed)))
          ;; the arming anchor: without it, a cell that failed to register
          ;; anything would go on to observe the right numbers for the
          ;; wrong reason -- zero minus zero is also zero.
          (unless tok (fail! "s4-mixed-token-not-issued"))
          (unless (= (watcher-count) (+ w0 2))
            (fail! "s4-mixed-both-not-stored" (+ w0 2) (watcher-count)))
          ;; the legacy unsubscribe: exactly one entry leaves, and it is
          ;; the legacy one.
          (demonitor-node 'mixed)
          (let ((w (watcher-count)))
            (when (= w w0)
              (fail! "s4-legacy-demonitor-took-the-token-subscription"
                     'expected (+ w0 1) 'got w))
            (unless (= w (+ w0 1))
              (fail! "s4-legacy-demonitor-removed-nothing"
                     'expected (+ w0 1) 'got w)))
          ;; and the token unsubscribe removes what is left
          (demonitor-node/token tok)
          (unless (= (watcher-count) w0)
            (fail! "s4-token-demonitor-did-not-remove"
                   'expected w0 'got (watcher-count))))))
    (display "legacy and token unsubscribes each own their half ok\n")

    ;; ---- and the same table's other operation: deduplication ------------
    ;; Registration asks "has this process already subscribed". Once the
    ;; table holds two shapes that question has two answers, and asking
    ;; only about the pid picks whichever call happened to come first.
    ;;
    ;; THE JUDGE IS THAT BOTH ORDERS AGREE. One order alone cannot tell
    ;; "both kept" from "one dropped": either rule yields a defensible
    ;; number in one order. It is the DISAGREEMENT between the orders that
    ;; says the question was asked about the wrong thing -- two orders
    ;; giving different totals is not a choice between two semantics, it
    ;; is neither of them.
    ;;
    ;; The failing order is the quiet one: the second call returns the
    ;; same nothing it always returns, so a caller that took a token and
    ;; then asked for the older subscription holds one subscription while
    ;; believing it holds two.
    (let ((watcher-count
            (lambda ()
              (let ((e (assq 'watchers (node-monitor-stats))))
                (unless e (fail! "node-monitor-stats-lacks-watchers"))
                (cdr e)))))
      ;; legacy first, then token
      (let ((w0 (watcher-count)))
        (monitor-node 'dedup-a)
        (let ((tok (monitor-node/token 'dedup-a)))
          (unless tok (fail! "s4-dedup-a-token-not-issued"))
          (let ((w (watcher-count)))
            (unless (= w (+ w0 2))
              (fail! "s4-dedup-legacy-then-token" 'expected (+ w0 2) 'got w)))
          (demonitor-node 'dedup-a)
          (demonitor-node/token tok))
        (let ((w (watcher-count)))
          (unless (= w w0) (fail! "s4-dedup-a-residue" 'expected w0 'got w))))
      ;; token first, then legacy -- the order a pid-only test loses
      (let ((w0 (watcher-count)))
        (let ((tok (monitor-node/token 'dedup-b)))
          (unless tok (fail! "s4-dedup-b-token-not-issued"))
          (monitor-node 'dedup-b)
          (let ((w (watcher-count)))
            (unless (= w (+ w0 2))
              (fail! "s4-dedup-token-then-legacy" 'expected (+ w0 2) 'got w)))
          (demonitor-node 'dedup-b)
          (demonitor-node/token tok))
        (let ((w (watcher-count)))
          (unless (= w w0) (fail! "s4-dedup-b-residue" 'expected w0 'got w)))))
    (display "registration deduplicates within a variant, both orders ok\n")

    ;; ---- protocol version in the handshake ------------------------------
    ;; The wire carries a protocol version in challenge and hello. It is
    ;; checked before the proof, so a refusal can name the real cause,
    ;; and it is bound INTO the proof, so the explicit field cannot be
    ;; tampered with independently. Four refusal cells; acceptance is the
    ;; real child handshake later in this file.

    ;; accept side. A 4-element hello with a correct PRE-VERSIONING proof
    ;; must be refused without a welcome (red before the change: it
    ;; authenticated). A 5-element hello whose proof was computed WITHOUT
    ;; the version owns the proof BINDING: a build that only checks the
    ;; explicit field answers it with welcome.
    (let ((probe-hello!
            (lambda (label hello-of-nonce)
              (let ((me self) (ref (gensym)))
                (spawn
                  (lambda ()
                    (tcp-connect! "127.0.0.1" port self)
                    (receive (after 3000 (send me (vector ref 'no-connect)))
                      (`#(tcp-connected ,c)
                        (tcp-read-start! c)
                        (let ((d (read-frame-or-closed label)))
                          (if (or (not (pair? d))
                                  (null? (cdr d)) (not (string? (cadr d))))
                              (send me (vector ref 'bad-challenge))
                              (begin
                                (tcp-write! c (frame-bytes
                                                (hello-of-nonce (cadr d))) #f)
                                (let ((d2 (read-frame-or-closed label)))
                                  (send me (vector ref
                                             (if (symbol? d2) d2 'welcomed)))))))
                        (tcp-close! c))
                      (`#(tcp-connect-failed ,e)
                        (send me (vector ref 'no-connect))))))
                (receive (after 8000 (fail! label 'probe-timeout))
                  (`#(,@ref ,what)
                    (unless (eq? what 'closed) (fail! label what)))))))
          ;; nonce-b spelled at the length real nodes use, so a refusal
          ;; can only be ABOUT the property under test -- an accidental
          ;; nonce-length requirement would otherwise refuse these for
          ;; the wrong reason and read as a pass
          (nb32 "cafecafecafecafecafecafecafecafe"))
      (probe-hello! "acceptor-answers-unversioned-hello"
        (lambda (nonce)
          (list 'hello 'relic (pre-versioning-proof nonce 'relic) nb32)))
      (probe-hello! "acceptor-accepts-proof-not-binding-version"
        (lambda (nonce)
          (list 'hello 'relic2 (pre-versioning-proof nonce 'relic2)
                nb32 3)))
      ;; version slot 999 with a proof that IS valid for version 3: an
      ;; acceptor that skips the explicit hello-version check but does
      ;; verify the bound proof would welcome this one
      (probe-hello! "acceptor-ignores-hello-version"
        (lambda (nonce)
          (list 'hello 'relic3 (versioned-proof nonce 'relic3 3)
                nb32 999)))
      ;; the acceptor's end of the injectivity rule, both halves.
      ;; A nonce-b carrying the separator is what the attacker WOULD
      ;; sign next; a name carrying it is what the attacker CLAIMS.
      ;; Note the second one's proof is genuinely correct for the
      ;; string it hashes -- refusing it cannot come from the proof
      ;; check, only from the name.
      (probe-hello! "acceptor-signs-structured-nonce-b"
        (lambda (nonce)
          (list 'hello 'relic4 (versioned-proof nonce 'relic4 3)
                colon-nonce 3)))
      (probe-hello! "acceptor-admits-colon-in-claimed-name"
        (lambda (nonce)
          (list 'hello (string->symbol "evil:a")
                (versioned-proof nonce (string->symbol "evil:a") 3)
                nb32 3)))
      ;; the name-length bound is WIRE SYNTAX, not a local construction
      ;; limit: without this check on the accept side, a name this node
      ;; could never be configured to dial can still connect in -- an
      ;; asymmetry that surfaces as an unroutable peer. The proof is
      ;; genuinely valid for the long name, so a refusal can only come
      ;; from the length rule.
      (probe-hello! "acceptor-admits-overlong-name"
        (lambda (nonce)
          (let ((long-name (string->symbol (make-string 300 #\n))))
            (list 'hello long-name (versioned-proof nonce long-name 3)
                  nb32 3)))))
    (display "acceptor refuses unversioned/unbound/mislabeled hello ok\n")

    ;; ⑤ boot-id is a NODE identity, not a connection id: two dials to
    ;;    the same acceptor must see the SAME bootid-A in the challenge.
    ;;    Red spelling of the failure: "boot-id got generated per
    ;;    connection" -- easy to write, and it never announces itself.
    (let ((me self) (ref (gensym)))
      (define (dial-read-bootid! tag)
        (spawn
          (lambda ()
            (tcp-connect! "127.0.0.1" port self)
            (receive (after 3000 (send me (vector ref tag 'no-connect)))
              (`#(tcp-connected ,c)
                (tcp-read-start! c)
                (let ((d (read-frame-or-closed "s1-bootid-stable")))
                  (send me (vector ref tag
                             (if (and (list? d) (= (length d) 4)
                                      (eq? (car d) 'challenge))
                                 (cadddr d) (list 'shape d)))))
                (tcp-close! c))
              (`#(tcp-connect-failed ,e) (send me (vector ref tag 'no-connect)))))))
      (dial-read-bootid! 'one)
      (dial-read-bootid! 'two)
      (let ((got '()))
        (let collect ((n 0))
          (when (< n 2)
            (receive (after 8000 (fail! "s1-bootid-stable" 'timeout))
              (`#(,@ref ,tag ,val) (set! got (cons (cons tag val) got))
                (collect (+ n 1))))))
        (let ((b1 (cdr (assq 'one got))) (b2 (cdr (assq 'two got))))
          (unless (and (hex16? b1) (hex16? b2))
            (fail! "s1-bootid-stable" 'not-hex16 b1 b2))
          (unless (string=? b1 b2)
            (fail! "s1-bootid-stable" 'per-connection-bootid b1 b2)))))
    ;; ---- the positive path, spoken by hand ------------------------------
    ;; A fake dialer that implements the SPECIFIED dialect (anchored to
    ;; the known-answer digest above) must be accepted, and the welcome
    ;; must be the exact three-element frame whose proof binds the
    ;; version. The real-child handshake later in this suite only shows
    ;; that two copies of the implementation agree with each other; this
    ;; cell is what ties the shared dialect to the specified one.
    (let ((me self) (ref (gensym))
          (nb32 "beefbeefbeefbeefbeefbeefbeefbeef"))
      (spawn
        (lambda ()
          (tcp-connect! "127.0.0.1" port self)
          (receive (after 3000 (send me (vector ref 'no-connect)))
            (`#(tcp-connected ,c)
              (tcp-read-start! c)
              (let ((d (read-frame-or-closed "wirepeer-challenge")))
                (cond
                  ((not (and (list? d) (= (length d) 4)))
                   (send me (vector ref 'challenge-shape)))
                  ((not (eq? (car d) 'challenge))
                   (send me (vector ref 'challenge-tag)))
                  ((not (string? (cadr d)))
                   (send me (vector ref 'challenge-nonce-not-string)))
                  ((not (eqv? (caddr d) 4))
                   (send me (vector ref 'challenge-version)))
                  ((not (string? (cadddr d)))
                   (send me (vector ref 'challenge-bootid-not-string)))
                  (else
                   (tcp-write! c (frame-bytes
                                   (list 'hello "wirepeer"
                                         (v4-proof-d (cadr d) "wirepeer"
                                                     probe-boot-id "1"
                                                     wire-name-of-this-node
                                                     (cadddr d))
                                         nb32 4 probe-boot-id 1))
                               #f)
                   (let ((w (read-frame-or-closed "wirepeer-welcome")))
                     (send me (vector ref
                       (cond ((symbol? w) w)   ; closed / closed-with-bytes
                             ((not (and (list? w) (= (length w) 3)))
                              'welcome-shape)
                             ((not (eq? (car w) 'welcome)) 'welcome-tag)
                             ;; v4: names are STRINGS on the wire
                             ((not (equal? (cadr w) wire-name-of-this-node))
                              'welcome-name)
                             ;; the welcome proof binds nonce-b, the
                             ;; acceptor's own name and ITS boot-id --
                             ;; the one it just sent in the challenge
                             ((not (equal? (caddr w)
                                           (v4-proof-a nb32
                                                       wire-name-of-this-node
                                                       (cadddr d))))
                              'welcome-proof-not-bound)
                             (else 'good))))))))
              (tcp-close! c))
            (`#(tcp-connect-failed ,e) (send me (vector ref 'no-connect))))))
      (receive (after 8000 (fail! "wirepeer-interop" 'probe-timeout))
        (`#(,@ref ,what)
          (unless (eq? what 'good) (fail! "wirepeer-interop" what)))))
    (display "specified dialect accepted end to end ok\n")

    ;; ==== S1: wire v4 -- RED FIRST ======================================
    ;; These cells encode the v4 dialect from the signed-off C design
    ;; (archive/igropyr-C-design/C-design.md §8): challenge grows a
    ;; boot-id slot (arity 4), hello grows boot-id and dial-gen (arity
    ;; 7, names as STRINGS on the wire), proof-D binds the dialer's
    ;; identity AND the target's (name-A, bootid-A from the challenge),
    ;; proof-A binds nonce-b:name-A:version:bootid-A. They are EXPECTED
    ;; RED against the v3 tree they thaw: the first assertion fails on
    ;; today's 3-element challenge. They go green when S1 lands, and
    ;; nothing in them may be edited to make that happen -- the digests
    ;; below anchor the formulas to the design's known-answer vectors,
    ;; recomputed independently three times (doc, this session, codex).
    (let ()
    (define (v4-proof key-string msg)
      (bytevector->hex
        (hmac-sha256 (string->utf8 key-string) (string->utf8 msg))))
    (define (msg-d nonce-a name-d bootid-d dialgen name-a bootid-a)
      (string-append nonce-a ":" name-d ":4:" bootid-d ":" dialgen
                     ":" name-a ":" bootid-a))
    (define (msg-a nonce-b name-a bootid-a)
      (string-append nonce-b ":" name-a ":4:" bootid-a))
    ;; one v4 probe = dial, read challenge, answer with a caller-built
    ;; hello (possibly tampered), report what came back. `expect` is
    ;; 'good for a welcome with a CORRECT proof-A, 'closed for refusal.
    (define (v4-probe! label expect build-hello)
      (let ((me self) (ref (gensym)))
        (spawn
          (lambda ()
            (tcp-connect! "127.0.0.1" port self)
            (receive (after 3000 (send me (vector ref 'no-connect)))
              (`#(tcp-connected ,c)
                (tcp-read-start! c)
                (let ((d (read-frame-or-closed label)))
                  (cond
                    ((not (and (list? d) (= (length d) 4)))
                     (send me (vector ref (list 'challenge-arity d))))
                    ((not (eq? (car d) 'challenge))
                     (send me (vector ref 'challenge-tag)))
                    ((not (eqv? (caddr d) 4))
                     (send me (vector ref (list 'challenge-version (caddr d)))))
                    ((not (hex16? (cadddr d)))
                     (send me (vector ref 'challenge-bootid-syntax)))
                    (else
                     (let ((nonce-a (cadr d)) (bootid-a (cadddr d)))
                       (tcp-write! c (frame-bytes
                                       (build-hello nonce-a bootid-a)) #f)
                       (let ((w (read-frame-or-closed label)))
                         (send me (vector ref
                           (cond ((symbol? w) w) ; closed / closed-with-bytes
                                 ((not (and (list? w) (= (length w) 3)
                                            (eq? (car w) 'welcome)))
                                  'welcome-shape)
                                 (else 'welcomed)))))))))
                (tcp-close! c))
              (`#(tcp-connect-failed ,e) (send me (vector ref 'no-connect))))))
        (receive (after 8000 (fail! label 'probe-timeout))
          (`#(,@ref ,what)
            (unless (eq? what (if (eq? expect 'good) 'welcomed 'closed))
              (fail! label what))))))
    (define s1-bootid-d "feedfacefeedface")
    (define (good-v4-hello name-d dialgen)
      (lambda (nonce-a bootid-a)
        (list 'hello name-d
              (v4-proof secret
                        (msg-d nonce-a name-d s1-bootid-d dialgen
                               "a" bootid-a))
              "beadbeadbeadbeadbeadbeadbeadbead" 4 s1-bootid-d
              (string->number dialgen))))
    ;; anchor: the design's known-answer vectors, secret "s". If these
    ;; fail the HELPER diverged from the spec, not the library.
    (unless (equal? (v4-proof "s" (msg-d (make-string 32 #\0) "d"
                                         (make-string 16 #\a) "7"
                                         "e" (make-string 16 #\b)))
                    "6323ff0b8e27276dc0ca365135fa51a4c855343d943ffc703e11df0f726cfbf0")
      (fail! "s1-kat-proof-d-helper-diverged"))
    (unless (equal? (v4-proof "s" (msg-a (make-string 32 #\1) "e"
                                         (make-string 16 #\b)))
                    "0870664de029139ae4ff303314198e4b03b7f5c19874243248b7bf808063fe40")
      (fail! "s1-kat-proof-a-helper-diverged"))
    ;; ① the specified v4 dialect is accepted end to end (RED today:
    ;;    the challenge is still v3's three elements)
    (v4-probe! "s1-v4-dialect-accepted" 'good (good-v4-hello "wire4" "7"))
    ;; ② the v3 dialect must now be REFUSED -- version 3 is over the
    ;;    wire and this node no longer speaks it (RED today: accepted)
    (let ((me self) (ref (gensym)))
      (spawn
        (lambda ()
          (tcp-connect! "127.0.0.1" port self)
          (receive (after 3000 (send me (vector ref 'no-connect)))
            (`#(tcp-connected ,c)
              (tcp-read-start! c)
              (let ((d (read-frame-or-closed "s1-v3-refused")))
                ;; whatever the challenge looks like, answer in v3
                (let ((nonce (if (and (pair? d) (pair? (cdr d))
                                      (string? (cadr d)))
                                 (cadr d) kat-nonce)))
                  (tcp-write! c (frame-bytes
                                  (list 'hello 'relicv3
                                        (versioned-proof nonce 'relicv3 3)
                                        "feedfeedfeedfeedfeedfeedfeedfeed" 3))
                              #f)
                  (let ((w (read-frame-or-closed "s1-v3-refused")))
                    (send me (vector ref (if (symbol? w) w 'welcomed))))))
              (tcp-close! c))
            (`#(tcp-connect-failed ,e) (send me (vector ref 'no-connect))))))
      (receive (after 8000 (fail! "s1-v3-hello-refused" 'probe-timeout))
        (`#(,@ref ,what)
          (unless (eq? what 'closed) (fail! "s1-v3-hello-refused" what)))))
    ;; ③ tampering contrast, discriminating only TOGETHER with ①:
    ;;    a proof bound to the WRONG target boot-id must be refused, and
    ;;    a dial-gen altered after signing must be refused. Each of
    ;;    these alone would be green today for the wrong reason (arity
    ;;    refusal); ① is the half that keeps the batch red until the
    ;;    real gate exists.
    (v4-probe! "s1-proof-wrong-target-bootid" 'closed
      (lambda (nonce-a bootid-a)
        (list 'hello "wire4b"
              (v4-proof secret
                        (msg-d nonce-a "wire4b" s1-bootid-d "7"
                               "a" (make-string 16 #\0))) ; not the real bootid-a
              "beadbeadbeadbeadbeadbeadbeadbead" 4 s1-bootid-d 7)))
    (v4-probe! "s1-dialgen-altered-after-signing" 'closed
      (lambda (nonce-a bootid-a)
        (list 'hello "wire4c"
              (v4-proof secret
                        (msg-d nonce-a "wire4c" s1-bootid-d "7"
                               "a" bootid-a))
              "beadbeadbeadbeadbeadbeadbeadbead" 4 s1-bootid-d
              8)))                       ; signed 7, sent 8
    ;; ④ dial-gen at 2^64 is a PROTOCOL refusal -- close this link,
    ;;    never the node (§8 item 3d: untrusted input must not become a
    ;;    node-level fail-stop). The survival half is the probe that
    ;;    follows: the same good handshake as ① must still succeed.
    (v4-probe! "s1-dialgen-out-of-range-refused" 'closed
      (good-v4-hello "wire4d" "18446744073709551616"))
    (v4-probe! "s1-node-survives-bad-dialgen" 'good
      (good-v4-hello "wire4e" "9"))
    ;; ⑥ THE GENERATOR, not just the consumer. Cells ①–⑤ all check what
    ;;    this node does with a dial-gen it RECEIVES; nothing above says
    ;;    anything about the one it EMITS -- and a field with no reader
    ;;    is the shape of a decoration. Until S2 moves issuance to the
    ;;    registrar (§10.9.20.2), this cell is that reader: a fake
    ;;    acceptor lets the node dial twice and asserts the sequence is
    ;;    per-peer, starts at 1, and advances by one, with the dialer's
    ;;    boot-id constant across the two dials.
    (let ((me self) (ref (gensym)) (gen-port 18086))
      (define seen (box '()))
      (define l
        (tcp-listen! "127.0.0.1" gen-port 16
          (lambda (c)
            (let ((pid (spawn
                         (lambda ()
                           ;; read-start inside the owner: the parent
                           ;; callback must not touch the conn after
                           ;; handing it over (C12 in the design, and
                           ;; the same shape the other fixtures use)
                           (tcp-read-start! c)
                           (tcp-write! c (frame-bytes
                                           (list 'challenge kat-nonce 4
                                                 probe-boot-id))
                                       #f)
                           (let ((d (read-frame-or-closed "s1-gen")))
                             (send me (vector ref
                               (if (and (list? d) (= (length d) 7))
                                   (cons (list-ref d 6) (list-ref d 5))
                                   (list 'shape d))))
                             (tcp-close! c))))))
              (conn-set-owner! c pid)))))
      (node-connect! 'gpeer "127.0.0.1" gen-port)
      (let collect ((n 0) (acc '()))
        (if (= n 2)
            (let* ((first (list-ref (reverse acc) 0))
                   (second (list-ref (reverse acc) 1)))
              (node-disconnect! 'gpeer)
              (when (or (pair? (car first)) (pair? (car second)))
                (fail! "s1-dialgen-generator" 'hello-shape first second))
              ;; per-peer numbering starts at 1 -- a global counter shared
              ;; across peers would show up here as a first value > 1
              (unless (eqv? (car first) 1)
                (fail! "s1-dialgen-generator" 'first-not-1 (car first)))
              ;; SAME AUTHORISATION, SAME NUMBER. The generator moved from
              ;; the dial site to the registrar's issuance point (design
              ;; §10.9.20.2), and that move changed the proposition: what
              ;; is monotone is the AUTHORISATION, not the attempt. One
              ;; authorisation spans however many dials the backoff makes,
              ;; so two attempts under it must carry the same generation --
              ;; an increment here would mean the number had gone back to
              ;; counting attempts. The revocation half is below.
              (unless (eqv? (car second) (car first))
                (fail! "s1-dialgen-generator" 'retry-changed-generation
                       (car first) (car second)))
              ;; the boot-id is the node's, not the connection's
              (unless (equal? (cdr first) (cdr second))
                (fail! "s1-dialgen-generator" 'bootid-varies-per-dial
                       (cdr first) (cdr second)))
              ;; THE OTHER HALF, and without it the cell above is passed
              ;; by a generator that always answers 1. Revoking the
              ;; authorisation (node-disconnect!) must make the next one
              ;; carry a HIGHER number: that is what stops a stale attempt
              ;; from arriving under a live authorisation's colours.
              (node-disconnect! 'gpeer)
              (sleep-ms 300)
              (node-connect! 'gpeer "127.0.0.1" gen-port)
              (receive (after 20000 (fail! "s1-dialgen-revocation" 'timeout))
                (`#(,@ref ,v3)
                  (when (pair? (car v3))
                    (fail! "s1-dialgen-revocation" 'hello-shape v3))
                  (unless (> (car v3) (car second))
                    (fail! "s1-dialgen-revocation" 'reissue-did-not-advance
                           (car second) (car v3)))))
              (node-disconnect! 'gpeer)
              (tcp-stop-listen! l))
            (receive (after 20000 (fail! "s1-dialgen-generator" 'timeout acc))
              (`#(,@ref ,v) (collect (+ n 1) (cons v acc)))))))
    (display "S1 wire-v4 cells passed\n"))
    ;; ==== S2: registrar, decision table, container -- RED FIRST ==========
    ;; The install rules are DATA now, and two properties of that data are
    ;; things no behavioural cell can see: I0 must be physically first
    ;; (reordering it only matters in the window where a parent dies mid
    ;; handshake -- otherwise everything stays green), and the rule names
    ;; must be the ones the design signed off. The library also asserts
    ;; the first of these at load time; this cell is the second reader,
    ;; and it is the one that says WHICH order was expected.
    (let ((order (node-install-rule-order)))
      (unless (pair? order)
        (fail! "s2-rule-order" 'empty order))
      (unless (eq? (car order) 'I0)
        (fail! "s2-rule-order" 'I0-not-first order))
      (unless (equal? order '(I0 I1 I2 I3 I4 I5 I6 I7 I8a I8b))
        (fail! "s2-rule-order" 'unexpected-order order)))
    ;; The orphan chain must be EMPTY whenever nothing is draining -- its
    ;; whole justification is that it exists only while a dead peer still
    ;; has undelivered events. A permanent table would be correct, silent,
    ;; and unbounded in the number of names ever seen (the shape D6
    ;; refused). Measured from outside because that is the only place the
    ;; property is visible: the chain has no name of its own.
    (unless (zero? (node-orphan-count))
      (fail! "s2-orphan-empty-at-rest" 'nonzero-before (node-orphan-count)))
    (let ((gen2-port 18087))
      (let ((l2 (tcp-listen! "127.0.0.1" gen2-port 16
                  (lambda (c)
                    (let ((pid (spawn
                                 (lambda ()
                                   (tcp-read-start! c)
                                   (tcp-write! c (frame-bytes
                                                   (list 'challenge kat-nonce 4
                                                         probe-boot-id))
                                               #f)
                                   (read-frame-or-closed "s2-orphan")
                                   (tcp-close! c)))))
                      (conn-set-owner! c pid))))))
        ;; connect, let it die, and come back under the same name: the
        ;; second dial exercises the adoption path (orphan -> I5), the
        ;; first exercises death (peers -> orphan). Both must leave the
        ;; chain empty once the events have drained.
        (node-connect! 'opeer "127.0.0.1" gen2-port)
        (sleep-ms 1500)
        (node-disconnect! 'opeer)
        (sleep-ms 1500)
        (tcp-stop-listen! l2)
        (sleep-ms 500)
        (unless (zero? (node-orphan-count))
          (fail! "s2-orphan-empty-at-rest" 'leaked-after-churn
                 (node-orphan-count)))))

    ;; ---- CV: what conversation depends on ------------------------------
    ;; conversation deliberately does NOT trust the reason on a
    ;; remote-down; it asks node-peers instead, because a reason can be
    ;; forwarded verbatim, can arrive with no link behind it, and carries
    ;; no ref (conversation.sc's own note). That makes node-peers a
    ;; load-bearing observable for at-most-once: a false 'unreachable
    ;; sends a resume to reconcile a step that already ran. These cells
    ;; are the node-side half of that contract.
    ;;
    ;; CV-1a: an entry must not outlive its link. If it did, a retry
    ;; would arrive under the SAME generation, hit I8a's <= and be
    ;; refused for ever -- the failure is silent and permanent, and
    ;; nothing else in the suite would notice it.
    (let ((cv-port 18088))
      (let ((lc (tcp-listen! "127.0.0.1" cv-port 16
                  (lambda (c)
                    (let ((pid (spawn
                                 (lambda ()
                                   (tcp-read-start! c)
                                   (tcp-write! c (frame-bytes
                                                   (list 'challenge kat-nonce 4
                                                         probe-boot-id))
                                               #f)
                                   (read-frame-or-closed "cv-probe")
                                   (tcp-close! c)))))
                      (conn-set-owner! c pid))))))
        (node-connect! 'cvpeer "127.0.0.1" cv-port)
        (sleep-ms 1200)
        ;; the fake acceptor never welcomes, so no entry should exist;
        ;; what must hold either way is that node-peers never names a
        ;; peer whose link is gone
        (tcp-stop-listen! lc)
        (node-disconnect! 'cvpeer)
        (sleep-ms 1200)
        ;; SCOPE, measured rather than assumed: this assertion holds both
        ;; when the entry was correctly removed AND when none was ever
        ;; installed (the fake acceptor never welcomes). The mutation
        ;; that makes remove-peer! keep its entry is caught earlier, by
        ;; backpressure-no-node-down -- so the discriminating power for
        ;; "an entry outlived its link" lives in THAT cell, not this one.
        ;; What this one owns is the pair, taken after a real
        ;; connect/disconnect cycle rather than at rest: the peer is not
        ;; listed AND nothing was left behind on the orphan chain.
        (when (memq 'cvpeer (node-peers))
          (fail! "cv-1a-entry-outlives-link" 'still-listed (node-peers)))
        (unless (zero? (node-orphan-count))
          (fail! "cv-1a-entry-outlives-link" 'orphan-leak
                 (node-orphan-count)))))

    ;; two long-lived processes for the S3 probe to watch
    (register 'monitor-victim
      (spawn (lambda () (receive (after 60000 (void)) (`#(stop) (void))))))
    (register 'monitor-victim-2
      (spawn (lambda () (receive (after 60000 (void)) (`#(stop) (void))))))
    ;; ---- S3: hosted-monitor admission ---------------------------------
    ;; The ceiling that bounds hosted monitors used to count table
    ;; entries, and arming used to overwrite its key. Both are visible
    ;; from a peer's chair: repeating the SAME (mref, target) must cost
    ;; nothing, and reusing an mref for a DIFFERENT target must cost the
    ;; link -- otherwise one authenticated peer holds an unbounded number
    ;; of agents behind a table of size one.
    ;;
    ;; Run in its own process: the frames belong to whoever owns the
    ;; socket, and the surrounding cells have their own conversations on
    ;; this scheduler.
    (let ((me self) (ref (gensym)))
      (spawn
        (lambda ()
          (let ((c (handshake-as! "monrepeat" "s3-mon-repeat")))
            (define (mon! mref name)
              (tcp-write! c (frame-bytes (list 'mon name mref)) #f))
            (define (quiet? ms)
              (receive (after ms #t)
                (`#(tcp-eof) #f)
                (`#(tcp-error ,_) #f)
                (`#(tcp-data ,_) #t)))
            ;; the target must actually exist and stay alive: an agent
            ;; watching a missing name answers noproc and retires at
            ;; once, and then the second frame is a fresh arm rather than
            ;; the repeat this cell is about
            (mon! 4001 'monitor-victim)
            (sleep-ms 200)
            (mon! 4001 'monitor-victim)
            (mon! 4001 'monitor-victim)
            (let ((survived (quiet? 700)))
              (mon! 4001 'monitor-victim-2)
              (let ((closed (not (quiet? 1500))))
                (tcp-close! c)
                (send me (vector ref survived closed)))))))
      (receive (after 15000 (fail! "s3-admission" 'timeout))
        (`#(,@ref ,survived ,closed)
          (unless survived
            (fail! "s3-mon-repeat-must-be-idempotent" 'link-closed))
          (unless closed
            (fail! "s3-mref-reuse-must-close-the-link" 'link-still-open))))
      (display "S3 admission cells passed\n"))
    ;; ---- S3: the two chains carry the same records --------------------
    ;; The global chain serves the reaper's restart sweep; the per-peer
    ;; chains serve eviction, which splices a whole chain out in one
    ;; step. A record sits on both, and the two are NOT symmetric:
    ;;
    ;;   only on the global chain  = the retiring state itself -- spliced
    ;;       out, DOWN not yet in, credit still held. Legitimate.
    ;;   only on a per-peer chain  = the reaper can never see it, so its
    ;;       DOWN is never awaited and the credit never comes back. A
    ;;       leak, and one with no symptom: nothing else in the system
    ;;       reads that chain.
    ;;
    ;; At rest the three readings must agree; the equality is the cell.
    (let ()
      (define (stat k)
        (let ((e (assq k (node-monitor-stats)))) (and e (cdr e))))
      (define (chains-agree? label)
        (let ((g (stat 'mon-chain)) (p (stat 'mon-peer-chains))
              (a (stat 'accounted)))
          (unless (and g p a)
            (fail! label 'stats-missing (node-monitor-stats)))
          (unless (= g p a)
            (fail! label 'chains-disagree (list 'global g 'per-peer p
                                                'accounted a)))
          g))
      (chains-agree? "s3-chains-at-rest-before")
      (let ((me self) (ref (gensym)))
        (spawn
          (lambda ()
            (let ((c (handshake-as! "chainpeer" "s3-chain-peer")))
              (tcp-write! c (frame-bytes (list 'mon 'monitor-victim 5001)) #f)
              (tcp-write! c (frame-bytes (list 'mon 'monitor-victim-2 5002)) #f)
              (sleep-ms 600)
              (send me (vector ref 'armed))
              ;; hold, then drop the link so every record retires
              (receive (after 4000 (void)) (`#(tcp-eof) (void)))
              (tcp-close! c))))
        (receive (after 12000 (fail! "s3-chains" 'arm-timeout))
          (`#(,@ref ,_)
            ;; armed: both chains must have grown, and still agree
            (let ((n (chains-agree? "s3-chains-while-armed")))
              (when (zero? n)
                (fail! "s3-chains" 'nothing-armed))))))
      ;; after the link is gone everything must come back -- the reading
      ;; that would stay high if a record were left on a per-peer chain
      ;; alone, or if credit were returned by an exit branch that a
      ;; killed agent never runs
      (let loop ((tries 40))
        (cond ((zero? (stat 'accounted)) (void))
              ((zero? tries)
               (fail! "s3-chains-return-to-baseline"
                      (node-monitor-stats)))
              (else (sleep-ms 250) (loop (- tries 1)))))
      (chains-agree? "s3-chains-at-rest-after")
      (display "S3 chain cells passed\n"))

    ;; ---- the hosted-monitor teardown walk drops EVERY parked monitor --
    ;;
    ;; A REGRESSION GUARD for drop-hosted-monitors!'s traversal, NOT a
    ;; discriminator for the race it was rewritten to close. That race --
    ;; a reaper retiring a node in the middle of the walk -- is not
    ;; reachable from this harness: the walk yields only on a tick-budget
    ;; preemption, which a few thousand monitors do not span, and send
    ;; does not yield the sender. So no cell turns red on the truncation
    ;; itself; that is recorded beside the code, not here. ⛔ Do not read
    ;; this green as coverage of the race.
    ;;
    ;; What this DOES own is the ordinary path over a real chain: arm
    ;; several monitors for one peer, drop the peer, and every one of them
    ;; must retire. A walk that stops early -- popping only the head,
    ;; mishandling the sentinel anchor, losing the tail -- leaves
    ;; accounted above baseline here, on any tree, with no timing needed.
    ;; Six is more than the two the chain cell above uses, so a
    ;; middle-of-chain error has somewhere to show.
    (let ()
      (define (stat k)
        (let ((e (assq k (node-monitor-stats)))) (and e (cdr e))))
      (define (await-accounted! label want tries)
        (let loop ((n 0))
          (cond ((eqv? (stat 'accounted) want) 'ok)
                ((= n tries)
                 (fail! label (list 'accounted (stat 'accounted) 'want want)))
                (else (sleep-ms 100) (loop (+ n 1))))))
      (define (vname i)
        (string->symbol (string-append "drop6-victim-" (number->string i))))
      (await-accounted! "drop6-baseline-before" 0 80)
      ;; the suite runs with a hosting ceiling of 2 (node-set-limits! 64 2
      ;; near the top), so six monitors would arm two and get overload for
      ;; the other four. Raise it for this cell -- a longer chain is the
      ;; point -- and restore it after, since a later cell reads the 2.
      (node-set-limits! #f 8)
      (for-each
        (lambda (i)
          (register (vname i)
            (spawn (lambda () (receive (after 60000 (void)) (`#(stop) (void)))))))
        '(1 2 3 4 5 6))
      (let ((me self) (ref (gensym)))
        (spawn
          (lambda ()
            (let ((c (handshake-as! "drop6peer" "drop6")))
              (for-each
                (lambda (i)
                  (tcp-write! c (frame-bytes (list 'mon (vname i) (+ 7000 i))) #f))
                '(1 2 3 4 5 6))
              (sleep-ms 800)
              (send me (vector ref 'armed))
              ;; hold past the main's while-armed read, then drop so the
              ;; teardown walk runs over the whole chain at once
              (receive (after 4000 (void)) (`#(tcp-eof) (void)))
              (tcp-close! c))))
        (receive (after 15000 (fail! "drop6" 'arm-timeout))
          (`#(,@ref ,_)
            ;; all six armed, and the three readings agree
            (let ((g (stat 'mon-chain)) (p (stat 'mon-peer-chains))
                  (a (stat 'accounted)))
              (unless (and (eqv? a 6) (= g p a))
                (fail! "drop6-arm"
                       (list 'mon-chain g 'mon-peer-chains p 'accounted a
                             'want 6)))))))
      ;; the peer is gone: every parked monitor must retire
      (await-accounted! "drop6-return-to-baseline" 0 80)
      (let ((g (stat 'mon-chain)) (p (stat 'mon-peer-chains))
            (a (stat 'accounted)))
        (unless (= g p a 0)
          (fail! "drop6-at-rest-after"
                 (list 'mon-chain g 'mon-peer-chains p 'accounted a))))
      (node-set-limits! #f 2)              ; restore the suite's standing ceiling
      (display "hosted-monitor teardown drops every parked monitor ok\n"))

    ;; ---- S3: a dead agent's entry must not answer for a live one ------
    ;; ⚠️ SCOPE, measured: this cell does NOT discriminate the liveness
    ;; precondition on its own. Removing that check from the arming path
    ;; leaves the cell green, because the reaper usually processes the
    ;; agent's DOWN and drops the entry before the re-arm arrives -- so
    ;; the re-arm takes the fresh-install branch either way, and the
    ;; window the check exists for is one this cell cannot reliably open.
    ;; What it does own is the end-to-end property: after a target dies
    ;; and a new one takes its name, arming the same triple again yields
    ;; a monitor that really follows the new target, and the credit for
    ;; it comes back. The precondition itself is guarded by construction
    ;; (arming reads liveness inside the same region that installs), not
    ;; by this cell.
    ;;
    ;; ⚠️ And the green itself is contingent: the window stays shut only
    ;; because the reaper currently drains its DOWN faster than a peer
    ;; can send the next frame. That is a property of today's timing,
    ;; not a guarantee -- if the sweep grows or the mailbox backs up, the
    ;; window opens and nothing here is watching it.
    ;; Moving credit return to the reaper moved something else with it:
    ;; the entry now outlives the agent, from the moment the agent dies
    ;; until the reaper has processed its DOWN. Inside that window a
    ;; repeat of the same triple used to find an entry and report
    ;; idempotent success -- telling the peer its monitor is armed while
    ;; the agent behind it is gone. Arming has to check that the agent is
    ;; alive, and re-arm when it is not.
    (let ((me self) (ref (gensym)))
      (spawn
        (lambda ()
          (let ((c (handshake-as! "revivepeer" "s3-revive")))
            (tcp-write! c (frame-bytes (list 'mon 'monitor-victim 6001)) #f)
            (sleep-ms 500)
            ;; kill what the agent is watching: the agent reports and
            ;; dies, and for a moment its entry is still in the table
            (let ((v (whereis 'monitor-victim)))
              (when v (kill v 'for-the-cell)))
            (sleep-ms 150)
            ;; re-register a target under the same name, then re-arm the
            ;; SAME triple. This must install a new agent, not answer
            ;; "already done" on behalf of the dead one.
            (register 'monitor-victim
              (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void))))))
            (tcp-write! c (frame-bytes (list 'mon 'monitor-victim 6001)) #f)
            (sleep-ms 700)
            ;; THE DISCRIMINATOR is the second kill, not the count. A
            ;; stale entry that answered "already armed" leaves the new
            ;; victim unwatched: killing it then returns nothing, and
            ;; accounted stays where it was. A real re-arm follows the
            ;; new victim and the credit comes back.
            (let ((v2 (whereis 'monitor-victim)))
              (when v2 (kill v2 'second-kill)))
            (sleep-ms 800)
            (send me (vector ref (assq 'accounted (node-monitor-stats))))
            (receive (after 3000 (void)) (`#(tcp-eof) (void)))
            (tcp-close! c))))
      (receive (after 15000 (fail! "s3-revive" 'timeout))
        (`#(,@ref ,acc)
          ;; the re-arm must have produced a live monitor again: a stale
          ;; entry answering "idempotent" leaves nothing armed and the
          ;; count sits at zero
          ;; after the second kill the credit must be back: a live
          ;; monitor followed that victim and its death was reported.
          ;; With a stale entry answering as armed, nothing watched the
          ;; new victim and the count never returns.
          (when (or (not acc) (not (zero? (cdr acc))))
            (fail! "s3-stale-entry-must-not-answer-as-armed" acc))))
      ;; leave the counters where they were found: this cell arms a
      ;; monitor and kills a target, and the later baseline cells count
      ;; both. Waiting for the reaper to drain is part of the cell, not
      ;; cleanup after it -- an assertion that the credit comes back.
      (let loop ((tries 40))
        (let ((acc (assq 'accounted (node-monitor-stats))))
          (cond ((and acc (zero? (cdr acc))) (void))
                ((zero? tries)
                 (fail! "s3-revive-credit-must-return" (node-monitor-stats)))
                (else (sleep-ms 250) (loop (- tries 1))))))
      (display "S3 revive cell passed\n"))
    ;; ---- S3: the warden actually restores the function ----------------
    ;; ⛔ THIS IS THE ONLY DEVICE COVERING THE POST-RESTART PATH. No probe
    ;; that does not kill the reaper can reach it -- deleting this cell
    ;; returns that path to zero coverage. It has already earned that
    ;; description once: it found a reaper that restarted, registered,
    ;; swept, and reported normally while establishing no monitors at
    ;; all, because the pid index it inherited made every record look
    ;; already-watched. Every observable was healthy; one number stopped
    ;; moving.
    ;; The reaper is the only thing that returns hosted-monitor credit,
    ;; so if it dies and nothing brings it back, the ceiling ratchets
    ;; shut in silence. Asserting that a NEW pid appeared would not say
    ;; that much: a reaper that restarts but never sweeps leaves every
    ;; record from before the restart unwatched, and a crash loop
    ;; produces new pids forever. So the assertion is the function --
    ;; kill it, then kill a watched target and require the credit back.
    (let ((me self) (ref (gensym)))
      (spawn
        (lambda ()
          (let ((c (handshake-as! "wardenpeer" "s3-warden")))
            (register 'warden-victim
              (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void))))))
            (tcp-write! c (frame-bytes (list 'mon 'warden-victim 7001)) #f)
            (sleep-ms 500)
            ;; take the reaper out from under the armed monitor
            (let ((r (whereis 'igropyr-node-reaper)))
              (unless r (fail! "s3-warden" 'no-reaper-registered))
              (kill r 'probe-kill))
            (sleep-ms 800)
            ;; the discriminator that separates "never came back" from
            ;; "came back but never swept": without it a dead warden
            ;; leaves this cell waiting instead of failing
            (unless (whereis 'igropyr-node-reaper)
              (fail! "s3-warden-must-restart-the-reaper" 'still-absent))
            (let ((v (whereis 'warden-victim)))
              (when v (kill v 'after-restart)))
            (sleep-ms 200)
            (send me (vector ref 'done))
            (receive (after 3000 (void)) (`#(tcp-eof) (void)))
            (tcp-close! c))))
      (receive (after 15000 (fail! "s3-warden" 'timeout))
        (`#(,@ref ,_) (void)))
      ;; the credit for a monitor armed BEFORE the restart must come back
      ;; after it: that can only happen if the new reaper swept the chain
      ;; and re-established the watch it inherited
      (let loop ((tries 40))
        (let ((acc (assq 'accounted (node-monitor-stats))))
          (cond ((and acc (zero? (cdr acc))) (void))
                ((zero? tries)
                 (fail! "s3-warden-restart-must-restore-the-function"
                        (node-monitor-stats)))
                (else (sleep-ms 250) (loop (- tries 1))))))
      (display "S3 warden cell passed\n"))
    ;; ---- S3: eviction conserves the credit ----------------------------
    ;; Admission pays for a record once, and that payment covers it from
    ;; arming until its DOWN -- across both phases. So eviction, which
    ;; moves a whole peer's chain from active to retiring in one splice,
    ;; must not change `accounted` at all: it applies for nothing and can
    ;; therefore not fail.
    ;;
    ;; ⚠️ WHAT THIS CELL DOES NOT WITNESS: retiring > 0. The whole
    ;; eviction -- splice, the walk that tells each agent to go, their
    ;; exits, and the reaper's DOWNs -- fits in one scheduling turn, and a
    ;; sampling loop is another green thread in that same scheduler: its
    ;; first sleep hands the entire sequence away. The intermediate state
    ;; is not "brief", it is unreachable from here. Conservation is
    ;; checked across the eviction instead of inside it, which is the
    ;; property that matters; the non-zero half is unwitnessed and is
    ;; recorded as such rather than asserted with a sleep that would pass
    ;; for the wrong reason.
    (let ()
      (define (stat k)
        (let ((st (node-monitor-stats)))
          (let ((e (assq k st)))
            (cond (e (cdr e))
                  (else (let ((ph (assq 'phases st)))
                          (and ph (let ((q (assq k (cdr ph)))) (and q (cdr q))))))))))
      (let ((me self) (ref (gensym)))
        (spawn
          (lambda ()
            (let ((c (handshake-as! "evictpeer" "s3-evict")))
              (register 'evict-victim
                (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void))))))
              ;; TWO, not more: this suite runs with the hosting ceiling
              ;; set to 2 (node-set-limits! 64 2 near the top), so a
              ;; larger number here would be refused and the cell would
              ;; be measuring the ceiling instead of the eviction
              (let arm ((i 0))
                (when (< i 2)
                  (tcp-write! c (frame-bytes
                                  (list 'mon 'evict-victim (+ 8100 i))) #f)
                  (sleep-ms 60)
                  (arm (+ i 1))))
              (sleep-ms 600)
              (send me (vector ref (stat 'accounted)))
              ;; dropping the link evicts the whole per-peer chain
              (tcp-close! c))))
        (receive (after 15000 (fail! "s3-evict" 'timeout))
          (`#(,@ref ,armed)
            (unless (and armed (= armed 2))
              (fail! "s3-evict" 'arming-count armed (node-monitor-stats))))))
      ;; ⚠️ MEASURED SCOPE: taking the evicted nodes off the GLOBAL chain
      ;; as well leaves this cell green. The walk tells each agent to go,
      ;; the agent exits, and the reaper returns the credit from its
      ;; DOWN -- none of which reads that chain. What the global chain
      ;; buys is the restart path: a reaper that comes back walks it to
      ;; re-establish the watches it inherited, and a node missing from
      ;; it is one it can never see again. That property belongs to the
      ;; warden cell above, which does kill the reaper; this cell does
      ;; not stand behind it.
      ;;
      ;; after the eviction has drained, every reading returns to zero.
      ;; A record left on a per-peer chain, or credit returned by an exit
      ;; branch a killed agent never runs, shows up here and nowhere else.
      (let loop ((tries 60))
        (cond ((and (eqv? (stat 'accounted) 0)
                    (eqv? (stat 'mon-chain) 0)
                    (eqv? (stat 'active) 0)
                    (eqv? (stat 'retiring) 0))
               (void))
              ((zero? tries)
               (fail! "s3-eviction-must-drain" (node-monitor-stats)))
              (else (sleep-ms 250) (loop (- tries 1)))))
      (display "S3 eviction cell passed\n"))




    ;; ---- S2: replacement, seen from the side that LOSES ---------------
    ;; Everything above asserts our own tables. A rule that says "refuse,
    ;; close, notify nobody" has a second half that only the peer can
    ;; see, and no assertion about our state can reach it: the frames we
    ;; already put on the wire are the peer's evidence, not ours.
    ;;
    ;; This drives a real replacement by hand -- two inbound handshakes
    ;; for one name -- which is also the only path in this suite that
    ;; executes (R1) at all. A generation BELOW the installed one must be
    ;; refused, and refusal means the loser never saw a welcome: a
    ;; welcome makes a real dialer install, announce node-up, and then
    ;; take the close as node-down, which is a pair of events out of
    ;; nothing.
    (let ()
      (define (inbound-as! label gen)
        ;; returns 'welcomed or 'closed, from the DIALER's chair
        (let ((me self) (ref (gensym)))
          (spawn
            (lambda ()
              (tcp-connect! "127.0.0.1" port self)
              (receive (after 3000 (send me (vector ref 'no-connect)))
                (`#(tcp-connected ,c)
                  (tcp-read-start! c)
                  (let ((d (read-frame-or-closed label)))
                    (if (not (and (list? d) (= (length d) 4)))
                        (send me (vector ref (list 'challenge-shape d)))
                        (let ((nonce-a (cadr d)) (bootid-a (cadddr d))
                              (nm (string-append "rep" (number->string gen))))
                          (tcp-write! c (frame-bytes
                                          (list 'hello nm
                                                (v4-proof-d nonce-a nm
                                                            probe-boot-id
                                                            (number->string gen)
                                                            wire-name-of-this-node
                                                            bootid-a)
                                                "beadbeadbeadbeadbeadbeadbeadbead"
                                                4 probe-boot-id gen))
                                      #f)
                          (let ((w (read-frame-or-closed label)))
                            (send me (vector ref
                              (if (symbol? w) w
                                  (if (and (list? w) (eq? (car w) 'welcome))
                                      'welcomed 'other))))))))
                  (tcp-close! c))
                (`#(tcp-connect-failed ,e) (send me (vector ref 'no-connect))))))
          (receive (after 9000 (fail! label 'probe-timeout))
            (`#(,@ref ,what) what))))
      (define (same-name-as! label gen)
        (let ((me self) (ref (gensym)))
          (spawn
            (lambda ()
              (tcp-connect! "127.0.0.1" port self)
              (receive (after 3000 (send me (vector ref 'no-connect)))
                (`#(tcp-connected ,c)
                  (tcp-read-start! c)
                  (let ((d (read-frame-or-closed label)))
                    (if (not (and (list? d) (= (length d) 4)))
                        (send me (vector ref (list 'challenge-shape d)))
                        (let ((nonce-a (cadr d)) (bootid-a (cadddr d)))
                          (tcp-write! c (frame-bytes
                                          (list 'hello "repeat"
                                                (v4-proof-d nonce-a "repeat"
                                                            probe-boot-id
                                                            (number->string gen)
                                                            wire-name-of-this-node
                                                            bootid-a)
                                                "beadbeadbeadbeadbeadbeadbeadbead"
                                                4 probe-boot-id gen))
                                      #f)
                          (let ((w (read-frame-or-closed label)))
                            (send me (vector ref
                              (if (symbol? w) w
                                  (if (and (list? w) (eq? (car w) 'welcome))
                                      'welcomed 'other))))))))
                  (tcp-close! c))
                (`#(tcp-connect-failed ,e) (send me (vector ref 'no-connect))))))
          (receive (after 9000 (fail! label 'probe-timeout))
            (`#(,@ref ,what) what))))
      (define (hold-open-as! label gen)
        ;; welcomes, then PARKS holding the connection, so the entry
        ;; stays installed. Returns (cons result session-pid).
        (let ((me self) (ref (gensym)))
          (let ((pid (spawn
                       (lambda ()
                         (tcp-connect! "127.0.0.1" port self)
                         (receive (after 3000 (send me (vector ref 'no-connect)))
                           (`#(tcp-connected ,c)
                             (tcp-read-start! c)
                             (let ((d (read-frame-or-closed label)))
                               (if (not (and (list? d) (= (length d) 4)))
                                   (send me (vector ref (list 'challenge-shape d)))
                                   (let ((nonce-a (cadr d)) (bootid-a (cadddr d)))
                                     (tcp-write! c (frame-bytes
                                                     (list 'hello "repeat"
                                                           (v4-proof-d nonce-a "repeat"
                                                                       probe-boot-id
                                                                       (number->string gen)
                                                                       wire-name-of-this-node
                                                                       bootid-a)
                                                           "beadbeadbeadbeadbeadbeadbeadbead"
                                                           4 probe-boot-id gen))
                                                 #f)
                                     (let ((w (read-frame-or-closed label)))
                                       (send me (vector ref
                                         (if (symbol? w) w
                                             (if (and (list? w) (eq? (car w) 'welcome))
                                                 'welcomed 'other))))
                                       ;; hold: only EOF (the replacement
                                       ;; closing us) ends this session
                                       (receive (after 20000 (void))
                                         (`#(tcp-eof) (void))
                                         (`#(tcp-error ,_) (void)))
                                       (tcp-close! c))))))
                           (`#(tcp-connect-failed ,e)
                             (send me (vector ref 'no-connect))))))))
            (receive (after 9000 (fail! label 'probe-timeout))
              (`#(,@ref ,what) (cons what pid))))))
      ;; the three names differ, so each handshake is a separate peer and
      ;; the generation is the only thing under test here
      (let ((first (inbound-as! "s2-rep-first" 7)))
        (unless (eq? first 'welcomed)
          (fail! "s2-replacement" 'first-not-welcomed first)))
      ;; SAME NAME, so these two are a real (R1) replacement rather than
      ;; two unrelated peers. A higher generation takes over; a LOWER one
      ;; is the refusal whose second half only the loser can see.
      ;; THE WINNER MUST STAY OPEN while the stale attempt is made.
      ;; Closing it first tears the entry down, and then the stale
      ;; generation lands on I5 -- "no entry, no current value, accept
      ;; any generation", which is a DIFFERENT rule with the same
      ;; observable. An earlier spelling of this cell closed each probe
      ;; as soon as it read the reply and was red for that reason, both
      ;; before and after the defect it was supposed to be watching: it
      ;; named I8a and exercised I5.
      (let ((held (hold-open-as! "s2-rep-gen8" 8)))
        (unless (eq? (car held) 'welcomed)
          (fail! "s2-replacement" 'higher-gen-not-welcomed (car held)))
        ;; THE DISCRIMINATOR. Without this the cell cannot tell "I8a
        ;; refused" from "I5 accepted": both answers look the same on the
        ;; wire, and only the presence of a live entry says which rule
        ;; the stale attempt is about to meet.
        (unless (memq 'repeat (node-peers))
          (fail! "s2-replacement" 'no-entry-so-the-next-probe-tests-I5
                 (node-peers)))
      ;; THE REFUSAL, ASSERTED FROM THE LOSER'S CHAIR. Design I8a says
      ;; "refuse, close, notify nobody"; the second half is a claim about
      ;; what the peer observes, so it can only be checked here. A
      ;; welcome sent before the install decision makes a real dialer
      ;; install, announce node-up, and then read the close as node-down
      ;; -- a pair of events out of nothing, on a link that was never
      ;; accepted.
        (let ((loser (same-name-as! "s2-rep-stale" 6)))
          (unless (eq? loser 'closed)
            (fail! "s2-stale-gen-must-not-be-welcomed" loser)))
        ;; NOT COVERED HERE, and the boundary is worth writing down: the
        ;; delete-then-insert spelling of the swap is unobservable only
        ;; in fault-free executions -- the whole sequence runs in one
        ;; non-preemptible region on a single scheduler thread, so no
        ;; reader can be running between the two writes. That says
        ;; nothing about the failure path: `atomically` does not roll
        ;; back, so a re-insert that raises leaves the entry absent
        ;; permanently, not for an instant, and CV-1 says entries never
        ;; go absent. What makes in-place replacement correct is that
        ;; property, not the width of the window.
        ;;
        ;; THE OLD CONNECTION MUST ACTUALLY BE CLOSED by the replacement,
        ;; and only the peer sitting on it can say so. (R1) closes it by
        ;; calling tcp-close! inside the region rather than by writing a
        ;; state word -- a marker would leave the handle open for ever,
        ;; and the difference is invisible from our own tables. The held
        ;; session parks until EOF, so if the close were neutralised it
        ;; would still be alive here.
        (let ((h2 (hold-open-as! "s2-rep-gen10" 10)))
          (unless (eq? (car h2) 'welcomed)
            (fail! "s2-replacement" 'gen10-not-welcomed (car h2)))
          (sleep-ms 800)
          (when (process-alive? (cdr held))
            (fail! "s2-old-conn-not-closed-by-replacement" 'still-parked))
          (kill (cdr h2) 'done)
          (sleep-ms 300))
        ;; leave nothing parked: the held session would otherwise still
        ;; own a connection when the later baseline cells count them
        (kill (cdr held) 'done)
        (sleep-ms 400))
      (display "S2 replacement cells passed\n"))

    ;; ---- a watch across a replacement: two incarnations, opposite answers --
    ;; A remote monitor has two halves: the watcher's rmonitors entry and
    ;; the agent the target hosts for it. Nothing on either side reports a
    ;; difference between them, so a target that quietly stops hosting its
    ;; half leaves the watcher believing it is watching, and a death that
    ;; never arrives looks exactly like a process that has not died.
    ;;
    ;; THE PEER HERE IS THE WATCHER and this node is the target: the
    ;; watcher's half is a frame the fixture sends, the target's half is
    ;; an agent this node hosts, and what the cells read is the mdown
    ;; FRAME ON THE WIRE -- the target's half and nothing else.
    ;;
    ;; ⭐ TWO CELLS, ONE FIXTURE, ONE CONSTANT APART, OPPOSITE VERDICTS.
    ;; A replacement has two sources and they want opposite things:
    ;;   - SAME incarnation, new connection: the peer is the same process,
    ;;     its rmonitors entry is still there, so the hosted half MUST
    ;;     survive;
    ;;   - NEW incarnation (different boot id): the old peer is gone, its
    ;;     parked agents are dead registrations, so they MUST be dropped --
    ;;     and a stale one that survives does not merely leak: it reports
    ;;     the death of a local process to the NEW incarnation, whose mref
    ;;     counter also restarts at 1, so the peer hears that a monitor it
    ;;     never armed has fired.
    ;;
    ;; ⛔ WHICH SOURCE EACH CELL DRIVES IS STRUCTURAL, NOT A COMMENT.
    ;; The same-incarnation cell keeps the boot id and RAISES the
    ;; generation (only I8a can replace on that). The new-incarnation cell
    ;; changes the boot id and KEEPS the generation (I8a refuses an equal
    ;; generation, so only I6 can replace on that). Change one constant in
    ;; either and it stops being the case it is named for -- and the other
    ;; cell, which expects the opposite, is sitting next to it.
    (let ()
      (define alt-boot-id "deadbeefdeadbeef")
      (define (mdown-count-session! label boot gen mref victim-name me ref)
        ;; Like watch-session!, but COUNTS the mdowns for its mref instead
        ;; of reporting the first one. The first one is all a correct node
        ;; ever sends; a second is the whole point of the cell, and the
        ;; helper that stops at the first cannot see it.
        (spawn
          (lambda ()
            (tcp-connect! "127.0.0.1" port self)
            (receive (after 3000 (send me (vector ref 'no-connect)))
              (`#(tcp-connected ,c)
                (tcp-read-start! c)
                (let ((d (read-frame-or-closed label)))
                  (if (not (and (list? d) (= (length d) 4)))
                      (send me (vector ref (list 'challenge-shape d)))
                      (let ((nonce-a (cadr d)) (bootid-a (cadddr d)))
                        (tcp-write! c (frame-bytes
                                        (list 'hello "wpeer"
                                              (v4-proof-d nonce-a "wpeer" boot
                                                          (number->string gen)
                                                          wire-name-of-this-node
                                                          bootid-a)
                                              "beadbeadbeadbeadbeadbeadbeadbead"
                                              4 boot gen))
                                    #f)
                        (let ((w (read-frame-or-closed label)))
                          (if (not (and (list? w) (eq? (car w) 'welcome)))
                              (send me (vector ref (if (symbol? w) w 'other)))
                              (begin
                                (when victim-name
                                  (tcp-write! c (frame-bytes
                                                  (list 'mon victim-name mref))
                                              #f))
                                (send me (vector ref 'welcomed))
                                ;; ⛔ TWO KINDS OF (mdown <mref> ...), and
                                ;; they must not be added together: the
                                ;; refusal a full node sends carries the
                                ;; SAME tag and the SAME mref as a real
                                ;; down (see dispatch!'s overload answer).
                                ;; A cell that counts frames counts the
                                ;; refusal as a report.
                                (let wait ((acc "") (k 0) (ov 0) (idle 0))
                                  (let* ((n (string-length acc))
                                         (nl (let scan ((j 0))
                                               (cond ((= j n) #f)
                                                     ((char=? (string-ref acc j)
                                                              #\newline) j)
                                                     (else (scan (+ j 1))))))
                                         (len (and nl (string->number
                                                        (substring acc 0 nl)))))
                                    (if (and len (>= n (+ nl 1 len)))
                                        (let* ((f (read (open-input-string
                                                          (substring acc (+ nl 1)
                                                                     (+ nl 1 len)))))
                                               (mine (and (list? f)
                                                          (eq? (car f) 'mdown)
                                                          (eqv? (cadr f) mref)))
                                               (over (and mine (= (length f) 3)
                                                          (eq? (caddr f) 'overload))))
                                          (wait (substring acc (+ nl 1 len) n)
                                                (if (and mine (not over)) (+ k 1) k)
                                                (if over (+ ov 1) ov)
                                                0))
                                        (if (>= idle 10)
                                            (send me (vector ref 'count k ov))
                                            (receive (after 600
                                                       (wait acc k ov (+ idle 1)))
                                              (`#(tcp-data ,bv)
                                                (wait (string-append
                                                        acc (utf8->string bv))
                                                      k ov 0))
                                              (`#(tcp-eof)
                                                (send me (vector ref 'count k ov)))
                                              (`#(tcp-error ,e)
                                                (send me (vector ref 'count k ov)))))))))))))))))))

      (define (burst-session! label boot gen me ref arm)
        ;; Handshake as "wpeer", then WAIT. On #(go victim mref) it writes
        ;; one segment: filler frames, then the `mon` last. Nothing is
        ;; read back here -- the mdown is written to the peer NAME, so it
        ;; arrives on whichever connection is current, which is the point.
        (spawn
          (lambda ()
            (tcp-connect! "127.0.0.1" port self)
            (receive (after 3000 (send me (vector ref 'no-connect)))
              (`#(tcp-connected ,c)
                (tcp-read-start! c)
                (let ((d (read-frame-or-closed label)))
                  (if (not (and (list? d) (= (length d) 4)))
                      (send me (vector ref (list 'challenge-shape d)))
                      (let ((nonce-a (cadr d)) (bootid-a (cadddr d)))
                        (tcp-write! c (frame-bytes
                                        (list 'hello "wpeer"
                                              (v4-proof-d nonce-a "wpeer" boot
                                                          (number->string gen)
                                                          wire-name-of-this-node
                                                          bootid-a)
                                              "beadbeadbeadbeadbeadbeadbeadbead"
                                              4 boot gen))
                                    #f)
                        (let ((w (read-frame-or-closed label)))
                          (if (not (and (list? w) (eq? (car w) 'welcome)))
                              (send me (vector ref (if (symbol? w) w 'other)))
                              (begin
                                ;; arm BEFORE the replacement when asked:
                                ;; the demon cell needs a watch to cancel.
                                (when arm
                                  (tcp-write! c (frame-bytes
                                                  (list 'mon (car arm) (cdr arm)))
                                              #f))
                                (send me (vector ref 'welcomed))
                                (receive (after 20000 (void))
                                  ;; The caller supplies the whole tail, in
                                  ;; order. Its last frame is the one under
                                  ;; test; the one before it is a marker
                                  ;; whose effect is observable, so the
                                  ;; marker's arrival proves this link
                                  ;; dispatched as far as the frame BEFORE
                                  ;; the one under test.
                                  (`#(go ,n ,tail)
                                    (tcp-write! c (burst-bytes n tail) #f)
                                    (receive (after 30000 (void))
                                      (`#(stop) (void))))))))))))))))

      (define (watch-session! label boot gen mref victim-name me ref)
        ;; Handshake as "wpeer" with `boot`/`gen`. When mref, arm it.
        ;; Then report the first mdown for it, or 'no-mdown when the read
        ;; window closes. -> the session's pid.
        (spawn
          (lambda ()
            (tcp-connect! "127.0.0.1" port self)
            (receive (after 3000 (send me (vector ref 'no-connect)))
              (`#(tcp-connected ,c)
                (tcp-read-start! c)
                (let ((d (read-frame-or-closed label)))
                  (if (not (and (list? d) (= (length d) 4)))
                      (send me (vector ref (list 'challenge-shape d)))
                      (let ((nonce-a (cadr d)) (bootid-a (cadddr d)))
                        (tcp-write! c (frame-bytes
                                        (list 'hello "wpeer"
                                              (v4-proof-d nonce-a "wpeer" boot
                                                          (number->string gen)
                                                          wire-name-of-this-node
                                                          bootid-a)
                                              "beadbeadbeadbeadbeadbeadbeadbead"
                                              4 boot gen))
                                    #f)
                        (let ((w (read-frame-or-closed label)))
                          (if (not (and (list? w) (eq? (car w) 'welcome)))
                              (send me (vector ref (if (symbol? w) w 'other)))
                              (begin
                                (when mref
                                  (tcp-write! c (frame-bytes
                                                  (list 'mon victim-name mref)) #f))
                                (send me (vector ref 'welcomed))
                                ;; READ WITHOUT read-frame-or-closed: that
                                ;; helper ends the whole run with its own
                                ;; label on a timeout, and a silence is
                                ;; exactly what these cells report. The
                                ;; verdict has to carry THIS cell's name.
                                (let wait ((acc ""))
                                  (let* ((n (string-length acc))
                                         (nl (let scan ((k 0))
                                               (cond ((= k n) #f)
                                                     ((char=? (string-ref acc k)
                                                              #\newline) k)
                                                     (else (scan (+ k 1))))))
                                         (len (and nl (string->number
                                                        (substring acc 0 nl)))))
                                    (if (and len (>= n (+ nl 1 len)))
                                        (let ((f (read (open-input-string
                                                         (substring acc (+ nl 1)
                                                                    (+ nl 1 len))))))
                                          (if (and (list? f) (eq? (car f) 'mdown))
                                              (send me (vector ref (list 'mdown (cadr f))))
                                              (wait (substring acc (+ nl 1 len) n))))
                                        (receive (after 5000
                                                   (send me (vector ref 'no-mdown)))
                                          (`#(tcp-data ,bv)
                                            (wait (string-append acc (utf8->string bv))))
                                          (`#(tcp-eof) (send me (vector ref 'closed)))
                                          (`#(tcp-error ,_)
                                            (send me (vector ref 'closed)))))))))))))
                (tcp-close! c))
              (`#(tcp-connect-failed ,e) (send me (vector ref 'no-connect)))))))
      (define (callee-count) (cdr (assq 'callee-agents (node-monitor-stats))))
      (define (welcomed! ref label)
        (receive (after 12000 (fail! label 'no-welcome))
          (`#(,@ref welcomed) 'ok)
          (`#(,@ref ,other) (fail! label (list 'handshake other)))))
      (define (armed! base label)
        ;; OBSERVABLY armed before the replacement: without this a cell
        ;; passes with nothing to lose.
        (let poll ((n 0))
          (unless (> (callee-count) base)
            (if (= n 60)
                (fail! label (list 'arm-never-landed (callee-count) base))
                (begin (sleep-ms 50) (poll (+ n 1)))))))

      ;; ---- same incarnation: the hosted half must survive -----------------
      (let* ((me self) (r1 (gensym)) (r2 (gensym))
             (victim (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void))))))
             (base (callee-count)))
        (register 'watch-victim victim)
        (let ((p1 (watch-session! "s-watch-old" probe-boot-id 31 9101
                                  'watch-victim me r1)))
          (welcomed! r1 "watch-same-incarnation")
          (armed! base "watch-same-incarnation")
          (let ((p2 (watch-session! "s-watch-new" probe-boot-id 32 #f
                                    'watch-victim me r2)))
            (welcomed! r2 "watch-same-incarnation")
            (sleep-ms 400)
            ;; ⭐ THE MIDDLE SAMPLE separates the two ways this can break.
            ;; A teardown on the replacement path shows up here, as a count
            ;; that has already fallen; a gate on the reporting side leaves
            ;; the count alone and shows up below, as a notice that never
            ;; comes. One reading, three sample points.
            (unless (> (callee-count) base)
              (fail! "watch-torn-down-on-same-incarnation" (callee-count)))
            (kill victim 'for-the-cell)
            (receive (after 12000 (fail! "watch-same-incarnation" 'verdict-timeout))
              (`#(,@r2 (mdown ,m)) (unless (eqv? m 9101)
                                     (fail! "watch-wrong-mref" m)))
              (`#(,@r2 ,what) (fail! "watch-lost-on-same-incarnation" what)))
            (kill p1 'done) (kill p2 'done))))
      (sleep-ms 700)
      (display "a watch survives a same-incarnation replacement ok\n")

      ;; ---- new incarnation: the hosted half must go, and stay quiet -------
      (let* ((me self) (r1 (gensym)) (r2 (gensym))
             (victim (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void))))))
             (base (callee-count)))
        (register 'watch-victim-2 victim)
        (let ((p1 (watch-session! "s-inc-old" probe-boot-id 31 9201
                                  'watch-victim-2 me r1)))
          (welcomed! r1 "watch-new-incarnation")
          (armed! base "watch-new-incarnation")
          ;; SAME generation, DIFFERENT boot id: I8a refuses an equal
          ;; generation, so the replacement here can only be I6.
          (let ((p2 (watch-session! "s-inc-new" alt-boot-id 31 #f
                                    'watch-victim-2 me r2)))
            (welcomed! r2 "watch-new-incarnation")
            ;; the old incarnation's registration must be gone
            (let poll ((n 0))
              (unless (= (callee-count) base)
                (if (= n 60)
                    (fail! "stale-registration-outlives-incarnation"
                           (list (callee-count) base))
                    (begin (sleep-ms 50) (poll (+ n 1))))))
            (kill victim 'for-the-cell)
            ;; ⭐ AND IT MUST NOT SPEAK. A stale agent reports by peer NAME,
            ;; so it would write to the new incarnation -- which armed
            ;; nothing and whose mref counter restarts at 1.
            (receive (after 9000 'ok)
              (`#(,@r2 (mdown ,m))
                (fail! "stale-agent-reported-to-new-incarnation" m))
              (`#(,@r2 no-mdown) 'ok)
              (`#(,@r2 ,other) (fail! "watch-new-incarnation" other)))
            (kill p1 'done) (kill p2 'done))))
      (sleep-ms 700)
      (display "a new incarnation drops the old one's hosted watch ok\n")

      ;; ---- a LATE control frame on a superseded same-incarnation link ---
      ;;
      ;; ⭐ THE ONLY CELLS THAT SEPARATE THE TWO ADMISSION PREDICATES.
      ;; The cells above replace the connection and then speak on the NEW
      ;; one, where "is this the current connection" and "is this the
      ;; current incarnation" give the same answer -- so they cannot tell
      ;; the two apart, and mutating the predicate back leaves them green.
      ;; Here the frame under test is dispatched by the link that has
      ;; ALREADY been superseded: connection-identity drops it,
      ;; incarnation admits it.
      ;;
      ;; ⛔ THE ANCHOR MEASURES AN ORDER, BECAUSE AN ORDER IS WHAT IS
      ;; CLAIMED. A first version asked whether an effect had appeared by
      ;; the time the welcome arrived -- one event, not two -- and a
      ;; mistimed run fails GREEN here, not red. What is asserted instead
      ;; is that the WELCOME arrives before the MARKER: the accept side
      ;; installs the replacement before it writes the welcome, and the
      ;; marker is the frame immediately before the one under test, so
      ;; welcome-then-marker means the replacement was in place while the
      ;; link still had the frame under test to dispatch.
      ;;
      ;; ⛔ AND THE VERDICT IS COUNTED PER MREF, NOT READ OFF THE GLOBAL
      ;; COUNT. Every session here is the same peer name, so one cell's
      ;; teardown drops the monitors another cell parked: a global count
      ;; that falls proves nothing about this cell's cancel. Killing the
      ;; watched process and counting the mdowns for THIS mref does.
      (let* ((me self) (r1 (gensym)) (r2 (gensym)) (rm (gensym))
             (victim (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void))))))
             (marker (spawn (lambda ()
                              (receive (after 30000 (void))
                                (`(tail ,m) (send me (vector rm 'tail m)))))))
             (base (callee-count)))
        (register 'watch-victim-3 victim)
        (register 'burst-marker marker)
        (let ((p1 (burst-session! "s-burst-old" probe-boot-id 31 me r1 #f)))
          (welcomed! r1 "late-mon-on-superseded-link")
          (let ((p2 (watch-session! "s-burst-new" probe-boot-id 32 #f
                                    'watch-victim-3 me r2)))
            (send p1 (vector 'go 4000
                             (list (list 'send 'burst-marker (list 'tail 9301))
                                   (list 'mon 'watch-victim-3 9301))))
            (let ((anchor
                    (receive (after 25000 'nothing)
                      (`#(,@r2 welcomed) 'ordered)
                      (`#(,@r2 ,other)
                        (fail! "late-mon-on-superseded-link"
                               (list 'handshake other)))
                      (`#(,@rm tail ,m) 'marker-first))))
              (cond
                ((eq? anchor 'nothing)
                 (fail! "late-mon-on-superseded-link" 'no-welcome-no-marker))
                ((eq? anchor 'marker-first)
                 (display "  💥 INCONCLUSIVE late-mon-on-superseded-link: ")
                 (display "the burst reached its tail before the replacement ")
                 (display "was installed; raise the filler count\n")
                 (kill p1 'done) (kill p2 'done))
                (else
                  (receive (after 20000
                             (fail! "burst-never-reached-tail" 'marker-timeout))
                    (`#(,@rm tail ,m)
                      (unless (eqv? m 9301) (fail! "burst-marker-wrong" m))))
                  (let poll ((n 0))
                    (unless (> (callee-count) base)
                      (if (= n 120)
                          (fail! "late-mon-dropped-on-superseded-link"
                                 (list (callee-count) base))
                          (begin (sleep-ms 50) (poll (+ n 1))))))
                  (kill victim 'for-the-cell)
                  (receive (after 12000
                             (fail! "late-mon-no-verdict" 'verdict-timeout))
                    (`#(,@r2 (mdown ,m))
                      (unless (eqv? m 9301) (fail! "late-mon-wrong-mref" m)))
                    (`#(,@r2 ,what)
                      (fail! "late-mon-not-reported" what)))
                  (kill p1 'done) (kill p2 'done)
                  (sleep-ms 700)
                  (display "a late mon on a superseded link ok\n")))))))

      ;; ---- and the cancel, the other direction of the same predicate ----
      ;; Armed while the connection is current; the CANCEL arrives on the
      ;; link that has since been superseded. The verdict is the number of
      ;; mdowns for this mref after the watched process dies: none if the
      ;; cancel was honoured, one if it was dropped. The superseded link's
      ;; own teardown cannot supply that -- remove-peer! only sweeps when
      ;; the connection it is given is still the peer's current one.
      (let* ((me self) (r1 (gensym)) (r2 (gensym)) (rm (gensym))
             (victim (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void))))))
             (marker (spawn (lambda ()
                              (receive (after 30000 (void))
                                (`(tail ,m) (send me (vector rm 'tail m)))))))
             (base (callee-count)))
        (register 'watch-victim-4 victim)
        (register 'burst-marker-2 marker)
        (let ((p1 (burst-session! "s-dem-old" probe-boot-id 41 me r1
                                  (cons 'watch-victim-4 9401))))
          (welcomed! r1 "late-demon-on-superseded-link")
          (armed! base "late-demon-on-superseded-link")
          ;; p2 does NOT arm: it is here to be the current connection and
          ;; to read what the target writes to the peer name.
          (let ((p2 (mdown-count-session! "s-dem-new" probe-boot-id 42 9401
                                          #f me r2)))
            (send p1 (vector 'go 4000
                             (list (list 'send 'burst-marker-2 (list 'tail 9401))
                                   (list 'demon 9401))))
            (let ((anchor
                    (receive (after 25000 'nothing)
                      (`#(,@r2 welcomed) 'ordered)
                      (`#(,@r2 ,other)
                        (fail! "late-demon-on-superseded-link"
                               (list 'handshake other)))
                      (`#(,@rm tail ,m) 'marker-first))))
              (cond
                ((eq? anchor 'nothing)
                 (fail! "late-demon-on-superseded-link" 'no-welcome-no-marker))
                ((eq? anchor 'marker-first)
                 (display "  💥 INCONCLUSIVE late-demon-on-superseded-link: ")
                 (display "the burst reached its tail before the replacement ")
                 (display "was installed; raise the filler count\n")
                 (kill p1 'done) (kill p2 'done))
                (else
                  (receive (after 20000
                             (fail! "demon-burst-never-reached-tail" 'marker-timeout))
                    (`#(,@rm tail ,m)
                      (unless (eqv? m 9401) (fail! "demon-burst-marker-wrong" m))))
                  (sleep-ms 600)
                  (kill victim 'for-the-cell)
                  (receive (after 20000
                             (fail! "late-demon-on-superseded-link" 'count-timeout))
                    (`#(,@r2 count ,k ,ov)
                      (unless (= k 0)
                        (fail! "late-demon-dropped-on-superseded-link"
                               (list 'mdowns k 'want 0 'overloads ov))))
                    (`#(,@r2 ,other)
                      (fail! "late-demon-on-superseded-link" other)))
                  (kill p1 'done) (kill p2 'done)
                  (sleep-ms 700)
                  (display "a late demon on a superseded link ok\n")))))))

      ;; ---- a retired-but-living agent must not outlive its retirement ----
      ;;
      ;; ⛔ RED FIRST. Retiring a stale record deletes the table entry,
      ;; unlinks it and returns the credit -- and does NOT stop the agent.
      ;; While the sweep ran on every replacement that did not matter: the
      ;; stop was already on its way. Since the sweep became conditional on
      ;; a new incarnation, a same-incarnation replacement leaves the agent
      ;; running, off every table, off every chain, and out of the count.
      ;;
      ;; It is visible from outside because BOTH agents write to the peer
      ;; NAME, which resolves to whichever connection is current: kill the
      ;; watched process and the same mref is reported TWICE. The watcher
      ;; side of a real node would honour only the first -- rmonitors is
      ;; already gone -- so nothing but a raw reader can see the second.
      ;;
      ;; The ceiling is the reason this matters rather than being untidy:
      ;; the credit was returned, so the admission test passes again, and
      ;; the loop is unbounded while the count stays where it started.
      (let* ((me self) (r1 (gensym)) (r2 (gensym))
             (victim (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void))))))
             (base (callee-count)))
        (register 'watch-victim-5 victim)
        (let ((p1 (watch-session! "s-leak-old" probe-boot-id 51 9501
                                  'watch-victim-5 me r1)))
          (welcomed! r1 "retired-agent-outlives-retirement")
          (armed! base "retired-agent-outlives-retirement")
          ;; same incarnation, higher generation: I8a replaces. The new
          ;; session arms THE SAME KEY, which is what drives the stale
          ;; record through the retirement path.
          (let ((p2 (mdown-count-session! "s-leak-new" probe-boot-id 52 9501
                                          'watch-victim-5 me r2)))
            (welcomed! r2 "retired-agent-outlives-retirement")
            (sleep-ms 600)
            (kill victim 'for-the-cell)
            (receive (after 20000
                       (fail! "retired-agent-outlives-retirement" 'count-timeout))
              ;; ⭐ TWO DIMENSIONS, because the fix changes BOTH -- and the
              ;; expected pair was got WRONG the first time, which is why
              ;; it is spelled out here rather than left to be inferred.
              ;;
              ;; Broken: the duplicate installs a second agent beside the
              ;; living one, nothing is refused, and the death is reported
              ;; TWICE -- (2 downs, 0 refusals).
              ;;
              ;; Fixed: a living stale agent does not make way. It is told
              ;; to stop -- so it LEAVES -- and the duplicate is refused.
              ;; Nothing is watching by the time the process dies, so the
              ;; death is reported NOT AT ALL -- (0 downs, 1 refusal). The
              ;; peer is not left guessing: the refusal is itself an
              ;; (mdown <mref> overload), which its own fire-remote-down!
              ;; turns into a remote-down, and the API says a later
              ;; attempt can succeed.
              ;;
              ;; ⛔ Counting only the downs would call BOTH trees wrong in
              ;; the same direction, and would also pass a node that
              ;; silently dropped the duplicate. The refusal is the
              ;; present-tense witness that it answered.
              ;; ⛔ THIS PAIR HAS BEEN WRONG TWICE, and the second time is
              ;; the one worth keeping: it was set to (0 downs, 1 refusal)
              ;; because that is what the code did once a living stale
              ;; record stopped making way. ⭐ But that behaviour was itself
              ;; the product of judging identity by CONNECTION -- an
              ;; expectation derived from an implementation, which pins a
              ;; defect down as the specification. With identity judged by
              ;; run, a repeat from the same run is what the protocol says
              ;; it is: free. The watch survives, reports once, and
              ;; nothing is refused.
              (`#(,@r2 count ,k ,ov)
                (unless (and (= k 1) (= ov 0))
                  (fail! "retired-agent-outlives-retirement"
                         (list 'downs k 'want 1 'refusals ov 'want 0))))
              (`#(,@r2 ,other)
                (fail! "retired-agent-outlives-retirement" other)))
            ;; ⭐ A THIRD PROPERTY, ASSERTED SEPARATELY: the permits come
            ;; back. Written as "no more than we started with" rather than
            ;; equality because every session here is the same peer name,
            ;; so another cell's teardown can push this below base -- and
            ;; a criterion that fails on someone else's cleanup is not
            ;; measuring this cell.
            (let poll ((n 0))
              (unless (<= (callee-count) base)
                (if (= n 120)
                    (fail! "retired-agent-still-counted"
                           (list (callee-count) base))
                    (begin (sleep-ms 50) (poll (+ n 1))))))
            (kill p1 'done) (kill p2 'done))))
      (sleep-ms 700)
      (display "a retired agent does not outlive its retirement ok\n")

      ;; ---- a REPEAT on a superseded link must not revoke the watch -----
      ;;
      ;; ⛔ RED FIRST, AND THE DEFECT IS SILENT. The protocol says so in
      ;; as many words a few hundred lines up: "A REPEAT OF THIS EXACT
      ;; REQUEST IS FREE". A peer may therefore send one, and a peer that
      ;; sent it just before a replacement has it dispatched by the link
      ;; that has since been superseded.
      ;;
      ;; Admission now judges by INCARNATION, so that repeat is let in --
      ;; but identity is still judged by CONNECTION, so the record it
      ;; finds looks stale, and the answer is to stop an agent that was
      ;; doing its job. The refusal is written back on the connection the
      ;; frame arrived on, which the replacement already closed, and
      ;; remove-peer! sweeps only for the connection that is current, so
      ;; no noconnection is produced either.
      ;;
      ;; ⭐ WHAT THE PEER SEES IS NOTHING AT ALL: its rmonitors row is
      ;; still there, the agent that would have reported is gone, and the
      ;; process it is watching can die unremarked. That is why the
      ;; verdict asserts BOTH numbers -- a watch that reports once, and
      ;; no refusal -- rather than only that something arrived.
      (let* ((me self) (r1 (gensym)) (r2 (gensym)) (rm (gensym))
             (victim (spawn (lambda () (receive (after 30000 (void)) (`#(stop) (void))))))
             (marker (spawn (lambda ()
                              (receive (after 30000 (void))
                                (`(tail ,m) (send me (vector rm 'tail m)))))))
             (base (callee-count)))
        (register 'watch-victim-6 victim)
        (register 'burst-marker-3 marker)
        (let ((p1 (burst-session! "s-rep-old" probe-boot-id 61 me r1
                                  (cons 'watch-victim-6 9601))))
          (welcomed! r1 "repeat-on-superseded-link-revokes-watch")
          (armed! base "repeat-on-superseded-link-revokes-watch")
          (let ((p2 (mdown-count-session! "s-rep-new" probe-boot-id 62 9601
                                          #f me r2)))
            (send p1 (vector 'go 4000
                             (list (list 'send 'burst-marker-3 (list 'tail 9601))
                                   ;; the repeat: the SAME triple it armed
                                   (list 'mon 'watch-victim-6 9601))))
            (let ((anchor
                    (receive (after 25000 'nothing)
                      (`#(,@r2 welcomed) 'ordered)
                      (`#(,@r2 ,other)
                        (fail! "repeat-on-superseded-link-revokes-watch"
                               (list 'handshake other)))
                      (`#(,@rm tail ,m) 'marker-first))))
              (cond
                ((eq? anchor 'nothing)
                 (fail! "repeat-on-superseded-link-revokes-watch"
                        'no-welcome-no-marker))
                ((eq? anchor 'marker-first)
                 (display "  💥 INCONCLUSIVE repeat-on-superseded-link: ")
                 (display "the burst reached its tail before the replacement ")
                 (display "was installed; raise the filler count\n")
                 (kill p1 'done) (kill p2 'done))
                (else
                  (receive (after 20000
                             (fail! "repeat-burst-never-reached-tail" 'marker-timeout))
                    (`#(,@rm tail ,m)
                      (unless (eqv? m 9601) (fail! "repeat-burst-marker-wrong" m))))
                  (sleep-ms 600)
                  (kill victim 'for-the-cell)
                  (receive (after 20000
                             (fail! "repeat-on-superseded-link-revokes-watch"
                                    'count-timeout))
                    (`#(,@r2 count ,k ,ov)
                      (unless (and (= k 1) (= ov 0))
                        (fail! "repeat-on-superseded-link-revokes-watch"
                               (list 'downs k 'want 1 'refusals ov 'want 0))))
                    (`#(,@r2 ,other)
                      (fail! "repeat-on-superseded-link-revokes-watch" other)))
                  (kill p1 'done) (kill p2 'done)
                  (sleep-ms 700)
                  (display "a repeat on a superseded link keeps the watch ok\n"))))))))


    (display "CV cells passed\n")
    (display "S2 registrar/container cells passed\n")
    ;; ==== end S2 ========================================================

    ;; ==== end S1 ========================================================

    ;; dial side. A challenge with no version slot must be refused
    ;; WITHOUT answering (red before the change: the dialer sent hello).
    ;; A mismatched version must also be a close -- green before the
    ;; change too (the old arity check refused it); it exists to stay
    ;; red-capable AFTER the arity moves to 3, when version equality is
    ;; the only thing left refusing it.
    (let ((round (box #f)) (me self))
      (define fake-port 18085)
      (define l
        (tcp-listen! "127.0.0.1" fake-port 16
          (lambda (c)
            (let ((pid (spawn
                         (lambda ()
                           (let ((tag (unbox round)))
                             (define (await-close!)
                               (receive (after 4000
                                          (send me (vector 'fake tag 'timeout)))
                                 (`#(tcp-data ,_)
                                   (send me (vector 'fake tag 'answered)))
                                 (`#(tcp-eof) (send me (vector 'fake tag 'closed)))
                                 (`#(tcp-error ,_)
                                   (send me (vector 'fake tag 'closed)))))
                             (case tag
                               ((legacy v999 v1 badnonce colon-nonce upper-nonce)
                                (tcp-write! c (frame-bytes
                                                (case tag
                                                  ((legacy) (list 'challenge "aaaabbbb"))
                                                  ((v999) (list 'challenge "aaaabbbb" 999))
                                                  ((v1) (list 'challenge "aaaabbbb" 1))
                                                  ((colon-nonce)
                                                   ;; v4 shape, so the version gate
                                                   ;; cannot refuse it first: what is
                                                   ;; on trial is the nonce alphabet
                                                   (list 'challenge colon-nonce 4
                                                         probe-boot-id))
                                                  ((upper-nonce)
                                                   ;; 32 hex digits, but UPPERCASE.
                                                   ;; Injectivity does not require
                                                   ;; refusing it -- uppercase has no
                                                   ;; colon, so it makes no HMAC
                                                   ;; alias. This refusal is a
                                                   ;; DELIBERATE narrowing, and it is
                                                   ;; legitimate only because "32
                                                   ;; lowercase hex" is NORMATIVE
                                                   ;; wire syntax, not an accident of
                                                   ;; what we emit: under lockstep,
                                                   ;; exact-match wire (version,
                                                   ;; shape, and now nonce alphabet),
                                                   ;; there is no third-party sender
                                                   ;; to lock out -- a peer that
                                                   ;; sent uppercase would be a
                                                   ;; different protocol, refused the
                                                   ;; way a wrong version is. The
                                                   ;; normative spelling is pinned in
                                                   ;; the wire doc, not just here;
                                                   ;; this cell is what turns red if
                                                   ;; someone widens the gate to "any
                                                   ;; colon-free string" with nothing
                                                   ;; else to say the margin shrank.
                                                   (list 'challenge
                                                         "0123456789ABCDEF0123456789ABCDEF"
                                                         4 probe-boot-id))
                                                  (else (list 'challenge 123 4
                                                              probe-boot-id))))
                                            #f)
                                (await-close!))
                               ((kat)
                                ;; the dialer's OWN hello, held against the
                                ;; v4 spec: arity 7, name as a STRING, the
                                ;; proof recomputed here from the specified
                                ;; formula (it binds our boot-id, which this
                                ;; fixture chose, so it cannot be a literal
                                ;; digest any more -- the KAT literal above
                                ;; still anchors the formula itself), and a
                                ;; dial-gen that is a non-negative integer.
                                (tcp-write! c (frame-bytes
                                                (list 'challenge kat-nonce 4
                                                      probe-boot-id))
                                            #f)
                                (let ((d (read-frame-or-closed "kat-hello")))
                                  (send me (vector 'fake tag
                                    (cond ((symbol? d) d)
                                          ((not (and (list? d) (= (length d) 7)))
                                           'hello-shape)
                                          ((not (eq? (car d) 'hello)) 'hello-tag)
                                          ((not (equal? (cadr d) "a")) 'hello-name)
                                          ((not (string? (list-ref d 5)))
                                           'hello-bootid)
                                          ((not (and (integer? (list-ref d 6))
                                                     (>= (list-ref d 6) 0)))
                                           'hello-dialgen)
                                          ((not (equal? (caddr d)
                                                        (v4-proof-d
                                                          kat-nonce "a"
                                                          (list-ref d 5)
                                                          (number->string
                                                            (list-ref d 6))
                                                          "z6" probe-boot-id)))
                                           'hello-proof-off-spec)
                                          ((not (string? (cadddr d)))
                                           'hello-nonce-b)
                                          ((not (eqv? (car (cddddr d)) 4))
                                           'hello-version)
                                          (else 'good))))))
                               ((unbound-welcome)
                                ;; speak the CURRENT protocol right up to the
                                ;; last frame, then bind nothing: the welcome
                                ;; proof uses the pre-versioning formula. The
                                ;; dialer must refuse it -- a build whose
                                ;; welcome check does not bind the version
                                ;; accepts and keeps the link open (timeout
                                ;; here), which is the red this cell owns.
                                ;; a compliant nonce: this fixture tests
                                ;; the welcome-proof binding, so the dialer
                                ;; must get PAST the nonce gate and send a
                                ;; hello. A short nonce here would be
                                ;; refused before that and the cell would
                                ;; never reach what it exists to check.
                                (tcp-write! c (frame-bytes
                                                (list 'challenge kat-nonce 4
                                                      probe-boot-id))
                                            #f)
                                (let ((d (read-frame-or-closed
                                           "unbound-welcome-hello")))
                                  (if (or (eq? d 'closed) (not (pair? d))
                                          (< (length d) 4))
                                      (send me (vector 'fake tag 'no-hello))
                                      (begin
                                        (tcp-write! c
                                          (frame-bytes
                                            (list 'welcome 'z3
                                              (pre-versioning-proof
                                                (cadddr d) 'z3)))
                                          #f)
                                        (await-close!))))))
                             (tcp-close! c))))))
              (conn-set-owner! c pid)
              (tcp-read-start! c)))))
      (define (expect-round! tag peer label wanted)
        (set-box! round tag)
        (node-connect! peer "127.0.0.1" fake-port)
        (let wait ()
          (receive (after 8000 (fail! label 'no-outcome))
            (`#(fake ,t ,what)
              (if (eq? t tag)
                  (unless (eq? what wanted) (fail! label what))
                  (wait)))))               ; straggler from another round
        (node-disconnect! peer))
      ;; The two version refusals must SPEAK. A dialer retries a
      ;; configured peer forever, so a refusal it never mentions is an
      ;; outage with no author: capture stderr across both rounds -- the
      ;; legacy line must name the pre-versioning peer, the mismatch
      ;; line both versions. Swapping the global error port is safe
      ;; here; nothing else in this window writes to it.
      (define errbuf (open-output-string))
      (let ((old (current-error-port)))
        (current-error-port errbuf)
        (expect-round! 'legacy 'z "dialer-answers-unversioned-challenge" 'closed)
        (expect-round! 'v999 'z2 "dialer-accepts-alien-version" 'closed)
        (sleep-ms 100)
        (current-error-port old))
      (let ((txt (get-output-string errbuf)))
        (unless (has-substr? txt "pre-2")
          (fail! "dial-refusal-silent-on-legacy-peer" txt))
        (unless (and (has-substr? txt "z2") (has-substr? txt "999"))
          (fail! "dial-refusal-silent-on-version-mismatch" txt)))
      ;; ---- the proof concatenation must be injective ------------------
      ;; hmac input is nonce:name:version. If a RECEIVED nonce may carry
      ;; a colon, the field boundary is ambiguous and the digest of an
      ;; honest node can be replayed under another name: feeding node a
      ;; the nonce "X:evil" yields HMAC(secret, "X:evil:a:2"), which is
      ;; byte-identical to what an attacker calling itself evil:a owes
      ;; for the real nonce "X". Measured, not argued -- both sides are
      ;; f987cbdb... for secret "test-mesh-secret".
      ;;
      ;; The load-bearing fix is at the RECEIVING end of each nonce: a
      ;; nonce that is not exactly 32 lowercase hex digits is refused
      ;; before it can be signed. This cell owns the dialer's end -- a
      ;; dialer that signs a structured nonce hands the attacker the
      ;; oracle, so the refusal must happen BEFORE any hello goes out.
      (expect-round! 'colon-nonce 'z8 "dialer-signs-structured-nonce" 'closed)
      (expect-round! 'upper-nonce 'z9 "dialer-accepts-uppercase-hex-nonce" 'closed)
      (expect-round! 'v1 'z4 "dialer-accepts-version-1" 'closed)
      (expect-round! 'badnonce 'z5 "dialer-accepts-nonstring-nonce" 'closed)
      (expect-round! 'unbound-welcome 'z3
                     "dialer-accepts-unbound-welcome-proof" 'closed)
      (expect-round! 'kat 'z6 "dialer-hello-off-spec" 'good)
      ;; A diagnostic that raises must not take the CLOSE with it. The
      ;; report runs on the way past a guard whose next clause swallows
      ;; everything so the connector can retry -- so a raise inside it
      ;; is invisible AND skips the tcp-close! that follows, leaking one
      ;; connection per retry, forever. Judged from the far end: the
      ;; fake acceptor sees EOF if the close happened, and times out if
      ;; it did not. (The port is unusable for the width of this round;
      ;; anything else printing here would raise too. The window is
      ;; narrow and nothing else in this suite prints.)
      (let ((old (current-error-port)))
        (current-error-port
          (make-custom-textual-output-port "exploding"
            (lambda (str start count) (raise 'diagnostic-exploded))
            #f #f (lambda () (void))))
        (guard (e (#t (current-error-port old) (raise e)))
          (expect-round! 'v999 'z7 "close-lost-when-diagnostic-raises" 'closed))
        (current-error-port old))
      (tcp-stop-listen! l))
    (display "dialer wire dialect pinned ok\n")

    ;; ---- post-auth wire shapes that must drop the link -------------------
    ;; Spoken from an AUTHENTICATED fake peer: these frames only reach
    ;; dispatch on a live link. Both cells expect the fail-closed answer
    ;; -- a close, not a reply.
    (let ((drop-probe!
            (lambda (label peer-name frame)
              (let ((me self) (ref (gensym)))
                (spawn
                  (lambda ()
                    (let ((c (handshake-as! peer-name label)))
                      (tcp-write! c (frame-bytes frame) #f)
                      (let ((d (read-frame-or-closed label)))
                        (send me (vector ref d))
                        (tcp-close! c)))))
                (receive (after 8000 (fail! label 'probe-timeout))
                  (`#(,@ref ,what)
                    (unless (eq? what 'closed) (fail! label what))))))))
      ;; The OLD 4-element call, from a peer that authenticated as v3.
      ;; The fail-closed rule owns it now: an unknown shape drops the
      ;; link. A build whose dispatch still accepts the pre-v3 arity
      ;; ANSWERS -- a reply frame comes back and this cell reads it
      ;; instead of the close.
      (drop-probe! "v3-refuses-4-element-call" 'stale-caller
                   (list 'call 'nonesuch 1 'x))
      ;; ...and the arity is pinned from BOTH sides: a six-element call
      ;; must drop too, or "refuses four" is just "requires at least
      ;; five" wearing a stricter label.
      (drop-probe! "v3-admits-6-element-call" 'stale-caller6
                   (list 'call 'nonesuch 3 'x 5000 'extra))
      ;; The timeout slot is validated at dispatch, BEFORE the serving
      ;; process is spawned. Validated inside the server instead, the
      ;; raise kills that process quietly and the link stays up -- this
      ;; cell then times out rather than reading the close, which is
      ;; exactly its red. One probe per input kind: the wrong TYPE, a
      ;; zero, a negative, and the inexact integer 2.0 -- the last is
      ;; what a validator that spells "integer?" but forgets "exact?"
      ;; admits, and (min 2.0 cap) then quietly contaminates arithmetic
      ;; downstream.
      (drop-probe! "call-timeout-slot-not-validated" 'stale-caller2
                   (list 'call 'nonesuch 2 'x "soon"))
      (drop-probe! "call-timeout-zero" 'stale-caller3
                   (list 'call 'nonesuch 4 'x 0))
      (drop-probe! "call-timeout-negative" 'stale-caller4
                   (list 'call 'nonesuch 5 'x -5))
      (drop-probe! "call-timeout-inexact" 'stale-caller5
                   (list 'call 'nonesuch 6 'x 2.0)))
    (display "stale call arities and malformed timeouts drop the link ok\n")

    ;; ---- the outgoing call frame, held against the wire ------------------
    ;; Everything above spoke TO this node; this cell reads what the node
    ;; itself EMITS for an rcall. Without it, "the timeout crosses the
    ;; wire" is only ever shown by two copies of this implementation
    ;; agreeing with each other -- a fixed slot of the right magnitude
    ;; would pass every behavioral cell. The frame must be exactly
    ;; (call <reg> <ref> <msg> <the caller's own timeout>), and the
    ;; reply routed back by ref must reach the caller as the value.
    (let* ((me self) (ref (gensym))
           ;; the acceptor INSTALLS the peer after writing welcome, so
           ;; the fake peer being ready does not mean this node can
           ;; address it yet -- the watch is armed before the spawn and
           ;; the call gated on node-up below, or the rcall races
           ;; install-peer! to a noconnection
           (armed (monitor-node 'callee))
           (callee-pid
        (spawn
          (lambda ()
            (let ((c (handshake-as! 'callee "outgoing-call-frame")))
            (let ((d (read-frame-or-closed "outgoing-call-frame")))
              (cond
                ((symbol? d) (send me (vector ref d)))
                ((not (and (list? d) (= (length d) 5)))
                 (send me (vector ref 'call-arity d)))
                ((not (eq? (car d) 'call))
                 (send me (vector ref 'call-tag d)))
                ((not (eq? (cadr d) 'echo))
                 (send me (vector ref 'call-reg d)))
                ((not (and (integer? (caddr d)) (exact? (caddr d))))
                 (send me (vector ref 'call-ref d)))
                ((not (equal? (cadddr d) (vector 'q)))
                 (send me (vector ref 'call-msg d)))
                ((not (eqv? (car (cddddr d)) 7321))
                 (send me (vector ref 'call-timeout-slot d)))
                (else
                 (tcp-write! c (frame-bytes
                                 (list 'reply (caddr d) (list 'ok 42)))
                             #f)
                 (send me (vector ref 'frame-good)))))
              ;; hold the link open until the caller has its answer; an
              ;; early close would fail the call for the wrong reason
              (receive (after 6000 'done) (`#(callee-done) 'ok))
              (tcp-close! c))))))
      (receive (after 8000 (fail! "outgoing-call-frame" 'no-node-up))
        (`#(node-up callee) 'ok))
      (demonitor-node 'callee)
      (spawn (lambda ()
               (send me (vector ref 'rcall
                 (guard (e (#t (list 'raised e)))
                   (rcall 'callee 'echo (vector 'q) 7321))))))
      (let wait ((frame? #f) (value? #f))
        (if (and frame? value?)
            (send callee-pid (vector 'callee-done))
            (receive (after 8000 (fail! "outgoing-call-frame" 'timeout
                                        frame? value?))
              (`#(,@ref frame-good) (wait #t value?))
              (`#(,@ref rcall ,v)
                (unless (equal? v 42) (fail! "outgoing-call-reply" v))
                (wait frame? #t))
              (`#(,@ref ,bad ,d) (fail! "outgoing-call-frame" bad d))))))
    (display "outgoing call frame carries the caller's timeout ok\n")

    ;; ---- outbound backpressure is per connection -------------------------
    ;; A peer that stops reading makes every frame to it queue in this
    ;; process; without a ceiling the queue grows as fast as senders can
    ;; call rsend -- unbounded memory on a control link -- and the only
    ;; exit was the 60s silence deadline. The ceiling is on IN-FLIGHT
    ;; BYTES PER CONNECTION, and crossing it must behave like a link
    ;; failure PROMPTLY: node-down within 8s, far below both the 15s
    ;; heartbeat and the 60s deadline, so neither of the old clocks can
    ;; be what passes this cell.
    (let ((me self) (ref (gensym))
          (zero-stats '((conns . 0) (bytes . 0))))
      ;; The baseline must be QUIESCENT, and quiescent here is the
      ;; literal zero alist -- which also pins the export's shape (a
      ;; stub answering '() or #f would fail this equality, not pass
      ;; vacuously). Earlier cells' connections are still tearing down
      ;; when this one starts, so a snapshot baseline made both deltas
      ;; below unreadable; and cleanup that never converges to zero is
      ;; itself the leak the final assertion owns, so waiting loses no
      ;; discrimination.
      ;;
      ;; The wait must OUTLAST A HANDSHAKE DEADLINE, not just a close
      ;; callback: the ceiling cell's challenged connections hold their
      ;; sockets and are only closed by the acceptor's 5s handshake
      ;; timeout, and everything between that cell and this one runs in
      ;; well under a second -- so up to ~5s of those entries are still
      ;; due here on a healthy build. (Measured, not assumed: the four
      ;; entries clear within 100ms of the deadline, and an earlier 2s
      ;; bound here read that tail as a leak.)
      (let poll ((n 0))
        (let ((s (node-outbound-stats)))
          (unless (equal? s zero-stats)
            (if (= n 200)
                (fail! "outbound-entries-linger-at-baseline" s)
                (begin (sleep-ms 50) (poll (+ n 1)))))))
      ;; armed BEFORE the peer exists: node-up is the gate that says
      ;; this node can address it (the acceptor installs the peer after
      ;; writing welcome, so the holder's 'ready alone races that)
      (monitor-node 'slowpeer)
      (let ((holder
              (spawn
                (lambda ()
                  (let ((c (handshake-as! 'slowpeer "backpressure-slow-reader")))
                    ;; stop reading at the KERNEL level: read-stop parks
                    ;; the fd, so the socket buffers fill and stay full.
                    ;; Merely never receiving would let libuv keep
                    ;; draining them into this process's mailbox.
                    (tcp-read-stop! c)
                    (send me (vector ref 'ready))
                    ;; hold the socket open across the flood: the far
                    ;; end closing is the event under test
                    (receive (after 20000 'give-up)
                      (`#(release) 'ok))
                    (tcp-close! c))))))
        (receive (after 8000 (fail! "backpressure-slow-reader" 'no-handshake))
          (`#(,@ref ready) 'ok))
        (receive (after 8000 (fail! "backpressure-slow-reader" 'no-node-up))
          (`#(node-up slowpeer) 'ok))
        ;; entry on first write, observably: the handshake made this
        ;; node WRITE on that conn (challenge, welcome), so its entry
        ;; exists before any flood -- exactly one conn above the
        ;; quiescent zero
        (let ((s (node-outbound-stats)))
          (unless (= (cdr (assq 'conns s)) 1)
            (fail! "outbound-entry-not-created-on-write" s)))
        ;; a pending rcall and a live remote monitor ride this link; the
        ;; backpressure close must fail BOTH over exactly as a link drop
        ;; would. Armed before the flood, judged after the node-down.
        (spawn (lambda ()
                 (send me (vector 'bp-rcall
                   (guard (e ((and (vector? e)
                                   (eq? (vector-ref e 0) 'rcall-error))
                              (vector-ref e 1)))
                     (rcall 'slowpeer 'svc 'x 30000)
                     'no-raise)))))
        (monitor-remote 'slowpeer 'never-there)
        (node-set-limits! #f #f #f 65536)
        ;; ~16 KiB serialized per frame, 600 frames ~ 10 MiB attempted:
        ;; far past any plausible kernel buffering plus the 64 KiB
        ;; ceiling (the margin is the portability argument -- loopback
        ;; buffers autotune, but not to ten megabytes). The loop stops
        ;; at the first refused send (the link died under it); sending
        ;; everything with the link still open means the count was
        ;; never kept.
        (let ((bv (make-bytevector 8192 7)))
          (let loop ((k 0))
            (cond
              ((= k 600) (fail! "backpressure-never-tripped"))
              ((rsend 'slowpeer 'sink bv) (loop (+ k 1)))
              (else 'tripped))))
        (receive (after 8000 (fail! "backpressure-no-node-down"))
          (`#(node-down slowpeer) 'ok))
        (receive (after 4000 (fail! "backpressure-pending-rcall-kept"))
          (`#(bp-rcall ,r)
            (unless (eq? r 'noconnection)
              (fail! "backpressure-pending-rcall-reason" r))))
        (receive (after 4000 (fail! "backpressure-monitor-kept"))
          (`#(remote-down slowpeer never-there ,r)
            (unless (eq? r 'noconnection)
              (fail! "backpressure-monitor-reason" r))))
        (demonitor-node 'slowpeer)
        (send holder (vector 'release))
        (node-set-limits! #f #f #f 16777216)
        ;; the accounting died with the connection: entries and in-flight
        ;; bytes return exactly to the quiescent zero (canceled writes
        ;; subtracted, the conn's entry dropped). Polled, not slept:
        ;; close-callback timing is the OS's, not this cell's.
        (let poll ((n 0))
          (let ((s (node-outbound-stats)))
            (unless (equal? s zero-stats)
              (if (= n 40)
                  (fail! "backpressure-accounting-residue" s)
                  (begin (sleep-ms 50) (poll (+ n 1)))))))))
    (display "outbound backpressure closes a slow reader, accounting clean ok\n")

    ;; ---- the ceiling has a trigger that inbound traffic cannot mute ------
    ;; The charge-side check fires only when this node WRITES. A
    ;; connection can sit over the ceiling with no further outbound
    ;; traffic -- and a peer that keeps SENDING resets the link's tick
    ;; timer, so even the ping that would recharge and trip never runs.
    ;; The inbound path must therefore check too: the very traffic that
    ;; mutes the tick becomes the trigger. Armed here without any kill:
    ;; flood under a high limit (charge never trips), then LOWER the
    ;; limit -- the connection is now over a ceiling nobody has checked
    ;; -- and let the peer send one frame that provokes no reply. Only
    ;; an inbound-side check can be what closes it.
    (let ((me self) (ref (gensym)))
      (monitor-node 'slowpeer2)
      (let ((holder
              (spawn
                (lambda ()
                  (let ((c (handshake-as! 'slowpeer2 "inbound-trigger")))
                    (tcp-read-stop! c)
                    (send me (vector ref 'ready))
                    (let wait ()
                      (receive (after 30000 'give-up)
                        (`#(poke)
                          ;; NOT a whole frame: a length header with no
                          ;; body. A complete frame would also trigger
                          ;; the check, but a fragment is the stronger
                          ;; probe -- bytes that never finish a datum
                          ;; still restart the link's tick timer, so a
                          ;; check that runs only after a parsed frame
                          ;; can be muted by exactly this dribble. The
                          ;; check must fire on ARRIVAL, not on parse.
                          (tcp-write! c (string->utf8 "64\n") #f)
                          (wait))
                        (`#(release) 'ok)))
                    (tcp-close! c))))))
        (receive (after 8000 (fail! "inbound-trigger" 'no-handshake))
          (`#(,@ref ready) 'ok))
        (receive (after 8000 (fail! "inbound-trigger" 'no-node-up))
          (`#(node-up slowpeer2) 'ok))
        ;; ~2 MB in flight against the default 16 MiB ceiling: every send
        ;; must be accepted and the link must stay up
        (let ((bv (make-bytevector 8192 5)))
          (do ((k 0 (+ k 1))) ((= k 130))
            (unless (rsend 'slowpeer2 'sink bv)
              (fail! "inbound-trigger-flood-refused" k))))
        ;; now the ceiling drops below what is already in flight
        (node-set-limits! #f #f #f 65536)
        (send holder (vector 'poke))
        (receive (after 8000 (fail! "inbound-trigger-no-close"))
          (`#(node-down slowpeer2) 'ok))
        (demonitor-node 'slowpeer2)
        (send holder (vector 'release))
        (node-set-limits! #f #f #f 16777216)
        (let poll ((n 0))
          (let ((s (node-outbound-stats)))
            (unless (equal? s '((conns . 0) (bytes . 0)))
              (if (= n 200)
                  (fail! "inbound-trigger-accounting-residue" s)
                  (begin (sleep-ms 50) (poll (+ n 1)))))))))
    (display "inbound traffic triggers the outbound ceiling ok\n")

    ;; ACCEPTED RESIDUE of the backpressure and backoff cells, named so
    ;; absence reads as decision, not oversight. Internal program points
    ;; never reach the wire or an export and are pinned by review and by
    ;; the change contract, not here: the increment landing strictly
    ;; before the write call, the limit checked on the increment side,
    ;; the completion closing over its own total, the single-outbound-
    ;; path architecture, connection-keyed (not name-keyed) accounting,
    ;; the 'outbound-backpressure close reason, and which hook removes
    ;; the entry. Likewise the connector's USE of reconnect-delay --
    ;; attempt counting and its reset after an authenticated link -- a
    ;; wall-clock observation of reconnect spacing would be flaky where
    ;; this suite is deterministic. The 16 MiB limit and 60000 serve cap
    ;; are exercised only as explicitly set values, never as defaults.
    ;;
    ;; Later review rounds added more of the same family, each pinned by
    ;; review and by the mechanism comment beside it: the charge, the
    ;; write, and its completion registration running under one
    ;; interrupt-disable (a kill between them is not injectable from out
    ;; here); the link-stop message carrying its connection so a late
    ;; one cannot kill the connector's NEXT link (nothing external can
    ;; forge or time that message); the backoff wait surviving a
    ;; straggler dial completion (a timing observation); the reset
    ;; threshold -- an authenticated link must outlive the delay the
    ;; connector was about to wait -- measured only as a reconnect
    ;; cadence (and measured, not assumed: reverting an earlier, weaker
    ;; threshold to plain authentication turned no cell red); and the
    ;; state-recheck inside each interrupt-disabled region before a
    ;; handle is used (the close-vs-use interleave is not reachable from
    ;; a test that cannot place a kill).

    
    ;; rsend to an unknown node: #f, no crash
    (unless (eq? #f (rsend 'nowhere 'svc 'x))
      (fail! "rsend-unknown"))
    (display "rsend to unknown node ok\n")

    ;; Handshake frames carry names inside the 4 KiB pre-auth frame
    ;; ceiling, so a name's length is wire-normative: refused at
    ;; configuration time, not at the first hello that overflows and
    ;; presents as a peer that mysteriously never comes up.
    (unless (guard (e ((assertion-violation? e) #t) (#t #f))
              (node-connect! (string->symbol (make-string 5000 #\n))
                             "127.0.0.1" 1)
              #f)
      (fail! "unbounded-peer-name-accepted"))
    (display "oversized peer name refused at node-connect! ok\n")

    ;; rsend to self is a local send
    (rsend 'a 'main (vector 'loopback 1))
    (receive (after 1000 (fail! "self-rsend"))
      (`#(loopback 1) 'ok))
    (display "rsend to self ok\n")

    ;; A missing local name completes through the self-monitor agent's
    ;; immediate path. Exercise a burst so agent publication and cleanup
    ;; can be preempted at every point without losing or duplicating DOWN.
    (do ((i 0 (+ i 1))) ((= i 64))
      (monitor-remote 'a 'missing-local-service))
    (let loop ((left 64))
      (unless (zero? left)
        (receive (after 2000 (fail! "self-monitor-noproc-timeout" left))
          (`#(remote-down a missing-local-service ,reason)
            (unless (eq? reason 'noproc)
              (fail! "self-monitor-noproc-reason" reason))
            (loop (- left 1))))))
    (receive (after 50 'ok)
      (`#(remote-down a missing-local-service ,reason)
        (fail! "self-monitor-duplicate-down" reason)))
    ;; Delivery was never the broken part -- retention was. The immediate
    ;; noproc path returned without removing its own caller-agents entry,
    ;; so 64 dead agent pids stayed rooted with nothing to ever sweep them.
    ;; Nothing above can see that; the table sizes can.
    (let ((stats (node-monitor-stats)))
      (for-each
        (lambda (k)
          (let ((n (cdr (assq k stats))))
            (unless (zero? n)
              (fail! "self-monitor-retained" k n))))
        '(rmonitors caller-agents owner-agents)))
    (display "missing self monitors clean up exactly once ok\n")

    ;; The arming step itself: the rmonitors entry and the owner agent
    ;; must appear in ONE atomic region. The entry roots the caller's pcb,
    ;; and when that caller dies the agent is the only thing that clears
    ;; it (the other paths that delete an entry -- a target-side down, a
    ;; link drop, an explicit demonitor -- all require the monitor to
    ;; still be running somewhere). So a kill landing between two separate
    ;; regions leaves an entry with nothing left to release it -- on a
    ;; mesh that stays up, forever.
    ;;
    ;; Aiming a kill at the gap between two adjacent statements does not
    ;; work, but the reason it does not is also the way in: a kill only
    ;; lands where the victim yields, so a yield inside the gap is a
    ;; yield another runnable process can SEE. This watches for that
    ;; state rather than aiming at it -- rmonitors above owner-agents,
    ;; read from ONE snapshot. Two calls would read the second count
    ;; before an arming and the first count after it, manufacturing the
    ;; very imbalance under test. The watcher spins rather than sleeps:
    ;; sleeping makes it unrunnable, and an imbalance nobody is scheduled
    ;; to observe passes unseen. set-timer walks the victim's preemption
    ;; point across the call -- a tick budget that expires inside an
    ;; atomic region is delivered when the outermost one exits, which in
    ;; a split arming is exactly the gap.
    ;;
    ;; Two things keep the reading unambiguous. The victim PARKS instead
    ;; of returning, for longer than a round is allowed to last, so its
    ;; own teardown cannot be in flight while it is watched: teardown
    ;; shows the same imbalance for a benign reason, since the owner
    ;; agent deletes its own table entry first and the rmonitors entry
    ;; second. And every round starts from a measured baseline, so the
    ;; previous round's teardown cannot be read as this round's arming.
    ;; With both, an imbalance can only be the split -- and killing the
    ;; victim there and finding the entry still present is the leak
    ;; itself rather than an inference about it.
    ;;
    ;; Each round must prove it ran the arming at all: it ends on a
    ;; caught gap or on an observed entry, never on a clock. k is swept
    ;; because a tick budget expires at compiler-inserted trap points,
    ;; whose spacing is a property of the build; the range is empirical
    ;; -- a tree with the two regions split apart is caught here at k=5,
    ;; deterministically -- and is not a claim that 60 rounds cover every
    ;; point on every build.
    (let* ((tables '(rmonitors caller-agents owner-agents))
           (at-baseline?
             (lambda ()
               (let ((s (node-monitor-stats)))
                 (for-all (lambda (k) (zero? (cdr (assq k s)))) tables))))
           (await-baseline!
             (lambda (label k)
               (let loop ((n 0))
                 (cond ((at-baseline?) 'ok)
                       ((= n 200) (fail! label k (node-monitor-stats)))
                       (else (sleep-ms 10) (loop (+ n 1))))))))
      (do ((k 1 (+ k 1))) ((> k 60))
        (await-baseline! "arming-window-baseline" k)
        (let* ((me self)
               (v (spawn (lambda ()
                           (send me (vector 'gap-ready))
                           (receive (`#(gap-go) 'ok))
                           (set-timer k)
                           (monitor-remote 'a 'main)
                           ;; park past the round's own bound: a victim
                           ;; that returned would tear the monitor down
                           ;; and produce the benign imbalance
                           (receive (after 10000 'done))))))
          ;; the victim has RUN before its budget is set -- a round that
          ;; killed a process still sitting in the run queue would test
          ;; nothing while looking exactly like a round that passed
          (receive (after 2000 (fail! "arming-window-victim-never-ran" k))
            (`#(gap-ready) 'ok))
          (send v (vector 'gap-go))
          (let ((deadline (+ (now-ms) 3000)))
            (let poll ()
              (let* ((s (node-monitor-stats))
                     (r (cdr (assq 'rmonitors s)))
                     (o (cdr (assq 'owner-agents s))))
                (cond
                  ((> r o)
                   (kill v 'caught-in-gap)
                   (sleep-ms 200)
                   (let ((s2 (node-monitor-stats)))
                     (if (> (cdr (assq 'rmonitors s2)) 0)
                         (fail! "arming-window-leaked" k s s2)
                         ;; the state itself should not exist on a merged
                         ;; region; seeing it and then losing the race to
                         ;; the kill is still a finding, not a pass
                         (fail! "arming-window-imbalance-without-leak"
                                k s s2))))
                  ((> r 0) 'this-round-armed)
                  ((> (now-ms) deadline)
                   (fail! "arming-window-round-never-armed" k s))
                  (else (poll))))))
          (kill v 'round-over)))
      (await-baseline! "arming-window-residue" 'end))
    (display "arming window: entry and agent inseparable under kill ok\n")

    ;; wrong secret: must never come up
    (spawn-child! "evil" "wrong-secret")
    (monitor-node 'evil)
    (receive (after 2500 'ok)
      (`#(node-up evil) (fail! "bad-secret-accepted")))
    (when (memq 'evil (node-peers)) (fail! "bad-secret-in-peers"))
    (display "wrong secret rejected ok\n")

    ;; the real peer comes up
    (spawn-child! "b" secret)
    (receive (after 10000 (fail! "node-up-timeout"))
      (`#(node-up b) 'ok))
    (unless (memq 'b (node-peers)) (fail! "peers-missing-b"))
    (display "handshake + node-up ok\n")

    ;; ---- a restart replays what was not finished, and ONLY that ---------
    ;; The deliverer is a supervised process now, so "it was delivered"
    ;; and "it is off the queue" are two moments with a gap between them,
    ;; and a successor picks up whatever sits in that gap. This cell is
    ;; about the other side of that promise: an event that finished must
    ;; not come back.
    ;;
    ;; The at-least-once half is cheap to satisfy by replaying everything,
    ;; and a suite that only checks "it arrived" would be perfectly happy
    ;; with a dispatcher that redelivers the whole queue on every restart
    ;; -- a legacy subscriber has no token and no number, so for it a
    ;; second copy is indistinguishable from a second event.
    ;;
    ;; The kill lands AFTER delivery completed: node-up for b was received
    ;; above, so that event is done and gone. Anything arriving now was
    ;; invented by the restart.
    ;;
    ;; ⚠️ NO DEMONSTRATED DISCRIMINATING POWER, and saying so is the
    ;; point. A completed event is unlinked from its head, so under this
    ;; implementation there is nothing left for a successor to replay --
    ;; the failure this cell describes is not reachable by mutating the
    ;; code as it stands. The one mutation that produces a repeat at all
    ;; (never marking an event done) is caught several cells earlier, by
    ;; the orphan chain refusing to empty, so its red never reaches here.
    ;;
    ;; It is kept as a guard against the cheap way to satisfy at least
    ;; once: replaying more than the unfinished head after a restart. A
    ;; legacy subscriber carries neither token nor number, so for it a
    ;; second copy and a second event are the same message, and a suite
    ;; that only ever checks "it arrived" would accept either. That the
    ;; guard cannot fail today is a fact about today's implementation,
    ;; not evidence that the property is being enforced.
    (let ((d (whereis 'igropyr-node-dispatcher)))
      (unless d (fail! "s4-dispatcher-not-registered"))
      (kill d 'restart-under-test)
      ;; the warden has to put a DIFFERENT process under the same name;
      ;; asserting only that the name resolves would pass while the dead
      ;; pid is still registered
      (let wait ((i 0))
        (let ((d2 (whereis 'igropyr-node-dispatcher)))
          (cond ((and d2 (not (eq? d2 d))) 'ok)
                ((> i 400) (fail! "s4-dispatcher-not-restarted"))
                (else (sleep-ms 25) (wait (+ i 1))))))
      (receive (after 1500 'ok)
        (`#(node-up b) (fail! "s4-restart-replayed-a-completed-event"))
        (`#(node-down b) (fail! "s4-restart-invented-a-down"))))
    (display "a dispatcher restart replays nothing that finished ok\n")

    ;; round-trip: extended payload must cross bit-intact both ways
    (let ((payload (vector 'blob (bytevector 0 127 255) 3.25 1/3 '(a . b))))
      (unless (rsend 'b 'svc (vector 'add1 41 payload))
        (fail! "rsend-b"))
      (receive (after 5000 (fail! "roundtrip-timeout"))
        (`#(ans ,n ,p)
          (unless (= n 42) (fail! "roundtrip-value" n))
          (unless (equal? p payload) (fail! "payload-fidelity" p)))))
    (display "rsend round-trip + payload fidelity ok\n")

    ;; The write side must never EMIT a frame its own read side would
    ;; refuse: an oversized payload is an error at the call site, not a
    ;; dead link for every other user of it. ~18 MB serialized against
    ;; the 8 MiB frame ceiling. Red before the gate existed: the frame
    ;; went out whole and the peer's length-header check dropped the
    ;; link -- one caller's mistake, everyone's outage.
    (let ((huge (make-bytevector 9000000 7)))
      (unless (guard (e (#t #t))
                (rsend 'b 'svc (vector 'add1 1 huge))
                #f)
        (fail! "oversized-frame-sent"))
      ;; refused locally: the link is unharmed and still carries traffic
      (unless (rsend 'b 'svc (vector 'add1 41 (vector)))
        (fail! "oversized-frame-broke-link"))
      (receive (after 5000 (fail! "oversized-frame-link-dead"))
        (`#(ans 42 ,p) 'ok)))
    (display "oversized frame refused locally, link unharmed ok\n")

    ;; ordering: a burst arrives in send order
    (do ((i 0 (+ i 1))) ((= i 100))
      (rsend 'b 'svc (vector 'add1 i (vector))))
    (let loop ((expect 1))
      (unless (= expect 101)
        (receive (after 5000 (fail! "ordering-timeout" expect))
          (`#(ans ,n ,p)
            (unless (= n expect) (fail! "ordering" expect n))
            (loop (+ expect 1))))))
    (display "in-order burst ok\n")

    ;; The ceiling must NOT act on a healthy link. Replies pace the
    ;; flow, so true in-flight bytes stay near one frame -- but the
    ;; cumulative volume crosses the limit many times over. That
    ;; separates the two accountings: an implementation that forgets to
    ;; subtract completed writes accumulates phantom in-flight bytes and
    ;; closes this link mid-loop; the correct one never comes near the
    ;; ceiling. (~16 KiB serialized per frame each way, 50 rounds ~ 800
    ;; KiB through a 256 KiB limit.)
    (node-set-limits! #f #f #f 262144)
    (let ((payload (make-bytevector 8192 3)))
      (do ((i 0 (+ i 1))) ((= i 50))
        (unless (rsend 'b 'svc (vector 'add1 i payload))
          (fail! "backpressure-false-trip-send" i))
        (receive (after 5000 (fail! "backpressure-false-trip" i))
          (`#(ans ,n ,p) 'ok))))
    (node-set-limits! #f #f #f 16777216)
    (display "outbound backpressure spares paced traffic ok\n")

    ;; rcall: synchronous cross-node call to a gen-server on b
    (unless (= 49 (rcall 'b 'calc (vector 'square 7)))
      (fail! "rcall-value"))
    (display "rcall round-trip ok\n")

    ;; The timeout goes ON THE WIRE, so rcall refuses to send what no
    ;; peer could use: a non-fixnum timeout is an error at the call
    ;; site. The write side is deliberately narrower than the read side
    ;; (which still takes any positive exact integer and caps it) --
    ;; without this gate the call is refused at the far end by dropping
    ;; the whole link, and every other caller on it pays for one typo.
    (let ((got (guard (e ((assertion-violation? e) 'refused)
                         (#t (list 'wrong-condition e)))
                 (rcall 'b 'calc (vector 'square 2) (expt 2 62))
                 'no-raise)))
      (unless (eq? got 'refused) (fail! "rcall-huge-timeout-sent" got))
      ;; refused LOCALLY: the link is unharmed and the next call rides it
      (unless (= 9 (rcall 'b 'calc (vector 'square 3)))
        (fail! "rcall-huge-timeout-broke-link")))
    (display "rcall refuses a non-fixnum timeout locally ok\n")

    ;; rcall to a gen-server that raises -> rcall-error, not a hang
    (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'rcall-error))
                          (vector-ref e 1)))
                 (rcall 'b 'calc (vector 'boom))
                 'no-raise)))
      (unless (memq got '(unavailable server-died call-failed))
        (fail! "rcall-error-kind" got)))
    (display "rcall remote failure -> rcall-error ok\n")

    ;; rcall to a missing server -> rcall-error (no hang)
    (let ((got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'rcall-error)) #t))
                 (rcall 'b 'nonesuch (vector 'x) 2000)
                 #f)))
      (unless got (fail! "rcall-missing")))
    (display "rcall missing server -> rcall-error ok\n")

    ;; ---- the caller's timeout crosses the wire ---------------------------
    ;; The v3 call frame carries the caller's timeout and the serving
    ;; side adopts it (capped) for its own gen-server-call. Before that,
    ;; the server used its local default: a caller patient beyond 5s was
    ;; answered (error ...) by a peer that had no idea how long the
    ;; caller was willing to wait. The slow handler sleeps 6.5s -- past
    ;; the old default, well inside this call's 10s -- so only a build
    ;; that ships the timeout in the frame can return the value.
    (let ((t0 (now-ms)))
      ;; guarded so the red has this cell's name: on a build that lets
      ;; the server default win, the rcall RAISES (the server answered
      ;; (error timeout) at its 5s default) rather than returning a
      ;; wrong value, and an unguarded raise would exit as a panic
      ;; instead of a reading
      (unless (eq? 'slept (guard (e (#t (list 'raised e)))
                            (rcall 'b 'slowcalc (vector 'slow) 10000)))
        (fail! "rcall-timeout-not-in-frame"))
      (let ((dt (- (now-ms) t0)))
        ;; the value must come from the handler actually finishing:
        ;; under 6s something answered early, over 9.5s something other
        ;; than the 6.5s sleep was the clock
        (when (or (< dt 6000) (> dt 9500))
          (fail! "rcall-slow-elapsed" dt))))
    (display "rcall timeout crosses the wire ok\n")

    ;; ...and a SHORT timeout still cuts the caller loose locally: the
    ;; frame's copy caps the server, it must never extend the caller.
    ;; let*, not let: the clock must be read BEFORE the call -- plain
    ;; let leaves the evaluation order unspecified, and this build ran
    ;; the rcall first, timing a completed call at zero
    (let* ((t0 (now-ms))
           (got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'rcall-error))
                           (vector-ref e 1)))
                  (rcall 'b 'slowcalc (vector 'slow) 1500)
                  'no-raise)))
      (unless (eq? got 'timeout) (fail! "rcall-short-timeout" got))
      (let ((dt (- (now-ms) t0)))
        (when (> dt 3000) (fail! "rcall-short-timeout-elapsed" dt))
        ;; ...and a LOWER bound: without it, a build that answers with a
        ;; synthetic immediate timeout reads as a working 1.5s clock
        (when (< dt 1200) (fail! "rcall-short-timeout-too-early" dt))))
    (display "rcall caller timeout still local ok\n")

    ;; The serve side's own cap is the other arm of the min(), and the
    ;; cap is the SERVER's setting -- so it is lowered on b, through the
    ;; fixture, not here. The same patient 10s call now comes back an
    ;; error in ~2s: the server adopted min(10000, 2000). A build that
    ;; takes the frame value alone serves the full sleep and returns
    ;; 'slept past the caller's 10s -- either the value or the elapsed
    ;; time turns this red.
    (rsend 'b 'svc (vector 'set-serve-cap 2000))
    (sleep-ms 200)
    (let* ((t0 (now-ms))
           (got (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'rcall-error))
                           (vector-ref e 1)))
                  (rcall 'b 'slowcalc (vector 'slow) 10000)
                  'no-raise)))
      (when (eq? got 'no-raise) (fail! "serve-cap-ignored"))
      (let ((dt (- (now-ms) t0)))
        ;; 4000 excludes both the old 5s server default and the uncapped
        ;; 6.5s handler (the previous cell's handler may still be asleep
        ;; when this call queues; the capped gen-server-call times out in
        ;; the queue just the same)
        (when (> dt 4000) (fail! "serve-cap-elapsed" dt))))
    (rsend 'b 'svc (vector 'set-serve-cap 60000))
    (sleep-ms 100)
    ;; b's slowcalc drains its queued sleeps for a while yet; nothing
    ;; between here and the quit touches 'slowcalc, and the child's
    ;; safety net was raised to 60s to cover these cells
    (display "serve-side cap arms the min ok\n")

    ;; distributed pubsub: a publish on node a must reach a subscriber
    ;; on node b (b relays it back as #(heard ...))
    (sleep-ms 300)                       ; let b's subscribe settle
    (publish 'room "cross-node-hello")
    (receive (after 5000 (fail! "dist-pubsub-timeout"))
      (`#(heard ,m)
        (unless (equal? m "cross-node-hello") (fail! "dist-pubsub-payload" m))))
    (display "distributed pubsub fan-out ok\n")

    ;; Remote monitor state is owned by its caller. Short-lived callers
    ;; must release target-side slots instead of leaving permanent watches.
    (do ((i 0 (+ i 1))) ((= i 2))
      (spawn (lambda () (monitor-remote 'b 'svc))))
    (sleep-ms 600)
    (let ((m (monitor-remote 'b 'svc)))
      (receive (after 400 'ok)
        (`#(remote-down b svc overload)
          (fail! "dead-monitor-callers-leaked-slots")))
      (demonitor-remote m))
    (display "dead monitor callers release remote slots ok\n")

    ;; monitor-remote: watch b's 'watched process, kill it, observe the
    ;; real exit reason cross the wire
    (monitor-remote 'b 'watched)
    (rsend 'b 'svc (vector 'kill-watched 'crash-reason))
    (receive (after 5000 (fail! "remote-down-timeout"))
      (`#(remote-down b watched ,reason)
        (unless (eq? reason 'crash-reason) (fail! "remote-down-reason" reason))))
    (display "monitor-remote -> remote-down with reason ok\n")

    ;; A reason the wire refuses must DEGRADE to 'exit, not take the
    ;; link with it. The serialization raise happens on the target's
    ;; first mdown attempt; the critical write path must let that raise
    ;; reach mon-agent's degradation guard rather than reading it as a
    ;; submission failure and dropping the link -- a build that swallows
    ;; both delivers noconnection here instead of 'exit.
    (monitor-remote 'b 'watched2)
    (rsend 'b 'svc (vector 'kill-watched-raw))
    (receive (after 5000 (fail! "exit-degrade-timeout"))
      (`#(remote-down b watched2 ,reason)
        (unless (eq? reason 'exit) (fail! "exit-degrade-reason" reason))))
    ;; ...and the LINK SURVIVED IT, said directly rather than inferred:
    ;; the proposition is "a refused reason does not take the link", and
    ;; reason='exit is only its consequence
    (unless (memq 'b (node-peers)) (fail! "exit-degrade-took-link"))
    (display "unserializable reason degrades to 'exit, link intact ok\n")

    ;; watching a name that isn't registered -> immediate noproc
    (monitor-remote 'b 'watched)                 ; now dead
    (receive (after 5000 (fail! "noproc-timeout"))
      (`#(remote-down b watched ,r) (unless (eq? r 'noproc) (fail! "noproc" r))))
    (display "monitor-remote missing name -> noproc ok\n")

    ;; demonitor: a demonitored watch must NOT fire when b dies
    (let ((m (monitor-remote 'b 'svc)))
      (demonitor-remote m))
    (receive (after 400 'ok)
      (`#(remote-down b svc ,_) (fail! "demonitor-still-fired")))
    (display "demonitor-remote silences the watch ok\n")

    ;; a live watch fires noconnection when the node's link drops
    (monitor-remote 'b 'svc)

    ;; peer exits -> node-down, remote-down(noconnection), rsend turns #f
    (rsend 'b 'svc (vector 'quit))
    (let wait ((down? #f) (noconn? #f))
      (unless (and down? noconn?)
        (receive (after 10000 (fail! "node-down-timeout" down? noconn?))
          (`#(node-down b) (wait #t noconn?))
          (`#(remote-down b svc ,r)
            (unless (eq? r 'noconnection) (fail! "noconnection" r))
            (wait down? #t)))))
    (when (memq 'b (node-peers)) (fail! "peers-still-b"))
    (unless (eq? #f (rsend 'b 'svc 'x)) (fail! "rsend-after-down"))
    (display "node-down + remote-down(noconnection) + rsend #f ok\n")

    ;; The wire whitelist holds on THIS node too. rsend used to skip the
    ;; check for its own node name, so a payload no peer would accept -- a
    ;; procedure, a port -- was delivered locally and refused everywhere
    ;; else: the same task succeeded or failed depending on which node a
    ;; round robin happened to pick, and the local case is exactly where
    ;; such a payload gets written and never noticed.
    (register 'wire-probe self)
    (let ((delivered (box #f)))
      (spawn (lambda ()
               (receive (after 1000 'done)
                 (`#(got ,x) (set-box! delivered #t)))))
      (unless (guard (e (#t #t)) (rsend (node-self) 'wire-probe (vector 'got car)) #f)
        (fail! "local rsend accepted a procedure payload"))
      ;; ...and an ordinary payload still goes through
      (unless (rsend (node-self) 'wire-probe (vector 'got "text"))
        (fail! "local rsend refused a wire-safe payload"))
      (receive (after 500 'done) (`#(got ,x) 'ok)))
    (display "local rsend enforces the wire whitelist ok\n")

    (display "ALL NODE TESTS PASSED\n")
    (exit 0)))
