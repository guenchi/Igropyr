#!chezscheme
;;; (igropyr node) integration test: two real OS processes.
;;;   - handshake + node-up
;;;   - rsend round-trip with extended-whitelist payload fidelity
;;;     (vector, bytevector, flonum, ratio through the wire and back)
;;;   - node-down when the peer exits
;;;   - a peer with the WRONG secret never becomes a node
;;;   - rsend to a disconnected node returns #f; to self delivers locally

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
;; the exact bytes "0123456789abcdef0123456789abcdef:a:2" with the key
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
  "6dce4923ad94cc2b347c9872217cd026328c9733e924a29506ada60f46621b99")
(unless (equal? (versioned-proof kat-nonce 'a 2) kat-hello-proof)
  (fail! "versioned-proof-helper-diverged-from-known-answer"))

(define (has-substr? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring s i (+ i m)) sub) #t)
            (else (loop (+ i 1)))))))

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (node-set-limits! 64 2)
    (start-pubsub!)
    (register 'main self)
    (monitor-node 'b)

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
                nb32 2)))
      ;; version slot 999 with a proof that IS valid for version 2: an
      ;; acceptor that skips the explicit hello-version check but does
      ;; verify the bound proof would welcome this one
      (probe-hello! "acceptor-ignores-hello-version"
        (lambda (nonce)
          (list 'hello 'relic3 (versioned-proof nonce 'relic3 2)
                nb32 999)))
      ;; the acceptor's end of the injectivity rule, both halves.
      ;; A nonce-b carrying the separator is what the attacker WOULD
      ;; sign next; a name carrying it is what the attacker CLAIMS.
      ;; Note the second one's proof is genuinely correct for the
      ;; string it hashes -- refusing it cannot come from the proof
      ;; check, only from the name.
      (probe-hello! "acceptor-signs-structured-nonce-b"
        (lambda (nonce)
          (list 'hello 'relic4 (versioned-proof nonce 'relic4 2)
                colon-nonce 2)))
      (probe-hello! "acceptor-admits-colon-in-claimed-name"
        (lambda (nonce)
          (list 'hello (string->symbol "evil:a")
                (versioned-proof nonce (string->symbol "evil:a") 2)
                nb32 2))))
    (display "acceptor refuses unversioned/unbound/mislabeled hello ok\n")

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
                  ((not (and (list? d) (= (length d) 3)))
                   (send me (vector ref 'challenge-shape)))
                  ((not (eq? (car d) 'challenge))
                   (send me (vector ref 'challenge-tag)))
                  ((not (string? (cadr d)))
                   (send me (vector ref 'challenge-nonce-not-string)))
                  ((not (eqv? (caddr d) 2))
                   (send me (vector ref 'challenge-version)))
                  (else
                   (tcp-write! c (frame-bytes
                                   (list 'hello 'wirepeer
                                         (versioned-proof (cadr d) 'wirepeer 2)
                                         nb32 2))
                               #f)
                   (let ((w (read-frame-or-closed "wirepeer-welcome")))
                     (send me (vector ref
                       (cond ((symbol? w) w)   ; closed / closed-with-bytes
                             ((not (and (list? w) (= (length w) 3)))
                              'welcome-shape)
                             ((not (eq? (car w) 'welcome)) 'welcome-tag)
                             ((not (eq? (cadr w) 'a)) 'welcome-name)
                             ((not (equal? (caddr w)
                                           (versioned-proof nb32 'a 2)))
                              'welcome-proof-not-bound)
                             (else 'good))))))))
              (tcp-close! c))
            (`#(tcp-connect-failed ,e) (send me (vector ref 'no-connect))))))
      (receive (after 8000 (fail! "wirepeer-interop" 'probe-timeout))
        (`#(,@ref ,what)
          (unless (eq? what 'good) (fail! "wirepeer-interop" what)))))
    (display "specified dialect accepted end to end ok\n")

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
                                                   (list 'challenge colon-nonce 2))
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
                                                         2))
                                                  (else (list 'challenge 123 2))))
                                            #f)
                                (await-close!))
                               ((kat)
                                ;; the dialer's OWN hello, held against the
                                ;; known answer: the proof must be the
                                ;; literal digest, the name its node name,
                                ;; the frame exactly five long, version 2
                                (tcp-write! c (frame-bytes
                                                (list 'challenge kat-nonce 2))
                                            #f)
                                (let ((d (read-frame-or-closed "kat-hello")))
                                  (send me (vector 'fake tag
                                    (cond ((symbol? d) d)
                                          ((not (and (list? d) (= (length d) 5)))
                                           'hello-shape)
                                          ((not (eq? (car d) 'hello)) 'hello-tag)
                                          ((not (eq? (cadr d) 'a)) 'hello-name)
                                          ((not (equal? (caddr d) kat-hello-proof))
                                           'hello-proof-off-spec)
                                          ((not (string? (cadddr d)))
                                           'hello-nonce-b)
                                          ((not (eqv? (car (cddddr d)) 2))
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
                                                (list 'challenge kat-nonce 2))
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

    ;; rsend to an unknown node: #f, no crash
    (unless (eq? #f (rsend 'nowhere 'svc 'x))
      (fail! "rsend-unknown"))
    (display "rsend to unknown node ok\n")

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

    ;; round-trip: extended payload must cross bit-intact both ways
    (let ((payload (vector 'blob (bytevector 0 127 255) 3.25 1/3 '(a . b))))
      (unless (rsend 'b 'svc (vector 'add1 41 payload))
        (fail! "rsend-b"))
      (receive (after 5000 (fail! "roundtrip-timeout"))
        (`#(ans ,n ,p)
          (unless (= n 42) (fail! "roundtrip-value" n))
          (unless (equal? p payload) (fail! "payload-fidelity" p)))))
    (display "rsend round-trip + payload fidelity ok\n")

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

    ;; rcall: synchronous cross-node call to a gen-server on b
    (unless (= 49 (rcall 'b 'calc (vector 'square 7)))
      (fail! "rcall-value"))
    (display "rcall round-trip ok\n")

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
