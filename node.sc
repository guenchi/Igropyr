#!chezscheme
;;; (igropyr node) -- node-to-node links: distribution phase 1.
;;;
;;; Connects igropyr instances (other cores via loopback, other machines
;;; via the network) into a mesh where a process on one node can message
;;; a REGISTERED NAME on another:
;;;
;;;   (node-start! 'a secret 4100)              ; identity + listener
;;;   (node-connect! 'b "10.0.0.2" 4100)        ; outbound, auto-reconnect
;;;   (rsend 'b 'worker-pool #(job 42))         ; -> (whereis 'worker-pool) on b
;;;   (monitor-node 'b)                         ; -> #(node-up b) / #(node-down b)
;;;
;;; Semantics mirror Erlang distribution deliberately:
;;;   - addressing is by registered name, never by raw pid (pids are
;;;     memory objects; names survive restarts, pids don't)
;;;   - rsend is fire-and-forget: #t means handed to a live link, #f
;;;     means no link -- delivery is never confirmed. Use monitor-node
;;;     (and application-level replies) for failure handling.
;;;   - messages between one pair of nodes arrive in send order (one
;;;     TCP connection per pair)
;;;   - rsend to the OWN node name is a plain local send (location
;;;     transparency)
;;;
;;; Wire protocol: length-prefixed frames -- "<decimal-len>\n<datum>" --
;;; carrying one EXTENDED-mode s-expression each (vectors, bytevectors
;;; and finite flonums cross intact; see (igropyr sexpr)). A frame that
;;; fails to parse, an oversized frame, or an unknown shape drops the
;;; connection: a confused peer is a dead peer, never a guessed-at one.
;;;
;;; Handshake (before anything else): mutual HMAC-SHA1 challenge/response
;;; on a shared secret. The secret itself never crosses the wire and a
;;; recorded proof cannot be replayed against a fresh nonce:
;;;   acceptor -> (challenge <nonce-a>)
;;;   dialer   -> (hello <name> <hmac(secret, nonce-a:name)> <nonce-b>)
;;;   acceptor -> (welcome <name> <hmac(secret, nonce-b:name)>)
;;;
;;; SECURITY: the dist port is FULL CONTROL of the node -- anyone on it
;;; can message any registered process, including supervisors. The
;;; listener binds 127.0.0.1 unless told otherwise, and there is no TLS:
;;; across machines, keep it on a private network (WireGuard, VPC).
;;;
;;; Duplicate connections (both sides dialing at once) are resolved
;;; deterministically: the connection whose DIALER has the smaller node
;;; name survives; both ends apply the same rule, so they converge.

(library (igropyr node)
  (export node-start! node-connect! node-disconnect! node-self
          rsend rcall monitor-node demonitor-node node-peers
          monitor-remote demonitor-remote)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr sexpr)
          (igropyr gen-server)
          (only (igropyr websocket) sha1))

  (define max-frame 8388608)        ; 8 MiB per datum
  (define handshake-timeout-ms 5000)
  (define tick-ms 15000)            ; heartbeat interval
  (define dead-ms 60000)            ; silence longer than this = dead link
  (define reconnect-ms 3000)

  ;; ---- identity ------------------------------------------------------

  (define self-name #f)             ; symbol, set by node-start!
  (define self-secret #f)           ; bytevector

  (define (node-self) self-name)

  ;; ---- shared tables --------------------------------------------------
  ;; Mutated from several green processes: every multi-step update runs
  ;; with interrupts disabled so preemption cannot interleave them (the
  ;; same discipline as the actor registry).

  ;; node-name -> #(conn link-pid dialer-name)
  (define peers (make-eq-hashtable))
  ;; node-name -> connector pid (owns the reconnect loop)
  (define connectors (make-eq-hashtable))
  ;; node-name -> list of watcher pids
  (define watchers (make-eq-hashtable))
  ;; rcall ref -> waiting caller pid (this node is the caller)
  (define pending (make-eqv-hashtable))
  (define rcall-counter 0)
  (define (next-rcall-ref!)
    (atomically (set! rcall-counter (+ rcall-counter 1)) rcall-counter))

  ;; cross-node process monitors. On the WATCHER node:
  ;;   rmonitors: mref -> #(caller node name)   (for demonitor + the
  ;;              noconnection synthesized when the link to node drops)
  ;;   caller-agents: mref -> agent pid         (self-watch only)
  ;; On the TARGET node:
  ;;   callee-agents: (peer . mref) -> agent pid  (one local monitor per
  ;;              remote watch; killed on demon). Keyed by (peer . mref)
  ;;              because mref is chosen by the watcher's own counter, so
  ;;              two watchers collide on it -- the pair namespaces them.
  (define rmonitors (make-eqv-hashtable))
  (define caller-agents (make-eqv-hashtable))
  (define callee-agents (make-hashtable equal-hash equal?))
  (define mref-counter 0)
  (define (next-mref!)
    (atomically (set! mref-counter (+ mref-counter 1)) mref-counter))

  (define-syntax atomically
    (syntax-rules ()
      ((_ body ...) (with-interrupts-disabled body ...))))

  (define (peer-entry name)
    (atomically (hashtable-ref peers name #f)))

  (define (live-entry name)
    (let ((e (peer-entry name)))
      (and e (eq? (conn-state (vector-ref e 0)) 'open) e)))

  (define (node-peers)
    (filter live-entry
            (vector->list (atomically (hashtable-keys peers)))))

  ;; ---- node up/down notification --------------------------------------

  (define (monitor-node name)
    (atomically
      (let ((l (hashtable-ref watchers name '())))
        (unless (memq self l)
          (hashtable-set! watchers name (cons self l)))))
    (void))

  (define (demonitor-node name)
    (atomically
      (hashtable-set! watchers name
        (remq self (hashtable-ref watchers name '()))))
    (void))

  (define (notify! name what)               ; what: node-up | node-down
    (let ((l (atomically (hashtable-ref watchers name '()))))
      (for-each
        (lambda (p)
          (if (process-alive? p)
              (send p (vector what name))
              (demonitor-dead! name p)))
        l)))

  (define (demonitor-dead! name p)
    (atomically
      (hashtable-set! watchers name
        (remq p (hashtable-ref watchers name '())))))

  ;; ---- framing ----------------------------------------------------------

  (define empty-bv (make-bytevector 0))

  (define (bv-append a b)
    (let ((la (bytevector-length a)) (lb (bytevector-length b)))
      (cond
        ((fx= la 0) b)
        ((fx= lb 0) a)
        (else (let ((r (make-bytevector (fx+ la lb))))
                (bytevector-copy! a 0 r 0 la)
                (bytevector-copy! b 0 r la lb)
                r)))))

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (fx- end start))))
      (bytevector-copy! bv start r 0 (fx- end start))
      r))

  ;; one frame: decimal length, newline, body. Serialized here, written
  ;; as one writev, so frames from different processes never interleave.
  (define (write-frame! c datum)
    (let* ((body (string->utf8 (sexpr->string-extended datum)))
           (head (string->utf8
                   (string-append (number->string (bytevector-length body))
                                  "\n"))))
      (tcp-writev! c (list head body) #f)))

  ;; Try to split one frame off buf.
  ;; -> (values datum rest) | (values 'more #f) ; raises 'protocol on junk
  (define (parse-frame buf)
    (let ((n (bytevector-length buf)))
      (let scan ((i 0) (len 0))
        (cond
          ((fx> i 8) (raise 'protocol))            ; length header too long
          ((fx>= i n) (values 'more #f))
          ((fx= (bytevector-u8-ref buf i) 10)      ; newline
           (when (or (fx= i 0) (> len max-frame)) (raise 'protocol))
           (let ((total (fx+ i 1 len)))
             (if (< n total)
                 (values 'more #f)
                 (values (string->sexpr-extended
                           (utf8->string (bv-sub buf (fx+ i 1) total)))
                         (bv-sub buf total n)))))
          (else
           (let ((b (bytevector-u8-ref buf i)))
             (unless (and (fx>= b 48) (fx<= b 57)) (raise 'protocol))
             (scan (fx+ i 1) (+ (* len 10) (fx- b 48)))))))))

  ;; Block (in the calling process) until one whole frame arrives.
  ;; -> (values datum rest) ; raises 'closed / 'timeout / 'protocol /
  ;; the sexpr-error vector on a malformed datum
  (define (read-frame c buf timeout)
    (let-values (((d rest) (parse-frame buf)))
      (if (eq? d 'more)
          (receive (after timeout (raise 'timeout))
            (`#(tcp-data ,bv) (read-frame c (bv-append buf bv) timeout))
            (`#(tcp-eof) (raise 'closed))
            (`#(tcp-error ,e) (raise 'closed))
            (`#(node-stop) (raise 'stop)))
          (values d rest))))

  ;; ---- HMAC-SHA1 handshake proofs ----------------------------------------

  (define (hmac-sha1 key msg)
    (let* ((block 64)
           (k (if (> (bytevector-length key) block) (sha1 key) key))
           (k+ (make-bytevector block 0))
           (ipad (make-bytevector block))
           (opad (make-bytevector block)))
      (bytevector-copy! k 0 k+ 0 (bytevector-length k))
      (do ((i 0 (fx+ i 1))) ((fx= i block))
        (let ((b (bytevector-u8-ref k+ i)))
          (bytevector-u8-set! ipad i (fxxor b #x36))
          (bytevector-u8-set! opad i (fxxor b #x5c))))
      (sha1 (bv-append opad (sha1 (bv-append ipad msg))))))

  (define hex-digits "0123456789abcdef")
  (define (bytevector->hex bv)
    (let* ((n (bytevector-length bv)) (s (make-string (* n 2))))
      (do ((i 0 (fx+ i 1))) ((fx= i n) s)
        (let ((b (bytevector-u8-ref bv i)))
          (string-set! s (fx* i 2) (string-ref hex-digits (fxsrl b 4)))
          (string-set! s (fx+ (fx* i 2) 1)
                       (string-ref hex-digits (fxand b 15)))))))

  (define (random-hex nbytes)
    (call-with-port (open-file-input-port "/dev/urandom")
      (lambda (p)
        (let ((bv (get-bytevector-n p nbytes)))
          (unless (and (bytevector? bv) (= (bytevector-length bv) nbytes))
            (raise 'entropy))                   ; short read: fail closed
          (bytevector->hex bv)))))

  (define (proof nonce name)
    (bytevector->hex
      (hmac-sha1 self-secret
        (string->utf8 (string-append nonce ":" (symbol->string name))))))

  ;; constant-time compare: an attacker probing digests byte by byte
  ;; learns nothing from response timing
  (define (proof=? a b)
    (and (string? a) (string? b)
         (fx= (string-length a) (string-length b))
         (let loop ((i 0) (acc 0))
           (if (fx= i (string-length a))
               (fx= acc 0)
               (loop (fx+ i 1)
                     (fxior acc (fxxor (char->integer (string-ref a i))
                                       (char->integer (string-ref b i)))))))))

  ;; ---- peer install / removal ---------------------------------------------
  ;; The tie-break: of two simultaneous connections between the same
  ;; pair, keep the one dialed by the smaller node name. Both ends see
  ;; the same dialer for the same physical connection, so both converge
  ;; on the same survivor.

  (define (name<? a b)
    (string<? (symbol->string a) (symbol->string b)))

  ;; -> #t if this conn was installed, #f if it lost the tie-break
  (define (install-peer! name c dialer)
    (let ((won?
           (atomically
             (let ((e (hashtable-ref peers name #f)))
               (if (and e (eq? (conn-state (vector-ref e 0)) 'open))
                   (if (name<? dialer (vector-ref e 2))
                       (begin                    ; new conn wins: evict old
                         (send (vector-ref e 1) (vector 'node-stop))
                         (hashtable-set! peers name (vector c self dialer))
                         'replaced)
                       #f)                       ; old conn wins
                   (begin
                     (hashtable-set! peers name (vector c self dialer))
                     #t))))))
      (when (eq? won? #t) (notify! name 'node-up))   ; a replacement is not a new up
      (and won? #t)))

  ;; idempotent: only removes the entry if it still belongs to this conn
  (define (remove-peer! name c)
    (let ((mine?
           (atomically
             (let ((e (hashtable-ref peers name #f)))
               (and e (eq? (vector-ref e 0) c)
                    (begin (hashtable-delete! peers name) #t))))))
      (tcp-close! c)
      (when mine?
        (fail-monitors-for! name)          ; DOWN(noconnection) for watchers
        (notify! name 'node-down))))

  ;; ---- the link: one process per live connection ---------------------------

  ;; the four wire shapes a link may carry (peer is the node at the far
  ;; end of c). Anything else is a confused peer -> drop the link.
  (define (dispatch! c peer d)
    (cond
      ;; (send ,reg-name ,msg) -> deliver to that registered process
      ((and (frame? d 'send 3) (symbol? (cadr d)))
       (let ((p (whereis (cadr d))))
         (when p (send p (caddr d)))))          ; unregistered name: drop
      ;; (call ,reg-name ,ref ,msg) -> serve a cross-node rcall
      ((and (frame? d 'call 4) (symbol? (cadr d)))
       (let ((reg (cadr d)) (ref (caddr d)) (m (cadddr d)))
         (spawn (lambda () (serve-rcall! peer reg ref m)))))
      ;; (reply ,ref ,result) -> route back to the waiting rcall caller,
      ;; but only if the reply arrives from the node that call targeted
      ;; (a ref is bound to its node, so one peer can't answer a call
      ;; the caller sent to another)
      ((frame? d 'reply 3)
       (let ((ref (cadr d)) (result (caddr d)))
         (let ((slot (atomically (hashtable-ref pending ref #f))))
           (when (and slot (eq? (vector-ref slot 1) peer))
             (send (vector-ref slot 0) (vector 'rcall-reply ref result))))))
      ;; (mon ,name ,mref ,origin) -> watch our local reg-name for origin.
      ;; Register the agent in callee-agents SYNCHRONOUSLY (before it can
      ;; run), so a demon frame that follows on this same link always
      ;; finds it -- the agent spawn alone would race the demon.
      ((and (frame? d 'mon 4) (symbol? (cadr d)) (symbol? (cadddr d)))
       (let* ((name (cadr d)) (mref (caddr d)) (origin (cadddr d))
              (key (cons peer mref)))
         (atomically
           (hashtable-set! callee-agents key
             (spawn (lambda () (mon-agent origin key name)))))))
      ;; (mdown ,mref ,reason) -> the watched process/link is gone; only
      ;; honor it from the node the monitor actually targets
      ((frame? d 'mdown 3)
       (let ((mref (cadr d)) (reason (caddr d)))
         (let ((entry (atomically (hashtable-ref rmonitors mref #f))))
           (when (and entry (eq? (vector-ref entry 1) peer))
             (fire-remote-down! mref reason)))))
      ;; (demon ,mref) -> stop a monitor we host for this peer
      ((frame? d 'demon 2)
       (let ((agent (atomically
                      (hashtable-ref callee-agents (cons peer (cadr d)) #f))))
         (when agent (send agent (vector 'demon-local)))))
      ((equal? d '(ping)) (write-frame! c '(pong)))
      ((equal? d '(pong)) (void))
      (else (raise 'protocol))))                ; confused peer: drop it

  (define (frame? d tag len)
    (and (pair? d) (eq? (car d) tag) (list? d) (= (length d) len)))

  ;; callee side of an rcall: run the local gen-server call (which brings
  ;; its own monitor + timeout), then ship the result back over the link.
  ;; Any failure -- no such server, it died, it timed out, or a reply
  ;; that will not serialize -- comes back as (error <reason-symbol>) so
  ;; the caller never hangs.
  (define (serve-rcall! peer reg ref m)
    (let ((result (guard (e (#t (list 'error (rcall-reason e))))
                    (list 'ok (gen-server-call reg m)))))
      (let ((e (live-entry peer)))
        (when e
          (guard (e2 (#t (link-write peer (list 'reply ref
                                                (list 'error 'not-serializable)))))
            (write-frame! (vector-ref e 0) (list 'reply ref result)))))))

  (define (rcall-reason e)
    (if (and (vector? e) (> (vector-length e) 1) (symbol? (vector-ref e 1)))
        (vector-ref e 1)                        ; e.g. gen-server-error tag
        'unavailable))

  ;; write one datum to a peer by name, if the link is live
  (define (link-write peer datum)
    (let ((e (live-entry peer)))
      (and e (begin (write-frame! (vector-ref e 0) datum) #t))))

  ;; ---- cross-node process monitor ----------------------------------------

  ;; target side: one process per remote watch. It locally monitors the
  ;; registered process and reports its death back over the link. A
  ;; missing name is an immediate 'noproc. The reason is shipped as-is
  ;; when wire-safe, else degraded to 'exit -- a monitor must always
  ;; deliver a DOWN, never wedge on a non-serializable reason.
  ;; key is (peer . mref); dispatch registered us under it before we ran
  (define (mon-agent origin key name)
    (let ((mref (cdr key))
          (p (whereis name)))
      (if (not p)
          (begin
            (atomically (hashtable-delete! callee-agents key))
            (link-write origin (list 'mdown mref 'noproc)))
          (let ((m (monitor p)))
            (receive
              (`#(DOWN ,@p ,reason)
                (atomically (hashtable-delete! callee-agents key))
                (guard (e (#t (link-write origin (list 'mdown mref 'exit))))
                  (link-write origin (list 'mdown mref reason))))
              (`#(demon-local)
                (demonitor m)
                (atomically (hashtable-delete! callee-agents key))))))))

  ;; watcher side: deliver #(remote-down node name reason) to the caller
  ;; that installed mref, once. Used for both a target-side mdown and a
  ;; link drop (which synthesizes 'noconnection).
  (define (fire-remote-down! mref reason)
    (let ((entry (atomically
                   (let ((e (hashtable-ref rmonitors mref #f)))
                     (when e (hashtable-delete! rmonitors mref))
                     e))))
      (when entry
        (send (vector-ref entry 0)
              (vector 'remote-down (vector-ref entry 1) (vector-ref entry 2)
                      reason)))))

  ;; self-watch agent: same contract, but the target is local, so the
  ;; DOWN is delivered straight to the caller (no link involved).
  (define (self-mon-agent caller mref name)
    (let ((p (whereis name)))
      (if (not p)
          (fire-remote-down! mref 'noproc)
          (let ((m (monitor p)))
            (receive
              (`#(DOWN ,@p ,reason)
                (atomically (hashtable-delete! caller-agents mref))
                (fire-remote-down! mref reason))
              (`#(demon-local)
                (demonitor m)
                (atomically (hashtable-delete! caller-agents mref))))))))

  ;; every rmonitor watching a node whose link just dropped gets a
  ;; synthesized noconnection (the target may be alive or dead -- across
  ;; a broken link they're indistinguishable, as in Erlang)
  (define (fail-monitors-for! node)
    (let-values (((mrefs entries) (atomically (hashtable-entries rmonitors))))
      (vector-for-each
        (lambda (mref e)
          (when (eq? (vector-ref e 1) node)
            (fire-remote-down! mref 'noconnection)))
        mrefs entries)))

  (define (link-loop c peer buf last-seen)
    (let drain ((buf buf))
      (let-values (((d rest) (parse-frame buf)))
        (if (eq? d 'more)
            (receive (after tick-ms
                        (if (> (- (now-ms) last-seen) dead-ms)
                            (raise 'closed)
                            (begin (write-frame! c '(ping))
                                   (link-loop c peer buf last-seen))))
              (`#(tcp-data ,bv)
                (link-loop c peer (bv-append buf bv) (now-ms)))
              (`#(tcp-eof) (raise 'closed))
              (`#(tcp-error ,e) (raise 'closed))
              (`#(node-stop) (raise 'stop)))
            (begin (dispatch! c peer d) (drain rest))))))

  ;; run the link until it drops, then clean up; never raises
  (define (run-link c peer buf)
    (guard (e (#t (remove-peer! peer c)))
      (link-loop c peer buf (now-ms))))

  ;; ---- accept side -----------------------------------------------------------

  (define (acceptor c)
    (guard (e (#t (tcp-close! c)))              ; failed handshake: just close
      (let ((nonce (random-hex 16)))
        (write-frame! c (list 'challenge nonce))
        (let-values (((d buf) (read-frame c empty-bv handshake-timeout-ms)))
          (unless (and (pair? d) (eq? (car d) 'hello)
                       (= (length d) 4)
                       (symbol? (cadr d))
                       (not (eq? (cadr d) self-name))
                       (proof=? (caddr d) (proof nonce (cadr d)))
                       (string? (cadddr d)))
            (raise 'auth))
          (let ((peer (cadr d)) (nonce-b (cadddr d)))
            (write-frame! c (list 'welcome self-name (proof nonce-b self-name)))
            (if (install-peer! peer c peer)     ; dialer = the remote side
                (run-link c peer buf)
                (tcp-close! c)))))))            ; lost the tie-break

  ;; ---- dial side --------------------------------------------------------------

  ;; one connect attempt; returns when the link is gone. Raises only 'stop.
  (define (dial! peer host port)
    (guard (e ((eq? e 'stop) (raise 'stop))
              (#t (void)))                      ; any failure: retry later
      (tcp-connect! host port self)
      (receive (after handshake-timeout-ms (raise 'timeout))
        (`#(tcp-connected ,c)
          (guard (e ((eq? e 'stop) (tcp-close! c) (raise 'stop))
                    (#t (tcp-close! c)))
            (tcp-read-start! c)
            (let-values (((d buf) (read-frame c empty-bv handshake-timeout-ms)))
              (unless (and (pair? d) (eq? (car d) 'challenge)
                           (= (length d) 2) (string? (cadr d)))
                (raise 'auth))
              (let ((nonce-b (random-hex 16)))
                (write-frame! c
                  (list 'hello self-name (proof (cadr d) self-name) nonce-b))
                (let-values (((d2 buf2) (read-frame c buf handshake-timeout-ms)))
                  (unless (and (pair? d2) (eq? (car d2) 'welcome)
                               (= (length d2) 3)
                               (eq? (cadr d2) peer)   ; it must BE who we dialed
                               (proof=? (caddr d2) (proof nonce-b peer)))
                    (raise 'auth))
                  (if (install-peer! peer c self-name)
                      (run-link c peer buf2)
                      (tcp-close! c)))))))
        (`#(tcp-connect-failed ,e) (void))
        (`#(node-stop) (raise 'stop)))))

  ;; the reconnect supervisor for one peer; lives until node-disconnect!
  (define (connector peer host port)
    (guard (e (#t (void)))                      ; 'stop lands here too
      (let loop ()
        (unless (live-entry peer)               ; a surviving inbound counts
          (dial! peer host port))
        (receive (after reconnect-ms (loop))
          (`#(node-stop) (void))
          ;; stragglers from a timed-out dial: release and keep looping
          (`#(tcp-connected ,c) (tcp-close! c) (loop))
          (`#(tcp-connect-failed ,e2) (loop))))))

  ;; ---- public API ---------------------------------------------------------------

  ;; Set this node's identity and shared secret; with a port, also
  ;; accept peers -- on 127.0.0.1 unless a host is given (the dist port
  ;; must never face the public internet).
  (define (node-start! name secret . rest)
    (unless (and (symbol? name) (string? secret))
      (assertion-violation 'node-start! "want (name-symbol secret-string)" name))
    (when self-name
      (assertion-violation 'node-start! "node already started" self-name))
    (set! self-name name)
    (set! self-secret (string->utf8 secret))
    (when (pair? rest)
      (let ((port (car rest))
            (host (if (pair? (cdr rest)) (cadr rest) "127.0.0.1")))
        (tcp-listen! host port 128
          (lambda (c)
            ;; libuv callback context: spawn + own + read-start only
            (let ((pid (spawn (lambda () (acceptor c)))))
              (conn-set-owner! c pid)
              (tcp-read-start! c))))))
    name)

  ;; Dial a peer (and keep dialing whenever the link is down).
  (define (node-connect! peer host port)
    (unless self-name
      (assertion-violation 'node-connect! "call node-start! first" peer))
    (when (eq? peer self-name)
      (assertion-violation 'node-connect! "cannot connect to self" peer))
    (atomically
      (let ((p (hashtable-ref connectors peer #f)))
        (unless (and p (process-alive? p))
          (hashtable-set! connectors peer
            (spawn (lambda () (connector peer host port)))))))
    (void))

  ;; Stop dialing and drop the live link, if any.
  (define (node-disconnect! peer)
    (let ((p (atomically
               (let ((p (hashtable-ref connectors peer #f)))
                 (hashtable-delete! connectors peer)
                 p))))
      (when (and p (process-alive? p)) (send p (vector 'node-stop))))
    (let ((e (peer-entry peer)))
      (when e (send (vector-ref e 1) (vector 'node-stop))))
    (void))

  ;; Send msg to the process registered as reg-name on node. #t = handed
  ;; to a live link (delivery still unconfirmed, as within a node); #f =
  ;; no link. Own node name = plain local send. Raises if msg contains
  ;; data outside the extended wire whitelist.
  (define (rsend node reg-name msg)
    (cond
      ((eq? node self-name)
       (let ((p (whereis reg-name)))
         (and p (begin (send p msg) #t))))
      ((live-entry node)
       => (lambda (e)
            (write-frame! (vector-ref e 0) (list 'send reg-name msg))
            #t))
      (else #f)))

  ;; Synchronous cross-node call to the GEN-SERVER registered as
  ;; reg-name on node; returns its reply, blocking the caller (default
  ;; 5s timeout). The own node name is a plain local gen-server-call.
  ;; Raises #(rcall-error <reason> <target>) on no link, timeout, or a
  ;; remote failure (no such server / it died / a non-serializable
  ;; reply). Both msg and the reply must be extended-wire-safe.
  (define (rcall node reg-name msg . rest)
    (let ((timeout (if (pair? rest) (car rest) 5000)))
      (cond
        ((eq? node self-name) (gen-server-call reg-name msg timeout))
        ((live-entry node)
         => (lambda (e)
              (let ((ref (next-rcall-ref!)))
                (atomically (hashtable-set! pending ref (vector self node)))
                (write-frame! (vector-ref e 0) (list 'call reg-name ref msg))
                (receive (after timeout
                            (atomically (hashtable-delete! pending ref))
                            (raise (vector 'rcall-error 'timeout reg-name)))
                  (`#(rcall-reply ,@ref ,result)
                    (atomically (hashtable-delete! pending ref))
                    ;; a well-formed reply is (ok ,v) or (error ,reason);
                    ;; anything else is a broken peer, not a hang
                    (cond
                      ((and (pair? result) (eq? (car result) 'ok) (pair? (cdr result)))
                       (cadr result))
                      ((and (pair? result) (eq? (car result) 'error) (pair? (cdr result)))
                       (raise (vector 'rcall-error (cadr result) reg-name)))
                      (else
                       (raise (vector 'rcall-error 'bad-reply reg-name)))))))))
        (else (raise (vector 'rcall-error 'noconnection node))))))

  ;; Watch the process registered as name on node. The caller later
  ;; receives exactly one #(remote-down ,node ,name ,reason):
  ;;   - reason = the target's exit reason when it dies
  ;;   - 'noproc       if no such name is registered when the watch is
  ;;                   established (which is asynchronous, so a target
  ;;                   that dies in that window also reports noproc --
  ;;                   monitor before the event that can kill it)
  ;;   - 'noconnection if the link to node drops first (the target may
  ;;                   be alive or dead -- indistinguishable across a
  ;;                   broken link, as in Erlang)
  ;; Returns a monitor ref for demonitor-remote. The own node name is a
  ;; local watch (still reported as remote-down, for a uniform API).
  ;; This is process-level; monitor-node is the node-level counterpart.
  (define (monitor-remote node name)
    (unless self-name
      (assertion-violation 'monitor-remote "call node-start! first" node))
    (let ((mref (next-mref!)))
      (cond
        ((eq? node self-name)
         (atomically (hashtable-set! rmonitors mref (vector self node name)))
         (let ((agent (spawn (lambda () (self-mon-agent self mref name)))))
           (atomically (hashtable-set! caller-agents mref agent))))
        ((live-entry node)
         => (lambda (e)
              (atomically (hashtable-set! rmonitors mref (vector self node name)))
              (write-frame! (vector-ref e 0) (list 'mon name mref self-name))))
        (else
         ;; no link at all: report immediately, nothing to install
         (send self (vector 'remote-down node name 'noconnection))))
      mref))

  ;; Cancel a monitor-remote. No further remote-down for it will arrive
  ;; (a DOWN already in flight may still be delivered, as in Erlang).
  (define (demonitor-remote mref)
    (let ((entry (atomically
                   (let ((e (hashtable-ref rmonitors mref #f)))
                     (when e (hashtable-delete! rmonitors mref))
                     e))))
      (when entry
        (let ((node (vector-ref entry 1)))
          (if (eq? node self-name)
              (let ((agent (atomically
                             (let ((a (hashtable-ref caller-agents mref #f)))
                               (hashtable-delete! caller-agents mref) a))))
                (when (and agent (process-alive? agent))
                  (send agent (vector 'demon-local))))
              (link-write node (list 'demon mref))))))
    (void))
)
