#!chezscheme
;;; Copyright 2018 - 2026 guenchi.
;;;
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;;
;;; http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

;;; (igropyr tcp) -- everything a connection or an owning process owns.
;;;
;;; THE CUT ABOVE (igropyr libuv) IS BY OWNERSHIP. What lives here hangs off an
;;; owner or a connection: the conn record and its table, listeners and their
;;; incarnations, the owner index and owner-death sweep, outbound connects,
;;; DNS, files and file streams, the TLS connection codec with its gate,
;;; watcher side and per-conn timers, and the accept counters. What belongs to
;;; the loop itself -- the FFI, the constants, the loop handle and its shared
;;; buffers -- is (igropyr libuv), below.
;;;
;;; THE SHARED BUFFERS ARRIVE AS LEASES. uv hands each one to a thunk inside
;;; an interrupt-disabled region; the bodies below are the same sequences in
;;; the same order they always ran in, and the lambda parameters deliberately
;;; keep the buffers' old names so those bodies did not have to be rewritten
;;; to be moved.
;;;
;;; THE HOOKS KEEP THEIR uv- NAMES. uv-set-deliver!, uv-set-self!,
;;; uv-set-tls-watcher-spawner! and uv-set-gate-wait! serve THIS layer, not the
;;; loop, and they live here -- but the public API is unchanged name for name
;;; by ruling, so the names stay as they are. Reading oddly is the price of not
;;; breaking every consumer.

(library (igropyr tcp)
  (export
    conn-count conn-handle conn-on-close! conn-owner
    conn-peer-ip conn-set-owner! conn-state conn-tls-retire!
    conn? dns-count dns-resolve! file-read-async!
    file-realpath file-scandir-async! file-stat-async! file-stream-chunk-ptr
    file-stream-close! file-stream-open! file-stream-open-under! file-stream-own!
    file-stream-raw! file-stream-read! file-unlink-async! fs-close-async!
    fs-count fs-fd-count fs-fsync-async! fs-job-count
    fs-mkdir-async! fs-open-async! fs-rename-async! fs-req-block-count
    fs-write-async!
    listener-backlog-effective listener-open? listener-token tcp-close!
    tcp-connect! tcp-connect-tls! tcp-listen! tcp-listen-tls!
    tcp-read-start!
    tcp-read-stop! tcp-stop-listen! tcp-write! tcp-write-foreign!
    tcp-writev! tcp-writev-raw!
    uv-accept-failure-counts uv-owner-died!
    uv-owner-index-count uv-set-alive?! uv-set-deliver! uv-set-gate-wait!
    uv-set-self!
    uv-set-tls-watcher-spawner!
    ;; write-block accounting, TCP-wide: a write block belongs to a
    ;; connection, not to a child process, so these are their own two
    ;; readings rather than entries in proc-stats -- a program with no
    ;; children still has write blocks to account for.
    write-blocks-live-count write-table-size
    ;; child processes
    proc? proc-spawn! proc-write! proc-stdin-close!
    proc-read-start! proc-read-stop! proc-kill! proc-kill-all! proc-close!
    proc-state proc-queued proc-pid proc-exit proc-owner proc-handle
    proc-stdin proc-stdout proc-stderr
    proc-count pipe-conn-count socket-conn-count proc-stats
    set-max-procs! set-proc-stdin-cap!
    ;; the watcher's interface to a connection's shared state
    tls-gate-grant-next! tls-gate-waiters-length tls-conn-holder
    tls-conn-peer-cb-hash tls-conn-shutdown?
    tls-conn-holder-monitor tls-conn-set-holder-monitor!
    tls-open-gate-and-drain! tls-watcher-exited! tls-inject-ciphertext!
    ;; knobs
    tls-handshake-max-set! tls-handshake-ms-set! tls-shutdown-ms-set!
    ;; INJECT-gated seams
    tls-raw-sink-writes tls-ssl-op-count tls-server-raw-reads
    tls-accept-callback-completions tls-gate-open-mark tls-live-watcher-count
    tls-live-timer-count tls-active-timer-count tls-handshaking-count
    tls-retire-effect-depths tls-raw-blocks tls-conn-charge tls-conn-totals
    tls-conn-timer-id tls-last-retire-reason tls-listener-context-id
    tls-timer-free-path tls-conn-in-table? tls-eof-deliveries
    tls-swallowed-errors tls-read-trace
    proc-handles-freed proc-exit-no-row-handles $proc-table-ref
    $proc-last-spawned-pid)

  ;; (igropyr libuv) IS BELOW THIS FILE and (igropyr tls-core) beside it; both
  ;; import neither this library nor each other's consumers, so there is no
  ;; cycle. There is no facade: this file names what it takes from the binding
  ;; layer, so the import list IS the dependency, checkable by reading it.
  (import (chezscheme) (igropyr platform) (igropyr inject)
          (only (igropyr libuv) AF-INET O-CLOEXEC O-DIRECTORY O-NOFOLLOW
            O-RDONLY S-IFMT S-IFREG UV-EINVAL UV-EOF buf-t-size c-close
            c-getsockopt c-open c-openat check connect-req-size fs-req-size
            getaddrinfo-req-size memcpy-cc memcpy-from-c memcpy-to-c now-ms
            tcp-handle-size timer-handle-size uv-accept uv-close uv-enomem
            uv-fileno uv-freeaddrinfo uv-fs-close uv-fs-fstat uv-fs-fsync
            uv-fs-get-ptr uv-fs-get-result uv-fs-get-statbuf uv-fs-mkdir
            uv-fs-open uv-fs-read uv-fs-realpath uv-fs-rename
            uv-fs-req-cleanup uv-fs-scandir uv-fs-scandir-next uv-fs-stat
            uv-fs-unlink uv-fs-write uv-getaddrinfo uv-in-callback?
            uv-ip4-addr uv-is-active uv-is-closing uv-listen uv-loop-handle
            uv-peername-lease uv-read-buf-base uv-read-buf-size uv-read-start
            uv-read-stop uv-scratch-lease uv-sockaddr-lease uv-strerror
            uv-tcp-bind uv-tcp-connect uv-tcp-init uv-tcp-nodelay
            uv-timer-init uv-timer-start uv-timer-stop uv-try-write uv-write
            uv-write-scratch-size write-req-size
            uv-handle-size uv-req-size
            uv-spawn uv-process-kill uv-kill uv-process-get-pid
            uv-pipe-init uv-shutdown
            UV-PROCESS UV-NAMED-PIPE UV-SHUTDOWN)
          (igropyr tls-core))

  ;; connection record; one per accepted TCP client
  (define-record-type (conn make-conn conn?)
    (fields
      (immutable handle conn-handle)             ; foreign address of uv_tcp_t
      (mutable owner conn-owner conn-set-owner-field!) ; pid of the reader process
      (mutable state conn-state conn-set-state!) ; open | closing | closed
      ;; one thunk, run exactly once when the handle's close completes --
      ;; see conn-on-close! below for why cleanup hangs off the conn
      (mutable cleanup conn-cleanup conn-set-cleanup!)
      ;; ONE FIELD, NOT FIFTEEN, AND THE CHOICE IS AN INVARIANT. #f on a
      ;; plaintext connection; otherwise the conn-tls record below. Retirement
      ;; DETACHES IT with a single assignment inside one interrupt-disabled
      ;; region, so every later caller sees #f -- which is what makes
      ;; conn-tls-retire! idempotent by shape rather than by agreement between
      ;; its callers. Fifteen separate fields would need fifteen detaches, and
      ;; "half detached" would be a state someone has to reason about; owner
      ;; death and watcher death can arrive together, so no caller can promise
      ;; to run the retirement only once.
      (mutable tls conn-tls conn-set-tls!)
      ;; THE HANDSHAKING SLOT, HELD FROM BEFORE THE TLS RECORD EXISTS. It
      ;; cannot live on conn-tls, because the window this closes is precisely
      ;; the one before that record is built.
      (mutable slot conn-slot conn-set-slot!)
      ;; TRANSPORT-LEVEL, AND ON THE CONN RATHER THAN THE TLS RECORD (E9).
      ;; Once the close_notify alert has been submitted nothing may be put on
      ;; this handle again, and that has to remain true after retirement has
      ;; detached conn-tls -- a flag on the TLS record would become
      ;; unreachable at exactly the moment the last writes are still landing.
      (mutable raw-sealed? conn-raw-sealed? conn-set-raw-sealed!)
      ;; WHAT THIS CONN IS, when it is not a socket. #f for every TCP
      ;; connection; for a child process's pipe it is (proc . stream), which is
      ;; what lets the shared read callback address the owner in the shape that
      ;; owner expects.
      ;;
      ;; It is also the discriminator for "the library owns this conn's
      ;; lifetime, not the application": a tagged conn refuses conn-on-close!
      ;; and conn-set-owner!, because its cleanup closure and its owner are part
      ;; of the proc's bookkeeping.
      (mutable tag conn-tag conn-set-tag!)))

  ;; ---- TLS state of one connection ---------------------------------------
  ;;
  ;; Reached only through conn-tls, and only while that field is non-#f. The
  ;; session is an opaque (igropyr tls-core) object: this file never holds an
  ;; SSL pointer, and every OpenSSL call goes through a session operation.
  ;;
  ;; The gate fields are shared state that both a writer and the watcher touch,
  ;; so every read-modify-write of them happens in one interrupt-disabled step
  ;; (Z8): a writer appends itself to waiters, the watcher pops it, and
  ;; retirement TAKES THE WHOLE LIST and refuses whoever it took -- whichever
  ;; of the two atomically takes a non-empty list is the one that answers, so
  ;; there is no double wake and no test of whether the watcher is still alive.
  (define-record-type (conn-tls-state make-conn-tls conn-tls?)
    (fields
      (immutable session conn-tls-session)      ; opaque tls-core session
      (immutable listener conn-tls-listener)    ; listener incarnation, or #f
      ;; inbound plaintext decrypted before the owner could receive it
      (mutable established? conn-tls-established? conn-tls-set-established!)
      ;; THE OWNER HAS BEEN TOLD THIS CONNECTION EXISTS. Distinct from
      ;; established?: a dial is established a moment before its answer is
      ;; delivered, and a terminal notification sent in that gap would name a
      ;; connection the owner has never heard of. Set in the same callback
      ;; frame as the publication itself, on both roles.
      (mutable owner-published? conn-tls-owner-published?
               conn-tls-set-owner-published!)
      (mutable eof? conn-tls-eof? conn-tls-set-eof!)
      ;; 'seen' AND 'delivered' ARE TWO FACTS. eof? alone meant a
      ;; close_notify followed by a FIN delivered two EOFs, and a FIN
      ;; arriving while the gate was shut delivered one AHEAD of the
      ;; buffered request -- the owner saw EOF, data, EOF.
      (mutable eof-sent? conn-tls-eof-sent? conn-tls-set-eof-sent!)
      (mutable gated? conn-tls-gated? conn-tls-set-gated!)
      (mutable inbound conn-tls-inbound conn-tls-set-inbound!)
      ;; write gate
      (mutable holder conn-tls-holder conn-tls-set-holder!)
      (mutable holder-monitor conn-tls-holder-monitor conn-tls-set-holder-monitor!)
      (mutable waiters conn-tls-waiters conn-tls-set-waiters!)
      (mutable closed? conn-tls-closed? conn-tls-set-closed!)
      (mutable closing? conn-tls-closing? conn-tls-set-closing!)
      ;; THE CLEAN-CLOSE DRAIN NEEDS TWO FLAGS, NOT ONE (E9), because the
      ;; two questions have different answers for a stretch of time.
      ;; finishing? means "some process is inside finish-shutdown" and is a
      ;; once-only entry guard, set before anything can fail. shutdown?
      ;; means "the alert exists and a bound is armed", and is set only once
      ;; both are true -- the repeat-close no-ops key on THAT, so a
      ;; finish-shutdown that raised on the way in never leaves a later
      ;; closer believing a drain is in progress.
      (mutable finishing? conn-tls-finishing? conn-tls-set-finishing!)
      (mutable shutdown? conn-tls-shutdown? conn-tls-set-shutdown!)
      (mutable aggregate conn-tls-aggregate conn-tls-set-aggregate!)
      ;; the one timer, live for the conn's whole life (Y3): armed for the
      ;; handshake, stopped on establishment, re-armed for clean shutdown
      (mutable timer conn-tls-timer conn-tls-set-timer!)
      (immutable timer-id conn-tls-timer-id)
      ;; armed? is tracked because active-timer accounting has three
      ;; movers -- arm, stop, close -- and only a flag makes each of them
      ;; idempotent with respect to the count.
      (mutable timer-armed? conn-tls-timer-armed? conn-tls-set-timer-armed!)
      ;; watcher
      (mutable watcher conn-tls-watcher conn-tls-set-watcher!)
      ;; accounting (X4)
      (mutable bio-held conn-tls-bio-held conn-tls-set-bio-held!)
      (mutable raw-queued conn-tls-raw-queued conn-tls-set-raw-queued!)
      (mutable charged conn-tls-charged conn-tls-set-charged!)
      (mutable refunded conn-tls-refunded conn-tls-set-refunded!)
      ;; the handshaking-ceiling slot, released exactly once (Y1)
      (mutable slot? conn-tls-slot? conn-tls-set-slot!)
      ;; recorded facts the seams read back
      (mutable gate-opened-ms conn-tls-gate-opened-ms conn-tls-set-gate-opened-ms!)
      (mutable retire-path conn-tls-retire-path conn-tls-set-retire-path!)
      (mutable retire-reason conn-tls-retire-reason conn-tls-set-retire-reason!)
      ;; (entry shared-min shared-max refusal-max session-retire-max
      ;;  uv-close-max), written ONLY by the retirement that wins the detach;
      ;; #f in a slot means that kind of effect did not happen.
      (mutable effect-depths conn-tls-effect-depths conn-tls-set-effect-depths!)
      ;; carries a terminalised aggregate's callback OUT of the retirement
      ;; region, so user code runs outside it
      (mutable abort-cb conn-tls-abort-cb conn-tls-set-abort-cb!)
      ;; The dial's completion record, or #f on a server-side record: nothing
      ;; dialled an accepted connection, so it has no attempt to conclude.
      ;; Reached from here so that a retirement -- the only path that still has
      ;; the connection in hand -- can fail the attempt it belongs to.
      (mutable connect-d conn-tls-connect-d conn-tls-set-connect-d!))
    (nongenerative)
    (sealed #t))

  ;; ---- TLS observation seams ---------------------------------------------
  ;;
  ;; THE RECORDING IS GATED TOO, not just the reader. These counters sit on
  ;; the write and read paths -- once per raw write, once per SSL call -- so an
  ;; ordinary build compiles them out entirely and pays nothing. That differs
  ;; from tls-core's live-session counter deliberately: that one moves once per
  ;; connection and its recording is always on.
  ;;
  ;; Gating both halves together also means there is never a recorded fact
  ;; with no way to read it, nor a reader of a variable that was compiled out.
  (meta define tls-seam-mode
    (let ((v (getenv "IGROPYR_INJECT")))
      (if (and v (string=? v "on")) 'on 'off)))

  ;; The interrupt-disable depth. Safe to call INSIDE a region -- the probe
  ;; raises the count and lowers it again, so it never reaches 0 there.
  ;;
  ;; AT DEPTH 0 THE PROBE IS NOT FREE: enable-interrupts reaching 0 may run
  ;; a pending interrupt, so calling it outside a region manufactures a
  ;; preemption point. That is harmless where the design already says the code
  ;; is preemptible, and it is why no assertion anywhere may read this and
  ;; conclude "depth is 0 here" about a line that must NOT be preemptible.
  (define (region-depth)
    (let ((n (disable-interrupts)))
      (enable-interrupts)
      (fx- n 1)))

  (meta-cond
    ((eq? tls-seam-mode 'on)
     (define raw-sink-writes 0)
     (define ssl-op-count 0)
     (define server-raw-reads 0)
     (define server-raw-read-bytes 0)
     (define accept-callback-completions 0)
     (define gate-opens 0)
     (define live-watchers 0)
     (define live-timers 0)
     (define active-timers 0)
     (define handshaking-count 0)
     (define (bump-raw-sink-writes!)
       (set! raw-sink-writes (fx+ raw-sink-writes 1)))
     (define (bump-ssl-op!) (set! ssl-op-count (fx+ ssl-op-count 1)))
     (define (bump-server-raw-read! n)
       (set! server-raw-reads (fx+ server-raw-reads 1))
       (set! server-raw-read-bytes (fx+ server-raw-read-bytes n)))
     (define (bump-accept-completion!)
       (set! accept-callback-completions (fx+ accept-callback-completions 1)))
     (define (bump-gate-open!) (set! gate-opens (fx+ gate-opens 1)))
     (define eof-deliveries 0)
     ;; every tcp-eof handed to an owner, counted once at the one place
     ;; that delivers it -- the row asserting "exactly one EOF" reads this
     (define (bump-eof-delivery!) (set! eof-deliveries (fx+ eof-deliveries 1)))
     ;; WHAT THE NON-ESCAPING GUARDS SWALLOWED. Stopping exceptions from
     ;; unwinding into C is necessary, but it also destroyed the evidence:
     ;; a connection that raised twice in its read callback left NO trace --
     ;; no EOF, no retire reason, no error -- and looked exactly like a
     ;; connection that had simply gone quiet. The condition object is kept
     ;; as-is rather than rendered: rendering can itself fail, and this runs
     ;; in the one place that must not raise.
     (define swallowed-count 0)
     (define swallowed-where #f)
     (define swallowed-what #f)
     (define (note-swallowed! where e)
       (set! swallowed-count (fx+ swallowed-count 1))
       (set! swallowed-where where)
       (set! swallowed-what e))
     (define (tls-swallowed-errors)
       (list swallowed-count swallowed-where swallowed-what))

     ;; A BOUNDED TRACE OF THE READ PATH'S STAGES. Two rounds of reasoning
     ;; from the source failed to explain a read that increments the raw-read
     ;; counter, swallows no exception, records no retirement, and never
     ;; reaches the decrypt -- each of those readings is consistent with the
     ;; code as written, which means the model is wrong somewhere invisible.
     ;; This records which stages were actually ENTERED, in order, instead of
     ;; inviting a third guess.
     (define read-trace '())
     (define read-trace-max 32)
     (define (note-read-stage! s)
       (set! read-trace
             (let ((l (append read-trace (list s))))
               (if (fx> (length l) read-trace-max) (cdr l) l))))
     (define (tls-read-trace) read-trace)
     (define (tls-eof-deliveries) eof-deliveries)
     (define (note-gate-open-ms! ms) (set! last-gate-open-ms ms))
     ;; A SET OF PIDS, NOT A COUNTER (E9). A counter only ever moves when
     ;; someone remembers to move it, and a watcher killed through its link
     ;; to a dying owner runs no exit code at all -- so the count stayed high
     ;; and a cell reading "1 watcher" could not tell a live watcher from a
     ;; link-killed one. Holding the pids lets the READER decide, by asking
     ;; whether each is still alive at the moment of the question.
     ;;
     ;; The liveness test comes from above (uv-alive?), for the same reason
     ;; identity and the watcher spawner do: this layer does not know what a
     ;; process is. With no hook installed the set is reported as-is, which
     ;; is the pre-E9 behaviour.
     (define watcher-pids '())
     (define (note-watcher! pid)
       (when pid (set! watcher-pids (cons pid watcher-pids))))
     (define (forget-watcher! pid)
       (set! watcher-pids (remq pid watcher-pids)))
     (define (bump-watchers! d) (set! live-watchers (fx+ live-watchers d)))
     (define (bump-live-timers! d) (set! live-timers (fx+ live-timers d)))
     (define (bump-active-timers! d) (set! active-timers (fx+ active-timers d)))
     (define (bump-handshaking! d) (set! handshaking-count (fx+ handshaking-count d)))
     (define (tls-raw-sink-writes) raw-sink-writes)
     (define (tls-ssl-op-count) ssl-op-count)
     (define (tls-server-raw-reads) (cons server-raw-reads server-raw-read-bytes))
     (define (tls-accept-callback-completions) accept-callback-completions)
     ;; GLOBAL, AND IT HAS TO BE: the cell watching this is the CLIENT, and
     ;; a client has no handle on the server's conn record -- when the bug is
     ;; that no handler ever ran, there is nothing to ask for one. A count plus
     ;; the last opening's timestamp answers "did the gate open, and when"
     ;; without needing the connection.
     (define last-gate-open-ms #f)
     (define (tls-gate-open-mark) (cons gate-opens last-gate-open-ms))
     ;; PRUNES AT READ TIME, and the pruning IS the answer: a watcher that
     ;; died without running its exit is dropped here and nowhere else.
     (define (tls-live-watcher-count)
       (when uv-alive?
         (set! watcher-pids (filter (lambda (p) (uv-alive? p)) watcher-pids)))
       (length watcher-pids))
     (define (tls-live-timer-count) live-timers)
     (define (tls-active-timer-count) active-timers)
     (define (tls-handshaking-count) handshaking-count)
     ;; NO ABSOLUTE DEPTH SEAM. The event-loop process runs with
     ;; interrupts PERMANENTLY disabled (actor.sc's header), so inside a
     ;; callback frame the depth is always >= 1 and the 0->1 transition
     ;; never happens. A token keyed on "this entry left depth 0" would
     ;; never fire in the only host this code runs in -- measured in a
     ;; plain script, where depth starts at 0, it looked like it worked.
     ;; What survives is DIFFERENCES relative to a sampled entry depth.
     ;; (entry shared-min shared-max refusal-max session-retire-max
     ;;  uv-close-max); #f where that kind of effect never happened.
     (define (retire-entry-depth) (region-depth))
     (define (retire-depths-init! t entry)
       (conn-tls-set-effect-depths! t (vector entry #f #f #f #f #f)))
     (define (note-shared-depth! t)
       (let ((v (conn-tls-effect-depths t)) (d (region-depth)))
         (when v
           (let ((lo (vector-ref v 1)) (hi (vector-ref v 2)))
             (when (or (not lo) (fx< d lo)) (vector-set! v 1 d))
             (when (or (not hi) (fx> d hi)) (vector-set! v 2 d))))))
     (define (note-effect-depth! t kind)
       (let ((v (conn-tls-effect-depths t)) (d (region-depth)))
         (when v
           (let ((i (case kind ((refusal) 3) ((session-retire) 4) (else 5))))
             (let ((cur (vector-ref v i)))
               (when (or (not cur) (fx> d cur)) (vector-set! v i d)))))))
     ;; READ IT OFF THE RECORD THE RETIREMENT WROTE, which means the caller
     ;; must hold the conn-tls state -- by the time retirement is done,
     ;; (conn-tls c) is #f. The cell keeps the record it was handed before the
     ;; close, which is why this takes the state and not the conn.
     ;; REGISTERED BEFORE SUBMISSION, so a snapshot list never records a
     ;; block after its own inline completion. Each entry is
     ;; (id aggregate-id size pending sealed? completed?) sampled at
     ;; registration; the monotonic completion order is appended as blocks
     ;; finish, so the cell can read the ORDER rather than infer it.
     (define next-raw-block-id 0)
     (define raw-blocks-by-conn (make-eqv-hashtable))
     (define (note-raw-block! t agg size)
       (let ((id next-raw-block-id))
         (set! next-raw-block-id (fx+ id 1))
         (hashtable-set! raw-blocks-by-conn t
           (append (hashtable-ref raw-blocks-by-conn t '())
                   (list (list id (tls-agg-id agg) size
                               (tls-agg-pending agg)
                               (tls-agg-sealed? agg)
                               (tls-agg-done? agg)))))
         id))
     (define raw-completions-by-conn (make-eqv-hashtable))
     (define (note-raw-block-done! t agg sz status)
       (hashtable-set! raw-completions-by-conn t
         (append (hashtable-ref raw-completions-by-conn t '())
                 (list (list (tls-agg-id agg) sz status
                             (tls-agg-pending agg)
                             (tls-agg-sealed? agg)
                             (tls-agg-done? agg))))))
     ;; -> (registered . completed); registered in submission order, completed
     ;; in the order the completions actually ran.
     ;;
     ;; IT TAKES THE CONN, NOT THE TLS STATE, like tls-conn-charge and
     ;; tls-conn-totals beside it. conn-tls is not exported, so a cell holding
     ;; a connection could not produce the t the earlier signature required:
     ;; the reading existed and was unreachable -- a ruler nobody could pick
     ;; up. The tables are still keyed by t; resolving it happens here.
     ;;
     ;; A RETIRED CONN ANSWERS '(() . ()), NOT #f. Retirement detaches the
     ;; state, so there is no key left to look under and nothing to report --
     ;; which is not the same as "this connection wrote nothing". Read it
     ;; while the connection is alive; a cell that reads after retirement is
     ;; measuring the detach, not the writes.
     (define (tls-raw-blocks c)
       (let ((t (conn-tls c)))
         (if (not t)
             (cons '() '())
             (cons (hashtable-ref raw-blocks-by-conn t '())
                   (hashtable-ref raw-completions-by-conn t '())))))
     (define (tls-conn-charge c)
       (let ((t (conn-tls c)))
         (and t (cons (conn-tls-bio-held t) (conn-tls-raw-queued t)))))
     (define (tls-conn-totals c)
       (let ((t (conn-tls c)))
         (and t (cons (conn-tls-charged t) (conn-tls-refunded t)))))
     (define (tls-conn-timer-id c)
       (let ((t (conn-tls c))) (and t (conn-tls-timer-id t))))
     ;; GLOBAL AND ARGUMENT-FREE, for the reason the gate mark is: when the
     ;; question is "who closed this connection and why", the asker generally
     ;; cannot reach the connection any more -- retirement has detached it.
     (define last-retire-reason #f)
     (define (note-retire-reason! path reason)
       (set! last-retire-reason (cons path reason)))
     (define (tls-last-retire-reason) last-retire-reason)

     ;; Which listener incarnation holds which context. The identity that
     ;; matters is the INCARNATION's, not the handle's: a later listener at
     ;; the same address is a different generation with its own context, and
     ;; the row this serves is "exactly one reference, retired once per
     ;; generation".
     (define (tls-listener-context-id h)
       (let ((v (hashtable-ref listener-table h #f)))
         (and v (let ((ctx (vector-ref v 3)))
                  (and ctx (cons (vector-ref v 0) ctx))))))

     ;; WHICH PATH GAVE THE TIMER BACK, because the two are not
     ;; interchangeable (Y4): an uninitialised handle is freed directly and
     ;; must never reach uv_close, while an initialised one must go out
     ;; through uv_close and be freed only by its close callback. A count of
     ;; timers cannot tell those apart; this records the route each one took.
     (define timer-free-paths '())
     (define (note-timer-free! how)
       (set! timer-free-paths (append timer-free-paths (list how))))
     (define (tls-timer-free-path) timer-free-paths)

     ;; Publication, as X2 defines it: membership of conn-table, asked by
     ;; handle so a cell can ask about a connection it no longer holds.
     (define (tls-conn-in-table? h)
       (and (hashtable-ref conn-table h #f) #t))
     ;; ---- child-process seams ---------------------------------------------
     ;;
     ;; THREE OF THESE ANSWER WITH ADDRESSES, NOT COUNTS, and that is the
     ;; whole point. The rule under test is "the process handle block is not
     ;; freed while a row still names its address", and a count of frees
     ;; cannot tell a premature free of THIS handle from a timely free of
     ;; some other child's. The address is what makes the two readings
     ;; different, so the address is what is recorded.
     (define proc-freed-handles '())
     (define (note-proc-handle-freed! h)
       (set! proc-freed-handles (append proc-freed-handles (list h))))
     (define (proc-handles-freed) proc-freed-handles)
     ;; The exit callback's no-row path, by address. A hit count alone says
     ;; "some handle exited with no row"; a cell driving a publication gap
     ;; has to know it was the handle it parked, and not a leftover from an
     ;; earlier child in the same run.
     (define proc-exit-no-row '())
     (define (note-proc-exit-no-row! h)
       (set! proc-exit-no-row (append proc-exit-no-row (list h))))
     (define (proc-exit-no-row-handles) proc-exit-no-row)
     ;; THE PID OF THE LAST CHILD THIS PROCESS ACTUALLY STARTED, recorded
     ;; even when the caller is handed a failure. The orphan paths are the
     ;; reason: uv_spawn reports an error, the caller never sees a proc, and
     ;; yet a real child is running -- so a cell asking "was it killed, is it
     ;; a zombie, is it gone" has no pid to ask about. Grepping ps for the
     ;; command line answers a different question and answers it badly (a
     ;; zombie's arguments are gone on some hosts, and an unrelated process
     ;; can match). Set only where a child provably exists, never from
     ;; uv_process_get_pid on a failed spawn, which reads uninitialised
     ;; memory.
     (define proc-last-pid #f)
     (define (note-spawned-pid! pid) (set! proc-last-pid pid))
     (define ($proc-last-spawned-pid) proc-last-pid)
     ;; IDENTITY, NOT FIELDS. A retained row is proved to be the SAME record
     ;; by (eq? ($proc-table-ref addr) p); reading its fields would pass just
     ;; as well against a later child's row that happens to look alike.
     (define ($proc-table-ref h) (hashtable-ref proc-table h #f))
     (define (tls-retire-effect-depths t)
       (let ((v (and t (conn-tls-effect-depths t))))
         (and v (vector->list v)))))
    (else
     (define (bump-raw-sink-writes!) (void))
     (define (bump-ssl-op!) (void))
     (define (bump-server-raw-read! n) (void))
     (define (bump-accept-completion!) (void))
     (define (bump-gate-open!) (void))
     (define (bump-eof-delivery!) (void))
     (define (note-swallowed! where e) (void))
     (define (note-read-stage! s) (void))
     (define (note-gate-open-ms! ms) (void))
     (define (bump-watchers! d) (void))
     (define (note-watcher! pid) (void))
     (define (forget-watcher! pid) (void))
     (define (bump-live-timers! d) (void))
     (define (bump-active-timers! d) (void))
     (define (bump-handshaking! d) (void))
     (define-syntax define-absent-seam
       (syntax-rules ()
         ((_ name)
          (define (name . _)
            (assertion-violation 'name
              "test seam: this artifact was expanded without IGROPYR_INJECT=on")))))
     (define-absent-seam tls-eof-deliveries)
     (define-absent-seam tls-swallowed-errors)
     (define-absent-seam tls-read-trace)
     (define-absent-seam tls-raw-sink-writes)
     (define-absent-seam tls-ssl-op-count)
     (define-absent-seam tls-server-raw-reads)
     (define-absent-seam tls-accept-callback-completions)
     (define-absent-seam tls-gate-open-mark)
     (define-absent-seam tls-live-watcher-count)
     (define-absent-seam tls-live-timer-count)
     (define-absent-seam tls-active-timer-count)
     (define-absent-seam tls-handshaking-count)
     (define (retire-entry-depth) 0)
     (define (retire-depths-init! t entry) (void))
     (define (note-shared-depth! t) (void))
     (define (note-retire-reason! path reason) (void))
     (define (note-timer-free! how) (void))
     (define-absent-seam tls-listener-context-id)
     (define-absent-seam tls-timer-free-path)
     (define-absent-seam tls-conn-in-table?)
     (define-absent-seam tls-last-retire-reason)
     (define (note-effect-depth! t kind) (void))
     (define (note-raw-block! t agg size) 0)
     (define (note-raw-block-done! t agg sz status) (void))
     (define-absent-seam tls-raw-blocks)
     (define-absent-seam tls-conn-charge)
     (define-absent-seam tls-conn-totals)
     (define-absent-seam tls-conn-timer-id)
     (define (note-proc-handle-freed! h) (void))
     (define (note-proc-exit-no-row! h) (void))
     (define (note-spawned-pid! pid) (void))
     (define-absent-seam $proc-last-spawned-pid)
     (define-absent-seam proc-handles-freed)
     (define-absent-seam proc-exit-no-row-handles)
     (define-absent-seam $proc-table-ref)
     (define-absent-seam tls-retire-effect-depths)))

  ;; GC roots (the "keep-live" story):
  ;; - conn-table roots every live connection's Scheme state while libuv
  ;;   holds the raw handle pointer; doubles as fd-leak accounting.
  ;; - write-table roots write-completion closures until the write_cb runs.
  ;; - locked-callbacks below roots the foreign-callable code objects; if
  ;;   the accept callback were collected, the next connection would jump
  ;;   into freed memory -- the classic crash under high concurrency.
  (define conn-table (make-eqv-hashtable))
  (define write-table (make-eqv-hashtable))

  ;; ---- write blocks: one allocator, one release ----------------------------
  ;;
  ;; A write block is the single [uv_write_t][uv_buf_t][payload] allocation a
  ;; queued write needs. Two producers make one -- the plaintext writer and the
  ;; TLS close-notify path -- and seven places can release one, which is why
  ;; this is a pair of helpers rather than a list of call sites: enumerating
  ;; release sites is how the TLS ones came to be missed.
  ;;
  ;; EVERY BLOCK IS ALLOCATED HERE AND RELEASED HERE. A raw foreign-alloc or
  ;; foreign-free of a write block anywhere else is a defect, and the counter
  ;; is what makes one visible: it is exported in the stats, so a test can
  ;; assert allocation balance at a baseline rather than infer it.
  ;;
  ;; INVARIANT: write-blocks-live = (hashtable-size write-table) + blocks
  ;; allocated but not yet registered. The second term is non-zero only
  ;; transiently, inside a writer's own region, so the two numbers agree at
  ;; every baseline.
  (define write-blocks-live 0)
  (define (alloc-write-block! size)
    (let ((b (foreign-alloc size)))
      (set! write-blocks-live (fx+ write-blocks-live 1))
      b))
  (define (free-write-block! block)
    (set! write-blocks-live (fx- write-blocks-live 1))
    (foreign-free block))
  (define (write-blocks-live-count) write-blocks-live)
  (define (write-table-size) (hashtable-size write-table))
  ;; pending outbound connects: req address -> (handle . owner-pid)
  (define connect-table (make-eqv-hashtable))
  ;; pending DNS lookups: getaddrinfo req address -> owner-pid
  (define getaddrinfo-table (make-eqv-hashtable))
  ;; pending async file reads: fs req address -> fs-op record
  (define fs-table (make-eqv-hashtable))
  (define (conn-count) (hashtable-size conn-table))

  ;; ---- child processes -----------------------------------------------------
  ;;
  ;; CHILD LIFETIME AND PIPE CLOSURE ARE SEPARATE FACTS, and conflating them is
  ;; what a single `state` field would do. `child` says whether there is a
  ;; process left to signal; the three pipe fields say what is still open in
  ;; libuv. A child can exit while a grandchild holds its stdout, and a pipe can
  ;; close while the child runs on.
  ;;
  ;; The exported (proc-state p) derives the three names a caller wants:
  ;; `running` while child = running; `exited` once it has exited but the handle
  ;; or a pipe is still open; `closed` when the handle is closed and every pipe
  ;; field is #f. `closed` has exactly one meaning -- nothing of this proc
  ;; remains in libuv -- which is what makes it safe to retire the row on it.
  (define-record-type (proc make-proc proc?)
    (fields
      ;; THE ALLOCATION IS RETAINED UNTIL THE ROW RETIRES. The process close
      ;; callback marks handle-alive? #f and does NOT free: the row is keyed on
      ;; this address, and freeing early would let a later spawn be handed the
      ;; same address while a row still named it. libuv holds no reference to a
      ;; closed handle, so keeping the block costs its size and nothing else.
      (immutable handle proc-handle)
      (immutable owner proc-owner)
      (mutable stdin proc-stdin proc-set-stdin!)     ; conn | #f once closed
      (mutable stdout proc-stdout proc-set-stdout!)
      (mutable stderr proc-stderr proc-set-stderr!)
      ;; #f once the exit callback has run: the pid is reusable from that
      ;; instant, so holding it would be holding something that now names
      ;; somebody else's process.
      (mutable pid proc-pid proc-set-pid!)
      (mutable exit proc-exit proc-set-exit!)        ; #f | (code . signal)
      (mutable child proc-child proc-set-child!)     ; running | exited | orphan
      (mutable handle-alive? proc-handle-alive? proc-set-handle-alive!)
      ;; accepted minus settled stdin bytes -- not "accepted total"
      (mutable queued proc-queued proc-set-queued!)
      (mutable kill-on-owner-death? proc-kill-on-owner-death?
               proc-set-kill-on-owner-death!)))

  ;; keyed on the handle ADDRESS, which is why the block above is retained
  (define proc-table (make-eqv-hashtable))
  ;; pending stdin shutdowns: uv_shutdown_t address -> the pipe conn
  (define shutdown-table (make-eqv-hashtable))
  (define (proc-count) (hashtable-size proc-table))

  ;; HOW MANY CONNS ARE PIPES, MAINTAINED RATHER THAN COUNTED. Walking
  ;; conn-table for this would allocate two vectors proportional to the
  ;; connection count INSIDE the region below -- on the call an http server
  ;; makes to publish its connection count. The counter is maintained at the
  ;; two places a tagged conn enters and leaves the table, the same
  ;; construction the write-block counter uses.
  (define pipe-conns-live 0)
  (define (note-pipe-conn! d) (set! pipe-conns-live (fx+ pipe-conns-live d)))
  (define (pipe-conn-count) pipe-conns-live)

  ;; ONE REGION FOR BOTH READINGS. Taken separately, a conn closing between them
  ;; makes the subtraction report a count no instant ever had.
  (define (socket-conn-count)
    (with-interrupts-disabled
      (fx- (hashtable-size conn-table) pipe-conns-live)))

  (define max-procs 256)
  (define (set-max-procs! n)
    (unless (and (fixnum? n) (fx> n 0))
      (assertion-violation 'set-max-procs! "want a positive fixnum" n))
    (set! max-procs n))
  (define proc-stdin-cap (* 16 1024 1024))
  (define (set-proc-stdin-cap! n)
    (unless (and (fixnum? n) (fx> n 0))
      (assertion-violation 'set-proc-stdin-cap! "want a positive fixnum" n))
    (set! proc-stdin-cap n))
  (define shutdown-immediate-errors 0)

  ;; ---- the F13 repair, and the check that licenses it ----------------------
  ;;
  ;; libuv 1.52.0's uv_spawn removes a failed process handle from the loop's
  ;; handle queue and does NOT re-initialise the node; uv__finish_close later
  ;; removes it again. A queue removal writes q->prev->next and q->next->prev,
  ;; so the second one writes through whatever neighbours the node held at the
  ;; first -- harmless only while those two are unchanged, and corrupting the
  ;; loop's handle list or touching freed memory as soon as any handle is
  ;; created or closed in between. 1.50.0 does not remove at all, so the repair
  ;; must be version-agnostic: it asks the node whether it is still linked
  ;; rather than asking libuv what version it is.
  ;;
  ;; THE SELF-CHECK RUNS ONCE AND GATES THE WHOLE FACILITY. These offsets are
  ;; internal layout, and a wrong one does not raise -- it writes a pointer into
  ;; the middle of another structure. So before the first spawn we build a
  ;; handle whose queue node must be self-consistent and verify it; if it is
  ;; not, every spawn is refused. Refusing a feature is recoverable; a bad
  ;; write is not.
  (define layout-checked #f)          ; #f not yet run | ok | bad
  (define (handle-queue-linked? h)
    ;; h.handle_queue.prev->next == &h.handle_queue
    (let ((node (+ h uv-handle-queue-next-offset))
          (prev (foreign-ref 'void* (+ h uv-handle-queue-prev-offset) 0)))
      (and (not (= prev 0))
           (= (foreign-ref 'void* prev 0) node))))
  (define (handle-queue-self-link! h)
    (let ((node (+ h uv-handle-queue-next-offset)))
      (foreign-set! 'void* (+ h uv-handle-queue-next-offset) 0 node)
      (foreign-set! 'void* (+ h uv-handle-queue-prev-offset) 0 node)))

  ;; THE REMOVAL ITSELF, AND IT EXISTS FOR ONE TEST AND NOTHING ELSE. This is
  ;; uv__queue_remove's body: q->prev->next = q->next; q->next->prev = q->prev.
  ;; The library never performs a removal of its own -- libuv owns that list --
  ;; and the only call is under an injection point that is #f unless a cell
  ;; arms it. It is here so the F13 repair's relink branch can be reached on a
  ;; host whose libuv does not produce that state (1.50.0), where the branch
  ;; would otherwise be untested code that only FreeBSD ever runs.
  (define (handle-queue-remove! h)
    (let ((next (foreign-ref 'void* (+ h uv-handle-queue-next-offset) 0))
          (prev (foreign-ref 'void* (+ h uv-handle-queue-prev-offset) 0)))
      (foreign-set! 'void* prev 0 next)
      (foreign-set! 'void* (+ next 8) 0 prev)))

  ;; -> #t when the layout is as declared. Uses a pipe handle because
  ;; uv_pipe_init needs no descriptor and links the handle like any other.
  (define (check-handle-layout!)
    (or (eq? layout-checked 'ok)
        (and (not (eq? layout-checked 'bad))
             ;; THE LOOP HAS TO EXIST FIRST, and this is not defensive
             ;; decoration: uv-loop is 0 until the scheduler runs uv-init!, and
             ;; uv_pipe_init on a null loop is a segfault, not an error return.
             ;; A check whose failure mode is memory corruption must fail
             ;; CLOSED when it cannot run at all -- refusing the facility is
             ;; recoverable, crashing is not.
             (not (= (uv-loop-handle) 0))
             (let ((h (foreign-alloc (uv-handle-size UV-NAMED-PIPE))))
               (let ((r (uv-pipe-init (uv-loop-handle) h 0)))
                 (cond
                   ((< r 0) (foreign-free h) (set! layout-checked 'bad) #f)
                   (else
                     (let ((ok? (handle-queue-linked? h)))
                       (set! layout-checked (if ok? 'ok 'bad))
                       ;; closed rather than freed: libuv has seen it
                       (uv-close h on-close-entry)
                       ok?))))))))

  ;; Applied to EVERY negative uv_spawn result, before anything else touches
  ;; the handle: both pointers are still valid at this instant because no other
  ;; handle operation has run since uv_spawn returned.
  (define (repair-spawn-queue! h)
    ;; TEST SEAM 'proc-simulate-queue-removal -- OWNING REGION: proc-spawn!'s,
    ;; so this runs with interrupts already off. When armed it performs the
    ;; removal 1.52.0's error: path performs; unarmed the override answers #f
    ;; and no pointer is written.
    (when (inject-override! 'proc-simulate-queue-removal #f)
      (handle-queue-remove! h))
    (if (handle-queue-linked? h)
        ;; COUNTED POINT 'proc-f13-linked -- unarmed: silent; armed it records
        ;; a skip rather than parking, because the caller's region is open.
        ;; This is 1.50.0's shape: the node is still in the loop's list, so
        ;; uv__finish_close will remove it exactly once.
        (inject-barrier! 'proc-f13-linked)
        (begin
          ;; COUNTED POINT 'proc-f13-relinked -- same region, same skip. This
          ;; is 1.52.0's shape: the node was removed and not re-initialised,
          ;; so without the self-link below the close path's removal would
          ;; write through the neighbours the node held at the first removal.
          (inject-barrier! 'proc-f13-relinked)
          (handle-queue-self-link! h))))

  ;; ---- proc lifetime: the derived state, and row retirement ---------------
  ;;
  ;; `closed` IS A CONJUNCTION OVER FOUR FIELDS, and it is written once here
  ;; rather than at each of the places that has to ask. The process handle and
  ;; the three pipes close independently and in any order, so every one of
  ;; them is the potential last one; whichever callback makes this answer true
  ;; is the one that retires the row.
  (define (proc-closed? p)
    (and (not (proc-handle-alive? p))
         (not (proc-stdin p))
         (not (proc-stdout p))
         (not (proc-stderr p))))

  ;; running | exited | closed. `orphan` is not reported: it is a fact about
  ;; how the child was started, not a state a caller can act on, and an orphan
  ;; that has exited is `exited` like any other.
  (define (proc-state p)
    (cond
      ((proc-closed? p) 'closed)
      ((eq? (proc-child p) 'running) 'running)
      (else 'exited)))

  (define (proc-stream-conn p stream)
    (case stream
      ((stdin) (proc-stdin p))
      ((stdout) (proc-stdout p))
      ((stderr) (proc-stderr p))
      (else #f)))

  (define (proc-clear-stream! p stream)
    (case stream
      ((stdin) (proc-set-stdin! p #f))
      ((stdout) (proc-set-stdout! p #f))
      ((stderr) (proc-set-stderr! p #f))
      (else (void))))

  ;; RUN BY WHICHEVER CLOSE CALLBACK MAKES THE PROC `closed` -- the process
  ;; one or a pipe's cleanup closure. Same ordering rule as on-close-code:
  ;; the pointer write first, the allocating step guarded in the middle, the
  ;; free last and unconditional. unindex-owner! allocates (remp), so a raise
  ;; there must not be able to keep the handle block alive forever.
  ;;
  ;; THREE SITES RELEASE A PROCESS HANDLE BLOCK AND ALL THREE ARE COUNTED
  ;; AND LOGGED, which is what makes the freed-address log a complete record
  ;; rather than a partial one: this retirement; the no-row close path, for a
  ;; block no row ever named; and proc-spawn!'s pre-spawn release, for a block
  ;; libuv never saw. Only this one can name an address a row has used, so
  ;; only this one can report the rule being broken -- but a log missing the
  ;; other two would answer "not freed" for reasons it could not distinguish.
  (define (retire-proc-row! p)
    (let ((h (proc-handle p)))
      (hashtable-delete! proc-table h)
      ;; INJECTION POINT 'proc-close-unindex -- OWNING GUARD: the one on this
      ;; line, which is meant to catch it. The swallow is recorded rather than
      ;; re-raised: the index keeps one stale entry, which the owner-death
      ;; traversal re-checks and skips, and everything below still runs.
      (guard (e (#t (note-swallowed! 'proc-close-unindex e)))
        (inject-fault! 'proc-close-unindex)
        (unindex-owner! (proc-owner p) 'proc h))
      ;; THE FREE COMES BEFORE THE INSTRUMENTATION, and that order is the
      ;; point: note-proc-handle-freed! APPENDS in an injected build, so it
      ;; allocates, so it can raise -- and an obligation placed after
      ;; something that can raise is an obligation that can be skipped. The
      ;; address is an integer and is never dereferenced, so recording it
      ;; after the block is gone is exactly as true as recording it before.
      ;; COUNTED POINT 'proc-handle-freed -- unarmed: silent. One hit per
      ;; process handle block released, here, at the no-row close path and at
      ;; proc-spawn!'s pre-spawn release; the address log beside it says WHICH
      ;; block each hit was for.
      (foreign-free h)
      (inject-barrier! 'proc-handle-freed)
      (note-proc-handle-freed! h)))

  ;; The cleanup hook every pipe conn carries. conn-on-close! refuses a tagged
  ;; conn precisely so that this closure cannot be overwritten: it is the only
  ;; thing that clears the proc's field for this stream, and without that the
  ;; proc would never become `closed` and its row would sit in the table for
  ;; the life of the VM.
  (define (make-pipe-cleanup p stream)
    (lambda ()
      (proc-clear-stream! p stream)
      (when (proc-closed? p) (retire-proc-row! p))))

  ;; uv_shutdown_t, for the half-close of a child's stdin. Read from libuv at
  ;; load time exactly as write-req-size and the others are.
  (define shutdown-req-size (uv-req-size UV-SHUTDOWN))

  ;; ---- shutdown requests: one allocator, one release -----------------------
  ;;
  ;; SAME CONSTRUCTION AS THE WRITE BLOCKS ABOVE, and for the same reason: one
  ;; request is allocated in a single place and released in three (the
  ;; pre-submission guard, the negative-submission branch, and the callback),
  ;; and a list of release sites is the shape that lets one be missed. The
  ;; counter is what makes the balance observable at a baseline instead of
  ;; inferred -- shutdown-table alone cannot show it, because a request that
  ;; was allocated and never registered is not in the table and a request the
  ;; callback has just freed has already left it.
  (define shutdown-reqs-live 0)
  (define (alloc-shutdown-req!)
    (let ((r (foreign-alloc shutdown-req-size)))
      (set! shutdown-reqs-live (fx+ shutdown-reqs-live 1))
      r))
  (define (free-shutdown-req! req)
    (set! shutdown-reqs-live (fx- shutdown-reqs-live 1))
    (foreign-free req))

  ;; delivery hook: (deliver owner-pid msg); installed by (igropyr actor)
  (define deliver (lambda (owner msg) (void)))
  (define (uv-set-deliver! proc) (set! deliver proc))

  ;; WHO IS CALLING. The write gate has to record the HOLDER's pid so the
  ;; watcher can monitor it, and this library sits BELOW (igropyr actor) --
  ;; actor imports it, never the other way round -- so identity arrives the
  ;; same way delivery does: a hook the upper layer installs at startup.
  ;;
  ;; #f until installed. A pure libuv program never installs it and never
  ;; needs it: only an APPLICATION write on a TLS connection asks, and such a
  ;; write cannot exist without the actor layer. Asking while it is #f is
  ;; therefore a wiring error and says so, rather than proceeding with no
  ;; identity and a gate nobody can be monitored through.
  (define uv-self #f)
  (define (uv-set-self! proc) (set! uv-self proc))

  ;; WHO MAKES THE WATCHER. Each established TLS connection needs one green
  ;; process, and it must link, monitor and park in a timed receive -- none of
  ;; which exists at this layer. (igropyr tls-watch) installs this hook when it
  ;; is invoked, and http.sc's TLS listen entry imports that library, so any
  ;; program that can open a TLS listener has necessarily installed it while a
  ;; plaintext or pure-libuv program pulls in nothing above actor.
  (define uv-tls-watcher-spawner #f)
  (define (uv-set-tls-watcher-spawner! proc) (set! uv-tls-watcher-spawner proc))

  ;; HOW A PARKED WRITER WAITS. receive is an actor primitive and does not
  ;; exist at this layer, so the wait is supplied from above like identity and
  ;; the watcher are. It is legal to park here precisely because the writer is
  ;; a green process: the identity assertion above has already refused any
  ;; caller running inside a libuv callback frame.
  ;; HOW THIS LAYER ASKS WHETHER A PROCESS IS ALIVE. Two callers, and the
  ;; second is not introspection: the watcher-count seam prunes pids whose
  ;; process died without running an exit, and the retirement's terminal
  ;; notification asks so it can stay silent when the owner is already gone.
  ;; Installed by (igropyr tls-watch) beside the other four. With no hook
  ;; installed the seam simply does not prune, and the notification defaults to
  ;; sending -- a reader parked forever is the worse failure of the two.
  (define uv-alive? #f)
  (define (uv-set-alive?! proc) (set! uv-alive? proc))

  (define uv-gate-wait #f)
  (define (uv-set-gate-wait! proc) (set! uv-gate-wait proc))


  ;; owner pid -> list of resources it may own. This is an INDEX, not the
  ;; truth: entries are added when ownership is established and removed
  ;; by unindex-owner! when a resource is finished with -- but a resource
  ;; handed to another owner leaves its entry behind on purpose, so the
  ;; list is still a superset and every candidate is re-checked against
  ;; the real owner before anything is closed. That
  ;; asymmetry is deliberate -- a stale entry costs one failed check, while
  ;; a MISSING entry would silently skip a resource that had to be freed,
  ;; and conn-set-owner! is exported, so ownership can move at any time.
  ;;
  ;; It exists because uv-owner-died! runs on EVERY process death, and
  ;; scanning four global tables there made each death cost O(all open
  ;; connections): measured at 34.5 us with none and 67.5 us with 6000, so
  ;; a busy server paid for its own concurrency on every request that
  ;; ended. The two quantities that grow under load were multiplying.
  (define owner-index (make-eq-hashtable))

  ;; THE READ AND THE WRITE ARE ONE STEP. Both of these are
  ;; read-modify-write on a table several green processes touch, and
  ;; neither was uninterruptible: a preemption between the read and the
  ;; write dropped whatever the other process had just added. The region
  ;; is nested wherever a caller already holds one -- that is safe, the
  ;; disable is counted -- so callers do not have to know.
  (define (index-owner! owner kind key)
    (when owner
      (with-interrupts-disabled
        (hashtable-set! owner-index owner
          (cons (cons kind key) (hashtable-ref owner-index owner '()))))))

  ;; A cell for owner-index-publish!, built where allocation is allowed.
  ;; Two pairs: the entry itself and the list cell that will carry it.
  ;; Publishing is set-cdr! plus hashtable-set!, and the latter CAN
  ;; allocate -- it adds a key the first time an owner appears, and may
  ;; grow. Preparing separately no longer shortens the region -- both
  ;; callers now prepare INSIDE theirs -- it survives because publishing
  ;; is then a set-cdr! and a store with the key already in hand, not
  ;; the region allocating nothing; an earlier version of this note
  ;; claimed the latter.
  ;; THE KEY IS FILLED IN AT PUBLISH TIME, not here, because the key
  ;; is a foreign address that does not exist yet: the allocation that
  ;; produces it happens inside the region, so that a kill before the
  ;; region can lose nothing but Scheme objects the collector reclaims.
  (define (owner-index-prepare! kind)
    (cons (cons kind #f) '()))

  ;; Push a prepared cell, filling in the key. Caller holds the region.
  ;; NOT allocation-free: the hashtable-set! can add a key or grow the
  ;; table, and either allocates. The split survives because publishing
  ;; is then a set-cdr! and a store with the key already in hand --
  ;; not because it makes the region allocation-free, which an earlier
  ;; version of this note claimed.
  (define (owner-index-publish! owner cell key)
    (when owner
      (set-cdr! (car cell) key)
      (set-cdr! cell (hashtable-ref owner-index owner '()))
      (hashtable-set! owner-index owner cell)))

  ;; Undo owner-index-publish!, and ONLY when the cell is still the head.
  ;; Caller holds the region.
  ;;
  ;; IT IS A NO-OP OTHERWISE, ON PURPOSE. Inside one region nothing
  ;; else can have pushed, so if the cell is the head it was published
  ;; here and popping it is exact.
  ;;
  ;; "NOT THE HEAD" DOES NOT MEAN "NEVER PUBLISHED" IN GENERAL -- a
  ;; synchronous re-entry that called index-owner! after this publish
  ;; would leave the cell below the new head, and this would silently do
  ;; nothing. Nothing does that today (the publish is the last expression
  ;; in every region that uses it), and that is the condition to recheck
  ;; before adding anything after a publish. Where the cell is not the
  ;; head, an
  ;; unindex-owner! sweep here would be a linear search removing an
  ;; entry that some other operation legitimately owns.
  (define (owner-index-unpublish-head! owner cell)
    (when owner
      (when (eq? (hashtable-ref owner-index owner '()) cell)
        (let ((rest (cdr cell)))
          (if (null? rest)
              (hashtable-delete! owner-index owner)
              (hashtable-set! owner-index owner rest))))))

  ;; Drop an entry when the resource is finished with.
  ;;
  ;; Leaving them was defensible while a stale entry only cost a failed
  ;; re-check -- but the list is per OWNER, and an owner can be long-lived.
  ;; A process that reconnects, resolves and reads files for days
  ;; accumulated one entry per operation it ever performed, held for the
  ;; life of that process, and then walked every one of them inside a
  ;; no-interrupts region when it finally died. Removal keeps the cost
  ;; proportional to what removal has reached rather than to what has
  ;; ever happened. It is still a superset of what the owner holds: a
  ;; resource handed to another owner leaves its entry behind on purpose
  ;; (see conn-set-owner!).
  ;;
  ;; Still a superset, not the truth: a resource handed on to another owner
  ;; leaves its entry behind under the old one, and uv-owner-died! re-checks
  ;; every candidate against the real owner before touching it.
  ;; Total entries across every owner. Exported for the same reason as
  ;; conn-count and fs-count: a registration that is never paired with a
  ;; removal has no symptom other than growth, and growth cannot be shown
  ;; to have stopped without a number to compare. It counts entries, not
  ;; owners -- one owner with a thousand stale registrations is the shape
  ;; this is here to catch, and an owner count would read as 1.
  (define (uv-owner-index-count)
    (with-interrupts-disabled
      (let-values (((ks vs) (hashtable-entries owner-index)))
        (let loop ((i 0) (n 0))
          (if (fx= i (vector-length vs))
              n
              (loop (fx+ i 1) (fx+ n (length (vector-ref vs i)))))))))

  ;; THE SEARCH RUNS INSIDE THE REGION, AND THAT COST IS REAL. remp is
  ;; O(n) and allocates, and n is the number of resources this owner has
  ;; OPEN -- so a long-lived owner holding many open resources makes the
  ;; region correspondingly long. That is the price of the read-modify-
  ;; write being atomic, and it is named here rather than hidden: the
  ;; bound is the length of that owner's index list. That list is a
  ;; SUPERSET of what the owner still holds -- a resource handed to
  ;; another owner leaves its entry behind on purpose, see the note at
  ;; conn-set-owner! -- so it is not exactly "open resources", only
  ;; bounded by what removal has not yet reached.
  (define (unindex-owner! owner kind key)
    (when owner
      (with-interrupts-disabled
      (let ((xs (hashtable-ref owner-index owner '())))
        (unless (null? xs)
          (let ((rest (remp (lambda (e)
                              (and (eq? (car e) kind) (equal? (cdr e) key)))
                            xs)))
            (if (null? rest)
                (hashtable-delete! owner-index owner)
                (hashtable-set! owner-index owner rest))))))))

  ;; Ownership is public and mutable -- an application hands a conn to the
  ;; process that will read it, and may hand it on again. The index has to
  ;; learn about every such move, so the setter is the hook rather than the
  ;; raw record field. The old owner's entry is left behind on purpose: it
  ;; becomes a stale candidate, which costs one failed re-check, whereas
  ;; forgetting to add the new one would skip a live resource at teardown.
  ;; The field and the index entry are ONE step. A safe point between them
  ;; is a window in which the new owner can die: uv-owner-died! for that pid
  ;; then finds no entry and skips the resource, and the entry that arrives
  ;; afterwards names a process already gone -- nothing will ever reclaim
  ;; it. Same family as the enqueue-write! and conn-on-close! windows.
  ;; A TAGGED CONN REFUSES THIS. A pipe belongs to its proc: the proc record
  ;; names the owner, the owner index entry was written with that owner, and
  ;; the owner-death traversal reaches the pipe through it. Re-pointing the
  ;; conn alone would leave all three disagreeing, and the disagreement is
  ;; silent -- so it is refused rather than reconciled.
  (define (conn-set-owner! c owner)
    (when (conn-tag c)
      (assertion-violation 'conn-set-owner!
        "a child process pipe cannot change owner" (conn-tag c)))
    (with-interrupts-disabled
      (conn-set-owner-field! c owner)
      (index-owner! owner 'conn (conn-handle c))))

  ;; Reclaim what a dead owner can no longer close itself. A killed
  ;; process does not run its dynamic-wind winders (see actor.sc @kill),
  ;; so a handler killed mid-download would otherwise leak its open fd,
  ;; its 256 KiB foreign chunk buffer and the uv_fs_t for the life of
  ;; the VM -- fs-table roots them, so the GC cannot help. The actor
  ;; layer calls this from its process-teardown path.
  (define (uv-owner-died! owner)
    (with-interrupts-disabled
      (let ((owned (hashtable-ref owner-index owner '())))
        (hashtable-delete! owner-index owner)
        (for-each
          (lambda (entry)
            (let ((kind (car entry)) (key (cdr entry)))
              (case kind
                ;; conn-table is the GC root for both the Scheme record and
                ;; the libuv handle, so leaving one here leaks an fd for the
                ;; lifetime of the VM. Re-check the owner: the index may name
                ;; a conn this process handed on to someone else.
                ((conn)
                 (let ((c (hashtable-ref conn-table key #f)))
                   (when (and c (eq? (conn-owner c) owner))
                     ;; THIS OVERRIDE DISABLES A REAL PROTECTION, and it
                     ;; exists only so a cell can make the WATCHER the sole
                     ;; supplier of the close and see whether it actually
                     ;; supplies it. With owner death closing the conn here
                     ;; AND the watcher aborting on DOWN, either one alone
                     ;; produces the same visible outcome -- so neither can be
                     ;; shown to work while the other is present. It is not a
                     ;; configuration switch: an ordinary build has no such
                     ;; branch at all.
                     (unless (inject-override! 'tls-owner-close-skip #f)
                       (tcp-close! c)))))
                ;; A DESCRIPTOR THE DEAD PROCESS STILL HELD. The write
                ;; side hands fds back to the caller and takes them again
                ;; one syscall at a time, so a process that dies between
                ;; two of its own calls leaves one open with nobody left
                ;; to close it. Closed synchronously here: the fd is
                ;; already ours to release and there is no one to tell.
                ;;
                ;; IT IS A RESOURCE BACKSTOP, NOT A TRANSACTION. What the
                ;; descriptor pointed at may be a half-written file, and
                ;; that is left exactly as it lies -- nothing here
                ;; truncates, deletes or rolls anything back. Reconciling
                ;; a partial write is the caller's protocol, and reading
                ;; this as "the framework tidied up" would be reading it
                ;; as the one thing it does not do.
                ((fsfd)
                 (let ((e (hashtable-ref fsw-fds key #f)))
                   (when (and e (eq? (car e) owner))
                     (let ((gen (cdr e)))
                     (hashtable-delete! fsw-fds key)
                     ;; A RECLAIM MUST COME AFTER THE LAST JOB THAT NAMES
                     ;; IT, or what gets closed is a NUMBER and not a
                     ;; file. A job already handed to the pool has not
                     ;; necessarily entered its syscall yet: close the
                     ;; descriptor here and the number can be reissued to
                     ;; something else before that thread runs, at which
                     ;; point a late write lands in an unrelated file and
                     ;; a late close shuts one. Owner death does not
                     ;; cancel jobs -- it only stops their answers being
                     ;; delivered -- so the wait is real and has to be
                     ;; waited out.
                     ;;
                     ;; THIS COVERS THE CLOSES THIS LIBRARY ISSUES -- the
                     ;; reclaim here and the orphaned-open return -- and
                     ;; not a close the CALLER submits. Ordering its own
                     ;; close after its own outstanding jobs on the same
                     ;; descriptor is the caller's, exactly as it is in C:
                     ;; one thread writing a descriptor while another
                     ;; closes it races the same reissue, and no
                     ;; descriptor API promises otherwise. (igropyr
                     ;; durable-async) is the worked example -- it keeps
                     ;; one job in flight at a time, so the question never
                     ;; arises for it.
                     (if (fd-in-flight? key)
                         (hashtable-set! fsw-closing key gen)
                         (close-fd-now! key))))))
                ;; An in-flight job: the callback is still coming and
                ;; still has to free the request, so only the delivery is
                ;; suppressed. Clearing the owner is what does that --
                ;; the callback checks it before delivering. Deleting the
                ;; entry instead would lose the record that this request
                ;; is outstanding.
                ((fsjob)
                 (let ((j (hashtable-ref fsw-table key #f)))
                   (when (and j (eq? (fsw-job-owner j) owner))
                     (fsw-job-owner-set! j #f))))
                ;; A connect request cannot be synchronously cancelled on
                ;; every supported libuv. Clear its owner instead; on-connect
                ;; then closes a late successful handle rather than
                ;; registering it for a dead pid.
                ((connect)
                 (let ((e (hashtable-ref connect-table key #f)))
                   (when (and e (eq? (vector-ref e 1) owner))
                     (vector-set! e 1 #f))))
                ;; DNS has no handle to close. Suppress its eventual delivery
                ;; while RETAINING the request entry so the callback still
                ;; frees it. Do NOT "simplify" this into a hashtable-delete!:
                ;; on-getaddrinfo runs either way and does the foreign-free,
                ;; so dropping the key here only loses the record that this
                ;; request is still outstanding. Setting #f is safe because
                ;; both delivery sites are guarded by (when owner ...).
                ((dns)
                 (when (eq? (hashtable-ref getaddrinfo-table key #f) owner)
                   (hashtable-set! getaddrinfo-table key #f)))
                ;; an fs op holds an open fd, a 256 KiB foreign chunk buffer
                ;; and the uv_fs_t; fs-table roots them, so the GC cannot help
                ((fs)
                 (let ((op (hashtable-ref fs-table key #f)))
                   (when (and op (eq? (fs-op-owner op) owner))
                     (file-stream-close! op))))
                ;; A CHILD PROCESS WHOSE OWNER IS GONE. This branch signals
                ;; and nothing else: the three pipes are reached by the (conn)
                ;; branch of this same traversal, from their own index
                ;; entries, and the row retires when they and the process
                ;; handle have all closed.
                ;;
                ;; SIGTERM, NOT SIGKILL, and not a close of the handle. An
                ;; active process handle closed before its exit callback
                ;; deregisters the child and leaves it unreaped; the child is
                ;; asked to end and libuv reaps it through the exit callback
                ;; exactly as it would for any other exit.
                ;;
                ;; Owner, child and handle are re-checked here because the
                ;; index is a superset: it can name a proc that has already
                ;; exited, whose handle has already closed, or -- the entry is
                ;; left behind on purpose -- one this pid no longer owns. The
                ;; fourth test is not a re-check but the caller's policy, set
                ;; at spawn.
                ((proc)
                 (let ((p (hashtable-ref proc-table key #f)))
                   (when (and p
                              (eq? (proc-owner p) owner)
                              (proc-kill-on-owner-death? p)
                              (eq? (proc-child p) 'running)
                              (proc-handle-alive? p))
                     (uv-process-kill (proc-handle p) 15))))
                (else (void)))))
          owned))))

  ;; live listeners: handle address -> #(token on-accept), one entry per
  ;; tcp-listen!. Keyed dispatch (not a single global) so several
  ;; servers can listen on different ports in one process; the table
  ;; also roots each listener's accept hook, which nothing else holds
  ;; (the handles themselves are foreign-alloc'd and are not the GC's
  ;; business).
  (define listener-table (make-eqv-hashtable))

  ;; ---- callbacks ----------------------------------------------------

  ;; alloc_cb: hand libuv one shared static buffer. Safe because libuv
  ;; is single-threaded and calls alloc_cb immediately before each
  ;; read_cb; the data is copied out before the next read.
  (define on-alloc-code
    (foreign-callable
      (lambda (handle suggested buf)
        (foreign-set! 'void* buf 0 (uv-read-buf-base))
        (foreign-set! 'unsigned-64 buf 8 (uv-read-buf-size)))
      (void* size_t void*)
      void))

  ;; read_cb: copy bytes into a fresh bytevector and deliver to the
  ;; connection's owner process. Errors/EOF are delivered as messages,
  ;; never raised.
  (define on-read-code
    (foreign-callable
      (lambda (stream nread buf)
        ;; MARKED BEFORE ANY BRANCH. "No tls-branch in the trace" has two
        ;; very different causes -- libuv never called us, or it called us and
        ;; we took the plaintext arm because the tls field was gone -- and the
        ;; existing marks cannot tell them apart. This one is entered on every
        ;; read callback whatever happens next.
        (note-read-stage! (if (fx> nread 0) 'cb+ (if (fx= nread 0) 'cb0 'cb-)))
        (let ((c (hashtable-ref conn-table stream #f)))
          (unless c (note-read-stage! 'cb-no-conn))
          (when c
            (let ((t (conn-tls c)))
              (unless t (note-read-stage! 'cb-plain))
              (cond
                ;; THE TLS BRANCH COMES FIRST, AND DELIBERATELY DOES NOT
                ;; TEST conn-owner. A TLS connection has NO owner until its
                ;; handshake completes (Z12 installs it at establishment), so
                ;; the owner gate below would drop every handshake byte and
                ;; the handshake would never advance.
                (t (note-read-stage! 'tls-branch) (tls-on-read c t nread buf))
                ;; A CHILD'S PIPE, WHICH IS A SEPARATE CLAUSE AND NOT A SHAPE
                ;; CHOICE INSIDE THE ONE BELOW. The delivery shape does depend
                ;; on the tag, but the SELF-CLOSE does not: an EOF on a pipe
                ;; has to release the handle whether or not there is an owner
                ;; to tell, and folding this into the owner-gated clause would
                ;; make a proc with no owner keep its pipe rows -- and so its
                ;; proc row -- for the life of the VM. A pipe conn is never a
                ;; TLS conn, so this sits second only to keep the TLS clause
                ;; first for the reason given above.
                ((conn-tag c)
                 ;; THE DELIVERY IS GUARDED HERE AND NOT IN THE ARM BELOW, and
                 ;; the asymmetry is deliberate. Both arms allocate -- the
                 ;; bytevector, the message vector, and the mailbox cell inside
                 ;; deliver -- and for a plain TCP conn a raise there unwinds
                 ;; into C, which is the accepted, pre-existing and TCP-wide
                 ;; residual this file already states. A PIPE HAS A SECOND
                 ;; CASUALTY the plaintext arm does not: the tcp-close! below
                 ;; is the only thing that releases this pipe, clears the
                 ;; proc's field for this stream and lets the row retire, and
                 ;; a raise on the way to it would skip all three. So the
                 ;; notification is contained and the release is not.
                 ;;
                 ;; Losing the message is the cheaper failure: the owner still
                 ;; learns the stream ended, because the close and the child's
                 ;; exit are both still coming.
                 (let* ((tag (conn-tag c))
                        (p (car tag))
                        (stream (cdr tag))
                        (owner (conn-owner c)))
                   (cond
                     ((> nread 0)
                      (when owner
                        (guard (e (#t (note-swallowed! 'proc-read-deliver e)))
                          (let ((bv (make-bytevector nread)))
                            (memcpy-from-c bv (foreign-ref 'void* buf 0) nread)
                            (deliver owner (vector 'proc-data p stream bv))))))
                     ;; spurious wakeup; ignore
                     ((= nread 0) (void))
                     (else
                      ;; NOTIFY, THEN RELEASE. The message names a conn the
                      ;; owner may still hold, and tcp-close! only schedules,
                      ;; so the order costs nothing and keeps the owner's view
                      ;; ahead of the teardown. The close runs whether or not
                      ;; the notification got through.
                      (when owner
                        (guard (e (#t (note-swallowed! 'proc-read-deliver e)))
                          (deliver owner
                            (if (= nread UV-EOF)
                                (vector 'proc-eof p stream)
                                (vector 'proc-error p stream nread)))))
                      (tcp-close! c)))))
                ;; the plaintext path, unchanged: still owner-gated
                ((conn-owner c)
                 (cond
                   ((> nread 0)
                    (let ((bv (make-bytevector nread)))
                      (memcpy-from-c bv (foreign-ref 'void* buf 0) nread)
                      (deliver (conn-owner c) (vector 'tcp-data bv))))
                   ((= nread 0) (void))   ; spurious wakeup; ignore
                   ((= nread UV-EOF)
                    (deliver (conn-owner c) (vector 'tcp-eof)))
                   (else
                    (deliver (conn-owner c) (vector 'tcp-error nread)))))
                (else (void)))))))
      (void* ssize_t void*)
      void))

  ;; close_cb: the single place where handle memory is freed.
  ;; ORDERED SO THAT NOTHING ALLOCATING PRECEDES SOMETHING UNCONDITIONAL.
  ;; unindex-owner! allocates, and it ran first and unguarded: a raise there
  ;; skipped the state change, the cleanup hook and the free, so one
  ;; allocation failure leaked a handle and left a conn that never finished
  ;; closing. The pointer writes now happen first, the fallible step is
  ;; guarded and counted, and the free is last and unconditional. Additive
  ;; for TCP: the same steps, in an order that survives a failure in any one.
  (define on-close-code
    (foreign-callable
      (lambda (handle)
        (let ((c (hashtable-ref conn-table handle #f)))
          (hashtable-delete! conn-table handle)
          (when c
            (when (conn-tag c) (note-pipe-conn! -1))
            (conn-set-state! c 'closed)
            ;; INJECTION POINT 'conn-close-unindex (fault) -- OWNING GUARD:
            ;; the one on the next line, which is meant to catch it. Nothing
            ;; else in this file can make unindex-owner! raise, and a guard
            ;; nothing can drive is a branch no cell can reach. The swallow is
            ;; recorded rather than re-raised: the owner index keeps a stale
            ;; entry, which the owner-death traversal re-checks and skips, and
            ;; the cleanup hook and the free below still run.
            (guard (e (#t (note-swallowed! 'conn-close-unindex e)))
              (inject-fault! 'conn-close-unindex)
              (unindex-owner! (conn-owner c) 'conn handle))
            (let ((clean (conn-cleanup c)))
              (when clean
                (conn-set-cleanup! c #f)
                ;; callback context: an escaping raise would unwind into C
                (guard (e (#t (void))) (clean))))))
        (foreign-free handle))
      (void*)
      void))

  ;; write_cb: run the stored completion closure, free the whole
  ;; [uv_write_t][uv_buf_t][payload] block in one shot.
  (define on-write-code
    (foreign-callable
      (lambda (req status)
        (let ((done (hashtable-ref write-table req #f)))
          (hashtable-delete! write-table req)
          (free-write-block! req)
          (when done (done status))))
      (void* int)
      void))

  ;; exit_cb: the child has been reaped. INVALIDATE FIRST, NOTIFY SECOND,
  ;; RELEASE LAST -- the order is the point.
  ;;
  ;; Step 2 below allocates nothing and cannot fail, and it is what makes the
  ;; record safe to read from anywhere afterwards: `pid` stops naming a
  ;; process the moment one is reaped, because that number is reusable from
  ;; that instant, and `child` stops saying there is something to signal. If
  ;; the notification ran first and raised, both would still claim a live
  ;; child that no longer exists.
  ;;
  ;; Step 5 is outside the guard and unconditional. A notification that
  ;; raised must not be able to leave the process handle registered in the
  ;; loop for the life of the VM.
  (define on-process-exit-code
    (foreign-callable
      (lambda (handle status signal)
        (let ((p (hashtable-ref proc-table handle #f)))
          (if (not p)
              ;; A MISS IS ONE SHAPE ONLY: an orphan whose row could not be
              ;; published (proc-spawn!'s rollback says so explicitly). The
              ;; handle is still registered and still ours to release, so the
              ;; no-row close path below closes and frees it.
              ;; COUNTED POINT 'proc-exit-cb-no-row -- unarmed: silent. The
              ;; address log beside it is what lets a cell say WHICH handle
              ;; took this path.
              ;; THE CLOSE IS THE OBLIGATION AND GOES FIRST. The log below
              ;; allocates in an injected build; behind it, a raise would
              ;; leave this handle registered in the loop for the life of the
              ;; VM. uv_close only schedules, so the address is still a
              ;; perfectly good thing to record afterwards.
              (begin
                (uv-close handle on-process-close-entry)
                (inject-barrier! 'proc-exit-cb-no-row)
                (note-proc-exit-no-row! handle))
              (begin
                ;; (2) unconditional, allocation-free invalidation. An orphan
                ;; stays an orphan: that field records how the child was
                ;; started, and the rollback that wrote it still owns the
                ;; reading that there is nobody to notify.
                (when (eq? (proc-child p) 'running) (proc-set-child! p 'exited))
                (proc-set-pid! p #f)
                ;; (3) guarded, because both the pair and the message
                ;; allocate. A swallow here loses the notification and
                ;; nothing else.
                ;; INJECTION POINT 'proc-exit-notify (fault) -- OWNING
                ;; GUARD: the one on the line above, which is meant to catch
                ;; it. It stands for the allocation in either the pair or the
                ;; message; a swallow loses the notification and leaves the
                ;; invalidation in step 2 and the close in step 5 intact.
                (guard (e (#t (note-swallowed! 'proc-exit-notify e)))
                  (inject-fault! 'proc-exit-notify)
                  (proc-set-exit! p (cons status signal))
                  (unless (eq? (proc-child p) 'orphan)
                    (deliver (proc-owner p) (vector 'proc-exit p status signal))))
                ;; (4) NO READER REMAINS, so stdin is closed here rather than
                ;; left for the owner. Writes still queued on it fail through
                ;; their completions with ECANCELED and are refunded, which is
                ;; the accounting proc-write! promises.
                (let ((in (proc-stdin p)))
                  (when in (tcp-close! in)))
                ;; (5) unconditional, outside every guard
                (uv-close handle on-process-close-entry)))))
      (void* integer-64 int)
      void))

  ;; close_cb for the process handle, and THE ONE THAT DOES NOT FREE. The row
  ;; is keyed on this address; freeing here would let a later spawn be handed
  ;; the same address while a row still named it, and that row's own cleanup
  ;; would then delete the newcomer's entry. The block is released at row
  ;; retirement instead -- or here, when no row ever named it.
  (define on-process-close-code
    (foreign-callable
      (lambda (handle)
        (let ((p (hashtable-ref proc-table handle #f)))
          (if (not p)
              ;; the no-row close path: nothing names this block.
              ;; COUNTED POINT 'proc-handle-freed -- free first, instrument
              ;; second, for the reason given at retire-proc-row!.
              (begin (foreign-free handle)
                     (inject-barrier! 'proc-handle-freed)
                     (note-proc-handle-freed! handle))
              (begin
                (proc-set-handle-alive! p #f)
                (when (proc-closed? p) (retire-proc-row! p))))))
      (void*)
      void))

  ;; shutdown_cb for a child's stdin. THE REQUEST IS FREED ON EVERY PATH AND
  ;; EXACTLY ONCE: look up, delete, free, before anything that could take a
  ;; different branch.
  ;;
  ;; THE STATE TEST IS WHAT REFUSES A CANCELLED REQUEST, not a comparison
  ;; against UV_ECANCELED. uv_close cancels a queued shutdown and delivers
  ;; that status, and it is uv_close -- from proc-close!, owner death, or the
  ;; child's exit -- that produces the only cancellations there are; every one
  ;; of those set the conn to `closing` before calling it, so "still open" is
  ;; already false when the cancelled callback arrives. The numeric constant
  ;; is deliberately not used: UV_ECANCELED is -ECANCELED, and ECANCELED is 85
  ;; on FreeBSD and 89 on macOS, so a literal would be wrong on one of the two
  ;; hosts this ships to and there is no binding here that translates it.
  (define on-shutdown-code
    (foreign-callable
      (lambda (req status)
        (let ((c (hashtable-ref shutdown-table req #f)))
          (hashtable-delete! shutdown-table req)
          (free-shutdown-req! req)
          ;; callback context: an escaping raise would unwind into C
          (guard (e (#t (note-swallowed! 'proc-shutdown-cb e)))
            (when c (tcp-close-raw! c)))))
      (void* int)
      void))

  ;; connection_cb: accept, register, hand the conn to the upper layer.
  ;; Accept errors are swallowed; the listener must stay alive.
  ;; Accept failures, counted rather than logged. Two of them, because
  ;; they mean different things: `error` is the listener callback being
  ;; handed a negative status by libuv; `refused` is uv_accept declining
  ;; a connection that was already announced.
  ;;
  ;; COUNTED BECAUSE THE ALTERNATIVE WAS NOTHING AT ALL. Both branches
  ;; discard silently -- correctly, since the listener has to stay alive
  ;; -- so a server dropping every arrival looked exactly like a server
  ;; nobody was calling. The kernel counts what it refuses itself; this
  ;; is the half that happens after the kernel handed the connection up.
  ;;
  ;; SATURATING, NOT WRAPPING. A wrapped counter reports a small number
  ;; after a large failure, and small numbers are the ones that get
  ;; ignored; at the ceiling this one stops moving instead, which is
  ;; "at least this many".
  ;;
  ;; THAT IS STILL A LOSS, AND IN A MISLEADING DIRECTION: an observer
  ;; watching deltas sees a saturated counter stop changing and can read
  ;; that as recovery. Saturation is chosen because the alternative is
  ;; worse, not because it is safe.
  (define accept-error-count 0)
  (define accept-refused-count 0)
  (define (bump-saturating n)
    (if (fx< n (greatest-fixnum)) (fx+ n 1) n))
  ;; BOTH VALUES ARE READ IN ONE REGION, then the list is built
  ;; outside it. Reading them across the allocations of the list would
  ;; let a bump land in between, so the pair returned could pair an old
  ;; error count with a new refused count -- a combination that never
  ;; existed. Individual fixnums are never torn; it is the PAIR that
  ;; needs the region, and callers comparing deltas are exactly who
  ;; would be misled.
  (define (uv-accept-failure-counts)
    (let-values (((e r) (with-interrupts-disabled
                          (values accept-error-count
                                  accept-refused-count))))
      (list (cons 'error e) (cons 'refused r))))

  (define on-connection-code
    (foreign-callable
      (lambda (server status)
       ;; AN OUTER GUARD, BECAUSE THIS IS A FOREIGN CALLABLE FRAME. Before
       ;; tls-accept! is even entered, foreign-alloc and make-conn can raise
       ;; under allocation pressure, and an exception leaving here unwinds
       ;; into C. The handler does the least it can and cannot itself raise.
       (guard (e (#t (note-swallowed! 'on-connection e)
                     (set! accept-error-count (bump-saturating accept-error-count))
                     (void)))
        (if (< status 0)
            ;; NO CELL COVERS THIS BRANCH. Making libuv hand a negative
            ;; status to a listener callback needs a condition this suite
            ;; cannot create; the counter is here so it is visible if it
            ;; happens in the field, and it is recorded as uncovered
            ;; rather than counted as tested.
            ;;
            ;; It is not the same event as a refusal: this is the accept
            ;; itself having failed, possibly before the kernel had a
            ;; connection to hand up at all, which is why the two are
            ;; counted separately.
            (set! accept-error-count (bump-saturating accept-error-count))
            (let ((client (foreign-alloc tcp-handle-size)))
              (uv-tcp-init (uv-loop-handle) client)
              ;; INJECTION POINT 'accept-refused -- OWNING GUARD: none in
              ;; this callback, and none may be added: it runs in foreign
              ;; callback context, where an escaping raise unwinds into C.
              ;; The injected value is a return rather than a raise, so it
              ;; takes the refusal branch as a real failure would.
              ;;
              ;; OVERRIDE, NOT RETURN, AND THE DIFFERENCE IS THE WHOLE
              ;; POINT HERE. uv_accept must actually RUN. libuv's
              ;; uv__server_io accept()s into server->accepted_fd before
              ;; calling this callback, and if the callback returns
              ;; without consuming it, uv__io_stop removes the listener
              ;; from the poll set -- permanently. A real uv_accept
              ;; failure closes that fd and calls uv__io_start, so the
              ;; listener survives one refusal. Skipping the call
              ;; therefore does not simulate a refusal; it simulates a
              ;; dead listener, which is a different defect wearing the
              ;; same errno. Measured: with inject-return! here, the cell
              ;; saw the second connection never accepted.
              ;;
              ;; What override leaves behind was checked and is clean: the
              ;; real accepted socket is closed by uv-close, its block is
              ;; freed by the close callback, no conn is built, and
              ;; neither conn-table nor owner-index gains an entry. The
              ;; timing differs from a real failure -- which closes the
              ;; descriptor inside uv_accept rather than attaching it to a
              ;; handle first -- but nothing persistent is left.
              (if (< (inject-override! 'accept-refused
                                       (uv-accept server client)) 0)
                  (begin
                    (set! accept-refused-count
                          (bump-saturating accept-refused-count))
                    (uv-close client on-close-entry))
                (let ((c (make-conn client #f 'open #f #f #f #f #f))
                      ;; #(token on-accept handshaking tls-ctx handle)
                      (v (hashtable-ref listener-table server #f)))
                  (uv-tcp-nodelay client 1)
                  (let ((ctx (incarnation-tls-ctx v)))
                    (cond
                      ((not v)
                       (hashtable-set! conn-table client c)
                       ;; listener already stopped: refuse the straggler
                       (tcp-close! c))
                      ;; THE TLS PATH PUBLISHES ITSELF. X2 requires the
                      ;; session to be installed in the conn BEFORE the conn
                      ;; reaches conn-table, so that a failure before
                      ;; publication is cleaned up by the only code that can
                      ;; see the session. The insert therefore moves inside
                      ;; tls-accept! rather than happening here.
                      (ctx (tls-accept! c v ctx))
                      (else
                        (hashtable-set! conn-table client c)
                        ((vector-ref v 1) c))))))))))
      (void* int)
      void))

  (define (addrinfo->ipv4 ai)
    (let loop ((ai ai))
      (if (= ai 0)
          #f
          (if (= (foreign-ref 'int ai 4) AF-INET)
              (let ((sa (foreign-ref 'void* ai addrinfo-address-offset)))
                (string-append
                  (number->string (foreign-ref 'unsigned-8 sa 4)) "."
                  (number->string (foreign-ref 'unsigned-8 sa 5)) "."
                  (number->string (foreign-ref 'unsigned-8 sa 6)) "."
                  (number->string (foreign-ref 'unsigned-8 sa 7))))
              (loop (foreign-ref 'void* ai addrinfo-next-offset))))))

  ;; Async file reads as an open -> fstat -> bounded read -> close
  ;; chain, all on libuv's thread pool. Two modes share the machinery:
  ;;   whole  -- accumulate every chunk, deliver #(file-read ,body) once
  ;;             (file-read-async!)
  ;;   stream -- deliver one #(file-chunk ,bv) per read and park until
  ;;             the consumer pulls again (file-stream-read!): flow
  ;;             control is the consumer's write pace, so a large file
  ;;             is served in constant memory (one chunk in flight).
  ;;             With file-stream-raw! the chunk STAYS in the op's C
  ;;             buffer and only its length is delivered -- the consumer
  ;;             sends it with tcp-write-foreign! (buffer -> kernel, no
  ;;             per-chunk Scheme allocation, no GC traffic).
  (define file-read-chunk-size 65536)
  ;; stream reads use bigger chunks: fewer thread-pool round trips per
  ;; GB; memory per in-flight download is still just one chunk
  (define stream-chunk-size 262144)

  (define-record-type (fs-op make-fs-op fs-op?)
    (fields
      (mutable owner fs-op-owner fs-op-owner-set!)   ; delivery target pid
      (immutable path fs-op-path)
      (immutable mode fs-op-mode)                    ; whole | stream
      ;; MUTABLE ONLY SO IT CAN BE FILLED IN AFTER THE ALLOCATION. The
      ;; record is built with req = #f and the foreign-alloc happens a
      ;; few lines later -- both inside the region now; see fs-start!.
      ;; Nothing else ever writes it, and it is set exactly once, before
      ;; the op is published anywhere.
      (mutable req fs-op-req fs-op-req-set!)         ; uv_fs_t address
      (mutable phase fs-op-phase fs-op-phase-set!)   ; open|fstat|idle|read|close
      (mutable aborted? fs-op-aborted? fs-op-aborted?-set!)
      (mutable raw? fs-op-raw? fs-op-raw?-set!)      ; deliver lengths, not bvs
      (mutable fd fs-op-fd fs-op-fd-set!)
      (mutable size fs-op-size fs-op-size-set!)
      (mutable offset fs-op-offset fs-op-offset-set!)
      (mutable chunks fs-op-chunks fs-op-chunks-set!)
      (mutable data fs-op-data fs-op-data-set!)       ; C read buffer
      (mutable buf fs-op-buf fs-op-buf-set!)))         ; uv_buf_t

  (define (fs-chunk-cap op)
    (if (eq? (fs-op-mode op) 'stream) stream-chunk-size file-read-chunk-size))

  (define (fs-body op)
    (let ((out (make-bytevector (fs-op-offset op))))
      (let loop ((xs (reverse (fs-op-chunks op))) (off 0))
        (unless (null? xs)
          (let ((bv (car xs)))
            (bytevector-copy! bv 0 out off (bytevector-length bv))
            (loop (cdr xs) (+ off (bytevector-length bv))))))
      out))

  ;; ---- fs request blocks, counted -----------------------------------
  ;;
  ;; THE COUNT AND THE BLOCK MOVE IN ONE REGION. A counter bumped
  ;; outside the region that allocates can be read between the two, and
  ;; the reading is then a number that no state ever had. Callers that
  ;; already hold a region nest for nothing.
  ;;
  ;; IT RECORDS, IT DOES NOT RESCUE. Nothing here frees a block whose
  ;; owner died; the count is how a test SEES that leak, not a mechanism
  ;; that prevents it. A rising count is a real leak and stays one.
  ;;
  ;; SCOPE IS fs-req-size BLOCKS ONLY. Write, connect and getaddrinfo
  ;; requests, the dirent buffers and the read and write payloads are
  ;; foreign-alloc'd too and are NOT counted here, so this number is not
  ;; "libuv memory" and must not be read as a total.
  (define fs-req-blocks 0)
  (define (fs-req-block-count) fs-req-blocks)
  (define (fs-req-alloc!)
    (with-interrupts-disabled
      (let ((p (foreign-alloc fs-req-size)))
        (set! fs-req-blocks (fx+ fs-req-blocks 1))
        p)))
  (define (fs-req-free! p)
    (with-interrupts-disabled
      (foreign-free p)
      (set! fs-req-blocks (fx- fs-req-blocks 1))))

  (define (fs-cleanup! op req)
    (when (> (fs-op-data op) 0) (foreign-free (fs-op-data op)))
    (when (> (fs-op-buf op) 0) (foreign-free (fs-op-buf op)))
    (unindex-owner! (fs-op-owner op) 'fs req)
    (hashtable-delete! fs-table req)
    (fs-req-free! req))

  (define (fs-fail! op req errno)
    ;; if a fd is open, close it (fire-and-forget) before reporting
    (when (>= (fs-op-fd op) 0)
      (let ((creq (fs-req-alloc!)))
        (uv-fs-close (uv-loop-handle) creq (fs-op-fd op) 0)   ; sync close, ignore
        (uv-fs-req-cleanup creq)
        (fs-req-free! creq)))
    (deliver (fs-op-owner op) (vector 'file-error errno))
    (fs-cleanup! op req))

  (define (regular-file-mode? mode)
    (= (bitwise-and mode S-IFMT) S-IFREG))

  ;; Deliver the completion and release the op. Reached only after
  ;; every read completed, so a close error (rare; e.g. NFS) must not
  ;; discard the data -- success is reported regardless of how close
  ;; went. whole mode reports the accumulated body; stream mode reports
  ;; end-of-stream; an aborted stream reports nothing.
  (define (fs-finish! op req)
    (unless (fs-op-aborted? op)
      (deliver (fs-op-owner op)
        (if (eq? (fs-op-mode op) 'stream)
            (vector 'file-eof)
            (vector 'file-read (fs-body op)))))
    (fs-cleanup! op req))

  ;; Release an aborted stream: close the fd (if open) reusing the op's
  ;; req, then free everything. Nothing is delivered.
  (define (fs-quiet-close! op req)
    (if (< (fs-op-fd op) 0)
        (fs-cleanup! op req)
        (begin
          (fs-op-phase-set! op 'close)
          (let ((r (uv-fs-close (uv-loop-handle) req (fs-op-fd op) on-fs-entry)))
            (when (< r 0)
              (uv-fs-req-cleanup req)
              (let ((creq (fs-req-alloc!)))
                (uv-fs-close (uv-loop-handle) creq (fs-op-fd op) 0)   ; sync close
                (uv-fs-req-cleanup creq)
                (fs-req-free! creq))
              (fs-cleanup! op req))))))

  ;; A callback fired on a stream that was aborted while the op was in
  ;; flight: unwind quietly whatever phase it was in.
  (define (fs-abort-step! op req result)
    (uv-fs-req-cleanup req)
    (case (fs-op-phase op)
      ((close) (fs-cleanup! op req))
      ((open)
       (when (>= result 0) (fs-op-fd-set! op result))
       (fs-quiet-close! op req))
      (else (fs-quiet-close! op req))))

  (define (start-fs-close! op req)
    (fs-op-phase-set! op 'close)
    (let ((r (uv-fs-close (uv-loop-handle) req (fs-op-fd op) on-fs-entry)))
      (when (< r 0)
        ;; could not queue the close: close synchronously instead, and
        ;; still deliver -- the data was fully read before this point
        (uv-fs-req-cleanup req)
        (let ((creq (fs-req-alloc!)))
          (uv-fs-close (uv-loop-handle) creq (fs-op-fd op) 0)   ; sync close, ignore
          (uv-fs-req-cleanup creq)
          (fs-req-free! creq))
        (fs-finish! op req))))

  (define (start-fs-fstat! op req)
    (fs-op-phase-set! op 'fstat)
    (let ((r (uv-fs-fstat (uv-loop-handle) req (fs-op-fd op) on-fs-entry)))
      (when (< r 0)
        (uv-fs-req-cleanup req)
        (fs-fail! op req r))))

  (define (start-fs-read! op req)
    (let ((remaining (- (fs-op-size op) (fs-op-offset op))))
      (if (<= remaining 0)
          (start-fs-close! op req)
          (let ((n (min (fs-chunk-cap op) remaining)))
            (fs-op-phase-set! op 'read)
            (foreign-set! 'unsigned-64 (fs-op-buf op) 8 n)
            (let ((r (uv-fs-read (uv-loop-handle) req (fs-op-fd op) (fs-op-buf op) 1
                                 (fs-op-offset op) on-fs-entry)))
              (when (< r 0)
                (uv-fs-req-cleanup req)
                (fs-fail! op req r)))))))

  (define on-fs-code
    (foreign-callable
      (lambda (req)
        (let ((op (hashtable-ref fs-table req #f))
              (result (uv-fs-get-result req)))
          (when op
            (if (fs-op-aborted? op)
                (fs-abort-step! op req result)
                (case (fs-op-phase op)
                  ((open)
                   (uv-fs-req-cleanup req)
                   (if (< result 0)
                       (fs-fail! op req result)
                       (begin
                         (fs-op-fd-set! op result)
                         (start-fs-fstat! op req))))
                  ((fstat)
                   (if (< result 0)
                       (begin
                         (uv-fs-req-cleanup req)
                         (fs-fail! op req result))
                       (let* ((st (uv-fs-get-statbuf req))
                              (mode (foreign-ref 'unsigned-64 st uv-stat-mode-offset))
                              (size (foreign-ref 'unsigned-64 st uv-stat-size-offset)))
                         (uv-fs-req-cleanup req)
                         (fs-op-size-set! op size)
                         (cond
                           ((not (regular-file-mode? mode))
                            (fs-fail! op req UV-EINVAL))
                           ((eq? (fs-op-mode op) 'stream)
                            ;; ready: report the size, then park until the
                            ;; consumer pulls the first chunk
                            (when (> size 0)
                              (let* ((data (foreign-alloc (fs-chunk-cap op)))
                                     (buf (foreign-alloc 16)))
                                (fs-op-data-set! op data)
                                (fs-op-buf-set! op buf)
                                (foreign-set! 'void* buf 0 data)))
                            (fs-op-phase-set! op 'idle)
                            (deliver (fs-op-owner op)
                                     (vector 'file-stream op size)))
                           ((= size 0)
                            (start-fs-close! op req))
                           (else
                            (let* ((data (foreign-alloc (fs-chunk-cap op)))
                                   (buf (foreign-alloc 16)))
                              (fs-op-data-set! op data)
                              (fs-op-buf-set! op buf)
                              (foreign-set! 'void* buf 0 data)
                              (start-fs-read! op req)))))))
                  ((read)
                   (uv-fs-req-cleanup req)
                   (cond
                     ((< result 0) (fs-fail! op req result))
                     ((= result 0) (start-fs-close! op req))   ; early EOF
                     (else
                      (let* ((remaining (- (fs-op-size op) (fs-op-offset op)))
                             (n (min result remaining)))
                        (fs-op-offset-set! op (+ (fs-op-offset op) n))
                        (cond
                          ((fs-op-raw? op)
                           ;; the bytes stay in the op's C buffer; hand
                           ;; over just the length -- the consumer writes
                           ;; straight from the buffer, zero Scheme alloc
                           (fs-op-phase-set! op 'idle)
                           (deliver (fs-op-owner op) (vector 'file-chunk n)))
                          ((eq? (fs-op-mode op) 'stream)
                           ;; hand over one chunk; the next read waits
                           ;; for the consumer's file-stream-read!
                           (let ((bv (make-bytevector n)))
                             (memcpy-from-c bv (fs-op-data op) n)
                             (fs-op-phase-set! op 'idle)
                             (deliver (fs-op-owner op) (vector 'file-chunk bv))))
                          (else
                           (let ((bv (make-bytevector n)))
                             (memcpy-from-c bv (fs-op-data op) n)
                             (fs-op-chunks-set! op (cons bv (fs-op-chunks op)))
                             (if (>= (fs-op-offset op) (fs-op-size op))
                                 (start-fs-close! op req)
                                 (start-fs-read! op req)))))))))
                  ((close)
                   (uv-fs-req-cleanup req)
                   (fs-finish! op req))
                  ;; ---- the three path-only operations ----------------
                  ;; Each delivers once and retires the op; none of them
                  ;; ever held a descriptor, so none goes near the close
                  ;; machinery above.
                  ((stat)
                   (if (< result 0)
                       (begin (uv-fs-req-cleanup req) (fs-fail! op req result))
                       (let ((sb (uv-fs-get-statbuf req)))
                         ;; READ EVERY FIELD BEFORE THE CLEANUP. The
                         ;; statbuf belongs to the request; cleanup is
                         ;; free to release it, so a field fetched
                         ;; afterwards would be reading freed memory.
                         (let ((fields
                                (list
                                  (cons 'dev   (foreign-ref 'unsigned-64 sb uv-stat-dev-offset))
                                  (cons 'mode  (foreign-ref 'unsigned-64 sb uv-stat-mode-offset))
                                  (cons 'nlink (foreign-ref 'unsigned-64 sb uv-stat-nlink-offset))
                                  (cons 'uid   (foreign-ref 'unsigned-64 sb uv-stat-uid-offset))
                                  (cons 'gid   (foreign-ref 'unsigned-64 sb uv-stat-gid-offset))
                                  (cons 'ino   (foreign-ref 'unsigned-64 sb uv-stat-ino-offset))
                                  (cons 'size  (foreign-ref 'unsigned-64 sb uv-stat-size-offset))
                                  (cons 'mtime-sec  (foreign-ref 'long sb uv-stat-mtime-sec-offset))
                                  (cons 'mtime-nsec (foreign-ref 'long sb uv-stat-mtime-nsec-offset))
                                  (cons 'ctime-sec  (foreign-ref 'long sb uv-stat-ctime-sec-offset))
                                  (cons 'ctime-nsec (foreign-ref 'long sb uv-stat-ctime-nsec-offset)))))
                           (uv-fs-req-cleanup req)
                           (unless (fs-op-aborted? op)
                             (deliver (fs-op-owner op) (vector 'file-stat fields)))
                           (fs-cleanup! op req)))))
                  ((unlink)
                   (uv-fs-req-cleanup req)
                   (if (< result 0)
                       (fs-fail! op req result)
                       (begin
                         (unless (fs-op-aborted? op)
                           (deliver (fs-op-owner op) (vector 'file-unlinked)))
                         (fs-cleanup! op req))))
                  ((scandir)
                   (if (< result 0)
                       (begin (uv-fs-req-cleanup req) (fs-fail! op req result))
                       ;; NOTHING MAY UNWIND OUT OF HERE INTO C. This is
                       ;; a libuv callback (see the file header); an
                       ;; exception crossing the C frame corrupts the
                       ;; process. The copy loop below allocates one
                       ;; Scheme string per entry, so on a large listing
                       ;; it is the most likely place in this file to run
                       ;; out of memory -- hence a guard that turns any
                       ;; raise into an errno the owner can read.
                       ;;
                       ;; ORDER: copy every name, THEN clean up, THEN
                       ;; deliver. libuv owns the name buffers and
                       ;; uv_fs_req_cleanup frees them, so a name
                       ;; retained past the cleanup is a dangling
                       ;; pointer. Nothing here keeps one.
                       ;;
                       ;; AND IT IS O(N) INSIDE THE CALLBACK. The
                       ;; scheduler is not running while this loop does;
                       ;; a directory of a million entries pauses the
                       ;; process for the length of a million string
                       ;; allocations. That is the cost of one message
                       ;; carrying a whole listing.
                       (let ((ent (foreign-alloc uv-dirent-size)))
                         (let ((names
                                (guard (e (#t 'oom))
                                  (let loop ((acc '()))
                                    (if (< (uv-fs-scandir-next req ent) 0)
                                        (reverse acc)
                                        (let ((p (foreign-ref 'void* ent
                                                   uv-dirent-name-offset)))
                                          (loop
                                            (cons (let rd ((i 0) (bs '()))
                                                    (let ((b (foreign-ref 'unsigned-8 p i)))
                                                      (if (fx= b 0)
                                                          (utf8->string
                                                            (u8-list->bytevector (reverse bs)))
                                                          (rd (fx+ i 1) (cons b bs)))))
                                                  acc))))))))
                           (foreign-free ent)
                           (uv-fs-req-cleanup req)
                           (unless (fs-op-aborted? op)
                             (deliver (fs-op-owner op)
                               (if (eq? names 'oom)
                                   (vector 'file-error uv-enomem)
                                   (vector 'file-entries names))))
                           (fs-cleanup! op req))))))))))
      (void*)
      void))

  ;; getaddrinfo_cb: tell the owner #(dns-resolved ,ip) or #(dns-failed ,e)
  (define on-getaddrinfo-code
    (foreign-callable
      (lambda (req status ai)
        (let ((owner (hashtable-ref getaddrinfo-table req #f)))
          (hashtable-delete! getaddrinfo-table req)
          ;; THE OTHER HALF OF dns-resolve!'s index-owner!, and this is
          ;; one of TWO places that owe it -- see the submission for the
          ;; other. A no-op when owner is #f: uv-owner-died! cleared it
          ;; and deleted that owner's whole index list in the same step,
          ;; so there is nothing left to remove. That is not the same
          ;; question as the getaddrinfo-table entry a few lines up,
          ;; which is deliberately RETAINED for a dead owner because this
          ;; callback still has to free the request.
          ;; THE FREE BELOW IS MANDATORY AND THIS CALL CAN RAISE.
          ;; unindex-owner! filters the owner's list with remp, so it
          ;; allocates. Unguarded it would skip the free -- and, in a
          ;; foreign callback, unwind into C; the same rule and the same
          ;; shape as the close callback above. Swallowing is the lesser
          ;; residue: a stale index entry costs growth, which
          ;; uv-owner-index-count reports, while the alternatives cost a
          ;; foreign block that nothing will ever free again.
          ;;
          ;; IT MUST STAY BEFORE THE FREE, not after. The key IS the
          ;; freed pointer: once the block is returned, the same address
          ;; can be handed to the next getaddrinfo request, and a removal
          ;; running then would delete that request's registration
          ;; instead of this one's.
          (guard (e (#t (void))) (unindex-owner! owner 'dns req))
          (foreign-free req)
          (if (< status 0)
              (when owner (deliver owner (vector 'dns-failed status)))
              (let ((ip (addrinfo->ipv4 ai)))
                (uv-freeaddrinfo ai)
                (when owner
                  (deliver owner
                    (if ip (vector 'dns-resolved ip) (vector 'dns-failed -1))))))))
      (void* int void*)
      void))

  ;; connect_cb for outbound connections: register the conn and tell the
  ;; owner process #(tcp-connected ,conn) or #(tcp-connect-failed ,errno).
  (define on-connect-code
    (foreign-callable
      (lambda (req status)
        (let ((entry (hashtable-ref connect-table req #f)))
          (hashtable-delete! connect-table req)
          ;; THE OTHER HALF OF index-owner!. Registering the request
          ;; against its owner and never taking it back left one entry
          ;; per connect on that owner's list, for the life of the
          ;; process -- a connector that reconnects on a timer grows it
          ;; without bound, and teardown walks all of it. There is no
          ;; symptom before that: the entry names a request that is
          ;; gone, and the teardown branch for it looks the request up
          ;; and finds nothing. A missing entry is silent, and so is a
          ;; surplus one.
          ;;
          ;; #f owner means uv-owner-died! already emptied that owner's
          ;; list, so there is nothing left to remove.
          (when (and entry (vector-ref entry 1))
            (unindex-owner! (vector-ref entry 1) 'connect req))
          (foreign-free req)
          (when entry
            ;; D IS RETAINED BEFORE THE ENTRY GOES. The request is freed just
            ;; above and the entry is already out of the table, so whatever this
            ;; callback still needs must be held in a local first.
            (let ((handle (vector-ref entry 0))
                  (owner (vector-ref entry 1))
                  (d (vector-ref entry 2))
                  (ctx (vector-ref entry 3))
                  (sni (vector-ref entry 4)))
              (cond
                ((< status 0)
                 (uv-close handle on-close-entry)
                 ;; A TLS dial answers through D, so this failure and any later one
                 ;; cannot both be delivered; a plaintext dial has no D and answers
                 ;; directly, exactly as before.
                 (if d
                     (complete-once! d (vector 'tcp-connect-failed status))
                     (when owner
                       (deliver owner (vector 'tcp-connect-failed status)))))
                ((not owner)
                 ;; The owner died while connect was in flight. The handle closes and
                 ;; TLS is never initialised. D is still marked failed so no later
                 ;; path finds the attempt pending; there is nobody to deliver to, and
                 ;; complete-once! drops the message while keeping the transition.
                 (when d (complete-once! d (vector 'tcp-connect-failed 'owner-gone)))
                 (uv-close handle on-close-entry))
                (else
                 (let ((c (make-conn handle owner 'open #f #f #f #f #f)))
                   ;; index and table together: an owner dying between them
                   ;; is told about a conn that teardown cannot find
                   (with-interrupts-disabled
                     (index-owner! owner 'conn handle)
                     (uv-tcp-nodelay handle 1)
                     (hashtable-set! conn-table handle c))
                   ;; A TLS dial is NOT connected yet: the handshake has not run. Its
                   ;; owner hears nothing until establishment, and the initialiser
                   ;; below owns every failure in between.
                   (if ctx
                       (tls-client-init! c d ctx sni)
                       (deliver owner (vector 'tcp-connected c))))))))))
      (void* int)
      void))



  ;; The per-conn TLS timer and its close callback. Both are locked with the
  ;; rest below: libuv holds their raw entry points, so a collected code
  ;; object would have the loop jump into freed memory.
  (define on-tls-timer-code
    (foreign-callable
      (lambda (handle) (on-tls-timer handle))
      (void*)
      void))

  (define on-tls-timer-close-code
    (foreign-callable
      (lambda (handle) (on-tls-timer-close handle))
      (void*)
      void))

  ;; Lock the callback code objects forever: libuv holds raw entry-point
  ;; pointers into them for the whole process lifetime.

  ;; ---- fs write side: one syscall per job -------------------------------
  ;;
  ;; DELIBERATELY NOT THE SHAPE OF THE READ SIDE ABOVE. That one hides a
  ;; composite sequence -- open, fstat, read, close -- behind a phase
  ;; machine and delivers once at the end, which is right when the library
  ;; owns the whole sequence. Here the caller owns it: a durable write is
  ;; write, flush, rename, flush the directory, and which of those to do,
  ;; in what order, and what to do when one fails are the caller's
  ;; decisions. So each job is one syscall, and the caller awaits them in
  ;; its own green process.
  ;;
  ;; WHAT THIS BUYS is the only reason it exists: the syscall runs on a
  ;; libuv thread-pool thread, so the scheduler keeps running. The
  ;; synchronous equivalents stop every green process in the runtime for
  ;; the duration -- measured elsewhere in this tree at 641ms for one
  ;; call on a busy filesystem.
  ;;
  ;; THE POOL IS SHARED AND SMALL. Four threads by default, shared with
  ;; DNS, and UV_THREADPOOL_SIZE is read once when the pool is first used
  ;; -- so it must be set in the environment before the process starts,
  ;; not from inside it. Enough concurrent file jobs will queue behind
  ;; each other and behind name resolution.
  ;;
  ;; The sequence a durable write needs is plain POSIX. ZFS honours it
  ;; with stronger semantics rather than weaker (the flush goes through
  ;; the intent log, rename is transactional, and the directory flush
  ;; degrades to a harmless no-op), so nothing here probes for a
  ;; filesystem or branches on one.
  (define fsw-table (make-eqv-hashtable))

  ;; fd -> (owner . gen), for the death cleanup below -- the pair, not a
  ;; bare owner; the generation note further down says why. A descriptor
  ;; opened here
  ;; belongs to the caller between calls, which is what "one syscall per
  ;; job" means -- and a caller that dies holding one would otherwise
  ;; leak it with no signal at all. That silent shape is the one this
  ;; library keeps removing; it is not going to be reintroduced by a new
  ;; entry point.
  ;; fd -> (owner . gen); see the generation note further down for why
  ;; the owner alone is not enough to identify a descriptor.
  (define fsw-fds (make-eqv-hashtable))

  (define fsw-next-id 0)

  (define (fsw-fresh-id!)
    (set! fsw-next-id (+ fsw-next-id 1))
    fsw-next-id)

  (define-record-type (fsw-job make-fsw-job fsw-job?)
    (fields
      (immutable id fsw-job-id)
      (mutable owner fsw-job-owner fsw-job-owner-set!)
      (immutable kind fsw-job-kind)         ; open|write|fsync|rename|close
      (immutable fd fsw-job-fd)             ; the fd acted on, or -1
      ;; WHICH TENANCY OF THAT NUMBER THIS JOB MEANT. Captured when the
      ;; job is submitted; see the generation note below.
      (mutable gen fsw-job-gen fsw-job-gen-set!)
      (mutable data fsw-job-data fsw-job-data-set!)   ; C copy of the bytes
      (mutable buf fsw-job-buf fsw-job-buf-set!)))    ; uv_buf_t

  (define (fsw-count) (hashtable-size fsw-table))
  (define (fs-job-count) (fsw-count))

  ;; HOW MANY DESCRIPTORS THIS SIDE IS HOLDING FOR CALLERS. Without it
  ;; the death cleanup above is code that was reviewed rather than
  ;; behaviour that is watched: a test can kill a process holding an fd,
  ;; but with nothing to read it cannot tell a close that happened from
  ;; one that did not. Approximate in the same sense as the job count --
  ;; it is read outside any lock and a job in flight may be about to
  ;; change it.
  (define (fs-fd-count) (hashtable-size fsw-fds))

  ;; Hand a descriptor back to the kernel with no owner to tell. Used
  ;; both when an owner dies and when one dies before its open finishes.
  ;; ITS RESULT IS NOT READ, and its callers say "closed" on the
  ;; strength of that. If this close fails and the OS still holds the
  ;; descriptor, it is now off every book here and nothing will reclaim
  ;; it -- the same unrepairable leak the asynchronous close branch
  ;; already admits to, reached a different way. Retrying is not the
  ;; repair: POSIX leaves the descriptor's state unspecified after a
  ;; failed close, so a second attempt can reach a number that has since
  ;; been reissued.
  (define (close-fd-now! fd)
    (let ((creq (fs-req-alloc!)))
      (uv-fs-close (uv-loop-handle) creq fd 0)
      (uv-fs-req-cleanup creq)
      (fs-req-free! creq)))

  ;; Descriptors whose owner has died while a job still refers to them.
  ;; See uv-owner-died!: closing one while a pool thread is about to act
  ;; on it closes a NUMBER, not a file.
  (define fsw-closing (make-eqv-hashtable))

  ;; HOW MANY IN-FLIGHT JOBS NAME EACH DESCRIPTOR. Counted rather than
  ;; searched: the question is asked once per descriptor when an owner
  ;; dies and again on every completion of a job that named a marked one,
  ;; and a scan of the whole job table each time is quadratic in the
  ;; queue. That work would happen inside owner teardown and inside
  ;; event-loop callbacks -- both places where nothing else in the
  ;; runtime can run -- so a deep queue would turn a bookkeeping question
  ;; into a pause.
  ;; A FILE DESCRIPTOR NUMBER IS A LEASE FROM THE OS, NOT AN IDENTITY.
  ;; The kernel reissues the smallest free number, so the same integer
  ;; names a different file the moment one is closed. Anything of ours
  ;; keyed only by that integer will eventually be asked about a tenancy
  ;; it was not talking about -- a close callback arriving after the
  ;; number has been handed to a new open would strike that new
  ;; registration off the books, and the descriptor it belongs to could
  ;; then never be reclaimed.
  ;;
  ;; So identity here is the number PLUS a generation: fsw-fds holds
  ;; (owner . gen), and each job captures the generation current when it
  ;; was submitted.
  ;;
  ;; WHAT EVERY REMOVAL SITE HAS IN COMMON is the intent -- establish
  ;; that the entry on the books is the one this code is talking about
  ;; before touching it. WHAT DIFFERS is the test, because they are
  ;; answering different questions:
  ;;
  ;;   a completion that arrives late  compares the GENERATION
  ;;                                   -- "is this still the tenancy I
  ;;                                      acted on?"
  ;;   the owner-death reclaim         compares the OWNER
  ;;                                   -- "is this descriptor mine to
  ;;                                      take back?", which a
  ;;                                      generation cannot answer
  ;;
  ;; Stating it as one uniform rule was the earlier wording here, and it
  ;; was wrong about the reclaim; the intent is shared, the test is not.
  ;; None of this reaches the public surface -- the primitives still take
  ;; and return plain descriptors.
  (define fsw-gen 0)
  (define (fsw-next-gen!)
    (set! fsw-gen (+ fsw-gen 1))
    fsw-gen)

  (define (fd-gen fd)
    (let ((e (hashtable-ref fsw-fds fd #f)))
      (and e (cdr e))))

  (define fsw-fd-refs (make-eqv-hashtable))

  (define (fd-ref+! fd)
    (when (>= fd 0)
      (hashtable-set! fsw-fd-refs fd (+ 1 (hashtable-ref fsw-fd-refs fd 0)))))

  (define (fd-ref-! fd)
    (when (>= fd 0)
      (let ((n (- (hashtable-ref fsw-fd-refs fd 0) 1)))
        (if (<= n 0)
            (hashtable-delete! fsw-fd-refs fd)
            (hashtable-set! fsw-fd-refs fd n)))))

  (define (fd-in-flight? fd)
    (> (hashtable-ref fsw-fd-refs fd 0) 0))

  ;; Called once a job has been removed from the table: if it was the
  ;; last one holding a descriptor that was waiting to be closed, this is
  ;; the moment the close is finally safe.
  (define (close-if-drained! fd gen)
    (let ((marked (and (>= fd 0) (hashtable-ref fsw-closing fd #f))))
      (when (and marked (eqv? marked gen) (not (fd-in-flight? fd)))
        (hashtable-delete! fsw-closing fd)
        (close-fd-now! fd))))

  (define (fsw-free! job req)
    (fd-ref-! (fsw-job-fd job))
    (when (> (fsw-job-data job) 0) (foreign-free (fsw-job-data job)))
    (when (> (fsw-job-buf job) 0) (foreign-free (fsw-job-buf job)))
    (unindex-owner! (fsw-job-owner job) 'fsjob req)
    (hashtable-delete! fsw-table req)
    (uv-fs-req-cleanup req)
    (fs-req-free! req))

  ;; A job whose owner died is completed and dropped rather than
  ;; delivered: the callback still runs, and it still has to free the
  ;; request and the copied bytes.
  (define on-fsw-code
    (foreign-callable
      (lambda (req)
        (let ((job (hashtable-ref fsw-table req #f)))
          (when job
            (let ((rc (uv-fs-get-result req))
                  (owner (fsw-job-owner job)))
              ;; an open that succeeded hands the caller a descriptor, so
              ;; it goes on the books; a close takes it off whether it
              ;; succeeded or not, for the reason spelled out on that
              ;; branch
              (case (fsw-job-kind job)
                ((open)
                 (cond
                   ((< rc 0) (void))
                   (owner
                    (hashtable-set! fsw-fds rc (cons owner (fsw-next-gen!)))
                    (index-owner! owner 'fsfd rc))
                   ;; AN OPEN THAT SUCCEEDED FOR A CALLER THAT IS GONE.
                   ;; Nobody will ever be told this descriptor exists, so
                   ;; it can never be closed by anyone: the owner sweep
                   ;; has already run and found nothing, and it is not on
                   ;; the books to be found later. The only correct thing
                   ;; to do with it is give it straight back.
                   (else (close-fd-now! rc))))
                ((close)
                 (let* ((fd (fsw-job-fd job))
                        (e (hashtable-ref fsw-fds fd #f)))
                   ;; ONLY IF THE BOOKS STILL MEAN THE FILE WE CLOSED.
                   ;; A callback that arrives after the number has been
                   ;; reissued would otherwise strike off a registration
                   ;; belonging to a live owner, whose descriptor could
                   ;; then never be reclaimed.
                   (when (and e (eqv? (cdr e) (fsw-job-gen job)))
                     (hashtable-delete! fsw-fds fd)
                     (unindex-owner! owner 'fsfd fd))
                   ;; STRUCK OFF WHETHER OR NOT IT CLOSED. On success it
                   ;; is closed and anything waiting to close it must not
                   ;; close the number again. On failure POSIX leaves the
                   ;; descriptor's state unspecified, and trying again can
                   ;; reach a number that has since been reissued -- so
                   ;; there is nothing safe left to do with it either. The
                   ;; books are cleared in both cases because in neither
                   ;; case may this side touch the number again; on the
                   ;; failing one that means a descriptor the OS may still
                   ;; hold is no longer tracked, which is a real leak with
                   ;; no safe repair from here.
                   (let ((marked (hashtable-ref fsw-closing fd #f)))
                     (when (and marked (eqv? marked (fsw-job-gen job)))
                       (hashtable-delete! fsw-closing fd)))))
                (else (void)))
              (when owner
                (deliver owner (vector 'fs-done (fsw-job-id job) rc)))
              (let ((fd (fsw-job-fd job)) (gen (fsw-job-gen job)))
                (fsw-free! job req)
                ;; After the job leaves the table, so this cannot see
                ;; itself as a reason to keep waiting.
                (close-if-drained! fd gen))))))
      (void*) void))

  ;; Submit one job. The id comes back at once and names the completion;
  ;; without it two jobs from the same process would arrive as the same
  ;; message and could not be told apart.
  ;; REGISTERING AND SUBMITTING ARE ONE ACT. Between the table entry and
  ;; the call that hands the request to libuv, this process can be
  ;; preempted and killed -- and then its continuation is discarded, `go`
  ;; never runs, and no callback is ever coming for a job that is on the
  ;; books. The owner sweep finds that job, waits for a completion that
  ;; cannot arrive, and everything it names is stranded: the request, the
  ;; copied bytes, and now the descriptor too, since a job that never
  ;; completes keeps fd-in-flight? true for ever and the deferred close
  ;; is never reached. Making the pair indivisible is what stops a job
  ;; existing that nothing will finish.
  ;; WHAT THIS REGION DOES NOT COVER. The request block, and for a write
  ;; the C buffer and the byte-by-byte copy into it, are allocated by the
  ;; caller of this procedure and therefore BEFORE the region opens. A
  ;; process killed in the middle of that copy leaks exactly those
  ;; allocations: nothing has them on any book yet, and the continuation
  ;; that would free them is gone.
  ;;
  ;; Pulling them inside is not the repair it looks like. The copy is
  ;; proportional to the payload -- a 192 MiB write is tens of
  ;; milliseconds of it -- and running that with interrupts held would
  ;; stop every green process for the duration, which is the single
  ;; thing the asynchronous path exists to avoid. So the region covers
  ;; what it can cover cheaply: from the moment anything is on the books
  ;; to the moment the request is in libuv's hands. A descriptor is never
  ;; stranded by the gap, because the reference count is not incremented
  ;; until inside; what the gap can lose is C memory.
  (define (fsw-submit! owner kind fd data buf go)
    (with-interrupts-disabled
      (let* ((req (fs-req-alloc!))
             (job (make-fsw-job (fsw-fresh-id!) owner kind fd #f data buf)))
        ;; Captured here, inside the atom that registers the job: which
        ;; tenancy of this number the job meant.
        (fsw-job-gen-set! job (fd-gen fd))
        (hashtable-set! fsw-table req job)
        (index-owner! owner 'fsjob req)
        (fd-ref+! fd)
        (let ((r (guard (e (#t
                            ;; THE SUBMISSION RAISED, so no callback is
                            ;; coming for a job that is on the books.
                            ;; Releasing it here is the whole reason the
                            ;; failure paths live inside this region: an
                            ;; exception leaves the tables exactly as it
                            ;; found them, which is not something the
                            ;; region gives for free -- interrupts are
                            ;; restored on the way out, table writes are
                            ;; not.
                            (fsw-free! job req)
                            (raise e)))
                   (go req))))
          (if (< r 0)
              ;; REFUSED BEFORE IT EVER REACHED THE POOL, and released
              ;; INSIDE the region. Doing this after leaving it left a
              ;; window of exactly the kind the region was added to
              ;; close: the job was on the books, the reference was
              ;; counted, no callback was ever coming, and a caller
              ;; killed in that window discarded the continuation that
              ;; was going to clean up -- stranding the request, the
              ;; bytes, and a descriptor that could then never drain.
              (begin
                (when owner
                  (deliver owner (vector 'fs-done (fsw-job-id job) r)))
                (fsw-free! job req)
                (fsw-job-id job))
              (fsw-job-id job))))))

  (define (fs-open-async! path flags mode owner)
    (fsw-submit! owner 'open -1 0 0
      (lambda (req)
        (uv-fs-open (uv-loop-handle) req path flags mode on-fsw-entry))))

  ;; THE BYTES ARE COPIED INTO C MEMORY, and that copy is not free on a
  ;; large payload. It is not avoidable: the collector may move a
  ;; bytevector, and libuv reads the buffer on a pool thread at a moment
  ;; nothing here controls.
  (define (fs-write-async! fd bytes offset owner)
    (let* ((n (bytevector-length bytes))
           (data (foreign-alloc (max n 1)))
           (buf (foreign-alloc 16)))
      (let loop ((i 0))
        (when (< i n)
          (foreign-set! 'unsigned-8 data i (bytevector-u8-ref bytes i))
          (loop (+ i 1))))
      (foreign-set! 'void* buf 0 data)
      (foreign-set! 'unsigned-64 buf 8 n)
      (fsw-submit! owner 'write fd data buf
        (lambda (req)
          (uv-fs-write (uv-loop-handle) req fd buf 1 offset on-fsw-entry)))))

  (define (fs-fsync-async! fd owner)
    (fsw-submit! owner 'fsync fd 0 0
      (lambda (req) (uv-fs-fsync (uv-loop-handle) req fd on-fsw-entry))))

  (define (fs-rename-async! from to owner)
    (fsw-submit! owner 'rename -1 0 0
      (lambda (req) (uv-fs-rename (uv-loop-handle) req from to on-fsw-entry))))

  (define (fs-close-async! fd owner)
    (fsw-submit! owner 'close fd 0 0
      (lambda (req) (uv-fs-close (uv-loop-handle) req fd on-fsw-entry))))

  ;; No fd and no buffer, like rename: the completion carries only the rc.
  ;; An existing directory comes back as -EEXIST rather than as an error
  ;; here, which is what lets a caller treat "already there" as success
  ;; without a prior stat -- and a prior stat would be a race anyway.
  (define (fs-mkdir-async! path mode owner)
    (fsw-submit! owner 'mkdir -1 0 0
      (lambda (req) (uv-fs-mkdir (uv-loop-handle) req path mode on-fsw-entry))))

  (define locked-callbacks
    (begin
      (lock-object on-alloc-code)
      (lock-object on-read-code)
      (lock-object on-close-code)
      (lock-object on-write-code)
      (lock-object on-connection-code)
      (lock-object on-connect-code)
      (lock-object on-getaddrinfo-code)
      (lock-object on-fs-code)
      (lock-object on-fsw-code)
      (lock-object on-tls-timer-code)
      (lock-object on-tls-timer-close-code)
      (lock-object on-process-exit-code)
      (lock-object on-process-close-code)
      (lock-object on-shutdown-code)
      ;; FOURTEEN, NOT SIXTEEN. on-timer-code and on-walk-code belong to the
      ;; loop itself -- its wakeup timer and uv_walk -- and are locked in
      ;; (igropyr libuv), beside the loop. Every code object must be locked in
      ;; whichever library holds it: libuv keeps only a raw entry pointer, so
      ;; a collected object means the loop jumps into freed memory. The
      ;; invariant is the ORDER -- construct, lock, take the entry, hand it
      ;; over -- not any registration, which C never sees.
      (vector on-alloc-code on-read-code on-close-code
              on-write-code on-connection-code on-connect-code
              on-getaddrinfo-code on-fs-code on-fsw-code
              on-tls-timer-code on-tls-timer-close-code
              on-process-exit-code on-process-close-code on-shutdown-code)))

  (define on-fsw-entry (foreign-callable-entry-point on-fsw-code))
  (define on-alloc-entry (foreign-callable-entry-point on-alloc-code))
  (define on-read-entry (foreign-callable-entry-point on-read-code))
  (define on-close-entry (foreign-callable-entry-point on-close-code))
  (define on-write-entry (foreign-callable-entry-point on-write-code))
  (define on-connection-entry (foreign-callable-entry-point on-connection-code))
  (define on-connect-entry (foreign-callable-entry-point on-connect-code))
  (define on-getaddrinfo-entry (foreign-callable-entry-point on-getaddrinfo-code))
  (define on-fs-entry (foreign-callable-entry-point on-fs-code))
  (define on-tls-timer-entry (foreign-callable-entry-point on-tls-timer-code))
  (define on-tls-timer-close-entry
    (foreign-callable-entry-point on-tls-timer-close-code))
  (define on-process-exit-entry
    (foreign-callable-entry-point on-process-exit-code))
  (define on-process-close-entry
    (foreign-callable-entry-point on-process-close-code))
  (define on-shutdown-entry (foreign-callable-entry-point on-shutdown-code))



  ;; ---- public API ----------------------------------------------------



  ;; optional trailing arg: uv_tcp_bind flags (UV_TCP_REUSEPORT = 2,
  ;; kernel-balanced multi-process listening).
  ;;
  ;; FreeBSD IS ON THE LIST, AND IT REACHES IT BY A DIFFERENT OPTION.
  ;; This matters here more than anywhere else: every igropyr deployment
  ;; runs on FreeBSD, and a note saying "Linux only" would tell the one
  ;; audience that needs this flag that it has nothing to gain.
  ;;
  ;; libuv's own header lists Linux 3.9+, DragonFlyBSD 3.6+, FreeBSD
  ;; 12.0+, Solaris 11.4 and AIX 7.2.5+ -- and NOT macOS. On FreeBSD the
  ;; kernel option is SO_REUSEPORT_LB, not SO_REUSEPORT: a different name
  ;; with the load-balancing semantics Linux gives the plain one, which
  ;; is why the platform note has to name the option and not just the
  ;; system.
  ;;
  ;; HOW FAR THE EVIDENCE GOES, because two different things are being
  ;; claimed and only one of them is checked here:
  ;;   - The platform list above is read from libuv's uv.h. Confirmed in
  ;;     two versions independently: 1.50.0 (locally) and 1.52.1 (the
  ;;     version installed on the deployment machines). They agree.
  ;;   - That FreeBSD's path is SO_REUSEPORT_LB is read from libuv's
  ;;     uv__sock_reuseport, in 1.52.1. NOT re-read here: this machine has
  ;;     only libuv's headers installed, not its C source.
  ;;   - THAT IT ACTUALLY DISTRIBUTES CONNECTIONS ON OUR MACHINES HAS
  ;;     NOT BEEN OBSERVED. That needs two processes on one port and a
  ;;     load run, and nobody has done it. What is written above is what
  ;;     libuv implements, not what we have measured.
  ;; opts: (flags [tls-ctx]). The context is taken HERE rather than patched
  ;; in afterwards -- see the incarnation vector below for why.
  (define (tcp-listen! host port backlog on-accept . opts)
    ;; the lease IS the region: it hands the shared address buffer to this
    ;; thunk with interrupts disabled and takes it back on return, so the
    ;; sequence below is unchanged and still cannot yield between resolving
    ;; the address and binding it.
    (uv-sockaddr-lease (lambda (sockaddr-buf)
    (let ((flags (if (pair? opts) (car opts) 0))
          (l (foreign-alloc tcp-handle-size))
          (inited? #f))
      ;; EVERY ONE OF THESE FOUR CAN FAIL, and one of them fails as a
      ;; matter of routine: a bind onto a port somebody else already
      ;; holds. Without this the handle allocated above is simply
      ;; abandoned -- and once uv_tcp_init has run it is not just memory,
      ;; it is a handle registered with the loop that nothing will ever
      ;; close. A server that retries its bind leaks one per attempt.
      ;;
      ;; Which release is right depends on how far we got: before init
      ;; the block is plain memory and is freed here; after it, the
      ;; handle belongs to libuv and has to go out through uv_close,
      ;; whose callback frees the block. Getting that backwards frees
      ;; memory the loop still holds a pointer to.
      (guard (e (#t (if inited? (uv-close l on-close-entry) (foreign-free l))
                    (raise e)))
        (check 'uv-tcp-init (uv-tcp-init (uv-loop-handle) l))
        (set! inited? #t)
        (check 'uv-ip4-addr (uv-ip4-addr host port sockaddr-buf))
        (check 'uv-tcp-bind (uv-tcp-bind l sockaddr-buf flags))
        (check 'uv-listen (uv-listen l backlog on-connection-entry))
        ;; #(token on-accept). The token is a fresh Scheme object per
        ;; LISTENER INCARNATION, and it is what makes an address safe to
        ;; use as an identity. Addresses alone are not: uv_handle_size
        ;; for a TCP handle was 264 bytes on the build this was measured
        ;; on (uv_handle_size is queried at run time and is not a
        ;; cross-platform constant; the argument does not depend on the
        ;; number, only on same-size reuse), and a foreign-alloc of that
        ;; size right after the close callback frees one returns the SAME
        ;; address -- measured, not feared. Without the token, a stopped
        ;; server's handle value would match a later listener's, so the
        ;; old server would report itself live and its shutdown would
        ;; stop somebody else's listener.
        ;; THE HANDSHAKING COUNT LIVES ON THIS OBJECT, not on the table
        ;; row (Y1). A handshaking conn holds a reference to this vector, so
        ;; the slot can still be released after the row is gone -- which is
        ;; exactly what happens when a listener is stopped while handshakes
        ;; are in flight. Slots 0/1 keep their meaning for every existing
        ;; reader; 2 is the count and 3 is the server context (#f = plaintext).
        ;; slot 4 is the handle this incarnation belongs to, so a conn
        ;; holding the incarnation can ask whether it is STILL the current one
        ;; (X3) without a reverse scan of the table.
        ;; PUBLISHED COMPLETE, INCLUDING THE CONTEXT. Filling slot 3 after
        ;; this row was already in the table was a window, not an untidiness:
        ;; between publication and the patch the event loop can accept a
        ;; queued connection, read ctx = #f, and take the PLAINTEXT branch --
        ;; a plain HTTP request reaching the reader on an https port. The
        ;; caller's context therefore arrives as an argument and is in the
        ;; vector the moment anything can see it.
        (hashtable-set! listener-table l
          (vector (list 'listener) on-accept 0
                  (if (and (pair? opts) (pair? (cdr opts))) (cadr opts) #f)
                  l))
        l)))))

  ;; Stop accepting new connections (graceful shutdown step 1);
  ;; established connections are unaffected. With a listener handle
  ;; (tcp-listen!'s return value) stops the listener at that address --
  ;; pass the token too if this caller may be stale, see the note there;
  ;; with no
  ;; argument stops every listener in the process.
  ;; Is this handle registered here under THIS incarnation? A lookup in
  ;; a table this library maintains -- not a question put to libuv, and
  ;; not an observation of the socket. What it is good for is that it
  ;; never DEREFERENCES the handle: once tcp-stop-listen! has run and the
  ;; close callback has freed the block, anything that reads through the
  ;; pointer -- uv_fileno included -- is a use-after-free, while using it
  ;; as a key is not.
  ;;
  ;; THE ADDRESS ALONE IS NOT AN IDENTITY, WHICH IS WHY THE TOKEN IS
  ;; REQUIRED. A freed address does not stay unmatched: a uv_tcp handle
  ;; was 264 bytes on the measured build -- the size is read at run time,
  ;; so treat the number as an illustration and the reuse as the point --
  ;; and a foreign-alloc of that size immediately after the
  ;; free returned the same address, so a later listener can be
  ;; registered under a stopped one's address. Membership alone would
  ;; then answer #t for a dead listener, and a stale owner's
  ;; tcp-stop-listen! would stop the new one.
  ;;
  ;; IT CAN ANSWER #f WHILE THE HANDLE IS STILL OPEN. The row is
  ;; removed when the stop is REQUESTED and the handle lives until the
  ;; close callback runs, which is a later turn of the loop -- so the
  ;; conservative interval is that whole asynchronous close, not the gap
  ;; to the next line. Early "not listening" is the safe direction; the
  ;; reverse is what the token prevents.
  ;; The token currently registered for this handle, or #f. Take it
  ;; immediately after tcp-listen! and keep it beside the handle; the
  ;; pair is the identity, neither half alone is.
  (define (listener-token h)
    (let ((v (and h (hashtable-ref listener-table h #f))))
      (and v (vector-ref v 0))))

  (define (listener-open? h token)
    (let ((v (and h (hashtable-ref listener-table h #f))))
      (and v (eq? token (vector-ref v 0)))))

  ;; (tcp-stop-listen!)            -- every listener in this process
  ;; (tcp-stop-listen! h)          -- that handle, whatever incarnation
  ;; (tcp-stop-listen! h token)    -- that handle ONLY if it is still the
  ;;                                  incarnation the token came from
  ;;
  ;; THE TWO-ARGUMENT FORM IS THE ONE TO USE FROM A LONG-LIVED OWNER.
  ;; A handle address can be reused by a later listener (see tcp-listen!),
  ;; so a stale owner calling the one-argument form stops whoever holds
  ;; that address now. The token form makes that a no-op instead.
  ;;
  ;; HOLDING THE HANDLE DOES NOT MAKE A CALLER SAFE, and an earlier
  ;; version of this note said it did ("a caller that created a listener
  ;; and stops it without ever releasing it cannot be stale"). Keeping
  ;; the number keeps nothing: the no-argument form, called by anyone,
  ;; stops and frees that listener, after which the address may belong
  ;; to someone else. The one-argument form is kept for compatibility --
  ;; every caller of it in this repository is a test that creates a
  ;; listener and stops it within one flow, checked by grep -- and new
  ;; code should pass the token.
  (define (tcp-stop-listen! . rest)
    ;; THE TEST AND THE CLOSE ARE ONE UNINTERRUPTIBLE STEP, for the
    ;; reason stated once for every call that passes a handle to libuv.
    ;; Two failures follow from splitting them, and both were reachable
    ;; before this region existed:
    ;;   - preempted after the TOKEN check, this call resumes and closes
    ;;     whatever now holds that address, because stop! re-tests only
    ;;     membership -- the stale-owner close the token exists to stop;
    ;;   - preempted after stop!'s own membership test, two callers each
    ;;     pass the same handle to uv_close.
    ;; The membership test inside stop! is therefore not redundant with
    ;; the token test outside it: it is what makes the no-argument sweep
    ;; safe over a snapshot that may already be stale.
    (define (stop! l)                        ; caller holds the region
      (when (hashtable-ref listener-table l #f)
        ;; THE INCARNATION OWNS ITS CONTEXT, so stopping it gives the
        ;; context back. Leaving that to the caller meant a direct
        ;; tcp-listen-tls! / tcp-stop-listen! lifecycle leaked one SSL_CTX per
        ;; generation, which contradicts the ownership this vector claims.
        (let ((v (hashtable-ref listener-table l #f)))
          (let ((ctx (and v (vector-ref v 3))))
            (when ctx (tls-context-retire! ctx))))
        (hashtable-delete! listener-table l)
        (uv-close l on-close-entry)))
    (cond
      ((null? rest)
       ;; The key vector is built OUTSIDE any region -- hashtable-keys
       ;; allocates -- and each stop is atomic on its own. A key that
       ;; goes away between the snapshot and its turn is handled by
       ;; stop!'s test; a listener created after the snapshot is simply
       ;; not in this sweep, which is what "every listener at the moment
       ;; of the call" means.
       (let ((ks (hashtable-keys listener-table)))
         (vector-for-each
           (lambda (l) (with-interrupts-disabled (stop! l)))
           ks)))
      ((null? (cdr rest))
       (with-interrupts-disabled (stop! (car rest))))
      (else
       (with-interrupts-disabled
         (when (listener-open? (car rest) (cadr rest))
           ;; INJECTION POINT 'tcp-stop-listen-before-close -- OWNING
           ;; REGION: the with-interrupts-disabled on the line above,
           ;; which is the region the comment at the top of this
           ;; procedure says must not be split.
           ;;
           ;; IT ALWAYS SKIPS, and it must: parking between the token
           ;; test and the close is exactly the split this region exists
           ;; to prevent. A barrier that parked here would reproduce the
           ;; stale-owner close it is meant to prove impossible.
           ;;
           ;; Interrupt state: injection ON -- depth 2, so 'skipped;
           ;; injection OFF -- (void).
           (inject-barrier! 'tcp-stop-listen-before-close)
           (stop! (car rest)))))))

  ;; NOTHING THAT NEEDS RETURNING EXISTS OUTSIDE THE REGION. The
  ;; foreign allocation and both publications happen inside it -- the
  ;; state vector is built outside, but it is a Scheme object the
  ;; collector reclaims -- so a kill before the region can discard
  ;; nothing that has to be handed back. That
  ;; closes a window this function used to have: req allocated, then a
  ;; preemption during the Scheme allocations that followed, then a kill
  ;; -- which discards the continuation without running any guard,
  ;; leaving a malloc'd request in no table, where uv-owner-died! cannot
  ;; find it either. There is no cell for that window (a kill cannot be
  ;; aimed into it with what the suite has); it is closed by
  ;; construction, and recorded as such.
  ;;
  ;; Allocation inside the region is allowed: a collect request is
  ;; deferred until the region is left, and the only failure shape is a
  ;; raise, which the handler catches. The prepare/publish split is
  ;; NOT about the region being allocation-free: hashtable-set! may
  ;; allocate when it adds a key or grows, and both callers now prepare
  ;; inside their region anyway.
  ;; SHAPED LIKE fs-start-fd!: the submission is INSIDE the region.
  ;; Publishing and submitting have to be one step, because the state
  ;; between them is one nothing can reclaim -- a published op whose
  ;; phase is 'open has no callback coming, and uv-owner-died! reaches it
  ;; only to call file-stream-close!, which does real work solely for
  ;; phase 'idle. So it sets the aborted flag and returns, and the row
  ;; and the request stay for the life of the process.
  ;;
  ;; An earlier version of this comment said pulling the submission in
  ;; "would buy nothing". It buys exactly that window. The cost is an
  ;; uninterruptible foreign call, and it is the right trade here because
  ;; uv_fs_open with a callback is an enqueue, not the I/O itself.
  ;; Roll back a partly-started fs operation. TOP LEVEL, and taking its
  ;; state as a vector, for two reasons that both bit earlier versions:
  ;;
  ;; A LOCAL PROCEDURE WOULD ALLOCATE A CLOSURE BEFORE THE GUARD that
  ;; is supposed to protect it. fs-start-fd! owns the caller's descriptor
  ;; from its first instruction, so an allocation failure there escaped
  ;; with the fd still open.
  ;;
  ;; ONE COPY, TWO CALL SITES. The handler and the refused-submission
  ;; branch both need exactly this, and when they were written separately
  ;; they drifted -- see the cleanup-safe? note below for what that cost.
  ;;
  ;; State vector: #(cell req cleanup-safe? fd fd-open?).
  ;;
  ;; AT MOST ONCE, NOT EXACTLY ONCE. Each slot is cleared BEFORE the
  ;; operation it guards, so a raise part way cannot make a second call
  ;; repeat a free or a close. The price is the other direction: a raise
  ;; BEFORE the operation takes effect loses that one resource. No flag
  ;; order gives exactly-once for an operation that may raise on either
  ;; side of its effect; leaking one block beats freeing one twice.
  ;; This is exactly-once only under the premise that these calls do
  ;; not raise, which is where they stand today.
  (define (fs-undo! st owner)
    (let ((cell (vector-ref st 0)) (req (vector-ref st 1)))
      ;; THE BOUNDARY IS DRAWN PER OPERATION, not uniformly. An
      ;; idempotent step keeps its slot live across itself, so a retry
      ;; after a raise can complete it; a step that must not run twice
      ;; has its slot cleared first, at the price of leaking on a raise
      ;; before the effect. unpublish-head! and hashtable-delete! are
      ;; retry-safe (a completed one makes the next a no-op); free and
      ;; close are not.
      (when cell
        (owner-index-unpublish-head! owner cell)
        (vector-set! st 0 #f))
      (when req
        (hashtable-delete! fs-table req)
        (vector-set! st 1 #f)
        ;; ONLY A REQUEST libuv HAS INITIALISED MAY BE CLEANED UP. Before
        ;; the submission this is raw foreign-alloc memory and
        ;; uv_fs_req_cleanup would be reading fields nothing wrote. The
        ;; separate pre-submission and post-submission paths had this
        ;; right; merging them into one rollback is what lost it.
        ;;
        ;; cleanup-safe? (slot 2) IS SET AFTER THE CALL RETURNS,
        ;; WHATEVER IT RETURNED, and that is safe because libuv
        ;; initialises the request before anything that can fail.
        ;; Verified by reading
        ;; src/unix/fs.c of libuv 1.50.0, 1.51.0, 1.52.0 and 1.52.1 --
        ;; every version this runs on today: INIT(subtype) is the first
        ;; statement of both uv_fs_open and uv_fs_fstat, the only earlier
        ;; failure is req == NULL, and a later PATH/uv__strdup failure
        ;; returns UV_ENOMEM with INIT already done and the very fields
        ;; uv_fs_req_cleanup reads left NULL.
        ;;
        ;; RE-READ THIS AGAINST A NEWER libuv BEFORE TRUSTING IT. The
        ;; property is whether INIT still precedes every failing path in
        ;; those two functions. Nothing here breaks loudly if it stops
        ;; being true -- cleanup on a request libuv never saw is
        ;; undefined, and undefined has been observed to mean SIGABRT
        ;; (measured, with a deliberately poisoned request).
        (when (vector-ref st 2) (uv-fs-req-cleanup req))
        (fs-req-free! req))
      (when (vector-ref st 4)
        (vector-set! st 4 #f)
        (c-close (vector-ref st 3)))))

  ;; The three operations that need no descriptor: stat, unlink, scandir.
  ;; One routine because their submission sequence is identical and only
  ;; the libuv call at the end differs -- three copies would be three
  ;; places to keep the region discipline in step.
  ;;
  ;; fd IS -1 HERE AND MUST STAY -1, and that is not cosmetic. When the
  ;; owner dies, uv-owner-died! reaches these ops through the same 'fs
  ;; arm as a stream read: file-stream-close! marks the op aborted, the
  ;; completion lands in fs-abort-step!, falls to its `else`, and calls
  ;; fs-quiet-close! -- whose FIRST test is (< fd 0), and which therefore
  ;; frees the request and delivers nothing. Give one of these ops an fd
  ;; and that same path will close a descriptor it does not own. The
  ;; reclaim path is correct for them BECAUSE the field is -1.
  ;;
  ;; THE OPERATION IS THE PHASE, not the mode. fs-op-mode already means
  ;; whole|stream -- the read pipeline's chunking policy, read in four
  ;; places -- and on-fs-code dispatches on phase alone. These ops carry
  ;; mode 'whole, which nothing on their path ever reads.
  ;;
  ;; The state vector is allocated before the region for the reason
  ;; fs-start! gives: at that instant nothing is owned, so the only
  ;; residual is the guard's own entry allocation, the file-wide floor.
  (define (fs-start-simple! path owner phase)
    (let ((st (vector #f #f #f -1 #f)) (op #f) (rc 0))
      (with-interrupts-disabled
        (guard (e (#t (fs-undo! st owner) (raise e)))
          (set! op (make-fs-op owner path 'whole #f phase #f #f -1 0 0 '() 0 0))
          (vector-set! st 0 (owner-index-prepare! 'fs))
          (vector-set! st 1 (fs-req-alloc!))
          (fs-op-req-set! op (vector-ref st 1))
          (hashtable-set! fs-table (vector-ref st 1) op)
          (owner-index-publish! owner (vector-ref st 0) (vector-ref st 1))
          ;; INJECTION POINT 'fs-simple-submit-gap -- OWNING GUARD: the
          ;; guard above. Same window and same consequence as
          ;; 'fs-submit-gap-open: a published, unsubmitted op is only
          ;; flagged by file-stream-close!, so its row and request would
          ;; stay forever.
          (inject-fault! 'fs-simple-submit-gap)
          (set! rc
            (case phase
              ((stat)   (uv-fs-stat   (uv-loop-handle) (vector-ref st 1) path on-fs-entry))
              ((unlink) (uv-fs-unlink (uv-loop-handle) (vector-ref st 1) path on-fs-entry))
              (else     (uv-fs-scandir (uv-loop-handle) (vector-ref st 1) path 0
                                       on-fs-entry))))
          ;; Set for the reason fs-start! sets it: the request is
          ;; initialised and safe to clean whatever the call returned.
          (vector-set! st 2 #t)
          (when (< rc 0)
            (fs-undo! st owner)
            ;; Inside the region, and for fs-start!'s reason: owner need
            ;; not be the caller, and it holds no handle to ask with.
            (deliver owner (vector 'file-error rc)))))
      op))

  ;; -> #(file-stat ,alist) or #(file-error ,errno) to owner.
  ;; THE FIELDS ARE KEYED, NOT POSITIONAL. A consumer reads with assq,
  ;; so a field added later breaks nothing that reads the ones before it.
  ;; Times are delivered as seconds AND nanoseconds, unconverted: a
  ;; consumer wanting milliseconds does that arithmetic itself, and one
  ;; wanting the full resolution still has it.
  (define (file-stat-async! path owner) (fs-start-simple! path owner 'stat))

  ;; -> #(file-unlinked) or #(file-error ,errno) to owner.
  (define (file-unlink-async! path owner) (fs-start-simple! path owner 'unlink))

  ;; -> #(file-entries ,names) or #(file-error ,errno) to owner. Names
  ;; only, without "." or "..", in whatever order the filesystem gave.
  ;;
  ;; EVERY ENTRY IS DELIVERED; there is no cap. A directory with a
  ;; million names produces a million strings, built inside the libuv
  ;; callback -- see the scandir arm for what that costs. Truncating and
  ;; reporting success would be worse: the consumer cannot tell a short
  ;; listing from a complete one. A directory big enough for that to
  ;; matter wants a batched opendir/readdir API, which this is not.
  (define (file-scandir-async! path owner) (fs-start-simple! path owner 'scandir))

  (define (fs-start! path owner mode)
    ;; THE STATE VECTOR AND THE GUARD'S OWN CONTINUATION ARE ALLOCATED
    ;; BEFORE ANY HANDLER EXISTS. That is true of every guard in this
    ;; file and is not repaired here: a Chez allocation failure is an
    ;; unrecoverable out-of-memory condition, not something a handler
    ;; could act on. Recorded as a residual rather than papered over.
    ;; This path holds nothing but Scheme objects at that moment anyway.
    (let ((st (vector #f #f #f -1 #f)) (op #f) (rc 0))
      ;; INJECTION POINT 'fs-open-before-region -- OWNING REGION: NONE,
      ;; and that is the whole reason this point exists here.
      ;;
      ;; THIS IS THE ONE OF THE THREE THAT CAN PARK. $inject-barrier
      ;; reads the interrupt depth and parks only when nothing above it
      ;; holds a region; here the state vector is allocated but the
      ;; region has not been entered, so a victim stops with an fs
      ;; request NOT yet allocated and nothing published.
      ;;
      ;; Interrupt state: injection ON -- depth 1 (whatever the caller
      ;; had, plus nothing), so the barrier parks; injection OFF -- the
      ;; form expands to (void) and this line costs nothing.
      (inject-barrier! 'fs-open-before-region)
      (with-interrupts-disabled
        (guard (e (#t (fs-undo! st owner) (raise e)))
          (set! op (make-fs-op owner path mode #f 'open #f #f -1 0 0 '() 0 0))
          (vector-set! st 0 (owner-index-prepare! 'fs))
          (vector-set! st 1 (fs-req-alloc!))
          (fs-op-req-set! op (vector-ref st 1))
          (hashtable-set! fs-table (vector-ref st 1) op)
          ;; INJECTION POINT 'fs-publish-second-half-open -- OWNING
          ;; GUARD: the guard above.
          (inject-fault! 'fs-publish-second-half-open)
          (owner-index-publish! owner (vector-ref st 0) (vector-ref st 1))
          ;; INJECTION POINT 'fs-open-after-publish -- OWNING REGION: the
          ;; with-interrupts-disabled opened above, and OWNING GUARD: the
          ;; guard above it.
          ;;
          ;; A BARRIER HERE ALWAYS SKIPS, BY CONSTRUCTION. The region
          ;; is already held, so $inject-barrier takes the reservation,
          ;; counts slot 8 and runs on rather than parking -- a victim
          ;; CANNOT be suspended holding this region, because nothing
          ;; else would ever run to resume it. The point is here so a
          ;; cell can assert that skip happened where the row was armed,
          ;; which is the only evidence that the depth test is live.
          ;;
          ;; Interrupt state: injection ON -- depth 2, so 'skipped;
          ;; injection OFF -- (void).
          (inject-barrier! 'fs-open-after-publish)
          ;; INJECTION POINT 'fs-submit-gap-open -- OWNING GUARD: the
          ;; same one. It stands for ANY raise between publishing and
          ;; submitting, the state nothing reclaims: file-stream-close!
          ;; acts only on phase 'idle, so a published, unsubmitted op is
          ;; merely flagged and its row and request stay forever.
          (inject-fault! 'fs-submit-gap-open)
          (set! rc (uv-fs-open (uv-loop-handle) (vector-ref st 1) path
                               O-RDONLY 0 on-fs-entry))
          ;; THE SLOT MEANS "cleanup is defined on this request", NOT
          ;; "it was submitted" -- an earlier name said submitted? and
          ;; was false: uv_fs_open can return UV_ENOMEM having submitted
          ;; nothing, and the request is still initialised and safe to
          ;; clean. Set here because this is the earliest point at which
          ;; that holds; the reading that establishes it, and the one
          ;; case it depends on not happening (req == NULL, which
          ;; foreign-alloc makes impossible by raising instead of
          ;; returning null), are with the consumer in fs-undo!.
          (vector-set! st 2 #t)
          (when (< rc 0)
            (fs-undo! st owner)
            ;; REPORTED INSIDE THE REGION, and that is deliberate.
            ;; owner is an explicit parameter of the exported API and
            ;; need not be the process that called: A may submit on
            ;; behalf of B. Telling the owner outside the region let a
            ;; kill in between leave B with neither an error nor any
            ;; callback to come, and for a whole-file read B holds no
            ;; handle to ask with -- it would wait forever.
            (deliver owner (vector 'file-error rc)))))
      op))

 ;; Start the ordinary asynchronous fstat/read pipeline from an fd that
  ;; has already been opened securely with openat.
  ;; THIS FUNCTION TAKES OWNERSHIP OF fd, INCLUDING WHEN IT FAILS. The
  ;; caller opened fd with openat and has no other handle on it, so a
  ;; raise that leaves this frame without closing it leaks a descriptor
  ;; that nothing in the process can name again -- it is not in fs-table,
  ;; not in the owner index, and not reachable from op, because op is
  ;; exactly what failed to be built. Measured, not argued: injecting a
  ;; failure between the allocation and the publish moved the /dev/fd
  ;; count from 12 to 13 with fs-count still 0.
  ;;
  ;; THE GUARD SPANS EVERYTHING, PUBLICATION AND SUBMISSION INCLUDED.
  ;; Earlier versions of this note said it stopped before publication and
  ;; that an fs-table row alone made the request reachable to
  ;; uv-owner-died!. Both were wrong: teardown walks the OWNER INDEX
  ;; first and needs both entries, and stopping the guard before the
  ;; publish left the state that has no reclaimer at all -- published,
  ;; unsubmitted, phase not 'idle, so file-stream-close! only flags it.
  ;;
  ;; ONE ALLOCATION STILL PRECEDES THE REGION: the state vector. If
  ;; Chez fails to allocate it, this frame is already holding the fd and
  ;; nothing closes it. SO THIS PATH IS NOT YET INDEPENDENT OF ITS
  ;; CALLER, and file-stream-open-under!'s enclosing region is what
  ;; covers that instant today. Three versions of this comment have now
  ;; claimed independence: the first while op and cell were built in the
  ;; let initialisers, the second while a local undo! allocated a closure
  ;; there, and the third while this vector did. Each time the claim was
  ;; written before the last allocation had actually moved.
  ;;
  ;; What is left is irreducible without changing the interface -- a Chez
  ;; allocation failure is unrecoverable and no handler could act on it,
  ;; and the alternative is preparing the vector before the caller opens
  ;; the descriptor. Recorded as a residual; the honest statement is that
  ;; this window exists and is covered only by the caller.
  ;;
  ;; Past that, a raise anywhere inside reaches the handler and a kill
  ;; cannot land inside at all. (The guard's setup is itself inside the
  ;; disabled region -- Chez expands guard within the dynamic-wind body
  ;; -- so only the vector above is outside.) Scheme allocation inside the region
  ;; is allowed: a collect request is deferred until the region is left,
  ;; and the only failure shape is a raise, which this handler catches.
  ;;
  ;; This function OWNS fd from the call, success or failure. Its caller
  ;; opened it with openat and holds no other handle on it.
  ;; THIS FUNCTION OWNS fd FROM ITS FIRST INSTRUCTION, success or
  ;; failure. Its caller opened it with openat and holds no other handle
  ;; on it, so every exit has to close it.
  ;;
  ;; THE STATE VECTOR IS THE CALLER'S, AND IT IS OLDER THAN THE fd.
  ;; This function used to allocate it here, after it already owned the
  ;; descriptor -- so the one allocation that could fail while holding an
  ;; unclosable fd was the first thing it did. Now the caller builds the
  ;; vector BEFORE openat and only writes the fd into it once openat has
  ;; returned one, inside its own region. There is no moment at which
  ;; this function owns an fd and has not yet allocated the thing that
  ;; records it.
  ;;
  ;; AND THAT IS WHY THE CALLER'S REGION IS NO LONGER LOAD-BEARING for
  ;; the fd. It was: the correctness of this function depended on being
  ;; called from inside one, which made it a part whose behaviour changed
  ;; with its context. It is self-contained now, and a cell can prove it
  ;; by deleting the caller's region and watching nothing leak.
  ;;
  ;; WHAT REMAINS, and it is smaller than what was here before but not
  ;; nothing: entering the guard allocates a continuation, and that
  ;; allocation is outside the guard it establishes -- the same floor
  ;; every guard in this file stands on (see fs-start!). The fd IS owned
  ;; at that instant, because the caller transferred it before the call.
  ;; So the honest statement is that the window shrank from "a vector and
  ;; a continuation" to "a continuation", not that it closed.
  (define (fs-start-fd! st fd path owner mode)
    (with-interrupts-disabled
        (guard (e (#t (fs-undo! st owner) (raise e)))
          ;; INJECTION POINT 'fs-preregion-fd -- OWNING GUARD: this one,
          ;; and it is placed first on purpose: it stands for "the very
          ;; first thing after ownership raises", which is the case the
          ;; old shape could not survive. A cell arming it must see the
          ;; fd closed.
          (inject-fault! 'fs-preregion-fd)
          (let ((op (make-fs-op owner path mode #f 'fstat #f #f fd 0 0 '() 0 0)))
            (vector-set! st 0 (owner-index-prepare! 'fs))
            ;; INJECTION POINT 'fs-oom-fd -- OWNING GUARD: the guard above,
            ;; the only one on this path. It stands for the allocation
            ;; below failing; either Scheme allocation reaches it too.
            (inject-fault! 'fs-oom-fd)
            (vector-set! st 1 (fs-req-alloc!))
            (fs-op-req-set! op (vector-ref st 1))
            (hashtable-set! fs-table (vector-ref st 1) op)
            ;; INJECTION POINT 'fs-publish-second-half -- OWNING GUARD: the
            ;; same one. A failure between the two publications.
            (inject-fault! 'fs-publish-second-half)
            (owner-index-publish! owner (vector-ref st 0) (vector-ref st 1))
            ;; INJECTION POINT 'fs-submit-gap-fd -- OWNING GUARD: the same
            ;; one. See fs-start! for what this window costs if it is left
            ;; outside the guard.
            (inject-fault! 'fs-submit-gap-fd)
            (fs-op-phase-set! op 'fstat)
            (let ((rc (uv-fs-fstat (uv-loop-handle) (vector-ref st 1)
                                   (fs-op-fd op) on-fs-entry)))
              (vector-set! st 2 #t)
              (when (< rc 0)
                (fs-undo! st owner)
                (deliver owner (vector 'file-error rc))))
            op))))

  (define (relative-parts rel)
    (let ((n (string-length rel)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n)
           (let ((part (substring rel start i)))
             (reverse (if (or (string=? part "") (string=? part "."))
                          acc (cons part acc)))))
          ((char=? (string-ref rel i) #\/)
           (let ((part (substring rel start i)))
             (loop (+ i 1) (+ i 1)
                   (if (or (string=? part "") (string=? part "."))
                       acc (cons part acc)))))
          (else (loop (+ i 1) start acc))))))

  ;; Open rel beneath root without following any untrusted path component.
  ;; The trusted root is opened once per call; every child is then resolved
  ;; relative to that stable directory fd. Returns an fd or -1.
  ;;
  ;; Do NOT hoist the root open into a cached fd. A directory fd names an
  ;; inode, not a path -- which is exactly why the walk below cannot be
  ;; raced, and exactly why keeping one across requests would pin the
  ;; directory that was there when it was opened. A deployment that swaps
  ;; its root atomically (ln -sfn releases/v2 current) would go on serving
  ;; the previous release until the process restarted, with nothing to
  ;; indicate it. The saving would be one syscall out of the 1 + 2N this
  ;; makes, on the cache-miss path only.
  (define (open-under root rel)
    (let ((parts (relative-parts rel)))
      (if (or (null? parts)
              (exists (lambda (p)
                        (or (string=? p "..")
                            (let loop ((i 0))
                              (and (< i (string-length p))
                                   (or (char=? (string-ref p i) #\nul)
                                       (loop (+ i 1)))))))
                      parts))
          -1
          (let ((root-fd
                  (c-open root
                    (bitwise-ior O-RDONLY O-DIRECTORY O-CLOEXEC) 0)))
            (if (< root-fd 0)
                -1
                (let loop ((dir root-fd) (xs parts))
                  (let* ((last? (null? (cdr xs)))
                         (flags (bitwise-ior O-RDONLY O-CLOEXEC O-NOFOLLOW
                                  (if last? 0 O-DIRECTORY)))
                         (next (c-openat dir (car xs) flags 0)))
                    (c-close dir)
                    (cond ((< next 0) -1)
                          (last? next)
                          (else (loop next (cdr xs)))))))))))

  ;; The path the OS itself would call this file: symlinks and . / ..
  ;; resolved, and on a case-insensitive filesystem the spelling corrected
  ;; to the one on disk, so every way of naming one file gives one answer.
  ;; #f if it does not resolve.
  ;;
  ;; SYNCHRONOUS -- a passed callback of 0 makes uv_fs_* block -- so this
  ;; stalls the scheduler for one path lookup. That is the same cost the
  ;; surrounding code already pays for file-exists?; do not put it on a
  ;; path that runs per request when the answer can be cached.
  (define (file-realpath path)
    (let ((req (fs-req-alloc!)))
      (dynamic-wind
        (lambda () (void))
        (lambda ()
          (let ((r (uv-fs-realpath (uv-loop-handle) req path 0)))
            (and (>= r 0)
                 (let ((p (uv-fs-get-ptr req)))
                   (and (not (eqv? p 0))
                        ;; the string is owned by the request; copy before
                        ;; the cleanup below frees it
                        (let loop ((i 0) (acc '()))
                          (let ((b (foreign-ref 'unsigned-8 p i)))
                            (if (fx= b 0)
                                (utf8->string
                                  (u8-list->bytevector (reverse acc)))
                                (loop (fx+ i 1) (cons b acc))))))))))
        (lambda ()
          (uv-fs-req-cleanup req)
          (fs-req-free! req)))))

  ;; Read a whole file on libuv's thread pool. The owner process later
  ;; receives #(file-read ,bytevector) or #(file-error ,errno). Never
  ;; blocks the scheduler, even for large files or slow filesystems.
  (define (file-read-async! path owner)
    (fs-start! path owner 'whole)
    (void))

  ;; Open a file as a consumer-driven chunk stream; returns the stream
  ;; handle (also carried by the ready message, and needed to close a
  ;; stream whose open never completed). The owner later receives
  ;; #(file-stream ,stream ,size) (ready; size from fstat) or
  ;; #(file-error ,errno). Then each file-stream-read! yields exactly
  ;; one of: #(file-chunk ,x) (a bytevector, or its length after
  ;; file-stream-raw!), #(file-eof) (all bytes delivered or the file
  ;; shrank -- the fd is already closed), or #(file-error ,errno) (fd
  ;; closed). One pull may be in flight at a time, so a slow consumer
  ;; holds one chunk of memory, not the file.
  (define (file-stream-open! path owner)
    (fs-start! path owner 'stream))

  ;; Confined counterpart used by app-static and rooted send-file!. #f is
  ;; an immediate refusal (missing path, symlink, or invalid component).
  (define (file-stream-open-under! root rel owner)
    ;; Keep the raw fd continuously protected: before fs-start-fd! installs
    ;; it in fs-table, actor teardown has no way to discover and close it.
    ;;
    ;; THE REGION COVERS PREEMPTION AND NOTHING ELSE. It stops actor
    ;; teardown from running here; it does not unwind, so it never
    ;; covered fs-start-fd! RAISING with the fd in hand -- that half is
    ;; fs-start-fd!'s own contract, which is why that function closes fd
    ;; on any pre-publication failure. Read the two together: this line
    ;; hands the descriptor over, and the callee owns it from the call,
    ;; success or failure.
    ;; THE STATE VECTOR IS BUILT BEFORE THE fd EXISTS. If this
    ;; allocation fails there is no descriptor yet to leak; built after
    ;; openat, the same failure would strand one. The two writes below
    ;; are the ownership transfer, and they happen only once openat has
    ;; actually returned a descriptor.
    (with-interrupts-disabled
      (let ((st (vector #f #f #f -1 #f)))
        (let ((fd (open-under root rel)))
          (and (>= fd 0)
               (begin
                 (vector-set! st 3 fd)
                 (vector-set! st 4 #t)
                 (fs-start-fd! st fd rel owner 'stream)))))))

  ;; Switch chunk delivery to lengths: the bytes stay in the stream's C
  ;; buffer (file-stream-chunk-ptr) until the next pull, so a consumer
  ;; that only forwards them (tcp-write-foreign!) never touches the
  ;; Scheme heap. Set it before the first pull.
  (define (file-stream-raw! op)
    (fs-op-raw?-set! op #t))

  (define (file-stream-chunk-ptr op)
    (fs-op-data op))

  ;; Transfer delivery of subsequent messages to another process (e.g.
  ;; a pump spawned after the stream was opened). Call it before the
  ;; new owner's first pull, with no pull in flight.
  ;; How many file streams are open. Same purpose as conn-count: an fd,
  ;; a uv_fs_t and a 256 KiB foreign buffer that outlive their owner are
  ;; invisible from Scheme -- fs-table roots them, so the GC will not
  ;; report them either -- and a leak that nothing can count is a leak
  ;; nothing can assert about.
  (define (fs-count) (hashtable-size fs-table))

  ;; In-flight getaddrinfo requests. Exported for the reason fs-count and
  ;; uv-owner-index-count are: the failure this pairs with -- a request
  ;; row that outlives its resolution -- has no symptom except growth,
  ;; and the owner index alone cannot show it, because that index is a
  ;; superset that a cell can watch return to baseline while this table
  ;; keeps a row nothing will ever reach.
  (define (dns-count) (hashtable-size getaddrinfo-table))

  ;; The accept-queue limit the kernel actually kept for this listener,
  ;; or #f where it cannot be read. listen() silently clamps the backlog
  ;; it is given to a system maximum (kern.ipc.soacceptqueue on FreeBSD,
  ;; somaxconn on Linux), and reports nothing: a server can ask for 8192,
  ;; be given 128, and overflow under a burst with no local symptom -- the
  ;; drops are counted in the kernel, not here.
  ;;
  ;; #f IS AN HONEST ANSWER AND A WRONG NUMBER IS NOT. Both the option
  ;; and its level come from (igropyr platform) and are #f until read
  ;; from the target's headers; while either is #f this returns #f rather
  ;; than calling getsockopt with a guessed constant, which would answer
  ;; for some other option and hand back a plausible integer.
  ;; ALL THREE BLOCKS ARE ALLOCATED TOGETHER SO ONE HANDLER CAN NAME
  ;; ALL THREE. The first version allocated val and len INSIDE a guard
  ;; whose handler knew only about fdbuf, so a raise from getsockopt
  ;; would have returned one block and leaked two. That raise was not
  ;; reachable in practice -- the arguments are fixnums and pointers,
  ;; and the read is from a block allocated three lines above -- which
  ;; is why the SHAPE is what was wrong, not the symptom. It was the
  ;; third instance of that shape in one day; the check that catches it
  ;; is to ask, at every foreign-alloc, which handler knows this name.
  ;;
  ;; ONE RESIDUAL, STATED RATHER THAN PAPERED OVER: if the second or
  ;; third foreign-alloc raises, the first is still leaked, because the
  ;; bindings run before any handler is installed. That is an allocation
  ;; failure of twelve bytes total, and covering it would need three
  ;; nested guards for a case where the process is already out of
  ;; memory. The gap is named here so a reader can weigh it rather than
  ;; assume it was handled.
  ;; THE CHECK AND THE FOREIGN USE ARE ONE UNINTERRUPTIBLE STEP, which
  ;; is the rule this file already states for every call that passes a
  ;; handle to libuv. A membership test on its own does NOT make this
  ;; safe: between the test and uv_fileno the process can be preempted,
  ;; another can stop the listener, and the loop can free the handle --
  ;; so the region has to span the test AND both foreign calls. The three
  ;; buffers are therefore allocated OUTSIDE it; the region does pointer
  ;; work, two FFI calls and the three foreign-frees done! performs --
  ;; no allocation.
  ;;
  ;; The token is checked, not just membership: a later listener can hold
  ;; this very address (see tcp-listen!), and answering for it would
  ;; report somebody else's backlog as this server's.
  (define (listener-backlog-effective l token)
    (and so-listenqlimit sol-socket
         (let ((fdbuf (foreign-alloc 4))
               (val   (foreign-alloc 4))
               (len   (foreign-alloc 4)))
           (define (done! x)
             (foreign-free fdbuf) (foreign-free val) (foreign-free len)
             x)
           (guard (e (#t (done! #f) (raise e)))
             (foreign-set! 'int len 0 4)
             (with-interrupts-disabled
               (if (not (listener-open? l token))
                   (done! #f)
                   (if (< (uv-fileno l fdbuf) 0)
                       (done! #f)
                       (let* ((fd (foreign-ref 'int fdbuf 0))
                              (rc (c-getsockopt fd sol-socket so-listenqlimit
                                                val len))
                              (answer (and (>= rc 0)
                                           (foreign-ref 'int val 0))))
                         (done! (and answer (> answer 0) answer))))))))))

  (define (file-stream-own! op pid)
    (with-interrupts-disabled
      (fs-op-owner-set! op pid)
    ;; The INDEX has to learn about the move too, exactly as conn-set-owner!
    ;; does for connections. Setting only the field meant uv-owner-died! for
    ;; the new owner found nothing to reclaim: a pump killed mid-download
    ;; left its fd, its uv_fs_t and its 256 KiB foreign buffer rooted by
    ;; fs-table for the life of the VM, which is the leak the index exists
    ;; to prevent.
      (index-owner! pid 'fs (fs-op-req op))))

  (define (file-stream-read! op)
    (when (and (not (fs-op-aborted? op)) (eq? (fs-op-phase op) 'idle))
      (start-fs-read! op (fs-op-req op))))

  ;; Abort/release a stream early (consumer done or gone). Idempotent;
  ;; nothing further is delivered. With an op in flight the completion
  ;; callback performs the close.
  (define (file-stream-close! op)
    (unless (fs-op-aborted? op)
      (fs-op-aborted?-set! op #t)
      (when (eq? (fs-op-phase op) 'idle)
        (fs-quiet-close! op (fs-op-req op)))))

  ;; Async DNS. The owner process later receives #(dns-resolved ,ip-string)
  ;; or #(dns-failed ,errno). libuv resolves on its thread pool, so the
  ;; scheduler is not blocked.
  ;; TWO EXITS, AND BOTH OWE AN unindex-owner!. A submission that
  ;; libuv refuses never reaches the callback, so the request is torn
  ;; down here instead; a submission it accepts is torn down there. The
  ;; index registration made below is one, and whichever exit runs has to
  ;; retire it -- neither of them covers the other.
  ;;
  ;; NEITHER OF THEM DID, AND NOTHING SAID SO. The entry survived every
  ;; completed resolution for the life of the owning process; only owner
  ;; death cleared it, by deleting that owner's list wholesale. The
  ;; symptom was growth alone, which is why unindex-owner! reports a
  ;; count -- and that count is what a cell reads here.
  (define (dns-resolve! host owner)
    (let ((req (foreign-alloc getaddrinfo-req-size)))
      (hashtable-set! getaddrinfo-table req owner)
      (index-owner! owner 'dns req)
      ;; INJECTION POINT 'getaddrinfo-refused -- OWNING GUARD: none. There
      ;; is no guard between here and the assertion; a negative return is
      ;; a value, not a raise, and it is read by the (when (< r 0) ...)
      ;; immediately below, which is the branch the cell exercises.
      (let ((r (inject-return! 'getaddrinfo-refused
                 (uv-getaddrinfo (uv-loop-handle) req on-getaddrinfo-entry host 0 0))))
        (when (< r 0)
          (hashtable-delete! getaddrinfo-table req)
          ;; Same ordering and the same reason as the callback's copy,
          ;; and a different handler: this runs on the caller's own
          ;; stack, not in a foreign callback, so an allocation failure
          ;; is reportable and is reported. What must not differ is the
          ;; free -- nothing else will ever reach this request, because
          ;; the table row is gone and a refused submission produces no
          ;; callback.
          ;;
          ;; ZERO COVERAGE, AND THE REASON IS NAMED. This branch runs
          ;; only when uv_getaddrinfo refuses SYNCHRONOUSLY. A name that
          ;; does not resolve is refused by the resolver instead, through
          ;; the callback with a negative status, so the suite's bad-host
          ;; case exercises the copy above and not this one: mutating
          ;; this line leaves test/dns-owner-index.sc green. host is
          ;; always a string here, so it is not currently known whether
          ;; any public call can reach it at all.
          ;; Do not manufacture reachability by changing this code to
          ;; suit a test.
          (guard (e (#t (foreign-free req) (raise e)))
            (unindex-owner! owner 'dns req))
          (foreign-free req)
          (deliver owner (vector 'dns-failed r))))))

  ;; Outbound TCP connection. The owner process later receives
  ;; #(tcp-connected ,conn) or #(tcp-connect-failed ,errno). Call
  ;; tcp-read-start! on the conn after the connected message arrives.
  ;; ---- connect completion record (D) ----------------------------------
  ;;
  ;; ONE ATTEMPT GETS EXACTLY ONE ANSWER, and D is what makes that checkable
  ;; rather than agreed. A TLS dial reaches its conclusion from several places
  ;; -- establishment, a failure before the TLS record is attached, and a
  ;; retirement after it -- and each would otherwise be free to deliver its own
  ;; #(tcp-connected) or #(tcp-connect-failed). Two answers to one dial is worse
  ;; than none: the caller acts on the first, and the second arrives against
  ;; state built from it.
  ;;
  ;; The record is created at submission, held by the request entry, kept by the
  ;; connect callback as that entry is freed, and referenced from the TLS record
  ;; once one exists. A server-side TLS record carries #f: nothing dialled it,
  ;; so there is no completion to report.
  (define-record-type (connect-d make-connect-d connect-d?)
    (fields (immutable recipient connect-d-recipient)
            (mutable state connect-d-state connect-d-set-state!))
    (nongenerative)
    (sealed #t))

  ;; -> #t if THIS call is the one that concluded the attempt.
  ;;
  ;; THE TEST AND THE TRANSITION ARE ONE STEP, and the delivery sits inside it.
  ;; Split, two concluding paths both read 'pending and both deliver. deliver is
  ;; a send and does not yield, so the region costs nothing and closes the window
  ;; completely.
  ;;
  ;; A dead recipient is not a failure to report: the answer is dropped, as any
  ;; message to a dead process is. What matters is that the attempt is marked
  ;; concluded either way, so no later path can find it pending and answer again.
  (define (complete-once! d msg)
    (and d
         (with-interrupts-disabled
           (and (eq? (connect-d-state d) 'pending)
                (begin
                  (connect-d-set-state!
                    d (if (eq? (vector-ref msg 0) 'tcp-connected)
                          'connected
                          'failed))
                  (let ((o (connect-d-recipient d)))
                    (when o (deliver o msg)))
                  #t)))))

  (define (connect-submit! host port owner d ctx sni)
    ;; The address buffer is a process-wide singleton and the allocations
    ;; below are preemption points: another green process starting its own
    ;; connect (or a listener binding) would overwrite the address we just
    ;; resolved, and we would connect to ITS host. Also covers the
    ;; connect-table mutation. Nothing here yields.
    (uv-sockaddr-lease (lambda (sockaddr-buf)
    (check 'uv-ip4-addr (uv-ip4-addr host port sockaddr-buf))
    (let ((h (foreign-alloc tcp-handle-size))
          (inited? #f)
          (req #f)
          (indexed? #f))
      ;; WHAT HAS BEEN TAKEN SO FAR, AND NOTHING ELSE. Each flag is set
      ;; immediately after the step that makes the resource ours, so the
      ;; release below never guesses: it undoes exactly what happened.
      ;; The alternative -- one cleanup that assumes the common case --
      ;; is what turns a failure in the middle into either a leak or a
      ;; double free, depending on where it stopped.
      ;;
      ;; It runs at most once. The guard re-raises after releasing, and
      ;; the synchronous-failure path below runs it only after the guard
      ;; has already been left behind.
      (define (release!)
        (when indexed?
          (unindex-owner! owner 'connect req)
          (set! indexed? #f))
        (when req
          (hashtable-delete! connect-table req)
          (foreign-free req)
          (set! req #f))
        (if inited? (uv-close h on-close-entry) (foreign-free h))
        (set! inited? #f))
      (let ((r (guard (e (#t (release!) (raise e)))
                 (check 'uv-tcp-init (uv-tcp-init (uv-loop-handle) h))
                 (set! inited? #t)
                 ;; INJECTION POINT 'connect-oom -- OWNING GUARD: the guard
                 ;; opened on the line above, and it is MEANT to catch this.
                 ;; That is the branch under test: the handle is inited and
                 ;; nothing else is, so release! must close it and free
                 ;; nothing else. There is no other guard between here and
                 ;; the assertion; the re-raise leaves tcp-connect! and the
                 ;; cell reads the two counts after the loop has run.
                 (inject-fault! 'connect-oom)
                 (set! req (foreign-alloc connect-req-size))
                 ;; THREE SLOTS, and the third is #f for a plaintext dial: that
                 ;; path answers once, from the callback, and has no other
                 ;; place it could answer from.
                 (hashtable-set! connect-table req
                                 (vector h owner d ctx sni))
                 (index-owner! owner 'connect req)
                 (set! indexed? #t)
                 ;; INJECTION POINT 'tcp-connect-refused -- OWNING GUARD:
                 ;; the same guard lexically, but it does NOT catch this
                 ;; one and must not: a refused submission is a negative
                 ;; RETURN, not a raise, so it flows out of the guard to
                 ;; the (when (< r 0) (release!) ...) below. The two
                 ;; points share a guard and exercise different branches,
                 ;; which is why they are separate points and not one.
                 (inject-return! 'tcp-connect-refused
                   (uv-tcp-connect req h sockaddr-buf on-connect-entry)))))
        (when (< r 0)
          (release!)
          (error (if ctx 'tcp-connect-tls! 'tcp-connect!) (uv-strerror r)))
        #t)))))

  ;; The plaintext dial, unchanged in behaviour: no completion record and no
  ;; TLS context, so the connect callback answers it directly and once.
  (define (tcp-connect! host port owner)
    (connect-submit! host port owner #f #f #f))

  ;; The TLS dial. Two things differ from the plaintext face, and both follow
  ;; from the handshake sitting between the TCP connect and anything the owner
  ;; can do with the connection:
  ;;
  ;; THE OWNER IS NOT TOLD AT TCP CONNECT. #(tcp-connected c) arrives only once
  ;; TLS is established, because a connection whose handshake has not run
  ;; cannot carry a byte the owner writes on it.
  ;;
  ;; THE ANSWER GOES THROUGH A COMPLETION RECORD. Between submission and
  ;; establishment the attempt can end at the TCP layer, in the initialiser, in
  ;; the handshake, or by the owner dying -- four places, each of which would
  ;; otherwise answer for itself. D makes exactly one of them the answer.
  ;;
  ;; sni is the name sent in the ClientHello, and the name verified against the
  ;; peer certificate when the context verifies at all; #f sends none.
  (define (tcp-connect-tls! host port owner ctx sni)
    (connect-submit! host port owner
                     (make-connect-d owner 'pending)
                     ctx sni))

  (define uv-tcp-getpeername
    (foreign-procedure "uv_tcp_getpeername" (void* void* void*) int))

  ;; The peer's IPv4 address as "a.b.c.d", or #f (not open, IPv6, or the
  ;; socket is gone). This is the ONLY caller-visible identity a remote
  ;; client cannot forge -- unlike any header it sends -- so it is what
  ;; per-client policy (rate limiting, banning) must key on.
  ;; THE STATE TEST AND THE HANDLE USE ARE ONE UNINTERRUPTIBLE STEP, here
  ;; and at every other FFI call that passes conn-handle -- a rule
  ;; this file has not always followed: tcp-stop-listen! split its test
  ;; from its uv-close until the incarnation work put them back
  ;; together, and listener-backlog-effective did the same. This is the
  ;; invariant, stated once for all of them:
  ;;
  ;;   a conn's handle may be passed to libuv only inside a region where
  ;;   its state has been observed 'open WITHOUT an intervening safe point
  ;;
  ;; It is not hygiene. close_cb -- the only place handle memory is freed
  ;; (see on-close-code) -- runs in the event-loop process, so it can only
  ;; interleave where this process can be preempted. Testing the state,
  ;; yielding, and then using the handle is a use-after-free: another
  ;; process closes, the loop runs the close callback, foreign-free
  ;; returns the memory, and the FFI call that follows hands libuv a dead
  ;; pointer. Inside a with-interrupts-disabled region there is no
  ;; preemption, the event loop cannot run, and the observation still
  ;; holds when the call is made.
  ;;
  ;; The test is for 'open specifically, not for "not closed": a handle
  ;; that has been submitted to uv_close is 'closing, and no FFI call
  ;; should touch it again even though its memory is still there.
  (define (conn-peer-ip c)
    (uv-peername-lease (lambda (peername-buf peername-len)
      (and (eq? (conn-state c) 'open)
           (begin
             (foreign-set! 'int peername-len 0 128)
             (and (>= (uv-tcp-getpeername (conn-handle c)
                                          peername-buf peername-len) 0)
                ;; sockaddr_in: sin_family differs in layout across
                ;; platforms, but sin_addr is always at offset 4
                (let ((fam (case platform-os
                             ((macos freebsd) (foreign-ref 'unsigned-8 peername-buf 1))
                             (else (foreign-ref 'unsigned-16 peername-buf 0)))))
                  (and (= fam AF-INET)
                       (string-append
                         (number->string (foreign-ref 'unsigned-8 peername-buf 4)) "."
                         (number->string (foreign-ref 'unsigned-8 peername-buf 5)) "."
                         (number->string (foreign-ref 'unsigned-8 peername-buf 6)) "."
                         (number->string (foreign-ref 'unsigned-8 peername-buf 7)))))))))))

  ;; Start delivering #(tcp-data ...) messages to the conn's owner.
  ;; Call after conn-set-owner!.
  ;; ASK WHETHER IT IS ALREADY READING; DO NOT DECODE AN ERRNO. Both the
  ;; accept path and the delayed on-accept start reading on a TLS connection,
  ;; so the second call is expected and must not read as a failure. An earlier
  ;; version compared the return against a hardcoded UV_EALREADY of -114 --
  ;; which is Linux's errno. EALREADY is 37 on macOS and on FreeBSD, where
  ;; every igropyr deployment runs, so on the machines that matter the normal
  ;; second start was counted as an error.
  ;;
  ;; uv_is_active answers the actual question and has no per-platform number
  ;; in it, so the redundant call is skipped rather than made and forgiven --
  ;; and any negative return that does happen is then a real failure.
  (define (tcp-read-start! c)
    (with-interrupts-disabled          ; test and use: see conn-peer-ip
      (if (not (eq? (conn-state c) 'open))
          #f
          (if (not (fx= 0 (uv-is-active (conn-handle c))))
              #t                        ; already reading: nothing to do
              (let ((r (uv-read-start (conn-handle c)
                                      on-alloc-entry on-read-entry)))
                (if (fx>= r 0)
                    #t
                    (begin (set! accept-error-count
                                 (bump-saturating accept-error-count))
                           #f)))))))

  ;; Stop delivering #(tcp-data ...), so the kernel's receive window closes
  ;; and the PEER is slowed down.
  ;;
  ;; Without this the loop reads as fast as the peer sends and copies every
  ;; segment into an unbounded actor mailbox, so a consumer that is slower
  ;; than its producer accumulates raw bytes in memory instead of exerting
  ;; back pressure -- and before any parser limit applies, because those
  ;; run on bytes that have already been queued. An actor mailbox is not a
  ;; substitute for the kernel's flow control.
  ;;
  ;; Safe to call when reads are already stopped, and on a closed conn.
  (define (tcp-read-stop! c)
    (with-interrupts-disabled          ; test and use: see conn-peer-ip
      (when (eq? (conn-state c) 'open)
        (uv-read-stop (conn-handle c))))
    (void))

  ;; Queue `len` bytes for an async write. fill-data! copies them into
  ;; the foreign data area. Allocates one block [uv_write_t][uv_buf_t]
  ;; [payload]; write_cb frees it and runs on-done in callback context
  ;; (must not yield). Returns #t if queued, #f on immediate error.
  (define (enqueue-write! c len fill-data! on-done)
    ;; INJECTION POINT (E1, allocation failure). Placed BEFORE the
    ;; allocation and before anything is published, so an injected raise
    ;; leaves exactly the state a real out-of-memory would: no block, no
    ;; write-table entry, nothing for the caller to unwind.
    ;;
    ;; IT IS NOT OUTSIDE EVERY INTERRUPT REGION, and an earlier note
    ;; here said it was -- checked lexically, where it does sit before
    ;; this procedure's own region, and not against the callers.
    ;; tcp-writev!'s small-write path enters a region and reaches here
    ;; without leaving it, and node.sc calls tcp-writev! inside
    ;; `atomically` as well. Raising there is nonetheless right: the
    ;; allocation this stands in for is in the same place, so the
    ;; injection reproduces the real failure rather than a tidier one.
    (inject-fault! 'writev-oom)
    (let* ((block (alloc-write-block! (+ write-req-size buf-t-size len)))
           (buf-ptr (+ block write-req-size))
           (data-ptr (+ buf-ptr buf-t-size)))
      (fill-data! data-ptr)
      (foreign-set! 'void* buf-ptr 0 data-ptr)
      (foreign-set! 'unsigned-64 buf-ptr 8 len)
      ;; PUBLISH BEFORE SUBMITTING. uv-write can complete before it returns
      ;; (a fast loopback write), and the callback looks the block up in
      ;; write-table -- so registering afterwards is a race the writer
      ;; loses: the completion finds nothing, frees the block, and the
      ;; writer then registers a freed address that nothing will ever
      ;; answer. Upstream that is a stream, a node send or a database
      ;; operation parked forever.
      ;;
      ;; Registering first cannot leak: the only way out without a
      ;; completion is uv-write failing, and that path removes the entry
      ;; again. The whole publish/submit pair is interrupt-free so the
      ;; callback cannot observe a half-built state.
      ;; The caller tested the state, but that was before this block was
      ;; allocated and filled -- both safe points. Re-testing HERE, inside
      ;; the region that submits, is what satisfies the invariant stated
      ;; at conn-peer-ip; the earlier test is an early-out, not a
      ;; guarantee. A connection closed in between takes the same exit as
      ;; a rejected uv-write: the block is freed and on-done reports the
      ;; failure, so the caller's accounting balances either way.
      ;; THE SEAL IS TESTED WHERE THE STATE IS (E9), in the same region and
      ;; on the same exit. Once the close_notify alert has been submitted
      ;; nothing else may reach this handle: a request queued behind the
      ;; alert would be written AFTER a TLS endpoint said it was done, which
      ;; the peer is entitled to treat as a protocol violation rather than
      ;; as data. The sealing entry below is the one writer that passes.
      ;;
      ;; TEST SEAM 'write-before-region -- OWNING REGION: NONE on the path
      ;; that matters, which is the whole point of putting it HERE. The
      ;; block exists and is filled, and the state has not yet been re-read,
      ;; so a victim parked on this line holds a block whose connection can
      ;; be closed underneath it. Resuming it then drives the in-region
      ;; rejection below -- the release site that nothing else can reach,
      ;; because every ordinary caller tests the state before allocating.
      ;;
      ;; WHETHER IT PARKS DEPENDS ON HOW THE WRITE ARRIVED, and a cell has
      ;; to know which of the three it is getting. Measured, not reasoned:
      ;;   - a payload too big for the scratch buffer arrives at depth 1 and
      ;;     PARKS -- the only path that gives a cell the window;
      ;;   - a payload that fits the scratch reaches this procedure only when
      ;;     uv_try_write refused or wrote a prefix, and then it arrives from
      ;;     inside uv-scratch-lease's region and counts a SKIP;
      ;;   - a small write that succeeds outright NEVER REACHES HERE AT ALL,
      ;;     so the point is not hit and the row stays `armed`.
      ;; node.sc's writes inside `atomically` are in the skipping class.
      (inject-barrier! 'write-before-region)
      (with-interrupts-disabled
        (if (or (not (eq? (conn-state c) 'open)) (conn-raw-sealed? c))
            (begin
              ;; COUNTED POINT: unarmed it is silent.
              (inject-barrier! 'write-block-released-plain-reject)
              (free-write-block! block)
              (when on-done (on-done -1))
              #f)
            (begin
              ;; GUARDED, BECAUSE THE BLOCK HAS NO OWNER UNTIL THIS SUCCEEDS.
              ;; hashtable-set! allocates; a raise here left the block allocated with
              ;; nothing that knew about it -- not even a counter, which is why the
              ;; leak had no observable at all.
              (guard (e (#t (inject-barrier! 'write-block-released-register-fail)
                            (free-write-block! block)
                            (raise e)))
                (inject-fault! 'write-register-oom)
                (hashtable-set! write-table block
                  (or on-done (lambda (status) (void)))))
              ;; INJECTION POINT (E1, negative errno). It wraps the RAW
              ;; FFI call and nothing else, which is what inject-return!
              ;; requires: when armed the call is SKIPPED, so the block is
              ;; never handed to libuv and the failure path below is free
              ;; to free it. Wrapping anything that had already acted on
              ;; the result would fake a failure after the work was done.
              (let ((r (inject-return! 'uv-write-neg
                         (uv-write block (conn-handle c) buf-ptr 1 on-write-entry))))
                (if (< r 0)
                    (begin
                      (hashtable-delete! write-table block)
                      (inject-barrier! 'write-block-released-plain-neg)
                      (free-write-block! block)
                      (when on-done (on-done r))
                      #f)
                    #t)))))))

  ;; THE ONE WRITER THAT MAY PASS THE SEAL, and it is the writer that SETS
  ;; it (E9). The flag and the submission are one region, so there is no
  ;; instant at which the alert is queued and the handle is not yet sealed --
  ;; a competing writer preempting into that gap would land behind the alert,
  ;; which is exactly what the seal exists to prevent.
  ;;
  ;; THE BLOCK IS ALLOCATED AND FILLED BY THE CALLER, before the region and
  ;; under the caller's guard: foreign-alloc can raise, and raising inside
  ;; this region would leave the seal set with no alert on the wire.
  ;;
  ;; on-done may run INLINE here, when uv_write refuses immediately. That is
  ;; safe because the only on-done this entry is given retires the
  ;; connection, and retirement is idempotent by shape (it wins or loses one
  ;; atomic detach) -- so a synchronous retire from inside this region and an
  ;; asynchronous one from the completion callback cannot both take effect.
  (define (enqueue-write-sealing! c t block buf-ptr on-done)
    (with-interrupts-disabled
      ;; INJECTION POINT 'tls-sealing-reject -- an OVERRIDE on the rejection
      ;; TEST, not on a call: the test is evaluated and its answer replaced,
      ;; so an armed cell reaches the release below on a connection that is
      ;; genuinely open. It needs a seam because this entry is private -- the
      ;; close-notify path is its only caller and a second close is suppressed
      ;; by finishing? -- so no ordinary write can make this branch run.
      (if (inject-override! 'tls-sealing-reject
            (or (not (eq? (conn-state c) 'open)) (conn-raw-sealed? c)))
          (begin
            (inject-barrier! 'write-block-released-sealing-reject)
            (free-write-block! block)
            (when on-done (on-done -1))
            #f)
          (begin
            ;; shutdown? and raw-sealed? go up together: the first says a
            ;; drain owns this connection, the second says the transport is
            ;; closed to everyone else. Setting either alone would be a
            ;; state no reader has a rule for.
            (conn-tls-set-shutdown! t #t)
            (conn-set-raw-sealed! c #t)
            ;; GUARDED FOR THE REASON THE PLAINTEXT REGISTRATION IS, with one
            ;; addition: the caller relinquished this block before calling, so its
            ;; own `block` is already #f and a raise reaching that outer guard finds
            ;; nothing to release. No double free.
            (guard (e (#t (inject-barrier! 'write-block-released-register-fail)
                          (free-write-block! block)
                          (raise e)))
              (inject-fault! 'write-register-oom)
              (hashtable-set! write-table block
                (or on-done (lambda (status) (void)))))
            ;; INJECTION POINT 'uv-write-sealing-neg -- the sealing twin of
            ;; 'uv-write-neg: it wraps the RAW submission, so an injected negative
            ;; skips the call and the release below is the real one.
            (let ((r (inject-return! 'uv-write-sealing-neg
                       (uv-write block (conn-handle c) buf-ptr 1 on-write-entry))))
              (if (< r 0)
                  (begin
                    (hashtable-delete! write-table block)
                    (inject-barrier! 'write-block-released-sealing-neg)
                    (free-write-block! block)
                    (when on-done (on-done r))
                    #f)
                  #t))))))

  ;; Write a sequence of bytevectors as one response. Small writes take
  ;; the uv_try_write fast path: the segments are packed into the shared
  ;; scratch buffer and written synchronously, skipping the write_req /
  ;; write_cb / hashtable / foreign-alloc of the queued path entirely --
  ;; on-done runs inline with status 0. A partial write or EAGAIN falls
  ;; back to the queued path for the unwritten remainder; writes larger
  ;; than the scratch go straight to the queued path. on-done runs in
  ;; caller context on the fast path (safe: not inside a libuv callback)
  ;; and in callback context on the queued path; either way it must not
  ;; yield. Returns #f if the connection is not open (on-done ran -1).
  ;; THE RAW SINK. Bytes go out exactly as given: no codec, no gate, no
  ;; accounting. For a TLS connection these bytes are always CIPHERTEXT, and
  ;; every kind of it comes through here -- handshake records, close_notify,
  ;; and application records alike (W1). tls-raw-sink-writes counts them all,
  ;; which makes it a consistency check and NOT an oracle: the discriminator
  ;; for "handshake output went through the codec-aware entry by mistake" is
  ;; the handshake failing from double encryption, not this counter moving.
  (define (tcp-writev-raw! c segs on-done)
    (bump-raw-sink-writes!)
    (if (not (eq? (conn-state c) 'open))
        (begin (when on-done (on-done -1)) #f)
        (let ((total (fold-left (lambda (a b) (+ a (bytevector-length b))) 0 segs)))
          (cond
            ((<= total uv-write-scratch-size)
             ;; The staging area and the uv_buf_t are process-wide
             ;; singletons, and this runs in ordinary green processes (an
             ;; HTTP worker writing a response, a db client sending a query)
             ;; with the preemption timer live. The packing loop and its
             ;; foreign calls are safe points, so without this region a
             ;; second writer could overwrite the scratch between our pack
             ;; and our uv_try_write -- and we would send ITS bytes on OUR
             ;; socket.
             ;;
             ;; THE LEASE IS THAT REGION. It hands both buffers to this
             ;; thunk with interrupts disabled and takes them back on
             ;; return, so everything below -- the state test, the pack, the
             ;; try_write, the partial result, the fast-path on-done, the
             ;; remainder copy, the write-table publication and the uv_write
             ;; submission -- still happens in one uninterruptible stretch,
             ;; in the order it always did. It is exit-safe; nothing here
             ;; yields.
             (uv-scratch-lease (lambda (write-scratch write-scratch-size scratch-buf)
             ;; The state test at the top of this procedure is an
             ;; early-out; the fold above it is a safe point, so the
             ;; observation that matters is this one, made in the same
             ;; region as the call. See conn-peer-ip for the invariant.
             (if (or (not (eq? (conn-state c) 'open)) (conn-raw-sealed? c))
                 (begin (when on-done (on-done -1)) #f)
                 (begin
                   ;; pack segments into scratch, then write in one shot
                   (let loop ((ss segs) (off 0))
                     (unless (null? ss)
                       (let ((n (bytevector-length (car ss))))
                         (memcpy-to-c (+ write-scratch off) (car ss) n)
                         (loop (cdr ss) (+ off n)))))
                   (foreign-set! 'void* scratch-buf 0 write-scratch)
                   (foreign-set! 'unsigned-64 scratch-buf 8 total)
                   ;; INJECTION POINT (E1, "nothing went out yet").
                   ;; Frames up to the scratch size finish here and never
                   ;; reach the queued path, so without this knob the
                   ;; small control frames -- mon, mdown, demon, a short
                   ;; rsend -- can never be made to fail. Injecting 0
                   ;; (EAGAIN) sends the caller down the queue-it-all
                   ;; branch, where the other two knobs live.
                   ;;
                   ;; ZERO, NEVER A POSITIVE PARTIAL COUNT. 0 is not
                   ;; something uv_try_write actually returns for a
                   ;; non-empty buffer -- libuv gives a positive count or
                   ;; a negative UV_EAGAIN -- so this is a surrogate, and
                   ;; it is chosen as the smallest value that lands on
                   ;; the queue-everything branch below without claiming
                   ;; any byte was written. A positive count would
                   ;; make the caller queue only the suffix -- the
                   ;; counter-example inject-return!'s rule is written
                   ;; against, and unrecoverable at every layer above.
                   (let ((n (inject-return! 'try-write-eagain
                              (uv-try-write (conn-handle c) scratch-buf 1))))
                     (cond
                       ((= n total)                 ; fully written now
                        (when on-done (on-done 0)) #t)
                       ((and (> n 0) (< n total))   ; partial: queue the rest
                       ;; A PARTIAL WRITE HAS ALREADY PUT BYTES ON THE
                       ;; WIRE, so failing to queue the remainder is not
                       ;; a failure to send -- it is a stream that now
                       ;; carries a truncated message with no way to
                       ;; retract it. Whatever is written next would be
                       ;; read as the missing tail. There is no recovery
                       ;; from that at this layer or any layer above it,
                       ;; so the connection is closed: the peer sees a
                       ;; connection drop, which every protocol on top of
                       ;; this already knows how to handle, instead of a
                       ;; framing error it has no vocabulary for.
                       ;; The close covers both ways queueing can fail --
                       ;; a returned #f, and a raise on the way there.
                        (let ((queued
                                (guard (e (#t (tcp-close! c) (raise e)))
                                  (enqueue-write! c (- total n)
                                    (lambda (dest)
                                      (memcpy-cc dest (+ write-scratch n)
                                                 (- total n)))
                                    on-done))))
                          (unless queued (tcp-close! c))
                          queued))
                       (else                        ; EAGAIN/0: queue all
                        (enqueue-write! c total
                          (lambda (dest) (memcpy-cc dest write-scratch total))
                          on-done)))))))))
            (else                                    ; too big for scratch
             (enqueue-write! c total
               (lambda (dest)
                 (let loop ((ss segs) (off 0))
                   (unless (null? ss)
                     (let ((n (bytevector-length (car ss))))
                       (memcpy-to-c (+ dest off) (car ss) n)
                       (loop (cdr ss) (+ off n))))))
               on-done))))))

  ;; single-bytevector write (websocket / redis / mysql)
  ;; A TLS listener is an ordinary listener whose incarnation carries a
  ;; server context. The context belongs to THIS incarnation and is retired
  ;; once when the listener is stopped -- a listener that changes incarnation
  ;; without retiring leaks one context per generation.
  (define (tcp-listen-tls! host port backlog on-accept ctx . opts)
    (apply tcp-listen! host port backlog on-accept
           (if (pair? opts) (car opts) 0) ctx '()))

  ;; ---- the conn's one timer (X3 / Y3 / Y4 / Z2) ---------------------------
  ;;
  ;; ONE TIMER FOR THE CONNECTION'S WHOLE LIFE. It is armed for the
  ;; handshake, STOPPED (not freed) on establishment, and re-armed for the
  ;; clean-shutdown deadline. So after a successful handshake the live timer
  ;; count is 1 and the active count is 0 -- allocating a second timer for
  ;; shutdown is the mutation that row exists to catch.
  (define tls-handshake-ms 10000)
  (define tls-shutdown-ms 2000)
  (define (tls-handshake-ms-set! n) (set! tls-handshake-ms n))
  (define (tls-shutdown-ms-set! n) (set! tls-shutdown-ms n))

  (define timer-conns (make-eqv-hashtable))   ; timer address -> conn
  (define next-timer-id 0)

  ;; INIT FAILURE AND START FAILURE ARE NOT THE SAME BOOKKEEPING (Y4).
  ;; uv_timer_init failing means the handle was never initialised: it is freed
  ;; DIRECTLY and must not be handed to uv_close. A uv_timer_start failure
  ;; after a successful init means libuv owns it, so it goes out through
  ;; uv_close and the close callback frees the memory -- the same distinction
  ;; the listener allocation already makes.
  ;; -> the timer address, or #f (the caller closes the conn).
  (define (tls-timer-new! c ms)
    (let ((tm (foreign-alloc timer-handle-size)))
      (if (fx< (inject-override! 'tls-timer-init-fail
                                 (uv-timer-init (uv-loop-handle) tm)) 0)
          (begin (note-timer-free! 'direct-free-uninitialised)
                 (foreign-free tm) #f)          ; never initialised
          (begin
            (bump-live-timers! 1)
            (hashtable-set! timer-conns tm c)
            (if (fx< (inject-override! 'tls-timer-start-fail
                                       (uv-timer-start tm on-tls-timer-entry ms 0)) 0)
                (begin
                  ;; initialised, so libuv owns it: out through uv_close
                  (hashtable-delete! timer-conns tm)
                  (uv-close tm on-tls-timer-close-entry)
                  #f)
                (begin (bump-active-timers! 1)
                       (conn-tls-set-timer-armed! (conn-tls c) #t)
                       tm))))))

  (define (tls-timer-stop! t)
    (let ((tm (conn-tls-timer t)))
      (when (and tm (conn-tls-timer-armed? t))
        (conn-tls-set-timer-armed! t #f)
        (uv-timer-stop tm)
        (bump-active-timers! -1))))

  ;; ONE REGION, AND THE HANDLE IS RE-READ INSIDE IT. As three separate
  ;; steps this both drifted the count -- a timer due immediately could fire
  ;; and be closed before the armed flag was published, so nothing decremented
  ;; -- and, far worse, allowed uv_timer_start on freed memory: the handle was
  ;; captured, another process retired the connection, the close callback
  ;; freed it, and the original process then started it.
  ;; -> #t if a bound is armed when this returns, #f if none could be. The
  ;; RESULT IS THE POINT (E9): the clean-close drain must never wait without
  ;; a bound, so its caller has to be able to tell. Before E9 this returned
  ;; whatever `when` produced and every caller ignored it.
  ;;
  ;; RESTARTING AN ALREADY-ARMED TIMER IS ALLOWED, and does not touch the
  ;; active count: uv_timer_start on a running timer restarts it, so the
  ;; handle is armed before and after and the count would double-report a
  ;; single armed timer. The drain's idle bound is exactly this operation --
  ;; each completion pushes the deadline out.
  (define (tls-timer-rearm! t ms)
    (with-interrupts-disabled
      (let ((tm (conn-tls-timer t)))     ; re-read: retirement sets it to #f
        (and tm
             (let ((was-armed? (conn-tls-timer-armed? t)))
               ;; INJECTION POINT 'tls-timer-rearm-fail -- OWNING REGION:
               ;; the with-interrupts-disabled above. It wraps the RAW FFI
               ;; call and nothing else, so an armed override supplies the
               ;; result uv_timer_start would have given and every branch
               ;; below runs as it would have on a real failure.
               ;;
               ;; DISTINCT FROM 'tls-timer-start-fail, which covers the
               ;; handshake arm only. A cell forcing the drain's progress
               ;; rearm to fail needs a point that the handshake path does
               ;; not also hit, or it cannot say which arm it broke.
               ;;
               ;; Interrupt state: injection ON and OFF alike -- this is a
               ;; return point, not a barrier; it never parks.
               (and (fx>= (inject-override! 'tls-timer-rearm-fail
                            (uv-timer-start tm on-tls-timer-entry ms 0))
                          0)
                    (begin
                      (unless was-armed?
                        (conn-tls-set-timer-armed! t #t)
                        (bump-active-timers! 1))
                      #t)))))))

  ;; Idempotent, and the ONLY path that gives the timer back: stop, then
  ;; uv_close, and only the close callback frees the memory.
  (define (tls-timer-close! t)
    (let ((tm (conn-tls-timer t)))
      (when tm
        ;; AN ARMED TIMER GIVES ITS ACTIVE COUNT BACK HERE. Closing one
        ;; without decrementing left active at 1 while live was already 0 --
        ;; which is what the clean-close path produced, because it RE-ARMS the
        ;; timer for the shutdown deadline and then closes it.
        (when (conn-tls-timer-armed? t)
          (conn-tls-set-timer-armed! t #f)
          (bump-active-timers! -1))
        (conn-tls-set-timer! t #f)
        (uv-timer-stop tm)
        (hashtable-delete! timer-conns tm)
        (uv-close tm on-tls-timer-close-entry))))

  (define on-tls-timer-close
    (lambda (tm)
      (bump-live-timers! -1)
      (note-timer-free! 'close-callback)
      (foreign-free tm)))

  (define on-tls-timer
    (lambda (tm)
      (let ((c (hashtable-ref timer-conns tm #f)))
        (when c
          (conn-tls-retire! c 'timer-expiry 'tls-timeout)))))

  ;; ---- the per-listener handshaking ceiling (Y1) --------------------------
  (define tls-handshake-max 1024)
  (define (tls-handshake-max-set! n) (set! tls-handshake-max n))

  (define (listener-incarnation h) (hashtable-ref listener-table h #f))
  (define (incarnation-tls-ctx v) (and v (vector-ref v 3)))
  (define (listener-handle-of v) (and v (vector-ref v 4)))

  ;; -> #t when a slot was taken. Refusal is the caller's business: an
  ;; over-ceiling conn is closed at once, with no SSL object created (X3).
  (define (listener-slot-take! v)
    (and v
         (with-interrupts-disabled
           (let ((n (vector-ref v 2)))
             (and (fx< n tls-handshake-max)
                  (begin (vector-set! v 2 (fx+ n 1))
                         (bump-handshaking! 1)
                         #t))))))

  ;; RELEASED EXACTLY ONCE, and the flag that guarantees it lives on the
  ;; CONN, not on the listener: every exit path -- establishment, handshake
  ;; failure, timer expiry, hard or clean close, pre-publication failure --
  ;; converges here, and only the first of them decrements.
  ;; Released exactly once, and it reads the slot off the CONN so it works
  ;; both before and after the TLS record exists.
  (define (conn-slot-release! c)
    (let ((v (with-interrupts-disabled
               (let ((v (conn-slot c)))
                 (when v (conn-set-slot! c #f))
                 v))))
      (when v
        (vector-set! v 2 (fx- (vector-ref v 2) 1))
        (bump-handshaking! -1))))

  ;; ---- accepting a TLS connection ----------------------------------------
  ;;
  ;; NOTHING HERE MAY RAISE INTO C. This runs in a libuv callback frame, so
  ;; every step that can raise -- session construction allocates and reads the
  ;; OpenSSL queue -- sits inside a guard that converts a raise into a local
  ;; close. Interrupt exclusion is no substitute: it has no rollback.
  ;; Bring up the TLS client role on a connection whose TCP connect has just
  ;; completed. Runs inside the connect callback.
  ;;
  ;; THE RECORD IS ATTACHED BEFORE THE TIMER EXISTS, and the order is the point.
  ;; tls-timer-new! can fail, and its failure has to be cleaned up by the
  ;; retirement path -- which only exists once conn-tls is set. Attaching second
  ;; would leave a session owned by nobody at exactly the moment something went
  ;; wrong.
  ;;
  ;; EVERY EXIT HERE CONCLUDES THE ATTEMPT. This procedure is the only thing
  ;; between a completed TCP connect and an established TLS session, so a
  ;; failure it swallows is an owner waiting forever for a message never sent.
  (define (tls-client-init! c d ctx sni)
    ;; BOTH OF THESE ARE VISIBLE TO THE GUARD, which is why they are bound out
    ;; here. The session used to be bound inside the guarded body, so a raise
    ;; between creating it and attaching it left the handler unable to name the
    ;; thing it had to free: the session simply leaked.
    ;;
    ;; ATTACHMENT IS TRACKED EXPLICITLY rather than read back from (conn-tls c).
    ;; That field is also what a concurrent retirement clears, so a handler
    ;; reading it could see #f for a record that WAS attached, and then free a
    ;; session the retirement already owns.
    (let ((sess #f) (attached? #f))
      (guard (e (#t (note-swallowed! 'tls-client-init e)
                    (guard (e2 (#t (note-swallowed! 'tls-client-init-cleanup e2)))
                      (if attached?
                          ;; retirement owns the session and the timer, and it
                          ;; fails D as it detaches
                          (conn-tls-retire! c 'pre-publication e)
                          (begin
                            ;; nothing attached: this frame still owns both the
                            ;; session and the answer
                            (note-retire-reason! 'pre-publication e)
                            (when sess (tls-session-retire! sess e))
                            (complete-once! d (vector 'tcp-connect-failed 'tls-init-raised))
                            (tcp-close-raw! c))))
                    #f))
        (set! sess (tls-session-new! ctx))
        (let ((why (tls-session-configure-client! sess sni)))
          (if why
              (begin
                ;; the session is ours and nothing else can reach it yet
                (tls-session-retire! sess why)
                (note-retire-reason! 'client-configure why)
                (complete-once! d (vector 'tcp-connect-failed 'tls-configure-failed))
                (tcp-close-raw! c)
                #f)
              (let ((t (make-conn-tls
                         sess
                         #f          ; listener -- absence of one IS the client role
                         #f          ; established?
                         #f          ; owner-published?
                         #f          ; eof?
                         #f          ; eof-sent?
                         #t          ; gated? -- nothing is delivered before the
                                     ;           watcher opens the gate
                         '()         ; inbound
                         #f #f '()   ; holder, holder-monitor, waiters
                         #f #f       ; closed?, closing?
                         #f #f       ; finishing?, shutdown? (E9)
                         #f          ; aggregate
                         #f          ; timer
                         (let ((i next-timer-id))
                           (set! next-timer-id (fx+ i 1)) i)
                         #f          ; timer-armed?
                         #f          ; watcher
                         0 0 0 0     ; bio-held raw-queued charged refunded
                         #f          ; slot? -- a dial takes no handshake slot
                         #f #f #f    ; gate-opened-ms, retire-path, reason
                         #f          ; effect-depths
                         #f          ; abort-cb
                         d)))        ; connect-d -- this dial's one answer
                (conn-set-tls! c t)
                (set! attached? #t)
                (let ((tm (tls-timer-new! c tls-handshake-ms)))
                  (if (not tm)
                      (begin
                        (conn-tls-retire! c 'timer-failed 'tls-timer-failed)
                        #f)
                      (begin
                        (conn-tls-set-timer! t tm)
                        ;; Same fatality as the accept side, and here it must also conclude
                        ;; the attempt: retirement fails D.
                        (unless (tcp-read-start! c)
                          (conn-tls-retire! c 'read-start-failed 'tls-read-start-failed))
                        ;; The ClientHello: the dialer speaks first, so without
                        ;; this pump nothing is ever sent and both ends wait.
                        (tls-pump! c t)
                        #t)))))))))

  (define (tls-accept! c v ctx)
    ;; A FAILURE HERE IS AN ABORT, NOT A CLEAN CLOSE. Calling tcp-close!
    ;; was wrong in a way a cell caught: by this point conn-set-tls! has run,
    ;; so tcp-close! dispatched to the CLEAN-close path -- which sends a
    ;; close_notify on a session that never established, and recorded the
    ;; retirement as (clean-close . tls-closed). X2/X5 say the opposite: a
    ;; pre-publication failure retires the session and closes the unpublished
    ;; handle, with no alert, and the reason recorded is this one.
    ;; THE HANDLER ITSELF MUST NOT RAISE. In R6RS a raise from the selected
    ;; guard clause propagates outward, so cleanup that can fail -- a deliver,
    ;; a close -- would escape this frame after all. It is wrapped again.
    (guard (e (#t (note-swallowed! 'tls-accept e)
                  (guard (e2 (#t (note-swallowed! 'tls-accept-cleanup e2)))
                    (if (conn-tls c)
                      (conn-tls-retire! c 'pre-publication e)
                      (begin
                        ;; nothing was attached, so retirement cannot run --
                        ;; but the slot may already be held (it is taken
                        ;; before any allocation), and it is released here or
                        ;; nowhere.
                        (note-retire-reason! 'pre-publication e)
                        (conn-slot-release! c)
                        (tcp-close-raw! c))))
                  #f))
      ;; THE CEILING IS CHECKED BEFORE ANY SSL OBJECT EXISTS (X3): an
      ;; over-limit connection costs a handle and nothing else.
      (if (not (listener-slot-take! v))
          (begin (tcp-close-raw! c) #f)
          (begin
            ;; THE SLOT IS RECORDED ON THE CONN BEFORE ANY ALLOCATION. It
            ;; used to be tracked only on the conn-tls record, which does not
            ;; exist yet -- so a raise between taking the slot and attaching
            ;; that record leaked the slot for the life of the listener, and
            ;; the ceiling drifted down one place per failure.
            (conn-set-slot! c v)
            (inject-fault! 'tls-accept-after-slot)
          (let ((sess (tls-session-new! ctx)))
            (let ((why (tls-session-configure-server! sess)))
              (if why
                  (begin
                    ;; same shape as above: nothing is published yet, so this
                    ;; is a direct retire-and-close, and it says so.
                    (note-retire-reason! 'pre-publication why)
                    (tls-session-retire! sess why)
                    (conn-slot-release! c)
                    (tcp-close-raw! c)
                    #f)
                  (let ((t (make-conn-tls
                             sess v
                             #f          ; established?
                             #f          ; owner-published?
                             #f          ; eof?
                             #f          ; eof-sent?
                             #t          ; gated? -- Z12: nothing is delivered
                             '()         ; inbound
                             #f #f '()   ; holder, holder-monitor, waiters
                             #f #f       ; closed?, closing?
                             #f #f       ; finishing?, shutdown? (E9)
                             #f          ; aggregate
                             #f          ; timer
                             (let ((i next-timer-id))
                               (set! next-timer-id (fx+ i 1)) i)
                             #f          ; timer-armed?
                             #f          ; watcher
                             0 0 0 0     ; bio-held raw-queued charged refunded
                             #t          ; slot? -- taken above
                             #f #f #f    ; gate-opened-ms, retire-path, reason
                             #f          ; effect-depths
                             #f          ; abort-cb
                             #f)))       ; connect-d -- nothing dialled this
                    ;; INSTALLED BEFORE THE CONN IS PUBLISHED (X2). Until
                    ;; conn-table has this handle nothing else in the process
                    ;; can reach the session, so a failure from here on is
                    ;; ours alone to clean up.
                    (conn-set-tls! c t)
                    (inject-fault! 'tls-accept-before-publish)
                    (hashtable-set! conn-table (conn-handle c) c)
                    (inject-fault! 'tls-accept-after-publish)
                    (let ((tm (tls-timer-new! c tls-handshake-ms)))
                      (if (not tm)
                          (begin (conn-tls-retire! c 'timer-failed 'tls-timer-failed) #f)
                          (begin
                            (conn-tls-set-timer! t tm)
                            ;; the handshake is driven by the read callback, so
                            ;; reading has to start before there is an owner
                            ;;
                            ;; A REFUSED READ-START IS FATAL, and its return was ignored. Without
                            ;; a read there is no callback, so the handshake never advances and
                            ;; nothing times it out on this side: the connection sits
                            ;; established-never, holding a session and a timer.
                            (unless (tcp-read-start! c)
                              (conn-tls-retire! c 'read-start-failed 'tls-read-start-failed))
                            (tls-pump! c t)
                            #t)))))))))))

  ;; CIPHERTEXT STRAIGHT INTO THE READ PATH, for rows that must control how
  ;; many raw reads a flight arrives in. TCP may split or coalesce whatever a
  ;; client writes, so "the client sent two records in one write" is not
  ;; something a cell can assert from the client side; this hands the bytes to
  ;; the same code the read callback would, in one delivery.
  (define (tls-inject-ciphertext! c bv)
    (guard (e (#t (note-swallowed! 'tls-inject e)
                  (guard (e2 (#t (note-swallowed! 'tls-inject-cleanup e2)))
                    (conn-tls-retire! c 'inject-raise 'tls-read-failed))
                  #f))
    (let ((t (conn-tls c)))
      (when t
        (bump-server-raw-read! (bytevector-length bv))
        (let ((werr (tls-session-feed! (conn-tls-session t) bv)))
          (if werr
              (conn-tls-retire! c 'feed-failed 'tls-read-failed)
              (tls-pump! c t)))))))

  ;; ---- the handshake driver and the read path ----------------------------
  (define (tls-on-read c t nread buf)
    ;; same shape as the accept guard: the handler's own cleanup is wrapped,
    ;; because a raise from a guard clause propagates out of this callback.
    (guard (e (#t (note-swallowed! 'tls-on-read e)
                  (guard (e2 (#t (note-swallowed! 'tls-on-read-cleanup e2)))
                    (conn-tls-retire! c 'read-raise 'tls-read-failed))
                  #f))
      (cond
        ((> nread 0)
         (let ((bv (make-bytevector nread)))
           (memcpy-from-c bv (foreign-ref 'void* buf 0) nread)
           (bump-server-raw-read! nread)
           (note-read-stage! 'data)
           (inject-fault! 'tls-read-step)
           (let ((werr (tls-session-feed! (conn-tls-session t) bv)))
             (note-read-stage! (if werr 'fed-err 'fed-ok))
             (if werr
                 (conn-tls-retire! c 'feed-failed 'tls-read-failed)
                 (tls-pump! c t)))))
        ((= nread 0) (note-read-stage! 'zero))
        ((= nread UV-EOF)
         (note-read-stage! 'fin)
         ;; A BARE FIN IS NOT AN EOF. close_notify sets eof? on the way
         ;; through the read loop; without it the stream was cut, and saying
         ;; "eof" would let a truncated response read as a complete one.
         ;;
         ;; AND IT WAITS FOR THE GATE. Delivering here while the gate is
         ;; shut put the EOF in front of plaintext that was still buffered.
         (if (conn-tls-eof? t)
             (tls-deliver-eof-once! c t)
             ;; BEFORE ESTABLISHMENT THIS IS NOT AN OWNER ERROR. A dial is answered
             ;; only at establishment, so the owner has not been told this
             ;; connection exists and #(tcp-error ...) would arrive about something
             ;; it never heard of. Retirement concludes the attempt through D
             ;; instead, which is the message it is actually waiting for.
             ;; THE NOTIFICATION IS NO LONGER SENT HERE. It is claimed with
             ;; the retirement instead, in the one exclusion that decides who
             ;; owns the connection -- so this path cannot notify an owner that
             ;; a competing retirement has already answered, and the
             ;; pre-publication test it used to make by hand is now the
             ;; eligibility rule every path shares.
             (conn-tls-retire! c 'truncated-eof 'tls-truncated-eof)))
        (else (note-read-stage! 'err) (conn-tls-retire! c 'read-error nread)))))

  ;; Not established: step, drain to the raw sink, stop when OpenSSL wants
  ;; more. Established: decrypt and deliver or buffer.
  (define (tls-pump! c t)
    (note-read-stage! (if (conn-tls-established? t) 'pump-est 'pump-hs))
    (if (conn-tls-established? t)
        (tls-read-plaintext! c t)
        (let loop ()
          (bump-ssl-op!)
          ;; THE OVERRIDE REPLACES BOTH VALUES, BEFORE ANY SUCCESS TEST
          ;; (W3). The real step runs -- the state is genuine -- and only the
          ;; verdict is forced; replacing a pair assembled after a success
          ;; branch had already been taken would change nothing.
          (let-values (((verdict payload)
                        (let-values (((v p) (tls-session-handshake-step!
                                              (conn-tls-session t))))
                          (let ((forced (inject-override! 'tls-handshake-result #f)))
                            (if forced (values forced #f) (values v p))))))
            ;; classify BEFORE draining, then send whatever the step produced
            ;; -- including the alert that explains a failure
            ;; A REFUSED HANDSHAKE WRITE IS FATAL, and its return was ignored.
            ;; The flight this drains is what the peer is waiting for; if it
            ;; never reaches the socket the handshake stalls until a timer ends
            ;; it, and on the dial side the attempt would never be concluded at
            ;; all. Retirement is the honest answer and carries D with it.
            ;; THE COMPLETION IS NOT #f, and it was. A queued handshake write that
            ;; fails ASYNCHRONOUSLY reports through on-done and nowhere else, so #f
            ;; meant a flight that never reached the peer retired nothing and
            ;; concluded no attempt.
            (let ((wrote?
                    (let ((out (tls-session-drain! (conn-tls-session t))))
                      (or (not out)
                          (tcp-writev-raw! c (list out)
                            ;; INJECTION POINT 'tls-handshake-write-status --
                            ;; OWNING REGION: whichever this completion runs in,
                            ;; and it is a RETURN point either way, so it never
                            ;; parks. It wraps a VARIABLE, not a call: the rule
                            ;; that inject-return! must only skip a call which
                            ;; did nothing else is vacuous here, because reading
                            ;; an argument does nothing at all. The real write
                            ;; stands; only the verdict this completion is given
                            ;; is forced.
                            ;;
                            ;; IT COVERS BOTH ARRIVALS, AND THAT IS DELIBERATE.
                            ;; tcp-writev-raw! calls this lambda inline when
                            ;; uv_try_write takes the whole flight (3833) and
                            ;; from the loop's write callback when the flight
                            ;; queues. An inline forced negative would retire
                            ;; BEFORE tls-established! runs, which is a
                            ;; different failure from the one this point exists
                            ;; for -- so the caller that wants the late one
                            ;; forces the flight onto the queued path with
                            ;; 'try-write-eagain (3829) rather than this
                            ;; library growing a branch to tell the two apart.
                            (lambda (status0)
                              (let ((status (inject-return!
                                              'tls-handshake-write-status
                                              status0)))
                                (when (fx< status 0)
                                  (conn-tls-retire! c 'handshake-write-failed
                                                    'tls-handshake-write-failed)))))))))
              ;; AND A SYNCHRONOUS FAILURE STOPS THE PUMP. Falling through to the
              ;; verdict after the write failed meant a 'done step built a watcher on
              ;; a connection this frame had just retired, and delivered
              ;; #(tcp-connected) for a dial that had already failed.
              (if (not wrote?)
                  (conn-tls-retire! c 'handshake-write-failed
                                    'tls-handshake-write-failed)
                  (case verdict
              ((done)
               (tls-established! c t)
               ;; DECRYPT IMMEDIATELY, AND THIS LINE IS THE WHOLE OF X3/H13.
               ;; A client normally sends its request in the SAME flight as its
               ;; Finished, so by the time the handshake reports done those
               ;; bytes are ALREADY in the read BIO. There will be no further
               ;; read callback -- the client has said everything it intends to
               ;; and is waiting for the response -- so if nothing decrypts
               ;; here the request is never seen and both ends wait forever.
               ;; Measured before this line existed: handshake complete, two
               ;; raw reads with the request in the second, ssl-op-count frozen
               ;; at the handshake's three, and the client giving up after 4 s.
               ;;
               ;; The gate is still closed at this point (Z12), so what comes
               ;; out is buffered and the watcher delivers it in order.
               ;;
               ;; ESTABLISHMENT CAN RETIRE THIS CONNECTION, so the record is re-read
               ;; rather than reused. tls-established! retires on a listener that went
               ;; away during the handshake, and on the dial side if the watcher cannot
               ;; be spawned -- both leave conn-tls detached while t still names the
               ;; record we were handed. Decrypting into a retired session is a read
               ;; through a pointer its owner has already given back.
               (when (eq? (conn-tls c) t)
                 (tls-read-plaintext! c t)))
              ((want-read) (void))                 ; wait for more ciphertext
              ((gone) (conn-tls-retire! c 'session-gone 'tls-conn-closed))
              ;; want-write IS AN ERROR HERE (W3), not a state to wait in:
              ;; the write BIO is unbounded, so OpenSSL asking for room means
              ;; something this code does not model.
              (else
                (conn-tls-retire! c 'handshake-failed
                                  (or payload 'tls-handshake-failed))))))))))

  ;; ESTABLISHMENT ORDER (Z12). The callback may not yield, and a spawned
  ;; process only runs after it returns, so this installs the owner, asks for
  ;; a watcher, leaves the gate CLOSED and returns. The watcher opens the gate
  ;; and drains what was buffered -- which is why the first plaintext of a TLS
  ;; connection arrives one scheduling turn later than on a plaintext one
  ;; (declared residual R-h).
  (define (tls-established! c t)
    (conn-tls-set-established! t #t)
    (tls-timer-stop! t)                      ; stopped, NOT freed (Z2/Y3)
    ;; A dialled connection never took a handshake slot, so this is a no-op for
    ;; it: conn-slot-release! reads the field and does nothing when it is #f.
    ;; That is why the client role needs no branch here and never touches
    ;; handshaking-count -- the existing shape already gives it.
    (conn-slot-release! c)
    (if (not (conn-tls-listener t))
        ;; ---- client role ------------------------------------------------
        ;;
        ;; FORKED BEFORE THE INCARNATION CHECK, and it has to be. That check
        ;; asks whether this connection's listener row is still in the listener
        ;; table; a dialled connection has no listener at all, so it would fail
        ;; the test and retire every successful dial with 'listener-gone. The
        ;; absence of a listener IS the client role.
        ;;
        ;; THE WATCHER EXISTS BEFORE THE ATTEMPT IS ANSWERED. The owner acts on
        ;; #(tcp-connected c) immediately -- writing on it is the normal first
        ;; move -- and a write needs the gate, which is the watcher's to grant.
        ;; Announcing the connection first would hand the owner a connection
        ;; whose gate nobody is there to give it.
        (begin
          (unless uv-tls-watcher-spawner
            (assertion-violation 'tls-established!
              "a TLS dial needs (igropyr tls-watch) imported: it installs the watcher spawner hook"))
          (conn-tls-set-watcher! t (uv-tls-watcher-spawner c))
          (bump-watchers! 1)
          (note-watcher! (conn-tls-watcher t))
          ;; Same callback frame, after the watcher is registered. The attempt
          ;; is concluded exactly once -- here, or on a failure path, never both.
          ;;
          ;; PUBLISHED BEFORE THE ANSWER, IN THIS FRAME. From the next line on
          ;; the owner knows the connection, so a retirement is entitled to
          ;; send it a terminal error; setting this after the answer would
          ;; leave a window in which the owner holds a connection that a
          ;; retirement believes it has never seen.
          (conn-tls-set-owner-published! t #t)
          (complete-once! (conn-tls-connect-d t) (vector 'tcp-connected c)))
        ;; ---- listener role ----------------------------------------------
        ;; revalidate the incarnation: the listener row can go during a handshake
        (let ((v (conn-tls-listener t)))
      (if (not (and v (eq? v (hashtable-ref listener-table
                                            (listener-handle-of v) #f))))
          (conn-tls-retire! c 'listener-gone 'tls-listener-stopped)
          (begin
            ((vector-ref v 1) c)             ; the delayed on-accept: owner in
            ;; on-accept is what hands this connection to an owner, so from
            ;; here it is published -- same frame, for the reason on the dial
            ;; side.
            (conn-tls-set-owner-published! t #t)
            (unless uv-tls-watcher-spawner
              (assertion-violation 'tls-accept!
                "a TLS listener needs (igropyr tls-watch) imported: it installs the watcher spawner hook"))
            (conn-tls-set-watcher! t (uv-tls-watcher-spawner c))
            (bump-watchers! 1)
            (note-watcher! (conn-tls-watcher t))
            ;; THE LAST LINE OF THE CALLBACK FRAME, which is exactly what
            ;; H18(a) needs: it asserts this frame RETURNED before the watcher
            ;; ran. Establishment happens inside the read callback, so this --
            ;; not the accept callback -- is where that frame ends.
            ;;
            ;; IT COUNTS ARRIVAL AT THIS LINE, NOT SUCCESS. Reading it as
            ;; "the owner was installed" would be reading more than it says.
            ;; It had no call site at all until now, so any earlier reading of
            ;; it was structurally 0 and meant nothing.
            (bump-accept-completion!))))))

  ;; EOF goes to the owner at most once, and only once the gate is open --
  ;; before that it stays recorded and the watcher delivers it after the
  ;; buffered plaintext, in order.
  (define (tls-deliver-eof-once! c t)
    (let ((send? (with-interrupts-disabled
                   (and (not (conn-tls-gated? t))
                        (not (conn-tls-eof-sent? t))
                        (begin (conn-tls-set-eof-sent! t #t) #t)))))
      (when send?
        (let ((o (conn-owner c))) (when o (deliver o (vector 'tcp-eof)))
          (bump-eof-delivery!)))))

  ;; Decrypt what arrived and either deliver it or hold it until the watcher
  ;; opens the gate.
  (define (tls-read-plaintext! c t)
    (note-read-stage! 'decrypt)
    (bump-ssl-op!)
    (let-values (((out eof?) (tls-session-decrypt! (conn-tls-session t) #vu8())))
      (when eof? (conn-tls-set-eof! t #t))
      ;; post-handshake protocol output (ticket acks, key updates)
      (let ((back (tls-session-drain! (conn-tls-session t))))
        (when back (tcp-writev-raw! c (list back) #f)))
      (when (fx> (bytevector-length out) 0)
        (if (conn-tls-gated? t)
            (conn-tls-set-inbound! t (append (conn-tls-inbound t) (list out)))
            (let ((o (conn-owner c)))
              (when o (deliver o (vector 'tcp-data out))))))
      (note-read-stage! (if eof? 'decrypt-eof 'decrypt-done))
      (when eof? (tls-deliver-eof-once! c t))))

  ;; ---- retirement of a TLS connection ------------------------------------
  ;;
  ;; IDEMPOTENT BY SHAPE. The conn's tls field is the gate: the region below
  ;; detaches it, and whoever loses that race finds #f and does nothing. That
  ;; matters because owner death and watcher death can arrive together, so no
  ;; caller can promise to run this once -- "exactly once" here means exactly
  ;; one EFFECTIVE retirement, not one call.
  ;;
  ;; THE REGION HOLDS SHARED-STATE EDITS ONLY (Delta 11). The refusal sends,
  ;; the session free and uv_close all happen after it: N sends and an
  ;; SSL_free inside one disabled region would be the widest region in this
  ;; file, and the waiter list has already been TAKEN, so nothing else can
  ;; answer those waiters no matter how long we take to do it.
  (define (conn-tls-retire! c path reason)
    (let* ((entry (retire-entry-depth))
           (taken
             (with-interrupts-disabled
               (let ((t (conn-tls c)))
                 (and t
                      (begin
                        (conn-set-tls! c #f)          ; <- the gate
                        ;; THE ATTEMPT IS CONCLUDED IN THE SAME EXCLUSION THAT DETACHES
                        ;; (mesh TLS). A dial that fails after its TLS record is attached ends
                        ;; HERE and nowhere else -- timer failure, a refused read-start, a
                        ;; handshake alert, a listener going away, an owner DOWN. Without this
                        ;; line every one of those left the dialer waiting for a message that
                        ;; no remaining path would send.
                        ;;
                        ;; Claimed with the detach so a second retirement cannot re-answer:
                        ;; whoever wins this exclusion owns the connection, and complete-once!
                        ;; is itself once-only, so a dial already answered by establishment is
                        ;; left alone.
                        ;; GUARDED, BECAUSE NOTHING AFTER IT MAY BE SKIPPED. Non-yielding does
                        ;; not mean non-raising: building the message or delivering it can raise,
                        ;; and every release below -- the reason, the depths, closed?, the slot,
                        ;; the session, the timer, the handle -- would then be skipped. Worse,
                        ;; the caller's own handler would retry the retirement, find conn-tls
                        ;; already #f, and do nothing: the connection would be orphaned with no
                        ;; path left that could free it.
                        ;;
                        ;; Losing the notification is the cheaper failure. If the raise came
                        ;; after the transition, D is already 'failed and the attempt IS
                        ;; concluded -- only the message went missing, and the dialer still
                        ;; learns through its own monitor. A leaked session has no second route.
                        (guard (e2 (#t (note-swallowed! 'retire-complete e2)))
                          (complete-once! (conn-tls-connect-d t)
                                          (vector 'tcp-connect-failed (cons path reason))))
                        ;; THE TERMINAL NOTIFICATION IS CLAIMED WITH THE
                        ;; RETIREMENT, in the same exclusion that decides who
                        ;; owns this connection. Sent from the losing paths
                        ;; instead, two competing retirements could each tell
                        ;; the owner, or the one that lost the detach could
                        ;; tell it after the winner had already finished.
                        ;; Whoever wins this exclusion is the only process
                        ;; entitled to speak, so the send belongs here.
                        ;;
                        ;; The recipient is read INSIDE the region, with the
                        ;; decision: reading it afterwards would let the owner
                        ;; change between deciding to notify and notifying.
                        ;;
                        ;; deliver is send -- insert and schedule, no yield --
                        ;; so it is legal with interrupts disabled and in every
                        ;; frame that can win here (read callback, write
                        ;; completion, timer, actor).
                        ;;
                        ;; SILENT PATHS, and why each is silent: the owner
                        ;; either does not exist yet (no-owner,
                        ;; closed-before-established, pre-publication), never
                        ;; will (listener-gone), or asked for this itself and
                        ;; is not to be told its own close was an error
                        ;; (closing?). A dead owner is silent because nothing
                        ;; reads its mailbox. Anything else notifies: a path
                        ;; added later is more safely noisy than silent, since
                        ;; the failure it prevents is a reader parked forever.
                        ;;
                        ;; GUARDED SEPARATELY from the answer above, and for
                        ;; the same reason: this runs in winner frames that
                        ;; have no outer guard, and nothing below it may be
                        ;; skipped. Losing the message costs a wake-up; losing
                        ;; the releases below leaks the connection.
                        (guard (e2 (#t (note-swallowed! 'retire-notify e2)))
                          (let ((o (conn-owner c)))
                            (when (and (conn-tls-owner-published? t)
                                       (not (conn-tls-closing? t))
                                       (not (memq path '(listener-gone
                                                         no-owner
                                                         closed-before-established
                                                         pre-publication)))
                                       o
                                       (or (not uv-alive?) (uv-alive? o)))
                              (deliver o (vector 'tcp-error reason)))))
                        ;; INJECTION POINT 'ret-gate-closed -- OWNING REGION:
                        ;; the with-interrupts-disabled this cond sits in.
                        ;; Placed where the state is DETACHED but not yet
                        ;; marked closed, which is the only moment those two
                        ;; facts disagree.
                        ;;
                        ;; SKIPPED BY CONSTRUCTION: the region is held, and
                        ;; parking here would leave a connection detached from
                        ;; its conn with closed? still #f -- the inconsistent
                        ;; state this region exists to make unobservable.
                        ;;
                        ;; Interrupt state: injection ON -- depth 2, so
                        ;; 'skipped; injection OFF -- (void).
                        (inject-barrier! 'ret-gate-closed)
                        ;; the accumulator lives ON THE RECORD, not in a
                        ;; module variable: the effects below are preemptible,
                        ;; so another conn's retirement can interleave with
                        ;; them and would clobber a shared one.
                        ;; RECORDED IMMEDIATELY AFTER THE DETACH. It used
                        ;; to be written near the end of the region, so a
                        ;; failure in between left a retirement that had
                        ;; certainly happened with no reason attached -- and
                        ;; "no reason" reads exactly like "never retired".
                        (note-retire-reason! path reason)
                        (retire-depths-init! t entry)
                        (note-shared-depth! t)
                        (conn-tls-set-closed! t #t)
                        (conn-slot-release! c)
                        ;; the aggregate is shared state, so it is terminalised
                        ;; here; unconditionally on pending (Z4)
                        (let ((a (conn-tls-aggregate t)))
                          (when a
                            (conn-tls-set-abort-cb! t
                              (tls-agg-terminalise! a reason))))
                        ;; ONLY THE WINNER WRITES THE REASON. A later
                        ;; idempotent call must not overwrite it with a
                        ;; generic one: the first cause is the one worth
                        ;; keeping.
                        (conn-tls-set-retire-path! t path)
                        (conn-tls-set-retire-reason! t reason)
                        (let ((ws (conn-tls-waiters t)))
                          (conn-tls-set-waiters! t '())
                          (note-shared-depth! t)
                          ;; THE TIMER AND THE SESSION GO BACK INSIDE THE
                          ;; REGION. They are foreign calls that allocate no
                          ;; Scheme memory, so they do not break the rule the
                          ;; region exists for -- and leaving them outside was
                          ;; measured to be worse: once conn-tls is detached,
                          ;; a kill before them orphans the timer and the
                          ;; session forever, because every later retirement
                          ;; sees #f and does nothing, and the expiring timer
                          ;; routes back through the same detached field.
                          ;;
                          ;; ONLY THE REFUSAL SENDS STAY OUTSIDE: they
                          ;; allocate, and there are as many of them as there
                          ;; are waiters.
                          (note-effect-depth! t 'session-retire)
                          (tls-session-retire! (conn-tls-session t)
                                               "tls: connection retired")
                          (when (conn-tls-timer t) (tls-timer-close! t))
                          (note-effect-depth! t 'uv-close)
                          (unless (eq? (conn-state c) 'closed)
                            (tcp-close-raw! c))
                          (cons t ws))))))))
      (when taken
        (let ((t (car taken)) (ws (cdr taken)))
          ;; whoever took the list answers it; these are sends, so they are
          ;; out here
          (for-each (lambda (w)
                      (note-effect-depth! t 'refusal)
                      (deliver (car w) (vector 'tcp-write-refused reason)))
                    ws)
          ;; THE CURRENT HOLDER IS REFUSED TOO. A writer granted the gate is
          ;; no longer on the waiter list, so refusing only the list left it
          ;; parked forever whenever the process that granted it died between
          ;; recording it as holder and telling it so. Refusing the holder
          ;; closes that case; the residual -- a kill between the atomic take
          ;; and the send -- needs a deterministic handoff and is declared,
          ;; not fixed, here.
          (let ((h (conn-tls-holder t)))
            (when h
              (note-effect-depth! t 'refusal)
              (deliver h (vector 'tcp-write-refused reason))))
          ;; the aborted write's own callback, fired outside the region
          (let ((cb (conn-tls-abort-cb t)))
            (when cb
              (conn-tls-set-abort-cb! t #f)
              (cb (if (fixnum? reason) reason -1))))
          ;; the watcher's exit is a consequence of the close, never a
          ;; prerequisite: nothing below waits for it
          (let ((w (conn-tls-watcher t)))
            (when w (deliver w (vector 'tls-retire))))
          #t))))

  ;; ---- application writes on a TLS connection ----------------------------
  ;;
  ;; Bounded chunks so that computing the charge cannot itself create an
  ;; unbounded transient (W4/X4).
  (define tls-chunk-size 16384)

  ;; ONE aggregate per application write, however many TLS records it becomes
  ;; (X1). Raw completions -- which may run INLINE on a full uv_try_write --
  ;; may only decrement pending, record first-error, and mark completed? once
  ;; sealed? and pending = 0; they never call user code and never re-enter SSL.
  (define next-agg-id 0)
  (define (fresh-agg-id) (let ((i next-agg-id)) (set! next-agg-id (fx+ i 1)) i))

  (define-record-type (tls-agg make-tls-agg tls-agg?)
    (fields
      (immutable id tls-agg-id)
      (mutable pending tls-agg-pending tls-agg-set-pending!)
      (mutable sealed? tls-agg-sealed? tls-agg-set-sealed!)
      (mutable error tls-agg-error tls-agg-set-error!)
      (mutable done? tls-agg-done? tls-agg-set-done!)
      (mutable cb tls-agg-cb tls-agg-set-cb!))
    (nongenerative)
    (sealed #t))

  ;; TERMINALISATION IS UNCONDITIONAL ON pending (Z4). An inline completion
  ;; can leave an unsealed aggregate at pending = 0, and an abort that skipped
  ;; it would let a surviving writer seal it later and fire the callback.
  ;; -> THE CALLBACK TO FIRE, OR #f, AND THE CALLER FIRES IT OUTSIDE THE
  ;; REGION. Clearing cb without ever calling it meant an application write in
  ;; flight when the connection was retired NEVER completed: the raw
  ;; completion afterwards saw done? and did nothing, and the writer waited
  ;; for an answer that could not come. Terminalising is a shared-state edit
  ;; and belongs in the region; invoking user code does not.
  (define (tls-agg-terminalise! a why)
    (and (not (tls-agg-sealed? a))
         (let ((cb (tls-agg-cb a)))
           (unless (tls-agg-error a) (tls-agg-set-error! a why))
           (tls-agg-set-done! a #t)
           (tls-agg-set-cb! a #f)
           cb)))

  ;; The user callback runs exactly once, OUTSIDE the serialised unit, by
  ;; whichever side observes sealed? and pending = 0 first.
  (define (tls-agg-maybe-finish! a)
    (let ((cb (with-interrupts-disabled
                (and (tls-agg-sealed? a)
                     (fx= (tls-agg-pending a) 0)
                     (not (tls-agg-done? a))
                     (let ((cb (tls-agg-cb a)))
                       (tls-agg-set-done! a #t)
                       (tls-agg-set-cb! a #f)
                       cb)))))
      (when cb (cb (or (tls-agg-error a) 0)))))

  ;; Acquire the write gate. ONE interrupt-disabled step on shared state, and
  ;; the message to the watcher is only a ping (Z8): testing the gate and then
  ;; sending would lose the request when retirement runs between the two.
  ;;
  ;; -> 'held when this caller now holds it, 'refused with the reason, or
  ;; 'parked when it was appended to the waiter list.
  ;; -> the pid of the process making an APPLICATION write.
  ;;
  ;; INTERNAL OUTPUT NEVER ASKS. Handshake records, close_notify and the
  ;; post-handshake protocol output go straight to the raw sink and take no
  ;; gate: they originate in a libuv callback frame, where the caller is the
  ;; event-loop process, and making that process a gate HOLDER would mean the
  ;; watcher monitoring the loop itself. The assertion below states that as a
  ;; mechanism rather than a convention -- if internal output ever reaches the
  ;; gate, it fails here instead of installing an unmonitorable holder.
  (define (tls-writer-identity)
    (when (uv-in-callback?)
      (assertion-violation 'tls-gate-acquire!
        "internal TLS output must use the raw sink, not the write gate"))
    (unless uv-self
      (assertion-violation 'tls-gate-acquire!
        "an application write on a TLS connection needs the actor layer's identity hook (uv-set-self!); a pure libuv program cannot make one"))
    (uv-self))

  (define (tls-gate-acquire! t me agg)
    (with-interrupts-disabled
      (cond
        ((conn-tls-closed? t) (cons 'refused 'tls-conn-closed))
        ((conn-tls-closing? t) (cons 'refused 'tls-closing))
        ((conn-tls-holder t)
         ;; INJECTION POINT 'gate-holder-append -- OWNING REGION: the
         ;; with-interrupts-disabled wrapping this cond. It sits after the
         ;; holder test and before the waiter is on the list, the window in
         ;; which a writer has been judged "must wait" but nothing yet records
         ;; that it is waiting.
         ;;
         ;; SKIPPED BY CONSTRUCTION: parking here would hold the region
         ;; while the list is mid-update, and both release and retirement read
         ;; that list atomically to decide who gets answered.
         ;;
         ;; Interrupt state: injection ON -- depth 2, so 'skipped;
         ;; injection OFF -- (void).
         (inject-barrier! 'gate-holder-append)
         ;; a pointer write on a cell the caller allocated before the region
         (conn-tls-set-waiters! t (append (conn-tls-waiters t) (list (cons me agg))))
         (cons 'parked #f))
        (else
          (conn-tls-set-holder! t me)
          (conn-tls-set-aggregate! t agg)
          (cons 'held #f)))))

  ;; EVERY GRANT IS ANNOUNCED, INCLUDING THE UNCONTENDED ONE. Z5 requires
  ;; the holder to be monitored FROM THE MOMENT IT HOLDS, and the watcher is
  ;; the only process that can monitor on anyone's behalf. Recording a holder
  ;; without telling the watcher left the common case -- an uncontended
  ;; acquisition -- unwatched: a WebSocket sender that died mid-aggregate
  ;; produced no DOWN at all and the gate stayed held for the connection's
  ;; life. The rare contended path was watched and the ordinary one was not,
  ;; which is the worst way round.
  (define (tls-gate-announce-holder! t pid)
    (let ((w (conn-tls-watcher t)))
      (when w (deliver w (vector 'tls-gate-granted pid)))))

  ;; Application write. The gate is held for the WHOLE aggregate; preemption
  ;; between chunk units is preserved (Y5), so what is serialised is
  ;; aggregates, not steps.
  (define (tls-conn-writev! c t segs on-done)
    (let* ((agg (make-tls-agg (fresh-agg-id) 0 #f #f #f on-done))
           (me  (tls-writer-identity))
           (got (tls-gate-acquire! t me agg)))
      (when (eq? (car got) 'held) (tls-gate-announce-holder! t me))
      (case (car got)
        ((refused)
         (when on-done (on-done -1))
         #f)
        ((parked)
         ;; A PARKED WRITER MUST WAIT. Writing anyway was a defect: two
         ;; writers on one connection would interleave their TLS records, and
         ;; serialising aggregates is the entire reason this gate exists
         ;; (Z3/Z5). It went unnoticed because HTTP allows one outstanding
         ;; write per connection, so the gate is uncontended there -- the
         ;; WebSocket senders it was built for are where it would have bitten.
         ;;
         ;; No timeout: every waiter gets exactly one outcome, because both
         ;; release and retirement answer whoever they atomically took off the
         ;; list (Z7/Z8).
         (tls-gate-ping! t)
         (unless uv-gate-wait
           (assertion-violation 'tls-conn-writev!
             "an application write on a TLS connection needs the actor layer's gate wait hook (uv-set-gate-wait!), installed by (igropyr tls-watch)"))
         (let ((answer (uv-gate-wait)))
           (if (eq? answer 'held)
               (tls-conn-write-chunks! c t agg segs on-done)
               (begin (when on-done (on-done -1)) #f))))
        (else
          ;; INJECTION POINT 'tls-after-held -- OWNING REGION: NONE.
          ;; ANCHORED AS "after a successful acquire, before the first
          ;; chunk", NOT as "after the announcement". tls-gate-announce-holder!
          ;; only tells the watcher; it is asynchronous and its position may
          ;; change, and this hook must NOT travel with it -- what a cell
          ;; needs is the gap between holding the gate and writing anything.
          ;;
          ;; PARKS: no region is held here, so a victim stops holding the
          ;; gate with the aggregate still empty -- which is the state a
          ;; competing writer or a retirement has to cope with.
          ;;
          ;; Interrupt state: injection ON -- depth 1, parks;
          ;; injection OFF -- (void).
          (inject-barrier! 'tls-after-held)
          (tls-conn-write-chunks! c t agg segs on-done)))))

  ;; The watcher tells us it is gone. Without this the live count only ever
  ;; rises, and a reading of 1 after retirement says nothing about whether the
  ;; watcher actually exited -- which is exactly how it was read once.
  ;; IT TAKES THE WATCHER'S OWN PID, NOT THE CONN (E9). By the time a watcher
  ;; exits, conn-tls may already be detached, so the connection can no longer
  ;; name the process that is leaving. Idempotent: removing a pid twice, or
  ;; one that was never recorded, is a no-op.
  (define (tls-watcher-exited! pid)
    (bump-watchers! -1)
    (forget-watcher! pid))

  ;; ---- what the watcher may touch ----------------------------------------
  ;;
  ;; THE WATCHER LIVES ABOVE actor AND TOUCHES NO RECORD FIELD. It reaches
  ;; the connection's shared state only through the operations below, which
  ;; are the same ones writers use, so there is exactly one discipline for the
  ;; gate rather than one per caller.

  ;; -> the entry granted the gate (pid . aggregate), or #f. Takes it in one
  ;; step, so a retirement racing this either finds the entry on the list or
  ;; does not see it at all.
  (define (tls-gate-grant-next! c)
    (let ((t (conn-tls c)))
      (and t
           (with-interrupts-disabled
             (let ((ws (conn-tls-waiters t)))
               (cond
                 ((or (null? ws) (conn-tls-closed? t) (conn-tls-holder t)) #f)
                 (else
                   (conn-tls-set-waiters! t (cdr ws))
                   (conn-tls-set-holder! t (car (car ws)))
                   (conn-tls-set-aggregate! t (cdr (car ws)))
                   (car ws))))))))

  ;; The live shared list's length -- read off the list itself, never off a
  ;; count kept beside it: a separate counter zeroed at teardown would answer
  ;; for a list that still had entries on it.
  (define (tls-gate-waiters-length c)
    (let ((t (conn-tls c)))
      (if (not t) 0 (with-interrupts-disabled (length (conn-tls-waiters t))))))

  (define (tls-conn-holder c)
    (let ((t (conn-tls c))) (and t (conn-tls-holder t))))

  ;; IS A CLEAN-CLOSE DRAIN IN PROGRESS ON THIS CONNECTION (E9)? The watcher
  ;; asks before acting on an owner DOWN: once the alert is queued under its
  ;; bound the owner is not needed to finish writing, and retiring on its
  ;; death would uv_close the handle and cancel the very bytes the drain
  ;; exists to deliver. A detached conn answers #f -- there is nothing left
  ;; to drain.
  ;; The peer certificate's channel-binding digest, or #f when the connection
  ;; has no TLS record, no peer certificate, or a signature algorithm with no
  ;; usable mapping. A caller that needs a binding must read #f as "no binding
  ;; available" and refuse -- never as an empty one, which would let two
  ;; different situations produce the same proof.
  (define (tls-conn-peer-cb-hash c)
    (let ((t (conn-tls c)))
      (and t (tls-session-peer-cb-hash (conn-tls-session t)))))

  (define (tls-conn-shutdown? c)
    (let ((t (conn-tls c))) (and t (conn-tls-shutdown? t) #t)))

  (define (tls-conn-holder-monitor c)
    (let ((t (conn-tls c))) (and t (conn-tls-holder-monitor t))))

  (define (tls-conn-set-holder-monitor! c m)
    (let ((t (conn-tls c))) (when t (conn-tls-set-holder-monitor! t m))))

  ;; "THE BUFFER IS EMPTY" AND "THE GATE IS OPEN" ARE ONE FACT (Z14).
  ;; They are established in the SAME region, and that is the whole content of
  ;; this procedure's correctness. Deciding emptiness in one region and opening
  ;; in a second left a window in between: the watcher is interruptible there,
  ;; the event-loop process can run a read callback, tls-read-plaintext! sees
  ;; gated? still #t and appends B to inbound -- and then the second region
  ;; opens the gate and this call returns. NOTHING REVISITS B. The watcher
  ;; calls open-and-drain ONCE (tls-watch.sc), so that plaintext was stranded
  ;; for the life of the connection, with no error and no counter moving.
  ;;
  ;; THE GATE STAYS SHUT UNTIL A ROUND FINDS NOTHING LEFT. Each round takes
  ;; a batch with the gate STILL CLOSED and delivers it outside the region, so
  ;; anything arriving meanwhile is appended to the buffer and cannot overtake
  ;; what is already in flight. Only the round that finds the buffer empty
  ;; opens the gate, in that same region. Bytes therefore either arrived
  ;; before (buffered, drained here, in order) or after (delivered directly).
  ;;
  ;; THE DELIVERIES MUST STAY OUTSIDE. deliver can raise and can be
  ;; preempted; holding the region across an arbitrary number of them would
  ;; make the drain's cost unbounded inside a no-interrupt window. Only the
  ;; empty decision, the gate fields, the timestamps and the counters are in.
  ;;
  ;; THE OWNER IS CHECKED BEFORE THE BUFFER IS TAKEN. Clearing first and
  ;; then finding no owner discarded that plaintext permanently. on-accept is
  ;; external code and may simply not install one, so the connection is
  ;; retired instead -- with a reason a cell can read.
  (define (tls-open-gate-and-drain! c)
    (let ((t (conn-tls c)))
      (when t
        (if (not (conn-owner c))
            (conn-tls-retire! c 'no-owner 'tls-no-owner)
            (let loop ()
              (let ((batch (with-interrupts-disabled
                             (let ((held (conn-tls-inbound t)))
                               (conn-tls-set-inbound! t '())
                               (when (null? held)
                                 ;; INJECTION POINT 'z14-empty-open -- OWNING
                                 ;; REGION: the with-interrupts-disabled on the
                                 ;; line above, between deciding the buffer is
                                 ;; empty and opening the gate. That is exactly
                                 ;; the seam this fix closed, so the point
                                 ;; exists to show it STAYS closed.
                                 ;;
                                 ;; SKIPPED BY CONSTRUCTION: the region is
                                 ;; held, so a victim cannot park here -- and
                                 ;; must not, since parking would reopen the
                                 ;; window by hand. A cell arms it to prove the
                                 ;; skip happens inside the region, not to
                                 ;; suspend anything.
                                 ;;
                                 ;; Interrupt state: injection ON -- depth 2,
                                 ;; so 'skipped; injection OFF -- (void).
                                 (inject-barrier! 'z14-empty-open)
                                 (conn-tls-set-gated! t #f)
                                 (conn-tls-set-gate-opened-ms! t (now-ms))
                                 (bump-gate-open!)
                                 (note-gate-open-ms! (now-ms)))
                               held))))
                (cond
                  ((pair? batch)
                   (let ((o (conn-owner c)))
                     (for-each (lambda (bv) (deliver o (vector 'tcp-data bv)))
                               batch))
                   (loop))
                  (else
                    ;; the recorded close_notify, now that order is safe.
                    ;; Outside the region as before: tls-deliver-eof-once!
                    ;; sends after its own inner region, and eof-sent? is
                    ;; atomic, so all three eof orderings stay correct.
                    (when (conn-tls-eof? t)
                      (tls-deliver-eof-once! c t))))))))))

  ;; Best-effort nudge. A lost ping costs latency only: the watcher has a
  ;; timed receive and re-reads the waiter list on every wake (Z8).
  (define (tls-gate-ping! t)
    ;; SUPPRESSION IS A TEST CONTROL, NOT A FAILURE MODE. Armed, it drops
    ;; the ping so a waiter can only be woken by a release -- which is how the
    ;; row that claims "a lost ping costs latency only" is made to prove it
    ;; rather than assert it.
    (unless (inject-override! 'tls-ping-suppress #f)
      (let ((w (conn-tls-watcher t)))
        (when w (deliver w (vector 'tls-gate-ping))))))

  ;; Release the gate and hand it to the next waiter, in ONE step on the shared
  ;; state; the reply to the woken writer is sent OUTSIDE it.
  ;;
  ;; WHOEVER TAKES THE ENTRY IS THE ONE WHO ANSWERS IT. The list is read and
  ;; rewritten inside the region, so a retirement racing this either finds the
  ;; entry still on the list (and refuses it) or does not see it at all (and
  ;; this call answers it). There is no test of whether the watcher is alive
  ;; and no way for a waiter to get two answers.
  (define (tls-gate-release! c t)
    ;; the holder is stepping down, so its monitor should go with it --
    ;; otherwise a writer that finishes and later exits produces a DOWN for a
    ;; connection it no longer has anything to do with.
    (let ((w (conn-tls-watcher t)))
      (when w (deliver w (vector 'tls-gate-released))))
    (let ((next (with-interrupts-disabled
                  (conn-tls-set-holder! t #f)
                  (conn-tls-set-holder-monitor! t #f)
                  (conn-tls-set-aggregate! t #f)
                  (let ((ws (conn-tls-waiters t)))
                    (cond
                      ((null? ws) #f)
                      ((conn-tls-closed? t) #f)
                      (else
                        (conn-tls-set-waiters! t (cdr ws))
                        (conn-tls-set-holder! t (car (car ws)))
                        (conn-tls-set-aggregate! t (cdr (car ws)))
                        (car ws)))))))
      (cond
        (next
          (deliver (car next) (vector 'tls-gate-held))
          ;; the new holder is monitored by the watcher, not by us (Z5)
          (tls-gate-announce-holder! t (car next)))
        (else
          ;; A CLEAN CLOSE THAT WAS WAITING FOR THIS RELEASE FINISHES HERE,
          ;; and until now nothing did it. tls-conn-close-clean! returns when a
          ;; holder is mid-aggregate, and its comment said "its release finds
          ;; the closing flag and finishes the shutdown" -- a mechanism that
          ;; did not exist, so the connection was left open with no
          ;; close_notify, no retirement and no uv_close. The comment was
          ;; describing an intention; this is the code.
          (when (and (conn-tls c) (conn-tls-closing? t))
            (tls-conn-finish-shutdown! c t))))))

  (define (tls-conn-write-chunks! c t agg segs on-done)
    (let loop ((ss segs) (off 0))
      (cond
        ((null? ss)
         ;; sealing is the whole-aggregate act; the callback fires outside it
         (with-interrupts-disabled (tls-agg-set-sealed! agg #t))
         (tls-gate-release! c t)
         (tls-agg-maybe-finish! agg)
         #t)
        (else
          (let* ((bv (car ss))
                 (n (bytevector-length bv))
                 (take (fxmin tls-chunk-size (fx- n off))))
            ;; ONE OUTER REGION PER CHUNK UNIT (Y5), and its FIRST act is
            ;; the field test (Delta 12). A conn retired between two chunks
            ;; must not start another one: the session it would write into has
            ;; been freed. The field is the same one retirement detaches, so
            ;; this needs no second agreement with the retirement path.
            (let ((r (with-interrupts-disabled
                       (inject-fault! 'tls-chunk-step)
                       (if (not (conn-tls c))
                           'retired
                           (let ((piece (if (and (fx= off 0) (fx= take n))
                                            bv
                                            (let ((b (make-bytevector take)))
                                              (bytevector-copy! bv off b 0 take)
                                              b))))
                             (bump-ssl-op!)
                             ;; no override here: forcing the CLASSIFICATION
                             ;; of SSL_write is done where the classification
                             ;; happens, inside (igropyr tls-core). Replacing
                             ;; the ciphertext at this level would leave the
                             ;; success branch already taken.
                             (let ((out (tls-session-encrypt!
                                          (conn-tls-session t) piece)))
                               (tls-agg-set-pending!
                                 agg (fx+ (tls-agg-pending agg) 1))
                               ;; THE BLOCK IS REGISTERED BEFORE IT IS
                               ;; SUBMITTED. uv_try_write can complete INLINE,
                               ;; so a completion can run before this call
                               ;; returns -- registering afterwards would
                               ;; record the block after its own completion
                               ;; had already been recorded, and the ordering
                               ;; the cell reads would be a lie.
                               (let ((sz (bytevector-length out)))
                                 (note-raw-block! t agg sz)
                                 (inject-fault! 'tls-between-chunks)
                                 ;; CHARGED ONLY ONCE THE SUBMISSION IS
                                 ;; ACCEPTED. Charging before this point left
                                 ;; the money unrecoverable when anything
                                 ;; between the two raised: the completion
                                 ;; that refunds is installed BY this call, so
                                 ;; a raise before it means no completion will
                                 ;; ever exist to give it back.
                                 (tls-conn-charge! t sz)
                                 ;; THE SIZE TRAVELS IN THE CLOSURE. A side
                                 ;; table keyed by (conn . aggregate) would
                                 ;; answer for the LAST block of an aggregate,
                                 ;; refunding the wrong amount whenever an
                                 ;; application write became more than one
                                 ;; record -- which is the normal case.
                                 (tcp-writev-raw!
                                   c (list out)
                                   (lambda (status)
                                     (tls-raw-done! c t agg sz status))))
                               'wrote))))))
              (cond
                ((eq? r 'retired)
                 ;; the stored reason is the whole answer; the aggregate is
                 ;; terminal and the gate is already closed by the retirement
                 (let ((cb (tls-agg-terminalise! agg 'tls-conn-closed)))
                   (when cb (cb -1)))
                 #f)
                ;; INJECTION POINTS 'agg-chunk-boundary and
                ;; 'agg-chunk-boundary-2 -- OWNING REGION: NONE. The per-chunk
                ;; region closed when r was bound, which is what makes Y5's
                ;; "preemption between chunk units is preserved" true; these
                ;; points stand exactly in that gap.
                ;;
                ;; PARK. A victim stops between two chunks of ONE aggregate
                ;; while holding the gate -- the state that distinguishes
                ;; "aggregates are serialised" from "steps are serialised".
                ;; Two points rather than one so a cell can hold two
                ;; successive boundaries; unarmed, each is a hit-free no-op.
                ;;
                ;; Interrupt state: injection ON -- depth 1, parks;
                ;; injection OFF -- (void).
                ((fx< (fx+ off take) n)
                 (inject-barrier! 'agg-chunk-boundary)
                 (inject-barrier! 'agg-chunk-boundary-2)
                 (loop ss (fx+ off take)))
                (else
                 ;; GUARDED so it never fires after the LAST chunk. Without
                 ;; (pair? (cdr ss)) the final transition parks a victim whose
                 ;; next act is to seal and release -- there is no following
                 ;; chunk to race with, so the park would be a boundary that
                 ;; is not a boundary, and the cell would be measuring the
                 ;; teardown instead.
                 (when (pair? (cdr ss))
                   (inject-barrier! 'agg-chunk-boundary)
                   (inject-barrier! 'agg-chunk-boundary-2))
                 (loop (cdr ss) 0)))))))))

  ;; Accounting transfers (X4): ciphertext produced is bio-held until it is
  ;; submitted, then raw-queued until its completion runs.
  (define (tls-conn-charge! t n)
    (conn-tls-set-raw-queued! t (fx+ (conn-tls-raw-queued t) n))
    (conn-tls-set-charged! t (fx+ (conn-tls-charged t) n)))

  ;; THE REFUND HAPPENS ON EVERY OUTCOME (X4), and it is asserted BEFORE
  ;; teardown clears the counters: charged-total and refunded-total are
  ;; monotonic, so a skipped refund shows up as an inequality that teardown
  ;; cannot hide.
  (define (tls-raw-done! c t agg sz status)
    (with-interrupts-disabled
      (tls-agg-set-pending! agg (fx- (tls-agg-pending agg) 1))
      (when (and (fx< status 0) (not (tls-agg-error agg)))
        (tls-agg-set-error! agg status)))
    (tls-conn-refund! t sz)
    ;; THE COMPLETION IS APPENDED, so the snapshot carries the ORDER blocks
    ;; finished in rather than leaving a reader to infer it from registration
    ;; order. Inline completions make those two orders differ, which is the
    ;; whole reason the registration happens before the submit.
    (note-raw-block-done! t agg sz status)
    (inject-fault! 'tls-after-refund)
    ;; THE SHUTDOWN BOUND IS AN IDLE BOUND, NOT A BUDGET (E9). A peer that
    ;; keeps reading pushes the deadline out with every completion and is
    ;; never truncated; a peer that stops reading is cut tls-shutdown-ms
    ;; after the LAST progress. A total deadline would cut a healthy slow
    ;; reader mid-stream, which is the failure this whole path exists to
    ;; stop.
    ;;
    ;; ONLY SUCCESSFUL COMPLETIONS EXTEND IT. A negative status means the
    ;; write did not reach the peer, so treating it as progress would let a
    ;; connection that is failing every write hold the handle open forever.
    ;;
    ;; The attachment is re-read here rather than trusted: retirement may
    ;; have detached t while this completion was in flight, and rearming a
    ;; detached record's timer is how the freed-handle bug in
    ;; tls-timer-rearm! used to be reached.
    (when (and (eq? (conn-tls c) t)
               (conn-tls-shutdown? t)
               (conn-tls-timer t)
               (fx>= status 0))
      (unless (tls-timer-rearm! t tls-shutdown-ms)
        (conn-tls-retire! c 'clean-close 'tls-shutdown-timer-failed)))
    (tls-agg-maybe-finish! agg))

  (define (tls-conn-refund! t n)
    (when t
      (with-interrupts-disabled
        (conn-tls-set-raw-queued! t (fx- (conn-tls-raw-queued t) n))
        (conn-tls-set-refunded! t (fx+ (conn-tls-refunded t) n)))))

  ;; THE CODEC-AWARE ENTRY, and the only one an application should call.
  ;; A plaintext connection goes straight to the raw sink, which is exactly
  ;; what it did before this split -- one field test more. A TLS connection
  ;; has its plaintext encrypted first, under the conn's write gate, and the
  ;; ciphertext reaches the socket through the raw sink above.
  ;;
  ;; THE TEST IS THE FIELD, not a flag someone sets alongside it: the same
  ;; field retirement detaches. A conn retired mid-write therefore stops being
  ;; a TLS conn for every subsequent write, which is the behaviour the chunk
  ;; loop relies on (Delta 12).
  (define (tcp-writev! c segs on-done)
    (let ((t (conn-tls c)))
      (if t
          (tls-conn-writev! c t segs on-done)
          (tcp-writev-raw! c segs on-done))))

  (define (tcp-write! c bv on-done)
    (tcp-writev! c (list bv) on-done))

  ;; Write len bytes straight from foreign memory (e.g. a file stream's
  ;; chunk buffer): the fast path is buffer -> kernel with no copy at
  ;; all; a partial write or EAGAIN copies only the unwritten remainder
  ;; into the queued write block. The source buffer is free for reuse
  ;; as soon as this returns. on-done as in tcp-writev!.
  (define (tcp-write-foreign! c ptr len on-done)
    (if (not (eq? (conn-state c) 'open))
        (begin (when on-done (on-done -1)) #f)
        (uv-scratch-lease (lambda (write-scratch write-scratch-size scratch-buf)
          ;; state OR seal, same exit shape as a closed connection (E9)
          (if (or (not (eq? (conn-state c) 'open)) (conn-raw-sealed? c))
              (begin (when on-done (on-done -1)) #f)
              (begin
                (foreign-set! 'void* scratch-buf 0 ptr)
                (foreign-set! 'unsigned-64 scratch-buf 8 len)
                ;; INJECTION POINT 'try-write-foreign-eagain -- OWNING
                ;; GUARD: none here. The guard further down covers the
                ;; partial branch's enqueue-write!, not this call, and a
                ;; 0 return is a value that the cond below reads: it
                ;; selects the queue-everything branch, which is the one
                ;; the cell follows to delivery.
                (let ((n (inject-return! 'try-write-foreign-eagain
                           (uv-try-write (conn-handle c) scratch-buf 1))))
                  (cond
                    ((= n len)                    ; fully written now
                     (when on-done (on-done 0)) #t)
                    ((and (> n 0) (< n len))      ; partial: queue the rest
                     ;; same as tcp-writev!'s partial branch: a prefix is
                     ;; already on the wire, so a remainder that cannot be
                     ;; queued leaves a truncated message behind it
                     (let ((queued
                             (guard (e (#t (tcp-close! c) (raise e)))
                               (enqueue-write! c (- len n)
                                 (lambda (dest)
                                   (memcpy-cc dest (+ ptr n) (- len n)))
                                 on-done))))
                       (unless queued (tcp-close! c))
                       queued))
                    (else                         ; EAGAIN/0: queue all
                     (enqueue-write! c len
                       (lambda (dest) (memcpy-cc dest ptr len))
                       on-done))))))))))

  ;; Idempotent close; memory is freed only in close_cb, so there is no
  ;; double-close and no fd leak.
  ;; Attach a cleanup thunk to a connection: it runs exactly once, when
  ;; libuv reports the handle closed -- WHOEVER closed it. That is the
  ;; point of hanging it off the conn instead of a code path: an owner
  ;; killed mid-request closes the conn via uv-owner-died!, and a killed
  ;; process runs neither winders nor guards, so any cleanup owned by
  ;; control flow is skipped. Cleanup owned by the resource is not.
  ;; Registering on an already-closed conn runs the thunk immediately.
  ;; The thunk runs in libuv callback context: it must not yield, park,
  ;; or raise (a raise here would unwind into C; it is swallowed).
  (define (conn-on-close! c thunk)
    ;; A TAGGED CONN REFUSES THIS TOO. There is ONE cleanup slot, and on a
    ;; pipe the library already owns it: the closure clears the proc's field
    ;; for that stream and retires the row when the proc is fully closed.
    ;; Overwriting it would not fail loudly -- the proc would simply never
    ;; reach `closed` and its row would sit in the table for the life of the
    ;; VM.
    (when (conn-tag c)
      (assertion-violation 'conn-on-close!
        "a child process pipe owns its cleanup hook" (conn-tag c)))
    ;; The state test and the store must be ONE operation. Between them the
    ;; close completion can run, and then the thunk is filed on a conn that
    ;; will never close again -- so it never runs at all, which for the TLS
    ;; user of this hook means a leaked SSL session, exactly what it exists
    ;; to prevent. Running it here instead is correct: the resource is gone,
    ;; so the cleanup is due now.
    (let ((run-now?
            (with-interrupts-disabled
              (if (eq? (conn-state c) 'closed)
                  #t
                  (begin (conn-set-cleanup! c thunk) #f)))))
      (when run-now? (thunk))))

  ;; THE TEST AND THE CLOSE ARE ONE STEP, and that is what makes this
  ;; idempotent rather than merely usually-idempotent. The state test and
  ;; uv-close are separated by a safe point, so two closers -- and this
  ;; connection has them, since a writer over its outbound ceiling closes
  ;; from its own process while the reader's error path closes from
  ;; another -- can both read 'open, both set 'closing, and both call
  ;; uv_close on the same handle. libuv answers a second uv_close on a
  ;; closing handle with an assert, which is not an exception this process
  ;; can catch. Disabling interrupts across the pair is the precondition
  ;; for the guarantee this procedure advertises, NOT an optimisation, and
  ;; it costs nothing: uv_close only files the handle for its close
  ;; callback and does not block.
  ;; A TLS CONNECTION CLOSES CLEANLY, A PLAINTEXT ONE CLOSES. The dispatch
  ;; is on the same field retirement detaches, so a conn already retired takes
  ;; the plain path -- which is what retirement itself relies on when it calls
  ;; this after detaching.
  ;; A CLOSE BEFORE ESTABLISHMENT IS A HARD RETIRE, not a clean one. The clean
  ;; path exists to flush queued application ciphertext and send a close_notify;
  ;; before the handshake completes there is neither, and the drain machinery
  ;; would instead hold the connection open under a bound while nobody is
  ;; waiting for anything. On a dial it matters twice: the owner's own teardown
  ;; reaches here, and a clean close would leave the attempt unconcluded for as
  ;; long as that bound lasts.
  (define (tcp-close! c)
    (let ((t (conn-tls c)))
      (cond
        ((not t) (tcp-close-raw! c))
        ((not (conn-tls-established? t))
         (conn-tls-retire! c 'closed-before-established 'tls-closed-early))
        (else (tls-conn-close-clean! c)))))

  ;; uv_close CANCELS EVERY QUEUED WRITE ON THE HANDLE, so reaching this from
  ;; a clean close before the drain finished is how E9's truncation happened.
  ;; A clean close now arrives here only from the alert's own completion or
  ;; from the shutdown timer -- both of which mean there is nothing left worth
  ;; waiting for. The hard paths (read error, peer reset, handshake failure,
  ;; explicit abort, holder death) still come straight here, deliberately:
  ;; they are the mechanism the bound is made of.
  (define (tcp-close-raw! c)
    (with-interrupts-disabled
      (when (and (eq? (conn-state c) 'open)
                 (= 0 (uv-is-closing (conn-handle c))))
        (conn-set-state! c 'closing)
        (uv-close (conn-handle c) on-close-entry))))

  ;; CLEAN CLOSE REFUSES THE ALREADY-PARKED (Z9). Entering the closing
  ;; state refuses EVERY waiter already on the list, in the same step that
  ;; sets the flag -- refusing only new acquirers would leave whoever was
  ;; parked at that instant waiting for a gate that will never be granted.
  ;; Only the current holder's aggregate is allowed to seal.
  ;;
  ;; The alert then goes out under the shutdown deadline, on the SAME timer
  ;; the handshake used (Y3): re-armed, not re-allocated.
  ;; THE FIRST CLOSE OWNS THE DRAIN (E9). A second closer -- typically the
  ;; owner exiting after the application already asked for the close -- must
  ;; not refuse waiters again or re-enter the shutdown: the alert is already
  ;; queued under its bound and the connection is going away on its own.
  (define (tls-conn-close-clean! c)
    (let* ((t (conn-tls c))
           (parked (and t (with-interrupts-disabled
                            (conn-tls-set-closing! t #t)
                            (let ((ws (conn-tls-waiters t)))
                              (conn-tls-set-waiters! t '())
                              ws)))))
      (when (and t (not (conn-tls-shutdown? t)))
        (for-each (lambda (w)
                    (deliver (car w) (vector 'tcp-write-refused 'tls-closing)))
                  (or parked '()))
        (if (conn-tls-holder t)
            ;; a holder is mid-aggregate: it seals, and its release finds the
            ;; closing flag and finishes the shutdown. Nothing is torn here --
            ;; a half-emitted application frame on the wire is worse than a
            ;; late close.
            (void)
            (tls-conn-finish-shutdown! c t)))))

  ;; A CLEAN CLOSE DRAINS BEFORE THE HANDLE CLOSES (E9). This used to submit
  ;; the alert and retire in the next expression -- and retirement calls
  ;; uv_close, which CANCELS every queued write request on the handle. A
  ;; connection that still had megabytes of application ciphertext in
  ;; libuv's request list therefore lost all of it, along with the alert
  ;; itself: the peer saw a truncated stream ending mid-record and no
  ;; close_notify. Nothing reported it, because cancelled requests still run
  ;; their completions and still refund, so the accounting balanced exactly
  ;; as it does on a successful send.
  ;;
  ;; The connection is now retired by whichever happens first: the alert's
  ;; own completion (everything queued ahead of it went out first -- libuv's
  ;; request list is FIFO), or the idle bound expiring, which means
  ;; tls-shutdown-ms passed with no progress at all. Neither is this
  ;; procedure's own return.
  (define (tls-conn-finish-shutdown! c t)
    ;; ONCE-ONLY, AND BEFORE ANYTHING CAN FAIL. Two closers can arrive
    ;; together -- an owner exit and an explicit close -- and the second must
    ;; not run SSL_shutdown on a session the first is already draining.
    (unless (with-interrupts-disabled
              (or (conn-tls-finishing? t)
                  (begin (conn-tls-set-finishing! t #t) #f)))
      ;; THE GUARD COVERS EVERY WAY OUT THAT IS NOT A SUBMITTED ALERT.
      ;; SSL_shutdown and the drain can raise, and so can foreign-alloc. The
      ;; caller is a release path or a close request: nobody above wants the
      ;; condition, so it is recorded as a retirement reason and swallowed.
      (let ((block #f))
        (guard (e (#t (when block
                        (inject-barrier! 'write-block-released-closenotify-guard)
                        (free-write-block! block))
                      (conn-tls-retire! c 'clean-close 'tls-shutdown-raised)))
          (bump-ssl-op!)
          (tls-session-shutdown! (conn-tls-session t))
          (inject-fault! 'tls-closenotify-delay)
          (let ((out (tls-session-drain! (conn-tls-session t))))
            (if (not out)
                ;; nothing to send: the session had already emitted its alert,
                ;; or is too dead to make one. No write to wait for, so this
                ;; is the whole close.
                (conn-tls-retire! c 'clean-close 'tls-closed)
                (let* ((len (bytevector-length out))
                       (blk (alloc-write-block! (+ write-req-size buf-t-size len)))
                       (buf-ptr (+ blk write-req-size))
                       (data-ptr (+ buf-ptr buf-t-size)))
                  (set! block blk)          ; the guard owns it until published
                  ;; INJECTION POINT 'tls-closenotify-owned-fault -- OWNING GUARD:
                  ;; the one above, while it still owns the block. Between the fill
                  ;; and the ownership transfer is the only window in which that
                  ;; guard has anything to release.
                  (inject-fault! 'tls-closenotify-owned-fault)
                  (memcpy-to-c data-ptr out len)
                  (foreign-set! 'void* buf-ptr 0 data-ptr)
                  (foreign-set! 'unsigned-64 buf-ptr 8 len)
                  ;; NEVER WAIT WITHOUT A BOUND. The alert is about to be
                  ;; queued behind an unknown amount of application data; if
                  ;; no timer can be armed, nothing would ever end the wait,
                  ;; so the close happens now instead.
                  ;; NO POINT OF ITS OWN HERE, DELIBERATELY. The seam that
                  ;; drives this branch is 'tls-timer-rearm-fail, and it
                  ;; already sits inside tls-timer-rearm! on the uv_timer_start
                  ;; it wraps: armed with a negative code that call answers -1,
                  ;; tls-timer-rearm! answers #f, and this test takes the
                  ;; failure arm. A second wrapper around the BOOLEAN here
                  ;; would share that one name across two different value
                  ;; domains -- the same arming would be read as an errno in
                  ;; one place and as a flag in the other, and whichever site
                  ;; consumed the occurrence first would decide which.
                  (if (not (tls-timer-rearm! t tls-shutdown-ms))
                      (begin
                        (inject-barrier! 'write-block-released-timer-fail)
                        (free-write-block! blk)
                        (set! block #f)
                        (conn-tls-retire! c 'clean-close 'tls-shutdown-timer-failed))
                      (begin
                        ;; published from here on: the sealing entry owns the
                        ;; block on every path, so the guard must not.
                        (set! block #f)
                        (enqueue-write-sealing! c t blk buf-ptr
                          (lambda (status)
                            (if (fx>= status 0)
                                (conn-tls-retire! c 'clean-close 'tls-closed)
                                (conn-tls-retire! c 'clean-close
                                  (cons 'tls-close-notify-failed status)))))
                        ;; INJECTION POINT 'tls-after-alert -- OWNING REGION:
                        ;; NONE. The sealing entry's region closed when it
                        ;; returned, so a victim parks here holding nothing,
                        ;; with the alert queued and not yet completed. That
                        ;; window is the whole subject of this procedure and
                        ;; is otherwise far too short to act in.
                        ;;
                        ;; Interrupt state: injection ON -- depth 1, parks;
                        ;; injection OFF -- (void).
                        (inject-barrier! 'tls-after-alert))))))))))

  ;; ---- child processes: the public face ----------------------------------

  ;; OPTIONS ARRIVE IN EITHER SHAPE, and that is Postel rather than sugar.
  ;; (proc-spawn! f a '(cwd . "/tmp") '(stdout . ignore)) and
  ;; (proc-spawn! f a '((cwd . "/tmp") (stdout . ignore))) both name the same
  ;; alist, and a caller holding one already-built list should not have to
  ;; apply. The two are told apart by the car of the single element: an option
  ;; is (symbol . value), a wrapped alist is a list whose first element is
  ;; itself a pair.
  (define (proc-opt-alist opts)
    (cond
      ((null? opts) '())
      ((and (null? (cdr opts))
            (let ((x (car opts)))
              (or (null? x) (and (pair? x) (pair? (car x))))))
       (car opts))
      (else opts)))

  (define (proc-opt o name default)
    (let ((e (assq name o)))
      (if e (cdr e) default)))

  (define (proc-stdio-mode o name)
    (let ((m (proc-opt o name 'pipe)))
      (case m
        ((pipe inherit ignore) m)
        (else
          (assertion-violation 'proc-spawn!
            "stdio mode must be pipe, inherit or ignore" name m)))))

  (define (proc-stream-name k)
    (case k ((0) 'stdin) ((1) 'stdout) (else 'stderr)))

  (define (proc-set-stream! p stream c)
    (case stream
      ((stdin) (proc-set-stdin! p c))
      ((stdout) (proc-set-stdout! p c))
      ((stderr) (proc-set-stderr! p c))
      (else (void))))

  (define process-handle-size (uv-handle-size UV-PROCESS))
  (define pipe-handle-size (uv-handle-size UV-NAMED-PIPE))

  ;; Start a child process without blocking the scheduler. Answers the proc,
  ;; or (failed . reason) where reason is a symbol for a refusal this library
  ;; made -- proc-limit, owner-dead, layout -- and a libuv error string for
  ;; one the operating system made.
  ;;
  ;; argv INCLUDES argv[0]; opts is the alist above: cwd, env (a list of
  ;; "K=V"; absent means inherit), stdin/stdout/stderr each pipe | inherit |
  ;; ignore, owner (a pid, default the caller), kill-on-owner-death (default
  ;; #t, SIGTERM).
  ;;
  ;; ONE INTERRUPT-DISABLED REGION RUNS FROM ADMISSION TO PUBLICATION, and
  ;; what it buys is that no callback can observe a half-built proc: the exit,
  ;; read and close callbacks run only inside uv-poll!, which runs only in the
  ;; event-loop process, which cannot be scheduled while this one holds the
  ;; region. Nothing inside yields or polls, and the one hook it calls --
  ;; uv-alive?, for the admission re-check -- is a predicate that does
  ;; neither.
  ;;
  ;; THE ONE SYNCHRONOUS WINDOW IN THIS FACILITY IS uv_spawn ITSELF. libuv's
  ;; unix spawn path reads the child's exec-error pipe with no timeout, so
  ;; process CREATION is "milliseconds, typically" rather than bounded. That
  ;; is a property of this one call and of nothing else here: no other
  ;; operation in this facility waits on the child at all.
  (define (proc-spawn! file argv . opts)
    (let* ((o (proc-opt-alist opts))
           (cwd (proc-opt o 'cwd #f))
           (env (proc-opt o 'env #f))
           (owner (proc-opt o 'owner (and uv-self (uv-self))))
           (kill? (proc-opt o 'kill-on-owner-death #t))
           (modes (vector (proc-stdio-mode o 'stdin)
                          (proc-stdio-mode o 'stdout)
                          (proc-stdio-mode o 'stderr))))
      ;; VALIDATED OUT HERE, where a raise costs nothing. Inside the region
      ;; the same raise would have to be unwound past allocated handles.
      (unless (string? file)
        (assertion-violation 'proc-spawn! "file must be a string" file))
      (unless (and (list? argv) (for-all string? argv))
        (assertion-violation 'proc-spawn! "argv must be a list of strings" argv))
      ;; AN EMPTY argv IS REFUSED HERE rather than marshalled. It passes the
      ;; test above, and what it produces is args[0] == NULL, which execvp is
      ;; not defined for: the failure would happen in the child, after the
      ;; fork, as whatever that platform does with a null program name. argv
      ;; carries argv[0] by this facility's contract, so its absence is a
      ;; caller error and says so at the only point that can still name the
      ;; caller.
      (when (null? argv)
        (assertion-violation 'proc-spawn! "argv must include argv[0]" argv))
      (when (and cwd (not (string? cwd)))
        (assertion-violation 'proc-spawn! "cwd must be a string" cwd))
      (when (and env (not (and (list? env) (for-all string? env))))
        (assertion-violation 'proc-spawn! "env must be a list of strings" env))
      ;; STEP 0, ONCE PER VM: the handle-queue layout self-check. It licenses
      ;; the only raw pointer write in this facility, and its failure mode is
      ;; memory corruption rather than an exception, so a facility that cannot
      ;; verify the layout refuses every spawn instead of guessing.
      (if (not (check-handle-layout!))
          (cons 'failed 'layout)
          (begin
            ;; TEST SEAM 'proc-spawn-admission -- OWNING REGION: NONE. It sits
            ;; between the caller's decision to spawn and the region's
            ;; admission tests, which is the window a cell needs in order to
            ;; kill the named owner and prove the re-check below is the one
            ;; that answers. Parks.
            (inject-barrier! 'proc-spawn-admission)
            (proc-spawn-region file argv cwd env owner kill? modes)))))

  (define (proc-spawn-region file argv cwd env owner kill? modes)
    (with-interrupts-disabled
      (cond
        ;; ADMISSION COUNTS ROWS, and a row lives until the proc is `closed`,
        ;; so the cap counts procs that still hold descriptors -- which is the
        ;; resource it exists to bound.
        ((fx>= (proc-count) max-procs) (cons 'failed 'proc-limit))
        ;; RE-CHECKED HERE, INSIDE THE REGION. A check before it leaves a
        ;; window in which the owner dies between the test and publication,
        ;; and what is published is then a proc nothing will ever reclaim.
        ((and owner uv-alive? (not (uv-alive? owner))) (cons 'failed 'owner-dead))
        (else
          ;; blocks: marshalled memory, consumed by uv_spawn.
          ;; ph: the process handle block.
          ;; spawned?: uv_spawn has returned, so libuv has seen ph.
          ;; released?: a release path has already run.
          (let ((blocks '())
                (ph #f)
                (spawned? #f)
                (released? #f)
                (child-pid #f)
                (pipe-h (vector #f #f #f))
                (pipe-inited? (vector #f #f #f))
                (pipe-conn (vector #f #f #f))
                (pipe-row? (vector #f #f #f))
                (pipe-idx? (vector #f #f #f))
                (p #f)
                (row? #f)
                (idx? #f))
            ;; EVERY RESOURCE CARRIES ITS OWN FLAG, set the instant it exists,
            ;; and the release paths act on the flags rather than on a guess
            ;; about how far the sequence got. That is what keeps a failure in
            ;; the middle from being either a leak or a double free.
            ;;
            ;; ONE RESIDUAL, NAMED RATHER THAN PAPERED OVER: the cons below
            ;; runs after its foreign-alloc, so a raise between the two loses
            ;; that one block. Closing it would need the allocation and the
            ;; record to be one operation, which foreign-alloc does not offer;
            ;; it is the same gap listener-backlog-effective states for its
            ;; three buffers, and it is bounded by one allocation.
            (define (alloc! n)
              (let ((b (foreign-alloc n)))
                (set! blocks (cons b blocks))
                b))
            (define (free-blocks!)
              (for-each foreign-free blocks)
              (set! blocks '()))
            (define (cstr s)
              (let* ((bv (string->utf8 s))
                     (n (bytevector-length bv))
                     (b (alloc! (+ n 1))))
                (memcpy-to-c b bv n)
                (foreign-set! 'unsigned-8 b n 0)
                b))
            ;; a NULL-terminated char**, as execvp wants it
            (define (cstr-array strs)
              (let ((a (alloc! (* 8 (+ (length strs) 1)))))
                (let loop ((xs strs) (i 0))
                  (if (null? xs)
                      (foreign-set! 'void* a (* 8 i) 0)
                      (begin
                        (foreign-set! 'void* a (* 8 i) (cstr (car xs)))
                        (loop (cdr xs) (+ i 1)))))
                a))
            ;; initialised -> uv_close, and the handle is freed by its close
            ;; callback; allocated-only -> foreign-free, because libuv has
            ;; never seen it and a close would be a close of nothing.
            (define (close-pipe-handles!)
              (let loop ((k 0))
                (when (fx< k 3)
                  (let ((h (vector-ref pipe-h k)))
                    (when h
                      (if (vector-ref pipe-inited? k)
                          (uv-close h on-close-entry)
                          (foreign-free h))
                      (vector-set! pipe-h k #f)
                      (vector-set! pipe-inited? k #f)))
                  (loop (fx+ k 1)))))
            (define (unpublish-pipes!)
              (let loop ((k 0))
                (when (fx< k 3)
                  (let ((c (vector-ref pipe-conn k)))
                    (when c
                      (when (vector-ref pipe-row? k)
                        (hashtable-delete! conn-table (conn-handle c))
                        (note-pipe-conn! -1)
                        (vector-set! pipe-row? k #f))
                      (when (vector-ref pipe-idx? k)
                        ;; INJECTION POINT 'proc-rollback-unindex (fault) --
                        ;; OWNING GUARD: the one on the next line. Each step of
                        ;; the rollback is guarded separately so that a raise
                        ;; in this allocating one cannot stop the steps after
                        ;; it; the cost is one stale index entry, which the
                        ;; owner-death traversal re-checks and skips.
                        (guard (e2 (#t (note-swallowed! 'proc-rollback-unindex e2)))
                          (inject-fault! 'proc-rollback-unindex)
                          (unindex-owner! owner 'conn (conn-handle c)))
                        (vector-set! pipe-idx? k #f))))
                  (loop (fx+ k 1)))))
            ;; The owner entry for a proc row that exists without one. Keeping
            ;; the ROW is what matters: an orphan with a row is in admission
            ;; accounting and its exit callback finds it. Only the owner-death
            ;; traversal cannot reach it, and an orphan has no pipes and a
            ;; SIGKILL already sent, so nothing depends on that reach.
            (define (recover-owner-entry!)
              (unless idx?
                ;; COUNTED POINT 'proc-orphan-unindexed -- unarmed: silent;
                ;; armed it records a skip, the caller's region being open.
                ;; INJECTION POINT 'proc-recover-index-fail (fault) is what
                ;; drives it.
                (guard (e2 (#t (inject-barrier! 'proc-orphan-unindexed)))
                  (inject-fault! 'proc-recover-index-fail)
                  (index-owner! owner 'proc ph)
                  (set! idx? #t))))
            (define (release-pre-spawn!)
              (set! released? #t)
              (free-blocks!)
              ;; NEVER INITIALISED: libuv has not seen this block, so it is
              ;; freed directly rather than closed.
              ;;
              ;; EVERY RELEASE FIRST, INSTRUMENTATION LAST. The log allocates
              ;; in an injected build, and released? is already set, so a
              ;; raise in the middle of this procedure is not retried by the
              ;; guard -- it would strand this block AND every pipe handle
              ;; below it. COUNTED POINT 'proc-handle-freed: the third of the
              ;; three sites that release a process handle block.
              (let ((freed ph))
                (when ph (foreign-free ph) (set! ph #f))
                (close-pipe-handles!)
                (when freed
                  (inject-barrier! 'proc-handle-freed)
                  (note-proc-handle-freed! freed))))
            (define (release-spawned-inactive!)
              (set! released? #t)
              (free-blocks!)
              (repair-spawn-queue! ph)
              (close-pipe-handles!)
              (uv-close ph on-process-close-entry)
              (set! ph #f))
            ;; THE CHILD IS RUNNING, so the order is fixed: kill first (no
            ;; allocation, cannot raise), then take the pipes apart, then make
            ;; sure the child is still accounted for by a row. An active
            ;; process handle is never uv_closed here: closing it would
            ;; deregister the process and leave the child unreaped.
            (define (rollback-active!)
              (set! released? #t)
              (uv-process-kill ph 9)
              (unpublish-pipes!)
              (when p
                (proc-set-stdin! p #f)
                (proc-set-stdout! p #f)
                (proc-set-stderr! p #f))
              (close-pipe-handles!)
              (if row?
                  ;; the row is there: rewriting it is pointer writes and
                  ;; cannot fail. The owner entry may still be missing --
                  ;; publishing a row and indexing its owner are two
                  ;; allocating steps -- and recovering it is the one step
                  ;; here that can raise, which is why it is guarded.
                  (begin (proc-set-child! p 'orphan) (recover-owner-entry!))
                  ;; no row: publish one now from the record's current flags.
                  ;; A raise at the row insertion leaves the no-row state, and
                  ;; the exit callback's no-row path closes and frees the
                  ;; handle -- the child already has its SIGKILL.
                  (begin
                    (guard (e2 (#t (void)))
                      (unless p
                        (set! p (make-proc ph owner #f #f #f child-pid #f
                                           'orphan #t 0 kill?)))
                      (proc-set-child! p 'orphan)
                      (hashtable-set! proc-table ph p)
                      (set! row? #t))
                    (when row? (recover-owner-entry!)))))
            (define (release-on-raise!)
              (unless released?
                (cond
                  ((not spawned?) (release-pre-spawn!))
                  ((not (= 0 (uv-is-active ph))) (rollback-active!))
                  (else (release-spawned-inactive!)))))
            (guard (e (#t (release-on-raise!) (raise e)))
              ;; (2) allocate and initialise, setting each flag as its
              ;; resource appears.
              (set! ph (foreign-alloc process-handle-size))
              (let ((pipe-err
                      (let loop ((k 0))
                        (cond
                          ((fx>= k 3) 0)
                          ((not (eq? (vector-ref modes k) 'pipe)) (loop (fx+ k 1)))
                          (else
                            (let ((h (foreign-alloc pipe-handle-size)))
                              (vector-set! pipe-h k h)
                              ;; INJECTION POINT 'proc-alloc-pipe-fail -- a
                              ;; RETURN, not an override: the call is skipped
                              ;; entirely, so the handle really is
                              ;; allocated-only and the direct foreign-free in
                              ;; close-pipe-handles! is the correct release.
                              ;; An override would leave a handle libuv had
                              ;; seen being freed as though it had not.
                              (let ((r (inject-return! 'proc-alloc-pipe-fail
                                         (uv-pipe-init (uv-loop-handle) h 0))))
                                (if (< r 0)
                                    r
                                    (begin
                                      (vector-set! pipe-inited? k #t)
                                      (loop (fx+ k 1)))))))))))
                (if (< pipe-err 0)
                    (begin (release-pre-spawn!)
                           (cons 'failed (uv-strerror pipe-err)))
                    (let ((ob (alloc! uv-process-options-size))
                          (sa (alloc! (* 3 uv-stdio-container-size))))
                      (foreign-set! 'void* ob uv-po-exit-cb-offset
                                    on-process-exit-entry)
                      (foreign-set! 'void* ob uv-po-file-offset (cstr file))
                      (foreign-set! 'void* ob uv-po-args-offset (cstr-array argv))
                      (foreign-set! 'void* ob uv-po-env-offset
                                    (if env (cstr-array env) 0))
                      (foreign-set! 'void* ob uv-po-cwd-offset
                                    (if cwd (cstr cwd) 0))
                      ;; EVERY FIELD IS WRITTEN, including the two that are
                      ;; zero: foreign-alloc does not clear, and uid/gid are
                      ;; read whenever the corresponding flag is set.
                      (foreign-set! 'unsigned-32 ob uv-po-flags-offset 0)
                      (foreign-set! 'int ob uv-po-stdio-count-offset 3)
                      (foreign-set! 'void* ob uv-po-stdio-offset sa)
                      (foreign-set! 'unsigned-32 ob uv-po-uid-offset 0)
                      (foreign-set! 'unsigned-32 ob uv-po-gid-offset 0)
                      ;; THE PIPE FLAGS DESCRIBE THE CHILD'S END. The child
                      ;; READS its stdin and WRITES its stdout and stderr, so
                      ;; the readable/writable pair is the other way round
                      ;; from this process's view of the same descriptors.
                      (let loop ((k 0))
                        (when (fx< k 3)
                          (let ((off (* k uv-stdio-container-size)))
                            (case (vector-ref modes k)
                              ((pipe)
                               (foreign-set! 'int sa (+ off uv-sc-flags-offset)
                                 (if (fx= k 0)
                                     (fxlogor UV-CREATE-PIPE UV-READABLE-PIPE)
                                     (fxlogor UV-CREATE-PIPE UV-WRITABLE-PIPE)))
                               (foreign-set! 'void* sa (+ off uv-sc-data-offset)
                                             (vector-ref pipe-h k)))
                              ((inherit)
                               (foreign-set! 'int sa (+ off uv-sc-flags-offset)
                                             UV-INHERIT-FD)
                               (foreign-set! 'void* sa (+ off uv-sc-data-offset) 0)
                               (foreign-set! 'int sa (+ off uv-sc-data-offset) k))
                              (else
                               (foreign-set! 'int sa (+ off uv-sc-flags-offset)
                                             UV-IGNORE)
                               (foreign-set! 'void* sa (+ off uv-sc-data-offset) 0))))
                          (loop (fx+ k 1))))
                      ;; TEST SEAM 'proc-stdio-bogus-stream -- when armed, the
                      ;; first container asked for as a pipe is described as
                      ;; an inherited descriptor -1 instead. uv_spawn's stdio
                      ;; loop answers UV_EINVAL for that and takes its error:
                      ;; label BEFORE any fork, which is the real path the F13
                      ;; repair exists for and the only one reachable without
                      ;; starting a child. Unarmed the override answers #f and
                      ;; nothing is rewritten.
                      (when (inject-override! 'proc-stdio-bogus-stream #f)
                        (let loop ((k 0))
                          (when (fx< k 3)
                            (if (eq? (vector-ref modes k) 'pipe)
                                (let ((off (* k uv-stdio-container-size)))
                                  (foreign-set! 'int sa (+ off uv-sc-flags-offset)
                                                UV-INHERIT-FD)
                                  (foreign-set! 'void* sa (+ off uv-sc-data-offset) 0)
                                  (foreign-set! 'int sa (+ off uv-sc-data-offset) -1))
                                (loop (fx+ k 1))))))
                      ;; (3) the spawn itself.
                      ;; INJECTION POINT 'proc-uv-spawn-result -- an OVERRIDE,
                      ;; because the cell it serves needs the real call to run
                      ;; and really start a child, and only then to be told it
                      ;; failed. That is the orphan shape: r < 0 with an active
                      ;; handle.
                      (let ((r (inject-override! 'proc-uv-spawn-result
                                 (uv-spawn (uv-loop-handle) ph ob))))
                        (set! spawned? #t)
                        ;; (4) the marshalled memory is consumed synchronously
                        (free-blocks!)
                        (cond
                          ((< r 0)
                           ;; (5) THE F13 REPAIR RUNS ON EVERY NEGATIVE RESULT
                           ;; AND BEFORE ANYTHING ELSE TOUCHES THE HANDLE: both
                           ;; queue pointers are still valid at this instant,
                           ;; because no other handle operation has run since
                           ;; uv_spawn returned and the region excludes
                           ;; callbacks.
                           (repair-spawn-queue! ph)
                           (if (= 0 (uv-is-active ph))
                               ;; the ordinary failure (a missing binary, a
                               ;; rejected stdio container): no child exists
                               (begin
                                 (set! released? #t)
                                 (close-pipe-handles!)
                                 (uv-close ph on-process-close-entry)
                                 (set! ph #f)
                                 (cons 'failed (uv-strerror r)))
                               ;; THE ORPHAN: the child is running although
                               ;; uv_spawn reports failure, because a parent
                               ;; stream failed to open after the fork. Kill
                               ;; first, then account for it.
                               (begin
                                 (set! released? #t)
                                 (set! child-pid (uv-process-get-pid ph))
                                 (note-spawned-pid! child-pid)
                                 (uv-process-kill ph 9)
                                 ;; INJECTION POINT 'proc-orphan-publish
                                 ;; (fault) -- OWNING GUARD: the one on the
                                 ;; next line. Without a row the handle stays
                                 ;; registered and the exit callback's no-row
                                 ;; path closes and frees it; it is never
                                 ;; closed here, because closing an active
                                 ;; process handle leaves the child unreaped.
                                 ;;
                                 ;; THE CONDITION IS HELD, NOT SWALLOWED, and
                                 ;; re-raised below. The caller has to learn
                                 ;; that its spawn ended in an allocation
                                 ;; failure and not merely in the libuv error
                                 ;; uv_spawn reported: those are two different
                                 ;; events and only one of them says the
                                 ;; process is out of memory. The guard exists
                                 ;; solely so the pipe handles below are still
                                 ;; released on the way out -- an escape
                                 ;; straight to the region's guard would skip
                                 ;; them, and that guard cannot close them
                                 ;; either, because this branch has already
                                 ;; marked the release done.
                                 (let ((pub-err #f))
                                   (guard (e2 (#t (set! pub-err e2)))
                                     (let ((op (make-proc ph owner #f #f #f
                                                          child-pid #f 'orphan
                                                          #t 0 kill?)))
                                       (inject-fault! 'proc-orphan-publish)
                                       (hashtable-set! proc-table ph op)
                                       (set! p op)
                                       (set! row? #t)
                                       (index-owner! owner 'proc ph)
                                       (set! idx? #t)))
                                   ;; libuv closed only the descriptors it
                                   ;; opened; these handles are ours
                                   (close-pipe-handles!)
                                   (if pub-err
                                       (raise pub-err)
                                       (cons 'failed (uv-strerror r)))))))
                          (else
                           (set! child-pid (uv-process-get-pid ph))
                           (note-spawned-pid! child-pid)
                           (set! p (make-proc ph owner #f #f #f child-pid #f
                                              'running #t 0 kill?))
                           ;; the conns exist but are UNPUBLISHED: nothing can
                           ;; reach them yet, which is why the tag and the
                           ;; cleanup closure can be installed directly here
                           ;; rather than through the refusing setters.
                           (let loop ((k 0))
                             (when (fx< k 3)
                               (when (vector-ref pipe-inited? k)
                                 (let ((c (make-conn (vector-ref pipe-h k) owner
                                                     'open #f #f #f #f #f))
                                       (nm (proc-stream-name k)))
                                   (conn-set-tag! c (cons p nm))
                                   (conn-set-cleanup! c (make-pipe-cleanup p nm))
                                   (vector-set! pipe-conn k c)
                                   (proc-set-stream! p nm c)))
                               (loop (fx+ k 1))))
                           ;; stdin is ours to write, never to read, so only
                           ;; the two output pipes are started
                           (let ((rr (let loop ((k 1))
                                       (if (fx>= k 3)
                                           0
                                           (let ((c (vector-ref pipe-conn k)))
                                             (if (not c)
                                                 (loop (fx+ k 1))
                                                 ;; INJECTION POINT
                                                 ;; 'proc-read-start-result --
                                                 ;; an OVERRIDE: the read
                                                 ;; really starts and the
                                                 ;; rollback really has to
                                                 ;; stop it, which uv_close on
                                                 ;; the handle does.
                                                 (let ((n (inject-override!
                                                            'proc-read-start-result
                                                            (uv-read-start
                                                              (conn-handle c)
                                                              on-alloc-entry
                                                              on-read-entry))))
                                                   (if (< n 0)
                                                       n
                                                       (loop (fx+ k 1))))))))))
                             (if (< rr 0)
                                 (begin
                                   (rollback-active!)
                                   (cons 'failed (uv-strerror rr)))
                                 (begin
                                   ;; PUBLISH IN A FIXED ORDER. Order matters
                                   ;; only to the rollback -- no callback can
                                   ;; run inside this region -- but the
                                   ;; rollback reads these flags, so each one
                                   ;; is set immediately after its step.
                                   (hashtable-set! proc-table ph p)
                                   (set! row? #t)
                                   ;; INJECTION POINT 'proc-publish-index-fail
                                   ;; (fault) -- OWNING GUARD: the one around
                                   ;; the whole region. It produces the state
                                   ;; the rollback keys on: row present, owner
                                   ;; entry absent.
                                   (inject-fault! 'proc-publish-index-fail)
                                   (index-owner! owner 'proc ph)
                                   (set! idx? #t)
                                   (let loop ((k 0) (n 0))
                                     (if (fx>= k 3)
                                         (void)
                                         (let ((c (vector-ref pipe-conn k)))
                                           (if (not c)
                                               (loop (fx+ k 1) n)
                                               (begin
                                                 (hashtable-set! conn-table
                                                   (conn-handle c) c)
                                                 (note-pipe-conn! 1)
                                                 (vector-set! pipe-row? k #t)
                                                 (index-owner! owner 'conn
                                                   (conn-handle c))
                                                 (vector-set! pipe-idx? k #t)
                                                 ;; INJECTION POINT
                                                 ;; 'proc-publish-fail (fault)
                                                 ;; -- OWNING GUARD: the
                                                 ;; region's. Fired after the
                                                 ;; proc row and exactly one
                                                 ;; conn row, which is the
                                                 ;; partially-published state
                                                 ;; the rollback has to undo.
                                                 (when (fx= n 0)
                                                   (inject-fault! 'proc-publish-fail))
                                                 (loop (fx+ k 1) (fx+ n 1)))))))
                                   p)))))))))))))))

  ;; ---- writing a child's stdin -------------------------------------------

  ;; -> #t once the bytes are accepted, #f when they are refused. The two
  ;; answers differ in exactly one observable: a refusal never calls on-done,
  ;; while an acceptance always settles, whether the write completes, fails
  ;; (EPIPE when the child has closed its end) or is cancelled.
  ;;
  ;; on-done RUNS IN CALLBACK CONTEXT AND MUST NOT YIELD OR PARK. It is
  ;; invoked inline inside this region when the write completes at once, and
  ;; from the loop's write callback otherwise; the guard around it contains a
  ;; raise, not a scheduler yield. Same contract tcp-write! carries, enforced
  ;; the same way -- by agreement, not by a check.
  ;;
  ;; THE CHARGE, THE SUBMISSION AND THE EXCEPTION REFUND ARE ONE REGION. A
  ;; kill takes effect only at a safe point with interrupts enabled, and
  ;; inside the region there is none, so a writer killed after proc-write!
  ;; returned cannot leave a charge nobody will settle.
  (define (proc-write! p bv . on-done)
    (let* ((done (if (null? on-done) #f (car on-done)))
           (len (bytevector-length bv))
           (settled? #f))
      ;; BUILT BEFORE THE CHARGE, because it is what discharges it: a closure
      ;; that did not exist yet could not be reached by a failure between the
      ;; two.
      (define (settle! status)
        (let ((first?
                (with-interrupts-disabled
                  (if settled?
                      #f
                      (begin
                        (set! settled? #t)
                        (proc-set-queued! p (fx- (proc-queued p) len))
                        #t)))))
          (if (not first?)
              ;; COUNTED POINT 'proc-write-settled-twice -- unarmed: silent.
              ;; A second settlement is absorbed rather than refused: the flag
              ;; is what makes "exactly once" hold, and the count is what
              ;; makes a collision visible instead of silent.
              (inject-barrier! 'proc-write-settled-twice)
              ;; the raise path settles too, but its caller gets the condition
              ;; rather than a completion, so no on-done is owed
              (when (and done (not (eq? status 'raised)))
                (guard (e (#t (note-swallowed! 'proc-write-done e)))
                  (done status))))))
      (define (complete! status)
        (settle! status)
        ;; TEST SEAM 'proc-write-settle-twice -- when armed the library
        ;; settles a second time on purpose, which is the collision the flag
        ;; above exists to absorb. Without the flag this is a double refund
        ;; and `queued` goes negative.
        (when (inject-override! 'proc-write-settle-twice #f)
          (settle! status)))
      (with-interrupts-disabled
        (let ((in (proc-stdin p)))
          (cond
            ((not (and in
                       (eq? (conn-state in) 'open)
                       (not (conn-raw-sealed? in))))
             #f)
            ((fx> (fx+ (proc-queued p) len) proc-stdin-cap) #f)
            (else
              (proc-set-queued! p (fx+ (proc-queued p) len))
              ;; tcp-write! can raise before it has taken the write -- the
              ;; foreign-alloc of the write block is inside it -- and in that
              ;; case nothing else will ever settle this charge.
              (guard (e (#t (settle! 'raised) (raise e)))
                (tcp-write! in bv complete!))
              #t))))))

  ;; Half-close a child's stdin, so the child reads EOF after the last byte of
  ;; every write that completed. -> #t when a close is under way, #f when
  ;; there is nothing to close (no stdin pipe, already closing, already
  ;; half-closed).
  ;;
  ;; NOT tcp-close!. Closing the handle cancels every queued write on it, so a
  ;; child that was still being fed would see a truncated stream; uv_shutdown
  ;; drains what is queued first and only then shuts the write side down.
  ;;
  ;; A NEGATIVE SUBMISSION MEANS NO CALLBACK FOLLOWS, so that branch resolves
  ;; the stream here rather than waiting for one.
  (define (proc-stdin-close! p)
    (with-interrupts-disabled
      (let ((in (proc-stdin p)))
        (if (not (and in
                      (eq? (conn-state in) 'open)
                      (not (conn-raw-sealed? in))))
            #f
            (let ((req #f))
              ;; ONE GUARD OVER THE WHOLE PRE-SUBMISSION SEQUENCE. Both the
              ;; allocation and the table write can raise, and either leaves
              ;; the seal already set -- so the pipe has to be closed on the
              ;; way out or nothing would ever finish it.
              (guard (e (#t (when req
                              (hashtable-delete! shutdown-table req)
                              (free-shutdown-req! req)
                              (set! req #f))
                            (tcp-close! in)
                            (raise e)))
                (conn-set-raw-sealed! in #t)
                (set! req (alloc-shutdown-req!))
                ;; INJECTION POINT 'proc-shutdown-register (fault) -- OWNING
                ;; GUARD: the one above, while the request exists and nothing
                ;; else knows about it. That is the only window in which the
                ;; handler has a request to free.
                (inject-fault! 'proc-shutdown-register)
                (hashtable-set! shutdown-table req in)
                ;; INJECTION POINT 'proc-uv-shutdown-result -- a RETURN, not
                ;; an override: the call is skipped, so no request is ever
                ;; stored on the stream and freeing it below is correct. An
                ;; override would free a request libuv still owned.
                (let ((r (inject-return! 'proc-uv-shutdown-result
                           (uv-shutdown req (conn-handle in) on-shutdown-entry))))
                  (if (< r 0)
                      (begin
                        (hashtable-delete! shutdown-table req)
                        (free-shutdown-req! req)
                        (set! req #f)
                        (set! shutdown-immediate-errors
                              (fx+ shutdown-immediate-errors 1))
                        (tcp-close! in)
                        #t)
                      (begin
                        ;; owned by the table from here: the guard must not
                        ;; free it if anything after this raises
                        (set! req #f)
                        #t)))))))))

  ;; ---- reading, signalling, closing --------------------------------------

  ;; REAL BACKPRESSURE, which a slow mailbox consumer is not: stopping the
  ;; read closes the kernel's window and the CHILD blocks in its write. The
  ;; read callback drains into the mailbox regardless of how fast anything
  ;; receives from it.
  (define (proc-read-stop! p stream)
    (let ((c (proc-stream-conn p stream)))
      (and c (begin (tcp-read-stop! c) #t))))

  (define (proc-read-start! p stream)
    (let ((c (proc-stream-conn p stream)))
      (and c (tcp-read-start! c))))

  ;; -> #t when a signal was sent, #f when there is no child left to signal.
  ;; PIPE STATE IS IRRELEVANT HERE: a child whose pipes this process already
  ;; closed is still a running child.
  (define (proc-kill! p signum)
    (with-interrupts-disabled
      (if (and (eq? (proc-child p) 'running) (proc-handle-alive? p))
          (begin (uv-process-kill (proc-handle p) signum) #t)
          #f)))

  ;; -> the number of children signalled.
  (define (proc-kill-all! signum)
    (with-interrupts-disabled
      (let ((ps (hashtable-values proc-table)))
        (let loop ((i 0) (n 0))
          (if (fx>= i (vector-length ps))
              n
              (let ((p (vector-ref ps i)))
                (if (and (eq? (proc-child p) 'running) (proc-handle-alive? p))
                    (begin (uv-process-kill (proc-handle p) signum)
                           (loop (fx+ i 1) (fx+ n 1)))
                    (loop (fx+ i 1) n))))))))

  ;; Close whichever pipes are still open. IDEMPOTENT, AND IT DOES NOT KILL:
  ;; the child keeps running and stays eligible for proc-kill! and for the
  ;; owner-death signal. Queued stdin writes fail through their completions
  ;; and are refunded; a pending stdin shutdown is cancelled. The row retires
  ;; once the process handle has closed too, which is after the exit.
  (define (proc-close! p)
    (let ((cs (with-interrupts-disabled
                (list (proc-stdin p) (proc-stdout p) (proc-stderr p)))))
      (for-each (lambda (c) (when c (tcp-close! c))) cs)
      (void)))

  ;; ONE REGION, so the seven numbers describe one instant rather than seven.
  ;; An alist rather than a tuple: the design named five quantities and two
  ;; more are read by the shutdown cells, and a key can be added later without
  ;; moving anything a reader already names.
  ;;
  ;; It walks proc-table, which allocates -- acceptable here because this is a
  ;; diagnostic call bounded by max-procs. socket-conn-count is the one that
  ;; may not walk, being on an http server's stats path, which is why the pipe
  ;; count it subtracts is maintained instead.
  (define (proc-stats)
    (with-interrupts-disabled
      (let ((ps (hashtable-values proc-table)))
        (let loop ((i 0) (running 0) (exited 0) (queued 0))
          (if (fx>= i (vector-length ps))
              (list (cons 'procs (hashtable-size proc-table))
                    (cons 'running running)
                    (cons 'exited-unclosed exited)
                    (cons 'pipes pipe-conns-live)
                    (cons 'queued-bytes queued)
                    (cons 'shutdown-pending (hashtable-size shutdown-table))
                    (cons 'shutdown-requests-live shutdown-reqs-live)
                    (cons 'shutdown-immediate-errors shutdown-immediate-errors))
              (let ((p (vector-ref ps i)))
                (loop (fx+ i 1)
                      (if (eq? (proc-child p) 'running) (fx+ running 1) running)
                      (if (eq? (proc-child p) 'exited) (fx+ exited 1) exited)
                      (fx+ queued (proc-queued p)))))))))
  )
