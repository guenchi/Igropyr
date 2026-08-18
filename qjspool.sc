#!chezscheme
;;; (igropyr qjspool) -- QuickJS renders in worker PROCESSES, behind the
;;; shared connection pool.
;;;
;;; WHY THIS EXISTS
;;;
;;; (igropyr quickjs) evaluates JS on the scheduler's own OS thread, inside
;;; with-interrupts-disabled. Its deadline bounds one call, but while that
;;; call runs NOTHING else in the process runs: no accepts, no reads, no
;;; timers -- and no watchdog, because every watchdog here is a green
;;; process too. The http pool's stuck-worker killer is stopped along with
;;; the thing it exists to protect. A render that reaches the deadline
;;; therefore costs the whole node its availability, and the crash-only
;;; rebuild that follows re-evaluates the bundle on the same thread with ten
;;; times the call budget. Misses for DIFFERENT keys stack: single-flight
;;; collapses repeats of one key, not a wave of distinct ones.
;;;
;;; The deadline cannot fix that from the inside. Aborting is cooperative --
;;; the interrupt handler can only ask, and the engine polls it only in its
;;; interpreter loop, so a long C builtin overruns it -- and the runtime
;;; that would enforce a wall clock is the one being blocked. Only something
;;; OUTSIDE the call can bound it, and only a separate process can be
;;; stopped outright.
;;;
;;; So the engine moves to the far side of a socket. That makes a render
;;; structurally identical to a query: an exclusive resource, borrowed for
;;; one request, whose work happens somewhere else. (igropyr connpool)
;;; already models exactly that -- checkout, leases, per-call and
;;; per-checkout deadlines, monitor reclaim when a borrower is killed,
;;; rebuild on death, statistics -- so this library supplies a wire protocol
;;; and error shapes and nothing more. None of the pool machinery is
;;; duplicated here.
;;;
;;; A runaway render now blocks its own worker process and nothing else: the
;;; caller's deadline is an ordinary receive-after, the scheduler keeps
;;; running, and the pool discards and rebuilds the connection.
;;;
;;; THE TWO SIDES
;;;
;;;   worker   qjs-worker-serve! boots the engine and answers render frames.
;;;            Run it as its own OS process -- qjs-worker.sc is that process:
;;;              scheme --script igropyr/qjs-worker.sc 127.0.0.1 9701 bundle.js
;;;
;;;   caller   (define p (qjspool '(("127.0.0.1" . 9701) ("127.0.0.1" . 9702))))
;;;            (qjspool-render p "renderPost" "{\"title\":\"Hi\"}")
;;;
;;; ONE CONNECTION PER WORKER. A worker is single-threaded and holds one
;;; engine, so two connections to the same worker serialize inside it. The
;;; pool is sized by the endpoint LIST -- one connection each -- and
;;; parallel renders come from running more worker processes, not from a
;;; larger pool against one. Rebuilt connections are handed out in rotation,
;;; so repeated failures at one endpoint can leave the distribution uneven;
;;; that costs latency, never correctness, because a worker serializes
;;; whatever it is given.
;;;
;;; WHAT THIS DOES NOT DO YET. Nothing here starts, stops or kills a worker
;;; process; they are started by whatever supervises the node, exactly as a
;;; database is. A worker wedged in a runaway render therefore stays wedged
;;; -- what the pool guarantees is that the CALLER is not, and that other
;;; endpoints keep serving. Killing one needs uv_spawn/uv_kill, which
;;; (igropyr libuv) does not bind.
;;;
;;; NO AUTHENTICATION. Any local process that can reach the port can ask for
;;; renders. Workers are meant to listen on 127.0.0.1.
;;;
;;; WIRE FORMAT -- one length-prefixed frame each way:
;;;
;;;   request    u32be n | u32be id | u16be fnlen | fn utf8 | props utf8
;;;   response   u32be n | u32be id | u8 status  | body
;;;              status 0 = the render's HTML, 1 = the JS error text.
;;;
;;; The ID is echoed by the worker and checked on the way back. Without it
;;; a response carries nothing that ties it to a request, and "the buffer
;;; is empty after I took my frame" does not cover a stray frame still in
;;; flight: it arrives later, on a connection that has since been returned
;;; to the pool and lent to somebody else, and answers THEIR render.
;;;
;;; THREE WAYS A RENDER FAILS, AND ONLY ONE COSTS THE CONNECTION.
;;;
;;;   a JS error   -- the worker ran the render and it threw. A NORMAL
;;;                   response (status 1), and the connection stays
;;;                   usable: the worker did its job and the answer is
;;;                   that the render raised.
;;;   local        -- the request never reached the socket: it could not
;;;                   be encoded, or its deadline was gone before the
;;;                   write. Nothing is in doubt because nothing was
;;;                   asked, so the connection stays usable too, and the
;;;                   caller is told why -- it is the caller's input that
;;;                   has to change, and no other worker would answer
;;;                   differently.
;;;   transport    -- bytes may have left this process. The connection is
;;;                   discarded, on the principle that a stream whose
;;;                   framing is in doubt cannot be trusted with the next
;;;                   reply. Malformed and oversized frames are the
;;;                   obvious ones, but not the only ones: a worker that
;;;                   ends the stream partway through a reply, and a
;;;                   render that outlives its deadline, are transport
;;;                   failures too, and retire the connection the same
;;;                   way.
;;;
;;; The dividing line between the last two is the write, and it is drawn
;;; at that one call in render-on!. All three reach the caller as
;;; (values #f text).
;;;
;;; WHAT partial-frame-ms ACTUALLY BOUNDS. It is measured from when this
;;; process got to LOOK at the bytes, not from when they reached the
;;; socket, and it is checked between renders rather than during one. A
;;; render is a synchronous FFI call that stops the whole runtime, so
;;; bytes arriving while one is in flight are not timestamped, are not
;;; read, and cannot start a clock -- and the render already running when
;;; a deadline passes finishes. Real arrival time would need an entry
;;; layer that the engine cannot block, which means another process again.
;;; The bound is therefore approximate by construction: it stops a peer
;;; from parking a half frame indefinitely, which is what it is for, and
;;; it is not a wall clock.

(library (igropyr qjspool)
  (export qjs-worker-serve!
          qjspool qjspool-connect qjspool?
          qjspool-render qjspool-render/bytes
          qjspool-timeout-ms qjspool-stats qjspool-close!)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr connpool)
          (igropyr buffer)
          (only (igropyr quickjs) qjs-boot! qjs-call/bytes))

  ;; Frames larger than this are not read: the length prefix arrives before
  ;; the body, so an absurd one would otherwise reserve the connection for a
  ;; body that never comes. 64 MiB is far above any rendered page and far
  ;; below anything that hurts to refuse.
  (define max-frame (* 64 1024 1024))
  (define connect-timeout-ms 5000)

  ;; Defaults chosen for the REQUEST path, not for a database: a render that
  ;; has not answered in five seconds has already cost more than the page it
  ;; was producing is worth. The caller's deadline is deliberately the
  ;; larger of the two -- see qjspool.
  (define default-render-ms 5000)
  (define default-checkout-ms 2000)

  ;; ---- errors --------------------------------------------------------------
  ;; A JS error is not one of these at all: it comes back as an ordinary
  ;; reply, because the connection is still perfectly good and the worker
  ;; did its job -- the answer is just that the render raised.
  ;;
  ;; THE KIND IS WHICH SIDE OF THE WRITE IT HAPPENED ON, and it decides
  ;; whether the connection survives. `transport` means bytes may have
  ;; left this process: the worker's state is unknown, the framing is in
  ;; doubt, and the connection is discarded. `local` means the request
  ;; never reached the socket, so there is nothing to be in doubt about
  ;; and the connection is exactly as it was.
  ;;
  ;; Transport is the DEFAULT, and local is what render-on! marks
  ;; deliberately: everything it does before the write is local, and
  ;; everything anywhere else is transport. Stated as a position rather
  ;; than a list of sites, because a list goes out of date the first time
  ;; one is added -- a new raise before the write must be given the local
  ;; kind, and anything reached after it must not.
  ;;
  ;; Defaulting this way round is the safe direction: of the two possible
  ;; mistakes, retiring a good connection costs a reconnect, while keeping
  ;; a doubtful one costs the next caller's answer.
  ;;
  ;; One tag with a field that tells them apart, as (igropyr mysql) does
  ;; with #(mysql-error code msg) and (igropyr postgresql) with its
  ;; 'transport state, rather than a second tag every predicate would
  ;; have to learn. None of this escapes the library: the public calls
  ;; answer with text.
  (define (qjs-err msg) (vector 'qjs-error 'transport msg))
  (define (qjs-local-err msg) (vector 'qjs-error 'local msg))
  (define (qjs-error? r) (and (vector? r) (eq? (vector-ref r 0) 'qjs-error)))
  (define (qjs-error-local? r)
    (and (qjs-error? r) (eq? (vector-ref r 1) 'local)))
  (define (qjs-error-text r) (vector-ref r 2))
  ;; Wrapping something that is not one of ours: transport, per the
  ;; default above. A local failure is only ever raised as one already.
  (define (as-qjs-error e context)
    (if (qjs-error? e)
        e
        (qjs-err (string-append context ": "
                   (cond ((string? e) e)
                         ((and (condition? e) (message-condition? e))
                          (condition-message e))
                         (else "unknown error"))))))

  ;; ---- frames --------------------------------------------------------------

  (define (bv-slice bv from n)
    (let ((out (make-bytevector n)))
      (bytevector-copy! bv from out 0 n)
      out))

  (define (encode-request id fn json)
    (let* ((f (string->utf8 fn)) (j (string->utf8 json))
           (fl (bytevector-length f)) (jl (bytevector-length j))
           (n (+ 4 2 fl jl)))
      ;; refused HERE rather than sent: the length field cannot carry it, and
      ;; a truncated name would ask the worker to render a different function
      (when (> fl 65535)
        (raise (qjs-err "render function name too long")))
      (when (> n max-frame)
        (raise (qjs-err "render request larger than the frame limit")))
      (let ((bv (make-bytevector (+ 4 n))))
        (bytevector-u32-set! bv 0 n (endianness big))
        (bytevector-u32-set! bv 4 id (endianness big))
        (bytevector-u16-set! bv 8 fl (endianness big))
        (bytevector-copy! f 0 bv 10 fl)
        (bytevector-copy! j 0 bv (+ 10 fl) jl)
        bv)))

  (define (encode-response id status body)
    (let ((n (+ 4 1 (bytevector-length body))))
      (if (> n max-frame)
          ;; Our own output must stay inside what the peer will accept, or a
          ;; successful render becomes a transport error that discards a
          ;; healthy connection. Reported as a JS-level failure instead.
          (encode-response id 1
            (string->utf8 "render output exceeds the frame limit"))
          (let ((bv (make-bytevector (+ 4 n))))
            (bytevector-u32-set! bv 0 n (endianness big))
            (bytevector-u32-set! bv 4 id (endianness big))
            (bytevector-u8-set! bv 8 status)
            (bytevector-copy! body 0 bv 9 (bytevector-length body))
            bv))))

  ;; -> the frame body with its length prefix dropped, or #f while the
  ;; buffer does not hold a whole frame. An oversized length RAISES rather
  ;; than returning #f: it is not a frame that will ever complete, and
  ;; waiting for more bytes would be waiting forever.
  (define (take-frame! buf)
    (and (>= (inbuf-length buf) 4)
         (let ((n (bytevector-u32-ref (inbuf-sub buf 0 4) 0 (endianness big))))
           (when (> n max-frame)
             (raise (qjs-err "peer announced a frame past the limit")))
           (and (>= (inbuf-length buf) (+ 4 n))
                (let ((body (inbuf-sub buf 4 (+ 4 n))))
                  (inbuf-consume! buf (+ 4 n))
                  body)))))

  ;; ---- worker side ---------------------------------------------------------

  ;; Boot the engine and listen. Returns the listener handle; the caller
  ;; runs the actor loop (qjs-worker.sc does both).
  ;; How long a HALF-DELIVERED request may stay half-delivered. Also read
  ;; from the boot options, so a caller (and the test) can shorten it.
  (define default-partial-frame-ms 30000)

  ;; A READ TRACE, off unless asked for. One line per read, flushed, so
  ;; that a test can assert what the reader actually saw rather than infer
  ;; it from how long a sleep was. That distinction is not academic: two
  ;; rounds of this library's review turned on an ad-hoc instrumentation
  ;; that measured zero because a worker reaped with kill -9 takes its
  ;; block-buffered output with it, and a wrong conclusion shipped. It is
  ;; a diagnostic for the same reason a production worker that starts
  ;; closing connections is otherwise a black box.
  (define trace-port (make-parameter #f))

  ;; WHOSE READ IT WAS. One worker serves many connections at once, and a
  ;; probe that asserts "a late read happened" against a global count can
  ;; be satisfied by a DIFFERENT connection's read -- which is the exact
  ;; kind of silent pass these assertions exist to remove. Every line
  ;; carries the connection's own process, so a count can be taken per
  ;; connection.
  ;; A DIAGNOSTIC MUST NOT KILL WHAT IT IS DIAGNOSING. This runs at the
  ;; top of the read path, outside the guard that turns a framing error
  ;; into a closed connection, so a write that fails -- a full disk, a
  ;; closed pipe -- would otherwise raise here and take down the
  ;; connection's process, while the listener stayed up, leaving a worker
  ;; that holds its port and fails every render. The first failure turns
  ;; tracing off for the life of the process; nothing after that can
  ;; raise.
  ;;
  ;; IT GOES SILENT WITHOUT SAYING SO, which is a gap and not an
  ;; oversight. Reporting on stderr instead would not close it, and the
  ;; reason is a level down: a worker is a separate process, so where its
  ;; stderr goes is chosen by whatever launched it, and redirecting it
  ;; away is ordinary -- the launcher in this repository's own tests
  ;; sends it to /dev/null. A report on a channel the library cannot
  ;; reach is worse than none, because it reads as coverage. The trace
  ;; file is no better, its port being what just failed. What is true is
  ;; not that no channel exists but that none is GUARANTEED here, and a
  ;; gap admitted beats a report that may go nowhere.
  ;;
  ;; So a trace that stops partway is ambiguous: tracing broke, the
  ;; worker was killed, or the process died. A fourth case leaves no
  ;; trace of itself at all -- an open file that is unlinked keeps taking
  ;; writes, so records keep being written to a path that no longer has
  ;; them and this handler never runs. A reader has to separate all four
  ;; by other means.
  ;;
  ;; WHAT IS GUARDED IS A WRITE THAT FAILS, NOT ONE THAT NEVER RETURNS,
  ;; and the second is the worse of the two: a guard catches nothing from
  ;; it, this is a synchronous write with interrupts disabled, and one OS
  ;; thread runs every connection -- so a worker asked only to describe
  ;; itself stops serving all of them. A slow write is the same shape as
  ;; a stuck one here; the guard bounds neither, it only keeps a raise
  ;; from killing the process.
  ;;
  ;; A FIFO is the sharpest case: opening one for writing WAITS for a
  ;; reader, so a worker pointed at one never reaches its listener; and
  ;; if a reader attaches and later stops, the pipe fills and every write
  ;; after that blocks. But slow storage does the same thing without
  ;; anyone choosing it -- a regular file on a network or fuse
  ;; filesystem, or a congested device, can hang at the open or at a
  ;; flush, and an operation that eventually returns an error can hang a
  ;; long time first. So the stretches that write a trace are bounded by
  ;; the STORAGE, not by anything arranged here, and claims elsewhere
  ;; about their being bounded are conditional on that.
  ;;
  ;; A VALIDATION-TIME FIX WAS TRIED AND REVERTED -- rejecting a
  ;; trace-file that exists and is not a regular file. Recorded because
  ;; it is the obvious thing to reach for, and it dies three ways:
  ;;
  ;;   - It rejects working configurations. /dev/null is not a regular
  ;;     file and is a perfectly good place to send a trace; nor is a
  ;;     tty. Worse, /dev/stderr names fd 2, so it classifies as
  ;;     whatever the launcher attached to stderr, and the same
  ;;     configuration passes or fails depending on how the process was
  ;;     started.
  ;;   - It does not close the window it aims at. The check tests a path
  ;;     and the open that follows resolves it again; anything able to
  ;;     write the directory can put a FIFO there in between, and the
  ;;     open blocks before there is a listener. Nor is "check after the
  ;;     open instead" a fix on its own: an ordinary blocking open never
  ;;     returns a descriptor to check. What settles THIS window is an
  ;;     open whose result the path can no longer be swapped out from
  ;;     under, which the next paragraph gets to.
  ;;   - The class it claimed to exclude does not hold together. A
  ;;     regular file on fuse CAN have its readiness decided by another
  ;;     process -- not on every operation, since caching and writeback
  ;;     can answer without the daemon, but on some -- and it passes.
  ;;
  ;; WHAT WOULD REFUSE A READER-LESS FIFO AT OPEN, in case the trade is
  ;; ever worth making -- refuse at open, which is less than "handle the
  ;; FIFO case": open O_WRONLY | O_NONBLOCK and let the open itself
  ;; answer, instead of asking a proxy question about the path
  ;; beforehand.
  ;; Measured, the same three targets the check above got wrong:
  ;;
  ;;     FIFO with no reader   ENXIO      (refused, correctly)
  ;;     regular file          succeeds   (accepted, correctly)
  ;;     /dev/null             succeeds   (accepted -- the check
  ;;                                       above refused it)
  ;;
  ;; The last line is where a proxy and the property part company: not
  ;; being a regular file is not the same as being able to wait, and
  ;; /dev/null is the ordinary case that shows it.
  ;;
  ;; NOT "an open that cannot wait", which overstates it twice over.
  ;; O_NONBLOCK governs the reader-less FIFO; it does not make path
  ;; resolution, a fuse OPEN round trip, or the storage behind a plain
  ;; file asynchronous, so that open can still wait on exactly the
  ;; targets the paragraph above says are left untouched. And it closes
  ;; the swap window ONLY if the descriptor it returns becomes the trace
  ;; port -- used as a probe, with the port opened by path afterwards,
  ;; the window is exactly as wide as before, since the second open
  ;; resolves the path again.
  ;;
  ;; AND IT SETTLES THE OPEN, NOT THE WRITES. What happens to a FIFO
  ;; after the open splits in two, and they need different answers. With
  ;; NO READER LEFT -- the last one closing, not just any one of several
  ;; -- a write raises SIGPIPE, and returns EPIPE once the signal is
  ;; handled some way other than by the default: blocked, ignored, or
  ;; caught by a handler that returns. A version that leaves the default
  ;; in place is taken down by the signal instead of being told its trace
  ;; failed. With a READER STILL OPEN THAT HAS STOPPED READING the pipe
  ;; fills instead, giving EAGAIN under O_NONBLOCK, and a large write may
  ;; complete short of what it was given. So keeping the refusal means
  ;; keeping O_NONBLOCK on that same open file description, giving
  ;; SIGPIPE some disposition other than the default, turning EPIPE and
  ;; EAGAIN alike into a visible failure rather than a quiet wait, and
  ;; checking for a short write and deciding what a half record means.
  ;; A version that gets the open right and lets the port block again has
  ;; moved the wedge, not removed it. All of which needs platform
  ;; constants through the FFI, a real cost for an opt-in diagnostic.
  ;; Removing
  ;; the exposure rather than detecting it takes a bounded queue drained
  ;; by a separate OS thread, the worker doing only a non-blocking
  ;; handoff -- a green process will not do, sharing the one thread.
  ;;
  ;; Deliberately none of those: the cost falls on an operator who turned
  ;; tracing on, and it is written down here rather than discovered.
  ;; ONE RECORD, ONE WRITE, UNDER ONE LOCK. Built as a string first and
  ;; emitted inside a region where nothing else can run. A record made of
  ;; several displays is not atomic just because there is one OS thread:
  ;; a green process can be preempted between any two of them, so two
  ;; connections' records interleave and the reader attributes the second
  ;; one's fields to the first. The enabled check and the switch to
  ;; disabled live in the same region, so a port read before a failure
  ;; cannot be used after it.
  (define (trace! . parts)
    (with-interrupts-disabled
      (let ((p (trace-port)))
        (when p
          (guard (e (#t (trace-port #f)))
            (display (apply string-append
                            "c" (number->string (process-id self)) " "
                            (append (map (lambda (x)
                                           (if (string? x) x (format "~a" x)))
                                         parts)
                                    (list "\n")))
                     p)
            (flush-output-port p))))))

  (define (qjs-worker-serve! host port bundle . rest)
    (let* ((qopts (if (pair? rest) (car rest) '()))
           (partial-ms (cond ((assq 'partial-frame-ms qopts) => cdr)
                             (else default-partial-frame-ms)))
           (trace (cond ((assq 'trace-file qopts) => cdr) (else #f))))
      (unless (and (integer? partial-ms) (exact? partial-ms) (> partial-ms 0))
        (assertion-violation 'qjs-worker-serve!
          "partial-frame-ms must be a positive exact integer" partial-ms))
      (when (assq 'trace-file qopts)
        (unless (string? trace)
          (assertion-violation 'qjs-worker-serve!
            "trace-file must be a path" trace)))
      (when (string? trace)
        (trace-port (guard (e (#t (assertion-violation 'qjs-worker-serve!
                                    "trace-file could not be opened" trace)))
                     (open-file-output-port trace
                                           (file-options no-fail no-truncate append)
                                           (buffer-mode line)
                                           (native-transcoder)))))
      (qjs-boot! bundle qopts)
      (tcp-listen! host port 128
        (lambda (c)
          ;; libuv callback context: spawn + register only, no yielding
          (let ((pid (spawn (lambda ()
                              (worker-conn-loop c (make-inbuf) partial-ms)))))
            (conn-set-owner! c pid)
            (tcp-read-start! c))))))

  ;; A HALF-DELIVERED frame gets a deadline; an idle connection does not.
  ;; Those are different silences. A pooled connection is legitimately idle
  ;; for as long as its caller has nothing to render, and closing it would
  ;; tear down healthy connections on a timer. Silence in the MIDDLE of a
  ;; frame is nobody's normal behaviour: it holds a process, a file
  ;; descriptor and everything already received -- and since a length
  ;; prefix up to the cap is accepted before its body arrives, a peer can
  ;; park most of a frame's worth of buffer per connection and simply stop,
  ;; without ever sending a FIN that would end it.
  (define (worker-conn-loop c buf partial-ms)
    (worker-conn-loop* c buf partial-ms #f #f))

  ;; `since` is the ABSOLUTE deadline of the frame currently half delivered,
  ;; or #f when nothing is. Re-arming a fresh timeout on every arrival made
  ;; this an inactivity timer, and an inactivity timer bounds nothing here:
  ;; a peer sending one byte just under the interval keeps the same half
  ;; frame -- and its process, its descriptor and most of a frame's worth of
  ;; buffer -- alive indefinitely. The deadline is taken once, on the pass
  ;; that finds something left over AFTER answering -- not when the buffer
  ;; stops being empty, which is earlier and can be a whole synchronous
  ;; render earlier, since the same callback may carry a complete slow
  ;; request ahead of the tail. Further bytes shorten the wait rather
  ;; than renew it. It is also re-checked after answering, because the
  ;; renders in between are synchronous and nothing was counting during
  ;; them.
  ;; `grace` is the instant after which no further delivery round is
  ;; offered -- see the close branch. #f until a round is first prepared,
  ;; which is later than the deadline first expiring: an expired frame
  ;; with queued bytes drains them one message per retry, and grace stays
  ;; #f across all of that. It is scoped to its deadline: wherever the
  ;; deadline is dropped or
  ;; renewed below, grace goes with it, so each half frame gets its own
  ;; and none inherits a spent one.
  (define (worker-conn-loop* c buf partial-ms since grace)
    ;; `grace` is a PARAMETER rather than the enclosing one, because the
    ;; delivery round in the close branch has just taken a limit that the
    ;; enclosing binding does not have yet, and re-entering here is how it
    ;; carries it. Copying the first steps of this procedure into that
    ;; branch instead worked, but put its trace ahead of the read-stop and
    ;; left two entry points to drift apart.
    (define (on-data bv grace)
      ;; READING STOPS FOR THE LENGTH OF THIS PASS. The loop turns it
      ;; back on where it goes back to waiting -- not only there, since
      ;; the tail below starts reading before it has decided whether to
      ;; wait at all, and an already-expired deadline closes instead --
      ;; and a path that turns it on may also match at once and go
      ;; straight back into a pass, when the same poll turn already
      ;; delivered a second message. What holds is the other direction,
      ;; and only for the stretch that matters: reading is off for every
      ;; PARSE-AND-RENDER pass. Not for every stretch that does work --
      ;; the close arms write their trace with reading still on, which
      ;; the note further down sets out, and bytes libuv delivers during
      ;; one of those is never looked at by anyone: the connection is
      ;; closing. So what holds is about renders, not about every byte
      ;; having a reader. While it
      ;; is off they stay in the socket's receive buffer, the window
      ;; closes, and the PEER's writes are what stall -- which is where
      ;; flow control belongs. An actor mailbox is not a substitute for
      ;; it: it is unbounded, and nothing in this protocol counts what has
      ;; been delivered and not yet parsed.
      ;;
      ;; AHEAD OF THE PARSE, therefore ahead of any render answer-all!
      ;; starts: the rule is about the whole pass, and putting it after
      ;; the parse would leave the renders -- the slowest thing this loop
      ;; does -- outside it.
      ;;
      ;; WHAT THIS BUYS is easy to understate, and an earlier note here
      ;; did: it said a pass could not be preempted at all, so the stop
      ;; was only insurance against some future version. That is wrong
      ;; on a batch. A render yields nothing (a synchronous call made
      ;; with interrupts disabled) and a single parse step burns no
      ;; preemption ticks -- measured, utf8->string of 8MiB lets a
      ;; competing process run zero times -- but answer-all! LOOPS,
      ;; and one 64KiB message can carry thousands of small requests
      ;; through parse, answer and write. A batch long enough crosses
      ;; the scheduler's quantum, the timer handler runs, and the poll
      ;; it turns lands between two renders. So the stop is load
      ;; bearing in the code as it stands, not only in some later one.
      ;;
      ;; Before the stop it is preemptible either way: a receive restores
      ;; interrupts before running the clause it matched, which is why
      ;; the stop is the first act rather than something done once per
      ;; wait. What this makes is the invariant
      ;; STRUCTURAL rather than incidental: it does not depend on nothing
      ;; in the pass ever parking or ever being preempted, which is a
      ;; property of the primitives used here rather than anything the
      ;; protocol promises, and the first version of this loop that
      ;; awaits anything mid-pass would otherwise reintroduce the leak
      ;; silently.
      (tcp-read-stop! c)
      (inbuf-append! buf bv)
      ;; a framing error is not recoverable on this connection: we no
      ;; longer know where the next request starts
      ;; The window for anything left over starts when the renders in this
      ;; same read are DONE, not when the bytes arrived.
      ;;
      ;; Starting it at arrival was the previous attempt, and it is worse:
      ;; the renders are synchronous, so a peer that pipelines two slow
      ;; requests with a partial tail behind them has its whole window
      ;; consumed before the tail is ever looked at -- measured against a
      ;; real worker, a tail that arrived with two 700ms renders got 0ms
      ;; and the connection was closed the instant the second answer went
      ;; out. That is a well-behaved pipelining client being cut off, which
      ;; is the thing answer-all! exists to support.
      ;;
      ;; What the arrival stamp was meant to stop -- a peer extending its
      ;; tail's life by sending slow work ahead of it -- costs that peer
      ;; real render time it asked for, and the buffer is bounded by the
      ;; frame cap either way. The liveness bug is the concrete one.
      ;; NO EXPIRY CHECK BEFORE THE PARSE. There was one, on the reasoning
      ;; that a receive answers a message already in its mailbox before it
      ;; consults its timer, so bytes completing a frame after the deadline
      ;; beat the timer that should have closed the connection. True, but
      ;; the reason they beat it is usually that WE were the ones running
      ;; late: a render is a synchronous call that stops the whole runtime,
      ;; so another connection's 700ms render swallows this one's 500ms
      ;; window whole, and the bytes sitting in the mailbox arrived well
      ;; inside it. Refusing them punishes a peer for our own scheduling.
      ;;
      ;; Nothing is lost by parsing first, because a peer that dribbles
      ;; never completes a frame: it consumes nothing and keeps its
      ;; original deadline, so the check BELOW takes it -- not
      ;; necessarily on this same read, and not necessarily by closing;
      ;; see A DELIVERY ROUND BEFORE CLOSING (the expiry branch) for what
      ;; that check does. Stated there and not restated here, because all
      ;; this argument needs is that something downstream takes the
      ;; dribbler, and every retelling of the rule has been a chance to
      ;; get it wrong. What the check up here changed was only the case
      ;; where the frame IS whole -- a real request, refused.
      ;; WHETHER WE WERE THE ONE RUNNING LATE, decided before the parse
      ;; because the parse moves the clock.
      ;;
      ;; This state is REACHABLE, and the scheduler is why. The event loop
      ;; polls libuv before it expires timers (actor.sc:740-746), and a
      ;; send to a process sitting in a timed receive cancels that
      ;; process's timeout outright rather than comparing it against the
      ;; clock (actor.sc:597-601). So when a synchronous render ends, the
      ;; bytes that arrived during it are delivered first and the
      ;; connection's own deadline never fires: it wakes holding data,
      ;; overdue. Measured across the suite: three such reads, overdue by
      ;; 300, 342 and 551ms.
      ;;
      ;; A round of this review once concluded the opposite from an
      ;; instrumented count of zero. That count was of the logging, not
      ;; the branch -- workers are reaped with kill -9 and Chez block
      ;; buffers to a file, so unflushed output dies with them.
      ;;
      ;; IT DOES NOT MEAN THE BYTES WERE PUNCTUAL. A peer with an
      ;; accomplice keeping the worker busy could send one byte after each
      ;; deadline and be forgiven for it forever. What a late read does
      ;; say is that everything libuv has ALREADY handed up was delivered
      ;; with nobody able to look at it -- so more of that delivery is
      ;; taken below before any decision, and a peer that has sent nothing
      ;; further has nothing to take. More, not all of it: the drained
      ;; branch takes one queued message per pass, so the run stops as
      ;; soon as a pass answers something or raises, whatever is still
      ;; queued behind it going with the connection.
      (let retry ((grace grace))
       (let ((late? (and since (>= (now-ms) since)))
            (before (inbuf-length buf)))
        ;; EVENT TYPES DO NOT SHARE FIELD NAMES. A close line also
        ;; reported "late=1", so an assertion looking for a late READ
        ;; counted closes as well -- a probe could pass on the strength of
        ;; the very event it was meant to rule out.
        (trace! "read buffered=" before
                " since=" (or since "-")
                " now=" (now-ms)
                " read-late=" (if late? "1" "0"))
        (if (guard (e (#t #f)) (answer-all! c buf) #t)
            (let* ((rest (inbuf-length buf))
                   ;; A FRAME WAS CONSUMED, so whatever is left over is a
                   ;; DIFFERENT half frame and gets a window of its own.
                   ;;
                   ;; WHICH BOUNDS THE FRAME, NOT THE CONNECTION. A peer
                   ;; that appends one cheap whole frame ahead of its tail
                   ;; each window renews forever, and it costs it a cheap
                   ;; render rather than the slow one an earlier note here
                   ;; assumed. Its lifetime is unbounded, and nothing on
                   ;; this side caps it: max-requests-per-connection is
                   ;; enforced by the caller's connection, never here.
                   ;;
                   ;; ITS MEMORY IS BOUNDED BY TWO DIFFERENT THINGS, and
                   ;; an earlier version of this note ran them together
                   ;; and then, correctly, said only what it could prove.
                   ;;
                   ;; While a frame is being ASSEMBLED, the bound is the
                   ;; cap: the length was checked before the body was
                   ;; accepted, so the buffer cannot outgrow the frame
                   ;; that was announced. It can overshoot it -- a message
                   ;; completing a maximum frame can carry up to 64KiB of
                   ;; the next one past it, and the buffer's doubling can
                   ;; hold twice the cap in backing store while
                   ;; take-frame! copies the body out again -- but that is
                   ;; a constant factor, which is what a cap is for.
                   ;;
                   ;; While this loop is BUSY, the cap bounds nothing: it
                   ;; is enforced on bytes that have already been queued,
                   ;; and inbuf-length cannot see the mailbox at all. What
                   ;; bounds that is the tcp-read-stop! at the top of
                   ;; on-data. Reading is on while this loop waits and
                   ;; goes off as the first act of the pass that
                   ;; follows, so it is off for the whole of a render --
                   ;; which is what this argument needs, and is weaker
                   ;; than "on only while waiting": a wake leaves it on
                   ;; until that first act runs.
                   ;; So a peer that writes faster than renders retire
                   ;; fills the kernel's receive buffer, has its window
                   ;; closed, and stalls on its own writes rather than
                   ;; having every segment copied into a mailbox nothing
                   ;; counts. The high-water mark is the socket buffer,
                   ;; which the kernel already sizes: no counter here to
                   ;; keep in step with one, and no option to get wrong.
                   ;;
                   ;; WHAT IS STILL IN FLIGHT WHEN THE STOP LANDS is one
                   ;; poll turn's delivery: libuv hands up everything
                   ;; readable in a turn, so several segments can already
                   ;; be in the mailbox before the first of them is
                   ;; looked at. take-queued! below is what draws on
                   ;; those, which is why a delivery split across
                   ;; messages is usually seen whole rather than as its
                   ;; first segment. One per pass, though, so it is not a
                   ;; guarantee that a whole poll turn reaches the buffer
                   ;; -- a pass that raises ends the run with the rest
                   ;; still in the mailbox.
                   ;; Keying the reset on "the buffer emptied" instead meant
                   ;; a peer that always keeps a partial tail -- which is
                   ;; what pipelining looks like -- was closed at the first
                   ;; frame's deadline however many complete frames it had
                   ;; delivered in between. Our own client never pipelines,
                   ;; but answer-all! exists for clients that do.
                   (consumed (< rest before))
                   ;; A RENEWED DEADLINE IS A NEW HALF FRAME, and grace is
                   ;; scoped to the deadline it was taken for: it has to
                   ;; die with that deadline or the next half frame
                   ;; inherits a budget already spent and is closed
                   ;; without the round this exists to give it. Clearing
                   ;; it on rest = 0 alone was not enough -- a peer that
                   ;; completes a frame while still owing the tail of the
                   ;; next one, which is what pipelining looks like, never
                   ;; passes through rest = 0.
                   (renewed (and (> rest 0) (or consumed (not since))))
                   (deadline (cond ((= rest 0) #f)
                                   (renewed (+ (now-ms) partial-ms))
                                   (else since)))
                   ;; PAIRED WITH IT HERE, not at each use. A renewed
                   ;; deadline can be expired by the time the branches
                   ;; below run -- partial-ms is only required to be a
                   ;; positive integer, so at 1 the clock ticking once
                   ;; between these two bindings is enough -- and the
                   ;; close branch would then read the PREVIOUS frame's
                   ;; grace, find it spent, and close a frame that had
                   ;; never been given a round. Deriving it once beside
                   ;; the deadline it belongs to is what makes "one
                   ;; deadline, one grace" hold on every path out of this
                   ;; cond rather than on the ones that were remembered.
                   (grace (if renewed #f grace)))
              (cond
                ((= rest 0) (worker-conn-loop* c buf partial-ms #f #f))
                ;; MORE OF THE SAME DELIVERY, before deciding against it.
                ;; libuv hands up at most 64KiB per callback, so a request
                ;; sent whole and in time still arrives in pieces; the
                ;; first completes no frame, and closing on it threw away
                ;; a request that was never late. Something already queued
                ;; tells that apart from a peer still owing us bytes,
                ;; which has nothing queued and is closed on the deadline
                ;; it had.
                ((and late? (not consumed) (take-queued! buf))
                 (trace! "drained rest=" rest) (retry grace))
                ;; A DELIVERY ROUND BEFORE CLOSING WHERE THE CAP LEAVES
                ;; ROOM FOR ONE -- and none where it does not, which is
                ;; the immediate close just below. Because an empty
                ;; mailbox is not an idle peer. take-queued! above sees
                ;; only what libuv has already handed up; bytes the peer
                ;; wrote in time can still be in the write queue, in a
                ;; socket buffer, or on the wire -- and they are exactly
                ;; there when we have just spent a long render not
                ;; reading, because the receive window was shut for all of
                ;; it. Measured: a peer that handed a 192KiB frame to
                ;; libuv 237ms INSIDE its window had 57KiB still in
                ;; flight when the render ended, and was closed for it.
                ;;
                ;; So the check that decides against the peer asks the
                ;; event loop once first. Reads go back on, and one
                ;; millisecond is not a grace period granted to the peer
                ;; -- it is the poll's own blocking bound. What it buys
                ;; is a turn of the loop, NOT a filter on when the bytes
                ;; were sent: a peer that writes a fresh byte after the
                ;; read-start below is answered by the same round, and
                ;; nothing here can tell that apart from a delivery
                ;; already on its way. Which is the point of the cap --
                ;; what bounds this is the total, not the length of one
                ;; round.
                ;;
                ;; THIS IS A WAIT, NOT AN INTERRUPTED PASS. Reading is on
                ;; while this loop is parked; this adds a third park
                ;; rather than leaving reads on across work.
                ;;
                ;; AND IT IS CAPPED, or it would undo the rule the
                ;; deadline exists for. Rounds are driven by bytes
                ;; arriving, and a peer dribbling one byte per round has
                ;; bytes arriving forever: without a cap this becomes the
                ;; inactivity timer the comment on `since` rejects, with
                ;; the interval cut from partial-ms to 1ms -- a bound of
                ;; hours where there was one of a fraction of a second.
                ;; The cap is one further partial-ms of rounds in total,
                ;; taken once and not renewed by a round that succeeds.
                ;;
                ;; WHAT IT GATES IS THE NEXT ROUND, NOT WHETHER A
                ;; FRAME IS STILL ACCEPTED. A round that hits goes on
                ;; to answer whatever it completed even if the clock
                ;; has passed `limit` by then: another connection's
                ;; synchronous render stops the whole runtime for as
                ;; long as it takes, and libuv is polled before timers
                ;; are, so a delivery can beat the very timeout meant
                ;; to end this.
                ;;
                ;; The other reading -- `limit` as an absolute deadline
                ;; for ACCEPTING a frame -- was considered and
                ;; rejected. Bytes in hand do not say when they were
                ;; sent, so refusing them refuses the peer that
                ;; dribbled past the cap AND the peer that delivered on
                ;; time into a window we had frozen; the second is who
                ;; this branch exists for, and a test of lateness that
                ;; we can move by rendering longer is not a test of the
                ;; peer. A frame already complete in the buffer is also
                ;; cheaper to answer than to discard, since discarding
                ;; it buys a retry -- the same render again, plus a
                ;; reconnection. The bound that remains: crossing
                ;; `limit` repeatedly requires completing frames, which
                ;; is progress, and a round completing nothing meets
                ;; the same spent `limit` at the next expiry and
                ;; closes. Renewal on `consumed` is the pipelining
                ;; decision above, not something this adds.
                ;;
                ;; IT STARTS WHEN THIS BRANCH IS FIRST REACHED, not at
                ;; the deadline. Anchoring it at the deadline would spend
                ;; the budget on the render we were blocked in -- a 745ms
                ;; render leaves 55ms of a 400ms cap, and a longer one
                ;; leaves none -- which is this very defect wearing a
                ;; different number. What the budget pays for is draining
                ;; the delivery chain once we are back, and that cannot
                ;; begin before we are back.
                ;;
                ;; Reached, not merely due: an expired frame with queued
                ;; bytes takes the drained branch above and retries,
                ;; possibly several times, and `grace` is still #f
                ;; through all of it -- so draining BEFORE the cap
                ;; exists is not charged to it, and the cap starts on
                ;; the pass that finds nothing left to take.
                ;;
                ;; Every drain before the cap exists, not just the first
                ;; one: the drained branch takes a single queued tcp-data
                ;; per retry, so what is owed to an incomplete frame
                ;; arrives over several passes with grace still #f
                ;; throughout. Not the whole mailbox -- take-queued!
                ;; matches tcp-data alone, and a queued message that
                ;; completes the frame ends the drain by making
                ;; `consumed` true. Once a round
                ;; has hit, the retry it re-enters carries the limit,
                ;; and draining after that DOES spend it -- which is
                ;; what makes a large negative grace-left readable
                ;; rather than a puzzle: payload size turns into cap
                ;; spent, one queued message at a time.
                ((>= (now-ms) deadline)
                 (let ((limit (or grace (+ (now-ms) partial-ms))))
                   (if (>= (now-ms) limit)
                       (let ((n (now-ms)))
                         ;; MEASURED, not written as the constant the
                         ;; branch implies: a branch taken says what was
                         ;; true on the way in, and the cap can be
                         ;; crossed after that while another connection's
                         ;; render holds the runtime.
                         ;;
                         ;; ONE SAMPLE FEEDS BOTH FIELDS. Reading the
                         ;; clock once per field let the pair contradict
                         ;; itself -- grace-spent=0 printed beside
                         ;; grace-left=-1, when the millisecond turned
                         ;; between the two reads. Neither field is the
                         ;; instant of the close, which no value printed
                         ;; before it can be; what they are is a single
                         ;; reading taken just before, and they agree
                         ;; with each other.
                         (trace! "close deadline rest=" rest
                                 " close-consumed=" (if consumed "1" "0")
                                 " close-late=" (if late? "1" "0")
                                 " grace-spent=" (if (>= n limit) "1" "0")
                                 " grace-left=" (- limit n))
                         (tcp-close! c))
                       (let ((t0 (now-ms)))
                         (tcp-read-start! c)
                         (receive (after 1
                                    ;; hit=0 says THE TIMEOUT ARM WAS
                                    ;; SELECTED, not that nothing has
                                    ;; arrived: interrupts are back on
                                    ;; before a timeout handler runs, so
                                    ;; a tcp-data can reach the mailbox
                                    ;; between the wake and this line and
                                    ;; will not be re-scanned. Read it as
                                    ;; "the round did not deliver", never
                                    ;; as "the peer sent nothing".
                                    (let ((n (now-ms)))
                                      (trace! "delivery round rest=" rest
                                              " hit=0 waited=" (- n t0))
                                      (trace! "close deadline rest=" rest
                                              " close-consumed="
                                              (if consumed "1" "0")
                                              " close-late="
                                              (if late? "1" "0")
                                              " grace-spent="
                                              (if (>= n limit) "1" "0")
                                              " grace-left=" (- limit n)))
                                    (tcp-close! c))
                           (`#(tcp-data ,bv)
                             ;; STOP BEFORE RECORDING, so this entry
                             ;; reaches the stop as directly as the
                             ;; ordinary one does. Tracing first left the
                             ;; loop preemptible with reads still on,
                             ;; which is the one thing the invariant
                             ;; above forbids; on-data stops again and
                             ;; libuv answers a stop on a stream that is
                             ;; not reading with success.
                             (tcp-read-stop! c)
                             (trace! "delivery round rest=" rest
                                     " hit=1 waited=" (- (now-ms) t0))
                             (on-data bv limit))
                           ;; WHERE says which of the three waits ended,
                           ;; since all three take the peer's end the
                           ;; same way and only the site tells them
                           ;; apart -- this one is the delivery round,
                           ;; so an end seen here is the peer closing
                           ;; while we were asking for the rest of a
                           ;; frame it still owed.
                           (`#(tcp-eof)
                             (trace! "close eof where=round rest=" rest)
                             (tcp-close! c))
                           (`#(tcp-error ,e)
                             (trace! "close error where=round rest=" rest)
                             (tcp-close! c)))))))
                (else (worker-conn-loop* c buf partial-ms deadline grace))))
            ;; THE PASS RAISED, and the guard above turns that into a
            ;; close. It used to be a silent one: the last thing in the
            ;; trace was an ordinary read, which is what a peer that
            ;; simply went away also leaves, so a malformed frame and a
            ;; vanished peer were the same picture.
            ;;
            ;; `answer-failed` NAMES ONE CAUSE, NOT THE ONLY ONE, and
            ;; which of them dominates is a property of the peer rather
            ;; than of this code -- a client sending nothing but
            ;; over-limit headers makes every one of these a take-frame!
            ;; failure with answer never reached, and one sending nothing
            ;; but zero-length frames makes every one of them the case
            ;; the name has in mind. Both raise inside the guard: a frame
            ;; whose header is well formed but whose body is too short to
            ;; hold a request, and a length past the limit, which
            ;; take-frame! refuses before answer is reached at all.
            ;;
            ;; A failed reply write is NOT among them, though it looks as
            ;; if it should be: tcp-write! is called with no completion
            ;; callback, so it reports an immediate failure by return
            ;; value and drops a later one, and nothing raises past the
            ;; guard. So read this line as "the pass raised", and do not
            ;; attribute it to the renderer without something else
            ;; saying so.
            (begin
              (trace! "close answer-failed rest=" (inbuf-length buf))
              (tcp-close! c))))))
    ;; BACK TO WAITING, so reading goes back on. WHAT HOLDS IS THAT NO
    ;; PARK IS ENTERED WITH READS OFF, AND THAT READS ARE OFF FOR THE
    ;; WHOLE OF A PASS -- a pass being the parse and the renders it runs,
    ;; which is the only stretch long enough for the back-pressure
    ;; argument above to need it. A pass entered from a receive turns
    ;; them off as its first act; a pass re-entered from a drained retry
    ;; does not need to, reading having never come back on since the
    ;; first. The paths that close instead release the handle, which ends
    ;; reading with it.
    ;;
    ;; NOT "reads are on exactly while parked", which this block claimed
    ;; in two earlier forms and is false in both directions. A receive
    ;; restores interrupts before running the arm it selected, so between
    ;; a wake and that first act reads are on while nothing is parked.
    ;; And the close arms -- timeout, EOF, error, and the already-expired
    ;; branch below -- run their trace with reads still on before closing.
    ;; Those stretches do no work that matters here, and are bounded so
    ;; long as tracing is; a blocking trace target makes them unbounded
    ;; and stops the worker outright, which the trace comment sets out.
    ;; The claim is scoped to a pass because that is the stretch the
    ;; argument actually rests on, not because the wider one was checked.
    ;;
    ;; SO ANYTHING ADDED BEFORE A CLOSE INHERITS NOTHING. The rule above
    ;; says nothing about work placed between a wake and its close, and
    ;; the traces sitting there are deliberate rather than covered.
    ;;
    ;; THREE PARKS, TWO ENABLING SITES: the delivery round in the close
    ;; branch starts its own before its receive, and this one covers
    ;; both receives below. A fourth wait needs an enabling site --
    ;; sharing this one if it sits beside those two, or bringing its own
    ;; if it sits where the round does. Not automatic either way, which
    ;; is the cost of the round; what makes it checkable is that every
    ;; receive here is reachable from one of the two.
    ;;
    ;; NO FLAG IS NEEDED, because both transitions are idempotent: libuv
    ;; answers a start on a stream that is already reading with
    ;; UV_EALREADY and a stop on one that is not reading with success, and
    ;; (igropyr libuv) discards both codes. So the first entry -- which
    ;; follows the tcp-read-start! the accept callback does when it hands
    ;; the connection to this process -- needs nothing to tell it apart
    ;; from a re-entry, and the one path that starts and then closes
    ;; rather than waiting (an already-expired deadline, just below) costs
    ;; a start that closing the handle undoes.
    (tcp-read-start! c)
    ;; EXPIRING HERE IS NOT THE CASE THE DELIVERY ROUND EXISTS FOR, and
    ;; that is the whole of why this path has none. The round pays back
    ;; time WE took: reads were off for the length of a render, so bytes
    ;; the peer sent in time could not reach us and an empty mailbox said
    ;; nothing about the peer. On this path reads were on for the entire
    ;; wait -- anything in flight would have arrived as tcp-data and woken
    ;; us -- so the mailbox being empty means what it appears to mean, and
    ;; a round would be an inactivity extension with nothing to justify
    ;; it. Adding one here would also not be capped by the same argument,
    ;; since no render bounds how often this path is reached.
    ;;
    ;; THE ARGUMENT ABOVE COVERS THE WAIT, NOT THE BRANCH THAT NEVER
    ;; WAITS. `left` can already be <= 0 here, and that close is reached
    ;; without entering a receive at all -- so "reads were on throughout"
    ;; is not true of it, and neither is the conclusion drawn from that.
    ;; It can discard a delivery we have already been handed: libuv hands
    ;; up a whole poll turn, so a second tcp-data can be sitting in the
    ;; mailbox while on-data works on the first; if that pass saw a
    ;; deadline still in the future it does not scan for queued bytes,
    ;; and the clock reaching the deadline between there and here closes
    ;; on a frame whose remaining bytes we hold. Narrow, but the same
    ;; shape as the defect the delivery round exists for, and left
    ;; standing here deliberately rather than by oversight.
    ;;
    ;; Both closes below say so, because an expiry decided here used to
    ;; leave no record at all: a connection would end with a normal read
    ;; as the last line and nothing after it, and telling this apart from
    ;; the peer vanishing took a round of elimination. `parked` is
    ;; MEASURED, not the timeout we asked for: a synchronous render on
    ;; another connection stops the whole runtime, so the wait can overrun
    ;; what was requested, and reporting the request instead would hide
    ;; exactly the overruns worth seeing.
    ;;
    ;; IT IS THIS INVOCATION'S WAIT, NOT THE CONNECTION'S. A half frame
    ;; can park most of its deadline, take a delivery at the last moment,
    ;; recurse, and reach the branch below with the deadline already
    ;; passed -- and that close prints 0 having listened for nearly the
    ;; whole window. So 0 means "this invocation did not wait", never
    ;; "we never waited"; summing a connection's waits needs the earlier
    ;; lines, which is why they are all printed rather than only the
    ;; last.
    (if (> (inbuf-length buf) 0)
        (let ((left (- (or since (+ (now-ms) partial-ms)) (now-ms))))
          (if (<= left 0)
              (begin
                (trace! "close idle-deadline rest=" (inbuf-length buf)
                        " parked=0")
                (tcp-close! c))
              (let ((t0 (now-ms)))
                (receive (after left
                           (trace! "close idle-deadline rest="
                                   (inbuf-length buf)
                                   " parked=" (- (now-ms) t0))
                           (tcp-close! c))
                  (`#(tcp-data ,bv) (on-data bv grace))
                  ;; where=parked: the peer ended while we were holding
                  ;; a half frame and waiting out its deadline, so it
                  ;; left bytes owed. Distinct from where=idle below,
                  ;; where nothing was owed and going away is ordinary.
                  (`#(tcp-eof)
                    (trace! "close eof where=parked rest="
                            (inbuf-length buf))
                    (tcp-close! c))
                  (`#(tcp-error ,e)
                    (trace! "close error where=parked rest="
                            (inbuf-length buf))
                    (tcp-close! c))))))
        (receive
          (`#(tcp-data ,bv) (on-data bv grace))
          ;; where=idle: nothing half delivered, so the peer ending here
          ;; is the ordinary way a connection finishes and this line is
          ;; the one that says so rather than leaving the reader to
          ;; infer it from a trace that simply stops.
          (`#(tcp-eof)
            (trace! "close eof where=idle rest=0")
            (tcp-close! c))
          (`#(tcp-error ,e)
            (trace! "close error where=idle rest=0")
            (tcp-close! c)))))

  ;; ONE message that libuv has already handed up, taken without waiting.
  ;; #t if there was one.
  ;;
  ;; ONE, not all of them, so that the announced length is checked
  ;; against the frame cap between every appended message rather than
  ;; after an unbounded run of them -- the same thing the ordinary path
  ;; gets by returning to the parser each time.
  ;;
  ;; THAT IS THE WHOLE REASON, and an earlier note here gave a second
  ;; one that cannot happen: that a peer which keeps sending would keep
  ;; a loop here fed indefinitely. It could not. This runs only after
  ;; on-data has stopped reading, so the connection produces no further
  ;; read callbacks; what can be drained is the finite chain already
  ;; delivered when the stop landed. The append and the recursion ARE
  ;; preemptible -- receive restores interrupts before running a matched
  ;; clause -- but being preemptible is not being refillable.
  (define (take-queued! buf)
    (receive (after 0 #f)
      (`#(tcp-data ,bv) (inbuf-append! buf bv) #t)))

  ;; Whole requests answered in order, for as long as they keep answering.
  ;; A client that pipelines gets its replies in the order it asked; the
  ;; pool never does, but a protocol that only works for one outstanding
  ;; request would fail obscurely for anything else that speaks it.
  ;; A frame that RAISES ends the loop and the connection -- whole at the
  ;; framing layer is not the same as answerable, a frame too short to
  ;; hold a request being the case that shows it -- so anything queued
  ;; behind it goes unanswered, and is abandoned with the buffer rather
  ;; than being skipped over.
  ;;
  ;; RAISES, not "fails": a render that never returns is not a failure
  ;; anything here can see. The guard at the caller waits on the same
  ;; thread, so a runaway builtin leaves the loop, the connection and
  ;; whatever is queued behind it in place indefinitely -- the wedged
  ;; worker the header describes, arriving through this door.
  ;;
  ;; And the buffer is not necessarily clear when a raise happens. It is
  ;; clear of the frame being ANSWERED, since take-frame! consumes before
  ;; answer runs; it is not clear when take-frame! is the one raising, on
  ;; a length past the limit, because nothing has been consumed at that
  ;; point. What holds either way is the part that matters: the close
  ;; that follows is what stops anything left in the buffer from being
  ;; mistaken for a partial tail and waited on -- the close, not the
  ;; consuming.
  ;;
  ;; ON THE PATHS THAT REACH IT. The failure arm records before it
  ;; closes, so a trace that BLOCKS INDEFINITELY stops the worker short
  ;; of the close, leaving the connection open with whatever is still
  ;; buffered -- which need not include the frame that failed: a frame
  ;; answer raises on was consumed before answer ran, whereas a length
  ;; take-frame! refuses is rejected before consuming anything, so what
  ;; stays is the bytes already received, which may be no more than the
  ;; four of the header -- and holding the one OS
  ;; thread, so every other
  ;; connection this worker serves stops with it. A trace that fails to
  ;; return by taking the process down instead is a different story: the
  ;; kernel closes the sockets on the way out. It is noted because the
  ;; sentence above would otherwise read as unconditional.
  ;;
  ;; TRACE FIRST BECAUSE NO CLOSE IN THE WORKER'S CONNECTION LOOP
  ;; PRECEDES ITS OWN RECORDING -- that loop and not this file, whose
  ;; caller-side closes carry no trace at all and never claimed to.
  ;; Narrower again than "the record cannot be lost", and between them
  ;; those two limits are the whole of what the ordering buys. Both
  ;; orderings have a window
  ;; between the two steps where the process can die. Dying after the
  ;; close, in the other ordering, leaves a connection that ended with
  ;; nothing said about it -- a close no line accounts for, which is the
  ;; thing these traces were added to abolish. Dying in this one leaves
  ;; no close either, and the exit closes the socket on its way out.
  ;;
  ;; IT DOES NOT MEAN A RECORD EXISTS. Death can land inside the trace
  ;; rather than after it, and a write that fails is swallowed where
  ;; tracing is turned off -- so this ordering can still reach the close
  ;; with nothing written. What it rules out is the close COMPLETING
  ;; while the attempt to record is still ahead of it.
  ;;
  ;; The cost is real and is not only the pathological case: the close
  ;; waits out whatever the trace takes, so a slow target -- a congested
  ;; or remote one, seconds rather than forever -- holds up the close
  ;; call by that much, and with it whatever end of the connection the
  ;; peer would have seen. Not always a FIN: after a reset there is
  ;; nothing left to deliver, and tcp-close! goes to uv_close rather
  ;; than a shutdown in any case. Blocking is the extreme of this delay,
  ;; not the only version of it.
  ;;
  ;; NOR IS THE DELAY THIS CONNECTION'S ALONE. The trace runs with
  ;; interrupts disabled on the thread that serves every connection, so
  ;; seconds spent writing one close record are seconds in which another
  ;; connection's request is not read and its render deadline can pass.
  ;; Paid anyway, because a silent close is the failure that costs a
  ;; reader a whole round of elimination -- but paid, not free, and the
  ;; bill is not confined to the connection being closed.
  ;; There was a version that stopped on
  ;; the tail's deadline, so that a peer queueing slow renders ahead of its
  ;; tail could not buy it a render apiece -- and it dropped requests: the
  ;; loop stopped with a COMPLETE frame still in the buffer, the caller
  ;; then treated that buffer as a partial tail and waited for bytes that
  ;; were never coming, and a legitimate request was never rendered, never
  ;; answered, and eventually closed on a deadline it had nothing to do
  ;; with. Silently dropping a request that arrived in time is worse than
  ;; the thing that guard was for, whose whole cost is renders the peer
  ;; asked for and paid for.
  ;;
  ;; What bounds a tail is the check AFTER this runs: a read that
  ;; completes nothing keeps the deadline it came in with, and that check
  ;; takes it -- see A DELIVERY ROUND BEFORE CLOSING (the expiry branch)
  ;; for when it closes and when it does not. Stated there and not
  ;; restated here: this note needs only that the tail has something
  ;; downstream backing it, and each retelling of the rule has been a
  ;; chance to overstate it. There was a check before this one instead,
  ;; and it refused whole frames that had arrived in time -- see the note
  ;; at the caller.
  (define (answer-all! c buf)
    (let loop ()
      (let ((f (take-frame! buf)))
        (when f
          (tcp-write! c (answer f) #f)
          (loop)))))

  (define (answer body)
    (let ((n (bytevector-length body)))
      (when (< n 6) (raise (qjs-err "short request frame")))
      (let ((id (bytevector-u32-ref body 0 (endianness big)))
            (fl (bytevector-u16-ref body 4 (endianness big))))
        (when (> (+ 6 fl) n) (raise (qjs-err "function-name length past the frame")))
        ;; THE REQUEST ID, so a reader can tie a connection to a request it
        ;; sent. Inferring which connection is which from "the one that
        ;; had not spoken yet" cannot tell a probe's connection from the
        ;; rival it starts alongside it.
        (trace! "answer id=" id)
        (let ((fn (utf8->string (bv-slice body 6 fl)))
              (json (utf8->string (bv-slice body (+ 6 fl) (- n 6 fl)))))
          ;; qjs-call/bytes never raises: it answers (values ok? bytes-or-text),
          ;; and a failed call has already rebuilt the engine
          (let-values (((ok s) (qjs-call/bytes fn json)))
            (if ok
                (encode-response id 0 s)
                (encode-response id 1 (string->utf8 s))))))))

  ;; ---- caller side: one connection ----------------------------------------

  ;; A reply is (ok . bytes) or (ok . text); anything that leaves the stream
  ;; unusable is a #(qjs-error ...) instead, which the pool recognizes.
  (define (reply-ok? r) (and (pair? r) (car r)))

  ;; Read one response, waiting only as long as this connection is willing
  ;; to. The deadline belongs HERE and not only to the caller: a worker
  ;; wedged in a runaway render never replies and never closes the socket,
  ;; so without it this process would wait forever and the pool would count
  ;; the connection busy for the life of the node.
  (define (read-response c buf deadline-ms ref id)
    (let ((f (take-frame! buf)))
      (if f
          ;; ONE request is outstanding, so one response is all there can
          ;; be. Bytes left over are the same desync the idle check refuses,
          ;; arriving by the other route: read past while this response was
          ;; being taken, they never appear as a message, and left in the
          ;; buffer the NEXT render finds a complete frame waiting before
          ;; its own answer can arrive and returns it -- a render that
          ;; succeeds with the previous exchange's leftovers.
          (begin
            (when (> (inbuf-length buf) 0)
              (raise (qjs-err "worker sent more than one response")))
            (decode-response f id))
          (let ((left (- deadline-ms (now-ms))))
            (if (<= left 0)
                (raise (qjs-err "render timed out"))
                (receive (after left (raise (qjs-err "render timed out")))
                  (`#(tcp-data ,bv) (inbuf-append! buf bv)
                    (read-response c buf deadline-ms ref id))
                  (`#(tcp-eof) (raise (qjs-err "worker closed the connection")))
                  (`#(tcp-error ,e) (raise (qjs-err (uv-strerror e))))
                  ;; A TEARDOWN HAS TO REACH US HERE. The pool sends pool-quit
                  ;; to reclaim a connection whose borrower died -- @kill
                  ;; discards winders, so the monitor is the only path back
                  ;; -- and a receive that matched only the socket left that
                  ;; message in the mailbox until the render deadline. The
                  ;; pool had marked the connection dying and had nothing to
                  ;; lend, so with a deadline set long enough to be worth
                  ;; setting (a minute), one killed caller took the pool out
                  ;; of service for a minute.
                  ;;
                  ;; Raising hands this to the same path a transport failure
                  ;; takes: reply, tell the pool, close, exit, be rebuilt.
                  (`#(pool-quit) (raise (qjs-err "connection shut down mid-render")))
                  ;; THE CALLER GAVE UP. Its deadline and this one are
                  ;; ordered only by a margin -- the caller's starts when it
                  ;; posts the request, ours when the request is written --
                  ;; so which fires first is a matter of degree, not of
                  ;; protocol. When the caller's does, it releases its lease
                  ;; and the pool is free to hand this connection to someone
                  ;; else while the worker is still rendering for nobody,
                  ;; and whatever it eventually writes lands in the middle
                  ;; of the next exchange.
                  ;;
                  ;; The worker cannot be told to stop and there is no
                  ;; knowing when it will finish, so the connection goes --
                  ;; which is what would have happened anyway had our own
                  ;; deadline been the one to fire.
                  ;;
                  ;; NOT COVERED BY A TEST, deliberately: producing this
                  ;; sequence on demand means making the caller's deadline
                  ;; expire before the connection's, and the library sets
                  ;; both -- the caller's is the larger by construction.
                  ;; What makes it reachable in production is that they are
                  ;; measured from different instants and the margin
                  ;; between them is finite, so a stall long enough (a
                  ;; blocking FFI call, a large collection) inverts them.
                  ;; Reaching it from a test would mean exposing the
                  ;; connection pid, which is worth less than the clause.
                  (`#(pool-request-cancel ,@ref ,from)
                    (raise (qjs-err "caller gave up on this render")))
                  ;; the pool itself died: nobody can adopt or reach us again
                  (`#(DOWN ,pid ,reason)
                    (raise (qjs-err "render pool went away mid-render")))))))))

  (define (decode-response body want-id)
    (let ((n (bytevector-length body)))
      (when (< n 5) (raise (qjs-err "short response frame")))
      (let ((id (bytevector-u32-ref body 0 (endianness big)))
            (status (bytevector-u8-ref body 4))
            (rest (bv-slice body 5 (- n 5))))
        ;; A frame for a request this connection is no longer waiting on is
        ;; not a reply, it is a desync -- and the one that survives being
        ;; read late, after the connection has gone back to the pool and
        ;; been lent to somebody else.
        (unless (= id want-id)
          (raise (qjs-err "worker answered a request we are not waiting on")))
        (case status
          ((0) (cons #t rest))
          ((1) (cons #f (utf8->string rest)))
          (else (raise (qjs-err "unknown response status")))))))

  ;; req is (fn . json)
  ;; The deadline is stamped BEFORE the request is encoded, not after.
  ;; Encoding is proportional to the props, so charging it to the margin
  ;; between this deadline and the caller's is charging it to the one
  ;; thing that keeps their order predictable.
  ;; The id is per connection and only has to distinguish THIS request from
  ;; the one before it on the same stream, so a counter is enough.
  ;; THE WRITE IS THE LINE. Everything above (tcp-write! …) failed with the
  ;; request still in this process; everything from it onward failed with
  ;; bytes possibly on the wire. That is the whole of what decides whether
  ;; the connection is kept, because retrying somewhere else only makes
  ;; sense when the failure had something to do with where it ran -- and a
  ;; failure this process can reproduce on its own is not changed by
  ;; handing it to another worker.
  ;;
  ;; The two local sites are not the same in character and are treated the
  ;; same on purpose: a request that cannot be encoded will fail identically
  ;; forever, while one that ran out of time before it was sent might well
  ;; succeed on a later attempt. Neither justifies discarding this
  ;; connection, which is what the kind governs; whether the CALLER retries
  ;; is the caller's to decide and it is told which happened.
  (define (render-on! c buf req render-ms ref id)
    (let* ((deadline (+ (now-ms) render-ms))
           ;; WHY it could not be encoded, not just that it could not.
           ;; encode-request raises with the reason -- a function name past
           ;; the length field, a request over the frame limit -- and this
           ;; used to replace all of them with one sentence that told the
           ;; caller nothing about the input it has to fix. The point of
           ;; answering a local failure to the caller is that the caller
           ;; can act on it.
           (frame-err #f)
           ;; LOCAL BY POSITION, whatever was raised. Encoding happens
           ;; before the write by construction, so anything that comes out
           ;; of it is local -- including a condition from below that
           ;; as-qjs-error would otherwise label transport by default. The
           ;; kind is decided here, where the position is known, rather
           ;; than trusted to every raise site inside encode-request.
           (frame (guard (e (#t (set! frame-err
                                      (qjs-local-err
                                        (qjs-error-text
                                          (as-qjs-error e "request"))))
                                #f))
                    (encode-request id (car req) (cdr req)))))
      (guard (e (#t (as-qjs-error e "render failed")))
        (unless frame
          (raise (or frame-err
                     (qjs-local-err "render request could not be encoded"))))
        ;; CHECKED AGAIN before the write. Encoding is proportional to the
        ;; props and the runtime can stall for longer than the whole
        ;; deadline, and sending a request we have already given up on
        ;; starts a render nobody will read -- on a worker that cannot be
        ;; told to stop.
        (when (>= (now-ms) deadline)
          (raise (qjs-local-err "render timed out before it was sent")))
        (tcp-write! c frame #f)
        (read-response c buf deadline ref id))))

  ;; An adopted connection watches its owner: the pool monitors its
  ;; connections and not the other way round, so a pool that died would
  ;; otherwise leave every connection running and holding an fd, with
  ;; nothing able to reach them. See the same note in (igropyr mysql).
  (define (serve-loop c buf notify render-ms max-id)
    (serve-loop* c buf notify render-ms max-id 0))

  (define (serve-loop* c buf notify render-ms max-id next-id)
    (receive
      (`#(DOWN ,pid ,reason)
        (if (and notify (eq? pid notify))
            (tcp-close! c)
            (serve-loop* c buf notify render-ms max-id next-id)))
      (`#(pool-request ,req ,ref ,from)
        (let ((r (render-on! c buf req render-ms ref next-id)))
          (cond
            ;; NOTHING LEFT THIS PROCESS, so there is nothing wrong with
            ;; this connection: no half-written frame, no reply owed, no
            ;; doubt about what the worker is doing -- it was never asked.
            ;; Retiring it here spent a reconnect to punish a connection
            ;; for the caller's argument, and under a caller that keeps
            ;; sending the same bad request it retired the pool one worker
            ;; at a time.
            ;;
            ;; The id does NOT advance: it exists to stop a reply to the
            ;; previous request being accepted as the answer to this one,
            ;; and no request went out under this one. Advancing would
            ;; leave a gap that means nothing on a stream whose ids are
            ;; only ever compared to the one outstanding.
            ((qjs-error-local? r)
             (send from (vector 'pool-reply ref r))
             (when notify (send notify (vector 'pool-idle self ref)))
             (serve-loop* c buf notify render-ms max-id next-id))
            ((qjs-error? r)
              (begin
          ;; THE POOL FIRST, then the caller. Telling the caller first
          ;; releases it, and its check-in can reach the pool before this
          ;; message does -- so the pool put a connection it was about to
          ;; be told was dead back into rotation and lent it to the next
          ;; borrower, whose statement went to a pid that then exited.
          ;; (The pool also refuses to re-lend a connection already marked
          ;; dying; both halves are needed, because that mark is what this
          ;; ordering makes arrive in time.)
          ;;
          ;; The cost of this order is a two-send window in which a kill
          ;; would leave the caller with no reply at all rather than a
          ;; duplicate one. That is a narrower window and a milder failure.
                (when notify (send notify (vector 'pool-conn-dead self)))
                (send from (vector 'pool-reply ref r))
                (tcp-close! c)))                   ; exit -> DOWN -> rebuild
            (else
              ;; SAME ORDER AS THE ERROR BRANCH ABOVE, and for the same
              ;; reason: when this answer is the connection's last, the
              ;; pool has to hear that before the caller is released, or
              ;; the caller's check-in gets there first and the pool lends
              ;; out a connection that is already exiting. Retiring also
              ;; means NOT reporting idle -- that is the message that puts
              ;; it back in rotation.
              ;;
              ;; The rule was stated twenty lines up and then not applied
              ;; here, which is how a rule kept as prose next to one of its
              ;; sites fails: deciding it before the reply is what makes it
              ;; hold at both.
              ;; ONE-BASED CAP, ZERO-BASED IDS. next-id is the id carried
              ;; by the answer being sent, and the first is 0, so the Nth
              ;; render is the one numbered N-1. Comparing the id to the
              ;; cap directly served N+1 -- invisible while the cap was
              ;; #xffffffff and a broken promise the moment it was a
              ;; number a caller chose.
              (let ((retiring (>= next-id (- max-id 1))))
                (when (and retiring notify)
                  ;; ON SCHEDULE, and it says so: a pool told only that a
                  ;; connection died treats a planned stand-down as a peer
                  ;; failure and backs off before rebuilding it.
                  (send notify (vector 'pool-conn-dead self 'retired)))
                (send from (vector 'pool-reply ref r))
                ;; the id ADVANCES: the next request must not be answerable
                ;; by a frame belonging to this one
                ;; RETIRED rather than wrapped. The field is u32, so an
                ;; unbounded counter eventually cannot be encoded at all --
                ;; about fifty days at a thousand renders a second, and
                ;; permanent for a lone connection, since nothing rebuilds
                ;; it. Wrapping fixes that and buys an ABA: a worker that
                ;; held on to an old response could replay it four billion
                ;; requests later against an id that now means something
                ;; else, and the check that exists to catch exactly that
                ;; would pass it. Ending the connection instead keeps ids
                ;; unique for the life of a stream, which is the property
                ;; the check is written on. It costs one reconnect per four
                ;; billion renders.
                (if retiring
                    (tcp-close! c)
                    (begin
                      (when notify (send notify (vector 'pool-idle self ref)))
                      (serve-loop* c buf notify render-ms max-id (+ next-id 1)))))))))
      ;; connpool-call sends this to whatever handle it was given when a call
      ;; times out; only a pool acts on it. Consumed here so it does not sit
      ;; in the mailbox slowing every later selective receive.
      (`#(pool-request-cancel ,ref ,from)
        (serve-loop* c buf notify render-ms max-id next-id))
      ;; a lone connection keeps no pool bookkeeping; answering is what
      ;; stops the request sitting here forever
      (`#(pool-stats ,ref ,from)
        (send from (vector 'pool-stats-reply ref #f))
        (serve-loop* c buf notify render-ms max-id next-id))
      (`#(pool-quit) (tcp-close! c))
      ;; Bytes arriving BETWEEN renders have no meaning in this protocol: a
      ;; worker speaks only when asked, and nothing is outstanding here.
      ;; They are evidence the stream is already out of step -- buffering
      ;; them would carry the desync into the next render's reply, and a
      ;; peer that dribbles forever would grow this buffer without bound.
      ;; Dropping the connection costs a rebuild; the pool does that anyway.
      (`#(tcp-data ,bv) (tcp-close! c))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; After reporting up, wait to be adopted. If nobody adopts -- the caller
  ;; timed out, or the pool was closed while we were connecting -- close and
  ;; exit rather than hold a socket nobody can reach.
  (define (await-adoption c buf notify render-ms max-id)
    (receive (after connect-timeout-ms (tcp-close! c))
      (`#(pool-adopt)
        (when notify (monitor notify))
        (serve-loop c buf notify render-ms max-id))
      (`#(pool-quit) (tcp-close! c))
      ;; likewise before adoption: nothing has been asked yet
      (`#(tcp-data ,bv) (tcp-close! c))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; Spawn a connection worker; it reports #(pool-up ,ref ,self ,status) to
  ;; report-to -- the ref lets the receiver ignore a stale report from an
  ;; earlier, timed-out attempt -- then waits to be adopted. Every failure
  ;; path closes the socket: the uv handle is freed only by tcp-close!, so
  ;; skipping it would leak one fd per retry.
  (define (start-connection host port render-ms max-id notify report-to ref)
    (spawn
      (lambda ()
        (define (report! status) (send report-to (vector 'pool-up ref self status)))
        (let ((started (guard (e (#t (as-qjs-error e "connect failed")))
                         (tcp-connect! host port self)
                         'ok)))
          (if (not (eq? started 'ok))
              (report! started)
              (receive (after connect-timeout-ms
                          (report! (qjs-err "connect timeout"))
                          ;; libuv resolves every connect exactly once: wait
                          ;; for the late callback and free the handle
                          (receive
                            (`#(tcp-connected ,c) (tcp-close! c))
                            (`#(tcp-connect-failed ,e) 'ok)))
                (`#(tcp-connect-failed ,e)
                  (report! (qjs-err (uv-strerror e))))
                (`#(tcp-connected ,c)
                  (tcp-read-start! c)
                  ;; no handshake: the connection is usable as soon as it is
                  ;; open, so there is nothing to authenticate before reporting
                  (report! 'ok)
                  (await-adoption c (make-inbuf) notify render-ms max-id))))))))

  ;; ---- caller side: the pool ----------------------------------------------

  ;; The handle carries its config because the deadlines are per-pool: two
  ;; pools of different things in one process do not share a timeout, and
  ;; the render path wants seconds where a database wants a minute.
  ;; pooled?: a POOL answers pool-checkout, a lone connection does not -- and
  ;; asking one for a lease is a wait that ends only in a timeout.
  (define-record-type (qjs-pool make-qjs-pool qjspool?)
    (fields handle cfg render-ms checkout-ms pooled?))

  (define (make-cfg render-ms checkout-ms)
    (make-connpool-cfg
      qjs-error?
      (qjs-err "render worker connection lost")
      (qjs-err "render pool closed")
      (qjs-err "render timed out")
      (qjs-err "no render worker available")
      "BEGIN"                       ; unused: a render is not a transaction
      ;; The CALLER waits longer than the connection does, so the connection's
      ;; own deadline is the one that fires: it can report the failure and
      ;; discard the wedged connection, where a caller-side timeout leaves
      ;; the connection sitting there believed to be busy.
      (+ render-ms 1000)
      checkout-ms))

  (define (endpoint-list who eps)
    (unless (and (list? eps) (pair? eps))
      (assertion-violation who "endpoints must be a non-empty list of (host . port)" eps))
    (for-each
      (lambda (e)
        (unless (and (pair? e) (string? (car e))
                     (integer? (cdr e)) (exact? (cdr e)) (> (cdr e) 0))
          (assertion-violation who "each endpoint must be (host . port)" e)))
      eps)
    eps)

  ;; How many renders one connection answers before it is retired. The
  ;; ceiling is not a policy choice: the id field is u32, so a counter that
  ;; kept going could not be encoded at all. There are 2^32 distinct ids
  ;; and the first is 0, so 2^32 requests fit exactly -- the ceiling is a
  ;; count, not the largest id, and reading it as the latter cost one
  ;; request per connection at every setting. A caller may set it lower to
  ;; recycle connections on a schedule of its own -- and a lower value is
  ;; the only way to reach the retirement path in a test, which is
  ;; otherwise four billion renders away.
  (define default-max-requests #x100000000)

  (define (opt-max-requests opts who)
    (let ((v (cond ((assq 'max-requests-per-connection opts) => cdr)
                   (else default-max-requests))))
      (unless (and (integer? v) (exact? v) (> v 0) (<= v default-max-requests))
        (assertion-violation who
          "max-requests-per-connection must be a positive exact integer no greater than #x100000000" v))
      v))

  (define (opt-ms opts key default who)
    (let ((v (cond ((assq key opts) => cdr) (else default))))
      (unless (and (integer? v) (exact? v) (> v 0))
        (assertion-violation who "timeout must be a positive exact integer (ms)" v))
      v))

  ;; A pool with one connection per endpoint. Options: (render-timeout-ms .
  ;; n) how long a render may take, (checkout-timeout-ms . n) how long a
  ;; caller waits for a free worker before being told there is none, and
  ;; (max-requests-per-connection . n) how many renders a connection
  ;; answers before it stands down and is rebuilt.
  ;;
  ;; Usable immediately: renders queue until the connections come up.
  (define (qjspool endpoints . rest)
    (let* ((opts (if (pair? rest) (car rest) '()))
           (eps (endpoint-list 'qjspool endpoints))
           (render-ms (opt-ms opts 'render-timeout-ms default-render-ms 'qjspool))
           (checkout-ms (opt-ms opts 'checkout-timeout-ms default-checkout-ms 'qjspool))
           (max-id (opt-max-requests opts 'qjspool))
           (cfg (make-cfg render-ms checkout-ms))
           (n (length eps))
           ;; Rebuilt connections rotate through the endpoints. The pool
           ;; hands out no slot identity, so this cannot pin a rebuild to
           ;; the endpoint that lost it; an uneven split costs latency
           ;; (a worker serializes whatever it is given) and nothing else.
           (next (box 0)))
      (make-qjs-pool
        (spawn
          (lambda ()
            (connpool-loop n
              (lambda (notify report-to ref)
                (let* ((i (unbox next))
                       (e (list-ref eps (modulo i n))))
                  (set-box! next (+ i 1))
                  (start-connection (car e) (cdr e) render-ms max-id
                                    notify report-to ref)))
              cfg)))
        cfg render-ms checkout-ms #t)))

  ;; One connection to one worker, with no pool behind it. Mainly for tests
  ;; and for a process that renders rarely: it has no queueing, no rebuild
  ;; and no statistics, and a dead worker makes it permanently useless.
  ;;
  ;; That last part is also its ceiling: ids are u32 and cannot wrap
  ;; without an ABA, so this handle stops working after 2^32 renders and
  ;; nothing brings it back. Refusing max-requests-per-connection below
  ;; makes the fast way of reaching that state noisy rather than silent;
  ;; it does not remove the ceiling, which is inherent to having no pool.
  (define (qjspool-connect host port . rest)
    (let* ((opts (if (pair? rest) (car rest) '()))
           (render-ms (opt-ms opts 'render-timeout-ms default-render-ms 'qjspool-connect))
           (checkout-ms (opt-ms opts 'checkout-timeout-ms default-checkout-ms
                                'qjspool-connect))
           ;; REFUSED HERE. A lone connection has no pool behind it, so
           ;; retiring one is not recycling, it is a handle that stops
           ;; working: nothing rebuilds it and every later render fails
           ;; for good. Accepting the option by symmetry with qjspool
           ;; would have been silent about that.
           (max-id (begin
                     (when (assq 'max-requests-per-connection opts)
                       (assertion-violation 'qjspool-connect
                         "max-requests-per-connection needs a pool to rebuild the connection; a lone connection cannot be recycled"
                         (cdr (assq 'max-requests-per-connection opts))))
                     default-max-requests))
           (cfg (make-cfg render-ms checkout-ms)))
      (connpool-drain-stale!)
      (let ((ref (gensym)))
        (start-connection host port render-ms max-id #f self ref)
        (receive (after (+ connect-timeout-ms 2000)
                    (raise (qjs-err "connect timeout")))
          (`#(pool-up ,@ref ,pid ,status)
            (if (eq? status 'ok)
                (begin (send pid (vector 'pool-adopt))
                       (make-qjs-pool pid cfg render-ms checkout-ms #f))
                (raise status)))))))

  (define (check-pool who p)
    (unless (qjspool? p)
      (assertion-violation who "not a render pool" p)))

  ;; -> (values ok? bytes-or-error-text). Deliberately the same contract as
  ;; qjs-call/bytes: ok with the HTML as UTF-8 bytes, or #f with the error
  ;; TEXT -- a JS throw, a timeout and a dead worker all arrive the same
  ;; way, so a caller that renders does not also have to supervise.
  (define (qjspool-render/bytes p fn props)
    (check-pool 'qjspool-render/bytes p)
    (unless (string? fn)
      (assertion-violation 'qjspool-render/bytes "function name must be a string" fn))
    (unless (string? props)
      (assertion-violation 'qjspool-render/bytes "props must be a JSON string" props))
    ;; as-qjs-error passes a #(qjs-error ...) through unchanged and wraps
    ;; anything else, so one branch covers a raised transport error and a
    ;; condition from below alike -- and both come out as TEXT, which is
    ;; what the contract promises.
    (guard (e (#t (values #f (qjs-error-text (as-qjs-error e "render failed")))))
      (let ((r (render-through p (cons fn props))))
        ;; A local failure arrives as a VALUE rather than a raise -- see
        ;; render-through for why it must not escape the lease -- so it is
        ;; unwrapped here. Both kinds reach the caller as the same
        ;; (values #f text) they always did.
        (if (qjs-error? r)
            (values #f (qjs-error-text r))
            (values (car r) (cdr r))))))

  ;; TWO deadlines, because a render has two ways to be slow and they call
  ;; for different answers. Waiting for a free worker means the pool is
  ;; saturated and nothing is wrong: give up early and shed the request,
  ;; rather than hold an http worker for the length of a render that has
  ;; not started. Waiting for the render itself is the render being slow.
  ;;
  ;; Borrowing the worker also matches what it is: single-threaded, one
  ;; engine, one render at a time. Sending renders as queued statements
  ;; would let the pool interleave them onto a connection that is already
  ;; busy from its own point of view.
  ;;
  ;; A lone connection has no pool to lease from, so it takes the direct
  ;; path; there is nothing to be saturated.
  (define (render-through p req)
    (let ((h (qjs-pool-handle p)) (cfg (qjs-pool-cfg p)))
      (if (qjs-pool-pooled? p)
          ;; #t: an escape here means the render may still be running on the
          ;; worker, so the connection goes back broken. Handing it back
          ;; clean lets the pool lend a worker that is still busy with the
          ;; request its caller has already abandoned.
          ;; A LOCAL FAILURE RETURNS RATHER THAN ESCAPING, and that is the
          ;; whole of what keeps the connection. connpool-call RAISES every
          ;; error, and an escape from this thunk is exactly what the #t
          ;; above turns into pool-checkin-broken -- so a request refused
          ;; before it was ever written still had its connection discarded
          ;; by the layer above, no matter what the serve loop decided.
          ;; (Measured before this line existed: six local failures, six
          ;; connections discarded and six reconnects, while the serve loop
          ;; was already keeping every one of them.)
          ;;
          ;; Transport errors must go on escaping: for those the #t is
          ;; right, because the render may still be running on the worker.
          (connpool-lease h
            (lambda (conn)
              (guard (e ((qjs-error-local? e) e))
                (connpool-call conn req cfg)))
            cfg #t)
          (guard (e ((qjs-error-local? e) e))
            (connpool-call h req cfg)))))

  ;; the same, decoded to a string on success
  (define (qjspool-render p fn props)
    (let-values (((ok v) (qjspool-render/bytes p fn props)))
      (if ok (values #t (utf8->string v)) (values #f v))))

  ;; The longest a render can take before it gives up: waiting for a free
  ;; worker, then rendering. A coordinator that waits on somebody else's
  ;; render (single-flight, say) has to allow at least this, or it times
  ;; out mid-render and starts the herd it was there to prevent.
  (define (qjspool-timeout-ms p)
    (check-pool 'qjspool-timeout-ms p)
    (+ (if (qjs-pool-pooled? p) (qjs-pool-checkout-ms p) 0)
       (qjs-pool-render-ms p) 1000))

  ;; The pool's own numbers. A render is a LEASE, so it is counted under
  ;; `checkouts`, and `checkout-wait-ms-*` is the time spent waiting for a
  ;; free worker -- the number that says whether to run more of them.
  ;;
  ;; `queries` and `query-ms-*` stay ZERO here, and that is not a gap in
  ;; the bookkeeping: the pool hands the worker over and the render's reply
  ;; goes straight from the connection to the caller, so the pool never
  ;; sees it. Render DURATION therefore has to be measured at the call
  ;; site; nothing in the pool is in a position to know it.
  (define (qjspool-stats p)
    (check-pool 'qjspool-stats p)
    (connpool-stats (qjs-pool-handle p)))

  (define (qjspool-close! p)
    (check-pool 'qjspool-close! p)
    (connpool-close! (qjs-pool-handle p)))
)
