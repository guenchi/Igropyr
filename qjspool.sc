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
;;; A JS error is a NORMAL response and the connection stays usable; only a
;;; malformed or oversized frame is a transport failure, and that discards
;;; the connection -- a stream whose framing is in doubt cannot be trusted
;;; with the next reply.
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
  ;; Transport only. A JS error is not one of these: it comes back as an
  ;; ordinary reply, because the connection is still perfectly good.
  (define (qjs-err msg) (vector 'qjs-error msg))
  (define (qjs-error? r) (and (vector? r) (eq? (vector-ref r 0) 'qjs-error)))
  (define (qjs-error-text r) (vector-ref r 1))
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
  (define (trace! . parts)
    (let ((p (trace-port)))
      (when p
        (display "c" p) (display (process-id self) p) (display " " p)
        (for-each (lambda (x) (display x p)) parts)
        (newline p)
        (flush-output-port p))))

  (define (qjs-worker-serve! host port bundle . rest)
    (let* ((qopts (if (pair? rest) (car rest) '()))
           (partial-ms (cond ((assq 'partial-frame-ms qopts) => cdr)
                             (else default-partial-frame-ms)))
           (trace (cond ((assq 'trace-file qopts) => cdr) (else #f))))
      (unless (and (integer? partial-ms) (exact? partial-ms) (> partial-ms 0))
        (assertion-violation 'qjs-worker-serve!
          "partial-frame-ms must be a positive exact integer" partial-ms))
      (when (string? trace)
        (trace-port (open-file-output-port trace
                                           (file-options no-fail no-truncate append)
                                           (buffer-mode line)
                                           (native-transcoder))))
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
    (worker-conn-loop* c buf partial-ms #f))

  ;; `since` is the ABSOLUTE deadline of the frame currently half delivered,
  ;; or #f when nothing is. Re-arming a fresh timeout on every arrival made
  ;; this an inactivity timer, and an inactivity timer bounds nothing here:
  ;; a peer sending one byte just under the interval keeps the same half
  ;; frame -- and its process, its descriptor and most of a frame's worth of
  ;; buffer -- alive indefinitely. The deadline is taken once, when the
  ;; buffer stops being empty, and further bytes shorten the wait rather
  ;; than renew it. It is also re-checked after answering, because the
  ;; renders in between are synchronous and nothing was counting during
  ;; them.
  (define (worker-conn-loop* c buf partial-ms since)
    (define (on-data bv)
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
      ;; never completes a frame: it consumes nothing, keeps its original
      ;; deadline, and is closed by the check BELOW on the very same read.
      ;; What the check up here changed was only the case where the frame
      ;; IS whole -- a real request, refused.
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
      ;; with nobody able to look at it -- so the rest of that delivery is
      ;; taken below before any decision, and a peer that has sent nothing
      ;; further has nothing to take.
      (let retry ()
       (let ((late? (and since (>= (now-ms) since)))
            (before (inbuf-length buf)))
        (trace! "read buffered=" before
                " since=" (or since "-")
                " now=" (now-ms)
                " late=" (if late? "1" "0"))
        (if (guard (e (#t #f)) (answer-all! c buf) #t)
            (let* ((rest (inbuf-length buf))
                   ;; A FRAME WAS CONSUMED, so whatever is left over is a
                   ;; DIFFERENT half frame and gets a window of its own.
                   ;;
                   ;; WHICH BOUNDS THE FRAME, NOT THE CONNECTION. A peer
                   ;; that appends one cheap whole frame ahead of its tail
                   ;; each window renews forever, and it costs it a cheap
                   ;; render rather than the slow one an earlier note here
                   ;; assumed. Its resources stay bounded -- one process,
                   ;; one descriptor, at most the frame cap of buffer --
                   ;; but its lifetime does not, and nothing on this side
                   ;; caps it: max-requests-per-connection is enforced by
                   ;; the caller's connection, never by this reader.
                   ;; Keying the reset on "the buffer emptied" instead meant
                   ;; a peer that always keeps a partial tail -- which is
                   ;; what pipelining looks like -- was closed at the first
                   ;; frame's deadline however many complete frames it had
                   ;; delivered in between. Our own client never pipelines,
                   ;; but answer-all! exists for clients that do.
                   (consumed (< rest before))
                   (deadline (cond ((= rest 0) #f)
                                   ((or consumed (not since))
                                    (+ (now-ms) partial-ms))
                                   (else since))))
              (cond
                ((= rest 0) (worker-conn-loop* c buf partial-ms #f))
                ;; THE REST OF THE SAME DELIVERY, before deciding against
                ;; it. libuv hands up at most 64KiB per callback, so a
                ;; request sent whole and in time still arrives in
                ;; pieces; the first completes no frame, and closing on it
                ;; threw away a request that was never late. Taking what
                ;; is already queued tells that apart from a peer still
                ;; owing us bytes, which has nothing queued and is closed
                ;; on the deadline it had.
                ((and late? (not consumed) (drain-queued! buf))
                 (trace! "drained rest=" rest) (retry))
                ((>= (now-ms) deadline)
                 (trace! "close deadline rest=" rest
                         " consumed=" (if consumed "1" "0")
                         " late=" (if late? "1" "0"))
                 (tcp-close! c))
                (else (worker-conn-loop* c buf partial-ms deadline))))
            (tcp-close! c)))))
    (if (> (inbuf-length buf) 0)
        (let ((left (- (or since (+ (now-ms) partial-ms)) (now-ms))))
          (if (<= left 0)
              (tcp-close! c)
              (receive (after left (tcp-close! c))
                (`#(tcp-data ,bv) (on-data bv))
                (`#(tcp-eof) (tcp-close! c))
                (`#(tcp-error ,e) (tcp-close! c)))))
        (receive
          (`#(tcp-data ,bv) (on-data bv))
          (`#(tcp-eof) (tcp-close! c))
          (`#(tcp-error ,e) (tcp-close! c)))))

  ;; Whatever libuv has already handed up, taken without waiting. #t if
  ;; anything was there. This is not a read: it cannot wait, so it can
  ;; only collect what was delivered while the worker was busy elsewhere.
  (define (drain-queued! buf)
    (let loop ((got #f))
      (receive (after 0 got)
        (`#(tcp-data ,bv) (inbuf-append! buf bv) (loop #t)))))

  ;; Every whole request the buffer holds, answered in order. A client that
  ;; pipelines gets its replies in the order it asked; the pool never does,
  ;; but a protocol that only works for one outstanding request would fail
  ;; obscurely for anything else that speaks it.
  ;; EVERY complete frame is answered. There was a version that stopped on
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
  ;; What bounds a tail is the check AFTER this runs: a read that completes
  ;; nothing keeps the deadline it came in with and is closed on that same
  ;; read. There was a check before this one instead, and it refused whole
  ;; frames that had arrived in time -- see the note at the caller.
  (define (answer-all! c buf)
    (let loop ()
      (let ((f (take-frame! buf)))
        (when f
          (tcp-write! c (answer f) #f)
          (loop)))))

  (define (answer body)
    (trace! "answer")
    (let ((n (bytevector-length body)))
      (when (< n 6) (raise (qjs-err "short request frame")))
      (let ((id (bytevector-u32-ref body 0 (endianness big)))
            (fl (bytevector-u16-ref body 4 (endianness big))))
        (when (> (+ 6 fl) n) (raise (qjs-err "function-name length past the frame")))
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
  (define (render-on! c buf req render-ms ref id)
    (let ((deadline (+ (now-ms) render-ms))
          (frame (guard (e (#t #f)) (encode-request id (car req) (cdr req)))))
      (guard (e (#t (as-qjs-error e "render failed")))
        (unless frame (raise (qjs-err "render request could not be encoded")))
        ;; CHECKED AGAIN before the write. Encoding is proportional to the
        ;; props and the runtime can stall for longer than the whole
        ;; deadline, and sending a request we have already given up on
        ;; starts a render nobody will read -- on a worker that cannot be
        ;; told to stop.
        (when (>= (now-ms) deadline)
          (raise (qjs-err "render timed out before it was sent")))
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
          (if (qjs-error? r)
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
                (tcp-close! c))                    ; exit -> DOWN -> rebuild
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
                      (serve-loop* c buf notify render-ms max-id (+ next-id 1))))))))
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
        (values (car r) (cdr r)))))

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
          (connpool-lease h (lambda (conn) (connpool-call conn req cfg)) cfg #t)
          (connpool-call h req cfg))))

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
