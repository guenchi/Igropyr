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
;;; one request, whose work happens somewhere else. (igropyr sqlpool)
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
;;;   request    u32be n | u16be fnlen | fn utf8 | props json utf8
;;;   response   u32be n | u8 status   | body
;;;              status 0 = the render's HTML, 1 = the JS error text.
;;;
;;; A JS error is a NORMAL response and the connection stays usable; only a
;;; malformed or oversized frame is a transport failure, and that discards
;;; the connection -- a stream whose framing is in doubt cannot be trusted
;;; with the next reply.

(library (igropyr qjspool)
  (export qjs-worker-serve!
          qjspool qjspool-connect qjspool?
          qjspool-render qjspool-render/bytes
          qjspool-timeout-ms qjspool-stats qjspool-close!)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr sqlpool)
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

  (define (encode-request fn json)
    (let* ((f (string->utf8 fn)) (j (string->utf8 json))
           (fl (bytevector-length f)) (jl (bytevector-length j))
           (n (+ 2 fl jl)))
      ;; refused HERE rather than sent: the length field cannot carry it, and
      ;; a truncated name would ask the worker to render a different function
      (when (> fl 65535)
        (raise (qjs-err "render function name too long")))
      (when (> n max-frame)
        (raise (qjs-err "render request larger than the frame limit")))
      (let ((bv (make-bytevector (+ 4 n))))
        (bytevector-u32-set! bv 0 n (endianness big))
        (bytevector-u16-set! bv 4 fl (endianness big))
        (bytevector-copy! f 0 bv 6 fl)
        (bytevector-copy! j 0 bv (+ 6 fl) jl)
        bv)))

  (define (encode-response status body)
    (let ((n (+ 1 (bytevector-length body))))
      (if (> n max-frame)
          ;; Our own output must stay inside what the peer will accept, or a
          ;; successful render becomes a transport error that discards a
          ;; healthy connection. Reported as a JS-level failure instead.
          (encode-response 1 (string->utf8 "render output exceeds the frame limit"))
          (let ((bv (make-bytevector (+ 4 n))))
            (bytevector-u32-set! bv 0 n (endianness big))
            (bytevector-u8-set! bv 4 status)
            (bytevector-copy! body 0 bv 5 (bytevector-length body))
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
  (define (qjs-worker-serve! host port bundle . rest)
    (let ((qopts (if (pair? rest) (car rest) '())))
      (qjs-boot! bundle qopts)
      (tcp-listen! host port 128
        (lambda (c)
          ;; libuv callback context: spawn + register only, no yielding
          (let ((pid (spawn (lambda () (worker-conn-loop c (make-inbuf))))))
            (conn-set-owner! c pid)
            (tcp-read-start! c))))))

  (define (worker-conn-loop c buf)
    (receive
      (`#(tcp-data ,bv)
        (inbuf-append! buf bv)
        ;; a framing error is not recoverable on this connection: we no
        ;; longer know where the next request starts
        (if (guard (e (#t #f)) (answer-all! c buf) #t)
            (worker-conn-loop c buf)
            (tcp-close! c)))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; Every whole request the buffer holds, answered in order. A client that
  ;; pipelines gets its replies in the order it asked; the pool never does,
  ;; but a protocol that only works for one outstanding request would fail
  ;; obscurely for anything else that speaks it.
  (define (answer-all! c buf)
    (let loop ()
      (let ((f (take-frame! buf)))
        (when f
          (tcp-write! c (answer f) #f)
          (loop)))))

  (define (answer body)
    (let ((n (bytevector-length body)))
      (when (< n 2) (raise (qjs-err "short request frame")))
      (let ((fl (bytevector-u16-ref body 0 (endianness big))))
        (when (> (+ 2 fl) n) (raise (qjs-err "function-name length past the frame")))
        (let ((fn (utf8->string (bv-slice body 2 fl)))
              (json (utf8->string (bv-slice body (+ 2 fl) (- n 2 fl)))))
          ;; qjs-call/bytes never raises: it answers (values ok? bytes-or-text),
          ;; and a failed call has already rebuilt the engine
          (let-values (((ok s) (qjs-call/bytes fn json)))
            (if ok
                (encode-response 0 s)
                (encode-response 1 (string->utf8 s))))))))

  ;; ---- caller side: one connection ----------------------------------------

  ;; A reply is (ok . bytes) or (ok . text); anything that leaves the stream
  ;; unusable is a #(qjs-error ...) instead, which the pool recognizes.
  (define (reply-ok? r) (and (pair? r) (car r)))

  ;; Read one response, waiting only as long as this connection is willing
  ;; to. The deadline belongs HERE and not only to the caller: a worker
  ;; wedged in a runaway render never replies and never closes the socket,
  ;; so without it this process would wait forever and the pool would count
  ;; the connection busy for the life of the node.
  (define (read-response c buf deadline-ms)
    (let ((f (take-frame! buf)))
      (if f
          (decode-response f)
          (let ((left (- deadline-ms (now-ms))))
            (if (<= left 0)
                (raise (qjs-err "render timed out"))
                (receive (after left (raise (qjs-err "render timed out")))
                  (`#(tcp-data ,bv) (inbuf-append! buf bv)
                    (read-response c buf deadline-ms))
                  (`#(tcp-eof) (raise (qjs-err "worker closed the connection")))
                  (`#(tcp-error ,e) (raise (qjs-err (uv-strerror e))))))))))

  (define (decode-response body)
    (let ((n (bytevector-length body)))
      (when (< n 1) (raise (qjs-err "short response frame")))
      (let ((status (bytevector-u8-ref body 0))
            (rest (bv-slice body 1 (- n 1))))
        (case status
          ((0) (cons #t rest))
          ((1) (cons #f (utf8->string rest)))
          (else (raise (qjs-err "unknown response status")))))))

  ;; req is (fn . json)
  (define (render-on! c buf req render-ms)
    (guard (e (#t (as-qjs-error e "render failed")))
      (tcp-write! c (encode-request (car req) (cdr req)) #f)
      (read-response c buf (+ (now-ms) render-ms))))

  ;; An adopted connection watches its owner: the pool monitors its
  ;; connections and not the other way round, so a pool that died would
  ;; otherwise leave every connection running and holding an fd, with
  ;; nothing able to reach them. See the same note in (igropyr mysql).
  (define (serve-loop c buf notify render-ms)
    (receive
      (`#(DOWN ,pid ,reason)
        (if (and notify (eq? pid notify))
            (tcp-close! c)
            (serve-loop c buf notify render-ms)))
      (`#(db-query ,req ,ref ,from)
        (let ((r (render-on! c buf req render-ms)))
          (send from (vector 'db-reply ref r))
          (if (qjs-error? r)
              (begin
                (when notify (send notify (vector 'db-conn-dead self)))
                (tcp-close! c))                    ; exit -> DOWN -> rebuild
              (begin
                (when notify (send notify (vector 'db-idle self)))
                (serve-loop c buf notify render-ms)))))
      ;; sql-query sends this to whatever handle it was given when a call
      ;; times out; only a pool acts on it. Consumed here so it does not sit
      ;; in the mailbox slowing every later selective receive.
      (`#(db-query-cancel ,ref ,from) (serve-loop c buf notify render-ms))
      ;; a lone connection keeps no pool bookkeeping; answering is what
      ;; stops the request sitting here forever
      (`#(db-stats ,ref ,from)
        (send from (vector 'db-stats-reply ref #f))
        (serve-loop c buf notify render-ms))
      (`#(db-quit) (tcp-close! c))
      (`#(tcp-data ,bv)                            ; stray data between renders
        (inbuf-append! buf bv)
        (serve-loop c buf notify render-ms))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; After reporting up, wait to be adopted. If nobody adopts -- the caller
  ;; timed out, or the pool was closed while we were connecting -- close and
  ;; exit rather than hold a socket nobody can reach.
  (define (await-adoption c buf notify render-ms)
    (receive (after connect-timeout-ms (tcp-close! c))
      (`#(db-adopt)
        (when notify (monitor notify))
        (serve-loop c buf notify render-ms))
      (`#(db-quit) (tcp-close! c))
      (`#(tcp-data ,bv) (inbuf-append! buf bv) (await-adoption c buf notify render-ms))
      (`#(tcp-eof) (tcp-close! c))
      (`#(tcp-error ,e) (tcp-close! c))))

  ;; Spawn a connection worker; it reports #(db-up ,ref ,self ,status) to
  ;; report-to -- the ref lets the receiver ignore a stale report from an
  ;; earlier, timed-out attempt -- then waits to be adopted. Every failure
  ;; path closes the socket: the uv handle is freed only by tcp-close!, so
  ;; skipping it would leak one fd per retry.
  (define (start-connection host port render-ms notify report-to ref)
    (spawn
      (lambda ()
        (define (report! status) (send report-to (vector 'db-up ref self status)))
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
                  (await-adoption c (make-inbuf) notify render-ms))))))))

  ;; ---- caller side: the pool ----------------------------------------------

  ;; The handle carries its config because the deadlines are per-pool: two
  ;; pools of different things in one process do not share a timeout, and
  ;; the render path wants seconds where a database wants a minute.
  (define-record-type (qjs-pool make-qjs-pool qjspool?)
    (fields handle cfg render-ms))

  (define (make-cfg render-ms checkout-ms)
    (make-sql-cfg
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

  (define (opt-ms opts key default who)
    (let ((v (cond ((assq key opts) => cdr) (else default))))
      (unless (and (integer? v) (exact? v) (> v 0))
        (assertion-violation who "timeout must be a positive exact integer (ms)" v))
      v))

  ;; A pool with one connection per endpoint. Options: (render-timeout-ms .
  ;; n) how long a render may take, (checkout-timeout-ms . n) how long a
  ;; caller waits for a free worker before being told there is none.
  ;;
  ;; Usable immediately: renders queue until the connections come up.
  (define (qjspool endpoints . rest)
    (let* ((opts (if (pair? rest) (car rest) '()))
           (eps (endpoint-list 'qjspool endpoints))
           (render-ms (opt-ms opts 'render-timeout-ms default-render-ms 'qjspool))
           (checkout-ms (opt-ms opts 'checkout-timeout-ms default-checkout-ms 'qjspool))
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
            (sql-pool-loop n
              (lambda (notify report-to ref)
                (let* ((i (unbox next))
                       (e (list-ref eps (modulo i n))))
                  (set-box! next (+ i 1))
                  (start-connection (car e) (cdr e) render-ms
                                    notify report-to ref)))
              cfg)))
        cfg render-ms)))

  ;; One connection to one worker, with no pool behind it. Mainly for tests
  ;; and for a process that renders rarely: it has no queueing, no rebuild
  ;; and no statistics, and a dead worker makes it permanently useless.
  (define (qjspool-connect host port . rest)
    (let* ((opts (if (pair? rest) (car rest) '()))
           (render-ms (opt-ms opts 'render-timeout-ms default-render-ms 'qjspool-connect))
           (checkout-ms (opt-ms opts 'checkout-timeout-ms default-checkout-ms
                                'qjspool-connect))
           (cfg (make-cfg render-ms checkout-ms)))
      (sql-drain-stale!)
      (let ((ref (gensym)))
        (start-connection host port render-ms #f self ref)
        (receive (after (+ connect-timeout-ms 2000)
                    (raise (qjs-err "connect timeout")))
          (`#(db-up ,@ref ,pid ,status)
            (if (eq? status 'ok)
                (begin (send pid (vector 'db-adopt))
                       (make-qjs-pool pid cfg render-ms))
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
      (let ((r (sql-query (qjs-pool-handle p) (cons fn props) (qjs-pool-cfg p))))
        (values (car r) (cdr r)))))

  ;; the same, decoded to a string on success
  (define (qjspool-render p fn props)
    (let-values (((ok v) (qjspool-render/bytes p fn props)))
      (if ok (values #t (utf8->string v)) (values #f v))))

  ;; the caller-side deadline, so a coordinator that waits on a render
  ;; (single-flight, say) can wait at least as long as the render may take
  (define (qjspool-timeout-ms p)
    (check-pool 'qjspool-timeout-ms p)
    (+ (qjs-pool-render-ms p) 1000))

  (define (qjspool-stats p)
    (check-pool 'qjspool-stats p)
    (sql-pool-stats (qjs-pool-handle p)))

  (define (qjspool-close! p)
    (check-pool 'qjspool-close! p)
    (sql-close! (qjs-pool-handle p)))
)
