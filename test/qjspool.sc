#!chezscheme
;;; (igropyr qjspool) -- renders served by worker PROCESSES.
;;;
;;; What this has to prove is one thing: a render that never returns costs
;;; the caller a deadline and nothing else. The same bundle is used both
;;; ways in the last check -- once through a worker process, once through
;;; the in-process engine -- with a ticker running alongside. Out of
;;; process the ticker keeps ticking; in process it does not tick at all,
;;; which is the whole reason this library exists.
;;;
;;; Also covered: a render round trip, a JS throw arriving as an ordinary
;;; failed reply that leaves the connection usable, an unknown function,
;;; pool statistics, and a render against a worker that is not there.
;;;
;;; SHIM-GATED like test/quickjs.sc: skips when no stock libquickjs is
;;; present, because the worker process cannot boot an engine without one.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr qjspool)
        (only (igropyr ssr) make-ssr ssr-render ssr-try-render ssr-invalidate! ssr-stats)
        (only (igropyr quickjs) qjs-boot! qjs-call/bytes))

;; (igropyr quickjs) is the pure-Scheme binding: it needs a stock shared
;; libquickjs. Gate on that so run-all stays green on hosts without QuickJS.
(define (quickjs-present?)
  (or (let ((e (getenv "IGROPYR_LIBQUICKJS_SO"))) (and e (> (string-length e) 0) (file-exists? e)))
      (file-exists? "libquickjs.dylib") (file-exists? "libquickjs.so")
      (file-exists? "/opt/homebrew/lib/quickjs/libquickjs.dylib")
      (file-exists? "/usr/local/lib/libquickjs.so")
      (file-exists? "/usr/local/lib/libquickjs.so.0")
      (file-exists? "libqjs.dylib") (file-exists? "libqjs.so")
      (file-exists? "/usr/local/lib/libqjs.so")
      (file-exists? "/usr/local/lib/libqjs.so.0")
      (file-exists? "/opt/homebrew/lib/libqjs.dylib")
      (file-exists? "/usr/lib/libqjs.so")
      (file-exists? "/usr/local/lib/quickjs/libquickjs.so")
      (file-exists? "/usr/lib/libquickjs.so")
      (file-exists? "/usr/lib/quickjs/libquickjs.so")))

(unless (quickjs-present?)
  (display "qjspool: no stock libquickjs found, test skipped\n") (exit 0))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c) (if c (ok label) (fail label)))

(define bundle-path "/tmp/igropyr-qjspool-bundle.js")
;; N counts renders IN THE WORKER, so a cache hit is provable from here:
;; on a hit the counter must not have advanced, which no amount of
;; inspecting the caller's own bookkeeping could show.
(define bundle "
var N = 0;
function hello(j){ var p = JSON.parse(j); return '<h1>' + p.name + '</h1>'; }
function counted(j){ N++; var p = JSON.parse(j); return '<p>' + p.t + '</p>'; }
function count(j){ return String(N); }
function boom(j){ throw new Error('render blew up'); }
function spin(j){ for(;;){} }
// slower than a short partial-frame window on purpose: a render is a
// synchronous call that stops the whole worker, so this is what a tail's
// deadline gets spent on.
function slow(j){ var t = Date.now(); while (Date.now() - t < 700) {} return 'S'; }
")

(define good-port 19731)
;; its own worker: a window far shorter than one render, which is what
;; makes a carried-in tail's deadline pass DURING a render rather than
;; between reads
(define carry-port 19734)
(define spin-port 19732)
(define half-port 19733)

(define (write-bundle!)
  (when (file-exists? bundle-path) (delete-file bundle-path))
  (call-with-output-file bundle-path (lambda (p) (display bundle p))))

(define (pid-file name) (string-append "/tmp/igropyr-qjsw-" name ".pid"))

;; a request frame, built here rather than through the pool: what these
;; probes need is control over where the byte boundaries fall, which the
;; pool by construction never gives (it writes one whole frame per read).
(define (qframe id fn json)
  (let* ((f (string->utf8 fn)) (j (string->utf8 json))
         (fl (bytevector-length f)) (jl (bytevector-length j))
         (n (+ 4 2 fl jl))
         (bv (make-bytevector (+ 4 n))))
    (bytevector-u32-set! bv 0 n (endianness big))
    (bytevector-u32-set! bv 4 id (endianness big))
    (bytevector-u16-set! bv 8 fl (endianness big))
    (bytevector-copy! f 0 bv 10 fl)
    (bytevector-copy! j 0 bv (+ 10 fl) jl)
    bv))

(define (bv-append a b)
  (let ((r (make-bytevector (+ (bytevector-length a) (bytevector-length b)))))
    (bytevector-copy! a 0 r 0 (bytevector-length a))
    (bytevector-copy! b 0 r (bytevector-length a) (bytevector-length b))
    r))

;; REPLIES ARE COUNTED AS FRAMES, never as tcp-data messages: two replies
;; written back to back usually arrive in one read, so a message count
;; says one and is wrong about it.
(define (count-frames acc)
  (let ((n (bytevector-length acc)))
    (let scan ((i 0) (k 0))
      (if (> (+ i 4) n)
          k
          (let ((len (bytevector-u32-ref acc i (endianness big))))
            (if (> (+ i 4 len) n) k (scan (+ i 4 len) (+ k 1))))))))

;; Backgrounded, because `system` blocks the ONE OS thread until the child
;; exits -- a foreground worker would deadlock the test against itself.
;; The pid is recorded rather than matched by name later: pkill -f does not
;; match reliably in every sandbox, and a leaked worker holds its port for
;; the next run.
(define (spawn-worker! name port timeout-ms . partial)
  (system (string-append "scheme --script igropyr/qjs-worker.sc 127.0.0.1 "
                         (number->string port) " " bundle-path
                         " timeout-ms=" (number->string timeout-ms)
                         ;; short enough to be observable: the default is
                         ;; half a minute, which is right in production and
                         ;; useless in a test
                         " partial-frame-ms="
                         (number->string (if (pair? partial) (car partial) 1200))
                         " >/dev/null 2>&1 & echo $! > " (pid-file name))))

(define (kill-worker! name)
  (system (string-append
            "kill -9 $(cat " (pid-file name) " 2>/dev/null) 2>/dev/null;"
            " rm -f " (pid-file name))))

;; Poll until the worker answers a render, rather than sleeping a guessed
;; interval: process start-up time is not a constant worth guessing at.
(define (await-worker! port tries)
  (let loop ((i 0))
    (if (>= i tries)
        #f
        (let ((p (guard (e (#t #f))
                   (qjspool-connect "127.0.0.1" port '((render-timeout-ms . 2000))))))
          (if (not p)
              (begin (sleep-ms 200) (loop (+ i 1)))
              (let-values (((k v) (qjspool-render p "hello" "{\"name\":\"up\"}")))
                (if k p (begin (sleep-ms 200) (loop (+ i 1))))))))))

(start-scheduler
  (lambda ()
    (write-bundle!)
    (kill-worker! "good") (kill-worker! "spin") (kill-worker! "half")
    (kill-worker! "carry")
    (spawn-worker! "good" good-port 800)
    ;; renders may run to 3s; a tail may not live past 400ms. That gap is
    ;; the point -- it puts a deadline INSIDE a render rather than between
    ;; two reads, which is where both of the bugs below lived.
    (spawn-worker! "carry" carry-port 3000 400)
    (spawn-worker! "half" half-port 800)
    (spawn-worker! "spin" spin-port 60000)   ; long engine deadline: the
                                             ; CALLER's timeout is what must
                                             ; end a runaway render here
    (let ((probe (await-worker! good-port 40)))
      (if (not probe)
          (fail "the worker process never came up" good-port)
          (begin
            ;; ---- a render round trip ------------------------------------
            (let ((pool (qjspool (list (cons "127.0.0.1" good-port))
                                 '((render-timeout-ms . 2000)))))
              (let-values (((k v) (qjspool-render pool "hello" "{\"name\":\"world\"}")))
                (check "a render comes back from the worker process"
                       (and k (string=? v "<h1>world</h1>"))))

              ;; ---- a JS throw is NOT a transport failure -------------------
              ;; It has to arrive as an ordinary failed reply, or every
              ;; throwing render would discard a healthy connection and the
              ;; pool would rebuild its way through the whole endpoint list.
              (let-values (((k v) (qjspool-render pool "boom" "{}")))
                (check "a JS throw comes back as a failed reply"
                       (and (not k) (string? v)))
                (when (and (not k) (string? v))
                  (check "the JS error text survives the wire"
                         (let loop ((i 0))
                           (cond ((> (+ i 11) (string-length v)) #f)
                                 ((string=? (substring v i (+ i 11)) "render blew") #t)
                                 (else (loop (+ i 1))))))))
              (let-values (((k v) (qjspool-render pool "hello" "{\"name\":\"again\"}")))
                (check "the connection is still usable after a JS throw"
                       (and k (string=? v "<h1>again</h1>"))))

              ;; an unknown function is the bundle's problem, not the wire's
              (let-values (((k v) (qjspool-render pool "nosuchfn" "{}")))
                (check "an unknown render function fails without killing the link"
                       (not k)))
              (let-values (((k v) (qjspool-render pool "hello" "{\"name\":\"third\"}")))
                (check "and the link still renders" (and k (string=? v "<h1>third</h1>"))))

              ;; ---- statistics come from the shared pool engine -------------
              (let ((st (qjspool-stats pool)))
                (check "the pool reports its size"
                       (equal? (cond ((assq 'size st) => cdr) (else #f)) 1))
                ;; renders are LEASES, so they are counted as checkouts.
                ;; `queries` stays zero on purpose: the pool hands over the
                ;; worker and the render's reply goes straight back to the
                ;; caller, so the pool never sees it (the same reason a
                ;; leased SQL connection's statements are invisible to it).
                (check "the pool counted the renders as checkouts"
                       (let ((q (cond ((assq 'checkouts st) => cdr) (else 0))))
                         (>= q 4)))
                (check "nothing is left in use once the renders are done"
                       (equal? (cond ((assq 'in-use st) => cdr) (else #f)) 0)))
              (qjspool-close! pool))

            ;; ---- (igropyr ssr) in front of the pool ----------------------
            ;; The cache has to sit in front of the WORKERS exactly as it sat
            ;; in front of the in-process engine: a hit must not reach them
            ;; at all. Proven from the worker's own render counter, which is
            ;; the only witness that cannot be faked by the caller's stats.
            (let* ((pool (qjspool (list (cons "127.0.0.1" good-port))
                                  '((render-timeout-ms . 2000))))
                   (r (make-ssr "" (list (cons 'engine pool)))))
              (define (worker-renders)
                (let-values (((k v) (qjspool-render pool "count" "{}")))
                  (and k (string->number v))))
              (let ((before (worker-renders)))
                (let ((a (ssr-render r "counted" '(("t" . "one"))
                                     '((key . "/k1"))))
                      (b (ssr-render r "counted" '(("t" . "one"))
                                     '((key . "/k1")))))
                  (check "ssr renders through the worker pool"
                         (and (string=? a "<p>one</p>") (string=? b a)))
                  (check "the second call was a cache HIT, not a second render"
                         (= (- (worker-renders) before) 1))
                  (let ((st (ssr-stats r)))
                    (check "and ssr counted it as a hit"
                           (equal? (cond ((assq 'hits st) => cdr) (else #f)) 1)))))
              ;; an invalidation must reach the workers again
              (let ((before (worker-renders)))
                (ssr-invalidate! r "/k1")
                (ssr-render r "counted" '(("t" . "one")) '((key . "/k1")))
                (check "after an invalidation the worker renders again"
                       (= (- (worker-renders) before) 1)))
              ;; a JS throw must surface without being cached
              (let-values (((k v) (ssr-try-render r "boom" '() '((key . "/bad")))))
                (check "a throwing render surfaces through ssr" (not k)))
              (qjspool-close! pool))

            ;; ---- a request that stops halfway ---------------------------
            ;;
            ;; A length prefix is accepted before its body arrives, so a
            ;; peer can announce a frame, send part of it and simply stop
            ;; -- no FIN, no error, nothing the worker would react to. That
            ;; held a process, a file descriptor and everything already
            ;; received for as long as the peer cared to keep the socket
            ;; open. IDLE is different and must stay unlimited: a pooled
            ;; connection is legitimately silent between renders, and the
            ;; checks above would fail if silence alone closed it.
            (let ((me self))
              (spawn
                (lambda ()
                  (tcp-connect! "127.0.0.1" half-port self)
                  (receive (after 3000 (send me (vector 'half 'no-connect)))
                    (`#(tcp-connect-failed ,e) (send me (vector 'half 'no-connect)))
                    (`#(tcp-connected ,c)
                      (tcp-read-start! c)
                      ;; announces ten bytes, sends one, then waits
                      (let ((bv (make-bytevector 5 0)))
                        (bytevector-u8-set! bv 3 10)
                        (tcp-write! c bv #f))
                      (let ((t0 (now-ms)))
                        (receive (after 6000 (send me (vector 'half 'never)))
                          (`#(tcp-eof) (send me (vector 'half (- (now-ms) t0))))
                          (`#(tcp-error ,e)
                            (send me (vector 'half (- (now-ms) t0))))))))))
              (receive (after 9000 (fail "half-frame probe never answered"))
                (`#(half ,r)
                  (check "a request that stops halfway does not hold the worker"
                         (and (number? r) (< r 5000)))
                  (display (string-append "  [info] half-delivered frame dropped after "
                                          (if (number? r) (number->string r) "never")
                                          "ms (configured 1200)\n")))))

            ;; ---- ...and dribbling does not renew that deadline -----------
            ;;
            ;; A timeout re-armed on every arrival is an INACTIVITY timer,
            ;; and inactivity is not what needs bounding: a peer sending one
            ;; byte just under the interval keeps the same half frame -- and
            ;; its process, its descriptor and most of a frame's worth of
            ;; buffer -- alive for as long as it cares to. The deadline is
            ;; taken once, when the buffer stops being empty.
            (let ((me self))
              (spawn
                (lambda ()
                  (tcp-connect! "127.0.0.1" half-port self)
                  (receive (after 3000 (send me (vector 'drib 'no-connect)))
                    (`#(tcp-connect-failed ,e) (send me (vector 'drib 'no-connect)))
                    (`#(tcp-connected ,c)
                      (tcp-read-start! c)
                      (let ((bv (make-bytevector 5 0)))
                        (bytevector-u8-set! bv 3 40)      ; announces 40 bytes
                        (tcp-write! c bv #f))
                      (let ((t0 (now-ms)))
                        ;; one byte every 400ms against a 1200ms deadline:
                        ;; three arrivals inside every window, indefinitely
                        (spawn (lambda ()
                                 (let drip ((i 0))
                                   (when (< i 12)
                                     (sleep-ms 400)
                                     (guard (e (#t 'gone))
                                       (tcp-write! c (make-bytevector 1 65) #f))
                                     (drip (+ i 1))))))
                        (receive (after 8000 (send me (vector 'drib 'never)))
                          (`#(tcp-eof) (send me (vector 'drib (- (now-ms) t0))))
                          (`#(tcp-error ,e)
                            (send me (vector 'drib (- (now-ms) t0))))))))))
              (receive (after 11000 (fail "dribble probe never answered"))
                (`#(drib ,r)
                  (check "dribbling bytes does not renew the half-frame deadline"
                         (and (number? r) (< r 4000)))
                  (display (string-append "  [info] dribbled half-frame dropped after "
                                          (if (number? r) (number->string r) "never")
                                          "ms (deadline 1200, a byte every 400)\n")))))

            ;; ---- two whole requests in ONE write are both answered --------
            ;;
            ;; This is worker-side behaviour, so it needs the real worker
            ;; and a raw client: the pool never writes two requests without
            ;; reading between them. There was a version that stopped
            ;; answering once a carried-in tail's deadline had passed, and
            ;; it stopped with a COMPLETE frame still in the buffer -- the
            ;; loop then treated that buffer as a partial tail and waited
            ;; for bytes that were never coming, so a request that arrived
            ;; whole was never rendered and never answered.
            (let ((me self))
              (spawn
                (lambda ()
                  (tcp-connect! "127.0.0.1" good-port self)
                  (receive (after 3000 (send me (vector 'pair 'no-connect)))
                    (`#(tcp-connect-failed ,e) (send me (vector 'pair 'no-connect)))
                    (`#(tcp-connected ,c)
                      (tcp-read-start! c)
                      (let* ((frame
                              (lambda (id fn json)
                                (let* ((f (string->utf8 fn)) (j (string->utf8 json))
                                       (fl (bytevector-length f))
                                       (jl (bytevector-length j))
                                       (n (+ 4 2 fl jl))
                                       (bv (make-bytevector (+ 4 n))))
                                  (bytevector-u32-set! bv 0 n (endianness big))
                                  (bytevector-u32-set! bv 4 id (endianness big))
                                  (bytevector-u16-set! bv 8 fl (endianness big))
                                  (bytevector-copy! f 0 bv 10 fl)
                                  (bytevector-copy! j 0 bv (+ 10 fl) jl)
                                  bv)))
                             (a (frame 0 "hello" "{\"name\":\"A\"}"))
                             (b (frame 1 "hello" "{\"name\":\"B\"}"))
                             (both (make-bytevector (+ (bytevector-length a)
                                                       (bytevector-length b)))))
                        ;; ONE write: the worker sees both frames in one read
                        (bytevector-copy! a 0 both 0 (bytevector-length a))
                        (bytevector-copy! b 0 both (bytevector-length a)
                                          (bytevector-length b))
                        (tcp-write! c both #f))
                      ;; Both answers must come back -- counted as FRAMES,
                      ;; not as messages: two replies written back to back
                      ;; usually arrive in a single read, so counting
                      ;; tcp-data would say one and be wrong about it.
                      (let wait ((acc (make-bytevector 0)))
                        (let* ((n (bytevector-length acc))
                               (frames
                                (let scan ((i 0) (k 0))
                                  (if (> (+ i 4) n)
                                      k
                                      (let ((len (bytevector-u32-ref
                                                   acc i (endianness big))))
                                        (if (> (+ i 4 len) n)
                                            k
                                            (scan (+ i 4 len) (+ k 1))))))))
                          (if (>= frames 2)
                              (send me (vector 'pair 'both))
                              (receive (after 3000 (send me (vector 'pair frames)))
                                (`#(tcp-data ,bv)
                                  (let ((more (make-bytevector
                                                (+ n (bytevector-length bv)))))
                                    (bytevector-copy! acc 0 more 0 n)
                                    (bytevector-copy! bv 0 more n
                                                      (bytevector-length bv))
                                    (wait more)))
                                (`#(tcp-eof) (send me (vector 'pair frames)))
                                (`#(tcp-error ,e)
                                  (send me (vector 'pair frames)))))))))))
              (receive (after 8000 (fail "pipelined probe never answered"))
                (`#(pair ,r)
                  (check "two whole requests in one write are both answered"
                         (eq? r 'both))
                  (display (string-append "  [info] pipelined pair: "
                                          (if (eq? r 'both) "both answered"
                                              (string-append "only "
                                                (number->string r)))
                                          "\n")))))

            ;; ---- a whole frame behind a carried-in tail ------------------
            ;;
            ;; The pipelined pair above lands in an EMPTY buffer, so the
            ;; connection has no deadline while it is parsed -- which is
            ;; why it stayed green against the version that dropped
            ;; requests. This one arrives the other way: a tail carried in
            ;; from an earlier read, its deadline passing during the very
            ;; render that is meant to be answering it, and a second whole
            ;; frame sitting behind it in the same read. That reader used
            ;; to stop on the old deadline with the third frame complete
            ;; in the buffer, then wait for bytes that were never coming.
            (let ((me self))
              (spawn
                (lambda ()
                  (tcp-connect! "127.0.0.1" carry-port self)
                  (receive (after 3000 (send me (vector 'carry 'no-connect)))
                    (`#(tcp-connect-failed ,e) (send me (vector 'carry 'no-connect)))
                    (`#(tcp-connected ,c)
                      (tcp-read-start! c)
                      (let* ((f1 (qframe 1 "slow" "{}"))
                             (f2 (qframe 2 "slow" "{}"))
                             (f3 (qframe 3 "hello" "{\"name\":\"C\"}"))
                             (head (let ((h (make-bytevector 2)))
                                     (bytevector-u8-set! h 0 (bytevector-u8-ref f2 0))
                                     (bytevector-u8-set! h 1 (bytevector-u8-ref f2 1))
                                     h))
                             (tail (let* ((n (bytevector-length f2))
                                          (t (make-bytevector (- n 2))))
                                     (bytevector-copy! f2 2 t 0 (- n 2))
                                     t)))
                        ;; read 1: a whole slow render, then two bytes that
                        ;; become the tail with a 400ms window of its own
                        (tcp-write! c (bv-append f1 head) #f)
                        (let wait1 ((acc (make-bytevector 0)))
                          (if (>= (count-frames acc) 1)
                              (begin
                                ;; read 2: the tail completes into another
                                ;; slow render -- which outlives the window
                                ;; the tail was given -- with a third whole
                                ;; frame behind it
                                (tcp-write! c (bv-append tail f3) #f)
                                (let wait2 ((acc2 acc))
                                  (if (>= (count-frames acc2) 3)
                                      (send me (vector 'carry 'all))
                                      (receive (after 5000
                                                 (send me (vector 'carry
                                                                  (count-frames acc2))))
                                        (`#(tcp-data ,bv) (wait2 (bv-append acc2 bv)))
                                        (`#(tcp-eof)
                                          (send me (vector 'carry (count-frames acc2))))
                                        (`#(tcp-error ,e)
                                          (send me (vector 'carry (count-frames acc2))))))))
                              (receive (after 5000 (send me (vector 'carry 'no-first)))
                                (`#(tcp-data ,bv) (wait1 (bv-append acc bv)))
                                (`#(tcp-eof) (send me (vector 'carry 'eof-first)))
                                (`#(tcp-error ,e)
                                  (send me (vector 'carry 'err-first))))))))))) 
              (receive (after 12000 (fail "carried-tail probe never answered"))
                (`#(carry ,r)
                  (check "a whole frame behind a carried-in tail is answered"
                         (eq? r 'all))
                  (unless (eq? r 'all)
                    (display "  [info] carried tail: ") (write r) (newline)))))

            ;; ---- an in-time frame is not charged for someone else's render
            ;;
            ;; A render stops the whole worker, so one connection's window
            ;; can pass entirely inside another connection's render. The
            ;; bytes are then already in the mailbox when the reader next
            ;; runs -- they arrived in time -- and a reader that consults
            ;; the clock before parsing closes a peer for being punctual.
            (let ((me self))
              (spawn
                (lambda ()
                  (tcp-connect! "127.0.0.1" carry-port self)
                  (receive (after 3000 (send me (vector 'punct 'no-connect)))
                    (`#(tcp-connect-failed ,e) (send me (vector 'punct 'no-connect)))
                    (`#(tcp-connected 'a)
                      (send me (vector 'punct 'bad-tag)))
                    (`#(tcp-connected ,ca)
                      (tcp-read-start! ca)
                      (let* ((fa (qframe 7 "hello" "{\"name\":\"P\"}"))
                             (n (bytevector-length fa))
                             (h (make-bytevector 6))
                             (rest (make-bytevector (- n 6))))
                        (bytevector-copy! fa 0 h 0 6)
                        (bytevector-copy! fa 6 rest 0 (- n 6))
                        (tcp-write! ca h #f)        ; a partial frame: window opens
                        ;; a SECOND connection asks for a 700ms render; the
                        ;; worker is off the air for its duration
                        (let ((mine self))
                          (spawn (lambda ()
                                   (tcp-connect! "127.0.0.1" carry-port self)
                                   (receive (after 3000 (void))
                                     (`#(tcp-connect-failed ,e) (void))
                                     (`#(tcp-connected ,cb)
                                       (tcp-read-start! cb)
                                       (tcp-write! cb (qframe 8 "slow" "{}") #f)
                                       (receive (after 5000 (void))
                                         (`#(tcp-data ,bv) (void))
                                         (`#(tcp-eof) (void))
                                         (`#(tcp-error ,e) (void))))))))
                        (sleep-ms 150)              ; well inside the 400ms window
                        (tcp-write! ca rest #f)
                        (let wait ((acc (make-bytevector 0)))
                          (if (>= (count-frames acc) 1)
                              (send me (vector 'punct 'answered))
                              (receive (after 6000 (send me (vector 'punct 'timeout)))
                                (`#(tcp-data ,bv) (wait (bv-append acc bv)))
                                (`#(tcp-eof) (send me (vector 'punct 'closed)))
                                (`#(tcp-error ,e)
                                  (send me (vector 'punct 'closed))))))))))) 
              (receive (after 12000 (fail "punctual-peer probe never answered"))
                (`#(punct ,r)
                  (check "a frame that arrived in time is answered even when a render outlasted its window"
                         (eq? r 'answered))
                  (unless (eq? r 'answered)
                    (display "  [info] punctual peer: ") (write r) (newline)))))

            ;; ---- a connection that retires under load --------------------
            ;;
            ;; The id field is u32, so a connection eventually has to be
            ;; retired rather than have its counter wrap. Four billion
            ;; renders away, that branch is unreachable in a test and was
            ;; therefore never run: retiring after two renders, or never
            ;; telling the pool at all, left every suite green. Setting the
            ;; cap to one puts a retirement between every pair of renders.
            ;;
            ;; What must hold is that no caller pays for it. A connection
            ;; on its way out that reports itself idle first -- or replies
            ;; first, and lets its borrower's check-in reach the pool
            ;; before the news of its death -- gets lent to the next
            ;; caller in the queue, whose request then goes to a pid that
            ;; is already exiting.
            ;;
            ;; HALF OF THAT IS STRUCTURAL and half is not. Reporting idle
            ;; while retiring is now unreachable -- the send sits in the
            ;; other arm -- and this probe would red if it came back. The
            ;; remaining route is the borrower own check-in racing the
            ;; news of the death, which needs the scheduler to preempt
            ;; between two sends; that ordering is not pinned by any test
            ;; here, because nothing outside the connection can make that
            ;; preemption happen.
            (let ((rp (qjspool (list (cons "127.0.0.1" good-port))
                               '((render-timeout-ms . 2000)
                                 (checkout-timeout-ms . 4000)
                                 (max-requests-per-connection . 1)))))
              (let ((me self) (n 12))
                (do ((i 0 (+ i 1))) ((= i n))
                  (spawn (lambda ()
                           (let-values (((k v) (qjspool-render
                                                 rp "hello"
                                                 "{\"name\":\"R\"}")))
                             (send me (vector 'retire k v))))))
                (let loop ((got 0) (bad 0) (why #f))
                  (if (= got n)
                      (begin
                        (check "every caller is answered across repeated retirements"
                               (= bad 0))
                        (when (> bad 0)
                          (display "  [info] retirement losses: ")
                          (write (cons bad why)) (newline)))
                      (receive (after 20000
                                 (fail "retirement probe never finished" got bad))
                        (`#(retire ,k ,v)
                          (if k (loop (+ got 1) bad why)
                              (loop (+ got 1) (+ bad 1) v)))))))
              (qjspool-close! rp))

            ;; ---- a worker that is not there ------------------------------
            ;; The pool must answer, not hang: an endpoint nobody is
            ;; listening on is the ordinary state during a deploy.
            (let ((dead (qjspool (list (cons "127.0.0.1" 19799))
                                 '((render-timeout-ms . 500)
                                   (checkout-timeout-ms . 700)))))
              (let-values (((k v) (qjspool-render dead "hello" "{\"name\":\"x\"}")))
                (check "a render against a missing worker fails rather than hangs"
                       (and (not k) (string? v))))
              (qjspool-close! dead))

            ;; ---- THE POINT ----------------------------------------------
            ;; A runaway render, both ways, with a ticker alongside. The
            ;; ticker is an ordinary green process: if the scheduler runs,
            ;; it counts.
            (let ((ticks (box 0)) (stop (box #f)))
              (spawn (lambda ()
                       (let loop ()
                         (unless (unbox stop)
                           (sleep-ms 50)
                           (set-box! ticks (+ 1 (unbox ticks)))
                           (loop)))))
              ;; out of process: the render never returns, the caller's
              ;; deadline ends it, and the ticker ran the whole time
              (set-box! ticks 0)
              (let ((spool (qjspool (list (cons "127.0.0.1" spin-port))
                                    '((render-timeout-ms . 1000)))))
                (let-values (((k v) (qjspool-render spool "spin" "{}")))
                  (check "a runaway render in a worker fails on the caller's deadline"
                         (not k)))
                (let ((out-of-process (unbox ticks)))
                  (check "the scheduler kept running through it"
                         (>= out-of-process 10))

                  ;; in process: the same render, same bundle, on this
                  ;; thread. Nothing else runs while it does.
                  (qjs-boot! bundle '((timeout-ms . 600)))
                  (set-box! ticks 0)
                  (let-values (((k2 v2) (qjs-call/bytes "spin" "{}")))
                    (check "the in-process engine also refuses to run forever"
                           (not k2)))
                  (let ((in-process (unbox ticks)))
                    (set-box! stop #t)
                    (display (string-append
                               "  [info] ticks during a runaway render: worker "
                               (number->string out-of-process)
                               ", in-process " (number->string in-process) "\n"))
                    ;; The engine's own deadline is SHORTER here (600ms vs
                    ;; 1000ms), so in-process had less wall clock to tick
                    ;; through and still must manage none: the comparison is
                    ;; not close enough to be a timing coincidence.
                    (check "the in-process render froze the scheduler outright"
                           (= in-process 0))))
                (qjspool-close! spool)))))
      (kill-worker! "good")
      (kill-worker! "spin")
      (kill-worker! "half")
      (kill-worker! "carry")
      (when (file-exists? bundle-path) (delete-file bundle-path))
      (if (= failures 0)
          (display "qjspool: all tests passed\n")
          (begin (display (number->string failures)) (display " failures\n")))
      (exit (if (= failures 0) 0 1)))))
