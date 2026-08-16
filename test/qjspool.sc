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

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c) (if c (ok label) (fail label)))

;; ---- a STRUCTURAL sentinel for the read stop ---------------------------
;;
;; worker-conn-loop*'s tcp-read-stop! has no behavioural test, and cannot
;; have one on this runtime: deleting the call leaves the entire suite
;; green. Reads happen only inside an event-loop poll, a poll happens only
;; where the loop yields, and a processing pass never yields -- a render
;; runs with interrupts disabled, and the bulk primitives around it burn
;; no preemption ticks at all (measured: utf8->string of 8MiB lets a
;; competing process run exactly zero times). No arrival order tells the
;; two versions apart, so no probe can either. See the flood probe below,
;; which reports the same figure with and without the call.
;;
;; What CAN be pinned is that the rule is still WRITTEN DOWN. This asserts
;; tcp-read-stop! is the first thing on-data does. Deleting it turns this
;; red; so does moving it below answer-all!, which is the subtler
;; regression -- a render would then run with reads still on, which is
;; precisely the window the rule exists to close.
;;
;; NOT A PROOF OF BEHAVIOUR, and it does not pretend to be one: it is a
;; guard against silent removal of a rule whose effect this runtime cannot
;; observe. Stated rather than dressed up as a functional test.
;;
;; IT RUNS BEFORE THE libquickjs GATE, deliberately. It reads source and
;; needs no engine, so gating it would retire this rule's only protection
;; on every host without QuickJS -- the exact silent-skip failure the
;; suite's own conventions forbid.
(let ()
  (define path "igropyr/qjspool.sc")
  (define (has? line sub)
    (let ((n (string-length line)) (m (string-length sub)))
      (let loop ((i 0))
        (cond ((> (+ i m) n) #f)
              ((string=? (substring line i (+ i m)) sub) #t)
              (else (loop (+ i 1)))))))
  (define (blank-or-comment? s)
    (let loop ((i 0))
      (cond ((= i (string-length s)) #t)
            ((or (char=? (string-ref s i) #\space)
                 (char=? (string-ref s i) #\tab))
             (loop (+ i 1)))
            ((char=? (string-ref s i) #\;) #t)
            (else #f))))
  ;; MISSING SOURCE IS A FAILURE, never a skip: this check costs nothing
  ;; and has no environmental precondition, so "could not read it" can
  ;; only mean the path assumption broke -- which would retire the check
  ;; silently, exactly what it is here to prevent.
  (if (not (file-exists? path))
      (fail "the worker source can be read for the structural check" path)
      (let ((lines (call-with-input-file path
                     (lambda (in)
                       (let loop ((acc '()))
                         (let ((l (get-line in)))
                           (if (eof-object? l) (reverse acc) (loop (cons l acc)))))))))
        ;; the first line of real code after on-data's header
        (let scan ((ls lines) (inside #f))
          (cond
            ((null? ls)
             (if inside
                 (fail "on-data has a first expression")
                 (fail "on-data was found in the worker source")))
            ((and (not inside) (has? (car ls) "(define (on-data bv)"))
             (scan (cdr ls) #t))
            ((not inside) (scan (cdr ls) #f))
            ((blank-or-comment? (car ls)) (scan (cdr ls) #t))
            (else
             (check "reading is stopped as the FIRST act of a read pass, ahead of any render"
                    (has? (car ls) "(tcp-read-stop! c)"))
             (unless (has? (car ls) "(tcp-read-stop! c)")
               (display "  [info] on-data's first expression is instead: ")
               (display (car ls)) (newline))))))))

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

;; WHAT IS SKIPPED IS THE WORKER TESTS, not the whole file: the
;; structural check above reads source only, so it has already run and
;; its verdict still decides the exit status. Saying "test skipped" while
;; a check had in fact failed would be the report this suite's
;; conventions exist to prevent.
(unless (quickjs-present?)
  (display "qjspool: no stock libquickjs found, WORKER tests skipped\n")
  (display "  (install a stock libquickjs, or set IGROPYR_LIBQUICKJS_SO, to run them;\n")
  (display "   the structural check above needs no engine and did run)\n")
  (exit (if (= failures 0) 0 1)))

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
// takes a LARGE argument and returns a tiny answer, so that a request
// costs the worker real decoding work (the props are converted to a
// string and back for the engine) without the reply size telling the
// peer anything about the worker's buffer. Used by the flood probe.
function eat(j){ return String(j.length); }
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
;; WHAT THE READER SAW, not what a sleep suggests it saw. The worker
;; appends one flushed line per read to this file when asked; probes below
;; assert against it rather than inferring the worker's state from their
;; own timing. Every one of these probes had its precondition -- "a render
;; was straddling this connection's window" -- established by a sleep and
;; asserted nowhere, and a review round found each of them able to pass
;; with that precondition absent.
(define (trace-file name) (string-append "/tmp/igropyr-qjsw-" name ".trace"))

(define (trace-lines name)
  (let ((p (trace-file name)))
    (if (not (file-exists? p))
        '()
        (call-with-input-file p
          (lambda (in)
            (let loop ((acc '()))
              (let ((l (get-line in)))
                (if (eof-object? l) (reverse acc) (loop (cons l acc))))))))))

(define (line-has? line sub)
  (let ((n (string-length line)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring line i (+ i m)) sub) #t)
            (else (loop (+ i 1)))))))

(define (trace-count name sub)
  (let loop ((ls (trace-lines name)) (k 0))
    (cond ((null? ls) k)
          ((line-has? (car ls) sub) (loop (cdr ls) (+ k 1)))
          (else (loop (cdr ls) k)))))

;; ATTRIBUTED, not just counted. One worker serves several connections at
;; once -- the probe's own, its rival's, and whatever the previous probe
;; has not closed yet -- so "a late read happened somewhere" can be true
;; while the probe's own connection saw nothing of the sort. Each trace
;; line names its connection, so a probe counts only lines belonging to a
;; connection that had not spoken before the probe started. That picks out
;; its own connection without the worker having to say which one it is.
(define (line-conn l)
  (let scan ((i 0))
    (cond ((= i (string-length l)) #f)
          ((char=? (string-ref l i) #\space) (substring l 0 i))
          (else (scan (+ i 1))))))

(define (trace-len name) (length (trace-lines name)))

;; WHICH CONNECTION IS MINE, asked rather than inferred. "The one that
;; had not spoken before I started" cannot tell a probe's connection from
;; the rival it starts alongside it, and every one of these probes starts
;; both at once -- so a rival's late read, drained delivery or refused
;; frame could satisfy an assertion about the probe's own. A warm-up
;; request carries an id nothing else uses; the trace ties that id to a
;; connection, and everything after is counted for that connection only.
;; A COMPLETE CHEAP REQUEST, answered before the probe's real work, whose
;; id nothing else uses. That answer is what puts this connection into the
;; trace under a name the assertions can look up.
(define (warm-up! c id)
  (tcp-write! c (qframe id "hello" "{\"name\":\"w\"}") #f)
  (let wait ((acc (make-bytevector 0)))
    (if (>= (count-frames acc) 1)
        #t
        (receive (after 4000 #f)
          (`#(tcp-data ,bv) (wait (bv-append acc bv)))
          (`#(tcp-eof) #f)
          (`#(tcp-error ,e) #f)))))

(define (trace-conn-of-id name id)
  (let ((want (string-append "answer id=" (number->string id))))
    (let loop ((ls (trace-lines name)))
      (cond ((null? ls) #f)
            ((line-has? (car ls) want) (line-conn (car ls)))
            (else (loop (cdr ls)))))))

(define (trace-count-of name conn before sub)
  (let loop ((k 0) (rest (trace-lines name)) (n 0))
    (cond ((null? rest) n)
          ((< k before) (loop (+ k 1) (cdr rest) n))
          (else
           (loop (+ k 1) (cdr rest)
                 (if (and conn
                          (equal? conn (line-conn (car rest)))
                          (line-has? (car rest) sub))
                     (+ n 1) n))))))

;; The number written immediately after `sub` on a trace line, or #f when
;; that field is not on it. Fields are read by name rather than by
;; position because the line's shape differs per event type -- the same
;; mistake the "late=" fields already cost this file once.
(define (line-number-after l sub)
  (let ((n (string-length l)) (m (string-length sub)))
    (let scan ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring l i (+ i m)) sub)
             (let digits ((j (+ i m)) (acc 0) (any #f))
               (if (and (< j n) (char<=? #\0 (string-ref l j) #\9))
                   (digits (+ j 1)
                           (+ (* acc 10) (- (char->integer (string-ref l j)) 48))
                           #t)
                   (and any acc))))
            (else (scan (+ i 1)))))))

;; The LARGEST value this connection reported for `sub`, over the lines
;; from `before` up to (not including) the first of its lines containing
;; `until`. How much a read loop is holding cannot be seen from outside
;; the worker -- a peer knows only what it handed to the kernel, and the
;; kernel's own buffers are counted nowhere -- so the trace is the only
;; witness there is.
;;
;; THE `until` BOUND IS NOT A CONVENIENCE. It is what makes the window
;; measured the one under test: reads being ON while this loop WAITS is
;; the correct state, and a peer with a half frame outstanding is
;; entitled to be read then, up to the frame cap. What has to be bounded
;; is what accumulates while the loop is not waiting, so the measurement
;; ends where the work it was measuring does.
(define (trace-max-until name conn before sub until)
  (let loop ((k 0) (rest (trace-lines name)) (mx 0))
    (cond ((null? rest) mx)
          ((< k before) (loop (+ k 1) (cdr rest) mx))
          (else
           (let ((l (car rest)))
             (cond
               ((not (and conn (equal? conn (line-conn l))))
                (loop (+ k 1) (cdr rest) mx))
               ((line-has? l until) mx)
               (else
                (loop (+ k 1) (cdr rest)
                      (let ((v (line-number-after l sub)))
                        (if (and v (> v mx)) v mx))))))))))

(define (trace-count-new name before sub)
  (let* ((ls (trace-lines name))
         (old (let loop ((k 0) (rest ls) (acc '()))
                (if (or (= k before) (null? rest))
                    acc
                    (let ((c (line-conn (car rest))))
                      (loop (+ k 1) (cdr rest)
                            (if (and c (not (member c acc))) (cons c acc) acc)))))))
    (let loop ((k 0) (rest ls) (n 0))
      (cond ((null? rest) n)
            ((< k before) (loop (+ k 1) (cdr rest) n))
            (else
             (let ((c (line-conn (car rest))))
               (loop (+ k 1) (cdr rest)
                     (if (and c (not (member c old)) (line-has? (car rest) sub))
                         (+ n 1) n))))))))

(define (spawn-worker! name port timeout-ms . partial)
  (system (string-append "rm -f " (trace-file name) "; "
                         "scheme --script igropyr/qjs-worker.sc 127.0.0.1 "
                         (number->string port) " " bundle-path
                         " timeout-ms=" (number->string timeout-ms)
                         ;; short enough to be observable: the default is
                         ;; half a minute, which is right in production and
                         ;; useless in a test
                         " partial-frame-ms="
                         (number->string (if (pair? partial) (car partial) 1200))
                         " trace-file=" (trace-file name)
                         " >/dev/null 2>&1 & echo $! > " (pid-file name))))

(define (kill-worker! name)
  (system (string-append
            "kill -9 $(cat " (pid-file name) " 2>/dev/null) 2>/dev/null;"
            ;; the trace outlives the worker on purpose: it is what a
            ;; failing probe is read against afterwards, and spawn-worker!
            ;; truncates it at the start of the next run
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
                ;; a live connection whose render failed: closing it is
                ;; not tidiness. The path is reached whenever connect
                ;; succeeded and the render did not -- a worker not
                ;; serving yet is the expected reason, but a bad bundle
                ;; or an engine error lands here too -- and it costs one
                ;; connection per retry, on the machine least able to
                ;; spare the descriptors.
                (if k p (begin (qjspool-close! p)
                               (sleep-ms 200)
                               (loop (+ i 1))))))))))

;; -> #t when the worker at `port` served a real request, #f (loudly)
;; when it never did. It must return rather than abort: `fail` only
;; counts, so anything after it still runs, and the caller has cleanup --
;; four workers to kill and a bundle to remove -- that must happen even
;; on this path.
(define (require-worker! label port)
  (let* ((t0 (now-ms))
         (w (await-worker! port 40)))
    (cond
      (w (qjspool-close! w)     ; readiness only: ask it to close, keep no handle
         (display (string-append "  [info] " label " worker answered after "
                                 (number->string (- (now-ms) t0))
                                 "ms of waiting here\n"))
         #t)
      (else
        (fail (string-append "the " label " worker never came up") port)
        #f))))

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
    ;; WAIT FOR EVERY WORKER, not just the first. Each is a whole Chez
    ;; process loading the library, and four of them start at once; on a
    ;; busy machine the later ones are still coming up while the cases
    ;; that use them run. (The good worker is probed last and only if the
    ;; other three answered: with one of them missing the run is over
    ;; anyway, and dialling a fourth adds nothing to the report.)
    ;;
    ;; CONNECT COMPLETING IS NOT THE WORKER BEING READY. The kernel can
    ;; finish the handshake on a listening socket whose process is not
    ;; serving, so a probe connects, writes, and then waits out its own
    ;; timeout -- and reports that as a deadline that never fired, which
    ;; reads like a fault in the thing under test rather than a worker that
    ;; was not there yet. Probes against a worker that never answers at all
    ;; report the opposite ("no-connect"). Both were seen in the same run on
    ;; a loaded machine, from workers that had no barrier.
    ;;
    ;; So the wait is a real round trip -- connect AND a render -- and it
    ;; ends when the worker can serve rather than when it can be dialled.
    ;; A missing worker is reported here, once, by name, instead of as a
    ;; string of deadline failures in whichever cases happen to use it.
    ;;
    ;; The printed time is how long THIS wait took, not how long the
    ;; worker took to start: the workers were spawned together, so a later
    ;; barrier may find its worker already up and report little or no
    ;; waiting at all.
    (let* ((carry-up (require-worker! "carry" carry-port))
           (half-up (require-worker! "half" half-port))
           (spin-up (require-worker! "spin" spin-port))
           ;; every one is asked before the gate, so a run missing two
           ;; workers says so twice rather than stopping at the first
           (probe (and carry-up half-up spin-up
                       (await-worker! good-port 40))))
      (if (not probe)
          ;; ...but do not also blame the good worker for somebody else
          (when (and carry-up half-up spin-up)
            (fail "the worker process never came up" good-port))
          (begin
            ;; readiness only, like the other three: the cases below open
            ;; their own pools, so holding this one just leaves a
            ;; connection parked for the length of the suite
            (qjspool-close! probe)
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

            ;; ---- a frame completed under someone else's render -----------
            ;;
            ;; WEAKER THAN IT LOOKS, and named for what it shows. The
            ;; intent was to pin that a peer which delivered in time is
            ;; not refused because its window passed inside another
            ;; connection's render. Instrumentation says the reader is
            ;; never reached in that state at all -- the connection's own
            ;; timer closes it first and its arrived bytes are never
            ;; delivered -- so what this actually pins is the ordinary
            ;; case: a frame that completes while the worker is busy is
            ;; still answered afterwards.
            ;;
            ;; A render stops the whole worker, so one connection's window
            ;; can pass entirely inside another connection's render. The
            ;; bytes are then already in the mailbox when the reader next
            ;; runs -- they arrived in time -- and a reader that consults
            ;; the clock before parsing closes a peer for being punctual.
            (let ((me self)
                  (mark (trace-len "carry")))
              (spawn
                (lambda ()
                  (tcp-connect! "127.0.0.1" carry-port self)
                  (receive (after 3000 (send me (vector 'punct 'no-connect)))
                    (`#(tcp-connect-failed ,e) (send me (vector 'punct 'no-connect)))
                    (`#(tcp-connected 'a)
                      (send me (vector 'punct 'bad-tag)))
                    (`#(tcp-connected ,ca)
                      (tcp-read-start! ca)
                      (warm-up! ca 907)
                      (let* ((fa (qframe 7 "hello" "{\"name\":\"P\"}"))
                             (n (bytevector-length fa))
                             (h (make-bytevector 6))
                             (rest (make-bytevector (- n 6))))
                        (bytevector-copy! fa 0 h 0 6)
                        (bytevector-copy! fa 6 rest 0 (- n 6))
                        (tcp-write! ca h #f)        ; a partial frame: window opens
                        ;; a SECOND connection asks for a 700ms render; the
                        ;; worker is off the air for its duration
                        ;; THE COMPETING RENDER IS ASSERTED, not assumed.
                        ;; Every failure path here used to be (void), so a
                        ;; port collision or a worker that had not come up
                        ;; turned the only probe of this behaviour into a
                        ;; tautology -- green, silent, and testing nothing.
                        (let ((rival self))
                          (spawn (lambda ()
                                   (tcp-connect! "127.0.0.1" carry-port self)
                                   (receive (after 3000
                                              (send rival (vector 'rival 'no-connect)))
                                     (`#(tcp-connect-failed ,e)
                                       (send rival (vector 'rival 'no-connect)))
                                     (`#(tcp-connected ,cb)
                                       (tcp-read-start! cb)
                                       (tcp-write! cb (qframe 8 "slow" "{}") #f)
                                       (receive (after 5000
                                                  (send rival (vector 'rival 'no-answer)))
                                         (`#(tcp-data ,bv)
                                           (send rival (vector 'rival 'rendered)))
                                         (`#(tcp-eof)
                                           (send rival (vector 'rival 'eof)))
                                         (`#(tcp-error ,e)
                                           (send rival (vector 'rival 'err)))))))))
                        (sleep-ms 150)              ; well inside the 400ms window
                        (tcp-write! ca rest #f)
                        (let wait ((acc (make-bytevector 0)) (rival #f))
                          (if (and rival (>= (count-frames acc) 1))
                              (send me (vector 'punct (if (eq? rival 'rendered)
                                                          'answered
                                                          (cons 'rival rival))))
                              (receive (after 8000 (send me (vector 'punct 'timeout)))
                                (`#(rival ,r) (wait acc r))
                                (`#(tcp-data ,bv) (wait (bv-append acc bv) rival))
                                (`#(tcp-eof) (send me (vector 'punct 'closed)))
                                (`#(tcp-error ,e)
                                  (send me (vector 'punct 'closed))))))))))) 
              (receive (after 12000 (fail "punctual-peer probe never answered"))
                (`#(punct ,r)
                  (check "a frame completed while another connection was rendering is answered"
                         (eq? r 'answered))
                  ;; ...AND IT WAS ACTUALLY LATE. Without a render
                  ;; straddling the window every read lands inside it and
                  ;; this proves nothing; the worker says which it was.
                  (let ((mine (trace-conn-of-id "carry" 907)))
                    (check "the probe's own connection is identified" (and mine #t))
                    (check "that frame's completing read was in fact overdue"
                           (> (trace-count-of "carry" mine mark "read-late=1") 0)))
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
            ;; WHAT THIS PROBE DOES NOT PIN, stated because an earlier
            ;; version of this comment claimed the opposite and was wrong:
            ;; putting the retiring `pool-idle` send back changes nothing
            ;; observable, because a qjspool connection is LEASED, so that
            ;; message finds no busy entry and does nothing at all. Nor is
            ;; the reply-before-conn-dead ordering pinned: it needs the
            ;; scheduler to preempt between two sends, which nothing
            ;; outside the connection can make happen. What is pinned is
            ;; below -- that retirement actually occurs, that the pool is
            ;; told, and that it is not billed as a failure.
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
                          (write (cons bad why)) (newline))
                        ;; ...AND THAT ANY OF IT HAPPENED. Asserting only
                        ;; that twelve callers were answered cannot tell a
                        ;; connection that retires and hands over cleanly
                        ;; from one that never retires at all -- ignoring
                        ;; the cap outright passed this probe. The count
                        ;; is what makes the feature observable, and it
                        ;; must land under retired, not under lost: a
                        ;; scheduled stand-down billed as a failure is the
                        ;; number an operator uses to decide whether the
                        ;; peer is flaky.
                        (let* ((st (qjspool-stats rp))
                               (ret (cond ((assq 'connections-retired st) => cdr)
                                          (else 0)))
                               (lost (cond ((assq 'connections-lost st) => cdr)
                                           (else 0))))
                          (check "a capped connection actually retires, once per render"
                                 (>= ret (- n 2)))
                          (check "a scheduled retirement is not booked as a connection lost"
                                 (= lost 0))
                          (display "  [info] retired ") (write ret)
                          (display " lost ") (write lost) (newline)))
                      (receive (after 20000
                                 (fail "retirement probe never finished" got bad))
                        (`#(retire ,k ,v)
                          (if k (loop (+ got 1) bad why)
                              (loop (+ got 1) (+ bad 1) v)))))))
              (qjspool-close! rp))

            ;; ---- a request bigger than one read --------------------------
            ;;
            ;; The probe above completes its frame in one read. TCP does
            ;; not promise that, and libuv hands up at most 64KiB per
            ;; callback, so a 192KiB request cannot arrive in fewer than
            ;; three. What this pins is reassembly across them. It does
            ;; NOT pin anything about deadlines: measured, every one of
            ;; those reads lands inside the window.
            (let ((me self)
                  (mark (trace-len "carry")))
              (spawn
                (lambda ()
                  (tcp-connect! "127.0.0.1" carry-port self)
                  (receive (after 3000 (send me (vector 'split 'no-connect)))
                    (`#(tcp-connect-failed ,e) (send me (vector 'split 'no-connect)))
                    (`#(tcp-connected ,ca)
                      (tcp-read-start! ca)
                      (warm-up! ca 909)
                      ;; BIGGER THAN ONE READ, so the split is structural
                      ;; rather than a race: libuv hands up at most 64KiB
                      ;; per callback, so a 192KiB request cannot arrive
                      ;; in fewer than three, however the peer wrote it.
                      (let* ((big (make-string 196608 #\x))
                             (fa (qframe 9 "hello"
                                         (string-append "{\"name\":\"" big "\"}")))
                             (n (bytevector-length fa))
                             (p1 (make-bytevector 6))
                             (p3 (make-bytevector (- n 6))))
                        (bytevector-copy! fa 0 p1 0 6)
                        (bytevector-copy! fa 6 p3 0 (- n 6))
                        (tcp-write! ca p1 #f)          ; the window opens
                        ;; AND IS READ BEFORE THE RENDER STARTS. Without
                        ;; that there is no carried-in deadline at all and
                        ;; the probe proves nothing -- it needs the worker
                        ;; to have seen the prefix while it was still idle.
                        ;; A short wait is not a proof, but it is the
                        ;; ordering the rest of this depends on, so it is
                        ;; at least stated.
                        (sleep-ms 40)
                        ;; ...AND THE COMPETING RENDER IS ASSERTED. Its
                        ;; failure paths were all silent, which is exactly
                        ;; the tautology fixed in the probe above: with no
                        ;; render straddling the window, every read lands
                        ;; inside it and the frame is answered whether the
                        ;; rule under test is there or not.
                        (let ((rival self))
                          (spawn (lambda ()
                                   (tcp-connect! "127.0.0.1" carry-port self)
                                   (receive (after 3000
                                              (send rival (vector 'rival 'no-connect)))
                                     (`#(tcp-connect-failed ,e)
                                       (send rival (vector 'rival 'no-connect)))
                                     (`#(tcp-connected ,cb)
                                       (tcp-read-start! cb)
                                       (tcp-write! cb (qframe 10 "slow" "{}") #f)
                                       (receive (after 5000
                                                  (send rival (vector 'rival 'no-answer)))
                                         (`#(tcp-data ,bv)
                                           (send rival (vector 'rival 'rendered)))
                                         (`#(tcp-eof) (send rival (vector 'rival 'eof)))
                                         (`#(tcp-error ,e)
                                           (send rival (vector 'rival 'err)))))))))
                        (sleep-ms 120)
                        ;; written whole and well inside the window; the
                        ;; worker is mid-render and sees none of it until
                        ;; afterwards, by which time the window has passed
                        ;; AND the first read it gets cannot complete the
                        ;; frame however punctual the peer was
                        (tcp-write! ca p3 #f)
                        (let wait ((acc (make-bytevector 0)) (rival #f))
                          (if (and rival (>= (count-frames acc) 1))
                              (send me (vector 'split (if (eq? rival 'rendered)
                                                          'answered
                                                          (cons 'rival rival))))
                              (receive (after 9000 (send me (vector 'split 'timeout)))
                                (`#(rival ,r) (wait acc r))
                                (`#(tcp-data ,bv) (wait (bv-append acc bv) rival))
                                (`#(tcp-eof) (send me (vector 'split 'closed)))
                                (`#(tcp-error ,e)
                                  (send me (vector 'split 'closed)))))))))))
              (receive (after 12000 (fail "split-request probe never answered"))
                (`#(split ,r)
                  (check "a request larger than one read is reassembled and answered"
                         (eq? r 'answered))
                  ;; ...BY THE RULE UNDER TEST. A reassembly that never
                  ;; went through a late, nothing-consumed read is the
                  ;; ordinary path and would pass with the rule removed.
                  (let ((mine (trace-conn-of-id "carry" 909)))
                    (check "the split probe's own connection is identified"
                           (and mine #t))
                    (check "that reassembly went through a drained late read"
                           (> (trace-count-of "carry" mine mark "drained") 0))
                  ;; ...ONE MESSAGE AT A TIME. Taking everything queued in
                  ;; a loop looked like a snapshot and was not -- a matched
                  ;; receive clause runs preemptibly, so a peer that keeps
                  ;; writing keeps the loop fed and the parser never runs,
                  ;; which is also where the frame cap is enforced. A
                  ;; delivery split over three messages must therefore
                  ;; return to the parser twice, not once.
                    (check "it returned to the parser between deliveries"
                           (>= (trace-count-of "carry" mine mark "drained") 2)))
                  (unless (eq? r 'answered)
                    (display "  [info] split request: ") (write r) (newline)))))

            ;; ---- a peer that floods behind its own requests ---------------
            ;;
            ;; A peer that pipelines megabyte-sized requests and pushes the
            ;; body of a frame it never finishes behind them, as fast as
            ;; the wire will take it. Every request must still be answered,
            ;; and the connection must still die on its half-frame deadline
            ;; rather than live on the flood.
            ;;
            ;; THIS PROBE DOES NOT DISCRIMINATE THE READ STOP, and says so
            ;; rather than implying otherwise. worker-conn-loop* stops
            ;; reading for the length of a processing pass so that a peer
            ;; writing faster than the reader retires has its window closed
            ;; instead of its segments copied into an unbounded mailbox.
            ;; That is the right rule, and it is what (igropyr http-client)
            ;; does around its on-chunk handler -- but on THIS runtime it
            ;; is not observable. Three runs each way: with the stop, the
            ;; connection peaked at 6016 / 8704 / 9152 KiB; with it deleted,
            ;; 8960 / 8960 / 8768 KiB. Overlapping ranges, no signal.
            ;;
            ;; The reason is that reads only ever happen during an event
            ;; loop poll, and this loop has no point at which it is running
            ;; while a poll can occur. A render is a synchronous call made
            ;; with interrupts disabled, so nothing is read while one runs
            ;; either way. Everything else in a pass -- inbuf-append!,
            ;; take-frame!'s slices, utf8->string and string->utf8 on the
            ;; props, encode-response, the write -- is a primitive, and
            ;; primitives burn no preemption ticks at all: measured here,
            ;; utf8->string of 8 MiB takes 9ms and lets a competing process
            ;; run exactly zero times, where a plain Scheme loop yields on
            ;; every slice. So the pass is never interrupted, reads already
            ;; happen only while this loop is parked in a receive, and
            ;; turning them off in between changes nothing that can be
            ;; measured from either end.
            ;;
            ;; What this DOES pin is the restart half, which is not
            ;; cosmetic: dropping the tcp-read-start! takes the whole suite
            ;; from 47 passing checks to 8, because a connection that stops
            ;; reading and never resumes goes deaf after its first read.
            ;; The figure is reported as [info] because it is the only
            ;; witness there is to how much reached the process -- a peer
            ;; knows only what it handed to the kernel -- and because a
            ;; regression that broke the bound would show up in it.
            (let ((me self)
                  (mark (trace-len "carry"))
                  (heavy 6)
                  ;; large enough that a request is delivered in pieces and
                  ;; its decode is real work, without being a frame the cap
                  ;; would refuse
                  (props-bytes (* 1024 1024))
                  ;; ANNOUNCED, NEVER COMPLETED. 64 MiB is exactly the
                  ;; frame cap, so it is accepted, and every byte behind
                  ;; it is buffered rather than parsed. The flood ceiling
                  ;; below stays far under it, so no render is ever
                  ;; started on this garbage.
                  (announce (* 64 1024 1024))
                  (chunk-bytes 65536)
                  ;; IN FLIGHT AT ONCE, and bounded on purpose. Handing
                  ;; libuv the whole flood in one go measures nothing --
                  ;; its write queue is unbounded, so the bytes would sit
                  ;; on THIS side either way and the peer would never feel
                  ;; the closed window. A small window makes the stall
                  ;; real and also caps what can still drain after the
                  ;; peer is told to stop.
                  (window 64)
                  (max-chunks 768))
              (spawn
                (lambda ()
                  (tcp-connect! "127.0.0.1" carry-port self)
                  (receive (after 3000 (send me (vector 'flood 'no-connect)))
                    (`#(tcp-connect-failed ,e) (send me (vector 'flood 'no-connect)))
                    (`#(tcp-connected ,ca)
                      (tcp-read-start! ca)
                      (warm-up! ca 913)
                      (let ((stop (box #f))
                            (accepted (box 0))
                            (props (make-string props-bytes #\x)))
                        ;; the requests and the announcement in one write,
                        ;; so the flood is strictly BEHIND them in the
                        ;; stream and cannot be reached until they are
                        ;; done
                        (let build ((k 0) (acc (make-bytevector 0)))
                          (if (= k heavy)
                              (tcp-write! ca
                                          (bv-append
                                            acc
                                            (let ((h (make-bytevector 4)))
                                              (bytevector-u32-set!
                                                h 0 announce (endianness big))
                                              h))
                                          #f)
                              (build (+ k 1)
                                     (bv-append acc (qframe (+ 50 k) "eat" props)))))
                        (spawn
                          (lambda ()
                            (let ((chunk (make-bytevector chunk-bytes 120))
                                  (w self))
                              (let pump ((issued 0) (done 0))
                                (cond
                                  ((or (unbox stop) (>= issued max-chunks)) 'done)
                                  ((< (- issued done) window)
                                   (if (guard (e (#t #f))
                                         (tcp-write! ca chunk
                                                     (lambda (st)
                                                       (send w (vector 'wrote st))))
                                         #t)
                                       (pump (+ issued 1) done)
                                       'done))
                                  (else
                                   (receive (after 8000 'done)
                                     (`#(wrote ,st)
                                       (set-box! accepted
                                                 (+ (unbox accepted) chunk-bytes))
                                       (pump issued (+ done 1))))))))))
                        ;; THE FLOOD STOPS WHEN THE REQUESTS ARE ANSWERED.
                        ;; The connection still has a 400ms window after
                        ;; that and reads are on for all of it, so a peer
                        ;; left running would push megabytes through the
                        ;; one state this is not measuring.
                        (let wait ((acc (make-bytevector 0)) (closed #f))
                          (if closed
                              (send me (vector 'flood
                                               (list (count-frames acc)
                                                     (unbox accepted))))
                              (begin
                                (when (>= (count-frames acc) heavy)
                                  (set-box! stop #t))
                                (receive (after 30000
                                           (set-box! stop #t)
                                           (send me (vector 'flood 'timeout)))
                                  (`#(tcp-data ,bv) (wait (bv-append acc bv) closed))
                                  (`#(tcp-eof) (set-box! stop #t) (wait acc #t))
                                  (`#(tcp-error ,e)
                                    (set-box! stop #t) (wait acc #t)))))))))))
              (receive (after 45000 (fail "flood probe never answered"))
                (`#(flood ,r)
                  ;; ...AND THE PRESSURE WAS REAL. A run in which the
                  ;; requests were never answered, or in which the peer
                  ;; never got a megabyte onto the wire, proves nothing
                  ;; about where the bytes ended up.
                  (check "the pipelined requests are all answered under a flood"
                         (and (pair? r) (= (car r) heavy)))
                  (check "the peer did get a flood onto the wire"
                         (and (pair? r) (>= (cadr r) (* 1024 1024))))
                  ;; ...AND THE FLOOD DID NOT KEEP IT ALIVE. A connection
                  ;; whose deadline is renewed by unparseable bytes is the
                  ;; failure the half-frame deadline exists to stop, and a
                  ;; flood is the cheapest way to try it: the wait above
                  ;; only ends on the close, so a run that reaches here at
                  ;; all saw one.
                  (check "the flooded connection is still closed on its deadline"
                         (pair? r))
                  (unless (pair? r)
                    (display "  [info] flood probe: ") (write r) (newline))
                  (let* ((mine (trace-conn-of-id "carry" 913))
                         ;; UP TO THE LAST REQUEST BEING ANSWERED, and
                         ;; over the whole connection, reported separately.
                         ;; Reads being on while this loop WAITS is the
                         ;; correct state and a half frame is entitled to
                         ;; be read then, up to the frame cap -- so the two
                         ;; numbers are different questions, and neither is
                         ;; asserted on (see the note above).
                         (during (and mine
                                      (trace-max-until
                                        "carry" mine mark "buffered="
                                        (string-append
                                          "answer id="
                                          (number->string (+ 50 heavy -1))))))
                         (total (and mine
                                     (trace-max-until "carry" mine mark
                                                      "buffered=" "close deadline"))))
                    (check "the flood probe's own connection is identified" (and mine #t))
                    (display (string-append
                               "  [info] flooded connection held at most "
                               (if during (number->string (div during 1024)) "?")
                               " KiB while answering and "
                               (if total (number->string (div total 1024)) "?")
                               " KiB over its life; the peer got "
                               (if (pair? r) (number->string (div (cadr r) 1024)) "?")
                               " KiB accepted onto the wire\n"))
                    ;; The one thing the frame cap really does promise: a
                    ;; connection cannot hold more than the frame it
                    ;; announced, whatever the peer does behind it.
                    (check "the flood never takes the connection past the frame cap"
                           (and total (< total (* 64 1024 1024))))))))

            ;; ---- a half frame dies on its deadline, busy worker or not ---
            ;;
            ;; A peer that keeps the worker busy sees its own window pass
            ;; inside someone else's render, and sends junk bytes after it
            ;; in the hope that a reader which could not have looked
            ;; sooner will forgive them. It gets nothing: the connection
            ;; is closed at the first render boundary after its deadline,
            ;; and the late bytes are never even delivered to it. Four
            ;; rounds of trying, and the close lands at the first one.
            ;;
            ;; This is the case a forgiving reader would have gotten
            ;; wrong, so it stays as the guard on ever adding one.
            (let ((me self)
                  (mark (trace-len "carry")))
              (spawn
                (lambda ()
                  (tcp-connect! "127.0.0.1" carry-port self)
                  (receive (after 3000 (send me (vector 'renew 'no-connect)))
                    (`#(tcp-connect-failed ,e) (send me (vector 'renew 'no-connect)))
                    (`#(tcp-connected ,ca)
                      (tcp-read-start! ca)
                      (warm-up! ca 911)
                      (let ((fa (qframe 11 "hello" "{\"name\":\"L\"}"))
                            (t0 (now-ms))
                            (watcher self)
                            (rounds 4))
                        ;; a prefix and nothing else, ever
                        (tcp-write! ca (let ((h (make-bytevector 4)))
                                         (bytevector-copy! fa 0 h 0 4)
                                         h)
                                    #f)
                        (spawn
                          (lambda ()
                            ;; each round: a render that STRADDLES the
                            ;; window (starts inside it, ends after it),
                            ;; then one junk byte while the worker is
                            ;; still inside that render
                            (let round ((k 0))
                              (when (< k rounds)
                                (sleep-ms 250)
                                ;; EACH RENDER IS ASSERTED. Every failure
                                ;; path here was (void), so a port
                                ;; collision or a worker that had not come
                                ;; up left no render straddling anything
                                ;; and the probe passed having tested
                                ;; nothing. A round of this review claimed
                                ;; in its commit message to have fixed
                                ;; that here; it fixed it in the probe
                                ;; above and not in this one.
                                (spawn (lambda ()
                                         (tcp-connect! "127.0.0.1" carry-port self)
                                         (receive (after 2000
                                                    (send watcher (vector 'rnd 'no-connect)))
                                           (`#(tcp-connect-failed ,e)
                                             (send watcher (vector 'rnd 'no-connect)))
                                           (`#(tcp-connected ,cb)
                                             (tcp-read-start! cb)
                                             (tcp-write! cb (qframe (+ 20 k) "slow" "{}") #f)
                                             (receive (after 3000
                                                        (send watcher (vector 'rnd 'no-answer)))
                                               (`#(tcp-data ,bv)
                                                 (send watcher (vector 'rnd 'rendered)))
                                               (`#(tcp-eof) (send watcher (vector 'rnd 'eof)))
                                               (`#(tcp-error ,e)
                                                 (send watcher (vector 'rnd 'err))))))))
                                (sleep-ms 50)
                                (guard (e (#t (void)))
                                  (tcp-write! ca (let ((b (make-bytevector 1)))
                                                   (bytevector-u8-set! b 0 7)
                                                   b)
                                              #f))
                                (sleep-ms 700)
                                (round (+ k 1))))))
                        ;; the close is reported with how many renders
                        ;; actually straddled a window by then: a close
                        ;; that happened because nothing was rendering
                        ;; proves nothing about forgiveness
                        ;; THE CLOSE DOES NOT END THE WAIT. A render that
                        ;; straddled the window finishes at about the same
                        ;; instant the connection is closed for it, so
                        ;; deciding on the eof alone reported "no render"
                        ;; once in three runs -- a race in the probe, not
                        ;; in the worker. The close time is recorded and
                        ;; the rivals are given a moment to report.
                        (let wait ((nrend 0) (bad #f) (closed #f))
                          (if (and closed (> nrend 0))
                              (send me (vector 'renew closed))
                              (receive (after (if closed 2000 12000)
                                         (send me (vector 'renew
                                                          (if closed
                                                              (cons 'no-render bad)
                                                              'never-closed))))
                                (`#(rnd rendered) (wait (+ nrend 1) bad closed))
                                (`#(rnd ,other) (wait nrend (or bad other) closed))
                                (`#(tcp-data ,bv) (wait nrend bad closed))
                                (`#(tcp-eof)
                                  (wait nrend bad (or closed (- (now-ms) t0))))
                                (`#(tcp-error ,e)
                                  (wait nrend bad (or closed (- (now-ms) t0))))))))))))
              (receive (after 20000 (fail "late-byte probe never answered"))
                (`#(renew ,r)
                  ;; one straddling render is ~950ms; four rounds of
                  ;; renewal ran past 3s in the version that forgave them
                  (check "a half frame is closed on its deadline whatever else the worker is doing"
                         (and (number? r) (< r 2000)))
                  ;; ...for the RIGHT reason: refused on a late read that
                  ;; completed nothing and had nothing more behind it,
                  ;; rather than closed by an unrelated framing error.
                  (let ((mine (trace-conn-of-id "carry" 911)))
                    (check "the late-byte probe's own connection is identified"
                           (and mine #t))
                    ;; and the close was decided on a read that WAS overdue:
                    ;; the ordinary timed-receive timeout closes too, and
                    ;; without this field a close for that reason counted
                    (check "it was refused on a late read with nothing left to take"
                           (> (trace-count-of "carry" mine mark "close-late=1") 0)))
                  (display "  [info] half frame closed after ") (write r)
                  (display "ms\n"))))

            ;; ---- the cap is checked where it is given --------------------
            ;;
            ;; Deleting the validation outright changed nothing anywhere,
            ;; which is what an unchecked public option looks like.
            (let ((bad (lambda (v)
                         (guard (e (#t 'raised))
                           (let ((p (qjspool (list (cons "127.0.0.1" good-port))
                                             (list (cons 'max-requests-per-connection v)))))
                             (qjspool-close! p)
                             'accepted)))))
              (check "a cap of zero is refused" (eq? (bad 0) 'raised))
              (check "a negative cap is refused" (eq? (bad -1) 'raised))
              (check "an inexact cap is refused" (eq? (bad 2.0) 'raised))
              ;; 2^32 ids, the first of them 0, so 2^32 requests fit and
              ;; 2^32+1 does not
              (check "a cap wider than the id field is refused"
                     (eq? (bad #x100000001) 'raised))
              (check "a cap of exactly the id space is allowed"
                     (eq? (bad #x100000000) 'accepted)))

            ;; A LONE CONNECTION CANNOT BE RECYCLED. Nothing rebuilds it,
            ;; so a cap it appears to accept would brick the handle at the
            ;; cap instead of recycling it -- which is what it did.
            (check "a lone connection refuses a cap it cannot honour"
                   (eq? (guard (e (#t 'raised))
                          (let ((h (qjspool-connect
                                     "127.0.0.1" good-port
                                     '((max-requests-per-connection . 2)))))
                            (qjspool-close! h)
                            'accepted))
                        'raised))

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
