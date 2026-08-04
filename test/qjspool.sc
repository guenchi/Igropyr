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
")

(define good-port 19731)
(define spin-port 19732)
(define half-port 19733)

(define (write-bundle!)
  (when (file-exists? bundle-path) (delete-file bundle-path))
  (call-with-output-file bundle-path (lambda (p) (display bundle p))))

(define (pid-file name) (string-append "/tmp/igropyr-qjsw-" name ".pid"))

;; Backgrounded, because `system` blocks the ONE OS thread until the child
;; exits -- a foreground worker would deadlock the test against itself.
;; The pid is recorded rather than matched by name later: pkill -f does not
;; match reliably in every sandbox, and a leaked worker holds its port for
;; the next run.
(define (spawn-worker! name port timeout-ms)
  (system (string-append "scheme --script igropyr/qjs-worker.sc 127.0.0.1 "
                         (number->string port) " " bundle-path
                         " timeout-ms=" (number->string timeout-ms)
                         ;; short enough to be observable: the default is
                         ;; half a minute, which is right in production and
                         ;; useless in a test
                         " partial-frame-ms=1200"
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
    (spawn-worker! "good" good-port 800)
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
      (when (file-exists? bundle-path) (delete-file bundle-path))
      (if (= failures 0)
          (display "qjspool: all tests passed\n")
          (begin (display (number->string failures)) (display " failures\n")))
      (exit (if (= failures 0) 0 1)))))
