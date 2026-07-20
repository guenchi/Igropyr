#!chezscheme
;;; (igropyr ssr) -- cached SSR over quickjs, both cache backends. A render
;;; caches by key; a second identical call HITS (no re-render, proven by a JS
;;; render counter); invalidate/clear drop entries; stats report hits/misses;
;;; a throwing render surfaces via ssr-try-render without being cached (engine
;;; recovers via crash-only rebuild). The redis-backend checks run only when a
;;; local Redis answers (else skipped). SHIM-GATED like test/quickjs.sc: skips
;;; cleanly when the QuickJS dylib is absent, so run-all stays green without it.

(import (chezscheme) (igropyr actor) (igropyr ssr)
        (only (igropyr quickjs) qjs-call!)
        (only (igropyr redis) redis-connect redis redis-close!))

(define (shim-present?)
  (or (let ((e (getenv "IGROPYR_QUICKJS_SO"))) (and e (> (string-length e) 0)))
      (file-exists? "igropyr/libigropyr-quickjs.dylib")
      (file-exists? ".build-links/igropyr/libigropyr-quickjs.dylib")
      (file-exists? "libigropyr-quickjs.dylib")
      (file-exists? "igropyr/libigropyr-quickjs.so")
      (file-exists? ".build-links/igropyr/libigropyr-quickjs.so")
      (file-exists? "libigropyr-quickjs.so")))

(unless (shim-present?)
  (display "ssr: shim not built, test skipped\n") (exit 0))

(define failures 0)
(define (check label ok)
  (unless ok (set! failures (+ failures 1)) (display "FAIL ") (display label) (newline)))
(define (L p s) (string-append p s))

;; render() counts its calls in a JS global so a cache HIT is provable (N does
;; not advance on a hit); count() reads it; boom() throws.
(define bundle "
var N = 0;
function render(j){ N++; var p = JSON.parse(j); return '<h1>'+p.t+'</h1>'; }
function slowRender(j){ N++; var s=0; for(var i=0;i<8000000;i++){s+=i;} if(s<0)return 'x';
  var p = JSON.parse(j); return '<h1>'+p.t+'</h1>'; }
function count(_){ return '' + N; }
function boom(j){ throw new Error('render failed'); }
")
(define (N) (string->number (qjs-call! "count" "")))

;; core cache behavior for ANY backend; assumes N == 0 (engine freshly booted)
(define (run-cache-checks r p)
  (check (L p "render-a")    (string=? (ssr-render r "render" '(("t" . "A")) '((key . "/a"))) "<h1>A</h1>"))
  (check (L p "rendered-1")  (= 1 (N)))
  (check (L p "hit")         (string=? (ssr-render r "render" '(("t" . "A")) '((key . "/a"))) "<h1>A</h1>"))
  (check (L p "no-rerender") (= 1 (N)))
  (check (L p "render-b")    (string=? (ssr-render r "render" '(("t" . "B")) '((key . "/b"))) "<h1>B</h1>"))
  (check (L p "rendered-2")  (= 2 (N)))
  (ssr-invalidate! r "/a")
  (check (L p "after-inval") (string=? (ssr-render r "render" '(("t" . "A")) '((key . "/a"))) "<h1>A</h1>"))
  (check (L p "rerender-3")  (= 3 (N)))
  (let ((s (ssr-stats r)))
    (check (L p "stats-hits")   (>= (cdr (assq 'hits s)) 1))
    (check (L p "stats-misses") (>= (cdr (assq 'misses s)) 3)))
  (ssr-clear! r)
  (check (L p "after-clear") (string=? (ssr-render r "render" '(("t" . "B")) '((key . "/b"))) "<h1>B</h1>"))
  (check (L p "rerender-4")  (= 4 (N))))

(start-scheduler
  (lambda ()
    ;; ---- memory backend (default) ----
    (let ((r (make-ssr bundle)))
      (run-cache-checks r "mem-")
      ;; default key (sha256 of props): same props hits the second time
      (let ((n0 (N)))
        (ssr-render r "render" '(("t" . "C")))
        (let ((n1 (N)))
          (check "mem-defaultkey-once" (= (+ n0 1) n1))
          (ssr-render r "render" '(("t" . "C")))
          (check "mem-defaultkey-hit" (= n1 (N)))))
      ;; try-render on a throwing fn -> (values #f text), not cached
      (let-values (((ok txt) (ssr-try-render r "boom" '(("t" . "X")) '((key . "/boom")))))
        (check "mem-tryrender-fails" (not ok))
        (check "mem-tryrender-text"  (and (string? txt) (> (string-length txt) 0))))
      ;; engine recovers after the throw (crash-only rebuild)
      (check "mem-recovers" (string=? (ssr-render r "render" '(("t" . "Z")) '((key . "/z"))) "<h1>Z</h1>")))

    ;; ---- redis backend (only when a local Redis answers) ----
    (let ((conn (guard (e (#t #f)) (redis-connect "127.0.0.1" 6379))))
      (if (not conn)
          (display "ssr: redis not reachable, redis-backend checks skipped\n")
          (let ((r (make-ssr bundle `((cache . (redis ,conn "ssrtest:"))))))  ; reboots engine -> N=0
            (ssr-clear! r)                     ; start from a clean namespace
            (run-cache-checks r "redis-")
            ;; the rendered HTML actually lives in Redis -> any peer node hits it
            (ssr-render r "render" '(("t" . "X")) '((key . "/x")))
            (check "redis-in-store" (equal? (redis conn "GET" "ssrtest:/x") "<h1>X</h1>"))
            (ssr-clear! r)                     ; cleanup + prove clear reaches Redis
            (check "redis-cleared" (not (redis conn "GET" "ssrtest:/x")))
            (redis-close! conn))))

    ;; ---- single-flight: K concurrent misses on ONE cold key render once ----
    ;; timeout-ms >> the slowRender loop so a slow box can't trip the deadline
    (let ((r (make-ssr bundle '((quickjs . ((timeout-ms . 20000)))))))   ; reboots -> N=0
      (let ((k 4) (me self))
        (do ((i 0 (+ i 1))) ((= i k))
          (spawn (lambda ()
                   (send me (vector 'sf
                     (guard (e (#t 'err))
                       (ssr-render r "slowRender" '(("t" . "H")) '((key . "/hot")))))))))
        (let loop ((got 0) (allok #t))
          (if (= got k)
              (check "sf-all-equal" allok)
              (receive (`#(sf ,html)
                         (loop (+ got 1) (and allok (equal? html "<h1>H</h1>")))))))
        (check "sf-rendered-once" (= 1 (N)))      ; K callers, ONE actual render
        ;; ssr-stats: renders (1) < misses (>=4) proves single-flight dedup
        (check "sf-renders-1"  (= 1 (cdr (assq 'renders (ssr-stats r)))))
        (check "sf-misses->=4" (>= (cdr (assq 'misses (ssr-stats r))) 4))))

    ;; ---- TTL expiry: an entry past ttl-ms re-renders ----
    (let ((r (make-ssr bundle '((ttl-ms . 50)))))    ; reboots -> N=0
      (ssr-render r "render" '(("t" . "T")) '((key . "/ttl")))
      (check "ttl-rendered-1" (= 1 (N)))
      (ssr-render r "render" '(("t" . "T")) '((key . "/ttl")))     ; hit
      (check "ttl-hit" (= 1 (N)))
      (sleep-ms 200)                                               ; past ttl
      (ssr-render r "render" '(("t" . "T")) '((key . "/ttl")))     ; expired -> re-render
      (check "ttl-expired-rerender" (= 2 (N))))

    ;; ---- size cap: over max-entries evicts the soonest-to-expire ----
    (let ((r (make-ssr bundle '((max-entries . 2)))))   ; reboots -> N=0
      (ssr-render r "render" '(("t" . "1")) '((key . "/e1"))) (sleep-ms 5)
      (ssr-render r "render" '(("t" . "2")) '((key . "/e2"))) (sleep-ms 5)
      (ssr-render r "render" '(("t" . "3")) '((key . "/e3")))
      (check "evict-size-capped" (<= (cdr (assq 'size (ssr-stats r))) 2))
      (ssr-render r "render" '(("t" . "1")) '((key . "/e1")))      ; /e1 evicted -> re-render
      (check "evict-rerender" (= 4 (N))))

    ;; ---- single-flight OFF: concurrent misses each render (no dedup) ----
    (let ((r (make-ssr bundle '((single-flight . #f)))))   ; reboots -> N=0
      (let ((k 4) (me self))
        (do ((i 0 (+ i 1))) ((= i k))
          (spawn (lambda ()
                   (send me (vector 'nf (ssr-render r "render" '(("t" . "H")) '((key . "/nf"))))))))
        (let loop ((got 0)) (when (< got k) (receive (`#(nf ,_) (loop (+ got 1))))))
        (check "no-single-flight-each-renders" (= 4 (N)))))

    (if (zero? failures)
        (begin (display "ssr: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
