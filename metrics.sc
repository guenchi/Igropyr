#!chezscheme
;;; (igropyr metrics) -- Prometheus metrics.
;;;
;;; A gen-server accumulates per-status request counts and request
;;; duration; a middleware records each request; an endpoint renders
;;; everything (plus http-stats connection/pool gauges) in Prometheus
;;; text format.
;;;
;;;   (define m (make-metrics))                    ; at boot
;;;   (app-use app (metrics-middleware m))         ; record every request
;;;   ;; after app-listen returns the server:
;;;   (app-get app "/metrics" (metrics-endpoint m srv))
;;;
;;; Business counters ride the same collector -- register nothing,
;;; just count; each name renders as its own TYPE counter family:
;;;
;;;   (metrics-count! m "iter_lookup_outcome_total" '(("outcome" . "hit")))
;;;   (metrics-count! m "jobs_done_total" '() 5)    ; labels optional, +n form
;;;   ;; -> iter_lookup_outcome_total{outcome="hit"} 1
;;;
;;; This library is the SIGNAL side only: it collects and it serializes,
;;; and it does not care whether the reader is curl, Prometheus, a
;;; browser, or a Goeteia app. The same collector renders three ways --
;;;
;;;   (app-get app "/metrics"     (metrics-endpoint m srv))  ; Prometheus
;;;   (app-get app "/stats.json"  (metrics-json m srv))      ; JSON snapshot
;;;   (app-get app "/stats.sexpr" (metrics-sexpr m srv))     ; sexpr snapshot
;;;
;;; -- and metrics-snapshot returns that same datum as a Scheme value
;;; for in-process callers. The browser dashboard PAGE (and a batteries-
;;; included admin listener) lives in (igropyr dashboard), which consumes
;;; these signals; presentation is not this library's concern.
;;;
;;; Cluster view: on a node (after node-start!), announce the local
;;; summary once --
;;;
;;;   (metrics-announce! m srv)
;;;
;;; -- and every peer that did the same shows up in the snapshot's
;;; "cluster" member (uptime, connections, requests, 5xx, pool), fetched
;;; over the existing node links by rcall; no extra HTTP exposure, no
;;; cross-origin fetches. Without node-start! "cluster" is null.

(library (igropyr metrics)
  (export make-metrics metrics-middleware metrics-endpoint metrics-count!
          metrics-snapshot metrics-json metrics-sexpr metrics-announce!)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr gen-server)
          (igropyr http) (igropyr express)
          (only (igropyr node) node-self node-peers rcall))

  ;; state: #(status-count-ht duration-sum-box duration-count-box
  ;;          custom-ht)  where custom-ht: name -> (label-string -> count)
  (define (metrics-init)
    (vector (make-eqv-hashtable) (box 0) (box 0)
            (make-hashtable string-hash string=?)))

  (define (metrics-cast msg st)
    (case (vector-ref msg 0)
      ((record)
       (let ((status (vector-ref msg 1)) (dur (vector-ref msg 2)))
         (hashtable-update! (vector-ref st 0) status (lambda (n) (+ n 1)) 0)
         (set-box! (vector-ref st 1) (+ (unbox (vector-ref st 1)) dur))
         (set-box! (vector-ref st 2) (+ (unbox (vector-ref st 2)) 1))))
      ((count)
       (let* ((name (vector-ref msg 1))
              (labels (vector-ref msg 2))
              (n (vector-ref msg 3))
              (custom (vector-ref st 3))
              (inner (or (hashtable-ref custom name #f)
                         (let ((h (make-hashtable string-hash string=?)))
                           (hashtable-set! custom name h)
                           h))))
         (hashtable-update! inner labels (lambda (v) (+ v n)) 0))))
    st)

  (define (hashtable->alist ht)
    (let-values (((ks vs) (hashtable-entries ht)))
      (let loop ((i 0) (acc '()))
        (if (= i (vector-length ks))
            acc
            (loop (+ i 1) (cons (cons (vector-ref ks i) (vector-ref vs i)) acc))))))

  ;; call 'dump -> #(status-alist duration-sum duration-count custom-alist)
  ;; custom-alist: ((name . ((label-string . count) ...)) ...)
  (define (metrics-call msg from st)
    (values
      (vector
        (hashtable->alist (vector-ref st 0))
        (unbox (vector-ref st 1))
        (unbox (vector-ref st 2))
        (map (lambda (kv) (cons (car kv) (hashtable->alist (cdr kv))))
             (hashtable->alist (vector-ref st 3))))
      st))

  ;; a metrics collector is just the gen-server pid
  (define (make-metrics)
    (gen-server-start metrics-init metrics-call metrics-cast))

  ;; Prometheus label escaping: backslash, double-quote, newline
  (define (escape-label-value v)
    (let-values (((p get) (open-string-output-port)))
      (do ((i 0 (+ i 1))) ((= i (string-length v)) (get))
        (let ((c (string-ref v i)))
          (case c
            ((#\\) (put-string p "\\\\"))
            ((#\") (put-string p "\\\""))
            ((#\newline) (put-string p "\\n"))
            (else (put-char p c)))))))

  ;; Prometheus name rules: metric [a-zA-Z_:][a-zA-Z0-9_:]*, label name
  ;; the same minus the colon
  (define (valid-name? s colon-ok?)
    (and (string? s) (> (string-length s) 0)
         (let loop ((i 0))
           (or (= i (string-length s))
               (let ((c (string-ref s i)))
                 (and (or (char<=? #\a c #\z) (char<=? #\A c #\Z)
                          (char=? c #\_)
                          (and colon-ok? (char=? c #\:))
                          (and (> i 0) (char<=? #\0 c #\9)))
                      (loop (+ i 1))))))))

  ;; labels alist -> "{k=\"v\",...}" or "" -- validated and SORTED by
  ;; label name: Prometheus treats label order as insignificant, so two
  ;; orderings of one set must map to ONE series -- unsorted they would
  ;; render as duplicate samples and fail the whole scrape. Cached per
  ;; distinct label set (label sets on the request path are near-
  ;; constant), so sort/escape work runs per series, not per increment;
  ;; the cache grows exactly as the collector's own series table does.
  (define label-cache (make-hashtable equal-hash equal?))

  (define (build-label-string labels)
    (for-each
      (lambda (kv)
        (unless (and (pair? kv) (valid-name? (car kv) #f) (string? (cdr kv)))
          (assertion-violation 'metrics-count! "bad label (name . value)" kv)))
      labels)
    (let ((sorted (sort (lambda (a b) (string<? (car a) (car b))) labels)))
      (let dup ((l sorted))
        (when (and (pair? l) (pair? (cdr l)))
          (when (string=? (caar l) (caadr l))
            (assertion-violation 'metrics-count! "duplicate label name" (caar l)))
          (dup (cdr l))))
      (if (null? sorted)
          ""
          (let-values (((p get) (open-string-output-port)))
            (put-char p #\{)
            (let loop ((l sorted) (first #t))
              (unless (null? l)
                (unless first (put-char p #\,))
                (put-string p (caar l))
                (put-string p "=\"")
                (put-string p (escape-label-value (cdar l)))
                (put-string p "\"")
                (loop (cdr l) #f)))
            (put-char p #\})
            (get)))))

  (define (label-string labels)
    (or (hashtable-ref label-cache labels #f)
        (let ((s (build-label-string labels)))
          (hashtable-set! label-cache labels s)
          s)))

  ;; count a business event: name is the Prometheus family, labels an
  ;; alist of (name . value) strings, n the increment (default 1).
  ;; Validated HERE, in the caller: gen-server-cast is fire-and-forget,
  ;; so bad input must fail the call site loudly instead of raising
  ;; inside the shared collector and silently killing every metric.
  ;; igropyr_* is reserved -- a custom family colliding with a built-in
  ;; one would render a duplicate # TYPE block and invalidate the scrape.
  (define reserved-prefix "igropyr_")

  (define (reserved-name? name)
    (let ((n (string-length reserved-prefix)))
      (and (>= (string-length name) n)
           (string=? (substring name 0 n) reserved-prefix))))

  (define metrics-count!
    (case-lambda
      ((m name labels) (metrics-count! m name labels 1))
      ((m name labels n)
       (unless (valid-name? name #t)
         (assertion-violation 'metrics-count! "bad metric name" name))
       (when (reserved-name? name)
         (assertion-violation 'metrics-count!
           "igropyr_ names are reserved for built-in families" name))
       (unless (and (real? n) (not (nan? n)))
         (assertion-violation 'metrics-count! "increment must be a real number" n))
       (gen-server-cast m (vector 'count name (label-string labels) n)))))

  ;; record each request's final status and wall-clock duration
  (define (metrics-middleware m)
    (lambda (req res next)
      (let ((t0 (now-ms)))
        (next)
        (gen-server-cast m (vector 'record (res-status res) (- (now-ms) t0))))))

  ;; ---- Prometheus text rendering ---------------------------------------

  (define (line . parts) (apply string-append (append parts (list "\n"))))

  (define (render-custom custom)
    (apply string-append
      (map (lambda (family)
             (string-append
               (line "# TYPE " (car family) " counter")
               (apply string-append
                 (map (lambda (lv)
                        (line (car family) (car lv) " "
                              (number->string (cdr lv))))
                      (cdr family)))))
           custom)))

  (define (render dump stats)
    (let ((counts (vector-ref dump 0))
          (sum (vector-ref dump 1))
          (count (vector-ref dump 2))
          (custom (vector-ref dump 3)))
      (define (stat key) (number->string (cdr (assq key stats))))
      (string-append
        (render-custom custom)
        (line "# HELP igropyr_requests_total HTTP requests by status")
        (line "# TYPE igropyr_requests_total counter")
        (apply string-append
          (map (lambda (kv)
                 (line "igropyr_requests_total{status=\""
                       (number->string (car kv)) "\"} "
                       (number->string (cdr kv))))
               counts))
        (line "# HELP igropyr_request_duration_ms Request duration summary")
        (line "# TYPE igropyr_request_duration_ms summary")
        (line "igropyr_request_duration_ms_sum " (number->string sum))
        (line "igropyr_request_duration_ms_count " (number->string count))
        (line "# TYPE igropyr_connections gauge")
        (line "igropyr_connections " (stat 'connections))
        (line "# TYPE igropyr_uptime_ms gauge")
        (line "igropyr_uptime_ms " (stat 'uptime-ms))
        (line "# TYPE igropyr_pool_workers gauge")
        (line "igropyr_pool_busy " (stat 'busy))
        (line "igropyr_pool_idle " (stat 'idle))
        (line "igropyr_pool_pending " (stat 'pending)))))

  ;; endpoint handler; srv is the http-server from app-listen
  (define (metrics-endpoint m srv)
    (lambda (req res)
      (let ((dump (gen-server-call m (vector 'dump)))
            (stats (http-stats srv)))
        (set-header! res "Content-Type" "text/plain; version=0.0.4")
        (res-send! res (string->utf8 (render dump stats))))))

  ;; ---- cluster view -------------------------------------------------------

  ;; the registered name peers rcall for a node's summary
  (define node-service 'igropyr-metrics)
  (define peer-timeout-ms 1000)

  ;; compact summary of this node, wire-safe (symbols/numbers only in
  ;; the alist -- it crosses node links)
  (define (node-summary m srv)
    (let ((dump (gen-server-call m (vector 'dump)))
          (stats (http-stats srv)))
      (define (stat k) (cdr (assq k stats)))
      (let loop ((l (vector-ref dump 0)) (total 0) (err5 0))
        (if (pair? l)
            (loop (cdr l) (+ total (cdar l))
                  (if (>= (caar l) 500) (+ err5 (cdar l)) err5))
            `((uptime-ms . ,(stat 'uptime-ms))
              (connections . ,(stat 'connections))
              (busy . ,(stat 'busy))
              (idle . ,(stat 'idle))
              (pending . ,(stat 'pending))
              (requests . ,total)
              (err5xx . ,err5)
              (duration-sum . ,(vector-ref dump 1))
              (duration-count . ,(vector-ref dump 2)))))))

  ;; Serve this node's summary to the mesh under the well-known name.
  ;; Call once after node-start! and app-listen; every peer that did
  ;; the same appears in each other's dashboard cluster table.
  (define (metrics-announce! m srv)
    (gen-server-start-named node-service
      (lambda () #f)
      (lambda (msg from st) (values (node-summary m srv) st))
      (lambda (msg st) st)))

  ;; summary alist -> JSON fields; anything missing or garbled in a
  ;; peer's reply becomes null -- a broken peer must not take the local
  ;; endpoint down
  (define summary-fields
    '((uptime-ms . "uptime_ms") (connections . "connections")
      (busy . "pool_busy") (idle . "pool_idle") (pending . "pool_pending")
      (requests . "requests") (err5xx . "err_5xx")
      (duration-sum . "duration_sum_ms") (duration-count . "duration_count")))

  (define (summary-json summary)
    (map (lambda (f)
           (cons (cdr f)
                 (let ((p (guard (e (#t #f)) (assq (car f) summary))))
                   (if (and (pair? p) (number? (cdr p))) (cdr p) 'null))))
         summary-fields))

  ;; the "cluster" JSON member: self plus one rcall per connected peer
  ;; (each bounded by peer-timeout-ms; a peer without metrics-announce!
  ;; renders up=false with null data). 'null when node-start! never ran.
  (define (cluster-json m srv)
    (if (not (node-self))
        'null
        `(("self" . ,(symbol->string (node-self)))
          ("nodes"
           . ,(list->vector
                (cons
                  ;; guard the SELF summary too: if the local collector/pool
                  ;; is unhealthy it renders up=#f + null, not a 500 (same as
                  ;; a peer that failed to answer)
                  (let ((self-sum (guard (e (#t #f)) (node-summary m srv))))
                    (append
                      `(("name" . ,(symbol->string (node-self)))
                        ("self" . #t) ("up" . ,(and self-sum #t)))
                      (summary-json (or self-sum '()))))
                  (map (lambda (peer)
                         (let ((s (guard (e (#t #f))
                                    (rcall peer node-service 'summary
                                           peer-timeout-ms))))
                           (append
                             `(("name" . ,(symbol->string peer))
                               ("self" . #f) ("up" . ,(and s #t)))
                             (summary-json (or s '())))))
                       (node-peers))))))))

  ;; ---- snapshot signal --------------------------------------------------

  ;; Everything /metrics renders, as a Scheme value in the JSON data
  ;; model (string-keyed alists = objects, vectors = arrays, 'null =
  ;; null). One builder, so the JSON and sexpr encodings can never
  ;; drift; in-process callers can consume it directly too.
  (define (metrics-snapshot m srv)
    ;; degrade, don't 500: if the collector is overloaded (gen-server-call
    ;; times out) or the pool supervisor is stuck (http-stats raises), the
    ;; health endpoint must still answer -- with nulls/zeros, not an error.
    (let ((dump (guard (e (#t (vector '() 0 0 '())))
                  (gen-server-call m (vector 'dump))))
          (stats (guard (e (#t '())) (http-stats srv))))
      (define (stat key) (let ((p (assq key stats))) (if p (cdr p) 'null)))
      `(("uptime_ms" . ,(stat 'uptime-ms))
        ("connections" . ,(stat 'connections))
        ("pool" . (("busy" . ,(stat 'busy))
                   ("idle" . ,(stat 'idle))
                   ("pending" . ,(stat 'pending))))
        ("requests" . ,(map (lambda (kv)
                              (cons (number->string (car kv)) (cdr kv)))
                            (vector-ref dump 0)))
        ("duration_sum_ms" . ,(vector-ref dump 1))
        ("duration_count" . ,(vector-ref dump 2))
        ("custom"
         . ,(list->vector
              (map (lambda (fam)
                     `(("name" . ,(car fam))
                       ("series"
                        . ,(list->vector
                             (map (lambda (lv)
                                    `(("labels" . ,(car lv))
                                      ("value" . ,(cdr lv))))
                                  (cdr fam))))))
                   (vector-ref dump 3))))
        ("cluster" . ,(cluster-json m srv)))))

  ;; the snapshot as JSON (dashboard polls it; doubles as a JSON API)
  (define (metrics-json m srv)
    (lambda (req res) (send-json! res (metrics-snapshot m srv))))

  ;; the snapshot as sexpr -- same shape, for Scheme/Goeteia consumers
  ;; and any reader that would rather read one datum than parse JSON
  (define (metrics-sexpr m srv)
    (lambda (req res) (send-sexpr! res (metrics-snapshot m srv))))
)
