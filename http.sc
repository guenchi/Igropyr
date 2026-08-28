#!chezscheme
;;; (igropyr http) -- HTTP/1.1 core, in the spirit of Node's `http` module.
;;;
;;; The core knows the protocol, not the framework: it parses requests,
;;; owns the connection lifecycle, runs every request through the fault-
;;; tolerant worker pool, and encodes responses. It exposes exactly one
;;; entry point:
;;;
;;;   (http-listen port (lambda (req res) ...))          ; 8 workers
;;;   (http-listen port (lambda (req res) ...) workers)
;;;
;;; There is no router, no middleware, no MIME table here -- those are
;;; framework concerns; see (igropyr express) for one such layer, or
;;; build your own: anything that produces a (lambda (req res)) handler
;;; sits on the same footing as express.
;;;
;;; Response primitives (the res.end level): set-status!, set-header!,
;;; res-send!. Convenience encoders (JSON, files, ...) belong to layers.
;;;
;;; Connection lifecycle:
;;;   accept -> one reader process per connection (a half-sent request
;;;   parks only its own reader and is reaped by a 30s timeout)
;;;   reader parses request line/headers/body incrementally, then sends
;;;   #(submit-task #(task ,id ,conn ,request)) to the supervisor;
;;;   a pool worker runs the handler and writes the response; the
;;;   write-completion callback tells the reader to parse the next
;;;   request (keep-alive) or closes the connection.

(library (igropyr http)
  (export http-listen http-swap! http-set-ws!
          http-stats http-stats-json http-shutdown! http-write-timeout!
          http-request-deadline!
          ;; A CONTROL CAPABILITY, and named as one here rather than
          ;; described as introspection, which is what an earlier version of
          ;; this comment called it. A live pid is authority, not a
          ;; reading, and this library re-exports send and kill below, so
          ;; whoever holds this can:
          ;;   (kill (http-server-sup srv) 'anything)  -- ends the image,
          ;;       because the pool supervisor is marked critical
          ;;   (send (http-server-sup srv) <datum>)    -- speaks the pool's
          ;;       private protocol directly, around the HTTP layer
          ;; and the pid stops addressing anything once that process dies:
          ;; nothing here mints a replacement. Do not hold it across a
          ;; restart of anything.
          ;;
          ;; THE ARGUMENT THAT IT WAS ALREADY READABLE WAS WRONG. http-stats
          ;; reads the same value internally, and an internal dependency is
          ;; not public access -- reaching the process is a different thing
          ;; from reading a number derived from it.
          ;;
          ;; What it is honestly for: tests and operational checks that must
          ;; act on the supervisor -- the suite that owns the critical
          ;; marking kills it -- and any future deliberate use of the pool's
          ;; lifecycle. NOT for health checking. Something that only wants
          ;; to know whether the pool is still alive should use
          ;; http-server-pool-alive?, which answers without handing over
          ;; the means to end the process.
          http-server-sup http-server-pool-alive?
          ;; record predicates, exported for boundary contracts
          ;; ((igropyr checked) in the framework layers) and any
          ;; user code that wants to type-test req/res values
          request? res?
          req-method req-path req-query req-headers req-header req-body
          req-keep-alive? req-version req-peer req-params req-params-set!
          req-local req-set-local!
          set-status! set-header! set-header-if-unanswered! res-send!
          res-begin! res-write! res-end!
          res-begin-file! res-write-file! res-write-chunk! res-abort-file!
          res-conn res-req res-status res-headers res-keep-alive?
          res-head-request? res-send-head! res-answered?
          res-streaming? res-abort! res-spawn!
          send-response! parse-query
          ;; Re-exported app-facing (igropyr actor) surface, so a core
          ;; application imports this library alone. Advanced primitives
          ;; (link/monitor/trap-exit, spawn&link) stay behind an explicit
          ;; (igropyr actor) import. Re-exporting the same original
          ;; bindings from several libraries is legal in R6RS: every
          ;; import path reaches the same binding, so importing this
          ;; library together with (igropyr actor) or (igropyr express)
          ;; never conflicts.
          start-scheduler spawn send receive self
          sleep-ms kill register whereis process-id)
  (import (chezscheme) (igropyr buffer)
          (igropyr actor) (igropyr libuv) (igropyr otp)
          (igropyr websocket))

  (define header-limit 8192)
  ;; body-limit / pipeline-limit are configurable at http-listen time via the
  ;; 'body-limit option (default 1 MiB). They are set! by http-listen, which
  ;; also keeps cp0 from inlining them as constants, so every parser read sees
  ;; the configured value. Process-global: the last http-listen wins.
  (define body-limit 1048576)
  (define trailer-limit 8192)
  ;; Bytes a client may pipeline while the current handler is still
  ;; producing its response. Without a cap a slow handler or a streaming
  ;; response lets a peer grow the reader's buffer without bound.
  (define pipeline-limit (+ header-limit body-limit))
  (define read-timeout-ms 30000)   ; slow/half requests reaped after this
  ;; Whole-request deadline. read-timeout-ms bounds the gap BETWEEN
  ;; segments and re-arms on every one, so a client sending one byte every
  ;; 29s holds a reader process and its buffer indefinitely -- classic
  ;; slowloris, at trivial cost to the attacker. This caps how long one
  ;; request may take to arrive, however steadily it dribbles.
  (define request-deadline-ms 60000)
  (define await-timeout-ms 60000)  ; reader waits this long for a response

  ;; How long one streamed write may wait for its peer to accept the bytes.
  ;;
  ;; A write parks its process until libuv reports the chunk out, which for a
  ;; peer that has stopped reading is never. The pool's stuck-ms bounds that
  ;; for a POOLED handler -- but a long stream is supposed to be detached
  ;; into its own process (see res-begin!'s docstring), and a spawned process
  ;; is not a pool worker, so nothing bounded it there. That is the shape a
  ;; slow SSE consumer takes: one parked relay per client, forever, while
  ;; whatever feeds it keeps queueing into an unbounded mailbox.
  ;;
  ;; Same 30 s as read-timeout-ms, and for the same reason: that bounds a
  ;; peer who will not SEND, this one a peer who will not READ, and there is
  ;; no case for being more patient with the second. It also matches the
  ;; pool's stuck-ms, so a detached stream is now bounded exactly like the
  ;; pooled handler it was detached from -- detaching was an accidental hole,
  ;; not a deliberately laxer path, so the two should not differ.
  ;;
  ;; This is NOT a liveness timer for the stream: an SSE connection with
  ;; nothing to say is normal and costs no write. Only a write whose bytes
  ;; the kernel refuses can expire, which means the peer's receive window has
  ;; been shut the whole time -- a live consumer drains a chunk in
  ;; milliseconds, and even a bad mobile link in seconds. Whatever feeds the
  ;; stream keeps queueing for this long, so the value is also the ceiling on
  ;; that backlog.
  (define default-write-timeout-ms 30000)
  (define write-timeout-ms default-write-timeout-ms)

  ;; Process-global, like the other ceilings here. 0 restores the old
  ;; unbounded wait, which is only ever right where no untrusted peer can
  ;; reach the port.
  (define (http-write-timeout! ms)
    (unless (and (integer? ms) (exact? ms) (>= ms 0))
      (assertion-violation 'http-write-timeout!
        "timeout must be a nonnegative exact integer (ms); 0 = unbounded" ms))
    (set! write-timeout-ms ms))

  ;; How long ONE request may take to arrive in total, first byte of the
  ;; request line to last byte of the body. Process-global like the rest.
  ;; A positive exact integer: unlike the write timeout there is no useful
  ;; unbounded setting, because "no deadline" is the slowloris this bounds.
  (define (http-request-deadline! ms)
    (unless (and (integer? ms) (exact? ms) (> ms 0))
      (assertion-violation 'http-request-deadline!
        "deadline must be a positive exact integer (ms)" ms))
    (set! request-deadline-ms ms))

  ;; ---- bytevector helpers ------------------------------------------------

  (define empty-bv (make-bytevector 0))

  ;; empty range: no allocation (every bodyless request used to pay
  ;; two empty bytevectors, body and leftover)
  (define (bv-sub bv start end)
    (if (fx>= start end)
        empty-bv
        (let ((r (make-bytevector (fx- end start))))
          (bytevector-copy! bv start r 0 (fx- end start))
          r)))

  ;; ---- request record ------------------------------------------------------

  (define-record-type (request make-request request?)
    (fields
      (immutable method req-method)      ; symbol: GET POST ...
      (immutable path req-path)          ; decoded path string
      (immutable query req-query)        ; alist of (string . string)
      ;; free slot owned by framework layers (e.g. router path params)
      (mutable params req-params req-params-set!)
      (immutable headers req-headers)    ; alist of (symbol . string)
      (immutable body req-body)          ; bytevector
      (immutable keep-alive? req-keep-alive?)
      ;; "HTTP/1.1" | "HTTP/1.0" | 'unsupported -- chunked framing is a
      ;; 1.1 feature and must not be sent to a 1.0 recipient
      (immutable version req-version)
      ;; the connection's peer IP ("a.b.c.d") or #f -- the one client
      ;; identity that cannot be forged by a header
      (immutable peer req-peer)
      ;; per-request scratch alist for middleware to stash values
      ;; (session, authenticated user, ...) for later handlers
      (mutable locals req-locals req-locals-set!)))

  ;; get/set a named value on the request (used by middleware to pass
  ;; data down the chain to the handler)
  (define (req-local req key)
    (let ((p (assq key (req-locals req))))
      (and p (cdr p))))

  (define (req-set-local! req key val)
    (let ((p (assq key (req-locals req))))
      (if p
          (set-cdr! p val)
          (req-locals-set! req (cons (cons key val) (req-locals req))))))

  (define (req-header req name)
    (let ((p (assq name (req-headers req))))
      (and p (cdr p))))

  ;; ---- parsing --------------------------------------------------------------

  (define (string-split s ch)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n) (reverse (cons (substring s start n) acc)))
          ((char=? (string-ref s i) ch)
           (loop (+ i 1) (+ i 1) (cons (substring s start i) acc)))
          (else (loop (+ i 1) start acc))))))

  (define (string-index s ch)
    (let ((n (string-length s)))
      (let scan ((i 0))
        (cond
          ((= i n) #f)
          ((char=? (string-ref s i) ch) i)
          (else (scan (+ i 1)))))))

  ;; %XX escapes are octets of a UTF-8 sequence: collect bytes first,
  ;; decode as UTF-8 once at the end (decoding each %XX to a character
  ;; directly would mangle multi-byte sequences like %E4%B8%AD).
  ;; plus-as-space?: only in query strings does "+" mean a space; in a
  ;; path "+" is a literal plus, so the caller controls it.
  ;; Fast path: no escape present means the string decodes to itself --
  ;; return it unchanged, zero allocation (the overwhelmingly common
  ;; case for paths and query parts).
  (define (percent-decode s plus-as-space?)
    (let ((n (string-length s)))
      (define (plain? i)
        (or (fx= i n)
            (let ((ch (string-ref s i)))
              (and (not (char=? ch #\%))
                   (not (and plus-as-space? (char=? ch #\+)))
                   (plain? (fx+ i 1))))))
      (if (plain? 0)
          s
          (let-values (((p get) (open-bytevector-output-port)))
            (let loop ((i 0))
              (when (fx< i n)
                (let ((ch (string-ref s i)))
                  (cond
                    ((and (char=? ch #\%) (fx< (fx+ i 2) n))
                     (let ((v (string->number (substring s (fx+ i 1) (fx+ i 3)) 16)))
                       (if v
                           (begin (put-u8 p v) (loop (fx+ i 3)))
                           (begin (put-u8 p 37) (loop (fx+ i 1))))))  ; literal '%'
                    ((and plus-as-space? (char=? ch #\+))
                     (put-u8 p 32) (loop (fx+ i 1)))
                    ((char<=? ch #\delete)          ; ASCII: one byte, direct
                     (put-u8 p (char->integer ch)) (loop (fx+ i 1)))
                    (else
                     (put-bytevector p (string->utf8 (string ch)))
                     (loop (fx+ i 1)))))))
            (utf8->string (get))))))

  ;; Collapse "//", drop "." and resolve ".." (RFC 3986 remove_dot_segments),
  ;; so EVERY layer sees the same path. The router matches on segments, which
  ;; silently drops empty ones -- "//admin/x" routes exactly like "/admin/x"
  ;; -- while a guard written the only way the framework allows,
  ;; (string-prefix? "/admin" (req-path req)), compares the raw string and
  ;; does not match. That gap lets a request skip an authentication or
  ;; rate-limit guard and still reach the guarded handler. Normalizing here,
  ;; once, closes it for middleware, the router and static serving alike.
  ;; ".." can never escape the root: it pops a segment only when one exists.
  (define (normalize-path path)
    (let ((n (string-length path)))
      (let loop ((i 0) (start 0) (acc '()))
        (define (emit)
          (if (fx> i start)
              (let ((seg (substring path start i)))
                (cond
                  ((string=? seg ".") acc)
                  ((string=? seg "..") (if (pair? acc) (cdr acc) acc))
                  (else (cons seg acc))))
              acc))                                  ; empty segment: drop
        (cond
          ((fx= i n)
           (let ((segs (reverse (emit))))
             (if (null? segs)
                 "/"
                 (let build ((l segs) (out '()))
                   (if (null? l)
                       (apply string-append (reverse out))
                       (build (cdr l) (cons (car l) (cons "/" out))))))))
          ((char=? (string-ref path i) #\/) (loop (fx+ i 1) (fx+ i 1) (emit)))
          (else (loop (fx+ i 1) start acc))))))

  (define (parse-query s)
    (if (string=? s "")
        '()
        (map (lambda (kv)
               (let ((eqp (string-index kv #\=)))
                 (if eqp
                     (cons (percent-decode (substring kv 0 eqp) #t)
                           (percent-decode
                             (substring kv (+ eqp 1) (string-length kv)) #t))
                     (cons (percent-decode kv #t) ""))))
             (string-split s #\&))))

  ;; ---- head parsing ----------------------------------------------------------
  ;; Hybrid strategy: ONE utf8->string over the whole header block
  ;; (which doubles as UTF-8 validation), then index scanning inside
  ;; that string -- no per-line substrings, no method interning, no
  ;; name substring+downcase+intern for the names every request
  ;; carries. Values get exactly one substring each, OWS-trimmed via
  ;; in-place bounds. (Pure byte-level parsing buys nothing here: Chez
  ;; has no ranged utf8->string, so per-value decoding would cost
  ;; bv-sub + utf8->string, two allocations against substring's one.)

  ;; 128-entry table: token char -> its lowercase, else #f. One lookup
  ;; answers validity and lowercasing together (fast-http's +tokens+).
  (define token-lc
    (let ((v (make-vector 128 #f)))
      (do ((i (char->integer #\a) (fx+ i 1))) ((fx> i (char->integer #\z)))
        (vector-set! v i (integer->char i)))
      (do ((i (char->integer #\0) (fx+ i 1))) ((fx> i (char->integer #\9)))
        (vector-set! v i (integer->char i)))
      (do ((i (char->integer #\A) (fx+ i 1))) ((fx> i (char->integer #\Z)))
        (vector-set! v i (integer->char (fx+ i 32))))
      (for-each (lambda (c) (vector-set! v (char->integer c) c))
                '(#\! #\# #\$ #\% #\& #\' #\* #\+ #\- #\. #\^ #\_ #\` #\| #\~))
      v))

  ;; lowercased token char, or #f when ch is not a legal field-name char
  (define (lc-token-char ch)
    (let ((i (char->integer ch)))
      (and (fx< i 128) (vector-ref token-lc i))))

  ;; the request methods this server routes; anything else answers 400
  ;; at parse time, so arbitrary method strings are never interned
  (define (match-method text end)     ; text[0, end)
    (define (is? s sym)
      (and (fx= end (string-length s))
           (let loop ((i 0))
             (if (fx= i end)
                 sym
                 (and (char=? (string-ref text i) (string-ref s i))
                      (loop (fx+ i 1)))))))
    (case end
      ((3) (or (is? "GET" 'GET) (is? "PUT" 'PUT)))
      ((4) (or (is? "POST" 'POST) (is? "HEAD" 'HEAD)))
      ((5) (or (is? "PATCH" 'PATCH) (is? "TRACE" 'TRACE)))
      ((6) (is? "DELETE" 'DELETE))
      ((7) (or (is? "OPTIONS" 'OPTIONS) (is? "CONNECT" 'CONNECT)))
      (else #f)))

  ;; supported versions come back as shared constants (no per-request
  ;; substring); a well-formed but unknown one yields 'unsupported so
  ;; the caller can answer 505 rather than 400
  (define (match-version text start end)
    (define (is? s)
      (and (fx= (fx- end start) (string-length s))
           (let loop ((i 0))
             (or (fx= i (string-length s))
                 (and (char=? (string-ref text (fx+ start i)) (string-ref s i))
                      (loop (fx+ i 1)))))))
    (cond
      ((is? "HTTP/1.1") "HTTP/1.1")
      ((is? "HTTP/1.0") "HTTP/1.0")
      (else 'unsupported)))

  ;; The names on virtually every request or upgrade, matched in place
  ;; (case-insensitively, via the token table) to pre-interned symbols:
  ;; the hot path allocates no name string and touches no oblist.
  ;; Bucketed by length so each name is compared against at most three.
  (define (common-header-name text start len)
    (define (at? name sym)
      (let loop ((i 0))
        (if (fx= i len)
            sym
            (let ((lc (lc-token-char (string-ref text (fx+ start i)))))
              (and lc (char=? lc (string-ref name i))
                   (loop (fx+ i 1)))))))
    (case len
      ((2) (at? "te" 'te))
      ((4) (or (at? "host" 'host) (at? "date" 'date)))
      ((6) (or (at? "cookie" 'cookie) (at? "accept" 'accept)
               (at? "expect" 'expect) (at? "origin" 'origin)
               (at? "pragma" 'pragma)))
      ((7) (or (at? "upgrade" 'upgrade) (at? "referer" 'referer)
               (at? "trailer" 'trailer)))
      ((10) (or (at? "connection" 'connection) (at? "user-agent" 'user-agent)))
      ((12) (at? "content-type" 'content-type))
      ((13) (or (at? "authorization" 'authorization)
                (at? "cache-control" 'cache-control)
                (at? "if-none-match" 'if-none-match)))
      ((14) (or (at? "content-length" 'content-length)
                (at? "accept-charset" 'accept-charset)))
      ((15) (or (at? "accept-encoding" 'accept-encoding)
                (at? "accept-language" 'accept-language)
                (at? "x-forwarded-for" 'x-forwarded-for)))
      ((16) (at? "content-encoding" 'content-encoding))
      ((17) (or (at? "transfer-encoding" 'transfer-encoding)
                (at? "sec-websocket-key" 'sec-websocket-key)
                (at? "if-modified-since" 'if-modified-since)))
      ((21) (at? "sec-websocket-version" 'sec-websocket-version))
      (else #f)))

  ;; rare name: validate and lowercase in ONE pass, then intern; an
  ;; illegal field-name char rejects the head (-> 400). Chez's oblist
  ;; holds symbols weakly, so these do not accumulate forever -- the
  ;; point of the common table is the allocation + hash, not a leak.
  (define (rare-header-name text start end)
    (let ((out (make-string (fx- end start))))
      (let loop ((i start))
        (if (fx= i end)
            (string->symbol out)
            (let ((lc (lc-token-char (string-ref text i))))
              (and lc
                   (begin
                     (string-set! out (fx- i start) lc)
                     (loop (fx+ i 1)))))))))

  ;; Header block scan. Repeated fields are coalesced into one
  ;; comma-joined value in wire order (RFC 7230); this lets
  ;; content-length see "5,6" and reject the conflict, and keeps
  ;; request accessors single-valued. A continuation line (obs-fold,
  ;; leading SP/TAB) or a line without a colon rejects the WHOLE head
  ;; (-> 400): silently dropping a line a fronting proxy may have
  ;; honored is request-smuggling room. Values are OWS-trimmed on both
  ;; ends: "Connection: close " must not read as keep-alive, and
  ;; "Content-Length:<tab>42" is legal.
  (define (parse-headers text start)
    (let ((n (string-length text)))
      (let loop ((i start) (acc '()))
        (if (fx>= i n)
            (reverse! acc)                       ; wire order
            (let* ((nl (let scan ((j i))
                         (cond ((fx>= j n) n)
                               ((char=? (string-ref text j) #\newline) j)
                               (else (scan (fx+ j 1))))))
                   ;; the slice stops just before the terminating CRLFCRLF,
                   ;; so the LAST line legitimately has no newline of its own
                   (last? (fx>= nl n))
                   (cr? (and (fx> nl i)
                             (char=? (string-ref text (fx- nl 1)) #\return)))
                   (crlf? (and (not last?) cr?))
                   (e (if crlf? (fx- nl 1) nl)))
              (cond
                ;; A line MUST end with CRLF. A bare LF is the classic
                ;; smuggling wedge: this parser would split on it while a
                ;; CRLF-strict proxy in front reads the same bytes as one
                ;; folded value, so the two disagree about how many
                ;; headers (and which Content-Length) the request has.
                ;; A stray CR is rejected for the same reason: leaving it
                ;; inside the value would hand a control character to
                ;; handlers and to token matchers like connection-has-token?.
                ((and (not last?) (not crlf?)) #f)
                ((and last? cr?) #f)
                ((fx= e i) (loop (fx+ nl 1) acc))                  ; blank line
                ((memv (string-ref text i) '(#\space #\tab)) #f)   ; obs-fold
                (else
                 (let ((colon (let scan ((j i))
                                (cond ((fx>= j e) #f)
                                      ((char=? (string-ref text j) #\:) j)
                                      (else (scan (fx+ j 1)))))))
                   (and colon (fx> colon i)
                        (let ((name (or (common-header-name text i (fx- colon i))
                                        (rare-header-name text i colon))))
                          (and name
                               (let* ((vs (let lp ((j (fx+ colon 1)))
                                            (if (and (fx< j e)
                                                     (memv (string-ref text j)
                                                           '(#\space #\tab)))
                                                (lp (fx+ j 1)) j)))
                                      (ve (let lp ((j e))
                                            (if (and (fx> j vs)
                                                     (memv (string-ref text (fx- j 1))
                                                           '(#\space #\tab)))
                                                (lp (fx- j 1)) j)))
                                      (val (substring text vs ve))
                                      (prev (assq name acc)))
                                 (if prev
                                     (begin
                                       (set-cdr! prev
                                         (string-append (cdr prev) "," val))
                                       (loop (fx+ nl 1) acc))
                                     (loop (fx+ nl 1)
                                           (cons (cons name val) acc)))))))))))))))

  ;; Parse request line + headers from bv[from, to).
  ;; Returns #(method path query version headers), or #f on malformed
  ;; input; a well-formed unknown version parses with 'unsupported in
  ;; the version slot (505, not 400).
  (define (parse-head bv from to)
    (guard (e (#t #f))
      (let* ((text (utf8->string (bv-sub bv from to)))
             (n (string-length text))
             (nl1 (let scan ((j 0))
                    (cond ((fx>= j n) n)
                          ((char=? (string-ref text j) #\newline) j)
                          (else (scan (fx+ j 1))))))
             ;; the request line must be CRLF-terminated as well (a bare
             ;; LF here is the same smuggling wedge as in the headers)
             (rl-crlf? (and (fx> nl1 0)
                            (char=? (string-ref text (fx- nl1 1)) #\return)))
             ;; a bare-LF request line is rejected (the guard above turns
             ;; the raise into a parse failure -> 400): same smuggling
             ;; wedge as a bare LF between headers
             (rl-end (cond (rl-crlf? (fx- nl1 1))
                           ((fx>= nl1 n) nl1)
                           (else (raise 'bare-lf-request-line)))))
        (define (find-sp from)
          (let loop ((i from))
            (cond ((fx>= i rl-end) #f)
                  ((char=? (string-ref text i) #\space) i)
                  (else (loop (fx+ i 1))))))
        (let* ((sp1 (find-sp 0))
               (sp2 (and sp1 (find-sp (fx+ sp1 1)))))
          (and sp1 sp2
               (fx> sp2 (fx+ sp1 1))               ; non-empty target
               (fx> rl-end (fx+ sp2 1))            ; non-empty version
               (not (find-sp (fx+ sp2 1)))         ; exactly three tokens
               (let ((method (match-method text sp1)))
                 (and method
                      (let* ((version (match-version text (fx+ sp2 1) rl-end))
                             (qpos (let loop ((i (fx+ sp1 1)))
                                     (cond ((fx>= i sp2) #f)
                                           ((char=? (string-ref text i) #\?) i)
                                           (else (loop (fx+ i 1))))))
                             ;; decode first, then normalize: %2F decodes to
                             ;; a real separator, and the router would treat
                             ;; it as one, so normalization must see it too
                             (path (normalize-path
                                     (percent-decode
                                       (substring text (fx+ sp1 1) (or qpos sp2))
                                       #f)))        ; "+" is literal in a path
                             (query (if qpos
                                        (parse-query
                                          (substring text (fx+ qpos 1) sp2))
                                        '()))
                             (headers (parse-headers text (fx+ nl1 1))))
                        (and headers
                             (vector method path query version headers))))))))))

  ;; a valid Content-Length is one or more identical strings of ASCII
  ;; digits (parse-header-lines coalesces repeats into one comma-joined
  ;; value). Returns a non-negative integer, 'absent, or 'bad.
  (define (all-digits? s)
    (and (> (string-length s) 0)
         (let loop ((i 0))
           (cond
             ((= i (string-length s)) #t)
             ((char<=? #\0 (string-ref s i) #\9) (loop (+ i 1)))
             (else #f)))))

  (define (content-length headers)
    (let ((p (assq 'content-length headers)))
      (if (not p)
          'absent
          (let ((parts (let split ((s (cdr p)) (acc '()) (start 0) (i 0))
                         (cond
                           ((= i (string-length s))
                            (reverse (cons (substring s start i) acc)))
                           ((char=? (string-ref s i) #\,)
                            (split s (cons (substring s start i) acc)
                                   (+ i 1) (+ i 1)))
                           (else (split s acc start (+ i 1)))))))
            ;; every repeated value must be a valid digit string and equal
            (let check ((ps parts) (val #f))
              (cond
                ((null? ps) val)
                ((not (all-digits? (car ps))) 'bad)
                (else
                 (let ((n (string->number (car ps))))
                   (cond
                     ((not val) (check (cdr ps) n))
                     ((= n val) (check (cdr ps) val))
                     (else 'bad))))))))))

  (define (trim-ows s)
    (let ((n (string-length s)))
      (let ((start (let loop ((i 0))
                     (if (and (< i n) (memv (string-ref s i) '(#\space #\tab)))
                         (loop (+ i 1)) i)))
            (end (let loop ((i n))
                   (if (and (> i 0) (memv (string-ref s (- i 1)) '(#\space #\tab)))
                       (loop (- i 1)) i))))
        (if (< start end) (substring s start end) ""))))

  ;; Only the transfer coding implemented by this server is one final,
  ;; non-repeated "chunked" token. Everything else is rejected rather than
  ;; falling back to Content-Length and disagreeing with an upstream proxy.
  (define (transfer-encoding headers)
    (let ((p (assq 'transfer-encoding headers)))
      (if (not p)
          'absent
          (let ((tokens (map (lambda (x) (string-downcase (trim-ows x)))
                             (string-split (cdr p) #\,))))
            (if (equal? tokens '("chunked")) 'chunked 'bad)))))

  (define (websocket-attempt? headers)
    (or (assq 'sec-websocket-key headers)
        (assq 'sec-websocket-version headers)
        (let ((u (assq 'upgrade headers)))
          (and u (string-ci=? (cdr u) "websocket")))))

  ;; Return the client key only for a complete RFC 6455 opening handshake.
  (define (websocket-key parsed)
    (let* ((headers (vector-ref parsed 4))
           (u (assq 'upgrade headers))
           (k (assq 'sec-websocket-key headers))
           (v (assq 'sec-websocket-version headers)))
      (and (eq? (vector-ref parsed 0) 'GET)
           (equal? (vector-ref parsed 3) "HTTP/1.1")
           u (string-ci=? (cdr u) "websocket")
           (connection-has-token? headers "upgrade")
           v (string=? (cdr v) "13")
           k (ws-valid-client-key? (cdr k))
           (cdr k))))

  ;; Connection is a comma-separated TOKEN LIST (RFC 9110): "close, TE"
  ;; really does mean close. Comparing the whole coalesced value would
  ;; read that as keep-alive and reuse a socket the peer is closing --
  ;; a framing desync with whatever sits in front of us.
  ;; Case-insensitive compare in place: no string-downcase copy.
  (define (connection-has-token? headers tok)
    (let ((p (assq 'connection headers)))
      (and p
           (let* ((v (cdr p)) (n (string-length v)) (tn (string-length tok)))
             (let loop ((i 0))
               (and (fx<= (fx+ i tn) n)
                    ;; token boundary on both sides: start of value or
                    ;; just past a comma/space, end likewise
                    (let ((before-ok?
                           (or (fx= i 0)
                               (let ((c (string-ref v (fx- i 1))))
                                 (or (char=? c #\,) (char=? c #\space)
                                     (char=? c #\tab)))))
                          (after-ok?
                           (or (fx= (fx+ i tn) n)
                               (let ((c (string-ref v (fx+ i tn))))
                                 (or (char=? c #\,) (char=? c #\space)
                                     (char=? c #\tab))))))
                      (if (and before-ok? after-ok?
                               (string-ci=? (substring v i (fx+ i tn)) tok))
                          #t
                          (loop (fx+ i 1))))))))))

  (define (keep-alive? version headers)
    (if (string=? version "HTTP/1.1")
        (not (connection-has-token? headers "close"))
        (and (connection-has-token? headers "keep-alive")
             (not (connection-has-token? headers "close")))))

  ;; ---- responses -------------------------------------------------------------

  (define (status-text s)
    (case s
      ((200) "OK") ((201) "Created") ((204) "No Content")
      ((301) "Moved Permanently") ((302) "Found") ((304) "Not Modified")
      ((400) "Bad Request") ((403) "Forbidden") ((404) "Not Found")
      ((408) "Request Timeout") ((413) "Payload Too Large")
      ((431) "Request Header Fields Too Large")
      ((500) "Internal Server Error") ((503) "Service Unavailable")
      ((505) "HTTP Version Not Supported")
      (else "Unknown")))

  ;; Complete status lines as compile-time constants: the common statuses
  ;; cost one case dispatch instead of a 3-part string-append per response.
  (define (status-line s)
    (case s
      ((200) "HTTP/1.1 200 OK\r\n")
      ((201) "HTTP/1.1 201 Created\r\n")
      ((204) "HTTP/1.1 204 No Content\r\n")
      ((301) "HTTP/1.1 301 Moved Permanently\r\n")
      ((302) "HTTP/1.1 302 Found\r\n")
      ((304) "HTTP/1.1 304 Not Modified\r\n")
      ((400) "HTTP/1.1 400 Bad Request\r\n")
      ((403) "HTTP/1.1 403 Forbidden\r\n")
      ((404) "HTTP/1.1 404 Not Found\r\n")
      ((408) "HTTP/1.1 408 Request Timeout\r\n")
      ((413) "HTTP/1.1 413 Payload Too Large\r\n")
      ((431) "HTTP/1.1 431 Request Header Fields Too Large\r\n")
      ((500) "HTTP/1.1 500 Internal Server Error\r\n")
      ((503) "HTTP/1.1 503 Service Unavailable\r\n")
      (else (string-append "HTTP/1.1 " (number->string s) " "
                           (status-text s) "\r\n"))))

  ;; Per-request response token: a one-shot claim shared by every path
  ;; that might answer a single request (the handler, the streaming
  ;; helpers, and the supervisor's fallback 500). Claiming is atomic, so
  ;; a stale write from a previous keep-alive request can never bleed
  ;; into the next one, and a fallback can never double-write.
  (define (make-token) (box #f))
  (define (claim! token)
    (with-interrupts-disabled
      (and (not (unbox token)) (set-box! token #t) #t)))

  ;; Framing headers are always emitted by the framework; drop any the
  ;; user set so they cannot be duplicated or conflict. Compared
  ;; case-insensitively in place -- no per-header string-downcase copy.
  (define (framing-header? name)
    (or (string-ci=? name "content-length")
        (string-ci=? name "connection")
        (string-ci=? name "transfer-encoding")))

  ;; Reject header names/values carrying CR or LF (response splitting).
  (define (header-safe? s)
    (not (or (string-index s #\return) (string-index s #\newline))))

  ;; Assemble a whole response head -- status line, user headers, then
  ;; the trailing framing pieces -- as ONE string-append: the pieces are
  ;; collected into a list and copied once, with no per-header
  ;; intermediate strings. Unsafe/framing headers are silently dropped.
  (define (assemble-head status headers . tail-pieces)
    (apply string-append
      (status-line status)
      (fold-right
        (lambda (h acc)
          (let ((k (car h)) (v (cdr h)))
            (if (and (header-safe? k) (header-safe? v)
                     (not (framing-header? k)))
                (cons* k ": " v "\r\n" acc)
                acc)))
        tail-pieces
        headers)))

  ;; Constant framing tails, chosen by keep-alive -- built once at load
  ;; time instead of appended piecewise per response.
  (define keep-alive-tail "\r\nConnection: keep-alive\r\n\r\n")
  (define close-tail "\r\nConnection: close\r\n\r\n")

  ;; 1xx, 204 and 304 are defined as bodyless: a client stops at the blank
  ;; line whatever follows it, so writing a body desynchronises a persistent
  ;; connection exactly the way a body on a HEAD does (RFC 9110 6.4.1/15.4.5).
  (define (status-forbids-body? status)
    (or (and (fx>= status 100) (fx< status 200))
        (fx= status 204) (fx= status 304)))

  ;; Narrower than the above on purpose: Content-Length is forbidden on 1xx
  ;; and 204, but a 304 MAY carry the length the corresponding 200 would
  ;; have had -- it is metadata there, not framing (RFC 9110 8.6/15.4.5).
  (define (status-forbids-length? status)
    (or (and (fx>= status 100) (fx< status 200)) (fx= status 204)))

  ;; Write a full response after its caller has claimed the request token.
  ;; The libuv write callback (no yielding) tells the reader to continue
  ;; (keep-alive) or closes the connection.
  ;; head-only: a HEAD response must carry the SAME headers a GET would --
  ;; Content-Length included -- and no body at all (RFC 9110 9.3.2). Writing
  ;; the body anyway desynchronises the connection: a conforming client
  ;; stops after the blank line, so the bytes that follow are read as the
  ;; start of the next response. Behind a shared cache that is a poisoning
  ;; primitive, which is why this is decided here, at the one place every
  ;; response is serialized, rather than left to each handler.
  ;; head-only: #f -- normal response; #t -- suppress the body, declaring
  ;; the length of the body passed in; an integer -- suppress the body and
  ;; declare THAT length (a HEAD for a file too large to read into memory,
  ;; where the size is known but the bytes must not be); 'unknown --
  ;; suppress the body and send NO Content-Length, for a HEAD whose GET
  ;; would have been chunked. RFC 7230 3.3.2: a HEAD response's
  ;; Content-Length is what the GET would have sent, so when that is not
  ;; known the field is omitted. Declaring 0 instead does not mean "unknown"
  ;; to anyone -- it means the resource is empty.
  (define (write-response!* c status headers body ka head-only)
    (let* ((suppress-body? (or head-only (status-forbids-body? status)))
           (head
              (if (or (status-forbids-length? status) (eq? head-only 'unknown))
                  (assemble-head status headers
                    (if ka keep-alive-tail close-tail))
                  (assemble-head status headers
                    "Content-Length: "
                    (number->string (if (integer? head-only)
                                        head-only
                                        (bytevector-length body)))
                    (if ka keep-alive-tail close-tail))))
             (owner (conn-owner c))
             (done (lambda (st)
                     (if (and ka (>= st 0))
                         (send owner (vector 'next-request))
                         (begin
                           (tcp-close! c)
                           (send owner (vector 'conn-closed)))))))
        ;; head and body are written as two segments -- no bv-append copy
        (if suppress-body?
            (tcp-writev! c (list (string->utf8 head)) done)
            (tcp-writev! c (list (string->utf8 head) body) done))))

  (define (send-response!* c token status headers body ka head-only)
    ;; Check the socket BEFORE claiming: the reader closes on its own
    ;; timeout, and a handler that finishes afterwards would otherwise
    ;; write to a freed handle. If that raises, the supervisor treats it
    ;; as a task crash and RE-RUNS the whole handler, duplicating whatever
    ;; non-idempotent work it had already done for a client that is long
    ;; gone. The streaming writers guard on conn-state for the same
    ;; reason; this is the one path that did not.
    (when (and (eq? (conn-state c) 'open) (claim! token))
      (write-response!* c status headers body ka head-only)))

  (define (send-response! c token status headers body ka)
    (send-response!* c token status headers body ka #f))

  ;; minimal error response; always closes. Uses a fresh token unless
  ;; one is supplied (reader-level errors have no task yet).
  (define (quick-response! c status text . tok)
    (send-response! c (if (pair? tok) (car tok) (make-token))
                    status '(("Content-Type" . "text/plain"))
                    (string->utf8 text) #f))

  ;; ---- res record + primitives (the res.end level) ----------------------------

  (define-record-type (res make-res res?)
    (fields
      (immutable conn res-conn)
      (immutable token res-token)          ; per-request one-shot claim
      (immutable req res-req)              ; the request, for layers (e.g. gzip)
      (mutable status res-status res-status-set!)
      (mutable headers res-headers res-headers-set!)
      (immutable keep-alive? res-keep-alive?)
      ;; plain | streaming | raw | done
      (mutable mode res-mode res-mode-set!)
      ;; bytes still owed in a fixed-length (res-begin-file!) response
      (mutable remaining res-remaining res-remaining-set!)))

  ;; Claim the response and capture the mutable status/header fields as
  ;; one operation. A layer can therefore conditionally publish a header
  ;; against the same token without a responder claiming an older header
  ;; snapshot in between its check and mutation.
  (define (claim-res! r)
    (with-interrupts-disabled
      (let ((c (res-conn r)) (token (res-token r)))
        (and (eq? (conn-state c) 'open)
             (not (unbox token))
             (begin
               (set-box! token #t)
               (vector (res-status r) (res-headers r)))))))

  (define (set-status! r s) (res-status-set! r s))

  ;; #t once the status line has gone out -- by res-send!, by res-begin!,
  ;; or by anything else that claimed the one-shot token. After that,
  ;; set-status! and set-header! still succeed and still do nothing: the
  ;; headers they would have written are already on the wire.
  ;;
  ;; Exported so a layer whose correctness depends on a header actually
  ;; reaching the client -- a rotated session cookie, say -- can refuse
  ;; loudly instead of half-applying an effect the client never learns of.
  (define (res-answered? r) (and (unbox (res-token r)) #t))

  ;; Silently ignore header names/values containing CR or LF; they are
  ;; also rejected again at render time.
  (define (set-header! r k v)
    (when (and (header-safe? k) (header-safe? v))
      (res-headers-set! r (cons (cons k v) (res-headers r)))))

  ;; Atomically add a header only while it is still possible for every
  ;; res response path to include it. #f means the response was already
  ;; claimed (or the header was unsafe); #t means a later claim snapshots
  ;; this header. This is for layers whose side effects depend on header
  ;; delivery, such as deleting an old session only after publishing its
  ;; replacement cookie.
  (define (set-header-if-unanswered! r k v)
    (and (header-safe? k) (header-safe? v)
         (with-interrupts-disabled
           (let ((token (res-token r)))
             (and (not (unbox token))
                  (begin
                    (res-headers-set! r (cons (cons k v) (res-headers r)))
                    #t))))))

  ;; Send the response: current status + accumulated headers + body
  ;; bytevector. One shot per request; later calls are ignored.
  (define (res-head-request? r)
    (let ((req (res-req r))) (and req (eq? (req-method req) 'HEAD) #t)))

  (define (res-send! r body)
    (let ((snapshot (claim-res! r)))
      (when snapshot
        (write-response!* (res-conn r)
          (vector-ref snapshot 0) (vector-ref snapshot 1)
          body (res-keep-alive? r) (res-head-request? r)))))

  ;; Answer a HEAD with the headers a GET would carry, declaring
  ;; content-length, and no body -- used where the body would otherwise be
  ;; streamed from disk and must not even be read.
  (define (res-send-head! r content-length)
    (let ((snapshot (claim-res! r)))
      (when snapshot
        (write-response!* (res-conn r)
          (vector-ref snapshot 0) (vector-ref snapshot 1)
          empty-bv (res-keep-alive? r) content-length))))

  ;; ---- streaming responses (Transfer-Encoding: chunked) ------------------------

  ;; Begin a streamed response: send status + headers now, body comes in
  ;; chunks. Marks the request as responded (the supervisor fallback
  ;; stays away) and tells the reader to wait for the stream to finish.
  ;; A long stream should be detached from the pool worker:
  ;;   (res-begin! r) (res-spawn! r (lambda () ... (res-write! r x) ... (res-end! r)))
  ;; res-spawn! rather than a plain spawn: nothing else notices a detached
  ;; producer that dies or returns without res-end!, and the reader waits
  ;; for the stream with no deadline.
  (define chunked-keep-alive-tail
    "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n")
  (define chunked-close-tail
    "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")

  ;; RFC 7230 3.3.1: chunked is an HTTP/1.1 feature and MUST NOT be sent
  ;; to an HTTP/1.0 recipient -- it does not implement it, so it reads the
  ;; hex size lines as body content and the payload is corrupted (and a
  ;; 1.0 proxy forwards that corruption). Such a client gets a
  ;; close-delimited body instead: no framing header, raw bytes, and the
  ;; connection closes to mark the end.
  (define (res-http10? r)
    (let ((req (res-req r)))
      (and req (equal? (req-version req) "HTTP/1.0"))))

  (define close-delimited-tail "Connection: close\r\n\r\n")

  (define (res-begin! r)
    (let ((c (res-conn r)) (snapshot (claim-res! r)))
      (when snapshot
        (let ((status (vector-ref snapshot 0)) (headers (vector-ref snapshot 1)))
          ;; Branch on the SNAPSHOT, not on (res-status r): claim-res! pairs
          ;; the claim with the status/header read under one interrupt-free
          ;; window, and re-reading here would reopen the gap it closes.
          ;; A HEAD belongs here with the bodyless statuses: same rule, same
          ;; consequence. Express routes HEAD to the GET handler, so a
          ;; streaming handler streams -- and res-send! and the static file
          ;; path both suppress the body for HEAD while this one did not,
          ;; sending chunk framing a conforming client stops before. Those
          ;; bytes then read as the start of the next response on a
          ;; kept-alive connection: the desynchronisation the HEAD comment in
          ;; write-response!* already spells out.
          (if (or (status-forbids-body? status) (res-head-request? r))
              ;; No chunked framing for a response that cannot carry a body --
              ;; announcing Transfer-Encoding and then sending the terminator
              ;; is itself a body. Answer it as a complete response and leave
              ;; the mode 'done, so res-write! returns #f and res-end! is a
              ;; no-op: a handler written as begin/write/end still terminates.
              (begin
                (res-mode-set! r 'done)
                ;; a STREAM's length is not known here -- the handler was
                ;; about to produce it chunk by chunk -- so this HEAD says
                ;; nothing about it rather than saying zero
                (write-response!* c status headers
                                  empty-bv (res-keep-alive? r)
                                  (if (res-head-request? r)
                                      'unknown
                                      #t)))
              (let ((raw? (res-http10? r)))
                (res-mode-set! r (if raw? 'streaming-raw 'streaming))
                (tcp-write! c
                  (string->utf8
                    (assemble-head status headers
                      (cond
                        (raw? close-delimited-tail)
                        ((res-keep-alive? r) chunked-keep-alive-tail)
                        (else chunked-close-tail))))
                  #f)
                (send (conn-owner c) (vector 'streaming))))))))

  ;; Write one chunk (string or bytevector). #f when the stream is not
  ;; open any more (e.g. the client disconnected) -- stop the loop then.
  (define crlf-bv (string->utf8 "\r\n"))

  ;; Write one chunk and WAIT for it to drain -- backpressure: the producer
  ;; runs at the client's pace, one chunk in flight. Without it a client
  ;; that stops reading (or simply reads slowly) never leaves conn-state
  ;; 'open, so a producer loop would keep queueing: enqueue-write! has no
  ;; cap and foreign-allocs every queued block, so memory the GC cannot
  ;; even see grows at the producer's full speed. One stalled reader per
  ;; streaming endpoint was enough to exhaust the machine.
  ;;
  ;; Same shape as res-write-fixed!: the completion usually runs INLINE
  ;; (uv_try_write took it all), leaving the status in the box with no
  ;; message and no receive; only a genuinely queued write parks this
  ;; process. A callback can only run inline here or from the event loop,
  ;; never between the unbox and the set-box!, because neither yields.
  ;;
  ;; A client that never drains used to park the writer indefinitely. For a
  ;; POOLED handler the worker's stuck-ms bounded that, and the resulting
  ;; kill closed the connection (see fail-task) -- but a long stream is
  ;; supposed to be detached into its own process (see res-begin! above),
  ;; and a spawned process is not a pool worker, so the recommended shape
  ;; was the unbounded one. write-timeout-ms now bounds every write.
  (define (write-wait-ms)
    (if (zero? write-timeout-ms) 'infinity write-timeout-ms))

  ;; Give up on a write whose peer never took the bytes. The connection has
  ;; to go: a chunked or SSE body cannot resume mid-chunk, and half of one
  ;; is worse on the wire than none. Marking the box first is what keeps the
  ;; completion, if it ever runs, from posting into a mailbox nobody is
  ;; reading -- and the drain covers the narrow case where it fired just as
  ;; the timer did, so the message is already queued.
  ;; r may be #f where the response record is not to hand; when it is
  ;; given, the response is marked FINISHED here. Leaving the mode alone
  ;; meant the exchange was over on the wire and still looked unfinished in
  ;; the record: res-spawn!'s watcher saw a stream in progress and aborted a
  ;; connection that was already closed, and a caller following the
  ;; documented "#f -> res-abort-file!" path did the same -- a second close
  ;; and a second conn-closed for one response.
  (define (abandon-write! b c . rest)
    (let ((r (and (pair? rest) (car rest))))
      (when r (res-mode-set! r 'done)))
    (set-box! b 'abandoned)
    (receive (after 0 'ok)
      (`#(chunk-written ,_) 'ok)
      (`#(file-written ,_) 'ok))
    ;; Closing the handle is not enough to end the request. The reader is
    ;; parked in await-streaming, which has NO deadline -- it waits for the
    ;; response to finish or for the connection to say it is over. A local
    ;; close produces no tcp-eof for us, so nothing woke it: the fd went
    ;; away and the reader process and its buffer stayed, one per timed-out
    ;; write, for the life of the server.
    ;;
    ;; abort-response! is the same signal for the same reason (a crash mid
    ;; stream); a write that timed out is another way for a stream to end
    ;; without its terminator.
    (abort-response! c))

  (define (res-write! r data)
    (let ((bv (if (string? data) (string->utf8 data) data))
          (c (res-conn r)))
      (and (memq (res-mode r) '(streaming streaming-raw))
           (eq? (conn-state c) 'open)
           (> (bytevector-length bv) 0)
           ;; chunk = <hex size>CRLF <data> CRLF, written as three
           ;; segments -- except on the close-delimited HTTP/1.0 path,
           ;; where the bytes go out bare
           (let ((b (box 'pending)) (me self))
             (tcp-writev! c
               (if (eq? (res-mode r) 'streaming-raw)
                   (list bv)
                   (list (string->utf8
                           (string-append
                             (number->string (bytevector-length bv) 16) "\r\n"))
                         bv
                         crlf-bv))
               (lambda (st)
                 (case (unbox b)
                   ((pending) (set-box! b st))
                   ;; timed out and gave up: nobody is in a receive for this,
                   ;; and a message left behind would be matched by the NEXT
                   ;; write from this process, reporting another chunk's fate
                   ((abandoned) (void))
                   (else (send me (vector 'chunk-written st))))))
             (let ((st (unbox b)))
               (if (eq? st 'pending)
                   (begin
                     (set-box! b 'parked)
                     (receive (after (write-wait-ms)
                                 (abandon-write! b c r)
                                 #f)
                       (`#(chunk-written ,st2) (>= st2 0))))
                   (>= st 0)))))))

  ;; Finish the stream: terminating chunk, then the usual keep-alive /
  ;; close continuation. The terminator is encoded once at load time;
  ;; sharing the bytevector across writes is safe because tcp-writev!
  ;; copies it out synchronously.
  (define chunk-terminator (string->utf8 "0\r\n\r\n"))

  (define (res-end! r)
    (let ((mode (res-mode r)))
      (when (memq mode '(streaming streaming-raw))
        ;; 'ending, not 'done: the terminator has not been WRITTEN yet, and
        ;; this process is about to park waiting for its completion. Marking
        ;; the response finished here meant res-spawn!'s watcher saw nothing
        ;; in progress -- so a producer killed while parked on that write
        ;; left the reader with neither next-request nor conn-closed, parked
        ;; in await-streaming forever. res-streaming? counts 'ending as in
        ;; progress; 'done is set below, when the write really is done.
        (res-mode-set! r 'ending)
        (let* ((c (res-conn r))
               (owner (conn-owner c)))
          (if (eq? mode 'streaming-raw)
              ;; close-delimited: the close IS the end of the body, so
              ;; there is no terminator and the connection cannot be reused
              (begin (res-mode-set! r 'done)
                     (tcp-close! c)
                     (send owner (vector 'conn-closed)))
              ;; The terminator gets the same deadline as every other write.
              ;; It used to be fire-and-forget, which meant a peer that
              ;; stopped reading exactly here never triggered the callback --
              ;; so neither next-request nor conn-closed was ever sent, and
              ;; the reader stayed in await-streaming, which has no deadline
              ;; of its own. That path is the one abort-response! cannot
              ;; cover: the handler did not crash, it FINISHED, so nothing
              ;; was ever going to abort on its behalf. The connection, its
              ;; write block and the reader process all stayed put.
              (let* ((ka (res-keep-alive? r))
                     (b (box 'pending))
                     (me self)
                     (finish!
                       (lambda (st)
                         (res-mode-set! r 'done)
                         (if (and ka (>= st 0))
                             (send owner (vector 'next-request))
                             (begin
                               (tcp-close! c)
                               (send owner (vector 'conn-closed)))))))
                (tcp-write! c chunk-terminator
                  (lambda (st)
                    (case (unbox b)
                      ((pending) (set-box! b st))
                      ((abandoned) (void))   ; see res-write!
                      (else (send me (vector 'chunk-written st))))))
                (let ((st (unbox b)))
                  (if (eq? st 'pending)
                      (begin
                        (set-box! b 'parked)
                        ;; A timeout is TERMINAL here: abandon-write! has
                        ;; already closed the connection and told the reader.
                        ;; Running finish! afterwards closed a second time
                        ;; and sent a second conn-closed for the same
                        ;; response -- two terminal notifications, and the
                        ;; second one arriving at whatever the reader had
                        ;; become.
                        (receive (after (write-wait-ms)
                                    (abandon-write! b c r))
                          (`#(chunk-written ,v) (finish! v))))
                      (finish! st))))))))) 

  ;; ---- fixed-length streaming (large files) --------------------------------

  ;; Begin a response of known length: status + headers + Content-Length
  ;; go out now, the body follows through res-write-file!. Claims the
  ;; token, so call this from the pool worker, then spawn a pump process
  ;; for the writes (as with res-begin!) -- a long download must not
  ;; occupy a worker or it would be killed as stuck.
  (define (res-begin-file! r len)
    (let ((c (res-conn r)) (snapshot (claim-res! r)))
      (when snapshot
        (let ((status (vector-ref snapshot 0)) (headers (vector-ref snapshot 1)))
          ;; A HEAD takes the same branch, and len as head-only is exactly
          ;; what it needs: a HEAD must carry the Content-Length a GET would
          ;; have declared and none of the bytes (RFC 9110 9.3.2). Without
          ;; this the file streamed in full behind the headers.
          (if (or (status-forbids-body? status) (res-head-request? r))
              ;; Passing len as head-only keeps the declared length of the
              ;; representation while sending none of it -- which is exactly
              ;; what a 304 wants, and is dropped outright for 204 and 1xx.
              (begin
                (res-mode-set! r 'done)
                (write-response!* c status headers
                                  empty-bv (res-keep-alive? r) len))
              (begin
                ;; A declared length of ZERO is already satisfied: there is
                ;; no block left to write, so no call can ever reach the
                ;; final-block branch that ends the response. Answering it
                ;; as a complete response here leaves the mode 'done, so a
                ;; caller written as begin-file/write/end still terminates
                ;; -- the same shape the bodyless branch above uses. Left
                ;; as a stream it parked the reader with nothing able to
                ;; release it but an abort.
                (if (fx= len 0)
                    (begin
                      (res-mode-set! r 'done)
                      (write-response!* c status headers
                                        empty-bv (res-keep-alive? r) 0))
                    (begin
                      (res-mode-set! r 'raw)
                      (res-remaining-set! r len)
                      (tcp-write! c
                        (string->utf8
                          (assemble-head status headers
                            "Content-Length: " (number->string len)
                            (if (res-keep-alive? r) keep-alive-tail close-tail)))
                        #f)
                      (send (conn-owner c) (vector 'streaming))))))))))

  ;; Write one chunk and wait for it to drain before returning --
  ;; backpressure: the producer runs exactly at the client's pace, one
  ;; chunk in flight. The final chunk (the one reaching the declared
  ;; length) instead carries the keep-alive/close continuation and is
  ;; not waited for. Returns 'more (continue), 'done (response
  ;; complete), or #f (connection gone -- call res-abort-file!).
  ;; do-write issues the actual write: (do-write completion-callback).
  (define (res-write-fixed! r n do-write)
    (let ((c (res-conn r))
          (remaining (res-remaining r)))
      (cond
        ((not (and (eq? (res-mode r) 'raw) (eq? (conn-state c) 'open))) #f)
        ((fx= n 0) 'more)
        ((> n remaining)
         (assertion-violation 'res-write-file!
           "chunk exceeds the declared Content-Length" n remaining))
        ((= n remaining)
         (res-remaining-set! r 0)
         (res-mode-set! r 'done)
         (let ((owner (conn-owner c)) (ka (res-keep-alive? r)))
           (do-write
             (lambda (st)
               (if (and ka (>= st 0))
                   (send owner (vector 'next-request))
                   (begin
                     (tcp-close! c)
                     (send owner (vector 'conn-closed))))))
           'done))
        (else
         (res-remaining-set! r (- remaining n))
         ;; The completion usually runs INLINE (uv_try_write wrote it
         ;; all): the status lands in the box and no message or receive
         ;; happens. Only a queued write parks this process. Safe: a
         ;; callback can only run inline here or from the event loop,
         ;; never between the unbox and the set-box! (no yield).
         (let ((b (box 'pending)) (me self))
           (do-write
             (lambda (st)
               (case (unbox b)
                 ((pending) (set-box! b st))
                 ((abandoned) (void))       ; see res-write! for why
                 (else (send me (vector 'file-written st))))))
           (let ((st (unbox b)))
             (if (eq? st 'pending)
                 (begin
                   (set-box! b 'parked)
                   (receive (after (write-wait-ms)
                               (abandon-write! b (res-conn r) r)
                               #f)
                     (`#(file-written ,st2) (and (>= st2 0) 'more))))
                 (and (>= st 0) 'more))))))))

  (define (res-write-file! r data)
    (let ((bv (if (string? data) (string->utf8 data) data)))
      (res-write-fixed! r (bytevector-length bv)
        (lambda (done) (tcp-write! (res-conn r) bv done)))))

  ;; raw-flavor sibling: the chunk is the file stream's C buffer
  ;; (file-stream-raw!), written to the socket without ever becoming a
  ;; bytevector -- fast path is buffer -> kernel, zero Scheme allocation.
  (define (res-write-chunk! r st len)
    (res-write-fixed! r len
      (lambda (done)
        (tcp-write-foreign! (res-conn r) (file-stream-chunk-ptr st) len done))))

  ;; A fixed-length response that cannot be completed (read error, file
  ;; shrank, client stalled out) has one correct exit: close the
  ;; connection -- the promised Content-Length can never be satisfied.
  ;; No-op unless a res-begin-file! response is in progress.
  (define (res-abort-file! r)
    (when (eq? (res-mode r) 'raw)
      (res-mode-set! r 'done)
      (let ((c (res-conn r)))
        (tcp-close! c)
        (send (conn-owner c) (vector 'conn-closed)))))

  ;; ---- task execution (inside a pool worker) -----------------------------------

  ;; A crash here kills the worker (Let It Crash): the supervisor retries
  ;; the task up to 3 times, then answers via fail-task below.
  ;; Task shapes: #(task id conn req token)          -- a request
  ;;              #(fail id conn req token info)     -- a failure report
  (define (run-task handler on-failure task)
    (let* ((c (vector-ref task 2))
           (req (vector-ref task 3))
           (token (vector-ref task 4))
           (r (make-res c token req 200 '() (req-keep-alive? req) 'plain 0)))
      (if (eq? (vector-ref task 0) 'fail)
          ;; failure hook: one attempt by construction. A raise inside the
          ;; hook is caught (the worker survives, so the supervisor never
          ;; retries it) and falls back to the plain 500.
          (begin
            (guard (e (#t (void)))
              (when on-failure
                (on-failure req r (vector-ref task 5))))
            (unless (unbox token)
              (quick-response! c 500 "Internal Server Error" token)))
          ;; Do not run a handler for a connection that is already gone.
          ;; Workers are few, so a slow handler backs requests up in the
          ;; supervisor's queue, and a client that disconnects (or a reader
          ;; that reaped a slow one) leaves its task sitting there. Running
          ;; it later means touching the database and any external service
          ;; for a request nobody is waiting on -- and after an outage the
          ;; whole stale backlog executes at once, which is the worst moment
          ;; for it. Nothing can be answered on a closed connection anyway:
          ;; every response path checks conn-state and quietly does nothing.
          (when (eq? (conn-state c) 'open)
            (handler req r)
            ;; handler finished without responding: don't leave the client hanging
            (unless (unbox token)
              (set-status! r 404)
              (set-header! r "Content-Type" "text/plain; charset=utf-8")
              (res-send! r not-found-body))))))

  (define not-found-body (string->utf8 "Not Found"))

  ;; The supervisor gave up on the task (crash retries exhausted, or a
  ;; stuck worker was killed -- killed FIRST, so by the time the client
  ;; hears about it there is no in-flight execution left). With an
  ;; on-failure hook configured the request is requeued as an urgent
  ;; failure task: a fresh worker runs the hook, which answers through
  ;; the normal response path (keep-alive preserved), enabling a
  ;; fail-fast retry loop on one connection. Without a hook -- or when
  ;; the hook's own task fails, or a partial response already went out
  ;; -- the last-resort 500 (which closes) is used.
  ;; A handler that already claimed the token has begun writing a response
  ;; (res-begin! / res-begin-file!), and the reader is parked in
  ;; await-streaming with no deadline waiting for it to finish. If that
  ;; handler then crashes -- or is killed as stuck -- no status line can be
  ;; sent any more: send-response! is a no-op on a claimed token, so the
  ;; 500 below would vanish silently, leaving the connection open, the fd
  ;; allocated and the reader parked forever. A client could accumulate
  ;; leaked connections on demand by hitting such a handler.
  ;;
  ;; The only correct signal at that point is to CLOSE: a chunked response
  ;; without its terminating chunk, or a fixed-length one short of its
  ;; Content-Length, is exactly how HTTP says "this response is truncated",
  ;; and both framings the client accepts detect it by construction. The
  ;; reader is told so it can stop waiting.
  ;; This response has begun a streamed body and has not finished it. That
  ;; is the state where "already answered" is true but the request is NOT
  ;; over: the status line went out, the terminator did not, and the reader
  ;; is parked in await-streaming with no deadline.
  ;; 'raw is res-begin-file!'s fixed-length stream and 'ending is res-end!
  ;; waiting for its terminator to go out. Both are responses that have
  ;; STARTED and not FINISHED, which is the whole question here, and leaving
  ;; either out meant the watcher stood by while the client waited forever
  ;; -- for the rest of a Content-Length it will never receive, or for a
  ;; terminating chunk whose writer was killed mid-write.
  (define (res-streaming? r)
    (and (memq (res-mode r) '(streaming streaming-raw raw ending)) #t))

  ;; End a streamed response that cannot be completed.
  ;;
  ;; There is no way to say "never mind" once the status line is out, so the
  ;; only honest signal is to close: a chunked body without its terminating
  ;; chunk, or a fixed-length one short of its Content-Length, is exactly how
  ;; HTTP says the response was truncated, and the client detects it by
  ;; construction. Sending nothing at all, which is what happened before,
  ;; leaves the client waiting for a body that will never arrive.
  (define (res-abort! r)
    (abort-response! (res-conn r)))

  ;; Detach a stream into its own process, the way res-begin!'s docstring
  ;; recommends -- and clean up if it does not finish.
  ;;
  ;; A plain (spawn producer) is not linked to anything. The connection's
  ;; owner is still the reader, so uv-owner-died! does not fire when the
  ;; producer dies, the pool's abort path is not involved (the producer is
  ;; not a pool worker), and the reader stays parked in await-streaming with
  ;; no deadline. A producer that crashed after one chunk, or simply
  ;; returned without calling res-end!, therefore left the client waiting on
  ;; a truncated response for as long as it cared to wait, and left a green
  ;; process and its buffer behind on the server. The framework recommended
  ;; that shape, so the framework should make it safe.
  ;;
  ;; The watcher monitors rather than guards inside the producer, because a
  ;; producer that is KILLED -- which is what a supervisor does to a stuck
  ;; one -- discards its winders and would run no guard. Monitoring an
  ;; already-dead pid delivers DOWN at once, so the narrow window between
  ;; spawn and monitor is covered too.
  ;;
  ;; Only a stream still open is aborted: a producer that ended the response
  ;; and then failed has already framed it correctly, and truncating a
  ;; completed response would corrupt the next one on a kept-alive
  ;; connection.
  (define (res-spawn! r thunk)
    (let ((p (spawn thunk)))
      (spawn
        (lambda ()
          (monitor p)
          (receive
            (`#(DOWN ,@p ,reason)
              (when (res-streaming? r) (res-abort! r))))))
      p))

  (define (abort-response! c)
    (tcp-close! c)
    (let ((owner (conn-owner c)))
      (when owner (send owner (vector 'conn-closed)))))

  (define (fail-task sup on-failure task info)
    (let ((c (vector-ref task 2))
          (req (vector-ref task 3))
          (token (vector-ref task 4)))
      (cond
        ;; the response has already started: nothing can be sent, close
        ((unbox token) (abort-response! c))
        ((and on-failure (eq? (vector-ref task 0) 'task))
         (send sup (vector 'submit-urgent
                     (vector 'fail (vector-ref task 1) c req token info))))
        (else (quick-response! c 500 "Internal Server Error" token)))))

  ;; ---- chunked transfer-encoding (request side) ----------------------------------

  ;; A chunked body's DECODED length is bounded by body-limit, but the
  ;; framing around it was not: a body well inside the limit could arrive
  ;; as a million chunk headers, costing a cons and a bytevector each.
  ;;
  ;; The count has to move with body-limit, which is a per-listen option.
  ;; Pinning it to a constant means raising the limit for uploads silently
  ;; starts rejecting them: at 32 MiB a 10 MiB body in 512-byte chunks is
  ;; 20 000 chunks and was answered 413 while a third of the configured
  ;; limit. Deriving it holds one invariant instead -- an average chunk of
  ;; at least 64 bytes -- and reproduces the old 16384 exactly at the
  ;; default limit. The floor keeps a deliberately tiny body-limit from
  ;; making ordinary chunking impossible.
  (define (chunk-count-limit) (max 16384 (div body-limit 64)))
  ;; Absolute, unlike the count: a single chunk-size line of four kilobytes
  ;; is malformed however large the body is allowed to be.
  (define chunk-line-limit 4096)
  (define chunk-overhead-limit 65536)

  ;; hex chunk size, stopping at ';' (chunk extensions); #f if malformed.
  ;; The size value keeps GENERIC arithmetic on purpose: an absurd hex
  ;; size must overflow into a bignum and be rejected by the body-limit
  ;; check, not crash on a fixnum overflow.
  (define (parse-chunk-size bv start end)
    (let loop ((i start) (v 0) (any #f))
      (if (fx= i end)
          (and any v)
          (let ((b (bytevector-u8-ref bv i)))
            (cond
              ((fx= b 59) (and any v))                               ; ';'
              ((and (fx>= b 48) (fx<= b 57)) (loop (fx+ i 1) (+ (* v 16) (- b 48)) #t))
              ((and (fx>= b 97) (fx<= b 102)) (loop (fx+ i 1) (+ (* v 16) (- b 87)) #t))
              ((and (fx>= b 65) (fx<= b 70)) (loop (fx+ i 1) (+ (* v 16) (- b 55)) #t))
              (else #f))))))

  (define forbidden-trailer-fields
    '(transfer-encoding content-length host connection trailer upgrade))

  ;; a trailer line must carry a token-valid name that is not on the
  ;; forbidden list; matching goes through the common-name table, so
  ;; attacker-chosen trailer names are never interned
  (define (valid-trailer-line? bv start end)
    (guard (e (#t #f))
      (let* ((line (utf8->string (bv-sub bv start end)))
             (colon (string-index line #\:)))
        (and colon (fx> colon 0)
             (let loop ((i 0))
               (or (fx= i colon)
                   (and (lc-token-char (string-ref line i))
                        (loop (fx+ i 1)))))
             (not (memq (common-header-name line 0 colon)
                        forbidden-trailer-fields))))))

  (define (bv-concat lst total)
    (let ((out (make-bytevector total)))
      (let loop ((l lst) (off 0))
        (if (null? l)
            out
            (let ((x (car l)))
              (bytevector-copy! x 0 out off (bytevector-length x))
              (loop (cdr l) (+ off (bytevector-length x))))))))

  ;; Try to parse a complete chunked body from the inbuf, body-start and
  ;; all other positions RELATIVE to the buffer's start. st is #f for a
  ;; fresh parse or the resume state from a previous 'more -- already
  ;; extracted chunks are never re-parsed and never re-copied, so a body
  ;; drip-fed in tiny segments costs each byte once, not O(segments)
  ;; rescans (which a 1-byte-segment peer could otherwise run up to
  ;; GB-level wasted CPU inside the 30s window).
  ;; -> (values 'done body end-index) | (values 'more resume-state #f)
  ;;  | (values 'too-large #f #f) | (values 'bad #f #f)
  ;;  | (values 'trailers-too-large #f #f)
  (define (parse-chunked-body buf body-start st)
    (let* ((bv (inbuf-bv buf)) (base (inbuf-start buf))
           (blen (inbuf-length buf)))
      ;; find-crlf over the window, relative positions
      (define (crlf-at pos)
        (let loop ((i pos))
          (cond
            ((fx>= (fx+ i 1) blen) #f)
            ((and (fx= (bytevector-u8-ref bv (fx+ base i)) 13)
                  (fx= (bytevector-u8-ref bv (fx+ base (fx+ i 1))) 10))
             i)
            (else (loop (fx+ i 1))))))
      (define (u8 i) (bytevector-u8-ref bv (fx+ base i)))
      (let loop ((pos (if st (vector-ref st 0) body-start))
                 (chunks (if st (vector-ref st 1) '()))
                 (len (if st (vector-ref st 2) 0))
                 (count (if st (vector-ref st 3) 0)))
        (let ((eol (crlf-at pos)))
          (cond
            ((> (- pos body-start) (+ body-limit chunk-overhead-limit))
             (values 'too-large #f #f))
            ((not eol)
             (if (> (- blen pos) chunk-line-limit)
                 (values 'too-large #f #f)
                 (values 'more (vector pos chunks len count) #f)))
            ((> (- eol pos) chunk-line-limit)
             (values 'too-large #f #f))
            (else
             (let ((size (parse-chunk-size bv (fx+ base pos) (fx+ base eol))))
               (cond
                 ((not size) (values 'bad #f #f))
                 ((> (+ len size) body-limit) (values 'too-large #f #f))
                 ((= size 0)
                  ;; Validate and cap optional trailers; a blank line ends
                  ;; the body. Trailer fields are currently ignored.
                  (let ((trailer-start (+ eol 2)))
                    (let scan ((p trailer-start))
                      (let ((e2 (crlf-at p)))
                        (cond
                          ((not e2)
                           (if (> (- blen trailer-start) trailer-limit)
                               (values 'trailers-too-large #f #f)
                               (values 'more (vector pos chunks len count) #f)))
                          ((> (- (+ e2 2) trailer-start) trailer-limit)
                           (values 'trailers-too-large #f #f))
                          ((= e2 p)
                           (values 'done (bv-concat (reverse chunks) len) (+ p 2)))
                          ((valid-trailer-line? bv (fx+ base p) (fx+ base e2))
                           (scan (+ e2 2)))
                          (else (values 'bad #f #f)))))))
                 ((>= count (chunk-count-limit)) (values 'too-large #f #f))
                 (else
                  (let ((dstart (+ eol 2)))
                    (if (< blen (+ dstart size 2))
                        (values 'more (vector pos chunks len count) #f)
                        (if (not (and (= (u8 (+ dstart size)) 13)
                                      (= (u8 (+ dstart size 1)) 10)))
                            (values 'bad #f #f)
                            (loop (+ dstart size 2)
                                  (cons (bv-sub bv (fx+ base dstart)
                                                (fx+ base (+ dstart size)))
                                        chunks)
                                  (+ len size)
                                  (+ count 1))))))))))))))

  ;; ---- reader process ----------------------------------------------------------

  (define task-counter 0)
  (define (next-task-id!)
    (set! task-counter (+ task-counter 1))
    task-counter)

  (define (make-reader c srv)
    (lambda () (reader-loop c srv (make-inbuf))))

  ;; The connection's inbuf is the reader's single accumulation state:
  ;; appends are amortized O(1)/byte, the header-end scan resumes where
  ;; it left off, and consuming a request is an offset bump -- none of
  ;; the append-and-rescan-from-zero / recopy-the-remainder patterns.
  (define (reader-loop c srv buf) (reader-loop* c srv buf #f))

  ;; started: when the first byte of THIS request arrived (#f while the
  ;; connection is idle between requests, which may last read-timeout-ms
  ;; but is not a request in progress).
  (define (reader-loop* c srv buf started)
    (let ((hend (inbuf-find-header-end buf)))
      (cond
        ;; SIZE FIRST. A complete header block used to be accepted whatever
        ;; its size, because finding the terminator won the cond -- so the
        ;; limit only ever caught a header still arriving, and a peer that
        ;; sent the whole thing in one go was never checked at all. Measured:
        ;; a 9 KiB header answered 200 against an 8 KiB limit.
        ;;
        ;; The block is bounded by hend, not by what else is buffered: a
        ;; pipelined second request sitting behind this one is not part of
        ;; this header, and charging it here would reject legitimate traffic.
        ((and hend (> (+ hend 4) header-limit))
         (quick-response! c 431 "Header Too Large"))
        (hend (have-header c srv buf hend (or started (now-ms))))
        ((> (inbuf-length buf) header-limit)
         (quick-response! c 431 "Header Too Large"))
        ((and started (> (- (now-ms) started) request-deadline-ms))
         (quick-response! c 408 "Request Timeout"))
        (else
         (receive (after (if started
                             ;; never wait past the whole-request deadline
                             (max 1 (min read-timeout-ms
                                         (- (+ started request-deadline-ms)
                                            (now-ms))))
                             read-timeout-ms)
                     (if (> (inbuf-length buf) 0)
                         (quick-response! c 408 "Request Timeout")
                         (tcp-close! c)))   ; idle connection: just close
           (`#(tcp-data ,bv)
             (inbuf-append! buf bv)
             (reader-loop* c srv buf (or started (now-ms))))
           (`#(tcp-eof) (tcp-close! c))
           (`#(tcp-error ,e) (tcp-close! c)))))))

  ;; client sent Expect: 100-continue and is waiting for the interim
  ;; response before transmitting the body (curl stalls ~1s without it)
  (define (expect-100? headers)
    (let ((p (assq 'expect headers)))
      (and p (string-ci=? (cdr p) "100-continue"))))

  (define continue-100 (string->utf8 "HTTP/1.1 100 Continue\r\n\r\n"))

  (define (have-header c srv buf hend started)
    (let* ((base (inbuf-start buf))
           (parsed (parse-head (inbuf-bv buf) base (fx+ base hend))))
      (if (not parsed)
          (quick-response! c 400 "Bad Request")
          (let* ((headers (vector-ref parsed 4))
                 (wskey (websocket-key parsed))
                 (resolver (unbox (http-server-wsbox srv)))
                 (te (transfer-encoding headers))
                 (clen (content-length headers)))
            (cond
              ;; parse-head yields 'unsupported for a well-formed version
              ;; it does not speak (garbage is a plain 400 there)
              ((eq? (vector-ref parsed 3) 'unsupported)
               (quick-response! c 505 "HTTP Version Not Supported"))
              ((or (eq? clen 'bad) (eq? te 'bad))
               (quick-response! c 400 "Bad Request"))
              ((and (eq? te 'chunked) (not (eq? clen 'absent)))
               (quick-response! c 400 "Bad Request"))
              ;; chunked is an HTTP/1.1 framing (RFC 7230 3.3.1). An
              ;; HTTP/1.0 request declaring it is a request whose message
              ;; boundary this server and an HTTP/1.0 intermediary would
              ;; read differently -- which is the whole mechanism of
              ;; request smuggling. The version check already exists for
              ;; RESPONSES (see res-http10?); requests had none.
              ((and (eq? te 'chunked) (equal? (vector-ref parsed 3) "HTTP/1.0"))
               (quick-response! c 400 "Bad Request"))
              ;; A 101 ends HTTP framing: everything after the header block
              ;; is read as WebSocket frames. So a request that also
              ;; DECLARES a body has two readings -- body then frames, or
              ;; frames straight away -- and this server took the second
              ;; without checking. The declared bytes were never collected,
              ;; never counted against body-limit, and went to the frame
              ;; parser instead. Refuse the ambiguity before the handshake.
              ((and wskey resolver
                    (or (not (eq? te 'absent))
                        (and (not (eq? clen 'absent)) (not (eqv? clen 0)))))
               (quick-response! c 400 "Bad Request"))
              ((and resolver (websocket-attempt? headers) (not wskey))
               (quick-response! c 400 "Bad WebSocket Handshake"))
              ;; websocket upgrade: resolve a session, shake hands, and
              ;; run the session in this reader process
              ((and wskey resolver)
               (let* ((req (make-request (vector-ref parsed 0)
                                         (vector-ref parsed 1)
                                         (vector-ref parsed 2)
                                         '() headers empty-bv #f
                                         (vector-ref parsed 3)
                                         (conn-peer-ip c) '()))
                      (session (resolver req)))
                 (cond
                   ((procedure? session)
                    (run-ws-session c
                      (inbuf-sub buf (fx+ hend 4) (inbuf-length buf))
                      wskey req session))
                   ;; #(ws-reject status text): an auth guard refused the
                   ;; upgrade -- answered before any handshake, so an
                   ;; unauthenticated peer never gets a socket
                   ((and (vector? session)
                         (fx= (vector-length session) 3)
                         (eq? (vector-ref session 0) 'ws-reject))
                    (quick-response! c (vector-ref session 1)
                                     (vector-ref session 2)))
                   (else (quick-response! c 404 "Not Found")))))
              ((eq? te 'chunked)
               (when (expect-100? headers) (tcp-write! c continue-100 #f))
               (collect-chunked c srv buf parsed (fx+ hend 4) #f started))
              (else
               (let ((n (if (eq? clen 'absent) 0 clen)))
                 (cond
                   ((> n body-limit)
                    (quick-response! c 413 "Payload Too Large"))
                   (else
                    (when (and (> n 0) (expect-100? headers))
                      (tcp-write! c continue-100 #f))
                    (collect-body c srv buf parsed n (+ hend 4 n) started))))))))))

  ;; Dispatch the parsed request to the worker pool, then await the
  ;; response. Every request goes through the pool, so every handler gets
  ;; the same fault tolerance (crash retry, stuck-worker kill).
  ;; The request's bytes are already consumed from buf; whatever remains
  ;; is pipelined data, carried as-is (no per-request remainder copy --
  ;; that was O(k^2) over a k-request pipeline).
  (define (dispatch-request! c srv parsed body buf)
    (let* ((headers (vector-ref parsed 4))
           (req (make-request (vector-ref parsed 0)
                              (vector-ref parsed 1)
                              (vector-ref parsed 2)
                              '()
                              headers
                              body
                              (keep-alive? (vector-ref parsed 3) headers)
                              (vector-ref parsed 3)
                              (conn-peer-ip c)
                              '()))
           (id (next-task-id!))
           (token (make-token)))
      (send (http-server-sup srv)
        (vector 'submit-task (vector 'task id c req token)))
      (await-response c srv buf #f)))

  ;; total = header block + body length, RELATIVE to the buffer start
  ;; The body phases share the header phase's whole-request deadline -- the
  ;; same absolute instant, not a second budget of the same length: without
  ;; any deadline a 1 MiB body dribbled one byte per 29 s pins a reader for
  ;; weeks, and with a restarting one it pins it for twice as long as the
  ;; setting says. `deadline` is an absolute ms timestamp.
  (define (body-wait-ms deadline)
    (if deadline
        (max 1 (min read-timeout-ms (- deadline (now-ms))))
        read-timeout-ms))

  ;; `started` is when the FIRST byte of this request arrived, carried in
  ;; from the header phase. Computing (+ (now-ms) request-deadline-ms) here
  ;; instead restarted the clock at the header/body boundary, so a client
  ;; could take almost the full deadline over the head and then almost the
  ;; full deadline again over the body -- twice the budget the setting names,
  ;; and the reader held for all of it.
  (define (collect-body c srv buf parsed clen total started)
    (collect-body* c srv buf parsed clen total
                   (+ started request-deadline-ms)))

  (define (collect-body* c srv buf parsed clen total deadline)
    (cond
      ((>= (inbuf-length buf) total)
       (let ((body (inbuf-sub buf (- total clen) total)))
         (inbuf-consume! buf total)
         (dispatch-request! c srv parsed body buf)))
      ((> (now-ms) deadline) (quick-response! c 408 "Request Timeout"))
      (else
       (receive (after (body-wait-ms deadline)
                   (quick-response! c 408 "Request Timeout"))
         (`#(tcp-data ,bv)
           (inbuf-append! buf bv)
           (collect-body* c srv buf parsed clen total deadline))
         (`#(tcp-eof) (tcp-close! c))
         (`#(tcp-error ,e) (tcp-close! c))))))

  (define (collect-chunked c srv buf parsed body-start st started)
    (collect-chunked* c srv buf parsed body-start st
                      (+ started request-deadline-ms)))

  (define (collect-chunked* c srv buf parsed body-start st deadline)
    (let-values (((status a b) (parse-chunked-body buf body-start st)))
      (case status
        ((done)
         (inbuf-consume! buf b)
         (dispatch-request! c srv parsed a buf))
        ((more)
         (if (> (now-ms) deadline)
             (quick-response! c 408 "Request Timeout")
             (receive (after (body-wait-ms deadline)
                         (quick-response! c 408 "Request Timeout"))
               (`#(tcp-data ,bv)
                 (inbuf-append! buf bv)
                 (collect-chunked* c srv buf parsed body-start a deadline))
               (`#(tcp-eof) (tcp-close! c))
               (`#(tcp-error ,e) (tcp-close! c)))))
        ((too-large) (quick-response! c 413 "Payload Too Large"))
        ((trailers-too-large) (quick-response! c 431 "Trailer Too Large"))
        (else (quick-response! c 400 "Bad Request")))))

  ;; Wait for the worker's response to complete. Data arriving meanwhile
  ;; (pipelining) is buffered; EOF is remembered so we stop after replying.
  (define (await-response c srv buf eof?)
    (receive (after await-timeout-ms (tcp-close! c))
      (`#(next-request)
        (if eof? (tcp-close! c) (reader-loop c srv buf)))
      (`#(conn-closed) 'done)
      (`#(streaming) (await-streaming c srv buf eof?))
      (`#(tcp-data ,bv)
        (inbuf-append! buf bv)
        (if (> (inbuf-length buf) pipeline-limit)
            (tcp-close! c)                          ; peer over-pipelining
            (await-response c srv buf eof?)))
      ;; EOF HERE IS NOT "THE CLIENT LEFT".
      ;;
      ;; This wait begins only once a COMPLETE request has been dispatched,
      ;; so an eof at this point means the peer closed its WRITE side having
      ;; said everything it had to say -- shutdown(SHUT_WR), which RFC 7230
      ;; 6.6 permits and which several clients and load generators do as a
      ;; matter of course. They are still waiting for the response.
      ;;
      ;; Closing immediately answered them with nothing: measured, a raw
      ;; client that half-closed after a complete request received 0 bytes.
      ;; So the eof is remembered and the response is delivered, after which
      ;; the connection closes because there is nothing left to reuse.
      ;;
      ;; What that gives up is real and was the reason for the earlier
      ;; behaviour: a client that truly vanished also reaches here, and its
      ;; queued work now runs. That saving is not worth answering a
      ;; conforming client with silence -- and it is partly recovered
      ;; anyway, because writing to a socket that is really gone fails at
      ;; once. Eof during reader-loop, where the request is INCOMPLETE, is a
      ;; different matter and still closes immediately.
      (`#(tcp-eof) (await-response c srv buf #t))
      (`#(tcp-error ,e) (tcp-close! c) 'done)))

  ;; A streamed (chunked/SSE) response is in progress: wait without a
  ;; deadline. The producer notices a departed client through res-write!
  ;; returning #f, or through its write timing out.
  ;; eof?: the peer has closed its WRITE side. It cannot send another
  ;; request, so when the stream ends there is nothing to keep the
  ;; connection for -- looping back to reader-loop would park it for a full
  ;; read timeout waiting for bytes that cannot come. Carrying the flag
  ;; through the transition is also why await-response takes it: dropping
  ;; it there lost the only thing known about the peer.
  (define (await-streaming c srv buf . rest)
    (let ((eof? (and (pair? rest) (car rest))))
    (receive (after 'infinity #f)
      (`#(next-request)
        (if eof? (begin (tcp-close! c) 'done) (reader-loop c srv buf)))
      (`#(conn-closed) 'done)
      (`#(tcp-data ,bv)
        (inbuf-append! buf bv)
        (if (> (inbuf-length buf) pipeline-limit)
            (begin (tcp-close! c) 'done)
            (await-streaming c srv buf eof?)))
      ;; Same reasoning as await-response's eof, and the same mistake was
      ;; here: a stream is under way, which means the request was complete,
      ;; so an eof is the peer closing its WRITE side and waiting. Closing
      ;; ended the stream at its first byte. A client that really left is
      ;; still noticed -- by the writes failing, which is what stops the
      ;; producer either way.
      (`#(tcp-eof) (await-streaming c srv buf #t))
      (`#(tcp-error ,e) (tcp-close! c) 'done))))

  ;; ---- websocket session ---------------------------------------------------------

  ;; 101 handshake, then hand the connection to the session procedure,
  ;; still inside this reader process (one process per ws connection).
  ;; A crashing session just closes its own connection.
  (define ws-handshake-prefix
    (string-append
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
      "Sec-WebSocket-Accept: "))

  ;; leftover: bytes already read past the upgrade request's header
  ;; block -- they belong to the ws stream
  (define (run-ws-session c leftover key req session)
    (tcp-write! c
      (string->utf8
        (string-append ws-handshake-prefix (ws-accept-key key) "\r\n\r\n"))
      #f)
    (let ((w (make-ws c leftover)))
      (guard (e (#t (void)))
        (session w req))
      (ws-close! w)))

  ;; ---- listen ------------------------------------------------------------------

  ;; The running server: worker-pool supervisor plus swappable slots.
  ;; hbox holds the (lambda (req res)) handler -- replacing it with
  ;; http-swap! upgrades the code with zero downtime (in-flight requests
  ;; finish on the old handler; new requests get the new one).
  ;; wsbox holds the websocket resolver: (lambda (req) session-or-#f).
  (define-record-type (http-server make-http-server http-server?)
    (fields
      (immutable sup http-server-sup)
      (immutable hbox http-server-hbox)
      (immutable wsbox http-server-wsbox)
      (immutable started http-server-started)
      ;; this server's listener handle, so shutdown stops only this
      ;; server (several servers may listen in one process)
      (mutable listener http-server-listener http-server-listener-set!)))

  (define (http-swap! srv handler)
    (set-box! (http-server-hbox srv) handler))

  (define (http-set-ws! srv resolver)
    (set-box! (http-server-wsbox srv) resolver))

  ;; IS THIS SERVER'S POOL SUPERVISOR STILL ALIVE -- that, and only that.
  ;; The name says pool on purpose. An earlier version of this was called
  ;; http-server-alive? and documented as "can this server still serve",
  ;; which it cannot answer: http-shutdown! stops the listener and leaves
  ;; the supervisor running, so the predicate stays true for a server that
  ;; will never accept another request (measured).
  ;;
  ;; What it IS good for: the pool supervisor is where requests go, so its
  ;; death means this server cannot serve -- a false answer is conclusive.
  ;; A true answer is not: readiness would also need the listener, and this
  ;; does not look at it. It says nothing about load either; a pool with
  ;; every worker busy and a long queue is alive, and http-stats is where
  ;; that is answered.
  ;;
  ;; It exists so that something which only wants to observe does not have
  ;; to take http-server-sup, which hands over the means to end the image.
  (define (http-server-pool-alive? srv)
    (process-alive? (http-server-sup srv)))

  ;; runtime snapshot: open connections, total requests, uptime, and the
  ;; worker pool's idle/busy/pending counters
  (define (http-stats srv)
    (append
      (list (cons 'connections (conn-count))
            (cons 'requests task-counter)
            (cons 'uptime-ms (- (now-ms) (http-server-started srv))))
      (pool-stats (http-server-sup srv))))

  ;; THE SAME SNAPSHOT AS A JSON VALUE. http-stats is a Scheme-facing
  ;; result read with assq, so its keys are symbols; (igropyr json)
  ;; refuses a symbol key. Handing http-stats straight to a JSON writer
  ;; therefore raises on its first member, and it did -- an endpoint
  ;; built that way answered for as long as symbols were written as
  ;; strings and stopped the day they were not. The conversion belongs
  ;; here, beside the thing being converted, rather than in each caller:
  ;; a caller-side adapter is invisible to the suites that own this
  ;; library, and the two that existed both lived in files no runner
  ;; executes.
  ;;
  ;; THE KEY NAMES ARE THE WIRE CONTRACT, so this spells each symbol and
  ;; changes nothing else: connections, requests, uptime-ms, and whatever
  ;; the pool contributes. Those are the exact names the endpoint emitted
  ;; back when a symbol key was written as a string, which makes this a
  ;; restoration rather than a redesign -- a client written against it
  ;; keeps working. Prettier spellings were considered and rejected here:
  ;; nothing in Scheme refers to these strings, so renaming one is
  ;; invisible at compile time and breaks only the consumer.
  (define (http-stats-json srv)
    (map (lambda (kv) (cons (symbol->string (car kv)) (cdr kv)))
         (http-stats srv)))

  ;; Graceful shutdown: stop accepting, then wait until every accepted
  ;; request has been answered (busy = pending = 0). Established
  ;; keep-alive connections stay open but receive no new dispatches;
  ;; their readers idle out. Call from a detached process, never from a
  ;; pool worker (the worker itself counts as busy -- deadlock).
  (define (http-shutdown! srv)
    (tcp-stop-listen! (http-server-listener srv))
    (let drain ()
      (let ((s (pool-stats (http-server-sup srv))))
        (if (and (= 0 (cdr (assq 'busy s)))
                 (= 0 (cdr (assq 'pending s))))
            'done
            (begin (sleep-ms 100) (drain))))))

  ;; Start the worker pool and the TCP listener; handler is
  ;; (lambda (req res) ...), run inside a pool worker for every request.
  ;; Must run inside the scheduler (call from the start-scheduler boot
  ;; thunk). Returns an http-server usable with http-swap!/http-set-ws!.
  ;;
  ;; The optional third argument configures the pool: either a plain
  ;; integer (worker count) or an alist:
  ;;   (http-listen 8080 handler
  ;;     `((workers . 16)        ; pool size            (default 8)
  ;;       (max-retries . 3)     ; crash retries        (default 3)
  ;;       (stuck-ms . 30000)    ; stuck-kill threshold (default 30000)
  ;;       (check-ms . 5000)     ; ticker interval      (default 5000)
  ;;       (on-failure . ,proc)  ; failure hook: (lambda (req res info))
  ;;                             ; runs on a fresh worker when retries are
  ;;                             ; exhausted or a stuck worker was killed;
  ;;                             ; info: ((kind . crash|stuck) (reason . r)
  ;;                             ;        (id . task-id) (attempts . n)
  ;;                             ;        (elapsed-ms . t)).
  ;;                             ; Unset: plain 500 as always.
  ;;       (host . "0.0.0.0")    ; interface to bind (default all). Set
  ;;                             ; "127.0.0.1" to keep a listener local --
  ;;                             ; e.g. an admin/metrics port that must not
  ;;                             ; be reachable off-box.
  ;;       (reuseport . #t)      ; SO_REUSEPORT bind: run N OS processes
  ;;                             ; on the same port, kernel-balanced
  ;;                             ; (Linux; not macOS)
  ;;       (body-limit . N)))    ; request body cap in bytes (default 1 MiB,
  ;;                             ; 413 beyond it). PROCESS-GLOBAL: the last
  ;;                             ; http-listen wins across all servers in
  ;;                             ; this process; pipeline-limit follows.
  (define (http-listen port handler . rest)
    (define opts
      (cond
        ((null? rest) '())
        ((integer? (car rest)) (list (cons 'workers (car rest))))
        ((or (null? (car rest)) (pair? (car rest))) (car rest))
        (else (assertion-violation 'http-listen "bad options" (car rest)))))
    (define (opt key default)
      (let ((p (assq key opts)))
        (if p (cdr p) default)))
    ;; Configurable body-limit (process-global): also unblocks cp0 constant
    ;; inlining so parser reads see the new value. Keep pipeline-limit in
    ;; step. A bad value must crash HERE, at boot -- deferred to request
    ;; time it raises inside the reader and the connection just drops.
    (let ((bl (opt 'body-limit #f)))
      (when bl
        (unless (and (fixnum? bl) (fx> bl 0))
          (assertion-violation 'http-listen
            "body-limit must be a positive fixnum" bl))
        (set! body-limit bl)
        (set! pipeline-limit (+ header-limit bl))))
    (let* ((hbox (box handler))
           (wsbox (box #f))
           (obox (box (opt 'on-failure #f)))
           (supbox (box #f))
           (sup (start-worker-pool (opt 'workers 8)
                  (lambda (task) (run-task (unbox hbox) (unbox obox) task))
                  (lambda (task info)
                    (fail-task (unbox supbox) (unbox obox) task info))
                  (opt 'max-retries 3)
                  (opt 'stuck-ms 30000)
                  (opt 'check-ms 5000)
                  ;; Only a task that has NOT answered may be re-run. A
                  ;; handler that responded and then raised -- in cleanup, in
                  ;; logging, on a middleware's way back out -- has already
                  ;; had its effects observed, and the claimed token means a
                  ;; retry could not produce a response anyway. Re-running it
                  ;; would repeat the writes it made while the client holds a
                  ;; success it will never see corrected.
                  (lambda (task) (not (unbox (vector-ref task 4))))))
           (host (opt 'host "0.0.0.0"))
           (srv (make-http-server sup hbox wsbox (now-ms) 0)))
      (unless (and (string? host) (> (string-length host) 0))
        (assertion-violation 'http-listen "host must be a non-empty string" host))
      (set-box! supbox sup)
      ;; LOSING THE POOL SUPERVISOR LEAVES A LISTENER THAT CANNOT SERVE.
      ;; Every request is submitted to it, so once it is gone requests are
      ;; submitted to nothing and time out -- while the process is still
      ;; running and still accepting connections. Marking it critical turns
      ;; that into an exit 70 instead. Nothing here could restart it and
      ;; reattach the workers and tasks it owned, which is why the answer is
      ;; to end the image rather than to grow a supervision tree.
      ;;
      ;; THE NAME CARRIES THE PORT, because a process may run several
      ;; listeners -- an application port and an admin or metrics port are
      ;; the usual pair -- and a panic saying only "http-worker-pool" would
      ;; not say which. ASSUMED HERE, and queued rather than built: that
      ;; every listener in the process is one the image cannot serve
      ;; without. A genuinely optional listener has no way to opt out of
      ;; this, and taking one down will end the process.
      (critical! sup (string->symbol
                       (string-append "http-worker-pool:"
                                      (number->string port))))
      (http-server-listener-set! srv
        (tcp-listen! host port 511
          (lambda (c)
            ;; libuv callback context: spawn + register only, no yielding
            (let ((pid (spawn (make-reader c srv))))
              (conn-set-owner! c pid)
              (tcp-read-start! c)))
          (if (opt 'reuseport #f) 2 0)))  ; UV_TCP_REUSEPORT
      (display (string-append "igropyr listening on http://" host ":"
                              (number->string port) "\n"))
      srv))
)
