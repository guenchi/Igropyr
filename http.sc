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
          http-stats http-shutdown!
          ;; record predicates, exported for boundary contracts
          ;; ((igropyr checked) in the framework layers) and any
          ;; user code that wants to type-test req/res values
          request? res?
          req-method req-path req-query req-headers req-header req-body
          req-keep-alive? req-params req-params-set!
          req-local req-set-local!
          set-status! set-header! res-send!
          res-begin! res-write! res-end!
          res-begin-file! res-write-file! res-write-chunk! res-abort-file!
          res-conn res-req res-status res-headers res-keep-alive?
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
  (define await-timeout-ms 60000)  ; reader waits this long for a response

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
                   (e (if (and (fx> nl i)
                               (char=? (string-ref text (fx- nl 1)) #\return))
                          (fx- nl 1)
                          nl)))
              (cond
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
             (rl-end (if (and (fx> nl1 0)
                              (char=? (string-ref text (fx- nl1 1)) #\return))
                         (fx- nl1 1)
                         nl1)))
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
                             (path (percent-decode
                                     (substring text (fx+ sp1 1) (or qpos sp2))
                                     #f))          ; "+" is literal in a path
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

  ;; websocket upgrade request? returns the Sec-WebSocket-Key or #f
  (define (websocket-key headers)
    (let ((u (assq 'upgrade headers))
          (k (assq 'sec-websocket-key headers)))
      (and u k (string-ci=? (cdr u) "websocket") (cdr k))))

  ;; case-insensitive compare in place: no string-downcase copy per request
  (define (keep-alive? version headers)
    (let ((p (assq 'connection headers)))
      (if (string=? version "HTTP/1.1")
          (not (and p (string-ci=? (cdr p) "close")))
          (and p (string-ci=? (cdr p) "keep-alive")))))

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
  (define (claim! token) (and (not (unbox token)) (set-box! token #t) #t))

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

  ;; Write a full response, guarded by the request's token. The libuv
  ;; write callback (no yielding) tells the reader to continue
  ;; (keep-alive) or closes the connection.
  (define (send-response! c token status headers body ka)
    (when (claim! token)
      (let* ((head
              (assemble-head status headers
                "Content-Length: " (number->string (bytevector-length body))
                (if ka keep-alive-tail close-tail)))
             (owner (conn-owner c)))
        ;; head and body are written as two segments -- no bv-append copy
        (tcp-writev! c (list (string->utf8 head) body)
          (lambda (st)
            (if (and ka (>= st 0))
                (send owner (vector 'next-request))
                (begin
                  (tcp-close! c)
                  (send owner (vector 'conn-closed)))))))))

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

  (define (set-status! r s) (res-status-set! r s))

  ;; Silently ignore header names/values containing CR or LF; they are
  ;; also rejected again at render time.
  (define (set-header! r k v)
    (when (and (header-safe? k) (header-safe? v))
      (res-headers-set! r (cons (cons k v) (res-headers r)))))

  ;; Send the response: current status + accumulated headers + body
  ;; bytevector. One shot per request; later calls are ignored.
  (define (res-send! r body)
    (send-response! (res-conn r) (res-token r) (res-status r) (res-headers r)
                    body (res-keep-alive? r)))

  ;; ---- streaming responses (Transfer-Encoding: chunked) ------------------------

  ;; Begin a streamed response: send status + headers now, body comes in
  ;; chunks. Marks the request as responded (the supervisor fallback
  ;; stays away) and tells the reader to wait for the stream to finish.
  ;; A long stream should be detached from the pool worker:
  ;;   (res-begin! r) (spawn (lambda () ... (res-write! r x) ... (res-end! r)))
  (define chunked-keep-alive-tail
    "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n")
  (define chunked-close-tail
    "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")

  (define (res-begin! r)
    (let ((c (res-conn r)))
      (when (claim! (res-token r))
        (res-mode-set! r 'streaming)
        (tcp-write! c
          (string->utf8
            (assemble-head (res-status r) (res-headers r)
              (if (res-keep-alive? r) chunked-keep-alive-tail chunked-close-tail)))
          #f)
        (send (conn-owner c) (vector 'streaming)))))

  ;; Write one chunk (string or bytevector). #f when the stream is not
  ;; open any more (e.g. the client disconnected) -- stop the loop then.
  (define crlf-bv (string->utf8 "\r\n"))

  (define (res-write! r data)
    (let ((bv (if (string? data) (string->utf8 data) data))
          (c (res-conn r)))
      (and (eq? (res-mode r) 'streaming)
           (eq? (conn-state c) 'open)
           (> (bytevector-length bv) 0)
           ;; chunk = <hex size>CRLF <data> CRLF, written as three segments
           (tcp-writev! c
             (list (string->utf8
                     (string-append (number->string (bytevector-length bv) 16) "\r\n"))
                   bv
                   crlf-bv)
             #f))))

  ;; Finish the stream: terminating chunk, then the usual keep-alive /
  ;; close continuation. The terminator is encoded once at load time;
  ;; sharing the bytevector across writes is safe because tcp-writev!
  ;; copies it out synchronously.
  (define chunk-terminator (string->utf8 "0\r\n\r\n"))

  (define (res-end! r)
    (when (eq? (res-mode r) 'streaming)
      (res-mode-set! r 'done)
      (let* ((c (res-conn r))
             (owner (conn-owner c))
             (ka (res-keep-alive? r)))
        (tcp-write! c chunk-terminator
          (lambda (st)
            (if (and ka (>= st 0))
                (send owner (vector 'next-request))
                (begin
                  (tcp-close! c)
                  (send owner (vector 'conn-closed)))))))))

  ;; ---- fixed-length streaming (large files) --------------------------------

  ;; Begin a response of known length: status + headers + Content-Length
  ;; go out now, the body follows through res-write-file!. Claims the
  ;; token, so call this from the pool worker, then spawn a pump process
  ;; for the writes (as with res-begin!) -- a long download must not
  ;; occupy a worker or it would be killed as stuck.
  (define (res-begin-file! r len)
    (let ((c (res-conn r)))
      (when (claim! (res-token r))
        (res-mode-set! r 'raw)
        (res-remaining-set! r len)
        (tcp-write! c
          (string->utf8
            (assemble-head (res-status r) (res-headers r)
              "Content-Length: " (number->string len)
              (if (res-keep-alive? r) keep-alive-tail close-tail)))
          #f)
        (send (conn-owner c) (vector 'streaming)))))

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
               (if (eq? (unbox b) 'pending)
                   (set-box! b st)
                   (send me (vector 'file-written st)))))
           (let ((st (unbox b)))
             (if (eq? st 'pending)
                 (begin
                   (set-box! b 'parked)
                   (receive
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
          (begin
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
  (define (fail-task sup on-failure task info)
    (let ((c (vector-ref task 2))
          (req (vector-ref task 3))
          (token (vector-ref task 4)))
      (if (and on-failure
               (eq? (vector-ref task 0) 'task)
               (not (unbox token)))
          (send sup (vector 'submit-urgent
                      (vector 'fail (vector-ref task 1) c req token info)))
          (quick-response! c 500 "Internal Server Error" token))))

  ;; ---- chunked transfer-encoding (request side) ----------------------------------

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
                 (len (if st (vector-ref st 2) 0)))
        (let ((eol (crlf-at pos)))
          (if (not eol)
              (if (> (- blen pos) (+ body-limit 1024))
                  (values 'too-large #f #f)
                  (values 'more (vector pos chunks len) #f))
              (let ((size (parse-chunk-size bv (fx+ base pos) (fx+ base eol))))
                (cond
                  ((not size) (values 'bad #f #f))
                  ((> (+ len size) body-limit) (values 'too-large #f #f))
                  ((= size 0)
                   ;; Validate and cap optional trailers; a blank line ends
                   ;; the body. Trailer fields are currently ignored. The
                   ;; trailer block re-scans from here on each segment --
                   ;; bounded by trailer-limit, so no quadratic exposure.
                   (let ((trailer-start (+ eol 2)))
                     (let scan ((p trailer-start))
                       (let ((e2 (crlf-at p)))
                         (cond
                           ((not e2)
                            (if (> (- blen trailer-start) trailer-limit)
                                (values 'trailers-too-large #f #f)
                                ;; resume at the zero-size line so the
                                ;; trailer phase re-enters here
                                (values 'more (vector pos chunks len) #f)))
                           ((> (- (+ e2 2) trailer-start) trailer-limit)
                            (values 'trailers-too-large #f #f))
                           ((= e2 p)
                            (values 'done (bv-concat (reverse chunks) len) (+ p 2)))
                           ((valid-trailer-line? bv (fx+ base p) (fx+ base e2))
                            (scan (+ e2 2)))
                           (else (values 'bad #f #f)))))))
                  (else
                   (let ((dstart (+ eol 2)))
                     (if (< blen (+ dstart size 2))
                         (values 'more (vector pos chunks len) #f)
                         (if (not (and (= (u8 (+ dstart size)) 13)
                                       (= (u8 (+ dstart size 1)) 10)))
                             (values 'bad #f #f)
                             (loop (+ dstart size 2)
                                   (cons (bv-sub bv (fx+ base dstart)
                                                 (fx+ base (+ dstart size)))
                                         chunks)
                                   (+ len size)))))))))))))

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
  (define (reader-loop c srv buf)
    (let ((hend (inbuf-find-header-end buf)))
      (cond
        (hend (have-header c srv buf hend))
        ((> (inbuf-length buf) header-limit)
         (quick-response! c 431 "Header Too Large"))
        (else
         (receive (after read-timeout-ms
                     (if (> (inbuf-length buf) 0)
                         (quick-response! c 408 "Request Timeout")
                         (tcp-close! c)))   ; idle connection: just close
           (`#(tcp-data ,bv) (inbuf-append! buf bv) (reader-loop c srv buf))
           (`#(tcp-eof) (tcp-close! c))
           (`#(tcp-error ,e) (tcp-close! c)))))))

  ;; client sent Expect: 100-continue and is waiting for the interim
  ;; response before transmitting the body (curl stalls ~1s without it)
  (define (expect-100? headers)
    (let ((p (assq 'expect headers)))
      (and p (string-ci=? (cdr p) "100-continue"))))

  (define continue-100 (string->utf8 "HTTP/1.1 100 Continue\r\n\r\n"))

  (define (have-header c srv buf hend)
    (let* ((base (inbuf-start buf))
           (parsed (parse-head (inbuf-bv buf) base (fx+ base hend))))
      (if (not parsed)
          (quick-response! c 400 "Bad Request")
          (let* ((headers (vector-ref parsed 4))
                 (wskey (websocket-key headers))
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
              ;; websocket upgrade: resolve a session, shake hands, and
              ;; run the session in this reader process
              ((and wskey resolver)
               (let* ((req (make-request (vector-ref parsed 0)
                                         (vector-ref parsed 1)
                                         (vector-ref parsed 2)
                                         '() headers empty-bv #f '()))
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
               (collect-chunked c srv buf parsed (fx+ hend 4) #f))
              (else
               (let ((n (if (eq? clen 'absent) 0 clen)))
                 (cond
                   ((> n body-limit)
                    (quick-response! c 413 "Payload Too Large"))
                   (else
                    (when (and (> n 0) (expect-100? headers))
                      (tcp-write! c continue-100 #f))
                    (collect-body c srv buf parsed n (+ hend 4 n)))))))))))

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
                              '()))
           (id (next-task-id!))
           (token (make-token)))
      (send (http-server-sup srv)
        (vector 'submit-task (vector 'task id c req token)))
      (await-response c srv buf #f)))

  ;; total = header block + body length, RELATIVE to the buffer start
  (define (collect-body c srv buf parsed clen total)
    (if (>= (inbuf-length buf) total)
        (let ((body (inbuf-sub buf (- total clen) total)))
          (inbuf-consume! buf total)
          (dispatch-request! c srv parsed body buf))
        (receive (after read-timeout-ms (quick-response! c 408 "Request Timeout"))
          (`#(tcp-data ,bv)
            (inbuf-append! buf bv)
            (collect-body c srv buf parsed clen total))
          (`#(tcp-eof) (tcp-close! c))
          (`#(tcp-error ,e) (tcp-close! c)))))

  (define (collect-chunked c srv buf parsed body-start st)
    (let-values (((status a b) (parse-chunked-body buf body-start st)))
      (case status
        ((done)
         (inbuf-consume! buf b)
         (dispatch-request! c srv parsed a buf))
        ((more)
         (receive (after read-timeout-ms (quick-response! c 408 "Request Timeout"))
           (`#(tcp-data ,bv)
             (inbuf-append! buf bv)
             (collect-chunked c srv buf parsed body-start a))
           (`#(tcp-eof) (tcp-close! c))
           (`#(tcp-error ,e) (tcp-close! c))))
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
      (`#(streaming) (await-streaming c srv buf))
      (`#(tcp-data ,bv)
        (inbuf-append! buf bv)
        (if (> (inbuf-length buf) pipeline-limit)
            (tcp-close! c)                          ; peer over-pipelining
            (await-response c srv buf eof?)))
      (`#(tcp-eof) (await-response c srv buf #t))
      (`#(tcp-error ,e) (await-response c srv buf #t))))

  ;; A streamed (chunked/SSE) response is in progress: wait without a
  ;; deadline. On client disconnect the reader closes and exits; the
  ;; producer notices through res-write! returning #f.
  (define (await-streaming c srv buf)
    (receive (after 'infinity #f)
      (`#(next-request) (reader-loop c srv buf))
      (`#(conn-closed) 'done)
      (`#(tcp-data ,bv)
        (inbuf-append! buf bv)
        (if (> (inbuf-length buf) pipeline-limit)
            (begin (tcp-close! c) 'done)
            (await-streaming c srv buf)))
      (`#(tcp-eof) (tcp-close! c) 'done)
      (`#(tcp-error ,e) (tcp-close! c) 'done)))

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

  ;; runtime snapshot: open connections, total requests, uptime, and the
  ;; worker pool's idle/busy/pending counters
  (define (http-stats srv)
    (append
      (list (cons 'connections (conn-count))
            (cons 'requests task-counter)
            (cons 'uptime-ms (- (now-ms) (http-server-started srv))))
      (pool-stats (http-server-sup srv))))

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
  ;;       (reuseport . #t)))    ; SO_REUSEPORT bind: run N OS processes
  ;;                             ; on the same port, kernel-balanced
  ;;                             ; (Linux; not macOS)
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
    ;; inlining so parser reads see the new value. Keep pipeline-limit in step.
    (let ((bl (opt 'body-limit #f)))
      (when bl (set! body-limit bl) (set! pipeline-limit (+ header-limit bl))))
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
                  (opt 'check-ms 5000)))
           (srv (make-http-server sup hbox wsbox (now-ms) 0)))
      (set-box! supbox sup)
      (http-server-listener-set! srv
        (tcp-listen! "0.0.0.0" port 511
          (lambda (c)
            ;; libuv callback context: spawn + register only, no yielding
            (let ((pid (spawn (make-reader c srv))))
              (conn-set-owner! c pid)
              (tcp-read-start! c)))
          (if (opt 'reuseport #f) 2 0)))  ; UV_TCP_REUSEPORT
      (display (string-append "igropyr listening on http://0.0.0.0:"
                              (number->string port) "\n"))
      srv))
)
