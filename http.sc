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
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr otp)
          (igropyr websocket))

  (define header-limit 8192)
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

  ;; Appending onto an empty buffer returns the other side unchanged --
  ;; the common first-chunk case costs nothing. Safe to alias: buffers
  ;; are treated as immutable by every caller.
  (define (bv-append a b)
    (let ((la (bytevector-length a))
          (lb (bytevector-length b)))
      (cond
        ((fx= la 0) b)
        ((fx= lb 0) a)
        (else
         (let ((r (make-bytevector (fx+ la lb))))
           (bytevector-copy! a 0 r 0 la)
           (bytevector-copy! b 0 r la lb)
           r)))))

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  ;; index of the \r\n\r\n terminating the header block, or #f
  (define (find-header-end bv)
    (let ((n (bytevector-length bv)))
      (let loop ((i 0))
        (cond
          ((fx> (fx+ i 3) (fx- n 1)) #f)
          ((and (fx= (bytevector-u8-ref bv i) 13)
                (fx= (bytevector-u8-ref bv (fx+ i 1)) 10)
                (fx= (bytevector-u8-ref bv (fx+ i 2)) 13)
                (fx= (bytevector-u8-ref bv (fx+ i 3)) 10))
           i)
          (else (loop (fx+ i 1)))))))

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

  ;; Split the header text on \n with the trailing \r of each line
  ;; dropped in the same pass -- one substring per line instead of the
  ;; split-then-strip double copy.
  (define (split-header-lines s)
    (let ((n (string-length s)))
      (define (line-end start end)
        (if (and (fx> end start)
                 (char=? (string-ref s (fx- end 1)) #\return))
            (fx- end 1)
            end))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((fx= i n)
           (reverse (cons (substring s start (line-end start n)) acc)))
          ((char=? (string-ref s i) #\newline)
           (loop (fx+ i 1) (fx+ i 1)
                 (cons (substring s start (line-end start i)) acc)))
          (else (loop (fx+ i 1) start acc))))))

  ;; "Content-Length: 42" -> (content-length . "42"), or #f
  (define (parse-header-line l)
    (let ((colon (string-index l #\:)))
      (and colon
           (let ((k (string->symbol (string-downcase (substring l 0 colon))))
                 (v (let trim ((j (+ colon 1)))
                      (if (and (< j (string-length l))
                               (char=? (string-ref l j) #\space))
                          (trim (+ j 1))
                          (substring l j (string-length l))))))
             (cons k v)))))

  ;; Repeated header fields are coalesced into one comma-joined value
  ;; (RFC 7230); this lets content-length see "5,6" and reject the
  ;; conflict, and keeps request accessors single-valued.
  (define (parse-header-lines lines)
    (let ((acc (fold-right
                 (lambda (l a)
                   (let ((kv (and (not (string=? l "")) (parse-header-line l))))
                     (if (not kv)
                         a
                         (let ((prev (assq (car kv) a)))
                           (if prev
                               (begin
                                 (set-cdr! prev
                                   (string-append (cdr prev) "," (cdr kv)))
                                 a)
                               (cons kv a))))))
                 '() lines)))
      acc))

  ;; Parse request line + headers from the header block.
  ;; Returns #(method path query version headers) or #f on malformed input.
  (define (parse-head bv hend)
    (guard (e (#t #f))
      (let* ((text (utf8->string (bv-sub bv 0 hend)))
             (lines (split-header-lines text))
             (rl (string-split (car lines) #\space)))
        (and (= (length rl) 3)
             (let* ((method (string->symbol (car rl)))
                    (target (cadr rl))
                    (version (caddr rl))
                    (qpos (string-index target #\?))
                    (path (percent-decode
                            (if qpos (substring target 0 qpos) target)
                            #f))                     ; "+" is literal in a path
                    (query (if qpos
                               (parse-query
                                 (substring target (+ qpos 1)
                                            (string-length target)))
                               '()))
                    (headers (parse-header-lines (cdr lines))))
               (vector method path query version headers))))))

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

  (define (find-crlf bv start)
    (let ((n (bytevector-length bv)))
      (let loop ((i start))
        (cond
          ((fx>= (fx+ i 1) n) #f)
          ((and (fx= (bytevector-u8-ref bv i) 13)
                (fx= (bytevector-u8-ref bv (fx+ i 1)) 10))
           i)
          (else (loop (fx+ i 1)))))))

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

  (define (header-token-char? ch)
    (or (char<=? #\a ch #\z) (char<=? #\A ch #\Z)
        (char<=? #\0 ch #\9)
        (memv ch '(#\! #\# #\$ #\% #\& #\' #\* #\+ #\- #\. #\^
                   #\_ #\` #\| #\~))))

  (define (valid-header-name? name)
    (and (> (string-length name) 0)
         (let loop ((i 0))
           (or (= i (string-length name))
               (and (header-token-char? (string-ref name i))
                    (loop (+ i 1)))))))

  (define (valid-trailer-line? bv start end)
    (guard (e (#t #f))
      (let ((kv (parse-header-line (utf8->string (bv-sub bv start end)))))
        (and kv
             (valid-header-name? (symbol->string (car kv)))
             (not (memq (car kv) forbidden-trailer-fields))))))

  (define (bv-concat lst total)
    (let ((out (make-bytevector total)))
      (let loop ((l lst) (off 0))
        (if (null? l)
            out
            (let ((x (car l)))
              (bytevector-copy! x 0 out off (bytevector-length x))
              (loop (cdr l) (+ off (bytevector-length x))))))))

  ;; Try to parse a complete chunked body starting at `start`.
  ;; -> (values 'done body end-index) | (values 'more #f #f)
  ;;  | (values 'too-large #f #f) | (values 'bad #f #f)
  (define (parse-chunked-body bv start)
    (let loop ((pos start) (chunks '()) (len 0))
      (let ((eol (find-crlf bv pos)))
        (if (not eol)
            (if (> (- (bytevector-length bv) start) (+ body-limit 1024))
                (values 'too-large #f #f)
                (values 'more #f #f))
            (let ((size (parse-chunk-size bv pos eol)))
              (cond
                ((not size) (values 'bad #f #f))
                ((> (+ len size) body-limit) (values 'too-large #f #f))
                ((= size 0)
                 ;; Validate and cap optional trailers; a blank line ends
                 ;; the body. Trailer fields are currently ignored.
                 (let ((trailer-start (+ eol 2)))
                   (let scan ((p trailer-start))
                     (let ((e2 (find-crlf bv p)))
                       (cond
                         ((not e2)
                          (if (> (- (bytevector-length bv) trailer-start) trailer-limit)
                              (values 'trailers-too-large #f #f)
                              (values 'more #f #f)))
                         ((> (- (+ e2 2) trailer-start) trailer-limit)
                          (values 'trailers-too-large #f #f))
                         ((= e2 p)
                          (values 'done (bv-concat (reverse chunks) len) (+ p 2)))
                         ((valid-trailer-line? bv p e2) (scan (+ e2 2)))
                         (else (values 'bad #f #f)))))))
                (else
                 (let ((dstart (+ eol 2)))
                   (if (< (bytevector-length bv) (+ dstart size 2))
                       (values 'more #f #f)
                       (if (not (and (= (bytevector-u8-ref bv (+ dstart size)) 13)
                                     (= (bytevector-u8-ref bv (+ dstart size 1)) 10)))
                           (values 'bad #f #f)
                           (loop (+ dstart size 2)
                                 (cons (bv-sub bv dstart (+ dstart size)) chunks)
                                 (+ len size))))))))))))

  ;; ---- reader process ----------------------------------------------------------

  (define task-counter 0)
  (define (next-task-id!)
    (set! task-counter (+ task-counter 1))
    task-counter)

  (define (make-reader c srv)
    (lambda () (reader-loop c srv empty-bv)))

  (define (reader-loop c srv acc)
    (let ((hend (find-header-end acc)))
      (cond
        (hend (have-header c srv acc hend))
        ((> (bytevector-length acc) header-limit)
         (quick-response! c 431 "Header Too Large"))
        (else
         (receive (after read-timeout-ms
                     (if (> (bytevector-length acc) 0)
                         (quick-response! c 408 "Request Timeout")
                         (tcp-close! c)))   ; idle connection: just close
           (`#(tcp-data ,bv) (reader-loop c srv (bv-append acc bv)))
           (`#(tcp-eof) (tcp-close! c))
           (`#(tcp-error ,e) (tcp-close! c)))))))

  (define (have-header c srv acc hend)
    (let ((parsed (parse-head acc hend)))
      (if (not parsed)
          (quick-response! c 400 "Bad Request")
          (let* ((headers (vector-ref parsed 4))
                 (wskey (websocket-key headers))
                 (resolver (unbox (http-server-wsbox srv)))
                 (te (transfer-encoding headers))
                 (clen (content-length headers)))
            (cond
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
                    (run-ws-session c acc hend wskey req session))
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
               (collect-chunked c srv acc parsed (+ hend 4)))
              (else
               (let ((n (if (eq? clen 'absent) 0 clen)))
                 (if (> n body-limit)
                     (quick-response! c 413 "Payload Too Large")
                     (collect-body c srv acc parsed n (+ hend 4 n))))))))))

  ;; Dispatch the parsed request to the worker pool, then await the
  ;; response. Every request goes through the pool, so every handler gets
  ;; the same fault tolerance (crash retry, stuck-worker kill).
  (define (dispatch-request! c srv parsed body leftover)
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
      (await-response c srv leftover #f)))

  (define (collect-body c srv acc parsed clen total)
    (if (>= (bytevector-length acc) total)
        (dispatch-request! c srv parsed
          (bv-sub acc (- total clen) total)
          (bv-sub acc total (bytevector-length acc)))
        (receive (after read-timeout-ms (quick-response! c 408 "Request Timeout"))
          (`#(tcp-data ,bv) (collect-body c srv (bv-append acc bv) parsed clen total))
          (`#(tcp-eof) (tcp-close! c))
          (`#(tcp-error ,e) (tcp-close! c)))))

  (define (collect-chunked c srv acc parsed body-start)
    (let-values (((st body end) (parse-chunked-body acc body-start)))
      (case st
        ((done)
         (dispatch-request! c srv parsed body
           (bv-sub acc end (bytevector-length acc))))
        ((more)
         (receive (after read-timeout-ms (quick-response! c 408 "Request Timeout"))
           (`#(tcp-data ,bv) (collect-chunked c srv (bv-append acc bv) parsed body-start))
           (`#(tcp-eof) (tcp-close! c))
           (`#(tcp-error ,e) (tcp-close! c))))
        ((too-large) (quick-response! c 413 "Payload Too Large"))
        ((trailers-too-large) (quick-response! c 431 "Trailer Too Large"))
        (else (quick-response! c 400 "Bad Request")))))

  ;; Wait for the worker's response to complete. Data arriving meanwhile
  ;; (pipelining) is buffered; EOF is remembered so we stop after replying.
  (define (await-response c srv leftover eof?)
    (receive (after await-timeout-ms (tcp-close! c))
      (`#(next-request)
        (if eof? (tcp-close! c) (reader-loop c srv leftover)))
      (`#(conn-closed) 'done)
      (`#(streaming) (await-streaming c srv leftover))
      (`#(tcp-data ,bv)
        (let ((buf (bv-append leftover bv)))
          (if (> (bytevector-length buf) pipeline-limit)
              (tcp-close! c)                        ; peer over-pipelining
              (await-response c srv buf eof?))))
      (`#(tcp-eof) (await-response c srv leftover #t))
      (`#(tcp-error ,e) (await-response c srv leftover #t))))

  ;; A streamed (chunked/SSE) response is in progress: wait without a
  ;; deadline. On client disconnect the reader closes and exits; the
  ;; producer notices through res-write! returning #f.
  (define (await-streaming c srv leftover)
    (receive (after 'infinity #f)
      (`#(next-request) (reader-loop c srv leftover))
      (`#(conn-closed) 'done)
      (`#(tcp-data ,bv)
        (let ((buf (bv-append leftover bv)))
          (if (> (bytevector-length buf) pipeline-limit)
              (begin (tcp-close! c) 'done)
              (await-streaming c srv buf))))
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

  (define (run-ws-session c acc hend key req session)
    (tcp-write! c
      (string->utf8
        (string-append ws-handshake-prefix (ws-accept-key key) "\r\n\r\n"))
      #f)
    (let ((w (make-ws c (bv-sub acc (+ hend 4) (bytevector-length acc)))))
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
