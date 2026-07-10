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
  (export http-listen http-swap! http-set-ws! http-set-fast!
          http-stats http-shutdown!
          req-method req-path req-query req-headers req-header req-body
          req-keep-alive? req-params req-params-set!
          set-status! set-header! res-send!
          res-begin! res-write! res-end!
          res-conn res-status res-headers res-keep-alive?
          send-response! parse-query)
  (import (chezscheme) (igropyr actor) (igropyr uv) (igropyr otp)
          (igropyr websocket))

  (define header-limit 8192)
  (define body-limit 1048576)
  (define trailer-limit 8192)
  ;; Bytes a client may pipeline while the current handler is still
  ;; producing its response.  Without a cap a slow handler/stream lets a
  ;; peer grow the reader's bytevector without bound.
  (define pipeline-limit (+ header-limit body-limit))
  (define read-timeout-ms 30000)   ; slow/half requests reaped after this
  (define await-timeout-ms 60000)  ; reader waits this long for a response

  ;; ---- bytevector helpers ------------------------------------------------

  (define empty-bv (make-bytevector 0))

  (define (bv-append a b)
    (let* ((la (bytevector-length a))
           (lb (bytevector-length b))
           (r (make-bytevector (+ la lb))))
      (bytevector-copy! a 0 r 0 la)
      (bytevector-copy! b 0 r la lb)
      r))

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  ;; index of the \r\n\r\n terminating the header block, or #f
  (define (find-header-end bv)
    (let ((n (bytevector-length bv)))
      (let loop ((i 0))
        (cond
          ((> (+ i 3) (- n 1)) #f)
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
      (immutable keep-alive? req-keep-alive?)))

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
  (define (hex-value ch)
    (let ((c (char->integer ch)))
      (cond
        ((and (>= c 48) (<= c 57)) (- c 48))
        ((and (>= c 65) (<= c 70)) (- c 55))
        ((and (>= c 97) (<= c 102)) (- c 87))
        (else #f))))

  (define (percent-decode s plus-as-space?)
    (let ((n (string-length s)))
      (let-values (((p get) (open-bytevector-output-port)))
        (let loop ((i 0))
          (when (< i n)
            (let ((ch (string-ref s i)))
              (cond
                ((char=? ch #\%)
                 (if (< (+ i 2) n)
                     (let ((hi (hex-value (string-ref s (+ i 1))))
                           (lo (hex-value (string-ref s (+ i 2)))))
                       (if (and hi lo)
                           (begin (put-u8 p (+ (* hi 16) lo)) (loop (+ i 3)))
                           (assertion-violation 'percent-decode
                             "invalid percent escape" s)))
                     (assertion-violation 'percent-decode
                       "truncated percent escape" s)))
                ((and plus-as-space? (char=? ch #\+))
                 (put-u8 p 32) (loop (+ i 1)))
                (else
                 (put-bytevector p (string->utf8 (string ch)))
                 (loop (+ i 1)))))))
        (utf8->string (get)))))

  (define (parse-query s)
    (if (string=? s "")
        '()
        (map (lambda (kv)
               ;; Split only at the first '='; values such as signatures
               ;; and base64 tokens commonly contain further '=' bytes.
               (let ((eq (string-index kv #\=)))
                 (if eq
                     (cons (percent-decode (substring kv 0 eq) #t)
                           (percent-decode
                             (substring kv (+ eq 1) (string-length kv)) #t))
                     (cons (percent-decode kv #t) ""))))
             (string-split s #\&))))

  (define (strip-cr l)
    (let ((n (string-length l)))
      (if (and (> n 0) (char=? (string-ref l (- n 1)) #\return))
          (substring l 0 (- n 1))
          l)))

  (define (http-token? s)
    (and (string? s) (> (string-length s) 0)
         (let loop ((i 0))
           (if (= i (string-length s))
               #t
               (let ((c (char->integer (string-ref s i))))
                 (and (or (and (>= c 48) (<= c 57))
                          (and (>= c 65) (<= c 90))
                          (and (>= c 97) (<= c 122))
                          (memv c '(33 35 36 37 38 39 42 43 45 46
                                    94 95 96 124 126)))
                      (loop (+ i 1))))))))

  (define (trim-ows s)
    (let ((n (string-length s)))
      (let left ((a 0))
        (if (and (< a n) (memv (string-ref s a) '(#\space #\tab)))
            (left (+ a 1))
            (let right ((b n))
              (if (and (> b a) (memv (string-ref s (- b 1))
                                           '(#\space #\tab)))
                  (right (- b 1))
                  (substring s a b)))))))

  ;; "Content-Length: 42" -> (content-length . "42"), or #f.
  ;; Malformed field names and values are rejected instead of silently
  ;; disappearing from the request.
  (define (parse-header-line l)
    (let ((colon (string-index l #\:)))
      (and colon
           (let* ((name (substring l 0 colon))
                  (v (trim-ows (substring l (+ colon 1) (string-length l)))))
             (and (http-token? name)
                  (not (string-index v #\return))
                  (not (string-index v (integer->char 0)))
                  (cons (string->symbol (string-downcase name)) v))))))

  ;; Repeated header fields are coalesced into one comma-joined value
  ;; (RFC 7230); this lets content-length see "5,6" and reject the
  ;; conflict, and keeps request accessors single-valued.
  (define (parse-header-lines lines)
    (let loop ((ls lines) (acc '()))
      (cond
        ((null? ls) acc)
        ((string=? (car ls) "") (loop (cdr ls) acc))
        (else
         (let ((kv (parse-header-line (car ls))))
           (and kv
                (let ((prev (assq (car kv) acc)))
                  (if prev
                      (begin
                        (set-cdr! prev (string-append (cdr prev) "," (cdr kv)))
                        (loop (cdr ls) acc))
                      (loop (cdr ls) (cons kv acc))))))))))

  ;; Parse request line + headers from the header block.
  ;; Returns #(method path query version headers) or #f on malformed input.
  (define (parse-head bv hend)
    (guard (e (#t #f))
      (let* ((text (utf8->string (bv-sub bv 0 hend)))
             (lines (map strip-cr (string-split text #\newline)))
             (rl (string-split (car lines) #\space)))
        (and (= (length rl) 3)
             (http-token? (car rl))
             (let* ((method (string->symbol (car rl)))
                    (target (cadr rl))
                    (version (caddr rl))
                    (qpos (string-index target #\?))
                    (path (percent-decode
                            (if qpos (substring target 0 qpos) target) #f))
                    (query (if qpos
                               (parse-query
                                 (substring target (+ qpos 1)
                                            (string-length target)))
                               '()))
                    (headers (parse-header-lines (cdr lines))))
               (and headers
                    (or (string=? version "HTTP/1.1")
                        (string=? version "HTTP/1.0"))
                    (vector method path query version headers)))))))

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
                            (reverse (cons (trim-ows (substring s start i)) acc)))
                           ((char=? (string-ref s i) #\,)
                            (split s (cons (trim-ows (substring s start i)) acc)
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

  ;; Only chunked request transfer coding is implemented.  Any other
  ;; value must be rejected; treating it as a bodyless request would
  ;; desynchronise the keep-alive stream.
  (define (transfer-encoding headers)
    (let ((p (assq 'transfer-encoding headers)))
      (cond
        ((not p) 'absent)
        ((string-ci=? (trim-ows (cdr p)) "chunked") 'chunked)
        (else 'bad))))

  (define (comma-header-has-token? value wanted)
    (exists (lambda (part) (string-ci=? (trim-ows part) wanted))
            (string-split value #\,)))

  ;; websocket upgrade request? returns the Sec-WebSocket-Key or #f
  (define (websocket-key headers)
    (let ((u (assq 'upgrade headers))
          (cn (assq 'connection headers))
          (k (assq 'sec-websocket-key headers))
          (v (assq 'sec-websocket-version headers)))
      (and u cn k v
           (string-ci=? (trim-ows (cdr u)) "websocket")
           (comma-header-has-token? (cdr cn) "upgrade")
           (string=? (trim-ows (cdr v)) "13")
           (not (string=? (trim-ows (cdr k)) ""))
           (trim-ows (cdr k)))))

  (define (keep-alive? version headers)
    (let ((p (assq 'connection headers)))
      (if (string=? version "HTTP/1.1")
          (not (and p (comma-header-has-token? (cdr p) "close")))
          (and p (comma-header-has-token? (cdr p) "keep-alive")))))

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

  ;; Per-request response token: a one-shot claim shared by every path
  ;; that might answer a single request (the handler, the streaming
  ;; helpers, and the supervisor's fallback 500). Claiming is atomic, so
  ;; a stale write from a previous keep-alive request can never bleed
  ;; into the next one, and a fallback can never double-write.
  (define (make-token) (box #f))
  (define (claim! token) (and (not (unbox token)) (set-box! token #t) #t))

  ;; Framing headers are always emitted by the framework; drop any the
  ;; user set so they cannot be duplicated or conflict.
  (define framing-headers '("content-length" "connection" "transfer-encoding"))
  (define (framing-header? name)
    (member (string-downcase name) framing-headers))

  ;; Reject malformed names and values carrying control delimiters
  ;; (response splitting).  NUL is rejected as well because downstream
  ;; proxies often treat it inconsistently.
  (define (header-value-safe? s)
    (and (string? s)
         (not (or (string-index s #\return)
                  (string-index s #\newline)
                  (string-index s (integer->char 0))))))

  (define (render-headers headers)
    (apply string-append
      (map (lambda (h)
             (let ((k (car h)) (v (cdr h)))
               (if (and (http-token? k) (header-value-safe? v)
                        (not (framing-header? k)))
                   (string-append k ": " v "\r\n")
                   "")))                 ; silently drop unsafe/framing
           headers)))

  ;; Write a full response, guarded by the request's token. The libuv
  ;; write callback (no yielding) tells the reader to continue
  ;; (keep-alive) or closes the connection.
  (define (send-response! c token status headers body ka)
    (when (claim! token)
      (let* ((head
              (string-append
                "HTTP/1.1 " (number->string status) " " (status-text status)
                "\r\n"
                (render-headers headers)
                "Content-Length: " (number->string (bytevector-length body))
                "\r\nConnection: " (if ka "keep-alive" "close")
                "\r\n\r\n"))
             (full (bv-append (string->utf8 head) body))
             (owner (conn-owner c)))
        (tcp-write! c full
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
      (mutable status res-status res-status-set!)
      (mutable headers res-headers res-headers-set!)
      (immutable keep-alive? res-keep-alive?)
      ;; plain | streaming | done
      (mutable mode res-mode res-mode-set!)))

  (define (set-status! r s) (res-status-set! r s))

  ;; Silently ignore header names/values containing CR or LF; they are
  ;; also rejected again at render time.
  (define (set-header! r k v)
    (when (and (http-token? k) (header-value-safe? v))
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
  (define (res-begin! r)
    (let ((c (res-conn r)))
      (when (claim! (res-token r))
        (res-mode-set! r 'streaming)
        (tcp-write! c
          (string->utf8
            (string-append
              "HTTP/1.1 " (number->string (res-status r)) " "
              (status-text (res-status r)) "\r\n"
              (render-headers (res-headers r))
              "Transfer-Encoding: chunked\r\nConnection: "
              (if (res-keep-alive? r) "keep-alive" "close")
              "\r\n\r\n"))
          #f)
        (send (conn-owner c) (vector 'streaming)))))

  ;; Write one chunk (string or bytevector). #f when the stream is not
  ;; open any more (e.g. the client disconnected) -- stop the loop then.
  (define (res-write! r data)
    (let ((bv (if (string? data) (string->utf8 data) data))
          (c (res-conn r)))
      (and (eq? (res-mode r) 'streaming)
           (eq? (conn-state c) 'open)
           (> (bytevector-length bv) 0)
           (tcp-write! c
             (bv-append
               (string->utf8
                 (string-append (number->string (bytevector-length bv) 16) "\r\n"))
               (bv-append bv (string->utf8 "\r\n")))
             #f))))

  ;; Finish the stream: terminating chunk, then the usual keep-alive /
  ;; close continuation.
  (define (res-end! r)
    (when (eq? (res-mode r) 'streaming)
      (res-mode-set! r 'done)
      (let* ((c (res-conn r))
             (owner (conn-owner c))
             (ka (res-keep-alive? r)))
        (tcp-write! c (string->utf8 "0\r\n\r\n")
          (lambda (st)
            (if (and ka (>= st 0))
                (send owner (vector 'next-request))
                (begin
                  (tcp-close! c)
                  (send owner (vector 'conn-closed)))))))))

  ;; ---- task execution (inside a pool worker) -----------------------------------

  ;; A crash here kills the worker (Let It Crash): the supervisor retries
  ;; the task up to 3 times, then answers 500 via fail-task below.
  ;; Task shape: #(task id conn req token)
  (define (run-task handler task)
    (let* ((c (vector-ref task 2))
           (req (vector-ref task 3))
           (token (vector-ref task 4))
           (r (make-res c token 200 '() (req-keep-alive? req) 'plain)))
      (handler req r)
      ;; handler finished without responding: don't leave the client hanging
      (unless (unbox token)
        (set-status! r 404)
        (set-header! r "Content-Type" "text/plain; charset=utf-8")
        (res-send! r (string->utf8 "Not Found")))))

  ;; supervisor gave up on the task (crash retries exhausted, or stuck
  ;; worker killed): last-resort 500 unless the request's token was
  ;; already claimed (partial or complete response already went out)
  (define (fail-task task)
    (let ((c (vector-ref task 2))
          (token (vector-ref task 4)))
      (quick-response! c 500 "Internal Server Error" token)))

  ;; ---- chunked transfer-encoding (request side) ----------------------------------

  (define (find-crlf bv start)
    (let ((n (bytevector-length bv)))
      (let loop ((i start))
        (cond
          ((>= (+ i 1) n) #f)
          ((and (fx= (bytevector-u8-ref bv i) 13)
                (fx= (bytevector-u8-ref bv (+ i 1)) 10))
           i)
          (else (loop (+ i 1)))))))

  ;; hex chunk size, stopping at ';' (chunk extensions); #f if malformed
  (define (parse-chunk-size bv start end)
    (let loop ((i start) (v 0) (any #f))
      (if (= i end)
          (and any v)
          (let ((b (bytevector-u8-ref bv i)))
            (cond
              ((= b 59) (and any v))                                 ; ';'
              ((and (>= b 48) (<= b 57)) (loop (+ i 1) (+ (* v 16) (- b 48)) #t))
              ((and (>= b 97) (<= b 102)) (loop (+ i 1) (+ (* v 16) (- b 87)) #t))
              ((and (>= b 65) (<= b 70)) (loop (+ i 1) (+ (* v 16) (- b 55)) #t))
              (else #f))))))

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
            (if (> (- (bytevector-length bv) pos) 1024)
                (values 'bad #f #f)
                (values 'more #f #f))
            (let ((size (parse-chunk-size bv pos eol)))
              (cond
                ((not size) (values 'bad #f #f))
                ((> (+ len size) body-limit) (values 'too-large #f #f))
                ((= size 0)
                 ;; skip optional trailers; a blank line ends the body
                 (let ((trailer-start (+ eol 2)))
                   (let scan ((p trailer-start))
                   (let ((e2 (find-crlf bv p)))
                     (cond
                       ;; A complete blank line wins even when pipelined
                       ;; bytes follow it; those bytes are not trailers.
                       ((and e2 (= e2 p))
                        (values 'done (bv-concat (reverse chunks) len) (+ p 2)))
                       ((and e2 (> (- e2 trailer-start) trailer-limit))
                        (values 'trailers-too-large #f #f))
                       ((not e2)
                        (if (> (- (bytevector-length bv) trailer-start)
                               trailer-limit)
                            (values 'trailers-too-large #f #f)
                            (values 'more #f #f)))
                       ;; Trailer fields use the same basic syntax as
                       ;; normal headers.  Decode/check one line at a time.
                       ((guard (e (#t #t))
                          (not (parse-header-line
                                 (utf8->string (bv-sub bv p e2)))))
                        (values 'bad #f #f))
                       (else (scan (+ e2 2))))))))
                (else
                 (let ((dstart (+ eol 2)))
                   (if (< (bytevector-length bv) (+ dstart size 2))
                       (values 'more #f #f)
                       (let ((tail (+ dstart size)))
                         (if (not (and (= (bytevector-u8-ref bv tail) 13)
                                       (= (bytevector-u8-ref bv (+ tail 1)) 10)))
                             (values 'bad #f #f)
                             (loop (+ tail 2)
                                   (cons (bv-sub bv dstart tail) chunks)
                                   (+ len size)))))))))))))

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
        ;; Check the located header too: libuv may deliver a complete
        ;; oversized header in one read, in which case checking only the
        ;; no-terminator branch lets it bypass header-limit.
        ((and hend (> (+ hend 4) header-limit))
         (quick-response! c 431 "Header Too Large"))
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
              ;; framing errors -> 400, close (bad/negative/conflicting
              ;; Content-Length, or both Content-Length and chunked)
              ((eq? clen 'bad)
               (quick-response! c 400 "Bad Request"))
              ((eq? te 'bad)
               (quick-response! c 400 "Bad Request"))
              ((and (eq? te 'chunked) (not (eq? clen 'absent)))
               (quick-response! c 400 "Bad Request"))
              ;; websocket upgrade: only after normal HTTP framing has
              ;; been validated, otherwise a malformed request body can
              ;; be mistaken for the first WebSocket frame.
              ((and wskey resolver
                    (eq? (vector-ref parsed 0) 'GET)
                    (string=? (vector-ref parsed 3) "HTTP/1.1"))
               (let* ((req (make-request (vector-ref parsed 0)
                                         (vector-ref parsed 1)
                                         (vector-ref parsed 2)
                                         '() headers empty-bv #f))
                      (session (resolver req)))
                 (if session
                     (run-ws-session c acc hend wskey req session)
                     (quick-response! c 404 "Not Found"))))
              ((eq? te 'chunked)
               (collect-chunked c srv acc parsed (+ hend 4)))
              (else
               (let ((n (if (eq? clen 'absent) 0 clen)))
                 (if (> n body-limit)
                     (quick-response! c 413 "Payload Too Large")
                     (collect-body c srv acc parsed n (+ hend 4 n))))))))))

  ;; Dispatch the parsed request. A "fast" route (the app-supplied
  ;; predicate returns true) is run inline in the reader process,
  ;; skipping the worker-pool round trip (submit-task -> worker ->
  ;; task-completed -> DOWN, ~4 messages + a context switch per
  ;; request). The trade-off: a fast handler loses the pool's crash
  ;; retry and stuck-kill; a crash is caught here and answered 500 (only
  ;; this connection is affected), and a fast handler that blocks or
  ;; loops freezes only its own connection. Mark a route fast only when
  ;; its handler is pure and returns promptly. Everything else goes
  ;; through the pool.
  (define (dispatch-request! c srv parsed body leftover)
    (let* ((headers (vector-ref parsed 4))
           (req (make-request (vector-ref parsed 0)
                              (vector-ref parsed 1)
                              (vector-ref parsed 2)
                              '()
                              headers
                              body
                              (keep-alive? (vector-ref parsed 3) headers)))
           (id (next-task-id!))
           (token (make-token))
           (fast? (unbox (http-server-fbox srv))))
      (if (and fast? (fast? req))
          ;; inline fast path: run the handler here, catch crashes
          (let ((task (vector 'task id c req token)))
            (guard (e (#t (quick-response! c 500 "Internal Server Error" token)))
              (run-task (unbox (http-server-hbox srv)) task))
            (await-response c srv leftover #f))
          (begin
            (send (http-server-sup srv)
              (vector 'submit-task (vector 'task id c req token)))
            (await-response c srv leftover #f)))))

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
        ((trailers-too-large) (quick-response! c 431 "Trailers Too Large"))
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
        (let ((next (bv-append leftover bv)))
          (if (> (bytevector-length next) pipeline-limit)
              (tcp-close! c)
              (await-response c srv next eof?))))
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
        (let ((next (bv-append leftover bv)))
          (if (> (bytevector-length next) pipeline-limit)
              (begin (tcp-close! c) 'done)
              (await-streaming c srv next))))
      (`#(tcp-eof) (tcp-close! c) 'done)
      (`#(tcp-error ,e) (tcp-close! c) 'done)))

  ;; ---- websocket session ---------------------------------------------------------

  ;; 101 handshake, then hand the connection to the session procedure,
  ;; still inside this reader process (one process per ws connection).
  ;; A crashing session just closes its own connection.
  (define (run-ws-session c acc hend key req session)
    (tcp-write! c
      (string->utf8
        (string-append
          "HTTP/1.1 101 Switching Protocols\r\n"
          "Upgrade: websocket\r\nConnection: Upgrade\r\n"
          "Sec-WebSocket-Accept: " (ws-accept-key key)
          "\r\n\r\n"))
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
  ;; fbox holds the fast-route predicate: (lambda (req) bool), or #f.
  (define-record-type (http-server make-http-server http-server?)
    (fields
      (immutable sup http-server-sup)
      (immutable hbox http-server-hbox)
      (immutable wsbox http-server-wsbox)
      (immutable fbox http-server-fbox)
      (immutable started http-server-started)))

  (define (http-swap! srv handler)
    (set-box! (http-server-hbox srv) handler))

  (define (http-set-ws! srv resolver)
    (set-box! (http-server-wsbox srv) resolver))

  ;; Install the fast-route predicate. When it returns true for a
  ;; request, that request runs inline in the reader (bypassing the
  ;; worker pool). See dispatch-request! for the trade-offs.
  (define (http-set-fast! srv pred)
    (set-box! (http-server-fbox srv) pred))

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
    (tcp-stop-listen!)
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
  ;;     '((workers . 16)        ; pool size            (default 8)
  ;;       (max-retries . 3)     ; crash retries        (default 3)
  ;;       (stuck-ms . 30000)    ; stuck-kill threshold (default 30000)
  ;;       (check-ms . 5000)     ; ticker interval      (default 5000)
  ;;       (reuseport . #t)))    ; SO_REUSEPORT bind: run N OS processes
  ;;                             ; on the same port, kernel-balanced
  ;;                             ; (Linux/FreeBSD; not macOS)
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
           (fbox (box #f))
           (sup (start-worker-pool (opt 'workers 8)
                  (lambda (task) (run-task (unbox hbox) task))
                  fail-task
                  (opt 'max-retries 3)
                  (opt 'stuck-ms 30000)
                  (opt 'check-ms 5000)))
           (srv (make-http-server sup hbox wsbox fbox (now-ms))))
      (tcp-listen! "0.0.0.0" port 511
        (lambda (c)
          ;; libuv callback context: spawn + register only, no yielding
          (let ((pid (spawn (make-reader c srv))))
            (conn-set-owner! c pid)
            (tcp-read-start! c)))
        (if (opt 'reuseport #f) 2 0))   ; UV_TCP_REUSEPORT
      (display (string-append "igropyr listening on http://0.0.0.0:"
                              (number->string port) "\n"))
      srv))
)
