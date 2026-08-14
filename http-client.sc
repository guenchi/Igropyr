#!chezscheme
;;; (igropyr http-client) -- non-blocking outbound HTTP/1.1 client.
;;;
;;; Same actor model as the database clients: each request runs in its
;;; own green process that connects, sends, and reads the reply, while
;;; the caller parks in receive -- the OS thread keeps serving other work.
;;;
;;; CONNECTIONS ARE REUSED. After a response that leaves the connection
;;; framed and drained, it is kept and handed to the next request for the
;;; same host/port/scheme -- saving a TCP handshake, and over TLS a full
;;; handshake, which for a small request is most of the cost. Pass
;;; (reuse . #f) to opt one request out; http-client-pool! sizes the pool,
;;; http-client-close-idle! empties it, http-client-pool-stats reports it.
;;;
;;; A pooled connection lives in its own process, which owns its socket. It
;;; has to: #(tcp-data bv) carries no connection identity, so one process
;;; owns exactly one socket. That process is also what makes idle pooling
;;; safe -- servers close keep-alive connections whenever they like, and a
;;; process sitting in receive SEES that eof and takes itself out of the
;;; pool instead of leaving a corpse for the next request to find.
;;;
;;;   (http-get "http://127.0.0.1:8080/json")
;;;     ;; -> a response; response-status / -headers / -body / -header
;;;   (http-post "http://host/api" "{\"x\":1}"
;;;              '((headers . (("Content-Type" . "application/json")))))
;;;   (http-request 'PUT url '((body . ,bv) (timeout . 5000)))
;;;
;;; Body arrives as a bytevector (utf8->string it if text). A transport
;;; failure or timeout raises #(http-client-error ,message).
;;;
;;; Streaming responses: pass (on-chunk . proc) and the body is
;;; delivered INCREMENTALLY instead of accumulated -- proc receives one
;;; bytevector per decoded chunk (chunked transfer), per arriving
;;; segment (counted or read-until-close bodies). The final response's
;;; body is empty; status/headers are real. The buffer is consumed as
;;; chunks are emitted, so an hours-long stream holds only the current
;;; unparsed tail in memory. Timeout semantics change with on-chunk:
;;; it bounds the IDLE GAP between chunks (0 = no idle timeout), and
;;; there is no total-request deadline -- a healthy slow stream runs
;;; forever. proc runs in the connection's green process (actor ops are
;;; fine there); if it raises, the socket is closed and the caller gets
;;; #(http-client-error "on-chunk handler raised").
;;;
;;;   (http-request 'POST url
;;;     `((body . ,payload)
;;;       (on-chunk . ,(lambda (bv) (publish 'tts-audio bv)))
;;;       (timeout . 15000)))   ; kill the stream after a 15s silence
;;;
;;; https:// works when the OPTIONAL (igropyr tls) library has been
;;; enabled -- (import (igropyr tls)) then (tls-enable!) once at startup.
;;; This library itself stays dependency-free: TLS plugs in through
;;; set-https-connector! as a pure byte codec (encrypt out, decrypt in),
;;; so the socket, timeout, and parsing paths here are identical for
;;; both schemes. Without it, https:// fails with a clear message.

(library (igropyr http-client)
  (export http-request http-get http-post
          response? response-status response-headers response-body
          response-header
          http-client-pool! http-client-pool-stats http-client-close-idle!
          set-https-connector!     ; internal: registered by (igropyr tls)
          ;; Re-exported app-facing (igropyr actor) surface: this library
          ;; can be the sole entry point of a client-only program (a
          ;; crawler, an API caller), which still needs the scheduler and
          ;; process primitives. Same original bindings as those
          ;; re-exported by (igropyr http) -- importing both never
          ;; conflicts.
          start-scheduler spawn send receive self
          sleep-ms kill register whereis process-id)
  (import (chezscheme) (igropyr buffer) (igropyr actor) (igropyr libuv))

  (define default-timeout-ms 30000)
  (define default-port 80)
  (define default-tls-port 443)
  (define max-response 33554432)      ; default response cap, 32 MiB (DoS
                                      ; guard); per-request override via
                                      ; the (max-response . bytes) opt

  ;; max-response bounds the BODY, and it was doing double duty as the only
  ;; bound on metadata as well -- so a hostile upstream could send a header
  ;; block, a Content-Length or a chunk-size line approaching 32 MiB, and
  ;; this client would copy it out, split it into strings, intern symbols
  ;; and hand the result to string->number. Runtime primitives over
  ;; megabyte-long numerals are neither cheap nor preemptible, and there is
  ;; one scheduler thread. The coupling also ran the wrong way: raising
  ;; max-response for a legitimately large download raised the metadata
  ;; ceiling with it.
  ;;
  ;; These match the server's own limits (header-limit, chunk-line-limit).
  ;; That is the right reference point -- what the server refuses to
  ;; receive is what a client has no reason to accept.
  (define max-response-head 8192)     ; whole status line + header block
  (define chunk-line-limit 4096)      ; one chunk-size line, extensions included

  ;; ---- TLS hook ---------------------------------------------------------
  ;;
  ;; (igropyr tls) registers a connector: (lambda (conn host timeout) codec)
  ;; called inside the connection process right after tcp-read-start!, so
  ;; it can drive the handshake with receive on the socket's messages.
  ;; codec = #(encrypt decrypt close):
  ;;   encrypt: plaintext bv -> ciphertext bv to write
  ;;   decrypt: ciphertext bv -> plaintext bv (may be empty: pure TLS records)
  ;;   close:   () -> free the session (no I/O)
  ;; On failure the connector raises #(http-client-error ,message).
  (define https-connector #f)
  (define (set-https-connector! f) (set! https-connector f))

  ;; ---- bytevector helpers ---------------------------------------------

  (define empty-bv (make-bytevector 0))

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  (define (bv-concat lst total)
    (let ((out (make-bytevector total)))
      (let loop ((l lst) (off 0))
        (if (null? l)
            out
            (let ((x (car l)))
              (bytevector-copy! x 0 out off (bytevector-length x))
              (loop (cdr l) (+ off (bytevector-length x))))))))

  (define (find-crlf bv start)
    (let ((n (bytevector-length bv)))
      (let loop ((i start))
        (cond
          ((>= (+ i 1) n) #f)
          ((and (fx= (bytevector-u8-ref bv i) 13)
                (fx= (bytevector-u8-ref bv (+ i 1)) 10))
           i)
          (else (loop (+ i 1)))))))

  (define (fail msg) (raise (vector 'http-client-error msg)))

  ;; ---- URL parsing ----------------------------------------------------

  (define (string-index s ch from)
    (let ((n (string-length s)))
      (let loop ((i from))
        (cond ((= i n) #f)
              ((char=? (string-ref s i) ch) i)
              (else (loop (+ i 1)))))))

  ;; "http[s]://host[:port][/path]" -> (values host port path-with-query tls?)
  (define (parse-url url)
    (let-values (((rest tls?)
                  (cond
                    ((and (>= (string-length url) 7)
                          (string-ci=? (substring url 0 7) "http://"))
                     (values (substring url 7 (string-length url)) #f))
                    ((and (>= (string-length url) 8)
                          (string-ci=? (substring url 0 8) "https://"))
                     (values (substring url 8 (string-length url)) #t))
                    (else (fail "url must start with http:// or https://")))))
      (let* ((slash (string-index rest #\/ 0))
             (authority (if slash (substring rest 0 slash) rest))
             (path (if slash (substring rest slash (string-length rest)) "/"))
             (colon (string-index authority #\: 0))
             (dport (if tls? default-tls-port default-port)))
        (if colon
            (values (substring authority 0 colon)
                    (or (string->number (substring authority (+ colon 1)
                                                   (string-length authority)))
                        dport)
                    path tls?)
            (values authority dport path tls?)))))

  ;; ---- request encoding ------------------------------------------------

  (define crlf (string->utf8 "\r\n"))

  ;; Reject CR/LF (and other control characters) anywhere they would end
  ;; a line early: a value carrying "\r\n" would inject extra headers or
  ;; a whole second request into the outbound stream (request splitting),
  ;; which is how an attacker-influenced object key, content-type or
  ;; token turns into a forged upstream request. The server side has the
  ;; same guard for responses (http.sc header-safe?); this is its
  ;; request-side counterpart, and it FAILS the call rather than silently
  ;; dropping the header, because a caller that asked to send an
  ;; authorization or content-type header must not have it vanish.
  (define (request-safe? s)
    (let ((n (string-length s)))
      (let loop ((i 0))
        (or (= i n)
            (let ((c (string-ref s i)))
              (and (char>? c #\space) (char<? c #\delete) (loop (+ i 1))))))))

  (define (check-request-part! what s)
    (unless (and (string? s) (request-safe? s))
      (raise (vector 'http-client-error
               (string-append "invalid " what
                              ": control characters are not allowed")))))

  (define (managed-request-header? name)
    (exists (lambda (reserved) (string-ci=? name reserved))
            '("Host" "Connection" "Content-Length" "Transfer-Encoding")))

  ;; host-header is host[:port] -- RFC 7230 wants the port whenever it
  ;; is not the scheme default (the caller computes it from parse-url)
  (define (build-request method host-header path headers body keep-alive?)
    (let ((body-bv (cond ((not body) empty-bv)
                         ((string? body) (string->utf8 body))
                         (else body))))
      ;; the request line and every header must be single-line
      (check-request-part! "request path" path)
      (check-request-part! "Host header" host-header)
      (for-each
        (lambda (h)
          (check-request-part! "header name" (car h))
          (when (managed-request-header? (car h))
            (raise (vector 'http-client-error
                     (string-append "header is managed by the client: " (car h)))))
          ;; A header VALUE may hold spaces, tabs (legal OWS) and
          ;; non-ASCII text (an S3 metadata value, a filename in
          ;; Content-Disposition): only the bytes that could terminate
          ;; the line or the message are refused, exactly like the
          ;; server's header-safe?. Over-restricting here would break
          ;; legitimate callers without adding any protection.
          (unless (and (string? (cdr h))
                       (let ((v (cdr h)))
                         (let loop ((i 0))
                           (or (= i (string-length v))
                               (let ((c (string-ref v i)))
                                 (and (not (char=? c #\return))
                                      (not (char=? c #\newline))
                                      (not (char=? c #\nul))
                                      (loop (+ i 1))))))))
            (raise (vector 'http-client-error
                     (string-append "invalid value for header " (car h)
                                    ": control characters are not allowed")))))
        headers)
      (let-values (((p get) (open-bytevector-output-port)))
        (define (line s) (put-bytevector p (string->utf8 s)) (put-bytevector p crlf))
        (line (string-append (symbol->string method) " " path " HTTP/1.1"))
        (line (string-append "Host: " host-header))
        ;; Announcing keep-alive is what makes reuse possible at all; the
        ;; response still decides (see reusable-response?). "close" is sent
        ;; when the caller opted out, so a server is never left holding a
        ;; connection this client will not use.
        (line (if keep-alive? "Connection: keep-alive" "Connection: close"))
        (for-each
          (lambda (h) (line (string-append (car h) ": " (cdr h))))
          headers)
        ;; Framing is derived exclusively from the bytes this function
        ;; serializes; callers cannot create duplicate/conflicting lengths.
        (cond
          ((> (bytevector-length body-bv) 0)
           (line (string-append "Content-Length: "
                                (number->string (bytevector-length body-bv)))))
          ((memq method '(PUT POST PATCH))
           (line "Content-Length: 0")))
        (put-bytevector p crlf)                    ; end of headers
        (put-bytevector p body-bv)
        (get))))

  ;; ---- response record + parsing --------------------------------------

  (define-record-type (response make-response response?)
    (fields
      (immutable status response-status)     ; integer
      (immutable headers response-headers)   ; alist, lowercase symbol keys
      (immutable body response-body)))        ; bytevector

  (define (response-header r name)
    (let ((p (assq name (response-headers r))))
      (and p (cdr p))))

  (define (parse-status-line bv end)
    ;; "HTTP/1.1 200 OK"
    (let* ((s (utf8->string (bv-sub bv 0 end)))
           (sp1 (string-index s #\space 0)))
      (and sp1
           (let ((sp2 (string-index s #\space (+ sp1 1))))
             (string->number
               (if sp2 (substring s (+ sp1 1) sp2)
                   (substring s (+ sp1 1) (string-length s))))))))

  ;; the version token of a status line: "HTTP/1.1 200 OK" -> "HTTP/1.1"
  (define (parse-http-version bv end)
    (let* ((s (utf8->string (bv-sub bv 0 end)))
           (sp (string-index s #\space 0)))
      (if sp (substring s 0 sp) "HTTP/1.1")))

  (define (parse-headers bv start end)
    ;; header lines between start and end (the \r\n\r\n index)
    (let loop ((pos start) (acc '()))
      (let ((eol (find-crlf bv pos)))
        (if (or (not eol) (>= pos end))
            (reverse acc)
            (let ((line (utf8->string (bv-sub bv pos eol))))
              (let ((colon (string-index line #\: 0)))
                (if colon
                    (let ((k (string->symbol
                               (string-downcase (substring line 0 colon))))
                          (v (let trim ((j (+ colon 1)))
                               (if (and (< j (string-length line))
                                        (char=? (string-ref line j) #\space))
                                   (trim (+ j 1))
                                   (substring line j (string-length line))))))
                      (loop (+ eol 2) (cons (cons k v) acc)))
                    (loop (+ eol 2) acc))))))))

  (define (header-values headers name)
    (let loop ((hs headers) (acc '()))
      (cond ((null? hs) (reverse acc))
            ((eq? (caar hs) name)
             (loop (cdr hs) (cons (cdar hs) acc)))
            (else (loop (cdr hs) acc)))))

  (define (trim-ows s)
    (let ((n (string-length s)))
      (let left ((start 0))
        (if (and (< start n) (memv (string-ref s start) '(#\space #\tab)))
            (left (+ start 1))
            (let right ((end n))
              (if (and (> end start)
                       (memv (string-ref s (- end 1)) '(#\space #\tab)))
                  (right (- end 1))
                  (substring s start end)))))))

  ;; Expand repeated fields and comma lists into one ordered value list.
  ;; Empty elements are retained so framing parsers can reject them.
  (define (comma-header-values headers name)
    (let split-fields ((fields (header-values headers name)) (acc '()))
      (if (null? fields)
          (reverse acc)
          (let* ((s (car fields)) (n (string-length s)))
            (let split-one ((start 0) (i 0) (acc acc))
              (cond
                ((= i n)
                 (split-fields (cdr fields)
                   (cons (trim-ows (substring s start i)) acc)))
                ((char=? (string-ref s i) #\,)
                 (split-one (+ i 1) (+ i 1)
                   (cons (trim-ows (substring s start i)) acc)))
                (else (split-one start (+ i 1) acc))))))))

  (define (decimal-integer s)
    (and (> (string-length s) 0)
         (let loop ((i 0))
           (cond ((= i (string-length s)) (string->number s))
                 ((char<=? #\0 (string-ref s i) #\9) (loop (+ i 1)))
                 (else #f)))))

  ;; -> #f (absent) | nonnegative integer | 'bad. Repeated/comma-separated
  ;; Content-Length values are legal only when every decimal value agrees.
  (define (response-content-length headers)
    (let ((values (comma-header-values headers 'content-length)))
      (if (null? values)
          #f
          (let ((first (decimal-integer (car values))))
            (if (and first (for-all (lambda (s)
                                      (let ((n (decimal-integer s)))
                                        (and n (= n first))))
                                    (cdr values)))
                first
                'bad)))))

  ;; The decoder implements only a single, final chunked transfer coding.
  ;; Any duplicate or unsupported coding must fail instead of falling back
  ;; to close-delimited input and disagreeing with another HTTP hop.
  (define (response-transfer-encoding headers)
    (let ((values (comma-header-values headers 'transfer-encoding)))
      (cond ((null? values) #f)
            ((and (null? (cdr values))
                  (string-ci=? (car values) "chunked"))
             'chunked)
            (else 'bad))))

  ;; Parse the chunk-size line at offset pos (relative to the buffer
  ;; start): scan for CRLF, strip any ";ext", read the hex size. The
  ;; ONE copy of the chunked-transfer grammar -- both the accumulating
  ;; and the streaming decoder below drive it. Anything but an unsigned
  ;; exact integer is 'bad: a negative size from a broken server would
  ;; otherwise misframe the stream (and a size of -4 makes the consumed
  ;; length exactly zero -- a busy spin).
  ;; -> (size . eol) | #f (need more bytes) | 'bad
  (define (chunk-size-at buf pos)
    (let ((bv (inbuf-bv buf)) (base (inbuf-start buf)) (n (inbuf-length buf)))
      (let scan ((i pos))
        (cond
          ;; Bound the LINE, not just the body. Without this the scan runs
          ;; to whatever the peer sends, and the text between pos and the
          ;; CRLF -- up to max-response -- is copied out, substring'd and
          ;; handed to string->number in base 16. A megabyte-long numeral is
          ;; neither cheap nor preemptible, and there is one scheduler
          ;; thread. Checked before the more-bytes test so an oversized line
          ;; is refused as it grows, not once it happens to complete.
          ((fx> (fx- i pos) chunk-line-limit) 'bad)
          ((fx>= (fx+ i 1) n) #f)
          ((and (fx= (bytevector-u8-ref bv (fx+ base i)) 13)
                (fx= (bytevector-u8-ref bv (fx+ base (fx+ i 1))) 10))
           (let ((size (string->number
                         (let ((line (utf8->string (inbuf-sub buf pos i))))
                           (let ((semi (string-index line #\; 0)))
                             (if semi (substring line 0 semi) line)))
                         16)))
             (if (and (integer? size) (exact? size) (>= size 0))
                 (cons size i)
                 'bad)))
          (else (scan (fx+ i 1)))))))

  ;; Resume chunked decoding over the inbuf; pos/chunks/got RELATIVE to
  ;; the buffer start. Chunks already extracted are never re-parsed and
  ;; never re-copied -- the old decode-chunked re-read every chunk into
  ;; a fresh output port on every tcp segment, GB-level rescans against
  ;; the 32MB response cap in the worst case.
  ;; -> #(done body) | #(more pos chunks got) | 'bad
  ;; are the two bytes at rel-pos exactly CR LF?
  (define (crlf-at? buf rel)
    (and (>= (inbuf-length buf) (+ rel 2))
         (let ((bv (inbuf-bv buf)) (base (inbuf-start buf)))
           (and (fx= (bytevector-u8-ref bv (fx+ base rel)) 13)
                (fx= (bytevector-u8-ref bv (fx+ base rel 1)) 10)))))

  ;; After the last chunk (size 0) comes the TRAILER SECTION: zero or more
  ;; header lines, then a blank line (RFC 7230 4.1). A response is not
  ;; complete until that blank line arrives.
  ;;
  ;; Declaring done at the "0" line meant a server that sent "0\r\n" and then
  ;; stopped -- or a connection cut at that exact point -- produced a
  ;; SUCCESSFUL reply with a body that happened to be whatever had arrived.
  ;; Truncation detection is the entire reason chunked framing exists; the
  ;; comment in tls.sc promising "the accepted framings detect truncation"
  ;; was not true of this decoder.
  ;;
  ;; -> rel position just past the terminating CRLF | #f (need more) | 'bad
  (define (trailer-end buf start)
    (let loop ((pos start) (lines 0))
      (cond
        ;; a peer may not spend us without bound on trailers either
        ((fx> lines 64) 'bad)
        ;; A TOTAL bound, not only a per-line one. This scan restarts from
        ;; `start` every time a fragment arrives -- the resumable state
        ;; carries the position of the last-chunk line, not a cursor inside
        ;; the trailer -- so the work is quadratic in the number of
        ;; fragments. With 64 lines of 4096 that was a 256 KiB section
        ;; rescanned per byte: about 34 billion comparisons, tens of
        ;; seconds, on the one scheduler thread. 8 KiB caps the same shape
        ;; at ~33 million, spread over the arrivals, which is nothing. A
        ;; trailer carries a checksum or two; nothing legitimate is near it.
        ((fx> (fx- pos start) 8192) 'bad)
        ((crlf-at? buf pos) (fx+ pos 2))        ; blank line: section over
        (else
         (let ((bv (inbuf-bv buf)) (base (inbuf-start buf))
               (n (inbuf-length buf)))
           (let scan ((i pos))
             (cond
               ((fx> (fx- i pos) chunk-line-limit) 'bad)
               ((fx>= (fx+ i 1) n) #f)
               ((and (fx= (bytevector-u8-ref bv (fx+ base i)) 13)
                     (fx= (bytevector-u8-ref bv (fx+ base (fx+ i 1))) 10))
                (loop (fx+ i 2) (fx+ lines 1)))
               (else (scan (fx+ i 1))))))))))

  (define (chunked-step buf pos chunks got)
    (let loop ((pos pos) (chunks chunks) (got got))
      (let ((r (chunk-size-at buf pos)))
        (cond
          ((not r) (vector 'more pos chunks got))
          ((eq? r 'bad) 'bad)
          (else
           (let ((size (car r)) (eol (cdr r)))
             (cond
               ((= size 0)
                (let ((end (trailer-end buf (fx+ eol 2))))
                  (cond
                    ((eq? end 'bad) 'bad)
                    ((not end) (vector 'more pos chunks got))
                    ;; the end offset comes back too: on a connection that
                    ;; will be REUSED the caller has to know where this
                    ;; response stopped, or bytes belonging to it would be
                    ;; read as the start of the next one
                    (else (vector 'done (bv-concat (reverse chunks) got) end)))))
               ((< (inbuf-length buf) (+ eol 2 size 2))
                (vector 'more pos chunks got))
               ;; the two bytes after the data MUST be CRLF; without
               ;; this the decoder would silently mis-slice a body from
               ;; a broken or hostile server (http.sc checks it too)
               ((not (crlf-at? buf (+ eol 2 size))) 'bad)
               (else
                (loop (+ eol 2 size 2)
                      (cons (inbuf-sub buf (+ eol 2) (+ eol 2 size)) chunks)
                      (+ got size))))))))))

  ;; ---- connection process ----------------------------------------------

  ;; Streaming chunked decode: emit each complete chunk and consume it
  ;; from the buffer immediately -- the buffer holds only the current
  ;; unparsed tail however long the stream runs. The next chunk header
  ;; is always at the buffer start. -> 'done | 'more | 'bad
  (define (chunked-stream-step! buf emit!)
    (let loop ()
      (let ((r (chunk-size-at buf 0)))
        (cond
          ((not r) 'more)
          ((eq? r 'bad) 'bad)
          (else
           (let ((size (car r)) (eol (cdr r)))
             (cond
               ;; the trailer section still has to arrive in full; its
               ;; contents are ignored, its TERMINATOR is what says the
               ;; response was not cut short
               ((= size 0)
                (let ((end (trailer-end buf (fx+ eol 2))))
                  (cond ((eq? end 'bad) 'bad)
                        ((not end) 'more)
                        ;; consume the final chunk and its trailer as well:
                        ;; leaving them in the buffer was harmless while
                        ;; every connection was closed after one response,
                        ;; and is corruption on a reused one
                        (else (inbuf-consume! buf end) 'done))))
               ((< (inbuf-length buf) (+ eol 2 size 2)) 'more)
               ;; Validate the delimiter before exposing the chunk. The
               ;; accumulating decoder already enforces this; streaming
               ;; must not emit bytes from a malformed response first.
               ((not (crlf-at? buf (+ eol 2 size))) 'bad)
               (else
                (emit! (inbuf-sub buf (+ eol 2) (+ eol 2 size)))
                (inbuf-consume! buf (+ eol 2 size 2))
                (loop)))))))))

  ;; ref tags each reply so a late reply (after the caller timed out)
  ;; cannot be mis-read by a later request from the same caller.
  ;; The parse advances INCREMENTALLY as segments arrive -- header scan,
  ;; counted-body check, and chunked decode all resume where they left
  ;; off instead of re-parsing the whole buffer per segment. state:
  ;;   'head                                    waiting for \r\n\r\n
  ;;   #(clen status headers body-start len)    counted body
  ;;   #(chunked status headers pos chunks got) chunked body, resumable
  ;;   #(eof status headers body-start)         body runs until close
  ;; and, with an on-chunk handler (emit), the streaming variants whose
  ;; body bytes are handed out and consumed instead of retained:
  ;;   #(sclen status headers remaining)
  ;;   #(schunked status headers)
  ;;   #(seof status headers)
  ;; Does this response leave the connection usable for another request?
  ;;
  ;; Only when the peer has not said otherwise and the response was framed
  ;; DETERMINATELY -- Content-Length or chunked. A body that ends at close
  ;; obviously cannot be followed by anything, and an error leaves the
  ;; framing in an unknown state. HTTP/1.0 defaults the other way (close
  ;; unless it says keep-alive), which matters behind an old proxy.
  ;; EVERY Connection header, not the first. A field may be repeated and is
  ;; equivalent to one field with the values joined by commas (RFC 7230
  ;; 3.2.2), so assq read only the first line: a response saying
  ;;   Connection: keep-alive
  ;;   Connection: close
  ;; was pooled. And "close" anywhere wins -- it is a refusal, and reading a
  ;; refusal as permission is the direction that corrupts the next request.
  (define (connection-header-says headers)
    (let loop ((hs headers) (seen 'unset))
      (cond
        ((null? hs) seen)
        ((eq? (caar hs) 'connection)
         (let ((v (string-downcase (cdar hs))))
           (cond
             ((token-in? v "close") 'close)          ; decisive, stop here
             ((token-in? v "keep-alive") (loop (cdr hs) 'keep-alive))
             (else (loop (cdr hs) seen)))))
        (else (loop (cdr hs) seen)))))

  ;; a comma-separated token list, matched whole -- "close" must not be
  ;; found inside "closeish" or a header value that merely mentions it
  (define (token-in? v tok)
    (let ((n (string-length v)) (m (string-length tok)))
      (let loop ((i 0) (start 0))
        (cond
          ((> i n) #f)
          ((or (= i n) (char=? (string-ref v i) #\,))
           (let trim-l ((a start))
             (cond
               ((and (< a i) (char-whitespace? (string-ref v a))) (trim-l (+ a 1)))
               (else
                (let trim-r ((b i))
                  (cond
                    ((and (> b a) (char-whitespace? (string-ref v (- b 1))))
                     (trim-r (- b 1)))
                    ((and (= (- b a) m) (string=? (substring v a b) tok)) #t)
                    (else (loop (+ i 1) (+ i 1)))))))))
          (else (loop (+ i 1) start))))))

  ;; Only a version this client actually speaks may default to persistent.
  ;; Excluding the exact string "HTTP/1.0" left everything else -- HTTP/0.9,
  ;; HTTP/9.9, a garbage token -- defaulting to keep-alive, which is
  ;; guessing about a peer whose framing rules are unknown. HTTP/1.1 is the
  ;; only version whose default is persistent; anything else closes unless
  ;; it explicitly says otherwise.
  ;; 1.1 defaults to persistent; 1.0 is persistent only when it SAYS so --
  ;; which is the original keep-alive mechanism and perfectly valid, so
  ;; refusing it (as an over-tight "1.1 only" rule did) throws away every
  ;; reuse against an HTTP/1.0 peer that asked for it. A version this
  ;; client does not speak is never persistent, explicit or not: its
  ;; framing rules are unknown, and that is not a thing to guess about.
  (define (reusable-response? headers version leftover)
    (and (= leftover 0)
         (case (connection-header-says headers)
           ((close) #f)
           ((keep-alive) (or (equal? version "HTTP/1.1")
                             (equal? version "HTTP/1.0")))
           (else (equal? version "HTTP/1.1")))))

  ;; finish: (disposition) -> void, called exactly once when the exchange
  ;; ends. 'reuse means the connection is framed, drained and usable for
  ;; another request; 'close means it must go. The loop no longer closes
  ;; the socket itself -- the process that owns it decides, because with
  ;; pooling that process outlives the request.
  (define (client-loop c caller ref buf state timeout codec emit max-resp method
                       deadline vbox progress last-chunk finish)
    ;; the peer's HTTP version, filled in when the head is parsed: HTTP/1.0
    ;; defaults to close, 1.1 to keep-alive
    (define (version) (unbox vbox))
    (define (reply! r keep?)
      (send caller (vector 'http-reply ref r))
      (finish (if keep? 'reuse 'close)))
    (define (err! msg) (send caller (vector 'http-error ref msg)) (finish 'close))
    ;; a crashing on-chunk handler must not rot in this loop: the typed
    ;; raise propagates to the process guards, which free the codec,
    ;; close the socket, and answer the caller with the message
    ;;
    ;; CONTRACT (behavioral guarantee, not an implementation detail):
    ;; the on-chunk callback is invoked synchronously from the read loop,
    ;; and socket reads are suspended for the duration of the callback.
    ;; Downstream code may rely on this ordering -- chunks never interleave
    ;; with callback execution, and no chunk is buffered behind a running
    ;; callback. Changing this (e.g. queueing callbacks) is a breaking
    ;; change to the streaming interface, not a refactor.
    ;;
    ;; Reads are STOPPED around the handler. The handler is called
    ;; synchronously from this loop, and a handler that does real work --
    ;; a database write, a disk write, anything that parks -- lets the
    ;; scheduler run while the event loop keeps reading the socket as fast
    ;; as the server sends. Those segments land as raw #(tcp-data ...) in
    ;; this process's mailbox, which is unbounded, and none of the response
    ;; limits apply to them: max-resp counts bytes the parser has seen, and
    ;; the parser has not run yet.
    ;;
    ;; Stopping reads closes the kernel's receive window instead, which is
    ;; where back pressure belongs -- a slow consumer should slow the
    ;; SENDER, not accumulate its output in memory.
    (define (emit! bv)
      ;; A chunk reached the consumer: THAT is what the streaming idle clock
      ;; measures. See the receive below.
      (set-box! last-chunk (now-ms))
      (tcp-read-stop! c)
      (guard (e (#t (fail "on-chunk handler raised")))
        (emit bv))
      (tcp-read-start! c))
    ;; drive the parser as far as the buffered bytes allow; replies (or
    ;; errors) and returns #f, or returns the state to keep waiting in
    (define (step state)
      (cond
        ((eq? state 'head)
         (let ((hend (inbuf-find-header-end buf)))
           (cond
             ;; SIZE FIRST, whether or not the block is complete. Checking it
             ;; only while still accumulating meant a peer that sent the whole
             ;; head in one segment was never checked at all -- the terminator
             ;; was found and the block parsed whatever its size. That is the
             ;; same defect the server side had (http.sc's header-limit), on
             ;; the other end of the wire, and it lets an upstream hand this
             ;; single-threaded parser a block bounded only by max-response.
             ((and hend (> (fx+ hend 4) max-response-head))
              (err! "response head too large") #f)
             ((not hend)
               ;; still accumulating: refuse a head block that has already
               ;; outgrown its ceiling rather than waiting for the terminator
               ;; that a hostile upstream may never send
               (if (> (inbuf-length buf) max-response-head)
                   (begin (err! "response head too large") #f)
                   'head))
             (else
               ;; the head block is copied out once (small); the line
               ;; helpers below work on that standalone bytevector
               (let* ((head (inbuf-sub buf 0 (fx+ hend 2)))
                      (sl-end (or (find-crlf head 0) hend))
                      (status (parse-status-line head sl-end))
                      (_ (set-box! vbox (parse-http-version head sl-end)))
                      (headers (parse-headers head (+ sl-end 2) hend))
                      (content-length (response-content-length headers))
                      (transfer-encoding (response-transfer-encoding headers)))
                 (cond
                   ((not status) (err! "malformed status line") #f)
                   ;; a 1xx interim response (100 Continue, 103 Early Hints, ...)
                   ;; is NOT the final reply -- RFC 9110 15.2: discard it and
                   ;; keep reading for the real status. 101 Switching Protocols
                   ;; is terminal (the connection leaves HTTP), so it is excluded
                   ;; and falls through to the no-body reply below.
                   ((and (fx>= status 100) (fx< status 200) (not (fx= status 101)))
                    (inbuf-consume! buf (fx+ hend 4))
                    (step 'head))
                   ((eq? content-length 'bad)
                    (err! "invalid Content-Length") #f)
                   ((eq? transfer-encoding 'bad)
                    (err! "invalid Transfer-Encoding") #f)
                   ((and content-length transfer-encoding)
                    (err! "ambiguous response framing") #f)
                   ;; HEAD, and 204/304/101, carry no body whatever the headers
                   ;; say (RFC 7230 3.3.3) -- reply now. Without this a HEAD to
                   ;; S3 would block on a Content-Length body never sent.
                   ((or (eq? method 'HEAD) (fx= status 204) (fx= status 304)
                        (fx= status 101))
                    ;; 101 hands the connection to another protocol, so it
                    ;; is never ours to reuse whatever the headers say
                    (reply! (make-response status headers empty-bv)
                            (and (not (fx= status 101))
                                 (reusable-response?
                                   headers (version)
                                   (- (inbuf-length buf) (fx+ hend 4)))))
                    #f)
                   (else
                    ;; streaming: the head is consumed so body handling
                    ;; works from the buffer start and stays flat
                    (when emit (inbuf-consume! buf (+ hend 4)))
                    (cond
                      (content-length
                       (step (if emit
                                 (vector 'sclen status headers content-length)
                                 (vector 'clen status headers (+ hend 4)
                                         content-length))))
                      (transfer-encoding
                       (step (if emit
                                 (vector 'schunked status headers)
                                 (vector 'chunked status headers (+ hend 4) '() 0))))
                      (else
                       (if emit
                           (step (vector 'seof status headers))
                           (vector 'eof status headers (+ hend 4))))))))))))
        ((eq? (vector-ref state 0) 'clen)
         (let ((body-start (vector-ref state 3)) (len (vector-ref state 4)))
           (if (>= (- (inbuf-length buf) body-start) len)
               (begin
                 (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                           (inbuf-sub buf body-start (+ body-start len)))
                         (reusable-response?
                           (vector-ref state 2) (version)
                           (- (inbuf-length buf) (+ body-start len))))
                 #f)
               state)))
        ((eq? (vector-ref state 0) 'chunked)
         (let ((r (chunked-step buf (vector-ref state 3)
                                (vector-ref state 4) (vector-ref state 5))))
           (cond
             ((eq? r 'bad) (err! "bad chunked response") #f)
             ((eq? (vector-ref r 0) 'done)
              (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                        (vector-ref r 1))
                      (reusable-response?
                        (vector-ref state 2) (version)
                        (- (inbuf-length buf) (vector-ref r 2))))
              #f)
             (else (vector 'chunked (vector-ref state 1) (vector-ref state 2)
                           (vector-ref r 1) (vector-ref r 2) (vector-ref r 3))))))
        ((eq? (vector-ref state 0) 'sclen)
         (let* ((remaining (vector-ref state 3))
                (take (min (inbuf-length buf) remaining)))
           (when (> take 0)
             (emit! (inbuf-sub buf 0 take))
             (inbuf-consume! buf take))
           (if (= take remaining)
               (begin
                 (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                           empty-bv)
                         (reusable-response? (vector-ref state 2) (version)
                                             (inbuf-length buf)))
                 #f)
               (vector 'sclen (vector-ref state 1) (vector-ref state 2)
                       (- remaining take)))))
        ((eq? (vector-ref state 0) 'schunked)
         (case (chunked-stream-step! buf emit!)
           ((bad) (err! "bad chunked response") #f)
           ((done)
            (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                      empty-bv)
                    (reusable-response? (vector-ref state 2) (version)
                                        (inbuf-length buf)))
            #f)
           (else state)))
        ((eq? (vector-ref state 0) 'seof)
         (let ((n (inbuf-length buf)))
           (when (> n 0)
             (emit! (inbuf-sub buf 0 n))
             (inbuf-consume! buf n))
           state))
        (else state)))                          ; 'eof mode: wait for close
    (let ((state (step state)))
      (when state
        ;; Two clocks, one wait: `timeout` is the idle allowance and resets
        ;; with every arrival; `deadline` is the absolute total budget and
        ;; never does. Whichever runs out first ends the request -- HERE, in
        ;; the process that owns the socket and the codec, so done! always
        ;; runs. The caller's own timer is only a backstop against this
        ;; process wedging, and a kill from it no longer happens on the
        ;; ordinary slow-upstream path.
        ;; For a STREAM there is no deadline (documented), so the idle
        ;; allowance is the only bound -- and it must measure idleness of
        ;; PROGRESS, not of bytes. Re-arming it on every arriving segment
        ;; meant an upstream could dribble bytes that never complete a
        ;; chunk: on-chunk never fired, the request never timed out, and the
        ;; connection was held for as long as the peer cared to keep typing.
        (receive (after (cond
                          (deadline (min timeout (max 0 (- deadline (now-ms)))))
                          ((and emit (not (eq? timeout 'infinity)))
                           (max 1 (- timeout (- (now-ms) (unbox last-chunk)))))
                          (else timeout))
                    (err! (if (and deadline (>= (now-ms) deadline))
                              "request timeout"
                              "response timeout")))
          (`#(tcp-data ,raw)
            (let ((bv (if codec ((vector-ref codec 1) raw) raw)))
              ;; The peer has said something about THIS request. After this
              ;; point a failure is not a stale pooled connection -- the
              ;; server was reached and may have acted -- so a retry would
              ;; risk repeating the work.
              (unless (zero? (bytevector-length bv)) (set-box! progress #t))
              (if (zero? (bytevector-length bv))   ; pure TLS records, no app data
                  (client-loop c caller ref buf state timeout codec emit max-resp method
                               deadline vbox progress last-chunk finish)
                  (begin
                    (inbuf-append! buf bv)
                    ;; with streaming consumption this caps the UNPARSED
                    ;; tail (e.g. one oversized chunk), not the stream total
                    (if (> (inbuf-length buf) max-resp)
                        (err! "response too large")
                        (client-loop c caller ref buf state timeout codec emit max-resp method
                               deadline vbox progress last-chunk finish))))))
          ;; The caller is gone. Everything after this point would be work
          ;; for nobody -- and for a stream, work with no end: no total
          ;; deadline, an on-chunk handler delivering into a dead process,
          ;; and this process holding the socket and the TLS codec for as
          ;; long as the upstream keeps sending.
          (`#(DOWN ,dpid ,dreason) (err! "caller is gone"))
          (`#(tcp-eof)
            (cond
              ;; a body delimited by the close: there is nothing left to reuse
              ((and (vector? state) (eq? (vector-ref state 0) 'eof))
               (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                         (inbuf-sub buf (vector-ref state 3) (inbuf-length buf)))
                       #f))
              ((and (vector? state) (eq? (vector-ref state 0) 'seof))
               (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                         empty-bv)
                       #f))
              (else (err! "connection closed early"))))
          (`#(tcp-error ,e) (err! "connection error"))))))

  ;; ---- connection reuse --------------------------------------------------
  ;;
  ;; A pooled connection lives in its OWN process, which owns the socket for
  ;; as long as the connection lasts. That is not a style choice: #(tcp-data
  ;; bv) carries no connection identity (libuv delivery names the owning
  ;; PROCESS, not the conn), so one process can own exactly one socket -- the
  ;; same rule websocket.sc states. A registry holding sockets directly could
  ;; not tell which of its idle connections had just closed.
  ;;
  ;; So: a keeper process per connection, and a registry that holds only
  ;; pids. The keeper is also what makes idle connections safe. Servers close
  ;; keep-alive connections all the time, and a keeper sitting in receive
  ;; SEES that eof and takes itself out of the pool. Without it, staleness
  ;; would only ever be discovered by a request failing.

  (define pool-max-idle-per-origin 4)
  (define pool-max-idle-total 64)
  (define pool-idle-ms 30000)      ; how long an unused connection is kept

  ;; Raise or lower the pool. #f leaves one alone, same shape as
  ;; redis-set-limits! and node-set-limits!.
  (define (http-client-pool! per-origin total idle-ms)
    (define (check who v)
      (unless (and (integer? v) (exact? v) (>= v 0))
        (assertion-violation 'http-client-pool!
          (string-append who " must be a nonnegative exact integer") v)))
    (when per-origin (check "per-origin" per-origin)
                     (set! pool-max-idle-per-origin per-origin))
    (when total (check "total" total) (set! pool-max-idle-total total))
    (when idle-ms (check "idle-ms" idle-ms) (set! pool-idle-ms idle-ms))
    (void))

  ;; counters, read by http-client-pool-stats
  (define stat-reused 0)
  (define stat-dialed 0)
  (define stat-stale 0)
  (define stat-retried 0)

  (define registry-pid #f)
  (define (registry)
    (if (and registry-pid (process-alive? registry-pid))
        registry-pid
        ;; Interrupts off across the check and the spawn: two requests
        ;; starting at once would otherwise each create a registry and the
        ;; second would replace the first, orphaning every connection the
        ;; first was holding.
        (with-interrupts-disabled
          (if (and registry-pid (process-alive? registry-pid))
              registry-pid
              (let ((p (spawn registry-loop)))
                (set! registry-pid p)
                p)))))

  (define (registry-loop)
    ;; origin -> list of (pid . monitor). The monitor handle is kept, not
    ;; just the pid: a monitor taken and never released is a registration
    ;; that accumulates for the life of the process, one per pooled
    ;; connection ever created.
    (let ((idle (make-hashtable string-hash string=?))
          (total 0))
      (define (entries origin) (hashtable-ref idle origin '()))
      (define (find-entry origin pid) (assq pid (entries origin)))
      (define (drop! origin pid)
        (let ((xs (entries origin)))
          (when (assq pid xs)
            (set! total (- total 1))
            (let ((rest (remp (lambda (e) (eq? (car e) pid)) xs)))
              (if (null? rest)
                  (hashtable-delete! idle origin)
                  (hashtable-set! idle origin rest))))))
      ;; demonitor, then drain a DOWN that was already delivered -- left
      ;; behind it would sit in this mailbox forever, one per pooled
      ;; connection ever handed out.
      ;;
      ;; -> #t if that DOWN was there, which is the registry finding out the
      ;; keeper is DEAD. Swallowing it silently and handing the pid out
      ;; anyway was worse than not monitoring at all: the requester got a
      ;; connection already known to be gone, and a non-idempotent request
      ;; then failed without a byte of it having been written.
      (define (release! origin pid)
        (let ((e (find-entry origin pid)))
          (and e
               (begin
                 (demonitor (cdr e))
                 (receive (after 0 #f) (`#(DOWN ,@pid ,reason) #t))))))
      (define (all-pids)
        (let ((vs (hashtable-values idle)) (acc '()))
          (do ((i 0 (+ i 1))) ((= i (vector-length vs)) acc)
            (set! acc (append (map car (vector-ref vs i)) acc)))))
      (define (forget-everywhere! pid)
        (let ((ks (hashtable-keys idle)))
          (do ((i 0 (+ i 1))) ((= i (vector-length ks)))
            (drop! (vector-ref ks i) pid))))
      (let loop ()
        (receive
          (`#(hc-take ,origin ,ref ,from)
            ;; Keep looking past keepers that turn out to be dead, and do
            ;; not hand one to a requester that is already gone -- that
            ;; would strand a live socket outside the registry, invisible to
            ;; both the statistics and http-client-close-idle!, until its
            ;; own idle timer eventually fired.
            (let scan ()
              (let ((xs (entries origin)))
                (cond
                  ((null? xs) (send from (vector 'hc-took ref #f)))
                  ((not (process-alive? from))
                   (send from (vector 'hc-took ref #f)))   ; discarded; the
                                                           ; keeper stays pooled
                  (else
                   (let* ((p (car (car xs)))
                          (dead? (release! origin p)))
                     (drop! origin p)
                     (if (or dead? (not (process-alive? p)))
                         (scan)
                         (send from (vector 'hc-took ref p))))))))
            (loop))
          (`#(hc-put ,origin ,pid ,ref)
            (let ((xs (entries origin)))
              (cond
                ((or (>= total pool-max-idle-total)
                     (>= (length xs) pool-max-idle-per-origin))
                 (send pid (vector 'hc-put-reply ref 'drop)))
                (else
                 ;; monitored while idle: a keeper killed outright (a
                 ;; supervisor, an owner cleanup) sends no hc-gone, and a
                 ;; dead pid handed to a later request is a wasted retry
                 (hashtable-set! idle origin (cons (cons pid (monitor pid)) xs))
                 (set! total (+ total 1))
                 (send pid (vector 'hc-put-reply ref 'keep)))))
            (loop))
          (`#(hc-gone ,origin ,pid)
            (release! origin pid)                ; its DOWN, if any, drained
            (drop! origin pid)
            (loop))
          (`#(DOWN ,pid ,reason)
            ;; the monitor is consumed by the DOWN itself, so only the
            ;; bookkeeping is left to clear
            (forget-everywhere! pid)
            (loop))
          (`#(hc-close-all ,ref ,from)
            (for-each (lambda (p) (send p (vector 'hc-quit))) (all-pids))
            (let ((ks (hashtable-keys idle)))
              (do ((i 0 (+ i 1))) ((= i (vector-length ks)))
                (let ((origin (vector-ref ks i)))
                  (for-each (lambda (e) (release! origin (car e)))
                            (entries origin)))))
            (hashtable-clear! idle)
            (set! total 0)
            (send from (vector 'hc-close-all-reply ref 'ok))
            (loop))
          (`#(hc-stats ,ref ,from)
            (send from
              (vector 'hc-stats-reply ref
                (list (cons 'idle total)
                      (cons 'origins (vector-length (hashtable-keys idle)))
                      (cons 'reused stat-reused)
                      (cons 'dialed stat-dialed)
                      (cons 'stale stat-stale)
                      (cons 'retried stat-retried))))
            (loop))))))

  ;; Close every idle pooled connection now. For shutdown, and for tests that
  ;; must not inherit a connection from an earlier case.
  (define (http-client-close-idle!)
    (let ((ref (gensym)))
      (send (registry) (vector 'hc-close-all ref self))
      (receive (after 5000 'timeout)
        (`#(hc-close-all-reply ,@ref ,r) r))))

  (define (http-client-pool-stats)
    (let ((ref (gensym)))
      (send (registry) (vector 'hc-stats ref self))
      (receive (after 5000 (raise (vector 'http-client-error "pool stats timeout")))
        (`#(hc-stats-reply ,@ref ,st) st))))

  ;; Ask the registry for an idle connection to this origin.
  (define (take-pooled! origin)
    (let ((ref (gensym)))
      (send (registry) (vector 'hc-take origin ref self))
      (receive (after 5000 #f)
        (`#(hc-took ,@ref ,p) p))))

  ;; May this request be sent again after a pooled connection turned out to
  ;; be already closed? Only when repeating it cannot repeat an effect: the
  ;; idempotent methods, or anything with no body to resend.
  ;; IDEMPOTENCE is the whole test. Treating "has no body" as replayable was
  ;; wrong: a bodyless POST or PATCH -- POST /orders/42/ship, PATCH with the
  ;; change in the path -- is an ordinary way to ask for an effect, and a
  ;; server that performed it and then lost the connection before answering
  ;; gets the request a second time. The stale check ("nothing was received")
  ;; does not save it: nothing received means nothing was received, not that
  ;; nothing was done.
  ;;
  ;; A body has nothing to do with it. It was in the rule because a body is
  ;; the part that must be re-sendable, which is a necessary condition, not
  ;; a sufficient one.
  (define (replayable? method body)
    (and (memq method '(GET HEAD PUT DELETE OPTIONS TRACE)) #t))

  ;; A connection's keeper. Owns c and the codec for the connection's whole
  ;; life, serves one request at a time, and decides after each whether the
  ;; connection may be kept.
  ;;
  ;; client-loop answers the KEEPER, not the original caller, and the keeper
  ;; forwards. That hop is what lets a failure on a REUSED connection with
  ;; nothing received be reported as 'stale rather than as an error: the
  ;; request never reached a server that acted on it, so it can be retried
  ;; on a fresh connection. On a freshly dialled connection the same failure
  ;; is a real error and is passed through unchanged.
  (define (keeper-serve c codec origin reused?
                        ref real-caller req idle emit max-resp method deadline)
    ;; Watch the caller for as long as we are working for it.
    ;;
    ;; The caller monitors this process; nothing monitored the caller. A
    ;; stream has no total deadline by design, so a caller killed by its
    ;; supervisor left this process holding the socket, the TLS codec and
    ;; the on-chunk handler -- still running it, delivering to a process
    ;; that no longer exists, for as long as the upstream kept sending. One
    ;; such leak per killed subscriber.
    ;;
    ;; A monitor rather than a link: a link would kill this process without
    ;; running the cleanup below, and the socket and codec would leak in a
    ;; different way.
    (let ((watch (monitor real-caller))
          (disp 'close)
          (progress (box #f))
          (vbox (box "HTTP/1.1"))
          ;; when the stream last delivered something; the request itself
          ;; counts as the starting point
          (last-chunk (box (now-ms)))
          (buf (make-inbuf)))
      (tcp-write! c (if codec ((vector-ref codec 0) req) req) #f)
      (client-loop c self ref buf 'head idle codec emit max-resp method
                   deadline vbox progress last-chunk (lambda (d) (set! disp d)))
      ;; client-loop has already sent its answer to us
      (receive (after 0 (void))
        (`#(http-reply ,@ref ,r) (send real-caller (vector 'http-reply ref r)))
        (`#(http-error ,@ref ,m)
          (if (and reused? (not (unbox progress)))
              (send real-caller (vector 'http-stale ref))
              (send real-caller (vector 'http-error ref m)))))
      ;; release the watch, and drain a DOWN already delivered -- left
      ;; behind it would be read by the idle receive below as this
      ;; connection's own trouble
      (when watch
        (demonitor watch)
        (receive (after 0 'ok) (`#(DOWN ,@real-caller ,reason) 'ok)))
      disp))

  (define (keeper-bye! c codec origin)
    (send (registry) (vector 'hc-gone origin self))
    (when codec ((vector-ref codec 2)))
    (tcp-close! c))

  (define (keeper-idle c codec origin)
    ;; The peer may already have closed. A server that answers and closes
    ;; queues tcp-data and then tcp-eof; client-loop consumes the data,
    ;; declares the response reusable and returns, and the eof is still
    ;; sitting in this mailbox. Offering the connection then advertises one
    ;; that is already gone: the next request is handed it, gets a DOWN, and
    ;; -- if it is not idempotent -- fails without ever having been written.
    ;;
    ;; So look before offering. Anything at all on the socket at this point
    ;; means the connection is not a clean starting point: an eof or error
    ;; obviously, and unsolicited data just as much.
    (let ((dirty (receive (after 0 #f)
                   (`#(tcp-eof) #t)
                   (`#(tcp-error ,e) #t)
                   (`#(tcp-data ,bv) #t))))
      (if dirty
          (keeper-bye! c codec origin)
          (keeper-offer c codec origin))))

  (define (keeper-offer c codec origin)
    ;; Offer ourselves to the pool; the registry decides whether it wants
    ;; another idle connection for this origin.
    (let ((r (gensym)))
      (send (registry) (vector 'hc-put origin self r))
      (receive (after 5000 (keeper-bye! c codec origin))
        (`#(hc-put-reply ,@r ,d)
          (if (eq? d 'keep)
              (keeper-wait c codec origin)
              (keeper-bye! c codec origin))))))

  (define (keeper-wait c codec origin)
    (receive (after (if (> pool-idle-ms 0) pool-idle-ms 1)
                (keeper-bye! c codec origin))
      (`#(hc-run ,ref ,real-caller ,req ,idle ,emit ,max-resp ,method ,deadline)
        (set! stat-reused (+ stat-reused 1))
        (let ((disp (keeper-serve c codec origin #t ref real-caller req idle
                                  emit max-resp method deadline)))
          (if (eq? disp 'reuse)
              (keeper-idle c codec origin)
              (keeper-bye! c codec origin))))
      ;; The server closed, or spoke unbidden. Either way this connection is
      ;; no longer a clean starting point, and noticing it HERE rather than
      ;; on the next request is the whole reason a keeper sits in receive.
      (`#(tcp-eof) (keeper-bye! c codec origin))
      (`#(tcp-error ,e) (keeper-bye! c codec origin))
      (`#(tcp-data ,bv) (keeper-bye! c codec origin))
      (`#(hc-quit) (keeper-bye! c codec origin))))

  ;; ---- public API ------------------------------------------------------

  (define ref-counter 0)

  ;; (http-request method url opts) where opts is an alist:
  ;;   (headers . ((name . value) ...))   extra request headers
  ;;   (body    . string-or-bytevector)   request body
  ;;   (timeout . milliseconds)           default 30000; a nonnegative
  ;;                                      exact integer. 0 (= no idle
  ;;                                      limit) is only legal together
  ;;                                      with on-chunk -- a plain
  ;;                                      request with no deadline could
  ;;                                      only ever hang. Without
  ;;                                      on-chunk it is also the total
  ;;                                      budget: dns + connect + TLS +
  ;;                                      response together answer
  ;;                                      within timeout + 2000ms.
  ;;   (on-chunk . proc)                  streaming: body bytevectors are
  ;;                                      handed to proc as they decode;
  ;;                                      the reply's body is empty. With
  ;;                                      on-chunk, timeout bounds the idle
  ;;                                      gap between chunks (0 = none) and
  ;;                                      there is no total deadline.
  ;;   (max-response . bytes)             cap on buffered response bytes
  ;;                                      (default 32 MiB); with on-chunk
  ;;                                      it bounds the unparsed tail, not
  ;;                                      the stream total
  ;;   (reuse . #f)                       do not take or leave a pooled
  ;;                                      connection for this request
  ;;
  ;; CONNECTIONS ARE REUSED by default: after a response that leaves the
  ;; connection framed and drained, it is kept and offered to the next
  ;; request for the same host/port/scheme. That saves a TCP handshake, and
  ;; over TLS a full handshake, which usually dominates a small request.
  ;; http-client-pool! sizes it; http-client-close-idle! empties it.
  ;;
  ;; A pooled connection can go stale: a server may close an idle keep-alive
  ;; connection at any moment, and it may do so exactly between being handed
  ;; out and being written to. When that happens with NOTHING received, the
  ;; request never reached a server that could have acted on it, and it is
  ;; retried once on a fresh connection -- but only for methods that are
  ;; idempotent or carry no body. A POST that loses that race is reported
  ;; rather than repeated: silently sending it twice is the one outcome
  ;; worse than failing.
  (define (http-request method url . rest)
    (let* ((opts (if (pair? rest) (car rest) '()))
           (headers (let ((p (assq 'headers opts))) (if p (cdr p) '())))
           (body (let ((p (assq 'body opts))) (and p (cdr p))))
           (timeout (let ((p (assq 'timeout opts))) (if p (cdr p) default-timeout-ms)))
           (on-chunk (let ((p (assq 'on-chunk opts))) (and p (cdr p))))
           (max-resp (let ((p (assq 'max-response opts)))
                       (if p (cdr p) max-response)))
           (reuse? (let ((p (assq 'reuse opts))) (if p (and (cdr p) #t) #t)))
           ;; internal: set by the stale retry so it dials rather than
           ;; taking another connection that may be equally stale
           (fresh-only? (and (assq '%fresh opts) #t)))
      (when on-chunk
        (unless (procedure? on-chunk)
          (fail "on-chunk must be a procedure")))
      (unless (and (integer? timeout) (exact? timeout) (>= timeout 0))
        (fail "timeout must be a nonnegative exact integer (milliseconds)"))
      (unless (or on-chunk (> timeout 0))
        (fail "timeout 0 (no idle limit) requires on-chunk streaming"))
      (unless (and (integer? max-resp) (exact? max-resp) (> max-resp 0))
        (fail "max-response must be a positive exact integer (bytes)"))
      (let (;; connection setup (dns/connect) always keeps a finite bound;
            ;; timeout 0 only lifts the response-side idle limit
            (setup-timeout (if (> timeout 0) timeout default-timeout-ms))
            (idle (if (> timeout 0) timeout 'infinity))
            (caller self)
            (ref (gensym)))
        (let-values (((host port path tls?) (parse-url url)))
          ;; fail fast, before any connection is attempted
          (when (and tls? (not https-connector))
            (fail "https not supported; import (igropyr tls) and call (tls-enable!)"))
          (let* (;; Host carries the port when it is not the scheme
                 ;; default (RFC 7230); TLS keeps the bare host for SNI
                 (host-header (if (= port (if tls? default-tls-port default-port))
                                  host
                                  (string-append host ":" (number->string port))))
                 ;; The total deadline is absolute and lives in the
                 ;; connection process, because that is where the socket and
                 ;; the TLS codec live: when it expires the process answers
                 ;; err! -> done! and frees them itself. It also caps the
                 ;; setup phases, which each kept a full setup-timeout before
                 ;; -- dns + connect + handshake could take 3x timeout while
                 ;; the caller's watchdog fired at timeout + 2000. Streaming
                 ;; keeps no total deadline (documented contract), so #f.
                 (deadline (and (not on-chunk) (+ (now-ms) timeout 2000)))
                 (origin (string-append (if tls? "https://" "http://")
                                        host ":" (number->string port)))
                 (req (build-request method host-header path headers body reuse?))
                 ;; A pooled connection for this origin, if the registry has
                 ;; one. Taken BEFORE the keeper is spawned, so a hit costs
                 ;; no process at all.
                 (pooled (and reuse? (not fresh-only?) (take-pooled! origin)))
                 (pid (or
                        pooled
                        (spawn
                        (lambda ()
                          (define (setup-left)
                            (if deadline
                                (min setup-timeout
                                     (max 0 (- deadline (now-ms))))
                                setup-timeout))
                          (guard (e (#t (send caller
                                          (vector 'http-error ref
                                            ;; surface codec/parse errors (e.g. a TLS
                                            ;; certificate failure) instead of a blur
                                            (if (and (vector? e)
                                                     (eq? (vector-ref e 0) 'http-client-error)
                                                     (string? (vector-ref e 1)))
                                                (vector-ref e 1)
                                                "request failed")))))
                            ;; resolve the host (a dotted IP resolves to itself), then
                            ;; connect to the IP
                            (dns-resolve! host self)
                            (receive (after (setup-left)
                                        (send caller (vector 'http-error ref "dns timeout")))
                              (`#(dns-resolved ,ip)
                                (tcp-connect! ip port self)
                                (receive (after (setup-left)
                                            (send caller (vector 'http-error ref "connect timeout"))
                                            ;; the connect is still in flight; if it
                                            ;; lands after we gave up, close it so the
                                            ;; conn/fd is not leaked
                                            (receive (after 5000 'done)
                                              (`#(tcp-connected ,c) (tcp-close! c))
                                              (`#(tcp-connect-failed ,e) 'done)))
                                  (`#(tcp-connected ,c)
                                    (tcp-read-start! c)
                                    ;; if TLS setup or a later codec step raises, free
                                    ;; the session and the socket before propagating
                                    (let ((codec #f))
                                      (guard (e (#t (when codec ((vector-ref codec 2)))
                                                    (tcp-close! c)
                                                    (raise e)))
                                        (when tls?
                                          (set! codec (https-connector c host (setup-left))))
                                        (set! stat-dialed (+ stat-dialed 1))
                                        (let ((disp (keeper-serve c codec origin #f ref caller
                                                                  req idle on-chunk max-resp
                                                                  method deadline)))
                                          (if (and reuse? (eq? disp 'reuse))
                                              (keeper-idle c codec origin)
                                              (keeper-bye! c codec origin))))))
                                  (`#(tcp-connect-failed ,e)
                                    (send caller (vector 'http-error ref (uv-strerror e))))))
                              (`#(dns-failed ,e)
                                (send caller (vector 'http-error ref "dns resolution failed")))))))))
                 ;; A stream has no total deadline, so the caller must not
                 ;; outlive the connection process unprotected: if it dies
                 ;; without reporting (killed by a supervisor, or a raise
                 ;; inside its own guard handler), the DOWN below answers
                 ;; instead of leaving the caller parked forever.
                 (mon (monitor pid)))
            ;; consume the monitor on every exit: a DOWN must not linger
            ;; in the caller's mailbox to confuse an unrelated receive
            (define (release!)
              (demonitor mon)
              (receive (after 0 #f) (`#(DOWN ,@pid ,_) #t)))
            ;; The pooled connection was already gone. Nothing was received,
            ;; so no server acted on this request and it can be sent again --
            ;; on a fresh connection, and only once.
            (define (retry-fresh!)
              (set! stat-stale (+ stat-stale 1))
              (if (replayable? method body)
                  (begin
                    (set! stat-retried (+ stat-retried 1))
                    ;; %fresh suppresses taking from the pool, so the retry
                    ;; cannot pick up a second stale connection and loop
                    (http-request method url (cons '(%fresh . #t) opts)))
                  (raise (vector 'http-client-error
                           "pooled connection was closed before any response; not retried because the request is not idempotent"))))
            ;; a pooled keeper is already running: hand it the job. After
            ;; the internal defines, which R6RS requires to come first.
            (when pooled
              (send pid (vector 'hc-run ref caller req idle on-chunk
                                max-resp method deadline)))
            ;; The total deadline is enforced INSIDE the connection process
            ;; (see `deadline` above), which answers http-error and cleans up
            ;; after itself; on the ordinary timeout path this receive gets
            ;; that message, not the after. The watchdog below fires only if
            ;; the connection process wedged past its own deadline, and only
            ;; then kills it -- a kill skips done!, so it must stay the last
            ;; resort, never the mechanism. Killing an already-exited pid is
            ;; a no-op (@kill checks alive?), so the race with a normal exit
            ;; is benign. A stream parks until the connection process
            ;; reports -- IT is bounded by the idle timeout (or, with idle
            ;; 0, by its own guards plus the monitor) -- so every path
            ;; still answers.
            (receive (after (if on-chunk 'infinity (+ timeout 7000))
                        (kill pid 'request-timeout)
                        (release!)
                        (raise (vector 'http-client-error "request timeout")))
              (`#(http-reply ,@ref ,resp) (release!) resp)
              (`#(http-stale ,@ref) (release!) (retry-fresh!))
              (`#(http-error ,@ref ,msg)
                (release!)
                (raise (vector 'http-client-error msg)))
              (`#(DOWN ,@pid ,reason)
                ;; A pooled keeper that died without answering had already
                ;; been closed by the server; nothing was sent to anyone.
                (if pooled
                    (retry-fresh!)
                    (raise (vector 'http-client-error "connection process died"))))))))))

  (define (http-get url . rest)
    (apply http-request 'GET url rest))

  (define (http-post url body . rest)
    (let ((opts (if (pair? rest) (car rest) '())))
      (http-request 'POST url (cons (cons 'body body) opts))))
)
