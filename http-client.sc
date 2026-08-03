#!chezscheme
;;; (igropyr http-client) -- non-blocking outbound HTTP/1.1 client.
;;;
;;; Same actor model as the database clients: each request runs in its
;;; own green process that connects, sends, and reads the reply, while
;;; the caller parks in receive -- the OS thread keeps serving other
;;; work. One connection per request (Connection: close); no pooling.
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
  (define (build-request method host-header path headers body)
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
        (line "Connection: close")
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

  (define (chunked-step buf pos chunks got)
    (let loop ((pos pos) (chunks chunks) (got got))
      (let ((r (chunk-size-at buf pos)))
        (cond
          ((not r) (vector 'more pos chunks got))
          ((eq? r 'bad) 'bad)
          (else
           (let ((size (car r)) (eol (cdr r)))
             (cond
               ((= size 0) (vector 'done (bv-concat (reverse chunks) got)))
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
               ((= size 0) 'done)               ; final chunk; trailers ignored
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
  (define (client-loop c caller ref buf state timeout codec emit max-resp method deadline)
    (define (done!) (when codec ((vector-ref codec 2))) (tcp-close! c))
    (define (reply! r) (send caller (vector 'http-reply ref r)) (done!))
    (define (err! msg) (send caller (vector 'http-error ref msg)) (done!))
    ;; a crashing on-chunk handler must not rot in this loop: the typed
    ;; raise propagates to the process guards, which free the codec,
    ;; close the socket, and answer the caller with the message
    (define (emit! bv)
      (guard (e (#t (fail "on-chunk handler raised")))
        (emit bv)))
    ;; drive the parser as far as the buffered bytes allow; replies (or
    ;; errors) and returns #f, or returns the state to keep waiting in
    (define (step state)
      (cond
        ((eq? state 'head)
         (let ((hend (inbuf-find-header-end buf)))
           (if (not hend)
               ;; still accumulating: refuse a head block that has already
               ;; outgrown its ceiling rather than waiting for the terminator
               ;; that a hostile upstream may never send
               (if (> (inbuf-length buf) max-response-head)
                   (begin (err! "response head too large") #f)
                   'head)
               ;; the head block is copied out once (small); the line
               ;; helpers below work on that standalone bytevector
               (let* ((head (inbuf-sub buf 0 (fx+ hend 2)))
                      (sl-end (or (find-crlf head 0) hend))
                      (status (parse-status-line head sl-end))
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
                    (reply! (make-response status headers empty-bv))
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
                           (vector 'eof status headers (+ hend 4)))))))))))
        ((eq? (vector-ref state 0) 'clen)
         (let ((body-start (vector-ref state 3)) (len (vector-ref state 4)))
           (if (>= (- (inbuf-length buf) body-start) len)
               (begin
                 (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                           (inbuf-sub buf body-start (+ body-start len))))
                 #f)
               state)))
        ((eq? (vector-ref state 0) 'chunked)
         (let ((r (chunked-step buf (vector-ref state 3)
                                (vector-ref state 4) (vector-ref state 5))))
           (cond
             ((eq? r 'bad) (err! "bad chunked response") #f)
             ((eq? (vector-ref r 0) 'done)
              (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                        (vector-ref r 1)))
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
                           empty-bv))
                 #f)
               (vector 'sclen (vector-ref state 1) (vector-ref state 2)
                       (- remaining take)))))
        ((eq? (vector-ref state 0) 'schunked)
         (case (chunked-stream-step! buf emit!)
           ((bad) (err! "bad chunked response") #f)
           ((done)
            (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                      empty-bv))
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
        (receive (after (if deadline
                            (min timeout (max 0 (- deadline (now-ms))))
                            timeout)
                    (err! (if (and deadline (>= (now-ms) deadline))
                              "request timeout"
                              "response timeout")))
          (`#(tcp-data ,raw)
            (let ((bv (if codec ((vector-ref codec 1) raw) raw)))
              (if (zero? (bytevector-length bv))   ; pure TLS records, no app data
                  (client-loop c caller ref buf state timeout codec emit max-resp method deadline)
                  (begin
                    (inbuf-append! buf bv)
                    ;; with streaming consumption this caps the UNPARSED
                    ;; tail (e.g. one oversized chunk), not the stream total
                    (if (> (inbuf-length buf) max-resp)
                        (err! "response too large")
                        (client-loop c caller ref buf state timeout codec emit max-resp method deadline))))))
          (`#(tcp-eof)
            (cond
              ((and (vector? state) (eq? (vector-ref state 0) 'eof))
               (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                         (inbuf-sub buf (vector-ref state 3) (inbuf-length buf)))))
              ((and (vector? state) (eq? (vector-ref state 0) 'seof))
               (reply! (make-response (vector-ref state 1) (vector-ref state 2)
                         empty-bv)))
              (else (err! "connection closed early"))))
          (`#(tcp-error ,e) (err! "connection error"))))))

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
  (define (http-request method url . rest)
    (let* ((opts (if (pair? rest) (car rest) '()))
           (headers (let ((p (assq 'headers opts))) (if p (cdr p) '())))
           (body (let ((p (assq 'body opts))) (and p (cdr p))))
           (timeout (let ((p (assq 'timeout opts))) (if p (cdr p) default-timeout-ms)))
           (on-chunk (let ((p (assq 'on-chunk opts))) (and p (cdr p))))
           (max-resp (let ((p (assq 'max-response opts)))
                       (if p (cdr p) max-response))))
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
                 (pid (spawn
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
                                        (let ((req (build-request method host-header path headers body)))
                                          (tcp-write! c (if codec ((vector-ref codec 0) req) req) #f))
                                        (client-loop c caller ref (make-inbuf) 'head idle codec
                                                     on-chunk max-resp method deadline))))
                                  (`#(tcp-connect-failed ,e)
                                    (send caller (vector 'http-error ref (uv-strerror e))))))
                              (`#(dns-failed ,e)
                                (send caller (vector 'http-error ref "dns resolution failed"))))))))
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
              (`#(http-error ,@ref ,msg)
                (release!)
                (raise (vector 'http-client-error msg)))
              (`#(DOWN ,@pid ,reason)
                (raise (vector 'http-client-error "connection process died")))))))))

  (define (http-get url . rest)
    (apply http-request 'GET url rest))

  (define (http-post url body . rest)
    (let ((opts (if (pair? rest) (car rest) '())))
      (http-request 'POST url (cons (cons 'body body) opts))))
)
