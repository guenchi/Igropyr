#!chezscheme
;;; (igropyr express) -- an Express-style framework on the Igropyr core.
;;;
;;; This is a framework layer, not part of the engine: it turns an app
;;; description (routes, middleware, static mounts) into the single
;;; (lambda (req res) ...) handler that (igropyr http)'s http-listen
;;; expects. Alternative frameworks can be built the same way against
;;; the same core.
;;;
;;;   (define app (create-app))
;;;   (app-get app "/users/:id" (lambda (req res) ...))
;;;   (app-use app (lambda (req res next) ...))
;;;   (app-static app "/assets" "./public")
;;;   (start-scheduler (lambda () (app-listen app 8080)))
;;;
;;; Convenience response encoders live here too (the res.json level):
;;; send-text!, send-html!, send-json!, send-file!.

(library (igropyr express)
  (export create-app app-get app-post app-put app-delete app-patch
          app-route-list
          app-use app-static app-ws app-listen app->handler
          req-param req-json req-form req-cookie
          set-cookie! set-cookie-if-unanswered!
          req-sexpr send-sexpr! app-rpc
          ws-send-sexpr! ws-recv-sexpr sse-send-sexpr!
          send-text! send-html! send-json! send-file!
          sse-start! sse-send! make-fault-handler
          static-cache-limits! static-cache-stats)
  (import (chezscheme) (igropyr checked)
          (igropyr actor) (igropyr libuv) (igropyr http)
          (igropyr json) (igropyr gzip) (igropyr sexpr)
          (only (igropyr websocket) ws-recv ws-send-text! ws?))

  ;; ---- string helpers -----------------------------------------------------

  (define (string-split s ch)
    (let ((n (string-length s)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((= i n) (reverse (cons (substring s start n) acc)))
          ((char=? (string-ref s i) ch)
           (loop (+ i 1) (+ i 1) (cons (substring s start i) acc)))
          (else (loop (+ i 1) start acc))))))

  ;; char-wise: no substring allocation on this per-request check
  (define (string-prefix? p s)
    (let ((pl (string-length p)))
      (and (fx>= (string-length s) pl)
           (let loop ((i 0))
             (or (fx= i pl)
                 (and (char=? (string-ref s i) (string-ref p i))
                      (loop (fx+ i 1))))))))

  ;; ---- response encoders (the res.json level) --------------------------------

  ;; compress bodies over this size when the client accepts gzip and the
  ;; content type is worth compressing (already-compressed formats like
  ;; images are skipped)
  (define gzip-min-size 1024)

  (define compressible-prefixes
    '("text/" "application/json" "application/javascript"
      "application/xml" "image/svg+xml"))

  (define (compressible-type? ctype)
    (exists (lambda (p) (string-prefix? p ctype)) compressible-prefixes))

  (define (finish! r ctype body)
    (set-header! r "Content-Type" ctype)
    (let ((ae (req-header (res-req r) 'accept-encoding)))
      (if (and (> (bytevector-length body) gzip-min-size)
               (compressible-type? ctype)
               (gzip-acceptable? ae))
          (let ((gz (gzip-compress body 6)))
            (if gz
                (begin
                  (set-header! r "Content-Encoding" "gzip")
                  (set-header! r "Vary" "Accept-Encoding")
                  (res-send! r gz))
                (res-send! r body)))          ; compression failed: send raw
          (res-send! r body))))

  ;; Every encoder also accepts a bytevector, taken as the body already
  ;; encoded. The fast pattern for constant responses is to do the
  ;; encoding ONCE at startup with define, so the handler just hands the
  ;; framework a pointer:
  ;;   (define home (string->utf8 "<h1>hi</h1>"))
  ;;   (app-get app "/" (lambda (req res) (send-html! res home)))
  (define (as-utf8 s) (if (string? s) (string->utf8 s) s))

  ;; body data accepted by every encoder: a string, or a bytevector
  ;; taken as the body already encoded
  (define (body-data? x) (or (string? x) (bytevector? x)))

  (define-checked (send-text! (r res?) (s body-data?))
    (finish! r "text/plain; charset=utf-8" (as-utf8 s)))
  (define-checked (send-html! (r res?) (s body-data?))
    (finish! r "text/html; charset=utf-8" (as-utf8 s)))
  ;; serialization comes from (igropyr json): alist with string keys ->
  ;; object, vector -> array, 'null -> null. A LIST IS NOT AN ARRAY and a
  ;; symbol is not a string; both are refused, so a handler that used to
  ;; hand over either now raises instead of emitting a document. A
  ;; bytevector is passed through as pre-serialized JSON (define it once
  ;; at startup).
  (define-checked (send-json! (r res?) obj)
    (finish! r "application/json; charset=utf-8"
             (if (bytevector? obj)
                 obj
                 (string->utf8 (json->string obj)))))

  ;; parse a JSON request body; #f when the body is not valid JSON
  (define-checked (req-json (req request?))
    (guard (e (#t #f))
      (string->json (utf8->string (req-body req)))))

  ;; ---- s-expression bodies: Scheme-to-Scheme RPC ---------------------------
  ;; (igropyr sexpr) is the safe parser -- whitelisted data, depth
  ;; limited, never the host reader. Payloads are DATA: dispatch on a
  ;; tag, never evaluate.

  ;; parse an s-expression body; #f when invalid (or over 1 MiB)
  (define-checked (req-sexpr (req request?))
    (guard (e (#t #f))
      (let ((body (req-body req)))
        (and (<= (bytevector-length body) (* 1024 1024))
             (string->sexpr-extended (utf8->string body))))))

  ;; a bytevector is passed through as a pre-serialized datum
  ;; Encode to wire bytes SEPARATELY, so a caller can put the encoding
  ;; inside its own guard: sexpr->string-extended raises on anything the
  ;; wire whitelist refuses, and where that raise lands decides whether a
  ;; request gets replayed.
  (define (encode-sexpr x) (string->utf8 (sexpr->string-extended x)))

  (define-checked (send-sexpr! (r res?) x)
    (finish! r "application/sexpr; charset=utf-8"
             (if (bytevector? x)
                 x
                 (string->utf8 (sexpr->string-extended x)))))

  ;; ---- cookies --------------------------------------------------------------

  (define (string-trim s)
    (let ((n (string-length s)))
      (let ((a (let lp ((i 0)) (if (and (< i n) (char=? (string-ref s i) #\space))
                                   (lp (+ i 1)) i)))
            (b (let lp ((i n)) (if (and (> i 0) (char=? (string-ref s (- i 1)) #\space))
                                   (lp (- i 1)) i))))
        (if (< a b) (substring s a b) ""))))

  (define (string-index s ch)
    (let ((n (string-length s)))
      (let lp ((i 0))
        (cond ((= i n) #f)
              ((char=? (string-ref s i) ch) i)
              (else (lp (+ i 1)))))))

  ;; value of a cookie sent by the client, or #f
  (define-checked (req-cookie (req request?) (name string?))
    (let ((h (req-header req 'cookie)))
      (and h
           (let lp ((parts (string-split h #\;)))
             (cond
               ((null? parts) #f)
               (else
                (let* ((kv (string-trim (car parts)))
                       (eqp (string-index kv #\=)))
                  (if (and eqp (string=? (substring kv 0 eqp) name))
                      (substring kv (+ eqp 1) (string-length kv))
                      (lp (cdr parts))))))))))

  ;; add a Set-Cookie header; extra attribute strings are appended:
  ;;   (set-cookie! res "sid" "abc" "Path=/" "HttpOnly" "Max-Age=3600")
  ;; A cookie value must not be able to introduce ATTRIBUTES. With ';'
  ;; allowed through, a reflected value like "en; Domain=example.com"
  ;; produced a cookie the browser accepts as domain-wide -- a host-only
  ;; session cookie suddenly readable by every subdomain, which is the
  ;; classic cookie-tossing/fixation setup. CR/LF would be dropped later
  ;; by set-header!, but SILENTLY, taking the whole Set-Cookie with it: a
  ;; login would appear to succeed while never setting its cookie. Both
  ;; are refused here, loudly, at the call site that can still do
  ;; something about it. Attributes are the caller's own literals and are
  ;; checked the same way.
  (define (cookie-part-ok? s)
    (let ((n (string-length s)))
      (let loop ((i 0))
        (or (= i n)
            (let ((c (string-ref s i)))
              (and (char>=? c #\space) (char<? c #\delete)
                   (not (char=? c #\;)) (not (char=? c #\,))
                   (loop (+ i 1))))))))

  (define (cookie-header who name value attrs)
    (unless (and (string? name) (cookie-part-ok? name))
      (assertion-violation who "invalid cookie name" name))
    (unless (and (string? value) (cookie-part-ok? value))
      (assertion-violation who
        "cookie value may not contain ';' ',' or control characters" value))
    (for-each
      (lambda (a)
        (unless (and (string? a) (cookie-part-ok? a))
          (assertion-violation who "invalid cookie attribute" a)))
      attrs)
    (apply string-append name "=" value
           (map (lambda (a) (string-append "; " a)) attrs)))

  (define (set-cookie! res name value . attrs)
    (set-header! res "Set-Cookie"
      (cookie-header 'set-cookie! name value attrs)))

  ;; #f when another process has already claimed the response; #t means
  ;; its eventual res response is guaranteed to include this cookie.
  (define (set-cookie-if-unanswered! res name value . attrs)
    (set-header-if-unanswered! res "Set-Cookie"
      (cookie-header 'set-cookie-if-unanswered! name value attrs)))

  ;; ---- form bodies (urlencoded + multipart/form-data) ---------------------------

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  ;; A searcher bound to one needle -> (searcher bv from [end [accept?]]),
  ;; giving the first accepted occurrence at or after `from` and before
  ;; optional `end` (clamped: an end past the buffer would read off it with
  ;; no error). accept? is called with each candidate start.
  ;;
  ;; KMP, because the needle is a MIME boundary and therefore chosen by the
  ;; sender. Restarting at every byte costs a factor of the boundary length
  ;; -- at the 1 MiB body limit a 70-byte all-dash boundary against an
  ;; all-dash body measures ~100 ms versus ~4 ms here, and that is 100 ms
  ;; during which the single-threaded scheduler runs nothing else.
  ;;
  ;; The failure table depends only on the needle, so it is built once and
  ;; captured WITH that needle -- the two cannot drift apart. A rejected
  ;; candidate resumes from its KMP fallback state in the SAME scan. Starting
  ;; a fresh search at candidate+1 would compare the entire needle again for
  ;; every overlapping full match: a 70-dash boundary in an all-dash payload
  ;; is exactly that CPU amplification path.
  (define (make-bv-searcher needle)
    (let ((m (bytevector-length needle))
          (fallback (make-vector (bytevector-length needle) 0)))
      (when (> m 0)
        (let build ((i 1) (j 0))
          (when (< i m)
            (cond
              ((fx= (bytevector-u8-ref needle i)
                    (bytevector-u8-ref needle j))
               (vector-set! fallback i (+ j 1))
               (build (+ i 1) (+ j 1)))
              ((> j 0) (build i (vector-ref fallback (- j 1))))
              (else (build (+ i 1) 0))))))
      (lambda (bv from . rest)
        (let ((n (if (pair? rest)
                     (fxmin (car rest) (bytevector-length bv))
                     (bytevector-length bv)))
              (accept? (if (and (pair? rest) (pair? (cdr rest)))
                           (cadr rest)
                           (lambda (p) #t))))
          (if (= m 0)
              (and (<= from n) (accept? from) from)
              (let scan ((i from) (j 0))
                (cond
                  ((>= i n) #f)
                  ((fx= (bytevector-u8-ref bv i) (bytevector-u8-ref needle j))
                   (if (= (+ j 1) m)
                       (let ((p (- (+ i 1) m)))
                         (if (accept? p)
                             p
                             (scan (+ i 1) (vector-ref fallback (- m 1)))))
                       (scan (+ i 1) (+ j 1))))
                  ((> j 0) (scan i (vector-ref fallback (- j 1))))
                  (else (scan (+ i 1) 0)))))))))

  ;; RFC 2046 bchars, spelled out as ASCII ranges. NOT char-alphabetic? /
  ;; char-numeric?: those are Unicode-aware here, so they admit characters
  ;; the grammar does not (char-alphabetic? #\e-acute and char-numeric? on
  ;; ARABIC-INDIC digits are both true). The boundary is what the delimiter
  ;; bytes are built from, so accepting more than a conforming sender can
  ;; emit is exactly the kind of disagreement the anchoring above closes.
  (define (bchar? c)
    (or (char<=? #\a c #\z) (char<=? #\A c #\Z) (char<=? #\0 c #\9)
        (char=? c #\space)
        (memv c '(#\' #\( #\) #\+ #\_ #\, #\- #\. #\/ #\: #\= #\?))))

  ;; boundary=... from a Content-Type header (possibly quoted)
  (define (valid-boundary? s)
    (and (fx> (string-length s) 0)
         (fx<= (string-length s) 70)
         (not (char=? (string-ref s (- (string-length s) 1)) #\space))
         (let loop ((i 0))
           (or (fx= i (string-length s))
               (and (bchar? (string-ref s i))
                    (loop (fx+ i 1)))))))

  (define (multipart-boundary ct)
    (let ((key "boundary="))
      (let lp ((i 0))
        (cond
          ((> (+ i (string-length key)) (string-length ct)) #f)
          ((string-ci=? (substring ct i (+ i (string-length key))) key)
           (let* ((start (+ i (string-length key)))
                  (b (if (and (< start (string-length ct))
                              (char=? (string-ref ct start) #\"))
                         (let scan ((j (+ start 1)))
                           (cond ((= j (string-length ct)) #f)
                                 ((char=? (string-ref ct j) #\")
                                  (substring ct (+ start 1) j))
                                 (else (scan (+ j 1)))))
                         (let scan ((j start))
                           (if (or (= j (string-length ct))
                                   (memv (string-ref ct j) '(#\; #\space #\tab)))
                               (substring ct start j)
                               (scan (+ j 1)))))))
             (and b (valid-boundary? b) b)))
          (else (lp (+ i 1)))))))

  ;; "form-data; name=\"a\"; filename=\"b\"" -> value of one attribute
  (define (disposition-attr line attr)
    (let ((key (string-append attr "=\"")))
      (let lp ((i 0))
        (cond
          ((> (+ i (string-length key)) (string-length line)) #f)
          ((string=? (substring line i (+ i (string-length key))) key)
           (let ((start (+ i (string-length key))))
             (let scan ((j start))
               (cond ((= j (string-length line)) #f)
                     ((char=? (string-ref line j) #\") (substring line start j))
                     (else (scan (+ j 1)))))))
          (else (lp (+ i 1)))))))

  ;; the header/body separator never varies, so its table is built once for
  ;; the life of the module rather than once per part
  (define search-crlf2 (make-bv-searcher (string->utf8 "\r\n\r\n")))

  ;; parse one multipart part: header block + payload
  ;; -> (name . string-value) or (name . #(file filename content-type bytes))
  (define (parse-part bv start end)
    (let ((hend (search-crlf2 bv start end)))
      (and hend (<= (+ hend 4) end)
           (let* ((head (utf8->string (bv-sub bv start hend)))
                  (data (bv-sub bv (+ hend 4) end))
                  (disp (let lp ((lines (string-split head #\newline)))
                          (cond
                            ((null? lines) "")
                            ((let ((l (car lines)))
                               (and (>= (string-length l) 20)
                                    (string-ci=? (substring l 0 20)
                                                 "content-disposition:")))
                             (car lines))
                            (else (lp (cdr lines))))))
                  (name (disposition-attr disp "name"))
                  (filename (disposition-attr disp "filename"))
                  (ctype (let lp ((lines (string-split head #\newline)))
                           (cond
                             ((null? lines) "application/octet-stream")
                             ((let ((l (car lines)))
                                (and (>= (string-length l) 13)
                                     (string-ci=? (substring l 0 13)
                                                  "content-type:")))
                              (string-trim
                                (let ((l (car lines)))
                                  (let ((s (substring l 13 (string-length l))))
                                    (if (and (> (string-length s) 0)
                                             (char=? (string-ref s (- (string-length s) 1))
                                                     #\return))
                                        (substring s 0 (- (string-length s) 1))
                                        s)))))
                             (else (lp (cdr lines)))))))
             (and name
                  (cons name
                        (if filename
                            (vector 'file filename ctype data)
                            (utf8->string data))))))))

  ;; A MIME delimiter is recognized only at the beginning of a line and
  ;; only when followed by CRLF or the final "--" suffix. Raw substring
  ;; matches inside uploaded bytes are ordinary file data.
  (define (bv-search-delimiter bv delim search from)
    (let ((n (bytevector-length bv)) (m (bytevector-length delim)))
      (search bv from n
        (lambda (p)
          (let ((after (+ p m)))
            (and (or (= p 0)
                     (and (>= p 2)
                          (= (bytevector-u8-ref bv (- p 2)) 13)
                          (= (bytevector-u8-ref bv (- p 1)) 10)))
                 (<= (+ after 2) n)
                 (or (and (= (bytevector-u8-ref bv after) 13)
                          (= (bytevector-u8-ref bv (+ after 1)) 10))
                     (and (= (bytevector-u8-ref bv after) 45)
                          (= (bytevector-u8-ref bv (+ after 1)) 45)
                          (or (= (+ after 2) n)
                              (and (<= (+ after 4) n)
                                   (= (bytevector-u8-ref bv (+ after 2)) 13)
                                   (= (bytevector-u8-ref bv (+ after 3)) 10)))))))))))

  (define (parse-multipart bv boundary)
    (let* ((delim (string->utf8 (string-append "--" boundary)))
           (search (make-bv-searcher delim)))
      (let lp ((pos (or (bv-search-delimiter bv delim search 0)
                        (bytevector-length bv)))
               (acc '()))
        (let ((part-start (+ pos (bytevector-length delim) 2))) ; skip \r\n
          (if (or (> part-start (bytevector-length bv))
                  ;; "--" right after the delimiter: final boundary
                  (and (<= (+ pos (bytevector-length delim) 2) (bytevector-length bv))
                       (fx= (bytevector-u8-ref bv (+ pos (bytevector-length delim))) 45)
                       (fx= (bytevector-u8-ref bv (+ pos (bytevector-length delim) 1)) 45)))
              (reverse acc)
              (let ((next (bv-search-delimiter bv delim search part-start)))
                (if (not next)
                    (reverse acc)
                    (let ((part (parse-part bv part-start (- next 2)))) ; strip \r\n
                      (lp next (if part (cons part acc) acc))))))))))

  ;; Parse a form body. urlencoded -> alist of strings; multipart ->
  ;; alist where text fields are strings and uploads are
  ;; #(file ,filename ,content-type ,bytevector). '() otherwise.
  (define-checked (req-form (req request?))
    (let ((ct (or (req-header req 'content-type) "")))
      (cond
        ((and (>= (string-length ct) 33)
              (string-ci=? (substring ct 0 33)
                           "application/x-www-form-urlencoded"))
         (parse-query (utf8->string (req-body req))))
        ((and (>= (string-length ct) 19)
              (string-ci=? (substring ct 0 19) "multipart/form-data"))
         (let ((b (multipart-boundary ct)))
           (if b (parse-multipart (req-body req) b) '())))
        (else '()))))

  ;; ---- Server-Sent Events -------------------------------------------------
  ;; Detach long streams from the pool worker:
  ;;   (sse-start! res)
  ;;   (spawn (lambda () ... (sse-send! res data) ... (res-end! res)))

  (define-checked (sse-start! (res res?))
    (set-header! res "Content-Type" "text/event-stream")
    (set-header! res "Cache-Control" "no-cache")
    (res-begin! res))

  ;; SSE breaks lines on CRLF, LF *or* a bare CR (the event stream format),
  ;; so all three have to become separate data: lines. Splitting on LF alone
  ;; would leave a bare CR inside a line, where the client still treats it as
  ;; a break -- and the text after it as a new FIELD.
  (define (sse-data-lines text)
    (let ((out '()) (cur '()) (n (string-length text)))
      (let loop ((i 0))
        (if (fx= i n)
            (begin (set! out (cons (list->string (reverse cur)) out))
                   (reverse out))
            (let ((ch (string-ref text i)))
              (cond
                ((char=? ch #\return)
                 (set! out (cons (list->string (reverse cur)) out))
                 (set! cur '())
                 ;; CRLF is one break, not two
                 (loop (if (and (fx< (fx+ i 1) n)
                                (char=? (string-ref text (fx+ i 1)) #\newline))
                           (fx+ i 2)
                           (fx+ i 1))))
                ((char=? ch #\newline)
                 (set! out (cons (list->string (reverse cur)) out))
                 (set! cur '())
                 (loop (fx+ i 1)))
                (else (set! cur (cons ch cur)) (loop (fx+ i 1)))))))))

  ;; returns #f when the client is gone -- stop the producer loop then
  ;;
  ;; Every line gets its own "data:" prefix, and EventSource rejoins them
  ;; with \n, so the string arrives intact. Concatenating the raw string
  ;; instead let any newline in it start a new FIELD: application data
  ;; containing "\nevent: x" changed the event type the browser dispatched
  ;; on, and "\n\n" ended the event early and began another. Anything that
  ;; streams user-supplied text -- chat, log lines, model output -- handed
  ;; the writer of that text control of the protocol.
  ;;
  ;; sse-send-sexpr! below already did this, for exactly this reason.
  (define-checked (sse-send! (res res?) (data string?))
    (res-write! res
      (string-append
        (apply string-append
               (map (lambda (l) (string-append "data: " l "\n"))
                    (sse-data-lines data)))
        "\n")))

  ;; ---- pool failure hook template -----------------------------------------------
  ;; Ready-made on-failure handler for app-listen's pool options. When the
  ;; pool gives up on a request (crash retries exhausted, or a stuck
  ;; worker killed -- killed first, so no execution is in flight), it
  ;; replies a small JSON envelope instead of the plain 500:
  ;;   {"fault":"crash"|"stuck", "attempts":n, "elapsed-ms":t, "retryable":true}
  ;; The connection stays open (keep-alive), so the client can resubmit
  ;; -- changed parameters, carried state -- on the same connection and
  ;; get a fresh retry round. Optional argument overrides the HTTP status
  ;; (default 503). For custom envelopes write your own
  ;; (lambda (req res info) ...) instead.
  ;;   (app-listen app 8080 `((stuck-ms . 3000) (check-ms . 1000)
  ;;                          (on-failure . ,(make-fault-handler))))
  (define (make-fault-handler . rest)
    (let ((status (if (pair? rest) (car rest) 503)))
      (lambda (req res info)
        (define (ref k d)
          (let ((p (assq k info))) (if p (cdr p) d)))
        (set-status! res status)
        (send-json! res
          (list (cons "fault" (symbol->string (ref 'kind 'crash)))
                (cons "attempts" (ref 'attempts 1))
                (cons "elapsed-ms" (ref 'elapsed-ms 0))
                (cons "retryable" #t))))))

  ;; ---- static files -----------------------------------------------------------

  (define (mime-type path)
    (let* ((dot (let scan ((i (- (string-length path) 1)))
                  (cond ((< i 0) #f)
                        ((char=? (string-ref path i) #\.) i)
                        (else (scan (- i 1))))))
           (ext (and dot (string-downcase
                           (substring path (+ dot 1) (string-length path))))))
      (cond
        ((equal? ext "html") "text/html; charset=utf-8")
        ((equal? ext "css") "text/css")
        ((equal? ext "js") "application/javascript")
        ((equal? ext "json") "application/json")
        ((equal? ext "txt") "text/plain; charset=utf-8")
        ((equal? ext "png") "image/png")
        ((equal? ext "jpg") "image/jpeg")
        ((equal? ext "jpeg") "image/jpeg")
        ((equal? ext "gif") "image/gif")
        ((equal? ext "svg") "image/svg+xml")
        ((equal? ext "ico") "image/x-icon")
        (else "application/octet-stream"))))

  (define (path-has-dotdot? s)
    (exists (lambda (p) (string=? p "..")) (string-split s #\/)))

  ;; a NUL byte can truncate a path in a lower-level file API, slipping
  ;; past an extension/suffix check (e.g. "safe.txt\x0;.jpg")
  (define (path-has-nul? s)
    (let loop ((i 0))
      (and (< i (string-length s))
           (or (fx= (char->integer (string-ref s i)) 0)
               (loop (+ i 1))))))

  ;; ---- static file cache -----------------------------------------------------
  ;;
  ;; Files are read once and kept in memory keyed by path; a request
  ;; re-reads only when the file's mtime has changed. This turns the
  ;; common case (serving an unchanged index.html / css / js) from a
  ;; blocking disk read + fresh allocation into a hashtable lookup, and
  ;; supplies a weak ETag for conditional requests (304 Not Modified).
  ;; Files larger than max-cache-file are served but not cached.

  (define max-cache-file (* 1024 1024))   ; 1 MiB per-file cache cap
  ;; A cached file's mtime is re-checked at most once per this many ms
  ;; (nginx open_file_cache_valid works the same way, default 60s there).
  ;; Within the window a hit costs a hashtable lookup and NO syscalls --
  ;; the stat pair (exists? + mtime) dominated cached static serving.
  (define stat-window-ms 1000)
  ;; canonical-path ->
  ;;   #(mtime size etag content-type body gzip-box last-stat-ms
  ;;     canonical-path hot-path)
  (define static-cache (make-hashtable string-hash string=?))
  ;; Keep exactly one request spelling hot for each canonical entry. This
  ;; preserves the no-syscall hit path for relative roots without letting
  ;; case/symlink aliases multiply full cache entries.
  (define static-cache-hot (make-hashtable string-hash string=?))
  ;; Ceilings on what the cache may hold. Generous by default -- a bound
  ;; on growth, not a working-set policy; over either one the cache is
  ;; cleared rather than evicted from, which is why they are set high
  ;; enough that ordinary serving never reaches them.
  (define max-static-cache-entries 4096)
  (define max-static-cache-bytes (* 64 1024 1024))
  (define static-cache-bytes 0)

  ;; Lower them for a memory-tight deployment, raise them for a host
  ;; serving a large asset set. #f leaves either alone. Takes effect on
  ;; the next store; lowering below what is already held simply means the
  ;; next one clears. Reaching a ceiling is also the only way to observe
  ;; this behaviour, so a test can ask for numbers it can actually fill
  ;; instead of writing 64 MiB to prove it.
  (define (static-cache-limits! entries bytes)
    (define (check-cap who cap)
      (unless (and (integer? cap) (exact? cap) (> cap 0))
        (assertion-violation 'static-cache-limits!
          (string-append who " cap must be a positive integer") cap)))
    (when entries
      (check-cap "entry" entries)
      (set! max-static-cache-entries entries))
    (when bytes
      (check-cap "byte" bytes)
      (set! max-static-cache-bytes bytes))
    (void))

  (define (entry-bytes e)
    (if (and e (bytevector? (vector-ref e 4)))
        (+ (bytevector-length (vector-ref e 4))
           (let ((g (unbox (vector-ref e 5))))
             (if g (bytevector-length g) 0)))
        0))

  (define (cache-store! path e)
    (with-interrupts-disabled
      (let ((old (hashtable-ref static-cache path #f)))
        (when old
          (set! static-cache-bytes (- static-cache-bytes (entry-bytes old)))
          (let ((hot (vector-ref old 8)))
            (when (eq? (hashtable-ref static-cache-hot hot #f) old)
              (hashtable-delete! static-cache-hot hot)))
          ;; delete rather than rely on the overwrite below: the oversize
          ;; branch no longer inserts, and a stale entry whose bytes were
          ;; just discharged must not keep serving
          (hashtable-delete! static-cache path))
        (let ((n (entry-bytes e)))
          ;; A runtime limit reduction takes effect on this store even when
          ;; the incoming entry itself cannot fit and will be skipped below.
          ;; Otherwise an already-over-budget cache could survive forever on
          ;; a workload made entirely of oversized misses.
          (when (or (> (hashtable-size static-cache)
                       max-static-cache-entries)
                    (> static-cache-bytes max-static-cache-bytes))
            (hashtable-clear! static-cache)
            (hashtable-clear! static-cache-hot)
            (set! static-cache-bytes 0))
          ;; Clearing cannot make an entry that is larger than the entire
          ;; byte budget fit. Serve it once, but do not let that single item
          ;; leave the supposedly hard ceiling exceeded.
          (unless (> n max-static-cache-bytes)
            (when (or (fx>= (hashtable-size static-cache)
                            max-static-cache-entries)
                      (> (+ static-cache-bytes n) max-static-cache-bytes))
              (hashtable-clear! static-cache)
              (hashtable-clear! static-cache-hot)
              (set! static-cache-bytes 0))
            (hashtable-set! static-cache path e)
            (hashtable-set! static-cache-hot (vector-ref e 8) e)
            (set! static-cache-bytes (+ static-cache-bytes n)))))))

  ;; What the cache is holding. Exported for the same reason as the node
  ;; monitor tables: the byte total is the thing that silently goes wrong --
  ;; an entry removed without discharging its bytes leaves the counter high
  ;; forever, and the only symptom is a cache that starts clearing itself on
  ;; every store. Nothing outside can see that, including a test.
  (define (static-cache-stats)
    (with-interrupts-disabled
      (list (cons 'entries (hashtable-size static-cache))
            (cons 'hot (hashtable-size static-cache-hot))
            (cons 'bytes static-cache-bytes))))

  ;; Undo exactly what cache-store! did for one entry: both tables and the
  ;; byte counter.
  ;;
  ;; A bare hashtable-delete! is not enough, and fails in two ways that are
  ;; both invisible. It would delete by the REQUEST path while the entry is
  ;; filed under the name the OS resolved -- those differ for every relative
  ;; root, and on macOS for anything under /tmp, which is a symlink -- so
  ;; usually nothing would be removed at all. And it would leave the bytes
  ;; charged: the counter only ever drops here or in cache-store!'s replace
  ;; path, so a root that sees churn drifts upward until it is permanently
  ;; over the ceiling, at which point every store clears the whole cache and
  ;; the hit rate goes to zero -- worse than the stale entry being evicted.
  ;;
  ;; The eq? guards are cache-store!'s: never remove a mapping that now
  ;; points at a different, live entry.
  (define (cache-evict! e)
    (with-interrupts-disabled
      (let ((canonical (vector-ref e 7)))
        (when (eq? (hashtable-ref static-cache canonical #f) e)
          (hashtable-delete! static-cache canonical)
          (set! static-cache-bytes (- static-cache-bytes (entry-bytes e)))))
      (let ((hot (vector-ref e 8)))
        (when (eq? (hashtable-ref static-cache-hot hot #f) e)
          (hashtable-delete! static-cache-hot hot)))))

  ;; Cache a lazily generated representation only while the aggregate byte
  ;; budget has room. The caller may still serve g once when it does not.
  (define (cache-gzip! path e g)
    (with-interrupts-disabled
      (when (and (eq? (hashtable-ref static-cache path #f) e)
                 (not (unbox (vector-ref e 5)))
                 (<= (+ static-cache-bytes (bytevector-length g))
                     max-static-cache-bytes))
        (set-box! (vector-ref e 5) g)
        (set! static-cache-bytes
          (+ static-cache-bytes (bytevector-length g)))))
    g)

  (define (file-mtime path)
    (guard (e (#t #f))
      (and (file-exists? path)
           (time-second (file-modification-time path)))))

  (define (etag-of size mtime)
    (string-append "W/\"" (number->string size 16) "-"
                   (number->string mtime 16) "\""))

  (define (bv-concat lst total)
    (let ((out (make-bytevector total)))
      (let loop ((l lst) (off 0))
        (if (null? l)
            out
            (let ((x (car l)))
              (bytevector-copy! x 0 out off (bytevector-length x))
              (loop (cdr l) (+ off (bytevector-length x))))))))

  ;; pull a whole (small) stream into one bytevector; #f on error/short
  (define (stream-read-all st size)
    (let loop ((chunks '()) (got 0))
      (file-stream-read! st)
      (receive (after 30000 (begin (file-stream-close! st) #f))
        (`#(file-chunk ,bv) (loop (cons bv chunks) (+ got (bytevector-length bv))))
        (`#(file-eof) (and (= got size) (bv-concat (reverse chunks) got)))
        (`#(file-error ,e) #f))))

  ;; return the cache entry for path (reading/refreshing as needed), or #f.
  ;; Within stat-window-ms of the last check the entry is trusted as-is;
  ;; past it the mtime is re-checked (and the window restamped), and the
  ;; file re-read only when the mtime actually changed.
  ;;
  ;; A cache miss opens the file as a stream so the size is known (from
  ;; fstat) BEFORE any bytes are read. A small file is pulled whole,
  ;; cached, and served from memory as before. A large one is cached as
  ;; METADATA only (body slot = 'large): within the stat window a
  ;; conditional request answers 304 with zero file operations, and a
  ;; download opens a fresh stream on demand -- the miss itself returns
  ;; a live one-shot #(stream handle size etag ctype) descriptor, which
  ;; the caller must either pump (stream-file!) or close.
  (define (stream-entry? e) (eq? (vector-ref e 0) 'stream))
  (define (large-entry? e) (eq? (vector-ref e 4) 'large))

  ;; ONE FILE, ONE ENTRY. The key is the name the OS resolves to, not the
  ;; one the client typed. On a case-insensitive filesystem -- macOS and
  ;; Windows by default -- every spelling of a name opens the same file,
  ;; so keying on the request path let a single asset occupy 2^letters
  ;; entries: unbounded memory from one file, and, once the capacity
  ;; ceilings existed, a way to wipe the whole cache with a few dozen
  ;; requests. Symlink aliases would collapse for the same reason, except
  ;; the confined open refuses them before an entry can exist at all.
  ;;
  ;; Resolving costs a blocking syscall, so it happens only when the typed
  ;; path is not already a key -- a client using the spelling its links
  ;; contain still reaches the body with no syscall at all, which is the
  ;; property the hot path is built around. Entries therefore only ever
  ;; exist under resolved names, and a request for a variant looks itself
  ;; up rather than storing a second copy.
  (define (static-entry path root rel)
    (let ((cached (or (hashtable-ref static-cache-hot path #f)
                      (hashtable-ref static-cache path #f)))
          (now (now-ms)))
      (if (and cached (< (- now (vector-ref cached 6)) stat-window-ms))
          cached
          (let ((mt (file-mtime path)))
            (if (not mt)
                (begin (when cached (cache-evict! cached)) #f)
                (if (and cached (= (vector-ref cached 0) mt))
                    (begin (vector-set! cached 6 now) cached)
                    (let ((key (or (file-realpath path) path)))
                      (let ((e (and (not (string=? key path))
                                    (hashtable-ref static-cache key #f))))
                        (if (and e (= (vector-ref e 0) mt))
                            (begin (vector-set! e 6 now) e)
                            (let ((fresh (open-entry key path mt now root rel)))
                              (unless fresh
                                (let ((stale (or e cached)))
                                  (when stale (cache-evict! stale))))
                              fresh))))))))))

  ;; open with a timeout that can never leak the fd: the handle comes
  ;; back synchronously, so a timed-out open is closed via its handle
  ;; (the abort flag also suppresses any late ready message).
  ;; -> (values stream size) | (values #f #f)
  (define (open-stream path root rel)
    (let ((st (if root
                  (file-stream-open-under! root rel self)
                  (file-stream-open! path self))))
      (if (not st)
          (values #f #f)
          (receive (after 30000 (begin (file-stream-close! st) (values #f #f)))
            (`#(file-stream ,@st ,size) (values st size))
            (`#(file-error ,e) (values #f #f))))))

  ;; `key' is the resolved name from static-entry: what the entry is filed
  ;; under and what the content type is taken from. The OPEN still goes
  ;; through the confined walk when there is a root -- resolving a name is
  ;; not permission to open it. `hot-path' is the spelling the client sent,
  ;; kept as that entry's no-syscall lookup key.
  (define (open-entry key hot-path mt now root rel)
    (let-values (((st size) (open-stream key root rel)))
      (and st
           (if (<= size max-cache-file)
               (let ((body (stream-read-all st size)))
                 (and body
                      ;; gzip-box holds the lazily-built gzip body
                       (let ((e (vector mt size (etag-of size mt)
                                        (mime-type key) body (box #f) now
                                        key hot-path)))
                         (cache-store! key e)
                         e)))
               (let ((etag (etag-of size mt)) (ctype (mime-type key)))
                 (cache-store! key
                   (vector mt size etag ctype 'large #f now key hot-path))
                 (vector 'stream st size etag ctype))))))

  ;; Pump a large file through a fixed-length response from a detached
  ;; process: the pool worker is released immediately, and each chunk
  ;; is read only after the previous one drained to the client
  ;; (res-write-chunk! waits) -- constant memory however slow the peer.
  ;; The stream runs raw: chunks go C buffer -> socket without touching
  ;; the Scheme heap, so a gigabyte download causes no GC traffic.
  (define (stream-file! r st size ctype)
    (set-header! r "Content-Type" ctype)
    (if (res-head-request? r)
        ;; HEAD: same headers a GET would send, including the real length,
        ;; but the bytes must never leave (and need not even be read)
        (begin (file-stream-close! st) (res-send-head! r size))
        (begin
    (res-begin-file! r size)
    (spawn
      (lambda ()
        (file-stream-own! st self)
        (file-stream-raw! st)
        (let loop ()
          (file-stream-read! st)
          (receive (after 30000 (res-abort-file! r))
            (`#(file-chunk ,len)
              (case (res-write-chunk! r st len)
                ((more) (loop))
                ((done) (void))
                (else (res-abort-file! r))))
            ;; eof before the promised length: file shrank underneath us
            (`#(file-eof) (res-abort-file! r))
            (`#(file-error ,e) (res-abort-file! r))))
        (file-stream-close! st))))))

  ;; window-hit download of a large (metadata-cached) file: open a
  ;; fresh stream on demand. Content-Length comes from the live fstat;
  ;; etag/ctype from the metadata (<= 1s stale, like every window hit).
  (define (serve-large! r ctype path root rel)
    (let-values (((st size) (open-stream path root rel)))
      (if st
          (stream-file! r st size ctype)
          (begin (set-status! r 404) (send-text! r "Not Found")))))

  ;; Public helper: send a file (cached read; no conditional request since
  ;; there is no req here). Files over the cache cap are streamed with
  ;; backpressure, not buffered.
  ;;
  ;;   (send-file! res "./data/report.pdf")        ; path used as given
  ;;   (send-file! res user-supplied "./data")     ; RESOLVED INSIDE ./data
  ;;
  ;; With a root, `path` is treated as a relative path inside it and gets
  ;; the full app-static treatment: no "..", no NUL, no dotfiles, and no
  ;; segment that is a symlink (so an uploaded link cannot point out of
  ;; the root). PASS THE ROOT whenever any part of the path comes from the
  ;; request -- without one this cannot tell an intended prefix from a
  ;; traversal, and an absolute path is sent as-is.
  ;;
  ;; Even rootless, a NUL is refused: file APIs below truncate at it, so
  ;; "secret.db\x0;.png" would pass an extension check in the caller and
  ;; then open secret.db.
  (define (send-file*! r path root)
    (let ((resolved
           (cond
             (root (safe-static-path root path))
             ((or (path-has-dotdot? path) (path-has-nul? path)) #f)
             (else path))))
      (if (not resolved)
          (begin (set-status! r 403) (send-text! r "Forbidden"))
          (let ((e (static-entry resolved root (and root path))))
            (cond
              ((not e) (set-status! r 404) (send-text! r "Not Found"))
              ((stream-entry? e)
               (stream-file! r (vector-ref e 1) (vector-ref e 2) (vector-ref e 4)))
              ((large-entry? e)
               (serve-large! r (vector-ref e 3) resolved root (and root path)))
              (else (finish! r (vector-ref e 3) (vector-ref e 4))))))))

  (define (send-file! r path . rest)
    (unless (res? r)
      (assertion-violation 'send-file! "not a response" r))
    (unless (string? path)
      (assertion-violation 'send-file! "path must be a string" path))
    (let ((root (and (pair? rest) (car rest))))
      (when (and root (not (string? root)))
        (assertion-violation 'send-file! "root must be a string" root))
      (send-file*! r path root)))

  ;; Serve a static file with caching + conditional request. abs-path is
  ;; already inside the mount root; caller has done the boundary check.
  ;; gzip ETag differs from the plain one so a client cannot confuse the
  ;; two representations: W/"..." -> W/"...-gz"
  (define (gzip-etag etag)
    (string-append (substring etag 0 (- (string-length etag) 1)) "-gz\""))

  (define (serve-static! r req abs-path root rel)
    (if (path-has-dotdot? abs-path)
        (begin (set-status! r 403) (send-text! r "Forbidden"))
        (let ((e (static-entry abs-path root rel)))
          (cond
            ((not e)
             (set-status! r 404) (send-text! r "Not Found"))
            ((stream-entry? e)
             ;; large file, first request (cache miss): the stream is
             ;; already open. Conditional requests answer from the etag;
             ;; otherwise pump it (no gzip -- the body is never held in
             ;; memory to compress).
             (let ((st (vector-ref e 1)) (size (vector-ref e 2))
                   (etag (vector-ref e 3)) (ctype (vector-ref e 4)))
               (set-header! r "ETag" etag)
               (set-header! r "Cache-Control" "public, max-age=3600")
               (if (equal? (req-header req 'if-none-match) etag)
                   (begin
                     (file-stream-close! st)
                     (set-status! r 304)
                     (res-send! r (make-bytevector 0)))
                   (stream-file! r st size ctype))))
            ((large-entry? e)
             ;; large file, window hit: everything needed for a 304 is
             ;; in the metadata -- a revalidation costs NO file
             ;; operations at all; only a download opens the file
             (let ((etag (vector-ref e 2)) (ctype (vector-ref e 3)))
               (set-header! r "ETag" etag)
               (set-header! r "Cache-Control" "public, max-age=3600")
               (if (equal? (req-header req 'if-none-match) etag)
                   (begin
                     (set-status! r 304)
                     (res-send! r (make-bytevector 0)))
                   (serve-large! r ctype abs-path root rel))))
            (else
             (let* ((size (vector-ref e 1))
                     (etag (vector-ref e 2))
                     (ctype (vector-ref e 3))
                     (body (vector-ref e 4))
                     (gzbox (vector-ref e 5))
                     ;; use gzip when the client accepts it and it's worth it
                     (gz (and (> size gzip-min-size)
                              (compressible-type? ctype)
                              (gzip-acceptable? (req-header req 'accept-encoding))
                              (or (unbox gzbox)
                                  ;; keyed by the requested name, so this
                                  ;; caches for the spelling links use and
                                  ;; merely serves for any other -- which
                                  ;; also keeps a variant from spending the
                                  ;; byte budget on a duplicate gzip
                                  (let ((g (gzip-compress body 6)))
                                    (and g
                                         (cache-gzip! (vector-ref e 7) e g))))))
                     (tag (if gz (gzip-etag etag) etag)))
                (set-header! r "ETag" tag)
                (set-header! r "Cache-Control" "public, max-age=3600")
                (when gz (set-header! r "Vary" "Accept-Encoding"))
                (cond
                  ((equal? (req-header req 'if-none-match) tag)
                   (set-status! r 304) (res-send! r (make-bytevector 0)))
                  (gz
                   (set-header! r "Content-Encoding" "gzip")
                   (set-header! r "Content-Type" ctype)
                   (res-send! r gz))
                  (else
                   (set-header! r "Content-Type" ctype)
                   (res-send! r body)))))))))

  ;; ---- router -------------------------------------------------------------------

  ;; "/users/:id" -> ("users" ":id"); "/" -> (). One pass, empty
  ;; segments skipped during the split rather than filtered after.
  (define (split-segments path)
    (let ((n (string-length path)))
      (let loop ((i 0) (start 0) (acc '()))
        (cond
          ((fx= i n)
           (reverse (if (fx> i start) (cons (substring path start i) acc) acc)))
          ((char=? (string-ref path i) #\/)
           (loop (fx+ i 1) (fx+ i 1)
                 (if (fx> i start) (cons (substring path start i) acc) acc)))
          (else (loop (fx+ i 1) start acc))))))

  ;; match pattern segments against path segments; alist of params or #f
  ;; ":name" captures one segment; a trailing "*" (Express splat) captures all
  ;; remaining segments joined with "/" under the param name "0". A
  ;; non-trailing "*" never reaches here: registration rejects it
  ;; (check-splat!), so the swallow-everything arm is safe.
  ;; index of the first #\: in s, or #f
  (define (seg-colon-index s)
    (let ((n (string-length s)))
      (let lp ((i 0)) (cond ((fx= i n) #f) ((char=? (string-ref s i) #\:) i) (else (lp (fx+ i 1)))))))

  (define (match-segments psegs segs)
    (let loop ((ps psegs) (ss segs) (params '()))
      (cond
        ((and (null? ps) (null? ss)) params)
        ((and (pair? ps) (string=? (car ps) "*"))
         (cons (cons "0"
                     (let join ((l ss) (acc ""))
                       (cond ((null? l) acc)
                             ((string=? acc "") (join (cdr l) (car l)))
                             (else (join (cdr l) (string-append acc "/" (car l)))))))
               params))
        ((or (null? ps) (null? ss)) #f)
        ((and (> (string-length (car ps)) 0)
              (char=? (string-ref (car ps) 0) #\:))
         (loop (cdr ps) (cdr ss)
               (cons (cons (substring (car ps) 1 (string-length (car ps)))
                           (car ss))
                     params)))
        ;; literal-prefix param (express syntax, e.g. "@:username"): the URL
        ;; segment must start with the literal prefix, the rest is the param.
        ((let ((ci (seg-colon-index (car ps)))) (and ci (fx> ci 0)))
         (let* ((p (car ps)) (ci (seg-colon-index p))
                (prefix (substring p 0 ci)) (name (substring p (fx+ ci 1) (string-length p)))
                (seg (car ss)) (pl (string-length prefix)))
           (if (and (fx> (string-length seg) pl) (string=? (substring seg 0 pl) prefix))
               (loop (cdr ps) (cdr ss) (cons (cons name (substring seg pl (string-length seg))) params))
               #f)))
        ((string=? (car ps) (car ss))
         (loop (cdr ps) (cdr ss) params))
        (else #f))))

  ;; router params are stored in the core request's layer-owned slot
  (define-checked (req-param (req request?) (name string?))
    (let ((p (assoc name (req-params req))))
      (and p (cdr p))))

  ;; ---- app ------------------------------------------------------------------------

  ;; routes: list of #(method segs handler); mw-chain: the middleware
  ;; list composed into one callable, rebuilt by app-use -- so a request
  ;; pays no fold/list walk; statics: list of (prefix . root);
  ;; ws-routes: list of #(segs session guard-or-#f)
  (define-checked-record app
    (mutable routes list?)
    (mutable middlewares list?)
    (mutable mw-chain procedure?)
    (mutable statics list?)
    (mutable ws-routes list?))

  ;; chain shape: (lambda (req r tail) ...); tail runs the router
  (define empty-chain (lambda (req r tail) (tail)))

  (define (compose-chain mws)
    (fold-right
      (lambda (mw rest)
        (lambda (req r tail) (mw req r (lambda () (rest req r tail)))))
      empty-chain
      mws))

  (define-checked (create-app) (make-app '() '() empty-chain '() '()))

  ;; Registering a route that already exists (same method + pattern)
  ;; REPLACES it -- this is what makes hot reloading work: re-evaluating
  ;; a routes file against a live app swaps the handlers in place.
  ;; A splat '*' is only meaningful as the LAST pattern segment --
  ;; anywhere else it swallows the rest of the path and the segments
  ;; after it silently never match. That is a route-table typo, so it
  ;; fails HERE, at registration, not as a mystery 200 in production.
  (define (check-splat! who pattern segs)
    (let loop ((ss segs))
      (when (pair? ss)
        (when (and (string=? (car ss) "*") (pair? (cdr ss)))
          (assertion-violation who
            "splat '*' must be the last pattern segment" pattern))
        (loop (cdr ss)))))

  ;; A ':' in a segment starts a param (":name" or "prefix:name"). The name
  ;; (everything after the first ':') must be a non-empty identifier with no
  ;; further ':' -- otherwise "/@:" registers an empty-named capture and
  ;; "/@:a:b" folds the second colon into the name, both silent mystery-misses
  ;; that req-param can never read. Reject them HERE, like check-splat!.
  (define (check-params! who pattern segs)
    (for-each
      (lambda (seg)
        (let ((ci (seg-colon-index seg)))
          (when ci
            (let ((name (substring seg (fx+ ci 1) (string-length seg))))
              (when (fx= (string-length name) 0)
                (assertion-violation who
                  "route param name is empty (segment ends with ':')" pattern))
              (when (seg-colon-index name)
                (assertion-violation who
                  "route segment has more than one ':' (one param per segment)"
                  pattern))))))
      segs))

  ;; REPLACING A HANDLER MUST NOT MOVE ITS ROUTE. Dispatch is
  ;; first-match-wins down this list in order, so a route's position IS
  ;; its priority -- and re-registering used to drop the old entry and
  ;; append the new one, which moved it to the end.
  ;;
  ;; That turned a hot swap of one handler into a change of routing.
  ;; Register "/u/me" and then "/u/:id", and "/u/me" wins as intended;
  ;; replace the handler for "/u/me" on a live server and it lands
  ;; AFTER the wildcard, so the new handler is unreachable and every
  ;; request for it silently goes to "/u/:id" instead. No exception, no
  ;; log, and the order was correct until the moment somebody replaced
  ;; something. Overlapping pairs like this are ordinary --
  ;; /users/me against /users/:id, /api/health against /api/:resource.
  ;;
  ;; So a matching (method, segments) has its handler swapped where it
  ;; already sits, and only a genuinely new route is appended. The
  ;; contract that registration order decides priority is unchanged for
  ;; new routes; what is withdrawn is an undocumented side effect of
  ;; re-registration that nobody could have wanted -- lowering a route's
  ;; priority is done by ordering the registrations, not by registering
  ;; twice.
  (define (add-route! a method pattern handler)
    (let ((segs (split-segments pattern)))
      (check-splat! 'add-route! pattern segs)
      (check-params! 'add-route! pattern segs)
      (let* ((same? (lambda (r)
                      (and (eq? (vector-ref r 0) method)
                           (equal? (vector-ref r 1) segs))))
             (replaced #f)
             (kept (map (lambda (r)
                          (if (same? r)
                              (begin (set! replaced #t)
                                     (vector method segs handler))
                              r))
                        (app-routes a))))
        (app-routes-set! a
          (if replaced
              kept
              (append kept (list (vector method segs handler))))))))

  ;; A READ-ONLY PROJECTION, NOT THE TABLE. What an app holds is a list
  ;; of #(method segments handler) with the segments already split the
  ;; way the router wants them; handing that out would make the router's
  ;; internal shape a public contract, and the next change to matching
  ;; would break whoever read it.
  ;;
  ;; This answers the question a caller actually has -- "what did this
  ;; app end up with registered?" -- which is otherwise reachable only by
  ;; scanning the source, a textual proxy for a semantic property.
  ;;
  ;; THE PATTERN IS REBUILT, NOT REMEMBERED. The original string is not
  ;; kept, so this reconstructs a canonical form from the segments: it is
  ;; not guaranteed to equal the literal that was registered. "/a/b/",
  ;; "/a//b" and "/a/b" all register the same route and all read back as
  ;; "/a/b"; the root reads back as "/". Parameter and splat segments
  ;; come back as written (":id", "*").
  ;;
  ;; Order is registration order, and it is also dispatch priority:
  ;; first match wins. Replacing a handler keeps its route where it was,
  ;; precisely because moving it would be changing the routing rather
  ;; than the handler (see add-route!).
  ;;
  ;; Nothing is shared with the app: the list, the pairs and the strings
  ;; are all fresh, so a caller cannot reach the router by mutating what
  ;; it was given.
  (define (segments->pattern segs)
    (if (null? segs)
        "/"
        (let loop ((ss segs) (out ""))
          (if (null? ss)
              out
              (loop (cdr ss) (string-append out "/" (car ss)))))))

  (define-checked (app-route-list (a app?))
    (map (lambda (r)
           (cons (vector-ref r 0) (segments->pattern (vector-ref r 1))))
         (app-routes a)))

  (define-checked (app-get (a app?) (pattern string?) (handler procedure?))
    (add-route! a 'GET pattern handler))
  (define-checked (app-post (a app?) (pattern string?) (handler procedure?))
    (add-route! a 'POST pattern handler))
  (define-checked (app-put (a app?) (pattern string?) (handler procedure?))
    (add-route! a 'PUT pattern handler))
  (define-checked (app-delete (a app?) (pattern string?) (handler procedure?))
    (add-route! a 'DELETE pattern handler))
  (define-checked (app-patch (a app?) (pattern string?) (handler procedure?))
    (add-route! a 'PATCH pattern handler))

  ;; RPC endpoint sugar: requests are (tag arg ...); the tag picks a
  ;; handler from the alist, which receives the argument list and
  ;; returns the reply datum. Unknown tags and bad payloads answer
  ;; (error ...) data, never a crash.
  ;;   (app-rpc app "/rpc"
  ;;     `((get-user . ,(lambda (args) ...))
  ;;       (add      . ,(lambda (args) (apply + args)))))
  ;;
  ;; Optional 4th argument: an auth guard (lambda (req) claims-or-#f),
  ;; the same request-guard protocol app-ws takes ((igropyr auth)'s
  ;; token-guard works for both). A refusal answers 401 with the sexpr
  ;; datum (error unauthorized) -- this is a sexpr channel, not JSON.
  ;; Claims land on the request's layer-owned slot (req-claims). A
  ;; handler that can take TWO arguments is called with (args req), so
  ;; it can read claims/params for per-tag authorization; one-argument
  ;; handlers work as before. Rest args, so plain define.
  ;;   (app-rpc app "/rpc"
  ;;     `((whoami . ,(lambda (args req) (json-ref (req-claims req) "sub"))))
  ;;     (token-guard (jwt-verifier key)))
  (define (app-rpc app path handlers . rest)
    (let ((auth-guard (and (pair? rest) (car rest))))
      (when auth-guard
        (unless (procedure? auth-guard)
          (assertion-violation 'app-rpc "guard must be a procedure" auth-guard)))
      (app-post app path
        (lambda (req res)
          (let ((claims (if auth-guard (auth-guard req) #t)))
            (cond
              ((not claims)
               (set-status! res 401)
               (send-sexpr! res '(error unauthorized)))
              (else
               (when auth-guard (req-set-local! req 'claims claims))
               (let ((msg (req-sexpr req)))
                 (if (and (pair? msg) (symbol? (car msg)))
                     (let ((h (assq (car msg) handlers)))
                       (if h
                           ;; The guard must cover the SERIALIZATION too, not
                           ;; just the call. A reply the wire whitelist
                           ;; refuses (a record, a port, a too-deep or
                           ;; cyclic structure) raises inside sexpr->string
                           ;; -- after the handler's side effects have
                           ;; committed. Outside the guard that raise killed
                           ;; the worker and the supervisor replayed the
                           ;; whole request up to max-retries, so a
                           ;; non-idempotent write ran four times. Note the
                           ;; irony it removes: a handler that CRASHES was
                           ;; never retried (the guard turned it into an
                           ;; error reply), while one that SUCCEEDED and
                           ;; returned an unserializable value was.
                           (send-sexpr! res
                             (guard (e (#t (encode-sexpr (list 'error 'handler-failed))))
                               (let* ((proc (cdr h))
                                      (reply
                                       (list 'ok
                                         (if (logbit? 2 (procedure-arity-mask proc))
                                             (proc (cdr msg) req)
                                             (proc (cdr msg))))))
                                 (encode-sexpr reply))))
                           (send-sexpr! res (list 'error 'unknown-tag (car msg)))))
                     (send-sexpr! res (list 'error 'bad-payload)))))))))))

  ;; ---- s-expressions over WebSocket and SSE ---------------------------------
  ;; a message is one datum: write to send, safe-parse on receive --
  ;; the natural framing for pushed data.

  (define-checked (ws-send-sexpr! (ws ws?) x)
    (ws-send-text! ws (sexpr->string-extended x)))

  ;; -> datum | 'close (connection over) | #f (binary or bad datum)
  (define-checked (ws-recv-sexpr (ws ws?))
    (let ((m (ws-recv ws)))
      (cond
        ((and (vector? m) (eq? (vector-ref m 0) 'text))
         (guard (e (#t #f)) (string->sexpr-extended (vector-ref m 1))))
        ((and (vector? m) (eq? (vector-ref m 0) 'close)) 'close)
        (else #f))))

  ;; one event, data = one datum. A literal newline inside a string
  ;; datum splits into multiple data: lines; EventSource rejoins them
  ;; with \n on the client, so the datum survives intact.
  (define-checked (sse-send-sexpr! (res res?) x)
    (let* ((text (sexpr->string-extended x))
           (lines (sse-data-lines text)))
      (res-write! res
        (string-append
          (apply string-append
                 (map (lambda (l) (string-append "data: " l "\n")) lines))
          "\n"))))

  ;; middleware: (lambda (req res next) ...); call (next) to continue.
  ;; The composed chain is rebuilt here, at registration time, so
  ;; mutation stays live while requests just call the prebuilt chain.
  (define-checked (app-use (a app?) (mw procedure?))
    (app-middlewares-set! a (append (app-middlewares a) (list mw)))
    (app-mw-chain-set! a (compose-chain (app-middlewares a))))

  ;; prefix/root get always-on semantic validation below (they shape
  ;; what the filesystem is asked for) -- that is business code, not a
  ;; dev-only contract, so only the app argument is contracted here
  (define-checked (app-static (a app?) prefix root)
    (unless (and (string? prefix) (> (string-length prefix) 0)
                 (char=? (string-ref prefix 0) #\/))
      (assertion-violation 'app-static
        "mount prefix must be an absolute URL path" prefix))
    (unless (and (string? root) (> (string-length root) 0)
                 (not (path-has-nul? root)))
      (assertion-violation 'app-static
        "static root must be a non-empty path without NUL" root))
    ;; store one canonical spelling: drop a trailing slash so "/assets/"
    ;; and "/assets" have identical segment-boundary behaviour (root "/"
    ;; itself is left as-is)
    (let ((p (if (and (> (string-length prefix) 1)
                      (char=? (string-ref prefix (- (string-length prefix) 1)) #\/))
                 (substring prefix 0 (- (string-length prefix) 1))
                 prefix)))
      (app-statics-set! a (append (app-statics a) (list (cons p root))))))

  ;; websocket route: session is (lambda (ws req) ...), run in the
  ;; connection's own process; :param segments work as in app-get.
  ;; Optional 4th argument: an auth guard (lambda (req) claims-or-#f),
  ;; run by the resolver BEFORE the 101 handshake -- truthy claims are
  ;; stashed on the request (read via (igropyr auth)'s req-claims) and
  ;; the upgrade proceeds; #f answers 401 with no handshake. Rest arg,
  ;; so plain define ((igropyr checked) is fixed-arity only).
  (define (app-ws a pattern session . rest)
    (let ((segs (split-segments pattern))
          (guard (and (pair? rest) (car rest))))
      (check-splat! 'app-ws pattern segs)
      (check-params! 'app-ws pattern segs)
      (when guard
        (unless (procedure? guard)
          (assertion-violation 'app-ws "guard must be a procedure" guard)))
      (app-ws-routes-set! a
        (append
          (filter (lambda (r) (not (equal? (vector-ref r 0) segs)))
                  (app-ws-routes a))
          (list (vector segs session guard))))))

  ;; resolver handed to the core: request -> session procedure,
  ;; #f (no route: 404), or #(ws-reject status text) (guard refused:
  ;; answered before any handshake)
  (define (ws-resolver a)
    (lambda (req)
      (let ((segs (split-segments (req-path req))))
        (let loop ((rs (app-ws-routes a)))
          (cond
            ((null? rs) #f)
            (else
             (let* ((r (car rs))
                    (params (match-segments (vector-ref r 0) segs)))
               (if params
                   (begin
                     (req-params-set! req params)
                     (let ((guard (vector-ref r 2)))
                       (if guard
                           (let ((claims (guard req)))
                             (if claims
                                 (begin (req-set-local! req 'claims claims)
                                        (vector-ref r 1))
                                 '#(ws-reject 401 "Unauthorized")))
                           (vector-ref r 1))))
                   (loop (cdr rs))))))))))

  ;; The request path relative to a mount prefix, or #f if it does not
  ;; belong to this mount. The prefix must align on a path boundary:
  ;; "/assets" matches "/assets" and "/assets/x", but NOT "/assets-x",
  ;; so a sibling directory cannot be reached by prefix confusion.
  (define (static-relative prefix path)
    (let ((pl (string-length prefix)) (nl (string-length path)))
      (cond
        ((string=? prefix "/")                     ; root mount
         (and (> nl 0) (char=? (string-ref path 0) #\/)
              (substring path 1 nl)))
        ((not (string-prefix? prefix path)) #f)
        ((= nl pl) "")                             ; exactly the mount root
        ((char=? (string-ref path pl) #\/)          ; prefix + "/..."
         (substring path (+ pl 1) nl))
        (else #f))))                                ; e.g. "/assets-private"

  ;; Resolve a URL-relative name under root without letting it escape.
  ;; Lexically validate the untrusted path. The subsequent file open walks
  ;; these components from a stable root directory fd with O_NOFOLLOW;
  ;; pathname checks alone would be vulnerable to a symlink swap race.
  ;; A segment starting with "." is refused: mounting a project directory
  ;; otherwise serves .env, .git/config and friends -- with a public
  ;; Cache-Control, so an intermediary keeps handing them out. ".well-known"
  ;; is the standard exception (ACME challenges, security.txt) and stays
  ;; reachable. "." itself is a no-op segment, handled above.
  (define (dotfile-segment? seg)
    (and (fx> (string-length seg) 0)
         (char=? (string-ref seg 0) #\.)
         (not (string=? seg "."))
         (not (string=? seg ".well-known"))))

  (define (safe-static-path root rel)
    (and (not (path-has-dotdot? rel))
         (not (path-has-nul? rel))
         (let loop ((base root) (parts (string-split rel #\/)))
           (cond
             ((null? parts) base)
             ((or (string=? (car parts) "") (string=? (car parts) "."))
              (loop base (cdr parts)))
             ((dotfile-segment? (car parts)) #f)
             (else
              (loop (string-append base "/" (car parts)) (cdr parts)))))))

  (define (try-static a req r)
    (and (eq? (routing-method req) 'GET)
         (exists
           (lambda (entry)
             (let* ((prefix (car entry)) (root (cdr entry))
                    (rel (static-relative prefix (req-path req)))
                    (path (and rel (safe-static-path root rel))))
               (and rel
                    (begin
                      ;; safe-static-path rejects ".." and NUL; the openat
                      ;; walk rejects symlink escapes before serving/cache.
                      (if path
                          (serve-static! r req path root rel)
                          (begin (set-status! r 403) (send-text! r "Forbidden")))
                      #t))))
           (app-statics a))))

  ;; RFC 9110 9.3.2: HEAD is GET without the body, so it is answered by the
  ;; GET route (and the GET static mount) -- the response encoder is what
  ;; drops the body, so the headers, including Content-Length, are exactly
  ;; the ones a GET would send. Without this every HEAD fell through to the
  ;; 404 arm, which then sent that page's body on a HEAD response and
  ;; desynchronised the connection.
  (define (routing-method req)
    (let ((m (req-method req))) (if (eq? m 'HEAD) 'GET m)))

  (define (route-dispatch a req r)
    (let ((segs (split-segments (req-path req))))
      (let loop ((routes (app-routes a)))
        (cond
          ((null? routes)
           (or (try-static a req r)
               (begin (set-status! r 404) (send-text! r "Not Found"))))
          (else
           (let ((route (car routes)))
             (let ((params (and (eq? (vector-ref route 0) (routing-method req))
                                (match-segments (vector-ref route 1) segs))))
               (if params
                   (begin
                     (req-params-set! req params)
                     ((vector-ref route 2) req r))
                   (loop (cdr routes))))))))))

  ;; Fold the app into the single (lambda (req res)) handler the core
  ;; expects: middlewares wrap the router, first-registered outermost.
  ;; The chain was composed when the middleware was registered; a request
  ;; only reads the chain slot (so app-use stays live) and runs it.
  (define-checked (app->handler (a app?))
    (lambda (req r)
      ((app-mw-chain a) req r (lambda () (route-dispatch a req r)))))

  ;; Returns the http-server, so callers can http-swap! the whole
  ;; handler later. Route/middleware mutations on the app are live
  ;; anyway (app->handler reads the app on every request).
  ;; Rest args, so plain define ((igropyr checked) is fixed-arity only).
  ;; The contracts line is the mixed-build canary: it reports the level
  ;; baked into THIS module at compile time (see checked.sc).
  (define (app-listen a port . opts)
    (printf "igropyr contracts: ~a\n" (contract-level))
    (let ((srv (apply http-listen port (app->handler a) opts)))
      (http-set-ws! srv (ws-resolver a))
      srv))
)
