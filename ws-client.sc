#!chezscheme
;;; Copyright 2018 - 2026 guenchi.
;;;
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;;
;;; http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

;;; (igropyr ws-client) -- outbound WebSocket client.
;;;
;;; Connects, performs the RFC 6455 upgrade handshake, and returns a ws
;;; session in client role (outbound frames are masked, inbound frames
;;; must be unmasked). The session is the same object the server side
;;; uses, so ws-recv / ws-send-text! / ws-send-binary! / ws-close! all
;;; work unchanged.
;;;
;;;   (define w (ws-connect "ws://127.0.0.1:8080/chat/42"))
;;;   (ws-send-text! w "hello")
;;;   (ws-recv w)            ; -> #(text s) | #(binary bv) | #(close)
;;;   (ws-close! w)
;;;
;;; Runs in the caller's green process; connect/handshake failures raise
;;; #(ws-client-error msg).

(library (igropyr ws-client)
  (export ws-connect
          ;; Re-exported session operations from (igropyr websocket):
          ;; ws-connect returns a session that is only usable through
          ;; these, so a client-only program imports this library alone.
          ws-recv ws-send-text! ws-send-binary! ws-close!
          ;; Re-exported app-facing (igropyr actor) surface, for the same
          ;; reason as (igropyr client): a client-only program still needs
          ;; the scheduler and process primitives. Same original bindings
          ;; as those re-exported by (igropyr http) -- importing both
          ;; never conflicts.
          start-scheduler spawn send receive self
          sleep-ms kill register whereis process-id)
  (import (chezscheme) (igropyr buffer)
          (only (igropyr util) digits->exact)
          (igropyr actor) (igropyr websocket)
          (only (igropyr libuv) now-ms uv-strerror)
          (only (igropyr tcp) dns-resolve! tcp-close! tcp-connect! tcp-read-start! tcp-write!)
          (only (igropyr crypto) base64-encode))

  (define connect-timeout-ms 10000)
  (define default-port 80)

  (define (fail msg) (raise (vector 'ws-client-error msg)))

  ;; ---- URL parsing (ws://host[:port][/path]) --------------------------

  (define (string-index s ch from)
    (let ((n (string-length s)))
      (let loop ((i from))
        (cond ((= i n) #f)
              ((char=? (string-ref s i) ch) i)
              (else (loop (+ i 1)))))))

  (define (parse-ws-url url)
    (let ((rest (cond
                  ((and (>= (string-length url) 5)
                        (string-ci=? (substring url 0 5) "ws://"))
                   (substring url 5 (string-length url)))
                  ((and (>= (string-length url) 6)
                        (string-ci=? (substring url 0 6) "wss://"))
                   (fail "wss not supported; put TLS behind a proxy"))
                  (else (fail "url must start with ws://")))))
      (let* ((slash (string-index rest #\/ 0))
             (authority (if slash (substring rest 0 slash) rest))
             (path (if slash (substring rest slash (string-length rest)) "/"))
             (colon (string-index authority #\: 0)))
        (if colon
            (values (substring authority 0 colon)
                    ;; the port comes from a caller-supplied URL: shape
                    ;; first, five digits being the whole port range
                    (or (digits->exact (substring authority (+ colon 1)
                                         (string-length authority))
                                       5)
                        default-port)
                    path)
            (values authority default-port path)))))

  ;; ---- handshake -------------------------------------------------------

  ;; 16 random bytes, base64 -> Sec-WebSocket-Key
  (define (make-ws-key)
    (base64-encode
      (call-with-port (open-file-input-port "/dev/urandom")
        (lambda (p) (get-bytevector-n p 16)))))

  ;; Request-line fields must stay on one printable ASCII line. Header
  ;; values additionally allow horizontal tab and non-ASCII text, but no
  ;; control byte that can terminate or corrupt the HTTP header block.
  (define (request-line-safe? s)
    (and (string? s)
         (> (string-length s) 0)
         (let loop ((i 0))
           (or (= i (string-length s))
               (let ((c (string-ref s i)))
                 (and (char>? c #\space) (char<? c #\delete)
                      (loop (+ i 1))))))))

  (define token-punctuation "!#$%&'*+-.^_`|~")

  (define (header-name-char? c)
    (or (char<=? #\a c #\z)
        (char<=? #\A c #\Z)
        (char<=? #\0 c #\9)
        (and (string-index token-punctuation c 0) #t)))

  (define (header-name-safe? s)
    (and (string? s)
         (> (string-length s) 0)
         (let loop ((i 0))
           (or (= i (string-length s))
               (and (header-name-char? (string-ref s i))
                    (loop (+ i 1)))))))

  (define (header-value-safe? s)
    (and (string? s)
         (let loop ((i 0))
           (or (= i (string-length s))
               (let* ((c (string-ref s i)) (n (char->integer c)))
                 (and (or (= n 9) (>= n 32))
                      (not (= n 127))
                      (loop (+ i 1))))))))

  ;; Sec-WebSocket-Extensions IS MANAGED BECAUSE NO EXTENSION IS
  ;; IMPLEMENTED: a caller could offer one, and a server that accepted it
  ;; would then send frames this client cannot read. Sec-WebSocket-Protocol
  ;; is NOT managed: a subprotocol changes nothing about framing, the caller
  ;; may offer some, and the 101 is checked against what was offered.
  (define (managed-handshake-header? name)
    (exists (lambda (reserved) (string-ci=? name reserved))
            '("Host" "Upgrade" "Connection"
              "Sec-WebSocket-Key" "Sec-WebSocket-Version"
              "Sec-WebSocket-Extensions"
              "Content-Length" "Transfer-Encoding")))

  ;; "a, b" -> ("a" "b"): the elements of a comma-separated field value,
  ;; each with surrounding whitespace removed.
  (define (comma-elements value)
    (let ((n (string-length value)))
      (let loop ((start 0) (i 0) (acc '()))
        (cond
          ((= i n) (reverse (cons (trim-ows (substring value start i)) acc)))
          ((char=? (string-ref value i) #\,)
           (loop (+ i 1) (+ i 1)
                 (cons (trim-ows (substring value start i)) acc)))
          (else (loop start (+ i 1) acc))))))

  ;; The subprotocols this request offers: every element of every
  ;; Sec-WebSocket-Protocol in the extra headers, in order. Each must be a
  ;; token and all must be distinct (RFC 6455 4.1), across repeated fields as
  ;; well as within one; anything else is refused here, before DNS, since a
  ;; server could not be held to an offer that is not one. Compared
  ;; case-sensitively, here and against the 101, as the RFC's tokens are.
  (define (offered-subprotocols extra-headers)
    (let ((offered
           (apply append
             (map (lambda (h)
                    (if (string-ci=? (car h) "Sec-WebSocket-Protocol")
                        (let ((xs (comma-elements (cdr h))))
                          (unless (for-all header-name-safe? xs)
                            (fail (string-append
                                    "invalid Sec-WebSocket-Protocol: "
                                    "each subprotocol must be a token")))
                          xs)
                        '()))
                  extra-headers))))
      (let loop ((xs offered))
        (unless (null? xs)
          (when (member (car xs) (cdr xs))
            (fail (string-append "invalid Sec-WebSocket-Protocol: "
                                 "subprotocol offered twice: " (car xs))))
          (loop (cdr xs))))
      offered))

  ;; Consume, and close, whatever an earlier timed-out attempt left behind.
  ;; A connect that lands after its caller gave up is a live socket nobody
  ;; owns; matched by a later attempt it is worse than a leak, because the
  ;; handshake would run over it.
  (define (drain-stale-connects!)
    (let loop ()
      (receive (after 0 'done)
        (`#(tcp-connected ,late) (tcp-close! late) (loop))
        (`#(tcp-connect-failed ,e) (loop))
        (`#(dns-resolved ,ip) (loop))
        (`#(dns-failed ,e) (loop)))))

  (define (validate-handshake-request! host path extra-headers)
    (unless (request-line-safe? host)
      (fail "invalid Host header: control characters are not allowed"))
    (unless (request-line-safe? path)
      (fail "invalid request path: control characters are not allowed"))
    (unless (list? extra-headers)
      (fail "extra headers must be an alist"))
    (for-each
      (lambda (h)
        (unless (and (pair? h) (header-name-safe? (car h)))
          (fail "invalid header name"))
        (when (managed-handshake-header? (car h))
          (fail (string-append "header is managed by the client: " (car h))))
        (unless (header-value-safe? (cdr h))
          (fail (string-append "invalid value for header " (car h)
                               ": control characters are not allowed"))))
      extra-headers))

  ;; THE Host FIELD'S AUTHORITY, made in this one place (RFC 6455 4.1, RFC
  ;; 9110 7.2): the host, and the port when it is not 80, the default for
  ;; ws://. A server or proxy that routes on the authority otherwise sees
  ;; the default port for a connection made to another. parse-ws-url does
  ;; not handle bracketed IPv6 literals -- it splits the authority at the
  ;; first colon -- and when it does, the brackets belong in this
  ;; procedure.
  (define (ws-authority host port)
    (if (= port default-port)
        host
        (string-append host ":" (number->string port))))

  (define (handshake-request authority path key extra-headers)
    (string->utf8
      (string-append
        "GET " path " HTTP/1.1\r\n"
        "Host: " authority "\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: " key "\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        (apply string-append
               (map (lambda (h)
                      (string-append (car h) ": " (cdr h) "\r\n"))
                    extra-headers))
        "\r\n")))

  (define (string-crlf-index s from)
    (let ((n (string-length s)))
      (let loop ((i from))
        (cond ((>= (+ i 1) n) #f)
              ((and (char=? (string-ref s i) #\return)
                    (char=? (string-ref s (+ i 1)) #\newline)) i)
              (else (loop (+ i 1)))))))

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

  (define (valid-101-status-line? line)
    (let ((sp1 (string-index line #\space 0)))
      (and sp1
           (string=? (substring line 0 sp1) "HTTP/1.1")
           (let* ((start (+ sp1 1))
                  (sp2 (string-index line #\space start))
                  (end (or sp2 (string-length line))))
             (string=? (substring line start end) "101")))))

  ;; Parse the already bounded handshake header block into lowercase names.
  ;; A malformed line invalidates the response instead of being skipped.
  (define (parse-response-headers text start)
    (let ((n (string-length text)))
      (let loop ((pos start) (acc '()))
        (cond
          ((= pos n) (reverse acc))
          (else
           (let ((eol (string-crlf-index text pos)))
             (and eol
                  (let* ((line (substring text pos eol))
                         (colon (string-index line #\: 0)))
                    ;; THE NAME MUST BE A TOKEN, so nothing -- not even a
                    ;; space before the colon -- separates it from the
                    ;; colon (RFC 9112 5.1). A name with a trailing space
                    ;; would otherwise be stored under a different key and
                    ;; slip past every check below that looks fields up by
                    ;; name.
                    (and colon (> colon 0)
                         (header-name-safe? (substring line 0 colon))
                         (loop (+ eol 2)
                           (cons (cons (string-downcase (substring line 0 colon))
                                       (trim-ows
                                         (substring line (+ colon 1)
                                                    (string-length line))))
                                 acc)))))))))))

  (define (response-header-values headers name)
    (let loop ((hs headers) (acc '()))
      (cond ((null? hs) (reverse acc))
            ((string=? (caar hs) name)
             (loop (cdr hs) (cons (cdar hs) acc)))
            (else (loop (cdr hs) acc)))))

  (define (value-has-token? value wanted)
    (let ((n (string-length value)))
      (let loop ((start 0) (i 0))
        (cond
          ((= i n)
           (string-ci=? (trim-ows (substring value start i)) wanted))
          ((char=? (string-ref value i) #\,)
           (or (string-ci=? (trim-ows (substring value start i)) wanted)
               (loop (+ i 1) (+ i 1))))
          (else (loop start (+ i 1)))))))

  (define (header-has-token? headers name wanted)
    (exists (lambda (value) (value-has-token? value wanted))
            (response-header-values headers name)))

  ;; RFC 6455 4.1: the response must be an HTTP/1.1 101 upgrade, nominate
  ;; websocket/Upgrade in its token fields, and carry exactly one Accept
  ;; field whose complete value proves possession of this request's key.
  (define (verify-response head-bv key offered)
    (guard (e (#t #f))
      (let* ((text (utf8->string head-bv))
             (status-end (string-crlf-index text 0)))
        (and status-end
             (valid-101-status-line? (substring text 0 status-end))
             (let ((headers (parse-response-headers text (+ status-end 2))))
               (and headers
                    (header-has-token? headers "upgrade" "websocket")
                    (header-has-token? headers "connection" "upgrade")
                    (let ((accepts
                           (response-header-values
                             headers "sec-websocket-accept")))
                      (and (= (length accepts) 1)
                           (string=? (car accepts) (ws-accept-key key))))
                    ;; ONLY WHAT WAS OFFERED MAY BE SELECTED (RFC 6455 4.1).
                    ;; A subprotocol: none, or exactly one value that is one
                    ;; of this request's offers -- with nothing offered, any
                    ;; is refused. An extension: this client offers none,
                    ;; and one such as permessage-deflate would change how
                    ;; every frame after this must be read; a field whose
                    ;; values are all empty selects nothing and is accepted.
                    (let ((selected (response-header-values
                                      headers "sec-websocket-protocol")))
                      (or (null? selected)
                          (and (= (length selected) 1)
                               (member (car selected) offered)
                               #t)))
                    (for-all (lambda (v) (string=? v ""))
                             (response-header-values
                               headers "sec-websocket-extensions"))))))))

  (define max-handshake-header 16384)   ; cap on the 101 response headers

  ;; read until the response headers are complete (resumable scan --
  ;; no rescans-from-zero as segments arrive), then verify
  ;; deadline is an ABSOLUTE time, not a per-segment budget. The receive
  ;; below re-arms on every arrival, so a peer that dribbles one byte just
  ;; inside the window holds this process and its connection open forever
  ;; at no cost to itself -- slowloris, against a client. The server bounds
  ;; the same shape with request-deadline-ms for the same reason.
  (define (await-handshake c key offered buf deadline)
    (let ((left (- deadline (now-ms))))
      (if (<= left 0)
          (begin (tcp-close! c) (fail "handshake timeout"))
          (await-handshake* c key offered buf deadline left))))

  (define (await-handshake* c key offered buf deadline left)
    (let ((hend (inbuf-find-header-end buf)))
      (cond
        ;; THE CEILING APPLIES TO A COMPLETE HEAD TOO. Checking it only
        ;; while still accumulating let a peer that sent the whole head in
        ;; one segment past it. The head is counted up to and including its
        ;; terminator; bytes after it are the first frame and are not.
        ((and hend (> (fx+ hend 4) max-handshake-header))
         (tcp-close! c) (fail "handshake header too large"))
        (hend
         (if (verify-response (inbuf-sub buf 0 (fx+ hend 2)) key offered)
             ;; leftover bytes after \r\n\r\n belong to the ws stream
             (make-ws-client c (inbuf-sub buf (fx+ hend 4) (inbuf-length buf)))
             (begin (tcp-close! c) (fail "handshake rejected"))))
        ((> (inbuf-length buf) max-handshake-header)
         (tcp-close! c) (fail "handshake header too large"))
        (else
         (receive (after left
                     (tcp-close! c) (fail "handshake timeout"))
           (`#(tcp-data ,bv)
             (inbuf-append! buf bv)
             (await-handshake c key offered buf deadline))
           (`#(tcp-eof) (tcp-close! c) (fail "connection closed during handshake"))
           (`#(tcp-error ,e) (tcp-close! c) (fail "connection error")))))))

  ;; ---- public API ------------------------------------------------------

  ;; Connect to a ws:// URL and complete the handshake; returns a ws
  ;; session. Runs in the caller's process. Optional rest argument: an
  ;; alist of extra handshake headers, e.g. the credential for a
  ;; guarded route ((igropyr auth)):
  ;;   (ws-connect url `(("Authorization" . ,(string-append "Bearer " tok))))
  (define (ws-connect url . rest)
    (let ((extra-headers (if (pair? rest) (car rest) '())))
      (let-values (((host port path) (parse-ws-url url)))
        ;; Validate before DNS or connect so attacker-controlled request
        ;; metadata cannot become a second header or request on the wire.
        (validate-handshake-request! host path extra-headers)
        (let ((offered (offered-subprotocols extra-headers)))
        ;; ONE SESSION PER PROCESS -- see ws-recv in (igropyr websocket).
        ;; DNS, connect and socket events all name this process and carry no
        ;; connection identity, so two sessions in one process consume each
        ;; other's messages. Spawn a process per session.
        ;; An earlier attempt from THIS process that timed out may still have
        ;; a connect in flight, and its #(tcp-connected ...) would otherwise
        ;; be matched by the receive below -- this attempt running its
        ;; handshake over somebody else's socket. Draining at ENTRY closes
        ;; that connection and costs this attempt nothing; the previous
        ;; approach waited five seconds at the point of failure, which both
        ;; delayed the caller and still missed anything landing later.
        (drain-stale-connects!)
        ;; ONE deadline for dns + connect + handshake. Each phase used to
        ;; get a full connect-timeout-ms of its own, so a caller asking for
        ;; ten seconds could wait twenty-five.
        (let ((deadline (+ (now-ms) connect-timeout-ms)))
          (define (left) (max 1 (- deadline (now-ms))))
          (dns-resolve! host self)
          (receive (after (left) (fail "dns timeout"))
            (`#(dns-resolved ,ip)
              (tcp-connect! ip port self)
              (receive (after (left) (fail "connect timeout"))
                (`#(tcp-connected ,c)
                  (tcp-read-start! c)
                  (let ((key (make-ws-key)))
                    (tcp-write! c (handshake-request (ws-authority host port)
                                                     path key extra-headers)
                                #f)
                    (await-handshake c key offered (make-inbuf) deadline)))
                (`#(tcp-connect-failed ,e) (fail (uv-strerror e)))))
            (`#(dns-failed ,e) (fail "dns resolution failed"))))))))
)
