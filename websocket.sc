#!chezscheme
;;; (igropyr websocket) -- WebSocket (RFC 6455) codec and session primitives.
;;;
;;; Pure protocol layer: SHA-1 + base64 for the upgrade handshake key,
;;; frame encoding/decoding (masking, fragmentation, ping/pong, close),
;;; and a ws session object owned by one green process. The HTTP core
;;; performs the upgrade and calls the user session as (session ws req);
;;; inside it:
;;;
;;;   (ws-recv ws)            ; blocks -> #(text ,s) | #(binary ,bv) | #(close)
;;;   (ws-send-text! ws s)
;;;   (ws-send-binary! ws bv)
;;;   (ws-close! ws)          ; idempotent
;;;
;;; ws-recv answers pings automatically and handles fragmented messages.

(library (igropyr websocket)
  (export ws-accept-key
          make-ws make-ws-client ws? ws-conn
          ws-recv ws-send-text! ws-send-binary! ws-close!)
  (import (chezscheme) (igropyr buffer)
          (igropyr actor) (igropyr libuv)
          (only (igropyr crypto) sha1 base64-encode))

  (define max-frame 1048576)          ; single frame payload cap
  (define max-message 8388608)        ; reassembled multi-frame message cap

  ;; ---- bytevector helpers -------------------------------------------------

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  (define (bv-concat lst)
    (let ((total (fold-left (lambda (n x) (+ n (bytevector-length x))) 0 lst)))
      (let ((out (make-bytevector total)))
        (let loop ((l lst) (off 0))
          (if (null? l)
              out
              (let ((x (car l)))
                (bytevector-copy! x 0 out off (bytevector-length x))
                (loop (cdr l) (+ off (bytevector-length x)))))))))

  ;; SHA-1 + base64 for the RFC 6455 accept-key live in (igropyr crypto).

  (define ws-guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

  (define (ws-accept-key key)
    (base64-encode (sha1 (string->utf8 (string-append key ws-guid)))))

  ;; ---- frame codec ----------------------------------------------------------

  ;; 4 random mask bytes (client frames MUST be masked, RFC 6455 5.3)
  (define (random-mask)
    (call-with-port (open-file-input-port "/dev/urandom")
      (lambda (p) (get-bytevector-n p 4))))

  ;; Encode a frame (FIN set). mask? masks the payload with a random key
  ;; (client role); servers send unmasked.
  (define (encode-frame op payload mask?)
    (let* ((n (bytevector-length payload))
           (hlen (cond ((< n 126) 2) ((< n 65536) 4) (else 10)))
           (mlen (if mask? 4 0))
           (bv (make-bytevector (+ hlen mlen n))))
      (bytevector-u8-set! bv 0 (fxior #x80 op))
      (let ((mbit (if mask? #x80 0)))
        (cond
          ((< n 126) (bytevector-u8-set! bv 1 (fxior mbit n)))
          ((< n 65536)
           (bytevector-u8-set! bv 1 (fxior mbit 126))
           (bytevector-u8-set! bv 2 (fxsrl n 8))
           (bytevector-u8-set! bv 3 (fxand n #xFF)))
          (else
           (bytevector-u8-set! bv 1 (fxior mbit 127))
           (do ((i 0 (+ i 1))) ((= i 8))
             (bytevector-u8-set! bv (+ 2 i)
               (fxand (bitwise-arithmetic-shift-right n (* 8 (- 7 i))) #xFF))))))
      (if mask?
          (let ((mkey (random-mask)))
            (bytevector-copy! mkey 0 bv hlen 4)
            (do ((i 0 (+ i 1))) ((= i n))
              (bytevector-u8-set! bv (+ hlen 4 i)
                (fxxor (bytevector-u8-ref payload i)
                       (bytevector-u8-ref mkey (fxand i 3))))))
          (bytevector-copy! payload 0 bv hlen n))
      bv))

  ;; decode one frame from bv[start, limit); unmasks a masked payload.
  ;; expect-masked?: server role requires client frames masked; client
  ;; role requires server frames unmasked. -> #(fin? op payload end) |
  ;; 'more | 'bad | 'too-large  (end is absolute, like start)
  (define (decode-frame bv start limit expect-masked?)
    (let ((have (- limit start)))
      (if (< have 2)
          'more
          (let* ((b0 (bytevector-u8-ref bv start))
                 (b1 (bytevector-u8-ref bv (+ start 1)))
                 (fin? (fx> (fxand b0 #x80) 0))
                 (rsv (fxand b0 #x70))
                 (op (fxand b0 #x0F))
                 (masked? (fx> (fxand b1 #x80) 0))
                 (len7 (fxand b1 #x7F))
                 (control? (fx>= op 8)))
            ;; RFC 6455 framing checks (all fatal -> 'bad, close):
            ;;  - masking must match the peer role
            ;;  - RSV bits are zero (no extensions negotiated)
            ;;  - opcode must be known (0,1,2,8,9,10)
            ;;  - control frames must be final and <= 125 bytes
            (cond
              ((not (eq? (and masked? #t) expect-masked?)) 'bad)
              ((not (fx= rsv 0)) 'bad)
              ((not (memv op '(0 1 2 8 9 10))) 'bad)
              ((and control? (or (not fin?) (fx> len7 125))) 'bad)
              (else
            (let-values
                (((plen lenbytes)
                  (cond
                    ((fx= len7 126)
                     (if (< have 4)
                         (values #f 0)
                         (values (fxior (fxsll (bytevector-u8-ref bv (+ start 2)) 8)
                                        (bytevector-u8-ref bv (+ start 3)))
                                 2)))
                    ((fx= len7 127)
                     (if (< have 10)
                         (values #f 0)
                         (values (do ((i 0 (+ i 1))
                                      (v 0 (+ (* v 256)
                                              (bytevector-u8-ref bv (+ start 2 i)))))
                                     ((= i 8) v))
                                 8)))
                    (else (values len7 0)))))
              (cond
                ((not plen) 'more)
                ;; extended lengths must use their minimal encoding, and
                ;; the 64-bit form must not set its sign bit (RFC 6455 5.2)
                ((and (fx= len7 126) (< plen 126)) 'bad)
                ((and (fx= len7 127)
                      (or (< plen 65536)
                          (> (bytevector-u8-ref bv (+ start 2)) 127))) 'bad)
                ;; a close frame's payload is 0 or >= 2 bytes, never 1
                ((and (fx= op 8) (fx= plen 1)) 'bad)
                ((> plen max-frame) 'too-large)
                (else
                 (let* ((mask-off (+ start 2 lenbytes))
                        (data-off (+ mask-off (if masked? 4 0)))
                        (end (+ data-off plen)))
                   (if (< limit end)
                       'more
                       (let ((payload (bv-sub bv data-off end)))
                         (when masked?
                           ;; per byte of every masked (client) frame:
                           ;; fx ops and fxand i 3, not generic +/mod
                           (do ((i 0 (fx+ i 1))) ((fx= i plen))
                             (bytevector-u8-set! payload i
                               (fxxor (bytevector-u8-ref payload i)
                                      (bytevector-u8-ref bv
                                        (fx+ mask-off (fxand i 3)))))))
                         (vector fin? op payload end)))))))))))))

  ;; ---- ws session object -----------------------------------------------------

  (define-record-type (ws make-ws-record ws?)
    (fields
      (immutable conn ws-conn)
      (immutable buf ws-buf)             ; inbuf of unconsumed stream bytes
      (immutable closedbox ws-closedbox)
      (immutable client? ws-client?)))    ; client role masks outbound frames

  (define (leftover->inbuf leftover)
    (let ((b (make-inbuf)))
      (inbuf-append! b leftover)
      b))

  ;; server-side session (frames it sends are unmasked; incoming masked)
  (define (make-ws conn leftover)
    (make-ws-record conn (leftover->inbuf leftover) (box #f) #f))

  ;; client-side session (frames it sends are masked; incoming unmasked)
  (define (make-ws-client conn leftover)
    (make-ws-record conn (leftover->inbuf leftover) (box #f) #t))

  (define (ws-send-frame! w op payload)
    (and (not (unbox (ws-closedbox w)))
         (tcp-write! (ws-conn w) (encode-frame op payload (ws-client? w)) #f)))

  (define (ws-send-text! w s) (ws-send-frame! w 1 (string->utf8 s)))
  (define (ws-send-binary! w bv) (ws-send-frame! w 2 bv))

  ;; idempotent: send a close frame (best effort) and close the socket
  (define (ws-close! w)
    (unless (unbox (ws-closedbox w))
      (set-box! (ws-closedbox w) #t)
      (let ((c (ws-conn w)))
        (tcp-write! c (encode-frame 8 (make-bytevector 0) (ws-client? w))
          (lambda (st) (tcp-close! c))))))

  ;; close with a status code (RFC 6455 7.4): 1002 protocol error,
  ;; 1007 invalid UTF-8 in a text message, 1009 message too big
  (define (ws-fail! w code)
    (unless (unbox (ws-closedbox w))
      (set-box! (ws-closedbox w) #t)
      (let ((c (ws-conn w))
            (payload (bytevector (fxand (fxsrl code 8) #xFF)
                                 (fxand code #xFF))))
        (tcp-write! c (encode-frame 8 payload (ws-client? w))
          (lambda (st) (tcp-close! c))))))

  ;; block until a complete frame is available (runs in the owning
  ;; process). -> a #(fin op payload end) frame, or a reason symbol:
  ;; 'protocol-error | 'message-too-large | 'close
  (define (next-frame! w)
    (let ((buf (ws-buf w)))
      (let loop ()
        ;; server expects masked frames; client expects unmasked
        (let ((r (decode-frame (inbuf-bv buf) (inbuf-start buf) (inbuf-end buf)
                               (not (ws-client? w)))))
          (cond
            ((vector? r)
             ;; consuming the frame is an offset bump, not a copy of
             ;; everything behind it (that was O(n^2) per burst)
             (inbuf-consume! buf (fx- (vector-ref r 3) (inbuf-start buf)))
             r)
            ((eq? r 'bad) 'protocol-error)
            ((eq? r 'too-large) 'message-too-large)
            (else
             (receive
               (`#(tcp-data ,bv) (inbuf-append! buf bv) (loop))
               (`#(tcp-eof) 'close)
               (`#(tcp-error ,e) 'close))))))))

  ;; Strict UTF-8 validation (RFC 3629): rejects overlong encodings,
  ;; surrogates (ED A0..BF), and code points above U+10FFFF. Chez's
  ;; utf8->string silently substitutes U+FFFD, so a text message must be
  ;; validated here to honour RFC 6455's 1007 requirement.
  (define (utf8-cont? bv i)
    (fx= (fxand (bytevector-u8-ref bv i) #xC0) #x80))

  (define (valid-utf8? bv)
    (let ((n (bytevector-length bv)))
      (let loop ((i 0))
        (if (>= i n)
            #t
            (let ((b (bytevector-u8-ref bv i)))
              (cond
                ((< b #x80) (loop (+ i 1)))                  ; ASCII
                ((< b #xC2) #f)                              ; stray cont / overlong
                ((< b #xE0)                                  ; 2-byte
                 (and (< (+ i 1) n) (utf8-cont? bv (+ i 1))
                      (loop (+ i 2))))
                ((< b #xF0)                                  ; 3-byte
                 (and (< (+ i 2) n) (utf8-cont? bv (+ i 1)) (utf8-cont? bv (+ i 2))
                      (let ((b1 (bytevector-u8-ref bv (+ i 1))))
                        (cond ((= b #xE0) (>= b1 #xA0))      ; no overlong
                              ((= b #xED) (<= b1 #x9F))      ; no surrogate
                              (else #t)))
                      (loop (+ i 3))))
                ((< b #xF5)                                  ; 4-byte
                 (and (< (+ i 3) n) (utf8-cont? bv (+ i 1))
                      (utf8-cont? bv (+ i 2)) (utf8-cont? bv (+ i 3))
                      (let ((b1 (bytevector-u8-ref bv (+ i 1))))
                        (cond ((= b #xF0) (>= b1 #x90))      ; no overlong
                              ((= b #xF4) (<= b1 #x8F))      ; <= U+10FFFF
                              (else #t)))
                      (loop (+ i 4))))
                (else #f)))))))

  ;; Block until the next complete message.
  ;; -> #(text ,string) | #(binary ,bytevector) | #(close)
  ;; Pings are answered, pongs ignored, fragments reassembled. A message
  ;; whose reassembled size would exceed max-message, or a frame that
  ;; violates the fragmentation sequence (a continuation with no message
  ;; in progress, or a new data frame mid-message), closes the socket with
  ;; the appropriate status code. Invalid UTF-8 in a text message is a
  ;; 1007 close (rather than a crash).
  (define (ws-recv w)
    (define (deliver op parts)
      (let ((body (bv-concat (reverse parts))))
        (cond
          ((= op 2) (vector 'binary body))
          ((valid-utf8? body) (vector 'text (utf8->string body)))
          (else (ws-fail! w 1007) (vector 'close)))))   ; invalid UTF-8
    (if (unbox (ws-closedbox w))
        (vector 'close)
        ;; op = opcode of the in-progress message (#f = none); size =
        ;; bytes accumulated so far
        (let loop ((op #f) (parts '()) (size 0))
          (let ((f (next-frame! w)))
            (if (not (vector? f))
                (begin
                  (case f
                    ((protocol-error) (ws-fail! w 1002))
                    ((message-too-large) (ws-fail! w 1009))
                    (else (ws-close! w)))
                  (vector 'close))
                (let* ((fin? (vector-ref f 0))
                       (fop (vector-ref f 1))
                       (payload (vector-ref f 2))
                       (new-size (+ size (bytevector-length payload))))
                  (case fop
                    ((9) (ws-send-frame! w 10 payload) (loop op parts size)) ; ping
                    ((10) (loop op parts size))                              ; pong
                    ((8) (ws-close! w) (vector 'close))
                    ((0)                                    ; continuation frame
                     (cond
                       ((not op) (ws-fail! w 1002) (vector 'close)) ; no message started
                       ((> new-size max-message) (ws-fail! w 1009) (vector 'close))
                       (else
                        (let ((parts (cons payload parts)))
                          (if fin? (deliver op parts) (loop op parts new-size))))))
                    (else                                   ; new data frame (1/2)
                     (cond
                       (op (ws-fail! w 1002) (vector 'close))    ; previous msg unfinished
                       ((> new-size max-message) (ws-fail! w 1009) (vector 'close))
                       (fin? (deliver fop (list payload)))
                       (else (loop fop (list payload) new-size)))))))))))
)
