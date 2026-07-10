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
  (export ws-accept-key sha1 base64-encode
          make-ws ws? ws-conn
          ws-recv ws-send-text! ws-send-binary! ws-close!)
  (import (chezscheme) (igropyr actor) (igropyr libuv))

  (define max-frame 1048576)          ; single frame payload cap
  (define max-message 8388608)        ; reassembled multi-frame message cap

  ;; ---- bytevector helpers -------------------------------------------------

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

  (define (bv-concat lst)
    (let ((total (fold-left (lambda (n x) (+ n (bytevector-length x))) 0 lst)))
      (let ((out (make-bytevector total)))
        (let loop ((l lst) (off 0))
          (if (null? l)
              out
              (let ((x (car l)))
                (bytevector-copy! x 0 out off (bytevector-length x))
                (loop (cdr l) (+ off (bytevector-length x)))))))))

  ;; ---- SHA-1 (needed only for the handshake; not for security) --------------

  (define mask32 #xFFFFFFFF)

  (define (rotl32 x n)
    (fxior (fxsll (fxand x (fx- (fxsll 1 (fx- 32 n)) 1)) n)
           (fxsrl x (fx- 32 n))))

  (define (add32 . xs)
    (fxand (apply fx+ xs) mask32))

  (define (sha1 msg)
    (let* ((len (bytevector-length msg))
           (padlen (let ((r (mod (+ len 1) 64)))
                     (if (<= r 56) (- 56 r) (- 120 r))))
           (total (+ len 1 padlen 8))
           (buf (make-bytevector total 0))
           (w (make-vector 80 0)))
      (bytevector-copy! msg 0 buf 0 len)
      (bytevector-u8-set! buf len #x80)
      ;; 64-bit big-endian bit length
      (do ((i 0 (+ i 1))) ((= i 8))
        (bytevector-u8-set! buf (- total 1 i)
          (fxand (bitwise-arithmetic-shift-right (* len 8) (* 8 i)) #xFF)))
      (let blocks ((blk 0)
                   (h0 #x67452301) (h1 #xEFCDAB89) (h2 #x98BADCFE)
                   (h3 #x10325476) (h4 #xC3D2E1F0))
        (if (= blk (div total 64))
            (let ((out (make-bytevector 20)))
              (let put ((i 0) (hs (list h0 h1 h2 h3 h4)))
                (unless (null? hs)
                  (let ((h (car hs)))
                    (bytevector-u8-set! out i (fxsrl h 24))
                    (bytevector-u8-set! out (+ i 1) (fxand (fxsrl h 16) #xFF))
                    (bytevector-u8-set! out (+ i 2) (fxand (fxsrl h 8) #xFF))
                    (bytevector-u8-set! out (+ i 3) (fxand h #xFF)))
                  (put (+ i 4) (cdr hs))))
              out)
            (begin
              (do ((t 0 (+ t 1))) ((= t 16))
                (let ((b (+ (* blk 64) (* t 4))))
                  (vector-set! w t
                    (fxior (fxsll (bytevector-u8-ref buf b) 24)
                           (fxsll (bytevector-u8-ref buf (+ b 1)) 16)
                           (fxsll (bytevector-u8-ref buf (+ b 2)) 8)
                           (bytevector-u8-ref buf (+ b 3))))))
              (do ((t 16 (+ t 1))) ((= t 80))
                (vector-set! w t
                  (rotl32 (fxxor (vector-ref w (- t 3))
                                 (vector-ref w (- t 8))
                                 (vector-ref w (- t 14))
                                 (vector-ref w (- t 16)))
                          1)))
              (let rounds ((t 0) (a h0) (b h1) (c h2) (d h3) (e h4))
                (if (= t 80)
                    (blocks (+ blk 1)
                            (add32 h0 a) (add32 h1 b) (add32 h2 c)
                            (add32 h3 d) (add32 h4 e))
                    (let ((f (cond
                               ((< t 20)
                                (fxior (fxand b c)
                                       (fxand (fxxor b mask32) d)))
                               ((< t 40) (fxxor b c d))
                               ((< t 60)
                                (fxior (fxand b c) (fxand b d) (fxand c d)))
                               (else (fxxor b c d))))
                          (k (cond
                               ((< t 20) #x5A827999)
                               ((< t 40) #x6ED9EBA1)
                               ((< t 60) #x8F1BBCDC)
                               (else #xCA62C1D6))))
                      (rounds (+ t 1)
                              (add32 (rotl32 a 5) f e k (vector-ref w t))
                              a (rotl32 b 30) c d)))))))))

  ;; ---- base64 -----------------------------------------------------------------

  (define b64-chars
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

  (define (base64-encode bv)
    (let ((n (bytevector-length bv)))
      (call-with-string-output-port
        (lambda (p)
          (define (out i) (write-char (string-ref b64-chars i) p))
          (let loop ((i 0))
            (let ((left (- n i)))
              (cond
                ((>= left 3)
                 (let ((b0 (bytevector-u8-ref bv i))
                       (b1 (bytevector-u8-ref bv (+ i 1)))
                       (b2 (bytevector-u8-ref bv (+ i 2))))
                   (out (fxsrl b0 2))
                   (out (fxior (fxsll (fxand b0 3) 4) (fxsrl b1 4)))
                   (out (fxior (fxsll (fxand b1 15) 2) (fxsrl b2 6)))
                   (out (fxand b2 63))
                   (loop (+ i 3))))
                ((= left 2)
                 (let ((b0 (bytevector-u8-ref bv i))
                       (b1 (bytevector-u8-ref bv (+ i 1))))
                   (out (fxsrl b0 2))
                   (out (fxior (fxsll (fxand b0 3) 4) (fxsrl b1 4)))
                   (out (fxsll (fxand b1 15) 2))
                   (write-char #\= p)))
                ((= left 1)
                 (let ((b0 (bytevector-u8-ref bv i)))
                   (out (fxsrl b0 2))
                   (out (fxsll (fxand b0 3) 4))
                   (write-char #\= p)
                   (write-char #\= p)))
                (else (void)))))))))

  (define ws-guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

  (define (ws-accept-key key)
    (base64-encode (sha1 (string->utf8 (string-append key ws-guid)))))

  ;; ---- frame codec ----------------------------------------------------------

  ;; encode a server frame (FIN set, no mask)
  (define (encode-frame op payload)
    (let* ((n (bytevector-length payload))
           (hlen (cond ((< n 126) 2) ((< n 65536) 4) (else 10)))
           (bv (make-bytevector (+ hlen n))))
      (bytevector-u8-set! bv 0 (fxior #x80 op))
      (cond
        ((< n 126) (bytevector-u8-set! bv 1 n))
        ((< n 65536)
         (bytevector-u8-set! bv 1 126)
         (bytevector-u8-set! bv 2 (fxsrl n 8))
         (bytevector-u8-set! bv 3 (fxand n #xFF)))
        (else
         (bytevector-u8-set! bv 1 127)
         (do ((i 0 (+ i 1))) ((= i 8))
           (bytevector-u8-set! bv (+ 2 i)
             (fxand (bitwise-arithmetic-shift-right n (* 8 (- 7 i))) #xFF)))))
      (bytevector-copy! payload 0 bv hlen n)
      bv))

  ;; decode one frame at `start`; unmasks client payloads
  ;; -> #(fin? opcode payload end-index) | 'more | 'bad
  (define (decode-frame bv start)
    (let ((have (- (bytevector-length bv) start)))
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
            ;;  - client frames MUST be masked
            ;;  - RSV bits are zero (no extensions negotiated)
            ;;  - opcode must be known (0,1,2,8,9,10)
            ;;  - control frames must be final and <= 125 bytes
            (cond
              ((not masked?) 'bad)
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
                ((> plen max-frame) 'bad)
                (else
                 (let* ((mask-off (+ start 2 lenbytes))
                        (data-off (+ mask-off (if masked? 4 0)))
                        (end (+ data-off plen)))
                   (if (< (bytevector-length bv) end)
                       'more
                       (let ((payload (bv-sub bv data-off end)))
                         (when masked?
                           (do ((i 0 (+ i 1))) ((= i plen))
                             (bytevector-u8-set! payload i
                               (fxxor (bytevector-u8-ref payload i)
                                      (bytevector-u8-ref bv (+ mask-off (mod i 4)))))))
                         (vector fin? op payload end)))))))))))))

  ;; ---- ws session object -----------------------------------------------------

  (define-record-type (ws make-ws-record ws?)
    (fields
      (immutable conn ws-conn)
      (immutable bufbox ws-bufbox)       ; box of unconsumed bytes
      (immutable closedbox ws-closedbox)))

  (define (make-ws conn leftover)
    (make-ws-record conn (box leftover) (box #f)))

  (define (ws-send-frame! w op payload)
    (and (not (unbox (ws-closedbox w)))
         (tcp-write! (ws-conn w) (encode-frame op payload) #f)))

  (define (ws-send-text! w s) (ws-send-frame! w 1 (string->utf8 s)))
  (define (ws-send-binary! w bv) (ws-send-frame! w 2 bv))

  ;; idempotent: send a close frame (best effort) and close the socket
  (define (ws-close! w)
    (unless (unbox (ws-closedbox w))
      (set-box! (ws-closedbox w) #t)
      (let ((c (ws-conn w)))
        (tcp-write! c (encode-frame 8 (make-bytevector 0))
          (lambda (st) (tcp-close! c))))))

  ;; block until a complete frame is available (runs in the owning process)
  (define (next-frame! w)
    (let loop ()
      (let* ((buf (unbox (ws-bufbox w)))
             (r (decode-frame buf 0)))
        (cond
          ((vector? r)
           (set-box! (ws-bufbox w)
                     (bv-sub buf (vector-ref r 3) (bytevector-length buf)))
           r)
          ((eq? r 'bad) 'close)
          (else
           (receive
             (`#(tcp-data ,bv)
               (set-box! (ws-bufbox w) (bv-append (unbox (ws-bufbox w)) bv))
               (loop))
             (`#(tcp-eof) 'close)
             (`#(tcp-error ,e) 'close)))))))

  ;; Block until the next complete message.
  ;; -> #(text ,string) | #(binary ,bytevector) | #(close)
  ;; Pings are answered, pongs ignored, fragments reassembled. A message
  ;; whose reassembled size would exceed max-message, or a frame that
  ;; violates the fragmentation sequence (a continuation with no message
  ;; in progress, or a new data frame mid-message), closes the socket.
  (define (ws-recv w)
    (define (deliver op parts)
      (let ((body (bv-concat (reverse parts))))
        (if (= op 1)
            (vector 'text (utf8->string body))
            (vector 'binary body))))
    (if (unbox (ws-closedbox w))
        (vector 'close)
        ;; op = opcode of the in-progress message (#f = none); size =
        ;; bytes accumulated so far
        (let loop ((op #f) (parts '()) (size 0))
          (let ((f (next-frame! w)))
            (if (eq? f 'close)
                (begin (ws-close! w) (vector 'close))
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
                       ((not op) (ws-close! w) (vector 'close)) ; no message started
                       ((> new-size max-message) (ws-close! w) (vector 'close))
                       (else
                        (let ((parts (cons payload parts)))
                          (if fin? (deliver op parts) (loop op parts new-size))))))
                    (else                                   ; new data frame (1/2)
                     (cond
                       (op (ws-close! w) (vector 'close))    ; previous msg unfinished
                       ((> new-size max-message) (ws-close! w) (vector 'close))
                       (fin? (deliver fop (list payload)))
                       (else (loop fop (list payload) new-size)))))))))))
)
