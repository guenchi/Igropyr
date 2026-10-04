#!chezscheme
;;; test/ws-client-protocol.sc -- the WebSocket client's handshake and close
;;; handling against recording servers (RFC 6455 4.1, 5.5.1, 7.4, 8.1).
;;;
;;; HOST CARRIES THE PORT. The request's Host must be the URL's authority:
;;; host and, for a port other than 80, the port. Two servers on two ports
;;; each read the Host they receive, so a constant port cannot pass both.
;;; The default-port case (no port in Host) is NOT covered: it needs a
;;; listener on port 80. Nor is IPv6: parse-ws-url takes no brackets yet.
;;;
;;; A COMPLETE OVERSIZED HANDSHAKE IS OVERSIZED. The cap on response heads
;;; (16384 bytes, terminator included) was applied only while the terminator
;;; had not arrived; a head delivered in one segment, terminator included,
;;; was parsed whatever its size. The rows sit on the boundary: a head of
;;; exactly 16384 bytes is accepted and one of 16385 refused; and a head of
;;; 16384 followed in the same segment by a 4-byte frame is accepted with
;;; the frame delivered, which a cap on the whole buffer would refuse. One
;;; tcp-write! of these sizes arrives on loopback as one segment here, as
;;; the pre-change red read; that is what loopback did, not a guarantee.
;;;
;;; ONLY WHAT WAS REQUESTED IS AGREED TO. A caller may request subprotocols
;;; through the extra headers of ws-connect; the 101 may then name one of
;;; them, and nothing else. This client implements no extension, so an
;;; Extensions request is refused before connecting, and a 101 naming one is
;;; refused.
;;;
;;; A CLOSE REASON IS UTF-8. The payload after the code is a UTF-8 reason
;;; (5.5.1); one that is not valid UTF-8 is a data error, answered with
;;; close code 1007 (7.4.1), where a valid one has its CODE echoed (the
;;; reply carries the code only). The client's close frame is masked; the
;;; server unmasks it, requires FIN set, RSV clear and opcode 8, and skips
;;; any ping or pong before it. The same loop serves the server side
;;; ((igropyr websocket) ws-recv); the client side is the one measured.
;;;
;;; Host and the close replies are read on the wire by the servers. The
;;; refusals are the client's own error, asserted by its REASON, so a timeout
;;; or a dropped connection cannot pass as a refusal. Every session runs in
;;; its own child process, as the library requires.

(import (chezscheme) (igropyr actor) (igropyr tcp) (igropyr ws-client)
        (only (igropyr websocket) ws-accept-key))

(define port 18852)
(define port2 18853)
(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define (index-of text sub from)
  (let ((n (string-length text)) (m (string-length sub)))
    (let loop ((i from))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring text i (+ i m))) i)
            (else (loop (+ i 1)))))))
(define (string-has? s sub) (and (index-of s sub 0) #t))
(define (header-value head name)
  (let ((i (index-of head (string-append "\r\n" name ": ") 0)))
    (and i (let* ((start (+ i 2 (string-length name) 2))
                  (end (index-of head "\r\n" start)))
             (substring head start end)))))
(define (head-path text)
  (let* ((sp1 (index-of text " " 0))
         (sp2 (and sp1 (index-of text " " (+ sp1 1)))))
    (if (and sp1 sp2) (substring text (+ sp1 1) sp2) "/")))
(define (request-key head) (or (header-value head "Sec-WebSocket-Key") ""))

;; what the servers saw: (port . head) newest first, and (path . reply) for
;; the close rows, reply = (opcode . unmasked payload) | 'timeout | 'eof
(define heads (box '()))
(define close-replies (box '()))

(define (bv-concat . bvs)
  (let* ((n (apply + (map bytevector-length bvs))) (out (make-bytevector n)))
    (let loop ((bs bvs) (o 0))
      (if (null? bs) out
          (let ((k (bytevector-length (car bs))))
            (bytevector-copy! (car bs) 0 out o k)
            (loop (cdr bs) (+ o k)))))))
;; an unmasked close frame from the server: code, then reason bytes
(define (close-frame code reason-bv)
  (let ((payload (bv-concat (bytevector (fxsrl code 8) (fxand code #xff)) reason-bv)))
    (bv-concat (bytevector #x88 (bytevector-length payload)) payload)))
(define text-frame-hi (bytevector #x81 2 104 105))

;; the frames in bv, parsed in order: ((fin? rsv opcode payload) ...), or
;; as many as are complete. Client frames are masked; the mask is removed.
(define (parse-client-frames bv)
  (let loop ((at 0) (acc '()))
    (if (< (- (bytevector-length bv) at) 2)
        (reverse acc)
        (let* ((b0 (bytevector-u8-ref bv at))
               (b1 (bytevector-u8-ref bv (+ at 1)))
               (fin? (fx= (fxand b0 #x80) #x80))
               (rsv (fxand b0 #x70))
               (op (fxand b0 #x0f))
               (masked? (fx= (fxand b1 #x80) #x80))
               (len (fxand b1 #x7f)))
          (if (or (not masked?) (>= len 126) (< (bytevector-length bv) (+ at 6 len)))
              (reverse acc)
              (let ((out (make-bytevector len)))
                (do ((i 0 (+ i 1))) ((= i len))
                  (bytevector-u8-set! out i
                    (fxxor (bytevector-u8-ref bv (+ at 6 i))
                           (bytevector-u8-ref bv (+ at 2 (mod i 4))))))
                (loop (+ at 6 len) (cons (list fin? rsv op out) acc))))))))
;; the first CLOSE frame among them, as (code . reason), or what was wrong
(define (close-of frames)
  (let loop ((fs frames))
    (cond ((null? fs) 'no-close-frame)
          ((memv (caddr (car fs)) '(9 10)) (loop (cdr fs)))
          (else
           (let ((f (car fs)))
             (cond ((not (car f)) 'close-without-fin)
                   ((not (fx= (cadr f) 0)) 'close-with-rsv)
                   ((not (fx= (caddr f) 8)) (list 'not-a-close (caddr f)))
                   ((< (bytevector-length (cadddr f)) 2) 'close-without-code)
                   (else (let ((p (cadddr f)))
                           (+ (* 256 (bytevector-u8-ref p 0)) (bytevector-u8-ref p 1))))))))))

;; a 101 head whose total length, terminator included, is exactly `total`
(define (head-of-size base total)
  (let ((pad (- total (string-length base) 11)))
    (string-append base "X-Pad: " (make-string pad #\x) "\r\n\r\n")))

(define (response-for head)
  (let* ((path (head-path head))
         (accept (ws-accept-key (request-key head)))
         (base (string-append "HTTP/1.1 101 Switching Protocols\r\n"
                              "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                              "Sec-WebSocket-Accept: " accept "\r\n")))
    (cond
      ((string=? path "/proto-chat") (string-append base "Sec-WebSocket-Protocol: chat\r\n\r\n"))
      ((string=? path "/proto-mqtt") (string-append base "Sec-WebSocket-Protocol: mqtt\r\n\r\n"))
      ((string=? path "/proto-other") (string-append base "Sec-WebSocket-Protocol: other\r\n\r\n"))
      ((string=? path "/proto-two") (string-append base "Sec-WebSocket-Protocol: chat, mqtt\r\n\r\n"))
      ((string=? path "/proto-twice") (string-append base "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n"))
      ((string=? path "/proto-Chat") (string-append base "Sec-WebSocket-Protocol: Chat\r\n\r\n"))
      ;; a space before the colon: not a header field at all (RFC 9112 5.1)
      ((string=? path "/proto-space-colon") (string-append base "Sec-WebSocket-Protocol : chat\r\n\r\n"))
      ((string=? path "/extension") (string-append base "Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"))
      ((string=? path "/extension-empty") (string-append base "Sec-WebSocket-Extensions: \r\n\r\n"))
      ((string=? path "/extension-dup") (string-append base "Sec-WebSocket-Extensions: \r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"))
      ((string=? path "/head-16384") (head-of-size base 16384))
      ((string=? path "/head-16385") (head-of-size base 16385))
      ((string=? path "/head-20000") (head-of-size base 20000))
      ((string=? path "/head-16384-then-frame") (head-of-size base 16384))
      (else (string-append base "\r\n")))))

(define (close-reply-for path)
  (cond
    ((string=? path "/close-valid") (close-frame 1000 (string->utf8 "bye")))
    ((string=? path "/close-1001") (close-frame 1001 (string->utf8 "going away")))
    ((string=? path "/close-multibyte") (close-frame 1000 (bytevector #xe5 #x86 #x8d #xe8 #xa7 #x81)))
    ((string=? path "/close-none") (close-frame 1000 (bytevector)))
    ((string=? path "/close-ff") (close-frame 1000 (bytevector #xff)))
    ((string=? path "/close-truncated") (close-frame 1000 (bytevector #xe2 #x82)))
    ((string=? path "/close-overlong") (close-frame 1000 (bytevector #xc0 #x80)))
    ((string=? path "/close-surrogate") (close-frame 1000 (bytevector #xed #xa0 #x80)))
    ((string=? path "/close-stray-cont") (close-frame 1000 (bytevector #x80)))
    ((string=? path "/close-bad-cont") (close-frame 1000 (bytevector #xe4 #x41 #x41)))
    ((string=? path "/close-above-max") (close-frame 1000 (bytevector #xf4 #x90 #x80 #x80)))
    (else (close-frame 1000 (bytevector)))))

(define (record-close! path v)
  (set-box! close-replies (cons (cons path v) (unbox close-replies))))

(define server-errors (box '()))
(define (condition-text e)
  (call-with-string-output-port
    (lambda (p)
      (when (and (condition? e) (who-condition? e)) (write (condition-who e) p) (display ": " p))
      (when (and (condition? e) (message-condition? e)) (display (condition-message e) p))
      (when (and (condition? e) (irritants-condition? e)) (display " " p) (write (condition-irritants e) p))
      (unless (condition? e) (write e p)))))
(define (serve! c on-port)
  (let ((pid
          (spawn
            (lambda ()
              ;; A SERVER THAT RAISES IS RECORDED, NOT SILENT: a row that reads
              ;; "not recorded" would otherwise hide the cause in this process.
              (guard (e (#t (set-box! server-errors (cons (condition-text e) (unbox server-errors)))))
                (let loop ((acc ""))
                  (receive (after 30000 (tcp-close! c))
                    (`#(tcp-data ,bv)
                      (let* ((text (string-append acc (utf8->string bv)))
                             (hend (index-of text "\r\n\r\n" 0)))
                        (if (not hend)
                            (loop text)
                            (let ((path (head-path text)))
                              (set-box! heads (cons (cons on-port text) (unbox heads)))
                              (cond
                                ((member path '("/head-then-frame" "/head-16384-then-frame"))
                                 (tcp-write! c (bv-concat (string->utf8 (response-for text)) text-frame-hi) #f)
                                 (sleep-ms 300) (tcp-close! c))
                                ((and (> (string-length path) 7) (string=? (substring path 0 7) "/close-"))
                                 (tcp-write! c (string->utf8 (response-for text)) #f)
                                 (sleep-ms 50)
                                 (tcp-write! c (close-reply-for path) #f)
                                 (let wait ((got (bytevector)))
                                   (receive (after 3000 (record-close! path 'timeout) (tcp-close! c))
                                     (`#(tcp-data ,bv2)
                                       (let* ((all (bv-concat got bv2))
                                              (v (close-of (parse-client-frames all))))
                                         (if (or (number? v) (symbol? v))
                                             (if (eq? v 'no-close-frame)
                                                 (wait all)
                                                 (begin (record-close! path v) (sleep-ms 50) (tcp-close! c)))
                                             (begin (record-close! path v) (sleep-ms 50) (tcp-close! c)))))
                                     (`#(tcp-eof) (record-close! path 'eof) (tcp-close! c))
                                     (`#(tcp-error ,e) (record-close! path 'error) (tcp-close! c)))))
                                (else
                                 (tcp-write! c (string->utf8 (response-for text)) #f)
                                 (sleep-ms 300)
                                 (tcp-close! c)))))))
                    (`#(tcp-eof) (tcp-close! c))
                    (`#(tcp-error ,e) (tcp-close! c)))))))))
    (conn-set-owner! c pid)
    (tcp-read-start! c)))

(define (start-servers!)
  (tcp-listen! "127.0.0.1" port 16 (lambda (c) (serve! c port)) 0)
  (tcp-listen! "127.0.0.1" port2 16 (lambda (c) (serve! c port2)) 0))

(define (url-on p path) (string-append "ws://127.0.0.1:" (number->string p) path))
(define (url path) (url-on port path))

;; EVERY SESSION IN ITS OWN PROCESS, with a unique tag, so a late answer from
;; a timed-out attempt cannot satisfy a later wait; a child that overruns is
;; killed. -> (ok . value) | (refused . message) | (raised-elsewhere . e) | timeout
(define (in-session u headers thunk)
  (let* ((main self)
         (tag (gensym))
         (child (spawn (lambda ()
                         (send main
                           (vector 'session tag
                             (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'ws-client-error))
                                        (cons 'refused (vector-ref e 1)))
                                       (#t (cons 'raised-elsewhere e)))
                               (cons 'ok (thunk (ws-connect u headers))))))))))
    (receive (after 12000 (kill child 'overrun) 'timeout)
      (`#(session ,t ,r) (when (eq? t tag) r)))))
(define (outcome path . headers)
  (in-session (url path) (if (pair? headers) (car headers) '())
              (lambda (w) (ws-close! w) 'connected)))
(define (connected? r) (equal? r '(ok . connected)))
(define (refused-for? r why) (and (pair? r) (eq? (car r) 'refused) (string-has? (cdr r) why)))

(define (wait-until pred ms)
  (let loop ((t 0))
    (cond ((pred) #t) ((>= t ms) #f) (else (sleep-ms 20) (loop (+ t 20))))))
(define (close-reply path)
  (if (wait-until (lambda () (assoc path (unbox close-replies))) 4000)
      (cdr (assoc path (unbox close-replies)))
      'not-recorded))

(start-scheduler
  (lambda ()
    (start-servers!)
    (sleep-ms 100)

    ;; ---- Host (RFC 6455 4.1) --------------------------------------------------
    (let ((r (outcome "/plain")))
      (check "twin: a plain 101 is accepted" (connected? r) r))
    (let ((host (cdr (assv port (unbox heads)))))
      (check "Host carries this URL's non-default port: 127.0.0.1:18852"
             (equal? (header-value host "Host") "127.0.0.1:18852") (header-value host "Host")))
    (let ((r (in-session (url-on port2 "/plain") '() (lambda (w) (ws-close! w) 'connected))))
      (check "twin: the second server accepts too" (connected? r) r))
    (let ((host (cdr (assv port2 (unbox heads)))))
      (check "and Host carries THAT port: 127.0.0.1:18853"
             (equal? (header-value host "Host") "127.0.0.1:18853") (header-value host "Host")))

    ;; ---- the handshake head's size (the client's own cap) ---------------------
    (let ((r (outcome "/head-16384")))
      (check "a 101 head of exactly 16384 bytes, terminator included, is accepted" (connected? r) r))
    (let ((r (outcome "/head-16385")))
      (check "a 101 head of 16385 bytes is refused as too large" (refused-for? r "handshake header too large") r))
    (let ((r (outcome "/head-20000")))
      (check "a complete 20000-byte head delivered in one write is refused as too large"
             (refused-for? r "handshake header too large") r))
    (let ((r (in-session (url "/head-then-frame") '() (lambda (w) (let ((m (ws-recv w))) (ws-close! w) m)))))
      (check "twin: a 101 followed in the same write by a text frame delivers that frame"
             (equal? r (cons 'ok (vector 'text "hi"))) r))
    (let ((r (in-session (url "/head-16384-then-frame") '() (lambda (w) (let ((m (ws-recv w))) (ws-close! w) m)))))
      (check "a 16384-byte head followed by a 4-byte frame is accepted (the frame is not head)"
             (equal? r (cons 'ok (vector 'text "hi"))) r))

    ;; ---- subprotocols and extensions (4.1) -------------------------------------
    (let ((r (outcome "/proto-chat")))
      (check "a 101 naming a subprotocol when none was requested is refused"
             (refused-for? r "handshake rejected") r))
    (let ((r (outcome "/proto-mqtt")))
      (check "whatever its name" (refused-for? r "handshake rejected") r))
    (let ((requested '(("Sec-WebSocket-Protocol" . "chat, mqtt"))))
      (let ((r (outcome "/proto-chat" requested)))
        (check "twin: a 101 choosing one of the requested subprotocols (chat of chat, mqtt) is accepted"
               (connected? r) r))
      (let ((r (outcome "/proto-mqtt" requested)))
        (check "twin: or the other one (mqtt)" (connected? r) r))
      (let ((r (outcome "/plain" requested)))
        (check "twin: or none" (connected? r) r))
      (let ((r (outcome "/proto-other" requested)))
        (check "a 101 choosing a subprotocol that was not requested is refused"
               (refused-for? r "handshake rejected") r))
      (let ((r (outcome "/proto-Chat" requested)))
        (check "a 101 choosing Chat when chat was requested is refused (tokens compare case-sensitively)"
               (refused-for? r "handshake rejected") r))
      (let ((r (outcome "/proto-two" requested)))
        (check "a 101 naming two subprotocols in one field is refused" (refused-for? r "handshake rejected") r))
      (let ((r (outcome "/proto-twice" requested)))
        (check "a 101 naming a subprotocol in two fields is refused" (refused-for? r "handshake rejected") r)))
    (let ((r (outcome "/proto-space-colon")))
      (check "a 101 whose Protocol field has a space before the colon is refused, not read past"
             (refused-for? r "handshake rejected") r))
    (let ((r (outcome "/extension")))
      (check "a 101 naming an extension (permessage-deflate) is refused" (refused-for? r "handshake rejected") r))
    (let ((r (outcome "/extension-dup")))
      (check "an empty Extensions field followed by a non-empty one is refused" (refused-for? r "handshake rejected") r))
    (let ((r (outcome "/extension-empty")))
      (check "twin: an empty Sec-WebSocket-Extensions names nothing: accepted" (connected? r) r))
    (let ((r (outcome "/plain" '(("Sec-WebSocket-Protocol" . "chat, chat")))))
      (check "offering the same subprotocol twice is refused before connecting (RFC 6455 4.1: each unique)"
             (refused-for? r "offered twice") r))
    (let ((r (outcome "/plain" '(("Sec-WebSocket-Protocol" . "chat") ("Sec-WebSocket-Protocol" . "chat")))))
      (check "also when it is offered once in each of two fields" (refused-for? r "offered twice") r))
    (let ((r (outcome "/plain" '(("Sec-WebSocket-Extensions" . "permessage-deflate")))))
      (check "requesting an extension is refused before connecting: this client implements none"
             (refused-for? r "managed by the client") r))

    ;; ---- close reason UTF-8 (5.5.1, 7.4.1, 8.1) ------------------------------
    (for-each
      (lambda (path label want)
        ;; let*: the reply is read AFTER the session ran, not before
        (let* ((session (in-session (url path) '() (lambda (w) (ws-recv w))))
               (reply (close-reply path)))
          (check (string-append "close with " label ": the client answers " (number->string want))
                 (eqv? reply want) reply session)))
      '("/close-valid" "/close-1001" "/close-multibyte" "/close-none"
        "/close-ff" "/close-truncated" "/close-overlong" "/close-surrogate"
        "/close-stray-cont" "/close-bad-cont" "/close-above-max")
      '("a valid ASCII reason (twin)" "code 1001 and a valid reason (twin: the code is echoed, not 1000)"
        "a valid multibyte reason (twin)" "no reason (twin)"
        "reason byte FF" "a truncated sequence E2 82" "an overlong encoding C0 80"
        "an encoded surrogate ED A0 80" "a stray continuation byte 80"
        "a bad continuation E4 41 41" "a code point above U+10FFFF (F4 90 80 80)")
      '(1000 1001 1000 1000 1007 1007 1007 1007 1007 1007 1007))

    (check "no server process raised" (null? (unbox server-errors)) (unbox server-errors))

    (if (zero? failures)
        (begin (display "ws-client-protocol: all tests passed\n") (exit 0))
        (begin (display "ws-client-protocol: ") (display failures) (display " failed\n") (exit 1)))))
