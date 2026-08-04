#!chezscheme
;;; (igropyr qjspool) on the wire, against FAKE workers.
;;;
;;; The worker side of this protocol is a TCP server, so the whole client
;;; can be driven by a stand-in that speaks frames and never boots an
;;; engine. That is what makes these cases runnable EVERYWHERE -- unlike
;;; test/qjspool.sc, this one needs no libquickjs -- and it is where the
;;; failure modes actually live: a peer that dribbles a response, one that
;;; announces a frame it will never send, one that answers nothing, one
;;; that talks when nothing was asked.
;;;
;;; The frame codec here is written a SECOND time, independently of the
;;; library's. Two implementations of the same format disagree loudly; one
;;; implementation tested against itself agrees with its own bugs.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr buffer)
        (igropyr qjspool))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c) (if c (ok label) (fail label)))

;; ---- an independent codec ------------------------------------------------

(define (put-u32! bv i n) (bytevector-u32-set! bv i n (endianness big)))
(define (get-u32 bv i) (bytevector-u32-ref bv i (endianness big)))
(define (get-u16 bv i) (bytevector-u16-ref bv i (endianness big)))

(define (frame status body-bv)
  (let* ((n (+ 1 (bytevector-length body-bv)))
         (bv (make-bytevector (+ 4 n))))
    (put-u32! bv 0 n)
    (bytevector-u8-set! bv 4 status)
    (bytevector-copy! body-bv 0 bv 5 (bytevector-length body-bv))
    bv))

;; the request the library sends -> (fn . json), or #f if incomplete
(define (take-request! buf)
  (and (>= (inbuf-length buf) 4)
       (let ((n (get-u32 (inbuf-sub buf 0 4) 0)))
         (and (>= (inbuf-length buf) (+ 4 n))
              (let ((body (inbuf-sub buf 4 (+ 4 n))))
                (inbuf-consume! buf (+ 4 n))
                (let ((fl (get-u16 body 0)))
                  (cons (utf8->string (sub body 2 fl))
                        (utf8->string (sub body (+ 2 fl) (- n 2 fl))))))))))

(define (sub bv from n)
  (let ((out (make-bytevector n))) (bytevector-copy! bv from out 0 n) out))

;; ---- fake workers --------------------------------------------------------

(define (fake-listen! port handler)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid (spawn (lambda () (handler c (make-inbuf))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))))

;; read one request, hand it to reply! (which writes whatever it likes),
;; repeat. reply! returning 'stop ends the connection.
(define (request-server reply!)
  (lambda (c buf)
    (let loop ()
      (receive
        (`#(tcp-data ,bv)
          (inbuf-append! buf bv)
          (let ((req (take-request! buf)))
            (if (not req)
                (loop)
                (if (eq? 'stop (reply! c req)) (tcp-close! c) (loop)))))
        (`#(tcp-eof) (tcp-close! c))
        (`#(tcp-error ,e) (tcp-close! c))))))

;; echoes what it was asked, so the REQUEST encoding is checked too: a
;; wrong length or offset would come back as the wrong function name
(define (echo-reply! c req)
  (tcp-write! c (frame 0 (string->utf8 (string-append (car req) "|" (cdr req)))) #f)
  'ok)

;; the same answer, delivered in two writes with a gap, so the client has
;; to reassemble across packets rather than assume one read = one frame
(define (dribble-reply! c req)
  (let* ((full (frame 0 (string->utf8 (string-append (car req) "|" (cdr req)))))
         (n (bytevector-length full))
         (cut 3))                       ; splits the LENGTH PREFIX itself
    (tcp-write! c (sub full 0 cut) #f)
    (sleep-ms 120)
    (tcp-write! c (sub full cut (- n cut)) #f)
    'ok))

;; announces a body it will never send, and one past the client's cap
(define (huge-reply! c req)
  (let ((bv (make-bytevector 4)))
    (put-u32! bv 0 (+ (* 64 1024 1024) 1))
    (tcp-write! c bv #f))
  'ok)

;; answers nothing at all: only a deadline can end this
(define (mute-reply! c req) 'ok)

;; writes half a frame and closes
(define (truncate-reply! c req)
  (let* ((full (frame 0 (string->utf8 "half")))
         (n (bytevector-length full)))
    (tcp-write! c (sub full 0 (- n 2)) #f))
  'stop)

(define base 19741)
(define (p n) (+ base n))

(start-scheduler
  (lambda ()
    (fake-listen! (p 0) (request-server echo-reply!))
    (fake-listen! (p 1) (request-server dribble-reply!))
    (fake-listen! (p 2) (request-server huge-reply!))
    (fake-listen! (p 3) (request-server mute-reply!))
    (fake-listen! (p 4) (request-server truncate-reply!))
    ;; Talks before anything is asked -- and what it says is a PERFECTLY
    ;; WELL-FORMED response. That is the case worth testing: junk that fails
    ;; to parse is refused by the frame limit whatever the client does with
    ;; it, so it cannot tell the two behaviours apart. A valid frame nobody
    ;; asked for is what gets attached to the next request's reply.
    ;;
    ;; Only the FIRST connection does it, so the pool's recovery is
    ;; observable too: the replacement serves normally.
    (let ((first? (box #t)))
      (fake-listen! (p 5)
        (lambda (c buf)
          (if (unbox first?)
              (begin
                (set-box! first? #f)
                (tcp-write! c (frame 0 (string->utf8 "JUNK")) #f)
                (let loop () (receive (`#(tcp-eof) (tcp-close! c))
                                      (`#(tcp-error ,e) (tcp-close! c))
                                      (`#(tcp-data ,bv) (loop)))))
              ((request-server echo-reply!) c buf)))))

    ;; ---- the round trip, both directions ---------------------------------
    (let ((c (qjspool-connect "127.0.0.1" (p 0) '((render-timeout-ms . 2000)))))
      (let-values (((k v) (qjspool-render c "renderPost" "{\"a\":1}")))
        (check "the request arrives with its function name and props intact"
               (and k (string=? v "renderPost|{\"a\":1}"))))
      ;; a name and a body that are not ASCII: the lengths are BYTES, and a
      ;; codec that counted characters would truncate exactly here
      (let-values (((k v) (qjspool-render c "渲染" "{\"t\":\"日本語\"}")))
        (check "multi-byte names and props survive the length fields"
               (and k (string=? v "渲染|{\"t\":\"日本語\"}"))))
      (let-values (((k v) (qjspool-render c "empty" "")))
        (check "an empty props string is a legal frame"
               (and k (string=? v "empty|"))))
      (qjspool-close! c))

    ;; ---- reassembly across packets ---------------------------------------
    (let ((c (qjspool-connect "127.0.0.1" (p 1) '((render-timeout-ms . 3000)))))
      (let-values (((k v) (qjspool-render c "split" "{}")))
        (check "a response split mid-LENGTH-PREFIX is reassembled"
               (and k (string=? v "split|{}"))))
      (qjspool-close! c))

    ;; ---- a length nobody will ever satisfy --------------------------------
    ;; Refused when the prefix is READ, not waited on: a client that waits
    ;; for the announced body holds the connection until its deadline for
    ;; every such frame, which is a free way to occupy a pool.
    (let* ((t0 (now-ms))
           (c (qjspool-connect "127.0.0.1" (p 2) '((render-timeout-ms . 4000)))))
      (let-values (((k v) (qjspool-render c "big" "{}")))
        (let ((took (- (now-ms) t0)))
          (check "an oversized announced frame fails immediately, not on the deadline"
                 (and (not k) (< took 2000)))
          (display (string-append "  [info] oversized frame rejected after "
                                  (number->string took) "ms (deadline was 4000)\n")))))

    ;; ---- a worker that answers nothing ------------------------------------
    (let* ((c (qjspool-connect "127.0.0.1" (p 3) '((render-timeout-ms . 600))))
           (t0 (now-ms)))
      (let-values (((k v) (qjspool-render c "quiet" "{}")))
        (let ((took (- (now-ms) t0)))
          (check "a silent worker ends on the render deadline"
                 (and (not k) (>= took 500) (< took 2500)))
          (display (string-append "  [info] silent worker gave up after "
                                  (number->string took) "ms (configured 600)\n")))))

    ;; ---- a response cut short ---------------------------------------------
    (let ((c (qjspool-connect "127.0.0.1" (p 4) '((render-timeout-ms . 1500)))))
      (let-values (((k v) (qjspool-render c "cut" "{}")))
        (check "a truncated response is an error, not a wait" (not k))))

    ;; ---- bytes nobody asked for -------------------------------------------
    ;; A worker speaks only when asked. Anything else means the stream is
    ;; already out of step, and carrying those bytes forward would attach
    ;; them to the NEXT reply -- so the connection goes, and the pool
    ;; rebuilds. Against a client that buffers them instead, the render
    ;; below returns the junk as if it were HTML.
    (let ((pool (qjspool (list (cons "127.0.0.1" (p 5)))
                         '((render-timeout-ms . 600) (checkout-timeout-ms . 1500)))))
      (sleep-ms 400)
      (let-values (((k v) (qjspool-render pool "after-junk" "{}")))
        ;; buffering them instead returns (#t . "JUNK"): a render that
        ;; SUCCEEDS with somebody else's bytes, which is worse than any
        ;; failure the pool knows how to recover from
        (check "an unsolicited frame never becomes the next reply"
               (not (and k (string=? v "JUNK")))))
      (let ((st (guard (e (#t '())) (qjspool-stats pool))))
        (check "the pool noticed it lost a connection"
               (>= (cond ((assq 'connections-lost st) => cdr) (else 0)) 1)))
      ;; the replacement connection is a normal worker: the pool recovers
      (let retry ((i 0))
        (let-values (((k v) (qjspool-render pool "recovered" "{}")))
          (cond ((and k (string=? v "recovered|{}"))
                 (ok "the rebuilt connection serves normally"))
                ((< i 5) (sleep-ms 300) (retry (+ i 1)))
                (else (fail "the pool never recovered after the drop" v)))))
      (qjspool-close! pool))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "qjspool-wire: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
