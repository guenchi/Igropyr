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

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp) (igropyr buffer)
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

;; id defaults to 0 -- the first request on a connection -- so the cases
;; that only care about framing stay short
(define (frame status body-bv . rest)
  (let* ((id (if (pair? rest) (car rest) 0))
         (n (+ 4 1 (bytevector-length body-bv)))
         (bv (make-bytevector (+ 4 n))))
    (put-u32! bv 0 n)
    (put-u32! bv 4 id)
    (bytevector-u8-set! bv 8 status)
    (bytevector-copy! body-bv 0 bv 9 (bytevector-length body-bv))
    bv))

;; the request the library sends -> (fn . json), or #f if incomplete
(define (take-request! buf)
  (and (>= (inbuf-length buf) 4)
       (let ((n (get-u32 (inbuf-sub buf 0 4) 0)))
         (and (>= (inbuf-length buf) (+ 4 n))
              (let ((body (inbuf-sub buf 4 (+ 4 n))))
                (inbuf-consume! buf (+ 4 n))
                (let ((id (get-u32 body 0))
                      (fl (get-u16 body 4)))
                  (list id
                        (utf8->string (sub body 6 fl))
                        (utf8->string (sub body (+ 6 fl) (- n 6 fl))))))))))

;; a request is (id fn json)
(define (req-id r) (car r))
(define (req-fn r) (cadr r))
(define (req-json r) (caddr r))

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
  (tcp-write! c (frame 0 (string->utf8 (string-append (req-fn req) "|" (req-json req)))
                  (req-id req))
              #f)
  'ok)

;; the same answer, delivered in two writes with a gap, so the client has
;; to reassemble across packets rather than assume one read = one frame
(define (dribble-reply! c req)
  (let* ((full (frame 0 (string->utf8 (string-append (req-fn req) "|" (req-json req)))
                  (req-id req)))
         (n (bytevector-length full))
         (cut 3))                       ; splits the LENGTH PREFIX itself
    (tcp-write! c (sub full 0 cut) #f)
    (sleep-ms 120)
    (tcp-write! c (sub full cut (- n cut)) #f)
    'ok))

;; answers correctly, and then appends a SECOND complete response in the
;; same write. The extra frame lands in the client's buffer rather than in
;; its mailbox, which is a different route to the same desync: the idle
;; check only sees messages, so bytes already read past cannot be caught
;; there.
(define (tailgate-reply! c req)
  (let* ((mine (frame 0 (string->utf8 (string-append (req-fn req) "|" (req-json req)))
                  (req-id req)))
         (extra (frame 0 (string->utf8 "TAILGATE") (req-id req)))
         (n1 (bytevector-length mine)) (n2 (bytevector-length extra))
         (both (make-bytevector (+ n1 n2))))
    (bytevector-copy! mine 0 both 0 n1)
    (bytevector-copy! extra 0 both n1 n2)
    (tcp-write! c both #f))
  'ok)

;; Answers correctly, and then -- after a delay -- writes a SECOND frame
;; carrying the id of the request it already answered. By the time it
;; arrives the connection has been handed back and lent to somebody else,
;; so the "buffer must be empty" check cannot see it: it was not read past,
;; it had not been sent yet. Only the id ties a response to a request.
;; The first request is answered at once and an extra frame carrying ITS id
;; is scheduled for 250ms later. The second is answered only after 600ms --
;; so the extra lands while the connection is WAITING for the second answer,
;; which is the only arrangement in which a buffer check cannot help: the
;; frame was not read past, it had not been sent yet.
(define late-seen (box 0))
(define (late-extra-reply! c req)
  (set-box! late-seen (+ 1 (unbox late-seen)))
  (if (= 1 (unbox late-seen))
      (begin
        (tcp-write! c (frame 0 (string->utf8 (string-append (req-fn req) "|" (req-json req)))
                        (req-id req))
                    #f)
        (spawn (lambda ()
                 (sleep-ms 250)
                 (guard (e (#t 'gone))
                   (tcp-write! c (frame 0 (string->utf8 "LATE") (req-id req)) #f)))))
      (spawn (lambda ()
               (sleep-ms 600)
               (guard (e (#t 'gone))
                 (tcp-write! c (frame 0 (string->utf8 "REAL-SECOND") (req-id req)) #f)))))
  'ok)

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
    (fake-listen! (p 7) (request-server tailgate-reply!))
    (fake-listen! (p 8) (request-server late-extra-reply!))
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

    ;; mute on its first connection, an ordinary worker afterwards
    (let ((first? (box #t)))
      (fake-listen! (p 6)
        (lambda (c buf)
          (if (unbox first?)
              (begin (set-box! first? #f) ((request-server mute-reply!) c buf))
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

    ;; ---- a second response riding along with the first ---------------------
    ;;
    ;; Same desync as the unsolicited frame above, by the other route: the
    ;; extra bytes were already read into the buffer while the first
    ;; response was being taken, so they never arrive as a message and the
    ;; idle check cannot see them. Left there, the NEXT render finds a
    ;; complete frame waiting before its own answer can arrive and returns
    ;; it -- a render that succeeds with the previous exchange's leftovers.
    ;; Stated as an invariant over BOTH calls, because which one catches it
    ;; depends on how the peer's single write is delivered: coalesced, the
    ;; leftover is seen while the first response is taken and that render
    ;; fails; split, the first succeeds and the second finds the stale
    ;; frame. Either is correct. What must never happen is that a render
    ;; RETURNS the tailgating bytes.
    (let ((c (qjspool-connect "127.0.0.1" (p 7) '((render-timeout-ms . 1500)))))
      (let-values (((k1 v1) (qjspool-render c "first" "{}")))
        (let-values (((k2 v2) (qjspool-render c "second" "{}")))
          (check "a tailgating frame is never returned as a render"
                 (not (or (and k1 (string=? v1 "TAILGATE"))
                          (and k2 (string=? v2 "TAILGATE")))))
          (check "and the desync is reported rather than carried forward"
                 (or (not k1) (not k2))))))

    ;; ---- an extra response that arrives LATE --------------------------
    ;;
    ;; The other half of the tailgating case, and the half a buffer check
    ;; cannot reach: the extra frame is written after the first answer has
    ;; been delivered, so it lands while the connection is serving the NEXT
    ;; request. Nothing about its shape says it is stale -- only the id it
    ;; carries, which belongs to a request this connection has finished.
    (let ((c (qjspool-connect "127.0.0.1" (p 8) '((render-timeout-ms . 2000)))))
      (let-values (((k1 v1) (qjspool-render c "first" "{}")))
        (check "the first answer is the one that was asked for"
               (and k1 (string=? v1 "first|{}"))))
      ;; no pause: the second request goes out while the extra is still on
      ;; its way, so the connection is inside read-response when it lands
      (let-values (((k2 v2) (qjspool-render c "second" "{}")))
        (check "a stale response is never returned as the next render"
               (not (and k2 (string=? v2 "LATE"))))))

    ;; ---- a borrower KILLED mid-render -------------------------------------
    ;;
    ;; A render holds its worker as a lease, and @kill discards
    ;; dynamic-wind winders -- so the check-in never runs and the pool's
    ;; monitor is the only path back. This is the first non-SQL driver to
    ;; take that path, and if it were missed the pool would count the
    ;; worker in use forever: one endpoint, one lease, nothing left to
    ;; lend, and every later render failing on the checkout deadline.
    ;; The render deadline is set FAR beyond this check's own patience on
    ;; purpose. A connection whose render times out discards itself and is
    ;; rebuilt, which heals the pool too -- so a short one would let that
    ;; path pass the test and the monitor could be broken without anyone
    ;; noticing. At a minute, nothing but the reclaim can finish in time.
    (let ((pool (qjspool (list (cons "127.0.0.1" (p 6)))
                         '((render-timeout-ms . 60000)
                           (checkout-timeout-ms . 700))))
          (me self))
      (sleep-ms 400)
      (let ((victim (spawn (lambda ()
                             (let-values (((k v) (qjspool-render pool "hangs" "{}")))
                               (send me (vector 'came-back k)))))))
        (sleep-ms 400)
        (kill victim 'reaped-mid-render)
        ;; the reclaim is not instant: the monitor fires, the connection is
        ;; discarded and rebuilt, and only then is there a worker to lend
        (let retry ((i 0))
          (let-values (((k v) (qjspool-render pool "after-kill" "{}")))
            (cond ((and k (string=? v "after-kill|{}"))
                   (ok "a killed borrower's worker comes back to the pool"))
                  ((< i 4) (sleep-ms 300) (retry (+ i 1)))
                  (else (fail "the lease was never reclaimed" v)))))
        (let ((st (guard (e (#t '())) (qjspool-stats pool))))
          (check "and nothing is left leased"
                 (equal? (cond ((assq 'in-use st) => cdr) (else #f)) 0))))
      (qjspool-close! pool))

    (sleep-ms 100)
    (if (zero? failures)
        (begin (display "qjspool-wire: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
