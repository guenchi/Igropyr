#!chezscheme
;;; (igropyr redis) -- non-blocking Redis client (RESP2).
;;;
;;; Every connection is one green process that owns a TCP link to the
;;; server. Callers send it commands as messages and park in receive
;;; until the reply arrives -- the OS thread never blocks, so hundreds
;;; of workers can wait on Redis while other requests keep being served.
;;; Commands from concurrent processes are pipelined over the single
;;; connection (written in order, replies matched FIFO), which is the
;;; idiomatic way to talk to a single-threaded Redis.
;;;
;;;   (define r (redis-connect "127.0.0.1" 6379))
;;;   (redis r "SET" "greeting" "hello")    ; -> "OK"
;;;   (redis r "GET" "greeting")            ; -> "hello"
;;;   (redis r "INCR" "counter")            ; -> 1
;;;   (redis r "GET" "missing")             ; -> #f       (nil)
;;;   (redis r "LRANGE" "l" 0 -1)           ; -> ("a" "b") (arrays -> lists)
;;;   (redis-close! r)
;;;
;;; Server errors (-ERR ...) raise #(redis-error ,message) in the caller.
;;; If the connection drops, waiting callers get the same error raised.

(library (igropyr redis)
  (export redis-connect redis redis-close!)
  (import (chezscheme) (igropyr actor) (igropyr libuv))

  (define connect-timeout-ms 5000)
  (define reply-timeout-ms 30000)
  (define max-reply-bytes (* 16 1024 1024))
  (define max-array-elements 65536)
  (define max-reply-items 65536)
  (define max-reply-depth 64)
  (define max-resp-line 1024)
  ;; A legal max-sized bulk also carries its length line and trailing CRLF.
  (define max-reply-buffer (+ max-reply-bytes max-resp-line 16))

  ;; ---- bytevector helpers ---------------------------------------------

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

  (define (find-crlf bv start)
    (let ((n (bytevector-length bv)))
      (let loop ((i start))
        (cond
          ((>= (+ i 1) n) #f)
          ((and (fx= (bytevector-u8-ref bv i) 13)
                (fx= (bytevector-u8-ref bv (+ i 1)) 10))
           i)
          (else (loop (+ i 1)))))))

  ;; strict UTF-8 check (RFC 3629); Chez's utf8->string substitutes
  ;; U+FFFD, so a binary value must be detected here to keep it raw
  (define (utf8-cont? bv i)
    (fx= (fxand (bytevector-u8-ref bv i) #xC0) #x80))

  (define (valid-utf8? bv)
    (let ((n (bytevector-length bv)))
      (let loop ((i 0))
        (if (>= i n)
            #t
            (let ((b (bytevector-u8-ref bv i)))
              (cond
                ((< b #x80) (loop (+ i 1)))
                ((< b #xC2) #f)
                ((< b #xE0)
                 (and (< (+ i 1) n) (utf8-cont? bv (+ i 1)) (loop (+ i 2))))
                ((< b #xF0)
                 (and (< (+ i 2) n) (utf8-cont? bv (+ i 1)) (utf8-cont? bv (+ i 2))
                      (let ((b1 (bytevector-u8-ref bv (+ i 1))))
                        (cond ((= b #xE0) (>= b1 #xA0))
                              ((= b #xED) (<= b1 #x9F))
                              (else #t)))
                      (loop (+ i 3))))
                ((< b #xF5)
                 (and (< (+ i 3) n) (utf8-cont? bv (+ i 1))
                      (utf8-cont? bv (+ i 2)) (utf8-cont? bv (+ i 3))
                      (let ((b1 (bytevector-u8-ref bv (+ i 1))))
                        (cond ((= b #xF0) (>= b1 #x90))
                              ((= b #xF4) (<= b1 #x8F))
                              (else #t)))
                      (loop (+ i 4))))
                (else #f)))))))

  ;; ---- RESP encoding ------------------------------------------------------

  (define (arg->bv a)
    (cond
      ((bytevector? a) a)
      ((string? a) (string->utf8 a))
      ((symbol? a) (string->utf8 (symbol->string a)))
      ((number? a) (string->utf8 (number->string a)))
      (else (assertion-violation 'redis "bad command argument" a))))

  (define crlf-bv (string->utf8 "\r\n"))

  (define (encode-command args)
    (let-values (((p get) (open-bytevector-output-port)))
      (put-bytevector p
        (string->utf8 (string-append "*" (number->string (length args)) "\r\n")))
      (for-each
        (lambda (a)
          (let ((bv (arg->bv a)))
            (put-bytevector p
              (string->utf8
                (string-append "$" (number->string (bytevector-length bv)) "\r\n")))
            (put-bytevector p bv)
            (put-bytevector p crlf-bv)))
        args)
      (get)))

  ;; ---- RESP parsing ---------------------------------------------------------
  ;; The parser returns 'more for incomplete input or a fatal marker for a
  ;; malformed/oversized reply. Counts are per top-level reply and prevent
  ;; shallow arrays from bypassing the nesting ceiling.
  (define (protocol-fatal msg) (vector 'redis-protocol-fatal msg))
  (define (protocol-fatal? v)
    (and (vector? v) (eq? (vector-ref v 0) 'redis-protocol-fatal)))

  (define (parse-reply buf pos depth count-box)
    (cond
      ((>= pos (bytevector-length buf)) (values 'more #f))
      ((>= (unbox count-box) max-reply-items)
       (values (protocol-fatal "reply has too many items") #f))
      (else
       (set-box! count-box (+ (unbox count-box) 1))
       (let ((eol (find-crlf buf (+ pos 1))))
         (cond
           ((not eol)
            (if (> (- (bytevector-length buf) pos) max-resp-line)
                (values (protocol-fatal "reply line too long") #f)
                (values 'more #f)))
           ((> (- eol pos) max-resp-line)
            (values (protocol-fatal "reply line too long") #f))
           (else
            (let ((line (utf8->string (bv-sub buf (+ pos 1) eol)))
                  (next (+ eol 2)))
              (case (integer->char (bytevector-u8-ref buf pos))
                ((#\+) (values line next))
                ((#\-) (values (vector 'redis-error line) next))
                ((#\:)
                 (let ((n (string->number line)))
                   (if (and n (integer? n) (exact? n))
                       (values n next)
                       (values (protocol-fatal "bad integer reply") #f))))
                ((#\$)
                 (let ((n (string->number line)))
                   (cond
                     ((not (and n (integer? n) (exact? n)))
                      (values (protocol-fatal "bad bulk length") #f))
                     ((= n -1) (values #f next))
                     ((< n 0) (values (protocol-fatal "bad bulk length") #f))
                     ((> n max-reply-bytes)
                      (values (protocol-fatal "bulk reply too large") #f))
                     ((< (bytevector-length buf) (+ next n 2))
                      (values 'more #f))
                     ((not (and (= (bytevector-u8-ref buf (+ next n)) 13)
                                (= (bytevector-u8-ref buf (+ next n 1)) 10)))
                      (values (protocol-fatal "bad bulk terminator") #f))
                     (else
                      (let ((raw (bv-sub buf next (+ next n))))
                        (values (if (valid-utf8? raw) (utf8->string raw) raw)
                                (+ next n 2)))))))
                ((#\*)
                 (let ((n (string->number line)))
                   (cond
                     ((not (and n (integer? n) (exact? n)))
                      (values (protocol-fatal "bad array length") #f))
                     ((= n -1) (values #f next))
                     ((or (< n 0) (> n max-array-elements))
                      (values (protocol-fatal "array reply too large") #f))
                     ((= n 0) (values '() next))
                     ((>= depth max-reply-depth)
                      (values (protocol-fatal "reply nesting too deep") #f))
                     (else
                      (let loop ((i 0) (p next) (acc '()))
                        (if (= i n)
                            (values (reverse acc) p)
                            (let-values (((v np)
                                          (parse-reply buf p (+ depth 1)
                                                       count-box)))
                              (cond
                                ((eq? v 'more) (values 'more #f))
                                ((protocol-fatal? v) (values v #f))
                                (else (loop (+ i 1) np (cons v acc)))))))))))
                (else (values (protocol-fatal "bad reply type") #f))))))))))

  ;; ---- connection process -----------------------------------------------------

  (define connection-lost (vector 'redis-error "connection lost"))

  ;; Each waiter is #(from ref live?). A caller that times out cancels
  ;; its exact ref (live? -> #f); its still-queued reply is then consumed
  ;; and discarded here instead of being delivered late into the caller's
  ;; mailbox. The entry stays in the FIFO so request/reply alignment is
  ;; preserved. Replies echo ref too, closing the small race where a
  ;; reply is delivered just as the caller's timeout fires (a bare pid
  ;; match could then mis-read that reply on the caller's next call).
  (define (reply-to! waiter v)
    (when (vector-ref waiter 2)
      (send (vector-ref waiter 0)
            (vector 'redis-reply (vector-ref waiter 1) v))))

  (define (conn-loop c buf waiters)
    (receive
      (`#(redis-cmd ,args ,ref ,from)
        (if (eq? (conn-state c) 'open)
            (begin
              (tcp-write! c (encode-command args) #f)
              (conn-loop c buf (append waiters (list (vector from ref #t)))))
            (begin
              (send from (vector 'redis-reply ref connection-lost))
              (conn-loop c buf waiters))))
      (`#(redis-cancel ,ref ,from)
        (for-each
          (lambda (w) (when (and (eq? (vector-ref w 0) from)
                                 (eq? (vector-ref w 1) ref))
                        (vector-set! w 2 #f)))
          waiters)
        (conn-loop c buf waiters))
      (`#(tcp-data ,bv)
        (if (> (+ (bytevector-length buf) (bytevector-length bv))
               max-reply-buffer)
            (protocol-fail c waiters "reply exceeds size limit")
            (let drain ((buf (bv-append buf bv)) (waiters waiters))
              (let-values (((v next) (parse-reply buf 0 0 (box 0))))
                (cond
                  ((eq? v 'more) (conn-loop c buf waiters))
                  ((protocol-fatal? v)
                   (protocol-fail c waiters (vector-ref v 1)))
                  (else
                   (when (pair? waiters) (reply-to! (car waiters) v))
                   (drain (bv-sub buf next (bytevector-length buf))
                          (if (pair? waiters) (cdr waiters) '()))))))))
      (`#(redis-quit)
        (for-each (lambda (w) (reply-to! w connection-lost)) waiters)
        (tcp-close! c))
      (`#(tcp-eof) (fail-all c buf waiters))
      (`#(tcp-error ,e) (fail-all c buf waiters))))

  ;; The connection dropped: fail everyone waiting, close the socket --
  ;; and KEEP SERVING. The redis-cmd clause above answers instantly with
  ;; connection-lost once the state leaves 'open; exiting here instead
  ;; would leave that fast path unreachable, and every later call would
  ;; send into a dead mailbox and park the full 30s reply timeout before
  ;; raising a misleading "reply timeout". Callers get an immediate,
  ;; accurate error and can rebuild the connection.
  (define (fail-all c buf waiters)
    (for-each (lambda (w) (reply-to! w connection-lost)) waiters)
    (tcp-close! c)
    (conn-loop c buf '()))

  (define (protocol-fail c waiters msg)
    (let ((e (vector 'redis-error (string-append "protocol error: " msg))))
      (for-each (lambda (w) (reply-to! w e)) waiters)
      (tcp-close! c)
      (conn-loop c (make-bytevector 0) '())))

  ;; ---- public API ----------------------------------------------------------------

  ;; Connect and return the connection (a process). Raises on failure.
  (define (redis-connect host port)
    (let ((caller self))
      (let ((pid (spawn
                   (lambda ()
                     (tcp-connect! host port self)
                     (receive (after connect-timeout-ms
                                 (send caller (vector 'redis-up self 'timeout)))
                       (`#(tcp-connected ,c)
                         (tcp-read-start! c)
                         (send caller (vector 'redis-up self 'ok))
                         (conn-loop c (make-bytevector 0) '()))
                       (`#(tcp-connect-failed ,e)
                         (send caller (vector 'redis-up self e))))))))
        (receive (after (+ connect-timeout-ms 1000)
                    (raise (vector 'redis-error "connect timeout")))
          (`#(redis-up ,pid ,status)
            (if (eq? status 'ok)
                pid
                (raise (vector 'redis-error
                               (if (number? status)
                                   (uv-strerror status)
                                   "connect timeout")))))))))

  ;; Run one command; blocks only the calling green process. The per-call
  ;; ref (a gensym) is echoed in the reply; on timeout the connection is
  ;; told to drop the still-pending reply, and the ref match means even a
  ;; reply already in the mailbox cannot be read by a later call.
  (define (redis rc . args)
    (let ((ref (gensym)))
      (send rc (vector 'redis-cmd args ref self))
      (receive (after reply-timeout-ms
                  (send rc (vector 'redis-cancel ref self))
                  (raise (vector 'redis-error "reply timeout")))
        (`#(redis-reply ,@ref ,v)
          (if (and (vector? v) (eq? (vector-ref v 0) 'redis-error))
              (raise v)
              v)))))

  (define (redis-close! rc)
    (send rc (vector 'redis-quit)))
)
