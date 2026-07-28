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
  (import (chezscheme) (igropyr actor) (igropyr buffer) (igropyr libuv))

  (define connect-timeout-ms 5000)
  (define reply-timeout-ms 30000)

  ;; ---- bytevector helpers ---------------------------------------------

  (define (bv-sub bv start end)
    (let ((r (make-bytevector (- end start))))
      (bytevector-copy! bv start r 0 (- end start))
      r))

  ;; Positions are relative to base, so parsing can work directly against
  ;; the amortized inbuf without copying the accumulated reply per segment.
  (define (find-crlf bv base limit start)
    (let loop ((i start))
      (cond
        ((>= (+ i 1) limit) #f)
        ((and (fx= (bytevector-u8-ref bv (+ base i)) 13)
              (fx= (bytevector-u8-ref bv (+ base i 1)) 10))
         i)
        (else (loop (+ i 1))))))

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

  ;; Resumable parse state is #(position array-stack). Each
  ;; stack frame is (remaining . reversed-values). Completed array elements
  ;; stay in the state when more bytes are needed, so a one-byte-at-a-time
  ;; server cannot make us reparse an ever-growing prefix quadratically.
  ;; -> (values 'done #(value consumed)) | (values 'more state)
  (define (parse-reply buf base limit state)
    (letrec
      ((more
         (lambda (pos stack)
           (values 'more (vector pos stack))))
       (accept
         (lambda (v pos stack)
           (if (null? stack)
               (values 'done (vector v pos))
               (let* ((frame (car stack))
                      (remaining (car frame))
                      (acc (cdr frame)))
                 (if (= remaining 1)
                     (accept (reverse (cons v acc)) pos (cdr stack))
                     (loop pos
                           (cons (cons (- remaining 1) (cons v acc))
                                 (cdr stack))))))))
       (loop
         (lambda (pos stack)
           (if (>= pos limit)
               (more pos stack)
               (let ((eol (find-crlf buf base limit (+ pos 1))))
                 (if (not eol)
                     (more pos stack)
                     (let ((line (utf8->string
                                   (bv-sub buf (+ base pos 1) (+ base eol))))
                           (next (+ eol 2)))
                       (case (integer->char (bytevector-u8-ref buf (+ base pos)))
                         ((#\+) (accept line next stack))
                         ((#\-) (accept (vector 'redis-error line) next stack))
                         ((#\:) (accept (string->number line) next stack))
                         ((#\$)
                          (let ((n (string->number line)))
                            (cond
                              ((not n)
                               (accept (vector 'redis-error "bad bulk length")
                                       next stack))
                              ((< n 0) (accept #f next stack))
                              ((< limit (+ next n 2)) (more pos stack))
                              ((not (and
                                      (= (bytevector-u8-ref buf (+ base next n)) 13)
                                      (= (bytevector-u8-ref buf (+ base next n 1)) 10)))
                               (accept (vector 'redis-error "bad bulk terminator")
                                       (+ next n 2) stack))
                              (else
                               (let ((raw (bv-sub buf (+ base next)
                                                  (+ base next n))))
                                 (accept
                                   (if (valid-utf8? raw) (utf8->string raw) raw)
                                   (+ next n 2) stack))))))
                         ((#\*)
                          (let ((n (string->number line)))
                            (cond
                              ((not n)
                               (accept (vector 'redis-error "bad array length")
                                       next stack))
                              ((< n 0) (accept #f next stack))
                              ((= n 0) (accept '() next stack))
                              (else (loop next (cons (cons n '()) stack))))))
                         (else
                          (accept (vector 'redis-error "bad reply type")
                                  next stack))))))))))
      (if state
          (loop (vector-ref state 0) (vector-ref state 1))
          (loop 0 '()))))

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

  (define (conn-loop c buf waiters parse-state)
    (receive
      (`#(redis-cmd ,args ,ref ,from)
        (if (eq? (conn-state c) 'open)
            (begin
              (tcp-write! c (encode-command args) #f)
        (conn-loop c buf (append waiters (list (vector from ref #t))) parse-state))
            (begin
              (send from (vector 'redis-reply ref connection-lost))
              (conn-loop c buf waiters parse-state))))
      (`#(redis-cancel ,ref ,from)
        (for-each
          (lambda (w) (when (and (eq? (vector-ref w 0) from)
                                 (eq? (vector-ref w 1) ref))
                        (vector-set! w 2 #f)))
          waiters)
        (conn-loop c buf waiters parse-state))
      (`#(tcp-data ,bv)
        (inbuf-append! buf bv)
        (let drain ((waiters waiters) (state parse-state))
          (let-values (((tag payload)
                        (parse-reply (inbuf-bv buf) (inbuf-start buf)
                                     (inbuf-length buf) state)))
            (if (eq? tag 'more)
                (conn-loop c buf waiters payload)
                (let ((v (vector-ref payload 0))
                      (next (vector-ref payload 1)))
                  (when (pair? waiters) (reply-to! (car waiters) v))
                  (inbuf-consume! buf next)
                  (drain (if (pair? waiters) (cdr waiters) '()) #f))))))
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
    (conn-loop c (make-inbuf) '() #f))

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
                          (conn-loop c (make-inbuf) '() #f))
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
