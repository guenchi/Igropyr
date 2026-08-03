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
  (export redis-connect redis redis-close! redis-set-limits!)
  (import (chezscheme) (igropyr actor) (igropyr buffer) (igropyr libuv))

  (define connect-timeout-ms 5000)
  (define reply-timeout-ms 30000)
  ;; Ceilings on what a reply may cost before it is refused. These bound a
  ;; SERVER, which is normally trusted -- so they are set where a legitimate
  ;; Redis reply never reaches them, and a compromised or confused peer
  ;; cannot spend the client without bound. Getting that balance wrong in
  ;; the strict direction is the greater danger: LRANGE, SMEMBERS, HGETALL
  ;; and KEYS routinely return hundreds of thousands of elements, and Redis
  ;; permits a single value up to 512 MiB, so a client that refuses those
  ;; has limited what the server is allowed to say rather than what an
  ;; attacker is.
  ;;
  ;; Depth and line length are different in kind: nesting past a few dozen,
  ;; or a line -- not a bulk payload, a LINE -- past a kilobyte, is a
  ;; malformed reply rather than a large one, so those stay tight.
  (define max-reply-bytes (* 512 1024 1024))   ; one bulk value
  (define max-array-elements 4000000)          ; elements in one array
  (define max-reply-items 8000000)             ; values in one whole reply
  (define max-reply-depth 64)                  ; nested arrays
  ;; 8 KiB, not 1: no RESP line is legitimately long, but a server error
  ;; message echoing a long key is a line, and refusing one would turn a
  ;; server-side complaint into a dropped connection.
  (define max-resp-line 8192)                  ; a +/-/:/$/* line
  ;; A legal max-sized bulk also carries its length line and trailing CRLF.
  (define max-reply-buffer (+ max-reply-bytes max-resp-line 16))

  ;; Lower them for a client talking to something it trusts less, or raise
  ;; them past an unusual workload. #f leaves one alone. Same shape as
  ;; node-set-limits! and static-cache-limits!; also what lets a test ask
  ;; for a ceiling it can actually reach.
  (define (redis-set-limits! bulk-bytes array-elements items depth line)
    (define (check who v)
      (unless (and (integer? v) (exact? v) (> v 0))
        (assertion-violation 'redis-set-limits!
          (string-append who " limit must be a positive integer") v)))
    (when bulk-bytes
      (check "bulk-bytes" bulk-bytes)
      (set! max-reply-bytes bulk-bytes)
      (set! max-reply-buffer (+ max-reply-bytes max-resp-line 16)))
    (when array-elements
      (check "array-elements" array-elements)
      (set! max-array-elements array-elements))
    (when items (check "items" items) (set! max-reply-items items))
    (when depth (check "depth" depth) (set! max-reply-depth depth))
    (when line
      (check "line" line)
      (set! max-resp-line line)
      (set! max-reply-buffer (+ max-reply-bytes max-resp-line 16)))
    (void))

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

  ;; A reply the parser refuses outright: the stream is desynchronised
  ;; after one, so there is nothing to resynchronise to and the connection
  ;; has to go. Kept distinct from #(redis-error ...) so a message the
  ;; SERVER sent is never mistaken for a protocol violation by the client.
  (define (protocol-fatal msg) (vector 'redis-protocol-fatal msg))
  (define (protocol-fatal? v)
    (and (vector? v) (eq? (vector-ref v 0) 'redis-protocol-fatal)))

  ;; Resumable parse state is
  ;;   #(position array-stack line-scan pending-bulk items)
  ;;
  ;; The retained line-scan cursor is what keeps a fragmented line from
  ;; being rescanned from its start on every segment. With max-resp-line in
  ;; place that can no longer be a quadratic blowup -- the cap bounds the
  ;; rescan to a few kilobytes -- so the cursor is now an economy rather
  ;; than a defence. It stays because it is free and correct; the ceiling
  ;; is what the guarantee rests on.
  ;; Each stack frame is (remaining . reversed-values). Completed array
  ;; elements, the CRLF scan cursor, and an already parsed bulk length all
  ;; stay in the state when more bytes are needed. Thus neither a fragmented
  ;; line nor a fragmented bulk body is rescanned from its beginning.
  ;; `items' counts every value produced for the reply being assembled, so
  ;; a flat million-element array is bounded even though its depth is 1.
  ;; -> (values 'done #(value consumed)) | (values 'more state)
  ;;  | (values 'fatal message)
  (define (parse-reply buf base limit state)
    (letrec
      ((more-line
         (lambda (pos stack items)
           ;; Retain one byte of overlap so a trailing CR can pair with an
           ;; LF in the next segment.
           (values 'more
             (vector pos stack (max (+ pos 1) (- limit 1)) #f items))))
       (more-bulk
         (lambda (pos stack next n items)
           (values 'more (vector pos stack #f (vector next n) items))))
       (fatal (lambda (msg) (values 'fatal msg)))
       (accept
         (lambda (v pos stack items)
           (if (> items max-reply-items)
               (fatal "reply has too many items")
               (if (null? stack)
                   (values 'done (vector v pos))
                   (let* ((frame (car stack))
                          (remaining (car frame))
                          (acc (cdr frame)))
                     (if (= remaining 1)
                         (accept (reverse (cons v acc)) pos (cdr stack) items)
                         (loop pos
                               (cons (cons (- remaining 1) (cons v acc))
                                     (cdr stack))
                               (+ pos 1) #f items)))))))
       (bulk
         (lambda (pos stack next n items)
           (cond
             ((< limit (+ next n 2)) (more-bulk pos stack next n items))
             ((not (and
                     (= (bytevector-u8-ref buf (+ base next n)) 13)
                     (= (bytevector-u8-ref buf (+ base next n 1)) 10)))
              (fatal "bad bulk terminator"))
             (else
              (let ((raw (bv-sub buf (+ base next) (+ base next n))))
                (accept (if (valid-utf8? raw) (utf8->string raw) raw)
                        (+ next n 2) stack (+ items 1)))))))
       (integer-line?
         (lambda (n) (and n (integer? n) (exact? n))))
       (loop
         (lambda (pos stack scan pending items)
           (if pending
               (bulk pos stack (vector-ref pending 0) (vector-ref pending 1)
                     items)
               (if (>= pos limit)
                   (more-line pos stack items)
                   (let ((eol (find-crlf buf base limit scan)))
                     (cond
                       ;; No terminator yet. The cursor already says how far
                       ;; the line has been scanned, so the overlong case is
                       ;; caught while it arrives rather than after.
                       ((not eol)
                        (if (> (- limit pos) max-resp-line)
                            (fatal "reply line too long")
                            (more-line pos stack items)))
                       ((> (- eol pos) max-resp-line)
                        (fatal "reply line too long"))
                       (else
                        (let ((line (utf8->string
                                   (bv-sub buf (+ base pos 1) (+ base eol))))
                           (next (+ eol 2)))
                       (case (integer->char (bytevector-u8-ref buf (+ base pos)))
                         ((#\+) (accept line next stack (+ items 1)))
                         ((#\-) (accept (vector 'redis-error line) next stack
                                        (+ items 1)))
                         ((#\:)
                          (let ((n (string->number line)))
                            (if (integer-line? n)
                                (accept n next stack (+ items 1))
                                (fatal "bad integer reply"))))
                         ((#\$)
                          (let ((n (string->number line)))
                            (cond
                              ((not (integer-line? n)) (fatal "bad bulk length"))
                              ((= n -1) (accept #f next stack (+ items 1)))
                              ((< n 0) (fatal "bad bulk length"))
                              ((> n max-reply-bytes)
                               (fatal "bulk reply too large"))
                              (else (bulk pos stack next n items)))))
                         ((#\*)
                          (let ((n (string->number line)))
                            (cond
                              ((not (integer-line? n)) (fatal "bad array length"))
                              ((= n -1) (accept #f next stack (+ items 1)))
                              ((or (< n 0) (> n max-array-elements))
                               (fatal "array reply too large"))
                              ((= n 0) (accept '() next stack (+ items 1)))
                              ;; the stack IS the nesting, so its length is
                              ;; the depth -- no counter to keep in step
                              ((>= (length stack) max-reply-depth)
                               (fatal "reply nesting too deep"))
                              (else
                               (loop next (cons (cons n '()) stack)
                                     (+ next 1) #f items)))))
                         (else (fatal "bad reply type"))))))))))))
      (if state
          (loop (vector-ref state 0) (vector-ref state 1)
                (vector-ref state 2) (vector-ref state 3)
                (vector-ref state 4))
          (loop 0 '() 1 #f 0))))

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

  ;; The waiter queue is FIFO by protocol -- RESP replies come back in the
  ;; order the commands went out, so a waiter cannot be reordered or removed.
  ;; It used to be a plain list appended with (append waiters (list w)), which
  ;; is O(N) per command: under a stalled Redis the queue grows and every
  ;; further command pays for the whole backlog, so enqueueing alone becomes
  ;; O(N^2). Same shape, and the same fix, as dpool's queue-rev.
  ;;
  ;; #(front back) with back reversed; order is (append front (reverse back)).
  (define (wq-empty) (vector '() '()))
  (define (wq-push q w) (vector (vector-ref q 0) (cons w (vector-ref q 1))))
  (define (wq-null? q) (and (null? (vector-ref q 0)) (null? (vector-ref q 1))))
  ;; normalise so front carries everything; amortised O(1) per element
  (define (wq-norm q)
    (if (null? (vector-ref q 0))
        (vector (reverse (vector-ref q 1)) '())
        q))
  (define (wq-peek q) (car (vector-ref (wq-norm q) 0)))
  (define (wq-pop q) (let ((n (wq-norm q)))
                       (vector (cdr (vector-ref n 0)) (vector-ref n 1))))
  (define (wq-list q) (append (vector-ref q 0) (reverse (vector-ref q 1))))

  (define (conn-loop c buf waiters parse-state)
    (receive
      (`#(redis-cmd ,args ,ref ,from)
        (if (eq? (conn-state c) 'open)
            (begin
              (tcp-write! c (encode-command args) #f)
        (conn-loop c buf (wq-push waiters (vector from ref #t)) parse-state))
            (begin
              (send from (vector 'redis-reply ref connection-lost))
              (conn-loop c buf waiters parse-state))))
      (`#(redis-cancel ,ref ,from)
        (for-each
          (lambda (w) (when (and (eq? (vector-ref w 0) from)
                                 (eq? (vector-ref w 1) ref))
                        (vector-set! w 2 #f)))
          (wq-list waiters))
        (conn-loop c buf waiters parse-state))
      (`#(tcp-data ,bv)
        ;; Checked BEFORE the append: a reply that cannot legally be this
        ;; large is refused while it is still arriving, not after the bytes
        ;; have been taken.
        (if (> (+ (inbuf-length buf) (bytevector-length bv)) max-reply-buffer)
            (protocol-fail c (wq-list waiters) "reply exceeds size limit")
            (begin
              (inbuf-append! buf bv)
              (let drain ((waiters waiters) (state parse-state))
                (let-values (((tag payload)
                              (parse-reply (inbuf-bv buf) (inbuf-start buf)
                                           (inbuf-length buf) state)))
                  (cond
                    ((eq? tag 'more) (conn-loop c buf waiters payload))
                    ((eq? tag 'fatal) (protocol-fail c (wq-list waiters) payload))
                    (else
                     (let ((v (vector-ref payload 0))
                           (next (vector-ref payload 1)))
                       (unless (wq-null? waiters) (reply-to! (wq-peek waiters) v))
                       (inbuf-consume! buf next)
                       (drain (if (wq-null? waiters) waiters (wq-pop waiters)) #f)))))))))
      (`#(redis-quit)
        (for-each (lambda (w) (reply-to! w connection-lost)) (wq-list waiters))
        (tcp-close! c))
      (`#(tcp-eof) (fail-all c buf (wq-list waiters)))
      (`#(tcp-error ,e) (fail-all c buf (wq-list waiters)))))

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
    (conn-loop c (make-inbuf) (wq-empty) #f))

  ;; A malformed or oversized reply desynchronises the stream: there is no
  ;; point in the byte sequence that can be trusted as the start of the next
  ;; reply, so the connection has to go. Everyone waiting is told why rather
  ;; than being left to time out. Keeps serving afterwards for the same
  ;; reason fail-all does -- the redis-cmd clause answers instantly once the
  ;; socket is no longer open.
  (define (protocol-fail c waiters msg)
    (let ((e (vector 'redis-error (string-append "protocol error: " msg))))
      (for-each (lambda (w) (reply-to! w e)) waiters)
      (tcp-close! c)
      (conn-loop c (make-inbuf) (wq-empty) #f)))

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
                          (conn-loop c (make-inbuf) (wq-empty) #f))
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
