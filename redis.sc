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
  (import (chezscheme) (igropyr actor) (igropyr uv))

  (define connect-timeout-ms 5000)
  (define reply-timeout-ms 30000)

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

  ;; ---- RESP encoding ------------------------------------------------------

  (define (arg->bv a)
    (cond
      ((bytevector? a) a)
      ((string? a) (string->utf8 a))
      ((symbol? a) (string->utf8 (symbol->string a)))
      ((number? a) (string->utf8 (number->string a)))
      (else (assertion-violation 'redis "bad command argument" a))))

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
            (put-bytevector p (string->utf8 "\r\n"))))
        args)
      (get)))

  ;; ---- RESP parsing ---------------------------------------------------------
  ;; (parse-reply buf pos) -> (values value next-pos) or (values 'more #f).
  ;; The symbol 'more cannot collide with real replies (strings, numbers,
  ;; lists, #f, or #(redis-error msg)).

  (define (parse-reply buf pos)
    (if (>= pos (bytevector-length buf))
        (values 'more #f)
        (let ((eol (find-crlf buf (+ pos 1))))
          (if (not eol)
              (values 'more #f)
              (let ((line (utf8->string (bv-sub buf (+ pos 1) eol)))
                    (next (+ eol 2)))
                (case (integer->char (bytevector-u8-ref buf pos))
                  ((#\+) (values line next))
                  ((#\-) (values (vector 'redis-error line) next))
                  ((#\:) (values (string->number line) next))
                  ((#\$)
                   (let ((n (string->number line)))
                     (cond
                       ((not n) (values (vector 'redis-error "bad bulk length") next))
                       ((< n 0) (values #f next))          ; nil
                       ((< (bytevector-length buf) (+ next n 2))
                        (values 'more #f))
                       (else
                        (values (utf8->string (bv-sub buf next (+ next n)))
                                (+ next n 2))))))
                  ((#\*)
                   (let ((n (string->number line)))
                     (cond
                       ((not n) (values (vector 'redis-error "bad array length") next))
                       ((< n 0) (values #f next))          ; nil array
                       (else
                        (let loop ((i 0) (p next) (acc '()))
                          (if (= i n)
                              (values (reverse acc) p)
                              (let-values (((v np) (parse-reply buf p)))
                                (if (eq? v 'more)
                                    (values 'more #f)
                                    (loop (+ i 1) np (cons v acc))))))))))
                  (else (values (vector 'redis-error "bad reply type") next))))))))

  ;; ---- connection process -----------------------------------------------------

  (define connection-lost (vector 'redis-error "connection lost"))

  ;; FIFO of pids waiting for replies, oldest first
  (define (conn-loop c buf waiters)
    (receive
      (`#(redis-cmd ,args ,from)
        (if (eq? (conn-state c) 'open)
            (begin
              (tcp-write! c (encode-command args) #f)
              (conn-loop c buf (append waiters (list from))))
            (begin
              (send from (vector 'redis-reply connection-lost))
              (conn-loop c buf waiters))))
      (`#(tcp-data ,bv)
        (let drain ((buf (bv-append buf bv)) (waiters waiters))
          (let-values (((v next) (parse-reply buf 0)))
            (if (eq? v 'more)
                (conn-loop c buf waiters)
                (begin
                  (when (pair? waiters)
                    (send (car waiters) (vector 'redis-reply v)))
                  (drain (bv-sub buf next (bytevector-length buf))
                         (if (pair? waiters) (cdr waiters) '())))))))
      (`#(redis-quit)
        (for-each
          (lambda (w) (send w (vector 'redis-reply connection-lost)))
          waiters)
        (tcp-close! c))
      (`#(tcp-eof) (fail-all c waiters))
      (`#(tcp-error ,e) (fail-all c waiters))))

  (define (fail-all c waiters)
    (for-each
      (lambda (w) (send w (vector 'redis-reply connection-lost)))
      waiters)
    (tcp-close! c))

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

  ;; Run one command; blocks only the calling green process.
  (define (redis rc . args)
    (send rc (vector 'redis-cmd args self))
    (receive (after reply-timeout-ms
                (raise (vector 'redis-error "reply timeout")))
      (`#(redis-reply ,v)
        (if (and (vector? v) (eq? (vector-ref v 0) 'redis-error))
            (raise v)
            v))))

  (define (redis-close! rc)
    (send rc (vector 'redis-quit)))
)
