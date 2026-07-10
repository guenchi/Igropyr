#!chezscheme
;;; (igropyr gen-server) -- the OTP gen-server pattern for Igropyr actors.
;;;
;;; A stateful service process reduced to three callbacks; the loop,
;;; request/reply matching, timeouts and death detection are done here,
;;; once, correctly:
;;;
;;;   (define counter
;;;     (gen-server-start
;;;       (lambda () 0)                            ; init -> state
;;;       (lambda (msg from state)                 ; handle-call
;;;         (values (+ state 1) (+ state 1)))      ;   (values reply new-state)
;;;       (lambda (msg state) state)))             ; handle-cast -> new-state
;;;
;;;   (gen-server-call counter 'incr)              ; sync; 5s default timeout
;;;   (gen-server-cast counter 'noop)              ; async
;;;
;;; Every call carries a unique tag, so replies can never be delivered
;;; to the wrong request; the caller monitors the server, so a server
;;; crash raises #(gen-server-error server-died reason) immediately
;;; instead of hanging until the timeout. Servers may be addressed by
;;; registered name (a symbol) or pid.

(library (igropyr gen-server)
  (export gen-server-start gen-server-start-named
          gen-server-call gen-server-cast)
  (import (chezscheme) (igropyr actor))

  (define default-timeout-ms 5000)

  (define ref-counter 0)
  (define (next-ref!)
    (set! ref-counter (+ ref-counter 1))
    ref-counter)

  (define (resolve srv)
    (if (symbol? srv)
        (or (whereis srv)
            (raise (vector 'gen-server-error 'no-such-server srv)))
        srv))

  ;; init: () -> state
  ;; handle-call: (msg from state) -> (values reply new-state)
  ;; handle-cast: (msg state) -> new-state
  ;; handle-info: (msg state) -> new-state    (optional; other messages,
  ;;                                           e.g. DOWN from monitors)
  (define (gen-server-start init handle-call handle-cast . rest)
    (let ((handle-info (if (pair? rest) (car rest) (lambda (m s) s))))
      (spawn
        (lambda ()
          (let loop ((state (init)))
            (receive
              (`#(gen-call ,from ,ref ,msg)
                (let-values (((reply new-state) (handle-call msg from state)))
                  (send from (vector 'gen-reply ref reply))
                  (loop new-state)))
              (`#(gen-cast ,msg)
                (loop (handle-cast msg state)))
              (other
                (loop (handle-info other state)))))))))

  (define (gen-server-start-named name . args)
    (register name (apply gen-server-start args)))

  (define (gen-server-call srv msg . rest)
    (let* ((timeout (if (pair? rest) (car rest) default-timeout-ms))
           (p (resolve srv))
           (ref (next-ref!))
           (m (monitor p)))
      (send p (vector 'gen-call self ref msg))
      (receive (after timeout
                  (demonitor m)
                  (raise (vector 'gen-server-error 'timeout msg)))
        (`#(gen-reply ,@ref ,reply)
          (demonitor m)
          reply)
        (`#(DOWN ,@p ,reason)
          (raise (vector 'gen-server-error 'server-died reason))))))

  (define (gen-server-cast srv msg)
    (send (resolve srv) (vector 'gen-cast msg)))
)
