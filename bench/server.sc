#!chezscheme
;;; Minimal benchmark server for repeatable source/AOT comparisons.
;;;
;;;   chez --script bench/server.sc express-pooled 18080 8
;;; Modes: express-pooled | core-pooled | express-fast

(import (chezscheme)
        (igropyr actor)
        (igropyr uv)
        (igropyr otp)
        (igropyr http)
        (igropyr websocket)
        (igropyr json)
        (igropyr express))

(define args (cdr (command-line)))
(define mode (if (pair? args) (car args) "express-pooled"))
(define port
  (if (and (pair? args) (pair? (cdr args)))
      (or (string->number (cadr args)) 18080)
      18080))
(define workers
  (if (and (pair? args) (pair? (cdr args)) (pair? (cddr args)))
      (or (string->number (caddr args)) 8)
      8))
(define profile-prefix
  (if (and (pair? args) (pair? (cdr args)) (pair? (cddr args))
           (pair? (cdddr args)))
      (cadddr args)
      "/tmp/igropyr-profile-"))

(define start-stats (statistics))
(define start-cpu 0)
(define start-real 0)
(define measured-requests 0)

(define (time->ms t)
  (+ (* (time-second t) 1000)
     (div (time-nanosecond t) 1000000)))

(define (reset-metrics!)
  (collect)
  ;; No-op for ordinary builds; clears instrumented counters when the
  ;; profile build is used so startup and warm-up do not pollute samples.
  (guard (e (#t (void))) (profile-clear))
  (set! measured-requests 0)
  (set! start-stats (statistics))
  (set! start-cpu (cpu-time))
  (set! start-real (real-time)))

(define (metrics-string)
  (let ((delta (sstats-difference (statistics) start-stats)))
    (string-append
      "requests=" (number->string measured-requests)
      " bytes=" (number->string (sstats-bytes delta))
      " collections=" (number->string (sstats-gc-count delta))
      " cpu_ms=" (number->string (- (cpu-time) start-cpu))
      " real_ms=" (number->string (- (real-time) start-real))
      " gc_cpu_ms=" (number->string (time->ms (sstats-gc-cpu delta)))
      " gc_real_ms=" (number->string (time->ms (sstats-gc-real delta)))
      " gc_bytes=" (number->string (sstats-gc-bytes delta))
      "\n")))

(define ok-body (string->utf8 "ok"))

(define (send-control-text! res text)
  (set-header! res "Content-Type" "text/plain")
  (res-send! res (string->utf8 text)))

(define (send-measured! res)
  (set! measured-requests (+ measured-requests 1))
  (set-header! res "Content-Type" "text/plain")
  (res-send! res ok-body))

(define (reset-handler req res)
  (reset-metrics!)
  (send-control-text! res "reset"))

(define (result-handler req res)
  (send-control-text! res (metrics-string)))

(define (profile-handler req res)
  (guard (e (#t (set-status! res 503)
                 (send-control-text! res "profile unavailable")))
    (profile-dump-html profile-prefix)
    (send-control-text! res (string-append profile-prefix "profile.html"))))

(define (measured-handler req res)
  (send-measured! res))

(define (run-express fast?)
  (let ((app (create-app)))
    (if fast?
        (app-get-fast app "/" measured-handler)
        (app-get app "/" measured-handler))
    ;; Control routes stay pooled and are outside measured traffic.
    (app-get app "/__bench/reset" reset-handler)
    (app-get app "/__bench/result" result-handler)
    (app-get app "/__bench/profile" profile-handler)
    (app-listen app port workers)))

(define (run-core)
  (http-listen port
    (lambda (req res)
      (cond
        ((string=? (req-path req) "/") (measured-handler req res))
        ((string=? (req-path req) "/__bench/reset") (reset-handler req res))
        ((string=? (req-path req) "/__bench/result") (result-handler req res))
        ((string=? (req-path req) "/__bench/profile") (profile-handler req res))
        (else (set-status! res 404) (send-control-text! res "not found"))))
    workers))

(unless (member mode '("express-pooled" "core-pooled" "express-fast"))
  (error 'bench/server "unknown mode" mode))

(start-scheduler
  (lambda ()
    (if (string=? mode "core-pooled")
        (run-core)
        (run-express (string=? mode "express-fast")))
    (printf "BENCH_READY mode=~a port=~a workers=~a\n" mode port workers)))
