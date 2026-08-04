#!chezscheme
;;; qjs-worker.sc -- one out-of-process QuickJS render worker.
;;;
;;;   scheme --script igropyr/qjs-worker.sc <host> <port> <bundle.js> [opts...]
;;;
;;; opts are key=value: timeout-ms, mem-mb, stack-kb, so-path -- the same
;;; ones qjs-boot! takes. Example:
;;;
;;;   scheme --script igropyr/qjs-worker.sc 127.0.0.1 9701 site.js timeout-ms=1500
;;;
;;; This process exists to be blocked. It holds the engine, so a render that
;;; runs away stops THIS scheduler and no other; the node that asked keeps
;;; serving, times the call out, and drops the connection. See the header of
;;; (igropyr qjspool) for why that cannot be arranged inside one process.
;;;
;;; BIND LOOPBACK. There is no authentication: whoever reaches the port can
;;; run any function the bundle exports.
;;;
;;; Started and restarted by whatever supervises the node -- rc.d, a
;;; process manager, a shell loop. Nothing here restarts it, and a worker
;;; wedged in a runaway render can only be ended from outside.

(import (chezscheme) (igropyr actor) (igropyr qjspool))

(define (die! msg)
  (display (string-append "qjs-worker: " msg "\n") (console-error-port))
  (exit 2))

(define (read-file path)
  (unless (file-exists? path) (die! (string-append "no such bundle: " path)))
  (call-with-input-file path
    (lambda (p)
      (let loop ((acc '()))
        (let ((s (get-string-n p 65536)))
          (if (eof-object? s)
              (apply string-append (reverse acc))
              (loop (cons s acc))))))))

;; key=value -> (key . value); numeric values are parsed as numbers, so
;; timeout-ms=1500 reaches qjs-boot! as a fixnum and not as a string it
;; would reject.
(define (parse-opt s)
  (let ((i (let loop ((i 0))
             (cond ((= i (string-length s)) #f)
                   ((char=? (string-ref s i) #\=) i)
                   (else (loop (+ i 1)))))))
    (unless i (die! (string-append "options are key=value, got: " s)))
    (let* ((k (string->symbol (substring s 0 i)))
           (v (substring s (+ i 1) (string-length s)))
           (n (string->number v)))
      (cons k (if (and n (exact? n) (integer? n)) n v)))))

(define args (command-line-arguments))

(when (< (length args) 3)
  (die! "usage: qjs-worker.sc <host> <port> <bundle.js> [key=value ...]"))

(let* ((host (car args))
       (port (string->number (cadr args)))
       (bundle-path (caddr args))
       (qopts (map parse-opt (cdddr args))))
  (unless (and port (exact? port) (integer? port) (> port 0) (< port 65536))
    (die! (string-append "bad port: " (cadr args))))
  ;; read the bundle BEFORE the scheduler starts: a missing or unreadable
  ;; file should exit with a message, not from inside a green process
  (let ((bundle (read-file bundle-path)))
    (start-scheduler
      (lambda ()
        ;; a bundle that does not parse must fail HERE, loudly, at startup
        ;; -- not once per render on a worker the pool believes is healthy
        (guard (e (#t (die! (string-append
                              "bundle failed to load: "
                              (if (and (condition? e) (message-condition? e))
                                  (condition-message e)
                                  "unknown error")))))
          (qjs-worker-serve! host port bundle qopts))
        (display (string-append "qjs-worker listening on " host ":"
                                (number->string port)
                                " (bundle " bundle-path ")\n"))
        (flush-output-port (console-output-port))))))
