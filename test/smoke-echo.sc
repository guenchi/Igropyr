;;; Smoke test for (igropyr libuv): a bare echo server with no actor layer.
;;; The deliver hook is abused to handle messages synchronously; the
;;; conn itself plays the role of the owner pid.
;;; Run: scheme --script test/smoke-echo.sc  (from the project root,
;;; with CHEZSCHEMELIBDIRS/CHEZSCHEMELIBEXTS set; see CLAUDE.md)

(import (chezscheme) (igropyr libuv))

(uv-init!)

(uv-set-deliver!
  (lambda (owner msg)
    ;; owner is the conn record in this smoke test
    (case (vector-ref msg 0)
      ((tcp-data)
       (tcp-write! owner (vector-ref msg 1)
         (lambda (status) (tcp-close! owner))))
      ((tcp-eof tcp-error)
       (tcp-close! owner)))))

(tcp-listen! "0.0.0.0" 5555 128
  (lambda (c)
    (conn-set-owner! c c)
    (tcp-read-start! c)))

(display "echo server on 127.0.0.1:5555\n")

(let loop ()
  (uv-poll! 1000)
  (loop))
