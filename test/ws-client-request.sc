#!chezscheme
;;; Outbound WebSocket request validation must reject line/header injection
;;; before it performs DNS or opens a socket.

(import (chezscheme) (igropyr ws-client))

(define failures 0)

(define (check-error label thunk expected)
  (let ((got
         (guard (e ((and (vector? e)
                         (>= (vector-length e) 2)
                         (eq? (vector-ref e 0) 'ws-client-error))
                    (vector-ref e 1))
                   (#t 'wrong-error))
           (thunk)
           'no-error)))
    (unless (equal? got expected)
      (set! failures (+ failures 1))
      (display "FAIL ") (display label)
      (display ": got ") (write got)
      (display ", want ") (write expected)
      (newline))))

(check-error "request-path-crlf"
  (lambda () (ws-connect "ws://example.test/chat\r\nX-Injected: yes"))
  "invalid request path: control characters are not allowed")

(check-error "host-crlf"
  (lambda () (ws-connect "ws://example.test\r\nX-Injected: yes/chat"))
  "invalid Host header: control characters are not allowed")

(check-error "header-name-crlf"
  (lambda ()
    (ws-connect "ws://example.test/chat"
                '(("X-Good\r\nX-Injected" . "yes"))))
  "invalid header name")

(check-error "header-value-crlf"
  (lambda ()
    (ws-connect "ws://example.test/chat"
                '(("X-Good" . "yes\r\nX-Injected: true"))))
  "invalid value for header X-Good: control characters are not allowed")

(check-error "managed-header-override"
  (lambda ()
    (ws-connect "ws://example.test/chat"
                '(("Connection" . "close"))))
  "header is managed by the client: Connection")

(if (= failures 0)
    (begin (display "WS CLIENT REQUEST VALIDATION PASSED\n") (exit 0))
    (begin (display failures) (display " failure(s)\n") (exit 1)))
