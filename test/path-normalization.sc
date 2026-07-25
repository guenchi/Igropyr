;; #2 regression: the router matches on segments (empty ones dropped), so
;; "//admin/x" routed exactly like "/admin/x" while a guard comparing
;; (req-path req) as a string did not match -- guard skipped, handler run.
;; Every layer must now see one normalized path.
(import (chezscheme) (igropyr actor) (igropyr http) (igropyr express)
        (igropyr http-client))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18772)

(start-scheduler
  (lambda ()
    (define (get* port path)
      (let ((r (http-request 'GET (string-append "http://127.0.0.1:"
                                                 (number->string port) path)
                             '((timeout . 4000)))))
        (cons (response-status r) (utf8->string (response-body r)))))
    (let ((app (create-app)))
      ;; a prefix guard written the only way the framework allows
      (app-use app
        (lambda (req res next)
          (let ((p (req-path req)))
            (if (and (>= (string-length p) 6)
                     (string=? (substring p 0 6) "/admin"))
                (begin (set-status! res 403) (send-text! res "guard blocked"))
                (next)))))
      (app-get app "/admin/secret" (lambda (req res) (send-text! res "SECRET LEAKED")))
      (app-get app "/public/ok"    (lambda (req res) (send-text! res "public")))
      ;; echo the path each layer sees
      (app-get app "/echo"         (lambda (req res) (send-text! res (req-path req))))
      (app-listen app port)
      (sleep-ms 300)

      ;; the attack: extra leading slash used to route but skip the guard
      (let ((r (get* port "//admin/secret")))
        (check "double-slash cannot bypass the guard"
               (and (= 403 (car r)) (string=? (cdr r) "guard blocked"))))
      (let ((r (get* port "///admin/secret")))
        (check "triple-slash cannot bypass" (= 403 (car r))))
      (let ((r (get* port "/admin//secret")))
        (check "inner double-slash cannot bypass" (= 403 (car r))))
      (let ((r (get* port "/./admin/secret")))
        (check "dot segment cannot bypass" (= 403 (car r))))
      (let ((r (get* port "/public/../admin/secret")))
        (check "dotdot cannot bypass" (= 403 (car r))))
      ;; the guard itself still works on the plain path
      (let ((r (get* port "/admin/secret")))
        (check "plain path still blocked" (= 403 (car r))))
      ;; unrelated routes keep working
      (let ((r (get* port "/public/ok")))
        (check "normal route unaffected" (and (= 200 (car r)) (string=? (cdr r) "public"))))
      (let ((r (get* port "//public//ok")))
        (check "normalized route still matches" (= 200 (car r))))
      ;; what the handler observes
      (let ((r (get* port "//echo")))
        (check "req-path is normalized" (string=? (cdr r) "/echo")))
      (let ((r (get* port "/a/../echo")))
        (check "dotdot resolved in req-path" (string=? (cdr r) "/echo")))
      ;; .. must not escape the root
      (let ((r (get* port "/../../echo")))
        (check "dotdot cannot escape root" (string=? (cdr r) "/echo")))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "path-normalization: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
