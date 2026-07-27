#!chezscheme
;;; Findings #6, #9 and #10 from the whole-codebase review, plus the
;;; base64/session items that have no server surface (#7, #8).
;;;
;;;  #6 send-file! only rejected "..": no NUL check (file APIs truncate
;;;     there, so "secret.db\0.png" passed an extension check and opened
;;;     secret.db) and no root, so an untrusted path escaped freely.
;;;  #9 app-static served dotfiles -- .env, .git/config -- with a public
;;;     Cache-Control.
;;; #10 HEAD fell through to the 404 arm and that response carried a body,
;;;     desynchronising a keep-alive connection.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
        (igropyr express) (igropyr http-client)
        (only (igropyr crypto) base64-decode base64-encode)
        (only (igropyr sexpr) string->sexpr)
        (only (igropyr jwt) jwt-verify))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18776)
(define root "/tmp/igropyr-serving-test")

;; a served tree with a dotfile and a secret whose name a suffix check
;; would accept only after NUL truncation
(system (string-append "rm -rf " root " && mkdir -p " root "/.git " root "/.well-known"))
(call-with-output-file (string-append root "/ok.txt")
  (lambda (p) (display "public file" p)))
(call-with-output-file (string-append root "/.env")
  (lambda (p) (display "SECRET_KEY=leaked" p)))
(call-with-output-file (string-append root "/.git/config")
  (lambda (p) (display "[remote]" p)))
(call-with-output-file (string-append root "/.well-known/probe")
  (lambda (p) (display "well-known ok" p)))
(call-with-output-file (string-append root "/secret.db")
  (lambda (p) (display "PRIVATE" p)))
(system (string-append "ln -s /etc/passwd " root "/link"))
(system (string-append "ln -s /etc " root "/escape"))

(start-scheduler
  (lambda ()
    ;; ---- #7: a hostile base64 tail must not escape each library's
    ;;      error contract as a raw assertion ---------------------------
    ;; "AB" is 12 bits: one byte plus four unused bits, and B sets one of
    ;; them -- the shortest input base64-decode must refuse as non-canonical.
    (let ((bad "AB")
          (bad-jwt-sig (string-append (substring (base64-encode
                                                   (make-bytevector 32 170))
                                                 0 42) "B")))
      (check "crypto base64-decode still rejects a non-canonical tail"
        (guard (e (#t #t)) (base64-decode bad) #f))
      (check "sexpr reports it as sexpr-error, not a raw assertion"
        (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'sexpr-error)) #t)
                  (#t #f))
          (string->sexpr (string-append "#u8\"" bad "\"")) #f))
      ;; jwt-verify is fail-closed by construction (any exception inside
      ;; means "invalid"), so the assertion never escaped there -- but it
      ;; must still answer #f rather than propagate anything
      (check "jwt treats it as an invalid token, raising nothing"
        (eq? #f (jwt-verify (string-append "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ."
                                           bad-jwt-sig)
                            "secret"))))

    (let ((app (create-app)))
      (app-static app "/static" root)
      ;; the documented download idiom, now with a root
      (app-get app "/dl"
        (lambda (req res)
          (let ((n (cond ((assoc "f" (req-query req)) => cdr) (else ""))))
            (send-file! res n root))))
      ;; the rootless form must still refuse a NUL
      (app-get app "/dl-rootless"
        (lambda (req res)
          (let ((n (cond ((assoc "f" (req-query req)) => cdr) (else ""))))
            (send-file! res (string-append root "/" n)))))
      (app-get app "/hello" (lambda (req res) (send-text! res "hello body")))
      (app-listen app port)
      (sleep-ms 300)

      (let* ((base (string-append "http://127.0.0.1:" (number->string port)))
             (GET (lambda (p) (http-request 'GET (string-append base p)
                                            '((timeout . 4000)))))
             (HEAD (lambda (p) (http-request 'HEAD (string-append base p)
                                             '((timeout . 4000))))))

        ;; ---- #9 dotfiles ------------------------------------------------
        (check "static serves a normal file"
          (= 200 (response-status (GET "/static/ok.txt"))))
        (check ".env is not served" (= 403 (response-status (GET "/static/.env"))))
        (check ".git/config is not served"
          (= 403 (response-status (GET "/static/.git/config"))))
        (check ".well-known stays reachable"
          (= 200 (response-status (GET "/static/.well-known/probe"))))
        (check "static refuses a symlinked file"
          (not (= 200 (response-status (GET "/static/link")))))
        (check "static refuses a symlinked directory escape"
          (not (= 200 (response-status (GET "/static/escape/passwd")))))

        ;; ---- #6 send-file! ----------------------------------------------
        (check "send-file! with a root serves an ordinary name"
          (= 200 (response-status (GET "/dl?f=ok.txt"))))
        (check "send-file! with a root refuses traversal"
          (= 403 (response-status (GET "/dl?f=../../etc/passwd"))))
        (check "send-file! with a root refuses a dotfile"
          (= 403 (response-status (GET "/dl?f=.env"))))
        ;; %00 decodes to a real NUL before routing
        (check "send-file! refuses a NUL-truncated name (with root)"
          (= 403 (response-status (GET "/dl?f=secret.db%00.png"))))
        (check "send-file! refuses a NUL-truncated name (rootless)"
          (= 403 (response-status (GET "/dl-rootless?f=secret.db%00.png"))))

        ;; ---- #10 HEAD ---------------------------------------------------
        (let ((r (HEAD "/hello")))
          (check "HEAD reaches the GET route (not 404)"
            (= 200 (response-status r)))
          (check "HEAD carries no body"
            (= 0 (bytevector-length (response-body r))))
          (check "HEAD still declares the GET Content-Length"
            (equal? "10" (cond ((assq 'content-length (response-headers r)) => cdr)
                               (else #f)))))
        (let ((r (HEAD "/static/ok.txt")))
          (check "HEAD on a static file: 200, no body"
            (and (= 200 (response-status r))
                 (= 0 (bytevector-length (response-body r))))))
        ;; a GET after HEADs on the same server still works: nothing desynced
        (check "GET after HEAD is unaffected"
          (= 200 (response-status (GET "/hello"))))))

    (sleep-ms 100)
    (system (string-append "rm -rf " root))
    (if (zero? failures)
        (begin (display "serving-hardening: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
