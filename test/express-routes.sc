#!chezscheme
;;; (igropyr express) route matching: :param captures, the trailing '*'
;;; splat (captured under param "0"), registration-order precedence,
;;; and the 404 fallthrough. Driven end to end over real HTTP.

(import (chezscheme) (igropyr actor) (igropyr libuv)
        (igropyr http) (igropyr express))

(define port 18089)
(define empty-bv (make-bytevector 0))

(define failures 0)
(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))
(define (fail label detail)
  (display "FAIL ") (display label) (display ": ") (write detail) (newline)
  (exit 1))

(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

;; GET path on a fresh connection; returns (status . body)
(define (get path)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'e ref 'connect)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c (string->utf8
                            (string-append "GET " path " HTTP/1.1\r\nHost: x\r\n"
                                           "Connection: close\r\n\r\n")) #f)
            (let loop ((buf empty-bv))
              (receive (after 3000
                          (tcp-close! c) (send caller (vector 'r ref buf)))
                (`#(tcp-data ,bv) (loop (bv-append buf bv)))
                (`#(tcp-eof) (send caller (vector 'r ref buf)))
                (`#(tcp-error ,e) (send caller (vector 'r ref buf))))))
          (`#(tcp-connect-failed ,e) (send caller (vector 'e ref e))))))
    (receive (after 8000 (fail "get" 'timeout))
      (`#(r ,@ref ,bv)
        (let* ((s (utf8->string bv))
               (st (and (> (string-length s) 12) (substring s 9 12)))
               (bend (let scan ((i 0))
                       (cond ((> (+ i 4) (string-length s)) #f)
                             ((string=? (substring s i (+ i 4)) "\r\n\r\n") i)
                             (else (scan (+ i 1)))))))
          (cons st (if bend (substring s (+ bend 4) (string-length s)) ""))))
      (`#(e ,@ref ,e) (fail "get" e)))))

(define app (create-app))
;; a concrete route registered BEFORE the splat: registration order is
;; the precedence, so /content/list wins over /content/*
(app-get app "/content/list" (lambda (req res) (send-text! res "LIST")))
(app-get app "/content/*"
  (lambda (req res) (send-text! res (string-append "S:" (or (req-param req "0") "#f")))))
(app-get app "/files/:id"
  (lambda (req res) (send-text! res (string-append "id=" (req-param req "id")))))

;; a non-trailing splat is a registration-time error (it would swallow
;; the rest of the path and silently disable the segments after it),
;; on both the HTTP and the ws registration paths
(check "mid-splat-rejected"
  (guard (c ((assertion-violation? c) #t) (#t #f))
    (app-get app "/bad/*/tail" (lambda (req res) res))
    #f))
(check "ws-mid-splat-rejected"
  (guard (c ((assertion-violation? c) #t) (#t #f))
    (app-ws app "/bad/*/tail" (lambda (ws req) req))
    #f))
;; trailing splat still registers fine on the ws path too
(check "ws-trailing-splat-ok"
  (begin (app-ws app "/wsplat/*" (lambda (ws req) req)) #t))

;; a literal-prefix param must name a non-empty capture with exactly one
;; ':' -- "/@:" captures nothing and "/@:a:b" folds the 2nd colon into the
;; name, both silent mystery-misses req-param can never read. Registration
;; must reject them on the HTTP and ws paths, like the mid-splat guard.
(check "empty-param-rejected"
  (guard (c ((assertion-violation? c) #t) (#t #f))
    (app-get app "/@:" (lambda (req res) res))
    #f))
(check "double-colon-rejected"
  (guard (c ((assertion-violation? c) #t) (#t #f))
    (app-get app "/@:a:b" (lambda (req res) res))
    #f))
(check "ws-empty-param-rejected"
  (guard (c ((assertion-violation? c) #t) (#t #f))
    (app-ws app "/@:" (lambda (ws req) req))
    #f))
;; a well-formed literal-prefix param still registers fine
(check "prefix-param-ok"
  (begin
    (app-get app "/u/@:name"
      (lambda (req res) (send-text! res (string-append "u=" (req-param req "name")))))
    #t))

(start-scheduler
  (lambda ()
    (app-listen app port '((workers . 2)))
    (sleep-ms 100)

    ;; splat captures all remaining segments joined with "/"
    (check "splat-multi"   (equal? (get "/content/a/b/c") '("200" . "S:a/b/c")))
    (check "splat-single"  (equal? (get "/content/x")     '("200" . "S:x")))
    ;; the splat also matches zero remaining segments (Express-style)
    (check "splat-empty"   (equal? (get "/content")       '("200" . "S:")))
    (check "splat-slash"   (equal? (get "/content/")      '("200" . "S:")))
    ;; a concrete route registered earlier takes precedence over the splat
    (check "concrete-wins" (equal? (get "/content/list")  '("200" . "LIST")))
    ;; :param still captures exactly one segment
    (check "param-one"     (equal? (get "/files/42")      '("200" . "id=42")))
    ;; :param does NOT swallow extra segments (that is the splat's job)
    (check "param-not-splat" (equal? (car (get "/files/42/extra")) "404"))
    ;; a literal-prefix param captures the segment tail after the prefix
    (check "prefix-param-capture" (equal? (get "/u/@alice") '("200" . "u=alice")))
    ;; unmatched path is a 404
    (check "miss-404"      (equal? (car (get "/nope"))     "404"))

    (if (zero? failures)
        (begin (display "express-routes: all tests passed") (newline) (exit 0))
        (begin (display failures) (display " failures") (newline) (exit 1)))))
