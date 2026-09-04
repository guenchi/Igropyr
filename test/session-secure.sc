#!chezscheme
;;; The session cookie's Secure attribute: a boolean or a per-request
;;; predicate, because one process can serve two schemes at once.
;;;
;;; EVERY "does not carry Secure" ASSERTION IS PRECEDED BY PROOF THAT THE
;;; PROBE SEES A COOKIE AT ALL. A probe that cannot find the set-cookie
;;; header and a response that genuinely omits the attribute produce the
;;; same "not found" -- this suite's first drafts elsewhere went green on
;;; exactly that confusion, twice (a handler that 500ed before any cookie
;;; existed; a header lookup keyed by the wrong type). So the shape here
;;; is always: assert the cookie line is present and non-empty, THEN ask
;;; what attributes ride on it.
;;;
;;; THE CALL COUNTER IS A TRIPWIRE, NOT DECOR. This suite's own first
;;; version proved why: its predicate referenced an accessor the script
;;; had not imported, the unbound-variable raise was swallowed by the
;;; very fail-closed guard under test, and both the true and false cases
;;; showed Secure -- the true case green for the wrong reason. Only the
;;; per-decision call count (zero, not two) named the real failure. If
;;; the counter assertion is ever removed, that whole class comes back
;;; unobserved.
;;;
;;; The fail-closed direction is asserted, not assumed: a predicate that
;;; raises must yield a NORMAL response whose cookie carries Secure --
;;; of the two wrong answers, omitting Secure hands the sid to the
;;; cleartext side, while adding it merely costs one cookie.

(import (chezscheme) (igropyr actor) (igropyr express) (igropyr session)
        (igropyr http) (igropyr libuv) (igropyr tcp))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))

(define empty-bv (make-bytevector 0))
(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na)
    (bytevector-copy! b 0 out na nb)
    out))

(define (http-req port text)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'r-err ref 'connect)))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c (string->utf8 text) #f)
            (let loop ((buf empty-bv))
              (receive (after 3000
                          (tcp-close! c)
                          (send caller (vector 'r-ok ref (utf8->string buf))))
                (`#(tcp-data ,bv) (loop (bv-append buf bv)))
                (`#(tcp-eof) (send caller (vector 'r-ok ref (utf8->string buf))))
                (`#(tcp-error ,e)
                  (send caller (vector 'r-ok ref (utf8->string buf)))))))
          (`#(tcp-connect-failed ,e)
            (send caller (vector 'r-err ref e))))))
    (receive (after 10000 (fail "http-req" 'timeout) "")
      (`#(r-ok ,@ref ,s) s)
      (`#(r-err ,@ref ,e) (fail "http-req" e) ""))))

(define (get port path . headers)
  (http-req port
    (string-append "GET " path " HTTP/1.1\r\nHost: x\r\n"
                   (apply string-append
                          (map (lambda (h) (string-append h "\r\n")) headers))
                   "Connection: close\r\n\r\n")))

;; the set-cookie LINE, or #f -- so "no cookie at all" and "cookie
;; without the attribute" cannot be mistaken for each other
(define (cookie-line resp)
  (let ((lower (list->string (map char-downcase (string->list resp)))))
    (let ((i (let loop ((k 0))
               (cond ((> (+ k 12) (string-length lower)) #f)
                     ((string=? (substring lower k (+ k 12)) "\nset-cookie:") k)
                     (else (loop (+ k 1)))))))
      (and i
           (let ((end (let loop ((k (+ i 1)))
                        (if (or (>= k (string-length resp))
                                (char=? (string-ref resp k) #\newline))
                            k (loop (+ k 1))))))
             (substring resp (+ i 1) end))))))

(define (has-attr? line attr)
  (let ((l (list->string (map char-downcase (string->list line))))
        (a (list->string (map char-downcase (string->list attr)))))
    (let loop ((i 0))
      (cond ((> (+ i (string-length a)) (string-length l)) #f)
            ((string=? (substring l i (+ i (string-length a))) a) #t)
            (else (loop (+ i 1)))))))

;; ---- four apps, four ports, one option each -------------------------------

(define p-default 18093)
(define p-off 18094)
(define p-pred 18095)
(define p-raise 18096)

(define pred-calls (box 0))

(define (mk-app secure-opt)
  (let ((app (create-app)) (store (make-session-store)))
    (app-use app (session-middleware store
                   (if (eq? secure-opt 'none)
                       '()
                       (list (cons 'secure secure-opt)))))
    (app-get app "/s"
      (lambda (req res)
        (session-set! (req-session req) 'k "v")
        (send-text! res "ok")))
    app))

(start-scheduler
  (lambda ()
    (app-listen (mk-app 'none) p-default '((workers . 1)))
    (app-listen (mk-app #f) p-off '((workers . 1)))
    (app-listen (mk-app (lambda (req)
                          (set-box! pred-calls (+ 1 (unbox pred-calls)))
                          (equal? (req-header req 'x-proto) "https")))
                p-pred '((workers . 1)))
    (app-listen (mk-app (lambda (req) (raise 'pred-bang)))
                p-raise '((workers . 1)))
    (sleep-ms 200)

    ;; ---- the boolean paths, byte-for-byte what they were ---------------
    (let ((line (cookie-line (get p-default "/s"))))
      (check "default: the cookie line exists (the probe sees data)"
             (and line (> (string-length line) 12)) line)
      (check "default #t still carries Secure"
             (and line (has-attr? line "; secure"))))
    (let ((line (cookie-line (get p-off "/s"))))
      (check "secure #f: the cookie line exists (positive control first)"
             (and line (> (string-length line) 12)) line)
      (check "secure #f still omits Secure"
             (and line (not (has-attr? line "; secure")))))

    ;; ---- the predicate: per request, both answers ----------------------
    (let ((line (cookie-line (get p-pred "/s" "X-Proto: https"))))
      (check "predicate true: cookie present" (and line #t))
      (check "predicate true adds Secure"
             (and line (has-attr? line "; secure"))))
    (let ((line (cookie-line (get p-pred "/s"))))
      (check "predicate false: cookie present (probe control)"
             (and line #t))
      (check "predicate false omits Secure"
             (and line (not (has-attr? line "; secure")))))
    (check "the predicate ran once per decision, not once at construction"
           (>= (unbox pred-calls) 2) (unbox pred-calls))

    ;; ---- fail closed ----------------------------------------------------
    (let* ((resp (get p-raise "/s"))
           (line (cookie-line resp)))
      (check "a raising predicate still answers the request"
             (and (> (string-length resp) 12)
                  (string=? (substring resp 9 12) "200"))
             (and (> (string-length resp) 12) (substring resp 9 12)))
      (check "...with a cookie" (and line #t))
      (check "...that fails CLOSED: Secure is present"
             (and line (has-attr? line "; secure"))))

    ;; ---- refused at construction ---------------------------------------
    (let ((store (make-session-store)))
      (guard (e (#t 'ok))
        (session-middleware store '((secure . "yes")))
        (fail "a string secure option was accepted"))
      (guard (e (#t 'ok))
        (session-middleware store (list (cons 'secure (lambda () #t))))
        (fail "a zero-argument predicate was accepted")))
    (ok "non-boolean non-unary options are refused when the middleware is built")

    (if (= failures 0)
        (begin (display "session-secure: all tests passed\n") (exit 0))
        (begin (display (number->string failures))
               (display " failures\n") (exit 1)))))
