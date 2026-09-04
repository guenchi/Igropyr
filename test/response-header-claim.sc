#!chezscheme
;;; The contract set-header-if-unanswered! offers, pinned without timing.
;;;
;;; This does NOT test atomicity -- nothing here races, so an
;;; implementation that checked and then mutated in two steps would pass.
;;; session-rotation-race.sc is what covers the window. What this covers is
;;; the promise the race test relies on being true afterwards:
;;;
;;;   #t  =>  the header IS in the response the client receives
;;;   claimed  =>  #f, always
;;;   #f  =>  session rotation must not have dropped the old id
;;;
;;; Those are the failure modes a later "simplification" would produce
;;; while leaving the race test green, because the race test only ever
;;; exercises the losing side.

(import (chezscheme) (igropyr actor) (igropyr express) (igropyr http)
        (igropyr libuv) (igropyr tcp) (igropyr session))

(define port 18816)
(define failures 0)

(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (find-substr hay needle)
  (let ((n (string-length hay)) (m (string-length needle)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring hay i (+ i m)) needle) i)
            (else (loop (+ i 1)))))))

(define empty-bv (make-bytevector 0))
(define (bv-append a b)
  (let* ((na (bytevector-length a)) (nb (bytevector-length b))
         (out (make-bytevector (+ na nb))))
    (bytevector-copy! a 0 out 0 na) (bytevector-copy! b 0 out na nb) out))

(define (http-get path . headers)
  (let ((caller self) (ref (gensym)))
    (spawn
      (lambda ()
        (tcp-connect! "127.0.0.1" port self)
        (receive (after 3000 (send caller (vector 'r ref "")))
          (`#(tcp-connected ,c)
            (tcp-read-start! c)
            (tcp-write! c
              (string->utf8
                (string-append "GET " path " HTTP/1.1\r\nHost: x\r\n"
                  (apply string-append
                         (map (lambda (h) (string-append h "\r\n")) headers))
                  "Connection: close\r\n\r\n"))
              #f)
            (let loop ((buf empty-bv))
              (receive (after 5000 (tcp-close! c)
                         (send caller (vector 'r ref (utf8->string buf))))
                (`#(tcp-data ,bv) (loop (bv-append buf bv)))
                (`#(tcp-eof) (send caller (vector 'r ref (utf8->string buf))))
                (`#(tcp-error ,_)
                  (send caller (vector 'r ref (utf8->string buf)))))))
          (`#(tcp-connect-failed ,e) (send caller (vector 'r ref ""))))))
    (receive (after 10000 "") (`#(r ,@ref ,s) s))))

(define store (make-session-store))
(define app (create-app))
(app-use app (session-middleware store '((secure . #f))))

;; ---- the two-sided contract, in one request ----------------------------
(define before-claim 'unrun)
(define after-claim 'unrun)

(app-get app "/contract"
  (lambda (req res)
    (set! before-claim
      (set-header-if-unanswered! res "X-Before" "yes"))
    (send-text! res "answered")          ; claims the response
    (set! after-claim
      (set-header-if-unanswered! res "X-After" "yes"))))

;; ---- rotation must not drop when publication fails ---------------------
(app-get app "/seed"
  (lambda (req res)
    (session-set! (req-session req) 'marker "kept")
    (send-text! res "seeded")))

(define rotate-outcome 'unrun)
(app-get app "/rotate-after-answer"
  (lambda (req res)
    (send-text! res "answered")          ; claims first
    (set! rotate-outcome
      (guard (e (#t 'refused))
        (session-regenerate! (req-session req))
        'rotated))))

(app-get app "/report"
  (lambda (req res)
    (send-text! res
      (string-append (if (eq? before-claim #t) "t" "f")
                     (if (eq? after-claim #f) "f" "t")
                     "|" (symbol->string rotate-outcome)))))

(define (extract-sid resp)
  (let ((at (find-substr resp "sid=")))
    (and at (let scan ((i (+ at 4)))
              (if (or (= i (string-length resp))
                      (memv (string-ref resp i) '(#\; #\return #\newline)))
                  (substring resp (+ at 4) i)
                  (scan (+ i 1)))))))

(define (body-of resp)
  (let ((b (find-substr resp "\r\n\r\n")))
    (if b (substring resp (+ b 4) (string-length resp)) "")))

(start-scheduler
  (lambda ()
    (app-listen app port)
    (sleep-ms 100)

    (let ((resp (http-get "/contract")))
      (check "publishing before the claim succeeds" (eq? #t before-claim))
      (check "publishing after the claim is refused" (eq? #f after-claim))
      ;; #t has to mean the client actually gets it, not merely that the
      ;; call returned: that is the whole promise the caller acts on
      (check "a published header reaches the client"
        (and (find-substr resp "X-Before: yes") #t))
      (check "a refused header does not reach the client"
        (not (find-substr resp "X-After"))))

    (let* ((seed (http-get "/seed"))
           (sid (extract-sid seed)))
      (check "seeded session exists" (and sid (session-peek store sid) #t))
      (when sid
        (http-get "/rotate-after-answer" (string-append "Cookie: sid=" sid))
        (sleep-ms 150)
        (check "rotation refuses once the response is claimed"
          (eq? 'refused rotate-outcome))
        ;; the point of refusing: the live id must survive it
        (check "a refused rotation leaves the old id in the store"
          (let ((data (session-peek store sid)))
            (and data (equal? (cdr (assq 'marker data)) "kept"))))))

    ;; the handler-side view, so a wrong value cannot hide behind a
    ;; passing HTTP status
    (display "  [contract] ") (display (body-of (http-get "/report"))) (newline)

    (if (zero? failures)
        (begin (display "response-header-claim: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
