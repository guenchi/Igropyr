#!chezscheme
;;; A CONNECTION THAT NEVER SENDS A BYTE IS CLOSED, AND THAT BRANCH HAD NO CELL.
;;;
;;; The header reader's timeout has two outcomes, and only one of them was
;;; covered anywhere in the tree:
;;;
;;;   (if (> (inbuf-length buf) 0)
;;;       (quick-response! c 408 "Request Timeout")   ; covered: a partial
;;;                                                   ; request is reaped
;;;       (tcp-close! c))                             ; NOT covered: a
;;;                                                   ; connection that has
;;;                                                   ; sent nothing at all
;;;
;;; The uncovered branch is the guard that keeps idle connections from
;;; accumulating. Remove it, or turn it into the 408 arm, and every existing
;;; suite still passes while a listener grows a permanent set of sockets that
;;; nothing will ever close. It was found empirically -- an experiment that
;;; wanted to hold idle connections open discovered it could not -- which is
;;; the signature of behaviour no test and no document describes.
;;;
;;; Two assertions, because one of them alone can be satisfied by the wrong
;;; server. "It closed" is also true of a server that drops every connection
;;; on arrival, so the cell also pins that the close does NOT come early.
;;; And it waits for tcp-eof specifically: a reset would arrive as tcp-error,
;;; which is a different behaviour that should not read as this one passing.
;;;
;;; WHAT MUTATION SAYS THIS CELL CAN AND CANNOT SEE (four mutations, shadow
;; tree, control green):
;;   * read-timeout-ms raised so the reaper effectively never fires  -> RED
;;     at the patience limit. This is the defect shape the cell exists for.
;;   * the idle branch answering 408 like the partial branch          -> RED
;;   * read-timeout-ms shortened to 250 ms                            -> RED
;;   * (tcp-close! c) replaced by (void)                        -> STILL GREEN,
;;     and the close was still observed at 30002 ms, the same instant as the
;;     real one. So the explicit close is not the only supplier of that
;;     observable: with it removed the handler simply returns and the socket
;;     goes away anyway. This cell therefore covers the BEHAVIOUR -- an
;;     idle connection is closed, at read-timeout-ms, cleanly -- and NOT that
;;     particular line. Anyone deleting the line should not read a green suite
;;     as permission; nothing here distinguishes the two paths.
;;
;; This cell costs read-timeout-ms of wall clock (30 s at the time of
;;; writing) because read-timeout-ms has no setter, unlike request-deadline-ms
;;; which http-request-deadline! can shorten for exactly this reason. That
;;; missing seam is why the branch went untested; if a setter is ever added,
;;; shorten this cell rather than deleting it.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
        (igropyr express))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18779)
(define early-ms 5000)     ; by here a correct server has NOT closed
(define patience-ms 60000) ; by here a correct server HAS closed

;; Connects, sends nothing, and reports what the server did and when.
;; Outcome is one of: eof (the branch under test), error (a reset, which is
;; a different behaviour), or none (still open when patience ran out).
(define (silent-client! report)
  (spawn
    (lambda ()
      (tcp-connect! "127.0.0.1" port self)
      (receive (after 5000 (send report (vector 'result 'no-connect #f)))
        (`#(tcp-connect-failed ,e) (send report (vector 'result 'no-connect #f)))
        (`#(tcp-connected ,c)
          (tcp-read-start! c)
          (let ((t0 (now-ms)))
            ;; Not one byte is ever written. That is the whole fixture.
            (receive (after patience-ms
                       (send report (vector 'result 'none (- (now-ms) t0))))
              (`#(tcp-eof)   (send report (vector 'result 'eof   (- (now-ms) t0))))
              (`#(tcp-error ,e) (send report (vector 'result 'error (- (now-ms) t0))))
              (`#(tcp-data ,bv)
                ;; A server that answers an empty request is neither branch.
                (send report (vector 'result 'data (- (now-ms) t0)))))))))))

(start-scheduler
  (lambda ()
    (let ((app (create-app)) (main self))
      (app-get app "/" (lambda (req res) (send-text! res "ok")))
      (app-listen app port)
      (sleep-ms 300)

      (silent-client! main)
      (receive (after (+ patience-ms 10000)
                 (check "the silent client reported at all" #f))
        (`#(result ,how ,ms)
          (check "the server closed an idle connection rather than holding it"
                 (eq? how 'eof))
          (check "it closed with a clean EOF, not a reset or a response"
                 (not (memq how '(error data))))
          ;; The paired half: "it closed" is also true of a server that drops
          ;; every arrival, so the close must not be early.
          (check "and it did not close on arrival"
                 (and ms (> ms early-ms)))
          (display "  (idle close observed at ") (display ms) (display " ms)\n")))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "idle-close: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
