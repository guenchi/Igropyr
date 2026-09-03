;;; inject-control.sc -- the arming side of fault injection.
;;;
;;; ⛔ TEST-ONLY, AND THE SEPARATION IS THE POINT. The primitives live in
;;; (igropyr inject) because the code being perturbed has to name them;
;;; this library is what a TEST uses to arm them, and nothing in the
;;; library proper may import it. That is checked mechanically rather
;;; than promised: a consumer's invoke-requirements must never mention
;;; (igropyr inject-control) -- see test/inject-isolation.ss.
;;;
;;; ⚠ IT IS ALSO WHY THE PROCESS FILTER LIVES HERE. (igropyr inject)
;;; imports (chezscheme) and nothing else, so it cannot know what a
;;; process is; arming with a pid builds a predicate here and hands the
;;; closure over. The instrument does not learn about the layer it
;;; perturbs. The barrier below is the same arrangement carried further:
;;; the PARKER is built here and stored in the row, so (igropyr inject)
;;; can suspend a process without knowing that processes exist.
;;;
;;; ⭐ THE BARRIER PROTOCOL, IN ORDER. Departing from it is what the
;;; assertions below are for; each step names the one that catches it.
;;;   1. controller: (inject-arm-barrier! point occurrence [timeout [before]])
;;;   2. victim reaches the point, reserves it, and reports:
;;;      #(inject-barrier ticket point victim-pid)
;;;   3. controller: (inject-barrier-wait ticket point bound-ms)
;;;   4. controller: (send victim (vector 'inject-resume ticket))
;;;   5. controller: (inject-release! ticket) -- ONLY after the state is
;;;      terminal, and release itself refuses while it is not.
;;;
;;; ⛔ resumed / skipped / timed-out SAY THAT THE RESERVATION IS
;;; CONSUMED, AND NOTHING ELSE. None of them says the victim finished the
;;; work it was parked in the middle of, or that it is still running. A
;;; cell that needs the work to have happened waits for a witness the
;;; VICTIM sends; a cell that reads state instead is asserting that the
;;; instrument moved, not that the subject did.
;;;
;;; ⚠ THE CONTROLLER MUST OUTLIVE THE WAIT, OR EXIT ON PURPOSE. The
;;; parker sends the report to the process that armed the barrier. If
;;; that process is gone the report is discarded silently (send to a dead
;;; pid is a no-op, actor.sc), the victim then parks for its full timeout,
;;; and the row is left behind holding a ticket nobody will release. Arm
;;; from the boot process, or arrange the exit yourself.
(library (igropyr inject-control)
  (export inject-arm-fault! inject-arm-return! inject-arm-barrier!
          inject-barrier-wait inject-barrier-cleanup! inject-barrier-drain!
          inject-release! inject-disarm! inject-hits inject-delivered
          inject-armed-points
          inject-barrier-state inject-barrier-skipped inject-barrier-timeouts)
  (import (chezscheme) (igropyr inject) (igropyr actor))

  ;; -> ticket. occurrence: #f = every hit, k = the k-th hit only.
  ;; pid: #f = any process, p = only while p is running.
  ;;
  ;; ⭐ THE TICKET IS THE ONLY HANDLE. It is global, monotone and never
  ;; reused -- re-arming the same point yields a new one -- so a report
  ;; that arrives late names the arming it came from and no other. A
  ;; controller that matched on the point name instead would credit a
  ;; stale report to the arming that replaced it.
  (define inject-arm-fault!
    (case-lambda
      ((point) (inject-arm-fault! point #f #f))
      ((point occurrence) (inject-arm-fault! point occurrence #f))
      ((point occurrence pid)
       ($inject-arm! point 'fault #f occurrence (pid-filter pid)))))

  ;; ⭐ THE VALUE RULES ARE NOT HERE. They live in $inject-arm!, which is
  ;; the boundary every arming path crosses -- including a direct call to
  ;; the exported raw form. A copy here would be a second supplier of the
  ;; same judgement and the one that gets bypassed.
  (define inject-arm-return!
    (case-lambda
      ((point value) (inject-arm-return! point value #f #f))
      ((point value occurrence) (inject-arm-return! point value occurrence #f))
      ((point value occurrence pid)
       ($inject-arm! point 'return value occurrence (pid-filter pid)))))

  ;; ⛔ `self` IS AN IDENTIFIER, NOT A PROCEDURE -- actor.sc binds it with
  ;; identifier-syntax. Writing (self) applied the current process record
  ;; as a function, so every pid-filtered arm raised at the hit, inside a
  ;; write path, instead of filtering. ⚠ No cell arms with a pid yet, so
  ;; the bug shipped invisible: a parameter that has never been exercised
  ;; is not a parameter that works.
  (define (pid-filter pid)
    (and pid (lambda () (eq? self pid))))

  ;; ---- barrier: arming ---------------------------------------------
  ;;
  ;; occurrence must be a positive fixnum; $inject-arm! refuses #f for a
  ;; barrier, because a barrier that fires on every hit parks the second
  ;; arrival before the controller has resumed the first.
  ;;
  ;; timeout-ms bounds how long the VICTIM stays parked. It is the
  ;; victim's own escape hatch, not the controller's: nothing else can
  ;; free a process that is parked in the middle of a region. Default
  ;; 30 s, which every cell's orchestration must finish well inside.
  ;;
  ;; before-report delays the report WITHOUT delaying the reservation.
  ;; The row goes to 'reserved at the hit and stays there for this long
  ;; before the parker publishes 'parked -- that window is the only way
  ;; to observe a reservation that has not been reported yet, which is
  ;; what makes "reserved" distinguishable from "never arrived".
  (define inject-arm-barrier!
    (case-lambda
      ((point occurrence) (inject-arm-barrier! point occurrence 30000 #f))
      ((point occurrence timeout-ms)
       (inject-arm-barrier! point occurrence timeout-ms #f))
      ((point occurrence timeout-ms before-report)
       ;; ⭐ CAPTURED HERE, NOT READ IN THE PARKER. The parker runs in the
       ;; victim, where `self` is the victim; the report has to go to the
       ;; process that armed it.
       (let ((controller self))
         ($inject-arm! point 'barrier
           (make-parker controller timeout-ms before-report)
           occurrence #f)))))

  ;; The parker owns slots 9, 10 and 11 from the moment $inject-barrier
  ;; applies it -- see the slot/writer table in inject.sc. It is the only
  ;; writer of each, which is what makes the regions here sufficient.
  (define (make-parker controller timeout-ms before-report)
    (lambda (point ticket row)
      ;; ⛔ A CONTROLLER CANNOT PARK ITSELF. It would publish the report
      ;; into its own inbox and then block waiting for a resume that only
      ;; it could send -- a deadlock that looks exactly like a victim
      ;; which never reached the point. Refusing here names it.
      (when (eq? self controller)
        (assertion-violation 'inject-barrier!
          "the controller is the victim: arm from another process"
          point ticket))
      (when before-report (sleep-ms before-report))
      ;; ⭐ ONE REGION: STATE, VICTIM AND REPORT TOGETHER. Publishing the
      ;; report before slot 11 is written would let a controller that
      ;; reacts immediately read a row whose victim slot is still #f, and
      ;; release is what reads it. These three are one fact.
      (with-interrupts-disabled
        (vector-set! row 10 'parked)
        (vector-set! row 11 self)
        (send controller (vector 'inject-barrier ticket point self)))
      ;; ⭐ ,@ticket COMPARES, IT DOES NOT BIND (actor.sc's match-qp). A
      ;; resume naming a different arming of the same point is left in
      ;; the inbox rather than mistaken for this one.
      (let ((resumed? (receive (after timeout-ms #f)
                        (`#(inject-resume ,@ticket) #t))))
        (with-interrupts-disabled
          (cond
            (resumed? (vector-set! row 10 'resumed))
            (else
             (vector-set! row 9 (fx+ (vector-ref row 9) 1))
             (vector-set! row 10 'timed-out)))))))

  ;; ---- barrier: waiting --------------------------------------------
  ;;
  ;; -> (parked . pid) | skipped | timeout. THE FIRST RESULT ONLY: it
  ;; does not release, and it does not wait a second time. A wait that
  ;; cleaned up after itself would make the timeout path untestable,
  ;; because the state it is supposed to leave behind is the evidence.
  ;;
  ;; ⚠ `skipped` HAS NO MESSAGE. A victim that hits the point with
  ;; interrupts already disabled cannot park -- it counts slot 8, marks
  ;; the row 'skipped and runs on -- so the only way to learn it is to
  ;; read the state when nothing arrived. That is why the timeout branch
  ;; reads state rather than reporting `timeout` outright.
  (define (inject-barrier-wait ticket point bound-ms)
    (receive (after bound-ms
               (if (eq? ($inject-barrier-state ticket) 'skipped)
                   'skipped
                   'timeout))
      (`#(inject-barrier ,@ticket ,@point ,pid) (cons 'parked pid))))

  ;; ---- barrier: releasing and cleanup ------------------------------
  ;;
  ;; ⭐ ONE ARGUMENT, AND alive? IS BOUND HERE. The raw face takes the
  ;; predicate because (igropyr inject) has no idea what a process is;
  ;; letting a caller pass one would let it pass a boolean, and
  ;; `(lambda (v) #t)` at that position turns the dead-victim exit into
  ;; "release anything", silently. There is one supplier: this line.
  (define (inject-release! ticket) ($inject-release! ticket process-alive?))
  (define (inject-disarm!) ($inject-disarm!))
  (define (inject-hits point) ($inject-hits point))

  ;; How many times an injected value was actually returned at this
  ;; point. Differs from inject-hits when the wrapped expression raises:
  ;; the occurrence is spent, nothing is delivered.
  (define (inject-delivered point) ($inject-delivered-count point))
  (define (inject-armed-points) ($inject-armed-points))

  ;; ⚠ BY TICKET. #f means "no barrier row with that ticket" -- released
  ;; already, or a ticket naming a fault/return row -- and is NOT 0.
  (define (inject-barrier-state ticket) ($inject-barrier-state ticket))
  (define (inject-barrier-skipped ticket) ($inject-barrier-skipped ticket))
  (define (inject-barrier-timeouts ticket) ($inject-barrier-timeouts ticket))

  ;; Resume a parked victim and wait for its state to become terminal.
  ;; -> the terminal state.
  ;;
  ;; ⭐ ONE SUBROUTINE, THREE CALLERS: both parked paths in cleanup!
  ;; below, and the cell that gets (parked . pid) from its FIRST wait and
  ;; does its own resume. Written out three times it would be three
  ;; chances to get the terminal set wrong.
  ;;
  ;; ⛔ A VICTIM THAT IS PARKED AND ALIVE AND NEVER RESUMES IS AN
  ;; INVARIANT FAILURE, NOT A RETRY. The report was published atomically
  ;; with the state, so the resume reached a live process that is still
  ;; sitting in its receive; waiting longer cannot change that.
  (define (inject-barrier-drain! pid ticket bound-ms)
    (send pid (vector 'inject-resume ticket))
    (let loop ((waited 0))
      (let ((st (inject-barrier-state ticket)))
        (cond
          ((memq st '(resumed timed-out)) st)
          ;; A victim that died while parked will never write a terminal
          ;; state; release has its own exit for exactly this row.
          ((and (eq? st 'parked) (not (process-alive? pid))) st)
          ((fx>= waited bound-ms)
           (if (and (eq? st 'parked) (process-alive? pid))
               (assertion-violation 'inject-barrier-cleanup!
                 "victim parked and alive but never resumed" ticket st)
               st))
          (else (sleep-ms 10) (loop (fx+ waited 10)))))))

  ;; ⚠ PRECONDITION: CALL THIS ONLY AFTER A FIRST WAIT RETURNED `timeout`.
  ;; A cell whose first wait returned (parked . pid) resumes it itself
  ;; (inject-barrier-drain!) and then releases; one that got `skipped`
  ;; waits for its completion witness and releases. Calling cleanup!
  ;; after either of those releases the row on the first step and then
  ;; waits second-wait-ms for a report that was already consumed.
  ;;
  ;; second-wait-ms is the caller's number: the arm's timeout-ms plus a
  ;; margin. The row does not store the timeout, so it cannot be derived.
  ;;
  ;; -> (released . row) | (released-after-drain . row), where row may be
  ;; #f when it was already gone. Rows that cannot be resolved are LEFT
  ;; IN PLACE and raise: a cleanup that deleted them would erase the only
  ;; evidence of what went wrong.
  (define cleanup-blocked (list 'barrier-still-live))

  (define (inject-barrier-cleanup! ticket point second-wait-ms)
    ;; ⭐ RELEASE FIRST. If the victim never reserved the point at all
    ;; there is nothing to wait for, and waiting would spend the whole
    ;; bound proving it. Release refuses only while the row is live, and
    ;; that refusal is the signal to start phase two.
    (let ((r (guard (e ((release-blocked? e) cleanup-blocked))
               (cons 'released (inject-release! ticket)))))
      (if (not (eq? r cleanup-blocked))
          r
          (let ((first (inject-barrier-wait ticket point second-wait-ms)))
            (cond
              ((pair? first)
               (inject-barrier-drain! (cdr first) ticket second-wait-ms)
               (cons 'released-after-drain (inject-release! ticket)))
              ((eq? first 'skipped)
               (cons 'released (inject-release! ticket)))
              (else
               ;; timeout: the state says which of two different
               ;; failures this is, and they are not interchangeable.
               (let ((st (inject-barrier-state ticket)))
                 (cond
                   ;; Reserved and never reported: the victim took the
                   ;; occurrence and then died, or is stuck before the
                   ;; report. Nothing to resume.
                   ((eq? st 'reserved)
                    (assertion-violation 'inject-barrier-cleanup!
                      "reservation never reported" point st))
                   ;; Parked: the report may have landed in the inbox
                   ;; just after the timeout branch was taken. One more
                   ;; wait distinguishes "late" from "never".
                   ((eq? st 'parked)
                    (let ((second (inject-barrier-wait ticket point second-wait-ms)))
                      (if (pair? second)
                          (begin
                            (inject-barrier-drain! (cdr second) ticket second-wait-ms)
                            (cons 'released-after-drain (inject-release! ticket)))
                          (assertion-violation 'inject-barrier-cleanup!
                            "parked but never reported" point st))))
                   (else (cons 'released (inject-release! ticket)))))))))))

  ;; ⛔ MATCHES THE RAW FACE'S OWN NAME. $inject-release! raises with who
  ;; = '$inject-release! (inject.sc), not the name of this library's
  ;; wrapper. Matching the wrapper's name here would re-raise every
  ;; refusal instead of entering phase two, and the cell would fail
  ;; inside cleanup! rather than at the thing cleanup! exists to survive.
  ;;
  ;; ⚠ Narrow on purpose: any OTHER assertion from release is a real
  ;; error and is re-raised by falling through the guard.
  (define (release-blocked? e)
    (and (assertion-violation? e)
         (who-condition? e)
         (eq? (condition-who e) '$inject-release!)
         (message-condition? e)
         (string=? (condition-message e) "barrier still live"))))
