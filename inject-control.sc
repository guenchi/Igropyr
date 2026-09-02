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
;;; perturbs.
(library (igropyr inject-control)
  (export inject-arm-fault! inject-arm-return! inject-release!
          inject-disarm! inject-hits inject-delivered inject-armed-points)
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

  (define (inject-release! ticket) ($inject-release! ticket))
  (define (inject-disarm!) ($inject-disarm!))
  (define (inject-hits point) ($inject-hits point))

  ;; How many times an injected value was actually returned at this
  ;; point. Differs from inject-hits when the wrapped expression raises:
  ;; the occurrence is spent, nothing is delivered.
  (define (inject-delivered point) ($inject-delivered-count point))
  (define (inject-armed-points) ($inject-armed-points)))
