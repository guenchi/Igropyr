#!chezscheme
;; The listener that stops accepting (accept-reserve-design.md).
;;
;; Under memory pressure foreign-alloc RAISES -- measured, it does not answer 0
;; -- and it used to raise inside the connection callback, in the window between
;; uv__server_io handing a descriptor up and uv_accept consuming it. The outer
;; guard counted the raise and returned; the descriptor stayed unconsumed; libuv
;; stopped polling the listener, for good, in silence. The fix moves the
;; allocation out of that window: the listener carries a RESERVE, plain memory
;; taken at listen time, and refills it AFTER each accept.
;;
;;   R1  rung 1, the normal path: accepted, and the reserve is full again after
;;   R2  THE INVARIANT: with a reserve in hand the accept path does not allocate
;;   R3  rung 2: a refill that failed leaves the reserve empty, and the NEXT
;;       connection is still accepted -- by allocating in the window, as before
;;   R4  rung 3: empty reserve and the in-window attempt fails too. The listener
;;       closes LOUDLY: refused, listener-open? #f, the count moves, and the
;;       port is free for a new listener -- released, not pinned
;;   R5  the twin that keeps R4 honest: the same setup without the second fault
;;       accepts and stays open. Without it R4 cannot tell a working ladder from
;;       an implementation that closes listeners whenever provoked
;;   R6  a raise between uv_accept and publication closes the client handle and
;;       leaves the listener alive -- the descriptor was already consumed
;;   R7  the counts name four causes and keep them apart
;;   R8  a reserve is a BLOCK, not an initialised handle: opening a listener
;;       adds ONE to the live handle count, not two
;;   R9  the same ladder on a pipe listener, since the reserve is per transport
;;
;; Seams this file needs, named here so the names are agreed in one place:
;;   ($listener-reserve? l)        -> #t when that listener holds a reserve
;;   'accept-reserve-rearm         fault point: the refill AFTER an accept
;;   'accept-reserve-inwindow      fault point: rung 2's attempt INSIDE the window
;;   'accept-before-publish        fault point: after uv_accept, before the conn
;;                                 reaches conn-table
;; Reaching rung 2 through 'accept-reserve-rearm rather than through a back door
;; matters: it is the state production would be in, arrived at the way
;; production would arrive at it.
(import (chezscheme) (igropyr actor) (igropyr tcp)
        (only (igropyr libuv) now-ms uv-live-handle-count)
        (igropyr inject-control))
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
(define (hits p) (or (inject-hits p) 0))
(define (counts) (uv-accept-failure-counts))
(define (count-of k) (cond ((assq k (counts)) => cdr) (else 'no-key)))
(define (handles-settled)
  (let poll ((prev (uv-live-handle-count)) (n 0))
    (sleep-ms 50)
    (let ((now (uv-live-handle-count)))
      (cond ((= now prev) now) ((>= n 100) now) (else (poll now (+ n 1)))))))
(define dir "/tmp/ig-ar")
(system (string-append "rm -rf " dir " && mkdir -p " dir))
(define port-base 18420)

(start-scheduler
  (lambda ()
    (define main self)
    ;; one listener, one dial, the accepted conn delivered here; #f if none came
    (define (listen-on port)
      (tcp-listen! "127.0.0.1" port 16 (lambda (c) (send main (vector 'acc c)))))
    (define (dial port) (tcp-connect! "127.0.0.1" port main))
    (define (took-a-connection? ms)
      (receive (after ms #f) (`#(acc ,c) c)))
    ;; THE DIALLING END HAS TO BE CLOSED TOO. The first version of this helper
    ;; took the completion message and returned the conn without closing it, so
    ;; every SUCCESSFUL dial left a live client conn and its handle behind. The
    ;; rows that count handles back to baseline are the ones that noticed -- R4
    ;; and R6 -- and they were reading this leak, not the implementation's.
    (define (drain-dial! ms)
      (receive (after ms 'none)
        (`#(tcp-connected ,c) (tcp-close! c) (list 'connected c))
        (`#(tcp-connect-failed ,s) (list 'failed s))))

    ;; ---- R1: the normal path refills -----------------------------------------
    (inject-disarm!)
    (let* ((port port-base)
           (l (listen-on port)))
      (check "R1: a fresh listener holds a reserve" ($listener-reserve? l))
      (dial port)
      (let ((srv (took-a-connection? 5000)))
        (check "R1: the connection was accepted" (and srv (conn? srv)) srv)
        (check "R1: and the reserve is full again afterwards"
               (within? 3000 (lambda () ($listener-reserve? l))))
        (when srv (tcp-close! srv)))
      (drain-dial! 3000)
      (tcp-stop-listen! l (listener-token l)))

    ;; ---- R2: HALF THE INVARIANT, AND THE HALF THAT MATTERS ---------------------
    ;; The in-window point is only reached when the reserve is empty. Arming it
    ;; while a reserve is in hand and seeing ZERO hits says the normal accept
    ;; path did not need to allocate. If a later change puts a foreign-alloc back
    ;; into the window, this row is what goes red.
    ;;
    ;; It does NOT witness "the window allocates nothing". Measured by the code
    ;; session: in an injection build every inject point costs 80 bytes of Scheme
    ;; heap per call, armed or not, and the window already holds one -- the
    ;; override wrapping uv_accept, which cannot be moved out because wrapping
    ;; that call is its whole purpose. In a production build the points expand
    ;; away and that cost is zero. So the invariant reads: no foreign-alloc on
    ;; rung 1, and in a production build no allocation at all.
    ;;
    ;; The half this row witnesses is the half that wedges listeners: the wedge
    ;; comes from foreign-alloc raising, not from the Scheme heap. Note also what
    ;; a (bytes-allocated) reading cannot see -- foreign-alloc goes to the C heap,
    ;; so its zero there means "does not move the Scheme heap", and the C-heap
    ;; allocation this batch exists to move out of the window is invisible to
    ;; that instrument. Only moving it is evidence that it moved.
    (inject-disarm!)
    (let* ((port (+ port-base 1))
           (l (listen-on port)))
      (inject-arm-fault! 'accept-reserve-inwindow 1)
      (dial port)
      (let ((srv (took-a-connection? 5000)))
        (check "R2: the connection was accepted with the reserve in hand" (and srv (conn? srv)) srv)
        (check "R2: the in-window allocation was never reached (no foreign-alloc on rung 1)"
               (eqv? (hits 'accept-reserve-inwindow) 0) (hits 'accept-reserve-inwindow))
        (when srv (tcp-close! srv)))
      (drain-dial! 3000)
      (inject-disarm!)
      (tcp-stop-listen! l (listener-token l)))

    ;; ---- R3: rung 2 ------------------------------------------------------------
    (inject-disarm!)
    (let* ((port (+ port-base 2))
           (l (listen-on port)))
      (inject-arm-fault! 'accept-reserve-rearm 1)
      (dial port)
      (let ((srv (took-a-connection? 5000)))
        (check "R3: the first connection was accepted" (and srv (conn? srv)) srv)
        (check "R3: the refill after it raised" (eqv? (hits 'accept-reserve-rearm) 1)
               (hits 'accept-reserve-rearm))
        (check "R3: so the listener now holds no reserve"
               (within? 3000 (lambda () (not ($listener-reserve? l)))))
        (when srv (tcp-close! srv)))
      (drain-dial! 3000)
      ;; the fault was one-shot: the second connection allocates in the window
      (dial port)
      (let ((srv (took-a-connection? 5000)))
        (check "R3: the SECOND connection is still accepted, from an empty reserve"
               (and srv (conn? srv)) srv)
        (check "R3: and the reserve is full again"
               (within? 3000 (lambda () ($listener-reserve? l))))
        (check "R3: the listener is still open" (listener-open? l (listener-token l)))
        (when srv (tcp-close! srv)))
      (drain-dial! 3000)
      (inject-disarm!)
      (tcp-stop-listen! l (listener-token l)))

    ;; ---- R4: rung 3 -------------------------------------------------------------
    (inject-disarm!)
    (let* ((port (+ port-base 3))
           (base-handles (handles-settled))
           (before (count-of 'exhausted))
           (l (listen-on port))
           (tok (listener-token l)))
      (inject-arm-fault! 'accept-reserve-rearm 1)
      (inject-arm-fault! 'accept-reserve-inwindow 1)
      (dial port)
      (let ((srv (took-a-connection? 5000)))
        (check "R4: the first connection was accepted" (and srv (conn? srv)) srv)
        (when srv (tcp-close! srv)))
      (drain-dial! 3000)
      ;; the second one finds no reserve and cannot make one
      (dial port)
      (check "R4: the second connection is NOT accepted" (not (took-a-connection? 2000)))
      (check "R4: both faults fired once"
             (and (eqv? (hits 'accept-reserve-rearm) 1) (eqv? (hits 'accept-reserve-inwindow) 1))
             (hits 'accept-reserve-rearm) (hits 'accept-reserve-inwindow))
      (check "R4: the listener answers closed" (within? 3000 (lambda () (not (listener-open? l tok)))))
      (check "R4: the exhausted count moved by one"
             (eqv? (count-of 'exhausted) (+ before 1)) (count-of 'exhausted) before)
      (drain-dial! 3000)
      (inject-disarm!)
      ;; THE READING THAT SAYS RELEASED RATHER THAN PINNED
      (let ((l2 (guard (e (#t #f)) (listen-on port))))
        (check "R4: a new listener takes the same port -- the old one released it" (and l2 #t))
        (when l2 (tcp-stop-listen! l2 (listener-token l2))))
      (check "R4: handles back to baseline"
             (within? 5000 (lambda () (= (uv-live-handle-count) base-handles)))
             (uv-live-handle-count) base-handles))

    ;; ---- R5: the twin that keeps R4 honest ---------------------------------------
    ;; same shape, only the in-window fault removed. If R4 passed because the
    ;; implementation closes a listener whenever anything goes wrong, this row
    ;; fails
    (inject-disarm!)
    (let* ((port (+ port-base 4))
           (before (count-of 'exhausted))
           (l (listen-on port))
           (tok (listener-token l)))
      (inject-arm-fault! 'accept-reserve-rearm 1)
      (dial port)
      (let ((srv (took-a-connection? 5000))) (when srv (tcp-close! srv)))
      (drain-dial! 3000)
      (dial port)
      (let ((srv (took-a-connection? 5000)))
        (check "R5: without the second fault the connection IS accepted" (and srv (conn? srv)) srv)
        (when srv (tcp-close! srv)))
      (drain-dial! 3000)
      (check "R5: and the listener is still open" (listener-open? l tok))
      (check "R5: and nothing was counted as exhausted"
             (eqv? (count-of 'exhausted) before) (count-of 'exhausted) before)
      (inject-disarm!)
      (tcp-stop-listen! l (listener-token l)))

    ;; ---- R6: a raise after uv_accept ------------------------------------------------
    ;; the descriptor is already consumed, so the listener is not in danger; what
    ;; must not happen is the client handle going with the exception
    (inject-disarm!)
    (let* ((port (+ port-base 5))
           (base-handles (handles-settled))
           (l (listen-on port))
           (tok (listener-token l)))
      (inject-arm-fault! 'accept-before-publish 1)
      (dial port)
      (check "R6: no conn reaches the accept callback" (not (took-a-connection? 2000)))
      (check "R6: the seam fired once" (eqv? (hits 'accept-before-publish) 1)
             (hits 'accept-before-publish))
      (check "R6: the listener survives -- the descriptor was consumed" (listener-open? l tok))
      (drain-dial! 3000)
      (inject-disarm!)
      ;; the next connection proves the listener is not merely open but working
      (dial port)
      (let ((srv (took-a-connection? 5000)))
        (check "R6: and it still accepts" (and srv (conn? srv)) srv)
        (when srv (tcp-close! srv)))
      (drain-dial! 3000)
      (tcp-stop-listen! l (listener-token l))
      (check "R6: the orphaned client handle was closed, not leaked"
             (within? 5000 (lambda () (= (uv-live-handle-count) base-handles)))
             (uv-live-handle-count) base-handles))

    ;; ---- R7: the counts --------------------------------------------------------------
    (let ((c (counts)))
      (check "R7: the failure counts name six causes, separately"
             (and (list? c) (= (length c) 6)
                  (assq 'callback-raised c) (assq 'accept-status c) (assq 'refused c)
                  (assq 'straggler c) (assq 'exhausted c) (assq 'read-start c)) c))

    ;; ---- R8: a reserve is a block, not a handle ----------------------------------------
    ;; an initialised handle would be in the loop's handle queue and uv_walk would
    ;; count it, so a listener would cost two. This row is what goes red if the
    ;; reserve is ever "simplified" into a pre-initialised handle
    (inject-disarm!)
    (let* ((port (+ port-base 6))
           (base-handles (handles-settled))
           (l (listen-on port)))
      (check "R8: it holds a reserve" ($listener-reserve? l))
      (check "R8: and opening the listener cost ONE handle, not two"
             (within? 3000 (lambda () (= (uv-live-handle-count) (+ base-handles 1))))
             (uv-live-handle-count) base-handles)
      (tcp-stop-listen! l (listener-token l))
      (check "R8: back to baseline after the stop"
             (within? 5000 (lambda () (= (uv-live-handle-count) base-handles)))
             (uv-live-handle-count) base-handles))

    ;; ---- R9: the same ladder on a pipe listener -------------------------------------
    (inject-disarm!)
    (let* ((path (string-append dir "/r9"))
           (l (pipe-listen! path 16 (lambda (c) (send main (vector 'acc c)))))
           (tok (listener-token l)))
      (check "R9: a pipe listener holds a reserve too" ($listener-reserve? l))
      (inject-arm-fault! 'accept-reserve-rearm 1)
      (inject-arm-fault! 'accept-reserve-inwindow 1)
      (pipe-connect! path main)
      (let ((srv (took-a-connection? 5000)))
        (check "R9: the first connection was accepted" (and srv (conn? srv)) srv)
        (when srv (tcp-close! srv)))
      (drain-dial! 3000)
      (pipe-connect! path main)
      (check "R9: the second is not accepted" (not (took-a-connection? 2000)))
      (check "R9: the pipe listener answers closed too"
             (within? 3000 (lambda () (not (listener-open? l tok)))))
      (drain-dial! 3000)
      (inject-disarm!))

    (if (zero? fails)
        (begin (display "ALL ACCEPT-RESERVE TESTS PASSED\n") (exit 0))
        (begin (display "ACCEPT-RESERVE VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
