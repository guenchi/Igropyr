#!chezscheme
;; The write block is owned before the copy begins
;; (archive/igropyr-mesh-tls-design/write-block-window-design.md).
;;
;; A block allocated for a queued write is orphaned if the writing process dies
;; before the block is registered: nothing holds it, so uv-owner-died! sweeping
;; that process finds nothing to free. Measured 2026-09-18 on the live tree:
;; live 1 / table 0 before the kill and live 1 / table 0 after it.
;;
;; THE FIRST DRAFT OF THIS FILE SAMPLED TWO INSTANTS AND INFERRED ABOUT THE
;; INTERVAL BETWEEN THEM, WHICH IS THE SUBJECT. It parked before the copy and
;; after it and compared counts. Two implementations the design forbids survive
;; that: one that indexes under either owner during the copy and drops the entry
;; before the later park, and one that unindexes right after the first park and
;; re-indexes before the second. Every snapshot agrees and the copy-time hole is
;; untouched.
;;
;; A1 IS THE INSTRUMENT THAT FIXES IT, AND IT IS DETERMINISTIC. Park at the
;; point that begins the copy; arm the point that ends it as a TRIPWIRE; release;
;; kill after a delay; then assert the tripwire's hit count is ZERO. Released
;; past the start and never arrived at the end means the kill landed strictly
;; inside fill-data!. The hit count is the witness, so a badly chosen delay does
;; not pass quietly -- it fails at that assertion with hits = 1.
;;
;; WHAT IS RED TODAY, AND WHY EACH ONE IS RED. Three different reasons, and the
;; rows are written so the readings tell them apart:
;;   - the mechanism does not exist yet   -> A1/B1/B2/D1 reclamation assertions
;;   - 'write-before-copy does not exist  -> the parks print #f for the pid
;;   - uv-owner-entry-count does not exist -> C1/C2 cannot even be expressed, and
;;     say so rather than substituting a total that proves nothing
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
;; a never-firing arming, so a point's hits are counted without parking anyone
(define (count! point) (inject-arm-barrier! point 1000000 60000))
(define (hits point) (or (inject-hits point) 0))
(define (blocks) (list (write-blocks-live-count) (write-table-size)))
(define (base) (list (uv-live-handle-count) (conn-count) (uv-owner-index-count)))
(define port 18870)
;; Chez has no bytevector-append; A2 needs one to compare what arrived.
(define (cat bvs)
  (let* ((n (apply + (map bytevector-length bvs))) (out (make-bytevector n)))
    (let loop ((bs bvs) (o 0))
      (if (null? bs) out
          (let ((k (bytevector-length (car bs))))
            (bytevector-copy! (car bs) 0 out o k)
            (loop (cdr bs) (+ o k)))))))

;; Past the 64 KiB scratch path. NOT "the small-write path never allocates":
;; tcp-writev!'s partial and EAGAIN branches reach enqueue-write! with payloads
;; that started below the threshold. What is true is narrower -- a write the
;; scratch path completes in one uv_try_write allocates no block -- and F1 is
;; the row that keeps the narrower claim honest.
(define queued-size 1048576)
(define small-size 16)

;; A payload built from ONE shared segment repeated: the copy moves 128 MiB
;; through 16384 loop iterations while the Scheme heap holds 8 KiB. The copy has
;; to be long enough for a kill to land inside it, and long has to be cheap.
(define long-seg (make-bytevector 8192 9))
(define (long-payload) (let loop ((i 0) (a '())) (if (fx= i 16384) a (loop (fx+ i 1) (cons long-seg a)))))

;; -> (ticket pid status-box return-box). pid is #f when the point was never
;; reached. The writer reports tcp-write!'s RETURN as well as its on-done status:
;; a row that reads only the callback passes against a #t return (proc-faults.sc
;; P30 waits for #(wrote r) for this reason).
(define (park-writer! c point thunk)
  (let* ((st (vector 'none)) (rv (vector 'none))
         (t (inject-arm-barrier! point 1 60000))
         (w (spawn (lambda () (vector-set! rv 0 (thunk c st)))))
         (r (inject-barrier-wait t point 5000)))
    (list t (and (pair? r) (cdr r)) st rv w)))

(define (one-shot-write c st)
  (tcp-write! c (make-bytevector queued-size 7) (lambda (s) (vector-set! st 0 s))))
(define (long-write c st)
  (tcp-writev! c (long-payload) (lambda (s) (vector-set! st 0 s))))

(define (release-parked! t pid)
  (guard (e (#t (list 'release-raised e)))
    (when pid (inject-barrier-drain! pid t 3000))
    (inject-release! t)))

(start-scheduler
  (lambda ()
    (define main self)
    (let ((b0 (base)) (k0 (blocks)))
      (check "premise: the two block counts agree at the baseline" (eqv? (car k0) (cadr k0)) k0)

      (let* ((srv #f) (got '())
             (l (tcp-listen! "127.0.0.1" port 16
                  (lambda (c) (set! srv c) (conn-set-owner! c main) (tcp-read-start! c))))
             (cli (begin (tcp-connect! "127.0.0.1" port main)
                         (receive (after 3000 #f) (`#(tcp-connected ,c) c)))))
        (check "premise: a connection pair, server reading" (and cli (within? 2000 (lambda () srv))))

        ;; ---- A1: the kill lands strictly inside the copy ------------------
        (let* ((w0 (write-blocks-live-count)) (i0 (uv-owner-index-count))
               (tw (inject-arm-barrier! 'write-before-region 1 60000))
               (p (park-writer! cli 'write-before-copy long-write))
               (t (car p)) (pid (cadr p)))
          (check "A1 premise: a writer parked between the allocation and the copy (#f = the point does not exist yet)"
                 (and pid #t) pid)
          (check "A1 premise: it holds one block, already owned, copy not started"
                 (and pid (eqv? (write-blocks-live-count) (+ w0 1))) (blocks) w0)
          (when pid (inject-barrier-drain! pid t 3000))
          (guard (e (#t (void))) (inject-release! t))
          (sleep-ms 5)
          (when pid (kill pid 'test-kill))
          (check "A1 the writer never reached the end of the copy -- so the kill was INSIDE it"
                 (and pid (eqv? (hits 'write-before-region) 0)) (hits 'write-before-region))
          (guard (e (#t (void))) (inject-release! tw))
          (check "A1 the block is reclaimed by the owner-death sweep"
                 (and pid (within? 5000 (lambda () (eqv? (write-blocks-live-count) w0))))
                 (write-blocks-live-count) w0)
          (check "A1 ...and so is its index entry (a freed block with a live entry is the other half)"
                 (and pid (within? 5000 (lambda () (eqv? (uv-owner-index-count) i0))))
                 (uv-owner-index-count) i0))
        (inject-disarm!)

        ;; ---- A2: the twin. Without it A1 is satisfied by a writer that never
        ;; got anywhere, and nothing here would read a single byte.
        (let* ((w0 (write-blocks-live-count))
               (payload (make-bytevector queued-size 66))
               (tw (inject-arm-barrier! 'write-before-region 1 60000))
               (st (vector 'none)) (rv (vector 'none)))
          (set! got '())
          (let* ((t (inject-arm-barrier! 'write-before-copy 1 60000))
                 (w (spawn (lambda () (vector-set! rv 0 (tcp-write! cli payload (lambda (s) (vector-set! st 0 s)))))))
                 (r (inject-barrier-wait t 'write-before-copy 5000))
                 (pid (and (pair? r) (cdr r))))
            (check "A2 premise: the twin parked the same way" (and pid #t) pid)
            (release-parked! t pid)
            (check "A2 the writer DID reach the end of the copy" (within? 5000 (lambda () (eqv? (hits 'write-before-region) 1))) (hits 'write-before-region))
            (guard (e (#t (void))) (inject-release! tw))
            (check "A2 the write completes with status 0 and returned true"
                   (within? 5000 (lambda () (and (eqv? (vector-ref st 0) 0) (eq? (vector-ref rv 0) #t))))
                   (vector-ref st 0) (vector-ref rv 0))
            (check "A2 the bytes arrived, and are the bytes that were sent"
                   (within? 8000 (lambda () (let ((n (apply + (map bytevector-length got))))
                                              (and (= n queued-size)
                                                   (equal? (cat (reverse got)) payload)))))
                   (apply + (map bytevector-length got)) queued-size)
            (check "A2 the block returns by the ordinary path"
                   (within? 3000 (lambda () (eqv? (write-blocks-live-count) w0))) (write-blocks-live-count) w0)))
        (inject-disarm!)

        ;; ---- B1/B2: the two ends of the interval, still worth having -------
        (let loop ((pts '(write-before-copy write-before-region)) (n 1))
          (unless (null? pts)
            (let* ((pt (car pts)) (w0 (write-blocks-live-count)) (i0 (uv-owner-index-count))
                   (p (park-writer! cli pt one-shot-write))
                   (t (car p)) (pid (cadr p)))
              (check (string-append "B" (number->string n) " premise: parked at " (symbol->string pt))
                     (and pid #t) pid)
              (check (string-append "B" (number->string n) " premise: holding one unregistered block")
                     (and pid (eqv? (write-blocks-live-count) (+ w0 1)) (eqv? (write-table-size) (cadr k0)))
                     (blocks) w0)
              (when pid (kill pid 'test-kill))
              (release-parked! t pid)
              (check (string-append "B" (number->string n) " a kill there leaks neither the block nor the entry")
                     (and pid (within? 5000 (lambda () (and (eqv? (write-blocks-live-count) w0)
                                                            (eqv? (uv-owner-index-count) i0)))))
                     (blocks) w0 (uv-owner-index-count) i0))
            (inject-disarm!)
            (loop (cdr pts) (+ n 1))))

        ;; ---- E1: allocation failure. The seam exists at tcp.sc:4391 and
        ;; nothing in the tree arms it, here or in proc-faults.sc.
        (let ((w0 (write-blocks-live-count)) (i0 (uv-owner-index-count)))
          (inject-arm-fault! 'writev-oom 1)
          (let ((r (guard (e (#t 'raised)) (tcp-write! cli (make-bytevector queued-size 5) (lambda (s) (void))))))
            (check "E1 an allocation failure reaches the caller" (eq? r 'raised) r)
            (check "E1 ...and owns nothing: no block, no entry"
                   (and (eqv? (write-blocks-live-count) w0) (eqv? (uv-owner-index-count) i0))
                   (blocks) w0 (uv-owner-index-count) i0))
          (inject-disarm!)
          (let ((st (vector 'none)))
            (check "E1 twin: the connection still works afterwards"
                   (and (tcp-write! cli (make-bytevector small-size 1) (lambda (s) (vector-set! st 0 s)))
                        (within? 3000 (lambda () (eqv? (vector-ref st 0) 0)))) (vector-ref st 0))))
        (inject-disarm!)

        ;; ---- E2: the publish inside the first region can raise, because
        ;; hashtable-set! allocates when it adds a key. Measured: 74.2 bytes on a
        ;; new key, 0.0 on an existing one -- so this is once per writing
        ;; process, not a corner. If it raises after the block exists and the
        ;; region has no release, the orphan is back, permanently.
        (let ((w0 (write-blocks-live-count)))
          (count! 'write-block-released-index-fail)
          (inject-arm-fault! 'write-index-oom 1)
          (let ((r (guard (e (#t (list 'raised e)))
                     (tcp-write! cli (make-bytevector queued-size 3) (lambda (s) (void))))))
            (check "E2 the point was actually hit (0 hits would make every assertion below vacuous)"
                   (eqv? (hits 'write-index-oom) 1) (hits 'write-index-oom))
            (check "E2 a raise in the first region reaches the caller" (and (pair? r) (eq? (car r) 'raised)) r)
            (check "E2 ...and the block it had already allocated is released there, exactly once"
                   (and (eqv? (hits 'write-block-released-index-fail) 1)
                        (eqv? (write-blocks-live-count) w0))
                   (hits 'write-block-released-index-fail) (blocks) w0)))
        (inject-disarm!)

        ;; ---- C1/C2: attributability, and the bystander entry.
        ;;
        ;; THESE TWO ROWS CANNOT BE WRITTEN YET, AND THEY FAIL SAYING SO rather
        ;; than being left out or faked with a total. uv-owner-index-count sums
        ;; every entry of every kind under every owner, so a row asserting it
        ;; rose by one proves nothing about WHOSE entry appeared or what kind it
        ;; is -- and a design whose whole point is "keyed by the writer" needs
        ;; exactly that. C2 needs the same seam: without it, replacing the
        ;; unpublish with "delete this owner's whole bucket" passes every other
        ;; row in this file, because the tested writers own nothing else.
        ;;
        ;; The seam: uv-owner-entry-count, taking an owner and a kind, in the
        ;; style of $listener-reserve?. A red that means "you still owe this
        ;; row" -- not "something broke".
        (begin
          (check "C1 OWED: needs uv-owner-entry-count (owner kind) -- the writer's entry is a 'write-block entry, and it is the WRITER's" #f 'seam-missing)
          (check "C2 OWED: needs the same seam -- a second resource held by the writer survives the write" #f 'seam-missing))

        ;; ---- F1: the entry paths. Every row above drives ONE of the six call
        ;; sites. The design's claim that all six are synchronous in the caller
        ;; was established by READING, and a reading is not a cell.
        (let ((before (begin (count! 'write-before-copy) (hits 'write-before-copy))))
          (check "F1 premise: the counting arming is in place" (eqv? before 0) before)
          (tcp-writev! cli (list (make-bytevector 40000 1) (make-bytevector 40000 2)) (lambda (s) (void)))
          (sleep-ms 300)
          (check "F1 a vectored write above the scratch threshold reaches the block path"
                 (>= (hits 'write-before-copy) 1) (hits 'write-before-copy))
          (let ((n (hits 'write-before-copy)))
            (tcp-write! cli (make-bytevector small-size 1) (lambda (s) (void)))
            (sleep-ms 200)
            (check "F1 a write the scratch path completes in one try-write allocates no block"
                   (eqv? (hits 'write-before-copy) n) (hits 'write-before-copy) n)))
        (inject-disarm!)

        (tcp-close! cli)
        (when srv (tcp-close! srv))
        (tcp-stop-listen! l)
        (check "section: both block counts back and equal" (within? 5000 (lambda () (equal? (blocks) k0))) (blocks) k0))

      ;; ---- D1: the record belongs to the WRITER, not to the conn's owner ----
      ;; On the rejected design the conn owner's death frees a block a live
      ;; writer is about to use: a leak traded for a use-after-free. The sweep
      ;; must leave it alone, and the writer must release it ITSELF through the
      ;; in-region state rejection.
      ;;
      ;; NOT "the only row that catches conn-owner keying": cli above is owned by
      ;; main, which outlives the killed writers, so A1/B1/B2 catch it too. This
      ;; row is for the INVERSE hazard, which nothing else here reaches.
      (let* ((w0 (write-blocks-live-count)) (c0 (conn-count))
             (srv #f)
             (l (tcp-listen! "127.0.0.1" (+ port 1) 16 (lambda (c) (set! srv c))))
             (holder (spawn (lambda () (let loop () (receive (m (send main m) (loop)))))))
             (cli (begin (tcp-connect! "127.0.0.1" (+ port 1) holder)
                         (receive (after 3000 #f) (`#(tcp-connected ,c) c)))))
        (check "D1 premise: the conn is owned by a process that is not the writer"
               (and cli (within? 2000 (lambda () srv)) (not (eq? holder main))) cli)
        (count! 'write-block-released-plain-reject)
        (let* ((p (park-writer! cli 'write-before-region one-shot-write))
               (t (car p)) (pid (cadr p)) (st (caddr p)) (rv (cadddr p)))
          (check "D1 premise: the writer is parked holding one block"
                 (and pid (not (eq? pid holder)) (eqv? (write-blocks-live-count) (+ w0 1)))
                 pid (blocks) w0)
          (kill holder 'test-kill)
          ;; The witness is THIS conn closing, not a global count: c0 was taken
          ;; before both conns existed and the accepted one stays open, so
          ;; conn-count never returns to it. A first draft asserted that and
          ;; would have hung on a premise that can never become true.
          (check "D1 premise: the owner's death swept its conn, so the sweep has run"
                 (within? 5000 (lambda () (not (eq? (conn-state cli) 'open)))) (conn-state cli))
          (check "D1 the sweep left the live writer's block alone"
                 (eqv? (write-blocks-live-count) (+ w0 1)) (blocks) w0)
          (release-parked! t pid)
          (check "D1 the resumed writer is refused: #f returned, on-done -1, released once BY THE WRITER"
                 (within? 5000 (lambda () (and (eq? (vector-ref rv 0) #f)
                                               (eqv? (vector-ref st 0) -1)
                                               (eqv? (hits 'write-block-released-plain-reject) 1)
                                               (eqv? (write-blocks-live-count) w0))))
                 (vector-ref rv 0) (vector-ref st 0) (hits 'write-block-released-plain-reject) (blocks) w0))
        (inject-disarm!)
        (when srv (tcp-close! srv))
        (tcp-stop-listen! l))

      (check "G the two block counts agree and are back at the baseline"
             (within? 5000 (lambda () (equal? (blocks) k0))) (blocks) k0)
      (check "G ...and so is the handle/conn/index baseline"
             (within? 5000 (lambda () (equal? (base) b0))) (base) b0))
    (if (zero? fails)
        (begin (display "ALL WRITE-BLOCK-WINDOW TESTS PASSED\n") (exit 0))
        (begin (display "WRITE-BLOCK-WINDOW VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
