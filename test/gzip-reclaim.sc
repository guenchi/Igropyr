;;; (igropyr gzip): native buffers survive the death of the process that
;;; allocated them, and are reclaimed anyway.
;;;
;;; A compression holds three foreign-alloc'd buffers -- the z_stream, the
;;; input copy and the output -- for the length of one deflate. A kill
;;; DISCARDS the victim's dynamic-wind after-thunks (see (igropyr actor)),
;;; so the winder that frees them does not run, and nothing on the C heap
;;; is reachable from Scheme afterwards to free it later. What closes that
;;; is a guardian: the record holding the three pointers is registered
;;; before any of them is allocated, and a later compression drains
;;; whatever the collector has handed back.
;;;
;;; This suite is separate from test/gzip.sc on purpose: that file is
;;; shared verbatim with the standalone gzip repository, which has no
;;; scheduler to kill anything in, and it must keep importing nothing but
;;; (chezscheme) and (igropyr gzip).
;;;
;;; HOW IT DISCRIMINATES, and the obvious way does not work. Killing a
;;; victim partway through a long deflate lands nothing: deflate is one
;;; foreign call, no other process can run while it is in progress, so
;;; the killer's timer does not come due until the victim has returned,
;;; finished and run its own winder. Measured: 200 rounds, 200 victims
;;; that completed by themselves. A suite built that way passes against a
;;; reclaim that does nothing at all.
;;;
;;; What decides the outcome is where the victim's SLICE ends, since the
;;; killer runs at exactly that point and nowhere else. So the victim
;;; sets its own remaining ticks with set-timer and the suite sweeps that
;;; number: somewhere in the sweep the slice ends between the allocations
;;; and the winder, which is the window. Each round that lands there
;;; strands the whole payload twice over.
;;;
;;; The measurement is the growth in resident memory across the sweep,
;;; not the absolute figure: freed native memory goes back to the
;;; allocator, which then satisfies the next round from it, so a working
;;; reclaim is flat no matter how many rounds run. A leak is not.
;;;
;;; Growth is the right observable rather than a counter inside the
;;; library, because a counter would report that free was CALLED. This
;;; reports that the memory came back.

(import (chezscheme) (igropyr actor) (igropyr gzip))

(define failures 0)
(define (fail label)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label) (newline))
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline)) (fail label)))

(define scratch
  (format "/tmp/igropyr-gzip-reclaim-~a-~a" (get-process-id) (real-time)))

;; Resident set size of this process, in KB, or #f if ps will not say.
;; ps is the only reading here that does not come from inside the process
;; being measured.
(define (rss-kb)
  (let ((f (string-append scratch ".rss")))
    (system (format "ps -o rss= -p ~a > ~a 2>/dev/null" (get-process-id) f))
    (and (file-exists? f)
         (let ((s (call-with-input-file f get-string-all)))
           (delete-file f)
           (let ((n (string->number (string-trim-both s))))
             (and (number? n) n))))))

(define (string-trim-both s)
  (let* ((n (string-length s))
         (a (let loop ((i 0))
              (cond ((>= i n) n)
                    ((char-whitespace? (string-ref s i)) (loop (+ i 1)))
                    (else i))))
         (b (let loop ((i n))
              (cond ((<= i a) a)
                    ((char-whitespace? (string-ref s (- i 1))) (loop (- i 1)))
                    (else i)))))
    (substring s a b)))

;; Incompressible: deflate must actually spend the time, and the output
;; buffer must actually be filled, or neither the window nor the leak is
;; the size this test assumes.
(define (urandom n)
  (let ((p (open-file-input-port "/dev/urandom")))
    (let ((bv (get-bytevector-n p n)))
      (close-port p)
      bv)))

(define MB (* 1024 1024))
(define payload-size (* 4 MB))
;; The slice lengths to try. The interesting ones are the few dozen ticks
;; it takes to get from the library's entry point to deflate; the sweep is
;; wider than that because the exact count is not a stable number to
;; write down, and rounds that miss the window cost only a compression.
(define sweep-to 200)
;; A round that lands in the window strands the input copy and the output
;; buffer, so a bit over 8MB each. Measured on this sweep: about 20 rounds
;; land there, and a broken reclaim grows by ~95MB while a working one
;; grows by single-digit MB once the heap has settled. 40MB sits between
;; those with room on both sides.
;;
;; The number was NOT chosen from the working figure alone. A threshold
;; picked that way passes whatever the code happens to do; this one was
;; set after watching a deliberately broken reclaim, which is the only
;; way to know the two are on opposite sides of it.
(define allowed-growth-kb (* 40 1024))
;; Rounds run before the first reading, so that it is not measuring the
;; heap's first growth rather than a leak.
(define warmup-rounds 20)

(start-scheduler
  (lambda ()
    (let ((probe (gzip-compress (make-bytevector 64 65) 6)))
      (cond
        ((not probe)
         ;; Not a pass. gzip-compress answers #f when this build has no
         ;; usable zlib -- on FreeBSD the runtime's embedded one, elsewhere
         ;; a shared object it could load. There is nothing here to reclaim
         ;; and nothing this suite can assert.
         (display "SKIPPED  (igropyr gzip) reports no usable zlib on this ")
         (display "build; nothing allocates, so there is nothing to reclaim\n")
         (exit 0))
        (else
          (let ((payload (urandom payload-size))
                (parent self)
                (killed-in-flight 0))
            ;; One round. The victim announces itself, sets its slice to k
            ;; ticks and starts compressing; announcing makes this process
            ;; runnable, so it is what the scheduler picks the moment the
            ;; victim's slice ends -- wherever that is. Then a collection
            ;; and one more compression, which is what drains whatever the
            ;; collector handed back.
            (define (round! k)
              (let ((v (spawn (lambda ()
                                (send parent (vector 'armed))
                                (set-timer k)
                                (gzip-compress payload 6)))))
                (receive (`#(armed) 'ok))
                (when (process-alive? v)
                  (kill v 'reclaim-test)
                  (set! killed-in-flight (+ killed-in-flight 1)))
                (collect (collect-maximum-generation))
                (gzip-compress (make-bytevector 64 66) 6)))

            (unless (and (bytevector? payload)
                         (= (bytevector-length payload) payload-size))
              (display "SKIPPED  /dev/urandom would not give ")
              (display payload-size)
              (display " bytes; cannot build an incompressible payload\n")
              (exit 0))

            (do ((k 1 (+ k 1))) ((> k warmup-rounds)) (round! k))
            (set! killed-in-flight 0)
            (let ((r1 (rss-kb)))
              (do ((k 1 (+ k 1))) ((> k sweep-to)) (round! k))
              (let ((r2 (rss-kb)))
                (cond
                  ((not (and r1 r2))
                   ;; Not a pass either: without ps there is no observable.
                   (display "SKIPPED  ps gave no resident-size reading; ")
                   (display "this suite has no other way to see the memory\n")
                   (exit 0))
                  (else
                    (printf "  before the sweep: ~a MB resident\n"
                            (quotient r1 1024))
                    (printf "  after ~a rounds:  ~a MB resident\n"
                            sweep-to (quotient r2 1024))
                    (printf "  growth over the sweep: ~a MB\n"
                            (quotient (- r2 r1) 1024))
                    (printf "  compressions killed in flight: ~a of ~a\n"
                            killed-in-flight sweep-to)
                    ;; Without this the suite would report a pass for a
                    ;; sweep in which every victim finished by itself --
                    ;; which is what the first version of it did.
                    (check "the sweep killed compressions in flight"
                           (> killed-in-flight 0))
                    (check "killed compressions do not strand native memory"
                           (< (- r2 r1) allowed-growth-kb))))))

            ;; The library must still work after all that: a reclaim that
            ;; freed something still in use would show up here.
            (let* ((again (gzip-compress payload 6)))
              (check "compression still works after the killed rounds"
                     (and again (> (bytevector-length again) 0))))))))

    (if (= failures 0)
        (begin (display "gzip-reclaim ok\n") (exit 0))
        (begin (printf "gzip-reclaim: ~a failure(s)\n" failures) (exit 1)))))
