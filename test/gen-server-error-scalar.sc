#!chezscheme
;;; gen-server's error slot: PASSTHROUGH or LABEL, nothing else.
;;;
;;; The last slot of #(gen-server-error reason slot) is either the value
;;; itself -- when it already is a small self-contained scalar, so
;;; 'server-died 'normal and a registered name stay eq?-dispatchable --
;;; or a LABEL built from predicates and accessors that execute no user
;;; code and copy no unbounded body: "#(tag ...)" for a request vector,
;;; "#<number>", "#<typename>", "#<gensym nick>", a name clipped to the
;;; budget. The old slot held the caller's message itself; a message
;;; names its replier, so the slot could hold a live process, and
;;; `write' on the error walked a pcb into a cycle, took the runtime
;;; down and printed the mailbox on the way -- reading the error was
;;; the detonating act. Two intermediate designs died in review:
;;; bounded printing (print-level bounds the walk but not the atoms) and
;;; a rationed port (the atom is rendered before any port sees it).
;;; Hence: the label is CONSTRUCTED small, never cut down from big.

(import (chezscheme) (igropyr actor) (igropyr gen-server))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (ok label) (display "  ok  ") (display label) (newline))
(define (check label c . info) (if c (ok label) (apply fail label info)))

(define (catch thunk) (guard (e (#t e)) (thunk) 'no-raise))

(define (writable? e)
  (string? (call-with-string-output-port (lambda (p) (write e p)))))

(define (err? e reason)
  (and (vector? e) (= 3 (vector-length e))
       (eq? (vector-ref e 0) 'gen-server-error)
       (eq? (vector-ref e 1) reason)))
(define (slot e) (vector-ref e 2))

(define (contains? hay needle)
  (let ((n (string-length hay)) (m (string-length needle)))
    (let loop ((k 0))
      (cond ((> (+ k m) n) #f)
            ((string=? (substring hay k (+ k m)) needle) #t)
            (else (loop (+ k 1)))))))

;; four record types whose writers misbehave in the four reviewed ways.
;; THE CELLS ASSERT THE CALL COUNTS STAY ZERO: an output-size assertion
;; would pass under the old rendering mechanism too -- only a label
;; built without invoking the writer keeps these at zero. That is the
;; discriminating difference.
(define loud-calls (box 0))
(define raise-calls (box 0))
(define steal-calls (box 0))
(define stolen-port (box #f))
(define swallow-calls (box 0))

(define-record-type loud-rec (fields a))
(record-writer (record-type-descriptor loud-rec)
  (lambda (r p wr)
    (set-box! loud-calls (+ 1 (unbox loud-calls)))
    (put-string p (make-string 5000 #\z))))
(define-record-type raise-rec (fields a))
(record-writer (record-type-descriptor raise-rec)
  (lambda (r p wr)
    (set-box! raise-calls (+ 1 (unbox raise-calls)))
    (raise 'writer-bang)))
(define-record-type steal-rec (fields a))
(record-writer (record-type-descriptor steal-rec)
  (lambda (r p wr)
    (set-box! steal-calls (+ 1 (unbox steal-calls)))
    (set-box! stolen-port p)))
(define-record-type swallow-rec (fields a))
(record-writer (record-type-descriptor swallow-rec)
  (lambda (r p wr)
    (set-box! swallow-calls (+ 1 (unbox swallow-calls)))
    (guard (e (#t #f)) (raise 'swallowed))
    (put-string p (make-string 300 #\y))))

(start-scheduler
  (lambda ()
    (define me self)

    ;; park a call against a fresh victim, kill it with `reason`,
    ;; hand back the server-died error the caller received
    (define (server-died-with reason)
      (let ((victim (gen-server-start
                      (lambda () 'st)
                      (lambda (msg from state)
                        (receive (`#(never-sent) (values 'x state))))
                      (lambda (msg state) state))))
        (spawn (lambda ()
                 (send me (vector 'de
                                  (catch (lambda ()
                                           (gen-server-call victim 'q 5000)))))))
        (sleep-ms 120)
        (kill victim reason)
        (receive (after 3000 'no-error-arrived)
          (`#(de ,e) e))))

    ;; ---- site: timeout, request vector carrying a process ------------
    (let* ((slow (gen-server-start
                   (lambda () 'st)
                   (lambda (msg from state)
                     (receive (`#(never-sent) (values 'x state))))
                   (lambda (msg state) state)))
           (e (catch (lambda ()
                       (gen-server-call slow (vector 'do-thing self) 300)))))
      (check "timeout: three-slot tagged error" (err? e 'timeout))
      (check "timeout: a pid-carrying request becomes a LABEL"
             (and (err? e 'timeout) (string? (slot e))))
      (check "timeout: the label names the request's tag"
             (and (err? e 'timeout) (string? (slot e))
                  (contains? (slot e) "do-thing")))
      (check "timeout: writing the error survives"
             (writable? e)))

    ;; ---- site: calling-self, same label treatment --------------------
    (let ((e (catch (lambda ()
                      (gen-server-call self (vector 'loop-back self) 300)))))
      (check "calling-self: tagged error" (err? e 'calling-self))
      (check "calling-self: the message becomes a LABEL, same as timeout"
             (and (err? e 'calling-self) (string? (slot e))
                  (contains? (slot e) "loop-back")))
      (check "calling-self: writing the error survives" (writable? e)))

    ;; ---- site: server-died -------------------------------------------
    (let ((e (server-died-with 'stabbed)))
      (check "server-died: a symbol reason arrives AS the symbol"
             (and (err? e 'server-died) (eq? 'stabbed (slot e))))
      (check "server-died: writing it survives" (writable? e)))
    (let ((e (server-died-with (vector 'evicted self))))
      (check "server-died: a structured reason becomes a label naming its tag"
             (and (err? e 'server-died) (string? (slot e))
                  (contains? (slot e) "evicted")))
      (check "server-died: writing the structured case survives"
             (writable? e)))

    ;; ---- site: no-such-server, identity up to the budget -------------
    (let* ((name200 (string->symbol (make-string 200 #\n)))
           (e (catch (lambda () (gen-server-call name200 'ping 300)))))
      (check "no-such-server: a 200-char name keeps identity"
             (and (err? e 'no-such-server) (eq? name200 (slot e)))))
    (let* ((name201 (string->symbol (make-string 201 #\n)))
           (e (catch (lambda () (gen-server-call name201 'ping 300)))))
      (check "no-such-server: a 201-char name becomes a 200-char label"
             (and (err? e 'no-such-server) (string? (slot e))
                  (= 200 (string-length (slot e)))
                  (not (eq? name201 (slot e))))))

    ;; ---- passthrough identity: the eight kinds -----------------------
    (let ((cases (list (cons 42 "fixnum") (cons #t "boolean")
                       (cons '() "null") (cons #\x "char")
                       (cons (eof-object) "eof") (cons (void) "void")
                       (cons 'gently "short symbol")
                       (cons "why" "short string"))))
      (for-each
        (lambda (c)
          (let ((e (server-died-with (car c))))
            (check (string-append "passthrough keeps identity: " (cdr c))
                   (and (err? e 'server-died) (eqv? (car c) (slot e)))
                   (and (err? e 'server-died) (slot e)))))
        cases))

    ;; ---- gensym never passes through ---------------------------------
    ;; the nickname is short; the UNIQUE NAME is unbounded and appears
    ;; only when the caller writes the error -- the wrong quantity to
    ;; have measured, which is why this is its own cell
    (let* ((g (gensym "tiny"))
           (e (server-died-with g)))
      (check "gensym arrives as a label, never itself"
             (and (err? e 'server-died) (string? (slot e))
                  (not (eq? g (slot e)))))
      (check "...and writing the error stays bounded"
             (let ((s (call-with-string-output-port
                        (lambda (p) (write e p)))))
               (and (string? s) (< (string-length s) 400)))))

    ;; ---- mechanism: a huge atom is labeled, not expanded -------------
    (let ((e (server-died-with (expt 10 500000))))
      (check "a 500000-digit integer arrives as #<number>"
             (and (err? e 'server-died) (equal? "#<number>" (slot e)))))

    ;; ---- mechanism: the four misbehaving writers are never invoked ---
    (for-each
      (lambda (mk name calls)
        (let ((e (server-died-with (mk 1))))
          (check (string-append name " reason arrives as its type label")
                 (and (err? e 'server-died) (string? (slot e))
                      (contains? (slot e) name)))
          (check (string-append name "'s writer was never invoked")
                 (= 0 (unbox calls)) (unbox calls))))
      (list make-loud-rec make-raise-rec make-steal-rec make-swallow-rec)
      (list "loud-rec" "raise-rec" "steal-rec" "swallow-rec")
      (list loud-calls raise-calls steal-calls swallow-calls))
    (check "no port was ever handed out to steal" (not (unbox stolen-port)))

    ;; ---- mechanism: labeling cost does not scale with the name -------
    ;; the million-char symbol is interned BEFORE the baseline, so the
    ;; measured window holds only the raise and its label construction.
    ;; A build-then-clip implementation copies the megabyte and shows up
    ;; megabytes over; the threshold sits an order of magnitude under
    ;; that and an order over scheduler noise.
    (let ((big-msg (vector (string->symbol (make-string 1000000 #\m)) 'x)))
      (catch (lambda () (gen-server-call self big-msg 100)))   ; warm
      (let* ((before (bytes-allocated))
             (e (catch (lambda () (gen-server-call self big-msg 100))))
             (delta (- (bytes-allocated) before)))
        (check "the million-char tag still labels"
               (and (err? e 'calling-self) (string? (slot e))
                    (<= (string-length (slot e)) 200)))
        (check "...allocating kilobytes, not the megabyte"
               (< delta 500000) delta)))

    ;; ---- mechanism: a mutating message cannot break the error --------
    ;; the slot is read once into a local before classification; under
    ;; preemptive scheduling a concurrent flipper used to land between
    ;; the reads and turn the raise into symbol->string blowing up
    (let ((msg (vector 'tag 'x)) (bad 0))
      (spawn (lambda ()
               (do ((i 0 (+ i 1))) ((= i 200000))
                 (vector-set! msg 0 (if (even? i) 'tag 17)))))
      (do ((i 0 (+ i 1))) ((= i 3000))
        (let ((e (catch (lambda () (gen-server-call self msg 100)))))
          (unless (err? e 'calling-self) (set! bad (+ bad 1)))))
      (check "3000 calls against a flipping message: every raise is the error"
             (= bad 0) bad))

    (if (zero? failures)
        (begin (display "gen-server-error-scalar: all tests passed\n")
               (exit 0))
        (begin (display (number->string failures))
               (display " failures\n") (exit 1)))))
