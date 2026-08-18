#!chezscheme
;;; (igropyr durable): the ordering is the contract, and the trace is how
;;; it is judged.
;;;
;;; WHAT IS ASSERTED AND WHAT IS NOT. Media durability is not observable
;;; from inside a process: no test here claims data reached a platter.
;;; What the API promises -- and what CAN be judged -- is a call
;;; sequence (fsync of the temp file strictly before the rename, fsync
;;; of the parent directory strictly after it) and fail-closed error
;;; propagation. The judge counts CALLS through the trace hook, not
;;; mtimes or file contents alone: rewriting identical bytes fools any
;;; content check, and a skipped fsync leaves no mark anywhere else.
;;;
;;; A deliberately-broken implementation is the calibration: dropping
;;; the temp fsync, or swapping the rename and the directory fsync,
;;; must redden the sequence assertions here. The trace records
;;; attempts on the failure path too ('raised entries), because "tried
;;; and failed" and "never called" must not fold into one observation.

(import (chezscheme) (igropyr durable))

(define failures 0)
(define (fail label . info)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (apply fail label info)))

(define macos?
  (let* ((m (symbol->string (machine-type))) (n (string-length m)))
    (and (>= n 3) (string=? (substring m (- n 3) n) "osx"))))

(define root
  (format "/tmp/igropyr-durable-test-~a-~a" (get-process-id) (real-time)))
(system (string-append "rm -rf " root "; mkdir -p " root))

;; ---- trace collection ---------------------------------------------------
;; entries accumulate newest-first; helpers read them oldest-first
(define entries (box '()))
(define (collect! op path rc)
  (set-box! entries (cons (list op path rc) (unbox entries))))
(define (reset!) (set-box! entries '()))
(define (trace) (reverse (unbox entries)))

(define (ops) (map car (trace)))
(define (index-of op)
  (let loop ((l (ops)) (i 0))
    (cond ((null? l) #f)
          ((eq? (car l) op) i)
          (else (loop (cdr l) (+ i 1))))))
(define (last-index-of op)
  (let loop ((l (ops)) (i 0) (found #f))
    (cond ((null? l) found)
          ((eq? (car l) op) (loop (cdr l) (+ i 1) i))
          (else (loop (cdr l) (+ i 1) found)))))
(define (count-op op)
  (let loop ((l (ops)) (n 0))
    (cond ((null? l) n)
          ((eq? (car l) op) (loop (cdr l) (+ n 1)))
          (else (loop (cdr l) n)))))

(define (string-prefix? p s)
  (and (>= (string-length s) (string-length p))
       (string=? (substring s 0 (string-length p)) p)))
(define (string-has? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring s i (+ i m)) sub) #t)
            (else (loop (+ i 1)))))))

(fs-trace-hook-set! collect!)

;; ---- the ordering, judged on calls --------------------------------------
(let ((target (string-append root "/a.bin"))
      (payload (string->utf8 "first payload")))
  (reset!)
  (let ((r (durable-write-file! target payload)))
    (check "a write returns its path" (equal? r target) r))
  ;; G-190's two hard sequence assertions. The directory flush carries
  ;; its own op family (dir-open/dir-fsync/...), so the two flushes are
  ;; told apart structurally rather than by first/last position -- and a
  ;; caller can tell "failed before the rename" from "failed after it"
  ;; without parsing paths, which is the distinction this library is for.
  (let ((f1 (index-of 'fsync)) (rn (index-of 'rename)) (f2 (index-of 'dir-fsync))
        (cl (index-of 'close))
        (fsync-path (let ((e (assq 'fsync (map (lambda (e) (cons (car e) (cadr e)))
                                               (trace)))))
                      (and e (cdr e))))
        (dir-path (let ((e (assq 'dir-fsync (map (lambda (e) (cons (car e) (cadr e)))
                                                 (trace)))))
                    (and e (cdr e)))))
    (check "the temp file is fsynced before the rename"
           (and f1 rn (< f1 rn)) (trace))
    (check "...and closed before it"
           (and cl rn (< cl rn)) (trace))
    (check "the parent directory is fsynced after the rename"
           (and rn f2 (> f2 rn)) (trace))
    ;; the RIGHT files: an implementation flushing the target (not the
    ;; temp) or the temp's own path as "the directory" passes an
    ;; order-only judge
    (check "the file fsync names the temp"
           (and fsync-path (string-has? fsync-path "tmp")
                (not (equal? fsync-path target)))
           fsync-path)
    (check "the directory fsync names the parent"
           (equal? dir-path root) dir-path))
  (if macos?
      (check "F_FULLFSYNC is issued for the file and for the directory"
             (and (>= (count-op 'fullfsync) 1)
                  (>= (count-op 'dir-fullfsync) 1))
             (ops))
      (check "no fullfsync op appears where the platform has none"
             (and (= 0 (count-op 'fullfsync)) (= 0 (count-op 'dir-fullfsync)))
             (ops)))
  ;; the temp file the write went to belongs to the target -- judged
  ;; structurally (prefix + a tmp marker), not by exact name: the
  ;; uniqueness suffix is the implementation's business
  (let ((w (assq 'write (map (lambda (e) (cons (car e) (cadr e))) (trace)))))
    (check "the write went to a temp file beside its target"
           (and w (string-prefix? target (cdr w))
                (not (equal? target (cdr w)))
                ;; judged on the SUFFIX: every path in this suite lives
                ;; under /tmp, so a substring test is always true and
                ;; judges nothing
                (let* ((p (cdr w)) (n (string-length p)))
                  (and (> n 4) (string=? (substring p (- n 4) n) ".tmp"))))
           w))
  ;; two writes to one target take distinct temp names -- the counter
  ;; part of the uniqueness scheme, observable in one process. (Cross-
  ;; process collision resistance -- the pid part -- is not tested.)
  (let ((w1 (box #f)) (w2 (box #f))
        (twice (string-append root "/twice.bin")))
    (with-fs-trace (lambda (op path rc)
                     (when (eq? op 'write)
                       (if (unbox w1) (set-box! w2 path) (set-box! w1 path))))
      (lambda ()
        (durable-write-file! twice (string->utf8 "t1"))
        (durable-write-file! twice (string->utf8 "t2"))))
    (check "two writes to one target use distinct temp names"
           (and (unbox w1) (unbox w2)
                (not (equal? (unbox w1) (unbox w2))))
           (unbox w1) (unbox w2)))
  ;; content sanity, including replacement -- rename semantics, not
  ;; append: the second write must fully supersede the first
  (check "the bytes read back"
         (equal? payload
                 (call-with-port (open-file-input-port target)
                                 get-bytevector-all)))
  ;; the second payload is STRICTLY shorter (2 bytes vs 13): an
  ;; implementation that overwrites from offset zero without truncating
  ;; leaves a tail of the first payload behind, and equal? catches it --
  ;; the first version of this check used a LONGER second payload and
  ;; judged nothing of the kind
  (let ((second (string->utf8 "xy")))
    (durable-write-file! target second)
    (check "a rewrite fully replaces the previous content"
           (equal? second
                   (call-with-port (open-file-input-port target)
                                   get-bytevector-all)))))

;; ---- ensure: existence without a spurious mkdir -------------------------
(let ((dir (string-append root "/sub")))
  (reset!)
  (durable-dir-ensure! dir)
  (check "the first ensure creates" (= 1 (count-op 'mkdir)) (ops))
  ;; ...and makes the creation durable: the parent directory is flushed
  ;; after the mkdir. Deleting that flush alone kept this suite green
  ;; once -- the entry can vanish in a crash and no read-back notices.
  (check "the first ensure flushes the parent after the mkdir"
         (let ((mk (index-of 'mkdir)) (df (index-of 'dir-fsync)))
           (and mk df (> df mk)))
         (ops))
  (reset!)
  (durable-dir-ensure! dir)
  ;; zero calls AT ALL for an existing directory: the implementation
  ;; returns before any syscall (an earlier comment here claimed the
  ;; parent fsync repeats -- it does not, and the trace says so)
  (check "a second ensure never calls mkdir" (= 0 (count-op 'mkdir)) (ops)))

;; ---- failure is closed, and it leaves a mark ----------------------------
(let ((bad (string-append root "/no-such-dir/x.bin")))
  (reset!)
  (let ((r (guard (e (#t e))
             (durable-write-file! bad (string->utf8 "x")))))
    ;; environmental failure (missing directory) arrives through Chez's
    ;; port layer, and must still be the unified error -- a caller
    ;; writes one guard, not two
    (check "an environmental failure is the unified error"
           (durable-error? r) r)
    (check "...naming the step it failed at"
           (and (durable-error? r) (eq? (durable-error-op r) 'write))
           (and (durable-error? r) (durable-error-op r)))
    (check "...and the path it failed on"
           (and (durable-error? r)
                (string-prefix? bad (durable-error-path r)))
           (and (durable-error? r) (durable-error-path r)))
    ;; the attempt is on the record even though it raised: "tried and
    ;; failed" and "never called" must be different observations
    (let ((raised (filter (lambda (e) (eq? (caddr e) 'raised)) (trace))))
      (check "the failed attempt left a 'raised entry"
             (and (pair? raised) (eq? (car (car raised)) 'write))
             (trace)))
    ;; ...and NOTHING after it -- judged on the WHOLE trace, not on a
    ;; shortlist of ops: an earlier form counted only fsync and rename,
    ;; and a wrong implementation issuing dir-opens after the failure
    ;; would have passed
    (check "fail closed: the 'raised entry is the last entry"
           (let ((t (trace)))
             (and (pair? t)
                  (eq? (caddr (car (reverse t))) 'raised)))
           (trace))))

;; ---- Chez-layer failures are unified too --------------------------------
;; mkdir and rename are Chez operations; their failures arrive as Chez
;; I/O conditions, and the one guard a caller writes must still catch
;; them. The base implementation unified only the FFI return codes and
;; let these escape -- the gap was found by walking the error path, and
;; these two injections keep it closed.
(let ((occupied (string-append root "/occupied")))
  ;; a regular file where the directory should go: mkdir must fail
  (durable-write-file! occupied (string->utf8 "in the way"))
  (let ((r (guard (e (#t e)) (durable-dir-ensure! occupied))))
    (check "a Chez-layer mkdir failure is the unified error"
           (and (durable-error? r) (eq? (durable-error-op r) 'mkdir))
           r)))
(let ((as-dir (string-append root "/target-is-dir")))
  ;; a directory where the target file should go: the rename must fail,
  ;; unified -- and the temp file must SURVIVE, content intact. It is
  ;; the only fsynced copy of the caller's data at that point; deleting
  ;; it on this branch would destroy the one good copy while the target
  ;; still holds the old bytes.
  (system (string-append "mkdir -p " as-dir))
  (reset!)
  (let ((r (guard (e (#t e))
             (durable-write-file! as-dir (string->utf8 "doomed")))))
    (check "a Chez-layer rename failure is the unified error"
           (and (durable-error? r) (eq? (durable-error-op r) 'rename))
           r)
    (let ((w (assq 'write (map (lambda (e) (cons (car e) (cadr e)))
                               (trace)))))
      (check "the temp file survives a failed rename, bytes intact"
             (and w (file-exists? (cdr w))
                  (equal? (string->utf8 "doomed")
                          (call-with-port (open-file-input-port (cdr w))
                                          get-bytevector-all)))
             w))))

;; ---- a libc-layer open failure is unified and leaks nothing ------------
;; a directory with permissions stripped: the dir-open step inside the
;; parent flush fails at the libc layer (not in Chez's port layer, which
;; the missing-directory case above exercises). Only the open branch is
;; injectable this way; fsync/close failures on healthy fds have no
;; portable construction and stay recorded as an uncovered gap.
(let ((locked (string-append root "/locked")))
  (system (string-append "mkdir -p " locked))
  (let ((target (string-append locked "/f.bin")))
    (system (string-append "chmod 111 " locked))  ; searchable, unreadable
    (reset!)
    (let ((r (guard (e (#t e))
               (durable-write-file! target (string->utf8 "x")))))
      (system (string-append "chmod 755 " locked))
      ;; which step fails first differs by platform (the temp write may
      ;; already be refused); what must hold is the unified shape and a
      ;; 'raised record with nothing after it
      (check "a permission failure is the unified error" (durable-error? r) r)
      (check "...and its attempt is on the record, last"
             (let ((t (trace)))
               (and (pair? t) (eq? (caddr (car (reverse t))) 'raised)))
             (trace)))))

;; ---- the error predicate is exactly as wide as the interface ------------
;; arity is part of the interface: the sibling vector that grew from two
;; elements to three, name unchanged, silently unmatched every caller
;; that tested vector-length. This predicate must reject both directions.
(check "durable-error? rejects a two-element tagged vector"
       (not (durable-error? (vector 'durable-error 'write))))
(check "durable-error? rejects a four-element tagged vector"
       (not (durable-error? (vector 'durable-error 'write "/x" 17))))

;; ---- a trailing separator is refused, not normalized --------------------
;; normalizing would fsync the WRONG directory -- an error with no
;; observable signal in an API whose whole meaning is durability
(let ((probe (box '())))
  (fs-trace-hook-set! (lambda (op path rc)
                        (set-box! probe (cons op (unbox probe)))))
  (let ((r (guard (e (#t (cond ((durable-error? e) 'durable)
                               ((assertion-violation? e) 'refused)
                               (else 'other))))
             (durable-write-file! (string-append root "/dir/")
                                  (string->utf8 "x"))
             'accepted)))
    (check "a path ending in a separator is refused at the door"
           (eq? r 'refused) r)
    ;; refused AT the door: a precondition failure must not have touched
    ;; the filesystem on the way out
    (check "...before any filesystem call"
           (null? (unbox probe)) (unbox probe)))
  (fs-trace-hook-set! collect!))

;; ---- with-fs-trace restores, on both exits ------------------------------
(let ((outer (box '())) (inner (box '())))
  (fs-trace-hook-set! (lambda (op path rc)
                        (set-box! outer (cons op (unbox outer)))))
  (with-fs-trace (lambda (op path rc)
                   (set-box! inner (cons op (unbox inner))))
    (lambda ()
      (durable-write-file! (string-append root "/w.bin")
                          (string->utf8 "w"))))
  (check "inside with-fs-trace the inner hook sees the calls"
         (pair? (unbox inner)))
  (check "...and the outer hook was silent meanwhile"
         (null? (unbox outer)) (unbox outer))
  (let ((seen-before (length (unbox outer))))
    (durable-write-file! (string-append root "/w2.bin") (string->utf8 "w"))
    (check "after a normal exit the outer hook is back"
           (> (length (unbox outer)) seen-before)))
  ;; the raising exit restores too -- the reason with-fs-trace exists:
  ;; a bare set! discipline leaks the hook of the first failing test
  ;; into every later one, and the symptom shows up far from the fault
  (set-box! inner '())
  (guard (e (#t 'expected))
    (with-fs-trace (lambda (op path rc)
                     (set-box! inner (cons op (unbox inner))))
      (lambda ()
        (durable-write-file! (string-append root "/no-such-dir/y.bin")
                            (string->utf8 "y")))))
  (let ((seen-before (length (unbox outer))))
    (durable-write-file! (string-append root "/w3.bin") (string->utf8 "w"))
    (check "after a raising exit the outer hook is back"
           (> (length (unbox outer)) seen-before))))

;; ---- a hook that raises is swallowed and masks nothing ------------------
(fs-trace-hook-set! (lambda (op path rc) (raise 'hook-broke)))
(let ((target (string-append root "/h.bin")))
  (let ((r (guard (e (#t (cons 'raised e)))
             (durable-write-file! target (string->utf8 "h")))))
    (check "a raising hook does not fail the write" (equal? r target) r))
  (let ((r (guard (e (#t e))
             (durable-write-file! (string-append root "/no-such-dir/z.bin")
                                 (string->utf8 "z")))))
    ;; the caller's error arrives, not the hook's: a diagnostic must
    ;; not replace what it is diagnosing
    (check "a raising hook does not mask the real failure"
           (and (durable-error? r) (eq? (durable-error-op r) 'write)) r)))
(fs-trace-hook-set! #f)

(system (string-append "rm -rf " root))
(if (= failures 0)
    (begin (display "durable: all tests passed\n") (exit 0))
    (begin (display (number->string failures))
           (display " failures\n")
           (exit 1)))
