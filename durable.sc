#!chezscheme
;;; (igropyr durable) -- writing a file so that a crash cannot leave a
;;; reader looking at half of it, and so that what was written is still
;;; there after the machine loses power.
;;;
;;; THE ORDER IS THE WHOLE OF IT. Writing to a temporary file and
;;; renaming is the well known half; the half that gets left out is that
;;; a rename is a change to a DIRECTORY, and a directory is a file that
;;; also has to be flushed. Leave the last step out and the sequence
;;; still passes every test that writes and reads back, on every machine
;;; that does not lose power during the test.
;;;
;;;   write body -> close it -> fsync body -> rename -> fsync PARENT DIR
;;;
;;; The body is flushed through a descriptor opened for that purpose,
;;; AFTER the writing port has been closed, because a Chez port does not
;;; hand out its file descriptor. fsync takes a descriptor for the file
;;; and not a writable channel to it, so this is sound -- but it means
;;; the path is resolved a second time, and an earlier version of this
;;; note claimed the flush came before the close, which was never what
;;; the code did.
;;;
;;; WHAT CANNOT BE CHECKED FROM IN HERE is whether any of it reached the
;;; medium. fsync returning zero says the kernel believes it handed the
;;; data to the device; a device with a volatile write cache can say so
;;; and lose it. On macOS F_FULLFSYNC asks for more than fsync does,
;;; which is why it is issued there. Nothing in this process can observe
;;; the difference, so the tests around this library assert the CALL
;;; SEQUENCE and the error behaviour, and claim nothing about durability
;;; itself. A test that claimed otherwise would be measuring its own
;;; expectations.
;;;
;;; IT BLOCKS THE WHOLE RUNTIME. Every call here is a synchronous
;;; syscall, and green processes share one OS thread, so a fsync stops
;;; every process in this runtime for as long as it takes -- not just
;;; the caller. That is bounded by the STORAGE and not by anything here:
;;; on a local disk it is milliseconds, on a network or fuse filesystem
;;; it can be seconds or longer, and an operation that eventually
;;; returns an error can take just as long to do it. So "call this
;;; rarely" is not the same as "this is cheap": the right places are
;;; startup, configuration changes, and the handful of writes whose loss
;;; would matter. A hot path needs the file I/O moved off this thread
;;; entirely, which this library does not do.
(library (igropyr durable)
  (export durable-write-file! durable-dir-ensure!
          fs-trace-hook-set! with-fs-trace
          durable-error? durable-error-op durable-error-path)
  (import (chezscheme) (igropyr platform))

  ;; REFUSED BEFORE ANYTHING ELSE IS TRIED, which is why it is a
  ;; definition and not a call at the foot of the body: definition
  ;; initialisers run in order, so this settles the platform before the
  ;; loader below goes looking for a libc on it.
  ;;
  ;; TWO DEFENCES, COVERING DIFFERENT HOLES -- and neither stands in for
  ;; the other. This one refuses a platform the framework does not
  ;; recognise at all, where machine-type is simply unfamiliar and
  ;; nothing has been verified. It says nothing about whether the
  ;; constants below were compiled on a platform that DOES get through:
  ;; the supported set is macOS, Linux and FreeBSD, and the table below
  ;; covers two of them. On Linux this check passes and O_RDONLY is
  ;; still a number nobody compiled there.
  ;;
  ;; So this answers "is the platform known", the table answers "were
  ;; these numbers measured here", and taking the first as covering the
  ;; second has the gap backwards.
  (define platform-checked (begin (ensure-supported-platform!) #t))

  ;; libc, through the loader that already reports every candidate it
  ;; tried. A second copy of that loop is how the last library to need
  ;; one ended up with a candidate list that drifted from this one.
  (define libc
    (load-first-shared-object!
      'igropyr-durable
      '("libc.dylib" "libc.so.7" "libc.so.6" "libc.so")))

  (define c-open  (foreign-procedure "open"  (string int int) int))
  (define c-close (foreign-procedure "close" (int) int))
  (define c-fsync (foreign-procedure "fsync" (int) int))
  (define c-fcntl (foreign-procedure "fcntl" (int int int) int))

  ;; MEASURED, not remembered -- compiled against <fcntl.h> on each
  ;; platform rather than taken from memory or from a table on the web:
  ;;
  ;;   macOS 15 (arm64)   O_RDONLY = 0, F_FULLFSYNC = 51
  ;;   FreeBSD 15.0       O_RDONLY = 0
  ;;
  ;; A third platform means compiling it there too. The values are
  ;; stable across the Unixes in practice, which is exactly what makes
  ;; assuming them tempting and what would make a wrong one hard to
  ;; notice: an O_RDONLY that is not 0 opens something, just not what
  ;; was meant.
  ;;
  ;; F_FULLFSYNC IS macOS ONLY and is never issued anywhere else: it is
  ;; not that other platforms define it differently, it is that they do
  ;; not define it at all.
  (define O_RDONLY 0)
  (define F_FULLFSYNC 51)
  (define macos? (eq? platform-os 'macos))

  ;; A DIRECTORY IS OPENED READ ONLY, and that is not a stylistic
  ;; preference: opening one for writing fails with EISDIR. fsync on a
  ;; read-only descriptor still flushes the file it refers to -- fsync
  ;; takes a descriptor for the file, not a writable channel to it.

  ;; ERRORS COME IN TWO KINDS, and they are raised differently on
  ;; purpose. A path that cannot be a file path, or a libc that will not
  ;; load, is a mistake in the calling program: assertion-violation, the
  ;; same as everywhere else in this framework's startup checks. A write
  ;; or a fsync that fails is the world refusing, which the caller may
  ;; well want to handle: a tagged vector, the shape every other library
  ;; here raises.
  ;;
  ;; THE ARITY AND FIELD ORDER ARE PART OF THE INTERFACE. Three fields,
  ;; tag first. A sibling of this vector once grew from two fields to
  ;; three without changing its name, and callers matching on
  ;; vector-length failed silently against the new one -- so the
  ;; predicate below checks the length, and adding a field here is a
  ;; breaking change to be announced, not a compatible addition.
  (define (durable-err op path) (vector 'durable-error op path))

  (define (durable-error? r)
    (and (vector? r)
         (= 3 (vector-length r))
         (eq? (vector-ref r 0) 'durable-error)))

  ;; `op` SAYS WHICH STEP GAVE UP, and exists because the steps mean
  ;; different things to a caller. A failure at 'write leaves the target
  ;; untouched and its old contents intact, which is safe to retry; a
  ;; failure flushing the parent directory happens AFTER the rename, so
  ;; the new contents may already be visible and merely not yet durable.
  ;; Those want different handling, and collapsing them would take away
  ;; the distinction this library exists to provide.
  ;;
  ;; WHICH IS WHY THE DIRECTORY FLUSH HAS ITS OWN SYMBOLS. Flushing the
  ;; temporary file reports 'open / 'fsync / 'fullfsync / 'close;
  ;; flushing the parent directory after the rename reports 'dir-open /
  ;; 'dir-fsync / 'dir-fullfsync / 'dir-close. They are the same code
  ;; and once reported the same way, which left the before-rename and
  ;; after-rename cases -- the two the caller most needs apart --
  ;; separable only by comparing the path string. That is structured
  ;; information downgraded to text, in the one distinction this
  ;; library exists to draw.
  ;;
  ;; It is for dispatch, NOT a verdict on durability -- nothing here can
  ;; give one -- and the set is not closed: a step added later brings a
  ;; symbol with it, so match with a fallback rather than exhaustively.
  (define (durable-error-op r) (vector-ref r 1))
  (define (durable-error-path r) (vector-ref r 2))

  (define (fail! op path) (raise (durable-err op path)))

  ;; ONE FAILURE SHAPE, INCLUDING FROM THE STEPS THAT DO NOT GO THROUGH
  ;; libc. Creating the file, renaming it and making a directory are
  ;; Chez operations, and they report by raising a Chez I/O condition --
  ;; a second error shape, and the one a caller is likeliest to leave
  ;; unhandled, because it is reached by exactly the environmental
  ;; failures that most need to stop the write: a full disk, a directory
  ;; that is not there, permissions. Converted here so that one guard
  ;; catches everything this library raises.
  ;;
  ;; A durable-error passes through unchanged: wrapping one again would
  ;; relabel it with the outer step and lose which step actually failed.
  (define (as-durable op path thunk)
    (guard (e ((durable-error? e) (raise e))
              (#t (fail! op path)))
      (thunk)))

  ;; EVERY step goes through it, the libc ones included. Those report
  ;; failure by returning a negative number, which is handled separately
  ;; below -- but the CALL can still raise on its own (a foreign entry
  ;; that will not resolve, an interrupt arriving in the middle), and one
  ;; guard catching everything is what this library sells. A step left
  ;; outside would be a third exception shape reaching a caller who was
  ;; told there were two.
  (define (step op path thunk)
    (traced op path (lambda () (as-durable op path thunk))))

  ;; A PATH THE OS CANNOT BE GIVEN is a mistake in the caller, and has to
  ;; be refused as one. An embedded NUL is the case that gets here: the
  ;; string is a perfectly good Scheme string, passes every check above,
  ;; and names nothing -- so without this it came back as a durable-error,
  ;; reported as though the filesystem had refused something.
  (define (check-path! who path)
    (unless (string? path)
      (assertion-violation who "path must be a string" path))
    (when (= 0 (string-length path))
      (assertion-violation who "path must not be empty" path))
    (let loop ((i 0))
      (cond ((= i (string-length path)) path)
            ((char=? (string-ref path i) (integer->char 0))
             (assertion-violation who
               "path must not contain a NUL character" path))
            (else (loop (+ i 1))))))

  ;; THE HOOK IS ONE GLOBAL, SET ONCE, and deliberately not a parameter.
  ;; A parameter would offer `parameterize`, which reads as "just for
  ;; this extent" and is not: green processes here share one dynamic
  ;; environment, so one process's binding is visible to every other and
  ;; two concurrent users of it interleave. Rather than document against
  ;; a form the API invites, the form is not offered.
  (define fs-trace-hook (box #f))

  ;; THE ARITY IS CHECKED, not just the type. A hook that takes the wrong
  ;; number of arguments raises on every call, and those raises are
  ;; dropped by the guard around hook calls -- so the operations happen
  ;; and NOTHING is recorded, which is the one failure a tracing facility
  ;; must not have. Rejecting it here turns a silent absence of records
  ;; into a refusal at the point of installation.
  (define (fs-trace-hook-set! h)
    (unless (or (not h)
                (and (procedure? h)
                     (logbit? 3 (procedure-arity-mask h))))
      (assertion-violation 'fs-trace-hook-set!
        "hook must be a procedure accepting three arguments, or #f" h))
    (set-box! fs-trace-hook h))

  ;; AND ITS COUNTERPART, so that a caller who installs one has a way to
  ;; take it back that survives an exception. Without this every user
  ;; writes their own dynamic-wind, and the ones who forget leave a hook
  ;; installed for whatever runs next -- which shows up as trouble far
  ;; away from the code that caused it.
  ;;
  ;; IT IS NOT ISOLATION, AND IT ASSUMES LIFO. What it restores is the
  ;; same single box, so two green processes using it at once still
  ;; overwrite each other -- and if their extents interleave rather than
  ;; nest, the later one to exit restores what it saved, which is the
  ;; other's hook and not the original. What it buys is that a raise
  ;; inside one properly nested extent does not strand a hook; it does
  ;; not make concurrent users independent, and it does not survive them
  ;; overlapping.
  (define (with-fs-trace h thunk)
    (let ((saved (unbox fs-trace-hook)))
      (dynamic-wind
        (lambda () (fs-trace-hook-set! h))
        thunk
        (lambda () (set-box! fs-trace-hook saved)))))

  ;; A HOOK MUST NOT TURN A FAILURE INTO TWO. It runs on the failure
  ;; path as well as the success path, it comes from the caller, and a
  ;; caller's procedure can raise -- so a raise from it here would
  ;; replace the error being reported with one from the reporting. Every
  ;; call is guarded and anything it raises is dropped.
  ;;
  ;; A hook that BLOCKS is a different matter and is not defended
  ;; against: it runs on the one OS thread, so a hook that waits stops
  ;; the runtime, and no wrapper here can make that safe. Callers get
  ;; told; that is all this can do.
  (define (call-hook op path outcome)
    (let ((h (unbox fs-trace-hook)))
      (when h
        (guard (e (#t (void)))
          (h op path outcome)))))

  ;; RECORD THE ATTEMPT BEFORE LETTING THE EXCEPTION GO, so that "tried
  ;; and failed" and "never got there" are different in the trace. They
  ;; look identical otherwise, and telling them apart afterwards is what
  ;; the trace is for.
  ;;
  ;; 'raised MARKS A RAISE, NOT EVERY FAILURE. A libc call that fails
  ;; returns a negative number rather than raising, so the hook sees that
  ;; number as the outcome and the step that follows turns it into a
  ;; durable-error. Both are visible in a trace, but they are visibly
  ;; different, and a reader looking only for 'raised will miss every
  ;; syscall failure in this library.
  (define (traced op path thunk)
    (let ((r (guard (e (#t (call-hook op path 'raised) (raise e)))
               (thunk))))
      (call-hook op path r)
      r))

  ;; THE PARENT OF A FILE PATH. A path ending in a separator is refused
  ;; rather than normalised: it is not a file path, and the tempting
  ;; reading -- treat "a/b/" as "a/b" -- would make the directory step
  ;; flush the wrong directory, which nothing observable would report.
  ;; A wrong target with no signal is the worst outcome available in a
  ;; library whose entire purpose is durability, so this refuses early.
  (define (parent-of who path)
    (let ((n (string-length path)))
      (when (= n 0)
        (assertion-violation who "path must not be empty" path))
      (when (char=? (string-ref path (- n 1)) #\/)
        (assertion-violation who
          "path must name a file, not end in a separator" path))
      (let loop ((i (- n 1)))
        (cond ((< i 0) ".")
              ((char=? (string-ref path i) #\/)
               (if (= i 0) "/" (substring path 0 i)))
              (else (loop (- i 1)))))))

  ;; fsync THE FILE THIS PATH NAMES. Opened read-only for the reason
  ;; above; closed on every exit, including the failing ones, and a
  ;; close that fails while cleaning up after an earlier failure does
  ;; not replace it -- the first failure is the one worth reporting.
  ;; `kind` PICKS THE op NAMES AND NOTHING ELSE -- the syscalls are the
  ;; same either way. It is a parameter rather than two copies of this
  ;; procedure because the sequence is the part worth having in one
  ;; place; the symbols are spelled out in both branches rather than
  ;; assembled from a prefix, so that grepping for 'dir-fsync finds
  ;; this.
  (define (fsync-path! kind path)
    (let* ((dir? (eq? kind 'dir))
           (op-open      (if dir? 'dir-open 'open))
           (op-fsync     (if dir? 'dir-fsync 'fsync))
           (op-fullfsync (if dir? 'dir-fullfsync 'fullfsync))
           (op-close     (if dir? 'dir-close 'close))
           (fd (step op-open path (lambda () (c-open path O_RDONLY 0)))))
      (when (< fd 0) (fail! op-open path))
      ;; THE DESCRIPTOR IS RELEASED BY A WIND, not by a close at each
      ;; exit. Every failing branch used to call one, which covered the
      ;; failures this code knows about and nothing else: a trace hook
      ;; that escapes through a continuation, or any other non-local
      ;; exit, would leave the descriptor open with no path left to
      ;; close it. Resource safety should not depend on having listed
      ;; the ways out.
      (let ((closed (box #f)))
        (dynamic-wind
          (lambda () (void))
          (lambda ()
            (let ((rc (step op-fsync path (lambda () (c-fsync fd)))))
              (when (< rc 0) (fail! op-fsync path)))
            (when macos?
              (let ((rc (step op-fullfsync path
                          (lambda () (c-fcntl fd F_FULLFSYNC 0)))))
                (when (< rc 0) (fail! op-fullfsync path))))
            (let ((rc (step op-close path (lambda () (c-close fd)))))
              (set-box! closed #t)
              (when (< rc 0) (fail! op-close path))))
          (lambda ()
            (unless (unbox closed)
              (set-box! closed #t)
              (guard (e (#t (void)))
                (step op-close path (lambda () (c-close fd))))))))))

  ;; A TEMPORARY NAME NOBODY ELSE IS USING. Two processes writing the
  ;; same target at once would otherwise share one temporary file and
  ;; interleave into it, and the loser's bytes would be the ones that
  ;; got renamed into place. The process id separates processes and the
  ;; counter separates writes within one.
  (define temp-counter (box 0))

  (define (temp-name-for path)
    (let ((n (unbox temp-counter)))
      (set-box! temp-counter (+ n 1))
      (string-append path "." (number->string (get-process-id))
                     "." (number->string n) ".tmp")))

  ;; CREATED EXCLUSIVELY, so that finding the name taken is a refusal
  ;; rather than a silent overwrite. The name alone is not unique enough
  ;; to rely on: a process id is reused after the process is gone and the
  ;; counter restarts at zero in the new one, so a temporary left behind
  ;; on purpose -- the one a failed rename keeps, holding the only copy
  ;; of somebody's data -- can be named again by a later run. Opening
  ;; that with a truncating mode would destroy exactly the file the
  ;; failure path went out of its way to preserve.
  ;;
  ;; Exclusive creation also refuses a path that already exists as a
  ;; symlink, which is what would otherwise let anything with write
  ;; access to the directory redirect this write onto a file of its
  ;; choosing. Measured: exclusive creates a new file, refuses an
  ;; existing one leaving its bytes intact, and refuses a symlink.
  ;;
  ;; A taken name is retried under the next number. Anything else is the
  ;; write failing, and is reported as one rather than retried a
  ;; thousand times -- a directory that is not there would otherwise
  ;; look exactly like contention.
  (define (open-temp! path)
    (let loop ((tries 0))
      (let* ((tmp (temp-name-for path))
             (port (guard (e (#t #f))
                     (open-file-output-port tmp (file-options exclusive)))))
        (cond (port (values tmp port))
              ((and (file-exists? tmp) (< tries 1024)) (loop (+ tries 1)))
              (else (step 'write tmp (lambda () (fail! 'write tmp))))))))

  (define (durable-write-file! path bytes)
    (check-path! 'durable-write-file! path)
    (unless (bytevector? bytes)
      (assertion-violation 'durable-write-file!
        "contents must be a bytevector" bytes))
    (let*-values (((dir) (parent-of 'durable-write-file! path))
                  ((tmp port) (open-temp! path)))
      ;; CLEAN UP AFTER A FAILED WRITE WITHOUT HIDING IT. The port is
      ;; closed and the temporary file removed on the way out, both
      ;; best-effort: either can fail on its own, and neither is allowed
      ;; to become the error the caller sees. A leaked descriptor and a
      ;; stray temporary are worth less than the reason the write failed.
      (traced 'write tmp
        (lambda ()
          (guard (e (#t (guard (e2 (#t (void))) (close-port port))
                        (guard (e2 (#t (void))) (delete-file tmp))
                        (fail! 'write tmp)))
            (put-bytevector port bytes)
            (flush-output-port port)
            (close-port port)
            0)))
      (fsync-path! 'file tmp)
      ;; THE TEMPORARY IS LEFT ALONE FROM HERE ON, unlike after a failed
      ;; write -- by the flush steps as well as by a failed rename. Its
      ;; contents are complete once the write returns, so deleting it
      ;; would destroy the one copy of data the caller handed over, while
      ;; the target still holds whatever it held before. A stray file an
      ;; operator can find beats bytes nobody can. That the flush steps
      ;; leave it too was previously true but unsaid, which left a reader
      ;; to guess from two stated cases what the ones between them did.
      (step 'rename path (lambda () (rename-file tmp path) 0))
      ;; THE STEP THAT GETS LEFT OUT. Without it the rename is in the
      ;; kernel's memory and not in the directory on the medium, and a
      ;; crash here can leave neither the old file nor the new one.
      (fsync-path! 'dir dir)
      path))

  (define (durable-dir-ensure! path)
    (check-path! 'durable-dir-ensure! path)
    (let ((parent (parent-of 'durable-dir-ensure! path)))
      ;; THE SECOND CALL DOES NO WRITING. Creating what is already there
      ;; would be a directory write and a flush on every startup, and on
      ;; slow storage that is not free.
      ;;
      ;; WHAT IT PROMISES IS ITS OWN CREATION, NOT ANYBODY ELSE'S. If
      ;; another process made this directory a moment ago and has not
      ;; flushed the parent, this call finds it present and returns
      ;; without flushing anything -- so a crash can still take it away.
      ;; That is deliberate: `ensure` answers a question about existence,
      ;; and underwriting an unflushed creation by someone else would
      ;; turn every idempotent check into disk I/O for a case that is a
      ;; disagreement between the two callers rather than a fault here.
      ;;
      ;; A LOSING RACE IS NOT A FAILURE. Two processes can both find the
      ;; directory missing and both call mkdir; one gets EEXIST. The
      ;; postcondition it was asked for holds anyway, so it looks again
      ;; rather than reporting an error for a directory that is now
      ;; there. It does not flush in that branch either, for the reason
      ;; just above: the creation was the other process's.
      (cond ((file-directory? path) path)
            (else
             (guard (e ((and (durable-error? e)
                             (file-directory? path))
                        path))
               (step 'mkdir path (lambda () (mkdir path) 0))
               (fsync-path! 'dir parent)
               path))))))
