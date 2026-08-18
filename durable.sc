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
;;;   write body -> fsync body -> close -> rename -> fsync PARENT DIR
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

  ;; MEASURED, not remembered. Compiled against <fcntl.h> on macOS 15
  ;; (arm64): O_RDONLY = 0, F_FULLFSYNC = 51. O_RDONLY is 0 on the other
  ;; supported targets as well, but the value below has only been
  ;; compiled out of the header on macOS -- if this library is ever
  ;; taken somewhere new, compile it there rather than assuming.
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

  ;; THE HOOK IS ONE GLOBAL, SET ONCE, and deliberately not a parameter.
  ;; A parameter would offer `parameterize`, which reads as "just for
  ;; this extent" and is not: green processes here share one dynamic
  ;; environment, so one process's binding is visible to every other and
  ;; two concurrent users of it interleave. Rather than document against
  ;; a form the API invites, the form is not offered.
  (define fs-trace-hook (box #f))

  (define (fs-trace-hook-set! h)
    (unless (or (not h) (procedure? h))
      (assertion-violation 'fs-trace-hook-set!
        "hook must be a procedure of three arguments, or #f" h))
    (set-box! fs-trace-hook h))

  ;; AND ITS COUNTERPART, so that a caller who installs one has a way to
  ;; take it back that survives an exception. Without this every user
  ;; writes their own dynamic-wind, and the ones who forget leave a hook
  ;; installed for whatever runs next -- which shows up as trouble far
  ;; away from the code that caused it.
  ;;
  ;; IT IS NOT ISOLATION. What it restores is the same single box, so
  ;; two green processes using it at once still overwrite each other;
  ;; what it buys is that an exception does not strand a hook, not that
  ;; concurrent users stop colliding.
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
           (fd (traced op-open path (lambda () (c-open path O_RDONLY 0)))))
      (when (< fd 0) (fail! op-open path))
      (let ((close-quietly!
              (lambda ()
                (guard (e (#t (void)))
                  (traced op-close path (lambda () (c-close fd)))))))
        (let ((rc (traced op-fsync path (lambda () (c-fsync fd)))))
          (when (< rc 0) (close-quietly!) (fail! op-fsync path)))
        (when macos?
          (let ((rc (traced op-fullfsync path
                      (lambda () (c-fcntl fd F_FULLFSYNC 0)))))
            (when (< rc 0) (close-quietly!) (fail! op-fullfsync path))))
        (let ((rc (traced op-close path (lambda () (c-close fd)))))
          (when (< rc 0) (fail! op-close path))))))

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

  (define (durable-write-file! path bytes)
    (unless (string? path)
      (assertion-violation 'durable-write-file! "path must be a string" path))
    (unless (bytevector? bytes)
      (assertion-violation 'durable-write-file!
        "contents must be a bytevector" bytes))
    (let* ((dir (parent-of 'durable-write-file! path))
           (tmp (temp-name-for path)))
      ;; CLEAN UP AFTER A FAILED WRITE WITHOUT HIDING IT. The port is
      ;; closed and the temporary file removed on the way out, both
      ;; best-effort: either can fail on its own, and neither is allowed
      ;; to become the error the caller sees. A leaked descriptor and a
      ;; stray temporary are worth less than the reason the write failed.
      (traced 'write tmp
        (lambda ()
          (let ((p #f))
            (guard (e (#t (when p (guard (e2 (#t (void))) (close-port p)))
                          (guard (e2 (#t (void))) (delete-file tmp))
                          (fail! 'write tmp)))
              (set! p (open-file-output-port tmp (file-options no-fail)))
              (put-bytevector p bytes)
              (flush-output-port p)
              (close-port p)
              (set! p #f)
              0))))
      (fsync-path! 'file tmp)
      ;; THE TEMPORARY IS LEFT ALONE IF THE RENAME FAILS, unlike after a
      ;; failed write. By this point its contents are complete and
      ;; flushed, so deleting it would destroy the one copy of data the
      ;; caller handed over, while the target still holds whatever it
      ;; held before. A stray file an operator can find beats bytes
      ;; nobody can.
      (traced 'rename path
        (lambda ()
          (as-durable 'rename path (lambda () (rename-file tmp path) 0))))
      ;; THE STEP THAT GETS LEFT OUT. Without it the rename is in the
      ;; kernel's memory and not in the directory on the medium, and a
      ;; crash here can leave neither the old file nor the new one.
      (fsync-path! 'dir dir)
      path))

  (define (durable-dir-ensure! path)
    (unless (string? path)
      (assertion-violation 'durable-dir-ensure! "path must be a string" path))
    (let ((parent (parent-of 'durable-dir-ensure! path)))
      ;; THE SECOND CALL DOES NO WRITING. Creating what is already there
      ;; would be a needless directory write on every startup; the
      ;; parent is flushed only when something was actually created,
      ;; since flushing a directory that did not change buys nothing.
      (cond ((file-directory? path) path)
            (else
             (traced 'mkdir path
               (lambda ()
                 (as-durable 'mkdir path (lambda () (mkdir path) 0))))
             (fsync-path! 'dir parent)
             path)))))
