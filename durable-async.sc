#!chezscheme
;;; DURABLE WRITES WITHOUT STOPPING THE WORLD.
;;;
;;; (igropyr durable) writes a file crash-safely with synchronous
;;; syscalls, which on one OS thread means every green process waits out
;;; every fsync. This library reaches the same end state on libuv's
;;; thread pool: the calling process parks between steps and the
;;; scheduler keeps running, so the physical cost of an fsync does not go
;;; away -- it is charged to the caller instead of to the whole node.
;;;
;;; THE SAME END STATE, NOT THE SAME STEPS. The synchronous library
;;; writes through a port, closes it, and REOPENS the path to flush it,
;;; because a Chez port does not hand out its descriptor. This one holds
;;; the descriptor it created and flushes that, so its sequence is
;;; open-write-fsync-close where the other's is write-open-fsync-close.
;;; Two consequences, both in this library's favour and neither promised
;;; away: there is no close-and-reopen window for another process to
;;; substitute the path in, and there is no separate reopen step to fail
;;; -- so the synchronous library's 'open failure after a successful
;;; write has no counterpart here. What IS promised to match is the error
;;; vocabulary and the outcome, not the order of the trace.
;;;
;;; WHICH ONE TO IMPORT. They are separate libraries and can be imported
;;; together; the exported names differ by suffix, so nothing collides.
;;; The synchronous one has no scheduler dependency at all and is the one
;;; to use before start-scheduler, in a tool, or from a script. This one
;;; requires a running scheduler because parking is how it yields.
;;;
;;; PLATFORM DURABILITY IS NOT UNIFORM, and this is a selection
;;; criterion rather than a footnote:
;;;
;;;   Linux, FreeBSD   identical guarantees to the synchronous library.
;;;                    fsync is the whole story there, and the extra
;;;                    step the synchronous one takes exists only on
;;;                    Darwin.
;;;   macOS            this library reaches fsync level: the kernel has
;;;                    handed the data to the device. The synchronous
;;;                    library additionally issues F_FULLFSYNC, which
;;;                    forces the device itself to flush. A caller that
;;;                    needs that on macOS must use the synchronous
;;;                    library there and pay the stop-the-world.
;;;
;;; WHY NOT BOTH. libuv binds no fcntl, and F_FULLFSYNC is a fcntl. The
;;; obvious repair -- run it on uv_queue_work -- does not work either:
;;; that callback runs on a pool thread, and a Chez foreign-callable
;;; cannot be entered from a thread Chez does not own. There is no pure
;;; Scheme route, so the route if it is ever needed is a C-shim variant
;;; repository, as (igropyr gzip) and (igropyr quickjs) already do. This
;;; paragraph exists so that the next person does not spend the
;;; afternoon rediscovering it.
;;;
;;; THE THREAD POOL IS SHARED AND SMALL. libuv runs four pool threads by
;;; default and file I/O shares them with DNS resolution, so a burst of
;;; durable writes and a burst of lookups contend. UV_THREADPOOL_SIZE
;;; changes it and is read once, at first use -- it must be set before
;;; the process starts, not from inside it.
;;;
;;; IT DOES NOT STOP THE WORLD, AND IT IS NOT FASTER. Measured on one
;;; machine with a 192 MiB payload, against a process ticking every 2ms:
;;;
;;;   synchronous    255 ms wall, competitor ticked   0 times
;;;   this library  4094 ms wall, competitor ticked 1734 times
;;;
;;; The first number is the point: 255 ms during which nothing else in
;;; the node ran at all, against 4 s during which everything did. The
;;; second is the price, and it is not small -- most of it is
;;; fs-write-async! copying the bytevector into C memory a byte at a
;;; time, which a payload of this size makes the dominant cost. So this
;;; is a latency-isolation trade and not an optimisation: choose it when
;;; a pause would hurt more than a longer write, which is the usual case
;;; for a node serving requests, and choose the synchronous one for bulk
;;; work where nothing else is waiting.
;;;
;;; ONE JOB IN FLIGHT PER CALL. Each step is submitted only after the
;;; previous one has completed. That is what makes the sequence a
;;; sequence: a pipelined implementation could have a rename in flight
;;; beside the fsync that is supposed to precede it.
;;;
;;; WHAT A KILL LEAVES BEHIND. A killed caller runs no winders, so there
;;; is no cleanup hook and the temporary is left wherever the sequence
;;; had got to: nothing at all before the open, a partial file if the
;;; write had begun, a complete one after the write returned, and
;;; nothing once the rename has happened (the target holds the new
;;; contents). Reclaiming those is an external matter -- they are named
;;; `<path>.<pid>.<n>.tmp` beside the target. The same applies to
;;; with-fs-trace: a kill inside its extent strands the shared hook,
;;; because the restore lives in a winder too.
;;;
;;; v1 IS FILE-LEVEL ONLY, deliberately. There is no batch or compound
;;; API: a multi-file commit -- several data files and then a pointer
;;; file naming them -- is an application protocol, and what a library
;;; can honestly provide is steps that can be awaited and composed. A
;;; compound entry point here would have to invent a commit order and a
;;; recovery story for somebody else's data.

(library (igropyr durable-async)
  (export durable-write-file-async! durable-dir-ensure-async!
          ;; RE-EXPORTED so that importing this library gives the whole
          ;; vocabulary. What it raises is #(durable-error op path), and a
          ;; caller that could not name the predicate for it would have to
          ;; import a second library to catch the errors of the one it is
          ;; using. Same reason (igropyr conversation) re-exports the
          ;; status predicates from (igropyr conv-status).
          durable-error? durable-error-op durable-error-path)
  (import (chezscheme)
          (igropyr actor)
          (igropyr libuv)
          (only (igropyr durable)
                durable-error? durable-error-op durable-error-path
                fs-trace-step))

  ;; THE SAME SHAPE, and it has to be the same shape rather than merely
  ;; similar: a caller that catches durable-error? around one library
  ;; must catch it around the other, and durable-error-op has to answer
  ;; with the op names it already knows.
  (define (durable-err op path) (vector 'durable-error op path))
  (define (fail! op path) (raise (durable-err op path)))

  ;; Refused before anything is submitted, so a caller's mistake never
  ;; becomes a filesystem error and never leaves a job in flight.
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

  (define temp-counter (box 0))
  (define (temp-name-for path)
    (let ((n (unbox temp-counter)))
      (set-box! temp-counter (+ n 1))
      (string-append path "." (number->string (get-process-id))
                     "." (number->string n) ".tmp")))

  ;; WAIT FOR THIS JOB, NOT FOR A COMPLETION. The caller may be using the
  ;; fs primitives directly as well, so its mailbox can hold other
  ;; #(fs-done ...) frames; matching the id is what keeps this sequence
  ;; from consuming one of those and mistaking somebody else's rc for its
  ;; own step's.
  (define (await-job id)
    (receive (`#(fs-done ,@id ,rc) rc)))

  ;; One step: submit, wait, and let the trace see it. The op and the
  ;; path are the ones the synchronous library uses, and the rc is the
  ;; outcome -- identical to how a libc step is recorded there.
  (define (fs-step op path submit)
    (fs-trace-step op path (lambda () (await-job (submit)))))

  (define EEXIST -17)

  ;; A negative rc is this library's only failure signal from the pool.
  (define (checked op path rc)
    (when (< rc 0) (fail! op path))
    rc)

  ;; ---- the write sequence ------------------------------------------------

  ;; EXCLUSIVE, THEN A DIFFERENT NAME. Finding the name taken is not a
  ;; failure: the synchronous library tries the next candidate and only a
  ;; caller that exhausts them is refused. The bound counts from zero and
  ;; continues while it is below 1024, so the candidates tried are
  ;; numbered 0 through 1024 -- 1025 of them, not 1024. The synchronous
  ;; library is off by the same one, so the two agree; the number is
  ;; written out here rather than restated as a round figure because a
  ;; round figure is what made it look checked.
  ;; That matters because a temporary is deliberately left behind by a
  ;; failed rename -- it holds the only copy of somebody's data -- and a
  ;; second run whose pid was reused and whose counter restarted at zero
  ;; will propose that exact name. Refusing on the first collision would
  ;; turn "somebody else's preserved data is in the way" into an error
  ;; the caller cannot act on; renaming past it is the answer.
  ;;
  ;; The exhausted case is classified 'write, not 'open, because that is
  ;; what the synchronous library answers and the two must agree.
  (define (open-temp! path)
    (let loop ((tries 0))
      (let* ((tmp (temp-name-for path))
             (rc (fs-step 'open tmp
                   (lambda ()
                     (fs-open-async! tmp
                       (bitwise-ior fs-o-wronly fs-o-creat fs-o-excl)
                       ;; 0666, NOT 0600, AND THIS DECIDES THE TARGET'S
                       ;; PERMISSIONS. The rename gives the target the
                       ;; temporary's mode, so a stricter mode here is not
                       ;; a stricter temporary -- it is a different
                       ;; product. The synchronous library opens through a
                       ;; Chez port, which creates 0666 and lets the umask
                       ;; subtract; matching that is what keeps switching
                       ;; between the two libraries from silently changing
                       ;; who can read what an application writes. Policy
                       ;; belongs to the caller's umask.
                       #o666 self)))))
        (cond ((>= rc 0) (values tmp rc))
              ;; ONLY A COLLISION IS RETRIED. Retrying every failure was
              ;; wrong twice over: it spent 1024 pool jobs discovering
              ;; that a missing directory is still missing, and the path
              ;; it finally reported was the 1024th candidate rather than
              ;; the one the synchronous library names for the same
              ;; failure. The synchronous library retries only when the
              ;; name exists; testing the rc for EEXIST asks the same
              ;; question without the stat it would otherwise need.
              ((and (= rc EEXIST) (< tries 1024)) (loop (+ tries 1)))
              ;; RAISED THROUGH THE TRACE, not beside it. The step that
              ;; failed was recorded as 'open with its rc, but what the
              ;; caller is told is 'write -- so without this the trace
              ;; holds no failed 'write at all and a reader comparing the
              ;; two sees an error that never happened. The synchronous
              ;; library raises this through its own step for the same
              ;; reason.
              (else (fs-trace-step 'write tmp
                      (lambda () (fail! 'write tmp))))))))

  ;; A SHORT WRITE IS NOT AN ERROR AND NOT A COMPLETION. The synchronous
  ;; library writes through a port, which either writes everything or
  ;; raises; the pool answers with a byte count, and a positive count
  ;; smaller than the buffer is a legal partial write. Treating one as
  ;; done would truncate the file silently -- the rename would then
  ;; publish a short file as though it were whole, which is precisely the
  ;; failure this library exists to prevent. The remainder is resubmitted
  ;; from the offset it reached.
  (define (write-all! tmp fd bytes)
    (let ((n (bytevector-length bytes)))
      ;; SUBMIT FIRST, THEN TEST. An empty payload still performs one
      ;; write of zero bytes, because the synchronous library still
      ;; records a 'write for it and a sequence that silently loses a
      ;; step for one input is not the same sequence. (Measured: the
      ;; primitive accepts a zero-length buffer and answers 0.)
      (let loop ((off 0))
        (if #f
            0
            (let ((rc (fs-step 'write tmp
                        (lambda ()
                          (fs-write-async! fd
                            ;; The first submission hands over the
                            ;; whole bytevector; only a short write
                            ;; makes a copy of what is left, so the
                            ;; common path copies nothing extra. A
                            ;; pathological sequence of one-byte writes
                            ;; would make this quadratic -- worth
                            ;; knowing, not worth pre-solving, since a
                            ;; local filesystem does not short-write a
                            ;; regular file in practice and the loop is
                            ;; here for correctness rather than for a
                            ;; case that is expected.
                            (if (= off 0)
                                bytes
                                (let* ((left (- n off))
                                       (rest (make-bytevector left)))
                                  (bytevector-copy! bytes off rest 0 left)
                                  rest))
                            off self)))))
              (when (< rc 0) (cleanup-temp! fd tmp) (fail! 'write tmp))
              ;; NO PROGRESS IS A FAILURE. A zero return with bytes still
              ;; to go leaves the offset where it was, so the same
              ;; remainder is copied and submitted again for ever, one
              ;; more pool job each time -- a livelock that never answers
              ;; the caller rather than an error it can act on. A regular
              ;; file should not do this; the loop exists for correctness,
              ;; and "should not" is not a termination argument.
              (when (and (= rc 0) (< off n))
                (cleanup-temp! fd tmp) (fail! 'write tmp))
              (let ((next (+ off rc)))
                (if (>= next n) 0 (loop next))))))))

  ;; BEST EFFORT, AND NEVER THE REPORTED ERROR. Closing and unlinking are
  ;; how a failed write tidies up; either can fail on its own, and
  ;; neither is allowed to replace the reason the write failed.
  ;; THROUGH THE TRACE LIKE EVERY OTHER STEP. A close on a cleanup path
  ;; is still an operation this library performed, and the synchronous
  ;; library records its own cleanup close; leaving these out made the
  ;; trace show a descriptor being opened and never closed, which is
  ;; exactly the shape a reader would investigate as a leak.
  (define (close-quietly fd)
    (guard (e (#t (void)))
      (fs-step 'close "" (lambda () (fs-close-async! fd self)))))

  (define (cleanup-temp! fd tmp)
    (close-quietly fd)
    ;; DELIBERATELY SYNCHRONOUS, AND THE ONE PLACE THIS LIBRARY BLOCKS.
    ;; There is no async unlink primitive to call. It runs only on the
    ;; failed-write path, so the common path never reaches it -- but on a
    ;; slow or networked filesystem it stops every green process for as
    ;; long as the unlink takes, which is the one thing this library
    ;; otherwise does not do. Removing it is a libuv-side addition
    ;; (uv_fs_unlink), not something that can be fixed from here.
    (guard (e (#t (void))) (delete-file tmp)))

  ;; fsync the file this fd names, then close it. Both steps are the
  ;; caller's to hear about, and neither deletes the temporary: once the
  ;; write has returned, the temporary holds complete data, and removing
  ;; it would destroy the only copy while the target still holds what it
  ;; held before.
  ;; TWO EXISTING SHAPES, SPLICED. Release the descriptor the way the
  ;; directory flush does, and keep the temporary the way every phase
  ;; after a successful body write does: the bytes are complete by now,
  ;; so the temporary holds the only copy of them while the target still
  ;; holds what it held before.
  ;;
  ;; A failing fsync used to raise with the descriptor still open. The
  ;; caller is alive on that path -- it caught a durable-error and went
  ;; on -- so the runtime's owner-died sweep never runs and nothing ever
  ;; reclaims it. The same rule was already written into the directory
  ;; flush below; it was missing here, which is what one rule in two
  ;; places costs.
  ;;
  ;; A failing CLOSE is deliberately not retried: POSIX leaves the
  ;; descriptor's state unspecified after one, and closing again can
  ;; reach a descriptor number something else has since been given.
  (define (flush-and-close! tmp fd)
    (let ((rc (fs-step 'fsync tmp (lambda () (fs-fsync-async! fd self)))))
      (when (< rc 0)
        (close-quietly fd)
        (fail! 'fsync tmp)))
    (checked 'close tmp
      (fs-step 'close tmp (lambda () (fs-close-async! fd self)))))

  ;; THE STEP THAT GETS LEFT OUT: a rename changes a DIRECTORY, and a
  ;; directory is a file that has to be flushed like any other. Without
  ;; it the rename is in the kernel's memory and not on the medium, and a
  ;; crash here can leave neither the old file nor the new one.
  (define (fsync-dir! dir)
    (let ((fd (checked 'dir-open dir
                (fs-step 'dir-open dir
                  (lambda ()
                    (fs-open-async! dir fs-o-rdonly 0 self))))))
      (let ((rc (fs-step 'dir-fsync dir
                  (lambda () (fs-fsync-async! fd self)))))
        (when (< rc 0)
          (guard (e (#t (void))) (await-job (fs-close-async! fd self)))
          (fail! 'dir-fsync dir)))
      (checked 'dir-close dir
        (fs-step 'dir-close dir (lambda () (fs-close-async! fd self))))))

  (define (durable-write-file-async! path bytes)
    (check-path! 'durable-write-file-async! path)
    (unless (bytevector? bytes)
      (assertion-violation 'durable-write-file-async!
        "contents must be a bytevector" bytes))
    (let ((dir (parent-of 'durable-write-file-async! path)))
      (let-values (((tmp fd) (open-temp! path)))
        (write-all! tmp fd bytes)
        (flush-and-close! tmp fd)
        (checked 'rename path
          (fs-step 'rename path
            (lambda () (fs-rename-async! tmp path self))))
        (fsync-dir! dir)
        path)))

  ;; ---- the directory ------------------------------------------------------

  ;; EEXIST DOES NOT MEAN "A DIRECTORY IS THERE". mkdir answers it for a
  ;; regular file of the same name too, and answering success then would
  ;; hand back a path that cannot hold anything. The synchronous library
  ;; asks file-directory?; this one has no stat, and rather than decode a
  ;; platform statbuf it opens the path with O_DIRECTORY, which succeeds
  ;; only for a directory and gives -ENOTDIR for anything else. A
  ;; synchronous file-directory? here would be a blocking syscall inside
  ;; the library whose whole purpose is not having one.
  (define (existing-directory? path)
    (let ((rc (fs-step 'dir-open path
                (lambda ()
                  (fs-open-async! path
                    (bitwise-ior fs-o-rdonly fs-o-directory) 0 self)))))
      (cond ((>= rc 0)
             ;; The probe's own descriptor. Its close rc is not checked:
             ;; the question being answered is "is this a directory", it
             ;; has already been answered, and turning a failed close into
             ;; a durable-error here would make classifying a path a
             ;; second source of failure. The registration is dropped
             ;; either way by the primitive.
             (guard (e (#t (void)))
               (fs-step 'dir-close path
                 (lambda () (fs-close-async! rc self))))
             #t)
            (else #f))))

  ;; IT MAKES ITS OWN CREATION DURABLE AND UNDERWRITES NOBODY ELSE'S.
  ;; Finding the directory already there returns without flushing
  ;; anything: this call did not create it, and flushing the parent would
  ;; be claiming a durability this call has no basis for -- the directory
  ;; may have been made a moment ago by a process that has not flushed,
  ;; and a crash can still take it away. Losing a mkdir race is not an
  ;; error either: the directory is there, which is what was asked.
  (define (durable-dir-ensure-async! path)
    (check-path! 'durable-dir-ensure-async! path)
    (let ((parent (parent-of 'durable-dir-ensure-async! path)))
      (let ((rc (fs-step 'mkdir path
                  (lambda () (fs-mkdir-async! path #o755 self)))))
        (cond ((>= rc 0) (fsync-dir! parent) path)
              ((and (= rc EEXIST) (existing-directory? path)) path)
              (else (fail! 'mkdir path))))))
)
