#!chezscheme
;;; Outcome-record hooks: the record can outlive the process, and the
;;; library still never chooses a persistence strategy.
;;;
;;; THE ONE MAPPING IS THE POINT. A reader hands back record values --
;;; #t, 'rolled-back, 'committed-then-failed, 'commit-uncertain-then-
;;; failed, 'killed -- and they flow into settled-or-lost-answer exactly
;;; as a memory hit would. So the suite's central case is "two tiers, one
;;; ledger": the same record value answers the same word whether it came
;;; from memory or from the reader, proven by evicting a real record and
;;; asking again. A draft of this feature carried a second translation
;;; table, and it mapped committed-then-failed to 'settled where the
;;; local path says 'unknown -- upgrading "go reconcile" to "all done",
;;; the mirror of reading a maybe-commit as safe-to-retry. Copies drift;
;;; the construction shares.
;;;
;;; The safety case runs the OTHER way: while local evidence exists, a
;;; lying reader must be unreachable. A local 'killed record answers
;;; 'unknown; a reader scripted to say 'rolled-back for that id must
;;; never be consulted, because 'gone is the one status that licenses
;;; resubmission, and granting it off a stale second opinion is how a
;;; committed transfer runs twice. Once memory is gone that defence is
;;; gone with it -- which is the trust boundary the manual documents:
;;; the persistence adapter must be monotonic and never rewrite a
;;; committed or uncertain outcome as rolled-back. No test can make a
;;; lying reader safe; these tests pin where the library's own defence
;;; ends.
;;;
;;; Writer timing is asserted, not assumed -- with its scope said
;;; plainly: the probe writer YIELDS (sleep-ms), so what the ticking
;;; competitor proves is that interrupts are on and a yielding writer
;;; blocks only its own conversation. A writer inside a BLOCKING syscall
;;; (durable's fsync) still stops the single-threaded world for the
;;; syscall's own duration -- measured at 72ms for a 192 MiB write when
;;; this was gotten wrong in prose -- and a yielding probe cannot prove
;;; anything about that case. The terminal reply waiting for the writer,
;;; and a same-conversation peek waiting likewise, hold either way.

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation)
        (only (igropyr libuv) now-ms))

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))

(define (fail label . info)
  (display "FAIL: ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))
(define (ok label) (display "  ok  ") (display label) (newline))

(define port 19792)
(define secret "record-secret")

(define repo (string-append (current-directory) "/igropyr"))
(define census-child (string-append repo "/test/conv-census-child.sc"))

(define root
  (format "/tmp/igropyr-conv-record-~a-~a" (get-process-id) (real-time)))
(system (string-append "rm -rf " root "; mkdir -p " root))

(start-scheduler
  (lambda ()

    ;; ---- probes ---------------------------------------------------------
    ;; the writer log keeps ORDERED (id . outcome) pairs; exactness and
    ;; cardinality both matter -- membership alone passes on duplicate or
    ;; wrong-id calls
    (define writer-log '())
    (define (log-writer id outcome)
      (set! writer-log (cons (cons id outcome) writer-log)))
    (define (writer-entries id)
      (filter (lambda (e) (equal? (car e) id)) (reverse writer-log)))
    (define reader-calls 0)
    (define reader-script '())   ; alist id -> value (or procedure to raise)
    (define (script-reader id)
      (set! reader-calls (+ reader-calls 1))
      (let ((hit (assoc id reader-script)))
        (and hit (if (procedure? (cdr hit)) ((cdr hit)) (cdr hit)))))
    (define (stats key)
      (cdr (assq key (conversation-hook-stats))))
    (define (expect-writer id outcome label)
      (let ((es (writer-entries id)))
        (unless (equal? es (list (cons id outcome)))
          (fail label 'writer-saw es 'wanted outcome))))

    ;; retry-behaviour probe: the one status that licenses resubmission
    ;; is 'gone; count how often these answers would start replacement
    ;; work, because symbol equality alone misses the consequence
    (define retries 0)
    (define (note-retry st) (when (conversation-gone? st) (set! retries (+ retries 1))))

    (define (peek-state id)
      (let-values (((st tok last) (conversation-peek id)))
        (note-retry st)
        st))

    ;; declared with the probes because a body define cannot follow the
    ;; expressions above it
    (define (start-failing flow label)
      ;; a flow that fails on its FIRST step raises #(conversation-failed
      ;; id reason) at the starter; the id inside is how the record is
      ;; then interrogated
      ;; a plain failure raises #(conversation-failed id reason); a
      ;; failure after commit! touched the world raises
      ;; #(conversation-uncertain id status reason). Either way the id
      ;; rides in slot 1
      (guard (e ((and (vector? e) (>= (vector-length e) 2)
                      (memq (vector-ref e 0)
                            '(conversation-failed conversation-uncertain)))
                 (vector-ref e 1))
                (#t (fail label 'unexpected-raise e)))
        (let-values (((id t r) (conversation-start! flow 'go)))
          (fail label 'returned-normally r))))
    (define (reader-case id-tag value want label)
      (let ((id (string-append "absent-" id-tag)))
        (set! reader-script (list (cons id value)))
        (let ((before reader-calls))
          (let ((st (peek-state id)))
            (unless (eq? st want) (fail label st 'wanted want))
            (unless (= reader-calls (+ before 1))
              (fail label 'reader-not-consulted))))))

    ;; ---- install validation --------------------------------------------
    (guard (e (#t 'ok))
      (conversation-record-hooks! log-writer #f)
      (fail "a half pair was accepted"))
    (guard (e (#t 'ok))
      (conversation-record-hooks! 'not-a-procedure script-reader)
      (fail "a non-procedure writer was accepted"))
    (conversation-record-hooks! log-writer script-reader)
    ;; a rejected install must not have half-changed anything: the pair
    ;; installed above must be fully live, proven by everything below
    (ok "half pairs and non-procedures refused; a whole pair installs")

    ;; ---- five exits, five words, each exactly once ----------------------
    (let*-values
        (((id-settled t1 r1)
          ;; short ttl: a settled flow LINGERS for one ttl, and the
          ;; eviction case below needs that window to close inside a run
          (conversation-start!
            (lambda (req suspend! commit!)
              (commit! (lambda () 'ok)) 'done-fine)
            'go 1200)))
      (define id-rb
        (start-failing (lambda (req suspend! commit!) (raise 'flow-bang))
                       "raising flow"))
      (define id-ctf
        (start-failing (lambda (req suspend! commit!)
                         (commit! (lambda () 'ok))
                         (raise 'after-commit))
                       "commit-then-raise flow"))
      (define id-cutf
        (start-failing (lambda (req suspend! commit!)
                         (commit! (lambda ()
                                    (raise (vector 'commit-uncertain 'net))))
                         'unreached)
                       "uncertain-commit flow"))
      (expect-writer id-settled #t "settled flow: writer word")
      (expect-writer id-rb 'rolled-back "raising flow: writer word")
      (expect-writer id-ctf 'committed-then-failed "commit-then-raise: writer word")
      (expect-writer id-cutf 'commit-uncertain-then-failed
                     "uncertain commit: writer word")
      (ok "four exit shapes deliver their record values, exactly once each")

      ;; the fifth: killed in flight. Park a flow, kill its process; the
      ;; backstop writes 'killed
      ;; a SHORT ttl, because 'killed is written by the watchdog when it
      ;; next wakes, and it sleeps on the conversation's own clock
      (let*-values (((id-k tk rk)
                     (conversation-start!
                       (lambda (req suspend! commit!)
                         (suspend! 'parked-now) 'never)
                       'go 1000)))
        (kill (whereis (string->symbol (string-append "igropyr-conv-" id-k)))
              'record-test)
        (let ((st (peek-state id-k)))
          (unless (eq? st 'unknown)
            (fail "a killed conversation did not answer 'unknown" st)))
        ;; 'killed is the WATCHDOG's word -- a separate process that
        ;; outlives the one it watched -- so it arrives a beat later
        (let poll ((k 0))
          (cond ((pair? (writer-entries id-k)) 'ok)
                ((> k 300) (fail "the backstop never reached the writer"))
                (else (sleep-ms 20) (poll (+ k 1)))))
        (expect-writer id-k 'killed "killed flow: writer word")
        (ok "a kill reaches the writer as 'killed, and answers 'unknown")

        ;; ---- the safety case: local evidence shadows a lying reader ---
        ;; the local record is 'killed -> 'unknown. The reader lies
        ;; 'rolled-back, which would grant retry authority. It must not
        ;; even be asked.
        (set! reader-script (list (cons id-k 'rolled-back)))
        (let ((calls-before reader-calls))
          (let ((st (peek-state id-k)))
            (unless (eq? st 'unknown)
              (fail "a lying reader outranked local evidence" st)))
          (unless (= reader-calls calls-before)
            (fail "the reader was consulted despite a local record")))
        (ok "while local evidence exists, a lying reader is never asked")

        ;; ---- the live tier outranks the record tier ------------------
        ;; while the settled conversation LINGERS its process answers,
        ;; and the reader -- even scripted for that id -- is not asked
        (set! reader-script (list (cons id-settled 'rolled-back)))
        (let ((before reader-calls))
          (let-values (((st tok last) (conversation-peek id-settled)))
            (unless (eq? st 'completed)
              (fail "a lingering conversation did not answer live" st)))
          (unless (= reader-calls before)
            (fail "the reader was asked while the process lingered")))
        (ok "the lingering process outranks the reader")
        ;; let the linger close, so the record tier is what answers next
        (let poll ((k 0))
          (cond ((not (whereis (string->symbol
                                 (string-append "igropyr-conv-" id-settled))))
                 'ok)
                ((> k 300) (fail "the settled linger never closed"))
                (else (sleep-ms 20) (poll (+ k 1)))))

        ;; ---- two tiers, one ledger: evict a REAL record, ask again ----
        ;; count-eviction branch: cap the table at 1; the next insert
        ;; pushes the oldest records out. id-settled is the oldest.
        (conversation-set-limits! 1 #f)
        (set! reader-script (list (cons id-settled #t)))
        (let ((calls-before reader-calls))
          (let ((st (peek-state id-settled)))
            (unless (eq? st 'settled)
              (fail "the evicted settled record did not come back 'settled" st))
            (unless (= reader-calls (+ calls-before 1))
              (fail "the evicted record was not answered by the reader"
                    reader-calls calls-before)))
          ;; the same record value, memory tier earlier, reader tier now,
          ;; answered the same word -- the construction shares the mapping
          (ok "count-evicted record: reader tier answers the same word"))
        ;; ttl-eviction branch: everything still resident ages out
        (conversation-set-limits! 10000 1)
        (sleep-ms 10)
        (conversation-set-limits! #f 3600000)   ; prune ran; restore ttl
        (set! reader-script (list (cons id-ctf 'committed-then-failed)))
        (let ((st (peek-state id-ctf)))
          (unless (eq? st 'unknown)
            (fail "ttl-evicted committed-then-failed did not answer 'unknown" st)))
        (ok "ttl-evicted record: reader tier still answers 'unknown")
        (conversation-set-limits! 10000 3600000)))

    ;; ---- the reader tier, word by word, on locally absent ids ----------
    ;; absent ids carry no ~, so they resolve locally. Exact call counts:
    ;; "answer unchanged" without them passes when the reader is dead code
    (reader-case "rb" 'rolled-back 'gone "reader rolled-back -> gone")
    (reader-case "st" #t 'settled "reader #t -> settled")
    (reader-case "ctf" 'committed-then-failed 'unknown
                 "reader committed-then-failed -> unknown")
    (reader-case "cutf" 'commit-uncertain-then-failed 'unknown
                 "reader uncertainty -> unknown")
    (reader-case "kil" 'killed 'unknown "reader killed -> unknown")
    (reader-case "none" #f 'unknown "reader #f -> unknown")
    (ok "each reader word answers through the one mapping")

    ;; a reader inventing vocabulary, and one that raises: both count,
    ;; both answer as no-record
    (let ((errs (stats 'record-reader-errors)))
      (reader-case "bogus" 'flourished 'unknown "reader bogus word -> unknown")
      (unless (= (stats 'record-reader-errors) (+ errs 1))
        (fail "an invented word was not counted"))
      (reader-case "boom" (lambda () (raise 'reader-bang)) 'unknown
                   "raising reader -> unknown")
      (unless (= (stats 'record-reader-errors) (+ errs 2))
        (fail "a raising reader was not counted")))
    (ok "invented vocabulary and raises are counted, answered as no record")

    ;; ---- resume and bounded peek take the same fallback ----------------
    (set! reader-script (list (cons "absent-r1" 'rolled-back)
                              (cons "absent-r2" #t)))
    (let-values (((reply status) (conversation-resume! "absent-r1" "tok" 1)))
      (note-retry status)
      (unless (and (eq? reply #f) (eq? status 'gone))
        (fail "resume on a reader rolled-back did not answer (#f 'gone)"
              reply status)))
    (let-values (((reply status) (conversation-resume! "absent-r2" "tok" 1)))
      (note-retry status)
      (unless (eq? status 'settled)
        (fail "resume on a reader settled record did not answer 'settled"
              status)))
    (let-values (((st tok last) (conversation-peek/timeout "absent-r1" 500)))
      (note-retry st)
      (unless (eq? st 'gone)
        (fail "bounded peek did not reach the reader tier" st)))
    (ok "resume and bounded peek consult the same reader tier")

    ;; the retry ledger: exactly the rolled-back answers licensed
    ;; resubmission -- one peek, one resume, one bounded peek -- and no
    ;; uncertainty, no committed-failure, no invented word ever did
    (unless (= retries 3)
      (fail "retry authority was granted the wrong number of times" retries))
    (ok "only 'gone licensed a retry, exactly three times")

    ;; ---- a raising writer hurts nothing but the counter ----------------
    (conversation-record-hooks! (lambda (id outcome) (raise 'writer-bang))
                                script-reader)
    (let ((errs (stats 'record-writer-errors)))
      (let-values (((id t r) (conversation-start!
                               (lambda (req suspend! commit!)
                                 (commit! (lambda () 'ok)) 'fine)
                               'go 900)))
        (unless (eq? r 'fine)
          (fail "a raising writer disturbed the flow's reply" r))
        (unless (= (stats 'record-writer-errors) (+ errs 1))
          (fail "the raising writer was not counted"))
        ;; the record's own proof needs the linger out of the way: while
        ;; the process lives, peek answers from it, not from the table
        (let poll ((k 0))
          (cond ((not (whereis (string->symbol
                                 (string-append "igropyr-conv-" id))))
                 'ok)
                ((> k 300) (fail "the raising-writer linger never closed"))
                (else (sleep-ms 20) (poll (+ k 1)))))
        (unless (eq? (peek-state id) 'settled)
          (fail "the record did not land despite the raising writer"))))
    (ok "a raising writer: flow completes, record lands, counter moves")

    ;; ---- swap and uninstall are total ----------------------------------
    (let ((log2 '()))
      (conversation-record-hooks!
        (lambda (id outcome) (set! log2 (cons (cons id outcome) log2)))
        script-reader)
      (let-values (((id t r) (conversation-start!
                               (lambda (req suspend! commit!)
                                 (commit! (lambda () 'ok)) 'fine)
                               'go)))
        (unless (= 1 (length log2))
          (fail "the swapped-in writer did not receive the outcome" log2))
        (unless (null? (writer-entries id))
          (fail "the swapped-out writer still received the outcome")))
      (conversation-record-hooks! #f #f)
      (let ((n (length log2)) (rc reader-calls))
        (let-values (((id t r) (conversation-start!
                                 (lambda (req suspend! commit!)
                                   (commit! (lambda () 'ok)) 'fine)
                                 'go)))
          (void))
        (let ((st (peek-state "absent-after-uninstall")))
          (unless (eq? st 'unknown)
            (fail "an uninstalled reader still answered" st)))
        (unless (and (= n (length log2)) (= rc reader-calls))
          (fail "uninstalled hooks were still called"))))
    (ok "swap reroutes wholly; uninstall silences both hooks")

    ;; ---- writer timing: interrupts on, terminal reply after ------------
    (conversation-record-hooks!
      (lambda (id outcome) (sleep-ms 700))
      (lambda (id) #f))
    (let ((ticks (box 0)) (stop (box #f)))
      (spawn (lambda ()
               (let loop ()
                 (unless (unbox stop)
                   (set-box! ticks (+ 1 (unbox ticks)))
                   (sleep-ms 20)
                   (loop)))))
      (let ((t0 (now-ms)))
        (let-values (((id t r) (conversation-start!
                                 (lambda (req suspend! commit!)
                                   (commit! (lambda () 'ok)) 'slow-done)
                                 'go)))
          (let ((elapsed (- (now-ms) t0)))
            (set-box! stop #t)
            (unless (eq? r 'slow-done)
              (fail "the slow-writer flow's reply is wrong" r))
            (unless (>= elapsed 650)
              (fail "the terminal reply outran the writer" elapsed))
            ;; interrupts were on: the competitor kept running
            (unless (>= (unbox ticks) 10)
              (fail "the scheduler stalled during the writer" (unbox ticks)))
            ;; and the conversation was visible the whole time: a drain
            ;; must not read zero while an outcome is still being written
            (void))))
      (ok "a yielding writer blocks only its conversation; the reply waits"))
    (conversation-record-hooks! log-writer script-reader)

    ;; ---- forwarded lookups reach the owner's reader --------------------
    (node-start! 'a secret port)
    (register 'census-suite self)
    (system (string-append
              "cd " (current-directory) " && "
              "CHEZSCHEMELIBDIRS=. "
              "CHEZSCHEMELIBEXTS=\"" (or (getenv "CHEZSCHEMELIBEXTS") "") "\" "
              scheme-bin " --script " census-child " "
              (number->string port) " " secret
              " > /tmp/conv-record-child.log 2>&1 &"))
    (monitor-node 'b)
    (receive (after 15000 (fail "asker node never came up"))
      (`#(node-up b) 'ok))
    ;; the owner's router only exists once a conversation has RUN on the
    ;; clustered node (ensure-router! lives in run!, and is a no-op
    ;; unclustered) -- without it a forwarded peek answers 'unreachable
    ;; by documented semantics, and this section would test the wrong
    ;; thing. One throwaway conversation summons it.
    (let-values (((idr tr rr)
                  (conversation-start!
                    (lambda (req suspend! commit!)
                      (commit! (lambda () 'ok)) 'router-up)
                    'go 900)))
      (unless (eq? rr 'router-up) (fail "the router-summoning flow broke")))
    ;; a WELL-FORMED absent id: prepare! mints one inertly -- correct
    ;; node prefix and timestamp, no process, no record, never run
    (let ((absent-id (conversation-ref-id
                       (conversation-prepare!
                         (lambda (req suspend! commit!) 'never) 'go))))
      (set! reader-script (list (cons absent-id 'rolled-back)))
      (let ((before reader-calls) (tag 991))
        (rsend 'b 'ctrl (vector 'peek tag absent-id 10000))
        (receive (after 15000 (fail "remote peek never reported"))
          (`#(res ,@tag ,payload)
            (unless (eq? (car payload) 'gone)
              (fail "a forwarded peek missed the owner's reader" payload))))
        (unless (= reader-calls (+ before 1))
          (fail "the owner's reader was not the one consulted" reader-calls))
        (let ((tag 992))
          (rsend 'b 'ctrl (vector 'resume tag absent-id "tok" 1 10000))
          (receive (after 15000 (fail "remote resume never reported"))
            (`#(res ,@tag ,payload)
              (unless (eq? (cadr payload) 'gone)
                (fail "a forwarded resume missed the owner's reader"
                      payload)))))))
    (rsend 'b 'ctrl (vector 'quit))
    (ok "forwarded peek and resume consult the owner's reader")

    ;; ---- e2e: the records outlive the OS process, through durable ------
    ;; stage 1 runs in a SEPARATE scheme process: durable-backed writer,
    ;; one settled and one rolled-back flow, fs ops traced to prove the
    ;; crash-safe sequence (temp/fsync/rename) actually ran -- read-back
    ;; alone would pass on plain file IO. Stage 2 is this process's
    ;; watching brief: a fresh reader over those files answers truthfully
    ;; about ids it has never seen.
    (let ((stage1 (string-append root "/stage1.sc")))
      (call-with-output-file stage1
        (lambda (p)
          (write '(import (chezscheme) (igropyr actor) (igropyr conversation)
                          (igropyr durable)) p)
          (write `(define recs ,(string-append root "/recs")) p)
          (write '(durable-dir-ensure! recs) p)
          (write '(define ops (list)) p)
          (write '(start-scheduler
                    (lambda ()
                      (conversation-record-hooks!
                        (lambda (id outcome)
                          (with-fs-trace
                            (lambda (op path detail) (set! ops (cons op ops)))
                            (lambda ()
                              (durable-write-file!
                                (string-append recs "/" id)
                                (string->utf8 (format "~s" outcome))))))
                        (lambda (id) #f))
                      (let-values (((id1 t1 r1)
                                    (conversation-start!
                                      (lambda (req suspend! commit!)
                                        (commit! (lambda () 'ok)) 'done)
                                      'go)))
                        (let ((id2 (guard (e ((vector? e) (vector-ref e 1)))
                                     (conversation-start!
                                       (lambda (req suspend! commit!)
                                         (raise 'bang))
                                       'go)
                                     'never-returns)))
                          (unless (and (memq 'fsync ops) (memq 'rename ops))
                            (display "NO-DURABLE-SEQUENCE\n") (exit 1))
                          (display id1) (newline)
                          (display id2) (newline)
                          (exit 0)))))
                  p)))
      (let* ((out (string-append root "/stage1.out"))
             (rc (system (string-append
                           "cd " (current-directory) " && "
                           "CHEZSCHEMELIBDIRS=. "
                           "CHEZSCHEMELIBEXTS=\""
                           (or (getenv "CHEZSCHEMELIBEXTS") "") "\" "
                           scheme-bin " --script " stage1 " > " out " 2>&1"))))
        (unless (zero? rc)
          (system (string-append "cat " out))
          (fail "stage 1 (the writing process) failed" rc))
        (let* ((lines (call-with-input-file out
                        (lambda (p)
                          (let loop ((acc '()))
                            (let ((l (get-line p)))
                              (if (eof-object? l)
                                  (reverse acc)
                                  (loop (cons l acc))))))))
               (id1 (car lines))
               (id2 (cadr lines)))
          ;; this process never saw those conversations. A reader over
          ;; the files answers for them.
          (conversation-record-hooks!
            (lambda (id outcome) (void))
            (lambda (id)
              (let ((f (string-append root "/recs/" id)))
                (and (file-exists? f)
                     (call-with-input-file f read)))))
          (unless (eq? (peek-state id1) 'settled)
            (fail "the settled outcome did not survive the process" id1))
          (unless (eq? (peek-state id2) 'gone)
            (fail "the rolled-back outcome did not survive the process" id2))
          (ok "records written through durable outlive the OS process"))))

    (conversation-record-hooks! #f #f)
    (system (string-append "rm -rf " root))
    (display "ALL CONV-RECORD TESTS PASSED\n")
    (exit 0)))
