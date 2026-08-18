#!chezscheme
;;; Mixed-version overload: what a PRE-REFUSAL asker experiences against
;;; an owner that refuses -- run against the real old code, not re-derived
;;; from reading it.
;;;
;;; The refusal frame #(conv-overload ref) shipped after the revision
;;; pinned here. An old asker's selective receive matches no such shape,
;;; so the claim is that it degrades to exactly the behaviour it already
;;; had: wait out its own ttl and answer 'unreachable -- not a crash, not
;;; a misread reply, and not a consumed token. All three parts are
;;; asserted: the word, the FULL wait (a refusal the old side could see
;;; would come back early), and the same token succeeding afterwards.
;;;
;;; What this file deliberately does NOT assert: the refusal frame left
;;; in the old asker's mailbox. It is real (the old drain does not take
;;; the shape), bounded by the mixed-version window, and the reason the
;;; upgrade order is entry-nodes-first; it is documented rather than
;;; observable from outside the child process.
;;;
;;; The pin is dd50b1f, the last revision before admission control: a
;;; protocol boundary, a fact of history that does not move. SKIPS,
;;; named: a worktree of an ancestor needs full git history; shallow or
;;; exported checkouts cannot run this and say so.

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation))

(define old-rev "dd50b1f")
(define old-tree "/tmp/igropyr-conv-overload-old")

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))

(define (fail label . info)
  (display "FAIL: ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))
(define (ok label) (display "  ok  ") (display label) (newline))

(define (sh cmd) (system cmd))

(define repo (string-append (current-directory) "/igropyr"))
(define child (string-append repo "/test/conv-mixed-overload-child.sc"))

(sh (string-append "git -C " repo " worktree remove --force " old-tree
                   " 2>/dev/null; rm -rf " old-tree))
(unless (zero? (sh (string-append
                     "git -C " repo " worktree add -q " old-tree " " old-rev
                     " 2>/dev/null")))
  (display "conv-mixed-overload: SKIP -- cannot create a worktree of ")
  (display old-rev)
  (display "\n  (needs full git history; shallow clones and exports")
  (display " cannot run the mixed-version case)\n")
  (exit 0))
(sh (string-append "cd " old-tree " && ln -sfn . igropyr"))

(define port 19790)
(define secret "overload-mixed-secret")

(start-scheduler
  (lambda ()

    (define (gated-flow name)
      (lambda (req suspend! commit!)
        (register name self)
        (let loop ((r (suspend! 'ready)))
          (case r
            ((block) (receive (`#(go) 'ok))
                     (loop (suspend! 'unblocked)))
            (else (loop (suspend! (vector 'echo r))))))))
    (define (echo-flow req suspend! commit!)
      (let loop ((n 1) (r req))
        (loop (+ n 1) (suspend! (vector 'echo r n)))))

    (node-start! 'a secret port)
    (register 'mixed self)
    (conv-set-forward-limit! 1)

    (sh (string-append
          "cd " old-tree " && CHEZSCHEMELIBDIRS=. "
          "CHEZSCHEMELIBEXTS=.chezscheme.sls::.no-obj:.ss::.no-obj:"
          ".sls::.no-obj:.scm::.no-obj:.sch::.no-obj:.sc::.no-obj "
          scheme-bin " --script " child " "
          (number->string port) " " secret
          " > /tmp/overload-mixed-child.log 2>&1 &"))
    (monitor-node 'b)
    (receive (after 15000 (fail "old asker never came up"))
      (`#(node-up b) 'ok))

    (let*-values (((id1 t1 r1) (conversation-start! (gated-flow 'g1) 'hi))
                  ((id2 t2 r2) (conversation-start! echo-flow 'hi)))
      (unless (and (eq? r1 'ready) (equal? r2 (vector 'echo 'hi 1)))
        (fail "the flows did not park" r1 r2))

      ;; the old asker's blocked forward takes the one slot
      (rsend 'b 'ctrl (vector 'hold id1 t1))
      (let poll ((k 0))
        (unless (= 1 (cdr (assq 'hosted (conversation-forward-stats))))
          (if (> k 250)
              (fail "the holding forward never occupied the slot")
              (begin (sleep-ms 20) (poll (+ k 1))))))
      (ok "the old asker's blocked forward holds the only slot")

      ;; the refusal the old asker cannot see: full wait, old word,
      ;; nothing consumed
      (rsend 'b 'ctrl (vector 'try id2 t2 3000))
      (receive (after 20000 (fail "old asker never reported the try"))
        (`#(tried ,reply ,status ,elapsed)
          (unless (eq? status 'unreachable)
            (fail "the old asker saw something other than its own vocabulary"
                  reply status))
          (unless (>= elapsed 2900)
            (fail "the old asker came back before its ttl -- it read a frame"
                  elapsed))))
      (ok "old asker against a refusing owner: full ttl, then 'unreachable")

      ;; release, then the SAME token must work: the refusal was refused
      ;; admission, so the old asker's request was never applied
      (send (whereis 'g1) (vector 'go))
      (receive (after 15000 (fail "the holding forward never returned"))
        (`#(held ,reply ,status)
          (unless (eq? reply 'unblocked)
            (fail "the released hold did not complete" reply status))))
      (rsend 'b 'ctrl (vector 'try id2 t2 10000))
      (receive (after 20000 (fail "old asker never reported the replay"))
        (`#(tried ,reply ,status ,elapsed)
          (unless (equal? reply (vector 'echo 5 2))
            (fail "the refused token did not replay as the SECOND application"
                  reply status))))
      (ok "the same token replays once the slot frees: nothing was consumed"))

    (rsend 'b 'ctrl (vector 'quit))
    (sh (string-append "git -C " repo " worktree remove --force " old-tree
                       " 2>/dev/null; rm -rf " old-tree))
    (display "ALL CONV-MIXED-OVERLOAD TESTS PASSED\n")
    (exit 0)))
