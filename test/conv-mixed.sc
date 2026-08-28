#!chezscheme
;;; RETIRED 2026-08-28 (B1, the wire protocol version) -- out of
;;; run-all.sh. This suite builds a mixed-WIRE-version mesh, and that
;;; scenario no longer exists: the version is exact-match and the mesh
;;; upgrades in lockstep, so a pre-v2 node cannot join one. The suite is
;;; kept, not deleted, because the scenario it covers at the APPLICATION
;;; layer is still real -- two nodes both speaking wire version 2 may
;;; run different code revisions.
;;;
;;; REVIVAL, and the condition is mechanical: the first
;;; conversation-protocol change that lands on top of the v2 baseline.
;;; Re-pin old-rev to the last v2 commit before that change and put this
;;; file back in run-all.sh. Until such a commit exists, re-pinning
;;; would produce a run that passes without testing anything, which is
;;; worse than a named absence.
;;;
;;; Mixed-version mesh: the rolling-upgrade claim, tested against a REAL
;;; old node instead of re-derived from the source.
;;;
;;; The wide peek/resume reply (the commit witness crossing the link)
;;; shipped in 7322d9d, guarded by a capability bit: a NEGATIVE ref means
;;; "I can read a wide reply"; an old router echoes the ref without
;;; interpreting it and answers narrow. The safety claim is three
;;; directions -- old->new, new->old, new->new -- and until this file it
;;; rested on reading the old code, not on running it.
;;;
;;; So this suite checks out the parent of that release into a worktree
;;; and runs node b from it, FROM SOURCE (the .no-obj mapping means no
;;; build step). Node a runs the current tree. The revision is pinned in
;;; this file on purpose: it is the protocol boundary, a fact of history
;;; that does not move.
;;;
;;;   new asker -> old owner: b owns a conversation; a resumes and peeks
;;;     it. a sends negative refs; b echoes them, answers narrow; a must
;;;     match the narrow shape and simply see no witness -- and must NOT
;;;     raise over the missing field.
;;;   old asker -> new owner: a owns a conversation and hands b the id;
;;;     b resumes it with an old-style positive ref. The current router's
;;;     narrow branch answers -- a branch no all-new mesh ever takes, so
;;;     without this case it has no coverage at all.
;;;
;;; SKIPS, named: this needs the git history (a worktree of an ancestor
;;; commit). A shallow or exported checkout cannot run it, and says so.

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation)
        (only (igropyr libuv) now-ms))

(define old-rev "7322d9d^")
(define old-tree "/tmp/igropyr-conv-mixed-old")

(define scheme-bin (or (getenv "SCHEME_BIN") "scheme"))

(define (fail label . info)
  (display "FAIL: ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline)
  (exit 1))

(define (sh cmd) (system cmd))

;; run-all's cwd is the links root, where `igropyr` is a symlink into the
;; real repository -- git follows it, so -C igropyr addresses the right
;; history whatever the checkout is called
(define repo (string-append (current-directory) "/igropyr"))
(define child (string-append repo "/test/conv-mixed-child.sc"))

;; ---- the old tree, from history -----------------------------------------
(sh (string-append "git -C " repo " worktree remove --force " old-tree
                   " 2>/dev/null; rm -rf " old-tree))
(unless (zero? (sh (string-append
                     "git -C " repo " worktree add -q " old-tree " " old-rev
                     " 2>/dev/null")))
  (display "conv-mixed: SKIP -- cannot create a worktree of ")
  (display old-rev)
  (display "\n  (needs full git history; shallow clones and exports")
  (display " cannot run the mixed-version case)\n")
  (exit 0))
(sh (string-append "cd " old-tree " && ln -sfn . igropyr"))

(define port 19788)
(define secret "mixed-secret")

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (register 'mixed self)

    ;; node b: the OLD library, this tree's child script
    (sh (string-append
          "cd " old-tree " && CHEZSCHEMELIBDIRS=. "
          "CHEZSCHEMELIBEXTS=.chezscheme.sls::.no-obj:.ss::.no-obj:"
          ".sls::.no-obj:.scm::.no-obj:.sch::.no-obj:.sc::.no-obj "
          scheme-bin " --script " child " "
          (number->string port) " " secret " > /tmp/mixed-child.log 2>&1 &"))

    (monitor-node 'b)
    (receive (after 15000 (fail "old node never came up"))
      (`#(node-up b) 'ok))

    ;; ---- direction 1: new asker -> old owner ---------------------------
    (receive (after 15000 (fail "old owner never reported its conversation"))
      (`#(owned ,id ,token ,reply)
        (unless (equal? reply (vector 'ack 5))
          (fail "old owner's first reply is wrong" reply))
        ;; resume across the mesh: negative ref out, narrow reply back
        (let-values (((r1 t1) (conversation-resume! id token 10)))
          (unless (equal? r1 (vector 'ack 15))
            (fail "resume against the old owner went wrong" r1)))
        ;; peek: the narrow reply has no witness field; the current
        ;; matcher must take it and answer normally, not raise
        (let-values (((st tok last) (conversation-peek id)))
          (unless (eq? st 'parked)
            (fail "peek against the old owner did not see it parked" st))
          (display "  ok  new asker, old owner: resumed and peeked narrow\n")
          ;; finish it so the child's flow completes
          (let-values (((r2 s2) (conversation-resume! id tok 'done)))
            (unless (equal? r2 (vector 'final 15))
              (fail "the old owner's final answer is wrong" r2))
            (display "  ok  new asker, old owner: completed through the mesh\n")))))

    ;; ---- direction 2: old asker -> new owner ---------------------------
    (let-values (((id token reply)
                  (conversation-start!
                    (lambda (req suspend! commit!)
                      (let loop ((sum 0) (r req))
                        (if (eq? r 'done)
                            (begin (commit! (lambda () 'ok))
                                   (vector 'final sum))
                            (loop (+ sum r)
                                  (suspend! (vector 'ack (+ sum r)))))))
                    7)))
      (unless (equal? reply (vector 'ack 7))
        (fail "the new owner's first reply is wrong" reply))
      (rsend 'b 'ctrl (vector 'ask id token 3))
      (receive (after 15000 (fail "old asker never reported back"))
        (`#(asked ,r ,status)
          ;; the old library's resume answers (values reply next-token);
          ;; what must hold is that the resume LANDED here with a
          ;; positive ref and the narrow branch answered it
          (unless (equal? r (vector 'ack 10))
            (fail "old asker's resume did not land" r status))
          (display "  ok  old asker, new owner: positive ref, narrow branch\n")))
      ;; and the conversation here really advanced
      (let-values (((st tok last) (conversation-peek id)))
        (unless (and (eq? st 'parked) (equal? last (vector 'ack 10)))
          (fail "the new owner's state did not advance" st last))
        (display "  ok  old asker, new owner: the state advanced here\n")))

    (rsend 'b 'ctrl (vector 'quit))
    (sh (string-append "git -C " repo " worktree remove --force " old-tree
                       " 2>/dev/null; rm -rf " old-tree))
    (display "ALL CONV-MIXED TESTS PASSED\n")
    (exit 0)))
