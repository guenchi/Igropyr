#!chezscheme
;;; Helper for test/conv-cluster.sc: the OWNER node <name> (b).
;;; Usage: scheme --script conv-cluster-child.sc <name> <port> <secret>
;;;
;;; Dials node 'a, waits for the link, then starts a conversation HERE
;;; (so this node owns its continuation) and ships the id + first reply
;;; back to node a. The flow accumulates each resumed number and answers
;;; #(ack sum); #(done) ends it with #(final sum). Node a resumes over
;;; the mesh, exercising the owner-forwarding path.

(import (chezscheme) (igropyr actor) (igropyr node) (igropyr conversation))

(define args (cdr (command-line)))
(define name (string->symbol (car args)))
(define port (string->number (cadr args)))
(define secret (caddr args))

(start-scheduler
  (lambda ()
    (node-start! name secret)
    (node-connect! 'a "127.0.0.1" port)
    (register 'ctrl self)
    ;; Safety net against a hung child. It is sized for the run node a
    ;; actually performs (about seven seconds), not for a formal worst
    ;; case: a's own waits nest, so no number here bounds them. Firing
    ;; it is never good news, and it is not always LEGIBLE news -- this
    ;; process exiting drops the link, and the last case is about a
    ;; dropped link, so a net that fired there would supply the very
    ;; event that case expects. That case asks separately whether the
    ;; drop was its own doing; this comment is here so the next person
    ;; to lengthen the suite knows why it does.
    ;; It can also be sent away. The last case node a runs is about a
    ;; dropped link, and this process exiting IS a dropped link, so while
    ;; this net is armed that case has two possible suppliers of the event
    ;; it is waiting for -- and the one it did not intend produces a green
    ;; run, not a red one. Node a stands it down and waits for the answer
    ;; before it cuts anything, after which only its own quit can drop the
    ;; link. What bounds this process after that is not a clock but node
    ;; a itself: the loop at the end exits on node-down. Node a's own
    ;; waits are all deadlined, so a failure is always REPORTED there --
    ;; but that answers who reports it, not who cleans up, and this
    ;; process is started in the background.
    (spawn (lambda ()
             (register 'net self)
             (receive (after 60000 (exit 1))
               (`#(stand-down ,to ,ref)
                 (rsend 'a to (vector 'net-down ref))))))

    (monitor-node 'a)
    (receive (after 10000 (exit 2)) (`#(node-up a) 'ok))

    ;; start the conversation in its own process; report id + first reply
    (spawn
      (lambda ()
        (call-with-values
          (lambda ()
            (conversation-start!
              (lambda (req suspend! commit!)
                (let loop ((sum 0) (r req))
                  (if (eq? r 'done)
                      (vector 'final sum)
                      (loop (+ sum r) (suspend! (vector 'ack (+ sum r)))))))
              0))
          ;; the token crosses the link with the id: a resume from another
          ;; node has to name the reply it is answering, exactly as a local
          ;; one does
          (lambda (id token first-reply)
            (rsend 'a 'main (vector 'conv-id id token first-reply))))))

    ;; A conversation whose commit THIS node witnessed, and which then
    ;; failed: the record here says committed-then-failed, and the whole
    ;; point of carrying the witness across the link is that node a's
    ;; lagging predicate cannot turn that into a retry.
    (let ((r (guard (e (#t e))
               (conversation-start!
                 (lambda (req suspend! commit!)
                   (commit! (lambda () 'tx))
                   (raise 'post-commit-cleanup-failure))
                 0))))
      ;; #(conversation-uncertain id outcome reason)
      (unless (and (vector? r) (eq? (vector-ref r 0) 'conversation-uncertain))
        (rsend 'a 'main (vector 'conv-witness-setup-failed r))
        (exit 3))
      (rsend 'a 'main (vector 'conv-witness (vector-ref r 1))))

    ;; ...and one whose commit is UNCERTAIN: the thunk signalled
    ;; commit-uncertain -- it did something that may already have taken
    ;; effect -- and the flow then died of it. The record here says
    ;; commit-uncertain-then-failed, which answers 'unknown but, unlike a
    ;; confirmed commit, does not outrank an authoritative #f.
    (let ((r (guard (e (#t e))
               (conversation-start!
                 (lambda (req suspend! commit!)
                   (commit! (lambda ()
                              (raise (vector 'commit-uncertain 'timed-out)))))
                 0))))
      (unless (and (vector? r) (eq? (vector-ref r 0) 'conversation-uncertain))
        (rsend 'a 'main (vector 'conv-uncertain-setup-failed r))
        (exit 4))
      (rsend 'a 'main (vector 'conv-uncertain (vector-ref r 1))))

    ;; A conversation that will be BUSY when the other node peeks at it:
    ;; its first step holds the floor for seconds, so a forwarded peek
    ;; parks in the waiting process rather than answering. That is the
    ;; state node a needs in order to kill an asker mid-wait.
    ;;
    ;; TWO THINGS ABOUT HOW IT IS DRIVEN, both there so that node a's
    ;; monitor counts have exactly one contributor -- the asker it is
    ;; testing. First, the resume is issued HERE rather than from node a:
    ;; a forwarded resume arms a monitor on node a and holds it for the
    ;; whole step, and then a rise in that count could be either the
    ;; resume or the asker, with only a sleep to tell them apart. A local
    ;; resume arms nothing there. Second, the step announces itself from
    ;; the inside, so "the conversation is busy" is a message sent by the
    ;; step rather than something node a infers from a table.
    (spawn
      (lambda ()
        (register 'drive-slow self)
        (call-with-values
          (lambda ()
            (conversation-start!
              (lambda (req suspend! commit!)
                (let ((a (suspend! (vector 'ready req))))
                  (rsend 'a 'main (vector 'busy 'slow))
                  (sleep-ms 8000)               ; holds the floor
                  (vector 'slow-done a)))
              0
              30000))
          (lambda (id token first-reply)
            (rsend 'a 'main (vector 'conv-slow id token))
            ;; ...and wait to be asked, for as long as it takes. Starting
            ;; the step here would make the announcement below a message
            ;; about the past: it would sit in node a's mailbox while the
            ;; step ran out, and a case reading it later would be testing
            ;; a conversation that had gone idle again. A deadline here
            ;; would put the coupling back in another form -- every case
            ;; before the one that drives this conversation would have to
            ;; fit inside it. The hung-child net above is what bounds this.
            (receive (`#(drive) 'ok))
            (conversation-resume! id token 1)))))

    ;; a second BUSY one. Node a needs a conversation it can still be
    ;; waiting on at the moment the link is cut: a peek only reaches the
    ;; branch that consults the peer list if it is already parked in the
    ;; forwarded receive when the drop happens, and it can only park
    ;; there while this node is too busy to answer. The step outlasts the
    ;; whole exchange on purpose -- this one is never meant to finish.
    (spawn
      (lambda ()
        (register 'drive-slow2 self)
        (call-with-values
          (lambda ()
            (conversation-start!
              (lambda (req suspend! commit!)
                (let ((a (suspend! (vector 'ready2 req))))
                  (rsend 'a 'main (vector 'busy 'slow2))
                  (sleep-ms 20000)
                  (vector 'done2 a)))
              0
              30000))
          (lambda (id token first-reply)
            (rsend 'a 'main (vector 'conv-slow2 id token))
            ;; ...and wait to be asked, for as long as it takes. Starting
            ;; the step here would make the announcement below a message
            ;; about the past: it would sit in node a's mailbox while the
            ;; step ran out, and a case reading it later would be testing
            ;; a conversation that had gone idle again. A deadline here
            ;; would put the coupling back in another form -- every case
            ;; before the one that drives this conversation would have to
            ;; fit inside it. The hung-child net above is what bounds this.
            (receive (`#(drive) 'ok))
            (conversation-resume! id token 1)))))

    ;; a third busy one: the stale-remote-down case needs its own, since
    ;; the reclaim case above kills its asker and leaves that one running
    (spawn
      (lambda ()
        (register 'drive-slow3 self)
        (call-with-values
          (lambda ()
            (conversation-start!
              (lambda (req suspend! commit!)
                (let ((a (suspend! (vector 'ready3 req))))
                  (rsend 'a 'main (vector 'busy 'slow3))
                  (sleep-ms 6000)
                  (vector 'done3 a)))
              0
              30000))
          (lambda (id token first-reply)
            (rsend 'a 'main (vector 'conv-slow3 id token))
            ;; ...and wait to be asked, for as long as it takes. Starting
            ;; the step here would make the announcement below a message
            ;; about the past: it would sit in node a's mailbox while the
            ;; step ran out, and a case reading it later would be testing
            ;; a conversation that had gone idle again. A deadline here
            ;; would put the coupling back in another form -- every case
            ;; before the one that drives this conversation would have to
            ;; fit inside it. The hung-child net above is what bounds this.
            (receive (`#(drive) 'ok))
            (conversation-resume! id token 1)))))

    ;; Node a cannot see this node's tables, and some of what it needs to
    ;; know is only visible here: a monitor armed on this node's router is
    ;; hosted HERE, so "the watcher's frame actually crossed the link" and
    ;; "the hosted side was released too" are both facts of this process.
    (let loop ()
      (receive
        (`#(quit) (exit 0))
        (`#(stats ,to ,ref)
          (rsend 'a to (vector 'stats ref (node-monitor-stats)))
          (loop))
        ;; POLICY, and it is a choice rather than a deduction: for this
        ;; suite a link that goes is the end of the run. The message says
        ;; the link was removed, NOT that node a's process died -- the
        ;; connector would redial every few seconds -- but both nodes here
        ;; are local, started together, and done in about seven seconds,
        ;; and every case reasons about link state, so a run that lost the
        ;; link has either finished (the last case cuts it deliberately)
        ;; or already gone wrong. Reconnecting would resume serving a run
        ;; whose results are void.
        ;;
        ;; This is what bounds this process once its net has stood down:
        ;; lifetime tied to the peer it exists to serve rather than to a
        ;; guessed number of seconds. Unlike the net it cannot hand the
        ;; last case the ending that case is looking for: that case cuts
        ;; the OWNER's link and waits for its own peek to answer, while
        ;; nothing here runs until a's link has gone from this side. (The
        ;; message is
        ;; a record of a removal, not a statement about now: with a
        ;; redial in between, this exit could cut a link that had just
        ;; come back. Under the policy above such a run is void anyway.)
        ;;
        ;; What this costs is stated rather than hidden: with the child
        ;; ending at the first drop, nothing here covers what happens
        ;; AFTER a reconnect -- whether the connector redials, and
        ;; whether an id still answers peek or resume once it has. That
        ;; is a gap in this suite, not a property of the library.
        ;;
        ;; Until this clause existed the message fell
        ;; into the catch-all below and was discarded, and a run that
        ;; failed after the net stood down left this process alive for
        ;; good, holding the suite's output and ready to answer the NEXT
        ;; run's node a with stale state.
        (`#(node-down a) (exit 0))
        ;; Deliberate: a test helper should not die of an unexpected
        ;; message. Everything fatal is named above.
        (,_ (loop))))))
