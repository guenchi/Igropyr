#!chezscheme
;;; (igropyr conversation-status) -- the answers a conversation can give,
;;; and nothing else.
;;;
;;; SPLIT OUT SO THAT ASKING WHAT A STATUS MEANS COSTS NOTHING. The status
;;; vocabulary is six one-line predicates, but they used to live in
;;; (igropyr conversation), which imports the actor scheduler, libuv and
;;; the node layer -- and whose body runs work at LOAD time: it stamps a
;;; clock and reads /dev/urandom for this process's incarnation. A caller
;;; that only wants to classify a value it was handed -- an HTTP layer
;;; deciding a status code, a reconciliation script reading a log -- had
;;; to pull the whole runtime in to do it. `(only (igropyr conversation)
;;; conversation-gone?)` does not help: it narrows the names, not the
;;; loading.
;;;
;;; So this library imports (chezscheme) and NOTHING ELSE, and its body
;;; defines procedures and nothing else. That is not an incidental
;;; property to preserve by habit -- it is the entire reason the file
;;; exists, and an import added here silently takes it away.
;;;
;;; (igropyr conversation) re-exports every name below, so code that
;;; already imports it needs no change.
;;;
;;; The statuses themselves are documented where they are produced; what
;;; follows is what each one licenses a caller to DO, which is the part
;;; that gets read at a call site.

(library (igropyr conversation-status)
  (export conversation-gone? conversation-stale? conversation-done?
          conversation-settled? conversation-unknown?
          conversation-unreachable?)
  (import (chezscheme))

  ;; THE ROLLBACK GUARANTEE, and the only answer that is one. A record
  ;; says the flow rolled back: it raised, or its park deadline raised
  ;; into it and nothing caught that, and either way it left through its
  ;; winders before its commit! returned. This is what a caller may retry
  ;; on -- the only status that licenses retrying.
  ;;
  ;; Applied to the STATUS, never to the reply. A flow may return the
  ;; symbol 'gone as a perfectly ordinary answer; only the status carries
  ;; control meaning.
  (define (conversation-gone? x) (eq? x 'gone))

  ;; Neither confirmed. The conversation is not here and no record says
  ;; what became of it -- it was stopped in flight, killed from outside,
  ;; taken down by a link, or its record aged out, was pushed out by newer
  ;; ones, or belonged to an earlier incarnation of this process. DO NOT
  ;; RESUBMIT: that is the one action this answer cannot license.
  ;; Reconcile against your own state instead, which is the only place the
  ;; truth still is.
  ;;
  ;; THIS IS THE DEFAULT, and that is the change worth knowing about.
  ;; Everywhere this appears, 'gone was previously returned as though a
  ;; missing record were a rollback guarantee -- a positive claim read off
  ;; an absence, and wrong for every death path that writes no record.
  (define (conversation-unknown? x) (eq? x 'unknown))

  ;; No definite reply came back from the owner node: the send failed, the
  ;; link went down, or the forwarding wait expired. Only the first of
  ;; those even shows the request did not leave; a lost link or an expired
  ;; wait is equally consistent with the request having ARRIVED and the
  ;; owner still working on it. None of them proves the owner died, and
  ;; under a partition the conversation may still be running and may still
  ;; commit. Treat it exactly as 'unknown and reconcile; retrying is how a
  ;; partition turns into duplicated effects.
  ;;
  ;; This predicate exists because the status does. Five of the six were
  ;; exported and this one was not, which left every caller either writing
  ;; (eq? x 'unreachable) beside five predicate calls, or abandoning the
  ;; predicates entirely. An abstraction that covers all but one case is
  ;; worse than none, because the gap is invisible until someone hits it.
  (define (conversation-unreachable? x) (eq? x 'unreachable))

  ;; The flow returned: reply is its final answer, and no token continues
  ;; it. Distinguishing this from 'gone is what tells a caller whether the
  ;; transaction committed.
  (define (conversation-done? x) (eq? x 'done))

  ;; The flow finished, but its answer is no longer retained -- the linger
  ;; window closed and only the record of completion is left. For a
  ;; transactional flow this is the OPPOSITE of 'gone: it committed. Read
  ;; your own state for the details; do not resubmit.
  (define (conversation-settled? x) (eq? x 'settled))

  ;; The request named a reply that is no longer the one being answered --
  ;; a duplicate, a retry, a second front end. It was NOT applied and will
  ;; not be, which is a fact about this conversation rather than a guess.
  ;;
  ;; It says nothing about whether the request it duplicates succeeded: the
  ;; step it was trying to repeat may well have run for whoever got there
  ;; first. A caller that reaches here should read the current state, not
  ;; resubmit -- it has no valid token to resubmit with, which is the point.
  (define (conversation-stale? x) (eq? x 'stale))
)
