;; Fine-grained reactivity: signals, effects, batching.
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (web reactive)
  (export signal signal-ref signal-set! signal-update!
          effect dispose-effect! root batch untracked)
  (import (rnrs))

  ;; a signal holds a value and the effects that read it;
  ;; an effect holds its thunk and the signals it read last run
  (define-record-type ($sig $make-sig $sig?)
    (fields (mutable v $sig-v $sig-v!)
            (mutable subs $sig-subs $sig-subs!)))
  (define-record-type ($eff $make-eff $eff?)
    (fields (mutable thunk $eff-thunk $eff-thunk!)
            (mutable deps $eff-deps $eff-deps!)
            (mutable live $eff-live $eff-live!)
            ;; effects created during this effect's run: they die with
            ;; it and are re-created fresh on every rerun
            (mutable kids $eff-kids $eff-kids!)))

  (define $current #f)                  ; the effect being (re)run
  (define $batch-depth 0)
  (define $queue '())                   ; effects awaiting a batch flush

  (define (signal init) ($make-sig init '()))

  (define (signal-ref s)
    ;; an owner made by `root` has no thunk: it collects kids for
    ;; disposal but never subscribes
    (when (and $current ($eff-thunk $current))
      (unless (memq $current ($sig-subs s))
        ($sig-subs! s (cons $current ($sig-subs s)))
        ($eff-deps! $current (cons s ($eff-deps $current)))))
    ($sig-v s))

  (define (signal-set! s v)
    (unless (eqv? v ($sig-v s))
      ($sig-v! s v)
      (let ((subs ($sig-subs s)))
        (if (< 0 $batch-depth)
            (for-each (lambda (e)
                        (unless (memq e $queue)
                          (set! $queue (cons e $queue))))
                      subs)
            (for-each $run-effect subs)))))
  (define (signal-update! s f)
    (signal-set! s (f (signal-ref s))))

  (define ($detach! e)
    (for-each (lambda (s) ($sig-subs! s (remq e ($sig-subs s))))
              ($eff-deps e))
    ($eff-deps! e '()))

  (define ($run-effect e)
    (when ($eff-live e)
      ($detach! e)
      (for-each dispose-effect! ($eff-kids e))
      ($eff-kids! e '())
      (let ((prev $current))
        (dynamic-wind
          (lambda () (set! $current e))
          ($eff-thunk e)
          (lambda () (set! $current prev))))))

  (define (effect thunk)
    (let ((e ($make-eff thunk '() #t '())))
      (when $current
        ($eff-kids! $current (cons e ($eff-kids $current))))
      ($run-effect e)
      e))
  (define (dispose-effect! e)
    ($eff-live! e #f)
    ($detach! e)
    (for-each dispose-effect! ($eff-kids e))
    ($eff-kids! e '()))

  ;; run thunk under a fresh detached owner: effects created inside
  ;; survive reruns of the enclosing effect and die only through the
  ;; returned disposer.  Yields (result . dispose).
  (define (root thunk)
    (let ((owner ($make-eff #f '() #t '()))
          (prev $current))
      (dynamic-wind
        (lambda () (set! $current owner))
        (lambda () (cons (thunk)
                         (lambda () (dispose-effect! owner))))
        (lambda () (set! $current prev)))))

  (define (batch thunk)
    (set! $batch-depth (+ $batch-depth 1))
    (let ((r (dynamic-wind
               (lambda () #f)
               thunk
               (lambda ()
                 (set! $batch-depth (- $batch-depth 1))
                 (when (zero? $batch-depth)
                   (let ((q (reverse $queue)))
                     (set! $queue '())
                     (for-each $run-effect q)))))))
      r))

  (define (untracked thunk)
    (let ((prev $current))
      (dynamic-wind
        (lambda () (set! $current #f))
        thunk
        (lambda () (set! $current prev))))))
