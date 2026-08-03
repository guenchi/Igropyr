#!chezscheme
;;; (igropyr blas) -- vector scoring at memory bandwidth: an optional
;;; CBLAS sgemv binding with a pure-Scheme fallback. One call fills
;;; scores[i] = row_i . query over a row-major float32 matrix -- the
;;; kernel of embedding search (RAG lookups, semantic dedup,
;;; recommendations).
;;;
;;;   (blas-scores! base n dim query scores)   ; total: BLAS or fallback
;;;     base:   flat float32 bytevector, row-major [n x dim]
;;;     query:  float32 bytevector [dim]
;;;     scores: float32 bytevector [n], overwritten
;;;   (blas-available?)   ; #t when a native BLAS backs the call
;;;   (blas-scores-pure! ...)  ; same contract, always the Scheme lane:
;;;     the reference to pin the native lane against, and reachable on a
;;;     host that has a BLAS (where blas-scores! would never run it)
;;;
;;; Loading is graceful by design (the tls.sc pattern): candidates are
;;; tried once at library init -- Accelerate on macOS, OpenBLAS/netlib
;;; on Linux and FreeBSD -- and a miss just means the pure loop, so
;;; correctness never depends on the native library. Callers with a
;;; fused scan of their own (inline filtering, early exit) can keep it
;;; behind blas-available? and use this only for the big-scan lane.
;;;
;;; Scheduling -- the constraint this binding is built around:
;;; an FFI call cannot be preempted, so one call stalls the calling
;;; scheduler for the scan's duration -- roughly 0.2 ms at 5k rows x
;;; 512 dims float32, ~5 ms at 100k (memory bandwidth). SPREAD those
;;; stalls: let every process scan its own replica inline, and the
;;; per-process stall duty cycle q*s/N stays negligible. Do NOT funnel
;;; searches into a few dedicated processes -- that adds a hop to
;;; every search and one saturating queue for nothing. If q*s/N ever
;;; climbs past a few percent, tile the call and yield between tiles,
;;; or offload it off the scheduler (the async-DNS threadpool
;;; pattern); when replicas outgrow memory, shard and scatter-gather.
;;; Spread out, never centralize.

(library (igropyr blas)
  (export blas-available? blas-scores! blas-scores-pure!)
  (import (chezscheme))

  (define candidates
    '(;; macOS: Accelerate bundles a full CBLAS
      "/System/Library/Frameworks/Accelerate.framework/Accelerate"
      ;; FreeBSD/Linux pkg names
      "libopenblas.so" "libopenblas.so.0"
      "libcblas.so" "libcblas.so.3" "libblas.so"))

  (define loaded?
    (let try ((l candidates))
      (cond ((null? l) #f)
            ((guard (e (#t #f)) (load-shared-object (car l)) #t) #t)
            (else (try (cdr l))))))

  ;; void cblas_sgemv(ORDER, TRANS, M, N, alpha, A, lda, X, incX, beta, Y, incY)
  (define sgemv
    (and loaded?
         (guard (e (#t #f))
           (foreign-procedure "cblas_sgemv"
             (int int int int float u8* int u8* int float u8* int)
             void))))

  (define cblas-row-major 101)
  (define cblas-no-trans 111)

  (define (blas-available?) (and sgemv #t))

  ;; The query is widened to f64 ONCE and scanned from a scratch buffer:
  ;; re-reading the f32 query inside the inner loop converts on every
  ;; multiply-add and measures ~35% slower, so the buffer earns its keep.
  ;;
  ;; flvector is the fastest backing for it but was added in Chez 10, and
  ;; it is the ONLY thing in this codebase that requires 10 -- a bytevector
  ;; of doubles is R6RS, behaves identically (bit-for-bit equal scores),
  ;; and costs ~14% on this lane. Rather than force that on everyone or
  ;; exclude older Chez outright, pick at expand time: meta-cond discards
  ;; the arm it does not take, so the flvector references never reach the
  ;; compiler where the type is absent. On Chez 10 this expands to exactly
  ;; the code it replaces.
  (meta-cond
    ((guard (e (#t #f)) (eval 'make-flvector (environment '(chezscheme))) #t)
     (define-syntax qbuf-make (syntax-rules () ((_ n) (make-flvector n))))
     (define-syntax qbuf-set! (syntax-rules () ((_ q j v) (flvector-set! q j v))))
     (define-syntax qbuf-ref (syntax-rules () ((_ q j) (flvector-ref q j)))))
    (else
     (define-syntax qbuf-make
       (syntax-rules () ((_ n) (make-bytevector (fx* n 8)))))
     (define-syntax qbuf-set!
       (syntax-rules () ((_ q j v) (bytevector-ieee-double-native-set! q (fx* j 8) v))))
     (define-syntax qbuf-ref
       (syntax-rules () ((_ q j) (bytevector-ieee-double-native-ref q (fx* j 8)))))))

  ;; the always-correct lane: same contract, double accumulation (the
  ;; native lane accumulates in f32 -- agreement within ~1e-4 for unit
  ;; vectors; pin with a tolerance when comparing). Exported because a
  ;; host with a BLAS would otherwise never execute it: it is the
  ;; correctness net under the native call, so it has to stay reachable
  ;; from a test on every host, not only on hosts that lack a BLAS.
  (define (scores-pure! base n dim query scores)
    (let ((q (qbuf-make dim)))
      (do ((j 0 (fx+ j 1))) ((fx= j dim))
        (qbuf-set! q j (bytevector-ieee-single-native-ref query (fx* j 4))))
      (do ((i 0 (fx+ i 1))) ((fx= i n))
        (let ((row (fx* i (fx* dim 4))))
          (let loop ((j 0) (acc 0.0))
            (if (fx= j dim)
                (bytevector-ieee-single-native-set! scores (fx* i 4) acc)
                (loop (fx+ j 1)
                      (fl+ acc (fl* (bytevector-ieee-single-native-ref
                                      base (fx+ row (fx* j 4)))
                                    (qbuf-ref q j))))))))))

  ;; Bounds are checked HERE, not left to the callee: the native call
  ;; reads raw pointers, so a short buffer would be a silent heap
  ;; overrun instead of a Scheme error.
  (define int32-max #x7fffffff)

  ;; Both entry points validate identically: the pure lane is exported, so
  ;; it must not be the lax door into the same buffers. `who' only names
  ;; the caller in the condition.
  (define (check-shapes! who base n dim query scores)
    ;; n and dim cross the FFI as C int (32-bit): a value above int32-max is
    ;; silently truncated by Chez, so the native call would read a DIFFERENT
    ;; shape than the buffer checks below validated -- reject here.
    (unless (and (fixnum? n) (fx>= n 0) (fx<= n int32-max)
                 (fixnum? dim) (fx>= dim 1) (fx<= dim int32-max))
      (assertion-violation who
        "want 0 <= n <= int32-max and 1 <= dim <= int32-max" (list n dim)))
    (unless (and (bytevector? base)
                 (>= (bytevector-length base) (* n dim 4)))
      (assertion-violation who "base shorter than n*dim float32s" base))
    (unless (and (bytevector? query)
                 (>= (bytevector-length query) (* dim 4)))
      (assertion-violation who "query shorter than dim float32s" query))
    (unless (and (bytevector? scores)
                 (>= (bytevector-length scores) (* n 4)))
      (assertion-violation who "scores shorter than n float32s" scores))
    ;; The output must not be one of the inputs. CBLAS sgemv gives no
    ;; guarantee about overlap between Y and X or A, so the native lane may
    ;; overwrite bytes it has yet to read -- undefined behaviour, and in
    ;; practice a silently wrong answer that depends on the BLAS build.
    ;;
    ;; It also means the two lanes would DISAGREE: the pure lane copies the
    ;; query first, so it produces one answer where the native lane produces
    ;; another, and a difference between lanes is the one thing this module
    ;; must never have. Rejecting is the honest contract -- an aliased call
    ;; has no defined result to return.
    (when (or (eq? scores query) (eq? scores base))
      (assertion-violation who
        "scores must not be the same bytevector as query or base (sgemv makes no guarantee about overlapping Y and X/A)"
        (if (eq? scores query) 'scores=query 'scores=base))))

  (define (blas-scores! base n dim query scores)
    (check-shapes! 'blas-scores! base n dim query scores)
    (if sgemv
        (sgemv cblas-row-major cblas-no-trans n dim 1.0 base dim query 1
               0.0 scores 1)
        (scores-pure! base n dim query scores)))

  ;; the pure lane on demand, whatever the host has: same contract, and on
  ;; a BLAS host the only way to reach this code at all.
  (define (blas-scores-pure! base n dim query scores)
    (check-shapes! 'blas-scores-pure! base n dim query scores)
    (scores-pure! base n dim query scores))
)
