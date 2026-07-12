;; The Igropyr hero: a honeycomb that catches fire like a lit fuse.
;;
;; The hexagon lattice is a graph (site/hive-data.ss). Dijkstra from the
;; bottom-left vertex gives every point its "arrival distance"; a front
;; that grows with time ignites each point as it passes, so fire crawls
;; along every edge and meets in the middle — a burning fuse network.
;; Rendered as one translucent point cloud through (web gl)'s command
;; buffer: the whole frame is one bridge call. Compiled to fire.wasm.
(import (rnrs) (web js) (web dom) (web gl) (web glsl) (hive-data))

;; ---- staging-memory layout ----
(define POS 8192)                      ; vec4 points (x,y,arrival,seed)
(%mem-grow 4)                          ; room for ~9k points (16 B each)

;; ---- the graph ----
(define V (vector-length hive-vx))
(define Ecount (vector-length hive-ea))
(define (vx i) (vector-ref hive-vx i))
(define (vy i) (vector-ref hive-vy i))
(define (elen a b)
  (let ((dx (fl- (vx a) (vx b))) (dy (fl- (vy a) (vy b))))
    (flsqrt (fl+ (fl* dx dx) (fl* dy dy)))))

;; adjacency as parallel vectors of lists: neighbor id and edge length
(define adj-n (make-vector V '()))
(define adj-l (make-vector V '()))
(let loop ((e 0))
  (when (< e Ecount)
    (let* ((a (vector-ref hive-ea e)) (b (vector-ref hive-eb e)) (L (elen a b)))
      (vector-set! adj-n a (cons b (vector-ref adj-n a)))
      (vector-set! adj-l a (cons L (vector-ref adj-l a)))
      (vector-set! adj-n b (cons a (vector-ref adj-n b)))
      (vector-set! adj-l b (cons L (vector-ref adj-l b))))
    (loop (+ e 1))))

;; ---- Dijkstra, O(V^2) ----
(define INF 1000000000.0)
(define dist (make-vector V INF))
(define done (make-vector V #f))
(vector-set! dist hive-seed 0.0)
(let steps ((k 0))
  (when (< k V)
    ;; pick the nearest not-yet-finalized vertex
    (let pick ((i 0) (best -1) (bd INF))
      (if (= i V)
          (when (>= best 0)
            (vector-set! done best #t)
            (let relax ((ns (vector-ref adj-n best)) (ls (vector-ref adj-l best)))
              (when (pair? ns)
                (let ((w (car ns)) (nd (fl+ (vector-ref dist best) (car ls))))
                  (when (fl<? nd (vector-ref dist w))
                    (vector-set! dist w nd))
                  (relax (cdr ns) (cdr ls))))))
          (if (and (not (vector-ref done i)) (fl<? (vector-ref dist i) bd))
              (pick (+ i 1) i (vector-ref dist i))
              (pick (+ i 1) best bd))))
    (steps (+ k 1))))

;; ---- sample each edge into the point cloud ----
;; a tiny fixnum-safe LCG gives each point a stable flicker seed
(define lcg 12345)
(define (rnd)                          ; -> [0,1) flonum
  (set! lcg (remainder (+ (* lcg 1103) 12345) 32749))
  (fl/ (fixnum->flonum lcg) 32749.0))

(define SP 2.6)
(define npoints
  (let ecut ((e 0) (n 0))
    (if (= e Ecount)
        n
        (let* ((a (vector-ref hive-ea e)) (b (vector-ref hive-eb e))
               (xa (vx a)) (ya (vy a)) (xb (vx b)) (yb (vy b))
               (L (elen a b))
               (da (vector-ref dist a)) (db (vector-ref dist b))
               (segs (let ((s (%fl->fx (fl/ L SP)))) (if (< s 2) 2 s))))
          (let put ((i 0) (m n))
            (if (> i segs)
                (ecut (+ e 1) m)
                (let* ((s (fl/ (fixnum->flonum i) (fixnum->flonum segs)))
                       (x (fl+ xa (fl* (fl- xb xa) s)))
                       (y (fl+ ya (fl* (fl- yb ya) s)))
                       (arr-a (fl+ da (fl* s L)))
                       (arr-b (fl+ db (fl* (fl- 1.0 s) L)))
                       (arr (if (fl<? arr-a arr-b) arr-a arr-b))
                       (o (+ POS (* m 16))))
                  (%mem-f32-set! o x)
                  (%mem-f32-set! (+ o 4) y)
                  (%mem-f32-set! (+ o 8) arr)
                  (%mem-f32-set! (+ o 12) (rnd))
                  (put (+ i 1) (+ m 1)))))))))

(define maxd
  (let mx ((i 0) (m 0.0))
    (if (= i V) m
        (let ((d (vector-ref dist i)))
          (mx (+ i 1) (if (and (fl<? d INF) (fl<? m d)) d m))))))

;; ---- shaders as s-expressions (web glsl) ----
(define vs
  (glsl->string
   '((attribute vec4 a)                ; x, y, arrival, seed (packed)
     (uniform float front)
     (varying float v_heat)
     (varying float v_seed)
     (define (main) void
       (local float heat (- front a.z))
       (set! v_heat heat)
       (set! v_seed a.w)
       ;; viewBox 1120x760 baked in (constant, no uniform)
       (local vec2 c (vec2 (- (* (/ a.x (fl 1120)) (fl 2)) (fl 1))
                           (- (fl 1) (* (/ a.y (fl 760)) (fl 2)))))
       (set! gl_Position (vec4 c (fl 0) (fl 1)))
       (local float sz (fl 2 40))
       (if (>= heat (fl 0))
           (local float tip (exp (- (/ (* heat heat) (fl 50)))))
           (local float glow (exp (- (/ (* heat heat) (fl 1250)))))
           (set! sz (+ (fl 2 40) (* (fl 8) tip) (* (fl 4) glow))))
       (set! gl_PointSize sz)))))

(define fs
  (glsl->string
   '((precision mediump float)
     (varying float v_heat)
     (varying float v_seed)
     (uniform float time)
     (define (main) void
       (local vec2 d (- gl_PointCoord (vec2 (fl 0 50) (fl 0 50))))
       (local float r2 (dot d d))
       (if (> r2 (fl 0 25)) (discard))
       (local float soft (- (fl 1) (* r2 (fl 4))))
       (local vec3 base (vec3 (fl 0 91) (fl 0 51) (fl 0 36)))
       (if (< v_heat (fl 0))
           (set! gl_FragColor (vec4 base (* (fl 0 28) soft)))
           (return))
       (local float flick (+ (fl 0 80) (* (fl 0 20) (sin (+ (* time (fl 22)) (* v_seed (fl 40)))))))
       (local float t (clamp (/ v_heat (fl 320)) (fl 0) (fl 1)))
       (local vec3 c (mix (vec3 (fl 1) (fl 0 93) (fl 0 62))
                          (vec3 (fl 1) (fl 0 42) (fl 0 2))
                          (smoothstep (fl 0) (fl 0 10) t)))
       (set! c (mix c (vec3 (fl 0 95) (fl 0 26) (fl 0 2)) (smoothstep (fl 0 10) (fl 0 35) t)))
       (set! c (mix c base (smoothstep (fl 0 35) (fl 1) t)))
       (local float av (mix (fl 1) (fl 0 28) (smoothstep (fl 0 05) (fl 1) t)))
       (set! gl_FragColor (vec4 (* c flick) (* av soft)))))))

;; ---- gl setup: one program, one buffer, upload once ----
(define canvas (get-element-by-id "hive"))
(gl-attach! canvas)
(gl-program! 0 vs fs)
(gl-buffer! 1)
(gl-uniform! 2 0 "front")
(gl-uniform! 3 0 "time")
(cmd-region! 0)

(cmd-begin!)
(cmd-bind-buffer! 1)
(cmd-buffer-data! POS (* npoints 16))
(cmd-vertex-attrib! 0 4 0 0)           ; single vec4 attribute
(cmd-flush!)

;; ---- the frame loop: fire front grows, wraps seamlessly ----
(define CYCLE 8.5)
(define TRAVEL (fl+ maxd 380.0))
(define t 0.0)
(define (frame!)
  (set! t (fl+ t 0.016))
  (when (fl<? CYCLE t) (set! t (fl- t CYCLE)))
  (let ((front (fl* (fl/ t CYCLE) TRAVEL)))
    (cmd-begin!)
    (cmd-viewport! 0 0 (%fl->fx hive-vb-w) (%fl->fx hive-vb-h))
    (cmd-blend! 'alpha)
    (cmd-clear! 0.0 0.0 0.0 0.0)
    (cmd-use-program! 0)
    (cmd-uniform1f! 2 front)
    (cmd-uniform1f! 3 t)
    (cmd-draw-arrays! GL-POINTS 0 npoints)
    (cmd-flush!)))

(js-eval "globalThis.__fire_gen = (globalThis.__fire_gen || 0) + 1")
(define gen (js->number (js-get (js-global) "__fire_gen")))
(letrec ((tick (lambda _
                 (when (= gen (js->number (js-get (js-global) "__fire_gen")))
                   (frame!)
                   (js-method (js-global) "requestAnimationFrame" tick)))))
  (js-method (js-global) "requestAnimationFrame" tick))
