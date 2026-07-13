;; The Igropyr hero: a honeycomb that catches fire like a lit fuse —
;; and now throws embers.
;;
;; The hexagon lattice is a graph (site/hive-data.ss). Dijkstra from the
;; bottom-left vertex gives every point its "arrival distance"; a front
;; that grows with time ignites each point as it passes, so fire crawls
;; along every edge and meets in the middle — a burning fuse network.
;; Where the front burns, embers rise: a transform-feedback particle
;; system whose physics IS the vertex shader — each ember respawns at
;; its home point, pops upward, arcs over under gravity, and dies, and
;; only glows while the front is passing its home. Everything renders
;; through (web fx) over (web gl)'s command buffer: one bridge call per
;; frame, GPU-resident particle state, zero per-frame Scheme physics.
(import (rnrs) (web js) (web dom) (web gl) (web glsl) (web fx)
        (hive-data))

(define canvas (get-element-by-id "hive"))
(fx-init! canvas)

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

;; ---- sample each edge into the fuse point cloud ----
(define SP 2.6)
(define (edge-segs e)
  (let* ((a (vector-ref hive-ea e)) (b (vector-ref hive-eb e))
         (s (%fl->fx (fl/ (elen a b) SP))))
    (if (< s 2) 2 s)))
(define npoints                        ; count first, then allocate
  (let cnt ((e 0) (n 0))
    (if (= e Ecount) n (cnt (+ e 1) (+ n (edge-segs e) 1)))))
(define POS (fx-alloc! (* npoints 16)))  ; vec4 points (x,y,arrival,seed)

;; a tiny fixnum-safe LCG gives each point a stable flicker seed
(define lcg 12345)
(define (rnd)                          ; -> [0,1) flonum
  (set! lcg (remainder (+ (* lcg 1103) 12345) 32749))
  (fl/ (fixnum->flonum lcg) 32749.0))

(let ecut ((e 0) (n 0))
  (when (< e Ecount)
    (let* ((a (vector-ref hive-ea e)) (b (vector-ref hive-eb e))
           (xa (vx a)) (ya (vy a)) (xb (vx b)) (yb (vy b))
           (L (elen a b))
           (da (vector-ref dist a)) (db (vector-ref dist b))
           (segs (edge-segs e)))
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
              (put (+ i 1) (+ m 1))))))))

(define maxd
  (let mx ((i 0) (m 0.0))
    (if (= i V) m
        (let ((d (vector-ref dist i)))
          (mx (+ i 1) (if (and (fl<? d INF) (fl<? m d)) d m))))))

;; ---- the fuse: one translucent point cloud, as before ----
(define fuse-p
  (fx-program!
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
       (set! gl_PointSize sz)))
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

;; ---- the embers: GPU particles, physics in the vertex shader ----
;; state: pos2 vel2 home2 (arrival life seed) = 36 bytes each; every
;; ember lives on one fuse point and only glows while the front is
;; passing its home, so the sparks track the fire around the lattice
(define NEMBER 3000)

(define ember-update
  (fx-tf-program!
   '((attribute vec2 a_pos)
     (attribute vec2 a_vel)
     (attribute vec2 a_home)
     (attribute vec3 a_meta)            ; arrival, life, seed
     (uniform float u_dt)
     (uniform float u_time)
     (varying vec2 v_pos)
     (varying vec2 v_vel)
     (varying vec2 v_home)
     (varying vec3 v_meta)
     (define (main) void
       (local float life (- a_meta.y (* u_dt "0.9")))
       (local vec2 pos a_pos)
       (local vec2 vel a_vel)
       (local float seed a_meta.z)
       (if-else (< life (fl 0))
                ;; dead: respawn on the home point, kick upward
                ((local float s (fract (* (sin (* seed "127.1"))
                                          "43758.5453")))
                 (set! pos (+ a_home (vec2 (* (- s (fl 0 50)) (fl 7))
                                           (fl 0))))
                 (set! vel (vec2 (* (- (fract (* s "7.3")) (fl 0 50))
                                    "30.0")
                                 (- (+ "46.0" (* s "52.0")))))
                 (set! life (+ "0.6" (* (fract (* s "3.7")) "0.9")))
                 (set! seed (fract (+ seed "0.6180339"))))
                ;; alive: an arc -- the upward kick decays under
                ;; gravity, so sparks pop up a little and fall
                ((set! vel (+ a_vel
                              (vec2 (* (sin (+ (* u_time (fl 3))
                                               (* seed "40.0")))
                                       (* "16.0" u_dt))
                                    (* "150.0" u_dt))))
                 (set! vel (* vel (max (- (fl 1) (* (fl 0 30) u_dt))
                                       (fl 0))))
                 (set! pos (+ a_pos (* vel u_dt)))))
       (set! v_pos pos)
       (set! v_vel vel)
       (set! v_home a_home)
       (set! v_meta (vec3 a_meta.x life seed))
       (set! gl_Position (vec4 (fl 0) (fl 0) (fl 0) (fl 1)))))
   '((precision mediump float)
     (define (main) void
       (set! gl_FragColor (vec4 (fl 0) (fl 0) (fl 0) (fl 1)))))))

(define ember-draw
  (fx-program!
   '((attribute vec2 a_pos)
     (attribute vec2 a_vel)
     (attribute vec2 a_home)
     (attribute vec3 a_meta)
     (uniform float front)
     (varying float v_life)
     (varying float v_gate)
     (varying float v_seed)
     (define (main) void
       ;; glow only while the front is passing this ember's home
       (local float w (- front a_meta.x))
       (local float gate (* (step (fl 0) w)
                            (- (fl 1) (smoothstep "60.0" "200.0" w))))
       (local vec2 c (vec2 (- (* (/ a_pos.x (fl 1120)) (fl 2)) (fl 1))
                           (- (fl 1) (* (/ a_pos.y (fl 760)) (fl 2)))))
       (set! gl_Position (vec4 c (fl 0) (fl 1)))
       (set! gl_PointSize (+ (fl 1 20) (* a_meta.y (fl 2 60))))
       (set! v_life a_meta.y)
       (set! v_gate gate)
       (set! v_seed a_meta.z)))
   '((precision mediump float)
     (varying float v_life)
     (varying float v_gate)
     (varying float v_seed)
     (uniform float time)
     (define (main) void
       (if (< v_gate (fl 0 02)) (discard))
       (local vec2 d (- gl_PointCoord (vec2 (fl 0 50) (fl 0 50))))
       (local float r2 (dot d d))
       (if (> r2 (fl 0 25)) (discard))
       (local float soft (- (fl 1) (* r2 (fl 4))))
       (local float flick (+ (fl 0 70)
                             (* (fl 0 30)
                                (sin (+ (* time "27.0")
                                        (* v_seed "50.0"))))))
       ;; hot at birth, deep ember red at death
       (local vec3 c (mix (vec3 (fl 0 85) (fl 0 22) (fl 0 02))
                          (vec3 (fl 1) (fl 0 66) (fl 0 20))
                          (smoothstep (fl 0 20) (fl 1) v_life)))
       (set! gl_FragColor
             (vec4 (* c flick)
                   (* (* v_gate soft)
                      (smoothstep (fl 0) (fl 0 30) v_life))))))))

;; ---- ember state: seeded on random fuse points, staggered lives ----
(define EMB (fx-alloc! (* NEMBER 36)))
(let seedp ((i 0))
  (when (< i NEMBER)
    (let* ((p (%fl->fx (fl* (rnd) (fixnum->flonum npoints))))
           (src (+ POS (* p 16)))
           (o (+ EMB (* i 36))))
      (%mem-f32-set! o (%mem-f32-ref src))            ; pos = home
      (%mem-f32-set! (+ o 4) (%mem-f32-ref (+ src 4)))
      (%mem-f32-set! (+ o 8) 0.0)                     ; vel
      (%mem-f32-set! (+ o 12) 0.0)
      (%mem-f32-set! (+ o 16) (%mem-f32-ref src))     ; home
      (%mem-f32-set! (+ o 20) (%mem-f32-ref (+ src 4)))
      (%mem-f32-set! (+ o 24) (%mem-f32-ref (+ src 8))) ; arrival
      (%mem-f32-set! (+ o 28) (rnd))                  ; life (staggered)
      (%mem-f32-set! (+ o 32) (rnd)))                 ; seed
    (seedp (+ i 1))))

;; ---- buffers: the fuse once, the embers ping-ponging A <-> B ----
(define fuse-buf (fx-buffer!))
(define emb-a (fx-buffer!))
(define emb-b (fx-buffer!))
(cmd-begin!)
(cmd-bind-buffer! fuse-buf)
(cmd-buffer-data! POS (* npoints 16))
(cmd-bind-buffer! emb-a)
(cmd-buffer-data! EMB (* NEMBER 36))
(cmd-bind-buffer! emb-b)
(cmd-buffer-data! EMB (* NEMBER 36))
(cmd-flush!)

;; ---- the frame loop: fire front grows, wraps seamlessly ----
(define CYCLE 8.5)
(define TRAVEL (fl+ maxd 380.0))
(define bufs (cons emb-a emb-b))
(define tw 0.0)
(fx-loop!
 (lambda (t dt)
   (let ((dtc (if (fl<? dt 0.05) dt 0.05)))
     (set! tw (fl+ tw dtc))
     (when (fl<? CYCLE tw) (set! tw (fl- tw CYCLE)))
     (let ((front (fl* (fl/ tw CYCLE) TRAVEL)))
       ;; embers step on the GPU: front buffer in, back buffer out
       (fx-use! ember-update (car bufs))
       (fx-uniform! ember-update 'u_dt dtc)
       (fx-uniform! ember-update 'u_time tw)
       (cmd-tf-buffer! (cdr bufs))
       (cmd-tf-begin!)
       (cmd-draw-arrays! GL-POINTS 0 NEMBER)
       (cmd-tf-end!)
       ;; the lattice, then the sparks above it
       (cmd-blend! 'alpha)
       (cmd-clear! 0.0 0.0 0.0 0.0)
       (fx-use! fuse-p fuse-buf)
       (fx-uniform! fuse-p 'front front)
       (fx-uniform! fuse-p 'time tw)
       (cmd-draw-arrays! GL-POINTS 0 npoints)
       (fx-use! ember-draw (cdr bufs))
       (fx-uniform! ember-draw 'front front)
       (fx-uniform! ember-draw 'time tw)
       (cmd-draw-arrays! GL-POINTS 0 NEMBER)
       (set! bufs (cons (cdr bufs) (car bufs)))))))
