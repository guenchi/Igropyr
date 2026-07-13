;; The Igropyr hero: a honeycomb that catches fire like a lit fuse —
;; and now throws embers.
;;
;; The hexagon lattice is a graph (site/hive-data.ss). Dijkstra from the
;; bottom-left vertex gives every point its "arrival distance"; a front
;; that grows with time ignites each point as it passes, so fire crawls
;; along every edge and meets in the middle — and the web only exists
;; where the fire has drawn it: unburned lattice is invisible, burned
;; edges remain as solid lines, and the ashes dissolve before the wrap.
;; Where the front burns, embers rise: a transform-feedback particle
;; system whose physics IS the vertex shader — each ember respawns at
;; its home point, pops upward, arcs over under gravity, and dies, and
;; only glows while the front is passing its home. The burn renders
;; into an HDR (half-float) target where the tip runs past white; a
;; threshold + separable blur turns the excess into a radiant halo,
;; composited onto the transparent canvas. Everything renders through
;; (web fx) over (web gl)'s command buffer: one bridge call per frame,
;; GPU-resident particle state, zero per-frame Scheme physics.
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
(define SP 1.2)
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
     (uniform float fade)               ; ashes dissolve before the wrap
     (define (main) void
       ;; ahead of the front the web does not exist yet: the fire
       ;; draws it into being
       (if (< v_heat (fl 0)) (discard))
       (local vec2 d (- gl_PointCoord (vec2 (fl 0 50) (fl 0 50))))
       (local float r2 (dot d d))
       (if (> r2 (fl 0 25)) (discard))
       (local float soft (- (fl 1) (* r2 (fl 4))))
       (local vec3 base (vec3 (fl 0 91) (fl 0 51) (fl 0 36)))
       (local float flick (+ (fl 0 80) (* (fl 0 20) (sin (+ (* time (fl 22)) (* v_seed (fl 40)))))))
       (local float t (clamp (/ v_heat (fl 320)) (fl 0) (fl 1)))
       (local vec3 c (mix (vec3 (fl 1) (fl 0 93) (fl 0 62))
                          (vec3 (fl 1) (fl 0 42) (fl 0 2))
                          (smoothstep (fl 0) (fl 0 10) t)))
       (set! c (mix c (vec3 (fl 0 95) (fl 0 26) (fl 0 2)) (smoothstep (fl 0 10) (fl 0 35) t)))
       (set! c (mix c base (smoothstep (fl 0 35) (fl 1) t)))
       (local float av (* (mix (fl 1) (fl 0 22) (smoothstep (fl 0 05) (fl 1) t))
                          fade))
       ;; the tip burns past white: HDR headroom the bloom pass finds
       (local float hot (+ (fl 1) (* "2.2" (exp (- (/ (* v_heat v_heat)
                                                      "60.0"))))))
       (set! gl_FragColor (vec4 (* (* c flick) hot) (* av soft)))))))

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
             (vec4 (* (* c flick)
                      (+ (fl 1) (* "1.4" (smoothstep (fl 0 60) (fl 1)
                                                     v_life))))
                   (* (* v_gate soft)
                      (smoothstep (fl 0) (fl 0 30) v_life))))))))

;; ---- HDR bloom: the scene renders past white into a half-float
;; target; a threshold keeps what burns, a separable blur spreads it,
;; and the composite lays fire plus halo onto the transparent canvas
(define scene-t (fx-target-hdr! 1120 760))
(define glow-a (fx-target! 560 380))
(define glow-b (fx-target! 560 380))

(define bright-q
  (fx-fullscreen!
   '((precision mediump float)
     (uniform sampler2D u_scene)
     (uniform vec2 u_texel)
     (define (main) void
       (local vec2 uv (* gl_FragCoord.xy u_texel))
       (local vec4 c (texture2D u_scene uv))
       (local float l (dot c.rgb (vec3 "0.2126" "0.7152" "0.0722")))
       (set! gl_FragColor
             (vec4 (* c.rgb (* c.a (smoothstep "1.0" "2.2" l)))
                   (fl 1)))))))

(define blur-q
  (fx-fullscreen!
   '((precision mediump float)
     (uniform sampler2D u_src)
     (uniform vec2 u_texel)
     (uniform vec2 u_dir)
     (define (tap (vec2 uv) (float o) (float w)) vec3
       (local vec4 c (texture2D u_src (+ uv (* (* u_dir u_texel) o))))
       (return (* c.rgb w)))
     (define (main) void
       (local vec2 uv (* gl_FragCoord.xy u_texel))
       (local vec3 acc (tap uv (fl 0) "0.227027"))
       (set! acc (+ acc (tap uv (fl 1) "0.1945946")))
       (set! acc (+ acc (tap uv (- (fl 1)) "0.1945946")))
       (set! acc (+ acc (tap uv (fl 2) "0.1216216")))
       (set! acc (+ acc (tap uv (- (fl 2)) "0.1216216")))
       (set! acc (+ acc (tap uv (fl 3) "0.054054")))
       (set! acc (+ acc (tap uv (- (fl 3)) "0.054054")))
       (set! acc (+ acc (tap uv (fl 4) "0.016216")))
       (set! acc (+ acc (tap uv (- (fl 4)) "0.016216")))
       (set! gl_FragColor (vec4 acc (fl 1)))))))

(define comp-q
  (fx-fullscreen!
   '((precision mediump float)
     (uniform sampler2D u_scene)
     (uniform sampler2D u_glow)
     (uniform vec2 u_texel)
     (define (main) void
       (local vec2 uv (* gl_FragCoord.xy u_texel))
       (local vec4 c (texture2D u_scene uv))
       (local vec4 g (texture2D u_glow uv))
       (local vec3 sum (+ c.rgb (* g.rgb "1.15")))
       ;; hue-preserving clamp: colors at or below 1 pass untouched,
       ;; the HDR core normalizes down -- its excess lives in the halo
       (local float mx (max (max sum.r sum.g) sum.b))
       (set! sum (/ sum (max mx (fl 1))))
       (local float ga (dot g.rgb (vec3 "0.5" "0.35" "0.15")))
       (set! gl_FragColor
             (vec4 sum (clamp (+ c.a (* ga "0.9"))
                              (fl 0) (fl 1))))))))

(define (glow-pass! q tgt tex setup)
  (if tgt (fx-bind-target! tgt) (fx-bind-canvas!))
  (fx-fullscreen-use! q 0.0)
  (cmd-bind-texture! 0 tex)
  (setup (fx-quad-program q))
  (fx-fullscreen-draw! q))

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
     ;; the front advances a fixed step per frame, exactly like the
     ;; original fire -- the burn pace is the one you remember; only
     ;; the ember physics runs on real dt
     (set! tw (fl+ tw 0.016))
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
       ;; the lattice and sparks burn into the HDR target
       (cmd-unbind-texture! 0)
       (cmd-unbind-texture! 1)
       (fx-bind-target! scene-t)
       (cmd-blend! 'alpha)
       (cmd-clear! 0.0 0.0 0.0 0.0)
       (fx-use! fuse-p fuse-buf)
       (fx-uniform! fuse-p 'front front)
       (fx-uniform! fuse-p 'time tw)
       ;; the overshoot tail (past every arrival) dissolves the ashes,
       ;; so the wrap lands on darkness and the next fuse lights clean
       (fx-uniform! fuse-p 'fade
                    (let ((f (fl- 1.0 (fl/ (fl- front (fl+ maxd 60.0))
                                           300.0))))
                      (if (fl<? f 0.0) 0.0 (if (fl<? 1.0 f) 1.0 f))))
       (cmd-draw-arrays! GL-POINTS 0 npoints)
       (fx-use! ember-draw (cdr bufs))
       (fx-uniform! ember-draw 'front front)
       (fx-uniform! ember-draw 'time tw)
       (cmd-draw-arrays! GL-POINTS 0 NEMBER)
       ;; what burns past white becomes a halo
       (cmd-blend! 'off)
       (glow-pass! bright-q glow-a (fx-target-texture scene-t)
                   (lambda (p)
                     (fx-uniform! p 'u_scene 0)
                     (fx-uniform! p 'u_texel
                                  (fl/ 1.0 560.0) (fl/ 1.0 380.0))))
       (glow-pass! blur-q glow-b (fx-target-texture glow-a)
                   (lambda (p)
                     (fx-uniform! p 'u_src 0)
                     (fx-uniform! p 'u_dir 1.0 0.0)
                     (fx-uniform! p 'u_texel
                                  (fl/ 1.0 560.0) (fl/ 1.0 380.0))))
       (glow-pass! blur-q glow-a (fx-target-texture glow-b)
                   (lambda (p)
                     (fx-uniform! p 'u_src 0)
                     (fx-uniform! p 'u_dir 0.0 1.0)
                     (fx-uniform! p 'u_texel
                                  (fl/ 1.0 560.0) (fl/ 1.0 380.0))))
       (glow-pass! comp-q #f (fx-target-texture scene-t)
                   (lambda (p)
                     (cmd-bind-texture! 1 (fx-target-texture glow-a))
                     (fx-uniform! p 'u_scene 0)
                     (fx-uniform! p 'u_glow 1)
                     (fx-uniform! p 'u_texel
                                  (fl/ 1.0 1120.0) (fl/ 1.0 760.0))))
       (set! bufs (cons (cdr bufs) (car bufs)))))))
