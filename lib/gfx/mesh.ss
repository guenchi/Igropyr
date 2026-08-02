;; Parametric meshes for raw-GL scenes: positions, normals, indices,
;; generated in pure Scheme -- what a framework's geometry classes
;; give you (box, sphere, torus...), without the framework.
;;
;;   (define m (mesh-torus 1.5 0.5))
;;   (define vbase (fx-alloc! (mesh-vertex-bytes m)))
;;   (define ibase (fx-alloc! (mesh-index-bytes m)))
;;   (mesh-write! m vbase ibase)
;;   ... per frame:
;;   (cmd-buffer-data! vbase (mesh-vertex-bytes m))
;;   (cmd-index-data! ibase (mesh-index-bytes m))
;;   (cmd-draw-elements! GL-TRIANGLES (mesh-index-count m))
;;
;; A mesh holds interleaved (x y z nx ny nz) flonums -- 24 bytes per
;; vertex, matching mesh-lit-vs's a_pos/a_normal layout -- and u16
;; indices (so at most 65536 vertices; every generator here is far
;; below).  Generation is pure and verifies headlessly; mesh-write!
;; lays the data into the staging memory for (gfx gl).
;;
;; mesh-lit-vs / mesh-lit-fs are ready-made glsl forms for one
;; directional light plus an ambient floor: uniforms u_mvp, u_model
;; (rotations/translations/uniform scale only -- normals go through
;; it with w=0), u_light (unit vector TOWARD the light), u_color,
;; u_ambient.  Compose or replace them freely; they are just data.
;;
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (gfx mesh)
  (export mesh? mesh-verts mesh-indices mesh-uvs
          mesh-optimize! mesh-remap! mesh-acmr
          mesh-vert-count mesh-index-count
          mesh-vertex-bytes mesh-index-bytes mesh-index-u32? mesh-write!
          mesh-vertex-bytes-f16 mesh-write-f16!
          mesh-vertex-bytes-uv mesh-write-uv!
          mesh-tangents mesh-vertex-bytes-tan mesh-write-tan!
          mesh-bounds
          mesh-plane mesh-box mesh-sphere mesh-cylinder mesh-torus
          mesh-heightmap
          mesh-lit-vs mesh-lit-fs mesh-tex-vs mesh-tex-fs
          mesh-normal-vs mesh-normal-fs mesh-pbr-vs mesh-pbr-fs)
  (import (rnrs) (gfx mat))

  (define $mesh-pi 3.141592653589793)
  (define $mesh-2pi 6.283185307179586)
  (define ($mesh-fl v) (if (flonum? v) v (exact->inexact v)))

  (define-record-type (mesh $make-mesh mesh?)
    (fields (immutable verts mesh-verts)      ; interleaved x y z nx ny nz
            (immutable indices mesh-indices)
            (immutable uvs mesh-uvs)))        ; u v per vertex, in [0,1]

  (define (mesh-vert-count m) (quotient (vector-length (mesh-verts m)) 6))
  (define (mesh-index-count m) (vector-length (mesh-indices m)))
  (define (mesh-vertex-bytes m) (* 4 (vector-length (mesh-verts m))))
  (define (mesh-vertex-bytes-uv m) (* 32 (mesh-vert-count m)))
  ;; meshes past 65536 vertices index as u32 (webgl2); the writers
  ;; switch layout automatically -- callers ask mesh-index-u32? to
  ;; pick cmd-index-data32!/cmd-draw-elements32! over the u16 pair
  (define (mesh-index-u32? m) (> (mesh-vert-count m) 65536))
  (define (mesh-index-bytes m)
    (if (mesh-index-u32? m)
        (* 4 (mesh-index-count m))
        (* 4 (quotient (+ (mesh-index-count m) 1) 2))))

  ;; one vertex into the verts vector at slot v
  (define ($mesh-v! vs v x y z nx ny nz)
    (let ((b (* v 6)))
      (vector-set! vs b x)
      (vector-set! vs (+ b 1) y)
      (vector-set! vs (+ b 2) z)
      (vector-set! vs (+ b 3) nx)
      (vector-set! vs (+ b 4) ny)
      (vector-set! vs (+ b 5) nz)))

  (define ($mesh-uv! uvs v u vv)        ; one vertex's texture coords
    (vector-set! uvs (* v 2) u)
    (vector-set! uvs (+ (* v 2) 1) vv))

  ;; a quad (a b | a+1 b+1) as two triangles at index slot k
  (define ($mesh-quad! ix k a b)
    (vector-set! ix k a)
    (vector-set! ix (+ k 1) b)
    (vector-set! ix (+ k 2) (+ a 1))
    (vector-set! ix (+ k 3) (+ a 1))
    (vector-set! ix (+ k 4) b)
    (vector-set! ix (+ k 5) (+ b 1)))

  ;; ---- generators ----
  (define (mesh-plane w d)                    ; on xz, +y normal
    (let ((hw (fl/ ($mesh-fl w) 2.0))
          (hd (fl/ ($mesh-fl d) 2.0))
          (vs (make-vector 24 0.0)))
      ($mesh-v! vs 0 (fl- 0.0 hw) 0.0 (fl- 0.0 hd) 0.0 1.0 0.0)
      ($mesh-v! vs 1 (fl- 0.0 hw) 0.0 hd           0.0 1.0 0.0)
      ($mesh-v! vs 2 hw           0.0 hd           0.0 1.0 0.0)
      ($mesh-v! vs 3 hw           0.0 (fl- 0.0 hd) 0.0 1.0 0.0)
      ($make-mesh vs (vector 0 1 2 0 2 3)
                  (vector 0.0 0.0  0.0 1.0  1.0 1.0  1.0 0.0))))

  ;; a heightfield: nx x nz cells over w x d on xz, y = (f x z) at
  ;; every grid point.  Normals come from central differences of f
  ;; itself (not the mesh), uvs span [0,1] -- terrain from any pure
  ;; height function
  (define (mesh-heightmap w d nx nz f)
    (let* ((w ($mesh-fl w)) (d ($mesh-fl d))
           (cols (+ nx 1)) (rows (+ nz 1))
           (sx (fl/ w (fixnum->flonum nx)))
           (sz (fl/ d (fixnum->flonum nz)))
           (vs (make-vector (* cols rows 6) 0.0))
           (uvs (make-vector (* cols rows 2) 0.0))
           (ix (make-vector (* nx nz 6) 0)))

      ;; sample the function once per grid point (plus a border ring
      ;; for the gradients) -- Safari's WasmGC pays dearly for boxed
      ;; flonum churn, so every avoided call counts
      (let ((hg (make-vector (* (+ cols 2) (+ rows 2)) 0.0)))
        (let sample ((j -1))
          (when (<= j rows)
            (let ((z (fl- (fl* (fixnum->flonum j) sz) (fl/ d 2.0))))
              (let col ((i -1))
                (when (<= i cols)
                  (vector-set!
                   hg (+ (* (+ j 1) (+ cols 2)) (+ i 1))
                   ($mesh-fl (f (fl- (fl* (fixnum->flonum i) sx)
                                     (fl/ w 2.0))
                                z)))
                  (col (+ i 1)))))
            (sample (+ j 1))))
        (let row ((j 0))
          (when (< j rows)
            (let ((z (fl- (fl* (fixnum->flonum j) sz) (fl/ d 2.0)))
                  (hrow (* (+ j 1) (+ cols 2))))
              (let col ((i 0))
                (when (< i cols)
                  (let* ((x (fl- (fl* (fixnum->flonum i) sx)
                                 (fl/ w 2.0)))
                         (hat (+ hrow (+ i 1)))
                         (y (vector-ref hg hat))
                         (gx (fl/ (fl- (vector-ref hg (+ hat 1))
                                       (vector-ref hg (- hat 1)))
                                  (fl* 2.0 sx)))
                         (gz (fl/ (fl- (vector-ref hg (+ hat cols 2))
                                       (vector-ref hg (- hat (+ cols 2))))
                                  (fl* 2.0 sz)))
                         (len (flsqrt (fl+ (fl+ (fl* gx gx) 1.0)
                                           (fl* gz gz))))
                         (v (+ (* j cols) i)))
                    ($mesh-v! vs v x y z
                              (fl/ (fl- 0.0 gx) len)
                              (fl/ 1.0 len)
                              (fl/ (fl- 0.0 gz) len))
                    (vector-set! uvs (* v 2)
                                 (fl/ (fixnum->flonum i)
                                      (fixnum->flonum nx)))
                    (vector-set! uvs (+ (* v 2) 1)
                                 (fl/ (fixnum->flonum j)
                                      (fixnum->flonum nz))))
                  (col (+ i 1)))))
            (row (+ j 1)))))
      (let cell ((j 0))
        (when (< j nz)
          (let cc ((i 0))
            (when (< i nx)
              (let* ((a (+ (* j cols) i))
                     (b (+ a 1))
                     (c (+ a cols))
                     (e (+ c 1))
                     (at (* 6 (+ (* j nx) i))))
                (vector-set! ix at a)
                (vector-set! ix (+ at 1) c)
                (vector-set! ix (+ at 2) e)
                (vector-set! ix (+ at 3) a)
                (vector-set! ix (+ at 4) e)
                (vector-set! ix (+ at 5) b))
              (cc (+ i 1))))
          (cell (+ j 1))))
      ($make-mesh vs ix uvs)))

  ;; face table: normal then four corners, in unit coordinates
  (define $mesh-box-faces
    '(((1 0 0) (( 1 -1 -1) ( 1  1 -1) ( 1  1  1) ( 1 -1  1)))
      ((-1 0 0) ((-1 -1  1) (-1  1  1) (-1  1 -1) (-1 -1 -1)))
      ((0 1 0) ((-1  1 -1) (-1  1  1) ( 1  1  1) ( 1  1 -1)))
      ((0 -1 0) ((-1 -1  1) (-1 -1 -1) ( 1 -1 -1) ( 1 -1  1)))
      ((0 0 1) ((-1 -1  1) ( 1 -1  1) ( 1  1  1) (-1  1  1)))
      ((0 0 -1) (( 1 -1 -1) (-1 -1 -1) (-1  1 -1) ( 1  1 -1)))))

  (define (mesh-box w h d)
    (let ((hx (fl/ ($mesh-fl w) 2.0))
          (hy (fl/ ($mesh-fl h) 2.0))
          (hz (fl/ ($mesh-fl d) 2.0))
          (vs (make-vector 144 0.0))          ; 24 verts
          (uvs (make-vector 48 0.0))
          (ix (make-vector 36 0)))
      (let face ((fs $mesh-box-faces) (f 0))
        (unless (null? fs)
          (let* ((spec (car fs))
                 (n (car spec)))
            (let corner ((cs (cadr spec)) (v (* f 4)))
              (unless (null? cs)
                (let ((c (car cs))
                      (k (- v (* f 4))))      ; corner 0..3 -> a full tile
                  ($mesh-v! vs v
                            (fl* hx (fixnum->flonum (car c)))
                            (fl* hy (fixnum->flonum (cadr c)))
                            (fl* hz (fixnum->flonum (caddr c)))
                            (fixnum->flonum (car n))
                            (fixnum->flonum (cadr n))
                            (fixnum->flonum (caddr n)))
                  ($mesh-uv! uvs v
                             (if (< k 2) 0.0 1.0)
                             (if (or (= k 1) (= k 2)) 1.0 0.0)))
                (corner (cdr cs) (+ v 1))))
            (let ((b (* f 4)) (k (* f 6)))
              (vector-set! ix k b)
              (vector-set! ix (+ k 1) (+ b 1))
              (vector-set! ix (+ k 2) (+ b 2))
              (vector-set! ix (+ k 3) b)
              (vector-set! ix (+ k 4) (+ b 2))
              (vector-set! ix (+ k 5) (+ b 3))))
          (face (cdr fs) (+ f 1))))
      ($make-mesh vs ix uvs)))

  (define (mesh-sphere r . opt)               ; UV sphere from the +y pole
    (let* ((segs (if (null? opt) 24 (car opt)))
           (rings (if (or (null? opt) (null? (cdr opt))) 16 (cadr opt)))
           (r ($mesh-fl r))
           (cols (+ segs 1))
           (vs (make-vector (* (+ rings 1) cols 6) 0.0))
           (uvs (make-vector (* (+ rings 1) cols 2) 0.0))
           (ix (make-vector (* rings segs 6) 0)))
      (let ring ((i 0))
        (when (<= i rings)
          (let* ((phi (fl/ (fl* $mesh-pi (fixnum->flonum i))
                           (fixnum->flonum rings)))
                 (sp (flsin phi))
                 (cp (flcos phi)))
            (let seg ((j 0))
              (when (<= j segs)
                (let* ((th (fl/ (fl* $mesh-2pi (fixnum->flonum j))
                                (fixnum->flonum segs)))
                       (nx (fl* sp (flcos th)))
                       (nz (fl* sp (flsin th))))
                  ($mesh-v! vs (+ (* i cols) j)
                            (fl* r nx) (fl* r cp) (fl* r nz)
                            nx cp nz)
                  ($mesh-uv! uvs (+ (* i cols) j)
                             (fl/ (fixnum->flonum j) (fixnum->flonum segs))
                             (fl/ (fixnum->flonum i) (fixnum->flonum rings))))
                (seg (+ j 1)))))
          (ring (+ i 1))))
      (let quad ((i 0) (k 0))
        (when (< i rings)
          (let inner ((j 0) (k k))
            (if (= j segs)
                (quad (+ i 1) k)
                (begin
                  ($mesh-quad! ix k (+ (* i cols) j) (+ (* (+ i 1) cols) j))
                  (inner (+ j 1) (+ k 6)))))))
      ($make-mesh vs ix uvs)))

  (define (mesh-cylinder r h . opt)
    (let* ((segs (if (null? opt) 24 (car opt)))
           (r ($mesh-fl r))
           (hy (fl/ ($mesh-fl h) 2.0))
           (cols (+ segs 1))
           (topc (* 2 cols))                  ; cap centers and rings
           (botc (+ topc cols 1))
           (vs (make-vector (* (+ botc cols 1) 6) 0.0))
           (uvs (make-vector (* (+ botc cols 1) 2) 0.0))
           (ix (make-vector (* 12 segs) 0)))
      (let seg ((j 0))
        (when (<= j segs)
          (let* ((th (fl/ (fl* $mesh-2pi (fixnum->flonum j))
                          (fixnum->flonum segs)))
                 (c (flcos th)) (s (flsin th))
                 (x (fl* r c)) (z (fl* r s))
                 (u (fl/ (fixnum->flonum j) (fixnum->flonum segs)))
                 (cu (fl+ 0.5 (fl* 0.5 c)))   ; caps: the disc itself
                 (cv (fl+ 0.5 (fl* 0.5 s))))
            ($mesh-v! vs j x hy z c 0.0 s)                  ; side, top ring
            ($mesh-v! vs (+ cols j) x (fl- 0.0 hy) z c 0.0 s)
            ($mesh-v! vs (+ topc 1 j) x hy z 0.0 1.0 0.0)   ; cap rings
            ($mesh-v! vs (+ botc 1 j) x (fl- 0.0 hy) z 0.0 -1.0 0.0)
            ($mesh-uv! uvs j u 0.0)
            ($mesh-uv! uvs (+ cols j) u 1.0)
            ($mesh-uv! uvs (+ topc 1 j) cu cv)
            ($mesh-uv! uvs (+ botc 1 j) cu cv))
          (seg (+ j 1))))
      ($mesh-v! vs topc 0.0 hy 0.0 0.0 1.0 0.0)
      ($mesh-v! vs botc 0.0 (fl- 0.0 hy) 0.0 0.0 -1.0 0.0)
      ($mesh-uv! uvs topc 0.5 0.5)
      ($mesh-uv! uvs botc 0.5 0.5)
      (let idx ((j 0) (k 0))
        (when (< j segs)
          ($mesh-quad! ix k j (+ cols j))
          (vector-set! ix (+ k 6) topc)
          (vector-set! ix (+ k 7) (+ topc 1 j 1))
          (vector-set! ix (+ k 8) (+ topc 1 j))
          (vector-set! ix (+ k 9) botc)
          (vector-set! ix (+ k 10) (+ botc 1 j))
          (vector-set! ix (+ k 11) (+ botc 1 j 1))
          (idx (+ j 1) (+ k 12))))
      ($make-mesh vs ix uvs)))

  (define (mesh-torus big small . opt)        ; ring radius, tube radius
    (let* ((segs (if (null? opt) 32 (car opt)))         ; around the ring
           (rings (if (or (null? opt) (null? (cdr opt))) 16 (cadr opt)))
           (br ($mesh-fl big))
           (tr ($mesh-fl small))
           (cols (+ rings 1))
           (vs (make-vector (* (+ segs 1) cols 6) 0.0))
           (uvs (make-vector (* (+ segs 1) cols 2) 0.0))
           (ix (make-vector (* segs rings 6) 0)))
      (let seg ((i 0))
        (when (<= i segs)
          (let* ((th (fl/ (fl* $mesh-2pi (fixnum->flonum i))
                          (fixnum->flonum segs)))
                 (ct (flcos th)) (st (flsin th)))
            (let tube ((j 0))
              (when (<= j rings)
                (let* ((ph (fl/ (fl* $mesh-2pi (fixnum->flonum j))
                                (fixnum->flonum rings)))
                       (cp (flcos ph)) (sp (flsin ph))
                       (d (fl+ br (fl* tr cp))))
                  ($mesh-v! vs (+ (* i cols) j)
                            (fl* d ct) (fl* tr sp) (fl* d st)
                            (fl* cp ct) sp (fl* cp st))
                  ($mesh-uv! uvs (+ (* i cols) j)
                             (fl/ (fixnum->flonum i) (fixnum->flonum segs))
                             (fl/ (fixnum->flonum j) (fixnum->flonum rings))))
                (tube (+ j 1)))))
          (seg (+ i 1))))
      (let quad ((i 0) (k 0))
        (when (< i segs)
          (let inner ((j 0) (k k))
            (if (= j rings)
                (quad (+ i 1) k)
                (begin
                  ($mesh-quad! ix k (+ (* i cols) j) (+ (* (+ i 1) cols) j))
                  (inner (+ j 1) (+ k 6)))))))
      ($make-mesh vs ix uvs)))

  ;; ---- vertex cache optimization (Forsyth 2006) ----
  ;; Reorders the triangles in place so vertices revisit while still
  ;; warm in the GPU's post-transform cache: a simulated 32-entry
  ;; LRU scores each vertex (recently-used high, with a bonus for
  ;; the last three; low-valence vertices boosted so stragglers
  ;; don't strand), each unemitted triangle scores as its vertices'
  ;; sum, and the best triangle emits next -- searched among the
  ;; cache's own triangles, falling back to a global scan.  Pure
  ;; arithmetic; mesh-acmr measures the result headlessly
  (define $vc-size 32)

  (define ($vc-vscore pos active)
    (if (= active 0)
        -1.0
        (fl+ (cond
              ((< pos 0) 0.0)
              ((< pos 3) 0.75)
              (else
               (let ((p (fl- 1.0 (fl/ (fixnum->flonum (- pos 3))
                                      (fixnum->flonum (- $vc-size 3))))))
                 (fl* p (flsqrt p)))))
             (fl* 2.0 (fl/ 1.0 (flsqrt (fixnum->flonum active)))))))

  (define (mesh-optimize! m)
    (let* ((ix (mesh-indices m))
           (nt (quotient (vector-length ix) 3))
           (nv (mesh-vert-count m))
           (adj (make-vector nv '()))
           (active (make-vector nv 0))
           (cpos (make-vector nv -1))
           (vscore (make-vector nv 0.0))
           (tscore (make-vector nt 0.0))
           (emitted (make-vector nt #f))
           (cache (make-vector (+ $vc-size 3) -1))
           (out (make-vector (vector-length ix) 0)))
      ;; adjacency and valences
      (let build ((t 0))
        (when (< t nt)
          (let each ((k 0))
            (when (< k 3)
              (let ((v (vector-ref ix (+ (* t 3) k))))
                (vector-set! adj v (cons t (vector-ref adj v)))
                (vector-set! active v (+ 1 (vector-ref active v))))
              (each (+ k 1))))
          (build (+ t 1))))
      (let seed ((v 0))
        (when (< v nv)
          (vector-set! vscore v ($vc-vscore -1 (vector-ref active v)))
          (seed (+ v 1))))
      (let seedt ((t 0))
        (when (< t nt)
          (vector-set! tscore t
                       (fl+ (vector-ref vscore
                                        (vector-ref ix (* t 3)))
                            (fl+ (vector-ref
                                  vscore
                                  (vector-ref ix (+ (* t 3) 1)))
                                 (vector-ref
                                  vscore
                                  (vector-ref ix (+ (* t 3) 2))))))
          (seedt (+ t 1))))
      ;; emit nt triangles
      (let emit ((n 0))
        (when (< n nt)
          ;; the candidate: best triangle among the cache's verts,
          ;; else the best anywhere
          (let* ((best
                  (let scan-cache ((k 0) (bt -1) (bs -1000000000.0))
                    (if (= k (+ $vc-size 3))
                        (if (>= bt 0)
                            bt
                            (let scan-all ((t 0) (bt -1) (bs -1000000000.0))
                              (cond
                               ((= t nt) bt)
                               ((and (not (vector-ref emitted t))
                                     (fl<? bs (vector-ref tscore t)))
                                (scan-all (+ t 1) t
                                          (vector-ref tscore t)))
                               (else (scan-all (+ t 1) bt bs)))))
                        (let ((v (vector-ref cache k)))
                          (if (< v 0)
                              (scan-cache (+ k 1) bt bs)
                              (let tris ((ts (vector-ref adj v))
                                         (bt bt) (bs bs))
                                (if (null? ts)
                                    (scan-cache (+ k 1) bt bs)
                                    (let ((t (car ts)))
                                      (if (and (not (vector-ref
                                                     emitted t))
                                               (fl<? bs
                                                     (vector-ref
                                                      tscore t)))
                                          (tris (cdr ts) t
                                                (vector-ref tscore t))
                                          (tris (cdr ts) bt
                                                bs)))))))))))
            (vector-set! emitted best #t)
            (let ((a (vector-ref ix (* best 3)))
                  (b (vector-ref ix (+ (* best 3) 1)))
                  (c (vector-ref ix (+ (* best 3) 2))))
              (vector-set! out (* n 3) a)
              (vector-set! out (+ (* n 3) 1) b)
              (vector-set! out (+ (* n 3) 2) c)
              (vector-set! active a (- (vector-ref active a) 1))
              (vector-set! active b (- (vector-ref active b) 1))
              (vector-set! active c (- (vector-ref active c) 1))
              ;; LRU update: the triangle's verts move to the front
              (let ((old (make-vector (+ $vc-size 3) -1)))
                (let cp ((k 0))
                  (when (< k (+ $vc-size 3))
                    (vector-set! old k (vector-ref cache k))
                    (cp (+ k 1))))
                (vector-set! cache 0 a)
                (vector-set! cache 1 b)
                (vector-set! cache 2 c)
                (let fill ((k 0) (w 3))
                  (when (and (< k (+ $vc-size 3))
                             (< w (+ $vc-size 3)))
                    (let ((v (vector-ref old k)))
                      (if (or (< v 0) (= v a) (= v b) (= v c))
                          (fill (+ k 1) w)
                          (begin
                            (vector-set! cache w v)
                            (fill (+ k 1) (+ w 1)))))))
                ;; rescore everything in (or just out of) the cache,
                ;; and every unemitted triangle it touches
                (let pos ((k 0))
                  (when (< k (+ $vc-size 3))
                    (let ((v (vector-ref cache k)))
                      (when (>= v 0)
                        (vector-set! cpos v (if (< k $vc-size) k -1))
                        (vector-set!
                         vscore v
                         ($vc-vscore (if (< k $vc-size) k -1)
                                     (vector-ref active v)))))
                    (pos (+ k 1))))
                (let ret ((k 0))
                  (when (< k (+ $vc-size 3))
                    (let ((v (vector-ref cache k)))
                      (when (>= v 0)
                        (let tris ((ts (vector-ref adj v)))
                          (when (pair? ts)
                            (let ((t (car ts)))
                              (unless (vector-ref emitted t)
                                (vector-set!
                                 tscore t
                                 (fl+ (vector-ref
                                       vscore
                                       (vector-ref ix (* t 3)))
                                      (fl+ (vector-ref
                                            vscore
                                            (vector-ref
                                             ix (+ (* t 3) 1)))
                                           (vector-ref
                                            vscore
                                            (vector-ref
                                             ix (+ (* t 3) 2))))))))
                            (tris (cdr ts))))))
                    (ret (+ k 1)))))))
          (emit (+ n 1))))
      ;; the new order lands back in the mesh
      (let put ((i 0))
        (when (< i (vector-length ix))
          (vector-set! ix i (vector-ref out i))
          (put (+ i 1))))
      ;; then remap the vertices to first-use order, so the vertex
      ;; buffer is fetched front to back and the pre-transform cache
      ;; (a straight prefetch stream) never jumps backward -- the
      ;; second half of the classic optimization
      (mesh-remap! m)
      m))

  ;; reorder the vertex arrays so vertices appear in the order the
  ;; (already cache-optimized) indices first reference them; every
  ;; per-vertex stream moves together and the indices renumber
  (define (mesh-remap! m)
    (let* ((vs (mesh-verts m))
           (uvs (mesh-uvs m))
           (ix (mesh-indices m))
           (nv (mesh-vert-count m))
           (n (vector-length ix))
           (newidx (make-vector nv -1))    ; old vertex -> new slot
           (nvs (make-vector (vector-length vs) 0.0))
           (nuvs (and uvs (make-vector (vector-length uvs) 0.0))))
      (let scan ((i 0) (next 0))
        (if (= i n)
            #f
            (let ((v (vector-ref ix i)))
              (if (>= (vector-ref newidx v) 0)
                  (scan (+ i 1) next)
                  (begin
                    (vector-set! newidx v next)
                    ;; copy the six interleaved floats
                    (let cp ((k 0))
                      (when (< k 6)
                        (vector-set! nvs (+ (* next 6) k)
                                     (vector-ref vs (+ (* v 6) k)))
                        (cp (+ k 1))))
                    (when nuvs
                      (vector-set! nuvs (* next 2)
                                   (vector-ref uvs (* v 2)))
                      (vector-set! nuvs (+ (* next 2) 1)
                                   (vector-ref uvs (+ (* v 2) 1))))
                    (scan (+ i 1) (+ next 1)))))))
      ;; the arrays are records' immutable fields, so write in place
      (let put ((i 0))
        (when (< i (vector-length vs))
          (vector-set! vs i (vector-ref nvs i))
          (put (+ i 1))))
      (when uvs
        (let put ((i 0))
          (when (< i (vector-length uvs))
            (vector-set! uvs i (vector-ref nuvs i))
            (put (+ i 1)))))
      (let put ((i 0))
        (when (< i n)
          (vector-set! ix i (vector-ref newidx (vector-ref ix i)))
          (put (+ i 1))))
      m))

  ;; average cache miss ratio under a FIFO cache: misses per
  ;; triangle, the classic figure of merit (1.0 or so is unoptimized
  ;; soup, ~0.6 is good for a 32-entry cache)
  (define (mesh-acmr m size)
    (let* ((ix (mesh-indices m))
           (n (vector-length ix))
           (fifo (make-vector size -1)))
      (let walk ((i 0) (head 0) (misses 0))
        (if (= i n)
            (fl/ (fixnum->flonum misses)
                 (fixnum->flonum (quotient n 3)))
            (let* ((v (vector-ref ix i))
                   (hit (let look ((k 0))
                          (and (< k size)
                               (or (= (vector-ref fifo k) v)
                                   (look (+ k 1)))))))
              (if hit
                  (walk (+ i 1) head misses)
                  (begin
                    (vector-set! fifo head v)
                    (walk (+ i 1)
                          (remainder (+ head 1) size)
                          (+ misses 1)))))))))

  ;; ---- into the staging memory: f32 verts, u16 index pairs ----
  ;; each u16 lands as two byte stores: packing a pair into one i32
  ;; would push indices past 16383 out of fixnum (i31) range
  (define ($mesh-u16! at v)
    (%mem-u8-set! at (remainder v 256))
    (%mem-u8-set! (+ at 1) (quotient v 256)))
  (define ($mesh-u32! at v)
    ($mesh-u16! at (remainder v 65536))
    ($mesh-u16! (+ at 2) (quotient v 65536)))
  (define ($mesh-write-ix! m ibase)
    (let* ((ix (mesh-indices m))
           (n (vector-length ix)))
      (if (mesh-index-u32? m)
          (let loop ((i 0) (at ibase))
            (when (< i n)
              ($mesh-u32! at (vector-ref ix i))
              (loop (+ i 1) (+ at 4))))
          (let loop ((i 0) (at ibase))
            (when (< i n)
              ($mesh-u16! at (vector-ref ix i))
              ($mesh-u16! (+ at 2) (if (< (+ i 1) n)
                                       (vector-ref ix (+ i 1))
                                       0))
              (loop (+ i 2) (+ at 4)))))))

  (define (mesh-write! m vbase ibase)
    (let ((vs (mesh-verts m)))
      (let loop ((i 0) (at vbase))
        (when (< i (vector-length vs))
          (%mem-f32-set! at (vector-ref vs i))
          (loop (+ i 1) (+ at 4)))))
    ($mesh-write-ix! m ibase))

  ;; ---- half-precision: the same interleaved stream, two bytes a
  ;; component.  IEEE f16 from the f32 bit pattern (a value bounces
  ;; through 4 scratch bytes of staging to expose its bits), with
  ;; round-to-nearest and inf on overflow; vertex coordinates and
  ;; unit normals lose nothing a screen shows.  Pair the layout with
  ;; cmd-vertex-attrib-h! -- stride 12, positions at 0, normals at 6
  (define ($mesh-f16 v scratch)         ; flonum -> f16 bits (fixnum)
    (%mem-f32-set! scratch v)
    (let* ((b0 (%mem-u8-ref scratch))
           (b1 (%mem-u8-ref (+ scratch 1)))
           (b2 (%mem-u8-ref (+ scratch 2)))
           (b3 (%mem-u8-ref (+ scratch 3)))
           (sign (* (quotient b3 128) 32768))
           (exp (+ (* (remainder b3 128) 2) (quotient b2 128)))
           (man (+ (* (remainder b2 128) 65536) (* b1 256) b0))
           (e (- exp 112)))              ; 127 - 15
      (cond
       ((= exp 255) (+ sign 31744 (if (> man 0) 512 0))) ; inf / nan
       ((>= e 31) (+ sign 31744))                        ; overflow
       ((<= e 0)                                         ; subnormal
        (if (< e -10)
            sign
            (let* ((m (+ man 8388608))                   ; hidden bit
                   (sh (- 14 e))                         ; 14..24
                   (d (let pow ((k 0) (p 1))
                        (if (= k sh) p (pow (+ k 1) (* p 2)))))
                   (q (quotient m d))
                   (r (remainder m d)))
              (+ sign q (if (>= (* r 2) d) 1 0)))))
       (else
        (let ((q (quotient man 8192))                    ; man >> 13
              (r (remainder man 8192)))
          (+ sign (* e 1024) q (if (>= r 4096) 1 0)))))))

  (define (mesh-write-f16! m vbase ibase scratch)
    (let ((vs (mesh-verts m)))
      (let loop ((i 0) (at vbase))
        (when (< i (vector-length vs))
          ($mesh-u16! at ($mesh-f16 (vector-ref vs i) scratch))
          (loop (+ i 1) (+ at 2)))))
    ($mesh-write-ix! m ibase))
  (define (mesh-vertex-bytes-f16 m) (* 12 (mesh-vert-count m)))

  ;; interleaved x y z nx ny nz u v -- 32 bytes per vertex, matching
  ;; mesh-tex-vs's a_pos/a_normal/a_uv layout
  (define (mesh-write-uv! m vbase ibase)
    (let ((vs (mesh-verts m))
          (uvs (mesh-uvs m))
          (n (mesh-vert-count m)))
      (let loop ((v 0) (at vbase))
        (when (< v n)
          (let ((b (* v 6)) (ub (* v 2)))
            (%mem-f32-set! at (vector-ref vs b))
            (%mem-f32-set! (+ at 4) (vector-ref vs (+ b 1)))
            (%mem-f32-set! (+ at 8) (vector-ref vs (+ b 2)))
            (%mem-f32-set! (+ at 12) (vector-ref vs (+ b 3)))
            (%mem-f32-set! (+ at 16) (vector-ref vs (+ b 4)))
            (%mem-f32-set! (+ at 20) (vector-ref vs (+ b 5)))
            (%mem-f32-set! (+ at 24) (vector-ref uvs ub))
            (%mem-f32-set! (+ at 28) (vector-ref uvs (+ ub 1))))
          (loop (+ v 1) (+ at 32)))))
    ($mesh-write-ix! m ibase))

  ;; the bounding sphere, for frustum culls: AABB center, then the
  ;; farthest vertex from it.  Pair with (gfx mat)'s
  ;; m4-frustum-planes / sphere-in-frustum? -- remember to transform
  ;; the center by the model matrix and scale the radius
  (define ($mesh-min a b) (if (fl<? a b) a b))
  (define ($mesh-max a b) (if (fl<? a b) b a))
  (define (mesh-bounds m)               ; (center . radius)
    (let* ((vs (mesh-verts m)) (n (mesh-vert-count m)))
      (let scan ((v 1)
                 (lx (vector-ref vs 0)) (hx (vector-ref vs 0))
                 (ly (vector-ref vs 1)) (hy (vector-ref vs 1))
                 (lz (vector-ref vs 2)) (hz (vector-ref vs 2)))
        (if (< v n)
            (let ((x (vector-ref vs (* v 6)))
                  (y (vector-ref vs (+ (* v 6) 1)))
                  (z (vector-ref vs (+ (* v 6) 2))))
              (scan (+ v 1)
                    ($mesh-min lx x) ($mesh-max hx x)
                    ($mesh-min ly y) ($mesh-max hy y)
                    ($mesh-min lz z) ($mesh-max hz z)))
            (let ((c (v3 (fl* 0.5 (fl+ lx hx))
                         (fl* 0.5 (fl+ ly hy))
                         (fl* 0.5 (fl+ lz hz)))))
              (let far ((v 0) (r2 0.0))
                (if (< v n)
                    (let* ((d (v3-sub ($mesh-p3 vs v 0) c))
                           (q (v3-dot d d)))
                      (far (+ v 1) (if (fl<? r2 q) q r2)))
                    (cons c (flsqrt r2)))))))))

  ;; ---- tangents, for normal mapping ----
  ;; per-triangle tangent/bitangent from the uv gradients (Lengyel),
  ;; accumulated per vertex, then Gram-Schmidt orthogonalized against
  ;; the normal.  w is the handedness: the shader rebuilds the
  ;; bitangent as cross(n, t) * w.
  (define ($mesh-p3 vs i off)           ; vec3 at `off` within vertex i
    (vector (vector-ref vs (+ (* i 6) off))
            (vector-ref vs (+ (* i 6) off 1))
            (vector-ref vs (+ (* i 6) off 2))))
  (define ($mesh-acc! acc i v)
    (let ((b (* i 3)))
      (vector-set! acc b (fl+ (vector-ref acc b) (v3-x v)))
      (vector-set! acc (+ b 1) (fl+ (vector-ref acc (+ b 1)) (v3-y v)))
      (vector-set! acc (+ b 2) (fl+ (vector-ref acc (+ b 2)) (v3-z v)))))
  (define ($mesh-get3 acc i)
    (vector (vector-ref acc (* i 3))
            (vector-ref acc (+ (* i 3) 1))
            (vector-ref acc (+ (* i 3) 2))))
  (define ($mesh-tiny? x) (and (fl<? x 0.00000001) (fl<? -0.00000001 x)))

  (define (mesh-tangents m)             ; (tx ty tz w) per vertex
    (let* ((vs (mesh-verts m)) (uvs (mesh-uvs m)) (ix (mesh-indices m))
           (n (mesh-vert-count m))
           (tan (make-vector (* n 3) 0.0))
           (bit (make-vector (* n 3) 0.0))
           (out (make-vector (* n 4) 0.0)))
      (let tri ((k 0))
        (when (< k (vector-length ix))
          (let* ((i0 (vector-ref ix k))
                 (i1 (vector-ref ix (+ k 1)))
                 (i2 (vector-ref ix (+ k 2)))
                 (e1 (v3-sub ($mesh-p3 vs i1 0) ($mesh-p3 vs i0 0)))
                 (e2 (v3-sub ($mesh-p3 vs i2 0) ($mesh-p3 vs i0 0)))
                 (du1 (fl- (vector-ref uvs (* i1 2))
                           (vector-ref uvs (* i0 2))))
                 (dv1 (fl- (vector-ref uvs (+ (* i1 2) 1))
                           (vector-ref uvs (+ (* i0 2) 1))))
                 (du2 (fl- (vector-ref uvs (* i2 2))
                           (vector-ref uvs (* i0 2))))
                 (dv2 (fl- (vector-ref uvs (+ (* i2 2) 1))
                           (vector-ref uvs (+ (* i0 2) 1))))
                 (d (fl- (fl* du1 dv2) (fl* du2 dv1))))
            (unless ($mesh-tiny? d)     ; a uv-degenerate triangle
              (let* ((r (fl/ 1.0 d))
                     (tv (v3-scale (v3-sub (v3-scale e1 dv2)
                                           (v3-scale e2 dv1)) r))
                     (bv (v3-scale (v3-sub (v3-scale e2 du1)
                                           (v3-scale e1 du2)) r)))
                ($mesh-acc! tan i0 tv) ($mesh-acc! tan i1 tv)
                ($mesh-acc! tan i2 tv)
                ($mesh-acc! bit i0 bv) ($mesh-acc! bit i1 bv)
                ($mesh-acc! bit i2 bv))))
          (tri (+ k 3))))
      (let each ((v 0))
        (when (< v n)
          (let* ((nv ($mesh-p3 vs v 3))
                 (raw ($mesh-get3 tan v))
                 (ortho (v3-sub raw (v3-scale nv (v3-dot nv raw))))
                 (t (if ($mesh-tiny? (v3-dot ortho ortho))
                        ;; no uv gradient reached this vertex: any
                        ;; unit vector perpendicular to the normal
                        (v3-normalize
                         (v3-cross nv
                                   (if (fl<? (fl* (v3-y nv) (v3-y nv))
                                             0.81)
                                       (v3 0.0 1.0 0.0)
                                       (v3 1.0 0.0 0.0))))
                        (v3-normalize ortho)))
                 (w (if (fl<? (v3-dot (v3-cross nv t) ($mesh-get3 bit v))
                              0.0)
                        -1.0 1.0))
                 (b (* v 4)))
            (vector-set! out b (v3-x t))
            (vector-set! out (+ b 1) (v3-y t))
            (vector-set! out (+ b 2) (v3-z t))
            (vector-set! out (+ b 3) w))
          (each (+ v 1))))
      out))

  ;; interleaved x y z nx ny nz u v tx ty tz w -- 48 bytes per
  ;; vertex, matching mesh-normal-vs's layout
  (define (mesh-vertex-bytes-tan m) (* 48 (mesh-vert-count m)))
  (define (mesh-write-tan! m vbase ibase)
    (let ((vs (mesh-verts m)) (uvs (mesh-uvs m))
          (tans (mesh-tangents m)) (n (mesh-vert-count m)))
      (let loop ((v 0) (at vbase))
        (when (< v n)
          (let ((b (* v 6)) (ub (* v 2)) (tb (* v 4)))
            (%mem-f32-set! at (vector-ref vs b))
            (%mem-f32-set! (+ at 4) (vector-ref vs (+ b 1)))
            (%mem-f32-set! (+ at 8) (vector-ref vs (+ b 2)))
            (%mem-f32-set! (+ at 12) (vector-ref vs (+ b 3)))
            (%mem-f32-set! (+ at 16) (vector-ref vs (+ b 4)))
            (%mem-f32-set! (+ at 20) (vector-ref vs (+ b 5)))
            (%mem-f32-set! (+ at 24) (vector-ref uvs ub))
            (%mem-f32-set! (+ at 28) (vector-ref uvs (+ ub 1)))
            (%mem-f32-set! (+ at 32) (vector-ref tans tb))
            (%mem-f32-set! (+ at 36) (vector-ref tans (+ tb 1)))
            (%mem-f32-set! (+ at 40) (vector-ref tans (+ tb 2)))
            (%mem-f32-set! (+ at 44) (vector-ref tans (+ tb 3))))
          (loop (+ v 1) (+ at 48)))))
    ($mesh-write-ix! m ibase))

  ;; ---- the standard lit program, as composable glsl forms ----
  (define mesh-lit-vs
    '((attribute vec3 a_pos)
      (attribute vec3 a_normal)
      (uniform mat4 u_mvp)
      (uniform mat4 u_model)
      (varying vec3 v_normal)
      (define (main) void
        (set! gl_Position (* u_mvp (vec4 a_pos (fl 1))))
        (set! v_normal (vec3 (* u_model (vec4 a_normal (fl 0))))))))

  ;; colors come in as sRGB, light in linear, encode back out --
  ;; the pow pair all the shipped fragment shaders share
  (define mesh-lit-fs
    '((precision mediump float)
      (uniform vec3 u_light)                  ; unit vector toward the light
      (uniform vec4 u_color)
      (uniform float u_ambient)
      (varying vec3 v_normal)
      (define (main) void
        (local vec3 n (normalize v_normal))
        (local float d (max (dot n u_light) (fl 0)))
        (local vec3 base (pow u_color.rgb (vec3 "2.2" "2.2" "2.2")))
        (local vec3 c (* base (+ u_ambient (* d (- (fl 1) u_ambient)))))
        (set! gl_FragColor
              (vec4 (pow c (vec3 "0.4545" "0.4545" "0.4545"))
                    u_color.a)))))

  ;; the same light over a texture: sample * u_color tint, then the
  ;; ambient/diffuse factor.  Pair with mesh-write-uv! (stride 32).
  (define mesh-tex-vs
    '((attribute vec3 a_pos)
      (attribute vec3 a_normal)
      (attribute vec2 a_uv)
      (uniform mat4 u_mvp)
      (uniform mat4 u_model)
      (varying vec3 v_normal)
      (varying vec2 v_uv)
      (define (main) void
        (set! gl_Position (* u_mvp (vec4 a_pos (fl 1))))
        (set! v_normal (vec3 (* u_model (vec4 a_normal (fl 0)))))
        (set! v_uv a_uv))))
  (define mesh-tex-fs
    '((precision mediump float)
      (uniform vec3 u_light)
      (uniform vec4 u_color)
      (uniform float u_ambient)
      (uniform sampler2D u_tex)
      (varying vec3 v_normal)
      (varying vec2 v_uv)
      (define (main) void
        (local vec3 n (normalize v_normal))
        (local float d (max (dot n u_light) (fl 0)))
        (local vec4 t (* (texture2D u_tex v_uv) u_color))
        (local vec3 base (pow t.rgb (vec3 "2.2" "2.2" "2.2")))
        (local vec3 c (* base (+ u_ambient (* d (- (fl 1) u_ambient)))))
        (set! gl_FragColor
              (vec4 (pow c (vec3 "0.4545" "0.4545" "0.4545"))
                    t.a)))))

  ;; the tangent-space normal-mapped variant of the lit program:
  ;; pairs with mesh-write-tan!'s 48-byte layout.  u_model must be
  ;; rotation/translation/uniform scale, as with mesh-lit-vs.
  (define mesh-normal-vs
    '((attribute vec3 a_pos)
      (attribute vec3 a_normal)
      (attribute vec2 a_uv)
      (attribute vec4 a_tangent)
      (uniform mat4 u_mvp)
      (uniform mat4 u_model)
      (varying vec2 v_uv)
      (varying vec3 v_t)
      (varying vec3 v_b)
      (varying vec3 v_n)
      (define (main) void
        (set! gl_Position (* u_mvp (vec4 a_pos (fl 1))))
        (set! v_uv a_uv)
        (set! v_n (vec3 (* u_model (vec4 a_normal (fl 0)))))
        (set! v_t (vec3 (* u_model (vec4 a_tangent.xyz (fl 0)))))
        (set! v_b (* (cross v_n v_t) a_tangent.w)))))
  (define mesh-normal-fs
    '((precision mediump float)
      (uniform sampler2D u_nmap)        ; rgb = tangent-space normal
      (uniform vec3 u_light)
      (uniform vec4 u_color)
      (uniform float u_ambient)
      (varying vec2 v_uv)
      (varying vec3 v_t)
      (varying vec3 v_b)
      (varying vec3 v_n)
      (define (main) void
        (local vec4 s (texture2D u_nmap v_uv))
        (local vec3 tn (- (* s.rgb (fl 2)) (vec3 (fl 1) (fl 1) (fl 1))))
        (local vec3 n (normalize (+ (+ (* v_t tn.x) (* v_b tn.y))
                                    (* v_n tn.z))))
        (local float d (max (dot n u_light) (fl 0)))
        (local vec3 base (pow u_color.rgb (vec3 "2.2" "2.2" "2.2")))
        (local vec3 c (* base (+ u_ambient (* d (- (fl 1) u_ambient)))))
        (set! gl_FragColor
              (vec4 (pow c (vec3 "0.4545" "0.4545" "0.4545"))
                    u_color.a)))))

  ;; ---- PBR: Cook-Torrance GGX with a real light probe ----
  ;; One directional light plus split-sum image-based ambient: u_sky
  ;; is a cube map prefiltered by (gfx ibl)'s ibl-prefilter! (its mip
  ;; chain holds GGX convolutions, u_mips = levels - 1) and u_lut is
  ;; ibl-brdf-lut!'s scale/bias table.  Pair with mesh-write! (stride
  ;; 24); gltf's gprim-metallic/gprim-roughness feed the factor
  ;; uniforms directly.  Reinhard tonemap + gamma on the way out.
  (define mesh-pbr-vs
    '((attribute vec3 a_pos)
      (attribute vec3 a_normal)
      (uniform mat4 u_mvp)
      (uniform mat4 u_model)
      (varying vec3 v_n)
      (varying vec3 v_wp)
      (define (main) void
        (set! gl_Position (* u_mvp (vec4 a_pos (fl 1))))
        (set! v_wp (vec3 (* u_model (vec4 a_pos (fl 1)))))
        (set! v_n (vec3 (* u_model (vec4 a_normal (fl 0))))))))

  (define mesh-pbr-fs
    '((precision mediump float)
      (uniform vec3 u_light)              ; unit vector toward the light
      (uniform vec3 u_eye)
      (uniform vec4 u_albedo)             ; sRGB in, like u_color
      (uniform float u_metallic)
      (uniform float u_roughness)
      (uniform samplerCube u_sky)
      (uniform sampler2D u_lut)
      (uniform float u_mips)
      (varying vec3 v_n)
      (varying vec3 v_wp)
      (define (main) void
        (local vec3 n (normalize v_n))
        (local vec3 v (normalize (- u_eye v_wp)))
        (local vec3 h (normalize (+ v u_light)))
        (local float ndl (max (dot n u_light) (fl 0)))
        (local float ndv (max (dot n v) "0.001"))
        (local float ndh (max (dot n h) (fl 0)))
        (local float hdv (max (dot h v) (fl 0)))
        (local vec3 albedo (pow u_albedo.rgb (vec3 "2.2" "2.2" "2.2")))
        (local vec3 f0 (mix (vec3 "0.04" "0.04" "0.04")
                            albedo u_metallic))
        ;; GGX distribution
        (local float a (* u_roughness u_roughness))
        (local float a2 (* a a))
        (local float dd (+ (* (* ndh ndh) (- a2 (fl 1))) (fl 1)))
        (local float D (/ a2 (* "3.14159265" (* dd dd))))
        ;; Smith-Schlick visibility
        (local float k (/ (* (+ u_roughness (fl 1))
                             (+ u_roughness (fl 1))) (fl 8)))
        (local float G (* (/ ndl (+ (* ndl (- (fl 1) k)) k))
                          (/ ndv (+ (* ndv (- (fl 1) k)) k))))
        ;; Fresnel-Schlick
        (local vec3 one (vec3 (fl 1) (fl 1) (fl 1)))
        (local vec3 F (+ f0 (* (- one f0) (pow (- (fl 1) hdv) (fl 5)))))
        (local vec3 spec (/ (* (* D G) F)
                            (+ (* (fl 4) (* ndl ndv)) "0.001")))
        (local vec3 kd (* (- one F) (- (fl 1) u_metallic)))
        (local vec3 direct (* (+ (* kd (/ albedo "3.14159265")) spec)
                              (* ndl (fl 3))))
        ;; split-sum ambient: the prefiltered mip chain picks the
        ;; blur by roughness, the LUT folds in the BRDF integral
        (local vec4 irr4 (textureCube u_sky n u_mips))
        (local vec3 irr (pow irr4.rgb (vec3 "2.2" "2.2" "2.2")))
        (local vec3 r (reflect (- v) n))
        (local vec4 pre4 (textureCube u_sky r (* u_roughness u_mips)))
        (local vec3 pre (pow pre4.rgb (vec3 "2.2" "2.2" "2.2")))
        (local vec4 ab (texture2D u_lut (vec2 ndv u_roughness)))
        (local vec3 c (+ direct
                         (+ (* (* kd albedo) irr)
                            (* pre (+ (* f0 ab.r)
                                      (vec3 ab.g ab.g ab.g))))))
        (set! c (/ c (+ c one)))          ; Reinhard
        (set! gl_FragColor
              (vec4 (pow c (vec3 "0.4545" "0.4545" "0.4545"))
                    u_albedo.a))))))
