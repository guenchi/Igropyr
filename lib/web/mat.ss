;; 3D math for raw-GL scenes: vec3 and column-major mat4 over plain
;; flonum vectors.  Pure -- no host, verifies headlessly -- and the
;; trig is our own (range-reduced polynomials in flonum arithmetic),
;; so both compiler hosts emit identical bytes, the same reasoning
;; that computes IEEE bits for flonum literals in pure Scheme.
;;
;;   (define proj (m4-perspective 0.9 (/ 800.0 600.0) 0.1 100.0))
;;   (define view (m4-look-at (v3 0 0 6) (v3 0 0 0) (v3 0 1 0)))
;;   (fx-uniform! p 'u_mvp (m4-mul proj (m4-mul view (m4-rotate-y t))))
;;
;; A mat4 is a 16-element vector, column-major (what uniformMatrix4fv
;; expects; fx-uniform!'s mat4 case feeds it through the command
;; buffer).  Constructors coerce their arguments; the operations
;; assume flonums -- they are the per-frame hot path.
;;
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (web mat)
  (export flsin flcos fltan
          v3 v3-x v3-y v3-z
          v3-add v3-sub v3-scale v3-dot v3-cross v3-normalize
          m4-identity m4-mul m4-scratch! m4-transform
          m4-translate m4-scale m4-rotate-x m4-rotate-y m4-rotate-z
          m4-from-quat m4-perspective m4-ortho m4-look-at
          m4-inverse m4-unproject
          m4-frustum-planes sphere-in-frustum?)
  (import (rnrs))

  (define ($mat-fl v) (if (flonum? v) v (exact->inexact v)))

  ;; ---- trig: reduce to [-pi/2, pi/2], one odd polynomial ----
  (define $mat-pi 3.141592653589793)
  (define $mat-2pi 6.283185307179586)
  (define $mat-pi/2 1.5707963267948966)

  (define ($mat-sin-poly x)             ; |x| <= pi/2, error < 1e-9
    (let ((x2 (fl* x x)))
      (fl* x
           (fl- 1.0 (fl* (fl/ x2 6.0)
                (fl- 1.0 (fl* (fl/ x2 20.0)
                     (fl- 1.0 (fl* (fl/ x2 42.0)
                          (fl- 1.0 (fl* (fl/ x2 72.0)
                               (fl- 1.0 (fl* (fl/ x2 110.0)
                                    (fl- 1.0 (fl* (fl/ x2 156.0)
                                         (fl- 1.0 (fl/ x2 210.0)))))))))))))))))

  (define (flsin x)
    (let* ((k (flfloor (fl+ (fl/ x $mat-2pi) 0.5)))
           (r (fl- x (fl* k $mat-2pi))))    ; r in [-pi, pi]
      ($mat-sin-poly
       (cond ((fl<? $mat-pi/2 r) (fl- $mat-pi r))
             ((fl<? r (fl- 0.0 $mat-pi/2)) (fl- (fl- 0.0 $mat-pi) r))
             (else r)))))
  (define (flcos x) (flsin (fl+ x $mat-pi/2)))
  (define (fltan x) (fl/ (flsin x) (flcos x)))

  ;; ---- vec3 ----
  (define (v3 x y z) (vector ($mat-fl x) ($mat-fl y) ($mat-fl z)))
  (define (v3-x v) (vector-ref v 0))
  (define (v3-y v) (vector-ref v 1))
  (define (v3-z v) (vector-ref v 2))
  (define (v3-add a b)
    (vector (fl+ (v3-x a) (v3-x b)) (fl+ (v3-y a) (v3-y b))
            (fl+ (v3-z a) (v3-z b))))
  (define (v3-sub a b)
    (vector (fl- (v3-x a) (v3-x b)) (fl- (v3-y a) (v3-y b))
            (fl- (v3-z a) (v3-z b))))
  (define (v3-scale a s)
    (let ((s ($mat-fl s)))
      (vector (fl* (v3-x a) s) (fl* (v3-y a) s) (fl* (v3-z a) s))))
  (define (v3-dot a b)
    (fl+ (fl+ (fl* (v3-x a) (v3-x b)) (fl* (v3-y a) (v3-y b)))
         (fl* (v3-z a) (v3-z b))))
  (define (v3-cross a b)
    (vector (fl- (fl* (v3-y a) (v3-z b)) (fl* (v3-z a) (v3-y b)))
            (fl- (fl* (v3-z a) (v3-x b)) (fl* (v3-x a) (v3-z b)))
            (fl- (fl* (v3-x a) (v3-y b)) (fl* (v3-y a) (v3-x b)))))
  (define (v3-normalize a)
    (let ((n (flsqrt (v3-dot a a))))
      (vector (fl/ (v3-x a) n) (fl/ (v3-y a) n) (fl/ (v3-z a) n))))

  ;; ---- mat4, column-major: m[col*4 + row] ----
  (define (m4-identity)
    (vector 1.0 0.0 0.0 0.0  0.0 1.0 0.0 0.0
            0.0 0.0 1.0 0.0  0.0 0.0 0.0 1.0))

  ;; hand these kernels 128 bytes of staging memory and m4-mul goes
  ;; wide: each result column is one f32x4 scale and three axpys
  ;; instead of sixteen scalar multiply-adds over boxed reads.
  ;; fx-init! wires this up automatically; without it the scalar
  ;; path runs (headless math tests exercise both).  The lanes are
  ;; f32 -- matrices bound for the GPU lose nothing
  (define $mat-scratch #f)
  (define (m4-scratch! base) (set! $mat-scratch base))

  (define ($m4-mul-simd a b s)
    (let ((m (make-vector 16 0.0))
          (cbase (+ s 64)))
      (let in ((k 0))                   ; A's columns, once, as f32
        (when (< k 16)
          (%mem-f32-set! (+ s (* k 4)) (vector-ref a k))
          (in (+ k 1))))
      (let col ((c 0))                  ; C[:,c] = sum A[:,k] * b_kc
        (when (< c 4)
          (let ((dst (+ cbase (* c 16)))
                (bc (* c 4)))
            (%f32x4-scale! dst s (vector-ref b bc))
            (%f32x4-axpy! dst dst (+ s 16) (vector-ref b (+ bc 1)))
            (%f32x4-axpy! dst dst (+ s 32) (vector-ref b (+ bc 2)))
            (%f32x4-axpy! dst dst (+ s 48) (vector-ref b (+ bc 3))))
          (col (+ c 1))))
      (let out ((k 0))
        (when (< k 16)
          (vector-set! m k (%mem-f32-ref (+ cbase (* k 4))))
          (out (+ k 1))))
      m))

  (define (m4-mul a b)                  ; (m4-mul a b) transforms as a after b
    (if $mat-scratch
        ($m4-mul-simd a b $mat-scratch)
        (let ((m (make-vector 16 0.0)))
          (let col ((c 0))
            (when (< c 4)
              (let row ((r 0))
                (when (< r 4)
                  (let sum ((k 0) (s 0.0))
                    (if (= k 4)
                        (vector-set! m (+ (* c 4) r) s)
                        (sum (+ k 1)
                             (fl+ s (fl* (vector-ref a (+ (* k 4) r))
                                         (vector-ref b (+ (* c 4) k)))))))
                  (row (+ r 1))))
              (col (+ c 1))))
          m)))

  (define (m4-transform m v)            ; point transform, w-divided
    (let ((x (v3-x v)) (y (v3-y v)) (z (v3-z v)))
      (define (row r)
        (fl+ (fl+ (fl* (vector-ref m r) x)
                  (fl* (vector-ref m (+ r 4)) y))
             (fl+ (fl* (vector-ref m (+ r 8)) z)
                  (vector-ref m (+ r 12)))))
      (let ((w (row 3)))
        (vector (fl/ (row 0) w) (fl/ (row 1) w) (fl/ (row 2) w)))))

  (define (m4-translate x y z)
    (vector 1.0 0.0 0.0 0.0  0.0 1.0 0.0 0.0  0.0 0.0 1.0 0.0
            ($mat-fl x) ($mat-fl y) ($mat-fl z) 1.0))
  (define (m4-scale x y z)
    (vector ($mat-fl x) 0.0 0.0 0.0  0.0 ($mat-fl y) 0.0 0.0
            0.0 0.0 ($mat-fl z) 0.0  0.0 0.0 0.0 1.0))

  (define (m4-rotate-x t)
    (let* ((t ($mat-fl t)) (c (flcos t)) (s (flsin t)))
      (vector 1.0 0.0 0.0 0.0
              0.0 c s 0.0
              0.0 (fl- 0.0 s) c 0.0
              0.0 0.0 0.0 1.0)))
  (define (m4-rotate-y t)
    (let* ((t ($mat-fl t)) (c (flcos t)) (s (flsin t)))
      (vector c 0.0 (fl- 0.0 s) 0.0
              0.0 1.0 0.0 0.0
              s 0.0 c 0.0
              0.0 0.0 0.0 1.0)))
  (define (m4-rotate-z t)
    (let* ((t ($mat-fl t)) (c (flcos t)) (s (flsin t)))
      (vector c s 0.0 0.0
              (fl- 0.0 s) c 0.0 0.0
              0.0 0.0 1.0 0.0
              0.0 0.0 0.0 1.0)))

  (define (m4-from-quat x y z w)        ; a unit quaternion's rotation
    (let* ((x ($mat-fl x)) (y ($mat-fl y)) (z ($mat-fl z)) (w ($mat-fl w))
           (xx (fl* x x)) (yy (fl* y y)) (zz (fl* z z))
           (xy (fl* x y)) (xz (fl* x z)) (yz (fl* y z))
           (wx (fl* w x)) (wy (fl* w y)) (wz (fl* w z)))
      (vector (fl- 1.0 (fl* 2.0 (fl+ yy zz)))
              (fl* 2.0 (fl+ xy wz))
              (fl* 2.0 (fl- xz wy))
              0.0
              (fl* 2.0 (fl- xy wz))
              (fl- 1.0 (fl* 2.0 (fl+ xx zz)))
              (fl* 2.0 (fl+ yz wx))
              0.0
              (fl* 2.0 (fl+ xz wy))
              (fl* 2.0 (fl- yz wx))
              (fl- 1.0 (fl* 2.0 (fl+ xx yy)))
              0.0
              0.0 0.0 0.0 1.0)))

  (define (m4-perspective fovy aspect near far)
    (let* ((f (fl/ 1.0 (fltan (fl/ ($mat-fl fovy) 2.0))))
           (near ($mat-fl near)) (far ($mat-fl far))
           (nf (fl/ 1.0 (fl- near far))))
      (vector (fl/ f ($mat-fl aspect)) 0.0 0.0 0.0
              0.0 f 0.0 0.0
              0.0 0.0 (fl* (fl+ far near) nf) -1.0
              0.0 0.0 (fl* 2.0 (fl* (fl* far near) nf)) 0.0)))

  (define (m4-ortho left right bottom top near far)
    (let* ((l ($mat-fl left)) (r ($mat-fl right))
           (b ($mat-fl bottom)) (t ($mat-fl top))
           (n ($mat-fl near)) (f ($mat-fl far)))
      (vector (fl/ 2.0 (fl- r l)) 0.0 0.0 0.0
              0.0 (fl/ 2.0 (fl- t b)) 0.0 0.0
              0.0 0.0 (fl/ -2.0 (fl- f n)) 0.0
              (fl/ (fl- 0.0 (fl+ r l)) (fl- r l))
              (fl/ (fl- 0.0 (fl+ t b)) (fl- t b))
              (fl/ (fl- 0.0 (fl+ f n)) (fl- f n)) 1.0)))

  ;; general 4x4 inverse by cofactor expansion; #f when singular.
  ;; the door to picking: invert the view-projection, unproject the
  ;; cursor, raycast with (web collide)
  (define (m4-inverse m)
    (define (a i) (vector-ref m i))
    (let* ((s0 (fl- (fl* (a 0) (a 5)) (fl* (a 4) (a 1))))
           (s1 (fl- (fl* (a 0) (a 9)) (fl* (a 8) (a 1))))
           (s2 (fl- (fl* (a 0) (a 13)) (fl* (a 12) (a 1))))
           (s3 (fl- (fl* (a 4) (a 9)) (fl* (a 8) (a 5))))
           (s4 (fl- (fl* (a 4) (a 13)) (fl* (a 12) (a 5))))
           (s5 (fl- (fl* (a 8) (a 13)) (fl* (a 12) (a 9))))
           (c5 (fl- (fl* (a 10) (a 15)) (fl* (a 14) (a 11))))
           (c4 (fl- (fl* (a 6) (a 15)) (fl* (a 14) (a 7))))
           (c3 (fl- (fl* (a 6) (a 11)) (fl* (a 10) (a 7))))
           (c2 (fl- (fl* (a 2) (a 15)) (fl* (a 14) (a 3))))
           (c1 (fl- (fl* (a 2) (a 11)) (fl* (a 10) (a 3))))
           (c0 (fl- (fl* (a 2) (a 7)) (fl* (a 6) (a 3))))
           (det (fl+ (fl- (fl+ (fl* s0 c5) (fl* s3 c2))
                          (fl+ (fl* s1 c4) (fl* s4 c1)))
                     (fl+ (fl* s2 c3) (fl* s5 c0)))))
      (if (and (fl<? det 0.000000000001)
               (fl<? -0.000000000001 det))
          #f
          (let ((r (fl/ 1.0 det)))
            (vector
             (fl* r (fl+ (fl- (fl* (a 5) c5) (fl* (a 9) c4))
                         (fl* (a 13) c3)))
             (fl* r (fl- (fl* (a 9) c2)
                         (fl+ (fl* (a 1) c5) (fl* (a 13) c1))))
             (fl* r (fl+ (fl- (fl* (a 1) c4) (fl* (a 5) c2))
                         (fl* (a 13) c0)))
             (fl* r (fl- (fl* (a 5) c1)
                         (fl+ (fl* (a 1) c3) (fl* (a 9) c0))))
             (fl* r (fl- (fl* (a 8) c4)
                         (fl+ (fl* (a 4) c5) (fl* (a 12) c3))))
             (fl* r (fl+ (fl- (fl* (a 0) c5) (fl* (a 8) c2))
                         (fl* (a 12) c1)))
             (fl* r (fl- (fl* (a 4) c2)
                         (fl+ (fl* (a 0) c4) (fl* (a 12) c0))))
             (fl* r (fl+ (fl- (fl* (a 0) c3) (fl* (a 4) c1))
                         (fl* (a 8) c0)))
             (fl* r (fl+ (fl- (fl* (a 7) s5) (fl* (a 11) s4))
                         (fl* (a 15) s3)))
             (fl* r (fl- (fl* (a 11) s2)
                         (fl+ (fl* (a 3) s5) (fl* (a 15) s1))))
             (fl* r (fl+ (fl- (fl* (a 3) s4) (fl* (a 7) s2))
                         (fl* (a 15) s0)))
             (fl* r (fl- (fl* (a 7) s1)
                         (fl+ (fl* (a 3) s3) (fl* (a 11) s0))))
             (fl* r (fl- (fl* (a 10) s4)
                         (fl+ (fl* (a 6) s5) (fl* (a 14) s3))))
             (fl* r (fl+ (fl- (fl* (a 2) s5) (fl* (a 10) s2))
                         (fl* (a 14) s1)))
             (fl* r (fl- (fl* (a 6) s2)
                         (fl+ (fl* (a 2) s4) (fl* (a 14) s0))))
             (fl* r (fl+ (fl- (fl* (a 2) s3) (fl* (a 6) s1))
                         (fl* (a 10) s0))))))))

  ;; NDC (x y in [-1,1], z in [-1,1]) back to world space through an
  ;; inverted view-projection: m4-transform already divides by w
  (define (m4-unproject inv-vp x y z)
    (m4-transform inv-vp (v3 x y z)))

  ;; the view frustum as six inward-facing planes #(nx ny nz d)
  ;; (Gribb-Hartmann rows of the view-projection), normalized so
  ;; nx*x + ny*y + nz*z + d is a true signed distance
  (define ($mat-plane m i sign)         ; row3 +/- row_i
    (define (r j) (vector-ref m (+ (* j 4) i)))
    (define (r3 j) (vector-ref m (+ (* j 4) 3)))
    (let* ((nx (fl+ (r3 0) (fl* sign (r 0))))
           (ny (fl+ (r3 1) (fl* sign (r 1))))
           (nz (fl+ (r3 2) (fl* sign (r 2))))
           (d (fl+ (r3 3) (fl* sign (r 3))))
           (len (flsqrt (fl+ (fl+ (fl* nx nx) (fl* ny ny))
                             (fl* nz nz)))))
      (vector (fl/ nx len) (fl/ ny len) (fl/ nz len) (fl/ d len))))

  (define (m4-frustum-planes vp)
    (vector ($mat-plane vp 0 1.0) ($mat-plane vp 0 -1.0)   ; left right
            ($mat-plane vp 1 1.0) ($mat-plane vp 1 -1.0)   ; bottom top
            ($mat-plane vp 2 1.0) ($mat-plane vp 2 -1.0))) ; near far

  ;; #f only when the sphere is entirely outside some plane, so a
  ;; #t is conservative -- exactly what a cull wants
  (define (sphere-in-frustum? planes c r)
    (let ((r (fl- 0.0 ($mat-fl r))))
      (let each ((i 0))
        (or (= i 6)
            (let ((p (vector-ref planes i)))
              (and (fl<? r (fl+ (fl+ (fl+ (fl* (vector-ref p 0) (v3-x c))
                                          (fl* (vector-ref p 1) (v3-y c)))
                                     (fl* (vector-ref p 2) (v3-z c)))
                                (vector-ref p 3)))
                   (each (+ i 1))))))))

  (define (m4-look-at eye center up)
    (let* ((z (v3-normalize (v3-sub eye center)))
           (x (v3-normalize (v3-cross up z)))
           (y (v3-cross z x)))
      (vector (v3-x x) (v3-x y) (v3-x z) 0.0
              (v3-y x) (v3-y y) (v3-y z) 0.0
              (v3-z x) (v3-z y) (v3-z z) 0.0
              (fl- 0.0 (v3-dot x eye))
              (fl- 0.0 (v3-dot y eye))
              (fl- 0.0 (v3-dot z eye)) 1.0))))
