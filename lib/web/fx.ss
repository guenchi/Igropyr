;; The effects harness over (web gl): programs that wire themselves.
;;
;; A shader authored as (web glsl) forms already declares its
;; interface; fx reads the attribute/uniform declarations back out of
;; the same forms and does the bookkeeping that gl-particles.ss does
;; by hand -- attribute locations and interleaved offsets, uniform
;; slots, resource slot numbers, staging-memory layout, the rAF loop:
;;
;;   (fx-init! canvas)
;;   (define q (fx-fullscreen! fragment-forms))   ; a shadertoy in ~15 lines
;;   (fx-loop! (lambda (t dt)
;;               (fx-fullscreen-use! q t)
;;               (fx-fullscreen-draw! q)))
;;
;; Slot numbers are owned by fx from (fx-init!) on: create resources
;; through fx-program!/fx-buffer!/fx-texture!, not with hand-numbered
;; gl-buffer! calls, or the two schemes collide.  Staging memory is
;; owned the same way: bytes [0, 64KiB) are the command region,
;; fx-alloc! hands out what lies above and grows the memory as needed.
;;
;; fx-ticks! (the timing pump: t and dt in seconds, no GL) and
;; fx-init-input! (polled keys and pointer) work without fx-init!'s
;; GL attachment, so a Three.js scene can use them too: pass the
;; renderer's domElement to fx-init-input!.
;;
;; Every float that reaches the command encoder is coerced here --
;; %mem-f32-set! traps on fixnums, so user code may pass either.
;;
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (web fx)
  (export fx-init! fx-slot! fx-alloc! fx-buffer! fx-texture!
          fx-width fx-height
          fx-target! fx-target-hdr! fx-target-msaa! fx-resolve!
          fx-cube-target! fx-bind-cube-face!
          fx-target? fx-target-texture
          fx-target-width fx-target-height
          fx-bind-target! fx-bind-canvas!
          fx-program! fx-program3! fx-tf-program! fx-ubo!
          fx-program? fx-program-slot fx-program-stride
          fx-program-istride
          fx-use! fx-use-instanced! fx-uniform!
          fx-ticks! fx-loop!
          fx-init-input! key-down? pointer-x pointer-y pointer-down?
          pointer-lock! pointer-locked? pointer-motion!
          fx-fullscreen! fx-quad-program
          fx-fullscreen-use! fx-fullscreen-draw!)
  (import (rnrs) (web js) (web gl) (web glsl))

  (define ($fx-fl v) (if (flonum? v) v (exact->inexact v)))

  ;; ---- init, slots, staging-memory allocation ----
  (define $fx-cmd-limit 65536)          ; command region [0, 64KiB)
  (define $fx-canvas #f)
  (define $fx-slot 0)
  (define $fx-heap 65536)

  (define ($fx-gen)
    (let ((g (js-get (js-global) "__goeteia_fx_gen")))
      (if (js-truthy? g) (js->number g) 0)))

  (define (fx-init! canvas)
    (set! $fx-canvas canvas)
    (gl-attach! canvas)
    (set! $fx-slot 0)
    (set! $fx-heap $fx-cmd-limit)
    ;; a fresh init retires loops from any earlier run of the page
    ;; (live editors re-run whole programs; fx-ticks! checks this)
    (js-set! (js-global) "__goeteia_fx_gen" (+ 1 ($fx-gen)))
    (cmd-region! 0))

  (define (fx-slot!)
    (unless $fx-canvas (error 'fx-slot! "call fx-init! first"))
    (let ((s $fx-slot)) (set! $fx-slot (+ s 1)) s))

  (define (fx-alloc! bytes)             ; 8-aligned bump; grows memory
    (let* ((r (remainder $fx-heap 8))
           (base (if (= r 0) $fx-heap (+ $fx-heap (- 8 r))))
           (end (+ base bytes))
           (have (* 65536 (%mem-size))))
      (when (> end have)
        (%mem-grow (quotient (+ (- end have) 65535) 65536)))
      (set! $fx-heap end)
      base))

  (define (fx-buffer!) (let ((s (fx-slot!))) (gl-buffer! s) s))
  (define (fx-texture!) (let ((s (fx-slot!))) (gl-texture! s) s))
  (define (fx-ubo! bytes) (let ((s (fx-slot!))) (gl-ubo! s bytes) s))

  ;; ---- offscreen render targets (webgl2) ----
  (define-record-type (fx-target $make-fx-target fx-target?)
    (fields (immutable fb $fx-target-fb)
            (immutable tex fx-target-texture)  ; sample it like any texture
            (immutable w fx-target-width)
            (immutable h fx-target-height)
            (immutable rfb $fx-target-rfb)))   ; msaa resolve fb, or #f

  (define (fx-target! w h . depth-only?)
    (let* ((fb (fx-slot!))
           (tex (fx-slot!)))
      (if (and (pair? depth-only?) (car depth-only?))
          (gl-target! fb tex w h #t)
          (gl-target! fb tex w h))
      ($make-fx-target fb tex w h #f)))

  ;; a half-float target: values past 1.0 survive for bloom and
  ;; tonemapping (WebGL 2 + EXT_color_buffer_float)
  (define (fx-target-hdr! w h)
    (let* ((fb (fx-slot!))
           (tex (fx-slot!)))
      (gl-target-hdr! fb tex w h)
      ($make-fx-target fb tex w h #f)))

  ;; a cube target: six faces around a point.  Bind face i, render
  ;; the world as the light sees it, then sample the texture with a
  ;; direction -- point-light shadows
  (define (fx-cube-target! dim)
    (let* ((fb (fx-slot!)))
      (let eat ((k 1)) (when (< k 6) (fx-slot!) (eat (+ k 1))))
      (let ((tex (fx-slot!)))
        (gl-cube-target! fb tex dim)
        ($make-fx-target fb tex dim dim #f))))
  (define (fx-bind-cube-face! t i)
    (cmd-bind-target! (+ ($fx-target-fb t) i))
    (cmd-viewport! 0 0 (fx-target-width t) (fx-target-height t)))

  ;; a multisampled target: render as usual, call (fx-resolve! t)
  ;; when the passes into it are done, then sample its texture
  (define (fx-target-msaa! w h samples)
    (let* ((fb (fx-slot!))
           (rfb (fx-slot!))
           (tex (fx-slot!)))
      (gl-target-msaa! fb rfb tex w h samples)
      ($make-fx-target fb tex w h rfb)))

  (define (fx-resolve! t)
    (unless ($fx-target-rfb t)
      (error 'fx-resolve! "not a multisampled target"))
    (cmd-resolve! ($fx-target-fb t) ($fx-target-rfb t)
                  (fx-target-width t) (fx-target-height t)))

  ;; binding also sets the viewport to match
  (define (fx-bind-target! t)
    (cmd-bind-target! ($fx-target-fb t))
    (cmd-viewport! 0 0 (fx-target-width t) (fx-target-height t)))
  (define (fx-bind-canvas!)
    (cmd-bind-canvas!)
    (cmd-viewport! 0 0 (fx-width) (fx-height)))

  (define (fx-width) (js->number (js-get $fx-canvas "width")))
  (define (fx-height) (js->number (js-get $fx-canvas "height")))

  ;; ---- programs wired from their own glsl forms ----
  ;; attributes named i_* are PER-INSTANCE: they get their own buffer,
  ;; stride and divisor through fx-use-instanced!
  (define-record-type (fx-program $make-fx-program fx-program?)
    (fields (immutable slot fx-program-slot)
            (immutable stride fx-program-stride)      ; per-vertex bytes
            (immutable attribs $fx-program-attribs)   ; ((loc size offset) ...)
            (immutable istride fx-program-istride)    ; per-instance bytes
            (immutable iattribs $fx-program-iattribs)
            (immutable uniforms $fx-program-uniforms))) ; name -> (slot . type)

  (define ($fx-instance-name? n)        ; i_offset, i_tint, ...
    (let ((s (symbol->string n)))
      (and (>= (string-length s) 2)
           (char=? (string-ref s 0) #\i)
           (char=? (string-ref s 1) #\_))))

  (define ($fx-attr-names as)           ; "a_pos,a_uv,..." for binding
    (if (null? as)
        ""
        (fold-left (lambda (acc a)
                     (string-append acc "," (symbol->string (car a))))
                   (symbol->string (caar as))
                   (cdr as))))

  (define (fx-program! vs-forms fs-forms)
    ($fx-program-src! vs-forms fs-forms
                      (glsl->string vs-forms) (glsl->string fs-forms)))
  ;; the same wiring from the same forms, rendered as ESSL 3.00 --
  ;; for shaders that need uniform blocks or transform feedback
  (define (fx-program3! vs-forms fs-forms)
    ($fx-program-src! vs-forms fs-forms
                      (glsl300-vs->string vs-forms)
                      (glsl300-fs->string fs-forms)))

  ;; a transform-feedback program: ESSL 3.00, and every varying the
  ;; vertex shader declares is captured, interleaved, into the bound
  ;; buffer -- the GPU-side particle update step
  (define (fx-tf-program! vs-forms fs-forms)
    ($fx-program-mk! vs-forms fs-forms
                     (glsl300-vs->string vs-forms)
                     (glsl300-fs->string fs-forms)
                     (fold-left (lambda (acc v)
                                  (if (string=? acc "")
                                      (symbol->string v)
                                      (string-append
                                       acc "," (symbol->string v))))
                                "" (glsl-varyings vs-forms))))

  (define ($fx-program-src! vs-forms fs-forms vs-src fs-src)
    ($fx-program-mk! vs-forms fs-forms vs-src fs-src #f))

  (define ($fx-program-mk! vs-forms fs-forms vs-src fs-src tf)
    (let* ((pslot (fx-slot!))
           (as (glsl-attributes vs-forms)))
      (if tf
          (gl-tf-program! pslot vs-src fs-src ($fx-attr-names as) tf)
          (gl-program! pslot vs-src fs-src ($fx-attr-names as)))
      (let ((uniforms (make-eq-hashtable)))
        (for-each (lambda (u)
                    (unless (hashtable-contains? uniforms (car u))
                      (let ((s (fx-slot!)))
                        (gl-uniform! s pslot (symbol->string (car u)))
                        (hashtable-set! uniforms (car u)
                                        (cons s (cadr u))))))
                  (append (glsl-uniforms vs-forms) (glsl-uniforms fs-forms)))
        ;; locations follow declaration order; vertex and instance
        ;; attributes each get their own interleaved layout
        (let loop ((as as) (loc 0) (voff 0) (ioff 0) (vacc '()) (iacc '()))
          (if (null? as)
              ($make-fx-program pslot voff (reverse vacc)
                                ioff (reverse iacc) uniforms)
              (let ((n (caar as)) (size (caddr (car as))))
                (if ($fx-instance-name? n)
                    (loop (cdr as) (+ loc 1) voff (+ ioff (* 4 size))
                          vacc (cons (list loc size ioff) iacc))
                    (loop (cdr as) (+ loc 1) (+ voff (* 4 size)) ioff
                          (cons (list loc size voff) vacc) iacc))))))))

  ;; use-program, bind the buffer, then the attribs: the pointer
  ;; captures the buffer bound at that moment
  (define (fx-use! prog buf-slot)
    (cmd-use-program! (fx-program-slot prog))
    (cmd-bind-buffer! buf-slot)
    (for-each (lambda (a)
                (cmd-vertex-attrib! (car a) (cadr a)
                                    (fx-program-stride prog) (caddr a)))
              ($fx-program-attribs prog)))

  ;; the instanced variant: vertex attributes from one buffer,
  ;; i_* attributes from another with divisor 1 (webgl2); draw with
  ;; cmd-draw-elements-instanced!
  (define (fx-use-instanced! prog buf-slot inst-slot)
    (fx-use! prog buf-slot)
    (cmd-bind-buffer! inst-slot)
    (for-each (lambda (a)
                (cmd-vertex-attrib! (car a) (cadr a)
                                    (fx-program-istride prog) (caddr a))
                (cmd-attrib-divisor! (car a) 1))
              ($fx-program-iattribs prog)))

  ;; dispatch on the declared type; sampler values are texture units
  (define (fx-uniform! prog name . vs)
    (let ((u (hashtable-ref ($fx-program-uniforms prog) name #f)))
      (unless u (error 'fx-uniform! "undeclared uniform" name))
      (let ((slot (car u)) (ty (cdr u)))
        (if (pair? ty)                  ; (array mat4 N): joint matrices
            (cmd-uniform-matrices! slot (car vs))
            (case ty
          ((float) (cmd-uniform1f! slot ($fx-fl (car vs))))
          ((vec2) (cmd-uniform2f! slot ($fx-fl (car vs)) ($fx-fl (cadr vs))))
          ((vec3) (cmd-uniform3f! slot ($fx-fl (car vs)) ($fx-fl (cadr vs))
                                  ($fx-fl (caddr vs))))
          ((vec4) (cmd-uniform4f! slot
                                  ($fx-fl (car vs)) ($fx-fl (cadr vs))
                                  ($fx-fl (caddr vs)) ($fx-fl (cadddr vs))))
          ((sampler2D samplerCube int) (cmd-uniform1i! slot (car vs)))
          ((mat4) (cmd-uniform-matrix4! slot (car vs)))  ; (web mat) m4
          (else (error 'fx-uniform! "unsupported uniform type" ty)))))))

  ;; ---- the timing pump and the frame loop ----
  ;; proc gets (t dt) in seconds; no GL side effects, so a Three.js
  ;; render loop can use it directly
  (define (fx-ticks! proc)
    (let ((t0 -1.0) (last 0.0) (gen ($fx-gen)))
      (letrec ((tick (lambda args
                       (when (= gen ($fx-gen))
                         (let ((s (fl/ ($fx-fl (js->number (car args)))
                                       1000.0)))
                           (when (fl<? t0 0.0)
                             (set! t0 s)
                             (set! last s))
                           (proc (fl- s t0) (fl- s last))
                           (set! last s))
                         (js-method (js-global) "requestAnimationFrame"
                                    tick)))))
        (js-method (js-global) "requestAnimationFrame" tick))))

  ;; ticks plus the GL frame plumbing: begin, viewport, user commands,
  ;; overflow check, one flush
  (define (fx-loop! proc)
    (fx-ticks!
     (lambda (t dt)
       (cmd-begin!)
       (cmd-viewport! 0 0 (fx-width) (fx-height))
       (proc t dt)
       (when (> (cmd-pos) $fx-cmd-limit)
         (error 'fx-loop! "command region overflow" (cmd-pos)))
       (cmd-flush!))))

  ;; ---- polled input ----
  (define $fx-keys (make-hashtable string-hash string=?))
  (define $fx-px 0.0)
  (define $fx-py 0.0)
  (define $fx-pdown #f)

  ;; keys on the window, pointer on the element (default: fx-init!'s
  ;; canvas; pass a Three.js renderer's domElement to use it there)
  (define (fx-init-input! . el)
    (let ((target (if (null? el) $fx-canvas (car el))))
      (unless target
        (error 'fx-init-input! "no element: pass one or call fx-init! first"))
      (js-method (js-global) "addEventListener" "keydown"
                 (lambda (e)
                   (hashtable-set! $fx-keys (js->string (js-get e "key")) #t)
                   (js-undefined)))
      (js-method (js-global) "addEventListener" "keyup"
                 (lambda (e)
                   (hashtable-set! $fx-keys (js->string (js-get e "key")) #f)
                   (js-undefined)))
      (js-method target "addEventListener" "pointermove"
                 (lambda (e)
                   (set! $fx-px ($fx-fl (js->number (js-get e "offsetX"))))
                   (set! $fx-py ($fx-fl (js->number (js-get e "offsetY"))))
                   (js-undefined)))
      (js-method target "addEventListener" "pointerdown"
                 (lambda (e) (set! $fx-pdown #t) (js-undefined)))
      (js-method target "addEventListener" "pointerup"
                 (lambda (e) (set! $fx-pdown #f) (js-undefined)))))

  (define (key-down? k) (hashtable-ref $fx-keys k #f))
  (define (pointer-x) $fx-px)
  (define (pointer-y) $fx-py)
  (define (pointer-down?) $fx-pdown)

  ;; ---- pointer lock: relative mouse for first-person cameras ----
  (define $fx-dx 0.0)
  (define $fx-dy 0.0)
  (define $fx-locked #f)

  ;; call once; clicking the element captures the pointer (browsers
  ;; require the gesture), Esc releases it.  While captured, mouse
  ;; motion accumulates as movementX/Y deltas.
  (define (pointer-lock! . el)
    (let ((target (if (null? el) $fx-canvas (car el)))
          (doc (js-get (js-global) "document")))
      (unless target
        (error 'pointer-lock! "no element: pass one or call fx-init! first"))
      (js-method target "addEventListener" "click"
                 (lambda (e)
                   (unless $fx-locked
                     (js-method target "requestPointerLock"))
                   (js-undefined)))
      (js-method doc "addEventListener" "pointerlockchange"
                 (lambda (e)
                   (set! $fx-locked
                         (js-truthy? (js-get doc "pointerLockElement")))
                   (js-undefined)))
      (js-method doc "addEventListener" "mousemove"
                 (lambda (e)
                   (when $fx-locked
                     (set! $fx-dx
                           (fl+ $fx-dx
                                ($fx-fl (js->number (js-get e "movementX")))))
                     (set! $fx-dy
                           (fl+ $fx-dy
                                ($fx-fl (js->number (js-get e "movementY"))))))
                   (js-undefined)))))

  (define (pointer-locked?) $fx-locked)

  ;; the motion since the last call, as (dx . dy); consuming resets,
  ;; so poll it once per frame
  (define (pointer-motion!)
    (let ((d (cons $fx-dx $fx-dy)))
      (set! $fx-dx 0.0)
      (set! $fx-dy 0.0)
      d))

  ;; ---- the fullscreen quad: fragment-shader effects ----
  (define-record-type (fx-quad $make-fx-quad fx-quad?)
    (fields (immutable prog fx-quad-program)
            (immutable buf $fx-quad-buf)
            (immutable base $fx-quad-base)))

  (define $fx-quad-vs
    '((attribute vec2 a_pos)
      (define (main) void
        (set! gl_Position (vec4 a_pos (fl 0) (fl 1))))))

  (define (fx-fullscreen! fs-forms)
    (let* ((prog (fx-program! $fx-quad-vs fs-forms))
           (buf (fx-buffer!))
           (base (fx-alloc! 32)))       ; one static triangle strip
      (%mem-f32-set! base -1.0)         (%mem-f32-set! (+ base 4) -1.0)
      (%mem-f32-set! (+ base 8) 1.0)    (%mem-f32-set! (+ base 12) -1.0)
      (%mem-f32-set! (+ base 16) -1.0)  (%mem-f32-set! (+ base 20) 1.0)
      (%mem-f32-set! (+ base 24) 1.0)   (%mem-f32-set! (+ base 28) 1.0)
      ($make-fx-quad prog buf base)))

  ;; u_time and u_resolution are set iff the fragment declares them;
  ;; set anything else with fx-uniform! on (fx-quad-program q)
  (define (fx-fullscreen-use! q t)
    (let ((prog (fx-quad-program q)))
      (fx-use! prog ($fx-quad-buf q))
      (cmd-buffer-data! ($fx-quad-base q) 32)
      (when (hashtable-contains? ($fx-program-uniforms prog) 'u_time)
        (fx-uniform! prog 'u_time t))
      (when (hashtable-contains? ($fx-program-uniforms prog) 'u_resolution)
        (fx-uniform! prog 'u_resolution (fx-width) (fx-height)))))

  (define (fx-fullscreen-draw! q)
    (cmd-draw-arrays! GL-TRIANGLE-STRIP 0 4)))
