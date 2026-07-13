;; Raw WebGL through a command buffer (tier 3).
;;
;; Per frame, Scheme encodes GL commands as words into the linear
;; staging memory and makes ONE bridge call; a JS replayer (embedded
;; here, injected once with js-eval) walks the words in a tight loop
;; and issues the real gl.* calls. Vertex data also lives in the
;; staging memory, so BUFFER-DATA uploads it zero-copy.
;;
;; Resources (programs, buffers, uniform locations) are JS objects and
;; cannot cross as bytes: they are created once at init time over the
;; normal FFI and kept in a slot table; commands refer to slot numbers.
;;
;;   (gl-attach! canvas)                      ; once
;;   (gl-program! 0 vs-src fs-src)            ; slots, once
;;   (gl-buffer! 1)
;;   (gl-uniform! 2 0 "u_time")
;;   ... per frame:
;;   (cmd-begin!)
;;   (cmd-clear! 0.1 0.1 0.15 1.0)
;;   (cmd-use-program! 0)
;;   (cmd-bind-buffer! 1)
;;   (cmd-buffer-data! vertex-base byte-len)  ; from staging memory
;;   (cmd-vertex-attrib! 0 2 0 0)
;;   (cmd-draw-arrays! GL-POINTS 0 n)
;;   (cmd-flush!)                             ; the one bridge call
;;
;; Layout is caller-chosen: commands go at cmd-base (set by
;; cmd-region!), vertex/user data wherever you put it.
;;
;; Copyright (c) 2026 guenchi. MIT license; see LICENSE.
(library (web gl)
  (export gl-attach! gl-program! gl-buffer! gl-uniform!
          gl-texture! gl-texture-upload! gl-texture-data! gl-cubemap!
          gl-cubemap-empty! gl-cube-face-fb! gl-slot-object!
          gl-target! gl-target-hdr! gl-target-msaa! gl-cube-target!
          gl-target-mrt!
          cmd-bind-target! cmd-bind-canvas! cmd-resolve!
          cmd-region! cmd-begin! cmd-flush! cmd-pos cmd-draws
          cmd-clear! cmd-use-program! cmd-bind-buffer! cmd-buffer-data!
          cmd-vertex-attrib! cmd-uniform1f! cmd-uniform4f!
          cmd-uniform1i! cmd-uniform2f! cmd-uniform3f! cmd-uniform-matrix4!
          cmd-bind-texture! cmd-unbind-texture!
          cmd-bind-cubemap! cmd-unbind-cubemap!
          cmd-depth!
          gl-vao! cmd-bind-vao! cmd-unbind-vao!
          gl-ubo! gl-uniform-block! cmd-bind-ubo! cmd-ubo-data!
          gl-tf-program! cmd-tf-buffer! cmd-tf-begin! cmd-tf-end!
          cmd-bind-index! cmd-index-data! cmd-draw-elements!
          cmd-index-data32! cmd-draw-elements32!
          cmd-attrib-divisor! cmd-draw-elements-instanced!
          cmd-uniform-matrices!
          cmd-draw-arrays! cmd-viewport! cmd-blend!
          GL-POINTS GL-LINES GL-TRIANGLES GL-TRIANGLE-STRIP)
  (import (rnrs) (web js))

  ;; WebGL draw-mode enums
  (define GL-POINTS 0)
  (define GL-LINES 1)
  (define GL-TRIANGLES 4)
  (define GL-TRIANGLE-STRIP 5)

  ;; ---- the JS replayer, injected once ----
  (define replayer-src
    (string-append
     "globalThis.__goeteia_gl = (canvas, memory) => {"
     " const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');"
     " if (gl.getExtension) gl.getExtension('EXT_color_buffer_float');"
     " const slots = [];"
     " const compile = (kind, src) => {"
     "   const s = gl.createShader(kind); gl.shaderSource(s, src); gl.compileShader(s);"
     "   if (!gl.getShaderParameter(s, gl.COMPILE_STATUS))"
     "     throw new Error(gl.getShaderInfoLog(s));"
     "   return s; };"
     " return {"
     "  program(slot, vs, fs, attribs) {"
     "    const p = gl.createProgram();"
     "    gl.attachShader(p, compile(gl.VERTEX_SHADER, vs));"
     "    gl.attachShader(p, compile(gl.FRAGMENT_SHADER, fs));"
     "    if (attribs) String(attribs).split(',').forEach((n, i) => {"
     "      if (n) gl.bindAttribLocation(p, i, n); });"
     "    gl.linkProgram(p);"
     "    if (!gl.getProgramParameter(p, gl.LINK_STATUS))"
     "      throw new Error(gl.getProgramInfoLog(p));"
     "    slots[slot] = p; },"
     "  buffer(slot) { slots[slot] = gl.createBuffer(); },"
     "  vao(slot) { slots[slot] = gl.createVertexArray(); },"
     "  ubo(slot, bytes) {"
     "    const b = gl.createBuffer();"
     "    gl.bindBuffer(gl.UNIFORM_BUFFER, b);"
     "    gl.bufferData(gl.UNIFORM_BUFFER, bytes, gl.DYNAMIC_DRAW);"
     "    slots[slot] = b; },"
     "  uniformBlock(pslot, name, binding) {"
     "    const p = slots[pslot];"
     "    gl.uniformBlockBinding(p, gl.getUniformBlockIndex(p, name),"
     "                           binding); },"
     "  uniform(slot, pslot, name) {"
     "    slots[slot] = gl.getUniformLocation(slots[pslot], name); },"
     "  texture(slot) {"
     "    const t = gl.createTexture();"
     "    gl.bindTexture(gl.TEXTURE_2D, t);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER,"
     "                     gl.LINEAR_MIPMAP_LINEAR);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);"
     "    slots[slot] = t; },"
     "  target(slot, tslot, w, h, mode) {"        ; 0 rgba8, 1 depth, 2 rgba16f
     "    const depthOnly = mode === 1;"
     "    const t = gl.createTexture();"
     "    gl.bindTexture(gl.TEXTURE_2D, t);"
     "    if (depthOnly)"
     "      gl.texImage2D(gl.TEXTURE_2D, 0, gl.DEPTH_COMPONENT24, w, h, 0,"
     "                    gl.DEPTH_COMPONENT, gl.UNSIGNED_INT, null);"
     "    else if (mode === 2)"
     "      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA16F, w, h, 0,"
     "                    gl.RGBA, gl.HALF_FLOAT, null);"
     "    else"
     "      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, w, h, 0,"
     "                    gl.RGBA, gl.UNSIGNED_BYTE, null);"
     "    const f = depthOnly ? gl.NEAREST : gl.LINEAR;"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, f);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, f);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);"
     "    slots[tslot] = t;"
     "    const fb = gl.createFramebuffer();"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, fb);"
     "    if (depthOnly) {"
     "      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT,"
     "                              gl.TEXTURE_2D, t, 0);"
     "      gl.drawBuffers([gl.NONE]);"
     "    } else {"
     "      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0,"
     "                              gl.TEXTURE_2D, t, 0);"
     "      const rb = gl.createRenderbuffer();"
     "      gl.bindRenderbuffer(gl.RENDERBUFFER, rb);"
     "      gl.renderbufferStorage(gl.RENDERBUFFER, gl.DEPTH_COMPONENT16, w, h);"
     "      gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT,"
     "                                 gl.RENDERBUFFER, rb);"
     "    }"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, null);"
     "    slots[slot] = fb; },"
     "  targetMrt(slot, tslot0, n, w, h) {"
     "    const fb = gl.createFramebuffer();"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, fb);"
     "    const bufs = [];"
     "    for (let i = 0; i < n; i++) {"
     "      const t = gl.createTexture();"
     "      gl.bindTexture(gl.TEXTURE_2D, t);"
     "      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA16F, w, h, 0,"
     "                    gl.RGBA, gl.HALF_FLOAT, null);"
     "      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);"
     "      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);"
     "      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);"
     "      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);"
     "      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0 + i,"
     "                              gl.TEXTURE_2D, t, 0);"
     "      bufs.push(gl.COLOR_ATTACHMENT0 + i);"
     "      slots[tslot0 + i] = t;"
     "    }"
     "    const rb = gl.createRenderbuffer();"
     "    gl.bindRenderbuffer(gl.RENDERBUFFER, rb);"
     "    gl.renderbufferStorage(gl.RENDERBUFFER, gl.DEPTH_COMPONENT16, w, h);"
     "    gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT,"
     "                               gl.RENDERBUFFER, rb);"
     "    gl.drawBuffers(bufs);"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, null);"
     "    slots[slot] = fb; },"
     "  slotObject(slot, obj) { slots[slot] = obj; },"
     "  cubemapEmpty(slot, dim, levels) {"
     "    const t = gl.createTexture();"
     "    gl.bindTexture(gl.TEXTURE_CUBE_MAP, t);"
     "    for (let l = 0; l < levels; l++)"
     "      for (let i = 0; i < 6; i++)"
     "        gl.texImage2D(gl.TEXTURE_CUBE_MAP_POSITIVE_X + i, l, gl.RGBA,"
     "                      dim >> l, dim >> l, 0, gl.RGBA,"
     "                      gl.UNSIGNED_BYTE, null);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_MAX_LEVEL,"
     "                     levels - 1);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_MIN_FILTER,"
     "                     gl.LINEAR_MIPMAP_LINEAR);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_MAG_FILTER, gl.LINEAR);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);"
     "    slots[slot] = t; },"
     "  cubeFaceFb(slot, tslot, face, level) {"
     "    const fb = gl.createFramebuffer();"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, fb);"
     "    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0,"
     "                            gl.TEXTURE_CUBE_MAP_POSITIVE_X + face,"
     "                            slots[tslot], level);"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, null);"
     "    slots[slot] = fb; },"
     "  cubeTarget(slot, tslot, dim) {"
     "    const t = gl.createTexture();"
     "    gl.bindTexture(gl.TEXTURE_CUBE_MAP, t);"
     "    for (let i = 0; i < 6; i++)"
     "      gl.texImage2D(gl.TEXTURE_CUBE_MAP_POSITIVE_X + i, 0, gl.RGBA16F,"
     "                    dim, dim, 0, gl.RGBA, gl.HALF_FLOAT, null);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_MIN_FILTER, gl.NEAREST);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_MAG_FILTER, gl.NEAREST);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);"
     "    slots[tslot] = t;"
     "    const rb = gl.createRenderbuffer();"
     "    gl.bindRenderbuffer(gl.RENDERBUFFER, rb);"
     "    gl.renderbufferStorage(gl.RENDERBUFFER, gl.DEPTH_COMPONENT16, dim, dim);"
     "    for (let i = 0; i < 6; i++) {"
     "      const fb = gl.createFramebuffer();"
     "      gl.bindFramebuffer(gl.FRAMEBUFFER, fb);"
     "      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0,"
     "                              gl.TEXTURE_CUBE_MAP_POSITIVE_X + i, t, 0);"
     "      gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT,"
     "                                 gl.RENDERBUFFER, rb);"
     "      slots[slot + i] = fb;"
     "    }"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, null); },"
     "  targetMsaa(slot, rslot, tslot, w, h, samples) {"
     "    const t = gl.createTexture();"
     "    gl.bindTexture(gl.TEXTURE_2D, t);"
     "    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, w, h, 0, gl.RGBA,"
     "                  gl.UNSIGNED_BYTE, null);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);"
     "    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);"
     "    slots[tslot] = t;"
     "    const rf = gl.createFramebuffer();"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, rf);"
     "    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0,"
     "                            gl.TEXTURE_2D, t, 0);"
     "    slots[rslot] = rf;"
     "    const fb = gl.createFramebuffer();"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, fb);"
     "    const cb = gl.createRenderbuffer();"
     "    gl.bindRenderbuffer(gl.RENDERBUFFER, cb);"
     "    gl.renderbufferStorageMultisample(gl.RENDERBUFFER, samples,"
     "                                      gl.RGBA8, w, h);"
     "    gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0,"
     "                               gl.RENDERBUFFER, cb);"
     "    const db = gl.createRenderbuffer();"
     "    gl.bindRenderbuffer(gl.RENDERBUFFER, db);"
     "    gl.renderbufferStorageMultisample(gl.RENDERBUFFER, samples,"
     "                                      gl.DEPTH_COMPONENT16, w, h);"
     "    gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT,"
     "                               gl.RENDERBUFFER, db);"
     "    gl.bindFramebuffer(gl.FRAMEBUFFER, null);"
     "    slots[slot] = fb; },"
     "  tfProgram(slot, vs, fs, attribs, varyings) {"
     "    const p = gl.createProgram();"
     "    gl.attachShader(p, compile(gl.VERTEX_SHADER, vs));"
     "    gl.attachShader(p, compile(gl.FRAGMENT_SHADER, fs));"
     "    if (attribs) String(attribs).split(',').forEach((n, i) => {"
     "      if (n) gl.bindAttribLocation(p, i, n); });"
     "    gl.transformFeedbackVaryings(p, String(varyings).split(','),"
     "                                 gl.INTERLEAVED_ATTRIBS);"
     "    gl.linkProgram(p);"
     "    if (!gl.getProgramParameter(p, gl.LINK_STATUS))"
     "      throw new Error(gl.getProgramInfoLog(p));"
     "    slots[slot] = p; },"
     "  textureUpload(slot, src, premul) {"
     "    if (premul) gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, true);"
     "    gl.bindTexture(gl.TEXTURE_2D, slots[slot]);"
     "    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA,"
     "                  gl.UNSIGNED_BYTE, src);"
     "    gl.generateMipmap(gl.TEXTURE_2D);"
     "    if (premul) gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false); },"
     "  textureData(slot, base, w, h) {"
     "    gl.bindTexture(gl.TEXTURE_2D, slots[slot]);"
     "    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, w, h, 0, gl.RGBA,"
     "                  gl.UNSIGNED_BYTE,"
     "                  new Uint8Array(memory.buffer, base, w * h * 4));"
     "    gl.generateMipmap(gl.TEXTURE_2D); },"
     "  cubemap(slot, base, dim) {"
     "    const t = gl.createTexture();"
     "    gl.bindTexture(gl.TEXTURE_CUBE_MAP, t);"
     "    for (let i = 0; i < 6; i++)"
     "      gl.texImage2D(gl.TEXTURE_CUBE_MAP_POSITIVE_X + i, 0, gl.RGBA,"
     "                    dim, dim, 0, gl.RGBA, gl.UNSIGNED_BYTE,"
     "                    new Uint8Array(memory.buffer,"
     "                                   base + i * dim * dim * 4,"
     "                                   dim * dim * 4));"
     "    gl.generateMipmap(gl.TEXTURE_CUBE_MAP);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_MIN_FILTER,"
     "                     gl.LINEAR_MIPMAP_LINEAR);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_MAG_FILTER, gl.LINEAR);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);"
     "    gl.texParameteri(gl.TEXTURE_CUBE_MAP, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);"
     "    slots[slot] = t; },"
     "  replay(base, end) {"
     "    const u = new Uint32Array(memory.buffer);"
     "    const f = new Float32Array(memory.buffer);"
     "    let p = base >> 2; const stop = end >> 2;"
     "    while (p < stop) switch (u[p++]) {"
     "     case 1: gl.clearColor(f[p], f[p+1], f[p+2], f[p+3]); p += 4;"
     "             gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT); break;"
     "     case 2: gl.useProgram(slots[u[p++]]); break;"
     "     case 3: gl.bindBuffer(gl.ARRAY_BUFFER, slots[u[p++]]); break;"
     "     case 4: gl.bufferData(gl.ARRAY_BUFFER,"
     "               new Float32Array(memory.buffer, u[p], u[p+1] >> 2),"
     "               gl.DYNAMIC_DRAW); p += 2; break;"
     "     case 5: gl.enableVertexAttribArray(u[p]);"
     "             gl.vertexAttribPointer(u[p], u[p+1], gl.FLOAT, false, u[p+2], u[p+3]);"
     "             if (gl.vertexAttribDivisor) gl.vertexAttribDivisor(u[p], 0);"
     "             p += 4; break;"
     "     case 6: gl.uniform1f(slots[u[p]], f[p+1]); p += 2; break;"
     "     case 7: gl.uniform4f(slots[u[p]], f[p+1], f[p+2], f[p+3], f[p+4]); p += 5; break;"
     "     case 8: { const m = u[p] === 0 ? gl.POINTS : u[p] === 1 ? gl.LINES"
     "                : u[p] === 5 ? gl.TRIANGLE_STRIP : gl.TRIANGLES;"
     "               gl.drawArrays(m, u[p+1], u[p+2]); p += 3; break; }"
     "     case 9: gl.viewport(u[p], u[p+1], u[p+2], u[p+3]); p += 4; break;"
     "     case 10: if (u[p] === 1) { const m = u[p+1]; gl.enable(gl.BLEND);"
     "                gl.blendFunc(m === 2 ? gl.ONE : gl.SRC_ALPHA,"
     "                             m === 1 ? gl.ONE"
     "                             : gl.ONE_MINUS_SRC_ALPHA); }"
     "              else gl.disable(gl.BLEND); p += 2; break;"
     "     case 11: gl.activeTexture(gl.TEXTURE0 + u[p]);"
     "              gl.bindTexture(gl.TEXTURE_2D, slots[u[p+1]]); p += 2; break;"
     "     case 12: gl.uniform1i(slots[u[p]], u[p+1]); p += 2; break;"
     "     case 13: gl.uniform2f(slots[u[p]], f[p+1], f[p+2]); p += 3; break;"
     "     case 14: gl.uniformMatrix4fv(slots[u[p]], false,"
     "                f.subarray(p + 1, p + 17)); p += 17; break;"
     "     case 15: if (u[p] === 1) gl.enable(gl.DEPTH_TEST);"
     "              else gl.disable(gl.DEPTH_TEST); p += 1; break;"
     "     case 16: gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, slots[u[p]]);"
     "              p += 1; break;"
     "     case 17: gl.bufferData(gl.ELEMENT_ARRAY_BUFFER,"
     "               new Uint16Array(memory.buffer, u[p], u[p+1] >> 1),"
     "               gl.DYNAMIC_DRAW); p += 2; break;"
     "     case 18: { const m = u[p] === 0 ? gl.POINTS : u[p] === 1 ? gl.LINES"
     "                : u[p] === 5 ? gl.TRIANGLE_STRIP : gl.TRIANGLES;"
     "                gl.drawElements(m, u[p+1], gl.UNSIGNED_SHORT, 0);"
     "                p += 2; break; }"
     "     case 19: gl.uniform3f(slots[u[p]], f[p+1], f[p+2], f[p+3]);"
     "              p += 4; break;"
     "     case 20: gl.bindFramebuffer(gl.FRAMEBUFFER, slots[u[p]]);"
     "              p += 1; break;"
     "     case 21: gl.bindFramebuffer(gl.FRAMEBUFFER, null); break;"
     "     case 22: gl.vertexAttribDivisor(u[p], u[p+1]); p += 2; break;"
     "     case 23: { const m = u[p] === 0 ? gl.POINTS : u[p] === 1 ? gl.LINES"
     "                : u[p] === 5 ? gl.TRIANGLE_STRIP : gl.TRIANGLES;"
     "                gl.drawElementsInstanced(m, u[p+1], gl.UNSIGNED_SHORT,"
     "                                         0, u[p+2]);"
     "                p += 3; break; }"
     "     case 24: gl.uniformMatrix4fv(slots[u[p]], false,"
     "                f.subarray(p + 2, p + 2 + 16 * u[p+1]));"
     "              p += 2 + 16 * u[p+1]; break;"
     "     case 25: gl.activeTexture(gl.TEXTURE0 + u[p]);"
     "              gl.bindTexture(gl.TEXTURE_CUBE_MAP, slots[u[p+1]]);"
     "              p += 2; break;"
     "     case 27: gl.bindVertexArray(slots[u[p]]); p += 1; break;"
     "     case 28: gl.bindVertexArray(null); break;"
     "     case 29: gl.activeTexture(gl.TEXTURE0 + u[p]);"
     "              gl.bindTexture(gl.TEXTURE_CUBE_MAP, null);"
     "              p += 1; break;"
     "     case 30: gl.activeTexture(gl.TEXTURE0 + u[p]);"
     "              gl.bindTexture(gl.TEXTURE_2D, null);"
     "              p += 1; break;"
     "     case 36: gl.bufferData(gl.ELEMENT_ARRAY_BUFFER,"
     "               new Uint32Array(memory.buffer, u[p], u[p+1] >> 2),"
     "               gl.DYNAMIC_DRAW); p += 2; break;"
     "     case 37: { const m = u[p] === 0 ? gl.POINTS : u[p] === 1 ? gl.LINES"
     "                : u[p] === 5 ? gl.TRIANGLE_STRIP : gl.TRIANGLES;"
     "                gl.drawElements(m, u[p+1], gl.UNSIGNED_INT, 0);"
     "                p += 2; break; }"
     "     case 31: gl.bindBufferBase(gl.UNIFORM_BUFFER, u[p],"
     "                                slots[u[p+1]]); p += 2; break;"
     "     case 33: gl.bindBufferBase(gl.TRANSFORM_FEEDBACK_BUFFER, 0,"
     "                                slots[u[p]]); p += 1; break;"
     "     case 34: gl.enable(gl.RASTERIZER_DISCARD);"
     "              gl.beginTransformFeedback(gl.POINTS); break;"
     "     case 35: gl.endTransformFeedback();"
     "              gl.disable(gl.RASTERIZER_DISCARD);"
     "              gl.bindBufferBase(gl.TRANSFORM_FEEDBACK_BUFFER, 0,"
     "                                null); break;"
     "     case 32: gl.bindBuffer(gl.UNIFORM_BUFFER, slots[u[p]]);"
     "              gl.bufferSubData(gl.UNIFORM_BUFFER, 0,"
     "                new Uint8Array(memory.buffer, u[p+1], u[p+2]));"
     "              p += 3; break;"
     "     case 26: gl.bindFramebuffer(gl.READ_FRAMEBUFFER, slots[u[p]]);"
     "              gl.bindFramebuffer(gl.DRAW_FRAMEBUFFER, slots[u[p+1]]);"
     "              gl.blitFramebuffer(0, 0, u[p+2], u[p+3],"
     "                                 0, 0, u[p+2], u[p+3],"
     "                                 gl.COLOR_BUFFER_BIT, gl.NEAREST);"
     "              gl.bindFramebuffer(gl.FRAMEBUFFER, null);"
     "              p += 4; break;"
     "     default: throw new Error('bad gl opcode');"
     "    } } }; };"))

  (define $gl #f)                       ; the replayer handle
  (define $replay #f)

  (define (gl-attach! canvas)
    (js-eval replayer-src)
    (set! $gl (js-call (js-get (js-global) "__goeteia_gl") (js-undefined)
                       canvas (js-get (js-global) "__goeteia_mem")))
    (set! $replay (js-get $gl "replay"))
    $gl)

  ;; optional 4th argument: a comma-joined attribute-name string bound
  ;; to locations 0,1,... before linking (drivers don't otherwise
  ;; guarantee declaration order)
  (define (gl-program! slot vs fs . attribs)
    (if (null? attribs)
        (js-method $gl "program" slot vs fs)
        (js-method $gl "program" slot vs fs (car attribs))))
  (define (gl-buffer! slot) (js-method $gl "buffer" slot))
  (define (gl-uniform! slot pslot name) (js-method $gl "uniform" slot pslot name))
  ;; textures: created LINEAR/CLAMP_TO_EDGE; upload takes a JS canvas
  ;; or image and may be called again to refresh (atlas growth); pass
  ;; #t as the third argument to premultiply alpha on upload (image
  ;; sprites under (cmd-blend! 'premul))
  (define (gl-texture! slot) (js-method $gl "texture" slot))
  ;; an offscreen render target (webgl2): a framebuffer in `slot`
  ;; whose attachment texture lands in `tslot` for later sampling.
  ;; depth-only? = a shadow-map style depth texture, else color+depth
  (define (gl-target! slot tslot w h . depth-only?)
    (js-method $gl "target" slot tslot w h
               (if (and (pair? depth-only?) (car depth-only?)) 1 0)))
  ;; a half-float target (RGBA16F): light in real HDR, tonemap later
  (define (gl-target-hdr! slot tslot w h)
    (js-method $gl "target" slot tslot w h 2))
  ;; a multi render target (webgl2 drawBuffers): one framebuffer in
  ;; `slot` with n half-float color attachments in slots tslot0..
  ;; tslot0+n-1 plus a depth renderbuffer -- a shader with (out ...)
  ;; forms writes them all in one pass.  Filters are NEAREST: a
  ;; G-buffer is read back pixel for pixel, and half-float LINEAR
  ;; would need one more extension for nothing
  (define (gl-target-mrt! slot tslot0 n w h)
    (js-method $gl "targetMrt" slot tslot0 n w h))
  ;; six half-float faces around a point: slots slot..slot+5 become
  ;; framebuffers (one per face, sharing a depth renderbuffer) and
  ;; tslot the cube map they render into -- point-light shadows
  (define (gl-cube-target! slot tslot dim)
    (js-method $gl "cubeTarget" slot tslot dim))
  ;; a multisampled target: render into `slot`, then cmd-resolve!
  ;; blits it into `rslot`, whose texture `tslot` is what you sample
  (define (gl-target-msaa! slot rslot tslot w h samples)
    (js-method $gl "targetMsaa" slot rslot tslot w h samples))
  ;; premul crosses as 1/0: a boolean would convert through js-eval,
  ;; whose nested %js-call would swallow the args already pushed
  (define (gl-texture-upload! slot src . premul)
    (if (or (null? premul) (not (car premul)))
        (js-method $gl "textureUpload" slot src)
        (js-method $gl "textureUpload" slot src 1)))
  ;; a vertex array object (webgl2): record a whole attribute setup
  ;; once, rebind it with one word per frame
  (define (gl-vao! slot) (js-method $gl "vao" slot))
  ;; a uniform buffer (webgl2 + ESSL 300 uniform blocks): shared
  ;; per-frame state every program reads from one upload
  (define (gl-ubo! slot bytes) (js-method $gl "ubo" slot bytes))
  ;; a program whose vertex outputs land in a buffer (interleaved):
  ;; the GPU-side update step of transform-feedback particles
  (define (gl-tf-program! slot vs fs attribs varyings)
    (js-method $gl "tfProgram" slot vs fs attribs varyings))
  ;; wire a program's named block to a binding point
  (define (gl-uniform-block! pslot name binding)
    (js-method $gl "uniformBlock" pslot name binding))
  ;; raw RGBA bytes out of the staging memory -- procedural textures
  (define (gl-texture-data! slot base w h)
    (js-method $gl "textureData" slot base w h))
  ;; a cube map from six dim*dim RGBA faces laid out consecutively at
  ;; base, in +x -x +y -y +z -z order
  (define (gl-cubemap! slot base dim)
    (js-method $gl "cubemap" slot base dim))
  ;; an empty cube map with an explicit mip chain, and a framebuffer
  ;; aimed at one face of one level -- the plumbing (web ibl) uses to
  ;; bake prefiltered environments
  (define (gl-cubemap-empty! slot dim levels)
    (js-method $gl "cubemapEmpty" slot dim levels))
  (define (gl-cube-face-fb! slot tslot face level)
    (js-method $gl "cubeFaceFb" slot tslot face level))
  ;; park a host-owned GL object (say, an XRWebGLLayer's
  ;; framebuffer) in the slot table, so commands can bind it
  (define (gl-slot-object! slot obj)
    (js-method $gl "slotObject" slot obj))

  ;; ---- the encoder: words into the staging memory ----
  (define $base 0)
  (define $p 0)
  (define $draw-count 0)                ; draws encoded this frame
  (define (cmd-region! base) (set! $base base))
  (define (cmd-begin!) (set! $p $base) (set! $draw-count 0))
  (define ($draw!) (set! $draw-count (+ $draw-count 1)))
  (define (u! v) (%mem-i32-set! $p v) (set! $p (+ $p 4)))
  (define (f! v) (%mem-f32-set! $p v) (set! $p (+ $p 4)))

  (define (cmd-clear! r g b a) (u! 1) (f! r) (f! g) (f! b) (f! a))
  (define (cmd-use-program! slot) (u! 2) (u! slot))
  (define (cmd-bind-buffer! slot) (u! 3) (u! slot))
  (define (cmd-buffer-data! offset bytes) (u! 4) (u! offset) (u! bytes))
  (define (cmd-vertex-attrib! loc size stride offset)
    (u! 5) (u! loc) (u! size) (u! stride) (u! offset))
  (define (cmd-uniform1f! slot x) (u! 6) (u! slot) (f! x))
  (define (cmd-uniform4f! slot x y z w)
    (u! 7) (u! slot) (f! x) (f! y) (f! z) (f! w))
  (define (cmd-draw-arrays! mode first count)
    ($draw!) (u! 8) (u! mode) (u! first) (u! count))
  (define (cmd-bind-texture! unit slot) (u! 11) (u! unit) (u! slot))
  (define (cmd-bind-cubemap! unit slot) (u! 25) (u! unit) (u! slot))
  ;; unbind before rendering into a cube target's faces: a cube map
  ;; both attached and bound for sampling is a feedback loop, and
  ;; ANGLE (Chrome) rejects every draw of it
  (define (cmd-unbind-cubemap! unit) (u! 29) (u! unit))
  ;; the 2D twin: post chains sample a target one frame and render
  ;; into it the next -- unbind its unit first, or strict validators
  ;; (WebKit) see the same feedback loop
  (define (cmd-unbind-texture! unit) (u! 30) (u! unit))
  (define (cmd-bind-vao! slot) (u! 27) (u! slot))
  (define (cmd-unbind-vao!) (u! 28))
  (define (cmd-bind-ubo! binding slot) (u! 31) (u! binding) (u! slot))
  (define (cmd-ubo-data! slot base bytes)  ; staging -> uniform buffer
    (u! 32) (u! slot) (u! base) (u! bytes))
  ;; transform feedback: aim the capture at a buffer, then bracket
  ;; the update draw (rasterizer discard on/off rides along)
  (define (cmd-tf-buffer! slot) (u! 33) (u! slot))
  (define (cmd-tf-begin!) (u! 34))
  (define (cmd-tf-end!) (u! 35))
  (define (cmd-uniform1i! slot v) (u! 12) (u! slot) (u! v))
  (define (cmd-uniform2f! slot x y) (u! 13) (u! slot) (f! x) (f! y))
  (define (cmd-uniform3f! slot x y z)
    (u! 19) (u! slot) (f! x) (f! y) (f! z))
  ;; m: a 16-element flonum vector, column-major ((web mat) makes them)
  (define (cmd-uniform-matrix4! slot m)
    (u! 14) (u! slot)
    (let loop ((i 0))
      (when (< i 16)
        (f! (vector-ref m i))
        (loop (+ i 1)))))
  (define (cmd-depth! on?) (u! 15) (u! (if on? 1 0)))
  ;; indexed meshes: a buffer slot bound as the element array, u16
  ;; indices uploaded from the staging memory, one drawElements
  (define (cmd-bind-index! slot) (u! 16) (u! slot))
  ;; 32-bit indices (webgl2): meshes past 65536 vertices
  (define (cmd-index-data32! base bytes) (u! 36) (u! base) (u! bytes))
  (define (cmd-draw-elements32! mode count)
    ($draw!) (u! 37) (u! mode) (u! count))
  (define (cmd-index-data! offset bytes) (u! 17) (u! offset) (u! bytes))
  (define (cmd-draw-elements! mode count)
    ($draw!) (u! 18) (u! mode) (u! count))
  ;; render into an offscreen target, or back to the canvas
  (define (cmd-bind-target! slot) (u! 20) (u! slot))
  (define (cmd-resolve! slot rslot w h)  ; blit msaa -> its resolve fb
    (u! 26) (u! slot) (u! rslot) (u! w) (u! h))
  (define (cmd-bind-canvas!) (u! 21))
  ;; instancing (webgl2): per-instance attributes advance once per
  ;; instance; one draw carries them all
  (define (cmd-attrib-divisor! loc div) (u! 22) (u! loc) (u! div))
  (define (cmd-draw-elements-instanced! mode count n)
    ($draw!) (u! 23) (u! mode) (u! count) (u! n))
  ;; ms: a vector of m4s (16-element flonum vectors) -- one upload
  ;; carries a whole skeleton's joint matrices
  (define (cmd-uniform-matrices! slot ms)
    (u! 24) (u! slot) (u! (vector-length ms))
    (let each ((k 0))
      (when (< k (vector-length ms))
        (let ((m (vector-ref ms k)))
          (let mat ((i 0))
            (when (< i 16)
              (f! (vector-ref m i))
              (mat (+ i 1)))))
        (each (+ k 1)))))
  (define (cmd-pos) $p)                 ; for overflow checks by callers
  (define (cmd-draws) $draw-count)      ; and HUDs counting the frame
  (define (cmd-viewport! x y w h) (u! 9) (u! x) (u! y) (u! w) (u! h))
  ;; blending for translucent draws: (cmd-blend! 'alpha) src-over,
  ;; (cmd-blend! 'add) additive glow, (cmd-blend! 'premul) src-over
  ;; for premultiplied textures, (cmd-blend! 'off) opaque
  (define (cmd-blend! mode)
    (u! 10)
    (case mode
      ((add)    (u! 1) (u! 1))
      ((alpha)  (u! 1) (u! 0))
      ((premul) (u! 1) (u! 2))
      (else     (u! 0) (u! 0))))

  ;; one bridge call replays the whole frame
  (define (cmd-flush!)
    (js-call $replay $gl $base $p)))
