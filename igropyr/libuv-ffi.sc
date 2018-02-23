(library (igropyr libuv-ffi)
  (export
    UV_RUN_DEFAULT
    uv_default_loop
    uv_run
    )
  (import (scheme))

  (define lib-name
    (case (machine-type)
      ((a6nt i3nt ta6nt ti3nt) "C:\\Program Files\\libuv\\libuv.dll")
      ((a6le i3le ta6le ti3le) "/usr/local/lib/libuv.so")
      ((a6osx i3osx ta6osx ti3osx) "/usr/local/lib/libuv.dylib")
      (else "libuv.so")))

  (define lib (load-shared-object lib-name))

  (define UV_RUN_DEFAULT 0)

  (define uv_default_loop
    (foreign-procedure "uv_default_loop" () iptr))

  (define uv_run
    (foreign-procedure "uv_run" (iptr int) int)
  )
)