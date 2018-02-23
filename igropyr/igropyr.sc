(library (igropyr igropyr)
  (export
    listen
  )
  (import 
    (scheme))

  (define lib (load-shared-object "./igropyr/libigropyr.so"))

  (define igropyr_start
    (foreign-procedure "igropyr_start" (int) int)
  )

  (define listen
    (lambda (port)
      (igropyr_start port)))
)