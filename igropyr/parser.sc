(library (igropyr parser)
  (export
    header-parser
    host?
    user-agent?
    accept-language?
    accept-encoding?
    cookie?
    connection?
  )
  (import
    (scheme)
    (igropyr http)
    (igropyr igropyr)
  )

  (define header-parser
    (foreign-procedure "igropyr_header_parser" (string string) string))

  (define host?
    (lambda (x)
      (header-parser x "Host")))

  (define user-agent?
    (lambda (x)
      (header-parser x "User-Agent")))

  (define accept-language?
    (lambda (x)
      (header-parser x "Accept-Language")))

  (define accept-encoding?
    (lambda (x)
      (header-parser x "Accept-Encoding")))

  (define cookie?
    (lambda (x)
      (header-parser x "Cookie")))

  (define connection?
    (lambda (x)
      (header-parser x "Connection")))









)