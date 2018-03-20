(library (igropyr http)
  (export
    server
    listen
    set
    request
    response
    sendfile
    errorpage
    header-parser
    path-parser
    par
  )
  (import
    (scheme)
    (igropyr igropyr)
  )


  (define lib (load-shared-object "./lib/igropyr/httpc.so"))

  (define igr_init
    (foreign-procedure "igr_init" (string string int) int)
  )

  (define igr_request
    (foreign-procedure "igr_handle_request" (iptr iptr) int))

  (define igr_response
    (foreign-procedure "igr_response" (int string string string) string))

  (define igr_errorpage
    (foreign-procedure "igr_errorpage" (int string) string))

  (define header-parser
    (foreign-procedure "igr_header_parser" (string string) string))
 
  (define path-parser
    (foreign-procedure "igr_path_parser" (string int) string))

  (define par
    (foreign-procedure "igr_par" (string string) boolean))


  (define request
    (lambda (info)
        (let ((code (foreign-callable info (string string string) string)))
            (lock-object code)
            (foreign-callable-entry-point code))))

  (define response
    (lambda (status type content)
      (if (list? content)
        (igr_response status type (car content) (cadr content))
        (igr_response status type "" content))))

    (define sendfile
      (lambda (type content)
        (string-append " " content)))


(define-syntax set
    (lambda (x)
      (syntax-case x ()
        ((_) #''())
        ((_ (e1 e2)) #'(list (cons e1 e2)))
        ((_ (e1 e2) (e3 e4) ...) #'(list (cons e1 e2) (cons e3 e4) ...)))))

  (define-syntax listen
    (lambda (x)
      (syntax-case x ()
        ((_) #''())
        ((_ e) #'(cond 
                  ((string? e) (list (cons 'ip e)))
                  ((integer? e) (list (cons 'port e)))
                  (else '())))
        ((_ e1 e2) #'(list (cons 'ip e1)(cons 'port e2))))))

  (define-syntax errorpage
    (lambda (x)
      (syntax-case x ()
        ((_ e) #'(igr_errorpage e ""))
        ((_ e1 e2) #'(igr_errorpage e1 e2)))))

  (define server 
    (lambda (res_get res_post set listen)
      (let ((staticpath (ref set 'staticpath))
            ;(connections (ref set 'connections))
            ;(keepalive (ref set 'keepalive))
            (ip (ref listen 'ip))
            (port (ref listen 'port)))
        (begin 
          (igr_request res_get res_post)
          (igr_init
            (if (null? staticpath)
            ""
            staticpath)
        ;(if (null? connections)
        ;   1024
        ;   connections)
        ;(if (null? keepalive)
        ;   5000
        ;   keepalive)
          (if (null? ip)
            "0.0.0.0"
            ip)
          (if (null? port)
            80
            port))))))




  
)

