(library (igropyr http)
  (export
    server
    listen
    set
    response
    callback
    par
  )
  (import
    (scheme)
  )




  (define lib (load-shared-object "./lib/igropyr/httpc.so"))

  (define igropyr_init
    (foreign-procedure "igropyr_init" (string string int) int)
  )

  (define igropyr_res_init
    (foreign-procedure "igropyr_res_init" (iptr) int))

  (define response
    (foreign-procedure "igropyr_response" (int string string) string))
 
   (define par
    (foreign-procedure "par" (string string) boolean))


  (define callback
    (lambda (p)
        (let ((code (foreign-callable p (string string string) string)))
            (lock-object code)
            (foreign-callable-entry-point code))))

  (define ref
    (lambda (str x)
      (if (null? str)
        '()
        (if (equal? (caar str) x)
          (cdar str)
          (ref (cdr str) x)))))

  (define-syntax set
    (lambda (x)
      (syntax-case x ()
        ((_) #''())
        ((_ (e1 e2)) #'(list (cons e1 e2))))))

  (define-syntax listen
    (lambda (x)
      (syntax-case x ()
        ((_) #''())
        ((_ (e1 e2)) #'(list (cons e1 e2)))
        ((_ (e1 e2)(e3 e4)) #'(list (cons e1 e2)(cons e3 e4)))
        ((_ e) #'(cond 
                  ((string? e) (list (cons 'ip e)))
                  ((integer? e) (list (cons 'port e)))
                  (else '())))
        ((_ e1 e2) #'(list (cons 'ip e1)(cons 'port e2))))))

  (define server 
    (lambda (request set listen)
      (let ((staticpath (ref set 'staticpath))
            ;(connections (ref set 'connections))
            ;(keepalive (ref set 'keepalive))
            (ip (ref listen 'ip))
            (port (ref listen 'port)))
        (begin 
          (igropyr_res_init request)
          (igropyr_init
            (if (null? staticpath)
            ""
            staticpath)
        ;(if (null? connections)
        ;   3600
        ;   connections)
        ;(if (null? keepalive)
        ;   36000
        ;   keepalive)
          (if (null? ip)
            "0.0.0.0"
            ip)
          (if (null? port)
            80
            port))))))
  
)

