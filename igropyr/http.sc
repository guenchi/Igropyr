

(library (igropyr http)
  (export
    server
    listen
    set
  )
  (import
    (scheme)
  )

  (define lib (load-shared-object "./igropyr/src/httpc.so"))

  (define index
    (lambda (str x)
      (if (null? str)
        '()
        (if (equal? (caar str) x)
          (cdar str)
          (index (cdr str) x)))))

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

  (define-syntax set
    (lambda (x)
      (syntax-case x ()
        ((_) #''())
        ((_ (e1 e2)) #'(list (cons e1 e2))))))


  (define igropyr_start
    (foreign-procedure "igropyr_start" (string int string) int)
  )

  (define server 
    (lambda (set listen)
      (let ((ip (index listen 'ip))
            (port (index listen 'port))
            (path (index set 'path)))
        (igropyr_start
          (if (null? ip)
            "0.0.0.0"
            ip)
          (if (null? port)
            80
            port)
          (if (null? path)
            ""
            path)))))
  
)

