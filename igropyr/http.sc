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


(define igropyr_init
    (foreign-procedure "igropyr_init" (string string int) int)
  )

  (define server 
    (lambda (set listen)
      (let ((staticpath (index set 'staticpath))
            ;(connections (index set 'connections))
            ;(keepalive (index set 'keepalive))
            (ip (index listen 'ip))
            (port (index listen 'port)))
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
            port)))))
  
)

