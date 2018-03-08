(library (igropyr igropyr)
  (export
    ref
    val
  )
  (import
    (scheme)
  )

  (define ref
    (lambda (str x)
      (if (null? str)
        '()
        (if (equal? (caar str) x)
          (cdar str)
          (ref (cdr str) x)))))
 
  (define val
      (lambda (str x)
          (if (null? str)
               '()
               (if (equal? (cdar str) x)
                    (caar str)
                    (val (cdr str) x)))))

)
