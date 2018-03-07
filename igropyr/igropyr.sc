(library (igropyr igropyr)
  (export
    ref
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

)