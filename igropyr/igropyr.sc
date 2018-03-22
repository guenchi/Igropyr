(library (igropyr igropyr)
  (export
    ref
    val
    str-index
    split
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

    (define str-index
        (lambda (s c)
            (let ((n (string-length s)))
                (let loop ((i 0))
                    (cond 
                        ((>= i n) #f)
                        ((char=? (string-ref s i) c) i)
                        (else (loop (+ i 1))))))))

    (define split
        (lambda (s c)
            (let loop ((s s))
                (if (string=? s "")
                    '()
                    (let ((i (str-index s c)))
                        (if i 
                            (cons (substring s 0 i) (loop (substring s (+ i 1) (string-length s))))
                            (list s)))))))

)
