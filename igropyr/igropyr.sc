(library (igropyr igropyr)
  (export
    ref
    val
    str-index
    split
    list-parser
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
            (letrec* ((len (string-length s))
                (walk (lambda (str begin end rst)
                        (cond 
                            ((>= begin len) rst)
                            ((or (= end len) (char=? (string-ref str end) c))
                                (walk 
                                    str 
                                    (+ end 1)
                                    (+ end 1)
                                    (if (= begin end) 
                                        rst
                                        (cons (substring str begin end) rst))))
                            (else (walk str begin (+ end 1) rst))))))
            (reverse (walk s 0 0 '())))))


    (define list-parser
        (lambda (lst)
            (let loop ((lst lst)(x "{"))
                (if (null? (cdr lst))
                    (string-append x "\"" (caar lst) "\":\"" 
                        (if (list? (cdar lst))
                            (loop (cdar lst) "{")
                            (cdr (car lst))) "\"}")
                    (loop (cdr lst) (string-append x "\"" (caar lst) "\":\"" 
                        (if (list? (cdar lst))
                            (loop (cdar lst) "{")
                            (cdar lst)) "\"," ))))))

)
