(library (igropyr igropyr)
  (export
    ref
    val
    split
    json-parser
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


    (define json-parser 
        (lambda (s)
            (read (open-input-string
                (let l
                    ((s s)(bgn 0)(end 0)(rst '())(len (string-length s))(quts? #f)(lst '(#t)))
                    (cond
                        ((= end len)
                            (apply string-append (reverse rst)))
                        ((and quts? (not (char=? (string-ref s end) #\")))
                            (l s bgn (+ end 1) rst len quts? lst))
                        (else
                          (case (string-ref s end)
                            (#\{
                                (l s (+ end 1) (+ end 1) 
                                    (cons 
                                        (string-append 
                                            (substring s bgn end) "((" ) rst) len quts? (cons #t lst)))
                            (#\}
                                (l s (+ end 1) (+ end 1) 
                                    (cons 
                                        (string-append 
                                            (substring s bgn end) "))") rst) len quts? (cdr lst)))
                            (#\[
                                (l s (+ end 1) (+ end 1) 
                                    (cons
                                        (string-append 
                                            (substring s bgn end) "#(") rst) len quts? (cons #f lst)))
                            (#\]
                                (l s (+ end 1) (+ end 1) 
                                    (cons 
                                        (string-append 
                                            (substring s bgn end) ")") rst) len quts? (cdr lst)))
                            (#\:
                                (l s (+ end 1) (+ end 1) 
                                    (cons 
                                        (string-append 
                                            (substring s bgn end) " . ") rst) len quts? lst))
                            (#\,
                                (l s (+ end 1) (+ end 1) 
                                    (cons 
                                        (string-append 
                                            (substring s bgn end) 
                                            (if (car lst) ")(" " ")) rst) len quts? lst))
                            (#\"
                                (l s bgn (+ end 1) rst len (not quts?) lst))
                            (else
                                (l s bgn (+ end 1) rst len quts? lst))))))))))


    (define list-parser
        (lambda (lst)
            (define f
                (lambda (x)
                    (if (string? x) 
                        (string-append "\"" x "\"") 
                        (number->string x))))
            (define v
                (lambda (x)
                    (if (= x 0) "" ",")))
            (define q
                (lambda (x)
                    (if (vector? x) "[" "{")))
            (let l ((lst lst)(x (q lst)))
                (if (vector? lst)
                    (string-append x 
                        (let t ((len (vector-length lst))(n 0)(y ""))
                            (if (< n len)
                                (t len (+ n 1)
                                    (if (atom? (vector-ref lst n))
                                        (if (vector? (vector-ref lst n))
                                            (l (vector-ref lst n) (string-append y (v n) "["))
                                            (string-append y (v n) (f (vector-ref lst n))))
                                        (l (vector-ref lst n) (string-append y (v n) "{"))))
                                (string-append y "]"))))
                    (if (null? (cdr lst))
                        (string-append x (f (caar lst)) ":"
                            (if (list? (cdar lst))
                                (l (cdar lst) (q (cdar lst)))
                                (if (vector? (cdar lst))
                                    (l (cdar lst) x)
                                    (f (cdar lst)))) "}")
                        (l (cdr lst)
                            (if (list? (cdar lst))
                                (string-append x (f (caar lst)) ":" (l (cdar lst) "{") ",")
                                (if (vector? (cdar lst))
                                    (string-append x (f (caar lst)) ":" (l (cdar lst) "[") ",")
                                    (string-append x (f (caar lst)) ":" (f (cdar lst)) ",")))))))))
                                     
                                     

)
