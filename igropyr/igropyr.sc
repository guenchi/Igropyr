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
                    ((s s)(bgn 0)(end 0)(rst '())(len (string-length s))(quts? #f)(lst '(#\{)))
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
                                            (substring s bgn end) "((" ) rst) len quts? (cons #\{ lst)))
                            (#\}
                                (l s (+ end 1) (+ end 1) 
                                    (cons 
                                        (string-append 
                                            (substring s bgn end) "))") rst) len quts? (cdr lst)))
                            (#\[
                                (l s (+ end 1) (+ end 1) 
                                    (cons
                                        (string-append 
                                            (substring s bgn end) "#(") rst) len quts? (cons #\[ lst)))
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
                                            (if (char=? #\{ (car lst)) ")(" " ")) rst) len quts? lst))
                            (#\"
                                (l s bgn (+ end 1) rst len (not quts?) lst))
                            (else
                                (l s bgn (+ end 1) rst len quts? lst))))))))))


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
