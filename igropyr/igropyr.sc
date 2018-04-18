;  MIT License

;  Copyright guenchi (c) 2018 
         
;  Permission is hereby granted, free of charge, to any person obtaining a copy
;  of this software and associated documentation files (the "Software"), to deal
;  in the Software without restriction, including without limitation the rights
;  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
;  copies of the Software, and to permit persons to whom the Software is
;  furnished to do so, subject to the following conditions:
         
;  The above copyright notice and this permission notice shall be included in all
;  copies or substantial portions of the Software.
         
;  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
;  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
;  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
;  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
;  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
;  SOFTWARE.




(library (igropyr igropyr)
  (export
    ref
    val
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
 

)
