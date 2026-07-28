#!chezscheme
;;; Static-cache entry and aggregate byte ceilings, including gzip bodies.

(import (chezscheme) (igropyr actor) (igropyr express)
        (igropyr http) (igropyr http-client))

(define port 18781)
(define root "/tmp/igropyr-static-cache-capacity")
(define failures 0)

(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (write-text path text)
  (call-with-output-file path (lambda (p) (display text p))))

(system (string-append "rm -rf " root " && mkdir -p " root))

;; One primed entry plus 4096 distinct inserts crosses the entry ceiling.
(do ((i 0 (+ i 1))) ((= i 4097))
  (write-text
    (string-append root "/entry-" (number->string i) ".txt")
    (if (= i 0) "old" "x")))
(system (string-append "cp -p " root "/entry-0.txt " root "/entry-stamp"))

;; Bodies alone reach the byte ceiling; gzip requests also exercise the
;; compressed-representation accounting path.
(define one-mib (* 1024 1024))
(define big-body (make-string one-mib #\x))
(do ((i 0 (+ i 1))) ((= i 65))
  (write-text
    (string-append root "/byte-" (number->string i) ".txt")
    (if (= i 0)
        (string-append "A" (substring big-body 1 one-mib))
        big-body)))
(system (string-append "cp -p " root "/byte-0.txt " root "/byte-stamp"))

(start-scheduler
  (lambda ()
    (let ((app (create-app)))
      (app-static app "/static" root)
      (app-listen app port)
      (sleep-ms 200)
      (let* ((base (string-append "http://127.0.0.1:"
                                  (number->string port) "/static/"))
             (GET (lambda (name)
                    (http-request 'GET (string-append base name)
                                  '((timeout . 10000)))))
             (GET-GZIP
               (lambda (name)
                 (http-request 'GET (string-append base name)
                   '((headers . (("Accept-Encoding" . "gzip")))
                     (timeout . 10000))))))
        (check "prime entry-count sentinel"
          (= 200 (response-status (GET "entry-0.txt"))))
        (delete-file (string-append root "/entry-0.txt"))
        (write-text (string-append root "/entry-0.txt") "new")
        (system (string-append "touch -r " root "/entry-stamp "
                               root "/entry-0.txt"))
        (let loop ((i 1) (ok #t))
          (if (= i 4097)
              (check "fill entry-count ceiling" ok)
              (let ((r (GET (string-append "entry-"
                                           (number->string i) ".txt"))))
                (loop (+ i 1) (and ok (= 200 (response-status r)))))))
        (check "entry ceiling evicts the primed sentinel"
          (equal? "new"
                  (utf8->string (response-body (GET "entry-0.txt")))))

        (check "prime byte-count sentinel"
          (= 200 (response-status (GET "byte-0.txt"))))
        (delete-file (string-append root "/byte-0.txt"))
        (write-text (string-append root "/byte-0.txt")
          (string-append "B" (substring big-body 1 one-mib)))
        (system (string-append "touch -r " root "/byte-stamp "
                               root "/byte-0.txt"))
        (let loop ((i 1) (ok #t))
          (if (= i 65)
              (check "fill byte/gzip ceiling" ok)
              (let ((r (GET-GZIP (string-append "byte-"
                                                (number->string i) ".txt"))))
                (loop (+ i 1) (and ok (= 200 (response-status r)))))))
        (check "byte/gzip ceiling evicts the primed sentinel"
          (= (char->integer #\B)
             (bytevector-u8-ref
               (response-body (GET "byte-0.txt")) 0)))))
    (system (string-append "rm -rf " root))
    (if (zero? failures)
        (begin
          (display "static-cache-capacity: all tests passed\n")
          (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
