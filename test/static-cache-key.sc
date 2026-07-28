#!chezscheme
;;; (igropyr express): one file, one static-cache entry.
;;;
;;; Where the filesystem is case-insensitive -- macOS and Windows by
;;; default -- many spellings of a name open the same file. Keying the
;;; cache on the requested path gave each spelling its own entry, so one
;;; asset could occupy 2^letters of them: unbounded memory chosen entirely
;;; by the caller, and, once the capacity ceilings existed, a way to evict
;;; everything with a few dozen requests.
;;;
;;; Sentinel method: rewrite a file's contents while pinning its mtime
;;; with touch -r, so the cached bytes and the on-disk bytes differ and
;;; only a re-read can return the new ones. A variant spelling that
;;; answers with the OLD bytes found the existing entry; one that answers
;;; with the new bytes had an entry of its own.

(import (chezscheme) (igropyr actor) (igropyr express)
        (igropyr http) (igropyr http-client))

(define port 18784)
(define root "/tmp/igropyr-static-cache-key")
(define failures 0)

(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (write-text path text)
  (when (file-exists? path) (delete-file path))
  (call-with-output-file path (lambda (p) (display text p))))

(system (string-append "rm -rf " root " && mkdir -p " root))

;; Does this filesystem fold case at all? Without that there are no
;; variant spellings to collapse and nothing here applies.
(write-text (string-append root "/probe.txt") "p")
(define case-folding?
  (file-exists? (string-append root "/PROBE.TXT")))

(define asset-bytes (* 32 1024))
;; Four assets' worth of budget: five distinct entries would cross it,
;; one shared entry does not. Set low so the test can fill it without
;; writing megabytes to prove a constant.
(define byte-cap (* 4 asset-bytes))
(define variants 6)

;; bit j of k decides the case of the j-th letter -> 2^11 spellings
(define (spelling k)
  (let* ((base "bigasset.bin") (s (string-copy base)))
    (let loop ((i 0) (j 0))
      (cond
        ((= i (string-length base)) s)
        ((char-alphabetic? (string-ref s i))
         (when (odd? (div k (expt 2 j)))
           (string-set! s i (char-upcase (string-ref s i))))
         (loop (+ i 1) (+ j 1)))
        (else (loop (+ i 1) j))))))

(cond
  ((not case-folding?)
   (display "static-cache-key: SKIP -- this filesystem is case-sensitive,\n")
   (display "  so one file has exactly one spelling and there is nothing to\n")
   (display "  collapse. Run on macOS or Windows to cover the folding case.\n")
   (system (string-append "rm -rf " root))
   (exit 0))
  (else
   (let ()
   (write-text (string-append root "/hot.txt") "old")
   (system (string-append "cp -p " root "/hot.txt " root "/stamp"))
   (write-text (string-append root "/bigasset.bin") (make-string asset-bytes #\z))

   (start-scheduler
     (lambda ()
       (let ((app (create-app)))
         (static-cache-limits! #f byte-cap)
         (app-static app "/static" root)
         (app-listen app port)
         (sleep-ms 200)
         (let* ((base (string-append "http://127.0.0.1:"
                                     (number->string port) "/static/"))
                (GET (lambda (name)
                       (http-request 'GET (string-append base name)
                                     '((timeout . 10000)))))
                (body-of (lambda (name)
                           (utf8->string (response-body (GET name))))))
           (check "hot file caches" (equal? "old" (body-of "hot.txt")))
           ;; same mtime, different bytes: only a re-read can see "new"
           (write-text (string-append root "/hot.txt") "new")
           (system (string-append "touch -r " root "/stamp " root "/hot.txt"))
           (check "cached entry still served" (equal? "old" (body-of "hot.txt")))
           (check "a variant spelling finds the same entry"
             (equal? "old" (body-of "HOT.txt")))
           (check "and so does a mixed one"
             (equal? "old" (body-of "hOt.TXT")))

           ;; Spellings of ONE asset. As separate entries they cross the
           ;; byte ceiling and take the hot entry with them; as a single
           ;; shared entry they cost one asset and evict nothing.
           (do ((k 0 (+ k 1))) ((= k variants))
             (GET (spelling k)))
           (check "a variant flood does not evict the hot entry"
             (equal? "old" (body-of "hot.txt")))))
       (system (string-append "rm -rf " root))
       (if (zero? failures)
           (begin (display "static-cache-key: all tests passed\n") (exit 0))
           (begin (display failures) (display " failures\n") (exit 1))))))))
