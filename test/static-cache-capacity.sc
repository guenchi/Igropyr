#!chezscheme
;;; Static-cache entry and aggregate byte ceilings, including gzip bodies.
;;;
;;; The ceilings are set down to numbers this test can fill. Proving the
;;; behaviour at the shipped defaults would mean writing 64 MiB and 4096
;;; files on every suite run purely to reach a constant; the behaviour
;;; under test is the same at any ceiling.
;;;
;;; Sentinel method throughout: rewrite a file's contents while pinning
;;; its mtime with touch -r, so cached bytes and on-disk bytes differ and
;;; only a re-read returns the new ones. Stale means the entry survived.

(import (chezscheme) (igropyr actor) (igropyr express)
        (igropyr http) (igropyr http-client))

(define port 18781)
;; Relative on purpose: file-realpath returns an absolute cache key. The
;; request spelling still needs a bounded hot lookup and must address the
;; same entry when adding a lazy gzip representation.
(define root "igropyr/test/tmp-static-cache-capacity")
(define failures 0)

(define (check label ok)
  (unless ok
    (set! failures (+ failures 1))
    (display "FAIL ") (display label) (newline)))

(define (write-text path text)
  (call-with-output-file path (lambda (p) (display text p))))

(system (string-append "rm -rf " root " && mkdir -p " root))

(define entry-cap 32)
(define chunk (* 16 1024))                 ; one cached body
(define byte-cap (* 9 chunk))              ; all nine plain bodies fit

(write-text (string-append root "/hot.txt") "cached")

;; One body that fits the normal per-file policy but can never fit this
;; test's aggregate budget. It must be served without entering the cache.
(define oversize-bytes (+ byte-cap 1))
(write-text (string-append root "/oversize.txt")
  (string-append "A" (make-string (- oversize-bytes 1) #\a)))
(system (string-append "cp -p " root "/oversize.txt " root "/oversize-stamp"))

;; Sentinel for lowering the byte ceiling below an already-cached body.
(write-text (string-append root "/lowered.txt")
  (string-append "L" (make-string (- chunk 1) #\l)))
(system (string-append "cp -p " root "/lowered.txt " root "/lowered-stamp"))

;; One primed entry plus entry-cap distinct inserts crosses the count.
(do ((i 0 (+ i 1))) ((= i (+ entry-cap 1)))
  (write-text
    (string-append root "/entry-" (number->string i) ".txt")
    (if (= i 0) "old" "x")))
(system (string-append "cp -p " root "/entry-0.txt " root "/entry-stamp"))

;; Bodies alone reach the byte ceiling; the gzip requests also exercise
;; the compressed-representation accounting path. Compressible content
;; that is not all one byte, so the gzip is not a rounding error.
(define (filler seed)
  (let ((s (make-string chunk)))
    (do ((i 0 (+ i 1))) ((= i chunk) s)
      (string-set! s i
        (integer->char (+ 97 (mod (+ seed (* i 7) (div i 31)) 26)))))))
(do ((i 0 (+ i 1))) ((= i 9))
  (write-text
    (string-append root "/byte-" (number->string i) ".txt")
    (filler i)))
(system (string-append "cp -p " root "/byte-0.txt " root "/byte-stamp"))

(start-scheduler
  (lambda ()
    (let ((app (create-app)))
      (static-cache-limits! entry-cap byte-cap)
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
        (check "serve an entry larger than the byte ceiling"
          (= 200 (response-status (GET "oversize.txt"))))
        (delete-file (string-append root "/oversize.txt"))
        (write-text (string-append root "/oversize.txt")
          (string-append "B" (make-string (- oversize-bytes 1) #\b)))
        (system (string-append "touch -r " root "/oversize-stamp "
                               root "/oversize.txt"))
        (check "an entry larger than the byte ceiling is not cached"
          (= (char->integer #\B)
             (bytevector-u8-ref (response-body (GET "oversize.txt")) 0)))

        ;; A relative root differs from file-realpath's canonical key. The
        ;; first request spelling is kept hot without creating alias entries.
        ;; Eviction must discharge the bytes, not just drop the mapping.
        ;; A bare delete leaves the counter charged forever, and the only
        ;; symptom is the ceiling tripping on every later store -- which no
        ;; assertion about content would ever notice.
        (let ((before (cdr (assq 'bytes (static-cache-stats)))))
          (check "evict-probe caches" (= 200 (response-status (GET "hot.txt"))))
          (check "evict-probe charged bytes"
            (> (cdr (assq 'bytes (static-cache-stats))) before))
          (delete-file (string-append root "/hot.txt"))
          (sleep-ms 1100)
          (check "evicting a deleted file observes it gone"
            (= 404 (response-status (GET "hot.txt"))))
          (check "eviction discharges the bytes it charged"
            (= before (cdr (assq 'bytes (static-cache-stats))))))
        (write-text (string-append root "/hot.txt") "cached")

        (check "prime relative-root hot entry"
          (= 200 (response-status (GET "hot.txt"))))
        (delete-file (string-append root "/hot.txt"))
        (check "relative-root hit avoids a second filesystem lookup"
          (equal? "cached"
                  (utf8->string (response-body (GET "hot.txt")))))

        (check "prime entry-count sentinel"
          (= 200 (response-status (GET "entry-0.txt"))))
        (delete-file (string-append root "/entry-0.txt"))
        (write-text (string-append root "/entry-0.txt") "new")
        (system (string-append "touch -r " root "/entry-stamp "
                               root "/entry-0.txt"))
        (let loop ((i 1) (ok #t))
          (if (= i (+ entry-cap 1))
              (check "fill entry-count ceiling" ok)
              (let ((r (GET (string-append "entry-"
                                           (number->string i) ".txt"))))
                (loop (+ i 1) (and ok (= 200 (response-status r)))))))
        (check "entry ceiling evicts the primed sentinel"
          (equal? "new"
                  (utf8->string (response-body (GET "entry-0.txt")))))

        ;; Force the count ceiling to clear the preceding small entries, so
        ;; the byte phase starts with exactly its sentinel body.
        (static-cache-limits! 1 byte-cap)
        (check "prime byte-count sentinel"
          (= 200 (response-status (GET "byte-0.txt"))))
        (static-cache-limits! entry-cap byte-cap)
        (delete-file (string-append root "/byte-0.txt"))
        (write-text (string-append root "/byte-0.txt")
          (string-append "B" (substring (filler 0) 1 chunk)))
        (system (string-append "touch -r " root "/byte-stamp "
                               root "/byte-0.txt"))
        (let loop ((i 1) (ok #t))
          (if (= i 9)
              (check "fill byte/gzip ceiling" ok)
              (let ((r (GET-GZIP (string-append "byte-"
                                                (number->string i) ".txt"))))
                (loop (+ i 1) (and ok (= 200 (response-status r)))))))
        (check "byte/gzip ceiling evicts the primed sentinel"
          (= (char->integer #\B)
             (bytevector-u8-ref
               (response-body (GET "byte-0.txt")) 0)))

        (check "prime limit-reduction sentinel"
          (= 200 (response-status (GET "lowered.txt"))))
        (delete-file (string-append root "/lowered.txt"))
        (write-text (string-append root "/lowered.txt")
          (string-append "N" (make-string (- chunk 1) #\n)))
        (system (string-append "touch -r " root "/lowered-stamp "
                               root "/lowered.txt"))
        (static-cache-limits! #f (- chunk 1))
        ;; This store is skipped because the incoming item is also too large;
        ;; it must still clear entries left above the newly lowered ceiling.
        (check "serve oversized item after lowering the ceiling"
          (= 200 (response-status (GET "oversize.txt"))))
        (check "lowered ceiling clears the existing oversized cache"
          (= (char->integer #\N)
             (bytevector-u8-ref
               (response-body (GET "lowered.txt")) 0)))))
    (system (string-append "rm -rf " root))
    (if (zero? failures)
        (begin
          (display "static-cache-capacity: all tests passed\n")
          (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
