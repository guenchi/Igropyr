#!chezscheme
;;; test/platform-candidates.sc -- the shared-library candidate lists name
;;; every Homebrew prefix.
;;;
;;; Homebrew installs under /opt/homebrew on Apple silicon and under
;;; /usr/local on x86_64. A macOS candidate list naming one prefix loads on
;;; one kind of machine and can fail on the other: on an x86_64 macOS 15
;;; host with libuv 1.52.1 installed under /usr/local, the list
;;; ("/opt/homebrew/lib/libuv.1.dylib" "libuv.1.dylib" "libuv.dylib") ended
;;; in "could not load any shared library candidate" (2026-10-01) -- the bare
;;; names were not found there.
;;;
;;; THE LISTS ARE PURE FUNCTIONS OF THE OS, so every machine's answer is read
;;; here, on any machine. That is what these rows can show. What they cannot
;;; show is that a library actually loads on an x86_64 Mac; only a run on one
;;; says that.
;;;
;;; ON THE TREE BEFORE THE CHANGE THIS FILE DOES NOT LOAD (the names it
;;; imports do not exist), which is a failure but not a measurement. Its rows
;;; are shown to discriminate by mutants of the change instead.
;;;
;;; THE LISTS ARE COMPARED WHOLE. A list is finite, so "exactly this list" is
;;; a criterion that closes; "contains these, in this order" lets an entry be
;;; put in front or a duplicate be put behind.
;;;
;;; WHAT IS NOT SHOWN: that the two loaders pass these lists to the loader
;;; unchanged. The rows at the end read the source for the call and for a
;;; path spelled outside platform.sc; a loader that built a path from pieces
;;; and ignored the helper's answer would pass them.

(import (chezscheme)
        (only (igropyr platform)
              platform-os
              homebrew-prefixes shared-object-candidates
              libuv-candidates quickjs-candidates))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define (prefix? p s)
  (and (<= (string-length p) (string-length s))
       (string=? (substring s 0 (string-length p)) p)))
(define (contains? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (and (<= (+ i m) n) (or (string=? (substring s i (+ i m)) sub) (loop (+ i 1)))))))
(define (index-of x xs)
  (let loop ((xs xs) (i 0))
    (cond ((null? xs) #f) ((equal? (car xs) x) i) (else (loop (cdr xs) (+ i 1))))))
;; xs appear in ys in the same relative order
(define (subsequence? xs ys)
  (cond ((null? xs) #t)
        ((null? ys) #f)
        ((equal? (car xs) (car ys)) (subsequence? (cdr xs) (cdr ys)))
        (else (subsequence? xs (cdr ys)))))
(define (last-n xs n) (list-tail xs (- (length xs) n)))

;; ---- the prefixes -----------------------------------------------------------
(check "both Homebrew prefixes are known, Apple silicon's first"
       (equal? homebrew-prefixes '("/opt/homebrew" "/usr/local"))
       homebrew-prefixes)

;; ---- libuv ------------------------------------------------------------------
(let ((c (libuv-candidates 'macos)))
  (for-each
    (lambda (p)
      (check (string-append "libuv on macOS: " p "/lib/libuv.1.dylib is a candidate")
             (member (string-append p "/lib/libuv.1.dylib") c) c)
      ;; the formula's own directory exists whether or not it is linked
      (check (string-append "libuv on macOS: " p "/opt/libuv/lib/libuv.1.dylib is a candidate")
             (member (string-append p "/opt/libuv/lib/libuv.1.dylib") c) c))
    '("/opt/homebrew" "/usr/local"))
  (check "libuv on macOS: the first candidate is the one Apple silicon loaded before the change"
         (equal? (car c) "/opt/homebrew/lib/libuv.1.dylib") (car c))
  (check "libuv on macOS: the bare names come last, in the order they had"
         (equal? (last-n c 2) '("libuv.1.dylib" "libuv.dylib")) c)
  (check "libuv on macOS: exactly these six, in this order"
         (equal? c '("/opt/homebrew/lib/libuv.1.dylib"
                     "/opt/homebrew/opt/libuv/lib/libuv.1.dylib"
                     "/usr/local/lib/libuv.1.dylib"
                     "/usr/local/opt/libuv/lib/libuv.1.dylib"
                     "libuv.1.dylib" "libuv.dylib"))
         c))
(check "libuv on FreeBSD: unchanged"
       (equal? (libuv-candidates 'freebsd) '("/usr/local/lib/libuv.so.1" "libuv.so.1" "libuv.so"))
       (libuv-candidates 'freebsd))
(check "libuv on Linux: unchanged"
       (equal? (libuv-candidates 'linux) '("libuv.so.1" "libuv.so"))
       (libuv-candidates 'linux))

;; ---- OpenSSL: built from the same prefixes, and what it answered before ------
(check "libcrypto on macOS: the four names it had, in the order it had them"
       (equal? (shared-object-candidates "libcrypto" 'macos)
               '("/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"
                 "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib"
                 "libcrypto.3.dylib" "libcrypto.dylib"))
       (shared-object-candidates "libcrypto" 'macos))
(check "libssl on FreeBSD and Linux: unchanged"
       (and (equal? (shared-object-candidates "libssl" 'freebsd) '("libssl.so.3" "libssl.so.1.1" "libssl.so"))
            (equal? (shared-object-candidates "libssl" 'linux) '("libssl.so.3" "libssl.so.1.1" "libssl.so")))
       (shared-object-candidates "libssl" 'freebsd))
(check "the one-argument form answers for THIS host's OS"
       (equal? (shared-object-candidates "libcrypto")
               (shared-object-candidates "libcrypto" platform-os))
       platform-os (shared-object-candidates "libcrypto"))
(check "and the macOS and FreeBSD answers differ, so that row can tell them apart"
       (not (equal? (shared-object-candidates "libcrypto" 'macos)
                    (shared-object-candidates "libcrypto" 'freebsd))))

;; ---- QuickJS ------------------------------------------------------------------
;; The list before the change, entry for entry. Off macOS it is the answer,
;; unchanged. On macOS the two Homebrew entries are each followed by the same
;; path under the other prefix; every old entry is still there, in the same
;; relative order. Which library loads CAN differ on one kind of host: where
;; no earlier candidate loads and both libraries sit under /usr/local, the
;; new /usr/local/lib/libqjs.dylib is taken where libquickjs.dylib was
;; before. That is the rule this list already had -- libqjs first.
(define quickjs-before
  '("libqjs.dylib" "libqjs.so"
    "/opt/homebrew/lib/libqjs.dylib"
    "/usr/local/lib/libqjs.so" "/usr/local/lib/libqjs.so.0" "/usr/lib/libqjs.so"
    "libquickjs.dylib" "libquickjs.so"
    "/opt/homebrew/lib/quickjs/libquickjs.dylib"
    "/usr/local/lib/libquickjs.so" "/usr/local/lib/libquickjs.so.0"
    "/usr/local/lib/quickjs/libquickjs.so"
    "/usr/lib/libquickjs.so" "/usr/lib/quickjs/libquickjs.so"))
(define quickjs-macos
  '("libqjs.dylib" "libqjs.so"
    "/opt/homebrew/lib/libqjs.dylib" "/usr/local/lib/libqjs.dylib"
    "/usr/local/lib/libqjs.so" "/usr/local/lib/libqjs.so.0" "/usr/lib/libqjs.so"
    "libquickjs.dylib" "libquickjs.so"
    "/opt/homebrew/lib/quickjs/libquickjs.dylib" "/usr/local/lib/quickjs/libquickjs.dylib"
    "/usr/local/lib/libquickjs.so" "/usr/local/lib/libquickjs.so.0"
    "/usr/local/lib/quickjs/libquickjs.so"
    "/usr/lib/libquickjs.so" "/usr/lib/quickjs/libquickjs.so"))
(for-each
  (lambda (os)
    (let* ((c (quickjs-candidates os))
           (tag (symbol->string os))
           (qjs (filter (lambda (s) (contains? s "libqjs")) c))
           (quickjs (filter (lambda (s) (contains? s "libquickjs")) c)))
      (check (string-append "quickjs on " tag ": every entry it had is still there, in the same order")
             (subsequence? quickjs-before c) c)
      (check (string-append "quickjs on " tag ": exactly the expected list")
             (equal? c (if (eq? os 'macos) quickjs-macos quickjs-before)) c)
      (check (string-append "quickjs on " tag ": every candidate is a libqjs or a libquickjs")
             (= (length c) (+ (length qjs) (length quickjs))) c)
      ;; THE ORDER THAT MATTERS: a libquickjs loaded first poisons the symbol
      ;; namespace for a libqjs loaded after it, so every libqjs comes first.
      (check (string-append "quickjs on " tag ": every libqjs candidate comes before the first libquickjs")
             (and (pair? qjs) (pair? quickjs)
                  (< (index-of (car (last-pair qjs)) c) (index-of (car quickjs) c)))
             c)))
  '(macos freebsd linux))
(let ((c (quickjs-candidates 'macos)))
  (for-each
    (lambda (p)
      (check (string-append "quickjs on macOS: " p "/lib/libqjs.dylib is a candidate")
             (member (string-append p "/lib/libqjs.dylib") c) c)
      (check (string-append "quickjs on macOS: " p "/lib/quickjs/libquickjs.dylib is a candidate")
             (member (string-append p "/lib/quickjs/libquickjs.dylib") c) c))
    '("/opt/homebrew" "/usr/local")))

;; ---- nobody else spells a prefix ----------------------------------------------
;; A TRIPWIRE, NOT A PROOF. It reads the code lines of the library sources
;; (everything before the first ';' on a line) for a quoted Homebrew path. It
;; would miss a path built from pieces. The control is platform.sc itself,
;; which must be seen to spell them, or the scan is seeing nothing.
(define (code-lines-with path needle)
  (call-with-input-file path
    (lambda (p)
      (let loop ((n 0))
        (let ((l (get-line p)))
          (if (eof-object? l)
              n
              (let* ((semi (let scan ((i 0))
                             (cond ((= i (string-length l)) i)
                                   ((char=? (string-ref l i) #\;) i)
                                   (else (scan (+ i 1))))))
                     (code (substring l 0 semi)))
                (loop (if (contains? code needle) (+ n 1) n)))))))))
(define needles '("\"/opt/homebrew" "\"/usr/local"))
(for-each
  (lambda (needle)
    (check (string-append "control: the scan sees platform.sc spell " needle)
           (> (code-lines-with "platform.sc" needle) 0)
           (code-lines-with "platform.sc" needle)))
  needles)
(let ((sources (filter (lambda (f)
                         (and (> (string-length f) 3)
                              (string=? (substring f (- (string-length f) 3) (string-length f)) ".sc")
                              (not (string=? f "platform.sc"))))
                       (directory-list "."))))
  ;; the two files this is about must be among those read, or a run from the
  ;; wrong directory would scan nothing and pass
  (for-each
    (lambda (f) (check (string-append "the scan reads " f) (member f sources)))
    '("libuv.sc" "quickjs.sc"))
  (for-each
    (lambda (f)
      (for-each
        (lambda (needle)
          (check (string-append f " spells no " needle " path of its own")
                 (eqv? (code-lines-with f needle) 0)
                 (code-lines-with f needle)))
        needles))
    sources))
;; and the two loaders ask platform.sc for their lists
(check "libuv.sc passes (libuv-candidates platform-os) to the loader"
       (eqv? (code-lines-with "libuv.sc" "(load-first-shared-object! 'libuv (libuv-candidates platform-os))") 1)
       (code-lines-with "libuv.sc" "(libuv-candidates"))
(check "quickjs.sc takes (quickjs-candidates platform-os)"
       (eqv? (code-lines-with "quickjs.sc" "(quickjs-candidates platform-os)") 1)
       (code-lines-with "quickjs.sc" "(quickjs-candidates"))

(if (zero? failures)
    (begin (display "platform-candidates: all tests passed\n") (exit 0))
    (begin (display "platform-candidates: ") (display failures) (display " failed\n") (exit 1)))
