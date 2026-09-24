#!chezscheme
;;; test/https-large-file.sc -- a TLS connection never carries plaintext.
;;;
;;; A static file above express's per-file cache cap (1 MiB) is not held in
;;; memory; it is streamed from a C buffer with tcp-write-foreign!. That
;;; export did not go through the TLS dispatcher that tcp-writev! is, so on an
;;; HTTPS listener the file's bytes went onto the connection unencrypted
;;; (2026-09-07 review, R01). The client sees a TLS record-layer failure; an
;;; observer on the link sees the file.
;;;
;;; THE PROPERTY IS ASSERTED ON THE WIRE, not inferred from a failed download:
;;; the client reaches the server through a relay that records every byte the
;;; server sends, and the file carries a sentinel string. Over TLS the
;;; sentinel must not appear in what the relay recorded.
;;;
;;; THE PLAINTEXT TWIN IS WHAT MAKES THAT ABSENCE MEAN SOMETHING. The same
;;; file through the same relay over plain HTTP must show the sentinel;
;;; otherwise "not found" could equally be a relay that recorded nothing or a
;;; search that cannot find anything. Each run also asserts the relay saw at
;;; least as many bytes as the file holds.
;;;
;;; THE TRANSPORT CELL CALLS THE EXPORT DIRECTLY. The guarantee belongs to
;;; tcp-write-foreign! for any caller, not to the one caller in http.sc. It
;;; also checks the export's own contract -- the source buffer is the caller's
;;; again the moment the call returns -- by overwriting the buffer immediately
;;; after the call: a TLS path that kept the pointer instead of copying would
;;; deliver the overwritten bytes.
;;;
;;; SCOPE, STATED SO THE GREEN IS NOT READ AS MORE. These cells pass #f as
;;; on-done and do not read the return value, and nothing here contends for the
;;; TLS write gate or retires a connection mid-write. So they say nothing about
;;; "on-done is called exactly once" or about what an immediate raw-write
;;; failure returns on the TLS path -- both open in the queue (F2, F1), both
;;; older than this cell.
;;;
;;; Needs the openssl CLI (test/tls-certs.sh). No injection seams.

(import (chezscheme)
        (igropyr actor) (igropyr tcp) (igropyr http) (igropyr http-client) (igropyr express)
        (igropyr tls)
        (only (igropyr libuv) now-ms))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define dir "/tmp/igropyr-https-large-file")
(system (string-append "sh igropyr/test/tls-certs.sh " dir " >/dev/null"))
(putenv "SSL_CERT_FILE" (string-append dir "/ca.pem"))
(define (in-dir f) (string-append dir "/" f))
(system (string-append "mkdir -p " (in-dir "files")))

(define tls-port 18710)
(define plain-port 18711)
(define tls-relay 18712)
(define plain-relay 18713)

;; ---- the file: above the 1 MiB per-file cache cap, full of a sentinel ----
(define sentinel
  (string->utf8 "R01-SENTINEL-7f3a9c-must-never-appear-in-plaintext-on-a-TLS-link|"))
(define file-size (+ (* 1024 1024) (* 256 1024)))
(define payload
  (let ((bv (make-bytevector file-size)) (m (bytevector-length sentinel)))
    (do ((i 0 (+ i 1))) ((= i file-size) bv)
      (bytevector-u8-set! bv i (bytevector-u8-ref sentinel (mod i m))))))
(call-with-port (open-file-output-port (in-dir "files/big.bin") (file-options no-fail))
  (lambda (p) (put-bytevector p payload)))

(define (contains? hay needle)
  (let ((n (bytevector-length hay)) (m (bytevector-length needle)))
    (let scan ((i 0))
      (cond ((> (+ i m) n) #f)
            ((let cmp ((k 0))
               (cond ((= k m) #t)
                     ((= (bytevector-u8-ref hay (+ i k)) (bytevector-u8-ref needle k)) (cmp (+ k 1)))
                     (else #f)))
             #t)
            (else (scan (+ i 1)))))))
(define (cat bvs)
  (let* ((n (apply + (map bytevector-length bvs))) (out (make-bytevector n)))
    (let loop ((bs bvs) (o 0))
      (if (null? bs) out
          (let ((k (bytevector-length (car bs))))
            (bytevector-copy! (car bs) 0 out o k)
            (loop (cdr bs) (+ o k)))))))

;; ---- a relay that records every byte the server sends ----
;; #(tcp-data bv) carries no connection, so each direction has its own owner.
(define (relay-pair! down up-port cap)
  (tcp-connect! "127.0.0.1" up-port self)
  (receive (after 5000 (tcp-close! down))
    (`#(tcp-connect-failed ,e) (tcp-close! down))
    (`#(tcp-connected ,up)
      (let ((back (spawn (lambda ()
                           (tcp-read-start! up)
                           (let loop ()
                             (receive
                               (`#(tcp-data ,bv)
                                 (set-box! cap (cons bv (unbox cap)))
                                 (tcp-write! down bv #f) (loop))
                               (`#(tcp-eof) (tcp-close! down))
                               (`#(tcp-error ,e) (tcp-close! down))))))))
        (conn-set-owner! up back)
        (tcp-read-start! down)
        (let loop ()
          (receive
            (`#(tcp-data ,bv) (tcp-write! up bv #f) (loop))
            (`#(tcp-eof) (tcp-close! up))
            (`#(tcp-error ,e) (tcp-close! up))))))))
(define (relay! port up-port cap)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (down)
      (let ((pid (spawn (lambda () (relay-pair! down up-port cap)))))
        (conn-set-owner! down pid)))))

;; ---- the direct transport route: tcp-write-foreign! from a cell-owned buffer ----
(define direct-size 200000)
(define (fill! p n byte) (do ((i 0 (+ i 1))) ((= i n)) (foreign-set! 'unsigned-8 p i byte)))
(define (direct-handler req res)
  (let ((c (res-conn res)) (buf (foreign-alloc direct-size)))
    (fill! buf direct-size #x41)
    (tcp-write! c (string->utf8 (string-append "HTTP/1.1 200 OK\r\nContent-Length: "
                                               (number->string direct-size)
                                               "\r\nConnection: close\r\n\r\n")) #f)
    (tcp-write-foreign! c buf direct-size #f)
    ;; THE CONTRACT: the buffer is the caller's again once the call returns.
    ;; Overwrite it and free it at once; a path that kept the pointer would
    ;; now deliver 'B' bytes or freed memory instead of the 'A' written.
    (fill! buf direct-size #x42)
    (foreign-free buf)))

(define (fetch scheme port path)
  (guard (e (#t (list 'raised (if (message-condition? e) (condition-message e) e))))
    (http-get (string-append scheme "://127.0.0.1:" (number->string port) path)
              '((timeout . 20000) (max-response . 8388608)))))
(define (status r) (and (not (pair? r)) (response-status r)))
(define (body r) (and (not (pair? r)) (response-body r)))

(start-scheduler
  (lambda ()
    (define tls-on (tls-enable!))
    (define app
      (let ((a (create-app)))
        (app-static a "/files" (in-dir "files"))
        (app-get a "/direct" direct-handler)
        a))
    (define tls-srv (http-listen tls-port (app->handler app)
                      (list (cons 'host "127.0.0.1") (cons 'workers 1)
                            (cons 'tls-cert (in-dir "good.pem")) (cons 'tls-key (in-dir "good.key")))))
    (define plain-srv (http-listen plain-port (app->handler app)
                        (list (cons 'host "127.0.0.1") (cons 'workers 1))))
    (define tls-cap (box '()))
    (define plain-cap (box '()))
    (define r1 (relay! tls-relay tls-port tls-cap))
    (define r2 (relay! plain-relay plain-port plain-cap))
    (sleep-ms 300)

    ;; ---- the plaintext twin first: it proves the relay records and the
    ;; search finds, so the TLS cell's "absent" is a reading, not silence
    (let ((r (fetch "http" plain-relay "/files/big.bin")))
      (sleep-ms 300)
      (let ((wire (cat (reverse (unbox plain-cap)))))
        (check "PLAIN twin: the large file downloads intact" (and (eqv? (status r) 200) (equal? (body r) payload))
               (status r) (and (body r) (bytevector-length (body r))) (if (pair? r) r 'ok))
        (check "PLAIN twin: the relay recorded at least the file's size" (>= (bytevector-length wire) file-size)
               (bytevector-length wire) file-size)
        (check "PLAIN twin: the sentinel IS on the wire (the search can find it)" (contains? wire sentinel))))

    ;; ---- R01: the same file over TLS, through the same kind of relay ----
    (let ((r (fetch "https" tls-relay "/files/big.bin")))
      (sleep-ms 300)
      (let ((wire (cat (reverse (unbox tls-cap)))))
        (check "R01: the large file downloads intact over HTTPS" (and (eqv? (status r) 200) (equal? (body r) payload))
               (status r) (and (body r) (bytevector-length (body r))) (if (pair? r) r 'ok))
        (check "R01: the relay recorded at least the file's size" (>= (bytevector-length wire) file-size)
               (bytevector-length wire) file-size)
        (check "R01: the sentinel is NOT on the wire (no plaintext on a TLS link)" (not (contains? wire sentinel)))))

    ;; ---- the export itself, both transports, with the reuse contract ----
    (for-each
      (lambda (scheme port)
        (let ((r (fetch scheme port "/direct")))
          (check (string-append "DIRECT " scheme ": tcp-write-foreign! delivers exactly the bytes written, not the overwritten buffer")
                 (and (eqv? (status r) 200) (body r) (= (bytevector-length (body r)) direct-size)
                      (let loop ((i 0)) (or (= i direct-size) (and (= (bytevector-u8-ref (body r) i) #x41) (loop (+ i 1))))))
                 (status r) (and (body r) (bytevector-length (body r)))
                 (and (body r) (> (bytevector-length (body r)) 0) (bytevector-u8-ref (body r) 0))
                 (if (pair? r) r 'ok))))
      '("http" "https") (list plain-port tls-port))

    (tcp-stop-listen! r1) (tcp-stop-listen! r2)
    (if (zero? failures)
        (begin (display "ALL HTTPS-LARGE-FILE TESTS PASSED\n") (exit 0))
        (begin (display "HTTPS-LARGE-FILE VERDICT: ") (display failures) (display " failed case(s)\n") (exit 1)))))
