#!chezscheme
;;; (igropyr sigv4) -- AWS Signature Version 4 request signing.
;;;
;;; Pure functions from request parts to the Authorization header --
;;; no sockets here. The HTTP side lives in (igropyr s3) (or any other
;;; AWS-flavoured caller), which feeds the signed headers to
;;; (igropyr client). Everything is deterministic given the datetime,
;;; so the AWS documented test vectors drive the test suite directly.
;;;
;;;   (sigv4-sign-headers 'PUT "/bucket/key" '()      ; decoded query params
;;;     '(("content-type" . "audio/wav"))             ; headers to send
;;;     payload-sha256-hex
;;;     '((host . "acct.r2.cloudflarestorage.com")
;;;       (access-key . "AKIA...") (secret . "...")
;;;       (region . "auto") (service . "s3")))
;;;   ;; -> headers alist INCLUDING x-amz-date, x-amz-content-sha256 and
;;;   ;;    authorization, EXCLUDING host: (igropyr client) writes the
;;;   ;;    Host line itself, so host is signed here but never sent twice.
;;;
;;; Conventions baked in (S3 flavour, which R2 follows):
;;;   - the canonical URI is the path AS SENT: percent-encoded once, no
;;;     normalization, no double encoding. Build it with sigv4-uri-encode
;;;     (keep-slash) and reuse the same string on the wire.
;;;   - sigv4-canonical-query both signs the params and IS the query
;;;     string to send, so signature and wire can never drift.
;;;   - x-amz-content-sha256 is added and signed by default (S3 requires
;;;     it); pass (content-sha256 . #f) in opts for non-S3 services.
;;;   - datetime defaults to now (UTC); pass (datetime . "YYYYMMDDThhmmssZ")
;;;     for reproducible signing (tests, pre-signed flows).
;;;
;;; Keys/secrets are strings; digests ride on (igropyr crypto), which
;;; returns raw bytes -- hex/encode decisions all happen here.

(library (igropyr sigv4)
  (export sigv4-sign-headers
          sigv4-uri-encode sigv4-canonical-query sigv4-canonical-request
          sigv4-signing-key sigv4-string-to-sign sigv4-authorization
          sigv4-datetime sha256-hex)
  (import (chezscheme) (igropyr crypto))

  ;; ---- small helpers ---------------------------------------------------

  (define (sha256-hex bv) (bytevector->hex (sha256 bv)))

  (define (opt opts key default)
    (let ((p (assq key opts))) (if p (cdr p) default)))

  (define (need opts key)
    (let ((p (assq key opts)))
      (unless p (assertion-violation 'sigv4-sign-headers "missing option" key))
      (cdr p)))

  ;; current UTC time as YYYYMMDDThhmmssZ
  (define (sigv4-datetime)
    (let ((d (current-date 0)))
      (define (pad2 n) (if (< n 10) (string-append "0" (number->string n))
                           (number->string n)))
      (string-append
        (number->string (date-year d)) (pad2 (date-month d)) (pad2 (date-day d))
        "T" (pad2 (date-hour d)) (pad2 (date-minute d)) (pad2 (date-second d)) "Z")))

  ;; ---- RFC 3986 strict percent-encoding --------------------------------

  (define unreserved?
    (let ((v (make-vector 256 #f)))
      (for-each
        (lambda (c) (vector-set! v (char->integer c) #t))
        (string->list
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"))
      (lambda (b) (vector-ref v b))))

  (define hex-upper "0123456789ABCDEF")

  ;; encode s (UTF-8 bytes) leaving unreserved chars; keep-slash? leaves
  ;; "/" for URI paths (S3 object keys contain slashes that stay literal)
  (define (sigv4-uri-encode s keep-slash?)
    (let ((bv (string->utf8 s)))
      (let-values (((p get) (open-string-output-port)))
        (do ((i 0 (fx+ i 1))) ((fx= i (bytevector-length bv)) (get))
          (let ((b (bytevector-u8-ref bv i)))
            (cond
              ((or (unreserved? b)
                   (and keep-slash? (fx= b (char->integer #\/))))
               (put-char p (integer->char b)))
              (else
               (put-char p #\%)
               (put-char p (string-ref hex-upper (fxsrl b 4)))
               (put-char p (string-ref hex-upper (fxand b #xF))))))))))

  ;; ---- canonical query -------------------------------------------------

  ;; params: ((name . value) ...) DECODED strings. Encode both sides,
  ;; sort by encoded name then encoded value, join k=v with &. The
  ;; result is both the canonical query string and the one to send.
  (define (sigv4-canonical-query params)
    (let* ((encoded (map (lambda (kv)
                           (cons (sigv4-uri-encode (car kv) #f)
                                 (sigv4-uri-encode (cdr kv) #f)))
                         params))
           (sorted (sort (lambda (a b)
                           (if (string=? (car a) (car b))
                               (string<? (cdr a) (cdr b))
                               (string<? (car a) (car b))))
                         encoded)))
      (fold-right (lambda (kv acc)
                    (let ((one (string-append (car kv) "=" (cdr kv))))
                      (if (string=? acc "") one (string-append one "&" acc))))
                  "" sorted)))

  ;; ---- canonical headers / request --------------------------------------

  ;; trim ends and collapse inner runs of spaces (SigV4 header value rule)
  (define (trim-collapse s)
    (let-values (((p get) (open-string-output-port)))
      (let loop ((i 0) (pending #f) (emitted #f))
        (if (fx= i (string-length s))
            (get)
            (let ((c (string-ref s i)))
              (if (char=? c #\space)
                  (loop (fx+ i 1) emitted emitted)
                  (begin
                    (when pending (put-char p #\space))
                    (put-char p c)
                    (loop (fx+ i 1) #f #t))))))))

  ;; headers: ((name . value) ...) raw, INCLUDING host.
  ;; -> (values canonical-request signed-headers-string)
  (define (sigv4-canonical-request method path canonical-query headers payload-hash)
    (let* ((lowered (map (lambda (h)
                           (cons (string-downcase (car h))
                                 (trim-collapse (cdr h))))
                         headers))
           (sorted (sort (lambda (a b) (string<? (car a) (car b))) lowered))
           (signed (fold-right (lambda (h acc)
                                 (if (string=? acc "")
                                     (car h)
                                     (string-append (car h) ";" acc)))
                               "" sorted))
           (canon-headers (apply string-append
                                 (map (lambda (h)
                                        (string-append (car h) ":" (cdr h) "\n"))
                                      sorted))))
      (values
        (string-append method "\n" path "\n" canonical-query "\n"
                       canon-headers "\n" signed "\n" payload-hash)
        signed)))

  ;; ---- key derivation / string to sign / authorization -------------------

  (define (sigv4-signing-key secret date region service)
    (let* ((k0 (hmac-sha256 (string->utf8 (string-append "AWS4" secret))
                            (string->utf8 date)))
           (k1 (hmac-sha256 k0 (string->utf8 region)))
           (k2 (hmac-sha256 k1 (string->utf8 service))))
      (hmac-sha256 k2 (string->utf8 "aws4_request"))))

  (define (sigv4-string-to-sign datetime scope canonical-request)
    (string-append "AWS4-HMAC-SHA256\n" datetime "\n" scope "\n"
                   (sha256-hex (string->utf8 canonical-request))))

  (define (sigv4-authorization access-key scope signed-headers signature)
    (string-append "AWS4-HMAC-SHA256 Credential=" access-key "/" scope
                   ", SignedHeaders=" signed-headers
                   ", Signature=" signature))

  ;; ---- the one-call entry ------------------------------------------------

  ;; method: symbol or string. path: as sent (encoded once). query:
  ;; decoded params alist. headers: to sign AND send (host NOT among
  ;; them). payload-hash: lowercase hex sha256 of the body ("UNSIGNED-
  ;; PAYLOAD" is also legal). opts: host access-key secret region
  ;; service [datetime] [content-sha256] [canonical-query] -- pass the
  ;; already-computed (sigv4-canonical-query query) string when the
  ;; caller also needs it for the URL, so it is built once and the
  ;; signature and the wire share one value by construction.
  ;; -> headers alist to pass to (igropyr client): input headers plus
  ;;    x-amz-date [x-amz-content-sha256] authorization.
  (define (sigv4-sign-headers method path query headers payload-hash opts)
    (let* ((method (string-upcase
                     (if (symbol? method) (symbol->string method) method)))
           (host (need opts 'host))
           (access-key (need opts 'access-key))
           (secret (need opts 'secret))
           (region (need opts 'region))
           (service (need opts 'service))
           (datetime (opt opts 'datetime (sigv4-datetime)))
           (date (substring datetime 0 8))
           (with-sha (opt opts 'content-sha256 #t))
           (sent-headers (append headers
                                 `(("x-amz-date" . ,datetime))
                                 (if with-sha
                                     `(("x-amz-content-sha256" . ,payload-hash))
                                     '())))
           (all-headers (cons (cons "host" host) sent-headers))
           (canonical-query (or (opt opts 'canonical-query #f)
                                (sigv4-canonical-query query)))
           (scope (string-append date "/" region "/" service "/aws4_request")))
      (let-values (((canonical signed)
                    (sigv4-canonical-request method path canonical-query
                                             all-headers payload-hash)))
        (let* ((sts (sigv4-string-to-sign datetime scope canonical))
               (key (sigv4-signing-key secret date region service))
               (sig (bytevector->hex (hmac-sha256 key (string->utf8 sts)))))
          (append sent-headers
                  `(("authorization" . ,(sigv4-authorization access-key scope
                                                             signed sig))))))))
)
