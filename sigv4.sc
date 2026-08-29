#!chezscheme
;;; (igropyr sigv4) -- AWS Signature Version 4 request signing.
;;;
;;; Pure functions from request parts to the Authorization header --
;;; no sockets here. The HTTP side lives in (igropyr s3) (or any other
;;; AWS-flavoured caller), which feeds the signed headers to
;;; (igropyr http-client). Everything is deterministic given the datetime,
;;; so the AWS documented test vectors drive the test suite directly.
;;;
;;;   (sigv4-sign-headers 'PUT "/bucket/key" '()      ; decoded query params
;;;     '(("content-type" . "audio/wav"))             ; headers to send
;;;     payload-sha256-hex
;;;     '((host . "acct.r2.cloudflarestorage.com")
;;;       (access-key . "AKIA...") (secret . "...")
;;;       (region . "auto") (service . "s3")))
;;;   ;; -> headers alist INCLUDING x-amz-date, x-amz-content-sha256 and
;;;   ;;    authorization, EXCLUDING host: (igropyr http-client) writes the
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
  ;; HEADER NAMES MUST BE RFC 7230 TOKENS. A name carrying ":", ";" or a
  ;; newline is refused with an assertion-violation rather than signed.
  ;; This is a narrowing, and it is deliberate: such a name signs a
  ;; canonical request AWS cannot reproduce from the headers it received,
  ;; so the request comes back 403 with no body and no diagnostic, on
  ;; exactly the calls that carried that header. The refusal replaces an
  ;; unexplainable 403 with an error at the call that caused it.
  (export sigv4-sign-headers
          sigv4-uri-encode sigv4-canonical-query sigv4-canonical-request
          sigv4-signing-key sigv4-string-to-sign sigv4-authorization
          sigv4-datetime sha256-hex)
  (import (chezscheme) (igropyr util) (igropyr crypto))

  ;; ---- small helpers ---------------------------------------------------

  (define (sha256-hex bv) (bytevector->hex (sha256 bv)))

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

  ;; Trim ends and collapse inner runs of whitespace to one space (SigV4
  ;; header value rule). TABS count: they are legal OWS in HTTP and AWS
  ;; canonicalizes with a whitespace split, so leaving one in signs a
  ;; different string than the server reconstructs -- an intermittent 403
  ;; that appears only for tab-bearing values.
  (define (ws-char? c) (or (char=? c #\space) (char=? c #\tab)))

  (define (trim-collapse s)
    (let-values (((p get) (open-string-output-port)))
      (let loop ((i 0) (pending #f) (emitted #f))
        (if (fx= i (string-length s))
            (get)
            (let ((c (string-ref s i)))
              (if (ws-char? c)
                  (loop (fx+ i 1) emitted emitted)
                  (begin
                    (when pending (put-char p #\space))
                    (put-char p c)
                    (loop (fx+ i 1) #f #t))))))))

  ;; A HEADER NAME IS AN RFC 7230 TOKEN, AND THAT IS CHECKED HERE RATHER
  ;; THAN ASSUMED. The canonical request joins a name to its value with
  ;; ":" and joins names to each other with ";", so a name carrying
  ;; either of those -- or a newline -- produces a string that differs
  ;; from the one AWS rebuilds out of the headers it received. The
  ;; signature then fails to match, and the failure is a 403 with no body
  ;; and no clue, on exactly the requests that carried that header and no
  ;; others.
  ;;
  ;; THE PREMISE THIS REPLACES WAS ALREADY FALSE. The encoding was safe
  ;; while every header name came from inside this library, and that has
  ;; not been true: sigv4-sign-headers takes a caller's headers and signs
  ;; them, which is what it is for. Writing the premise down instead of
  ;; enforcing it would have recorded something the code contradicts one
  ;; call away.
  ;;
  ;; Names only. A VALUE containing a newline has a related problem and a
  ;; different owner: values are checked, and split requests prevented,
  ;; where the request is written -- see the note in the gap ledger.
  (define (header-name-char? c)
    (or (and (char>=? c #\a) (char<=? c #\z))
        (and (char>=? c #\A) (char<=? c #\Z))
        (and (char>=? c #\0) (char<=? c #\9))
        (memv c '(#\! #\# #\$ #\% #\& #\' #\* #\+ #\- #\.
                  #\^ #\_ #\` #\| #\~))))

  (define (header-name? s)
    (and (string? s)
         (fx> (string-length s) 0)
         (let loop ((i 0))
           (or (fx= i (string-length s))
               (and (header-name-char? (string-ref s i))
                    (loop (fx+ i 1)))))))

  ;; headers: ((name . value) ...) raw, INCLUDING host.
  ;; -> (values canonical-request signed-headers-string)
  (define (sigv4-canonical-request method path canonical-query headers payload-hash)
    (for-each
      (lambda (h)
        (unless (and (pair? h) (header-name? (car h)))
          (assertion-violation 'sigv4-canonical-request
            "header name must be a non-empty RFC 7230 token; a name carrying \":\", \";\" or a newline signs a request AWS cannot reproduce"
            (and (pair? h) (car h)))))
      headers)
    (let* ((lowered (map (lambda (h)
                           (cons (string-downcase (car h))
                                 (trim-collapse (cdr h))))
                         headers))
           ;; SigV4 requires values for a REPEATED name to be joined with
           ;; "," into a single canonical line, appearing once in
           ;; SignedHeaders. Emitting two lines (and the name twice) made
           ;; AWS -- which rebuilds the canonical request from the single
           ;; header it received -- compute a different signature, so every
           ;; such request failed 403 with no useful diagnostic. Callers
           ;; reach this by passing a header sigv4-sign-headers also adds,
           ;; e.g. their own x-amz-content-sha256.
           (merged (fold-right
                     (lambda (h acc)
                       (cond
                         ((assoc (car h) acc)
                          => (lambda (prev)
                               (cons (cons (car h)
                                           (string-append (cdr h) "," (cdr prev)))
                                     (remp (lambda (x) (equal? (car x) (car h)))
                                           acc))))
                         (else (cons h acc))))
                     '() lowered))
           (sorted (sort (lambda (a b) (string<? (car a) (car b))) merged))
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
  ;; -> headers alist to pass to (igropyr http-client): input headers plus
  ;;    x-amz-date [x-amz-content-sha256] authorization.
  (define (sigv4-sign-headers method path query headers payload-hash opts)
    (let* ((method (string-upcase
                     (if (symbol? method) (symbol->string method) method)))
           (host (need 'sigv4-sign-headers opts 'host))
           (access-key (need 'sigv4-sign-headers opts 'access-key))
           (secret (need 'sigv4-sign-headers opts 'secret))
           (region (need 'sigv4-sign-headers opts 'region))
           (service (need 'sigv4-sign-headers opts 'service))
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
