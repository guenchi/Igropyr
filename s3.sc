#!chezscheme
;;; (igropyr s3) -- S3-compatible object storage over (igropyr client):
;;; AWS S3, Cloudflare R2, MinIO... anything speaking the S3 REST API.
;;;
;;;   (define r2 (make-s3 '((endpoint . "https://ACCT.r2.cloudflarestorage.com")
;;;                         (bucket . "iter")
;;;                         (access-key . "...") (secret . "...")
;;;                         (region . "auto"))))          ; R2 region is "auto"
;;;   (s3-put! r2 "items/x/L1_en.wav" wav-bytes "audio/wav")  ; -> etag | #t
;;;   (s3-get r2 "items/x/L1_en.wav")                     ; -> bytevector | #f (404)
;;;   (s3-copy! r2 "sandbox/s1/L1_en.wav" "items/x/L1_en.wav")
;;;   (s3-delete! r2 "sandbox/s1/L1_en.wav")              ; 404 counts as done
;;;   (s3-list r2 "sandbox/s1/")                          ; -> keys, paginates inside
;;;   (s3-delete-prefix! r2 "sandbox/s1/")                ; list + delete each
;;;
;;; Path-style addressing (endpoint/bucket/key) -- what R2 and MinIO
;;; use; virtual-host buckets work too by baking the bucket into the
;;; endpoint host and passing (bucket . "") if ever needed. Object keys
;;; go in DECODED; slashes stay literal, everything else is
;;; percent-encoded once and the same string is signed and sent.
;;;
;;; One request = one connection, inherited from (igropyr client) -- the
;;; deliberate no-pool decision lives there, not here. https needs
;;; (igropyr tls) enabled once at boot. HTTP-level failures raise
;;; #(s3-error status message) apart from the two soft spots a caller
;;; always branches on anyway: s3-get returns #f on 404 and s3-delete!
;;; treats 404 as success (idempotent GC). TRANSPORT-level failures
;;; (timeout, refused connection, response over the cap) pass through
;;; as the client's #(http-client-error message) -- they have no status
;;; and are usually retryable where an s3-error is not. The client caps
;;; buffered responses at 32 MiB; objects bigger than that need
;;; (max-response . bytes) in the make-s3 opts or they can be put but
;;; never fetched.
;;;
;;; DeleteObjects (the XML batch call) is deliberately absent: it
;;; requires Content-MD5, and MD5 is not in (igropyr crypto) -- GC-scale
;;; workloads do fine with list + per-key DELETE (s3-delete-prefix!).
;;; The ListObjectsV2 XML is parsed with a minimal tag scanner (S3
;;; responses are machine-generated and flat), entities unescaped.

(library (igropyr s3)
  (export make-s3 s3?
          s3-put! s3-get s3-copy! s3-delete! s3-delete-prefix! s3-list)
  (import (chezscheme) (igropyr crypto) (igropyr sigv4) (igropyr client))

  ;; make-s3 (exported below) takes an opts alist; raw-s3 is internal
  (define-record-type (s3 raw-s3 s3?)
    (fields base        ; "https://host[:port]" with no trailing slash
            host        ; host[:port when non-default] -- byte-for-byte
                        ; what (igropyr client) puts in Host, because
                        ; SigV4 signs the Host header
            bucket access-key secret region timeout max-response))

  (define (opt opts key default)
    (let ((p (assq key opts))) (if p (cdr p) default)))

  (define (need opts key)
    (let ((p (assq key opts)))
      (unless p (assertion-violation 'make-s3 "missing option" key))
      (cdr p)))

  ;; endpoint -> (values base host). Accepts http[s]://host[:port] ONLY:
  ;; a path here would make the signed canonical URI ("/bucket/key") and
  ;; the path on the wire (base + path) disagree -- every request 403s
  ;; with SignatureDoesNotMatch and no hint -- so it is rejected loudly.
  ;; host mirrors the client's Host header exactly, port included when
  ;; non-default, since that header is part of the signature.
  (define (parse-endpoint ep)
    (let*-values
        (((ep) (values
                 (if (and (> (string-length ep) 0)
                          (char=? (string-ref ep (- (string-length ep) 1)) #\/))
                     (substring ep 0 (- (string-length ep) 1))
                     ep)))
         ((authority dport)
          (cond
            ((and (>= (string-length ep) 7)
                  (string-ci=? (substring ep 0 7) "http://"))
             (values (substring ep 7 (string-length ep)) 80))
            ((and (>= (string-length ep) 8)
                  (string-ci=? (substring ep 0 8) "https://"))
             (values (substring ep 8 (string-length ep)) 443))
            (else (assertion-violation 'make-s3
                    "endpoint must be http[s]://host[:port]" ep)))))
      (when (or (string=? authority "")
                (let loop ((i 0))
                  (and (< i (string-length authority))
                       (or (char=? (string-ref authority i) #\/)
                           (loop (+ i 1))))))
        (assertion-violation 'make-s3
          "endpoint must be http[s]://host[:port] with no path" ep))
      (let* ((colon (let loop ((i 0))
                      (cond ((= i (string-length authority)) #f)
                            ((char=? (string-ref authority i) #\:) i)
                            (else (loop (+ i 1))))))
             (port (and colon
                        (string->number
                          (substring authority (+ colon 1)
                                     (string-length authority))))))
        (when (and colon (not (and (integer? port) (exact? port) (> port 0))))
          (assertion-violation 'make-s3 "bad endpoint port" ep))
        (values ep
                (if (and colon (not (= port dport)))
                    authority                          ; host:port as sent
                    (if colon (substring authority 0 colon) authority))))))

  ;; opts: endpoint bucket access-key secret [region "auto"]
  ;; [timeout 30000] [max-response -- client's 32 MiB default]
  (define (make-s3 opts)
    (let-values (((base host) (parse-endpoint (need opts 'endpoint))))
      (raw-s3 base host
              (need opts 'bucket)
              (need opts 'access-key) (need opts 'secret)
              (opt opts 'region "auto")
              (opt opts 'timeout 30000)
              (opt opts 'max-response #f))))

  (define empty-bv (make-bytevector 0))
  (define empty-payload-hash (sha256-hex empty-bv))

  (define (object-path s key)
    (string-append "/" (s3-bucket s) "/" (sigv4-uri-encode key #t)))

  (define (bucket-path s)
    (string-append "/" (s3-bucket s)))

  (define (s3-fail status body)
    (raise (vector 's3-error status
                   (let ((s (if (bytevector? body) (utf8->string body) "")))
                     (if (> (string-length s) 300) (substring s 0 300) s)))))

  ;; sign + send. query: decoded params alist. Returns the response;
  ;; caller decides which statuses are acceptable. The canonical query
  ;; is computed ONCE and both signed and sent -- signature and wire
  ;; share the value by construction, not by recomputation. Bodyless
  ;; PUT/POST needs no special casing here: (igropyr client) writes the
  ;; explicit Content-Length: 0 itself (unsigned, which SigV4 permits).
  (define (request s method path query headers body)
    (let* ((body-bv (or body empty-bv))
           (payload-hash (if (= (bytevector-length body-bv) 0)
                             empty-payload-hash
                             (sha256-hex body-bv)))
           (qs (sigv4-canonical-query query))
           (signed (sigv4-sign-headers method path query headers payload-hash
                     `((host . ,(s3-host s))
                       (access-key . ,(s3-access-key s))
                       (secret . ,(s3-secret s))
                       (region . ,(s3-region s))
                       (service . "s3")
                       (canonical-query . ,qs))))
           (url (string-append (s3-base s) path
                               (if (string=? qs "") "" (string-append "?" qs)))))
      (http-request method url
        `((headers . ,signed)
          (body . ,body-bv)
          (timeout . ,(s3-timeout s))
          . ,(let ((mr (s3-max-response s)))
               (if mr `((max-response . ,mr)) '()))))))

  (define (ok? status) (and (>= status 200) (< status 300)))

  ;; raise a typed s3-error unless the status is 2xx; returns r
  (define (check! r)
    (unless (ok? (response-status r))
      (s3-fail (response-status r) (response-body r)))
    r)

  ;; ---- operations --------------------------------------------------------

  ;; -> etag string (quotes stripped) or #t when the server sent none
  (define (s3-put! s key data content-type)
    (let ((r (check! (request s 'PUT (object-path s key) '()
                              `(("content-type" . ,content-type)) data))))
      (let ((etag (response-header r 'etag)))
        (if etag (strip-quotes etag) #t))))

  ;; -> bytevector | #f on 404
  (define (s3-get s key)
    (let ((r (request s 'GET (object-path s key) '() '() #f)))
      (cond ((ok? (response-status r)) (response-body r))
            ((= (response-status r) 404) #f)
            (else (s3-fail (response-status r) (response-body r))))))

  ;; server-side copy within the bucket (promotion: sandbox/… -> items/…)
  (define (s3-copy! s src-key dst-key)
    (check! (request s 'PUT (object-path s dst-key) '()
                     `(("x-amz-copy-source" . ,(object-path s src-key)))
                     #f))
    #t)

  ;; idempotent: 404 counts as deleted
  (define (s3-delete! s key)
    (let ((r (request s 'DELETE (object-path s key) '() '() #f)))
      (unless (or (ok? (response-status r)) (= (response-status r) 404))
        (s3-fail (response-status r) (response-body r)))
      #t))

  ;; all keys under prefix, following continuation tokens
  (define (s3-list s prefix)
    (let loop ((token #f) (pages '()))
      (let* ((query (append `(("list-type" . "2") ("prefix" . ,prefix))
                            (if token `(("continuation-token" . ,token)) '())))
             (r (check! (request s 'GET (bucket-path s) query '() #f)))
             (xml (utf8->string (response-body r)))
             (pages (cons (xml-all xml "Key") pages))
             (truncated (xml-one xml "IsTruncated"))
             (next (and truncated (string=? truncated "true")
                        (xml-one xml "NextContinuationToken"))))
        (if next
            (loop next pages)
            (apply append (reverse pages))))))

  (define (s3-delete-prefix! s prefix)
    (for-each (lambda (k) (s3-delete! s k)) (s3-list s prefix))
    #t)

  ;; ---- tiny helpers --------------------------------------------------------

  (define (strip-quotes v)
    (let ((n (string-length v)))
      (if (and (>= n 2) (char=? (string-ref v 0) #\")
               (char=? (string-ref v (- n 1)) #\"))
          (substring v 1 (- n 1))
          v)))

  ;; ---- minimal flat-XML extraction (S3 list responses) ---------------------

  (define (string-search hay needle start)
    (let ((hn (string-length hay)) (nn (string-length needle)))
      (let loop ((i start))
        (cond ((> (+ i nn) hn) #f)
              ((let check ((j 0))
                 (or (= j nn)
                     (and (char=? (string-ref hay (+ i j)) (string-ref needle j))
                          (check (+ j 1)))))
               i)
              (else (loop (+ i 1)))))))

  (define (prefix-at? s pre i)
    (let ((pn (string-length pre)) (sn (string-length s)))
      (and (<= (+ i pn) sn)
           (let check ((j 0))
             (or (= j pn)
                 (and (char=? (string-ref s (+ i j)) (string-ref pre j))
                      (check (+ j 1))))))))

  ;; "&#13;" / "&#xD;" at i -> emit the character, return the index
  ;; after ';' -- S3 emits control characters in object keys as numeric
  ;; references (they cannot appear literally in XML 1.0), and a key
  ;; read back wrong is a key that can never be deleted. #f when not a
  ;; well-formed reference to a valid scalar value.
  (define (numeric-ref s i p)
    (and (prefix-at? s "&#" i)
         (let* ((n (string-length s))
                (hex? (and (< (+ i 2) n)
                           (memv (string-ref s (+ i 2)) '(#\x #\X))))
                (radix (if hex? 16 10)))
           (define (digit c)
             (let ((v (cond ((char<=? #\0 c #\9) (- (char->integer c) 48))
                            ((char<=? #\a c #\f) (- (char->integer c) 87))
                            ((char<=? #\A c #\F) (- (char->integer c) 55))
                            (else #f))))
               (and v (< v radix) v)))
           (let loop ((j (+ i (if hex? 3 2))) (v 0) (any #f))
             (and (< j n)
                  (let ((c (string-ref s j)))
                    (cond
                      ((char=? c #\;)
                       (and any (< v #x110000)
                            (not (and (>= v #xD800) (<= v #xDFFF)))
                            (begin (put-char p (integer->char v)) (+ j 1))))
                      ((digit c) => (lambda (d) (loop (+ j 1) (+ (* v radix) d) #t)))
                      (else #f))))))))

  (define (xml-unescape s)
    (let-values (((p get) (open-string-output-port)))
      (let loop ((i 0))
        (if (= i (string-length s))
            (get)
            (if (char=? (string-ref s i) #\&)
                (let ((try (lambda (ent ch)
                             (and (prefix-at? s ent i)
                                  (begin (put-char p ch)
                                         (+ i (string-length ent)))))))
                  (loop (or (try "&amp;" #\&) (try "&lt;" #\<) (try "&gt;" #\>)
                            (try "&quot;" #\") (try "&apos;" #\')
                            (numeric-ref s i p)
                            (begin (put-char p #\&) (+ i 1)))))
                (begin (put-char p (string-ref s i)) (loop (+ i 1))))))))

  ;; every <tag>…</tag> text, unescaped, in document order
  (define (xml-all xml tag)
    (let ((open (string-append "<" tag ">"))
          (close (string-append "</" tag ">")))
      (let loop ((i 0) (acc '()))
        (let ((a (string-search xml open i)))
          (if (not a)
              (reverse acc)
              (let* ((b (+ a (string-length open)))
                     (c (string-search xml close b)))
                (if (not c)
                    (reverse acc)
                    (loop (+ c (string-length close))
                          (cons (xml-unescape (substring xml b c)) acc)))))))))

  ;; first <tag>…</tag> text only -- no full-document collection
  (define (xml-one xml tag)
    (let* ((open (string-append "<" tag ">"))
           (a (string-search xml open 0)))
      (and a
           (let* ((b (+ a (string-length open)))
                  (c (string-search xml (string-append "</" tag ">") b)))
             (and c (xml-unescape (substring xml b c)))))))
)
