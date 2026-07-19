#!chezscheme
;;; (igropyr aws) -- shared SigV4 POST plumbing for AWS query/JSON services:
;;; the sign-and-POST that (igropyr sts) and (igropyr ses) build on. The
;;; signing is (igropyr sigv4); this adds endpoint parsing, the
;;; x-www-form-urlencoded body builder for the query protocol, and a minimal
;;; flat-XML tag reader. Nothing here is S3-specific: (content-sha256 . #f)
;;; drops the S3-only x-amz-content-sha256 header while still signing the
;;; payload hash. ((igropyr s3) keeps its own request path.)
;;;
;;;   (aws-signed-post "https://sts.us-east-1.amazonaws.com" "sts"
;;;     "us-east-1" ak sk "/"
;;;     '(("content-type" . "application/x-www-form-urlencoded"))
;;;     form-bytes 30000)          ; -> the (igropyr http-client) response

(library (igropyr aws)
  (export aws-signed-post endpoint->host form-encode xml-first)
  (import (chezscheme) (igropyr sigv4) (igropyr http-client))

  ;; "http[s]://host[:port][/...]" -> "host[:port]" -- exactly what
  ;; (igropyr http-client) writes in the Host header, so SigV4 signs the
  ;; same bytes that go on the wire.
  (define (endpoint->host endpoint)
    (let* ((n (string-length endpoint))
           (start (let loop ((i 0))
                    (cond ((> (+ i 3) n) 0)
                          ((and (char=? (string-ref endpoint i) #\:)
                                (char=? (string-ref endpoint (+ i 1)) #\/)
                                (char=? (string-ref endpoint (+ i 2)) #\/))
                           (+ i 3))
                          (else (loop (+ i 1))))))
           (end (let loop ((i start))
                  (cond ((>= i n) n)
                        ((char=? (string-ref endpoint i) #\/) i)
                        (else (loop (+ i 1)))))))
      (substring endpoint start end)))

  ;; alist of (name . value) -> x-www-form-urlencoded body string, both
  ;; sides RFC 3986 percent-encoded (AWS query protocol: space is %20).
  (define (form-encode pairs)
    (let loop ((l pairs) (acc ""))
      (if (null? l)
          acc
          (let ((kv (string-append (sigv4-uri-encode (caar l) #f) "="
                                   (sigv4-uri-encode (cdar l) #f))))
            (loop (cdr l) (if (string=? acc "") kv (string-append acc "&" kv)))))))

  ;; sign + POST; returns the (igropyr http-client) response. endpoint is the
  ;; base URL ("https://sts.us-east-1.amazonaws.com", or a test
  ;; "http://127.0.0.1:PORT"); host is derived from it and signed. https
  ;; needs (igropyr tls) enabled once at boot.
  (define (aws-signed-post endpoint service region access-key secret path headers body timeout)
    (let* ((host (endpoint->host endpoint))
           (payload-hash (sha256-hex body))
           (signed (sigv4-sign-headers 'POST path '() headers payload-hash
                     `((host . ,host)
                       (access-key . ,access-key) (secret . ,secret)
                       (region . ,region) (service . ,service)
                       (content-sha256 . #f)))))
      (http-request 'POST (string-append endpoint path)
        `((headers . ,signed) (body . ,body) (timeout . ,timeout)))))

  ;; content of the first <tag>...</tag> in a flat XML string, or #f. STS
  ;; responses are machine-generated and shallow, and the fields we read
  ;; (AccessKeyId, SessionToken, Expiration, Message) carry no XML entities.
  (define (xml-first xml tag)
    (let* ((open (string-append "<" tag ">"))
           (ol (string-length open))
           (a (str-search xml open 0)))
      (and a
           (let ((b (str-search xml (string-append "</" tag ">") (+ a ol))))
             (and b (substring xml (+ a ol) b))))))

  (define (str-search hay needle start)
    (let ((hn (string-length hay)) (nn (string-length needle)))
      (let loop ((i start))
        (cond ((> (+ i nn) hn) #f)
              ((string=? (substring hay i (+ i nn)) needle) i)
              (else (loop (+ i 1)))))))
)
