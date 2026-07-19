#!chezscheme
;;; (igropyr ses) -- Amazon SES v2 SendEmail (the JSON API). The message
;;; (subject + HTML) is the caller's; this sends one already-rendered
;;; message. A non-ASCII From display name is RFC 2047 mime-word encoded,
;;; or clients (Gmail) show only the address local-part.
;;;
;;;   (define ses (make-ses '((region . "eu-west-3")
;;;                           (access-key . "...") (secret . "..."))))
;;;   (ses-send-email ses "noreply@ynthu.com" "云图" "u@x.com" subject html)
;;;     ;; -> the MessageId string; raises #(ses-error status body) otherwise

(library (igropyr ses)
  (export make-ses ses-send-email)
  (import (chezscheme) (igropyr aws)
          (only (igropyr json) json->string json-ref string->json)
          (only (igropyr http-client) response-status response-body)
          (only (igropyr crypto) base64-encode))

  (define-record-type (ses make-ses-raw ses?)
    (fields endpoint region access-key secret timeout))

  ;; opts: region access-key secret [endpoint] [timeout]
  (define (make-ses opts)
    (define (opt k d) (let ((p (assq k opts))) (if p (cdr p) d)))
    (let ((region (opt 'region "us-east-1")))
      (make-ses-raw
        (opt 'endpoint (string-append "https://email." region ".amazonaws.com"))
        region (opt 'access-key "") (opt 'secret "") (opt 'timeout 30000))))

  (define (ascii? s)
    (let loop ((i 0))
      (cond ((= i (string-length s)) #t)
            ((< (char->integer (string-ref s i)) 128) (loop (+ i 1)))
            (else #f))))

  ;; an ASCII display name outside RFC 5322 atom text (a comma, angle bracket,
  ;; quote, ...) must be a quoted-string, else it mis-parses the address or a
  ;; second angle-addr in the name spoofs the sender. '.' and space are left
  ;; bare (a phrase is space-separated dot-atoms).
  (define (atom-safe? c)
    (or (char<=? #\a c #\z) (char<=? #\A c #\Z) (char<=? #\0 c #\9)
        (and (memv c '(#\space #\! #\# #\$ #\% #\& #\' #\* #\+ #\-
                       #\/ #\= #\? #\^ #\_ #\` #\{ #\| #\} #\~ #\.))
             #t)))
  (define (all-atom-safe? s)
    (let loop ((i 0))
      (or (= i (string-length s))
          (and (atom-safe? (string-ref s i)) (loop (+ i 1))))))
  (define (quote-string s)                 ; "..." with \ and " backslash-escaped
    (call-with-string-output-port
      (lambda (p)
        (write-char #\" p)
        (let loop ((i 0))
          (when (< i (string-length s))
            (let ((c (string-ref s i)))
              (when (or (char=? c #\") (char=? c #\\)) (write-char #\\ p))
              (write-char c p))
            (loop (+ i 1))))
        (write-char #\" p))))

  ;; RFC 2047 B-encoding, split on UTF-8 codepoint boundaries so each
  ;; =?UTF-8?B?...?= word stays within the 75-char limit (12 fixed + <=60
  ;; base64 of <=45 payload bytes); adjacent words join with a space, which a
  ;; compliant parser drops between encoded-words. Splitting matters because a
  ;; long non-ASCII name is otherwise one over-length word strict MTAs reject.
  (define (encode-mime-word s)
    (let ((n (string-length s)))
      (let loop ((i 0) (cs 0) (cb 0) (words '()))
        (define (word end)
          (string-append "=?UTF-8?B?"
            (base64-encode (string->utf8 (substring s cs end))) "?="))
        (cond
          ((= i n)
           (fold-left (lambda (a w) (if (string=? a "") w (string-append a " " w)))
                      "" (reverse (if (> i cs) (cons (word i) words) words))))
          (else
           (let ((b (bytevector-length (string->utf8 (substring s i (+ i 1))))))
             (if (and (> i cs) (> (+ cb b) 45))
                 (loop i i 0 (cons (word i) words))
                 (loop (+ i 1) cs (+ cb b) words))))))))

  ;; From display name: pure-ASCII atom text as is; ASCII with a special ->
  ;; quoted-string; non-ASCII -> RFC 2047 encoded word(s).
  (define (format-display-name name)
    (if (ascii? name)
        (if (all-atom-safe? name) name (quote-string name))
        (encode-mime-word name)))

  ;; from-name may be #f or "" (address only). to is one address string OR a
  ;; list of address strings. subject/html are strings. -> MessageId string
  ;; (or #t when SES accepts but returns no parseable id); raises
  ;; #(ses-error status body) on a non-2xx response.
  (define (ses-send-email s from-addr from-name to subject html)
    (let* ((from (if (and from-name (> (string-length from-name) 0))
                     (string-append (format-display-name from-name)
                                    " <" from-addr ">")
                     from-addr))
           ;; ToAddresses is a vector so (igropyr json) writes it as a JSON
           ;; array unambiguously; every object is an alist.
           (body (string->utf8
                   (json->string
                     `(("FromEmailAddress" . ,from)
                       ("Destination" . (("ToAddresses" .
                         ,(if (list? to) (list->vector to) (vector to)))))
                       ("Content" .
                        (("Simple" .
                          (("Subject" . (("Data" . ,subject) ("Charset" . "UTF-8")))
                           ("Body" . (("Html" . (("Data" . ,html)
                                                 ("Charset" . "UTF-8")))))))))))))
           (r (aws-signed-post (ses-endpoint s) "ses" (ses-region s)
                (ses-access-key s) (ses-secret s) "/v2/email/outbound-emails"
                '(("content-type" . "application/json"))
                body (ses-timeout s)))
           (status (response-status r))
           (txt (utf8->string (response-body r))))
      (if (and (>= status 200) (< status 300))
          ;; a 2xx with an empty/non-JSON body (LB, gzip, partial write) must
          ;; not raise json-error past the ses-error-only contract
          (let ((j (guard (e (#t #f)) (string->json txt))))
            (or (and j (json-ref j "MessageId")) #t))
          (raise (vector 'ses-error status txt)))))
)
