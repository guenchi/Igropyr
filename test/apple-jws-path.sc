#!chezscheme
;;; test/apple-jws-path.sc -- verify-jws-x5c validates the certificate PATH,
;;; not only each adjacent pair (2026-09-07 review, R15).
;;;
;;; Checking every certificate against the next one says nothing about
;;; constraints that span the chain: a CA limited to pathlen 0 above another
;;; CA, an extension marked critical that nothing here understands, a policy
;;; constraint, an intermediate that never said it is a CA. Each case below
;;; is a fresh EC P-256 hierarchy made by test/apple-jws-path.sh, and a real
;;; ES256 JWS signed by that hierarchy's leaf, so a refusal can only come
;;; from the chain.
;;;
;;; THE TWINS ARE WHAT MAKE THE REFUSALS MEAN SOMETHING. The valid hierarchy
;;; must verify (else every refusal could be a JWS this file cannot build);
;;; the non-critical copy of the unknown extension must verify (else "refuse
;;; critical" could be "refuse unknown"); the policy twin, whose certificates
;;; do assert a common policy under the same constraint, must verify (else
;;; the policy row could be "refuse any policy constraint").
;;;
;;; ROW 4 IS A GUARD, NOT A RED PROOF. The pairwise code already refuses it.
;;; It is there for the check that the path OpenSSL verified is the path that
;;; was presented: without that check it would be accepted.
;;;
;;; ROW 8 PINS OPENSSL, NOT A CHECK OF THIS LIBRARY. OpenSSL's default
;;; profile refuses an intermediate without basicConstraints (measured with
;;; openssl verify on 3.6.3 and 3.5.4); the library relies on that instead of
;;; repeating it. The row goes red if an OpenSSL, or a flag, stops refusing.
;;;
;;; THE TWINS ARE SEPARATE HIERARCHIES. A twin also differs from its case in
;;; keys, serials and subject names; none of those is compared across cases
;;; by anything under test. The policy pair is two hierarchies too. The
;;; extensions the generator sets on purpose differ in one place only, the
;;; leaf's certificatePolicies; the key identifiers (subjectKeyIdentifier,
;;; authorityKeyIdentifier) differ as well, because they derive from the keys.
;;;
;;; The rows before row 1 are SETUP: they fail on a broken generator or
;;; filesystem and never because of the verifier.
;;;
;;; Needs the openssl CLI, 3.4 or later (the expired case uses x509 -not_before);
;;; fails, not skips, without it -- the first row names the generator.

(import (chezscheme) (igropyr apple-jws)
        (only (igropyr crypto) base64-encode))

(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))

(define dir "/tmp/igropyr-apple-jws-path")
(define gen-rc (system (string-append "sh test/apple-jws-path.sh " dir)))
(check "setup: the generator ran" (eqv? gen-rc 0) gen-rc)
(define (in-dir f) (string-append dir "/" f))

(define (read-file f)
  (call-with-port (open-file-input-port f) get-bytevector-all))

;; every file the generator meant to write is there and not empty
(let ((listed (call-with-input-file (in-dir "manifest")
                (lambda (p)
                  (let loop ((acc '()))
                    (let ((l (get-line p)))
                      (if (eof-object? l) (reverse acc) (loop (cons l acc)))))))))
  (check "setup: the manifest lists every case's files" (= (length listed) 75) (length listed))
  (for-each
    (lambda (f)
      (check (string-append "setup: generated " f)
             (and (file-exists? (in-dir f)) (> (bytevector-length (read-file (in-dir f))) 0))))
    listed))

(define (b64url bv)
  (let* ((std (base64-encode bv)) (n (string-length std)))
    (let loop ((i 0) (acc '()))
      (if (= i n)
          (list->string (reverse acc))
          (let ((c (string-ref std i)))
            (loop (+ i 1)
                  (cond ((char=? c #\+) (cons #\- acc))
                        ((char=? c #\/) (cons #\_ acc))
                        ((char=? c #\=) acc)
                        (else (cons c acc)))))))))

;; DER ECDSA-Sig-Value (SEQUENCE of two INTEGERs) -> JOSE's 64-byte R||S
(define (der->raw der)
  (let ((out (make-bytevector 64 0)))
    (define (put! off start len)
      (let* ((skip (let loop ((k 0))
                     (if (and (< k (- len 1)) (= 0 (bytevector-u8-ref der (+ start k))))
                         (loop (+ k 1))
                         k)))
             (n (- len skip)))
        (bytevector-copy! der (+ start skip) out (+ off (- 32 n)) n)))
    (let* ((rlen (bytevector-u8-ref der 3))
           (spos (+ 4 rlen))
           (slen (bytevector-u8-ref der (+ spos 1))))
      (put! 0 4 rlen)
      (put! 32 (+ spos 2) slen)
      out)))

;; a JWS whose x5c is the named files of case c, signed by c's leaf key
(define (jws c files payload)
  (let* ((x5c (map (lambda (f) (string-append "\"" (base64-encode (read-file (in-dir (string-append c "/" f)))) "\""))
                   files))
         (header (string-append "{\"alg\":\"ES256\",\"x5c\":["
                                (fold-left (lambda (acc s) (if (string=? acc "") s (string-append acc "," s))) "" x5c)
                                "]}"))
         (input (string-append (b64url (string->utf8 header)) "." (b64url (string->utf8 payload))))
         (in-file (in-dir (string-append c "/signing-input")))
         (sig-file (in-dir (string-append c "/sig.der"))))
    (call-with-port (open-file-output-port in-file (file-options no-fail))
      (lambda (p) (put-bytevector p (string->utf8 input))))
    (system (string-append "openssl dgst -sha256 -sign " (in-dir (string-append c "/leaf.key"))
                           " -out " sig-file " " in-file))
    (string-append input "." (b64url (der->raw (read-file sig-file))))))

(define (root-of c) (read-file (in-dir (string-append c "/root.der"))))

;; the whole raised vector, or 'accepted when the payload comes back intact
(define (raw-outcome c files pins)
  (let ((payload (string-append "{\"r15\":\"" c "\"}")))
    (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'apple-jws-error)) e))
      (let ((bv (verify-jws-x5c (jws c files payload) pins)))
        (if (equal? (utf8->string bv) payload) 'accepted (list 'wrong-payload (utf8->string bv)))))))
;; the code verify-jws-x5c raises, or 'accepted; one pin unless given a list
(define (outcome c files . pins)
  (let ((r (raw-outcome c files (if (null? pins) (list (root-of c)) (car pins)))))
    (if (vector? r) (vector-ref r 1) r)))
(define (contains? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (and (<= (+ i m) n) (or (string=? (substring s i (+ i m)) sub) (loop (+ i 1)))))))

(define three '("leaf.der" "i1.der" "root.der"))

(define (expect label want got)
  (check label (equal? want got) 'got got))

;; 1. the valid hierarchy: accepted, with policy processing on and no
;;    policies anywhere
(expect "1 valid root -> marked CA -> marked leaf: accepted" 'accepted (outcome "valid" three))
;; 2. the review's case: the CA under the root allows no further CA below it
(expect "2 pathlen 0 exceeded: chain-failed" 'chain-failed
        (outcome "pathlen" '("leaf.der" "i1.der" "i2.der" "root.der")))
;; 3. an extension nobody here understands, on the intermediate
(expect "3 unknown CRITICAL extension on the intermediate: chain-failed" 'chain-failed
        (outcome "critext" three))
(expect "3 twin: the same extension not critical: accepted" 'accepted
        (outcome "noncritext" three))
;; 4. the leaf hangs off the root; the marked CA is presented but unused
(expect "4 presented chain is not the verified chain: chain-failed" 'chain-failed
        (outcome "detour" three))
;; 5. a valid chain whose root is not the pinned one, refused before path work
(expect "5 root not pinned: invalid-root" 'invalid-root
        (outcome "valid" three (list (root-of "policy"))))
;;    and before the path is judged: this chain's path is ALSO invalid
;;    (pathlen), so a verifier that judged the path first answers chain-failed
(expect "5 root not pinned AND path invalid: invalid-root, not chain-failed" 'invalid-root
        (outcome "pathlen" '("leaf.der" "i1.der" "i2.der" "root.der") (list (root-of "valid"))))
;;    every pin in the list is usable, not only the first
(expect "5 twin: the chain's root pinned second of two: accepted" 'accepted
        (outcome "valid" three (list (root-of "policy") (root-of "valid"))))
;; 6. an expired leaf
(expect "6 expired leaf: cert-expired" 'cert-expired (outcome "expired" three))
(expect "6 not-yet-valid leaf: cert-expired" 'cert-expired (outcome "future" three))
;; 7. requireExplicitPolicy on the intermediate, and a leaf that asserts none
(expect "7 explicit policy required, none asserted: chain-failed" 'chain-failed
        (outcome "policy" three))
(expect "7 twin: same constraint, both certificates assert a policy: accepted" 'accepted
        (outcome "policyok" three))
;; 8. keyCertSign but no basicConstraints on the intermediate
(expect "8 intermediate without basicConstraints: chain-failed" 'chain-failed
        (outcome "nobc" three))
;; 9. a longer valid chain: every intermediate goes to OpenSSL, not only x5c[1]
(expect "9 valid four-certificate chain: accepted" 'accepted
        (outcome "valid4" '("leaf.der" "i1.der" "i2.der" "root.der")))
;; 10. presented out of order: the verified path has the same length but a
;;     different certificate at position 1 (the unmarked one). Only a
;;     comparison of each element, not of the lengths, refuses it.
(expect "10 presented order differs from the verified path, same length: chain-failed" 'chain-failed
        (outcome "order" '("leaf.der" "i1.der" "i2.der" "root.der")))
;; 11. each Apple marker checked on its own
(expect "11 leaf marker missing alone: chain-failed" 'chain-failed (outcome "noleafmark" three))
(expect "11 WWDR marker missing alone: chain-failed" 'chain-failed (outcome "nowwdr" three))
;; 12. name constraints on the intermediate
(expect "12 leaf name outside the intermediate's name constraints: chain-failed" 'chain-failed
        (outcome "namebad" three))
(expect "12 twin: leaf name inside them: accepted" 'accepted (outcome "namegood" three))
;; 13. what the deliberately non-strict profile must keep accepting
(expect "13 CA basicConstraints not marked critical (strict refuses): accepted" 'accepted
        (outcome "bcnoncrit" three))
(expect "13 leaf with an extendedKeyUsage (no purpose is set): accepted" 'accepted
        (outcome "eku" three))
;; 14. the refusal carries OpenSSL's reason, not only the code
(let ((r (raw-outcome "pathlen" '("leaf.der" "i1.der" "i2.der" "root.der") (list (root-of "pathlen")))))
  (check "14 chain-failed message names OpenSSL's reason (path length)"
         (and (vector? r) (string? (vector-ref r 2)) (contains? (vector-ref r 2) "path length"))
         r))

(if (zero? failures)
    (begin (display "apple-jws-path: all tests passed\n") (exit 0))
    (begin (display "apple-jws-path: ") (display failures) (display " failed\n") (exit 1)))
