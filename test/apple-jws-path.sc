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
  (check "setup: the manifest lists every case's files" (= (length listed) 96) (length listed))
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
;;     different certificate at position 1 (the unmarked one). Of verifiers
;;     that let OpenSSL build the path, one comparing positions, not only the
;;     lengths, refuses it -- comparing position 1 alone would be enough; a
;;     pairwise verifier refuses it too (leaf is not issued by i1), so this row
;;     guards the comparison, it does not prove it compares every position.
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
;; 15. ES256 is ECDSA on P-256 (RFC 7518 3.4). A leaf whose key is on
;;     another curve, or is not EC at all, is refused -- here the chain, the
;;     markers and the signature are all otherwise good. Row 1 (a P-256 leaf,
;;     accepted) is the twin; p384ca is the production-shaped twin (Apple's
;;     root is P-384): the requirement is on the leaf, not on the chain.
(for-each
  (lambda (c label)
    (let ((r (raw-outcome c three (list (root-of c)))))
      (check (string-append "15 leaf key " label ": sig-failed naming EC P-256")
             (and (vector? r) (eq? (vector-ref r 1) 'sig-failed)
                  (string? (vector-ref r 2)) (contains? (vector-ref r 2) "EC P-256"))
             r)))
  '("k1leaf" "dsaleaf" "bpleaf" "p224leaf")
  '("on secp256k1" "is DSA" "on brainpoolP256r1" "on P-224"))
(expect "15 P-384 root and intermediate above a P-256 leaf: accepted" 'accepted
        (outcome "p384ca" three))
;;     THE KEY IS THE REASON GIVEN, EVEN WHEN THE SIGNATURE IS ALSO BAD. The
;;     same secp256k1 token with one signature character changed (still 64
;;     bytes) must be refused naming the key. This shows which reason wins,
;;     not the order of the calls: a verifier that verified first, kept the
;;     answer and then reported the key would read the same.
(define (flip-signature tok)
  (let* ((n (string-length tok)) (i (- n 10)))
    (string-append (substring tok 0 i)
                   (if (char=? (string-ref tok i) #\A) "B" "A")
                   (substring tok (+ i 1) n))))
(define (outcome-of-token tok root)
  (guard (e ((and (vector? e) (eq? (vector-ref e 0) 'apple-jws-error)) e))
    (let* ((payload-b64 (let loop ((i 0) (dots '()))
                          (cond ((= i (string-length tok))
                                 (let ((d (reverse dots)))
                                   (substring tok (+ 1 (car d)) (cadr d))))
                                ((char=? (string-ref tok i) #\.) (loop (+ i 1) (cons i dots)))
                                (else (loop (+ i 1) dots)))))
           (bv (verify-jws-x5c tok (list root))))
      ;; accepted only with the payload the token carried, as raw-outcome does
      (if (and (bytevector? bv) (string=? (b64url bv) payload-b64))
          'accepted
          (list 'wrong-payload bv)))))
(let ((r (outcome-of-token (flip-signature (jws "k1leaf" three "{\"r15\":\"k1leaf\"}"))
                           (root-of "k1leaf"))))
  (check "15 a secp256k1 leaf with a broken signature is refused naming its key"
         (and (vector? r) (eq? (vector-ref r 1) 'sig-failed)
              (string? (vector-ref r 2)) (contains? (vector-ref r 2) "EC P-256"))
         r))
;;     and a P-256 leaf with a broken signature is refused FOR THE SIGNATURE:
;;     the key check must not stand in for verifying it.
(let ((r (outcome-of-token (flip-signature (jws "valid" three "{\"r15\":\"valid\"}"))
                           (root-of "valid"))))
  (check "15 a P-256 leaf with a broken signature is refused, and not for its key"
         (and (vector? r) (eq? (vector-ref r 1) 'sig-failed)
              (string? (vector-ref r 2)) (not (contains? (vector-ref r 2) "EC P-256")))
         r))

;; 16. EVERY NAMED CURVE THIS HOST'S OPENSSL LISTS, EXCEPT P-256, IS REFUSED,
;;     in its default encoding, and so are RSA, Ed25519 and Ed448 -- the set
;;     the generator enumerated, under one shared root and intermediate. The
;;     P-256 twin differs from each in the leaf's key and also in subject,
;;     serial, payload and signature, which the key check does not read.
;;     These tokens are not signed -- a curve above 256 bits cannot fit its
;;     signature in 64 bytes -- so the signature is 64 fixed bytes, and the
;;     refusal must name the key: a refusal for the signature would read
;;     "does not verify" instead.
;;
;;     WHAT THIS DELIBERATELY DOES NOT COVER, so "is there a wrong criterion
;;     that still passes" has a written answer:
;;     - a group with no name (explicit parameters). A criterion admitting NID
;;       0 would pass. Not built: on OpenSSL 3.6.3 an explicit-parameter
;;       P-256 decodes back to NID 415 (review, 2026-09-27), so the only NID-0
;;       key is a custom curve, which a real notification leaf is not.
;;     - a P-256 point in a non-default encoding (compressed). A criterion
;;       that also demanded the default encoding would wrongly refuse it and
;;       still pass here. Apple's leaves are named P-256 in the default form.
;;     - any key type or size outside the enumeration. The non-EC types are
;;       one size each (RSA 2048, Ed25519, Ed448), so "P-256, or RSA of 3072
;;       bits and more" would pass. No finite set of refused keys can stop a
;;       criterion of the form "P-256, or something not in the set"; this is
;;       the boundary of the enumeration, stated rather than extended. Within
;;       it, the only criterion that passes every row is EC on P-256.
(define (read-lines f)
  (if (file-exists? f)
      (call-with-input-file f
        (lambda (p)
          (let loop ((acc '()))
            (let ((l (get-line p)))
              (if (eof-object? l) (reverse acc) (loop (cons l acc)))))))
      '()))
(define (curves-token leaf)
  (let* ((x5c (map (lambda (f) (string-append "\"" (base64-encode (read-file (in-dir (string-append "curves/" f)))) "\""))
                   (list (string-append leaf ".der") "i1.der" "root.der")))
         (header (string-append "{\"alg\":\"ES256\",\"x5c\":["
                                (fold-left (lambda (acc s) (if (string=? acc "") s (string-append acc "," s))) "" x5c)
                                "]}")))
    (string-append (b64url (string->utf8 header)) "."
                   (b64url (string->utf8 "{\"r16\":1}")) "."
                   (b64url (make-bytevector 64 7)))))
(let ((made (read-lines (in-dir "curves/made")))
      (refused (read-lines (in-dir "curves/refused-by-openssl")))
      (root (read-file (in-dir "curves/root.der"))))
  (check "16 setup: the generator made at least ten non-P-256 leaves" (>= (length made) 10) (length made))
  ;; ACCOUNTED FOR, NOT ONLY COUNTED: every listed curve other than P-256,
  ;; plus the three non-EC types, is either made or refused by openssl with
  ;; its reason, and the curves the earlier rows name are among the made.
  (let ((listed (read-lines (in-dir "curves/listed"))))
    (check "16 setup: made + refused-by-openssl = listed curves - P-256 + 3 non-EC types"
           (= (+ (length made) (length refused))
              (+ (- (length listed) (if (member "prime256v1" listed) 1 0)) 3))
           (length made) (length refused) (length listed))
    (for-each
      (lambda (c)
        (check (string-append "16 setup: " c " is among the leaves made") (member c made)))
      '("secp384r1" "secp521r1" "secp256k1" "brainpoolP256r1" "rsa2048" "ed25519")))
  (display "  [info] ") (display (length made)) (display " non-P-256 leaves made; openssl could not make ")
  (display (length refused)) (display "\n")
  (for-each (lambda (l) (display "  [info]   ") (display l) (newline)) refused)
  ;; the twin, same root and intermediate, a real signature
  (let ((r (outcome-of-token (jws "curves" three "{\"r15\":\"curves\"}") root)))
    (check "16 twin: the P-256 leaf in this hierarchy is accepted" (eq? r 'accepted) r))
  (let ((wrong
          (fold-left
            (lambda (acc leaf)
              (let ((r (outcome-of-token (curves-token leaf) root)))
                (if (and (vector? r) (eq? (vector-ref r 1) 'sig-failed)
                         (string? (vector-ref r 2)) (contains? (vector-ref r 2) "EC P-256"))
                    acc
                    (cons (list leaf (if (vector? r) (vector-ref r 2) r)) acc))))
            '() made)))
    (check (string-append "16 every one of the " (number->string (length made))
                          " non-P-256 leaves is refused naming EC P-256")
           (null? wrong) (length wrong) (if (pair? wrong) (reverse wrong) '()))))

;;     a P-384 leaf under a P-384 intermediate: refused. The requirement is
;;     P-256, not "the leaf's curve matches its issuer's".
(let* ((x5c (map (lambda (f) (string-append "\"" (base64-encode (read-file (in-dir (string-append "p384ca/" f)))) "\""))
                 '("leaf384.der" "i1.der" "root.der")))
       (tok (string-append (b64url (string->utf8 (string-append "{\"alg\":\"ES256\",\"x5c\":["
                                                                (car x5c) "," (cadr x5c) "," (caddr x5c) "]}")))
                           "." (b64url (string->utf8 "{\"r16\":2}")) "." (b64url (make-bytevector 64 7))))
       (r (outcome-of-token tok (root-of "p384ca"))))
  (check "16 a P-384 leaf under a P-384 intermediate is refused naming EC P-256"
         (and (vector? r) (eq? (vector-ref r 1) 'sig-failed)
              (string? (vector-ref r 2)) (contains? (vector-ref r 2) "EC P-256"))
         r))

;; 14. the refusal carries OpenSSL's reason, not only the code
(let ((r (raw-outcome "pathlen" '("leaf.der" "i1.der" "i2.der" "root.der") (list (root-of "pathlen")))))
  (check "14 chain-failed message names OpenSSL's reason (path length)"
         (and (vector? r) (string? (vector-ref r 2)) (contains? (vector-ref r 2) "path length"))
         r))

(if (zero? failures)
    (begin (display "apple-jws-path: all tests passed\n") (exit 0))
    (begin (display "apple-jws-path: ") (display failures) (display " failed\n") (exit 1)))
