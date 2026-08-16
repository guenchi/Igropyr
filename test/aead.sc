#!chezscheme
;;; (igropyr aead) AES-256-GCM.
;;;
;;; A cipher validated only by its own round-trip is not validated at all:
;;; encrypt-then-decrypt agrees with itself no matter what it computes. So
;;; every byte this suite asserts comes from OUTSIDE this codebase.
;;;
;;;  1. Published known-answer vectors: test cases 13-18 of McGrew & Viega's
;;;     GCM specification, the AES-256 set carried forward into NIST SP
;;;     800-38D's validation material and quoted by RFC 5288 / RFC 6367 and
;;;     every other GCM implementation. Exact ciphertext AND exact tag are
;;;     asserted, for a 96-bit IV, an 8-bit-short IV and a 480-bit IV, with
;;;     and without associated data.
;;;
;;;  2. A second implementation, in another language and another process:
;;;     python3's `cryptography` AESGCM, or node's crypto, whichever is
;;;     present. Both directions are exercised -- what we seal it must open,
;;;     what it seals we must open -- and it must also REJECT a ciphertext we
;;;     tampered with, so the two sides agree on rejection and not merely on
;;;     acceptance. This is gated (it is the only part of the suite that
;;;     needs anything beyond libcrypto) and names what is missing when it
;;;     self-skips. The openssl CLI is deliberately not used here: `openssl
;;;     enc` has no way to emit or supply a GCM tag.
;;;
;;; Then the failure modes, which is where an AEAD is actually load-bearing:
;;; a tampered ciphertext, tag, AAD or key must all answer #f and must never
;;; hand back plaintext, while a wrong key or IV LENGTH -- the caller's own
;;; configuration, not attacker input -- must raise.

(import (chezscheme) (igropyr aead) (only (igropyr crypto) bytevector->hex))

(define failures 0)
(define (fail label)
  (set! failures (+ failures 1))
  (display "FAIL  ") (display label) (newline))
(define (check label ok)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (fail label)))

(define (str-contains? m needle)
  (let ((nl (string-length needle)) (ml (string-length m)))
    (let loop ((i 0))
      (cond ((fx> (fx+ i nl) ml) #f)
            ((string=? (substring m i (fx+ i nl)) needle) #t)
            (else (loop (fx+ i 1)))))))

;; Did the thunk raise a condition whose own message contains `needle`?
;; This distinguishes OUR bound check (which refuses before allocating or
;; calling into the FFI) from an incidental low-level error a too-large
;; value would raise anyway -- so a "raises" assertion actually pins the
;; fix, not just any exception.
(define (raises-message-containing? needle thunk)
  (guard (e ((and (message-condition? e)
                  (string? (condition-message e))
                  (str-contains? (condition-message e) needle))
             #t)
            (#t #f))
    (thunk)
    #f))
(define (check= label got want)
  (if (equal? got want)
      (begin (display "  ok  ") (display label) (newline))
      (begin (fail label)
             (display "    got  ") (write got) (newline)
             (display "    want ") (write want) (newline))))

(define dir "/tmp/igropyr-aead-test")
(system (string-append "rm -rf " dir " && mkdir -p " dir))

;; ---- helpers -----------------------------------------------------------

(define (hex->bv s)
  (let* ((n (div (string-length s) 2))
         (bv (make-bytevector n)))
    (do ((i 0 (+ i 1))) ((= i n) bv)
      (bytevector-u8-set! bv i
        (string->number (substring s (* 2 i) (+ 2 (* 2 i))) 16)))))

(define (hex bv) (bytevector->hex bv))
(define (u s) (string->utf8 s))

;; a copy with one byte flipped -- the smallest change an attacker can make
(define (flip bv i)
  (let ((c (bytevector-copy bv)))
    (bytevector-u8-set! c i (fxxor 1 (bytevector-u8-ref bv i)))
    c))

(define (raises? thunk)
  (guard (e (#t #t)) (thunk) #f))

;; an authentication failure must be exactly #f: not a shorter plaintext,
;; not a partially decrypted buffer, not a raise
(define (must-be-false label v) (check label (eq? #f v)))

(define (rejects label thunk) (check label (raises? thunk)))

(define (bv-xor a b)
  (let ((r (make-bytevector (bytevector-length a))))
    (do ((i 0 (+ i 1))) ((= i (bytevector-length a)) r)
      (bytevector-u8-set! r i (fxxor (bytevector-u8-ref a i)
                                     (bytevector-u8-ref b i))))))

;; run a command, answer its first line of output with the trailing newline
;; removed (or "" if it produced none)
(define capture-file (string-append dir "/out.txt"))
(define (run-capture cmd)
  (system (string-append "( " cmd " ) > " capture-file " 2>/dev/null"))
  (let ((s (call-with-port (open-input-file capture-file) get-string-all)))
    (let loop ((n (string-length s)))
      (cond ((= n 0) "")
            ((memv (string-ref s (- n 1)) '(#\newline #\return)) (loop (- n 1)))
            (else (substring s 0 n))))))

;; ---- 1. published known-answer vectors ---------------------------------
;;
;; McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", appendix B,
;; test cases 13-18 (the AES-256 cases). K/IV/P/A/C/T exactly as published.

(define K256a (make-string 64 #\0))                  ; 32 zero bytes
(define K256b "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
(define P60 (string-append
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
  "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"))
(define P64 (string-append P60 "1aafd255"))
(define A20 "feedfacedeadbeeffeedfacedeadbeefabaddad2")
(define C60 (string-append
  "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
  "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"))
(define C64 (string-append C60 "898015ad"))

;; (name key iv plaintext aad ciphertext tag)
(define gcm-kats
  (list
    (list "gcm-tc13" K256a (make-string 24 #\0) "" "" "" "530f8afbc74536b9a963b4f1c4cb738b")
    (list "gcm-tc14" K256a (make-string 24 #\0) (make-string 32 #\0) ""
          "cea7403d4d606b6e074ec5d3baf39d18" "d0d1c8a799996bf0265b98b5d48ab919")
    (list "gcm-tc15" K256b "cafebabefacedbaddecaf888" P64 "" C64
          "b094dac5d93471bdec1a502270e3cc6c")
    (list "gcm-tc16" K256b "cafebabefacedbaddecaf888" P60 A20 C60
          "76fc6ece0f4e1768cddf8853bb2d551b")
    ;; a 64-bit IV: GCM derives the counter block by GHASHing it instead of
    ;; using it directly, a different code path inside the cipher
    (list "gcm-tc17" K256b "cafebabefacedbad" P60 A20
          (string-append "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0"
                         "feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f")
          "3a337dbf46a792c45e454913fe2ea8f2")
    ;; a 480-bit IV, the same derived path over multiple GHASH blocks
    (list "gcm-tc18" K256b
          (string-append "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
                         "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b")
          P60 A20
          (string-append "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4"
                         "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f")
          "a44a8266ee1c8eb0c8b5d4cf5ae9f19a")))

(for-each
  (lambda (kat)
    (let* ((name (list-ref kat 0))
           (key (hex->bv (list-ref kat 1)))
           (iv  (hex->bv (list-ref kat 2)))
           (pt  (hex->bv (list-ref kat 3)))
           (aad (hex->bv (list-ref kat 4)))
           (ct  (list-ref kat 5))
           (tag (list-ref kat 6))
           (r   (aes-256-gcm-encrypt key iv pt aad)))
      (check= (string-append name "-ciphertext") (hex (vector-ref r 0)) ct)
      (check= (string-append name "-tag") (hex (vector-ref r 1)) tag)
      ;; and back: the vector's own ciphertext must decrypt to its plaintext
      (check= (string-append name "-decrypt")
              (hex (aes-256-gcm-decrypt key iv (hex->bv ct) aad (hex->bv tag)))
              (list-ref kat 3))
      ;; seal is exactly ciphertext || tag, and open is its inverse
      (check= (string-append name "-seal")
              (hex (aes-256-gcm-seal key iv pt aad))
              (string-append ct tag))
      (check= (string-append name "-open")
              (hex (aes-256-gcm-open key iv (hex->bv (string-append ct tag)) aad))
              (list-ref kat 3))))
  gcm-kats)

;; the KAT with the tag bound to the wrong AAD: same ciphertext, and the
;; published tag of tc15 (no AAD) must not authenticate tc16's AAD
(check "kat-tag-is-bound-to-aad"
  (not (aes-256-gcm-decrypt (hex->bv K256b) (hex->bv "cafebabefacedbaddecaf888")
                            (hex->bv C60) (hex->bv A20)
                            (hex->bv "b094dac5d93471bdec1a502270e3cc6c"))))

;; #f and an empty bytevector are the same AAD, as documented
(let* ((key (hex->bv K256b)) (iv (hex->bv "cafebabefacedbaddecaf888")))
  (check= "aad-#f-equals-empty"
          (hex (aes-256-gcm-seal key iv (hex->bv P64) #f))
          (hex (aes-256-gcm-seal key iv (hex->bv P64) (make-bytevector 0))))
  (check= "aad-#f-matches-tc15" (hex (aes-256-gcm-seal key iv (hex->bv P64) #f))
          (string-append C64 "b094dac5d93471bdec1a502270e3cc6c"))
  (check "open-accepts-#f-for-empty-aad"
    (equal? (aes-256-gcm-open key iv (aes-256-gcm-seal key iv (u "x") (make-bytevector 0)) #f)
            (u "x"))))

;; ---- 2. a second implementation, in another process --------------------

(define py-peer (string-append dir "/peer.py"))
(define js-peer (string-append dir "/peer.js"))

(when (file-exists? py-peer) (delete-file py-peer))
(with-output-to-file py-peer
  (lambda ()
    (display "import sys\n")
    (display "from binascii import unhexlify, hexlify\n")
    (display "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")
    (display "mode, k, iv, aad, data = sys.argv[1:6]\n")
    (display "a = AESGCM(unhexlify(k))\n")
    (display "ad = unhexlify(aad) if aad else None\n")
    (display "try:\n")
    (display "    if mode == 'seal':\n")
    (display "        out = a.encrypt(unhexlify(iv), unhexlify(data), ad)\n")
    (display "    else:\n")
    (display "        out = a.decrypt(unhexlify(iv), unhexlify(data), ad)\n")
    (display "    print(hexlify(out).decode())\n")
    (display "except Exception:\n")
    (display "    print('ERR')\n")))

(when (file-exists? js-peer) (delete-file js-peer))
(with-output-to-file js-peer
  (lambda ()
    (display "const c = require('crypto');\n")
    (display "const a = process.argv.slice(2);\n")
    (display "const K = Buffer.from(a[1],'hex'), IV = Buffer.from(a[2],'hex');\n")
    (display "const AD = a[3] ? Buffer.from(a[3],'hex') : null;\n")
    (display "const D = Buffer.from(a[4],'hex');\n")
    (display "try {\n")
    (display "  if (a[0] === 'seal') {\n")
    (display "    const ci = c.createCipheriv('aes-256-gcm', K, IV, {authTagLength:16});\n")
    (display "    if (AD) ci.setAAD(AD);\n")
    (display "    const ct = Buffer.concat([ci.update(D), ci.final()]);\n")
    (display "    console.log(Buffer.concat([ct, ci.getAuthTag()]).toString('hex'));\n")
    (display "  } else {\n")
    (display "    const de = c.createDecipheriv('aes-256-gcm', K, IV, {authTagLength:16});\n")
    (display "    if (AD) de.setAAD(AD);\n")
    (display "    de.setAuthTag(D.subarray(D.length-16));\n")
    (display "    const pt = Buffer.concat([de.update(D.subarray(0,D.length-16)), de.final()]);\n")
    (display "    console.log(pt.toString('hex'));\n")
    (display "  }\n")
    (display "} catch (e) { console.log('ERR'); }\n")))

;; python3's `cryptography` first, node second; each is a build of the
;; primitive this process did not make and does not link

;; The interpreter is looked up by every name it ships under, not just
;; the one this developer happens to have: FreeBSD installs python3.11
;; and no `python3`, so a hard-coded name silently loses the peer this
;; check exists to compare against -- and losing it looks exactly like
;; not having it.
(define python
  (let try ((cs '("python3" "python3.13" "python3.12" "python3.11"
                  "python3.10" "python")))
    (cond ((null? cs) #f)
          ((zero? (system (string-append (car cs)
                            " -c 'import cryptography' >/dev/null 2>&1")))
           (car cs))
          (else (try (cdr cs))))))

(define peer
  (cond (python
         (cons (string-append python "-cryptography")
               (string-append python " " py-peer)))
        ((zero? (system "node -e 'require(\"crypto\")' >/dev/null 2>&1"))
         (cons "node-crypto" (string-append "node " js-peer)))
        (else #f)))

(if peer
    (display (string-append "  [peer] cross-implementation checks run against "
                            (car peer) "\n"))
    (begin
      (display "  SKIP cross-implementation checks: no second AES-256-GCM\n")
      (display "       implementation on this host. The suite looked for\n")
      (display "       python3 with the `cryptography` package (pip3 install\n")
      (display "       cryptography) and for node (its built-in crypto\n")
      (display "       module). Install either one and this section runs.\n")
      (display "       The published-vector and failure-mode checks above and\n")
      (display "       below still ran; only the second implementation is\n")
      (display "       missing. The openssl CLI cannot stand in: `openssl enc`\n")
      (display "       provides no way to supply or emit a GCM tag.\n")))

(define (peer-call mode key iv aad data)
  (run-capture (string-append (cdr peer) " " mode " " (hex key) " " (hex iv)
                              " " (if (= 0 (bytevector-length aad)) "''" (hex aad))
                              " " (if (= 0 (bytevector-length data)) "''" (hex data)))))

(when peer
  (let ((key (aead-random-bytes aes-256-gcm-key-bytes))
        (iv  (aead-random-bytes aes-256-gcm-iv-bytes))
        (aad (u "purpose=cross-check;v=1"))
        (msg (u "a message that must survive the trip out and back")))
    ;; (a) sealed here, opened there
    (let ((sealed (aes-256-gcm-seal key iv msg aad)))
      (check= "peer-opens-what-we-sealed" (peer-call "open" key iv aad sealed) (hex msg))
      ;; and the peer must REJECT a forgery, or "it agreed" would only mean
      ;; "it accepted everything"
      (check= "peer-rejects-our-tampered-ciphertext"
              (peer-call "open" key iv aad (flip sealed 0)) "ERR")
      (check= "peer-rejects-our-tampered-tag"
              (peer-call "open" key iv aad
                         (flip sealed (- (bytevector-length sealed) 1)))
              "ERR")
      (check= "peer-rejects-wrong-aad"
              (peer-call "open" key iv (u "purpose=other;v=1") sealed) "ERR"))
    ;; (b) sealed there, opened here -- and byte-identical to ours, since
    ;; GCM is deterministic in (key, iv, aad, plaintext)
    (let ((theirs (hex->bv (peer-call "seal" key iv aad msg))))
      (check= "peer-seal-equals-ours" (hex theirs) (hex (aes-256-gcm-seal key iv msg aad)))
      (check= "we-open-what-peer-sealed" (aes-256-gcm-open key iv theirs aad) msg)
      (check "we-reject-peer-sealed-tampered"
        (not (aes-256-gcm-open key iv (flip theirs 3) aad)))
      (check "we-reject-peer-sealed-wrong-aad"
        (not (aes-256-gcm-open key iv theirs (u "purpose=other;v=1")))))
    ;; empty plaintext and empty AAD across the boundary: the paths that
    ;; skip EVP_*Update entirely
    (let ((sealed (aes-256-gcm-seal key iv (make-bytevector 0) (make-bytevector 0))))
      (check= "peer-opens-empty-plaintext" (peer-call "open" key iv (make-bytevector 0) sealed) "")
      (check= "peer-seals-empty-plaintext"
              (peer-call "seal" key iv (make-bytevector 0) (make-bytevector 0))
              (hex sealed)))
    ;; a length that is not a multiple of the 16-byte block, either side
    (let* ((odd (u "seventeen bytes.."))
           (sealed (aes-256-gcm-seal key iv odd #f)))
      (check= "peer-opens-non-block-multiple" (peer-call "open" key iv (make-bytevector 0) sealed)
              (hex odd))
      (check= "we-open-peer-non-block-multiple"
              (aes-256-gcm-open key iv
                (hex->bv (peer-call "seal" key iv (make-bytevector 0) odd)) #f)
              odd))
    ;; several thousand blocks, so the update path runs more than once
    ;; internally on both sides. The size is bounded by ARG_MAX rather than
    ;; by what is interesting: the hex travels on the peer's command line,
    ;; and 40000 bytes is 80KB of argument on a limit that is 256KB on the
    ;; tightest target.
    (let* ((n 40000)
           (big (make-bytevector n))
           (_ (do ((i 0 (+ i 1))) ((= i n)) (bytevector-u8-set! big i (mod (* i 7) 256))))
           (sealed (aes-256-gcm-seal key iv big (u "big"))))
      (check= "peer-opens-40k" (peer-call "open" key iv (u "big") sealed) (hex big))
      (check= "we-open-peer-40k"
              (aes-256-gcm-open key iv (hex->bv (peer-call "seal" key iv (u "big") big)) (u "big"))
              big))))

;; ---- 3. length and shape ------------------------------------------------

(let ((key (aead-random-bytes 32)) (iv (aead-random-bytes 12)))
  ;; GCM is a counter mode: the ciphertext is exactly as long as the
  ;; plaintext at every length, block-aligned or not
  (for-each
    (lambda (n)
      (let* ((pt (aead-random-bytes (max n 1)))
             (pt (if (= n 0) (make-bytevector 0) pt))
             (r (aes-256-gcm-encrypt key iv pt #f)))
        (check (string-append "ct-length-preserved-" (number->string n))
          (and (= n (bytevector-length (vector-ref r 0)))
               (= 16 (bytevector-length (vector-ref r 1)))
               (= (+ n 16) (bytevector-length (aes-256-gcm-seal key iv pt #f)))))))
    '(0 1 15 16 17 31 32 33 255 4096))
  (check "encrypt-returns-2-vector"
    (let ((r (aes-256-gcm-encrypt key iv (u "x") #f)))
      (and (vector? r) (= 2 (vector-length r)))))
  (check "tag-bytes-constant" (= 16 aes-256-gcm-tag-bytes))
  (check "key-bytes-constant" (= 32 aes-256-gcm-key-bytes))
  (check "iv-bytes-constant"  (= 12 aes-256-gcm-iv-bytes))
  ;; a long AAD spans several GHASH blocks and is not block-aligned
  (let* ((aad (aead-random-bytes 1000))
         (sealed (aes-256-gcm-seal key iv (u "bound") aad)))
    (check "long-aad-roundtrip" (equal? (aes-256-gcm-open key iv sealed aad) (u "bound")))
    (check "long-aad-tamper-rejected"
      (not (aes-256-gcm-open key iv sealed (flip aad 999))))))

;; ---- 4. authentication failures: #f, and never plaintext ---------------

(let* ((key (aead-random-bytes 32))
       (other-key (aead-random-bytes 32))
       (iv (aead-random-bytes 12))
       (other-iv (aead-random-bytes 12))
       (aad (u "record=42"))
       (msg (u "the plaintext that must not escape"))
       (r (aes-256-gcm-encrypt key iv msg aad))
       (ct (vector-ref r 0))
       (tag (vector-ref r 1))
       (sealed (aes-256-gcm-seal key iv msg aad)))
  (check "baseline-open" (equal? (aes-256-gcm-open key iv sealed aad) msg))
  (must-be-false "tampered-ciphertext-first-byte"
    (aes-256-gcm-decrypt key iv (flip ct 0) aad tag))
  (must-be-false "tampered-ciphertext-last-byte"
    (aes-256-gcm-decrypt key iv (flip ct (- (bytevector-length ct) 1)) aad tag))
  (must-be-false "tampered-tag" (aes-256-gcm-decrypt key iv ct aad (flip tag 7)))
  (must-be-false "tampered-aad" (aes-256-gcm-decrypt key iv ct (flip aad 3) tag))
  (must-be-false "aad-dropped" (aes-256-gcm-decrypt key iv ct #f tag))
  (must-be-false "aad-added"
    (aes-256-gcm-decrypt key iv (vector-ref (aes-256-gcm-encrypt key iv msg #f) 0)
                         aad (vector-ref (aes-256-gcm-encrypt key iv msg #f) 1)))
  (must-be-false "wrong-key" (aes-256-gcm-decrypt other-key iv ct aad tag))
  (must-be-false "wrong-iv"  (aes-256-gcm-decrypt key other-iv ct aad tag))
  (must-be-false "truncated-ciphertext"
    (let ((short (make-bytevector (- (bytevector-length ct) 1))))
      (bytevector-copy! ct 0 short 0 (- (bytevector-length ct) 1))
      (aes-256-gcm-decrypt key iv short aad tag)))
  (must-be-false "extended-ciphertext"
    (let ((long (make-bytevector (+ 1 (bytevector-length ct)) 0)))
      (bytevector-copy! ct 0 long 0 (bytevector-length ct))
      (aes-256-gcm-decrypt key iv long aad tag)))
  ;; a tag of the wrong length can never authenticate; the documented answer
  ;; is #f, reached without touching the cipher
  (must-be-false "tag-15-bytes"
    (let ((t (make-bytevector 15))) (bytevector-copy! tag 0 t 0 15)
      (aes-256-gcm-decrypt key iv ct aad t)))
  (must-be-false "tag-17-bytes"
    (let ((t (make-bytevector 17 0))) (bytevector-copy! tag 0 t 0 16)
      (aes-256-gcm-decrypt key iv ct aad t)))
  (must-be-false "tag-0-bytes" (aes-256-gcm-decrypt key iv ct aad (make-bytevector 0)))
  ;; seal/open: anything shorter than a tag is attacker-supplied garbage
  (must-be-false "sealed-empty" (aes-256-gcm-open key iv (make-bytevector 0) aad))
  (must-be-false "sealed-15-bytes" (aes-256-gcm-open key iv (make-bytevector 15 0) aad))
  (must-be-false "sealed-16-zero-bytes" (aes-256-gcm-open key iv (make-bytevector 16 0) aad))
  (must-be-false "sealed-tampered" (aes-256-gcm-open key iv (flip sealed 2) aad))
  (must-be-false "sealed-tag-tampered"
    (aes-256-gcm-open key iv (flip sealed (- (bytevector-length sealed) 1)) aad))
  ;; every single-bit flip in a short ciphertext must be caught, not just
  ;; the two ends
  (let* ((short (u "sixteen bytes!!!"))
         (s (aes-256-gcm-seal key iv short #f)))
    (check "every-bit-flip-rejected"
      (let loop ((i 0))
        (cond ((= i (bytevector-length s)) #t)
              ((aes-256-gcm-open key iv (flip s i) #f) #f)
              (else (loop (+ i 1))))))))

;; ---- 5. caller errors raise (they are configuration, not input) --------

(let ((key (aead-random-bytes 32)) (iv (aead-random-bytes 12)) (pt (u "x")))
  (rejects "key-16-bytes-rejected" (lambda () (aes-256-gcm-seal (make-bytevector 16 0) iv pt #f)))
  (rejects "key-31-bytes-rejected" (lambda () (aes-256-gcm-seal (make-bytevector 31 0) iv pt #f)))
  (rejects "key-33-bytes-rejected" (lambda () (aes-256-gcm-seal (make-bytevector 33 0) iv pt #f)))
  (rejects "key-0-bytes-rejected"  (lambda () (aes-256-gcm-seal (make-bytevector 0) iv pt #f)))
  (rejects "key-not-bytevector"    (lambda () (aes-256-gcm-seal "0123456789abcdef0123456789abcdef" iv pt #f)))
  (rejects "iv-empty-rejected"     (lambda () (aes-256-gcm-seal key (make-bytevector 0) pt #f)))
  (rejects "iv-not-bytevector"     (lambda () (aes-256-gcm-seal key 12 pt #f)))
  (rejects "plaintext-not-bytevector" (lambda () (aes-256-gcm-seal key iv "text" #f)))
  (rejects "aad-not-bytevector"    (lambda () (aes-256-gcm-seal key iv pt "aad")))
  (rejects "open-key-wrong-length" (lambda () (aes-256-gcm-open (make-bytevector 31 0) iv (make-bytevector 32 0) #f)))
  (rejects "open-iv-empty"         (lambda () (aes-256-gcm-open key (make-bytevector 0) (make-bytevector 32 0) #f)))
  (rejects "open-sealed-not-bytevector" (lambda () (aes-256-gcm-open key iv "sealed" #f)))
  (rejects "decrypt-tag-not-bytevector" (lambda () (aes-256-gcm-decrypt key iv (make-bytevector 4 0) #f "tag")))
  (rejects "decrypt-ct-not-bytevector"  (lambda () (aes-256-gcm-decrypt key iv "ct" #f (make-bytevector 16 0))))
  ;; a short key must NOT be silently padded to 32 nor a long one truncated:
  ;; either would quietly make two different keys into the same key, so the
  ;; near-misses are checked one at a time rather than as a range
  (rejects "key-24-bytes-rejected" (lambda () (aes-256-gcm-seal (make-bytevector 24 0) iv pt #f)))
  (rejects "key-64-bytes-rejected" (lambda () (aes-256-gcm-seal (make-bytevector 64 0) iv pt #f)))
  (rejects "decrypt-key-wrong-length"
    (lambda () (aes-256-gcm-decrypt (make-bytevector 16 0) iv (make-bytevector 4 0)
                                    #f (make-bytevector 16 0)))))

;; ---- 6. aead-random-bytes ----------------------------------------------

(check "random-length" (= 12 (bytevector-length (aead-random-bytes 12))))
(check "random-differs"
  (not (equal? (aead-random-bytes 32) (aead-random-bytes 32))))
(check "random-32-differs-over-many"
  (let loop ((i 0) (seen '()))
    (if (= i 50)
        #t
        (let ((b (aead-random-bytes 16)))
          (and (not (member b seen)) (loop (+ i 1) (cons b seen)))))))
(check "random-0-rejected"        (raises? (lambda () (aead-random-bytes 0))))
(check "random-negative-rejected" (raises? (lambda () (aead-random-bytes -1))))
(check "random-flonum-rejected"   (raises? (lambda () (aead-random-bytes 16.0))))
(check "random-non-number-rejected" (raises? (lambda () (aead-random-bytes "16"))))

;; ---- 7. what the module PROMISES about IV reuse -------------------------
;;
;; The header says the library will not generate the IV, and that an IV must
;; never repeat under one key. It does not detect reuse, and cannot: a
;; stateless procedure has nothing to remember. What it does promise is that
;; it is a faithful GCM, and a faithful GCM leaks exactly this much on
;; reuse. Pinning it means a later "optimisation" that quietly randomised or
;; derived the IV -- changing the contract callers were told to satisfy --
;; would be caught here rather than in a caller's counter.

(let* ((key (aead-random-bytes 32))
       (iv (aead-random-bytes 12))
       (m1 (u "attack at dawn!!"))
       (m2 (u "attack at dusk!!"))
       (c1 (vector-ref (aes-256-gcm-encrypt key iv m1 #f) 0))
       (c2 (vector-ref (aes-256-gcm-encrypt key iv m2 #f) 0)))
  ;; same inputs, same output: deterministic, so the IV really is the
  ;; caller's and nothing random is being mixed in behind their back
  (check "deterministic-under-fixed-iv"
    (equal? (aes-256-gcm-seal key iv m1 #f) (aes-256-gcm-seal key iv m1 #f)))
  ;; and this is the documented cost of repeating one: the keystream
  ;; cancels and the XOR of the plaintexts falls out
  (check "iv-reuse-leaks-plaintext-xor"
    (equal? (bv-xor c1 c2) (bv-xor m1 m2)))
  ;; a fresh IV does not
  (let ((c3 (vector-ref (aes-256-gcm-encrypt key (aead-random-bytes 12) m2 #f) 0)))
    (check "fresh-iv-does-not-leak" (not (equal? (bv-xor c1 c3) (bv-xor m1 m2)))))
  ;; reuse is not rejected -- it is the caller's contract, and a test that
  ;; assumed otherwise would be asserting a guarantee nobody makes
  (check "iv-reuse-not-rejected"
    (bytevector? (aes-256-gcm-seal key iv m2 #f))))

;; ---- 8. the caller's mistakes are reported whatever an attacker sends ---
;;
;; A wrong TYPE is the caller's own bug and raises; a ciphertext that will
;; not authenticate is an attacker's input and answers #f. Which of the two
;; a call is must not depend on the attacker: a sealed message too short to
;; hold a tag used to short-circuit before the aad was ever looked at, so
;; the same wrong aad raised or did not depending on how many bytes arrived.

(let ((key (aead-random-bytes 32))
      (iv (aead-random-bytes 12)))
  (define (raises? thunk) (guard (e (#t #t)) (thunk) #f))
  (check "open-checks-aad-type-on-a-short-input"
    (raises? (lambda () (aes-256-gcm-open key iv (make-bytevector 4) "not bytes"))))
  (check "open-checks-aad-type-on-an-empty-input"
    (raises? (lambda () (aes-256-gcm-open key iv (make-bytevector 0) 'nope))))
  ;; the long input already did, and must keep doing so
  (check "open-checks-aad-type-on-a-long-input"
    (raises? (lambda () (aes-256-gcm-open key iv (make-bytevector 64) "not bytes"))))
  ;; and a short input with a LEGAL aad is still an answer, not an error
  (check "short-input-with-legal-aad-answers-false"
    (not (aes-256-gcm-open key iv (make-bytevector 4) (u "ctx"))))
  (check "short-input-with-no-aad-answers-false"
    (not (aes-256-gcm-open key iv (make-bytevector 4) #f))))

;; ---- 9. what a rejected message costs -----------------------------------
;;
;; Rejecting a forgery should be cheap. It used to allocate about three
;; copies of the payload before answering #f -- the ciphertext lifted out of
;; the sealed message, the decryption scratch, and on the success path the
;; plaintext again -- so an attacker could buy three megabytes of heap
;; churn with one forged megabyte. Measured, not asserted by eye: with the
;; collector switched off for the duration, bytes-allocated is monotonic and
;; the difference across a call IS what the call allocated.

(let* ((key (aead-random-bytes 32))
       (iv (aead-random-bytes 12))
       (n (* 4 1024 1024))
       (pt (make-bytevector n 7))
       (sealed (aes-256-gcm-seal key iv pt #f))
       (forged (flip sealed 0)))
  (define (allocated-by thunk)
    (collect (collect-maximum-generation))
    (let ((h (collect-request-handler)))
      (collect-request-handler void)
      (let* ((b0 (bytes-allocated))
             (_ (thunk))
             (d (- (bytes-allocated) b0)))
        (collect-request-handler h)
        (collect (collect-maximum-generation))
        d)))
  (let ((rejected (allocated-by (lambda () (aes-256-gcm-open key iv forged #f))))
        (accepted (allocated-by (lambda () (aes-256-gcm-open key iv sealed #f)))))
    (display "  [alloc] 4 MiB payload: reject ") (display rejected)
    (display " B, accept ") (display accepted) (display " B\n")
    ;; one payload-sized buffer plus slack, not two or three. The bound is
    ;; 1.5x so it cannot be met by accident and cannot fail on rounding.
    (check "rejecting-a-forgery-allocates-one-buffer"
      (< rejected (* 3/2 n)))
    (check "opening-a-real-message-allocates-one-buffer"
      (< accepted (* 3/2 n)))))

;; ---- 10. the OpenSSL error queue belongs to the OS thread ---------------
;;
;; One OS thread runs every green process, so all of them share one error
;; queue. A library that calls ERR_clear_error on its failure path is
;; deleting whatever else was on it -- an in-flight TLS session preempted
;; between SSL_read and SSL_get_error, for instance -- and a library that
;; clears nothing leaves its own failures to be reported as somebody else's
;; reason. Neither is acceptable, and the answer is a scope: mark on entry,
;; pop to the mark on exit, so exactly the entries this operation pushed go
;; away. Checked from outside the library, against the same libcrypto.

(define ERR_clear_error #f)
(define ERR_peek_error #f)
(define push-openssl-error! #f)

(let ()
  (import (igropyr platform))
  (load-first-shared-object! 'aead-test (shared-object-candidates "libcrypto"))
  (set! ERR_clear_error (foreign-procedure "ERR_clear_error" () void))
  (set! ERR_peek_error (foreign-procedure "ERR_peek_error" () unsigned-long))
  (let ((BIO_new_mem_buf (foreign-procedure "BIO_new_mem_buf" (void* int) void*))
        (BIO_free (foreign-procedure "BIO_free" (void*) int))
        (PEM_read_bio_PUBKEY
          (foreign-procedure "PEM_read_bio_PUBKEY" (void* void* void* void*) void*))
        (memcpy-to-c (foreign-procedure "memcpy" (void* u8* size_t) void*))
        ;; no Proc-Type/DEK-Info here, so a NULL callback cannot reach a
        ;; passphrase prompt; it just fails and leaves entries on the queue
        (garbage (u "-----BEGIN PUBLIC KEY-----\nAAAAAAAAAAAAAAAA\n-----END PUBLIC KEY-----\n")))
    (set! push-openssl-error!
      (lambda ()
        (let* ((len (bytevector-length garbage))
               (buf (foreign-alloc len)))
          (memcpy-to-c buf garbage len)
          (let ((bio (BIO_new_mem_buf buf len)))
            (PEM_read_bio_PUBKEY bio 0 0 0)
            (BIO_free bio))
          (foreign-free buf))))))

(let* ((key (aead-random-bytes 32))
       (iv (aead-random-bytes 12))
       (sealed (aes-256-gcm-seal key iv (u "queue probe") (u "aad")))
       (forged (flip sealed 3)))
  ;; each check plants its own entry, so one of them failing cannot make the
  ;; next one fail for a reason that is not its own
  (define (with-planted-error thunk)
    (ERR_clear_error)
    (push-openssl-error!)
    (let ((planted (ERR_peek_error)))
      (thunk)
      (and (not (zero? planted)) (= planted (ERR_peek_error)))))
  (define (leaves-nothing thunk)
    (ERR_clear_error)
    (thunk)
    (zero? (ERR_peek_error)))
  (ERR_clear_error)
  (push-openssl-error!)
  (if (zero? (ERR_peek_error))
      (begin
        (ERR_clear_error)
        (display "  SKIP error-queue scoping checks: a deliberately malformed\n")
        (display "       PEM left nothing on this build's error queue, so\n")
        (display "       there is no planted entry to see preserved and the\n")
        (display "       checks would pass vacuously.\n"))
      (begin
        (ERR_clear_error)
        ;; a rejected tag must not delete an unrelated pending error
        (check "aead-failure-preserves-an-unrelated-error"
          (with-planted-error
            (lambda () (aes-256-gcm-open key iv forged (u "aad")))))
        ;; nor a successful call
        (check "aead-success-preserves-an-unrelated-error"
          (with-planted-error
            (lambda () (aes-256-gcm-open key iv sealed (u "aad")))))
        ;; nor a raise out of one
        (check "aead-raise-preserves-an-unrelated-error"
          (with-planted-error
            (lambda ()
              (guard (e (#t #t))
                (aes-256-gcm-encrypt (make-bytevector 31 0) iv (u "x") #f)))))
        (check "aead-random-bytes-preserves-an-unrelated-error"
          (with-planted-error (lambda () (aead-random-bytes 16))))
        ;; and in the other direction: nothing of its own is left behind
        (check "aead-failure-leaves-nothing-behind"
          (leaves-nothing (lambda () (aes-256-gcm-open key iv forged (u "aad")))))
        (check "aead-success-leaves-nothing-behind"
          (leaves-nothing (lambda () (aes-256-gcm-open key iv sealed (u "aad")))))
        (check "aead-random-bytes-leaves-nothing-behind"
          (leaves-nothing (lambda () (aead-random-bytes 16))))
        (ERR_clear_error))))

;; NOT TESTED, and worth saying so rather than shipping an assertion that
;; cannot fail: that the decryption buffer is zeroed when the tag is
;; rejected. The buffer is internal, and once aes-256-gcm-decrypt has
;; returned #f nothing in Scheme holds a reference to it -- there is no
;; supported way to look at freed heap from inside the process, and a check
;; that scanned for the plaintext would be asserting something about the
;; collector, not about this library. The wipe is verifiable only by reading
;; the failure branch of decrypt-core.

;; ---- 11. FFI discipline: the error paths must free their contexts ------
;;
;; Each call allocates an EVP_CIPHER_CTX, and a GCM context carries its
;; multiplication tables -- kilobytes apiece. A path that raises or answers
;; #f without freeing shows up as unbounded RSS growth here and nowhere
;; else, since nothing else in the suite runs a failure often enough.

(define rss-file (string-append dir "/rss.txt"))
(define (rss-kb)
  (system (string-append "ps -o rss= -p " (number->string (get-process-id))
                         " > " rss-file " 2>/dev/null"))
  (let ((s (call-with-port (open-input-file rss-file) get-string-all)))
    (or (string->number (let loop ((i 0))
                          (cond ((= i (string-length s)) "0")
                                ((char-whitespace? (string-ref s i)) (loop (+ i 1)))
                                (else (let loop2 ((j i))
                                        (if (or (= j (string-length s))
                                                (char-whitespace? (string-ref s j)))
                                            (substring s i j)
                                            (loop2 (+ j 1))))))))
        0)))

(let* ((key (aead-random-bytes 32))
       (iv (aead-random-bytes 12))
       (sealed (aes-256-gcm-seal key iv (u "leak probe") (u "aad")))
       (bad (flip sealed 0))
       (badkey (make-bytevector 31 0))
       (n 50000))
  ;; warm up so the comparison is not measuring first-touch growth
  (do ((i 0 (+ i 1))) ((= i 2000))
    (aes-256-gcm-open key iv bad (u "aad")))
  (collect (collect-maximum-generation))
  (let ((before (rss-kb)))
    (if (zero? before)
        ;; a zero reading is no reading: comparing 0 to 0 would pass however
        ;; badly the library leaked, which is worse than not measuring
        (begin
          (display "  SKIP resident-set check: `ps -o rss= -p PID` printed no\n")
          (display "       number on this host, so there is nothing to compare\n")
          (display "       and the check would pass vacuously. Every other\n")
          (display "       check in this suite ran; to cover the FFI free paths\n")
          (display "       as well, run where ps reports RSS in kilobytes.\n"))
        (begin
          (do ((i 0 (+ i 1))) ((= i n))
            ;; authentication failure: freed by the dynamic-wind, or leaked
            (aes-256-gcm-open key iv bad (u "aad"))
            ;; a raise out of the middle of a call: same question, harder path
            (guard (e (#t #t)) (aes-256-gcm-seal badkey iv (u "x") #f)))
          (collect (collect-maximum-generation))
          (let* ((after (rss-kb)) (grew (- after before)))
            (display "  [rss] ") (display n)
            (display " failed opens + refused keys: ") (display before)
            (display " -> ") (display after) (display " KB\n")
            ;; one leaked GCM context is several KB; 50000 of them is hundreds
            ;; of megabytes, so this bound is loose enough not to be noise and
            ;; tight enough to catch a missing free
            (check "no-rss-growth-on-failure-paths" (< grew 65536)))))))

;; ---- 32-bit addressing edges (opt-in: each allocates ~2 GiB) ----------
;; aead-max-bytes = 2^31-1 is the ceiling for the C int lengths OpenSSL's
;; RAND_bytes and the cipher take. These pin the two places a length past
;; it must be refused cleanly rather than truncated or over-produced.
(if (getenv "IGROPYR_AEAD_HUGE_TEST")
    (let ((max-bytes (- (expt 2 31) 1)))
      ;; A4: a request past the int ceiling must be refused BY OUR CHECK
      ;; (message names the ceiling), before allocation or the FFI -- not
      ;; merely raise some low-level error a too-large value would raise
      ;; anyway
      (check "random past 32-bit ceiling raises our own bound error"
        (raises-message-containing? "exceeds"
          (lambda () (aead-random-bytes (+ max-bytes 1)))))
      ;; A3: seal must refuse (again by our own check) a plaintext whose
      ;; sealed form (plaintext || 16-byte tag) would exceed what open can
      ;; address -- otherwise seal produces a message its own opener rejects
      (let ((k (make-bytevector 32 7)) (iv (make-bytevector 12 3)))
        (check "seal refuses plaintext whose sealed form open cannot address"
          (raises-message-containing? "too long"
            (lambda ()
              (aes-256-gcm-seal k iv (make-bytevector (- max-bytes 15) 0) #f))))))
    (begin
      (display "  skip  32-bit addressing edges (set IGROPYR_AEAD_HUGE_TEST")
      (display " to run; each allocates ~2 GiB)\n")))

(system (string-append "rm -rf " dir))

(if (zero? failures)
    (begin (display "aead: all tests passed\n") (exit 0))
    (begin (display failures) (display " failures\n") (exit 1)))
