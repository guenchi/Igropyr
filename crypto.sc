#!chezscheme
;;; (igropyr crypto) -- hashing, HMAC, base64, and hex.
;;;
;;; The small pile of primitives the rest of igropyr needs for wire
;;; handshakes, gathered in one place instead of three:
;;;
;;;   sha1 / sha256          bytevector -> raw digest (20 / 32 bytes)
;;;   hmac-sha1 / hmac-sha256  (key msg) -> raw digest; keys longer than
;;;                            the 64-byte block are hashed first (RFC 2104)
;;;   base64-encode          bytevector -> string (RFC 4648, '=' padded)
;;;   base64-decode          string -> bytevector (skips '=', whitespace)
;;;   bytevector->hex        bytevector -> lowercase hex string
;;;
;;; None of it is a security boundary on its own: SHA-1 lives here only
;;; for the WebSocket upgrade key and the MySQL auth scramble, both of
;;; which the wire protocols mandate. The node distribution handshake
;;; uses hmac-sha256. All functions are pure and depend only on
;;; (chezscheme), so this library sits at the bottom of the build.

(library (igropyr crypto)
  (export sha1 sha256 hmac-sha1 hmac-sha256 pbkdf2-hmac-sha256
          base64-encode base64-decode bytevector->hex)
  (import (chezscheme))

  ;; concatenate two bytevectors (HMAC's inner/outer pad || message)
  (define (bv-append a b)
    (let ((la (bytevector-length a)) (lb (bytevector-length b)))
      (let ((r (make-bytevector (fx+ la lb))))
        (bytevector-copy! a 0 r 0 la)
        (bytevector-copy! b 0 r la lb)
        r)))

  ;; ---- shared 32-bit arithmetic ---------------------------------------

  (define mask32 #xFFFFFFFF)

  (define (add32 . xs)
    (fxand (apply fx+ xs) mask32))

  (define (rotl32 x n)
    (fxior (fxsll (fxand x (fx- (fxsll 1 (fx- 32 n)) 1)) n)
           (fxsrl x (fx- 32 n))))

  (define (rotr32 x n)
    (fxior (fxsrl x n)
           (fxsll (fxand x (fx- (fxsll 1 n) 1)) (fx- 32 n))))

  (define (shr32 x n) (fxsrl x n))

  ;; ---- SHA-1 ----------------------------------------------------------

  (define (sha1 msg)
    (let* ((len (bytevector-length msg))
           (padlen (let ((r (mod (+ len 1) 64)))
                     (if (<= r 56) (- 56 r) (- 120 r))))
           (total (+ len 1 padlen 8))
           (buf (make-bytevector total 0))
           (w (make-vector 80 0)))
      (bytevector-copy! msg 0 buf 0 len)
      (bytevector-u8-set! buf len #x80)
      (do ((i 0 (+ i 1))) ((= i 8))
        (bytevector-u8-set! buf (- total 1 i)
          (fxand (bitwise-arithmetic-shift-right (* len 8) (* 8 i)) #xFF)))
      (let blocks ((blk 0)
                   (h0 #x67452301) (h1 #xEFCDAB89) (h2 #x98BADCFE)
                   (h3 #x10325476) (h4 #xC3D2E1F0))
        (if (= blk (div total 64))
            (let ((out (make-bytevector 20)))
              (let put ((i 0) (hs (list h0 h1 h2 h3 h4)))
                (unless (null? hs)
                  (let ((h (car hs)))
                    (bytevector-u8-set! out i (fxsrl h 24))
                    (bytevector-u8-set! out (+ i 1) (fxand (fxsrl h 16) #xFF))
                    (bytevector-u8-set! out (+ i 2) (fxand (fxsrl h 8) #xFF))
                    (bytevector-u8-set! out (+ i 3) (fxand h #xFF)))
                  (put (+ i 4) (cdr hs))))
              out)
            (begin
              (do ((t 0 (+ t 1))) ((= t 16))
                (let ((b (+ (* blk 64) (* t 4))))
                  (vector-set! w t
                    (fxior (fxsll (bytevector-u8-ref buf b) 24)
                           (fxsll (bytevector-u8-ref buf (+ b 1)) 16)
                           (fxsll (bytevector-u8-ref buf (+ b 2)) 8)
                           (bytevector-u8-ref buf (+ b 3))))))
              (do ((t 16 (+ t 1))) ((= t 80))
                (vector-set! w t
                  (rotl32 (fxxor (vector-ref w (- t 3))
                                 (vector-ref w (- t 8))
                                 (vector-ref w (- t 14))
                                 (vector-ref w (- t 16)))
                          1)))
              (let rounds ((t 0) (a h0) (b h1) (c h2) (d h3) (e h4))
                (if (= t 80)
                    (blocks (+ blk 1)
                            (add32 h0 a) (add32 h1 b) (add32 h2 c)
                            (add32 h3 d) (add32 h4 e))
                    (let ((f (cond
                               ((< t 20)
                                (fxior (fxand b c)
                                       (fxand (fxxor b mask32) d)))
                               ((< t 40) (fxxor b c d))
                               ((< t 60)
                                (fxior (fxand b c) (fxand b d) (fxand c d)))
                               (else (fxxor b c d))))
                          (k (cond
                               ((< t 20) #x5A827999)
                               ((< t 40) #x6ED9EBA1)
                               ((< t 60) #x8F1BBCDC)
                               (else #xCA62C1D6))))
                      (rounds (+ t 1)
                              (add32 (rotl32 a 5) f e k (vector-ref w t))
                              a (rotl32 b 30) c d)))))))))

  ;; ---- SHA-256 --------------------------------------------------------

  (define sha256-k
    '#(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1
       #x923f82a4 #xab1c5ed5 #xd807aa98 #x12835b01 #x243185be #x550c7dc3
       #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174 #xe49b69c1 #xefbe4786
       #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
       #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147
       #x06ca6351 #x14292967 #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
       #x650a7354 #x766a0abb #x81c2c92e #x92722c85 #xa2bfe8a1 #xa81a664b
       #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
       #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a
       #x5b9cca4f #x682e6ff3 #x748f82ee #x78a5636f #x84c87814 #x8cc70208
       #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))

  (define (sha256 msg)
    (let* ((len (bytevector-length msg))
           (padlen (let ((r (mod (+ len 1) 64)))
                     (if (<= r 56) (- 56 r) (- 120 r))))
           (total (+ len 1 padlen 8))
           (buf (make-bytevector total 0))
           (w (make-vector 64 0)))
      (bytevector-copy! msg 0 buf 0 len)
      (bytevector-u8-set! buf len #x80)
      (do ((i 0 (+ i 1))) ((= i 8))
        (bytevector-u8-set! buf (- total 1 i)
          (fxand (bitwise-arithmetic-shift-right (* len 8) (* 8 i)) #xFF)))
      (let blocks ((blk 0)
                   (h0 #x6a09e667) (h1 #xbb67ae85) (h2 #x3c6ef372)
                   (h3 #xa54ff53a) (h4 #x510e527f) (h5 #x9b05688c)
                   (h6 #x1f83d9ab) (h7 #x5be0cd19))
        (if (= blk (div total 64))
            (let ((out (make-bytevector 32)))
              (let put ((i 0) (hs (list h0 h1 h2 h3 h4 h5 h6 h7)))
                (unless (null? hs)
                  (let ((h (car hs)))
                    (bytevector-u8-set! out i (fxsrl h 24))
                    (bytevector-u8-set! out (+ i 1) (fxand (fxsrl h 16) #xFF))
                    (bytevector-u8-set! out (+ i 2) (fxand (fxsrl h 8) #xFF))
                    (bytevector-u8-set! out (+ i 3) (fxand h #xFF)))
                  (put (+ i 4) (cdr hs))))
              out)
            (begin
              (do ((t 0 (+ t 1))) ((= t 16))
                (let ((b (+ (* blk 64) (* t 4))))
                  (vector-set! w t
                    (fxior (fxsll (bytevector-u8-ref buf b) 24)
                           (fxsll (bytevector-u8-ref buf (+ b 1)) 16)
                           (fxsll (bytevector-u8-ref buf (+ b 2)) 8)
                           (bytevector-u8-ref buf (+ b 3))))))
              (do ((t 16 (+ t 1))) ((= t 64))
                (let ((s0 (let ((x (vector-ref w (- t 15))))
                            (fxxor (rotr32 x 7) (rotr32 x 18) (shr32 x 3))))
                      (s1 (let ((x (vector-ref w (- t 2))))
                            (fxxor (rotr32 x 17) (rotr32 x 19) (shr32 x 10)))))
                  (vector-set! w t
                    (add32 (vector-ref w (- t 16)) s0 (vector-ref w (- t 7)) s1))))
              (let rounds ((t 0) (a h0) (b h1) (c h2) (d h3)
                           (e h4) (f h5) (g h6) (h h7))
                (if (= t 64)
                    (blocks (+ blk 1)
                            (add32 h0 a) (add32 h1 b) (add32 h2 c) (add32 h3 d)
                            (add32 h4 e) (add32 h5 f) (add32 h6 g) (add32 h7 h))
                    (let* ((S1 (fxxor (rotr32 e 6) (rotr32 e 11) (rotr32 e 25)))
                           (ch (fxxor (fxand e f) (fxand (fxxor e mask32) g)))
                           (t1 (add32 h S1 ch (vector-ref sha256-k t) (vector-ref w t)))
                           (S0 (fxxor (rotr32 a 2) (rotr32 a 13) (rotr32 a 22)))
                           (mj (fxxor (fxand a b) (fxand a c) (fxand b c)))
                           (t2 (add32 S0 mj)))
                      (rounds (+ t 1)
                              (add32 t1 t2) a b c
                              (add32 d t1) e f g)))))))))

  ;; ---- HMAC (RFC 2104) ------------------------------------------------
  ;; Generic over any 64-byte-block hash; SHA-1 and SHA-256 both qualify.

  (define (hmac hash block key msg)
    (let* ((k (if (> (bytevector-length key) block) (hash key) key))
           (k+ (make-bytevector block 0))
           (ipad (make-bytevector block))
           (opad (make-bytevector block)))
      (bytevector-copy! k 0 k+ 0 (bytevector-length k))
      (do ((i 0 (fx+ i 1))) ((fx= i block))
        (let ((b (bytevector-u8-ref k+ i)))
          (bytevector-u8-set! ipad i (fxxor b #x36))
          (bytevector-u8-set! opad i (fxxor b #x5c))))
      (hash (bv-append opad (hash (bv-append ipad msg))))))

  (define (hmac-sha1 key msg) (hmac sha1 64 key msg))
  (define (hmac-sha256 key msg) (hmac sha256 64 key msg))

  ;; ---- PBKDF2 (RFC 2898, PRF = HMAC-SHA256) ---------------------------
  ;; Password hashing where there is no bcrypt/scrypt: pick a random
  ;; per-user salt and a high iteration count, store salt+iterations+DK.
  ;; password and salt are bytevectors; dk-len is the wanted byte length.
  (define (pbkdf2-hmac-sha256 password salt iterations dk-len)
    (define h-len 32)
    (define (u32be i)
      (bytevector (fxand (fxsrl i 24) #xFF) (fxand (fxsrl i 16) #xFF)
                  (fxand (fxsrl i 8) #xFF) (fxand i #xFF)))
    (define (xor-into! acc u)          ; acc ^= u over the first h-len bytes
      (do ((j 0 (fx+ j 1))) ((fx= j h-len) acc)
        (bytevector-u8-set! acc j
          (fxxor (bytevector-u8-ref acc j) (bytevector-u8-ref u j)))))
    (define (block i)                  ; T_i = U_1 xor U_2 xor ... xor U_c
      (let ((u1 (hmac-sha256 password (bv-append salt (u32be i)))))
        (let loop ((c 1) (u u1) (acc (bytevector-copy u1)))
          (if (fx>= c iterations)
              acc
              (let ((u* (hmac-sha256 password u)))
                (loop (fx+ c 1) u* (xor-into! acc u*)))))))
    (let* ((nblocks (fxdiv (fx+ dk-len (fx- h-len 1)) h-len))
           (out (make-bytevector (fx* nblocks h-len))))
      (do ((i 1 (fx+ i 1))) ((fx> i nblocks))
        (bytevector-copy! (block i) 0 out (fx* (fx- i 1) h-len) h-len))
      (if (fx= (bytevector-length out) dk-len)
          out
          (let ((r (make-bytevector dk-len)))
            (bytevector-copy! out 0 r 0 dk-len)
            r))))

  ;; ---- base64 ---------------------------------------------------------

  (define b64-chars
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

  (define (base64-encode bv)
    (let ((n (bytevector-length bv)))
      (call-with-string-output-port
        (lambda (p)
          (define (out i) (write-char (string-ref b64-chars i) p))
          (let loop ((i 0))
            (let ((left (- n i)))
              (cond
                ((>= left 3)
                 (let ((b0 (bytevector-u8-ref bv i))
                       (b1 (bytevector-u8-ref bv (+ i 1)))
                       (b2 (bytevector-u8-ref bv (+ i 2))))
                   (out (fxsrl b0 2))
                   (out (fxior (fxsll (fxand b0 3) 4) (fxsrl b1 4)))
                   (out (fxior (fxsll (fxand b1 15) 2) (fxsrl b2 6)))
                   (out (fxand b2 63))
                   (loop (+ i 3))))
                ((= left 2)
                 (let ((b0 (bytevector-u8-ref bv i))
                       (b1 (bytevector-u8-ref bv (+ i 1))))
                   (out (fxsrl b0 2))
                   (out (fxior (fxsll (fxand b0 3) 4) (fxsrl b1 4)))
                   (out (fxsll (fxand b1 15) 2))
                   (write-char #\= p)))
                ((= left 1)
                 (let ((b0 (bytevector-u8-ref bv i)))
                   (out (fxsrl b0 2))
                   (out (fxsll (fxand b0 3) 4))
                   (write-char #\= p)
                   (write-char #\= p)))
                (else (void)))))))))

  (define (b64-value ch)
    (cond
      ((and (char<=? #\A ch) (char<=? ch #\Z)) (- (char->integer ch) 65))
      ((and (char<=? #\a ch) (char<=? ch #\z)) (+ 26 (- (char->integer ch) 97)))
      ((and (char<=? #\0 ch) (char<=? ch #\9)) (+ 52 (- (char->integer ch) 48)))
      ((char=? ch #\+) 62)
      ((char=? ch #\/) 63)
      (else #f)))

  (define (base64-decode s)
    (let-values (((p get) (open-bytevector-output-port)))
      (let loop ((i 0) (acc 0) (bits 0))
        (if (= i (string-length s))
            (get)
            (let ((v (b64-value (string-ref s i))))
              (if (not v)
                  (loop (+ i 1) acc bits)   ; skip '=', newlines, etc.
                  (let ((acc (+ (* acc 64) v)) (bits (+ bits 6)))
                    (if (>= bits 8)
                        (let ((keep (- bits 8)))
                          (put-u8 p (fxand (bitwise-arithmetic-shift-right acc keep) #xFF))
                          (loop (+ i 1) (fxand acc (- (fxsll 1 keep) 1)) keep))
                        (loop (+ i 1) acc bits)))))))))

  ;; ---- hex ------------------------------------------------------------

  (define hex-digits "0123456789abcdef")

  (define (bytevector->hex bv)
    (let* ((n (bytevector-length bv)) (s (make-string (* n 2))))
      (do ((i 0 (fx+ i 1))) ((fx= i n) s)
        (let ((b (bytevector-u8-ref bv i)))
          (string-set! s (fx* i 2) (string-ref hex-digits (fxsrl b 4)))
          (string-set! s (fx+ (fx* i 2) 1) (string-ref hex-digits (fxand b 15)))))))
)
