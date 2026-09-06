#!chezscheme
;;; mesh-proof.sc -- an INDEPENDENT implementation of the mesh handshake proofs
;;; for protocol version 5, for the cells that drive a node's handshake by hand.
;;;
;;; Written from the design (archive/igropyr-mesh-tls-design, section 4.3 and
;;; codex r2-P 3), not copied from node.sc: a cell that shares the production
;;; helper would pass whatever that helper computes. The preimages are
;;;   D = nonce-a ":" name-d ":5:" bootid-d ":" dialgen ":" name-a ":" bootid-a ":" cbhex
;;;   A = nonce-b ":" name-a ":5:" bootid-a ":" cbhex
;;; where cbhex is the lowercase hex of the RFC 5929 tls-server-end-point hash of
;;; the acceptor's certificate, and the EMPTY string on a plaintext link (the
;;; trailing separator is present in both cases). The HMAC key is the UTF-8 of
;;; the shared secret; the proof is the lowercase hex of HMAC-SHA256.
(library (test mesh-proof)
  (export v5-proof-d v5-proof-a v5-preimage-d v5-preimage-a cb->hex)
  (import (chezscheme) (only (igropyr crypto) hmac-sha256 bytevector->hex))
  (define (cb->hex cb) (if cb (bytevector->hex cb) ""))
  (define (v5-preimage-d nonce-a name-d bootid-d dialgen name-a bootid-a cb)
    (string-append nonce-a ":" name-d ":5:" bootid-d ":" (number->string dialgen) ":"
                   name-a ":" bootid-a ":" (cb->hex cb)))
  (define (v5-preimage-a nonce-b name-a bootid-a cb)
    (string-append nonce-b ":" name-a ":5:" bootid-a ":" (cb->hex cb)))
  (define (mac secret msg)
    (bytevector->hex (hmac-sha256 (string->utf8 secret) (string->utf8 msg))))
  (define (v5-proof-d secret nonce-a name-d bootid-d dialgen name-a bootid-a cb)
    (mac secret (v5-preimage-d nonce-a name-d bootid-d dialgen name-a bootid-a cb)))
  (define (v5-proof-a secret nonce-b name-a bootid-a cb)
    (mac secret (v5-preimage-a nonce-b name-a bootid-a cb)))
)
