#!chezscheme
;;; test/rcall-reply-peer.sc -- a reply is taken only from the peer the
;;; call was sent to.
;;;
;;; A pending call is indexed by its ref and remembers the peer it went
;;; to. A reply frame carrying that ref from ANOTHER authenticated peer
;;; must change nothing: not be delivered as the answer, and not take the
;;; pending entry with it -- a branch that deleted the entry before it
;;; compared the peer would leave the real peer's answer, arriving next,
;;; with nothing to deliver to, and the caller with a timeout. The reply
;;; branch compares the slot's peer first and does both the send and the
;;; delete under that comparison; this file pins it (R21 of the
;;; 2026-09-07 review, whose reproduction executed an extracted copy of the
;;; branch rather than the node).
;;;
;;; Two fake peers complete the handshake by hand; the node's rcall goes to
;;; `callee`; the call frame's ref is handed to `intruder`, which answers
;;; first with a value of its own; `callee` answers after it. The caller
;;; must get callee's value, promptly. Twin: with no intruder, the same.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr tcp) (igropyr node)
        (only (igropyr crypto) hmac-sha256 bytevector->hex))

(define port 18103)
(define secret "test-mesh-secret")
(define failures 0)
(define (check label ok . info)
  (if ok
      (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info)
             (newline))))
(define (fail! label . info)
  (apply check label #f info)
  (display "rcall-reply-peer: aborted\n") (exit 1))

;; ---- the wire, copied from test/node.sc ---------------------------------------------------
(define (frame-bytes datum)
  (let ((o (open-output-string)))
    (write datum o)
    (let ((body (get-output-string o)))
      (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))
(define (read-frame-or-closed label)
  (let loop ((acc ""))
    (let* ((n (string-length acc))
           (nl (let scan ((k 0))
                 (cond ((= k n) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1))))))
           (len (and nl (string->number (substring acc 0 nl)))))
      (if (and len (>= n (+ nl 1 len)))
          (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len))))
          (receive (after 4000 (fail! label 'frame-timeout acc))
            (`#(tcp-data ,bv) (loop (string-append acc (utf8->string bv))))
            (`#(tcp-eof) (if (zero? (string-length acc)) 'closed 'closed-with-bytes))
            (`#(tcp-error ,_) (if (zero? (string-length acc)) 'closed 'closed-with-bytes)))))))
(define wire-name-of-this-node "a")
(define probe-boot-id "feedfacefeedface")
(define (v4-hmac msg) (bytevector->hex (hmac-sha256 (string->utf8 secret) (string->utf8 msg))))
(define (v4-proof-d nonce-a name-d bootid-d dialgen name-a bootid-a)
  (v4-hmac (string-append nonce-a ":" name-d ":5:" bootid-d ":" dialgen ":" name-a ":" bootid-a ":")))
(define (handshake-as! name label)
  (tcp-connect! "127.0.0.1" port self)
  (receive (after 3000 (fail! label 'no-connect))
    (`#(tcp-connected ,c)
      (tcp-read-start! c)
      (let ((d (read-frame-or-closed label)))
        (unless (and (pair? d) (= (length d) 4) (eq? (car d) 'challenge))
          (fail! label 'challenge-shape d))
        (let ((nonce-a (cadr d)) (bootid-a (cadddr d)))
          (tcp-write! c (frame-bytes (list 'hello name
                                           (v4-proof-d nonce-a name probe-boot-id "1" wire-name-of-this-node bootid-a)
                                           "feedfeedfeedfeedfeedfeedfeedfeed" 5 probe-boot-id 1))
                      #f)
          (let ((w (read-frame-or-closed label)))
            (unless (and (pair? w) (eq? (car w) 'welcome)) (fail! label 'no-welcome w)))))
      c)
    (`#(tcp-connect-failed ,e) (fail! label 'no-connect e))))

;; A fake peer in its own process: handshakes, then follows orders from
;; main: #(expect-call from) reads one call frame and sends #(call-ref ref)
;; to `from`; #(reply ref value) writes a reply frame; #(close).
(define (peer! name)
  (let* ((me self)
         (pid
    (spawn
      (lambda ()
        (let ((c (handshake-as! name name)))
          (send me (vector 'peer-up name))
          (let loop ()
            (receive
              (`#(expect-call ,from)
                (let ((d (read-frame-or-closed name)))
                  (if (and (pair? d) (eq? (car d) 'call) (= (length d) 5))
                      (send from (vector 'call-ref (caddr d)))
                      (send from (vector 'call-ref #f d))))
                (loop))
              (`#(reply ,ref ,value)
                (tcp-write! c (frame-bytes (list 'reply ref (list 'ok value))) #f)
                (loop))
              (`#(close) (tcp-close! c)))))))))
    (receive (after 5000 (fail! name 'no-peer-up)) (`#(peer-up ,n) (void)))
    pid))

(define (call! who reg)
  (let ((me self) (ref (gensym)))
    (spawn (lambda ()
             (send me (vector ref (guard (e (#t (list 'raised e))) (rcall who reg (vector 'q) 6000))))))
    ref))

(start-scheduler
  (lambda ()
    (node-start! 'a secret port)
    (sleep-ms 200)
    (register 'main self)
    (let ((me self))
      (monitor-node 'callee)
      (monitor-node 'intruder)
      (let ((callee (peer! "callee")) (intruder (peer! "intruder")))
        (receive (after 8000 (fail! "setup" 'no-node-up-callee)) (`#(node-up callee) 'ok))
        (receive (after 8000 (fail! "setup" 'no-node-up-intruder)) (`#(node-up intruder) 'ok))

        ;; ---- twin: the callee answers, nobody else ---------------------------------------
        (send callee (vector 'expect-call me))
        (let* ((ref (call! 'callee 'echo))
               (cref (receive (after 5000 #f) (`#(call-ref ,r) r))))
          (check "twin: the call frame reaches the callee with an exact ref" (and cref (integer? cref)) cref)
          (send callee (vector 'reply cref 42))
          (let ((v (receive (after 7000 'timeout) (`#(,@ref ,v) v))))
            (check "twin: the callee's reply is the call's value" (equal? v 42) v)))

        ;; ---- an intruder answers first with the same ref ----------------------------------
        (send callee (vector 'expect-call me))
        (let* ((t0 (now-ms))
               (ref (call! 'callee 'echo))
               (cref (receive (after 5000 #f) (`#(call-ref ,r) r))))
          (check "the call frame reaches the callee" (and cref (integer? cref)) cref)
          (send intruder (vector 'reply cref 999))
          (sleep-ms 300)
          (send callee (vector 'reply cref 42))
          (let ((v (receive (after 7000 'timeout) (`#(,@ref ,v) v))))
            (check "a reply from a peer the call was not sent to is not delivered as the answer"
                   (not (equal? v 999)) v)
            (check "the real peer's reply, arriving after it, is delivered -- the pending entry survived the intruder"
                   (equal? v 42) v)
            (check "  promptly, not by the caller's timeout" (< (- (now-ms) t0) 3000) (- (now-ms) t0))))

        (send callee (vector 'close))
        (send intruder (vector 'close))))
    (if (zero? failures)
        (begin (display "rcall-reply-peer: all tests passed\n") (exit 0))
        (begin (display "rcall-reply-peer: ") (display failures) (display " failed\n") (exit 1)))))
