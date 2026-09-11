#!chezscheme
;;; plain-peer.sc -- a plaintext mesh peer by hand, for cells that need a
;;; controllable far end without TLS (B' cleanup-record cells).
;;;
;;;   (plain-peer-open host port name boot-id gen secret ms) -> peer | (failed . why)
;;;       connects, completes the version-5 handshake as `name` (empty binding),
;;;       returns after the welcome; the peer process then serves frames.
;;;   (plain-peer-frames peer)            -> frames received so far (oldest first), drained
;;;   (plain-peer-wait-frame peer pred ms) -> the first received frame satisfying pred, or #f
;;;   (plain-peer-send! peer datum)        ; a frame to the node, e.g. (reply ref (ok 42)) or (mdown mref reason)
;;;   (plain-peer-auto-reply! peer thunk)  ; answer every (call ...) frame with (reply ref (ok (thunk msg)))
;;;   (plain-peer-close! peer)             ; close the socket (the node sees tcp-eof)
;;;   (plain-peer-alive? peer)
;;;   (plain-peer-closed? peer)           -> #t once the node closed the socket (tcp-eof/error seen)
;;;   (plain-peer-count peer pred)        -> how many received frames satisfy pred (not drained)
;;;
;;; The peer keeps leftover bytes across reads: two frames coalesced in one
;;; tcp-data are both parsed.
;;;
;;; A QUERY THAT GETS NO ANSWER IS A FIXTURE FAILURE, NOT AN EMPTY RESULT. An
;;; earlier version answered a query timeout with '() / #f, so a fixture that
;;; had died made every "the peer never received X" assertion pass. Each query
;;; carries a fresh tag and only its own answer is accepted, so a late answer
;;; to an earlier query cannot be mistaken for this one's.
(library (test plain-peer)
  (export plain-peer-open plain-peer-frames plain-peer-wait-frame plain-peer-send!
          plain-peer-auto-reply! plain-peer-close! plain-peer-alive? plain-peer-pid plain-peer-closed?
          plain-peer-count)
  (import (chezscheme) (igropyr actor)
          (only (igropyr tcp) tcp-connect! tcp-read-start! tcp-write! tcp-close!)
          (only (igropyr libuv) now-ms)
          (test mesh-proof))

  (define-record-type peer (fields pid))
  (define (plain-peer-pid p) (peer-pid p))

  (define (frame-bytes datum)
    (let ((o (open-output-string)))
      (write datum o)
      (let ((body (get-output-string o)))
        (string->utf8 (string-append (number->string (string-length body)) "\n" body)))))

  ;; parse as many complete frames as `acc` holds -> (values frames leftover)
  (define (parse-frames acc)
    (let loop ((acc acc) (out '()))
      (let* ((n (string-length acc))
             (nl (let scan ((k 0)) (cond ((= k n) #f) ((char=? (string-ref acc k) #\newline) k) (else (scan (+ k 1))))))
             (len (and nl (string->number (substring acc 0 nl)))))
        (if (and len (>= n (+ nl 1 len)))
            (loop (substring acc (+ nl 1 len) n)
                  (cons (read (open-input-string (substring acc (+ nl 1) (+ nl 1 len)))) out))
            (values (reverse out) acc)))))

  (define (plain-peer-open host port name boot-id gen secret ms)
    (let ((main self))
      (let ((p (spawn (lambda () (peer-body main host port name boot-id gen secret)))))
        (receive (after ms (cons 'failed 'timeout))
          (`#(plain-peer-up ,@p) (make-peer p))
          (`#(plain-peer-failed ,@p ,why) (cons 'failed why))))))

  (define (peer-body main host port name boot-id gen secret)
    (define (fail why) (send main (vector 'plain-peer-failed self why)))
    (tcp-connect! host port self)
    (receive (after 5000 (fail 'connect-timeout))
      (`#(tcp-connect-failed ,e) (fail (list 'connect e)))
      (`#(tcp-connected ,c)
        (tcp-read-start! c)
        ;; handshake: read the challenge, answer hello, expect welcome
        (let hs ((acc "") (stage 'challenge))
          (let-values (((frames rest) (parse-frames acc)))
            (cond
              ((and (eq? stage 'challenge) (pair? frames)
                    (let ((d (car frames)))
                      (and (pair? d) (eq? (car d) 'challenge)
                           (let ((nonce-a (cadr d)) (version (caddr d)) (bootid-a (cadddr d)))
                             (tcp-write! c (frame-bytes (list 'hello name
                                                              (v5-proof-d secret nonce-a name boot-id gen "a" bootid-a #f)
                                                              "feedfeedfeedfeedfeedfeedfeedfeed" version boot-id gen)) #f)
                             #t))))
               ;; any frames after the challenge in the same read are kept
               (hs (if (null? (cdr frames)) rest (string-append (frames->string (cdr frames)) rest)) 'welcome))
              ((and (eq? stage 'welcome) (pair? frames)
                    (let ((w (car frames))) (and (pair? w) (eq? (car w) 'welcome))))
               (send main (vector 'plain-peer-up self))
               (serve c (cdr frames) rest))
              (else
               (receive (after 5000 (fail (list 'handshake-timeout stage)))
                 (`#(tcp-data ,bv) (hs (string-append acc (utf8->string bv)) stage))
                 (`#(tcp-eof) (fail (list 'closed-during-handshake stage)))
                 (`#(tcp-error ,e) (fail (list 'error-during-handshake e)))))))))))

  ;; re-encode already-parsed frames so they can be re-read with the leftover
  (define (frames->string frames)
    (apply string-append (map (lambda (d) (utf8->string (frame-bytes d))) frames)))

  ;; the served state: received frames (newest first), leftover bytes, auto-reply thunk
  (define (serve c pending0 acc0)
    (let loop ((got (reverse pending0)) (acc acc0) (auto #f) (closed? #f))
      (define (handle! frames)
        ;; auto-reply to calls when armed
        (when auto
          (for-each (lambda (d)
                      (when (and (pair? d) (eq? (car d) 'call) (= (length d) 5))
                        (let ((ref (caddr d)) (msg (cadddr d)))
                          (tcp-write! c (frame-bytes (list 'reply ref (list 'ok (auto msg)))) #f))))
                    frames)))
      (receive
        (`#(tcp-data ,bv)
          (let-values (((frames rest) (parse-frames (string-append acc (utf8->string bv)))))
            (handle! frames)
            (loop (append (reverse frames) got) rest auto closed?)))
        (`#(tcp-eof) (loop got acc auto #t))
        (`#(tcp-error ,e) (loop got acc auto #t))
        (`#(frames ,who ,tag) (send who (vector 'answer tag (reverse got))) (loop '() acc auto closed?))
        (`#(peek ,who ,tag) (send who (vector 'answer tag (reverse got))) (loop got acc auto closed?))
        (`#(closed? ,who ,tag) (send who (vector 'answer tag closed?)) (loop got acc auto closed?))
        (`#(send-frame ,datum) (unless closed? (tcp-write! c (frame-bytes datum) #f)) (loop got acc auto closed?))
        (`#(auto-reply ,thunk) (loop got acc thunk closed?))
        (`#(close) (tcp-close! c)))))

  ;; one query at a time per asking process; the tag pins the answer to it
  (define query-seq 0)
  (define (query! p op)
    (set! query-seq (+ query-seq 1))
    (let ((tag query-seq))
      (send (peer-pid p) (vector op self tag))
      (receive (after 2000 (error 'plain-peer "fixture unresponsive" op (process-id (peer-pid p))))
        (`#(answer ,@tag ,v) v))))
  (define (plain-peer-frames p) (query! p 'frames))
  (define (plain-peer-wait-frame p pred ms)
    (let ((deadline (+ (now-ms) ms)))
      (let loop ()
        (let ((fs (query! p 'peek)))
          (cond ((find pred fs) => (lambda (f) f))
                ((> (now-ms) deadline) #f)
                (else (sleep-ms 30) (loop)))))))
  (define (plain-peer-count p pred) (length (filter pred (query! p 'peek))))
  (define (plain-peer-send! p datum) (send (peer-pid p) (vector 'send-frame datum)))
  (define (plain-peer-auto-reply! p thunk) (send (peer-pid p) (vector 'auto-reply thunk)))
  (define (plain-peer-close! p) (send (peer-pid p) (vector 'close)))
  (define (plain-peer-alive? p) (process-alive? (peer-pid p)))
  (define (plain-peer-closed? p) (query! p 'closed?))
)
