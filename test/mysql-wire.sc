#!chezscheme
;;; (igropyr mysql) wire-level tests against an in-process fake server.
;;;
;;; MySQL had NO fake-wire suite at all: test/mysql.sc needs a live server
;;; and self-skips everywhere, so every line of framing and reassembly in
;;; the driver was exercised only on a machine someone had set up by hand.
;;; A loopback listener speaking just enough of the protocol makes those
;;; paths run everywhere, which is the point of this file.
;;;
;;; Covered:
;;;   * a full mysql_native_password handshake and a result set, so the
;;;     framing under test is the real client path and not a stub;
;;;   * REASSEMBLY across fragment boundaries, which is what the buffer
;;;     migration changed and what nothing else here exercises;
;;;   * a packet whose length the 24-bit field cannot express must be
;;;     refused rather than truncated. Writing the low 24 bits and sending
;;;     the whole payload desynchronises the connection, which is worse
;;;     than failing: the server reads a wrong length and every byte after
;;;     it becomes the next packet.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr mysql))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

(define port 18789)

(define (bv-append . bvs)
  (let* ((n (apply + (map bytevector-length bvs)))
         (r (make-bytevector n)))
    (let loop ((bvs bvs) (pos 0))
      (if (null? bvs)
          r
          (begin (bytevector-copy! (car bvs) 0 r pos (bytevector-length (car bvs)))
                 (loop (cdr bvs) (+ pos (bytevector-length (car bvs)))))))))

(define (u8* . xs) (u8-list->bytevector xs))
(define (zeros n) (make-bytevector n 0))

;; one MySQL packet: 3-byte little-endian length, sequence byte, payload
(define (packet payload seq)
  (let ((n (bytevector-length payload)))
    (bv-append (u8* (fxand n #xFF) (fxand (fxsrl n 8) #xFF)
                    (fxand (fxsrl n 16) #xFF) (fxand seq #xFF))
               payload)))

;; length-encoded string, short form only (< 251 bytes) -- enough here
(define (lenenc s)
  (let ((bv (string->utf8 s)))
    (bv-append (u8* (bytevector-length bv)) bv)))

;; HandshakeV10 announcing mysql_native_password, with a 20-byte nonce
;; split 8 + 12 + NUL exactly as the protocol lays it out.
(define nonce-a (u8* 1 2 3 4 5 6 7 8))
(define nonce-b (u8* 9 10 11 12 13 14 15 16 17 18 19 20))
(define greeting
  (bv-append
    (u8* 10)                          ; protocol version
    (string->utf8 "8.0.0-fake") (u8* 0)
    (u8* 1 0 0 0)                     ; thread id
    nonce-a
    (u8* 0)                           ; filler
    (u8* #xFF #xF7)                   ; capability flags, lower 16
    (u8* 33)                          ; charset
    (u8* 2 0)                         ; status flags
    (u8* #x0F #x80)                   ; capability flags, upper 16
    (u8* 21)                          ; auth-plugin-data length (8 + 12 + 1)
    (zeros 10)                        ; reserved
    nonce-b (u8* 0)
    (string->utf8 "mysql_native_password") (u8* 0)))

(define ok-packet (bv-append (u8* 0 0 0) (u8* 2 0) (u8* 0 0)))
(define eof-packet (bv-append (u8* #xFE 0 0) (u8* 2 0)))

;; ColumnDefinition41: catalog, schema, table, org_table, name, ...
(define (column-def name)
  (bv-append (lenenc "def") (lenenc "") (lenenc "") (lenenc "")
             (lenenc name) (lenenc name)
             (u8* #x0C) (u8* 33 0) (u8* 0 0 0 0) (u8* #xFD) (u8* 0 0) (u8* 0) (u8* 0 0)))

;; How the server should answer COM_QUERY, chosen per connection.
(define mode (box 'small))
;; How large one row value is, and in what size pieces the reply is written.
(define big-value-bytes (box 0))
(define fragment-bytes (box 0))
(define fragment-gap-ms (box 0))

(define (start-server!)
  (tcp-listen! "127.0.0.1" port 16
    (lambda (c)
      (let ((pid
              (spawn
                (lambda ()
                  (tcp-write! c (packet greeting 0) #f)
                  ;; the client's handshake response; contents unchecked --
                  ;; test/mysql.sc covers real authentication against a real
                  ;; server, this file is about framing
                  (receive (after 5000 (tcp-close! c))
                    (`#(tcp-data ,_)
                      (tcp-write! c (packet ok-packet 2) #f)
                      (let serve ()
                        (receive (after 20000 (tcp-close! c))
                          (`#(tcp-data ,_)
                            (let* ((value (make-string (unbox big-value-bytes) #\x))
                                   (reply
                                     (bv-append
                                       (packet (u8* 1) 1)               ; one column
                                       (packet (column-def "v") 2)
                                       (packet eof-packet 3)
                                       ;; a lenenc string >= 2^16 uses the
                                       ;; 0xFD + 3-byte-length form
                                       (packet (bv-append
                                                 (u8* #xFD)
                                                 (u8* (fxand (unbox big-value-bytes) #xFF)
                                                      (fxand (fxsrl (unbox big-value-bytes) 8) #xFF)
                                                      (fxand (fxsrl (unbox big-value-bytes) 16) #xFF))
                                                 (string->utf8 value))
                                               4)
                                       (packet eof-packet 5))))
                              ;; write it in fragments of the configured size,
                              ;; which is what makes reassembly cost visible
                              ;; A yield between fragments is what makes the
                              ;; fragment count REAL. Written back to back
                              ;; they coalesce in the socket buffer and
                              ;; arrive as a handful of large reads, which is
                              ;; why a first version of this test measured
                              ;; almost no difference between a linear and a
                              ;; quadratic reassembly.
                              (let ((step (unbox fragment-bytes))
                                    (gap (unbox fragment-gap-ms))
                                    (n (bytevector-length reply)))
                                (let write-frag ((i 0))
                                  (when (< i n)
                                    (let ((end (min n (+ i step))))
                                      (tcp-write! c (let ((piece (make-bytevector (- end i))))
                                                      (bytevector-copy! reply i piece 0 (- end i))
                                                      piece)
                                                  #f)
                                      (when (> gap 0) (sleep-ms gap))
                                      (write-frag end)))))
                              (serve)))
                          (`#(tcp-eof) (tcp-close! c))
                          (`#(tcp-error ,_) (tcp-close! c)))))
                    (`#(tcp-eof) (tcp-close! c))
                    (`#(tcp-error ,_) (tcp-close! c)))))))
        (conn-set-owner! c pid)
        (tcp-read-start! c)))
    0))

(start-scheduler
  (lambda ()
    (start-server!)
    (sleep-ms 200)

    ;; ---- the handshake and a small result --------------------------------
    (set-box! big-value-bytes 8)
    (set-box! fragment-bytes 65536)
    (set-box! fragment-gap-ms 0)
    (let ((conn (mysql-connect "127.0.0.1" port "user" "pw" "db")))
      (let ((r (mysql-query conn "SELECT v")))
        (check "handshake completes and a result set parses"
          (and (vector? r) (eq? (vector-ref r 0) 'rows)))
        (check "the row value survives"
          (equal? '(("xxxxxxxx")) (vector-ref r 2))))
      (mysql-close! conn))

    ;; ---- reassembly across fragment boundaries ---------------------------
    ;; 8 MiB arriving in 256 separate reads. This is the case the buffer
    ;; migration is about: the old bytevector-in-a-box copied the whole
    ;; accumulation on every fragment, an inbuf appends in amortized O(1).
    ;;
    ;; There is NO timing assertion here, deliberately. Measured both ways
    ;; at this size: 357 ms linear against 411 ms quadratic -- 256 copies of
    ;; a growing 8 MiB buffer is about a gigabyte of memcpy, and memcpy is
    ;; fast. The quadratic term only becomes visible at thousands of
    ;; fragments, and a peer that dribbles that finely is bounded by its own
    ;; round-trips long before the copying matters. Asserting on a 54 ms gap
    ;; would be asserting on noise, and a threshold loose enough to be
    ;; stable would pass against the old code -- which is not a test.
    ;;
    ;; The migration stands on being the same shape as the PostgreSQL
    ;; driver's buffer and on removing a quadratic term, not on a
    ;; measurement it does not support. What IS asserted is that the packet
    ;; reassembles correctly across 256 boundaries, which is the part the
    ;; change could have broken and which no other test covers.
    (set-box! big-value-bytes (* 8 1024 1024))
    (set-box! fragment-bytes (* 32 1024))
    (set-box! fragment-gap-ms 1)
    (let ((conn (mysql-connect "127.0.0.1" port "user" "pw" "db")))
      (let* ((t0 (now-ms))
             (r (mysql-query conn "SELECT v"))
             (ms (- (now-ms) t0)))
        (check "a fragmented multi-megabyte reply parses"
          (and (vector? r) (eq? (vector-ref r 0) 'rows)
               (= (* 8 1024 1024)
                  (string-length (car (car (vector-ref r 2)))))))
        (display "  [info] 8 MiB in 256 fragments: ") (display ms)
        (display " ms (quadratic reassembly measured 411 ms; see above)\n"))
      (mysql-close! conn))

    ;; ---- a packet the length field cannot describe ------------------------
    ;; 16 MiB and above needs the protocol's continuation split, which this
    ;; client does not implement. What it must not do is write the low 24
    ;; bits and send the whole payload: the server then reads a wrong length
    ;; and every byte after it becomes the next packet, so the connection is
    ;; desynchronised rather than failed.
    (set-box! big-value-bytes 8)
    (set-box! fragment-bytes 65536)
    (set-box! fragment-gap-ms 0)
    (let ((conn (mysql-connect "127.0.0.1" port "user" "pw" "db")))
      (check "an oversized query is refused, not truncated"
        (guard (e (#t #t))
          (mysql-query conn (make-string (* 17 1024 1024) #\a))
          #f))
      (mysql-close! conn))

    (sleep-ms 200)
    (if (zero? failures)
        (begin (display "mysql-wire: all tests passed\n") (exit 0))
        (begin (display failures) (display " failures\n") (exit 1)))))
