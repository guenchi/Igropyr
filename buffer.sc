#!chezscheme
;;; (igropyr buffer) -- resumable input buffer for byte-stream parsers.
;;;
;;; Every stream reader in the tree (http, websocket, node, client,
;;; ws-client) has the same job: accumulate tcp segments, scan for a
;;; delimiter or a known length, hand a slice to the parser, drop the
;;; consumed prefix, repeat. Done naively -- re-append + re-scan from
;;; zero on every segment, re-copy the remainder on every message --
;;; that is the O(n^2) family this component replaces.
;;;
;;;   (define b (make-inbuf))
;;;   (inbuf-append! b segment)        ; amortized O(1) per byte
;;;   (inbuf-find-header-end b)        ; resumable \r\n\r\n scan
;;;   (inbuf-sub b from to)            ; fresh bytevector, RELATIVE range
;;;   (inbuf-consume! b n)             ; drop n bytes from the front: O(1)
;;;   (inbuf-length b)                 ; unconsumed byte count
;;;
;;; Representation: one bytevector window [start, end) plus a scan
;;; position. Hot parsers read the raw window directly --
;;;
;;;   (let ((bv (inbuf-bv b)) (base (inbuf-start b)))
;;;     ... (bytevector-u8-ref bv (fx+ base i)) ...)
;;;
;;; -- so per-byte access pays no cross-library call; the buffer's own
;;; operations run once per event, where their cost is irrelevant.
;;; ALL indices in the public API are RELATIVE to the current start
;;; (0 = first unconsumed byte); only the raw window is absolute.
;;; Relative positions kept by callers (e.g. a chunked parser's resume
;;; state) stay valid across appends: compaction moves data and start
;;; together, and consume! is the only thing that shifts the origin.
;;;
;;; Costs: the first segment into an empty buffer is aliased, not
;;; copied (the single-segment request costs zero, as before -- safe
;;; because stream segments are fresh and treated as immutable
;;; everywhere). Later appends grow owned storage geometrically, so a
;;; body arriving in k segments copies each byte O(1) times amortized
;;; instead of O(k). consume! just advances start; when everything is
;;; consumed the storage is dropped, so a keep-alive connection idles
;;; holding nothing.
;;;
;;; The buffer NEVER aliases its storage out: inbuf-sub copies. The
;;; only aliasing is inward (the empty-buffer append), of a segment
;;; nobody else retains. Mutating a segment after handing it to
;;; inbuf-append! is a caller bug.

(library (igropyr buffer)
  (export make-inbuf inbuf?
          inbuf-length inbuf-append! inbuf-consume! inbuf-clear!
          inbuf-bv inbuf-start inbuf-end
          inbuf-sub inbuf-find-header-end)
  (import (chezscheme) (igropyr checked))

  (define empty-bv (make-bytevector 0))

  (define min-grow 1024)

  ;; bv[start,end) is live data; scan is RELATIVE to start (bytes
  ;; already searched for \r\n\r\n); owned? tells whether bv is private
  ;; storage we may write into past end (an aliased segment is not).
  (define-record-type (inbuf %make-inbuf inbuf?)
    (fields
      (mutable bv %ibv %ibv-set!)
      (mutable start %istart %istart-set!)
      (mutable end %iend %iend-set!)
      (mutable scan %iscan %iscan-set!)
      (mutable owned %iowned? %iowned-set!)))

  (define (make-inbuf) (%make-inbuf empty-bv 0 0 0 #f))

  (define-checked (inbuf-length (b inbuf?))
    (fx- (%iend b) (%istart b)))

  ;; raw window for hot parsers: absolute indices into inbuf-bv
  (define-checked (inbuf-bv (b inbuf?)) (%ibv b))
  (define-checked (inbuf-start (b inbuf?)) (%istart b))
  (define-checked (inbuf-end (b inbuf?)) (%iend b))

  (define-checked (inbuf-append! (b inbuf?) (chunk bytevector?))
    (let ((clen (bytevector-length chunk)))
      (unless (fx= clen 0)
        (let* ((start (%istart b)) (end (%iend b)) (len (fx- end start)))
          (cond
            ;; empty: alias the segment; the common whole-request-in-one-
            ;; segment case costs nothing
            ((fx= len 0)
             (%ibv-set! b chunk)
             (%istart-set! b 0)
             (%iend-set! b clen)
             (%iscan-set! b 0)
             (%iowned-set! b #f))
            (else
             (let* ((bv (%ibv b))
                    (cap (bytevector-length bv))
                    (need (fx+ len clen)))
               (cond
                 ;; room past end in owned storage: append in place
                 ((and (%iowned? b) (fx>= (fx- cap end) clen))
                  (bytevector-copy! chunk 0 bv end clen)
                  (%iend-set! b (fx+ end clen)))
                 ;; owned storage big enough after sliding the live data
                 ;; down (bytevector-copy! handles overlap); relative
                 ;; positions survive because start moves with the data
                 ((and (%iowned? b) (fx>= cap need))
                  (bytevector-copy! bv start bv 0 len)
                  (bytevector-copy! chunk 0 bv len clen)
                  (%istart-set! b 0)
                  (%iend-set! b need))
                 ;; grow geometrically: each byte is copied O(1) times
                 ;; amortized however many segments arrive
                 (else
                  (let* ((ncap (fxmax need (fx* 2 cap) min-grow))
                         (nbv (make-bytevector ncap)))
                    (bytevector-copy! bv start nbv 0 len)
                    (bytevector-copy! chunk 0 nbv len clen)
                    (%ibv-set! b nbv)
                    (%istart-set! b 0)
                    (%iend-set! b need)
                    (%iowned-set! b #t)))))))))))

  ;; drop n bytes from the front; O(1). Fully consumed -> release the
  ;; storage (idle keep-alive connections hold nothing). The scan
  ;; position resets: what remains is the NEXT message, none of it
  ;; searched yet.
  (define-checked (inbuf-consume! (b inbuf?) (n fixnum?))
    (let ((start (fx+ (%istart b) n)))
      (if (fx>= start (%iend b))
          (inbuf-clear! b)
          (begin
            (%istart-set! b start)
            (%iscan-set! b 0)))))

  (define-checked (inbuf-clear! (b inbuf?))
    (%ibv-set! b empty-bv)
    (%istart-set! b 0)
    (%iend-set! b 0)
    (%iscan-set! b 0)
    (%iowned-set! b #f))

  ;; fresh copy of the RELATIVE range [from, to); empty range allocates
  ;; nothing (every bodyless request used to pay two empty allocations)
  (define-checked (inbuf-sub (b inbuf?) (from fixnum?) (to fixnum?))
    (if (fx>= from to)
        empty-bv
        (let* ((abs-from (fx+ (%istart b) from))
               (r (make-bytevector (fx- to from))))
          (bytevector-copy! (%ibv b) abs-from r 0 (fx- to from))
          r)))

  ;; RELATIVE index of the \r\n\r\n terminating a header block, or #f.
  ;; Resumable: bytes are scanned once however many segments the head
  ;; arrives in -- on a miss the scan position parks 3 bytes back so a
  ;; terminator straddling segments is still found.
  (define-checked (inbuf-find-header-end (b inbuf?))
    (let* ((bv (%ibv b)) (start (%istart b)) (end (%iend b))
           (limit (fx- end 3)))
      (let loop ((i (fx+ start (%iscan b))))
        (cond
          ((fx>= i limit)
           (%iscan-set! b (fxmax 0 (fx- (fx- end start) 3)))
           #f)
          ((and (fx= (bytevector-u8-ref bv i) 13)
                (fx= (bytevector-u8-ref bv (fx+ i 1)) 10)
                (fx= (bytevector-u8-ref bv (fx+ i 2)) 13)
                (fx= (bytevector-u8-ref bv (fx+ i 3)) 10))
           (fx- i start))
          (else (loop (fx+ i 1)))))))
)
