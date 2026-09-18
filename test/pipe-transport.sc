#!chezscheme
;; A unix-domain-socket transport beside the TCP one (pipe-transport-design.md).
;;   U1   listen + connect + a payload each way
;;   U2   THE TWIN: one table of read/write/close steps run against a TCP pair
;;        and a pipe pair; both must answer identically. A cell that exercised
;;        only the pipe would pass while the two transports drifted apart
;;   U3   conn-on-close! fires on a pipe conn -- the row the `tag` ruling breaks
;;        and nothing else here would catch
;;   U4   the accepted pipe conn is UNTAGGED: conn-set-owner! is accepted on it
;;        (a tagged conn raises; see proc-spawn.sc P23 for the other side)
;;   U5   a path held by a PLAIN FILE gives an error, not a crash
;;   U6   a path already bound by a live listener gives EADDRINUSE, AND THE
;;        SOCKET FILE IS STILL THERE afterwards -- the no-unlink ruling as a
;;        reading rather than as prose
;;   U7   103 characters binds, 104 is refused by the library's own check with
;;        the limit in the message. sun_path is 104 on both our platforms
;;        (macOS sys/un.h, FreeBSD SUNPATHLEN) -- smaller than Linux's 108
;;   U8   a dial to a path nothing is listening on delivers
;;        #(tcp-connect-failed status) and leaks no request: run twice, live
;;        handles back to baseline
;;   U9   a bind that fails AFTER uv_pipe_init leaves the live-handle count at
;;        its baseline once the loop has polled -- the reading that separates
;;        uv-close from foreign-free on that path
;;   U10  counters: after a pipe listener has accepted, proc-stats's child-pipe
;;        count is unchanged and socket-conn-count has gone up by one
;;   U11  conn-peer-ip on a pipe conn answers #f without calling the TCP
;;        operation
;;   U12  close the listener, unlink, listen again on the same path
;;
;; NOT covered here, deliberately, and recorded rather than left to be noticed:
;; that uv_tcp_nodelay is not called on a pipe handle. It has no observable
;; effect from Scheme; the mutation matrix carries it (leave the call
;; unconditional and U1's round trip still passes, so only the matrix can say).
(import (chezscheme) (igropyr actor) (igropyr tcp)
        (only (igropyr libuv) now-ms uv-live-handle-count))
;; uv-accept-failure-counts comes from (igropyr tcp), imported whole above
(define fails 0)
(define (check label ok . info)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! fails (+ fails 1)) (display "FAIL  ") (display label)
             (for-each (lambda (x) (display " ") (write x)) info) (newline))))
(define (handles-settled)
  ;; two equal readings in a row: a count taken while an earlier listener is
  ;; still closing is not a baseline. U8's first version read one during U6/U7's
  ;; close window and could never get back to it
  (let poll ((prev (uv-live-handle-count)) (n 0))
    (sleep-ms 50)
    (let ((now (uv-live-handle-count)))
      (cond ((= now prev) now) ((>= n 100) now) (else (poll now (+ n 1)))))))
(define (within? ms thunk)
  (let ((deadline (+ (now-ms) ms)))
    (let loop () (cond ((thunk) #t) ((> (now-ms) deadline) #f) (else (sleep-ms 20) (loop))))))
;; a short directory, because U7 measures the PATH's length and a long base
;; would make the directory the thing under test
(define dir "/tmp/ig-u")
(system (string-append "rm -rf " dir " && mkdir -p " dir))
(define (p name) (string-append dir "/" name))
(define (err-string thunk)
  (guard (e (#t (cond ((and (message-condition? e) (condition-message e)) => values)
                      (else (list 'raised e)))))
    (thunk) #f))
(define (bv s) (string->utf8 s))
;; Chez has no string-search; this cell needs one only to ask whether a
;; diagnostic mentions a term, so it is a plain scan rather than an import
(define (contains? s sub)
  (and (string? s)
       (let ((n (string-length s)) (m (string-length sub)))
         (let loop ((i 0))
           (and (<= (+ i m) n)
                (or (string=? (substring s i (+ i m)) sub) (loop (+ i 1))))))))

(start-scheduler
  (lambda ()
    ;; `self` is a variable bound to this process, not a procedure
    (define main self)
    ;; ---- U1 ------------------------------------------------------------------
    ;; AN ACCEPTED CONN HAS NO OWNER. make-conn gives owner #f (tcp.sc:1599),
    ;; so nothing is delivered until conn-set-owner! names a process. The first
    ;; version of this file started reads without it and then waited for data
    ;; that could not arrive -- and in U2 that made BOTH transports read #f,
    ;; so the two answer lists matched and the twin passed while measuring
    ;; nothing. The rows below therefore also assert that the payload arrived,
    ;; not only that the two sides agree.
    (let* ((path (p "u1"))
           (got-server '())
           (l (pipe-listen! path 16
                (lambda (c)
                  ;; `main`, not `self`: the accept callback does not run in the
                  ;; process that is waiting for the data
                  (conn-set-owner! c main)
                  (tcp-read-start! c)
                  (send main (vector 'accepted c))))))
      (check "U1: the listener exists" (and l #t))
      (pipe-connect! path self)
      (let ((client (receive (after 5000 #f) (`#(tcp-connected ,c) c))))
        (check "U1: the dial completed with #(tcp-connected conn)" (and client (conn? client)) client)
        (let ((srv (receive (after 5000 #f) (`#(accepted ,c) c))))
          (check "U1: the listener accepted" (and srv (conn? srv)) srv)
          (when (and client srv)
            (tcp-read-start! client)
            (tcp-write! client (bv "ping") #f)
            (check "U1: the server read what the client wrote"
                   (equal? (receive (after 5000 #f) (`#(tcp-data ,b) b)) (bv "ping")))
            (tcp-write! srv (bv "pong") #f)
            (check "U1: the client read what the server wrote"
                   (equal? (receive (after 5000 #f) (`#(tcp-data ,b) b)) (bv "pong")))
            ;; ---- U3 -----------------------------------------------------------
            (let ((closed #f))
              (conn-on-close! srv (lambda () (set! closed #t)))
              (tcp-close! srv)
              (check "U3: conn-on-close! fired on a pipe conn" (within? 3000 (lambda () closed))))
            ;; ---- U4 -----------------------------------------------------------
            (check "U4: the accepted pipe conn is untagged (conn-set-owner! is accepted)"
                   (guard (e (#t #f)) (conn-set-owner! client self) #t))
            ;; ---- U11 ----------------------------------------------------------
            ;; THIS ROW PINS THE ANSWER, NOT THE GUARD, and the difference is
            ;; measured: with the type discriminator in conn-peer-ip replaced by
            ;; #t, all 28 rows here stay green, this one included. The old code
            ;; already answered #f -- it called the TCP operation on a pipe
            ;; handle and the operation failed, so the >= 0 test produced #f
            ;; anyway. What the discriminator removes is a TYPE hazard, an
            ;; operation declared on uv_tcp_t* being handed a uv_pipe_t, and on
            ;; these two platforms that has no observable consequence. So the
            ;; guard has NO red cell and cannot be given one here; the criterion
            ;; for it is the declaration, not the behaviour. Do not cite this
            ;; row as coverage for the discriminator.
            (check "U11: conn-peer-ip on a pipe conn is #f (the ANSWER; see above)"
                   (eq? (conn-peer-ip client) #f) (conn-peer-ip client))
            (tcp-close! client)))
        (tcp-stop-listen! l (listener-token l))))

    ;; ---- U5 --------------------------------------------------------------------
    (let ((path (p "u5")))
      (system (string-append "printf x > " path))
      (let ((msg (err-string (lambda () (pipe-listen! path 16 (lambda (c) (void)))))))
        (check "U5: a path held by a plain file gives an error, not a crash" (string? msg) msg)))

    ;; ---- U6 --------------------------------------------------------------------
    (let* ((path (p "u6"))
           (l (pipe-listen! path 16 (lambda (c) (void)))))
      (let ((msg (err-string (lambda () (pipe-listen! path 16 (lambda (c) (void)))))))
        (check "U6: a second listener on the same path is refused" (string? msg) msg)
        (check "U6: ...and the refusal names the address being in use"
               (and (string? msg) (or (contains? msg "EADDRINUSE") (contains? msg "in use"))) msg))
      (check "U6: the socket file is still there -- the library did not unlink it"
             (file-exists? path))
      (tcp-stop-listen! l (listener-token l)))

    ;; ---- U7 --------------------------------------------------------------------
    ;; both boundary paths live in the same short directory, so the only thing
    ;; that differs between the two rows is the length of the path itself
    (let* ((base (string-append dir "/"))
           (pad (lambda (n) (string-append base (make-string (- n (string-length base)) #\a)))))
      (let* ((ok-path (pad 103))
             (l (guard (e (#t #f)) (pipe-listen! ok-path 16 (lambda (c) (void))))))
        (check "U7: a 103-character path binds" (and l #t) (string-length ok-path))
        (when l (tcp-stop-listen! l (listener-token l))))
      (let* ((long-path (pad 104))
             (msg (err-string (lambda () (pipe-listen! long-path 16 (lambda (c) (void)))))))
        (check "U7: a 104-character path is refused" (string? msg) msg)
        (check "U7: ...by this library, with the limit in the message"
               (and (string? msg) (contains? msg "104")) msg)
        (check "U7: ...and nothing was created at that path" (not (file-exists? long-path)))))

    ;; ---- U8 --------------------------------------------------------------------
    (let ((path (p "u8-nobody"))
          (base (handles-settled)))
      (pipe-connect! path self)
      (check "U8: a dial to nothing gives #(tcp-connect-failed status)"
             (receive (after 5000 #f) (`#(tcp-connect-failed ,s) #t)))
      (pipe-connect! path self)
      (check "U8: the second dial fails the same way"
             (receive (after 5000 #f) (`#(tcp-connect-failed ,s) #t)))
      (check "U8: two failed dials leak no handle"
             (within? 5000 (lambda () (= (uv-live-handle-count) base)))
             (uv-live-handle-count) base))

    ;; ---- U9 --------------------------------------------------------------------
    (let* ((path (p "u9"))
           (base (handles-settled)))
      (system (string-append "printf x > " path))
      (err-string (lambda () (pipe-listen! path 16 (lambda (c) (void)))))
      (check "U9: a bind that fails after init leaves the live-handle count at baseline"
             (within? 5000 (lambda () (= (uv-live-handle-count) base)))
             (uv-live-handle-count) base))

    ;; ---- U10 -------------------------------------------------------------------
    (let* ((path (p "u10"))
           (child-pipes (lambda () (cond ((assq 'pipes (proc-stats)) => cdr) (else 'no-key))))
           (before-pipes (child-pipes))
           (before-socks (socket-conn-count))
           (l (pipe-listen! path 16 (lambda (c) (send main (vector 'u10 c))))))
      (pipe-connect! path self)
      (let ((client (receive (after 5000 #f) (`#(tcp-connected ,c) c)))
            (srv (receive (after 5000 #f) (`#(u10 ,c) c))))
        (check "U10: both ends are up" (and client srv))
        (check "U10: the child-pipe count did not move -- these are not a child's pipes"
               (equal? (child-pipes) before-pipes) (child-pipes) before-pipes)
        (check "U10: socket-conn-count counts them"
               (= (socket-conn-count) (+ before-socks 2)) (socket-conn-count) before-socks)
        (when client (tcp-close! client))
        (when srv (tcp-close! srv)))
      (tcp-stop-listen! l (listener-token l)))

    ;; ---- U13: the accept-failure counters keep their causes apart ------------
    ;; The straggler branch -- accept ran but the listener row was already gone
    ;; -- used to pour its count into the same bucket as a real uv_accept
    ;; refusal. A count that cannot separate its two causes is, for the rarer
    ;; one, not a record at all. This row goes red the day someone merges them
    ;; back, which is the only way that decision would otherwise be noticed.
    ;; SIX now, and this row has gone red twice for the right reason. First when
    ;; `exhausted` arrived (a listener closing because it could not allocate a
    ;; client handle), then when `error` was split: it had been carrying two
    ;; opposite diagnoses -- our own code raising while handling an inbound
    ;; connection, and libuv reporting a negative status for the accept itself,
    ;; possibly before there was a connection at all. Somebody reading `error: 3`
    ;; could not tell which half to investigate. Widened each time rather than
    ;; loosened; a row that stopped checking the length would stop noticing the
    ;; next one.
    (let ((c (uv-accept-failure-counts)))
      (check "U13: the failure counts name six causes, separately"
             (and (list? c) (= (length c) 6)
                  (assq 'callback-raised c) (assq 'accept-status c) (assq 'refused c)
                  (assq 'straggler c) (assq 'exhausted c) (assq 'read-start c)) c)
      (check "U13: and nothing in this cell provoked any of them"
             (and (list? c) (for-all (lambda (kv) (eqv? (cdr kv) 0)) c)) c))

    ;; ---- U12 -------------------------------------------------------------------
    (let* ((path (p "u12"))
           (l (pipe-listen! path 16 (lambda (c) (void)))))
      (tcp-stop-listen! l (listener-token l))
      (system (string-append "rm -f " path))
      (let ((l2 (guard (e (#t #f)) (pipe-listen! path 16 (lambda (c) (void))))))
        (check "U12: after stop and unlink the same path binds again" (and l2 #t))
        (when l2 (tcp-stop-listen! l2 (listener-token l2)))))

    ;; ---- U2: THE TWIN ----------------------------------------------------------
    ;; one script, two transports. Each step answers a value; the two lists must
    ;; be equal. Written as data so that neither transport can quietly get a
    ;; different sequence
    (let ()
      (define (run-pair make-pair label)
        (let-values (((client srv stop!) (make-pair)))
          (let ((answers '()))
            (define (note! x) (set! answers (cons x answers)))
            (cond
              ((not (and client srv)) (list 'no-pair))
              (else
                ;; both ends need an owner before either can be read from
                (conn-set-owner! client self) (conn-set-owner! srv self)
                (tcp-read-start! client) (tcp-read-start! srv)
                (note! (list 'conn? (conn? client) (conn? srv)))
                (note! (list 'write-returns (and (tcp-write! client (bv "abc") #f) #t)))
                (note! (list 'server-read (receive (after 5000 #f) (`#(tcp-data ,b) b))))
                (note! (list 'write-back (and (tcp-write! srv (bv "de") #f) #t)))
                (note! (list 'client-read (receive (after 5000 #f) (`#(tcp-data ,b) b))))
                (note! (list 'owner-settable (guard (e (#t #f)) (conn-set-owner! client self) #t)))
                (note! (list 'on-close-settable (guard (e (#t #f)) (conn-on-close! client (lambda () (void))) #t)))
                (note! (list 'close-returns (begin (tcp-close! client) (tcp-close! srv) #t)))
                (stop!)
                (reverse answers))))))
      (define (tcp-pair)
        (let* ((port 18321)
               (l (tcp-listen! "127.0.0.1" port 16 (lambda (c) (send main (vector 'tw c))))))
          (tcp-connect! "127.0.0.1" port self)
          (let ((client (receive (after 5000 #f) (`#(tcp-connected ,c) c)))
                (srv (receive (after 5000 #f) (`#(tw ,c) c))))
            (values client srv (lambda () (tcp-stop-listen! l (listener-token l)))))))
      (define (pipe-pair)
        (let* ((path (p "twin"))
               (l (pipe-listen! path 16 (lambda (c) (send main (vector 'tw c))))))
          (pipe-connect! path self)
          (let ((client (receive (after 5000 #f) (`#(tcp-connected ,c) c)))
                (srv (receive (after 5000 #f) (`#(tw ,c) c))))
            (values client srv (lambda () (tcp-stop-listen! l (listener-token l)))))))
      (let ((a (run-pair tcp-pair "tcp"))
            (b (run-pair pipe-pair "pipe")))
        (check "U2: the TCP pair answered every step" (and (list? a) (> (length a) 1)) a)
        ;; ANTI-VACUITY, AND IT IS THE POINT OF THE ROW BELOW IT. Two lists of
        ;; #f are equal. The first version of this twin could not deliver to
        ;; either side, so both read #f, the lists matched, and the twin passed
        ;; having measured nothing. Equality is only evidence once each side is
        ;; known to have carried the payload
        (check "U2: the TCP side actually carried the bytes"
               (and (list? a) (member (list 'server-read (bv "abc")) a) #t) a)
        (check "U2: the pipe side actually carried the bytes"
               (and (list? b) (member (list 'server-read (bv "abc")) b) #t) b)
        (check "U2: the pipe pair answers every step exactly as the TCP pair does"
               (equal? a b) a b)))

    (if (zero? fails)
        (begin (display "ALL PIPE-TRANSPORT TESTS PASSED\n") (exit 0))
        (begin (display "PIPE-TRANSPORT VERDICT: ") (display fails) (display " failed case(s)\n") (exit 1)))))
