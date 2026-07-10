;;; (igropyr libuv) -- minimal libuv FFI layer for Igropyr.
;;;
;;; This library talks to libuv directly through Chez's FFI: no C shim.
;;; It knows nothing about green processes; message delivery to the
;;; upper layer goes through a hook installed with uv-set-deliver!.
;;;
;;; INVARIANT: code running inside a libuv callback (anything reached
;;; from uv-poll!) must never yield, never block in receive, and never
;;; raise. Callbacks only copy data, mutate registries, and deliver
;;; messages. Yielding would unwind a continuation through a C stack
;;; frame and corrupt the process.

(library (igropyr libuv)
  (export uv-init! uv-poll! now-ms uv-set-deliver!
          tcp-listen! tcp-stop-listen! tcp-connect! dns-resolve!
          file-read-async!
          tcp-read-start! tcp-write! tcp-writev! tcp-close!
          conn? conn-handle conn-owner conn-set-owner!
          conn-state conn-count uv-strerror)
  (import (chezscheme) (igropyr platform))

  ;; Shared objects must be loaded before the foreign-procedure
  ;; definitions below are evaluated (library body runs in order).
  (define shared-objects
    (begin
      (ensure-supported-platform!)
      (load-first-shared-object! 'libuv
        (if (eq? platform-os 'macos)
            '("/opt/homebrew/lib/libuv.1.dylib" "libuv.1.dylib" "libuv.dylib")
            '("libuv.so.1" "libuv.so")))
      (load-first-shared-object! 'libc
        (if (eq? platform-os 'macos)
            '("libSystem.B.dylib" "libSystem.dylib")
            '("libc.so.6" "libc.so")))))

  ;; libuv enum constants (from uv.h, libuv 1.50)
  (define UV-RUN-NOWAIT 2)
  (define UV-RUN-ONCE 1)
  (define UV-TCP 12)
  (define UV-TIMER 13)
  (define UV-WRITE 3)
  (define UV-EOF -4095)

  ;; foreign procedures
  (define uv-loop-size   (foreign-procedure "uv_loop_size" () size_t))
  (define uv-loop-init   (foreign-procedure "uv_loop_init" (void*) int))
  (define uv-run         (foreign-procedure "uv_run" (void* int) int))
  (define uv-hrtime      (foreign-procedure "uv_hrtime" () unsigned-64))
  (define uv-handle-size (foreign-procedure "uv_handle_size" (int) size_t))
  (define uv-req-size    (foreign-procedure "uv_req_size" (int) size_t))
  (define uv-ip4-addr    (foreign-procedure "uv_ip4_addr" (string int void*) int))
  (define uv-tcp-init    (foreign-procedure "uv_tcp_init" (void* void*) int))
  (define uv-tcp-connect (foreign-procedure "uv_tcp_connect" (void* void* void* void*) int))
  (define uv-getaddrinfo (foreign-procedure "uv_getaddrinfo" (void* void* void* string void* void*) int))
  (define uv-freeaddrinfo (foreign-procedure "uv_freeaddrinfo" (void*) void))
  (define uv-fs-open  (foreign-procedure "uv_fs_open" (void* void* string int int void*) int))
  (define uv-fs-read  (foreign-procedure "uv_fs_read" (void* void* int void* unsigned-int long void*) int))
  (define uv-fs-close (foreign-procedure "uv_fs_close" (void* void* int void*) int))
  (define uv-fs-fstat (foreign-procedure "uv_fs_fstat" (void* void* int void*) int))
  (define uv-fs-get-result (foreign-procedure "uv_fs_get_result" (void*) ssize_t))
  (define uv-fs-get-statbuf (foreign-procedure "uv_fs_get_statbuf" (void*) void*))
  (define uv-fs-req-cleanup (foreign-procedure "uv_fs_req_cleanup" (void*) void))
  (define uv-tcp-bind    (foreign-procedure "uv_tcp_bind" (void* void* unsigned-int) int))
  (define uv-tcp-nodelay (foreign-procedure "uv_tcp_nodelay" (void* int) int))
  (define uv-listen      (foreign-procedure "uv_listen" (void* int void*) int))
  (define uv-accept      (foreign-procedure "uv_accept" (void* void*) int))
  (define uv-read-start  (foreign-procedure "uv_read_start" (void* void* void*) int))
  (define uv-read-stop   (foreign-procedure "uv_read_stop" (void*) int))
  (define uv-write       (foreign-procedure "uv_write" (void* void* void* unsigned-int void*) int))
  (define uv-try-write   (foreign-procedure "uv_try_write" (void* void* unsigned-int) int))
  (define uv-close       (foreign-procedure "uv_close" (void* void*) void))
  (define uv-is-closing  (foreign-procedure "uv_is_closing" (void*) int))
  (define uv-strerror    (foreign-procedure "uv_strerror" (int) string))
  (define uv-timer-init  (foreign-procedure "uv_timer_init" (void* void*) int))
  (define uv-timer-start (foreign-procedure "uv_timer_start" (void* void* unsigned-64 unsigned-64) int))
  (define uv-timer-stop  (foreign-procedure "uv_timer_stop" (void*) int))
  (define memcpy-from-c  (foreign-procedure "memcpy" (u8* void* size_t) void*))
  (define memcpy-to-c    (foreign-procedure "memcpy" (void* u8* size_t) void*))
  (define memcpy-cc      (foreign-procedure "memcpy" (void* void* size_t) void*))

  (define UV-CONNECT 2)
  (define UV-GETADDRINFO 8)
  (define UV-FS 6)
  (define O-RDONLY 0)
  (define UV-EINVAL -22)
  (define S-IFMT #o170000)
  (define S-IFREG #o100000)
  (define tcp-handle-size (uv-handle-size UV-TCP))
  (define timer-handle-size (uv-handle-size UV-TIMER))
  (define write-req-size (uv-req-size UV-WRITE))
  (define connect-req-size (uv-req-size UV-CONNECT))
  (define getaddrinfo-req-size (uv-req-size UV-GETADDRINFO))
  (define fs-req-size (uv-req-size UV-FS))
  (define buf-t-size 16)             ; uv_buf_t on arm64: {void* base; size_t len}

  ;; monotonic milliseconds
  (define (now-ms) (div (uv-hrtime) 1000000))

  (define (check who r)
    (if (< r 0)
        (error who (uv-strerror r))
        r))

  ;; connection record; one per accepted TCP client
  (define-record-type (conn make-conn conn?)
    (fields
      (immutable handle conn-handle)             ; foreign address of uv_tcp_t
      (mutable owner conn-owner conn-set-owner!) ; pid of the reader process
      (mutable state conn-state conn-set-state!))) ; open | closing | closed

  ;; GC roots (the "keep-live" story):
  ;; - conn-table roots every live connection's Scheme state while libuv
  ;;   holds the raw handle pointer; doubles as fd-leak accounting.
  ;; - write-table roots write-completion closures until the write_cb runs.
  ;; - locked-callbacks below roots the foreign-callable code objects; if
  ;;   the accept callback were collected, the next connection would jump
  ;;   into freed memory -- the classic crash under high concurrency.
  (define conn-table (make-eqv-hashtable))
  (define write-table (make-eqv-hashtable))
  ;; pending outbound connects: req address -> (handle . owner-pid)
  (define connect-table (make-eqv-hashtable))
  ;; pending DNS lookups: getaddrinfo req address -> owner-pid
  (define getaddrinfo-table (make-eqv-hashtable))
  ;; pending async file reads: fs req address -> fs-op record
  (define fs-table (make-eqv-hashtable))
  (define (conn-count) (hashtable-size conn-table))

  ;; delivery hook: (deliver owner-pid msg); installed by (igropyr actor)
  (define deliver (lambda (owner msg) (void)))
  (define (uv-set-deliver! proc) (set! deliver proc))

  ;; live listeners: handle address -> accept hook, one entry per
  ;; tcp-listen!. Keyed dispatch (not a single global) so several
  ;; servers can listen on different ports in one process; the table
  ;; also roots the listener handles for the GC.
  (define listener-table (make-eqv-hashtable))

  ;; global libuv state, allocated in uv-init!
  (define uv-loop 0)
  (define wakeup-timer 0)
  (define sockaddr-buf 0)
  (define read-buf 0)
  (define read-buf-size 65536)
  ;; reusable scratch for the uv_try_write fast path (single OS thread,
  ;; used only for the duration of a synchronous try_write)
  (define write-scratch 0)
  (define write-scratch-size 65536)
  (define scratch-buf 0)             ; one reusable uv_buf_t

  ;; ---- callbacks ----------------------------------------------------

  ;; alloc_cb: hand libuv one shared static buffer. Safe because libuv
  ;; is single-threaded and calls alloc_cb immediately before each
  ;; read_cb; the data is copied out before the next read.
  (define on-alloc-code
    (foreign-callable
      (lambda (handle suggested buf)
        (foreign-set! 'void* buf 0 read-buf)
        (foreign-set! 'unsigned-64 buf 8 read-buf-size))
      (void* size_t void*)
      void))

  ;; read_cb: copy bytes into a fresh bytevector and deliver to the
  ;; connection's owner process. Errors/EOF are delivered as messages,
  ;; never raised.
  (define on-read-code
    (foreign-callable
      (lambda (stream nread buf)
        (let ((c (hashtable-ref conn-table stream #f)))
          (when (and c (conn-owner c))
            (cond
              ((> nread 0)
               (let ((bv (make-bytevector nread)))
                 (memcpy-from-c bv (foreign-ref 'void* buf 0) nread)
                 (deliver (conn-owner c) (vector 'tcp-data bv))))
              ((= nread 0) (void))   ; spurious wakeup; ignore
              ((= nread UV-EOF)
               (deliver (conn-owner c) (vector 'tcp-eof)))
              (else
               (deliver (conn-owner c) (vector 'tcp-error nread)))))))
      (void* ssize_t void*)
      void))

  ;; close_cb: the single place where handle memory is freed.
  (define on-close-code
    (foreign-callable
      (lambda (handle)
        (let ((c (hashtable-ref conn-table handle #f)))
          (hashtable-delete! conn-table handle)
          (when c (conn-set-state! c 'closed)))
        (foreign-free handle))
      (void*)
      void))

  ;; write_cb: run the stored completion closure, free the whole
  ;; [uv_write_t][uv_buf_t][payload] block in one shot.
  (define on-write-code
    (foreign-callable
      (lambda (req status)
        (let ((done (hashtable-ref write-table req #f)))
          (hashtable-delete! write-table req)
          (foreign-free req)
          (when done (done status))))
      (void* int)
      void))

  ;; connection_cb: accept, register, hand the conn to the upper layer.
  ;; Accept errors are swallowed; the listener must stay alive.
  (define on-connection-code
    (foreign-callable
      (lambda (server status)
        (when (>= status 0)
          (let ((client (foreign-alloc tcp-handle-size)))
            (uv-tcp-init uv-loop client)
            (if (< (uv-accept server client) 0)
                (uv-close client on-close-entry)
                (let ((c (make-conn client #f 'open))
                      (p (hashtable-ref listener-table server #f)))
                  (uv-tcp-nodelay client 1)
                  (hashtable-set! conn-table client c)
                  (if p
                      (p c)
                      ;; listener already stopped: refuse the straggler
                      (tcp-close! c)))))))
      (void* int)
      void))

  ;; walk the addrinfo linked list, return the first IPv4 as "a.b.c.d".
  ;; Supported LP64 addrinfo layouts share ai_family @ 4 and ai_next @ 40;
  ;; ai_addr is selected by (igropyr platform). sockaddr_in.sin_addr @ 4.
  (define AF-INET 2)
  (define (addrinfo->ipv4 ai)
    (let loop ((ai ai))
      (if (= ai 0)
          #f
          (if (= (foreign-ref 'int ai 4) AF-INET)
              (let ((sa (foreign-ref 'void* ai addrinfo-address-offset)))
                (string-append
                  (number->string (foreign-ref 'unsigned-8 sa 4)) "."
                  (number->string (foreign-ref 'unsigned-8 sa 5)) "."
                  (number->string (foreign-ref 'unsigned-8 sa 6)) "."
                  (number->string (foreign-ref 'unsigned-8 sa 7))))
              (loop (foreign-ref 'void* ai addrinfo-next-offset))))))

  ;; Async whole-file read as an open -> fstat -> bounded read -> close
  ;; chain, all on libuv's thread pool.
  (define file-read-chunk-size 65536)

  (define-record-type (fs-op make-fs-op fs-op?)
    (fields
      (immutable owner fs-op-owner)
      (immutable path fs-op-path)
      (mutable phase fs-op-phase fs-op-phase-set!)   ; open|fstat|read|close
      (mutable fd fs-op-fd fs-op-fd-set!)
      (mutable size fs-op-size fs-op-size-set!)
      (mutable offset fs-op-offset fs-op-offset-set!)
      (mutable chunks fs-op-chunks fs-op-chunks-set!)
      (mutable data fs-op-data fs-op-data-set!)       ; C read buffer
      (mutable buf fs-op-buf fs-op-buf-set!)))         ; uv_buf_t

  (define (fs-body op)
    (let ((out (make-bytevector (fs-op-offset op))))
      (let loop ((xs (reverse (fs-op-chunks op))) (off 0))
        (unless (null? xs)
          (let ((bv (car xs)))
            (bytevector-copy! bv 0 out off (bytevector-length bv))
            (loop (cdr xs) (+ off (bytevector-length bv))))))
      out))

  (define (fs-cleanup! op req)
    (when (> (fs-op-data op) 0) (foreign-free (fs-op-data op)))
    (when (> (fs-op-buf op) 0) (foreign-free (fs-op-buf op)))
    (hashtable-delete! fs-table req)
    (foreign-free req))

  (define (fs-fail! op req errno)
    ;; if a fd is open, close it (fire-and-forget) before reporting
    (when (>= (fs-op-fd op) 0)
      (let ((creq (foreign-alloc fs-req-size)))
        (uv-fs-close uv-loop creq (fs-op-fd op) 0)   ; sync close, ignore
        (uv-fs-req-cleanup creq)
        (foreign-free creq)))
    (deliver (fs-op-owner op) (vector 'file-error errno))
    (fs-cleanup! op req))

  (define (regular-file-mode? mode)
    (= (bitwise-and mode S-IFMT) S-IFREG))

  ;; Deliver the accumulated data and release the op. Reached only after
  ;; every read completed, so a close error (rare; e.g. NFS) must not
  ;; discard the data -- success is reported regardless of how close went.
  (define (fs-finish! op req)
    (deliver (fs-op-owner op) (vector 'file-read (fs-body op)))
    (fs-cleanup! op req))

  (define (start-fs-close! op req)
    (fs-op-phase-set! op 'close)
    (let ((r (uv-fs-close uv-loop req (fs-op-fd op) on-fs-entry)))
      (when (< r 0)
        ;; could not queue the close: close synchronously instead, and
        ;; still deliver -- the data was fully read before this point
        (uv-fs-req-cleanup req)
        (let ((creq (foreign-alloc fs-req-size)))
          (uv-fs-close uv-loop creq (fs-op-fd op) 0)   ; sync close, ignore
          (uv-fs-req-cleanup creq)
          (foreign-free creq))
        (fs-finish! op req))))

  (define (start-fs-fstat! op req)
    (fs-op-phase-set! op 'fstat)
    (let ((r (uv-fs-fstat uv-loop req (fs-op-fd op) on-fs-entry)))
      (when (< r 0)
        (uv-fs-req-cleanup req)
        (fs-fail! op req r))))

  (define (start-fs-read! op req)
    (let ((remaining (- (fs-op-size op) (fs-op-offset op))))
      (if (<= remaining 0)
          (start-fs-close! op req)
          (let ((n (min file-read-chunk-size remaining)))
            (fs-op-phase-set! op 'read)
            (foreign-set! 'unsigned-64 (fs-op-buf op) 8 n)
            (let ((r (uv-fs-read uv-loop req (fs-op-fd op) (fs-op-buf op) 1
                                 (fs-op-offset op) on-fs-entry)))
              (when (< r 0)
                (uv-fs-req-cleanup req)
                (fs-fail! op req r)))))))

  (define on-fs-code
    (foreign-callable
      (lambda (req)
        (let ((op (hashtable-ref fs-table req #f))
              (result (uv-fs-get-result req)))
          (when op
            (case (fs-op-phase op)
              ((open)
               (uv-fs-req-cleanup req)
               (if (< result 0)
                   (fs-fail! op req result)
                   (begin
                     (fs-op-fd-set! op result)
                     (start-fs-fstat! op req))))
              ((fstat)
               (if (< result 0)
                   (begin
                     (uv-fs-req-cleanup req)
                     (fs-fail! op req result))
                   (let* ((st (uv-fs-get-statbuf req))
                          (mode (foreign-ref 'unsigned-64 st uv-stat-mode-offset))
                          (size (foreign-ref 'unsigned-64 st uv-stat-size-offset)))
                     (uv-fs-req-cleanup req)
                     (fs-op-size-set! op size)
                     (if (not (regular-file-mode? mode))
                         (fs-fail! op req UV-EINVAL)
                         (if (= size 0)
                             (start-fs-close! op req)
                             (let* ((data (foreign-alloc file-read-chunk-size))
                                    (buf (foreign-alloc 16)))
                               (fs-op-data-set! op data)
                               (fs-op-buf-set! op buf)
                               (foreign-set! 'void* buf 0 data)
                               (start-fs-read! op req)))))))
              ((read)
               (uv-fs-req-cleanup req)
               (cond
                 ((< result 0) (fs-fail! op req result))
                 ((= result 0) (start-fs-close! op req))
                 (else
                  (let* ((remaining (- (fs-op-size op) (fs-op-offset op)))
                         (n (min result remaining))
                         (bv (make-bytevector n)))
                    (memcpy-from-c bv (fs-op-data op) n)
                    (fs-op-chunks-set! op (cons bv (fs-op-chunks op)))
                    (fs-op-offset-set! op (+ (fs-op-offset op) n))
                    (if (>= (fs-op-offset op) (fs-op-size op))
                        (start-fs-close! op req)
                        (start-fs-read! op req))))))
              ((close)
               (uv-fs-req-cleanup req)
               (fs-finish! op req))))))
      (void*)
      void))

  ;; getaddrinfo_cb: tell the owner #(dns-resolved ,ip) or #(dns-failed ,e)
  (define on-getaddrinfo-code
    (foreign-callable
      (lambda (req status ai)
        (let ((owner (hashtable-ref getaddrinfo-table req #f)))
          (hashtable-delete! getaddrinfo-table req)
          (foreign-free req)
          (if (< status 0)
              (when owner (deliver owner (vector 'dns-failed status)))
              (let ((ip (addrinfo->ipv4 ai)))
                (uv-freeaddrinfo ai)
                (when owner
                  (deliver owner
                    (if ip (vector 'dns-resolved ip) (vector 'dns-failed -1))))))))
      (void* int void*)
      void))

  ;; connect_cb for outbound connections: register the conn and tell the
  ;; owner process #(tcp-connected ,conn) or #(tcp-connect-failed ,errno).
  (define on-connect-code
    (foreign-callable
      (lambda (req status)
        (let ((entry (hashtable-ref connect-table req #f)))
          (hashtable-delete! connect-table req)
          (foreign-free req)
          (when entry
            (let ((handle (car entry)) (owner (cdr entry)))
              (if (< status 0)
                  (begin
                    (uv-close handle on-close-entry)
                    (deliver owner (vector 'tcp-connect-failed status)))
                  (let ((c (make-conn handle owner 'open)))
                    (uv-tcp-nodelay handle 1)
                    (hashtable-set! conn-table handle c)
                    (deliver owner (vector 'tcp-connected c))))))))
      (void* int)
      void))

  ;; timer_cb for the poll wakeup timer: exists only to bound the
  ;; blocking uv_run(ONCE) wait; does nothing.
  (define on-timer-code
    (foreign-callable
      (lambda (handle) (void))
      (void*)
      void))

  ;; Lock the callback code objects forever: libuv holds raw entry-point
  ;; pointers into them for the whole process lifetime.
  (define locked-callbacks
    (begin
      (lock-object on-alloc-code)
      (lock-object on-read-code)
      (lock-object on-close-code)
      (lock-object on-write-code)
      (lock-object on-connection-code)
      (lock-object on-connect-code)
      (lock-object on-getaddrinfo-code)
      (lock-object on-fs-code)
      (lock-object on-timer-code)
      (vector on-alloc-code on-read-code on-close-code
              on-write-code on-connection-code on-connect-code
              on-getaddrinfo-code on-fs-code on-timer-code)))

  (define on-alloc-entry (foreign-callable-entry-point on-alloc-code))
  (define on-read-entry (foreign-callable-entry-point on-read-code))
  (define on-close-entry (foreign-callable-entry-point on-close-code))
  (define on-write-entry (foreign-callable-entry-point on-write-code))
  (define on-connection-entry (foreign-callable-entry-point on-connection-code))
  (define on-connect-entry (foreign-callable-entry-point on-connect-code))
  (define on-getaddrinfo-entry (foreign-callable-entry-point on-getaddrinfo-code))
  (define on-fs-entry (foreign-callable-entry-point on-fs-code))
  (define on-timer-entry (foreign-callable-entry-point on-timer-code))

  ;; ---- public API ----------------------------------------------------

  (define (uv-init!)
    (set! uv-loop (foreign-alloc (uv-loop-size)))
    (check 'uv-loop-init (uv-loop-init uv-loop))
    (set! wakeup-timer (foreign-alloc timer-handle-size))
    (check 'uv-timer-init (uv-timer-init uv-loop wakeup-timer))
    (set! sockaddr-buf (foreign-alloc 128))
    (set! read-buf (foreign-alloc read-buf-size))
    (set! write-scratch (foreign-alloc write-scratch-size))
    (set! scratch-buf (foreign-alloc buf-t-size)))

  ;; Pump the event loop. timeout-ms = 0: poll without blocking.
  ;; timeout-ms > 0: block in the OS poller until I/O arrives or the
  ;; wakeup timer fires -- zero busy-wait when idle.
  (define (uv-poll! timeout-ms)
    (if (<= timeout-ms 0)
        (uv-run uv-loop UV-RUN-NOWAIT)
        (begin
          (uv-timer-start wakeup-timer on-timer-entry timeout-ms 0)
          (uv-run uv-loop UV-RUN-ONCE)
          (uv-timer-stop wakeup-timer))))

  ;; optional trailing arg: uv_tcp_bind flags (UV_TCP_REUSEPORT = 2,
  ;; kernel-balanced multi-process listening; Linux/FreeBSD only)
  (define (tcp-listen! host port backlog on-accept . opts)
    (let ((flags (if (pair? opts) (car opts) 0))
          (l (foreign-alloc tcp-handle-size)))
      (check 'uv-tcp-init (uv-tcp-init uv-loop l))
      (check 'uv-ip4-addr (uv-ip4-addr host port sockaddr-buf))
      (check 'uv-tcp-bind (uv-tcp-bind l sockaddr-buf flags))
      (check 'uv-listen (uv-listen l backlog on-connection-entry))
      (hashtable-set! listener-table l on-accept)
      l))

  ;; Stop accepting new connections (graceful shutdown step 1);
  ;; established connections are unaffected. With a listener handle
  ;; (tcp-listen!'s return value) stops that server only; with no
  ;; argument stops every listener in the process.
  (define (tcp-stop-listen! . rest)
    (define (stop! l)
      (when (hashtable-ref listener-table l #f)
        (hashtable-delete! listener-table l)
        (uv-close l on-close-entry)))
    (if (pair? rest)
        (stop! (car rest))
        (vector-for-each stop! (hashtable-keys listener-table))))

  ;; Read a whole file on libuv's thread pool. The owner process later
  ;; receives #(file-read ,bytevector) or #(file-error ,errno). Never
  ;; blocks the scheduler, even for large files or slow filesystems.
  (define (file-read-async! path owner)
    (let ((req (foreign-alloc fs-req-size))
          (op (make-fs-op owner path 'open -1 0 0 '() 0 0)))
      (hashtable-set! fs-table req op)
      (let ((r (uv-fs-open uv-loop req path O-RDONLY 0 on-fs-entry)))
        (when (< r 0)
          (uv-fs-req-cleanup req)
          (fs-fail! op req r)))))

  ;; Async DNS. The owner process later receives #(dns-resolved ,ip-string)
  ;; or #(dns-failed ,errno). libuv resolves on its thread pool, so the
  ;; scheduler is not blocked.
  (define (dns-resolve! host owner)
    (let ((req (foreign-alloc getaddrinfo-req-size)))
      (hashtable-set! getaddrinfo-table req owner)
      (let ((r (uv-getaddrinfo uv-loop req on-getaddrinfo-entry host 0 0)))
        (when (< r 0)
          (hashtable-delete! getaddrinfo-table req)
          (foreign-free req)
          (deliver owner (vector 'dns-failed r))))))

  ;; Outbound TCP connection. The owner process later receives
  ;; #(tcp-connected ,conn) or #(tcp-connect-failed ,errno). Call
  ;; tcp-read-start! on the conn after the connected message arrives.
  (define (tcp-connect! host port owner)
    (check 'uv-ip4-addr (uv-ip4-addr host port sockaddr-buf))
    (let ((h (foreign-alloc tcp-handle-size))
          (req (foreign-alloc connect-req-size)))
      (check 'uv-tcp-init (uv-tcp-init uv-loop h))
      (hashtable-set! connect-table req (cons h owner))
      (let ((r (uv-tcp-connect req h sockaddr-buf on-connect-entry)))
        (when (< r 0)
          (hashtable-delete! connect-table req)
          (foreign-free req)
          (uv-close h on-close-entry)
          (error 'tcp-connect! (uv-strerror r)))
        #t)))

  ;; Start delivering #(tcp-data ...) messages to the conn's owner.
  ;; Call after conn-set-owner!.
  (define (tcp-read-start! c)
    (when (eq? (conn-state c) 'open)
      (uv-read-start (conn-handle c) on-alloc-entry on-read-entry)))

  ;; Queue `len` bytes for an async write. fill-data! copies them into
  ;; the foreign data area. Allocates one block [uv_write_t][uv_buf_t]
  ;; [payload]; write_cb frees it and runs on-done in callback context
  ;; (must not yield). Returns #t if queued, #f on immediate error.
  (define (enqueue-write! c len fill-data! on-done)
    (let* ((block (foreign-alloc (+ write-req-size buf-t-size len)))
           (buf-ptr (+ block write-req-size))
           (data-ptr (+ buf-ptr buf-t-size)))
      (fill-data! data-ptr)
      (foreign-set! 'void* buf-ptr 0 data-ptr)
      (foreign-set! 'unsigned-64 buf-ptr 8 len)
      (let ((r (uv-write block (conn-handle c) buf-ptr 1 on-write-entry)))
        (if (< r 0)
            (begin (foreign-free block) (when on-done (on-done r)) #f)
            (begin
              (hashtable-set! write-table block
                (or on-done (lambda (status) (void))))
              #t)))))

  ;; Write a sequence of bytevectors as one response. Small writes take
  ;; the uv_try_write fast path: the segments are packed into the shared
  ;; scratch buffer and written synchronously, skipping the write_req /
  ;; write_cb / hashtable / foreign-alloc of the queued path entirely --
  ;; on-done runs inline with status 0. A partial write or EAGAIN falls
  ;; back to the queued path for the unwritten remainder; writes larger
  ;; than the scratch go straight to the queued path. on-done runs in
  ;; caller context on the fast path (safe: not inside a libuv callback)
  ;; and in callback context on the queued path; either way it must not
  ;; yield. Returns #f if the connection is not open (on-done ran -1).
  (define (tcp-writev! c segs on-done)
    (if (not (eq? (conn-state c) 'open))
        (begin (when on-done (on-done -1)) #f)
        (let ((total (fold-left (lambda (a b) (+ a (bytevector-length b))) 0 segs)))
          (cond
            ((<= total write-scratch-size)
             ;; pack segments into scratch, then try to write in one shot
             (let loop ((ss segs) (off 0))
               (unless (null? ss)
                 (let ((n (bytevector-length (car ss))))
                   (memcpy-to-c (+ write-scratch off) (car ss) n)
                   (loop (cdr ss) (+ off n)))))
             (foreign-set! 'void* scratch-buf 0 write-scratch)
             (foreign-set! 'unsigned-64 scratch-buf 8 total)
             (let ((n (uv-try-write (conn-handle c) scratch-buf 1)))
               (cond
                 ((= n total)                       ; fully written now
                  (when on-done (on-done 0)) #t)
                 ((and (> n 0) (< n total))         ; partial: queue the rest
                  (enqueue-write! c (- total n)
                    (lambda (dest) (memcpy-cc dest (+ write-scratch n) (- total n)))
                    on-done))
                 (else                              ; EAGAIN/0: queue all
                  (enqueue-write! c total
                    (lambda (dest) (memcpy-cc dest write-scratch total))
                    on-done)))))
            (else                                    ; too big for scratch
             (enqueue-write! c total
               (lambda (dest)
                 (let loop ((ss segs) (off 0))
                   (unless (null? ss)
                     (let ((n (bytevector-length (car ss))))
                       (memcpy-to-c (+ dest off) (car ss) n)
                       (loop (cdr ss) (+ off n))))))
               on-done))))))

  ;; single-bytevector write (websocket / redis / mysql)
  (define (tcp-write! c bv on-done)
    (tcp-writev! c (list bv) on-done))

  ;; Idempotent close; memory is freed only in close_cb, so there is no
  ;; double-close and no fd leak.
  (define (tcp-close! c)
    (when (and (eq? (conn-state c) 'open)
               (= 0 (uv-is-closing (conn-handle c))))
      (conn-set-state! c 'closing)
      (uv-close (conn-handle c) on-close-entry)))
)
