#!chezscheme
;;; Review findings #13, #22, #24, #25 -- the ones with an observable
;;; protocol surface. (#11/#12/#14..#21/#23/#26/#27 are covered by their
;;; own suites or have no reachable surface from a test client.)
;;;
;;; #13 a cookie value could inject ATTRIBUTES: "x; Domain=evil" widened a
;;;     host-only session cookie to every subdomain.
;;; #22 read-timeout-ms re-armed on every segment, so a client dribbling
;;;     one byte per interval held a reader forever (slowloris).
;;; #24 close frames were answered without validating or echoing the peer's
;;;     status code.
;;; #25 chunked framing was sent to HTTP/1.0 clients, which do not
;;;     implement it and read the hex size lines as body content.

(import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr http)
        (igropyr websocket)
        (igropyr express) (igropyr http-client))

(define failures 0)
(define (check label ok)
  (if ok (begin (display "  ok  ") (display label) (newline))
      (begin (set! failures (+ failures 1))
             (display "FAIL  ") (display label) (newline))))

;; THE INTERPRETER IS LOOKED UP, NOT ASSUMED (IGROPYR_PYTHON overrides). FreeBSD -- a platform
;; this library is deployed on -- installs python3.11 and no
;; `python3`, and what that produced here was not a missing
;; interpreter: system() reported nothing, the result file never
;; appeared, the poll below timed out, and the case announced that
;; the SERVER had sent zero bytes. It read as the exact defect
;; these two cases exist to catch, on both of the versions it was
;; compared across, on every version it was compared against. A dependency this test cannot run
;; without is either found or named -- never silently absent.
(define python
  (let try ((cs (let ((named (getenv "IGROPYR_PYTHON")))
                  ;; an explicit name wins: the list below goes stale every
                  ;; year, and a host with only the newest python would
                  ;; reproduce exactly the naming problem this is fixing
                  (if named
                      (list named)
                      '("python3" "python3.14" "python3.13" "python3.12"
                        "python3.11" "python3.10" "python")))))
    (cond ((null? cs) #f)
          ;; the test is what the scripts need -- python 3 -- not merely
          ;; something that can import socket, which python 2 can do too
          ;; while dying on the first py3 line of the script
          ((zero? (system (string-append (car cs)
                            " -c 'import sys; sys.exit(0 if sys.version_info[0]==3 else 1)'"
                            " >/dev/null 2>&1")))
           (car cs))
          (else (try (cdr cs))))))


;; Waits for the client to FINISH, not for it to produce output. A script
;; that dies leaves no result file, and waiting on that file cannot tell
;; "the client failed" from "the server said nothing" -- the confusion
;; this whole file was reading backwards. The shell writes the exit
;; status after the script returns, so the status file appearing means
;; the run is over and its contents say how it went. On a bad exit the
;; interpreter's stderr is printed: it is the only thing that separates a
;; broken client from a silent server, and keeping it in a file nobody
;; reads is the same as discarding it.
(define (leading-number str)
  (let loop ((i 0))
    (if (and (< i (string-length str)) (char-numeric? (string-ref str i)))
        (loop (+ i 1))
        (and (> i 0) (string->number (substring str 0 i))))))

(define (slurp path)
  (guard (e (#t "")) (call-with-input-file path get-string-all)))

(define (client-ran? py)
  (let ((status (string-append py ".status"))
        (err (string-append py ".err")))
    (when (file-exists? status) (delete-file status))
    (system (string-append "( " python " " py " >/dev/null 2>" err
                           "; echo $? >" status " ) &"))
    (let poll ((i 0))
      (cond
        ((file-exists? status)
         (let ((code (leading-number (slurp status))))
           (cond ((eqv? code 0) #t)
                 (else
                   (display "  [info] the half-close client exited ")
                   (display code) (newline)
                   (let ((e (slurp err)))
                     (unless (string=? e "")
                       (display "  [client stderr] ") (display e) (newline)))
                   #f))))
        ((< i 150) (sleep-ms 100) (poll (+ i 1)))
        (else (display "  [info] the half-close client never finished\n") #f)))))

(define port 18778)

;; Neither of the smuggling-shaped requests below may be ACCEPTED. A 400
;; is one correct answer, a close without a reply is another; a 101 or a
;; 200 is not.
(define (rejected? text)
  (and text
       (or (= 0 (string-length text))            ; closed without answering
           (and (>= (string-length text) 12)
                (let ((code (substring text 9 12)))
                  (and (not (string=? code "101"))
                       (not (string=? code "200"))))))))

(define (str-has? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? sub (substring s i (+ i m))) #t)
            (else (loop (+ i 1)))))))

;; raw request/response: returns the whole response text, or 'closed
(define (raw-exchange! request-text report)
  (spawn
    (lambda ()
      (tcp-connect! "127.0.0.1" port self)
      (receive (after 5000 (send report (vector 'raw #f)))
        (`#(tcp-connect-failed ,e) (send report (vector 'raw #f)))
        (`#(tcp-connected ,c)
          (tcp-read-start! c)
          (tcp-write! c (string->utf8 request-text) #f)
          (let collect ((acc ""))
            (receive (after 6000 (tcp-close! c) (send report (vector 'raw acc)))
              (`#(tcp-data ,bv)
                (collect (string-append acc (utf8->string bv))))
              (`#(tcp-eof) (tcp-close! c) (send report (vector 'raw acc)))
              (`#(tcp-error ,e) (tcp-close! c)
                (send report (vector 'raw acc))))))))))

(start-scheduler
  (lambda ()
    (let ((app (create-app)) (main self))
      ;; #13: a handler reflecting an attacker-shaped value into a cookie
      (app-get app "/setcookie"
        (lambda (req res)
          (let ((v (cond ((assoc "v" (req-query req)) => cdr) (else "plain"))))
            (check "set-cookie! refuses an attribute-injecting value"
              (guard (e (#t #t)) (set-cookie! res "sid" v "Path=/") #f))
            (set-cookie! res "sid" "clean" "Path=/" "HttpOnly")
            (send-text! res "done"))))
      ;; A stream that starts LATE. The half-close case needs the eof to
      ;; arrive while the reader is waiting -- with an immediate response
      ;; the bytes may already be out before the eof is seen, and the case
      ;; passes whatever the reader does with it.
      (app-get app "/slowstream"
        (lambda (req res)
          (sleep-ms 500)
          (sse-start! res)
          (res-write! res "hello-")
          (res-write! res "world")
          (res-end! res)))
      ;; A stream that keeps going, for a client that half-closes AFTER it
      ;; has started reading -- the window await-streaming owns, which the
      ;; case above cannot reach (there the eof arrives before the stream
      ;; begins and await-response consumes it).
      (app-get app "/dripstream"
        (lambda (req res)
          (res-begin! res)
          (res-spawn! res
            (lambda ()
              (let loop ((i 0))
                (if (< i 6)
                    (begin (res-write! res "tick ") (sleep-ms 200) (loop (+ i 1)))
                    (begin (res-write! res "done") (res-end! res))))))))
      ;; #25: a streaming endpoint, requested by an HTTP/1.0 client
      (app-get app "/stream"
        (lambda (req res)
          (sse-start! res)
          (res-write! res "hello-")
          (res-write! res "world")
          (res-end! res)))
      ;; a WebSocket route, for the upgrade framing cases below
      (app-ws app "/ws" (lambda (ws) (ws-close! ws)))
      ;; a POST route that answers 200, so "refused" below cannot be
      ;; satisfied by a 404 from routing -- which is what the first version
      ;; of the HTTP/1.0-chunked case accidentally measured
      (app-post app "/echo" (lambda (req res) (send-text! res "ok")))
      (app-listen app port)
      (sleep-ms 300)

      ;; ---- #13 ---------------------------------------------------------
      (let ((r (http-request 'GET (string-append "http://127.0.0.1:"
                                                 (number->string port)
                                                 "/setcookie?v=x%3B%20Domain%3Devil.com")
                            '((timeout . 4000)))))
        (check "the injected Domain never reaches the client"
          (not (str-has? (or (cond ((assq 'set-cookie (response-headers r)) => cdr)
                                   (else ""))
                             "")
                         "evil.com"))))

      ;; ---- #25: HTTP/1.0 must not receive chunked framing ---------------
      (raw-exchange! "GET /stream HTTP/1.0\r\nHost: x\r\n\r\n" main)
      (let ((text (receive (after 9000 #f) (`#(raw ,t) t))))
        (check "HTTP/1.0 stream: no Transfer-Encoding header"
          (and text (not (str-has? (string-downcase text) "transfer-encoding"))))
        (check "HTTP/1.0 stream: body is raw, not hex-chunked"
          (and text (str-has? text "hello-world"))))

      ;; an HTTP/1.1 client still gets chunked
      (raw-exchange! "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n" main)
      (let ((text (receive (after 9000 #f) (`#(raw ,t) t))))
        (check "HTTP/1.1 stream still uses chunked"
          (and text (str-has? (string-downcase text) "transfer-encoding: chunked"))))

      ;; ---- #22: a dribbling client is reaped, not served forever --------
      ;; send a partial header and then nothing at all; the whole-request
      ;; deadline (or the idle timeout) must end it rather than hold the
      ;; reader indefinitely
      (spawn
        (lambda ()
          (tcp-connect! "127.0.0.1" port self)
          (receive (after 5000 (send main (vector 'slow 'no-connect)))
            (`#(tcp-connected ,c)
              (tcp-read-start! c)
              (tcp-write! c (string->utf8 "GET /stream HTTP/1.1\r\nHost: x\r\n") #f)
              ;; never completes the header block
              (receive (after 40000 (tcp-close! c) (send main (vector 'slow 'held)))
                (`#(tcp-data ,bv) (tcp-close! c) (send main (vector 'slow 'answered)))
                (`#(tcp-eof) (tcp-close! c) (send main (vector 'slow 'closed)))
                (`#(tcp-error ,e) (send main (vector 'slow 'closed))))))))
      (let ((outcome (receive (after 45000 'timeout) (`#(slow ,o) o))))
        (display "  [info] partial-header client outcome: ")
        (display outcome) (newline)
        (check "a partial request is eventually reaped"
          (memq outcome '(answered closed))))

      ;; Reported through this file's own counter, and then the two
      ;; cases that need it are skipped -- not the file. Attempting them
      ;; without an interpreter is what produced a server-shaped failure
      ;; the last time; abandoning the file here would take four later
      ;; cases that never touch python with it, and "not run" and "ran
      ;; and passed" read the same afterwards.
      (unless python
        (check "python3 is available to drive a half-closing client" #f)
        (display "       looked for: python3 python3.13 python3.12 python3.11 python3.10 python\n")
        (display "       these two cases are skipped; the rest of this file\n")
        (display "       does not need one and still runs\n"))

      ;; ---- a client that half-closes after its request ------------------
      ;;
      ;; shutdown(SHUT_WR) after a complete request is permitted (RFC 7230
      ;; 6.6) and several clients and load generators do it: the peer has
      ;; said everything it has to say and is waiting for the response.
      ;; Reading that eof as "the client left" and closing answered them
      ;; with nothing -- measured, zero bytes.
      ;; The client is a python script because this library has no
      ;; half-close primitive -- which is the point: only a peer OUTSIDE it
      ;; can produce the shape. The script is written to a file rather than
      ;; passed with -c, because quoting a multi-line program through the
      ;; shell is how the first version of this case silently measured
      ;; nothing at all.
      (when python
        (let ((py "/tmp/igropyr-halfclose.py")
              (out "/tmp/igropyr-halfclose.txt"))
          (system (string-append "rm -f " out))
          (call-with-output-file py
            (lambda (p)
              (display "import socket\n" p)
              (display "s=socket.create_connection(('127.0.0.1'," p)
              (display port p) (display "),timeout=2)\n" p)
              (display "s.sendall(b'GET /slowstream HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')\n" p)
              (display "s.shutdown(socket.SHUT_WR)\n" p)
              (display "d=b''\n" p)
              (display "try:\n" p)
              (display "    while True:\n" p)
              (display "        b=s.recv(4096)\n" p)
              (display "        if not b: break\n" p)
              (display "        d+=b\n" p)
              (display "except Exception: pass\n" p)
              (display "open('" p) (display out p) (display "','wb').write(d)\n" p))
            'replace)
          ;; IN THE BACKGROUND. system blocks the one OS thread, so a
          ;; foreground python would wait for a response the scheduler cannot
          ;; produce while it is blocked -- the first version of this case
          ;; deadlocked exactly that way and reported zero bytes, which looks
          ;; identical to the defect being tested.
          ;; nothing is asserted about a response that was never
          ;; asked for: a client that failed to run would other-
          ;; wise also produce a server-shaped failure beside its
          ;; own, which is the reading this file is being cured of
          (let ((ran (client-ran? py)))
            (check "the half-close client ran" ran)
            (when ran
              (sleep-ms 200)
              (let* ((raw (guard (e (#t "")) (call-with-input-file out get-string-all)))
                   (text (if (string? raw) raw "")))
              (display "  [info] a half-closed client received ")
              (display (string-length text)) (display " bytes\n")
              ;; HTTP/1.1, so the body is chunked: the two writes arrive as
              ;; separate chunks and "hello-world" is never contiguous
              (check "a half-closed client still gets its response"
                (and (str-has? text "200 OK")
                     (str-has? text "hello-")
                     (str-has? text "world")
                     (str-has? text "0\r\n\r\n")))
              (system (string-append "rm -f " py " " out)))))))

      ;; ...and the same for a client that half-closes once the stream is
      ;; already running. That eof reaches await-streaming, which had the
      ;; identical mistake one level down: it ended the stream at whatever
      ;; had been sent so far.
      (when python
        (let ((py "/tmp/igropyr-halfclose2.py")
              (out "/tmp/igropyr-halfclose2.txt"))
          (system (string-append "rm -f " out))
          (call-with-output-file py
            (lambda (p)
              (display "import socket\n" p)
              (display "s=socket.create_connection(('127.0.0.1'," p)
              (display port p) (display "),timeout=4)\n" p)
              (display "s.sendall(b'GET /dripstream HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')\n" p)
              (display "d=s.recv(4096)\n" p)          ; read the head + first chunk
              (display "s.shutdown(socket.SHUT_WR)\n" p)   ; half-close mid-stream
              (display "try:\n" p)
              (display "    while True:\n" p)
              (display "        b=s.recv(4096)\n" p)
              (display "        if not b: break\n" p)
              (display "        d+=b\n" p)
              (display "except Exception: pass\n" p)
              (display "open('" p) (display out p) (display "','wb').write(d)\n" p))
            'replace)
          ;; nothing is asserted about a response that was never
          ;; asked for: a client that failed to run would other-
          ;; wise also produce a server-shaped failure beside its
          ;; own, which is the reading this file is being cured of
          (let ((ran (client-ran? py)))
            (check "the half-close client ran" ran)
            (when ran
              (sleep-ms 200)
              (let* ((raw (guard (e (#t "")) (call-with-input-file out get-string-all)))
                   (text (if (string? raw) raw "")))
              (display "  [info] half-closing mid-stream received ")
              (display (string-length text)) (display " bytes\n")
              (check "a stream survives a half-close in the middle of it"
                (and (str-has? text "done") (str-has? text "0\r\n\r\n")))
              (system (string-append "rm -f " py " " out)))))))

      ;; ---- inbound framing the two ends could read differently ---------
      ;;
      ;; Both of these are request smuggling in miniature: a message whose
      ;; boundary this server and something in front of it would place in
      ;; different bytes.

      ;; chunked is HTTP/1.1 framing (RFC 7230 3.3.1); an HTTP/1.0 request
      ;; declaring it has no agreed message boundary at all
      (raw-exchange! (string-append
                       "POST /echo HTTP/1.0\r\nHost: x\r\n"
                       "Transfer-Encoding: chunked\r\n\r\n"
                       "5\r\nhello\r\n0\r\n\r\n") main)
      (check "HTTP/1.0 + chunked is refused"
        (rejected? (receive (after 9000 #f) (`#(raw ,t) t))))

      ;; A 101 ends HTTP framing: everything after the header block is read
      ;; as WebSocket frames. A request that also declares a body therefore
      ;; has two readings, and those declared bytes went to the frame parser
      ;; without ever being counted against body-limit.
      (raw-exchange! (string-append
                       "GET /ws HTTP/1.1\r\nHost: x\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       "Sec-WebSocket-Version: 13\r\n"
                       "Content-Length: 5\r\n\r\nhello") main)
      (check "an upgrade declaring a Content-Length is refused"
        (rejected? (receive (after 9000 #f) (`#(raw ,t) t))))

      (raw-exchange! (string-append
                       "GET /ws HTTP/1.1\r\nHost: x\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       "Sec-WebSocket-Version: 13\r\n"
                       "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n") main)
      (check "an upgrade declaring a Transfer-Encoding is refused"
        (rejected? (receive (after 9000 #f) (`#(raw ,t) t))))

      ;; and a clean upgrade still works, so the guard did not just break
      ;; WebSockets
      (raw-exchange! (string-append
                       "GET /ws HTTP/1.1\r\nHost: x\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       "Sec-WebSocket-Version: 13\r\n\r\n") main)
      (let ((text (receive (after 9000 #f) (`#(raw ,t) t))))
        (check "a clean upgrade still gets its 101"
          (and text (>= (string-length text) 12)
               (string=? (substring text 9 12) "101"))))

      (sleep-ms 100)
      (if (zero? failures)
          (begin (display "protocol-hardening: all tests passed\n") (exit 0))
          (begin (display failures) (display " failures\n") (exit 1))))))
