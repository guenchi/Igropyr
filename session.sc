#!chezscheme
;;; (igropyr session) -- cookie-based sessions.
;;;
;;; A session store is a gen-server holding sid -> (data . expiry); a
;;; ticker prunes expired sessions. The middleware reads the session
;;; cookie, loads the session onto the request, and after the handler
;;; runs persists it back if it changed (issuing a Set-Cookie for a new
;;; session). Handlers read/write via session-get / session-set!.
;;;
;;;   (define store (make-session-store))          ; at boot
;;;   (app-use app (session-middleware store))
;;;   ;; in a handler:
;;;   (let ((s (req-session req)))
;;;     (session-set! s 'user "alice")
;;;     (session-get s 'user))
;;;
;;; sids come from the OS CSPRNG (/dev/urandom).

(library (igropyr session)
  (export make-session-store session-middleware
          req-session session-get session-set! session-clear!)
  (import (chezscheme) (igropyr actor) (igropyr libuv) (igropyr gen-server)
          (igropyr http) (igropyr express))

  (define default-ttl-ms (* 30 60 1000))    ; 30 minutes
  (define prune-interval-ms 60000)          ; 1 minute

  ;; ---- secure random session id ---------------------------------------

  (define (random-hex n-bytes)
    (call-with-port (open-file-input-port "/dev/urandom")
      (lambda (p)
        (let ((bv (get-bytevector-n p n-bytes)))
          (apply string-append
            (map (lambda (i)
                   (let ((h (number->string (bytevector-u8-ref bv i) 16)))
                     (if (= 1 (string-length h)) (string-append "0" h) h)))
                 (iota n-bytes)))))))

  (define (new-sid) (random-hex 16))         ; 128-bit

  ;; ---- store (a gen-server) -------------------------------------------

  ;; state: eqv? no -- keys are strings, use string hashtable sid -> (data . expiry)
  (define (store-init) (make-hashtable string-hash string=?))

  ;; sync: get (needs a reply)
  (define (store-call msg from tbl)
    (case (vector-ref msg 0)
      ((get)
       (let ((entry (hashtable-ref tbl (vector-ref msg 1) #f)))
         (if (and entry (> (cdr entry) (now-ms)))
             (values (car entry) tbl)            ; data alist
             (values #f tbl))))
      (else (values 'bad-request tbl))))

  ;; async: put / drop / prune (no reply needed)
  (define (store-cast msg tbl)
    (case (vector-ref msg 0)
      ((put)
       (hashtable-set! tbl (vector-ref msg 1)
         (cons (vector-ref msg 2) (+ (now-ms) (vector-ref msg 3)))))
      ((drop) (hashtable-delete! tbl (vector-ref msg 1)))
      ((prune)
       (let ((now (now-ms)))
         (let-values (((ks vs) (hashtable-entries tbl)))
           (vector-for-each
             (lambda (k v) (when (<= (cdr v) now) (hashtable-delete! tbl k)))
             ks vs)))))
    tbl)

  ;; a store is #(pid ttl)
  (define (make-session-store . opt)
    (let ((ttl (if (pair? opt) (car opt) default-ttl-ms))
          (pid (gen-server-start store-init store-call store-cast)))
      (spawn (lambda () (prune-loop pid)))
      (vector pid ttl)))

  (define (prune-loop pid)
    (sleep-ms prune-interval-ms)
    (gen-server-cast pid (vector 'prune))
    (prune-loop pid))

  (define (store-pid store) (vector-ref store 0))
  (define (store-ttl store) (vector-ref store 1))

  ;; ---- session object (lives on the request) --------------------------

  ;; sid, mutable data alist, mutable dirty? flag
  (define-record-type (session make-session session?)
    (fields
      (immutable sid session-sid)
      (mutable data session-data session-data-set!)
      (mutable dirty session-dirty? session-dirty-set!)
      (mutable new? session-new? session-new-set!)))

  (define (session-get s key)
    (let ((p (assq key (session-data s)))) (and p (cdr p))))

  (define (session-set! s key val)
    (let ((p (assq key (session-data s))))
      (if p (set-cdr! p val)
          (session-data-set! s (cons (cons key val) (session-data s)))))
    (session-dirty-set! s #t))

  (define (session-clear! s)
    (session-data-set! s '())
    (session-dirty-set! s #t))

  ;; handler-facing accessor
  (define (req-session req) (req-local req 'session))

  ;; ---- middleware ------------------------------------------------------

  (define cookie-name "sid")

  (define (session-middleware store)
    (lambda (req res next)
      (let* ((sid (req-cookie req cookie-name))
             (data (and sid (gen-server-call (store-pid store)
                              (vector 'get sid))))
             (s (if data
                    (make-session sid data #f #f)
                    (make-session (new-sid) '() #f #t))))
        (req-set-local! req 'session s)
        (when (session-new? s)
          (set-cookie! res cookie-name (session-sid s)
                       "Path=/" "HttpOnly" "SameSite=Lax"))
        (next)
        ;; persist after the handler if the session changed
        (when (or (session-dirty? s) (session-new? s))
          (gen-server-cast (store-pid store)   ; async: don't block the response
            (vector 'put (session-sid s) (session-data s) (store-ttl store)))))))
)
