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
          req-session session-get session-set! session-clear! session-regenerate!
          session-peek)
  (import (chezscheme) (igropyr checked)
          (igropyr actor) (igropyr libuv) (igropyr gen-server)
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
             ;; COPY the pairs out. Handing back the store's own alist made
             ;; session-set!'s set-cdr! mutate the stored session directly:
             ;; a concurrent request on the same sid saw the write before it
             ;; was committed (and still saw it if the writing request then
             ;; failed), and session-peek -- documented as a snapshot, and
             ;; the credential session-guard authenticates a WebSocket with
             ;; -- observed it too. The per-key merge in 'put is what
             ;; actually commits a change.
             (values (map (lambda (kv) (cons (car kv) (cdr kv))) (car entry))
                     tbl)
             (values #f tbl))))
      (else (values 'bad-request tbl))))

  ;; async: put / drop / prune (no reply needed)
  (define (store-cast msg tbl)
    (case (vector-ref msg 0)
      ;; #(put sid delta cleared? ttl): MERGE the keys this request
      ;; actually touched into whatever the store holds now, rather than
      ;; overwriting with a snapshot taken before the handler ran. Two
      ;; concurrent requests on one sid both read the same starting data;
      ;; a whole-alist write would silently drop the first one's fields.
      ((put)
       (let* ((sid (vector-ref msg 1))
              (delta (vector-ref msg 2))
              (cleared? (vector-ref msg 3))
              (entry (hashtable-ref tbl sid #f))
              (base (if (or cleared? (not entry) (<= (cdr entry) (now-ms)))
                        '()
                        (car entry)))
              (merged (fold-left
                        (lambda (acc kv)
                          (cons kv (remp (lambda (p) (eq? (car p) (car kv)))
                                         acc)))
                        base delta)))
         (hashtable-set! tbl sid
           (cons merged (+ (now-ms) (vector-ref msg 4))))))
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

  ;; Read-only store lookup: the data alist of a live session, or #f.
  ;; This is (igropyr auth)'s session-guard channel for authenticating
  ;; WebSocket upgrades, where the middleware never runs -- a snapshot,
  ;; not a live session object, and nothing is persisted back.
  (define-checked (session-peek (store vector?) (sid string?))
    (gen-server-call (store-pid store) (vector 'get sid)))

  ;; ---- session object (lives on the request) --------------------------

  ;; sid, mutable data alist, mutable dirty?/new? flags; `touched` is the
  ;; alist of keys this request actually wrote (the delta merged into the
  ;; store), and `cleared?` records a session-clear! so the merge starts
  ;; from empty instead of from a concurrent writer's data.
  (define-checked-record session
    (mutable sid string?)
    (mutable data list?)
    (mutable dirty? boolean?)
    (mutable new? boolean?)
    (mutable touched list?)
    (mutable cleared? boolean?)
    (rotate procedure?))

  (define (make-session/fresh sid data new? rotate)
    (make-session sid data #f new? '() #f rotate))

  (define-checked (session-get (s session?) (key symbol?))
    (let ((p (assq key (session-data s)))) (and p (cdr p))))

  (define-checked (session-set! (s session?) (key symbol?) val)
    (let ((p (assq key (session-data s))))
      (if p (set-cdr! p val)
          (session-data-set! s (cons (cons key val) (session-data s)))))
    ;; record the write itself, so the store merges only this key
    (session-touched-set! s
      (cons (cons key val)
            (remp (lambda (p) (eq? (car p) key)) (session-touched s))))
    (session-dirty?-set! s #t))

  (define-checked (session-clear! (s session?))
    (session-data-set! s '())
    (session-touched-set! s '())
    (session-cleared?-set! s #t)
    (session-dirty?-set! s #t))

  ;; Rotate an established identifier at an authentication or privilege
  ;; boundary. A cookie-less request already has a freshly generated,
  ;; unguessable id, so rotating that new id would only emit two competing
  ;; Set-Cookie fields for the same response.
  (define-checked (session-regenerate! (s session?))
    (if (session-new? s)
        (session-sid s)
        (let ((old (session-sid s)) (fresh (new-sid)))
          ;; Issue the replacement cookie before mutating the object; a bad
          ;; middleware option must fail without invalidating the live id.
          ((session-rotate s) old fresh)
          (session-sid-set! s fresh)
          (session-new?-set! s #t)
          ;; The new store entry starts empty, so persist the full snapshot.
          (session-touched-set! s
            (map (lambda (kv) (cons (car kv) (cdr kv))) (session-data s)))
          (session-cleared?-set! s #t)
          (session-dirty?-set! s #t)
          fresh)))

  ;; handler-facing accessor
  (define-checked (req-session (req request?)) (req-local req 'session))

  ;; ---- middleware ------------------------------------------------------

  (define default-cookie-name "sid")

  (define (opt o k d) (let ((p (assq k o))) (if p (cdr p) d)))

  ;; Options: (cookie . "name"), (secure . bool), (same-site . "Lax"),
  ;; (max-age . seconds | #f), (path . "/").
  ;;
  ;; `secure` defaults to #t: the sid is a bearer credential (it is also
  ;; what session-guard authenticates a WebSocket upgrade with), so the
  ;; browser must never attach it to a plaintext request. Pass
  ;; '((secure . #f)) for local http development.
  ;;
  ;; A session is persisted only when the handler actually WROTE to it.
  ;; Minting a store entry for every cookie-less request would (a) let
  ;; any anonymous visitor hold a live, store-resident session -- which
  ;; session-guard would then have to distinguish from a real login --
  ;; and (b) grow the store without bound under unauthenticated traffic.
  ;; (define-checked has no rest-argument form; check by hand)
  (define (session-middleware store . rest)
    (unless (vector? store)
      (assertion-violation 'session-middleware
        "store must be a session store" store))
    (let* ((o (if (pair? rest) (car rest) '()))
           (cname (opt o 'cookie default-cookie-name))
           (path (opt o 'path "/"))
           (same-site (opt o 'same-site "Lax"))
           (max-age (opt o 'max-age #f))
           (secure? (opt o 'secure #t)))
      (lambda (req res next)
        (define (issue-cookie! sid)
          (apply set-cookie! res cname sid
                 (string-append "Path=" path)
                 "HttpOnly"
                 (string-append "SameSite=" same-site)
                 (append (if secure? '("Secure") '())
                         (if max-age
                             (list (string-append "Max-Age="
                                                  (number->string max-age)))
                             '()))))
        (define (rotate! old fresh)
          ;; Once the response is out, set-cookie! still succeeds and still
          ;; does nothing -- the header it would have written is already on
          ;; the wire. Dropping the old id anyway would leave the client
          ;; holding a cookie for a session that no longer exists: silently
          ;; logged out, with the next request starting over as anonymous.
          ;; Refuse instead, and refuse BEFORE either effect, so the live
          ;; id survives a handler that regenerates in the wrong order.
          (when (res-answered? res)
            (assertion-violation 'session-regenerate!
              "response already sent -- the new cookie cannot reach the client; regenerate before answering"
              old))
          (issue-cookie! fresh)
          (gen-server-cast (store-pid store) (vector 'drop old)))
        (let* ((sid (req-cookie req cname))
               (data (and sid (gen-server-call (store-pid store)
                                (vector 'get sid))))
               (s (if data
                      (make-session/fresh sid data #f rotate!)
                      (make-session/fresh (new-sid) '() #t rotate!))))
          (req-set-local! req 'session s)
          ;; The cookie must go out with the response headers, i.e. before
          ;; the handler runs, so a new sid is always announced; only the
          ;; STORE entry waits for an actual write.
          (when (session-new? s)
            (issue-cookie! (session-sid s)))
          (next)
          ;; persist only what the handler wrote (see store-cast 'put)
          (when (session-dirty? s)
            (gen-server-cast (store-pid store)  ; async: don't block the response
              (vector 'put (session-sid s) (session-touched s)
                      (session-cleared? s) (store-ttl store))))))))
)
