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
          (igropyr actor) (igropyr gen-server)
          (only (igropyr libuv) now-ms)
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

  ;; sync: get / copy (need a reply)
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
      ;; Prepare a rotated id before it can be announced to the client.
      ;; Keep the old id until the middleware knows whether the handler
      ;; actually answered: a pre-response failure leaves the client on old,
      ;; while a post-response failure leaves it on this already-live copy.
      ((copy)
       (let ((fresh (vector-ref msg 1))
             (data (vector-ref msg 2))
             (ttl (vector-ref msg 3)))
         ;; Copy the pairs: session-set! mutates the request-local alist.
         (hashtable-set! tbl fresh
           (cons (map (lambda (kv) (cons (car kv) (cdr kv))) data)
                 (+ (now-ms) ttl)))
         (values #t tbl)))
      (else (values 'bad-request tbl))))

  ;; async: put / drop / prune (no reply needed)
  (define (store-cast msg tbl)
    (case (vector-ref msg 0)
      ;; #(put sid delta cleared? ttl create?): MERGE the keys this request
      ;; actually touched into whatever the store holds now, rather than
      ;; overwriting with a snapshot taken before the handler ran. Two
      ;; concurrent requests on one sid both read the same starting data;
      ;; a whole-alist write would silently drop the first one's fields.
      ;; An established request may update only an id that is still live:
      ;; after rotation drops old, an in-flight request on old must not be
      ;; able to recreate that retired bearer credential.
      ((put)
       (let* ((sid (vector-ref msg 1))
              (delta (vector-ref msg 2))
              (cleared? (vector-ref msg 3))
              (entry (hashtable-ref tbl sid #f)))
         (when (or entry (vector-ref msg 5))
           (let* ((base (if (or cleared? (not entry)
                               (<= (cdr entry) (now-ms)))
                            '()
                            (car entry)))
                  (merged (fold-left
                            (lambda (acc kv)
                              (cons kv
                                (remp (lambda (p) (eq? (car p) (car kv)))
                                      acc)))
                            base delta)))
             (hashtable-set! tbl sid
               (cons merged (+ (now-ms) (vector-ref msg 4))))))))
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

  ;; CLEARING ENDS THE IDENTITY, NOT ONLY THE DATA. Emptying the data
  ;; and leaving the id alone is not a logout: the browser keeps the same
  ;; sid, and so does anyone who copied it. The next login writes into
  ;; that same id, so a captured sid survives the logout meant to end it
  ;; and comes back as a live authenticated session. The property to hold
  ;; on to is one sentence: AFTER A CLEAR, THE OLD SID MUST NO LONGER BE
  ;; A USABLE IDENTITY.
  ;;
  ;; ORDER MATTERS TWICE HERE.
  ;;
  ;; The data is emptied BEFORE rotating, because the rotation copies
  ;; whatever the session holds at that moment into the new entry --
  ;; rotate first and the new id starts life holding everything the clear
  ;; was supposed to remove.
  ;;
  ;; The id is replaced AFTER the rotation returns, because publishing
  ;; the replacement cookie can fail (the response may already have been
  ;; sent) and a failure must leave the caller on an id that still
  ;; resolves.
  ;;
  ;; A session that is already new is left alone, the way
  ;; session-regenerate! leaves it: its id has not reached the client
  ;; yet, so there is nothing to invalidate, and rotating anyway would
  ;; put two Set-Cookie fields for the same session in one response.
  (define-checked (session-clear! (s session?))
    (session-data-set! s '())
    (session-touched-set! s '())
    (session-cleared?-set! s #t)
    (session-dirty?-set! s #t)
    (unless (session-new? s)
      (let ((old (session-sid s)) (fresh (new-sid)))
        ((session-rotate s) 'session-clear! old fresh (session-data s))
        (session-sid-set! s fresh)
        (session-new?-set! s #t)))
    (void))

  ;; Rotate an established identifier at an authentication or privilege
  ;; boundary. A cookie-less request already has a freshly generated,
  ;; unguessable id, so rotating that new id would only emit two competing
  ;; Set-Cookie fields for the same response.
  ;;
  ;; IDEMPOTENT within one request: rotating marks the session new, so a
  ;; second call takes the branch above and returns the id the first one
  ;; issued, without a second rotation or a second cookie. That is what
  ;; makes it safe for two layers to each insist on rotating -- neither has
  ;; to know whether the other already did. It also means a caller cannot
  ;; use repeated calls to mint successive ids inside one request; there is
  ;; one identity per request, and this decides what it is.
  (define-checked (session-regenerate! (s session?))
    (if (session-new? s)
        (session-sid s)
        (let ((old (session-sid s)) (fresh (new-sid)))
          ;; Issue the replacement cookie before mutating the object; a bad
          ;; middleware option must fail without invalidating the live id.
          ((session-rotate s) 'session-regenerate! old fresh (session-data s))
          (session-sid-set! s fresh)
          (session-new?-set! s #t)
          ;; The prepared store entry has the pre-rotation snapshot; mark the
          ;; final commit as a full replacement so later handler writes are
          ;; applied to exactly this request's state.
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

  ;; Options: (cookie . "name"), (secure . bool | procedure),
  ;; (same-site . "Lax"), (max-age . seconds | #f), (path . "/").
  ;;
  ;; `secure` defaults to #t: the sid is a bearer credential (it is also
  ;; what session-guard authenticates a WebSocket upgrade with), so the
  ;; browser must never attach it to a plaintext request. Pass
  ;; '((secure . #f)) for local http development.
  ;;
  ;; IT MAY ALSO BE A PROCEDURE OF ONE ARGUMENT, called with the request
  ;; at each point a cookie is issued; a true answer attaches Secure.
  ;; One process can serve two schemes at once -- public HTTPS through a
  ;; proxy and a plaintext tunnel on the inside -- and a value read once
  ;; at construction cannot be right for both: with Secure on, the
  ;; plaintext side's browser silently refuses to store the cookie and
  ;; the session vanishes the instant it is created; with it off, the
  ;; public side's sid travels in clear.
  ;;
  ;; WHAT DECIDES IS THE CALLER'S, and this framework deliberately does
  ;; not read X-Forwarded-Proto or any relative for you. Which header can
  ;; be believed is a fact about a deployment -- which proxy sets it,
  ;; whether anything upstream of it can forge it -- and a library that
  ;; guessed would be guessing about somebody else's network. Read
  ;; whatever your own front end guarantees.
  ;;
  ;; A PREDICATE THAT RAISES IS TREATED AS #t, and the cost of that is
  ;; worth stating honestly rather than talking down. Attaching Secure
  ;; where it was not wanted does NOT cost merely one refused cookie:
  ;; the response carrying it went out over the plaintext side anyway,
  ;; so that sid has already been on the wire in clear, and Secure only
  ;; stops the browser keeping it. The caller sees a session that will
  ;; not stick, retries, and mints another exposed sid each time, each
  ;; leaving an orphan entry until its TTL.
  ;;
  ;; It is still the better direction, for a reason that survives the
  ;; correction: without Secure the browser KEEPS a plaintext-side
  ;; cookie and re-sends it on every later request, so one leak becomes
  ;; a standing one. Fail-closed converts an ongoing exposure into a
  ;; visible failure to log in. It does not undo the exposure of the
  ;; response that has already gone.
  ;;
  ;; The same answer covers a predicate that returns no value or several,
  ;; which is not a raise and would otherwise escape the guard where its
  ;; result meets a single-value binding. It does NOT cover a predicate
  ;; that escapes through a captured continuation: that is not a raise
  ;; and not a return, so nothing here runs -- the cookie, and possibly
  ;; the request, simply go elsewhere.
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
           (secure-opt (opt o 'secure #t)))
      ;; CHECKED WHERE IT IS ACCEPTED, not where it is used: a predicate
      ;; that cannot take a request would otherwise raise on every cookie
      ;; and be swallowed by the fail-closed guard, so every session would
      ;; get Secure and nothing would say why.
      (unless (or (boolean? secure-opt)
                  (and (procedure? secure-opt)
                       (logbit? 1 (procedure-arity-mask secure-opt))))
        (assertion-violation 'session-middleware
          "secure must be a boolean or a procedure accepting one argument"
          secure-opt))
      (lambda (req res next)
        (let ((rotated-old #f) (rotated-fresh #f))
          ;; The boolean path is the boolean path: no call into the
          ;; caller's code and no guard around anything. (There is an
          ;; internal call and a boolean? test; what is promised is that
          ;; nothing of the caller's runs and nothing of the caller's
          ;; errors can be swallowed.)
          (define (secure-now?)
            (if (boolean? secure-opt)
                secure-opt
                (guard (e (#t #t))
                  (call-with-values
                    (lambda () (secure-opt req))
                    (lambda vs
                      (if (and (pair? vs) (null? (cdr vs)))
                          (and (car vs) #t)
                          #t))))))
          (define (issue-cookie-with! setter sid)
            (apply setter res cname sid
                   (string-append "Path=" path)
                   "HttpOnly"
                   (string-append "SameSite=" same-site)
                   (append (if (secure-now?) '("Secure") '())
                           (if max-age
                               (list (string-append "Max-Age="
                                                    (number->string max-age)))
                               '()))))
          (define (issue-cookie! sid)
            (issue-cookie-with! set-cookie! sid))
          (define (issue-cookie-if-unanswered! sid)
            (issue-cookie-with! set-cookie-if-unanswered! sid))
          (define (drop! sid)
            (gen-server-cast (store-pid store) (vector 'drop sid)))
          ;; `who` NAMES THE CALL THAT ASKED FOR THIS. Both
          ;; session-regenerate! and session-clear! rotate, and a caller
          ;; that rotated too late has to be told which of its own calls
          ;; was too late -- an error naming the wrong one sends them
          ;; looking at the wrong line.
          (define (rotate! who old fresh data)
            ;; Publishing the replacement cookie and claiming a response race
            ;; on the same token. Whichever wins is definitive: a successful
            ;; publication is included in the responder's atomic header
            ;; snapshot; a claimed response makes this raise before either
            ;; store id moves. A separate res-answered? check has a TOCTOU gap.
            (unless (issue-cookie-if-unanswered! fresh)
              (assertion-violation who
                "response already sent -- the new cookie cannot reach the client; rotate the session before answering"
                old))
            ;; Synchronous: session-regenerate! cannot return (and the handler
            ;; cannot send the cookie) until fresh is a valid store entry --
            ;; a handler that answers and THEN fails must leave the client's
            ;; new id resolvable. old deliberately stays live until next
            ;; either returns or fails: a pre-response failure leaves the
            ;; client on old, and old must still exist then.
            (gen-server-call (store-pid store)
              (vector 'copy fresh data (store-ttl store)))
            (set! rotated-old old)
            (set! rotated-fresh fresh))
          (let* ((sid (req-cookie req cname))
                 (data (and sid (gen-server-call (store-pid store)
                                  (vector 'get sid))))
                 (s (if data
                        (make-session/fresh sid data #f rotate!)
                        (make-session/fresh (new-sid) '() #t rotate!))))
            (define (persist!)
              ;; Persist only what the handler wrote (see store-cast 'put).
              (when (session-dirty? s)
                (gen-server-cast (store-pid store)
                  (vector 'put (session-sid s) (session-touched s)
                          (session-cleared? s) (store-ttl store)
                          ;; create? -- only a session this middleware minted
                          ;; (or rotated: regenerate! re-marks it new) may
                          ;; CREATE its entry; an established session updates
                          ;; old entries only, so a commit racing a rotation
                          ;; cannot resurrect the retired id (see store-cast)
                          (session-new? s)))))
            (req-set-local! req 'session s)
            ;; The cookie must go out with the response headers, i.e. before
            ;; the handler runs, so a new sid is always announced; only the
            ;; STORE entry waits for an actual write.
            (when (session-new? s)
              (issue-cookie! (session-sid s)))
            (guard (e
                    (#t
                     ;; An answered response may already have exposed the
                     ;; session id, so commit every write made before the
                     ;; failure. If rotation happened, keep fresh and retire
                     ;; old; otherwise discard the unannounced copy. Then
                     ;; preserve the handler failure for the HTTP supervisor.
                     (when (res-answered? res) (persist!))
                     (when rotated-old
                       (if (res-answered? res)
                           (drop! rotated-old)
                           (drop! rotated-fresh)))
                     (raise e)))
              (next)
              ;; Both casts target the same store and are sent in order, so a
              ;; successful rotation commits fresh before invalidating old.
              (persist!)
              (when rotated-old (drop! rotated-old))))))))
)
