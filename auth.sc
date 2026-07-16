#!chezscheme
;;; (igropyr auth) -- authentication: the ROLE layer, credential-format
;;; neutral. Token formats live elsewhere ((igropyr jwt) today); this
;;; library turns any verifier into request guards for both channels:
;;;
;;;   ;; HTTP routes: middleware, refuses with 401
;;;   (app-use app (auth (jwt-verifier key)))
;;;   (app-use app (auth (jwt-verifier key '((leeway . 30)))
;;;                      '((optional . #t))))
;;;
;;;   ;; WebSocket routes: guard checked BEFORE the 101 handshake
;;;   (app-ws app "/chat" chat-session (token-guard (jwt-verifier key)))
;;;   (app-ws app "/feed" feed-session (session-guard store))
;;;
;;;   ;; both channels: claims in the handler / ws session
;;;   (req-claims req)
;;;
;;; Two verifier shapes:
;;;   token verifier  (lambda (token) claims | #f)   -- e.g. jwt-verifier
;;;   request guard   (lambda (req) claims | #f)     -- what app-ws takes
;;; token-guard lifts the former into the latter; session-guard is a
;;; request guard natively (the credential is the session cookie).
;;;
;;; WebSocket credentials: the upgrade request never runs the
;;; middleware chain (it is intercepted before the worker pool), so
;;; app-ws takes the guard directly and express rejects the upgrade
;;; with 401 BEFORE any handshake -- an unauthenticated peer never
;;; gets a socket. token-guard reads Authorization: Bearer first and
;;; falls back to a ?token= query parameter, because the browser
;;; WebSocket API cannot set headers. CAVEAT: query-string tokens can
;;; end up in proxy/access logs; prefer the header wherever the client
;;; can set one, and keep query tokens short-lived. session-guard
;;; reads the session cookie and answers the session's data alist as
;;; the claims -- a read-only snapshot at upgrade time; a long-lived
;;; ws session does not see later session mutations.
;;;
;;; Everything here is always-on business code (credentials are
;;; external input); contracts only guard our own callers' types.

(library (igropyr auth)
  (export auth req-claims token-guard session-guard)
  (import (chezscheme) (igropyr checked)
          (igropyr http) (igropyr express)
          (only (igropyr session) session-peek))

  (define (opt alist key default)
    (let ((p (assq key alist))) (if p (cdr p) default)))

  (define (bearer-token req)
    (let ((h (req-header req 'authorization)))
      (and (string? h)
           (fx>= (string-length h) 7)
           (string-ci=? (substring h 0 7) "Bearer ")
           (let ((t (substring h 7 (string-length h))))
             (and (fx> (string-length t) 0) t)))))

  ;; ---- HTTP middleware ------------------------------------------------------
  ;; verify is any (lambda (token) claims-or-#f). Options:
  ;; (optional . #t) lets a request WITHOUT a token through (req-claims
  ;; stays #f); a present-but-invalid token still answers 401.
  ;; (on-fail . (lambda (req res) ...)) overrides the refusal -- the
  ;; default answers 401 + WWW-Authenticate: Bearer with a small JSON
  ;; body; an s-expression endpoint may prefer a sexpr body.

  (define (default-auth-fail req res)
    (set-status! res 401)
    (set-header! res "WWW-Authenticate" "Bearer")
    (send-json! res '((error . "unauthorized"))))

  (define (auth verify . rest)
    (unless (procedure? verify)             ; boot-time config error, be loud
      (assertion-violation 'auth "verify must be a procedure" verify))
    (let* ((o (if (pair? rest) (car rest) '()))
           (optional (opt o 'optional #f))
           (on-fail (opt o 'on-fail default-auth-fail)))
      (lambda (req res next)
        (let* ((tok (bearer-token req))
               (claims (and tok (verify tok))))
          (cond
            (claims
             (req-set-local! req 'claims claims)
             (next))
            ((and optional (not tok))
             (next))
            (else (on-fail req res)))))))

  ;; claims left by (auth ...) or an app-ws guard, or #f
  (define-checked (req-claims (req request?))
    (req-local req 'claims))

  ;; ---- WebSocket guards ---------------------------------------------------
  ;; A guard is (lambda (req) claims-or-#f), run by the ws resolver
  ;; before the 101 handshake; #f answers 401 with no upgrade.

  ;; lift a token verifier into a request guard: Authorization: Bearer
  ;; first, then the ?token= query parameter (browser WebSocket API
  ;; cannot set headers). (query . "name") renames the parameter;
  ;; (query . #f) disables the fallback for header-capable clients.
  (define (token-guard verify . rest)
    (unless (procedure? verify)
      (assertion-violation 'token-guard "verify must be a procedure" verify))
    (let* ((o (if (pair? rest) (car rest) '()))
           (qname (opt o 'query "token")))
      (lambda (req)
        (let ((tok (or (bearer-token req)
                       (and qname
                            ;; req-query is the already-parsed alist
                            (let ((p (assoc qname (req-query req))))
                              (and p (fx> (string-length (cdr p)) 0)
                                   (cdr p)))))))
          (and tok (verify tok))))))

  ;; request guard on the cookie session: the sid cookie must name a
  ;; live session in the store; its data alist becomes the claims.
  ;; (cookie . "name") matches a session-middleware with a custom
  ;; cookie name (the default is "sid" on both sides).
  (define (session-guard store . rest)
    (unless (vector? store)
      (assertion-violation 'session-guard "store must be a session store" store))
    (let* ((o (if (pair? rest) (car rest) '()))
           (cname (opt o 'cookie "sid")))
      (lambda (req)
        (let ((sid (req-cookie req cname)))
          (and sid (session-peek store sid))))))
)
