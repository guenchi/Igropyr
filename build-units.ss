;;; build-units.ss -- the one list of Igropyr libraries, in dependency
;;; order, plus the check that keeps it honest.
;;;
;;; Loaded by build.ss and by the whole-program builds. It exists because
;;; the list used to be written out four times: build.ss carried all of
;;; it while build-whole.ss, build-pgo.ss and build-profile.ss each
;;; carried a copy that had stopped being updated, and each of those
;;; three was missing twenty-one libraries. Nothing failed. A library
;;; absent from a build is not a build error -- it stays source-only,
;;; takes a fresh UID in every process, and quietly makes everything
;;; compiled against it reload.
;;;
;;; Four copies of a list is four chances to forget. There is now one,
;;; and it is compared against the directory rather than trusted.

;; ⛔ NO PRODUCTION BUILD MAY BE MADE WITH FAULT INJECTION ARMED, and
;; this is the place that can say so once. The switch is read when a
;; library is expanded, so a .so compiled while IGROPYR_INJECT=on carries
;; injection code and an invoke-time refusal -- an artifact that is
;; neither usable in production nor obviously broken until something
;; loads it.
;;
;; ⭐ IT LIVES HERE BECAUSE THE LIST DOES. build.ss is not the only thing
;; that compiles these units: build-whole.ss, build-profile.ss and
;; build-pgo.ss load this same file and compile the same names. A refusal
;; written into one of four consumers is a refusal three builds do not
;; have -- and the first version of this guard was exactly that.
;; ⚠ AND ONLY A FIFTH ENTRY POINT THAT LOADS THIS FILE gets it. An
;; entry point calling compile-library or compile-program directly is
;; outside this guard entirely -- today there is none, and that is a
;; fact about the repository rather than a property of this line.
(let ((v (getenv "IGROPYR_INJECT")))
  (when (and v (string=? v "on"))
    (assertion-violation 'build-units
      "IGROPYR_INJECT=on: refusing to compile igropyr libraries with fault injection armed")))

(define library-units
  '("igropyr/util.sc"
    "igropyr/checked.sc"
    ;; ⭐ COMPILED EVEN THOUGH IT SHIPS INERT. libuv imports it, so it has
    ;; to resolve in a compiled build; with IGROPYR_INJECT unset its
    ;; macros expand to the guarded expression or to nothing and no
    ;; consumer refers to its runtime part. The refusal at the head of
    ;; this file stops every build entry point that loads the list, so
    ;; this line cannot produce an armed .so.
    "igropyr/inject.sc"
    "igropyr/buffer.sc"
    "igropyr/platform.sc"
    ;; ⭐ BEFORE libuv.sc, WHICH IMPORTS IT. Compiling a unit after its
    ;; importer makes Chez build the importer against a different
    ;; instance of it; the order here is the dependency order, not a
    ;; preference. It sits after platform.sc, its only dependency.
    "igropyr/tls-core.sc"
    "igropyr/durable.sc"
    "igropyr/quickjs.sc"
    "igropyr/crypto.sc"
    "igropyr/blas.sc"
    "igropyr/libuv.sc"
    "igropyr/actor.sc"
    ;; after actor and libuv, which it drives, and after durable, whose
    ;; error predicates and traced step it re-uses. Missing from this
    ;; list until now, which made it the one source-only library in the
    ;; set -- and a source-only library takes a fresh UID per process, so
    ;; anything compiled against it reloads silently. Same reason the
    ;; sexpr note below gives.
    "igropyr/durable-async.sc"
    ;; json-internal BEFORE json, and for the reason the note above
    ;; gives: json.so imports it, so leaving it source-only makes it take
    ;; a fresh UID per process and every dependent .so reload silently --
    ;; or, once json.so exists, refuse to load at all ("a different
    ;; compilation instance"). It was added as a file without being added
    ;; here, which is the same omission this list already documents.
    "igropyr/json-internal.sc"
    "igropyr/json.sc"
    "igropyr/gzip.sc"
    ;; sexpr must be compiled too: a source-only library gets a fresh
    ;; UID per process, which invalidates every dependent .so ("reloading
    ;; because a dependency has changed") -- node/express/dpool would be
    ;; silently re-expanded from source on every start
    "igropyr/sexpr.sc"
    "igropyr/otp.sc"
    "igropyr/websocket.sc"
    "igropyr/ws-client.sc"
    "igropyr/gen-server.sc"
    "igropyr/node.sc"
    "igropyr/conv-status.sc"
    "igropyr/conversation.sc"
    "igropyr/http.sc"
    "igropyr/pubsub.sc"
    "igropyr/dpool.sc"
    "igropyr/express.sc"
    "igropyr/session.sc"
    "igropyr/auth.sc"
    "igropyr/middleware.sc"
    "igropyr/jwt.sc"
    "igropyr/metrics.sc"
    "igropyr/dashboard.sc"
    "igropyr/http-client.sc"
    "igropyr/sigv4.sc"
    "igropyr/s3.sc"
    "igropyr/aws.sc"
    "igropyr/sts.sc"
    "igropyr/ses.sc"
    "igropyr/sns.sc"
    "igropyr/cloudwatch.sc"
    "igropyr/s3-control.sc"
    "igropyr/tls.sc"
    "igropyr/apple-jws.sc"
    "igropyr/jwks.sc"
    "igropyr/kdf.sc"
    ;; rsa and aead import only (igropyr platform) -- the libcrypto loader --
    ;; so they can sit anywhere after it; they are kept with the other
    ;; libcrypto-backed libraries above rather than scattered.
    "igropyr/rsa.sc"
    "igropyr/aead.sc"
    "igropyr/redis.sc"
    ;; connpool is the shared checkout/lease engine: it imports only actor
    ;; and libuv, and every pooled driver below imports it.
    "igropyr/connpool.sc"
    "igropyr/qjspool.sc"
    ;; ssr comes after both of its pools' dependencies -- qjspool (the
    ;; render engine) and redis (a cache backend).
    "igropyr/ssr.sc"
    "igropyr/mysql.sc"
    "igropyr/postgresql.sc"
    "igropyr/cluster.sc"))

;; Sources that are deliberately NOT libraries. Each carries its reason,
;; and adding to this list is the only way to make a new .sc file legal
;; here -- which is the point: it costs a sentence, and the sentence is
;; the record of a decision somebody made on purpose.
(define non-libraries
  '(("app.sc"
     . "entry-point program, not a library: the whole-program builds compile it with compile-program, and a per-library build must not compile it at all")
    ("qjs-worker.sc"
     . "standalone script, run as `scheme --script igropyr/qjs-worker.sc`; nothing imports it")
    ("inject-control.sc"
     . "test-only: the arming side of fault injection. ⛔ Compiling it into a production build would put the instrument in the product; nothing in the library imports it, and test/inject-isolation.ss checks that mechanically by walking invoke edges")))

;; Compare the list against the directory it claims to describe.
;;
;; This is the guard, and it is deliberately two-sided: a file on disk
;; that nobody listed is the failure that happened, and a listed file
;; that is no longer on disk is the one that happens next, after a
;; rename. Both stop the build and both say which names are involved --
;; a build that fails without naming the file is a build that gets
;; worked around.
(define (check-library-list! who listed)
  (define (basename p)
    (let ((i (string-length "igropyr/")))
      (if (and (> (string-length p) i)
               (string=? (substring p 0 i) "igropyr/"))
          (substring p i (string-length p))
          p)))
  (define (source? f)
    (let ((n (string-length f)))
      (and (> n 3) (string=? (substring f (- n 3) n) ".sc"))))
  (let* ((on-disk (sort string<?
                        (filter (lambda (f)
                                  (and (source? f) (not (assoc f non-libraries))))
                                (map (lambda (x) (if (string? x) x (format "~a" x)))
                                     (directory-list "igropyr")))))
         (named (sort string<? (map basename listed)))
         (missing (filter (lambda (f) (not (member f named))) on-disk))
         (extra   (filter (lambda (f) (not (member f on-disk))) named)))
    (unless (and (null? missing) (null? extra))
      (printf "\n~a: the library list does not match igropyr/\n" who)
      (unless (null? missing)
        (printf "  on disk but not listed (add in dependency order, or\n")
        (printf "  add to non-libraries WITH a reason): ~a\n" missing))
      (unless (null? extra)
        (printf "  listed but not on disk: ~a\n" extra))
      (error who "library list is out of date"))
    (printf "~a: ~a libraries, list matches igropyr/\n" who (length named))))
