#!chezscheme
;;; The names applications import must not move by accident.
;;;
;;; A mechanical rename inside this repo silently rewrote six of them:
;;; `sql-query` -> `connpool-call` also matched the SUBSTRING inside
;;; `mysql-query` and `postgresql-query`, and the same for `sql-close!`
;;; and `sql-pool-stats`. Every use moved with every definition, so the
;;; whole suite stayed green while `mysql-query` had stopped existing --
;;; a break that would only surface in the applications that import it.
;;;
;;; Importing each name by hand is what catches that. `(only ...)` fails
;;; at expansion time when a name is absent, so this file does not need
;;; to call anything: loading it IS the assertion.

;;; THIS FILE IS A TRANSCRIPTION, NOT A DERIVED ARTIFACT, and the
;;; difference is the whole point. Its value comes from being a SECOND
;;; copy that does not move when a definition moves: a rename that
;;; rewrites a library and every use of it leaves this list behind, and
;;; the mismatch is the alarm. Regenerating it from the library sources
;;; would make it agree with them by construction, which is exactly the
;;; agreement it exists to withhold -- the guard would still be here,
;;; still green, and no longer capable of failing.
;;;
;;; So: a new export is added HERE BY HAND, in the same change that adds
;;; it to the library. Never re-emit this file from a script.
;;;
;;; The first eleven libraries below were written by hand when the rename
;;; above happened. The rest were transcribed in one pass afterwards,
;;; covering the other forty-three -- before that pass, forty-three of
;;; the fifty-four libraries had no guard on their names at all, which
;;; included every library in the core.

(import (chezscheme)
        (only (igropyr connpool)
              make-connpool-cfg connpool-loop connpool-call
              connpool-drain-stale! connpool-check-size!
              sql-transaction connpool-lease connpool-close! connpool-stats
              connpool-cfg-set-observer! connpool-observer-failures)
        (only (igropyr mysql)
              mysql-connect mysql-pool mysql-query mysql-close!
              mysql-pool-stats mysql-transaction call-with-mysql-connection
              mysql-observe!)
        (only (igropyr postgresql)
              postgresql-connect postgresql-pool postgresql-query
              postgresql-execute postgresql-close! postgresql-pool-stats
              postgresql-transaction call-with-postgresql-connection)
        (only (igropyr qjspool)
              qjs-worker-serve! qjspool qjspool-connect qjspool?
              qjspool-render qjspool-render/bytes
              qjspool-timeout-ms qjspool-stats qjspool-close!)
        (only (igropyr ssr)
              make-ssr ssr-render ssr-render/bytes ssr-try-render
              ssr-try-render/bytes ssr-invalidate! ssr-clear! ssr-stats)
        (only (igropyr conversation)
              conversation-start! conversation-resume! conversation-peek
              conversation-gone? conversation-stale? conversation-done?
              conversation-settled? conversation-unknown?
              conversation-unreachable?
              conversation-set-limits! conversation-hook-stats
              conversation-prepare! conversation-run!
              conversation-abandon! conversation-ref-id
              conversation-peek/timeout conversation-no-answer-yet?
              conversation-overloaded? conversation-forward-stats
              conv-set-forward-limit! conv-set-forward-hold-ms!
              conversation-census conversation-quiesce!
              conversation-quiescing?)
        ;; the same predicates again, from the library that has no
        ;; initialisation of its own: a pure consumer imports THIS one, and
        ;; that it exports the whole vocabulary is part of the public face
        ;; rsa joins the list with rsa-key-consistency-checked, which is
        ;; the whole point of that accessor: a caller that must not sign
        ;; on an unverified key asks for it by name, and a rename that
        ;; took the name away would leave the question unanswerable while
        ;; every suite stayed green.
        (only (igropyr rsa)
              rsa-key? rsa-key-private? rsa-key-bits
              rsa-key-consistency-checked
              rsa-key-modulus rsa-key-exponent rsa-key-free!
              rsa-private-key-from-pem rsa-public-key-from-pem
              rsa-public-key-from-modulus
              rsa-load-private-key rsa-load-public-key
              rsa-sign-sha256 rsa-verify-sha256)
        (only (igropyr express)
              create-app app-use app-get app-post app-listen
              ;; the assembled app's own answer to "what is registered",
              ;; so a test need not scan source text for it
              app-route-list)
        (only (igropyr durable)
              durable-write-file! durable-dir-ensure!
              fs-trace-hook-set! with-fs-trace
              durable-error? durable-error-op durable-error-path)
        (only (igropyr durable-async)
              durable-write-file-async! durable-dir-ensure-async!
              ;; re-exported: importing the async library alone must give
              ;; the vocabulary to catch what it raises
              durable-error? durable-error-op durable-error-path)
        (only (igropyr conv-status)
              conversation-gone? conversation-stale? conversation-done?
              conversation-settled? conversation-unknown?
              conversation-unreachable? conversation-no-answer-yet?
              conversation-overloaded?)
        (only (igropyr actor)
              spawn spawn&link send receive self link monitor
              demonitor process-trap-exit kill register
              unregister whereis sleep-ms process-alive?
              process-id process-count process-monitor-count
              critical! uncritical! start-scheduler)
        (only (igropyr aead)
              aes-256-gcm-encrypt aes-256-gcm-decrypt
              aes-256-gcm-seal aes-256-gcm-open
              aes-256-gcm-key-bytes aes-256-gcm-iv-bytes
              aes-256-gcm-tag-bytes aead-random-bytes)
        (only (igropyr apple-jws)
              verify-apple-jws verify-jws-x5c
              apple-root-ca-g3-der)
        (only (igropyr auth)
              auth req-claims token-guard session-guard)
        (only (igropyr aws)
              aws-signed-post endpoint->host form-encode
              xml-first)
        (only (igropyr blas)
              blas-available? blas-scores! blas-scores-pure!)
        (only (igropyr buffer)
              make-inbuf inbuf? inbuf-length inbuf-append!
              inbuf-consume! inbuf-clear! inbuf-bv inbuf-start
              inbuf-end inbuf-sub inbuf-find-header-end)
        (only (igropyr checked)
              define-checked define-checked-record
              contract-level ->)
        (only (igropyr cloudwatch)
              make-cloudwatch cloudwatch-put-metric)
        (only (igropyr cluster)
              cluster-start cluster-stop)
        (only (igropyr crypto)
              sha1 sha256 hmac-sha1 hmac-sha256
              pbkdf2-hmac-sha256 base64-encode base64-decode
              base64url-encode base64url-decode bytevector->hex)
        (only (igropyr dashboard)
              dashboard-html mount-dashboard! admin-listen)
        (only (igropyr dpool)
              dpool-start dpool-submit dpool-await
              dpool-worker-start dpool-stats)
        (only (igropyr gen-server)
              gen-server-start gen-server-start-named
              gen-server-call gen-server-cast)
        (only (igropyr gzip)
              gzip-compress gzip-acceptable?)
        (only (igropyr http)
              http-listen http-swap! http-set-ws! http-stats
              http-stats-json http-shutdown! http-write-timeout!
              http-request-deadline! http-server-sup
              http-server-pool-alive? http-server-ready?
              http-server-backlog http-server-backlog-effective
              request? res? req-method
              req-path req-query req-headers req-header req-body
              req-keep-alive? req-version req-peer req-params
              req-params-set! req-local req-set-local!
              set-status! set-header! set-header-if-unanswered!
              res-send! res-begin! res-write! res-end!
              res-begin-file! res-write-file! res-write-chunk!
              res-abort-file! res-conn res-req res-status
              res-headers res-keep-alive? res-head-request?
              res-send-head! res-answered? res-streaming?
              res-abort! res-spawn! send-response! parse-query
              start-scheduler spawn send receive self sleep-ms
              kill register whereis process-id)
        (only (igropyr http-client)
              http-request http-get http-post response?
              response-status response-headers response-body
              response-header http-client-pool!
              http-client-pool-stats http-client-close-idle!
              set-https-connector! start-scheduler spawn send
              receive self sleep-ms kill register whereis
              process-id)
        (only (igropyr json)
              string->json json->string json-object? json-array?
              json-null? json-ref json-ref* json-set json-set*
              json-drop json-drop* json-push json-push*
              json-insert json-insert* json-update json-update*)
        (only (igropyr json-internal)
              json-number-text? before-precision-tag
              repair-precision-tag number-text)
        (only (igropyr jwks)
              jwks-load-key jwks-key-id jwks-key-free!
              jwks-document jwks-sign jwks-verify jwks-fetch!
              jwks-cache-clear!)
        (only (igropyr jwt)
              jwt-sign jwt-verify jwt-verifier jwt-decode)
        (only (igropyr kdf)
              kdf-pbkdf2-sha256 kdf-scrypt kdf-argon2id
              kdf-argon2id-available? password-hash
              password-verify)
        (only (igropyr libuv)
              uv-init! uv-poll! now-ms now-ns uv-set-deliver!
              uv-owner-died! tcp-listen! tcp-stop-listen!
              listener-open? listener-token
              tcp-connect! dns-resolve! file-read-async!
              file-realpath file-stream-open!
              file-stream-open-under! file-stream-read!
              file-stream-close! file-stream-own!
              file-stream-raw! file-stream-chunk-ptr
              fs-open-async! fs-write-async! fs-fsync-async!
              fs-rename-async! fs-close-async! fs-mkdir-async!
              fs-job-count fs-fd-count fs-o-rdonly fs-o-wronly
              fs-o-creat fs-o-trunc fs-o-excl fs-o-directory
              fs-o-cloexec fs-count tcp-read-start!
              tcp-read-stop! tcp-write! tcp-writev!
              tcp-write-foreign! tcp-close! conn? conn-handle
              conn-owner conn-set-owner! conn-peer-ip
              conn-on-close! conn-state conn-count
              uv-owner-index-count uv-live-handle-count
              uv-strerror)
        (only (igropyr metrics)
              make-metrics metrics-middleware metrics-endpoint
              metrics-count! metrics-snapshot metrics-json
              metrics-sexpr metrics-announce!)
        (only (igropyr middleware)
              cors security-headers logger rate-limit
              error-handler)
        (only (igropyr node)
              node-start! node-connect! node-disconnect!
              node-self rsend rcall monitor-node demonitor-node
              node-peers monitor-remote demonitor-remote
              node-set-limits! node-monitor-stats
              node-outbound-stats reconnect-delay
              submission-failure? node-install-rule-order
              node-orphan-count monitor-node/token
              demonitor-node/token)
        (only (igropyr otp)
              start-worker-pool pool-stats)
        (only (igropyr platform)
              platform-os platform-arch
              ensure-supported-platform!
              load-first-shared-object! shared-object-candidates
              addrinfo-address-offset addrinfo-next-offset
              uv-stat-mode-offset uv-stat-size-offset)
        (only (igropyr pubsub)
              start-pubsub! subscribe unsubscribe publish)
        (only (igropyr quickjs)
              qjs-boot! qjs-call qjs-call/bytes qjs-call!
              qjs-healthy? qjs-generation qjs-shutdown!)
        (only (igropyr redis)
              redis-connect redis redis-close! redis-set-limits!)
        (only (igropyr s3)
              make-s3 s3? s3-put! s3-get s3-head s3-copy!
              s3-delete! s3-delete-prefix! s3-list s3-restore!)
        (only (igropyr s3-control)
              make-s3-control s3-control-create-job
              s3-control-describe-job s3-control-error?)
        (only (igropyr ses)
              make-ses ses-send-email)
        (only (igropyr session)
              make-session-store session-middleware req-session
              session-get session-set! session-clear!
              session-regenerate! session-peek)
        (only (igropyr sexpr)
              string->sexpr sexpr->string string->sexpr-extended
              sexpr->string-extended)
        (only (igropyr sigv4)
              sigv4-sign-headers sigv4-uri-encode
              sigv4-canonical-query sigv4-canonical-request
              sigv4-signing-key sigv4-string-to-sign
              sigv4-authorization sigv4-datetime sha256-hex)
        (only (igropyr sns)
              make-sns sns-publish)
        (only (igropyr sts)
              make-sts sts-get-federation-token)
        (only (igropyr tls)
              tls-enable! tls-establish!)
        (only (igropyr util)
              opt need string-search string-contains?
              string-suffix?)
        (only (igropyr websocket)
              ws-accept-key ws-valid-client-key? make-ws
              make-ws-client ws? ws-conn ws-recv ws-send-text!
              ws-send-binary! ws-close! ws-write-timeout!)
        (only (igropyr ws-client)
              ws-connect ws-recv ws-send-text! ws-send-binary!
              ws-close! start-scheduler spawn send receive self
              sleep-ms kill register whereis process-id))

(display "public names: all present\n")
