#!chezscheme
;;; Helper for test/node.sc: a second OS process acting as node <name>.
;;; Usage: scheme --script node-child.sc <name> <port> <secret>
;;; Dials node 'a on 127.0.0.1:<port>, then:
;;;   - registers 'svc: #(add1 ,x ,p) -> (rsend 'a 'main #(ans ,(+ x 1) ,p))
;;;     and #(quit) -> exit (drops the link -> node-down on a)
;;;   - registers a gen-server 'calc for rcall: #(square ,n) -> n*n,
;;;     #(boom) -> raises (so the caller sees an rcall-error)
;;;   - starts pubsub, subscribes to 'room, relays #(pub room ,m) to
;;;     node a's 'main as #(heard ,m)
;;;   - #(watch ,target) -> monitor-remote 'a target, replies #(watched ,mref);
;;;     a #(remote-down node name reason) for it is RETAINED (the link it
;;;     reports on is down at that moment) and handed over on #(drain)
;;;     as #(drained ,list), over whatever link is live then;
;;;     #(stats) -> replies #(stats ,(node-monitor-stats)). These let a
;;;     cell make THIS node the watcher and read this node's hosting
;;;     counts -- injection state is per process, so a cell that needs
;;;     the hit on the hosting side must host on its own side and watch
;;;     from here.
;;; Exits by itself after <lifetime-ms> (4th argument, default 60000) as
;;; a safety net.

(import (chezscheme) (igropyr actor) (igropyr node)
        (igropyr gen-server) (igropyr pubsub))

(define args (cdr (command-line)))
(define name (string->symbol (car args)))
(define port (string->number (cadr args)))
(define secret (caddr args))
(define pending '())                    ; notices held until a drains them
(define lifetime-ms (if (> (length args) 3) (string->number (cadddr args)) 60000))

(start-scheduler
  (lambda ()
    (node-start! name secret)
    (node-set-limits! 64 2)
    (node-connect! 'a "127.0.0.1" port)
    (start-pubsub!)
    (register 'svc self)

    ;; a gen-server target for rcall
    (gen-server-start-named 'calc
      (lambda () 0)
      (lambda (msg from state)
        (case (vector-ref msg 0)
          ((square) (let ((n (vector-ref msg 1))) (values (* n n) state)))
          ((boom) (raise 'kaboom))
          (else (values 'bad state))))
      (lambda (msg state) state))

    ;; A SEPARATE server for the slow-handler cells: 'calc is a corpse
    ;; after the suite's boom call kills it, so anything after that
    ;; ordering point would see no-such-server instead of what it came
    ;; to measure. This one sleeps past the old 5s server-side default,
    ;; inside a 10s caller timeout: only a timeout carried in the call
    ;; frame lets the caller see 'slept (see test/node.sc).
    (gen-server-start-named 'slowcalc
      (lambda () 0)
      (lambda (msg from state)
        (case (vector-ref msg 0)
          ((slow) (sleep-ms 6500) (values 'slept state))
          (else (values 'bad state))))
      (lambda (msg state) state))

    ;; relay room traffic back to node a so the test can observe fan-out
    (spawn (lambda ()
             (subscribe 'room)
             (let loop ()
               (receive (`#(pub room ,m)
                          (rsend 'a 'main (vector 'heard m)) (loop))))))

    ;; a process node a can monitor-remote; #(mon-die ,reason) makes it
    ;; exit with that reason so the watcher observes it
    (register 'watched
      (spawn (lambda ()
               (let loop ()
                 (receive (`#(mon-die ,reason) (kill self reason)))))))

    ;; a second watchable process, for the 'exit-degradation cell: its
    ;; death reason is built HERE, locally, because a reason carrying a
    ;; procedure cannot be injected over the wire -- which is exactly
    ;; the property the cell needs (the wire refusing it is the trigger)
    (register 'watched2
      (spawn (lambda ()
               (receive (`#(raw-die) 'ok))
               (kill self (vector 'unprintable (lambda () #f))))))

    ;; safety net: generous enough to cover the slow-handler cells the
    ;; suite runs against this child (two 'slow calls plus the rest)
    (spawn (lambda () (sleep-ms lifetime-ms) (exit 1)))
    (let loop ()
      (receive
        (`#(add1 ,x ,payload)
          (rsend 'a 'main (vector 'ans (+ x 1) payload))
          (loop))
        (`#(kill-watched ,reason)
          (let ((p (whereis 'watched))) (when p (kill p reason)))
          (loop))
        (`#(kill-watched-raw)
          (let ((p (whereis 'watched2))) (when p (send p (vector 'raw-die))))
          (loop))
        ;; the serve-side timeout cap is THIS node's setting, not the
        ;; caller's; the suite lowers it through here to watch the cap
        ;; arm of the min() without a sixty-second handler
        (`#(set-serve-cap ,n)
          (node-set-limits! #f #f #f #f n)
          (loop))
        ;; watcher role: arm a watch on a's process and report the mref;
        ;; the notice for it arrives in this very mailbox and is forwarded
        (`#(watch ,target)
          (let ((m (monitor-remote 'a target)))
            (rsend 'a 'main (vector 'watched m)))
          (loop))
        ;; A NOTICE IS RETAINED, NOT FORWARDED. It is #(remote-down node
        ;; name reason) -- no mref, correlate by name -- and it arrives
        ;; while the link it reports on is down: an rsend here would
        ;; return #f and the notice would be gone. It waits for a's
        ;; #(drain), which can only arrive over the next live link.
        (`#(remote-down ,n ,nm ,reason)
          (set! pending (cons (vector 'remote-down n nm reason) pending))
          (loop))
        (`#(drain)
          (rsend 'a 'main (vector 'drained (reverse pending)))
          (set! pending '())
          (loop))
        (`#(stats)
          (rsend 'a 'main (vector 'stats (node-monitor-stats)))
          (loop))
        (`#(quit) (exit 0))))))
