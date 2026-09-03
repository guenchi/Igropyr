#!chezscheme
;;; The death-log renderer pins the print parameters it renders under, so a
;;; line it writes says the same thing whatever the application has done to
;;; those parameters globally. This suite is what makes that claim
;;; falsifiable: without the pins the same reason renders differently.
;;;
;;; ⭐ HOW A CHOSEN OBJECT REACHES THE RENDERER. The warden carries the
;;; registered name igropyr-node-warden precisely so a harness can put a
;;; message in front of its diagnostic branches (node.sc says so where the
;;; name is defined). Its receive matches #(DOWN pid reason) without
;;; validating the sender, and a pid it does not manage takes the
;;; "DOWN from a process it does not manage" branch, which renders the
;;; reason through raised-object-text and writes it to the current error
;;; port. Sending that message with this process's own pid therefore
;;; renders any object we like, restarts no child, and does not touch the
;;; warden's death counters. Capturing it is the same string-port swap
;;; test/node.sc already uses.
;;;
;;; ⭐ TWO RENDERING SITES, AND EVERY WITNESS GOES THROUGH BOTH. An
;;; ordinary value is printed by `show`; a condition carrying a format
;;; string as its message is printed by `(apply format msg irr)`, which is
;;; a different entry to the printer. A pin that covers one and not the
;;; other would pass a suite that only tested the first, so each witness
;;; is rendered bare AND as the irritant of an errorf condition.
;;;
;;; ⚠ THE CONTROLS ARE NOT DECORATION. Two cases use a parameter that is
;;; already pinned (print-radix). If the harness itself were broken -- the
;;; warden not reached, the error port not captured, the substring test
;;; inverted -- those would fail too, and a red run would say nothing about
;;; the pins. They are what distinguishes "the pin is missing" from "the
;;; measurement is broken".
(import (chezscheme) (igropyr actor) (igropyr node))

(define port 18090)
(define secret "test-render-pins-secret")
(define fails 0)

(define (fail! label . info)
  (set! fails (+ fails 1))
  (display "FAIL ") (display label)
  (for-each (lambda (x) (display " ") (write x)) info)
  (newline))

(define (has-substr? s sub)
  (let ((n (string-length s)) (m (string-length sub)))
    (let loop ((i 0))
      (cond ((> (+ i m) n) #f)
            ((string=? (substring s i (+ i m)) sub) #t)
            (else (loop (+ i 1)))))))

;; Render obj through the warden's unmanaged-DOWN diagnostic; -> the text.
(define (render-through-warden obj)
  (let ((w (whereis 'igropyr-node-warden)))
    (if (not w)
        (begin (fail! "no-warden-registered") "")
        (let ((buf (open-output-string)) (old (current-error-port)))
          (current-error-port buf)
          (send w (vector 'DOWN self obj))
          ;; ⚠ POLL FOR THE LINE, DO NOT SLEEP A FIXED TIME. The warden is
          ;; another process and nothing orders its run against this one, so
          ;; a fixed wait is a guess that goes red under load rather than
          ;; when the renderer is wrong -- the same mistake this suite's
          ;; sibling in test/inject.sc was fixed for. The completeness
          ;; condition is the newline the diagnostic ends with: the warden
          ;; can be preempted part way through writing it.
          ;;
          ;; ⚠ get-output-string CLEARS the port (measured on Chez 10.1.0:
          ;; a second read of an unwritten port returns ""), so each poll
          ;; must accumulate what it took rather than re-read the whole.
          (let poll ((n 0) (acc ""))
            (let ((acc (string-append acc (get-output-string buf))))
              (cond ((has-substr? acc "\n") (current-error-port old) acc)
                    ((fx= n 300) (current-error-port old) acc)
                    (else (sleep-ms 10) (poll (fx+ n 1) acc)))))))))

;; One case: set a parameter to a hostile value, render, restore, and check
;; that the wanted text is present and the hostile rendering is absent.
;; Both directions are checked: "wanted present" alone would pass a line
;; that carried both, which is what a partial pin could produce.
(define (case! label set-hostile! restore! obj want unwanted)
  (set-hostile!)
  (let ((txt (guard (e (#t (restore!) (raise e))) (render-through-warden obj))))
    (restore!)
    (cond ((string=? txt "") (fail! label 'no-output))
          ((not (has-substr? txt want)) (fail! label 'missing want txt))
          ((has-substr? txt unwanted) (fail! label 'hostile-rendering-leaked unwanted txt))
          (else (display "  ok ") (display label) (newline)))))

;; the same witness as the irritant of a genuine format condition, so the
;; (apply format msg irr) site is exercised rather than `show`
(define (fmt-condition witness)
  (guard (e (#t e)) (errorf 'probe "value ~s" witness)))

(start-scheduler
  (lambda ()
    (node-start! 'rp secret port)
    (let wait ((n 0))
      (cond ((whereis 'igropyr-node-warden) 'up)
            ((= n 100) (fail! "warden-never-registered"))
            (else (sleep-ms 50) (wait (+ n 1)))))

    ;; --- controls: a parameter that is already pinned -------------------
    (case! "control-radix-bare"
           (lambda () (print-radix 2)) (lambda () (print-radix 10))
           255 "255" "#b11111111")
    (case! "control-radix-format"
           (lambda () (print-radix 2)) (lambda () (print-radix 10))
           (fmt-condition 255) "255" "#b11111111")

    ;; --- print-char-name ------------------------------------------------
    (case! "char-name-bare"
           (lambda () (print-char-name #t)) (lambda () (print-char-name #f))
           (integer->char 133) "#\\x85" "#\\nel")
    (case! "char-name-format"
           (lambda () (print-char-name #t)) (lambda () (print-char-name #f))
           (fmt-condition (integer->char 133)) "#\\x85" "#\\nel")

    ;; --- print-subnormal-precision ---------------------------------------
    (case! "subnormal-bare"
           (lambda () (print-subnormal-precision #f)) (lambda () (print-subnormal-precision #t))
           5e-324 "5e-324|1" "e-324)")
    (case! "subnormal-format"
           (lambda () (print-subnormal-precision #f)) (lambda () (print-subnormal-precision #t))
           (fmt-condition 5e-324) "5e-324|1" "e-324 in")

    ;; --- print-select-flonum-exponential-format ---------------------------
    (let ((keep (print-select-flonum-exponential-format)))
      (case! "flonum-format-bare"
             (lambda () (print-select-flonum-exponential-format (lambda (e p n) #f)))
             (lambda () (print-select-flonum-exponential-format keep))
             1e20 "1e20" "100000000000000000000")
      (case! "flonum-format-format"
             (lambda () (print-select-flonum-exponential-format (lambda (e p n) #f)))
             (lambda () (print-select-flonum-exponential-format keep))
             (fmt-condition 1e20) "1e20" "100000000000000000000"))

    ;; ==== the renderer's other stated contracts ==========================
    ;; Each expectation below is taken from what the renderer's own comments
    ;; promise, not from watching it run: an expectation read off the
    ;; implementation would pin whatever it does today, including a defect.
    ;;
    ;; ⚠ These share the harness with the pin cases above, so the two
    ;; print-radix controls cover them too: if the seam breaks, everything
    ;; here goes red together and the controls say why.

    ;; The whole line, marker included, fits in reason-text-total (512), and
    ;; it is ONE line -- a death log that spans lines is not greppable.
    (let* ((huge (make-string 5000 #\x))
           (txt (render-through-warden
                  (condition (make-error) (make-who-condition 'probe)
                             (make-message-condition "big")
                             (make-irritants-condition (list huge))))))
      (cond ((not (has-substr? txt "...[truncated]"))
             (fail! "budget-no-marker" (string-length txt)))
            ((> (string-length txt) 800) (fail! "budget-line-too-long" (string-length txt)))
            ((not (= 1 (let count ((i 0) (n 0))
                         (cond ((= i (string-length txt)) n)
                               ((char=? (string-ref txt i) #\newline) (count (+ i 1) (+ n 1)))
                               (else (count (+ i 1) n))))))
             (fail! "budget-not-one-line" txt))
            (else (display "  ok budget-truncates-to-one-marked-line\n"))))

    ;; Control characters are replaced, because a log line is not merely
    ;; newline-free: tabs and escapes break it too.
    (let ((txt (render-through-warden
                 (condition (make-error) (make-who-condition 'probe)
                            (make-message-condition "line one\nline two\ttabbed")
                            (make-irritants-condition (list 1))))))
      (cond ((has-substr? txt "\t") (fail! "scrub-tab-survived" txt))
            ((not (has-substr? txt "line one line two tabbed"))
             (fail! "scrub-did-not-fold-to-spaces" txt))
            (else (display "  ok control-characters-folded\n"))))

    ;; who goes LAST: a who long enough to fill the budget must not push the
    ;; message out, because the message is the part that says what went wrong.
    (let ((txt (render-through-warden
                 (condition (make-error)
                            (make-who-condition (string->symbol (make-string 600 #\w)))
                            (make-message-condition "the real diagnosis")
                            (make-irritants-condition (list 1))))))
      (if (has-substr? txt "the real diagnosis")
          (display "  ok long-who-does-not-evict-the-message\n")
          (fail! "long-who-evicted-the-message" txt)))

    ;; A literal tilde in an ORDINARY assertion message is text, not a
    ;; directive: guessing from the shape once rendered "literal ~a text"
    ;; as an interpolation and dropped the irritant's presentation.
    (let ((txt (render-through-warden
                 (condition (make-assertion-violation) (make-who-condition 'probe)
                            (make-message-condition "literal ~a text")
                            (make-irritants-condition (list 'bar))))))
      (cond ((not (has-substr? txt "literal ~a text")) (fail! "literal-tilde-interpreted" txt))
            ((not (has-substr? txt "bar")) (fail! "literal-tilde-lost-irritant" txt))
            (else (display "  ok literal-tilde-kept-with-its-irritant\n"))))

    ;; A genuine format condition IS expanded -- printing message and
    ;; irritants apart would give "~s is not a pair with irritants ()".
    (let ((txt (render-through-warden (fmt-condition (list 1 2)))))
      (if (has-substr? txt "value (1 2)")
          (display "  ok format-condition-expanded\n")
          (fail! "format-condition-not-expanded" txt)))

    ;; The renderer never raises: one that could would take the node down
    ;; from inside the warden's DOWN handling.
    (let ()
      (define-record-type hostile (fields x))
      (record-writer (record-type-descriptor hostile)
                     (lambda (r p wr) (error 'hostile-writer "writer raises")))
      (let ((txt (render-through-warden (make-hostile 1))))
        (cond ((string=? txt "") (fail! "raising-writer-produced-no-line"))
              ((not (has-substr? txt "could not be rendered"))
               (fail! "raising-writer-not-caught" txt))
              (else (display "  ok raising-record-writer-is-caught\n")))))

    (if (zero? fails)
        (begin (display "ALL RENDER PIN TESTS PASSED\n") (exit 0))
        (begin (display "RENDER PIN VERDICT: ") (display fails)
               (display " failed case(s)\n") (exit 1)))))
