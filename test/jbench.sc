#!chezscheme
;;; Hot-path microbenchmark. NOT a pass/fail suite and deliberately NOT
;;; registered in run-all.sh -- timing assertions flake, and a flaky red
;;; teaches people to ignore red. This is a measuring tool.
;;;
;;; WHEN TO RUN. Any change that touches one of the three hot paths --
;;; per-request (parse -> handler -> serialize -> write), per-message
;;; (receive / gen-server call), per-process spawn/death -- runs this
;;; before and after, on the same machine in the same session, and the
;;; change ships with both numbers. "Sounds cheap" and "sounds
;;; expensive" are judgments without a unit; the table this prints is
;;; the unit.
;;;
;;; PROTOCOL. Three runs, take the minimum (the minimum is the run with
;;; the least scheduler noise; means smear noise in). Workload shapes
;;; are FROZEN: comparability across time matters more than realism, so
;;; extend by adding rows, never by editing existing ones.
;;;
;;;   git stash / checkout the before-tree, run, note numbers;
;;;   restore the after-tree, run, compare. (Or use two worktrees.)

(import (chezscheme) (igropyr json))

(define (us thunk n)
  (let ((t0 (current-time 'time-monotonic)))
    (do ((i 0 (+ i 1))) ((= i n)) (thunk))
    (let ((t1 (current-time 'time-monotonic)))
      (/ (+ (* 1e6 (- (time-second t1) (time-second t0)))
            (/ (- (time-nanosecond t1) (time-nanosecond t0)) 1e3))
         n))))

(define (bench label thunk n)
  (printf "~a ~a us\n" label (min (us thunk n) (us thunk n) (us thunk n))))

;; frozen workload shapes ------------------------------------------------

;; number-heavy: the shape of a typical list-of-records API response
(define nums-doc
  (list (cons "items"
              (list->vector
                (map (lambda (i)
                       (list (cons "id" i)
                             (cons "score" (* i 1.5))
                             (cons "ok" #t)))
                     (iota 50))))))

;; string-heavy: exercises the writer's clean-string fast path
(define strs-doc
  (list (cons "rows"
              (list->vector
                (map (lambda (i)
                       (list (cons "name" "abcdefghij")
                             (cons "addr" "1234 somewhere street")))
                     (iota 50))))))

(define small '(("ok" . #t) ("n" . 42)))

(define parse-src
  "{\"a\":[1,2.5,\"x\",true,null],\"b\":{\"c\":\"hello world\",\"d\":12345}}")

(bench "write-nums-150 " (lambda () (json->string nums-doc)) 20000)
(bench "write-strs-100 " (lambda () (json->string strs-doc)) 20000)
(bench "write-small    " (lambda () (json->string small)) 200000)
(bench "parse-typical  " (lambda () (string->json parse-src)) 100000)
