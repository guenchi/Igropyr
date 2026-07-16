#!chezscheme
;;; (igropyr checked): a bad IGROPYR_CONTRACTS value must fail loudly at
;;; expansion time -- a misspelled value silently disabling checks would
;;; give false confidence. run-all.sh runs this with IGROPYR_CONTRACTS=on
;;; and expects a nonzero exit mentioning the variable.

(import (chezscheme) (igropyr checked))

(define-checked (f (x fixnum?)) x)

;; reaching here means the bad value was accepted: that is the failure
(display "checked-badenv: bad IGROPYR_CONTRACTS value was accepted") (newline)
(exit 1)
