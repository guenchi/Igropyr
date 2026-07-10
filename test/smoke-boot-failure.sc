#!chezscheme
(import (chezscheme) (igropyr actor))

(start-scheduler
  (lambda ()
    (error 'boot-test "deliberate boot failure")))

