#!chezscheme
;;; Copyright 2018 - 2026 guenchi.
;;;
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;;
;;; http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

;;; (igropyr jose) -- protected-header rules shared by the JWS verifiers.
;;;
;;;   (jose-crit-present? header)   ; -> #t when header has a crit member
;;;
;;; (igropyr jwt), (igropyr jwks) and (igropyr apple-jws) each decide for
;;; themselves which algorithm and which key they accept; those decisions
;;; differ and stay where they are. What lives here is a rule that is the
;;; same for every one of them, so that it is written once. Each verifier
;;; still reports a refusal in its own shape.

(library (igropyr jose)
  (export jose-crit-present?)
  (import (chezscheme) (only (igropyr json) json-ref))

  ;; RFC 7515 4.1.11 gives two grounds for refusing a token that carries
  ;; crit, and this test covers both:
  ;;
  ;;   - a crit naming an extension the recipient does not understand makes
  ;;     the token invalid (MUST). Nothing here implements any extension,
  ;;     so every extension crit can name is one of those.
  ;;   - a crit that breaks the rules on its own form -- an empty list,
  ;;     something that is not a list of names, a name the specification
  ;;     itself defines -- is a producer error that a recipient is permitted
  ;;     to refuse (MAY), and this one does.
  ;;
  ;; So the test is presence alone, whatever the value. That is a policy the
  ;; RFC permits, not the least it requires: a recipient that applied only
  ;; the MUST would still refuse every crit naming an extension, and would
  ;; differ from this only on a malformed crit.
  ;;
  ;; THE PRESENCE TEST HOLDS ONLY WHILE NOTHING HERE UNDERSTANDS AN EXTENSION.
  ;; The day one is implemented, this has to become a real check of each
  ;; name crit lists against the extensions that are understood.
  ;;
  ;; THE THUNK IS WHAT MAKES THIS CORRECT, not decoration. Without one,
  ;; json-ref answers #f both when there is no crit member and when the
  ;; member's value is false, so the one-line version of this test accepts
  ;; {"crit": false} -- a header that does carry the member. The sentinel
  ;; is a fresh pair, so nothing the parser returns can be eq? to it.
  ;;
  ;; header must already be known to be a parsed JSON object.
  (define (jose-crit-present? header)
    (let ((absent (list 'absent)))
      (not (eq? (json-ref header "crit" (lambda () absent)) absent)))))
