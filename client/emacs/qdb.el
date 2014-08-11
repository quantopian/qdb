;;
;; Copyright 2014 Quantopian, Inc.
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;; http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.
(defvar qdb-executable (executable-find "qdb-cli")
  "Program used by `run-qdb'")

(defvar qdb-mode-map
  (let ((map (nconc (make-sparse-keymap) comint-mode-map)))
    ;; example definition
    (define-key map "\t" 'completion-at-point)
    map)
  "Basic mode map for `run-qdb'")

(defvar qdb-prompt-regexp "(qdb)"
  "Prompt for `run-qdb'.")

(defun qdb--initialize ()
  "Helper function to initialize qdb"
  (setq comint-process-echoes t)
  (setq comint-use-prompt-regexp t))

(defconst qdb-keywords
  '("b" "break"
    "c" "continue"
    "cl" "clear"
    "l" "list"
    "n" "next"
    "q" "quit"
    "s" "step"
    "r" "return"
    "unt" "until"
    "w" "watch"
    "unw" "unwatch"
    "u" "up"
    "d" "down"
    "p" "pause"
    "locals"
    "tbreak"
    "help"
    "EOF"))

(defvar qdb-font-lock-keywords
  (list
   ;; highlight all the reserved commands.
   `(,(concat "\\_<"
              (regexp-opt qdb-keywords) "\\_>") . font-lock-keyword-face))
  "Additional expressions to highlight in `qdb-mode'.")

(define-derived-mode qdb-mode comint-mode "qdb"
  "Major mode for `run-qdb'.

\\<qdb-mode-map>"
  nil "qdb"
  (setq comint-prompt-regexp qdb-prompt-regexp)
  (setq comint-prompt-read-only t)
  (set (make-local-variable 'paragraph-separate) "\\'")
  (set (make-local-variable 'font-lock-defaults) '(qdb-font-lock-keywords t))
  (set (make-local-variable 'paragraph-start) qdb-prompt-regexp))
(add-hook 'qdb-mode-hook 'qdb--initialize)

(defun qdb-open-out-file (out-file qdb-buffer)
  "Opens the out-file in a tail -f type mode and pops back the repl."
  (call-process-shell-command "touch" nil nil nil out-file)
  (start-process "qdb-out" "*qdb-out*" "tail" "-f" out-file)
  (switch-to-buffer "*qdb-out*")
  (read-only-mode)
  (pop-to-buffer qdb-buffer))


(defvar qdb-default-uuid "qdb")
(defvar qdb-default-addr "ws://localhost:8002/{uuid}")
(defvar qdb-default-auth "")

(defun run-qdb (uuid addr auth)
  "Starts a new qdb session inside of emacs."
  (interactive "suuid: \nsaddr: \nsauth: ")
  (let* ((real-uuid (if (not (string= uuid ""))
                        uuid
                      qdb-default-uuid))
         (real-addr (if (not (string= addr ""))
                        addr
                        qdb-default-addr))
         (real-auth (if (not (string= auth ""))
                        auth
                      qdb-default-auth))
         (qdb-buffer (make-comint-in-buffer
                      "qdb" nil qdb-executable
                      nil "-w" real-addr "-u" real-uuid "-a" auth)))
    (switch-to-buffer qdb-buffer)
    (qdb-mode)
    (qdb-open-out-file (format "/tmp/qdb/.%s" real-uuid) qdb-buffer)))
