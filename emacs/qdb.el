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
    "list"
    "n" "next"
    "q" "quit"
    "s" "step"
    "r" "return"
    "unt" "until"
    "w" "watch"
    "unw" "unwatch"
    "tbreak"))

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
  (start-process "qdb-out" "*qdb-out*" "tail" "-f" out-file)
  (switch-to-buffer "*qdb-out*")
  (read-only-mode)
  (pop-to-buffer qdb-buffer))

(defun run-qdb (uuid addr auth)
  "Starts a new qdb session inside of emacs."
  (interactive "suuid (default: \"qdb\"): \nsaddr (default: \
\"ws://localhost:8002/debug_session/{uuid}\"): \nsauth (default: \"\"): ")
  (let* ((real-uuid (if (not (string= uuid ""))
                        uuid
                      "qdb"))
         (real-addr (if (not (string= addr ""))
                        addr
                      "ws://localhost:8002/debug_session/{uuid}"))
         (qdb-buffer (make-comint-in-buffer
                      "qdb" nil qdb-executable
                      nil "-w" real-addr "-u" real-uuid "-a" auth)))
    (switch-to-buffer qdb-buffer)
    (qdb-mode)
    (qdb-open-out-file (format "/tmp/qdb/.%s" real-uuid) qdb-buffer)))
