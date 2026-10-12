// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

//go:build windows

package proctree

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// Windows n'a pas de groupe a qui envoyer un signal: taskkill /T suit la
// filiation depuis le processus et arrete chaque descendant, puis le processus
// lui-meme. Il est appele par son chemin systeme, jamais cherche dans le PATH.
func prepare(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		root := os.Getenv("SystemRoot")
		if root == "" {
			return cmd.Process.Kill()
		}
		taskkill := filepath.Join(root, "System32", "taskkill.exe")
		// #nosec G204 -- binaire systeme a chemin fixe, seul argument variable
		// un pid entier.
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		if err := exec.Command(taskkill, "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run(); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
