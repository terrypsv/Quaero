// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package proctree

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// Un petit-enfant qui garde la sortie ouverte bloquerait l'attente jusqu'a
// WaitDelay s'il survivait a l'annulation. Arrete avec l'arbre, la commande
// rend la main presque aussitot.
func TestAnnulationArreteLArbre(t *testing.T) {
	var name string
	var args []string
	switch runtime.GOOS {
	case "windows":
		name = os.Getenv("ComSpec")
		if name == "" {
			t.Skip("ComSpec absent")
		}
		// ping est un enfant de cmd et herite de sa sortie.
		args = []string{"/c", "ping -n 30 127.0.0.1"}
	default:
		name = "sh"
		// sleep est un enfant de sh et herite de sa sortie.
		args = []string{"-c", "sleep 30 & wait"}
	}
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s absent", name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	Prepare(cmd)

	start := time.Now()
	_ = cmd.Run()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("la commande a rendu la main en %s: un descendant a survecu a l'annulation", elapsed)
	}
}

func TestPrepareBorneLAttente(t *testing.T) {
	cmd := exec.Command("quaero-inexistant")
	Prepare(cmd)
	if cmd.WaitDelay != WaitDelay {
		t.Errorf("WaitDelay = %s, attendu %s", cmd.WaitDelay, WaitDelay)
	}
	if (runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "darwin") && cmd.Cancel == nil {
		t.Error("annulation de l'arbre non posee")
	}
}
