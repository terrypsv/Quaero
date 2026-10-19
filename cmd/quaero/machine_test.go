// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// L'identifiant se tire une fois et se relit ensuite. Un fichier abime n'est
// pas ecrase: il n'y a alors pas d'identifiant.
func TestIdentifiantDeMachine(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".quaero", "poste")
	first := machineID(path)
	if !machineRe.MatchString(first) || machineID(path) != first {
		t.Fatalf("identifiant %q, relu %q", first, machineID(path))
	}
	if err := os.WriteFile(path, []byte("abime"), 0o600); err != nil {
		t.Fatal(err)
	}
	if id := machineID(path); id != "" {
		t.Errorf("fichier abime: %q", id)
	}
	if b, _ := os.ReadFile(path); string(b) != "abime" {
		t.Errorf("fichier abime ecrase: %q", b)
	}
}
