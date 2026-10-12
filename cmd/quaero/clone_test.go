// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"strings"
	"testing"
)

// Le clone est superficiel et prudent: une branche, pas d'etiquettes, pas de
// hooks, pas de sous-modules par le protocole fichier.
func TestCloneArgs(t *testing.T) {
	args := strings.Join(cloneArgs("https://github.com/a/b.git", "/tmp/x"), " ")
	for _, want := range []string{"--depth 1", "--single-branch", "--no-tags", "core.hooksPath=", "protocol.file.allow=never"} {
		if !strings.Contains(args, want) {
			t.Errorf("arguments de clone sans %q: %s", want, args)
		}
	}
	// Le dossier cible est le dernier argument, l'URL juste avant.
	if args := cloneArgs("URL", "DIR"); args[len(args)-1] != "DIR" || args[len(args)-2] != "URL" {
		t.Errorf("ordre des arguments: %v", args)
	}
}

// Un dossier local l'emporte sur une reference de depot de meme forme.
func TestResolveScanTargetLocalDAbord(t *testing.T) {
	dir := t.TempDir()
	got, label, untrusted, cleanup, err := resolveScanTarget(t.Context(), dir)
	defer cleanup()
	if err != nil {
		t.Fatalf("resolveScanTarget: %v", err)
	}
	if got != dir || untrusted || label != dir {
		t.Errorf("dossier local lu comme %q, non_fiable=%v", got, untrusted)
	}
}

func TestResolveScanTargetInvalide(t *testing.T) {
	_, _, _, cleanup, err := resolveScanTarget(t.Context(), "pas-un-depot")
	defer cleanup()
	if err == nil {
		t.Error("une cible qui n'est ni dossier ni depot doit echouer")
	}
}
