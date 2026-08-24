// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package github

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func withHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	} else {
		t.Setenv("HOME", dir)
	}
	return dir
}

func TestSaveAndLoadToken(t *testing.T) {
	withHome(t)

	if got := LoadToken(); got != "" {
		t.Errorf("premier demarrage: jeton = %q, want vide", got)
	}

	path, err := SaveToken("  jeton-de-test  ")
	if err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	if filepath.Base(path) != configFile {
		t.Errorf("chemin = %q", path)
	}
	if got := LoadToken(); got != "jeton-de-test" {
		t.Errorf("jeton relu = %q, les espaces devaient etre elagues", got)
	}
}

// Un identifiant lisible par tous est un identifiant partage avec tous les
// processus de la machine.
func TestStoredTokenIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("les permissions POSIX ne s'appliquent pas ici")
	}
	withHome(t)

	path, err := SaveToken("secret")
	if err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("permissions = %o, want 600", mode)
	}
}

func TestEmptyTokenIsRefused(t *testing.T) {
	withHome(t)
	if _, err := SaveToken("   "); err == nil {
		t.Error("un jeton vide doit etre refuse")
	}
}

func TestForgetToken(t *testing.T) {
	withHome(t)
	if _, err := SaveToken("secret"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	if _, err := ForgetToken(); err != nil {
		t.Fatalf("ForgetToken: %v", err)
	}
	if got := LoadToken(); got != "" {
		t.Errorf("jeton toujours present: %q", got)
	}
}

// Oublier un jeton absent n'est pas une erreur: c'est deja l'etat voulu.
func TestForgetIsIdempotent(t *testing.T) {
	withHome(t)
	if _, err := ForgetToken(); err != nil {
		t.Errorf("ForgetToken sur un fichier absent: %v", err)
	}
}

func TestCorruptConfigIsTreatedAsAbsent(t *testing.T) {
	home := withHome(t)
	path := filepath.Join(home, configDir, configFile)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte("{ ceci n est pas du json"), 0o600)

	if got := LoadToken(); got != "" {
		t.Errorf("configuration illisible: jeton = %q, want vide", got)
	}
}
